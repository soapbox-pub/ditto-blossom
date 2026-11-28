//! `ditto-blossom ban`, `unban` and `bans`: keep blobs and uploaders out
//! for good. Safe beside a running server, as `remove` is: the writer checks
//! the bans in the transaction that would store a blob, so nothing banned
//! gets in once the ban is committed. The server bans the same way, through
//! its writer, when a scan finds a match.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::blobs::{self, Files};
use crate::config::Config;
use crate::hash::{Hash, Hasher};
use crate::lmdb::RwTxn;
use crate::store::{Ban, Banned, Record, Store};
use crate::upload::now;

/// Ban each target and take out what it names: a blob, or an uploader's
/// blobs. A blob only banned uploaders own is removed and banned, so
/// another key can't put it back; one others own too stays theirs, and the
/// banned uploaders are taken off it. With `preserve`, each blob is copied
/// there, and its copy checked, before anything is removed.
pub fn ban(
    config: &Config,
    targets: &[Banned],
    reason: &str,
    preserve: Option<&Path>,
) -> Result<()> {
    let store = Store::open(&config.data)?;
    let files = Files::open(&config.data, 1, false)?;
    ban_in(&store, &files, targets, reason, preserve).map(|_| ())
}

/// The records of the blobs it removed: what a cache in front may still
/// hold copies of.
pub fn ban_in(
    store: &Store,
    files: &Files,
    targets: &[Banned],
    reason: &str,
    preserve: Option<&Path>,
) -> Result<Vec<Record>> {
    ban_with(store, files, targets, reason, preserve, false).map(|(removed, _)| removed)
}

/// `ban_in`, and with `uploaders`, the owners of the blobs named too (see
/// `ban_txn_with`). And how many uploaders that was.
fn ban_with(
    store: &Store,
    files: &Files,
    targets: &[Banned],
    reason: &str,
    preserve: Option<&Path>,
    uploaders: bool,
) -> Result<(Vec<Record>, usize)> {
    let mut txn = store.write_txn()?;
    let (doomed, found) = ban_txn_with(
        store,
        files,
        &mut txn,
        targets,
        reason,
        preserve,
        now(),
        uploaders,
    )?;
    txn.commit()?;
    let mut removed = Vec::with_capacity(doomed.len());
    for (seq, rec) in doomed {
        files.remove(seq, &rec.hash)?;
        crate::info!("removed", "blob": rec.hash.hex(), "size": rec.size);
        removed.push(rec);
    }
    Ok((removed, found))
}

/// Ban blobs as child sexual abuse material, with everyone who uploaded
/// them and any `accounts` named besides, keeping a copy of each blob it
/// removes in `dir` first (see `ban_in`): those accounts' other blobs are
/// kept as its context. A blob that isn't stored is banned all the same,
/// so it can't be uploaded, with nothing to keep. The records of the blobs
/// removed, and how many uploaders were banned.
pub fn ban_csam(
    store: &Store,
    files: &Files,
    hashes: &[Hash],
    accounts: &[[u8; 32]],
    dir: &Path,
) -> Result<(Vec<Record>, usize)> {
    if hashes.is_empty() {
        bail!("CSAM is banned by the blob that's CSAM");
    }
    let targets: Vec<Banned> = hashes
        .iter()
        .copied()
        .map(Banned::Blob)
        .chain(accounts.iter().copied().map(Banned::Pubkey))
        .collect();
    ban_with(store, files, &targets, "CSAM", Some(dir), true)
}

/// Take blobs out entirely, whoever owns them, without banning them. The
/// records of those that were here.
pub fn remove_in(store: &Store, files: &Files, hashes: &[Hash]) -> Result<Vec<Record>> {
    let mut removed = Vec::new();
    for hash in hashes {
        let mut txn = store.write_txn()?;
        let Some(seq) = store.seq_of(&txn, hash)? else {
            crate::info!("remove_absent", "blob": hash.hex());
            continue;
        };
        let rec = store
            .record(&txn, seq)?
            .context("a blob without its record")?;
        store.remove(&mut txn, seq, &rec)?;
        txn.commit()?;
        files.remove(seq, hash)?;
        crate::info!("removed", "blob": hash.hex(), "size": rec.size);
        removed.push(rec);
    }
    Ok(removed)
}

/// A new file only its owner can read: what's preserved may be evidence.
fn private(path: &Path) -> Result<std::fs::File> {
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?)
}

/// A ban's work within `txn`: the blobs it takes out are returned, their
/// files for the caller to remove once it commits. Everything is found and
/// preserved before anything is written, so if a copy fails, `txn` is as it
/// was, and can be committed with whatever else it holds.
pub fn ban_txn(
    store: &Store,
    files: &Files,
    txn: &mut RwTxn<'_>,
    targets: &[Banned],
    reason: &str,
    preserve: Option<&Path>,
    at: u64,
) -> Result<Vec<(u64, Record)>> {
    ban_txn_with(store, files, txn, targets, reason, preserve, at, false).map(|(doomed, _)| doomed)
}

/// `ban_txn`, and with `uploaders`, the owners of the blobs named too, found
/// in the same transaction, so none who uploads one meanwhile is missed.
/// And how many uploaders that was.
#[allow(clippy::too_many_arguments)]
fn ban_txn_with(
    store: &Store,
    files: &Files,
    txn: &mut RwTxn<'_>,
    targets: &[Banned],
    reason: &str,
    preserve: Option<&Path>,
    at: u64,
    uploaders: bool,
) -> Result<(Vec<(u64, Record)>, usize)> {
    if let Some(dir) = preserve {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .and_then(|()| {
                std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            })
            .with_context(|| format!("Could not make {} private", dir.display()))?;
    }
    // The blobs named, as against the rest of an uploader's, kept as context.
    let flagged: Vec<Hash> = targets
        .iter()
        .filter_map(|t| match t {
            Banned::Blob(h) => Some(*h),
            Banned::Pubkey(_) => None,
        })
        .collect();
    let mut targets = targets.to_vec();
    let mut found = BTreeSet::new();
    if uploaders {
        for hash in &flagged {
            if let Some(seq) = store.seq_of(txn, hash)? {
                found.extend(store.owners_of(txn, seq)?);
            }
        }
        for pk in &found {
            if !targets.contains(&Banned::Pubkey(*pk)) {
                targets.push(Banned::Pubkey(*pk));
            }
        }
    }
    let banned: BTreeSet<[u8; 32]> = targets
        .iter()
        .filter_map(|t| match t {
            Banned::Pubkey(pk) => Some(*pk),
            Banned::Blob(_) => None,
        })
        .collect();
    // Removed and banned; and kept, with the banned uploaders taken off.
    let mut doomed: BTreeMap<u64, Record> = BTreeMap::new();
    let mut disowned: BTreeMap<u64, Record> = BTreeMap::new();
    for target in &targets {
        let seqs = match target {
            Banned::Blob(h) => store.seq_of(txn, h)?.into_iter().collect(),
            Banned::Pubkey(pk) => store.owned(txn, pk)?,
        };
        crate::info!("banned", "target": describe(target), "blobs": seqs.len());
        for seq in seqs {
            let Some(rec) = store.record(txn, seq)? else {
                continue;
            };
            let named = matches!(target, Banned::Blob(_));
            let others = store
                .owners_of(txn, seq)?
                .iter()
                .any(|o| !banned.contains(o));
            if named || !others {
                doomed.insert(seq, rec);
            } else {
                disowned.insert(seq, rec);
            }
        }
    }
    disowned.retain(|seq, _| !doomed.contains_key(seq));
    // Each blob's owners, only the banned ones unless it's named, and why.
    let mut each = Vec::with_capacity(doomed.len() + disowned.len());
    for (seq, rec) in doomed.iter().chain(&disowned) {
        let owners: Vec<[u8; 32]> = store
            .owners_of(txn, *seq)?
            .into_iter()
            .filter(|o| flagged.contains(&rec.hash) || banned.contains(o))
            .collect();
        let why = if flagged.contains(&rec.hash) {
            reason.to_string()
        } else {
            match reason {
                "" => "uploader banned".to_string(),
                r => format!("uploader banned: {r}"),
            }
        };
        each.push((*seq, rec, owners, why));
    }
    if let Some(dir) = preserve {
        for (seq, rec, owners, why) in &each {
            let reports = store.reports_of(txn, &rec.hash)?;
            let context_of: &[Hash] = if flagged.contains(&rec.hash) {
                &[]
            } else {
                &flagged
            };
            let copied = match store.body(txn, *seq)? {
                Some(b) => keep(dir, &rec.hash, &mut &b[..]),
                None => blobs::open_noatime(&files.path(&rec.hash, false))
                    .map_err(anyhow::Error::from)
                    .and_then(|mut f| keep(dir, &rec.hash, &mut f)),
            };
            copied
                .and_then(|()| record(dir, rec, owners, &reports, at, why, context_of))
                .with_context(|| format!("Could not preserve {}", rec.hash.hex()))?;
        }
        // The copies' names, as well as their bytes, survive a crash.
        std::fs::File::open(dir)?.sync_all()?;
    }
    for target in &targets {
        store.ban(txn, &entry_for(*target, at, reason))?;
    }
    for (seq, rec, owners, why) in &each {
        if doomed.contains_key(seq) {
            store.ban(txn, &entry_for(Banned::Blob(rec.hash), at, why))?;
            store.remove(txn, *seq, rec)?;
        } else {
            for pk in owners {
                store.remove_owner(txn, *seq, rec.uploaded, pk)?;
            }
            crate::info!("disowned", "blob": rec.hash.hex(), "owners": owners.len());
        }
    }
    Ok((doomed.into_iter().collect(), found.len()))
}

/// What following a page of a peer's decisions came to.
#[derive(Default)]
pub struct Followed {
    pub banned: usize,
    pub unbanned: usize,
    pub removed: Vec<Record>,
}

/// Carry out a page of a peer's decisions (see `peers`), each that's newer
/// than this server's own on its target, as of when the peer made it: a ban
/// as `ban_in` would, preserving to `evidence` first if it's for CSAM; an
/// unban as `unban_in`. Not a ban whose reason starts with one of `skip`,
/// nor a ban of a key in `exempt`. In one commit with how far it got.
#[allow(clippy::too_many_arguments)]
pub fn follow(
    store: &Store,
    files: &Files,
    decisions: &[crate::store::Decision],
    peer: &str,
    skip: &[String],
    exempt: &std::collections::HashSet<[u8; 32]>,
    evidence: &Path,
) -> Result<Followed> {
    let mut txn = store.write_txn()?;
    let mut out = Followed::default();
    let mut doomed = Vec::new();
    for d in decisions {
        if store
            .decided_at(&txn, d.target)?
            .is_some_and(|at| at >= d.at)
        {
            continue;
        }
        let Some(ban) = &d.ban else {
            if store.unban_at(&mut txn, &d.target, d.at)? {
                crate::info!("peer_unbanned", "peer": peer, "target": describe(&d.target));
                out.unbanned += 1;
            }
            continue;
        };
        if skip.iter().any(|p| ban.reason.starts_with(p.as_str())) {
            continue;
        }
        if let Banned::Pubkey(pk) = d.target
            && exempt.contains(&pk)
        {
            crate::info!("peer_ban_exempt", "peer": peer, "target": describe(&d.target));
            continue;
        }
        let stored = match d.target {
            Banned::Blob(h) => store.seq_of(&txn, &h)?.is_some(),
            Banned::Pubkey(pk) => !store.owned(&txn, &pk)?.is_empty(),
        };
        if stored {
            crate::info!("peer_banned", "peer": peer, "target": describe(&d.target), "reason": ban.reason);
            let preserve = ban.reason.starts_with("CSAM").then_some(evidence);
            let (gone, _) = ban_txn_with(
                store,
                files,
                &mut txn,
                &[d.target],
                &ban.reason,
                preserve,
                d.at,
                false,
            )?;
            doomed.extend(gone);
        } else {
            store.ban(&mut txn, &entry_for(d.target, d.at, &ban.reason))?;
        }
        out.banned += 1;
    }
    if let Some(last) = decisions.last() {
        store.set_peer_cursor(&mut txn, peer, &last.cursor)?;
    }
    txn.commit()?;
    for (seq, rec) in doomed {
        files.remove(seq, &rec.hash)?;
        crate::info!("removed", "blob": rec.hash.hex(), "size": rec.size);
        out.removed.push(rec);
    }
    Ok(out)
}

/// Copy a blob's bytes to `dir/<sha256>`, only its owner able to read it,
/// durably, and check the copy's hash.
pub fn keep(dir: &Path, hash: &Hash, from: &mut impl Read) -> Result<()> {
    let to = dir.join(hash.hex());
    std::io::copy(from, &mut private(&to)?)?;
    std::fs::File::open(&to)?.sync_all()?;
    let mut f = std::fs::File::open(&to)?;
    let (mut h, mut buf) = (Hasher::new(), vec![0; 1 << 20]);
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let got: Hash = h.finish();
    if got != *hash {
        bail!("its copy hashes to {}", got.hex());
    }
    crate::info!("preserved", "blob": hash.hex(), "to": to.display().to_string());
    Ok(())
}

/// Write what's known of a blob beside its copy, as `dir/<sha256>.json`:
/// the removal takes its owners with it, and a report needs them. A blob
/// kept only as context, as another of an uploader's, names the blobs
/// banned (`context_of`).
fn record(
    dir: &Path,
    rec: &Record,
    owners: &[[u8; 32]],
    reports: &[Vec<u8>],
    at: u64,
    reason: &str,
    context_of: &[Hash],
) -> Result<()> {
    let reports: Vec<serde_json::Value> = reports
        .iter()
        .map(|r| {
            serde_json::from_slice(r)
                .unwrap_or_else(|_| String::from_utf8_lossy(r).into_owned().into())
        })
        .collect();
    let json = serde_json::json!({
        "sha256": rec.hash.hex(),
        "size": rec.size,
        "type": rec.mime,
        "uploaded": rec.uploaded,
        "owners": owners.iter().map(hex::encode).collect::<Vec<_>>(),
        "reports": reports,
        "banned": at,
        "reason": reason,
        "context_of": context_of.iter().map(Hash::hex).collect::<Vec<_>>(),
    });
    write_record(&dir.join(format!("{}.json", rec.hash.hex())), &json)
}

fn write_record(path: &Path, json: &serde_json::Value) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut f = private(&tmp)?;
    serde_json::to_writer_pretty(&mut f, json)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Every record kept in `dir`, newest ban first: none if there's no `dir`.
/// One that won't read is logged and passed over, not the end of the rest.
pub fn evidence(dir: &Path) -> Result<Vec<serde_json::Value>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut all = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json") {
            let json = std::fs::read(&path)
                .map_err(anyhow::Error::from)
                .and_then(|b| Ok(serde_json::from_slice::<serde_json::Value>(&b)?));
            match json {
                Ok(json) if json["sha256"].is_string() => all.push(json),
                Ok(_) => {
                    crate::warn!("evidence_unreadable", "file": path.display().to_string(), "error": "not a record")
                }
                Err(e) => {
                    crate::warn!("evidence_unreadable", "file": path.display().to_string(), "error": format!("{e:#}"))
                }
            }
        }
    }
    all.sort_by_key(|r| std::cmp::Reverse(r["banned"].as_u64().unwrap_or(0)));
    Ok(all)
}

/// Note on a banned blob's record, and on those kept as its context, the
/// CyberTipline report that names it, made `at`: the year they're kept for
/// counts from then. How many records it was noted on.
pub fn reported(dir: &Path, hash: &Hash, id: &str, at: u64) -> Result<usize> {
    let hex = hash.hex();
    let mut noted = 0;
    for mut rec in evidence(dir)? {
        let ours = rec["sha256"] == hex.as_str()
            || rec["context_of"]
                .as_array()
                .is_some_and(|c| c.iter().any(|h| h == hex.as_str()));
        if !ours {
            continue;
        }
        rec["reported"] = serde_json::json!({ "id": id, "at": at });
        let name = rec["sha256"]
            .as_str()
            .context("A record without its hash")?;
        write_record(&dir.join(format!("{name}.json")), &rec)?;
        noted += 1;
    }
    if noted > 0 {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(noted)
}

/// How long evidence is kept after its report: 18 U.S.C. § 2258A(h).
pub const KEEP_FOR: u64 = 365 * 86400;

/// Delete evidence whose report was made `KEEP_FOR` before `now`: each
/// copy and its record. What's never been reported is kept. The hashes
/// deleted.
pub fn expire(dir: &Path, now: u64) -> Result<Vec<String>> {
    let mut gone = Vec::new();
    for rec in evidence(dir)? {
        let Some(at) = rec["reported"]["at"].as_u64() else {
            continue;
        };
        if at + KEEP_FOR > now {
            continue;
        }
        let hex = rec["sha256"]
            .as_str()
            .context("A record without its hash")?;
        // Only a hash names a copy here, never a path.
        if Hash::parse(hex.as_bytes()).is_none() {
            continue;
        }
        match std::fs::remove_file(dir.join(hex)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        std::fs::remove_file(dir.join(format!("{hex}.json")))?;
        crate::info!("evidence_expired", "blob": hex, "reported": at);
        gone.push(hex.to_string());
    }
    if !gone.is_empty() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(gone)
}

/// Lift bans. An uploader's blobs, banned with it, stay banned.
pub fn unban(config: &Config, targets: &[Banned]) -> Result<()> {
    unban_in(&Store::open(&config.data)?, targets)
}

pub fn unban_in(store: &Store, targets: &[Banned]) -> Result<()> {
    let mut txn = store.write_txn()?;
    for target in targets {
        let was = store.unban(&mut txn, target)?;
        crate::info!("unbanned", "target": describe(target), "was_banned": was);
    }
    txn.commit()?;
    Ok(())
}

/// Every ban, a line each: `blob|pubkey <hex> <unix seconds> <reason>`.
pub fn list(config: &Config) -> Result<()> {
    let store: &'static Store = Box::leak(Box::new(Store::open(&config.data)?));
    for b in store.bans()? {
        let (kind, hex) = match b.target {
            Banned::Blob(h) => ("blob", h.hex()),
            Banned::Pubkey(pk) => ("pubkey", hex::encode(pk)),
        };
        println!("{kind}\t{hex}\t{}\t{}", b.at, b.reason);
    }
    Ok(())
}

fn entry_for(target: Banned, at: u64, reason: &str) -> Ban {
    Ban {
        target,
        at,
        reason: reason.to_string(),
    }
}

fn describe(target: &Banned) -> String {
    match target {
        Banned::Blob(h) => format!("blob:{}", h.hex()),
        Banned::Pubkey(pk) => format!("pubkey:{}", hex::encode(pk)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_goes_a_year_after_its_report_and_not_before() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (Hash::of(b"reported"), Hash::of(b"never reported"));
        for h in [a, b] {
            let rec = Record {
                hash: h,
                size: 1,
                uploaded: 0,
                mime: None,
                flags: 0,
                br_size: 0,
            };
            std::fs::write(dir.path().join(h.hex()), b"x").unwrap();
            record(dir.path(), &rec, &[], &[], 0, "CSAM", &[]).unwrap();
        }
        reported(dir.path(), &a, "123", 1000).unwrap();
        assert!(expire(dir.path(), 1000 + KEEP_FOR - 1).unwrap().is_empty());
        assert_eq!(expire(dir.path(), 1000 + KEEP_FOR).unwrap(), [a.hex()]);
        assert!(!dir.path().join(a.hex()).exists());
        assert!(!dir.path().join(format!("{}.json", a.hex())).exists());
        // Unreported, it's kept however long it's been.
        assert!(expire(dir.path(), u64::MAX / 2).unwrap().is_empty());
        assert!(dir.path().join(b.hex()).exists());
    }
}
