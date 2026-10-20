//! `ditto-blossom ban`, `unban` and `bans`: keep blobs and uploaders out
//! for good. Safe beside a running server, as `remove` is: the writer checks
//! the bans in the transaction that would store a blob, so nothing banned
//! gets in once the ban is committed.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::blobs::{self, Files};
use crate::config::Config;
use crate::hash::{Hash, Hasher};
use crate::store::{Ban, Banned, Record, Store};
use crate::upload::now;

/// Ban each target and take out what it names: a blob, or every blob an
/// uploader owns, whoever else owns it. A banned uploader's blobs are
/// banned too, so another key can't put them back. With `preserve`, each
/// blob is copied there, and its copy checked, before anything is removed.
pub fn ban(
    config: &Config,
    targets: &[Banned],
    reason: &str,
    preserve: Option<&Path>,
) -> Result<()> {
    let store = Store::open(&config.data)?;
    let files = Files::open(&config.data, 1, false)?;
    ban_in(&store, &files, targets, reason, preserve)
}

pub fn ban_in(
    store: &Store,
    files: &Files,
    targets: &[Banned],
    reason: &str,
    preserve: Option<&Path>,
) -> Result<()> {
    let at = now();
    let entry = |target| Ban {
        target,
        at,
        reason: reason.to_string(),
    };
    let mut txn = store.write_txn()?;
    let mut doomed: BTreeMap<u64, Record> = BTreeMap::new();
    for target in targets {
        store.ban(&mut txn, &entry(*target))?;
        let seqs = match target {
            Banned::Blob(h) => store.seq_of(&txn, h)?.into_iter().collect(),
            Banned::Pubkey(pk) => store.owned(&txn, pk)?,
        };
        crate::info!("banned", "target": describe(target), "blobs": seqs.len());
        for seq in seqs {
            if let Some(rec) = store.record(&txn, seq)? {
                doomed.insert(seq, rec);
            }
        }
    }
    for (seq, rec) in &doomed {
        // Within the transaction, so nothing is removed that wasn't copied.
        if let Some(dir) = preserve {
            let body = store.body(&txn, *seq)?;
            keep(files, dir, rec, body)
                .with_context(|| format!("Could not preserve {}", rec.hash.hex()))?;
        }
        store.ban(&mut txn, &entry(Banned::Blob(rec.hash)))?;
        store.remove(&mut txn, *seq, rec)?;
    }
    txn.commit()?;
    for (seq, rec) in doomed {
        files.remove(seq, &rec.hash)?;
        crate::info!("removed", "blob": rec.hash.hex(), "size": rec.size);
    }
    Ok(())
}

/// Copy a blob to `dir/<sha256>`, durably, and check the copy's hash.
fn keep(files: &Files, dir: &Path, rec: &Record, body: Option<Vec<u8>>) -> Result<()> {
    let to = dir.join(rec.hash.hex());
    match body {
        Some(b) => std::fs::write(&to, b)?,
        None => {
            std::io::copy(
                &mut blobs::open_noatime(&files.path(&rec.hash, false))?,
                &mut std::fs::File::create(&to)?,
            )?;
        }
    }
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
    if got != rec.hash {
        bail!("its copy hashes to {}", got.hex());
    }
    crate::info!("preserved", "blob": rec.hash.hex(), "size": rec.size, "to": to.display().to_string());
    Ok(())
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

fn describe(target: &Banned) -> String {
    match target {
        Banned::Blob(h) => format!("blob:{}", h.hex()),
        Banned::Pubkey(pk) => format!("pubkey:{}", hex::encode(pk)),
    }
}
