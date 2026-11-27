//! `ditto-blossom ban`, `unban` and `bans`: keep blobs and uploaders out
//! for good. Safe beside a running server, as `remove` is: the writer checks
//! the bans in the transaction that would store a blob, so nothing banned
//! gets in once the ban is committed. The server bans the same way, through
//! its writer, when a scan finds a match.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::blobs::{self, Files};
use crate::config::Config;
use crate::hash::{Hash, Hasher};
use crate::lmdb::RwTxn;
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
    let mut txn = store.write_txn()?;
    let doomed = ban_txn(store, files, &mut txn, targets, reason, preserve, now())?;
    txn.commit()?;
    for (seq, rec) in doomed {
        files.remove(seq, &rec.hash)?;
        crate::info!("removed", "blob": rec.hash.hex(), "size": rec.size);
    }
    Ok(())
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
    let entry = |target| Ban {
        target,
        at,
        reason: reason.to_string(),
    };
    let mut doomed: BTreeMap<u64, Record> = BTreeMap::new();
    for target in targets {
        let seqs = match target {
            Banned::Blob(h) => store.seq_of(txn, h)?.into_iter().collect(),
            Banned::Pubkey(pk) => store.owned(txn, pk)?,
        };
        crate::info!("banned", "target": describe(target), "blobs": seqs.len());
        for seq in seqs {
            if let Some(rec) = store.record(txn, seq)? {
                doomed.insert(seq, rec);
            }
        }
    }
    if let Some(dir) = preserve {
        for (seq, rec) in &doomed {
            let copied = match store.body(txn, *seq)? {
                Some(b) => keep(dir, &rec.hash, &mut &b[..]),
                None => blobs::open_noatime(&files.path(&rec.hash, false))
                    .map_err(anyhow::Error::from)
                    .and_then(|mut f| keep(dir, &rec.hash, &mut f)),
            };
            copied.with_context(|| format!("Could not preserve {}", rec.hash.hex()))?;
        }
    }
    for target in targets {
        store.ban(txn, &entry(*target))?;
    }
    for (seq, rec) in &doomed {
        store.ban(txn, &entry(Banned::Blob(rec.hash)))?;
        store.remove(txn, *seq, rec)?;
    }
    Ok(doomed.into_iter().collect())
}

/// Copy a blob's bytes to `dir/<sha256>`, durably, and check the copy's
/// hash.
pub fn keep(dir: &Path, hash: &Hash, from: &mut impl Read) -> Result<()> {
    let to = dir.join(hash.hex());
    std::io::copy(from, &mut std::fs::File::create(&to)?)?;
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
