//! `ditto-blossom ban`, `unban` and `bans`: keep blobs and uploaders out
//! for good. Safe beside a running server, as `remove` is: the writer checks
//! the bans in the transaction that would store a blob, so nothing banned
//! gets in once the ban is committed.

use std::collections::BTreeMap;

use anyhow::Result;

use crate::blobs::Files;
use crate::config::Config;
use crate::store::{Ban, Banned, Record, Store};
use crate::upload::now;

/// Ban each target and take out what it names: a blob, or every blob an
/// uploader owns, whoever else owns it. A banned uploader's blobs are
/// banned too, so another key can't put them back.
pub fn ban(config: &Config, targets: &[Banned], reason: &str) -> Result<()> {
    let store = Store::open(&config.data)?;
    let files = Files::open(&config.data, 1, false)?;
    ban_in(&store, &files, targets, reason)
}

pub fn ban_in(store: &Store, files: &Files, targets: &[Banned], reason: &str) -> Result<()> {
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
