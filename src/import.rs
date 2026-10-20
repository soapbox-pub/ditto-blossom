//! `ditto-blossom import`: take over a blossom-server's blobs.
//!
//! Reads its SQLite database (blobs and owners) and its flat blob directory
//! (`<sha256>[.ext]`), and adds every blob not here yet: small ones copied
//! inline, the rest hard-linked into place, so nothing is copied when both
//! are on one filesystem. Blobs already here only gain owners, so it can be
//! run again to catch up before a cutover.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};

use crate::blobs::{self, Files};
use crate::config::Config;
use crate::hash::{Hash, Hasher};
use crate::mime;
use crate::store::{INLINE_MAX, Record, Store, flag};

const BATCH: usize = 5000;

#[derive(Default, Debug)]
struct Counts {
    added: u64,
    inline: u64,
    present: u64,
    owners: u64,
    missing: u64,
    unreadable: u64,
    corrupt: u64,
    sniffed: u64,
    banned: u64,
}

pub fn run(config: &Config, sqlite: &Path, dir: &Path, copy: bool, verify: bool) -> Result<()> {
    let started = Instant::now();
    let store: &'static Store = Box::leak(Box::new(Store::open(&config.data)?));
    let files = Files::open(&config.data, 1, false)?;
    let db = Connection::open_with_flags(sqlite, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("Could not open {}", sqlite.display()))?;

    crate::info!("import_listing", "dir": dir.display().to_string());
    let mut on_disk: HashMap<Hash, PathBuf> = HashMap::new();
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let Some(hash) = name
            .to_str()
            .and_then(|n| n.get(..64))
            .and_then(|h| Hash::parse(h.as_bytes()))
        else {
            continue;
        };
        on_disk.insert(hash, entry.path());
    }

    let mut owners: HashMap<Hash, Vec<[u8; 32]>> = HashMap::new();
    {
        let mut q = db.prepare("SELECT blob, pubkey FROM owners")?;
        let mut rows = q.query([])?;
        while let Some(r) = rows.next()? {
            let (blob, pubkey): (String, String) = (r.get(0)?, r.get(1)?);
            let (Some(blob), Ok(pk)) = (Hash::parse(blob.as_bytes()), hex::decode(&pubkey)) else {
                continue;
            };
            if let Ok(pk) = <[u8; 32]>::try_from(pk) {
                owners.entry(blob).or_default().push(pk);
            }
        }
    }
    crate::info!("import_started", "files": on_disk.len(), "owned_blobs": owners.len());

    let mut q =
        db.prepare("SELECT sha256, size, type, uploaded FROM blobs ORDER BY uploaded, sha256")?;
    let mut rows = q.query([])?;
    let mut counts = Counts::default();
    let mut batch: Vec<(Hash, Option<String>, u64)> = Vec::with_capacity(BATCH);
    loop {
        let row = rows.next()?;
        if let Some(r) = row {
            let hex: String = r.get(0)?;
            if let Some(hash) = Hash::parse(hex.as_bytes()) {
                let ty: Option<String> = r.get(2)?;
                let uploaded: i64 = r.get(3)?;
                batch.push((hash, ty, uploaded.max(0) as u64));
            }
        }
        if batch.len() == BATCH || (row.is_none() && !batch.is_empty()) {
            write_batch(
                store,
                &files,
                &batch,
                &on_disk,
                &owners,
                copy,
                verify,
                &mut counts,
            )?;
            batch.clear();
            crate::info!("import_progress", "added": counts.added, "present": counts.present, "missing": counts.missing, "unreadable": counts.unreadable, "corrupt": counts.corrupt, "banned": counts.banned);
        }
        if row.is_none() {
            break;
        }
    }
    // Hard links' directory entries, made outside any database commit.
    let data = std::fs::File::open(&config.data)?;
    // SAFETY: syncfs on an open descriptor.
    unsafe { libc::syncfs(std::os::fd::AsRawFd::as_raw_fd(&data)) };
    crate::info!(
        "import_finished",
        "added": counts.added, "inline": counts.inline, "present": counts.present, "owners_added": counts.owners,
        "missing": counts.missing, "unreadable": counts.unreadable, "corrupt": counts.corrupt, "sniffed": counts.sniffed,
        "banned": counts.banned, "seconds": started.elapsed().as_secs()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_batch(
    store: &'static Store,
    files: &Files,
    batch: &[(Hash, Option<String>, u64)],
    on_disk: &HashMap<Hash, PathBuf>,
    owners: &HashMap<Hash, Vec<[u8; 32]>>,
    copy: bool,
    verify: bool,
    counts: &mut Counts,
) -> Result<()> {
    let mut txn = store.write_txn()?;
    for (hash, ty, uploaded) in batch {
        if store.banned(&txn, Some(hash), None)? {
            counts.banned += 1;
            continue;
        }
        let mut pks = Vec::new();
        for pk in owners.get(hash).into_iter().flatten() {
            if !store.banned(&txn, None, Some(pk))? {
                pks.push(*pk);
            }
        }
        let pks = &pks;
        if let Some(seq) = store.seq_of(&txn, hash)? {
            counts.present += 1;
            let rec = store
                .record(&txn, seq)?
                .context("a blob without its record")?;
            for pk in pks {
                counts.owners += u64::from(store.add_owner(&mut txn, seq, rec.uploaded, pk)?);
            }
            continue;
        }
        let Some(path) = on_disk.get(hash) else {
            counts.missing += 1;
            continue;
        };
        // A file this user may not read is that file's problem, not the
        // import's: say so and go on.
        if let Err(e) = blobs::open_noatime(path) {
            crate::warn!("import_unreadable", "path": path.display().to_string(), "error": e.to_string());
            counts.unreadable += 1;
            continue;
        }
        let size = std::fs::metadata(path)?.len();
        let small = size as usize <= INLINE_MAX;
        let body = if small {
            Some(std::fs::read(path)?)
        } else {
            None
        };
        if small || verify {
            let actual = match &body {
                Some(b) => Hash::of(b),
                None => hash_file(path)?,
            };
            if actual != *hash {
                counts.corrupt += 1;
                crate::warn!("import_corrupt", "blob": hash.hex(), "actual": actual.hex());
                continue;
            }
        }
        let mime = match ty.as_deref().and_then(mime::normalize) {
            Some(t) => Some(t),
            None => {
                let mut head = vec![0; 8192];
                let n = blobs::open_noatime(path)?.read(&mut head)?;
                let t = mime::sniff(&head[..n]);
                counts.sniffed += u64::from(t.is_some());
                t
            }
        };
        if !small {
            files.adopt(path, hash, copy).with_context(|| match copy {
                true => format!("Could not copy {}", path.display()),
                false => format!(
                    "Could not link {} into place (on another filesystem? then use --copy)",
                    path.display()
                ),
            })?;
        }
        let rec = Record {
            hash: *hash,
            size,
            uploaded: *uploaded,
            mime,
            flags: if small { flag::INLINE } else { 0 },
            br_size: 0,
        };
        let seq = store.next_seq(&txn)?;
        store.insert(&mut txn, seq, &rec, body.as_deref())?;
        for pk in pks {
            counts.owners += u64::from(store.add_owner(&mut txn, seq, rec.uploaded, pk)?);
        }
        counts.added += 1;
        counts.inline += u64::from(small);
    }
    txn.commit()?;
    Ok(())
}

fn hash_file(path: &Path) -> Result<Hash> {
    let mut f = blobs::open_noatime(path)?;
    let mut h = Hasher::new();
    let mut buf = vec![0; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finish());
        }
        h.update(&buf[..n]);
    }
}

/// `ditto-blossom remove`: take blobs out entirely, whoever owns them, as a
/// moderator would, or to carry deletes over from another server. Safe beside
/// a running server: once the record is gone it answers 404.
pub fn remove(config: &Config, hashes: &[Hash]) -> Result<()> {
    let store: &'static Store = Box::leak(Box::new(Store::open(&config.data)?));
    let files = Files::open(&config.data, 1, false)?;
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
    }
    Ok(())
}
