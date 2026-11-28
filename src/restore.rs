//! `ditto-blossom restore`: put back blobs a ban took out by mistake, from
//! the copies it preserved. Safe beside a running server, as `ban` is.
//!
//! Each `<sha256>` file in the directory is unbanned, linked back into
//! place (or, if small, read back into the database) and given back to its
//! owners: those its `<sha256>.json` names, else `--owner`. Then the copy
//! is removed. What `--except` names stays banned and preserved: the blob
//! that really was what it was banned for.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};

use crate::blobs::{self, Files};
use crate::config::Config;
use crate::hash::{Hash, Hasher};
use crate::mime;
use crate::store::{Banned, INLINE_MAX, Record, Store, flag};
use crate::upload::now;

/// Blobs put back a transaction.
const BATCH: usize = 500;

#[derive(Default, Debug)]
pub struct Counts {
    pub restored: u64,
    /// Already here again (uploaded since): given its owners back.
    pub present: u64,
    pub kept: u64,
    pub corrupt: u64,
}

pub fn run(
    config: &Config,
    dir: &Path,
    owners: &[[u8; 32]],
    except: &[Hash],
    verify: bool,
) -> Result<Counts> {
    let store = Store::open(&config.data)?;
    let files = Files::open(&config.data, 1, false)?;
    restore_in(&store, &files, dir, owners, except, verify)
}

pub fn restore_in(
    store: &Store,
    files: &Files,
    dir: &Path,
    owners: &[[u8; 32]],
    except: &[Hash],
    verify: bool,
) -> Result<Counts> {
    let except: HashSet<Hash> = except.iter().copied().collect();
    let mut hashes = Vec::new();
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))?
    {
        let name = entry?.file_name();
        if let Some(h) = name.to_str().and_then(|n| Hash::parse(n.as_bytes()))
            && name.len() == 64
        {
            hashes.push(h);
        }
    }
    hashes.sort();
    crate::info!("restore_started", "dir": dir.display().to_string(), "blobs": hashes.len());
    let mut counts = Counts::default();
    for chunk in hashes.chunks(BATCH) {
        let mut done = Vec::new();
        let mut txn = store.write_txn()?;
        for hash in chunk {
            if except.contains(hash) {
                counts.kept += 1;
                continue;
            }
            let path = dir.join(hash.hex());
            let meta = read_meta(dir, hash);
            let mut pks: Vec<[u8; 32]> = meta
                .as_ref()
                .and_then(|m| m["owners"].as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(|o| hex::decode(o.as_str()?).ok()?.try_into().ok())
                .collect();
            if pks.is_empty() {
                pks = owners.to_vec();
            }
            if let Some(seq) = store.seq_of(&txn, hash)? {
                store.unban(&mut txn, &Banned::Blob(*hash))?;
                let rec = store
                    .record(&txn, seq)?
                    .context("a blob without its record")?;
                for pk in &pks {
                    store.add_owner(&mut txn, seq, rec.uploaded, pk)?;
                }
                counts.present += 1;
                done.push(*hash);
                continue;
            }
            let size = std::fs::metadata(&path)?.len();
            let small = size as usize <= INLINE_MAX;
            let body = if small {
                Some(std::fs::read(&path)?)
            } else {
                None
            };
            if small || verify {
                let actual = match &body {
                    Some(b) => Hash::of(b),
                    None => hash_file(&path)?,
                };
                if actual != *hash {
                    crate::warn!("restore_corrupt", "blob": hash.hex(), "actual": actual.hex());
                    counts.corrupt += 1;
                    continue;
                }
            }
            let declared = meta
                .as_ref()
                .and_then(|m| m["type"].as_str().and_then(mime::normalize));
            let mime = match declared {
                Some(t) => Some(t),
                None => {
                    let mut head = vec![0; 8192];
                    let n = blobs::open_noatime(&path)?.read(&mut head)?;
                    mime::sniff(&head[..n])
                }
            };
            if !small {
                files.adopt(&path, hash, false).with_context(|| {
                    format!("Could not link {} back into place", path.display())
                })?;
            }
            let uploaded = meta
                .as_ref()
                .and_then(|m| m["uploaded"].as_u64())
                .unwrap_or_else(now);
            let rec = Record {
                hash: *hash,
                size,
                uploaded,
                mime,
                flags: if small { flag::INLINE } else { 0 },
                br_size: 0,
            };
            store.unban(&mut txn, &Banned::Blob(*hash))?;
            let seq = store.next_seq(&txn)?;
            store.insert(&mut txn, seq, &rec, body.as_deref())?;
            for pk in &pks {
                store.add_owner(&mut txn, seq, rec.uploaded, pk)?;
            }
            counts.restored += 1;
            done.push(*hash);
        }
        if !done.is_empty() {
            files.sync()?;
        }
        txn.commit()?;
        // Back in place: the copy (a second link, for a large blob) goes.
        for hash in done {
            let _ = std::fs::remove_file(dir.join(hash.hex()));
            let _ = std::fs::remove_file(dir.join(format!("{}.json", hash.hex())));
        }
        crate::info!("restore_progress", "restored": counts.restored, "present": counts.present, "kept": counts.kept, "corrupt": counts.corrupt);
    }
    crate::info!("restore_done", "restored": counts.restored, "present": counts.present, "kept": counts.kept, "corrupt": counts.corrupt);
    Ok(counts)
}

fn read_meta(dir: &Path, hash: &Hash) -> Option<serde_json::Value> {
    let bytes = std::fs::read(dir.join(format!("{}.json", hash.hex()))).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn hash_file(path: &Path) -> Result<Hash> {
    let mut f = blobs::open_noatime(path)?;
    let (mut h, mut buf) = (Hasher::new(), vec![0; 1 << 20]);
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finish());
        }
        h.update(&buf[..n]);
    }
}

#[cfg(test)]
mod tests {
    use crate::e2e::{client, put, start};
    use crate::hash::Hash;
    use crate::store::Banned;

    #[tokio::test]
    async fn puts_back_what_a_ban_took_but_the_blob_it_was_for() {
        let s = start("").await;
        let c = client();
        let pk = [7u8; 32];
        let small = b"a small blob of theirs".to_vec();
        let large: Vec<u8> = (0..300_000u32).map(|i| (i * 11 % 256) as u8).collect();
        let bad = b"the one it was for".to_vec();
        for data in [&small, &large, &bad] {
            let h = put(s.app, data, Some("image/png"));
            let mut txn = s.app.store.write_txn().unwrap();
            let seq = s.app.store.seq_of(&txn, &h).unwrap().unwrap();
            s.app
                .store
                .add_owner(&mut txn, seq, 1_760_000_000, &pk)
                .unwrap();
            txn.commit().unwrap();
        }
        let kept = tempfile::tempdir().unwrap();
        crate::moderate::ban_in(
            s.app.store,
            s.app.files,
            &[
                Banned::Blob(Hash::of(&small)),
                Banned::Blob(Hash::of(&large)),
                Banned::Blob(Hash::of(&bad)),
            ],
            "test",
            Some(kept.path()),
            &Default::default(),
        )
        .unwrap();
        let get = |h: Hash| c.get(format!("{}/{}", s.url, h.hex())).send();
        assert_eq!(get(Hash::of(&large)).await.unwrap().status(), 404);

        let counts = super::restore_in(
            s.app.store,
            s.app.files,
            kept.path(),
            &[],
            &[Hash::of(&bad)],
            true,
        )
        .unwrap();
        assert_eq!((counts.restored, counts.kept, counts.corrupt), (2, 1, 0));
        for data in [&small, &large] {
            let r = get(Hash::of(data)).await.unwrap();
            assert_eq!(r.status(), 200);
            assert_eq!(&r.bytes().await.unwrap()[..], &data[..]);
            assert!(s.app.store.is_owner(&Hash::of(data), &pk).unwrap());
            assert!(!s.app.store.is_banned(Some(&Hash::of(data)), None).unwrap());
            assert!(!kept.path().join(Hash::of(data).hex()).exists());
        }
        // The blob it was for stays out, and its copy stays.
        assert_eq!(get(Hash::of(&bad)).await.unwrap().status(), 404);
        assert!(s.app.store.is_banned(Some(&Hash::of(&bad)), None).unwrap());
        assert!(kept.path().join(Hash::of(&bad).hex()).exists());
    }
}
