//! Blob metadata, and the bytes of small blobs, in LMDB.
//!
//! A durable environment, `meta`, each commit flushed before it returns,
//! and a lazy one, `stats`, that a crash may lose. One durable environment,
//! not ditto-relay's two: each costs its own flushes a commit, and small
//! blobs' bytes (about 1.5 GB of production's) are in tables of their own
//! anyway. Tables:
//!
//! - `blobs`: seq, a native u64 (`INTEGER_KEY`) -> [`Record`]. Seqs only grow,
//!   so new records are appended.
//! - `ids`: sha256 -> seq (u64 LE). Whether a blob is here never reads its
//!   record.
//! - `owners`: pubkey -> `DUPFIXED` stamps, uploaded (u32 BE) then seq (48 bits
//!   BE), so a pubkey's blobs sort oldest first: `/list` pages and counts per
//!   pubkey come straight from the index.
//! - `blob_owners`: seq (u64 BE) -> `DUPFIXED` pubkeys.
//! - `reports`: sha256 then the report's event id -> its JSON.
//! - `info`: `version` -> the layout's version.
//! - `bodies`: seq -> the bytes of a blob up to [`INLINE_MAX`].
//! - `brotli`: seq -> a brotli copy up to [`INLINE_MAX`].
//! - `access` (stats): seq -> the day (u16 LE, since the epoch) it was last read.
//!
//! Reads go through a reset-and-renewed read transaction kept per thread
//! and store ([`Store::read`]), measured at 2.3x a fresh
//! transaction per lookup on eight threads.

use std::cell::RefCell;
use std::path::Path;

use anyhow::{Context, Result, bail};
use bytes::Bytes;

use crate::hash::Hash;
use crate::lmdb::{self, Db, DbFlags, Env, RwTxn, Txn};

/// Blobs up to this size live inline in LMDB rather than as files: reading
/// one costs 0.53 µs against 2.2 µs to open, read and close a file.
pub const INLINE_MAX: usize = 16 << 10;
/// The maps are only address space; files grow as they fill.
const MAP_SIZE: usize = 1 << 40;
const MAX_READERS: u32 = 4096;
const VERSION: &[u8] = b"1";

pub mod flag {
    /// The bytes are in `bodies`, not a file.
    pub const INLINE: u8 = 1;
    /// A brotli copy exists (in `brotli`, or as a `.br` file).
    pub const BROTLI: u8 = 2;
    /// Compression has been tried, whether or not a copy was kept.
    pub const BROTLI_CHECKED: u8 = 4;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub hash: Hash,
    pub size: u64,
    /// Unix seconds of its first upload.
    pub uploaded: u64,
    pub mime: Option<String>,
    pub flags: u8,
    /// The brotli copy's size, with [`flag::BROTLI`].
    pub br_size: u64,
}

const RECORD_V1: u8 = 1;
const FIXED: usize = 60;

impl Record {
    /// `[version, flags, codec, type length] hash size uploaded br_size type`.
    /// The codec byte is 0, raw bytes; it's there so a recompressed tier can
    /// be added without rewriting records.
    pub fn encode(&self) -> Vec<u8> {
        let mime = self.mime.as_deref().unwrap_or("").as_bytes();
        let mut v = Vec::with_capacity(FIXED + mime.len());
        v.extend_from_slice(&[RECORD_V1, self.flags, 0, mime.len() as u8]);
        v.extend_from_slice(&self.hash.0);
        v.extend_from_slice(&self.size.to_le_bytes());
        v.extend_from_slice(&self.uploaded.to_le_bytes());
        v.extend_from_slice(&self.br_size.to_le_bytes());
        v.extend_from_slice(mime);
        v
    }

    pub fn decode(v: &[u8]) -> Option<Record> {
        if v.len() < FIXED || v[0] != RECORD_V1 || v[2] != 0 {
            return None;
        }
        let mime_len = v[3] as usize;
        let mime = v.get(FIXED..FIXED + mime_len)?;
        let u64_at = |i: usize| u64::from_le_bytes(v[i..i + 8].try_into().expect("8 bytes"));
        Some(Record {
            hash: Hash(v[4..36].try_into().expect("32 bytes")),
            size: u64_at(36),
            uploaded: u64_at(44),
            br_size: u64_at(52),
            flags: v[1],
            mime: (mime_len > 0).then(|| String::from_utf8_lossy(mime).into_owned()),
        })
    }

    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

/// An owners entry: when, then which blob.
fn stamp(uploaded: u64, seq: u64) -> [u8; 10] {
    let mut s = [0; 10];
    s[..4].copy_from_slice(&(uploaded.min(u32::MAX as u64) as u32).to_be_bytes());
    s[4..].copy_from_slice(&seq.to_be_bytes()[2..]);
    s
}

fn stamp_parts(s: &[u8]) -> (u64, u64) {
    let uploaded = u32::from_be_bytes(s[..4].try_into().expect("4 bytes")) as u64;
    let mut seq = [0; 8];
    seq[2..].copy_from_slice(&s[4..10]);
    (uploaded, u64::from_be_bytes(seq))
}

/// A blob as a read finds it.
pub struct Found {
    pub seq: u64,
    pub record: Record,
    /// Whether this is its brotli copy.
    pub brotli: bool,
    /// The copy's bytes, if they're inline.
    pub body: Option<Bytes>,
}

pub struct Store {
    env: Env,
    stats: Env,
    blobs: Db,
    ids: Db,
    owners: Db,
    blob_owners: Db,
    reports: Db,
    bodies: Db,
    brotli: Db,
    access: Db,
}

thread_local! {
    /// A renewable reader for each store this thread has read, by address.
    static READERS: RefCell<Vec<(usize, lmdb::Reader<'static>)>> = const { RefCell::new(Vec::new()) };
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store> {
        for sub in ["meta", "stats"] {
            std::fs::create_dir_all(dir.join(sub))
                .with_context(|| format!("Could not create {}", dir.join(sub).display()))?;
        }
        let env = Env::open(
            &dir.join("meta"),
            lmdb::Sync::Durable,
            MAP_SIZE,
            16,
            MAX_READERS,
        )
        .with_context(|| {
            format!(
                "Could not open the database in {}",
                dir.join("meta").display()
            )
        })?;
        let info = env.create_db("info", DbFlags::PLAIN)?;
        let store_env_tables = (
            env.create_db("blobs", DbFlags::INTEGER_KEY)?,
            env.create_db("ids", DbFlags::PLAIN)?,
            env.create_db("owners", DbFlags::DUP_FIXED)?,
            env.create_db("blob_owners", DbFlags::DUP_FIXED)?,
            env.create_db("reports", DbFlags::PLAIN)?,
            env.create_db("bodies", DbFlags::INTEGER_KEY)?,
            env.create_db("brotli", DbFlags::INTEGER_KEY)?,
        );
        {
            let mut txn = env.write_txn()?;
            match txn.get(info, b"version")? {
                None => {
                    txn.put(info, b"version", VERSION)?;
                    txn.commit()?;
                }
                Some(v) if v == VERSION => {}
                Some(v) => bail!(
                    "The database is version {}, this server reads {}",
                    String::from_utf8_lossy(v),
                    String::from_utf8_lossy(VERSION)
                ),
            }
        }
        let (stats, access) = open_stats(&dir.join("stats"))?;
        let (blobs, ids, owners, blob_owners, reports, bodies, brotli) = store_env_tables;
        Ok(Store {
            env,
            stats,
            blobs,
            ids,
            owners,
            blob_owners,
            reports,
            bodies,
            brotli,
            access,
        })
    }

    /// Run `f` in a fresh snapshot of the durable environment, through this
    /// thread's renewable reader. `f` mustn't read the store again itself.
    pub fn read<R>(&'static self, f: impl FnOnce(&Txn<'_>) -> R) -> Result<R> {
        let key = self as *const Store as usize;
        READERS.with(|cell| {
            let mut readers = cell.borrow_mut();
            let i = match readers.iter().position(|(k, _)| *k == key) {
                Some(i) => i,
                None => {
                    readers.push((key, self.env.reader()?));
                    readers.len() - 1
                }
            };
            Ok(readers[i].1.read(f)?)
        })
    }

    /// The blob named `hash`: its brotli copy if `prefer_brotli` and it has
    /// one, else its own bytes; with them, if they're inline.
    pub fn find(&'static self, hash: &Hash, prefer_brotli: bool) -> Result<Option<Found>> {
        self.read(|txn| -> Result<Option<Found>> {
            let Some(seq) = self.seq_of(txn, hash)? else {
                return Ok(None);
            };
            let Some(record) = self.record(txn, seq)? else {
                return Ok(None);
            };
            let brotli = prefer_brotli && record.has(flag::BROTLI);
            let inline = if brotli {
                record.br_size as usize <= INLINE_MAX
            } else {
                record.has(flag::INLINE)
            };
            let table = if brotli { self.brotli } else { self.bodies };
            let body = match inline {
                true => txn
                    .get(table, &seq.to_ne_bytes())?
                    .map(Bytes::copy_from_slice),
                false => None,
            };
            Ok(Some(Found {
                seq,
                record,
                brotli,
                body,
            }))
        })?
    }

    /// How many blobs there are.
    pub fn count(&'static self) -> Result<usize> {
        Ok(self.read(|txn| txn.len(self.ids))??)
    }

    /// A pubkey's blobs, newest first: at most `limit`, uploaded no later
    /// than `until` and no earlier than `since`, and before `after` (a blob
    /// of theirs, as a page's last) if given.
    pub fn list(
        &'static self,
        pubkey: &[u8; 32],
        after: Option<&Hash>,
        limit: usize,
        since: Option<u64>,
        until: Option<u64>,
    ) -> Result<Vec<Record>> {
        self.read(|txn| -> Result<Vec<Record>> {
            // The first stamp not wanted: the cursor's own, or anything after `until`.
            let mut bound: Option<[u8; 10]> = until.map(|u| stamp(u.saturating_add(1), 0));
            if let Some(after) = after {
                let Some(seq) = self.seq_of(txn, after)? else {
                    return Ok(Vec::new());
                };
                let Some(rec) = self.record(txn, seq)? else {
                    return Ok(Vec::new());
                };
                let s = stamp(rec.uploaded, seq);
                bound = Some(bound.map_or(s, |b| b.min(s)));
            }
            let mut cur = txn.cursor(self.owners)?;
            if cur.set(pubkey)?.is_none() {
                return Ok(Vec::new());
            }
            let mut entry = match bound {
                Some(b) => match cur.get_both_range(pubkey, &b)? {
                    Some(_) => cur.prev_dup()?,
                    None => {
                        cur.set(pubkey)?;
                        cur.last_dup()?
                    }
                },
                None => cur.last_dup()?,
            };
            let mut out = Vec::new();
            while let Some((_, s)) = entry {
                let (uploaded, seq) = stamp_parts(s);
                if since.is_some_and(|since| uploaded < since) || out.len() >= limit {
                    break;
                }
                if let Some(rec) = self.record(txn, seq)? {
                    out.push(rec);
                }
                entry = cur.prev_dup()?;
            }
            Ok(out)
        })?
    }

    #[cfg(test)]
    pub fn is_owner(&'static self, hash: &Hash, pubkey: &[u8; 32]) -> Result<bool> {
        self.read(|txn| -> Result<bool> {
            let Some(seq) = self.seq_of(txn, hash)? else {
                return Ok(false);
            };
            self.owned_by(txn, seq, pubkey)
        })?
    }

    // What the writer (and import) use, within their own transactions.

    pub fn write_txn(&self) -> Result<RwTxn<'_>> {
        Ok(self.env.write_txn()?)
    }

    pub fn seq_of(&self, txn: &Txn<'_>, hash: &Hash) -> Result<Option<u64>> {
        Ok(txn
            .get(self.ids, &hash.0)?
            .map(|v| u64::from_le_bytes(v.try_into().unwrap_or_default())))
    }

    pub fn record(&self, txn: &Txn<'_>, seq: u64) -> Result<Option<Record>> {
        match txn.get(self.blobs, &seq.to_ne_bytes())? {
            None => Ok(None),
            Some(v) => Ok(Some(Record::decode(v).context("A blob record is corrupt")?)),
        }
    }

    /// The seq the next new blob gets.
    pub fn next_seq(&self, txn: &Txn<'_>) -> Result<u64> {
        let mut cur = txn.cursor(self.blobs)?;
        Ok(match cur.last()? {
            Some((k, _)) => u64::from_ne_bytes(k.try_into().context("A blob key is corrupt")?) + 1,
            None => 1,
        })
    }

    /// Add a new blob as `seq`, which must be [`next_seq`](Self::next_seq),
    /// with its bytes if it's inline.
    pub fn insert(
        &self,
        txn: &mut RwTxn<'_>,
        seq: u64,
        rec: &Record,
        body: Option<&[u8]>,
    ) -> Result<()> {
        if !txn.append(self.blobs, &seq.to_ne_bytes(), &rec.encode())? {
            bail!("blob {seq} is out of order");
        }
        txn.put(self.ids, &rec.hash.0, &seq.to_le_bytes())?;
        if let Some(body) = body {
            txn.put(self.bodies, &seq.to_ne_bytes(), body)?;
        }
        Ok(())
    }

    pub fn update(&self, txn: &mut RwTxn<'_>, seq: u64, rec: &Record) -> Result<()> {
        txn.put(self.blobs, &seq.to_ne_bytes(), &rec.encode())?;
        Ok(())
    }

    pub fn put_brotli(&self, txn: &mut RwTxn<'_>, seq: u64, copy: &[u8]) -> Result<()> {
        txn.put(self.brotli, &seq.to_ne_bytes(), copy)?;
        Ok(())
    }

    /// Whether `pubkey` didn't own it already.
    pub fn add_owner(
        &self,
        txn: &mut RwTxn<'_>,
        seq: u64,
        uploaded: u64,
        pubkey: &[u8; 32],
    ) -> Result<bool> {
        let added = txn.put_dup(self.blob_owners, &seq.to_be_bytes(), pubkey)?;
        txn.put_dup(self.owners, pubkey, &stamp(uploaded, seq))?;
        Ok(added)
    }

    /// Whether `pubkey` owned it.
    pub fn remove_owner(
        &self,
        txn: &mut RwTxn<'_>,
        seq: u64,
        uploaded: u64,
        pubkey: &[u8; 32],
    ) -> Result<bool> {
        let removed = txn.del(self.blob_owners, &seq.to_be_bytes(), Some(pubkey))?;
        txn.del(self.owners, pubkey, Some(&stamp(uploaded, seq)))?;
        Ok(removed)
    }

    #[cfg(test)]
    pub fn owned_by(&self, txn: &Txn<'_>, seq: u64, pubkey: &[u8; 32]) -> Result<bool> {
        let mut cur = txn.cursor(self.blob_owners)?;
        Ok(cur
            .get_both_range(&seq.to_be_bytes(), pubkey)?
            .is_some_and(|(_, v)| v == pubkey))
    }

    pub fn owner_count(&self, txn: &Txn<'_>, seq: u64) -> Result<usize> {
        let mut cur = txn.cursor(self.blob_owners)?;
        Ok(match cur.set(&seq.to_be_bytes())? {
            Some(_) => cur.count()?,
            None => 0,
        })
    }

    /// Forget a blob entirely: its record, name, inline bytes and owners.
    /// Its files are the caller's to remove.
    pub fn remove(&self, txn: &mut RwTxn<'_>, seq: u64, rec: &Record) -> Result<()> {
        let mut owners = Vec::new();
        {
            let mut cur = txn.cursor(self.blob_owners)?;
            let mut e = cur.set(&seq.to_be_bytes())?;
            while let Some((_, pk)) = e {
                owners.push(<[u8; 32]>::try_from(pk).context("An owner is corrupt")?);
                e = cur.next_dup()?;
            }
        }
        for pk in owners {
            txn.del(self.owners, &pk, Some(&stamp(rec.uploaded, seq)))?;
        }
        txn.del(self.blob_owners, &seq.to_be_bytes(), None)?;
        txn.del(self.blobs, &seq.to_ne_bytes(), None)?;
        txn.del(self.ids, &rec.hash.0, None)?;
        txn.del(self.bodies, &seq.to_ne_bytes(), None)?;
        txn.del(self.brotli, &seq.to_ne_bytes(), None)?;
        Ok(())
    }

    /// Keep a report (a kind 1984 event's JSON) about a blob. Whether it's new.
    pub fn put_report(
        &self,
        txn: &mut RwTxn<'_>,
        hash: &Hash,
        event_id: &[u8; 32],
        json: &[u8],
    ) -> Result<bool> {
        let mut key = [0; 64];
        key[..32].copy_from_slice(&hash.0);
        key[32..].copy_from_slice(event_id);
        if txn.get(self.reports, &key)?.is_some() {
            return Ok(false);
        }
        txn.put(self.reports, &key, json)?;
        Ok(true)
    }

    /// Every blob's seq and record, in seq order, `chunk` at a time, each
    /// chunk read in its own transaction so none is held long.
    pub fn each_record(&'static self, chunk: usize, mut f: impl FnMut(u64, Record)) -> Result<()> {
        let mut from = 0u64;
        loop {
            let batch = self.read(|txn| -> Result<Vec<(u64, Record)>> {
                let mut cur = txn.cursor(self.blobs)?;
                let mut out = Vec::new();
                let mut e = cur.set_range(&from.to_ne_bytes())?;
                while let Some((k, v)) = e {
                    let seq = u64::from_ne_bytes(k.try_into().context("A blob key is corrupt")?);
                    out.push((seq, Record::decode(v).context("A blob record is corrupt")?));
                    if out.len() == chunk {
                        break;
                    }
                    e = cur.next()?;
                }
                Ok(out)
            })??;
            let Some(&(last, _)) = batch.last() else {
                return Ok(());
            };
            let done = batch.len() < chunk;
            for (seq, rec) in batch {
                f(seq, rec);
            }
            if done {
                return Ok(());
            }
            from = last + 1;
        }
    }

    /// Record the day each of `seqs` was last read.
    pub fn touch(&self, seqs: &[u64], day: u16) -> Result<()> {
        let mut txn = self.stats.write_txn()?;
        for seq in seqs {
            txn.put(self.access, &seq.to_ne_bytes(), &day.to_le_bytes())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// The day a blob was last read, if it has been since stats began.
    #[cfg(test)]
    pub fn last_read(&self, seq: u64) -> Result<Option<u16>> {
        let txn = self.stats.read_txn()?;
        Ok(txn
            .get(self.access, &seq.to_ne_bytes())?
            .and_then(|v| Some(u16::from_le_bytes(v.try_into().ok()?))))
    }

    /// Flush the lazy stats to disk (at shutdown).
    pub fn sync_stats(&self) -> Result<()> {
        Ok(self.stats.sync()?)
    }
}

/// The stats environment, made afresh if it won't open: it's lazy, so a
/// crash of the machine may have left it corrupt, and it holds nothing that
/// can't be lost.
fn open_stats(dir: &Path) -> Result<(Env, Db)> {
    let open = || -> Result<(Env, Db)> {
        let env = Env::open(dir, lmdb::Sync::Lazy, MAP_SIZE, 2, MAX_READERS)?;
        let access = env.create_db("access", DbFlags::INTEGER_KEY)?;
        Ok((env, access))
    };
    match open() {
        Ok(v) => Ok(v),
        Err(e) => {
            crate::warn!("stats_reset", "error": e.to_string());
            std::fs::remove_dir_all(dir)?;
            std::fs::create_dir_all(dir)?;
            open()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn temp_store() -> (tempfile::TempDir, &'static Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Box::leak(Box::new(Store::open(dir.path()).unwrap()));
        (dir, store)
    }

    fn rec(n: u8, uploaded: u64) -> Record {
        Record {
            hash: Hash::of(&[n]),
            size: 1,
            uploaded,
            mime: Some("text/plain".into()),
            flags: flag::INLINE,
            br_size: 0,
        }
    }

    #[test]
    fn records_round_trip() {
        let mut r = rec(1, 1_700_000_000);
        r.flags |= flag::BROTLI;
        r.br_size = 77;
        assert_eq!(Record::decode(&r.encode()), Some(r.clone()));
        r.mime = None;
        assert_eq!(Record::decode(&r.encode()), Some(r));
        assert_eq!(Record::decode(&[9; 70]), None);
    }

    #[test]
    fn finds_lists_and_removes() {
        let (_dir, store) = temp_store();
        let pk = [7u8; 32];
        let mut txn = store.write_txn().unwrap();
        for n in 0..5u8 {
            let seq = store.next_seq(&txn).unwrap();
            let r = rec(n, 1000 + n as u64);
            store.insert(&mut txn, seq, &r, Some(&[n])).unwrap();
            store.add_owner(&mut txn, seq, r.uploaded, &pk).unwrap();
        }
        txn.commit().unwrap();

        let found = store.find(&Hash::of(&[3]), false).unwrap().unwrap();
        assert_eq!(found.body.as_deref(), Some(&[3u8][..]));
        assert_eq!(found.record.uploaded, 1003);
        assert!(store.find(&Hash::of(b"nope"), false).unwrap().is_none());
        assert_eq!(store.count().unwrap(), 5);

        let all: Vec<u64> = store
            .list(&pk, None, 10, None, None)
            .unwrap()
            .iter()
            .map(|r| r.uploaded)
            .collect();
        assert_eq!(all, [1004, 1003, 1002, 1001, 1000]);
        let page: Vec<u64> = store
            .list(&pk, Some(&Hash::of(&[3])), 2, None, None)
            .unwrap()
            .iter()
            .map(|r| r.uploaded)
            .collect();
        assert_eq!(page, [1002, 1001]);
        let window: Vec<u64> = store
            .list(&pk, None, 10, Some(1001), Some(1003))
            .unwrap()
            .iter()
            .map(|r| r.uploaded)
            .collect();
        assert_eq!(window, [1003, 1002, 1001]);
        assert!(
            store
                .list(&[8; 32], None, 10, None, None)
                .unwrap()
                .is_empty()
        );
        assert!(store.is_owner(&Hash::of(&[2]), &pk).unwrap());
        assert!(!store.is_owner(&Hash::of(&[2]), &[8; 32]).unwrap());

        let mut txn = store.write_txn().unwrap();
        let seq = store.seq_of(&txn, &Hash::of(&[2])).unwrap().unwrap();
        let r = store.record(&txn, seq).unwrap().unwrap();
        assert_eq!(store.owner_count(&txn, seq).unwrap(), 1);
        store.remove(&mut txn, seq, &r).unwrap();
        txn.commit().unwrap();
        assert!(store.find(&Hash::of(&[2]), false).unwrap().is_none());
        assert_eq!(store.list(&pk, None, 10, None, None).unwrap().len(), 4);

        store.touch(&[1, 3], 20_000).unwrap();
        assert_eq!(store.last_read(3).unwrap(), Some(20_000));
        assert_eq!(store.last_read(4).unwrap(), None);
    }
}
