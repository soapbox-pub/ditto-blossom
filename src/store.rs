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
//! - `banned_blobs`: sha256 -> [`Ban`]: never stored again, whoever sends it.
//! - `banned_pubkeys`: pubkey -> [`Ban`]: owns nothing new.
//! - `unbans`: kind (0 blob, 1 pubkey) then hash or pubkey -> when its ban
//!   was lifted (u64 LE): a decision, as much as a ban is.
//! - `decisions`: when (u64 BE), kind, hash or pubkey -> 1 for a ban, 0 for
//!   an unban: every target's latest, in order of when, for peers to follow
//!   (see `peers`).
//! - `info`: `version` -> the layout's version; `decisions` once that's been
//!   filled from the bans already here; `peer:<url>` -> how far into that
//!   peer's decisions this server has read.
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
    /// Stored before it was scanned, and not scanned yet (see `scan`).
    pub const UNSCANNED: u8 = 8;
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

const BLOB: u8 = 0;
const PUBKEY: u8 = 1;

/// A ban or unban, as `decisions` keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Its key in `decisions`, to read on from.
    pub cursor: Vec<u8>,
    pub target: Banned,
    pub at: u64,
    /// The ban, or `None` for an unban.
    pub ban: Option<Ban>,
}

fn target_key(target: &Banned) -> [u8; 33] {
    let mut k = [0; 33];
    match target {
        Banned::Blob(h) => k[1..].copy_from_slice(&h.0),
        Banned::Pubkey(pk) => {
            k[0] = PUBKEY;
            k[1..].copy_from_slice(pk);
        }
    }
    k
}

fn decision_key(at: u64, target: &Banned) -> Vec<u8> {
    let t = target_key(target);
    decision_key_of(at, t[0], &t[1..])
}

fn decision_key_of(at: u64, kind: u8, key: &[u8]) -> Vec<u8> {
    let mut k = at.to_be_bytes().to_vec();
    k.push(kind);
    k.extend_from_slice(key);
    k
}

fn parse_decision_key(k: &[u8]) -> Option<(u64, Banned)> {
    if k.len() != 41 {
        return None;
    }
    let at = u64::from_be_bytes(k[..8].try_into().ok()?);
    let key: [u8; 32] = k[9..].try_into().ok()?;
    let target = match k[8] {
        BLOB => Banned::Blob(Hash(key)),
        PUBKEY => Banned::Pubkey(key),
        _ => return None,
    };
    Some((at, target))
}

/// Bans from before decisions were kept, as decisions.
fn fill_decisions(txn: &mut RwTxn<'_>, banned: [Db; 2], decisions: Db) -> Result<()> {
    let mut keys = Vec::new();
    for (db, kind) in banned.into_iter().zip([BLOB, PUBKEY]) {
        let mut cur = txn.cursor(db)?;
        let mut e = cur.first()?;
        while let Some((k, v)) = e {
            let at = u64::from_le_bytes(
                v.get(..8)
                    .and_then(|b| b.try_into().ok())
                    .context("A ban is corrupt")?,
            );
            keys.push(decision_key_of(at, kind, k));
            e = cur.next()?;
        }
    }
    for k in &keys {
        txn.put(decisions, k, &[1])?;
    }
    Ok(())
}

/// What's banned: a blob, by its hash, or an uploader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Banned {
    Blob(Hash),
    Pubkey([u8; 32]),
}

/// A ban as kept: `banned_at (u64 LE) reason`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ban {
    pub target: Banned,
    /// Unix seconds.
    pub at: u64,
    pub reason: String,
}

impl Ban {
    fn encode(&self) -> Vec<u8> {
        let mut v = self.at.to_le_bytes().to_vec();
        v.extend_from_slice(self.reason.as_bytes());
        v
    }

    fn decode(target: Banned, v: &[u8]) -> Option<Ban> {
        Some(Ban {
            target,
            at: u64::from_le_bytes(v.get(..8)?.try_into().ok()?),
            reason: String::from_utf8_lossy(&v[8..]).into_owned(),
        })
    }
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

/// A blob's seq, record and owners.
type Owned = (u64, Record, Vec<[u8; 32]>);

pub struct Store {
    env: Env,
    stats: Env,
    blobs: Db,
    ids: Db,
    owners: Db,
    blob_owners: Db,
    reports: Db,
    banned_blobs: Db,
    banned_pubkeys: Db,
    /// Blobs kept while Shield couldn't be asked about them: hash → when.
    unscanned: Db,
    unbans: Db,
    decisions: Db,
    info: Db,
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
        let banned_blobs = env.create_db("banned_blobs", DbFlags::PLAIN)?;
        let banned_pubkeys = env.create_db("banned_pubkeys", DbFlags::PLAIN)?;
        let unscanned = env.create_db("unscanned", DbFlags::PLAIN)?;
        let unbans = env.create_db("unbans", DbFlags::PLAIN)?;
        let decisions = env.create_db("decisions", DbFlags::PLAIN)?;
        {
            let mut txn = env.write_txn()?;
            match txn.get(info, b"version")? {
                None => {
                    txn.put(info, b"version", VERSION)?;
                }
                Some(v) if v == VERSION => {}
                Some(v) => bail!(
                    "The database is version {}, this server reads {}",
                    String::from_utf8_lossy(v),
                    String::from_utf8_lossy(VERSION)
                ),
            }
            if txn.get(info, b"decisions")?.is_none() {
                fill_decisions(&mut txn, [banned_blobs, banned_pubkeys], decisions)?;
                txn.put(info, b"decisions", b"1")?;
            }
            txn.commit()?;
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
            banned_blobs,
            banned_pubkeys,
            unscanned,
            unbans,
            decisions,
            info,
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

    /// Whether `hash` or `pubkey`, either given, is banned.
    pub fn is_banned(
        &'static self,
        hash: Option<&Hash>,
        pubkey: Option<&[u8; 32]>,
    ) -> Result<bool> {
        self.read(|txn| self.banned(txn, hash, pubkey))?
    }

    /// Every ban, blobs first.
    pub fn bans(&'static self) -> Result<Vec<Ban>> {
        self.read(|txn| -> Result<Vec<Ban>> {
            let mut out = Vec::new();
            for (db, blob) in [(self.banned_blobs, true), (self.banned_pubkeys, false)] {
                let mut cur = txn.cursor(db)?;
                let mut e = cur.first()?;
                while let Some((k, v)) = e {
                    let key: [u8; 32] = k.try_into().context("A ban's key is corrupt")?;
                    let target = match blob {
                        true => Banned::Blob(Hash(key)),
                        false => Banned::Pubkey(key),
                    };
                    out.push(Ban::decode(target, v).context("A ban is corrupt")?);
                    e = cur.next()?;
                }
            }
            Ok(out)
        })?
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
        for pk in self.owners_of(txn, seq)? {
            txn.del(self.owners, &pk, Some(&stamp(rec.uploaded, seq)))?;
        }
        txn.del(self.blob_owners, &seq.to_be_bytes(), None)?;
        txn.del(self.blobs, &seq.to_ne_bytes(), None)?;
        txn.del(self.ids, &rec.hash.0, None)?;
        txn.del(self.bodies, &seq.to_ne_bytes(), None)?;
        txn.del(self.brotli, &seq.to_ne_bytes(), None)?;
        txn.del(self.unscanned, &rec.hash.0, None)?;
        Ok(())
    }

    /// Who owns a blob.
    pub fn owners_of(&self, txn: &Txn<'_>, seq: u64) -> Result<Vec<[u8; 32]>> {
        let mut owners = Vec::new();
        let mut cur = txn.cursor(self.blob_owners)?;
        let mut e = cur.set(&seq.to_be_bytes())?;
        while let Some((_, pk)) = e {
            owners.push(<[u8; 32]>::try_from(pk).context("An owner is corrupt")?);
            e = cur.next_dup()?;
        }
        Ok(owners)
    }

    /// Note a blob kept without Shield's say, to ask again later.
    pub fn queue_unscanned(&self, txn: &mut RwTxn<'_>, hash: &Hash, at: u64) -> Result<()> {
        txn.put(self.unscanned, &hash.0, &at.to_le_bytes())?;
        Ok(())
    }

    pub fn unqueue_unscanned(&self, txn: &mut RwTxn<'_>, hash: &Hash) -> Result<()> {
        txn.del(self.unscanned, &hash.0, None)?;
        Ok(())
    }

    /// Up to `limit` blobs waiting on Shield.
    pub fn unscanned(&'static self, limit: usize) -> Result<Vec<Hash>> {
        self.read(|txn| -> Result<Vec<Hash>> {
            let mut cur = txn.cursor(self.unscanned)?;
            let mut out = Vec::new();
            let mut e = cur.first()?;
            while let Some((k, _)) = e {
                if out.len() == limit {
                    break;
                }
                out.push(Hash(k.try_into().context("An unscanned entry is corrupt")?));
                e = cur.next()?;
            }
            Ok(out)
        })?
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

    pub fn banned(
        &self,
        txn: &Txn<'_>,
        hash: Option<&Hash>,
        pubkey: Option<&[u8; 32]>,
    ) -> Result<bool> {
        if let Some(h) = hash
            && txn.get(self.banned_blobs, &h.0)?.is_some()
        {
            return Ok(true);
        }
        Ok(match pubkey {
            Some(pk) => txn.get(self.banned_pubkeys, pk)?.is_some(),
            None => false,
        })
    }

    pub fn ban(&self, txn: &mut RwTxn<'_>, ban: &Ban) -> Result<()> {
        self.forget_decision(txn, &ban.target)?;
        let (db, key) = self.ban_key(&ban.target);
        txn.put(db, key, &ban.encode())?;
        txn.put(self.decisions, &decision_key(ban.at, &ban.target), &[1])?;
        Ok(())
    }

    /// Lift a ban now. Whether it was banned.
    pub fn unban(&self, txn: &mut RwTxn<'_>, target: &Banned) -> Result<bool> {
        self.unban_at(txn, target, crate::upload::now())
    }

    /// Lift a ban, as decided `at`. Whether it was banned.
    pub fn unban_at(&self, txn: &mut RwTxn<'_>, target: &Banned, at: u64) -> Result<bool> {
        if self.ban_of(txn, *target)?.is_none() {
            return Ok(false);
        }
        self.forget_decision(txn, target)?;
        let (db, key) = self.ban_key(target);
        txn.del(db, key, None)?;
        txn.put(self.unbans, &target_key(target), &at.to_le_bytes())?;
        txn.put(self.decisions, &decision_key(at, target), &[0])?;
        Ok(true)
    }

    /// When a target was last banned or unbanned, if it ever was.
    pub fn decided_at(&self, txn: &Txn<'_>, target: Banned) -> Result<Option<u64>> {
        if let Some(b) = self.ban_of(txn, target)? {
            return Ok(Some(b.at));
        }
        Ok(txn
            .get(self.unbans, &target_key(&target))?
            .and_then(|v| v.try_into().ok())
            .map(u64::from_le_bytes))
    }

    /// Take a target's latest decision out of `decisions`, and its unban
    /// out of `unbans`, before another replaces it.
    fn forget_decision(&self, txn: &mut RwTxn<'_>, target: &Banned) -> Result<()> {
        if let Some(old) = self.ban_of(txn, *target)? {
            txn.del(self.decisions, &decision_key(old.at, target), None)?;
        }
        let tk = target_key(target);
        let unbanned: Option<u64> = txn
            .get(self.unbans, &tk)?
            .and_then(|v| v.try_into().ok())
            .map(u64::from_le_bytes);
        if let Some(at) = unbanned {
            txn.del(self.decisions, &decision_key(at, target), None)?;
            txn.del(self.unbans, &tk, None)?;
        }
        Ok(())
    }

    /// Up to `limit` decisions, oldest first, after the one `after` names
    /// (its `cursor`), or from the first. And whether there are more.
    pub fn decisions(
        &'static self,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<(Vec<Decision>, bool)> {
        self.read(|txn| -> Result<(Vec<Decision>, bool)> {
            let mut cur = txn.cursor(self.decisions)?;
            let mut e = match after {
                Some(k) => match cur.set_range(k)? {
                    Some((found, _)) if found == k => cur.next()?,
                    other => other,
                },
                None => cur.first()?,
            };
            let mut out = Vec::new();
            while let Some((k, v)) = e {
                if out.len() == limit {
                    return Ok((out, true));
                }
                let (at, target) = parse_decision_key(k).context("A decision is corrupt")?;
                let ban = match v {
                    [1] => Some(
                        self.ban_of(txn, target)?
                            .context("A ban decided without its ban")?,
                    ),
                    _ => None,
                };
                out.push(Decision {
                    cursor: k.to_vec(),
                    target,
                    at,
                    ban,
                });
                e = cur.next()?;
            }
            Ok((out, false))
        })?
    }

    /// How far into a peer's decisions this server has read.
    pub fn peer_cursor(&'static self, url: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("peer:{url}");
        self.read(|txn| Ok(txn.get(self.info, key.as_bytes())?.map(<[u8]>::to_vec)))?
    }

    pub fn set_peer_cursor(&self, txn: &mut RwTxn<'_>, url: &str, cursor: &[u8]) -> Result<()> {
        txn.put(self.info, format!("peer:{url}").as_bytes(), cursor)?;
        Ok(())
    }

    /// A target's ban, if it's banned.
    pub fn ban_of(&self, txn: &Txn<'_>, target: Banned) -> Result<Option<Ban>> {
        let (db, key) = self.ban_key(&target);
        Ok(txn.get(db, key)?.and_then(|v| Ban::decode(target, v)))
    }

    /// How many blobs, and how many pubkeys, are banned.
    pub fn ban_counts(&self, txn: &Txn<'_>) -> Result<(usize, usize)> {
        Ok((txn.len(self.banned_blobs)?, txn.len(self.banned_pubkeys)?))
    }

    /// How many reports are kept.
    pub fn report_count(&self, txn: &Txn<'_>) -> Result<usize> {
        Ok(txn.len(self.reports)?)
    }

    /// Every report kept, with the blob it names, in order of blob.
    pub fn reports(&self, txn: &Txn<'_>) -> Result<Vec<(Hash, Vec<u8>)>> {
        let mut cur = txn.cursor(self.reports)?;
        let mut out = Vec::new();
        let mut e = cur.first()?;
        while let Some((k, json)) = e {
            let hash: [u8; 32] = k
                .get(..32)
                .and_then(|h| h.try_into().ok())
                .context("A report's key is corrupt")?;
            out.push((Hash(hash), json.to_vec()));
            e = cur.next()?;
        }
        Ok(out)
    }

    fn ban_key<'a>(&self, target: &'a Banned) -> (Db, &'a [u8]) {
        match target {
            Banned::Blob(h) => (self.banned_blobs, &h.0),
            Banned::Pubkey(pk) => (self.banned_pubkeys, pk),
        }
    }

    /// The bytes of an inline blob.
    pub fn body(&self, txn: &Txn<'_>, seq: u64) -> Result<Option<Vec<u8>>> {
        Ok(txn
            .get(self.bodies, &seq.to_ne_bytes())?
            .map(<[u8]>::to_vec))
    }

    /// The reports (kind 1984 events' JSON) kept about a blob.
    pub fn reports_of(&self, txn: &Txn<'_>, hash: &Hash) -> Result<Vec<Vec<u8>>> {
        let mut cur = txn.cursor(self.reports)?;
        let mut out = Vec::new();
        let mut e = cur.set_range(&hash.0)?;
        while let Some((k, json)) = e {
            if !k.starts_with(&hash.0) {
                break;
            }
            out.push(json.to_vec());
            e = cur.next()?;
        }
        Ok(out)
    }

    /// The seqs of a pubkey's blobs.
    pub fn owned(&self, txn: &Txn<'_>, pubkey: &[u8; 32]) -> Result<Vec<u64>> {
        let mut cur = txn.cursor(self.owners)?;
        let mut out = Vec::new();
        let mut e = cur.set(pubkey)?;
        while let Some((_, s)) = e {
            out.push(stamp_parts(s).1);
            e = cur.next_dup()?;
        }
        Ok(out)
    }

    /// Blobs newest first, from below `before` (a seq) if given: those
    /// `keep` takes, at most `limit` of them, looking at no more than
    /// `budget`. And the seq to go on below, unless that was the last.
    pub fn recent(
        &'static self,
        before: Option<u64>,
        limit: usize,
        budget: usize,
        keep: impl Fn(&Record) -> bool,
    ) -> Result<(Vec<Record>, Option<u64>)> {
        self.read(|txn| -> Result<(Vec<Record>, Option<u64>)> {
            let mut cur = txn.cursor(self.blobs)?;
            let mut e = match before {
                Some(b) => match cur.set_range(&b.to_ne_bytes())? {
                    Some(_) => cur.prev()?,
                    None => cur.last()?,
                },
                None => cur.last()?,
            };
            let (mut out, mut looked) = (Vec::new(), 0);
            while let Some((k, v)) = e {
                let seq = u64::from_ne_bytes(k.try_into().context("A blob key is corrupt")?);
                if out.len() >= limit || looked >= budget {
                    return Ok((out, Some(seq + 1)));
                }
                looked += 1;
                let rec = Record::decode(v).context("A blob record is corrupt")?;
                if keep(&rec) {
                    out.push(rec);
                }
                e = cur.prev()?;
            }
            Ok((out, None))
        })?
    }

    /// Every blob's seq, record and owners, `chunk` at a time as
    /// `each_record`.
    pub fn each_record_owned(
        &'static self,
        chunk: usize,
        mut f: impl FnMut(u64, Record, Vec<[u8; 32]>),
    ) -> Result<()> {
        let mut from = 0u64;
        loop {
            let batch = self.read(|txn| -> Result<Vec<Owned>> {
                let mut cur = txn.cursor(self.blobs)?;
                let mut out = Vec::new();
                let mut e = cur.set_range(&from.to_ne_bytes())?;
                while let Some((k, v)) = e {
                    let seq = u64::from_ne_bytes(k.try_into().context("A blob key is corrupt")?);
                    let rec = Record::decode(v).context("A blob record is corrupt")?;
                    out.push((seq, rec, self.owners_of(txn, seq)?));
                    if out.len() == chunk {
                        break;
                    }
                    e = cur.next()?;
                }
                Ok(out)
            })??;
            let Some(&(last, _, _)) = batch.last() else {
                return Ok(());
            };
            let done = batch.len() < chunk;
            for (seq, rec, owners) in batch {
                f(seq, rec, owners);
            }
            if done {
                return Ok(());
            }
            from = last + 1;
        }
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

    /// The day each blob was last read, by seq, for those read since stats
    /// began.
    pub fn last_reads(&self) -> Result<std::collections::HashMap<u64, u16>> {
        let txn = self.stats.read_txn()?;
        let mut cur = txn.cursor(self.access)?;
        let mut out = std::collections::HashMap::new();
        let mut e = cur.first()?;
        while let Some((k, v)) = e {
            let seq = u64::from_ne_bytes(k.try_into().context("An access key is corrupt")?);
            if let Ok(day) = <[u8; 2]>::try_from(v) {
                out.insert(seq, u16::from_le_bytes(day));
            }
            e = cur.next()?;
        }
        Ok(out)
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

    #[test]
    fn each_target_keeps_its_latest_decision() {
        let (_dir, store) = temp_store();
        let (blob, pk) = (Banned::Blob(Hash::of(b"x")), Banned::Pubkey([3; 32]));
        let ban = |target, at| Ban {
            target,
            at,
            reason: format!("at {at}"),
        };
        let mut txn = store.write_txn().unwrap();
        store.ban(&mut txn, &ban(blob, 10)).unwrap();
        store.ban(&mut txn, &ban(pk, 20)).unwrap();
        store.ban(&mut txn, &ban(blob, 30)).unwrap();
        assert!(store.unban_at(&mut txn, &pk, 40).unwrap());
        assert!(
            !store.unban_at(&mut txn, &pk, 50).unwrap(),
            "not banned now"
        );
        assert_eq!(store.decided_at(&txn, blob).unwrap(), Some(30));
        assert_eq!(store.decided_at(&txn, pk).unwrap(), Some(40));
        assert_eq!(
            store
                .decided_at(&txn, Banned::Blob(Hash::of(b"y")))
                .unwrap(),
            None
        );
        txn.commit().unwrap();
        let (all, more) = store.decisions(None, 10).unwrap();
        assert!(!more);
        let seen: Vec<_> = all
            .iter()
            .map(|d| (d.target, d.at, d.ban.is_some()))
            .collect();
        assert_eq!(seen, [(blob, 30, true), (pk, 40, false)]);
        let (rest, _) = store.decisions(Some(&all[0].cursor), 10).unwrap();
        assert_eq!(rest, all[1..]);

        // Banned again, the unban's forgotten.
        let mut txn = store.write_txn().unwrap();
        store.ban(&mut txn, &ban(pk, 60)).unwrap();
        txn.commit().unwrap();
        let (all, _) = store.decisions(None, 10).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].ban.as_ref().unwrap().reason, "at 60");

        // Bans from before decisions were kept are found.
        let mut txn = store.write_txn().unwrap();
        txn.clear(store.decisions).unwrap();
        fill_decisions(
            &mut txn,
            [store.banned_blobs, store.banned_pubkeys],
            store.decisions,
        )
        .unwrap();
        txn.commit().unwrap();
        assert_eq!(store.decisions(None, 10).unwrap().0, all);
    }

    #[test]
    fn bans_and_owned() {
        let (_dir, store) = temp_store();
        let (pk, other) = ([7u8; 32], [8u8; 32]);
        let mut txn = store.write_txn().unwrap();
        for n in 0..3u8 {
            let seq = store.next_seq(&txn).unwrap();
            let r = rec(n, 1000 + n as u64);
            store.insert(&mut txn, seq, &r, Some(&[n])).unwrap();
            store.add_owner(&mut txn, seq, r.uploaded, &pk).unwrap();
        }
        assert_eq!(store.owned(&txn, &pk).unwrap(), [1, 2, 3]);
        assert!(store.owned(&txn, &other).unwrap().is_empty());

        let blob = Hash::of(b"bad");
        for target in [Banned::Blob(blob), Banned::Pubkey(pk)] {
            let ban = Ban {
                target,
                at: 1_760_000_000,
                reason: "csam".into(),
            };
            store.ban(&mut txn, &ban).unwrap();
        }
        txn.commit().unwrap();

        assert!(store.is_banned(Some(&blob), None).unwrap());
        assert!(store.is_banned(None, Some(&pk)).unwrap());
        assert!(
            store
                .is_banned(Some(&Hash::of(b"fine")), Some(&pk))
                .unwrap()
        );
        assert!(
            !store
                .is_banned(Some(&Hash::of(b"fine")), Some(&other))
                .unwrap()
        );
        assert!(!store.is_banned(None, None).unwrap());
        let bans = store.bans().unwrap();
        assert_eq!(bans.len(), 2);
        assert_eq!(bans[0].target, Banned::Blob(blob));
        assert_eq!(bans[1].target, Banned::Pubkey(pk));
        assert_eq!(bans[1].reason, "csam");

        let mut txn = store.write_txn().unwrap();
        assert!(store.unban(&mut txn, &Banned::Pubkey(pk)).unwrap());
        assert!(!store.unban(&mut txn, &Banned::Pubkey(pk)).unwrap());
        txn.commit().unwrap();
        assert!(!store.is_banned(None, Some(&pk)).unwrap());
        assert!(store.is_banned(Some(&blob), None).unwrap());
    }
}
