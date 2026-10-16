//! The one thread that writes the store.
//!
//! Requests send it jobs and await its replies. It takes whatever is queued
//! and does it all in one transaction, one durable commit: a commit costs a
//! couple of flushes whatever it holds, so under load uploads share them
//! (64 a commit is 24x the uploads a second). New files are put
//! in place and flushed, the batch's together with one `syncfs`, before the
//! commit that makes them visible: a blob the database knows of is always
//! whole on disk.

use std::sync::mpsc;

use anyhow::{Context, Result};
use tokio::sync::oneshot;

use crate::blobs::{Files, TempFile};
use crate::hash::Hash;
use crate::store::{INLINE_MAX, Record, Store, flag};

/// The most jobs one commit takes.
const MAX_BATCH: usize = 256;

/// A received blob, hashed and (unless small) written to a temp file.
pub struct Ingested {
    pub hash: Hash,
    pub size: u64,
    pub mime: Option<String>,
    pub body: IngestedBody,
}

pub enum IngestedBody {
    Inline(Vec<u8>),
    File(TempFile),
}

pub struct Stored {
    pub record: Record,
    /// Whether it's new, or was here already (201 or 200, BUD-02).
    pub created: bool,
}

pub enum Deleted {
    /// Gone entirely: no one owns it now.
    Removed,
    /// The pubkey no longer owns it; others still do.
    Disowned,
    /// Not here, or not theirs.
    NotOwned,
}

/// A brotli copy, made in the background (see `compress`).
pub enum BrotliCopy {
    Inline(Vec<u8>),
    File(TempFile, u64),
    /// Tried, and not worth keeping.
    None,
}

enum Job {
    Insert(
        Ingested,
        Option<[u8; 32]>,
        u64,
        oneshot::Sender<Result<Stored>>,
    ),
    AddOwner(Hash, [u8; 32], oneshot::Sender<Result<Option<Record>>>),
    Delete(Hash, [u8; 32], oneshot::Sender<Result<Deleted>>),
    Brotli(u64, Hash, BrotliCopy),
    Report(Vec<Hash>, [u8; 32], Vec<u8>, oneshot::Sender<Result<()>>),
}

#[derive(Clone)]
pub struct Writer {
    tx: mpsc::Sender<Job>,
}

impl Writer {
    pub fn start(store: &'static Store, files: &'static Files) -> Writer {
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("writer".into())
            .spawn(move || run(store, files, rx))
            .expect("the writer thread starts");
        Writer { tx }
    }

    async fn ask<T>(&self, make: impl FnOnce(oneshot::Sender<Result<T>>) -> Job) -> Result<T> {
        let (reply, answer) = oneshot::channel();
        self.tx
            .send(make(reply))
            .ok()
            .context("the writer has stopped")?;
        answer.await.context("the writer has stopped")?
    }

    /// Keep a blob, owned by `owner` if given, uploaded `now`.
    pub async fn insert(
        &self,
        blob: Ingested,
        owner: Option<[u8; 32]>,
        now: u64,
    ) -> Result<Stored> {
        self.ask(|r| Job::Insert(blob, owner, now, r)).await
    }

    /// Give an existing blob another owner; `None` if it isn't here.
    pub async fn add_owner(&self, hash: Hash, owner: [u8; 32]) -> Result<Option<Record>> {
        self.ask(|r| Job::AddOwner(hash, owner, r)).await
    }

    pub async fn delete(&self, hash: Hash, owner: [u8; 32]) -> Result<Deleted> {
        self.ask(|r| Job::Delete(hash, owner, r)).await
    }

    pub async fn report(&self, hashes: Vec<Hash>, event_id: [u8; 32], json: Vec<u8>) -> Result<()> {
        self.ask(|r| Job::Report(hashes, event_id, json, r)).await
    }

    /// Record a brotli copy; nobody waits on it.
    pub fn brotli(&self, seq: u64, hash: Hash, copy: BrotliCopy) {
        let _ = self.tx.send(Job::Brotli(seq, hash, copy));
    }
}

/// What a batch owes once it's committed (or failed).
enum Reply {
    Insert(oneshot::Sender<Result<Stored>>, Result<Stored>),
    AddOwner(
        oneshot::Sender<Result<Option<Record>>>,
        Result<Option<Record>>,
    ),
    Delete(oneshot::Sender<Result<Deleted>>, Result<Deleted>),
    Report(oneshot::Sender<Result<()>>, Result<()>),
}

fn run(store: &'static Store, files: &'static Files, rx: mpsc::Receiver<Job>) {
    while let Ok(first) = rx.recv() {
        let mut jobs = vec![first];
        while jobs.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(j) => jobs.push(j),
                Err(_) => break,
            }
        }
        batch(store, files, jobs);
    }
}

fn batch(store: &'static Store, files: &'static Files, jobs: Vec<Job>) {
    let mut replies = Vec::with_capacity(jobs.len());
    let mut placed: Vec<(Hash, bool)> = Vec::new();
    let mut unlink: Vec<(u64, Hash)> = Vec::new();
    let mut txn = match store.write_txn() {
        Ok(t) => t,
        Err(e) => return fail_all(jobs, &e),
    };
    for job in jobs {
        match job {
            Job::Insert(blob, owner, now, reply) => {
                let r = insert(store, files, &mut txn, blob, owner, now, &mut placed);
                replies.push(Reply::Insert(reply, r));
            }
            Job::AddOwner(hash, owner, reply) => {
                let r = (|| -> Result<Option<Record>> {
                    let Some(seq) = store.seq_of(&txn, &hash)? else {
                        return Ok(None);
                    };
                    let rec = store
                        .record(&txn, seq)?
                        .context("a blob without its record")?;
                    store.add_owner(&mut txn, seq, rec.uploaded, &owner)?;
                    Ok(Some(rec))
                })();
                replies.push(Reply::AddOwner(reply, r));
            }
            Job::Delete(hash, owner, reply) => {
                let r = (|| -> Result<Deleted> {
                    let Some(seq) = store.seq_of(&txn, &hash)? else {
                        return Ok(Deleted::NotOwned);
                    };
                    let rec = store
                        .record(&txn, seq)?
                        .context("a blob without its record")?;
                    if !store.remove_owner(&mut txn, seq, rec.uploaded, &owner)? {
                        return Ok(Deleted::NotOwned);
                    }
                    if store.owner_count(&txn, seq)? > 0 {
                        return Ok(Deleted::Disowned);
                    }
                    store.remove(&mut txn, seq, &rec)?;
                    if !rec.has(flag::INLINE) || rec.br_size as usize > INLINE_MAX {
                        unlink.push((seq, hash));
                    }
                    Ok(Deleted::Removed)
                })();
                replies.push(Reply::Delete(reply, r));
            }
            Job::Brotli(seq, hash, copy) => {
                if let Err(e) = brotli(store, files, &mut txn, seq, hash, copy, &mut placed) {
                    crate::warn!("brotli_store_failed", "blob": hash.hex(), "error": format!("{e:#}"));
                }
            }
            Job::Report(hashes, id, json, reply) => {
                let r = (|| -> Result<()> {
                    for h in &hashes {
                        store.put_report(&mut txn, h, &id, &json)?;
                    }
                    Ok(())
                })();
                replies.push(Reply::Report(reply, r));
            }
        }
    }
    let flushed = match placed.is_empty() {
        true => Ok(()),
        false => files.sync().context("Could not flush new blobs to disk"),
    };
    let committed = flushed.and_then(|()| Ok(txn.commit()?));
    let failed = committed.err().map(|e| format!("{e:#}"));
    match &failed {
        Some(e) => {
            crate::error!("commit_failed", "error": e);
            // Nothing knows of the files placed for it; take them back out.
            for (hash, brotli) in placed {
                let _ = std::fs::remove_file(files.path(&hash, brotli));
            }
        }
        None => {
            for (seq, hash) in unlink {
                if let Err(e) = files.remove(seq, &hash) {
                    crate::warn!("unlink_failed", "blob": hash.hex(), "error": e.to_string());
                }
            }
        }
    }
    // Every answer waits on the commit: nothing is promised until it's durable.
    fn settle<T>(r: Result<T>, failed: &Option<String>) -> Result<T> {
        match failed {
            Some(e) => Err(anyhow::anyhow!("{e}")),
            None => r,
        }
    }
    for reply in replies {
        match reply {
            Reply::Insert(tx, r) => drop(tx.send(settle(r, &failed))),
            Reply::AddOwner(tx, r) => drop(tx.send(settle(r, &failed))),
            Reply::Delete(tx, r) => drop(tx.send(settle(r, &failed))),
            Reply::Report(tx, r) => drop(tx.send(settle(r, &failed))),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn insert(
    store: &Store,
    files: &Files,
    txn: &mut crate::lmdb::RwTxn<'_>,
    blob: Ingested,
    owner: Option<[u8; 32]>,
    now: u64,
    placed: &mut Vec<(Hash, bool)>,
) -> Result<Stored> {
    if let Some(seq) = store.seq_of(txn, &blob.hash)? {
        let record = store
            .record(txn, seq)?
            .context("a blob without its record")?;
        if let Some(pk) = owner {
            store.add_owner(txn, seq, record.uploaded, &pk)?;
        }
        return Ok(Stored {
            record,
            created: false,
        });
    }
    let inline = matches!(blob.body, IngestedBody::Inline(_));
    let record = Record {
        hash: blob.hash,
        size: blob.size,
        uploaded: now,
        mime: blob.mime,
        flags: if inline { flag::INLINE } else { 0 },
        br_size: 0,
    };
    let seq = store.next_seq(txn)?;
    match blob.body {
        IngestedBody::Inline(bytes) => store.insert(txn, seq, &record, Some(&bytes))?,
        IngestedBody::File(tmp) => {
            files
                .place(tmp, &blob.hash, false)
                .context("Could not put the blob in place")?;
            placed.push((blob.hash, false));
            store.insert(txn, seq, &record, None)?;
        }
    }
    if let Some(pk) = owner {
        store.add_owner(txn, seq, record.uploaded, &pk)?;
    }
    Ok(Stored {
        record,
        created: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn brotli(
    store: &Store,
    files: &Files,
    txn: &mut crate::lmdb::RwTxn<'_>,
    seq: u64,
    hash: Hash,
    copy: BrotliCopy,
    placed: &mut Vec<(Hash, bool)>,
) -> Result<()> {
    // Deleted while it was being compressed: nothing to do.
    let Some(mut rec) = store.record(txn, seq)? else {
        return Ok(());
    };
    rec.flags |= flag::BROTLI_CHECKED;
    match copy {
        BrotliCopy::None => {}
        BrotliCopy::Inline(bytes) => {
            store.put_brotli(txn, seq, &bytes)?;
            rec.flags |= flag::BROTLI;
            rec.br_size = bytes.len() as u64;
        }
        BrotliCopy::File(tmp, size) => {
            files.place(tmp, &hash, true)?;
            placed.push((hash, true));
            rec.flags |= flag::BROTLI;
            rec.br_size = size;
        }
    }
    store.update(txn, seq, &rec)
}

fn fail_all(jobs: Vec<Job>, e: &anyhow::Error) {
    for job in jobs {
        let err = anyhow::anyhow!("{e:#}");
        match job {
            Job::Insert(.., r) => drop(r.send(Err(err))),
            Job::AddOwner(.., r) => drop(r.send(Err(err))),
            Job::Delete(.., r) => drop(r.send(Err(err))),
            Job::Report(.., r) => drop(r.send(Err(err))),
            Job::Brotli(..) => {}
        }
    }
}
