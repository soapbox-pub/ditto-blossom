//! Taking in a blob's bytes, from an upload's body or a mirror's download:
//! counted against the limit, hashed, and (past the inline size) written to
//! a temp file on a blocking thread, which is also where they're
//! hashed, so a big upload never holds an async thread for long.

use std::future::Future;
use std::io::{self, Write};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use tokio::sync::mpsc;

use crate::blobs::{Files, TempFile};
use crate::hash::{Hash, Hasher};
use crate::mime;
use crate::store::INLINE_MAX;
use crate::writer::{Ingested, IngestedBody};

/// How long a body may go without sending anything.
pub const IDLE: Duration = Duration::from_secs(30);
/// Chunks queued for the blocking writer before reading waits on it.
const QUEUE: usize = 16;
/// How much of a large upload is written between nudges to write it out.
const WRITEBACK_EVERY: usize = 8 << 20;

/// Where a blob's bytes come from.
pub trait Source: Send {
    /// The next chunk, `None` at the end.
    fn next(&mut self) -> impl Future<Output = Option<io::Result<Bytes>>> + Send;
}

impl Source for hyper::body::Incoming {
    async fn next(&mut self) -> Option<io::Result<Bytes>> {
        loop {
            match self.frame().await? {
                Err(e) => return Some(Err(io::Error::other(e))),
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        return Some(Ok(data));
                    }
                }
            }
        }
    }
}

impl Source for reqwest::Response {
    async fn next(&mut self) -> Option<io::Result<Bytes>> {
        self.chunk().await.map_err(io::Error::other).transpose()
    }
}

#[derive(Debug)]
pub enum Error {
    TooLarge,
    /// Fewer or more bytes than declared.
    WrongLength,
    /// Nothing arrived for [`IDLE`].
    Stalled,
    Read(io::Error),
    Disk(io::Error),
}

/// Chunks on their way to the blocking writer, and its eventual answer.
type Spill = (
    mpsc::Sender<Bytes>,
    tokio::task::JoinHandle<io::Result<(Hash, TempFile)>>,
);

/// Read all of `src`, at most `max` bytes, and exactly `declared` if given.
/// The type is `declared_type` if it's one, else whatever the bytes look
/// like.
pub async fn ingest(
    files: &'static Files,
    mut src: impl Source,
    declared: Option<u64>,
    max: u64,
    declared_type: Option<&str>,
) -> Result<Ingested, Error> {
    let mut head: Vec<u8> = Vec::new();
    let mut size: u64 = 0;
    let mut spill: Option<Spill> = None;
    loop {
        let chunk = match tokio::time::timeout(IDLE, src.next()).await {
            Err(_) => return Err(Error::Stalled),
            Ok(None) => break,
            Ok(Some(Err(e))) => return Err(Error::Read(e)),
            Ok(Some(Ok(c))) => c,
        };
        size += chunk.len() as u64;
        if size > max {
            return Err(Error::TooLarge);
        }
        if declared.is_some_and(|d| size > d) {
            return Err(Error::WrongLength);
        }
        match &spill {
            Some((tx, _)) => {
                if tx.send(chunk).await.is_err() {
                    // The blocking side only stops early on an error.
                    let (_, task) = spill.take().expect("spilling");
                    let e = match task.await {
                        Ok(Err(e)) => e,
                        Ok(Ok(_)) => io::Error::other("the temp file's writer stopped early"),
                        Err(e) => io::Error::other(e),
                    };
                    return Err(Error::Disk(e));
                }
            }
            None => {
                head.extend_from_slice(&chunk);
                if head.len() > INLINE_MAX {
                    let (tx, rx) = mpsc::channel(QUEUE);
                    let task = tokio::task::spawn_blocking(move || write_file(files, rx));
                    tx.send(Bytes::copy_from_slice(&head))
                        .await
                        .map_err(|_| Error::Disk(io::Error::other("the writer stopped")))?;
                    head.truncate(8192);
                    spill = Some((tx, task));
                }
            }
        }
    }
    if declared.is_some_and(|d| size != d) {
        return Err(Error::WrongLength);
    }
    let mime = declared_type
        .and_then(mime::normalize)
        .or_else(|| mime::sniff(&head));
    match spill {
        None => Ok(Ingested {
            hash: Hash::of(&head),
            size,
            mime,
            body: IngestedBody::Inline(head),
        }),
        Some((tx, task)) => {
            drop(tx);
            let (hash, tmp) = task
                .await
                .map_err(|e| Error::Disk(io::Error::other(e)))?
                .map_err(Error::Disk)?;
            Ok(Ingested {
                hash,
                size,
                mime,
                body: IngestedBody::File(tmp),
            })
        }
    }
}

/// Write and hash chunks as they come. The writer flushes the file, with
/// every other in its batch, before anything knows of it.
fn write_file(files: &Files, mut rx: mpsc::Receiver<Bytes>) -> io::Result<(Hash, TempFile)> {
    let mut tmp = files.temp()?;
    let mut hasher = Hasher::new();
    let fd = std::os::fd::AsRawFd::as_raw_fd(tmp.file());
    {
        let mut out = io::BufWriter::with_capacity(1 << 20, tmp.file());
        let mut since_writeback = 0;
        while let Some(chunk) = rx.blocking_recv() {
            hasher.update(&chunk);
            out.write_all(&chunk)?;
            since_writeback += chunk.len();
            if since_writeback >= WRITEBACK_EVERY {
                out.flush()?;
                start_writeback(fd);
                since_writeback = 0;
            }
        }
        out.flush()?;
    }
    start_writeback(fd);
    Ok((hasher.finish(), tmp))
}

/// Have the kernel start writing a file's dirty pages out now, without
/// waiting: by the time the writer's `syncfs` comes, most are on disk, and
/// it waits on little.
fn start_writeback(fd: std::os::fd::RawFd) {
    // SAFETY: an open descriptor; only asks for writeback to begin.
    unsafe { libc::sync_file_range(fd, 0, 0, libc::SYNC_FILE_RANGE_WRITE) };
}
