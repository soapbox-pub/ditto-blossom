//! Brotli copies of compressible blobs, made in the background at low CPU
//! priority, never on the upload's path: quality 11 runs at 0.4-1 MB/s
//! (spike 4). A copy is kept only if it saves at least 5%; either way the
//! blob is marked as tried, so it isn't tried again.
//!
//! New blobs are offered as they're stored. At startup, every compressible
//! blob not yet tried is queued too: that's how blobs imported from
//! blossom-server, or offered while the queue was full, get theirs.

use std::io::Write;
use std::sync::mpsc;

use crate::blobs::{self, Files};
use crate::hash::Hash;
use crate::mime;
use crate::store::{INLINE_MAX, Record, Store, flag};
use crate::writer::{BrotliCopy, Writer};

/// Blobs waiting for a worker.
const QUEUE: usize = 4096;
/// Smaller than this, a blob arrives in one packet anyway.
const MIN_SIZE: u64 = 512;
/// Bigger than this isn't worth the CPU.
const MAX_SIZE: u64 = 256 << 20;

pub struct Compressor {
    tx: mpsc::SyncSender<(u64, Hash)>,
}

/// Whether a blob should get a brotli copy and hasn't been tried yet.
pub fn wanted(rec: &Record) -> bool {
    !rec.has(flag::BROTLI_CHECKED)
        && mime::compressible(rec.mime.as_deref())
        && (MIN_SIZE..=MAX_SIZE).contains(&rec.size)
}

impl Compressor {
    /// Start `workers` threads, and queue every blob still to be tried. With
    /// none, offers go nowhere and nothing is compressed.
    pub fn start(
        store: &'static Store,
        files: &'static Files,
        writer: Writer,
        workers: usize,
    ) -> Compressor {
        let (tx, rx) = mpsc::sync_channel::<(u64, Hash)>(QUEUE);
        if workers == 0 {
            return Compressor { tx };
        }
        let rx = std::sync::Arc::new(parking_lot::Mutex::new(rx));
        for i in 0..workers {
            let (rx, writer) = (rx.clone(), writer.clone());
            std::thread::Builder::new()
                .name(format!("brotli-{i}"))
                .spawn(move || {
                    // SAFETY: lowers this thread's own priority; nothing else.
                    unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 15) };
                    loop {
                        let job = rx.lock().recv();
                        let Ok((seq, hash)) = job else { return };
                        match compress(store, files, seq, &hash) {
                            Ok(Some((seq, copy))) => writer.brotli(seq, hash, copy),
                            Ok(None) => {}
                            Err(e) => crate::warn!("brotli_failed", "blob": hash.hex(), "error": format!("{e:#}")),
                        }
                    }
                })
                .expect("a brotli thread starts");
        }
        let backlog = tx.clone();
        std::thread::Builder::new()
            .name("brotli-backlog".into())
            .spawn(move || {
                let mut queued = 0u64;
                let r = store.each_record(1000, |seq, rec| {
                    if wanted(&rec) && backlog.send((seq, rec.hash)).is_ok() {
                        queued += 1;
                    }
                });
                if let Err(e) = r {
                    crate::warn!("brotli_backlog_failed", "error": format!("{e:#}"));
                }
                if queued > 0 {
                    crate::info!("brotli_backlog_queued", "blobs": queued);
                }
            })
            .expect("the backlog thread starts");
        Compressor { tx }
    }

    /// Offer a new blob. If the queue is full it's left for the next start.
    pub fn offer(&self, rec: &Record) {
        if wanted(rec) {
            // It's a blob just stored, so it has a seq; the record holds it
            // only by hash, so look it up when the worker gets to it.
            let _ = self.tx.try_send((0, rec.hash));
        }
    }
}

/// Brotli quality by size, as npanel does it: 11 is about 1 MB/s.
fn quality(size: u64) -> i32 {
    match size {
        s if s <= 1 << 20 => 11,
        s if s <= 16 << 20 => 9,
        _ => 5,
    }
}

/// The blob's seq and its copy (or that none is worth keeping); `None` if
/// it's gone, was replaced, or has been tried already.
fn compress(
    store: &'static Store,
    files: &Files,
    seq: u64,
    hash: &Hash,
) -> anyhow::Result<Option<(u64, BrotliCopy)>> {
    let Some(found) = store.find(hash, false)? else {
        return Ok(None);
    };
    if (seq != 0 && seq != found.seq) || !wanted(&found.record) {
        return Ok(None);
    }
    let seq = found.seq;
    let rec = &found.record;
    let mapped;
    let data: &[u8] = match &found.body {
        Some(b) => b,
        None => {
            let file = blobs::open_noatime(&files.path(hash, false))?;
            // SAFETY: blob files are never changed once in place.
            mapped = unsafe { memmap2::Mmap::map(&file)? };
            &mapped
        }
    };
    let params = brotli::enc::BrotliEncoderParams {
        quality: quality(rec.size),
        lgwin: 24,
        size_hint: data.len(),
        ..Default::default()
    };
    let mut out = Vec::new();
    brotli::BrotliCompress(&mut &data[..], &mut out, &params)?;
    if out.len() as u64 > rec.size - rec.size / 20 {
        return Ok(Some((seq, BrotliCopy::None)));
    }
    if out.len() <= INLINE_MAX {
        return Ok(Some((seq, BrotliCopy::Inline(out))));
    }
    let mut tmp = files.temp()?;
    tmp.file().write_all(&out)?;
    Ok(Some((seq, BrotliCopy::File(tmp, out.len() as u64))))
}
