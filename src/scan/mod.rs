//! Refusing explicit images and video.
//!
//! Every upload and mirror whose bytes are a picture or a video (by what the
//! bytes are, never by the type the client declares), and every one a
//! browser would show the pictures in (markup carrying them in data URIs,
//! a PDF), by its bytes or the type it's served as, is scanned on a pool of
//! worker threads: before it's stored, or with `background`, after, held
//! unserved until then. Anything scoring at or over the threshold is
//! refused, or taken out. Bytes that are no kind of media, which includes
//! everything encrypted, pass unscanned, and without waiting for a worker:
//! there's nothing in them to judge.
//!
//! What's refused by its score is banned, as an operator would ban it, so
//! the same blob offered again is refused from its `X-SHA-256` before a
//! byte of it is read.

pub mod cli;
mod embedded;
mod ffmpeg;
mod jpeg;
pub mod known;
pub mod model;
mod pdf;
mod pixels;
mod sandbox;
pub mod thumb;
pub mod train;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::config;
use crate::hash::Hash;
use model::{Encoder, Head, INPUT_LEN};
use pixels::Square;

/// Scans waiting for a worker. Uploads in progress are capped well below
/// this (`MAX_RECEIVING`), so it only fills if something else is wrong.
const QUEUE: usize = 256;
/// Scans one address may have waiting or underway at once: one client's
/// slow videos can't fill the queue everyone else's uploads wait in.
pub const PER_ADDRESS: usize = 4;
/// The bytes of a blob its type is told from.
pub const HEAD: usize = 8192;

/// What a blob's bytes are, as far as scanning goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Decoded here.
    Image,
    /// Decoded by ffmpeg: video, and AVIF, HEIC and JPEG XL.
    Video,
    /// Not media, or nothing that can be looked at.
    Other,
}

/// The kind of media `ty` (a sniffed type) is.
pub fn kind(ty: Option<&str>) -> Kind {
    match ty {
        Some(
            "image/jpeg"
            | "image/png"
            | "image/apng"
            | "image/gif"
            | "image/webp"
            | "image/bmp"
            | "image/tiff"
            | "image/x-icon"
            | "image/vnd.microsoft.icon",
        ) => Kind::Image,
        Some("image/avif" | "image/heif" | "image/heic" | "image/jxl") => Kind::Video,
        Some(t) if t.starts_with("video/") => Kind::Video,
        _ => Kind::Other,
    }
}

/// Types a browser shows as a page, drawing the pictures in its data URIs.
fn page_type(ty: &str) -> bool {
    matches!(
        ty,
        "text/html" | "application/xhtml+xml" | "text/xml" | "application/xml"
    ) || ty.ends_with("+xml")
}

/// A PDF, as a browser's viewer finds one: `%PDF-` in its first KiB.
fn is_pdf(head: &[u8]) -> bool {
    memchr::memmem::find(&head[..head.len().min(1024)], b"%PDF-").is_some()
}

/// What's looked at in a blob.
struct Looks {
    kind: Kind,
    /// Data URIs, as a page or an SVG shows them.
    markup: bool,
    pdf: bool,
}

/// What to look at in bytes beginning `head`, sniffed as `ty` and served
/// as `served`, the type the uploader declared: a page or a PDF only shows
/// as one if it's served as one, whatever its bytes look like.
fn looks(ty: Option<&str>, head: &[u8], served: Option<&str>) -> Looks {
    let served = served.map(|t| {
        t.split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
    });
    Looks {
        kind: match kind(ty) {
            // Sound in MP4's container (M4A) can carry pictures too: ffmpeg
            // finds any, and lets sound alone pass.
            Kind::Other if crate::mime::is_iso_bmff(head) => Kind::Video,
            k => k,
        },
        markup: embedded::is_markup(head) || served.as_deref().is_some_and(page_type),
        pdf: is_pdf(head) || served.as_deref() == Some("application/pdf"),
    }
}

/// Whether a blob beginning `head`, served as `served`, needs a worker to
/// judge it: anything but what's no kind of media, which is judged here and
/// now, so it never waits behind media in the queue.
pub fn needs_worker(head: &[u8], served: Option<&str>) -> bool {
    let head = &head[..head.len().min(HEAD)];
    let l = looks(crate::mime::sniff(head).as_deref(), head, served);
    l.kind != Kind::Other || l.markup || l.pdf
}

/// The scans each address has waiting or underway (see `PER_ADDRESS`).
#[derive(Default)]
pub struct Turns(Mutex<HashMap<IpAddr, usize>>);

/// One of an address's scans: given back when dropped.
pub struct Turn<'a> {
    turns: &'a Turns,
    key: IpAddr,
}

impl Turns {
    /// A turn for `ip`, unless it has `PER_ADDRESS` already. IPv6 addresses
    /// count by their /64, which one client can have the whole of.
    pub fn take(&self, ip: IpAddr) -> Option<Turn<'_>> {
        let key = match ip {
            IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => {
                let mut o = v6.octets();
                o[8..].fill(0);
                IpAddr::from(o)
            }
            IpAddr::V6(v6) => IpAddr::V4(v6.to_ipv4_mapped().expect("mapped")),
            v4 => v4,
        };
        let mut all = self.0.lock();
        let n = all.entry(key).or_default();
        if *n >= PER_ADDRESS {
            return None;
        }
        *n += 1;
        Some(Turn { turns: self, key })
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut all = self.turns.0.lock();
        if let Some(n) = all.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                all.remove(&self.key);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Outcome {
    /// Not media: passed unscanned.
    NotMedia,
    /// Media this server isn't set up to look at (video, without ffmpeg).
    Unscanned,
    /// The highest score of anything looked at: the chance it's explicit.
    Scored(f32),
    /// Media that couldn't be decoded, and why.
    Undecodable(String),
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub outcome: Outcome,
    /// The type the bytes were taken for.
    pub ty: Option<String>,
    /// Squares looked at.
    pub looked: usize,
    pub millis: f64,
    /// Of which decoding took.
    pub decode_millis: f64,
}

/// What's refused.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub threshold: f32,
    pub refuse_undecodable: bool,
}

impl Rule {
    /// The threshold in force is the config's, else the head's.
    pub fn of(scan: &config::Scan, head: Option<&Head>) -> Result<Rule> {
        let threshold = match (scan.threshold, head) {
            (Some(t), _) => t,
            (None, Some(h)) => h.threshold,
            (None, None) => bail!("[scan] needs `head` (see ditto-blossom train) or a `threshold`"),
        };
        Ok(Rule {
            threshold,
            refuse_undecodable: scan.refuse_undecodable,
        })
    }
}

impl Verdict {
    pub fn refused(&self, rule: Rule) -> bool {
        match &self.outcome {
            Outcome::Scored(s) => *s >= rule.threshold,
            Outcome::Undecodable(_) => rule.refuse_undecodable,
            Outcome::NotMedia | Outcome::Unscanned => false,
        }
    }

    pub fn score(&self) -> Option<f32> {
        match self.outcome {
            Outcome::Scored(s) => Some(s),
            _ => None,
        }
    }
}

/// Where a blob's bytes are.
pub enum Input {
    Bytes(Arc<[u8]>),
    File(PathBuf),
}

struct Job {
    input: Input,
    /// The type it's served as.
    served: Option<String>,
    work: Work,
}

/// What a worker is asked: to judge a blob, or to embed it for training.
enum Work {
    Check(Box<dyn FnOnce(Verdict) + Send>),
    Embed(Box<dyn FnOnce(Result<Embedding>) + Send>),
}

/// A blob's squares embedded, as `train` reads them, and the encoder's
/// fingerprint, which a training cache is kept for.
pub struct Embedding {
    pub fingerprint: Vec<f32>,
    pub squares: Vec<Vec<f32>>,
}

/// Too many scans waiting.
#[derive(Debug)]
pub struct Busy;

pub struct Scanner {
    pub rule: Rule,
    tx: mpsc::SyncSender<Job>,
    /// Blobs stored and waiting for a background scan.
    later: mpsc::Sender<Hash>,
    later_rx: Mutex<Option<mpsc::Receiver<Hash>>>,
    /// How many of those there are, queued or being scanned.
    pending: std::sync::atomic::AtomicUsize,
    /// Each address's scans before storing.
    pub turns: Turns,
}

impl Scanner {
    /// Load the encoder and start the workers, failing if it can't load.
    pub fn start(scan: &config::Scan) -> Result<Scanner> {
        let model = scan
            .model
            .clone()
            .context("[scan] needs `model`, the image encoder's path")?;
        let ffmpeg = (!scan.ffmpeg.as_os_str().is_empty()).then(|| scan.ffmpeg.clone());
        if let Some(ff) = &ffmpeg {
            let p = sandbox::probe(ff);
            crate::info!("ffmpeg_sandbox", "landlock_abi": p.landlock, "network_namespace": p.netns,
                "files_confined": p.files(), "network_confined": p.network());
            if !(p.files() && p.network()) {
                if scan.require_sandbox {
                    bail!(
                        "scan.require_sandbox: ffmpeg can't be confined here (files {}, network {}); \
                         it needs Landlock (Linux 5.13+), and 6.7+ or user namespaces",
                        p.files(),
                        p.network()
                    );
                }
                crate::warn!("ffmpeg_unconfined", "files_confined": p.files(), "network_confined": p.network());
            }
            sandbox::require(scan.require_sandbox);
        }
        let head = load_head(scan)?;
        let rule = Rule::of(scan, head.as_deref())?;
        let workers = scan.workers.unwrap_or_else(default_workers).max(1);
        let background = scan.background;
        // Scanning after the fact gives way to taking uploads. The encoder's
        // own threads are made as it loads, and take its priority.
        let lower = move || {
            if background {
                // SAFETY: lowers this thread's own priority; nothing else.
                unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 10) };
            }
        };
        let shared = Shared::start(&model, head, workers, lower)?;
        let (tx, rx) = mpsc::sync_channel::<Job>(QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..workers {
            let (rx, ffmpeg, shared) = (rx.clone(), ffmpeg.clone(), shared.clone());
            std::thread::Builder::new()
                .name(format!("scan-{i}"))
                .spawn(move || {
                    lower();
                    let mut worker = Worker::sharing(shared, ffmpeg);
                    loop {
                        let job = rx.lock().recv();
                        let Ok(job) = job else { return };
                        match job.work {
                            Work::Check(reply) => {
                                reply(worker.check_safely(&job.input, job.served.as_deref()))
                            }
                            Work::Embed(reply) => {
                                reply(worker.embed_safely(&job.input, job.served.as_deref()))
                            }
                        }
                    }
                })
                .context("A scan worker didn't start")?;
        }
        let (later, later_rx) = mpsc::channel();
        Ok(Scanner {
            rule,
            later,
            later_rx: Mutex::new(Some(later_rx)),
            pending: std::sync::atomic::AtomicUsize::new(0),
            turns: Turns::default(),
            tx,
        })
    }

    /// Scan a blob, served as `served`, on a worker.
    pub async fn check(&self, input: Input, served: Option<&str>) -> Result<Verdict, Busy> {
        let (reply, rx) = oneshot::channel();
        let work = Work::Check(Box::new(move |v| drop(reply.send(v))));
        let served = served.map(String::from);
        self.tx
            .try_send(Job {
                input,
                served,
                work,
            })
            .map_err(|_| Busy)?;
        rx.await.map_err(|_| Busy)
    }

    /// Embed a blob's squares on a worker, as `train` would, to keep for
    /// training.
    pub async fn embed(&self, input: Input, served: Option<&str>) -> Result<Embedding> {
        let (reply, rx) = oneshot::channel();
        let work = Work::Embed(Box::new(move |e| drop(reply.send(e))));
        let served = served.map(String::from);
        self.tx
            .try_send(Job {
                input,
                served,
                work,
            })
            .map_err(|_| anyhow::anyhow!("The scanners are busy; try again shortly"))?;
        rx.await.context("A scan worker stopped")?
    }

    /// Queue a stored blob for a background scan.
    pub fn later(&self, hash: Hash) {
        self.pending
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.later.send(hash).is_err() {
            self.pending
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Blobs stored and not yet scanned, of those queued since the start.
    pub fn pending(&self) -> usize {
        self.pending.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Scan stored blobs as they're queued, and those an earlier run left
    /// unscanned: refused ones are taken out, the rest are served.
    pub fn start_background(app: &'static crate::app::App) {
        let Some(scanner) = app.scanner.as_ref() else {
            return;
        };
        let Some(rx) = scanner.later_rx.lock().take() else {
            return;
        };
        std::thread::Builder::new()
            .name("scan-later".into())
            .spawn(move || {
                while let Ok(hash) = rx.recv() {
                    let done = || {
                        scanner.pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    };
                    let found = match app.store.find(&hash, false) {
                        Ok(Some(f)) if f.record.has(crate::store::flag::UNSCANNED) => f,
                        Ok(_) => {
                            done();
                            continue;
                        }
                        Err(e) => {
                            crate::error!("scan_find_failed", "blob": hash.hex(), "error": format!("{e:#}"));
                            done();
                            continue;
                        }
                    };
                    let input = match found.body {
                        Some(b) => Input::Bytes(Arc::from(&b[..])),
                        None => Input::File(app.files.path(&hash, false)),
                    };
                    let (seq, size, queued) = (found.seq, found.record.size, Instant::now());
                    let served = found.record.mime.clone();
                    let reply = Box::new(move |v: Verdict| {
                        let refused = v.refused(scanner.rule);
                        if refused {
                            crate::info!(
                                "refused", "via": "background", "blob": hash.hex(), "size": size,
                                "type": v.ty, "score": v.score(), "outcome": format!("{:?}", v.outcome),
                                "ms": v.millis.round(), "waited_ms": queued.elapsed().as_millis() as u64,
                            );
                        }
                        app.writer.scanned(seq, hash, refused.then(|| v.score()));
                        scanner.pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    });
                    // Waits for room: the queue is the backlog's pace.
                    let job = Job {
                        input,
                        served,
                        work: Work::Check(reply),
                    };
                    if scanner.tx.send(job).is_err() {
                        return;
                    }
                }
            })
            .expect("the background scan thread starts");
        std::thread::Builder::new()
            .name("scan-backlog".into())
            .spawn(move || {
                let mut queued = 0u64;
                let r = app.store.each_record(1000, |_, rec| {
                    if rec.has(crate::store::flag::UNSCANNED) {
                        scanner.later(rec.hash);
                        queued += 1;
                    }
                });
                if let Err(e) = r {
                    crate::warn!("scan_backlog_failed", "error": format!("{e:#}"));
                }
                if queued > 0 {
                    crate::info!("scan_backlog_queued", "blobs": queued);
                }
            })
            .expect("the scan backlog thread starts");
    }
}

/// Two: ~16 images a second, past the busiest minute one server had in
/// eight months (4.8/s). Workers share one encoder, ~380 MB.
fn default_workers() -> usize {
    2
}

/// The head the config names. Each worker checks it against its encoder.
pub fn load_head(scan: &config::Scan) -> Result<Option<Arc<Head>>> {
    scan.head
        .as_deref()
        .map(|p| Head::load(p).map(Arc::new))
        .transpose()
}

/// What scores a square: the encoder and head, or in tests a stand-in.
trait Classifier: Send {
    fn score(&mut self, square: &[u8]) -> Result<f32>;
    /// The square's embedding, which the head scores.
    fn embed(&mut self, square: &[u8]) -> Result<Vec<f32>>;
    /// What tells this encoder's embeddings from another's.
    fn fingerprint(&mut self) -> Result<Vec<f32>>;
}

struct Clip {
    encoder: Encoder,
    head: Arc<Head>,
    input: Vec<f32>,
}

impl Classifier for Clip {
    fn score(&mut self, square: &[u8]) -> Result<f32> {
        let e = self.embed(square)?;
        Ok(self.head.score(&e))
    }

    fn embed(&mut self, square: &[u8]) -> Result<Vec<f32>> {
        model::to_input(square, &mut self.input);
        self.encoder.embed(&self.input)
    }

    fn fingerprint(&mut self) -> Result<Vec<f32>> {
        self.encoder.fingerprint()
    }
}

/// Tests' stand-in, `model = "test:red"`: how much redder than green the
/// square is, so red is "explicit" and grey isn't.
#[cfg(test)]
struct Red;

#[cfg(test)]
impl Classifier for Red {
    fn score(&mut self, square: &[u8]) -> Result<f32> {
        let e = self.embed(square)?;
        Ok((e[0] - e[1]).clamp(0.0, 1.0))
    }

    /// Its mean red, green and blue, 0 to 1.
    fn embed(&mut self, square: &[u8]) -> Result<Vec<f32>> {
        let mut sums = [0u64; 3];
        for px in square.chunks_exact(3) {
            for (s, v) in sums.iter_mut().zip(px) {
                *s += *v as u64;
            }
        }
        let n = (square.len() / 3) as f32 * 255.0;
        Ok(sums.iter().map(|s| *s as f32 / n).collect())
    }

    fn fingerprint(&mut self) -> Result<Vec<f32>> {
        Ok(vec![1.0, 0.0, 0.0])
    }
}

/// What's asked of the shared classifier, and where to answer.
enum Ask {
    Score(Square, mpsc::SyncSender<Result<f32>>),
    Embed(Square, mpsc::SyncSender<Result<Vec<f32>>>),
    Fingerprint(mpsc::SyncSender<Result<Vec<f32>>>),
}

/// One classifier on a thread of its own, its encoder running on as many
/// cores as there are workers, which decode side by side and hand it their
/// squares. It scores as many a second as an encoder a worker did, holds
/// its weights once rather than ~380 MB a worker, and a worker waiting on
/// ffmpeg holds no encoder idle.
#[derive(Clone)]
struct Shared(mpsc::Sender<Ask>);

impl Shared {
    /// Load the classifier on its thread, after `setup` runs there.
    fn start(
        model: &Path,
        head: Option<Arc<Head>>,
        threads: usize,
        setup: impl FnOnce() + Send + 'static,
    ) -> Result<Shared> {
        let (tx, rx) = mpsc::channel::<Ask>();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let model = model.to_path_buf();
        std::thread::Builder::new()
            .name("scan-encoder".into())
            .spawn(move || {
                setup();
                let mut c = match classifier(&model, head, threads) {
                    Ok(c) => {
                        let _ = ready_tx.send(Ok(()));
                        c
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                while let Ok(ask) = rx.recv() {
                    match ask {
                        Ask::Score(sq, reply) => drop(reply.send(c.score(&sq))),
                        Ask::Embed(sq, reply) => drop(reply.send(c.embed(&sq))),
                        Ask::Fingerprint(reply) => drop(reply.send(c.fingerprint())),
                    }
                }
            })
            .context("The scan encoder didn't start")?;
        ready_rx
            .recv()
            .context("The scan encoder stopped while starting")??;
        Ok(Shared(tx))
    }

    fn ask<T>(&self, make: impl FnOnce(mpsc::SyncSender<Result<T>>) -> Ask) -> Result<T> {
        let (reply, answer) = mpsc::sync_channel(1);
        self.0
            .send(make(reply))
            .ok()
            .context("the scan encoder stopped")?;
        answer.recv().context("the scan encoder stopped")?
    }
}

impl Classifier for Shared {
    fn score(&mut self, square: &[u8]) -> Result<f32> {
        self.ask(|r| Ask::Score(square.to_vec(), r))
    }

    fn embed(&mut self, square: &[u8]) -> Result<Vec<f32>> {
        self.ask(|r| Ask::Embed(square.to_vec(), r))
    }

    fn fingerprint(&mut self) -> Result<Vec<f32>> {
        self.ask(Ask::Fingerprint)
    }
}

/// The classifier `path` names, its encoder running on `threads` cores.
fn classifier(path: &Path, head: Option<Arc<Head>>, threads: usize) -> Result<Box<dyn Classifier>> {
    #[cfg(test)]
    if path == Path::new("test:red") {
        return Ok(Box::new(Red));
    }
    let head =
        head.context("[scan] needs `head`, the trained head's path (see ditto-blossom train)")?;
    let mut encoder = Encoder::load(path, threads)?;
    head.check(&mut encoder)?;
    Ok(Box::new(Clip {
        encoder,
        head,
        input: vec![0.0; INPUT_LEN],
    }))
}

/// Decoding, on one thread, and a classifier: its own, or the shared one.
pub struct Worker {
    model: Box<dyn Classifier>,
    ffmpeg: Option<PathBuf>,
    /// The encoder's fingerprint, once asked for.
    fingerprint: Option<Vec<f32>>,
}

impl Worker {
    /// A worker with a classifier of its own, on one core.
    pub fn new(model: &Path, head: Option<Arc<Head>>, ffmpeg: Option<PathBuf>) -> Result<Worker> {
        Ok(Worker {
            model: classifier(model, head, 1)?,
            ffmpeg,
            fingerprint: None,
        })
    }

    fn sharing(model: Shared, ffmpeg: Option<PathBuf>) -> Worker {
        Worker {
            model: Box::new(model),
            ffmpeg,
            fingerprint: None,
        }
    }

    /// [`embed`](Self::embed), a decoder's panic made an error.
    pub fn embed_safely(&mut self, input: &Input, served: Option<&str>) -> Result<Embedding> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.embed(input, served)))
            .unwrap_or_else(|_| Err(anyhow::anyhow!("A decoder panicked")))
    }

    /// Every square a scan would look at, embedded, as `train` does.
    pub fn embed(&mut self, input: &Input, served: Option<&str>) -> Result<Embedding> {
        let mapped;
        let bytes: &[u8] = match input {
            Input::Bytes(b) => b,
            Input::File(p) => {
                mapped = map(p)?;
                &mapped
            }
        };
        let (_, squares) = decode(bytes, input, served, self.ffmpeg.as_deref());
        let squares = squares?
            .filter(|s| !s.is_empty())
            .context("There's no picture in it to learn from")?;
        let squares = squares
            .iter()
            .map(|sq| self.model.embed(sq))
            .collect::<Result<Vec<_>>>()?;
        let fingerprint = match &self.fingerprint {
            Some(f) => f.clone(),
            None => {
                let f = self.model.fingerprint()?;
                self.fingerprint = Some(f.clone());
                f
            }
        };
        Ok(Embedding {
            fingerprint,
            squares,
        })
    }

    /// [`check`](Self::check), with a decoder's panic on malformed bytes
    /// made an undecodable verdict rather than the end of the worker.
    pub fn check_safely(&mut self, input: &Input, served: Option<&str>) -> Verdict {
        let checked =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check(input, served)));
        checked.unwrap_or_else(|_| Verdict {
            outcome: Outcome::Undecodable("a decoder panicked".into()),
            ty: None,
            looked: 0,
            millis: 0.0,
            decode_millis: 0.0,
        })
    }

    pub fn check(&mut self, input: &Input, served: Option<&str>) -> Verdict {
        let started = Instant::now();
        let mapped;
        let bytes: &[u8] = match input {
            Input::Bytes(b) => b,
            Input::File(p) => match map(p) {
                Ok(m) => {
                    mapped = m;
                    &mapped
                }
                Err(e) => {
                    return Verdict {
                        outcome: Outcome::Undecodable(format!("unreadable: {e}")),
                        ty: None,
                        looked: 0,
                        millis: 0.0,
                        decode_millis: 0.0,
                    };
                }
            },
        };
        let (ty, squares) = decode(bytes, input, served, self.ffmpeg.as_deref());
        let decode_millis = started.elapsed().as_secs_f64() * 1000.0;
        let (outcome, looked) = match squares {
            Ok(None) if kind(ty.as_deref()) == Kind::Other => (Outcome::NotMedia, 0),
            Ok(None) => (Outcome::Unscanned, 0),
            Ok(Some(sq)) => match self.score(&sq) {
                Ok(s) => (Outcome::Scored(s), sq.len()),
                Err(e) => (Outcome::Undecodable(format!("{e:#}")), sq.len()),
            },
            Err(e) => (Outcome::Undecodable(format!("{e:#}")), 0),
        };
        Verdict {
            outcome,
            ty,
            looked,
            millis: started.elapsed().as_secs_f64() * 1000.0,
            decode_millis,
        }
    }

    /// The highest score of any square; it stops at the first that's
    /// certain, as nothing after it could lower the answer.
    fn score(&mut self, squares: &[Square]) -> Result<f32> {
        if squares.is_empty() {
            bail!("nothing to look at");
        }
        let mut worst = 0.0f32;
        for sq in squares {
            // `max` would pass over NaN, and the blob with it.
            let s = self.model.score(sq)?;
            if !s.is_finite() {
                bail!("the encoder gave no score");
            }
            worst = worst.max(s);
            if worst > 0.995 {
                break;
            }
        }
        Ok(worst)
    }
}

/// The type the bytes are taken for and the squares to look at: `None`
/// for bytes there's nothing to look at in, or (video, without ffmpeg)
/// nothing this server can. `served` is the type they're served as.
pub fn decode(
    bytes: &[u8],
    input: &Input,
    served: Option<&str>,
    ffmpeg: Option<&Path>,
) -> (Option<String>, Result<Option<Vec<Square>>>) {
    let head = &bytes[..bytes.len().min(HEAD)];
    let ty = crate::mime::sniff(head);
    let looks = looks(ty.as_deref(), head, served);
    // However many times ffmpeg is run for it, a blob gets this long.
    let deadline = Instant::now() + ffmpeg::TIMEOUT;
    let mut squares = match looks.kind {
        Kind::Other => Ok(None),
        Kind::Image => pixels::decode(bytes, ty.as_deref().unwrap_or_default()).map(Some),
        Kind::Video => match ffmpeg {
            None => Ok(None),
            Some(ff) => {
                let src = match input {
                    Input::File(p) => ffmpeg::Input::File(p),
                    Input::Bytes(b) => ffmpeg::Input::Bytes(b),
                };
                let still = ty.as_deref().is_some_and(|t| t.starts_with("image/"));
                ffmpeg::squares(ff, src, still, deadline)
            }
        },
    };
    // A file may be more than one thing at once: a picture that's a PDF
    // too shows as either, as it's served.
    if looks.markup {
        squares = more(squares, || embedded::squares(bytes, ffmpeg, deadline));
    }
    if looks.pdf {
        squares = more(squares, || pdf::squares(bytes, deadline));
    }
    (ty, squares)
}

/// Squares found, and those from another look, unless either failed.
fn more(
    found: Result<Option<Vec<Square>>>,
    then: impl FnOnce() -> Result<Option<Vec<Square>>>,
) -> Result<Option<Vec<Square>>> {
    let found = found?;
    Ok(match (found, then()?) {
        (Some(mut a), Some(b)) => {
            a.extend(b);
            Some(a)
        }
        (a, b) => a.or(b),
    })
}

pub fn map(path: &Path) -> std::io::Result<memmap2::Mmap> {
    let file = crate::blobs::open_noatime(path)?;
    // SAFETY: temp files are written once, by the upload that's waiting on
    // this scan, and not touched while it waits. Stored blobs (a background
    // scan's) are never written once placed, only unlinked, which leaves
    // the mapping whole. Nothing truncates either, which would SIGBUS.
    unsafe { memmap2::Mmap::map(&file) }
}
