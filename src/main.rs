//! ditto-blossom: a Blossom server on LMDB, built for ext4 and sendfile.

mod access;
mod admin;
mod app;
mod auth;
mod blobs;
mod compress;
mod config;
#[cfg(test)]
mod e2e;
mod hash;
mod http;
mod import;
mod ingest;
mod limits;
mod lmdb;
mod log;
mod mime;
mod mirror;
mod moderate;
mod pdq;
mod peers;
mod restore;
mod routes;
mod scan;
mod send_file;
mod serve;
mod server;
mod shield;
mod store;
mod upload;
mod writer;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;

use crate::config::Config;

const USAGE: &str = "\
usage:
  ditto-blossom [serve] [-c CONFIG]
  ditto-blossom import [-c CONFIG] --sqlite DB --blobs DIR [--copy] [--verify]
  ditto-blossom remove [-c CONFIG] SHA256...
  ditto-blossom ban [-c CONFIG] [--reason TEXT] [--preserve DIR] [--pubkey HEX]... [SHA256]...
  ditto-blossom unban [-c CONFIG] [--pubkey HEX]... [SHA256]...
  ditto-blossom bans [-c CONFIG]
  ditto-blossom restore [-c CONFIG] [--owner HEX]... [--except SHA256]... [--verify] DIR
  ditto-blossom scan [-c CONFIG] [--from SEQ] [--limit N] [--dry-run]
  ditto-blossom scan [-c CONFIG | --model ENCODER --head HEAD] [--threshold T] [--ffmpeg PATH] [--jobs N] [--refused] PATH...
  ditto-blossom train [-c CONFIG | --model ENCODER] --labels LABELS --out HEAD [--blobs DIR]... [--catch 0.99] [--c 3] [--jobs N] [--scores FILE] [--cache FILE]
  ditto-blossom pdq FILE...
  ditto-blossom --version

CONFIG defaults to ./ditto-blossom.toml.
import takes over a blossom-server's blobs: its SQLite database and its blob
directory. Files are hard-linked into place unless --copy; --verify hashes
every file, not only the small ones.
remove takes blobs out entirely, whoever owns them.
ban does that and keeps them out: banned blobs aren't stored again, by
anyone, and banned pubkeys can't upload or mirror. A pubkey's ban takes out
and bans every blob it owns; --preserve copies each blob it removes to DIR
first. unban lifts bans; bans lists them.
restore puts back what a ban took out by mistake, from the copies --preserve
(or a scan match) kept in DIR: each is unbanned, linked back into place and
given back to the owners its <sha256>.json names, or --owner. --except names
blobs to leave banned and preserved.
scan, given no files, asks Arachnid Shield about every image already here,
and deals with each match as an upload's: preserved, banned with its
uploaders, recorded and alerted. --from carries on from the seq a stopped
scan gave; --limit stops after N blobs; --dry-run only lists matches.
scan, given files and directories, scores them for explicit media as
uploads would be, one JSON line each; --refused prints only those that
would be refused. Pointed at the data's blobs/ directory, the names it
prints are hashes `ban` takes.
train fits the scan head to LABELS, {\"<sha256>\": \"explicit\" | \"clean\"},
finding the blobs under each --blobs DIR (the data's blobs/ if none), and
chooses the threshold that catches --catch of the explicit, unseen.
pdq prints each image's PDQ hash (base64) and quality, as scan sends them.";

/// How often reads are folded into the access table.
const ACCESS_FLUSH: Duration = Duration::from_secs(300);

fn main() {
    if let Err(e) = run() {
        eprintln!("ditto-blossom: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let command = match args.peek().map(String::as_str) {
        Some(
            "serve" | "import" | "remove" | "ban" | "unban" | "bans" | "scan" | "train" | "pdq"
            | "restore",
        ) => args.next().expect("peeked"),
        Some("--version" | "-V") => {
            println!("ditto-blossom {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return Ok(());
        }
        _ => "serve".to_string(),
    };
    let mut config_path = PathBuf::from("ditto-blossom.toml");
    let (mut sqlite, mut dir, mut copy, mut verify) = (None, None, false, false);
    let mut hashes = Vec::new();
    let (mut pubkeys, mut reason, mut preserve) = (Vec::new(), String::new(), None);
    let (mut from, mut limit, mut dry_run) = (0u64, None, false);
    let names_blobs = matches!(command.as_str(), "remove" | "ban" | "unban");
    let targeted = matches!(command.as_str(), "ban" | "unban");
    // scan and train
    let scanning = command == "scan" || command == "train";
    let (mut model, mut head, mut threshold, mut ffmpeg, mut jobs) = (None, None, None, None, None);
    let (mut refused, mut paths) = (false, Vec::new());
    let (mut labels, mut out, mut scores, mut blob_dirs) = (None, None, None, Vec::new());
    let mut cache = None;
    let (mut catch, mut c) = (0.99f64, 3.0f64);
    let mut config_given = false;
    let (mut restore_owners, mut restore_except) = (Vec::new(), Vec::new());
    while let Some(arg) = args.next() {
        let mut value = || args.next().with_context(|| format!("{arg} needs a value"));
        let mut number = |what: &str| -> Result<f64> {
            value()?
                .parse()
                .with_context(|| format!("{what} is a number"))
        };
        match arg.as_str() {
            "-c" | "--config" => {
                config_path = value()?.into();
                config_given = true;
            }
            "--model" if scanning => model = Some(PathBuf::from(value()?)),
            "--ffmpeg" if scanning => ffmpeg = Some(PathBuf::from(value()?)),
            "--jobs" if scanning => jobs = Some(number("--jobs")?.max(1.0) as usize),
            "--head" if command == "scan" => head = Some(PathBuf::from(value()?)),
            "--threshold" if command == "scan" => threshold = Some(number("--threshold")? as f32),
            "--refused" if command == "scan" => refused = true,
            path if (command == "scan" || command == "pdq") && !path.starts_with('-') => {
                paths.push(PathBuf::from(path))
            }
            "--labels" if command == "train" => labels = Some(PathBuf::from(value()?)),
            "--out" if command == "train" => out = Some(PathBuf::from(value()?)),
            "--scores" if command == "train" => scores = Some(PathBuf::from(value()?)),
            "--cache" if command == "train" => cache = Some(PathBuf::from(value()?)),
            "--blobs" if command == "train" => blob_dirs.push(PathBuf::from(value()?)),
            "--catch" if command == "train" => catch = number("--catch")?,
            "--c" if command == "train" => c = number("--c")?,
            "--sqlite" if command == "import" => sqlite = Some(PathBuf::from(value()?)),
            "--blobs" if command == "import" => dir = Some(PathBuf::from(value()?)),
            "--copy" if command == "import" => copy = true,
            "--verify" if command == "import" => verify = true,
            "--reason" if command == "ban" => reason = value()?,
            "--preserve" if command == "ban" => preserve = Some(PathBuf::from(value()?)),
            "--from" if command == "scan" => {
                from = value()?.parse().context("--from takes a blob's seq")?
            }
            "--limit" if command == "scan" => {
                limit = Some(value()?.parse().context("--limit takes a number")?)
            }
            "--dry-run" if command == "scan" => dry_run = true,
            "--verify" if command == "restore" => verify = true,
            "--owner" | "--except" if command == "restore" => {
                let v = value()?;
                match arg.as_str() {
                    "--owner" => restore_owners.push(
                        hex::decode(&v)
                            .ok()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .with_context(|| format!("{v} isn't a hex pubkey"))?,
                    ),
                    _ => restore_except.push(
                        hash::Hash::parse(v.as_bytes())
                            .with_context(|| format!("{v} isn't a SHA-256 hash"))?,
                    ),
                }
            }
            path if command == "restore" && !path.starts_with('-') => {
                dir = Some(PathBuf::from(path))
            }
            "--pubkey" if targeted => {
                let hex = value()?;
                pubkeys.push(
                    hex::decode(&hex)
                        .ok()
                        .and_then(|v| <[u8; 32]>::try_from(v).ok())
                        .with_context(|| format!("{hex} isn't a hex pubkey"))?,
                );
            }
            hex if names_blobs && !hex.starts_with('-') => hashes.push(
                hash::Hash::parse(hex.as_bytes())
                    .with_context(|| format!("{hex} isn't a SHA-256 hash"))?,
            ),
            _ => bail!("unexpected argument {arg}\n\n{USAGE}"),
        }
    }
    // scan given no files asks Shield about what's stored, below.
    let shield_scan = command == "scan" && paths.is_empty();
    if shield_scan
        && (model.is_some()
            || head.is_some()
            || threshold.is_some()
            || ffmpeg.is_some()
            || jobs.is_some()
            || refused)
    {
        bail!("scan needs files or directories to score\n\n{USAGE}");
    }
    if command == "scan" && !shield_scan && (from > 0 || limit.is_some() || dry_run) {
        bail!("--from, --limit and --dry-run are for scan given no files\n\n{USAGE}");
    }
    if scanning && !shield_scan {
        // A config is read unless the encoder is given without one.
        let config = (config_given || model.is_none())
            .then(|| Config::load(&config_path))
            .transpose()?;
        let mut scan = config
            .as_ref()
            .map_or_else(Default::default, |c| c.scan.clone());
        scan.model = model.or(scan.model);
        scan.head = head.or(scan.head);
        scan.threshold = threshold.or(scan.threshold);
        scan.ffmpeg = ffmpeg.unwrap_or(scan.ffmpeg);
        if command == "scan" {
            return scan::cli::run(&scan, &paths, jobs, refused);
        }
        if !(0.5..1.0).contains(&catch) {
            bail!("--catch is a share, at least 0.5 and under 1");
        }
        if blob_dirs.is_empty() {
            let c = config.context("train needs --blobs DIR, or a config")?;
            blob_dirs.push(c.data.join("blobs"));
        }
        let all = std::thread::available_parallelism().map_or(1, |n| n.get());
        return scan::train::run(
            &scan,
            &scan::train::Options {
                labels: labels.context("train needs --labels")?,
                out: out.context("train needs --out, where the head goes")?,
                blobs: blob_dirs,
                catch,
                c,
                jobs: jobs.unwrap_or(all),
                scores,
                cache,
            },
        );
    }
    let targets: Vec<store::Banned> = hashes
        .iter()
        .map(|h| store::Banned::Blob(*h))
        .chain(pubkeys.into_iter().map(store::Banned::Pubkey))
        .collect();
    if targeted && targets.is_empty() {
        bail!("{command} needs a SHA256 or --pubkey\n\n{USAGE}");
    }
    if command == "pdq" {
        return pdq_files(&paths);
    }
    let config = Config::load(&config_path)?;
    match command.as_str() {
        "remove" => import::remove(&config, &hashes),
        "ban" => moderate::ban(&config, &targets, &reason, preserve.as_deref()),
        "unban" => moderate::unban(&config, &targets),
        "bans" => moderate::list(&config),
        "restore" => restore::run(
            &config,
            &dir.context("restore needs the directory the copies are in")?,
            &restore_owners,
            &restore_except,
            verify,
        )
        .map(|_| ()),
        "scan" => {
            install_crypto();
            scan::known::scan_existing(&config, from, limit, dry_run)
        }
        "import" => import::run(
            &config,
            &sqlite.context("import needs --sqlite")?,
            &dir.context("import needs --blobs")?,
            copy,
            verify,
        ),
        _ => serve(config),
    }
}

fn pdq_files(paths: &[PathBuf]) -> Result<()> {
    for p in paths {
        let f =
            std::fs::File::open(p).with_context(|| format!("Could not open {}", p.display()))?;
        match pdq::of(std::io::BufReader::new(f)) {
            Ok(Some(h)) => println!("{}\t{:.2}\t{}", h.base64(), h.quality, p.display()),
            Ok(None) => println!("-\t-\t{}", p.display()),
            Err(e) => println!("-\t{e}\t{}", p.display()),
        }
    }
    Ok(())
}

fn serve(config: Config) -> Result<()> {
    raise_nofile();
    install_crypto();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let app = app::App::open(config)?;
        let listener = tokio::net::TcpListener::bind(app.config.listen)
            .await
            .with_context(|| format!("Could not listen on {}", app.config.listen))?;
        crate::info!("listening", "address": app.config.listen.to_string(), "public_url": app.config.public_url, "blobs": app.store.count().unwrap_or(0));

        let shutdown = CancellationToken::new();
        if let Some(addr) = app.config.admin.listen {
            let admin = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("Could not listen on {addr}"))?;
            crate::info!("admin_listening", "address": addr.to_string());
            tokio::spawn(server::serve(
                admin,
                move |req, peer| admin::handle(app, req, peer),
                shutdown.clone(),
            ));
        }
        tokio::spawn(flush_access(app, shutdown.clone()));
        tokio::spawn(expire_evidence(app, shutdown.clone()));
        tokio::spawn(stop_on_signal(shutdown.clone()));
        tokio::spawn(peers::follow(app, shutdown.clone()));
        tokio::spawn(scan::known::retry_unscanned(
            app,
            Duration::from_secs(app.config.scan.retry_every.max(10)),
            shutdown.clone(),
        ));
        server::serve(listener, move |req, peer| routes::handle(app, req, peer), shutdown).await;

        let seqs = app.access.take();
        app.store.touch(&seqs, access::today())?;
        app.store.sync_stats()?;
        crate::info!("stopped");
        Ok(())
    })
}

async fn flush_access(app: &'static app::App, shutdown: CancellationToken) {
    let mut every = tokio::time::interval(ACCESS_FLUSH);
    every.tick().await;
    loop {
        tokio::select! {
            _ = every.tick() => {}
            _ = shutdown.cancelled() => return,
        }
        let seqs = app.access.take();
        if seqs.is_empty() {
            continue;
        }
        let result =
            tokio::task::spawn_blocking(move || app.store.touch(&seqs, access::today())).await;
        if let Ok(Err(e)) = result {
            crate::warn!("access_flush_failed", "error": format!("{e:#}"));
        }
    }
}

/// Delete evidence kept its year past its report, at startup and daily.
async fn expire_evidence(app: &'static app::App, shutdown: CancellationToken) {
    let mut every = tokio::time::interval(Duration::from_secs(86400));
    loop {
        tokio::select! {
            _ = every.tick() => {}
            _ = shutdown.cancelled() => return,
        }
        let dir = app.config.evidence();
        let result =
            tokio::task::spawn_blocking(move || moderate::expire(&dir, upload::now())).await;
        if let Ok(Err(e)) = result {
            crate::warn!("evidence_expire_failed", "error": format!("{e:#}"));
        }
    }
}

async fn stop_on_signal(shutdown: CancellationToken) {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    crate::info!("stopping");
    shutdown.cancel();
}

/// The TLS that mirroring fetches with uses ring, as the hashing does.
pub fn install_crypto() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Mapped blobs hold their files open, so allow as many as the hard limit.
fn raise_nofile() {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain syscalls on a local struct.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
            lim.rlim_cur = lim.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }
}
