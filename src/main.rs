//! ditto-blossom: a Blossom server on LMDB, built for ext4 and sendfile.

mod access;
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
mod routes;
mod send_file;
mod serve;
mod server;
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
  ditto-blossom --version

CONFIG defaults to ./ditto-blossom.toml.
import takes over a blossom-server's blobs: its SQLite database and its blob
directory. Files are hard-linked into place unless --copy; --verify hashes
every file, not only the small ones.";

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
        Some("serve" | "import") => args.next().expect("peeked"),
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
    while let Some(arg) = args.next() {
        let mut value = || args.next().with_context(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "-c" | "--config" => config_path = value()?.into(),
            "--sqlite" if command == "import" => sqlite = Some(PathBuf::from(value()?)),
            "--blobs" if command == "import" => dir = Some(PathBuf::from(value()?)),
            "--copy" if command == "import" => copy = true,
            "--verify" if command == "import" => verify = true,
            _ => bail!("unexpected argument {arg}\n\n{USAGE}"),
        }
    }
    let config = Config::load(&config_path)?;
    match command.as_str() {
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
        tokio::spawn(flush_access(app, shutdown.clone()));
        tokio::spawn(stop_on_signal(shutdown.clone()));
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
