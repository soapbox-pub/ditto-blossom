//! What every request reaches: config, the store, files, the writer and
//! the background workers.

use anyhow::Result;

use crate::access::Access;
use crate::auth::{Token, Verifier};
use crate::blobs::Files;
use crate::compress::Compressor;
use crate::config::Config;
use crate::limits::RateLimit;
use crate::store::Store;
use crate::writer::Writer;

/// The most uploads and mirrors received at once; more get 503.
const MAX_RECEIVING: usize = 64;

pub struct App {
    pub config: Config,
    pub store: &'static Store,
    pub files: &'static Files,
    pub access: Access,
    pub writer: Writer,
    pub auth: Verifier,
    pub upload_limit: RateLimit,
    /// Bytes uploaded and mirrored.
    pub upload_bytes: RateLimit,
    /// Uploads and mirrors receiving at once: each holds a blocking thread.
    pub receiving: tokio::sync::Semaphore,
    pub compressor: Compressor,
    /// What mirrors fetch with.
    pub http: reqwest::Client,
    /// Scans uploads for explicit media, if the config says to.
    pub scanner: Option<crate::scan::Scanner>,
    /// Matches new images against known CSAM, if the config says to.
    pub shield: Option<crate::scan::known::Scanner>,
    /// Admins signed in to the dashboard.
    pub admin: crate::admin::Sessions,
}

impl App {
    /// Whether a token's key is exempt from upload limits.
    pub fn exempt(&self, token: Option<&Token>) -> bool {
        token.is_some_and(|t| self.config.upload.exempt.contains(&t.pubkey))
    }

    /// The largest blob a token's key may upload or mirror.
    pub fn max_size(&self, token: Option<&Token>) -> u64 {
        if self.exempt(token) {
            u64::MAX
        } else {
            self.config.upload.max_size
        }
    }

    /// Whether a client may start another upload or mirror, taking a token
    /// from its bucket if so. Exempt keys always may, and take none.
    pub fn allow_upload(&self, token: Option<&Token>, ip: std::net::IpAddr) -> bool {
        self.exempt(token) || self.upload_limit.allow(ip)
    }

    /// Take `bytes` from a client's hourly allowance, or say how long until
    /// it may. Exempt keys always may, and take nothing.
    pub fn allow_bytes(
        &self,
        token: Option<&Token>,
        ip: std::net::IpAddr,
        bytes: u64,
    ) -> Result<(), std::time::Duration> {
        if self.exempt(token) {
            return Ok(());
        }
        self.upload_bytes.take(ip, bytes)
    }

    /// Take `bytes` from a client's allowance whatever's left in it.
    pub fn charge_bytes(&self, token: Option<&Token>, ip: std::net::IpAddr, bytes: u64) {
        if !self.exempt(token) {
            self.upload_bytes.charge(ip, bytes);
        }
    }

    /// Open everything under the config's data directory and start the
    /// writer and compressor threads. Leaked: it lives as long as the
    /// process, and requests borrow it for good.
    pub fn open(config: Config) -> Result<&'static App> {
        crate::install_crypto();
        let store: &'static Store = Box::leak(Box::new(Store::open(&config.data)?));
        let files: &'static Files = Box::leak(Box::new(Files::open(
            &config.data,
            config.open_files,
            true,
        )?));
        let writer = Writer::start(store, files);
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        let workers = config.compress_threads.unwrap_or((cpus / 2).max(1));
        let compressor = Compressor::start(store, files, writer.clone(), workers);
        let http = crate::mirror::client(config.mirror.allow_private);
        let shield = crate::scan::known::Scanner::open(&config)?;
        let scanner = if config.scan.refuses() {
            Some(crate::scan::Scanner::start(&config.scan)?)
        } else {
            None
        };
        let app: &'static App = Box::leak(Box::new(App {
            auth: Verifier::new(config.domain()?),
            upload_limit: RateLimit::per_minute(config.upload.per_minute),
            upload_bytes: RateLimit::new(
                config.upload.bytes_per_hour,
                std::time::Duration::from_secs(3600),
            ),
            receiving: tokio::sync::Semaphore::new(MAX_RECEIVING),
            config,
            store,
            files,
            access: Access::default(),
            writer,
            compressor,
            http,
            scanner,
            shield,
            admin: Default::default(),
        }));
        crate::scan::Scanner::start_background(app);
        Ok(app)
    }
}
