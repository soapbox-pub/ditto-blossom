//! What every request reaches: config, the store, files, the writer and
//! the background workers.

use anyhow::Result;

use crate::access::Access;
use crate::auth::Verifier;
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
    /// Uploads and mirrors receiving at once: each holds a blocking thread.
    pub receiving: tokio::sync::Semaphore,
    pub compressor: Compressor,
    /// What mirrors fetch with.
    pub http: reqwest::Client,
}

impl App {
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
        Ok(Box::leak(Box::new(App {
            auth: Verifier::new(config.domain()?),
            upload_limit: RateLimit::new(config.upload.per_minute),
            receiving: tokio::sync::Semaphore::new(MAX_RECEIVING),
            config,
            store,
            files,
            access: Access::default(),
            writer,
            compressor,
            http,
        })))
    }
}
