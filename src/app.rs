//! What every request reaches: config, the store, files, and the writer.

use anyhow::Result;

use crate::access::Access;
use crate::blobs::Files;
use crate::config::Config;
use crate::store::Store;

pub struct App {
    pub config: Config,
    /// `public_url`'s hostname, which `server` tags must name.
    pub domain: String,
    pub store: &'static Store,
    pub files: Files,
    pub access: Access,
}

impl App {
    /// Open everything under the config's data directory. Leaked: it lives
    /// as long as the process, and requests borrow it for good.
    pub fn open(config: Config) -> Result<&'static App> {
        let store = Box::leak(Box::new(Store::open(&config.data)?));
        let files = Files::open(&config.data, config.open_files)?;
        let domain = config.domain()?;
        Ok(Box::leak(Box::new(App { config, domain, store, files, access: Access::default() })))
    }
}
