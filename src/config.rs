//! The config file, TOML. Every setting has a default but `data` and
//! `public_url`.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where to listen, plain HTTP: TLS belongs to whatever is in front.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Where blobs and the database live. Meant to be on ext4 (or xfs).
    pub data: PathBuf,
    /// The address clients reach the server at, which blob URLs begin with,
    /// and whose hostname `server` tags in auth tokens must name.
    pub public_url: String,
    /// Peers whose `X-Forwarded-For` is believed: whatever proxy or tunnel
    /// is in front. Everyone else is taken at their socket address.
    #[serde(default = "default_trusted")]
    pub trusted_proxies: Vec<IpAddr>,
    /// Mapped blob files kept open, so serving a warm one costs no system
    /// call before the send.
    #[serde(default = "default_open_files")]
    pub open_files: usize,
    /// Threads making brotli copies in the background, at low priority.
    /// Half the CPUs if unset; 0 makes none.
    #[serde(default)]
    pub compress_threads: Option<usize>,
    #[serde(default)]
    pub upload: Upload,
    #[serde(default)]
    pub list: List,
    #[serde(default)]
    pub mirror: Mirror,
    #[serde(default)]
    pub report: Report,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upload {
    #[serde(default = "yes")]
    pub require_auth: bool,
    /// Bytes.
    #[serde(default = "default_max_size")]
    pub max_size: u64,
    /// Uploads (and mirrors) a client may start a minute.
    #[serde(default = "default_per_minute")]
    pub per_minute: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct List {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub require_auth: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mirror {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Let mirrors fetch from private and local addresses too. Only for a
    /// server whose clients may reach everything it can, like one mirroring
    /// within a private network.
    #[serde(default)]
    pub allow_private: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:3000".parse().expect("an address")
}
fn default_trusted() -> Vec<IpAddr> {
    vec![
        "127.0.0.1".parse().expect("an address"),
        "::1".parse().expect("an address"),
    ]
}
fn default_open_files() -> usize {
    4096
}
fn default_max_size() -> u64 {
    2 << 30
}
fn default_per_minute() -> u32 {
    60
}
fn yes() -> bool {
    true
}

impl Default for Upload {
    fn default() -> Upload {
        Upload {
            require_auth: true,
            max_size: default_max_size(),
            per_minute: default_per_minute(),
        }
    }
}
impl Default for Mirror {
    fn default() -> Mirror {
        Mirror {
            enabled: true,
            allow_private: false,
        }
    }
}
impl Default for Report {
    fn default() -> Report {
        Report { enabled: true }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Could not read {}", path.display()))?;
        Config::parse(&text).with_context(|| format!("{} isn't a valid config", path.display()))
    }

    pub fn parse(text: &str) -> Result<Config> {
        let mut config: Config = toml::from_str(text)?;
        config.public_url = config.public_url.trim_end_matches('/').to_string();
        config.domain()?;
        Ok(config)
    }

    /// The hostname of `public_url`, lowercase, as BUD-11 `server` tags give it.
    pub fn domain(&self) -> Result<String> {
        let rest = self
            .public_url
            .strip_prefix("https://")
            .or_else(|| self.public_url.strip_prefix("http://"))
            .context("public_url must begin with https:// or http://")?;
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = match host.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or_default(),
            None => host.rsplit_once(':').map_or(host, |(h, _)| h),
        };
        if host.is_empty() {
            bail!("public_url has no hostname");
        }
        Ok(host.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_fill_in() {
        let c = Config::parse(
            "data = \"/srv/blossom\"\npublic_url = \"https://Blossom.Example.com:8443/\"\n",
        )
        .unwrap();
        assert_eq!(c.listen, default_listen());
        assert_eq!(c.public_url, "https://Blossom.Example.com:8443");
        assert_eq!(c.domain().unwrap(), "blossom.example.com");
        assert!(c.upload.require_auth);
        assert!(!c.list.enabled);
    }

    #[test]
    fn rejects_unknown_settings_and_bad_urls() {
        assert!(
            Config::parse("data = \"/x\"\npublic_url = \"https://a\"\nlisten_on = 3\n").is_err()
        );
        assert!(Config::parse("data = \"/x\"\npublic_url = \"blossom.example.com\"\n").is_err());
    }
}
