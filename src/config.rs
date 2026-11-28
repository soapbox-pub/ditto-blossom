//! The config file, TOML. Every setting has a default but `data` and
//! `public_url`.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

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
    #[serde(default)]
    pub scan: Scan,
    #[serde(default)]
    pub admin: Admin,
    #[serde(default)]
    pub moderation: Moderation,
}

/// Bans and unbans shared with other servers (see `peers`): each serves
/// its own, and follows its peers', the latest decision on a blob or a
/// pubkey winning wherever it was made.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Moderation {
    /// A file of tokens, a line each, that peers read this server's
    /// decisions with (`GET /moderation/decisions`). Unset: none may.
    #[serde(default)]
    pub tokens_file: Option<PathBuf>,
    /// Servers whose decisions this one follows.
    #[serde(default)]
    pub peers: Vec<Peer>,
    /// Seconds between reads of each peer's decisions.
    #[serde(default = "default_pull_every")]
    pub pull_every: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    /// Its `public_url`.
    pub url: String,
    /// A file holding the token it gave this server, readable by the
    /// server alone.
    pub token_file: PathBuf,
    /// Its bans whose reasons start with one of these aren't followed,
    /// like `"scan:"` for those its explicit-media scanner made.
    #[serde(default)]
    pub skip: Vec<String>,
}

fn default_pull_every() -> u64 {
    60
}

impl Default for Moderation {
    fn default() -> Moderation {
        Moderation {
            tokens_file: None,
            peers: Vec::new(),
            pull_every: default_pull_every(),
        }
    }
}

/// The admin dashboard, on a listener of its own (see `admin`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admin {
    /// Where the dashboard listens. Unset: there's none.
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    /// The dashboard's address as admins' browsers reach it, like
    /// `https://admin.blossom.example.com`: a sign-in is taken only if it
    /// was signed for this address. Unset: `http://` and `listen`, which
    /// must then be an address of its own, not 0.0.0.0 or [::].
    #[serde(default)]
    pub url: Option<String>,
    /// Pubkeys, hex, that may sign in.
    #[serde(default, deserialize_with = "pubkeys")]
    pub pubkeys: HashSet<[u8; 32]>,
    /// Where banning as CSAM keeps its evidence: `evidence` in `data`
    /// unless set. Owner-only, and never served.
    #[serde(default)]
    pub preserve: Option<PathBuf>,
    /// The labels `ditto-blossom train --labels` reads, which the dashboard
    /// adds to. Unset, with `embeddings`: it can't label.
    #[serde(default)]
    pub labels: Option<PathBuf>,
    /// The embeddings `train --cache` reads: a blob labelled here is
    /// embedded into it at once, so it can still be trained on once it's
    /// banned or removed. Banning as CSAM takes a blob out of both.
    #[serde(default)]
    pub embeddings: Option<PathBuf>,
    /// Relays the dashboard asks, from the admin's browser, for the
    /// profiles (kind 0) of the pubkeys it shows. Unset: `RELAYS`; empty:
    /// it asks none.
    #[serde(default)]
    pub relays: Option<Vec<String>>,
    /// The cache in front of `public_url`, by name, like `Cloudflare`: the
    /// dashboard lists what each ban and removal deleted, to purge from it.
    /// Unset: there's none, and no list.
    #[serde(default)]
    pub cdn: Option<String>,
}

/// Whether `host[:port]` is this machine.
fn loopback(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub const RELAYS: [&str; 3] = [
    "wss://relay.ditto.pub",
    "wss://relay.primal.net",
    "wss://relay.damus.io",
];

impl Admin {
    /// The dashboard's address, as admins sign in to it (see `url`).
    pub fn url(&self) -> Option<String> {
        match (&self.url, self.listen) {
            (Some(u), _) => Some(u.clone()),
            (None, Some(addr)) => Some(format!("http://{addr}")),
            (None, None) => None,
        }
    }

    pub fn relays(&self) -> Vec<String> {
        match &self.relays {
            Some(r) => r.clone(),
            None => RELAYS.iter().map(|r| r.to_string()).collect(),
        }
    }
}

/// Whether a relay's URL is plain enough to name in the dashboard's
/// Content-Security-Policy: `wss://`, a host, maybe a port and a path.
fn plain_relay(url: &str) -> bool {
    url.strip_prefix("wss://").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-:/_~".contains(c))
    })
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
    /// Bytes a client may upload and mirror an hour. A blob larger than
    /// this needs the hour's whole allowance, and uses up the next ones.
    #[serde(default = "default_bytes_per_hour")]
    pub bytes_per_hour: u64,
    /// Pubkeys, hex, whose uploads and mirrors skip `max_size`,
    /// `per_minute` and `bytes_per_hour`, when their auth token is good.
    #[serde(default, deserialize_with = "pubkeys")]
    pub exempt: HashSet<[u8; 32]>,
}

fn pubkeys<'de, D: Deserializer<'de>>(d: D) -> Result<HashSet<[u8; 32]>, D::Error> {
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|s| {
            hex::decode(s)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| D::Error::custom(format!("{s:?} isn't a hex pubkey")))
        })
        .collect()
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

/// Scanning new uploads and mirrors (see `scan`), on with `enabled` by
/// whichever part is set up: matching known CSAM with Arachnid Shield, with
/// `credentials_file` (see `scan::known`), and refusing explicit media,
/// with `model`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scan {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_shield_url")]
    pub shield_url: String,
    /// A file holding `username:password` for Shield, readable by the
    /// server and no one else.
    #[serde(default)]
    pub credentials_file: Option<PathBuf>,
    /// Where a match's blobs and its record are kept, a directory each:
    /// what US law has a provider preserve for its NCMEC report.
    #[serde(default)]
    pub evidence: Option<PathBuf>,
    /// Run on each match, with its record (JSON) on stdin: to tell someone.
    #[serde(default)]
    pub alert_command: Vec<String>,
    /// Seconds between tries at blobs kept while Shield couldn't be asked.
    #[serde(default = "default_retry_every")]
    pub retry_every: u64,
    /// The image encoder, ONNX (see contrib/clip-model.py).
    #[serde(default)]
    pub model: Option<PathBuf>,
    /// The head over it, as `ditto-blossom train` writes it.
    #[serde(default)]
    pub head: Option<PathBuf>,
    /// Scores at or over this are refused: the chance, 0 to 1, that what
    /// was seen is explicit. Unset: the threshold training chose.
    #[serde(default)]
    pub threshold: Option<f32>,
    /// Threads scanning, each with its own copy of the encoder (~380 MB) and
    /// ~8 images a second on one core. 2 if unset.
    #[serde(default)]
    pub workers: Option<usize>,
    /// The ffmpeg that video, AVIF, HEIC and JPEG XL are decoded with. Empty:
    /// none, and those pass unscanned.
    #[serde(default = "default_ffmpeg")]
    pub ffmpeg: PathBuf,
    /// Refuse media that can't be decoded. A browser shows what it can of a
    /// broken image, so one this can't read isn't safe to let through.
    #[serde(default = "yes")]
    pub refuse_undecodable: bool,
    /// Store uploads at once and scan them after, so scanning never slows
    /// an upload: a refused blob is taken out when its scan is done.
    #[serde(default)]
    pub background: bool,
    /// Don't start, and never run ffmpeg, unless it can run with its files
    /// and network both shut off (see `scan::sandbox`). On unless turned
    /// off; off, it runs as confined as the kernel allows, and the log says
    /// how.
    #[serde(default = "yes")]
    pub require_sandbox: bool,
    /// With `background`, don't serve a blob until it's been scanned (503
    /// and Retry-After until then), rather than serving it meanwhile.
    #[serde(default = "yes")]
    pub hold: bool,
}

impl Scan {
    /// Whether new images are matched against known CSAM with Shield.
    pub fn shield(&self) -> bool {
        self.enabled && self.credentials_file.is_some()
    }

    /// Whether explicit media is refused, by `model` (and `head`).
    pub fn refuses(&self) -> bool {
        self.enabled && self.model.is_some()
    }
}

fn default_shield_url() -> String {
    "https://shield.projectarachnid.com".into()
}
fn default_retry_every() -> u64 {
    300
}
fn default_ffmpeg() -> PathBuf {
    PathBuf::from("ffmpeg")
}

impl Default for Scan {
    fn default() -> Scan {
        Scan {
            enabled: false,
            shield_url: default_shield_url(),
            credentials_file: None,
            evidence: None,
            alert_command: Vec::new(),
            retry_every: default_retry_every(),
            model: None,
            head: None,
            threshold: None,
            workers: None,
            ffmpeg: default_ffmpeg(),
            refuse_undecodable: true,
            background: false,
            require_sandbox: true,
            hold: true,
        }
    }
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
fn default_bytes_per_hour() -> u64 {
    1 << 30
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
            bytes_per_hour: default_bytes_per_hour(),
            exempt: HashSet::new(),
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
        let scan = &config.scan;
        if scan.enabled {
            if !scan.shield() && !scan.refuses() {
                bail!("scan needs credentials_file, for Shield, or model, or both");
            }
            if scan.shield() && scan.evidence.is_none() {
                bail!("scan needs evidence, a directory to keep matches in");
            }
        }
        if config
            .scan
            .threshold
            .is_some_and(|t| !(0.0..=1.0).contains(&t))
        {
            bail!("scan.threshold must be between 0 and 1");
        }
        if config.admin.listen.is_some() && config.admin.pubkeys.is_empty() {
            bail!("admin.listen needs admin.pubkeys, who may sign in");
        }
        if let Some(u) = &mut config.admin.url {
            *u = u.trim_end_matches('/').to_string();
            let host = u.split_once("://").map_or("", |(_, h)| h);
            if !(u.starts_with("https://") || u.starts_with("http://"))
                || host.is_empty()
                || !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c))
            {
                bail!(
                    "admin.url: {u:?} isn't the dashboard's address, like https://admin.blossom.example.com"
                );
            }
        } else if config.admin.listen.is_some_and(|a| a.ip().is_unspecified()) {
            bail!("admin.listen is every address, so set admin.url, the one admins sign in at");
        }
        // Over plain http the session cookie would cross the network.
        if let Some(u) = config.admin.url()
            && let Some(host) = u.strip_prefix("http://")
            && !loopback(host)
        {
            bail!("admin.url: {u:?} is plain http off this machine; use https, or loopback");
        }
        if let Some(bad) = config.admin.relays().iter().find(|r| !plain_relay(r)) {
            bail!("admin.relays: {bad:?} isn't a wss:// URL");
        }
        for peer in &mut config.moderation.peers {
            peer.url = peer.url.trim_end_matches('/').to_string();
            if !(peer.url.starts_with("https://") || peer.url.starts_with("http://")) {
                bail!("moderation.peers: {:?} isn't a server's URL", peer.url);
            }
        }
        Ok(config)
    }

    /// Where banning as CSAM keeps its evidence.
    pub fn evidence(&self) -> PathBuf {
        self.admin
            .preserve
            .clone()
            .unwrap_or_else(|| self.data.join("evidence"))
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
    fn scan_turns_on_whatever_is_set_up() {
        let scan = |rest: &str| {
            Config::parse(&format!(
                "data = \"/x\"\npublic_url = \"https://a\"\n[scan]\nenabled = true\n{rest}"
            ))
        };
        assert!(scan("").is_err());
        assert!(
            scan("credentials_file = \"/c\"\n").is_err(),
            "needs evidence"
        );
        let c = scan("credentials_file = \"/c\"\nevidence = \"/e\"\n").unwrap();
        assert!(c.scan.shield() && !c.scan.refuses());
        let c = scan("model = \"/m\"\nhead = \"/h\"\n").unwrap();
        assert!(!c.scan.shield() && c.scan.refuses());
        let c = scan("credentials_file = \"/c\"\nevidence = \"/e\"\nmodel = \"/m\"\n").unwrap();
        assert!(c.scan.shield() && c.scan.refuses());
        let off = Config::parse(
            "data = \"/x\"\npublic_url = \"https://a\"\n[scan]\ncredentials_file = \"/c\"\nmodel = \"/m\"\n",
        )
        .unwrap();
        assert!(!off.scan.shield() && !off.scan.refuses());
    }

    #[test]
    fn ffmpeg_must_be_confined_unless_turned_off() {
        let base = "data = \"/x\"\npublic_url = \"https://a\"\n";
        assert!(Config::parse(base).unwrap().scan.require_sandbox);
        assert!(Scan::default().require_sandbox);
        let off = Config::parse(&format!("{base}[scan]\nrequire_sandbox = false\n")).unwrap();
        assert!(!off.scan.require_sandbox);
    }

    #[test]
    fn rejects_unknown_settings_and_bad_urls() {
        assert!(
            Config::parse("data = \"/x\"\npublic_url = \"https://a\"\nlisten_on = 3\n").is_err()
        );
        assert!(Config::parse("data = \"/x\"\npublic_url = \"blossom.example.com\"\n").is_err());
    }

    #[test]
    fn exempt_takes_hex_pubkeys_only() {
        let base = "data = \"/x\"\npublic_url = \"https://a\"\n[upload]\n";
        let key = "781a1527055f74c1f70230f10384609b34548f8ab6a0a6caa74025827f9fdae5";
        let c = Config::parse(&format!("{base}exempt = [\"{key}\"]\n")).unwrap();
        let bytes: [u8; 32] = hex::decode(key).unwrap().try_into().unwrap();
        assert!(c.upload.exempt.contains(&bytes));
        assert!(Config::parse(&format!("{base}exempt = [\"{}\"]\n", &key[2..])).is_err());
        assert!(Config::parse(&format!("{base}exempt = [\"npub1xyz\"]\n")).is_err());
    }

    #[test]
    fn admin_needs_someone_to_sign_in() {
        let base =
            "data = \"/x\"\npublic_url = \"https://a\"\n[admin]\nlisten = \"127.0.0.1:3001\"\n";
        let key = "781a1527055f74c1f70230f10384609b34548f8ab6a0a6caa74025827f9fdae5";
        assert!(Config::parse(base).is_err());
        let c = Config::parse(&format!("{base}pubkeys = [\"{key}\"]\n")).unwrap();
        assert_eq!(c.admin.pubkeys.len(), 1);
        assert!(
            Config::parse("data = \"/x\"\npublic_url = \"https://a\"\n")
                .unwrap()
                .admin
                .listen
                .is_none()
        );
        assert_eq!(c.admin.relays().len(), 3);
        let relays =
            |r: &str| Config::parse(&format!("{base}pubkeys = [\"{key}\"]\nrelays = [{r}]\n"));
        assert_eq!(
            relays("\"wss://relay.example.com/x\"")
                .unwrap()
                .admin
                .relays()
                .len(),
            1
        );
        assert!(relays("").unwrap().admin.relays().is_empty());
        assert!(relays("\"https://relay.example.com\"").is_err());
        assert!(relays("\"wss://a; script-src *\"").is_err());
    }

    #[test]
    fn admin_url_is_where_admins_sign_in() {
        let key = "781a1527055f74c1f70230f10384609b34548f8ab6a0a6caa74025827f9fdae5";
        let admin = |rest: &str| {
            Config::parse(&format!(
                "data = \"/x\"\npublic_url = \"https://a\"\n[admin]\npubkeys = [\"{key}\"]\n{rest}"
            ))
        };
        let c = admin("listen = \"127.0.0.1:3001\"\n").unwrap();
        assert_eq!(c.admin.url().unwrap(), "http://127.0.0.1:3001");
        let c = admin("listen = \"0.0.0.0:3001\"\nurl = \"https://admin.example.com/\"\n").unwrap();
        assert_eq!(c.admin.url().unwrap(), "https://admin.example.com");
        assert!(admin("listen = \"0.0.0.0:3001\"\n").is_err());
        assert!(admin("listen = \"[::]:3001\"\n").is_err());
        assert!(admin("url = \"admin.example.com\"\n").is_err());
        // Plain http only on this machine.
        assert!(admin("listen = \"192.168.1.5:3001\"\n").is_err());
        assert!(admin("url = \"http://admin.example.com\"\n").is_err());
        assert!(admin("url = \"http://localhost:3001\"\n").is_ok());
        assert!(admin("listen = \"192.168.1.5:3001\"\nurl = \"https://admin.lan\"\n").is_ok());
        assert!(admin("url = \"https://admin.example.com/x\"\n").is_err());
        assert!(admin("url = \"http://[::1]:3001\"\n").is_ok());
    }
}
