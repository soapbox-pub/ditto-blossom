//! Arachnid Shield (<https://shield.projectarachnid.com/docs/>), the
//! Canadian Centre for Child Protection's free API for matching media
//! against known CSAM. Only PDQ hashes are sent to it, never media.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::pdq::Pdq;

/// Hashes asked about in one request.
pub const BATCH: usize = 100;
const TIMEOUT: Duration = Duration::from_secs(15);

pub struct Shield {
    url: String,
    user: String,
    password: String,
    http: reqwest::Client,
}

/// What Shield says of a hash.
#[derive(Debug, Clone, Deserialize)]
pub struct Verdict {
    /// `csam`, `harmful-abusive-material`, `test` or `no-known-match`.
    pub classification: String,
    /// `exact` or `near`, when it matched.
    #[serde(default)]
    pub match_type: Option<String>,
    #[serde(default)]
    pub near_match_details: Vec<serde_json::Value>,
}

impl Verdict {
    /// Whether it's known material, to keep out. Shield's own test images
    /// count, so the whole path can be tried on a live server.
    pub fn matched(&self) -> bool {
        self.classification != "no-known-match"
    }
}

#[derive(Deserialize)]
struct PdqResponse {
    scanned_hashes: HashMap<String, Verdict>,
}

impl Shield {
    /// `credentials` is `username:password`, as the Shield account page
    /// gives them.
    pub fn new(url: &str, credentials: &str) -> Result<Shield> {
        let (user, password) = credentials
            .trim()
            .split_once(':')
            .context("Shield credentials should be username:password")?;
        crate::install_crypto();
        Ok(Shield {
            url: url.trim_end_matches('/').to_string(),
            user: user.to_string(),
            password: password.to_string(),
            http: reqwest::Client::builder()
                .user_agent(concat!("ditto-blossom/", env!("CARGO_PKG_VERSION")))
                .timeout(TIMEOUT)
                .no_proxy()
                .build()
                .context("The Shield client won't build")?,
        })
    }

    /// Shield's verdict on each hash, in order. At most [`BATCH`].
    pub async fn check(&self, hashes: &[Pdq]) -> Result<Vec<Verdict>> {
        let encoded: Vec<String> = hashes.iter().map(Pdq::base64).collect();
        let resp = self
            .http
            .post(format!("{}/v1/pdq", self.url))
            .basic_auth(&self.user, Some(&self.password))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(
                &serde_json::json!({ "hashes": encoded }),
            )?)
            .send()
            .await
            .context("Shield couldn't be reached")?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .context("Shield's answer didn't arrive")?;
        if !status.is_success() {
            bail!(
                "Shield answered {status}: {}",
                String::from_utf8_lossy(&body[..body.len().min(200)])
            );
        }
        let answer: PdqResponse =
            serde_json::from_slice(&body).context("Shield's answer isn't what was expected")?;
        encoded
            .iter()
            .map(|h| {
                answer
                    .scanned_hashes
                    .get(h)
                    .cloned()
                    .with_context(|| format!("Shield didn't answer for {h}"))
            })
            .collect()
    }
}
