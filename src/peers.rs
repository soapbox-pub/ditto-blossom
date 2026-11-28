//! Moderation shared with other servers. Each server serves its decisions,
//! every ban and unban as `decisions` in the store keeps them, at
//! `GET /moderation/decisions` to peers holding a token it gave them, and
//! reads its own peers' every `moderation.pull_every` seconds. A target's
//! latest decision wins wherever it was made, by when it was made, so a
//! decision a peer took from here and serves back is no news, and a ban
//! lifted on either side is lifted on both.
//!
//! A peer's ban is carried out as a ban here would be (see
//! `moderate::follow`): what's stored of it is removed, a CSAM ban's
//! preserved first, and banned pubkeys taken off blobs others own too.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::app::App;
use crate::config::{Config, Peer};
use crate::hash::Hash;
use crate::http::error;
use crate::server::Body;
use crate::store::{Ban, Banned, Decision};

/// Decisions a page, by default and at most.
const PAGE: usize = 1000;
const MAX_PAGE: usize = 5000;

pub struct Peers {
    /// Tokens peers may read this server's decisions with.
    tokens: Vec<String>,
    /// Peers followed, each with the token it gave this server.
    follow: Vec<(Peer, String)>,
    http: reqwest::Client,
}

impl Peers {
    pub fn open(config: &Config) -> Result<Peers> {
        let m = &config.moderation;
        let tokens = match &m.tokens_file {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("Could not read {}", path.display()))?;
                let tokens: Vec<String> = text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from)
                    .collect();
                if let Some(short) = tokens.iter().find(|t| t.len() < 32) {
                    bail!(
                        "{}: a token of {} characters is too easily guessed; use 32 or more",
                        path.display(),
                        short.len()
                    );
                }
                tokens
            }
            None => Vec::new(),
        };
        let mut follow = Vec::new();
        for peer in &m.peers {
            let token = std::fs::read_to_string(&peer.token_file)
                .with_context(|| format!("Could not read {}", peer.token_file.display()))?
                .trim()
                .to_string();
            if token.is_empty() {
                bail!("{} holds no token", peer.token_file.display());
            }
            follow.push((peer.clone(), token));
        }
        Ok(Peers {
            tokens,
            follow,
            // Peers are the operator's to name, private addresses or not.
            http: crate::mirror::client(true),
        })
    }

    fn allows(&self, given: &str) -> bool {
        // Every token compared in full, so the time taken says nothing.
        self.tokens
            .iter()
            .fold(false, |ok, t| ok | same(t.as_bytes(), given.as_bytes()))
    }
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// `GET /moderation/decisions?after=CURSOR&limit=N`: this server's bans and
/// unbans, oldest first, for a peer holding one of `moderation.tokens_file`.
pub fn decisions(app: &'static App, req: &Request<Incoming>) -> Response<Body> {
    if app.peers.tokens.is_empty() {
        return error(StatusCode::NOT_FOUND, "Not found");
    }
    let given = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !app.peers.allows(given.trim()) {
        return error(StatusCode::UNAUTHORIZED, "A peer's token is needed");
    }
    let (mut after, mut limit) = (None, PAGE);
    for (k, v) in url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes()) {
        match &*k {
            "after" => match hex::decode(&*v) {
                Ok(c) => after = Some(c),
                Err(_) => return error(StatusCode::BAD_REQUEST, "after is a cursor, in hex"),
            },
            "limit" => match v.parse::<usize>() {
                Ok(n) => limit = n.clamp(1, MAX_PAGE),
                Err(_) => return error(StatusCode::BAD_REQUEST, "limit is a number"),
            },
            _ => {}
        }
    }
    let (page, more) = match app.store.decisions(after.as_deref(), limit) {
        Ok(p) => p,
        Err(e) => {
            crate::error!("decisions_failed", "error": format!("{e:#}"));
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The decisions couldn't be read",
            );
        }
    };
    let decisions: Vec<Value> = page.iter().map(to_json).collect();
    let mut r = crate::http::json(
        StatusCode::OK,
        &json!({ "decisions": decisions, "more": more }),
    );
    // Not for any cache in front: what's banned, and by whom, is the peers'.
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    r
}

fn to_json(d: &Decision) -> Value {
    let (kind, hex) = match d.target {
        Banned::Blob(h) => ("blob", h.hex()),
        Banned::Pubkey(pk) => ("pubkey", hex::encode(pk)),
    };
    let mut v = json!({
        "cursor": hex::encode(&d.cursor),
        "kind": kind,
        "target": hex,
        "at": d.at,
        "banned": d.ban.is_some(),
    });
    if let Some(b) = &d.ban {
        v["reason"] = b.reason.clone().into();
    }
    v
}

fn from_json(v: &Value) -> Option<Decision> {
    let key: [u8; 32] = hex::decode(v["target"].as_str()?).ok()?.try_into().ok()?;
    let target = match v["kind"].as_str()? {
        "blob" => Banned::Blob(Hash(key)),
        "pubkey" => Banned::Pubkey(key),
        _ => return None,
    };
    let at = v["at"].as_u64()?;
    let ban = match v["banned"].as_bool()? {
        true => Some(Ban {
            target,
            at,
            reason: v["reason"].as_str().unwrap_or("").to_string(),
        }),
        false => None,
    };
    Some(Decision {
        cursor: hex::decode(v["cursor"].as_str()?).ok()?,
        target,
        at,
        ban,
    })
}

/// Read each peer's new decisions, every `moderation.pull_every` seconds.
pub async fn follow(app: &'static App, shutdown: CancellationToken) {
    if app.peers.follow.is_empty() {
        return;
    }
    let every = Duration::from_secs(app.config.moderation.pull_every.max(10));
    let mut tick = tokio::time::interval(every);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.cancelled() => return,
        }
        for (peer, token) in &app.peers.follow {
            if let Err(e) = pull(app, peer, token, &shutdown).await {
                crate::warn!("peer_pull_failed", "peer": peer.url, "error": format!("{e:#}"));
            }
        }
    }
}

/// Follow one peer's decisions from where this server left off, a page at
/// a time, each page carried out in one commit with how far it got.
pub(crate) async fn pull(
    app: &'static App,
    peer: &Peer,
    token: &str,
    shutdown: &CancellationToken,
) -> Result<()> {
    let (mut banned, mut unbanned, mut removed) = (0, 0, 0);
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        let mut url = format!("{}/moderation/decisions?limit={PAGE}", peer.url);
        if let Some(c) = app.store.peer_cursor(&peer.url)? {
            url.push_str(&format!("&after={}", hex::encode(c)));
        }
        let r = app.peers.http.get(&url).bearer_auth(token).send().await?;
        if !r.status().is_success() {
            bail!("{} answered {}", peer.url, r.status().as_u16());
        }
        let v: Value = serde_json::from_slice(&r.bytes().await?)
            .with_context(|| format!("{} didn't answer with decisions", peer.url))?;
        let page: Vec<Decision> = v["decisions"]
            .as_array()
            .context("No decisions in the answer")?
            .iter()
            .map(|d| from_json(d).with_context(|| format!("A decision that won't read: {d}")))
            .collect::<Result<_>>()?;
        if page.is_empty() {
            break;
        }
        let peer = peer.clone();
        let protected = app.config.protected();
        let evidence = app.config.evidence();
        let followed = tokio::task::spawn_blocking(move || {
            crate::moderate::follow(
                app.store, app.files, &page, &peer.url, &peer.skip, &protected, &evidence,
            )
        })
        .await??;
        banned += followed.banned;
        unbanned += followed.unbanned;
        removed += followed.removed.len();
        if !v["more"].as_bool().unwrap_or(false) {
            break;
        }
    }
    if banned + unbanned > 0 {
        crate::info!("peer_followed", "peer": peer.url, "banned": banned, "unbanned": unbanned, "removed": removed);
    }
    Ok(())
}
