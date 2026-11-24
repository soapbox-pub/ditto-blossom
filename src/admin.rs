//! The admin dashboard: a page, and the JSON API it calls, on a listener of
//! its own (`admin.listen`). An admin signs in once with NIP-98, a kind
//! 27235 event their NIP-07 extension signs, and gets a session cookie.
//!
//! Nothing here shows media unblurred unasked, logs users' addresses or
//! pubkeys, or keeps a copy of what a ban removes unless the ban says to,
//! for evidence. What admins do is logged, with the admin's own pubkey.
//!
//! It may be reached from the internet, on a host name of its own
//! (`admin.url`): the page is static, a sign-in is taken only if it was
//! signed for that address, everything else needs a session, a change needs
//! a JSON body (so no form or plain cross-origin request makes one), and
//! the cookie is `Secure` whenever the address is https.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::App;
use crate::hash::Hash;
use crate::http::{self, error};
use crate::routes::blob_url;
use crate::server::Body;
use crate::store::{Ban, Banned, Record, flag};
use crate::upload::now;

const PAGE: &str = include_str!("../assets/admin.html");
const SCRIPT: &str = include_str!("../assets/admin.js");
const STYLE: &str = include_str!("../assets/admin.css");
const ICON: &[u8] = include_bytes!("../assets/icon.png");
const BANNER: &[u8] = include_bytes!("../assets/banner.jpg");
const FAVICON: &[u8] = include_bytes!("../assets/favicon.ico");
const COOKIE: &str = "ditto_blossom_admin";
/// How long a session lasts, in seconds.
const SESSION: u64 = 12 * 3600;
/// How long a sign-in event is remembered, to refuse it again: longer than
/// the minute either side of now it's good for.
const USED_FOR: u64 = 180;
/// The largest request body the API reads.
const MAX_BODY: usize = 1 << 20;
/// Blobs a pubkey lookup returns at once.
const PAGE_SIZE: usize = 100;
/// Sign-ins tried a minute, at most, from one address.
const LOGINS_PER_MINUTE: u32 = 10;

/// An admin's pubkey, and when their session ends.
type Session = ([u8; 32], u64);

/// Who's signed in, and the sign-in events already used.
#[derive(Default)]
pub struct Sessions {
    /// By session token.
    live: Mutex<HashMap<[u8; 32], Session>>,
    used: Mutex<HashMap<[u8; 32], u64>>,
    /// Held while the training labels and embeddings are written.
    labelling: Mutex<()>,
    /// Held while evidence records are rewritten.
    noting: Mutex<()>,
    /// Blobs an admin has looked at in Review and found fine, so it doesn't
    /// show them again: read from `admin-reviewed` in `data` when first
    /// needed, a hash a line, and added to.
    reviewed: Mutex<Option<std::collections::HashSet<[u8; 32]>>>,
    /// The home page's overview, and when it was worked out.
    overview: Mutex<Option<(u64, Value)>>,
    /// Sign-ins tried, by address: each costs a signature check.
    logins: std::sync::OnceLock<crate::limits::RateLimit>,
    thumbs: Thumbs,
}

/// Thumbnails made lately, kept here and not in the browser (every answer
/// is `no-store`), and the turns to make more.
struct Thumbs {
    made: Mutex<lru::LruCache<(Hash, u32), Bytes>>,
    making: tokio::sync::Semaphore,
}

/// Thumbnails kept: a few pages of the grid's and Review's.
const THUMBS_KEPT: usize = 1000;
/// Thumbnails made at once, each on a core.
const THUMBS_AT_ONCE: usize = 4;

impl Default for Thumbs {
    fn default() -> Thumbs {
        Thumbs {
            made: Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(THUMBS_KEPT).expect("non-zero"),
            )),
            making: tokio::sync::Semaphore::new(THUMBS_AT_ONCE),
        }
    }
}

impl Sessions {
    fn start(&self, pubkey: [u8; 32], now: u64) -> [u8; 32] {
        let mut token = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut token)
            .expect("the system's randomness");
        let mut live = self.live.lock();
        live.retain(|_, (_, ends)| *ends > now);
        live.insert(token, (pubkey, now + SESSION));
        token
    }

    fn who(&self, token: &[u8; 32], now: u64) -> Option<[u8; 32]> {
        self.live
            .lock()
            .get(token)
            .filter(|(_, ends)| *ends > now)
            .map(|(pk, _)| *pk)
    }

    fn end(&self, token: &[u8; 32]) {
        self.live.lock().remove(token);
    }

    /// Whether a sign-in event is new, remembering it if so.
    fn fresh(&self, id: [u8; 32], now: u64) -> bool {
        let mut used = self.used.lock();
        used.retain(|_, at| *at + USED_FOR > now);
        used.insert(id, now).is_none()
    }
}

pub async fn handle(app: &'static App, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
    let mut r = route(app, req, peer).await;
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    r
}

async fn route(app: &'static App, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    match (&method, path.as_str()) {
        (&Method::GET, "/") => page(app),
        (&Method::GET, "/admin.js") => asset(SCRIPT, "text/javascript; charset=utf-8"),
        (&Method::GET, "/admin.css") => asset(STYLE, "text/css; charset=utf-8"),
        (&Method::GET, "/icon.png") => image(ICON, "image/png"),
        (&Method::GET, "/banner.jpg") => image(BANNER, "image/jpeg"),
        (&Method::GET, "/favicon.ico") => image(FAVICON, "image/x-icon"),
        (&Method::POST, "/api/login") => login(app, &req, peer),
        (_, p) if p.starts_with("/api/") => {
            let token = session_token(&req);
            let Some(admin) = token.and_then(|t| app.admin.who(&t, now())) else {
                return error(StatusCode::UNAUTHORIZED, "Sign in first");
            };
            if method == Method::POST && !is_json(&req) {
                return error(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Send JSON, as application/json",
                );
            }
            api(app, req, admin, token.expect("signed in"), &method, &path).await
        }
        _ => error(StatusCode::NOT_FOUND, "Not found"),
    }
}

async fn api(
    app: &'static App,
    req: Request<Incoming>,
    admin: [u8; 32],
    token: [u8; 32],
    method: &Method,
    path: &str,
) -> Response<Body> {
    let result = match (method, path) {
        (&Method::GET, "/api/session") => Ok(json!({ "pubkey": hex::encode(admin) })),
        (&Method::POST, "/api/logout") => {
            app.admin.end(&token);
            Ok(json!({}))
        }
        (&Method::GET, "/api/stats") => stats(app),
        (&Method::GET, "/api/overview" | "/api/usage") => overview(app).await,
        (&Method::GET, "/api/bans") => bans(app),
        (&Method::GET, "/api/reports") => reports(app),
        (&Method::GET, p) if p.starts_with("/api/blob/") => blob(app, &p["/api/blob/".len()..]),
        (&Method::GET, p) if p.starts_with("/api/pubkey/") => {
            pubkey(app, &p["/api/pubkey/".len()..], req.uri().query())
        }
        (&Method::POST, "/api/ban") => match body(req).await {
            Ok(b) => ban(app, admin, &b).await,
            Err(r) => return r,
        },
        (&Method::POST, "/api/csam") => match body(req).await {
            Ok(b) => csam(app, admin, &b).await,
            Err(r) => return r,
        },
        (&Method::GET, "/api/evidence") => evidence(app),
        (&Method::POST, "/api/evidence/reported") => match body(req).await {
            Ok(b) => reported(app, admin, &b).await,
            Err(r) => return r,
        },
        (&Method::POST, "/api/unban") => match body(req).await {
            Ok(b) => unban(app, admin, &b).await,
            Err(r) => return r,
        },
        (&Method::GET, "/api/media") => {
            let query = req.uri().query().map(String::from);
            tokio::task::spawn_blocking(move || media(app, query.as_deref()))
                .await
                .unwrap_or_else(|e| Err(Failure::Internal(e.into())))
        }
        (&Method::POST, "/api/reviewed") => match body(req).await {
            Ok(b) => reviewed(app, &b),
            Err(r) => return r,
        },
        (&Method::GET, p) if p.starts_with("/api/thumb/") => {
            return thumb(app, &p["/api/thumb/".len()..], req.uri().query()).await;
        }
        (&Method::GET, p) if p.starts_with("/api/score/") => {
            score(app, &p["/api/score/".len()..]).await
        }
        (&Method::POST, "/api/remove") => match body(req).await {
            Ok(b) => remove(app, admin, &b).await,
            Err(r) => return r,
        },
        (&Method::POST, "/api/label") => match body(req).await {
            Ok(b) => label(app, admin, &b).await,
            Err(r) => return r,
        },
        _ => return error(StatusCode::NOT_FOUND, "Not found"),
    };
    match result {
        Ok(v) => http::json(StatusCode::OK, &v),
        Err(Failure::Bad(why)) => error(StatusCode::BAD_REQUEST, &why),
        Err(Failure::Internal(e)) => {
            crate::error!("admin_failed", "path": path, "error": format!("{e:#}"));
            error(StatusCode::INTERNAL_SERVER_ERROR, "That couldn't be done")
        }
    }
}

enum Failure {
    Bad(String),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Self {
        Failure::Internal(e)
    }
}

type Answer = Result<Value, Failure>;

fn page(app: &App) -> Response<Body> {
    // The sign-in card names the server, as its public page does.
    let host = app
        .config
        .public_url
        .split_once("://")
        .map_or(app.config.public_url.as_str(), |(_, h)| h)
        .trim_end_matches('/');
    let page = PAGE
        .replace("{{host}}", &escape(host))
        .replace("{{version}}", env!("CARGO_PKG_VERSION"));
    let mut r = Response::new(Full::new(Bytes::from(page)));
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    // Blobs are shown as thumbnails made here, never kept by the browser,
    // and opened from the public server, fetched afresh from it once
    // deleted, so this browser forgets them. Profiles come from
    // the relays named, and their pictures from wherever they say, over https.
    let csp = format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' {0} {1}; \
         img-src 'self' {0} https:; media-src {0}; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'",
        app.config.public_url,
        app.config.admin.relays().join(" "),
    );
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    r
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn image(body: &'static [u8], ty: &'static str) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from_static(body)));
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(ty));
    r
}

fn asset(body: &'static str, ty: &'static str) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(ty));
    r
}

/// `POST /api/login`, with a NIP-98 event for this URL: a session cookie.
fn login(app: &'static App, req: &Request<Incoming>, peer: SocketAddr) -> Response<Body> {
    let ip = crate::routes::client_ip(app, req, peer);
    let logins = app
        .admin
        .logins
        .get_or_init(|| crate::limits::RateLimit::per_minute(LOGINS_PER_MINUTE));
    if !logins.allow(ip) {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-ins; try again in a minute",
        );
    }
    // Signed for this dashboard's own address, whatever Host was sent: an
    // event signed for another site's /api/login is no sign-in here.
    let Some(base) = app.config.admin.url() else {
        return error(StatusCode::NOT_FOUND, "There's no dashboard here");
    };
    let now = now();
    let (pubkey, id) =
        match crate::auth::verify_http(req.headers(), "POST", &format!("{base}/api/login"), now) {
            Ok(v) => v,
            Err("The event is for another URL") => {
                return error(
                    StatusCode::UNAUTHORIZED,
                    &format!("Sign in at {base}, the dashboard's address"),
                );
            }
            Err(why) => return error(StatusCode::UNAUTHORIZED, why),
        };
    let https = base.starts_with("https://");
    if !app.config.admin.pubkeys.contains(&pubkey) {
        return error(StatusCode::FORBIDDEN, "That key isn't an admin here");
    }
    if !app.admin.fresh(id, now) {
        return error(StatusCode::UNAUTHORIZED, "That sign-in was used already");
    }
    let token = app.admin.start(pubkey, now);
    crate::info!("admin_signed_in", "admin": hex::encode(pubkey));
    let mut r = http::json(StatusCode::OK, &json!({ "pubkey": hex::encode(pubkey) }));
    // The dashboard is https, whatever ended TLS before here, so the cookie
    // is never sent over plain http.
    let cookie = format!(
        "{COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION}{}",
        hex::encode(token),
        if https { "; Secure" } else { "" }
    );
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        r.headers_mut().insert(header::SET_COOKIE, v);
    }
    r
}

fn session_token(req: &Request<Incoming>) -> Option<[u8; 32]> {
    req.headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .and_then(|(_, value)| hex::decode(value).ok())
        .and_then(|v| v.try_into().ok())
}

fn is_json(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim_start().starts_with("application/json"))
}

async fn body(req: Request<Incoming>) -> Result<Bytes, Response<Body>> {
    match Limited::new(req.into_body(), MAX_BODY).collect().await {
        Ok(b) => Ok(b.to_bytes()),
        Err(_) => Err(error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "The body is too large",
        )),
    }
}

/// The addresses a cache in front of this server may hold removed blobs
/// at, for the admin to purge there: each by its hash alone, and with the
/// extension its URL has, as a cache keeps each address it was asked for
/// apart.
fn cached_urls(app: &App, removed: &[Record]) -> Vec<String> {
    let mut urls = Vec::with_capacity(removed.len() * 2);
    for rec in removed {
        let bare = format!("{}/{}", app.config.public_url, rec.hash.hex());
        let full = crate::routes::blob_url(app, &rec.hash, rec.mime.as_deref());
        if full != bare {
            urls.push(full);
        }
        urls.push(bare);
    }
    urls
}

fn stats(app: &'static App) -> Answer {
    let evidence: Vec<Value> = crate::moderate::evidence(&app.config.evidence())?
        .into_iter()
        .filter(flagged)
        .collect();
    let blobs = app.store.count()?;
    let ((banned_blobs, banned_pubkeys), reports) = app
        .store
        .read(|txn| anyhow::Ok((app.store.ban_counts(txn)?, app.store.report_count(txn)?)))??;
    Ok(json!({
        "blobs": blobs,
        "banned_blobs": banned_blobs,
        "banned_pubkeys": banned_pubkeys,
        "reports": reports,
        "scan": app.scanner.as_ref().map(|s| json!({
            "threshold": s.rule.threshold,
            "refuse_undecodable": s.rule.refuse_undecodable,
            "background": app.config.scan.background,
            "waiting": s.pending(),
        })),
        "unreported": evidence.iter().filter(|r| r["reported"].is_null()).count(),
        "oldest_unreported": evidence
            .iter()
            .filter(|r| r["reported"].is_null())
            .filter_map(|r| r["banned"].as_u64())
            .min(),
        "evidence": evidence.len(),
        "relays": app.config.admin.relays(),
        "cdn": app.config.admin.cdn,
        "labelling": labelling(app).is_some(),
        "public_url": app.config.public_url,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// How long the usage is kept before it's worked out again, in seconds.
const OVERVIEW_FOR: u64 = 300;
/// How many accounts the usage names as using the most space.
const TOP: usize = 20;
/// Days of uploads it shows one by one.
const DAYS: u64 = 90;

/// `GET /api/overview` and `GET /api/usage`: what's stored and how it's
/// used, as the home page shows it in brief and Usage in full. One read
/// through every record, its owners and when it was last read, kept for a
/// while.
async fn overview(app: &'static App) -> Answer {
    let now = now();
    if let Some((at, v)) = app.admin.overview.lock().as_ref()
        && at + OVERVIEW_FOR > now
    {
        return Ok(v.clone());
    }
    let v = tokio::task::spawn_blocking(move || work_out_usage(app, now))
        .await
        .map_err(|e| Failure::Internal(e.into()))??;
    *app.admin.overview.lock() = Some((now, v.clone()));
    Ok(v)
}

/// Files and bytes.
#[derive(Default, Clone, Copy)]
struct Tally {
    files: u64,
    bytes: u64,
}

impl Tally {
    fn add(&mut self, bytes: u64) {
        self.files += 1;
        self.bytes += bytes;
    }

    fn json(self) -> Value {
        json!({ "files": self.files, "bytes": self.bytes })
    }
}

/// `YYYY-MM` for a time, in UTC.
fn month_of(secs: u64) -> String {
    // Howard Hinnant's days-to-civil.
    let z = (secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}")
}

fn work_out_usage(app: &'static App, now: u64) -> anyhow::Result<Value> {
    use crate::scan::Kind;
    use std::collections::BTreeMap;
    let today = now / 86400;
    let first_day = today + 1 - DAYS;
    let last_reads = app.store.last_reads()?;
    let (mut all, mut kinds, mut shared, mut saved) =
        (Tally::default(), [Tally::default(); 3], 0u64, 0u64);
    let mut days = vec![Tally::default(); DAYS as usize];
    let mut months: BTreeMap<String, Tally> = BTreeMap::new();
    let mut types: HashMap<String, Tally> = HashMap::new();
    // Under 10 KB, 100 KB, 1 MB, 10 MB, 100 MB, and over.
    const SIZES: [u64; 5] = [10_000, 100_000, 1_000_000, 10_000_000, 100_000_000];
    let mut sizes = [Tally::default(); 6];
    // Last read within a day, a week, 30 days, 90 days; before; never.
    let mut reads = [Tally::default(); 6];
    // An uploader's files, bytes, and first upload.
    let mut per: HashMap<[u8; 32], (u64, u64, u64)> = HashMap::new();
    app.store.each_record_owned(5000, |seq, rec, owners| {
        all.add(rec.size);
        let k = match crate::scan::kind(rec.mime.as_deref()) {
            Kind::Image => 0,
            Kind::Video => 1,
            Kind::Other => 2,
        };
        kinds[k].add(rec.size);
        if let Some(d) = (rec.uploaded / 86400).checked_sub(first_day)
            && let Some(day) = days.get_mut(d as usize)
        {
            day.add(rec.size);
        }
        months
            .entry(month_of(rec.uploaded))
            .or_default()
            .add(rec.size);
        types
            .entry(rec.mime.clone().unwrap_or_else(|| "unknown".into()))
            .or_default()
            .add(rec.size);
        sizes[SIZES.iter().position(|&s| rec.size < s).unwrap_or(5)].add(rec.size);
        let read = match last_reads.get(&seq) {
            None => 5,
            Some(&d) => match today.saturating_sub(u64::from(d)) {
                0 => 0,
                1..=6 => 1,
                7..=29 => 2,
                30..=89 => 3,
                _ => 4,
            },
        };
        reads[read].add(rec.size);
        if owners.len() > 1 {
            shared += 1;
            saved += rec.size * (owners.len() as u64 - 1);
        }
        // Each owner of a blob uploaded all of it.
        for o in owners {
            let e = per.entry(o).or_insert((0, 0, u64::MAX));
            e.0 += 1;
            e.1 += rec.size;
            e.2 = e.2.min(rec.uploaded);
        }
    })?;

    // Uploaders: how many, how much each, and when each came.
    let mut new_by_month: BTreeMap<String, u64> = BTreeMap::new();
    // 1 file, 2-10, 11-100, 101-1,000, more.
    let mut spread = [0u64; 5];
    for (files, _, first) in per.values() {
        *new_by_month.entry(month_of(*first)).or_default() += 1;
        spread[match files {
            1 => 0,
            2..=10 => 1,
            11..=100 => 2,
            101..=1000 => 3,
            _ => 4,
        }] += 1;
    }
    let uploaders = per.len();
    let mut top: Vec<([u8; 32], (u64, u64, u64))> = per.into_iter().collect();
    top.sort_unstable_by_key(|(_, (_, bytes, _))| std::cmp::Reverse(*bytes));
    top.truncate(TOP);

    let mut types: Vec<(String, Tally)> = types.into_iter().collect();
    types.sort_unstable_by_key(|(_, t)| std::cmp::Reverse(t.bytes));
    let rest = types
        .iter()
        .skip(12)
        .fold(Tally::default(), |mut a, (_, t)| {
            a.files += t.files;
            a.bytes += t.bytes;
            a
        });
    types.truncate(12);

    // Bans and reports by month; the scanner's refusals apart.
    let bans = app.store.bans()?;
    let mut ban_months: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut by_scanner = 0u64;
    for b in &bans {
        let m = ban_months.entry(month_of(b.at)).or_default();
        match b.target {
            Banned::Blob(_) => m.0 += 1,
            Banned::Pubkey(_) => m.1 += 1,
        }
        if b.reason.starts_with("scan:") {
            by_scanner += 1;
        }
    }
    let mut report_months: BTreeMap<String, u64> = BTreeMap::new();
    let reports = app.store.read(|txn| app.store.reports(txn))??;
    for (_, json) in &reports {
        let at = serde_json::from_slice::<Value>(json)
            .ok()
            .and_then(|v| v["created_at"].as_u64())
            .unwrap_or(0);
        if at > 0 {
            *report_months.entry(month_of(at)).or_default() += 1;
        }
    }

    let spread: Vec<Value> = [
        "1 file",
        "2–10 files",
        "11–100 files",
        "101–1,000 files",
        "over 1,000 files",
    ]
    .iter()
    .zip(spread)
    .map(|(label, n)| json!({ "label": label, "uploaders": n }))
    .collect();
    let labels = |names: &[&str], tallies: &[Tally]| -> Vec<Value> {
        names
            .iter()
            .zip(tallies)
            .map(|(n, t)| json!({ "label": n, "files": t.files, "bytes": t.bytes }))
            .collect()
    };
    Ok(json!({
        "at": now,
        "files": all.files,
        "bytes": all.bytes,
        "uploaders": uploaders,
        "kinds": { "image": kinds[0].json(), "video": kinds[1].json(), "other": kinds[2].json() },
        "shared": { "files": shared, "saved": saved },
        "days": days.iter().enumerate().map(|(i, t)| json!({
            "day": (first_day + i as u64) * 86400,
            "files": t.files,
            "bytes": t.bytes,
        })).collect::<Vec<_>>(),
        "months": months.iter().map(|(m, t)| json!({
            "month": m,
            "files": t.files,
            "bytes": t.bytes,
            "new_uploaders": new_by_month.get(m).copied().unwrap_or(0),
        })).collect::<Vec<_>>(),
        "types": types.iter().map(|(ty, t)| json!({ "type": ty, "files": t.files, "bytes": t.bytes }))
            .chain((rest.files > 0).then(|| json!({ "type": "everything else", "files": rest.files, "bytes": rest.bytes })))
            .collect::<Vec<_>>(),
        "sizes": labels(&["under 10 KB", "10–100 KB", "100 KB–1 MB", "1–10 MB", "10–100 MB", "over 100 MB"], &sizes),
        "reads": labels(&["today", "this week", "this month", "last 90 days", "longer ago", "not since tracking began"], &reads),
        "spread": spread,
        "top": top.iter().map(|(pk, (files, bytes, first))| json!({
            "pubkey": hex::encode(pk),
            "files": files,
            "bytes": bytes,
            "since": first,
        })).collect::<Vec<_>>(),
        "bans": {
            "blobs": bans.iter().filter(|b| matches!(b.target, Banned::Blob(_))).count(),
            "pubkeys": bans.iter().filter(|b| matches!(b.target, Banned::Pubkey(_))).count(),
            "by_scanner": by_scanner,
            "months": ban_months.iter().map(|(m, (b, p))| json!({ "month": m, "blobs": b, "pubkeys": p })).collect::<Vec<_>>(),
        },
        "reports": {
            "total": reports.len(),
            "months": report_months.iter().map(|(m, n)| json!({ "month": m, "reports": n })).collect::<Vec<_>>(),
        },
    }))
}

fn record(app: &App, rec: &Record) -> Value {
    json!({
        "sha256": rec.hash.hex(),
        "size": rec.size,
        "type": rec.mime,
        "uploaded": rec.uploaded,
        "unscanned": rec.has(flag::UNSCANNED),
        "url": blob_url(app, &rec.hash, rec.mime.as_deref()),
    })
}

fn ban_json(ban: &Ban) -> Value {
    let (kind, target) = match ban.target {
        Banned::Blob(h) => ("blob", h.hex()),
        Banned::Pubkey(pk) => ("pubkey", hex::encode(pk)),
    };
    json!({ "kind": kind, "target": target, "at": ban.at, "reason": ban.reason })
}

/// A report's event, as admins need it: who, when, why, and about which blob.
fn report_json(hash: &Hash, json: &[u8]) -> Value {
    let ev: Value = serde_json::from_slice(json).unwrap_or(Value::Null);
    let kind = ev["tags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .find(|t| {
            t.first().and_then(Value::as_str) == Some("x")
                && t.get(1).and_then(Value::as_str) == Some(&hash.hex())
        })
        .and_then(|t| t.get(2))
        .and_then(Value::as_str)
        .map(String::from);
    json!({
        "sha256": hash.hex(),
        "id": ev["id"],
        "reporter": ev["pubkey"],
        "created_at": ev["created_at"],
        "type": kind,
        "content": ev["content"],
    })
}

fn blob(app: &'static App, hex: &str) -> Answer {
    let hash = Hash::parse(hex.as_bytes())
        .ok_or_else(|| Failure::Bad("That isn't a SHA-256 hash".into()))?;
    let v = app.store.read(|txn| -> anyhow::Result<Value> {
        let ban = app.store.ban_of(txn, Banned::Blob(hash))?;
        let reports: Vec<Value> = app
            .store
            .reports_of(txn, &hash)?
            .iter()
            .map(|r| report_json(&hash, r))
            .collect();
        let (stored, owners) = match app.store.seq_of(txn, &hash)? {
            Some(seq) => match app.store.record(txn, seq)? {
                Some(rec) => (Some(record(app, &rec)), app.store.owners_of(txn, seq)?),
                None => (None, Vec::new()),
            },
            None => (None, Vec::new()),
        };
        Ok(json!({
            "sha256": hash.hex(),
            "stored": stored,
            "owners": owners.iter().map(hex::encode).collect::<Vec<_>>(),
            "ban": ban.as_ref().map(ban_json),
            "reports": reports,
        }))
    })??;
    Ok(v)
}

fn pubkey(app: &'static App, hex: &str, query: Option<&str>) -> Answer {
    let pk: [u8; 32] = hex::decode(hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Failure::Bad("That isn't a hex pubkey".into()))?;
    let cursor = query
        .unwrap_or_default()
        .split('&')
        .find_map(|p| p.strip_prefix("cursor="))
        .map(|c| {
            Hash::parse(c.as_bytes()).ok_or_else(|| Failure::Bad("The cursor isn't a hash".into()))
        })
        .transpose()?;
    let (ban, owned, stats) = app.store.read(|txn| -> anyhow::Result<_> {
        let seqs = app.store.owned(txn, &pk)?;
        // What they've stored, as a profile's numbers: on the first page.
        let stats = match cursor {
            Some(_) => Value::Null,
            None => {
                let (mut bytes, mut media, mut reports) = (0u64, 0usize, 0usize);
                let (mut first, mut last) = (u64::MAX, 0u64);
                for &seq in &seqs {
                    let Some(rec) = app.store.record(txn, seq)? else {
                        continue;
                    };
                    bytes += rec.size;
                    first = first.min(rec.uploaded);
                    last = last.max(rec.uploaded);
                    if crate::scan::kind(rec.mime.as_deref()) != crate::scan::Kind::Other {
                        media += 1;
                    }
                    reports += app.store.reports_of(txn, &rec.hash)?.len();
                }
                json!({
                    "bytes": bytes,
                    "media": media,
                    "reports": reports,
                    "first": (first != u64::MAX).then_some(first),
                    "last": (last != 0).then_some(last),
                })
            }
        };
        Ok((
            app.store.ban_of(txn, Banned::Pubkey(pk))?,
            seqs.len(),
            stats,
        ))
    })??;
    let recs = app
        .store
        .list(&pk, cursor.as_ref(), PAGE_SIZE, None, None)?;
    Ok(json!({
        "pubkey": hex::encode(pk),
        "ban": ban.as_ref().map(ban_json),
        "owned": owned,
        "stats": stats,
        "blobs": recs.iter().map(|r| record(app, r)).collect::<Vec<_>>(),
        "next": (recs.len() == PAGE_SIZE).then(|| recs.last().map(|r| r.hash.hex())).flatten(),
    }))
}

fn bans(app: &'static App) -> Answer {
    let mut all = app.store.bans()?;
    all.sort_by_key(|b| std::cmp::Reverse(b.at));
    Ok(Value::Array(all.iter().map(ban_json).collect()))
}

fn reports(app: &'static App) -> Answer {
    let rows = app.store.read(|txn| -> anyhow::Result<Vec<Value>> {
        let mut rows = Vec::new();
        for (hash, json) in app.store.reports(txn)? {
            let mut row = report_json(&hash, &json);
            let stored = app.store.seq_of(txn, &hash)?.is_some();
            let banned = app.store.ban_of(txn, Banned::Blob(hash))?.is_some();
            row["stored"] = stored.into();
            row["banned"] = banned.into();
            rows.push(row);
        }
        Ok(rows)
    })??;
    let mut rows = rows;
    rows.sort_by_key(|r| std::cmp::Reverse(r["created_at"].as_u64().unwrap_or(0)));
    Ok(Value::Array(rows))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Targets {
    #[serde(default)]
    blobs: Vec<String>,
    #[serde(default)]
    pubkeys: Vec<String>,
    #[serde(default)]
    reason: String,
}

impl Targets {
    fn parse(body: &[u8]) -> Result<(Targets, Vec<Banned>), Failure> {
        let t: Targets = serde_json::from_slice(body)
            .map_err(|e| Failure::Bad(format!("The body isn't what was expected: {e}")))?;
        let mut targets = Vec::new();
        for h in &t.blobs {
            let hash = Hash::parse(h.trim().as_bytes())
                .ok_or_else(|| Failure::Bad(format!("{h} isn't a SHA-256 hash")))?;
            targets.push(Banned::Blob(hash));
        }
        for k in &t.pubkeys {
            let pk: [u8; 32] = hex::decode(k.trim())
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| Failure::Bad(format!("{k} isn't a hex pubkey")))?;
            targets.push(Banned::Pubkey(pk));
        }
        if targets.is_empty() {
            return Err(Failure::Bad("Name a blob or a pubkey".into()));
        }
        Ok((t, targets))
    }
}

async fn ban(app: &'static App, admin: [u8; 32], body: &[u8]) -> Answer {
    let (t, targets) = Targets::parse(body)?;
    let reason = t.reason.trim().to_string();
    let (blobs, pubkeys) = (t.blobs.len(), t.pubkeys.len());
    let (removed, reason) = tokio::task::spawn_blocking(move || {
        crate::moderate::ban_in(app.store, app.files, &targets, &reason, None).map(|r| (r, reason))
    })
    .await
    .map_err(|e| Failure::Internal(e.into()))??;
    crate::info!("admin_ban", "admin": hex::encode(admin), "blobs": blobs, "pubkeys": pubkeys,
        "removed": removed.len(), "reason": reason);
    let n = removed.len();
    let mut answer = json!({ "urls": cached_urls(app, &removed) });
    answer["removed"] = n.into();
    Ok(answer)
}

/// Whether an evidence record is of a blob banned as CSAM, rather than one
/// kept as its context.
fn flagged(rec: &Value) -> bool {
    rec["context_of"].as_array().is_none_or(Vec::is_empty)
}

fn one_hash(body: &[u8]) -> Result<(Hash, Value), Failure> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|e| Failure::Bad(format!("The body isn't what was expected: {e}")))?;
    let hash = v["sha256"]
        .as_str()
        .and_then(|h| Hash::parse(h.trim().as_bytes()))
        .ok_or_else(|| Failure::Bad("Name a blob by its SHA-256".into()))?;
    Ok((hash, v))
}

/// `POST /api/csam {"sha256"}`: ban a blob as child sexual abuse material,
/// and everyone who uploaded it, keeping a copy of the blob before it's
/// removed. Their other blobs are removed too, and kept as its context.
async fn csam(app: &'static App, admin: [u8; 32], body: &[u8]) -> Answer {
    let (hash, _) = one_hash(body)?;
    let dir = app.config.evidence();
    let (removed, uploaders, unlearned) = tokio::task::spawn_blocking(move || {
        let (removed, uploaders) =
            crate::moderate::ban_csam(app.store, app.files, &[hash], &[], &dir)?;
        // Nothing it banned stays in what the scanner is trained on.
        let mut gone: Vec<String> = removed.iter().map(|r| r.hash.hex()).collect();
        gone.push(hash.hex());
        let unlearned = unlearn(app, &gone)?;
        anyhow::Ok((removed, uploaders, unlearned))
    })
    .await
    .map_err(|e| Failure::Internal(e.into()))??;
    let kept = removed.iter().filter(|r| r.hash == hash).count();
    crate::info!("admin_csam", "admin": hex::encode(admin), "blob": hash.hex(),
        "uploaders": uploaders, "kept": kept, "removed": removed.len(), "unlearned": unlearned);
    let mut answer = json!({ "urls": cached_urls(app, &removed) });
    answer["kept"] = kept.into();
    answer["uploaders"] = uploaders.into();
    Ok(answer)
}

/// `GET /api/evidence`: each blob banned as CSAM, with what a report needs,
/// whether it's been reported, and how many more were kept as its context.
fn evidence(app: &'static App) -> Answer {
    let dir = app.config.evidence();
    let all = crate::moderate::evidence(&dir)?;
    let items: Vec<Value> = all
        .iter()
        .filter(|r| flagged(r))
        .map(|r| {
            let hex = r["sha256"].as_str().unwrap_or_default();
            let context = all
                .iter()
                .filter(|o| {
                    o["context_of"]
                        .as_array()
                        .is_some_and(|c| c.iter().any(|h| h == hex))
                })
                .count();
            let mut v = r.clone();
            v["context"] = context.into();
            v["path"] = dir.join(hex).display().to_string().into();
            v
        })
        .collect();
    Ok(json!({ "dir": dir.display().to_string(), "items": items }))
}

/// `POST /api/evidence/reported {"sha256", "report"}`: note the CyberTipline
/// report that names a blob banned as CSAM.
async fn reported(app: &'static App, admin: [u8; 32], body: &[u8]) -> Answer {
    let (hash, v) = one_hash(body)?;
    let id = v["report"].as_str().unwrap_or_default().trim().to_string();
    if id.is_empty() || id.len() > 100 {
        return Err(Failure::Bad("Give the CyberTipline report's number".into()));
    }
    let dir = app.config.evidence();
    let (at, report) = (now(), id.clone());
    let noted = tokio::task::spawn_blocking(move || {
        let _held = app.admin.noting.lock();
        crate::moderate::reported(&dir, &hash, &report, at)
    })
    .await
    .map_err(|e| Failure::Internal(e.into()))??;
    if noted == 0 {
        return Err(Failure::Bad(format!(
            "No evidence is kept of {}",
            hash.hex()
        )));
    }
    crate::info!("admin_reported", "admin": hex::encode(admin), "blob": hash.hex(), "report": id);
    Ok(json!({ "noted": noted }))
}

async fn unban(app: &'static App, admin: [u8; 32], body: &[u8]) -> Answer {
    let (t, targets) = Targets::parse(body)?;
    let (blobs, pubkeys) = (t.blobs.len(), t.pubkeys.len());
    tokio::task::spawn_blocking(move || crate::moderate::unban_in(app.store, &targets))
        .await
        .map_err(|e| Failure::Internal(e.into()))??;
    crate::info!("admin_unban", "admin": hex::encode(admin), "blobs": blobs, "pubkeys": pubkeys);
    Ok(json!({}))
}

/// Blobs a page of the media view holds, and the most records one request
/// looks through to fill it, so a narrow filter can't hold a read long.
const MEDIA_PAGE: usize = 60;
/// Blobs a page of Review holds: few, each read to see what it is.
const REVIEW_PAGE: usize = 15;
const MEDIA_BUDGET: usize = 20_000;
/// How many times a page looks further back for blobs whose bytes are
/// media, when most of what was declared media isn't.
const MEDIA_ROUNDS: usize = 8;

/// Who uploaded a stored blob, hex.
fn owners_hex(app: &'static App, hash: &Hash) -> Vec<String> {
    app.store
        .read(|txn| -> anyhow::Result<Vec<[u8; 32]>> {
            Ok(match app.store.seq_of(txn, hash)? {
                Some(seq) => app.store.owners_of(txn, seq)?,
                None => Vec::new(),
            })
        })
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
        .iter()
        .map(hex::encode)
        .collect()
}

/// What each record's first bytes say it is, read all at once.
fn sniff_all(app: &'static App, recs: &[Record]) -> Vec<Option<String>> {
    std::thread::scope(|s| {
        let reading: Vec<_> = recs
            .iter()
            .map(|r| s.spawn(move || sniffed(app, &r.hash)))
            .collect();
        reading
            .into_iter()
            .map(|h| h.join().unwrap_or(None))
            .collect()
    })
}

/// What a stored blob's first bytes say it is, whatever it was declared.
fn sniffed(app: &'static App, hash: &Hash) -> Option<String> {
    use std::io::Read;
    let found = app.store.find(hash, false).ok()??;
    let head = match found.body {
        Some(b) => b[..b.len().min(4096)].to_vec(),
        None => {
            let mut f = std::fs::File::open(app.files.path(hash, false)).ok()?;
            let mut buf = vec![0; 4096];
            let n = f.read(&mut buf).ok()?;
            buf.truncate(n);
            buf
        }
    };
    crate::mime::sniff(&head)
}

/// The training files, when labelling is set up: labels, embeddings, and
/// the scanner whose encoder embeds them.
fn labelling(
    app: &'static App,
) -> Option<(
    &'static PathBuf,
    &'static PathBuf,
    &'static crate::scan::Scanner,
)> {
    let a = &app.config.admin;
    Some((
        a.labels.as_ref()?,
        a.embeddings.as_ref()?,
        app.scanner.as_ref()?,
    ))
}

/// The labels file, `{"<sha256>": "explicit" | "clean"}`; empty if there's none.
fn read_labels(
    path: &std::path::Path,
) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    match std::fs::read(path) {
        Ok(b) => Ok(serde_json::from_slice(&b)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(e) => Err(e.into()),
    }
}

fn write_labels(
    path: &std::path::Path,
    labels: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(labels)?)?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Whether a blob is banned as CSAM.
fn banned_as_csam(app: &'static App, hash: &Hash) -> anyhow::Result<bool> {
    let ban = app
        .store
        .read(|txn| app.store.ban_of(txn, Banned::Blob(*hash)))??;
    Ok(ban.is_some_and(|b| b.reason == "CSAM"))
}

/// Take blobs out of the training labels and embeddings, whether or not
/// labelling is on now. How many labels and embedding lines went.
fn unlearn(app: &'static App, hashes: &[String]) -> anyhow::Result<usize> {
    let _held = app.admin.labelling.lock();
    let mut gone = 0;
    if let Some(path) = &app.config.admin.labels {
        let mut all = read_labels(path)?;
        let before = all.len();
        all.retain(|h, _| !hashes.contains(h));
        if all.len() < before {
            gone += before - all.len();
            write_labels(path, &all)?;
        }
    }
    if let Some(path) = &app.config.admin.embeddings {
        gone += crate::scan::train::forget_in_cache(path, hashes)?;
    }
    Ok(gone)
}

/// `GET /api/media?kind=image|video|media|all&before=<cursor>`: stored blobs,
/// newest first, each with its training label if it has one.
fn reviewed_file(app: &App) -> PathBuf {
    app.config.data.join("admin-reviewed")
}

/// The blobs found fine in Review, read in if they haven't been.
fn with_reviewed<R>(
    app: &'static App,
    f: impl FnOnce(&mut std::collections::HashSet<[u8; 32]>) -> R,
) -> anyhow::Result<R> {
    let mut held = app.admin.reviewed.lock();
    if held.is_none() {
        let set = match std::fs::read_to_string(reviewed_file(app)) {
            Ok(text) => text
                .lines()
                .filter_map(|l| Hash::parse(l.trim().as_bytes()).map(|h| h.0))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Default::default(),
            Err(e) => return Err(e.into()),
        };
        *held = Some(set);
    }
    Ok(f(held.as_mut().expect("read in")))
}

/// `POST /api/reviewed {"blobs"}`: found fine in Review, not to be shown
/// there again.
fn reviewed(app: &'static App, body: &[u8]) -> Answer {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let hashes = Blobs::parse(body)?;
    let new: Vec<Hash> = with_reviewed(app, |set| {
        hashes.into_iter().filter(|h| set.insert(h.0)).collect()
    })?;
    if !new.is_empty() {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(reviewed_file(app))
            .map_err(anyhow::Error::from)?;
        let lines: String = new.iter().map(|h| format!("{}\n", h.hex())).collect();
        f.write_all(lines.as_bytes()).map_err(anyhow::Error::from)?;
    }
    Ok(json!({ "reviewed": new.len() }))
}

fn media(app: &'static App, query: Option<&str>) -> Answer {
    use crate::scan::Kind;
    let (mut kind, mut before, mut fresh) = ("media", None, false);
    for pair in query
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
    {
        match pair.split_once('=').unwrap_or((pair, "")) {
            ("kind", k @ ("image" | "video" | "media" | "all")) => kind = k,
            // Only what nobody has reviewed or labelled yet.
            ("new", "1") => fresh = true,
            ("before", b) => {
                before = Some(
                    b.parse::<u64>()
                        .map_err(|_| Failure::Bad("The cursor isn't valid".into()))?,
                )
            }
            _ => return Err(Failure::Bad(format!("{pair} isn't understood"))),
        }
    }
    let wanted = move |k: Kind| match (kind, k) {
        ("all", _) => true,
        ("image", Kind::Image) => true,
        ("video", Kind::Video) => true,
        ("media", k) => k != Kind::Other,
        _ => false,
    };
    let labels = match &app.config.admin.labels {
        Some(p) => read_labels(p)?,
        None => Default::default(),
    };
    // The declared type picks what to look at. For Review, the bytes decide
    // too, an encrypted attachment declared an image being no picture to
    // review: its few are read at once, as files not read lately come off
    // the disk slowly. Browsing reads none, so pages deep in the past come
    // as fast as the first; the browser drops what it can't show.
    let page = if fresh { REVIEW_PAGE } else { MEDIA_PAGE };
    let (mut recs, mut next) = (Vec::new(), before);
    for _ in 0..MEDIA_ROUNDS {
        let (found, more) = app
            .store
            .recent(next, page - recs.len(), MEDIA_BUDGET, |rec| {
                wanted(crate::scan::kind(rec.mime.as_deref()))
                    && !(fresh
                        && (labels.contains_key(&rec.hash.hex())
                            || with_reviewed(app, |set| set.contains(&rec.hash.0))
                                .unwrap_or(false)))
            })?;
        let types = if fresh {
            sniff_all(app, &found)
        } else {
            vec![None; found.len()]
        };
        for (rec, ty) in found.into_iter().zip(types) {
            if !fresh || wanted(crate::scan::kind(ty.as_deref())) {
                recs.push((rec, ty));
            }
        }
        next = more;
        if !fresh || next.is_none() || recs.len() >= page {
            break;
        }
    }
    let blobs: Vec<Value> = recs
        .iter()
        .map(|(r, ty)| {
            let mut v = record(app, r);
            v["label"] = labels.get(&r.hash.hex()).cloned().into();
            v["media"] = ty.clone().into();
            v["owners"] = owners_hex(app, &r.hash).into();
            v
        })
        .collect();
    Ok(json!({ "blobs": blobs, "next": next.map(|n| n.to_string()) }))
}

/// Where a stored blob's bytes are, for a scan worker, and the type it's
/// served as.
fn input_of(
    app: &'static App,
    hash: &Hash,
) -> Result<(crate::scan::Input, Option<String>), Failure> {
    let found = app
        .store
        .find(hash, false)?
        .ok_or_else(|| Failure::Bad(format!("{} isn't stored", hash.hex())))?;
    let input = match found.body {
        Some(b) => crate::scan::Input::Bytes(std::sync::Arc::from(&b[..])),
        None => crate::scan::Input::File(app.files.path(hash, false)),
    };
    Ok((input, found.record.mime))
}

/// `GET /api/thumb/<sha256>?side=400|1280`: a small JPEG of a stored
/// picture or video (see `scan::thumb`). 415 for what's no kind of media,
/// and 422 for what won't decode, so the browser's image fails on either.
async fn thumb(app: &'static App, hex: &str, query: Option<&str>) -> Response<Body> {
    use crate::scan::thumb::{SIDES, make_safely};
    let Some(hash) = Hash::parse(hex.as_bytes()) else {
        return error(StatusCode::BAD_REQUEST, "That isn't a SHA-256 hash");
    };
    let side = match query.and_then(|q| q.strip_prefix("side=")) {
        None if query.is_none() => SIDES[0],
        Some(s) => match s.parse() {
            Ok(n) if SIDES.contains(&n) => n,
            _ => return error(StatusCode::BAD_REQUEST, "side is 400 or 1280"),
        },
        None => return error(StatusCode::BAD_REQUEST, "side is 400 or 1280"),
    };
    // Only what's stored now, made or kept: a removed blob is never shown.
    let found = match app.store.find(&hash, false) {
        Ok(Some(f)) => f,
        Ok(None) => {
            let mut made = app.admin.thumbs.made.lock();
            for s in SIDES {
                made.pop(&(hash, s));
            }
            return error(StatusCode::NOT_FOUND, "It isn't stored here");
        }
        Err(e) => {
            crate::error!("admin_failed", "path": "/api/thumb", "error": format!("{e:#}"));
            return error(StatusCode::INTERNAL_SERVER_ERROR, "That couldn't be done");
        }
    };
    let jpeg = |b: Bytes| {
        let mut r = Response::new(Full::new(b));
        r.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
        r
    };
    let kept = || app.admin.thumbs.made.lock().get(&(hash, side)).cloned();
    if let Some(b) = kept() {
        return jpeg(b);
    }
    let Ok(_turn) = app.admin.thumbs.making.acquire().await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "Try again shortly");
    };
    // Made by another request while this one waited its turn.
    if let Some(b) = kept() {
        return jpeg(b);
    }
    let input = match found.body {
        Some(b) => crate::scan::Input::Bytes(std::sync::Arc::from(&b[..])),
        None => crate::scan::Input::File(app.files.path(&hash, false)),
    };
    let ffmpeg = &app.config.scan.ffmpeg;
    let ffmpeg = (!ffmpeg.as_os_str().is_empty()).then(|| ffmpeg.clone());
    let made =
        tokio::task::spawn_blocking(move || make_safely(&input, side, ffmpeg.as_deref())).await;
    match made {
        Ok(Ok(Some(t))) => {
            let b = Bytes::from(t);
            app.admin.thumbs.made.lock().put((hash, side), b.clone());
            jpeg(b)
        }
        Ok(Ok(None)) => error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "It isn't a picture or a video",
        ),
        Ok(Err(_)) => error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "It doesn't decode as a picture or a video",
        ),
        Err(e) => {
            crate::error!("admin_failed", "path": "/api/thumb", "error": e.to_string());
            error(StatusCode::INTERNAL_SERVER_ERROR, "That couldn't be done")
        }
    }
}

/// `GET /api/score/<sha256>`: what a scan makes of a stored blob now.
async fn score(app: &'static App, hex: &str) -> Answer {
    let hash = Hash::parse(hex.as_bytes())
        .ok_or_else(|| Failure::Bad("That isn't a SHA-256 hash".into()))?;
    let scanner = app
        .scanner
        .as_ref()
        .ok_or_else(|| Failure::Bad("Scanning is off here".into()))?;
    let (input, served) = input_of(app, &hash)?;
    let v = scanner
        .check(input, served.as_deref())
        .await
        .map_err(|_| Failure::Bad("The scanners are busy; try again shortly".into()))?;
    Ok(json!({
        "sha256": hash.hex(),
        "score": v.score(),
        "outcome": format!("{:?}", v.outcome),
        "refused": v.refused(scanner.rule),
        "threshold": scanner.rule.threshold,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Blobs {
    blobs: Vec<String>,
}

impl Blobs {
    fn parse(body: &[u8]) -> Result<Vec<Hash>, Failure> {
        let b: Blobs = serde_json::from_slice(body)
            .map_err(|e| Failure::Bad(format!("The body isn't what was expected: {e}")))?;
        hashes(&b.blobs)
    }
}

/// Blobs named by hex, at least one.
fn hashes(blobs: &[String]) -> Result<Vec<Hash>, Failure> {
    let hashes = blobs
        .iter()
        .map(|h| {
            Hash::parse(h.trim().as_bytes())
                .ok_or_else(|| Failure::Bad(format!("{h} isn't a SHA-256 hash")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if hashes.is_empty() {
        return Err(Failure::Bad("Name a blob".into()));
    }
    Ok(hashes)
}

/// `POST /api/remove`: take blobs out, whoever owns them, without banning
/// them, and keeping nothing.
async fn remove(app: &'static App, admin: [u8; 32], body: &[u8]) -> Answer {
    let hashes = Blobs::parse(body)?;
    let removed = tokio::task::spawn_blocking(move || {
        crate::moderate::remove_in(app.store, app.files, &hashes)
    })
    .await
    .map_err(|e| Failure::Internal(e.into()))??;
    crate::info!("admin_remove", "admin": hex::encode(admin), "removed": removed.len());
    let n = removed.len();
    let mut answer = json!({ "urls": cached_urls(app, &removed) });
    answer["removed"] = n.into();
    Ok(answer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Label {
    blobs: Vec<String>,
    /// "explicit" or "clean".
    label: String,
}

/// `POST /api/label`: label stored blobs for training, each embedded into
/// the cache at once, so it can still be trained on once it's gone. Never
/// a blob banned as CSAM.
async fn label(app: &'static App, admin: [u8; 32], body: &[u8]) -> Answer {
    let b: Label = serde_json::from_slice(body)
        .map_err(|e| Failure::Bad(format!("The body isn't what was expected: {e}")))?;
    let hashes = hashes(&b.blobs)?;
    let label = match b.label.as_str() {
        l @ ("explicit" | "clean") => l.to_string(),
        _ => {
            return Err(Failure::Bad(
                "The label is \"explicit\" or \"clean\"".into(),
            ));
        }
    };
    let (labels, cache, scanner) = labelling(app).ok_or_else(|| {
        Failure::Bad(
            "Labelling needs scanning on, and admin.labels and admin.embeddings set".into(),
        )
    })?;
    let mut done = 0;
    for hash in hashes {
        if banned_as_csam(app, &hash)? {
            return Err(Failure::Bad(format!("{} is banned as CSAM", hash.hex())));
        }
        let (input, served) = input_of(app, &hash)?;
        let e = scanner
            .embed(input, served.as_deref())
            .await
            .map_err(|e| Failure::Bad(format!("{} couldn't be embedded: {e:#}", hash.hex())))?;
        let label = label.clone();
        let kept = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
            let _held = app.admin.labelling.lock();
            // Banned as CSAM while it was embedded: its unlearning is done.
            if banned_as_csam(app, &hash)? {
                return Ok(false);
            }
            let h = hash.hex();
            crate::scan::train::add_to_cache(cache, &e.fingerprint, &h, &e.squares)?;
            let mut all = read_labels(labels)?;
            all.insert(h, label);
            write_labels(labels, &all)?;
            Ok(true)
        })
        .await
        .map_err(|e| Failure::Internal(e.into()))??;
        if !kept {
            return Err(Failure::Bad(format!("{} is banned as CSAM", hash.hex())));
        }
        done += 1;
    }
    crate::info!("admin_label", "admin": hex::encode(admin), "label": label, "blobs": done);
    Ok(json!({ "labelled": done }))
}
