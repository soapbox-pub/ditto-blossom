//! The endpoints that write: `PUT /upload` and its `HEAD` preflight
//! (BUD-02, BUD-06), `DELETE /<sha256>` and `GET /list/<pubkey>` (BUD-12),
//! `PUT /report` (BUD-09).

use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap};
use hyper::{Request, Response, StatusCode};
use serde_json::{Value, json};

use crate::app::App;
use crate::auth::{Refusal, Token};
use crate::hash::Hash;
use crate::http::{self, error};
use crate::ingest;
use crate::routes::{blob_url, client_ip};
use crate::scan::known::{Banner, Checked, Match, Source};
use crate::server::Body;
use crate::store::Record;
use crate::writer::{Deleted, Refused};

const BANNED: &str = "This blob, or its uploader, is banned here";

/// A 403 if the blob or the uploader is banned. A failed read lets the
/// request on; the writer checks again before anything is kept.
pub fn refuse_banned(
    app: &'static App,
    hash: Option<&Hash>,
    token: Option<&Token>,
) -> Option<Response<Body>> {
    app.store
        .is_banned(hash, token.map(|t| &t.pubkey))
        .unwrap_or(false)
        .then(|| error(StatusCode::FORBIDDEN, BANNED))
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A blob descriptor (BUD-02), with its NIP-94 tags (BUD-08).
pub fn descriptor(app: &App, rec: &Record) -> Value {
    let ty = rec.mime.as_deref().unwrap_or("application/octet-stream");
    let url = blob_url(app, &rec.hash, rec.mime.as_deref());
    let hex = rec.hash.hex();
    json!({
        "url": url, "sha256": hex, "size": rec.size, "type": ty, "uploaded": rec.uploaded,
        "nip94": [["url", url], ["m", ty], ["x", hex], ["size", rec.size.to_string()]],
    })
}

/// The token for `verb`, or a refusal if one is needed and missing, or bad.
fn token(
    app: &App,
    headers: &HeaderMap,
    verb: &str,
    required: bool,
) -> Result<Option<Token>, Refusal> {
    match app.auth.check(headers, verb, now())? {
        None if required => Err((
            StatusCode::UNAUTHORIZED,
            "This needs a Nostr auth token (BUD-11)",
        )),
        t => Ok(t),
    }
}

fn header_hash(headers: &HeaderMap) -> Result<Option<Hash>, Refusal> {
    match headers.get("x-sha-256") {
        None => Ok(None),
        Some(v) => Hash::parse(v.as_bytes())
            .map(Some)
            .ok_or((StatusCode::BAD_REQUEST, "X-SHA-256 isn't a SHA-256 hash")),
    }
}

fn number(headers: &HeaderMap, name: impl header::AsHeaderName) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.trim().parse().ok()
}

pub async fn upload(app: &'static App, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
    let ip = client_ip(app, &req, peer);
    let (parts, body) = req.into_parts();
    let h = &parts.headers;
    let token = match token(app, h, "upload", app.config.upload.require_auth) {
        Ok(t) => t,
        Err((status, why)) => return error(status, why),
    };
    let Some(length) = number(h, header::CONTENT_LENGTH) else {
        return error(StatusCode::LENGTH_REQUIRED, "Uploads need a Content-Length");
    };
    let max_size = app.max_size(token.as_ref());
    if length > max_size {
        return too_large(max_size);
    }
    let claimed = match header_hash(h) {
        Ok(c) => c,
        Err((status, why)) => return error(status, why),
    };
    if let (Some(t), Some(c)) = (&token, &claimed)
        && !t.allows(c)
    {
        return error(StatusCode::FORBIDDEN, "The auth token isn't for this blob");
    }
    if let Some(r) = refuse_banned(app, claimed.as_ref(), token.as_ref()) {
        return r;
    }
    if !app.allow_upload(token.as_ref(), ip) {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many uploads; try again in a minute",
        );
    }
    // Here already: nothing to read.
    if let Some(c) = claimed
        && let Ok(true) = app.store.find(&c, false).map(|f| f.is_some())
    {
        let owner = token.as_ref().map(|t| t.pubkey);
        let rec = match owner {
            Some(pk) => app.writer.add_owner(c, pk).await,
            None => app.store.find(&c, false).map(|f| f.map(|f| f.record)),
        };
        if let Ok(Some(rec)) = rec {
            return http::json(StatusCode::OK, &descriptor(app, &rec));
        }
    }
    if let Err(wait) = app.allow_bytes(token.as_ref(), ip, length) {
        return too_much(wait, "upload");
    }
    let Ok(_receiving) = app.receiving.try_acquire() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many uploads at once; try again shortly",
        );
    };

    let declared_type = h
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let blob = match ingest::ingest(
        app.files,
        body,
        Some(length),
        max_size,
        declared_type.as_deref(),
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return ingest_error(e),
    };
    if claimed.is_some_and(|c| c != blob.hash) {
        return error(StatusCode::CONFLICT, "The blob's hash isn't X-SHA-256");
    }
    if let Some(t) = &token
        && !t.allows(&blob.hash)
    {
        return error(StatusCode::FORBIDDEN, "The auth token isn't for this blob");
    }
    store(app, blob, token.map(|t| t.pubkey), ip, "upload").await
}

const REFUSED: &str = "Explicit images and video aren't accepted here";

/// Stored unscanned (`scan.background`) while fewer than this wait for a
/// scan; past it, uploads are scanned before they're stored, so a flood
/// can't put off scanning what's served meanwhile.
const BACKLOG: usize = 1000;

/// Scan a received blob, if scanning is on: a refusal, or `None` to keep it.
/// A blob a scan refused before is banned, so it's refused without a look.
/// `ip` is who sent it: each address has a few scans at a time.
pub async fn screen(
    app: &'static App,
    blob: &mut crate::writer::Ingested,
    how: &str,
    ip: std::net::IpAddr,
) -> Option<Response<Body>> {
    let scanner = app.scanner.as_ref()?;
    if let Some(r) = refuse_banned(app, Some(&blob.hash), None) {
        return Some(r);
    }
    // Stored already, so served already: scanning it again changes nothing.
    if let Ok(Some(_)) = app.store.find(&blob.hash, false) {
        return None;
    }
    // No kind of media, nor a page or PDF to show any: nothing to judge,
    // and no reason to wait behind what there is.
    let head = match &blob.body {
        crate::writer::IngestedBody::Inline(v) => v[..v.len().min(crate::scan::HEAD)].to_vec(),
        crate::writer::IngestedBody::File(t) => match read_head(t.path()).await {
            Ok(h) => h,
            Err(e) => {
                crate::error!("scan_head_failed", "blob": blob.hash.hex(), "error": e.to_string());
                return Some(error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "The upload couldn't be read back",
                ));
            }
        },
    };
    if !crate::scan::needs_worker(&head, blob.mime.as_deref()) {
        return None;
    }
    if app.config.scan.background && scanner.pending() < BACKLOG {
        blob.unscanned = true;
        return None;
    }
    let Some(_turn) = scanner.turns.take(ip) else {
        let mut r = error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many of your uploads being checked at once; try again shortly",
        );
        r.headers_mut().insert(
            header::RETRY_AFTER,
            hyper::header::HeaderValue::from_static("2"),
        );
        return Some(r);
    };
    let input = match &blob.body {
        crate::writer::IngestedBody::Inline(v) => crate::scan::Input::Bytes(v.as_slice().into()),
        crate::writer::IngestedBody::File(t) => crate::scan::Input::File(t.path().to_path_buf()),
    };
    let Ok(verdict) = scanner.check(input, blob.mime.as_deref()).await else {
        return Some(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many uploads being checked; try again shortly",
        ));
    };
    let refused = verdict.refused(scanner.rule);
    if refused || matches!(verdict.outcome, crate::scan::Outcome::Undecodable(_)) {
        crate::info!(
            if refused { "refused" } else { "unscanned" },
            "via": how, "blob": blob.hash.hex(), "size": blob.size, "type": verdict.ty,
            "score": verdict.score(), "outcome": format!("{:?}", verdict.outcome),
            "ms": verdict.millis.round(),
        );
    }
    if !refused {
        return None;
    }
    if let Some(s) = verdict.score() {
        if let Err(e) = app.writer.refuse(blob.hash, s).await {
            crate::error!("refuse_record_failed", "blob": blob.hash.hex(), "error": format!("{e:#}"));
        }
        Some(error(StatusCode::FORBIDDEN, REFUSED))
    } else {
        Some(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "What it shows couldn't all be read to be checked",
        ))
    }
}

/// A file's first `scan::HEAD` bytes, or all of it if it's shorter.
async fn read_head(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await?;
    let mut head = vec![0; crate::scan::HEAD];
    let mut n = 0;
    while n < head.len() {
        match f.read(&mut head[n..]).await? {
            0 => break,
            k => n += k,
        }
    }
    head.truncate(n);
    Ok(head)
}

/// Keep an ingested blob and answer with its descriptor: 201 if it's new,
/// 200 if it was here (BUD-02, BUD-04). A new image is checked against
/// known CSAM first, if Shield is set up, and a match isn't kept; then, if
/// explicit media is refused, it's scanned for that (see `screen`).
pub async fn store(
    app: &'static App,
    mut blob: crate::writer::Ingested,
    owner: Option<[u8; 32]>,
    ip: IpAddr,
    how: &str,
) -> Response<Body> {
    let (hash, size) = (blob.hash, blob.size);
    let mut unasked = false;
    if let Some(scanner) = &app.shield
        && !matches!(app.store.find(&hash, false), Ok(Some(_)))
    {
        match scanner.check(&blob).await {
            Checked::Skipped | Checked::Clean => {}
            Checked::Unchecked(e) => {
                crate::warn!("scan_deferred", "blob": hash.hex(), "error": e);
                unasked = true;
            }
            Checked::Matched(pdq, verdict) => {
                let source = Source::of_ingested(&blob);
                let m = Match {
                    hash,
                    size,
                    mime: blob.mime.as_deref(),
                    pdq,
                    verdict,
                    via: how,
                    owners: owner.into_iter().collect(),
                    ip: Some(ip),
                    uploaded: None,
                };
                if let Err(e) = scanner
                    .on_match(m, Some(&source), Banner::Writer(&app.writer))
                    .await
                {
                    crate::error!("scan_match_failed", "blob": hash.hex(), "error": format!("{e:#}"));
                }
                return error(StatusCode::FORBIDDEN, BANNED);
            }
        }
    }
    if let Some(refusal) = screen(app, &mut blob, how, ip).await {
        return refusal;
    }
    let unscanned = blob.unscanned;
    match app.writer.insert(blob, owner, now(), unasked).await {
        Ok(stored) => {
            if stored.created {
                crate::info!("stored", "via": how, "blob": hash.hex(), "size": size, "type": stored.record.mime, "owner": owner.map(hex::encode), "ip": ip.to_string(), "unasked": unasked, "unscanned": unscanned);
                app.compressor.offer(&stored.record);
                if unscanned && let Some(s) = &app.scanner {
                    s.later(hash);
                }
            }
            let status = if stored.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            http::json(status, &descriptor(app, &stored.record))
        }
        Err(e) if e.downcast_ref::<Refused>().is_some() => {
            crate::info!("refused_banned", "via": how, "blob": hash.hex(), "owner": owner.map(hex::encode));
            error(StatusCode::FORBIDDEN, BANNED)
        }
        Err(e) => {
            crate::error!("store_failed", "blob": hash.hex(), "error": format!("{e:#}"));
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The blob couldn't be stored",
            )
        }
    }
}

/// A 429 for a client past its hourly bytes, with when to come back.
pub fn too_much(wait: std::time::Duration, how: &str) -> Response<Body> {
    let secs = wait.as_secs().max(1);
    crate::info!("limited_bytes", "via": how, "retry_after": secs);
    let mut r = error(
        StatusCode::TOO_MANY_REQUESTS,
        &format!(
            "Too much uploaded this hour; try again in {} minutes",
            secs.div_ceil(60)
        ),
    );
    r.headers_mut().insert(header::RETRY_AFTER, secs.into());
    r
}

fn too_large(max_size: u64) -> Response<Body> {
    error(
        StatusCode::PAYLOAD_TOO_LARGE,
        &format!("Blobs may be at most {max_size} bytes"),
    )
}

pub fn ingest_error(e: ingest::Error) -> Response<Body> {
    match e {
        ingest::Error::TooLarge => error(StatusCode::PAYLOAD_TOO_LARGE, "The blob is too large"),
        ingest::Error::WrongLength => error(
            StatusCode::BAD_REQUEST,
            "The body's length isn't Content-Length",
        ),
        ingest::Error::Stalled => error(StatusCode::REQUEST_TIMEOUT, "The body stopped arriving"),
        ingest::Error::Read(e) => {
            crate::info!("ingest_read_failed", "error": e.to_string());
            error(StatusCode::BAD_REQUEST, "The body couldn't be read")
        }
        ingest::Error::Disk(e) => {
            crate::error!("ingest_failed", "error": e.to_string());
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The blob couldn't be written",
            )
        }
    }
}

/// BUD-06: whether an upload would be accepted, from its headers alone.
pub fn head_upload(app: &'static App, req: &Request<Incoming>) -> Response<Body> {
    let h = req.headers();
    let token = match token(app, h, "upload", app.config.upload.require_auth) {
        Ok(t) => t,
        Err((status, why)) => return error(status, why),
    };
    let claimed = match header_hash(h) {
        Ok(c) => c,
        Err((status, why)) => return error(status, why),
    };
    let Some(length) = number(h, "x-content-length") else {
        return error(StatusCode::LENGTH_REQUIRED, "X-Content-Length is required");
    };
    let max_size = app.max_size(token.as_ref());
    if length > max_size {
        return too_large(max_size);
    }
    if let (Some(t), Some(c)) = (&token, &claimed)
        && !t.allows(c)
    {
        return error(StatusCode::FORBIDDEN, "The auth token isn't for this blob");
    }
    if let Some(r) = refuse_banned(app, claimed.as_ref(), token.as_ref()) {
        return r;
    }
    http::empty(StatusCode::OK)
}

pub async fn delete(app: &'static App, req: &Request<Incoming>, hash: Hash) -> Response<Body> {
    let token = match token(app, req.headers(), "delete", true) {
        Ok(t) => t.expect("required"),
        Err((status, why)) => return error(status, why),
    };
    if !token.allows(&hash) {
        return error(StatusCode::FORBIDDEN, "The auth token isn't for this blob");
    }
    match app.writer.delete(hash, token.pubkey).await {
        Ok(Deleted::NotOwned) => error(StatusCode::NOT_FOUND, "No such blob of yours"),
        Ok(d) => {
            crate::info!("deleted", "blob": hash.hex(), "removed": matches!(d, Deleted::Removed));
            http::empty(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            crate::error!("delete_failed", "blob": hash.hex(), "error": format!("{e:#}"));
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The blob couldn't be deleted",
            )
        }
    }
}

/// BUD-12: a pubkey's blobs, newest first, paged by `cursor` (the last
/// blob of the previous page) and `limit`; `since`/`until` too.
pub fn list(app: &'static App, req: &Request<Incoming>, pubkey: &str) -> Response<Body> {
    if !app.config.list.enabled {
        return error(StatusCode::NOT_FOUND, "Listing blobs is turned off here");
    }
    if let Err((status, why)) = token(app, req.headers(), "list", app.config.list.require_auth) {
        return error(status, why);
    }
    let Some(pk) = hex::decode(pubkey)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
    else {
        return error(StatusCode::BAD_REQUEST, "That isn't a hex pubkey");
    };
    let mut cursor = None;
    let (mut limit, mut since, mut until) = (100usize, None, None);
    for pair in req
        .uri()
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|p| !p.is_empty())
    {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let bad = || error(StatusCode::BAD_REQUEST, "A query parameter isn't valid");
        match k {
            "cursor" => match Hash::parse(v.as_bytes()) {
                Some(h) => cursor = Some(h),
                None => return bad(),
            },
            "limit" => match v.parse::<usize>() {
                Ok(n) => limit = n.clamp(1, 1000),
                Err(_) => return bad(),
            },
            "since" => match v.parse() {
                Ok(n) => since = Some(n),
                Err(_) => return bad(),
            },
            "until" => match v.parse() {
                Ok(n) => until = Some(n),
                Err(_) => return bad(),
            },
            _ => {}
        }
    }
    match app.store.list(&pk, cursor.as_ref(), limit, since, until) {
        Ok(recs) => http::json(
            StatusCode::OK,
            &Value::Array(
                recs.iter()
                    .filter(|r| !r.has(crate::store::flag::SUSPENDED))
                    .map(|r| descriptor(app, r))
                    .collect(),
            ),
        ),
        Err(e) => {
            crate::error!("list_failed", "error": format!("{e:#}"));
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The list couldn't be read",
            )
        }
    }
}

/// BUD-09: a signed NIP-56 report (kind 1984) naming blobs by `x` tags.
pub async fn report(app: &'static App, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
    if !app.config.report.enabled {
        return error(StatusCode::NOT_FOUND, "Reports are turned off here");
    }
    if !app.upload_limit.allow(client_ip(app, &req, peer)) {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests; try again in a minute",
        );
    }
    let body = match http_body_util::Limited::new(req.into_body(), 64 << 10)
        .collect()
        .await
    {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Reports may be at most 64 KiB",
            );
        }
    };
    let (id, hashes) = match crate::auth::verify_report(&body) {
        Ok(v) => v,
        Err(reason) => return error(StatusCode::BAD_REQUEST, reason),
    };
    match app.writer.report(hashes.clone(), id, body.to_vec()).await {
        Ok(()) => {
            crate::info!("reported", "blobs": hashes.iter().map(Hash::hex).collect::<Vec<_>>(), "event": hex::encode(id));
            http::empty(StatusCode::OK)
        }
        Err(e) => {
            crate::error!("report_failed", "error": format!("{e:#}"));
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The report couldn't be kept",
            )
        }
    }
}
