//! The endpoints that write: `PUT /upload` and its `HEAD` preflight
//! (BUD-02, BUD-06), `DELETE /<sha256>` and `GET /list/<pubkey>` (BUD-12),
//! `PUT /report` (BUD-09).

use std::net::SocketAddr;
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
use crate::server::Body;
use crate::store::Record;
use crate::writer::Deleted;

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
    if length > app.config.upload.max_size {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("Blobs may be at most {} bytes", app.config.upload.max_size),
        );
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
    if !app.upload_limit.allow(ip) {
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
        app.config.upload.max_size,
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
    store(app, blob, token.map(|t| t.pubkey), "upload").await
}

/// Keep an ingested blob and answer with its descriptor: 201 if it's new,
/// 200 if it was here (BUD-02, BUD-04).
pub async fn store(
    app: &'static App,
    blob: crate::writer::Ingested,
    owner: Option<[u8; 32]>,
    how: &str,
) -> Response<Body> {
    let (hash, size) = (blob.hash, blob.size);
    match app.writer.insert(blob, owner, now()).await {
        Ok(stored) => {
            if stored.created {
                crate::info!("stored", "via": how, "blob": hash.hex(), "size": size, "type": stored.record.mime);
                app.compressor.offer(&stored.record);
            }
            let status = if stored.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            http::json(status, &descriptor(app, &stored.record))
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
    if length > app.config.upload.max_size {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("Blobs may be at most {} bytes", app.config.upload.max_size),
        );
    }
    if let (Some(t), Some(c)) = (&token, &claimed)
        && !t.allows(c)
    {
        return error(StatusCode::FORBIDDEN, "The auth token isn't for this blob");
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
            &Value::Array(recs.iter().map(|r| descriptor(app, r)).collect()),
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
