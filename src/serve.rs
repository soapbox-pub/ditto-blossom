//! GET and HEAD of a blob: negotiation, conditional requests, ranges, and
//! the body, inline or from a mapping that sendfile(2) sends.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};

use crate::app::App;
use crate::hash::Hash;
use crate::http::{self, error};
use crate::mime;
use crate::server::Body;

pub async fn blob(app: &'static App, req: &Request<Incoming>, hash: Hash) -> Response<Body> {
    let head = req.method() == Method::HEAD;
    let headers = req.headers();
    let range = headers.get(header::RANGE);
    // A range is of the blob's own bytes, so a request for one gets those.
    let prefer_brotli = range.is_none() && http::accepts(headers, "br");
    let found = match app.store.find(&hash, prefer_brotli) {
        Ok(Some(f)) => f,
        Ok(None) => return error(StatusCode::NOT_FOUND, "Blob not found"),
        Err(e) => {
            crate::error!("find_failed", "blob": hash.hex(), "error": format!("{e:#}"));
            return error(StatusCode::INTERNAL_SERVER_ERROR, "The database couldn't be read");
        }
    };
    app.access.touch(found.seq);
    let rec = &found.record;
    let ty = rec.mime.as_deref();
    let negotiable = mime::compressible(ty) || rec.has(crate::store::flag::BROTLI);
    let etag = if found.brotli { format!("\"{}-br\"", hash.hex()) } else { format!("\"{}\"", hash.hex()) };

    let mut builder = Response::builder()
        .header(header::ETAG, &etag)
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(header::LAST_MODIFIED, httpdate::fmt_http_date(std::time::UNIX_EPOCH + std::time::Duration::from_secs(rec.uploaded)));
    if negotiable {
        builder = builder.header(header::VARY, "Accept-Encoding");
    }
    if http::none_match(headers, &etag) {
        return builder.status(StatusCode::NOT_MODIFIED).body(Full::new(Bytes::new())).expect("valid headers");
    }

    let size = if found.brotli { rec.br_size } else { rec.size };
    let mut status = StatusCode::OK;
    let mut window = (0, size);
    builder = builder
        .header(header::CONTENT_TYPE, HeaderValue::from_str(ty.unwrap_or("application/octet-stream")).unwrap_or(HeaderValue::from_static("application/octet-stream")))
        .header(header::ACCEPT_RANGES, "bytes")
        .header("x-content-type-options", "nosniff");
    if found.brotli {
        builder = builder.header(header::CONTENT_ENCODING, "br");
    }
    if let Some(r) = range.filter(|_| http::if_range(headers, &etag)) {
        match http::parse_range(r.as_bytes(), size) {
            None => {}
            Some(Err(())) => {
                let mut e = error(StatusCode::RANGE_NOT_SATISFIABLE, "Range not satisfiable");
                e.headers_mut().insert(header::CONTENT_RANGE, HeaderValue::from_str(&format!("bytes */{size}")).expect("ascii"));
                return e;
            }
            Some(Ok((first, last))) => {
                status = StatusCode::PARTIAL_CONTENT;
                window = (first, last + 1);
                builder = builder.header(header::CONTENT_RANGE, format!("bytes {first}-{last}/{size}"));
            }
        }
    }
    builder = builder.status(status).header(header::CONTENT_LENGTH, window.1 - window.0);
    if head {
        return builder.body(Full::new(Bytes::new())).expect("valid headers");
    }

    let bytes = match found.body {
        Some(b) => b,
        None => match body(app, found.seq, hash, found.brotli).await {
            Ok(b) => b,
            Err(e) => {
                crate::error!("blob_unreadable", "blob": hash.hex(), "brotli": found.brotli, "error": e.to_string());
                return error(StatusCode::INTERNAL_SERVER_ERROR, "The blob couldn't be read");
            }
        },
    };
    if bytes.len() as u64 != size {
        crate::error!("blob_size_mismatch", "blob": hash.hex(), "brotli": found.brotli, "recorded": size, "actual": bytes.len());
        return error(StatusCode::INTERNAL_SERVER_ERROR, "The blob couldn't be read");
    }
    // A slice of a registered mapping is still recognised, so ranges go by
    // sendfile too.
    let bytes = bytes.slice(window.0 as usize..window.1 as usize);
    builder.body(Full::new(bytes)).expect("valid headers")
}

/// A file blob's mapping: from the cache, or mapped on the blocking pool,
/// as opening and mapping may wait on the disk.
async fn body(app: &'static App, seq: u64, hash: Hash, brotli: bool) -> std::io::Result<Bytes> {
    if let Some(b) = app.files.cached(seq, brotli) {
        return Ok(b);
    }
    tokio::task::spawn_blocking(move || app.files.map(seq, &hash, brotli)).await.map_err(std::io::Error::other)?
}
