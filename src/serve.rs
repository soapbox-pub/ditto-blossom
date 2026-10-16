//! GET and HEAD of a blob: negotiation, conditional requests, ranges, and
//! the body, inline or from a mapping that sendfile(2) sends.
//!
//! A blob is served as one of three representations, each with its own
//! entity tag: its own bytes; its brotli copy, to clients that take brotli;
//! or gzip made on the spot (level 1, 140 MB/s a core) for clients
//! that take gzip but not brotli, like Tor Browser on onion services. A
//! range is always of its own bytes.

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

/// Gzip on the spot only for blobs this size or smaller.
const GZIP_MAX: u64 = 16 << 20;
const GZIP_MIN: u64 = 512;

#[derive(Clone, Copy, PartialEq)]
enum Coding {
    Identity,
    Brotli,
    Gzip,
}

pub async fn blob(app: &'static App, req: &Request<Incoming>, hash: Hash) -> Response<Body> {
    let head = req.method() == Method::HEAD;
    let headers = req.headers();
    let range = headers.get(header::RANGE);
    let takes_br = http::accepts(headers, "br");
    let found = match app.store.find(&hash, range.is_none() && takes_br) {
        Ok(Some(f)) => f,
        Ok(None) => return error(StatusCode::NOT_FOUND, "Blob not found"),
        Err(e) => {
            crate::error!("find_failed", "blob": hash.hex(), "error": format!("{e:#}"));
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The database couldn't be read",
            );
        }
    };
    app.access.touch(found.seq);
    let rec = &found.record;
    let ty = rec.mime.as_deref();
    let compressible = mime::compressible(ty);
    let coding = if found.brotli {
        Coding::Brotli
    } else if range.is_none()
        && compressible
        && !takes_br
        && http::accepts(headers, "gzip")
        && (GZIP_MIN..=GZIP_MAX).contains(&rec.size)
    {
        Coding::Gzip
    } else {
        Coding::Identity
    };
    let tag = |c: Coding| match c {
        Coding::Identity => format!("\"{}\"", hash.hex()),
        Coding::Brotli => format!("\"{}-br\"", hash.hex()),
        Coding::Gzip => format!("\"{}-gz\"", hash.hex()),
    };
    let negotiable = compressible || found.brotli;
    let base = |etag: &str| {
        let mut b = Response::builder()
            .header(header::ETAG, etag)
            .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
            .header(
                header::LAST_MODIFIED,
                httpdate::fmt_http_date(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(rec.uploaded),
                ),
            );
        if negotiable {
            b = b.header(header::VARY, "Accept-Encoding");
        }
        b
    };
    if http::none_match(headers, &tag(coding)) {
        return base(&tag(coding))
            .status(StatusCode::NOT_MODIFIED)
            .body(Full::new(Bytes::new()))
            .expect("valid headers");
    }

    // The bytes, unless this is a HEAD whose length the record knows.
    let mut coding = coding;
    let mut bytes = None;
    if !head || coding == Coding::Gzip {
        let b = match found.body.clone() {
            Some(b) => b,
            None => match body(app, found.seq, hash, found.brotli).await {
                Ok(b) => b,
                Err(e) => {
                    crate::error!("blob_unreadable", "blob": hash.hex(), "brotli": found.brotli, "error": e.to_string());
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "The blob couldn't be read",
                    );
                }
            },
        };
        let expected = if found.brotli { rec.br_size } else { rec.size };
        if b.len() as u64 != expected {
            crate::error!("blob_size_mismatch", "blob": hash.hex(), "brotli": found.brotli, "recorded": expected, "actual": b.len());
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The blob couldn't be read",
            );
        }
        bytes = Some(b);
        if coding == Coding::Gzip {
            let raw = bytes.clone().expect("just read");
            match tokio::task::spawn_blocking(move || gzip(&raw))
                .await
                .ok()
                .flatten()
            {
                Some(z) => bytes = Some(z),
                None => coding = Coding::Identity,
            }
        }
    }

    let etag = tag(coding);
    let size = match (coding, &bytes) {
        (Coding::Brotli, _) => rec.br_size,
        (Coding::Gzip, Some(b)) => b.len() as u64,
        _ => rec.size,
    };
    let mut builder = base(&etag)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_str(ty.unwrap_or("application/octet-stream"))
                .unwrap_or(HeaderValue::from_static("application/octet-stream")),
        )
        .header(header::ACCEPT_RANGES, "bytes")
        .header("x-content-type-options", "nosniff");
    match coding {
        Coding::Brotli => builder = builder.header(header::CONTENT_ENCODING, "br"),
        Coding::Gzip => builder = builder.header(header::CONTENT_ENCODING, "gzip"),
        Coding::Identity => {}
    }
    let mut status = StatusCode::OK;
    let mut window = (0, size);
    if let Some(r) = range.filter(|_| http::if_range(headers, &etag)) {
        match http::parse_range(r.as_bytes(), size) {
            None => {}
            Some(Err(())) => {
                let mut e = error(StatusCode::RANGE_NOT_SATISFIABLE, "Range not satisfiable");
                e.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{size}")).expect("ascii"),
                );
                return e;
            }
            Some(Ok((first, last))) => {
                status = StatusCode::PARTIAL_CONTENT;
                window = (first, last + 1);
                builder = builder.header(
                    header::CONTENT_RANGE,
                    format!("bytes {first}-{last}/{size}"),
                );
            }
        }
    }
    builder = builder
        .status(status)
        .header(header::CONTENT_LENGTH, window.1 - window.0);
    let body = match (head, bytes) {
        (false, Some(b)) => b.slice(window.0 as usize..window.1 as usize),
        _ => Bytes::new(),
    };
    // A slice of a registered mapping is still recognised, so ranges go by
    // sendfile too.
    builder.body(Full::new(body)).expect("valid headers")
}

/// A file blob's mapping: from the cache, or mapped on the blocking pool,
/// as opening and mapping may wait on the disk.
async fn body(app: &'static App, seq: u64, hash: Hash, brotli: bool) -> std::io::Result<Bytes> {
    if let Some(b) = app.files.cached(seq, brotli) {
        return Ok(b);
    }
    let files = app.files;
    tokio::task::spawn_blocking(move || files.map(seq, &hash, brotli))
        .await
        .map_err(std::io::Error::other)?
}

/// Gzip level 1, if it saves at least 5%.
fn gzip(data: &[u8]) -> Option<Bytes> {
    let mut c = libdeflater::Compressor::new(libdeflater::CompressionLvl::new(1).ok()?);
    let mut out = vec![0; c.gzip_compress_bound(data.len())];
    let n = c.gzip_compress(data, &mut out).ok()?;
    if n as u64 > data.len() as u64 - data.len() as u64 / 20 {
        return None;
    }
    out.truncate(n);
    Some(Bytes::from(out))
}
