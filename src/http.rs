//! Pieces of HTTP the routes share: error replies with `X-Reason`, JSON,
//! ranges, entity tags, and content-coding negotiation.

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Response, StatusCode};

use crate::server::Body;

/// A plain-text error whose reason is also in `X-Reason` (BUD-01).
pub fn error(status: StatusCode, reason: &str) -> Response<Body> {
    let reason: String = reason
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .collect();
    let mut r = Response::new(Full::new(Bytes::from(reason.clone())));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Ok(v) = HeaderValue::from_str(&reason) {
        h.insert("x-reason", v);
    }
    r
}

pub fn json(status: StatusCode, value: &serde_json::Value) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from(
        serde_json::to_vec(value).unwrap_or_default(),
    )));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

pub fn empty(status: StatusCode) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::new()));
    *r.status_mut() = status;
    r
}

/// A single `bytes=` range resolved against `size`: `Some(Ok((first, last)))`,
/// `Some(Err(()))` if it can't be satisfied, `None` if it isn't one this
/// server answers (several ranges, another unit, nonsense): those get the
/// whole blob, as RFC 9110 allows.
pub fn parse_range(v: &[u8], size: u64) -> Option<Result<(u64, u64), ()>> {
    let v = std::str::from_utf8(v).ok()?.trim().strip_prefix("bytes=")?;
    if v.contains(',') {
        return None;
    }
    let (a, b) = v.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    if size == 0 {
        return Some(Err(()));
    }
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 {
            return Some(Err(()));
        }
        return Some(Ok((size.saturating_sub(n), size - 1)));
    }
    let a: u64 = a.parse().ok()?;
    let b: u64 = if b.is_empty() {
        size - 1
    } else {
        b.parse::<u64>().ok()?.min(size - 1)
    };
    if a >= size || a > b {
        return Some(Err(()));
    }
    Some(Ok((a, b)))
}

/// Whether `If-None-Match` names `etag` (weakly, as RFC 9110 says it must be
/// compared), or is `*`.
pub fn none_match(headers: &HeaderMap, etag: &str) -> bool {
    let Some(v) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    v.split(',')
        .map(str::trim)
        .any(|t| t == "*" || t.strip_prefix("W/").unwrap_or(t) == etag)
}

/// Whether a `Range` should be honoured: there's no `If-Range`, or it names
/// this representation (strongly).
pub fn if_range(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_RANGE)
        .is_none_or(|v| v.as_bytes() == etag.as_bytes())
}

/// Whether `Accept-Encoding` takes `coding` (q above zero, by name or `*`).
pub fn accepts(headers: &HeaderMap, coding: &str) -> bool {
    let Some(v) = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let mut named = None;
    let mut star = None;
    for item in v.split(',') {
        let mut parts = item.split(';');
        let name = parts.next().unwrap_or("").trim();
        let q = parts
            .find_map(|p| {
                p.trim()
                    .strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
            })
            .unwrap_or(1.0);
        if name.eq_ignore_ascii_case(coding) {
            named = Some(q);
        } else if name == "*" {
            star = Some(q);
        }
    }
    named.or(star).is_some_and(|q| q > 0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range(b"bytes=0-99", 1000), Some(Ok((0, 99))));
        assert_eq!(parse_range(b"bytes=900-", 1000), Some(Ok((900, 999))));
        assert_eq!(parse_range(b"bytes=-100", 1000), Some(Ok((900, 999))));
        assert_eq!(parse_range(b"bytes=-5000", 1000), Some(Ok((0, 999))));
        assert_eq!(parse_range(b"bytes=990-5000", 1000), Some(Ok((990, 999))));
        assert_eq!(parse_range(b"bytes=1000-", 1000), Some(Err(())));
        assert_eq!(parse_range(b"bytes=5-2", 1000), Some(Err(())));
        assert_eq!(parse_range(b"bytes=-0", 1000), Some(Err(())));
        assert_eq!(parse_range(b"bytes=0-1,5-6", 1000), None);
        assert_eq!(parse_range(b"items=0-1", 1000), None);
        assert_eq!(parse_range(b"bytes=x-1", 1000), None);
    }

    #[test]
    fn negotiation() {
        let mut h = HeaderMap::new();
        assert!(!accepts(&h, "br"));
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        assert!(accepts(&h, "br") && accepts(&h, "gzip"));
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip;q=1.0, br;q=0"),
        );
        assert!(!accepts(&h, "br") && accepts(&h, "gzip"));
        h.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("*;q=0.5"));
        assert!(accepts(&h, "br"));
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        assert!(!accepts(&h, "gzip"));
    }

    #[test]
    fn entity_tags() {
        let mut h = HeaderMap::new();
        h.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("\"a\", W/\"b\""),
        );
        assert!(none_match(&h, "\"b\""));
        assert!(!none_match(&h, "\"c\""));
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(none_match(&h, "\"c\""));
        assert!(if_range(&HeaderMap::new(), "\"x\""));
    }
}
