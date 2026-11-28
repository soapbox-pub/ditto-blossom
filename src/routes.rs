//! Requests to responses: the Blossom endpoints, the landing page, CORS.

use std::net::{IpAddr, SocketAddr};

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
use crate::upload;

const LANDING: &str = include_str!("../assets/index.html");
const FAVICON: &[u8] = include_bytes!("../assets/favicon.ico");
const ICON: &[u8] = include_bytes!("../assets/icon.png");
const BANNER: &[u8] = include_bytes!("../assets/banner.jpg");

pub async fn handle(app: &'static App, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
    let mut response = route(app, req, peer).await;
    let h = response.headers_mut();
    // BUD-01: every response, so browsers on any origin can read blobs.
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    h.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("X-Reason, Content-Length, Content-Range, Content-Encoding, ETag"),
    );
    response
}

async fn route(app: &'static App, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    if method == Method::OPTIONS {
        return preflight();
    }
    match (method, path.as_str()) {
        (Method::GET, "/") => landing(app),
        (Method::GET, "/favicon.ico") => asset("image/x-icon", FAVICON),
        (Method::GET, "/icon.png") => asset("image/png", ICON),
        (Method::GET, "/banner.jpg") => asset("image/jpeg", BANNER),
        (Method::PUT, "/upload") => upload::upload(app, req, peer).await,
        (Method::HEAD, "/upload") => upload::head_upload(app, &req),
        (Method::PUT, "/mirror") => crate::mirror::mirror(app, req, peer).await,
        (Method::PUT, "/report") => upload::report(app, req, peer).await,
        (Method::GET, "/moderation/decisions") => crate::peers::decisions(app, &req),
        (Method::PUT | Method::HEAD, "/media") => error(
            StatusCode::NOT_FOUND,
            "Media optimization (BUD-05) isn't offered here",
        ),
        (Method::GET, p) if p.starts_with("/list/") => {
            upload::list(app, &req, &p["/list/".len()..])
        }
        (Method::DELETE, p) => match blob_path(p) {
            Some(hash) => upload::delete(app, &req, hash).await,
            None => error(StatusCode::NOT_FOUND, "Not found"),
        },
        (Method::GET | Method::HEAD, p) => match blob_path(p) {
            Some(hash) => crate::serve::blob(app, &req, hash).await,
            None => error(StatusCode::NOT_FOUND, "Not found"),
        },
        _ => error(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed"),
    }
}

/// `/<sha256>` or `/<sha256>.<ext>`; the extension says nothing (BUD-01).
pub fn blob_path(path: &str) -> Option<Hash> {
    let name = path.strip_prefix('/')?;
    let (hex, ext) = name.split_at_checked(64)?;
    if !(ext.is_empty() || ext.starts_with('.') && !ext.contains('/')) {
        return None;
    }
    Hash::parse(hex.as_bytes())
}

fn preflight() -> Response<Body> {
    let mut r = http::empty(StatusCode::NO_CONTENT);
    let h = r.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Authorization, *"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, HEAD, PUT, DELETE"),
    );
    h.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
    r
}

fn landing(app: &'static App) -> Response<Body> {
    let count = app.store.count().unwrap_or(0);
    let page = LANDING
        .replace("{{public_url}}", &app.config.public_url)
        .replace("{{count}}", &group_digits(count))
        .replace("{{version}}", env!("CARGO_PKG_VERSION"));
    let mut r = Response::new(Full::new(Bytes::from(page)));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );
    r
}

fn asset(content_type: &'static str, bytes: &'static [u8]) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from_static(bytes)));
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    r
}

fn group_digits(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Who's asking: the socket's address, or, from a trusted proxy, the last
/// address in X-Forwarded-For that isn't a trusted proxy. Proxies append to
/// the header, so what's left of that is the client's to write.
pub fn client_ip(app: &App, req: &Request<Incoming>, peer: SocketAddr) -> IpAddr {
    let forwarded = req
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok());
    forwarded_for(&app.config.trusted_proxies, peer.ip(), forwarded)
}

fn forwarded_for<'a>(
    trusted: &[IpAddr],
    peer: IpAddr,
    headers: impl Iterator<Item = &'a str>,
) -> IpAddr {
    if !trusted.contains(&peer) {
        return peer;
    }
    let hops: Vec<&str> = headers.flat_map(|v| v.split(',')).collect();
    let mut client = peer;
    for hop in hops.iter().rev() {
        let Ok(ip) = hop.trim().parse::<IpAddr>() else {
            break;
        };
        client = ip;
        if !trusted.contains(&ip) {
            break;
        }
    }
    client
}

/// The URL a blob is served at, with the extension its type gets.
pub fn blob_url(app: &App, hash: &Hash, ty: Option<&str>) -> String {
    format!(
        "{}/{}.{}",
        app.config.public_url,
        hash.hex(),
        mime::extension(ty)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_paths() {
        let hex = Hash::of(b"x").hex();
        assert!(blob_path(&format!("/{hex}")).is_some());
        assert!(blob_path(&format!("/{hex}.png")).is_some());
        assert!(blob_path(&format!("/{hex}png")).is_none());
        assert!(blob_path(&format!("/{hex}.png/x")).is_none());
        assert!(blob_path(&format!("/x/{hex}")).is_none());
        assert!(blob_path("/upload").is_none());
        assert_eq!(group_digits(1376705), "1,376,705");
        assert_eq!(group_digits(12), "12");
    }

    #[test]
    fn forwarded_for_is_read_from_the_right() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let trusted = [ip("127.0.0.1"), ip("10.0.0.2")];
        let at = |peer: &str, h: &[&str]| forwarded_for(&trusted, ip(peer), h.iter().copied());
        // Whatever a client writes first is passed over for what was appended.
        assert_eq!(at("127.0.0.1", &["6.6.6.6, 1.2.3.4"]), ip("1.2.3.4"));
        assert_eq!(
            at("127.0.0.1", &["6.6.6.6", "1.2.3.4, 10.0.0.2"]),
            ip("1.2.3.4")
        );
        assert_eq!(at("127.0.0.1", &["junk, 1.2.3.4"]), ip("1.2.3.4"));
        assert_eq!(at("127.0.0.1", &[]), ip("127.0.0.1"));
        assert_eq!(at("127.0.0.1", &["10.0.0.2"]), ip("10.0.0.2"));
        // Not from a proxy: the header counts for nothing.
        assert_eq!(at("5.5.5.5", &["1.2.3.4"]), ip("5.5.5.5"));
    }
}
