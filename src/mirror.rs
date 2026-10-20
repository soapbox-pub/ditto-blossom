//! `PUT /mirror` (BUD-04): fetch a blob from another server and keep it.
//!
//! The URL is a client's, so the fetch only ever reaches public addresses:
//! names are resolved by a resolver that drops every other kind, literal
//! addresses are checked, and so is each redirect's. The download goes
//! through the same ingest as an upload, size limit included.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use crate::app::App;
use crate::http::error;
use crate::routes::client_ip;
use crate::server::Body;
use crate::upload::{ingest_error, store};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The whole fetch, however big the blob.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_REDIRECTS: usize = 3;

/// The client mirrors fetch with: public addresses only, unless
/// `allow_private`.
pub fn client(allow_private: bool) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .user_agent(concat!("ditto-blossom/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .no_proxy();
    if !allow_private {
        b = b.dns_resolver(Arc::new(PublicOnly));
    }
    b.redirect(reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            attempt.error("too many redirects")
        } else if !allow_private && !allowed(attempt.url()) {
            attempt.error("a redirect to an address that isn't public")
        } else {
            attempt.follow()
        }
    }))
    .build()
    .expect("the mirror client builds")
}

pub async fn mirror(app: &'static App, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
    if !app.config.mirror.enabled {
        return error(StatusCode::NOT_FOUND, "Mirroring is turned off here");
    }
    let token = match app
        .auth
        .check(req.headers(), "upload", crate::upload::now())
    {
        Err((status, reason)) => return error(status, reason),
        Ok(None) if app.config.upload.require_auth => {
            return error(
                StatusCode::UNAUTHORIZED,
                "This needs a Nostr auth token (BUD-11)",
            );
        }
        Ok(t) => t,
    };
    // A token naming one blob names what's coming: refuse it unfetched.
    let named = token.as_ref().and_then(|t| match t.x.as_slice() {
        [h] => Some(*h),
        _ => None,
    });
    if let Some(r) = crate::upload::refuse_banned(app, named.as_ref(), token.as_ref()) {
        return r;
    }
    if !app.upload_limit.allow(client_ip(app, &req, peer)) {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many uploads; try again in a minute",
        );
    }
    let body = match http_body_util::Limited::new(req.into_body(), 16 << 10)
        .collect()
        .await
    {
        Ok(b) => b.to_bytes(),
        Err(_) => return error(StatusCode::BAD_REQUEST, "The body should be {\"url\": …}"),
    };
    let Some(url) = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("url")?.as_str().map(String::from))
    else {
        return error(StatusCode::BAD_REQUEST, "The body should be {\"url\": …}");
    };
    let Ok(url) = reqwest::Url::parse(&url) else {
        return error(StatusCode::BAD_REQUEST, "That URL isn't valid");
    };
    if !matches!(url.scheme(), "http" | "https")
        || !(app.config.mirror.allow_private || allowed(&url))
    {
        return error(
            StatusCode::BAD_REQUEST,
            "Only public http(s) URLs can be mirrored",
        );
    }
    let Ok(_receiving) = app.receiving.try_acquire() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many uploads at once; try again shortly",
        );
    };

    let response = match app.http.get(url.clone()).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            return error(
                StatusCode::BAD_GATEWAY,
                &format!("The other server answered {}", r.status().as_u16()),
            );
        }
        Err(e) => {
            crate::info!("mirror_fetch_failed", "url": url.as_str(), "error": e.to_string());
            return error(StatusCode::BAD_GATEWAY, "The blob couldn't be fetched");
        }
    };
    let length = response.content_length();
    if length.is_some_and(|l| l > app.config.upload.max_size) {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "The blob is too large");
    }
    let declared_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let blob = match crate::ingest::ingest(
        app.files,
        response,
        length,
        app.config.upload.max_size,
        declared_type.as_deref(),
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return ingest_error(e),
    };
    // A mirror must name what it fetches (BUD-04, BUD-11): the URL alone
    // says nothing trustworthy about the bytes.
    if let Some(t) = &token
        && !t.names(&blob.hash)
    {
        return error(
            StatusCode::CONFLICT,
            "The fetched blob isn't the one the auth token names",
        );
    }
    store(app, blob, token.map(|t| t.pubkey), "mirror").await
}

/// Whether a URL's host may be fetched: a name (checked when it resolves),
/// or a public address.
fn allowed(url: &reqwest::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => {
            !d.eq_ignore_ascii_case("localhost") && !d.to_ascii_lowercase().ends_with(".localhost")
        }
        Some(url::Host::Ipv4(v4)) => public(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => public(IpAddr::V6(v6)),
        None => false,
    }
}

/// Resolves names to their public addresses only.
struct PublicOnly;

impl reqwest::dns::Resolve for PublicOnly {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|a| public(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{} has no public address", name.as_str()).into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Whether an address is on the public internet.
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            // NAT64 embeds an IPv4 address in its last 32 bits.
            if s[0] == 0x64 && s[1] == 0xff9b {
                return public(IpAddr::V4(std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                )));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses() {
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(!public(bad.parse().unwrap()), "{bad}");
        }
        for good in ["1.1.1.1", "8.8.8.8", "2606:4700::1111", "64:ff9b::101:101"] {
            assert!(public(good.parse().unwrap()), "{good}");
        }
        assert!(!allowed(&"http://localhost:3000/x".parse().unwrap()));
        assert!(!allowed(&"http://10.0.0.1/x".parse().unwrap()));
        assert!(!allowed(&"http://[::1]/x".parse().unwrap()));
        assert!(allowed(&"https://blossom.primal.net/abc".parse().unwrap()));
    }
}
