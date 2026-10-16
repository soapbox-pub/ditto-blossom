//! End-to-end: a real server on a loopback port, talked to over HTTP.

use std::io::Write;
use std::sync::atomic::Ordering;

use reqwest::StatusCode;

use crate::app::App;
use crate::config::Config;
use crate::hash::Hash;
use crate::store::{INLINE_MAX, Record, flag};

pub struct Server {
    pub app: &'static App,
    pub url: String,
    _dir: tempfile::TempDir,
}

/// A server on a free port, its config amended by `extra` (TOML).
pub async fn start(extra: &str) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let toml = format!(
        "data = {:?}\npublic_url = \"http://{addr}\"\n{extra}",
        dir.path().to_str().unwrap()
    );
    let app = App::open(Config::parse(&toml).unwrap()).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    tokio::spawn(crate::server::serve(
        listener,
        move |req, peer| crate::routes::handle(app, req, peer),
        shutdown,
    ));
    Server {
        app,
        url: format!("http://{addr}"),
        _dir: dir,
    }
}

/// Store a blob directly, as an upload would, returning its hash.
pub fn put(app: &'static App, data: &[u8], mime: Option<&str>) -> Hash {
    let hash = Hash::of(data);
    let small = data.len() <= INLINE_MAX;
    if !small {
        let mut tmp = app.files.temp().unwrap();
        tmp.file().write_all(data).unwrap();
        app.files.place(tmp, &hash, false).unwrap();
        app.files.sync().unwrap();
    }
    let mut txn = app.store.write_txn().unwrap();
    let seq = app.store.next_seq(&txn).unwrap();
    let rec = Record {
        hash,
        size: data.len() as u64,
        uploaded: 1_760_000_000,
        mime: mime.map(String::from),
        flags: if small { flag::INLINE } else { 0 },
        br_size: 0,
    };
    app.store
        .insert(&mut txn, seq, &rec, small.then_some(data))
        .unwrap();
    txn.commit().unwrap();
    hash
}

pub fn client() -> reqwest::Client {
    crate::install_crypto();
    reqwest::Client::builder().no_proxy().build().unwrap()
}

#[tokio::test]
async fn serves_small_and_large_blobs() {
    let s = start("").await;
    let small = b"hello, blossom".to_vec();
    let large: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let hs = put(s.app, &small, Some("text/plain"));
    let hl = put(s.app, &large, Some("video/mp4"));
    let c = client();

    let r = c
        .get(format!("{}/{}.txt", s.url, hs.hex()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["content-type"], "text/plain");
    assert_eq!(r.headers()["etag"], format!("\"{}\"", hs.hex()));
    assert_eq!(r.headers()["access-control-allow-origin"], "*");
    assert_eq!(r.headers()["vary"], "Accept-Encoding");
    assert_eq!(r.bytes().await.unwrap(), small);

    let before = crate::server::SENT.load(Ordering::Relaxed);
    let r = c
        .get(format!("{}/{}", s.url, hl.hex()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.headers().get("vary").is_none());
    assert_eq!(r.bytes().await.unwrap(), large);
    let sent = crate::server::SENT.load(Ordering::Relaxed) - before;
    assert!(
        sent >= large.len() as u64,
        "only {sent} bytes went by sendfile"
    );

    // Once more, now from the cache of mappings, and a range of it.
    let r = c
        .get(format!("{}/{}", s.url, hl.hex()))
        .header("range", "bytes=1000000-1999999")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        r.headers()["content-range"],
        "bytes 1000000-1999999/3000000"
    );
    assert_eq!(r.bytes().await.unwrap(), large[1_000_000..2_000_000]);
}

#[tokio::test]
async fn head_conditional_ranges_and_errors() {
    let s = start("").await;
    let data: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
    let h = put(s.app, &data, None);
    let c = client();
    let url = format!("{}/{}.bin", s.url, h.hex());

    let r = c.head(&url).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["content-length"], "50000");
    assert_eq!(r.headers()["content-type"], "application/octet-stream");
    assert_eq!(r.headers()["accept-ranges"], "bytes");
    assert!(r.bytes().await.unwrap().is_empty());

    let r = c
        .get(&url)
        .header("if-none-match", format!("\"{}\"", h.hex()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_MODIFIED);

    let r = c
        .get(&url)
        .header("range", "bytes=-10")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(r.bytes().await.unwrap(), data[49_990..]);

    let r = c
        .get(&url)
        .header("range", "bytes=60000-")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(r.headers()["content-range"], "bytes */50000");

    // If-Range for another representation: the whole blob.
    let r = c
        .get(&url)
        .header("range", "bytes=0-9")
        .header("if-range", "\"other\"")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    let missing = Hash::of(b"missing").hex();
    let r = c.get(format!("{}/{missing}", s.url)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(r.headers()["x-reason"], "Blob not found");
    let r = c.head(format!("{}/{missing}", s.url)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert!(r.bytes().await.unwrap().is_empty(), "HEAD never has a body");

    let r = c
        .request(reqwest::Method::OPTIONS, format!("{}/upload", s.url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        r.headers()["access-control-allow-methods"],
        "GET, HEAD, PUT, DELETE"
    );

    let r = c.get(&s.url).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().await.unwrap().contains("<strong>1</strong> blobs"));

    let r = c.get(format!("{}/icon.png", s.url)).send().await.unwrap();
    assert_eq!(r.headers()["content-type"], "image/png");
}

mod writes;
