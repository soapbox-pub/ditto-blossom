//! End-to-end: scanning uploads against a stand-in for Arachnid Shield.

use std::collections::HashSet;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use http_body_util::BodyExt;
use reqwest::StatusCode;
use serde_json::{Value, json};

use super::{client, start};
use crate::auth::tests::{keypair, token};
use crate::hash::Hash;
use crate::store::Banned;
use crate::upload::now;

const BAD: &[u8] = include_bytes!("../../tests/pdq/bridge-1-original.jpg");

/// Shield, as far as these tests need: `bad` hashes are CSAM, and it can be
/// made to fail.
struct Mock {
    url: String,
    bad: std::sync::Mutex<HashSet<String>>,
    down: AtomicBool,
    asked: AtomicUsize,
}

async fn mock() -> Arc<Mock> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let m = Arc::new(Mock {
        url: format!("http://{}", listener.local_addr().unwrap()),
        bad: Default::default(),
        down: AtomicBool::new(false),
        asked: AtomicUsize::new(0),
    });
    let state = m.clone();
    tokio::spawn(crate::server::serve(
        listener,
        move |req: hyper::Request<hyper::body::Incoming>, _| {
            let m = state.clone();
            async move {
                m.asked.fetch_add(1, Ordering::SeqCst);
                if m.down.load(Ordering::SeqCst) {
                    return crate::http::error(StatusCode::SERVICE_UNAVAILABLE, "down");
                }
                // "user:secret", as the credentials file says.
                if req.headers().get("authorization").map(|v| v.as_bytes())
                    != Some(b"Basic dXNlcjpzZWNyZXQ=")
                {
                    return crate::http::error(StatusCode::UNAUTHORIZED, "who?");
                }
                assert_eq!(req.uri().path(), "/v1/pdq");
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let asked: Value = serde_json::from_slice(&body).unwrap();
                let bad = m.bad.lock().unwrap();
                let mut out = serde_json::Map::new();
                for h in asked["hashes"].as_array().unwrap() {
                    let h = h.as_str().unwrap();
                    let v = match bad.contains(h) {
                        true => json!({"classification": "csam", "match_type": "near",
                            "near_match_details": [{"timestamp": 0.0, "sha1_base32": "X",
                            "sha256_hex": "AB", "classification": "csam"}]}),
                        false => json!({"classification": "no-known-match"}),
                    };
                    out.insert(h.to_string(), v);
                }
                crate::http::json(StatusCode::OK, &json!({ "scanned_hashes": out }))
            }
        },
        tokio_util::sync::CancellationToken::new(),
    ));
    m
}

fn pdq_of(data: &[u8]) -> String {
    crate::pdq::of(Cursor::new(data)).unwrap().unwrap().base64()
}

/// A small PNG, unlike any other `seed` gives.
fn png(seed: u32) -> Vec<u8> {
    let img = image::RgbImage::from_fn(64, 64, |x, y| {
        let v = ((x * (seed + 3) + y * y * (seed + 1)) % 256) as u8;
        image::Rgb([v, v.wrapping_mul(3), 255 - v])
    });
    let mut out = Vec::new();
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
        .unwrap();
    out
}

struct Setup {
    s: super::Server,
    shield: Arc<Mock>,
    evidence: tempfile::TempDir,
    alerts: std::path::PathBuf,
    _etc: tempfile::TempDir,
}

async fn setup(extra: &str) -> Setup {
    setup_scanning(extra, "").await
}

/// `setup`, with `scan` added to its `[scan]`.
async fn setup_scanning(extra: &str, scan: &str) -> Setup {
    let shield = mock().await;
    shield.bad.lock().unwrap().insert(pdq_of(BAD));
    let etc = tempfile::tempdir().unwrap();
    let creds = etc.path().join("shield");
    std::fs::write(&creds, "user:secret\n").unwrap();
    let alerts = etc.path().join("alerts");
    let evidence = tempfile::tempdir().unwrap();
    let s = start(&format!(
        "{extra}\n[scan]\nenabled = true\nshield_url = {:?}\ncredentials_file = {:?}\nevidence = {:?}\n\
         alert_command = [\"sh\", \"-c\", \"cat >> {}\"]\n{scan}",
        shield.url,
        creds.to_str().unwrap(),
        evidence.path().to_str().unwrap(),
        alerts.display(),
    ))
    .await;
    Setup {
        s,
        shield,
        evidence,
        alerts,
        _etc: etc,
    }
}

fn auth(kp: &secp256k1::Keypair, x: &[Hash]) -> String {
    token(kp, "upload", x, Some("127.0.0.1"), now() + 600, now() - 1)
}

fn pk(kp: &secp256k1::Keypair) -> [u8; 32] {
    kp.x_only_public_key().0.to_byte_array()
}

/// Each incident directory under `evidence`, oldest first, with its record.
fn incidents(evidence: &std::path::Path) -> Vec<(std::path::PathBuf, Value)> {
    let mut dirs: Vec<_> = std::fs::read_dir(evidence)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    dirs.sort_by_key(|d| (d.as_os_str().len(), d.clone()));
    dirs.into_iter()
        .map(|d| {
            let record =
                serde_json::from_slice(&std::fs::read(d.join("record.json")).unwrap()).unwrap();
            (d, record)
        })
        .collect()
}

/// The one incident directory under `evidence`, and its record.
fn incident(evidence: &std::path::Path) -> (std::path::PathBuf, Value) {
    let mut all = incidents(evidence);
    assert_eq!(all.len(), 1, "{all:?}");
    all.remove(0)
}

#[tokio::test]
async fn a_match_is_kept_out_preserved_and_its_uploader_banned() {
    let t = setup("").await;
    let (s, c) = (&t.s, client());
    let (bad, other) = (keypair(), keypair());
    let upload = |kp: &secp256k1::Keypair, data: &[u8]| {
        c.put(format!("{}/upload", s.url))
            .header("authorization", auth(kp, &[Hash::of(data)]))
            .body(data.to_vec())
            .send()
    };
    let get = |h: Hash| c.get(format!("{}/{}", s.url, h.hex())).send();

    // Clean images and non-images are kept; only images are asked about.
    let earlier = png(1);
    assert_eq!(
        upload(&bad, &earlier).await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(t.shield.asked.load(Ordering::SeqCst), 1);
    assert_eq!(
        upload(&other, b"just text").await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(t.shield.asked.load(Ordering::SeqCst), 1);

    // The match: refused, and never served.
    let r = upload(&bad, BAD).await.unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        get(Hash::of(BAD)).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );

    // Preserved, with the uploader's other blob, which is gone too.
    let (dir, record) = incident(t.evidence.path());
    assert_eq!(
        std::fs::read(dir.join("blobs").join(Hash::of(BAD).hex())).unwrap(),
        BAD
    );
    assert_eq!(
        std::fs::read(dir.join("blobs").join(Hash::of(&earlier).hex())).unwrap(),
        earlier
    );
    assert_eq!(
        get(Hash::of(&earlier)).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(Hash::of(b"just text")).await.unwrap().status(),
        StatusCode::OK
    );
    assert!(!s.app.store.is_banned(None, Some(&pk(&other))).unwrap());

    // The record says who, from where, and what Shield said.
    assert_eq!(record["blob"], Hash::of(BAD).hex());
    assert_eq!(record["via"], "upload");
    assert_eq!(record["uploaders"], json!([hex::encode(pk(&bad))]));
    assert_eq!(record["banned_uploaders"], json!([hex::encode(pk(&bad))]));
    assert_eq!(record["ip"], "127.0.0.1");
    assert_eq!(record["shield"]["classification"], "csam");
    assert_eq!(record["pdq"], pdq_of(BAD));
    assert_eq!(record["removed"], json!([Hash::of(&earlier).hex()]));
    assert_eq!(record["problems"], json!([]));

    // The alert got the record.
    let alert: Value = serde_json::from_slice(&std::fs::read(&t.alerts).unwrap()).unwrap();
    assert_eq!(alert["blob"], Hash::of(BAD).hex());

    // Banned: the key, and the blob for anyone.
    assert!(s.app.store.is_banned(None, Some(&pk(&bad))).unwrap());
    assert_eq!(
        upload(&bad, &png(2)).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    // Another key sending the same image is a match of its own: its own
    // record, beside the first, and banned too.
    assert_eq!(
        upload(&other, BAD).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let all = incidents(t.evidence.path());
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].1["uploaders"], json!([hex::encode(pk(&bad))]));
    assert_eq!(all[1].1["uploaders"], json!([hex::encode(pk(&other))]));
    assert_eq!(all[1].1["removed"], json!([Hash::of(b"just text").hex()]));
    assert!(s.app.store.is_banned(None, Some(&pk(&other))).unwrap());

    // Everyone else is unaffected.
    let third = keypair();
    assert_eq!(
        upload(&third, &png(3)).await.unwrap().status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn an_outage_keeps_uploads_and_asks_again() {
    let t = setup("").await;
    let (s, c) = (&t.s, client());
    let kp = keypair();
    t.shield.down.store(true, Ordering::SeqCst);
    let r = c
        .put(format!("{}/upload", s.url))
        .header("authorization", auth(&kp, &[Hash::of(BAD)]))
        .body(BAD.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    assert_eq!(s.app.store.unscanned(10).unwrap(), vec![Hash::of(BAD)]);

    // Still down: it stays queued.
    let scanner = s.app.shield.as_ref().unwrap();
    assert!(
        crate::scan::known::retry_round(s.app, scanner)
            .await
            .is_err()
    );
    assert_eq!(s.app.store.unscanned(10).unwrap().len(), 1);

    t.shield.down.store(false, Ordering::SeqCst);
    crate::scan::known::retry_round(s.app, scanner)
        .await
        .unwrap();
    assert!(s.app.store.unscanned(10).unwrap().is_empty());
    let r = c
        .get(format!("{}/{}", s.url, Hash::of(BAD).hex()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let (dir, record) = incident(t.evidence.path());
    assert_eq!(record["via"], "retry");
    assert_eq!(record["uploaders"], json!([hex::encode(pk(&kp))]));
    assert_eq!(
        std::fs::read(dir.join("blobs").join(Hash::of(BAD).hex())).unwrap(),
        BAD
    );
    assert!(
        s.app
            .store
            .is_banned(Some(&Hash::of(BAD)), Some(&pk(&kp)))
            .unwrap()
    );

    // A clean one kept in an outage leaves the queue, and stays.
    t.shield.down.store(true, Ordering::SeqCst);
    let clean = png(7);
    let r = c
        .put(format!("{}/upload", s.url))
        .header("authorization", auth(&keypair(), &[Hash::of(&clean)]))
        .body(clean.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    t.shield.down.store(false, Ordering::SeqCst);
    crate::scan::known::retry_round(s.app, scanner)
        .await
        .unwrap();
    assert!(s.app.store.unscanned(10).unwrap().is_empty());
    let r = c
        .get(format!("{}/{}", s.url, Hash::of(&clean).hex()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn exempt_keys_lose_the_blob_but_not_the_key() {
    let kp = keypair();
    let t = setup(&format!(
        "[upload]\nexempt = [\"{}\"]",
        hex::encode(pk(&kp))
    ))
    .await;
    let (s, c) = (&t.s, client());
    let r = c
        .put(format!("{}/upload", s.url))
        .header("authorization", auth(&kp, &[Hash::of(BAD)]))
        .body(BAD.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let (_, record) = incident(t.evidence.path());
    assert_eq!(record["banned_uploaders"], json!([]));
    let bans = s.app.store.bans().unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].target, Banned::Blob(Hash::of(BAD)));
}

#[tokio::test]
async fn shield_is_asked_before_explicit_media_is_refused() {
    let red = |seed: u32| {
        let img = image::RgbImage::from_fn(64, 64, |x, y| {
            image::Rgb([255, ((x * seed + y * 7) % 64) as u8, 0])
        });
        let mut out = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    };
    let (matched, explicit) = (red(3), red(5));
    let t = setup_scanning("", "model = \"test:red\"\nthreshold = 0.5\n").await;
    t.shield.bad.lock().unwrap().insert(pdq_of(&matched));
    let (s, c) = (&t.s, client());
    let kp = keypair();
    let upload = |data: &[u8]| {
        c.put(format!("{}/upload", s.url))
            .header("authorization", auth(&kp, &[Hash::of(data)]))
            .body(data.to_vec())
            .send()
    };

    // Explicit and known: dealt with as CSAM, not merely refused.
    assert_eq!(
        upload(&matched).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let (dir, _) = incident(t.evidence.path());
    assert!(dir.join("blobs").join(Hash::of(&matched).hex()).exists());
    let ban = s
        .app
        .store
        .read(|txn| s.app.store.ban_of(txn, Banned::Blob(Hash::of(&matched))))
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(ban.reason.starts_with("CSAM"), "{}", ban.reason);

    // Explicit only: refused by its score, with no incident. (The uploader
    // is banned by now, so another key sends it.)
    let other = keypair();
    let r = c
        .put(format!("{}/upload", s.url))
        .header("authorization", auth(&other, &[Hash::of(&explicit)]))
        .body(explicit.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(incidents(t.evidence.path()).len(), 1);
    let ban = s
        .app
        .store
        .read(|txn| s.app.store.ban_of(txn, Banned::Blob(Hash::of(&explicit))))
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(ban.reason.starts_with("scan"), "{}", ban.reason);
}
