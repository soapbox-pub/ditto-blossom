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
    /// The evidence folder: the data's own `evidence`.
    evidence: std::path::PathBuf,
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
    let s = start(&format!(
        "{extra}\n[scan]\nenabled = true\nshield_url = {:?}\ncredentials_file = {:?}\n\
         alert_command = [\"sh\", \"-c\", \"cat >> {}\"]\n{scan}",
        shield.url,
        creds.to_str().unwrap(),
        alerts.display(),
    ))
    .await;
    let evidence = s.app.config.evidence();
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

/// The evidence kept of a blob: its record, and its copy if one was made.
fn kept(evidence: &std::path::Path, h: Hash) -> (Value, Option<Vec<u8>>) {
    let rec =
        serde_json::from_slice(&std::fs::read(evidence.join(format!("{}.json", h.hex()))).unwrap())
            .unwrap();
    (rec, std::fs::read(evidence.join(h.hex())).ok())
}

/// The blobs banned as CSAM, as the dashboard's Evidence lists them.
fn flagged(evidence: &std::path::Path) -> Vec<Value> {
    crate::moderate::evidence(evidence)
        .unwrap()
        .into_iter()
        .filter(|r| r["context_of"].as_array().is_none_or(Vec::is_empty))
        .collect()
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

    // Preserved in the evidence folder, as the dashboard keeps CSAM; the
    // uploader's other blob suspended: hidden, kept in place, and recorded
    // as its context.
    let (record, copy) = kept(&t.evidence, Hash::of(BAD));
    assert_eq!(copy.unwrap(), BAD);
    let (context, copy) = kept(&t.evidence, Hash::of(&earlier));
    assert!(copy.is_none());
    assert_eq!(context["context_of"], json!([Hash::of(BAD).hex()]));
    assert_eq!(context["suspended"], true);
    assert_eq!(flagged(&t.evidence).len(), 1);
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
    assert_eq!(record["sha256"], Hash::of(BAD).hex());
    assert_eq!(record["size"], BAD.len());
    assert_eq!(record["owners"], json!([hex::encode(pk(&bad))]));
    assert!(
        record["reason"]
            .as_str()
            .unwrap()
            .starts_with("CSAM: Arachnid Shield csam (near)")
    );
    assert!(record["reported"].is_null());
    let d = &record["detections"][0];
    assert_eq!(d["by"], "Arachnid Shield");
    assert_eq!(d["via"], "upload");
    assert_eq!(d["uploaders"], json!([hex::encode(pk(&bad))]));
    assert_eq!(d["ip"], "127.0.0.1");
    assert_eq!(d["classification"], "csam");
    assert_eq!(d["match_type"], "near");
    assert_eq!(d["pdq"], pdq_of(BAD));
    assert_eq!(d["problems"], json!([]));

    // The alert says the same, and what the ban did.
    let alert: Value = serde_json::from_slice(&std::fs::read(&t.alerts).unwrap()).unwrap();
    assert_eq!(alert["blob"], Hash::of(BAD).hex());
    assert_eq!(alert["banned_uploaders"], json!([hex::encode(pk(&bad))]));
    assert_eq!(alert["suspended"], json!([Hash::of(&earlier).hex()]));
    assert_eq!(alert["detection"]["ip"], "127.0.0.1");

    // Banned: the key, and the blob for anyone.
    assert!(s.app.store.is_banned(None, Some(&pk(&bad))).unwrap());
    assert_eq!(
        upload(&bad, &png(2)).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    // Another key sending the same image is a match of its own: noted on
    // the same record, beside the first, and banned too.
    assert_eq!(
        upload(&other, BAD).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let (record, _) = kept(&t.evidence, Hash::of(BAD));
    assert_eq!(
        record["owners"],
        json!([hex::encode(pk(&bad)), hex::encode(pk(&other))])
    );
    let ds = record["detections"].as_array().unwrap();
    assert_eq!(ds.len(), 2);
    assert_eq!(ds[1]["uploaders"], json!([hex::encode(pk(&other))]));
    assert_eq!(flagged(&t.evidence).len(), 1);
    let (context, _) = kept(&t.evidence, Hash::of(b"just text"));
    assert_eq!(context["suspended"], true);
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
    let (record, copy) = kept(&t.evidence, Hash::of(BAD));
    assert_eq!(copy.unwrap(), BAD);
    assert_eq!(record["owners"], json!([hex::encode(pk(&kp))]));
    assert_eq!(record["detections"][0]["via"], "retry");
    assert_eq!(
        record["detections"][0]["uploaders"],
        json!([hex::encode(pk(&kp))])
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
    let alert: Value = serde_json::from_slice(&std::fs::read(&t.alerts).unwrap()).unwrap();
    assert_eq!(alert["banned_uploaders"], json!([]));
    assert_eq!(kept(&t.evidence, Hash::of(BAD)).1.unwrap(), BAD);
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
    assert!(kept(&t.evidence, Hash::of(&matched)).1.is_some());
    let ban = s
        .app
        .store
        .read(|txn| s.app.store.ban_of(txn, Banned::Blob(Hash::of(&matched))))
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(ban.reason.starts_with("CSAM"), "{}", ban.reason);

    // Explicit only: refused by its score, kept as no evidence. (The uploader
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
    assert_eq!(flagged(&t.evidence).len(), 1);
    let ban = s
        .app
        .store
        .read(|txn| s.app.store.ban_of(txn, Banned::Blob(Hash::of(&explicit))))
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(ban.reason.starts_with("scan"), "{}", ban.reason);
}
