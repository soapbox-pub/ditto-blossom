//! End-to-end: uploads, deletes, lists, reports, mirrors, compression.

use std::time::Duration;

use reqwest::StatusCode;
use serde_json::Value;

use super::{client, put, start};
use crate::auth::tests::{keypair, signed, token};
use crate::hash::Hash;
use crate::upload::now;

fn auth(kp: &secp256k1::Keypair, verb: &str, x: &[Hash]) -> String {
    token(kp, verb, x, Some("127.0.0.1"), now() + 600, now() - 1)
}

#[tokio::test]
async fn uploads_dedupes_and_refuses() {
    let s = start("").await;
    let c = client();
    let kp = keypair();
    let upload = |data: Vec<u8>, auth: Option<String>| {
        let mut r = c.put(format!("{}/upload", s.url)).body(data);
        if let Some(a) = auth {
            r = r.header("authorization", a);
        }
        r
    };
    let small = b"a small blob".to_vec();
    let large: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 256) as u8).collect();
    for data in [&small, &large] {
        let h = Hash::of(data);
        let r = upload(data.clone(), Some(auth(&kp, "upload", &[h])))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        let d: Value = r.json().await.unwrap();
        assert_eq!(d["sha256"], h.hex());
        assert_eq!(d["size"], data.len());
        assert_eq!(d["url"], format!("{}/{}.bin", s.url, h.hex()));
        let got = c
            .get(d["url"].as_str().unwrap())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(&got[..], &data[..]);
        // Again, and again with X-SHA-256 so the body isn't even read.
        let r = upload(data.clone(), Some(auth(&kp, "upload", &[h])))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let r = upload(data.clone(), Some(auth(&kp, "upload", &[h])))
            .header("x-sha-256", h.hex())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }
    // A PNG's type comes from its bytes when the client doesn't say.
    let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR and so on".to_vec();
    let r = upload(png.clone(), Some(auth(&kp, "upload", &[Hash::of(&png)])))
        .send()
        .await
        .unwrap();
    let d: Value = r.json().await.unwrap();
    assert_eq!(d["type"], "image/png");
    assert!(d["url"].as_str().unwrap().ends_with(".png"));

    let other = b"other bytes".to_vec();
    let r = upload(other.clone(), None).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = upload(
        other.clone(),
        Some(auth(&kp, "upload", &[Hash::of(b"else")])),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = upload(other.clone(), Some(auth(&kp, "upload", &[])))
        .header("x-sha-256", Hash::of(b"else").hex())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let r = upload(other, Some(auth(&kp, "delete", &[])))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let head = || {
        c.head(format!("{}/upload", s.url))
            .header("authorization", auth(&kp, "upload", &[]))
    };
    assert_eq!(
        head().send().await.unwrap().status(),
        StatusCode::LENGTH_REQUIRED
    );
    assert_eq!(
        head()
            .header("x-content-length", "99999999999")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        head()
            .header("x-content-length", "100")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn deletes_lists_and_reports() {
    let s = start("[list]\nenabled = true\n").await;
    let c = client();
    let (alice, bob) = (keypair(), keypair());
    let data: Vec<u8> = (0..100_000u32).map(|i| (i % 13) as u8).collect();
    let h = Hash::of(&data);
    for kp in [&alice, &bob] {
        let r = c
            .put(format!("{}/upload", s.url))
            .header("authorization", auth(kp, "upload", &[h]))
            .body(data.clone())
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());
    }
    let alice_hex = hex::encode(alice.x_only_public_key().0.to_byte_array());
    let list = || async {
        c.get(format!("{}/list/{alice_hex}", s.url))
            .send()
            .await
            .unwrap()
            .json::<Vec<Value>>()
            .await
            .unwrap()
    };
    let listed = list().await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["sha256"], h.hex());

    let delete = |kp: &secp256k1::Keypair| {
        c.delete(format!("{}/{}", s.url, h.hex()))
            .header("authorization", auth(kp, "delete", &[h]))
            .send()
    };
    assert_eq!(
        delete(&keypair()).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete(&alice).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    // Bob still owns it.
    assert_eq!(
        c.get(format!("{}/{}", s.url, h.hex()))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(list().await.is_empty());
    let path = s.app.files.path(&h, false);
    assert!(path.exists());
    assert_eq!(delete(&bob).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(
        c.get(format!("{}/{}", s.url, h.hex()))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(!path.exists(), "the file goes with its last owner");

    let report = signed(
        &alice,
        1984,
        vec![vec!["x".into(), h.hex(), "spam".into()]],
        "spam",
    );
    assert_eq!(
        c.put(format!("{}/report", s.url))
            .body(report)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let r = c
        .put(format!("{}/report", s.url))
        .body("{\"kind\":1984}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn compresses_in_the_background_and_negotiates() {
    let s = start("").await;
    let c = client();
    let kp = keypair();
    let js: Vec<u8> = (0..4000)
        .flat_map(|i| format!("function f{i}(a) {{ return a * {i} + 1; }}\n").into_bytes())
        .collect();
    let h = Hash::of(&js);
    let r = c
        .put(format!("{}/upload", s.url))
        .header("authorization", auth(&kp, "upload", &[h]))
        .header("content-type", "text/javascript")
        .body(js.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let url = format!("{}/{}.js", s.url, h.hex());

    // gzip on the spot for a client that takes gzip and not brotli.
    let r = c
        .get(&url)
        .header("accept-encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["content-encoding"], "gzip");
    assert_eq!(r.headers()["etag"], format!("\"{}-gz\"", h.hex()));
    let z = r.bytes().await.unwrap();
    let mut plain = vec![0; js.len()];
    let n = libdeflater::Decompressor::new()
        .gzip_decompress(&z, &mut plain)
        .unwrap();
    assert_eq!(&plain[..n], &js[..]);

    let mut br = None;
    for _ in 0..200 {
        let r = c
            .get(&url)
            .header("accept-encoding", "gzip, br")
            .send()
            .await
            .unwrap();
        if r.headers()
            .get("content-encoding")
            .is_some_and(|v| v == "br")
        {
            br = Some(r.bytes().await.unwrap());
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let br = br.expect("a brotli copy within 10 s");
    assert!(br.len() < js.len() / 4);
    let mut plain = Vec::new();
    brotli::BrotliDecompress(&mut &br[..], &mut plain).unwrap();
    assert_eq!(plain, js);
    // Its own bytes to whoever asks for nothing, and for a range.
    let r = c.get(&url).send().await.unwrap();
    assert!(r.headers().get("content-encoding").is_none());
    assert_eq!(r.bytes().await.unwrap(), js);
    let r = c
        .get(&url)
        .header("accept-encoding", "br")
        .header("range", "bytes=0-9")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(r.bytes().await.unwrap(), js[..10]);
}

#[tokio::test]
async fn mirrors_and_limits() {
    let origin = start("").await;
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 199) as u8).collect();
    let h = put(origin.app, &data, Some("image/webp"));
    let src = format!("{}/{}.webp", origin.url, h.hex());
    let c = client();
    let kp = keypair();
    let body = serde_json::json!({ "url": src }).to_string();

    // A server that won't fetch from local addresses.
    let strict = start("").await;
    let r = c
        .put(format!("{}/mirror", strict.url))
        .header(
            "authorization",
            token(&kp, "upload", &[h], None, now() + 60, now()),
        )
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let s = start("[mirror]\nallow_private = true\n[upload]\nper_minute = 3\n").await;
    let mirror = |x: Hash| {
        c.put(format!("{}/mirror", s.url))
            .header("authorization", auth(&kp, "upload", &[x]))
            .body(body.clone())
            .send()
    };
    assert_eq!(
        mirror(Hash::of(b"something else")).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    let r = mirror(h).await.unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let d: Value = r.json().await.unwrap();
    assert_eq!(d["type"], "image/webp");
    assert_eq!(
        c.get(d["url"].as_str().unwrap())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
        data
    );
    // The third of three a minute: here already. The fourth: too many.
    assert_eq!(mirror(h).await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        mirror(h).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn bans_keep_blobs_and_uploaders_out() {
    use crate::store::Banned;

    let s = start("[mirror]\nallow_private = true\n").await;
    let c = client();
    let (bad, good) = (keypair(), keypair());
    let pk = |kp: &secp256k1::Keypair| kp.x_only_public_key().0.to_byte_array();
    let upload = |kp: &secp256k1::Keypair, data: &[u8]| {
        c.put(format!("{}/upload", s.url))
            .header("authorization", auth(kp, "upload", &[Hash::of(data)]))
            .body(data.to_vec())
    };
    let get = |h: Hash| c.get(format!("{}/{}", s.url, h.hex())).send();
    let small = b"banned small blob".to_vec();
    let large: Vec<u8> = (0..300_000u32).map(|i| (i * 13 % 256) as u8).collect();
    let kept = b"someone else's blob".to_vec();
    for data in [&small, &large] {
        assert_eq!(
            upload(&bad, data).send().await.unwrap().status(),
            StatusCode::CREATED
        );
    }
    assert_eq!(
        upload(&good, &kept).send().await.unwrap().status(),
        StatusCode::CREATED
    );

    let kept_copies = tempfile::tempdir().unwrap();
    crate::moderate::ban_in(
        s.app.store,
        s.app.files,
        &[Banned::Pubkey(pk(&bad))],
        "csam",
        Some(kept_copies.path()),
    )
    .unwrap();
    // Preserved first, inline and file alike.
    for data in [&small, &large] {
        let copy = std::fs::read(kept_copies.path().join(Hash::of(data).hex())).unwrap();
        assert_eq!(&copy, data);
    }

    // Its blobs are gone, files and all, and banned; others' aren't.
    for data in [&small, &large] {
        assert_eq!(
            get(Hash::of(data)).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }
    assert!(!s.app.files.path(&Hash::of(&large), false).exists());
    assert_eq!(get(Hash::of(&kept)).await.unwrap().status(), StatusCode::OK);
    assert_eq!(s.app.store.bans().unwrap().len(), 3);

    // The banned key can't upload anything, even new bytes.
    let r = upload(&bad, b"anything new").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        r.headers()["x-reason"],
        "This blob, or its uploader, is banned here"
    );

    // Another key can't put its blobs back: refused before the body with
    // X-SHA-256, by the writer without it, and at the BUD-06 preflight.
    for data in [&small, &large] {
        let h = Hash::of(data);
        let r = upload(&good, data)
            .header("x-sha-256", h.hex())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let r = upload(&good, data).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let r = c
            .head(format!("{}/upload", s.url))
            .header("authorization", auth(&good, "upload", &[h]))
            .header("x-sha-256", h.hex())
            .header("x-content-length", data.len().to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(get(h).await.unwrap().status(), StatusCode::NOT_FOUND);
    }

    // Nor mirror them in from elsewhere.
    let origin = start("").await;
    let h = put(origin.app, &large, None);
    let body = serde_json::json!({ "url": format!("{}/{}", origin.url, h.hex()) }).to_string();
    let mirror = |kp: &secp256k1::Keypair, x: Hash| {
        c.put(format!("{}/mirror", s.url))
            .header("authorization", auth(kp, "upload", &[x]))
            .body(body.clone())
            .send()
    };
    assert_eq!(
        mirror(&good, h).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        mirror(&bad, Hash::of(&kept)).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(get(h).await.unwrap().status(), StatusCode::NOT_FOUND);

    // Lifting the key's ban lets it upload again; its old blobs stay banned.
    crate::moderate::unban_in(s.app.store, &[Banned::Pubkey(pk(&bad))]).unwrap();
    assert_eq!(
        upload(&bad, b"anything new").send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&bad, &small).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}
