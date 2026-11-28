//! End-to-end: the admin dashboard's sign-in, lookups, bans and evidence.

use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, HOST, SET_COOKIE};
use serde_json::{Value, json};

use super::{Server, client, start};
use crate::auth::tests::{http_auth, keypair, signed, token};
use crate::hash::Hash;
use crate::upload::now;

/// A server whose admin is `admin`, and its dashboard's address.
async fn with_dashboard(admin: &secp256k1::Keypair, extra: &str) -> (Server, String) {
    dashboard(admin, extra, "http").await
}

/// `with_dashboard`, its `admin.url` given with `scheme`, as if TLS were
/// ended in front of it.
async fn dashboard(admin: &secp256k1::Keypair, extra: &str, scheme: &str) -> (Server, String) {
    let pk = hex::encode(admin.x_only_public_key().0.to_byte_array());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let s = start(&format!(
        "[admin]\npubkeys = [\"{pk}\"]\nurl = \"{scheme}://{addr}\"\n{extra}"
    ))
    .await;
    let app = s.app;
    tokio::spawn(crate::server::serve(
        listener,
        move |req, peer| crate::admin::handle(app, req, peer),
        tokio_util::sync::CancellationToken::new(),
    ));
    (s, format!("http://{addr}"))
}

/// Sign in as `kp`: the session cookie, or the refusal's status.
async fn sign_in(url: &str, kp: &secp256k1::Keypair) -> Result<String, StatusCode> {
    let r = client()
        .post(format!("{url}/api/login"))
        .header(
            AUTHORIZATION,
            http_auth(kp, &format!("{url}/api/login"), "POST", now()),
        )
        .send()
        .await
        .unwrap();
    if r.status() != StatusCode::OK {
        return Err(r.status());
    }
    let cookie = r.headers()[SET_COOKIE].to_str().unwrap();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    assert!(!cookie.contains("Secure"), "signed in over http");
    Ok(cookie.split(';').next().unwrap().to_string())
}

#[tokio::test]
async fn only_admins_sign_in_and_only_once_per_event() {
    let (admin, stranger) = (keypair(), keypair());
    let (_s, url) = with_dashboard(&admin, "").await;
    let c = client();

    // The page and its script are there for anyone; the API isn't.
    let page = c.get(format!("{url}/")).send().await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let csp = page.headers()["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert!(!csp.contains("unsafe-inline"));
    for asset in ["admin.js", "admin.css"] {
        assert_eq!(
            c.get(format!("{url}/{asset}"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        c.get(format!("{url}/api/stats"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    assert_eq!(
        sign_in(&url, &stranger).await.unwrap_err(),
        StatusCode::FORBIDDEN
    );
    let cookie = sign_in(&url, &admin).await.unwrap();
    let me: Value = c
        .get(format!("{url}/api/session"))
        .header(COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        me["pubkey"],
        hex::encode(admin.x_only_public_key().0.to_byte_array())
    );

    // An event for another URL, or one already used, doesn't sign anyone in.
    // (Made a second earlier than sign_in's, which it would otherwise equal.)
    let login = format!("{url}/api/login");
    let used = http_auth(&admin, &login, "POST", now() - 1);
    let post = |h: String| c.post(&login).header(AUTHORIZATION, h).send();
    assert_eq!(post(used.clone()).await.unwrap().status(), StatusCode::OK);
    assert_eq!(post(used).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    // An event signed for another site's sign-in is refused, whatever Host
    // it's sent with.
    for host in [None, Some("example.com")] {
        let elsewhere = http_auth(&admin, "http://example.com/api/login", "POST", now());
        let mut r = c.post(&login).header(AUTHORIZATION, elsewhere);
        if let Some(h) = host {
            r = r.header(HOST, h);
        }
        assert_eq!(r.send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    // At an https address, with TLS ended in front, the cookie is never sent
    // over plain http, and an event for the plain http address is refused.
    let (_tls, at) = dashboard(&admin, "", "https").await;
    let login = format!("{at}/api/login");
    let post = |h: String| c.post(&login).header(AUTHORIZATION, h).send();
    let plain = http_auth(&admin, &login, "POST", now());
    assert_eq!(
        post(plain).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let tls = http_auth(&admin, &login.replacen("http:", "https:", 1), "POST", now());
    let r = post(tls).await.unwrap();
    assert!(
        r.headers()[SET_COOKIE]
            .to_str()
            .unwrap()
            .ends_with("; Secure")
    );

    // A change isn't taken as a form post, and signing out ends the session.
    let r = c
        .post(format!("{url}/api/ban"))
        .header(COOKIE, &cookie)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("blobs=x")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let out = c
        .post(format!("{url}/api/logout"))
        .header(COOKIE, &cookie)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), StatusCode::OK);
    assert_eq!(
        c.get(format!("{url}/api/stats"))
            .header(COOKIE, &cookie)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn looks_up_and_bans_blobs_and_uploaders() {
    let (admin, uploader, reporter) = (keypair(), keypair(), keypair());
    let evidence = tempfile::tempdir().unwrap();
    let (s, url) = with_dashboard(
        &admin,
        &format!("preserve = {:?}\n", evidence.path().to_str().unwrap()),
    )
    .await;
    let c = client();
    let cookie = sign_in(&url, &admin).await.unwrap();
    let get = |path: &str| {
        let r = c.get(format!("{url}{path}")).header(COOKIE, &cookie).send();
        async move { r.await.unwrap().json::<Value>().await.unwrap() }
    };
    let post = |path: &str, body: Value| {
        let r = c
            .post(format!("{url}{path}"))
            .header(COOKIE, &cookie)
            .json(&body)
            .send();
        async move { r.await.unwrap() }
    };

    // Two blobs by one uploader, one of them reported.
    let upload = |data: &'static [u8]| {
        c.put(format!("{}/upload", s.url))
            .header(
                AUTHORIZATION,
                token(
                    &uploader,
                    "upload",
                    &[Hash::of(data)],
                    Some("127.0.0.1"),
                    now() + 600,
                    now() - 1,
                ),
            )
            .body(data)
            .send()
    };
    let (a, b): (&[u8], &[u8]) = (b"first blob", b"second blob");
    for data in [a, b] {
        assert_eq!(upload(data).await.unwrap().status(), StatusCode::CREATED);
    }
    let (ha, hb) = (Hash::of(a).hex(), Hash::of(b).hex());
    let report = signed(
        &reporter,
        1984,
        vec![vec!["x".into(), ha.clone(), "illegal".into()]],
        "bad",
    );
    let r = c
        .put(format!("{}/report", s.url))
        .body(report)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());

    let stats = get("/api/stats").await;
    assert_eq!(
        (stats["blobs"].as_u64(), stats["reports"].as_u64()),
        (Some(2), Some(1))
    );
    let reports = get("/api/reports").await;
    assert_eq!(reports[0]["sha256"], ha);
    assert_eq!(reports[0]["type"], "illegal");
    assert_eq!(reports[0]["stored"], true);

    let up = hex::encode(uploader.x_only_public_key().0.to_byte_array());
    let blob = get(&format!("/api/blob/{ha}")).await;
    assert_eq!(blob["stored"]["size"], a.len());
    assert_eq!(blob["owners"], json!([up]));
    assert_eq!(blob["reports"].as_array().unwrap().len(), 1);
    assert!(blob["ban"].is_null());
    // The overview adds up what's stored, and who stored it.
    let o = get("/api/overview").await;
    assert_eq!(
        (o["files"].as_u64(), o["uploaders"].as_u64()),
        (Some(2), Some(1))
    );
    assert_eq!(o["bytes"], a.len() + b.len());
    assert_eq!(o["top"][0]["pubkey"], up);
    assert_eq!(o["top"][0]["files"], 2);
    assert_eq!(o["days"].as_array().unwrap().len(), 90);
    assert_eq!(o["days"][89]["files"], 2);
    // And in full, for Usage: by type, by size, by when last read, by month.
    let u = get("/api/usage").await;
    assert_eq!(u["types"][0]["files"], 2);
    assert_eq!(u["sizes"][0]["files"], 2, "both under 10 KB");
    assert_eq!(u["reads"][5]["files"], 2, "neither read yet");
    assert_eq!(u["months"].as_array().unwrap().len(), 1);
    assert_eq!(u["months"][0]["new_uploaders"], 1);
    assert_eq!(u["spread"][1]["uploaders"], 1, "one uploader with 2 files");
    assert_eq!(u["shared"]["saved"], 0);

    let who = get(&format!("/api/pubkey/{up}")).await;
    assert_eq!(who["owned"], 2);
    assert_eq!(who["blobs"].as_array().unwrap().len(), 2);

    // Banned as CSAM, the reported blob goes, kept, and its uploader is
    // banned, their other blobs suspended and recorded as its context.
    let r = post("/api/csam", json!({ "sha256": ha })).await;
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value = r.json().await.unwrap();
    assert_eq!(
        (v["kept"].as_u64(), v["uploaders"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(
        v["urls"].as_array().unwrap().len(),
        4,
        "two addresses a blob"
    );
    let dir = evidence.path();
    assert_eq!(std::fs::read(dir.join(&ha)).unwrap(), a);
    assert!(!dir.join(&hb).exists(), "suspended, so kept where it was");
    let context: Value =
        serde_json::from_slice(&std::fs::read(dir.join(format!("{hb}.json"))).unwrap()).unwrap();
    assert_eq!(context["context_of"], json!([ha]));
    assert_eq!(context["suspended"], true);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(dir.metadata().unwrap().permissions().mode() & 0o777, 0o700);
    for h in [&ha, &hb] {
        let gone = c.get(format!("{}/{h}", s.url)).send().await.unwrap();
        assert_eq!(gone.status(), StatusCode::NOT_FOUND);
    }
    assert_eq!(
        get(&format!("/api/blob/{ha}")).await["ban"]["reason"],
        "CSAM"
    );
    assert_eq!(
        upload(b"anything").await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let bans = get("/api/bans").await;
    assert_eq!(
        bans.as_array().unwrap().len(),
        2,
        "the blob and its uploader"
    );

    // It's listed as evidence until a CyberTipline report is noted on it.
    assert_eq!(get("/api/stats").await["unreported"], 1);
    let kept = get("/api/evidence").await;
    let items = kept["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["sha256"], ha);
    assert_eq!(items[0]["owners"], json!([up]));
    assert_eq!(items[0]["reports"].as_array().unwrap().len(), 1);
    assert_eq!(items[0]["context"], 1);
    assert!(items[0]["reported"].is_null());
    let r = post(
        "/api/evidence/reported",
        json!({ "sha256": ha, "report": " " }),
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let r = post(
        "/api/evidence/reported",
        json!({ "sha256": ha, "report": "123456" }),
    )
    .await;
    assert_eq!(r.json::<Value>().await.unwrap(), json!({ "noted": 2 }));
    assert_eq!(get("/api/stats").await["unreported"], 0);
    let item = &get("/api/evidence").await["items"][0];
    assert_eq!(item["reported"]["id"], "123456");

    // A record that won't read is passed over, not the end of the dashboard.
    std::fs::write(dir.join("torn.json"), b"{\"sha256\": \"ab").unwrap();
    assert_eq!(get("/api/stats").await["evidence"], 1);
    assert_eq!(
        get("/api/evidence").await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    std::fs::remove_file(dir.join("torn.json")).unwrap();

    // A blob that isn't stored has nothing to keep, but its hash is banned,
    // so it can't be uploaded.
    let never = Hash::of(b"never").hex();
    let r = post("/api/csam", json!({ "sha256": never })).await;
    assert_eq!(
        r.json::<Value>().await.unwrap(),
        json!({ "kept": 0, "uploaders": 0, "urls": [] })
    );
    assert_eq!(
        get(&format!("/api/blob/{never}")).await["ban"]["reason"],
        "CSAM"
    );
    assert_eq!(get("/api/stats").await["unreported"], 0);

    // A ban needs a target, but no reason; unbanning lifts it.
    let r = post("/api/ban", json!({ "blobs": [hb] })).await;
    assert_eq!(r.status(), StatusCode::OK);
    let r = post("/api/ban", json!({ "reason": "nothing named" })).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let r = post("/api/unban", json!({ "pubkeys": [up] })).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(get(&format!("/api/pubkey/{up}")).await["ban"].is_null());
    assert_eq!(
        upload(b"anything").await.unwrap().status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn keeps_evidence_in_data_unless_told_elsewhere() {
    let admin = keypair();
    let (s, url) = with_dashboard(&admin, "").await;
    let c = client();
    let cookie = sign_in(&url, &admin).await.unwrap();
    let h = super::put(s.app, b"a blob", None).hex();
    let r = c
        .post(format!("{url}/api/csam"))
        .header(COOKIE, &cookie)
        .json(&json!({ "sha256": h }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let dir = s.app.config.evidence();
    assert!(dir.ends_with("evidence"));
    assert_eq!(std::fs::read(dir.join(&h)).unwrap(), b"a blob");
    // Plain bans keep nothing, and can't be asked to.
    let h2 = super::put(s.app, b"another", None).hex();
    let ban = |body: Value| {
        c.post(format!("{url}/api/ban"))
            .header(COOKIE, &cookie)
            .json(&body)
            .send()
    };
    assert_eq!(
        ban(json!({ "blobs": [h2], "reason": "x", "preserve": true }))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    // A ban says where a cache in front may still hold what it removed:
    // by the hash alone, and with the extension its URL has.
    let banned: Value = ban(json!({ "blobs": [h2] }))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(banned["removed"], 1);
    assert_eq!(
        banned["urls"],
        json!([format!("{}/{h2}.bin", s.url), format!("{}/{h2}", s.url)])
    );
    assert!(!dir.join(&h2).exists());
}

/// A noisy PNG of one colour, as an upload of a picture would be.
fn png(colour: [u8; 3]) -> Vec<u8> {
    let mut seed = 7u32;
    let img = image::RgbImage::from_fn(96, 96, |_, _| {
        image::Rgb(colour.map(|c| {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            c.saturating_add((seed >> 28) as u8)
        }))
    });
    let mut out = std::io::Cursor::new(Vec::new());
    img.write_to(&mut out, image::ImageFormat::Png).unwrap();
    out.into_inner()
}

#[tokio::test]
async fn lists_scores_labels_and_removes_media() {
    let admin = keypair();
    let dir = tempfile::tempdir().unwrap();
    let (labels, embeddings) = (dir.path().join("labels.json"), dir.path().join("emb.jsonl"));
    let (s, url) = with_dashboard(
        &admin,
        &format!(
            "cdn = \"Cloudflare\"\nlabels = {:?}\nembeddings = {:?}\n[scan]\nenabled = true\nmodel = \"test:red\"\nthreshold = 0.5\n",
            labels.to_str().unwrap(),
            embeddings.to_str().unwrap()
        ),
    )
    .await;
    let c = client();
    let cookie = sign_in(&url, &admin).await.unwrap();
    let get = |path: String| {
        let r = c.get(format!("{url}{path}")).header(COOKIE, &cookie).send();
        async move { r.await.unwrap().json::<Value>().await.unwrap() }
    };
    let post = |path: &str, body: Value| {
        let r = c
            .post(format!("{url}{path}"))
            .header(COOKIE, &cookie)
            .json(&body)
            .send();
        async move { r.await.unwrap() }
    };

    let red = super::put(s.app, &png([230, 20, 20]), Some("image/png")).hex();
    let grey = super::put(s.app, &png([128, 128, 128]), Some("image/png")).hex();
    let text = super::put(s.app, b"just text", Some("text/plain")).hex();
    // An encrypted attachment, declared what it was before it was encrypted.
    let sealed: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let sealed = super::put(s.app, &sealed, Some("image/webp")).hex();
    // The cache in front is the one the config names; none is looked for.
    let stats = get("/api/stats".into()).await;
    assert_eq!(stats["cdn"], "Cloudflare");
    assert_eq!(stats["labelling"], true);
    let hashes = |page: &Value| -> Vec<String> {
        page["blobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["sha256"].as_str().unwrap().to_string())
            .collect()
    };

    // Browsing goes by the declared type, newest first, reading no files:
    // the browser drops what it can't show.
    let page = get("/api/media".into()).await;
    assert_eq!(hashes(&page), [sealed.as_str(), &grey, &red]);
    assert!(page["next"].is_null());

    // Thumbnails: a JPEG of a picture, made here, to a signed-in admin; and
    // none of the attachment that claims to be one, or of text.
    let thumb = |hex: &str, query: &str, signed_in: bool| {
        let mut r = c.get(format!("{url}/api/thumb/{hex}{query}"));
        if signed_in {
            r = r.header(COOKIE, &cookie);
        }
        async move { r.send().await.unwrap() }
    };
    let r = thumb(&grey, "?side=1280", true).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["content-type"], "image/jpeg");
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert!(image::load_from_memory(&r.bytes().await.unwrap()).is_ok());
    assert_eq!(
        thumb(&grey, "", false).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        thumb(&grey, "?side=9", true).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        thumb(&sealed, "", true).await.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(
        thumb(&text, "", true).await.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    // Review goes by what the bytes are, so the attachment isn't offered;
    // and found fine there, a blob isn't offered again.
    let fresh = get("/api/media?new=1".into()).await;
    assert_eq!(hashes(&fresh), [grey.as_str(), &red]);
    assert_eq!(fresh["blobs"][0]["media"], "image/png");
    let r = post("/api/reviewed", json!({ "blobs": [grey] })).await;
    assert_eq!(r.json::<Value>().await.unwrap(), json!({ "reviewed": 1 }));
    let fresh = get("/api/media?new=1".into()).await;
    assert_eq!(hashes(&fresh), [red.as_str()]);
    assert_eq!(
        get("/api/media?kind=all".into()).await["blobs"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        get("/api/media?kind=video".into()).await["blobs"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let scored = get(format!("/api/score/{red}")).await;
    assert_eq!(scored["refused"], true);
    assert_eq!(get(format!("/api/score/{grey}")).await["refused"], false);

    // Labels go into the labels file, embeddings into the cache.
    let r = post("/api/label", json!({ "blobs": [red], "label": "explicit" })).await;
    assert_eq!(r.json::<Value>().await.unwrap(), json!({ "labelled": 1 }));
    let r = post("/api/label", json!({ "blobs": [grey], "label": "clean" })).await;
    assert_eq!(r.status(), StatusCode::OK);
    let file: Value = serde_json::from_slice(&std::fs::read(&labels).unwrap()).unwrap();
    assert_eq!(
        file,
        json!({ red.clone(): "explicit", grey.clone(): "clean" })
    );
    let cache = std::fs::read_to_string(&embeddings).unwrap();
    assert_eq!(cache.lines().count(), 3, "a header and a line a blob");
    assert!(cache.contains(&red) && cache.contains(&grey));
    let page = get("/api/media".into()).await;
    assert_eq!(page["blobs"][2]["label"], "explicit");
    let r = post("/api/label", json!({ "blobs": [red], "label": "maybe" })).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let r = post("/api/label", json!({ "blobs": [text], "label": "clean" })).await;
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "nothing to learn from in text"
    );

    // Removing takes it out without banning it.
    let r = post("/api/remove", json!({ "blobs": [grey] })).await;
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["removed"], 1);
    assert_eq!(v["urls"][0], format!("{}/{grey}.png", s.url));
    assert_eq!(
        c.get(format!("{}/{grey}", s.url))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(get(format!("/api/blob/{grey}")).await["ban"].is_null());
    // Its thumbnail, made before, isn't shown once it's gone.
    assert_eq!(
        thumb(&grey, "?side=1280", true).await.status(),
        StatusCode::NOT_FOUND
    );

    // Banned as CSAM, a blob leaves the labels and the embeddings, and
    // can't be labelled again.
    let r = post("/api/csam", json!({ "sha256": red })).await;
    assert_eq!(r.status(), StatusCode::OK);
    let file: Value = serde_json::from_slice(&std::fs::read(&labels).unwrap()).unwrap();
    assert!(file.get(&red).is_none());
    assert_eq!(file[&grey], "clean");
    let cache = std::fs::read_to_string(&embeddings).unwrap();
    assert!(!cache.contains(&red) && cache.contains(&grey));
    let r = post("/api/label", json!({ "blobs": [red], "label": "explicit" })).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(
        r.headers()["x-reason"]
            .to_str()
            .unwrap()
            .contains("banned as CSAM")
    );
}
