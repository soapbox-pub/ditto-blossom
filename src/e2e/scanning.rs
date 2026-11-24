//! End-to-end: refusing explicit media, with a stand-in model that calls
//! anything red explicit.

use std::io::Cursor;

use reqwest::StatusCode;

use super::{client, put, start};
use crate::auth::tests::{keypair, token};
use crate::hash::Hash;
use crate::upload::now;

const SCAN: &str = "[scan]\nenabled = true\nmodel = \"test:red\"\nthreshold = 0.5\nworkers = 2\n";
const RED: [u8; 3] = [230, 20, 20];
const GREY: [u8; 3] = [128, 128, 128];

/// Noisy pixels around a colour, so a PNG of them doesn't compress small.
fn noise(w: u32, h: u32, colour: impl Fn(u32, u32) -> [u8; 3]) -> image::RgbImage {
    let mut seed = 0x9e37_79b9u32;
    image::RgbImage::from_fn(w, h, |x, y| {
        let base = colour(x, y);
        image::Rgb(base.map(|c| {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            c.saturating_add((seed >> 28) as u8).saturating_sub(8)
        }))
    })
}

fn encode(img: &image::RgbImage, format: image::ImageFormat) -> Vec<u8> {
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, format).unwrap();
    out.into_inner()
}

fn auth(kp: &secp256k1::Keypair, x: &[Hash]) -> String {
    token(kp, "upload", x, Some("127.0.0.1"), now() + 600, now() - 1)
}

async fn upload(url: &str, kp: &secp256k1::Keypair, data: &[u8]) -> reqwest::Response {
    client()
        .put(format!("{url}/upload"))
        .header("authorization", auth(kp, &[Hash::of(data)]))
        // What a client says the type is counts for nothing.
        .header("content-type", "application/octet-stream")
        .body(data.to_vec())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn refuses_explicit_uploads_and_remembers_them() {
    let s = start(SCAN).await;
    let c = client();
    let kp = keypair();

    let red = encode(&noise(200, 200, |_, _| RED), image::ImageFormat::Png);
    assert!(red.len() > crate::store::INLINE_MAX, "a file, not inline");
    let h = Hash::of(&red);
    let r = upload(&s.url, &kp, &red).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(
        r.headers()["x-reason"]
            .to_str()
            .unwrap()
            .contains("Explicit")
    );
    let r = c
        .get(format!("{}/{}", s.url, h.hex()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "not stored");

    // Refused again from its hash alone: the preflight, and an upload
    // naming it.
    let r = c
        .head(format!("{}/upload", s.url))
        .header("authorization", auth(&kp, &[h]))
        .header("x-sha-256", h.hex())
        .header("x-content-length", red.len().to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = c
        .put(format!("{}/upload", s.url))
        .header("authorization", auth(&kp, &[h]))
        .header("x-sha-256", h.hex())
        .body(red.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // Small enough to be inline: scanned from memory, refused all the same.
    let small = encode(&noise(16, 16, |_, _| RED), image::ImageFormat::Png);
    assert!(small.len() <= crate::store::INLINE_MAX);
    assert_eq!(
        upload(&s.url, &kp, &small).await.status(),
        StatusCode::FORBIDDEN
    );

    // What isn't explicit, or isn't media at all, is kept.
    let grey = encode(&noise(300, 200, |_, _| GREY), image::ImageFormat::Jpeg);
    assert_eq!(
        upload(&s.url, &kp, &grey).await.status(),
        StatusCode::CREATED
    );
    let opaque: Vec<u8> = (0..100_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    assert_eq!(
        upload(&s.url, &kp, &opaque).await.status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn looks_at_every_frame_and_every_part() {
    let s = start(SCAN).await;
    let kp = keypair();

    // Grey for most of its length, red at the end.
    let mut gif = Vec::new();
    {
        let mut enc = image::codecs::gif::GifEncoder::new(&mut gif);
        let frames = (0..40).map(|i| {
            let c = if i < 32 { GREY } else { RED };
            image::Frame::new(image::RgbaImage::from_pixel(
                64,
                64,
                image::Rgba([c[0], c[1], c[2], 255]),
            ))
        });
        enc.encode_frames(frames).unwrap();
    }
    assert_eq!(
        upload(&s.url, &kp, &gif).await.status(),
        StatusCode::FORBIDDEN
    );

    // Red in a fifth of a square image is too little to matter...
    let square = noise(200, 200, |_, y| if y >= 160 { RED } else { GREY });
    let square = encode(&square, image::ImageFormat::Png);
    assert_eq!(
        upload(&s.url, &kp, &square).await.status(),
        StatusCode::CREATED
    );
    // ...but at the end of a long one, it's a piece of its own.
    let strip = noise(100, 500, |_, y| if y >= 400 { RED } else { GREY });
    let strip = encode(&strip, image::ImageFormat::Png);
    assert_eq!(
        upload(&s.url, &kp, &strip).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn refuses_what_it_cannot_read_unless_told_not_to() {
    let mut broken = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    broken.extend((0..30_000u32).map(|i| (i % 251) as u8));
    let kp = keypair();
    let s = start(SCAN).await;
    assert_eq!(
        upload(&s.url, &kp, &broken).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let lax = start(&format!("{SCAN}refuse_undecodable = false\n")).await;
    assert_eq!(
        upload(&lax.url, &kp, &broken).await.status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn refuses_mirrors_and_their_repeats() {
    let origin = start("").await;
    let red = encode(&noise(200, 200, |_, _| RED), image::ImageFormat::Png);
    let h = put(origin.app, &red, Some("image/png"));
    let body = serde_json::json!({ "url": format!("{}/{}.png", origin.url, h.hex()) }).to_string();
    let s = start(&format!("{SCAN}[mirror]\nallow_private = true\n")).await;
    let c = client();
    let kp = keypair();
    for _ in 0..2 {
        let r = c
            .put(format!("{}/mirror", s.url))
            .header("authorization", auth(&kp, &[h]))
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }
    // Uploaded directly, it's refused as soon as it's hashed, unscanned.
    assert_eq!(
        upload(&s.url, &kp, &red).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn refuses_explicit_video() {
    let dir = tempfile::tempdir().unwrap();
    let make = |colour: &str| {
        let path = dir.path().join(format!("{colour}.mp4"));
        let ok = std::process::Command::new("ffmpeg")
            .args(["-nostdin", "-loglevel", "error", "-f", "lavfi", "-i"])
            .arg(format!("color=c={colour}:s=160x120:d=8:r=10"))
            .args(["-c:v", "mpeg4", "-g", "10", "-y"])
            .arg(&path)
            .status()
            .is_ok_and(|s| s.success());
        ok.then(|| std::fs::read(path).unwrap())
    };
    let (Some(red), Some(grey)) = (make("red"), make("gray")) else {
        eprintln!("no ffmpeg: video untested");
        return;
    };
    let s = start(SCAN).await;
    let kp = keypair();
    assert_eq!(
        upload(&s.url, &kp, &red).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        upload(&s.url, &kp, &grey).await.status(),
        StatusCode::CREATED
    );

    // Sound with no picture, in a video container: nothing to judge.
    let voice = dir.path().join("voice.mp4");
    let ok = std::process::Command::new("ffmpeg")
        .args([
            "-nostdin",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "sine=f=440:d=2",
        ])
        .args(["-c:a", "aac", "-y"])
        .arg(&voice)
        .status()
        .unwrap();
    assert!(ok.success());
    let voice = std::fs::read(voice).unwrap();
    assert_eq!(
        upload(&s.url, &kp, &voice).await.status(),
        StatusCode::CREATED
    );
    // MP4's container under brands the sniffer doesn't know, or that say
    // it's sound, is still looked into: 3GP, as phones make, and M4A.
    let remux = |name: &str, args: &[&str]| {
        let path = dir.path().join(name);
        let ok = std::process::Command::new("ffmpeg")
            .args(["-nostdin", "-loglevel", "error", "-i"])
            .arg(dir.path().join("red.mp4"))
            .args(["-c", "copy"])
            .args(args)
            .arg("-y")
            .arg(&path)
            .status()
            .unwrap();
        assert!(ok.success(), "{name}");
        std::fs::read(path).unwrap()
    };
    for (name, args) in [
        ("red.3gp", &["-f", "3gp"][..]),
        ("red-m4a.mp4", &["-f", "mp4", "-brand", "M4A "][..]),
        ("red-odd.mp4", &["-f", "mp4", "-brand", "wxyz"][..]),
    ] {
        let data = remux(name, args);
        assert_eq!(&data[4..8], b"ftyp", "{name}");
        assert_eq!(
            upload(&s.url, &kp, &data).await.status(),
            StatusCode::FORBIDDEN,
            "{name}"
        );
    }
    let voice_3gp = dir.path().join("voice.3gp");
    let ok = std::process::Command::new("ffmpeg")
        .args(["-nostdin", "-loglevel", "error", "-f", "lavfi", "-i"])
        .arg("sine=f=440:d=2")
        .args(["-c:a", "aac", "-f", "3gp", "-y"])
        .arg(&voice_3gp)
        .status()
        .unwrap();
    assert!(ok.success());
    assert_eq!(
        upload(&s.url, &kp, &std::fs::read(voice_3gp).unwrap())
            .await
            .status(),
        StatusCode::CREATED
    );

    // A video container ffmpeg can't read at all is still refused.
    let mut broken = red.clone();
    broken.truncate(64);
    broken.extend(std::iter::repeat_n(0x5a, 4000));
    assert_eq!(
        upload(&s.url, &kp, &broken).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // Bytes that sniff as MP4 but probe as a DASH playlist aren't read as
    // one: ffmpeg would open the file it names, any file on this machine.
    let mpd = format!(
        "<!--ftypjp2 --><MPD xmlns=\"urn:mpeg:dash:schema:mpd:2011\" \
         profiles=\"urn:mpeg:dash:profile:isoff-on-demand:2011\" type=\"static\" \
         mediaPresentationDuration=\"PT8S\" minBufferTime=\"PT1S\"><Period>\
         <AdaptationSet mimeType=\"video/mp4\"><Representation id=\"1\" bandwidth=\"1000\">\
         <BaseURL>file://{}</BaseURL></Representation></AdaptationSet></Period></MPD>",
        dir.path().join("red.mp4").display()
    );
    // Large enough to be scanned from its file, as stdin would allow no
    // files anyway.
    let mpd = format!("{mpd}{}", " ".repeat(crate::store::INLINE_MAX));
    assert_eq!(
        upload(&s.url, &kp, mpd.as_bytes()).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // Grey cover art put first doesn't stand in for the red video: in MKV
    // it's a track of its own, ahead of the video and not marked as art.
    let cover = dir.path().join("cover.png");
    std::fs::write(
        &cover,
        encode(&noise(320, 240, |_, _| GREY), image::ImageFormat::Png),
    )
    .unwrap();
    let covered = dir.path().join("covered.mkv");
    let ok = std::process::Command::new("ffmpeg")
        .args(["-nostdin", "-loglevel", "error", "-i"])
        .arg(&cover)
        .arg("-i")
        .arg(dir.path().join("red.mp4"))
        .args(["-map", "0", "-map", "1", "-c", "copy", "-y"])
        .arg(&covered)
        .status()
        .unwrap();
    assert!(ok.success());
    let covered = std::fs::read(covered).unwrap();
    assert_eq!(
        upload(&s.url, &kp, &covered).await.status(),
        StatusCode::FORBIDDEN
    );

    // More video streams than are looked at, the red one last and marked
    // the one to play: not passed for the grey ones before it.
    let streams = dir.path().join("streams.mkv");
    let mut cmd = std::process::Command::new("ffmpeg");
    cmd.args(["-nostdin", "-loglevel", "error"]);
    for c in ["gray", "gray", "gray", "red"] {
        cmd.args(["-f", "lavfi", "-i"])
            .arg(format!("color=c={c}:s=160x120:d=2:r=10"));
    }
    for i in 0..4 {
        cmd.args(["-map", &format!("{i}:v")])
            .arg(format!("-disposition:v:{i}"))
            .arg(if i == 3 { "default" } else { "0" });
    }
    let ok = cmd
        .args(["-c:v", "mpeg4", "-g", "10", "-y"])
        .arg(&streams)
        .status()
        .unwrap();
    assert!(ok.success());
    assert_eq!(
        upload(&s.url, &kp, &std::fs::read(streams).unwrap())
            .await
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

async fn upload_as(url: &str, kp: &secp256k1::Keypair, data: &[u8], ty: &str) -> reqwest::Response {
    client()
        .put(format!("{url}/upload"))
        .header("authorization", auth(kp, &[Hash::of(data)]))
        .header("content-type", ty)
        .body(data.to_vec())
        .send()
        .await
        .unwrap()
}

/// A one-page PDF drawing `jpeg`, as an image XObject.
fn pdf_of(jpeg: &[u8]) -> Vec<u8> {
    let content = b"q 200 0 0 200 0 0 cm /Im0 Do Q";
    let objs: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
           /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>"
            .to_vec(),
        [
            format!(
                "<< /Type /XObject /Subtype /Image /Width 200 /Height 200 /ColorSpace /DeviceRGB \
                 /BitsPerComponent 8 /Filter /DCTDecode /Length {} >>\nstream\n",
                jpeg.len()
            )
            .into_bytes(),
            jpeg.to_vec(),
            b"\nendstream".to_vec(),
        ]
        .concat(),
        [
            format!("<< /Length {} >>\nstream\n", content.len()).into_bytes(),
            content.to_vec(),
            b"\nendstream".to_vec(),
        ]
        .concat(),
    ];
    let mut pdf = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend(format!("{} 0 obj\n", i + 1).bytes());
        pdf.extend(o);
        pdf.extend(b"\nendobj\n");
    }
    let xref = pdf.len();
    pdf.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).bytes());
    for o in offsets {
        pdf.extend(format!("{o:010} 00000 n \n").bytes());
    }
    pdf.extend(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .bytes(),
    );
    pdf
}

/// What shows pictures as a page or a PDF is looked into as one: by its
/// bytes, or by the type it's served as, whatever its bytes begin with.
#[tokio::test]
async fn looks_into_pdfs_and_pages() {
    let s = start(SCAN).await;
    let kp = keypair();
    let red = encode(&noise(200, 200, |_, _| RED), image::ImageFormat::Jpeg);
    let grey = encode(&noise(200, 200, |_, _| GREY), image::ImageFormat::Jpeg);
    assert_eq!(
        upload(&s.url, &kp, &pdf_of(&red)).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        upload(&s.url, &kp, &pdf_of(&grey)).await.status(),
        StatusCode::CREATED
    );
    // A browser's viewer finds the header past a few bytes of anything.
    let mut late = b"junk\n".to_vec();
    late.extend(pdf_of(&encode(
        &noise(201, 200, |_, _| RED),
        image::ImageFormat::Jpeg,
    )));
    assert_eq!(
        upload_as(&s.url, &kp, &late, "application/pdf")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );

    // A page that doesn't begin with markup is still a page, served as one.
    let png = encode(&noise(64, 64, |_, _| RED), image::ImageFormat::Png);
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &png);
    let page = format!("\0 hello <img src=\"data:image/png;base64,{b64}\">");
    assert_eq!(
        upload(&s.url, &kp, page.as_bytes()).await.status(),
        StatusCode::CREATED,
        "served as bytes, it shows nothing"
    );
    let page = format!("\0\0 hello <img src=\"data:image/png;base64,{b64}\">");
    assert_eq!(
        upload_as(&s.url, &kp, page.as_bytes(), "text/html")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
}

/// One address's scans don't hold up anyone's: past a few at once, its
/// media is turned away, and what's no kind of media never waits for a
/// scan at all.
#[tokio::test]
async fn one_address_has_a_few_scans_at_a_time() {
    let s = start(SCAN).await;
    let kp = keypair();
    let scanner = s.app.scanner.as_ref().unwrap();
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let held: Vec<_> = (0..crate::scan::PER_ADDRESS)
        .map(|_| scanner.turns.take(ip).unwrap())
        .collect();
    let grey = encode(&noise(64, 64, |_, _| GREY), image::ImageFormat::Png);
    let r = upload(&s.url, &kp, &grey).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers().contains_key("retry-after"));
    assert_eq!(
        upload_as(&s.url, &kp, b"console.log(1)", "text/javascript")
            .await
            .status(),
        StatusCode::CREATED
    );
    drop(held);
    assert_eq!(
        upload(&s.url, &kp, &grey).await.status(),
        StatusCode::CREATED
    );
}

/// A scan's refusal is a ban, the same as an operator's, and `unban` lifts
/// either.
#[tokio::test]
async fn refusals_are_bans_and_can_be_lifted() {
    use crate::store::Banned;
    let s = start(SCAN).await;
    let kp = keypair();
    let red = encode(&noise(200, 200, |_, _| RED), image::ImageFormat::Png);
    let grey = encode(&noise(200, 200, |_, _| GREY), image::ImageFormat::Png);
    assert_eq!(
        upload(&s.url, &kp, &red).await.status(),
        StatusCode::FORBIDDEN
    );
    // The writer records it without being waited on.
    for _ in 0..100 {
        if s.app.store.is_banned(Some(&Hash::of(&red)), None).unwrap() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        s.app.store.is_banned(Some(&Hash::of(&red)), None).unwrap(),
        "banned"
    );
    let reason = s
        .app
        .store
        .bans()
        .unwrap()
        .into_iter()
        .find(|b| b.target == Banned::Blob(Hash::of(&red)))
        .unwrap()
        .reason;
    assert!(reason.starts_with("scan: scored "), "{reason}");

    // An operator bans a stored blob.
    assert_eq!(
        upload(&s.url, &kp, &grey).await.status(),
        StatusCode::CREATED
    );
    let h = Hash::of(&grey);
    crate::moderate::ban(&s.app.config, &[Banned::Blob(h)], "test", None).unwrap();
    let r = client()
        .get(format!("{}/{}", s.url, h.hex()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        upload(&s.url, &kp, &grey).await.status(),
        StatusCode::FORBIDDEN
    );
    crate::moderate::unban(&s.app.config, &[Banned::Blob(h)]).unwrap();
    assert_eq!(
        upload(&s.url, &kp, &grey).await.status(),
        StatusCode::CREATED
    );
}

/// `train` fits a head to labels, and a server scans with it.
#[tokio::test]
async fn trains_a_head_and_scans_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = dir.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let mut labels = serde_json::Map::new();
    for i in 0..40u32 {
        let explicit = i % 2 == 0;
        // Reds and greys of varying shade; a few stored without an extension.
        let shade = (i * 3) as u8;
        let c = if explicit {
            [200 + shade / 3, 30 + shade, 30]
        } else {
            [100 + shade, 100 + shade, 110 + shade]
        };
        let png = encode(&noise(64, 64, |_, _| c), image::ImageFormat::Png);
        let h = Hash::of(&png).hex();
        let name = if i % 5 == 0 {
            h.clone()
        } else {
            format!("{h}.png")
        };
        std::fs::write(blobs.join(name), &png).unwrap();
        labels.insert(h, (if explicit { "explicit" } else { "clean" }).into());
    }
    let label_file = dir.path().join("labels.json");
    std::fs::write(&label_file, serde_json::to_vec(&labels).unwrap()).unwrap();
    let head = dir.path().join("head.json");
    let scan = crate::config::Scan {
        model: Some("test:rgb".into()),
        ..Default::default()
    };
    crate::scan::train::run(
        &scan,
        &crate::scan::train::Options {
            labels: label_file,
            blobs: vec![blobs],
            out: head.clone(),
            catch: 0.95,
            c: 3.0,
            jobs: 2,
            scores: None,
            cache: Some(dir.path().join("cache.jsonl")),
        },
    )
    .unwrap();
    let trained = crate::scan::model::Head::load(&head).unwrap();
    assert_eq!(trained.weights.len(), 3);
    // The pictures gone, the cache alone trains the same head.
    std::fs::remove_dir_all(dir.path().join("blobs")).unwrap();
    let again = dir.path().join("again.json");
    crate::scan::train::run(
        &scan,
        &crate::scan::train::Options {
            labels: dir.path().join("labels.json"),
            blobs: vec![],
            out: again.clone(),
            catch: 0.95,
            c: 3.0,
            jobs: 2,
            scores: None,
            cache: Some(dir.path().join("cache.jsonl")),
        },
    )
    .unwrap();
    let again = crate::scan::model::Head::load(&again).unwrap();
    assert_eq!(again.weights, trained.weights);

    let s = start(&format!(
        "[scan]\nenabled = true\nmodel = \"test:rgb\"\nhead = {:?}\nworkers = 1\n",
        head.to_str().unwrap()
    ))
    .await;
    let kp = keypair();
    let red = encode(
        &noise(120, 90, |_, _| [220, 40, 30]),
        image::ImageFormat::Jpeg,
    );
    let grey = encode(
        &noise(120, 90, |_, _| [140, 140, 150]),
        image::ImageFormat::Jpeg,
    );
    assert_eq!(
        upload(&s.url, &kp, &red).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        upload(&s.url, &kp, &grey).await.status(),
        StatusCode::CREATED
    );
}

/// Wait until every background scan is done.
async fn drained(s: &super::Server) {
    let scanner = s.app.scanner.as_ref().unwrap();
    while scanner.pending() > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    // The writer's commit of the last one.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

#[tokio::test]
async fn scans_in_the_background_and_holds_until_then() {
    let s = start(&format!("{SCAN}background = true\n")).await;
    let c = client();
    let kp = keypair();
    let red = encode(&noise(200, 200, |_, _| RED), image::ImageFormat::Png);
    let grey = encode(&noise(200, 200, |_, _| GREY), image::ImageFormat::Png);
    let small_red = encode(&noise(16, 16, |_, _| RED), image::ImageFormat::Png);
    for b in [&red, &grey, &small_red] {
        assert_eq!(
            upload(&s.url, &kp, b).await.status(),
            StatusCode::CREATED,
            "taken at once"
        );
    }
    let get = |b: &[u8]| c.get(format!("{}/{}", s.url, Hash::of(b).hex())).send();
    drained(&s).await;
    assert_eq!(
        get(&red).await.unwrap().status(),
        StatusCode::NOT_FOUND,
        "taken out"
    );
    assert_eq!(
        get(&small_red).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    let r = get(&grey).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(&r.bytes().await.unwrap()[..], &grey[..]);
    // Remembered: refused at once next time, not taken and scanned again.
    assert_eq!(
        upload(&s.url, &kp, &red).await.status(),
        StatusCode::FORBIDDEN
    );
}

/// Store a blob as a background upload leaves it: there, but unscanned.
fn put_unscanned(app: &'static crate::app::App, data: &[u8]) -> Hash {
    let h = put(app, data, Some("image/png"));
    let mut txn = app.store.write_txn().unwrap();
    let seq = app.store.seq_of(&txn, &h).unwrap().unwrap();
    let mut rec = app.store.record(&txn, seq).unwrap().unwrap();
    rec.flags |= crate::store::flag::UNSCANNED;
    app.store.update(&mut txn, seq, &rec).unwrap();
    txn.commit().unwrap();
    h
}

#[tokio::test]
async fn holds_a_blob_until_it_is_scanned() {
    let grey = encode(&noise(200, 200, |_, _| GREY), image::ImageFormat::Png);
    let c = client();
    let s = start(&format!("{SCAN}background = true\n")).await;
    let h = put_unscanned(s.app, &grey);
    let r = c
        .get(format!("{}/{}", s.url, h.hex()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.headers()["retry-after"], "1");
    // Once scanned, served.
    s.app.scanner.as_ref().unwrap().later(h);
    drained(&s).await;
    let r = c
        .get(format!("{}/{}", s.url, h.hex()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Told not to hold, a blob is served while it waits.
    let open = start(&format!("{SCAN}background = true\nhold = false\n")).await;
    let h = put_unscanned(open.app, &grey);
    let r = c
        .get(format!("{}/{}", open.url, h.hex()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

/// Uploads a second, with scanning off and on: `NSFW_MODEL=… NSFW_HEAD=… NSFW_IMAGES=dir
/// cargo test --release bench_uploads --
/// --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_uploads() {
    let (Ok(model), Ok(dir)) = (std::env::var("NSFW_MODEL"), std::env::var("NSFW_IMAGES")) else {
        panic!("set NSFW_MODEL and NSFW_IMAGES");
    };
    let mut files: Vec<Vec<u8>> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    files.sort();
    let rounds: usize = std::env::var("NSFW_ROUNDS").map_or(4, |r| r.parse().unwrap());
    let concurrency = 32;
    let workers = std::env::var("NSFW_WORKERS").unwrap_or_else(|_| "8".into());
    let background = std::env::var("NSFW_BACKGROUND").is_ok();
    for scan in [false, true] {
        let extra = if scan {
            let head =
                std::env::var("NSFW_HEAD").map_or(String::new(), |p| format!("head = {p:?}\n"));
            format!(
                "[scan]\nenabled = true\nmodel = {model:?}\n{head}workers = {workers}\nbackground = {background}\n[upload]\nper_minute = 1000000\n"
            )
        } else {
            "[upload]\nper_minute = 1000000\n".into()
        };
        let s = start(&extra).await;
        let s = &s;
        // Every upload new: a byte after the end changes the hash, not the picture.
        let mut bodies = Vec::new();
        for r in 0..rounds {
            for f in &files {
                let mut b = f.clone();
                b.extend_from_slice(&[scan as u8, r as u8]);
                bodies.push(b);
            }
        }
        let kp = std::sync::Arc::new(keypair());
        let queue = std::sync::Arc::new(parking_lot::Mutex::new(bodies));
        let started = std::time::Instant::now();
        let tasks: Vec<_> = (0..concurrency)
            .map(|_| {
                let (queue, kp, url) = (queue.clone(), kp.clone(), s.url.clone());
                tokio::spawn(async move {
                    let mut lat = Vec::new();
                    loop {
                        let Some(b) = queue.lock().pop() else {
                            return lat;
                        };
                        let t = std::time::Instant::now();
                        let r = upload(&url, &kp, &b).await;
                        assert_eq!(r.status(), StatusCode::CREATED);
                        lat.push(t.elapsed().as_secs_f64() * 1000.0);
                    }
                })
            })
            .collect();
        let mut lat = Vec::new();
        for t in tasks {
            lat.extend(t.await.unwrap());
        }
        let wall = started.elapsed().as_secs_f64();
        lat.sort_by(f64::total_cmp);
        let p = |q: f64| lat[((lat.len() - 1) as f64 * q) as usize];
        eprintln!(
            "scan {}: {} uploads in {wall:.1}s, {:.1}/s; latency p50 {:.0} ms, p99 {:.0} ms",
            if scan { "on " } else { "off" },
            lat.len(),
            lat.len() as f64 / wall,
            p(0.5),
            p(0.99)
        );
        if scan && background {
            drained(s).await;
            let all = started.elapsed().as_secs_f64();
            eprintln!(
                "  all scanned {all:.1}s after the first upload: {:.1} scans/s",
                lat.len() as f64 / all
            );
        }
    }
}
