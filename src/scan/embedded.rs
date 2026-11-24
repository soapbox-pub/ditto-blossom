//! Pictures inside markup. An SVG or an HTML page is no picture to the
//! model, but a browser shows the images it carries in `data:` URIs (as
//! `<img>`, `<image>`, or a CSS background) as plainly as a file of their
//! own, so they're scanned as if they were one.
//!
//! They're found as a browser finds them: after HTML's character references
//! and CSS's escapes are decoded and the tabs and newlines a URL loses are
//! dropped, in any case, and percent-decoded, and as a `srcset` reads them
//! too. What's in one is judged by its bytes, as an `<img>` judges it,
//! whatever type the URI declares.
//!
//! What can't all be looked at (more pictures than `MAX_IMAGES`, markup
//! nested deeper than `MAX_DEPTH`, more text than `MAX_TEXT`, or past the
//! deadline) is undecodable, not passed: a picture could be put past any
//! limit that let the rest through.

use std::path::Path;
use std::time::Instant;

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use super::pixels::{self, Square};
use super::{Kind, kind};

/// Pictures taken out of one blob, at most.
const MAX_IMAGES: usize = 64;
/// An SVG in a data URI in a page: looked into this deep.
const MAX_DEPTH: usize = 2;
/// A data URI's header, `image/png;base64` and the like, at most.
const MAX_HEADER: usize = 256;
/// The most text looked through for data URIs.
const MAX_TEXT: usize = 64 << 20;

const BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

struct Found<'a> {
    images: usize,
    out: Vec<Square>,
    ffmpeg: Option<&'a Path>,
    deadline: Instant,
    /// Why not everything in it was looked at, if it wasn't.
    unseen: Option<&'static str>,
}

/// The squares of every image embedded in `bytes`, markup, or `None` if
/// there are none. Images that don't decode are passed over: a browser
/// shows nothing for them either. AVIF, HEIC and JPEG XL go to `ffmpeg`, if
/// there is one, by `deadline`.
pub fn squares(
    bytes: &[u8],
    ffmpeg: Option<&Path>,
    deadline: Instant,
) -> anyhow::Result<Option<Vec<Square>>> {
    if bytes.len() > MAX_TEXT {
        anyhow::bail!("more markup than is looked through");
    }
    let mut found = Found {
        images: 0,
        out: Vec::new(),
        ffmpeg,
        deadline,
        unseen: None,
    };
    collect(bytes, 0, &mut found);
    if let Some(why) = found.unseen {
        anyhow::bail!("{why}");
    }
    Ok((!found.out.is_empty()).then_some(found.out))
}

pub fn is_markup(bytes: &[u8]) -> bool {
    let b = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    b.iter().take(1024).find(|c| !c.is_ascii_whitespace()) == Some(&b'<')
}

fn collect(bytes: &[u8], depth: usize, found: &mut Found<'_>) {
    let text = unescape(bytes);
    let lower = text.to_ascii_lowercase();
    let finder = memchr::memmem::Finder::new(b"data:");
    let mut at = 0;
    while let Some(i) = finder.find(&lower[at..]) {
        if found.unseen.is_some() {
            return;
        }
        if Instant::now() >= found.deadline {
            found.unseen = Some("it took too long to look through");
            return;
        }
        let scheme = at + i;
        let start = scheme + b"data:".len();
        at = start;
        // The header ends at the comma.
        let Some(comma) = lower[start..]
            .iter()
            .take(MAX_HEADER)
            .position(|&c| c == b',' || b"\"'()<>".contains(&c))
            .filter(|&n| lower[start + n] == b',')
        else {
            continue;
        };
        // `;base64`, spaces allowed before it, as fetch has it.
        let base64 = lower[start..start + comma]
            .trim_ascii_end()
            .strip_suffix(b"base64")
            .is_some_and(|h| h.trim_ascii_end().ends_with(b";"));
        let body = start + comma + 1;
        // Quoted, the URI ends at its quote; else at what ends a CSS url().
        let quote = scheme
            .checked_sub(1)
            .map(|q| text[q])
            .filter(|c| matches!(c, b'"' | b'\''));
        let end = text[body..]
            .iter()
            .position(|c| match quote {
                Some(q) => *c == q,
                None => b"\"') <>".contains(c),
            })
            .map_or(text.len(), |n| body + n);
        // Read as `src` reads it, the whole of it, and as `srcset` does, to
        // the first space; what's after it, another data URI in the same
        // `srcset`, is found by going on from here.
        let whole = &text[body..end];
        let mut readings = vec![whole];
        if let Some(sp) = whole.iter().position(u8::is_ascii_whitespace) {
            let first = whole[..sp].trim_ascii_end();
            let first = first.strip_suffix(b",").unwrap_or(first);
            if !first.is_empty() {
                readings.push(first);
            }
        }
        for reading in readings {
            let mut payload = percent_decode(reading);
            if base64 {
                payload.retain(|c| !c.is_ascii_whitespace());
                let Ok(decoded) = BASE64.decode(&payload) else {
                    continue;
                };
                payload = decoded;
            }
            look(&payload, depth, found);
        }
    }
}

/// One data URI's bytes: a picture, or markup that may hold more.
fn look(payload: &[u8], depth: usize, found: &mut Found<'_>) {
    let ty = crate::mime::sniff(&payload[..payload.len().min(8192)]);
    match kind(ty.as_deref()) {
        Kind::Image => {
            if !count(found) {
                return;
            }
            if let Ok(sq) = pixels::decode(payload, ty.as_deref().unwrap_or_default()) {
                found.out.extend(sq);
            }
        }
        // AVIF, HEIC and JPEG XL: an <img> shows them; video it doesn't.
        Kind::Video if ty.as_deref().is_some_and(|t| t.starts_with("image/")) => {
            if !count(found) {
                return;
            }
            if let Some(ff) = found.ffmpeg {
                let src = super::ffmpeg::Input::Bytes(payload);
                if let Ok(Some(sq)) = super::ffmpeg::squares(ff, src, true, found.deadline) {
                    found.out.extend(sq);
                }
            }
        }
        _ if is_markup(payload) => {
            if depth + 1 >= MAX_DEPTH {
                found.unseen = Some("markup in it is nested too deep to look through");
            } else if count(found) {
                collect(payload, depth + 1, found);
            }
        }
        _ => {}
    }
}

/// Count one more picture, unless that's more than are looked at.
fn count(found: &mut Found<'_>) -> bool {
    if found.images >= MAX_IMAGES {
        found.unseen = Some("more pictures in it than are looked at");
        return false;
    }
    found.images += 1;
    true
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

fn percent_decode(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (
            b[i],
            b.get(i + 1).and_then(|&c| hex(c)),
            b.get(i + 2).and_then(|&c| hex(c)),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push(h << 4 | l);
                i += 3;
            }
            (c, ..) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// HTML's named references that spell out a URI's punctuation.
const NAMED: &[(&[u8], u8)] = &[
    (b"colon;", b':'),
    (b"sol;", b'/'),
    (b"comma;", b','),
    (b"semi;", b';'),
    (b"plus;", b'+'),
    (b"equals;", b'='),
    (b"percnt;", b'%'),
    (b"period;", b'.'),
    (b"lpar;", b'('),
    (b"rpar;", b')'),
    (b"quot;", b'"'),
    (b"apos;", b'\''),
    (b"amp;", b'&'),
    (b"lt;", b'<'),
    (b"gt;", b'>'),
    (b"Tab;", b'\t'),
    (b"NewLine;", b'\n'),
];

/// The text as a browser's URL parser would get it: HTML's character
/// references and CSS's escapes decoded (those that are ASCII), and tabs
/// and newlines, which a URL drops, gone. Only for finding URIs in.
fn unescape(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let (c, used) = match b[i] {
            b'&' => reference(&b[i + 1..]).map_or((Some(b'&'), 1), |(c, n)| (Some(c), n + 1)),
            b'\\' => css_escape(&b[i + 1..]).map_or((Some(b'\\'), 1), |(c, n)| (c, n + 1)),
            c => (Some(c), 1),
        };
        if let Some(c) = c
            && !matches!(c, b'\t' | b'\n' | b'\r')
        {
            out.push(c);
        }
        i += used;
    }
    out
}

/// A character reference after its `&`: the character, and its length.
fn reference(b: &[u8]) -> Option<(u8, usize)> {
    if let Some(rest) = b.strip_prefix(b"#") {
        let (radix, digits, skip) = match rest.first() {
            Some(b'x' | b'X') => (16, &rest[1..], 2),
            _ => (10, rest, 1),
        };
        let n = digits
            .iter()
            .take(8)
            .take_while(|c| (**c as char).is_digit(radix))
            .count();
        let v = u32::from_str_radix(std::str::from_utf8(&digits[..n]).ok()?, radix).ok()?;
        let semi = (digits.get(n) == Some(&b';')) as usize;
        return (v > 0 && v < 128).then_some((v as u8, skip + n + semi));
    }
    NAMED
        .iter()
        .find(|(name, _)| b.starts_with(name))
        .map(|(name, c)| (*c, name.len()))
}

/// A CSS escape after its `\`: the character (none for an escaped newline,
/// or one past ASCII), and its length.
fn css_escape(b: &[u8]) -> Option<(Option<u8>, usize)> {
    let first = *b.first()?;
    if first == b'\n' {
        return Some((None, 1));
    }
    let n = b
        .iter()
        .take(6)
        .take_while(|c| c.is_ascii_hexdigit())
        .count();
    if n == 0 {
        return Some((Some(first), 1));
    }
    let v = u32::from_str_radix(std::str::from_utf8(&b[..n]).ok()?, 16).ok()?;
    let space = b.get(n).is_some_and(|c| c.is_ascii_whitespace()) as usize;
    Some(((v > 0 && v < 128).then_some(v as u8), n + space))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png() -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        image::RgbImage::from_pixel(8, 8, image::Rgb([200, 10, 10]))
            .write_to(&mut out, image::ImageFormat::Png)
            .unwrap();
        out.into_inner()
    }

    fn found(b: impl AsRef<[u8]>) -> usize {
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        squares(b.as_ref(), None, deadline)
            .unwrap()
            .map_or(0, |s| s.len())
    }

    #[test]
    fn finds_images_in_svg_and_in_svg_in_html() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(png());
        // Wrapped, as encoders like to.
        let wrapped: String = b64
            .as_bytes()
            .chunks(20)
            .map(|c| format!("{}\n  ", std::str::from_utf8(c).unwrap()))
            .collect();
        let svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,{wrapped}"/></svg>"#
        );
        assert_eq!(found(&svg), 1);
        let inner = base64::engine::general_purpose::STANDARD.encode(&svg);
        let html = format!(
            r#"<!doctype html><div style="background:url('data:image/svg+xml;base64,{inner}')"></div>"#
        );
        assert_eq!(found(html), 1);
        assert_eq!(found(b"<p>no pictures</p>"), 0);
        assert_eq!(found(b"not markup data:image/png;base64,AAAA"), 0);
    }

    /// The ways a browser still finds an image that a plain search for
    /// `data:image/…;base64,` misses.
    #[test]
    fn finds_images_however_theyre_written() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(png());
        let img = |uri: &str| format!(r#"<html><img src="{uri}"></html>"#);
        // In capitals.
        assert_eq!(found(img(&format!("DATA:IMAGE/PNG;BASE64,{b64}"))), 1);
        // Spelled with character references, or with a tab in the scheme.
        assert_eq!(
            found(img(&format!("&#100;ata&colon;image/png;base64,{b64}"))),
            1
        );
        assert_eq!(found(img(&format!("da&#x9;ta:image/png;base64,{b64}"))), 1);
        // With CSS escapes.
        let css = format!(r#"<div style="background:url('\64 ata:image/png;base64,{b64}')">"#);
        assert_eq!(found(css), 1);
        // Percent-encoded, or declared as something else entirely.
        let pct = b64.replace('+', "%2B").replace('/', "%2F");
        assert_eq!(found(img(&format!("data:image/png;base64,{pct}"))), 1);
        assert_eq!(found(img(&format!("data:text/plain;base64,{b64}"))), 1);
        assert_eq!(found(img(&format!("data:;base64,{b64}"))), 1);
        // In an SVG that's percent-encoded, not base64.
        let svg = format!(
            "<svg xmlns='http://www.w3.org/2000/svg'><image href='data:image/png;base64,{b64}'/></svg>"
        );
        let svg_pct: String = svg
            .bytes()
            .map(|c| match c {
                b'<' | b'>' | b'/' | b'+' | b' ' | b'=' => format!("%{c:02X}"),
                c => (c as char).to_string(),
            })
            .collect();
        // Seen in the SVG, and in the page around it, where it's plain too.
        assert!(found(img(&format!("data:image/svg+xml,{svg_pct}"))) >= 1);
    }

    /// Data URIs that aren't pictures don't use up the pictures looked at.
    #[test]
    fn junk_first_hides_nothing() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(png());
        let mut page = String::from("<html>");
        for _ in 0..100 {
            page.push_str(r#"<img src="data:image/png;base64,AAAA">"#);
        }
        page.push_str(&format!(
            r#"<img src="data:image/png;base64,{b64}"></html>"#
        ));
        assert_eq!(found(page), 1);
    }

    /// A picture in a `srcset`, alone or after another.
    #[test]
    fn finds_images_in_srcset() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(png());
        let one = format!(r#"<img srcset="data:image/png;base64,{b64} 1x">"#);
        assert_eq!(found(one), 1);
        let two = format!(
            r#"<img srcset="data:image/png;base64,{b64} 1x, data:image/png;base64,{b64} 2x">"#
        );
        assert!(found(two) >= 2);
    }

    /// Past any limit, nothing is passed: what's left unseen could be a
    /// picture put there for the purpose.
    #[test]
    fn what_cannot_all_be_seen_is_undecodable() {
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let b64 = base64::engine::general_purpose::STANDARD.encode(png());
        let img = format!(r#"<img src="data:image/png;base64,{b64}">"#);
        let at_most = img.repeat(MAX_IMAGES);
        assert_eq!(found(&at_most), MAX_IMAGES);
        let more = img.repeat(MAX_IMAGES + 1);
        assert!(squares(more.as_bytes(), None, deadline).is_err());

        let svg = |inner: &str| {
            let b = base64::engine::general_purpose::STANDARD.encode(format!(
                r#"<svg xmlns="http://www.w3.org/2000/svg">{inner}</svg>"#
            ));
            format!(r#"<image href="data:image/svg+xml;base64,{b}"/>"#)
        };
        let deep = svg(&svg(&img.replace("<img src", "<image href")));
        assert!(squares(format!("<html>{deep}</html>").as_bytes(), None, deadline).is_err());
        let past = Instant::now() - std::time::Duration::from_secs(1);
        assert!(squares(img.as_bytes(), None, past).is_err());
    }
}
