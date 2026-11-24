//! Pictures in a PDF. A viewer draws every image in one: image XObjects,
//! wherever they're used (pages, forms, patterns, annotations), and images
//! written inline in a content stream. Each is decoded near enough to what
//! the viewer draws to be judged. One this can't decode (JPEG 2000, JBIG2,
//! CCITT fax, an unusual colour space, an inline image with a filter) makes
//! the PDF undecodable, so it's refused as any picture that won't read is
//! (`scan.refuse_undecodable`): passing it over would let a picture through
//! by its encoding alone.

use std::collections::HashSet;
use std::hash::{Hash as _, Hasher};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use image::metadata::Orientation;
use lopdf::content::Content;
use lopdf::{Dictionary, Document, LoadOptions, Object, Stream};

use super::pixels::{self, MAX_PIXELS, Raster, Square};

/// Images looked at in one PDF, at most: one with more is refused.
const MAX_IMAGES: usize = 100;
/// An image narrower or shorter than this shows too little to judge, and
/// isn't looked at.
const TINY: u64 = 16;
/// The most bytes one stream inflates to.
const MAX_STREAM: usize = 256 << 20;
/// The most bytes all of a PDF's streams inflate to, here, together.
const MAX_INFLATED: usize = 1 << 30;

/// The squares of every image in a PDF, `None` if it has none.
pub fn squares(bytes: &[u8], deadline: Instant) -> Result<Option<Vec<Square>>> {
    let options = LoadOptions {
        max_decompressed_size: Some(MAX_STREAM),
        ..Default::default()
    };
    let doc = Document::load_mem_with_options(bytes, options)
        .map_err(|e| anyhow!("it doesn't read as a PDF: {e}"))?;
    if doc.is_encrypted() {
        bail!("it's encrypted with a password");
    }
    let mut look = Look {
        doc: &doc,
        out: Vec::new(),
        images: 0,
        inflated: 0,
        seen: HashSet::new(),
    };
    for obj in doc.objects.values() {
        if Instant::now() >= deadline {
            bail!("it took too long to look through");
        }
        let Object::Stream(s) = obj else {
            continue;
        };
        if s.dict.get(b"Subtype").and_then(Object::as_name).ok() == Some(b"Image") {
            look.image(&s.dict, &s.content, false)?;
        } else if may_draw(&s.dict) {
            look.content(s)?;
        }
    }
    Ok((!look.out.is_empty()).then_some(look.out))
}

struct Look<'a> {
    doc: &'a Document,
    out: Vec<Square>,
    images: usize,
    inflated: usize,
    /// Images already looked at, by a hash of their dictionary and bytes:
    /// a logo on every page is looked at once.
    seen: HashSet<u64>,
}

/// Whether a stream that isn't an image may be a content stream, which
/// can hold inline images: not one of the kinds of stream that can't.
fn may_draw(dict: &Dictionary) -> bool {
    let name = |k: &[u8]| dict.get(k).and_then(Object::as_name).ok();
    !matches!(
        name(b"Type"),
        Some(b"XRef" | b"ObjStm" | b"Metadata" | b"EmbeddedFile" | b"CMap")
    ) && !matches!(
        name(b"Subtype"),
        Some(b"Type1C" | b"CIDFontType0C" | b"OpenType" | b"XML")
    ) && !dict.has(b"Length1")
        && !dict.has(b"FunctionType")
        && !(dict.has(b"N") && !dict.has(b"BBox"))
}

/// A filter's full name, for its inline abbreviation.
fn filter_name(f: &[u8]) -> &[u8] {
    match f {
        b"AHx" => b"ASCIIHexDecode",
        b"A85" => b"ASCII85Decode",
        b"LZW" => b"LZWDecode",
        b"Fl" => b"FlateDecode",
        b"RL" => b"RunLengthDecode",
        b"CCF" => b"CCITTFaxDecode",
        b"DCT" => b"DCTDecode",
        f => f,
    }
}

impl Look<'_> {
    fn deref<'b>(&'b self, o: &'b Object) -> &'b Object {
        self.doc.dereference(o).map_or(o, |(_, o)| o)
    }

    /// A dictionary entry, by its name or (inline) its abbreviation.
    fn get<'b>(&'b self, dict: &'b Dictionary, key: &[u8], abbr: &[u8]) -> Option<&'b Object> {
        dict.get(key)
            .or_else(|_| dict.get(abbr))
            .ok()
            .map(|o| self.deref(o))
    }

    fn number(&self, dict: &Dictionary, key: &[u8], abbr: &[u8]) -> Option<f64> {
        match self.get(dict, key, abbr)? {
            Object::Integer(i) => Some(*i as f64),
            Object::Real(r) => Some(*r as f64),
            _ => None,
        }
    }

    fn count(&mut self, n: usize) -> Result<()> {
        self.inflated += n;
        if self.inflated > MAX_INFLATED {
            bail!("its streams inflate to too much to look through");
        }
        Ok(())
    }

    /// Inline images in a content stream. A content stream lopdf can't
    /// parse is passed over, unless it has an inline image in it.
    fn content(&mut self, s: &Stream) -> Result<()> {
        let Ok(data) = s.decompressed_content_with_limit(MAX_STREAM) else {
            return Ok(());
        };
        self.count(data.len())?;
        let marks = inline_marks(&data);
        if marks.is_empty() {
            return Ok(());
        }
        let mut n = 0;
        for op in Content::decode_iter(&data) {
            let Ok(op) = op else {
                bail!("an inline image in it doesn't read");
            };
            if op.operator != "BI" {
                continue;
            }
            let size = marks.get(n).copied().flatten();
            n += 1;
            match op.operands.as_slice() {
                [Object::Stream(image)] => self.image(&image.dict, &image.content, true)?,
                // lopdf reads no inline image with a filter, or with a
                // colour space named in the page's resources.
                _ if size.is_some_and(|(w, h)| w < TINY || h < TINY) => {}
                _ => bail!("an inline image in it can't be read"),
            }
        }
        Ok(())
    }

    fn image(&mut self, dict: &Dictionary, content: &[u8], inline: bool) -> Result<()> {
        let w = self
            .number(dict, b"Width", b"W")
            .context("an image without a width")?;
        let h = self
            .number(dict, b"Height", b"H")
            .context("an image without a height")?;
        if !(w.is_finite() && h.is_finite() && w >= 0.0 && h >= 0.0) {
            bail!("an image of no size");
        }
        let (w, h) = (w as u64, h as u64);
        if w < TINY || h < TINY {
            return Ok(());
        }
        if w * h > MAX_PIXELS {
            bail!("a {w}x{h} image is more pixels than are decoded");
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        format!("{dict:?}").hash(&mut hasher);
        content.hash(&mut hasher);
        if !self.seen.insert(hasher.finish()) {
            return Ok(());
        }
        self.images += 1;
        if self.images > MAX_IMAGES {
            bail!("more than {MAX_IMAGES} images in it");
        }
        let filters: Vec<Vec<u8>> = match self.get(dict, b"Filter", b"F") {
            None => Vec::new(),
            Some(Object::Name(n)) => vec![filter_name(n).to_vec()],
            Some(Object::Array(a)) => a
                .iter()
                .map(|f| self.deref(f).as_name().map(|n| filter_name(n).to_vec()))
                .collect::<Result<_, _>>()
                .map_err(|_| anyhow!("an image's filters aren't names"))?,
            Some(_) => bail!("an image's filter isn't a name"),
        };
        // A picture codec is the last filter, if there is one; those before
        // it are lopdf's to undo.
        let codec = filters
            .last()
            .filter(|f| {
                matches!(
                    f.as_slice(),
                    b"DCTDecode" | b"JPXDecode" | b"JBIG2Decode" | b"CCITTFaxDecode"
                )
            })
            .cloned();
        let before = &filters[..filters.len() - codec.is_some() as usize];
        let data = if inline || before.is_empty() {
            content.to_vec()
        } else {
            let mut d = dict.clone();
            d.set(
                "Filter",
                Object::Array(before.iter().map(|f| Object::Name(f.clone())).collect()),
            );
            if let Ok(Object::Array(params)) = dict.get(b"DecodeParms").map(|o| self.deref(o)) {
                d.set(
                    "DecodeParms",
                    Object::Array(params[..before.len().min(params.len())].to_vec()),
                );
            }
            Stream::new(d, content.to_vec())
                .decompressed_content_with_limit(MAX_STREAM)
                .map_err(|e| anyhow!("an image's data doesn't inflate: {e}"))?
        };
        self.count(data.len())?;
        match codec.as_deref() {
            Some(b"DCTDecode") => {
                let sq = pixels::decode(&data, "image/jpeg")
                    .context("a JPEG image in it doesn't decode")?;
                self.out.extend(sq);
                Ok(())
            }
            Some(b"JPXDecode") => bail!("a JPEG 2000 image in it, which isn't read"),
            Some(b"JBIG2Decode") => bail!("a JBIG2 image in it, which isn't read"),
            Some(_) => bail!("a CCITT fax image in it, which isn't read"),
            None => self.raw(dict, w as usize, h as usize, &data),
        }
    }

    /// Samples, as an image's dictionary lays them out, to RGB.
    fn raw(&mut self, dict: &Dictionary, w: usize, h: usize, data: &[u8]) -> Result<()> {
        let mask = matches!(
            self.get(dict, b"ImageMask", b"IM"),
            Some(Object::Boolean(true))
        );
        let space = if mask {
            Space::Gray
        } else {
            let cs = self
                .get(dict, b"ColorSpace", b"CS")
                .context("an image without a colour space")?
                .clone();
            self.space(&cs, 0)?
        };
        let bpc = if mask {
            1
        } else {
            self.number(dict, b"BitsPerComponent", b"BPC")
                .context("an image without its bits per component")? as usize
        };
        if !matches!(bpc, 1 | 2 | 4 | 8 | 16) {
            bail!("an image of {bpc} bits per component");
        }
        let n = space.components();
        // What each sample's value maps to, by /Decode: 0 to 255, or for an
        // indexed image, an index.
        let top = (1usize << bpc) - 1;
        let decode: Vec<f64> = match self.get(dict, b"Decode", b"D") {
            Some(Object::Array(a)) => a
                .iter()
                .map(|v| match self.deref(v) {
                    Object::Integer(i) => *i as f64,
                    Object::Real(r) => *r as f64,
                    _ => 0.0,
                })
                .collect(),
            _ => Vec::new(),
        };
        let range = |c: usize| -> (f64, f64) {
            match (decode.get(2 * c), decode.get(2 * c + 1)) {
                (Some(a), Some(b)) => (*a, *b),
                _ => match &space {
                    Space::Indexed { .. } => (0.0, top as f64),
                    _ => (0.0, 1.0),
                },
            }
        };
        let tables: Vec<Vec<u8>> = (0..n)
            .map(|c| {
                let (lo, hi) = range(c);
                (0..=top)
                    .map(|v| {
                        let x = lo + v as f64 * (hi - lo) / top as f64;
                        match &space {
                            Space::Indexed { .. } => x.round().clamp(0.0, 255.0) as u8,
                            _ => (x * 255.0).round().clamp(0.0, 255.0) as u8,
                        }
                    })
                    .collect()
            })
            .collect();
        let row_bytes = (w * n * bpc).div_ceil(8);
        let mut rgb = Vec::with_capacity(w * h * 3);
        let mut px = vec![0u8; n];
        for y in 0..h {
            let row = data.get(y * row_bytes..).unwrap_or_default();
            for x in 0..w {
                for (c, p) in px.iter_mut().enumerate() {
                    let bit = (x * n + c) * bpc;
                    let v = match bpc {
                        16 => u16::from_be_bytes([
                            row.get(bit / 8).copied().unwrap_or(0),
                            row.get(bit / 8 + 1).copied().unwrap_or(0),
                        ]) as usize,
                        8 => row.get(bit / 8).copied().unwrap_or(0) as usize,
                        _ => {
                            let byte = row.get(bit / 8).copied().unwrap_or(0) as usize;
                            (byte >> (8 - bpc - bit % 8)) & top
                        }
                    };
                    *p = tables[c][v];
                }
                space.to_rgb(&px, &mut rgb);
            }
        }
        let r = Raster {
            width: w as u32,
            height: h as u32,
            pixels: &rgb,
            alpha: false,
        };
        pixels::squares(&r, Orientation::NoTransforms, true, &mut self.out)
    }

    fn space(&self, cs: &Object, depth: usize) -> Result<Space> {
        if depth > 2 {
            bail!("an image's colour space is nested too deep");
        }
        let cs = self.deref(cs);
        let (name, args): (&[u8], &[Object]) = match cs {
            Object::Name(n) => (n, &[]),
            Object::Array(a) => match a.first().map(|o| self.deref(o)) {
                Some(Object::Name(n)) => (n, &a[1..]),
                _ => bail!("an image's colour space isn't one"),
            },
            _ => bail!("an image's colour space isn't one"),
        };
        Ok(match name {
            b"DeviceGray" | b"G" | b"CalGray" => Space::Gray,
            b"DeviceRGB" | b"RGB" | b"CalRGB" => Space::Rgb,
            b"DeviceCMYK" | b"CMYK" => Space::Cmyk,
            b"ICCBased" => {
                let profile = args.first().map(|o| self.deref(o));
                match profile
                    .and_then(|p| p.as_stream().ok())
                    .and_then(|s| s.dict.get(b"N").ok())
                {
                    Some(Object::Integer(1)) => Space::Gray,
                    Some(Object::Integer(3)) => Space::Rgb,
                    Some(Object::Integer(4)) => Space::Cmyk,
                    _ => bail!("an ICC colour space of no known number of components"),
                }
            }
            b"Separation" => Space::Tint(1),
            b"DeviceN" => match args.first().map(|o| self.deref(o)) {
                Some(Object::Array(names)) if (1..=32).contains(&names.len()) => {
                    Space::Tint(names.len())
                }
                _ => bail!("a DeviceN colour space without its colourants"),
            },
            b"Indexed" | b"I" => {
                let [base, hival, lookup, ..] = args else {
                    bail!("an indexed colour space without its table");
                };
                let base = self.space(base, depth + 1)?;
                if matches!(base, Space::Indexed { .. }) {
                    bail!("an indexed colour space over another");
                }
                let hival = match self.deref(hival) {
                    Object::Integer(i) if (0..=255).contains(i) => *i as usize,
                    _ => bail!("an indexed colour space's highest index isn't one"),
                };
                let lookup = match self.deref(lookup) {
                    Object::String(s, _) => s.clone(),
                    Object::Stream(s) => s
                        .decompressed_content_with_limit(1 << 16)
                        .map_err(|e| anyhow!("an indexed colour space's table: {e}"))?,
                    _ => bail!("an indexed colour space's table isn't one"),
                };
                Space::Indexed {
                    base: Box::new(base),
                    hival,
                    lookup,
                }
            }
            n => bail!(
                "an image in the {} colour space, which isn't read",
                String::from_utf8_lossy(n)
            ),
        })
    }
}

/// The colour spaces read, near enough to judge what's drawn.
enum Space {
    Gray,
    Rgb,
    Cmyk,
    /// Separation or DeviceN: inks whose colour a function gives. Drawn as
    /// grey, more ink darker, which keeps the shapes they make.
    Tint(usize),
    Indexed {
        base: Box<Space>,
        hival: usize,
        lookup: Vec<u8>,
    },
}

impl Space {
    fn components(&self) -> usize {
        match self {
            Space::Gray | Space::Indexed { .. } => 1,
            Space::Rgb => 3,
            Space::Cmyk => 4,
            Space::Tint(n) => *n,
        }
    }

    fn to_rgb(&self, px: &[u8], out: &mut Vec<u8>) {
        match self {
            Space::Gray => out.extend_from_slice(&[px[0]; 3]),
            Space::Rgb => out.extend_from_slice(&px[..3]),
            Space::Cmyk => {
                let k = 255 - px[3] as u32;
                for &c in &px[..3] {
                    out.push(((255 - c as u32) * k / 255) as u8);
                }
            }
            Space::Tint(n) => {
                let ink = px.iter().map(|&v| v as u32).sum::<u32>() / *n as u32;
                out.extend_from_slice(&[255 - ink as u8; 3]);
            }
            Space::Indexed {
                base,
                hival,
                lookup,
            } => {
                let n = base.components();
                let i = (px[0] as usize).min(*hival) * n;
                let mut entry = [0u8; 4];
                for (c, e) in entry.iter_mut().take(n).enumerate() {
                    *e = lookup.get(i + c).copied().unwrap_or(0);
                }
                base.to_rgb(&entry[..n], out);
            }
        }
    }
}

/// The width and height each inline image in a content stream declares,
/// in order, read from the raw text between its `BI` and `ID`: what's
/// known of the ones lopdf can't read.
fn inline_marks(data: &[u8]) -> Vec<Option<(u64, u64)>> {
    let space = |c: Option<&u8>| c.is_none_or(|c| c.is_ascii_whitespace());
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = memchr::memmem::find(&data[at..], b"BI") {
        let start = at + i;
        at = start + 2;
        if !(space(start.checked_sub(1).and_then(|p| data.get(p))) && space(data.get(at))) {
            continue;
        }
        // The dictionary ends at `ID`, a word of its own.
        let dict_end = data[at..].windows(4).take(4096).position(|w| {
            w[0].is_ascii_whitespace() && &w[1..3] == b"ID" && w[3].is_ascii_whitespace()
        });
        let Some(end) = dict_end else {
            continue;
        };
        let text = String::from_utf8_lossy(&data[at..at + end]);
        let words: Vec<&str> = text.split_ascii_whitespace().collect();
        let value = |keys: &[&str]| {
            words
                .windows(2)
                .find(|p| keys.contains(&p[0]))
                .and_then(|p| p[1].parse::<u64>().ok())
        };
        out.push(value(&["/W", "/Width"]).zip(value(&["/H", "/Height"])));
        at += end + 3;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::dictionary;

    /// A one-page PDF drawing `streams` as image XObjects, and `content`
    /// as its page.
    fn pdf(images: Vec<Stream>, content: &[u8]) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let mut xobjects = Dictionary::new();
        for (i, s) in images.into_iter().enumerate() {
            let id = doc.add_object(s);
            xobjects.set(format!("Im{i}"), Object::Reference(id));
        }
        let contents = doc.add_object(Stream::new(dictionary! {}, content.to_vec()));
        let pages = doc.new_object_id();
        let page = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
            "Resources" => dictionary! { "XObject" => xobjects },
            "Contents" => contents,
        });
        doc.objects.insert(
            pages,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page.into()],
                "Count" => 1,
            }),
        );
        let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
        doc.trailer.set("Root", catalog);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    fn image(w: i64, h: i64, cs: Object, bpc: i64, data: Vec<u8>) -> Stream {
        let mut s = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => w,
                "Height" => h,
                "ColorSpace" => cs,
                "BitsPerComponent" => bpc,
            },
            data,
        );
        s.compress().unwrap();
        s
    }

    fn found(bytes: &[u8]) -> Result<Option<Vec<Square>>> {
        squares(bytes, Instant::now() + std::time::Duration::from_secs(30))
    }

    /// The mean colour of the first square.
    fn mean(sq: &[Square]) -> [u8; 3] {
        let mut sums = [0u64; 3];
        for p in sq[0].chunks_exact(3) {
            for c in 0..3 {
                sums[c] += p[c] as u64;
            }
        }
        sums.map(|s| (s / (sq[0].len() / 3) as u64) as u8)
    }

    #[test]
    fn reads_raw_jpeg_and_indexed_images() {
        let red: Vec<u8> = [220u8, 10, 10].repeat(64 * 64);
        let sq = found(&pdf(vec![image(64, 64, "DeviceRGB".into(), 8, red)], b""))
            .unwrap()
            .unwrap();
        assert_eq!(mean(&sq), [220, 10, 10]);

        // Two bits a sample, each index the palette's red.
        let palette = Object::Array(vec![
            "Indexed".into(),
            "DeviceRGB".into(),
            3.into(),
            Object::string_literal(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 230, 20, 20]),
        ]);
        let sq = found(&pdf(
            vec![image(64, 64, palette, 2, vec![0xff; 16 * 64])],
            b"",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(mean(&sq), [230, 20, 20]);

        let mut jpeg = std::io::Cursor::new(Vec::new());
        image::RgbImage::from_pixel(64, 64, image::Rgb([200, 30, 30]))
            .write_to(&mut jpeg, image::ImageFormat::Jpeg)
            .unwrap();
        let mut s = Stream::new(
            dictionary! {
                "Subtype" => "Image", "Width" => 64, "Height" => 64,
                "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8,
                "Filter" => "DCTDecode",
            },
            jpeg.into_inner(),
        );
        s.allows_compression = false;
        let sq = found(&pdf(vec![s], b"")).unwrap().unwrap();
        let [r, g, _] = mean(&sq);
        assert!(r > 180 && g < 60, "{r} {g}");
    }

    #[test]
    fn reads_inline_images() {
        let mut content = b"q 200 0 0 200 0 0 cm BI /W 32 /H 32 /CS /RGB /BPC 8 ID ".to_vec();
        content.extend([210u8, 15, 15].repeat(32 * 32));
        content.extend(b"\nEI Q");
        let sq = found(&pdf(vec![], &content)).unwrap().unwrap();
        assert_eq!(mean(&sq), [210, 15, 15]);
        // With a filter, lopdf doesn't read it: refused, unless it's tiny.
        let filtered = |w: u32| {
            let mut c = format!("BI /W {w} /H {w} /CS /RGB /BPC 8 /F /AHx ID ").into_bytes();
            c.extend("ff0000".repeat((w * w) as usize).bytes());
            c.extend(b"> EI");
            c
        };
        assert!(found(&pdf(vec![], &filtered(64))).is_err());
        assert!(found(&pdf(vec![], &filtered(4))).unwrap().is_none());
    }

    #[test]
    fn refuses_what_it_cannot_read_and_passes_what_is_tiny() {
        let jbig2 = Stream::new(
            dictionary! {
                "Subtype" => "Image", "Width" => 64, "Height" => 64,
                "ColorSpace" => "DeviceGray", "BitsPerComponent" => 1,
                "Filter" => "JBIG2Decode",
            },
            vec![0; 100],
        );
        assert!(found(&pdf(vec![jbig2], b"")).is_err());
        let lab = Object::Array(vec!["Lab".into(), Object::Dictionary(Dictionary::new())]);
        assert!(found(&pdf(vec![image(64, 64, lab, 8, vec![0; 64 * 64 * 3])], b"")).is_err());
        let tiny = image(8, 8, "DeviceRGB".into(), 8, vec![255; 8 * 8 * 3]);
        assert!(found(&pdf(vec![tiny], b"")).unwrap().is_none());
        assert!(found(&pdf(vec![], b"BT ET")).unwrap().is_none());
        // More images than are looked at, each its own.
        let many = (0..=MAX_IMAGES as u8)
            .map(|i| image(16, 16, "DeviceGray".into(), 8, vec![i; 256]))
            .collect();
        assert!(found(&pdf(many, b"")).is_err());
    }
}
