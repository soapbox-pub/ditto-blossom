//! Big JPEGs, decoded at an eighth of their size or so: the encoder only
//! wants 224 pixels a side.
//!
//! A progressive JPEG's first scans carry every 8x8 block's DC coefficient,
//! its average, which is the image at 1/8 scale: those are read and every
//! AC scan, most of the file, is skipped unread (a 12 MP photo in ~5 ms
//! rather than ~100). A baseline JPEG interleaves DC with AC, so it's
//! decoded by jpeg-decoder with its IDCT scaled down (~3x quicker than in
//! full). Anything else, or anything small, gets a full decode.

use anyhow::{Result, bail};
use image::metadata::Orientation;

use super::model::SIDE;
use super::pixels::{MAX_PIXELS, Raster, Square, exif_orientation, squares};

/// Smaller than this, a full decode by zune-jpeg is as quick.
const MIN_PIXELS: u64 = 4 << 20;
/// The DC image is used only if its short side is at least the encoder's.
const DC_SHORT_SIDE: usize = SIDE;
/// The most blocks a component may have.
const MAX_BLOCKS: usize = 16 << 20;
/// The most pixels a baseline JPEG may have, decoded scaled: every block is
/// still entropy-decoded, and its data may be missing, read as zeros, so
/// a few bytes could otherwise ask for 4 billion.
const MAX_BASELINE_PIXELS: u64 = 4 * MAX_PIXELS;
/// The most scans read, zune-jpeg's own limit: past it a full decode
/// fails too.
const MAX_SCANS: usize = 100;
/// The most DC scans read, each a pass over every block. An encoder sends
/// one or two a component; ones with no data cost a byte or so.
const MAX_DC_SCANS: usize = 16;

/// Squares for a big JPEG decoded scaled down, or `false` if it's one
/// better left to a full decode.
pub fn squares_scaled(bytes: &[u8], out: &mut Vec<Square>) -> Result<bool> {
    let Some(head) = Header::parse(bytes) else {
        return Ok(false);
    };
    if (head.width as u64 * head.height as u64) < MIN_PIXELS {
        return Ok(false);
    }
    let orientation = head
        .exif
        .map_or(Orientation::NoTransforms, exif_orientation);
    if head.progressive
        && head.width.min(head.height) / 8 >= DC_SHORT_SIDE
        && let Some((w, h, px)) = dc_image(bytes, &head)
    {
        let r = Raster {
            width: w as u32,
            height: h as u32,
            pixels: &px,
            alpha: false,
        };
        squares(&r, orientation, true, out)?;
        return Ok(true);
    }
    if head.progressive {
        return Ok(false);
    }
    if head.width as u64 * head.height as u64 > MAX_BASELINE_PIXELS {
        bail!(
            "{}x{} is more pixels than are decoded",
            head.width,
            head.height
        );
    }
    // What jpeg-decoder can't read is left to zune-jpeg, as it reads more.
    let had = out.len();
    scaled_baseline(bytes, orientation, out).or_else(|_| {
        out.truncate(had);
        Ok(false)
    })
}

fn scaled_baseline(bytes: &[u8], orientation: Orientation, out: &mut Vec<Square>) -> Result<bool> {
    let mut d = jpeg_decoder::Decoder::new(bytes);
    d.read_info()?;
    let Some(info) = d.info() else {
        return Ok(false);
    };
    if info.width as u64 * info.height as u64 > MAX_BASELINE_PIXELS {
        bail!(
            "{}x{} is more pixels than are decoded",
            info.width,
            info.height
        );
    }
    if !matches!(
        info.pixel_format,
        jpeg_decoder::PixelFormat::RGB24 | jpeg_decoder::PixelFormat::L8
    ) {
        return Ok(false);
    }
    // The smallest scale leaving the short side at least SIDE, so a long
    // image's square pieces are too.
    let (w, h) = d.scale(SIDE as u16, SIDE as u16)?;
    if w as u64 * h as u64 > MAX_PIXELS {
        bail!(
            "{}x{} is more pixels than are decoded",
            info.width,
            info.height
        );
    }
    let mut px = d.decode()?;
    if info.pixel_format == jpeg_decoder::PixelFormat::L8 {
        px = px.iter().flat_map(|&l| [l, l, l]).collect();
    }
    if px.len() < w as usize * h as usize * 3 {
        bail!("a JPEG shorter than its size");
    }
    let r = Raster {
        width: w as u32,
        height: h as u32,
        pixels: &px,
        alpha: false,
    };
    squares(&r, orientation, true, out)?;
    Ok(true)
}

struct Component {
    id: u8,
    h: usize,
    v: usize,
    tq: usize,
}

/// What's before the first scan: enough to choose a decode.
struct Header<'a> {
    progressive: bool,
    width: usize,
    height: usize,
    components: Vec<Component>,
    exif: Option<&'a [u8]>,
}

fn u16_at(b: &[u8], i: usize) -> Option<usize> {
    Some(((*b.get(i)? as usize) << 8) | *b.get(i + 1)? as usize)
}

/// The segments of a JPEG up to its first scan: (marker, body, offset after).
fn segments<'a>(
    bytes: &'a [u8],
    mut at: usize,
    mut f: impl FnMut(u8, &'a [u8], usize) -> Option<bool>,
) -> Option<()> {
    loop {
        while bytes.get(at)? != &0xFF {
            at += 1;
        }
        while bytes.get(at)? == &0xFF {
            at += 1;
        }
        let marker = *bytes.get(at)?;
        at += 1;
        if marker == 0xD8 || (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            continue;
        }
        if marker == 0xD9 {
            return Some(());
        }
        let len = u16_at(bytes, at)?;
        let body = bytes.get(at + 2..at + len.max(2))?;
        at += len.max(2);
        if !f(marker, body, at)? {
            return Some(());
        }
    }
}

impl<'a> Header<'a> {
    fn parse(bytes: &'a [u8]) -> Option<Header<'a>> {
        if bytes.get(..2)? != [0xFF, 0xD8] {
            return None;
        }
        let mut head: Option<Header<'a>> = None;
        let (mut exif, mut adobe_rgb) = (None, false);
        segments(bytes, 2, |marker, body, _| {
            match marker {
                0xE1 if body.starts_with(b"Exif\0\0") => exif = Some(&body[6..]),
                // An Adobe segment saying its three components aren't YCbCr.
                0xEE if body.starts_with(b"Adobe") && body.len() >= 12 => adobe_rgb = body[11] == 0,
                0xC0..=0xCF if !matches!(marker, 0xC4 | 0xC8 | 0xCC) => {
                    if head.is_some() {
                        return None;
                    }
                    let progressive = match marker {
                        0xC0 | 0xC1 => false,
                        0xC2 => true,
                        _ => return None,
                    };
                    if *body.first()? != 8 {
                        return None;
                    }
                    let height = u16_at(body, 1)?;
                    let width = u16_at(body, 3)?;
                    let n = *body.get(5)? as usize;
                    let mut components = Vec::new();
                    for i in 0..n {
                        let c = body.get(6 + i * 3..9 + i * 3)?;
                        let (h, v) = ((c[1] >> 4) as usize, (c[1] & 15) as usize);
                        if !(1..=4).contains(&h) || !(1..=4).contains(&v) || c[2] > 3 {
                            return None;
                        }
                        components.push(Component {
                            id: c[0],
                            h,
                            v,
                            tq: c[2] as usize,
                        });
                    }
                    head = Some(Header {
                        progressive,
                        width,
                        height,
                        components,
                        exif: None,
                    });
                }
                // Read to the first scan, as libjpeg does: an Adobe or EXIF
                // segment after the frame's header counts as much as one before.
                0xDA => return head.is_some().then_some(false),
                _ => {}
            }
            Some(true)
        })?;
        let mut head = head?;
        let n = head.components.len();
        if head.width == 0 || head.height == 0 || !(n == 1 || n == 3) || (n == 3 && adobe_rgb) {
            return None;
        }
        // Component ids R, G, B mean RGB, not YCbCr.
        if n == 3 && head.components.iter().map(|c| c.id).eq(*b"RGB") {
            return None;
        }
        head.exif = exif;
        Some(head)
    }
}

/// A canonical Huffman table, decoded a bit at a time: DC symbols are one
/// a block, so that's plenty.
struct Huffman {
    maxcode: [i32; 17],
    valptr: [i32; 17],
    mincode: [i32; 17],
    values: Vec<u8>,
}

impl Huffman {
    fn new(counts: &[u8], values: &[u8]) -> Option<Huffman> {
        let (mut maxcode, mut valptr, mut mincode) = ([-1i32; 17], [0i32; 17], [0i32; 17]);
        let (mut code, mut k) = (0i32, 0i32);
        for len in 1..=16 {
            let n = counts[len - 1] as i32;
            if n > 0 {
                valptr[len] = k;
                mincode[len] = code;
                code += n;
                k += n;
                maxcode[len] = code - 1;
            }
            code <<= 1;
        }
        (k as usize <= values.len()).then(|| Huffman {
            maxcode,
            valptr,
            mincode,
            values: values.to_vec(),
        })
    }

    fn decode(&self, r: &mut Bits<'_>) -> Option<u8> {
        let mut code = 0i32;
        for len in 1..=16 {
            code = (code << 1) | r.bit() as i32;
            if code <= self.maxcode[len] {
                return self
                    .values
                    .get((self.valptr[len] + code - self.mincode[len]) as usize)
                    .copied();
            }
        }
        None
    }
}

/// Entropy-coded bits, unstuffed, stopping at the next marker.
struct Bits<'a> {
    data: &'a [u8],
    at: usize,
    acc: u32,
    have: u32,
    /// Hit a marker (or the end): only zeros from here.
    marker: bool,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8], at: usize) -> Bits<'a> {
        Bits {
            data,
            at,
            acc: 0,
            have: 0,
            marker: false,
        }
    }

    fn fill(&mut self) {
        while self.have <= 24 {
            let mut byte = 0;
            if !self.marker {
                match (self.data.get(self.at), self.data.get(self.at + 1)) {
                    (Some(0xFF), Some(0x00)) => {
                        byte = 0xFF;
                        self.at += 2;
                    }
                    (Some(0xFF), _) | (None, _) => self.marker = true,
                    (Some(&b), _) => {
                        byte = b;
                        self.at += 1;
                    }
                }
            }
            self.acc |= (byte as u32) << (24 - self.have);
            self.have += 8;
        }
    }

    fn bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.fill();
        let v = self.acc >> (32 - n);
        self.acc <<= n;
        self.have -= n;
        v
    }

    fn bit(&mut self) -> u32 {
        self.bits(1)
    }

    /// Past a restart marker: drop the partial byte, step over RSTn.
    fn restart(&mut self) {
        self.acc = 0;
        self.have = 0;
        self.marker = false;
        if self.data.get(self.at) == Some(&0xFF)
            && self
                .data
                .get(self.at + 1)
                .is_some_and(|m| (0xD0..=0xD7).contains(m))
        {
            self.at += 2;
        }
    }
}

/// Where the entropy-coded data starting at `at` ends: its next marker
/// that isn't a restart.
fn scan_end(bytes: &[u8], mut at: usize) -> usize {
    loop {
        match bytes
            .get(at..)
            .and_then(|b| b.iter().position(|&x| x == 0xFF))
        {
            None => return bytes.len(),
            Some(i) => at += i,
        }
        match bytes.get(at + 1) {
            Some(0x00) | Some(0xD0..=0xD7) | Some(0xFF) => at += 1,
            _ => return at,
        }
    }
}

fn extend(v: u32, s: u32) -> i32 {
    if s == 0 {
        0
    } else if v < 1 << (s - 1) {
        v as i32 - (1 << s) + 1
    } else {
        v as i32
    }
}

/// The DC image of a progressive JPEG, RGB, at 1/8 scale: `None` if it
/// can't be had (a scan missing, a table missing), for a full decode.
fn dc_image(bytes: &[u8], head: &Header<'_>) -> Option<(usize, usize, Vec<u8>)> {
    let comps = &head.components;
    let hmax = comps.iter().map(|c| c.h).max()?;
    let vmax = comps.iter().map(|c| c.v).max()?;
    let mcux = head.width.div_ceil(8 * hmax);
    let mcuy = head.height.div_ceil(8 * vmax);
    // Each component's blocks, padded to whole MCUs.
    let dims: Vec<(usize, usize)> = comps.iter().map(|c| (mcux * c.h, mcuy * c.v)).collect();
    if dims.iter().any(|(w, h)| w * h > MAX_BLOCKS) {
        return None;
    }
    let mut dc: Vec<Vec<i16>> = dims.iter().map(|(w, h)| vec![0; w * h]).collect();
    let mut seen = vec![false; comps.len()];
    let mut quant: [Option<u16>; 4] = [None; 4];
    // Each component's table as it was at its first scan, which libjpeg
    // keeps whatever's defined after.
    let mut latched: Vec<Option<u16>> = vec![None; comps.len()];
    let mut tables: [Option<Huffman>; 4] = [None, None, None, None];
    let mut restart = 0usize;
    let (mut scans, mut dc_scans) = (0, 0);

    let mut at = 2;
    loop {
        // Segments until the next scan.
        let mut sos: Option<(Vec<u8>, usize)> = None;
        segments(bytes, at, |marker, body, after| {
            match marker {
                0xDB => {
                    let mut i = 0;
                    while i < body.len() {
                        let (p, t) = (body[i] >> 4, (body[i] & 15) as usize);
                        if t > 3 {
                            return None;
                        }
                        quant[t] = Some(if p == 0 {
                            *body.get(i + 1)? as u16
                        } else {
                            u16_at(body, i + 1)? as u16
                        });
                        i += 1 + 64 * (p as usize + 1);
                    }
                }
                0xC4 => {
                    let mut i = 0;
                    while i < body.len() {
                        let (class, t) = (body[i] >> 4, (body[i] & 15) as usize);
                        let counts = body.get(i + 1..i + 17)?;
                        let n: usize = counts.iter().map(|&c| c as usize).sum();
                        let values = body.get(i + 17..i + 17 + n)?;
                        if class == 0 && t < 4 {
                            tables[t] = Some(Huffman::new(counts, values)?);
                        }
                        i += 17 + n;
                    }
                }
                0xDD => restart = u16_at(body, 0)?,
                0xDA => {
                    sos = Some((body.to_vec(), after));
                    return Some(false);
                }
                _ => {}
            }
            Some(true)
        })?;
        let Some((sos, data)) = sos else { break };
        let ns = *sos.first()? as usize;
        let spec = sos.get(1 + ns * 2..4 + ns * 2)?;
        let (ss, ah, al) = (spec[0], spec[2] >> 4, (spec[2] & 15) as u32);
        let end = scan_end(bytes, data);
        scans += 1;
        if scans > MAX_SCANS {
            return None;
        }
        let mut members = Vec::new();
        for i in 0..ns {
            let id = *sos.get(1 + i * 2)?;
            let td = (sos.get(2 + i * 2)? >> 4) as usize;
            let ci = comps.iter().position(|c| c.id == id)?;
            if latched[ci].is_none() {
                latched[ci] = Some(quant[comps[ci].tq]?);
            }
            members.push((ci, td));
        }
        if ss == 0 {
            dc_scans += 1;
            if dc_scans > MAX_DC_SCANS {
                return None;
            }
            if ah == 0
                && members
                    .iter()
                    .any(|&(_, td)| td > 3 || tables[td].is_none())
            {
                return None;
            }
            let mut r = Bits::new(bytes, data);
            let mut pred = vec![0i32; comps.len()];
            let mut count = 0usize;
            let mut unit = |r: &mut Bits<'_>,
                            pred: &mut [i32],
                            ci: usize,
                            td: usize,
                            bx: usize,
                            by: usize|
             -> Option<()> {
                let (w, _) = dims[ci];
                let slot = dc[ci].get_mut(by * w + bx)?;
                if ah == 0 {
                    let s = tables[td].as_ref()?.decode(r)? as u32;
                    if s > 11 {
                        return None;
                    }
                    let diff = extend(r.bits(s), s);
                    pred[ci] = pred[ci].wrapping_add(diff);
                    *slot = pred[ci].wrapping_shl(al) as i16;
                } else if r.bit() == 1 {
                    *slot |= 1 << al;
                }
                Some(())
            };
            if ns == 1 {
                // Not interleaved: the component's own blocks, unpadded.
                let (ci, td) = members[0];
                let c = &comps[ci];
                let bw = (head.width * c.h).div_ceil(hmax).div_ceil(8);
                let bh = (head.height * c.v).div_ceil(vmax).div_ceil(8);
                for by in 0..bh {
                    for bx in 0..bw {
                        if restart > 0 && count > 0 && count.is_multiple_of(restart) {
                            r.restart();
                            pred.iter_mut().for_each(|p| *p = 0);
                        }
                        unit(&mut r, &mut pred, ci, td, bx, by)?;
                        count += 1;
                    }
                }
            } else {
                for my in 0..mcuy {
                    for mx in 0..mcux {
                        if restart > 0 && count > 0 && count.is_multiple_of(restart) {
                            r.restart();
                            pred.iter_mut().for_each(|p| *p = 0);
                        }
                        for &(ci, td) in &members {
                            let c = &comps[ci];
                            for v in 0..c.v {
                                for h in 0..c.h {
                                    unit(&mut r, &mut pred, ci, td, mx * c.h + h, my * c.v + v)?;
                                }
                            }
                        }
                        count += 1;
                    }
                }
            }
            // Ran into the end of the file partway: not whole.
            if r.marker && r.at >= bytes.len() {
                return None;
            }
            if ah == 0 {
                for &(ci, _) in &members {
                    seen[ci] = true;
                }
            }
        }
        at = end;
        if at >= bytes.len() {
            break;
        }
    }
    if !seen.iter().all(|&s| s) {
        return None;
    }
    let quant: Vec<u16> = latched.into_iter().collect::<Option<_>>()?;

    // The average of each block, which is DC x q / 8, level-shifted.
    let ow = head.width.div_ceil(8);
    let oh = head.height.div_ceil(8);
    let value = |ci: usize, x: usize, y: usize| -> f32 {
        let c = &comps[ci];
        let (w, h) = dims[ci];
        let bx = (x * c.h / hmax).min(w - 1);
        let by = (y * c.v / vmax).min(h - 1);
        (dc[ci][by * w + bx] as f32 * quant[ci] as f32 / 8.0 + 128.0).clamp(0.0, 255.0)
    };
    let mut px = Vec::with_capacity(ow * oh * 3);
    for y in 0..oh {
        for x in 0..ow {
            let l = value(0, x, y);
            if comps.len() == 1 {
                let l = l as u8;
                px.extend_from_slice(&[l, l, l]);
            } else {
                let (cb, cr) = (value(1, x, y) - 128.0, value(2, x, y) - 128.0);
                let rgb = [
                    l + 1.402 * cr,
                    l - 0.344_136 * cb - 0.714_136 * cr,
                    l + 1.772 * cb,
                ];
                px.extend(rgb.map(|v| v.round().clamp(0.0, 255.0) as u8));
            }
        }
    }
    Some((ow, oh, px))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each DC pixel is its 8x8 block's average in a full decode, give or
    /// take rounding: with 4:2:0 chroma, and with restart markers.
    #[test]
    fn dc_image_is_the_image_at_an_eighth() {
        for bytes in [
            &include_bytes!("testdata/progressive.jpg")[..],
            &include_bytes!("testdata/progressive-restarts.jpg")[..],
        ] {
            let head = Header::parse(bytes).unwrap();
            assert!(head.progressive);
            let (w, h, px) = dc_image(bytes, &head).unwrap();
            assert_eq!((w, h), (80, 60));
            let full = image::load_from_memory(bytes).unwrap().into_rgb8();
            let mut err = 0f64;
            for y in 0..h {
                for x in 0..w {
                    for c in 0..3 {
                        let mut sum = 0u32;
                        for dy in 0..8 {
                            for dx in 0..8 {
                                sum += full.get_pixel((x * 8 + dx) as u32, (y * 8 + dy) as u32)[c]
                                    as u32;
                            }
                        }
                        err += (sum as f64 / 64.0 - px[(y * w + x) * 3 + c] as f64).abs();
                    }
                }
            }
            let mean = err / (w * h * 3) as f64;
            assert!(mean < 3.0, "mean error {mean}");
        }
    }

    #[test]
    fn truncated_or_baseline_jpegs_are_left_to_a_full_decode() {
        let bytes = include_bytes!("testdata/progressive.jpg");
        let head = Header::parse(bytes).unwrap();
        // Cut inside the first scan: the DC image isn't whole.
        let sos = bytes.windows(2).position(|w| w == [0xFF, 0xDA]).unwrap();
        assert!(dc_image(&bytes[..sos + 200], &head).is_none());
        let mut baseline = Vec::new();
        image::RgbImage::from_pixel(64, 64, image::Rgb([9, 9, 9]))
            .write_to(
                &mut std::io::Cursor::new(&mut baseline),
                image::ImageFormat::Jpeg,
            )
            .unwrap();
        assert!(!Header::parse(&baseline).unwrap().progressive);
    }

    /// `bytes` with `extra` put in before its EOI.
    fn before_eoi(bytes: &[u8], extra: &[u8]) -> Vec<u8> {
        let eoi = bytes.len() - 2;
        assert_eq!(bytes[eoi..], [0xFF, 0xD9]);
        [&bytes[..eoi], extra, &bytes[eoi..]].concat()
    }

    /// Tables redefined after the scans that use them are ignored, as
    /// libjpeg (so browsers) ignores them: else every block's average
    /// comes out ~128, a grey square that scores clean whatever it shows.
    #[test]
    fn quant_tables_are_those_of_a_components_first_scan() {
        let bytes = include_bytes!("testdata/progressive.jpg");
        let ones = [
            &[0xFF, 0xDB, 0x00, 0x84, 0x00][..],
            &[1; 64],
            &[0x01],
            &[1; 64],
        ]
        .concat();
        let late = before_eoi(bytes, &ones);
        let head = Header::parse(bytes).unwrap();
        let (_, _, want) = dc_image(bytes, &head).unwrap();
        let (_, _, got) = dc_image(&late, &Header::parse(&late).unwrap()).unwrap();
        assert!(got == want, "a late DQT changed the DC image");
    }

    /// Scans that add nothing, cheap to send and each a pass over every
    /// block, are only taken so many times.
    #[test]
    fn endless_dc_scans_are_refused() {
        let bytes = include_bytes!("testdata/progressive.jpg");
        // An interleaved DC refinement scan (Ah 1, Al 0), with no data.
        let scan = [0xFF, 0xDA, 0x00, 0x0C, 3, 1, 0, 2, 0, 3, 0, 0, 0, 0x10];
        let bomb = before_eoi(bytes, &scan.repeat(5000));
        let started = std::time::Instant::now();
        assert!(dc_image(&bomb, &Header::parse(&bomb).unwrap()).is_none());
        assert!(
            started.elapsed().as_secs_f64() < 1.0,
            "{:?}",
            started.elapsed()
        );
    }

    /// A baseline JPEG of a few bytes claiming to be 65535 pixels a side:
    /// refused from its header, not decoded block by empty block.
    #[test]
    fn huge_baseline_jpegs_are_refused_unread() {
        let mut bytes = Vec::new();
        image::RgbImage::from_pixel(64, 64, image::Rgb([9, 9, 9]))
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Jpeg,
            )
            .unwrap();
        let sof = bytes.windows(2).position(|w| w == [0xFF, 0xC0]).unwrap();
        bytes[sof + 5..sof + 9].copy_from_slice(&[0xFF; 4]);
        let sos = bytes.windows(2).position(|w| w == [0xFF, 0xDA]).unwrap();
        let len = ((bytes[sos + 2] as usize) << 8) | bytes[sos + 3] as usize;
        bytes.truncate(sos + 2 + len);
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        let started = std::time::Instant::now();
        assert!(squares_scaled(&bytes, &mut Vec::new()).is_err());
        assert!(
            started.elapsed().as_secs_f64() < 1.0,
            "{:?}",
            started.elapsed()
        );
    }

    /// An Adobe segment saying "RGB" after the frame header still counts,
    /// as libjpeg reads it: else RGB is taken for YCbCr, colours scrambled.
    #[test]
    fn segments_after_the_frame_header_count() {
        let bytes = include_bytes!("testdata/progressive.jpg");
        let sof = bytes.windows(2).position(|w| w == [0xFF, 0xC2]).unwrap();
        let after = sof + 2 + (((bytes[sof + 2] as usize) << 8) | bytes[sof + 3] as usize);
        let adobe = b"\xFF\xEE\x00\x0EAdobe\x00\x64\x00\x00\x00\x00\x00";
        let b = [&bytes[..after], &adobe[..], &bytes[after..]].concat();
        assert!(Header::parse(&b).is_none(), "RGB is left to a full decode");
    }

    /// Corrupted and cut-short JPEGs: never a panic, never a hang.
    #[test]
    fn survives_corruption() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for original in [
            &include_bytes!("testdata/progressive.jpg")[..],
            &include_bytes!("testdata/progressive-restarts.jpg")[..],
        ] {
            for _ in 0..1500 {
                let mut b = original.to_vec();
                for _ in 0..1 + next() % 8 {
                    let i = (next() % b.len() as u64) as usize;
                    b[i] = next() as u8;
                }
                if next() % 4 == 0 {
                    b.truncate((next() % b.len() as u64) as usize);
                }
                if let Some(head) = Header::parse(&b) {
                    let _ = dc_image(&b, &head);
                }
                if next() % 8 == 0 {
                    let _ = super::super::pixels::decode(&b, "image/jpeg");
                }
            }
        }
    }
}
