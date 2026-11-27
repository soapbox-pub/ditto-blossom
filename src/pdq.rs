//! PDQ, Meta's perceptual hash: images that look alike hash alike, so a
//! resized or recompressed copy of a known image still matches it. This is
//! what Arachnid Shield is asked about (see `scan`), so the images
//! themselves never leave the server.
//!
//! The hashing is the pdqhash crate's (Apache-2.0,
//! <https://github.com/darwinium-com/pdqhash>), which matches Meta's
//! reference bit for bit, taken in here so images are decoded by a current
//! `image`, with limits, rather than the 2021 one that crate pins.

#![allow(clippy::needless_range_loop)] // Matrix arithmetic reads best indexed.

use std::io::{BufRead, Seek};

use image::{DynamicImage, ImageFormat, ImageReader, Limits};

mod dct;

const LUMA_FROM_R: f32 = 0.299;
const LUMA_FROM_G: f32 = 0.587;
const LUMA_FROM_B: f32 = 0.114;

/// Smaller than this either way, an image says too little to hash.
const MIN_DIM: u32 = 5;
/// Larger images are scaled to this first, as the pdqhash crate and Meta's
/// tools do: far quicker, and close enough for matching.
const DOWNSAMPLE: u32 = 512;
const JAROSZ_PASSES: usize = 2;
const BUFFER_W_H: usize = 64;
const DCT_OUTPUT_W_H: usize = 16;
const DCT_OUTPUT_SIZE: usize = DCT_OUTPUT_W_H * DCT_OUTPUT_W_H;
pub const HASH_LEN: usize = DCT_OUTPUT_SIZE / 8;

/// Past these, an image isn't decoded: a few kilobytes can claim to be
/// gigapixels.
const MAX_DIM: u32 = 20_000;
const MAX_ALLOC: u64 = 512 << 20;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pdq {
    pub hash: [u8; HASH_LEN],
    /// 0 to 1: how much detail there was to hash. Flat images hash poorly.
    pub quality: f32,
}

impl Pdq {
    pub fn base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.hash)
    }
}

/// The formats hashed: what a Blossom server is mostly sent, that `image`
/// decodes in pure Rust.
fn hashable(f: ImageFormat) -> bool {
    matches!(
        f,
        ImageFormat::Jpeg
            | ImageFormat::Png
            | ImageFormat::WebP
            | ImageFormat::Gif
            | ImageFormat::Bmp
    )
}

/// Whether the bytes begin like an image this hashes.
pub fn looks_hashable(head: &[u8]) -> bool {
    image::guess_format(head).is_ok_and(hashable)
}

/// The PDQ of an image, by its contents, whatever its name or declared
/// type; `Ok(None)` if it isn't an image this hashes, or is too small.
/// An animation is hashed by its first frame.
pub fn of(reader: impl BufRead + Seek) -> Result<Option<Pdq>, image::ImageError> {
    let mut r = ImageReader::new(reader).with_guessed_format()?;
    if !r.format().is_some_and(hashable) {
        return Ok(None);
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIM);
    limits.max_image_height = Some(MAX_DIM);
    limits.max_alloc = Some(MAX_ALLOC);
    r.limits(limits);
    Ok(of_image(&r.decode()?))
}

pub fn of_image(img: &DynamicImage) -> Option<Pdq> {
    if img.width() < MIN_DIM || img.height() < MIN_DIM {
        return None;
    }
    let small;
    let img = if img.width() > DOWNSAMPLE || img.height() > DOWNSAMPLE {
        small = img.thumbnail_exact(DOWNSAMPLE.min(img.width()), DOWNSAMPLE.min(img.height()));
        &small
    } else {
        img
    };
    let (w, h) = (img.width() as usize, img.height() as usize);
    let mut luma: Vec<f32> = img
        .to_rgb8()
        .pixels()
        .map(|p| p[0] as f32 * LUMA_FROM_R + p[1] as f32 * LUMA_FROM_G + p[2] as f32 * LUMA_FROM_B)
        .collect();
    Some(of_luma(&mut luma, w, h))
}

/// PDQ of a luma image, `w` by `h`, row-major. Blurs it in place.
fn of_luma(luma: &mut [f32], w: usize, h: usize) -> Pdq {
    let window_rows = jarosz_window(w, BUFFER_W_H);
    let window_cols = jarosz_window(h, BUFFER_W_H);
    jarosz_filter(luma, h, w, window_rows, window_cols, JAROSZ_PASSES);
    let buf = decimate(luma, h, w);
    let dct = dct64_to_16(&buf);
    Pdq {
        hash: to_bits(&dct),
        quality: quality(&buf),
    }
}

fn jarosz_window(old: usize, new: usize) -> usize {
    old.div_ceil(2 * new)
}

fn jarosz_filter(buf: &mut [f32], rows: usize, cols: usize, wr: usize, wc: usize, reps: usize) {
    let mut tmp = vec![0.0; buf.len()];
    for _ in 0..reps {
        for i in 0..rows {
            box_1d(buf, i * cols, &mut tmp, cols, 1, wr);
        }
        for j in 0..cols {
            box_1d(&tmp, j, buf, rows, cols, wc);
        }
    }
}

#[inline(always)]
fn box_1d(input: &[f32], start: usize, out: &mut [f32], len: usize, stride: usize, window: usize) {
    let half = (window + 2) / 2; // 7→4, 8→5
    let p1 = half - 1;
    let p2 = window - half + 1;
    let oi_off = p1 * stride;
    let li_off = p2 * stride;
    let (mut sum, mut n) = (0.0f32, 0.0f32);
    let p1_end = oi_off + start;
    for ri in (start..p1_end).step_by(stride) {
        sum += input[ri];
        n += 1.0;
    }
    let p2_end = window * stride + start;
    for ri in (p1_end..p2_end).step_by(stride) {
        sum += input[ri];
        n += 1.0;
        out[ri - oi_off] = sum / n;
    }
    let p3_end = len * stride + start;
    for ri in (p2_end..p3_end).step_by(stride) {
        let oi = ri - oi_off;
        sum += input[ri];
        sum -= input[oi - li_off];
        out[oi] = sum / n;
    }
    let p4_start = (len - half + 1) * stride + start;
    for oi in (p4_start..p3_end).step_by(stride) {
        sum -= input[oi - li_off];
        n -= 1.0;
        out[oi] = sum / n;
    }
}

fn decimate(input: &[f32], rows: usize, cols: usize) -> [[f32; BUFFER_W_H]; BUFFER_W_H] {
    let mut out = [[0.0; BUFFER_W_H]; BUFFER_W_H];
    for (i, row) in out.iter_mut().enumerate() {
        let ini = ((i * 2 + 1) * rows) / (BUFFER_W_H * 2);
        for (j, v) in row.iter_mut().enumerate() {
            let inj = ((j * 2 + 1) * cols) / (BUFFER_W_H * 2);
            *v = input[ini * cols + inj];
        }
    }
    out
}

fn quality(buf: &[[f32; BUFFER_W_H]; BUFFER_W_H]) -> f32 {
    let mut sum = 0.0;
    for i in 0..BUFFER_W_H - 1 {
        for j in 0..BUFFER_W_H {
            sum += ((buf[i][j] - buf[i + 1][j]) / 255.).abs();
        }
    }
    for row in buf {
        for j in 0..BUFFER_W_H - 1 {
            sum += ((row[j] - row[j + 1]) / 255.).abs();
        }
    }
    (sum / 90.).min(1.0)
}

fn dct64_to_16(input: &[[f32; BUFFER_W_H]; BUFFER_W_H]) -> [f32; DCT_OUTPUT_SIZE] {
    let mut mid = [[0.0; BUFFER_W_H]; DCT_OUTPUT_W_H];
    for i in 0..DCT_OUTPUT_W_H {
        for j in 0..BUFFER_W_H {
            let mut s = 0.0;
            for (k, row) in input.iter().enumerate() {
                s += f32::from_bits(dct::DCT_MATRIX[i][k]) * row[j];
            }
            mid[i][j] = s;
        }
    }
    let mut out = [0.0; DCT_OUTPUT_SIZE];
    for i in 0..DCT_OUTPUT_W_H {
        for j in 0..DCT_OUTPUT_W_H {
            let mut s = 0.0;
            for k in 0..BUFFER_W_H {
                s += mid[i][k] * f32::from_bits(dct::DCT_MATRIX[j][k]);
            }
            out[i * DCT_OUTPUT_W_H + j] = s;
        }
    }
    out
}

/// Torben's median: no sorting, no allocation.
fn median(m: &[f32]) -> f32 {
    let mut min = m.iter().copied().fold(f32::INFINITY, f32::min);
    let mut max = m.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let half = m.len().div_ceil(2);
    loop {
        let guess = (min + max) / 2.0;
        let (mut less, mut greater, mut equal) = (0, 0, 0);
        let (mut below, mut above) = (min, max);
        for &v in m {
            if v < guess {
                less += 1;
                below = below.max(v);
            } else if v > guess {
                greater += 1;
                above = above.min(v);
            } else {
                equal += 1;
            }
        }
        if less <= half && greater <= half {
            return if less >= half {
                below
            } else if less + equal >= half {
                guess
            } else {
                above
            };
        } else if less > greater {
            max = below;
        } else {
            min = above;
        }
    }
}

fn to_bits(dct: &[f32; DCT_OUTPUT_SIZE]) -> [u8; HASH_LEN] {
    let med = median(dct);
    let mut hash = [0; HASH_LEN];
    for i in 0..HASH_LEN {
        let mut byte = 0;
        for j in 0..8 {
            if dct[i * 8 + j] > med {
                byte |= 1 << j;
            }
        }
        hash[HASH_LEN - i - 1] = byte;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_size(data: &[u8]) -> String {
        let img = image::load_from_memory(data).unwrap();
        let (w, h) = (img.width() as usize, img.height() as usize);
        let mut luma: Vec<f32> = img
            .to_rgb8()
            .pixels()
            .map(|p| {
                p[0] as f32 * LUMA_FROM_R + p[1] as f32 * LUMA_FROM_G + p[2] as f32 * LUMA_FROM_B
            })
            .collect();
        hex::encode(of_luma(&mut luma, w, h).hash)
    }

    /// The pdqhash crate's vectors, which match Meta's reference.
    #[test]
    fn matches_the_reference() {
        assert_eq!(
            full_size(include_bytes!("../tests/pdq/bridge-1-original.jpg")),
            "f8f8f0cee0f4a84f06370a22038f63f0b36e2ed596621e1d33e6b39c4e9c9b22"
        );
        assert_eq!(
            full_size(include_bytes!("../tests/pdq/bridge-5-flipx.jpg")),
            "f8f80f31e0f417b20e37f5cd028f980fb36ed02a9662c1e233e64c634e9c64dd"
        );
    }

    fn distance(a: &[u8; HASH_LEN], b: &[u8; HASH_LEN]) -> u32 {
        a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
    }

    /// Scaling first, and recompressing, keep a hash well within the 31
    /// bits PDQ matching allows.
    #[test]
    fn survives_downsampling_and_recompression() {
        let data = include_bytes!("../tests/pdq/bridge-1-original.jpg");
        let reference: [u8; HASH_LEN] =
            hex::decode("f8f8f0cee0f4a84f06370a22038f63f0b36e2ed596621e1d33e6b39c4e9c9b22")
                .unwrap()
                .try_into()
                .unwrap();
        let ours = of(std::io::Cursor::new(&data[..])).unwrap().unwrap();
        assert!(
            distance(&ours.hash, &reference) <= 16,
            "{}",
            distance(&ours.hash, &reference)
        );
        assert!(ours.quality > 0.5);

        let img = image::load_from_memory(data).unwrap().resize(
            300,
            300,
            image::imageops::FilterType::Triangle,
        );
        let mut png = Vec::new();
        img.write_to(&mut std::io::Cursor::new(&mut png), ImageFormat::Png)
            .unwrap();
        let small = of(std::io::Cursor::new(&png[..])).unwrap().unwrap();
        assert!(
            distance(&small.hash, &reference) <= 31,
            "{}",
            distance(&small.hash, &reference)
        );
    }

    #[test]
    fn skips_what_it_doesnt_hash() {
        assert!(
            of(std::io::Cursor::new(&b"hello, not an image"[..]))
                .unwrap()
                .is_none()
        );
        assert!(!looks_hashable(b"\x00\x00\x00\x18ftypmp42"));
        assert!(looks_hashable(
            &include_bytes!("../tests/pdq/bridge-1-original.jpg")[..64]
        ));
        let tiny = DynamicImage::new_rgb8(3, 3);
        assert!(of_image(&tiny).is_none());
    }

    #[test]
    fn refuses_claimed_giants() {
        // A PNG header claiming 100000 x 100000 pixels.
        let mut png = Vec::new();
        image::DynamicImage::new_rgb8(8, 8)
            .write_to(&mut std::io::Cursor::new(&mut png), ImageFormat::Png)
            .unwrap();
        png[16..20].copy_from_slice(&100_000u32.to_be_bytes());
        png[20..24].copy_from_slice(&100_000u32.to_be_bytes());
        assert!(of(std::io::Cursor::new(&png[..])).is_err());
    }
}
