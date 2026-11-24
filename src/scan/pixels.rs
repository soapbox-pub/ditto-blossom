//! From an image's bytes to the squares the encoder looks at.
//!
//! What's scanned is what a viewer would see: the image turned upright by
//! its EXIF orientation, transparent pixels laid over both white and black
//! (a picture hidden in the alpha channel shows on one or the other), every
//! part of a long image (a strip squashed into a square hides what's in it),
//! and frames from across an animation, not only its first.

use std::io::Cursor;

use anyhow::{Result, bail};
use fast_image_resize::images::{Image, ImageRef};
use fast_image_resize::{FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer};
use image::{AnimationDecoder, ImageDecoder, Limits, metadata::Orientation};

use super::model::SIDE;

/// One square, RGB, row by row.
pub type Square = Vec<u8>;

pub const SQUARE_LEN: usize = SIDE * SIDE * 3;

/// The most pixels decoded at full size. A JPEG this big is decoded at a
/// fraction of its size instead (see [`jpeg`]), so this bounds the rest.
pub const MAX_PIXELS: u64 = 64 << 20;
/// A long image's side this many times its other is scanned in pieces too.
const LONG: f64 = 1.6;
/// The most square pieces a long image is scanned in, beside the whole.
const MAX_TILES: usize = 4;
/// Frames of an animation scanned, at most, spread across it.
pub const MAX_FRAMES: usize = 6;
/// Pixels of animation frames decoded before the rest are let go.
const MAX_FRAME_PIXELS: u64 = 400 << 20;

pub(super) fn limits() -> Limits {
    let mut l = Limits::default();
    l.max_alloc = Some(MAX_PIXELS * 4 + (16 << 20));
    l
}

fn options() -> ResizeOptions {
    // Catmull-Rom is bicubic, as CLIP was trained on.
    ResizeOptions::new().resize_alg(ResizeAlg::Convolution(FilterType::CatmullRom))
}

/// Pixels of any layout, before they're made squares.
pub struct Raster<'a> {
    pub width: u32,
    pub height: u32,
    /// RGB or RGBA, row by row.
    pub pixels: &'a [u8],
    pub alpha: bool,
}

/// The squares for one picture: the whole, squashed, and if it's long, its
/// square pieces; each twice over if it's partly transparent.
pub fn squares(
    r: &Raster<'_>,
    orientation: Orientation,
    tiles: bool,
    out: &mut Vec<Square>,
) -> Result<()> {
    let (w, h) = (r.width, r.height);
    if w == 0 || h == 0 {
        bail!("an empty image");
    }
    let pixel = if r.alpha {
        PixelType::U8x4
    } else {
        PixelType::U8x3
    };
    let see_through = r.alpha && r.pixels.chunks_exact(4).any(|p| p[3] != 255);
    // Whole-pixel (left, top, side) pieces, copied out before resizing:
    // fast_image_resize 6.1's AVX2 RGBA kernel reads out of bounds given a
    // fractional crop box, so its cropping is never used.
    let mut crops = vec![None];
    let (long, short) = (w.max(h), w.min(h));
    if tiles && long as f64 / short as f64 > LONG {
        let n = long.div_ceil(short).min(MAX_TILES as u32);
        for i in 0..n {
            let at = ((long - short) as u64 * i as u64 / (n - 1) as u64) as u32;
            crops.push(Some(if w > h { (at, 0) } else { (0, at) }));
        }
    }
    let bpp = pixel.size();
    let mut resizer = Resizer::new();
    for crop in crops {
        let piece;
        let src = match crop {
            None => ImageRef::new(w, h, r.pixels, pixel)?,
            Some((left, top)) => {
                let row = w as usize * bpp;
                piece = (top..top + short)
                    .flat_map(|y| {
                        let at = y as usize * row + left as usize * bpp;
                        &r.pixels[at..at + short as usize * bpp]
                    })
                    .copied()
                    .collect::<Vec<u8>>();
                ImageRef::new(short, short, &piece, pixel)?
            }
        };
        let mut dst = Image::new(SIDE as u32, SIDE as u32, pixel);
        resizer.resize(&src, &mut dst, &options())?;
        let px = dst.into_vec();
        if !r.alpha {
            out.push(orient(px, orientation));
        } else if !see_through {
            out.push(orient(drop_alpha(&px, None), orientation));
        } else {
            out.push(orient(drop_alpha(&px, Some(255)), orientation));
            out.push(orient(drop_alpha(&px, Some(0)), orientation));
        }
    }
    Ok(())
}

/// RGBA to RGB, laid over a grey of `under` (or with alpha ignored).
fn drop_alpha(rgba: &[u8], under: Option<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(rgba.len() / 4 * 3);
    for p in rgba.chunks_exact(4) {
        match under {
            None => out.extend_from_slice(&p[..3]),
            Some(bg) => {
                let a = p[3] as u32;
                for &c in &p[..3] {
                    out.push(((c as u32 * a + bg as u32 * (255 - a) + 127) / 255) as u8);
                }
            }
        }
    }
    out
}

/// Turn a square upright. Squashing then turning is the same as turning
/// then squashing, so this happens on the small square, not the image.
pub fn orient(px: Square, o: Orientation) -> Square {
    if o == Orientation::NoTransforms {
        return px;
    }
    let n = SIDE;
    let mut out = vec![0u8; px.len()];
    for y in 0..n {
        for x in 0..n {
            // Where the upright pixel (x, y) comes from.
            let (sx, sy) = match o {
                Orientation::NoTransforms => (x, y),
                Orientation::Rotate90 => (y, n - 1 - x),
                Orientation::Rotate180 => (n - 1 - x, n - 1 - y),
                Orientation::Rotate270 => (n - 1 - y, x),
                Orientation::FlipHorizontal => (n - 1 - x, y),
                Orientation::FlipVertical => (x, n - 1 - y),
                Orientation::Rotate90FlipH => (y, x),
                Orientation::Rotate270FlipH => (n - 1 - y, n - 1 - x),
            };
            let (d, s) = ((y * n + x) * 3, (sy * n + sx) * 3);
            out[d..d + 3].copy_from_slice(&px[s..s + 3]);
        }
    }
    out
}

/// Squares for an image the `image` crate reads: JPEG, PNG and APNG, GIF,
/// WebP, BMP, TIFF, ICO.
pub fn decode(bytes: &[u8], mime: &str) -> Result<Vec<Square>> {
    let mut out = Vec::new();
    match mime {
        "image/jpeg" => {
            if !super::jpeg::squares_scaled(bytes, &mut out)? {
                still(
                    image::codecs::jpeg::JpegDecoder::new(Cursor::new(bytes))?,
                    &mut out,
                )?;
            }
        }
        "image/png" | "image/apng" => {
            let mut d = image::codecs::png::PngDecoder::new(Cursor::new(bytes))?;
            if d.is_apng()? {
                check_size(d.dimensions())?;
                d.set_limits(limits())?;
                frames(d.apng()?, &mut out)?;
            } else {
                still(d, &mut out)?;
            }
        }
        "image/gif" => {
            let mut d = image::codecs::gif::GifDecoder::new(Cursor::new(bytes))?;
            check_size(d.dimensions())?;
            d.set_limits(limits())?;
            frames(d, &mut out)?;
        }
        "image/webp" => {
            let mut d = image::codecs::webp::WebPDecoder::new(Cursor::new(bytes))?;
            if d.has_animation() {
                check_size(d.dimensions())?;
                d.set_limits(limits())?;
                frames(d, &mut out)?;
            } else {
                still(d, &mut out)?;
            }
        }
        _ => {
            let reader = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
            still(reader.into_decoder()?, &mut out)?;
        }
    }
    Ok(out)
}

pub(super) fn check_size((w, h): (u32, u32)) -> Result<()> {
    if w as u64 * h as u64 > MAX_PIXELS {
        bail!("{w}x{h} is more pixels than are decoded");
    }
    Ok(())
}

fn still(mut d: impl ImageDecoder, out: &mut Vec<Square>) -> Result<()> {
    check_size(d.dimensions())?;
    d.set_limits(limits())?;
    let orientation = d.orientation().unwrap_or(Orientation::NoTransforms);
    let img = image::DynamicImage::from_decoder(d)?;
    let (width, height) = (img.width(), img.height());
    if img.color().has_alpha() {
        let px = img.into_rgba8();
        squares(
            &Raster {
                width,
                height,
                pixels: &px,
                alpha: true,
            },
            orientation,
            true,
            out,
        )
    } else {
        let px = img.into_rgb8();
        squares(
            &Raster {
                width,
                height,
                pixels: &px,
                alpha: false,
            },
            orientation,
            true,
            out,
        )
    }
}

/// Frames spread across an animation, however long: every frame is kept
/// until there are too many, then every other, and so on, so what's left is
/// evenly spaced whatever the count.
fn frames<'a>(d: impl AnimationDecoder<'a>, out: &mut Vec<Square>) -> Result<()> {
    let mut kept: Vec<Vec<Square>> = Vec::new();
    let (mut stride, mut decoded) = (1usize, 0u64);
    for (i, frame) in d.into_frames().enumerate() {
        let frame = match frame {
            Ok(f) => f,
            // A broken frame after good ones ends the animation, as it does
            // for a browser; with none good, it's undecodable.
            Err(e) if kept.is_empty() => return Err(e.into()),
            Err(_) => break,
        };
        let buf = frame.into_buffer();
        decoded += buf.width() as u64 * buf.height() as u64;
        if i % stride == 0 {
            let mut sq = Vec::new();
            let r = Raster {
                width: buf.width(),
                height: buf.height(),
                pixels: buf.as_raw(),
                alpha: true,
            };
            // An animation's frames aren't tiled: the frames cost enough.
            squares(&r, Orientation::NoTransforms, false, &mut sq)?;
            kept.push(sq);
            if kept.len() > MAX_FRAMES {
                kept = kept.into_iter().step_by(2).collect();
                stride *= 2;
            }
        }
        if decoded > MAX_FRAME_PIXELS {
            break;
        }
    }
    if kept.is_empty() {
        bail!("an animation without frames");
    }
    out.extend(kept.into_iter().flatten());
    Ok(())
}

/// Read an EXIF orientation from a JPEG's APP1 segment.
pub fn exif_orientation(exif: &[u8]) -> Orientation {
    Orientation::from_exif_chunk(exif).unwrap_or(Orientation::NoTransforms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orientation_turns_the_square() {
        let mut px = vec![0u8; SQUARE_LEN];
        // A mark at the top right.
        let at = (SIDE - 1) * 3;
        px[at] = 9;
        let r = orient(px.clone(), Orientation::Rotate90);
        // Turned clockwise, the top right goes to the bottom right.
        assert_eq!(r[((SIDE - 1) * SIDE + SIDE - 1) * 3], 9);
        let r = orient(px.clone(), Orientation::Rotate180);
        assert_eq!(r[(SIDE - 1) * SIDE * 3], 9);
        let r = orient(px, Orientation::FlipHorizontal);
        assert_eq!(r[0], 9);
    }

    #[test]
    fn long_images_are_tiled_and_transparency_doubled() {
        let (w, h) = (400u32, 1600u32);
        let rgb = vec![128u8; (w * h * 3) as usize];
        let mut out = Vec::new();
        squares(
            &Raster {
                width: w,
                height: h,
                pixels: &rgb,
                alpha: false,
            },
            Orientation::NoTransforms,
            true,
            &mut out,
        )
        .unwrap();
        assert_eq!(out.len(), 1 + 4);
        assert!(out.iter().all(|s| s.len() == SQUARE_LEN));

        let mut rgba = [200u8, 200, 200, 255].repeat(100 * 100);
        rgba[3] = 0;
        let mut out = Vec::new();
        squares(
            &Raster {
                width: 100,
                height: 100,
                pixels: &rgba,
                alpha: true,
            },
            Orientation::NoTransforms,
            true,
            &mut out,
        )
        .unwrap();
        assert_eq!(out.len(), 2, "over white and over black");
        rgba[3] = 255;
        let mut out = Vec::new();
        squares(
            &Raster {
                width: 100,
                height: 100,
                pixels: &rgba,
                alpha: true,
            },
            Orientation::NoTransforms,
            true,
            &mut out,
        )
        .unwrap();
        assert_eq!(out.len(), 1, "opaque: once");
    }

    /// A long RGBA image whose pieces don't start on whole pixels once
    /// divided evenly: crashed fast_image_resize when it did the cropping.
    #[test]
    fn long_transparent_images_with_uneven_pieces() {
        let (w, h) = (426u32, 128u32);
        let rgba: Vec<u8> = (0..w * h * 4)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let mut out = Vec::new();
        let r = Raster {
            width: w,
            height: h,
            pixels: &rgba,
            alpha: true,
        };
        squares(&r, Orientation::NoTransforms, true, &mut out).unwrap();
        assert_eq!(out.len(), 2 * (1 + 4));
    }

    #[test]
    fn animations_keep_frames_spread_across() {
        let mut gif = Vec::new();
        {
            let mut enc = image::codecs::gif::GifEncoder::new(&mut gif);
            let frames = (0..40u8).map(|i| {
                image::Frame::new(image::RgbaImage::from_pixel(
                    8,
                    8,
                    image::Rgba([i * 6, 0, 0, 255]),
                ))
            });
            enc.encode_frames(frames).unwrap();
        }
        let squares = decode(&gif, "image/gif").unwrap();
        assert!(
            (MAX_FRAMES / 2..=MAX_FRAMES).contains(&squares.len()),
            "{}",
            squares.len()
        );
        // The last kept frame is from late in the animation.
        let last = squares.last().unwrap()[0];
        assert!(last >= 32 * 6 - 6, "{last}");
    }
}
