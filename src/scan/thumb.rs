//! Small pictures of stored media, for the dashboard: a page of them comes
//! from this server's own disk, a few KB each, rather than every file at
//! full size through whatever is in front of `public_url`.
//!
//! Each is a JPEG of what a viewer would see first, fitting a square of one
//! of [`SIDES`]: an image upright by its EXIF orientation, transparency
//! laid over white, an animation's first frame, and a video's first
//! keyframe, by ffmpeg, confined as for a scan. Bytes that are no kind of
//! media get none, and neither do those that won't decode, which is how the
//! dashboard knows an encrypted attachment from a picture.

use std::io::Cursor;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use fast_image_resize::images::{Image, ImageRef};
use fast_image_resize::{FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer};
use image::{DynamicImage, ImageDecoder, RgbImage, metadata::Orientation};

use super::{HEAD, Input, Kind, ffmpeg, pixels};

/// The squares a thumbnail fits: a tile in the grid, and a picture to judge.
pub const SIDES: [u32; 2] = [400, 1280];
const QUALITY: u8 = 80;
/// How long ffmpeg may take over a video's thumbnail.
const POSTER_TIMEOUT: Duration = Duration::from_secs(20);

/// [`make`], a decoder's panic made an error.
pub fn make_safely(input: &Input, side: u32, ffmpeg: Option<&Path>) -> Result<Option<Vec<u8>>> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| make(input, side, ffmpeg)))
        .unwrap_or_else(|_| Err(anyhow::anyhow!("a decoder panicked")))
}

/// A JPEG of the blob fitting a `side` square, or `None` if it's no kind of
/// media. Video, and the images only ffmpeg reads, need `ffmpeg`.
pub fn make(input: &Input, side: u32, ffmpeg: Option<&Path>) -> Result<Option<Vec<u8>>> {
    let mapped;
    let bytes: &[u8] = match input {
        Input::Bytes(b) => b,
        Input::File(p) => {
            mapped = super::map(p)?;
            &mapped
        }
    };
    let head = &bytes[..bytes.len().min(HEAD)];
    let ty = crate::mime::sniff(head);
    let kind = match super::kind(ty.as_deref()) {
        Kind::Other if crate::mime::is_iso_bmff(head) => Kind::Video,
        k => k,
    };
    match kind {
        Kind::Other => Ok(None),
        Kind::Image => {
            let (w, h, px, orientation) = match ty.as_deref() {
                Some("image/jpeg") => match scaled_jpeg(bytes, side) {
                    Some(d) => d,
                    None => decoded(bytes)?,
                },
                _ => decoded(bytes)?,
            };
            encode(w, h, &px, orientation, side).map(Some)
        }
        Kind::Video => {
            let ff = ffmpeg.context("there's no ffmpeg to read it with")?;
            let src = match input {
                Input::File(p) => ffmpeg::Input::File(p),
                Input::Bytes(b) => ffmpeg::Input::Bytes(b),
            };
            ffmpeg::poster(ff, src, side, Instant::now() + POSTER_TIMEOUT).map(Some)
        }
    }
}

/// RGB pixels, their width and height, and how to turn them upright.
type Decoded = (u32, u32, Vec<u8>, Orientation);

/// A JPEG decoded at the smallest of 1/8, 1/4, 1/2 or full size that's at
/// least the thumbnail's: a phone's photo is read at an eighth of its
/// pixels. `None` for one this decoder won't read, left to the other.
fn scaled_jpeg(bytes: &[u8], side: u32) -> Option<Decoded> {
    let orientation = image::codecs::jpeg::JpegDecoder::new(Cursor::new(bytes))
        .ok()
        .and_then(|mut d| d.orientation().ok())
        .unwrap_or(Orientation::NoTransforms);
    let mut d = jpeg_decoder::Decoder::new(bytes);
    d.read_info().ok()?;
    let info = d.info()?;
    pixels::check_size((info.width as u32, info.height as u32)).ok()?;
    let (tw, th) = fit(info.width as u32, info.height as u32, side);
    let (w, h) = d.scale(tw as u16, th as u16).ok()?;
    let px = d.decode().ok()?;
    let px = match d.info()?.pixel_format {
        jpeg_decoder::PixelFormat::RGB24 => px,
        jpeg_decoder::PixelFormat::L8 => px.iter().flat_map(|&v| [v, v, v]).collect(),
        _ => return None,
    };
    (px.len() == w as usize * h as usize * 3).then_some((w as u32, h as u32, px, orientation))
}

/// Any image the `image` crate reads, its first frame, over white.
fn decoded(bytes: &[u8]) -> Result<Decoded> {
    let mut d = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()?
        .into_decoder()?;
    pixels::check_size(d.dimensions())?;
    d.set_limits(pixels::limits())?;
    let orientation = d.orientation().unwrap_or(Orientation::NoTransforms);
    let img = DynamicImage::from_decoder(d)?;
    let (w, h) = (img.width(), img.height());
    let px = if img.color().has_alpha() {
        img.into_rgba8()
            .chunks_exact(4)
            .flat_map(|p| {
                let a = p[3] as u32;
                let over = |c: u8| ((c as u32 * a + 255 * (255 - a) + 127) / 255) as u8;
                [over(p[0]), over(p[1]), over(p[2])]
            })
            .collect()
    } else {
        img.into_rgb8().into_raw()
    };
    Ok((w, h, px, orientation))
}

/// The largest size, `w` by `h` in proportion, fitting a `side` square and
/// no larger than it is.
fn fit(w: u32, h: u32, side: u32) -> (u32, u32) {
    let long = w.max(h);
    if long <= side {
        return (w.max(1), h.max(1));
    }
    let scale = |v: u32| ((v as u64 * side as u64).div_ceil(long as u64) as u32).max(1);
    (scale(w), scale(h))
}

/// Shrunk to fit, turned upright, as a JPEG. Turning comes last, on the
/// small picture: fitting a square doesn't care which way up it is.
fn encode(w: u32, h: u32, px: &[u8], orientation: Orientation, side: u32) -> Result<Vec<u8>> {
    let (tw, th) = fit(w, h, side);
    let small = if (tw, th) == (w, h) {
        px.to_vec()
    } else {
        let src = ImageRef::new(w, h, px, PixelType::U8x3)?;
        let mut dst = Image::new(tw, th, PixelType::U8x3);
        let options = ResizeOptions::new().resize_alg(ResizeAlg::Convolution(FilterType::Lanczos3));
        Resizer::new().resize(&src, &mut dst, &options)?;
        dst.into_vec()
    };
    let mut img = DynamicImage::ImageRgb8(
        RgbImage::from_raw(tw, th, small).context("the pixels aren't the picture's size")?,
    );
    img.apply_orientation(orientation);
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, QUALITY).encode(
        img.as_bytes(),
        img.width(),
        img.height(),
        image::ExtendedColorType::Rgb8,
    )?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn size(jpeg: &[u8]) -> (u32, u32) {
        let d = image::codecs::jpeg::JpegDecoder::new(Cursor::new(jpeg)).unwrap();
        d.dimensions()
    }

    fn png(w: u32, h: u32, alpha: bool) -> Vec<u8> {
        let img = if alpha {
            DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
                w,
                h,
                image::Rgba([200, 0, 0, 0]),
            ))
        } else {
            DynamicImage::ImageRgb8(RgbImage::from_pixel(w, h, image::Rgb([200, 0, 0])))
        };
        let mut out = Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    #[test]
    fn fits_the_square_keeping_proportions() {
        assert_eq!(fit(4000, 3000, 400), (400, 300));
        assert_eq!(fit(1000, 4000, 400), (100, 400));
        assert_eq!(fit(300, 200, 400), (300, 200), "never larger");
        assert_eq!(fit(10_000, 1, 400), (400, 1));
    }

    #[test]
    fn makes_jpegs_of_pictures_and_nothing_of_the_rest() {
        let wide = Input::Bytes(png(1600, 900, false).into());
        let t = make(&wide, 400, None).unwrap().unwrap();
        assert_eq!(size(&t), (400, 225));

        // A JPEG, read scaled down.
        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut jpeg)
            .encode(
                &vec![90u8; 2000 * 1000 * 3],
                2000,
                1000,
                image::ExtendedColorType::Rgb8,
            )
            .unwrap();
        let t = make(&Input::Bytes(jpeg.into()), 1280, None)
            .unwrap()
            .unwrap();
        assert_eq!(size(&t), (1280, 640));

        // Transparent: laid over white, not black.
        let clear = make(&Input::Bytes(png(50, 50, true).into()), 400, None)
            .unwrap()
            .unwrap();
        let px = image::load_from_memory(&clear).unwrap().into_rgb8();
        assert!(px.get_pixel(25, 25).0.iter().all(|&c| c > 240));

        assert!(
            make(
                &Input::Bytes(b"just some text".as_slice().into()),
                400,
                None
            )
            .unwrap()
            .is_none()
        );
        // Claims to be a PNG, and isn't one: an error, not a picture.
        let mut fake = png(10, 10, false);
        fake.truncate(40);
        fake.extend([0x55; 64]);
        assert!(make(&Input::Bytes(fake.into()), 400, None).is_err());
    }
}
