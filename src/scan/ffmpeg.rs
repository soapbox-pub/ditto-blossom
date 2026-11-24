//! Video, and the image formats the `image` crate doesn't read (AVIF, HEIC,
//! JPEG XL), through ffmpeg: frames spread across the whole length, read
//! back as raw squares of the encoder's size.
//!
//! Only keyframes are decoded, so a long video costs about what its
//! demuxing does rather than a full decode. ffmpeg turns frames upright by
//! their rotation metadata itself. It runs confined (see `sandbox`).

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use super::model::SIDE;
use super::pixels::{MAX_FRAMES, MAX_PIXELS, SQUARE_LEN, Square};

/// How long ffmpeg may take over one blob, every run of it together: past
/// this the run is killed, and the blob is undecodable.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// Where the bytes are: a file, or (small blobs) in memory, piped in.
pub enum Input<'a> {
    File(&'a Path),
    Bytes(&'a [u8]),
}

/// Video streams scanned, at most: which one a player shows isn't certain,
/// so every one is looked at, cover art included, and a video with more
/// is undecodable rather than partly seen.
const MAX_STREAMS: usize = 3;

/// The demuxers for what's sniffed as video, AVIF, HEIC or JPEG XL. ffmpeg
/// picks one by probing for itself, and would take bytes that sniff as MP4
/// for a DASH playlist, then open the files it names.
const FORMATS: &str = "mov,matroska,avi,asf,mpeg,mpegvideo,flv,jpegxl_pipe,jpegxl_anim";

/// Frames of a video, or of an image (`still`): an image's length isn't
/// asked for, so an animated one gets its first keyframes, not a spread.
/// `None` for sound with no picture at all: audio in a video container.
/// Every run ends by `deadline`.
pub fn squares(
    ffmpeg: &Path,
    input: Input<'_>,
    still: bool,
    deadline: Instant,
) -> Result<Option<Vec<Square>>> {
    let (length, streams, audio) = if still {
        (None, 1, 0)
    } else {
        probe(ffmpeg, &input, deadline)?
    };
    // Only when ffmpeg read the streams and found sound and nothing to see;
    // a video it can't read at all is still undecodable.
    if streams == 0 && audio > 0 {
        return Ok(None);
    }
    if streams > MAX_STREAMS {
        bail!("{streams} video streams in it, more than are looked at");
    }
    let mut frames = Vec::new();
    for stream in 0..streams.clamp(1, MAX_STREAMS) {
        // An image is left to ffmpeg's choice of stream, which puts a HEIC's
        // grid of tiles together (7.1 and later).
        let map = (!still).then(|| format!("0:v:{stream}"));
        frames.extend(stream_squares(
            ffmpeg,
            &input,
            length,
            map.as_deref(),
            deadline,
        )?);
    }
    if frames.is_empty() {
        bail!("no frames in it");
    }
    Ok(Some(frames))
}

fn stream_squares(
    ffmpeg: &Path,
    input: &Input<'_>,
    length: Option<f64>,
    map: Option<&str>,
    deadline: Instant,
) -> Result<Vec<Square>> {
    // A frame every `gap` seconds, at most MAX_FRAMES of them; with no
    // length (a still image), the first.
    let gap = length.map_or(0.0, |d| d / MAX_FRAMES as f64);
    let filter = format!(
        "select='isnan(prev_selected_t)+gte(t-prev_selected_t\\,{gap:.3})',\
         scale={SIDE}:{SIDE}:flags=bicubic,format=rgb24"
    );
    let mut cmd = base(ffmpeg);
    cmd.args(["-skip_frame", "nokey"]);
    cmd.args(["-max_pixels", &MAX_PIXELS.to_string()]);
    open(&mut cmd, input);
    if let Some(m) = map {
        cmd.args(["-map", m]);
    }
    cmd.args(["-an", "-sn", "-dn", "-vf", &filter])
        .args(["-fps_mode", "vfr", "-frames:v", &MAX_FRAMES.to_string()])
        .args(["-f", "rawvideo", "pipe:1"]);
    let (out, ok) = run(cmd, input, true, deadline)?;
    if out.len() < SQUARE_LEN && !ok {
        bail!("ffmpeg couldn't decode it");
    }
    Ok(out.chunks_exact(SQUARE_LEN).map(<[u8]>::to_vec).collect())
}

/// The first keyframe, as a JPEG fitting a `side` square and no larger than
/// it is: what the dashboard shows of a video, or of an image only ffmpeg
/// reads.
pub fn poster(ffmpeg: &Path, input: Input<'_>, side: u32, deadline: Instant) -> Result<Vec<u8>> {
    let mut cmd = base(ffmpeg);
    cmd.args(["-skip_frame", "nokey"]);
    cmd.args(["-max_pixels", &MAX_PIXELS.to_string()]);
    open(&mut cmd, &input);
    let fit = format!(
        "scale='min({side},iw)':'min({side},ih)':force_original_aspect_ratio=decrease:flags=bicubic,\
         format=yuvj420p"
    );
    cmd.args(["-an", "-sn", "-dn", "-vf", &fit, "-frames:v", "1"])
        .args(["-q:v", "4", "-c:v", "mjpeg", "-f", "image2pipe", "pipe:1"]);
    let (out, ok) = run(cmd, &input, true, deadline)?;
    if !ok || out.is_empty() {
        bail!("ffmpeg made no picture of it");
    }
    Ok(out)
}

fn base(ffmpeg: &Path) -> Command {
    let mut cmd = Command::new(ffmpeg);
    cmd.args([
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-threads",
        "1",
    ]);
    cmd
}

/// The input, read as one of `FORMATS` and from nowhere else.
fn open(cmd: &mut Command, input: &Input<'_>) {
    cmd.args(["-protocol_whitelist", "file,pipe"])
        .args(["-format_whitelist", FORMATS])
        .args(["-i", source(input)]);
}

fn source<'a>(input: &'a Input<'_>) -> &'a str {
    match input {
        Input::File(p) => p.to_str().unwrap_or("pipe:0"),
        Input::Bytes(_) => "pipe:0",
    }
}

/// The length in seconds (`None` for none) and the numbers of video and
/// audio streams, from the summary ffmpeg prints of an input it's given
/// nothing to do with.
fn probe(
    ffmpeg: &Path,
    input: &Input<'_>,
    deadline: Instant,
) -> Result<(Option<f64>, usize, usize)> {
    let mut cmd = Command::new(ffmpeg);
    cmd.args(["-nostdin", "-hide_banner"]);
    open(&mut cmd, input);
    let (err, _) = run(cmd, input, false, deadline)?;
    let text = String::from_utf8_lossy(&err);
    let count = |kind: &str| {
        text.lines()
            .filter(|l| l.trim_start().starts_with("Stream #0:") && l.contains(kind))
            .count()
    };
    let (streams, audio) = (count(": Video: "), count(": Audio: "));
    Ok((length(&text), streams, audio))
}

/// The input's length from its `Duration:` line. Only a line of its own
/// counts: metadata, the uploader's to write, is printed before it as
/// `key : value`, a value's line breaks continuing as ` : rest`.
fn length(text: &str) -> Option<f64> {
    let line = text
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("Duration: "))?;
    let mut secs = 0.0;
    for part in line.split(',').next()?.trim().split(':') {
        secs = secs * 60.0 + part.parse::<f64>().ok()?;
    }
    (secs.is_finite() && secs > 0.0).then_some(secs)
}

/// Run to the end (or the deadline), feeding in-memory input on stdin, and
/// give back stdout (or with `!stdout`, stderr) and whether it succeeded.
fn run(
    mut cmd: Command,
    input: &Input<'_>,
    stdout: bool,
    deadline: Instant,
) -> Result<(Vec<u8>, bool)> {
    if Instant::now() >= deadline {
        bail!("ffmpeg took longer than {}s", TIMEOUT.as_secs());
    }
    cmd.stdin(if matches!(input, Input::Bytes(_)) {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    if stdout {
        cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    } else {
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());
    }
    super::sandbox::confine(
        &mut cmd,
        match input {
            Input::File(p) => Some(p),
            Input::Bytes(_) => None,
        },
    );
    let mut child = cmd.spawn().context("ffmpeg didn't start")?;
    let feeder = match input {
        Input::Bytes(b) => {
            let mut stdin = child.stdin.take().expect("piped");
            let b = b.to_vec();
            Some(std::thread::spawn(move || {
                let _ = stdin.write_all(&b);
            }))
        }
        Input::File(_) => None,
    };
    let mut pipe: Box<dyn Read + Send> = if stdout {
        Box::new(child.stdout.take().expect("piped"))
    } else {
        Box::new(child.stderr.take().expect("piped"))
    };
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        // Never more than the frames asked for, and a little summary.
        let _ = pipe
            .by_ref()
            .take((SQUARE_LEN * MAX_FRAMES + (64 << 10)) as u64)
            .read_to_end(&mut buf);
        buf
    });
    let ok = wait(&mut child, deadline)?;
    let out = reader.join().unwrap_or_default();
    if let Some(f) = feeder {
        let _ = f.join();
    }
    Ok((out, ok))
}

fn wait(child: &mut Child, deadline: Instant) -> Result<bool> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("ffmpeg took longer than {}s", TIMEOUT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::length;

    #[test]
    fn length_is_not_the_uploaders_to_choose() {
        let summary = "Input #0, mov,mp4,m4a,3gp,3g2,mj2, from 'spoof.mp4':
  Metadata:
    major_brand     : isom
    title           : Duration: 99999:00:00.00, x
    comment         : a
                    :   Duration: 99999:00:00.00, x
  Duration: 00:00:10.00, start: 0.000000, bitrate: 12 kb/s
  Stream #0:0[0x1](und): Video: h264, yuv420p, 64x64, 5 fps";
        assert_eq!(length(summary), Some(10.0));
        assert_eq!(length("  Duration: N/A, bitrate: N/A"), None);
        assert_eq!(length("  Duration: inf:00:00.00, start: 0"), None);
    }
}
