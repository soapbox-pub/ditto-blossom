//! The classifier: a CLIP image encoder (OpenAI's ViT-B/32) turns a 224x224
//! square into an embedding, and a linear head trained on the operator's
//! own labels (`ditto-blossom train`) turns that into the chance it's
//! explicit. A ready-made NSFW model draws someone else's line; the head
//! draws this server's, and is retrained in seconds when that moves.
//!
//! On ONNX Runtime, one encoder for the server's scan workers, run on as
//! many cores as there are workers: it holds its ~380 MB of weights once,
//! and scores as fast as an encoder a worker on a core each did. A session
//! isn't safe to run from two threads at once, so it has a thread of its
//! own (see `Shared`).

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;
use ort::value::TensorRef;
use serde::{Deserialize, Serialize};

/// The side of the square the encoder sees.
pub const SIDE: usize = 224;
/// Floats in one input: 3 planes of SIDE x SIDE.
pub const INPUT_LEN: usize = 3 * SIDE * SIDE;
/// CLIP's per-channel normalisation.
const MEAN: [f32; 3] = [0.481_454_66, 0.457_827_5, 0.408_210_73];
const STD: [f32; 3] = [0.268_629_54, 0.261_302_6, 0.275_777_1];
/// How alike an encoder's embedding of the probe must be to the one a head
/// was trained with. A re-export of the same weights is within ~1e-6; the
/// int8 build of the same encoder, ~0.98.
const SAME_ENCODER: f32 = 0.999;

pub enum Encoder {
    Onnx {
        session: Session,
        input: String,
    },
    /// Tests' stand-in, `model = "test:rgb"`: the square's mean colour.
    #[cfg(test)]
    Rgb,
}

fn environment() -> Result<&'static ort::environment::Environment> {
    static ENV: OnceLock<ort::environment::Environment> = OnceLock::new();
    if let Some(e) = ENV.get() {
        return Ok(e);
    }
    let env = ort::init()
        .with_name("ditto-blossom")
        .with_telemetry(false)
        .build()
        .map_err(|e| anyhow!("ONNX Runtime didn't start: {e}"))?;
    Ok(ENV.get_or_init(|| env))
}

/// RGB rows to the encoder's normalised planes.
pub fn to_input(sq: &[u8], out: &mut [f32]) {
    let plane = SIDE * SIDE;
    for (i, px) in sq.chunks_exact(3).enumerate() {
        for c in 0..3 {
            out[c * plane + i] = (px[c] as f32 / 255.0 - MEAN[c]) / STD[c];
        }
    }
}

/// A fixed picture, the same everywhere: gradients and stripes, so every
/// part of the encoder has something to say about it.
fn probe() -> Vec<f32> {
    let mut sq = Vec::with_capacity(SIDE * SIDE * 3);
    for y in 0..SIDE {
        for x in 0..SIDE {
            let stripe = if (x / 16 + y / 24) % 2 == 0 { 40 } else { 0 };
            sq.extend([
                (x * 255 / SIDE) as u8,
                (y * 255 / SIDE) as u8,
                (((x + y) * 127 / SIDE) + stripe) as u8,
            ]);
        }
    }
    let mut input = vec![0.0; INPUT_LEN];
    to_input(&sq, &mut input);
    input
}

impl Encoder {
    /// The encoder at `path`, run on `threads` cores.
    pub fn load(path: &Path, threads: usize) -> Result<Encoder> {
        #[cfg(test)]
        if path == Path::new("test:rgb") {
            return Ok(Encoder::Rgb);
        }
        let err = |e: ort::Error<_>| anyhow!("{e}");
        let session = Session::builder(environment()?)
            .map_err(|e| anyhow!("{e}"))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(err)?
            .with_intra_threads(threads.max(1))
            .map_err(err)?
            .with_inter_threads(1)
            .map_err(err)?
            // Each session keeps its own optimised weights, ~380 MB for B/32;
            // sharing them between sessions was measured to save nothing.
            .commit_from_file(path)
            .map_err(|e| anyhow!("{} isn't a model ONNX Runtime can run: {e}", path.display()))?;
        let input = session
            .inputs()
            .first()
            .context("The model has no input")?
            .name()
            .to_string();
        let mut enc = Encoder::Onnx { session, input };
        // An encoder of another shape fails here rather than on the first upload.
        let e = enc
            .embed(&probe())
            .with_context(|| format!("{} isn't a {SIDE}x{SIDE} image encoder", path.display()))?;
        if e.is_empty() || e.iter().any(|v| !v.is_finite()) {
            bail!("{} gives no usable embedding", path.display());
        }
        Ok(enc)
    }

    /// The embedding of `input` (from [`to_input`]), of unit length.
    pub fn embed(&mut self, input: &[f32]) -> Result<Vec<f32>> {
        let mut e = match self {
            Encoder::Onnx {
                session,
                input: name,
            } => {
                let tensor = TensorRef::from_array_view(([1usize, 3, SIDE, SIDE], input))
                    .map_err(|e| anyhow!("{e}"))?;
                let out = session
                    .run(ort::inputs![name.as_str() => tensor])
                    .map_err(|e| anyhow!("{e}"))?;
                let (_, v) = out[0]
                    .try_extract_tensor::<f32>()
                    .map_err(|e| anyhow!("{e}"))?;
                v.to_vec()
            }
            #[cfg(test)]
            Encoder::Rgb => {
                let plane = SIDE * SIDE;
                (0..3)
                    .map(|c| input[c * plane..(c + 1) * plane].iter().sum::<f32>() / plane as f32)
                    .collect()
            }
        };
        let norm = e.iter().map(|v| v * v).sum::<f32>().sqrt();
        if norm > 0.0 {
            e.iter_mut().for_each(|v| *v /= norm);
        }
        Ok(e)
    }

    /// The embedding of the fixed probe picture: what a head checks to know
    /// the encoder is the one it was trained over, whatever its file's bytes.
    pub fn fingerprint(&mut self) -> Result<Vec<f32>> {
        self.embed(&probe())
    }
}

/// A linear head over the encoder's embedding, as `ditto-blossom train`
/// writes it. It travels: any server running the same encoder can use it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Head {
    /// The encoder's [fingerprint](Encoder::fingerprint) at training:
    /// another encoder's embeddings mean nothing to the weights.
    pub encoder: Vec<f32>,
    pub weights: Vec<f32>,
    pub bias: f32,
    /// The threshold chosen at training, used unless the config sets one.
    pub threshold: f32,
    /// What training measured, for the record.
    #[serde(default)]
    pub trained: serde_json::Value,
}

impl Head {
    pub fn load(path: &Path) -> Result<Head> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Could not read {}", path.display()))?;
        let head: Head = serde_json::from_str(&text)
            .with_context(|| format!("{} isn't a scan head", path.display()))?;
        let n = head.weights.len();
        let finite = head
            .weights
            .iter()
            .chain([&head.bias])
            .all(|w| w.is_finite());
        if n == 0 || head.encoder.len() != n || !finite || !(0.0..=1.0).contains(&head.threshold) {
            bail!("{} isn't a usable scan head", path.display());
        }
        Ok(head)
    }

    /// Whether `encoder` is the one it was trained over.
    pub fn check(&self, encoder: &mut Encoder) -> Result<()> {
        let f = encoder.fingerprint()?;
        if f.len() != self.encoder.len() {
            bail!(
                "the encoder gives {} numbers; the head was trained over one giving {}",
                f.len(),
                self.encoder.len()
            );
        }
        let alike: f32 = f.iter().zip(&self.encoder).map(|(a, b)| a * b).sum();
        if alike < SAME_ENCODER {
            bail!(
                "the scan head was trained over another encoder (fingerprints {alike:.4} alike): \
                 retrain it with ditto-blossom train"
            );
        }
        Ok(())
    }

    /// The chance an embedding is of something explicit.
    pub fn score(&self, e: &[f32]) -> f32 {
        let z = self.bias + self.weights.iter().zip(e).map(|(w, x)| w * x).sum::<f32>();
        1.0 / (1.0 + (-z).exp())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_scores_and_checks_the_encoder() {
        let sq = [255u8, 0, 128].repeat(SIDE * SIDE);
        let mut x = vec![0.0; INPUT_LEN];
        to_input(&sq, &mut x);
        assert!((x[0] - (1.0 - MEAN[0]) / STD[0]).abs() < 1e-5);
        assert!((x[SIDE * SIDE] - (0.0 - MEAN[1]) / STD[1]).abs() < 1e-5);
        let mut enc = Encoder::load(Path::new("test:rgb"), 1).unwrap();
        let mut head = Head {
            encoder: enc.fingerprint().unwrap(),
            weights: vec![2.0, -2.0, 0.0],
            bias: 0.0,
            threshold: 0.5,
            trained: serde_json::Value::Null,
        };
        assert!(head.score(&[1.0, 0.0, 0.0]) > 0.85);
        assert!((head.score(&[0.5, 0.5, 0.0]) - 0.5).abs() < 1e-6);
        head.check(&mut enc).unwrap();
        head.encoder = vec![0.0, 0.0, 1.0];
        assert!(head.check(&mut enc).is_err(), "another encoder");
    }
}
