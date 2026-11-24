//! `ditto-blossom train`: fit the scan head to the operator's labels.
//!
//! Every labelled blob is decoded as an upload would be, and every square
//! a scan would look at embedded by the encoder. A logistic regression over
//! those embeddings is the head: an explicit blob's whole picture is an
//! explicit example, and every square of a clean blob a clean one, since a
//! scan refuses on any square. Its threshold is chosen from 5-fold
//! cross-validation, each blob scored as a scan scores it (its highest
//! square) by a fit that never saw it, as the lowest that still catches
//! `catch` of what's labelled explicit.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, bail};
use parking_lot::Mutex;
use serde_json::json;

use super::model::{Encoder, Head, INPUT_LEN, to_input};
use super::{Input, decode, map};
use crate::config;

pub struct Options {
    pub labels: PathBuf,
    pub blobs: Vec<PathBuf>,
    pub out: PathBuf,
    /// The share of labelled-explicit blobs the threshold must catch.
    pub catch: f64,
    /// Inverse regularisation strength, as scikit-learn's `C`.
    pub c: f64,
    pub jobs: usize,
    /// Where to write each labelled blob's cross-validated score, if anywhere.
    pub scores: Option<PathBuf>,
    /// Embeddings kept from earlier runs, read and added to: a blob in it
    /// needn't be on disk any more, so a head can be retrained over blobs
    /// since removed (refused ones, say) without keeping the pictures.
    pub cache: Option<PathBuf>,
}

/// One labelled blob's squares, embedded.
type Embedded = (String, bool, Vec<Vec<f32>>);

/// The cache: a header line naming the encoder by its fingerprint, then a
/// line a blob, `{"sha256", "squares": [base64 of little-endian f32s, …]}`.
/// Embeddings only, never pixels. A line that won't read (one torn by a
/// crash, say) is passed over, as is one whose embeddings aren't this
/// encoder's length.
fn read_cache(path: &Path, fingerprint: &[f32]) -> Result<HashMap<String, Vec<Vec<f32>>>> {
    use base64::Engine;
    let text = match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        r => r.with_context(|| format!("Could not read {}", path.display()))?,
    };
    let mut lines = text.lines();
    if !same_encoder(lines.next().unwrap_or("{}"), fingerprint)? {
        bail!("{} was made with another encoder", path.display());
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let line = |l: &str| -> Option<(String, Vec<Vec<f32>>)> {
        let v: serde_json::Value = serde_json::from_str(l).ok()?;
        let mut squares = Vec::new();
        for s in v["squares"].as_array()? {
            let bytes = b64.decode(s.as_str()?).ok()?;
            if bytes.len() != fingerprint.len() * 4 {
                return None;
            }
            squares.push(
                bytes
                    .chunks_exact(4)
                    .map(|c| f32::from_le_bytes(c.try_into().expect("4")))
                    .collect(),
            );
        }
        let hash = v["sha256"].as_str()?;
        (!squares.is_empty()).then(|| (hash.to_string(), squares))
    };
    let mut out = HashMap::new();
    let mut bad = 0;
    for l in lines.filter(|l| !l.is_empty()) {
        match line(l) {
            Some((hash, squares)) => {
                out.insert(hash, squares);
            }
            None => bad += 1,
        }
    }
    if bad > 0 {
        eprintln!("{bad} lines of {} passed over: unreadable", path.display());
    }
    Ok(out)
}

/// Whether a cache's header line names this encoder.
fn same_encoder(header: &str, fingerprint: &[f32]) -> Result<bool> {
    let head: serde_json::Value = serde_json::from_str(header)?;
    let theirs: Vec<f32> = serde_json::from_value(head["encoder"].clone()).unwrap_or_default();
    let alike: f32 = theirs.iter().zip(fingerprint).map(|(a, b)| a * b).sum();
    Ok(theirs.len() == fingerprint.len() && alike >= 0.999)
}

/// Add one blob's embeddings to a cache, starting it if there's none; a
/// later line for the same blob takes the place of an earlier one.
pub fn add_to_cache(
    path: &Path,
    fingerprint: &[f32],
    hash: &str,
    squares: &[Vec<f32>],
) -> Result<()> {
    append_cache(path, fingerprint, &[(hash, squares)])
}

/// Take blobs' embeddings out of a cache: every line that names one, torn
/// ones included. How many lines went. The cache is rewritten, so a `train`
/// adding to it meanwhile may lose what it added.
pub fn forget_in_cache(path: &Path, hashes: &[String]) -> Result<usize> {
    let text = match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        r => r.with_context(|| format!("Could not read {}", path.display()))?,
    };
    let mut lines = text.lines();
    let mut out = lines.next().map(|h| format!("{h}\n")).unwrap_or_default();
    let mut gone = 0;
    for l in lines {
        if hashes.iter().any(|h| l.contains(h.as_str())) {
            gone += 1;
        } else {
            out.push_str(l);
            out.push('\n');
        }
    }
    if gone > 0 {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, out)?;
        std::fs::File::open(&tmp)?.sync_all()?;
        std::fs::rename(&tmp, path)?;
    }
    Ok(gone)
}

/// Add blobs' embeddings to a cache, appending only: `train` and the
/// dashboard may both be adding to it at once.
fn append_cache(path: &Path, fingerprint: &[f32], rows: &[(&str, &[Vec<f32>])]) -> Result<()> {
    use base64::Engine;
    use std::io::{BufRead, Write};
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut out = String::new();
    match std::fs::File::open(path) {
        Ok(f) => {
            let mut header = String::new();
            std::io::BufReader::new(f).read_line(&mut header)?;
            if !same_encoder(header.trim(), fingerprint)? {
                bail!("{} was made with another encoder", path.display());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            out.push_str(&json!({ "encoder": fingerprint }).to_string());
            out.push('\n');
        }
        Err(e) => return Err(e).with_context(|| format!("Could not read {}", path.display())),
    }
    for (hash, squares) in rows {
        let squares: Vec<String> = squares
            .iter()
            .map(|e| b64.encode(e.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>()))
            .collect();
        out.push_str(&json!({ "sha256": hash, "squares": squares }).to_string());
        out.push('\n');
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("Could not write {}", path.display()))?;
    f.write_all(out.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

pub fn run(scan: &config::Scan, o: &Options) -> Result<()> {
    let model = scan
        .model
        .clone()
        .context("no encoder: give --model, or [scan] model in the config")?;
    let ffmpeg = (!scan.ffmpeg.as_os_str().is_empty()).then(|| scan.ffmpeg.clone());
    let labels: HashMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(&o.labels)
            .with_context(|| format!("Could not read {}", o.labels.display()))?,
    )
    .context("labels should be {\"<sha256>\": \"explicit\" | \"clean\", …}")?;
    let fingerprint = Encoder::load(&model, 1)?.fingerprint()?;
    let cache = match &o.cache {
        Some(p) => read_cache(p, &fingerprint)?,
        None => HashMap::new(),
    };
    let mut files = Vec::new();
    for d in &o.blobs {
        walk(d, &labels, &mut files);
    }
    files.sort();
    files.dedup_by(|a, b| a.0 == b.0);
    let cached: Vec<Embedded> = labels
        .iter()
        .filter_map(|(h, v)| {
            let explicit = match v.as_str() {
                "explicit" => true,
                "clean" => false,
                _ => return None,
            };
            Some((h.clone(), explicit, cache.get(h)?.clone()))
        })
        .collect();
    files.retain(|f| !cache.contains_key(&f.0));
    let wanted = labels
        .values()
        .filter(|v| *v == "explicit" || *v == "clean")
        .count();
    eprintln!(
        "{} of {wanted} labelled blobs cached, {} found to embed",
        cached.len(),
        files.len()
    );

    let started = std::time::Instant::now();
    let files = Arc::new(files);
    let next = Arc::new(AtomicUsize::new(0));
    let out = Arc::new(Mutex::new(Vec::new()));
    let skipped = Arc::new(AtomicUsize::new(0));
    // An encoder a thread, ~380 MB each: none if everything is cached.
    let threads: Vec<_> = (0..o.jobs.max(1).min(files.len()))
        .map(|_| {
            let (files, next, out, skipped) =
                (files.clone(), next.clone(), out.clone(), skipped.clone());
            let (model, ffmpeg) = (model.clone(), ffmpeg.clone());
            std::thread::spawn(move || -> Result<()> {
                let mut enc = Encoder::load(&model, 1)?;
                let mut input = vec![0.0; INPUT_LEN];
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((hash, explicit, path)) = files.get(i) else {
                        return Ok(());
                    };
                    // Every square a scan looks at; the whole picture first.
                    let squares = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let bytes = map(path).ok()?;
                        let (_, sq) =
                            decode(&bytes, &Input::File(path.clone()), None, ffmpeg.as_deref());
                        sq.ok().flatten().filter(|s| !s.is_empty())
                    }));
                    let Ok(Some(squares)) = squares else {
                        skipped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let mut embs = Vec::with_capacity(squares.len());
                    for sq in &squares {
                        to_input(sq, &mut input);
                        embs.push(enc.embed(&input)?);
                    }
                    out.lock().push((hash.clone(), *explicit, embs));
                }
            })
        })
        .collect();
    for t in threads {
        t.join()
            .map_err(|_| anyhow::anyhow!("an embedding thread panicked"))??;
    }
    let mut rows: Vec<Embedded> = std::mem::take(&mut *out.lock());
    if let Some(p) = &o.cache
        && !rows.is_empty()
    {
        let new: Vec<(&str, &[Vec<f32>])> = rows.iter().map(|r| (r.0.as_str(), &r.2[..])).collect();
        append_cache(p, &fingerprint, &new)?;
        eprintln!(
            "cached {} more ({} in {})",
            rows.len(),
            cache.len() + rows.len(),
            p.display()
        );
    }
    rows.extend(cached);
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let npos = rows.iter().filter(|r| r.1).count();
    let nneg = rows.len() - npos;
    let nsq: usize = rows.iter().map(|r| r.2.len()).sum();
    eprintln!(
        "embedded {} ({npos} explicit, {nneg} clean, {} undecodable; {nsq} squares) in {:.0}s",
        rows.len(),
        skipped.load(Ordering::Relaxed),
        started.elapsed().as_secs_f64()
    );
    if npos < 10 || nneg < 10 {
        bail!("too few labels to train on: give at least 10 of each");
    }
    // Training examples: an explicit blob's whole picture (its other
    // squares may well be clean), and every square of a clean blob.
    let (mut x, mut xy, mut owner) = (Vec::new(), Vec::new(), Vec::new());
    for (b, r) in rows.iter().enumerate() {
        let take = if r.1 { 1 } else { r.2.len() };
        for e in &r.2[..take] {
            x.push(e.iter().map(|&v| v as f64).collect::<Vec<f64>>());
            xy.push(r.1);
            owner.push(b);
        }
    }
    let y: Vec<bool> = rows.iter().map(|r| r.1).collect();
    // A blob as a scan scores it: its highest square.
    let blob_score = |fit: &Logistic, b: usize| {
        rows[b]
            .2
            .iter()
            .map(|e| fit.score(&e.iter().map(|&v| v as f64).collect::<Vec<f64>>()))
            .fold(0.0, f64::max)
    };

    // Cross-validated scores, folds by blob.
    let folds = stratified_folds(&y, 5);
    let mut oof = vec![0.0; y.len()];
    for f in 0..5 {
        let tr: Vec<usize> = (0..x.len()).filter(|&i| folds[owner[i]] != f).collect();
        let fit = Logistic::fit(&x, &xy, &tr, o.c);
        for b in (0..y.len()).filter(|&b| folds[b] == f) {
            oof[b] = blob_score(&fit, b);
        }
    }
    let auc = auc(&oof, &y);
    let threshold = threshold_for(&oof, &y, o.catch);
    let at = |t: f64| {
        let missed = (0..y.len()).filter(|&i| y[i] && oof[i] < t).count();
        let blocked = (0..y.len()).filter(|&i| !y[i] && oof[i] >= t).count();
        (missed, blocked)
    };
    eprintln!("cross-validated AUC {auc:.4}. Thresholds, by the share of explicit caught:");
    let mut table = Vec::new();
    for want in [0.90, 0.95, 0.98, 0.99, 0.995] {
        let t = threshold_for(&oof, &y, want);
        let (m, b) = at(t);
        eprintln!(
            "  catch {:5.1}%: threshold {t:.3}, missed {m}/{npos}, clean blocked {b}/{nneg}",
            want * 100.0
        );
        table.push(json!({"catch": want, "threshold": t, "missed": m, "clean_blocked": b}));
    }
    let (missed, blocked) = at(threshold);

    if let Some(p) = &o.scores {
        let mut s = String::new();
        for (r, sc) in rows.iter().zip(&oof) {
            s.push_str(&json!({"sha256": r.0, "explicit": r.1, "score": sc}).to_string());
            s.push('\n');
        }
        std::fs::write(p, s).with_context(|| format!("Could not write {}", p.display()))?;
    }

    let all: Vec<usize> = (0..x.len()).collect();
    let fit = Logistic::fit(&x, &xy, &all, o.c);
    let head = Head {
        encoder: fingerprint,
        weights: fit.w.iter().map(|&v| v as f32).collect(),
        bias: fit.b as f32,
        threshold: threshold as f32,
        trained: json!({
            "labels": rows.len(), "explicit": npos, "clean": nneg, "c": o.c,
            "catch": o.catch, "cv_auc": auc, "cv_missed": missed, "cv_clean_blocked": blocked,
            "thresholds": table, "at": crate::upload::now(),
        }),
    };
    std::fs::write(&o.out, serde_json::to_string_pretty(&head)?)
        .with_context(|| format!("Could not write {}", o.out.display()))?;
    eprintln!(
        "wrote {}: threshold {threshold:.3}, which caught {:.1}% of explicit ({missed} missed) and blocked {blocked} of {nneg} clean, unseen",
        o.out.display(),
        100.0 * (npos - missed) as f64 / npos as f64
    );
    Ok(())
}

/// Labelled blobs under `dir`: files named by their hash, with or without
/// an extension (blossom-server's layout and this server's).
fn walk(dir: &Path, labels: &HashMap<String, String>, out: &mut Vec<(String, bool, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            walk(&p, labels, out);
            continue;
        }
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.ends_with(".br") {
            continue;
        }
        let hash = name.split('.').next().unwrap_or("").to_ascii_lowercase();
        match labels.get(&hash).map(String::as_str) {
            Some("explicit") => out.push((hash, true, p)),
            Some("clean") => out.push((hash, false, p)),
            _ => {}
        }
    }
}

/// Each sample's fold, explicit and clean spread evenly and the same every run.
fn stratified_folds(y: &[bool], k: usize) -> Vec<usize> {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut folds = vec![0; y.len()];
    for class in [true, false] {
        let mut idx: Vec<usize> = (0..y.len()).filter(|&i| y[i] == class).collect();
        for i in (1..idx.len()).rev() {
            idx.swap(i, (rand() % (i as u64 + 1)) as usize);
        }
        for (n, i) in idx.into_iter().enumerate() {
            folds[i] = n % k;
        }
    }
    folds
}

/// The highest threshold that still scores at least `catch` of the
/// explicit at or over it.
fn threshold_for(scores: &[f64], y: &[bool], catch: f64) -> f64 {
    let mut pos: Vec<f64> = scores
        .iter()
        .zip(y)
        .filter(|(_, y)| **y)
        .map(|(s, _)| *s)
        .collect();
    pos.sort_by(f64::total_cmp);
    let k = ((1.0 - catch) * pos.len() as f64).floor() as usize;
    pos[k.min(pos.len() - 1)]
}

/// The chance a random explicit scores over a random clean.
fn auc(scores: &[f64], y: &[bool]) -> f64 {
    let mut idx: Vec<usize> = (0..scores.len()).collect();
    idx.sort_by(|&a, &b| scores[a].total_cmp(&scores[b]));
    let (mut rank_sum, mut npos) = (0.0, 0.0);
    let mut i = 0;
    while i < idx.len() {
        let mut j = i;
        while j + 1 < idx.len() && scores[idx[j + 1]] == scores[idx[i]] {
            j += 1;
        }
        let rank = (i + j) as f64 / 2.0 + 1.0;
        for &k in &idx[i..=j] {
            if y[k] {
                rank_sum += rank;
                npos += 1.0;
            }
        }
        i = j + 1;
    }
    let nneg = scores.len() as f64 - npos;
    (rank_sum - npos * (npos + 1.0) / 2.0) / (npos * nneg)
}

/// L2-regularised logistic regression, classes weighted to count equally,
/// the intercept unpenalised: scikit-learn's `LogisticRegression(C,
/// class_weight="balanced")`, fit by Newton's method.
struct Logistic {
    w: Vec<f64>,
    b: f64,
}

impl Logistic {
    fn score(&self, x: &[f64]) -> f64 {
        sigmoid(self.b + dot(&self.w, x))
    }

    fn fit(x: &[Vec<f64>], y: &[bool], rows: &[usize], c: f64) -> Logistic {
        let d = x[0].len();
        let npos = rows.iter().filter(|&&i| y[i]).count() as f64;
        let n = rows.len() as f64;
        let weight = |i: usize| c * n / (2.0 * if y[i] { npos } else { n - npos });
        let loss = |w: &[f64], b: f64| {
            let mut l = 0.5 * dot(w, w);
            for &i in rows {
                let z = b + dot(w, &x[i]);
                // log(1 + e^-z) for y, log(1 + e^z) for not, without overflow.
                let m = if y[i] { -z } else { z };
                l += weight(i) * (m.max(0.0) + (-m.abs()).exp().ln_1p());
            }
            l
        };
        let (mut w, mut b) = (vec![0.0; d], 0.0);
        let mut current = loss(&w, b);
        for _ in 0..100 {
            // Gradient and Hessian over [w; b].
            let mut g = vec![0.0; d + 1];
            let mut h = vec![0.0; (d + 1) * (d + 1)];
            g[..d].copy_from_slice(&w);
            for k in 0..d {
                h[k * (d + 1) + k] = 1.0;
            }
            for &i in rows {
                let p = sigmoid(b + dot(&w, &x[i]));
                let s = weight(i);
                let r = s * (p - if y[i] { 1.0 } else { 0.0 });
                let q = s * p * (1.0 - p);
                let xi = &x[i];
                for a in 0..d {
                    g[a] += r * xi[a];
                    let qa = q * xi[a];
                    let row = &mut h[a * (d + 1)..(a + 1) * (d + 1)];
                    for (hb, xb) in row[..=a].iter_mut().zip(xi) {
                        *hb += qa * xb;
                    }
                    row[d] += qa;
                }
                g[d] += r;
                h[d * (d + 1) + d] += q;
            }
            // The solve reads only the lower triangle: the intercept's row
            // is its column, filled above.
            for a in 0..d {
                h[d * (d + 1) + a] = h[a * (d + 1) + d];
            }
            let step = solve_spd(&mut h, &g, d + 1);
            // Halve the step until the loss falls.
            let mut t = 1.0;
            loop {
                let nw: Vec<f64> = w.iter().zip(&step).map(|(w, s)| w - t * s).collect();
                let nb = b - t * step[d];
                let l = loss(&nw, nb);
                if l <= current || t < 1e-6 {
                    let done = current - l < 1e-10 * current.max(1.0);
                    w = nw;
                    b = nb;
                    current = l;
                    if done {
                        return Logistic { w, b };
                    }
                    break;
                }
                t /= 2.0;
            }
        }
        Logistic { w, b }
    }
}

fn sigmoid(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(a, b)| a * b).sum()
}

/// Solve `h x = g` for symmetric positive-definite `h` (overwritten) by
/// Cholesky.
fn solve_spd(h: &mut [f64], g: &[f64], n: usize) -> Vec<f64> {
    for j in 0..n {
        let mut s = h[j * n + j];
        for k in 0..j {
            s -= h[j * n + k] * h[j * n + k];
        }
        let l = s.max(1e-12).sqrt();
        h[j * n + j] = l;
        for i in j + 1..n {
            let mut s = h[i * n + j];
            for k in 0..j {
                s -= h[i * n + k] * h[j * n + k];
            }
            h[i * n + j] = s / l;
        }
    }
    let mut z = g.to_vec();
    for i in 0..n {
        for k in 0..i {
            z[i] -= h[i * n + k] * z[k];
        }
        z[i] /= h[i * n + i];
    }
    for i in (0..n).rev() {
        for k in i + 1..n {
            z[i] -= h[k * n + i] * z[k];
        }
        z[i] /= h[i * n + i];
    }
    z
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forgets_blobs_in_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.jsonl");
        let fp = [1.0f32, 0.0, 0.0];
        assert_eq!(forget_in_cache(&path, &["aa".into()]).unwrap(), 0);
        add_to_cache(&path, &fp, "aa", &[vec![0.5, 0.5, 0.5]]).unwrap();
        add_to_cache(&path, &fp, "bb", &[vec![0.5, 0.5, 0.5]]).unwrap();
        add_to_cache(&path, &fp, "aa", &[vec![0.1, 0.1, 0.1]]).unwrap();
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"sha256\": \"aa\", \"squa\n");
        std::fs::write(&path, text).unwrap();
        assert_eq!(forget_in_cache(&path, &["aa".into()]).unwrap(), 3);
        let cache = read_cache(&path, &fp).unwrap();
        assert_eq!(cache.keys().collect::<Vec<_>>(), ["bb"]);
    }

    /// A torn line, a blob with no squares, embeddings of the wrong length:
    /// each passed over, none a panic or the end of training.
    #[test]
    fn cache_lines_that_wont_do_are_passed_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.jsonl");
        let fp = [1.0f32, 0.0, 0.0];
        add_to_cache(&path, &fp, "good", &[vec![0.5, 0.5, 0.5]]).unwrap();
        add_to_cache(&path, &fp, "empty", &[]).unwrap();
        add_to_cache(&path, &fp, "short", &[vec![0.5]]).unwrap();
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"sha256\": \"torn\", \"squa\n");
        std::fs::write(&path, text).unwrap();
        let cache = read_cache(&path, &fp).unwrap();
        assert_eq!(cache.keys().collect::<Vec<_>>(), ["good"]);
    }

    #[test]
    fn fits_separates_and_measures() {
        // Two overlapping clouds in 4 dimensions, one class four times the other.
        let mut seed = 7u64;
        let mut r = move || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            ((seed >> 33) as f64 / (1u64 << 31) as f64) - 0.5
        };
        let (mut x, mut y) = (Vec::new(), Vec::new());
        for i in 0..1000 {
            let pos = i % 5 == 0;
            let shift = if pos { 0.6 } else { -0.2 };
            x.push(
                (0..4)
                    .map(|k| r() + if k == 0 { shift } else { 0.0 })
                    .collect::<Vec<_>>(),
            );
            y.push(pos);
        }
        let all: Vec<usize> = (0..y.len()).collect();
        let fit = Logistic::fit(&x, &y, &all, 3.0);
        let s: Vec<f64> = x.iter().map(|v| fit.score(v)).collect();
        assert!(fit.w[0] > 1.0, "{:?}", fit.w);
        assert!(
            fit.w[1..].iter().all(|w| w.abs() < 0.1 * fit.w[0]),
            "{:?}",
            fit.w
        );
        // At the optimum the objective's gradient vanishes.
        let (n, npos) = (1000.0, 200.0);
        let mut g = fit.w.clone();
        let mut gb = 0.0;
        for i in 0..1000 {
            let wt = 3.0 * n / (2.0 * if y[i] { npos } else { n - npos });
            let r = wt * (fit.score(&x[i]) - if y[i] { 1.0 } else { 0.0 });
            for k in 0..4 {
                g[k] += r * x[i][k];
            }
            gb += r;
        }
        assert!(g.iter().chain([&gb]).all(|v| v.abs() < 1e-4), "{g:?} {gb}");
        assert!(auc(&s, &y) > 0.9);
        // Balanced: about as many of each above 0.5 as their share is caught.
        let t = threshold_for(&s, &y, 0.95);
        assert!(s.iter().zip(&y).filter(|(s, y)| **y && **s >= t).count() >= 190);
        let folds = stratified_folds(&y, 5);
        for f in 0..5 {
            assert_eq!((0..1000).filter(|&i| folds[i] == f && y[i]).count(), 40);
        }
    }

    #[test]
    fn auc_counts_ties_as_half() {
        assert_eq!(auc(&[0.1, 0.9], &[false, true]), 1.0);
        assert_eq!(auc(&[0.5, 0.5], &[false, true]), 0.5);
    }
}
