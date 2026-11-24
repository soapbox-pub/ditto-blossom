//! `ditto-blossom scan`: score files as uploads would be, to choose a
//! threshold, or to find what's already stored that would be refused now.
//! One JSON object a file on stdout; a summary on stderr.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use parking_lot::Mutex;
use serde_json::json;

use super::{Input, Outcome, Worker};
use crate::config;

pub fn run(
    scan: &config::Scan,
    paths: &[PathBuf],
    jobs: Option<usize>,
    refused_only: bool,
) -> Result<()> {
    let model = scan
        .model
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no model: give --model, or [scan] model in the config"))?;
    super::confine_ffmpeg(scan)?;
    let ffmpeg = (!scan.ffmpeg.as_os_str().is_empty()).then(|| scan.ffmpeg.clone());
    let head = super::load_head(scan)?;
    let rule = super::Rule::of(scan, head.as_deref())?;
    let mut files = Vec::new();
    for p in paths {
        walk(p.clone(), &mut files);
    }
    files.sort();
    let files = Arc::new(files);
    let started = std::time::Instant::now();
    let next = Arc::new(AtomicUsize::new(0));
    let times = Arc::new(Mutex::new(Vec::new()));
    let counts = Arc::new(Mutex::new([0usize; 4]));
    let jobs = jobs.unwrap_or_else(super::default_workers).max(1);
    let threads: Vec<_> = (0..jobs)
        .map(|_| {
            let (files, next, times, counts) = (files.clone(), next.clone(), times.clone(), counts.clone());
            let (model, ffmpeg, head) = (model.clone(), ffmpeg.clone(), head.clone());
            std::thread::spawn(move || -> Result<()> {
                let mut w = Worker::new(&model, head, ffmpeg)?;
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = files.get(i) else { return Ok(()) };
                    let v = w.check_safely(&Input::File(path.clone()), None);
                    let refused = v.refused(rule);
                    {
                        let mut c = counts.lock();
                        c[match v.outcome {
                            Outcome::Scored(_) => 0,
                            Outcome::Undecodable(_) => 1,
                            _ => 2,
                        }] += 1;
                        c[3] += refused as usize;
                    }
                    if matches!(v.outcome, Outcome::Scored(_)) {
                        times.lock().push(v.millis);
                    }
                    if refused_only && !refused {
                        continue;
                    }
                    let (outcome, why) = match &v.outcome {
                        Outcome::NotMedia => ("not_media", None),
                        Outcome::Unscanned => ("unscanned", None),
                        Outcome::Scored(_) => ("scored", None),
                        Outcome::Undecodable(e) => ("undecodable", Some(e.clone())),
                    };
                    println!(
                        "{}",
                        json!({
                            "path": path, "type": v.ty, "outcome": outcome, "error": why,
                            "score": v.score().map(|s| (s * 10000.0).round() / 10000.0),
                            "looked": v.looked, "ms": (v.millis * 10.0).round() / 10.0,
                            "decode_ms": (v.decode_millis * 10.0).round() / 10.0, "refused": refused,
                        })
                    );
                }
            })
        })
        .collect();
    for t in threads {
        t.join()
            .map_err(|_| anyhow::anyhow!("a scan thread panicked"))??;
    }
    let wall = started.elapsed().as_secs_f64();
    let mut t = times.lock().clone();
    t.sort_by(f64::total_cmp);
    let pct = |p: f64| {
        t.get(((t.len() as f64 - 1.0) * p).round() as usize)
            .copied()
            .unwrap_or(0.0)
    };
    let c = counts.lock();
    eprintln!(
        "{} files: {} scored, {} undecodable, {} other; {} refused at {}. ms per scored file: p50 {:.1}, p90 {:.1}, p99 {:.1}, max {:.1}; {:.1} files/s on {jobs} threads",
        files.len(),
        c[0],
        c[1],
        c[2],
        c[3],
        rule.threshold,
        pct(0.5),
        pct(0.9),
        pct(0.99),
        pct(1.0),
        files.len() as f64 / wall
    );
    Ok(())
}

fn walk(path: PathBuf, out: &mut Vec<PathBuf>) {
    match std::fs::read_dir(&path) {
        Ok(entries) => {
            for e in entries.flatten() {
                // A link to a directory isn't followed: it may lead back here.
                if e.file_type().is_ok_and(|t| t.is_symlink()) && e.path().is_dir() {
                    continue;
                }
                walk(e.path(), out);
            }
        }
        // Brotli copies are a blob's twin, not a blob.
        Err(_) if path.extension().is_some_and(|e| e == "br") => {}
        Err(_) => out.push(path),
    }
}
