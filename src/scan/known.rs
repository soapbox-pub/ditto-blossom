//! Keeping known CSAM out, with Arachnid Shield.
//!
//! Each new image is hashed with PDQ here, and only the hash goes to
//! Shield. A match isn't stored: it's banned as the dashboard bans CSAM,
//! preserved in the evidence folder (`admin.preserve`) with a record of who
//! sent it, from where and what Shield said, and its uploader (unless
//! protected) banned, whose other blobs are suspended: hidden, and kept, so
//! lifting the ban undoes it. The dashboard's Evidence lists it until its
//! NCMEC report is noted. Then `scan.alert_command` is run, to tell someone.
//!
//! If Shield can't be asked, the blob is kept and queued, and asked about
//! again every `scan.retry_every` seconds: an outage doesn't stop uploads.
//! `ditto-blossom scan` asks about blobs already here.

use std::io::{BufReader, Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::json;
use tokio::sync::Semaphore;

use crate::app::App;
use crate::blobs::Files;
use crate::config::Config;
use crate::hash::Hash;
use crate::pdq::{self, Pdq};
use crate::shield::{BATCH, Shield, Verdict};
use crate::store::{Banned, Store};
use crate::upload::now;
use crate::writer::{BanJob, Ingested, IngestedBody};

/// Images decoded at once: each may take a few hundred megabytes.
const DECODING: usize = 4;
/// How long an alert command may run.
const ALERT_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Scanner {
    pub shield: Shield,
    evidence: PathBuf,
    alert: Vec<String>,
    /// Keys a match never bans (see `Config::protected`).
    protected: crate::moderate::Protected,
    decoding: Semaphore,
}

/// What a check of one blob came to.
pub enum Checked {
    /// Not an image hashed here, or too small to hash.
    Skipped,
    Clean,
    Matched(Pdq, Verdict),
    /// Shield couldn't be asked, or the image couldn't be read.
    Unchecked(String),
}

/// Where a blob's bytes are, to hash.
pub enum Source {
    Bytes(Vec<u8>),
    File(PathBuf),
}

impl Source {
    pub fn of_ingested(blob: &Ingested) -> Source {
        match &blob.body {
            IngestedBody::Inline(b) => Source::Bytes(b.clone()),
            IngestedBody::File(t) => Source::File(t.path().to_path_buf()),
        }
    }

    /// Its PDQ, on this thread: `Ok(None)` if it isn't an image hashed.
    fn pdq(&self) -> Result<Option<Pdq>> {
        match self {
            Source::Bytes(b) => {
                if !pdq::looks_hashable(&b[..b.len().min(64)]) {
                    return Ok(None);
                }
                Ok(pdq::of(Cursor::new(&b[..]))?)
            }
            Source::File(p) => {
                let mut f = crate::blobs::open_noatime(p)?;
                let mut head = [0u8; 64];
                let n = read_up_to(&mut f, &mut head)?;
                if !pdq::looks_hashable(&head[..n]) {
                    return Ok(None);
                }
                use std::io::Seek;
                f.rewind()?;
                Ok(pdq::of(BufReader::new(f))?)
            }
        }
    }

    fn copy_to(&self, dir: &Path, hash: &Hash) -> Result<()> {
        match self {
            Source::Bytes(b) => crate::moderate::keep(dir, hash, &mut &b[..]),
            Source::File(p) => crate::moderate::keep(dir, hash, &mut std::fs::File::open(p)?),
        }
    }
}

fn read_up_to(f: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// A match, as recorded beside its evidence and sent to the alert command.
pub struct Match<'a> {
    pub hash: Hash,
    pub size: u64,
    pub mime: Option<&'a str>,
    pub pdq: Pdq,
    pub verdict: Verdict,
    /// `upload`, `mirror`, `retry` or `scan`.
    pub via: &'a str,
    /// Who sent or owns it.
    pub owners: Vec<[u8; 32]>,
    pub ip: Option<std::net::IpAddr>,
    /// When it was uploaded, if it was kept.
    pub uploaded: Option<u64>,
}

/// How a match's ban is carried out: through the server's writer, or
/// straight to the store from the `scan` command.
pub enum Banner<'a> {
    Writer(&'a crate::writer::Writer),
    Direct(&'a Store, &'a Files),
}

impl Banner<'_> {
    async fn ban(&self, job: BanJob) -> Result<crate::writer::BanDone> {
        match self {
            Banner::Writer(w) => w.ban(job).await,
            Banner::Direct(store, files) => {
                let mut txn = store.write_txn()?;
                let done = crate::moderate::ban_txn(
                    store,
                    files,
                    &mut txn,
                    &job.targets,
                    &job.reason,
                    job.preserve.as_deref(),
                    now(),
                    &job.protected,
                )?;
                txn.commit()?;
                let mut removed = Vec::new();
                for (seq, rec) in done.removed {
                    files.remove(seq, &rec.hash)?;
                    crate::info!("removed", "blob": rec.hash.hex(), "size": rec.size);
                    removed.push(rec.hash);
                }
                Ok((removed, done.suspended.iter().map(|r| r.hash).collect()))
            }
        }
    }
}

impl Scanner {
    pub fn open(config: &Config) -> Result<Option<Scanner>> {
        let scan = &config.scan;
        if !scan.shield() {
            return Ok(None);
        }
        let creds_path = scan
            .credentials_file
            .as_ref()
            .context("scan needs credentials_file")?;
        let creds = std::fs::read_to_string(creds_path)
            .with_context(|| format!("Could not read {}", creds_path.display()))?;
        if let Some(old) = &scan.evidence {
            crate::warn!("scan_evidence_unused", "dir": old.display().to_string(),
                "note": "matches are kept in admin.preserve now, with the dashboard's");
        }
        let evidence = config.evidence();
        Ok(Some(Scanner {
            shield: Shield::new(&scan.shield_url, &creds)?,
            evidence,
            alert: scan.alert_command.clone(),
            protected: config.protected(),
            decoding: Semaphore::new(DECODING),
        }))
    }

    /// Hash a blob, off the async threads.
    pub async fn pdq(&self, source: Source) -> Result<Option<Pdq>> {
        let _permit = self.decoding.acquire().await?;
        tokio::task::spawn_blocking(move || source.pdq()).await?
    }

    /// Check one blob as it arrives.
    pub async fn check(&self, blob: &Ingested) -> Checked {
        let pdq = match self.pdq(Source::of_ingested(blob)).await {
            Ok(None) => return Checked::Skipped,
            Ok(Some(p)) => p,
            // Not decodable: not an image a client can show either.
            Err(e) if e.downcast_ref::<image::ImageError>().is_some() => {
                crate::info!("scan_undecodable", "blob": blob.hash.hex(), "error": format!("{e:#}"));
                return Checked::Skipped;
            }
            Err(e) => return Checked::Unchecked(format!("{e:#}")),
        };
        match self.shield.check(&[pdq]).await {
            Ok(v) => match v.into_iter().next() {
                Some(v) if v.matched() => Checked::Matched(pdq, v),
                Some(_) => Checked::Clean,
                None => Checked::Unchecked("Shield gave no verdict".into()),
            },
            Err(e) => Checked::Unchecked(format!("{e:#}")),
        }
    }

    /// Deal with a match as the dashboard's **Child abuse…** does (see
    /// `moderate::ban_csam`): the blob is preserved in the evidence folder
    /// (`admin.preserve`) and banned, with its uploaders but protected keys,
    /// whose other blobs are suspended and recorded as its context. Its
    /// record there gains what Shield said, how it came and from what
    /// address, so the dashboard's Evidence lists it for the NCMEC report.
    /// Then the alert. `source` is its bytes if it wasn't kept (a match on
    /// arrival); otherwise the ban preserves it. Where its copy is.
    pub async fn on_match(
        &self,
        m: Match<'_>,
        source: Option<&Source>,
        banner: Banner<'_>,
    ) -> Result<PathBuf> {
        let at = now();
        let dir = self.evidence.clone();
        let mut problems = Vec::new();
        let banned_owners: Vec<[u8; 32]> = m
            .owners
            .iter()
            .filter(|pk| !self.protected.contains(*pk))
            .copied()
            .collect();
        let reason = format!(
            "CSAM: Arachnid Shield {} ({}) match on {}",
            m.verdict.classification,
            m.verdict.match_type.as_deref().unwrap_or("?"),
            m.via,
        );
        // Not stored, so no ban will copy it: kept here first.
        if let Some(src) = source {
            let kept = crate::moderate::private_dir(&dir).and_then(|()| {
                src.copy_to(&dir, &m.hash)?;
                crate::moderate::record_unstored(
                    &dir, &m.hash, m.size, m.mime, &m.owners, at, &reason,
                )
            });
            if let Err(e) = kept {
                problems.push(format!("preserving the blob: {e:#}"));
            }
        }
        let mut targets = vec![Banned::Blob(m.hash)];
        targets.extend(banned_owners.iter().map(|pk| Banned::Pubkey(*pk)));
        let job = |targets: Vec<Banned>| BanJob {
            targets,
            reason: reason.clone(),
            preserve: Some(dir.clone()),
            protected: self.protected.clone(),
        };
        let (removed, suspended) = match banner.ban(job(targets)).await {
            Ok(r) => r,
            Err(e) => {
                // At least keep the blob itself out; its owners wait for a
                // person.
                problems.push(format!("banning its uploaders: {e:#}"));
                banner
                    .ban(job(vec![Banned::Blob(m.hash)]))
                    .await
                    .unwrap_or_else(|e| {
                        problems.push(format!("banning the blob: {e:#}"));
                        (Vec::new(), Vec::new())
                    })
            }
        };
        let mut detection = json!({
            "by": "Arachnid Shield",
            "via": m.via,
            "at": at,
            "uploaders": m.owners.iter().map(hex::encode).collect::<Vec<_>>(),
            "ip": m.ip.map(|ip| ip.to_string()),
            "classification": m.verdict.classification,
            "match_type": m.verdict.match_type,
            "near_match_details": m.verdict.near_match_details,
            "pdq": m.pdq.base64(),
            "pdq_quality": m.pdq.quality,
            "problems": problems,
        });
        if let Err(e) =
            crate::moderate::add_detection(&dir, &m.hash, &m.owners, Some(detection.clone()))
        {
            problems.push(format!("recording what Shield said: {e:#}"));
            detection["problems"] = json!(problems);
        }
        let alert = json!({
            "blob": m.hash.hex(),
            "size": m.size,
            "type": m.mime,
            "uploaded": m.uploaded,
            "uploaders": m.owners.iter().map(hex::encode).collect::<Vec<_>>(),
            "banned_uploaders": banned_owners.iter().map(hex::encode).collect::<Vec<_>>(),
            "ip": m.ip.map(|ip| ip.to_string()),
            "detection": detection,
            "removed": removed.iter().map(Hash::hex).collect::<Vec<_>>(),
            "suspended": suspended.iter().map(Hash::hex).collect::<Vec<_>>(),
            "evidence": dir.join(m.hash.hex()).display().to_string(),
            "problems": problems,
        });
        crate::error!("scan_match", "blob": m.hash.hex(), "via": m.via, "classification": m.verdict.classification, "uploaders": alert["uploaders"], "ip": alert["ip"], "suspended": suspended.len(), "evidence": alert["evidence"], "problems": alert["problems"]);
        self.alert(serde_json::to_vec_pretty(&alert)?).await;
        Ok(dir.join(m.hash.hex()))
    }

    async fn alert(&self, record: Vec<u8>) {
        let Some((cmd, args)) = self.alert.split_first() else {
            return;
        };
        let run = async {
            use tokio::io::AsyncWriteExt;
            let mut child = tokio::process::Command::new(cmd)
                .args(args)
                .stdin(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(&record).await?;
            }
            anyhow::Ok(child.wait().await?)
        };
        match tokio::time::timeout(ALERT_TIMEOUT, run).await {
            Ok(Ok(status)) if status.success() => {}
            Ok(Ok(status)) => crate::error!("alert_failed", "status": status.to_string()),
            Ok(Err(e)) => crate::error!("alert_failed", "error": format!("{e:#}")),
            Err(_) => crate::error!("alert_failed", "error": "timed out"),
        }
    }
}

/// Ask Shield again, every `retry_every`, about blobs kept without its say.
pub async fn retry_unscanned(
    app: &'static App,
    every: Duration,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let Some(scanner) = &app.shield else {
        return;
    };
    let mut tick = tokio::time::interval(every);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.cancelled() => return,
        }
        if let Err(e) = retry_round(app, scanner).await {
            crate::warn!("scan_retry_failed", "error": format!("{e:#}"));
        }
    }
}

pub(crate) async fn retry_round(app: &'static App, scanner: &Scanner) -> Result<()> {
    loop {
        let waiting = app.store.unscanned(BATCH)?;
        if waiting.is_empty() {
            return Ok(());
        }
        let mut hashed = Vec::new();
        for hash in &waiting {
            let Some(found) = app.store.find(hash, false)? else {
                app.writer.unqueue(*hash);
                continue;
            };
            let source = match &found.body {
                Some(b) => Source::Bytes(b.to_vec()),
                None => Source::File(app.files.path(hash, false)),
            };
            match scanner.pdq(source).await {
                Ok(Some(p)) => hashed.push((*hash, found, p)),
                Ok(None) => app.writer.unqueue(*hash),
                Err(e) => {
                    crate::info!("scan_undecodable", "blob": hash.hex(), "error": format!("{e:#}"));
                    app.writer.unqueue(*hash);
                }
            }
        }
        let pdqs: Vec<Pdq> = hashed.iter().map(|(_, _, p)| *p).collect();
        let verdicts = scanner.shield.check(&pdqs).await?;
        let mut matched = 0;
        for ((hash, found, pdq), verdict) in hashed.into_iter().zip(verdicts) {
            if !verdict.matched() {
                app.writer.unqueue(hash);
                continue;
            }
            matched += 1;
            let owners = app
                .store
                .read(|txn| app.store.owners_of(txn, found.seq))??;
            let m = Match {
                hash,
                size: found.record.size,
                mime: found.record.mime.as_deref(),
                pdq,
                verdict,
                via: "retry",
                owners,
                ip: None,
                uploaded: Some(found.record.uploaded),
            };
            scanner
                .on_match(m, None, Banner::Writer(&app.writer))
                .await?;
        }
        crate::info!("scan_retried", "blobs": pdqs.len(), "matched": matched);
        // Unqueueing is asynchronous; let it land before reading again.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// `ditto-blossom scan`: ask Shield about every image already here, from
/// blob `from` on (the seq it last printed, to carry on).
pub fn scan_existing(config: &Config, from: u64, limit: Option<u64>, dry_run: bool) -> Result<()> {
    let scanner = Scanner::open(config)?
        .context("Shield isn't set up in the config: scan.enabled and credentials_file")?;
    let store: &'static Store = Box::leak(Box::new(Store::open(&config.data)?));
    let files: &'static Files = Box::leak(Box::new(Files::open(&config.data, 1, false)?));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (mut seen, mut hashed, mut matched) = (0u64, 0u64, 0u64);
    let mut batch: Vec<(u64, crate::store::Record, Pdq)> = Vec::new();
    let mut last = from;

    let flush = |batch: &mut Vec<(u64, crate::store::Record, Pdq)>| -> Result<u64> {
        if batch.is_empty() {
            return Ok(0);
        }
        let pdqs: Vec<Pdq> = batch.iter().map(|(_, _, p)| *p).collect();
        let verdicts = runtime.block_on(async {
            let mut tries = 0;
            loop {
                match scanner.shield.check(&pdqs).await {
                    Ok(v) => break Ok(v),
                    Err(e) if tries < 5 => {
                        tries += 1;
                        crate::warn!("scan_shield_failed", "error": format!("{e:#}"), "retry_in": 30 * tries);
                        tokio::time::sleep(Duration::from_secs(30 * tries)).await;
                    }
                    Err(e) => break Err(e),
                }
            }
        })?;
        let mut n = 0;
        for ((seq, rec, pdq), verdict) in batch.drain(..).zip(verdicts) {
            if !verdict.matched() {
                continue;
            }
            n += 1;
            let owners = store.read(|txn| store.owners_of(txn, seq))??;
            if dry_run {
                println!(
                    "match\t{}\t{}\t{}",
                    rec.hash.hex(),
                    verdict.classification,
                    owners.iter().map(hex::encode).collect::<Vec<_>>().join(",")
                );
                continue;
            }
            let m = Match {
                hash: rec.hash,
                size: rec.size,
                mime: rec.mime.as_deref(),
                pdq,
                verdict,
                via: "scan",
                owners,
                ip: None,
                uploaded: Some(rec.uploaded),
            };
            let dir = runtime.block_on(scanner.on_match(m, None, Banner::Direct(store, files)))?;
            println!("match\t{}\t{}", rec.hash.hex(), dir.display());
        }
        Ok(n)
    };

    let mut failure = None;
    store.each_record(1000, |seq, rec| {
        if failure.is_some() || seq < from || limit.is_some_and(|l| seen >= l) {
            return;
        }
        seen += 1;
        last = seq;
        let source = match store.read(|txn| store.body(txn, seq)) {
            Ok(Ok(Some(b))) => Source::Bytes(b),
            _ => Source::File(files.path(&rec.hash, false)),
        };
        match source.pdq() {
            Ok(Some(p)) => {
                hashed += 1;
                batch.push((seq, rec, p));
            }
            Ok(None) => {}
            Err(e) => crate::info!("scan_undecodable", "blob": rec.hash.hex(), "error": format!("{e:#}")),
        }
        if batch.len() >= BATCH {
            match flush(&mut batch) {
                Ok(n) => matched += n,
                Err(e) => failure = Some(e),
            }
        }
        if seen % 10_000 == 0 {
            crate::info!("scan_progress", "seq": seq, "seen": seen, "hashed": hashed, "matched": matched);
        }
    })?;
    if let Some(e) = failure {
        return Err(e.context(format!("Stopped; carry on with --from {last}")));
    }
    matched += flush(&mut batch)?;
    crate::info!("scan_done", "seq": last, "seen": seen, "hashed": hashed, "matched": matched);
    Ok(())
}
