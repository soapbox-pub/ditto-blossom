# ditto-blossom

A [Blossom](https://github.com/hzrd149/blossom) server for Nostr clients,
built to replace blossom.ditto.pub's blossom-server.

Against blossom-server 6.3.1, same four cores, production's data:

| | ditto-blossom | blossom-server | |
| --- | ---: | ---: | ---: |
| GET 1 KB | 321k/s | 1.9k/s | 170x |
| GET 64 KB | 147k/s (9 GB/s) | 1.8k/s | 80x |
| 404 | 403k/s | 4.3k/s | 95x |
| production's last day of requests, replayed | 21.7 GB/s, p99 106 ms | 0.47 GB/s, p99 4.6 s | 46x |
| uploads, 1 KB, 64 at once | 1,755/s | 299/s (and 503s) | 5.9x |
| uploads, 1 MB, 64 at once | 222 MB/s | 101 MB/s (and 503s) | 2.2x |

Uploads are durable before they're acknowledged.

## What it serves

- BUD-01: `GET`/`HEAD /<sha256>[.ext]`, ranges, conditional requests, CORS,
  `X-Reason` on errors
- BUD-02: `PUT /upload`
- BUD-04: `PUT /mirror`, public addresses only
- BUD-06: `HEAD /upload`
- BUD-08: NIP-94 tags in descriptors
- BUD-09: `PUT /report`
- BUD-11: Nostr auth tokens
- BUD-12: `DELETE /<sha256>` by owner, and `GET /list/<pubkey>` (off by
  default)

Not BUD-05 or BUD-07.

Compressible blobs are served brotli or gzip. All blobs are served with
`nosniff` and, except PDFs, `Content-Security-Policy: sandbox`.

## How it's built

- hyper, HTTP/1.1; large blobs sent with sendfile(2).
- LMDB for metadata; blobs up to 16 KiB inline, larger ones as files under
  `blobs/ab/cd/`.
- One writer thread commits each batch in one durable transaction.
- Reads write nothing; last-read days are folded in every five minutes.

## Running it

Use **ext4 or xfs**. On ZFS, use an ext4 zvol, not a dataset, and run
`fstrim` on a timer.

```sh
cargo build --release
cp target/release/ditto-blossom /usr/local/bin/
cp contrib/ditto-blossom.toml /etc/ditto-blossom.toml   # set data and public_url
useradd --system --home /var/lib/ditto-blossom ditto-blossom
cp contrib/ditto-blossom.service /etc/systemd/system/
systemctl enable --now ditto-blossom
```

If `data` isn't `/var/lib/ditto-blossom`, change `ReadWritePaths` in the
unit. Logs are JSON lines on stdout.

### Limits

`[upload] max_size` caps a blob's size, `per_minute` the uploads and
mirrors one address (one /64 for IPv6) may start a minute, and
`bytes_per_hour` how much they may bring in an hour (1 GiB unless set). An
upload is counted by its Content-Length before it's read, a mirror by the
other server's Content-Length, or by what arrived if it sent none; blobs
already here and named by `X-SHA-256` cost nothing. A blob larger than the
hour's allowance goes through only when none of it is spent, and uses up
the hours after it. Past the allowance, clients get 429 with
`Retry-After`. Pubkeys in `exempt`, hex, skip all three, but not bans,
when they sign the request's auth token:

```toml
[upload]
exempt = ["<hex>"]
```

## Taking over from blossom-server

```sh
ditto-blossom import -c /etc/ditto-blossom.toml \
  --sqlite /path/to/blossom-server/data/sqlite.db \
  --blobs /path/to/blossom-server/data/blobs
```

Hard-links files in (`--copy` to copy instead), adds missing owners, and
can be rerun. `--verify` hash-checks every file.

Run `import`, `remove` and `ban` as the server's user
(`sudo -u ditto-blossom …`); they can run beside the server.

`ditto-blossom remove SHA256...` deletes blobs, whoever owns them.

## Banning

```sh
ditto-blossom ban -c /etc/ditto-blossom.toml \
  [--reason TEXT] [--preserve DIR] [--pubkey HEX]... [SHA256]...
```

A banned blob can't be stored again by anyone. A banned pubkey can't
upload or mirror; blobs only it owns are deleted and banned, and it's
taken off blobs others also own.

`--preserve DIR` copies each blob before deleting it, with
`<sha256>.json` (size, type, first upload, owners, reports, reason).
Owner-only; if a copy fails, nothing is deleted.

`unban` lifts bans (a pubkey's blobs stay banned); `bans` lists them.

## Admin dashboard

```toml
[admin]
listen = "127.0.0.1:3001"
pubkeys = ["<hex>"]
# url = "https://admin.example.com"   # if not reached at http://<listen>
# preserve = "/var/lib/ditto-blossom/evidence"
# cdn = "Cloudflare"
# labels = "/var/lib/ditto-blossom/labels.json"
# embeddings = "/var/lib/ditto-blossom/embeddings.jsonl"
```

Sign in with a NIP-07 extension (one NIP-98 event, signed for `url`). The
session lasts 12 hours and ends on restart.

Reach it by SSH tunnel (`ssh -L 3001:127.0.0.1:3001`), or proxy its own
host name to it over https and set `url`; plain http is only allowed on
loopback. A page that gets your extension
to sign a kind 27235 event for that URL can sign in as you, so have the
extension ask before signing.

It has Review (new media one at a time), Reports, Bans, Evidence, a Media
grid, Usage, and search by blob or pubkey. Media is blurred by default,
and shown as thumbnails the server makes, a video's from its first frame
(by `[scan] ffmpeg`), so a page of it doesn't come full size through
whatever is in front of `public_url`; opening one fetches the original.
Uploaders' names and pictures come from their Nostr profiles, which your
browser asks `admin.relays` for.

With `cdn` set, each deletion's URLs are listed under **Purge**, to purge
from the CDN.

With scanning on and `labels` and `embeddings` set, **Looks fine** and **Not
allowed** label the file clean or explicit for `train`, and save its
embeddings so it can be trained on after it's deleted.

### Child sexual abuse material

**Child abuse…** bans the blob and its uploaders, removing all they
uploaded, and keeps a copy of it, and of the rest as its context, in
`preserve` (`data/evidence` by default) for your report to NCMEC. Copies
are deleted a year after its report number is entered. The dashboard's Help
covers the rest.

## Refusing explicit media

Off by default. With `[scan]` enabled and `model` and `head` set, uploads
and mirrors that are images, video, pages or PDFs are scored, and refused (403) at or above the
threshold. The bytes decide what a file is, not its declared type.
Encrypted and other non-media files pass unscanned.

The score is a linear head, trained on your labels, over CLIP ViT-B/32
embeddings.

```sh
contrib/clip-model.py /var/lib/ditto-blossom/clip-b32.onnx
ditto-blossom train -c /etc/ditto-blossom.toml --labels labels.json \
  --out /var/lib/ditto-blossom/head.json --catch 0.99
```

`labels.json` is `{"<sha256>": "explicit" | "clean"}`. A few thousand is
enough. The threshold is chosen by cross-validation to catch `--catch` of
the explicit. `--cache FILE` keeps embeddings so removed blobs can still
be trained on. A head only loads with the encoder it was trained on.

Scans look at: EXIF-rotated images; long images in square pieces;
transparency over white and black; frames across animations; keyframes of
every video stream (via ffmpeg, also for AVIF, HEIC, JPEG XL); data-URI
images in HTML and SVG; images in PDFs. The highest score counts.

Media that can't be decoded or fully examined is refused (422) by default.
A refused blob is banned with its score as the reason; `unban` lifts it.

### Background scanning

With `background = true`, uploads are stored at once and scanned after; a
refused blob is then deleted. With `hold` (default on) blobs return 503
until scanned. Past 1,000 waiting, uploads are scanned before storing.
Each address has at most four scans at once (429 beyond).

Stored blobs aren't rescanned. To check them (given files, `scan` scores
them; given none, it asks Shield instead):

```sh
ditto-blossom scan -c /etc/ditto-blossom.toml --refused /var/lib/ditto-blossom/blobs
```

Blobs of 16 KiB or less are in LMDB and aren't covered.

### Cost and ffmpeg

About 8 images a second per worker, ~380 MB for the encoder. CPU only.

Use a static ffmpeg build. It runs with a 60-second limit, no new
privileges, 4 GiB of memory, Landlock (Linux 5.13+) limiting it to the blob
and system libraries, and no network: its own network namespace, or under
the systemd unit (which forbids namespaces) Landlock on Linux 6.7+. The
`ffmpeg_sandbox` log line at startup says what it got; `require_sandbox =
true` refuses to start without both. `ffmpeg = ""` passes those formats
unscanned.

### Limits

- Encrypted blobs can't be scanned.
- **This is not CSAM detection.** That needs hash matching: see
  [Scanning](#scanning).
- The encoder sees 224x224 pixels.
- Not looked at: EXIF thumbnails, archives, PDF attachments, images a page
  links to.

## Scanning

With `[scan]` enabled and `credentials_file` set, each new image is
checked against known CSAM with
[Arachnid Shield](https://shield.projectarachnid.com/docs/), the Canadian
Centre for Child Protection's free API. The server hashes the image with
[PDQ](https://github.com/facebook/ThreatExchange/tree/main/pdq) itself and
sends only the hash, so resized and recompressed copies of known images
match too, and no image leaves the server. JPEG, PNG, WebP, GIF (its first
frame) and BMP are hashed; video and other formats aren't yet.

A match isn't stored. Instead, in one new directory under `evidence`:

- `blobs/` gets the blob, and every other blob its uploader owned, which
  their ban takes out (as `ban --preserve` would);
- `record.json` says when, how it came (`upload`, `mirror`, `retry` or
  `scan`), who sent it and from what address, its PDQ and what Shield
  said;

then the blob and its uploader are banned (keys in `upload.exempt` lose the
blob but keep their key), and `alert_command` is run with the record on
stdin. The server answers 403. A US provider must report what it finds to
[NCMEC](https://report.cybertip.org/) and preserve it for a year; the
directory is what that takes.

If Shield can't be asked, the image is kept and queued, and asked about
again every `retry_every` seconds, so an outage doesn't stop uploads. A
match found then is dealt with the same way.

```sh
sudo -u ditto-blossom ditto-blossom scan -c /etc/ditto-blossom.toml [--dry-run]
```

given no files, asks about every image already stored, a hundred hashes a
request, beside the running server. It logs `scan_progress` with the seq
it's reached; if it stops, `--from SEQ` carries on; `--limit N` stops after
N blobs, to time a slice first. `--dry-run` lists matches and touches nothing.
`ditto-blossom pdq FILE...` prints the hashes it would send.

## Developing

```sh
cargo clippy --all-targets
cargo test
```

Scanning tests use a stand-in model that flags red; video tests need
`ffmpeg` on the path. Benchmark against the real model:

```sh
NSFW_MODEL=clip-b32.onnx NSFW_HEAD=head.json NSFW_IMAGES=some/pictures \
  cargo test --release bench_uploads -- --ignored --nocapture
```

License: AGPL-3.0-or-later.
