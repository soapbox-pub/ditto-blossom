# ditto-blossom

A [Blossom](https://github.com/hzrd149/blossom) server: blobs addressed by
their SHA-256, for Nostr clients. Built to replace blossom.ditto.pub's
blossom-server, and to be as fast as the hardware allows.

On the same four cores, with production's data, against blossom-server
6.3.1:

| | ditto-blossom | blossom-server | |
| --- | ---: | ---: | ---: |
| GET 1 KB | 321k/s | 1.9k/s | 170x |
| GET 64 KB | 147k/s (9 GB/s) | 1.8k/s | 80x |
| 404 | 403k/s | 4.3k/s | 95x |
| production's last day of requests, replayed | 21.7 GB/s, p99 106 ms | 0.47 GB/s, p99 4.6 s | 46x |
| uploads, 1 KB, 64 at once | 1,755/s | 299/s (and 503s) | 5.9x |
| uploads, 1 MB, 64 at once | 222 MB/s | 101 MB/s (and 503s) | 2.2x |

Every upload is on disk before it's acknowledged; blossom-server's aren't.
How each choice was made, with the measurements, is in [docs/plan.md](docs/plan.md)
and [spikes/](spikes/).

## What it serves

- BUD-01: `GET`/`HEAD /<sha256>[.ext]`, ranges, conditional requests, CORS,
  `X-Reason` on errors
- BUD-02: `PUT /upload`, 201 when new and 200 when already here
- BUD-04: `PUT /mirror`, public addresses only
- BUD-06: `HEAD /upload`
- BUD-08: NIP-94 tags in descriptors
- BUD-09: `PUT /report`
- BUD-11: Nostr auth tokens, standard or URL-safe base64
- BUD-12: `DELETE /<sha256>` (by owner; the blob goes with its last owner),
  and `GET /list/<pubkey>` (off by default)

Not BUD-05 media optimization, nor BUD-07 payments.

Compressible blobs (text, JSON, JavaScript…) get a brotli copy in the
background, served to clients that take brotli; clients that take gzip but
not brotli, like Tor Browser on onion services, get gzip made on the spot.

## How it's built

- hyper, HTTP/1.1, with large blobs sent by sendfile(2) from mappings
  recognised by address (npanel's trick).
- LMDB for metadata, with a renewed read transaction per thread; blobs up
  to 16 KiB inline in it, larger ones as files under `blobs/ab/cd/`.
- One writer thread commits whatever is queued in a single durable
  transaction, after one `syncfs` makes the batch's new files durable.
- No database writes on reads: reads set a bit, folded into a last-read day
  per blob every five minutes.

## Running it

It wants a Linux filesystem with a page cache that sendfile can hand to
sockets: **ext4 or xfs**. On ZFS, put the data on an ext4-formatted zvol
rather than a dataset; serving large blobs from a dataset costs about three
times the CPU (spike 7). If you delete blobs, run `fstrim` on a timer so a
zvol gives freed space back.

```sh
cargo build --release
cp target/release/ditto-blossom /usr/local/bin/
cp contrib/ditto-blossom.toml /etc/ditto-blossom.toml   # set data and public_url
useradd --system --home /var/lib/ditto-blossom ditto-blossom
cp contrib/ditto-blossom.service /etc/systemd/system/
systemctl enable --now ditto-blossom
```

If `data` isn't `/var/lib/ditto-blossom`, change `ReadWritePaths` in the
unit to match. Logs are one JSON object per line on stdout.

## Taking over from blossom-server

```sh
ditto-blossom import -c /etc/ditto-blossom.toml \
  --sqlite /path/to/blossom-server/data/sqlite.db \
  --blobs /path/to/blossom-server/data/blobs
```

It adds every blob not here yet, hard-linking files into place (so put
`data` on the same filesystem as the old blobs, or pass `--copy`), and
gives existing ones any owners they're missing, so it can be run again just
before switching over. Blobs with no type get one from their bytes. Small
blobs are hash-checked as they're copied in; `--verify` checks every file.

## Developing

```sh
cargo clippy --all-targets
cargo test
```

License: AGPL-3.0-or-later.
