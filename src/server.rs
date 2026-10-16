//! Serving HTTP/1.1 on a listener, a task per connection, with large blobs'
//! bodies sent by sendfile(2). After npanel's.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// How long a client has to send its request headers, so a connection that
/// never finishes them isn't held open forever.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// How long open connections get to finish once shutdown begins.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
/// The most a request's head may take, in bytes.
const MAX_HEAD: usize = 64 << 10;

pub type Body = Full<Bytes>;

/// Serve `handler` on `listener` until `shutdown` fires, then give open
/// connections a moment to finish.
pub async fn serve<H, F>(listener: TcpListener, handler: H, shutdown: CancellationToken)
where
    H: Fn(Request<Incoming>, SocketAddr) -> F + Send + Sync + 'static,
    F: Future<Output = Response<Body>> + Send + 'static,
{
    let handler = Arc::new(handler);
    let open = TaskTracker::new();
    loop {
        let (stream, remote) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    // Out of descriptors, or a connection reset mid-accept:
                    // neither is a reason to stop serving.
                    crate::warn!("accept_failed", "error": e.to_string());
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = shutdown.cancelled() => break,
        };
        let _ = stream.set_nodelay(true);
        let handler = handler.clone();
        let shutdown = shutdown.clone();
        open.spawn(async move {
            let io = TcpIo { stream: TokioIo::new(stream), corked: false };
            let service = hyper::service::service_fn(move |req| {
                let response = handler(req, remote);
                async move { Ok::<_, std::convert::Infallible>(response.await) }
            });
            let connection = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .max_buf_size(MAX_HEAD)
                .keep_alive(true)
                .serve_connection(io, service);
            let mut connection = std::pin::pin!(connection);
            tokio::select! {
                _ = connection.as_mut() => {}
                _ = shutdown.cancelled() => {
                    connection.as_mut().graceful_shutdown();
                    let _ = connection.await;
                }
            }
        });
    }
    drop(listener);
    open.close();
    if tokio::time::timeout(DRAIN_TIMEOUT, open.wait()).await.is_err() {
        crate::warn!("drain_timed_out");
    }
}

/// A TCP connection for hyper, which sends a large blob with sendfile(2):
/// the kernel hands the file's pages to the socket, and nothing is copied
/// through the process. See `send_file` for how it knows a blob when it sees
/// one.
struct TcpIo {
    stream: TokioIo<TcpStream>,
    /// Whether `TCP_CORK` is on, which it is while a file is being sent.
    corked: bool,
}

#[cfg(test)]
pub static SENT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl hyper::rt::Read for TcpIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: hyper::rt::ReadBufCursor<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for TcpIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        // hyper passes a body's bytes through uncopied only to a writer that
        // takes them vectored, which is what lets this one recognise a file.
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // A slice below the threshold can only be a file's if it is the tail
        // of one already being sent, which only a corked socket has. An empty
        // one is nobody's: sending nothing of a file would report a write of
        // nothing, which hyper takes for a dead connection.
        let file = bufs
            .iter()
            .enumerate()
            .filter(|(_, buf)| !buf.is_empty() && (this.corked || buf.len() >= crate::send_file::MIN))
            .find_map(|(at, buf)| crate::send_file::find(buf).map(|(fd, offset)| (at, fd, offset)));
        if let Some((at, fd, offset)) = file {
            return this.poll_send_file(cx, &bufs[..at], fd, offset, bufs[at].len());
        }
        // Corked with no file to finish shouldn't happen, but if it did, these
        // bytes would wait up to the kernel's 200 ms behind the cork.
        if this.corked {
            set_cork(this.stream.inner(), false)?;
            this.corked = false;
        }
        Pin::new(&mut this.stream).poll_write_vectored(cx, bufs)
    }
}

impl TcpIo {
    /// Write `head`, then `len` bytes of the file `fd` from `offset`, and
    /// report how much of the two went out, as a vectored write would.
    fn poll_send_file(&mut self, cx: &mut Context<'_>, head: &[io::IoSlice<'_>], fd: std::os::fd::RawFd, offset: u64, len: usize) -> Poll<io::Result<usize>> {
        // Corked, the head and the file fill whole segments together, which
        // is nginx's `tcp_nopush`; with `TCP_NODELAY` alone a large file goes
        // in a quarter more segments, and its head in a packet of its own.
        if !self.corked {
            set_cork(self.stream.inner(), true)?;
            self.corked = true;
        }
        let head_len: usize = head.iter().map(|b| b.len()).sum();
        let written = if head_len == 0 {
            0
        } else {
            let w = std::task::ready!(hyper::rt::Write::poll_write_vectored(Pin::new(&mut self.stream), cx, head))?;
            if w < head_len {
                return Poll::Ready(Ok(w));
            }
            w
        };
        let stream = self.stream.inner();
        let mut offset = libc::off_t::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        loop {
            // Given an offset to read from, sendfile leaves the file's own
            // position alone, so one file can be sent on many connections.
            let sent = stream.try_io(tokio::io::Interest::WRITABLE, || {
                // SAFETY: both descriptors are open for the length of the call
                // (see `send_file::find`), and `offset` is a valid `off_t`.
                let n = unsafe { libc::sendfile(stream.as_raw_fd(), fd, &mut offset, len) };
                usize::try_from(n).map_err(|_| io::Error::last_os_error())
            });
            match sent {
                // The head went out, so that is what this call reports; the
                // next one meets the full socket, or the error, again.
                Err(_) if written > 0 => return Poll::Ready(Ok(written)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::task::ready!(stream.poll_write_ready(cx))?,
                Err(e) => return Poll::Ready(Err(e)),
                Ok(n) => {
                    #[cfg(test)]
                    SENT.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    // All of this file there is to write: uncorking sends its
                    // last partial segment now, rather than after 200 ms.
                    if n == len {
                        set_cork(stream, false)?;
                        self.corked = false;
                    }
                    return Poll::Ready(Ok(written + n));
                }
            }
        }
    }
}

fn set_cork(stream: &TcpStream, on: bool) -> io::Result<()> {
    let value = libc::c_int::from(on);
    // SAFETY: the descriptor is open, and `value` is the `int` TCP_CORK takes.
    let r = unsafe {
        libc::setsockopt(stream.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_CORK, (&raw const value).cast(), std::mem::size_of::<libc::c_int>() as libc::socklen_t)
    };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}
