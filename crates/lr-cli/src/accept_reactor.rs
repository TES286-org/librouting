//! Event-driven accept loops for the daemon's management listeners —
//! the runtime API's Unix socket and the metrics endpoint's TCP
//! listener (ROADMAP async-I/O item).
//!
//! Before this module both listeners ran the same poll-and-sleep loop:
//! a `set_nonblocking(true)` listener polled with `accept()` and
//! slept 100 ms between empty results — ten wakeups a second per
//! listener while idle, and an inbound connection waited out up to
//! 100 ms of that sleep before the daemon served it.
//!
//! The accept reactor replaces that with one `mio::Poll` per listener:
//!
//! - the listener is registered READABLE; a readable event drains the
//!   accept queue until `WouldBlock`, handing each accepted stream to
//!   the caller's connection handler unchanged;
//! - a `mio::Waker` — owned by a small watcher thread that polls the
//!   daemon's `running` flag at the old loop's own 100 ms cadence —
//!   fires once on shutdown, so the accept loop exits within the
//!   latency class it had before, without the loop itself polling;
//! - a 1 s poll ceiling bounds a missed wake (waker loss, shutdown
//!   racing the registration) — the loop re-checks `running` itself
//!   each time it wakes;
//! - a hard `accept` error (EMFILE, ENFILE, ENOBUFS) backs the queue
//!   off 100 ms — the listener stays registered and level-triggered,
//!   so its events are skipped until the deadline passes rather than
//!   spinning the loop.
//!
//! The accepted streams convert back to their blocking `std` shapes
//! and the per-connection threads keep their read-timeout serving
//! model: the accept loop is the poll-and-sleep surface the ROADMAP
//! names, not the connection serving.

use std::io::{self, ErrorKind};
use std::net::TcpListener as StdTcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use mio::net::TcpListener as MioTcpListener;
#[cfg(unix)]
use mio::net::UnixListener as MioUnixListener;
use mio::{Events, Interest, Poll, Registry, Token, Waker};

/// Reserved token the shutdown waker fires.
const WAKER_TOKEN: Token = Token(usize::MAX);

/// Reserved token the registered listener fires.
const LISTENER_TOKEN: Token = Token(usize::MAX - 1);

/// Poll ceiling: bounds a missed waker, and re-checks `running` at
/// least this often even if nothing fires.
const POLL_CEILING: Duration = Duration::from_secs(1);

/// How long the loop pauses accepting after a hard `accept` error
/// (EMFILE, ENFILE, ENOBUFS): the poll-and-sleep loop slept 100 ms
/// in the same case. The listener stays registered and
/// level-triggered, so its events are skipped until the deadline
/// passes — without this guard a persistently failing `accept` would
/// spin the loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// The cadence the shutdown watcher polls `running` at — the same
/// latency class the poll-and-sleep loop offered. Each tick is one
/// atomic load instead of an `accept` syscall.
const SHUTDOWN_WATCH_MS: Duration = Duration::from_millis(100);

/// One listener the reactor can drive: registration, acceptance and
/// the conversion of each accepted stream back to its blocking `std`
/// shape (the per-connection threads serve `std` streams with read
/// timeouts).
trait AcceptSource: mio::event::Source + Sized {
    /// The `std` stream shape a connection thread takes over.
    type StdStream;

    /// Accept once; `Ok(None)` means the queue is drained for now.
    fn accept_std(&mut self) -> io::Result<Option<Self::StdStream>>;
}

impl AcceptSource for MioTcpListener {
    type StdStream = std::net::TcpStream;

    fn accept_std(&mut self) -> io::Result<Option<Self::StdStream>> {
        match self.accept() {
            Ok((stream, _)) => Ok(Some(std::net::TcpStream::from(stream))),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(unix)]
impl AcceptSource for MioUnixListener {
    type StdStream = std::os::unix::net::UnixStream;

    fn accept_std(&mut self) -> io::Result<Option<Self::StdStream>> {
        match self.accept() {
            Ok((stream, _)) => Ok(Some(std::os::unix::net::UnixStream::from(stream))),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Drive one listener until the daemon stops: register it READABLE,
/// drain the accept queue on every readable event and hand each
/// accepted stream to `on_conn`. `watcher_name` names the shutdown
/// watcher thread in logs/dumps (`lr-api-waker`, `lr-metrics-waker`).
fn run<L: AcceptSource>(
    listener: L,
    running: &Arc<AtomicBool>,
    watcher_name: &'static str,
    mut on_conn: impl FnMut(L::StdStream),
) {
    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(_) => return,
    };
    let registry: Registry = match poll.registry().try_clone() {
        Ok(r) => r,
        Err(_) => return,
    };
    let waker = match Waker::new(&registry, WAKER_TOKEN) {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut listener = listener;
    if registry
        .register(&mut listener, LISTENER_TOKEN, Interest::READABLE)
        .is_err()
    {
        return;
    }
    spawn_shutdown_watcher(running, waker, watcher_name);

    let mut events = Events::with_capacity(64);
    let mut accept_backoff_until: Option<Instant> = None;
    loop {
        let _ = poll.poll(&mut events, Some(POLL_CEILING));
        if !running.load(Ordering::Relaxed) {
            // The socket file cleanup (API) and the port release
            // happen on drop, back in the caller.
            let _ = registry.deregister(&mut listener);
            return;
        }
        for event in events.iter() {
            let token = event.token();
            if token == WAKER_TOKEN {
                // Shutdown or a spurious wake; the loop-head check
                // decides.
                continue;
            }
            if token != LISTENER_TOKEN || !event.is_readable() {
                continue;
            }
            if let Some(until) = accept_backoff_until {
                if Instant::now() < until {
                    continue;
                }
                accept_backoff_until = None;
            }
            loop {
                match listener.accept_std() {
                    Ok(Some(stream)) => on_conn(stream),
                    Ok(None) => break,
                    Err(e) => {
                        log_error!(crate::Component::Daemon, "accept failed: {e}");
                        accept_backoff_until = Some(Instant::now() + ACCEPT_ERROR_BACKOFF);
                        break;
                    }
                }
            }
        }
    }
}

/// Watch `running` at the poll-and-sleep loop's old cadence and wake
/// the reactor once when it clears — one atomic load per tick, no
/// `accept` syscall. The reactor's poll ceiling catches the case where
/// the wake is lost.
fn spawn_shutdown_watcher(running: &Arc<AtomicBool>, waker: Waker, name: &'static str) {
    let running = Arc::clone(running);
    let _ = thread::Builder::new().name(name.into()).spawn(move || {
        while running.load(Ordering::Relaxed) {
            thread::sleep(SHUTDOWN_WATCH_MS);
        }
        let _ = waker.wake();
    });
}

/// The metrics endpoint's accept loop: a TCP listener on a `mio::Poll`.
pub(crate) fn tcp_accept_loop(
    listener: StdTcpListener,
    running: &Arc<AtomicBool>,
    on_conn: impl FnMut(std::net::TcpStream),
) {
    // The reactor owns the non-blocking switch so the caller can
    // never forget it.
    let _ = listener.set_nonblocking(true);
    let mio = MioTcpListener::from_std(listener);
    run(mio, running, "lr-metrics-waker", on_conn);
}

/// The runtime API's accept loop: a Unix domain listener on a
/// `mio::Poll`. Windows serves the API over named pipes with a
/// blocking `ConnectNamedPipe` accept — already event-driven, no
/// poll-and-sleep loop to retire.
#[cfg(unix)]
pub(crate) fn unix_accept_loop(
    listener: std::os::unix::net::UnixListener,
    running: &Arc<AtomicBool>,
    on_conn: impl FnMut(std::os::unix::net::UnixStream),
) {
    // The reactor owns the non-blocking switch so the caller can
    // never forget it.
    let _ = listener.set_nonblocking(true);
    let mio = MioUnixListener::from_std(listener);
    run(mio, running, "lr-api-waker", on_conn);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A client connects while the loop idles inside `poll`: the
    /// readable event wakes it immediately and the connection handler
    /// runs — proven by the echo the handler writes back.
    #[test]
    fn tcp_loop_serves_a_connection_from_an_idle_poll() {
        let running = Arc::new(AtomicBool::new(true));
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let thread = thread::Builder::new()
            .name("lr-test-accept".into())
            .spawn({
                let running = Arc::clone(&running);
                move || {
                    tcp_accept_loop(listener, &running, |mut stream| {
                        let _ = stream.write_all(b"hi");
                    });
                }
            })
            .unwrap();

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi", "the connection was served");

        running.store(false, Ordering::Relaxed);
        thread.join().unwrap();
    }

    /// Shutdown: `running` clearing stops the loop within the
    /// watcher's cadence (the ceiling is 1 s; the watcher is faster).
    #[test]
    fn tcp_loop_exits_on_shutdown() {
        let running = Arc::new(AtomicBool::new(true));
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let start = Instant::now();
        let thread = thread::Builder::new()
            .name("lr-test-accept".into())
            .spawn({
                let running = Arc::clone(&running);
                move || {
                    tcp_accept_loop(listener, &running, |_stream| {});
                }
            })
            .unwrap();

        // The loop is inside poll; a client connection confirms it is
        // live, then shutdown must return the thread promptly.
        let _client = std::net::TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::from_millis(200));
        running.store(false, Ordering::Relaxed);
        thread.join().unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "shutdown returned the loop promptly, took {elapsed:?}"
        );
    }

    /// The Unix-domain loop: same shape, different socket family.
    #[cfg(unix)]
    #[test]
    fn unix_loop_serves_a_connection_from_an_idle_poll() {
        let dir =
            std::env::temp_dir().join(format!("lr-accept-reactor-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let path = dir.to_str().unwrap().to_string();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let running = Arc::new(AtomicBool::new(true));

        let thread = thread::Builder::new()
            .name("lr-test-accept".into())
            .spawn({
                let running = Arc::clone(&running);
                move || {
                    unix_accept_loop(listener, &running, |mut stream| {
                        let _ = stream.write_all(b"hi");
                    });
                }
            })
            .unwrap();

        let mut client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi", "the connection was served");

        running.store(false, Ordering::Relaxed);
        thread.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }
}
