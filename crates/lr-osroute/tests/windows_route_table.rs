//! Windows route-table backend tests (kernel-gated: Administrator,
//! Windows) — the Windows sibling of `route_kernel.rs`.
//!
//! Production (v1.0.0-rc.4) reported two Windows route-table defects
//! that no mock can adjudicate because they live in netio's own row
//! validation and forwarding behaviour:
//!
//! 1. **Blackhole idiom** — `CreateIpForwardEntry2` with a loopback
//!    *gateway* (127.0.0.1 / ::1, the `route add ... 127.0.0.1` idiom)
//!    fails with `ERROR_INVALID_PARAMETER` (87). The backend now
//!    installs the on-link form on a real egress interface; the
//!    regression test asserts the install succeeds **and** that a
//!    connect to a covered non-local address is discarded rather than
//!    locally accepted (the weak-host trap that turned lr's previous
//!    on-link-loopback form into a live loopback service — its own
//!    0.0.0.0:179 listener answered SYNs for the blackholed space and
//!    produced "peer closed connection" storms).
//! 2. **Egress interface resolution** — `GetBestRoute2` resolves a v4
//!    next hop by longest-prefix over the *current* FIB, so a next hop
//!    inside a 169.254.0.0/16 APIPA connected route (present on the
//!    reporter's box via an unrelated adapter) resolves to that adapter
//!    — not to the tunnel the route was learned on. The regression test
//!    reproduces the shape with a staged 169.254.188.0/24 (same
//!    longest-prefix steal, but it leaves 169.254.169.254 — the cloud
//!    metadata service — off-link, which is what killed the first probe
//!    dispatches on Azure runners) and proves the explicit-ifindex
//!    install path lands the row on the requested interface.
//!
//! Run (Administrator shell):
//! `cargo test -p lr-osroute --test windows_route_table -- --ignored --nocapture`
//!
//! The `fib_semantics_probe_matrix` test is the research transcript the
//! two regressions were distilled from: it installs every plausible row
//! form across the modern and legacy IP Helper APIs and prints how the
//! stack actually treats each (`PROBE|` lines, no assertions — run it
//! with `-- --ignored --nocapture fib_semantics` when auditing a new
//! Windows build).
//!
//! ## Wedge containment (read before touching the harness)
//!
//! This suite historically wedged whole CI jobs: the step stayed
//! `in_progress` past its own `timeout-minutes` until the job ceiling
//! cancelled everything, on sixteen consecutive runs
//! (36125163593 … 36217837148) — across every harness revision,
//! including a final pure-PowerShell step with detached launches and
//! bounded `WaitForExit` budgets whose script provably finished while
//! the runner still could not finalise the step. The mechanism that
//! fits every observation: a process stuck in an UNINTERRUPTIBLE
//! kernel call (wedged netio) is marked for death by
//! `TerminateProcess` but never actually reaped, and everything that
//! waits on its death — bash's `wait`, the runner's step timeout, the
//! step finalisation itself — hangs with it. Nothing at the workflow
//! layer can fix that, so the suite moved off the every-push CI job
//! into windows-fib-probe.yml — a per-test job matrix whose
//! `if: always()` steps commit each test's transcript to the
//! dispatched ref even when a sibling wedges. The last timestamped
//! `PROBE|` line of a wedged run names the exact call site that hung;
//! that transcript is the data the kernel-level fix needs. Inside
//! this binary, the defenses:
//!
//! 1. **The binary kills itself** — every test arms
//!    [`arm_watchdog`] before its first netio call; at the budget the
//!    watchdog thread terminates the process from kernel mode
//!    (`TerminateProcess(GetCurrentProcess(), 70)` — immune to the
//!    user-mode stdio locks that can deadlock `process::exit`'s
//!    flush). Exit 70 is distinct from libtest's failure codes.
//! 2. **Timestamped transcripts** — every `PROBE|` line carries the
//!    elapsed seconds since the process started, so a killed run's
//!    transcript names the exact call site that hung (the line after
//!    the last timestamp).
//! 3. **Console-less children** — every process this binary spawns
//!    (`ping.exe`, `powershell.exe`, `route.exe`) rides
//!    `CREATE_NO_WINDOW`: it attaches no console, holds nothing the
//!    step finalisation could wait on, and its stdio is
//!    file-redirected anyway.

#![cfg(windows)]

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use lr_core::addr::{IpAddr as LrIpAddr, Prefix};
use lr_osroute::ospf_transport;
use lr_osroute::OsRouteTable;
use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry, CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable,
    GetBestRoute2, GetIpForwardTable2, InitializeIpForwardEntry, MIB_IPFORWARDROW,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};

const V4_PREFIX: Prefix = Prefix::new_v4([198, 51, 100, 0], 24); // TEST-NET-2
const V4_PROBE: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
const V6_PREFIX: Prefix = Prefix::new_v6(
    [
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    64,
);
const V6_PROBE: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xdead, 0xbeef, 0, 0, 0, 7));
const PROBE_PORT: u16 = 45999;
const LOOPBACK_IF: u32 = 1;

fn lr4(a: Ipv4Addr) -> LrIpAddr {
    LrIpAddr::V4(a.octets())
}

/// Test-process start — every `PROBE|` line is stamped with the
/// elapsed seconds since the first log call, so a wedged run's
/// transcript shows exactly WHERE it stopped (the last timestamp is
/// the hang site; the next line names the API that never returned).
static T0: OnceLock<Instant> = OnceLock::new();

fn log(line: String) {
    let t0 = T0.get_or_init(Instant::now);
    println!("PROBE|[{:>7.1}s] {line}", t0.elapsed().as_secs_f32());
}

// ---------------------------------------------------------------------
// Self-watchdog — the harness's own guarantee that THIS process
// cannot be the thing a CI job waits on forever.
// ---------------------------------------------------------------------

/// Arm a hard wall-clock watchdog for this test process.
///
/// Why this exists: every prior CI shape for this suite (runs
/// 36125163593 … 362) ended with the step `in_progress` past its own
/// `timeout-minutes` until the JOB ceiling cancelled everything. Run
/// 362 isolated the root cause of the infinite wait: MSYS/Git-Bash
/// `timeout` cannot kill a native Windows child — its SIGTERM is
/// undeliverable to cargo.exe — so an external wrapper is no
/// terminator at all, and the runner can neither reap the tree nor
/// enforce the step timeout on that shape. The watchdog closes the
/// hole from the inside: whatever hangs, the process kills ITSELF at
/// the budget, unconditionally.
///
/// Why `TerminateProcess` and not `std::process::exit`: exit() runs
/// libc's at-exit handlers, which flush every stdio stream — if the
/// wedged code died holding the stdout lock (a `println!` mid-write
/// against a full/broken pipe), the flush deadlocks and the process
/// STILL never exits. `TerminateProcess(GetCurrentProcess(), ..)` is
/// a kernel-mode kill: no user-mode locks, no flushes, no atexit.
/// Exit code 70 is distinct from libtest's failure codes so the
/// transcript's tail line ("watchdog budget exceeded") reads as a
/// watchdog kill, not a test assertion failure.
///
/// The guard disarms on drop (normal completion); the watchdog
/// thread is reaped by the join in `Drop`.
struct Watchdog {
    armed: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.armed.store(false, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn arm_watchdog(budget: Duration) -> Watchdog {
    const WATCHDOG_EXIT: u32 = 70;
    let armed = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&armed);
    let deadline = Instant::now() + budget;
    let thread = std::thread::Builder::new()
        .name("test-watchdog".into())
        .spawn(move || {
            while flag.load(Ordering::SeqCst) {
                if Instant::now() >= deadline {
                    // SAFETY: GetCurrentProcess() returns the current
                    // process's pseudo-handle (always valid); the call
                    // terminates this process from kernel mode.
                    unsafe {
                        TerminateProcess(GetCurrentProcess(), WATCHDOG_EXIT);
                    }
                    // Unreachable on success; fall back to a slow exit
                    // if the kernel refused (it does not for self-kill).
                    std::process::exit(WATCHDOG_EXIT as i32);
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        })
        .expect("spawn watchdog thread");
    Watchdog {
        armed,
        thread: Some(thread),
    }
}

// ---------------------------------------------------------------------
// FFI helpers (mirrors crates/lr-osroute/src/windows.rs patterns)
// ---------------------------------------------------------------------

fn sockaddr4(a: Ipv4Addr) -> SOCKADDR_INET {
    let mut sa: SOCKADDR_INET = unsafe { core::mem::zeroed() };
    let v4 = unsafe { &mut *core::ptr::addr_of_mut!(sa).cast::<SOCKADDR_IN>() };
    v4.sin_family = AF_INET;
    v4.sin_addr.S_un.S_un_b.s_b1 = a.octets()[0];
    v4.sin_addr.S_un.S_un_b.s_b2 = a.octets()[1];
    v4.sin_addr.S_un.S_un_b.s_b3 = a.octets()[2];
    v4.sin_addr.S_un.S_un_b.s_b4 = a.octets()[3];
    sa
}

fn sockaddr6(a: Ipv6Addr, scope_id: u32) -> SOCKADDR_INET {
    let mut sa: SOCKADDR_INET = unsafe { core::mem::zeroed() };
    let v6 = unsafe { &mut *core::ptr::addr_of_mut!(sa).cast::<SOCKADDR_IN6>() };
    v6.sin6_family = AF_INET6;
    v6.sin6_addr.u.Byte = a.octets();
    if a.octets()[..2] == [0xfe, 0x80] {
        v6.Anonymous.sin6_scope_id = scope_id;
    }
    sa
}

/// Modern-API row. `next_hop = None` means "unspecified next hop of the
/// prefix's family" (the documented on-link form), not "field unset".
fn row2(
    prefix: &Prefix,
    next_hop: Option<IpAddr>,
    if_index: u32,
    loopback_flag: bool,
) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { core::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = if_index;
    let nh = match (prefix.addr, next_hop) {
        (LrIpAddr::V4(_), Some(IpAddr::V4(a))) => sockaddr4(a),
        (LrIpAddr::V4(_), _) => sockaddr4(Ipv4Addr::UNSPECIFIED),
        (LrIpAddr::V6(_), Some(IpAddr::V6(a))) => sockaddr6(a, if_index),
        (LrIpAddr::V6(_), _) => sockaddr6(Ipv6Addr::UNSPECIFIED, 0),
    };
    let dst = match prefix.addr {
        LrIpAddr::V4(b) => sockaddr4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
        LrIpAddr::V6(b) => sockaddr6(
            Ipv6Addr::new(
                u16::from_be_bytes([b[0], b[1]]),
                u16::from_be_bytes([b[2], b[3]]),
                u16::from_be_bytes([b[4], b[5]]),
                u16::from_be_bytes([b[6], b[7]]),
                u16::from_be_bytes([b[8], b[9]]),
                u16::from_be_bytes([b[10], b[11]]),
                u16::from_be_bytes([b[12], b[13]]),
                u16::from_be_bytes([b[14], b[15]]),
            ),
            0,
        ),
    };
    row.DestinationPrefix.Prefix = dst;
    row.DestinationPrefix.PrefixLength = prefix.prefix_len;
    row.NextHop = nh;
    row.Loopback = loopback_flag;
    row
}

fn create2(row: &MIB_IPFORWARD_ROW2) -> u32 {
    // SAFETY: `row` is a fully initialised stack value; the API only
    // reads from it.
    unsafe { CreateIpForwardEntry2(row) }
}

fn delete2(row: &MIB_IPFORWARD_ROW2) -> u32 {
    // SAFETY: see create2.
    unsafe { DeleteIpForwardEntry2(row) }
}

/// Legacy-API row (route.exe's path; v4 only).
fn legacy_row(
    prefix: &Prefix,
    gateway: Ipv4Addr,
    if_index: u32,
    fwd_type: u32,
) -> MIB_IPFORWARDROW {
    let mask = if prefix.prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.prefix_len)
    };
    let LrIpAddr::V4(b) = prefix.addr else {
        unreachable!("legacy API is IPv4 only");
    };
    let mut row: MIB_IPFORWARDROW = unsafe { core::mem::zeroed() };
    // MIB_IPFORWARDROW fields carry IPv4 addresses/masks in network
    // byte order: the u32 VALUE must satisfy LE(value) == wire bytes,
    // which is from_le_bytes(octets) on the little-endian targets
    // Windows runs on.
    row.dwForwardDest = u32::from_le_bytes(b);
    row.dwForwardMask = u32::from_le_bytes(mask.to_be_bytes());
    row.dwForwardNextHop = u32::from_le_bytes(gateway.octets());
    row.dwForwardIfIndex = if_index;
    // Union fields with Copy arms are safe to assign directly.
    row.Anonymous1.dwForwardType = fwd_type;
    row.Anonymous2.dwForwardProto = 3; // MIB_IPPROTO_NETMGMT
    row.dwForwardMetric1 = 1;
    row
}

/// One formatted FIB row for a prefix: `if=, nexthop=, proto=,
/// loopback=, metric=`. None when the table has no row for it.
fn fib_row(prefix: &Prefix) -> Option<String> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = core::ptr::null_mut();
    // SAFETY: out-pointer; ownership transferred to us.
    let rc = unsafe { GetIpForwardTable2(0, &mut table) };
    if rc != NO_ERROR || table.is_null() {
        return None;
    }
    let n = unsafe { (*table).NumEntries } as usize;
    let rows = unsafe { core::ptr::addr_of!((*table).Table) as *const MIB_IPFORWARD_ROW2 };
    let mut out = None;
    for row in unsafe { core::slice::from_raw_parts(rows, n) } {
        let (addr, _plen) = unsafe {
            let sa = &row.DestinationPrefix.Prefix;
            let family = sa.si_family;
            if family == AF_INET6 {
                let v6 = &*core::ptr::addr_of!(*sa).cast::<SOCKADDR_IN6>();
                (
                    IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)),
                    row.DestinationPrefix.PrefixLength,
                )
            } else {
                let v4 = &*core::ptr::addr_of!(*sa).cast::<SOCKADDR_IN>();
                let s = &v4.sin_addr.S_un.S_un_b;
                (
                    IpAddr::V4(Ipv4Addr::new(s.s_b1, s.s_b2, s.s_b3, s.s_b4)),
                    row.DestinationPrefix.PrefixLength,
                )
            }
        };
        let plen = row.DestinationPrefix.PrefixLength;
        let same = match (addr, prefix.addr) {
            (IpAddr::V4(a), LrIpAddr::V4(b)) => a.octets() == b,
            (IpAddr::V6(a), LrIpAddr::V6(b)) => a.octets() == b,
            _ => false,
        };
        if plen != prefix.prefix_len || !same {
            continue;
        }
        let nh = unsafe {
            let sa = &row.NextHop;
            if sa.si_family == AF_INET6 {
                let v6 = &*core::ptr::addr_of!(*sa).cast::<SOCKADDR_IN6>();
                IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)).to_string()
            } else {
                let v4 = &*core::ptr::addr_of!(*sa).cast::<SOCKADDR_IN>();
                let s = &v4.sin_addr.S_un.S_un_b;
                IpAddr::V4(Ipv4Addr::new(s.s_b1, s.s_b2, s.s_b3, s.s_b4)).to_string()
            }
        };
        out = Some(format!(
            "if={} nh={} proto={} loopback={} metric={}",
            row.InterfaceIndex, nh, row.Protocol, row.Loopback, row.Metric
        ));
    }
    // SAFETY: release the API-allocated buffer.
    unsafe { FreeMibTable(table as *const core::ffi::c_void) };
    out
}

/// Delete every row the table holds for `prefix` (the daemon's
/// delete-by-prefix shape) and report the last return code.
fn delete_all_for(prefix: &Prefix) -> u32 {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = core::ptr::null_mut();
    // SAFETY: out-pointer; ownership transferred to us.
    let rc = unsafe { GetIpForwardTable2(0, &mut table) };
    if rc != NO_ERROR || table.is_null() {
        return rc;
    }
    let n = unsafe { (*table).NumEntries } as usize;
    let rows = unsafe { core::ptr::addr_of!((*table).Table) as *const MIB_IPFORWARD_ROW2 };
    let mut last = NO_ERROR;
    for row in unsafe { core::slice::from_raw_parts(rows, n) } {
        if row.DestinationPrefix.PrefixLength != prefix.prefix_len {
            continue;
        }
        let (addr, _plen) = unsafe {
            let sa = &row.DestinationPrefix.Prefix;
            if sa.si_family == AF_INET6 {
                let v6 = &*core::ptr::addr_of!(*sa).cast::<SOCKADDR_IN6>();
                (
                    IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)),
                    row.DestinationPrefix.PrefixLength,
                )
            } else {
                let v4 = &*core::ptr::addr_of!(*sa).cast::<SOCKADDR_IN>();
                let s = &v4.sin_addr.S_un.S_un_b;
                (
                    IpAddr::V4(Ipv4Addr::new(s.s_b1, s.s_b2, s.s_b3, s.s_b4)),
                    row.DestinationPrefix.PrefixLength,
                )
            }
        };
        let same = match (addr, prefix.addr) {
            (IpAddr::V4(a), LrIpAddr::V4(b)) => a.octets() == b,
            (IpAddr::V6(a), LrIpAddr::V6(b)) => a.octets() == b,
            _ => false,
        };
        if same {
            // SAFETY: row is a table entry copy; the API matches on the
            // full row key.
            last = unsafe { DeleteIpForwardEntry2(row) };
        }
    }
    // SAFETY: release the API-allocated buffer.
    unsafe { FreeMibTable(table as *const core::ffi::c_void) };
    last
}

/// `GetBestRoute2` interface resolution — the daemon's fallback when a
/// route carries no explicit egress interface.
fn best_route_if(dest: IpAddr) -> Option<u32> {
    let sa = match dest {
        IpAddr::V4(a) => sockaddr4(a),
        IpAddr::V6(a) => sockaddr6(a, 0),
    };
    let mut best: MIB_IPFORWARD_ROW2 = unsafe { core::mem::zeroed() };
    let mut src: SOCKADDR_INET = unsafe { core::mem::zeroed() };
    // SAFETY: null luid/source pick the current compartment; both
    // out-pointers reference live stack values.
    let rc = unsafe {
        GetBestRoute2(
            core::ptr::null(),
            0,
            core::ptr::null(),
            &sa,
            0,
            &mut best,
            &mut src,
        )
    };
    (rc == NO_ERROR)
        .then_some(best.InterfaceIndex)
        .filter(|i| *i != 0)
}

// ---------------------------------------------------------------------
// Behaviour measurement
// ---------------------------------------------------------------------

/// Classify what the local stack does with a connect() to `dest`:
/// `accept:<peer>` (a 0.0.0.0 listener answered — local-accept),
/// `timeout` (packet discarded — true blackhole), `refused` (RST),
/// or `err:<e>` (fast path error, e.g. host unreachable).
///
/// Every wait here is bounded and every resource is released before
/// returning: the accept thread polls a non-blocking listener and
/// stops on a shared flag, so the listener is dropped within
/// milliseconds of the measurement ending. The earlier shape moved
/// the listener into a thread blocked forever in `accept()` — the
/// port then stayed bound for the process's lifetime and every later
/// call in the same probe run returned `listener-error`, silently
/// degrading the whole measurement series.
fn tcp_connect_behaviour(dest: IpAddr) -> String {
    let bind: SocketAddr = match dest {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), PROBE_PORT),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), PROBE_PORT),
    };
    let listener = match TcpListener::bind(bind) {
        Ok(l) => l,
        Err(e) => return format!("listener-error:{e}"),
    };
    if let Err(e) = listener.set_nonblocking(true) {
        return format!("listener-error:{e}");
    }
    let seen = Arc::new(AtomicBool::new(false));
    let seen_t = Arc::clone(&seen);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let peer_log = Arc::new(std::sync::Mutex::new(String::new()));
    let peer_t = Arc::clone(&peer_log);
    let accept_thread = std::thread::spawn(move || {
        // Hard self-limit: even if the join below is skipped by a
        // panic elsewhere, this thread ends and frees the port.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !stop_t.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((s, peer)) => {
                    seen_t.store(true, Ordering::SeqCst);
                    *peer_t.lock().unwrap() = peer.to_string();
                    // Half-close without reading: keep the socket quiet.
                    let _ = s.shutdown(std::net::Shutdown::Both);
                    return;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return,
            }
        }
    });
    std::thread::sleep(Duration::from_millis(200));
    let target = SocketAddr::new(dest, PROBE_PORT);
    let res = TcpStream::connect_timeout(&target, Duration::from_millis(2500));
    let _ = res.as_ref().map(|s| {
        let _ = s.shutdown(std::net::Shutdown::Both);
    });
    // Unblock the accept thread and reap it: bounded, and the listener
    // (owned by that thread) is dropped with it.
    stop.store(true, Ordering::SeqCst);
    let _ = accept_thread.join();
    match res {
        Ok(_) => {
            if seen.load(Ordering::SeqCst) {
                format!("accept:{}", peer_log.lock().unwrap().clone())
            } else {
                "connected-but-no-accept".into()
            }
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "timeout".into(),
            std::io::ErrorKind::ConnectionRefused => "refused(rst)".into(),
            _ => format!("err:{e}"),
        },
    }
}

/// ICMP echo behaviour: `reply:<from>` (local-accept) vs `timeout` vs
/// `unreachable`. Returns "n/a" when ping.exe is missing or wedged
/// past its own `-w` plus a 30 s hard budget (see [`run_bounded`]).
fn ping_behaviour(dest: IpAddr) -> String {
    let args = [
        "-n",
        "1",
        "-w",
        "2000",
        if dest.is_ipv6() { "-6" } else { "-4" },
        &dest.to_string(),
    ];
    let (text, status) = match run_bounded("ping.exe", &args, Duration::from_secs(30)) {
        Ok(v) => v,
        Err(_) => return "n/a".into(),
    };
    if status.is_none() {
        return "n/a (ping exceeded the 30s budget)".into();
    }
    if text.contains("Request timed out") || text.contains("timed out") {
        "timeout".into()
    } else if text.contains("Reply from") || text.contains("reply from") {
        // "Reply from X:" — X is normally the probed destination itself
        // when the stack answered locally.
        let from = text
            .lines()
            .find(|l| l.contains("Reply from") || l.contains("reply from"))
            .and_then(|l| l.split_whitespace().nth(2))
            .unwrap_or("?")
            .to_string();
        format!("reply:{from}")
    } else if text.contains("Destination host unreachable")
        || text.contains("unreachable")
        || text.contains("General failure")
    {
        "unreachable".into()
    } else {
        format!("other:{text}")
    }
}

// ---------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------

/// First up adapter with a global IPv4 — the probe's "real" interface.
fn primary_interface() -> Option<(String, u32, Ipv4Addr)> {
    let ifaces = ospf_transport::list_interfaces().ok()?;
    for i in ifaces {
        if !i.up || i.v4.is_empty() {
            continue;
        }
        for a in &i.v4 {
            if a.is_link_local() || a.is_loopback() || a.is_broadcast() {
                continue;
            }
            let idx = ospf_transport::ifindex_of(&i.name)?;
            return Some((i.name.clone(), idx, *a));
        }
    }
    None
}

/// Run `program args` under a hard wall-clock budget, returning its
/// combined output. A child that outlives its budget is killed and
/// reaped only within a bounded grace window, then abandoned — see
/// the kill path below.
///
/// Output goes to temp FILES, never pipes: a grandchild that inherits
/// the write end of a pipe (the WMI provider host, `conhost`, anything
/// the child spawns) keeps the pipe open after the child dies, and a
/// blocked `read_to_string` on the other end never sees EOF. Files
/// always reach EOF at the current write position, so after the kill
/// the read below is immediate and final: whatever the child wrote
/// before the budget expired is what the caller sees.
///
/// The child is spawned with `CREATE_NO_WINDOW`: console-subsystem
/// children otherwise ATTACH to this process's console, and `conhost`
/// is owned by the OS, not by any process tree — `taskkill /T` from
/// the CI harness cannot reach it. A wedged console-attached
/// descendant keeping `conhost` alive after the test binary and the
/// step's bash have both exited is the surviving explanation for the
/// step-finalisation wedge the runs 362-364 evidence narrowed to
/// (bash spawning a LEAF console exe has never wedged; this suite's
/// binary spawns grandchildren). With no console, the children cannot
/// hold one open; their stdio is file-redirected anyway.
fn run_bounded(
    program: &str,
    args: &[&str],
    budget: Duration,
) -> Result<(String, Option<bool>), String> {
    use std::os::windows::process::CommandExt;
    // CREATE_NO_WINDOW — the child gets no console (and does not
    // attach the parent's). 0x08000000, winbase.h.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let tag = program
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(program)
        .replace('.', "_");
    let out_path = std::env::temp_dir().join(format!(
        "lr-osroute-probe-{}-{}.out",
        std::process::id(),
        tag
    ));
    let err_path = std::env::temp_dir().join(format!(
        "lr-osroute-probe-{}-{}.err",
        std::process::id(),
        tag
    ));
    let out_file = std::fs::File::create(&out_path).map_err(|e| e.to_string())?;
    let err_file = std::fs::File::create(&err_path).map_err(|e| e.to_string())?;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdout(out_file)
        .stderr(err_file)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + budget;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    // Bounded reaping, never an open-ended wait(): a
                    // child stuck in an uninterruptible kernel call is
                    // marked for death by the kill above but its
                    // process handle never signals, so `wait()` would
                    // hang this process with it — the amplifier that
                    // turns one wedged child into a wedged whole CI
                    // step. Poll a short grace window, then abandon
                    // the survivor: its stdio is file-redirected and
                    // it holds no console, so nothing this process's
                    // callers wait on is shared with it. The overrun
                    // is reported by the `None` status the caller
                    // already treats as a budget failure.
                    let grace = Instant::now() + Duration::from_secs(3);
                    loop {
                        match child.try_wait() {
                            Ok(Some(_)) | Err(_) => break,
                            Ok(None) if Instant::now() >= grace => break,
                            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                        }
                    }
                    break None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(e.to_string());
            }
        }
    };
    let out = std::fs::read_to_string(&out_path).unwrap_or_default();
    let err = std::fs::read_to_string(&err_path).unwrap_or_default();
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);
    let success = status.map(|s| s.success());
    Ok((format!("{out}{err}"), success))
}

/// PowerShell with a 60 s budget — see [`run_bounded`] for why the
/// output goes through files and why the kill at the budget's end is
/// final (the historical pipe-based shape deadlocked on inherited
/// write handles and wedged whole CI jobs).
fn powershell(script: &str) -> Result<String, String> {
    const BUDGET: Duration = Duration::from_secs(60);
    match run_bounded(
        "powershell.exe",
        &["-NoProfile", "-Command", script],
        BUDGET,
    ) {
        Ok((out, Some(true))) => Ok(out),
        Ok((out, Some(false))) => Err(out),
        Ok((_, None)) => Err(format!(
            "powershell timed out after {}s: {script}",
            BUDGET.as_secs()
        )),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------
// The probe matrix
// ---------------------------------------------------------------------

#[test]
#[ignore = "research probe — mutates the real FIB; run as Administrator"]
fn fib_semantics_probe_matrix() {
    // Armed before any netio call: the watchdog guarantees this
    // process exits within the budget no matter what hangs, so a
    // wedge costs one bounded, transcript-annotated failure instead
    // of a whole CI job. Legitimate worst case for the 15-form
    // matrix is ~2 min (sleeps + bounded connects + bounded pings);
    // 5 min is the >2x margin.
    let _watchdog = arm_watchdog(Duration::from_secs(300));
    log("=== reference rows (the system's own loopback routes) ===".into());
    for p in [
        Prefix::new_v4([127, 0, 0, 0], 8),
        Prefix::new_v4([127, 0, 0, 1], 32),
        Prefix::new_v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128),
    ] {
        log(format!("ref {p} -> {:?}", fib_row(&p)));
    }

    let (ifname, ifidx, primary_v4) =
        primary_interface().expect("no usable IPv4 adapter for the probe");
    log(format!(
        "env primary-if name={ifname} index={ifidx} addr={primary_v4}"
    ));
    log(format!("env loopback-if index={LOOPBACK_IF}"));

    let v4_forms: Vec<(&str, MIB_IPFORWARD_ROW2)> = vec![
        (
            "e2-127-gw-if1 (current lr idiom)",
            row2(
                &V4_PREFIX,
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                LOOPBACK_IF,
                false,
            ),
        ),
        (
            "e2-onlink-if1 (previous lr idiom)",
            row2(&V4_PREFIX, None, LOOPBACK_IF, false),
        ),
        (
            "e2-onlink-if1-loopflag",
            row2(&V4_PREFIX, None, LOOPBACK_IF, true),
        ),
        (
            "e2-127-gw-if1-loopflag",
            row2(
                &V4_PREFIX,
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                LOOPBACK_IF,
                true,
            ),
        ),
        ("e2-onlink-real-if", row2(&V4_PREFIX, None, ifidx, false)),
        (
            "e2-gw-self-real-if",
            row2(&V4_PREFIX, Some(IpAddr::V4(primary_v4)), ifidx, false),
        ),
        (
            "e2-gw-unreachable-real-if",
            row2(
                &V4_PREFIX,
                Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                ifidx,
                false,
            ),
        ),
    ];

    for (name, row) in v4_forms {
        delete_all_for(&V4_PREFIX);
        let rc = create2(&row);
        log(format!("form [{name}] CreateIpForwardEntry2 rc={rc}"));
        if rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS {
            log(format!("form [{name}] row={:?}", fib_row(&V4_PREFIX)));
            std::thread::sleep(Duration::from_millis(300));
            log(format!(
                "form [{name}] tcp={}",
                tcp_connect_behaviour(V4_PROBE)
            ));
            log(format!("form [{name}] ping={}", ping_behaviour(V4_PROBE)));
            let drc = delete2(&row);
            log(format!(
                "form [{name}] DeleteIpForwardEntry2 rc={drc} left={:?}",
                fib_row(&V4_PREFIX)
            ));
        }
    }

    // Legacy API v4 (route.exe's path) — both forward types.
    for (name, gw, fwd_type) in [
        ("legacy-127-gw-if1-type4", Ipv4Addr::new(127, 0, 0, 1), 4u32),
        ("legacy-127-gw-if1-type3", Ipv4Addr::new(127, 0, 0, 1), 3),
    ] {
        delete_all_for(&V4_PREFIX);
        let row = legacy_row(&V4_PREFIX, gw, LOOPBACK_IF, fwd_type);
        // SAFETY: plain struct, read-only API.
        let rc = unsafe { CreateIpForwardEntry(&row) };
        log(format!("form [{name}] CreateIpForwardEntry rc={rc}"));
        if rc == NO_ERROR {
            log(format!("form [{name}] row={:?}", fib_row(&V4_PREFIX)));
            std::thread::sleep(Duration::from_millis(300));
            log(format!(
                "form [{name}] tcp={}",
                tcp_connect_behaviour(V4_PROBE)
            ));
            log(format!("form [{name}] ping={}", ping_behaviour(V4_PROBE)));
            log(format!(
                "form [{name}] delete-by-prefix rc={}",
                delete_all_for(&V4_PREFIX)
            ));
        }
    }

    // route.exe itself (what the classic advice installs) — through
    // the same bounded runner so it cannot wedge the probe either.
    delete_all_for(&V4_PREFIX);
    let (rcout, _) = match run_bounded(
        "route.exe",
        &["add", "198.51.100.0", "mask", "255.255.255.0", "127.0.0.1"],
        Duration::from_secs(30),
    ) {
        Ok(v) => v,
        Err(e) => {
            log(format!("form [route-exe-127] spawn-error {e}"));
            (String::new(), None)
        }
    };
    log(format!("form [route-exe-127] out={rcout:?}"));
    if fib_row(&V4_PREFIX).is_some() {
        log(format!(
            "form [route-exe-127] row={:?}",
            fib_row(&V4_PREFIX)
        ));
        std::thread::sleep(Duration::from_millis(300));
        log(format!(
            "form [route-exe-127] tcp={}",
            tcp_connect_behaviour(V4_PROBE)
        ));
        log(format!(
            "form [route-exe-127] ping={}",
            ping_behaviour(V4_PROBE)
        ));
        log(format!(
            "form [route-exe-127] delete-by-prefix rc={}",
            delete_all_for(&V4_PREFIX)
        ));
    }

    // IPv6 forms.
    let v6_forms: Vec<(&str, MIB_IPFORWARD_ROW2)> = vec![
        (
            "e2-v6-::1-gw-if1 (current lr idiom)",
            row2(
                &V6_PREFIX,
                Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                LOOPBACK_IF,
                false,
            ),
        ),
        (
            "e2-v6-onlink-if1",
            row2(&V6_PREFIX, None, LOOPBACK_IF, false),
        ),
        (
            "e2-v6-onlink-if1-loopflag",
            row2(&V6_PREFIX, None, LOOPBACK_IF, true),
        ),
        ("e2-v6-onlink-real-if", row2(&V6_PREFIX, None, ifidx, false)),
        (
            "e2-v6-gw-unreachable-real-if",
            row2(
                &V6_PREFIX,
                Some(IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0xfeed, 0, 0, 0, 0, 1,
                ))),
                ifidx,
                false,
            ),
        ),
    ];
    for (name, row) in v6_forms {
        delete_all_for(&V6_PREFIX);
        let rc = create2(&row);
        log(format!("form6 [{name}] CreateIpForwardEntry2 rc={rc}"));
        if rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS {
            log(format!("form6 [{name}] row={:?}", fib_row(&V6_PREFIX)));
            std::thread::sleep(Duration::from_millis(300));
            log(format!(
                "form6 [{name}] tcp={}",
                tcp_connect_behaviour(V6_PROBE)
            ));
            log(format!("form6 [{name}] ping={}", ping_behaviour(V6_PROBE)));
            log(format!(
                "form6 [{name}] delete rc={} left={:?}",
                delete2(&row),
                fib_row(&V6_PREFIX)
            ));
        }
    }

    delete_all_for(&V4_PREFIX);
    delete_all_for(&V6_PREFIX);
    log("=== blackhole probe done ===".into());
}

#[test]
#[ignore = "research probe — mutates the real FIB; run as Administrator"]
fn probe_next_hop_interface_resolution() {
    let _watchdog = arm_watchdog(Duration::from_secs(300));
    let Some((ifname, ifidx, primary_v4)) = primary_interface() else {
        log("ifidx-probe skipped: no usable adapter".into());
        return;
    };
    log(format!(
        "env primary-if name={ifname} index={ifidx} addr={primary_v4}"
    ));

    // Reproduce the production shape: a 169.254.x.y connected route on
    // the primary interface steals next-hop resolution for the tunnel
    // peer's 169.254.x.y address. The staged prefix is a /24
    // (169.254.188.0/24 covering the ghost next hop) rather than the
    // full APIPA /16 the production box had: the longest-prefix steal
    // mechanism is identical, but 169.254.169.254 (the cloud metadata
    // service) stays off-link. Staging the real /16 on a cloud runner
    // makes IMDS unreachable and the runner agent loses its health
    // check — the run-36125163593/36128494485 cancellations.
    let apipa = Ipv4Addr::new(169, 254, 188, 1);
    let ps = format!(
        "New-NetIPAddress -InterfaceAlias '{}' -IPAddress {} -PrefixLength 24 -SkipAsSource $true -PolicyStore ActiveStore",
        ifname, apipa
    );
    match powershell(&ps) {
        Ok(_) => log(format!("env added {apipa}/24 on {ifname}")),
        Err(e) => {
            log(format!(
                "ifidx-probe degraded: cannot add APIPA address: {e}"
            ));
            return;
        }
    }

    let ghost_nexthop = Ipv4Addr::new(169, 254, 188, 9); // the "tunnel peer" address
                                                         // Baseline: with no explicit egress, the daemon's GetBestRoute2
                                                         // fallback resolves the next hop through the staged connected route.
    log(format!(
        "resolve GetBestRoute2({ghost_nexthop}) -> if={:?} (the staged /24 owner is {ifidx}; the tunnel is NOT)",
        best_route_if(IpAddr::V4(ghost_nexthop))
    ));

    // The fix path: an explicit egress interface must win. Install a
    // route on the LOOPBACK interface (stands in for the "other"
    // interface) with the ghost next hop, and verify the row's
    // InterfaceIndex — not the FIB's idea of where the next hop lives.
    let mut table = lr_osroute::windows::IpHelper::connect().expect("IpHelper::connect");
    let prefix = Prefix::new_v4([203, 0, 113, 0], 24);
    match table.add_route(prefix, lr4(ghost_nexthop), LOOPBACK_IF) {
        Ok(()) => log(format!(
            "install via {} oif {} (explicit) -> row={:?}",
            ghost_nexthop,
            LOOPBACK_IF,
            fib_row(&prefix)
        )),
        Err(e) => log(format!("install explicit-oif failed: {e}")),
    }
    match table.delete_route(prefix) {
        Ok(()) => log("delete explicit-oif route ok".into()),
        Err(e) => log(format!("delete explicit-oif route failed: {e}")),
    }

    // And the buggy path for contrast: oif 0 resolves via GetBestRoute2.
    match table.add_route(prefix, lr4(ghost_nexthop), 0) {
        Ok(()) => log(format!(
            "install via {} oif 0 (resolved) -> row={:?}",
            ghost_nexthop,
            fib_row(&prefix)
        )),
        Err(e) => log(format!("install oif-0 failed: {e}")),
    }
    let _ = table.delete_route(prefix);

    // Cleanup the APIPA address.
    let rm = format!(
        "Remove-NetIPAddress -InterfaceAlias '{}' -IPAddress {} -Confirm:$false -PolicyStore ActiveStore -ErrorAction SilentlyContinue",
        ifname, apipa
    );
    match powershell(&rm) {
        Ok(_) => log(format!("env removed {apipa}/24")),
        Err(e) => log(format!("cleanup warning: {e}")),
    }
    log("=== ifidx probe done ===".into());
}

// ---------------------------------------------------------------------
// Regression tests (assertive) — these are the CI-gated Windows
// siblings of route_kernel.rs: they drive the production
// `lr_osroute::windows::IpHelper` backend and assert the behaviour
// the rc.4 production fixes promised.
// ---------------------------------------------------------------------

/// The blackhole install must (a) succeed, (b) put down an on-link row
/// on a *real* egress interface, (c) make a connect to a covered
/// non-local address fail WITHOUT the 0.0.0.0 listener answering, and
/// (d) withdraw cleanly. The pre-fix loopback-gateway form failed (a)
/// with `ERROR_INVALID_PARAMETER` (87); the on-link-loopback form
/// before it satisfied (a) but failed (c) — the weak-host local-accept
/// trap that made lr's own BGP listener answer SYNs for the blackholed
/// space.
#[test]
#[ignore = "mutates the real FIB — run as Administrator on Windows"]
fn blackhole_route_discards_not_accepts() {
    let _watchdog = arm_watchdog(Duration::from_secs(300));
    let Some((_ifname, ifidx, _)) = primary_interface() else {
        eprintln!("skipped: no usable IPv4 adapter");
        return;
    };
    let mut table = lr_osroute::windows::IpHelper::connect().expect("IpHelper::connect");
    let prefix = V4_PREFIX;
    let _ = table.delete_route(prefix);

    // (a) + (b): the install succeeds and lands on a real interface.
    table
        .add_blackhole_route(prefix)
        .unwrap_or_else(|e| panic!("blackhole install failed: {e}"));
    let row = fib_row(&prefix).unwrap_or_else(|| panic!("no FIB row for {prefix} after install"));
    println!("row: {row}");
    assert!(
        !row.contains("if=1 "),
        "blackhole must not egress the loopback interface (local-accept trap): {row}"
    );
    let row_if: u32 = row
        .split("if=")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(
        row_if != 0 && row_if != LOOPBACK_IF,
        "blackhole egress must be a real interface, not loopback/unresolved: {row}"
    );
    if row_if != ifidx {
        println!(
            "note: blackhole egress {row_if} differs from the primary adapter {ifidx} \
             (the default-route owner won — expected on multihomed runners)"
        );
    }

    // (c): a connect into the covered space is discarded — the listener
    // must NOT see the connection. Both a timeout (silent discard) and
    // a fast unreachable are acceptable blackhole outcomes; an accept
    // or an RST from the local stack is the local-accept regression.
    std::thread::sleep(Duration::from_millis(300));
    let behaviour = tcp_connect_behaviour(V4_PROBE);
    println!("connect behaviour: {behaviour}");
    assert!(
        !behaviour.starts_with("accept:"),
        "blackhole locally accepted the connection (weak-host trap): {behaviour}"
    );
    assert!(
        !behaviour.starts_with("refused"),
        "blackhole delivered locally and RST'd (weak-host trap): {behaviour}"
    );

    // (d): withdrawal removes the row.
    table
        .delete_route(prefix)
        .unwrap_or_else(|e| panic!("blackhole delete failed: {e}"));
    assert!(
        fib_row(&prefix).is_none(),
        "blackhole row survived the withdrawal: {:?}",
        fib_row(&prefix)
    );
}

/// An explicit egress interface must win over the FIB's own
/// next-hop resolution: reproduce the production shape (a 169.254.x.y
/// connected route on one adapter claiming the tunnel peer's next
/// hop) and verify the install lands on the *requested* interface —
/// the rc.4 defect had every Babel route egress the APIPA adapter
/// instead of the tunnel. The staged shape is a /24 (see the ifidx
/// probe above): same steal mechanism, cloud-runner-safe.
#[test]
#[ignore = "mutates the real FIB — run as Administrator on Windows"]
fn explicit_oif_beats_fib_resolution() {
    let _watchdog = arm_watchdog(Duration::from_secs(300));
    let Some((ifname, ifidx, _)) = primary_interface() else {
        eprintln!("skipped: no usable IPv4 adapter");
        return;
    };
    // The "other" interface to pin egress to: the loopback pseudo-
    // interface stands in for the tunnel (it is a distinct, always-
    // present interface index).
    let pinned_if: u32 = 1;
    let apipa = Ipv4Addr::new(169, 254, 188, 1);
    let ps = format!(
        "New-NetIPAddress -InterfaceAlias '{}' -IPAddress {} -PrefixLength 24 -SkipAsSource $true -PolicyStore ActiveStore",
        ifname, apipa
    );
    if let Err(e) = powershell(&ps) {
        eprintln!("skipped: cannot stage the 169.254.188.0/24 shape: {e}");
        return;
    }

    let mut table = lr_osroute::windows::IpHelper::connect().expect("IpHelper::connect");
    let prefix = Prefix::new_v4([203, 0, 113, 0], 24);
    let ghost = LrIpAddr::V4([169, 254, 188, 9]);
    let _ = table.delete_route(prefix);

    // Baseline (the bug): with no explicit egress the daemon's
    // GetBestRoute2 fallback resolves the ghost next hop through the
    // APIPA /16 — to the adapter that owns it, not the "tunnel".
    let resolved = best_route_if(IpAddr::V4(Ipv4Addr::new(169, 254, 188, 9)));
    println!(
        "GetBestRoute2(169.254.188.9) -> {resolved:?} (APIPA owner: {ifidx}, pinned egress: {pinned_if})"
    );

    // The fix under test: an explicit if_index pins the row.
    table
        .add_route(prefix, ghost, pinned_if)
        .unwrap_or_else(|e| panic!("explicit-oif install failed: {e}"));
    let row = fib_row(&prefix).unwrap_or_else(|| panic!("no FIB row for {prefix} after install"));
    println!("row: {row}");
    let row_if: u32 = row
        .split("if=")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert_eq!(
        row_if, pinned_if,
        "explicit egress interface must own the row: {row}"
    );
    let _ = table.delete_route(prefix);
    assert!(fib_row(&prefix).is_none(), "row survived delete: {row}");

    // Cleanup the staged APIPA address.
    let rm = format!(
        "Remove-NetIPAddress -InterfaceAlias '{}' -IPAddress {} -Confirm:$false -PolicyStore ActiveStore -ErrorAction SilentlyContinue",
        ifname, apipa
    );
    let _ = powershell(&rm);
}
