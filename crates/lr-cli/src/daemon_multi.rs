//! `lr-daemon --protocol bgp,ospf,babel` — the rc.3 multi-protocol
//! supervisor.
//!
//! One process runs a *combination* of routing protocols: the BGP,
//! OSPF (v2 or v3) and Babel engines each keep their own transport and
//! I/O loop on a dedicated thread, but they share the process-wide
//! plumbing exactly once:
//!
//! - **one [`DefaultRouter`]** — the shared Loc-RIB. Every engine adds
//!   its sessions to the same router instance, so routes learned by
//!   any protocol are visible to all of them (per preference) and to
//!   the runtime API. Cross-protocol *advertisement* stays opt-in via
//!   the router's redistribution pipes — sharing the RIB does not leak
//!   OSPF internals into BGP (FRR `redistribute` / BIRD `pipe`
//!   semantics).
//! - **one running flag** — SIGTERM/SIGINT stop every engine at once.
//! - **one ticker** — a single `tick()` clock drives BGP FSM timers,
//!   OSPF LSA refresh/aging and Babel expiry for the whole router.
//! - **one runtime API socket** — status/sessions/routes/reload cover
//!   every engine's sessions; protocol-specific status lines are
//!   contributed through the [`MultiStatus`] registry.
//!
//! ```text
//!   ┌──────────────────────────────────────────────────────────────┐
//!   │ lr-daemon --protocol bgp,ospf,babel                            │
//!   │                                                                │
//!   │  supervisor thread                                             │
//!   │  ┌─────────── signals ── dispatch ──┐  ┌────────────────────┐ │
//!   │  │  spawn engines → wait Started    │  │ ticker (shared)    │ │
//!   │  │  privdrop → API socket → release │  │ tick + poll events │ │
//!   │  │  supervise → join all            │  └─────────▲──────────┘ │
//!   │  └──────────────────────────────────┘            │            │
//!   │     ┌──────────────┬───────────────┬─────────────┴──────────┐ │
//!   │     │ engine: bgp  │ engine: ospf  │ engine: babel          │ │
//!   │     │ TCP :179     │ raw :89       │ UDP :6696              │ │
//!   │     │ connectors + │ per-(area,rid)│ hello/announce + recv  │ │
//!   │     │ accept loop  │ sessions      │ loop                   │ │
//!   │     └──────┬───────┴───────┬───────┴────────────┬───────────┘ │
//!   │            └───────────────┴────────────────────┘             │
//!   │                        one shared DefaultRouter               │
//!   └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! Startup is gated: every engine binds its sockets *first* (OSPF raw
//! sockets and the BGP :179 listener need privileges), reports
//! [`EngineReport::Started`], then blocks on its [`StartGate`]. Once
//! every engine has started, the supervisor drops privileges, creates
//! the management socket as the reduced user, releases the gates and
//! enters its supervision loop. A startup failure in any engine aborts
//! the whole combination (the supervisor aborts the gates, stops the
//! running flag and returns the failing engine's exit code) — a
//! half-configured daemon never serves traffic.

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use lr_core::addr::RouterId;
use lr_router::DefaultRouter;

use crate::daemon_config::DaemonConfig;

/// Shared state one embedded engine receives from the supervisor.
///
/// Engines are the *same* code paths as the standalone daemons —
/// `run_bgp_daemon` and friends take `Option<EngineHost>`; `None` is
/// the classic single-protocol daemon (own router, own running flag,
/// own ticker/API/signals), `Some(host)` plugs the engine into this
/// supervisor's shared plumbing.
pub(crate) struct EngineHost {
    /// The supervisor's runtime: shared router, shared running flag,
    /// shared reload closure. The engine skips constructing its own.
    pub(crate) runtime: Arc<crate::Runtime>,
    /// Session-thread liveness the shared ticker waits on at shutdown
    /// (the BGP engine counts its live peer sessions here).
    pub(crate) live_sessions: Arc<AtomicUsize>,
    /// Startup report channel to the supervisor: send
    /// [`EngineReport::Started`] once every socket is bound.
    pub(crate) report: SyncSender<EngineReport>,
    /// Release gate: after reporting Started, block here until the
    /// supervisor releases (privilege drop + API socket happen first).
    pub(crate) gate: Arc<StartGate>,
    /// Registry for protocol-specific `status` lines served through
    /// the shared runtime API socket.
    pub(crate) status: Arc<MultiStatus>,
}

/// Startup report an engine sends to the supervisor. Failure needs no
/// message here: an engine that cannot start simply returns its exit
/// code from the run function (printing diagnostics on the way), and
/// the supervisor notices the thread finishing before the report.
pub(crate) enum EngineReport {
    /// All sockets bound; the engine is waiting on its `StartGate`.
    Started,
}

/// One-shot startup gate between the supervisor and one engine.
///
/// Engines block in [`StartGate::wait`] after binding their sockets;
/// the supervisor either [`releases`](StartGate::release) them (normal
/// startup) or [`aborts`](StartGate::abort) them (a sibling engine
/// failed). A `Condvar` (not a plain `Barrier`) so a failing engine
/// that never reaches the gate cannot wedge the others.
pub(crate) struct StartGate {
    state: Mutex<GateState>,
    cv: Condvar,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GateState {
    Waiting,
    Released,
    Aborted,
}

impl StartGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(GateState::Waiting),
            cv: Condvar::new(),
        })
    }

    /// Engine side: block until the supervisor releases (`Ok`) or
    /// aborts (`Err`) the startup.
    pub(crate) fn wait(&self) -> Result<(), ()> {
        let mut state = self.state.lock().unwrap();
        loop {
            match *state {
                GateState::Released => return Ok(()),
                GateState::Aborted => return Err(()),
                GateState::Waiting => state = self.cv.wait(state).unwrap(),
            }
        }
    }

    /// Supervisor side: engines may enter their main loops.
    pub(crate) fn release(&self) {
        let mut state = self.state.lock().unwrap();
        *state = GateState::Released;
        drop(state);
        self.cv.notify_all();
    }

    /// Supervisor side: startup failed elsewhere; engines should
    /// unwind and exit without running.
    pub(crate) fn abort(&self) {
        let mut state = self.state.lock().unwrap();
        *state = GateState::Aborted;
        drop(state);
        self.cv.notify_all();
    }
}

/// One engine's status section for the shared runtime API.
pub(crate) type StatusSection = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Protocol-specific status lines contributed by the engines for the
/// shared runtime API `status` command. Engines register a closure at
/// startup (e.g. OSPF registers its graceful-restart + SR view); the
/// supervisor's `status_lines` flattens every section in registration
/// order.
pub(crate) struct MultiStatus {
    sections: Mutex<Vec<StatusSection>>,
}

impl MultiStatus {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            sections: Mutex::new(Vec::new()),
        })
    }

    /// Add one engine's status section.
    pub(crate) fn register(&self, section: StatusSection) {
        self.sections.lock().unwrap().push(section);
    }

    /// Flatten every section into the lines the API serves.
    fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        for section in self.sections.lock().unwrap().iter() {
            out.extend(section());
        }
        out
    }
}

/// One supervised protocol engine.
struct Engine {
    /// Engine name for logs ("bgp", "ospf", "ospf3", "babel").
    name: &'static str,
    handle: JoinHandle<ExitCode>,
    gate: Arc<StartGate>,
    report: Receiver<EngineReport>,
    /// Whether the engine's `Started` report has been received.
    started: bool,
}

/// Run the multi-protocol daemon: one shared router, one running
/// flag, one ticker and one API socket, one thread per engine.
///
/// `set` holds two or more of `bgp`, `ospf`, `babel` (the dispatcher
/// rejects anything else before calling this). `ospf` resolves to the
/// v2 or v3 engine per the config's `[ospf] version`.
pub(crate) fn run_multi_daemon(cfg: &DaemonConfig, rid: RouterId, set: &[String]) -> ExitCode {
    // The supervisor is the *sole* signal consumer: engine-side
    // dispatch becomes a no-op (see dispatch_signals), so connector
    // threads and session pumps can never steal the shutdown signal.
    if let Err(sig) = crate::signal::init() {
        eprintln!("daemon: cannot install signal handlers (signal {})", sig);
        return ExitCode::from(1);
    }
    crate::signal::set_supervised(true);

    // Shared plumbing.
    let router = Arc::new(Mutex::new(DefaultRouter::new()));
    // ---- [[redistribute]] / [[aggregate]] (ROADMAP-v3 D4.1/D4.2). ----
    // Applied once, here, before any engine spawns: pipes scan the
    // (still empty) Loc-RIB and fire on every later selection; the
    // embedded engines must not re-apply on the shared router.
    if let Err(e) = crate::apply_cross_protocol_config(cfg, &mut router.lock().unwrap()) {
        eprintln!("error: {}", e);
        return ExitCode::from(2);
    }
    let running = Arc::new(AtomicBool::new(true));
    let live_sessions = Arc::new(AtomicUsize::new(0));
    let status = MultiStatus::new();
    let current_networks = Arc::new(Mutex::new(cfg.networks.clone()));
    let runtime = Arc::new(crate::Runtime {
        reload: Arc::new({
            let router = Arc::clone(&router);
            let current_networks = Arc::clone(&current_networks);
            let config_path = cfg.config_path.clone();
            let config_dialect = cfg.config_dialect.clone();
            move || {
                crate::reload_config(
                    config_path.as_deref(),
                    config_dialect.as_deref(),
                    &router,
                    &current_networks,
                    None,
                    None,
                )
            }
        }),
        router: Arc::clone(&router),
        running: Arc::clone(&running),
        status_lines: Arc::new({
            let status = Arc::clone(&status);
            move || status.lines()
        }),
    });

    println!("librouting daemon (lr-daemon)");
    println!("  protocols:   {} (one shared Loc-RIB)", set.join(","));
    println!("  router-id:   {}", rid);
    println!("  install:     {}", cfg.install_kernel);
    println!("  platform:    {}", lr_osroute::PLATFORM_NAME);

    // One shared ticker drives every session's timers (BGP keepalive,
    // OSPF refresh/aging, Babel expiry) from one clock.
    let ticker = crate::spawn_ticker(&runtime, cfg.install_kernel, Arc::clone(&live_sessions));

    // ---- Spawn one thread per engine. ----
    let mut engines: Vec<Engine> = Vec::new();
    for name in set {
        let (report_tx, report_rx) = sync_channel::<EngineReport>(1);
        let gate = StartGate::new();
        let host = EngineHost {
            runtime: Arc::clone(&runtime),
            live_sessions: Arc::clone(&live_sessions),
            report: report_tx,
            gate: Arc::clone(&gate),
            status: Arc::clone(&status),
        };
        let cfg = cfg.clone();
        let engine_name: &'static str = match name.as_str() {
            "bgp" => "bgp",
            "ospf" => {
                if cfg.ospf_version == "v3" {
                    "ospf3"
                } else {
                    "ospf"
                }
            }
            "babel" => "babel",
            // The dispatcher validated the set; anything else is a bug.
            other => unreachable!("multi-protocol dispatcher let '{}' through", other),
        };
        let spawn = thread::Builder::new()
            .name(format!("lr-engine-{engine_name}"))
            .spawn(move || match engine_name {
                "bgp" => crate::run_bgp_daemon(&cfg, rid, Some(host)),
                "ospf" => crate::daemon_ospf::run_ospf_daemon(&cfg, rid, Some(host)),
                "ospf3" => crate::daemon_ospf3::run_ospf3_daemon(&cfg, rid, Some(host)),
                "babel" => crate::run_babel_daemon(&cfg, Some(host)),
                _ => unreachable!(),
            });
        match spawn {
            Ok(handle) => engines.push(Engine {
                name: engine_name,
                handle,
                gate,
                report: report_rx,
                started: false,
            }),
            Err(e) => {
                eprintln!("daemon: cannot spawn the {} engine: {}", name, e);
                shutdown_after_failure(&runtime, engines, ticker);
                return ExitCode::from(1);
            }
        }
    }

    // ---- Wait for every engine to finish binding its sockets. ----
    // An engine that fails startup never reports Started; its thread
    // finishes instead, so a report channel going away (or a finished
    // handle) is the failure signal — with the engine's exit code.
    let mut failure: Option<ExitCode> = None;
    loop {
        let mut all_started = true;
        let mut index = 0;
        while index < engines.len() {
            let engine = &mut engines[index];
            if engine.started {
                index += 1;
                continue;
            }
            let failed = match engine.report.try_recv() {
                Ok(EngineReport::Started) => {
                    engine.started = true;
                    index += 1;
                    continue;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // Still running and not reporting yet — unless the
                    // thread finished, which means startup failed.
                    engine.handle.is_finished()
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Dropped the report without sending: startup
                    // failure (the thread is on its way out).
                    true
                }
            };
            if !failed {
                all_started = false;
                index += 1;
                continue;
            }
            // Startup failure: take the engine out and read its code.
            let engine = engines.swap_remove(index);
            let code = join_engine(engine.handle);
            eprintln!("daemon: {} engine failed during startup", engine.name);
            failure = Some(code);
            break;
        }
        if failure.is_some() || all_started {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    if let Some(code) = failure {
        // Abort the combination: engines waiting on their gates exit,
        // engines still starting see the clear running flag.
        running.store(false, Ordering::Relaxed);
        for engine in &engines {
            engine.gate.abort();
        }
        for engine in engines {
            join_engine(engine.handle);
        }
        join_ticker(ticker);
        println!("daemon: multi-protocol startup aborted");
        return code;
    }

    // Every engine is bound. Privileged work is done: drop root before
    // touching any network input, then create the management socket as
    // the reduced user, then let the engines run.
    if let Err(e) = crate::do_privdrop(cfg) {
        eprintln!("daemon: {}", e);
        abort_all(&runtime, engines, ticker);
        return ExitCode::from(1);
    }
    if let Err(e) = crate::spawn_api(cfg, &runtime) {
        eprintln!("daemon: {}", e);
        abort_all(&runtime, engines, ticker);
        return ExitCode::from(1);
    }
    for engine in &engines {
        engine.gate.release();
    }
    println!("daemon: {} engine(s) running", engines.len());

    // ---- Supervise: dispatch signals, watch for engine deaths. ----
    // Any engine exiting while the daemon should be running is fatal —
    // a combination that silently lost one protocol is not a running
    // combination. The supervisor stops the others gracefully and
    // returns the dead engine's code.
    let mut engine_failure: Option<ExitCode> = None;
    while running.load(Ordering::Relaxed) {
        crate::dispatch_pending_signals(&runtime);
        let mut index = 0;
        while index < engines.len() {
            if engines[index].handle.is_finished() {
                let engine = engines.swap_remove(index);
                let code = join_engine(engine.handle);
                eprintln!(
                    "daemon: {} engine exited — stopping the remaining engines",
                    engine.name
                );
                engine_failure = Some(if code == ExitCode::SUCCESS {
                    // An engine returning SUCCESS mid-run is still a
                    // surprise; surface it as an error exit.
                    ExitCode::from(1)
                } else {
                    code
                });
                running.store(false, Ordering::Relaxed);
            } else {
                index += 1;
            }
        }
        if engine_failure.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Graceful shutdown: the engines' loops watch the same running
    // flag; SIGTERM/INT cleared it above.
    if engine_failure.is_none() {
        // Final signal sweep so a SIGHUP delivered during the shutdown
        // handshake does not vanish (best-effort, like the engines).
        crate::dispatch_pending_signals(&runtime);
    }
    for engine in engines {
        join_engine(engine.handle);
    }
    join_ticker(ticker);
    println!("daemon: multi-protocol shutdown complete");
    engine_failure.unwrap_or(ExitCode::SUCCESS)
}

/// Abort a fully-started combination after the supervisor itself hit
/// a fatal error (privilege drop or API socket failure): abort the
/// gates, clear the running flag, join everything.
fn abort_all(runtime: &crate::Runtime, engines: Vec<Engine>, ticker: JoinHandle<()>) {
    runtime.running.store(false, Ordering::Relaxed);
    for engine in &engines {
        engine.gate.abort();
    }
    for engine in engines {
        join_engine(engine.handle);
    }
    join_ticker(ticker);
}

/// Stop the world after an engine spawn failure (used before the
/// engines vector is complete): clear the running flag and join
/// whatever already spawned. The gates are still unreleased, so the
/// joined engines abort themselves once they reach the gate — or
/// return early because the flag is already clear.
fn shutdown_after_failure(runtime: &crate::Runtime, engines: Vec<Engine>, ticker: JoinHandle<()>) {
    runtime.running.store(false, Ordering::Relaxed);
    for engine in &engines {
        engine.gate.abort();
    }
    for engine in engines {
        join_engine(engine.handle);
    }
    join_ticker(ticker);
}

/// Join one engine thread, mapping a panic into an error exit code.
fn join_engine(handle: JoinHandle<ExitCode>) -> ExitCode {
    match handle.join() {
        Ok(code) => code,
        Err(_) => {
            eprintln!("daemon: engine thread panicked");
            ExitCode::from(1)
        }
    }
}

/// Join the shared ticker thread (unit payload; a panic is logged).
fn join_ticker(handle: JoinHandle<()>) {
    if handle.join().is_err() {
        eprintln!("daemon: ticker thread panicked");
    }
}
