//! Peer-level configuration reload for the BGP engine — issue #101
//! "Improving Configuration Reloading": atomic replacement of the
//! configuration with the automatic restart of only the minimal
//! necessary units.
//!
//! The unit model:
//!
//! - **One `[[peer]]` is one unit.** A peer added, removed or changed
//!   with session-affecting fields costs exactly that peer's
//!   sessions: the reload stops its connector, closes its live
//!   transports with the matching RFC 4486 §4.1 Cease subcode
//!   (Peer De-configured for a removal, Administrative Reset for a
//!   reconfiguration), removes and re-adds its router sessions, and
//!   respawns its connector. Every other peer's Established sessions
//!   keep running.
//! - **Policy is one unit, swapped in place.** Route-maps, named
//!   lists and per-session filter bindings live behind the
//!   [`LivePolicyState`](super::daemon_policy::LivePolicyState) swap
//!   boundary; a reload re-compiles them against the post-diff
//!   session handles and swaps. Sessions whose import policy may have
//!   changed are soft-reconfigured (`soft_reconfig_inbound`) — the
//!   BIRD `configure` behaviour — instead of restarted.
//! - **The listener is one unit.** A listen-address change or a
//!   change of the armed session-auth set replaces the listener
//!   socket: the reactor detaches and drops the old one, the reload
//!   binds and arms the fresh socket and re-attaches it.
//! - **BFD sessions are per-peer units** driven through the
//!   supervisor's command channel; the `[bfd]` timer triple re-points
//!   every session through `BfdSession::update_timers` (RFC 5880
//!   §6.8.3).
//!
//! Atomicity: the reload validates everything fallible first — the
//! fresh file parses and finalizes, every peer's auth builds, every
//! referenced route-map and filter name resolves — and only then
//! applies. A validation failure keeps the running configuration
//! entirely unchanged. The apply-phase steps are infallible by
//! construction for a finalized BGP config; the one OS-level
//! exception, a BFD socket bind for a newly enabled `bfd = true`
//! peer, keeps that peer untouched and reports it instead of
//! silently running without fast-fail.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::TcpListener as StdTcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use lr_bgp::error::BgpCeaseSubcode;
use lr_core::addr::RouterId;
use lr_osroute::tcp_auth::TcpAuth;
use lr_router::{DefaultRouter, RouterInstance, SessionHandle};

#[cfg(feature = "exchange-plane")]
use super::wire_exchange_plane;
use super::{
    build_inbound_gate, build_peer_gtsm, build_peer_tcp_auth, build_session_config,
    dial_local_address, expected_peer_ip, listener_auth, listener_gtsm, resolve, spawn_connector,
    PeerEntry, PeerRegistry, Runtime,
};
use crate::bgp_reactor;
use crate::daemon_bfd::{self, BfdFlags};
use crate::daemon_config::{DaemonConfig, PeerSpec};
use crate::daemon_policy::{self, LivePolicyState, SharedPolicyState};
use crate::{bind_tcp_reuse, Component};

/// Upper bound on waiting for a stopped connector thread to acknowledge
/// its exit: the sleep slices are ≤100 ms, the dial timeout 5 s, the
/// final flush 500 ms — 8 s covers the worst chain with margin.
const CONNECTOR_EXIT_WAIT: Duration = Duration::from_secs(8);

/// What a reload does with one configured peer, decided by diffing
/// the resolved live spec against the resolved fresh spec. Peers are
/// identified by their transport identity — `(remote, address)` — so
/// renaming a peer or reordering the `[[peer]]` table is not a
/// restart, and changing the address a peer is reached at is a
/// remove-plus-add.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PeerAction {
    /// The resolved specs are equal — nothing to do.
    Keep,
    /// Only policy bindings and/or the `shutdown` flag changed —
    /// applied in place, no session restart.
    HotUpdate,
    /// Session-affecting fields changed — restart this peer's
    /// sessions (RFC 4486 §4.1 Cease/4 Administrative Reset).
    Restart,
    /// The peer is no longer in the fresh config — stop it (Cease/3
    /// Peer De-configured) and remove it.
    Remove,
    /// The peer is new in the fresh config — start it.
    Add,
}

/// One planned per-peer change.
struct PlannedPeer {
    /// Index into the fresh config's `peers` table (`usize::MAX` for
    /// removals, which have no fresh counterpart).
    fresh_index: usize,
    /// Index into the live registry when the peer already exists.
    live_index: Option<usize>,
    action: PeerAction,
}

/// The fresh config's peer table classified against the live set.
struct PeerReloadPlan {
    peers: Vec<PlannedPeer>,
    /// The listener must be replaced (address or armed-auth change).
    replace_listener: bool,
    /// The `[bfd]` timer triple changed and every session must
    /// re-point.
    bfd_timers_changed: bool,
}

/// The transport identity of a peer: `(remote, address)` after
/// template resolution. Two specs with the same identity describe the
/// same neighbour; anything else is a different peer.
fn peer_identity(spec: &PeerSpec) -> (Option<&str>, Option<&str>) {
    (spec.remote.as_deref(), spec.address.as_deref())
}

/// Classify one old→new spec pair.
pub(super) fn classify_peer_change(old: &PeerSpec, new: &PeerSpec) -> PeerAction {
    if old == new {
        return PeerAction::Keep;
    }
    // `name` is a log label, the policy bindings apply in place, and
    // `shutdown` toggles the connector and the admin-down gate — all
    // hot. Everything else touches the OPEN negotiation, the
    // transport or the socket options and needs a session restart.
    let mut cold = false;
    macro_rules! differs {
        ($field:ident) => {
            if old.$field != new.$field {
                cold = true;
            }
        };
    }
    differs!(remote);
    differs!(address);
    differs!(peer_as);
    differs!(extends);
    differs!(hold_time);
    differs!(gr_restart_time);
    differs!(llgr_stale_time);
    differs!(llgr_max_stale_time);
    differs!(local_address);
    differs!(local_address_v6);
    differs!(md5_key);
    differs!(tcp_ao_keys);
    differs!(tcp_ao_algorithm);
    differs!(tcp_ao_maclen);
    differs!(add_path);
    differs!(add_path_max_paths);
    differs!(mp_families);
    differs!(default_ipv4_unicast);
    differs!(allow_local_as);
    differs!(soft_reconfig_inbound);
    differs!(extended_next_hop);
    differs!(gtsm_hops);
    differs!(max_prefixes);
    differs!(max_prefix_action);
    differs!(max_prefix_threshold);
    differs!(max_prefix_restart_time);
    differs!(bfd);
    differs!(bfd_multihop);
    differs!(exchange_plane);
    differs!(exchange_plane_policy_role);
    differs!(graceful_shutdown);
    differs!(route_reflector_client);
    differs!(extended_message);
    differs!(bgp_role);
    differs!(fqdn);
    differs!(bfd_strict_mode);
    differs!(software_version);
    differs!(paths_limit);
    differs!(link_local_next_hop);
    differs!(orf);
    differs!(orf_entries);
    if cold {
        PeerAction::Restart
    } else {
        PeerAction::HotUpdate
    }
}

/// Build the reload plan: classify every fresh peer against the live
/// registry and decide the listener / BFD-timer actions. Pure — no
/// mutation, no I/O; the caller validates auth and policy references
/// next.
fn plan_peer_reload(
    live: &[PeerEntry],
    fresh: &DaemonConfig,
    live_listen_addr: Option<&str>,
    live_armed_auth: &TcpAuth,
    live_bfd_timers: (u32, u32, u8),
) -> PeerReloadPlan {
    let mut peers = Vec::with_capacity(fresh.peers.len());
    for (fresh_index, spec) in fresh.peers.iter().enumerate() {
        let live_index = live
            .iter()
            .position(|e| peer_identity(&e.spec) == peer_identity(spec));
        let action = match live_index {
            Some(idx) => classify_peer_change(&live[idx].spec, spec),
            None => PeerAction::Add,
        };
        peers.push(PlannedPeer {
            fresh_index,
            live_index,
            action,
        });
    }
    // Live peers absent from the fresh table are removed.
    for (live_index, entry) in live.iter().enumerate() {
        let identity = peer_identity(&entry.spec);
        if !fresh.peers.iter().any(|p| peer_identity(p) == identity) {
            peers.push(PlannedPeer {
                fresh_index: usize::MAX,
                live_index: Some(live_index),
                action: PeerAction::Remove,
            });
        }
    }
    // Listener replacement: a bind-address change, or a change of the
    // auth set the listener must be armed with (computed exactly like
    // startup's `listener_auth`, from the fresh table).
    let replace_listener = match live_listen_addr {
        Some(old_addr) => match fresh.listen_addr.as_deref() {
            None => true,
            Some(new_addr) => new_addr != old_addr || &listener_auth_of(fresh) != live_armed_auth,
        },
        // No listener today: a fresh listen address needs a new one.
        None => fresh.listen_addr.is_some(),
    };
    let bfd_timers_changed = live_bfd_timers
        != (
            fresh.bfd_min_tx_ms,
            fresh.bfd_min_rx_ms,
            fresh.bfd_multiplier,
        );
    PeerReloadPlan {
        peers,
        replace_listener,
        bfd_timers_changed,
    }
}

/// The auth configuration a shared listener must be armed with —
/// every inbound-capable peer's auth, which must all be identical
/// (the same rule startup enforces; heterogeneous keys stay a
/// restart).
fn listener_auth_of(fresh: &DaemonConfig) -> TcpAuth {
    let strict = fresh.explicit_peers || fresh.peers.len() > 1;
    let auths: Vec<TcpAuth> = if strict {
        fresh
            .peers
            .iter()
            .filter(|p| p.is_inbound() || (p.is_outbound() && fresh.listen_addr.is_some()))
            .filter_map(|p| build_peer_tcp_auth(fresh, p).ok())
            .collect()
    } else {
        fresh
            .peers
            .first()
            .and_then(|p| build_peer_tcp_auth(fresh, p).ok())
            .into_iter()
            .collect()
    };
    auths.first().cloned().unwrap_or(TcpAuth::None)
}

/// Everything the peer-reload engine drives: the live peer set, the
/// reactor, the BFD supervisor handle, the policy swap boundary and
/// the observability maps. Built once by the BGP engine (standalone
/// or embedded in the multi-protocol supervisor) and shared into its
/// reload closure.
pub(super) struct BgpReloadContext {
    pub(super) rid: RouterId,
    pub(super) router: Arc<RwLock<DefaultRouter>>,
    pub(super) runtime: Arc<Runtime>,
    pub(super) registry: PeerRegistry,
    pub(super) reactor: bgp_reactor::BgpReactor,
    pub(super) bfd: Arc<Mutex<daemon_bfd::BfdSupervisor>>,
    pub(super) policy: SharedPolicyState,
    pub(super) gs_exempt: Arc<RwLock<BTreeSet<u64>>>,
    pub(super) session_labels: Arc<Mutex<HashMap<u64, String>>>,
    pub(super) live_sessions: Arc<AtomicUsize>,
    /// The address the live listener is bound to, if any.
    pub(super) listen_addr: Mutex<Option<String>>,
    /// The auth the live listener is armed with.
    pub(super) armed_auth: Mutex<TcpAuth>,
    pub(super) strict_inbound: bool,
    /// The daemon-wide configuration as last applied (the diff base
    /// for policy-change detection). Updated by the daemon-level
    /// reload after every successful pass.
    pub(super) current_config: Arc<Mutex<DaemonConfig>>,
}

impl BgpReloadContext {
    /// Stop one peer's connector and live sessions with the RFC 4486
    /// §4.1 Cease subcode the caller chose, wait for the connector
    /// thread to acknowledge its exit, then remove the router
    /// sessions. The registry is NOT touched — the caller owns the
    /// entry's fate.
    ///
    /// No registry lock may be held by the caller: the reactor thread
    /// runs the inbound gate, which takes the read lock per accepted
    /// connection, and this function waits on the reactor's close
    /// handshake.
    fn stop_peer_sessions(
        &self,
        entry: &PeerEntry,
        subcode: BgpCeaseSubcode,
        lines: &mut Vec<String>,
    ) {
        // 1. Stop the connector: no new dials race the teardown.
        entry.stop.store(true, Ordering::Relaxed);
        // 2. Graceful slot teardown — queues the Cease NOTIFICATION,
        //    flushes it, closes the socket, then confirms. A handle
        //    with no live slot confirms immediately; a connector
        //    blocked on its session's completion channel is woken by
        //    the teardown's callback.
        for handle in [Some(entry.handle), entry.handle_in].into_iter().flatten() {
            if let Err(e) = self.reactor.close_session_admin(handle, subcode as u8) {
                lines.push(format!(
                    "reload: peer {}: session #{} close: {e}",
                    entry.label(),
                    handle.0
                ));
            }
        }
        // 3. Wait for the connector thread to acknowledge the stop so
        //    a replacement can never overlap a lagging predecessor
        //    (a dial in flight, a submission in the reactor queue).
        let spawned = entry.connector_gen.load(Ordering::Relaxed);
        let deadline = Instant::now() + CONNECTOR_EXIT_WAIT;
        while entry.connector_exited.load(Ordering::Relaxed) < spawned {
            if Instant::now() >= deadline {
                lines.push(format!(
                    "reload: peer {}: connector did not confirm its exit in time — \
                     a replacement connector is deferred to the next reload",
                    entry.label()
                ));
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // 4. Remove the router sessions: Adj-RIB-In purge, bookkeeping
        //    teardown, best-path re-selection and withdrawal
        //    propagation to the surviving peers.
        let mut r = self.router.write().unwrap();
        for handle in [Some(entry.handle), entry.handle_in].into_iter().flatten() {
            let _ = r.remove_session(handle);
        }
    }

    /// Remove one peer's BFD session (peer removed, or `bfd` turned
    /// off).
    fn bfd_remove(&self, entry: &PeerEntry) {
        if entry.bfd.is_some() {
            if let Some(peer_ip) = expected_peer_ip(&entry.spec) {
                self.bfd
                    .lock()
                    .unwrap()
                    .remove_peer(entry.label(), to_std_ip(peer_ip));
            }
        }
    }

    /// Add (or keep) one peer's BFD session. Returns the liveness
    /// flags: the freshly created session's on first enable, or the
    /// surviving session's when the peer restarts with `bfd`
    /// unchanged (the BFD session is independent of the BGP
    /// transport).
    fn bfd_add(
        &self,
        cfg: &DaemonConfig,
        spec: &PeerSpec,
        prior: Option<&BfdFlags>,
    ) -> Result<Option<BfdFlags>, String> {
        if !cfg.effective_bfd(spec) {
            return Ok(None);
        }
        // A surviving session keeps its flags — the peer address and
        // mode are the peer's identity, which a restart leaves
        // unchanged by definition.
        if let Some(flags) = prior {
            return Ok(Some(flags.clone()));
        }
        let Some(peer_ip) = expected_peer_ip(spec) else {
            return Err(format!(
                "peer {}: bfd requires a resolvable peer address \
                 ('remote' host or 'address')",
                spec.label()
            ));
        };
        let Some(local_ip) = dial_local_address(cfg, spec, peer_ip.is_ipv6()) else {
            return Err(format!(
                "peer {}: bfd requires a local address of the peer's family \
                 (--local-address / local_address; local_address_v6 for an IPv6 peer)",
                spec.label()
            ));
        };
        let mode = if cfg.effective_bfd_multihop(spec) {
            lr_osroute::bfd_transport::BfdMode::Multihop
        } else {
            lr_osroute::bfd_transport::BfdMode::SingleHop
        };
        let flags = self.bfd.lock().unwrap().add_peer(daemon_bfd::BfdPeerSpec {
            label: spec.label().to_string(),
            peer_ip: to_std_ip(peer_ip),
            local_ip: to_std_ip(local_ip),
            mode,
        })?;
        Ok(Some(flags))
    }

    /// Build one peer's sessions on the live router and return its
    /// registry entry. The spec must be validated (peer AS, auth) —
    /// this is the apply phase.
    fn build_peer_entry(
        &self,
        cfg: &DaemonConfig,
        spec: &PeerSpec,
        collision_group: u64,
    ) -> Result<PeerEntry, String> {
        let auth = build_peer_tcp_auth(cfg, spec)?;
        let gtsm = build_peer_gtsm(cfg, spec);
        let sc = build_session_config(cfg, spec, self.rid);
        let bidirectional = spec.is_outbound() && (spec.is_inbound() || cfg.listen_addr.is_some());
        let mut sc_out = sc.clone();
        let mut sc_in: Option<lr_router::SessionConfig> = None;
        if bidirectional {
            sc_out.collision_group = Some(collision_group);
            sc_out.locally_initiated = true;
            let mut c = sc.clone();
            c.collision_group = Some(collision_group);
            c.locally_initiated = false;
            sc_in = Some(c);
        }
        let mut r = self.router.write().unwrap();
        let handle = r.add_session(sc_out)?;
        let handle_in = match sc_in {
            Some(c) => Some(r.add_session(c)?),
            None => None,
        };
        let has_import = spec.import.is_some() || spec.import_filter.is_some();
        let has_export = spec.export.is_some() || spec.export_filter.is_some();
        for hh in [Some(handle), handle_in].into_iter().flatten() {
            r.set_session_policy(hh, has_import, has_export)?;
            // Exchange plane (feature `exchange-plane`): activate the
            // record plane for peers that opted in.
            #[cfg(feature = "exchange-plane")]
            if spec.exchange_plane.unwrap_or(cfg.exchange_plane) {
                wire_exchange_plane(&mut r, hh, cfg, spec)?;
            }
        }
        #[cfg(not(feature = "exchange-plane"))]
        {
            let xp_requested = spec.exchange_plane.unwrap_or(cfg.exchange_plane)
                || !cfg.exchange_plane_keys.is_empty();
            if xp_requested {
                return Err(format!(
                    "peer {}: exchange_plane requested but this binary was built \
                     without the exchange-plane feature",
                    spec.label()
                ));
            }
        }
        Ok(PeerEntry {
            spec: spec.clone(),
            handle,
            handle_in,
            auth,
            gtsm,
            bfd: None,
            busy: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            connector_gen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            connector_exited: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            outbound_lost_collision: Arc::new(AtomicBool::new(false)),
            admin_down: spec.shutdown.unwrap_or(false),
            bfd_strict_mode: spec.bfd_strict_mode.unwrap_or(cfg.bfd_strict_mode),
        })
    }

    /// Spawn the connector for one registry entry unless it is
    /// admin-down or not outbound.
    fn spawn_connector_for(&self, entry: &PeerEntry, fresh: &DaemonConfig) {
        if entry.admin_down || !entry.spec.is_outbound() {
            return;
        }
        spawn_connector(
            &self.runtime,
            &self.reactor,
            entry,
            fresh,
            Arc::clone(&self.live_sessions),
        );
    }

    /// Validate + apply the fresh peer table. Returns the report
    /// lines; an `Err` means validation failed and *nothing* was
    /// applied (the caller keeps the running configuration).
    pub(super) fn reload_peers(&self, fresh: &DaemonConfig) -> Result<Vec<String>, String> {
        let current = self.current_config.lock().unwrap().clone();
        let live: Vec<PeerEntry> = self.registry.read().unwrap().clone();
        let live_listen = self.listen_addr.lock().unwrap().clone();
        let live_auth = self.armed_auth.lock().unwrap().clone();
        let live_bfd = {
            let bfd = self.bfd.lock().unwrap();
            (bfd.min_tx_ms(), bfd.min_rx_ms(), bfd.detect_multiplier())
        };
        let plan = plan_peer_reload(&live, fresh, live_listen.as_deref(), &live_auth, live_bfd);

        // ---- Validation pass: everything fallible, no mutation. ----
        // Speaker identity is daemon-wide: the local AS is baked into
        // every session configuration and the safety net, the
        // router-id into every OPEN. A change is a daemon restart,
        // not a per-unit reload — refuse the whole reload so the
        // operator sees it as one atomic decision.
        if fresh.local_as != current.local_as {
            return Err(format!(
                "local AS {} -> {} requires a daemon restart (speaker identity)",
                current.local_as, fresh.local_as
            ));
        }
        if fresh.router_id != current.router_id {
            return Err(format!(
                "router-id {} -> {} requires a daemon restart (speaker identity)",
                current.router_id, fresh.router_id
            ));
        }
        for spec in &fresh.peers {
            if fresh.effective_peer_as(spec) == 0 {
                return Err(format!(
                    "peer {}: no peer AS configured (set peer_as or the global --peer-as)",
                    spec.label()
                ));
            }
            if spec.is_inbound() && fresh.listen_addr.is_none() {
                return Err(format!(
                    "peer {}: inbound peers require --listen",
                    spec.label()
                ));
            }
            build_peer_tcp_auth(fresh, spec)
                .map_err(|e| format!("peer {}: {}", spec.label(), e))?;
            // BFD prerequisites for the peers that will need a *new*
            // session (first enable; an unchanged bfd survives the
            // peer restart).
            let needs_bfd = fresh.effective_bfd(spec)
                && live
                    .iter()
                    .find(|e| peer_identity(&e.spec) == peer_identity(spec))
                    .is_none_or(|e| e.bfd.is_none());
            if needs_bfd {
                let Some(peer_ip) = expected_peer_ip(spec) else {
                    return Err(format!(
                        "peer {}: bfd requires a resolvable peer address \
                         ('remote' host or 'address')",
                        spec.label()
                    ));
                };
                if dial_local_address(fresh, spec, peer_ip.is_ipv6()).is_none() {
                    return Err(format!(
                        "peer {}: bfd requires a local address of the peer's family",
                        spec.label()
                    ));
                }
            }
        }
        // Policy references: every bound route-map / filter name must
        // resolve in the fresh table (the full state build happens in
        // the apply phase, against the post-diff handles).
        let probe = daemon_policy::build_policy_set(fresh).map_err(|e| format!("policy: {e}"))?;
        for peer in &fresh.peers {
            for name in [&peer.import, &peer.export].into_iter().flatten() {
                if probe.route_map(name).is_none() {
                    return Err(format!("peer {}: unknown route-map '{name}'", peer.label()));
                }
            }
        }
        let filters = daemon_policy::build_filters(fresh).map_err(|e| format!("policy: {e}"))?;
        for peer in &fresh.peers {
            for name in [&peer.import_filter, &peer.export_filter]
                .into_iter()
                .flatten()
            {
                if !filters.iter().any(|(n, _)| n == name) {
                    return Err(format!("peer {}: unknown filter '{name}'", peer.label()));
                }
            }
        }
        // Listener replacement prerequisite: the fresh address must
        // resolve (the bind itself is retried in the apply phase).
        if plan.replace_listener && fresh.listen_addr.is_some() {
            let addr = fresh.listen_addr.as_deref().expect("checked is_some");
            if resolve(addr).is_none() {
                return Err(format!("cannot resolve {addr}"));
            }
        }

        // ---- Apply pass. ----
        let mut lines = Vec::new();
        let policy_sections_changed = policy_config_changed(&current, fresh);

        // BFD timer re-point first: every surviving session picks the
        // fresh triple up before any peer churn (RFC 5880 §6.8.3).
        if plan.bfd_timers_changed {
            self.bfd.lock().unwrap().update_timers(
                fresh.bfd_min_tx_ms,
                fresh.bfd_min_rx_ms,
                fresh.bfd_multiplier,
            );
            lines.push(format!(
                "reload: bfd timers -> min_tx {} ms, min_rx {} ms, multiplier {}",
                fresh.bfd_min_tx_ms, fresh.bfd_min_rx_ms, fresh.bfd_multiplier
            ));
        }

        // Removals and restarts first (free the identities), then
        // additions — a peer that moved address leaves the old
        // identity before the new one binds.
        let mut restarted: Vec<PeerEntry> = Vec::new();
        for planned in plan.peers.iter().filter(|p| p.action == PeerAction::Remove) {
            let Some(idx) = planned.live_index else {
                continue;
            };
            let entry = &live[idx];
            self.stop_peer_sessions(entry, BgpCeaseSubcode::PeerDeconfigured, &mut lines);
            self.bfd_remove(entry);
            lines.push(format!("reload: peer {} removed", entry.label()));
        }
        for planned in plan
            .peers
            .iter()
            .filter(|p| p.action == PeerAction::Restart)
        {
            let Some(idx) = planned.live_index else {
                continue;
            };
            let entry = &live[idx];
            self.stop_peer_sessions(entry, BgpCeaseSubcode::AdministrativeReset, &mut lines);
            lines.push(format!(
                "reload: peer {} reconfigured — restarting its sessions \
                 (RFC 4486 §4.1 Cease/4)",
                entry.label()
            ));
            restarted.push(entry.clone());
        }

        // Registry rewrite: one write lock, one pass — drop removed
        // entries, swap hot updates' specs, drop the restarted
        // entries (their replacements are appended below).
        {
            let mut registry = self.registry.write().unwrap();
            let remove_set: BTreeSet<usize> = plan
                .peers
                .iter()
                .filter(|p| p.action == PeerAction::Remove)
                .filter_map(|p| p.live_index)
                .collect();
            let mut new_entries: Vec<PeerEntry> = Vec::with_capacity(registry.len());
            for (idx, entry) in registry.iter().enumerate() {
                if remove_set.contains(&idx) {
                    continue;
                }
                if let Some(planned) = plan
                    .peers
                    .iter()
                    .find(|p| p.live_index == Some(idx) && p.action == PeerAction::HotUpdate)
                {
                    let spec = &fresh.peers[planned.fresh_index];
                    let mut e = entry.clone();
                    e.admin_down = spec.shutdown.unwrap_or(false);
                    e.spec = spec.clone();
                    new_entries.push(e);
                } else {
                    new_entries.push(entry.clone());
                }
            }
            let restart_ids: BTreeSet<(Option<String>, Option<String>)> = restarted
                .iter()
                .map(|e| (e.spec.remote.clone(), e.spec.address.clone()))
                .collect();
            new_entries.retain(|e| {
                !restart_ids.contains(&(e.spec.remote.clone(), e.spec.address.clone()))
            });
            *registry = new_entries;
        }

        // Restarted peers: BFD first (a session whose config did not
        // change survives the BGP restart), then the fresh sessions.
        for old in &restarted {
            let spec = fresh
                .peers
                .iter()
                .find(|p| peer_identity(p) == peer_identity(&old.spec))
                .expect("the plan matched it");
            match self.bfd_add(fresh, spec, old.bfd.as_ref()) {
                Ok(bfd) => {
                    let group = (self.registry.read().unwrap().len() + 1) as u64;
                    match self.build_peer_entry(fresh, spec, group) {
                        Ok(mut entry) => {
                            entry.bfd = bfd;
                            self.registry.write().unwrap().push(entry.clone());
                            self.spawn_connector_for(&entry, fresh);
                        }
                        Err(e) => {
                            // Apply-phase failure for a finalized
                            // config is a daemon bug; report it loudly
                            // and leave the peer down rather than
                            // half-configured.
                            if let (Some(_bfd), Some(peer_ip)) = (&bfd, expected_peer_ip(spec)) {
                                self.bfd
                                    .lock()
                                    .unwrap()
                                    .remove_peer(spec.label(), to_std_ip(peer_ip));
                            }
                            lines.push(format!(
                                "reload: peer {}: {e} — the peer is DOWN; \
                                 fix the configuration and reload again",
                                spec.label()
                            ));
                        }
                    }
                }
                Err(e) => {
                    lines.push(format!(
                        "reload: peer {}: {e} — the peer is DOWN; fix the \
                         configuration and reload again",
                        spec.label()
                    ));
                }
            }
        }

        // Additions.
        for planned in plan.peers.iter().filter(|p| p.action == PeerAction::Add) {
            let spec = &fresh.peers[planned.fresh_index];
            match self.bfd_add(fresh, spec, None) {
                Ok(bfd) => {
                    let group = (self.registry.read().unwrap().len() + 1) as u64;
                    match self.build_peer_entry(fresh, spec, group) {
                        Ok(mut entry) => {
                            entry.bfd = bfd;
                            self.registry.write().unwrap().push(entry.clone());
                            self.spawn_connector_for(&entry, fresh);
                            lines.push(format!("reload: peer {} added", spec.label()));
                        }
                        Err(e) => {
                            if let (Some(_bfd), Some(peer_ip)) = (&bfd, expected_peer_ip(spec)) {
                                self.bfd
                                    .lock()
                                    .unwrap()
                                    .remove_peer(spec.label(), to_std_ip(peer_ip));
                            }
                            lines.push(format!("reload: peer {}: {e} — not added", spec.label()));
                        }
                    }
                }
                Err(e) => {
                    lines.push(format!("reload: peer {}: {e} — not added", spec.label()));
                }
            }
        }

        // `shutdown` toggles on hot-updated peers: Cease/2 close +
        // connector stop when turning down; connector spawn when
        // turning up (the stop handshake above guarantees the old
        // connector is gone before a new one spawns).
        for planned in plan
            .peers
            .iter()
            .filter(|p| p.action == PeerAction::HotUpdate)
        {
            let Some(idx) = planned.live_index else {
                continue;
            };
            let old = &live[idx];
            let spec = &fresh.peers[planned.fresh_index];
            let was_down = old.admin_down;
            let now_down = spec.shutdown.unwrap_or(false);
            let entry_now = self
                .registry
                .read()
                .unwrap()
                .iter()
                .find(|e| peer_identity(&e.spec) == peer_identity(spec))
                .cloned();
            match (was_down, now_down) {
                (false, true) => {
                    // FRR `neighbor X shutdown`: close the live
                    // sessions with the shutdown Cease and stop the
                    // connector; the entry stays (admin-down).
                    if let Some(entry) = &entry_now {
                        self.stop_peer_sessions(
                            entry,
                            BgpCeaseSubcode::AdministrativeShutdown,
                            &mut lines,
                        );
                    }
                    lines.push(format!(
                        "reload: peer {} admin-down (shutdown = true)",
                        spec.label()
                    ));
                }
                (true, false) => {
                    if let Some(entry) = &entry_now {
                        entry.stop.store(false, Ordering::Relaxed);
                        self.spawn_connector_for(entry, fresh);
                    }
                    lines.push(format!(
                        "reload: peer {} admin-up (shutdown = false) — connector started",
                        spec.label()
                    ));
                }
                _ => {}
            }
            // RFC 8212 §3 policy-presence changes on a hot update:
            // re-declare the directions.
            if let Some(entry) = &entry_now {
                let has_import = spec.import.is_some() || spec.import_filter.is_some();
                let has_export = spec.export.is_some() || spec.export_filter.is_some();
                let mut r = self.router.write().unwrap();
                for hh in [Some(entry.handle), entry.handle_in].into_iter().flatten() {
                    let _ = r.set_session_policy(hh, has_import, has_export);
                }
            }
        }

        // Policy rebuild + swap against the post-diff handles, then
        // soft reconfigure the sessions whose import policy may have
        // changed (BIRD `configure` semantics: re-import in place
        // instead of bouncing the session).
        {
            let metrics = self.runtime.filter_metrics.lock().unwrap().clone();
            let handles: BTreeMap<usize, Option<(u64, Option<u64>)>> = {
                // The registry is in its post-diff shape; map the
                // fresh config's peer order onto it by identity.
                let registry = self.registry.read().unwrap();
                fresh
                    .peers
                    .iter()
                    .enumerate()
                    .map(|(idx, spec)| {
                        let entry = registry
                            .iter()
                            .find(|e| peer_identity(&e.spec) == peer_identity(spec));
                        (idx, entry.map(|e| (e.handle.0, e.handle_in.map(|h| h.0))))
                    })
                    .collect()
            };
            let prior: Option<LivePolicyState> = Some((**self.policy.read().unwrap()).clone());
            let state = daemon_policy::build_live_policy_state(
                fresh,
                metrics.as_ref(),
                prior.as_ref(),
                |idx| handles.get(&idx).copied().flatten(),
            )
            .map_err(|e| format!("policy: {e}"))?;
            state.install(&self.policy);
            if policy_sections_changed {
                let mut reconfigured = 0;
                {
                    let mut r = self.router.write().unwrap();
                    let registry = self.registry.read().unwrap();
                    for entry in registry.iter() {
                        for hh in [Some(entry.handle), entry.handle_in].into_iter().flatten() {
                            if r.soft_reconfig_inbound(hh).is_ok() {
                                reconfigured += 1;
                            }
                        }
                    }
                }
                lines.push(format!(
                    "reload: policy recompiled ({} session(s) soft-reconfigured)",
                    reconfigured
                ));
            }
        }

        // RFC 8326 §3.1 exemptions: recompute against the post-diff
        // handles.
        {
            let mut exempt = BTreeSet::new();
            let registry = self.registry.read().unwrap();
            for spec in fresh.peers.iter() {
                if spec.graceful_shutdown == Some(false) {
                    if let Some(entry) = registry
                        .iter()
                        .find(|e| peer_identity(&e.spec) == peer_identity(spec))
                    {
                        exempt.insert(entry.handle.0);
                        if let Some(h2) = entry.handle_in {
                            exempt.insert(h2.0);
                        }
                    }
                }
            }
            *self.gs_exempt.write().unwrap() = exempt;
        }

        // Observability: session labels follow the handles.
        {
            let registry = self.registry.read().unwrap();
            let labels: HashMap<u64, String> = registry
                .iter()
                .flat_map(|e| {
                    let base = e.spec.label().to_string();
                    let mut pairs = vec![(e.handle.0, base.clone())];
                    if let Some(h2) = e.handle_in {
                        pairs.push((h2.0, format!("{base} (inbound)")));
                    }
                    pairs
                })
                .collect();
            *self.session_labels.lock().unwrap() = labels;
        }

        // Listener replacement (bind-address change or armed-auth
        // change): detach the old socket, bind + arm the fresh one,
        // re-attach. Inbound connections are refused for the window.
        if plan.replace_listener {
            if let Some(addr) = fresh.listen_addr.clone() {
                match self.replace_listener(&addr, fresh) {
                    Ok(()) => lines.push(format!(
                        "reload: listener replaced on {addr} (auth re-armed)"
                    )),
                    Err(e) => lines.push(format!(
                        "reload: listener replacement failed ({e}) — \
                         the previous listener keeps serving"
                    )),
                }
            } else if self.reactor.detach_listener().is_ok() {
                // The fresh config dropped --listen: the listener goes.
                *self.listen_addr.lock().unwrap() = None;
                *self.armed_auth.lock().unwrap() = TcpAuth::None;
                lines.push("reload: listener removed (no --listen in the fresh config)".into());
            }
        }

        Ok(lines)
    }

    /// Detach, rebind and re-attach the listener with freshly armed
    /// auth and GTSM filters.
    fn replace_listener(&self, addr: &str, fresh: &DaemonConfig) -> Result<(), String> {
        self.reactor.detach_listener()?;
        let sockaddr = resolve(addr).ok_or_else(|| format!("cannot resolve {addr}"))?;
        // The old socket is closed by the detach; a racing process can
        // steal the port — retry a bounded number of times.
        let mut listener: Option<StdTcpListener> = None;
        let mut last_err = String::new();
        for _ in 0..5 {
            match bind_tcp_reuse(sockaddr) {
                Ok(l) => {
                    listener = Some(l);
                    break;
                }
                Err(e) => {
                    last_err = e.to_string();
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        let l = listener.ok_or_else(|| format!("bind {addr} failed: {last_err}"))?;
        // Arm auth + GTSM from the fresh table, exactly like startup.
        let inbound_auth = {
            let registry = self.registry.read().unwrap();
            listener_auth(fresh, &registry).map_err(|e| format!("session auth arming: {e}"))?
        };
        lr_osroute::tcp_auth::arm_listener(&l, &inbound_auth)
            .map_err(|e| format!("session auth arming: {e}"))?;
        let inbound_gtsm = {
            let registry = self.registry.read().unwrap();
            listener_gtsm(fresh, &registry)
        };
        if !inbound_gtsm.is_disabled() {
            lr_osroute::gtsm::arm_listener_gtsm(&l, &inbound_gtsm)
                .map_err(|e| format!("GTSM arming: {e}"))?;
        }
        l.set_nonblocking(true)
            .map_err(|e| format!("cannot set listener non-blocking: {e}"))?;
        let gate = build_inbound_gate(
            Arc::clone(&self.registry),
            self.strict_inbound,
            Arc::clone(&self.live_sessions),
        );
        self.reactor.attach_listener(l, gate)?;
        *self.listen_addr.lock().unwrap() = Some(addr.to_string());
        *self.armed_auth.lock().unwrap() = inbound_auth;
        Ok(())
    }
}

/// Map an `lr_core` address onto the std type.
fn to_std_ip(ip: lr_core::addr::IpAddr) -> std::net::IpAddr {
    match ip {
        lr_core::addr::IpAddr::V4(o) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(o)),
        lr_core::addr::IpAddr::V6(o) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(o)),
    }
}

/// Whether any policy-carrying section of the configuration changed
/// between the running config and the fresh one — the trigger for
/// recompiling and soft-reconfiguring.
fn policy_config_changed(current: &DaemonConfig, fresh: &DaemonConfig) -> bool {
    current.route_maps != fresh.route_maps
        || current.prefix_lists != fresh.prefix_lists
        || current.as_path_lists != fresh.as_path_lists
        || current.community_lists != fresh.community_lists
        || current.filters != fresh.filters
        || current.filter_functions != fresh.filter_functions
        || current.peers != fresh.peers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(remote: Option<&str>, address: Option<&str>) -> PeerSpec {
        let mut p = PeerSpec::default();
        p.remote = remote.map(str::to_string);
        p.address = address.map(str::to_string);
        p
    }

    fn entry_of(spec: PeerSpec) -> PeerEntry {
        PeerEntry {
            spec,
            handle: SessionHandle(1),
            handle_in: None,
            auth: TcpAuth::None,
            gtsm: Default::default(),
            bfd: None,
            busy: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            connector_gen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            connector_exited: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            outbound_lost_collision: Arc::new(AtomicBool::new(false)),
            admin_down: false,
            bfd_strict_mode: false,
        }
    }

    #[test]
    fn equal_specs_keep() {
        assert_eq!(
            classify_peer_change(
                &spec(Some("1.2.3.4:179"), None),
                &spec(Some("1.2.3.4:179"), None)
            ),
            PeerAction::Keep
        );
    }

    #[test]
    fn policy_binding_and_shutdown_changes_are_hot() {
        let a = spec(Some("1.2.3.4:179"), None);
        let mut b = a.clone();
        b.import = Some("rm-in".into());
        assert_eq!(classify_peer_change(&a, &b), PeerAction::HotUpdate);
        b.shutdown = Some(true);
        assert_eq!(classify_peer_change(&a, &b), PeerAction::HotUpdate);
        b.import = None;
        b.shutdown = None;
        b.name = Some("renamed".into());
        assert_eq!(classify_peer_change(&a, &b), PeerAction::HotUpdate);
        b.name = None;
        b.export_filter = Some("f-out".into());
        assert_eq!(classify_peer_change(&a, &b), PeerAction::HotUpdate);
    }

    #[test]
    fn session_affecting_changes_restart() {
        for mutate in [
            (|p: &mut PeerSpec| p.peer_as = 65010) as fn(&mut PeerSpec),
            |p: &mut PeerSpec| p.hold_time = Some(60),
            |p: &mut PeerSpec| p.md5_key = Some("k".into()),
            |p: &mut PeerSpec| p.add_path = Some(true),
            |p: &mut PeerSpec| p.bfd = Some(true),
            |p: &mut PeerSpec| p.bgp_role = Some(("rs-client".into(), true)),
            |p: &mut PeerSpec| p.orf = Some(Vec::new()),
            |p: &mut PeerSpec| p.max_prefixes = Some(1000),
            |p: &mut PeerSpec| p.gtsm_hops = Some(2),
            |p: &mut PeerSpec| p.paths_limit = Some(vec![(1, 0, 8)]),
        ] {
            let a = spec(Some("1.2.3.4:179"), None);
            let mut b = a.clone();
            mutate(&mut b);
            assert_eq!(
                classify_peer_change(&a, &b),
                PeerAction::Restart,
                "the mutated field must restart the peer"
            );
        }
    }

    #[test]
    fn plan_classifies_add_remove_and_listener() {
        let base = DaemonConfig::default();
        let mut fresh = DaemonConfig::default();
        fresh.listen_addr = Some("0.0.0.0:179".into());
        let mut keep_spec = spec(Some("10.0.0.1:179"), None);
        keep_spec.peer_as = 65001;
        fresh.peers = vec![keep_spec.clone(), spec(None, Some("10.0.0.2"))];
        let plan = plan_peer_reload(
            &[entry_of(keep_spec)],
            &fresh,
            None,
            &TcpAuth::None,
            (base.bfd_min_tx_ms, base.bfd_min_rx_ms, base.bfd_multiplier),
        );
        assert_eq!(plan.peers.len(), 2);
        assert_eq!(plan.peers[0].action, PeerAction::Keep);
        assert_eq!(plan.peers[1].action, PeerAction::Add);
        assert!(
            plan.replace_listener,
            "a listen address appearing needs a listener"
        );
        assert!(!plan.bfd_timers_changed);
    }

    #[test]
    fn plan_marks_removals() {
        let fresh = DaemonConfig::default();
        let plan = plan_peer_reload(
            &[entry_of(spec(Some("10.0.0.1:179"), None))],
            &fresh,
            None,
            &TcpAuth::None,
            (0, 0, 0),
        );
        assert_eq!(plan.peers.len(), 1);
        assert_eq!(plan.peers[0].action, PeerAction::Remove);
        assert_eq!(plan.peers[0].fresh_index, usize::MAX);
    }

    #[test]
    fn hot_shutdown_toggle_is_not_a_restart() {
        let a = spec(Some("10.0.0.1:179"), None);
        let mut b = a.clone();
        b.shutdown = Some(true);
        assert_eq!(classify_peer_change(&a, &b), PeerAction::HotUpdate);
    }
}
