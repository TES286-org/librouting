//! `lr-daemon --protocol ospf` with `[ospf] version = "v3"` — OSPFv3
//! daemon mode (RFC 5340).
//!
//! The v3 counterpart of [`daemon_ospf`](crate::daemon_ospf): the same
//! poll-driven split (the [`DefaultRouter`] pipeline owns the neighbor
//! FSMs, per-area LSDBs, flooding and SPF; this module owns everything
//! the embedder must supply), with the v3 specifics:
//!
//! - **Transport** — one raw IPv6 socket per configured interface
//!   ([`lr_osroute::ospf_transport::OspfV6Transport`]), multicasting to
//!   ff02::5 (RFC 5340 §4.2.1). No interface address is required: the
//!   source is the link-local address (`interface_v6_addrs`), which the
//!   daemon also advertises in its Link-LSA (§4.4.3.4).
//! - **Interface IDs** — the kernel ifindex (FRR convention). The
//!   neighbor's Interface ID comes from its Hello's Interface ID field,
//!   which is exactly what our Router-LSA's p2p link descriptions need
//!   (§A.4.3).
//! - **Self-origination** — a Router-LSA per area (p2p links per Full
//!   adjacency, or the RFC 5340 §4.4.3.2 transit links on broadcast
//!   segments), a Link-LSA per interface (the §4.4.3.4 MUST, carrying
//!   the link-local address and the interface's global prefixes), and
//!   the Intra-Area-Prefix-LSAs attaching the global prefixes to the
//!   Router-LSA (§4.4.3.5) — plus, as the elected DR of a broadcast
//!   segment, the Network-LSA (§4.4.3.3) and the network-referenced
//!   Intra-Area-Prefix-LSA carrying the segment's prefixes.
//! - **Broadcast segments** — `network_type = "broadcast"` runs the
//!   RFC 5340 §4.1.2 interface FSM over the RFC 2328 §9.4 election
//!   (Router-ID identity, [`lr_ospf::interface::elect_v3`]): Waiting
//!   → DR/BDR/DR-Other, Hello DR/BDR fields (§A.3.2), the §10.4
//!   adjacency gate pushed through `set_ospf_dr_state`, the §12.4.2
//!   (v3 §4.4.3.3) Network-LSA lifecycle and the §4.4.3.5
//!   network-referenced prefix split (the DR advertises the segment's
//!   prefixes; transit-reported interfaces stay out of the router's
//!   own Intra-Area-Prefix-LSA).
//! - **Checksum egress** — every packet's IPv6 upper-layer checksum is
//!   finalized with the pseudo-header (source link-local, destination
//!   ff02::5) right before the sendto (RFC 5340 §A.3.1); receive-side
//!   verification is skipped like FRR's ospf6d.
//! - **Next-hop bookkeeping for the kernel** — the link-local →
//!   interface mapping learned from Hello sources feeds
//!   [`crate::v6_nexthop_oifs`], so the kernel mirror can attach the
//!   RTA_OIF a link-local gateway needs.
//! - **Graceful restart (RFC 5187)** — the v3 counterpart of the v2
//!   daemon's RFC 3623 machinery: helper mode (§3 via
//!   [`lr_ospf::gr::HelperEntry`], one per neighbour session — the
//!   restarting router's Hellos stop, so the dead timer keeps the
//!   neighbour while helper mode is active), the graceful-shutdown
//!   Grace-LSA flood (§2.1 — LS type 0x000b, Link State ID = the
//!   Interface ID, state-file-persisted deadline and sequence floor)
//!   and the restarting router's recovery (§2.2/§2.3: origination
//!   suppressed, pre-restart adjacencies re-established from the
//!   retained Router-LSA's p2p links, Grace-LSA flush on exit). The
//!   Interface IDs the retained LSAs are keyed by are the kernel
//!   ifindexes — stable across the process restart (RFC 5187 §3.2's
//!   preservation requirement holds structurally while the interface
//!   stays up).
//!
//! Scope of slice 1 was point-to-point segments only; broadcast
//! segments (DR election, Network-LSAs, network-referenced
//! Intra-Area-Prefix-LSAs) are the current slice. Slice 3 adds the
//! RFC 9513 SRv6 surface: with `[[ospf.srv6_locator]]` configuration
//! the daemon originates the area-scoped Router Information LSA (the
//! SRv6 Capabilities, SR-Algorithm and Node MSD TLVs, RFC 9513
//! §2-§4) and the SRv6 Locator LSA (§7, with the §8 End SID and the
//! optional §10 SID Structure) alongside the topology LSAs, and
//! `[ospf] srv6_receive` opens the §5 locator-reception gate on the
//! router pipeline.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use lr_core::addr::{IpAddr, RouterId};
use lr_ospf::codec::OspfCodec;
use lr_ospf::gr::{HelperCheck, HelperEntry, RestartTracker};
use lr_ospf::interface::{elect_v3, IfState, V3Elector};
use lr_ospf::lsa::grace::{originate_grace_lsa_v3, GraceLsaBody, GraceReason};
use lr_ospf::lsa::srv6::{locator_route_type, msd_type, NodeMsd};
use lr_ospf::lsa::v3::{
    originate_v3_intra_area_prefix_lsa, originate_v3_link_lsa, originate_v3_network_lsa,
    originate_v3_router_lsa, V3LinkLsaBody, V3Prefix, V3RouterLsaBody, LINK_TYPE_POINTTOPOINT,
    LINK_TYPE_TRANSIT, LS_TYPE_INTRA_PREFIX, LS_TYPE_LINK, LS_TYPE_NETWORK, LS_TYPE_ROUTER,
    ROUTER_BIT_B, ROUTER_BIT_E, ROUTER_BIT_V6,
};
use lr_ospf::lsa::{
    originate_v3_e_intra_area_prefix_lsa, originate_v3_e_link_lsa, originate_v3_e_network_lsa,
    originate_v3_e_router_lsa, EPrefixTlv, ERouterLinkTlv, LS_TYPE_E_INTRA_PREFIX, LS_TYPE_E_LINK,
    LS_TYPE_E_NETWORK, LS_TYPE_E_ROUTER,
};
use lr_ospf::lsa::{
    originate_v3_srv6_locator_lsa, originate_v3_srv6_ri_lsa, Srv6EndSidSubTlv, Srv6LocatorTlv,
    Srv6SidStructure, PREFIX_OPT_AC, PREFIX_OPT_LA, PREFIX_OPT_NU, SRV6_CAP_O_FLAG,
};
use lr_ospf::lsa::{LS_TYPE_SRV6_LOCATOR, LS_TYPE_V3_ROUTER_INFORMATION};
use lr_ospf::origination::finalize_v3_packet;
use lr_ospf::packet::{HelloBody, OspfBody, OspfPacketType, OSPF_V3_OPTIONS_DEFAULT};
use lr_osroute::ospf_transport::{interface_v6_addrs, OspfV6Transport};
use lr_router::{
    DefaultRouter, OspfGraceEvent, OspfNetworkType, RouterInstance, SessionConfig, SessionHandle,
};

use crate::daemon_config::{area_label, DaemonConfig, OspfIfSpec, OspfSrv6LocatorSpec};
use crate::daemon_multi::{EngineHost, EngineReport};
use crate::daemon_ospf::{
    grace_sequence_base, GRACE_FLOOD_INTERVAL_MS, GRACE_FLOOD_REPEATS, GRACE_PUMP_SLICE_MS,
};

/// Loop cadence: also the dead-timer / hello-timer granularity.
const LOOP_INTERVAL_MS: u64 = 50;

/// Delay before an adjacency-driven Router-LSA re-origination:
/// receivers throttle new LSA instances by MinLSArrival (RFC 2328
/// §14, 1 s) — mirrored from the v2 daemon.
const REORIGINATE_DELAY_MS: u64 = 1_500;

/// RFC 2328 §14.1 (extended to v3 by §4.4.3): self-originated LSAs are
/// refreshed before they reach half MaxAge — the v2 default cadence.
const LS_REFRESH_MS: u64 = 1_800_000;

/// Previous-sequence floor for one self-originated LSA: the in-memory
/// lineage OR the instance currently in the area LSDB, whichever is
/// newer. After a graceful-restart recovery (RFC 5187 §2.3 (1)/(2),
/// inheriting RFC 3623) the pre-restart instances the helpers
/// re-delivered through the database exchange ARE the floor — a fresh
/// 0x80000001 would be older than every neighbour's copy and silently
/// ignored (RFC 2328 §12.1.2 signed comparison), so the LSA would never
/// refresh and age out an hour later. A free function (not a method)
/// because the call sites sit inside `&mut self.interfaces` walks.
fn lsa_seq_floor(
    router: &DefaultRouter,
    area: u32,
    ls_type: u16,
    ls_id: u32,
    adv: u32,
    memory: Option<u32>,
) -> Option<u32> {
    let lsdb = router
        .ospf_area_lsa(area, ls_type, ls_id, adv)
        .map(|l| l.header.ls_sequence_number);
    match (memory, lsdb) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// RFC 9513 §9.2: resolve the LAN End.X derivation base — the
/// configured prefix masked to its length (host bits cleared, so the
/// derived `base | R` SIDs are pure functions of the base and the
/// neighbor's Router-ID), with the covering locator's algorithm (0
/// when the locator leaves it default). The finalize pass already
/// fail-closed on containment and the ≤ /96 length.
fn mask_lan_base(text: &str, locators: &[OspfSrv6LocatorSpec]) -> Option<([u8; 16], u8)> {
    let p: lr_core::addr::Prefix = text.parse().ok()?;
    let lr_core::addr::IpAddr::V6(octets) = p.addr else {
        return None;
    };
    let len = (p.prefix_len as usize).min(128);
    let mut base = octets;
    for (i, b) in base.iter_mut().enumerate() {
        let bit_start = i * 8;
        if bit_start >= len {
            *b = 0;
        } else if bit_start + 8 > len {
            *b &= !0u8 << (8 - (len - bit_start));
        }
    }
    let algorithm = covering_locator_algorithm(locators, &base).unwrap_or(0);
    Some((base, algorithm))
}

/// The algorithm of the first `[[ospf.srv6_locator]]` whose prefix
/// covers `sid` (RFC 9513 §9's containment requirement), or `None`
/// when no locator covers it. The finalize pass fail-closes on
/// uncovered SIDs; this is the resolve-time lookup shared by the §9.1
/// SID and the §9.2 LAN base.
fn covering_locator_algorithm(locators: &[OspfSrv6LocatorSpec], sid: &[u8; 16]) -> Option<u8> {
    locators.iter().find_map(|loc| {
        let p: lr_core::addr::Prefix = loc.prefix.as_deref()?.parse().ok()?;
        let lr_core::addr::IpAddr::V6(pb) = p.addr else {
            return None;
        };
        let len = (p.prefix_len as usize).min(128);
        let full = len / 8;
        let rem = len % 8;
        let covered = sid[..full] == pb[..full]
            && (rem == 0 || {
                let mask = !0u8 << (8 - rem);
                sid[full] & mask == pb[full] & mask
            });
        covered.then_some(loc.algorithm.unwrap_or(0))
    })
}

/// The Router-Link TLV form of a legacy link descriptor (RFC 8362
/// §3.2) — the E-Router-LSA origination switch. p2p links on an
/// interface with a configured End.X SID (`[[ospf.interface]]
/// srv6_end_x`, RFC 9513 §9.1) carry it in the sub-TLV region.
/// Broadcast transit links carry the RFC 9513 §9 set: the plain
/// §9.1 End.X for the DR adjacency (when we are not the DR) plus one
/// §9.2 LAN End.X per Full BDR/DR-Other neighbor.
///
/// The RFC 9513 §9 origination inputs for one broadcast interface.
struct LanEndXSpec {
    /// §9.1: the DR adjacency rides the plain End.X sub-TLV — `None`
    /// when we are the DR (no adjacency to ourselves), when the DR
    /// adjacency is not Full, or when `srv6_end_x` is not configured.
    dr_sid: Option<([u8; 16], u8)>,
    /// §9.2: the masked `srv6_end_x_lan` base + the covering
    /// locator's algorithm; each Full neighbor `R` in `neighbors`
    /// gets the SID `base | R`.
    base: Option<([u8; 16], u8)>,
    /// The Full neighbors the LAN End.X sub-TLVs cover: everyone but
    /// the DR (the BDR + the DR-Others; RFC 2328 §A.4 keeps
    /// DR-Others at 2-Way with each other, so this is exactly our
    /// Full set minus the DR). Router-ID order (the neighbors
    /// BTreeMap's iteration order).
    neighbors: Vec<u32>,
}

fn e_router_links(
    links: &[lr_ospf::lsa::v3::V3RouterLink],
    end_x_by_if: &BTreeMap<u32, ([u8; 16], u8)>,
    lan_end_x_by_if: &BTreeMap<u32, LanEndXSpec>,
) -> Vec<ERouterLinkTlv> {
    links
        .iter()
        .map(|l| {
            let mut sub_tlvs = Vec::new();
            match l.link_type {
                LINK_TYPE_POINTTOPOINT => {
                    if let Some((sid, algorithm)) = end_x_by_if.get(&l.interface_id) {
                        lr_ospf::lsa::Srv6EndXSidSubTlv {
                            flags: 0,
                            behavior: 5, // End.X (RFC 8986)
                            algorithm: *algorithm,
                            weight: 0,
                            sid: *sid,
                            structure: None,
                        }
                        .encode(&mut sub_tlvs);
                    }
                }
                LINK_TYPE_TRANSIT => {
                    // RFC 9513 §9, broadcast segments: the plain §9.1
                    // End.X covers the DR adjacency (a non-DR router's
                    // view of the network vertex), and one §9.2 LAN
                    // End.X per Full BDR/DR-Other neighbor — the
                    // neighbor Router-ID field distinguishing the
                    // per-neighbor SIDs riding the same link.
                    if let Some(spec) = lan_end_x_by_if.get(&l.interface_id) {
                        if let Some((sid, algorithm)) = spec.dr_sid {
                            lr_ospf::lsa::Srv6EndXSidSubTlv {
                                flags: 0,
                                behavior: 5, // End.X (RFC 8986)
                                algorithm,
                                weight: 0,
                                sid,
                                structure: None,
                            }
                            .encode(&mut sub_tlvs);
                        }
                        if let Some((base, algorithm)) = spec.base {
                            for rid in &spec.neighbors {
                                // `base | R`: the Router-ID fills the
                                // low 32 bits (the base is masked, so
                                // the OR never collides with prefix
                                // bits).
                                let mut sid = base;
                                for (i, b) in rid.to_be_bytes().iter().enumerate() {
                                    sid[12 + i] |= b;
                                }
                                lr_ospf::lsa::Srv6LanEndXSidSubTlv {
                                    flags: 0,
                                    behavior: 5, // End.X (RFC 8986)
                                    algorithm,
                                    weight: 0,
                                    neighbor_router_id: *rid,
                                    sid,
                                    structure: None,
                                }
                                .encode(&mut sub_tlvs);
                            }
                        }
                    }
                }
                _ => {}
            }
            ERouterLinkTlv {
                link_type: l.link_type,
                metric: l.metric,
                interface_id: l.interface_id,
                neighbor_interface_id: l.neighbor_interface_id,
                neighbor_router_id: l.neighbor_router_id,
                sub_tlvs,
            }
        })
        .collect()
}

/// The Intra-Area-Prefix TLV form of legacy prefixes (RFC 8362 §3.7).
fn e_prefix_tlvs(prefixes: Vec<V3Prefix>) -> Vec<EPrefixTlv> {
    prefixes
        .into_iter()
        .map(|p| EPrefixTlv {
            metric: 0,
            prefix: p,
            sub_tlvs: Vec::new(),
        })
        .collect()
}

/// The v3-extended Debug wire trace (`LR_OSPF_DEBUG`): walk a packet
/// stream and print kind/length/router-id per frame.
fn dbg_send_trace(bytes: &[u8]) {
    if std::env::var_os("LR_OSPF_DEBUG").is_none() {
        return;
    }
    let mut off = 0usize;
    while off + lr_ospf::packet::OspfHeader::LEN_V3 <= bytes.len() {
        let len = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]) as usize;
        if len < lr_ospf::packet::OspfHeader::LEN_V3 || off + len > bytes.len() {
            break;
        }
        eprintln!(
            "dbg-send kind={} len={} rid={:08x}",
            bytes[off + 1],
            len,
            u32::from_be_bytes([
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7]
            ])
        );
        off += len;
    }
}

/// One configured v3 interface, resolved against the running kernel.
struct Ospf3Interface {
    name: String,
    area: u32,
    cost: u16,
    /// Interface MTU advertised in DBDs.
    mtu: u16,
    hello_interval: u16,
    dead_interval: u32,
    /// The kernel ifindex — our OSPFv3 Interface ID on this link
    /// (FRR convention, and the value the kernel mirror needs).
    interface_id: u32,
    /// Our link-local source address on the link (the value peers use
    /// as their next hop toward us).
    link_local: Ipv6Addr,
    /// Global IPv6 prefixes configured on the interface — the stub
    /// prefixes the Link-LSA and Intra-Area-Prefix-LSA advertise.
    prefixes: Vec<(Ipv6Addr, u8)>,
    transport: OspfV6Transport,
    /// Last Hello we sent (ms since daemon start).
    last_hello_ms: u64,
    /// Router-ids heard on this interface (from their Hellos).
    heard: BTreeMap<u32, HeardNeighbor>,
    /// RFC 2328 §9.1 network type: p2p (default) or broadcast. Only
    /// broadcast segments run the §9.4 DR/BDR election (RFC 5340
    /// §4.1.2 keeps the v2 election on Router-ID identity).
    network_type: OspfNetworkType,
    /// RFC 9513 §9.1: the local End.X SID
    /// (`[[ospf.interface]] srv6_end_x`) with the algorithm of the
    /// locator it is allocated from — rides the E-Router-LSA's p2p
    /// Router-Link TLV sub-TLV region once the adjacency is Full; on
    /// broadcast segments it covers the adjacency to the DR.
    end_x_sid: Option<([u8; 16], u8)>,
    /// RFC 9513 §9.2: the LAN End.X derivation base
    /// (`[[ospf.interface]] srv6_end_x_lan`, masked to its prefix
    /// length) with the covering locator's algorithm — one LAN End.X
    /// sub-TLV per Full BDR/DR-Other neighbor `R` on the broadcast
    /// segment, the SID derived as `base | R` (the Router-ID fills
    /// the low 32 bits, the RFC 8402 argument position).
    end_x_lan: Option<([u8; 16], u8)>,
    /// Router Priority advertised in Hellos (§A.3.2; 0 = never DR/BDR).
    priority: u8,
    /// Interface FSM state (§9.1): Waiting until the WaitTimer or
    /// BackupSeen, then DR/Backup/DR-Other from the election. p2p
    /// interfaces stay PointToPoint.
    if_state: IfState,
    /// Elected DR — its Router ID (the v3 §10.4 identity; 0 = none).
    dr: u32,
    /// Elected Backup Designated Router (Router ID; 0 = none).
    bdr: u32,
    /// When the §9.3 WaitTimer fires (ms since daemon start).
    wait_deadline_ms: u64,
    /// Set when a received Hello changes the election input (a
    /// neighbor became bidirectional, or its DR/BDR declarations or
    /// priority changed — §9.3 NeighborChange); the next pump
    /// re-runs the election.
    election_dirty: bool,
    /// Sequence number of our current Network-LSA for this segment
    /// (§4.4.3.3) and whether one is live in the area LSDB.
    net_lsa_seq: Option<u32>,
    net_lsa_active: bool,
    /// Sequence number of our current network-referenced
    /// Intra-Area-Prefix-LSA (§4.4.3.5) and whether one is live.
    net_iap_seq: Option<u32>,
    net_iap_active: bool,
}

/// One neighbor heard on an interface. The v3-specific datum is the
/// neighbor's Interface ID on the shared link, from its Hello's
/// Interface ID field — the Neighbor Interface ID of our p2p link
/// description (§A.4.3) and the key to its Link-LSA. On broadcast
/// segments the Hello's DR/BDR fields (Router IDs, §A.3.2) and the
/// Router Priority feed the §9.4 election.
#[derive(Debug, Clone, Copy)]
struct HeardNeighbor {
    /// The neighbor's Interface ID on this link.
    interface_id: u32,
    priority: u8,
    /// The neighbor's link-local address (the Hello's source).
    link_local: Ipv6Addr,
    last_ms: u64,
    /// The neighbor lists our router-id (state ≥ 2-Way, §10.1).
    bidirectional: bool,
    /// The DR the neighbor claims in its Hellos (Router ID; 0 = none).
    stated_dr: u32,
    /// The BDR the neighbor claims in its Hellos (Router ID).
    stated_bdr: u32,
}

/// One dynamic neighbor session, keyed `(area, router-id)`.
struct Neighbor {
    handle: SessionHandle,
    ifindex: u32,
    established: bool,
    /// RFC 3623 §3 / RFC 5187 (the helper half): retains the
    /// adjacency (dead-timer suspension in `pump_dead_timer`) while
    /// the restarting neighbour's Hellos are silent.
    helper: HelperEntry,
}

struct Ospf3Daemon {
    router: Arc<RwLock<DefaultRouter>>,
    interfaces: Vec<Ospf3Interface>,
    neighbors: BTreeMap<(u32, u32), Neighbor>,
    /// Router-LSA re-origination due times (area → ms), MinLSArrival
    /// spaced like the v2 daemon.
    pending_reorig: BTreeMap<u32, u64>,
    /// Area → anchor session (registers the area; self-origination
    /// rides it, output discarded).
    anchors: BTreeMap<u32, SessionHandle>,
    /// Per-LSA sequence floors: area → Router-LSA, (area, ifindex) →
    /// Link-LSA, (area, ls_id) → Intra-Area-Prefix-LSA, area →
    /// SRv6 Router-Information-LSA, area → SRv6 Locator-LSA.
    router_lsa_seq: BTreeMap<u32, u32>,
    /// Area → E-Router-LSA (the RFC 8362 carrier — shared by the
    /// extended mode and the RFC 9513 §9 sparse-mode companion).
    e_router_lsa_seq: BTreeMap<u32, u32>,
    link_lsa_seq: BTreeMap<(u32, u32), u32>,
    iap_lsa_seq: BTreeMap<(u32, u32), u32>,
    ri_lsa_seq: BTreeMap<u32, u32>,
    srv6_lsa_seq: BTreeMap<u32, u32>,
    /// Last self-origination per area (ms) — the §14.1 refresh cadence.
    last_orig_ms: BTreeMap<u32, u64>,
    /// RFC 9513 origination state (`None` = SRv6 off — the daemon stays
    /// byte-identical to a pre-SRv6 one).
    srv6: Option<Srv6Origination>,
    /// RFC 8362 Extended-LSA mode (`[ospf] extended_lsas`): originate
    /// the E-Router/E-Network/E-Link/E-Intra-Area-Prefix LSAs instead
    /// of the legacy shapes (`ExtendedLSASupport`, Appendix A). Off by
    /// default — byte-identical to a pre-E-LSA daemon.
    extended_lsas: bool,
    router_id: RouterId,
    /// Snapshot for the runtime API `status` command.
    status: Arc<Mutex<Vec<String>>>,
    // ---- Graceful restart (RFC 5187) ----
    /// §3 helper policy (default on, `--ospf-no-gr-helper` refuses).
    gr_helper_enabled: bool,
    /// FRR `supported_grace_time`: the grace ceiling this router
    /// honours as a helper (`--ospf-helper-grace-cap`, seconds).
    gr_helper_cap: u32,
    /// The configured grace period (seconds) — advertised in the
    /// shutdown Grace-LSAs and persisted to the state file
    /// (`--ospf-grace-period`).
    gr_grace_period: u32,
    /// Monotonic floor for this router's Grace-LSA sequence lineage
    /// (each originated instance advances it; seeded from the state
    /// file across restarts so the post-recovery flush is always
    /// newer than the instances the helpers hold).
    gr_seq_floor: u32,
    /// Where the graceful-restart state (deadline + grace period +
    /// sequence floor) survives the restart — `--ospf-gr-state-file`,
    /// defaulting to `<api-socket>.gr`.
    gr_state_file: Option<String>,
    /// §2 recovery, per area: each tracker holds that area's
    /// pre-restart adjacency set and latches its outcome. Non-empty
    /// while recovery is live.
    gr_recovery: BTreeMap<u32, RestartTracker>,
    /// Area → last-seen LSDB topology version (the §3.2 (3) exit).
    gr_topology: BTreeMap<u32, u64>,
}

/// The resolved RFC 9513 origination state: what `reoriginate_area`
/// advertises in every configured area. Built once from the validated
/// config (§7.1 locators resolved to wire TLVs with their §8 End SIDs).
struct Srv6Origination {
    /// SRv6 Capabilities TLV flags (RFC 9513 §2; the O-flag).
    capabilities: u16,
    /// SR-Algorithm TLV values (RFC 8665 §3.1): the distinct locator
    /// algorithms, ascending.
    algorithms: Vec<u8>,
    /// Node MSD TLV pairs (RFC 8476 §2), MSD-type order 41/42/44/45.
    msds: Vec<NodeMsd>,
    /// The §7.1 Locator TLVs, one per configured locator.
    locators: Vec<Srv6LocatorTlv>,
}

impl Srv6Origination {
    /// Resolve the validated `[[ospf.srv6_locator]]` configuration into
    /// the origination state. Parse failures cannot happen (finalize
    /// rejected them) but are handled fail-soft: the offending locator
    /// is dropped with a log line, never a panic.
    fn from_config(cfg: &DaemonConfig) -> Self {
        let capabilities = if cfg.ospf_srv6_o_flag {
            SRV6_CAP_O_FLAG
        } else {
            0
        };
        let mut algorithms = std::collections::BTreeSet::new();
        let mut locators = Vec::new();
        for spec in &cfg.ospf_srv6_locators {
            let Some(text) = spec.prefix.as_deref() else {
                continue; // finalize() already rejected this
            };
            let Ok(prefix) = text.parse::<lr_core::addr::Prefix>() else {
                continue;
            };
            let lr_core::addr::IpAddr::V6(octets) = prefix.addr else {
                continue;
            };
            // §7.1: the locator prefix is advertised with the host
            // bits zeroed (the crate's Prefix keeps them that way).
            let algorithm = spec.algorithm.unwrap_or(0);
            algorithms.insert(algorithm);
            // §8: the End SID value defaults to the locator prefix
            // itself (the RFC 8986 End behavior on the locator).
            let sid = match spec.sid.as_deref() {
                Some(text) => match text.parse::<lr_core::addr::IpAddr>() {
                    Ok(IpAddr::V6(octets)) => octets,
                    _ => {
                        eprintln!("daemon: ospf3 srv6 locator {text}: bad sid, locator skipped");
                        continue;
                    }
                },
                None => octets,
            };
            let structure = match (
                spec.block_len,
                spec.node_len,
                spec.function_len,
                spec.argument_len,
            ) {
                (Some(lb), Some(ln), Some(f), Some(a)) => Some(Srv6SidStructure {
                    lb_len: lb,
                    ln_len: ln,
                    func_len: f,
                    arg_len: a,
                }),
                _ => None,
            };
            locators.push(Srv6LocatorTlv {
                route_type: locator_route_type::INTRA_AREA,
                algorithm,
                locator_len: prefix.prefix_len,
                options: if spec.anycast.unwrap_or(false) {
                    PREFIX_OPT_AC
                } else {
                    0
                },
                metric: spec.metric.unwrap_or(0),
                prefix: octets,
                end_sids: vec![Srv6EndSidSubTlv {
                    flags: 0,
                    behavior: spec.behavior.unwrap_or(1), // 1 = End
                    sid,
                    structure,
                }],
                fwd_addr: None,
                route_tag: None,
            });
        }
        let mut msds = Vec::new();
        for (msd, value) in [
            (msd_type::SRH_MAX_SL, cfg.ospf_srv6_max_sl),
            (msd_type::SRH_MAX_END_POP, cfg.ospf_srv6_max_end_pop),
            (msd_type::SRH_MAX_H_ENCAPS, cfg.ospf_srv6_max_h_encaps),
            (msd_type::SRH_MAX_END_D, cfg.ospf_srv6_max_end_d),
        ] {
            if let Some(v) = value {
                msds.push((msd, v));
            }
        }
        Self {
            capabilities,
            algorithms: algorithms.into_iter().collect(),
            msds,
            locators,
        }
    }

    /// The origination gate: SRv6 state exists only when locators are
    /// configured — reception alone never turns a daemon into an
    /// SRv6 originator (fail-closed default).
    fn maybe_from_config(cfg: &DaemonConfig) -> Option<Self> {
        (!cfg.ospf_srv6_locators.is_empty()).then(|| Self::from_config(cfg))
    }
}

/// `lr-daemon --protocol ospf` with `[ospf] version = "v3"`.
pub fn run_ospf3_daemon(cfg: &DaemonConfig, rid: RouterId, host: Option<EngineHost>) -> ExitCode {
    if cfg.ospf_interfaces.is_empty() {
        eprintln!(
            "daemon: --protocol ospf needs at least one interface \
             (--ospf-interface NAME or [[ospf.interface]] tables)"
        );
        return ExitCode::from(2);
    }
    let mut interfaces: Vec<Ospf3Interface> = Vec::new();
    for spec in &cfg.ospf_interfaces {
        match resolve_interface(cfg, spec) {
            Ok(iface) => {
                println!(
                    "daemon: ospf3 interface {} area {} — ifindex {} (interface id), \
                     link-local {}, {} global prefix(es), cost {}, hello {}s dead {}s, {}",
                    iface.name,
                    area_label(iface.area),
                    iface.interface_id,
                    iface.link_local,
                    iface.prefixes.len(),
                    iface.cost,
                    iface.hello_interval,
                    iface.dead_interval,
                    match iface.network_type {
                        OspfNetworkType::PointToPoint => "point-to-point",
                        OspfNetworkType::Broadcast => "broadcast",
                    },
                );
                interfaces.push(iface);
            }
            Err(e) => {
                eprintln!("daemon: ospf interface {}: {}", spec.label(), e);
                return ExitCode::from(1);
            }
        }
    }
    // Standalone: apply the cross-protocol config ([[static]],
    // [[aggregate]], [[redistribute]]) like the multi-protocol
    // supervisor — a `--protocol ospf` daemon must not silently ignore
    // its [[static]] table.
    let router: Arc<RwLock<DefaultRouter>> = match &host {
        Some(h) => Arc::clone(&h.runtime.router),
        None => {
            let router = Arc::new(RwLock::new(DefaultRouter::new()));
            if let Err(e) = crate::apply_cross_protocol_config(cfg, &mut router.write().unwrap()) {
                eprintln!("error: {}", e);
                return ExitCode::from(2);
            }
            router
        }
    };
    let mut daemon = Ospf3Daemon {
        router,
        interfaces,
        neighbors: BTreeMap::new(),
        pending_reorig: BTreeMap::new(),
        anchors: BTreeMap::new(),
        router_lsa_seq: BTreeMap::new(),
        e_router_lsa_seq: BTreeMap::new(),
        link_lsa_seq: BTreeMap::new(),
        iap_lsa_seq: BTreeMap::new(),
        ri_lsa_seq: BTreeMap::new(),
        srv6_lsa_seq: BTreeMap::new(),
        last_orig_ms: BTreeMap::new(),
        srv6: Srv6Origination::maybe_from_config(cfg),
        extended_lsas: cfg.ospf_extended_lsas,
        router_id: rid,
        status: Arc::new(Mutex::new(Vec::new())),
        gr_helper_enabled: cfg.ospf_gr_helper,
        gr_helper_cap: cfg.ospf_helper_grace_cap,
        gr_grace_period: cfg.ospf_grace_period,
        gr_seq_floor: 0,
        gr_state_file: cfg
            .ospf_gr_state_file
            .clone()
            .or_else(|| cfg.api_socket.as_ref().map(|s| format!("{s}.gr"))),
        gr_recovery: BTreeMap::new(),
        gr_topology: BTreeMap::new(),
    };
    if let Some(s) = &daemon.srv6 {
        println!(
            "daemon: ospf3 SRv6 origination on — {} locator(s), algorithms {:?}, \
             o-flag {}, {} MSD limit(s)",
            s.locators.len(),
            s.algorithms,
            if cfg.ospf_srv6_o_flag { "on" } else { "off" },
            s.msds.len(),
        );
    }
    // ---- Router: one anchor session per area (v3). ----
    // RFC 5187 §2 (inherited from RFC 3623 §2): recovery is *resumed*,
    // not assumed — the state file written by the pre-restart process
    // carries the grace deadline. A fresh start (no file, or a deadline
    // already past) runs normal OSPF; a resume keeps topology-LSA
    // origination suppressed until §2.2 exits (every pre-restart
    // adjacency Full, an inconsistent LSA, or the grace timeout).
    if cfg.ospf_graceful_restart {
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        match daemon.gr_state_file.as_deref().map(std::fs::read_to_string) {
            Some(Ok(text)) => {
                let mut parts = text.split_whitespace();
                let (deadline, period, floor) = (
                    parts.next().and_then(|d| d.parse::<u64>().ok()),
                    parts.next().and_then(|p| p.parse::<u32>().ok()),
                    parts.next().and_then(|s| s.parse::<u32>().ok()),
                );
                match (deadline, period) {
                    (Some(deadline), Some(period)) if deadline > now_unix_ms => {
                        println!(
                            "daemon: ospf3 graceful restart recovery started \
                             (grace period {period}s, resuming a restart)"
                        );
                        // The pre-restart process's Grace-LSA sequence
                        // floor: every instance we send from here on is
                        // strictly newer than the ones the helpers hold.
                        if let Some(floor) = floor {
                            daemon.gr_seq_floor = daemon.gr_seq_floor.max(floor);
                        }
                        // The trackers run on the main-loop clock; the
                        // remaining wallclock seconds translate 1:1.
                        let remaining_secs = u32::try_from((deadline - now_unix_ms) / 1_000)
                            .unwrap_or(1)
                            .max(1);
                        for area in daemon.interfaces.iter().map(|i| i.area) {
                            daemon
                                .gr_recovery
                                .entry(area)
                                .or_insert_with(|| RestartTracker::new(remaining_secs, 0));
                        }
                    }
                    _ => {
                        // Expired or malformed: remove so a later
                        // graceful shutdown rewrites it cleanly.
                        let _ = daemon.gr_state_file.as_deref().map(std::fs::remove_file);
                        println!("daemon: ospf3 graceful restart state expired — fresh start");
                    }
                }
            }
            _ => {
                println!(
                    "daemon: ospf3 graceful restart enabled (no prior grace state — fresh start)"
                );
            }
        }
    }
    let iface_mtu = daemon.interfaces.first().map(|i| i.mtu).unwrap_or(1500);
    {
        let router_arc = Arc::clone(&daemon.router);
        let mut router = router_arc.write().unwrap();
        if cfg.ospf_srv6_receive {
            // RFC 9513 §5 reception: project learned Locator LSAs into
            // the per-node SRv6 database and install the §5 locator
            // routes (fail-closed off by default, like `sr_receive`).
            router.set_ospf_srv6_receive(true);
        }
        if cfg.ospf_extended_lsas {
            // RFC 8362 Extended-LSA mode (Appendix A
            // `ExtendedLSASupport`): the v3 calculations prefer a
            // speaker's Extended LSAs; the origination switch lives in
            // this module's self-origination walk.
            router.set_ospf_v3_extended_lsas(true);
        }
        for area in daemon.interfaces.iter().map(|i| i.area) {
            if daemon.anchors.contains_key(&area) {
                continue;
            }
            match router.add_session(SessionConfig::ospfv3(rid, area).with_ospf_mtu(iface_mtu)) {
                Ok(h) => {
                    daemon.anchors.insert(area, h);
                }
                Err(e) => {
                    eprintln!("daemon: ospf add_session area {}: {}", area_label(area), e);
                    return ExitCode::from(1);
                }
            }
        }
    }
    // ---- Signals + runtime API + ticker. ----
    // Signal installs are idempotent; the multi-protocol supervisor
    // already did them (and owns dispatch — see signal::set_supervised).
    if let Err(sig) = crate::signal::init() {
        eprintln!("daemon: cannot install signal handlers (signal {})", sig);
        return ExitCode::from(1);
    }
    // The OSPFv3 status view (helper snapshot + session summaries)
    // serves through whichever runtime API socket exists: the engine's
    // own when standalone, the supervisor's shared one when embedded.
    let status_lines = {
        let status = Arc::clone(&daemon.status);
        let router = Arc::clone(&daemon.router);
        Arc::new(move || {
            let mut lines = status.lock().map(|s| s.clone()).unwrap_or_default();
            if let Ok(router) = router.read() {
                for s in router.session_summaries() {
                    lines.push(format!(
                        "ospf3 session #{} kind={} state={}",
                        s.handle.0, s.kind, s.state
                    ));
                }
                // RFC 9513 §9: the projected adjacency End.X SIDs, one
                // line per (node, SID) — grep-friendly for the interop
                // labs (`status | grep srv6-endx`).
                for (area, db) in router.ospf_srv6_databases() {
                    for (rid, node) in &db.nodes {
                        for x in &node.end_x_sids {
                            lines.push(format!(
                                "srv6-endx {} area={} router={:08x} behavior={} alg={} neighbor={:08x}{}",
                                Ipv6Addr::from(x.sid),
                                area_label(area),
                                rid,
                                x.behavior,
                                x.algorithm,
                                x.lan_neighbor_router_id
                                    .unwrap_or(x.neighbor_router_id),
                                if x.lan_neighbor_router_id.is_some() { " lan" } else { "" },
                            ));
                        }
                    }
                }
            }
            lines
        }) as Arc<dyn Fn() -> Vec<String> + Send + Sync>
    };
    // Standalone: own running flag, own runtime, own API socket and
    // ticker. Embedded: the supervisor's shared runtime, with the v3
    // status view registered into its MultiStatus registry and a
    // startup gate between the raw-socket binds above and the LSA
    // origination + main loop below.
    let runtime = match &host {
        Some(h) => {
            h.status.register(Arc::clone(&status_lines));
            Arc::clone(&h.runtime)
        }
        None => Arc::new(crate::Runtime {
            reload: Arc::new(|| {
                vec![
                    "ospf3: configuration reload is not supported yet; shutdown still works"
                        .to_string(),
                ]
            }),
            router: Arc::clone(&daemon.router),
            running: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            status_lines: Arc::clone(&status_lines),
            roa_len: None,
            filter_metrics: Mutex::new(None),
            session_labels: Arc::new(Mutex::new(HashMap::new())),
        }),
    };
    let running = Arc::clone(&runtime.running);
    match &host {
        None => {
            if let Err(e) = crate::spawn_api(cfg, &runtime) {
                eprintln!("daemon: {}", e);
                return ExitCode::from(1);
            }
            if let Err(e) = crate::spawn_metrics(cfg, &runtime) {
                eprintln!("daemon: {}", e);
                return ExitCode::from(1);
            }
            crate::spawn_ticker(
                &runtime,
                cfg.install_kernel,
                Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            );
        }
        Some(h) => {
            // Embedded: every interface's raw socket is bound; report
            // readiness and wait for the supervisor's release (privilege
            // drop + API socket happen in between).
            let _ = h.report.send(EngineReport::Started);
            if h.gate.wait().is_err() {
                println!("daemon: ospf3 engine startup aborted");
                return ExitCode::SUCCESS;
            }
        }
    }

    // ---- Initial self-origination per area. ----
    // RFC 5187 §2 (1) (inherited from RFC 3623): suppressed while
    // graceful-restart recovery is live — the pre-restart instances
    // (re-received from the helping neighbours) keep describing the
    // topology until §2.2 exits.
    if daemon.gr_recovery.is_empty() {
        let router_arc = Arc::clone(&daemon.router);
        let mut router = router_arc.write().unwrap();
        let areas: Vec<u32> = daemon.anchors.keys().copied().collect();
        for area in areas {
            daemon.reoriginate_area(&mut router, area, 0);
        }
    }

    // ---- Main loop. ----
    let start = std::time::Instant::now();
    let mut recv_buf = [0u8; 65535];
    println!(
        "daemon: ospf3 main loop started ({} interface(s))",
        daemon.interfaces.len()
    );
    while running.load(std::sync::atomic::Ordering::Relaxed) {
        crate::dispatch_signals(&runtime);
        if !running.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let now_ms = start.elapsed().as_millis() as u64;
        daemon.pump(&mut recv_buf, now_ms);
        std::thread::sleep(Duration::from_millis(LOOP_INTERVAL_MS));
    }
    // Graceful shutdown. With graceful restart enabled (RFC 5187 §2.1,
    // inheriting RFC 3623 §2.1) the teardown is replaced: originate a
    // Grace-LSA per interface (LS type 0x000b, Link State ID = the
    // Interface ID, retransmitted a few times — the flood path has no
    // acks) and exit *without* closing sessions, so no Loc-RIB
    // withdrawals fire and the kernel FIB the forwarding plane relies
    // on survives the restart. Between flood rounds the daemon keeps
    // servicing the protocol (see `graceful_shutdown_flood`) so peers
    // whose LSA refresh is still un-ACKed can drain their retransmission
    // lists and engage helper mode on a later round. Without it: close
    // every session so the router emits the down events, then let the
    // ticker drain them.
    if cfg.ospf_graceful_restart {
        daemon.graceful_shutdown_flood(&mut recv_buf, &start);
        let period = lr_ospf::gr::clamp_grace_period(cfg.ospf_grace_period);
        println!(
            "daemon: ospf3 graceful shutdown complete (neighbours asked to retain LSAs for {period}s)"
        );
        return ExitCode::SUCCESS;
    }
    {
        let router_arc = Arc::clone(&daemon.router);
        let mut router = router_arc.write().unwrap();
        for n in daemon.neighbors.values() {
            router.close_session(n.handle);
        }
        for anchor in daemon.anchors.values() {
            router.close_session(*anchor);
        }
        for ev in router.poll_events() {
            crate::daemon_ospf::log_event(&ev);
        }
    }
    println!("daemon: ospf3 shutdown complete");
    ExitCode::SUCCESS
}

/// Resolve one configured interface for v3: the IPv6 raw transport, the
/// link-local source address and the global prefixes. No IPv4 address
/// is needed (RFC 5340 §3.1: OSPFv3 runs per-link, not per-subnet).
fn resolve_interface(cfg: &DaemonConfig, spec: &OspfIfSpec) -> Result<Ospf3Interface, String> {
    let name = spec.label().to_string();
    let v6addrs = interface_v6_addrs(&name).map_err(|e| e.to_string())?;
    let link_local = v6addrs
        .iter()
        .find(|a| a.is_link_local())
        .map(|a| a.addr)
        .ok_or_else(|| format!("no IPv6 link-local address on {name}"))?;
    let prefixes: Vec<(Ipv6Addr, u8)> = v6addrs
        .iter()
        .filter(|a| !a.is_link_local())
        .map(|a| (a.addr, a.prefix_len))
        .collect();
    let transport = OspfV6Transport::bind(&name, false).map_err(|e| {
        if e.is_permission_denied() {
            format!(
                "{e} (raw OSPF sockets need root or a user/network namespace \
                 — e.g. unshare -Urn)"
            )
        } else {
            e.to_string()
        }
    })?;
    transport
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking on {name}: {e}"))?;
    let iface_mtu = transport.mtu().unwrap_or(1500);
    let hello = spec
        .hello_interval
        .unwrap_or(cfg.ospf_hello_interval)
        .max(1);
    let dead = spec
        .dead_interval
        .unwrap_or(cfg.ospf_dead_interval)
        .max(u32::from(hello));
    // RFC 2328 §9.1 network type (the §9.4 election applies only on
    // broadcast segments; RFC 5340 §4.1.2 keeps the v2 algorithm).
    let network_type = match spec.network_type.as_deref() {
        None | Some("p2p") | Some("point-to-point") | Some("") => OspfNetworkType::PointToPoint,
        Some("broadcast") => OspfNetworkType::Broadcast,
        Some(other) => {
            return Err(format!(
                "unknown network_type '{other}' (use \"p2p\" or \"broadcast\")"
            ))
        }
    };
    let priority = spec.priority.unwrap_or(1);
    let interface_id = transport.ifindex();
    // RFC 9513 §9.1: resolve the configured End.X SID with its
    // locator's algorithm (the finalize pass already fail-closed on
    // containment; here we only need the covering locator's
    // algorithm — 0 when the locator leaves it default).
    let end_x_sid = spec.srv6_end_x.as_deref().and_then(|text| {
        let sid: Ipv6Addr = text.parse().ok()?;
        let algorithm =
            covering_locator_algorithm(&cfg.ospf_srv6_locators, &sid.octets()).unwrap_or(0);
        Some((sid.octets(), algorithm))
    });
    // RFC 9513 §9.2: resolve the LAN End.X derivation base — the
    // configured prefix masked to its length (host bits cleared, so
    // the derived `base | R` SIDs are pure functions of the base and
    // the neighbor's Router-ID), with the covering locator's
    // algorithm. The finalize pass already fail-closed on
    // containment and the ≤ /96 length.
    let end_x_lan = spec
        .srv6_end_x_lan
        .as_deref()
        .and_then(|text| mask_lan_base(text, &cfg.ospf_srv6_locators));
    Ok(Ospf3Interface {
        name,
        area: spec.area.unwrap_or(cfg.ospf_area),
        cost: spec.cost.unwrap_or(10),
        mtu: iface_mtu,
        hello_interval: hello,
        dead_interval: dead,
        interface_id,
        link_local,
        prefixes,
        transport,
        last_hello_ms: 0,
        heard: BTreeMap::new(),
        network_type,
        end_x_sid,
        end_x_lan,
        priority,
        // §9.3: broadcast interfaces come up in Waiting and wait
        // RouterDeadInterval before electing (p2p has no election;
        // priority-0 routers skip Waiting per §9.4 — never eligible,
        // BIRD/FRR go straight to DR-Other too).
        if_state: if network_type == OspfNetworkType::Broadcast && priority > 0 {
            IfState::Waiting
        } else {
            IfState::DrOther
        },
        dr: 0,
        bdr: 0,
        // §9.3: the WaitTimer runs RouterDeadInterval from ifup. The
        // main-loop clock starts right after resolve, so the deadline
        // is the dead interval itself.
        wait_deadline_ms: if network_type == OspfNetworkType::Broadcast && priority > 0 {
            u64::from(dead) * 1000
        } else {
            0
        },
        election_dirty: false,
        net_lsa_seq: None,
        net_lsa_active: false,
        net_iap_seq: None,
        net_iap_active: false,
    })
}

impl Ospf3Interface {
    /// §10.5: fold one received Hello into the interface's neighbor
    /// table. The v3 identity inputs are the neighbor's Interface ID
    /// (Hello Interface ID field) and its link-local source address.
    /// On broadcast segments the Hello's DR/BDR claims (Router IDs)
    /// and Router Priority feed the §9.4 election: the interface is
    /// flagged election-dirty when the neighbor became bidirectional
    /// (the elector set grew) or its DR/BDR declarations or priority
    /// changed (§9.3 NeighborChange — BIRD hello.c parity: only
    /// declare-transitions matter, not every claim value change).
    fn track_hello(
        &mut self,
        rid: u32,
        link_local: Ipv6Addr,
        body: &HelloBody,
        our_rid: u32,
        now_ms: u64,
    ) {
        let bidirectional = body.neighbors.contains(&our_rid);
        let became_bidirectional = match self.heard.get(&rid) {
            Some(prev) => {
                if self.network_type == OspfNetworkType::Broadcast
                    && (prev.priority != body.priority
                        || (prev.stated_dr == rid) != (body.dr == rid)
                        || (prev.stated_bdr == rid) != (body.bdr == rid))
                {
                    self.election_dirty = true;
                }
                bidirectional && !prev.bidirectional
            }
            None => bidirectional,
        };
        if became_bidirectional {
            self.election_dirty = true;
        }
        let entry = self.heard.entry(rid).or_insert(HeardNeighbor {
            interface_id: body.network_mask, // v3: Interface ID slot
            priority: body.priority,
            link_local,
            last_ms: now_ms,
            bidirectional,
            stated_dr: body.dr,
            stated_bdr: body.bdr,
        });
        entry.interface_id = body.network_mask;
        entry.priority = body.priority;
        entry.link_local = link_local;
        entry.last_ms = now_ms;
        entry.bidirectional = bidirectional;
        entry.stated_dr = body.dr;
        entry.stated_bdr = body.bdr;
    }
}

impl Ospf3Daemon {
    fn pump(&mut self, recv_buf: &mut [u8], now_ms: u64) {
        self.pump_inbound(recv_buf, now_ms);
        self.pump_election(now_ms);
        self.pump_adjacency(now_ms);
        self.pump_dead_timer(now_ms);
        self.pump_reoriginate(now_ms);
        self.pump_gr(now_ms);
        self.pump_hellos(now_ms);
        self.pump_outbound();
    }

    /// Drive the interface FSM and the DR/BDR election on broadcast
    /// segments (RFC 2328 §9.3/§9.4 over the RFC 5340 §4.1.2
    /// Router-ID identity). p2p interfaces never elect (§9.4 does not
    /// apply) and are skipped.
    fn pump_election(&mut self, now_ms: u64) {
        let mut changed_areas: Vec<u32> = Vec::new();
        let self_rid = self.router_id.as_u32();
        for iface in &mut self.interfaces {
            if iface.network_type != OspfNetworkType::Broadcast {
                continue;
            }
            let fire = match iface.if_state {
                IfState::Waiting => {
                    // §9.3 BackupSeen: a bidirectional neighbor declared
                    // itself BDR, or declared itself DR with no BDR —
                    // track_hello flags both by dirtying the interface.
                    iface.election_dirty
                        || (iface.wait_deadline_ms != 0 && now_ms >= iface.wait_deadline_ms)
                }
                IfState::DrOther | IfState::Backup | IfState::Dr => {
                    // §9.3 NeighborChange: the DR/BDR relationship of a
                    // neighbor (or the bidirectional set) changed.
                    iface.election_dirty
                }
                _ => false,
            };
            if fire {
                iface.wait_deadline_ms = 0;
                iface.election_dirty = false;
                if Self::run_election(iface, &mut self.neighbors, &self.router, self_rid, now_ms) {
                    // The transit-link set (§4.4.3.2) and the
                    // Network-LSA membership (§4.4.3.3) may have
                    // changed.
                    if !changed_areas.contains(&iface.area) {
                        changed_areas.push(iface.area);
                    }
                }
            }
        }
        let now = now_ms;
        for area in changed_areas {
            self.schedule_reoriginate(area, now);
        }
    }

    /// One §9.4 election round on `iface`: the elector list is the
    /// bidirectional neighbors heard within the dead window plus this
    /// router itself, keyed by Router IDs (the RFC 5340 §4.1.2
    /// identity). The result lands in the Hello DR/BDR fields (§A.3.2)
    /// and is pushed into every session on the segment, whose §10.4
    /// adjacency gate the router re-runs (§9.4 step 7).
    ///
    /// Returns whether the elected pair (or our role) changed.
    fn run_election(
        iface: &mut Ospf3Interface,
        neighbors: &mut BTreeMap<(u32, u32), Neighbor>,
        router: &RwLock<DefaultRouter>,
        self_rid: u32,
        now_ms: u64,
    ) -> bool {
        let dead_ms = u64::from(iface.dead_interval) * 1000;
        let mut electors: Vec<V3Elector> = iface
            .heard
            .iter()
            .filter(|(_, h)| h.bidirectional && now_ms.saturating_sub(h.last_ms) <= dead_ms)
            .map(|(&rid, h)| V3Elector {
                router_id: rid,
                priority: h.priority,
                stated_dr: h.stated_dr,
                stated_bdr: h.stated_bdr,
            })
            .collect();
        // Router X itself is on the list (§9.4), claiming its current
        // view of the segment.
        electors.push(V3Elector {
            router_id: self_rid,
            priority: iface.priority,
            stated_dr: iface.dr,
            stated_bdr: iface.bdr,
        });
        let (dr, bdr) = elect_v3(&electors, self_rid);
        let changed = dr != iface.dr || bdr != iface.bdr;
        iface.dr = dr;
        iface.bdr = bdr;
        // §9.4 step 5: derive our interface state from the result.
        let next_state = if self_rid == dr {
            IfState::Dr
        } else if self_rid == bdr {
            IfState::Backup
        } else {
            IfState::DrOther
        };
        let role_changed = next_state != iface.if_state;
        iface.if_state = next_state;
        // §9.4 step 7: the AdjOK? event on every neighbor — pushed via
        // set_ospf_dr_state, which re-runs the §10.4 decision per
        // session (advance to ExStart or demote to 2-Way).
        let mut router = router.write().unwrap();
        for ((area, _rid), n) in neighbors.iter_mut() {
            if *area != iface.area || n.ifindex != iface.interface_id {
                continue;
            }
            match router.set_ospf_dr_state(n.handle, dr, bdr) {
                Ok(_) => {}
                Err(e) => eprintln!("daemon: ospf3 dr state: {}", e),
            }
        }
        if changed || role_changed {
            println!(
                "daemon: ospf3 iface {} elected DR {} / BDR {} — we are {}",
                iface.name,
                fmt_rid(dr),
                fmt_rid(bdr),
                iface.if_state.name()
            );
        }
        changed || role_changed
    }

    /// Receive every pending datagram and feed it into the matching
    /// neighbor session, creating sessions for unknown routers. v6 raw
    /// sockets deliver the OSPF packet without the IPv6 header, and
    /// receive-side checksum verification is skipped (FRR ospf6d
    /// parity — the RFC 5340 §4.2.2 checks the daemon enforces are
    /// version, area and source identity).
    fn pump_inbound(&mut self, recv_buf: &mut [u8], now_ms: u64) {
        let mut datagrams: Vec<(u32, u32, Vec<u8>, Ipv6Addr)> = Vec::new();
        for iface in &mut self.interfaces {
            loop {
                match iface.transport.recv_from(recv_buf) {
                    Ok(Some((n, src))) => {
                        let ospf = &recv_buf[..n];
                        if ospf.len() < lr_ospf::packet::OspfHeader::LEN_V3 {
                            continue;
                        }
                        if ospf_debug_enabled() {
                            eprintln!(
                                "dbg-recv kind={} len={} rid={:08x} src={}",
                                ospf.get(1).copied().unwrap_or(0),
                                u16::from_be_bytes([ospf[2], ospf[3]]),
                                u32::from_be_bytes([ospf[4], ospf[5], ospf[6], ospf[7]]),
                                src
                            );
                        }
                        if ospf.get(1).copied() == Some(OspfPacketType::Hello as u8)
                            && ospf.len() >= 12
                        {
                            let hello_rid =
                                u32::from_be_bytes([ospf[4], ospf[5], ospf[6], ospf[7]]);
                            let hello_area =
                                u32::from_be_bytes([ospf[8], ospf[9], ospf[10], ospf[11]]);
                            if hello_rid != self.router_id.as_u32() && hello_area == iface.area {
                                if let Some(body) = parse_hello_body_v3(ospf) {
                                    iface.track_hello(
                                        hello_rid,
                                        src,
                                        &body,
                                        self.router_id.as_u32(),
                                        now_ms,
                                    );
                                    // The neighbor's link-local rides its
                                    // interface: register it for the
                                    // kernel mirror's RTA_OIF lookups.
                                    crate::v6_nexthop_oifs()
                                        .lock()
                                        .map(|mut m| {
                                            m.insert(IpAddr::V6(src.octets()), iface.interface_id)
                                        })
                                        .ok();
                                }
                            }
                        }
                        datagrams.push((iface.interface_id, iface.area, ospf.to_vec(), src));
                    }
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("daemon: ospf recv {}: {}", iface.name, e);
                        break;
                    }
                }
            }
        }
        let mut accepted: Vec<(u32, u32, u32, usize, u16)> = Vec::new();
        for (idx, (interface_id, iface_area, bytes, _src)) in datagrams.iter().enumerate() {
            let Some((rid, area, _len)) = demux_header(bytes) else {
                continue;
            };
            if area != *iface_area || rid == self.router_id.as_u32() {
                continue;
            }
            let mtu = self
                .interfaces
                .iter()
                .find(|i| i.interface_id == *interface_id)
                .map(|i| i.mtu)
                .unwrap_or(1500);
            accepted.push((*interface_id, area, rid, idx, mtu));
        }
        if accepted.is_empty() {
            return;
        }
        let router_arc = Arc::clone(&self.router);
        let mut router = router_arc.write().unwrap();
        for (interface_id, area, rid, idx, mtu) in accepted {
            let key = (area, rid);
            if !self.neighbors.contains_key(&key) {
                // Broadcast segments carry the network type and the
                // segment identities into the session: §10.4 gates
                // adjacency on the elected DR/BDR, identified by
                // Router ID (RFC 5340 §4.1.2 — the v3 Hello's DR/BDR
                // fields are Router IDs, §A.3.2).
                let cfg_build = self
                    .interfaces
                    .iter()
                    .find(|i| i.interface_id == interface_id)
                    .map(|iface| {
                        let cfg = SessionConfig::ospfv3(self.router_id, area)
                            .with_ospf_mtu(mtu)
                            .with_ospf_network_type(iface.network_type);
                        match iface.network_type {
                            OspfNetworkType::Broadcast => cfg
                                .with_ospf_interface_ip(self.router_id.as_u32())
                                .with_ospf_neighbor_ip(rid),
                            OspfNetworkType::PointToPoint => cfg,
                        }
                    })
                    .unwrap_or_else(|| SessionConfig::ospfv3(self.router_id, area));
                match router.add_session(cfg_build) {
                    Ok(h) => {
                        // Push the current election result so a session
                        // joining mid-life adopts the segment's DR/BDR
                        // immediately (the v2 daemon pattern).
                        if let Some(iface) = self
                            .interfaces
                            .iter()
                            .find(|i| i.interface_id == interface_id)
                        {
                            if iface.network_type == OspfNetworkType::Broadcast {
                                let _ = router.set_ospf_dr_state(h, iface.dr, iface.bdr);
                            }
                        }
                        self.neighbors.insert(
                            key,
                            Neighbor {
                                handle: h,
                                ifindex: interface_id,
                                established: false,
                                helper: HelperEntry::default(),
                            },
                        );
                        println!(
                            "daemon: ospf3 neighbor {} discovered (area {}, iface {})",
                            fmt_rid(rid),
                            area_label(area),
                            self.interfaces
                                .iter()
                                .find(|i| i.interface_id == interface_id)
                                .map(|i| i.name.as_str())
                                .unwrap_or("?")
                        );
                    }
                    Err(e) => {
                        eprintln!("daemon: ospf3 add_session: {e}");
                        continue;
                    }
                }
            }
            let handle = self.neighbors[&key].handle;
            if let Err(e) = router.feed_input(handle, &datagrams[idx].2) {
                eprintln!("daemon: ospf3 feed_input: {e}");
            }
        }
        // Events are consumed (logged + kernel-mirrored) solely by the
        // ticker thread — the daemon would race it here and steal
        // RouteInstalled events before the mirror sees them.
    }

    /// Track Full transitions via session summaries (the v2 pattern)
    /// and schedule Router-LSA re-origination for the affected areas.
    /// Both directions matter: a newly Full adjacency adds a link to
    /// the Router-LSA, and a Full → 2-Way demotion (the §10.4 gate
    /// closing on an election change) removes it — without the
    /// downward edge the stale link lingers until the §14.1 refresh.
    fn pump_adjacency(&mut self, now_ms: u64) {
        let mut newly_full: Vec<(u32, u32)> = Vec::new();
        let mut dropped_full: Vec<(u32, u32)> = Vec::new();
        let mut changed_areas: Vec<u32> = Vec::new();
        {
            let router_arc = Arc::clone(&self.router);
            let router = router_arc.read().unwrap();
            let summaries = router.session_summaries();
            for ((area, rid), n) in self.neighbors.iter_mut() {
                let est = summaries
                    .iter()
                    .any(|s| s.handle == n.handle && s.established);
                if est && !n.established {
                    n.established = true;
                    changed_areas.push(*area);
                    newly_full.push((*area, *rid));
                } else if !est && n.established {
                    n.established = false;
                    changed_areas.push(*area);
                    dropped_full.push((*area, *rid));
                }
            }
        }
        for area in changed_areas {
            self.schedule_reoriginate(area, now_ms);
        }
        for (area, rid) in newly_full {
            println!(
                "daemon: ospf3 neighbor {} Full (area {})",
                fmt_rid(rid),
                area_label(area)
            );
        }
        for (area, rid) in dropped_full {
            println!(
                "daemon: ospf3 neighbor {} left Full (area {}) — adjacency demoted",
                fmt_rid(rid),
                area_label(area)
            );
        }
    }

    /// Tear sessions down after RouterDeadInterval without a packet.
    /// Neighbours in graceful-restart helper mode (RFC 5187 §3 via
    /// RFC 3623 §3) are exempt — FRR's ospf6d resets the inactivity
    /// timer while helping (`inactivity_timer`): their `heard`
    /// entries and sessions are retained for the grace period; the
    /// helper exits re-evaluate.
    fn pump_dead_timer(&mut self, now_ms: u64) {
        // RFC 3623 §3 retention set, computed up front so the
        // interface loop below can stay a plain mutable walk.
        let retained: std::collections::BTreeSet<(u32, u32)> = self
            .neighbors
            .iter()
            .filter(|(_, n)| n.helper.is_active())
            .map(|((area, rid), _)| (*area, *rid))
            .collect();
        let mut expired: Vec<(u32, u32)> = Vec::new();
        // Broadcast interfaces that lost a heard neighbor: the
        // bidirectional elector set shrank (§9.3 NeighborChange).
        let mut election_dirty_ifaces: Vec<u32> = Vec::new();
        for iface in &mut self.interfaces {
            let dead_ms = u64::from(iface.dead_interval) * 1000;
            let gone: Vec<u32> = iface
                .heard
                .iter()
                .filter(|(rid, h)| {
                    now_ms.saturating_sub(h.last_ms) > dead_ms
                        && !retained.contains(&(iface.area, **rid))
                })
                .map(|(rid, _)| *rid)
                .collect();
            for rid in gone {
                iface.heard.remove(&rid);
                expired.push((iface.area, rid));
                if iface.network_type == OspfNetworkType::Broadcast {
                    election_dirty_ifaces.push(iface.interface_id);
                }
            }
        }
        if expired.is_empty() {
            return;
        }
        let router_arc = Arc::clone(&self.router);
        let mut router = router_arc.write().unwrap();
        for (area, rid) in expired {
            if let Some(n) = self.neighbors.remove(&(area, rid)) {
                router.close_session(n.handle);
                println!(
                    "daemon: ospf3 neighbor {} dead (area {}) — session closed",
                    fmt_rid(rid),
                    area_label(area)
                );
            }
        }
        drop(router);
        for iface in &mut self.interfaces {
            if election_dirty_ifaces.contains(&iface.interface_id) {
                iface.election_dirty = true;
            }
        }
        let areas: Vec<u32> = self.anchors.keys().copied().collect();
        for area in areas {
            self.schedule_reoriginate(area, now_ms);
        }
    }

    /// Re-originate the Router-LSA when scheduled (adjacency changes)
    /// or when the §14.1 refresh cadence elapses.
    fn pump_reoriginate(&mut self, now_ms: u64) {
        let mut due: Vec<(u32, u64)> = self
            .pending_reorig
            .iter()
            .filter(|(_, t)| **t <= now_ms)
            .map(|(a, t)| (*a, *t))
            .collect();
        for area in self.anchors.keys() {
            let needs_refresh = self
                .last_orig_ms
                .get(area)
                .map(|t| now_ms.saturating_sub(*t) >= LS_REFRESH_MS)
                .unwrap_or(false);
            if needs_refresh {
                due.push((*area, now_ms));
            }
        }
        if due.is_empty() {
            return;
        }
        due.sort_by_key(|(_, t)| *t);
        let areas: Vec<u32> = due.into_iter().map(|(a, _)| a).collect();
        let router_arc = Arc::clone(&self.router);
        let mut router = router_arc.write().unwrap();
        for area in areas {
            self.pending_reorig.remove(&area);
            self.reoriginate_area(&mut router, area, now_ms);
        }
    }

    fn schedule_reoriginate(&mut self, area: u32, now_ms: u64) {
        // No-op while graceful-restart recovery is live: RFC 5187 §2
        // (1) (inherited from RFC 3623 §2) — the pre-restart LSAs the
        // helpers retained keep describing the topology until §2.2
        // exits recovery (the exit path re-origination is driven
        // directly, not through here).
        if self.gr_recovery.contains_key(&area) {
            return;
        }
        let due = now_ms + REORIGINATE_DELAY_MS;
        self.pending_reorig
            .entry(area)
            .and_modify(|t| *t = (*t).min(due))
            .or_insert(due);
    }

    /// One pump pass of the graceful-restart machines (RFC 5187,
    /// inheriting RFC 3623): the received Grace-LSA events (§3.1
    /// helper entry / §3.2 (1) flush exit), the §3.2 (3)
    /// topology-change exits for helpers, the §3.2 (2) grace
    /// timeouts, and the §2.2 recovery evaluation for the restarting
    /// side.
    fn pump_gr(&mut self, now_ms: u64) {
        // The grace channel first: a flush event must be able to end
        // helper mode before the topology/timeout machinery below
        // re-evaluates the same neighbour.
        {
            let router_arc = Arc::clone(&self.router);
            let mut router = router_arc.write().unwrap();
            let grace_events = router.drain_ospf_grace_events();
            drop(router);
            for ev in &grace_events {
                self.on_grace_lsa_event(ev, now_ms);
            }
        }
        let mut helper_exits: Vec<(u32, u32, lr_ospf::gr::HelperExit)> = Vec::new();
        let mut gr_recovery_done: Option<lr_ospf::gr::RestartOutcome> = None;
        {
            let router_arc = Arc::clone(&self.router);
            let router = router_arc.read().unwrap();

            // §3.2 (3): topology changes terminate helpers. Per area,
            // the poll-side counterpart of FRR ospf6d's
            // `ospf6_helper_handle_topo_chg` walk (area granularity:
            // a p2p lab's area maps 1:1 to a segment; the
            // flooding-allowed refinement of §3.2 (3)b is future
            // work).
            for area in self.anchors.keys().copied().collect::<Vec<u32>>() {
                let version = router.ospf_area_topology_version(area).unwrap_or(0);
                let known = self.gr_topology.get(&area).copied();
                match known {
                    None => {
                        // First observation after startup — no change yet.
                        self.gr_topology.insert(area, version);
                    }
                    Some(v) if v != version => {
                        self.gr_topology.insert(area, version);
                        for ((n_area, rid), n) in self.neighbors.iter_mut() {
                            if *n_area == area && n.helper.is_active() {
                                if let Some(exit) = n.helper.on_topology_change() {
                                    helper_exits.push((*n_area, *rid, exit));
                                }
                            }
                        }
                    }
                    Some(_) => {}
                }
            }
            // §3.2 (2): grace-period deadlines.
            for ((area, rid), n) in self.neighbors.iter_mut() {
                if let Some(exit) = n.helper.poll(now_ms) {
                    helper_exits.push((*area, *rid, exit));
                }
            }

            // §2.2: the restarting side. Feed adjacency observations,
            // verify back-links, poll the outcome.
            if !self.gr_recovery.is_empty() {
                let our_rid = self.router_id.as_u32();
                let areas: Vec<u32> = self.gr_recovery.keys().copied().collect();
                for area in areas {
                    let Some(tracker) = self.gr_recovery.get_mut(&area) else {
                        continue;
                    };
                    // Seed the pre-restart adjacency set once our old
                    // Router-LSA (re-received from a helper through
                    // database exchange) shows up in the LSDB — the
                    // v3 §2.2 (1) yardstick is the p2p link set
                    // (neighbor Router IDs, §A.4.3).
                    if let Some(lsa) = router.ospf_area_lsa(area, LS_TYPE_ROUTER, 0, our_rid) {
                        if let Some(body) = V3RouterLsaBody::decode(&lsa.body) {
                            let p2p: Vec<u32> = body
                                .links
                                .iter()
                                .filter(|l| l.link_type == LINK_TYPE_POINTTOPOINT)
                                .map(|l| l.neighbor_router_id)
                                .collect();
                            tracker.set_pre_restart_adjacencies(p2p);
                        }
                    }
                    // §2.2 (1) yardstick: every listed adjacency Full.
                    let listed: Vec<u32> = tracker.adjacency_ids().collect();
                    for rid in listed {
                        let full = self.neighbors.get(&(area, rid)).map(|n| n.established);
                        tracker.observe_adjacency(rid, full);
                        // §2.2 (2): back-link verification — a Full
                        // neighbour whose Router-LSA no longer links
                        // back to us means it never helped (or
                        // stopped). The v3 back-link is the p2p
                        // descriptor naming our Router ID (§A.4.3), or
                        // a transit link onto a segment we describe.
                        if full == Some(true) {
                            if let Some(their) = router.ospf_area_lsa(area, LS_TYPE_ROUTER, 0, rid)
                            {
                                let back =
                                    V3RouterLsaBody::decode(&their.body).is_some_and(|body| {
                                        body.links.iter().any(|l| {
                                            l.link_type == LINK_TYPE_POINTTOPOINT
                                                && l.neighbor_router_id == our_rid
                                        }) || body
                                            .links
                                            .iter()
                                            .any(|l| l.link_type == LINK_TYPE_TRANSIT)
                                    });
                                if !back {
                                    tracker.mark_inconsistent();
                                }
                            }
                        }
                    }
                    if let Some(outcome) = tracker.poll(now_ms) {
                        if outcome != lr_ospf::gr::RestartOutcome::AdjacenciesRestablished {
                            gr_recovery_done = Some(outcome);
                        }
                    }
                }
                // Global §2.2 (1): recovery succeeds when every area's
                // tracker reports all adjacencies back.
                if gr_recovery_done.is_none()
                    && !self.gr_recovery.is_empty()
                    && self.gr_recovery.values_mut().all(|t| {
                        t.poll(now_ms).is_some_and(|o| {
                            o == lr_ospf::gr::RestartOutcome::AdjacenciesRestablished
                        })
                    })
                {
                    gr_recovery_done = Some(lr_ospf::gr::RestartOutcome::AdjacenciesRestablished);
                }
            }
        }
        for (area, rid, exit) in helper_exits {
            println!(
                "daemon: ospf3 neighbor {} (area {}): helper mode exited — {}",
                fmt_rid(rid),
                area_label(area),
                exit.reason()
            );
            self.after_helper_exit(area, rid, now_ms);
        }
        if let Some(outcome) = gr_recovery_done {
            self.exit_gr_recovery(outcome, now_ms);
        }
        self.refresh_gr_status();
    }

    /// One received Grace-LSA (the router already decoded + deduped
    /// it). RFC 5187 §2/§3 (via RFC 3623 §3.1): on a flush (MaxAge)
    /// exit helper mode; on a fresh instance run the entry checks
    /// against the neighbour session and the configured policy. The
    /// v3 neighbour identity is the Advertising Router — RFC 5187 §1:
    /// OSPFv3 neighbours are always Router-ID identified, no
    /// router-address TLV indirection.
    fn on_grace_lsa_event(&mut self, ev: &OspfGraceEvent, now_ms: u64) {
        let area = ev.area;
        let rid = ev.advertising_router;
        let Some(n) = self.neighbors.get_mut(&(area, rid)) else {
            if !ev.purged {
                println!(
                    "daemon: ospf3 grace-LSA from {} (area {}): no session, not helping \
                     (RFC 3623 3.1 (1) — neighbour not Full)",
                    fmt_rid(rid),
                    area_label(area)
                );
            }
            return;
        };
        if ev.purged {
            if let Some(exit) = n.helper.on_flush() {
                println!(
                    "daemon: ospf3 neighbor {} (area {}): helper mode exited — {}",
                    fmt_rid(rid),
                    area_label(area),
                    exit.reason()
                );
                self.after_helper_exit(area, rid, now_ms);
            }
            return;
        }
        let body = GraceLsaBody {
            grace_period: ev.grace_period_secs,
            reason: GraceReason::from_u8(ev.reason),
            ipv4_address: ev.interface_addr_v4,
            ipv6_address: ev.interface_addr_v6,
        };
        let neighbor_full = n.established;
        let check = HelperCheck {
            neighbor_full,
            helper_enabled: self.gr_helper_enabled,
            supported_grace_cap_secs: self.gr_helper_cap,
            self_restarting: self.gr_recovery.contains_key(&area),
            lsa: &body,
            lsa_age_secs: ev.ls_age_secs,
            now_ms,
        };
        let transition = n.helper.on_grace_lsa(check);
        match transition {
            lr_ospf::gr::HelperTransition::Entered { .. } => {
                println!(
                    "daemon: ospf3 neighbor {} (area {}): helper mode entered (grace {}s, \
                     reason {}) — adjacency and LSAs retained",
                    fmt_rid(rid),
                    area_label(area),
                    ev.grace_period_secs,
                    match ev.reason {
                        1 => "software restart",
                        2 => "software reload/upgrade",
                        3 => "redundant switchover",
                        _ => "unknown",
                    }
                );
            }
            lr_ospf::gr::HelperTransition::Refreshed { .. } => {}
            lr_ospf::gr::HelperTransition::Refused(why) => {
                println!(
                    "daemon: ospf3 neighbor {} (area {}): not helping — {}",
                    fmt_rid(rid),
                    area_label(area),
                    why.reason()
                );
            }
        }
    }

    /// Re-evaluate a neighbour after its helper relationship ended
    /// (§3.2, FRR ospf6d `ospf6_gr_helper_exit`): re-run the DR
    /// election inputs on broadcast segments, re-originate the area's
    /// self-described LSAs (the retained adjacency drops unless the
    /// neighbour is really back), and reap the session if it stayed
    /// silent past the dead interval.
    fn after_helper_exit(&mut self, area: u32, rid: u32, now_ms: u64) {
        if let Some(ifindex) = self.neighbors.get(&(area, rid)).map(|n| n.ifindex) {
            if let Some(iface) = self
                .interfaces
                .iter_mut()
                .find(|i| i.interface_id == ifindex)
            {
                iface.election_dirty = true;
            }
        }
        // Reap a neighbour that is still silent: without the helper
        // retention the dead timer would have removed it already.
        let still_quiet = self.interfaces.iter().any(|i| {
            i.area == area
                && i.heard.get(&rid).is_some_and(|h| {
                    now_ms.saturating_sub(h.last_ms) > u64::from(i.dead_interval) * 1_000
                })
        });
        if still_quiet {
            if let Some(n) = self.neighbors.remove(&(area, rid)) {
                let router_arc = Arc::clone(&self.router);
                let mut router = router_arc.write().unwrap();
                router.close_session(n.handle);
                for ev in router.poll_events() {
                    crate::daemon_ospf::log_event(&ev);
                }
            }
            for iface in self.interfaces.iter_mut() {
                if iface.area == area {
                    iface.heard.remove(&rid);
                    iface.election_dirty = true;
                }
            }
            println!(
                "daemon: ospf3 neighbor {} dead (area {}) — session closed",
                fmt_rid(rid),
                area_label(area)
            );
        }
        self.schedule_reoriginate(area, now_ms);
    }

    /// §2.3: leave graceful restart (success or failure): flush the
    /// Grace-LSAs this router originated (helpers exit on the MaxAge
    /// instance), re-enable origination and re-originate the area's
    /// self-described LSAs from current state.
    fn exit_gr_recovery(&mut self, outcome: lr_ospf::gr::RestartOutcome, now_ms: u64) {
        let areas: Vec<u32> = self.gr_recovery.keys().copied().collect();
        println!(
            "daemon: ospf3 graceful restart recovery ended — {}",
            outcome.reason()
        );
        self.gr_recovery.clear();
        if let Some(state) = self.gr_state_file.as_deref() {
            let _ = std::fs::remove_file(state);
        }
        // §2.3 (6): flush the Grace-LSAs — the MaxAge instances tell
        // the helpers the restart finished (§3.2 (1)).
        self.send_grace_lsas(true);
        // §2.3 (1)/(2): re-originate the Router-/Link-/IAP-LSAs from
        // current state — via the scheduled path so MinLSArrival
        // (RFC 2328 §14) paces the instance the exchange just
        // delivered. The sequence floors come from the retained
        // pre-restart LSAs inside reoriginate_area.
        for area in areas {
            self.schedule_reoriginate(area, now_ms);
        }
        // A topology-observing restart exit refreshes the helper-side
        // snapshot so our own re-origination does not read as a
        // topology change (helpers for other routers on this box).
        {
            let router_arc = Arc::clone(&self.router);
            let router = router_arc.read().unwrap();
            for area in self.anchors.keys() {
                if let Some(v) = router.ospf_area_topology_version(*area) {
                    self.gr_topology.insert(*area, v);
                }
            }
        }
    }

    /// Build and (re)transmit the Grace-LSA of every interface inside
    /// one LS-Update per interface, directly on the transport (the
    /// restarting router speaks before any adjacency exists; §2.1).
    /// `flush` selects the §2.3 MaxAge flush form instead of the
    /// shutdown announcement. The v3 shapes: LS type 0x000b, Link
    /// State ID = the Interface ID (RFC 5187 §2.2), no address TLV
    /// (FRR's `ospf6_gr_lsa_originate` form).
    fn send_grace_lsas(&mut self, flush: bool) {
        let period_hint = lr_ospf::gr::clamp_grace_period(self.gr_grace_period);
        let our_rid = self.router_id.as_u32();
        // Sequence derivation: strictly newer than every instance this
        // router ever sent — the wallclock base (which grows across
        // restarts) OR the persisted floor + 1, whichever is larger.
        // Each originated LSA advances the floor, so a flush followed
        // by another shutdown (or a restart) can never emit an
        // older/equal instance.
        let mut floor = self.gr_seq_floor;
        for iface in &mut self.interfaces {
            // The flush keeps a valid body (period ≥ 1, reason ≤ 3):
            // FRR ospf6d's grace-LSA extraction rejects a period of 0
            // or an unknown reason code even for the MaxAge instance
            // (ospf6_extract_grace_lsa_fields: "Wrong Grace LSA
            // packet"), and FRR's own purge (`ospf6_lsa_purge`) keeps
            // the full TLV set — only the age and sequence differ from
            // the announcement. BIRD and lr ignore the flush body, so
            // the richer shape is safe everywhere.
            let body = GraceLsaBody {
                grace_period: period_hint,
                reason: GraceReason::SoftwareRestart,
                ipv4_address: None,
                ipv6_address: None,
            };
            let seq = grace_sequence_base().max(floor.wrapping_add(1));
            floor = seq;
            let Some(mut lsa) = originate_grace_lsa_v3(
                our_rid,
                iface.interface_id,
                &body,
                Some(seq.wrapping_sub(1)),
            ) else {
                continue;
            };
            if flush {
                lsa.header.ls_age = lr_ospf::lsdb::MAX_AGE_SECS;
                lsa.finalize();
            }
            let packet = lr_ospf::packet::OspfPacket {
                header: lr_ospf::packet::OspfHeader {
                    version: lr_ospf::packet::OspfVersion::V3 as u8,
                    kind: OspfPacketType::LinkStateUpdate as u8,
                    length: 0,
                    router_id: our_rid,
                    area_id: iface.area,
                    checksum: 0,
                    au_type_or_instance: 0,
                    auth_data: 0,
                },
                body: OspfBody::LsUpdate(lr_ospf::packet::LsUpdateBody {
                    lsa_count: 1,
                    lsas: vec![lsa],
                }),
            };
            match OspfCodec::v3().encode_vec(&packet) {
                Ok(mut bytes) => {
                    finalize_v3_packet(&mut bytes, &iface.link_local.octets(), &MULTICAST_ALL_SPF);
                    if let Err(e) = iface.transport.send_multicast(&bytes) {
                        eprintln!("daemon: ospf3 grace-LSA send {}: {}", iface.name, e);
                    }
                    // RFC 2328 §13.5 direct flooding: every
                    // bidirectional neighbour on this interface also
                    // gets a unicast copy at its link-local — the
                    // helper entry must not hinge on one multicast
                    // surviving a loaded scheduler (RFC 3623 §2.1:
                    // retransmit until received).
                    let heard: Vec<Ipv6Addr> = iface
                        .heard
                        .values()
                        .filter(|n| n.bidirectional)
                        .map(|n| n.link_local)
                        .collect();
                    for dst in heard {
                        if let Err(e) = iface.transport.send_unicast(dst, &bytes) {
                            eprintln!("daemon: ospf3 grace-LSA unicast {dst}: {e}");
                        }
                    }
                }
                Err(e) => eprintln!("daemon: ospf3 grace-LSA encode: {e}"),
            }
        }
        self.gr_seq_floor = floor;
    }

    /// The §2.1 shutdown flood: send the Grace-LSAs on every
    /// interface, retransmitting a bounded number of times (the
    /// flood path is fire-and-forget; FRR ospf6d performs ack-tracked
    /// reliable flooding, we approximate with repeats). Also persists
    /// the grace state file so the restarted process knows to enter
    /// recovery (deadline, grace period, sequence floor) — the
    /// non-volatile-storage note of RFC 3623 §2.1 / FRR's
    /// `ospf6_gr_nvm_update`.
    fn graceful_shutdown_flood(&mut self, recv_buf: &mut [u8], start: &std::time::Instant) {
        let period = lr_ospf::gr::clamp_grace_period(self.gr_grace_period);
        for attempt in 0..GRACE_FLOOD_REPEATS {
            self.send_grace_lsas(false);
            if attempt + 1 < GRACE_FLOOD_REPEATS {
                let next_round =
                    std::time::Instant::now() + Duration::from_millis(GRACE_FLOOD_INTERVAL_MS);
                // Service the protocol while the flood window runs: a
                // peer that just re-originated its Router-LSA (the
                // post-Full refresh) has it on its LS retransmission
                // list for us, and FRR's strict-LSA-check helper entry
                // refuses helper mode until the ACK arrives. Pumping
                // input between rounds sends that ACK, keeps our
                // Hellos flowing so the peer's neighbour state stays
                // Full (§3.1 (1)), and lets the next round's fresh
                // Grace-LSA instance re-run the helper checks.
                while std::time::Instant::now() < next_round {
                    let now_ms = start.elapsed().as_millis() as u64;
                    self.pump_grace_quiet(recv_buf, now_ms);
                    std::thread::sleep(Duration::from_millis(GRACE_PUMP_SLICE_MS));
                }
            }
        }
        // Persist the grace state AFTER the flood so the sequence
        // floor covers every instance just sent (the deadline runs
        // from the shutdown moment).
        let deadline_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            + u64::from(period) * 1_000;
        if let Some(state) = &self.gr_state_file {
            let line = format!("{deadline_unix_ms} {period} {}\n", self.gr_seq_floor);
            if let Err(e) = std::fs::write(state, line) {
                eprintln!("daemon: ospf3 grace state write {state}: {e}");
            }
        }
    }

    /// Minimal protocol servicing during the graceful-shutdown flood
    /// window: receive (so in-flight peer LSAs get ACKed by the
    /// session machinery), Hellos (keep the peer's view of us Full,
    /// §3.1 (1)), outbound. Everything that mutates the pre-restart
    /// topology — re-origination, DR election, adjacency teardown — is
    /// deliberately skipped: §2.1 wants the router's LSAs frozen while
    /// the Grace-LSAs are announced and acknowledged.
    fn pump_grace_quiet(&mut self, recv_buf: &mut [u8], now_ms: u64) {
        self.pump_inbound(recv_buf, now_ms);
        self.pump_hellos(now_ms);
        self.pump_outbound();
    }

    /// Refresh the runtime-API status snapshot (cheap: a small vec).
    fn refresh_gr_status(&self) {
        let mut lines = Vec::new();
        if let Some((_, tracker)) = self.gr_recovery.first_key_value() {
            lines.push(format!(
                "ospf3 graceful restart: recovering (grace deadline +{}ms)",
                tracker.grace_deadline_ms()
            ));
        }
        let helpers: Vec<String> = self
            .neighbors
            .iter()
            .filter(|(_, n)| n.helper.is_active())
            .map(|((area, rid), n)| {
                format!(
                    "  helper {} (area {}, {}s grace left)",
                    fmt_rid(*rid),
                    area_label(*area),
                    n.helper.last_period_secs()
                )
            })
            .collect();
        if !helpers.is_empty() {
            lines.push("ospf3 graceful restart helpers:".to_string());
            lines.extend(helpers);
        }
        if let Ok(mut s) = self.status.lock() {
            *s = lines;
        }
    }

    /// Send one v3 Hello per interface whose interval elapsed,
    /// listing the router-ids heard inside the dead window (§A.3.2).
    fn pump_hellos(&mut self, now_ms: u64) {
        for iface in self.interfaces.iter_mut() {
            let interval_ms = u64::from(iface.hello_interval) * 1000;
            if now_ms.saturating_sub(iface.last_hello_ms) < interval_ms {
                continue;
            }
            iface.last_hello_ms = now_ms;
            let dead_ms = u64::from(iface.dead_interval) * 1000;
            let neighbors: Vec<u32> = iface
                .heard
                .iter()
                .filter(|(_, h)| now_ms.saturating_sub(h.last_ms) <= dead_ms)
                .map(|(rid, _)| *rid)
                .collect();
            let hello = HelloBody {
                // v3: the network-mask slot carries the Interface ID.
                network_mask: iface.interface_id,
                hello_interval: iface.hello_interval,
                options: OSPF_V3_OPTIONS_DEFAULT,
                priority: iface.priority,
                dead_interval: iface.dead_interval.min(u32::from(u16::MAX)),
                // p2p segments elect no DR (§9.4 does not apply); on
                // broadcast segments the fields carry the elected
                // Router IDs (§A.3.2, RFC 5340 §4.1.2).
                dr: if iface.network_type == OspfNetworkType::Broadcast {
                    iface.dr
                } else {
                    0
                },
                bdr: if iface.network_type == OspfNetworkType::Broadcast {
                    iface.bdr
                } else {
                    0
                },
                neighbors,
            };
            let pkt = lr_ospf::packet::OspfPacket {
                header: lr_ospf::packet::OspfHeader {
                    version: lr_ospf::packet::OspfVersion::V3 as u8,
                    kind: OspfPacketType::Hello as u8,
                    length: 0,
                    router_id: self.router_id.as_u32(),
                    area_id: iface.area,
                    checksum: 0,
                    au_type_or_instance: 0,
                    auth_data: 0,
                },
                body: OspfBody::Hello(hello),
            };
            let mut bytes = match OspfCodec::v3().encode_vec(&pkt) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("daemon: ospf3 hello encode: {e}");
                    continue;
                }
            };
            finalize_v3_packet(&mut bytes, &iface.link_local.octets(), &MULTICAST_ALL_SPF);
            dbg_send_trace(&bytes);
            if let Err(e) = iface.transport.send_multicast(&bytes) {
                eprintln!("daemon: ospf3 hello send {}: {}", iface.name, e);
            }
        }
    }

    /// Drain neighbor sessions and send every packet as its own
    /// datagram, checksum finalized for the pseudo-header this
    /// interface actually uses (source link-local, destination
    /// ff02::5 for the multicast shapes, the peer's link-local for
    /// the conversational ones). Anchor output is discarded (no wire
    /// neighbor).
    fn pump_outbound(&mut self) {
        // (ifindex, destination, datagram). RFC 2328 §8.1 (inherited by
        // RFC 5340 §4.2: "the IPv6 destination address is chosen from
        // among the addresses AllSPFRouters, AllDRouters, and the
        // Neighbor IP address associated with the other end of the
        // adjacency"): on broadcast networks only Hello, LSU and LSAck
        // ride multicast — the per-adjacency conversation packets (DD,
        // LSR) are unicast at the peer's link-local. Multicasting those
        // breaks segments with three or more speakers: every router
        // dispatches by header Router-ID, so the two independent
        // sequence-numbered conversations of one DR interleave in each
        // DR-Other's single session with it and the negotiation
        // deadlocks (caught by tests/interop/ospf6_e_lsa_endx_lan.sh).
        let mut outbound: Vec<(u32, [u8; 16], Vec<u8>)> = Vec::new();
        {
            let router_arc = Arc::clone(&self.router);
            let mut router = router_arc.write().unwrap();
            for ((_area, rid), n) in &self.neighbors {
                let stream = router.drain_output(n.handle);
                if stream.is_empty() {
                    continue;
                }
                // The peer's link-local (Hello source). Unknown peer —
                // fall back to multicast rather than dropping: the
                // conversation is dead either way, but a multicast DD
                // still reaches it if it lives.
                let peer_ll = self
                    .interfaces
                    .iter()
                    .find(|i| i.interface_id == n.ifindex)
                    .and_then(|i| i.heard.get(rid))
                    .map(|h| h.link_local.octets());
                let mut off = 0usize;
                while off + lr_ospf::packet::OspfHeader::LEN_V3 <= stream.len() {
                    let len = u16::from_be_bytes([stream[off + 2], stream[off + 3]]) as usize;
                    if len < lr_ospf::packet::OspfHeader::LEN_V3 || off + len > stream.len() {
                        break;
                    }
                    let kind = stream[off + 1];
                    let conversational = matches!(
                        kind,
                        k if k == OspfPacketType::DatabaseDescription as u8
                            || k == OspfPacketType::LinkStateRequest as u8
                    );
                    let dst = match (conversational, peer_ll) {
                        (true, Some(ll)) => ll,
                        _ => MULTICAST_ALL_SPF,
                    };
                    outbound.push((n.ifindex, dst, stream[off..off + len].to_vec()));
                    off += len;
                }
            }
            for anchor in self.anchors.values() {
                let _ = router.drain_output(*anchor);
            }
        }
        for (interface_id, dst, mut bytes) in outbound {
            let Some(iface) = self
                .interfaces
                .iter_mut()
                .find(|i| i.interface_id == interface_id)
            else {
                continue;
            };
            finalize_v3_packet(&mut bytes, &iface.link_local.octets(), &dst);
            dbg_send_trace(&bytes);
            if dst == MULTICAST_ALL_SPF {
                if let Err(e) = iface.transport.send_multicast(&bytes) {
                    eprintln!("daemon: ospf3 send {}: {}", iface.name, e);
                }
            } else if let Err(e) = iface.transport.send_unicast(Ipv6Addr::from(dst), &bytes) {
                eprintln!(
                    "daemon: ospf3 send {} unicast {}: {}",
                    iface.name,
                    Ipv6Addr::from(dst),
                    e
                );
            }
        }
    }

    /// Originate the area's self-described LSAs and feed them to the
    /// anchor session so the router floods them to every neighbor:
    /// the Router-LSA (one p2p link per Full adjacency), a Link-LSA
    /// per interface (the §4.4.3.4 MUST) and one Intra-Area-Prefix-LSA
    /// carrying the global prefixes attached to the Router-LSA.
    fn reoriginate_area(&mut self, router: &mut DefaultRouter, area: u32, now_ms: u64) {
        let mut lsas: Vec<lr_ospf::lsa::Lsa> = Vec::new();
        // Per-interface Link-LSAs (always) and p2p links (Full only).
        for iface in &self.interfaces {
            if iface.area != area {
                continue;
            }
            let prefixes: Vec<V3Prefix> = iface
                .prefixes
                .iter()
                .map(|(addr, len)| {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&addr.octets());
                    V3Prefix {
                        prefix_len: *len,
                        options: 0,
                        metric: 0,
                        addr: octets,
                    }
                })
                .collect();
            let key = (area, iface.interface_id);
            let link_lsa_type = if self.extended_lsas {
                LS_TYPE_E_LINK
            } else {
                LS_TYPE_LINK
            };
            let seq = lsa_seq_floor(
                router,
                area,
                link_lsa_type,
                iface.interface_id,
                self.router_id.as_u32(),
                self.link_lsa_seq.get(&key).copied(),
            );
            let originated = if self.extended_lsas {
                originate_v3_e_link_lsa(
                    self.router_id.as_u32(),
                    iface.interface_id,
                    1,
                    OSPF_V3_OPTIONS_DEFAULT,
                    iface.link_local.octets(),
                    e_prefix_tlvs(prefixes),
                    seq,
                )
            } else {
                originate_v3_link_lsa(
                    self.router_id.as_u32(),
                    iface.interface_id,
                    1,
                    OSPF_V3_OPTIONS_DEFAULT,
                    iface.link_local.octets(),
                    prefixes,
                    seq,
                )
            };
            match originated {
                Some(lsa) => {
                    self.link_lsa_seq.insert(key, lsa.header.ls_sequence_number);
                    lsas.push(lsa);
                }
                None => eprintln!(
                    "daemon: ospf3 link-LSA sequence space exhausted on {}",
                    iface.name
                ),
            }
        }
        // Router-LSA links + the broadcast segment LSA set (§4.4.3.2
        // transit links, §4.4.3.3 Network-LSA, §4.4.3.5 network IAP).
        let mut links: Vec<lr_ospf::lsa::v3::V3RouterLink> = Vec::new();
        // Interfaces described as transit links: their global prefixes
        // ride the DR's network-referenced Intra-Area-Prefix-LSA, not
        // our router-referenced one (§4.4.3.5).
        let mut transit_reported: BTreeMap<u32, ()> = BTreeMap::new();
        // The Full neighbor set per interface — the RFC 9513 §9.2 LAN
        // End.X inputs below need it alongside the link builder.
        let mut established_by_if: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for iface in &mut self.interfaces {
            if iface.area != area {
                continue;
            }
            let established: Vec<u32> = self
                .neighbors
                .iter()
                .filter(|((n_area, _rid), n)| {
                    *n_area == area && n.ifindex == iface.interface_id && n.established
                })
                .map(|(&(_, rid), _)| rid)
                .collect();
            established_by_if.insert(iface.interface_id, established.clone());
            match iface.network_type {
                OspfNetworkType::PointToPoint => {
                    for rid in &established {
                        let neighbor_interface_id =
                            iface.heard.get(rid).map(|h| h.interface_id).unwrap_or(0);
                        links.push(lr_ospf::lsa::v3::V3RouterLink {
                            link_type: LINK_TYPE_POINTTOPOINT,
                            metric: iface.cost,
                            interface_id: iface.interface_id,
                            neighbor_interface_id,
                            neighbor_router_id: *rid,
                        });
                    }
                }
                OspfNetworkType::Broadcast => {
                    // FRR ospf6d `ospf6_router_lsa_originate` parity: a
                    // broadcast interface is described only as a
                    // transit link, and only when this router is the
                    // DR with at least one Full adjacency, or is fully
                    // adjacent with the elected DR. Otherwise the
                    // interface is not transit yet and stays out of
                    // the Router-LSA (adjacencies cannot form before a
                    // DR exists — §10.4 gates on the elected pair).
                    let we_are_dr =
                        iface.if_state == IfState::Dr && iface.dr == self.router_id.as_u32();
                    let dr_reachable = !we_are_dr
                        && iface.dr != 0
                        && established.contains(&iface.dr)
                        && iface.heard.get(&iface.dr).map(|h| h.interface_id).is_some();
                    let describe = (we_are_dr && !established.is_empty()) || dr_reachable;
                    if describe {
                        let (neighbor_interface_id, neighbor_router_id) = if we_are_dr {
                            // The DR describes itself: the network vertex's
                            // neighbor fields are its own (FRR keeps the
                            // self-referential shape, §A.4.3 type 2).
                            (iface.interface_id, self.router_id.as_u32())
                        } else {
                            (
                                iface
                                    .heard
                                    .get(&iface.dr)
                                    .map(|h| h.interface_id)
                                    .unwrap_or(0),
                                iface.dr,
                            )
                        };
                        links.push(lr_ospf::lsa::v3::V3RouterLink {
                            link_type: LINK_TYPE_TRANSIT,
                            metric: iface.cost,
                            interface_id: iface.interface_id,
                            neighbor_interface_id,
                            neighbor_router_id,
                        });
                        transit_reported.insert(iface.interface_id, ());
                    }
                    // §4.4.3.3: as the DR with at least one Full
                    // adjacency, originate the Network-LSA listing
                    // every fully adjacent router (ourselves included)
                    // with the Options OR'd from the fully adjacent
                    // neighbors' Link-LSAs. Anything else flushes the
                    // instance we may still hold (§14.1 MaxAge).
                    if we_are_dr && !established.is_empty() {
                        let mut options = OSPF_V3_OPTIONS_DEFAULT;
                        for rid in &established {
                            let Some(h) = iface.heard.get(rid) else {
                                continue;
                            };
                            if let Some(llsa) =
                                router.ospf_area_lsa(area, LS_TYPE_LINK, h.interface_id, *rid)
                            {
                                if let Some(body) = V3LinkLsaBody::decode(&llsa.body) {
                                    options |= body.options;
                                }
                            }
                        }
                        let mut attached = vec![self.router_id.as_u32()];
                        attached.extend_from_slice(&established);
                        let net_lsa_type = if self.extended_lsas {
                            LS_TYPE_E_NETWORK
                        } else {
                            LS_TYPE_NETWORK
                        };
                        let net_seq = lsa_seq_floor(
                            router,
                            area,
                            net_lsa_type,
                            iface.interface_id,
                            self.router_id.as_u32(),
                            iface.net_lsa_seq,
                        );
                        let net_originated = if self.extended_lsas {
                            originate_v3_e_network_lsa(
                                self.router_id.as_u32(),
                                iface.interface_id,
                                options,
                                &attached,
                                net_seq,
                            )
                        } else {
                            originate_v3_network_lsa(
                                self.router_id.as_u32(),
                                iface.interface_id,
                                options,
                                &attached,
                                net_seq,
                            )
                        };
                        match net_originated {
                            Some(lsa) => {
                                iface.net_lsa_seq = Some(lsa.header.ls_sequence_number);
                                iface.net_lsa_active = true;
                                lsas.push(lsa);
                            }
                            None => eprintln!(
                                "daemon: ospf3 network-LSA sequence space exhausted on {}",
                                iface.name
                            ),
                        }
                    } else if iface.net_lsa_active {
                        // A former DR flushes the Network-LSA it
                        // originated (§14.1 MaxAge reflood, the v2
                        // daemon pattern).
                        if let Some(seq) = iface.net_lsa_seq {
                            let flushed = if self.extended_lsas {
                                originate_v3_e_network_lsa(
                                    self.router_id.as_u32(),
                                    iface.interface_id,
                                    OSPF_V3_OPTIONS_DEFAULT,
                                    &[self.router_id.as_u32()],
                                    Some(seq),
                                )
                            } else {
                                originate_v3_network_lsa(
                                    self.router_id.as_u32(),
                                    iface.interface_id,
                                    OSPF_V3_OPTIONS_DEFAULT,
                                    &[self.router_id.as_u32()],
                                    Some(seq),
                                )
                            };
                            if let Some(mut lsa) = flushed {
                                lsa.header.ls_age = lr_ospf::lsdb::MAX_AGE_SECS;
                                lsa.finalize();
                                lsas.push(lsa);
                            }
                        }
                        iface.net_lsa_active = false;
                        iface.net_lsa_seq = None;
                    }
                }
            }
        }
        // RFC 5340 §4.8: a router is V6-capable; E (ASBR) follows the
        // actual redistribution state — FRR `ospf6_router_lsa_originate`
        // sets it from IS_OSPF_ASBR, BIRD from `p->asbr`. Claiming it
        // unconditionally makes peers track a phantom ASBR; omitting it
        // while originating 0x4005s hides every external route (the
        // v2 wire form of this bug was caught by
        // tests/interop/redistribute_bird.sh). B (ABR) rides the same
        // word: more than one attached v3 area. Regular areas only in
        // slice 1 — the finalizer rejects stub/NSSA v3 areas via the
        // v2 policy path.
        let mut bits = ROUTER_BIT_V6;
        if router.ospf_is_asbr() {
            bits |= ROUTER_BIT_E;
        }
        if router.ospf_router_lsa_flags(area).border {
            bits |= ROUTER_BIT_B;
        }
        // RFC 9513 §9: the interface End.X SIDs ride the E-Router-LSA's
        // Router-Link TLV sub-TLVs — the §9.1 form on p2p links and on
        // the broadcast DR adjacency, the §9.2 LAN form per Full
        // BDR/DR-Other broadcast neighbor. In extended mode the
        // E-Router-LSA is the topology carrier; in legacy mode
        // (RFC 8362 §6.2 sparse-mode) a complete E-Router-LSA companion
        // carries them alongside the legacy topology — receivers
        // ignore it for the SPF but the SRv6 database still projects
        // the SIDs.
        let end_x_by_if: BTreeMap<u32, ([u8; 16], u8)> = self
            .interfaces
            .iter()
            .filter_map(|i| i.end_x_sid.map(|sid| (i.interface_id, sid)))
            .collect();
        let lan_end_x_by_if: BTreeMap<u32, LanEndXSpec> = self
            .interfaces
            .iter()
            .filter(|i| i.area == area && i.network_type == OspfNetworkType::Broadcast)
            .filter_map(|i| {
                let established = established_by_if.get(&i.interface_id)?;
                let we_are_dr = i.if_state == IfState::Dr && i.dr == self.router_id.as_u32();
                // §9.1 covers the DR adjacency: only a non-DR router
                // has one, and only once it is Full (the transit link
                // carrying it is described under the same conditions).
                let dr_sid = (!we_are_dr && i.dr != 0 && established.contains(&i.dr))
                    .then_some(i.end_x_sid)
                    .flatten();
                // §9.2 covers everyone else we are Full with — the
                // BDR and the DR-Others (as the DR: every neighbor).
                let neighbors: Vec<u32> = established
                    .iter()
                    .copied()
                    .filter(|rid| *rid != i.dr)
                    .collect();
                (dr_sid.is_some() || (i.end_x_lan.is_some() && !neighbors.is_empty())).then_some((
                    i.interface_id,
                    LanEndXSpec {
                        dr_sid,
                        base: i.end_x_lan,
                        neighbors,
                    },
                ))
            })
            .collect();
        let router_lsa_type = if self.extended_lsas {
            LS_TYPE_E_ROUTER
        } else {
            LS_TYPE_ROUTER
        };
        let seq = lsa_seq_floor(
            router,
            area,
            router_lsa_type,
            0,
            self.router_id.as_u32(),
            self.router_lsa_seq.get(&area).copied(),
        );
        let router_originated = if self.extended_lsas {
            originate_v3_e_router_lsa(
                self.router_id.as_u32(),
                bits,
                OSPF_V3_OPTIONS_DEFAULT,
                e_router_links(&links, &end_x_by_if, &lan_end_x_by_if),
                seq,
            )
        } else {
            originate_v3_router_lsa(
                self.router_id.as_u32(),
                bits,
                OSPF_V3_OPTIONS_DEFAULT,
                &links,
                seq,
            )
        };
        match router_originated {
            Some(lsa) => {
                self.router_lsa_seq
                    .insert(area, lsa.header.ls_sequence_number);
                // One Intra-Area-Prefix-LSA attaching every global
                // prefix to our Router-LSA (§4.4.3.5; skip when the
                // interfaces carry no global addresses). Interfaces
                // reported as transit links are skipped: their
                // prefixes ride the DR's network-referenced
                // Intra-Area-Prefix-LSA instead (§4.4.3.5 — "prefixes
                // that will be included in the intra-area-prefix-LSA
                // for the link are skipped").
                let mut prefixes: Vec<V3Prefix> = Vec::new();
                for iface in &self.interfaces {
                    if iface.area != area || transit_reported.contains_key(&iface.interface_id) {
                        continue;
                    }
                    for (addr, len) in &iface.prefixes {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&addr.octets());
                        prefixes.push(V3Prefix {
                            prefix_len: *len,
                            options: 0,
                            metric: 0,
                            addr: octets,
                        });
                    }
                }
                if !prefixes.is_empty() {
                    let iap_key = (area, 1u32);
                    let iap_lsa_type = if self.extended_lsas {
                        LS_TYPE_E_INTRA_PREFIX
                    } else {
                        LS_TYPE_INTRA_PREFIX
                    };
                    let iap_seq = lsa_seq_floor(
                        router,
                        area,
                        iap_lsa_type,
                        1,
                        self.router_id.as_u32(),
                        self.iap_lsa_seq.get(&iap_key).copied(),
                    );
                    let iap_originated = if self.extended_lsas {
                        originate_v3_e_intra_area_prefix_lsa(
                            self.router_id.as_u32(),
                            1,
                            LS_TYPE_E_ROUTER,
                            0,
                            self.router_id.as_u32(),
                            e_prefix_tlvs(prefixes),
                            iap_seq,
                        )
                    } else {
                        originate_v3_intra_area_prefix_lsa(
                            self.router_id.as_u32(),
                            1,
                            LS_TYPE_ROUTER,
                            0,
                            self.router_id.as_u32(),
                            prefixes,
                            iap_seq,
                        )
                    };
                    if let Some(iap) = iap_originated {
                        self.iap_lsa_seq
                            .insert(iap_key, iap.header.ls_sequence_number);
                        lsas.push(iap);
                    }
                }
                lsas.push(lsa);
            }
            None => {
                eprintln!(
                    "daemon: ospf3 router-LSA sequence space exhausted for area {}",
                    area_label(area)
                );
                return;
            }
        }
        // RFC 9513 §9 sparse-mode companion: with End.X SIDs configured
        // but extended mode off, the complete E-Router-LSA rides the
        // same LSU as the legacy topology — legacy receivers store and
        // re-flood it (U-bit) without using it for the SPF, and the
        // SRv6 database projects the adjacency SIDs from it.
        if !self.extended_lsas && (!end_x_by_if.is_empty() || !lan_end_x_by_if.is_empty()) {
            let e_seq = lsa_seq_floor(
                router,
                area,
                LS_TYPE_E_ROUTER,
                0,
                self.router_id.as_u32(),
                self.e_router_lsa_seq.get(&area).copied(),
            );
            match originate_v3_e_router_lsa(
                self.router_id.as_u32(),
                bits,
                OSPF_V3_OPTIONS_DEFAULT,
                e_router_links(&links, &end_x_by_if, &lan_end_x_by_if),
                e_seq,
            ) {
                Some(lsa) => {
                    self.e_router_lsa_seq
                        .insert(area, lsa.header.ls_sequence_number);
                    lsas.push(lsa);
                }
                None => eprintln!(
                    "daemon: ospf3 E-Router-LSA sequence space exhausted for area {}",
                    area_label(area)
                ),
            }
        }
        // §4.4.3.5, the DR half: on every broadcast segment where this
        // router is the DR, originate the network-referenced
        // Intra-Area-Prefix-LSA carrying the segment's prefixes — the
        // union of the Link-LSA prefixes of every fully adjacent
        // neighbor (ourselves included), NU/LA-marked prefixes and
        // link-locals excluded, duplicates merged with their options
        // OR'd together. A former DR flushes its instance.
        for iface in &mut self.interfaces {
            if iface.area != area || iface.network_type != OspfNetworkType::Broadcast {
                continue;
            }
            let we_are_dr = iface.if_state == IfState::Dr && iface.dr == self.router_id.as_u32();
            let has_full = self.neighbors.iter().any(|((n_area, _), n)| {
                *n_area == area && n.ifindex == iface.interface_id && n.established
            });
            if we_are_dr && has_full {
                // Dedup keyed (prefix length, address) → OR'd options
                // (§4.4.3.5). BTreeMap keeps the wire order stable.
                let mut merged: BTreeMap<(u8, [u8; 16]), u8> = BTreeMap::new();
                let mut collect = |prefixes: &[V3Prefix]| {
                    for p in prefixes {
                        // §A.4.1: NU- and LA-marked prefixes are not
                        // copied; link-locals are never advertised.
                        if p.options & (PREFIX_OPT_NU | PREFIX_OPT_LA) != 0 {
                            continue;
                        }
                        if p.addr[0] == 0xfe && (p.addr[1] & 0xc0) == 0x80 {
                            continue;
                        }
                        merged
                            .entry((p.prefix_len, p.addr))
                            .and_modify(|o| *o |= p.options)
                            .or_insert(p.options);
                    }
                };
                let mut own: Vec<V3Prefix> = Vec::new();
                for (addr, len) in &iface.prefixes {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&addr.octets());
                    own.push(V3Prefix {
                        prefix_len: *len,
                        options: 0,
                        metric: 0,
                        addr: octets,
                    });
                }
                collect(&own);
                for ((n_area, rid), n) in self.neighbors.iter() {
                    if *n_area != area || n.ifindex != iface.interface_id || !n.established {
                        continue;
                    }
                    let Some(h) = iface.heard.get(rid) else {
                        continue;
                    };
                    if let Some(llsa) =
                        router.ospf_area_lsa(area, LS_TYPE_LINK, h.interface_id, *rid)
                    {
                        if let Some(body) = V3LinkLsaBody::decode(&llsa.body) {
                            collect(&body.prefixes);
                        }
                    }
                }
                let prefixes: Vec<V3Prefix> = merged
                    .into_iter()
                    .map(|((prefix_len, addr), options)| V3Prefix {
                        prefix_len,
                        options,
                        metric: 0,
                        addr,
                    })
                    .collect();
                // Network-referenced IAPs use a distinct Link State ID
                // space from the router-referenced one (§4.4.3.5: "a
                // router may originate several Intra-Area-Prefix-LSAs
                // per area, disambiguated by the Link State ID"). The
                // ifindex with a marker bit keeps per-segment instances
                // apart from the router-referenced LS ID 1.
                let iap_key = (area, iface.interface_id | 1 << 31);
                let iap_lsa_type = if self.extended_lsas {
                    LS_TYPE_E_INTRA_PREFIX
                } else {
                    LS_TYPE_INTRA_PREFIX
                };
                let iap_seq = lsa_seq_floor(
                    router,
                    area,
                    iap_lsa_type,
                    iap_key.1,
                    self.router_id.as_u32(),
                    self.iap_lsa_seq.get(&iap_key).copied(),
                );
                let iap_originated = if self.extended_lsas {
                    originate_v3_e_intra_area_prefix_lsa(
                        self.router_id.as_u32(),
                        iap_key.1,
                        LS_TYPE_E_NETWORK,
                        iface.interface_id,
                        self.router_id.as_u32(),
                        e_prefix_tlvs(prefixes),
                        iap_seq,
                    )
                } else {
                    originate_v3_intra_area_prefix_lsa(
                        self.router_id.as_u32(),
                        iap_key.1,
                        LS_TYPE_NETWORK,
                        iface.interface_id,
                        self.router_id.as_u32(),
                        prefixes,
                        iap_seq,
                    )
                };
                if let Some(iap) = iap_originated {
                    self.iap_lsa_seq
                        .insert(iap_key, iap.header.ls_sequence_number);
                    iface.net_iap_seq = Some(iap.header.ls_sequence_number);
                    iface.net_iap_active = true;
                    lsas.push(iap);
                }
            } else if iface.net_iap_active {
                // No longer the DR (or no Full adjacency left): flush
                // the network-referenced IAP — the new DR advertises
                // the segment's prefixes (§4.4.3.5).
                if let Some(seq) = iface.net_iap_seq {
                    let flushed = if self.extended_lsas {
                        originate_v3_e_intra_area_prefix_lsa(
                            self.router_id.as_u32(),
                            iface.interface_id | 1 << 31,
                            LS_TYPE_E_NETWORK,
                            iface.interface_id,
                            self.router_id.as_u32(),
                            Vec::new(),
                            Some(seq),
                        )
                    } else {
                        originate_v3_intra_area_prefix_lsa(
                            self.router_id.as_u32(),
                            iface.interface_id | 1 << 31,
                            LS_TYPE_NETWORK,
                            iface.interface_id,
                            self.router_id.as_u32(),
                            Vec::new(),
                            Some(seq),
                        )
                    };
                    if let Some(mut lsa) = flushed {
                        lsa.header.ls_age = lr_ospf::lsdb::MAX_AGE_SECS;
                        lsa.finalize();
                        lsas.push(lsa);
                    }
                }
                iface.net_iap_active = false;
                iface.net_iap_seq = None;
            }
        }
        self.last_orig_ms.insert(area, now_ms);
        // RFC 9513 slice 3: the SRv6 Router Information LSA (§2-§4,
        // instance ID 0) and the Locator LSA (§7, all locators, Link
        // State ID 1) ride the same LSU as the topology LSAs, so a
        // locator change refreshes through the normal re-origination
        // and §14.1 cadences.
        if let Some(s) = &self.srv6 {
            let ri_seq = lsa_seq_floor(
                router,
                area,
                LS_TYPE_V3_ROUTER_INFORMATION,
                0,
                self.router_id.as_u32(),
                self.ri_lsa_seq.get(&area).copied(),
            );
            match originate_v3_srv6_ri_lsa(
                self.router_id.as_u32(),
                s.capabilities,
                &s.algorithms,
                &s.msds,
                ri_seq,
            ) {
                Some(ri) => {
                    self.ri_lsa_seq.insert(area, ri.header.ls_sequence_number);
                    lsas.push(ri);
                }
                None => eprintln!(
                    "daemon: ospf3 SRv6 RI-LSA sequence space exhausted for area {}",
                    area_label(area)
                ),
            }
            let loc_seq = lsa_seq_floor(
                router,
                area,
                LS_TYPE_SRV6_LOCATOR,
                1,
                self.router_id.as_u32(),
                self.srv6_lsa_seq.get(&area).copied(),
            );
            match originate_v3_srv6_locator_lsa(self.router_id.as_u32(), 1, &s.locators, loc_seq) {
                Some(loc_lsa) => {
                    self.srv6_lsa_seq
                        .insert(area, loc_lsa.header.ls_sequence_number);
                    lsas.push(loc_lsa);
                }
                None => eprintln!(
                    "daemon: ospf3 SRv6 Locator-LSA sequence space exhausted for area {}",
                    area_label(area)
                ),
            }
        }
        let Some(&anchor) = self.anchors.get(&area) else {
            return;
        };
        let packet = lr_ospf::packet::OspfPacket {
            header: lr_ospf::packet::OspfHeader {
                version: lr_ospf::packet::OspfVersion::V3 as u8,
                kind: OspfPacketType::LinkStateUpdate as u8,
                length: 0,
                router_id: self.router_id.as_u32(),
                area_id: area,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::LsUpdate(lr_ospf::packet::LsUpdateBody {
                lsa_count: lsas.len() as u32,
                lsas,
            }),
        };
        match OspfCodec::v3().encode_vec(&packet) {
            Ok(bytes) => {
                if let Err(e) = router.feed_input(anchor, &bytes) {
                    eprintln!("daemon: ospf3 self-origination feed: {e}");
                }
            }
            Err(e) => eprintln!("daemon: ospf3 self-origination encode: {e}"),
        }
    }
}

/// The multicast destination every v3 packet uses (slice 1 floods and
/// Hellos are multicast-only): ff02::5, AllSPFRouters.
use lr_osroute::ospf_transport::ALL_SPF_ROUTERS_V6 as MULTICAST_ALL_SPF;

/// The cached `LR_OSPF_DEBUG` gate for the wire trace.
fn ospf_debug_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("LR_OSPF_DEBUG").is_some())
}

/// Decode a received OSPFv3 Hello body (§A.3.2). Returns `None` for
/// short, non-v3 or non-Hello packets.
fn parse_hello_body_v3(bytes: &[u8]) -> Option<HelloBody> {
    match OspfCodec::v3().decode_slice(bytes).ok()?? {
        lr_ospf::packet::OspfPacket {
            body: OspfBody::Hello(body),
            ..
        } => Some(body),
        _ => None,
    }
}

/// Parse the fixed 16-byte v3 header for demux: (router-id, area, length).
fn demux_header(bytes: &[u8]) -> Option<(u32, u32, u16)> {
    if bytes.len() < lr_ospf::packet::OspfHeader::LEN_V3 {
        return None;
    }
    if bytes[0] != 3 {
        return None; // only v3 on the v6 transport
    }
    let len = u16::from_be_bytes([bytes[2], bytes[3]]);
    if bytes.len() < usize::from(len) {
        return None;
    }
    Some((
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        len,
    ))
}

fn fmt_rid(rid: u32) -> String {
    RouterId::from_u32(rid).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_config::{DaemonConfig, OspfSrv6LocatorSpec};

    fn locator_spec(prefix: &str) -> OspfSrv6LocatorSpec {
        OspfSrv6LocatorSpec {
            prefix: Some(prefix.to_string()),
            ..Default::default()
        }
    }

    fn v6_octets(text: &str) -> [u8; 16] {
        match text.parse::<IpAddr>().expect("valid v6") {
            IpAddr::V6(o) => o,
            _ => panic!("not v6"),
        }
    }

    #[test]
    fn srv6_off_without_locators() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        cfg.ospf_srv6_receive = true;
        // Reception alone does not turn origination on: the daemon
        // carries SRv6 state only when locators are configured.
        assert!(Srv6Origination::maybe_from_config(&cfg).is_none());
        cfg.ospf_srv6_locators = vec![locator_spec("2001:db8:a:1::/48")];
        assert!(Srv6Origination::maybe_from_config(&cfg).is_some());
    }

    #[test]
    fn srv6_origination_defaults() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        cfg.ospf_srv6_locators = vec![locator_spec("2001:db8:a:1::/48")];
        let s = Srv6Origination::from_config(&cfg);
        // No O-flag by default; algorithm 0 derived from the locator.
        assert_eq!(s.capabilities, 0);
        assert_eq!(s.algorithms, vec![0]);
        assert!(s.msds.is_empty());
        assert_eq!(s.locators.len(), 1);
        let loc = &s.locators[0];
        assert_eq!(loc.route_type, locator_route_type::INTRA_AREA);
        assert_eq!(loc.algorithm, 0);
        assert_eq!(loc.locator_len, 48);
        assert_eq!(loc.options, 0);
        assert_eq!(loc.metric, 0);
        assert_eq!(loc.prefix, v6_octets("2001:db8:a:1::"));
        // The End SID defaults to the locator prefix, behavior End,
        // no SID Structure sub-TLV.
        assert_eq!(loc.end_sids.len(), 1);
        let sid = &loc.end_sids[0];
        assert_eq!(sid.behavior, 1);
        assert_eq!(sid.sid, v6_octets("2001:db8:a:1::"));
        assert!(sid.structure.is_none());
        // The encoded TLV round-trips through the slice-2 decoder.
        let mut wire = Vec::new();
        loc.encode(&mut wire);
        let (decoded, _) = Srv6LocatorTlv::decode(&wire, 0).expect("decodable");
        assert_eq!(&decoded, loc);
    }

    #[test]
    fn srv6_origination_full_attributes() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.protocol = "ospf".to_string();
        cfg.ospf_srv6_o_flag = true;
        cfg.ospf_srv6_max_sl = Some(8);
        cfg.ospf_srv6_max_end_d = Some(6);
        cfg.ospf_srv6_locators = vec![
            OspfSrv6LocatorSpec {
                prefix: Some("2001:db8:a:1::/64".to_string()),
                algorithm: Some(128), // flexible-algorithm space
                metric: Some(30),
                anycast: Some(true),
                sid: Some("2001:db8:a:1:f00d::".to_string()),
                behavior: Some(1),
                block_len: Some(32),
                node_len: Some(16),
                function_len: Some(16),
                argument_len: Some(0),
            },
            locator_spec("2001:db8:a:2::/64"),
        ];
        let s = Srv6Origination::from_config(&cfg);
        assert_eq!(s.capabilities, SRV6_CAP_O_FLAG);
        // Distinct algorithms, ascending (BTreeSet order).
        assert_eq!(s.algorithms, vec![0, 128]);
        // MSD pairs in the 41/42/44/45 wire order, only the configured ones.
        assert_eq!(
            s.msds,
            vec![(msd_type::SRH_MAX_SL, 8), (msd_type::SRH_MAX_END_D, 6)]
        );
        assert_eq!(s.locators.len(), 2);
        let first = &s.locators[0];
        assert_eq!(first.options, PREFIX_OPT_AC);
        assert_eq!(first.metric, 30);
        assert_eq!(first.end_sids[0].sid, v6_octets("2001:db8:a:1:f00d::"));
        assert_eq!(
            first.end_sids[0].structure,
            Some(Srv6SidStructure {
                lb_len: 32,
                ln_len: 16,
                func_len: 16,
                arg_len: 0,
            })
        );
        // The full TLV round-trips through the slice-2 decoder.
        let mut wire = Vec::new();
        first.encode(&mut wire);
        let (decoded, _) = Srv6LocatorTlv::decode(&wire, 0).expect("decodable");
        assert_eq!(&decoded, first);
    }

    #[test]
    fn lan_end_x_base_masks_host_bits() {
        // /96: the low 32 bits clear — the Router-ID argument slot.
        assert_eq!(
            mask_lan_base("2001:db8:a:1:ffff:ffff:ffff:ffff/96", &[])
                .unwrap()
                .0,
            v6_octets("2001:db8:a:1:ffff:ffff::")
        );
        // /64: everything below the prefix clears.
        assert_eq!(
            mask_lan_base("2001:db8:a:1:dead:beef::1/64", &[])
                .unwrap()
                .0,
            v6_octets("2001:db8:a:1::")
        );
        // A non-byte-aligned length keeps the partial octet's high
        // bits (100 = 12 bytes + 4 bits: 0xff & 0xf0 = 0xf0).
        assert_eq!(
            mask_lan_base("2001:db8:a:1:0:0:ffff:ffff/100", &[])
                .unwrap()
                .0,
            v6_octets("2001:db8:a:1::f000:0")
        );
        // The covering locator's algorithm rides along (algorithm 128
        // on the covering locator, 0 default on the other).
        let locators = vec![
            locator_spec("2001:db8:a:1::/48"),
            OspfSrv6LocatorSpec {
                prefix: Some("2001:db8:b::/48".to_string()),
                algorithm: Some(128),
                ..Default::default()
            },
        ];
        assert_eq!(
            mask_lan_base("2001:db8:b:ffff::/96", &locators).unwrap().1,
            128
        );
        assert_eq!(
            mask_lan_base("2001:db8:a:1:ffff::/96", &locators)
                .unwrap()
                .1,
            0
        );
    }

    #[test]
    fn e_router_links_broadcast_carries_9_1_and_9_2() {
        // A BDR's transit link (§A.4.3 type 2): Full with the DR
        // 3.3.3.3 and the DR-Others 4.4.4.4 + 5.5.5.5. RFC 9513 §9:
        // the plain End.X (§9.1) covers the DR adjacency, one LAN
        // End.X (§9.2) per DR-Other, all riding the same link.
        let links = vec![lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_TRANSIT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 77,
            neighbor_router_id: 0x0303_0303, // the DR
        }];
        let end_x_by_if = BTreeMap::new();
        let mut lan_end_x_by_if = BTreeMap::new();
        lan_end_x_by_if.insert(
            5u32,
            LanEndXSpec {
                dr_sid: Some((v6_octets("2001:db8:a:1::100"), 0)),
                base: Some((v6_octets("2001:db8:a:1:ffff::"), 0)),
                neighbors: vec![0x0404_0404, 0x0505_0505],
            },
        );
        let out = e_router_links(&links, &end_x_by_if, &lan_end_x_by_if);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].link_type, LINK_TYPE_TRANSIT);
        // §9.1: one plain End.X, the configured SID verbatim.
        let plain = lr_ospf::lsa::srv6::walk_end_x_sub_tlvs(&out[0].sub_tlvs);
        assert_eq!(plain.len(), 1);
        assert_eq!(plain[0].sid, v6_octets("2001:db8:a:1::100"));
        assert_eq!(plain[0].behavior, 5); // End.X (RFC 8986)
        assert_eq!(plain[0].algorithm, 0);
        assert_eq!(plain[0].flags, 0);
        // §9.2: one LAN End.X per neighbor, the SID derived as
        // base | Router-ID (the RID fills the low 32 bits).
        let lan = lr_ospf::lsa::srv6::walk_lan_end_x_sub_tlvs(&out[0].sub_tlvs);
        assert_eq!(lan.len(), 2);
        assert_eq!(lan[0].neighbor_router_id, 0x0404_0404);
        assert_eq!(lan[0].sid, v6_octets("2001:db8:a:1:ffff::404:404"));
        assert_eq!(lan[0].behavior, 5);
        assert_eq!(lan[1].neighbor_router_id, 0x0505_0505);
        assert_eq!(lan[1].sid, v6_octets("2001:db8:a:1:ffff::505:505"));
        // The §9.1 sub-TLV precedes the §9.2 instances on the wire
        // (type 31 before 32 in emission order; the §9.1 instance is
        // 4 + 24 = 28 octets, 4-aligned, so the LAN form starts at
        // 28).
        let t = u16::from_be_bytes([out[0].sub_tlvs[0], out[0].sub_tlvs[1]]);
        assert_eq!(t, lr_ospf::lsa::srv6::EXT_SUBTLV_END_X_SID);
        let t2 = u16::from_be_bytes([out[0].sub_tlvs[28], out[0].sub_tlvs[29]]);
        assert_eq!(t2, lr_ospf::lsa::srv6::EXT_SUBTLV_LAN_END_X_SID);
    }

    #[test]
    fn e_router_links_dr_has_no_9_1_dr_adjacency() {
        // The DR describes itself (§A.4.3 self-referential shape): it
        // has no adjacency to a DR, so no §9.1 sub-TLV — only the
        // §9.2 LAN End.X per Full neighbor (BDR + DR-Others).
        let links = vec![lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_TRANSIT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 5,
            neighbor_router_id: 0x0303_0303, // ourselves
        }];
        let end_x_by_if = BTreeMap::new();
        let mut lan_end_x_by_if = BTreeMap::new();
        lan_end_x_by_if.insert(
            5u32,
            LanEndXSpec {
                dr_sid: None,
                base: Some((v6_octets("2001:db8:a:1:ffff::"), 0)),
                neighbors: vec![0x0202_0202, 0x0404_0404],
            },
        );
        let out = e_router_links(&links, &end_x_by_if, &lan_end_x_by_if);
        assert!(lr_ospf::lsa::srv6::walk_end_x_sub_tlvs(&out[0].sub_tlvs).is_empty());
        let lan = lr_ospf::lsa::srv6::walk_lan_end_x_sub_tlvs(&out[0].sub_tlvs);
        assert_eq!(lan.len(), 2);
        assert_eq!(lan[0].neighbor_router_id, 0x0202_0202);
        assert_eq!(lan[0].sid, v6_octets("2001:db8:a:1:ffff::202:202"));
    }

    #[test]
    fn e_router_links_p2p_keeps_the_plain_form() {
        // A p2p link (§A.4.3 type 1) with the §9.1 SID configured:
        // exactly one plain End.X, no LAN forms.
        let links = vec![lr_ospf::lsa::v3::V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 77,
            neighbor_router_id: 0x0202_0202,
        }];
        let mut end_x_by_if = BTreeMap::new();
        end_x_by_if.insert(5u32, (v6_octets("2001:db8:a:1::100"), 0));
        let out = e_router_links(&links, &end_x_by_if, &BTreeMap::new());
        let plain = lr_ospf::lsa::srv6::walk_end_x_sub_tlvs(&out[0].sub_tlvs);
        assert_eq!(plain.len(), 1);
        assert_eq!(plain[0].sid, v6_octets("2001:db8:a:1::100"));
        assert!(lr_ospf::lsa::srv6::walk_lan_end_x_sub_tlvs(&out[0].sub_tlvs).is_empty());
    }
}
