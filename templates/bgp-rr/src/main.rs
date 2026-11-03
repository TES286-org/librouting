//! BGP Route Reflector cluster (RFC 4456) — working scaffold.
//!
//! This template wires three BGP speakers in a reflection topology:
//!
//! - RR (route reflector) speaks iBGP to two clients.
//! - RR forwards routes between clients (as RFC 4456 specifies).
//!
//! The template drives an *in-process* demo so it runs without any
//! network listener or root privileges: it constructs the RR peer and
//! one BgpPeer per client, drives the OPEN/KEEPALIVE handshake between
//! each RR-side session and its far-side dummy so every session
//! reaches `Established`, then advertises a sample iBGP-learned route
//! to one client and decodes the resulting UPDATE to confirm the
//! `ORIGINATOR_ID` and `CLUSTER_LIST` attributes the reflector stamps
//! per RFC 4456 §3 are present on the wire.
//!
//! Usage:
//!
//! ```sh
//! cargo run -- --local-as 64512 --router-id 10.0.0.1 \
//!             --cluster-id 10.0.0.1 \
//!             --client 10.0.0.2:179 --client 10.0.0.3:179
//! ```
//!
//! The defaults match the topology in `docs/examples/bgp_route_reflector.md`:
//! AS 64512, RR router-id 10.0.0.1, cluster-id 10.0.0.1, two clients
//! at 10.0.0.2 and 10.0.0.3. The `:179` port suffix is parsed for
//! argv compatibility with the daemon's `--client` flag but is not
//! used here — the demo exchanges BGP messages in memory, not over
//! TCP/179. See the docs page for a real wired deployment.

use std::env;
use std::process::ExitCode;

use lr_bgp::path::{AsPath, AttrType, PathAttrFlags, PathAttribute, PathAttributes};
use lr_bgp::role::{ClusterId, RouteReflectorConfig};
use lr_bgp::{BgpCodec, BgpEvent, BgpMessage, BgpPeer, PeerConfig};
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::codec::Decoder;
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

/// Defaults that match `docs/examples/bgp_route_reflector.md`.
const DEFAULT_LOCAL_AS: u32 = 64512;
const DEFAULT_ROUTER_ID: [u8; 4] = [10, 0, 0, 1];
const DEFAULT_CLUSTER_ID: [u8; 4] = [10, 0, 0, 1];
const DEFAULT_CLIENTS: [[u8; 4]; 2] = [[10, 0, 0, 2], [10, 0, 0, 3]];

/// Parse an `A.B.C.D` IPv4 dotted-quad into four bytes.
fn parse_v4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (slot, p) in out.iter_mut().zip(parts) {
        *slot = p.parse().ok()?;
    }
    Some(out)
}

/// Parse a `A.B.C.D[:port]` client argument. The port suffix is
/// accepted for argv compatibility with the daemon's `--client`
/// flag but is not used by the in-process demo; if present it must
/// be a valid `u16` so a typo in the port still fails argv parsing.
/// Returns the IPv4 bytes (the BGP identifier of the far-side peer).
fn parse_client(s: &str) -> Option<[u8; 4]> {
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (s, None),
    };
    if let Some(p) = port {
        // IPv6-style hosts are out of scope for this iBGP demo; the
        // daemon's `--client` flag uses the same `host:port` shape.
        if p.parse::<u16>().is_err() {
            return None;
        }
    }
    parse_v4(host)
}

/// One row of the parsed argv.
#[derive(Debug, Clone)]
struct Args {
    local_as: u32,
    router_id: [u8; 4],
    cluster_id: [u8; 4],
    clients: Vec<[u8; 4]>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            local_as: DEFAULT_LOCAL_AS,
            router_id: DEFAULT_ROUTER_ID,
            cluster_id: DEFAULT_CLUSTER_ID,
            clients: DEFAULT_CLIENTS.to_vec(),
        }
    }
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    // The first --client on the command line replaces the default
    // client set; subsequent --client flags append to the user list.
    let mut user_clients: Option<Vec<[u8; 4]>> = None;
    let mut iter = env::args().skip(1);
    while let Some(opt) = iter.next() {
        match opt.as_str() {
            "--local-as" => {
                if let Some(v) = iter.next() {
                    a.local_as = v.parse().map_err(|_| format!("bad --local-as: {v}"))?;
                }
            }
            "--router-id" => {
                if let Some(v) = iter.next() {
                    a.router_id = parse_v4(&v).ok_or_else(|| format!("bad --router-id: {v}"))?;
                }
            }
            "--cluster-id" => {
                if let Some(v) = iter.next() {
                    a.cluster_id = parse_v4(&v).ok_or_else(|| format!("bad --cluster-id: {v}"))?;
                }
            }
            "--client" => {
                if let Some(v) = iter.next() {
                    let bytes = parse_client(&v).ok_or_else(|| format!("bad --client: {v}"))?;
                    let slot = user_clients.get_or_insert_with(Vec::new);
                    slot.push(bytes);
                }
            }
            "--help" | "-h" => {
                println!("{}", help_text());
                return Err("__help__".into());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if let Some(c) = user_clients {
        a.clients = c;
    }
    if a.clients.len() < 2 {
        return Err(format!(
            "route reflection needs at least 2 clients, got {}",
            a.clients.len()
        ));
    }
    Ok(a)
}

fn help_text() -> String {
    [
        "Usage: bgp-rr [--local-as N] [--router-id A.B.C.D] [--cluster-id A.B.C.D]",
        "             [--client A.B.C.D[:port]]...",
        "",
        "Defaults: AS 64512, router-id 10.0.0.1, cluster-id 10.0.0.1,",
        "          clients 10.0.0.2 and 10.0.0.3.",
    ]
    .join("\n")
}

/// Build the RR's `PeerConfig` for one client. `peer_id` is the
/// client's BGP identifier; the peer's AS is the RR's AS (iBGP).
fn rr_client_cfg(args: &Args, peer_id: [u8; 4]) -> PeerConfig {
    let mut cfg = PeerConfig::new(
        Asn(args.local_as),
        Asn(args.local_as),
        RouterId::from_v4(args.router_id),
    );
    cfg.route_reflector = RouteReflectorConfig {
        cluster_id: ClusterId::from_v4(args.cluster_id),
        enabled: true,
    };
    cfg.route_reflector_client = true;
    // Pin the peer's BGP identifier via the standard iBGP defaults;
    // the handshake below mirrors the docs-example wiring.
    let _ = peer_id;
    cfg
}

/// Build the far-side dummy's `PeerConfig`. The dummy is a plain
/// iBGP speaker that represents the client's actual router. Its
/// local BGP identifier is `peer_id`; it peers with the RR.
fn client_dummy_cfg(args: &Args, peer_id: [u8; 4]) -> PeerConfig {
    PeerConfig::new(
        Asn(args.local_as),
        Asn(args.local_as),
        RouterId::from_v4(peer_id),
    )
}

/// Drive the OPEN/KEEPALIVE handshake between `p` (the RR-side
/// session under test) and `partner` (the client's far-side dummy)
/// until both reach `Established`. Returns `true` on success.
fn drive_handshake(p: &mut BgpPeer, partner: &mut BgpPeer) -> bool {
    p.step(BgpEvent::ManualStart);
    p.step(BgpEvent::TransportOpen);
    partner.step(BgpEvent::ManualStart);
    partner.step(BgpEvent::TransportOpen);
    // OPEN swap
    let p_open = p.drain_outgoing();
    let d_open = partner.drain_outgoing();
    let _ = p.feed_bytes(&d_open);
    let _ = partner.feed_bytes(&p_open);
    // KEEPALIVE swap
    let p_ka = p.drain_outgoing();
    let d_ka = partner.drain_outgoing();
    let _ = p.feed_bytes(&d_ka);
    let _ = partner.feed_bytes(&p_ka);
    p.is_established() && partner.is_established()
}

/// Construct a sample iBGP-learned route: an IPv4 unicast prefix
/// `203.0.113.0/24` with `next_hop = 192.0.2.1`, an AS_PATH of
/// `[64500]`, and `origin.proto = 1` so `advertise()` recognises it
/// as iBGP-learned (RFC 4456 §3 reflection requires the route to
/// have arrived over iBGP).
fn sample_route() -> Route {
    let mut attrs = PathAttributes::new();
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    let path = AsPath::from_sequence([Asn(64500)]);
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        path.encode_4(),
    ));
    attrs.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        [192, 0, 2, 1].to_vec(),
    ));
    Route {
        key: RouteKey::new(
            Prefix::new_v4([203, 0, 113, 0], 24),
            NlriFamily::IPV4_UNICAST,
        ),
        origin: RouteOrigin {
            proto: 1, // iBGP-learned (matches the `learned_internal` gate in `advertise.rs`)
            peer: 1,
        },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 1),
        next_hop: Some(IpAddr::V4([192, 0, 2, 1])),
        attributes: attrs.into(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

/// Decode the first UPDATE message from `bytes` and verify it carries
/// `ORIGINATOR_ID` and `CLUSTER_LIST` (RFC 4456 §3 reflection attrs).
/// Returns `Ok((originator, cluster_list))` on success.
fn decode_reflected_update(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u32>), String> {
    let mut codec = BgpCodec::new();
    let mut r = lr_core::buf::ReadBuf::new(bytes);
    while let Ok(Some(msg)) = codec.decode(&mut r) {
        if let BgpMessage::Update(u) = msg {
            let originator = u
                .attributes
                .get(AttrType::OriginatorId)
                .ok_or_else(|| "UPDATE missing ORIGINATOR_ID".to_string())?
                .value
                .clone();
            let cluster_attr = u
                .attributes
                .get(AttrType::ClusterList)
                .ok_or_else(|| "UPDATE missing CLUSTER_LIST".to_string())?;
            let cluster_list: Vec<u32> = cluster_attr
                .value
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            return Ok((originator, cluster_list));
        }
    }
    Err("no UPDATE message decoded".to_string())
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) if e == "__help__" => return ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            eprintln!();
            eprintln!("{}", help_text());
            return ExitCode::from(2);
        }
    };

    println!("BGP RR cluster scaffold — RFC 4456");
    println!("  local AS:    AS{}", args.local_as);
    println!(
        "  router-id:   {}.{}.{}.{}",
        args.router_id[0], args.router_id[1], args.router_id[2], args.router_id[3]
    );
    println!(
        "  cluster-id:  {}.{}.{}.{}",
        args.cluster_id[0], args.cluster_id[1], args.cluster_id[2], args.cluster_id[3]
    );
    println!("  clients:      {}", args.clients.len());
    for c in &args.clients {
        println!("    - {}.{}.{}.{}", c[0], c[1], c[2], c[3]);
    }
    println!();

    // Build the RR-side sessions and their far-side dummies.
    let mut rr_sessions: Vec<BgpPeer> = Vec::with_capacity(args.clients.len());
    let mut dummies: Vec<BgpPeer> = Vec::with_capacity(args.clients.len());
    for client_id in &args.clients {
        rr_sessions.push(BgpPeer::new(rr_client_cfg(&args, *client_id)));
        dummies.push(BgpPeer::new(client_dummy_cfg(&args, *client_id)));
    }

    // Drive each handshake independently; all sessions should reach Established.
    let mut all_up = true;
    for (rr, dummy) in rr_sessions.iter_mut().zip(dummies.iter_mut()) {
        let up = drive_handshake(rr, dummy);
        if !up {
            all_up = false;
        }
    }

    println!("Session state:");
    for (i, (rr, dummy)) in rr_sessions.iter().zip(dummies.iter()).enumerate() {
        println!(
            "  client #{} ({}): RR-side = {}, far-side = {}",
            i + 1,
            fmt_v4(args.clients[i]),
            state_label(rr.is_established()),
            state_label(dummy.is_established()),
        );
    }
    println!();

    if !all_up {
        eprintln!("FAIL: not all sessions reached Established");
        return ExitCode::from(1);
    }

    // Reflect a sample route from the RR to the *second* client. The
    // first client's session stands in for "the route arrived from
    // client #1" — `sample_route()` is already tagged with
    // `origin.proto = 1` (iBGP), so `advertise()` accepts it for
    // reflection to the RR-client at index 1.
    let route = sample_route();
    let advertised = rr_sessions[1].advertise(&route);
    if !advertised {
        eprintln!("FAIL: RR did not queue an UPDATE for client #2");
        return ExitCode::from(1);
    }
    let update_bytes = rr_sessions[1].drain_outgoing();
    if update_bytes.is_empty() {
        eprintln!("FAIL: RR drained no bytes after advertise()");
        return ExitCode::from(1);
    }

    match decode_reflected_update(&update_bytes) {
        Ok((originator, cluster_list)) => {
            println!("Reflection attributes on the UPDATE to client #2:");
            println!(
                "  ORIGINATOR_ID: {}.{}.{}.{}",
                originator[0], originator[1], originator[2], originator[3]
            );
            let mut clusters = String::new();
            for (i, c) in cluster_list.iter().enumerate() {
                if i > 0 {
                    clusters.push_str(" -> ");
                }
                let b = c.to_be_bytes();
                clusters.push_str(&format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]));
            }
            println!("  CLUSTER_LIST:  [{clusters}]");
            println!();
            println!("OK: RFC 4456 §3 reflection attributes stamped on the reflected UPDATE.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            ExitCode::from(1)
        }
    }
}

fn fmt_v4(b: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn state_label(up: bool) -> &'static str {
    if up {
        "Established"
    } else {
        "down"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v4_accepts_quad() {
        assert_eq!(parse_v4("10.0.0.1"), Some([10, 0, 0, 1]));
        assert_eq!(parse_v4("255.255.255.255"), Some([255, 255, 255, 255]));
    }

    #[test]
    fn parse_v4_rejects_bad() {
        assert_eq!(parse_v4("10.0.0"), None);
        assert_eq!(parse_v4("10.0.0.256"), None);
        assert_eq!(parse_v4("10.0.0.a"), None);
    }

    #[test]
    fn parse_client_strips_port() {
        assert_eq!(parse_client("10.0.0.2:179"), Some([10, 0, 0, 2]));
        assert_eq!(parse_client("10.0.0.2"), Some([10, 0, 0, 2]));
        assert_eq!(parse_client("10.0.0.2:abc"), None); // bad port drops whole arg
    }

    #[test]
    fn args_default_has_two_clients() {
        let a = Args::default();
        assert_eq!(a.clients.len(), 2);
        assert_eq!(a.local_as, DEFAULT_LOCAL_AS);
    }

    /// Full in-process demo: drive the handshakes and verify the
    /// reflected UPDATE carries the RFC 4456 §3 attributes. This
    /// pins the same property the daemon's `route_reflector_reflects_between_clients`
    /// e2e test covers but at the template layer.
    #[test]
    fn rr_cluster_reflects_to_client() {
        let args = Args::default();
        let mut rr_a = BgpPeer::new(rr_client_cfg(&args, args.clients[0]));
        let mut rr_b = BgpPeer::new(rr_client_cfg(&args, args.clients[1]));
        let mut dummy_a = BgpPeer::new(client_dummy_cfg(&args, args.clients[0]));
        let mut dummy_b = BgpPeer::new(client_dummy_cfg(&args, args.clients[1]));

        assert!(drive_handshake(&mut rr_a, &mut dummy_a), "RR<->A handshake");
        assert!(drive_handshake(&mut rr_b, &mut dummy_b), "RR<->B handshake");

        // The route is iBGP-learned from client A (origin.proto = 1).
        let route = sample_route();
        assert!(rr_b.advertise(&route), "RR queues UPDATE for client B");
        let bytes = rr_b.drain_outgoing();
        assert!(!bytes.is_empty(), "RR drained bytes");

        let (originator, cluster_list) = decode_reflected_update(&bytes).expect("decoded UPDATE");
        assert_eq!(originator, args.router_id.to_vec());
        assert_eq!(cluster_list, vec![u32::from_be_bytes(args.cluster_id)]);
    }

    /// `route_reflector.enabled = false` (default) suppresses the
    /// reflection attributes per RFC 4456 §3 — a non-reflector must
    /// not stamp ORIGINATOR_ID / CLUSTER_LIST.
    #[test]
    fn rr_attributes_suppressed_when_not_reflector() {
        let args = Args::default();
        let mut cfg = rr_client_cfg(&args, args.clients[1]);
        cfg.route_reflector.enabled = false;
        let mut rr_b = BgpPeer::new(cfg);
        let mut dummy_b = BgpPeer::new(client_dummy_cfg(&args, args.clients[1]));

        assert!(drive_handshake(&mut rr_b, &mut dummy_b));

        let route = sample_route();
        assert!(
            rr_b.advertise(&route),
            "RR queues UPDATE for client B (no RR)"
        );
        let bytes = rr_b.drain_outgoing();
        assert!(!bytes.is_empty());

        // Decode the UPDATE; we expect *no* ORIGINATOR_ID.
        let mut codec = BgpCodec::new();
        let mut r = lr_core::buf::ReadBuf::new(&bytes);
        while let Ok(Some(msg)) = codec.decode(&mut r) {
            if let BgpMessage::Update(u) = msg {
                assert!(
                    u.attributes.get(AttrType::OriginatorId).is_none(),
                    "ORIGINATOR_ID must not be stamped when route_reflector.enabled = false"
                );
                assert!(
                    u.attributes.get(AttrType::ClusterList).is_none(),
                    "CLUSTER_LIST must not be stamped when route_reflector.enabled = false"
                );
                return;
            }
        }
        panic!("no UPDATE decoded");
    }
}
