// Re-export the daemon crate root so the nested test modules can write
// `use super::*;` (referring to `daemon_tests`) and still see every item
// the daemon binary brings into scope — types like `DefaultRouter`,
// `SessionConfig`, the log macros, the helper fns, etc.
use super::*;

#[cfg(test)]
mod lsp_tests {
    use super::*;

    /// The private tag is a magic byte by necessity (const context);
    /// this pins it to the lr-bgp definition so a renumbering breaks
    /// the build's tests, not the dataplane.
    #[test]
    fn label_stack_tag_matches_lr_bgp() {
        assert_eq!(
            LR_MPLS_LABEL_STACK_TAG,
            lr_bgp::path::AttrType::LrMplsLabelStack.to_u8()
        );
    }

    /// Build a best route shaped like the router pipeline emits it:
    /// `proto` 2 = locally originated, anything else = peer-learned.
    fn route(
        origin_proto: u32,
        next_hop: Option<IpAddr>,
        stack: Option<&lr_mpls::LabelStack>,
    ) -> lr_core::rib::Route {
        let mut attrs = lr_core::attr::Attributes::new();
        if let Some(s) = stack {
            attrs.insert(lr_core::attr::Attribute {
                tag: lr_core::attr::AttrTag(LR_MPLS_LABEL_STACK_TAG),
                flags: 0x20, // optional (matches PathAttribute::set_label_stack)
                value: s.encode_4octet(),
            });
        }
        lr_core::rib::Route {
            key: lr_core::rib::RouteKey::new(
                "198.51.100.0/24".parse().unwrap(),
                NlriFamily::IPV4_LABELED_UNICAST,
            ),
            origin: lr_core::rib::RouteOrigin {
                proto: origin_proto,
                peer: 0,
            },
            protocol: lr_core::rib::Protocol::Bgp,
            preference: lr_core::rib::Preference::new(
                lr_core::rib::Protocol::Bgp.default_admin_distance(),
                0,
            ),
            next_hop,
            attributes: attrs,
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    #[test]
    fn plain_when_no_label_stack() {
        let r = route(0, Some(IpAddr::V4([192, 0, 2, 1])), None);
        assert_eq!(lsp_decision(&r), LspDecision::Plain);
    }

    #[test]
    fn push_for_received_labelled_route() {
        let stack = lr_mpls::LabelStack::from_values([100]);
        let r = route(0, Some(IpAddr::V4([192, 0, 2, 1])), Some(&stack));
        assert_eq!(lsp_decision(&r), LspDecision::Push(stack));
    }

    #[test]
    fn pop_local_for_originated_labelled_route() {
        let stack = lr_mpls::LabelStack::from_values([100]);
        let r = route(2, None, Some(&stack));
        assert_eq!(
            lsp_decision(&r),
            LspDecision::PopLocal(lr_mpls::Label::new_value(100))
        );
    }

    #[test]
    fn plain_for_implicit_null_top_label() {
        // PHP: the tail advertises implicit null, the head must not push.
        let stack = lr_mpls::LabelStack::from_values([lr_mpls::Label::IMPLICIT_NULL.value]);
        let r = route(0, Some(IpAddr::V4([192, 0, 2, 1])), Some(&stack));
        assert_eq!(lsp_decision(&r), LspDecision::Plain);
    }

    #[test]
    fn plain_when_received_route_has_no_next_hop() {
        let stack = lr_mpls::LabelStack::from_values([100]);
        let r = route(0, None, Some(&stack));
        assert_eq!(lsp_decision(&r), LspDecision::Plain);
    }

    #[test]
    fn garbled_stack_attribute_is_ignored() {
        let mut r = route(0, Some(IpAddr::V4([192, 0, 2, 1])), None);
        r.attributes.insert(lr_core::attr::Attribute {
            tag: lr_core::attr::AttrTag(LR_MPLS_LABEL_STACK_TAG),
            flags: 0x20,
            value: vec![0xff; 3], // not a multiple of 4 → decode failure
        });
        assert_eq!(lsp_decision(&r), LspDecision::Plain);
    }

    #[test]
    fn multi_label_stack_round_trips() {
        let stack = lr_mpls::LabelStack::from_values([100, 200]);
        let r = route(0, Some(IpAddr::V4([192, 0, 2, 1])), Some(&stack));
        match lsp_decision(&r) {
            LspDecision::Push(s) => {
                assert_eq!(
                    s.labels().iter().map(|l| l.value).collect::<Vec<_>>(),
                    [100, 200]
                );
            }
            other => panic!("expected Push, got {:?}", other),
        }
    }
}

#[cfg(test)]
mod babel_router_id_tests {
    use super::*;
    use crate::daemon_config::DaemonConfig;

    fn boot() -> [u8; 8] {
        // Deterministic nonce so the fallback path tests are
        // reproducible.
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    }

    /// The configured IPv4 router-id becomes the 8-octet Babel
    /// router-id BIRD puts on the wire: zero-padded to 8 bytes,
    /// network-byte order. `172.23.10.102` ⇒
    /// `00:00:00:00:ac:17:0a:66`.
    #[test]
    fn configured_router_id_zero_pads_to_eight_bytes_bird_style() {
        let rid = babel_router_id_for(
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            boot(),
            Some(std::net::Ipv4Addr::new(172, 23, 10, 102)),
        );
        assert_eq!(rid, [0, 0, 0, 0, 172, 23, 10, 102]);
    }

    /// The configured router-id wins regardless of the transport
    /// family — a v6 link-local transport (the Babel default on
    /// Ethernet) still advertises the operator's chosen router-id,
    /// not a random EUI-64. This is the bug that produced the
    /// `7f:a2:de:dc:29:86:fb:75` random id on the BIRD peer's
    /// `show babel routes` output.
    #[test]
    fn configured_router_id_overrides_v6_random_fallback() {
        let ll = std::net::IpAddr::V6("fe80::1".parse().unwrap());
        let with_cfg = babel_router_id_for(ll, boot(), Some(std::net::Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(with_cfg, [0, 0, 0, 0, 10, 0, 0, 1]);
        // Without a configured router-id, the v6 transport falls back
        // to the per-boot nonce — that path is unchanged so a
        // router-id-less embedder keeps the historical behaviour.
        let without_cfg = babel_router_id_for(ll, boot(), None);
        assert_eq!(without_cfg, boot());
    }

    /// A v4 transport without a configured router-id keeps the
    /// historical mix (IPv4 in the *low* four octets, per-boot nonce
    /// in the *high* four). This is the only path RFC 8966 §3.3
    /// actually requires uniqueness for, so a regression here
    /// would re-introduce router-id collisions on dual-stack
    /// embedders without a router-id.
    #[test]
    fn v4_fallback_keeps_mix_when_no_router_id_configured() {
        let rid = babel_router_id_for(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            boot(),
            None,
        );
        // The IPv4 occupies the low four octets (the
        // network-byte-order value BIRD's `proto_get_router_id`
        // would zero-extend in the other direction); the per-boot
        // nonce fills the remaining four so two daemons on the same
        // link with the same IPv4 do not collide.
        assert_eq!(rid, [192, 0, 2, 1, 0x55, 0x66, 0x77, 0x88]);
    }

    /// `babel_router_id_from_config` parses the daemon's
    /// `router_id` string tolerantly: `host:port` legacy forms and
    /// stray whitespace must not fool it. Empty / unset router-ids
    /// surface as `None`, which the caller turns into the per-boot
    /// fallback path.
    #[test]
    fn router_id_from_config_parses_ipv4_and_rejects_garbage() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.router_id = "172.23.10.102".to_string();
        assert_eq!(
            babel_router_id_from_config(&cfg),
            Some(std::net::Ipv4Addr::new(172, 23, 10, 102))
        );
        // A `host:port` form should still parse (the legacy single-peer
        // daemon sometimes configures the router-id alongside the
        // listen address this way).
        cfg.router_id = "172.23.10.102:179".to_string();
        assert_eq!(
            babel_router_id_from_config(&cfg),
            Some(std::net::Ipv4Addr::new(172, 23, 10, 102))
        );
        cfg.router_id = String::new();
        assert_eq!(babel_router_id_from_config(&cfg), None);
        cfg.router_id = "not-an-ip".to_string();
        assert_eq!(babel_router_id_from_config(&cfg), None);
    }

    /// `babel_iface_manual` plumbs the configured router-id into the
    /// `BabelIface.router_id` field on the manual single-socket path
    /// — the same value `build_babel_announcement` later pushes as
    /// the Router-Id TLV on the wire. The loopback address lets the
    /// test run on any Linux/macOS CI container without a dedicated
    /// adapter; the assertion is on the router-id wiring, not on the
    /// socket binding (which `babel_transport_new` exercises
    /// separately).
    #[test]
    fn babel_iface_manual_uses_configured_router_id() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.router_id = "172.23.10.102".to_string();
        cfg.babel_port = 0; // ephemeral — port collisions across tests
        let iface = babel_iface_manual(&cfg, "127.0.0.1", boot()).unwrap();
        assert_eq!(iface.router_id, [0, 0, 0, 0, 172, 23, 10, 102]);
        // Without a configured router-id, the manual path keeps the
        // historical per-boot nonce — no regression for embedders
        // that ship without `--router-id`.
        cfg.router_id = String::new();
        let iface = babel_iface_manual(&cfg, "127.0.0.1", boot()).unwrap();
        assert_eq!(iface.router_id, [127, 0, 0, 1, 0x55, 0x66, 0x77, 0x88]);
    }

    /// The manual-path interface built from a loopback address (which
    /// resolves to `lo`/`lo0` on every Unix) carries the `manual`
    /// marker and now resolves `check_link: true` from the device —
    /// issue #39's BIRD `check link` parity. The startup logger relies
    /// on `manual` (not `name.is_empty()`) to keep the single-socket
    /// log line, so the two assertions together pin both halves of the
    /// fix.
    #[test]
    fn babel_iface_manual_sets_manual_marker_and_check_link() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.babel_port = 0; // ephemeral — port collisions across tests
        let iface = babel_iface_manual(&cfg, "127.0.0.1", boot()).unwrap();
        assert!(iface.manual, "manual-path interface must carry manual=true");
        assert!(
            !iface.name.is_empty(),
            "loopback must resolve to a named interface (got {:?})",
            iface.name
        );
        assert!(
            iface.check_link,
            "manual path with a resolved device must poll the link (check_link=true)"
        );
        assert!(
            iface.if_index > 0,
            "loopback must resolve to a non-zero kernel index (got {})",
            iface.if_index
        );
    }
}

#[cfg(test)]
mod manual_iface_link_state_tests {
    use super::manual_iface_link_state;
    use std::net::IpAddr;

    /// A loopback address resolves to the system loopback interface
    /// on every platform the project targets — the resolved outcome.
    /// The name is platform-dependent (`lo` on Linux, `lo0` on
    /// macOS/BSDs) so the assertion is on the shape, not the string.
    #[test]
    fn loopback_address_resolves() {
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        let (name, check_link, if_index) = manual_iface_link_state(local);
        assert!(
            !name.is_empty(),
            "loopback must resolve to a named interface"
        );
        assert!(
            check_link,
            "a resolved device must enable the check-link poll"
        );
        assert!(
            if_index > 0,
            "loopback must resolve to a non-zero kernel index (got {if_index})"
        );
    }

    /// An address in TEST-NET-2 (RFC 5737) is guaranteed not to be on
    /// any system interface — the unresolved outcome, which must keep
    /// the historical fallback shape so the manual-path daemon still
    /// runs without a device to poll.
    #[test]
    fn unassigned_address_yields_historical_fallback() {
        let local: IpAddr = "198.51.100.250".parse().unwrap();
        let (name, check_link, if_index) = manual_iface_link_state(local);
        assert!(
            name.is_empty(),
            "an unassigned address must not resolve to a name (got {name:?})"
        );
        assert!(
            !check_link,
            "an unassigned address must not enable the check-link poll"
        );
        assert_eq!(if_index, 0, "an unassigned address must not seed if_index");
    }

    /// A v6 loopback (`::1`) resolves the same way on every platform —
    /// the resolved outcome for the v6 transport path. Guards against
    /// a v4-only implementation of the matcher.
    #[test]
    fn ipv6_loopback_resolves() {
        let local: IpAddr = "::1".parse().unwrap();
        let (name, check_link, if_index) = manual_iface_link_state(local);
        assert!(!name.is_empty(), "::1 must resolve to a named interface");
        assert!(
            check_link,
            "a resolved v6 device must enable the check-link poll"
        );
        assert!(if_index > 0, "::1 must resolve to a non-zero kernel index");
    }

    /// The helper is pure with respect to its inputs — calling it twice
    /// with the same address yields the same triple. This is a
    /// belt-and-braces guard against an accidental mutation of the
    /// system interface list (the helper takes it by value).
    #[test]
    fn repeated_calls_are_stable() {
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        let first = manual_iface_link_state(local);
        let second = manual_iface_link_state(local);
        assert_eq!(first, second);
    }
}

#[cfg(test)]
mod peer_local_address_tests {
    use super::*;
    use crate::daemon_config::{DaemonConfig, PeerSpec};

    /// When the operator did not set `local_address`, the daemon's
    /// `router-id` is the next-best source IP for outbound BGP — it
    /// is a real IPv4 on the host (BGP requires it as the
    /// BGP-IDENTIFIER) and sourcing from it makes the peer's
    /// source-IP match succeed. This is the regression that produced
    /// the `peer closed connection` loop on Windows when the kernel
    /// picked a different interface's source IP.
    #[test]
    fn router_id_is_default_source_when_local_address_unset() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.router_id = "172.23.10.102".to_string();
        let peer = PeerSpec::default();
        assert_eq!(
            peer_local_address(&cfg, &peer),
            Some(IpAddr::V4([172, 23, 10, 102]))
        );
    }

    /// An explicit `local_address` always wins over the router-id
    /// default — operators with a loopback-anycast source need to
    /// override the inferred value.
    #[test]
    fn explicit_local_address_wins_over_router_id_default() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.router_id = "172.23.10.102".to_string();
        cfg.local_address = Some("10.0.0.1".to_string());
        let peer = PeerSpec::default();
        assert_eq!(
            peer_local_address(&cfg, &peer),
            Some(IpAddr::V4([10, 0, 0, 1]))
        );
    }

    /// Per-peer `local_address` overrides the per-protocol value,
    /// which overrides the router-id default.
    #[test]
    fn per_peer_local_address_wins_over_protocol_value() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.router_id = "172.23.10.102".to_string();
        cfg.local_address = Some("10.0.0.1".to_string());
        let peer = PeerSpec {
            local_address: Some("10.0.0.2".to_string()),
            ..PeerSpec::default()
        };
        assert_eq!(
            peer_local_address(&cfg, &peer),
            Some(IpAddr::V4([10, 0, 0, 2]))
        );
    }

    /// `host:port` legacy form still parses out the host portion so
    /// the router-id default survives a config that writes the
    /// listen address into the router-id slot by mistake.
    #[test]
    fn router_id_with_port_suffix_still_parses() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.router_id = "172.23.10.102:179".to_string();
        let peer = PeerSpec::default();
        assert_eq!(
            peer_local_address(&cfg, &peer),
            Some(IpAddr::V4([172, 23, 10, 102]))
        );
    }

    /// When neither `local_address` nor a usable router-id is
    /// configured, the function falls through to the historical
    /// listen_addr path — no regression for embedders that ship a
    /// bare `--listen` config without `--router-id`.
    #[test]
    fn falls_back_to_listen_addr_when_no_router_id() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.router_id = String::new();
        cfg.listen_addr = Some("0.0.0.0:179".to_string());
        let peer = PeerSpec::default();
        assert_eq!(
            peer_local_address(&cfg, &peer),
            Some(IpAddr::V4([0, 0, 0, 0]))
        );
    }
}

#[cfg(test)]
mod kernel_mirror_tests {
    use super::*;
    use lr_core::attr::Attributes;
    use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};
    use lr_osroute::{KernelRoute, OsRouteError, OsRouteTable};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Operation {
        Add(Prefix, IpAddr, u32),
        AddBlackhole(Prefix),
        Delete(Prefix),
    }

    struct RecordingTable {
        operations: Arc<Mutex<Vec<Operation>>>,
    }

    impl OsRouteTable for RecordingTable {
        type Error = OsRouteError;

        fn add_route(
            &mut self,
            prefix: Prefix,
            next_hop: IpAddr,
            if_index: u32,
        ) -> Result<(), Self::Error> {
            self.operations
                .lock()
                .unwrap()
                .push(Operation::Add(prefix, next_hop, if_index));
            Ok(())
        }

        fn add_blackhole_route(&mut self, prefix: Prefix) -> Result<(), Self::Error> {
            self.operations
                .lock()
                .unwrap()
                .push(Operation::AddBlackhole(prefix));
            Ok(())
        }

        fn delete_route(&mut self, prefix: Prefix) -> Result<(), Self::Error> {
            self.operations
                .lock()
                .unwrap()
                .push(Operation::Delete(prefix));
            Ok(())
        }

        fn list_routes(&mut self) -> Result<Vec<KernelRoute>, Self::Error> {
            Ok(Vec::new())
        }
    }

    fn route(protocol: Protocol, octet: u8) -> Route {
        let prefix = Prefix::new_v4([10, octet, 0, 0], 16);
        Route {
            key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin {
                proto: u32::from(octet) + 10,
                peer: 1,
            },
            protocol,
            preference: Preference::new(protocol.default_admin_distance(), 10),
            next_hop: Some(IpAddr::V4([192, 0, 2, octet])),
            attributes: Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    #[test]
    fn every_routing_protocol_uses_the_kernel_mirror() {
        let operations = Arc::new(Mutex::new(Vec::new()));
        let mut mirror = KernelMirror::with_ip_table(Box::new(RecordingTable {
            operations: Arc::clone(&operations),
        }));
        let routes = [
            route(Protocol::Bgp, 1),
            route(Protocol::Ospfv2, 2),
            route(Protocol::Ospfv3, 3),
            route(Protocol::Babel, 4),
        ];

        let mut events: Vec<_> = routes
            .iter()
            .cloned()
            .map(RouterEvent::RouteInstalled)
            .collect();
        events.extend(
            routes
                .iter()
                .map(|route| RouterEvent::RouteWithdrawn(route.key.clone())),
        );
        mirror.apply(&events);

        let operations = operations.lock().unwrap();
        assert_eq!(operations.len(), 8);
        for (index, route) in routes.iter().enumerate() {
            assert_eq!(
                operations[index],
                Operation::Add(route.key.prefix, route.next_hop.unwrap(), 0)
            );
            assert_eq!(
                operations[index + routes.len()],
                Operation::Delete(route.key.prefix)
            );
        }
    }

    /// A blackhole static route (next_hop = None, protocol = Static)
    /// reaches the kernel via `add_blackhole_route` — not via
    /// `add_route(None, ...)`. Pre-fix this test would fail because the
    /// daemon's KernelMirror::apply had no blackhole path and skipped
    /// every None-next-hop route (silently dropping the static discard).
    #[test]
    fn blackhole_static_routes_use_add_blackhole_route() {
        let operations: Arc<Mutex<Vec<Operation>>> = Arc::new(Mutex::new(Vec::new()));
        let mut mirror = KernelMirror::with_ip_table(Box::new(RecordingTable {
            operations: Arc::clone(&operations),
        }));
        let prefix = Prefix::new_v4([192, 0, 2, 0], 24);
        let route = Route {
            key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 2, peer: 0 },
            protocol: Protocol::Static,
            preference: Preference::new(1, 10),
            next_hop: None,
            attributes: Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        mirror.apply(&[RouterEvent::RouteInstalled(route)]);
        let ops = operations.lock().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], Operation::AddBlackhole(prefix));
    }

    /// A connected route (next_hop = None, protocol = Connected) must
    /// NOT reach the kernel — the kernel already has it from the
    /// interface assignment. Pre-fix this test would fail because the
    /// daemon installed every None-next-hop route as blackhole,
    /// breaking OSPF HELLO reception on the interface's own prefix.
    #[test]
    fn connected_routes_with_none_next_hop_are_skipped() {
        let operations: Arc<Mutex<Vec<Operation>>> = Arc::new(Mutex::new(Vec::new()));
        let mut mirror = KernelMirror::with_ip_table(Box::new(RecordingTable {
            operations: Arc::clone(&operations),
        }));
        let prefix = Prefix::new_v4([10, 99, 1, 0], 24);
        let route = Route {
            key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: Protocol::Connected,
            preference: Preference::new(0, 0),
            next_hop: None,
            attributes: Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        mirror.apply(&[RouterEvent::RouteInstalled(route)]);
        let ops = operations.lock().unwrap();
        assert!(
            ops.is_empty(),
            "connected route must not be installed or blackholed, got: {ops:?}"
        );
    }

    /// A registered v4 next hop pins the egress interface of the
    /// install — the rc.4 Windows production defect: a Babel route
    /// learned over a tunnel whose v4-in-v6 next hop (the AE 1
    /// NextHop TLV value) was resolved by the kernel's longest-prefix
    /// against an APIPA 169.254.0.0/16 connected route on an
    /// unrelated adapter, so every learned route egressed the wrong
    /// interface and the BGP sessions above them never connected.
    /// Pre-fix the mirror only consulted the registry for link-local
    /// v6 gateways and passed `oif 0` for v4, deferring to the very
    /// resolution that was wrong.
    #[test]
    fn registered_v4_nexthop_pins_the_egress_interface() {
        let operations: Arc<Mutex<Vec<Operation>>> = Arc::new(Mutex::new(Vec::new()));
        let mut mirror = KernelMirror::with_ip_table(Box::new(RecordingTable {
            operations: Arc::clone(&operations),
        }));
        let next_hop = IpAddr::V4([169, 254, 1, 6]); // the peer's v4 on the babel link
        register_nexthop_oif(next_hop, 58); // the tunnel's ifindex
        let prefix = Prefix::new_v4([172, 23, 10, 98], 32);
        let route = Route {
            key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 4, peer: 6 },
            protocol: Protocol::Babel,
            preference: Preference::new(120, 256),
            next_hop: Some(next_hop),
            attributes: Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        mirror.apply(&[RouterEvent::RouteInstalled(route)]);
        let ops = operations.lock().unwrap();
        assert_eq!(ops.len(), 1, "got: {ops:?}");
        assert_eq!(
            ops[0],
            Operation::Add(prefix, next_hop, 58),
            "the install must carry the session's egress interface, not oif 0"
        );
        // Cleanup: the registry is process-global.
        nexthop_oifs().lock().unwrap().remove(&next_hop);
    }

    /// An unregistered v4 next hop keeps `oif 0` — the kernel's own
    /// recursive resolution is correct for ordinary BGP gateways.
    #[test]
    fn unregistered_v4_nexthop_leaves_egress_to_the_kernel() {
        let operations: Arc<Mutex<Vec<Operation>>> = Arc::new(Mutex::new(Vec::new()));
        let mut mirror = KernelMirror::with_ip_table(Box::new(RecordingTable {
            operations: Arc::clone(&operations),
        }));
        let next_hop = IpAddr::V4([172, 23, 10, 98]);
        let prefix = Prefix::new_v4([172, 23, 10, 104], 32);
        let route = Route {
            key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer: 1 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: Some(next_hop),
            attributes: Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        mirror.apply(&[RouterEvent::RouteInstalled(route)]);
        let ops = operations.lock().unwrap();
        assert_eq!(ops.len(), 1, "got: {ops:?}");
        assert_eq!(ops[0], Operation::Add(prefix, next_hop, 0));
    }

    /// The registry API never pins a zero interface (the "unresolved"
    /// sentinel) and overwrites stale mappings.
    #[test]
    fn registry_never_pins_zero_and_overwrites() {
        let nh = IpAddr::V4([169, 254, 200, 1]);
        register_nexthop_oif(nh, 0);
        assert_eq!(nexthop_oif(&nh), 0);
        register_nexthop_oif(nh, 9);
        assert_eq!(nexthop_oif(&nh), 9);
        register_nexthop_oif(nh, 10);
        assert_eq!(nexthop_oif(&nh), 10);
        nexthop_oifs().lock().unwrap().remove(&nh);
    }
}

#[cfg(test)]
mod source_diagnostic_tests {
    use super::*;

    /// `diagnose_source_address` must not panic when the peer has no
    /// `local_address` configured — the diagnostic is a no-op in that
    /// case. This pins the "hint, not a gate" contract: the daemon
    /// runs unconditionally, the diagnostic only adds information.
    #[test]
    fn diagnose_source_address_no_local_is_no_op() {
        let cfg = DaemonConfig {
            local_as: 64512,
            router_id: "10.0.0.1".into(),
            ..DaemonConfig::default()
        };
        // No local_address configured anywhere — the diagnostic must
        // return without panicking.
        let spec = PeerSpec {
            remote: Some("127.0.0.1:179".into()),
            ..PeerSpec::default()
        };
        let auth = TcpAuth::default();
        let gtsm = Gtsm::default();
        let entry = PeerEntry {
            spec,
            handle: SessionHandle(0),
            handle_in: None,
            auth,
            gtsm,
            bfd: None,
            busy: Arc::new(AtomicBool::new(false)),
            outbound_lost_collision: Arc::new(AtomicBool::new(false)),
        };
        // The function returns (); the test is that it does not panic.
        diagnose_source_address(&cfg, &entry);
    }
}

#[cfg(test)]
mod babel_retraction_tests {
    use super::*;
    use lr_babel::message::{Hello, Ihu, NextHop, RouterId as RouterIdTlv, Update};
    use lr_babel::tlv::{Tlv, TlvType};

    /// A peer frame announcing `prefix` (24) on behalf of `router_id`:
    /// Hello + IHU (the peer's rxcost toward us — no IHU, no accepted
    /// Update) + Router-Id + Next Hop + Update, the daemon wire shape.
    fn peer_frame(router_id: [u8; 8], prefix: [u8; 3], seqno: u16, metric: u16) -> Vec<u8> {
        let mut frame = lr_babel::BabelFrame::empty();
        frame
            .body
            .push(Tlv::new(TlvType::Hello, Hello::new(seqno, 100).encode()));
        frame
            .body
            .push(Tlv::new(TlvType::Ihu, Ihu::new(96, 300).encode()));
        frame.body.push(Tlv::new(
            TlvType::RouterId,
            RouterIdTlv { id: router_id }.encode().to_vec(),
        ));
        frame.body.push(Tlv::new(
            TlvType::NextHop,
            NextHop {
                ae: 1,
                address: IpAddr::V4([127, 0, 0, 1]),
            }
            .encode(),
        ));
        frame.body.push(Tlv::new(
            TlvType::Update,
            Update {
                ae: 1,
                flags: 0,
                prefix_len: 24,
                omitted: 0,
                interval_cs: 300,
                seqno,
                metric,
                prefix: prefix.to_vec(),
                src_prefix_len: 0,
                src_prefix: Vec::new(),
            }
            .encode(),
        ));
        lr_babel::BabelCodec::new().encode_vec(&frame).unwrap()
    }

    /// A v4-transport interface on loopback: a real unicast socket (the
    /// struct embeds one), no multicast, no auth, `next_hop_v4` set —
    /// the shape `babel_iface_manual` builds for a v4 local address.
    /// Bound to 127.0.0.1 (not 127.0.0.2): macOS only configures
    /// 127.0.0.1 on loopback, while Linux covers the whole 127/8.
    fn loopback_iface(session: SessionHandle, port: u16) -> BabelIface {
        let uc = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        BabelIface {
            name: "lo0".into(),
            manual: false,
            transports: vec![BabelTransport {
                local: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                scope_id: 0,
                port,
                group: std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 111)),
                uc,
                mc: None,
            }],
            port,
            hello_interval_ms: 1_000,
            update_interval_ms: 3_000,
            rxcost: 96,
            rtt_cost: 0,
            rtt_min_us: 10_000,
            rtt_max_us: 120_000,
            check_link: false,
            next_hop_v4: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            next_hop_v6: None,
            extended_next_hop: false,
            session,
            if_index: 0,
            auth: None,
            auth_debug_line: String::new(),
            router_id: [1, 2, 3, 4, 5, 6, 7, 8],
            hello_seqno: 0,
            seqno: 0,
            last_sig: String::new(),
            advertised: std::collections::BTreeMap::new(),
            last_announce_ms: 0,
            last_gc_ms: 0,
            link_up: true,
        }
    }

    /// Updates and retractions in one decoded frame, as
    /// `(metric, prefix-octets)` pairs in wire order.
    fn update_metrics(frame: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let decoded = lr_babel::BabelCodec::new()
            .decode_slice(frame)
            .unwrap()
            .expect("a whole frame");
        let mut out = Vec::new();
        for tlv in &decoded.body {
            if tlv.kind == TlvType::Update && tlv.value.len() >= 10 {
                let metric = u16::from_be_bytes([tlv.value[8], tlv.value[9]]);
                let plen = tlv.value[2] as usize;
                let pl = plen.div_ceil(8);
                out.push((metric, tlv.value[10..10 + pl].to_vec()));
            }
        }
        out
    }

    const ORIGIN: [u8; 8] = [8, 8, 8, 8, 0, 0, 0, 1];
    const PFX: [u8; 3] = [10, 99, 1];

    /// RFC 8966 §3.5.5 wire regression (the babel_multihop.sh e2e
    /// failure): when the session a claim was learned on goes down, the
    /// NEXT announcement on the other interfaces must carry the
    /// infinity-metric retraction immediately — not defer it. The
    /// carriage gate used to share `want_v4`/`want_v6` with fresh
    /// announcements; those collapse to false the moment the family's
    /// last route vanishes, so the retraction was silently dropped and
    /// peers held the stale route until its hold time lapsed.
    #[test]
    fn link_down_flush_retracts_the_lost_claim_on_the_wire() {
        let mut r = DefaultRouter::new();
        // S0: the interface the claim was learned on (veth0b shape).
        let s0 = r
            .add_session(SessionConfig::babel(IpAddr::V4([127, 0, 0, 2])))
            .unwrap();
        r.start_session(s0).unwrap();
        // S1: the announcing interface (veth1b shape).
        let s1 = r
            .add_session(SessionConfig::babel(IpAddr::V4([127, 0, 1, 2])))
            .unwrap();
        r.start_session(s1).unwrap();

        r.feed_input(s0, &peer_frame(ORIGIN, PFX, 7, 96))
            .expect("a well-formed daemon-shaped frame");
        assert_eq!(r.babel_reachable(s1).len(), 1, "the claim is reachable");

        let mut iface = loopback_iface(s1, 16_696);
        // Seed the bookkeeping the way a previous announcement did.
        iface.advertised = r
            .babel_reachable(s1)
            .into_iter()
            .map(|route| (route.key, route.seqno))
            .collect();

        // Steady state: the claim is announced with its real metric and
        // NOT retracted.
        let steady = build_babel_announcement(
            &r,
            &mut iface,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            0,
            None,
            None,
        );
        let ups = update_metrics(&steady);
        // The re-advertised metric folds in the reception-side link cost
        // (advertised 96 + the IHU's txcost 96) — babeld parity.
        assert!(
            ups.contains(&(192, PFX.to_vec())),
            "the claim is announced: {ups:?}"
        );
        assert!(
            !ups.iter().any(|(m, _)| *m == 0xFFFF),
            "no retraction while the claim is alive: {ups:?}"
        );

        // The learned-on session dies (check-link flush).
        r.babel_flush_session(s0);
        assert!(r.babel_reachable(s1).is_empty());

        // The next announcement must retract the lost claim immediately
        // (metric=infinity under the origin's Router-Id), so the peers
        // drop it instead of timing it out.
        let retraction = build_babel_announcement(
            &r,
            &mut iface,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            0,
            None,
            None,
        );
        let ups = update_metrics(&retraction);
        assert!(
            ups.contains(&(0xFFFF, PFX.to_vec())),
            "the lost claim is retracted on the wire: {ups:?}"
        );
        // And the retraction is sent once — the bookkeeping must not
        // re-retract the claim on the following announcement.
        let followup = build_babel_announcement(
            &r,
            &mut iface,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            0,
            None,
            None,
        );
        assert!(
            !update_metrics(&followup)
                .iter()
                .any(|(m, p)| *m == 0xFFFF && p.as_slice() == PFX),
            "the retraction is not repeated forever: {:?}",
            update_metrics(&followup)
        );
    }
}
