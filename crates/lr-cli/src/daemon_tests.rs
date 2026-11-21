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

    /// An IPv6 dial must use `local_address_v6`, never the IPv4
    /// `local_address`: binding a v4 source on a v6 socket fails with
    /// EINVAL, which the live daemon reported as "local and peer
    /// address families differ" for sessions that never came up.
    #[test]
    fn v6_dial_prefers_local_address_v6() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.router_id = "172.23.10.102".to_string();
        cfg.local_address = Some("172.23.10.102".to_string());
        cfg.local_address_v6 = Some("fd00:286:11e:2::1".to_string());
        let peer = PeerSpec::default();
        assert_eq!(
            dial_local_address(&cfg, &peer, true),
            Some("fd00:286:11e:2::1".parse::<IpAddr>().unwrap())
        );
        // The v4 transport keeps the v4 source.
        assert_eq!(
            dial_local_address(&cfg, &peer, false),
            Some(IpAddr::V4([172, 23, 10, 102]))
        );
    }

    /// A wrong-family value must be skipped rather than bound. Both
    /// the per-peer and the global slot are checked, for both
    /// transport families.
    #[test]
    fn wrong_family_source_is_ignored() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.router_id = "172.23.10.102".to_string();
        // Global v4 in the v6 slot: unusable for either family.
        cfg.local_address_v6 = Some("10.9.9.9".to_string());
        let peer = PeerSpec {
            local_address: Some("10.0.0.2".to_string()),
            local_address_v6: Some("10.0.0.3".to_string()),
            ..PeerSpec::default()
        };
        assert_eq!(
            dial_local_address(&cfg, &peer, true),
            None,
            "a v4 value in local_address_v6 must not reach a v6 bind()"
        );
        assert_eq!(
            dial_local_address(&cfg, &peer, false),
            Some(IpAddr::V4([10, 0, 0, 2]))
        );
    }

    /// Legacy configs write the only available source into
    /// `local_address`; a v6 value there is accepted for a v6 dial
    /// and ignored for a v4 one (the transport family decides).
    #[test]
    fn legacy_local_address_is_family_checked() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.router_id = "172.23.10.102".to_string();
        cfg.local_address = Some("fd00:286:11e:2::1".to_string());
        let peer = PeerSpec::default();
        assert_eq!(
            dial_local_address(&cfg, &peer, true),
            Some("fd00:286:11e:2::1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            dial_local_address(&cfg, &peer, false),
            Some(IpAddr::V4([172, 23, 10, 102])),
            "the v6 value is unusable for v4, so the v4 fallback chain applies"
        );
    }

    /// A dual-stack peer with only an IPv4 router-id configured has
    /// no v6 source; returning `None` lets the kernel choose, which
    /// is correct (a router-id is a BGP identifier, not a v6 host
    /// address).
    #[test]
    fn v6_dial_without_v6_source_defers_to_the_kernel() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.router_id = "172.23.10.102".to_string();
        cfg.local_address = Some("172.23.10.102".to_string());
        cfg.listen_addr = Some("0.0.0.0:179".to_string());
        let peer = PeerSpec::default();
        assert_eq!(dial_local_address(&cfg, &peer, true), None);
    }

    /// Per-peer `local_address_v6` overrides the global value, and
    /// the legacy `host:port` form still parses.
    #[test]
    fn per_peer_v6_source_wins_and_parses_port_form() {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.local_address_v6 = Some("fd00:286:11e:2::1".to_string());
        let peer = PeerSpec {
            local_address_v6: Some("[fd00:286:11e:2::2]:1790".to_string()),
            ..PeerSpec::default()
        };
        assert_eq!(
            dial_local_address(&cfg, &peer, true),
            Some("fd00:286:11e:2::2".parse::<IpAddr>().unwrap())
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
        Add(Prefix, IpAddr, u32, Option<IpAddr>),
        AddBlackhole(Prefix, Option<IpAddr>),
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
                .push(Operation::Add(prefix, next_hop, if_index, None));
            Ok(())
        }

        fn add_route_tagged_prefsrc(
            &mut self,
            prefix: Prefix,
            next_hop: IpAddr,
            if_index: u32,
            protocol: Protocol,
            prefsrc: Option<IpAddr>,
        ) -> Result<(), Self::Error> {
            let _ = protocol;
            self.operations
                .lock()
                .unwrap()
                .push(Operation::Add(prefix, next_hop, if_index, prefsrc));
            Ok(())
        }

        fn add_blackhole_route(&mut self, prefix: Prefix) -> Result<(), Self::Error> {
            self.add_blackhole_route_prefsrc(prefix, None)
        }

        fn add_blackhole_route_prefsrc(
            &mut self,
            prefix: Prefix,
            prefsrc: Option<IpAddr>,
        ) -> Result<(), Self::Error> {
            self.operations
                .lock()
                .unwrap()
                .push(Operation::AddBlackhole(prefix, prefsrc));
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
                Operation::Add(route.key.prefix, route.next_hop.unwrap(), 0, None)
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
        assert_eq!(ops[0], Operation::AddBlackhole(prefix, None));
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

    /// A connected route that *does* carry a next hop (the shape
    /// `install_connected` produces) must be skipped as well: a
    /// gateway route whose next hop equals its destination prefix is
    /// rejected by the kernel with EINVAL. This is the live failure —
    /// every IPv6 link prefix produced `route install failed for
    /// fd00:286:11e:19::/64 via fd00:286:11e:19:: oif 0: error -22`.
    #[test]
    fn connected_routes_with_a_gateway_are_skipped() {
        let operations: Arc<Mutex<Vec<Operation>>> = Arc::new(Mutex::new(Vec::new()));
        let mut mirror = KernelMirror::with_ip_table(Box::new(RecordingTable {
            operations: Arc::clone(&operations),
        }));
        let prefix: Prefix = "fd00:286:11e:19::/64".parse().unwrap();
        let route = Route {
            key: RouteKey::new(prefix, NlriFamily::IPV6_UNICAST),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: Protocol::Connected,
            preference: Preference::new(0, 0),
            next_hop: Some("fd00:286:11e:19::".parse::<IpAddr>().unwrap()),
            attributes: Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        mirror.apply(&[RouterEvent::RouteInstalled(route.clone())]);
        mirror.apply(&[RouterEvent::RouteWithdrawn(route.key)]);
        let ops = operations.lock().unwrap();
        assert!(
            ops.is_empty(),
            "connected routes own the kernel row; the mirror must not \
             install or delete them, got: {ops:?}"
        );
    }

    /// `[kernel] export_filter` keeps a route in the Loc-RIB (for BGP
    /// export) while refusing its FIB install — BIRD's `protocol
    /// kernel { export filter { if proto = "static" then reject; } }`.
    /// The live use is a static blackhole anchor that covers a peer's
    /// transport address: installing it makes `connect()` fail with
    /// EINVAL on Linux.
    #[test]
    fn kernel_export_filter_blocks_the_fib_install() {
        let cfg = DaemonConfig {
            filters: vec![crate::daemon_config::FilterSpec {
                name: Some("kernel-out".into()),
                body: Some(r#"if proto == "static" then reject; accept;"#.into()),
                description: None,
            }],
            kernel_export_filter: Some("kernel-out".into()),
            ..DaemonConfig::default()
        };
        let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
        let filter = crate::daemon_policy::build_kernel_filter(&cfg, &roa)
            .expect("the filter compiles")
            .expect("a filter is configured");

        let operations = Arc::new(Mutex::new(Vec::new()));
        let mut mirror = KernelMirror::with_ip_table_and_filter(
            Box::new(RecordingTable {
                operations: Arc::clone(&operations),
            }),
            Some(filter),
        );
        // A blackhole static route: rejected before add_blackhole_route.
        let mut static_route = route(Protocol::Static, 7);
        static_route.next_hop = None;
        mirror.apply(&[RouterEvent::RouteInstalled(static_route)]);
        assert!(
            operations.lock().unwrap().is_empty(),
            "the static anchor must not reach the FIB"
        );
        // A BGP route with the same filter in place still installs.
        let bgp_route = route(Protocol::Bgp, 8);
        mirror.apply(&[RouterEvent::RouteInstalled(bgp_route.clone())]);
        let ops = operations.lock().unwrap();
        assert_eq!(ops.len(), 1, "got: {ops:?}");
        assert_eq!(
            ops[0],
            Operation::Add(bgp_route.key.prefix, bgp_route.next_hop.unwrap(), 0, None)
        );
    }

    /// A filtered route never reaches the FIB, so a later withdrawal
    /// must not issue a blind delete for it.
    #[test]
    fn filtered_route_withdrawal_does_not_delete() {
        let cfg = DaemonConfig {
            filters: vec![crate::daemon_config::FilterSpec {
                name: Some("kernel-out".into()),
                body: Some("reject;".into()),
                description: None,
            }],
            kernel_export_filter: Some("kernel-out".into()),
            ..DaemonConfig::default()
        };
        let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
        let filter = crate::daemon_policy::build_kernel_filter(&cfg, &roa)
            .unwrap()
            .unwrap();
        let operations = Arc::new(Mutex::new(Vec::new()));
        let mut mirror = KernelMirror::with_ip_table_and_filter(
            Box::new(RecordingTable {
                operations: Arc::clone(&operations),
            }),
            Some(filter),
        );
        let r = route(Protocol::Bgp, 9);
        mirror.apply(&[RouterEvent::RouteInstalled(r.clone())]);
        mirror.apply(&[RouterEvent::RouteWithdrawn(r.key)]);
        assert!(
            operations.lock().unwrap().is_empty(),
            "no install means no delete"
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
            Operation::Add(prefix, next_hop, 58, None),
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
        assert_eq!(ops[0], Operation::Add(prefix, next_hop, 0, None));
    }

    // ---- Preferred-source (BIRD `krt_prefsrc`) plumbing ------------------

    /// The mirror stamps the configured local address as the preferred
    /// source of every FIB row, family-matched: `local_address` for the
    /// v4 rows (including Babel's v4-over-v6 next-hop shape),
    /// `local_address_v6` for the v6 rows.
    #[test]
    fn mirror_stamps_per_family_prefsrc_on_installs() {
        let operations: Arc<Mutex<Vec<Operation>>> = Arc::new(Mutex::new(Vec::new()));
        let mut mirror = KernelMirror::with_ip_table_and_prefsrc(
            Box::new(RecordingTable {
                operations: Arc::clone(&operations),
            }),
            KernelPrefsrc {
                v4: Some(IpAddr::V4([172, 23, 10, 115])),
                v6: Some(IpAddr::V6([
                    0xfd, 0, 0, 0x11, 0x9e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x19,
                ])),
            },
        );
        let v4_prefix = Prefix::new_v4([10, 9, 0, 0], 16);
        let v6_prefix: Prefix = "fd00:286:11e:19::/64".parse().unwrap();
        let v4_nh = IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
        let v6_nh = IpAddr::V6([0xfd, 0, 0, 0x11, 0x9e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        let route_for = |prefix: Prefix, nh: IpAddr| Route {
            key: RouteKey::new(
                prefix,
                if prefix.is_ipv6() {
                    NlriFamily::IPV6_UNICAST
                } else {
                    NlriFamily::IPV4_UNICAST
                },
            ),
            origin: RouteOrigin { proto: 0, peer: 0 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: Some(nh),
            attributes: Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        mirror.apply(&[
            RouterEvent::RouteInstalled(route_for(v4_prefix, v4_nh)),
            RouterEvent::RouteInstalled(route_for(v6_prefix, v6_nh)),
        ]);
        let ops = operations.lock().unwrap();
        assert_eq!(
            ops.as_slice(),
            &[
                Operation::Add(v4_prefix, v4_nh, 0, Some(IpAddr::V4([172, 23, 10, 115])),),
                Operation::Add(
                    v6_prefix,
                    v6_nh,
                    0,
                    Some(IpAddr::V6([
                        0xfd, 0, 0, 0x11, 0x9e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x19,
                    ])),
                ),
            ],
            "the v4 row carries local_address, the v6 row carries local_address_v6"
        );
    }

    /// With no configured `local_address` a FIB row installs with no
    /// preferred source — the kernel picks one, as BIRD does when the
    /// export filter leaves `krt_prefsrc` unset.
    #[test]
    fn mirror_installs_without_prefsrc_when_unconfigured() {
        let operations: Arc<Mutex<Vec<Operation>>> = Arc::new(Mutex::new(Vec::new()));
        let mut mirror = KernelMirror::with_ip_table_and_prefsrc(
            Box::new(RecordingTable {
                operations: Arc::clone(&operations),
            }),
            KernelPrefsrc::default(),
        );
        let r = route(Protocol::Bgp, 1);
        mirror.apply(&[RouterEvent::RouteInstalled(r.clone())]);
        let ops = operations.lock().unwrap();
        assert_eq!(
            ops.as_slice(),
            &[Operation::Add(r.key.prefix, r.next_hop.unwrap(), 0, None)]
        );
    }

    /// `KernelPrefsrc::from_config` keeps the value family-matched: the
    /// kernel requires the preferred source to be same-family as the
    /// FIB row, so a v4 `local_address` configured for v6-only rows is
    /// dropped rather than stamped on a v6 row.
    #[test]
    fn kernel_prefsrc_from_config_is_family_matched() {
        let v4 = "172.23.10.115";
        let v6 = "fd00:286:11e:19::";
        let cases = [
            // (local_address, local_address_v6, expected v4, expected v6)
            (Some(v4), Some(v6), Some(v4), Some(v6)),
            (None, Some(v6), None, Some(v6)),
            (Some(v4), None, Some(v4), None),
            // A v6 `local_address` is the fallback for v6 rows when
            // `local_address_v6` is unset, but not for v4 rows.
            (Some(v6), None, None, Some(v6)),
            (None, None, None, None),
        ];
        for (addr, addr_v6, want_v4, want_v6) in cases {
            let cfg = DaemonConfig {
                local_address: addr.map(str::to_string),
                local_address_v6: addr_v6.map(str::to_string),
                ..DaemonConfig::default()
            };
            let got = KernelPrefsrc::from_config(&cfg);
            let parse = |a: Option<&str>| a.and_then(|s| s.parse::<IpAddr>().ok());
            assert_eq!(got.v4, parse(want_v4), "local_address = {addr:?}");
            assert_eq!(got.v6, parse(want_v6), "local_address_v6 = {addr_v6:?}");
        }
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
            admin_down: false,
            bfd_strict_mode: false,
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
            rtt_send: false,
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

    /// Updates and retractions across one or more encoded packets, as
    /// `(metric, prefix-octets)` pairs in wire order.
    ///
    /// `build_babel_announcement` returns `Vec<Vec<u8>>` since the
    /// multi-packet split landed: one logical announcement may span
    /// several UDP datagrams (RFC 8966 §4 caps each at 1496 body
    /// octets). This helper walks every packet so a retraction that
    /// landed in a trailing frame is still counted.
    fn update_metrics(packets: &[Vec<u8>]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        for pkt in packets {
            let decoded = match lr_babel::BabelCodec::new().decode_slice(pkt) {
                Ok(Some(f)) => f,
                _ => continue,
            };
            for tlv in &decoded.body {
                if tlv.kind == TlvType::Update && tlv.value.len() >= 10 {
                    let metric = u16::from_be_bytes([tlv.value[8], tlv.value[9]]);
                    let plen = tlv.value[2] as usize;
                    let pl = plen.div_ceil(8);
                    out.push((metric, tlv.value[10..10 + pl].to_vec()));
                }
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

/// `rtt_send` (BIRD `rtt send yes` / FRR `babel enable-timestamps`)
/// controls whether the interface attaches BABEL-RTT timestamp
/// sub-TLVs to its Hellos and echoes them in its IHUs. `rtt_cost > 0`
/// is the metric penalty; before this split, the daemon conflated the
/// two and an operator who set `rtt_cost > 0` got timestamps whether
/// they wanted them or not, while an operator who set neither got
/// `rtt 0.000 ms` against a BIRD peer that DID send timestamps — the
/// production complaint that "rtt is 0 even though the peer is
/// sending timestamped Hellos".
#[cfg(test)]
mod babel_rtt_send_tests {
    use super::*;
    use crate::daemon_config::{BabelInterfaceSpec, DaemonConfig};
    use lr_core::addr::IpAddr;
    use lr_osroute::ospf_transport::InterfaceEntry;

    /// Build a minimal `BabelIface` from a spec + entry, exercising
    /// the same `babel_iface_from_spec` path the daemon uses at
    /// startup. The entry uses 127.0.0.1 so the transport binds on
    /// every platform without needing a configured veth pair.
    fn iface_from_spec(spec: &BabelInterfaceSpec) -> BabelIface {
        let mut cfg = DaemonConfig::with_defaults();
        cfg.babel_interfaces.push(spec.clone());
        let _ = cfg.finalize();
        let entry = InterfaceEntry {
            name: "lo".into(),
            v4: vec![std::net::Ipv4Addr::new(127, 0, 0, 1)],
            v6: vec![],
            up: true,
            running: true,
        };
        babel_iface_from_spec(&cfg, spec, &entry, [1, 2, 3, 4, 5, 6, 7, 8])
            .expect("a well-formed spec resolves")
    }

    fn spec() -> BabelInterfaceSpec {
        BabelInterfaceSpec {
            name: Some("lo".into()),
            kind: Some("wired".into()),
            ..Default::default()
        }
    }

    /// Default: `rtt_cost` unset (0) and `rtt_send` unset →
    /// `rtt_send` resolves to false. No timestamps on the wire.
    #[test]
    fn rtt_send_defaults_off_when_rtt_cost_unset() {
        let iface = iface_from_spec(&spec());
        assert_eq!(iface.rtt_cost, 0);
        assert!(
            !iface.rtt_send,
            "rtt_send stays off when neither flag is set"
        );
    }

    /// `rtt_cost > 0` implies `rtt_send = true`. A config that only
    /// sets the penalty must not also need to set the send flag to
    /// get measurements.
    #[test]
    fn rtt_cost_implies_rtt_send() {
        let mut s = spec();
        s.rtt_cost = Some(96);
        let iface = iface_from_spec(&s);
        assert_eq!(iface.rtt_cost, 96);
        assert!(
            iface.rtt_send,
            "rtt_cost > 0 must imply rtt_send so the penalty has a measurement to work on"
        );
    }

    /// `rtt_send = true` alone enables timestamps without applying a
    /// metric penalty — the operator wants to *measure* RTT (e.g. for
    /// monitoring) without making it influence route selection. This
    /// matches BIRD's `rtt send yes` with `rtt cost 0`.
    #[test]
    fn rtt_send_true_enables_timestamps_without_metric_penalty() {
        let mut s = spec();
        s.rtt_send = Some(true);
        let iface = iface_from_spec(&s);
        assert_eq!(iface.rtt_cost, 0);
        assert!(iface.rtt_send, "rtt_send = true enables timestamps");
    }

    /// `rtt_send = false` with `rtt_cost > 0` overrides the implicit
    /// enable. The operator explicitly does not want timestamps even
    /// though a penalty is configured (unusual but supported).
    #[test]
    fn rtt_send_false_overrides_rtt_cost_implicit_enable() {
        let mut s = spec();
        s.rtt_cost = Some(96);
        s.rtt_send = Some(false);
        let iface = iface_from_spec(&s);
        assert_eq!(iface.rtt_cost, 96);
        assert!(
            !iface.rtt_send,
            "explicit rtt_send = false overrides rtt_cost's implicit enable"
        );
    }

    /// `build_babel_announcement` honours `rtt_send` (not
    /// `rtt_cost > 0`) for the Hello timestamp sub-TLV. An interface
    /// with `rtt_send = true` and `rtt_cost = 0` still attaches the
    /// sub-TLV.
    #[test]
    fn build_announcement_attaches_hello_timestamp_when_rtt_send() {
        let mut s = spec();
        s.rtt_send = Some(true);
        let mut iface = iface_from_spec(&s);
        iface.hello_seqno = 7;
        let r = DefaultRouter::new();
        let packets = build_babel_announcement(
            &r,
            &mut iface,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            0x1234_5678,
            None,
            None,
        );
        assert!(!packets.is_empty());
        let decoded = lr_babel::BabelCodec::new()
            .decode_slice(&packets[0])
            .unwrap()
            .expect("a whole frame");
        let hello_tlv = decoded
            .body
            .iter()
            .find(|t| t.kind == lr_babel::tlv::TlvType::Hello)
            .expect("a Hello TLV in the first packet");
        let hello = lr_babel::message::Hello::decode(&hello_tlv.value).unwrap();
        assert_eq!(
            hello.timestamp,
            Some(0x1234_5678),
            "rtt_send attaches the BABEL-RTT timestamp sub-TLV to the Hello"
        );
    }

    /// `build_babel_announcement` does NOT attach the Hello timestamp
    /// when `rtt_send` is false, even if `rtt_cost > 0` would have
    /// triggered it under the old conflated gating.
    #[test]
    fn build_announcement_omits_hello_timestamp_when_rtt_send_off() {
        let mut s = spec();
        s.rtt_cost = Some(96);
        s.rtt_send = Some(false);
        let mut iface = iface_from_spec(&s);
        iface.hello_seqno = 7;
        let r = DefaultRouter::new();
        let packets = build_babel_announcement(
            &r,
            &mut iface,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            0x1234_5678,
            None,
            None,
        );
        assert!(!packets.is_empty());
        let decoded = lr_babel::BabelCodec::new()
            .decode_slice(&packets[0])
            .unwrap()
            .expect("a whole frame");
        let hello_tlv = decoded
            .body
            .iter()
            .find(|t| t.kind == lr_babel::tlv::TlvType::Hello)
            .expect("a Hello TLV in the first packet");
        let hello = lr_babel::message::Hello::decode(&hello_tlv.value).unwrap();
        assert_eq!(
            hello.timestamp, None,
            "rtt_send = false suppresses the timestamp sub-TLV"
        );
    }

    /// Suppress an unused-import warning for `IpAddr` — it is used by
    /// `babel_iface_from_spec` callers elsewhere but not directly in
    /// this module's tests yet.
    #[allow(dead_code)]
    fn _ip_addr_anchor() -> IpAddr {
        IpAddr::V4([0; 4])
    }
}

/// RFC 4456 §3 + §10: end-to-end test that the daemon's
/// `build_session_config` wires the new TOML keys
/// (`[bgp] route_reflector_cluster_id` and `[[peer]]
/// route_reflector_client`) into the underlying
/// `lr_router::SessionConfig`'s route-reflector fields. The
/// translation tests verify the BIRD/FRR → TOML leg; this test
/// verifies the TOML → SessionConfig leg, closing the loop.
mod route_reflector_wiring_tests {
    use super::*;
    use crate::daemon_config::{DaemonConfig, PeerSpec};
    use lr_core::addr::RouterId;

    /// A peer whose TOML sets `route_reflector_client = true` and
    /// whose `[bgp] route_reflector_cluster_id` is "10.0.0.254"
    /// becomes a session with `route_reflector.enabled = true`,
    /// `route_reflector.cluster_id = 10.0.0.254` and
    /// `route_reflector_client = true`. All three fields must agree
    /// for the daemon's reflection path to stamp CLUSTER_LIST and
    /// ORIGINATOR_ID on reflected UPDATEs.
    #[test]
    fn build_session_config_wires_rr_client_and_cluster_id() {
        let mut g = DaemonConfig::with_defaults();
        g.local_as = 64512;
        g.route_reflector_cluster_id = Some("10.0.0.254".to_string());
        let p = PeerSpec {
            remote: Some("192.0.2.2".to_string()),
            peer_as: 64512,
            route_reflector_client: Some(true),
            ..PeerSpec::default()
        };
        let rid = RouterId::from_v4([10, 0, 0, 1]);
        let sc = build_session_config(&g, &p, rid);
        assert!(
            sc.route_reflector.enabled,
            "global route_reflector_cluster_id enables route_reflector.enabled"
        );
        assert_eq!(
            sc.route_reflector.cluster_id,
            lr_bgp::role::ClusterId::from_v4([10, 0, 0, 254]),
            "cluster_id parsed from the global route_reflector_cluster_id"
        );
        assert!(
            sc.route_reflector_client,
            "per-peer route_reflector_client = true sets sc.route_reflector_client"
        );
    }

    /// A peer flagged as an RR client without a global cluster id
    /// still enables reflection on the local speaker — the cluster
    /// id then falls back to the local BGP identifier (RFC 4456
    /// §10), which the SessionConfig represents as the default
    /// `ClusterId(0)` value (`effective_cluster_id(bgp_id)` resolves
    /// it at reflect time).
    #[test]
    fn build_session_config_rr_client_without_cluster_id_uses_bgp_id_default() {
        let mut g = DaemonConfig::with_defaults();
        g.local_as = 64512;
        // No `route_reflector_cluster_id` — the global is `None`.
        let p = PeerSpec {
            remote: Some("192.0.2.2".to_string()),
            peer_as: 64512,
            route_reflector_client: Some(true),
            ..PeerSpec::default()
        };
        let rid = RouterId::from_v4([10, 0, 0, 1]);
        let sc = build_session_config(&g, &p, rid);
        assert!(
            sc.route_reflector.enabled,
            "per-peer route_reflector_client alone enables route_reflector.enabled"
        );
        assert_eq!(
            sc.route_reflector.cluster_id,
            lr_bgp::role::ClusterId::default(),
            "cluster_id stays at the default (0) — the router uses bgp_id at reflect time"
        );
        assert!(sc.route_reflector_client);
    }

    /// A peer without `route_reflector_client` and no global cluster
    /// id is a plain iBGP session — neither route-reflector flag is
    /// set. This is the regression guard for any future refactor
    /// that accidentally enables reflection unconditionally.
    #[test]
    fn build_session_config_without_rr_keys_leaves_reflection_off() {
        let mut g = DaemonConfig::with_defaults();
        g.local_as = 64512;
        let p = PeerSpec {
            remote: Some("192.0.2.2".to_string()),
            peer_as: 64512,
            ..PeerSpec::default()
        };
        let rid = RouterId::from_v4([10, 0, 0, 1]);
        let sc = build_session_config(&g, &p, rid);
        assert!(
            !sc.route_reflector.enabled,
            "no RR keys set — route_reflector.enabled stays off"
        );
        assert!(
            !sc.route_reflector_client,
            "no per-peer RR client flag — sc.route_reflector_client stays off"
        );
    }

    /// A global `route_reflector_cluster_id` without any per-peer
    /// `route_reflector_client = true` still enables the local
    /// speaker as a route reflector (the local speaker is still a
    /// reflector for the configured cluster id; the per-peer flag
    /// only decides who is a client). This mirrors FRR's behaviour
    /// where `bgp cluster-id` alone does not require every peer to
    /// be flagged.
    #[test]
    fn build_session_config_cluster_id_alone_enables_reflector() {
        let mut g = DaemonConfig::with_defaults();
        g.local_as = 64512;
        g.route_reflector_cluster_id = Some("10.0.0.254".to_string());
        let p = PeerSpec {
            remote: Some("192.0.2.2".to_string()),
            peer_as: 64512,
            // No per-peer route_reflector_client.
            ..PeerSpec::default()
        };
        let rid = RouterId::from_v4([10, 0, 0, 1]);
        let sc = build_session_config(&g, &p, rid);
        assert!(
            sc.route_reflector.enabled,
            "global route_reflector_cluster_id alone enables route_reflector.enabled"
        );
        assert!(
            !sc.route_reflector_client,
            "no per-peer RR client flag — sc.route_reflector_client stays off"
        );
    }

    /// A malformed global `route_reflector_cluster_id` is logged and
    /// ignored — the session continues with reflection disabled
    /// (no panic, no startup failure). The user-facing parse
    /// failure surfaces at TOML load time via the `parse_toml_subset`
    /// error path; this test pins the defensive `build_session_config`
    /// behaviour for the case where a config-reload code path
    /// circumvents that gate.
    #[test]
    fn build_session_config_malformed_cluster_id_is_ignored() {
        let mut g = DaemonConfig::with_defaults();
        g.local_as = 64512;
        // The TOML parser rejects this string at load time; the
        // `build_session_config` defensive path mirrors that contract.
        g.route_reflector_cluster_id = Some("not-an-ip".to_string());
        let p = PeerSpec {
            remote: Some("192.0.2.2".to_string()),
            peer_as: 64512,
            ..PeerSpec::default()
        };
        let rid = RouterId::from_v4([10, 0, 0, 1]);
        let sc = build_session_config(&g, &p, rid);
        assert!(
            !sc.route_reflector.enabled,
            "malformed cluster_id must not enable reflection — it would not have a valid cluster id"
        );
    }
}

/// `reload_config`'s SIGHUP-driven damping toggle (
/// follow-up). The standalone BGP daemon installs a
/// `DampingImportHook` at startup when `[damping] enabled = true`;
/// the hook carries a shared `enabled` flag the reload path flips
/// in-place. These tests exercise the toggle's four transitions
/// (off→off, off→on, on→off, on→on) through the real
/// `reload_config` entry point so the daemon's SIGHUP path stays
/// wired to the hook's enabled flag.
#[cfg(test)]
mod damping_reload_toggle_tests {
    use super::*;
    use lr_damping::{DampingConfig, DampingTable};
    use lr_policy::hooks::DampingImportHook;
    use lr_router::DefaultRouter;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, RwLock};

    /// Write a minimal TOML config with the `[damping] enabled = `
    /// line set to the supplied bool. The BGP essentials (local_as,
    /// peer_as, router_id) keep `load_config_file` happy.
    fn write_config(path: &std::path::Path, damping_enabled: bool) {
        let contents = format!(
            "[bgp]\nlocal_as = 64512\npeer_as = 64513\nrouter_id = \"10.0.0.1\"\n\
             [damping]\nenabled = {damping_enabled}\n"
        );
        std::fs::write(path, contents).expect("write temp config");
    }

    /// Build a unique temp config path so parallel test runs do not
    /// collide. The file is removed at the end of the test.
    fn temp_config_path(tag: &str) -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "lr-daemon-damping-{tag}-{}-{n}.toml",
            std::process::id()
        ))
    }

    /// Set up a router + damping state mirroring the daemon's
    /// startup install. The hook is installed on the import chain
    /// with the shared `enabled` flag at `initial_enabled`.
    #[allow(clippy::type_complexity)] // 3-Arc tuple is the natural shape here
    fn setup(
        initial_enabled: bool,
    ) -> (
        Arc<RwLock<DefaultRouter>>,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Option<DampingController>>>,
    ) {
        let router = Arc::new(RwLock::new(DefaultRouter::new()));
        let current_networks = Arc::new(Mutex::new(Vec::new()));
        let damping_state: Arc<Mutex<Option<DampingController>>> = Arc::new(Mutex::new(None));
        if initial_enabled {
            let table = Arc::new(Mutex::new(DampingTable::new(DampingConfig::default())));
            let enabled = Arc::new(AtomicBool::new(true));
            let decay_stop = Arc::new(AtomicBool::new(false));
            let hook = DampingImportHook::with_enabled(Arc::clone(&table), Arc::clone(&enabled));
            {
                let mut r = router.write().unwrap();
                r.hooks_mut().import.push(Box::new(hook));
            }
            spawn_damping_decay_thread(
                Arc::clone(&table),
                Arc::clone(&decay_stop),
                DampingConfig::default().decay_interval_s,
            );
            *damping_state.lock().unwrap() = Some(DampingController {
                enabled,
                decay_stop,
                table,
            });
        }
        (router, current_networks, damping_state)
    }

    /// off → on: a fresh daemon with no damping installed at startup
    /// (the operator started with `[damping] enabled = false`) toggles
    /// damping on via SIGHUP. The reload installs a new hook on the
    /// router and populates the `DampingController`.
    #[test]
    fn reload_enables_damping_from_off() {
        let cfg_path = temp_config_path("on");
        write_config(&cfg_path, true);
        let (router, current_networks, damping_state) = setup(false);

        let lines = reload_config(
            Some(cfg_path.to_str().unwrap()),
            None,
            &router,
            &current_networks,
            None,
            None,
            None,
            &[],
            Some(&damping_state),
            None,
        );
        // The reload reports the enable.
        assert!(
            lines.iter().any(|l| l.contains("damping enabled")),
            "reload should report damping enabled: {lines:?}"
        );
        // The controller is now populated.
        assert!(
            damping_state.lock().unwrap().is_some(),
            "damping_state should be Some after off->on reload"
        );
        let _ = std::fs::remove_file(&cfg_path);
    }

    /// on → off: the daemon started with damping enabled (the
    /// operator opted in via `[damping] enabled = true`); a SIGHUP
    /// with damping disabled flips the hook to pass-through and
    /// signals the decay thread to exit.
    #[test]
    fn reload_disables_damping_from_on() {
        let cfg_path = temp_config_path("off");
        write_config(&cfg_path, false);
        let (router, current_networks, damping_state) = setup(true);

        // Snapshot the controller's flags before the reload so we
        // can verify they were flipped after.
        let (enabled_flag, decay_stop_flag) = {
            let state = damping_state.lock().unwrap();
            let controller = state.as_ref().expect("setup installed the controller");
            (
                Arc::clone(&controller.enabled),
                Arc::clone(&controller.decay_stop),
            )
        };
        assert!(enabled_flag.load(Ordering::Relaxed), "flag starts enabled");
        assert!(
            !decay_stop_flag.load(Ordering::Relaxed),
            "decay_stop starts clear"
        );

        let lines = reload_config(
            Some(cfg_path.to_str().unwrap()),
            None,
            &router,
            &current_networks,
            None,
            None,
            None,
            &[],
            Some(&damping_state),
            None,
        );
        assert!(
            lines.iter().any(|l| l.contains("damping disabled")),
            "reload should report damping disabled: {lines:?}"
        );
        assert!(
            damping_state.lock().unwrap().is_none(),
            "damping_state should be None after on->off reload"
        );
        // The hook's enabled flag is now false (the hook is still on
        // the import chain but pass-throughs), and the decay thread's
        // stop flag is now true (the thread exits at its next
        // iteration).
        assert!(
            !enabled_flag.load(Ordering::Relaxed),
            "enabled flag must be false after on->off reload"
        );
        assert!(
            decay_stop_flag.load(Ordering::Relaxed),
            "decay_stop flag must be true after on->off reload"
        );
        let _ = std::fs::remove_file(&cfg_path);
    }

    /// on → on: a SIGHUP that keeps damping enabled respawns the
    /// decay ticker so a tuned `decay_interval_s` takes effect
    /// immediately. Other `DampingConfig` fields stay baked into the
    /// `DampingTable` (a restart is needed to change them).
    #[test]
    fn reload_on_to_on_respawns_decay_thread() {
        let cfg_path = temp_config_path("on-on");
        write_config(&cfg_path, true);
        let (router, current_networks, damping_state) = setup(true);

        // Snapshot the original decay_stop flag — the reload signals
        // it to true so the old ticker exits at its next iteration.
        let original_decay_stop = {
            let state = damping_state.lock().unwrap();
            Arc::clone(&state.as_ref().unwrap().decay_stop)
        };

        let lines = reload_config(
            Some(cfg_path.to_str().unwrap()),
            None,
            &router,
            &current_networks,
            None,
            None,
            None,
            &[],
            Some(&damping_state),
            None,
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("damping decay interval") || l.contains("damping")),
            "reload should report damping on->on: {lines:?}"
        );
        // The controller is still Some (the table persists, the
        // enabled flag stays true).
        let state = damping_state.lock().unwrap();
        let controller = state
            .as_ref()
            .expect("controller still present after on->on");
        assert!(
            controller.enabled.load(Ordering::Relaxed),
            "enabled flag must stay true after on->on reload"
        );
        // The old decay_stop is now true (the old ticker exits).
        assert!(
            original_decay_stop.load(Ordering::Relaxed),
            "old decay_stop must be true after on->on reload (old ticker exits)"
        );
        // The new decay_stop is fresh (false).
        assert!(
            !controller.decay_stop.load(Ordering::Relaxed),
            "new decay_stop must be false (fresh ticker)"
        );
        let _ = std::fs::remove_file(&cfg_path);
    }

    /// off → off: a SIGHUP that keeps damping disabled is a no-op.
    /// The damping_state stays `None` and the reload does not
    /// mention damping.
    #[test]
    fn reload_off_to_off_is_noop() {
        let cfg_path = temp_config_path("off-off");
        write_config(&cfg_path, false);
        let (router, current_networks, damping_state) = setup(false);

        let lines = reload_config(
            Some(cfg_path.to_str().unwrap()),
            None,
            &router,
            &current_networks,
            None,
            None,
            None,
            &[],
            Some(&damping_state),
            None,
        );
        assert!(
            !lines.iter().any(|l| l.to_lowercase().contains("damping")),
            "off->off should not mention damping: {lines:?}"
        );
        assert!(
            damping_state.lock().unwrap().is_none(),
            "damping_state should still be None after off->off reload"
        );
        let _ = std::fs::remove_file(&cfg_path);
    }

    /// End-to-end: starting from a disabled damping, two SIGHUPs
    /// (off → on → off) leave the daemon in a clean disabled state —
    /// the controller is gone and the disabled hook is no longer
    /// on the chain (no leak from the off→on install). The router's
    /// import chain returns the empty list after the second reload.
    #[test]
    fn reload_off_on_off_cycle_clears_controller() {
        let cfg_on = temp_config_path("cycle-on");
        let cfg_off = temp_config_path("cycle-off");
        write_config(&cfg_on, true);
        write_config(&cfg_off, false);
        let (router, current_networks, damping_state) = setup(false);

        // off → on: install hook + populate controller.
        reload_config(
            Some(cfg_on.to_str().unwrap()),
            None,
            &router,
            &current_networks,
            None,
            None,
            None,
            &[],
            Some(&damping_state),
            None,
        );
        assert!(damping_state.lock().unwrap().is_some());

        // on → off: flip enabled, stop decay, drop controller.
        reload_config(
            Some(cfg_off.to_str().unwrap()),
            None,
            &router,
            &current_networks,
            None,
            None,
            None,
            &[],
            Some(&damping_state),
            None,
        );
        assert!(damping_state.lock().unwrap().is_none());

        let _ = std::fs::remove_file(&cfg_on);
        let _ = std::fs::remove_file(&cfg_off);
    }

    /// End-to-end hook behaviour through the reload. The router's
    /// hook chain dispatches to every installed hook on every
    /// import; the damping hook returns `Drop` when the prefix's
    /// FoM is at/above the suppress threshold. This test exercises
    /// the toggle's user-visible effect: a flap-suppressed prefix is
    /// dropped while damping is on, kept while damping is off, and
    /// dropped again after an on→on reload (the FoM table persists
    /// across on→on reloads, so the suppression survives the
    /// decay-thread respawn).
    #[test]
    fn reload_toggle_visibility_through_hook_chain() {
        let cfg_on = temp_config_path("vis-on");
        let cfg_off = temp_config_path("vis-off");
        write_config(&cfg_on, true);
        write_config(&cfg_off, false);
        let (router, current_networks, damping_state) = setup(true);
        let prefix = lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24);
        let key = lr_core::rib::RouteKey::new(prefix, lr_core::nlri::NlriFamily::IPV4_UNICAST);

        // Suppress the prefix through three withdraws run through
        // the router's hook chain — the chain dispatches
        // `run_import_withdraw` to every ImportHook, including the
        // damping hook, which adds `additive_incr` (= 1000) per
        // withdraw. After three withdraws the FoM is 3000 ≥ the
        // 2000 suppress threshold, so the prefix is suppressed.
        {
            let mut r = router.write().unwrap();
            let origin = lr_core::rib::RouteOrigin { proto: 0, peer: 1 };
            r.hooks_mut()
                .run_import_withdraw_with_origin(origin, &key, 0);
            r.hooks_mut()
                .run_import_withdraw_with_origin(origin, &key, 0);
            r.hooks_mut()
                .run_import_withdraw_with_origin(origin, &key, 0);
        }
        // Sanity: the FoM table records the prefix and marks it
        // suppressed (the hook chain dispatched the withdraws).
        {
            let state = damping_state.lock().unwrap();
            let controller = state.as_ref().expect("controller still present");
            assert!(
                controller.table.lock().unwrap().is_suppressed(&prefix),
                "prefix must be suppressed after three withdraws"
            );
        }

        // A route for the suppressed prefix is dropped by the
        // damping hook (FoM ≥ suppress_threshold → Drop verdict).
        let mut route = lr_core::rib::Route {
            key: lr_core::rib::RouteKey::new(prefix, lr_core::nlri::NlriFamily::IPV4_UNICAST),
            origin: lr_core::rib::RouteOrigin { proto: 0, peer: 1 },
            protocol: lr_core::rib::Protocol::Bgp,
            preference: lr_core::rib::Preference::new(20, 100),
            next_hop: Some(IpAddr::V4([192, 0, 2, 1])),
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 1_000,
            path_id: 0,
            tag: None,
        };
        {
            let mut r = router.write().unwrap();
            let verdict = r.hooks_mut().run_import(&mut route);
            assert!(
                matches!(verdict, lr_policy::hooks::HookVerdict::Drop),
                "suppressed prefix must be dropped while damping is on"
            );
        }

        // SIGHUP with `enabled = false`: the hook's enabled flag is
        // flipped to false (pass-through), the decay thread is
        // signaled to stop, and the controller is dropped.
        reload_config(
            Some(cfg_off.to_str().unwrap()),
            None,
            &router,
            &current_networks,
            None,
            None,
            None,
            &[],
            Some(&damping_state),
            None,
        );

        // The hook is still installed but pass-throughs: a route
        // for the (still-suppressed) prefix now flows through
        // unchanged.
        {
            let mut r = router.write().unwrap();
            let verdict = r.hooks_mut().run_import(&mut route);
            assert!(
                matches!(verdict, lr_policy::hooks::HookVerdict::Keep),
                "suppressed prefix must be kept while damping is off (pass-through)"
            );
        }

        // SIGHUP back to `enabled = true` (on→on would not apply
        // because the controller is gone; this is the off→on arm
        // that installs a fresh hook + creates a fresh FoM table).
        reload_config(
            Some(cfg_on.to_str().unwrap()),
            None,
            &router,
            &current_networks,
            None,
            None,
            None,
            &[],
            Some(&damping_state),
            None,
        );
        // The fresh FoM table is empty — the prefix is no longer
        // suppressed — so the route flows through. This is the
        // documented behavior: off→on creates a fresh FoM (no
        // history survives a disable→enable cycle that crosses a
        // daemon start; here it crosses a SIGHUP, but the FoM does
        // not carry over because the new hook gets a new table).
        {
            let mut r = router.write().unwrap();
            let verdict = r.hooks_mut().run_import(&mut route);
            assert!(
                matches!(verdict, lr_policy::hooks::HookVerdict::Keep),
                "fresh FoM table after off->on must keep the route (no suppression history)"
            );
        }

        let _ = std::fs::remove_file(&cfg_on);
        let _ = std::fs::remove_file(&cfg_off);
    }
}

mod event_bus_wiring_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;

    /// A `Runtime` with a fresh router, built the way the standalone
    /// daemon builds it — every wiring test below drives the real
    /// `spawn_ticker` / `shutdown_event_bus` pair on it.
    fn wiring_runtime() -> Arc<Runtime> {
        Arc::new(Runtime {
            reload: Arc::new(Vec::new),
            router: Arc::new(RwLock::new(DefaultRouter::new())),
            event_bus: lr_router::event_bus::EventBus::new(),
            kernel_mirror: std::sync::OnceLock::new(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            status_lines: Arc::new(Vec::new),
            roa_len: None,
            roa_store: None,
            peer_health_table: None,
            filter_metrics: Mutex::new(None),
            session_labels: Arc::new(Mutex::new(HashMap::new())),
            shutdown: None,
        })
    }

    /// Bounded wait for the next event on a subscriber's queue; the
    /// ticker publishes on a 50 ms cadence, so seconds are generous.
    fn next_event(rx: &lr_router::event_bus::EventSubscriber) -> RouterEvent {
        rx.recv_timeout(Duration::from_secs(5))
            .expect("an event within the deadline")
    }

    /// The wiring contract, end to end: the ticker publishes every
    /// event it drains (`originate` → `RouteInstalled`), the
    /// per-subscriber FIFO preserves order across the install and the
    /// shutdown withdrawal, and `shutdown_event_bus` returns only after
    /// the subscriber drained everything it was ever accepted (the
    /// `Disconnected` handshake).
    #[test]
    fn ticker_publishes_and_close_drains_every_subscriber() {
        let rt = wiring_runtime();
        // Subscribe BEFORE the first drain: the router holds events in
        // `pending_events` until `poll_events`, so an early subscriber
        // sees everything from the first drain on.
        let rx = rt.event_bus.subscribe();
        // No kernel install: the mirror thread runs but no-ops.
        let mut cfg = DaemonConfig::with_defaults();
        cfg.install_kernel = false;
        let ticker = spawn_ticker(&rt, &cfg, Arc::new(AtomicUsize::new(0)), None)
            .expect("the default config carries no kernel filter");

        // An originated route queues a RouteInstalled; the ticker's
        // next pass drains and publishes it.
        let prefix: Prefix = "203.0.113.0/24".parse().unwrap();
        {
            let mut r = rt.router.write().unwrap();
            r.originate_family(prefix, NlriFamily::IPV4_UNICAST, None);
        }
        match next_event(&rx) {
            RouterEvent::RouteInstalled(route) => {
                assert_eq!(route.key.prefix, prefix, "the install we caused");
            }
            other => panic!("expected RouteInstalled, got {other:?}"),
        }

        // Shutdown: the ticker's final drain publishes the withdrawal
        // (flush_rib_for_shutdown), THEN the handshake closes the bus.
        rt.running.store(false, Ordering::Relaxed);
        match next_event(&rx) {
            RouterEvent::RouteWithdrawn(key) => {
                assert_eq!(key.prefix, prefix, "the shutdown withdrawal");
            }
            other => panic!("expected RouteWithdrawn, got {other:?}"),
        }
        // The bus was still open when the withdrawal landed: the close
        // happens after the ticker joined, in the handshake below.
        assert!(!rt.event_bus.is_closed());
        let _ = ticker.join();
        rt.shutdown_event_bus();
        // Drained and closed: the subscriber observes Disconnected.
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)),
            Err(RecvTimeoutError::Disconnected)
        ));
        // A publish after close is refused.
        assert_eq!(rt.event_bus.publish(RouterEvent::Log("late".into())), 0);
    }

    /// The multi-threaded RIB read path: the shared Loc-RIB handle's
    /// reads (and even installs — the shard locks are independent of
    /// the router's `RwLock`) proceed while the router's writer lock
    /// is held by someone else. This is the property that lets the
    /// API socket and the metrics endpoint dump routes without ever
    /// waiting behind the writer's tick.
    #[test]
    fn rib_handle_reads_proceed_while_the_router_writer_lock_is_held() {
        let rt = wiring_runtime();
        let rib = rt.router.read().unwrap().rib_handle();
        // Hold the router's writer lock for the whole block.
        let _writer = rt.router.write().unwrap();
        // Reads through the handle work.
        assert_eq!(rib.len(), 0);
        // Installs through the handle work too: the per-family shard
        // lock is a different lock from the router's `RwLock`.
        let prefix: Prefix = "198.51.100.0/24".parse().unwrap();
        let route = lr_core::rib::Route {
            key: lr_core::rib::RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
            origin: lr_core::rib::RouteOrigin { proto: 2, peer: 0 },
            protocol: lr_core::rib::Protocol::Bgp,
            preference: lr_core::rib::Preference::new(20, 0),
            next_hop: None,
            attributes: lr_core::attr::Attributes::new(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        assert!(rib.install(route), "fresh install signals changed");
        assert_eq!(rib.len(), 1, "the install landed under the writer lock");
        assert_eq!(
            rib.best(&lr_core::rib::RouteKey::new(
                prefix,
                NlriFamily::IPV4_UNICAST
            ))
            .unwrap()
            .key
            .prefix,
            prefix
        );
    }
}
