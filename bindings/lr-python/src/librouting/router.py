"""High-level router handle."""

from __future__ import annotations

from ._ffi import ffi, get_lib, alloc_bytes, free_bytes, copy_bytes

# Wire protocol identifiers (mirrors LrProtocol in lr_ffi.h).
PROTO_BGP = 0
PROTO_OSPF = 1
PROTO_OSPF3 = 2
PROTO_BABEL = 3
PROTO_STATIC = 4
PROTO_CONNECTED = 5

# Metric transformation for redistribution pipes.
METRIC_INHERIT = 0
METRIC_FIXED = 1
METRIC_ADD = 2


class LrError(Exception):
    pass


class Router:
    """A librouting router instance."""

    def __init__(self):
        lib = get_lib()
        ptr = lib.lr_router_new()
        if ptr == ffi.NULL:
            raise LrError("lr_router_new returned NULL")
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None:
            get_lib().lr_router_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def add_bgp_session(self, local_as: int, peer_as: int, local_bgp_id: int,
                        hold_time: int = 90, keepalive: int = 0, asn4: bool = True,
                        graceful_restart: bool = True, gr_restart_time: int = 120,
                        long_lived_gr: bool = False, llgr_stale_time: int = 0,
                        llgr_max_stale_time: int = 0) -> int:
        """Add a BGP session and return its handle.

        ``gr_restart_time`` is the RFC 4724 restart time in seconds.
        ``llgr_stale_time`` is the RFC 9494 long-lived stale time in
        seconds; LLGR requires GR (RFC 9494 §4.1), so it is only
        advertised when ``graceful_restart`` is set.
        ``llgr_max_stale_time`` optionally caps the stale time received
        from the peer (0 = honour the peer's value).
        """
        h = ffi.new("uint64_t*")
        rc = get_lib().lr_router_add_bgp_session_ext(
            self._ptr,
            int(local_as), int(peer_as), int(local_bgp_id),
            int(hold_time), int(keepalive), 1 if asn4 else 0,
            1 if graceful_restart else 0, int(gr_restart_time),
            1 if long_lived_gr else 0, int(llgr_stale_time),
            int(llgr_max_stale_time),
            h,
        )
        if rc != 0:
            raise LrError(f"lr_router_add_bgp_session failed (rc={rc}): {last_error()}")
        return int(h[0])

    # OSPF area kinds (LR_AREA_*).
    AREA_NORMAL = 0
    AREA_STUB = 1
    AREA_STUB_NO_SUMMARY = 2
    AREA_NSSA = 3
    AREA_NSSA_NO_SUMMARY = 4

    # OSPF interface network types (LR_NET_*).
    NET_PTP = 0
    NET_BROADCAST = 1

    # OSPF protocol versions (LR_OSPF_*).
    OSPF_V2 = 2
    OSPF_V3 = 3

    def add_ospf_session(self, router_id: int, area_id: int) -> int:
        """Add an OSPFv2 session with the library defaults (MTU 1500,
        point-to-point network, Normal area) and return its handle."""
        h = ffi.new("uint64_t*")
        rc = get_lib().lr_router_add_ospf_session(self._ptr, int(router_id), int(area_id), h)
        if rc != 0:
            raise LrError(f"lr_router_add_ospf_session failed (rc={rc}): {last_error()}")
        return int(h[0])

    def add_ospfv3_session(self, router_id: int, area_id: int) -> int:
        """Add an OSPFv3 session (RFC 5340) with the library defaults and
        return its handle. Router IDs stay 32-bit and are shared with
        OSPFv2 within one router; areas are version-exclusive."""
        h = ffi.new("uint64_t*")
        rc = get_lib().lr_router_add_ospfv3_session(self._ptr, int(router_id), int(area_id), h)
        if rc != 0:
            raise LrError(f"lr_router_add_ospfv3_session failed (rc={rc}): {last_error()}")
        return int(h[0])

    def add_ospf_session_ext(self, version: int, router_id: int, area_id: int,
                             area_kind: int = 0, default_metric: int = 0,
                             mtu: int = 1500, network_type: int = 0,
                             interface_ip: int | None = None,
                             neighbor_ip: int | None = None) -> int:
        """Add an OSPF session with the full knob set and return its handle.

        ``version`` is ``OSPF_V2`` or ``OSPF_V3``; ``area_kind`` one of the
        ``AREA_*`` constants (the stub/NSSA kinds inject a default route
        with ``default_metric``); ``network_type`` is ``NET_PTP`` or
        ``NET_BROADCAST`` (RFC 2328 §9.1). ``interface_ip`` /
        ``neighbor_ip`` are the §10.4 segment identities as 32-bit IPv4
        integers (the v2 interface address / the v3 Router ID); ``None``
        leaves them unset.
        """
        h = ffi.new("uint64_t*")
        rc = get_lib().lr_router_add_ospf_session_ext(
            self._ptr,
            int(version), int(router_id), int(area_id),
            int(area_kind), int(default_metric), int(mtu), int(network_type),
            0 if interface_ip is None else 1, int(interface_ip or 0),
            0 if neighbor_ip is None else 1, int(neighbor_ip or 0),
            h,
        )
        if rc != 0:
            raise LrError(f"lr_router_add_ospf_session_ext failed (rc={rc}): {last_error()}")
        return int(h[0])

    def add_babel_session(self, addr: bytes) -> int:
        """Add one Babel interface session (RFC 8966 §4.2.1) and return
        its handle. ``addr`` is the 4-byte IPv4 or 16-byte IPv6 local
        address announced in Hellos."""
        if len(addr) not in (4, 16):
            raise LrError("add_babel_session: bad address length (want 4 or 16)")
        h = ffi.new("uint64_t*")
        rc = get_lib().lr_router_add_babel_session(
            self._ptr, addr, 1 if len(addr) == 16 else 0, h,
        )
        if rc != 0:
            raise LrError(f"lr_router_add_babel_session failed (rc={rc}): {last_error()}")
        return int(h[0])

    def feed_input(self, session: int, data: bytes) -> None:
        if not data:
            return
        rc = get_lib().lr_router_feed_input(self._ptr, int(session), data, len(data))
        if rc != 0:
            raise LrError(f"lr_router_feed_input failed (rc={rc}): {last_error()}")

    def drain_output(self, session: int) -> bytes:
        b = alloc_bytes()
        rc = get_lib().lr_router_drain_output(self._ptr, int(session), b)
        if rc != 0:
            raise LrError(f"lr_router_drain_output failed (rc={rc}): {last_error()}")
        try:
            return copy_bytes(b)
        finally:
            free_bytes(b)

    def tick(self, now_ms: int) -> None:
        rc = get_lib().lr_router_tick(self._ptr, int(now_ms))
        if rc != 0:
            raise LrError(f"lr_router_tick failed (rc={rc}): {last_error()}")

    def start_session(self, session: int) -> None:
        """Begin protocol operation (BGP: ManualStart + TransportOpen)."""
        rc = get_lib().lr_router_start_session(self._ptr, int(session))
        if rc != 0:
            raise LrError(f"lr_router_start_session failed (rc={rc}): {last_error()}")

    def set_mrai(self, session: int, interval_ms: int) -> None:
        """Set the per-prefix RFC 4271 UPDATE batching interval in milliseconds.

        Set ``interval_ms`` to zero to disable batching and flush pending updates.
        """
        rc = get_lib().lr_router_set_mrai(self._ptr, int(session), int(interval_ms))
        if rc != 0:
            raise LrError(f"lr_router_set_mrai failed (rc={rc}): {last_error()}")

    def set_add_path(self, session: int, enabled: bool) -> None:
        """Enable or disable RFC 7911 Add-Path on one BGP session.

        Call after ``add_bgp_session`` and before ``start_session`` — the
        capability is negotiated in OPEN. The peer must also offer
        Add-Path; see :meth:`set_add_path_max_paths`.
        """
        rc = get_lib().lr_router_set_add_path(
            self._ptr, int(session), 1 if enabled else 0
        )
        if rc != 0:
            raise LrError(f"lr_router_set_add_path failed (rc={rc}): {last_error()}")

    def set_add_path_max_paths(self, max_paths: int) -> None:
        """Cap how many paths per prefix the RFC 7911 decision process keeps.

        Router-wide; values below 1 are clamped to 1 (single-path).
        """
        rc = get_lib().lr_router_set_add_path_max_paths(self._ptr, int(max_paths))
        if rc != 0:
            raise LrError(
                f"lr_router_set_add_path_max_paths failed (rc={rc}): {last_error()}"
            )

    def set_ebgp_requires_policy(self, enabled: bool) -> None:
        """Enable or disable the RFC 8212 default eBGP route behaviors.

        When enabled, an external BGP session (eBGP or a confederation
        boundary) with no explicit import policy declared via
        :meth:`set_session_policy` discards received routes, and one with
        no export policy advertises nothing (RFC 8212 §3).
        """
        rc = get_lib().lr_router_set_ebgp_requires_policy(
            self._ptr, 1 if enabled else 0
        )
        if rc != 0:
            raise LrError(
                f"lr_router_set_ebgp_requires_policy failed (rc={rc}): {last_error()}"
            )

    def set_enforce_first_as(self, enabled: bool) -> None:
        """Enable or disable FRR ``bgp enforce-first-as`` (W2.2).

        When enabled, an UPDATE received from an external BGP peer (eBGP
        or a confederation boundary) whose AS_PATH leftmost sequence
        segment's first AS is not the peer's negotiated AS is rejected
        before the Adj-RIB-In. When off (the default —
        ``no bgp enforce-first-as``), the route is admitted subject to the
        ordinary policy and safety checks. iBGP and confederation-internal
        sessions are exempt, mirroring FRR.
        """
        rc = get_lib().lr_router_set_enforce_first_as(
            self._ptr, 1 if enabled else 0
        )
        if rc != 0:
            raise LrError(
                f"lr_router_set_enforce_first_as failed (rc={rc}): {last_error()}"
            )

    def set_session_policy(self, session: int, import_: bool, export: bool) -> None:
        """Declare which directions of a BGP session carry explicit policy.

        RFC 8212 §3: a direction left false is subject to the default
        deny when :meth:`set_ebgp_requires_policy` is active. The policy
        itself runs through the hook chain. Unknown session handles
        raise.
        """
        rc = get_lib().lr_router_set_session_policy(
            self._ptr,
            int(session),
            1 if import_ else 0,
            1 if export else 0,
        )
        if rc != 0:
            raise LrError(
                f"lr_router_set_session_policy failed (rc={rc}): {last_error()}"
            )

    def set_extended_next_hop(self, session: int,
                              tuples: list[tuple[int, int, int]] | None = None) -> None:
        """Configure RFC 5549 Extended Next-Hop on a BGP session.

        Each tuple is ``(nlri_afi, nlri_safi, nexthop_afi)`` — the
        canonical entry is ``(1, 1, 2)`` (IPv4 unicast over an IPv6
        next-hop). Pass ``None`` or an empty list to clear.

        Must be called after :meth:`add_bgp_session` and before
        :meth:`start_session` — the capability is negotiated in OPEN.
        """
        if not tuples:
            rc = get_lib().lr_router_set_extended_next_hop(
                self._ptr, int(session), ffi.NULL, 0
            )
        else:
            buf = bytearray()
            for nlri_afi, nlri_safi, nh_afi in tuples:
                buf += int(nlri_afi).to_bytes(2, "big")
                buf += bytes([int(nlri_safi) & 0xFF])
                buf += int(nh_afi).to_bytes(2, "big")
            rc = get_lib().lr_router_set_extended_next_hop(
                self._ptr, int(session), bytes(buf), len(tuples)
            )
        if rc != 0:
            raise LrError(
                f"lr_router_set_extended_next_hop failed (rc={rc}): {last_error()}"
            )

    def set_mp_families(self, session: int,
                        families: list[tuple[int, int]] | None = None) -> None:
        """Override the MP-BGP address families advertised in OPEN.

        Each entry is ``(afi, safi)`` — e.g. ``(1, 1)`` for IPv4 unicast
        and ``(2, 1)`` for IPv6 unicast. Pass ``None`` or empty to clear
        (the session then advertises no MP-BGP families).
        """
        if not families:
            rc = get_lib().lr_router_set_mp_families(
                self._ptr, int(session), ffi.NULL, 0
            )
        else:
            buf = bytearray()
            for afi, safi in families:
                buf += int(afi).to_bytes(2, "big")
                buf += bytes([0])  # reserved
                buf += bytes([int(safi) & 0xFF])
            rc = get_lib().lr_router_set_mp_families(
                self._ptr, int(session), bytes(buf), len(families)
            )
        if rc != 0:
            raise LrError(
                f"lr_router_set_mp_families failed (rc={rc}): {last_error()}"
            )

    def set_local_address(self, session: int, addr: str) -> None:
        """Set the local source address for next-hop-self egress.

        Accepts an IPv4 or IPv6 literal. For RFC 5549 ENH egress over
        IPv6 pass an IPv6 literal. Must be called before
        :meth:`start_session`.
        """
        import ipaddress
        ip = ipaddress.ip_address(addr)
        family = 1 if ip.version == 4 else 2
        packed = ip.packed
        rc = get_lib().lr_router_set_local_address(
            self._ptr, int(session), int(family), packed, len(packed)
        )
        if rc != 0:
            raise LrError(
                f"lr_router_set_local_address failed (rc={rc}): {last_error()}"
            )

    def set_default_ipv4_unicast(self, session: int, enabled: bool) -> None:
        """Configure FRR ``bgp default ipv4-unicast`` (W2.1) for one session.

        When ``enabled`` is ``True`` (the default), IPv4 unicast is
        implicitly active even when :meth:`set_mp_families` did not list
        it. When ``False``, IPv4 unicast must be added explicitly via
        :meth:`set_mp_families` to be active — the FRR
        ``no bgp default ipv4-unicast`` posture. Must be called before
        :meth:`start_session`; unknown handles or already-established
        sessions raise :class:`LrError`.
        """
        rc = get_lib().lr_router_set_default_ipv4_unicast(
            self._ptr, int(session), 1 if enabled else 0
        )
        if rc != 0:
            raise LrError(
                f"lr_router_set_default_ipv4_unicast failed (rc={rc}): {last_error()}"
            )

    def set_local_as_tolerance(self, session: int, tolerance: int) -> None:
        """Configure FRR ``neighbor X allowas-in N`` / BIRD ``allow local as`` (W2.3).

        ``tolerance = 0`` (the default) rejects any occurrence of the
        local AS in a received AS_PATH (RFC 4271 §9.1.2.15). ``N > 0``
        admits a route whose AS_PATH contains the local AS up to N
        times (FRR ``allowas-in N``, default N=1).
        ``tolerance = 0xFFFFFFFF`` (``math.inf``-equivalent for the
        unsigned 32-bit field) admits any number (FRR ``allowas-any``).
        iBGP is exempt. Must be called before :meth:`start_session`;
        unknown handles or already-established sessions raise
        :class:`LrError`.
        """
        if tolerance < 0 or tolerance > 0xFFFFFFFF:
            raise LrError(
                f"tolerance out of range [0, 0xFFFFFFFF]: {tolerance}"
            )
        rc = get_lib().lr_router_set_local_as_tolerance(
            self._ptr, int(session), int(tolerance)
        )
        if rc != 0:
            raise LrError(
                f"lr_router_set_local_as_tolerance failed (rc={rc}): {last_error()}"
            )

    def set_soft_reconfig_inbound(self, session: int, enabled: bool) -> None:
        """Configure FRR ``neighbor X soft-reconfiguration inbound`` (W2.4).

        When ``enabled`` is ``True``, the router retains the
        pre-policy Adj-RIB-In for this session — the raw received
        routes before the import hook chain runs — so
        :meth:`soft_reconfig_inbound` can re-evaluate the policy
        without re-fetching from the peer (``clear ip bgp * soft
        in``). Off by default (FRR's default; the cost is duplicate
        RIB memory per peer). Must be called before
        :meth:`start_session`; unknown handles or already-established
        sessions raise :class:`LrError`.
        """
        rc = get_lib().lr_router_set_soft_reconfig_inbound(
            self._ptr, int(session), 1 if enabled else 0
        )
        if rc != 0:
            raise LrError(
                f"lr_router_set_soft_reconfig_inbound failed (rc={rc}): {last_error()}"
            )

    def soft_reconfig_inbound(self, session: int) -> int:
        """FRR ``clear ip bgp * soft in`` (W2.4).

        Re-evaluate the import policy against the pre-policy
        Adj-RIB-In for this session, replacing the session's entries
        in the post-policy RIB with the re-imported routes. Returns
        the number of routes re-evaluated. No-ops (returns 0) when
        the session did not have :meth:`set_soft_reconfig_inbound`
        enabled — the pre-policy RIB was not retained. Unknown
        handles raise :class:`LrError`.
        """
        rc = get_lib().lr_router_soft_reconfig_inbound(self._ptr, int(session))
        if rc < 0:
            raise LrError(
                f"lr_router_soft_reconfig_inbound failed (rc={rc}): {last_error()}"
            )
        return int(rc)

    def request_route_refresh(self, session: int, afi: int = 1, safi: int = 1) -> bool:
        """Ask an established BGP peer to resend an RFC 2918 address family.

        Returns ``False`` if the peer did not negotiate route refresh.
        """
        rc = get_lib().lr_router_request_route_refresh(
            self._ptr, int(session), int(afi), int(safi)
        )
        if rc < 0:
            raise LrError(
                f"lr_router_request_route_refresh failed (rc={rc}): {last_error()}"
            )
        return bool(rc)

    def originate_v4(self, prefix: str, next_hop: str | None = None) -> None:
        """Originate a local IPv4 route, e.g. originate_v4("203.0.113.0/24", "192.0.2.1")."""
        addr_str, _, plen_str = prefix.partition("/")
        plen = int(plen_str) if plen_str else 32
        parts = addr_str.split(".")
        if len(parts) != 4:
            raise LrError(f"invalid IPv4 prefix: {prefix}")
        try:
            addr = bytes(int(p) for p in parts)
        except ValueError as e:
            raise LrError(f"invalid IPv4 prefix: {prefix}") from e
        if next_hop is not None:
            nh_parts = next_hop.split(".")
            if len(nh_parts) != 4:
                raise LrError(f"invalid next-hop: {next_hop}")
            try:
                nh = bytes(int(p) for p in nh_parts)
            except ValueError as e:
                raise LrError(f"invalid next-hop: {next_hop}") from e
            nh_buf = ffi.new("uint8_t[]", nh)
            rc = get_lib().lr_router_originate_v4(self._ptr, addr, plen, nh_buf)
        else:
            rc = get_lib().lr_router_originate_v4(self._ptr, addr, plen, ffi.NULL)
        if rc != 0:
            raise LrError(f"lr_router_originate_v4 failed (rc={rc}): {last_error()}")

    def originate_v6(self, prefix: str, next_hop: str | None = None) -> None:
        """Originate a local IPv6 unicast route, e.g. originate_v6("2001:db8::/32").

        The route is advertised to established MP-BGP peers via
        MP_REACH_NLRI.
        """
        addr, plen = _parse_v6_prefix(prefix)
        nh_buf = _parse_v6_next_hop(next_hop)
        rc = get_lib().lr_router_originate_v6(self._ptr, addr, plen, nh_buf)
        if rc != 0:
            raise LrError(f"lr_router_originate_v6 failed (rc={rc}): {last_error()}")

    def withdraw_v4(self, prefix: str) -> bool:
        """Withdraw a locally originated IPv4 route (FRR ``no network``).

        Returns ``True`` when a route was withdrawn; ``False`` when the
        prefix was not locally originated (an idempotent no-op, matching
        FRR/BIRD ``no network`` on an absent statement).
        """
        addr, plen = _parse_v4_prefix(prefix)
        rc = get_lib().lr_router_withdraw_v4(self._ptr, addr, plen)
        if rc < 0:
            raise LrError(f"lr_router_withdraw_v4 failed (rc={rc}): {last_error()}")
        return rc == 0

    def withdraw_v6(self, prefix: str) -> bool:
        """Withdraw a locally originated IPv6 unicast route.

        See ``withdraw_v4`` for the semantics and the return value.
        """
        addr, plen = _parse_v6_prefix(prefix)
        rc = get_lib().lr_router_withdraw_v6(self._ptr, addr, plen)
        if rc < 0:
            raise LrError(f"lr_router_withdraw_v6 failed (rc={rc}): {last_error()}")
        return rc == 0

    def install_static_v4(self, prefix: str, next_hop: str | None = None,
                          metric: int = 0, tag: int = 0) -> None:
        """Install a static IPv4 route into the Loc-RIB (BIRD ``protocol
        static``, FRR ``ip route``).

        The route's protocol is ``Static`` and its admin distance is 1,
        so it wins over every dynamic protocol except Connected. Pass
        ``next_hop=None`` to install a blackhole route (FRR ``Null0``,
        BIRD ``blackhole``). ``metric`` is the per-route metric within
        the static protocol (lower wins); ``tag`` is an optional 32-bit
        route tag carried through redistribution pipes (0 means no tag).
        """
        addr, plen = _parse_v4_prefix(prefix)
        nh_buf = _parse_v4_next_hop(next_hop)
        rc = get_lib().lr_router_install_static_v4(
            self._ptr, addr, plen, nh_buf, int(metric), int(tag)
        )
        if rc != 0:
            raise LrError(
                f"lr_router_install_static_v4 failed (rc={rc}): {last_error()}"
            )

    def install_static_v6(self, prefix: str, next_hop: str | None = None,
                          metric: int = 0, tag: int = 0) -> None:
        """Install a static IPv6 route into the Loc-RIB.

        See ``install_static_v4`` for the semantics.
        """
        addr, plen = _parse_v6_prefix(prefix)
        nh_buf = _parse_v6_next_hop(next_hop)
        rc = get_lib().lr_router_install_static_v6(
            self._ptr, addr, plen, nh_buf, int(metric), int(tag)
        )
        if rc != 0:
            raise LrError(
                f"lr_router_install_static_v6 failed (rc={rc}): {last_error()}"
            )

    def uninstall_static_v4(self, prefix: str) -> bool:
        """Remove a previously-installed static IPv4 route.

        Returns ``True`` when a route was removed; ``False`` when the
        prefix was not a static route (an idempotent no-op, matching
        ``withdraw_v4``'s contract).
        """
        addr, plen = _parse_v4_prefix(prefix)
        rc = get_lib().lr_router_uninstall_static_v4(self._ptr, addr, plen)
        if rc < 0:
            raise LrError(
                f"lr_router_uninstall_static_v4 failed (rc={rc}): {last_error()}"
            )
        return rc == 0

    def uninstall_static_v6(self, prefix: str) -> bool:
        """Remove a previously-installed static IPv6 route.

        See ``uninstall_static_v4`` for the semantics and the return value.
        """
        addr, plen = _parse_v6_prefix(prefix)
        rc = get_lib().lr_router_uninstall_static_v6(self._ptr, addr, plen)
        if rc < 0:
            raise LrError(
                f"lr_router_uninstall_static_v6 failed (rc={rc}): {last_error()}"
            )
        return rc == 0

    def originate_labeled_v4(self, prefix: str, labels: list[int],
                              next_hop: str | None = None) -> None:
        """Originate an RFC 8277 labelled IPv4 BGP route (AFI=1, SAFI=4).

        ``labels`` is a list of 20-bit MPLS label values (top of stack
        first); the bottom-of-stack bit is set automatically.
        """
        addr, plen = _parse_v4_prefix(prefix)
        labels_arr = ffi.new("uint32_t[]", [int(v) & 0xfffff for v in labels])
        nh_buf = _parse_v4_next_hop(next_hop)
        rc = get_lib().lr_router_originate_labeled_v4(
            self._ptr, addr, plen, labels_arr, len(labels), nh_buf
        )
        if rc != 0:
            raise LrError(
                f"lr_router_originate_labeled_v4 failed (rc={rc}): {last_error()}"
            )

    def originate_labeled_v6(self, prefix: str, labels: list[int],
                              next_hop: str | None = None) -> None:
        """Originate an RFC 8277 labelled IPv6 BGP route (AFI=2, SAFI=4).

        See ``originate_labeled_v4`` for the label-stack semantics.
        """
        addr, plen = _parse_v6_prefix(prefix)
        labels_arr = ffi.new("uint32_t[]", [int(v) & 0xfffff for v in labels])
        nh_buf = _parse_v6_next_hop(next_hop)
        rc = get_lib().lr_router_originate_labeled_v6(
            self._ptr, addr, plen, labels_arr, len(labels), nh_buf
        )
        if rc != 0:
            raise LrError(
                f"lr_router_originate_labeled_v6 failed (rc={rc}): {last_error()}"
            )

    def poll_events(self, capacity: int = 32) -> list[dict]:
        """Poll up to ``capacity`` pending router events (ROADMAP-v3 D5.5).

        Returns a list of dicts with the fields ``kind`` (int),
        ``session``, ``prefix`` (bytes), ``prefix_len``, ``is_ipv6``,
        ``path_id``, ``count``, ``limit``, ``pct``, ``action`` and
        ``text``. Events beyond the buffer are requeued, so polling
        with a small buffer loses nothing. Transport-plane events
        (outgoing bytes, timers) never surface here.
        """
        if capacity <= 0:
            raise LrError(f"poll_events: capacity must be positive, got {capacity}")
        arr = ffi.new("lr_event_t[]", capacity)
        n = get_lib().lr_router_poll_events(self._ptr, arr, capacity)
        if n < 0:
            raise LrError(f"lr_router_poll_events failed (rc={n}): {last_error()}")
        out = []
        for i in range(n):
            e = arr[i]
            text_end = 0
            while text_end < len(e.text) and e.text[text_end] != 0:
                text_end += 1
            out.append({
                "kind": e.kind,
                "session": e.session,
                "prefix": bytes(e.prefix),
                "prefix_len": e.prefix_len,
                "is_ipv6": e.is_ipv6 != 0,
                "path_id": e.path_id,
                "count": e.count,
                "limit": e.limit,
                "pct": e.pct,
                "action": e.action,
                "text": ffi.unpack(e.text, text_end).decode("utf-8", "replace"),
            })
        return out

    def rib_len(self) -> int:
        n = get_lib().lr_router_rib_len(self._ptr)
        if n < 0:
            raise LrError(f"lr_router_rib_len failed (rc={n})")
        return int(n)

    def rib_dump(self) -> str:
        """Dump the Loc-RIB as a text table (one route per line)."""
        b = alloc_bytes()
        rc = get_lib().lr_router_rib_dump(self._ptr, b)
        if rc != 0:
            raise LrError(f"lr_router_rib_dump failed (rc={rc}): {last_error()}")
        try:
            return copy_bytes(b).decode("utf-8", errors="replace")
        finally:
            free_bytes(b)

    def sessions_dump(self) -> str:
        """Dump every session's operational summary (one line per session)."""
        b = alloc_bytes()
        rc = get_lib().lr_router_sessions_dump(self._ptr, b)
        if rc != 0:
            raise LrError(f"lr_router_sessions_dump failed (rc={rc}): {last_error()}")
        try:
            return copy_bytes(b).decode("utf-8", errors="replace")
        finally:
            free_bytes(b)

    def add_roa_entry(
        self,
        prefix: str,
        max_length: int = 0,
        asn: int = 0,
    ) -> None:
        """Add one Route Origin Authorization entry (RFC 6482 §3 /
        RFC 6811 §2) to the router's ROA table. ``prefix`` is a CIDR
        string (``"203.0.113.0/24"`` or ``"2001:db8::/32"``).
        ``max_length`` defaults to the prefix length (exact-prefix
        authorization). ``asn`` is the authorized origin AS.
        """
        import ipaddress
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError as e:
            raise LrError(f"invalid prefix {prefix!r}: {e}") from e
        if max_length == 0:
            max_length = net.prefixlen
        if net.version == 4:
            v4 = ffi.new("uint8_t[]", net.network_address.packed)
            v6 = ffi.NULL
        else:
            v4 = ffi.NULL
            v6 = ffi.new("uint8_t[]", net.network_address.packed)
        rc = get_lib().lr_router_add_roa_entry(
            self._ptr,
            v4,
            v6,
            int(net.prefixlen),
            int(max_length),
            int(asn),
        )
        if rc != 0:
            raise LrError(f"lr_router_add_roa_entry failed (rc={rc}): {last_error()}")

    def set_roa_validate(self, enable: bool) -> None:
        """Toggle RFC 6811 §2 prefix-origin validation on/off."""
        rc = get_lib().lr_router_set_roa_validate(self._ptr, 1 if enable else 0)
        if rc != 0:
            raise LrError(f"lr_router_set_roa_validate failed (rc={rc}): {last_error()}")

    # ===== D4.4 — redistribution / aggregation / damping =====

    def add_redistribution_pipe(self, source: int, target: int,
                                metric_policy: int = METRIC_INHERIT,
                                metric: int = 0, tag: int | None = None,
                                allow: list[str] | None = None) -> None:
        """Install a redistribution pipe (BIRD ``pipe`` / FRR
        ``redistribute``). Routes from ``source`` are re-originated
        into ``target`` with the configured metric policy, optional
        ``tag`` and optional ``allow`` prefix-list; ``allow is None``
        redistributes everything."""
        allow_ptr = ffi.NULL
        allow_count = 0
        if allow:
            arr = ffi.new("lr_prefix_t[]", len(allow))
            for i, pfx in enumerate(allow):
                arr[i] = _make_prefix(pfx)[0]
            allow_ptr = arr
            allow_count = len(allow)
        rc = get_lib().lr_router_add_redistribution_pipe(
            self._ptr, int(source), int(target), int(metric_policy), int(metric),
            1 if tag is not None else 0, int(tag or 0), allow_ptr, allow_count)
        if rc != 0:
            raise LrError(f"lr_router_add_redistribution_pipe failed (rc={rc}): {last_error()}")

    def add_aggregate(self, prefix: str) -> None:
        """Register an RFC 4271 section 9.2.2.2 aggregate (originated
        while a more-specific exists, withdrawn when the last one
        disappears)."""
        p = _make_prefix(prefix)
        rc = get_lib().lr_router_add_aggregate(self._ptr, p)
        if rc != 0:
            raise LrError(f"lr_router_add_aggregate failed (rc={rc}): {last_error()}")

    def remove_aggregate(self, prefix: str) -> None:
        """Withdraw a previously registered aggregate (unknown
        prefixes are a no-op)."""
        p = _make_prefix(prefix)
        rc = get_lib().lr_router_remove_aggregate(self._ptr, p)
        if rc != 0:
            raise LrError(f"lr_router_remove_aggregate failed (rc={rc}): {last_error()}")

    def set_damping(self, additive_incr: int = 1000, suppress_threshold: int = 2000,
                    reuse_threshold: int = 750, upper_limit: int = 60000,
                    decay_interval_s: int = 30, decay_factor_active: float = 0.97,
                    decay_factor_withdrawn: float = 0.5) -> "Damping":
        """Install the RFC 2439 damping import hook and return a
        Damping handle the caller drives with decay()."""
        cfg = ffi.new("lr_damping_config_t*", {
            "additive_incr": additive_incr,
            "suppress_threshold": suppress_threshold,
            "reuse_threshold": reuse_threshold,
            "upper_limit": upper_limit,
            "decay_interval_s": decay_interval_s,
            "decay_factor_active": decay_factor_active,
            "decay_factor_withdrawn": decay_factor_withdrawn,
        })
        d = get_lib().lr_router_set_damping(self._ptr, cfg)
        if not d:
            raise LrError(f"lr_router_set_damping failed: {last_error()}")
        return Damping(d)


class Damping:
    """Owned handle to a shared RFC 2439 damping table. The router's
    import hook keeps its own reference; destroy() releases only the
    embedder's decay access."""

    def __init__(self, ptr):
        self._d = ptr

    def decay(self, now_s: int) -> int:
        """Drive one decay pass; returns the number of prefixes that
        re-emerged from suppression."""
        rc = get_lib().lr_damping_decay(self._d, int(now_s))
        if rc < 0:
            raise LrError(f"lr_damping_decay failed (rc={rc}): {last_error()}")
        return rc

    def destroy(self) -> None:
        if self._d:
            get_lib().lr_damping_destroy(self._d)
            self._d = None

    def __del__(self):
        try:
            self.destroy()
        except Exception:
            pass

def abi_version() -> int:
    return int(get_lib().lr_abi_version())


def _make_prefix(prefix: str):
    """Build an lr_prefix_t from an 'a.b.c.d/len' or 'v6::/len' string."""
    import ipaddress
    net = ipaddress.ip_network(prefix, strict=False)
    p = ffi.new("lr_prefix_t*")
    packed = net.network_address.packed
    for i, octet in enumerate(packed):
        p.addr[i] = octet
    p.is_ipv6 = 1 if net.version == 6 else 0
    p.prefix_len = net.prefixlen
    return p


def last_error() -> str:
    cstr = get_lib().lr_last_error()
    if cstr == ffi.NULL:
        return ""
    return ffi.string(cstr).decode("utf-8", errors="replace")


def mpls_platform_labels() -> int:
    """Kernel MPLS platform-labels capability (Linux only).

    Returns 0 when MPLS routing is not enabled, 16 or 20 when it is.
    Non-Linux platforms always return 0.
    """
    return int(get_lib().lr_mpls_platform_labels())


def _parse_v4_prefix(prefix: str):
    """Return (uint8_t[4], prefix_len) for a "a.b.c.d/plen" string."""
    addr_str, _, plen_str = prefix.partition("/")
    plen = int(plen_str) if plen_str else 32
    parts = addr_str.split(".")
    if len(parts) != 4:
        raise LrError(f"invalid IPv4 prefix: {prefix}")
    try:
        addr = ffi.new("uint8_t[]", bytes(int(p) for p in parts))
    except ValueError as e:
        raise LrError(f"invalid IPv4 prefix: {prefix}") from e
    return addr, plen


def _parse_v4_next_hop(next_hop: str | None):
    if next_hop is None:
        return ffi.NULL
    parts = next_hop.split(".")
    if len(parts) != 4:
        raise LrError(f"invalid IPv4 next-hop: {next_hop}")
    try:
        return ffi.new("uint8_t[]", bytes(int(p) for p in parts))
    except ValueError as e:
        raise LrError(f"invalid IPv4 next-hop: {next_hop}") from e


def _parse_v6_prefix(prefix: str):
    import ipaddress
    net = ipaddress.ip_network(prefix, strict=False)
    if net.version != 6:
        raise LrError(f"not an IPv6 prefix: {prefix}")
    return ffi.new("uint8_t[]", net.network_address.packed), net.prefixlen


def _parse_v6_next_hop(next_hop: str | None):
    if next_hop is None:
        return ffi.NULL
    import ipaddress
    try:
        addr = ipaddress.ip_address(next_hop)
    except ValueError as e:
        raise LrError(f"invalid IPv6 next-hop: {next_hop}") from e
    if addr.version != 6:
        raise LrError(f"not an IPv6 next-hop: {next_hop}")
    return ffi.new("uint8_t[]", addr.packed)
