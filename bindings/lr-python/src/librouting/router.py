"""High-level router handle."""

from __future__ import annotations

from ._ffi import ffi, get_lib, alloc_bytes, free_bytes, copy_bytes


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


def abi_version() -> int:
    return int(get_lib().lr_abi_version())


def last_error() -> str:
    cstr = get_lib().lr_last_error()
    if cstr == ffi.NULL:
        return ""
    return ffi.string(cstr).decode("utf-8", errors="replace")
