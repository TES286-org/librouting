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
