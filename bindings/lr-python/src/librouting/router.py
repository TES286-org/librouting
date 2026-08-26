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
                        hold_time: int = 90, keepalive: int = 0, asn4: bool = True) -> int:
        h = ffi.new("uint64_t*")
        rc = get_lib().lr_router_add_bgp_session(
            self._ptr,
            int(local_as), int(peer_as), int(local_bgp_id),
            int(hold_time), int(keepalive), 1 if asn4 else 0,
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


def abi_version() -> int:
    return int(get_lib().lr_abi_version())


def last_error() -> str:
    cstr = get_lib().lr_last_error()
    if cstr == ffi.NULL:
        return ""
    return ffi.string(cstr).decode("utf-8", errors="replace")
