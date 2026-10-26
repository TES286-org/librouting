"""BFD Control packet wire codec (RFC 5880 §4.1).

Mirrors the C ABI surface lr_bfd_* in lr_ffi.h and the Rust pub API
of lr_bfd::{BfdCodec, BfdPacket, State, Diagnostic, PacketFlags}.
Resource cleanup is released via ``__del__`` / ``close()`` /
context-manager protocol, matching the rest of the package.
"""

from __future__ import annotations

from ._ffi import ffi, get_lib, alloc_bytes, free_bytes, copy_bytes
from .router import LrError, last_error


# ---- Constants (mirrors LR_BFD_*) ----

STATE_ADMIN_DOWN = 0
STATE_DOWN = 1
STATE_INIT = 2
STATE_UP = 3

DIAG_NONE = 0
DIAG_CTRL_EXPIRED = 1
DIAG_ECHO_FAILED = 2
DIAG_NEIGHBOR_SIGNALLED = 3
DIAG_FWD_RESET = 4
DIAG_PATH_DOWN = 5
DIAG_CONCAT_PATH_DOWN = 6
DIAG_ADMIN_DOWN = 7
DIAG_REV_PATH_DOWN = 8
DIAG_MISCONN_DEFECT = 9


def _check_rc(rc: int, what: str) -> None:
    if rc != 0:
        raise LrError(f"{what} failed (rc={rc}): {last_error()}")


class BfdPacket:
    """An owned handle to one BFD Control packet (RFC 5880 §4.1).

    Construct with :meth:`BfdPacket.new` (empty defaults) or
    :meth:`BfdPacket.heartbeat` (Up-state heartbeat). Read fields via
    the properties; mutate via the ``set_*`` methods. Encode to wire
    bytes via :meth:`encode`; decode raw bytes via
    :func:`decode_bfd_packet`.
    """

    def __init__(self) -> None:
        # Not meant to be called directly — use BfdPacket.new() /
        # BfdPacket.heartbeat() / decode_bfd_packet().
        self._ptr = ffi.NULL

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        """Release the underlying handle. Safe to call multiple times."""
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_bfd_packet_free(ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> "BfdPacket":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def new(cls) -> "BfdPacket":
        """Construct an empty BFD packet with sensible defaults
        (state=Down, diag=None, detect_mult=3, intervals=1s, no auth).
        """
        ptr = get_lib().lr_bfd_packet_new()
        if ptr == ffi.NULL:
            raise LrError("lr_bfd_packet_new returned NULL")
        out = cls.__new__(cls)
        out._ptr = ptr
        return out

    @classmethod
    def heartbeat(cls, my_disc: int, your_disc: int) -> "BfdPacket":
        """Construct an "Up" heartbeat packet (state=Up, diag=None,
        detect_mult=3, intervals=1s, no auth).
        """
        ptr = get_lib().lr_bfd_packet_heartbeat(my_disc, your_disc)
        if ptr == ffi.NULL:
            raise LrError("lr_bfd_packet_heartbeat returned NULL")
        out = cls.__new__(cls)
        out._ptr = ptr
        return out

    @property
    def version(self) -> int:
        """The BFD version (always 1 per RFC 5880 §4.1)."""
        return int(get_lib().lr_bfd_packet_version(self._ptr))

    @property
    def diag(self) -> int:
        """The diagnostic code (one of the DIAG_* constants)."""
        return int(get_lib().lr_bfd_packet_diag(self._ptr))

    @property
    def state(self) -> int:
        """The peer state (one of the STATE_* constants)."""
        return int(get_lib().lr_bfd_packet_state(self._ptr))

    @property
    def flags(self) -> int:
        """The flags bitmask (M | D | A | C | F | P)."""
        return int(get_lib().lr_bfd_packet_flags(self._ptr))

    @property
    def detect_mult(self) -> int:
        """The detect multiplier."""
        return int(get_lib().lr_bfd_packet_detect_mult(self._ptr))

    @property
    def my_discriminator(self) -> int:
        """The My Discriminator field."""
        return int(get_lib().lr_bfd_packet_my_discriminator(self._ptr))

    @property
    def your_discriminator(self) -> int:
        """The Your Discriminator field."""
        return int(get_lib().lr_bfd_packet_your_discriminator(self._ptr))

    @property
    def desired_min_tx_interval(self) -> int:
        """The Desired Min TX Interval (microseconds)."""
        return int(get_lib().lr_bfd_packet_desired_min_tx_interval(self._ptr))

    @property
    def required_min_rx_interval(self) -> int:
        """The Required Min RX Interval (microseconds)."""
        return int(get_lib().lr_bfd_packet_required_min_rx_interval(self._ptr))

    @property
    def required_min_echo_interval(self) -> int:
        """The Required Min Echo Interval (microseconds)."""
        return int(get_lib().lr_bfd_packet_required_min_echo_interval(self._ptr))

    @property
    def length(self) -> int:
        """The wire length (24 + auth section)."""
        return int(get_lib().lr_bfd_packet_length(self._ptr))

    def set_diag(self, diag: int) -> None:
        rc = get_lib().lr_bfd_packet_set_diag(self._ptr, diag)
        _check_rc(rc, "lr_bfd_packet_set_diag")

    def set_state(self, state: int) -> None:
        rc = get_lib().lr_bfd_packet_set_state(self._ptr, state)
        _check_rc(rc, "lr_bfd_packet_set_state")

    def set_flags(self, flags: int) -> None:
        rc = get_lib().lr_bfd_packet_set_flags(self._ptr, flags)
        _check_rc(rc, "lr_bfd_packet_set_flags")

    def set_detect_mult(self, mult: int) -> None:
        rc = get_lib().lr_bfd_packet_set_detect_mult(self._ptr, mult)
        _check_rc(rc, "lr_bfd_packet_set_detect_mult")

    def set_my_discriminator(self, disc: int) -> None:
        rc = get_lib().lr_bfd_packet_set_my_discriminator(self._ptr, disc)
        _check_rc(rc, "lr_bfd_packet_set_my_discriminator")

    def set_your_discriminator(self, disc: int) -> None:
        rc = get_lib().lr_bfd_packet_set_your_discriminator(self._ptr, disc)
        _check_rc(rc, "lr_bfd_packet_set_your_discriminator")

    def set_desired_min_tx_interval(self, interval: int) -> None:
        rc = get_lib().lr_bfd_packet_set_desired_min_tx_interval(self._ptr, interval)
        _check_rc(rc, "lr_bfd_packet_set_desired_min_tx_interval")

    def set_required_min_rx_interval(self, interval: int) -> None:
        rc = get_lib().lr_bfd_packet_set_required_min_rx_interval(self._ptr, interval)
        _check_rc(rc, "lr_bfd_packet_set_required_min_rx_interval")

    def set_required_min_echo_interval(self, interval: int) -> None:
        rc = get_lib().lr_bfd_packet_set_required_min_echo_interval(self._ptr, interval)
        _check_rc(rc, "lr_bfd_packet_set_required_min_echo_interval")

    def encode(self) -> bytes:
        """Encode the packet to its wire form (24 bytes + auth)."""
        b = alloc_bytes()
        rc = get_lib().lr_bfd_encode(self._ptr, b)
        _check_rc(rc, "lr_bfd_encode")
        try:
            return copy_bytes(b)
        finally:
            free_bytes(b)


def decode_bfd_packet(data: bytes) -> BfdPacket:
    """Decode one BFD Control packet from raw bytes.

    Raises :class:`LrError` on a decode failure.
    """
    if not data:
        raise LrError("decode_bfd_packet: empty input")
    out = ffi.new("lr_bfd_packet_t*")
    rc = get_lib().lr_bfd_decode(data, len(data), out)
    _check_rc(rc, "lr_bfd_decode")
    if out[0] == ffi.NULL:
        raise LrError(f"lr_bfd_decode: {last_error()}")
    p = BfdPacket.__new__(BfdPacket)
    p._ptr = out[0]
    return p
