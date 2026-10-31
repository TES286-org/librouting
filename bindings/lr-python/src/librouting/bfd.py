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

    # ---- BfdPacket auth integration (RFC 5880 §4.1 A bit) ----

    def set_auth(self, section: "BfdAuthSection | None") -> None:
        """Install (or replace) the Authentication Section on the packet.

        The section handle is *consumed* — the boxed AuthSection is
        moved into the packet, so the caller must NOT call ``close()``
        on the same ``BfdAuthSection`` afterwards. Pass ``None`` to
        clear the auth field.
        """
        if section is None:
            rc = get_lib().lr_bfd_packet_set_auth(self._ptr, ffi.NULL)
            _check_rc(rc, "lr_bfd_packet_set_auth")
            return
        # Take ownership of the section's pointer; clear it on the
        # Python side so the next close() / __del__ is a no-op.
        raw = section._ptr
        section._ptr = ffi.NULL
        rc = get_lib().lr_bfd_packet_set_auth(self._ptr, raw)
        _check_rc(rc, "lr_bfd_packet_set_auth")

    @property
    def auth_present(self) -> bool:
        """True when the packet carries an Authentication Section."""
        return bool(get_lib().lr_bfd_packet_auth_present(self._ptr))

    def auth(self) -> "BfdAuthSection | None":
        """Read a *copy* of the packet's Authentication Section.

        Returns ``None`` when the packet has no auth section. The
        returned :class:`BfdAuthSection` is owned by the caller —
        ``close()`` it (or let GC pick it up).
        """
        out = ffi.new("lr_bfd_auth_section_t*")
        rc = get_lib().lr_bfd_packet_auth(self._ptr, out)
        _check_rc(rc, "lr_bfd_packet_auth")
        if out[0] == ffi.NULL:
            return None
        s = BfdAuthSection.__new__(BfdAuthSection)
        s._ptr = out[0]
        return s


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


# ---- AuthType constants (RFC 5880 §8 IANA registry) ----

AUTH_TYPE_SIMPLE_PASSWORD = 1
AUTH_TYPE_KEYED_MD5 = 2
AUTH_TYPE_METICULOUS_KEYED_MD5 = 3
AUTH_TYPE_KEYED_SHA1 = 4
AUTH_TYPE_METICULOUS_KEYED_SHA1 = 5

# Auth algorithm ids (mirror LR_BFD_AUTH_ALGO_*).
AUTH_ALGO_KEYED_MD5 = 1
AUTH_ALGO_METICULOUS_KEYED_MD5 = 2
AUTH_ALGO_KEYED_SHA1 = 3
AUTH_ALGO_METICULOUS_KEYED_SHA1 = 4


def auth_type_expected_digest_len(auth_type: int) -> int:
    """Expected digest length for the keyed-hash auth types
    (RFC 5880 §4.3 / §4.4). Returns ``-1`` for Simple Password and
    unknown types (no fixed length to validate against).
    """
    return int(get_lib().lr_bfd_auth_type_expected_digest_len(auth_type))


def auth_type_is_keyed_hash(auth_type: int) -> bool:
    """True (1) when ``auth_type`` is one of the four keyed-hash types."""
    return bool(get_lib().lr_bfd_auth_type_is_keyed_hash(auth_type))


def auth_type_is_meticulous(auth_type: int) -> bool:
    """True (1) when ``auth_type`` is one of the two Meticulous variants."""
    return bool(get_lib().lr_bfd_auth_type_is_meticulous(auth_type))


class BfdAuthKey:
    """An owned handle to one BFD AuthKey (RFC 5880 §4.2).

    Construct with :meth:`BfdAuthKey.new` (raw secret) or
    :meth:`BfdAuthKey.simple_password` (the §4.2 convenience
    constructor). Read fields via the properties.
    """

    def __init__(self) -> None:
        self._ptr = ffi.NULL

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_bfd_auth_key_free(ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> "BfdAuthKey":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def new(cls, key_id: int, secret: bytes) -> "BfdAuthKey":
        ptr = get_lib().lr_bfd_auth_key_new(key_id, secret, len(secret))
        if ptr == ffi.NULL:
            raise LrError(f"lr_bfd_auth_key_new: {last_error()}")
        out = cls.__new__(cls)
        out._ptr = ptr
        return out

    @classmethod
    def simple_password(cls, key_id: int, password: bytes) -> "BfdAuthKey":
        ptr = get_lib().lr_bfd_auth_key_simple_password(key_id, password, len(password))
        if ptr == ffi.NULL:
            raise LrError(f"lr_bfd_auth_key_simple_password: {last_error()}")
        out = cls.__new__(cls)
        out._ptr = ptr
        return out

    @property
    def key_id(self) -> int:
        return int(get_lib().lr_bfd_auth_key_key_id(self._ptr))

    @property
    def data_len(self) -> int:
        return int(get_lib().lr_bfd_auth_key_data_len(self._ptr))

    @property
    def data(self) -> bytes:
        n = self.data_len
        if n == 0:
            return b""
        buf = ffi.new("uint8_t[]", n)
        out_len = ffi.new("uintptr_t*")
        rc = get_lib().lr_bfd_auth_key_data(self._ptr, buf, n, out_len)
        _check_rc(rc, "lr_bfd_auth_key_data")
        return bytes(ffi.buffer(buf, int(out_len[0])))


class BfdAuthSection:
    """An owned handle to one BFD Authentication Section
    (RFC 5880 §4.2-§4.4).

    Construct with one of the five type-specific class methods
    (:meth:`simple_password` / :meth:`keyed_md5` /
    :meth:`meticulous_keyed_md5` / :meth:`keyed_sha1` /
    :meth:`meticulous_keyed_sha1`). Read fields via the properties.
    """

    def __init__(self) -> None:
        self._ptr = ffi.NULL

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_bfd_auth_section_free(ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> "BfdAuthSection":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def _wrap(cls, ptr) -> "BfdAuthSection":
        out = cls.__new__(cls)
        out._ptr = ptr
        return out

    @classmethod
    def simple_password(cls, password: bytes, key_id: int) -> "BfdAuthSection":
        ptr = get_lib().lr_bfd_auth_section_simple_password(password, len(password), key_id)
        if ptr == ffi.NULL:
            raise LrError(f"lr_bfd_auth_section_simple_password: {last_error()}")
        return cls._wrap(ptr)

    @classmethod
    def keyed_md5(cls, key_id: int, sequence: int, digest: bytes) -> "BfdAuthSection":
        ptr = get_lib().lr_bfd_auth_section_keyed_md5(key_id, sequence, digest, len(digest))
        if ptr == ffi.NULL:
            raise LrError(f"lr_bfd_auth_section_keyed_md5: {last_error()}")
        return cls._wrap(ptr)

    @classmethod
    def meticulous_keyed_md5(cls, key_id: int, sequence: int, digest: bytes) -> "BfdAuthSection":
        ptr = get_lib().lr_bfd_auth_section_meticulous_keyed_md5(key_id, sequence, digest, len(digest))
        if ptr == ffi.NULL:
            raise LrError(f"lr_bfd_auth_section_meticulous_keyed_md5: {last_error()}")
        return cls._wrap(ptr)

    @classmethod
    def keyed_sha1(cls, key_id: int, sequence: int, digest: bytes) -> "BfdAuthSection":
        ptr = get_lib().lr_bfd_auth_section_keyed_sha1(key_id, sequence, digest, len(digest))
        if ptr == ffi.NULL:
            raise LrError(f"lr_bfd_auth_section_keyed_sha1: {last_error()}")
        return cls._wrap(ptr)

    @classmethod
    def meticulous_keyed_sha1(cls, key_id: int, sequence: int, digest: bytes) -> "BfdAuthSection":
        ptr = get_lib().lr_bfd_auth_section_meticulous_keyed_sha1(key_id, sequence, digest, len(digest))
        if ptr == ffi.NULL:
            raise LrError(f"lr_bfd_auth_section_meticulous_keyed_sha1: {last_error()}")
        return cls._wrap(ptr)

    @property
    def auth_type(self) -> int:
        return int(get_lib().lr_bfd_auth_section_auth_type(self._ptr))

    @property
    def key_id(self) -> int:
        return int(get_lib().lr_bfd_auth_section_key_id(self._ptr))

    @property
    def sequence(self) -> int | None:
        """The sequence number, or ``None`` when the section has no
        sequence (Simple Password / unknown types)."""
        out_seq = ffi.new("uint32_t*")
        rc = get_lib().lr_bfd_auth_section_sequence(self._ptr, out_seq)
        if rc < 0:
            raise LrError(f"lr_bfd_auth_section_sequence: {last_error()}")
        return int(out_seq[0]) if rc == 1 else None

    @property
    def data_len(self) -> int:
        return int(get_lib().lr_bfd_auth_section_data_len(self._ptr))

    @property
    def data(self) -> bytes:
        n = self.data_len
        if n == 0:
            return b""
        buf = ffi.new("uint8_t[]", n)
        out_len = ffi.new("uintptr_t*")
        rc = get_lib().lr_bfd_auth_section_data(self._ptr, buf, n, out_len)
        _check_rc(rc, "lr_bfd_auth_section_data")
        return bytes(ffi.buffer(buf, int(out_len[0])))

    @property
    def wire_len(self) -> int:
        return int(get_lib().lr_bfd_auth_section_wire_len(self._ptr))


class BfdKeyedAuth:
    """An owned handle to one BFD keyed-hash auth state
    (RFC 5880 §6.7 / §6.8.5).

    Construct with :meth:`BfdKeyedAuth.new`. Read state via the
    properties; produce the wire auth section via
    :meth:`auth_section_for_tx`; sign outbound packets via
    :meth:`sign_packet`; verify inbound packets via
    :meth:`verify_inbound`.
    """

    def __init__(self) -> None:
        self._ptr = ffi.NULL

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        ptr = getattr(self, "_ptr", None)
        if ptr is not None and ptr != ffi.NULL:
            get_lib().lr_bfd_keyed_auth_free(ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> "BfdKeyedAuth":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @classmethod
    def new(cls, algorithm: int, key_id: int, secret: bytes) -> "BfdKeyedAuth":
        ptr = get_lib().lr_bfd_keyed_auth_new(algorithm, key_id, secret, len(secret))
        if ptr == ffi.NULL:
            raise LrError(f"lr_bfd_keyed_auth_new: {last_error()}")
        out = cls.__new__(cls)
        out._ptr = ptr
        return out

    @property
    def key_id(self) -> int:
        return int(get_lib().lr_bfd_keyed_auth_key_id(self._ptr))

    @property
    def algorithm(self) -> int:
        return int(get_lib().lr_bfd_keyed_auth_algorithm(self._ptr))

    @property
    def auth_type_value(self) -> int:
        return int(get_lib().lr_bfd_keyed_auth_auth_type_value(self._ptr))

    @property
    def digest_len(self) -> int:
        return int(get_lib().lr_bfd_keyed_auth_digest_len(self._ptr))

    @property
    def is_meticulous(self) -> bool:
        return bool(get_lib().lr_bfd_keyed_auth_is_meticulous(self._ptr))

    @property
    def xmit_seq(self) -> int:
        return int(get_lib().lr_bfd_keyed_auth_xmit_seq(self._ptr))

    @property
    def rcv_auth_seq_known(self) -> bool:
        return bool(get_lib().lr_bfd_keyed_auth_rcv_auth_seq_known(self._ptr))

    @property
    def rcv_auth_seq(self) -> int:
        return int(get_lib().lr_bfd_keyed_auth_rcv_auth_seq(self._ptr))

    def advance_xmit_seq(self) -> None:
        rc = get_lib().lr_bfd_keyed_auth_advance_xmit_seq(self._ptr)
        _check_rc(rc, "lr_bfd_keyed_auth_advance_xmit_seq")

    def auth_section_for_tx(self) -> BfdAuthSection:
        """Build the wire auth section to ride the next outbound packet
        (RFC 5880 §6.7.3 / §6.7.4): the auth type, key ID, current
        transmit sequence and the shared key in the digest field.
        """
        ptr = get_lib().lr_bfd_keyed_auth_auth_section_for_tx(self._ptr)
        if ptr == ffi.NULL:
            raise LrError(f"lr_bfd_keyed_auth_auth_section_for_tx: {last_error()}")
        return BfdAuthSection._wrap(ptr)

    def sign_packet(self, packet: bytearray) -> None:
        """Sign an encoded outbound BFD Control packet in place
        (RFC 5880 §6.7.3 / §6.7.4). The packet MUST be the full encoded
        packet with the auth section's digest field carrying the
        shared key (as produced by ``auth_section_for_tx`` +
        :meth:`BfdPacket.encode`).
        """
        # CFFI wants a writable buffer; bytearray supports the buffer
        # protocol. We use ``ffi.from_buffer`` for zero-copy.
        if not isinstance(packet, (bytearray, memoryview)):
            raise TypeError("sign_packet requires a mutable bytearray / memoryview")
        buf = ffi.from_buffer("uint8_t[]", packet)
        rc = get_lib().lr_bfd_keyed_auth_sign_packet(self._ptr, buf, len(packet))
        _check_rc(rc, "lr_bfd_keyed_auth_sign_packet")

    def verify_inbound(self, packet: bytes, section: BfdAuthSection, detect_mult: int) -> bool:
        """Verify an inbound BFD Control packet against this auth state
        (RFC 5880 §6.7.3 / §6.7.4 anti-replay + digest check). Returns
        ``True`` when the packet authenticates and the sequence
        number is within the anti-replay window (the receive state is
        updated in place); ``False`` otherwise.
        """
        rc = get_lib().lr_bfd_keyed_auth_verify_inbound(
            self._ptr, packet, len(packet), section._ptr, detect_mult
        )
        if rc < 0:
            raise LrError(f"lr_bfd_keyed_auth_verify_inbound: {last_error()}")
        return bool(rc)

