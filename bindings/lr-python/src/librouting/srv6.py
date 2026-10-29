"""SRv6 structured types — Segment Identifier, Locator, Routing Header, Behavior.

Mirrors the `lr_srv6` Rust crate (RFC 8754 SRv6 data-plane primitives +
RFC 8986 endpoint behavior registry). Each type wraps an opaque C ABI
handle and owns its lifetime through `__del__` / context-manager
protocols. The class surface mirrors the Rust API hierarchy:

* `Sid`           — `lr_srv6::Sid`           (RFC 8754 §3)
* `Locator`       — `lr_srv6::Locator`       (RFC 8754 §3.1)
* `Srh`           — `lr_srv6::Srh`           (RFC 8754 §2)
* `SrhError`      — `lr_srv6::SrhError`      (RFC 8754 §2 — discriminant codes)
* `Behavior`      — `lr_srv6::Behavior`      (RFC 8986 §4 — endpoint behaviors)
* `SidParseError` — `lr_srv6::SidParseError`
* `LocatorParseError` — `lr_srv6::LocatorParseError`

The class methods are the FFI-shaped counterparts of the Rust methods —
`Sid.from_str`, `Sid.octets`, `Sid.is_unspecified`,
`Sid.locator_slice`, `Sid.from_locator_tail`, `Sid.is_inside_locator`,
`Locator.new`, `Locator.from_sid`, `Locator.contains_sid`,
`Locator.sid_with_tail`, `Locator.sid_with_index`, `Srh.new`,
`Srh.with_segments_left`, `Srh.with_next_header` / `_flags` / `_tag` /
`_tlvs`, `Srh.first_segment`, `Srh.current_destination`,
`Srh.segment_at`, `Srh.encode`, etc.
"""

from __future__ import annotations

from ._ffi import ffi, get_lib, alloc_bytes, free_bytes, copy_bytes
from .router import LrError

# ----------------------------------------------------------------------
# Constants — mirror lr_srv6::srh / lr_srv6::behavior pub consts and
# the LR_SRV6_* #defines in include/lr_ffi.h.
# ----------------------------------------------------------------------

# SRH routing type (RFC 8754 §2, IANA "IPv6 Routing Types" registry).
ROUTING_TYPE_SRH = 4

# SRH flag bits (RFC 8754 §2.1 + the Linux uapi deployed set).
FLAG_OAM = 0x20
FLAG_HMAC = 0x08
FLAG_ALERT = 0x10
FLAG_PROTECTED = 0x40

# SRH layout (RFC 8754 §2).
SRH_FIXED_LEN = 8
SRH_SEGMENT_LEN = 16
TLV_PAD1 = 0
TLV_PADN = 1
MAX_SEGMENTS = 127
MAX_BLOCK_BITS = 128

# SrhError discriminants — mirror lr_srv6::SrhError variants.
SRH_ERR_TOO_SHORT = 0
SRH_ERR_LENGTH_MISMATCH = 1
SRH_ERR_EMPTY_SEGMENT_LIST = 2
SRH_ERR_TOO_MANY_SEGMENTS = 3
SRH_ERR_LAST_ENTRY_OUT_OF_RANGE = 4
SRH_ERR_SEGMENTS_LEFT_OUT_OF_RANGE = 5
SRH_ERR_WRONG_ROUTING_TYPE = 6
SRH_ERR_RESERVED_FLAG_BITS = 7
SRH_ERR_UNKNOWN = -1

# Names for the discriminant codes — used by `SrhError.name_of`.
_SRH_ERR_NAMES = {
    SRH_ERR_TOO_SHORT: "TooShort",
    SRH_ERR_LENGTH_MISMATCH: "LengthMismatch",
    SRH_ERR_EMPTY_SEGMENT_LIST: "EmptySegmentList",
    SRH_ERR_TOO_MANY_SEGMENTS: "TooManySegments",
    SRH_ERR_LAST_ENTRY_OUT_OF_RANGE: "LastEntryOutOfRange",
    SRH_ERR_SEGMENTS_LEFT_OUT_OF_RANGE: "SegmentsLeftOutOfRange",
    SRH_ERR_WRONG_ROUTING_TYPE: "WrongRoutingType",
    SRH_ERR_RESERVED_FLAG_BITS: "ReservedFlagBits",
    SRH_ERR_UNKNOWN: "Unknown",
}


class SidParseError(Exception):
    """A SID string failed to parse (RFC 5952 §4).

    Discriminant codes mirror the C ABI's
    `lr_srv6_sid_parse_error_name` mapping (1..=4):
    - `EMPTY = 1`
    - `DOUBLE_DOUBLE_COLON = 2`
    - `BAD_HEXTET = 3`
    - `WRONG_LENGTH = 4`
    """

    EMPTY = 1
    DOUBLE_DOUBLE_COLON = 2
    BAD_HEXTET = 3
    WRONG_LENGTH = 4

    _NAMES = {
        EMPTY: "Empty",
        DOUBLE_DOUBLE_COLON: "DoubleDoubleColon",
        BAD_HEXTET: "BadHextet",
        WRONG_LENGTH: "WrongLength",
    }

    def __init__(self, code: int, message: str = ""):
        self.code = code
        self.message = message or self._NAMES.get(code, "UnknownSidParseError")
        super().__init__(f"SidParseError({self._NAMES.get(code, code)}): {self.message}")

    @classmethod
    def from_code(cls, code: int) -> "SidParseError":
        return cls(code, cls._NAMES.get(code, "UnknownSidParseError"))


class LocatorParseError(Exception):
    """A Locator string failed to parse (RFC 8754 §3.1 + RFC 5952 §4).

    Discriminant codes mirror the C ABI's
    `lr_srv6_locator_parse_error_name` mapping (1..=3):
    - `MISSING_PREFIX_LEN = 1`
    - `BAD_ADDR = 2`
    - `BAD_PREFIX_LEN = 3`
    """

    MISSING_PREFIX_LEN = 1
    BAD_ADDR = 2
    BAD_PREFIX_LEN = 3

    _NAMES = {
        MISSING_PREFIX_LEN: "MissingPrefixLen",
        BAD_ADDR: "BadAddr",
        BAD_PREFIX_LEN: "BadPrefixLen",
    }

    def __init__(self, code: int, message: str = ""):
        self.code = code
        self.message = message or self._NAMES.get(code, "UnknownLocatorParseError")
        super().__init__(
            f"LocatorParseError({self._NAMES.get(code, code)}): {self.message}"
        )

    @classmethod
    def from_code(cls, code: int) -> "LocatorParseError":
        return cls(code, cls._NAMES.get(code, "UnknownLocatorParseError"))


class SrhError(Exception):
    """An SRH encode/decode error (RFC 8754 §2 — `SrhError` discriminant)."""

    def __init__(self, code: int, message: str = ""):
        self.code = code
        self.message = message or _SRH_ERR_NAMES.get(code, "UnknownSrhError")
        super().__init__(f"SrhError({_SRH_ERR_NAMES.get(code, code)}): {self.message}")

    @classmethod
    def from_last(cls) -> "SrhError | None":
        """Build a `SrhError` from the most recent FFI call's recorded
        code. Returns `None` when the last error was not an SRH error."""
        code = int(get_lib().lr_srv6_srh_last_err_code())
        if code == SRH_ERR_UNKNOWN:
            return None
        return cls(code, _SRH_ERR_NAMES.get(code, "UnknownSrhError"))


def _check(rc: int, what: str) -> None:
    """Raise LrError on non-zero rc; if the recorded error is an
    SrhError, raise that variant instead so callers can `except` by type."""
    if rc == 0:
        return
    srh = SrhError.from_last()
    if srh is not None:
        raise srh
    raise LrError(f"{what} failed (rc={rc}): {_last_error()}")


def _last_error() -> str:
    p = get_lib().lr_last_error()
    if p == ffi.NULL:
        return ""
    return ffi.string(p).decode("utf-8", errors="replace")


def _u8_buf(n: int):
    """Allocate a fixed-size `uint8_t[N]` buffer."""
    return ffi.new(f"uint8_t[{n}]")


def _sid_bytes_to_str(b: bytes) -> str:
    """Format 16 raw bytes as the canonical IPv6 textual form (RFC 5952 §4)."""
    # Pass the bytes through the C ABI's `lr_srv6_sid_to_str` so the
    # Python binding renders SIDs identically to the Rust crate's
    # Display impl. The C function uses a thread-local static buffer
    # (single-threaded use only); we copy out before returning.
    if len(b) != 16:
        raise ValueError(f"Sid must be 16 bytes, got {len(b)}")
    ptr = get_lib().lr_srv6_sid_to_str(b)
    if ptr == ffi.NULL:
        return ""
    return ffi.string(ptr).decode("utf-8", errors="replace")


class Sid:
    """A 128-bit SRv6 Segment Identifier (RFC 8754 §3).

    Wraps an `lr_srv6_sid_t` opaque handle. The class mirrors
    `lr_srv6::Sid`'s public API: construction from raw bytes
    (`Sid.from_octets`), parsing from text (`Sid.from_str`),
    rendering (`str(sid)`), membership queries
    (`is_inside_locator`), and locator-tail composition
    (`from_locator_tail`).
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        # Private ctor — use a factory (from_octets / from_str /
        # from_locator_tail) so we always go through the C ABI.
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            get_lib().lr_srv6_sid_free(self._ptr)
            self._ptr = None

    def __enter__(self) -> "Sid":
        return self

    def __exit__(self, *_):
        self.__del__()

    def __repr__(self) -> str:
        return f"Sid({self})"

    def __str__(self) -> str:
        """Canonical IPv6 textual form (RFC 5952 §4)."""
        return _sid_bytes_to_str(self.octets())

    def __eq__(self, other) -> bool:
        if isinstance(other, Sid):
            return self.octets() == other.octets()
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.octets())

    # ---- construction ----

    @classmethod
    def from_octets(cls, octets: bytes) -> "Sid":
        """Build a SID from 16 raw bytes (network byte order)."""
        if len(octets) != 16:
            raise ValueError(f"Sid must be 16 bytes, got {len(octets)}")
        ptr = get_lib().lr_srv6_sid_new(octets)
        if ptr == ffi.NULL:
            raise LrError("lr_srv6_sid_new returned null")
        return cls(ptr)

    @classmethod
    def UNSPECIFIED(cls) -> "Sid":
        """All-zeros SID — `::` per RFC 8754 §3.1."""
        return cls.from_octets(b"\x00" * 16)

    @classmethod
    def from_str(cls, s: str) -> "Sid":
        """Parse a SID from the canonical IPv6 textual form (RFC 5952 §4).

        Mirrors `Sid::from_str` in `lr_srv6::sid`.
        Raises `SidParseError` on malformed input — the discriminant code
        mirrors `lr_srv6::SidParseError` (1..=4).
        Raises `LrError` for non-parse failures (NULL, bad UTF-8, panic).
        """
        if not isinstance(s, str):
            raise TypeError(f"Sid.from_str expects str, got {type(s).__name__}")
        out = _u8_buf(16)
        b = s.encode("utf-8")
        rc = get_lib().lr_srv6_sid_from_str(b, out)
        if rc == 0:
            return cls.from_octets(bytes(ffi.buffer(out, 16)))
        if rc > 0:
            # Positive rc is a SidParseError discriminant code (1..=4).
            raise SidParseError.from_code(rc)
        # Negative rc is a generic LrError (null/utf-8/panic).
        raise LrError(f"lr_srv6_sid_from_str failed (rc={rc}): {_last_error()}")

    @classmethod
    def from_locator_tail(
        cls, locator: bytes, tail: bytes, locator_block_bits: int
    ) -> "Sid":
        """Build a SID from a locator prefix and a function/argument tail
        (RFC 8754 §3.1). Mirrors `Sid::from_locator_tail`."""
        loc_bytes = (locator_block_bits + 7) // 8
        if len(locator) != loc_bytes:
            raise ValueError(
                f"locator must be {loc_bytes} bytes for block_bits={locator_block_bits}, "
                f"got {len(locator)}"
            )
        if len(tail) + loc_bytes != 16:
            raise ValueError(
                f"locator + tail must be 16 bytes, got {loc_bytes + len(tail)}"
            )
        ptr = get_lib().lr_srv6_sid_from_locator_tail(
            locator, len(locator), tail, len(tail), locator_block_bits
        )
        if ptr == ffi.NULL:
            raise LrError("lr_srv6_sid_from_locator_tail returned null")
        return cls(ptr)

    # ---- accessors ----

    def octets(self) -> bytes:
        """The 16 raw bytes, network byte order."""
        out = _u8_buf(16)
        rc = get_lib().lr_srv6_sid_octets(self._ptr, out)
        _check(rc, "lr_srv6_sid_octets")
        return bytes(ffi.buffer(out, 16))

    def is_unspecified(self) -> bool:
        """True when the SID equals the all-zeros SID (`::`)."""
        return bool(get_lib().lr_srv6_sid_is_unspecified(self._ptr))

    def locator_slice(self, locator_block_bits: int) -> tuple[int, int] | None:
        """Slice the locator prefix out of the SID (RFC 8754 §3.1).

        Returns `(offset_bytes, byte_count)` so the caller can borrow the
        slice via `sid.octets()[offset:offset+len]`. Returns `None` if
        `locator_block_bits` exceeds 128 or is not a multiple of 8.
        """
        out_off = ffi.new("uintptr_t*")
        out_len = ffi.new("uintptr_t*")
        ok = get_lib().lr_srv6_sid_locator_slice(
            self._ptr, locator_block_bits, out_off, out_len
        )
        if not ok:
            return None
        return (int(out_off[0]), int(out_len[0]))

    def is_inside_locator(
        self, locator: bytes, locator_block_bits: int
    ) -> bool:
        """True when the SID falls inside the given locator block (RFC 8754 §3.1).

        Returns `False` (rather than raising) on an invalid bit length —
        the contract is a plain membership check.
        """
        if not isinstance(locator, (bytes, bytearray)):
            raise TypeError(f"locator must be bytes, got {type(locator).__name__}")
        return bool(
            get_lib().lr_srv6_sid_is_inside_locator(
                self._ptr, bytes(locator), len(locator), locator_block_bits
            )
        )


class Locator:
    """A locator block: an IPv6 prefix plus its bit length (RFC 8754 §3.1).

    Wraps an `lr_srv6_locator_t` opaque handle. Mirrors `lr_srv6::Locator`:
    `Locator.new(addr, block_bits)`, `Locator.from_sid(sid, block_bits)`,
    `Locator.from_str("fcbb:bb00::/48")`, `contains_sid(sid)`,
    `sid_with_tail(tail)`, `sid_with_index(idx)`.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            get_lib().lr_srv6_locator_free(self._ptr)
            self._ptr = None

    def __enter__(self) -> "Locator":
        return self

    def __exit__(self, *_):
        self.__del__()

    def __repr__(self) -> str:
        return f"Locator({self}/{self.block_bits()})"

    def __str__(self) -> str:
        """Canonical `addr/prefixlen` textual form (RFC 5952 §4 + RFC 8754 §3.1)."""
        addr = self.addr()
        ptr = get_lib().lr_srv6_locator_to_str(addr, self.block_bits())
        if ptr == ffi.NULL:
            return ""
        return ffi.string(ptr).decode("utf-8", errors="replace")

    def __eq__(self, other) -> bool:
        if isinstance(other, Locator):
            return self.addr() == other.addr() and self.block_bits() == other.block_bits()
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.addr(), self.block_bits()))

    # ---- construction ----

    @classmethod
    def new(cls, addr: bytes, block_bits: int) -> "Locator":
        """Construct a Locator from a 16-byte address and a bit length.

        The address is masked so host bits are zero (RFC 8754 §3.1).
        Raises `ValueError` if `block_bits > 128`.
        """
        if len(addr) != 16:
            raise ValueError(f"addr must be 16 bytes, got {len(addr)}")
        if block_bits > MAX_BLOCK_BITS:
            raise ValueError(f"block_bits must be <= {MAX_BLOCK_BITS}, got {block_bits}")
        ptr = get_lib().lr_srv6_locator_new(addr, block_bits)
        if ptr == ffi.NULL:
            raise LrError("lr_srv6_locator_new returned null")
        return cls(ptr)

    @classmethod
    def from_sid(cls, sid: Sid, block_bits: int) -> "Locator":
        """Build a Locator from a `Sid`'s high `block_bits` bits."""
        ptr = get_lib().lr_srv6_locator_from_sid(sid._ptr, block_bits)
        if ptr == ffi.NULL:
            raise LrError("lr_srv6_locator_from_sid returned null")
        return cls(ptr)

    @classmethod
    def from_str(cls, s: str) -> "Locator":
        """Parse `"fcbb:bb00::/48"` (RFC 5952 §4 + a `/prefix` suffix).

        Mirrors `Locator::from_str` in `lr_srv6::locator`.
        Raises `LocatorParseError` on malformed input — the discriminant
        code mirrors `lr_srv6::LocatorParseError` (1..=3).
        Raises `LrError` for non-parse failures (NULL, bad UTF-8, panic).
        """
        if not isinstance(s, str):
            raise TypeError(f"Locator.from_str expects str, got {type(s).__name__}")
        out_addr = _u8_buf(16)
        out_bits = ffi.new("uint8_t*")
        b = s.encode("utf-8")
        rc = get_lib().lr_srv6_locator_from_str(b, out_addr, out_bits)
        if rc == 0:
            return cls.new(bytes(ffi.buffer(out_addr, 16)), int(out_bits[0]))
        if rc > 0:
            # Positive rc is a LocatorParseError discriminant code (1..=3).
            raise LocatorParseError.from_code(rc)
        # Negative rc is a generic LrError (null/utf-8/panic).
        raise LrError(f"lr_srv6_locator_from_str failed (rc={rc}): {_last_error()}")

    # ---- accessors ----

    def addr(self) -> bytes:
        """The raw 16-byte address (host bits zeroed)."""
        out = _u8_buf(16)
        rc = get_lib().lr_srv6_locator_addr(self._ptr, out)
        _check(rc, "lr_srv6_locator_addr")
        return bytes(ffi.buffer(out, 16))

    def block_bits(self) -> int:
        """The locator prefix length in bits (RFC 8754 §3.1)."""
        return int(get_lib().lr_srv6_locator_block_bits(self._ptr))

    def block_bytes(self) -> int:
        """The locator's byte length (rounded up)."""
        return int(get_lib().lr_srv6_locator_block_bytes(self._ptr))

    def contains_sid(self, sid: Sid) -> bool:
        """True when `sid` falls inside this locator."""
        return bool(get_lib().lr_srv6_locator_contains_sid(self._ptr, sid._ptr))

    def sid_with_tail(self, tail: bytes) -> Sid:
        """Build a `Sid` under this locator by appending the 16-byte `tail`
        (function + arguments). Mirrors `Locator::sid_with_tail`."""
        if len(tail) != 16:
            raise ValueError(f"tail must be 16 bytes, got {len(tail)}")
        ptr = get_lib().lr_srv6_locator_sid_with_tail(self._ptr, tail)
        if ptr == ffi.NULL:
            raise LrError("lr_srv6_locator_sid_with_tail returned null")
        return Sid(ptr)

    def sid_with_index(self, function_index: int) -> Sid | None:
        """Allocate a `Sid` at a given function index inside this locator.
        Returns `None` when the locator leaves no room for a 4-byte function.
        """
        ptr = get_lib().lr_srv6_locator_sid_with_index(self._ptr, function_index)
        if ptr == ffi.NULL:
            return None
        return Sid(ptr)


class Srh:
    """The IPv6 Segment Routing Header (RFC 8754 §2).

    Wraps an `lr_srv6_srh_t` opaque handle. Mirrors `lr_srv6::Srh`:
    `Srh.new(segments)`, `Srh.with_segments_left(segments, sl)`,
    builder-style setters (`with_next_header`, `with_flags`, `with_tag`,
    `with_tlvs`), accessors (`next_header`, `segments_left`,
    `last_entry`, `flags`, `tag`, `segment_count`, `segment_at`,
    `first_segment`, `current_destination`, `tlvs`, `len`, `is_empty`),
    and `encode()` to produce the wire bytes.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    def __del__(self):
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            get_lib().lr_srv6_srh_free(self._ptr)
            self._ptr = None

    def __enter__(self) -> "Srh":
        return self

    def __exit__(self, *_):
        self.__del__()

    def __repr__(self) -> str:
        n = self.segment_count()
        return f"Srh(segments={n}, segments_left={self.segments_left()})"

    # ---- construction ----

    @classmethod
    def new(cls, segments: list[Sid] | list[bytes]) -> "Srh":
        """Build an SRH from a segment list.

        `segments` is a list of `Sid` instances or 16-byte `bytes`/`bytearray`
        values. `segments_left` defaults to `len(segments) - 1` (RFC 8754
        §4.2 — the sender's view: the first segment is the destination
        address, `segments_left` points at the last segment to visit).
        Raises `SrhError` on an empty list, a too-long list, or an
        out-of-range `segments_left`.
        """
        return cls._from_segments(segments, None)

    @classmethod
    def with_segments_left(
        cls,
        segments: list[Sid] | list[bytes],
        segments_left: int,
    ) -> "Srh":
        """Like `new` but with an explicit `segments_left`."""
        return cls._from_segments(segments, segments_left)

    @classmethod
    def _from_segments(cls, segments, segments_left) -> "Srh":
        if not segments:
            raise SrhError(SRH_ERR_EMPTY_SEGMENT_LIST, "segment list is empty")
        if len(segments) > MAX_SEGMENTS:
            raise SrhError(
                SRH_ERR_TOO_MANY_SEGMENTS,
                f"segment list exceeds the {MAX_SEGMENTS}-segment maximum",
            )
        flat = bytearray()
        for s in segments:
            if isinstance(s, Sid):
                flat.extend(s.octets())
            elif isinstance(s, (bytes, bytearray)):
                if len(s) != 16:
                    raise ValueError(f"segment must be 16 bytes, got {len(s)}")
                flat.extend(s)
            else:
                raise TypeError(
                    f"segment must be Sid or bytes, got {type(s).__name__}"
                )
        if segments_left is None:
            ptr = get_lib().lr_srv6_srh_new(bytes(flat), len(segments))
        else:
            ptr = get_lib().lr_srv6_srh_new_with_segments_left(
                bytes(flat), len(segments), segments_left
            )
        if ptr == ffi.NULL:
            raise LrError("lr_srv6_srh_new returned null")
        return cls(ptr)

    # ---- builder setters (return self for chaining) ----

    def with_next_header(self, next_header: int) -> "Srh":
        """Set the Next Header field (RFC 8200 §2)."""
        rc = get_lib().lr_srv6_srh_set_next_header(self._ptr, next_header)
        _check(rc, "lr_srv6_srh_set_next_header")
        return self

    def with_flags(self, flags: int) -> "Srh":
        """Set the flags (RFC 8754 §2.1)."""
        rc = get_lib().lr_srv6_srh_set_flags(self._ptr, flags)
        _check(rc, "lr_srv6_srh_set_flags")
        return self

    def with_tag(self, tag: int) -> "Srh":
        """Set the Tag field (RFC 8754 §2.4)."""
        rc = get_lib().lr_srv6_srh_set_tag(self._ptr, tag)
        _check(rc, "lr_srv6_srh_set_tag")
        return self

    def with_tlvs(self, tlvs: bytes) -> "Srh":
        """Set the TLV bytes (RFC 8754 §2.6)."""
        if not isinstance(tlvs, (bytes, bytearray)):
            raise TypeError(f"tlvs must be bytes, got {type(tlvs).__name__}")
        rc = get_lib().lr_srv6_srh_set_tlvs(self._ptr, bytes(tlvs), len(tlvs))
        _check(rc, "lr_srv6_srh_set_tlvs")
        return self

    # ---- accessors ----

    def next_header(self) -> int:
        return int(get_lib().lr_srv6_srh_next_header(self._ptr))

    def segments_left(self) -> int:
        return int(get_lib().lr_srv6_srh_segments_left(self._ptr))

    def last_entry(self) -> int:
        return int(get_lib().lr_srv6_srh_last_entry(self._ptr))

    def flags(self) -> int:
        return int(get_lib().lr_srv6_srh_flags(self._ptr))

    def tag(self) -> int:
        return int(get_lib().lr_srv6_srh_tag(self._ptr))

    def segment_count(self) -> int:
        return int(get_lib().lr_srv6_srh_segment_count(self._ptr))

    def segment_at(self, index: int) -> bytes | None:
        """Segment at `index` (16 raw bytes) or `None` if out of range."""
        out = _u8_buf(16)
        rc = get_lib().lr_srv6_srh_segment_at(self._ptr, index, out)
        if rc != 0:
            return None
        return bytes(ffi.buffer(out, 16))

    def segments(self) -> list[bytes]:
        """All segments as a list of 16-byte `bytes`."""
        n = self.segment_count()
        return [self.segment_at(i) for i in range(n)]  # type: ignore[misc]

    def tlvs(self) -> bytes:
        """The TLV bytes following the segment list (RFC 8754 §2.6)."""
        b = alloc_bytes()
        rc = get_lib().lr_srv6_srh_tlvs(self._ptr, b)
        _check(rc, "lr_srv6_srh_tlvs")
        out = copy_bytes(b)
        free_bytes(b)
        return out

    def first_segment(self) -> bytes | None:
        """Segment List[0] — the destination address at the sender (RFC 8754 §4.1)."""
        out = _u8_buf(16)
        rc = get_lib().lr_srv6_srh_first_segment(self._ptr, out)
        if rc != 0:
            return None
        return bytes(ffi.buffer(out, 16))

    def current_destination(self) -> bytes | None:
        """Segment List[Segments Left] — the current destination (RFC 8754 §4.1)."""
        out = _u8_buf(16)
        rc = get_lib().lr_srv6_srh_current_destination(self._ptr, out)
        if rc != 0:
            return None
        return bytes(ffi.buffer(out, 16))

    def len(self) -> int:
        """Number of segments in the SRH (mirrors `Srh::len`).

        For the wire length in bytes, see [`Srh.encode`] (whose
        `bytes` length is the wire length) or compute it as
        `SRH_FIXED_LEN + segment_count * SRH_SEGMENT_LEN + len(tlvs)`,
        rounded up to a multiple of 8.
        """
        return int(get_lib().lr_srv6_srh_len(self._ptr))

    def is_empty(self) -> bool:
        """True when the SRH has no segments."""
        return bool(get_lib().lr_srv6_srh_is_empty(self._ptr))

    def hdr_ext_len(self) -> int:
        """The Hdr Ext Len field (RFC 8200 §4.8 — 8-octet units, minus 1)."""
        return int(get_lib().lr_srv6_srh_hdr_ext_len(self._ptr))

    def encode(self) -> bytes:
        """Encode the SRH into wire bytes (RFC 8754 §2 — auto-padded to
        a multiple of 8 octets). Raises `SrhError` on encode failure."""
        b = alloc_bytes()
        rc = get_lib().lr_srv6_srh_encode(self._ptr, b)
        if rc != 0:
            free_bytes(b)
            srh = SrhError.from_last()
            raise srh if srh is not None else LrError(
                f"lr_srv6_srh_encode failed (rc={rc}): {_last_error()}"
            )
        out = copy_bytes(b)
        free_bytes(b)
        return out


class Behavior:
    """RFC 8986 endpoint behavior registry — End, End.X, End.DX6, End.DT4,
    End.B6.Encaps.Red, etc. with the exact 16-bit IANA wire values.

    The class is a thin wrapper around the C ABI's `lr_srv6_behavior_*`
    functions; instances are not constructed — all methods are class
    methods or static, mirroring the Rust `Behavior` enum's
    `from_wire` / `wire_value` / `is_psp` / `name` shape.
    """

    # No instances — every method is class-level.
    def __init__(self):
        raise TypeError("Behavior is a static registry; do not instantiate")

    # ---- wire parsing ----

    @classmethod
    def from_wire(cls, wire: int) -> tuple[int, str] | None:
        """Parse a 16-bit wire value into `(canonical_wire, name)`.

        Returns `None` if the wire value does not name a known behavior.
        Mirrors `Behavior::from_wire` in `lr_srv6::behavior`. The
        `canonical_wire` is the wire value with reserved flag bits
        stripped; the `name` is the IANA-registered mnemonic (e.g.
        `"End"`, `"End.X"`, `"End.DX6"`).
        """
        out_value = ffi.new("uint16_t*")
        cap = 64
        buf = ffi.new(f"char[{cap}]")
        ok = get_lib().lr_srv6_behavior_from_wire(wire, out_value, buf, cap)
        if not ok:
            return None
        name = ffi.string(buf).decode("utf-8", errors="replace")
        return (int(out_value[0]), name)

    @classmethod
    def wire_value(cls, wire: int) -> int:
        """Canonical wire value for `wire` (strips reserved bits)."""
        return int(get_lib().lr_srv6_behavior_wire_value(wire))

    # ---- flag-bit queries (RFC 8986 §4.1 — PSP/USP/USD) ----

    @classmethod
    def is_psp(cls, wire: int) -> bool:
        """True when the behavior carries the Penultimate Segment Pop flag."""
        return bool(get_lib().lr_srv6_behavior_is_psp(wire))

    @classmethod
    def is_usp(cls, wire: int) -> bool:
        """True when the behavior carries the Ultimate Segment Pop flag."""
        return bool(get_lib().lr_srv6_behavior_is_usp(wire))

    @classmethod
    def is_usd(cls, wire: int) -> bool:
        """True when the behavior carries the Ultimate Segment Decap flag."""
        return bool(get_lib().lr_srv6_behavior_is_usd(wire))

    @classmethod
    def is_decap(cls, wire: int) -> bool:
        """True when the behavior decapsulates the inner packet (End.DX*/DT*)."""
        return bool(get_lib().lr_srv6_behavior_is_decap(wire))

    @classmethod
    def is_cross_connect(cls, wire: int) -> bool:
        """True when the behavior is a cross-connect variant (End.X)."""
        return bool(get_lib().lr_srv6_behavior_is_cross_connect(wire))

    @classmethod
    def is_table_lookup(cls, wire: int) -> bool:
        """True when the behavior does a table lookup (End.DT*/End.DX6/...)."""
        return bool(get_lib().lr_srv6_behavior_is_table_lookup(wire))

    # ---- naming ----

    @classmethod
    def name(cls, wire: int) -> str:
        """The IANA-registered behavior name (e.g. "End", "End.X",
        "End.DT4"). Returns the wire value as a hex string when the
        behavior is unknown."""
        cap = 64
        buf = ffi.new(f"char[{cap}]")
        n = get_lib().lr_srv6_behavior_name(wire, buf, cap)
        if n == 0:
            return f"Unknown(0x{wire:04x})"
        return ffi.string(buf).decode("utf-8", errors="replace")


__all__ = [
    # Constants
    "ROUTING_TYPE_SRH",
    "FLAG_OAM",
    "FLAG_HMAC",
    "FLAG_ALERT",
    "FLAG_PROTECTED",
    "SRH_FIXED_LEN",
    "SRH_SEGMENT_LEN",
    "TLV_PAD1",
    "TLV_PADN",
    "MAX_SEGMENTS",
    "MAX_BLOCK_BITS",
    "SRH_ERR_TOO_SHORT",
    "SRH_ERR_LENGTH_MISMATCH",
    "SRH_ERR_EMPTY_SEGMENT_LIST",
    "SRH_ERR_TOO_MANY_SEGMENTS",
    "SRH_ERR_LAST_ENTRY_OUT_OF_RANGE",
    "SRH_ERR_SEGMENTS_LEFT_OUT_OF_RANGE",
    "SRH_ERR_WRONG_ROUTING_TYPE",
    "SRH_ERR_RESERVED_FLAG_BITS",
    "SRH_ERR_UNKNOWN",
    # Types
    "Sid",
    "Locator",
    "Srh",
    "Behavior",
    "SrhError",
    "SidParseError",
    "LocatorParseError",
]
