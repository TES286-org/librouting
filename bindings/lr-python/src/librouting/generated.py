"""Auto-generated low-level Python wrappers for the C ABI.

Produced by ``scripts/gen_python.py`` from ``include/lr_ffi.h``.
Each class is a thin RAII wrapper around an opaque C handle;
methods are 1:1 pass-throughs to the corresponding ``lr_*`` entry points.
Prefer the hand-written wrappers in the other modules when they exist.
"""

from __future__ import annotations

from ._ffi import ffi, get_lib, last_error
from .router import LrError

_lib = get_lib()


class BabelAckReq:
    """Low-level RAII wrapper around ``lr_babel_ack_req_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_ack_req_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_ack_req_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, nonce, interval_cs):
        """Construct a new ``lr_babel_ack_req_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_babel_ack_req_new(nonce, interval_cs)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def nonce(self):
        """Low-level wrapper for ``lr_babel_ack_req_nonce``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_ack_req_nonce(self._ptr)

    def interval_cs(self):
        """Low-level wrapper for ``lr_babel_ack_req_interval_cs``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_ack_req_interval_cs(self._ptr)


class BabelAck:
    """Low-level RAII wrapper around ``lr_babel_ack_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_ack_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_ack_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, opaque):
        """Construct a new ``lr_babel_ack_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_babel_ack_new(opaque)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def opaque(self):
        """Low-level wrapper for ``lr_babel_ack_opaque``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_ack_opaque(self._ptr)

    def encode(self, out):
        """Low-level wrapper for ``lr_babel_ack_encode``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_ack_encode(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BabelHello:
    """Low-level RAII wrapper around ``lr_babel_hello_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_hello_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_hello_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, seqno, interval_cs):
        """Construct a new ``lr_babel_hello_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_babel_hello_new(seqno, interval_cs)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def set_unicast(self, on):
        """Low-level wrapper for ``lr_babel_hello_set_unicast``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_hello_set_unicast(self._ptr, on)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def seqno(self):
        """Low-level wrapper for ``lr_babel_hello_seqno``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_hello_seqno(self._ptr)

    def interval_cs(self):
        """Low-level wrapper for ``lr_babel_hello_interval_cs``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_hello_interval_cs(self._ptr)

    def flags(self):
        """Low-level wrapper for ``lr_babel_hello_flags``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_hello_flags(self._ptr)

    def timestamp(self, present, ts_us):
        """Low-level wrapper for ``lr_babel_hello_timestamp``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_hello_timestamp(self._ptr, present, ts_us)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def encode(self, out):
        """Low-level wrapper for ``lr_babel_hello_encode``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_hello_encode(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BabelIhu:
    """Low-level RAII wrapper around ``lr_babel_ihu_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_ihu_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_ihu_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, rxcost, interval_cs):
        """Construct a new ``lr_babel_ihu_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_babel_ihu_new(rxcost, interval_cs)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def rxcost(self):
        """Low-level wrapper for ``lr_babel_ihu_rxcost``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_ihu_rxcost(self._ptr)

    def interval_cs(self):
        """Low-level wrapper for ``lr_babel_ihu_interval_cs``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_ihu_interval_cs(self._ptr)

    def ae(self):
        """Low-level wrapper for ``lr_babel_ihu_ae``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_ihu_ae(self._ptr)

    def address(self, octets_out, present_out):
        """Low-level wrapper for ``lr_babel_ihu_address``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_ihu_address(self._ptr, octets_out, present_out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def encode(self, out):
        """Low-level wrapper for ``lr_babel_ihu_encode``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_ihu_encode(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BabelMacKey:
    """Low-level RAII wrapper around ``lr_babel_mac_key_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_mac_key_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_mac_key_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, algorithm, secret, secret_len):
        """Construct a new ``lr_babel_mac_key_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_babel_mac_key_new(algorithm, secret, secret_len)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def algorithm(self):
        """Low-level wrapper for ``lr_babel_mac_key_algorithm``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_mac_key_algorithm(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def digest_len(self):
        """Low-level wrapper for ``lr_babel_mac_key_digest_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_mac_key_digest_len(self._ptr)

    def secret_len(self):
        """Low-level wrapper for ``lr_babel_mac_key_secret_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_mac_key_secret_len(self._ptr)

    def secret_copy(self, out, cap):
        """Low-level wrapper for ``lr_babel_mac_key_secret_copy``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_mac_key_secret_copy(self._ptr, out, cap)


class BabelNextHop:
    """Low-level RAII wrapper around ``lr_babel_next_hop_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_next_hop_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_next_hop_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def ae(self):
        """Low-level wrapper for ``lr_babel_next_hop_ae``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_next_hop_ae(self._ptr)

    def address(self, out, out_len):
        """Low-level wrapper for ``lr_babel_next_hop_address``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_next_hop_address(self._ptr, out, out_len)

    def encode(self, out):
        """Low-level wrapper for ``lr_babel_next_hop_encode``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_next_hop_encode(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BabelPacketCounter:
    """Low-level RAII wrapper around ``lr_babel_packet_counter_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_packet_counter_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_packet_counter_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, index, index_len, initial):
        """Construct a new ``lr_babel_packet_counter_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_babel_packet_counter_new(index, index_len, initial)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def peek_counter(self):
        """Low-level wrapper for ``lr_babel_packet_counter_peek_counter``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_packet_counter_peek_counter(self._ptr)

    def peek_index_len(self):
        """Low-level wrapper for ``lr_babel_packet_counter_peek_index_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_packet_counter_peek_index_len(self._ptr)

    def peek_index_copy(self, out, cap):
        """Low-level wrapper for ``lr_babel_packet_counter_peek_index_copy``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_packet_counter_peek_index_copy(self._ptr, out, cap)


class BabelPseudoHeader:
    """Low-level RAII wrapper around ``lr_babel_pseudo_header_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_pseudo_header_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_pseudo_header_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def encode(self, out):
        """Low-level wrapper for ``lr_babel_pseudo_header_encode``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_pseudo_header_encode(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BabelReplayProtection:
    """Low-level RAII wrapper around ``lr_babel_replay_protection_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_replay_protection_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_replay_protection_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_babel_replay_protection_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_babel_replay_protection_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def accept(self, index, index_len, counter):
        """Low-level wrapper for ``lr_babel_replay_protection_accept``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_replay_protection_accept(self._ptr, index, index_len, counter)


class BabelRouteRequest:
    """Low-level RAII wrapper around ``lr_babel_route_request_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_route_request_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_route_request_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class BabelSeqnoRequest:
    """Low-level RAII wrapper around ``lr_babel_seqno_request_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_seqno_request_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_seqno_request_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, prefix_v4, prefix_v6, prefix_len, seqno, router_id, hop_count):
        """Construct a new ``lr_babel_seqno_request_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_babel_seqno_request_new(prefix_v4, prefix_v6, prefix_len, seqno, router_id, hop_count)
        if not p:
            raise LrError(last_error())
        return cls(p)


class BabelTlv:
    """Low-level RAII wrapper around ``lr_babel_tlv_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_tlv_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_tlv_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, kind, value, value_len):
        """Construct a new ``lr_babel_tlv_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_babel_tlv_new(kind, value, value_len)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def kind(self):
        """Low-level wrapper for ``lr_babel_tlv_kind``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_tlv_kind(self._ptr)

    def value(self, out):
        """Low-level wrapper for ``lr_babel_tlv_value``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_tlv_value(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BabelUpdate:
    """Low-level RAII wrapper around ``lr_babel_update_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_babel_update_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_babel_update_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, prefix_len_bits, prefix, prefix_len_bytes, seqno, metric):
        """Construct a new ``lr_babel_update_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_babel_update_new(prefix_len_bits, prefix, prefix_len_bytes, seqno, metric)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def ae(self):
        """Low-level wrapper for ``lr_babel_update_ae``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_update_ae(self._ptr)

    def flags(self):
        """Low-level wrapper for ``lr_babel_update_flags``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_update_flags(self._ptr)

    def prefix_len(self):
        """Low-level wrapper for ``lr_babel_update_prefix_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_update_prefix_len(self._ptr)

    def omitted(self):
        """Low-level wrapper for ``lr_babel_update_omitted``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_update_omitted(self._ptr)

    def interval_cs(self):
        """Low-level wrapper for ``lr_babel_update_interval_cs``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_update_interval_cs(self._ptr)

    def seqno(self):
        """Low-level wrapper for ``lr_babel_update_seqno``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_update_seqno(self._ptr)

    def metric(self):
        """Low-level wrapper for ``lr_babel_update_metric``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_update_metric(self._ptr)

    def prefix(self, out, out_len):
        """Low-level wrapper for ``lr_babel_update_prefix``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_update_prefix(self._ptr, out, out_len)

    def prefix_len_bytes(self):
        """Low-level wrapper for ``lr_babel_update_prefix_len_bytes``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_update_prefix_len_bytes(self._ptr)

    def src_prefix_len(self):
        """Low-level wrapper for ``lr_babel_update_src_prefix_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_update_src_prefix_len(self._ptr)

    def src_prefix(self, out, out_len):
        """Low-level wrapper for ``lr_babel_update_src_prefix``. See ``include/lr_ffi.h``."""
        return _lib.lr_babel_update_src_prefix(self._ptr, out, out_len)

    def set_ae(self, ae):
        """Low-level wrapper for ``lr_babel_update_set_ae``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_update_set_ae(self._ptr, ae)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_flags(self, flags):
        """Low-level wrapper for ``lr_babel_update_set_flags``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_update_set_flags(self._ptr, flags)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_omitted(self, omitted):
        """Low-level wrapper for ``lr_babel_update_set_omitted``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_update_set_omitted(self._ptr, omitted)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_interval_cs(self, interval_cs):
        """Low-level wrapper for ``lr_babel_update_set_interval_cs``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_update_set_interval_cs(self._ptr, interval_cs)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def encode(self, out):
        """Low-level wrapper for ``lr_babel_update_encode``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_babel_update_encode(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BfdConfig:
    """Low-level RAII wrapper around ``lr_bfd_config_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bfd_config_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bfd_config_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, detect_mult, desired_min_tx_interval_us, required_min_rx_interval_us, required_min_echo_interval_us, role):
        """Construct a new ``lr_bfd_config_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bfd_config_new(detect_mult, desired_min_tx_interval_us, required_min_rx_interval_us, required_min_echo_interval_us, role)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def detect_mult(self):
        """Low-level wrapper for ``lr_bfd_config_detect_mult``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_config_detect_mult(self._ptr)

    def role(self):
        """Low-level wrapper for ``lr_bfd_config_role``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_config_role(self._ptr)

    def desired_min_tx_interval(self):
        """Low-level wrapper for ``lr_bfd_config_desired_min_tx_interval``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_config_desired_min_tx_interval(self._ptr)

    def required_min_rx_interval(self):
        """Low-level wrapper for ``lr_bfd_config_required_min_rx_interval``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_config_required_min_rx_interval(self._ptr)

    def required_min_echo_interval(self):
        """Low-level wrapper for ``lr_bfd_config_required_min_echo_interval``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_config_required_min_echo_interval(self._ptr)

    def set_detect_mult(self, value):
        """Low-level wrapper for ``lr_bfd_config_set_detect_mult``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_config_set_detect_mult(self._ptr, value)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_desired_min_tx_interval(self, value):
        """Low-level wrapper for ``lr_bfd_config_set_desired_min_tx_interval``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_config_set_desired_min_tx_interval(self._ptr, value)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_required_min_rx_interval(self, value):
        """Low-level wrapper for ``lr_bfd_config_set_required_min_rx_interval``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_config_set_required_min_rx_interval(self._ptr, value)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_required_min_echo_interval(self, value):
        """Low-level wrapper for ``lr_bfd_config_set_required_min_echo_interval``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_config_set_required_min_echo_interval(self._ptr, value)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_role(self, role):
        """Low-level wrapper for ``lr_bfd_config_set_role``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_config_set_role(self._ptr, role)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_auth_key(self, password, password_len):
        """Low-level wrapper for ``lr_bfd_config_set_auth_key``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_config_set_auth_key(self._ptr, password, password_len)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def has_auth_key(self):
        """Low-level wrapper for ``lr_bfd_config_has_auth_key``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_config_has_auth_key(self._ptr)


class BfdSessionEvent:
    """Low-level RAII wrapper around ``lr_bfd_session_event_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bfd_session_event_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bfd_session_event_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def kind(self):
        """Low-level wrapper for ``lr_bfd_session_event_kind``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_event_kind(self._ptr)

    def state_change_fields(self, out_from, out_to, out_diag):
        """Low-level wrapper for ``lr_bfd_session_event_state_change_fields``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_session_event_state_change_fields(self._ptr, out_from, out_to, out_diag)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BfdSession:
    """Low-level RAII wrapper around ``lr_bfd_session_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bfd_session_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bfd_session_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def set_keyed_auth(self, auth):
        """Low-level wrapper for ``lr_bfd_session_set_keyed_auth``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_session_set_keyed_auth(self._ptr, auth)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def keyed_auth_present(self):
        """Low-level wrapper for ``lr_bfd_session_keyed_auth_present``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_keyed_auth_present(self._ptr)

    def update_timers(self, now_ms, desired_min_tx, required_min_rx, out_array, out_count):
        """Low-level wrapper for ``lr_bfd_session_update_timers``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_session_update_timers(self._ptr, now_ms, desired_min_tx, required_min_rx, out_array, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def remote_detect_mult(self):
        """Low-level wrapper for ``lr_bfd_session_remote_detect_mult``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_remote_detect_mult(self._ptr)

    def poll_active(self):
        """Low-level wrapper for ``lr_bfd_session_poll_active``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_poll_active(self._ptr)

    def remote_diag(self):
        """Low-level wrapper for ``lr_bfd_session_remote_diag``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_remote_diag(self._ptr)

    def state(self):
        """Low-level wrapper for ``lr_bfd_session_state``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_state(self._ptr)

    def is_up(self):
        """Low-level wrapper for ``lr_bfd_session_is_up``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_is_up(self._ptr)

    def my_discriminator(self):
        """Low-level wrapper for ``lr_bfd_session_my_discriminator``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_my_discriminator(self._ptr)

    def remote_discriminator(self):
        """Low-level wrapper for ``lr_bfd_session_remote_discriminator``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_remote_discriminator(self._ptr)

    def local_diag(self):
        """Low-level wrapper for ``lr_bfd_session_local_diag``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_local_diag(self._ptr)

    def remote_state(self):
        """Low-level wrapper for ``lr_bfd_session_remote_state``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_remote_state(self._ptr)

    def tx_interval_us(self):
        """Low-level wrapper for ``lr_bfd_session_tx_interval_us``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_tx_interval_us(self._ptr)

    def detection_time_us(self):
        """Low-level wrapper for ``lr_bfd_session_detection_time_us``. See ``include/lr_ffi.h``."""
        return _lib.lr_bfd_session_detection_time_us(self._ptr)

    def drain_outgoing(self, out):
        """Low-level wrapper for ``lr_bfd_session_drain_outgoing``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_session_drain_outgoing(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def feed_bytes(self, now_ms, data, len, out_array, out_count):
        """Low-level wrapper for ``lr_bfd_session_feed_bytes``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_session_feed_bytes(self._ptr, now_ms, data, len, out_array, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def tick(self, now_ms, out_array, out_count):
        """Low-level wrapper for ``lr_bfd_session_tick``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_session_tick(self._ptr, now_ms, out_array, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def start(self, now_ms, out_array, out_count):
        """Low-level wrapper for ``lr_bfd_session_start``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_session_start(self._ptr, now_ms, out_array, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def admin_down(self, out_array, out_count):
        """Low-level wrapper for ``lr_bfd_session_admin_down``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bfd_session_admin_down(self._ptr, out_array, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BgpCapabilityArray:
    """Low-level RAII wrapper around ``lr_bgp_capability_array_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def __del__(self):
        pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class BgpCapability:
    """Low-level RAII wrapper around ``lr_bgp_capability_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_capability_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_cap_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class BgpCodec:
    """Low-level RAII wrapper around ``lr_bgp_codec_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_codec_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_codec_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_bgp_codec_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bgp_codec_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def set_asn4(self, asn4):
        """Low-level wrapper for ``lr_bgp_codec_set_asn4``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_codec_set_asn4(self._ptr, asn4)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def asn4_active(self):
        """Low-level wrapper for ``lr_bgp_codec_asn4_active``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_codec_asn4_active(self._ptr)

    def set_add_path(self, tx, tx_count, rx, rx_count):
        """Low-level wrapper for ``lr_bgp_codec_set_add_path``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_codec_set_add_path(self._ptr, tx, tx_count, rx, rx_count)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def decode_slice(self, data, len, out):
        """Low-level wrapper for ``lr_bgp_codec_decode_slice``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_codec_decode_slice(self._ptr, data, len, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def encode_vec(self, msg, out):
        """Low-level wrapper for ``lr_bgp_codec_encode_vec``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_codec_encode_vec(self._ptr, msg, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BgpCommunity:
    """Low-level RAII wrapper around ``lr_bgp_community_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_community_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_community_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, asn, value):
        """Construct a new ``lr_bgp_community_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bgp_community_new(asn, value)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def as_u32(self):
        """Low-level wrapper for ``lr_bgp_community_as_u32``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_community_as_u32(self._ptr)

    def asn(self):
        """Low-level wrapper for ``lr_bgp_community_asn``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_community_asn(self._ptr)

    def value(self):
        """Low-level wrapper for ``lr_bgp_community_value``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_community_value(self._ptr)

    def kind(self):
        """Low-level wrapper for ``lr_bgp_community_kind``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_community_kind(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BgpConfedConfig:
    """Low-level RAII wrapper around ``lr_bgp_confed_config_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_confed_config_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_confed_config_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, members, count, confederation_id):
        """Construct a new ``lr_bgp_confed_config_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bgp_confed_config_new(members, count, confederation_id)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def contains(self, asn):
        """Low-level wrapper for ``lr_bgp_confed_config_contains``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_confed_config_contains(self._ptr, asn)

    def external_as(self):
        """Low-level wrapper for ``lr_bgp_confed_config_external_as``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_confed_config_external_as(self._ptr)

    def member_count(self):
        """Low-level wrapper for ``lr_bgp_confed_config_member_count``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_confed_config_member_count(self._ptr)

    def member_at(self, index):
        """Low-level wrapper for ``lr_bgp_confed_config_member_at``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_confed_config_member_at(self._ptr, index)


class BgpExtCommunity:
    """Low-level RAII wrapper around ``lr_bgp_ext_community_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_ext_community_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_ext_community_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, kind, subtype, global_, local):
        """Construct a new ``lr_bgp_ext_community_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bgp_ext_community_new(kind, subtype, global_, local)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def kind(self):
        """Low-level wrapper for ``lr_bgp_ext_community_kind``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_ext_community_kind(self._ptr)

    def subtype(self):
        """Low-level wrapper for ``lr_bgp_ext_community_subtype``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_ext_community_subtype(self._ptr)

    def global_(self):
        """Low-level wrapper for ``lr_bgp_ext_community_global``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_ext_community_global(self._ptr)

    def local(self):
        """Low-level wrapper for ``lr_bgp_ext_community_local``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_ext_community_local(self._ptr)


class BgpLsAttr:
    """Low-level RAII wrapper around ``lr_bgp_ls_attr_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_ls_attr_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_ls_attr_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_bgp_ls_attr_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bgp_ls_attr_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def len(self):
        """Low-level wrapper for ``lr_bgp_ls_attr_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_ls_attr_len(self._ptr)

    def is_empty(self):
        """Low-level wrapper for ``lr_bgp_ls_attr_is_empty``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_ls_attr_is_empty(self._ptr)

    def value_len(self):
        """Low-level wrapper for ``lr_bgp_ls_attr_value_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_ls_attr_value_len(self._ptr)

    def encode(self, out):
        """Low-level wrapper for ``lr_bgp_ls_attr_encode``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_ls_attr_encode(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def find(self, ty, out_index):
        """Low-level wrapper for ``lr_bgp_ls_attr_find``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_ls_attr_find(self._ptr, ty, out_index)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BgpLsTlvVec:
    """Low-level RAII wrapper around ``lr_bgp_ls_tlv_vec_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_ls_tlv_vec_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_ls_tlv_vec_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def len(self):
        """Low-level wrapper for ``lr_bgp_ls_tlv_vec_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_ls_tlv_vec_len(self._ptr)

    def at(self, index):
        """Low-level wrapper for ``lr_bgp_ls_tlv_vec_at``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_ls_tlv_vec_at(self._ptr, index)


class BgpOtc:
    """Low-level RAII wrapper around ``lr_bgp_otc_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_otc_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_otc_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, asn):
        """Construct a new ``lr_bgp_otc_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bgp_otc_new(asn)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def encode(self, out):
        """Low-level wrapper for ``lr_bgp_otc_encode``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_otc_encode(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def value(self):
        """Low-level wrapper for ``lr_bgp_otc_value``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_otc_value(self._ptr)

    def is_set(self):
        """Low-level wrapper for ``lr_bgp_otc_is_set``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_otc_is_set(self._ptr)


class BgpPeerConfig:
    """Low-level RAII wrapper around ``lr_bgp_peer_config_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_peer_config_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_peer_config_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, local_as, peer_as, local_bgp_id):
        """Construct a new ``lr_bgp_peer_config_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bgp_peer_config_new(local_as, peer_as, local_bgp_id)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def local_as(self):
        """Low-level wrapper for ``lr_bgp_peer_config_local_as``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_local_as(self._ptr)

    def peer_as(self):
        """Low-level wrapper for ``lr_bgp_peer_config_peer_as``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_peer_as(self._ptr)

    def local_bgp_id(self, out):
        """Low-level wrapper for ``lr_bgp_peer_config_local_bgp_id``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_config_local_bgp_id(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def hold_time(self):
        """Low-level wrapper for ``lr_bgp_peer_config_hold_time``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_hold_time(self._ptr)

    def keepalive(self):
        """Low-level wrapper for ``lr_bgp_peer_config_keepalive``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_keepalive(self._ptr)

    def asn4(self):
        """Low-level wrapper for ``lr_bgp_peer_config_asn4``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_asn4(self._ptr)

    def route_refresh(self):
        """Low-level wrapper for ``lr_bgp_peer_config_route_refresh``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_route_refresh(self._ptr)

    def enhanced_rr(self):
        """Low-level wrapper for ``lr_bgp_peer_config_enhanced_rr``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_enhanced_rr(self._ptr)

    def graceful_restart(self):
        """Low-level wrapper for ``lr_bgp_peer_config_graceful_restart``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_graceful_restart(self._ptr)

    def graceful_restart_time(self):
        """Low-level wrapper for ``lr_bgp_peer_config_graceful_restart_time``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_graceful_restart_time(self._ptr)

    def long_lived(self):
        """Low-level wrapper for ``lr_bgp_peer_config_long_lived``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_long_lived(self._ptr)

    def long_lived_stale_time(self):
        """Low-level wrapper for ``lr_bgp_peer_config_long_lived_stale_time``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_long_lived_stale_time(self._ptr)

    def is_rr_client(self):
        """Low-level wrapper for ``lr_bgp_peer_config_is_rr_client``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_is_rr_client(self._ptr)

    def is_rs_client(self):
        """Low-level wrapper for ``lr_bgp_peer_config_is_rs_client``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_is_rs_client(self._ptr)

    def default_ipv4_unicast(self):
        """Low-level wrapper for ``lr_bgp_peer_config_default_ipv4_unicast``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_default_ipv4_unicast(self._ptr)

    def add_path(self):
        """Low-level wrapper for ``lr_bgp_peer_config_add_path``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_add_path(self._ptr)

    def is_ebgp(self):
        """Low-level wrapper for ``lr_bgp_peer_config_is_ebgp``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_is_ebgp(self._ptr)

    def keepalive_interval(self):
        """Low-level wrapper for ``lr_bgp_peer_config_keepalive_interval``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_keepalive_interval(self._ptr)

    def ipv4_unicast_active(self):
        """Low-level wrapper for ``lr_bgp_peer_config_ipv4_unicast_active``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_ipv4_unicast_active(self._ptr)

    def peer_role(self):
        """Low-level wrapper for ``lr_bgp_peer_config_peer_role``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_config_peer_role(self._ptr)

    def set_hold_time(self, hold_time):
        """Low-level wrapper for ``lr_bgp_peer_config_set_hold_time``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_config_set_hold_time(self._ptr, hold_time)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_keepalive(self, keepalive):
        """Low-level wrapper for ``lr_bgp_peer_config_set_keepalive``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_config_set_keepalive(self._ptr, keepalive)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_asn4(self, asn4):
        """Low-level wrapper for ``lr_bgp_peer_config_set_asn4``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_config_set_asn4(self._ptr, asn4)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_rr_client(self, enabled):
        """Low-level wrapper for ``lr_bgp_peer_config_set_rr_client``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_config_set_rr_client(self._ptr, enabled)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_graceful_restart(self, enabled):
        """Low-level wrapper for ``lr_bgp_peer_config_set_graceful_restart``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_config_set_graceful_restart(self._ptr, enabled)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BgpPeer:
    """Low-level RAII wrapper around ``lr_bgp_peer_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_peer_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_peer_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, local_as, peer_as, local_bgp_id, hold_time, keepalive, asn4):
        """Construct a new ``lr_bgp_peer_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bgp_peer_new(local_as, peer_as, local_bgp_id, hold_time, keepalive, asn4)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def state(self):
        """Low-level wrapper for ``lr_bgp_peer_state``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_state(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def is_established(self):
        """Low-level wrapper for ``lr_bgp_peer_is_established``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_is_established(self._ptr)

    def peer_bgp_id(self, out):
        """Low-level wrapper for ``lr_bgp_peer_peer_bgp_id``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_peer_bgp_id(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def peer_as(self, out):
        """Low-level wrapper for ``lr_bgp_peer_peer_as``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_peer_as(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def negotiated_hold_time(self):
        """Low-level wrapper for ``lr_bgp_peer_negotiated_hold_time``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_negotiated_hold_time(self._ptr)

    def feed_bytes(self, data, len):
        """Low-level wrapper for ``lr_bgp_peer_feed_bytes``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_feed_bytes(self._ptr, data, len)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def drain_outgoing(self, out):
        """Low-level wrapper for ``lr_bgp_peer_drain_outgoing``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_drain_outgoing(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_manual_start(self):
        """Low-level wrapper for ``lr_bgp_peer_step_manual_start``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_step_manual_start(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_manual_stop(self):
        """Low-level wrapper for ``lr_bgp_peer_step_manual_stop``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_step_manual_stop(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_transport_open(self):
        """Low-level wrapper for ``lr_bgp_peer_step_transport_open``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_step_transport_open(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_transport_fatal(self):
        """Low-level wrapper for ``lr_bgp_peer_step_transport_fatal``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_step_transport_fatal(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_transport_close(self):
        """Low-level wrapper for ``lr_bgp_peer_step_transport_close``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_step_transport_close(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_timer_connect_retry(self):
        """Low-level wrapper for ``lr_bgp_peer_step_timer_connect_retry``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_step_timer_connect_retry(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_timer_hold_expired(self):
        """Low-level wrapper for ``lr_bgp_peer_step_timer_hold_expired``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_step_timer_hold_expired(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_timer_keepalive(self):
        """Low-level wrapper for ``lr_bgp_peer_step_timer_keepalive``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_step_timer_keepalive(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_timer_idle_hold(self):
        """Low-level wrapper for ``lr_bgp_peer_step_timer_idle_hold``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_step_timer_idle_hold(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def advertise(self, route):
        """Low-level wrapper for ``lr_bgp_peer_advertise``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_advertise(self._ptr, route)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def advertise_with_originator(self, route, originator_bgp_id_present, originator_bgp_id_addr):
        """Low-level wrapper for ``lr_bgp_peer_advertise_with_originator``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_advertise_with_originator(self._ptr, route, originator_bgp_id_present, originator_bgp_id_addr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def withdraw(self, prefixes, count, family_afi, family_safi):
        """Low-level wrapper for ``lr_bgp_peer_withdraw``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_withdraw(self._ptr, prefixes, count, family_afi, family_safi)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def send_end_of_rib(self, family_afi, family_safi):
        """Low-level wrapper for ``lr_bgp_peer_send_end_of_rib``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_send_end_of_rib(self._ptr, family_afi, family_safi)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def message_stats(self, out):
        """Low-level wrapper for ``lr_bgp_peer_message_stats``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_message_stats(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def hold_time(self):
        """Low-level wrapper for ``lr_bgp_peer_hold_time``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_hold_time(self._ptr)

    def keepalive(self):
        """Low-level wrapper for ``lr_bgp_peer_keepalive``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_keepalive(self._ptr)

    def local_as(self):
        """Low-level wrapper for ``lr_bgp_peer_local_as``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_local_as(self._ptr)

    def asn4(self):
        """Low-level wrapper for ``lr_bgp_peer_asn4``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_asn4(self._ptr)

    def ipv4_unicast_active(self):
        """Low-level wrapper for ``lr_bgp_peer_ipv4_unicast_active``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_ipv4_unicast_active(self._ptr)

    def is_rr_client(self):
        """Low-level wrapper for ``lr_bgp_peer_is_rr_client``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_is_rr_client(self._ptr)

    def is_rs_client(self):
        """Low-level wrapper for ``lr_bgp_peer_is_rs_client``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_is_rs_client(self._ptr)

    def role(self):
        """Low-level wrapper for ``lr_bgp_peer_role``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_role(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def route_refresh_negotiated(self):
        """Low-level wrapper for ``lr_bgp_peer_route_refresh_negotiated``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_route_refresh_negotiated(self._ptr)

    def enhanced_route_refresh_negotiated(self):
        """Low-level wrapper for ``lr_bgp_peer_enhanced_route_refresh_negotiated``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_enhanced_route_refresh_negotiated(self._ptr)

    def add_path_negotiated(self):
        """Low-level wrapper for ``lr_bgp_peer_add_path_negotiated``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_add_path_negotiated(self._ptr)

    def add_path_tx_for(self, family):
        """Low-level wrapper for ``lr_bgp_peer_add_path_tx_for``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_add_path_tx_for(self._ptr, family)

    def add_path_rx_for(self, family):
        """Low-level wrapper for ``lr_bgp_peer_add_path_rx_for``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_add_path_rx_for(self._ptr, family)

    def extended_next_hop_for(self, nlri_afi, nlri_safi, nexthop_afi):
        """Low-level wrapper for ``lr_bgp_peer_extended_next_hop_for``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_extended_next_hop_for(self._ptr, nlri_afi, nlri_safi, nexthop_afi)

    def negotiated_graceful_restart_time(self):
        """Low-level wrapper for ``lr_bgp_peer_negotiated_graceful_restart_time``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_negotiated_graceful_restart_time(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def llgr_negotiated(self):
        """Low-level wrapper for ``lr_bgp_peer_llgr_negotiated``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_llgr_negotiated(self._ptr)

    def negotiated_llgr_stale_time(self, family):
        """Low-level wrapper for ``lr_bgp_peer_negotiated_llgr_stale_time``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_negotiated_llgr_stale_time(self._ptr, family)

    def received_cease_collision(self):
        """Low-level wrapper for ``lr_bgp_peer_received_cease_collision``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_received_cease_collision(self._ptr)

    def notification_received(self):
        """Low-level wrapper for ``lr_bgp_peer_notification_received``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_notification_received(self._ptr)

    def request_route_refresh(self, family):
        """Low-level wrapper for ``lr_bgp_peer_request_route_refresh``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_request_route_refresh(self._ptr, family)

    def begin_enhanced_route_refresh(self, family):
        """Low-level wrapper for ``lr_bgp_peer_begin_enhanced_route_refresh``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_begin_enhanced_route_refresh(self._ptr, family)

    def end_enhanced_route_refresh(self, family):
        """Low-level wrapper for ``lr_bgp_peer_end_enhanced_route_refresh``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_end_enhanced_route_refresh(self._ptr, family)

    def enqueue_notification(self, code, subcode):
        """Low-level wrapper for ``lr_bgp_peer_enqueue_notification``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_enqueue_notification(self._ptr, code, subcode)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def reset(self):
        """Low-level wrapper for ``lr_bgp_peer_reset``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_reset(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def advertised_tuples(self, out_count, out_array):
        """Low-level wrapper for ``lr_bgp_peer_advertised_tuples``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bgp_peer_advertised_tuples(self._ptr, out_count, out_array)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BgpPeerTopology:
    """Low-level RAII wrapper around ``lr_bgp_peer_topology_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_peer_topology_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_peer_topology_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, role, rr_client, rs_client, otc_role):
        """Construct a new ``lr_bgp_peer_topology_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bgp_peer_topology_new(role, rr_client, rs_client, otc_role)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def role(self):
        """Low-level wrapper for ``lr_bgp_peer_topology_role``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_topology_role(self._ptr)

    def rr_client(self):
        """Low-level wrapper for ``lr_bgp_peer_topology_rr_client``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_topology_rr_client(self._ptr)

    def rs_client(self):
        """Low-level wrapper for ``lr_bgp_peer_topology_rs_client``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_topology_rs_client(self._ptr)

    def otc_role(self):
        """Low-level wrapper for ``lr_bgp_peer_topology_otc_role``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_topology_otc_role(self._ptr)

    def can_advertise(self, from_, route_otc):
        """Low-level wrapper for ``lr_bgp_peer_topology_can_advertise``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_peer_topology_can_advertise(self._ptr, from_, route_otc)


class BgpRrConfig:
    """Low-level RAII wrapper around ``lr_bgp_rr_config_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_rr_config_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_rr_config_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, cluster_id, enabled):
        """Construct a new ``lr_bgp_rr_config_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bgp_rr_config_new(cluster_id, enabled)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def cluster_id(self):
        """Low-level wrapper for ``lr_bgp_rr_config_cluster_id``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_rr_config_cluster_id(self._ptr)

    def enabled(self):
        """Low-level wrapper for ``lr_bgp_rr_config_enabled``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_rr_config_enabled(self._ptr)


class BgpRsConfig:
    """Low-level RAII wrapper around ``lr_bgp_rs_config_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bgp_rs_config_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_rs_config_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, client, inbound_policy, outbound_policy):
        """Construct a new ``lr_bgp_rs_config_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bgp_rs_config_new(client, inbound_policy, outbound_policy)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def client(self):
        """Low-level wrapper for ``lr_bgp_rs_config_client``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_rs_config_client(self._ptr)

    def strip_count(self):
        """Low-level wrapper for ``lr_bgp_rs_config_strip_count``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_rs_config_strip_count(self._ptr)

    def strip_at(self, index):
        """Low-level wrapper for ``lr_bgp_rs_config_strip_at``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_rs_config_strip_at(self._ptr, index)

    def add_count(self):
        """Low-level wrapper for ``lr_bgp_rs_config_add_count``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_rs_config_add_count(self._ptr)

    def add_at(self, index):
        """Low-level wrapper for ``lr_bgp_rs_config_add_at``. See ``include/lr_ffi.h``."""
        return _lib.lr_bgp_rs_config_add_at(self._ptr, index)


class BmpCodec:
    """Low-level RAII wrapper around ``lr_bmp_codec_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bmp_codec_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bmp_codec_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_bmp_codec_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_bmp_codec_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def decode_slice(self, data, len, out):
        """Low-level wrapper for ``lr_bmp_codec_decode_slice``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bmp_codec_decode_slice(self._ptr, data, len, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def feed(self, data, len):
        """Low-level wrapper for ``lr_bmp_codec_feed``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bmp_codec_feed(self._ptr, data, len)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def next_message(self, out):
        """Low-level wrapper for ``lr_bmp_codec_next_message``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bmp_codec_next_message(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def encode_vec(self, m, out):
        """Low-level wrapper for ``lr_bmp_codec_encode_vec``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bmp_codec_encode_vec(self._ptr, m, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BmpMessage:
    """Low-level RAII wrapper around ``lr_bmp_message_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bmp_message_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bmp_message_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def type(self):
        """Low-level wrapper for ``lr_bmp_message_type``. See ``include/lr_ffi.h``."""
        return _lib.lr_bmp_message_type(self._ptr)

    def peer_present(self):
        """Low-level wrapper for ``lr_bmp_message_peer_present``. See ``include/lr_ffi.h``."""
        return _lib.lr_bmp_message_peer_present(self._ptr)

    def peer_header(self, out):
        """Low-level wrapper for ``lr_bmp_message_peer_header``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bmp_message_peer_header(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def payload_len(self):
        """Low-level wrapper for ``lr_bmp_message_payload_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_bmp_message_payload_len(self._ptr)

    def payload(self, out):
        """Low-level wrapper for ``lr_bmp_message_payload``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_bmp_message_payload(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class BytesT:
    """Low-level RAII wrapper around ``lr_bytes_t_handle``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_bytes_t_handle`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_bgp_cap_bytes_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class DampingTable:
    """Low-level RAII wrapper around ``lr_damping_table_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_damping_table_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_damping_table_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, cfg):
        """Construct a new ``lr_damping_table_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_damping_table_new(cfg)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def config(self, out):
        """Low-level wrapper for ``lr_damping_table_config``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_damping_table_config(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def on_withdraw(self, prefix, now_s):
        """Low-level wrapper for ``lr_damping_table_on_withdraw``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_damping_table_on_withdraw(self._ptr, prefix, now_s)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def on_announce(self, prefix, now_s):
        """Low-level wrapper for ``lr_damping_table_on_announce``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_damping_table_on_announce(self._ptr, prefix, now_s)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def is_suppressed(self, prefix):
        """Low-level wrapper for ``lr_damping_table_is_suppressed``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_damping_table_is_suppressed(self._ptr, prefix)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def decay_all(self, now_s, out_reactivated, cap):
        """Low-level wrapper for ``lr_damping_table_decay_all``. See ``include/lr_ffi.h``."""
        return _lib.lr_damping_table_decay_all(self._ptr, now_s, out_reactivated, cap)

    def forget(self, prefix):
        """Low-level wrapper for ``lr_damping_table_forget``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_damping_table_forget(self._ptr, prefix)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def len(self):
        """Low-level wrapper for ``lr_damping_table_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_damping_table_len(self._ptr)

    def at(self, index, out):
        """Low-level wrapper for ``lr_damping_table_at``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_damping_table_at(self._ptr, index, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class Filter:
    """Low-level RAII wrapper around ``lr_filter_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_filter_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_filter_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def name(self, out, cap):
        """Low-level wrapper for ``lr_filter_name``. See ``include/lr_ffi.h``."""
        return _lib.lr_filter_name(self._ptr, out, cap)

    def evaluate(self, route, ctx, out_verdict, out_reason):
        """Low-level wrapper for ``lr_filter_evaluate``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_filter_evaluate(self._ptr, route, ctx, out_verdict, out_reason)
        if rc < 0:
            raise LrError(last_error())
        return rc


class LdpDiscoveryConfig:
    """Low-level RAII wrapper around ``lr_ldp_discovery_config_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ldp_discovery_config_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ldp_discovery_config_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, local_lsr_id, local_label_space):
        """Construct a new ``lr_ldp_discovery_config_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ldp_discovery_config_new(local_lsr_id, local_label_space)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def set_transport_v4(self, addr):
        """Low-level wrapper for ``lr_ldp_discovery_config_set_transport_v4``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_discovery_config_set_transport_v4(self._ptr, addr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_transport_v6(self, addr):
        """Low-level wrapper for ``lr_ldp_discovery_config_set_transport_v6``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_discovery_config_set_transport_v6(self._ptr, addr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_link_hello_hold(self, hold):
        """Low-level wrapper for ``lr_ldp_discovery_config_set_link_hello_hold``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_discovery_config_set_link_hello_hold(self._ptr, hold)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_targeted_hello_hold(self, hold):
        """Low-level wrapper for ``lr_ldp_discovery_config_set_targeted_hello_hold``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_discovery_config_set_targeted_hello_hold(self._ptr, hold)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_prefer_ipv6(self, prefer_ipv6):
        """Low-level wrapper for ``lr_ldp_discovery_config_set_prefer_ipv6``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_discovery_config_set_prefer_ipv6(self._ptr, prefer_ipv6)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_accept_targeted(self, accept):
        """Low-level wrapper for ``lr_ldp_discovery_config_set_accept_targeted``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_discovery_config_set_accept_targeted(self._ptr, accept)
        if rc < 0:
            raise LrError(last_error())
        return rc


class LdpDiscovery:
    """Low-level RAII wrapper around ``lr_ldp_discovery_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ldp_discovery_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ldp_discovery_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def adjacency_count(self):
        """Low-level wrapper for ``lr_ldp_discovery_adjacency_count``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_discovery_adjacency_count(self._ptr)

    def adjacency_at(self, index, out):
        """Low-level wrapper for ``lr_ldp_discovery_adjacency_at``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_discovery_adjacency_at(self._ptr, index, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def adjacency_for_peer(self, peer_lsr_id, peer_label_space, out):
        """Low-level wrapper for ``lr_ldp_discovery_adjacency_for_peer``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_discovery_adjacency_for_peer(self._ptr, peer_lsr_id, peer_label_space, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def remove_adjacencies_for_peer(self, peer_lsr_id, peer_label_space):
        """Low-level wrapper for ``lr_ldp_discovery_remove_adjacencies_for_peer``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_discovery_remove_adjacencies_for_peer(self._ptr, peer_lsr_id, peer_label_space)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def tick(self, now_ms):
        """Low-level wrapper for ``lr_ldp_discovery_tick``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_discovery_tick(self._ptr, now_ms)

    def outgoing_count(self):
        """Low-level wrapper for ``lr_ldp_discovery_outgoing_count``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_discovery_outgoing_count(self._ptr)


class LdpEngineConfig:
    """Low-level RAII wrapper around ``lr_ldp_engine_config_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ldp_engine_config_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ldp_engine_config_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def set_transport_addr_v6(self, transport_addr_v6):
        """Low-level wrapper for ``lr_ldp_engine_config_set_transport_addr_v6``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_config_set_transport_addr_v6(self._ptr, transport_addr_v6)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_prefer_ipv6(self, prefer_ipv6):
        """Low-level wrapper for ``lr_ldp_engine_config_set_prefer_ipv6``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_config_set_prefer_ipv6(self._ptr, prefer_ipv6)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_keepalive_time(self, keepalive_time):
        """Low-level wrapper for ``lr_ldp_engine_config_set_keepalive_time``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_config_set_keepalive_time(self._ptr, keepalive_time)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_max_pdu_len(self, max_pdu_len):
        """Low-level wrapper for ``lr_ldp_engine_config_set_max_pdu_len``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_config_set_max_pdu_len(self._ptr, max_pdu_len)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_advertisement(self, advertisement):
        """Low-level wrapper for ``lr_ldp_engine_config_set_advertisement``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_config_set_advertisement(self._ptr, advertisement)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_link_hello_hold(self, hold):
        """Low-level wrapper for ``lr_ldp_engine_config_set_link_hello_hold``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_config_set_link_hello_hold(self._ptr, hold)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_targeted_hello_hold(self, hold):
        """Low-level wrapper for ``lr_ldp_engine_config_set_targeted_hello_hold``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_config_set_targeted_hello_hold(self._ptr, hold)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_accept_targeted(self, accept):
        """Low-level wrapper for ``lr_ldp_engine_config_set_accept_targeted``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_config_set_accept_targeted(self._ptr, accept)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_loop_detection(self, enabled, path_vector_limit):
        """Low-level wrapper for ``lr_ldp_engine_config_set_loop_detection``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_config_set_loop_detection(self._ptr, enabled, path_vector_limit)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_label_range(self, label_min, label_max):
        """Low-level wrapper for ``lr_ldp_engine_config_set_label_range``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_config_set_label_range(self._ptr, label_min, label_max)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def add_reserved_label(self, label):
        """Low-level wrapper for ``lr_ldp_engine_config_add_reserved_label``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_config_add_reserved_label(self._ptr, label)
        if rc < 0:
            raise LrError(last_error())
        return rc


class LdpEngine:
    """Low-level RAII wrapper around ``lr_ldp_engine_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ldp_engine_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ldp_engine_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def on_connected(self, now_ms, conn, peer_lsr, peer_label_space):
        """Low-level wrapper for ``lr_ldp_engine_on_connected``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_on_connected(self._ptr, now_ms, conn, peer_lsr, peer_label_space)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def on_connect_failed(self, peer_lsr, peer_label_space):
        """Low-level wrapper for ``lr_ldp_engine_on_connect_failed``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_on_connect_failed(self._ptr, peer_lsr, peer_label_space)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def feed_tcp(self, now_ms, conn, data, len):
        """Low-level wrapper for ``lr_ldp_engine_feed_tcp``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_feed_tcp(self._ptr, now_ms, conn, data, len)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def on_closed(self, now_ms, conn):
        """Low-level wrapper for ``lr_ldp_engine_on_closed``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_on_closed(self._ptr, now_ms, conn)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def tick(self, now_ms):
        """Low-level wrapper for ``lr_ldp_engine_tick``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_tick(self._ptr, now_ms)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def shutdown_peer(self, now_ms, peer_lsr, peer_label_space):
        """Low-level wrapper for ``lr_ldp_engine_shutdown_peer``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_shutdown_peer(self._ptr, now_ms, peer_lsr, peer_label_space)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def drain_udp(self, out):
        """Low-level wrapper for ``lr_ldp_engine_drain_udp``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_drain_udp(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def drain_tcp(self, conn, out):
        """Low-level wrapper for ``lr_ldp_engine_drain_tcp``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_drain_tcp(self._ptr, conn, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def drain_tcp_all(self, out):
        """Low-level wrapper for ``lr_ldp_engine_drain_tcp_all``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_drain_tcp_all(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def transit_label_count(self):
        """Low-level wrapper for ``lr_ldp_engine_transit_label_count``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_engine_transit_label_count(self._ptr)

    def adjacency_count(self):
        """Low-level wrapper for ``lr_ldp_engine_adjacency_count``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_engine_adjacency_count(self._ptr)

    def adjacency_at(self, index, out_peer_lsr, out_peer_label_space, out_kind, out_source_is_ipv6, source_addr, out_transport_is_ipv6, transport_addr, out_hold_time_secs, out_last_seen_ms, out_config_seq_present, out_config_seq, out_dual_stack_present, out_dual_stack_prefer_ipv6):
        """Low-level wrapper for ``lr_ldp_engine_adjacency_at``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_adjacency_at(self._ptr, index, out_peer_lsr, out_peer_label_space, out_kind, out_source_is_ipv6, source_addr, out_transport_is_ipv6, transport_addr, out_hold_time_secs, out_last_seen_ms, out_config_seq_present, out_config_seq, out_dual_stack_present, out_dual_stack_prefer_ipv6)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def session_state(self, peer_lsr, peer_label_space):
        """Low-level wrapper for ``lr_ldp_engine_session_state``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_engine_session_state(self._ptr, peer_lsr, peer_label_space)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def take_events(self, out, cap):
        """Low-level wrapper for ``lr_ldp_engine_take_events``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_engine_take_events(self._ptr, out, cap)


class LdpFec:
    """Low-level RAII wrapper around ``lr_ldp_fec_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ldp_fec_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ldp_fec_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def is_wildcard(self):
        """Low-level wrapper for ``lr_ldp_fec_is_wildcard``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_fec_is_wildcard(self._ptr)

    def single_prefix(self, octets_out, prefix_len_out, present_out):
        """Low-level wrapper for ``lr_ldp_fec_single_prefix``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_fec_single_prefix(self._ptr, octets_out, prefix_len_out, present_out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class LdpLabelStore:
    """Low-level RAII wrapper around ``lr_ldp_label_store_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ldp_label_store_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ldp_label_store_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_ldp_label_store_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ldp_label_store_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def learn(self, peer_lsr_id, peer_label_space, prefix_addr, is_ipv6, prefix_len, label):
        """Low-level wrapper for ``lr_ldp_label_store_learn``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_label_store_learn(self._ptr, peer_lsr_id, peer_label_space, prefix_addr, is_ipv6, prefix_len, label)

    def unlearn(self, peer_lsr_id, peer_label_space, prefix_addr, is_ipv6, prefix_len, out_label):
        """Low-level wrapper for ``lr_ldp_label_store_unlearn``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_label_store_unlearn(self._ptr, peer_lsr_id, peer_label_space, prefix_addr, is_ipv6, prefix_len, out_label)

    def label_from(self, peer_lsr_id, peer_label_space, prefix_addr, is_ipv6, prefix_len, out_label):
        """Low-level wrapper for ``lr_ldp_label_store_label_from``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_label_store_label_from(self._ptr, peer_lsr_id, peer_label_space, prefix_addr, is_ipv6, prefix_len, out_label)

    def unlearn_peer(self, peer_lsr_id, peer_label_space):
        """Low-level wrapper for ``lr_ldp_label_store_unlearn_peer``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_label_store_unlearn_peer(self._ptr, peer_lsr_id, peer_label_space)

    def unlearn_by_label(self, peer_lsr_id, peer_label_space, label, out_prefixes, cap):
        """Low-level wrapper for ``lr_ldp_label_store_unlearn_by_label``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_label_store_unlearn_by_label(self._ptr, peer_lsr_id, peer_label_space, label, out_prefixes, cap)

    def unlearn_all_from(self, peer_lsr_id, peer_label_space, out_prefixes, cap):
        """Low-level wrapper for ``lr_ldp_label_store_unlearn_all_from``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_label_store_unlearn_all_from(self._ptr, peer_lsr_id, peer_label_space, out_prefixes, cap)

    def advertise(self, prefix_addr, is_ipv6, prefix_len, label, out_previous):
        """Low-level wrapper for ``lr_ldp_label_store_advertise``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_label_store_advertise(self._ptr, prefix_addr, is_ipv6, prefix_len, label, out_previous)

    def withdraw_advertised(self, prefix_addr, is_ipv6, prefix_len, out_label):
        """Low-level wrapper for ``lr_ldp_label_store_withdraw_advertised``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_label_store_withdraw_advertised(self._ptr, prefix_addr, is_ipv6, prefix_len, out_label)

    def advertised_label(self, prefix_addr, is_ipv6, prefix_len, out_label):
        """Low-level wrapper for ``lr_ldp_label_store_advertised_label``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_label_store_advertised_label(self._ptr, prefix_addr, is_ipv6, prefix_len, out_label)


class LdpLabel:
    """Low-level RAII wrapper around ``lr_ldp_label_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ldp_label_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ldp_label_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, value):
        """Construct a new ``lr_ldp_label_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ldp_label_new(value)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def value(self):
        """Low-level wrapper for ``lr_ldp_label_value``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_label_value(self._ptr)

    def is_valid(self):
        """Low-level wrapper for ``lr_ldp_label_is_valid``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_label_is_valid(self._ptr)


class LdpPdu:
    """Low-level RAII wrapper around ``lr_ldp_pdu_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ldp_pdu_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ldp_pdu_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def sender(self):
        """Low-level wrapper for ``lr_ldp_pdu_sender``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_pdu_sender(self._ptr)

    def version(self):
        """Low-level wrapper for ``lr_ldp_pdu_version``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_pdu_version(self._ptr)

    def message_count(self):
        """Low-level wrapper for ``lr_ldp_pdu_message_count``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_pdu_message_count(self._ptr)

    def message_type_at(self, index):
        """Low-level wrapper for ``lr_ldp_pdu_message_type_at``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_pdu_message_type_at(self._ptr, index)

    def message_id_at(self, index):
        """Low-level wrapper for ``lr_ldp_pdu_message_id_at``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_pdu_message_id_at(self._ptr, index)

    def message_u_bit_at(self, index):
        """Low-level wrapper for ``lr_ldp_pdu_message_u_bit_at``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_pdu_message_u_bit_at(self._ptr, index)


class LdpSession:
    """Low-level RAII wrapper around ``lr_ldp_session_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ldp_session_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ldp_session_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, local_lsr_id, local_label_space, peer_lsr_id, peer_label_space, keepalive_time, max_pdu_len):
        """Construct a new ``lr_ldp_session_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ldp_session_new(local_lsr_id, local_label_space, peer_lsr_id, peer_label_space, keepalive_time, max_pdu_len)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def state(self):
        """Low-level wrapper for ``lr_ldp_session_state``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_state(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def is_operational(self):
        """Low-level wrapper for ``lr_ldp_session_is_operational``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_session_is_operational(self._ptr)

    def start(self, now_ms):
        """Low-level wrapper for ``lr_ldp_session_start``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_start(self._ptr, now_ms)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def drain_outgoing(self, out):
        """Low-level wrapper for ``lr_ldp_session_drain_outgoing``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_drain_outgoing(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def peer(self, out):
        """Low-level wrapper for ``lr_ldp_session_peer``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_peer(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def negotiated(self, out_keepalive, out_max_pdu_len):
        """Low-level wrapper for ``lr_ldp_session_negotiated``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_negotiated(self._ptr, out_keepalive, out_max_pdu_len)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def tick(self, now_ms):
        """Low-level wrapper for ``lr_ldp_session_tick``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_tick(self._ptr, now_ms)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def transport_closed(self):
        """Low-level wrapper for ``lr_ldp_session_transport_closed``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_transport_closed(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def shutdown(self, now_ms):
        """Low-level wrapper for ``lr_ldp_session_shutdown``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_shutdown(self._ptr, now_ms)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def feed_pdu(self, pdu, now_ms):
        """Low-level wrapper for ``lr_ldp_session_feed_pdu``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_feed_pdu(self._ptr, pdu, now_ms)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def send_label_mapping(self, message_id, fec, label):
        """Low-level wrapper for ``lr_ldp_session_send_label_mapping``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_send_label_mapping(self._ptr, message_id, fec, label)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def send_label_withdraw(self, message_id, fec, label):
        """Low-level wrapper for ``lr_ldp_session_send_label_withdraw``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_send_label_withdraw(self._ptr, message_id, fec, label)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def send_label_request(self, message_id, fec):
        """Low-level wrapper for ``lr_ldp_session_send_label_request``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_send_label_request(self._ptr, message_id, fec)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def send_label_release(self, message_id, fec, label, status_code):
        """Low-level wrapper for ``lr_ldp_session_send_label_release``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_send_label_release(self._ptr, message_id, fec, label, status_code)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def send_address_message(self, addrs, count, is_ipv6):
        """Low-level wrapper for ``lr_ldp_session_send_address_message``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_send_address_message(self._ptr, addrs, count, is_ipv6)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def enqueue_notification(self, status_code, msg_id, msg_type):
        """Low-level wrapper for ``lr_ldp_session_enqueue_notification``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ldp_session_enqueue_notification(self._ptr, status_code, msg_id, msg_type)
        if rc < 0:
            raise LrError(last_error())
        return rc


class LdpTransit:
    """Low-level RAII wrapper around ``lr_ldp_transit_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ldp_transit_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ldp_transit_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, label_min, label_max, reserved, reserved_count):
        """Construct a new ``lr_ldp_transit_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ldp_transit_new(label_min, label_max, reserved, reserved_count)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def label_of(self, prefix_addr, is_ipv6, prefix_len, out_label):
        """Low-level wrapper for ``lr_ldp_transit_label_of``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_transit_label_of(self._ptr, prefix_addr, is_ipv6, prefix_len, out_label)

    def is_allocated(self, prefix_addr, is_ipv6, prefix_len):
        """Low-level wrapper for ``lr_ldp_transit_is_allocated``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_transit_is_allocated(self._ptr, prefix_addr, is_ipv6, prefix_len)

    def allocated_count(self):
        """Low-level wrapper for ``lr_ldp_transit_allocated_count``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_transit_allocated_count(self._ptr)

    def allocate(self, prefix_addr, is_ipv6, prefix_len, out_label):
        """Low-level wrapper for ``lr_ldp_transit_allocate``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_transit_allocate(self._ptr, prefix_addr, is_ipv6, prefix_len, out_label)

    def release(self, prefix_addr, is_ipv6, prefix_len, out_label):
        """Low-level wrapper for ``lr_ldp_transit_release``. See ``include/lr_ffi.h``."""
        return _lib.lr_ldp_transit_release(self._ptr, prefix_addr, is_ipv6, prefix_len, out_label)


class MplsLabelStack:
    """Low-level RAII wrapper around ``lr_mpls_label_stack_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_mpls_label_stack_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_mpls_label_stack_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_mpls_label_stack_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_mpls_label_stack_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def into_vec(self, out):
        """Low-level wrapper for ``lr_mpls_label_stack_into_vec``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mpls_label_stack_into_vec(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def encode_4octet(self, out):
        """Low-level wrapper for ``lr_mpls_label_stack_encode_4octet``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mpls_label_stack_encode_4octet(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def encode_3octet(self, out):
        """Low-level wrapper for ``lr_mpls_label_stack_encode_3octet``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mpls_label_stack_encode_3octet(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def len(self):
        """Low-level wrapper for ``lr_mpls_label_stack_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_mpls_label_stack_len(self._ptr)

    def is_empty(self):
        """Low-level wrapper for ``lr_mpls_label_stack_is_empty``. See ``include/lr_ffi.h``."""
        return _lib.lr_mpls_label_stack_is_empty(self._ptr)

    def at(self, index, out_value, out_tc, out_ttl):
        """Low-level wrapper for ``lr_mpls_label_stack_at``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mpls_label_stack_at(self._ptr, index, out_value, out_tc, out_ttl)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def push(self, label):
        """Low-level wrapper for ``lr_mpls_label_stack_push``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mpls_label_stack_push(self._ptr, label)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def push_bottom(self, label):
        """Low-level wrapper for ``lr_mpls_label_stack_push_bottom``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mpls_label_stack_push_bottom(self._ptr, label)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def pop(self):
        """Low-level wrapper for ``lr_mpls_label_stack_pop``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mpls_label_stack_pop(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def all_reserved(self):
        """Low-level wrapper for ``lr_mpls_label_stack_all_reserved``. See ``include/lr_ffi.h``."""
        return _lib.lr_mpls_label_stack_all_reserved(self._ptr)

    def contains(self, label):
        """Low-level wrapper for ``lr_mpls_label_stack_contains``. See ``include/lr_ffi.h``."""
        return _lib.lr_mpls_label_stack_contains(self._ptr, label)


class MplsLabel:
    """Low-level RAII wrapper around ``lr_mpls_label_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_mpls_label_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_mpls_label_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, value):
        """Construct a new ``lr_mpls_label_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_mpls_label_try_new(value)
        if not p:
            raise LrError(last_error())
        return cls(p)

    @classmethod
    def new(cls, value):
        """Construct a new ``lr_mpls_label_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_mpls_label_new(value)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def with_tc(self, tc):
        """Low-level wrapper for ``lr_mpls_label_with_tc``. See ``include/lr_ffi.h``."""
        p = _lib.lr_mpls_label_with_tc(self._ptr, tc)
        if not p:
            raise LrError(last_error())
        return MplsLabel.__wrap__(p)

    def with_ttl(self, ttl):
        """Low-level wrapper for ``lr_mpls_label_with_ttl``. See ``include/lr_ffi.h``."""
        p = _lib.lr_mpls_label_with_ttl(self._ptr, ttl)
        if not p:
            raise LrError(last_error())
        return MplsLabel.__wrap__(p)

    def value(self):
        """Low-level wrapper for ``lr_mpls_label_value``. See ``include/lr_ffi.h``."""
        return _lib.lr_mpls_label_value(self._ptr)

    def tc(self):
        """Low-level wrapper for ``lr_mpls_label_tc``. See ``include/lr_ffi.h``."""
        return _lib.lr_mpls_label_tc(self._ptr)

    def ttl(self):
        """Low-level wrapper for ``lr_mpls_label_ttl``. See ``include/lr_ffi.h``."""
        return _lib.lr_mpls_label_ttl(self._ptr)

    def is_reserved(self):
        """Low-level wrapper for ``lr_mpls_label_is_reserved``. See ``include/lr_ffi.h``."""
        return _lib.lr_mpls_label_is_reserved(self._ptr)

    def encode_3octet(self, bottom, out):
        """Low-level wrapper for ``lr_mpls_label_encode_3octet``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mpls_label_encode_3octet(self._ptr, bottom, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def encode_4octet(self, bottom, out):
        """Low-level wrapper for ``lr_mpls_label_encode_4octet``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mpls_label_encode_4octet(self._ptr, bottom, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class MrtReader:
    """Low-level RAII wrapper around ``lr_mrt_reader_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_mrt_reader_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_mrt_reader_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_mrt_reader_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_mrt_reader_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def decode_slice(self, data, len, out):
        """Low-level wrapper for ``lr_mrt_reader_decode_slice``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mrt_reader_decode_slice(self._ptr, data, len, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def feed(self, data, len):
        """Low-level wrapper for ``lr_mrt_reader_feed``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mrt_reader_feed(self._ptr, data, len)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def next_record(self, out):
        """Low-level wrapper for ``lr_mrt_reader_next_record``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mrt_reader_next_record(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class MrtRecord:
    """Low-level RAII wrapper around ``lr_mrt_record_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_mrt_record_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_mrt_record_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def type(self):
        """Low-level wrapper for ``lr_mrt_record_type``. See ``include/lr_ffi.h``."""
        return _lib.lr_mrt_record_type(self._ptr)

    def is_rib(self):
        """Low-level wrapper for ``lr_mrt_record_is_rib``. See ``include/lr_ffi.h``."""
        return _lib.lr_mrt_record_is_rib(self._ptr)

    def unknown_subtype(self, out_msg_type, out_subtype):
        """Low-level wrapper for ``lr_mrt_record_unknown_subtype``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mrt_record_unknown_subtype(self._ptr, out_msg_type, out_subtype)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def peer_index_table_summary(self, out_collector_bgp_id, out_view_name_len, out_peer_count):
        """Low-level wrapper for ``lr_mrt_record_peer_index_table_summary``. See ``include/lr_ffi.h``."""
        return _lib.lr_mrt_record_peer_index_table_summary(self._ptr, out_collector_bgp_id, out_view_name_len, out_peer_count)

    def peer_index_table_view_name(self, out, out_len):
        """Low-level wrapper for ``lr_mrt_record_peer_index_table_view_name``. See ``include/lr_ffi.h``."""
        return _lib.lr_mrt_record_peer_index_table_view_name(self._ptr, out, out_len)

    def peer_index_table_peer_at(self, index, out):
        """Low-level wrapper for ``lr_mrt_record_peer_index_table_peer_at``. See ``include/lr_ffi.h``."""
        return _lib.lr_mrt_record_peer_index_table_peer_at(self._ptr, index, out)

    def rib_table_summary(self, out_sequence, out_prefix, out_add_path, out_entry_count):
        """Low-level wrapper for ``lr_mrt_record_rib_table_summary``. See ``include/lr_ffi.h``."""
        return _lib.lr_mrt_record_rib_table_summary(self._ptr, out_sequence, out_prefix, out_add_path, out_entry_count)

    def rib_table_entry_at(self, index, out):
        """Low-level wrapper for ``lr_mrt_record_rib_table_entry_at``. See ``include/lr_ffi.h``."""
        return _lib.lr_mrt_record_rib_table_entry_at(self._ptr, index, out)


class MrtRibDump:
    """Low-level RAII wrapper around ``lr_mrt_rib_dump_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_mrt_rib_dump_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_mrt_rib_dump_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, collector_bgp_id, view_name):
        """Construct a new ``lr_mrt_rib_dump_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_mrt_rib_dump_new(collector_bgp_id, view_name)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def add_peer(self, peer):
        """Low-level wrapper for ``lr_mrt_rib_dump_add_peer``. See ``include/lr_ffi.h``."""
        return _lib.lr_mrt_rib_dump_add_peer(self._ptr, peer)

    def add_table(self, sequence, prefix_addr, prefix_len, is_ipv6, add_path, entries, entry_count):
        """Low-level wrapper for ``lr_mrt_rib_dump_add_table``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mrt_rib_dump_add_table(self._ptr, sequence, prefix_addr, prefix_len, is_ipv6, add_path, entries, entry_count)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def encode(self, timestamp, out):
        """Low-level wrapper for ``lr_mrt_rib_dump_encode``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_mrt_rib_dump_encode(self._ptr, timestamp, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class OspfAsbrDest:
    """Low-level RAII wrapper around ``lr_ospf_asbr_dest_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_asbr_dest_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_asbr_dest_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, asbr, metric):
        """Construct a new ``lr_ospf_asbr_dest_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_asbr_dest_new(asbr, metric)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def asbr(self):
        """Low-level wrapper for ``lr_ospf_asbr_dest_asbr``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_asbr_dest_asbr(self._ptr)

    def metric(self):
        """Low-level wrapper for ``lr_ospf_asbr_dest_metric``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_asbr_dest_metric(self._ptr)


class OspfCryptoAuth:
    """Low-level RAII wrapper around ``lr_ospf_crypto_auth_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_crypto_auth_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_crypto_auth_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, key_id, key, key_len):
        """Construct a new ``lr_ospf_crypto_auth_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_crypto_auth_new(key_id, key, key_len)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def with_sha1(self):
        """Low-level wrapper for ``lr_ospf_crypto_auth_with_sha1``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_crypto_auth_with_sha1(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def key_id(self):
        """Low-level wrapper for ``lr_ospf_crypto_auth_key_id``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_crypto_auth_key_id(self._ptr)

    def algorithm(self):
        """Low-level wrapper for ``lr_ospf_crypto_auth_algorithm``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_crypto_auth_algorithm(self._ptr)

    def crypto_seq(self):
        """Low-level wrapper for ``lr_ospf_crypto_auth_crypto_seq``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_crypto_auth_crypto_seq(self._ptr)

    def advance_seq(self):
        """Low-level wrapper for ``lr_ospf_crypto_auth_advance_seq``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_crypto_auth_advance_seq(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def key(self, out, out_len):
        """Low-level wrapper for ``lr_ospf_crypto_auth_key``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_crypto_auth_key(self._ptr, out, out_len)

    def key_len(self):
        """Low-level wrapper for ``lr_ospf_crypto_auth_key_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_crypto_auth_key_len(self._ptr)


class OspfDbExchange:
    """Low-level RAII wrapper around ``lr_ospf_db_exchange_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_db_exchange_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_db_exchange_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, router_id, area_id, iface_mtu):
        """Construct a new ``lr_ospf_db_exchange_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_db_exchange_new(router_id, area_id, iface_mtu)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def with_rxmt_interval(self, ms):
        """Low-level wrapper for ``lr_ospf_db_exchange_with_rxmt_interval``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_db_exchange_with_rxmt_interval(self._ptr, ms)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def rxmt_interval_ms(self):
        """Low-level wrapper for ``lr_ospf_db_exchange_rxmt_interval_ms``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_db_exchange_rxmt_interval_ms(self._ptr)

    def phase(self):
        """Low-level wrapper for ``lr_ospf_db_exchange_phase``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_db_exchange_phase(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def is_full(self):
        """Low-level wrapper for ``lr_ospf_db_exchange_is_full``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_db_exchange_is_full(self._ptr)

    def started(self):
        """Low-level wrapper for ``lr_ospf_db_exchange_started``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_db_exchange_started(self._ptr)

    def restart(self, seq):
        """Low-level wrapper for ``lr_ospf_db_exchange_restart``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_db_exchange_restart(self._ptr, seq)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def initial_db_desc(self, seq, now_ms):
        """Low-level wrapper for ``lr_ospf_db_exchange_initial_db_desc``. See ``include/lr_ffi.h``."""
        p = _lib.lr_ospf_db_exchange_initial_db_desc(self._ptr, seq, now_ms)
        if not p:
            raise LrError(last_error())
        return OspfPacket.__wrap__(p)

    def poll(self, now_ms, out_packets, out_count):
        """Low-level wrapper for ``lr_ospf_db_exchange_poll``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_db_exchange_poll(self._ptr, now_ms, out_packets, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def take_ls_request(self, now_ms):
        """Low-level wrapper for ``lr_ospf_db_exchange_take_ls_request``. See ``include/lr_ffi.h``."""
        p = _lib.lr_ospf_db_exchange_take_ls_request(self._ptr, now_ms)
        if not p:
            raise LrError(last_error())
        return OspfPacket.__wrap__(p)

    def pending_requests(self):
        """Low-level wrapper for ``lr_ospf_db_exchange_pending_requests``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_db_exchange_pending_requests(self._ptr)

    def on_db_desc_packet(self, neighbor, lsdb, data, len, now_ms, out):
        """Low-level wrapper for ``lr_ospf_db_exchange_on_db_desc_packet``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_db_exchange_on_db_desc_packet(self._ptr, neighbor, lsdb, data, len, now_ms, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def on_ls_request_packet(self, neighbor, lsdb, data, len, now_ms, out):
        """Low-level wrapper for ``lr_ospf_db_exchange_on_ls_request_packet``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_db_exchange_on_ls_request_packet(self._ptr, neighbor, lsdb, data, len, now_ms, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def on_ls_update_packet(self, neighbor, data, len, out):
        """Low-level wrapper for ``lr_ospf_db_exchange_on_ls_update_packet``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_db_exchange_on_ls_update_packet(self._ptr, neighbor, data, len, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class OspfExternalRoute:
    """Low-level RAII wrapper around ``lr_ospf_external_route_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def __del__(self):
        pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def prefix(self, octets_out, prefix_len_out):
        """Low-level wrapper for ``lr_ospf_external_route_prefix``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_external_route_prefix(self._ptr, octets_out, prefix_len_out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def metric(self):
        """Low-level wrapper for ``lr_ospf_external_route_metric``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_external_route_metric(self._ptr)

    def metric_type(self):
        """Low-level wrapper for ``lr_ospf_external_route_metric_type``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_external_route_metric_type(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def internal_cost(self):
        """Low-level wrapper for ``lr_ospf_external_route_internal_cost``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_external_route_internal_cost(self._ptr)

    def asbr(self):
        """Low-level wrapper for ``lr_ospf_external_route_asbr``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_external_route_asbr(self._ptr)

    def border_router(self, present, border_router):
        """Low-level wrapper for ``lr_ospf_external_route_border_router``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_external_route_border_router(self._ptr, present, border_router)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def forwarding_addr(self):
        """Low-level wrapper for ``lr_ospf_external_route_forwarding_addr``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_external_route_forwarding_addr(self._ptr)

    def tag(self):
        """Low-level wrapper for ``lr_ospf_external_route_tag``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_external_route_tag(self._ptr)


class OspfExternalRouteV3:
    """Low-level RAII wrapper around ``lr_ospf_external_route_v3_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def __del__(self):
        pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def prefix(self, octets_out, prefix_len_out):
        """Low-level wrapper for ``lr_ospf_external_route_v3_prefix``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_external_route_v3_prefix(self._ptr, octets_out, prefix_len_out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def metric(self):
        """Low-level wrapper for ``lr_ospf_external_route_v3_metric``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_external_route_v3_metric(self._ptr)

    def metric_type(self):
        """Low-level wrapper for ``lr_ospf_external_route_v3_metric_type``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_external_route_v3_metric_type(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def internal_cost(self):
        """Low-level wrapper for ``lr_ospf_external_route_v3_internal_cost``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_external_route_v3_internal_cost(self._ptr)

    def asbr(self):
        """Low-level wrapper for ``lr_ospf_external_route_v3_asbr``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_external_route_v3_asbr(self._ptr)

    def border_router(self, present, border_router):
        """Low-level wrapper for ``lr_ospf_external_route_v3_border_router``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_external_route_v3_border_router(self._ptr, present, border_router)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def next_hop(self, octets_out, present_out):
        """Low-level wrapper for ``lr_ospf_external_route_v3_next_hop``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_external_route_v3_next_hop(self._ptr, octets_out, present_out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def route_tag(self, present, tag):
        """Low-level wrapper for ``lr_ospf_external_route_v3_route_tag``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_external_route_v3_route_tag(self._ptr, present, tag)
        if rc < 0:
            raise LrError(last_error())
        return rc


class OspfExternalRouteV3Vec:
    """Low-level RAII wrapper around ``lr_ospf_external_route_v3_vec_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_external_route_v3_vec_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_external_route_v3_vec_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def len(self):
        """Low-level wrapper for ``lr_ospf_external_route_v3_vec_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_external_route_v3_vec_len(self._ptr)

    def at(self, index):
        """Low-level wrapper for ``lr_ospf_external_route_v3_vec_at``. See ``include/lr_ffi.h``."""
        p = _lib.lr_ospf_external_route_v3_vec_at(self._ptr, index)
        if not p:
            raise LrError(last_error())
        return OspfExternalRouteV3.__wrap__(p)


class OspfExternalRouteVec:
    """Low-level RAII wrapper around ``lr_ospf_external_route_vec_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_external_route_vec_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_external_route_vec_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def len(self):
        """Low-level wrapper for ``lr_ospf_external_route_vec_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_external_route_vec_len(self._ptr)

    def at(self, index):
        """Low-level wrapper for ``lr_ospf_external_route_vec_at``. See ``include/lr_ffi.h``."""
        p = _lib.lr_ospf_external_route_vec_at(self._ptr, index)
        if not p:
            raise LrError(last_error())
        return OspfExternalRoute.__wrap__(p)


class OspfHelperEntry:
    """Low-level RAII wrapper around ``lr_ospf_helper_entry_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_helper_entry_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_helper_entry_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_ospf_helper_entry_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_helper_entry_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def is_active(self):
        """Low-level wrapper for ``lr_ospf_helper_entry_is_active``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_helper_entry_is_active(self._ptr)

    def grace_deadline_ms(self):
        """Low-level wrapper for ``lr_ospf_helper_entry_grace_deadline_ms``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_helper_entry_grace_deadline_ms(self._ptr)

    def last_period_secs(self):
        """Low-level wrapper for ``lr_ospf_helper_entry_last_period_secs``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_helper_entry_last_period_secs(self._ptr)


class OspfIfAction:
    """Low-level RAII wrapper around ``lr_ospf_if_action_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_if_action_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_interface_action_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class OspfInterface:
    """Low-level RAII wrapper around ``lr_ospf_interface_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_interface_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_interface_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, area_id):
        """Construct a new ``lr_ospf_interface_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_interface_new(area_id)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def state(self):
        """Low-level wrapper for ``lr_ospf_interface_state``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_interface_state(self._ptr)

    def priority(self):
        """Low-level wrapper for ``lr_ospf_interface_priority``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_interface_priority(self._ptr)

    def hello_interval(self):
        """Low-level wrapper for ``lr_ospf_interface_hello_interval``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_interface_hello_interval(self._ptr)

    def dead_interval(self):
        """Low-level wrapper for ``lr_ospf_interface_dead_interval``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_interface_dead_interval(self._ptr)

    def dr(self):
        """Low-level wrapper for ``lr_ospf_interface_dr``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_interface_dr(self._ptr)

    def bdr(self):
        """Low-level wrapper for ``lr_ospf_interface_bdr``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_interface_bdr(self._ptr)

    def area_id(self):
        """Low-level wrapper for ``lr_ospf_interface_area_id``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_interface_area_id(self._ptr)

    def router_id(self):
        """Low-level wrapper for ``lr_ospf_interface_router_id``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_interface_router_id(self._ptr)

    def ip(self):
        """Low-level wrapper for ``lr_ospf_interface_ip``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_interface_ip(self._ptr)

    def set_priority(self, priority):
        """Low-level wrapper for ``lr_ospf_interface_set_priority``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_interface_set_priority(self._ptr, priority)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_hello_interval(self, hello_interval):
        """Low-level wrapper for ``lr_ospf_interface_set_hello_interval``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_interface_set_hello_interval(self._ptr, hello_interval)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_dead_interval(self, dead_interval):
        """Low-level wrapper for ``lr_ospf_interface_set_dead_interval``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_interface_set_dead_interval(self._ptr, dead_interval)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_router_id(self, router_id):
        """Low-level wrapper for ``lr_ospf_interface_set_router_id``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_interface_set_router_id(self._ptr, router_id)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_ip(self, ip):
        """Low-level wrapper for ``lr_ospf_interface_set_ip``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_interface_set_ip(self._ptr, ip)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_interface_up(self, out_array, out_count):
        """Low-level wrapper for ``lr_ospf_interface_step_interface_up``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_interface_step_interface_up(self._ptr, out_array, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_interface_down(self, out_array, out_count):
        """Low-level wrapper for ``lr_ospf_interface_step_interface_down``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_interface_step_interface_down(self._ptr, out_array, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_wait_timer(self, out_array, out_count):
        """Low-level wrapper for ``lr_ospf_interface_step_wait_timer``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_interface_step_wait_timer(self._ptr, out_array, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_backup_seen(self, out_array, out_count):
        """Low-level wrapper for ``lr_ospf_interface_step_backup_seen``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_interface_step_backup_seen(self._ptr, out_array, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_neighbor_change(self, electors, count, out_array, out_count):
        """Low-level wrapper for ``lr_ospf_interface_step_neighbor_change``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_interface_step_neighbor_change(self._ptr, electors, count, out_array, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc


class OspfLsaBox:
    """Low-level RAII wrapper around ``lr_ospf_lsa_box_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_lsa_box_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_lsa_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class OspfLsaHdrBox:
    """Low-level RAII wrapper around ``lr_ospf_lsa_hdr_box_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_lsa_hdr_box_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_lsa_header_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class OspfNeighbor:
    """Low-level RAII wrapper around ``lr_ospf_neighbor_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_neighbor_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_neighbor_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, router_id):
        """Construct a new ``lr_ospf_neighbor_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_neighbor_new(router_id)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def state(self):
        """Low-level wrapper for ``lr_ospf_neighbor_state``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_neighbor_state(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_hello_seen(self, dr, bdr, priority):
        """Low-level wrapper for ``lr_ospf_neighbor_step_hello_seen``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_neighbor_step_hello_seen(self._ptr, dr, bdr, priority)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_adj_ok(self, proceed):
        """Low-level wrapper for ``lr_ospf_neighbor_step_adj_ok``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_neighbor_step_adj_ok(self._ptr, proceed)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def step_kill(self):
        """Low-level wrapper for ``lr_ospf_neighbor_step_kill``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_neighbor_step_kill(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc


class OspfNssaDefault:
    """Low-level RAII wrapper around ``lr_ospf_nssa_default_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_nssa_default_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_nssa_default_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, metric):
        """Construct a new ``lr_ospf_nssa_default_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_nssa_default_new(metric)
        if not p:
            raise LrError(last_error())
        return cls(p)


class OspfNssaRouteVec:
    """Low-level RAII wrapper around ``lr_ospf_nssa_route_vec_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def __del__(self):
        pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class OspfPacket:
    """Low-level RAII wrapper around ``lr_ospf_packet_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_packet_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_packet_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def version(self):
        """Low-level wrapper for ``lr_ospf_packet_version``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_packet_version(self._ptr)

    def type(self):
        """Low-level wrapper for ``lr_ospf_packet_type``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_packet_type(self._ptr)

    def router_id(self):
        """Low-level wrapper for ``lr_ospf_packet_router_id``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_packet_router_id(self._ptr)

    def area_id(self):
        """Low-level wrapper for ``lr_ospf_packet_area_id``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_packet_area_id(self._ptr)

    def body_kind(self):
        """Low-level wrapper for ``lr_ospf_packet_body_kind``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_packet_body_kind(self._ptr)


class OspfRestartTracker:
    """Low-level RAII wrapper around ``lr_ospf_restart_tracker_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def __del__(self):
        pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def recovering(self):
        """Low-level wrapper for ``lr_ospf_restart_tracker_recovering``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_restart_tracker_recovering(self._ptr)

    def grace_deadline_ms(self):
        """Low-level wrapper for ``lr_ospf_restart_tracker_grace_deadline_ms``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_restart_tracker_grace_deadline_ms(self._ptr)


class OspfRetransmit:
    """Low-level RAII wrapper around ``lr_ospf_retransmit_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_retransmit_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_retransmit_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_ospf_retransmit_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_retransmit_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def len(self):
        """Low-level wrapper for ``lr_ospf_retransmit_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_retransmit_len(self._ptr)

    def is_empty(self):
        """Low-level wrapper for ``lr_ospf_retransmit_is_empty``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_retransmit_is_empty(self._ptr)

    def contains(self, ls_type, ls_id, adv_router):
        """Low-level wrapper for ``lr_ospf_retransmit_contains``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_retransmit_contains(self._ptr, ls_type, ls_id, adv_router)

    def record_flood(self, lsa, now_ms):
        """Low-level wrapper for ``lr_ospf_retransmit_record_flood``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_retransmit_record_flood(self._ptr, lsa, now_ms)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def remove(self, ls_type, ls_id, adv_router):
        """Low-level wrapper for ``lr_ospf_retransmit_remove``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_retransmit_remove(self._ptr, ls_type, ls_id, adv_router)

    def clear(self):
        """Low-level wrapper for ``lr_ospf_retransmit_clear``. See ``include/lr_ffi.h``."""
        _lib.lr_ospf_retransmit_clear(self._ptr)

    def apply_acks(self, acks, count):
        """Low-level wrapper for ``lr_ospf_retransmit_apply_acks``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_retransmit_apply_acks(self._ptr, acks, count)

    def poll(self, now_ms, rxmt_interval_ms, out, out_count):
        """Low-level wrapper for ``lr_ospf_retransmit_poll``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_retransmit_poll(self._ptr, now_ms, rxmt_interval_ms, out, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc


class OspfRouterLsaLink:
    """Low-level RAII wrapper around ``lr_ospf_router_lsa_link_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_router_lsa_link_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_router_lsa_link_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, link_kind, field1, field2, field3, metric):
        """Construct a new ``lr_ospf_router_lsa_link_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_router_lsa_link_new(link_kind, field1, field2, field3, metric)
        if not p:
            raise LrError(last_error())
        return cls(p)


class OspfSimplePassword:
    """Low-level RAII wrapper around ``lr_ospf_simple_password_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_simple_password_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_simple_password_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, password, password_len):
        """Construct a new ``lr_ospf_simple_password_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_simple_password_new(password, password_len)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def password(self, out):
        """Low-level wrapper for ``lr_ospf_simple_password_password``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_simple_password_password(self._ptr, out)


class OspfSpfResult:
    """Low-level RAII wrapper around ``lr_ospf_spf_result_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_spf_result_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_spf_result_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class OspfSpfV3Result:
    """Low-level RAII wrapper around ``lr_ospf_spf_v3_result_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_spf_v3_result_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_spf_v3_result_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class OspfSrDb:
    """Low-level RAII wrapper around ``lr_ospf_sr_db_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_sr_db_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_sr_db_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class OspfSrv6Db:
    """Low-level RAII wrapper around ``lr_ospf_srv6_db_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_srv6_db_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_srv6_db_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr


class OspfSummaryDest:
    """Low-level RAII wrapper around ``lr_ospf_summary_dest_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_summary_dest_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_summary_dest_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, prefix_v4, prefix_v6, prefix_len, metric):
        """Construct a new ``lr_ospf_summary_dest_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_summary_dest_new(prefix_v4, prefix_v6, prefix_len, metric)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def metric(self):
        """Low-level wrapper for ``lr_ospf_summary_dest_metric``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_summary_dest_metric(self._ptr)

    def prefix(self, octets_out, prefix_len_out):
        """Low-level wrapper for ``lr_ospf_summary_dest_prefix``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_summary_dest_prefix(self._ptr, octets_out, prefix_len_out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class OspfV3Auth:
    """Low-level RAII wrapper around ``lr_ospf_v3_auth_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_ospf_v3_auth_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_ospf_v3_auth_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, sa_id, key, key_len):
        """Construct a new ``lr_ospf_v3_auth_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_ospf_v3_auth_new(sa_id, key, key_len)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def with_sha1(self):
        """Low-level wrapper for ``lr_ospf_v3_auth_with_sha1``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_v3_auth_with_sha1(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def with_source(self, source):
        """Low-level wrapper for ``lr_ospf_v3_auth_with_source``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_ospf_v3_auth_with_source(self._ptr, source)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def sa_id(self):
        """Low-level wrapper for ``lr_ospf_v3_auth_sa_id``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_v3_auth_sa_id(self._ptr)

    def algorithm(self):
        """Low-level wrapper for ``lr_ospf_v3_auth_algorithm``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_v3_auth_algorithm(self._ptr)

    def trailer_len(self):
        """Low-level wrapper for ``lr_ospf_v3_auth_trailer_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_v3_auth_trailer_len(self._ptr)

    def key(self, out, out_len):
        """Low-level wrapper for ``lr_ospf_v3_auth_key``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_v3_auth_key(self._ptr, out, out_len)

    def key_len(self):
        """Low-level wrapper for ``lr_ospf_v3_auth_key_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_ospf_v3_auth_key_len(self._ptr)


class Osroute:
    """Low-level RAII wrapper around ``lr_osroute_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def __del__(self):
        pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def add_route(self, prefix, next_hop, next_hop_len, if_index):
        """Low-level wrapper for ``lr_osroute_add_route``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_osroute_add_route(self._ptr, prefix, next_hop, next_hop_len, if_index)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def add_route_tagged(self, prefix, next_hop, next_hop_len, if_index, protocol):
        """Low-level wrapper for ``lr_osroute_add_route_tagged``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_osroute_add_route_tagged(self._ptr, prefix, next_hop, next_hop_len, if_index, protocol)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def add_blackhole_route(self, prefix):
        """Low-level wrapper for ``lr_osroute_add_blackhole_route``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_osroute_add_blackhole_route(self._ptr, prefix)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def delete_route(self, prefix):
        """Low-level wrapper for ``lr_osroute_delete_route``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_osroute_delete_route(self._ptr, prefix)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def list_routes_count(self):
        """Low-level wrapper for ``lr_osroute_list_routes_count``. See ``include/lr_ffi.h``."""
        return _lib.lr_osroute_list_routes_count(self._ptr)

    def list_routes(self, out, cap):
        """Low-level wrapper for ``lr_osroute_list_routes``. See ``include/lr_ffi.h``."""
        return _lib.lr_osroute_list_routes(self._ptr, out, cap)

    def has_route(self, prefix):
        """Low-level wrapper for ``lr_osroute_has_route``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_osroute_has_route(self._ptr, prefix)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def destroy(self):
        """Low-level wrapper for ``lr_osroute_destroy``. See ``include/lr_ffi.h``."""
        _lib.lr_osroute_destroy(self._ptr)


class PolicyChain:
    """Low-level RAII wrapper around ``lr_policy_chain_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_policy_chain_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_policy_chain_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_policy_chain_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_policy_chain_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def push(self, map):
        """Low-level wrapper for ``lr_policy_chain_push``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_policy_chain_push(self._ptr, map)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def evaluate(self, route, resolver):
        """Low-level wrapper for ``lr_policy_chain_evaluate``. See ``include/lr_ffi.h``."""
        return _lib.lr_policy_chain_evaluate(self._ptr, route, resolver)

    def len(self):
        """Low-level wrapper for ``lr_policy_chain_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_policy_chain_len(self._ptr)


class Policy:
    """Low-level RAII wrapper around ``lr_policy_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_policy_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_policy_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, name):
        """Construct a new ``lr_policy_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_policy_new(name)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def name(self):
        """Low-level wrapper for ``lr_policy_name``. See ``include/lr_ffi.h``."""
        return _lib.lr_policy_name(self._ptr)

    def chain(self):
        """Low-level wrapper for ``lr_policy_chain``. See ``include/lr_ffi.h``."""
        p = _lib.lr_policy_chain(self._ptr)
        if not p:
            raise LrError(last_error())
        return PolicyChain.__wrap__(p)


class RoaTableBuilder:
    """Low-level RAII wrapper around ``lr_roa_table_builder_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_roa_table_builder_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_roa_table_builder_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_roa_table_builder_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_roa_table_builder_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def add(self, prefix, max_length, asn):
        """Low-level wrapper for ``lr_roa_table_builder_add``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_roa_table_builder_add(self._ptr, prefix, max_length, asn)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def add_entry(self, entry):
        """Low-level wrapper for ``lr_roa_table_builder_add_entry``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_roa_table_builder_add_entry(self._ptr, entry)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def build(self):
        """Low-level wrapper for ``lr_roa_table_builder_build``. See ``include/lr_ffi.h``."""
        p = _lib.lr_roa_table_builder_build(self._ptr)
        if not p:
            raise LrError(last_error())
        return RoaTable.__wrap__(p)


class RoaTable:
    """Low-level RAII wrapper around ``lr_roa_table_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_roa_table_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_roa_table_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls):
        """Construct a new ``lr_roa_table_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_roa_table_new()
        if not p:
            raise LrError(last_error())
        return cls(p)

    def len(self):
        """Low-level wrapper for ``lr_roa_table_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_roa_table_len(self._ptr)

    def is_empty(self):
        """Low-level wrapper for ``lr_roa_table_is_empty``. See ``include/lr_ffi.h``."""
        return _lib.lr_roa_table_is_empty(self._ptr)

    def validate(self, addr, is_ipv6, prefix_len, origin_as, has_origin):
        """Low-level wrapper for ``lr_roa_table_validate``. See ``include/lr_ffi.h``."""
        return _lib.lr_roa_table_validate(self._ptr, addr, is_ipv6, prefix_len, origin_as, has_origin)

    def entry_at(self, index, out_addr, out_is_ipv6, out_prefix_len, out_max_length, out_asn):
        """Low-level wrapper for ``lr_roa_table_entry_at``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_roa_table_entry_at(self._ptr, index, out_addr, out_is_ipv6, out_prefix_len, out_max_length, out_asn)
        if rc < 0:
            raise LrError(last_error())
        return rc


class RtrPdu:
    """Low-level RAII wrapper around ``lr_rtr_pdu_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_rtr_pdu_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_rtr_pdu_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def encode(self, version, out):
        """Low-level wrapper for ``lr_rtr_pdu_encode``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_encode(self._ptr, version, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def encode_vec(self, version, out):
        """Low-level wrapper for ``lr_rtr_pdu_encode_vec``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_encode_vec(self._ptr, version, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def type(self, out):
        """Low-level wrapper for ``lr_rtr_pdu_type``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_type(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def min_version(self, out):
        """Low-level wrapper for ``lr_rtr_pdu_min_version``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_min_version(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def session_id(self, out):
        """Low-level wrapper for ``lr_rtr_pdu_session_id``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_session_id(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def serial(self, out):
        """Low-level wrapper for ``lr_rtr_pdu_serial``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_serial(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def announce(self, out):
        """Low-level wrapper for ``lr_rtr_pdu_announce``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_announce(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def ipv4_prefix_fields(self, out_prefix_v4, out_prefix_len, out_max_length, out_asn):
        """Low-level wrapper for ``lr_rtr_pdu_ipv4_prefix_fields``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_ipv4_prefix_fields(self._ptr, out_prefix_v4, out_prefix_len, out_max_length, out_asn)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def ipv6_prefix_fields(self, out_prefix_v6, out_prefix_len, out_max_length, out_asn):
        """Low-level wrapper for ``lr_rtr_pdu_ipv6_prefix_fields``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_ipv6_prefix_fields(self._ptr, out_prefix_v6, out_prefix_len, out_max_length, out_asn)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def end_of_data_intervals(self, out_present, out_refresh, out_retry, out_expire):
        """Low-level wrapper for ``lr_rtr_pdu_end_of_data_intervals``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_end_of_data_intervals(self._ptr, out_present, out_refresh, out_retry, out_expire)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def router_key_fields(self, out_ski, out_asn, out_spki):
        """Low-level wrapper for ``lr_rtr_pdu_router_key_fields``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_router_key_fields(self._ptr, out_ski, out_asn, out_spki)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def error_code(self, out):
        """Low-level wrapper for ``lr_rtr_pdu_error_code``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_error_code(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def erroneous_pdu(self, out):
        """Low-level wrapper for ``lr_rtr_pdu_erroneous_pdu``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_erroneous_pdu(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def error_text(self, out):
        """Low-level wrapper for ``lr_rtr_pdu_error_text``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_error_text(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def customer_asn(self, out):
        """Low-level wrapper for ``lr_rtr_pdu_customer_asn``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_customer_asn(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def providers(self, out_providers, cap, out_count):
        """Low-level wrapper for ``lr_rtr_pdu_providers``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_rtr_pdu_providers(self._ptr, out_providers, cap, out_count)
        if rc < 0:
            raise LrError(last_error())
        return rc


class SafetyNet:
    """Low-level RAII wrapper around ``lr_safety_net_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_safety_net_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_safety_net_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, local_as):
        """Construct a new ``lr_safety_net_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_safety_net_new(local_as)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def with_local_addr(self, addr_v4, addr_v6):
        """Low-level wrapper for ``lr_safety_net_with_local_addr``. See ``include/lr_ffi.h``."""
        p = _lib.lr_safety_net_with_local_addr(self._ptr, addr_v4, addr_v6)
        if not p:
            raise LrError(last_error())
        return SafetyNet.__wrap__(p)

    def check(self, route, is_ebgp):
        """Low-level wrapper for ``lr_safety_net_check``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_safety_net_check(self._ptr, route, is_ebgp)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def config_enabled(self):
        """Low-level wrapper for ``lr_safety_net_config_enabled``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_safety_net_config_enabled(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def config_set_enabled(self, enabled):
        """Low-level wrapper for ``lr_safety_net_config_set_enabled``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_safety_net_config_set_enabled(self._ptr, enabled)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def config_get_bool(self, field):
        """Low-level wrapper for ``lr_safety_net_config_get_bool``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_safety_net_config_get_bool(self._ptr, field)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def config_set_bool(self, field, value):
        """Low-level wrapper for ``lr_safety_net_config_set_bool``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_safety_net_config_set_bool(self._ptr, field, value)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def config_get_u64(self, field):
        """Low-level wrapper for ``lr_safety_net_config_get_u64``. See ``include/lr_ffi.h``."""
        return _lib.lr_safety_net_config_get_u64(self._ptr, field)

    def config_set_u64(self, field, value):
        """Low-level wrapper for ``lr_safety_net_config_set_u64``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_safety_net_config_set_u64(self._ptr, field, value)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def check_violation(self, route, is_ebgp):
        """Low-level wrapper for ``lr_safety_net_check_violation``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_safety_net_check_violation(self._ptr, route, is_ebgp)
        if rc < 0:
            raise LrError(last_error())
        return rc


class SessionConfig:
    """Low-level RAII wrapper around ``lr_session_config_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_session_config_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_session_config_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def with_mp_families(self, families, count):
        """Low-level wrapper for ``lr_session_config_with_mp_families``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_mp_families(self._ptr, families, count)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)

    def with_add_path(self):
        """Low-level wrapper for ``lr_session_config_with_add_path``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_add_path(self._ptr)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)

    def with_extended_next_hop(self):
        """Low-level wrapper for ``lr_session_config_with_extended_next_hop``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_extended_next_hop(self._ptr)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)

    def with_extended_next_hop_tuple(self, nlri_afi, nlri_safi, nexthop_afi):
        """Low-level wrapper for ``lr_session_config_with_extended_next_hop_tuple``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_extended_next_hop_tuple(self._ptr, nlri_afi, nlri_safi, nexthop_afi)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)

    def with_graceful_restart(self, restart_time_secs):
        """Low-level wrapper for ``lr_session_config_with_graceful_restart``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_graceful_restart(self._ptr, restart_time_secs)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)

    def with_long_lived_gr(self, stale_time_secs):
        """Low-level wrapper for ``lr_session_config_with_long_lived_gr``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_long_lived_gr(self._ptr, stale_time_secs)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)

    def with_llgr_max_stale_time(self, cap_secs):
        """Low-level wrapper for ``lr_session_config_with_llgr_max_stale_time``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_llgr_max_stale_time(self._ptr, cap_secs)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)

    def with_mrai_ms(self, mrai_ms):
        """Low-level wrapper for ``lr_session_config_with_mrai_ms``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_mrai_ms(self._ptr, mrai_ms)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)

    def with_route_reflector_client(self):
        """Low-level wrapper for ``lr_session_config_with_route_reflector_client``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_route_reflector_client(self._ptr)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)

    def with_maximum_prefix(self, limit, action):
        """Low-level wrapper for ``lr_session_config_with_maximum_prefix``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_maximum_prefix(self._ptr, limit, action)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)

    def with_maximum_prefix_threshold(self, pct):
        """Low-level wrapper for ``lr_session_config_with_maximum_prefix_threshold``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_maximum_prefix_threshold(self._ptr, pct)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)

    def with_maximum_prefix_restart_time(self, secs):
        """Low-level wrapper for ``lr_session_config_with_maximum_prefix_restart_time``. See ``include/lr_ffi.h``."""
        p = _lib.lr_session_config_with_maximum_prefix_restart_time(self._ptr, secs)
        if not p:
            raise LrError(last_error())
        return SessionConfig.__wrap__(p)


class Srv6Locator:
    """Low-level RAII wrapper around ``lr_srv6_locator_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_srv6_locator_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_srv6_locator_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, addr, block_bits):
        """Construct a new ``lr_srv6_locator_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_srv6_locator_new(addr, block_bits)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def addr(self, out_addr):
        """Low-level wrapper for ``lr_srv6_locator_addr``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_srv6_locator_addr(self._ptr, out_addr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def block_bits(self):
        """Low-level wrapper for ``lr_srv6_locator_block_bits``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_locator_block_bits(self._ptr)

    def contains_sid(self, sid):
        """Low-level wrapper for ``lr_srv6_locator_contains_sid``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_locator_contains_sid(self._ptr, sid)

    def sid_with_tail(self, tail):
        """Low-level wrapper for ``lr_srv6_locator_sid_with_tail``. See ``include/lr_ffi.h``."""
        p = _lib.lr_srv6_locator_sid_with_tail(self._ptr, tail)
        if not p:
            raise LrError(last_error())
        return Srv6Sid.__wrap__(p)

    def block_bytes(self):
        """Low-level wrapper for ``lr_srv6_locator_block_bytes``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_locator_block_bytes(self._ptr)

    def sid_with_index(self, function_index):
        """Low-level wrapper for ``lr_srv6_locator_sid_with_index``. See ``include/lr_ffi.h``."""
        p = _lib.lr_srv6_locator_sid_with_index(self._ptr, function_index)
        if not p:
            raise LrError(last_error())
        return Srv6Sid.__wrap__(p)


class Srv6Sid:
    """Low-level RAII wrapper around ``lr_srv6_sid_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_srv6_sid_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_srv6_sid_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, octets):
        """Construct a new ``lr_srv6_sid_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_srv6_sid_new(octets)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def octets(self, out_octets):
        """Low-level wrapper for ``lr_srv6_sid_octets``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_srv6_sid_octets(self._ptr, out_octets)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def is_unspecified(self):
        """Low-level wrapper for ``lr_srv6_sid_is_unspecified``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_sid_is_unspecified(self._ptr)

    def locator_slice(self, locator_block_bits, out_offset, out_len):
        """Low-level wrapper for ``lr_srv6_sid_locator_slice``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_sid_locator_slice(self._ptr, locator_block_bits, out_offset, out_len)

    def is_inside_locator(self, locator, locator_len, locator_block_bits):
        """Low-level wrapper for ``lr_srv6_sid_is_inside_locator``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_sid_is_inside_locator(self._ptr, locator, locator_len, locator_block_bits)

    def as_ptr(self):
        """Low-level wrapper for ``lr_srv6_sid_as_ptr``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_sid_as_ptr(self._ptr)


class Srv6Srh:
    """Low-level RAII wrapper around ``lr_srv6_srh_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_srv6_srh_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_srv6_srh_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    @classmethod
    def new(cls, data, count):
        """Construct a new ``lr_srv6_srh_t``. Throws ``LrError`` on failure."""
        p = _lib.lr_srv6_srh_new(data, count)
        if not p:
            raise LrError(last_error())
        return cls(p)

    def current_destination(self, out):
        """Low-level wrapper for ``lr_srv6_srh_current_destination``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_srv6_srh_current_destination(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def len(self):
        """Low-level wrapper for ``lr_srv6_srh_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_srh_len(self._ptr)

    def is_empty(self):
        """Low-level wrapper for ``lr_srv6_srh_is_empty``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_srh_is_empty(self._ptr)

    def hdr_ext_len(self):
        """Low-level wrapper for ``lr_srv6_srh_hdr_ext_len``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_srh_hdr_ext_len(self._ptr)

    def set_next_header(self, next_header):
        """Low-level wrapper for ``lr_srv6_srh_set_next_header``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_srv6_srh_set_next_header(self._ptr, next_header)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_flags(self, flags):
        """Low-level wrapper for ``lr_srv6_srh_set_flags``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_srv6_srh_set_flags(self._ptr, flags)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_tag(self, tag):
        """Low-level wrapper for ``lr_srv6_srh_set_tag``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_srv6_srh_set_tag(self._ptr, tag)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def set_tlvs(self, tlvs, tlvs_len):
        """Low-level wrapper for ``lr_srv6_srh_set_tlvs``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_srv6_srh_set_tlvs(self._ptr, tlvs, tlvs_len)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def next_header(self):
        """Low-level wrapper for ``lr_srv6_srh_next_header``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_srh_next_header(self._ptr)

    def segments_left(self):
        """Low-level wrapper for ``lr_srv6_srh_segments_left``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_srh_segments_left(self._ptr)

    def last_entry(self):
        """Low-level wrapper for ``lr_srv6_srh_last_entry``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_srh_last_entry(self._ptr)

    def flags(self):
        """Low-level wrapper for ``lr_srv6_srh_flags``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_srh_flags(self._ptr)

    def tag(self):
        """Low-level wrapper for ``lr_srv6_srh_tag``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_srh_tag(self._ptr)

    def segment_count(self):
        """Low-level wrapper for ``lr_srv6_srh_segment_count``. See ``include/lr_ffi.h``."""
        return _lib.lr_srv6_srh_segment_count(self._ptr)

    def segment_at(self, index, out):
        """Low-level wrapper for ``lr_srv6_srh_segment_at``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_srv6_srh_segment_at(self._ptr, index, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def tlvs(self, out):
        """Low-level wrapper for ``lr_srv6_srh_tlvs``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_srv6_srh_tlvs(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def first_segment(self, out):
        """Low-level wrapper for ``lr_srv6_srh_first_segment``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_srv6_srh_first_segment(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def encode(self, out):
        """Low-level wrapper for ``lr_srv6_srh_encode``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_srv6_srh_encode(self._ptr, out)
        if rc < 0:
            raise LrError(last_error())
        return rc


class TcpAuth:
    """Low-level RAII wrapper around ``lr_tcp_auth_t``.

    Generated; prefer the hand-written wrappers in the other modules when they exist.
    """

    __slots__ = ("_ptr",)

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def __wrap__(cls, ptr):
        """Wrap an existing C handle without taking ownership of construction.
        The handle is still freed by ``__del__``."""
        return cls(ptr)

    def free(self) -> None:
        """Release the underlying ``lr_tcp_auth_t`` handle."""
        if getattr(self, "_ptr", None) is not None and self._ptr != ffi.NULL:
            _lib.lr_tcp_auth_free(self._ptr)
            self._ptr = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @property
    def ptr(self):
        """Return the raw CFFI pointer for direct C ABI access."""
        return self._ptr

    def kind(self):
        """Low-level wrapper for ``lr_tcp_auth_kind``. See ``include/lr_ffi.h``."""
        rc = _lib.lr_tcp_auth_kind(self._ptr)
        if rc < 0:
            raise LrError(last_error())
        return rc

    def is_none(self):
        """Low-level wrapper for ``lr_tcp_auth_is_none``. See ``include/lr_ffi.h``."""
        return _lib.lr_tcp_auth_is_none(self._ptr)

def babel_decode_frame(data, len, out):
    """Low-level wrapper for ``lr_babel_decode_frame``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_babel_decode_frame(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def best_path_select(routes, count, cfg):
    """Low-level wrapper for ``lr_best_path_select``. See ``include/lr_ffi.h``."""
    p = _lib.lr_best_path_select(routes, count, cfg)
    if not p:
        raise LrError(last_error())
    return Route.__wrap__(p)

def best_path_rank(routes, count, cfg, out):
    """Low-level wrapper for ``lr_best_path_rank``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_best_path_rank(routes, count, cfg, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def best_path_multipath(routes, count, cfg, out):
    """Low-level wrapper for ``lr_best_path_multipath``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_best_path_multipath(routes, count, cfg, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bfd_decode(data, len, out):
    """Low-level wrapper for ``lr_bfd_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bfd_decode(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bfd_auth_type_expected_digest_len(auth_type):
    """Low-level wrapper for ``lr_bfd_auth_type_expected_digest_len``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_auth_type_expected_digest_len(auth_type)

def bfd_auth_type_is_keyed_hash(auth_type):
    """Low-level wrapper for ``lr_bfd_auth_type_is_keyed_hash``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_auth_type_is_keyed_hash(auth_type)

def bfd_auth_type_is_meticulous(auth_type):
    """Low-level wrapper for ``lr_bfd_auth_type_is_meticulous``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_auth_type_is_meticulous(auth_type)

def bgp_reconcile_as4(wire_present, wire_data, wire_len, as4_present, as4_data, as4_len, out):
    """Low-level wrapper for ``lr_bgp_reconcile_as4``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_reconcile_as4(wire_present, wire_data, wire_len, as4_present, as4_data, as4_len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_decode_tlv_stream(data, len, out_count, out_array):
    """Low-level wrapper for ``lr_bgp_decode_tlv_stream``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_decode_tlv_stream(data, len, out_count, out_array)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_encode_tlv_stream(tlvs, count, out):
    """Low-level wrapper for ``lr_bgp_encode_tlv_stream``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_encode_tlv_stream(tlvs, count, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_labeled_nlri_encode_list(data, len, add_path, out):
    """Low-level wrapper for ``lr_bgp_labeled_nlri_encode_list``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_labeled_nlri_encode_list(data, len, add_path, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_error_code_from_u8(v):
    """Low-level wrapper for ``lr_bgp_error_code_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_error_code_from_u8(v)

def bgp_error_code_to_u8(v):
    """Low-level wrapper for ``lr_bgp_error_code_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_error_code_to_u8(v)

def bgp_error_code_name(v):
    """Low-level wrapper for ``lr_bgp_error_code_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_error_code_name(v)

def bgp_open_error_subcode_from_u8(v):
    """Low-level wrapper for ``lr_bgp_open_error_subcode_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_open_error_subcode_from_u8(v)

def bgp_open_error_subcode_to_u8(v):
    """Low-level wrapper for ``lr_bgp_open_error_subcode_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_open_error_subcode_to_u8(v)

def bgp_open_error_subcode_name(v):
    """Low-level wrapper for ``lr_bgp_open_error_subcode_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_open_error_subcode_name(v)

def bgp_update_error_subcode_from_u8(v):
    """Low-level wrapper for ``lr_bgp_update_error_subcode_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_update_error_subcode_from_u8(v)

def bgp_update_error_subcode_to_u8(v):
    """Low-level wrapper for ``lr_bgp_update_error_subcode_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_update_error_subcode_to_u8(v)

def bgp_update_error_subcode_name(v):
    """Low-level wrapper for ``lr_bgp_update_error_subcode_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_update_error_subcode_name(v)

def bgp_header_error_subcode_from_u8(v):
    """Low-level wrapper for ``lr_bgp_header_error_subcode_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_header_error_subcode_from_u8(v)

def bgp_header_error_subcode_to_u8(v):
    """Low-level wrapper for ``lr_bgp_header_error_subcode_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_header_error_subcode_to_u8(v)

def bgp_header_error_subcode_name(v):
    """Low-level wrapper for ``lr_bgp_header_error_subcode_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_header_error_subcode_name(v)

def bgp_cease_subcode_from_u8(v):
    """Low-level wrapper for ``lr_bgp_cease_subcode_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_cease_subcode_from_u8(v)

def bgp_cease_subcode_to_u8(v):
    """Low-level wrapper for ``lr_bgp_cease_subcode_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_cease_subcode_to_u8(v)

def bgp_cease_subcode_name(v):
    """Low-level wrapper for ``lr_bgp_cease_subcode_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_cease_subcode_name(v)

def bgp_ls_nlri_type_from_u16(v):
    """Low-level wrapper for ``lr_bgp_ls_nlri_type_from_u16``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_ls_nlri_type_from_u16(v)

def bgp_ls_nlri_type_to_u16(v):
    """Low-level wrapper for ``lr_bgp_ls_nlri_type_to_u16``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_ls_nlri_type_to_u16(v)

def bgp_ls_nlri_type_name(v):
    """Low-level wrapper for ``lr_bgp_ls_nlri_type_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_ls_nlri_type_name(v)

def bgp_origin_kind_from_u8(v):
    """Low-level wrapper for ``lr_bgp_origin_kind_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_origin_kind_from_u8(v)

def bgp_origin_kind_to_u8(v):
    """Low-level wrapper for ``lr_bgp_origin_kind_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_origin_kind_to_u8(v)

def bgp_origin_kind_name(v):
    """Low-level wrapper for ``lr_bgp_origin_kind_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_origin_kind_name(v)

def bgp_route_refresh_subtype_from_u8(v):
    """Low-level wrapper for ``lr_bgp_route_refresh_subtype_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_route_refresh_subtype_from_u8(v)

def bgp_route_refresh_subtype_to_u8(v):
    """Low-level wrapper for ``lr_bgp_route_refresh_subtype_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_route_refresh_subtype_to_u8(v)

def bgp_route_refresh_subtype_name(v):
    """Low-level wrapper for ``lr_bgp_route_refresh_subtype_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_route_refresh_subtype_name(v)

def bgp_ls_decode_tlv_stream(data, len, out):
    """Low-level wrapper for ``lr_bgp_ls_decode_tlv_stream``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_ls_decode_tlv_stream(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_attr_type_to_u8(t):
    """Low-level wrapper for ``lr_bgp_attr_type_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_attr_type_to_u8(t)

def bgp_attr_type_from_u8(wire, out_canonical):
    """Low-level wrapper for ``lr_bgp_attr_type_from_u8``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_attr_type_from_u8(wire, out_canonical)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_compute_originator_id(existing_present, existing_addr, local_bgp_id, out_addr, out_present):
    """Low-level wrapper for ``lr_bgp_compute_originator_id``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_compute_originator_id(existing_present, existing_addr, local_bgp_id, out_addr, out_present)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_cluster_list_has_loop(cluster_list, count, local_cluster):
    """Low-level wrapper for ``lr_bgp_cluster_list_has_loop``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_cluster_list_has_loop(cluster_list, count, local_cluster)

def bgp_prepend_cluster_id(cluster_list, count, local_cluster, out):
    """Low-level wrapper for ``lr_bgp_prepend_cluster_id``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_prepend_cluster_id(cluster_list, count, local_cluster, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_ext_next_hop_supports(tuples, count, nlri_afi, nlri_safi, nh_afi):
    """Low-level wrapper for ``lr_bgp_ext_next_hop_supports``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_ext_next_hop_supports(tuples, count, nlri_afi, nlri_safi, nh_afi)

def bgp_labeled_nlri_ipv4_implicit_null(prefix_addr, prefix_len, out):
    """Low-level wrapper for ``lr_bgp_labeled_nlri_ipv4_implicit_null``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_labeled_nlri_ipv4_implicit_null(prefix_addr, prefix_len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bmp_decode(data, len, out):
    """Low-level wrapper for ``lr_bmp_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bmp_decode(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bmp_peer_flags_is_ipv6(peer_flags):
    """Low-level wrapper for ``lr_bmp_peer_flags_is_ipv6``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_peer_flags_is_ipv6(peer_flags)

def bmp_peer_flags_is_post_policy(peer_flags):
    """Low-level wrapper for ``lr_bmp_peer_flags_is_post_policy``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_peer_flags_is_post_policy(peer_flags)

def bmp_peer_flags_is_legacy_as_path(peer_flags):
    """Low-level wrapper for ``lr_bmp_peer_flags_is_legacy_as_path``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_peer_flags_is_legacy_as_path(peer_flags)

def bgp_cap_code_from_wire(wire):
    """Low-level wrapper for ``lr_bgp_cap_code_from_wire``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_cap_code_from_wire(wire)

def bgp_cap_four_octet_as(asn):
    """Low-level wrapper for ``lr_bgp_cap_four_octet_as``. See ``include/lr_ffi.h``."""
    p = _lib.lr_bgp_cap_four_octet_as(asn)
    if not p:
        raise LrError(last_error())
    return BgpCapability.__wrap__(p)

def bgp_cap_multiprotocol(afi, safi):
    """Low-level wrapper for ``lr_bgp_cap_multiprotocol``. See ``include/lr_ffi.h``."""
    p = _lib.lr_bgp_cap_multiprotocol(afi, safi)
    if not p:
        raise LrError(last_error())
    return BgpCapability.__wrap__(p)

def bgp_cap_extended_next_hop(tuples, count):
    """Low-level wrapper for ``lr_bgp_cap_extended_next_hop``. See ``include/lr_ffi.h``."""
    p = _lib.lr_bgp_cap_extended_next_hop(tuples, count)
    if not p:
        raise LrError(last_error())
    return BgpCapability.__wrap__(p)

def bgp_cap_new(code, value, value_len):
    """Low-level wrapper for ``lr_bgp_cap_new``. See ``include/lr_ffi.h``."""
    p = _lib.lr_bgp_cap_new(code, value, value_len)
    if not p:
        raise LrError(last_error())
    return BgpCapability.__wrap__(p)

def bgp_cap_route_refresh():
    """Low-level wrapper for ``lr_bgp_cap_route_refresh``. See ``include/lr_ffi.h``."""
    p = _lib.lr_bgp_cap_route_refresh()
    if not p:
        raise LrError(last_error())
    return BgpCapability.__wrap__(p)

def bgp_cap_add_path(families, count):
    """Low-level wrapper for ``lr_bgp_cap_add_path``. See ``include/lr_ffi.h``."""
    p = _lib.lr_bgp_cap_add_path(families, count)
    if not p:
        raise LrError(last_error())
    return BgpCapability.__wrap__(p)

def bgp_cap_enhanced_rr():
    """Low-level wrapper for ``lr_bgp_cap_enhanced_rr``. See ``include/lr_ffi.h``."""
    p = _lib.lr_bgp_cap_enhanced_rr()
    if not p:
        raise LrError(last_error())
    return BgpCapability.__wrap__(p)

def bgp_cap_graceful_restart(restart_flags, restart_time_secs, families, count):
    """Low-level wrapper for ``lr_bgp_cap_graceful_restart``. See ``include/lr_ffi.h``."""
    p = _lib.lr_bgp_cap_graceful_restart(restart_flags, restart_time_secs, families, count)
    if not p:
        raise LrError(last_error())
    return BgpCapability.__wrap__(p)

def bgp_cap_long_lived_gr(families, count):
    """Low-level wrapper for ``lr_bgp_cap_long_lived_gr``. See ``include/lr_ffi.h``."""
    p = _lib.lr_bgp_cap_long_lived_gr(families, count)
    if not p:
        raise LrError(last_error())
    return BgpCapability.__wrap__(p)

def bgp_cap_encode_set(caps, count, out):
    """Low-level wrapper for ``lr_bgp_cap_encode_set``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_cap_encode_set(caps, count, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_cap_decode_set(data, len, out_caps, out_count):
    """Low-level wrapper for ``lr_bgp_cap_decode_set``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_cap_decode_set(data, len, out_caps, out_count)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_decode(data, len, out):
    """Low-level wrapper for ``lr_bgp_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_decode(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_encode_keepalive(out):
    """Low-level wrapper for ``lr_bgp_encode_keepalive``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_encode_keepalive(out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_encode_open(my_as, hold_time, bgp_id, as4, out):
    """Low-level wrapper for ``lr_bgp_encode_open``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_encode_open(my_as, hold_time, bgp_id, as4, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_encode_notification(error_code, error_subcode, data, data_len, out):
    """Low-level wrapper for ``lr_bgp_encode_notification``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_encode_notification(error_code, error_subcode, data, data_len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_encode_update_withdraw_v4(prefixes, n_prefixes, out):
    """Low-level wrapper for ``lr_bgp_encode_update_withdraw_v4``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_encode_update_withdraw_v4(prefixes, n_prefixes, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_encode_update_announce_v4(prefixes, n_prefixes, next_hop, as_path, as_path_len, origin, as4, out):
    """Low-level wrapper for ``lr_bgp_encode_update_announce_v4``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_encode_update_announce_v4(prefixes, n_prefixes, next_hop, as_path, as_path_len, origin, as4, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_decode_v2(data, len, out):
    """Low-level wrapper for ``lr_ospf_decode_v2``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_decode_v2(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def babel_decode(data, len, out):
    """Low-level wrapper for ``lr_babel_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_babel_decode(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_decode_message(data, len):
    """Low-level wrapper for ``lr_bgp_decode_message``. See ``include/lr_ffi.h``."""
    p = _lib.lr_bgp_decode_message(data, len)
    if not p:
        raise LrError(last_error())
    return BgpMessage.__wrap__(p)

def bgp_encode_ipv4_nlri(prefixes, count, out):
    """Low-level wrapper for ``lr_bgp_encode_ipv4_nlri``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_encode_ipv4_nlri(prefixes, count, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_decode_ipv4_nlri(data, len, out):
    """Low-level wrapper for ``lr_bgp_decode_ipv4_nlri``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_decode_ipv4_nlri(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def protocol_bird_name(proto, out_name, name_cap):
    """Low-level wrapper for ``lr_protocol_bird_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_protocol_bird_name(proto, out_name, name_cap)

def protocol_default_admin_distance(proto):
    """Low-level wrapper for ``lr_protocol_default_admin_distance``. See ``include/lr_ffi.h``."""
    return _lib.lr_protocol_default_admin_distance(proto)

def instant_from_millis(millis):
    """Low-level wrapper for ``lr_instant_from_millis``. See ``include/lr_ffi.h``."""
    return _lib.lr_instant_from_millis(millis)

def instant_from_secs(secs):
    """Low-level wrapper for ``lr_instant_from_secs``. See ``include/lr_ffi.h``."""
    return _lib.lr_instant_from_secs(secs)

def instant_as_millis(instant):
    """Low-level wrapper for ``lr_instant_as_millis``. See ``include/lr_ffi.h``."""
    return _lib.lr_instant_as_millis(instant)

def instant_as_secs(instant):
    """Low-level wrapper for ``lr_instant_as_secs``. See ``include/lr_ffi.h``."""
    return _lib.lr_instant_as_secs(instant)

def instant_saturating_sub(earlier, later):
    """Low-level wrapper for ``lr_instant_saturating_sub``. See ``include/lr_ffi.h``."""
    return _lib.lr_instant_saturating_sub(earlier, later)

def instant_checked_add(instant, duration_ms):
    """Low-level wrapper for ``lr_instant_checked_add``. See ``include/lr_ffi.h``."""
    return _lib.lr_instant_checked_add(instant, duration_ms)

def duration_from_millis(millis):
    """Low-level wrapper for ``lr_duration_from_millis``. See ``include/lr_ffi.h``."""
    return _lib.lr_duration_from_millis(millis)

def duration_from_secs(secs):
    """Low-level wrapper for ``lr_duration_from_secs``. See ``include/lr_ffi.h``."""
    return _lib.lr_duration_from_secs(secs)

def duration_as_millis(duration_ms):
    """Low-level wrapper for ``lr_duration_as_millis``. See ``include/lr_ffi.h``."""
    return _lib.lr_duration_as_millis(duration_ms)

def duration_as_secs(duration_ms):
    """Low-level wrapper for ``lr_duration_as_secs``. See ``include/lr_ffi.h``."""
    return _lib.lr_duration_as_secs(duration_ms)

def duration_checked_add(a, b):
    """Low-level wrapper for ``lr_duration_checked_add``. See ``include/lr_ffi.h``."""
    return _lib.lr_duration_checked_add(a, b)

def crc16_arc(bytes, len):
    """Low-level wrapper for ``lr_crc16_arc``. See ``include/lr_ffi.h``."""
    return _lib.lr_crc16_arc(bytes, len)

def crc32c(bytes, len):
    """Low-level wrapper for ``lr_crc32c``. See ``include/lr_ffi.h``."""
    return _lib.lr_crc32c(bytes, len)

def fletcher32(bytes, len):
    """Low-level wrapper for ``lr_fletcher32``. See ``include/lr_ffi.h``."""
    return _lib.lr_fletcher32(bytes, len)

def bfd_auth_type_from_u8(v):
    """Low-level wrapper for ``lr_bfd_auth_type_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_auth_type_from_u8(v)

def bfd_auth_type_to_u8(v):
    """Low-level wrapper for ``lr_bfd_auth_type_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_auth_type_to_u8(v)

def bfd_auth_type_name(v):
    """Low-level wrapper for ``lr_bfd_auth_type_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_auth_type_name(v)

def bfd_diagnostic_from_u8(v):
    """Low-level wrapper for ``lr_bfd_diagnostic_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_diagnostic_from_u8(v)

def bfd_diagnostic_to_u8(v):
    """Low-level wrapper for ``lr_bfd_diagnostic_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_diagnostic_to_u8(v)

def bfd_diagnostic_name(v):
    """Low-level wrapper for ``lr_bfd_diagnostic_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_diagnostic_name(v)

def bfd_state_from_u8(v):
    """Low-level wrapper for ``lr_bfd_state_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_state_from_u8(v)

def bfd_state_to_u8(v):
    """Low-level wrapper for ``lr_bfd_state_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_state_to_u8(v)

def bfd_state_name(v):
    """Low-level wrapper for ``lr_bfd_state_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bfd_state_name(v)

def bmp_msg_type_from_u8(v):
    """Low-level wrapper for ``lr_bmp_msg_type_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_msg_type_from_u8(v)

def bmp_msg_type_to_u8(v):
    """Low-level wrapper for ``lr_bmp_msg_type_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_msg_type_to_u8(v)

def bmp_msg_type_name(v):
    """Low-level wrapper for ``lr_bmp_msg_type_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_msg_type_name(v)

def bmp_peer_type_from_u8(v):
    """Low-level wrapper for ``lr_bmp_peer_type_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_peer_type_from_u8(v)

def bmp_peer_type_to_u8(v):
    """Low-level wrapper for ``lr_bmp_peer_type_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_peer_type_to_u8(v)

def bmp_peer_type_name(v):
    """Low-level wrapper for ``lr_bmp_peer_type_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_peer_type_name(v)

def bmp_peer_down_reason_from_u8(v):
    """Low-level wrapper for ``lr_bmp_peer_down_reason_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_peer_down_reason_from_u8(v)

def bmp_peer_down_reason_to_u8(v):
    """Low-level wrapper for ``lr_bmp_peer_down_reason_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_peer_down_reason_to_u8(v)

def bmp_peer_down_reason_name(v):
    """Low-level wrapper for ``lr_bmp_peer_down_reason_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_bmp_peer_down_reason_name(v)

def ldp_message_type_from_u16(v):
    """Low-level wrapper for ``lr_ldp_message_type_from_u16``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_message_type_from_u16(v)

def ldp_message_type_to_u16(v):
    """Low-level wrapper for ``lr_ldp_message_type_to_u16``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_message_type_to_u16(v)

def ldp_message_type_name(v):
    """Low-level wrapper for ``lr_ldp_message_type_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_message_type_name(v)

def ldp_tlv_type_from_u16(v):
    """Low-level wrapper for ``lr_ldp_tlv_type_from_u16``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_tlv_type_from_u16(v)

def ldp_tlv_type_to_u16(v):
    """Low-level wrapper for ``lr_ldp_tlv_type_to_u16``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_tlv_type_to_u16(v)

def ldp_tlv_type_name(v):
    """Low-level wrapper for ``lr_ldp_tlv_type_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_tlv_type_name(v)

def ldp_advertisement_mode_from_u8(v):
    """Low-level wrapper for ``lr_ldp_advertisement_mode_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_advertisement_mode_from_u8(v)

def ldp_advertisement_mode_to_u8(v):
    """Low-level wrapper for ``lr_ldp_advertisement_mode_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_advertisement_mode_to_u8(v)

def ldp_advertisement_mode_name(v):
    """Low-level wrapper for ``lr_ldp_advertisement_mode_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_advertisement_mode_name(v)

def bfd_auth_type_from_algorithm(algorithm):
    """Low-level wrapper for ``lr_bfd_auth_type_from_algorithm``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bfd_auth_type_from_algorithm(algorithm)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ip_net_into_inner(net, out):
    """Low-level wrapper for ``lr_ip_net_into_inner``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ip_net_into_inner(net, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def instant_checked_sub(instant, other, out):
    """Low-level wrapper for ``lr_instant_checked_sub``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_instant_checked_sub(instant, other, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ldp_encode_hello_pdu(sender, message_id, hold_time, target, out):
    """Low-level wrapper for ``lr_ldp_encode_hello_pdu``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ldp_encode_hello_pdu(sender, message_id, hold_time, target, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ldp_decode(data, len, out):
    """Low-level wrapper for ``lr_ldp_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ldp_decode(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ldp_status_code_new(code):
    """Low-level wrapper for ``lr_ldp_status_code_new``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_status_code_new(code)

def ldp_status_code_is_fatal(code):
    """Low-level wrapper for ``lr_ldp_status_code_is_fatal``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_status_code_is_fatal(code)

def ldp_status_code_is_forward(code):
    """Low-level wrapper for ``lr_ldp_status_code_is_forward``. See ``include/lr_ffi.h``."""
    return _lib.lr_ldp_status_code_is_forward(code)

def babel_link_cost(rxcost):
    """Low-level wrapper for ``lr_babel_link_cost``. See ``include/lr_ffi.h``."""
    return _lib.lr_babel_link_cost(rxcost)

def babel_rtt_penalty(rtt_us, rtt_min_us, rtt_max_us, max_penalty):
    """Low-level wrapper for ``lr_babel_rtt_penalty``. See ``include/lr_ffi.h``."""
    return _lib.lr_babel_rtt_penalty(rtt_us, rtt_min_us, rtt_max_us, max_penalty)

def babel_feasible(route_seqno, route_metric, feasible_seqno, feasible_metric):
    """Low-level wrapper for ``lr_babel_feasible``. See ``include/lr_ffi.h``."""
    return _lib.lr_babel_feasible(route_seqno, route_metric, feasible_seqno, feasible_metric)

def ldp_compare_transport_addrs(a_is_v6, a, b_is_v6, b):
    """Low-level wrapper for ``lr_ldp_compare_transport_addrs``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ldp_compare_transport_addrs(a_is_v6, a, b_is_v6, b)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ldp_role_for(local_is_v6, local, remote_is_v6, remote):
    """Low-level wrapper for ``lr_ldp_role_for``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ldp_role_for(local_is_v6, local, remote_is_v6, remote)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_sr_remote_label(srgb_base, srgb_range, sid, flags, out, out_present):
    """Low-level wrapper for ``lr_ospf_sr_remote_label``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_sr_remote_label(srgb_base, srgb_range, sid, flags, out, out_present)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_sr_encode_ri_lsa_body(srgb_base, srgb_range, out):
    """Low-level wrapper for ``lr_ospf_sr_encode_ri_lsa_body``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_sr_encode_ri_lsa_body(srgb_base, srgb_range, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_sr_decode_ri_lsa_body(data, len, out_srgb_base, out_srgb_range, out_present):
    """Low-level wrapper for ``lr_ospf_sr_decode_ri_lsa_body``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_sr_decode_ri_lsa_body(data, len, out_srgb_base, out_srgb_range, out_present)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_sr_opaque_type_from_lsid(link_state_id):
    """Low-level wrapper for ``lr_ospf_sr_opaque_type_from_lsid``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_sr_opaque_type_from_lsid(link_state_id)

def mpls_stack_last_err_code():
    """Low-level wrapper for ``lr_mpls_stack_last_err_code``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_mpls_stack_last_err_code()
    if rc < 0:
        raise LrError(last_error())
    return rc

def mrt_decode(data, len, out):
    """Low-level wrapper for ``lr_mrt_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_mrt_decode(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def mrt_encode_peer_index_table(timestamp, collector_bgp_id, view_name, peers, peer_count, out):
    """Low-level wrapper for ``lr_mrt_encode_peer_index_table``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_mrt_encode_peer_index_table(timestamp, collector_bgp_id, view_name, peers, peer_count, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def mrt_encode_rib_table(timestamp, sequence, prefix_addr, prefix_len, is_ipv6, add_path, entries, entry_count, out):
    """Low-level wrapper for ``lr_mrt_encode_rib_table``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_mrt_encode_rib_table(timestamp, sequence, prefix_addr, prefix_len, is_ipv6, add_path, entries, entry_count, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def mrt_walk_attributes(entry, out_summary, as_path_buf, as_path_cap, communities_buf, communities_cap):
    """Low-level wrapper for ``lr_mrt_walk_attributes``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_mrt_walk_attributes(entry, out_summary, as_path_buf, as_path_cap, communities_buf, communities_cap)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_decode_v2_packet(data, len, out):
    """Low-level wrapper for ``lr_ospf_decode_v2_packet``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_decode_v2_packet(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_decode_v3_packet(data, len, out):
    """Low-level wrapper for ``lr_ospf_decode_v3_packet``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_decode_v3_packet(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_finalize_v2_packet(bytes, len):
    """Low-level wrapper for ``lr_ospf_finalize_v2_packet``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_finalize_v2_packet(bytes, len)

def ospf_finalize_v2_stream(bytes, len):
    """Low-level wrapper for ``lr_ospf_finalize_v2_stream``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_finalize_v2_stream(bytes, len)

def ospf_v2_packet_checksum_ok(bytes, len):
    """Low-level wrapper for ``lr_ospf_v2_packet_checksum_ok``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_v2_packet_checksum_ok(bytes, len)

def ospf_finalize_v3_packet(bytes, len, src, dst):
    """Low-level wrapper for ``lr_ospf_finalize_v3_packet``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_finalize_v3_packet(bytes, len, src, dst)

def ospf_finalize_v3_stream(bytes, len, src, dst):
    """Low-level wrapper for ``lr_ospf_finalize_v3_stream``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_finalize_v3_stream(bytes, len, src, dst)

def ospf_summary_lsa_id_for(prefix_v4, prefix_v6, prefix_len, existing, count, out):
    """Low-level wrapper for ``lr_ospf_summary_lsa_id_for``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_summary_lsa_id_for(prefix_v4, prefix_v6, prefix_len, existing, count, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_originate_summary_lsa(router_id, dest, prev_seq, out):
    """Low-level wrapper for ``lr_ospf_originate_summary_lsa``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_originate_summary_lsa(router_id, dest, prev_seq, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_originate_v3_inter_area_prefix_lsa(router_id, ls_id, dest, prev_seq, out):
    """Low-level wrapper for ``lr_ospf_originate_v3_inter_area_prefix_lsa``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_originate_v3_inter_area_prefix_lsa(router_id, ls_id, dest, prev_seq, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_originate_nssa_lsa(router_id, dest, prev_seq, out):
    """Low-level wrapper for ``lr_ospf_originate_nssa_lsa``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_originate_nssa_lsa(router_id, dest, prev_seq, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_originate_nssa_default_lsa(router_id, default_dest, prev_seq, out):
    """Low-level wrapper for ``lr_ospf_originate_nssa_default_lsa``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_originate_nssa_default_lsa(router_id, default_dest, prev_seq, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_au_type_from_u16(wire):
    """Low-level wrapper for ``lr_ospf_au_type_from_u16``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_au_type_from_u16(wire)

def ospf_au_type_to_u16(value):
    """Low-level wrapper for ``lr_ospf_au_type_to_u16``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_au_type_to_u16(value)

def ospf_au_type_name(value):
    """Low-level wrapper for ``lr_ospf_au_type_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_au_type_name(value)

def ospf_crypto_algorithm_to_u8(value):
    """Low-level wrapper for ``lr_ospf_crypto_algorithm_to_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_crypto_algorithm_to_u8(value)

def ospf_crypto_algorithm_from_u8(value):
    """Low-level wrapper for ``lr_ospf_crypto_algorithm_from_u8``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_crypto_algorithm_from_u8(value)

def ospf_crypto_algorithm_name(value):
    """Low-level wrapper for ``lr_ospf_crypto_algorithm_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_crypto_algorithm_name(value)

def ospf_crypto_algorithm_digest_len(value):
    """Low-level wrapper for ``lr_ospf_crypto_algorithm_digest_len``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_crypto_algorithm_digest_len(value)

def ospf_crypto_algorithm_trailer_len(value):
    """Low-level wrapper for ``lr_ospf_crypto_algorithm_trailer_len``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_crypto_algorithm_trailer_len(value)

def ospf_version_from_u8(v):
    """Low-level wrapper for ``lr_ospf_version_from_u8``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_version_from_u8(v)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_if_state_name(state):
    """Low-level wrapper for ``lr_ospf_if_state_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_if_state_name(state)

def ospf_external_metric_type_e_bit(t):
    """Low-level wrapper for ``lr_ospf_external_metric_type_e_bit``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_external_metric_type_e_bit(t)

def ospf_external_metric_type_from_e_bit(e_bit):
    """Low-level wrapper for ``lr_ospf_external_metric_type_from_e_bit``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_external_metric_type_from_e_bit(e_bit)

def ospf_grace_tlv_type_from_u16(v):
    """Low-level wrapper for ``lr_ospf_grace_tlv_type_from_u16``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_grace_tlv_type_from_u16(v)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_grace_reason_from_u8(v):
    """Low-level wrapper for ``lr_ospf_grace_reason_from_u8``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_grace_reason_from_u8(v)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_router_lsa_flags_to_word(virtual_link, asbr, border):
    """Low-level wrapper for ``lr_ospf_router_lsa_flags_to_word``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_router_lsa_flags_to_word(virtual_link, asbr, border)

def ospf_router_lsa_flags_from_word(word, out_v, out_e, out_b):
    """Low-level wrapper for ``lr_ospf_router_lsa_flags_from_word``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_router_lsa_flags_from_word(word, out_v, out_e, out_b)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_originate_external_lsa(router_id, dest, prev_seq, out):
    """Low-level wrapper for ``lr_ospf_originate_external_lsa``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_originate_external_lsa(router_id, dest, prev_seq, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_originate_summary_asbr_lsa(router_id, asbr_dest, prev_seq, out):
    """Low-level wrapper for ``lr_ospf_originate_summary_asbr_lsa``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_originate_summary_asbr_lsa(router_id, asbr_dest, prev_seq, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_elect(electors, count, self_router_id, self_ip, self_priority, self_stated_dr, self_stated_bdr, out_dr, out_bdr):
    """Low-level wrapper for ``lr_ospf_elect``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_elect(electors, count, self_router_id, self_ip, self_priority, self_stated_dr, self_stated_bdr, out_dr, out_bdr)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_elect_v3(electors, count, self_router_id, self_priority, self_stated_dr, self_stated_bdr, out_dr, out_bdr):
    """Low-level wrapper for ``lr_ospf_elect_v3``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_elect_v3(electors, count, self_router_id, self_priority, self_stated_dr, self_stated_bdr, out_dr, out_bdr)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_clamp_grace_period(secs):
    """Low-level wrapper for ``lr_ospf_clamp_grace_period``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_clamp_grace_period(secs)

def ospf_mask_to_prefix_len(mask):
    """Low-level wrapper for ``lr_ospf_mask_to_prefix_len``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_mask_to_prefix_len(mask)

def ospf_prefix_len_to_mask(len):
    """Low-level wrapper for ``lr_ospf_prefix_len_to_mask``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_prefix_len_to_mask(len)

def ospf_grace_lsa_type():
    """Low-level wrapper for ``lr_ospf_grace_lsa_type``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_grace_lsa_type()

def ospf_opaque_lsa_id(opaque_type, opaque_id):
    """Low-level wrapper for ``lr_ospf_opaque_lsa_id``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_opaque_lsa_id(opaque_type, opaque_id)

def ospf_unpack_opaque_lsa_id(link_state_id, out_type, out_id):
    """Low-level wrapper for ``lr_ospf_unpack_opaque_lsa_id``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_unpack_opaque_lsa_id(link_state_id, out_type, out_id)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_with_grace_restart_capable(options):
    """Low-level wrapper for ``lr_ospf_with_grace_restart_capable``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_with_grace_restart_capable(options)

def ospf_is_grace_restart_capable(options):
    """Low-level wrapper for ``lr_ospf_is_grace_restart_capable``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_is_grace_restart_capable(options)

def ospf_encode_summary_lsa_body(network_mask, metric, out):
    """Low-level wrapper for ``lr_ospf_encode_summary_lsa_body``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_encode_summary_lsa_body(network_mask, metric, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_decode_summary_lsa_body(data, len, out_mask, out_metric):
    """Low-level wrapper for ``lr_ospf_decode_summary_lsa_body``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_decode_summary_lsa_body(data, len, out_mask, out_metric)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_encode_as_external_body(network_mask, metric, external_type2, forwarding_addr_v4, external_route_tag, out):
    """Low-level wrapper for ``lr_ospf_encode_as_external_body``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_encode_as_external_body(network_mask, metric, external_type2, forwarding_addr_v4, external_route_tag, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_decode_as_external_body(data, len, out_mask, out_metric, out_external_type2, out_forwarding_addr_v4, out_external_route_tag):
    """Low-level wrapper for ``lr_ospf_decode_as_external_body``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_decode_as_external_body(data, len, out_mask, out_metric, out_external_type2, out_forwarding_addr_v4, out_external_route_tag)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_decode_router_links(data, len, out_count, out_array):
    """Low-level wrapper for ``lr_ospf_decode_router_links``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_decode_router_links(data, len, out_count, out_array)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_router_lsa_flags_byte(data, len, out):
    """Low-level wrapper for ``lr_ospf_router_lsa_flags_byte``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_router_lsa_flags_byte(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_encode_v3_inter_area_prefix_body(is_v6, prefix_addr, prefix_len, metric, out):
    """Low-level wrapper for ``lr_ospf_encode_v3_inter_area_prefix_body``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_encode_v3_inter_area_prefix_body(is_v6, prefix_addr, prefix_len, metric, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_decode_v3_inter_area_prefix_body(data, len, out_prefix_len, out_metric, out_prefix_addr):
    """Low-level wrapper for ``lr_ospf_decode_v3_inter_area_prefix_body``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_decode_v3_inter_area_prefix_body(data, len, out_prefix_len, out_metric, out_prefix_addr)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_is_e_lsa_type(ls_type):
    """Low-level wrapper for ``lr_ospf_is_e_lsa_type``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_is_e_lsa_type(ls_type)

def ospf_walk_e_lsa_tlvs(data, len, out_count, out_array):
    """Low-level wrapper for ``lr_ospf_walk_e_lsa_tlvs``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_walk_e_lsa_tlvs(data, len, out_count, out_array)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_srv6_behavior_valid_for_end_sid(behavior):
    """Low-level wrapper for ``lr_ospf_srv6_behavior_valid_for_end_sid``. See ``include/lr_ffi.h``."""
    return _lib.lr_ospf_srv6_behavior_valid_for_end_sid(behavior)

def ospf_originate_router_lsa(router_id, flags_byte, links, count, prev_seq, out):
    """Low-level wrapper for ``lr_ospf_originate_router_lsa``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_originate_router_lsa(router_id, flags_byte, links, count, prev_seq, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def ospf_originate_network_lsa(dr_router_id, dr_addr, mask, attached_routers, count, prev_seq, out):
    """Low-level wrapper for ``lr_ospf_originate_network_lsa``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_ospf_originate_network_lsa(dr_router_id, dr_addr, mask, attached_routers, count, prev_seq, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def apply_set_error_name(code):
    """Low-level wrapper for ``lr_apply_set_error_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_apply_set_error_name(code)

def bgp_cluster_id_from_u32(v):
    """Low-level wrapper for ``lr_bgp_cluster_id_from_u32``. See ``include/lr_ffi.h``."""
    return _lib.lr_bgp_cluster_id_from_u32(v)

def bgp_cluster_id_to_v4_bytes(cluster_id, out):
    """Low-level wrapper for ``lr_bgp_cluster_id_to_v4_bytes``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_cluster_id_to_v4_bytes(cluster_id, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def mpls_platform_labels():
    """Low-level wrapper for ``lr_mpls_platform_labels``. See ``include/lr_ffi.h``."""
    return _lib.lr_mpls_platform_labels()

def rtr_error_code_name(code, out_name):
    """Low-level wrapper for ``lr_rtr_error_code_name``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_rtr_error_code_name(code, out_name)
    if rc < 0:
        raise LrError(last_error())
    return rc

def rtr_error_code_is_fatal(code, out):
    """Low-level wrapper for ``lr_rtr_error_code_is_fatal``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_rtr_error_code_is_fatal(code, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def rtr_error_code_from_u16(code):
    """Low-level wrapper for ``lr_rtr_error_code_from_u16``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_rtr_error_code_from_u16(code)
    if rc < 0:
        raise LrError(last_error())
    return rc

def srv6_encode_srh(data, len, out):
    """Low-level wrapper for ``lr_srv6_encode_srh``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_srv6_encode_srh(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def srv6_decode_srh(data, len, out):
    """Low-level wrapper for ``lr_srv6_decode_srh``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_srv6_decode_srh(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def srv6_behavior_from_wire(wire, out_value, out_name, name_cap):
    """Low-level wrapper for ``lr_srv6_behavior_from_wire``. See ``include/lr_ffi.h``."""
    return _lib.lr_srv6_behavior_from_wire(wire, out_value, out_name, name_cap)

def srv6_behavior_wire_value(wire):
    """Low-level wrapper for ``lr_srv6_behavior_wire_value``. See ``include/lr_ffi.h``."""
    return _lib.lr_srv6_behavior_wire_value(wire)

def srv6_behavior_is_psp(wire):
    """Low-level wrapper for ``lr_srv6_behavior_is_psp``. See ``include/lr_ffi.h``."""
    return _lib.lr_srv6_behavior_is_psp(wire)

def srv6_behavior_is_usp(wire):
    """Low-level wrapper for ``lr_srv6_behavior_is_usp``. See ``include/lr_ffi.h``."""
    return _lib.lr_srv6_behavior_is_usp(wire)

def srv6_behavior_is_usd(wire):
    """Low-level wrapper for ``lr_srv6_behavior_is_usd``. See ``include/lr_ffi.h``."""
    return _lib.lr_srv6_behavior_is_usd(wire)

def srv6_behavior_is_decap(wire):
    """Low-level wrapper for ``lr_srv6_behavior_is_decap``. See ``include/lr_ffi.h``."""
    return _lib.lr_srv6_behavior_is_decap(wire)

def srv6_behavior_is_cross_connect(wire):
    """Low-level wrapper for ``lr_srv6_behavior_is_cross_connect``. See ``include/lr_ffi.h``."""
    return _lib.lr_srv6_behavior_is_cross_connect(wire)

def srv6_behavior_is_table_lookup(wire):
    """Low-level wrapper for ``lr_srv6_behavior_is_table_lookup``. See ``include/lr_ffi.h``."""
    return _lib.lr_srv6_behavior_is_table_lookup(wire)

def srv6_behavior_name(wire, out_name, name_cap):
    """Low-level wrapper for ``lr_srv6_behavior_name``. See ``include/lr_ffi.h``."""
    return _lib.lr_srv6_behavior_name(wire, out_name, name_cap)

def bgp_well_known_origin_decode(data, len, out):
    """Low-level wrapper for ``lr_bgp_well_known_origin_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_origin_decode(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_origin_encode(kind, out):
    """Low-level wrapper for ``lr_bgp_well_known_origin_encode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_origin_encode(kind, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_next_hop_decode(data, len, out_is_ipv6, out_addr):
    """Low-level wrapper for ``lr_bgp_well_known_next_hop_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_next_hop_decode(data, len, out_is_ipv6, out_addr)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_next_hop_encode(is_ipv6, addr, out):
    """Low-level wrapper for ``lr_bgp_well_known_next_hop_encode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_next_hop_encode(is_ipv6, addr, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_med_decode(data, len, out):
    """Low-level wrapper for ``lr_bgp_well_known_med_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_med_decode(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_med_encode(value, out):
    """Low-level wrapper for ``lr_bgp_well_known_med_encode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_med_encode(value, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_local_pref_decode(data, len, out):
    """Low-level wrapper for ``lr_bgp_well_known_local_pref_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_local_pref_decode(data, len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_local_pref_encode(value, out):
    """Low-level wrapper for ``lr_bgp_well_known_local_pref_encode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_local_pref_encode(value, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_aggregator_decode(data, len, out_asn, out_speaker):
    """Low-level wrapper for ``lr_bgp_well_known_aggregator_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_aggregator_decode(data, len, out_asn, out_speaker)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_aggregator_encode_4(asn, speaker, out):
    """Low-level wrapper for ``lr_bgp_well_known_aggregator_encode_4``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_aggregator_encode_4(asn, speaker, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_originator_id_decode(data, len, out_bgp_id):
    """Low-level wrapper for ``lr_bgp_well_known_originator_id_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_originator_id_decode(data, len, out_bgp_id)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_originator_id_encode(bgp_id, out):
    """Low-level wrapper for ``lr_bgp_well_known_originator_id_encode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_originator_id_encode(bgp_id, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_cluster_list_decode(data, len, out_clusters, cap, out_count):
    """Low-level wrapper for ``lr_bgp_well_known_cluster_list_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_cluster_list_decode(data, len, out_clusters, cap, out_count)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_cluster_list_encode(clusters, count, out):
    """Low-level wrapper for ``lr_bgp_well_known_cluster_list_encode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_cluster_list_encode(clusters, count, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_aigp_decode(data, len, out_metric):
    """Low-level wrapper for ``lr_bgp_well_known_aigp_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_aigp_decode(data, len, out_metric)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_aigp_encode(metric, out):
    """Low-level wrapper for ``lr_bgp_well_known_aigp_encode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_aigp_encode(metric, out)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_pmsi_tunnel_decode(data, len, out_flags, out_tunnel_type, out_label, out_tunnel_id):
    """Low-level wrapper for ``lr_bgp_well_known_pmsi_tunnel_decode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_pmsi_tunnel_decode(data, len, out_flags, out_tunnel_type, out_label, out_tunnel_id)
    if rc < 0:
        raise LrError(last_error())
    return rc

def bgp_well_known_pmsi_tunnel_encode(flags, tunnel_type, label, tunnel_id, tunnel_id_len, out):
    """Low-level wrapper for ``lr_bgp_well_known_pmsi_tunnel_encode``. See ``include/lr_ffi.h``."""
    rc = _lib.lr_bgp_well_known_pmsi_tunnel_encode(flags, tunnel_type, label, tunnel_id, tunnel_id_len, out)
    if rc < 0:
        raise LrError(last_error())
    return rc
