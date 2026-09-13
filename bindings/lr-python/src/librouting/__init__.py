"""librouting Python bindings (CFFI-based).

Exposes Layer-3 router lifecycle + Layer-1 codec helpers.
The shared library `liblr_ffi.so` is loaded at import time. The path can be
overridden via the `LIBROUTING_LIB` environment variable; otherwise we look
in the workspace's `target/release` directory.
"""

from .router import LrError, Router, abi_version, last_error, mpls_platform_labels
from .roa import ROA_INVALID, ROA_NOT_FOUND, ROA_VALID, RoaStore
from .codec import (
    encode_keepalive,
    decode_bgp,
    decode_ospf_v2,
    decode_babel,
    encode_srv6_srh,
    decode_srv6_srh,
)

__all__ = [
    "Router",
    "RoaStore",
    "ROA_VALID",
    "ROA_NOT_FOUND",
    "ROA_INVALID",
    "encode_keepalive",
    "decode_bgp",
    "decode_ospf_v2",
    "decode_babel",
    "encode_srv6_srh",
    "decode_srv6_srh",
    "abi_version",
    "last_error",
    "mpls_platform_labels",
    "LrError",
]

__version__ = "1.0.0-rc.2"
