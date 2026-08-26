"""librouting Python bindings (CFFI-based).

Exposes Layer-3 router lifecycle + Layer-1 codec helpers.
The shared library `liblr_ffi.so` is loaded at import time. The path can be
overridden via the `LIBROUTING_LIB` environment variable; otherwise we look
in the workspace's `target/release` directory.
"""

from .router import Router, abi_version, last_error
from .codec import (
    encode_keepalive,
    decode_bgp,
    decode_ospf_v2,
    decode_babel,
)

__all__ = [
    "Router",
    "encode_keepalive",
    "decode_bgp",
    "decode_ospf_v2",
    "decode_babel",
    "abi_version",
    "last_error",
]

__version__ = "0.1.0"
