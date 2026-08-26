"""Tests for the Python librouting bindings."""

import os
import sys
import pathlib

# Locate the workspace's built shared library.
_HERE = pathlib.Path(__file__).resolve().parent
_ROOT = _HERE
for _ in range(8):
    if (_ROOT / "Cargo.toml").exists():
        break
    _ROOT = _ROOT.parent

candidates = [
    _ROOT / "target" / "release" / "liblr_ffi.so",
    _ROOT / "target" / "debug" / "liblr_ffi.so",
]
for c in candidates:
    if c.exists():
        os.environ.setdefault("LIBROUTING_LIB", str(c))
        break

# Make the src/librouting package importable.
sys.path.insert(0, str(_ROOT / "bindings" / "lr-python" / "src"))

import librouting


def test_abi_version():
    assert librouting.abi_version() > 0


def test_encode_keepalive():
    b = librouting.encode_keepalive()
    assert len(b) == 19
    assert b[18] == 4


def test_decode_bgp():
    b = librouting.encode_keepalive()
    out = librouting.decode_bgp(b)
    assert len(out) == len(b)


def test_router_lifecycle():
    with librouting.Router() as r:
        h = r.add_bgp_session(local_as=64512, peer_as=64513, local_bgp_id=0x0a000001)
        assert h == 1
        # No input yet; drain should produce empty bytes.
        out = r.drain_output(h)
        assert isinstance(out, bytes)
        r.tick(0)


if __name__ == "__main__":
    test_abi_version()
    test_encode_keepalive()
    test_decode_bgp()
    test_router_lifecycle()
    print("all tests passed")
