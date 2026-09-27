#!/usr/bin/env python3
"""Craft Babel (RFC 8966) TLV frames for interop tests.

The lr-daemon's own Babel stack is the codec under test, so we cannot
use it to generate the stimulus packets — that would be testing the
codec against itself. This helper emits the wire bytes for the small
set of frames the interop suite needs:

  teach <router-id-hex> <ae> <plen> <prefix-bytes-hex> <seqno> <metric>
      A frame carrying Hello + IHU + RouterId + NextHop + Update that
      teaches one route. The IHU is required: babeld/BIRD accept no
      Update from a neighbour that has not sent an IHU yet (txcost
      stays infinite).

  retract-wildcard
      A frame with a single AE 0, metric 0xFFFF Update — the RFC 8966
      §4.6.9 wildcard retraction that flushes every route this
      neighbour taught us.

  retract-prefix <ae> <plen> <prefix-bytes-hex>
      A frame with a single per-prefix retraction (metric 0xFFFF).

Frames are written to stdout as raw bytes; the test harness sends
them via `nc -u` or a small Python UDP socket to the daemon's babel
port. The Hello/IHU/RouterId/NextHop TLVs are the same shape the
daemon itself emits, so the daemon's reception path sees a frame
indistinguishable from a real peer's.

Usage:
  babel_send.py teach <rid-hex> <ae> <plen> <prefix-hex> <seqno> <metric> > frame.bin
  babel_send.py retract-wildcard > frame.bin
  babel_send.py retract-prefix <ae> <plen> <prefix-hex> > frame.bin
"""
import struct
import sys

# Babel TLV type IDs (RFC 8966 §4.4).
TLV_PAD1 = 0
TLV_PADN = 1
TLV_ACK_REQ = 2
TLV_ACK = 3
TLV_HELLO = 4
TLV_IHU = 5
TLV_ROUTER_ID = 6
TLV_NEXT_HOP = 7
TLV_UPDATE = 8
TLV_ROUTE_REQUEST = 9
TLV_SEQNO_REQUEST = 10


def tlv(kind: int, body: bytes) -> bytes:
    """Encode one TLV: type(1) + length(1) + body(length)."""
    assert len(body) <= 0xFF, f"TLV body too long: {len(body)}"
    return bytes([kind, len(body)]) + body


def hello(seqno: int, interval_cs: int) -> bytes:
    """Hello TLV (§4.6.1): Seqno(2) + Interval(2)."""
    return tlv(TLV_HELLO, struct.pack(">HH", seqno, interval_cs))


def ihu(ae: int, rxcost: int, interval_cs: int, address: bytes) -> bytes:
    """IHU TLV (§4.6.2): AE(1) + Reserved(1) + Rxcost(2) + Interval(2) + Address."""
    return tlv(TLV_IHU, struct.pack(">BxHH", ae, rxcost, interval_cs) + address)


def router_id(rid: bytes) -> bytes:
    """Router-Id TLV (§4.6.7): 8 bytes."""
    assert len(rid) == 8, f"router-id must be 8 bytes, got {len(rid)}"
    return tlv(TLV_ROUTER_ID, rid)


def next_hop(ae: int, address: bytes) -> bytes:
    """NextHop TLV (§4.6.4): AE(1) + Reserved(1) + Address."""
    return tlv(TLV_NEXT_HOP, struct.pack(">Bx", ae) + address)


def update(ae: int, flags: int, plen: int, omitted: int,
           interval_cs: int, seqno: int, metric: int,
           prefix: bytes, src_prefix: bytes = b"", src_plen: int = 0) -> bytes:
    """Update TLV (§4.6.3).

    Body: AE(1) + Flags(1) + Plen(1) + Omitted(1) + Interval(2) +
    Seqno(2) + Metric(2) + Prefix(ceil(Plen/8) - Omitted).
    """
    body = struct.pack(">BBBBHHH", ae, flags, plen, omitted,
                       interval_cs, seqno, metric) + prefix
    if src_plen > 0:
        # RFC 9079 Source Prefix sub-TLV (type 128, mandatory bit set).
        sub = bytes([128, len(src_prefix) + 1, src_plen]) + src_prefix
        body += sub
    return tlv(TLV_UPDATE, body)


def frame(tlvs: list[bytes]) -> bytes:
    """A Babel frame (RFC 8966 §4.2): magic(1) + version(1) + body-length(2, BE) + body.

    The 4-byte header is mandatory — the daemon's codec rejects packets
    without it (`ParseError::invalid(0, "babel.header.magic")`).
    """
    body = b"".join(tlvs)
    assert len(body) <= 0xFFFF, f"babel body too long: {len(body)}"
    return bytes([0x2A, 0x02]) + struct.pack(">H", len(body)) + body


def parse_prefix_hex(s: str) -> bytes:
    """Parse a hex string like 'fd000286011e0006' into raw bytes."""
    s = s.replace(":", "").replace(" ", "")
    if len(s) % 2 != 0:
        raise SystemExit(f"prefix hex must have even length: {s!r}")
    return bytes.fromhex(s)


def parse_rid_hex(s: str) -> bytes:
    """Parse an 8-byte router-id hex string like '00000000ac170a61'."""
    b = parse_prefix_hex(s)
    if len(b) != 8:
        raise SystemExit(f"router-id must be 8 bytes (16 hex chars), got {len(b)}")
    return b


def cmd_teach(args: list[str]) -> bytes:
    """teach <rid-hex> <ae> <plen> <prefix-hex> <seqno> <metric>

    The peer's address for the IHU/NextHop is the all-zeros address of
    the AE family — the daemon's reception code resolves a 0.0.0.0 / ::
    next hop to the datagram sender (RFC 8966 §3.5.3), so the test
    does not need to know its own source address.
    """
    if len(args) != 6:
        raise SystemExit("teach needs: <rid-hex> <ae> <plen> <prefix-hex> <seqno> <metric>")
    rid = parse_rid_hex(args[0])
    ae = int(args[1])
    plen = int(args[2])
    prefix = parse_prefix_hex(args[3])
    seqno = int(args[4])
    metric = int(args[5])
    # The IHU/NextHop address length depends on AE.
    if ae in (1, 4):
        addr = b"\x00\x00\x00\x00"  # 0.0.0.0
        ihu_ae = 1
    else:
        addr = b"\x00" * 16  # ::
        ihu_ae = 2
    return frame([
        hello(1, 100),                      # 1 s Hello interval
        ihu(ihu_ae, 96, 300, addr),         # rxcost 96, 3 s IHU
        router_id(rid),
        next_hop(ae, addr),
        update(ae, 0, plen, 0, 300, seqno, metric, prefix),
    ])


def cmd_retract_wildcard(args: list[str]) -> bytes:
    """retract-wildcard — AE 0, metric 0xFFFF (RFC 8966 §4.6.9)."""
    if args:
        raise SystemExit("retract-wildcard takes no arguments")
    return frame([
        update(0, 0, 0, 0, 0, 0, 0xFFFF, b""),
    ])


def cmd_retract_prefix(args: list[str]) -> bytes:
    """retract-prefix <ae> <plen> <prefix-hex> — per-prefix retraction."""
    if len(args) != 3:
        raise SystemExit("retract-prefix needs: <ae> <plen> <prefix-hex>")
    ae = int(args[0])
    plen = int(args[1])
    prefix = parse_prefix_hex(args[2])
    return frame([
        update(ae, 0, plen, 0, 0, 0, 0xFFFF, prefix),
    ])


COMMANDS = {
    "teach": cmd_teach,
    "retract-wildcard": cmd_retract_wildcard,
    "retract-prefix": cmd_retract_prefix,
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__, file=sys.stderr)
        return 2
    cmd = sys.argv[1]
    body = COMMANDS[cmd](sys.argv[2:])
    # Write raw bytes to stdout.
    sys.stdout.buffer.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
