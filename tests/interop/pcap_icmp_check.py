#!/usr/bin/env python3
"""ICMP echo-request audit of a pcap produced by pcap_sniff.py icmp mode.

Reads one or more classic-pcap files (linktype 1, Ethernet) and prints
one line per ICMP/ICMPv6 echo REQUEST in the compact form

    <src> -> <dst> id=<n> seq=<n> (v4|v6)

The transit interop tests use it to prove a packet was really FORWARDED
through a transit router: the same echo request (identical id/seq)
must appear on the transit's ingress capture AND its egress capture —
a reply proving reachability does not distinguish "relayed by r2" from
"answered by r2", the two captures do.

Usage: pcap_icmp_check.py <capture.pcap> [...]
Exit status 0 when at least one echo request was found, 1 otherwise.
"""
import struct
import sys

IPPROTO_ICMP = 1
IPPROTO_ICMPV6 = 58
_V6_EXT = {0, 43, 44, 51, 60}


def _iter_frames(path):
    """Yield Ethernet frames from a classic pcap file."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":  # little-endian
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":  # big-endian
        endian = ">"
    else:
        return
    off = 24
    while off + 16 <= len(data):
        _sec, _usec, incl, _orig = struct.unpack(endian + "IIII", data[off : off + 16])
        off += 16
        if off + incl > len(data):
            break
        yield data[off : off + incl]
        off += incl


def _v4_str(b):
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


def _v6_str(b):
    groups = [f"{(b[i] << 8) | b[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(groups)


def _echo_request(frame):
    """(src, dst, id, seq, family) when the frame is an ICMP echo request."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack(">H", frame[12:14])[0]
    if ethertype == 0x0800:  # IPv4
        ip = frame[14:]
        if len(ip) < 24 or (ip[0] >> 4) != 4 or ip[9] != IPPROTO_ICMP:
            return None
        src, dst = _v4_str(ip[12:16]), _v4_str(ip[16:20])
        icmp = ip[(ip[0] & 0xF) * 4 :]
        if len(icmp) < 8 or icmp[0] != 8:  # echo request
            return None
        echo_id, seq = struct.unpack(">HH", icmp[4:8])
        return src, dst, echo_id, seq, "v4"
    if ethertype == 0x86DD:  # IPv6
        ip = frame[14:]
        if len(ip) < 48 or (ip[0] >> 4) != 6 or ip[6] != IPPROTO_ICMPV6:
            return None
        src, dst = _v6_str(ip[8:24]), _v6_str(ip[24:40])
        nh, off = ip[6], 40
        while nh in _V6_EXT:
            if off + 2 > len(ip):
                return None
            nh = ip[off]
            hlen = 8 if nh in (44, 0, 43, 60) else (ip[off + 1] + 2) * 4
            off += hlen
        icmp = ip[off:]
        if len(icmp) < 8 or icmp[0] != 128:  # echo request
            return None
        echo_id, seq = struct.unpack(">HH", icmp[4:8])
        return src, dst, echo_id, seq, "v6"
    return None


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    found = 0
    for path in sys.argv[1:]:
        for frame in _iter_frames(path):
            req = _echo_request(frame)
            if req is None:
                continue
            src, dst, echo_id, seq, fam = req
            print(f"{path}: {src} -> {dst} id={echo_id} seq={seq} ({fam})")
            found += 1
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
