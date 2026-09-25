#!/usr/bin/env python3
"""Portable Babel packet sniffer (AF_PACKET -> classic pcap).

tcpdump cannot run inside unprivileged user+net namespaces: its
mandatory privilege drop (``-Z``, explicit or the default) calls
initgroups(), which issues setgroups() — a syscall the kernel denies
in any user namespace whose /proc/<pid>/setgroups file reads "deny".
tcpdump dies with "Couldn't change to 'root' ... Operation not
permitted" before capturing a single packet.

Python's AF_PACKET raw socket needs only CAP_NET_RAW, which a fresh
user namespace grants its creator, so this sniffer works in exactly
the environment the interop tests run in (and under real root, where
it also sidesteps tcpdump's privsep entirely).

Usage: pcap_sniff.py <interface> <output.pcap> [udp_port|icmp] [duration_s]

- writes a classic pcap file (linktype 1, Ethernet) readable by
  babel_decode.py and every other pcap consumer
- filters in userspace: only UDP datagrams whose source or
  destination port equals ``udp_port`` (default 6696, Babel) are
  recorded, so the file stays small and to the point
- passing the literal ``icmp`` as the third argument records ICMP
  (v4 and v6) echo requests/replies instead — the forwarding-proof
  mode used by the transit interop tests (assert the echo request
  appears on the transit router's ingress AND egress interfaces)
- runs until SIGTERM/SIGINT, or — when ``duration_s`` is given —
  until that many seconds have elapsed
- packets are written unbuffered, so a capture killed mid-flight
  still leaves a valid, parseable pcap behind
"""
import errno
import signal
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
IPPROTO_UDP = 17

# IPv6 extension-header types whose payload is another header we can
# walk past to reach the transport header: hop-by-hop (0), routing
# (43), fragment (44), AH (51) and destination options (60).
_V6_EXT = {0, 43, 44, 51, 60}
IPPROTO_ICMP = 1
IPPROTO_ICMPV6 = 58


def _udp_ports(frame):
    """Return (sport, dport) when the frame carries UDP, else None."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack(">H", frame[12:14])[0]
    if ethertype == 0x0800:  # IPv4
        ip = frame[14:]
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            return None
        if ip[9] != IPPROTO_UDP:
            return None
        l4 = ip[(ip[0] & 0xF) * 4:]
    elif ethertype == 0x86DD:  # IPv6
        ip = frame[14:]
        if len(ip) < 40 or (ip[0] >> 4) != 6:
            return None
        nh = ip[6]
        off = 40
        while nh in _V6_EXT:
            if off + 2 > len(ip):
                return None
            nh = ip[off]
            if nh == 44:  # fragment header: fixed 8 octets
                hlen = 8
            elif nh == 51:  # AH: length in 4-octet units, + 8, - 2
                hlen = (ip[off + 1] + 2) * 4
            else:  # hop-by-hop / routing / dest-opts: 8-octet units
                hlen = (ip[off + 1] + 1) * 8
            off += hlen
        if nh != IPPROTO_UDP:
            return None
        l4 = ip[off:]
    else:
        return None
    if len(l4) < 4:
        return None
    return struct.unpack(">HH", l4[:4])


def _is_icmp(frame):
    """True when the frame carries an ICMP(v6) echo request or reply."""
    if len(frame) < 14:
        return False
    ethertype = struct.unpack(">H", frame[12:14])[0]
    if ethertype == 0x0800:  # IPv4
        ip = frame[14:]
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            return False
        return ip[9] in (IPPROTO_ICMP, IPPROTO_ICMPV6)
    if ethertype == 0x86DD:  # IPv6
        ip = frame[14:]
        if len(ip) < 40 or (ip[0] >> 4) != 6:
            return False
        return ip[6] in (IPPROTO_ICMP, IPPROTO_ICMPV6)
    return False


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    iface, out_path = sys.argv[1], sys.argv[2]
    flt = sys.argv[3] if len(sys.argv) > 3 else "6696"
    icmp_mode = flt == "icmp"
    port = None if icmp_mode else int(flt)
    duration = float(sys.argv[4]) if len(sys.argv) > 4 else None

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    # NOTE: the socket() protocol argument is passed to the syscall
    # verbatim and therefore needs htons(); the bind() tuple protocol
    # is converted to network order by CPython itself (it performs the
    # htons internally), so it must stay in HOST order. Passing
    # htons() here double-swaps the value and the socket goes deaf.
    s.bind((iface, ETH_P_ALL))
    # A short poll interval keeps SIGTERM handling responsive while
    # never missing packets (the kernel buffers between polls).
    s.settimeout(0.2)

    stop = False

    def on_signal(_sig, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    deadline = time.time() + duration if duration is not None else None
    # Classic pcap global header: magic, v2.4, thiszone 0, sigfigs 0,
    # snaplen 65535, linktype 1 (Ethernet).
    captured = 0
    with open(out_path, "wb", buffering=0) as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        while not stop:
            if deadline is not None and time.time() >= deadline:
                break
            try:
                frame, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                raise
            if icmp_mode:
                if not _is_icmp(frame):
                    continue
            else:
                ports = _udp_ports(frame)
                if ports is None:
                    continue
                if ports[0] != port and ports[1] != port:
                    continue
            now = time.time()
            sec, usec = int(now), int((now % 1) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
            captured += 1
    print(f"pcap_sniff: captured {captured} packet(s) on {iface}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
