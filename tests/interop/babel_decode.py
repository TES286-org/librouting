#!/usr/bin/env python3
"""Decode Babel (RFC 8966) TLVs from a pcap of UDP port 6696 traffic.

Usage: babel_decode.py <pcap> [max-packets]
Prints one line per packet with sender -> receiver and the TLV list,
so announcement composition and ordering can be inspected directly.
"""
import sys
import struct

# Minimal pcap reader (little/big endian, Ethernet/IPv4/IPv6)
def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian = "<"  # nanosecond
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian = ">"
    else:
        raise SystemExit("not a pcap file")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype not in (1, 101):  # Ethernet or raw IP
        raise SystemExit(f"unsupported linktype {linktype}")
    off = 24
    pkts = []
    while off + 16 <= len(data):
        _, _, caplen, origlen = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + caplen]
        off += caplen
        pkts.append((linktype, pkt))
    return pkts


def parse_pkt(linktype, pkt):
    """Return (src, dst, udp_payload) or None."""
    if linktype == 1:
        if len(pkt) < 14:
            return None
        ethertype = struct.unpack(">H", pkt[12:14])[0]
        ip = pkt[14:]
    else:
        ethertype = struct.unpack(">H", pkt[:2])[0] if len(pkt) >= 2 else None
        ip = pkt[4:] if False else pkt
        # linktype 101 = raw IP with 4-byte pseudo header
        if linktype == 101:
            ethertype = None
            ip = pkt[4:]
    if ethertype == 0x0800:
        if len(ip) < 20:
            return None
        ihl = (ip[0] & 0xF) * 4
        proto = ip[9]
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        total = struct.unpack(">H", ip[2:4])[0]
        l4 = ip[ihl:total]
    elif ethertype == 0x86DD:
        if len(ip) < 40:
            return None
        proto = ip[6]
        src = ":".join(f"{ip[i]:02x}{ip[i+1]:02x}" for i in range(8, 24, 2))
        dst = ":".join(f"{ip[i]:02x}{ip[i+1]:02x}" for i in range(24, 40, 2))
        plen = struct.unpack(">H", ip[4:6])[0]
        l4 = ip[40:40 + plen]
    elif linktype == 101:
        v = ip[0] >> 4
        if v == 4:
            ihl = (ip[0] & 0xF) * 4
            proto = ip[9]
            src = ".".join(str(b) for b in ip[12:16])
            dst = ".".join(str(b) for b in ip[16:20])
            total = struct.unpack(">H", ip[2:4])[0]
            l4 = ip[ihl:total]
        elif v == 6:
            proto = ip[6]
            src = ":".join(f"{ip[i]:02x}{ip[i+1]:02x}" for i in range(8, 24, 2))
            dst = ":".join(f"{ip[i]:02x}{ip[i+1]:02x}" for i in range(24, 40, 2))
            plen = struct.unpack(">H", ip[4:6])[0]
            l4 = ip[40:40 + plen]
        else:
            return None
    else:
        return None
    if proto != 17:
        return None
    if len(l4) < 8:
        return None
    sport, dport, ulen, _csum = struct.unpack(">HHHH", l4[:8])
    payload = l4[8:ulen]
    return src, dst, sport, dport, payload


AE_NAMES = {0: "wild", 1: "v4", 2: "v6", 3: "v6ll", 4: "v4via6"}

TLV_NAMES = {
    0: "Pad1", 1: "PadN", 2: "AckReq", 3: "Ack", 4: "Hello", 5: "IHU",
    6: "RouterId", 7: "NextHop", 8: "Update", 9: "RouteReq", 10: "SeqnoReq",
    11: "MAC", 12: "PC", 13: "ChallengeReq", 14: "ChallengeReply",
}


def fmt_addr(ae, octets):
    if ae in (1, 4):
        # AE 4 (IPv4-via-IPv6, RFC 9229) carries an IPv4 prefix.
        return ".".join(str(b) for b in (octets + b"\x00" * 4)[:4])
    if ae == 2:
        b = (octets + b"\x00" * 16)[:16]
        return ":".join(f"{b[i]:02x}{b[i+1]:02x}" for i in range(0, 16, 2))
    if ae == 3:
        b = b"\xfe\x80" + (octets + b"\x00" * 8)[:8]
        return ":".join(f"{b[i]:02x}{b[i+1]:02x}" for i in range(0, 16, 2))
    return "?"


def decode_babel(payload):
    if len(payload) < 4:
        return None
    magic, version, blen = payload[0], payload[1], struct.unpack(">H", payload[2:4])[0]
    if magic != 0x2A or version != 2:
        return f"BAD magic={magic} version={version}"
    body = payload[4:4 + blen]
    out = []
    i = 0
    while i < len(body):
        t = body[i]
        if t == 0:
            out.append("Pad1")
            i += 1
            continue
        if i + 2 > len(body):
            out.append("TRUNC")
            break
        ln = body[i + 1]
        v = body[i + 2:i + 2 + ln]
        if t == 4:  # Hello
            flags, seq, iv = struct.unpack(">HHH", v[:6])
            out.append(f"Hello(seq={seq} iv={iv}cs flags={flags:#x})")
        elif t == 5:  # IHU
            ae = v[0]
            rxc, iv = struct.unpack(">HH", v[2:6])
            out.append(f"IHU(ae={AE_NAMES.get(ae, ae)} rxc={rxc} iv={iv}cs)")
        elif t == 6:  # RouterId
            rid = ":".join(f"{b:02x}" for b in v[2:10])
            out.append(f"RouterId({rid})")
        elif t == 7:  # NextHop
            ae = v[0]
            out.append(f"NextHop(ae={AE_NAMES.get(ae, ae)} {fmt_addr(ae, v[2:])})")
        elif t == 8:  # Update
            ae, flags, plen, omitted = v[0], v[1], v[2], v[3]
            iv, seq, metric = struct.unpack(">HHH", v[4:10])
            pfx = fmt_addr(ae, v[10:])
            name = TLV_NAMES.get(8, "8")
            fl = []
            if flags & 0x80:
                fl.append("DEF_PREFIX")
            if flags & 0x40:
                fl.append("ROUTER_ID")
            out.append(
                f"Update(ae={AE_NAMES.get(ae, ae)} {pfx}/{plen} seq={seq} "
                f"metric={metric} iv={iv}cs omit={omitted}"
                + (f" flags={'+'.join(fl)}" if fl else "") + ")"
            )
        elif t == 9:
            out.append(f"RouteReq(len={ln})")
        elif t == 10:
            ae = v[0]
            plen = v[2]
            seq, hop, rid_hi = struct.unpack(">HHI", v[4:12]) if ln >= 12 else (0, 0, 0)
            out.append(f"SeqnoReq(ae={AE_NAMES.get(ae, ae)} plen={plen} seq={seq} hopcnt={hop})")
        else:
            out.append(f"{TLV_NAMES.get(t, f'TLV{t}')}(len={ln})")
        i += 2 + ln
    return " | ".join(out)


def main():
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    pkts = read_pcap(path)
    n = 0
    for linktype, pkt in pkts:
        r = parse_pkt(linktype, pkt)
        if not r:
            continue
        src, dst, sport, dport, payload = r
        if dport != 6696 and sport != 6696:
            continue
        decoded = decode_babel(payload)
        if decoded is None:
            continue
        print(f"{src}:{sport} -> {dst}:{dport}  {decoded}")
        n += 1
        if n >= limit:
            break


if __name__ == "__main__":
    main()
