#!/usr/bin/env python3
"""Recording TCP proxy for the wire-level parity harness (W5.3).

Sits between lr-daemon (client side) and a reference implementation
(upstream side), forwarding bytes transparently while recording every
BGP message per direction. The recording feeds `lr parity-replay`,
which replays the captured stream into an offline router and dumps the
resulting Loc-RIB as MRT; `lr mrt diff` then compares it against the
reference implementation's own dump. See tests/interop/parity.sh and
docs/ROADMAP.md (W5.3).

The proxy speaks no BGP: it reassembles messages from the byte streams
using the RFC 4271 framing (16-octet marker, 2-octet length) purely so
each recorded line is exactly one message — TCP coalescing must not
leak into the capture.

Usage:
    capture_proxy.py --listen 127.0.0.1:PORT --upstream 127.0.0.1:PORT \
        --capture FILE

Capture format: one JSON object per line,
    {"dir":"up","hex":"ffffffff..."}    client -> upstream (lr -> peer)
    {"dir":"down","hex":"ffffffff..."}  upstream -> client (peer -> lr)
"""

import argparse
import socket
import sys
import threading

MARKER = b"\xff" * 16


class Rec(object):
    """Append-only capture file writer (one line per BGP message)."""

    def __init__(self, path):
        self.lock = threading.Lock()
        self.f = open(path, "a", buffering=1)

    def record(self, direction, data):
        with self.lock:
            self.f.write('{"dir":"%s","hex":"%s"}\n' % (direction, data.hex()))
            self.f.flush()


def pump(src, dst, rec, direction):
    """Read bytes from src, split them into BGP messages, forward the
    bytes untouched to dst and record per-message lines."""
    buf = b""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
            buf += data
            # Reassemble complete messages: marker + len(2) + rest.
            while True:
                idx = buf.find(MARKER)
                if idx < 0:
                    # No marker: keep the last 15 bytes (a marker may
                    # straddle the read boundary), drop the garbage.
                    buf = buf[-15:]
                    break
                if idx > 0:
                    buf = buf[idx:]
                if len(buf) < 18:
                    break
                length = int.from_bytes(buf[16:18], "big")
                if length < 19 or length > 4096:
                    # Not a valid length after a marker byte pattern:
                    # drop the false marker and resync.
                    buf = buf[1:]
                    continue
                if len(buf) < length:
                    break
                rec.record(direction, buf[:length])
                buf = buf[length:]
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="client-facing addr:port")
    ap.add_argument("--upstream", required=True, help="reference addr:port")
    ap.add_argument("--capture", required=True, help="capture output file")
    args = ap.parse_args()

    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lhost, lport = args.listen.rsplit(":", 1)
    lst.bind((lhost, int(lport)))
    lst.listen(1)
    uhost, uport = args.upstream.rsplit(":", 1)

    print("capture-proxy: listening on %s, upstream %s, capture %s"
          % (args.listen, args.upstream, args.capture), flush=True)
    conn, _ = lst.accept()
    up = socket.create_connection((uhost, int(uport)))
    rec = Rec(args.capture)

    c2u = threading.Thread(target=pump, args=(conn, up, rec, "up"), daemon=True)
    u2c = threading.Thread(target=pump, args=(up, conn, rec, "down"), daemon=True)
    c2u.start()
    u2c.start()
    c2u.join()
    u2c.join(timeout=5)
    print("capture-proxy: connection closed", flush=True)


if __name__ == "__main__":
    sys.exit(main())
