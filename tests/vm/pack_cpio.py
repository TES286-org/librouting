#!/usr/bin/env python3
"""Minimal deterministic newc (SVR4, magic 070701) cpio writer.

Packs a directory tree into an uncompressed newc cpio archive — the
format the Linux kernel expects for an initramfs. Equivalent to
`find . | cpio -o -H newc`, with no cpio dependency and reproducible
ordering (sorted, depth-first). Used by tests/vm/build_initramfs.sh to
build the kernel-gated interop VM image.

Usage: pack_cpio.py <src_root> <out.cpio>
"""

import os
import sys

MAGIC = b"070701"
NUL = b"\0"
TRAILER = b"TRAILER!!!"


def pad_to(buf: bytes, align: int = 4) -> bytes:
    r = len(buf) % align
    return buf if r == 0 else buf + NUL * (align - r)


def entry(name: str, mode: int, uid=0, gid=0, nlink=1, mtime=0, data=b"",
          devmajor=0, devminor=0, rdevmajor=0, rdevminor=0,
          filesize=None, ino=[0]) -> bytes:
    """One newc header + name + data, 4-byte aligned throughout.

    namesize includes the trailing NUL (the kernel parser relies on it).
    """
    ino[0] = (ino[0] % 0x3FFFFFFF) + 1
    if filesize is None:
        filesize = len(data)
    names = name.encode()
    hdr = (
        MAGIC
        + b"%08X" % ino[0]
        + b"%08X" % mode
        + b"%08X" % uid
        + b"%08X" % gid
        + b"%08X" % nlink
        + b"%08X" % mtime
        + b"%08X" % filesize
        + b"%08X" % devmajor
        + b"%08X" % devminor
        + b"%08X" % rdevmajor
        + b"%08X" % rdevminor
        + b"%08X" % (len(names) + 1)
        + b"00000000"  # chksum: unused for the 070701 variant
    )
    out = hdr + names + NUL
    out = pad_to(out)
    out += data
    return pad_to(out)


def walk(root: str):
    """Yield (relname, lstat, data) in sorted depth-first order."""
    yield ".", None, None
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        rel = os.path.relpath(dirpath, root)
        for d in sorted(dirnames):
            p = os.path.join(dirpath, d)
            yield "./" + os.path.normpath(os.path.join(rel, d)), os.lstat(p), None
        for f in sorted(filenames):
            p = os.path.join(dirpath, f)
            st = os.lstat(p)
            data = b""
            if not os.path.islink(p):
                with open(p, "rb") as fh:
                    data = fh.read()
            yield "./" + os.path.normpath(os.path.join(rel, f)), st, data


def main() -> None:
    src, outp = sys.argv[1], sys.argv[2]
    out = bytearray()
    for name, st, data in walk(src):
        if st is None:
            out += entry(name, mode=0o040755)
            continue
        perm = st.st_mode & 0o7777
        ftype = st.st_mode & 0o170000
        if ftype == 0o120000:  # symlink: body is the target path
            target = os.readlink(os.path.join(src, name[2:])).encode()
            out += entry(name, mode=0o120000 | perm, filesize=len(target),
                         data=target)
        elif ftype == 0o040000:  # directory
            out += entry(name, mode=0o040000 | perm, nlink=2)
        else:  # regular file
            out += entry(name, mode=0o100000 | perm, data=data)
    out += entry("TRAILER!!!", mode=0)
    out += NUL * ((512 - len(out) % 512) % 512)
    with open(outp, "wb") as fh:
        fh.write(bytes(out))
    print(f"packed {len(out)} bytes -> {outp}")


if __name__ == "__main__":
    main()
