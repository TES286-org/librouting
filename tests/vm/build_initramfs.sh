#!/usr/bin/env bash
# Build a minimal initramfs that runs the kernel-gated interop tests
# (tcp_ao.sh, mpls_lsp.sh, ldp.sh) inside a QEMU VM as real root.
#
# See tests/vm/README.md for the full story: which kernel features the
# guest needs (TCP-AO >= 6.7, AF_MPLS, veth, user namespaces) and where
# to get a suitable kernel image + module tree.
#
# Env:
#   LR_VM_KERNEL   directory containing boot/vmlinuz-* and
#                  lib/modules/<KVER>/ (kernel image + module tree).
#                  On Debian/Ubuntu this is what `dpkg-deb -x` of
#                  linux-image-*, linux-modules-* and
#                  linux-modules-extra-* produces.
#   LR_VM_OUT      where to write the initramfs (default: /tmp)
#   LR_VM_PROFILE  lr-daemon build profile: debug (default) | release
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LR_VM_KERNEL=${LR_VM_KERNEL:?set LR_VM_KERNEL to the extracted kernel deb tree}
LR_VM_OUT=${LR_VM_OUT:-/tmp}
LR_VM_PROFILE=${LR_VM_PROFILE:-debug}

# locate kernel image + modules; prefer the running kernel's version
# when present (e.g. LR_VM_KERNEL=/ on a CI runner), else first entries
KVER=$(uname -r)
[ -d "$LR_VM_KERNEL/lib/modules/$KVER" ] || KVER=$(ls "$LR_VM_KERNEL/lib/modules" | head -1)
VMKERNEL="/boot/vmlinuz-$KVER"
[ -f "$VMKERNEL" ] || VMKERNEL=$(ls "$LR_VM_KERNEL"/boot/vmlinuz-* | head -1)
KMOD="$LR_VM_KERNEL/lib/modules/$KVER"
echo "== kernel: $VMKERNEL (modules: $KVER) =="

RFS=$(mktemp -d /tmp/lr-vm-rootfs.XXXXXX)
trap 'rm -rf "$RFS"' EXIT

# --- skeleton: real directories only (no symlinks; some build
#     sandboxes forbid creating them and they are not needed) ---
mkdir -p "$RFS"/{bin,sbin,usr/bin,usr/sbin,lib/x86_64-linux-gnu,lib64,proc,sys,dev,run,tmp,etc,work/librouting}

copy_bin() {  # copy the real binary behind `command -v`
    local b
    b=$(command -v "$1") || { echo "MISSING BINARY: $1" >&2; exit 1; }
    if [ "$b" = "$1" ]; then
        # shell builtin — fall back to the real coreutils binary
        b="/usr/bin/$1"
        [ -f "$b" ] || { echo "NO REAL BINARY: $1" >&2; exit 1; }
    fi
    cp -L "$b" "$RFS/usr/bin/$1"
}

# --- core userland ---
for b in bash sh ls cat grep sed awk cut tr sort uniq wc head tail \
         rm rmdir mkdir sleep chmod ln date basename dirname tee touch \
         id mount umount uname ps ip ping unshare nsenter sysctl \
         hostname mktemp cp mv sync od dd env stat readlink seq find \
         xargs true false; do
    copy_bin "$b"
done
# bash builtins cover echo/printf/test/kill; the real binaries are
# copied where they exist so `unshare ... true` style execs work.
# /init's `#!/bin/bash` shebang needs the interpreter at the literal
# path (bin/ is a real directory here, not a usr/bin symlink):
cp -L /bin/bash "$RFS/bin/bash"
cp -L /bin/sh "$RFS/bin/sh"

# --- modprobe + depmod (kmod); KMOD_BIN points at a kmod extract
#     (e.g. from `dpkg-deb -x kmod_*.deb`) when the host lacks kmod ---
KMOD_BIN=${KMOD_BIN:-}
for tool in modprobe depmod; do
    if command -v "$tool" >/dev/null 2>&1; then
        cp -L "$(command -v "$tool")" "$RFS/usr/sbin/$tool"
    elif [ -n "$KMOD_BIN" ] && [ -x "$KMOD_BIN/usr/sbin/$tool" ]; then
        cp -L "$KMOD_BIN/usr/sbin/$tool" "$RFS/usr/sbin/$tool"
    else
        echo "note: host lacks $tool (set KMOD_BIN to a kmod extract)" >&2
        exit 1
    fi
done

# --- dynamic loader: PT_INTERP is /lib64/ld-linux-x86-64.so.2 ---
cp -L /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$RFS/lib64/"
# shared-library closure for every copied ELF
for elf in "$RFS"/usr/bin/* "$RFS"/usr/sbin/*; do
    [ -f "$elf" ] || continue
    ldd "$elf" 2>/dev/null | awk '/=> \//{print $3} /^\//{print $1}' |
    while read -r so; do
        tgt="$RFS/lib/x86_64-linux-gnu/$(basename "$so")"
        [ -f "$tgt" ] || cp -L "$so" "$tgt"
    done
done

# --- kernel modules (full tree incl. linux-modules-extra) ---
mkdir -p "$RFS/lib/modules"
cp -r "$KMOD" "$RFS/lib/modules/"
# regenerate the module index: distro module debs ship one, but merged
# trees (base + extra) and trimmed trees need a fresh depmod pass
depmod -b "$RFS" "$KVER" >/dev/null 2>&1 || \
    "$RFS/usr/sbin/depmod" -b "$RFS" "$KVER" >/dev/null 2>&1 || true
[ -s "$RFS/lib/modules/$KVER/modules.dep" ] || {
    echo "FATAL: modules.dep missing after depmod" >&2; exit 1;
}

# --- workload: lr-daemon + the three kernel-gated scripts, in the
#     repo layout the scripts expect (cd "$(dirname $0)"/../..) ---
BIN="target/$LR_VM_PROFILE/lr-daemon"
[ -x "$REPO/$BIN" ] || cargo build -p lr-cli --"$LR_VM_PROFILE"
mkdir -p "$RFS/work/librouting/target/$LR_VM_PROFILE" \
         "$RFS/work/librouting/tests/interop"
cp "$REPO/$BIN" "$RFS/work/librouting/target/$LR_VM_PROFILE/"
ldd "$REPO/$BIN" 2>/dev/null | awk '/=> \//{print $3} /^\//{print $1}' |
while read -r so; do
    tgt="$RFS/lib/x86_64-linux-gnu/$(basename "$so")"
    [ -f "$tgt" ] || cp -L "$so" "$tgt"
done
# Copy the shared library first (every new-style script sources it),
# then the scripts the VM runs. The VM runs as root, so the scripts'
# forwarding phases (lr_enable_forwarding + lr_verify_ping, the
# ip_forward-gated transit hop in bgp_transit.sh) actually execute —
# unlike the rootless unshare -Urn path where they SKIP.
cp "$REPO/tests/interop/_lib.sh" "$RFS/work/librouting/tests/interop/"
for s in tcp_ao.sh mpls_lsp.sh ldp.sh ospf.sh \
         bgp_kernel_install.sh bgp_transit.sh; do
    cp "$REPO/tests/interop/$s" "$RFS/work/librouting/tests/interop/"
done

# --- guest init ---
cat > "$RFS/init" <<'EOF'
#!/bin/bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LD_LIBRARY_PATH=/lib/x86_64-linux-gnu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
hostname lr-vm
# some distro kernels (Ubuntu 24.04+) gate unprivileged user namespaces
sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null || true
echo "=== init: rootfs up ==="
ip link set lo up
unshare -Urn true && echo "USERNS_OK" || echo "USERNS_FAIL rc=$?"
modprobe veth && echo "modprobe veth OK"
modprobe mpls_router && echo "modprobe mpls_router OK"
modprobe mpls_iptunnel && echo "modprobe mpls_iptunnel OK"
cd /work/librouting
rc_all=0
# ospf.sh + bgp_transit.sh run as root here — their forwarding phases
# (lr_verify_ping through an ip_forward transit router) actually
# execute, unlike the rootless CI where they SKIP.
for t in tcp_ao.sh mpls_lsp.sh ldp.sh ospf.sh \
         bgp_kernel_install.sh bgp_transit.sh; do
    bash tests/interop/$t; rc=$?
    echo "MARKER $t rc=$rc"
    [ $rc -ne 0 ] && rc_all=1
done
echo "MARKER_ALL rc=$rc_all"
echo ALLDONE
sync
echo o > /proc/sysrq-trigger 2>/dev/null || poweroff -f || true
sleep 5
echo o > /proc/sysrq-trigger 2>/dev/null || true
EOF
chmod +x "$RFS/init"

# --- pack ---
python3 "$(dirname "$0")/pack_cpio.py" "$RFS" "$LR_VM_OUT/lr-vm-initramfs.cpio"
gzip -1 -f "$LR_VM_OUT/lr-vm-initramfs.cpio"
echo "BUILD OK: $LR_VM_OUT/lr-vm-initramfs.cpio.gz"
echo "KERNEL: $VMKERNEL"
