#!/usr/bin/env bash
# Boot the kernel-gated interop VM built by build_initramfs.sh and
# report the aggregate result.
#
# Env:
#   LR_VM_KERNEL  extracted kernel deb tree (see build_initramfs.sh)
#   LR_VM_QEMU    qemu binary (default: qemu-system-x86_64)
#   LR_VM_QEMU_EXTRA_ARGS  extra qemu flags, e.g. -L <data-dir> for
#                  custom qemu builds whose BIOS/data dir is not
#                  auto-detected
#   LR_VM_MEM     guest memory MiB (default 1024)
#   LR_VM_SMP     guest vCPUs (default 2)
#   LR_VM_LOG     serial console log (default /tmp/lr-vm-run.log)
#   LR_VM_TIMEOUT overall timeout seconds (default 1800)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LR_VM_KERNEL=${LR_VM_KERNEL:?set LR_VM_KERNEL to the extracted kernel deb tree}
LR_VM_QEMU=${LR_VM_QEMU:-qemu-system-x86_64}
LR_VM_MEM=${LR_VM_MEM:-1024}
LR_VM_SMP=${LR_VM_SMP:-2}
LR_VM_LOG=${LR_VM_LOG:-/tmp/lr-vm-run.log}
LR_VM_TIMEOUT=${LR_VM_TIMEOUT:-1800}
LR_VM_QEMU_EXTRA_ARGS=${LR_VM_QEMU_EXTRA_ARGS:-}

bash "$DIR/build_initramfs.sh"
KVER=$(uname -r)
[ -d "$LR_VM_KERNEL/lib/modules/$KVER" ] || KVER=$(ls "$LR_VM_KERNEL/lib/modules" | head -1)
VMKERNEL="/boot/vmlinuz-$KVER"
[ -f "$VMKERNEL" ] || VMKERNEL=$(ls "$LR_VM_KERNEL"/boot/vmlinuz-* | head -1)

rm -f "$LR_VM_LOG"
# -serial file: is unbuffered; stdio redirection loses output when the
# host reaps qemu before the guest finishes
"$LR_VM_QEMU" \
    -display none -monitor none \
    -serial file:"$LR_VM_LOG" \
    -no-reboot \
    -m "$LR_VM_MEM" -smp "$LR_VM_SMP" \
    -kernel "$VMKERNEL" \
    -initrd /tmp/lr-vm-initramfs.cpio.gz \
    -append "console=ttyS0 rdinit=/init panic=-1 loglevel=6" \
    $LR_VM_QEMU_EXTRA_ARGS \
    </dev/null &
QPID=$!
trap 'kill "$QPID" 2>/dev/null || true' EXIT

SECS=0
while kill -0 "$QPID" 2>/dev/null; do
    sleep 5
    SECS=$((SECS + 5))
    if [ "$SECS" -ge "$LR_VM_TIMEOUT" ]; then
        echo "TIMEOUT after ${LR_VM_TIMEOUT}s" >&2
        kill "$QPID" 2>/dev/null || true
        exit 124
    fi
done

echo "=== serial log tail ==="
tail -c 4000 "$LR_VM_LOG"
rc=1
if grep -q "^MARKER_ALL rc=0" "$LR_VM_LOG"; then
    rc=0
fi
echo "=== VM result: rc=$rc ==="
exit $rc
