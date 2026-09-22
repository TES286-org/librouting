# Kernel-gated interop tests in a QEMU VM

Six interop scripts need kernel features or privileges the host may not
provide:

| Script | Kernel requirement | Skip signal |
|--------|--------------------|-------------|
| `tests/interop/tcp_ao.sh` | TCP-AO (`CONFIG_TCP_AO`), Linux >= 6.7 | `SKIP: kernel lacks TCP-AO` |
| `tests/interop/mpls_lsp.sh` phase 2 | `mpls_router` + `mpls_iptunnel` modules, `AF_MPLS` | `SKIP: phase 2 (dataplane)` |
| `tests/interop/ldp.sh` phase 3 | same as above | `SKIP: phase 3 (dataplane)` |
| `tests/interop/ospf.sh` phase 4 | `ip_forward` as real root | `SKIP: ip_forward not available` |
| `tests/interop/bgp_kernel_install.sh` | rootless-capable; full chain in the VM | (runs everywhere; VM adds nothing skipped) |
| `tests/interop/bgp_transit.sh` phase 4 | `ip_forward` as real root | `SKIP: ip_forward unavailable` |

On CI runners the Ubuntu images ship these (TCP-AO on 24.04's 6.8+
kernel, the MPLS modules via `modprobe` as root — the nightly workflow
installs `linux-modules-extra-$(uname -r)` first, because the azure
kernel's base module package does not contain `mpls_router`), so the
workflows run the tests natively. On a workstation, container, or
restricted sandbox without the right kernel or without root, this
directory provides a repeatable fallback: a minimal initramfs VM (no
disk image, no installation) where the tests run as real root against
a kernel that has everything enabled.

## What the harness does

1. `build_initramfs.sh` assembles a tiny rootfs with the guest
   userland (bash, coreutils, iproute2, ping, kmod), the freshly built
   `lr-daemon`, and the six scripts, then packs it with
   `pack_cpio.py` (a dependency-free newc cpio writer) and gzips it.
2. `run_vm.sh` boots `qemu-system-x86_64` with `-kernel` / `-initrd`
   (no disk), pipes the serial console into a log file, and waits for
   the guest's `MARKER_ALL` line. The exit code is 0 only when all
   six scripts passed inside the guest.

TCG (software emulation) is enough; the whole run takes a few minutes.
With `/dev/kvm` it is faster.

## Requirements

- `qemu-system-x86_64` on the host (`apt install qemu-system-x86`).
- A kernel image + module tree with TCP-AO and MPLS enabled. Any
  distro kernel >= 6.7 with `CONFIG_TCP_AO=y|m` works. Debian 13's
  6.12 kernel ships without TCP-AO (`# CONFIG_TCP_AO is not set`);
  Ubuntu 24.04's 6.8 kernel has it built in. Extract the kernel debs
  (`linux-image-*`, `linux-modules-*`, `linux-modules-extra-*`) into a
  directory and point `LR_VM_KERNEL` at it:

  ```sh
  mkdir -p /opt/lr-kernel
  dpkg-deb -x linux-image-6.8.0-139-generic_*.deb /opt/lr-kernel/
  dpkg-deb -x linux-modules-6.8.0-139-generic_*.deb /opt/lr-kernel/
  dpkg-deb -x linux-modules-extra-6.8.0-139-generic_*.deb /opt/lr-kernel/
  ```

- The guest userland binaries come from the host (bash, coreutils,
  iproute2, iputils-ping, kmod, glibc), so the host needs them
  installed; the harness copies the `ldd` closure automatically.

## Usage

```sh
LR_VM_KERNEL=/opt/lr-kernel tests/vm/run_vm.sh
```

Useful overrides: `LR_VM_PROFILE=release` (default `debug`),
`LR_VM_MEM`, `LR_VM_SMP`, `LR_VM_LOG`, `LR_VM_TIMEOUT`. The serial log
contains each script's full output plus the `MARKER <script> rc=<n>`
lines.
