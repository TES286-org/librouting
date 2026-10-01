# Kernel-gated interop tests in a QEMU VM

The interop scripts below need kernel features or privileges a host may not
provide. CI runs them in the QEMU VM described here; a workstation, container
or restricted sandbox without the right kernel, or without root, can do the
same. `bgp_kernel_install.sh` is not kernel-gated — it is in the VM list so
one boot covers the whole set.

| Script | Needs | Skip signal |
| --- | --- | --- |
| `tests/interop/tcp_ao.sh` | TCP-AO (`CONFIG_TCP_AO`) | `SKIP: kernel lacks TCP-AO` |
| `tests/interop/mpls_lsp.sh` phase 2 | `mpls_router`, `mpls_iptunnel`, `AF_MPLS` | `SKIP: phase 2 (dataplane)` |
| `tests/interop/ldp.sh` phase 3 | same as above | `SKIP: phase 3 (dataplane)` |
| `tests/interop/ospf.sh` phase 4 | `ip_forward` as real root | `SKIP: ip_forward not available` |
| `tests/interop/bgp_transit.sh` phase 4 | `ip_forward` as real root | `SKIP: ip_forward unavailable` |
| `tests/interop/bgp_kernel_install.sh` | none; not kernel-gated | missing tool or platform |

CI runners have these features, so the workflows run the tests natively. The
VM is the repeatable fallback: a minimal initramfs with no disk image and no
installation, where the scripts run as real root.

## What the harness does

`build_initramfs.sh` assembles a tiny rootfs with the guest userland (bash,
coreutils, iproute2, ping, kmod), the freshly built `lr-daemon` and the
scripts, then packs it with `pack_cpio.py` and gzips it.

`run_vm.sh` boots `qemu-system-x86_64` with `-kernel` / `-initrd` (no disk),
pipes the serial console into a log file, and waits for the guest's
`MARKER_ALL` line. It exits 0 only when every script passed inside the guest.

## Requirements

- `qemu-system-x86_64` on the host (`apt install qemu-system-x86`).
- A kernel image and module tree with TCP-AO and MPLS enabled. Extract the
  kernel packages into a directory and point `LR_VM_KERNEL` at it:

  ```sh
  mkdir -p /opt/lr-kernel
  dpkg-deb -x linux-image-*.deb /opt/lr-kernel/
  dpkg-deb -x linux-modules-*.deb /opt/lr-kernel/
  dpkg-deb -x linux-modules-extra-*.deb /opt/lr-kernel/
  ```

- The guest userland comes from the host (bash, coreutils, iproute2,
  iputils-ping, kmod, glibc); the harness copies the `ldd` closure.

## Usage

```sh
LR_VM_KERNEL=/opt/lr-kernel tests/vm/run_vm.sh
```

`run_vm.sh` calls `build_initramfs.sh`, then boots the initramfs at
`/tmp/lr-vm-initramfs.cpio.gz`, so leave `LR_VM_OUT` at its default.

- `build_initramfs.sh` takes `LR_VM_KERNEL` (required), `LR_VM_OUT` (default
  `/tmp`) and `LR_VM_PROFILE` (`debug` or `release`).
- `run_vm.sh` takes `LR_VM_KERNEL` (required), `LR_VM_QEMU`,
  `LR_VM_QEMU_EXTRA_ARGS`, `LR_VM_MEM` (default 1024), `LR_VM_SMP` (default
  2), `LR_VM_LOG` (default `/tmp/lr-vm-run.log`) and `LR_VM_TIMEOUT`
  (default 1800 seconds).

Each script prints `MARKER <script> rc=<n>` into the serial log.
