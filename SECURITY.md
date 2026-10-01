# Security policy

## Supported versions

librouting is pre-1.0. Security fixes land on `main` and are published in
whatever pre-release tag comes next; there is no maintenance branch for
older releases. If you run an older build, move to the latest tag.

The workspace version is `[workspace.package] version` in
[`Cargo.toml`](Cargo.toml) — check that file for what "latest" means
today.

After 1.0 the policy becomes: the latest minor release is supported, and
older minors are not.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Mail **<security@tes286.top>** with:

1. What the issue is and what impact you observed.
2. A minimal reproducer: configuration, commands, and observed versus
   expected behaviour. For a live protocol session a packet capture
   (`tcpdump -w`) is ideal.
3. The affected version — the output of `lr version`, or the `Cargo.toml`
   revision you depend on.
4. Anything you already tried as a mitigation.

You should get an acknowledgement within 72 hours. If you do not, open a
public issue that discloses nothing about the vulnerability — just that
the mailbox has not acknowledged a report — so the maintainers see it.

## Coordinated disclosure

A 90-day embargo, modelled on the Linux kernel's policy:

| Day | What happens |
| --- | --- |
| 0 | You report privately; we acknowledge within 72 hours. |
| 0–14 | We reproduce, triage and assign a severity. |
| 14–30 | We develop and privately verify a fix. |
| 30 | If the fix is ready we coordinate a release with you. If it needs longer we negotiate an extension. |
| 90 | Public disclosure with credit, or earlier if the fix has shipped. |

You are free to publish after day 90 regardless. We credit you in the
release notes and the [`CHANGELOG.md`](CHANGELOG.md) entry unless you ask
to stay anonymous.

## Threat model

librouting parses untrusted network bytes from BGP, OSPF, Babel, LDP,
BFD, BMP and MRT peers. Every wire codec is expected to be panic-free
against arbitrary input: that is what the cargo-fuzz targets in
`fuzz/fuzz_targets/` and the nightly job that runs them exist to verify,
and why the CI matrix runs `cargo miri` over the FFI crate.

The daemon runs as an ordinary user process. BGP, Babel, BFD, BMP and MRT
need no privileges. OSPFv2/v3 raw sockets and the kernel-gated SRv6 and
MPLS features do, and those are better run under a dedicated user with
`CAP_NET_RAW` than as root.

## Out of scope

- **Dependencies.** Report those upstream. We run `cargo audit` and
  `cargo deny check` nightly
  ([`.github/workflows/nightly.yml`](.github/workflows/nightly.yml)) and
  bump the affected dependency once a patched version exists.
- **Operator misconfiguration.** Peering with an untrusted router without
  an import filter is a self-inflicted denial of service.
  [`docs/RUNBOOK.md`](docs/RUNBOOK.md) covers the hardening we recommend.
- **Other implementations.** Issues in BIRD, FRR or any other daemon we
  interoperate with belong to their projects.

## Encryption

Plain mail is the canonical channel. If you need end-to-end encryption,
say so in your first message and we will arrange a key exchange
out-of-band.
