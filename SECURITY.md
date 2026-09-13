# Security Policy

## Supported versions

librouting is pre-1.0 (currently `1.0.0-rc.3`). Security fixes are
backported only to the latest `-rc` line on `main`; there is no
separate release branch until 1.0 ships. Once 1.0 lands, the policy
becomes:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | yes — latest minor |
| 0.x     | no — pre-release   |

If you are running an older `-rc`, upgrade to `main` for security
fixes; the API is frozen for the rc line, so upgrades are
low-friction.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Send mail to **security@tes286.top** with:

1. A description of the issue and the impact you have observed.
2. A minimal reproducer (config + commands + observed vs. expected
   behaviour). If the reproducer involves a live protocol session, a
   packet capture (`tcpdump -w`) is ideal.
3. The affected version (output of `lr --version` or the
   `Cargo.toml` revision you depend on).
4. Any mitigations you have already tried.

You should receive an acknowledgement within **72 hours**. If you do
not, ping the maintainers through a public GitHub issue that does
*not* disclose the vulnerability itself — just "the
security@ mailbox has not acknowledged report X submitted on
YYYY-MM-DD".

## Coordinated disclosure

We follow a **90-day embargo** modelled on the Linux kernel's
policy:

* Day 0 — you report privately. We acknowledge within 72 hours.
* Day 0–14 — we reproduce, triage, and assign a severity
  (low / medium / high / critical).
* Day 14–30 — we develop and privately verify a fix.
* Day 30 — if a fix is ready, we coordinate a release with you. If
  the fix needs longer, we negotiate an extension; you are free to
  publish details after day 90 regardless.
* Day 90 — public disclosure with credit (or earlier if a fix has
  shipped).

We will credit you in the release notes and the
[`CHANGELOG.md`](CHANGELOG.md) entry unless you ask to remain
anonymous.

## Threat model

librouting parses untrusted network bytes from BGP, OSPF, Babel,
LDP, BFD, BMP and MRT peers. By design, every wire codec must be
panic-free against arbitrary input — this is what the fuzzing
targets in [`docs/ROADMAP-v3.md`](docs/ROADMAP-v3.md) D6 are designed
to verify, and why the CI matrix runs `cargo miri` on the FFI
crate.

The daemon runs as a regular user process. It does not require
`CAP_NET_ADMIN` for BGP / Babel / BFD / BMP / MRT; OSPFv2/v3 raw
sockets and SRv6 / MPLS kernel-gated features do require elevated
privileges, and we recommend running those under a dedicated user
with `CAP_NET_RAW` only rather than as root.

## What is not in scope

* Vulnerabilities in dependencies — report those upstream. We run
  `cargo audit` and `cargo deny check` nightly
  ([`.github/workflows/nightly.yml`](.github/workflows/nightly.yml))
  and will bump the affected dependency as soon as a patched version
  is available.
* Self-DoS scenarios where an operator misconfigures the daemon
  (e.g. peering with an untrusted router without an import filter).
  The [`RUNBOOK.md`](docs/RUNBOOK.md) covers the recommended
  hardening.
* Issues in BIRD, FRR, or any other reference implementation we
  interoperate with.

## PGP

A PGP key for encrypting vulnerability reports will be published
here once 1.0 ships. For the rc line, plain-text mail to
security@tes286.top is the canonical channel; if you need end-to-end
encryption, ask in your initial report and we will arrange a
key exchange out-of-band.
