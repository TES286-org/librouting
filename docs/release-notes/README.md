# Release note drafts

This directory holds the maintainer-filled release-note drafts for
each librouting release. The `release.yml` workflow creates a draft
GitHub Release on every `v*` tag push with auto-generated notes
(the "What's Changed" PR list) and the artifact / SBOM / signature
boilerplate body; the maintainer then fills in the per-release
narrative — the Breaking changes / New features / Fixes /
Compatibility sections — from the commit log and publishes the
release (`docs/RELEASE-PLAN.md` §3.2).

Each file here is the narrative section that goes between the
boilerplate and the "What's Changed" list, following the convention
the v1.1.0 and v1.1.1 releases established. A file is added in the
same PR that bumps the workspace version, so the draft is ready to
paste into the release body when the tag is cut.

The release history itself lives in
[`../CHANGELOG.md`](../CHANGELOG.md) — no other document carries a
release entry (`docs/RELEASE-PLAN.md` §3.3).
