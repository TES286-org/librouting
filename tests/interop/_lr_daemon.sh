#!/usr/bin/env bash
# Resolve the lr-daemon binary path for the current platform. On
# Windows the binary has a .exe suffix; on Unix it does not. Prints
# the path on stdout and exits 0 if found, or exits 1 with a
# diagnostic on stderr if no build is present.
#
# Call from the repo root (every interop script does `cd "$(dirname
# "$0")/../.."` before invoking this helper):
#
#   BIN=$(./tests/interop/_lr_daemon.sh)
#
# The helper checks the debug build first (faster to iterate on), then
# falls back to the release build. The Windows .exe form is checked
# alongside the Unix form so the same interop scripts run on
# windows-2022 GitHub Actions runners via Git Bash — no separate
# PowerShell port is needed.
set -euo pipefail

for bin in \
    target/debug/lr-daemon \
    target/debug/lr-daemon.exe \
    target/release/lr-daemon \
    target/release/lr-daemon.exe
do
    if [ -f "$bin" ]; then
        echo "$bin"
        exit 0
    fi
done

echo "lr-daemon binary not found in target/{debug,release}/" \
    "(run \`cargo build -p lr-cli\` first)" >&2
exit 1
