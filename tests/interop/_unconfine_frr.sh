#!/usr/bin/env bash
# Unload the AppArmor profiles Ubuntu 26.04 ships for the FRR daemons.
#
# The `apparmor` 5.0 package on 26.04 carries enforcing profiles for
# /usr/lib/frr/{bgpd,babeld,ldpd,ospfd,ospf6d,staticd,...}. They
# allow only FRR's packaged paths (/run/frr, /var/tmp/frr), so a lab
# that starts a daemon unprivileged with its pid, log and vty socket
# under /tmp dies in pid_output() before the vty answers:
#
#   Can't create pid lock file /tmp/lr_md5_interop/p4/bgpd.pid (Permission denied)
#
# The confinement is distro packaging, not behaviour under test, so the
# interop CI jobs remove it before running the labs. Run as root:
#
#   sudo tests/interop/_unconfine_frr.sh
#
# A no-op when apparmor_parser is absent, AppArmor is disabled, or no
# FRR profile is installed (Ubuntu <= 24.04, containers and WSL).
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "_unconfine_frr.sh: must run as root" >&2
    exit 1
fi
if ! command -v apparmor_parser >/dev/null 2>&1; then
    echo "_unconfine_frr.sh: apparmor_parser not installed; nothing to do"
    exit 0
fi
# WSL and containers usually carry the parser but not an enabled LSM;
# there is nothing to unload there (and securityfs is absent, so the
# parser can only warn).
if [ -r /sys/module/apparmor/parameters/enabled ] &&
    [ "$(cat /sys/module/apparmor/parameters/enabled)" != "Y" ]; then
    echo "_unconfine_frr.sh: AppArmor is not enabled; nothing to do"
    exit 0
fi

removed=0
for profile in /etc/apparmor.d/*; do
    [ -f "$profile" ] || continue
    grep -q "/usr/lib/frr/" "$profile" || continue
    name=$(basename "$profile")
    # The disable symlink keeps the profile unloaded if apparmor.service
    # re-parses /etc/apparmor.d later in the job; -R drops it from the
    # running kernel now.
    mkdir -p /etc/apparmor.d/disable
    ln -sf "$profile" "/etc/apparmor.d/disable/$name"
    apparmor_parser -R "$profile" 2>/dev/null || true
    if [ -r /sys/kernel/security/apparmor/profiles ] &&
        grep -q "^$name " /sys/kernel/security/apparmor/profiles; then
        echo "_unconfine_frr.sh: $name is still loaded after removal" >&2
        exit 1
    fi
    echo "_unconfine_frr.sh: unloaded AppArmor profile $name"
    removed=$((removed + 1))
done

if [ "$removed" -eq 0 ]; then
    echo "_unconfine_frr.sh: no FRR AppArmor profiles installed; nothing to do"
fi
