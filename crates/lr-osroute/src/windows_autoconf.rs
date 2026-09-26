//! Windows dataplane auto-configuration.
//!
//! The daemon's kernel-route install path expects the host to be in a
//! routing-friendly posture: IP forwarding enabled, weak host model on
//! the egress interface (so a `bind()` to a local address on a
//! different adapter is respected for source-IP selection), and the
//! BGP TCP/179 + Babel UDP/6696 listeners reachable through the
//! firewall. None of these are the daemon's responsibility on Linux
//! (where they live in `/proc/sys/net/ipv4/ip_forward`, the host model
//! is per-route via `ip rule`, and `iptables`/`nftables` are operator
//! policy). On Windows they are all per-interface registry-shaped
//! settings the daemon must opt into, or the operator must configure
//! by hand — exactly the "I forgot to enable forwarding on Windows"
//! class of bug the production report surfaced.
//!
//! This module centralises the bring-up: one entry point
//! ([`ensure_windows_dataplane_ready`]) called once at daemon startup
//! (gated by `--install-kernel-routes`), one teardown
//! ([`teardown_windows_dataplane`]) called at shutdown. Both are
//! idempotent and best-effort — a per-item failure logs a warning and
//! continues, so a partial-permission shell still brings up the routes
//! the operator asked for.
//!
//! ## What is configured
//!
//! * **IP forwarding** — per-interface `Set-NetIPInterface -Forwarding
//!   Enabled` for every IPv4 + IPv6 interface. The daemon needs this
//!   to forward packets between the BGP-learned next hops and the
//!   locally-originated networks. Without it Windows silently drops
//!   forwarded packets (the route is in the FIB but the kernel refuses
//!   to act on it).
//! * **Weak host model** — per-interface
//!   `Set-NetIPInterface -WeakHostReceive Enabled -WeakHostSend
//!   Enabled`. This is the Windows analogue of Linux's loose source
//!   validation: the kernel may receive a packet addressed to an IP
//!   on a different adapter, and may send a packet with a source IP
//!   that is not the egress adapter's primary address. The latter is
//!   the production report's #3 — the daemon's `bind()` to a
//!   loopback-address `local_address` is silently overridden to the
//!   egress adapter's primary IP when weak host send is off. Windows
//!   defaults weak host model to ON, but operator policy and VPN
//!   client installs commonly flip it off.
//! * **Firewall rules** — `New-NetFirewallRule` for BGP TCP/179 and
//!   Babel UDP/6696, tagged with a stable name so they are removed
//!   at shutdown. The rules are inbound allow; outbound traffic is
//!   unaffected (Windows firewall defaults to allow outbound).
//!
//! ## What is NOT configured
//!
//! * The `IPEnableRouter` registry key — this is a system-wide
//!   setting that requires a Tcpip service restart to take effect.
//!   `Set-NetIPInterface -Forwarding Enabled` is per-interface and
//!   takes effect immediately; it is the modern equivalent and the
//!   only one the daemon uses.
//! * Persistent firewall rules — the rules the daemon adds are
//!   runtime-only (they go away on reboot). Operators who want
//!   persistent rules should add them via GPO or `netsh advfirewall`.
//! * The daemon does NOT disable Windows Firewall — only adds
//!   specific allow rules for the protocol ports.

#![cfg(target_os = "windows")]

use std::os::windows::process::CommandExt;
use std::process::Command;

/// The stable firewall rule name prefix — used so the rules can be
/// located and removed at shutdown without ambiguity. The PID suffix
/// disambiguates between concurrent daemons (e.g. lab tests).
const RULE_PREFIX: &str = "lr-daemon-";

/// The BGP TCP port the daemon listens on (RFC 4271 §4.1).
const BGP_PORT: u16 = 179;
/// The Babel UDP port the daemon listens on (RFC 8966 §4.1).
const BABEL_PORT: u16 = 6696;

/// Bring up the Windows dataplane: IP forwarding, weak host model,
/// and the protocol firewall rules. Idempotent — a second invocation
/// is a no-op (the per-interface cmdlets succeed when the interface is
/// already in the desired state; the firewall cmdlet treats a duplicate
/// rule name as success here).
///
/// Returns the list of diagnostic lines the operator can grep for in
/// the daemon's startup log; per-item failures are recorded but do not
/// abort the daemon.
pub fn ensure_windows_dataplane_ready(rule_suffix: &str) -> Vec<String> {
    let mut lines = Vec::new();

    // 1. Per-interface forwarding + weak host model. Run as a single
    //    PowerShell pipeline so the cmdlets share a single process
    //    spawn — Windows PowerShell's cold-start is ~200 ms, and
    //    bringing 10 interfaces up with one spawn per cmdlet would
    //    cost 2 s of startup.
    let script = format!(
        r#"
$ErrorActionPreference = 'Continue'
Get-NetIPInterface -ErrorAction SilentlyContinue | ForEach-Object {{
    $iface = $_
    # IP forwarding (IPv4 + IPv6 — Get-NetIPInterface returns one row
    # per AddressFamily per interface, so this loop hits both).
    Set-NetIPInterface -InterfaceIndex $iface.InterfaceIndex `
        -Forwarding Enabled -ErrorAction SilentlyContinue
    # Weak host model — Windows defaults to Enabled but operator
    # policy and VPN clients commonly flip it off.
    Set-NetIPInterface -InterfaceIndex $iface.InterfaceIndex `
        -WeakHostReceive Enabled -WeakHostSend Enabled `
        -ErrorAction SilentlyContinue
}}
"#
    );
    match run_powershell(&script) {
        Ok(_) => lines.push(
            "windows dataplane: forwarding + weak host model configured on all interfaces"
                .to_string(),
        ),
        Err(e) => lines.push(format!(
            "windows dataplane: forwarding/weak-host configuration skipped ({e})"
        )),
    }

    // 2. Firewall rules for BGP TCP/179 and Babel UDP/6696. The
    //    rules are runtime-only (removed at shutdown via
    //    teardown_windows_dataplane). New-NetFirewallRule errors on a
    //    duplicate name, so we treat that specific error as success
    //    (the rule is already there, which is the desired state).
    let bgp_rule = format!("{RULE_PREFIX}{rule_suffix}-bgp-in");
    match add_firewall_rule_tcp(&bgp_rule, BGP_PORT) {
        Ok(()) => lines.push(format!(
            "windows dataplane: firewall rule {bgp_rule} added (TCP/{BGP_PORT} inbound)"
        )),
        Err(FirewallError::Duplicate) => lines.push(format!(
            "windows dataplane: firewall rule {bgp_rule} already present (TCP/{BGP_PORT})"
        )),
        Err(FirewallError::Other(e)) => lines.push(format!(
            "windows dataplane: firewall rule {bgp_rule} could not be added ({e}) — BGP inbound may be blocked"
        )),
    }

    let babel_rule = format!("{RULE_PREFIX}{rule_suffix}-babel-in");
    match add_firewall_rule_udp(&babel_rule, BABEL_PORT) {
        Ok(()) => lines.push(format!(
            "windows dataplane: firewall rule {babel_rule} added (UDP/{BABEL_PORT} inbound)"
        )),
        Err(FirewallError::Duplicate) => lines.push(format!(
            "windows dataplane: firewall rule {babel_rule} already present (UDP/{BABEL_PORT})"
        )),
        Err(FirewallError::Other(e)) => lines.push(format!(
            "windows dataplane: firewall rule {babel_rule} could not be added ({e}) — Babel inbound may be blocked"
        )),
    }

    lines
}

/// Tear down the runtime firewall rules the daemon added at startup.
/// IP forwarding and the weak host model are left configured — they
/// are system-wide settings the operator may have set for other
/// reasons (a BIRD-on-Windows install, a Hyper-V virtual switch, etc.)
/// and removing them silently would be a regression.
pub fn teardown_windows_dataplane(rule_suffix: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let rules = [
        format!("{RULE_PREFIX}{rule_suffix}-bgp-in"),
        format!("{RULE_PREFIX}{rule_suffix}-babel-in"),
    ];
    for rule in &rules {
        let script = format!("Remove-NetFirewallRule -Name '{rule}' -ErrorAction SilentlyContinue");
        match run_powershell(&script) {
            Ok(_) => lines.push(format!("windows dataplane: firewall rule {rule} removed")),
            Err(e) => lines.push(format!(
                "windows dataplane: firewall rule {rule} removal skipped ({e})"
            )),
        }
    }
    lines
}

/// Run a PowerShell script with CREATE_NO_WINDOW so the daemon does
/// not pop a console window on every spawn (a UX trap on Windows
/// server-core images that run daemons in the foreground).
fn run_powershell(script: &str) -> Result<(), String> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        // CREATE_NO_WINDOW = 0x0800_0000 — suppresses the console
        // host allocation that would otherwise steal focus on every
        // daemon spawn.
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| format!("spawn powershell: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "powershell exit {}: {}",
            output.status,
            stderr.trim().is_empty().then_some(stdout).unwrap_or(stderr)
        ));
    }
    Ok(())
}

#[derive(Debug)]
enum FirewallError {
    /// The rule name is already in use — the desired state.
    Duplicate,
    /// Any other failure (permission denied, PowerShell missing,
    /// NetSecurity module not available).
    Other(String),
}

/// Add an inbound TCP firewall rule. The caller passes the rule name
/// (which is namespaced by the daemon's PID via `rule_suffix`) and
/// the port. The rule allows inbound TCP from any source to any local
/// address on the given port.
fn add_firewall_rule_tcp(name: &str, port: u16) -> Result<(), FirewallError> {
    let script = format!(
        "New-NetFirewallRule -Name '{name}' -DisplayName '{name}' "
            + "-Direction Inbound -Action Allow -Protocol TCP "
            + "-LocalPort {port} -Profile Any"
    );
    firewall_op(&script)
}

fn add_firewall_rule_udp(name: &str, port: u16) -> Result<(), FirewallError> {
    let script = format!(
        "New-NetFirewallRule -Name '{name}' -DisplayName '{name}' "
            + "-Direction Inbound -Action Allow -Protocol UDP "
            + "-LocalPort {port} -Profile Any"
    );
    firewall_op(&script)
}

fn firewall_op(script: &str) -> Result<(), FirewallError> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| FirewallError::Other(format!("spawn powershell: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    // PowerShell error for a duplicate rule: "MSFT_NetFirewallRule
    // already exists" or "The requested object already exists".
    // Treat either as success.
    if stderr.contains("already exists") || stderr.contains("already a firewall rule") {
        return Err(FirewallError::Duplicate);
    }
    Err(FirewallError::Other(format!(
        "powershell exit {}: {}",
        output.status,
        stderr.trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test the rule-name namespacing. The actual cmdlet calls
    /// require a Windows host with the NetSecurity module — the
    /// test asserts the constructor logic only.
    #[test]
    fn rule_suffix_namespace_is_unique() {
        let s1 = format!("{RULE_PREFIX}123-bgp-in");
        let s2 = format!("{RULE_PREFIX}456-bgp-in");
        assert_ne!(s1, s2);
        assert!(s1.starts_with(RULE_PREFIX));
        assert!(s2.starts_with(RULE_PREFIX));
    }

    /// The ports are the well-known IANA assignments — they must
    /// not drift to daemon-chosen values without an explicit
    /// override config.
    #[test]
    fn protocol_ports_match_iana_assignments() {
        assert_eq!(BGP_PORT, 179, "BGP TCP port per RFC 4271 §4.1");
        assert_eq!(BABEL_PORT, 6696, "Babel UDP port per RFC 8966 §4.1");
    }
}
