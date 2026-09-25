//! SRv6 kernel interop — install real `seg6` / `seg6local` routes via
//! the new `lr-osroute::seg6_route` API and verify the kernel accepts
//! them with `ip -6 route show`.
//!
//! This is the SRv6 slice-1 acceptance gate (mirrors what
//! `tests/interop/mpls_lsp.sh` does for SR-MPLS): the codec's wire
//! bytes are accepted by a real Linux kernel's `seg6` lwtunnel parser.
//!
//! The test is **kernel-gated**:
//! - Skips when `seg6_enabled` is false (set
//!   `net.ipv6.conf.all.seg6_enabled=1` to enable).
//! - Skips when `iproute2` (`ip`) is not on PATH.
//! - Skips when run without `CAP_NET_ADMIN` (the route-install
//!   syscall returns EPERM). CI runners don't grant this by default;
//!   operators should run the test locally with `sudo` or inside a
//!   rootless netns (`unshare -Urn`).
//!
//! The wire format itself is pinned by 17 unit tests in
//! `crates/lr-osroute/src/seg6_route.rs` that run unconditionally in
//! `cargo test --workspace` — this integration test is *additional*
//! end-to-end verification against a real kernel, not the only check.
//!
//! Run locally with: `sudo sysctl -w net.ipv6.conf.all.seg6_enabled=1
//! && sudo cargo test --test srv6_kernel -- --ignored --nocapture`.

#![cfg(target_os = "linux")]

use std::process::Command;

use lr_core::addr::Prefix;
use lr_osroute::ospf_transport;
use lr_osroute::seg6_route::{seg6_enabled, Seg6EncapMode, Seg6LocalRoute, Seg6Netlink, Seg6Route};
use lr_srv6::{Behavior, Sid, Srh};
use std::str::FromStr;

/// The loopback interface's ifindex — the egress device every route
/// in this suite installs with. The kernel's `fib6_nh_init` rejects a
/// device-less, gateway-less IPv6 route with `ENODEV` (run 36136529031
/// failed exactly so), and inside the rootless netns the only interface
/// is `lo`. `if_nametoindex` is netns-aware, so the lookup resolves the
/// *current* namespace's loopback (index 1 in a fresh netns, but not
/// assumed). The device is also brought up when possible: newer kernels
/// additionally refuse a down egress device with `ENETDOWN`.
fn loopback_ifindex() -> u32 {
    // Best effort: newer kernels refuse an egress device that is
    // administratively down with ENETDOWN, and a fresh netns starts
    // with lo down. Bringing it up needs CAP_NET_ADMIN, which the
    // rootless user namespace grants; elsewhere the failure is
    // ignored and the install surfaces the real kernel errno.
    let _ = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status();
    ospf_transport::ifindex_of("lo").unwrap_or(1)
}

/// True when `ip -6 route` exists and accepts the `seg6`/`seg6local`
/// keywords (Linux 4.10+ with `CONFIG_IPV6_SEG6_LWTUNNEL`).
fn iproute2_has_seg6() -> bool {
    let out = Command::new("ip").args(["route", "help"]).output().ok();
    let Some(out) = out else {
        return false;
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{}\n{}", stdout, String::from_utf8_lossy(&out.stderr));
    combined.contains("seg6")
}

fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => String::new(),
    }
}

/// Parse and pretty-print the seg6 routes the kernel has installed.
/// Used for diagnostics.
fn show_seg6_routes() -> String {
    let mut s = String::new();
    s.push_str("=== seg6 routes (main table) ===\n");
    s.push_str(&ip(&["-6", "route", "show", "table", "main"]));
    s.push_str("=== seg6local routes (local table) ===\n");
    s.push_str(&ip(&["-6", "route", "show", "table", "local"]));
    s
}

/// Skip predicate: returns `Some(reason)` when the kernel cannot
/// accept SRv6 routes from this process. The reason is logged so a CI
/// operator can see why the test skipped.
fn kernel_unavailable() -> Option<&'static str> {
    if !seg6_enabled() {
        return Some("net.ipv6.conf.all.seg6_enabled is not 1");
    }
    if !iproute2_has_seg6() {
        return Some(
            "iproute2 lacks seg6 support (need Linux 4.10+ with CONFIG_IPV6_SEG6_LWTUNNEL)",
        );
    }
    None
}

/// True when the error is a privilege error (EPERM) — the kernel
/// accepted the wire format but rejected the install because the
/// process lacks CAP_NET_ADMIN. The test skips in that case rather
/// than failing: the wire format itself is already verified by the
/// unit tests in seg6_route.rs.
fn is_privilege_error(e: &lr_osroute::seg6_route::Seg6RouteError) -> bool {
    matches!(
        e,
        lr_osroute::seg6_route::Seg6RouteError::Kernel(s)
            if s.contains("EPERM") || s.contains("insufficient privileges")
    )
}

#[test]
#[ignore = "kernel-gated: requires seg6_enabled=1 + CAP_NET_ADMIN (run as root or in a rootless netns)"]
fn seg6_route_installs_into_kernel_main_table() {
    if let Some(reason) = kernel_unavailable() {
        eprintln!("SKIP: {}", reason);
        return;
    }

    let mut nl = match Seg6Netlink::connect() {
        Ok(nl) => nl,
        Err(e) => {
            if is_privilege_error(&e) {
                eprintln!("SKIP: Seg6Netlink::connect returned EPERM (run as root or in a rootless netns)");
                return;
            }
            panic!("Seg6Netlink::connect failed unexpectedly: {}", e);
        }
    };

    // Build a seg6 encap route: 2001:db8:1::/48 → push SRH with two
    // segments. The SIDs are in the IANA IPv6 documentation prefix
    // (RFC 3849) so they don't accidentally route real traffic. The
    // egress device is the namespace's loopback — mandatory, see
    // `loopback_ifindex`.
    let sid1 = Sid::from_str("2001:db8:dead:beef::1").unwrap();
    let sid2 = Sid::from_str("2001:db8:dead:beef::2").unwrap();
    let srh = Srh::new(vec![sid1, sid2])
        .unwrap()
        .with_next_header(59) // No Next Header
        .with_tag(0xa1b2);
    let prefix: Prefix = "2001:db8:1::/48".parse().unwrap();
    let route = Seg6Route::new(prefix, srh)
        .with_mode(Seg6EncapMode::Encap)
        .with_if_index(loopback_ifindex());

    let res = nl.add_seg6_route(&route);
    if let Err(e) = &res {
        if is_privilege_error(e) {
            eprintln!("SKIP: add_seg6_route returned EPERM (run as root or in a rootless netns)");
            return;
        }
        eprintln!("add_seg6_route failed: {}\n{}", e, show_seg6_routes());
    }
    // Always clean up, even on failure, so the test is idempotent.
    let _ = nl.delete_seg6_route(prefix);
    res.expect("seg6 encap route should install into the kernel");

    // Re-install and verify the kernel actually sees the route.
    nl.add_seg6_route(&route)
        .expect("re-install seg6 encap route");
    let main_table = ip(&["-6", "route", "show", "table", "main"]);
    assert!(
        main_table.contains("2001:db8:1::/48"),
        "seg6 route missing from main table:\n{}",
        main_table
    );
    assert!(
        main_table.contains("seg6"),
        "seg6 encap not displayed by `ip route`:\n{}",
        main_table
    );
    let _ = nl.delete_seg6_route(prefix);
}

#[test]
#[ignore = "kernel-gated: requires seg6_enabled=1 + CAP_NET_ADMIN (run as root or in a rootless netns)"]
fn seg6local_route_installs_into_kernel_local_table() {
    if let Some(reason) = kernel_unavailable() {
        eprintln!("SKIP: {}", reason);
        return;
    }

    let mut nl = match Seg6Netlink::connect() {
        Ok(nl) => nl,
        Err(e) => {
            if is_privilege_error(&e) {
                eprintln!("SKIP: Seg6Netlink::connect returned EPERM (run as root or in a rootless netns)");
                return;
            }
            panic!("Seg6Netlink::connect failed unexpectedly: {}", e);
        }
    };

    // Build a seg6local End route: a SID whose behavior is plain
    // `End` (RFC 8986 §4.1 — the simplest endpoint, no parameters
    // required). The route-level egress device is the namespace's
    // loopback — the kernel rejects a device-less IPv6 route with
    // ENODEV (this is distinct from the End.X action's own `oif`
    // parameter, which rides inside RTA_ENCAP).
    let sid = Sid::from_str("2001:db8:dead:beef::abcd").unwrap();
    let route = Seg6LocalRoute::new(sid, Behavior::End).with_if_index(loopback_ifindex());

    let res = nl.add_seg6local_route(&route);
    if let Err(e) = &res {
        if is_privilege_error(e) {
            eprintln!(
                "SKIP: add_seg6local_route returned EPERM (run as root or in a rootless netns)"
            );
            return;
        }
        eprintln!("add_seg6local_route failed: {}\n{}", e, show_seg6_routes());
    }
    let _ = nl.delete_seg6local_route(sid);
    res.expect("seg6local End route should install into the kernel");

    nl.add_seg6local_route(&route)
        .expect("re-install seg6local End route");
    let local_table = ip(&["-6", "route", "show", "table", "local"]);
    assert!(
        local_table.contains("2001:db8:dead:beef::abcd"),
        "seg6local SID missing from local table:\n{}",
        local_table
    );
    assert!(
        local_table.contains("seg6local"),
        "seg6local action not displayed by `ip route`:\n{}",
        local_table
    );
    let _ = nl.delete_seg6local_route(sid);
}
