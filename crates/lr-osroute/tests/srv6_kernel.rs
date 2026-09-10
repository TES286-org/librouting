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
//! - Skips when run as a non-root user without `CAP_NET_ADMIN` (the
//!   route-install syscall needs it).
//!
//! Run locally with: `sudo sysctl -w net.ipv6.conf.all.seg6_enabled=1
//! && cargo test --test srv6_kernel -- --ignored --nocapture`.

#![cfg(target_os = "linux")]

use std::process::Command;

use lr_core::addr::Prefix;
use lr_osroute::seg6_route::{seg6_enabled, Seg6EncapMode, Seg6LocalRoute, Seg6Netlink, Seg6Route};
use lr_srv6::{Behavior, Sid, Srh};
use std::str::FromStr;

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

fn have_net_admin() -> bool {
    // `ip netns add` requires CAP_NET_ADMIN — if it fails, we don't
    // have the privilege to install routes either.
    Command::new("ip")
        .args(["netns", "list"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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

#[test]
#[ignore = "kernel-gated: requires seg6_enabled=1 + CAP_NET_ADMIN"]
fn seg6_route_installs_into_kernel_main_table() {
    if !seg6_enabled() {
        eprintln!("SKIP: net.ipv6.conf.all.seg6_enabled is not 1");
        return;
    }
    if !iproute2_has_seg6() {
        eprintln!(
            "SKIP: iproute2 lacks seg6 support (need Linux 4.10+ with CONFIG_IPV6_SEG6_LWTUNNEL)"
        );
        return;
    }
    if !have_net_admin() {
        eprintln!("SKIP: no CAP_NET_ADMIN (run as root)");
        return;
    }

    let mut nl = match Seg6Netlink::connect() {
        Ok(nl) => nl,
        Err(e) => {
            eprintln!("SKIP: Seg6Netlink::connect failed: {}", e);
            return;
        }
    };

    // Build a seg6 encap route: 2001:db8:1::/48 → push SRH with two
    // segments. The SIDs are in the IANA IPv6 documentation prefix
    // (RFC 3849) so they don't accidentally route real traffic.
    let sid1 = Sid::from_str("2001:db8:dead:beef::1").unwrap();
    let sid2 = Sid::from_str("2001:db8:dead:beef::2").unwrap();
    let srh = Srh::new(vec![sid1, sid2])
        .unwrap()
        .with_next_header(59) // No Next Header
        .with_tag(0xa1b2);
    let prefix: Prefix = "2001:db8:1::/48".parse().unwrap();
    let route = Seg6Route::new(prefix, srh).with_mode(Seg6EncapMode::Encap);

    let res = nl.add_seg6_route(&route);
    if let Err(e) = &res {
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
#[ignore = "kernel-gated: requires seg6_enabled=1 + CAP_NET_ADMIN"]
fn seg6local_route_installs_into_kernel_local_table() {
    if !seg6_enabled() {
        eprintln!("SKIP: net.ipv6.conf.all.seg6_enabled is not 1");
        return;
    }
    if !iproute2_has_seg6() {
        eprintln!("SKIP: iproute2 lacks seg6 support");
        return;
    }
    if !have_net_admin() {
        eprintln!("SKIP: no CAP_NET_ADMIN (run as root)");
        return;
    }

    let mut nl = match Seg6Netlink::connect() {
        Ok(nl) => nl,
        Err(e) => {
            eprintln!("SKIP: Seg6Netlink::connect failed: {}", e);
            return;
        }
    };

    // Build a seg6local End route: a SID whose behavior is plain
    // `End` (RFC 8986 §4.1 — the simplest endpoint, no parameters
    // required).
    let sid = Sid::from_str("2001:db8:dead:beef::abcd").unwrap();
    let route = Seg6LocalRoute::new(sid, Behavior::End);

    let res = nl.add_seg6local_route(&route);
    if let Err(e) = &res {
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
