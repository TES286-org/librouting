//! Kernel-gated route-table backend tests (real netlink, main table).
//!
//! What is verified here cannot be checked by the mock-socket unit tests
//! in `linux.rs`: how the kernel's own matcher treats the requests lr
//! sends. The regression that motivated this file: `delete_route` sent
//! `rtm_type = RTN_UNICAST`, and the IPv4 fib delete matcher compares the
//! requested type against every candidate row — a delete naming unicast
//! never matched an installed `RTN_BLACKHOLE` row, failed with ESRCH, and
//! the blackhole stayed in the kernel after the operator removed the
//! static route (or shut the daemon down). Only v4 exhibited it: IPv6's
//! fib6 ignores the type on delete. The delete now sends the
//! `RTN_UNSPEC` wildcard, which is exactly what iproute2's plain
//! `ip route del PREFIX` relies on.
//!
//! The RFC 5549 case belongs here for the same reason: the IPv4 FIB
//! accepts an IPv6 next hop only when the gateway travels as `RTA_VIA`,
//! so an assertion on the attribute bytes cannot prove that the kernel
//! takes the route.
//!
//! - Skips when the process lacks `CAP_NET_ADMIN` (run as root or in a
//!   rootless netns: `unshare -Urn cargo test -p lr-osroute --test
//!   route_kernel -- --ignored --nocapture`).
//! - The wire format itself is pinned by the mock-socket unit tests in
//!   `linux.rs`; this file proves the kernel accepts and acts on it.

use lr_core::addr::{IpAddr, Prefix};
use lr_osroute::{OsRouteTable, RtNetlink};

/// Prefixes for this run (both families, one each; the netns under test
/// is disposable, but distinct-from-documentation ranges keep a
/// coincidental collision from silently passing the "absent" assert).
const V4: Prefix = Prefix::new_v4([198, 51, 100, 0], 24); // TEST-NET-2
const V6: Prefix = Prefix::new_v6(
    [0xfd, 0x00, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    64,
);
/// RFC 5549 case: an IPv4 destination reached through an IPv6 next hop.
/// TEST-NET-3 keeps it distinct from `V4`.
const V4_VIA_V6: Prefix = Prefix::new_v4([203, 0, 113, 0], 24);

fn table_has(t: &mut RtNetlink, prefix: Prefix) -> bool {
    t.list_routes()
        .map(|routes| routes.iter().any(|r| r.prefix == prefix))
        .unwrap_or(false)
}

fn next_hop_of(t: &mut RtNetlink, prefix: Prefix) -> Option<IpAddr> {
    t.list_routes()
        .ok()?
        .into_iter()
        .find(|r| r.prefix == prefix)?
        .next_hop
}

/// Bring the netns's loopback up — a fresh netns has it DOWN, and a
/// DOWN lo makes every `via 127.0.0.1` gateway
/// unreachable (the kernel answers ENETUNREACH, exactly as it would
/// for any gateway whose output interface is down). Returns false
/// when iproute2 is unavailable, in which case the unicast test
/// skips.
fn loopback_up() -> bool {
    match std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
    {
        Ok(st) => st.success(),
        Err(_) => false,
    }
}

/// Create a dummy link and return its ifindex — the IPv6 half of the
/// unicast round trip needs a real egress device: fib6 rejects a
/// host-scope loopback gateway (`via ::1`) on some kernels (Azure's
/// CI kernel answers EINVAL), and the production babel shape is a
/// link-local gateway over an explicit RTA_OIF anyway, so the test
/// mirrors that: `via fe80::42 dev dummy0`. Returns None (skip) when
/// the link cannot be created.
fn dummy_link() -> Option<u32> {
    dummy_link_named("dummy0")
}

/// Create a dummy link called `name` and return its ifindex.
fn dummy_link_named(name: &str) -> Option<u32> {
    if !ip_ok(&["link", "add", name, "type", "dummy"]) {
        return None;
    }
    let _ = ip_ok(&["link", "set", name, "up"]);
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show", name])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    // "2: dummy0: <...> ..." — the ifindex is before the colon.
    s.split(':')
        .next()
        .and_then(|idx| idx.trim().parse::<u32>().ok())
}

fn ip_ok(args: &[&str]) -> bool {
    std::process::Command::new("ip")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// True when the error is a privilege error — the process lacks
/// CAP_NET_ADMIN. Connect failures surface as io::Error text
/// ("Operation not permitted"), netlink ACK failures as negative errno
/// ("rtnetlink: error -1"). The test skips in either shape rather than
/// failing: the wire format itself is pinned by the mock-socket unit
/// tests in linux.rs.
fn is_privilege_error(e: &lr_osroute::OsRouteError) -> bool {
    let s = &e.0;
    if s.contains("EPERM")
        || s.contains("Operation not permitted")
        || s.contains("insufficient privileges")
    {
        return true;
    }
    // Match the errno at the end of the message, not as a substring: a
    // `contains("error -1")` test also matches `error -113`
    // (EHOSTUNREACH) and would skip a real failure.
    s.ends_with("os error 1") || s.ends_with("rtnetlink: error -1")
}

#[test]
#[ignore = "kernel-gated: requires CAP_NET_ADMIN (run as root or in a rootless netns)"]
fn blackhole_install_and_delete_round_trip() {
    let mut t = match RtNetlink::connect() {
        Ok(t) => t,
        Err(e) => {
            if is_privilege_error(&e) {
                eprintln!(
                    "SKIP: RtNetlink::connect returned EPERM (run as root or in a rootless netns)"
                );
                return;
            }
            panic!("RtNetlink::connect failed unexpectedly: {}", e);
        }
    };

    for prefix in [V4, V6] {
        // Clean slate: a leftover from a previous aborted run would make
        // the final "absent" assert pass for the wrong reason.
        let _ = t.delete_route(prefix);

        match t.add_blackhole_route(prefix) {
            Ok(()) => {}
            Err(e) => {
                if is_privilege_error(&e) {
                    eprintln!("SKIP: add_blackhole_route returned EPERM");
                    return;
                }
                panic!("add_blackhole_route({prefix}) failed: {}", e);
            }
        }
        assert!(
            table_has(&mut t, prefix),
            "blackhole {prefix} must be in the kernel after add_blackhole_route"
        );

        // The regression: this used to fail with ESRCH on IPv4 (the
        // delete named RTN_UNICAST, which never matches an
        // RTN_BLACKHOLE row) and the blackhole survived the delete.
        t.delete_route(prefix)
            .unwrap_or_else(|e| panic!("delete_route({prefix}) failed: {}", e));
        assert!(
            !table_has(&mut t, prefix),
            "blackhole {prefix} must be gone from the kernel after delete_route — \
             the RTN_UNICAST-shaped delete left it behind (ESRCH mismatch)"
        );

        // Idempotent delete: the kernel says ESRCH, lr says Ok.
        t.delete_route(prefix)
            .unwrap_or_else(|e| panic!("second delete_route({prefix}) must be idempotent: {}", e));
    }
}

#[test]
#[ignore = "kernel-gated: requires CAP_NET_ADMIN (run as root or in a rootless netns)"]
fn unicast_install_and_delete_round_trip() {
    if !loopback_up() {
        eprintln!("SKIP: cannot bring lo up (iproute2 missing)");
        return;
    }
    let Some(dummy) = dummy_link() else {
        eprintln!("SKIP: cannot create a dummy link for the v6 gateway");
        return;
    };
    let mut t = match RtNetlink::connect() {
        Ok(t) => t,
        Err(e) => {
            if is_privilege_error(&e) {
                eprintln!(
                    "SKIP: RtNetlink::connect returned EPERM (run as root or in a rootless netns)"
                );
                return;
            }
            panic!("RtNetlink::connect failed unexpectedly: {}", e);
        }
    };

    // v4: `via 127.0.0.1` — the kernel resolves the output interface
    // from the table. v6: the production babel shape — a link-local
    // gateway over an explicit RTA_OIF (fib6 requires the device for
    // non-resolvable gateways, and host-scope loopback gateways are
    // EINVAL on some kernels).
    for (prefix, gateway, oif) in [
        (V4, IpAddr::V4([127, 0, 0, 1]), 0),
        (
            V6,
            IpAddr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42]),
            dummy,
        ),
    ] {
        let _ = t.delete_route(prefix);
        match t.add_route_tagged(prefix, gateway, oif, lr_core::rib::Protocol::Babel) {
            Ok(()) => {}
            Err(e) => {
                if is_privilege_error(&e) {
                    eprintln!("SKIP: add_route_tagged returned EPERM");
                    return;
                }
                panic!("add_route_tagged({prefix}) failed: {}", e);
            }
        }
        assert!(
            table_has(&mut t, prefix),
            "unicast {prefix} must be in the kernel after add_route_tagged"
        );
        t.delete_route(prefix)
            .unwrap_or_else(|e| panic!("delete_route({prefix}) failed: {}", e));
        assert!(
            !table_has(&mut t, prefix),
            "unicast {prefix} must be gone from the kernel after delete_route"
        );
    }
}

/// RFC 5549: an IPv4 route whose next hop is IPv6, over an interface
/// that carries no IPv4 address at all.
///
/// The regression: `add_route_tagged` put the 16-byte IPv6 next hop in
/// `RTA_GATEWAY` on an `AF_INET` rtmsg. The IPv4 FIB reads that
/// attribute with `nla_get_in_addr()` (4 bytes), so it saw the first
/// four bytes of the IPv6 address as an IPv4 gateway — unreachable, and
/// the install failed with `ENETUNREACH`. The same next hop as
/// `RTA_VIA` (`struct rtvia`) is accepted, which is the form iproute2
/// emits for `ip route add PREFIX via inet6 GW dev IFACE`.
///
/// The dump assertion also pins the read side: the kernel returns such
/// a gateway as `RTA_VIA` (`fib_nexthop_info()`), never `RTA_GATEWAY`,
/// so `list_routes()` must decode it back to the original next hop.
#[test]
#[ignore = "kernel-gated: requires CAP_NET_ADMIN (run as root or in a rootless netns)"]
fn rfc5549_v4_route_over_v6_next_hop_on_v6_only_interface() {
    const LINK: &str = "dummy-rfc5549";
    const GATEWAY: IpAddr = IpAddr::V6([
        0xfd, 0x00, 0x00, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ]);

    if !ip_ok(&["link", "set", "lo", "up"]) {
        eprintln!("SKIP: cannot bring lo up (iproute2 missing)");
        return;
    }
    let Some(dummy) = dummy_link_named(LINK) else {
        eprintln!("SKIP: cannot create the {LINK} dummy link");
        return;
    };
    // IPv6-only: no IPv4 address is assigned to the link. The gateway
    // is on-link through this connected IPv6 prefix, exactly the
    // production v6-only tunnel shape.
    let prefix = "fd00:99::1/64";
    if !ip_ok(&["-6", "addr", "add", prefix, "dev", LINK, "nodad"])
        && !ip_ok(&["-6", "addr", "add", prefix, "dev", LINK])
    {
        let _ = ip_ok(&["link", "del", LINK]);
        eprintln!("SKIP: cannot assign {prefix} to {LINK}");
        return;
    }

    let mut t = match RtNetlink::connect() {
        Ok(t) => t,
        Err(e) => {
            let _ = ip_ok(&["link", "del", LINK]);
            if is_privilege_error(&e) {
                eprintln!(
                    "SKIP: RtNetlink::connect returned EPERM (run as root or in a rootless netns)"
                );
                return;
            }
            panic!("RtNetlink::connect failed unexpectedly: {}", e);
        }
    };

    let _ = t.delete_route(V4_VIA_V6);
    match t.add_route_tagged(V4_VIA_V6, GATEWAY, dummy, lr_core::rib::Protocol::Babel) {
        Ok(()) => {}
        Err(e) => {
            let _ = ip_ok(&["link", "del", LINK]);
            if is_privilege_error(&e) {
                eprintln!("SKIP: add_route_tagged returned EPERM");
                return;
            }
            panic!("RFC 5549 add_route_tagged({V4_VIA_V6} via {GATEWAY}) failed: {e}");
        }
    }
    assert!(
        table_has(&mut t, V4_VIA_V6),
        "RFC 5549 route {V4_VIA_V6} must be in the kernel FIB"
    );
    assert_eq!(
        next_hop_of(&mut t, V4_VIA_V6),
        Some(GATEWAY),
        "the dump must decode RTA_VIA back to the IPv6 next hop"
    );

    t.delete_route(V4_VIA_V6)
        .unwrap_or_else(|e| panic!("delete_route({V4_VIA_V6}) failed: {e}"));
    assert!(
        !table_has(&mut t, V4_VIA_V6),
        "RFC 5549 route {V4_VIA_V6} must be gone after delete_route"
    );

    let _ = ip_ok(&["link", "del", LINK]);
}
