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

fn table_has(t: &mut RtNetlink, prefix: Prefix) -> bool {
    t.list_routes()
        .map(|routes| routes.iter().any(|r| r.prefix == prefix))
        .unwrap_or(false)
}

/// Bring the netns's loopback up — a fresh netns has it DOWN, and a
/// DOWN lo makes every `via 127.0.0.1` / `via ::1` gateway
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

/// True when the error is a privilege error — the process lacks
/// CAP_NET_ADMIN. Connect failures surface as io::Error text
/// ("Operation not permitted"), netlink ACK failures as negative errno
/// ("rtnetlink: error -1"). The test skips in either shape rather than
/// failing: the wire format itself is pinned by the mock-socket unit
/// tests in linux.rs.
fn is_privilege_error(e: &lr_osroute::OsRouteError) -> bool {
    let s = &e.0;
    s.contains("EPERM")
        || s.contains("Operation not permitted")
        || s.contains("os error 1")
        || s.contains("rtnetlink: error -1")
        || s.contains("insufficient privileges")
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

    // A usable next hop for both families: the netns's own loopback. The
    // v4 form resolves the gateway's output interface from the table
    // (`via 127.0.0.1`); the v6 fib6 REQUIRES an explicit RTA_OIF for a
    // host-scope gateway (EINVAL otherwise) — which is also why the
    // daemon's v6 installs always carry the learned oif.
    for (prefix, gateway, oif) in [
        (V4, IpAddr::V4([127, 0, 0, 1]), 0),
        (
            V6,
            IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            1, // lo
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
