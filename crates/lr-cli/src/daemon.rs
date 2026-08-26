//! `lr-daemon` — example librouting daemon.
//!
//! This is a *reference* daemon wiring together the lr-* crates into a
//! complete, embeddable router. It is intentionally minimal — no config file,
//! no signal handling, no logging framework, no supervision. The point is to
//! show the wiring so embedders can fork and build their own production
//! daemon on top.
//!
//! Architecture:
//!
//! ```text
//! +-----------------+    +------------+    +------------+
//! |  TCP listener   | -> |  BgpPeer   | -> |  AdjRibIn |
//! +-----------------+    +------------+    +------------+
//!                                                   |
//!                                                   v
//!                                              +---------+
//!                                              |  LocRib |
//!                                              +---------+
//!                                                   |
//!                                                   v
//! +----------+    +--------------+    +--------------------+
//! | OS FIB   | <- | lr-osroute   | <- | BestPath selection |
//! +----------+    +--------------+    +--------------------+
//! ```
//!
//! Usage:
//!
//! ```text
//! lr-daemon --local-as 64512 --peer-as 64513 --router-id 10.0.0.1
//! ```
//!
//! The daemon does **not** install routes into the kernel by default (so it
//! is safe to run in any environment). Use `--install-kernel-routes` to
//! enable kernel route installation via lr-osroute (requires root + Linux).

use std::env;
use std::process::ExitCode;

use lr_router::RouterInstance;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let mut local_as: u32 = 0;
    let mut peer_as: u32 = 0;
    let mut router_id: Option<String> = None;
    let mut install_kernel = false;
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--local-as" if i + 1 < args.len() => {
                local_as = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--peer-as" if i + 1 < args.len() => {
                peer_as = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--router-id" if i + 1 < args.len() => {
                router_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--install-kernel-routes" => {
                install_kernel = true;
                i += 1;
            }
            "-h" | "--help" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("unknown arg: {}", a);
                return ExitCode::from(2);
            }
        }
    }
    if local_as == 0 || peer_as == 0 || router_id.is_none() {
        print_usage();
        return ExitCode::from(2);
    }
    let rid = lr_core::addr::RouterId::from_str(&router_id.unwrap()).expect("invalid router-id");
    let mut router = lr_router::DefaultRouter::new();
    let _h = router
        .add_session(lr_router::SessionConfig::bgp(
            lr_core::addr::Asn(local_as),
            lr_core::addr::Asn(peer_as),
            rid,
        ))
        .expect("add_session");

    println!("librouting daemon (lr-daemon)");
    println!("  local AS:    AS{}", local_as);
    println!("  peer AS:     AS{}", peer_as);
    println!("  router-id:   {}", rid);
    println!("  install:     {}", install_kernel);

    // The daemon is purely poll-driven; the embedder supplies bytes via
    // SessionConfig and pumps the router via `tick` + `poll_events`. A real
    // daemon would:
    //   1. open a TCP listener on :179 (BGP);
    //   2. accept inbound connections / make outbound ones;
    //   3. wire bytes into the router via feed_input;
    //   4. drain outbound bytes via drain_output and write to the socket;
    //   5. every tick, poll_events for route updates and install them via
    //      lr-osroute::RtNetlink.
    //
    // This file is intentionally non-functional — it prints the
    // configuration and exits so a real embedder has the wiring reference.

    println!("daemon: shutdown (no I/O loop wired yet; see source comments)");
    ExitCode::SUCCESS
}

fn print_usage() {
    println!(
        "lr-daemon — example librouting daemon\n\n\
         USAGE:\n  \
         lr-daemon --local-as AS --peer-as AS --router-id A.B.C.D \
         [--install-kernel-routes] [-h]"
    );
}

// We need `RouterId::from_str` from `core::str::FromStr`:
use core::str::FromStr;
