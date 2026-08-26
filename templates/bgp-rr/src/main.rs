//! BGP Route Reflector cluster (RFC 4456) — scaffolding template.
//!
//! This template wires three BGP peers in a reflection topology:
//!
//! - RR (route reflector) speaks iBGP to two clients.
//! - RR forwards routes between clients (as RFC 4456 specifies).
//!
//! Usage:
//!   cargo run -- --local-as 64512 --router-id 10.0.0.1
//!            --client 10.0.0.2:179 --client 10.0.0.3:179

use std::env;

fn main() {
    let mut args = env::args().skip(1);
    let mut local_as: u32 = 0;
    let mut router_id: Option<String> = None;
    let mut clients: Vec<String> = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--local-as" => {
                if let Some(v) = args.next() {
                    local_as = v.parse().unwrap_or(0);
                }
            }
            "--router-id" => {
                if let Some(v) = args.next() {
                    router_id = Some(v);
                }
            }
            "--client" => {
                if let Some(v) = args.next() {
                    clients.push(v);
                }
            }
            _ => {}
        }
    }
    let rid = router_id
        .and_then(|s| s.parse().ok())
        .unwrap_or(lr_core::addr::RouterId::from_v4([10, 0, 0, 1]));
    println!("BGP RR cluster scaffold");
    println!("  local AS:    AS{}", local_as);
    println!("  router-id:   {}", rid);
    println!("  clients:     {}", clients.join(", "));
    println!();
    println!("See docs/examples/bgp_route_reflector.md for the full implementation.");
}
