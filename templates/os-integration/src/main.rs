//! OS route table integration — scaffolding template.

use lr_core::addr::{IpAddr, Prefix};
use lr_osroute::{OsRouteTable, RtNetlink};

fn main() {
    let mut rt = match RtNetlink::connect() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rtnetlink connect: {}", e);
            return;
        }
    };
    // List all routes.
    match rt.list_routes() {
        Ok(rs) => {
            println!("prefix                            next_hop             if   metric proto");
            for r in rs {
                println!(
                    "{:<32} {:<20} {:<4} {:<6} {:?}",
                    r.prefix.to_string(),
                    r.next_hop
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "(none)".into()),
                    r.if_index.unwrap_or(0),
                    r.metric,
                    r.protocol,
                );
            }
        }
        Err(e) => eprintln!("list_routes: {}", e),
    }
    // Try adding a route (will fail without CAP_NET_ADMIN).
    let prefix: Prefix = "203.0.113.0/24".parse().unwrap();
    let gw: IpAddr = "198.51.100.1".parse().unwrap();
    match rt.add_route(prefix, gw, 0) {
        Ok(_) => println!("added: {} via {}", prefix, gw),
        Err(e) => eprintln!("add_route: {}", e),
    }
}
