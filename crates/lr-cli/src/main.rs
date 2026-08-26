//! `lr` — the librouting CLI tool.
//!
//! Subcommands:
//!
//! - `lr decode <kind> <hex>` — decode a wire message and print its fields.
//!   `<kind>` is one of `bgp-open`, `bgp-keepalive`, `bgp-update`, `bfd`,
//!   `ospf-hello`, `babel-tlv`.
//! - `lr encode <kind> <json>` — encode a wire message from a JSON spec.
//! - `lr version` — print the library version + feature flags.
//! - `lr routes list` — dump the kernel routing table (Linux only).
//! - `lr routes add <prefix> <gw> <if_index>` — add a route to the kernel.
//! - `lr routes del <prefix>` — delete a route from the kernel.
//!
//! This is a *demonstration* CLI — it intentionally has no dependencies on
//! argument-parsing libraries (clap, structopt) to keep the build fast.
//! Operators looking for a production BGP daemon should look at FRR / BIRD /
//! OpenBGPD; this CLI is for inspecting the librouting library itself.

use std::env;
use std::process::ExitCode;

use lr_core::buf::ReadBuf;
use lr_core::codec::Decoder;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return ExitCode::from(1);
    }
    let cmd = args[1].as_str();
    let rest = &args[2..];
    match cmd {
        "version" | "--version" | "-v" => {
            println!("librouting {}", VERSION);
            println!("crates: lr-core, lr-bgp, lr-ospf, lr-babel, lr-rib, lr-policy, lr-router, lr-bfd, lr-damping, lr-osroute, lr-ffi");
            ExitCode::SUCCESS
        }
        "decode" => decode(rest),
        "routes" => routes(rest),
        "help" | "--help" | "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("error: unknown command '{}'", cmd);
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    println!("librouting {} — CLI tool", VERSION);
    println!();
    println!("USAGE:");
    println!("    lr <command> [args]");
    println!();
    println!("COMMANDS:");
    println!("    version            Print library version + crate list");
    println!("    decode <kind> <hex> Decode a wire message");
    println!("                       kind: bgp-open|bgp-keepalive|bfd");
    println!("    routes list         Dump kernel routing table");
    println!("    routes add <prefix> <gw> <if_index>");
    println!("                       Add a route to the kernel");
    println!("    routes del <prefix> Delete a route from the kernel");
    println!("    help                Show this message");
}

fn decode(args: &[String]) -> ExitCode {
    if args.len() < 2 {
        eprintln!("usage: lr decode <kind> <hex>");
        return ExitCode::from(2);
    }
    let kind = args[0].as_str();
    let hex = &args[1];
    let bytes = match decode_hex(hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("hex parse error: {}", e);
            return ExitCode::from(1);
        }
    };
    match kind {
        "bgp-open" | "bgp-keepalive" => {
            // Use the lr-bgp codec.
            let mut codec = lr_bgp::BgpCodec::new();
            let mut r = ReadBuf::new(&bytes);
            match codec.decode(&mut r) {
                Ok(Some(msg)) => {
                    println!("{:#?}", msg);
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("error: not enough bytes to decode");
                    ExitCode::from(1)
                }
                Err(e) => {
                    eprintln!("decode error: {}", e);
                    ExitCode::from(1)
                }
            }
        }
        "bfd" => {
            let mut codec = lr_bfd::BfdCodec::new();
            let mut r = ReadBuf::new(&bytes);
            match codec.decode(&mut r) {
                Ok(Some(p)) => {
                    println!("{:#?}", p);
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("error: not enough bytes to decode");
                    ExitCode::from(1)
                }
                Err(e) => {
                    eprintln!("decode error: {}", e);
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("error: unknown kind '{}'", kind);
            ExitCode::from(2)
        }
    }
}

fn routes(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("usage: lr routes <list|add|del>");
        return ExitCode::from(2);
    }
    let sub = args[0].as_str();
    match sub {
        "list" => {
            let mut rt = match lr_osroute::RtNetlink::connect() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("rtnetlink connect: {}", e);
                    return ExitCode::from(1);
                }
            };
            use lr_osroute::OsRouteTable;
            let routes = match rt.list_routes() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("list_routes: {}", e);
                    return ExitCode::from(1);
                }
            };
            println!("prefix                            next_hop             if   metric proto");
            for r in routes {
                println!(
                    "{:<32} {:<20} {:<4} {:<6} {:?}",
                    r.prefix.to_string(),
                    r.next_hop
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "(none)".to_string()),
                    r.if_index.unwrap_or(0),
                    r.metric,
                    r.protocol,
                );
            }
            ExitCode::SUCCESS
        }
        "add" => {
            if args.len() < 4 {
                eprintln!("usage: lr routes add <prefix> <gw> <if_index>");
                return ExitCode::from(2);
            }
            let prefix: lr_core::addr::Prefix = match args[1].parse() {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("invalid prefix: {}", args[1]);
                    return ExitCode::from(1);
                }
            };
            let gw: lr_core::addr::IpAddr = match args[2].parse() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("invalid gw: {}", args[2]);
                    return ExitCode::from(1);
                }
            };
            let if_index: u32 = match args[3].parse() {
                Ok(i) => i,
                Err(_) => {
                    eprintln!("invalid if_index: {}", args[3]);
                    return ExitCode::from(1);
                }
            };
            let mut rt = match lr_osroute::RtNetlink::connect() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("rtnetlink connect: {}", e);
                    return ExitCode::from(1);
                }
            };
            use lr_osroute::OsRouteTable;
            if let Err(e) = rt.add_route(prefix, gw, if_index) {
                eprintln!("add_route: {}", e);
                return ExitCode::from(1);
            }
            println!("added: {} via {} dev {}", prefix, gw, if_index);
            ExitCode::SUCCESS
        }
        "del" | "delete" => {
            if args.len() < 2 {
                eprintln!("usage: lr routes del <prefix>");
                return ExitCode::from(2);
            }
            let prefix: lr_core::addr::Prefix = match args[1].parse() {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("invalid prefix: {}", args[1]);
                    return ExitCode::from(1);
                }
            };
            let mut rt = match lr_osroute::RtNetlink::connect() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("rtnetlink connect: {}", e);
                    return ExitCode::from(1);
                }
            };
            use lr_osroute::OsRouteTable;
            if let Err(e) = rt.delete_route(prefix) {
                eprintln!("delete_route: {}", e);
                return ExitCode::from(1);
            }
            println!("deleted: {}", prefix);
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("error: unknown routes subcommand '{}'", sub);
            ExitCode::from(2)
        }
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().trim_start_matches("0x");
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| format!("hex digit {}..{}: {}", i, i + 2, e))?;
        out.push(byte);
    }
    Ok(out)
}
