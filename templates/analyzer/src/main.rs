//! Wire-message analyzer — decode a hex blob into readable messages.
//!
//! Usage:
//!   echo 001e0204... | cargo run -- bgp
//!   echo 001e0204... | cargo run -- ospf
//!   echo 001e0204... | cargo run -- ospfv3
//!   echo 001e0204... | cargo run -- babel
//!
//! The positional argument selects the decoder. `bgp`, `ospf`, `ospfv3`
//! and `babel` are wired up; reading a pcap file instead of a hex blob
//! would need the `pcap` crate as a dependency.

use std::env;
use std::io::Read;

use lr_core::buf::ReadBuf;
use lr_core::codec::Decoder;

fn main() {
    let mut args = env::args().skip(1);
    let kind = args.next().unwrap_or_else(|| "bgp".into());
    let mut input = String::new();
    let _ = std::io::stdin().read_to_string(&mut input);
    let input = input.trim();
    let bytes = match decode_hex(input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("hex parse error: {}", e);
            return;
        }
    };
    if let Err(e) = run(&kind, &bytes) {
        eprintln!("decode error: {}", e);
        std::process::exit(1);
    }
}

/// Drive one codec over `bytes`, printing each decoded PDU. The codec
/// type stays opaque to `main` so future decoders slot in by adding a
/// match arm here.
fn run(kind: &str, bytes: &[u8]) -> Result<(), String> {
    match kind {
        "bgp" => drive(lr_bgp::BgpCodec::new(), bytes),
        "ospf" | "ospfv2" => drive(lr_ospf::OspfCodec::v2(), bytes),
        "ospfv3" | "ospf3" => drive(lr_ospf::OspfCodec::v3(), bytes),
        "babel" => drive(lr_babel::BabelCodec::new(), bytes),
        _ => Err(format!("unknown kind: {kind} (try bgp|ospf|ospfv3|babel)")),
    }
}

/// Repeatedly call `codec.decode` until the buffer stops yielding PDU
/// frames. Each decoded PDU is printed with `{:#?}` so the operator
/// sees the full structured shape, not a one-line summary.
fn drive<M: std::fmt::Debug, D: Decoder<M>>(mut codec: D, bytes: &[u8]) -> Result<(), String> {
    let mut r = ReadBuf::new(bytes);
    while let Ok(Some(msg)) = codec.decode(&mut r) {
        println!("{:#?}", msg);
    }
    Ok(())
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s
        .trim()
        .trim_start_matches("0x")
        .replace([' ', '\n', '\t'], "");
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())?);
    }
    Ok(out)
}
