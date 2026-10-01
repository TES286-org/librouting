//! Wire-message analyzer — decode a hex blob into readable messages.
//!
//! Usage:
//!   echo 001e0204... | cargo run -- bgp
//!
//! The optional positional argument selects the decoder. `bgp` is the
//! default and the only one implemented in this template; reading a pcap
//! file instead of a hex blob would need the `pcap` crate as a dependency.

use std::env;
use std::io::Read;

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
    match kind.as_str() {
        "bgp" => {
            let mut codec = lr_bgp::BgpCodec::new();
            let mut r = lr_core::buf::ReadBuf::new(&bytes);
            use lr_core::codec::Decoder;
            while let Ok(Some(msg)) = codec.decode(&mut r) {
                println!("{:#?}", msg);
            }
        }
        _ => {
            eprintln!("unknown kind: {}", kind);
        }
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().trim_start_matches("0x").replace([' ', '\n', '\t'], "");
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())?);
    }
    Ok(out)
}
