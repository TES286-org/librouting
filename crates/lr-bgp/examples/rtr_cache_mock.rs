//! Mock RPKI-RTR cache server — speaks the [`lr_bgp::rtr`] codec over
//! TCP so the interop lab (`tests/interop/rtr_bird.sh`) can run BIRD
//! 2's RPKI client against librouting's encoder/decoder.
//!
//! Usage: `rtr_cache_mock <port>` — serves one fixed dataset:
//!
//! * ROA 192.0.2.0/24 (max 24) — AS 64512
//! * ROA 2001:db8::/48 (max 64) — AS 64512
//!
//! Protocol behavior (RFC 8210 §6 from the cache side):
//!
//! * On connect it waits for the client's Reset Query or Serial
//!   Query (BIRD sends a Reset Query with its maximum version and
//!   downgrades when it sees our version-1 PDUs, §7).
//! * Reset Query → Cache Response + both Prefix PDUs (announce) +
//!   End of Data at serial 1.
//! * Serial Query → empty diff + End of Data at the same serial.
//! * Responds to Error Reports by closing.
//!
//! Runs until terminated; one client at a time, sequentially.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use lr_bgp::rtr::{self, RtrPdu, RTR_VERSION_1};

/// The fixed dataset (session 0x00ff; serial advances per reset).
const SESSION_ID: u16 = 0x00ff;

fn dataset() -> Vec<RtrPdu> {
    vec![
        RtrPdu::Ipv4Prefix {
            announce: true,
            prefix: lr_core::addr::Prefix::new_v4([192, 0, 2, 0], 24),
            max_length: 24,
            asn: 64512,
        },
        RtrPdu::Ipv6Prefix {
            announce: true,
            prefix: lr_core::addr::Prefix::new_v6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                48,
            ),
            max_length: 64,
            asn: 64512,
        },
    ]
}

fn send(stream: &mut TcpStream, pdu: &RtrPdu) -> std::io::Result<()> {
    let mut buf = Vec::new();
    rtr::encode(pdu, RTR_VERSION_1, &mut buf);
    stream.write_all(&buf)
}

/// Read exactly one PDU (framing-aware: header first, then body).
fn recv(stream: &mut TcpStream) -> Option<RtrPdu> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).ok()?;
    let len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let mut body = vec![0u8; len - 8];
    stream.read_exact(&mut body).ok()?;
    let mut full = header.to_vec();
    full.extend_from_slice(&body);
    match rtr::decode(&full) {
        Ok(Some((_version, pdu, _))) => Some(pdu),
        _ => None,
    }
}

fn serve_client(stream: &mut TcpStream) {
    let mut serial: u32 = 1;
    loop {
        let Some(pdu) = recv(stream) else {
            return;
        };
        match pdu {
            RtrPdu::ResetQuery => {
                eprintln!("mock-cache: Reset Query -> full dataset at serial {serial}");
                if send(
                    stream,
                    &RtrPdu::CacheResponse {
                        session_id: SESSION_ID,
                    },
                )
                .is_err()
                {
                    return;
                }
                for roa in dataset() {
                    if send(stream, &roa).is_err() {
                        return;
                    }
                }
                if send(
                    stream,
                    &RtrPdu::EndOfData {
                        session_id: SESSION_ID,
                        serial,
                        refresh_interval: Some(60),
                        retry_interval: Some(30),
                        expire_interval: Some(600),
                    },
                )
                .is_err()
                {
                    return;
                }
            }
            RtrPdu::SerialQuery { session_id, .. } => {
                eprintln!("mock-cache: Serial Query (session {session_id}) -> empty diff");
                // Empty incremental diff: straight to End of Data at
                // the same serial.
                if send(
                    stream,
                    &RtrPdu::CacheResponse {
                        session_id: SESSION_ID,
                    },
                )
                .is_err()
                {
                    return;
                }
                if send(
                    stream,
                    &RtrPdu::EndOfData {
                        session_id: SESSION_ID,
                        serial,
                        refresh_interval: Some(60),
                        retry_interval: Some(30),
                        expire_interval: Some(600),
                    },
                )
                .is_err()
                {
                    return;
                }
            }
            RtrPdu::ErrorReport { error_code, .. } => {
                eprintln!("mock-cache: Error Report from client: {error_code:?} — closing");
                return;
            }
            other => {
                eprintln!("mock-cache: unexpected PDU {other:?} — closing");
                return;
            }
        }
        serial = serial.wrapping_add(1);
    }
}

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(8282);
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("mock-cache: bind 127.0.0.1:{port} failed: {e}");
            std::process::exit(1);
        }
    };
    println!("mock-cache: listening on 127.0.0.1:{port} (session {SESSION_ID:#06x})");
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(60)));
                serve_client(&mut s);
                eprintln!("mock-cache: client closed");
            }
            Err(e) => eprintln!("mock-cache: accept error: {e}"),
        }
    }
}
