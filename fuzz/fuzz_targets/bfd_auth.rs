//! Fuzz target: BFD Keyed MD5 / Keyed SHA1 authentication
//! (RFC 5880 §6.7.3 / §6.7.4).
//!
//! The BFD auth section's digest path receives arbitrary bytes from a
//! possibly-hostile peer. The contract is that the codec and the
//! auth-verify path **never panic** on any input — a panic here is a
//! remote denial-of-service against the BFD session, which is the
//! fast-fail liveness signal for every protocol multiplexed through
//! it. Specifically:
//!
//! - [`lr_bfd::packet::BfdCodec::decode`] must return
//!   `Ok(Some(packet))`, `Ok(None)` or `Err(ParseError)` for any
//!   `&[u8]` — never panic.
//! - [`lr_bfd::keyed_auth::BfdKeyedAuth::verify_inbound`] must return
//!   `bool` for any `(packet_bytes, auth_section, detect_mult)`
//!   where the section was extracted from the same `packet_bytes` —
//!   never panic. It is the receiver-side gate.
//!
//! The fuzzer synthesizes a BFD Control packet from arbitrary bytes,
//! encodes it with a fixed shared key in the digest field, computes
//! the keyed-hash digest, optionally tampers with one byte, then
//! feeds the resulting bytes through `BfdCodec::decode` and
//! `BfdKeyedAuth::verify_inbound`. The result of `verify_inbound` is
//! discarded; the contract is "no panic", not "the verdict matches a
//! reference".
//!
//! Run locally:
//!
//! ```bash
//! cargo +nightly fuzz run bfd_auth -- -max_total_time=60
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use lr_bfd::keyed_auth::{BfdKeyedAuth, KeyedAuthAlgorithm};
use lr_bfd::packet::{BfdCodec, BfdPacket, PacketFlags, State};
use lr_bfd::AuthSection;
use lr_core::buf::{ReadBuf, WriteBuf};
use lr_core::codec::{Decoder, Encoder};

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }
    // Derive a fixed-key auth state from the first byte so the
    // fuzzer explores both MD5 and SHA1 paths.
    let algo = match data[0] & 1 {
        0 => KeyedAuthAlgorithm::KeyedMd5,
        _ => KeyedAuthAlgorithm::KeyedSha1,
    };
    let secret = b"shared-secret".to_vec();
    let Some(ka) = BfdKeyedAuth::new(1, algo, secret) else {
        return;
    };
    // Derive a BfdPacket from the remaining bytes. The packet is
    // fully populated from the fuzz input so the codec path is
    // exercised against arbitrary field combinations.
    let my_disc = u32::from_be_bytes([data[1], data[2], data[3], data[4]])
        .max(1)
        .wrapping_add(1);
    let your_disc = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
    let mut flags = PacketFlags::empty();
    flags.set(PacketFlags::AUTH, true);
    let p = BfdPacket {
        diag: lr_bfd::packet::Diagnostic::None,
        state: match data[9] & 0x3 {
            0 => State::AdminDown,
            1 => State::Down,
            2 => State::Init,
            _ => State::Up,
        },
        flags,
        detect_mult: (data[10] % 5).max(1),
        my_discriminator: my_disc,
        your_discriminator: your_disc,
        desired_min_tx_interval: 1_000_000,
        required_min_rx_interval: 1_000_000,
        required_min_echo_interval: 0,
        auth: Some(ka.auth_section_for_tx()),
    };
    let mut buf = [0u8; 96];
    let mut w = WriteBuf::new(&mut buf);
    let codec = BfdCodec::new();
    let Ok(n) = codec.encode(&p, &mut w) else {
        return;
    };
    // Sign the packet in place — the last `digest_len` bytes
    // become the keyed-hash digest.
    ka.sign_packet(&mut buf[..n]);
    // Optionally tamper with one byte of the digest (this exercises
    // the rejection path). The last byte of the fuzz input decides.
    let wire = if !data.is_empty() && data[data.len() - 1] & 1 == 1 {
        let mut wire = buf[..n].to_vec();
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        wire
    } else {
        buf[..n].to_vec()
    };
    // Decode the packet and (when the auth section parses) feed it
    // through verify_inbound. The codec may reject malformed input;
    // verify_inbound must not panic on any well-typed section.
    let mut codec_d = BfdCodec::new();
    let mut r = ReadBuf::new(&wire);
    if let Ok(Some(decoded)) = codec_d.decode(&mut r) {
        if let Some(section) = decoded.auth.as_ref() {
            let mut ka_v = ka.clone();
            let _accept = ka_v.verify_inbound(&wire, section, 3);
        }
    }
    // Also exercise the section decoder directly against arbitrary
    // bytes — it must not panic on any input.
    let mut r2 = ReadBuf::new(&data[24..]);
    let _ = AuthSection::decode(&mut r2);
});
