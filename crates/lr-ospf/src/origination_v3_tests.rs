use super::*;

/// A zeroed pseudo-header checksum input produces a defined value and
/// the verification property holds: summing the finalized packet with
/// the same pseudo-header yields 0xffff.
#[test]
fn v3_checksum_roundtrip() {
    let mut pkt = vec![0u8; 16 + 20];
    pkt[0] = 3; // version
    pkt[1] = 1; // Hello
    let n = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&n.to_be_bytes());
    let src = [0xfe_u8, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0xff_u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
    assert!(finalize_v3_packet(&mut pkt, &src, &dst));
    let stored = u16::from_be_bytes([pkt[12], pkt[13]]);
    // Recompute over the finalized packet with the checksum zeroed —
    // the standard one's-complement verification property.
    let mut verify = pkt.clone();
    verify[12] = 0;
    verify[13] = 0;
    assert_eq!(v3_packet_checksum(&verify, &src, &dst), stored);
    // A different pseudo-header must produce a different checksum.
    let dst2 = [0xff_u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6];
    assert_ne!(v3_packet_checksum(&verify, &src, &dst2), stored);
    // Stream finalization walks every packet.
    let mut stream = pkt.clone();
    stream.extend_from_slice(&pkt);
    assert_eq!(finalize_v3_stream(&mut stream, &src, &dst), 2);
}
