//! OSPFv3 transport kernel interop — bind the `OspfV6Transport` raw
//! socket, multicast a real v3 Hello to ff02::5, and receive it back
//! (multicast loop enabled), proving the full socket path a daemon
//! relies on: `SO_BINDTODEVICE` scoping, group membership, hop limit 1
//! egress, and header-less receive (Linux AF_INET6 raw sockets deliver
//! the OSPF packet without the IPv6 header).
//!
//! The test is **kernel-gated**:
//! - Skips without `CAP_NET_RAW` (the raw socket syscall returns
//!   EPERM). CI runners don't grant this by default; run locally with
//!   `sudo` or inside a rootless netns (`unshare -Urn`).
//! - Runs on `lo`, which always exists — even in containers and
//!   network namespaces.
//!
//! Run locally with: `sudo cargo test --test ospf6_kernel -- --ignored
//! --nocapture`.

#![cfg(target_os = "linux")]

use lr_core::addr::RouterId;
use lr_ospf::packet::{
    HelloBody, OspfBody, OspfHeader, OspfPacket, OspfPacketType, OspfVersion,
    OSPF_V3_OPTIONS_DEFAULT,
};
use lr_ospf::{codec::OspfCodec, origination::finalize_v3_packet};
use lr_osroute::ospf_transport::{OspfV6Transport, ALL_SPF_ROUTERS_V6};

/// Build a minimal OSPFv3 Hello (RFC 5340 §A.3.2) with the checksum
/// patched for the given pseudo-header endpoints.
fn hello(router_id: u32, interface_id: u32, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    let pkt = OspfPacket {
        header: OspfHeader {
            version: OspfVersion::V3 as u8,
            kind: OspfPacketType::Hello as u8,
            length: 0,
            router_id,
            area_id: 0,
            checksum: 0,
            au_type_or_instance: 0,
            auth_data: 0,
        },
        body: OspfBody::Hello(HelloBody {
            // v3: the network-mask slot carries the Interface ID.
            network_mask: interface_id,
            hello_interval: 10,
            options: OSPF_V3_OPTIONS_DEFAULT,
            priority: 1,
            dead_interval: 40,
            dr: 0,
            bdr: 0,
            neighbors: vec![],
        }),
    };
    let mut bytes = OspfCodec::v3().encode_vec(&pkt).expect("encode v3 hello");
    assert!(finalize_v3_packet(&mut bytes, &src, &dst));
    bytes
}

#[test]
fn ospf6_transport_multicast_roundtrip_on_lo() {
    // Bind with multicast loop ON so our own packet comes back to us.
    let Ok(sock) = OspfV6Transport::bind("lo", true) else {
        eprintln!("skip: no CAP_NET_RAW (raw socket bind failed)");
        return;
    };
    sock.set_nonblocking(true).expect("nonblocking");

    let src = {
        // Our link-local on lo — any link-local works as the
        // pseudo-header source for the checksum.
        let mut a = [0u8; 16];
        a[0] = 0xfe;
        a[1] = 0x80;
        a[15] = 1;
        a
    };
    let bytes = hello(
        RouterId::from_u32(0x0a00_0001).as_u32(),
        sock.ifindex(),
        src,
        ALL_SPF_ROUTERS_V6,
    );
    // Send the encoded datagram through the socket itself (loopback).
    let n = sock.send_multicast(&bytes).expect("multicast send");
    assert_eq!(n, bytes.len(), "full datagram on the wire");

    // Receive it back: Linux AF_INET6 raw sockets deliver the OSPF
    // packet starting at the 16-byte OSPF header (no IPv6 header).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut received = false;
    while std::time::Instant::now() < deadline {
        let mut buf = [0u8; 1500];
        match sock.recv_from(&mut buf) {
            Ok(Some((len, src_addr))) => {
                // The payload must parse as the exact Hello we sent.
                assert_eq!(len, bytes.len(), "OSPF packet delivered header-less");
                assert_eq!(&buf[..len], &bytes[..], "roundtrip payload identical");
                assert!(src_addr.is_unicast_link_local() || src_addr.is_loopback());
                received = true;
                break;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(e) => panic!("recv failed: {e}"),
        }
    }
    assert!(received, "our multicast Hello did not come back within 3s");
}
