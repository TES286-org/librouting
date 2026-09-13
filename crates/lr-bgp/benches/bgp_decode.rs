//! `cargo bench -p lr-bgp --bench bgp_decode` — measure BGP wire
//! decode throughput (ROADMAP-v3 D6.2).
//!
//! Three benches cover the hot paths every BGP peer hits per packet:
//!
//! * `decode_open`       — a minimal OPEN (RFC 4271 §8 sample).
//!   Sent once per session, but the codec path is shared with the
//!   much hotter UPDATE path, so a regression here is a regression
//!   everywhere.
//! * `decode_keepalive`  — header-only 19-byte message. The minimum
//!   per-byte cost of the codec.
//! * `decode_update_full` — a realistic UPDATE with ORIGIN, AS_PATH
//!   (4 hops), NEXT_HOP and one /24 NLRI. This is the dominant
//!   per-packet cost on a BGP speaker receiving the full table.
//!
//! Results are reported as ns/iter and throughput (MB/s). The
//! bench harness uses Criterion's `iter_batched_ref` so the codec's
//! internal carryover buffer does not allocate per iteration.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use lr_bgp::codec::BgpCodec;
use lr_bgp::message::update::Nlri;
use lr_bgp::message::{BgpMessage, Keepalive, Open, Update};
use lr_bgp::path::{AsPath, AttrType, PathAttrFlags, PathAttribute};
use lr_core::addr::{Asn, Prefix, RouterId};

/// Minimal OPEN: AS 65001, hold 180, BGP-ID 192.0.2.1, no params.
fn open_bytes() -> Vec<u8> {
    let open = Open::new(Asn(65001), 180, RouterId::from_v4([192, 0, 2, 1]));
    BgpCodec::new()
        .with_asn4(false)
        .encode_vec(&BgpMessage::Open(open))
        .expect("encode OPEN")
}

/// Minimal KEEPALIVE: 19-byte header only.
fn keepalive_bytes() -> Vec<u8> {
    BgpCodec::new()
        .encode_vec(&BgpMessage::Keepalive(Keepalive))
        .expect("encode KEEPALIVE")
}

/// Full UPDATE: announce 192.0.2.0/24 with ORIGIN=IGP, AS_PATH
/// (4 ASes), NEXT_HOP=192.0.2.1.
fn update_bytes() -> Vec<u8> {
    let mut u = Update::new();
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        AsPath::from_sequence([Asn(100), Asn(200), Asn(300), Asn(400)]).encode_4(),
    ));
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::NextHop,
        vec![192, 0, 2, 1],
    ));
    u.nlri.push(Nlri::plain(Prefix::new_v4([192, 0, 2, 0], 24)));
    BgpCodec::new()
        .with_asn4(true)
        .encode_vec(&BgpMessage::Update(u))
        .expect("encode UPDATE")
}

fn bench_decode(c: &mut Criterion) {
    let open = open_bytes();
    let keepalive = keepalive_bytes();
    let update = update_bytes();

    let mut group = c.benchmark_group("bgp_decode");
    group.throughput(Throughput::Bytes(open.len() as u64));
    group.bench_function("decode_open", |b| {
        b.iter_batched_ref(
            BgpCodec::new,
            |codec| {
                let _ = black_box(codec.decode_slice(&open).unwrap());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.throughput(Throughput::Bytes(keepalive.len() as u64));
    group.bench_function("decode_keepalive", |b| {
        b.iter_batched_ref(
            BgpCodec::new,
            |codec| {
                let _ = black_box(codec.decode_slice(&keepalive).unwrap());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.throughput(Throughput::Bytes(update.len() as u64));
    group.bench_function("decode_update_full", |b| {
        b.iter_batched_ref(
            || BgpCodec::new().with_asn4(true),
            |codec| {
                let _ = black_box(codec.decode_slice(&update).unwrap());
            },
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
