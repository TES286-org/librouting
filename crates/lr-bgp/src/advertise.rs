//! Egress UPDATE generation (RFC 4271 §5 + RFC 4456 §3 + RFC 9234 §4).
//!
//! [`BgpPeer::advertise`] converts a Loc-RIB route back into a wire UPDATE,
//! applying the per-neighbor egress rules before encoding:
//!
//! | Topology            | AS_PATH            | NEXT_HOP         | LOCAL_PREF |
//! |---------------------|--------------------|------------------|------------|
//! | eBGP / confed-ext   | prepend local AS   | next-hop-self*   | stripped   |
//! | iBGP / confed-int   | unchanged          | preserved        | injected (default 100) |
//! | RR client           | unchanged          | preserved        | preserved  |
//!
//! \* `next-hop-self`: rewritten to [`PeerConfig::local_address`] when
//! configured; otherwise preserved.
//!
//! Route-Reflector reflection (RFC 4456): when advertising to an RR client
//! the speaker adds its ORIGINATOR_ID (if not present) and prepends its
//! cluster ID to CLUSTER_LIST so loops can be detected downstream.
//!
//! The function is pure w.r.t. the route: the caller-supplied `Route` is
//! never mutated. OTC (RFC 9234) marking is applied when the local role is
//! configured and the route has no OTC yet.

use crate::fsm::BgpPeer;
use crate::message::update::{Nlri, Update};
use crate::message::BgpMessage;
use crate::path::{
    AttrType, Community, LocalPref, MpNextHop, MpReach, PathAttrFlags, PathAttribute,
    PathAttributes,
};
use crate::role::otc::Otc;

use lr_core::addr::Prefix;
use lr_core::nlri::NlriFamily;
use lr_core::rib::Route;

impl BgpPeer {
    /// Advertise a route to this peer. Applies egress rules, encodes the
    /// UPDATE and appends it to the outbound buffer. Returns `false` (and
    /// sends nothing) when the route is not advertisable to this peer —
    /// e.g. an iBGP-learned route to a non-client iBGP peer.
    pub fn advertise(&mut self, route: &Route) -> bool {
        if !self.is_established() {
            return false;
        }
        // FRR `no bgp default ipv4-unicast` (W2.1): a peer not activated
        // for IPv4 unicast must not receive IPv4 NLRI — neither the
        // legacy section nor the RFC 5549 ENH MP_REACH form. Returning
        // `false` here makes the router skip the Adj-RIB-Out entry, so
        // the peer sees nothing for the family (matches FRR's "the
        // neighbor is not activated for IPv4 unicast" behaviour).
        if route.key.family == NlriFamily::IPV4_UNICAST && !self.cfg.ipv4_unicast_active() {
            return false;
        }
        let topo = self.cfg.compute_topology();

        // iBGP split-horizon (RFC 4271 §10): a route learned from an iBGP
        // peer is not re-advertised to another iBGP peer unless that peer
        // is an RR client of this speaker (reflection).
        let learned_internal =
            route.origin.proto == 1 && route.protocol == lr_core::rib::Protocol::Bgp;
        if learned_internal && topo.role.is_internal() && !topo.rr_client {
            return false;
        }

        // OTC (RFC 9234 §5 egress rule 2): a route that already carries an
        // OTC attribute MUST NOT be propagated to Providers, Peers, or
        // RSes — it may go only to Customers and RS-clients.
        let mut attrs: PathAttributes = route.attributes.clone().into();
        let route_otc = attrs.get(AttrType::Otc).and_then(|a| Otc::decode(&a.value));
        if !crate::role::otc::otc_can_advertise(route_otc.unwrap_or(Otc(0)), topo.otc) {
            return false;
        }

        // RFC 9494 §4.3: a long-lived stale route (LLGR_STALE) must not be
        // advertised to a neighbor that did not advertise the LLGR
        // capability. The community itself is passed through untouched for
        // neighbors that did — §4.3 forbids stripping LLGR_STALE.
        if attrs.has_community(Community::LLGR_STALE) && !self.llgr_negotiated() {
            return false;
        }

        // W6.3 exchange-plane (feature `exchange-plane`): attach the
        // record-set attribute (or forward the received type-251
        // forwarding material) after every early-return egress gate —
        // only UPDATEs that actually go out carry records, and
        // withdrawals/EoR never do (design §4: attached to NLRI-carrying
        // UPDATEs).
        #[cfg(feature = "exchange-plane")]
        self.attach_exchange_plane(&mut attrs, route);

        // --- AS_PATH ---
        let mut as_path = attrs.as_path().unwrap_or_default();
        if topo.role.prepends_as_path() {
            as_path.prepend(self.cfg.local_as);
        }
        attrs.remove(AttrType::AsPath);
        attrs.remove(AttrType::As4Path);
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::AsPath,
            if self.cfg.asn4 {
                as_path.encode_4()
            } else {
                as_path.encode_2()
            },
        ));

        // --- LOCAL_PREF: iBGP only (RFC 4271 §5.1.4 / §9.1.2.2) ---
        // LOCAL_PREF is well-known discretionary → optional bit MUST be 0.
        // Peers such as BIRD/FRR validate well-known attribute flags and
        // reset the session on a malformed optional bit.
        if topo.role.is_internal() {
            if attrs.local_pref().is_none() {
                attrs.insert(PathAttribute::new(
                    PathAttrFlags::new().set_transitive(true),
                    AttrType::LocalPref,
                    LocalPref(100).encode().to_vec(),
                ));
            }
        } else {
            attrs.remove(AttrType::LocalPref);
        }

        // --- NEXT_HOP ---
        // RFC 5549: when (1, 1, 2) is negotiated and our local source is
        // IPv6, IPv4 NLRI egress rewrites NEXT_HOP to a 16-byte IPv6
        // address. Without ENH the peer would reject the IPv6 next-hop,
        // so we fall back to the original IPv4 next-hop (or skip the
        // route if none exists).
        let mut next_hop = route
            .next_hop
            .or_else(|| attrs.next_hop().map(|n| n.to_ip()));
        if topo.role.rewrites_next_hop() {
            if let Some(local) = self.cfg.local_address {
                let enh_ipv4_over_v6 = route.key.family == NlriFamily::IPV4_UNICAST
                    && self.extended_next_hop_for(1, 1, 2);
                match (local, route.key.family, enh_ipv4_over_v6) {
                    // IPv6 NLRI with an IPv6 local source: next-hop-self
                    // rewrites the MP_REACH next-hop to the local IPv6.
                    (lr_core::addr::IpAddr::V6(_), NlriFamily::IPV6_UNICAST, _) => {
                        next_hop = Some(local);
                    }
                    // IPv4 NLRI + ENH negotiated + IPv6 local source: the
                    // well-known NEXT_HOP attribute carries a 16-byte IPv6.
                    (lr_core::addr::IpAddr::V6(_), NlriFamily::IPV4_UNICAST, true) => {
                        attrs.remove(AttrType::NextHop);
                        attrs.insert(Self::next_hop_attr(local));
                        next_hop = Some(local);
                    }
                    // IPv4 NLRI + IPv4 local source: classic next-hop-self.
                    (lr_core::addr::IpAddr::V4(_), NlriFamily::IPV4_UNICAST, _) => {
                        attrs.remove(AttrType::NextHop);
                        attrs.insert(Self::next_hop_attr(local));
                        next_hop = Some(local);
                    }
                    // IPv4 NLRI + IPv6 local source without ENH: leave the
                    // route's IPv4 next-hop intact (or skip if none).
                    (lr_core::addr::IpAddr::V6(_), NlriFamily::IPV4_UNICAST, false) => {}
                    // IPv6 NLRI with an IPv4 local source: an IPv4 next-hop
                    // is invalid for AFI=2 MP_REACH (RFC 4760 §3 requires
                    // 16/32-byte next-hops), so keep the route's original
                    // next-hop instead of rewriting it to the IPv4 source.
                    (lr_core::addr::IpAddr::V4(_), NlriFamily::IPV6_UNICAST, _) => {}
                    // Other MP-BGP families with a matching-family local
                    // source: rewrite the MP_REACH next-hop accordingly.
                    (lr_core::addr::IpAddr::V4(_), _, _) | (lr_core::addr::IpAddr::V6(_), _, _) => {
                        next_hop = Some(local);
                    }
                }
            }
        } else if next_hop.is_none() && route.origin.proto == 2 {
            // Locally originated route (proto 2) advertised to an
            // internal peer: egress preserves the route's NEXT_HOP
            // (RFC 4271 §10), but a route with none would leave the
            // UPDATE without the mandatory NEXT_HOP attribute (§6.3)
            // and the peer would discard it. Synthesize our own
            // address — §5.1.3's "address of the router that should
            // be used as the next hop" for self-originated routes.
            if let Some(local) = self.cfg.local_address {
                match (local, route.key.family) {
                    (lr_core::addr::IpAddr::V4(_), NlriFamily::IPV4_UNICAST) => {
                        attrs.remove(AttrType::NextHop);
                        attrs.insert(Self::next_hop_attr(local));
                        next_hop = Some(local);
                    }
                    (lr_core::addr::IpAddr::V6(_), NlriFamily::IPV6_UNICAST) => {
                        next_hop = Some(local);
                    }
                    _ => {}
                }
            }
        }

        // --- Route-Reflector reflection attributes (RFC 4456 §3) ---
        // ORIGINATOR_ID and CLUSTER_LIST are optional non-transitive
        // (RFC 4456 §5): optional=1, transitive=0 → 0x80.
        if topo.rr_client {
            let cluster = self
                .cfg
                .route_reflector
                .effective_cluster_id(self.cfg.local_bgp_id);
            // ORIGINATOR_ID: the BGP-ID of the originator in the local AS.
            if attrs.get(AttrType::OriginatorId).is_none() {
                attrs.insert(PathAttribute::new(
                    PathAttrFlags::new().set_optional(true),
                    AttrType::OriginatorId,
                    self.cfg.local_bgp_id.to_v4_bytes().to_vec(),
                ));
            }
            // CLUSTER_LIST: prepend our cluster ID for loop detection.
            let mut list: Vec<u32> = attrs
                .get(AttrType::ClusterList)
                .map(|a| {
                    a.value
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                        .collect()
                })
                .unwrap_or_default();
            list.insert(0, cluster.0);
            let mut bytes = Vec::with_capacity(list.len() * 4);
            for c in &list {
                bytes.extend_from_slice(&c.to_be_bytes());
            }
            attrs.insert(PathAttribute::new(
                PathAttrFlags::new().set_optional(true),
                AttrType::ClusterList,
                bytes,
            ));
        }

        // --- NLRI ---
        let family = route.key.family;
        let mut update = Update::new();

        // RFC 8277 labelled-unicast: the NLRI carries the label stack
        // before the prefix. Pull the stack from the route's private
        // `LrMplsLabelStack` attribute (set by the FSM on receive or by
        // `originate_labeled` on the local side) and encode it via the
        // labelled MP_REACH helper. Skip advertisement when the route
        // carries no label stack — a label-less labelled route is a
        // consistency violation, not something to send on the wire.
        #[cfg(feature = "labeled_unicast")]
        if family.is_labeled_unicast() {
            let stack = attrs.label_stack();
            let Some(stack) = stack else {
                return false;
            };
            let nh = match next_hop {
                Some(lr_core::addr::IpAddr::V4(b)) => MpNextHop::V4(b),
                Some(lr_core::addr::IpAddr::V6(b)) => MpNextHop::V6Global(b),
                None => return false,
            };
            attrs.remove(AttrType::NextHop);
            attrs.remove(AttrType::MpReachNlri);
            attrs.remove(AttrType::MpUnreachNlri);
            attrs.remove(AttrType::LrMplsLabelStack); // never sent on wire
            let entries = vec![crate::path::LabeledNlri::with_path_id(
                route.path_id,
                stack,
                route.key.prefix,
            )];
            attrs.insert(PathAttribute::new(
                PathAttrFlags::new().set_optional(true),
                AttrType::MpReachNlri,
                crate::path::encode_labeled_mp_reach(
                    family,
                    &nh,
                    &entries,
                    self.add_path_tx_for(family),
                ),
            ));
            update.attributes = attrs;
            self.send_msg(&BgpMessage::Update(update));
            return true;
        }

        // RFC 5549: when (1, 1, 2) is negotiated and the next-hop is IPv6,
        // IPv4 NLRI is carried by MP_REACH_NLRI (AFI=1, SAFI=1) with a
        // 16-byte IPv6 next-hop. BIRD 2.x rejects a 16-byte well-known
        // NEXT_HOP attribute even with ENH negotiated, so MP_REACH is the
        // interoperable form.
        let enh_ipv4_over_v6 = family == NlriFamily::IPV4_UNICAST
            && self.extended_next_hop_for(1, 1, 2)
            && matches!(next_hop, Some(lr_core::addr::IpAddr::V6(_)));
        if enh_ipv4_over_v6 {
            let nh = match next_hop {
                Some(lr_core::addr::IpAddr::V6(b)) => MpNextHop::V4OverV6(b),
                _ => unreachable!("checked above"),
            };
            attrs.remove(AttrType::NextHop);
            attrs.remove(AttrType::MpReachNlri);
            attrs.remove(AttrType::MpUnreachNlri);
            let entries = vec![Nlri::new(route.path_id, route.key.prefix)];
            attrs.insert(PathAttribute::new(
                PathAttrFlags::new().set_optional(true),
                AttrType::MpReachNlri,
                MpReach::new(family, nh, entries).encode_ex(self.add_path_tx_for(family)),
            ));
        } else {
            match family {
                NlriFamily::IPV4_UNICAST => {
                    if let Some(nh) = next_hop {
                        if attrs.get(AttrType::NextHop).is_none() {
                            attrs.insert(Self::next_hop_attr(nh));
                        }
                    }
                    update.nlri.push(Nlri::new(route.path_id, route.key.prefix));
                }
                _ => {
                    let nh = match next_hop {
                        Some(lr_core::addr::IpAddr::V4(b)) => MpNextHop::V4(b),
                        Some(lr_core::addr::IpAddr::V6(b)) => MpNextHop::V6Global(b),
                        None => return false, // cannot encode MP_REACH without next-hop
                    };
                    attrs.remove(AttrType::MpReachNlri);
                    attrs.remove(AttrType::MpUnreachNlri);
                    let entries = vec![Nlri::new(route.path_id, route.key.prefix)];
                    attrs.insert(PathAttribute::new(
                        PathAttrFlags::new().set_optional(true),
                        AttrType::MpReachNlri,
                        MpReach::new(family, nh, entries).encode_ex(self.add_path_tx_for(family)),
                    ));
                }
            }
        }
        update.attributes = attrs;
        self.send_msg(&BgpMessage::Update(update));
        true
    }

    /// Withdraw prefixes previously advertised to this peer (single-path
    /// mode: the entries carry no RFC 7911 path identifier).
    pub fn withdraw(&mut self, prefixes: &[Prefix], family: NlriFamily) {
        let entries: Vec<Nlri> = prefixes.iter().map(|p| Nlri::plain(*p)).collect();
        self.withdraw_paths(&entries, family);
    }

    /// Withdraw specific paths previously advertised to this peer. Each
    /// entry carries the RFC 7911 path identifier it was advertised under
    /// (0 in single-path mode, where the identifier is simply not encoded).
    pub fn withdraw_paths(&mut self, entries: &[Nlri], family: NlriFamily) {
        if !self.is_established() {
            return;
        }
        // FRR `no bgp default ipv4-unicast` (W2.1): a peer not activated
        // for IPv4 unicast must not have IPv4 withdrawals sent to it —
        // since the advertise() side already refused to send the routes,
        // a withdrawal would be a no-op anyway. Skip to keep the wire
        // clean.
        if family == NlriFamily::IPV4_UNICAST && !self.cfg.ipv4_unicast_active() {
            return;
        }
        let mut update = Update::new();

        // RFC 8277 labelled-unicast withdrawals go through the labelled
        // MP_UNREACH encoder. The label stack is implicit on withdrawal
        // (only the prefix identifies the route); we synthesise a single
        // implicit-null label so the NLRI bytes are well-formed.
        #[cfg(feature = "labeled_unicast")]
        if family.is_labeled_unicast() {
            let labelled: Vec<crate::path::LabeledNlri> = entries
                .iter()
                .map(|e| {
                    crate::path::LabeledNlri::with_path_id(
                        e.path_id,
                        lr_mpls::LabelStack::from_labels([lr_mpls::Label::new_value(
                            lr_mpls::Label::IMPLICIT_NULL.value,
                        )]),
                        e.prefix,
                    )
                })
                .collect();
            let mp = crate::path::encode_labeled_mp_unreach(
                family,
                &labelled,
                self.add_path_tx_for(family),
            );
            update.attributes.insert(PathAttribute::new(
                PathAttrFlags::new().set_optional(true),
                AttrType::MpUnreachNlri,
                mp,
            ));
            self.send_msg(&BgpMessage::Update(update));
            return;
        }

        // RFC 5549: IPv4 NLRI advertised via MP_REACH must also be withdrawn
        // via MP_UNREACH (the legacy `withdrawn` field would not match the
        // original MP_REACH advertisement for a peer that tracks routes by
        // the MP-BGP family).
        let enh_ipv4_over_v6 =
            family == NlriFamily::IPV4_UNICAST && self.extended_next_hop_for(1, 1, 2);
        match family {
            NlriFamily::IPV4_UNICAST if !enh_ipv4_over_v6 => {
                update.withdrawn.extend_from_slice(entries)
            }
            _ => {
                let mp = crate::path::MpUnreach::new(family, entries.to_vec());
                update.attributes.insert(PathAttribute::new(
                    PathAttrFlags::new().set_optional(true),
                    AttrType::MpUnreachNlri,
                    mp.encode_ex(self.add_path_tx_for(family)),
                ));
            }
        }
        self.send_msg(&BgpMessage::Update(update));
    }

    /// Send the End-of-RIB (EoR) marker: an UPDATE carrying no withdrawn
    /// routes, no path attributes and no NLRI (RFC 4724 §4). Well-behaved
    /// speakers emit it after the initial table dump so the peer can detect
    /// convergence (BIRD and FRR both log and act on it).
    ///
    /// FRR `no bgp default ipv4-unicast` (W2.1): the empty UPDATE is
    /// conventionally the IPv4 unicast EoR marker. A peer not activated
    /// for IPv4 unicast must not signal convergence for it — silently
    /// skip the send. MP-family EoR (via MP_UNREACH_NLRI with just the
    /// AFI/SAFI) is sent through the family-iteration egress, not here.
    pub fn send_end_of_rib(&mut self) {
        if !self.is_established() {
            return;
        }
        if !self.cfg.ipv4_unicast_active() {
            return;
        }
        let update = Update::new();
        self.send_msg(&BgpMessage::Update(update));
    }

    fn next_hop_attr(ip: lr_core::addr::IpAddr) -> PathAttribute {
        use crate::path::NextHop;
        let nh = match ip {
            lr_core::addr::IpAddr::V4(b) => NextHop::from_v4(b),
            lr_core::addr::IpAddr::V6(b) => NextHop::from_v6(b),
        };
        PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::NextHop,
            nh.encode(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::{BgpEvent, BgpPeer};
    use crate::path::AsPath;
    use crate::peer::PeerConfig;
    use lr_core::addr::{Asn, IpAddr, RouterId};
    use lr_core::codec::Decoder;
    use lr_core::rib::{Preference, Protocol, RouteKey, RouteOrigin};

    fn established_peer(cfg: PeerConfig) -> BgpPeer {
        // Full OPEN/KEEPALIVE handshake against a dummy partner so the
        // peer under test actually reaches Established.
        let mut p = BgpPeer::new(cfg.clone());
        let mut dummy = BgpPeer::new(PeerConfig::new(
            cfg.peer_as,
            cfg.local_as,
            RouterId::from_v4([10, 9, 9, 9]),
        ));
        p.step(BgpEvent::ManualStart);
        p.step(BgpEvent::TransportOpen);
        dummy.step(BgpEvent::ManualStart);
        dummy.step(BgpEvent::TransportOpen);
        let p_open = p.drain_outgoing();
        let d_open = dummy.drain_outgoing();
        let _ = p.feed_bytes(&d_open);
        let _ = dummy.feed_bytes(&p_open);
        let p_ka = p.drain_outgoing();
        let d_ka = dummy.drain_outgoing();
        let _ = p.feed_bytes(&d_ka);
        let _ = dummy.feed_bytes(&p_ka);
        assert!(p.is_established());
        p
    }

    fn bgp_route(
        as_path: &[u32],
        next_hop: [u8; 4],
        prefix: [u8; 4],
        pl: u8,
        origin: u32,
    ) -> Route {
        let mut attrs = PathAttributes::new();
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![0],
        ));
        let path = AsPath::from_sequence(as_path.iter().copied().map(Asn));
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::AsPath,
            path.encode_4(),
        ));
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::NextHop,
            next_hop.to_vec(),
        ));
        Route {
            key: RouteKey::new(Prefix::new_v4(prefix, pl), NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin {
                proto: origin,
                peer: 7,
            },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, as_path.len() as u32),
            next_hop: Some(IpAddr::V4(next_hop)),
            attributes: attrs.into(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        }
    }

    /// UPDATE egress books one `update_sent` per PDU: advertisement,
    /// withdrawal and the End-of-RIB marker each count once, and the
    /// receiver's `update_received` follows when the bytes are fed.
    #[test]
    fn message_stats_count_update_egress() {
        let cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        let mut peer = established_peer(cfg.clone());
        assert_eq!(peer.message_stats().update_sent, 0);

        let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
        assert!(peer.advertise(&route));
        assert_eq!(peer.message_stats().update_sent, 1);

        peer.withdraw(
            &[Prefix::new_v4([203, 0, 113, 0], 24)],
            NlriFamily::IPV4_UNICAST,
        );
        assert_eq!(peer.message_stats().update_sent, 2, "withdrawal counts");

        peer.send_end_of_rib();
        assert_eq!(peer.message_stats().update_sent, 3, "EoR marker counts");

        // Feed the drained bytes into a live partner: the receiving
        // side counts the same PDUs.
        let mut partner = {
            let mut p = BgpPeer::new(PeerConfig::new(
                cfg.peer_as,
                cfg.local_as,
                RouterId::from_v4([10, 9, 9, 9]),
            ));
            let mut dummy = BgpPeer::new(cfg.clone());
            p.step(BgpEvent::ManualStart);
            p.step(BgpEvent::TransportOpen);
            dummy.step(BgpEvent::ManualStart);
            dummy.step(BgpEvent::TransportOpen);
            let _ = p.feed_bytes(&dummy.drain_outgoing()).unwrap();
            let _ = dummy.feed_bytes(&p.drain_outgoing()).unwrap();
            let _ = p.feed_bytes(&dummy.drain_outgoing()).unwrap();
            let _ = dummy.feed_bytes(&p.drain_outgoing()).unwrap();
            assert!(p.is_established());
            p
        };
        let wire = peer.drain_outgoing();
        let _ = partner.feed_bytes(&wire).unwrap();
        assert_eq!(
            partner.message_stats().update_received,
            3,
            "receiver counts all three UPDATEs"
        );
    }

    /// eBGP egress: AS prepended, LOCAL_PREF stripped.
    #[test]
    fn ebgp_advertise_prepends_and_strips_local_pref() {
        let cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        let mut peer = established_peer(cfg);
        let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
        assert!(peer.advertise(&route));
        let bytes = peer.drain_outgoing();
        assert_eq!(bytes[18], 2); // UPDATE

        // Feed the UPDATE into a matching peer and verify the AS path grew.
        let remote = established_peer(PeerConfig::new(
            Asn(64513),
            Asn(64512),
            RouterId::from_v4([10, 0, 0, 2]),
        ));
        // bring remote into Established via KEEPALIVE exchange is complex;
        // decode the UPDATE directly instead.
        let mut dec = crate::codec::BgpCodec::new();
        let mut r = lr_core::buf::ReadBuf::new(&bytes);
        if let Ok(Some(BgpMessage::Update(u))) = dec.decode(&mut r) {
            let path = u.attributes.as_path_wire(true).unwrap();
            let ases = path.as_sequence();
            assert_eq!(ases, vec![Asn(64512), Asn(64500)]);
            assert!(u.attributes.local_pref().is_none());
            assert_eq!(u.nlri.len(), 1);
        } else {
            panic!("UPDATE did not decode");
        }
        let _ = remote;
    }

    /// iBGP egress: no prepend, LOCAL_PREF injected with default 100.
    #[test]
    fn ibgp_advertise_injects_local_pref() {
        let cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
        let mut peer = established_peer(cfg);
        let route = bgp_route(&[], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
        assert!(peer.advertise(&route));
        let bytes = peer.drain_outgoing();
        let mut dec = crate::codec::BgpCodec::new();
        let mut r = lr_core::buf::ReadBuf::new(&bytes);
        if let Ok(Some(BgpMessage::Update(u))) = dec.decode(&mut r) {
            let path = u.attributes.as_path_wire(true).unwrap();
            assert!(path.as_sequence().is_empty());
            assert_eq!(u.attributes.local_pref(), Some(LocalPref(100)));
        } else {
            panic!("UPDATE did not decode");
        }
    }

    /// iBGP split-horizon: an iBGP-learned route is not re-advertised to
    /// another non-client iBGP peer.
    #[test]
    fn ibgp_split_horizon() {
        let cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
        let mut peer = established_peer(cfg);
        let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 1);
        assert!(!peer.advertise(&route)); // origin.proto == 1 → iBGP-learned
        assert!(peer.drain_outgoing().is_empty());
    }

    /// iBGP egress of a locally originated route with no next-hop must
    /// synthesize NEXT_HOP from the local address: an UPDATE without
    /// the attribute is discarded by the peer (RFC 4271 §6.3, §5.1.3).
    #[test]
    fn ibgp_locally_originated_route_gets_next_hop() {
        let mut cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
        cfg.local_address = Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1]));
        let mut peer = established_peer(cfg);
        // proto 2 = locally originated; no NEXT_HOP attribute either.
        let mut attrs = PathAttributes::new();
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::Origin,
            vec![0],
        ));
        attrs.insert(PathAttribute::new(
            PathAttrFlags::new().set_transitive(true),
            AttrType::AsPath,
            AsPath::from_sequence([]).encode_4(),
        ));
        let route = Route {
            key: RouteKey::new(
                Prefix::new_v4([203, 0, 113, 0], 24),
                NlriFamily::IPV4_UNICAST,
            ),
            origin: RouteOrigin { proto: 2, peer: 0 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 0),
            next_hop: None,
            attributes: attrs.into(),
            age_ms: 0,
            path_id: 0,
            tag: None,
        };
        assert!(peer.advertise(&route));
        let bytes = peer.drain_outgoing();
        let mut dec = crate::codec::BgpCodec::new();
        let mut r = lr_core::buf::ReadBuf::new(&bytes);
        match dec.decode(&mut r) {
            Ok(Some(BgpMessage::Update(u))) => {
                assert_eq!(
                    u.attributes.next_hop().map(|n| n.to_ip()),
                    Some(lr_core::addr::IpAddr::V4([192, 0, 2, 1])),
                    "NEXT_HOP must be synthesized from the local address"
                );
            }
            _ => panic!("UPDATE did not decode"),
        }
    }

    /// RR reflection: advertising an iBGP-learned route to an RR client
    /// succeeds and carries ORIGINATOR_ID + CLUSTER_LIST.
    #[test]
    fn rr_reflection_to_client() {
        let mut cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
        cfg.route_reflector_client = true;
        let mut peer = established_peer(cfg);
        let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 1);
        assert!(peer.advertise(&route));
        let bytes = peer.drain_outgoing();
        let mut dec = crate::codec::BgpCodec::new();
        let mut r = lr_core::buf::ReadBuf::new(&bytes);
        if let Ok(Some(BgpMessage::Update(u))) = dec.decode(&mut r) {
            assert!(u.attributes.get(AttrType::OriginatorId).is_some());
            assert!(u.attributes.get(AttrType::ClusterList).is_some());
        } else {
            panic!("UPDATE did not decode");
        }
    }

    /// Withdraw encoding: withdraw-only UPDATE roundtrips.
    #[test]
    fn withdraw_encodes() {
        let cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        let mut peer = established_peer(cfg);
        peer.withdraw(
            &[Prefix::new_v4([203, 0, 113, 0], 24)],
            NlriFamily::IPV4_UNICAST,
        );
        let bytes = peer.drain_outgoing();
        let mut dec = crate::codec::BgpCodec::new();
        let mut r = lr_core::buf::ReadBuf::new(&bytes);
        if let Ok(Some(BgpMessage::Update(u))) = dec.decode(&mut r) {
            assert_eq!(u.withdrawn.len(), 1);
            assert!(u.nlri.is_empty());
        } else {
            panic!("UPDATE did not decode");
        }
    }

    /// Attribute flag conformance: strict implementations (BIRD, FRR)
    /// validate the optional/transitive bits of well-known attributes.
    /// LOCAL_PREF is well-known discretionary → 0x40; ORIGINATOR_ID and
    /// CLUSTER_LIST are optional non-transitive → 0x80.
    #[test]
    fn attribute_flags_match_rfc() {
        let mut cfg = PeerConfig::new(Asn(64512), Asn(64512), RouterId::from_v4([10, 0, 0, 1]));
        cfg.route_reflector_client = true;
        let mut peer = established_peer(cfg);
        let route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
        assert!(peer.advertise(&route));
        let bytes = peer.drain_outgoing();
        let mut dec = crate::codec::BgpCodec::new();
        let mut r = lr_core::buf::ReadBuf::new(&bytes);
        let msg = dec.decode(&mut r).unwrap().unwrap();
        let BgpMessage::Update(u) = msg else {
            panic!("expected UPDATE");
        };
        let lp = u.attributes.get(AttrType::LocalPref).expect("LOCAL_PREF");
        assert_eq!(lp.flags.0 & 0xc0, 0x40, "LOCAL_PREF must be well-known");
        let oi = u
            .attributes
            .get(AttrType::OriginatorId)
            .expect("ORIGINATOR_ID");
        assert_eq!(
            oi.flags.0 & 0xc0,
            0x80,
            "ORIGINATOR_ID optional non-transitive"
        );
        let cl = u
            .attributes
            .get(AttrType::ClusterList)
            .expect("CLUSTER_LIST");
        assert_eq!(
            cl.flags.0 & 0xc0,
            0x80,
            "CLUSTER_LIST optional non-transitive"
        );
    }

    /// End-of-RIB marker: an empty UPDATE (no withdrawn, no attributes, no
    /// NLRI) per RFC 4724 §4.
    #[test]
    fn end_of_rib_is_empty_update() {
        let cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        let mut peer = established_peer(cfg);
        peer.send_end_of_rib();
        let bytes = peer.drain_outgoing();
        assert_eq!(bytes.len(), 23); // 19-byte header + 4 zero length fields
        assert_eq!(bytes[18], 2); // UPDATE type
        let mut dec = crate::codec::BgpCodec::new();
        let mut r = lr_core::buf::ReadBuf::new(&bytes);
        match dec.decode(&mut r).unwrap().unwrap() {
            BgpMessage::Update(u) => {
                assert!(u.withdrawn.is_empty());
                assert!(u.nlri.is_empty());
                assert_eq!(u.attributes.len(), 0);
            }
            _ => panic!("expected UPDATE"),
        }
    }

    fn llgr_peer(long_lived: bool) -> BgpPeer {
        let mut cfg = PeerConfig::new(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]));
        cfg.graceful_restart = true;
        cfg.long_lived = long_lived;
        cfg.long_lived_stale_time = 3600;
        cfg.mp_families = vec![NlriFamily::IPV4_UNICAST];
        // The dummy partner must mirror the LLGR setting so negotiation
        // succeeds/fails on both sides.
        let mut p = BgpPeer::new(cfg.clone());
        let mut dummy_cfg =
            PeerConfig::new(Asn(64513), Asn(64512), RouterId::from_v4([10, 9, 9, 9]));
        dummy_cfg.graceful_restart = true;
        dummy_cfg.long_lived = long_lived;
        dummy_cfg.long_lived_stale_time = 3600;
        dummy_cfg.mp_families = vec![NlriFamily::IPV4_UNICAST];
        let mut dummy = BgpPeer::new(dummy_cfg);
        p.step(BgpEvent::ManualStart);
        p.step(BgpEvent::TransportOpen);
        dummy.step(BgpEvent::ManualStart);
        dummy.step(BgpEvent::TransportOpen);
        let p_open = p.drain_outgoing();
        let d_open = dummy.drain_outgoing();
        let _ = p.feed_bytes(&d_open);
        let _ = dummy.feed_bytes(&p_open);
        let p_ka = p.drain_outgoing();
        let d_ka = dummy.drain_outgoing();
        let _ = p.feed_bytes(&d_ka);
        let _ = dummy.feed_bytes(&p_ka);
        assert!(p.is_established());
        p
    }

    fn llgr_stale_route() -> Route {
        let mut route = bgp_route(&[64500], [192, 0, 2, 1], [203, 0, 113, 0], 24, 0);
        let mut attrs: PathAttributes = route.attributes.clone().into();
        attrs.insert_community(Community::LLGR_STALE);
        route.attributes = attrs.into();
        route
    }

    /// RFC 9494 §4.3: an LLGR_STALE route is not advertised to a neighbor
    /// that did not advertise the LLGR capability.
    #[test]
    fn llgr_stale_route_not_advertised_without_llgr_peer() {
        let mut peer = llgr_peer(false);
        assert!(!peer.llgr_negotiated());
        assert!(!peer.advertise(&llgr_stale_route()));
        assert!(peer.drain_outgoing().is_empty());
    }

    /// RFC 9494 §4.3: to an LLGR-capable neighbor the stale route is
    /// advertised and the LLGR_STALE community is preserved.
    #[test]
    fn llgr_stale_route_advertised_with_community_intact() {
        let mut peer = llgr_peer(true);
        assert!(peer.llgr_negotiated());
        assert!(peer.advertise(&llgr_stale_route()));
        let bytes = peer.drain_outgoing();
        let mut dec = crate::codec::BgpCodec::new();
        let mut r = lr_core::buf::ReadBuf::new(&bytes);
        match dec.decode(&mut r).unwrap().unwrap() {
            BgpMessage::Update(u) => {
                assert!(
                    u.attributes.has_community(Community::LLGR_STALE),
                    "LLGR_STALE must survive egress"
                );
            }
            _ => panic!("expected UPDATE"),
        }
    }
}
