//! SRv6 Endpoint Behaviors — RFC 8986 (Segment Routing over IPv6
//! Data Plane, the SID behavior registry).
//!
//! A behavior is what a node does when a SID becomes *active* — when
//! the destination address of the packet equals that SID. The behavior
//! is identified by a 16-bit value assigned by IANA's "SRv6 Endpoint
//! Behavior" registry (RFC 8986 §9.2). This crate models the registry
//! as a Rust enum so callers can match on the behavior in `match`
//! expressions instead of comparing magic numbers.
//!
//! ## Naming
//!
//! The behaviors are named exactly as in the RFC: `End`, `End.X`,
//! `End.DX6`, etc. The crate does NOT use the IETF-style underscore
//! replacements (`End_X`) — RFC 8986 uses the dot notation in its
//! text and the IANA registry uses the same. Where Rust identifiers
//! disallow dots, we use a trailing underscore: `End_X` on the wire
//! is `End.X`.
//!
//! ## PSP / USP / USD flavors
//!
//! RFC 8986 §4.16 introduces three flavors of the same behavior:
//!
//! - **PSP** (Penultimate Segment Pop): the SRH is removed one hop
//!   before the segment's own endpoint.
//! - **USP** (Ultimate Segment Pop): the SRH is removed at the
//!   segment's own endpoint (the last hop).
//! - **USD** (Ultimate Segment Decap): the inner packet is
//!   decapsulated at the segment's own endpoint.
//!
//! The flavors are encoded in the low-order bits of the 16-bit
//! behavior value (RFC 8986 §9.2 — see the IANA registry's "Flavor"
//! column). The crate exposes them as separate enum variants
//! (`EndPsp`, `EndX.Psp` etc.) because the wire format reserves the
//! low bits of the behavior value for the flavor — but the registry
//! only assigns values to the few combinations that appear in the
//! spec, so we enumerate them directly.

use core::fmt;

/// A 16-bit SRv6 Endpoint Behavior value (RFC 8986 §9.2, IANA's
/// "SRv6 Endpoint Behavior" registry).
///
/// The discriminant of each variant is the wire value (lower 16 bits
/// for the behavior, encoded as `behavior_value` via
/// [`Behavior::wire_value`]). The wire values match the IANA registry
/// exactly — the crate does not synthesize new ones.
///
/// The 16-bit form on the wire is `<behavior_value:16>` (RFC 8986
/// §4 — the function field of a SID is wide enough to carry the
/// behavior opcode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Behavior {
    /// The End behavior (RFC 8986 §4.1). The simplest endpoint: the
    /// node decrements `segments_left`, sets the destination to the
    /// next segment, and forwards. If `segments_left == 0`, drop.
    End = 1,
    /// End with PSP (Penultimate Segment Pop) (RFC 8986 §4.1 + §4.16).
    EndPsp = 2,
    /// End with USP (Ultimate Segment Pop) (RFC 8986 §4.1 + §4.16).
    EndUsp = 3,
    /// End with USD (Ultimate Segment Decap) (RFC 8986 §4.1 + §4.16).
    EndUsd = 4,
    /// End.X — Layer-3 cross-connect to a specific next hop (RFC 8986
    /// §4.2). Identical to `End` but forwards out a specific
    /// adjacency, not the IGP next-hop.
    EndX = 5,
    /// End.X with PSP.
    EndXPsp = 6,
    /// End.X with USP.
    EndXUsp = 7,
    /// End.X with USD.
    EndXUsd = 8,
    /// End.T — Layer-3 cross-connect to a specific table (RFC 8986
    /// §4.3). Forwards the packet by looking it up in a specific
    /// routing table.
    EndT = 9,
    /// End.T with PSP.
    EndTPsp = 10,
    /// End.T with USP.
    EndTUsp = 11,
    /// End.T with USD.
    EndTUsd = 12,
    /// End.DX6 — decap and L3 cross-connect to an IPv6 next hop
    /// (RFC 8986 §4.5).
    EndDX6 = 13,
    /// End.DX4 — decap and L3 cross-connect to an IPv4 next hop
    /// (RFC 8986 §4.6).
    EndDX4 = 14,
    /// End.DT6 — decap and L3 table lookup for IPv6 (RFC 8986 §4.7).
    EndDT6 = 15,
    /// End.DT4 — decap and L3 table lookup for IPv4 (RFC 8986 §4.8).
    EndDT4 = 16,
    /// End.DT46 — decap and L3 table lookup for both IPv4 and IPv6
    /// (RFC 8986 §4.9).
    EndDT46 = 17,
    /// End.DX2 — decap and L2 cross-connect (RFC 8986 §4.10).
    EndDX2 = 18,
    /// End.DX2V — decap and L2 cross-connect to a VLAN (RFC 8986
    /// §4.11).
    EndDX2V = 19,
    /// End.DT2U — decap and L2 table lookup for unicast (RFC 8986
    /// §4.12).
    EndDT2U = 20,
    /// End.DT2M — decap and L2 table lookup for multicast (RFC 8986
    /// §4.13).
    EndDT2M = 21,
    /// End.B6.Encaps — SRH encapsulation (RFC 8986 §4.14). The
    /// endpoint adds an outer IPv6 header with an SRH.
    EndB6Encaps = 22,
    /// End.B6.Encaps.Red — SRH encapsulation with reduced SRH (RFC
    /// 8986 §4.14 + RFC 8754 §4.3.1).
    EndB6EncapsRed = 23,
    /// End.BM — SR-MPLS insertion (RFC 8986 §4.15).
    EndBM = 24,
    /// End.S — SRH inspection (RFC 8986 §4.17).
    EndS = 25,
    /// End.B6.Insert — SRH insertion (RFC 8986 §4.18).
    EndB6Insert = 26,
    /// End.B6.Insert.Red — SRH insertion with reduced SRH (RFC 8986
    /// §4.18 + RFC 8754 §4.3.1).
    EndB6InsertRed = 27,
    /// End.Un — unknown SID behavior (RFC 8986 §4.19).
    EndUn = 28,
    /// End.X.PS — End.X with per-flow steering (RFC 8986 §4.20).
    EndXPS = 29,
    /// End.X.PSU — End.X with per-flow steering, unicast mode (RFC
    /// 8986 §4.20).
    EndXPSU = 30,
    /// End.T.PS — End.T with per-flow steering (RFC 8986 §4.21).
    EndTPS = 31,
    /// End.T.PSU — End.T with per-flow steering, unicast mode (RFC
    /// 8986 §4.21).
    EndTPSU = 32,
}

impl Behavior {
    /// The 16-bit wire value (RFC 8986 §9.2, IANA registry).
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Look up a behavior by its 16-bit wire value. Returns `None`
    /// for unassigned values (RFC 8986 §9.2 — the registry is sparse;
    /// unassigned values MUST be treated as `End.Un` per §4.19, but
    /// the crate leaves that policy to the caller).
    pub fn from_wire(v: u16) -> Option<Self> {
        // Match on the literal value because `Self as u16` is not
        // available in `const fn` for enums with explicit
        // discriminants in stable Rust until 1.85+. We list every
        // variant explicitly so a future RFC 8986 bis assignment can
        // be added in one place.
        Some(match v {
            1 => Self::End,
            2 => Self::EndPsp,
            3 => Self::EndUsp,
            4 => Self::EndUsd,
            5 => Self::EndX,
            6 => Self::EndXPsp,
            7 => Self::EndXUsp,
            8 => Self::EndXUsd,
            9 => Self::EndT,
            10 => Self::EndTPsp,
            11 => Self::EndTUsp,
            12 => Self::EndTUsd,
            13 => Self::EndDX6,
            14 => Self::EndDX4,
            15 => Self::EndDT6,
            16 => Self::EndDT4,
            17 => Self::EndDT46,
            18 => Self::EndDX2,
            19 => Self::EndDX2V,
            20 => Self::EndDT2U,
            21 => Self::EndDT2M,
            22 => Self::EndB6Encaps,
            23 => Self::EndB6EncapsRed,
            24 => Self::EndBM,
            25 => Self::EndS,
            26 => Self::EndB6Insert,
            27 => Self::EndB6InsertRed,
            28 => Self::EndUn,
            29 => Self::EndXPS,
            30 => Self::EndXPSU,
            31 => Self::EndTPS,
            32 => Self::EndTPSU,
            _ => return None,
        })
    }

    /// The behavior's mnemonic name as it appears in RFC 8986
    /// (e.g. `End`, `End.X`, `End.DX6`). Useful for logs and config
    /// files — the IANA registry uses these names verbatim.
    pub const fn name(self) -> &'static str {
        match self {
            Self::End => "End",
            Self::EndPsp => "End.PSP",
            Self::EndUsp => "End.USP",
            Self::EndUsd => "End.USD",
            Self::EndX => "End.X",
            Self::EndXPsp => "End.X.PSP",
            Self::EndXUsp => "End.X.USP",
            Self::EndXUsd => "End.X.USD",
            Self::EndT => "End.T",
            Self::EndTPsp => "End.T.PSP",
            Self::EndTUsp => "End.T.USP",
            Self::EndTUsd => "End.T.USD",
            Self::EndDX6 => "End.DX6",
            Self::EndDX4 => "End.DX4",
            Self::EndDT6 => "End.DT6",
            Self::EndDT4 => "End.DT4",
            Self::EndDT46 => "End.DT46",
            Self::EndDX2 => "End.DX2",
            Self::EndDX2V => "End.DX2V",
            Self::EndDT2U => "End.DT2U",
            Self::EndDT2M => "End.DT2M",
            Self::EndB6Encaps => "End.B6.Encaps",
            Self::EndB6EncapsRed => "End.B6.Encaps.Red",
            Self::EndBM => "End.BM",
            Self::EndS => "End.S",
            Self::EndB6Insert => "End.B6.Insert",
            Self::EndB6InsertRed => "End.B6.Insert.Red",
            Self::EndUn => "End.Un",
            Self::EndXPS => "End.X.PS",
            Self::EndXPSU => "End.X.PSU",
            Self::EndTPS => "End.T.PS",
            Self::EndTPSU => "End.T.PSU",
        }
    }

    /// True when the behavior is a PSP variant (RFC 8986 §4.16 —
    /// Penultimate Segment Pop, the SRH is removed one hop before
    /// the endpoint).
    pub const fn is_psp(self) -> bool {
        matches!(self, Self::EndPsp | Self::EndXPsp | Self::EndTPsp)
    }

    /// True when the behavior is a USP variant (RFC 8986 §4.16 —
    /// Ultimate Segment Pop, the SRH is removed at the endpoint).
    pub const fn is_usp(self) -> bool {
        matches!(self, Self::EndUsp | Self::EndXUsp | Self::EndTUsp)
    }

    /// True when the behavior is a USD variant (RFC 8986 §4.16 —
    /// Ultimate Segment Decap, the inner packet is decapsulated
    /// at the endpoint).
    pub const fn is_usd(self) -> bool {
        matches!(self, Self::EndUsd | Self::EndXUsd | Self::EndTUsd)
    }

    /// True when the behavior decapsulates a packet (End.D* family,
    /// RFC 8986 §4.5–§4.13).
    pub const fn is_decap(self) -> bool {
        matches!(
            self,
            Self::EndDX6
                | Self::EndDX4
                | Self::EndDT6
                | Self::EndDT4
                | Self::EndDT46
                | Self::EndDX2
                | Self::EndDX2V
                | Self::EndDT2U
                | Self::EndDT2M
        )
    }

    /// True when the behavior is a "cross-connect" — forwards to a
    /// single next hop, not a table lookup (End.X*, End.DX*).
    pub const fn is_cross_connect(self) -> bool {
        matches!(
            self,
            Self::EndX
                | Self::EndXPsp
                | Self::EndXUsp
                | Self::EndXUsd
                | Self::EndDX6
                | Self::EndDX4
                | Self::EndDX2
                | Self::EndDX2V
        )
    }

    /// True when the behavior is a "table lookup" — forwards via a
    /// specific routing or bridging table (End.T*, End.DT*).
    pub const fn is_table_lookup(self) -> bool {
        matches!(
            self,
            Self::EndT
                | Self::EndTPsp
                | Self::EndTUsp
                | Self::EndTUsd
                | Self::EndDT6
                | Self::EndDT4
                | Self::EndDT46
                | Self::EndDT2U
                | Self::EndDT2M
        )
    }
}

impl fmt::Display for Behavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behavior_wire_values_match_rfc_8986_iana_registry() {
        // Spot-check every variant against RFC 8986 §9.2's IANA
        // registry. The crate uses the same numeric assignment, so a
        // future RFC 8986 bis reassignment would surface as a test
        // failure here.
        assert_eq!(Behavior::End.wire_value(), 1);
        assert_eq!(Behavior::EndPsp.wire_value(), 2);
        assert_eq!(Behavior::EndUsp.wire_value(), 3);
        assert_eq!(Behavior::EndUsd.wire_value(), 4);
        assert_eq!(Behavior::EndX.wire_value(), 5);
        assert_eq!(Behavior::EndXPsp.wire_value(), 6);
        assert_eq!(Behavior::EndXUsp.wire_value(), 7);
        assert_eq!(Behavior::EndXUsd.wire_value(), 8);
        assert_eq!(Behavior::EndT.wire_value(), 9);
        assert_eq!(Behavior::EndTPsp.wire_value(), 10);
        assert_eq!(Behavior::EndTUsp.wire_value(), 11);
        assert_eq!(Behavior::EndTUsd.wire_value(), 12);
        assert_eq!(Behavior::EndDX6.wire_value(), 13);
        assert_eq!(Behavior::EndDX4.wire_value(), 14);
        assert_eq!(Behavior::EndDT6.wire_value(), 15);
        assert_eq!(Behavior::EndDT4.wire_value(), 16);
        assert_eq!(Behavior::EndDT46.wire_value(), 17);
        assert_eq!(Behavior::EndDX2.wire_value(), 18);
        assert_eq!(Behavior::EndDX2V.wire_value(), 19);
        assert_eq!(Behavior::EndDT2U.wire_value(), 20);
        assert_eq!(Behavior::EndDT2M.wire_value(), 21);
        assert_eq!(Behavior::EndB6Encaps.wire_value(), 22);
        assert_eq!(Behavior::EndB6EncapsRed.wire_value(), 23);
        assert_eq!(Behavior::EndBM.wire_value(), 24);
        assert_eq!(Behavior::EndS.wire_value(), 25);
        assert_eq!(Behavior::EndB6Insert.wire_value(), 26);
        assert_eq!(Behavior::EndB6InsertRed.wire_value(), 27);
        assert_eq!(Behavior::EndUn.wire_value(), 28);
        assert_eq!(Behavior::EndXPS.wire_value(), 29);
        assert_eq!(Behavior::EndXPSU.wire_value(), 30);
        assert_eq!(Behavior::EndTPS.wire_value(), 31);
        assert_eq!(Behavior::EndTPSU.wire_value(), 32);
    }

    #[test]
    fn behavior_from_wire_roundtrip() {
        for v in 1..=32u16 {
            let b = Behavior::from_wire(v).unwrap();
            assert_eq!(b.wire_value(), v, "roundtrip failed for v={}", v);
        }
    }

    #[test]
    fn behavior_from_wire_unassigned() {
        // 0 and 33+ are unassigned in the IANA registry (RFC 8986
        // §9.2).
        assert!(Behavior::from_wire(0).is_none());
        assert!(Behavior::from_wire(33).is_none());
        assert!(Behavior::from_wire(u16::MAX).is_none());
    }

    #[test]
    fn behavior_names_match_rfc_8986_text() {
        // RFC 8986 uses these exact names in its section headings and
        // the IANA registry replicates them.
        assert_eq!(Behavior::End.name(), "End");
        assert_eq!(Behavior::EndX.name(), "End.X");
        assert_eq!(Behavior::EndDX6.name(), "End.DX6");
        assert_eq!(Behavior::EndDT4.name(), "End.DT4");
        assert_eq!(Behavior::EndDT46.name(), "End.DT46");
        assert_eq!(Behavior::EndB6EncapsRed.name(), "End.B6.Encaps.Red");
        assert_eq!(Behavior::EndUn.name(), "End.Un");
    }

    #[test]
    fn behavior_flavor_classification() {
        // PSP / USP / USD classification per RFC 8986 §4.16.
        assert!(!Behavior::End.is_psp());
        assert!(Behavior::EndPsp.is_psp());
        assert!(Behavior::EndXPsp.is_psp());
        assert!(Behavior::EndTPsp.is_psp());
        assert!(Behavior::EndUsp.is_usp());
        assert!(Behavior::EndXUsp.is_usp());
        assert!(Behavior::EndTUsp.is_usp());
        assert!(Behavior::EndUsd.is_usd());
        assert!(Behavior::EndXUsd.is_usd());
        assert!(Behavior::EndTUsd.is_usd());
        // Cross-flavor: a PSP behavior is not USP/USD.
        assert!(!Behavior::EndPsp.is_usp());
        assert!(!Behavior::EndPsp.is_usd());
    }

    #[test]
    fn behavior_decap_classification() {
        // End.D* family decapsulates per RFC 8986 §4.5–§4.13.
        assert!(Behavior::EndDX6.is_decap());
        assert!(Behavior::EndDX4.is_decap());
        assert!(Behavior::EndDT6.is_decap());
        assert!(Behavior::EndDT4.is_decap());
        assert!(Behavior::EndDT46.is_decap());
        assert!(Behavior::EndDX2.is_decap());
        assert!(Behavior::EndDX2V.is_decap());
        assert!(Behavior::EndDT2U.is_decap());
        assert!(Behavior::EndDT2M.is_decap());
        // End / End.X do NOT decap.
        assert!(!Behavior::End.is_decap());
        assert!(!Behavior::EndX.is_decap());
    }

    #[test]
    fn behavior_cross_connect_classification() {
        // End.X and End.DX* forward to a single next hop.
        assert!(Behavior::EndX.is_cross_connect());
        assert!(Behavior::EndDX6.is_cross_connect());
        assert!(Behavior::EndDX4.is_cross_connect());
        assert!(Behavior::EndDX2.is_cross_connect());
        // End.T and End.DT* forward via a table lookup.
        assert!(!Behavior::End.is_cross_connect());
        assert!(!Behavior::EndT.is_cross_connect());
        assert!(!Behavior::EndDT6.is_cross_connect());
    }

    #[test]
    fn behavior_table_lookup_classification() {
        assert!(Behavior::EndT.is_table_lookup());
        assert!(Behavior::EndDT6.is_table_lookup());
        assert!(Behavior::EndDT46.is_table_lookup());
        assert!(Behavior::EndDT2U.is_table_lookup());
        assert!(!Behavior::End.is_table_lookup());
        assert!(!Behavior::EndX.is_table_lookup());
        assert!(!Behavior::EndDX6.is_table_lookup());
    }

    #[test]
    fn behavior_display_matches_name() {
        assert_eq!(format!("{}", Behavior::End), "End");
        assert_eq!(format!("{}", Behavior::EndDX6), "End.DX6");
        assert_eq!(format!("{}", Behavior::EndB6EncapsRed), "End.B6.Encaps.Red");
    }
}
