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
//! ## Two numbering universes (read this before touching the wire)
//!
//! The IANA registry and the Linux kernel's `seg6local` netlink API
//! number the *same* behaviors differently:
//!
//! | Behavior   | IANA | Linux `SEG6_LOCAL_ACTION_*` |
//! |------------|------|------------------------------|
//! | End        | 1    | 1                            |
//! | End.X      | 5    | 2                            |
//! | End.T      | 9    | 3                            |
//! | End.DX6    | 16   | 5                            |
//! | End.DX4    | 17   | 6                            |
//! | End.DT6    | 18   | 7                            |
//!
//! The IANA values ride in control-plane identifiers (BGP-LS SRv6 SID
//! TLVs, SR Policy descriptors, the SID's FUNCT field). The kernel
//! values ride only in the `SEG6_LOCAL_ACTION` netlink attribute.
//! `lr-osroute::seg6_route` owns the translation between the two;
//! this crate must never encode a kernel value.
//!
//! The enum below carries the **IANA** values, verified line-by-line
//! against the live registry
//! (`https://www.iana.org/assignments/segment-routing/`): RFC 8986
//! assigned the contiguous block 1–24 plus 26–39 (25 is Reserved);
//! later RFCs appended from 40 (End.MAP/End.Limit, RFC 9433; the
//! NEXT-CSID family, RFC 9800). Unassigned values are `None` from
//! [`Behavior::from_wire`]; RFC 8986 §4.19 says the data plane treats
//! them as "End.Un" (count and drop), which is a *policy*, not a
//! registry value, so no variant is synthesized for it.
//!
//! ## PSP / USP / USD flavors
//!
//! RFC 8986 §4.16 defines three flavors; the registry assigns a
//! distinct value to each base+flavor combination that appears in the
//! spec (`End with PSP` = 2, `End.X with USP` = 7, … through
//! `End.T with PSP, USP & USD` = 39). The crate models each assigned
//! combination as its own variant, mirroring the registry's flat
//! structure, and exposes [`Behavior::is_psp`] / [`is_usp`] /
//! [`Behavior::is_usd`] classifiers for the flavor bits.

use core::fmt;

/// A 16-bit SRv6 Endpoint Behavior value (RFC 8986 §9.2, IANA's
/// "SRv6 Endpoint Behavior" registry).
///
/// The discriminant of each variant is the wire value (lower 16 bits
/// for the behavior, encoded as `behavior_value` via
/// [`Behavior::wire_value`]). The wire values match the IANA registry
/// exactly — the crate does not synthesize new ones. Value 25 is
/// Reserved by the registry and deliberately has no variant.
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
    /// End with PSP & USP (RFC 8986 §4.1 + §4.16).
    EndPspUsp = 4,
    /// End.X — Layer-3 cross-connect to a specific next hop (RFC 8986
    /// §4.2). Identical to `End` but forwards out a specific
    /// adjacency, not the IGP next-hop.
    EndX = 5,
    /// End.X with PSP (RFC 8986 §4.2 + §4.16).
    EndXPsp = 6,
    /// End.X with USP (RFC 8986 §4.2 + §4.16).
    EndXUsp = 7,
    /// End.X with PSP & USP (RFC 8986 §4.2 + §4.16).
    EndXPspUsp = 8,
    /// End.T — Layer-3 cross-connect to a specific table (RFC 8986
    /// §4.3). Forwards the packet by looking it up in a specific
    /// routing table.
    EndT = 9,
    /// End.T with PSP (RFC 8986 §4.3 + §4.16).
    EndTPsp = 10,
    /// End.T with USP (RFC 8986 §4.3 + §4.16).
    EndTUsp = 11,
    /// End.T with PSP & USP (RFC 8986 §4.3 + §4.16).
    EndTPspUsp = 12,
    /// End.B6.Insert — SRH insertion (RFC 8986 §4.14). The endpoint
    /// inserts the specified SRH into the packet.
    EndB6Insert = 13,
    /// End.B6.Encaps — SRH encapsulation (RFC 8986 §4.14). The
    /// endpoint adds an outer IPv6 header with an SRH.
    EndB6Encaps = 14,
    /// End.BM — SR-MPLS insertion (RFC 8986 §4.15).
    EndBM = 15,
    /// End.DX6 — decap and L3 cross-connect to an IPv6 next hop
    /// (RFC 8986 §4.5).
    EndDX6 = 16,
    /// End.DX4 — decap and L3 cross-connect to an IPv4 next hop
    /// (RFC 8986 §4.6).
    EndDX4 = 17,
    /// End.DT6 — decap and L3 table lookup for IPv6 (RFC 8986 §4.7).
    EndDT6 = 18,
    /// End.DT4 — decap and L3 table lookup for IPv4 (RFC 8986 §4.8).
    EndDT4 = 19,
    /// End.DT46 — decap and L3 table lookup for both IPv4 and IPv6
    /// (RFC 8986 §4.9).
    EndDT46 = 20,
    /// End.DX2 — decap and L2 cross-connect (RFC 8986 §4.10).
    EndDX2 = 21,
    /// End.DX2V — decap and L2 cross-connect to a VLAN (RFC 8986
    /// §4.11).
    EndDX2V = 22,
    /// End.DT2U — decap and L2 table lookup for unicast (RFC 8986
    /// §4.12).
    EndDT2U = 23,
    /// End.DT2M — decap and L2 table lookup for multicast (RFC 8986
    /// §4.13).
    EndDT2M = 24,
    // 25 is Reserved by the IANA registry — deliberately no variant.
    /// End.B6.Insert.Red — SRH insertion with reduced SRH (RFC 8986
    /// §4.14 + RFC 8754 §4.3.1).
    EndB6InsertRed = 26,
    /// End.B6.Encaps.Red — SRH encapsulation with reduced SRH (RFC
    /// 8986 §4.14 + RFC 8754 §4.3.1).
    EndB6EncapsRed = 27,
    /// End with USD (Ultimate Segment Decap) (RFC 8986 §4.1 + §4.16).
    EndUsd = 28,
    /// End with PSP & USD (RFC 8986 §4.1 + §4.16).
    EndPspUsd = 29,
    /// End with USP & USD (RFC 8986 §4.1 + §4.16).
    EndUspUsd = 30,
    /// End with PSP, USP & USD (RFC 8986 §4.1 + §4.16).
    EndPspUspUsd = 31,
    /// End.X with USD (RFC 8986 §4.2 + §4.16).
    EndXUsd = 32,
    /// End.X with PSP & USD (RFC 8986 §4.2 + §4.16).
    EndXPspUsd = 33,
    /// End.X with USP & USD (RFC 8986 §4.2 + §4.16).
    EndXUspUsd = 34,
    /// End.X with PSP, USP & USD (RFC 8986 §4.2 + §4.16).
    EndXPspUspUsd = 35,
    /// End.T with USD (RFC 8986 §4.3 + §4.16).
    EndTUsd = 36,
    /// End.T with PSP & USD (RFC 8986 §4.3 + §4.16).
    EndTPspUsd = 37,
    /// End.T with USP & USD (RFC 8986 §4.3 + §4.16).
    EndTUspUsd = 38,
    /// End.T with PSP, USP & USD (RFC 8986 §4.3 + §4.16).
    EndTPspUspUsd = 39,
    // Later RFC assignments (40 End.MAP / 41 End.Limit — RFC 9433;
    // the NEXT-CSID family — RFC 9800) are not modelled yet; add them
    // here with their registry values when needed.
}

impl Behavior {
    /// The 16-bit wire value (RFC 8986 §9.2, IANA registry).
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Look up a behavior by its 16-bit wire value. Returns `None`
    /// for unassigned values (RFC 8986 §9.2 — the registry is sparse:
    /// 0 is invalid, 25 is Reserved, and everything ≥ 40 currently
    /// unassigned by this crate is either a later-RFC assignment the
    /// crate does not model or genuinely unallocated; both MUST be
    /// treated as `End.Un` per §4.19 by data-plane policy, but the
    /// crate leaves that decision to the caller).
    pub fn from_wire(v: u16) -> Option<Self> {
        // Match on the literal value so the mapping stays a
        // reviewable transcript of the registry itself.
        Some(match v {
            1 => Self::End,
            2 => Self::EndPsp,
            3 => Self::EndUsp,
            4 => Self::EndPspUsp,
            5 => Self::EndX,
            6 => Self::EndXPsp,
            7 => Self::EndXUsp,
            8 => Self::EndXPspUsp,
            9 => Self::EndT,
            10 => Self::EndTPsp,
            11 => Self::EndTUsp,
            12 => Self::EndTPspUsp,
            13 => Self::EndB6Insert,
            14 => Self::EndB6Encaps,
            15 => Self::EndBM,
            16 => Self::EndDX6,
            17 => Self::EndDX4,
            18 => Self::EndDT6,
            19 => Self::EndDT4,
            20 => Self::EndDT46,
            21 => Self::EndDX2,
            22 => Self::EndDX2V,
            23 => Self::EndDT2U,
            24 => Self::EndDT2M,
            26 => Self::EndB6InsertRed,
            27 => Self::EndB6EncapsRed,
            28 => Self::EndUsd,
            29 => Self::EndPspUsd,
            30 => Self::EndUspUsd,
            31 => Self::EndPspUspUsd,
            32 => Self::EndXUsd,
            33 => Self::EndXPspUsd,
            34 => Self::EndXUspUsd,
            35 => Self::EndXPspUspUsd,
            36 => Self::EndTUsd,
            37 => Self::EndTPspUsd,
            38 => Self::EndTUspUsd,
            39 => Self::EndTPspUspUsd,
            _ => return None,
        })
    }

    /// The behavior's mnemonic name exactly as the IANA registry
    /// spells it (e.g. `End`, `End.X`, `End with PSP`, `End.DX6`).
    /// Useful for logs and config files.
    pub const fn name(self) -> &'static str {
        match self {
            Self::End => "End",
            Self::EndPsp => "End with PSP",
            Self::EndUsp => "End with USP",
            Self::EndPspUsp => "End with PSP & USP",
            Self::EndX => "End.X",
            Self::EndXPsp => "End.X with PSP",
            Self::EndXUsp => "End.X with USP",
            Self::EndXPspUsp => "End.X with PSP & USP",
            Self::EndT => "End.T",
            Self::EndTPsp => "End.T with PSP",
            Self::EndTUsp => "End.T with USP",
            Self::EndTPspUsp => "End.T with PSP & USP",
            Self::EndB6Insert => "End.B6.Insert",
            Self::EndB6Encaps => "End.B6.Encaps",
            Self::EndBM => "End.BM",
            Self::EndDX6 => "End.DX6",
            Self::EndDX4 => "End.DX4",
            Self::EndDT6 => "End.DT6",
            Self::EndDT4 => "End.DT4",
            Self::EndDT46 => "End.DT46",
            Self::EndDX2 => "End.DX2",
            Self::EndDX2V => "End.DX2V",
            Self::EndDT2U => "End.DT2U",
            Self::EndDT2M => "End.DT2M",
            Self::EndB6InsertRed => "End.B6.Insert.Red",
            Self::EndB6EncapsRed => "End.B6.Encaps.Red",
            Self::EndUsd => "End with USD",
            Self::EndPspUsd => "End with PSP & USD",
            Self::EndUspUsd => "End with USP & USD",
            Self::EndPspUspUsd => "End with PSP, USP & USD",
            Self::EndXUsd => "End.X with USD",
            Self::EndXPspUsd => "End.X with PSP & USD",
            Self::EndXUspUsd => "End.X with USP & USD",
            Self::EndXPspUspUsd => "End.X with PSP, USP & USD",
            Self::EndTUsd => "End.T with USD",
            Self::EndTPspUsd => "End.T with PSP & USD",
            Self::EndTUspUsd => "End.T with USP & USD",
            Self::EndTPspUspUsd => "End.T with PSP, USP & USD",
        }
    }

    /// True when the behavior carries the PSP flavor (RFC 8986
    /// §4.16 — Penultimate Segment Pop, the SRH is removed one hop
    /// before the endpoint).
    pub const fn is_psp(self) -> bool {
        matches!(
            self,
            Self::EndPsp
                | Self::EndPspUsp
                | Self::EndPspUsd
                | Self::EndPspUspUsd
                | Self::EndXPsp
                | Self::EndXPspUsp
                | Self::EndXPspUsd
                | Self::EndXPspUspUsd
                | Self::EndTPsp
                | Self::EndTPspUsp
                | Self::EndTPspUsd
                | Self::EndTPspUspUsd
        )
    }

    /// True when the behavior carries the USP flavor (RFC 8986
    /// §4.16 — Ultimate Segment Pop, the SRH is removed at the
    /// endpoint).
    pub const fn is_usp(self) -> bool {
        matches!(
            self,
            Self::EndUsp
                | Self::EndPspUsp
                | Self::EndUspUsd
                | Self::EndPspUspUsd
                | Self::EndXUsp
                | Self::EndXPspUsp
                | Self::EndXUspUsd
                | Self::EndXPspUspUsd
                | Self::EndTUsp
                | Self::EndTPspUsp
                | Self::EndTUspUsd
                | Self::EndTPspUspUsd
        )
    }

    /// True when the behavior carries the USD flavor (RFC 8986
    /// §4.16 — Ultimate Segment Decap, the inner packet is
    /// decapsulated at the endpoint).
    pub const fn is_usd(self) -> bool {
        matches!(
            self,
            Self::EndUsd
                | Self::EndPspUsd
                | Self::EndUspUsd
                | Self::EndPspUspUsd
                | Self::EndXUsd
                | Self::EndXPspUsd
                | Self::EndXUspUsd
                | Self::EndXPspUspUsd
                | Self::EndTUsd
                | Self::EndTPspUsd
                | Self::EndTUspUsd
                | Self::EndTPspUspUsd
        )
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
                | Self::EndXPspUsp
                | Self::EndXUsd
                | Self::EndXPspUsd
                | Self::EndXUspUsd
                | Self::EndXPspUspUsd
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
                | Self::EndTPspUsp
                | Self::EndTUsd
                | Self::EndTPspUsd
                | Self::EndTUspUsd
                | Self::EndTPspUspUsd
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

    /// Every assigned value in RFC 8986's block, checked against the
    /// live IANA registry (segment-routing page, "SRv6 Endpoint
    /// Behaviors" table). 25 is Reserved and MUST stay absent.
    const RFC_8986_ASSIGNMENTS: &[(u16, &str)] = &[
        (1, "End"),
        (2, "End with PSP"),
        (3, "End with USP"),
        (4, "End with PSP & USP"),
        (5, "End.X"),
        (6, "End.X with PSP"),
        (7, "End.X with USP"),
        (8, "End.X with PSP & USP"),
        (9, "End.T"),
        (10, "End.T with PSP"),
        (11, "End.T with USP"),
        (12, "End.T with PSP & USP"),
        (13, "End.B6.Insert"),
        (14, "End.B6.Encaps"),
        (15, "End.BM"),
        (16, "End.DX6"),
        (17, "End.DX4"),
        (18, "End.DT6"),
        (19, "End.DT4"),
        (20, "End.DT46"),
        (21, "End.DX2"),
        (22, "End.DX2V"),
        (23, "End.DT2U"),
        (24, "End.DT2M"),
        (26, "End.B6.Insert.Red"),
        (27, "End.B6.Encaps.Red"),
        (28, "End with USD"),
        (29, "End with PSP & USD"),
        (30, "End with USP & USD"),
        (31, "End with PSP, USP & USD"),
        (32, "End.X with USD"),
        (33, "End.X with PSP & USD"),
        (34, "End.X with USP & USD"),
        (35, "End.X with PSP, USP & USD"),
        (36, "End.T with USD"),
        (37, "End.T with PSP & USD"),
        (38, "End.T with USP & USD"),
        (39, "End.T with PSP, USP & USD"),
    ];

    #[test]
    fn behavior_wire_values_match_rfc_8986_iana_registry() {
        // Every registry assignment round-trips through the enum with
        // the exact value and the exact registry name.
        for (v, name) in RFC_8986_ASSIGNMENTS {
            let b = Behavior::from_wire(*v).unwrap_or_else(|| {
                panic!("registry value {v} ({name}) has no variant");
            });
            assert_eq!(b.wire_value(), *v, "{name}: wire value drifted");
            assert_eq!(b.name(), *name, "value {v}: name drifted from the registry");
        }
    }

    #[test]
    fn behavior_registry_block_is_fully_modelled() {
        // 1-24 and 26-39 are all assigned by RFC 8986 and all modelled;
        // 25 is Reserved; 0 is invalid; 40+ are later/unassigned.
        let mut assigned = 0;
        for v in 1..=39u16 {
            let has = Behavior::from_wire(v).is_some();
            if v == 25 {
                assert!(!has, "25 is Reserved by IANA — must have no variant");
            } else {
                assert!(has, "RFC 8986 assignment {v} is missing a variant");
                assigned += 1;
            }
        }
        assert_eq!(assigned, 38, "RFC 8986 assigned 38 values (1-24, 26-39)");
    }

    #[test]
    fn behavior_from_wire_unassigned() {
        // 0 is invalid, 25 Reserved, 40+ unassigned-or-unmodelled,
        // and the registry's high ranges (32768+ Private Use is the
        // only other populated block) are not behaviors either.
        assert!(Behavior::from_wire(0).is_none());
        assert!(Behavior::from_wire(25).is_none());
        assert!(Behavior::from_wire(40).is_none());
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
    }

    #[test]
    fn behavior_flavor_classification() {
        // PSP / USP / USD classification per RFC 8986 §4.16.
        assert!(!Behavior::End.is_psp());
        assert!(Behavior::EndPsp.is_psp());
        assert!(Behavior::EndXPsp.is_psp());
        assert!(Behavior::EndTPsp.is_psp());
        // Combined flavors carry every bit they name.
        assert!(Behavior::EndPspUsp.is_psp() && Behavior::EndPspUsp.is_usp());
        assert!(Behavior::EndPspUspUsd.is_psp() && Behavior::EndPspUspUsd.is_usp());
        assert!(Behavior::EndPspUspUsd.is_usd());
        assert!(Behavior::EndXUsd.is_usd());
        assert!(Behavior::EndTUsd.is_usd());
        // Cross-flavor: a PSP-only behavior is not USP/USD.
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
        assert_eq!(format!("{}", Behavior::EndUsd), "End with USD");
    }
}
