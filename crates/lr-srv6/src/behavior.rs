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
//! RFC 9433 appended 40 (End.MAP) and 41 (End.Limit) for the 3GPP
//! mobile user plane. RFC 9800 (Compressed SRv6 Segment-List
//! Encoding) appends the NEXT-CSID family at 43–50, 52–59, 85–97
//! (End / End.X / End.T with NEXT-CSID plus their flavor
//! combinations, plus End.B6.Encaps / End.B6.Encaps.Red / End.BM /
//! End.LBS / End.XLBS with NEXT-CSID). RFC 10018 appends End.DTMC4 /
//! End.DTMC6 / End.DTMC46 at 76–78 (decap to an MPLS table). The
//! draft-only assignments at 42 / 51 / 60-68 (NEXT-ONLY-CSID and
//! uDX/uDT — pre-RFC 9800 draft), the GTP family at 69-72 (RFC 9433
//! §6.4-§6.7 — needs a GTP argument layout the crate does not
//! model), and the REPLACE-CSID family at 101-141 (RFC 9800's
//! second flavor — same structure as NEXT-CSID but a separate
//! container layout) are not yet modelled here. Unassigned values
//! are `None` from [`Behavior::from_wire`]; RFC 8986 §4.19 says the
//! data plane treats them as "End.Un" (count and drop), which is a
//! *policy*, not a registry value, so no variant is synthesized for
//! it.
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
    /// End.MAP — SRv6 mobile user-plane mapping (RFC 9433 §6.2).
    /// The endpoint replaces the active SID (a per-PDU-session
    /// anchoring SID) with the next-hop SID stored in its local
    /// mapping table, then forwards. Used in 3GPP mobile user-plane
    /// interworking to chain UPFs without re-encapsulating.
    EndMap = 40,
    /// End.Limit — per-session rate-limit (RFC 9433 §6.8). Rate-
    /// limits traffic destined to the SID by the configured policy,
    /// letting the operator cap the bandwidth consumed by a mobile
    /// session independently of forwarding. The packet is otherwise
    /// processed as `End` (RFC 8986 §4.1).
    EndLimit = 41,
    // 42 is End with NEXT-ONLY-CSID (draft-filsfils-spring-net-pgm-
    // extension-srv6-usid) — pre-RFC 9800 draft assignment. RFC 9800
    // obsoleted the draft with a fresh block starting at 43; 42 stays
    // unmodelled (the registry still carries the draft entry, but no
    // RFC references it).
    /// End with NEXT-CSID (RFC 9800 §4.1.1). The NEXT-CSID flavor lets
    /// a single 128-bit SID carry a sequence of short C-SIDs that the
    /// endpoint walks in place — the segment-list compression the
    /// RFC introduces. End with NEXT-CSID is the basic End behavior
    /// with the NEXT-CSID flavor.
    EndWithNextCsid = 43,
    /// End with NEXT-CSID & PSP (RFC 9800 §4.1.1 + §4.16).
    EndWithNextCsidPsp = 44,
    /// End with NEXT-CSID & USP (RFC 9800 §4.1.1 + §4.16).
    EndWithNextCsidUsp = 45,
    /// End with NEXT-CSID, PSP & USP (RFC 9800 §4.1.1 + §4.16).
    EndWithNextCsidPspUsp = 46,
    /// End with NEXT-CSID & USD (RFC 9800 §4.1.1 + §4.16).
    EndWithNextCsidUsd = 47,
    /// End with NEXT-CSID, PSP & USD (RFC 9800 §4.1.1 + §4.16). The
    /// common short name in deployments is `uN` (uNode) — most SRv6
    /// implementations install this variant as the per-node SID.
    EndWithNextCsidPspUsd = 48,
    /// End with NEXT-CSID, USP & USD (RFC 9800 §4.1.1 + §4.16).
    EndWithNextCsidUspUsd = 49,
    /// End with NEXT-CSID, PSP, USP & USD (RFC 9800 §4.1.1 + §4.16).
    EndWithNextCsidPspUspUsd = 50,
    // 51 is End.X with NEXT-ONLY-CSID (draft-filsfils-spring-net-pgm-
    // extension-srv6-usid) — pre-RFC 9800 draft. Same reason as 42.
    /// End.X with NEXT-CSID (RFC 9800 §4.2.1). Cross-connect to a
    /// specific adjacency with the NEXT-CSID flavor.
    EndXWithNextCsid = 52,
    /// End.X with NEXT-CSID & PSP (RFC 9800 §4.2.1 + §4.16).
    EndXWithNextCsidPsp = 53,
    /// End.X with NEXT-CSID & USP (RFC 9800 §4.2.1 + §4.16).
    EndXWithNextCsidUsp = 54,
    /// End.X with NEXT-CSID, PSP & USP (RFC 9800 §4.2.1 + §4.16).
    EndXWithNextCsidPspUsp = 55,
    /// End.X with NEXT-CSID & USD (RFC 9800 §4.2.1 + §4.16).
    EndXWithNextCsidUsd = 56,
    /// End.X with NEXT-CSID, PSP & USD (RFC 9800 §4.2.1 + §4.16). The
    /// common short name in deployments is `uA` (uAdjacency).
    EndXWithNextCsidPspUsd = 57,
    /// End.X with NEXT-CSID, USP & USD (RFC 9800 §4.2.1 + §4.16).
    EndXWithNextCsidUspUsd = 58,
    /// End.X with NEXT-CSID, PSP, USP & USD (RFC 9800 §4.2.1 + §4.16).
    EndXWithNextCsidPspUspUsd = 59,
    // 60-68 are the uDX/uDT family from the same pre-RFC 9800 draft
    // (draft-filsfils-spring-net-pgm-extension-srv6-usid). RFC 9800
    // obsoleted the draft; the registry still carries the draft
    // entries but no RFC references them. Left unmodelled.
    // 69-72 are End.M.GTP6.D / End.M.GTP6.Di / End.M.GTP6.E /
    // End.M.GTP4.E (RFC 9433 §6.4-§6.7 — 3GPP mobile user-plane GTP
    // interworking). They depend on a GTP-specific argument layout
    // the crate does not model; left for a follow-up that lands the
    // GTP container layout alongside the variants.
    // 73-75 are draft assignments (End.DTM, End.M Mirror, End.Replicate
    // — RFC 9524). RFC 9524's End.Replicate will land in a follow-up
    // alongside its replication-group state model.
    /// End.DTMC4 — decap and MPLS table lookup for IPv4 (RFC 10018
    /// §4.1). The decap-and-table-lookup variant whose forwarding
    /// result is an MPLS label stack instead of an L3 next hop —
    /// used in SRv6-MPLS interworking where the inner packet is
    /// MPLS-encapsulated.
    EndDtmc4 = 76,
    /// End.DTMC6 — decap and MPLS table lookup for IPv6 (RFC 10018
    /// §4.2). Same shape as `End.DTMC4` for IPv6 payloads.
    EndDtmc6 = 77,
    /// End.DTMC46 — decap and MPLS table lookup for both IPv4 and
    /// IPv6 (RFC 10018 §4.3). The dual-family variant.
    EndDtmc46 = 78,
    // 79-84 are draft / RFC 9491 (End.BXC, End.NSH) assignments that
    // depend on argument layouts the crate does not model; left for
    // follow-ups that land the layout alongside the variant.
    /// End.T with NEXT-CSID (RFC 9800 §4.3.1). Table lookup with the
    /// NEXT-CSID flavor.
    EndTWithNextCsid = 85,
    /// End.T with NEXT-CSID & PSP (RFC 9800 §4.3.1 + §4.16).
    EndTWithNextCsidPsp = 86,
    /// End.T with NEXT-CSID & USP (RFC 9800 §4.3.1 + §4.16).
    EndTWithNextCsidUsp = 87,
    /// End.T with NEXT-CSID, PSP & USP (RFC 9800 §4.3.1 + §4.16).
    EndTWithNextCsidPspUsp = 88,
    /// End.T with NEXT-CSID & USD (RFC 9800 §4.3.1 + §4.16).
    EndTWithNextCsidUsd = 89,
    /// End.T with NEXT-CSID, PSP & USD (RFC 9800 §4.3.1 + §4.16).
    EndTWithNextCsidPspUsd = 90,
    /// End.T with NEXT-CSID, USP & USD (RFC 9800 §4.3.1 + §4.16).
    EndTWithNextCsidUspUsd = 91,
    /// End.T with NEXT-CSID, PSP, USP & USD (RFC 9800 §4.3.1 + §4.16).
    EndTWithNextCsidPspUspUsd = 92,
    /// End.B6.Encaps with NEXT-CSID (RFC 9800 §4.14). SRH
    /// encapsulation with the NEXT-CSID flavor.
    EndB6EncapsWithNextCsid = 93,
    /// End.B6.Encaps.Red with NEXT-CSID (RFC 9800 §4.14). Reduced-SRH
    /// encapsulation with NEXT-CSID.
    EndB6EncapsRedWithNextCsid = 94,
    /// End.BM with NEXT-CSID (RFC 9800 §4.15). SR-MPLS insertion with
    /// NEXT-CSID.
    EndBmWithNextCsid = 95,
    /// End.LBS with NEXT-CSID (RFC 9800 §4.4). Locator-Block swap
    /// under the NEXT-CSID flavor — the endpoint rewrites the
    /// locator-block portion of the active SID sequence, letting a
    /// multi-domain path cross locator-block boundaries without
    /// popping.
    EndLbsWithNextCsid = 96,
    /// End.XLBS with NEXT-CSID (RFC 9800 §4.5). The cross-connect
    /// variant of End.LBS — swaps the locator block and forwards out
    /// a specific adjacency.
    EndXlbsWithNextCsid = 97,
    // 98-100 are pre-RFC draft assignments (End.B6.Encaps.Red /
    // End.B6.Insert.Red with NEXT-CSID, PSP & USD; End.PSID). 100 is
    // draft-ietf-spring-srv6-path-segment. Left for follow-ups.
    // 101-141 (REPLACE-CSID family from RFC 9800) — the second flavor
    // RFC 9800 introduces. Same structure as the NEXT-CSID family
    // (End/End.X/End.T with REPLACE-CSID + flavor combinations, plus
    // the End.DX*/End.DT* REPLACE-CSID forms and End.LBS/XLBS with
    // REPLACE-CSID). Left for a follow-up so the model can land the
    // REPLACE-CSID container layout (RFC 9800 §5) alongside the
    // variants.
    // 158-160 are RFC 9801 (End.DX1 family). Left for a follow-up.
}

impl Behavior {
    /// The 16-bit wire value (RFC 8986 §9.2, IANA registry).
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    /// Look up a behavior by its 16-bit wire value. Returns `None`
    /// for unassigned values (RFC 8986 §9.2 — the registry is sparse:
    /// 0 is invalid, 25 is Reserved; the draft-only assignments at
    /// 42 / 51 / 60-68 / 73-75 / 79-84 / 98-100 and the REPLACE-CSID
    /// family at 101-141 / RFC 9801 family at 158-160 are not yet
    /// modelled here, and per §4.19 the data plane treats them as
    /// `End.Un` — the crate leaves that decision to the caller).
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
            40 => Self::EndMap,
            41 => Self::EndLimit,
            // RFC 9800 NEXT-CSID family (End / End.X / End.T with
            // NEXT-CSID + flavor combinations, plus End.B6.Encaps /
            // End.B6.Encaps.Red / End.BM / End.LBS / End.XLBS with
            // NEXT-CSID).
            43 => Self::EndWithNextCsid,
            44 => Self::EndWithNextCsidPsp,
            45 => Self::EndWithNextCsidUsp,
            46 => Self::EndWithNextCsidPspUsp,
            47 => Self::EndWithNextCsidUsd,
            48 => Self::EndWithNextCsidPspUsd,
            49 => Self::EndWithNextCsidUspUsd,
            50 => Self::EndWithNextCsidPspUspUsd,
            52 => Self::EndXWithNextCsid,
            53 => Self::EndXWithNextCsidPsp,
            54 => Self::EndXWithNextCsidUsp,
            55 => Self::EndXWithNextCsidPspUsp,
            56 => Self::EndXWithNextCsidUsd,
            57 => Self::EndXWithNextCsidPspUsd,
            58 => Self::EndXWithNextCsidUspUsd,
            59 => Self::EndXWithNextCsidPspUspUsd,
            // RFC 10018 End.DTMC family (decap to MPLS table).
            76 => Self::EndDtmc4,
            77 => Self::EndDtmc6,
            78 => Self::EndDtmc46,
            85 => Self::EndTWithNextCsid,
            86 => Self::EndTWithNextCsidPsp,
            87 => Self::EndTWithNextCsidUsp,
            88 => Self::EndTWithNextCsidPspUsp,
            89 => Self::EndTWithNextCsidUsd,
            90 => Self::EndTWithNextCsidPspUsd,
            91 => Self::EndTWithNextCsidUspUsd,
            92 => Self::EndTWithNextCsidPspUspUsd,
            93 => Self::EndB6EncapsWithNextCsid,
            94 => Self::EndB6EncapsRedWithNextCsid,
            95 => Self::EndBmWithNextCsid,
            96 => Self::EndLbsWithNextCsid,
            97 => Self::EndXlbsWithNextCsid,
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
            Self::EndMap => "End.MAP",
            Self::EndLimit => "End.Limit",
            // RFC 9800 NEXT-CSID family — names match the IANA
            // registry verbatim ("End with NEXT-CSID", etc.).
            Self::EndWithNextCsid => "End with NEXT-CSID",
            Self::EndWithNextCsidPsp => "End with NEXT-CSID & PSP",
            Self::EndWithNextCsidUsp => "End with NEXT-CSID & USP",
            Self::EndWithNextCsidPspUsp => "End with NEXT-CSID, PSP & USP",
            Self::EndWithNextCsidUsd => "End with NEXT-CSID & USD",
            Self::EndWithNextCsidPspUsd => "End with NEXT-CSID, PSP & USD",
            Self::EndWithNextCsidUspUsd => "End with NEXT-CSID, USP & USD",
            Self::EndWithNextCsidPspUspUsd => "End with NEXT-CSID, PSP, USP & USD",
            Self::EndXWithNextCsid => "End.X with NEXT-CSID",
            Self::EndXWithNextCsidPsp => "End.X with NEXT-CSID & PSP",
            Self::EndXWithNextCsidUsp => "End.X with NEXT-CSID & USP",
            Self::EndXWithNextCsidPspUsp => "End.X with NEXT-CSID, PSP & USP",
            Self::EndXWithNextCsidUsd => "End.X with NEXT-CSID & USD",
            Self::EndXWithNextCsidPspUsd => "End.X with NEXT-CSID, PSP & USD",
            Self::EndXWithNextCsidUspUsd => "End.X with NEXT-CSID, USP & USD",
            Self::EndXWithNextCsidPspUspUsd => "End.X with NEXT-CSID, PSP, USP & USD",
            // RFC 10018 End.DTMC family.
            Self::EndDtmc4 => "End.DTMC4",
            Self::EndDtmc6 => "End.DTMC6",
            Self::EndDtmc46 => "End.DTMC46",
            // RFC 9800 End.T with NEXT-CSID and the B6/BM/LBS/XLBS
            // NEXT-CSID variants.
            Self::EndTWithNextCsid => "End.T with NEXT-CSID",
            Self::EndTWithNextCsidPsp => "End.T with NEXT-CSID & PSP",
            Self::EndTWithNextCsidUsp => "End.T with NEXT-CSID & USP",
            Self::EndTWithNextCsidPspUsp => "End.T with NEXT-CSID, PSP & USP",
            Self::EndTWithNextCsidUsd => "End.T with NEXT-CSID & USD",
            Self::EndTWithNextCsidPspUsd => "End.T with NEXT-CSID, PSP & USD",
            Self::EndTWithNextCsidUspUsd => "End.T with NEXT-CSID, USP & USD",
            Self::EndTWithNextCsidPspUspUsd => "End.T with NEXT-CSID, PSP, USP & USD",
            Self::EndB6EncapsWithNextCsid => "End.B6.Encaps with NEXT-CSID",
            Self::EndB6EncapsRedWithNextCsid => "End.B6.Encaps.Red with NEXT-CSID",
            Self::EndBmWithNextCsid => "End.BM with NEXT-CSID",
            Self::EndLbsWithNextCsid => "End.LBS with NEXT-CSID",
            Self::EndXlbsWithNextCsid => "End.XLBS with NEXT-CSID",
        }
    }

    /// True when the behavior carries the PSP flavor (RFC 8986
    /// §4.16 — Penultimate Segment Pop, the SRH is removed one hop
    /// before the endpoint). Includes the NEXT-CSID variants whose
    /// name carries PSP (RFC 9800 §4.16 reuses the same flavor bits).
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
                | Self::EndWithNextCsidPsp
                | Self::EndWithNextCsidPspUsp
                | Self::EndWithNextCsidPspUsd
                | Self::EndWithNextCsidPspUspUsd
                | Self::EndXWithNextCsidPsp
                | Self::EndXWithNextCsidPspUsp
                | Self::EndXWithNextCsidPspUsd
                | Self::EndXWithNextCsidPspUspUsd
                | Self::EndTWithNextCsidPsp
                | Self::EndTWithNextCsidPspUsp
                | Self::EndTWithNextCsidPspUsd
                | Self::EndTWithNextCsidPspUspUsd
        )
    }

    /// True when the behavior carries the USP flavor (RFC 8986
    /// §4.16 — Ultimate Segment Pop, the SRH is removed at the
    /// endpoint). Includes the NEXT-CSID variants whose name carries
    /// USP (RFC 9800 §4.16 reuses the same flavor bits).
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
                | Self::EndWithNextCsidUsp
                | Self::EndWithNextCsidPspUsp
                | Self::EndWithNextCsidUspUsd
                | Self::EndWithNextCsidPspUspUsd
                | Self::EndXWithNextCsidUsp
                | Self::EndXWithNextCsidPspUsp
                | Self::EndXWithNextCsidUspUsd
                | Self::EndXWithNextCsidPspUspUsd
                | Self::EndTWithNextCsidUsp
                | Self::EndTWithNextCsidPspUsp
                | Self::EndTWithNextCsidUspUsd
                | Self::EndTWithNextCsidPspUspUsd
        )
    }

    /// True when the behavior carries the USD flavor (RFC 8986
    /// §4.16 — Ultimate Segment Decap, the inner packet is
    /// decapsulated at the endpoint). Includes the NEXT-CSID variants
    /// whose name carries USD (RFC 9800 §4.16 reuses the same flavor
    /// bits).
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
                | Self::EndWithNextCsidUsd
                | Self::EndWithNextCsidPspUsd
                | Self::EndWithNextCsidUspUsd
                | Self::EndWithNextCsidPspUspUsd
                | Self::EndXWithNextCsidUsd
                | Self::EndXWithNextCsidPspUsd
                | Self::EndXWithNextCsidUspUsd
                | Self::EndXWithNextCsidPspUspUsd
                | Self::EndTWithNextCsidUsd
                | Self::EndTWithNextCsidPspUsd
                | Self::EndTWithNextCsidUspUsd
                | Self::EndTWithNextCsidPspUspUsd
        )
    }

    /// True when the behavior decapsulates a packet (End.D*
    /// family, RFC 8986 §4.5–§4.13). Includes the End.DTMC family
    /// (RFC 10018 — decap to an MPLS table).
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
                | Self::EndDtmc4
                | Self::EndDtmc6
                | Self::EndDtmc46
        )
    }

    /// True when the behavior is a "cross-connect" — forwards to a
    /// single next hop, not a table lookup (End.X*, End.DX*). Includes
    /// the End.X with NEXT-CSID family (RFC 9800 §4.2.1).
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
                | Self::EndXWithNextCsid
                | Self::EndXWithNextCsidPsp
                | Self::EndXWithNextCsidUsp
                | Self::EndXWithNextCsidPspUsp
                | Self::EndXWithNextCsidUsd
                | Self::EndXWithNextCsidPspUsd
                | Self::EndXWithNextCsidUspUsd
                | Self::EndXWithNextCsidPspUspUsd
        )
    }

    /// True when the behavior is a "table lookup" — forwards via a
    /// specific routing or bridging table (End.T*, End.DT*). Includes
    /// the End.T with NEXT-CSID family (RFC 9800 §4.3.1) and the
    /// End.DTMC family (RFC 10018 — decap to an MPLS table).
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
                | Self::EndTWithNextCsid
                | Self::EndTWithNextCsidPsp
                | Self::EndTWithNextCsidUsp
                | Self::EndTWithNextCsidPspUsp
                | Self::EndTWithNextCsidUsd
                | Self::EndTWithNextCsidPspUsd
                | Self::EndTWithNextCsidUspUsd
                | Self::EndTWithNextCsidPspUspUsd
                | Self::EndDtmc4
                | Self::EndDtmc6
                | Self::EndDtmc46
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
        // 0 is invalid, 25 Reserved, 42 / 51 / 60-68 are draft-only
        // assignments (pre-RFC 9800 NEXT-ONLY-CSID and uDX/uDT)
        // deliberately not modelled, 69-72 are RFC 9433 GTP family
        // (not modelled — needs GTP argument layout), 73-75 / 79-84 /
        // 98-100 are draft assignments not modelled. The REPLACE-CSID
        // family at 101-141 is RFC 9800's second flavor, also not
        // modelled yet (separate container layout). The registry's
        // high ranges (32768+ Private Use) are not behaviors either.
        assert!(Behavior::from_wire(0).is_none());
        assert!(Behavior::from_wire(25).is_none());
        assert!(
            Behavior::from_wire(42).is_none(),
            "42 = End with NEXT-ONLY-CSID (draft, pre-RFC 9800) — not modelled"
        );
        assert!(
            Behavior::from_wire(51).is_none(),
            "51 = End.X with NEXT-ONLY-CSID (draft) — not modelled"
        );
        assert!(
            Behavior::from_wire(60).is_none(),
            "60 = uDX6 (draft) — not modelled"
        );
        assert!(
            Behavior::from_wire(69).is_none(),
            "69 = End.M.GTP6.D (RFC 9433) — not modelled"
        );
        assert!(
            Behavior::from_wire(72).is_none(),
            "72 = End.M.GTP4.E (RFC 9433) — not modelled"
        );
        assert!(
            Behavior::from_wire(101).is_none(),
            "101 = End with REPLACE-CSID (RFC 9800) — not modelled yet"
        );
        assert!(Behavior::from_wire(u16::MAX).is_none());
    }

    /// RFC 9433 §6.2 (End.MAP) and §6.8 (End.Limit) wire values,
    /// checked against the live IANA registry:
    /// <https://www.iana.org/assignments/segment-routing/srv6-endpoint-behaviors.csv>
    /// (rows `40,0x0028,End.MAP,[RFC 9433],IETF` and
    /// `41,0x0029,End.Limit,[RFC 9433],IETF`).
    #[test]
    fn behavior_rfc_9433_assignments() {
        let map = Behavior::from_wire(40).expect("End.MAP assigned at 40");
        assert_eq!(map, Behavior::EndMap);
        assert_eq!(map.wire_value(), 40);
        assert_eq!(map.name(), "End.MAP");

        let limit = Behavior::from_wire(41).expect("End.Limit assigned at 41");
        assert_eq!(limit, Behavior::EndLimit);
        assert_eq!(limit.wire_value(), 41);
        assert_eq!(limit.name(), "End.Limit");

        // RFC 9433 assigns the *mobile user-plane* End.M.* family
        // (End.M.GTP6.D/Di/E, End.M.GTP4.E) at 69-72. Those depend on
        // a GTP-specific argument layout the crate does not model;
        // left for a follow-up.
        for v in [69u16, 70, 71, 72] {
            assert!(
                Behavior::from_wire(v).is_none(),
                "{v}: End.M.* not modelled"
            );
        }
    }

    /// Every RFC 9800 NEXT-CSID family assignment, checked against
    /// the live IANA registry (rows `43..=50, 52..=59, 85..=97` with
    /// `Reference = RFC 9800`). The common short names `uN` (End
    /// with NEXT-CSID, PSP & USD = 48) and `uA` (End.X with NEXT-CSID,
    /// PSP & USD = 57) are documented in the variant doc-comments;
    /// the registry itself spells them in the long form.
    #[test]
    fn behavior_rfc_9800_next_csid_assignments() {
        // (wire value, expected variant, IANA-registry name). The
        // registry is the source of truth; the variant discriminant
        // and the `name()` output must match exactly.
        let cases: &[(u16, Behavior, &str)] = &[
            // End with NEXT-CSID family (RFC 9800 §4.1.1).
            (43, Behavior::EndWithNextCsid, "End with NEXT-CSID"),
            (44, Behavior::EndWithNextCsidPsp, "End with NEXT-CSID & PSP"),
            (45, Behavior::EndWithNextCsidUsp, "End with NEXT-CSID & USP"),
            (
                46,
                Behavior::EndWithNextCsidPspUsp,
                "End with NEXT-CSID, PSP & USP",
            ),
            (47, Behavior::EndWithNextCsidUsd, "End with NEXT-CSID & USD"),
            (
                48,
                Behavior::EndWithNextCsidPspUsd,
                "End with NEXT-CSID, PSP & USD",
            ),
            (
                49,
                Behavior::EndWithNextCsidUspUsd,
                "End with NEXT-CSID, USP & USD",
            ),
            (
                50,
                Behavior::EndWithNextCsidPspUspUsd,
                "End with NEXT-CSID, PSP, USP & USD",
            ),
            // End.X with NEXT-CSID family (RFC 9800 §4.2.1).
            (52, Behavior::EndXWithNextCsid, "End.X with NEXT-CSID"),
            (
                53,
                Behavior::EndXWithNextCsidPsp,
                "End.X with NEXT-CSID & PSP",
            ),
            (
                54,
                Behavior::EndXWithNextCsidUsp,
                "End.X with NEXT-CSID & USP",
            ),
            (
                55,
                Behavior::EndXWithNextCsidPspUsp,
                "End.X with NEXT-CSID, PSP & USP",
            ),
            (
                56,
                Behavior::EndXWithNextCsidUsd,
                "End.X with NEXT-CSID & USD",
            ),
            (
                57,
                Behavior::EndXWithNextCsidPspUsd,
                "End.X with NEXT-CSID, PSP & USD",
            ),
            (
                58,
                Behavior::EndXWithNextCsidUspUsd,
                "End.X with NEXT-CSID, USP & USD",
            ),
            (
                59,
                Behavior::EndXWithNextCsidPspUspUsd,
                "End.X with NEXT-CSID, PSP, USP & USD",
            ),
            // End.T with NEXT-CSID family (RFC 9800 §4.3.1).
            (85, Behavior::EndTWithNextCsid, "End.T with NEXT-CSID"),
            (
                86,
                Behavior::EndTWithNextCsidPsp,
                "End.T with NEXT-CSID & PSP",
            ),
            (
                87,
                Behavior::EndTWithNextCsidUsp,
                "End.T with NEXT-CSID & USP",
            ),
            (
                88,
                Behavior::EndTWithNextCsidPspUsp,
                "End.T with NEXT-CSID, PSP & USP",
            ),
            (
                89,
                Behavior::EndTWithNextCsidUsd,
                "End.T with NEXT-CSID & USD",
            ),
            (
                90,
                Behavior::EndTWithNextCsidPspUsd,
                "End.T with NEXT-CSID, PSP & USD",
            ),
            (
                91,
                Behavior::EndTWithNextCsidUspUsd,
                "End.T with NEXT-CSID, USP & USD",
            ),
            (
                92,
                Behavior::EndTWithNextCsidPspUspUsd,
                "End.T with NEXT-CSID, PSP, USP & USD",
            ),
            // End.B6.Encaps / End.B6.Encaps.Red / End.BM with NEXT-CSID.
            (
                93,
                Behavior::EndB6EncapsWithNextCsid,
                "End.B6.Encaps with NEXT-CSID",
            ),
            (
                94,
                Behavior::EndB6EncapsRedWithNextCsid,
                "End.B6.Encaps.Red with NEXT-CSID",
            ),
            (95, Behavior::EndBmWithNextCsid, "End.BM with NEXT-CSID"),
            // End.LBS / End.XLBS with NEXT-CSID (RFC 9800 §4.4-§4.5).
            (96, Behavior::EndLbsWithNextCsid, "End.LBS with NEXT-CSID"),
            (97, Behavior::EndXlbsWithNextCsid, "End.XLBS with NEXT-CSID"),
        ];
        for (v, expect_variant, expect_name) in cases {
            let b = Behavior::from_wire(*v).unwrap_or_else(|| {
                panic!("RFC 9800 wire value {v} ({expect_name}) has no variant");
            });
            assert_eq!(b, *expect_variant, "wire {v}: variant mismatch");
            assert_eq!(b.wire_value(), *v, "{expect_name}: wire value drifted");
            assert_eq!(
                b.name(),
                *expect_name,
                "wire {v}: name drifted from the IANA registry"
            );
        }
    }

    /// RFC 10018 End.DTMC family (decap to MPLS table):
    /// `76,0x004C,End.DTMC4,[RFC 10018],IETF`,
    /// `77,0x004D,End.DTMC6,[RFC 10018],IETF`,
    /// `78,0x004E,End.DTMC46,[RFC 10018],IETF`.
    #[test]
    fn behavior_rfc_10018_dtmc_assignments() {
        let dtmc4 = Behavior::from_wire(76).expect("End.DTMC4 assigned at 76");
        assert_eq!(dtmc4, Behavior::EndDtmc4);
        assert_eq!(dtmc4.wire_value(), 76);
        assert_eq!(dtmc4.name(), "End.DTMC4");

        let dtmc6 = Behavior::from_wire(77).expect("End.DTMC6 assigned at 77");
        assert_eq!(dtmc6, Behavior::EndDtmc6);
        assert_eq!(dtmc6.wire_value(), 77);
        assert_eq!(dtmc6.name(), "End.DTMC6");

        let dtmc46 = Behavior::from_wire(78).expect("End.DTMC46 assigned at 78");
        assert_eq!(dtmc46, Behavior::EndDtmc46);
        assert_eq!(dtmc46.wire_value(), 78);
        assert_eq!(dtmc46.name(), "End.DTMC46");
    }

    /// Flavor classification for the RFC 9800 NEXT-CSID family —
    /// the PSP/USP/USD classifiers must cover the new variants,
    /// mirroring the same flavor bits the non-CSID family carries.
    #[test]
    fn behavior_next_csid_flavor_classification() {
        // End with NEXT-CSID, PSP & USD (uN) carries PSP and USD.
        let un = Behavior::EndWithNextCsidPspUsd;
        assert!(un.is_psp(), "uN carries PSP");
        assert!(!un.is_usp(), "uN does not carry USP");
        assert!(un.is_usd(), "uN carries USD");

        // End.X with NEXT-CSID, PSP & USD (uA) carries PSP and USD.
        let ua = Behavior::EndXWithNextCsidPspUsd;
        assert!(ua.is_psp(), "uA carries PSP");
        assert!(!ua.is_usp(), "uA does not carry USP");
        assert!(ua.is_usd(), "uA carries USD");
        // uA is a cross-connect (End.X family).
        assert!(ua.is_cross_connect(), "uA is a cross-connect");
        assert!(!ua.is_table_lookup(), "uA is not a table lookup");

        // End.T with NEXT-CSID, PSP, USP & USD carries every flavor.
        let endt_all = Behavior::EndTWithNextCsidPspUspUsd;
        assert!(endt_all.is_psp());
        assert!(endt_all.is_usp());
        assert!(endt_all.is_usd());
        assert!(
            endt_all.is_table_lookup(),
            "End.T with NEXT-CSID is a table lookup"
        );
        assert!(!endt_all.is_cross_connect());

        // Plain End with NEXT-CSID (43) carries no flavor.
        let plain = Behavior::EndWithNextCsid;
        assert!(!plain.is_psp());
        assert!(!plain.is_usp());
        assert!(!plain.is_usd());
        // End with NEXT-CSID is neither a cross-connect nor a table
        // lookup — it is the basic End behavior with the NEXT-CSID
        // flavor.
        assert!(!plain.is_cross_connect());
        assert!(!plain.is_table_lookup());
    }

    /// End.DTMC4/6/46 (RFC 10018) decap and look up an MPLS table —
    /// they share the decap and table-lookup classifications with
    /// the End.DT* family.
    #[test]
    fn behavior_dtmc_classification() {
        assert!(Behavior::EndDtmc4.is_decap());
        assert!(Behavior::EndDtmc6.is_decap());
        assert!(Behavior::EndDtmc46.is_decap());
        assert!(Behavior::EndDtmc4.is_table_lookup());
        assert!(Behavior::EndDtmc6.is_table_lookup());
        assert!(Behavior::EndDtmc46.is_table_lookup());
        // DTMC is not a cross-connect (it is a table lookup).
        assert!(!Behavior::EndDtmc4.is_cross_connect());
        // End.LBS / End.XLBS with NEXT-CSID (RFC 9800 §4.4-§4.5)
        // are neither cross-connect nor table-lookup — they are a
        // new behavior class (locator-block swap).
        assert!(!Behavior::EndLbsWithNextCsid.is_cross_connect());
        assert!(!Behavior::EndLbsWithNextCsid.is_table_lookup());
        assert!(!Behavior::EndXlbsWithNextCsid.is_cross_connect());
        assert!(!Behavior::EndXlbsWithNextCsid.is_table_lookup());
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
        assert_eq!(format!("{}", Behavior::EndMap), "End.MAP");
        assert_eq!(format!("{}", Behavior::EndLimit), "End.Limit");
    }
}
