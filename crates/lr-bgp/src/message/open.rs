//! OPEN message (RFC 4271 §4.2).

use lr_core::addr::{Asn, RouterId};

/// BGP OPEN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    /// Protocol version (must be 4).
    pub version: u8,
    /// Sender AS number (may be 23456 AS_TRANS when ASN4 capability is used).
    pub my_as: Asn,
    /// Hold time proposed (seconds), 0 means keep default.
    pub hold_time: u16,
    /// Sender BGP identifier.
    pub bgp_id: RouterId,
    /// Optional parameters (capabilities, auth).
    pub params: Vec<OpenParam>,
}

impl Open {
    pub fn new(my_as: Asn, hold_time: u16, bgp_id: RouterId) -> Self {
        Self {
            version: 4,
            my_as,
            hold_time,
            bgp_id,
            params: Vec::new(),
        }
    }

    /// True if AS_TRANS (23456) is set, indicating the actual ASN is in the
    /// 4-byte AS capability (RFC 4893 §7).
    pub fn uses_as_trans(&self) -> bool {
        self.my_as.is_as23456()
    }
}

/// One OPEN optional parameter (RFC 4271 §4.2). Parameter type 2 is
/// capabilities (RFC 5492).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenParam {
    pub param_type: u8,
    pub value: Vec<u8>,
}

impl OpenParam {
    pub const PARAM_TYPE_CAPABILITY: u8 = 2;
}
