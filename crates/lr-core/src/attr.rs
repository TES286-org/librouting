//! Tagged-attribute container used by path-attribute-style protocols (BGP)
//! and as a generic "extra metadata" carrier for OSPF/Babel.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// A tag identifying a path attribute. Tags are protocol-specific; we keep
/// them as a small enum that BGP extends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttrTag(pub u8);

impl AttrTag {
    pub const fn raw(v: u8) -> Self {
        Self(v)
    }
}

/// A path attribute container. Each protocol populates `tag` and `value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub tag: AttrTag,
    pub flags: u8,
    pub value: Vec<u8>,
}

/// Ordered attribute set keyed by tag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attributes {
    inner: BTreeMap<u8, Attribute>,
}

impl Attributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, a: Attribute) {
        self.inner.insert(a.tag.0, a);
    }

    pub fn get(&self, tag: AttrTag) -> Option<&Attribute> {
        self.inner.get(&tag.0)
    }

    /// Read a 4-byte big-endian unsigned integer attribute in place
    /// — no `Vec<u8>` clone, no `Attribute` struct dereference beyond
    /// the BTreeMap lookup. Used by the filter DSL's integer fast
    /// paths (LOCAL_PREF / MED, GitHub #19 P3): the previous path
    /// (`get(tag).map(|a| a.value.clone()).and_then(...)`) allocated a
    /// fresh `Vec<u8>` for every attribute read on the hot path; this
    /// method reads the 4 bytes directly off the stored slice.
    ///
    /// Returns `None` when the tag is absent or the value is not
    /// exactly 4 bytes long (the BGP wire format for LOCAL_PREF and
    /// MED is always 4 bytes per RFC 4271 §5.1.5 / §4.2.4, so a
    /// length mismatch indicates a malformed attribute and is
    /// treated as "absent" — the caller's `unwrap_or(0)` default
    /// applies).
    pub fn get_u32_be(&self, tag: AttrTag) -> Option<u32> {
        let a = self.inner.get(&tag.0)?;
        let b = a.value.as_slice().try_into().ok()?;
        Some(u32::from_be_bytes(b))
    }

    /// Read a 1-byte unsigned integer attribute in place. Used by
    /// the filter DSL's `bgp.origin` fast path (GitHub #19 P3).
    /// Returns `None` when the tag is absent or the value is not
    /// exactly 1 byte long (the BGP wire format for ORIGIN is always
    /// 1 byte per RFC 4271 §4.2.1).
    pub fn get_u8(&self, tag: AttrTag) -> Option<u8> {
        let a = self.inner.get(&tag.0)?;
        let b = a.value.first().copied()?;
        Some(b)
    }

    pub fn remove(&mut self, tag: AttrTag) -> Option<Attribute> {
        self.inner.remove(&tag.0)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Attribute> {
        self.inner.values()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}
