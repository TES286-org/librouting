//! Tagged-attribute container used by path-attribute-style protocols (BGP)
//! and as a generic "extra metadata" carrier for OSPF/Babel.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
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
