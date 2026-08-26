//! Thin byte buffer abstractions used by the codec traits.
//!
//! These are simple slice-backed adapters with helpers commonly needed by
//! protocol codecs (various integer widths, length-prefixed framing,
//! backpatching). The library avoids coupling to `std::io::Read`/`Write` so
//! that `no_std` analyzers can use it.

/// Read-side buffer view used by [`super::codec::Decoder`].
pub struct ReadBuf<'a> {
    inner: &'a [u8],
    pos: usize,
}

impl<'a> ReadBuf<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { inner: buf, pos: 0 }
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.inner.len() - self.pos
    }

    #[inline]
    pub fn advance(&mut self, n: usize) {
        assert!(self.pos + n <= self.inner.len(), "ReadBuf advance overflow");
        self.pos += n;
    }

    #[inline]
    pub fn chunk(&self) -> &[u8] {
        &self.inner[self.pos..]
    }

    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn peek_u8(&self) -> Option<u8> {
        self.chunk().first().copied()
    }

    #[inline]
    pub fn get_u8(&mut self) -> Option<u8> {
        let v = self.peek_u8()?;
        self.pos += 1;
        Some(v)
    }

    #[inline]
    pub fn get_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.inner[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    pub fn get_u16_be(&mut self) -> Option<u16> {
        let b = self.get_bytes(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn get_u32_be(&mut self) -> Option<u32> {
        let b = self.get_bytes(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn get_u64_be(&mut self) -> Option<u64> {
        let b = self.get_bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(u64::from_be_bytes(a))
    }
}

impl<'a> AsRef<[u8]> for ReadBuf<'a> {
    fn as_ref(&self) -> &[u8] {
        self.chunk()
    }
}

/// Write-side buffer used by [`super::codec::Encoder`].
pub struct WriteBuf<'a> {
    inner: &'a mut [u8],
    pos: usize,
}

impl<'a> WriteBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { inner: buf, pos: 0 }
    }

    #[inline]
    pub fn remaining_mut(&self) -> usize {
        self.inner.len() - self.pos
    }

    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn put_u8(&mut self, v: u8) -> Option<()> {
        if self.pos >= self.inner.len() {
            return None;
        }
        self.inner[self.pos] = v;
        self.pos += 1;
        Some(())
    }

    #[inline]
    pub fn put_bytes(&mut self, b: &[u8]) -> Option<()> {
        if self.remaining_mut() < b.len() {
            return None;
        }
        self.inner[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
        Some(())
    }

    pub fn put_u16_be(&mut self, v: u16) -> Option<()> {
        self.put_bytes(&v.to_be_bytes())
    }

    pub fn put_u32_be(&mut self, v: u32) -> Option<()> {
        self.put_bytes(&v.to_be_bytes())
    }

    pub fn put_u64_be(&mut self, v: u64) -> Option<()> {
        self.put_bytes(&v.to_be_bytes())
    }

    /// Reserve `n` bytes at the current position and return the starting
    /// offset so the caller can backpatch later.
    pub fn reserve(&mut self, n: usize) -> Option<usize> {
        if self.remaining_mut() < n {
            return None;
        }
        let start = self.pos;
        self.pos += n;
        Some(start)
    }

    /// Backpatch `b.len()` bytes at the given offset.
    pub fn patch(&mut self, at: usize, b: &[u8]) -> Option<()> {
        if at + b.len() > self.inner.len() {
            return None;
        }
        self.inner[at..at + b.len()].copy_from_slice(b);
        Some(())
    }

    pub fn written(&self) -> &[u8] {
        &self.inner[..self.pos]
    }

    pub fn capacity(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_be_integers() {
        let b = [0x12u8, 0x34, 0x56, 0x78];
        let mut r = ReadBuf::new(&b);
        assert_eq!(r.get_u16_be(), Some(0x1234));
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.get_u16_be(), Some(0x5678));
    }

    #[test]
    fn write_be_integers() {
        let mut b = [0u8; 4];
        let mut w = WriteBuf::new(&mut b);
        assert!(w.put_u16_be(0x1234).is_some());
        assert!(w.put_u16_be(0x5678).is_some());
        assert_eq!(&b, &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn backpatch() {
        let mut b = [0u8; 6];
        let mut w = WriteBuf::new(&mut b);
        let at = w.reserve(2).unwrap();
        w.put_u16_be(0xabcd).unwrap();
        w.patch(at, &[0xff, 0xff]).unwrap();
        assert_eq!(&b, &[0xff, 0xff, 0xab, 0xcd, 0, 0]);
    }
}
