//! CRC-16 (used by Babel for its per-frame checksum) and CRC-32C (used by
//! Babel `PadN`/optional CRC TLV). Both implemented with table-free algorithms
//! for small binary size.

const fn crc16_fletcher_table() -> [u16; 256] {
    let mut t = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u16;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
            j += 1;
        }
        t[i] = crc;
        i += 1;
    }
    t
}

static CRC16_TABLE: [u16; 256] = crc16_fletcher_table();

/// CRC-16/ARC (used by Babel; polynomial 0xA001 reversed).
pub fn crc16_arc(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for b in bytes {
        let idx = ((crc as u8) ^ b) as usize;
        crc = (crc >> 8) ^ CRC16_TABLE[idx];
    }
    crc
}

// CRC-32C (Castagnoli), software table-free implementation using slicing-by-1.
const fn crc32c_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82f63b78
            } else {
                crc >> 1
            };
            j += 1;
        }
        t[i] = crc;
        i += 1;
    }
    t
}

static CRC32C_TABLE: [u32; 256] = crc32c_table();

/// CRC-32C (Castagnoli), used for Babel `PadN`/optional CRC TLV and OSPFv3
/// upper-layer checksum input.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for b in bytes {
        let idx = ((crc as u8) ^ b) as usize;
        crc = (crc >> 8) ^ CRC32C_TABLE[idx];
    }
    crc ^ 0xffff_ffff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_known_vectors() {
        // "123456789" -> 0xbb3d for CRC-16/ARC.
        assert_eq!(crc16_arc(b"123456789"), 0xbb3d);
    }

    #[test]
    fn crc32c_known_vectors() {
        // "123456789" -> 0xe3069283 for CRC-32C.
        assert_eq!(crc32c(b"123456789"), 0xe3069283);
    }
}
