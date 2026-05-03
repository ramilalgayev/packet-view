use crate::PacketError;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Ipv6Header<'a> {
    bytes: &'a [u8],
}

impl<'a> Ipv6Header<'a> {
    pub const LEN: usize = 40;
    pub const VERSION: u8 = 6;

    pub fn new(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < Self::LEN {
            return Err(PacketError::TooShort {
                needed: Self::LEN,
                actual: bytes.len(),
            });
        }

        let version = bytes[0] >> 4;
        if version != Self::VERSION {
            return Err(PacketError::InvalidVersion {
                expected: Self::VERSION,
                actual: version,
            });
        }

        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        &self.bytes[..Self::LEN]
    }

    pub fn version(&self) -> u8 {
        self.bytes[0] >> 4
    }

    pub fn traffic_class(&self) -> u8 {
        ((self.bytes[0] & 0x0f) << 4) | (self.bytes[1] >> 4)
    }

    pub fn flow_label(&self) -> u32 {
        let b1 = (self.bytes[1] & 0x0f) as u32;
        let b2 = self.bytes[2] as u32;
        let b3 = self.bytes[3] as u32;
        (b1 << 16) | (b2 << 8) | b3
    }

    pub fn payload_len(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }

    pub fn next_header(&self) -> u8 {
        self.bytes[6]
    }

    pub fn hop_limit(&self) -> u8 {
        self.bytes[7]
    }

    pub fn src(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.bytes[8..24]);
        out
    }

    pub fn dst(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.bytes[24..40]);
        out
    }

    pub fn payload(&self) -> &'a [u8] {
        let start = Self::LEN;
        let end = core::cmp::min(start + self.payload_len() as usize, self.bytes.len());
        &self.bytes[start..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV6: [u8; 40] = [
        0x60, 0x12, 0x34, 0x56,
        0x00, 0x00,
        17,
        64,
        0x20, 0x01, 0x0d, 0xb8,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1,
        0x20, 0x01, 0x0d, 0xb8,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 2,
    ];

    #[test]
    fn parses_basic_ipv6_header() {
        let ip = Ipv6Header::new(&IPV6).unwrap();
        assert_eq!(ip.version(), 6);
        assert_eq!(ip.traffic_class(), 0x01);
        assert_eq!(ip.flow_label(), 0x23456);
        assert_eq!(ip.payload_len(), 0);
        assert_eq!(ip.next_header(), 17);
        assert_eq!(ip.hop_limit(), 64);
        assert_eq!(ip.src(), [
            0x20, 0x01, 0x0d, 0xb8,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 1,
        ]);
        assert_eq!(ip.dst(), [
            0x20, 0x01, 0x0d, 0xb8,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 2,
        ]);
    }

    #[test]
    fn rejects_short_ipv6_header() {
        assert_eq!(
            Ipv6Header::new(&IPV6[..39]),
            Err(PacketError::TooShort { needed: 40, actual: 39 })
        );
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = IPV6;
        bytes[0] = 0x40;
        assert_eq!(
            Ipv6Header::new(&bytes),
            Err(PacketError::InvalidVersion { expected: 6, actual: 4 })
        );
    }
}
