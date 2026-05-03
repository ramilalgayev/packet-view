use crate::PacketError;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Ipv4Header<'a> {
    bytes: &'a [u8],
}

impl<'a> Ipv4Header<'a> {
    pub const MIN_PACKAGE_LEN: usize = 20;
    pub const VERSION: u8 = 4;

    pub fn new(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < Self::MIN_PACKAGE_LEN {
            return Err(PacketError::TooShort {
                needed: Self::MIN_PACKAGE_LEN,
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

        let ihl_words = bytes[0] & 0x0f;
        if ihl_words < 5 {
            return Err(PacketError::InvalidIpv4HeaderLength { ihl_words });
        }

        let header_len = ihl_words as usize * 4;
        if bytes.len() < header_len {
            return Err(PacketError::TooShort {
                needed: header_len,
                actual: bytes.len(),
            });
        }

        let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if total_len < header_len {
            return Err(PacketError::InvalidIpv4TotalLength {
                header_len,
                total_len,
            });
        }

        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        &self.bytes[..self.header_len()]
    }

    pub fn version(&self) -> u8 {
        self.bytes[0] >> 4
    }

    pub fn ihl_words(&self) -> u8 {
        self.bytes[0] & 0x0f
    }

    pub fn header_len(&self) -> usize {
        self.ihl_words() as usize * 4
    }

    pub fn dscp(&self) -> u8 {
        self.bytes[1] >> 2
    }

    pub fn ecn(&self) -> u8 {
        self.bytes[1] & 0b11
    }

    pub fn total_len(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }

    pub fn flags(&self) -> u8 {
        self.bytes[6] >> 5
    }

    pub fn fragment_offset(&self) -> u16 {
        let raw = u16::from_be_bytes([self.bytes[6], self.bytes[7]]);
        raw & 0x1fff
    }

    pub fn ttl(&self) -> u8 {
        self.bytes[8]
    }

    pub fn protocol(&self) -> u8 {
        self.bytes[9]
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[10], self.bytes[11]])
    }

    pub fn src(&self) -> [u8; 4] {
        [self.bytes[12], self.bytes[13], self.bytes[14], self.bytes[15]]
    }

    pub fn dst(&self) -> [u8; 4] {
        [self.bytes[16], self.bytes[17], self.bytes[18], self.bytes[19]]
    }

    pub fn options(&self) -> &'a [u8] {
        &self.bytes[Self::MIN_PACKAGE_LEN..self.header_len()]
    }

    pub fn payload(&self) -> &'a [u8] {
        let header_len = self.header_len();
        let total_len = self.total_len() as usize;
        let end = core::cmp::min(total_len, self.bytes.len());
        &self.bytes[header_len..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4: [u8; 20] = [
        0x45, 0x00, 0x00, 0x14,
        0x12, 0x34, 0x40, 0x00,
        64, 17, 0xab, 0xcd,
        192, 168, 1, 10,
        8, 8, 8, 8,
    ];

    #[test]
    fn parses_basic_ipv4_header() {
        let ip = Ipv4Header::new(&IPV4).unwrap();
        assert_eq!(ip.version(), 4);
        assert_eq!(ip.ihl_words(), 5);
        assert_eq!(ip.header_len(), 20);
        assert_eq!(ip.total_len(), 20);
        assert_eq!(ip.identification(), 0x1234);
        assert_eq!(ip.flags(), 0b010);
        assert_eq!(ip.fragment_offset(), 0);
        assert_eq!(ip.ttl(), 64);
        assert_eq!(ip.protocol(), 17);
        assert_eq!(ip.checksum(), 0xabcd);
        assert_eq!(ip.src(), [192, 168, 1, 10]);
        assert_eq!(ip.dst(), [8, 8, 8, 8]);
    }

    #[test]
    fn rejects_short_ipv4_header() {
        assert_eq!(
            Ipv4Header::new(&IPV4[..19]),
            Err(PacketError::TooShort { needed: 20, actual: 19 })
        );
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = IPV4;
        bytes[0] = 0x65;
        assert_eq!(
            Ipv4Header::new(&bytes),
            Err(PacketError::InvalidVersion { expected: 4, actual: 6 })
        );
    }
}