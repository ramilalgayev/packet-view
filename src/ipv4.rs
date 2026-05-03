use crate::PacketError;

#[derive(Debug, Clone, Copy, PartialEq)]
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

    const IPV4_MIN_HEADER_LEN: usize = 20;

    const IPV4_VERSION_IHL: u8 = 0x45;
    const IPV4_DSCP_ECN: u8 = 0x00;
    const IPV4_TOTAL_LEN: [u8; 2] = 20u16.to_be_bytes();
    const IPV4_IDENTIFICATION: [u8; 2] = 0x1234u16.to_be_bytes();
    const IPV4_FLAGS_FRAGMENT_OFFSET: [u8; 2] = 0x4000u16.to_be_bytes();
    const IPV4_TTL: u8 = 64;
    const IPV4_PROTOCOL_UDP: u8 = 17;
    const IPV4_CHECKSUM: [u8; 2] = 0xabcdu16.to_be_bytes();
    const IPV4_SRC: [u8; 4] = [192, 168, 1, 10];
    const IPV4_DST: [u8; 4] = [8, 8, 8, 8];

    const IPV4_HEADER: [u8; IPV4_MIN_HEADER_LEN] = [
        IPV4_VERSION_IHL,
        IPV4_DSCP_ECN,
        IPV4_TOTAL_LEN[0],
        IPV4_TOTAL_LEN[1],
        IPV4_IDENTIFICATION[0],
        IPV4_IDENTIFICATION[1],
        IPV4_FLAGS_FRAGMENT_OFFSET[0],
        IPV4_FLAGS_FRAGMENT_OFFSET[1],
        IPV4_TTL,
        IPV4_PROTOCOL_UDP,
        IPV4_CHECKSUM[0],
        IPV4_CHECKSUM[1],
        IPV4_SRC[0],
        IPV4_SRC[1],
        IPV4_SRC[2],
        IPV4_SRC[3],
        IPV4_DST[0],
        IPV4_DST[1],
        IPV4_DST[2],
        IPV4_DST[3],
    ];

    #[test]
    fn parses_basic_ipv4_header() {
        let header = Ipv4Header::new(&IPV4_HEADER).unwrap();

        assert_eq!(header.version(), 4);
        assert_eq!(header.ihl_words(), 5);
        assert_eq!(header.header_len(), IPV4_MIN_HEADER_LEN);
        assert_eq!(header.dscp(), 0);
        assert_eq!(header.ecn(), 0);
        assert_eq!(header.total_len(), 20);
        assert_eq!(header.identification(), 0x1234);
        assert_eq!(header.flags(), 0b010);
        assert_eq!(header.fragment_offset(), 0);
        assert_eq!(header.ttl(), IPV4_TTL);
        assert_eq!(header.protocol(), IPV4_PROTOCOL_UDP);
        assert_eq!(header.checksum(), 0xabcd);
        assert_eq!(header.src(), IPV4_SRC);
        assert_eq!(header.dst(), IPV4_DST);
        assert_eq!(header.options(), &[]);
        assert_eq!(header.payload(), &[]);
    }

    #[test]
    fn rejects_short_ipv4_header() {
        let short_header = &IPV4_HEADER[..IPV4_MIN_HEADER_LEN - 1];

        assert_eq!(
            Ipv4Header::new(short_header),
            Err(PacketError::TooShort {
                needed: IPV4_MIN_HEADER_LEN,
                actual: IPV4_MIN_HEADER_LEN - 1,
            })
        );
    }

    #[test]
    fn rejects_wrong_ipv4_version() {
        let mut header_bytes = IPV4_HEADER;
        header_bytes[0] = 0x65; // version = 6, IHL = 5

        assert_eq!(
            Ipv4Header::new(&header_bytes),
            Err(PacketError::InvalidVersion {
                expected: 4,
                actual: 6,
            })
        );
    }

    #[test]
    fn rejects_invalid_ipv4_ihl() {
        let mut header_bytes = IPV4_HEADER;
        header_bytes[0] = 0x44; // version = 4, IHL = 4 words / 16 bytes

        assert_eq!(
            Ipv4Header::new(&header_bytes),
            Err(PacketError::InvalidIpv4HeaderLength { ihl_words: 4 })
        );
    }

    #[test]
    fn rejects_ipv4_total_len_smaller_than_header_len() {
        let mut header_bytes = IPV4_HEADER;
        header_bytes[2..4].copy_from_slice(&19u16.to_be_bytes());

        assert_eq!(
            Ipv4Header::new(&header_bytes),
            Err(PacketError::InvalidIpv4TotalLength {
                header_len: IPV4_MIN_HEADER_LEN,
                total_len: 19,
            })
        );
    }
}