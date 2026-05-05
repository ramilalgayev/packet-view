use crate::{PacketError, PacketView, PacketViewMut};
use crate::view::PacketSpec;
use crate::checksum;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ipv4 {}

impl Ipv4 {
    pub const MIN_PACKET_LEN: usize = 20;
    pub const VERSION: u8 = 4;
}

impl PacketSpec for Ipv4 {
    fn validate(bytes: &[u8]) -> Result<(), PacketError> {
        if bytes.len() < Self::MIN_PACKET_LEN {
            return Err(PacketError::TooShort {
                needed: Self::MIN_PACKET_LEN,
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

        Ok(())
    }

    fn header_len(bytes: &[u8]) -> usize {
        debug_assert!(
            !bytes.is_empty(),
            "header_len called on empty slice; call validate() first"
        );
        ((bytes[0] & 0x0f) as usize) * 4
    }
}

pub trait Ipv4Packet {
    fn bytes(&self) -> &[u8];

    fn version(&self) -> u8 {
        self.bytes()[0] >> 4
    }

    fn ihl_words(&self) -> u8 {
        self.bytes()[0] & 0x0f
    }

    fn header_len(&self) -> usize {
        self.ihl_words() as usize * 4
    }

    fn dscp(&self) -> u8 {
        self.bytes()[1] >> 2
    }

    fn ecn(&self) -> u8 {
        self.bytes()[1] & 0b11
    }

    fn total_len(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[2], self.bytes()[3]])
    }

    fn identification(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[4], self.bytes()[5]])
    }

    fn flags(&self) -> u8 {
        self.bytes()[6] >> 5
    }

    fn fragment_offset(&self) -> u16 {
        let raw = u16::from_be_bytes([self.bytes()[6], self.bytes()[7]]);
        raw & 0x1fff
    }

    fn ttl(&self) -> u8 {
        self.bytes()[8]
    }

    fn protocol(&self) -> u8 {
        self.bytes()[9]
    }

    fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[10], self.bytes()[11]])
    }

    fn src(&self) -> [u8; 4] {
        [self.bytes()[12], self.bytes()[13], self.bytes()[14], self.bytes()[15]]
    }

    fn dst(&self) -> [u8; 4] {
        [self.bytes()[16], self.bytes()[17], self.bytes()[18], self.bytes()[19]]
    }

    fn options(&self) -> &[u8] {
        &self.bytes()[Ipv4::MIN_PACKET_LEN..self.header_len()]
    }

    fn payload(&self) -> &[u8] {
        let header_len = self.header_len();
        let total_len = self.total_len() as usize;
        let end = core::cmp::min(total_len, self.bytes().len());
        &self.bytes()[header_len..end]
    }
}

impl<'a> PacketView<'a, Ipv4> {
    pub fn new_verified(bytes: &'a [u8]) -> Result<Self, PacketError> {
        let view = Self::new(bytes)?;
        let h = view.header_bytes();

        if !checksum::verify(h) {
            let stored = view.checksum();
            let expected = {
                let mut sum = 0u32;
                let mut i = 0;
                while i + 1 < h.len() {
                    let word = if i == 10 { 0u16 }
                               else { u16::from_be_bytes([h[i], h[i + 1]]) };
                    sum += word as u32;
                    i += 2;
                }
                while sum >> 16 != 0 {
                    sum = (sum & 0xffff) + (sum >> 16);
                }
                !(sum as u16)
            };
            return Err(PacketError::InvalidChecksum {
                expected,
                actual: stored,
            });
        }

        Ok(view)
    }
}

impl<'a> PacketViewMut<'a, Ipv4> {
    pub fn set_ttl(&mut self, value: u8) {
        self.as_slice_mut()[8] = value;
    }

    pub fn set_protocol(&mut self, value: u8) {
        self.as_slice_mut()[9] = value;
    }

    pub fn set_checksum(&mut self, value: u16) {
        self.as_slice_mut()[10..12].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_src(&mut self, value: [u8; 4]) {
        self.as_slice_mut()[12..16].copy_from_slice(&value);
    }

    pub fn set_dst(&mut self, value: [u8; 4]) {
        self.as_slice_mut()[16..20].copy_from_slice(&value);
    }

    pub fn compute_and_set_checksum(&mut self) {
        // zero out the checksum field first
        self.as_slice_mut()[10] = 0;
        self.as_slice_mut()[11] = 0;

        let header_len = self.header_len();
        let checksum = checksum::compute(&self.as_slice()[..header_len], 10);
        self.set_checksum(checksum);
    }
}

impl<'a> Ipv4Packet for PacketView<'a, Ipv4> {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> Ipv4Packet for PacketViewMut<'a, Ipv4> {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ipv4Header, Ipv4HeaderMut};

    const IPV4_MIN_PACKET_LEN: usize = 20;

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
    const IPV4_VALID_CHECKSUM: u16 = 0x56e3;
    const IPV4_HEADER_VALID_CHECKSUM: [u8; 20] = [
        0x45, 0x00,
        0x00, 0x14,
        0x12, 0x34,
        0x40, 0x00,
        0x40,
        0x11,
        0x56, 0xe3,
        192, 168, 1, 10,
        8, 8, 8, 8,
    ];

    const IPV4_HEADER: [u8; IPV4_MIN_PACKET_LEN] = [
        IPV4_VERSION_IHL,
        IPV4_DSCP_ECN,
        IPV4_TOTAL_LEN[0], IPV4_TOTAL_LEN[1],
        IPV4_IDENTIFICATION[0], IPV4_IDENTIFICATION[1],
        IPV4_FLAGS_FRAGMENT_OFFSET[0], IPV4_FLAGS_FRAGMENT_OFFSET[1],
        IPV4_TTL,
        IPV4_PROTOCOL_UDP,
        IPV4_CHECKSUM[0], IPV4_CHECKSUM[1],
        IPV4_SRC[0], IPV4_SRC[1], IPV4_SRC[2], IPV4_SRC[3],
        IPV4_DST[0], IPV4_DST[1], IPV4_DST[2], IPV4_DST[3],
    ];

    #[test]
    fn parses_basic_ipv4_header() {
        let header = Ipv4Header::new(&IPV4_HEADER).unwrap();

        assert_eq!(header.version(), 4);
        assert_eq!(header.ihl_words(), 5);
        assert_eq!(header.header_len(), IPV4_MIN_PACKET_LEN);
        assert_eq!(header.total_len(), 20);
        assert_eq!(header.ttl(), IPV4_TTL);
        assert_eq!(header.protocol(), IPV4_PROTOCOL_UDP);
        assert_eq!(header.checksum(), 0xabcd);
        assert_eq!(header.src(), IPV4_SRC);
        assert_eq!(header.dst(), IPV4_DST);
        assert_eq!(header.options(), &[]);
        assert_eq!(header.payload(), &[]);
    }

    #[test]
    fn edits_ipv4_header_without_losing_read_api() {
        let mut bytes = IPV4_HEADER;
        let mut header = Ipv4HeaderMut::new(&mut bytes).unwrap();

        header.set_ttl(128);
        header.set_protocol(6);
        header.set_checksum(0xbeef);
        header.set_src([10, 0, 0, 1]);
        header.set_dst([10, 0, 0, 2]);

        assert_eq!(header.ttl(), 128);
        assert_eq!(header.protocol(), 6);
        assert_eq!(header.checksum(), 0xbeef);
        assert_eq!(header.src(), [10, 0, 0, 1]);
        assert_eq!(header.dst(), [10, 0, 0, 2]);
    }

    #[test]
    fn rejects_short_ipv4_header() {
        let short_header = &IPV4_HEADER[..IPV4_MIN_PACKET_LEN - 1];

        assert_eq!(
            Ipv4Header::new(short_header),
            Err(PacketError::TooShort {
                needed: IPV4_MIN_PACKET_LEN,
                actual: IPV4_MIN_PACKET_LEN - 1,
            })
        );
    }

    #[test]
    fn rejects_wrong_ipv4_version() {
        let mut header_bytes = IPV4_HEADER;
        header_bytes[0] = 0x65;

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
        header_bytes[0] = 0x44;

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
                header_len: IPV4_MIN_PACKET_LEN,
                total_len: 19,
            })
        );
    }

    #[test]
fn new_verified_accepts_valid_checksum() {
    let header = Ipv4Header::new_verified(&IPV4_HEADER_VALID_CHECKSUM).unwrap();
    assert_eq!(header.checksum(), IPV4_VALID_CHECKSUM);
}

    #[test]
    fn new_verified_rejects_invalid_checksum() {
        let mut bytes = IPV4_HEADER_VALID_CHECKSUM;
        bytes[10] = 0xde; // corrupt the checksum
        bytes[11] = 0xad;
    
        assert_eq!(
            Ipv4Header::new_verified(&bytes),
            Err(PacketError::InvalidChecksum {
                expected: IPV4_VALID_CHECKSUM,
                actual: 0xdead,
            })
        );
    }

    #[test]
    fn new_accepts_invalid_checksum_without_verifying() {
        // new() must never touch the checksum — 0xabcd is wrong but new() passes
        assert!(Ipv4Header::new(&IPV4_HEADER).is_ok());
    }

    #[test]
    fn compute_and_set_checksum_produces_valid_header() {
        // Start from the header with the bad checksum, fix it, verify it
        let mut bytes = IPV4_HEADER_VALID_CHECKSUM;
        bytes[10] = 0xde; // corrupt first
        bytes[11] = 0xad;

        let mut header = Ipv4HeaderMut::new(&mut bytes).unwrap();
        header.compute_and_set_checksum();

        assert_eq!(header.checksum(), IPV4_VALID_CHECKSUM);
        // Also verify the whole header passes new_verified
        assert!(Ipv4Header::new_verified(&bytes).is_ok());
    }

    #[test]
    fn compute_and_set_checksum_round_trips_after_mutation() {
        let mut bytes = IPV4_HEADER_VALID_CHECKSUM;
        let mut header = Ipv4HeaderMut::new(&mut bytes).unwrap();

        // mutate some fields
        header.set_ttl(128);
        header.set_src([10, 0, 0, 1]);
        header.set_dst([10, 0, 0, 2]);

        // checksum is now stale — recompute
        header.compute_and_set_checksum();

        // drop the mut borrow and verify immutably
        drop(header);
        assert!(Ipv4Header::new_verified(&bytes).is_ok());
    }
}