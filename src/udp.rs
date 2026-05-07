use crate::{PacketError, PacketView, PacketViewMut};
use crate::view::PacketSpec;
use crate::checksum;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Udp {}

impl Udp {
    pub const HEADER_LEN: usize = 8;
}

impl PacketSpec for Udp {
        fn validate(bytes: &[u8]) -> Result<(), PacketError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(PacketError::TooShort {
                needed: Self::HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let length = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;

        if length < Self::HEADER_LEN {
            return Err(PacketError::InvalidUdpLength {
                header_len: Self::HEADER_LEN,
                actual: length,
            });
        }

        if length > bytes.len() {
            return Err(PacketError::TooShort {
                needed: length,
                actual: bytes.len(),
            });
        }

        Ok(())
    }

    fn header_len(_: &[u8]) -> usize {
        Self::HEADER_LEN
    }
}

pub trait UdpPacket {
    fn bytes(&self) -> &[u8];

    fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[0], self.bytes()[1]])
    }

    fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[2], self.bytes()[3]])
    }

    fn length(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[4], self.bytes()[5]])
    }

    fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[6], self.bytes()[7]])
    }

    fn payload(&self) -> &[u8] {
        let end = core::cmp::min(
            self.length() as usize,
            self.bytes().len(),
        );
        &self.bytes()[Udp::HEADER_LEN..end]
    }
}

impl<'a> UdpPacket for PacketView<'a, Udp> {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> UdpPacket for PacketViewMut<'a, Udp> {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> PacketViewMut<'a, Udp> {
    pub fn set_src_port(&mut self, value: u16) {
        self.as_slice_mut()[0..2].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_dst_port(&mut self, value: u16) {
        self.as_slice_mut()[2..4].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_length(&mut self, value: u16) {
        self.as_slice_mut()[4..6].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_checksum(&mut self, value: u16) {
        self.as_slice_mut()[6..8].copy_from_slice(&value.to_be_bytes());
    }
}

const UDP_PROTOCOL: u8 = 17;
const UDP_CHECKSUM_OFFSET: usize = 6;

fn udp_len_from_header(udp_bytes: &[u8]) -> usize {
    u16::from_be_bytes([udp_bytes[4], udp_bytes[5]]) as usize
}

pub fn udp_checksum_ipv4(
    src: [u8; 4],
    dst: [u8; 4],
    udp_bytes: &[u8],
) -> u16 {
    let udp_len = udp_len_from_header(udp_bytes);

    let mut pseudo = [0u8; 12];

    pseudo[0..4].copy_from_slice(&src);
    pseudo[4..8].copy_from_slice(&dst);
    pseudo[8] = 0;
    pseudo[9] = UDP_PROTOCOL;
    pseudo[10..12].copy_from_slice(&(udp_len as u16).to_be_bytes());

    checksum::transport_checksum_with_pseudo_header(&pseudo, udp_bytes, UDP_CHECKSUM_OFFSET)
}

pub fn udp_checksum_ipv6(
    src: [u8; 16],
    dst: [u8; 16],
    udp_bytes: &[u8],
) -> u16 {
    let udp_len = udp_len_from_header(udp_bytes);

    let mut pseudo = [0u8; 40];

    pseudo[0..16].copy_from_slice(&src);
    pseudo[16..32].copy_from_slice(&dst);
    pseudo[32..36].copy_from_slice(&(udp_len as u32).to_be_bytes());
    pseudo[36..39].fill(0);
    pseudo[39] = UDP_PROTOCOL;

    checksum::transport_checksum_with_pseudo_header(&pseudo, udp_bytes, UDP_CHECKSUM_OFFSET)
}


impl<'a> PacketView<'a, Udp> {
    /// Verifies UDP checksum over an IPv4 pseudo-header.
    /// Pass src and dst from the enclosing IPv4 header.
    pub fn new_verified_ipv4(
        bytes: &'a [u8],
        src: [u8; 4],
        dst: [u8; 4],
    ) -> Result<Self, PacketError> {
        let view = Self::new(bytes)?;

        // A checksum of 0x0000 means "not computed" in UDP over IPv4 — skip verification
        if view.checksum() == 0x0000 {
            return Ok(view);
        }

        let expected = udp_checksum_ipv4(src, dst, bytes);
        if expected != view.checksum() {
            return Err(PacketError::InvalidChecksum {
                expected,
                actual: view.checksum(),
            });
        }

        Ok(view)
    }

    /// Verifies UDP checksum over an IPv6 pseudo-header.
    /// In IPv6, UDP checksum is mandatory — 0x0000 is never valid.
    pub fn new_verified_ipv6(
        bytes: &'a [u8],
        src: [u8; 16],
        dst: [u8; 16],
    ) -> Result<Self, PacketError> {
        let view = Self::new(bytes)?;

        let expected = udp_checksum_ipv6(src, dst, bytes);
        if expected != view.checksum() {
            return Err(PacketError::InvalidChecksum {
                expected,
                actual: view.checksum(),
            });
        }

        Ok(view)
    }
}

impl<'a> PacketViewMut<'a, Udp> {
    pub fn compute_and_set_checksum_ipv4(&mut self, src: [u8; 4], dst: [u8; 4]) {
        let cksum = udp_checksum_ipv4(src, dst, self.as_slice());
        self.set_checksum(cksum);
    }

    pub fn compute_and_set_checksum_ipv6(&mut self, src: [u8; 16], dst: [u8; 16]) {
        let cksum = udp_checksum_ipv6(src, dst, self.as_slice());
        self.set_checksum(cksum);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{UdpHeader, UdpHeaderMut};

    extern crate std;

    // =========================================================
    // Test data
    // =========================================================

    const UDP_SRC_PORT: u16 = 12345;
    const UDP_DST_PORT: u16 = 53;     // DNS
    const UDP_PAYLOAD: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    const UDP_LENGTH: u16 = (Udp::HEADER_LEN + UDP_PAYLOAD.len()) as u16; // 12

    // IPv4 addresses for pseudo-header
    const IPV4_SRC: [u8; 4] = [192, 168, 1, 10];
    const IPV4_DST: [u8; 4] = [8, 8, 8, 8];

    // IPv6 addresses for pseudo-header
    const IPV6_SRC: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1,
    ];
    const IPV6_DST: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 2,
    ];

    // Build a raw UDP datagram with a given checksum value.
    // Payload is always UDP_PAYLOAD.
    fn build_udp(checksum: u16) -> [u8; 12] {
        let src = UDP_SRC_PORT.to_be_bytes();
        let dst = UDP_DST_PORT.to_be_bytes();
        let len = UDP_LENGTH.to_be_bytes();
        let ck  = checksum.to_be_bytes();
        [
            src[0], src[1],
            dst[0], dst[1],
            len[0], len[1],
            ck[0],  ck[1],
            UDP_PAYLOAD[0], UDP_PAYLOAD[1], UDP_PAYLOAD[2], UDP_PAYLOAD[3],
        ]
    }

    // Build a UDP datagram with the correct IPv4 checksum pre-computed.
    fn build_udp_valid_ipv4() -> [u8; 12] {
        let bytes = build_udp(0x0000);
        let cksum = udp_checksum_ipv4(IPV4_SRC, IPV4_DST, &bytes);
        build_udp(cksum)
    }

    // Build a UDP datagram with the correct IPv6 checksum pre-computed.
    fn build_udp_valid_ipv6() -> [u8; 12] {
        let bytes = build_udp(0x0000);
        let cksum = udp_checksum_ipv6(IPV6_SRC, IPV6_DST, &bytes);
        build_udp(cksum)
    }

    // =========================================================
    // Group 1 — basic parsing
    // =========================================================

    #[test]
    fn parses_basic_udp_header() {
        let bytes = build_udp(0xabcd);
        let header = UdpHeader::new(&bytes).unwrap();

        assert_eq!(header.src_port(), UDP_SRC_PORT);
        assert_eq!(header.dst_port(), UDP_DST_PORT);
        assert_eq!(header.length(), UDP_LENGTH);
        assert_eq!(header.checksum(), 0xabcd);
        assert_eq!(header.payload(), &UDP_PAYLOAD);
    }

    #[test]
    fn payload_is_bounded_by_length_field() {
        // extra bytes after the declared length must not appear in payload()
        let mut bytes = std::vec::Vec::new();
        bytes.extend_from_slice(&build_udp(0x0000));
        bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // trailing garbage

        let header = UdpHeader::new(&bytes).unwrap();
        assert_eq!(header.payload(), &UDP_PAYLOAD);
        assert_eq!(header.payload().len(), 4);
    }

    #[test]
    fn payload_is_empty_for_header_only_datagram() {
        // length = 8 → no payload
        let bytes = [
            0x30, 0x39,  // src port
            0x00, 0x35,  // dst port
            0x00, 0x08,  // length = 8 (header only)
            0x00, 0x00,  // checksum
        ];
        let header = UdpHeader::new(&bytes).unwrap();
        assert_eq!(header.payload(), &[]);
    }

    // =========================================================
    // Group 2 — validate() error paths
    // =========================================================

    #[test]
    fn rejects_too_short() {
        let bytes = &build_udp(0x0000)[..7]; // one byte short

        assert_eq!(
            UdpHeader::new(bytes),
            Err(PacketError::TooShort {
                needed: Udp::HEADER_LEN,
                actual: 7,
            })
        );
    }

    #[test]
    fn rejects_length_field_smaller_than_header() {
        let mut bytes = build_udp(0x0000);
        bytes[4] = 0x00;
        bytes[5] = 0x07; // length = 7 < 8

        assert_eq!(
            UdpHeader::new(&bytes),
            Err(PacketError::InvalidUdpLength {
                header_len: Udp::HEADER_LEN,
                actual: 7,
            })
        );
    }

    #[test]
    fn rejects_length_field_of_zero() {
        let mut bytes = build_udp(0x0000);
        bytes[4] = 0x00;
        bytes[5] = 0x00; // length = 0

        assert_eq!(
            UdpHeader::new(&bytes),
            Err(PacketError::InvalidUdpLength {
                header_len: Udp::HEADER_LEN,
                actual: 0,
            })
        );
    }

    // =========================================================
    // Group 3 — mutation
    // =========================================================

    #[test]
    fn edits_udp_header_without_losing_read_api() {
        let mut bytes = build_udp(0x0000);
        let mut header = UdpHeaderMut::new(&mut bytes).unwrap();

        header.set_src_port(9999);
        header.set_dst_port(80);
        header.set_length(8);
        header.set_checksum(0xbeef);

        assert_eq!(header.src_port(), 9999);
        assert_eq!(header.dst_port(), 80);
        assert_eq!(header.length(), 8);
        assert_eq!(header.checksum(), 0xbeef);
    }

    // =========================================================
    // Group 4 — IPv4 checksum
    // =========================================================

    #[test]
    fn new_verified_ipv4_accepts_valid_checksum() {
        let bytes = build_udp_valid_ipv4();
        assert!(UdpHeader::new_verified_ipv4(&bytes, IPV4_SRC, IPV4_DST).is_ok());
    }

    #[test]
    fn new_verified_ipv4_rejects_invalid_checksum() {
        let mut bytes = build_udp_valid_ipv4();
        bytes[6] ^= 0xff; // corrupt checksum

        assert!(matches!(
            UdpHeader::new_verified_ipv4(&bytes, IPV4_SRC, IPV4_DST),
            Err(PacketError::InvalidChecksum { .. })
        ));
    }

    #[test]
    fn new_verified_ipv4_accepts_zero_checksum() {
        // 0x0000 means "not computed" in UDP over IPv4 — must be accepted
        let bytes = build_udp(0x0000);
        assert!(UdpHeader::new_verified_ipv4(&bytes, IPV4_SRC, IPV4_DST).is_ok());
    }

    #[test]
    fn new_verified_ipv4_rejects_wrong_src() {
        let bytes = build_udp_valid_ipv4();
        let wrong_src = [10, 0, 0, 1];

        // checksum was built with IPV4_SRC — wrong src must fail
        assert!(matches!(
            UdpHeader::new_verified_ipv4(&bytes, wrong_src, IPV4_DST),
            Err(PacketError::InvalidChecksum { .. })
        ));
    }

    #[test]
    fn new_verified_ipv4_rejects_wrong_dst() {
        let bytes = build_udp_valid_ipv4();
        let wrong_dst = [1, 1, 1, 1];

        assert!(matches!(
            UdpHeader::new_verified_ipv4(&bytes, IPV4_SRC, wrong_dst),
            Err(PacketError::InvalidChecksum { .. })
        ));
    }

    #[test]
    fn compute_and_set_checksum_ipv4_round_trips() {
        let mut bytes = build_udp(0xdead); // start with garbage checksum
        let mut header = UdpHeaderMut::new(&mut bytes).unwrap();
        header.compute_and_set_checksum_ipv4(IPV4_SRC, IPV4_DST);
        drop(header);

        assert!(UdpHeader::new_verified_ipv4(&bytes, IPV4_SRC, IPV4_DST).is_ok());
    }

    #[test]
    fn compute_and_set_checksum_ipv4_round_trips_after_mutation() {
        let mut bytes = build_udp_valid_ipv4();
        let mut header = UdpHeaderMut::new(&mut bytes).unwrap();

        header.set_src_port(9999);
        header.set_dst_port(80);
        header.compute_and_set_checksum_ipv4(IPV4_SRC, IPV4_DST);
        drop(header);

        assert!(UdpHeader::new_verified_ipv4(&bytes, IPV4_SRC, IPV4_DST).is_ok());
    }

    // =========================================================
    // Group 5 — IPv6 checksum
    // =========================================================

    #[test]
    fn new_verified_ipv6_accepts_valid_checksum() {
        let bytes = build_udp_valid_ipv6();
        assert!(UdpHeader::new_verified_ipv6(&bytes, IPV6_SRC, IPV6_DST).is_ok());
    }

    #[test]
    fn new_verified_ipv6_rejects_invalid_checksum() {
        let mut bytes = build_udp_valid_ipv6();
        bytes[6] ^= 0xff;

        assert!(matches!(
            UdpHeader::new_verified_ipv6(&bytes, IPV6_SRC, IPV6_DST),
            Err(PacketError::InvalidChecksum { .. })
        ));
    }

    #[test]
    fn new_verified_ipv6_rejects_zero_checksum() {
        // unlike IPv4, zero checksum is never valid in UDP over IPv6
        let bytes = build_udp(0x0000);

        assert!(matches!(
            UdpHeader::new_verified_ipv6(&bytes, IPV6_SRC, IPV6_DST),
            Err(PacketError::InvalidChecksum { .. })
        ));
    }

    #[test]
    fn new_verified_ipv6_rejects_wrong_src() {
        let bytes = build_udp_valid_ipv6();
        let wrong_src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];

        assert!(matches!(
            UdpHeader::new_verified_ipv6(&bytes, wrong_src, IPV6_DST),
            Err(PacketError::InvalidChecksum { .. })
        ));
    }

    #[test]
    fn compute_and_set_checksum_ipv6_round_trips() {
        let mut bytes = build_udp(0xdead);
        let mut header = UdpHeaderMut::new(&mut bytes).unwrap();
        header.compute_and_set_checksum_ipv6(IPV6_SRC, IPV6_DST);
        drop(header);

        assert!(UdpHeader::new_verified_ipv6(&bytes, IPV6_SRC, IPV6_DST).is_ok());
    }

    #[test]
    fn compute_and_set_checksum_ipv6_round_trips_after_mutation() {
        let mut bytes = build_udp_valid_ipv6();
        let mut header = UdpHeaderMut::new(&mut bytes).unwrap();

        header.set_src_port(4444);
        header.set_dst_port(443);
        header.compute_and_set_checksum_ipv6(IPV6_SRC, IPV6_DST);
        drop(header);

        assert!(UdpHeader::new_verified_ipv6(&bytes, IPV6_SRC, IPV6_DST).is_ok());
    }

    // =========================================================
    // Group 6 — checksum helper functions directly
    // =========================================================

    #[test]
    fn udp_checksum_ipv4_is_stable() {
        let bytes = build_udp(0x0000);
        assert_eq!(
            udp_checksum_ipv4(IPV4_SRC, IPV4_DST, &bytes),
            udp_checksum_ipv4(IPV4_SRC, IPV4_DST, &bytes),
        );
    }

    #[test]
    fn udp_checksum_ipv6_is_stable() {
        let bytes = build_udp(0x0000);
        assert_eq!(
            udp_checksum_ipv6(IPV6_SRC, IPV6_DST, &bytes),
            udp_checksum_ipv6(IPV6_SRC, IPV6_DST, &bytes),
        );
    }

    #[test]
    fn ipv4_and_ipv6_checksums_differ_for_same_payload() {
        // same UDP bytes, different IP versions — checksums must differ
        // because the pseudo-headers are different
        let bytes = build_udp(0x0000);
        let ck4 = udp_checksum_ipv4(IPV4_SRC, IPV4_DST, &bytes);
        let ck6 = udp_checksum_ipv6(IPV6_SRC, IPV6_DST, &bytes);
        assert_ne!(ck4, ck6);
    }

    #[test]
    fn checksum_changes_when_payload_changes() {
        let bytes_a = build_udp(0x0000);
        let mut bytes_b = build_udp(0x0000);
        bytes_b[8] ^= 0xff; // flip a payload byte

        let ck_a = udp_checksum_ipv4(IPV4_SRC, IPV4_DST, &bytes_a);
        let ck_b = udp_checksum_ipv4(IPV4_SRC, IPV4_DST, &bytes_b);
        assert_ne!(ck_a, ck_b);
    }

    #[test]
    fn checksum_changes_when_port_changes() {
        let bytes_a = build_udp(0x0000);
        let mut bytes_b = build_udp(0x0000);
        bytes_b[0] ^= 0xff; // flip src port high byte

        let ck_a = udp_checksum_ipv4(IPV4_SRC, IPV4_DST, &bytes_a);
        let ck_b = udp_checksum_ipv4(IPV4_SRC, IPV4_DST, &bytes_b);
        assert_ne!(ck_a, ck_b);
    }
}