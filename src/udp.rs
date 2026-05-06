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

pub fn udp_checksum_ipv4(
    src: [u8; 4],
    dst: [u8; 4],
    udp_bytes: &[u8],
) -> u16 {
    let udp_len = udp_bytes.len() as u16;

    let pseudo = [
        src[0], src[1], src[2], src[3],
        dst[0], dst[1], dst[2], dst[3],
        0,
        17,
        (udp_len >> 8) as u8,
        (udp_len & 0xff) as u8,
    ];

    let pseudo_sum = checksum::ones_complement_sum(&pseudo, None) as u32;
    let udp_sum = checksum::ones_complement_sum(udp_bytes, Some(6)) as u32;

    let sum = pseudo_sum + udp_sum;

    let sum = (sum & 0xffff).wrapping_add(sum >> 16);
    let sum = (sum & 0xffff).wrapping_add(sum >> 16);
    !(sum as u16)
}

pub fn udp_checksum_ipv6(
    src: [u8; 16],
    dst: [u8; 16],
    udp_bytes: &[u8],
) -> u16 {
    let udp_len = udp_bytes.len() as u32;

    let pseudo = [
        src[0],  src[1],  src[2],  src[3],
        src[4],  src[5],  src[6],  src[7],
        src[8],  src[9],  src[10], src[11],
        src[12], src[13], src[14], src[15],
        dst[0],  dst[1],  dst[2],  dst[3],
        dst[4],  dst[5],  dst[6],  dst[7],
        dst[8],  dst[9],  dst[10], dst[11],
        dst[12], dst[13], dst[14], dst[15],
        (udp_len >> 24) as u8,
        (udp_len >> 16) as u8,
        (udp_len >> 8)  as u8,
        (udp_len)       as u8,
        0, 0, 0,
        17,
    ];

    let pseudo_sum = checksum::ones_complement_sum(&pseudo, None) as u32;
    let udp_sum = checksum::ones_complement_sum(udp_bytes, Some(6)) as u32;

    let sum = pseudo_sum + udp_sum;
    let sum = (sum & 0xffff).wrapping_add(sum >> 16);
    let sum = (sum & 0xffff).wrapping_add(sum >> 16);
    !(sum as u16)
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