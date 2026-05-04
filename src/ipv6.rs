use crate::{PacketError, PacketView, PacketViewMut};
use crate::view::PacketSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHeaderType {
    BasicIPv6Header,                        // Null
    HopByHopOptions,                        // 0
    RoutingHeader,                          // 43
    FragmentHeader,                         // 44
    AuthenticationHeader,                   // 51
    EncapsulationSecurityPayloadHeader,     // 50
    DestinationOptions,                     // 60
    MobilityHeader,                         // 135
    NoNextHeader,                           // 59
    // Upper layer
    TCP,                                    // 6
    UDP,                                    // 17
    ICMPv6,                                 // 58
    // Default
    Unknown(u8),
}

impl From<u8> for NextHeaderType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::HopByHopOptions,
            6 => Self::TCP,
            17 => Self::UDP,
            43 => Self::RoutingHeader,
            44 => Self::FragmentHeader,
            50 => Self::EncapsulationSecurityPayloadHeader,
            51 => Self::AuthenticationHeader,
            58 => Self::ICMPv6,
            59 => Self::NoNextHeader,
            60 => Self::DestinationOptions,
            135 => Self::MobilityHeader,
            other => Self::Unknown(other),
        }
    }
}

impl NextHeaderType {
    pub fn is_extension(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NextHeader<'a> {
    pub kind: NextHeaderType,
    bytes: &'a [u8],
}

impl<'a> NextHeader<'a> {
    pub fn next_header(&self) -> u8 {
        self.bytes[0]
    }

    pub fn len_bytes(&self) -> usize {
        (self.bytes[1] as usize + 1) * 8
    }

    pub fn data(&self) -> &'a [u8] {
        &self.bytes[2..self.len_bytes()]
    }
}

pub struct NextHeaders<'a> {
    remaining: &'a [u8],
    next: u8,
    errored: bool,
}

impl<'a> Iterator for NextHeaders<'a> {
    type Item = Result<NextHeader<'a>, PacketError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.errored {
            return None;
        }

        let kind = NextHeaderType::from(self.next);
        if !kind.is_extension() {
            return None; // we've reached the payload protocol, stop
        }

        if self.remaining.len() < 8 {
            self.errored = true;
            return Some(Err(PacketError::TooShort {
                needed: 8,
                actual: self.remaining.len(),
            }));
        }

        let len = (self.remaining[1] as usize + 1) * 8;

        if self.remaining.len() < len {
            self.errored = true;
            return Some(Err(PacketError::TooShort {
                needed: len,
                actual: self.remaining.len(),
            }));
        }

        let header = NextHeader {
            kind,
            bytes: &self.remaining[..len],
        };

        self.next = self.remaining[0]; // next_header field of current header
        self.remaining = &self.remaining[len..];

        Some(Ok(header))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ipv6 {}

impl Ipv6 {
    pub const MIN_PACKET_LEN: usize = 40;
    pub const VERSION: u8 = 6;
}

impl PacketSpec for Ipv6 {
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

        Ok(())
    }

    fn header_len(_: &[u8]) -> usize {
        Self::MIN_PACKET_LEN
    }
}

pub trait Ipv6Packet {
    fn bytes(&self) -> &[u8];

    fn version(&self) -> u8 {
        self.bytes()[0] >> 4
    }

    fn traffic_class(&self) -> u8 {
        ((self.bytes()[0] & 0x0f) << 4) | (self.bytes()[1] >> 4)
    }

    fn flow_label(&self) -> u32 {
        let b1 = (self.bytes()[1] & 0x0f) as u32;
        let b2 = self.bytes()[2] as u32;
        let b3 = self.bytes()[3] as u32;
        (b1 << 16) | (b2 << 8) | b3
    }

    fn payload_len(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[4], self.bytes()[5]])
    }

    fn next_header(&self) -> u8 {
        self.bytes()[6]
    }

    fn extension_headers(&self) -> NextHeaders<'_> {
        NextHeaders {
            remaining: &self.bytes()[Ipv6::MIN_PACKET_LEN..],
            next: self.next_header(),
            errored: false,
        }
    }

    /// Walks the extension header chain and returns the upper-layer protocol byte.
    /// Returns None if the chain is malformed.
    fn upper_layer_protocol(&self) -> Option<u8> {
        let mut next = self.next_header();
        let mut remaining = &self.bytes()[Ipv6::MIN_PACKET_LEN..];

        loop {
            let kind = NextHeaderType::from(next);
            if !kind.is_extension() {
                return Some(next);
            }
            if remaining.len() < 8 { return None; }
            let len = (remaining[1] as usize + 1) * 8;
            if remaining.len() < len { return None; }
            next = remaining[0];
            remaining = &remaining[len..];
        }
    }

    fn hop_limit(&self) -> u8 {
        self.bytes()[7]
    }

    fn src(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.bytes()[8..24]);
        out
    }

    fn dst(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.bytes()[24..40]);
        out
    }

    fn payload(&self) -> &[u8] {
        let start = Ipv6::MIN_PACKET_LEN;
        let end = core::cmp::min(start + self.payload_len() as usize, self.bytes().len());
        &self.bytes()[start..end]
    }
}

impl<'a> Ipv6Packet for PacketView<'a, Ipv6> {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> Ipv6Packet for PacketViewMut<'a, Ipv6> {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> PacketViewMut<'a, Ipv6> {
    pub fn set_payload_len(&mut self, value: u16) {
        self.as_slice_mut()[4..6].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_next_header(&mut self, value: u8) {
        self.as_slice_mut()[6] = value;
    }

    pub fn set_hop_limit(&mut self, value: u8) {
        self.as_slice_mut()[7] = value;
    }

    pub fn set_src(&mut self, value: [u8; 16]) {
        self.as_slice_mut()[8..24].copy_from_slice(&value);
    }

    pub fn set_dst(&mut self, value: [u8; 16]) {
        self.as_slice_mut()[24..40].copy_from_slice(&value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ipv6Header, Ipv6HeaderMut};

    const IPV6_MIN_PACKAGE_LEN: usize = 40;

    const IPV6_VERSION_TRAFFIC_CLASS_HIGH: u8 = 0x60;
    const IPV6_TRAFFIC_CLASS_LOW_FLOW_HIGH: u8 = 0x12;
    const IPV6_FLOW_LABEL_LOW: [u8; 2] = [0x34, 0x56];
    const IPV6_PAYLOAD_LEN: [u8; 2] = 0u16.to_be_bytes();
    const IPV6_NEXT_HEADER_UDP: u8 = 17;
    const IPV6_HOP_LIMIT: u8 = 64;
    const IPV6_SRC: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1,
    ];
    const IPV6_DST: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 2,
    ];

    const IPV6_HEADER: [u8; IPV6_MIN_PACKAGE_LEN] = [
        IPV6_VERSION_TRAFFIC_CLASS_HIGH,
        IPV6_TRAFFIC_CLASS_LOW_FLOW_HIGH,
        IPV6_FLOW_LABEL_LOW[0], IPV6_FLOW_LABEL_LOW[1],
        IPV6_PAYLOAD_LEN[0], IPV6_PAYLOAD_LEN[1],
        IPV6_NEXT_HEADER_UDP,
        IPV6_HOP_LIMIT,
        IPV6_SRC[0], IPV6_SRC[1], IPV6_SRC[2], IPV6_SRC[3],
        IPV6_SRC[4], IPV6_SRC[5], IPV6_SRC[6], IPV6_SRC[7],
        IPV6_SRC[8], IPV6_SRC[9], IPV6_SRC[10], IPV6_SRC[11],
        IPV6_SRC[12], IPV6_SRC[13], IPV6_SRC[14], IPV6_SRC[15],
        IPV6_DST[0], IPV6_DST[1], IPV6_DST[2], IPV6_DST[3],
        IPV6_DST[4], IPV6_DST[5], IPV6_DST[6], IPV6_DST[7],
        IPV6_DST[8], IPV6_DST[9], IPV6_DST[10], IPV6_DST[11],
        IPV6_DST[12], IPV6_DST[13], IPV6_DST[14], IPV6_DST[15],
    ];

    #[test]
    fn parses_basic_ipv6_header() {
        let header = Ipv6Header::new(&IPV6_HEADER).unwrap();

        assert_eq!(header.version(), 6);
        assert_eq!(header.traffic_class(), 0x01);
        assert_eq!(header.flow_label(), 0x23456);
        assert_eq!(header.payload_len(), 0);
        assert_eq!(header.next_header(), IPV6_NEXT_HEADER_UDP);
        assert_eq!(header.hop_limit(), IPV6_HOP_LIMIT);
        assert_eq!(header.src(), IPV6_SRC);
        assert_eq!(header.dst(), IPV6_DST);
        assert_eq!(header.payload(), &[]);
    }

    #[test]
    fn edits_ipv6_header_without_losing_read_api() {
        let mut bytes = IPV6_HEADER;
        let mut header = Ipv6HeaderMut::new(&mut bytes).unwrap();
        let new_src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        let new_dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4];

        header.set_payload_len(32);
        header.set_next_header(6);
        header.set_hop_limit(128);
        header.set_src(new_src);
        header.set_dst(new_dst);

        assert_eq!(header.payload_len(), 32);
        assert_eq!(header.next_header(), 6);
        assert_eq!(header.hop_limit(), 128);
        assert_eq!(header.src(), new_src);
        assert_eq!(header.dst(), new_dst);
    }

    #[test]
    fn rejects_short_ipv6_header() {
        let short_header = &IPV6_HEADER[..IPV6_MIN_PACKAGE_LEN - 1];

        assert_eq!(
            Ipv6Header::new(short_header),
            Err(PacketError::TooShort {
                needed: IPV6_MIN_PACKAGE_LEN,
                actual: IPV6_MIN_PACKAGE_LEN - 1,
            })
        );
    }

    #[test]
    fn rejects_wrong_ipv6_version() {
        let mut header_bytes = IPV6_HEADER;
        header_bytes[0] = 0x40;

        assert_eq!(
            Ipv6Header::new(&header_bytes),
            Err(PacketError::InvalidVersion {
                expected: 6,
                actual: 4,
            })
        );
    }
}
