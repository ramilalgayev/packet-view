use crate::{PacketError, PacketView, PacketViewMut};
use crate::view::PacketSpec;

pub mod ext_headers;

use ext_headers::{HDR_EXT_LEN};

pub use ext_headers::{
    FragmentHeader,
    NextHeader,
    NextHeaderData,
    NextHeaderType,
    NextHeaders,
};

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

    fn next_header_raw(&self) -> u8 {
        self.bytes()[6]
    }

    fn extension_headers(&self) -> NextHeaders<'_> {
        NextHeaders {
            remaining: &self.bytes()[Ipv6::MIN_PACKET_LEN..],
            next: self.next_header_raw(),
            errored: false,
        }
    }

    fn fragment_header(&self) -> Option<FragmentHeader<'_>> {
        for ext in self.extension_headers() {
            if let Ok(NextHeader { data: NextHeaderData::Fragment(frag), .. }) = ext {
                return Some(frag);
            }
        }
        None
    }

    fn is_fragment(&self) -> bool {
        self.fragment_header().is_some()
    }

    fn upper_layer_protocol(&self) -> Option<u8> {
        let mut next = self.next_header_raw();
        let mut remaining = &self.bytes()[Ipv6::MIN_PACKET_LEN..];

        loop {
            let kind = NextHeaderType::from(next);
            if !kind.is_extension() {
                return Some(next);
            }
            if remaining.len() < 8 { return None; }
            
            let len = if matches!(kind, NextHeaderType::FragmentHeader) {
                HDR_EXT_LEN
            } else {
                (remaining[1] as usize + 1) * 8
            };

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

impl<'a> PacketView<'a, Ipv6> {
    pub fn new_checked(bytes: &'a [u8]) -> Result<Self, PacketError> {
        let view = Self::new(bytes)?;
        for next in view.extension_headers() {
            next?;
        }
        Ok(view)
    }

    pub fn new_checked_defrag(bytes: &'a [u8]) -> Result<Self, PacketError> {
        let view = Self::new_checked(bytes)?;
        if view.is_fragment() {
            return Err(PacketError::FragmentedPacket);
        }
        Ok(view)
    }
}

impl<'a> PacketViewMut<'a, Ipv6> {
    pub fn new_checked(bytes: &'a mut [u8]) -> Result<Self, PacketError> {
        PacketView::<Ipv6>::new_checked(bytes)?;
        Self::new(bytes)
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
    use crate::{Ipv6Header, Ipv6HeaderMut, PacketError};
    extern crate std;
    use std::vec::Vec;

    const IPV6_MIN_PACKET_LEN: usize = 40;

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

    const IPV6_HEADER: [u8; IPV6_MIN_PACKET_LEN] = [
        IPV6_VERSION_TRAFFIC_CLASS_HIGH,
        IPV6_TRAFFIC_CLASS_LOW_FLOW_HIGH,
        IPV6_FLOW_LABEL_LOW[0], IPV6_FLOW_LABEL_LOW[1],
        IPV6_PAYLOAD_LEN[0], IPV6_PAYLOAD_LEN[1],
        IPV6_NEXT_HEADER_UDP,
        IPV6_HOP_LIMIT,
        IPV6_SRC[0],  IPV6_SRC[1],  IPV6_SRC[2],  IPV6_SRC[3],
        IPV6_SRC[4],  IPV6_SRC[5],  IPV6_SRC[6],  IPV6_SRC[7],
        IPV6_SRC[8],  IPV6_SRC[9],  IPV6_SRC[10], IPV6_SRC[11],
        IPV6_SRC[12], IPV6_SRC[13], IPV6_SRC[14], IPV6_SRC[15],
        IPV6_DST[0],  IPV6_DST[1],  IPV6_DST[2],  IPV6_DST[3],
        IPV6_DST[4],  IPV6_DST[5],  IPV6_DST[6],  IPV6_DST[7],
        IPV6_DST[8],  IPV6_DST[9],  IPV6_DST[10], IPV6_DST[11],
        IPV6_DST[12], IPV6_DST[13], IPV6_DST[14], IPV6_DST[15],
    ];

    // HopByHop (type 0), 8 bytes, next = UDP (17), hdr_ext_len = 0
    const HOP_BY_HOP_EXT: [u8; 8] = [17, 0, 0, 0, 0, 0, 0, 0];

    // Routing (type 43), 16 bytes, next = UDP (17), hdr_ext_len = 1 → (1+1)*8 = 16
    const ROUTING_EXT: [u8; 16] = [17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // Fragment (type 44), always 8 bytes
    // next = UDP (17), offset = 1 (bits 15..3 of bytes 2-3), M = 1, id = 0xdeadbeef
    // bytes 2-3: offset=1 → 0b0000_0000_0000_1_xxx → shifted: 1<<3 = 8 = 0x0008, M=1 → 0x0009
    const FRAGMENT_EXT_MORE: [u8; 8] = [17, 0, 0x00, 0x09, 0xde, 0xad, 0xbe, 0xef];

    // Same but M = 0 (last fragment), offset = 1
    const FRAGMENT_EXT_LAST: [u8; 8] = [17, 0, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef];

    // Builds a full packet: fixed header (next_header set by caller after) + ext bytes + payload
    fn build_ipv6_packet(next_header: u8, ext_headers: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut packet = IPV6_HEADER.to_vec();
        let payload_len = (ext_headers.len() + payload.len()) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[6] = next_header;
        packet.extend_from_slice(ext_headers);
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn parses_basic_ipv6_header() {
        let header = Ipv6Header::new(&IPV6_HEADER).unwrap();

        assert_eq!(header.version(), 6);
        assert_eq!(header.traffic_class(), 0x01);
        assert_eq!(header.flow_label(), 0x23456);
        assert_eq!(header.payload_len(), 0);
        assert_eq!(header.next_header_raw(), IPV6_NEXT_HEADER_UDP);
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
        assert_eq!(header.next_header_raw(), 6);
        assert_eq!(header.hop_limit(), 128);
        assert_eq!(header.src(), new_src);
        assert_eq!(header.dst(), new_dst);
    }

    #[test]
    fn rejects_short_ipv6_header() {
        let short_header = &IPV6_HEADER[..IPV6_MIN_PACKET_LEN - 1];

        assert_eq!(
            Ipv6Header::new(short_header),
            Err(PacketError::TooShort {
                needed: IPV6_MIN_PACKET_LEN,
                actual: IPV6_MIN_PACKET_LEN - 1,
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

    #[test]
    fn no_extension_headers_iterator_is_empty() {
        let header = Ipv6Header::new(&IPV6_HEADER).unwrap();
        let exts: Vec<_> = header.extension_headers().collect();
        assert!(exts.is_empty());
    }

    #[test]
    fn single_hop_by_hop_extension_header() {
        let packet = build_ipv6_packet(0, &HOP_BY_HOP_EXT, &[]);
        let header = Ipv6Header::new(&packet).unwrap();

        let exts: Vec<_> = header.extension_headers()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].kind, NextHeaderType::HopByHopOptions);
        assert_eq!(exts[0].len_bytes, 8);
        assert_eq!(exts[0].next_header, 17);
    }

    #[test]
    fn chained_hop_by_hop_then_routing() {
        // HopByHop → Routing → UDP
        let mut hop = HOP_BY_HOP_EXT;
        hop[0] = 43; // next = Routing

        let mut ext_bytes = Vec::new();
        ext_bytes.extend_from_slice(&hop);
        ext_bytes.extend_from_slice(&ROUTING_EXT); // next = UDP (17)

        let packet = build_ipv6_packet(0, &ext_bytes, &[]);
        let header = Ipv6Header::new(&packet).unwrap();

        let exts: Vec<_> = header.extension_headers()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(exts.len(), 2);
        assert_eq!(exts[0].kind, NextHeaderType::HopByHopOptions);
        assert_eq!(exts[0].len_bytes, 8);
        assert_eq!(exts[1].kind, NextHeaderType::RoutingHeader);
        assert_eq!(exts[1].len_bytes, 16);
        assert_eq!(exts[1].next_header, 17);
    }

    #[test]
    fn upper_layer_protocol_with_no_extension_headers() {
        let header = Ipv6Header::new(&IPV6_HEADER).unwrap();
        assert_eq!(header.upper_layer_protocol(), Some(17));
    }

    #[test]
    fn upper_layer_protocol_skips_extension_headers() {
        let mut hop = HOP_BY_HOP_EXT;
        hop[0] = 43; // next = Routing

        let mut ext_bytes = Vec::new();
        ext_bytes.extend_from_slice(&hop);
        ext_bytes.extend_from_slice(&ROUTING_EXT); // next = UDP (17)

        let packet = build_ipv6_packet(0, &ext_bytes, &[]);
        let header = Ipv6Header::new(&packet).unwrap();

        assert_eq!(header.upper_layer_protocol(), Some(17));
    }

    #[test]
    fn fragment_header_more_fragments() {
        let packet = build_ipv6_packet(44, &FRAGMENT_EXT_MORE, &[]);
        let header = Ipv6Header::new(&packet).unwrap();

        assert!(header.is_fragment());

        let frag = header.fragment_header().unwrap();
        assert_eq!(frag.next_header(), 17);
        assert_eq!(frag.fragment_offset(), 1);
        assert!(frag.more_fragments());
        assert!(!frag.is_last_fragment());
        assert_eq!(frag.identification(), 0xdeadbeef);
    }

    #[test]
    fn fragment_header_last_fragment() {
        let packet = build_ipv6_packet(44, &FRAGMENT_EXT_LAST, &[]);
        let header = Ipv6Header::new(&packet).unwrap();

        let frag = header.fragment_header().unwrap();
        assert!(!frag.more_fragments());
        assert!(frag.is_last_fragment());
        assert_eq!(frag.identification(), 0xdeadbeef);
    }

    #[test]
    fn is_fragment_false_when_no_fragment_header() {
        let header = Ipv6Header::new(&IPV6_HEADER).unwrap();
        assert!(!header.is_fragment());
    }

    #[test]
    fn fragment_header_len_is_always_8_bytes() {
        let packet = build_ipv6_packet(44, &FRAGMENT_EXT_MORE, &[]);
        let header = Ipv6Header::new(&packet).unwrap();

        let exts: Vec<_> = header.extension_headers()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].len_bytes, 8);
    }

    #[test]
    fn new_checked_defrag_rejects_packet_with_more_fragments() {
        let packet = build_ipv6_packet(44, &FRAGMENT_EXT_MORE, &[]);

        assert_eq!(
            Ipv6Header::new_checked_defrag(&packet),
            Err(PacketError::FragmentedPacket)
        );
    }

    #[test]
    fn new_checked_defrag_rejects_last_fragment() {
        // Even M=0 is still a fragment — the header being present means reassembly is needed
        let packet = build_ipv6_packet(44, &FRAGMENT_EXT_LAST, &[]);

        assert_eq!(
            Ipv6Header::new_checked_defrag(&packet),
            Err(PacketError::FragmentedPacket)
        );
    }

    #[test]
    fn malformed_ext_header_too_short_for_minimum() {
        // Only 4 bytes after fixed header — below the 8-byte minimum
        let truncated = [0u8; 4];
        let packet = build_ipv6_packet(0, &truncated, &[]);
        let header = Ipv6Header::new(&packet).unwrap(); // fixed header is fine

        let result: Result<Vec<_>, _> = header.extension_headers().collect();
        assert_eq!(
            result,
            Err(PacketError::TooShort { needed: 8, actual: 4 })
        );
    }

    #[test]
    fn malformed_ext_header_len_exceeds_remaining_bytes() {
        // hdr_ext_len = 5 → claims (5+1)*8 = 48 bytes, but only 8 bytes present
        let mut bad_ext = HOP_BY_HOP_EXT;
        bad_ext[1] = 5;

        let packet = build_ipv6_packet(0, &bad_ext, &[]);
        let header = Ipv6Header::new(&packet).unwrap();

        let result: Result<Vec<_>, _> = header.extension_headers().collect();
        assert_eq!(
            result,
            Err(PacketError::TooShort { needed: 48, actual: 8 })
        );
    }

    #[test]
    fn iterator_stops_after_error() {
        let truncated = [0u8; 4];
        let packet = build_ipv6_packet(0, &truncated, &[]);
        let header = Ipv6Header::new(&packet).unwrap();

        let mut iter = header.extension_headers();
        assert!(iter.next().unwrap().is_err()); // first → error
        assert!(iter.next().is_none());          // second → stopped
    }

    #[test]
    fn new_checked_rejects_malformed_extension_headers() {
        let truncated = [0u8; 4];
        let packet = build_ipv6_packet(0, &truncated, &[]);

        assert_eq!(
            Ipv6Header::new_checked(&packet),
            Err(PacketError::TooShort { needed: 8, actual: 4 })
        );
    }

    #[test]
    fn unknown_next_header_mid_chain_stops_iterator() {
        // Unknown(253) is not an extension header — iterator stops there
        let mut hop = HOP_BY_HOP_EXT;
        hop[0] = 253; // next = Unknown(253)

        let packet = build_ipv6_packet(0, &hop, &[]);
        let header = Ipv6Header::new(&packet).unwrap();

        let exts: Vec<_> = header.extension_headers()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(exts.len(), 1);
        assert_eq!(header.upper_layer_protocol(), Some(253));
    }

    #[test]
    fn new_accepts_packet_with_malformed_ext_headers() {
        // new() only checks the fixed 40-byte header
        let truncated = [0u8; 4];
        let packet = build_ipv6_packet(0, &truncated, &[]);
        assert!(Ipv6Header::new(&packet).is_ok());
    }

    #[test]
    fn new_checked_accepts_well_formed_single_ext_header() {
        let packet = build_ipv6_packet(0, &HOP_BY_HOP_EXT, &[]);
        assert!(Ipv6Header::new_checked(&packet).is_ok());
    }

    #[test]
    fn new_checked_accepts_packet_with_no_ext_headers() {
        assert!(Ipv6Header::new_checked(&IPV6_HEADER).is_ok());
    }

    #[test]
    fn new_checked_accepts_chained_ext_headers() {
        let mut hop = HOP_BY_HOP_EXT;
        hop[0] = 43;

        let mut ext_bytes = Vec::new();
        ext_bytes.extend_from_slice(&hop);
        ext_bytes.extend_from_slice(&ROUTING_EXT);

        let packet = build_ipv6_packet(0, &ext_bytes, &[]);
        assert!(Ipv6Header::new_checked(&packet).is_ok());
    }
}