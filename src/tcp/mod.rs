// src/tcp/mod.rs

pub mod flags;
pub mod options;
pub mod seq;

use crate::{PacketError, PacketView, PacketViewMut};
use crate::view::PacketSpec;
use crate::checksum;
use flags::*;
use options::TcpOptions;

pub use seq::{
    wrapping_after, wrapping_after_or_eq,
    wrapping_before, wrapping_before_or_eq,
    wrapping_distance,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tcp {}

impl Tcp {
    pub const MIN_HEADER_LEN: usize = 20;
}

impl PacketSpec for Tcp {
    fn validate(bytes: &[u8]) -> Result<(), PacketError> {
        if bytes.len() < Tcp::MIN_HEADER_LEN {
            return Err(PacketError::TooShort {
                needed: Tcp::MIN_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let data_offset = bytes[12] >> 4;
        if data_offset < 5 {
            return Err(PacketError::InvalidTcpHeaderLength { data_offset });
        }

        let header_len = data_offset as usize * 4;
        if bytes.len() < header_len {
            return Err(PacketError::TooShort {
                needed: header_len,
                actual: bytes.len(),
            });
        }

        Ok(())
    }

    fn header_len(bytes: &[u8]) -> usize {
        debug_assert!(bytes.len() > Tcp::MIN_HEADER_LEN, "header_len called on too small slice");
        (bytes[12] >> 4) as usize * 4
    }
}

pub trait TcpPacket {
    fn bytes(&self) -> &[u8];

    fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[0], self.bytes()[1]])
    }

    fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[2], self.bytes()[3]])
    }

    fn seq_number(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes()[4], self.bytes()[5],
            self.bytes()[6], self.bytes()[7],
        ])
    }

    fn ack_number(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes()[8],  self.bytes()[9],
            self.bytes()[10], self.bytes()[11],
        ])
    }

    fn data_offset(&self) -> u8 {
        self.bytes()[12] >> 4
    }

    fn header_len(&self) -> usize {
        self.data_offset() as usize * 4
    }

    fn flags_raw(&self) -> u16 {
        let high = (self.bytes()[12] & 0x01) as u16; // NS bit
        let low  =  self.bytes()[13] as u16;
        (high << 8) | low
    }

    fn is_ns(&self)  -> bool { self.flags_raw() & NS  != 0 }
    fn is_cwr(&self) -> bool { self.flags_raw() & CWR != 0 }
    fn is_ece(&self) -> bool { self.flags_raw() & ECE != 0 }
    fn is_urg(&self) -> bool { self.flags_raw() & URG != 0 }
    fn is_ack(&self) -> bool { self.flags_raw() & ACK != 0 }
    fn is_psh(&self) -> bool { self.flags_raw() & PSH != 0 }
    fn is_rst(&self) -> bool { self.flags_raw() & RST != 0 }
    fn is_syn(&self) -> bool { self.flags_raw() & SYN != 0 }
    fn is_fin(&self) -> bool { self.flags_raw() & FIN != 0 }

    fn window_size(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[14], self.bytes()[15]])
    }

    fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[16], self.bytes()[17]])
    }

    fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes([self.bytes()[18], self.bytes()[19]])
    }

    fn options(&self) -> TcpOptions<'_> {
        TcpOptions {
            remaining: &self.bytes()[Tcp::MIN_HEADER_LEN..self.header_len()],
            errored: false,
            done: false,
        }
    }

    fn options_raw(&self) -> &[u8] {
        &self.bytes()[Tcp::MIN_HEADER_LEN..self.header_len()]
    }

    fn payload(&self) -> &[u8] {
        &self.bytes()[self.header_len()..]
    }
}

impl<'a> TcpPacket for PacketView<'a, Tcp> {
    fn bytes(&self) -> &[u8] { self.as_slice() }
}

impl<'a> TcpPacket for PacketViewMut<'a, Tcp> {
    fn bytes(&self) -> &[u8] { self.as_slice() }
}

// ── setters ──────────────────────────────────────────────────

impl<'a> PacketViewMut<'a, Tcp> {
    pub fn set_src_port(&mut self, value: u16) {
        self.as_slice_mut()[0..2].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_dst_port(&mut self, value: u16) {
        self.as_slice_mut()[2..4].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_seq_number(&mut self, value: u32) {
        self.as_slice_mut()[4..8].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_ack_number(&mut self, value: u32) {
        self.as_slice_mut()[8..12].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_flags(&mut self, value: u16) {
        let ns = ((value >> 8) as u8) & 0x01;
        let data_offset = self.as_slice()[12] & 0xf0;

        self.as_slice_mut()[12] = data_offset | ns;
        self.as_slice_mut()[13] = value as u8;
    }

    pub fn set_data_offset(&mut self, value: u8) {
        debug_assert!(value >= 5);
        self.as_slice_mut()[12] =
            (value << 4) | (self.as_slice()[12] & 0x0f);
    }

    pub fn set_window_size(&mut self, value: u16) {
        self.as_slice_mut()[14..16].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_checksum(&mut self, value: u16) {
        self.as_slice_mut()[16..18].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_urgent_pointer(&mut self, value: u16) {
        self.as_slice_mut()[18..20].copy_from_slice(&value.to_be_bytes());
    }
}

const TCP_PROTOCOL: u8 = 6;
const TCP_CHECKSUM_OFFSET: usize = 16;

pub fn tcp_checksum_ipv4(
    src: [u8; 4],
    dst: [u8; 4],
    tcp_bytes: &[u8],
) -> u16 {
    let tcp_len = tcp_bytes.len() as u16;

    let mut pseudo = [0u8; 12];

    pseudo[0..4].copy_from_slice(&src);
    pseudo[4..8].copy_from_slice(&dst);
    pseudo[8] = 0;
    pseudo[9] = TCP_PROTOCOL;
    pseudo[10..12].copy_from_slice(&tcp_len.to_be_bytes());

    checksum::transport_checksum_with_pseudo_header(&pseudo, tcp_bytes, TCP_CHECKSUM_OFFSET)
}

pub fn tcp_checksum_ipv6(
    src: [u8; 16],
    dst: [u8; 16],
    tcp_bytes: &[u8],
) -> u16 {
    let tcp_len = tcp_bytes.len() as u32;

    let mut pseudo = [0u8; 40];

    pseudo[0..16].copy_from_slice(&src);
    pseudo[16..32].copy_from_slice(&dst);
    pseudo[32..36].copy_from_slice(&tcp_len.to_be_bytes());
    pseudo[36..39].fill(0);
    pseudo[39] = TCP_PROTOCOL;

    checksum::transport_checksum_with_pseudo_header(&pseudo, tcp_bytes, TCP_CHECKSUM_OFFSET)
}

impl<'a> PacketView<'a, Tcp> {
    pub fn new_verified_ipv4(
        bytes: &'a [u8],
        src: [u8; 4],
        dst: [u8; 4],
    ) -> Result<Self, PacketError> {
        let view = Self::new(bytes)?;
        let expected = tcp_checksum_ipv4(src, dst, bytes);
        if expected != view.checksum() {
            return Err(PacketError::InvalidChecksum {
                expected,
                actual: view.checksum(),
            });
        }
        Ok(view)
    }

    pub fn new_verified_ipv6(
        bytes: &'a [u8],
        src: [u8; 16],
        dst: [u8; 16],
    ) -> Result<Self, PacketError> {
        let view = Self::new(bytes)?;
        let expected = tcp_checksum_ipv6(src, dst, bytes);
        if expected != view.checksum() {
            return Err(PacketError::InvalidChecksum {
                expected,
                actual: view.checksum(),
            });
        }
        Ok(view)
    }
}

impl<'a> PacketViewMut<'a, Tcp> {
    pub fn compute_and_set_checksum_ipv4(&mut self, src: [u8; 4], dst: [u8; 4]) {
        let cksum = tcp_checksum_ipv4(src, dst, self.as_slice());
        self.set_checksum(cksum);
    }

    pub fn compute_and_set_checksum_ipv6(&mut self, src: [u8; 16], dst: [u8; 16]) {
        let cksum = tcp_checksum_ipv6(src, dst, self.as_slice());
        self.set_checksum(cksum);
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TcpHeader, TcpHeaderMut, TcpOptionKind};
    use std::vec::Vec;

    // =========================================================
    // Test data constants
    // =========================================================

    const TCP_SRC_PORT: u16 = 12345;
    const TCP_DST_PORT: u16 = 80;
    const _TCP_SEQ:      u32 = 0xdeadbeef;
    const TCP_ACK:      u32 = 0xcafebabe;
    const TCP_WINDOW:   u16 = 65535;

    // IPv4 addresses
    const IPV4_SRC: [u8; 4] = [192, 168, 1, 10];
    const IPV4_DST: [u8; 4] = [93, 184, 216, 34];

    // IPv6 addresses
    const IPV6_SRC: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1,
    ];
    const IPV6_DST: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 2,
    ];

    // Builds a minimal 20-byte TCP header with given flags and checksum.
    // data_offset = 5 (no options), payload appended separately.
    fn build_tcp(flags: u16, checksum: u16) -> [u8; 20] {
        let src  = TCP_SRC_PORT.to_be_bytes();
        let dst  = TCP_DST_PORT.to_be_bytes();
        let seq  = TCP_ACK.to_be_bytes();
        let ack  = TCP_ACK.to_be_bytes();
        let ck   = checksum.to_be_bytes();
        let win  = TCP_WINDOW.to_be_bytes();

        // byte 12: data_offset=5 in high nibble, NS flag in bit 0
        let offset_flags_high = (5u8 << 4) | ((flags >> 8) as u8 & 0x01);
        let flags_low = (flags & 0xff) as u8;

        [
            src[0], src[1],
            dst[0], dst[1],
            seq[0], seq[1], seq[2], seq[3],
            ack[0], ack[1], ack[2], ack[3],
            offset_flags_high,
            flags_low,
            win[0], win[1],
            ck[0],  ck[1],
            0x00,   0x00,   // urgent pointer
        ]
    }

    // Builds a TCP segment with payload and correct IPv4 checksum.
    fn build_tcp_ipv4(flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&build_tcp(flags, 0x0000));
        bytes.extend_from_slice(payload);
        let cksum = tcp_checksum_ipv4(IPV4_SRC, IPV4_DST, &bytes);
        bytes[16] = (cksum >> 8) as u8;
        bytes[17] = (cksum & 0xff) as u8;
        bytes
    }

    // Builds a TCP segment with payload and correct IPv6 checksum.
    fn build_tcp_ipv6(flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&build_tcp(flags, 0x0000));
        bytes.extend_from_slice(payload);
        let cksum = tcp_checksum_ipv6(IPV6_SRC, IPV6_DST, &bytes);
        bytes[16] = (cksum >> 8) as u8;
        bytes[17] = (cksum & 0xff) as u8;
        bytes
    }

    // Builds a TCP header with options region and correct IPv4 checksum.
    // options_bytes must be padded to a multiple of 4.
    fn build_tcp_with_options(options_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
        assert!(options_bytes.len() % 4 == 0, "options must be 4-byte aligned");
        let data_offset = (5 + options_bytes.len() / 4) as u8;
        assert!(data_offset <= 15, "options too long");

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&build_tcp(SYN | ACK, 0x0000));
        // patch data_offset
        bytes[12] = (data_offset << 4) | (bytes[12] & 0x01);
        bytes.extend_from_slice(options_bytes);
        bytes.extend_from_slice(payload);

        let cksum = tcp_checksum_ipv4(IPV4_SRC, IPV4_DST, &bytes);
        bytes[16] = (cksum >> 8) as u8;
        bytes[17] = (cksum & 0xff) as u8;
        bytes
    }

    // =========================================================
    // Group 1 — basic parsing
    // =========================================================

    #[test]
    fn parses_basic_tcp_header() {
        let bytes = build_tcp(SYN, 0xabcd);
        let header = TcpHeader::new(&bytes).unwrap();

        assert_eq!(header.src_port(), TCP_SRC_PORT);
        assert_eq!(header.dst_port(), TCP_DST_PORT);
        assert_eq!(header.seq_number(), TCP_ACK);  // we used TCP_ACK for seq in builder
        assert_eq!(header.ack_number(), TCP_ACK);
        assert_eq!(header.data_offset(), 5);
        assert_eq!(header.header_len(), 20);
        assert_eq!(header.window_size(), TCP_WINDOW);
        assert_eq!(header.checksum(), 0xabcd);
        assert_eq!(header.urgent_pointer(), 0);
        assert_eq!(header.payload(), &[]);
        assert_eq!(header.options_raw(), &[]);
    }

    #[test]
    fn payload_is_bytes_after_header() {
        let payload = [0x01, 0x02, 0x03, 0x04];
        let bytes = build_tcp_ipv4(ACK | PSH, &payload);
        let header = TcpHeader::new(&bytes).unwrap();

        assert_eq!(header.payload(), &payload);
    }

    #[test]
    fn header_len_reflects_data_offset() {
        // data_offset = 7 → header_len = 28 (8 bytes of options)
        let options = [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]; // 8 NOPs
        let bytes = build_tcp_with_options(&options, &[]);
        let header = TcpHeader::new(&bytes).unwrap();

        assert_eq!(header.data_offset(), 7);
        assert_eq!(header.header_len(), 28);
        assert_eq!(header.options_raw(), &options);
    }

    // =========================================================
    // Group 2 — validate() error paths
    // =========================================================

    #[test]
    fn rejects_too_short() {
        let bytes = &build_tcp(SYN, 0x0000)[..19];
        assert_eq!(
            TcpHeader::new(bytes),
            Err(PacketError::TooShort { needed: 20, actual: 19 })
        );
    }

    #[test]
    fn rejects_data_offset_less_than_5() {
        let mut bytes = build_tcp(SYN, 0x0000);
        bytes[12] = (4u8 << 4) | (bytes[12] & 0x01); // data_offset = 4

        assert_eq!(
            TcpHeader::new(&bytes),
            Err(PacketError::InvalidTcpHeaderLength { data_offset: 4 })
        );
    }

    #[test]
    fn rejects_data_offset_zero() {
        let mut bytes = build_tcp(SYN, 0x0000);
        bytes[12] = bytes[12] & 0x01; // data_offset = 0

        assert_eq!(
            TcpHeader::new(&bytes),
            Err(PacketError::InvalidTcpHeaderLength { data_offset: 0 })
        );
    }

    #[test]
    fn rejects_data_offset_beyond_buffer() {
        let mut bytes = build_tcp(SYN, 0x0000);
        // claim data_offset = 15 (60 byte header) but buffer is only 20
        bytes[12] = (15u8 << 4) | (bytes[12] & 0x01);

        assert_eq!(
            TcpHeader::new(&bytes),
            Err(PacketError::TooShort { needed: 60, actual: 20 })
        );
    }

    // =========================================================
    // Group 3 — flags
    // =========================================================

    #[test]
    fn syn_flag_set() {
        let bytes = build_tcp(SYN, 0);
        let header = TcpHeader::new(&bytes).unwrap();
        assert!(header.is_syn());
        assert!(!header.is_ack());
        assert!(!header.is_fin());
        assert!(!header.is_rst());
        assert!(!header.is_psh());
        assert!(!header.is_urg());
        assert!(!header.is_ece());
        assert!(!header.is_cwr());
        assert!(!header.is_ns());
    }

    #[test]
    fn ack_flag_set() {
        let bytes = build_tcp(ACK, 0);
        let header = TcpHeader::new(&bytes).unwrap();
        assert!(header.is_ack());
        assert!(!header.is_syn());
    }

    #[test]
    fn syn_ack_flags_set() {
        let bytes = build_tcp(SYN | ACK, 0);
        let header = TcpHeader::new(&bytes).unwrap();
        assert!(header.is_syn());
        assert!(header.is_ack());
        assert!(!header.is_fin());
    }

    #[test]
    fn fin_ack_flags_set() {
        let bytes = build_tcp(FIN | ACK, 0);
        let header = TcpHeader::new(&bytes).unwrap();
        assert!(header.is_fin());
        assert!(header.is_ack());
        assert!(!header.is_syn());
    }

    #[test]
    fn rst_flag_set() {
        let bytes = build_tcp(RST, 0);
        let header = TcpHeader::new(&bytes).unwrap();
        assert!(header.is_rst());
        assert!(!header.is_syn());
    }

    #[test]
    fn ns_flag_sits_in_byte_12() {
        // NS is bit 8 of the 9-bit flags field — it lives in byte 12 bit 0
        let bytes = build_tcp(NS, 0);
        let header = TcpHeader::new(&bytes).unwrap();
        assert!(header.is_ns());
        assert!(!header.is_syn());
        assert!(!header.is_ack());
    }

    #[test]
    fn all_flags_set() {
        let all = NS | CWR | ECE | URG | ACK | PSH | RST | SYN | FIN;
        let bytes = build_tcp(all, 0);
        let header = TcpHeader::new(&bytes).unwrap();
        assert!(header.is_ns());
        assert!(header.is_cwr());
        assert!(header.is_ece());
        assert!(header.is_urg());
        assert!(header.is_ack());
        assert!(header.is_psh());
        assert!(header.is_rst());
        assert!(header.is_syn());
        assert!(header.is_fin());
    }

    #[test]
    fn no_flags_set() {
        let bytes = build_tcp(0, 0);
        let header = TcpHeader::new(&bytes).unwrap();
        assert!(!header.is_ns());
        assert!(!header.is_cwr());
        assert!(!header.is_ece());
        assert!(!header.is_urg());
        assert!(!header.is_ack());
        assert!(!header.is_psh());
        assert!(!header.is_rst());
        assert!(!header.is_syn());
        assert!(!header.is_fin());
    }

    // =========================================================
    // Group 4 — mutation
    // =========================================================

    #[test]
    fn edits_tcp_header_without_losing_read_api() {
        let mut bytes = build_tcp(SYN, 0x0000).to_vec();
        let mut header = TcpHeaderMut::new(&mut bytes).unwrap();

        header.set_src_port(9999);
        header.set_dst_port(443);
        header.set_seq_number(0x11111111);
        header.set_ack_number(0x22222222);
        header.set_flags(ACK | PSH);
        header.set_window_size(1024);
        header.set_urgent_pointer(0);

        assert_eq!(header.src_port(), 9999);
        assert_eq!(header.dst_port(), 443);
        assert_eq!(header.seq_number(), 0x11111111);
        assert_eq!(header.ack_number(), 0x22222222);
        assert!(header.is_ack());
        assert!(header.is_psh());
        assert!(!header.is_syn());
        assert_eq!(header.window_size(), 1024);
    }

    #[test]
    fn set_flags_preserves_data_offset() {
        let mut bytes = build_tcp(SYN, 0x0000);
        let mut header = TcpHeaderMut::new(&mut bytes).unwrap();

        let offset_before = header.data_offset();
        header.set_flags(ACK | FIN);
        assert_eq!(header.data_offset(), offset_before);
    }

    // =========================================================
    // Group 5 — options iterator
    // =========================================================

    #[test]
    fn no_options_iterator_is_empty() {
        let bytes = build_tcp(SYN, 0x0000);
        let header = TcpHeader::new(&bytes).unwrap();
        let opts: Vec<_> = header.options().collect();
        assert!(opts.is_empty());
    }

    #[test]
    fn nop_options_are_yielded_individually() {
        // 4 NOP bytes = 4 individual NOP options
        let options = [0x01, 0x01, 0x01, 0x01];
        let bytes = build_tcp_with_options(&options, &[]);
        let header = TcpHeader::new(&bytes).unwrap();

        let opts: Vec<_> = header.options()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(opts.len(), 4);
        assert!(opts.iter().all(|o| matches!(o.kind, TcpOptionKind::Nop)));
    }

    #[test]
    fn mss_option_parsed_correctly() {
        // MSS option: kind=2, length=4, value=1460
        let mss: u16 = 1460;
        let options = [
            0x02, 0x04,
            (mss >> 8) as u8, (mss & 0xff) as u8,
        ];
        let bytes = build_tcp_with_options(&options, &[]);
        let header = TcpHeader::new(&bytes).unwrap();

        let opts: Vec<_> = header.options()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].kind, TcpOptionKind::Mss);
        assert_eq!(opts[0].mss(), Some(1460));
    }

    #[test]
    fn window_scale_option_parsed_correctly() {
        // WindowScale: kind=3, length=3, shift=7, then 1 NOP pad
        let options = [0x03, 0x03, 0x07, 0x01];
        let bytes = build_tcp_with_options(&options, &[]);
        let header = TcpHeader::new(&bytes).unwrap();

        let opts: Vec<_> = header.options()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(opts.len(), 2); // WindowScale + NOP
        assert_eq!(opts[0].window_scale(), Some(7));
        assert!(matches!(opts[1].kind, TcpOptionKind::Nop));
    }

    #[test]
    fn timestamp_option_parsed_correctly() {
        // Timestamp: kind=8, length=10, ts_val=0x12345678, ts_ecr=0xdeadbeef
        // + 2 NOP padding to reach 12 bytes (multiple of 4)
        let ts_val: u32 = 0x12345678;
        let ts_ecr: u32 = 0xdeadbeef;
        let options = [
            0x01, 0x01,             // 2 NOPs
            0x08, 0x0a,             // kind=8, length=10
            (ts_val >> 24) as u8, (ts_val >> 16) as u8,
            (ts_val >> 8)  as u8, (ts_val)       as u8,
            (ts_ecr >> 24) as u8, (ts_ecr >> 16) as u8,
            (ts_ecr >> 8)  as u8, (ts_ecr)       as u8,
        ];
        let bytes = build_tcp_with_options(&options, &[]);
        let header = TcpHeader::new(&bytes).unwrap();

        let opts: Vec<_> = header.options()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let ts = opts.iter().find(|o| matches!(o.kind, TcpOptionKind::Timestamp)).unwrap();
        assert_eq!(ts.timestamp(), Some((ts_val, ts_ecr)));
    }

    #[test]
    fn eol_option_stops_iterator() {
        // EOL at byte 0, then garbage — iterator must stop after EOL
        let options = [0x00, 0xff, 0xff, 0xff];
        let bytes = build_tcp_with_options(&options, &[]);
        let header = TcpHeader::new(&bytes).unwrap();

        let opts: Vec<_> = header.options()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(opts.len(), 1);
        assert!(matches!(opts[0].kind, TcpOptionKind::Eol));
    }

    #[test]
    fn malformed_option_length_too_short_returns_error() {
        // kind=2 (MSS) but length=1 — invalid, minimum is 2
        let options = [0x02, 0x01, 0x00, 0x00];
        let bytes = build_tcp_with_options(&options, &[]);
        let header = TcpHeader::new(&bytes).unwrap();

        let result: Result<Vec<_>, _> = header.options().collect();
        assert!(matches!(
            result,
            Err(PacketError::InvalidTcpOptionLength { kind: 2, length: 1 })
        ));
    }

    #[test]
    fn malformed_option_length_exceeds_remaining_returns_error() {
        // kind=8 (Timestamp) claims length=10 but only 4 bytes available
        let options = [0x08, 0x0a, 0x00, 0x00];
        let bytes = build_tcp_with_options(&options, &[]);
        let header = TcpHeader::new(&bytes).unwrap();

        let result: Result<Vec<_>, _> = header.options().collect();
        assert!(matches!(
            result,
            Err(PacketError::TooShort { needed: 10, actual: 4 })
        ));
    }

    #[test]
    fn iterator_stops_after_options_error() {
        let options = [0x02, 0x01, 0x00, 0x00]; // invalid MSS length
        let bytes = build_tcp_with_options(&options, &[]);
        let header = TcpHeader::new(&bytes).unwrap();

        let mut iter = header.options();
        assert!(iter.next().unwrap().is_err());
        assert!(iter.next().is_none()); // must stop
    }

    #[test]
    fn typical_syn_options_parsed_fully() {
        // A realistic SYN options block: MSS + NOP + WindowScale + NOP + NOP + SackPermitted
        // MSS(1460) + NOP + WS(7) + NOP + NOP + SACK_OK padded to 12 bytes
        let options = [
            0x02, 0x04, 0x05, 0xb4,  // MSS = 1460
            0x01,                     // NOP
            0x03, 0x03, 0x07,         // WindowScale = 7
            0x01, 0x01,               // NOP NOP
            0x04, 0x02,               // SackPermitted
        ];
        let bytes = build_tcp_with_options(&options, &[]);
        let header = TcpHeader::new(&bytes).unwrap();

        let opts: Vec<_> = header.options()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(opts.len(), 6);
        assert_eq!(opts[0].mss(), Some(1460));
        assert!(matches!(opts[1].kind, TcpOptionKind::Nop));
        assert_eq!(opts[2].window_scale(), Some(7));
        assert!(matches!(opts[3].kind, TcpOptionKind::Nop));
        assert!(matches!(opts[4].kind, TcpOptionKind::Nop));
        assert!(matches!(opts[5].kind, TcpOptionKind::SackPermitted));
    }

    // =========================================================
    // Group 6 — IPv4 checksum
    // =========================================================

    #[test]
    fn new_verified_ipv4_accepts_valid_checksum() {
        let bytes = build_tcp_ipv4(SYN, &[]);
        assert!(TcpHeader::new_verified_ipv4(&bytes, IPV4_SRC, IPV4_DST).is_ok());
    }

    #[test]
    fn new_verified_ipv4_rejects_invalid_checksum() {
        let mut bytes = build_tcp_ipv4(SYN, &[]);
        bytes[16] ^= 0xff;

        assert!(matches!(
            TcpHeader::new_verified_ipv4(&bytes, IPV4_SRC, IPV4_DST),
            Err(PacketError::InvalidChecksum { .. })
        ));
    }

    #[test]
    fn new_verified_ipv4_rejects_wrong_src() {
        let bytes = build_tcp_ipv4(SYN, &[]);
        assert!(matches!(
            TcpHeader::new_verified_ipv4(&bytes, [10, 0, 0, 1], IPV4_DST),
            Err(PacketError::InvalidChecksum { .. })
        ));
    }

    #[test]
    fn new_verified_ipv4_with_payload() {
        let payload = [0xca, 0xfe, 0xba, 0xbe];
        let bytes = build_tcp_ipv4(ACK | PSH, &payload);
        assert!(TcpHeader::new_verified_ipv4(&bytes, IPV4_SRC, IPV4_DST).is_ok());
    }

    #[test]
    fn compute_and_set_checksum_ipv4_round_trips() {
        let mut bytes = build_tcp_ipv4(SYN, &[]);
        bytes[16] = 0xde; // corrupt
        bytes[17] = 0xad;

        let mut header = TcpHeaderMut::new(&mut bytes).unwrap();
        header.compute_and_set_checksum_ipv4(IPV4_SRC, IPV4_DST);
        drop(header);

        assert!(TcpHeader::new_verified_ipv4(&bytes, IPV4_SRC, IPV4_DST).is_ok());
    }

    #[test]
    fn compute_and_set_checksum_ipv4_round_trips_after_mutation() {
        let mut bytes = build_tcp_ipv4(SYN, &[]);
        let mut header = TcpHeaderMut::new(&mut bytes).unwrap();

        header.set_seq_number(0xaaaaaaaa);
        header.set_window_size(4096);
        header.compute_and_set_checksum_ipv4(IPV4_SRC, IPV4_DST);
        drop(header);

        assert!(TcpHeader::new_verified_ipv4(&bytes, IPV4_SRC, IPV4_DST).is_ok());
    }

    // =========================================================
    // Group 7 — IPv6 checksum
    // =========================================================

    #[test]
    fn new_verified_ipv6_accepts_valid_checksum() {
        let bytes = build_tcp_ipv6(SYN, &[]);
        assert!(TcpHeader::new_verified_ipv6(&bytes, IPV6_SRC, IPV6_DST).is_ok());
    }

    #[test]
    fn new_verified_ipv6_rejects_invalid_checksum() {
        let mut bytes = build_tcp_ipv6(SYN, &[]);
        bytes[16] ^= 0xff;

        assert!(matches!(
            TcpHeader::new_verified_ipv6(&bytes, IPV6_SRC, IPV6_DST),
            Err(PacketError::InvalidChecksum { .. })
        ));
    }

    #[test]
    fn new_verified_ipv6_with_payload() {
        let payload = [0x01, 0x02, 0x03];
        let bytes = build_tcp_ipv6(ACK | PSH, &payload);
        assert!(TcpHeader::new_verified_ipv6(&bytes, IPV6_SRC, IPV6_DST).is_ok());
    }

    #[test]
    fn compute_and_set_checksum_ipv6_round_trips() {
        let mut bytes = build_tcp_ipv6(SYN, &[]);
        bytes[16] = 0xde;
        bytes[17] = 0xad;

        let mut header = TcpHeaderMut::new(&mut bytes).unwrap();
        header.compute_and_set_checksum_ipv6(IPV6_SRC, IPV6_DST);
        drop(header);

        assert!(TcpHeader::new_verified_ipv6(&bytes, IPV6_SRC, IPV6_DST).is_ok());
    }

    // =========================================================
    // Group 8 — sequence number arithmetic
    // =========================================================

    #[test]
    fn seq_after_normal() {
        assert!(wrapping_after(200, 100));
        assert!(!wrapping_after(100, 200));
        assert!(!wrapping_after(100, 100));
    }

    #[test]
    fn seq_after_wraparound() {
        assert!(wrapping_after(100, u32::MAX - 50));
        assert!(!wrapping_after(u32::MAX - 50, 100));
    }

    #[test]
    fn seq_before_normal() {
        assert!(wrapping_before(100, 200));
        assert!(!wrapping_before(200, 100));
    }

    #[test]
    fn seq_before_wraparound() {
        assert!(wrapping_before(u32::MAX - 50, 100));
    }

    #[test]
    fn seq_after_or_eq_includes_equal() {
        assert!(wrapping_after_or_eq(100, 100));
        assert!(wrapping_after_or_eq(101, 100));
        assert!(!wrapping_after_or_eq(99, 100));
    }

    #[test]
    fn seq_before_or_eq_includes_equal() {
        assert!(wrapping_before_or_eq(100, 100));
        assert!(wrapping_before_or_eq(99, 100));
        assert!(!wrapping_before_or_eq(101, 100));
    }

    #[test]
    fn seq_distance_normal() {
        assert_eq!(wrapping_distance(100, 200), 100);
    }

    #[test]
    fn seq_distance_wraparound() {
        assert_eq!(wrapping_distance(u32::MAX - 50, 50), 101);
    }

    #[test]
    fn seq_distance_zero_when_equal() {
        assert_eq!(wrapping_distance(42, 42), 0);
    }

    #[test]
    fn seq_number_from_parsed_header() {
        // verify seq arithmetic works on values extracted from a real header
        let bytes = build_tcp(SYN, 0x0000);
        let header = TcpHeader::new(&bytes).unwrap();
        let seq = header.seq_number();

        assert!(wrapping_after(seq + 1, seq));
        assert!(wrapping_before(seq - 1, seq));
        assert!(wrapping_after_or_eq(seq, seq));
    }
}