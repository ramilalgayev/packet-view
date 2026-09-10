use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PacketError {
    #[error("packet too short: need {needed} bytes, got {actual}")]
    TooShort { needed: usize, actual: usize },

    #[error("invalid version: expected {expected}, got {actual}")]
    InvalidVersion { expected: u8, actual: u8 },

    #[error("invalid IPv4 IHL: {ihl_words} (minimum is 5)")]
    InvalidIpv4HeaderLength { ihl_words: u8 },

    #[error("IPv4 total_len {total_len} is smaller than header_len {header_len}")]
    InvalidIpv4TotalLength { header_len: usize, total_len: usize },

    #[error("packet is a fragment — payload is incomplete")]
    FragmentedPacket,

    #[error("invalid checksum: expected {expected:#06x}, got {actual:#06x}")]
    InvalidChecksum { expected: u16, actual: u16 },

    #[error("UDP length field {actual} is smaller than header length {header_len}")]
    InvalidUdpLength { header_len: usize, actual: usize },

    #[error("TCP option kind {kind} has invalid length {length} (minimum 2)")]
    InvalidTcpOptionLength { kind: u8, length: u8 },

    #[error("TCP data offset {data_offset} is too small (minimum 5)")]
    InvalidTcpHeaderLength { data_offset: u8 },
}
