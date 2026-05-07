#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    TooShort {
        needed: usize,
        actual: usize,
    },
    InvalidVersion {
        expected: u8,
        actual: u8,
    },
    InvalidIpv4HeaderLength {
        ihl_words: u8,
    },
    InvalidIpv4TotalLength {
        header_len: usize,
        total_len: usize,
    },
    FragmentedPacket,
    InvalidChecksum { expected: u16, actual: u16 },
    InvalidUdpLength {
        header_len: usize,
        actual: usize,
    },
    InvalidTcpOptionLength { kind: u8, length: u8 },
    InvalidTcpHeaderLength { data_offset: u8 },
}

impl core::fmt::Display for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { needed, actual } =>
                write!(f, "packet too short: need {needed} bytes, got {actual}"),
            Self::InvalidVersion { expected, actual } =>
                write!(f, "invalid version: expected {expected}, got {actual}"),
            Self::InvalidIpv4HeaderLength { ihl_words } =>
                write!(f, "invalid IPv4 IHL: {ihl_words} (minimum is 5)"),
            Self::InvalidIpv4TotalLength { header_len, total_len } =>
                write!(f, "IPv4 total_len {total_len} is smaller than header_len {header_len}"),
            Self::FragmentedPacket =>
                write!(f, "packet is a fragment — payload is incomplete"),
            Self::InvalidChecksum { expected, actual } =>
                write!(f, "invalid checksum: expected {expected:#06x}, got {actual:#06x}"),
            Self::InvalidUdpLength { header_len, actual } =>
                write!(f, "UDP length field {actual} is smaller than header length {header_len}"),
            Self::InvalidTcpOptionLength { kind, length } =>
                write!(f, "TCP option kind {kind} has invalid length {length} (minimum 2)"),
            Self::InvalidTcpHeaderLength { data_offset } =>
                write!(f, "TCP data offset {data_offset} is too small (minimum 5)"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PacketError {}