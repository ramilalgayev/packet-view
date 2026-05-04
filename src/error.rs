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
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PacketError {}