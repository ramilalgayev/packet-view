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