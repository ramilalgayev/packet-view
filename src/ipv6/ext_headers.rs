use crate::PacketError;

pub(super) const HDR_EXT_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHeaderType {
    HopByHopOptions,
    RoutingHeader,
    FragmentHeader,
    AuthenticationHeader,
    EncapsulationSecurityPayloadHeader,
    DestinationOptions,
    MobilityHeader,
    NoNextHeader,
    TCP,
    UDP,
    ICMPv6,
    Unknown(u8),
}

impl From<u8> for NextHeaderType {
    fn from(value: u8) -> Self {
        match value {
            0   => Self::HopByHopOptions,
            6   => Self::TCP,
            17  => Self::UDP,
            43  => Self::RoutingHeader,
            44  => Self::FragmentHeader,
            50  => Self::EncapsulationSecurityPayloadHeader,
            51  => Self::AuthenticationHeader,
            58  => Self::ICMPv6,
            59  => Self::NoNextHeader,
            60  => Self::DestinationOptions,
            135 => Self::MobilityHeader,
            n   => Self::Unknown(n),
        }
    }
}

impl NextHeaderType {
    pub fn is_extension(self) -> bool {
        matches!(
            self,
            Self::HopByHopOptions
                | Self::RoutingHeader
                | Self::FragmentHeader
                | Self::AuthenticationHeader
                | Self::EncapsulationSecurityPayloadHeader
                | Self::DestinationOptions
                | Self::MobilityHeader
        )
    }
}

/// The Fragment extension header — always exactly 8 bytes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FragmentHeader<'a> {
    pub(super) bytes: &'a [u8; 8],
}

impl<'a> FragmentHeader<'a> {
    pub fn next_header(&self) -> u8 {
        self.bytes[0]
    }

    pub fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]]) >> 3
    }

    pub fn more_fragments(&self) -> bool {
        self.bytes[3] & 0x01 != 0
    }

    pub fn is_last_fragment(&self) -> bool {
        !self.more_fragments()
    }

    pub fn identification(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[4],
            self.bytes[5],
            self.bytes[6],
            self.bytes[7],
        ])
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NextHeaderData<'a> {
    Fragment(FragmentHeader<'a>),
    Other(&'a [u8]),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NextHeader<'a> {
    pub kind: NextHeaderType,
    pub next_header: u8,
    pub len_bytes: usize,
    pub data: NextHeaderData<'a>,
}

pub struct NextHeaders<'a> {
    pub(super) remaining: &'a [u8],
    pub(super) next: u8,
    pub(super) errored: bool,
}

impl<'a> Iterator for NextHeaders<'a> {
    type Item = Result<NextHeader<'a>, PacketError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.errored {
            return None;
        }

        let kind = NextHeaderType::from(self.next);
        if !kind.is_extension() {
            return None;
        }

        if self.remaining.len() < HDR_EXT_LEN {
            self.errored = true;
            return Some(Err(PacketError::TooShort {
                needed: HDR_EXT_LEN,
                actual: self.remaining.len(),
            }));
        }

        let len = if matches!(kind, NextHeaderType::FragmentHeader) {
            HDR_EXT_LEN
        } else {
            (self.remaining[1] as usize + 1) * 8
        };

        if self.remaining.len() < len {
            self.errored = true;
            return Some(Err(PacketError::TooShort {
                needed: len,
                actual: self.remaining.len(),
            }));
        }

        let data = if matches!(kind, NextHeaderType::FragmentHeader) {
            let arr: &[u8; 8] = self.remaining[..8]
                .try_into()
                .expect("length already checked above");
            NextHeaderData::Fragment(FragmentHeader { bytes: arr })
        } else {
            NextHeaderData::Other(&self.remaining[2..len])
        };

        let header = NextHeader {
            kind,
            next_header: self.remaining[0],
            len_bytes: len,
            data,
        };

        self.next = self.remaining[0];
        self.remaining = &self.remaining[len..];

        Some(Ok(header))
    }
}