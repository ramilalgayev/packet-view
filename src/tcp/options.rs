// src/tcp/options.rs

use crate::PacketError;

/// Known TCP option kinds per IANA registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOptionKind {
    Eol,                // 0  — end of options list
    Nop,                // 1  — no-operation padding
    Mss,                // 2  — maximum segment size
    WindowScale,        // 3  — window scaling factor
    SackPermitted,      // 4  — selective ack permitted
    Sack,               // 5  — selective ack block
    Timestamp,          // 8  — timestamp + echo
    Unknown(u8),
}

impl From<u8> for TcpOptionKind {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Eol,
            1 => Self::Nop,
            2 => Self::Mss,
            3 => Self::WindowScale,
            4 => Self::SackPermitted,
            5 => Self::Sack,
            8 => Self::Timestamp,
            n => Self::Unknown(n),
        }
    }
}

/// A single parsed TCP option borrowing from the packet bytes.
#[derive(Debug, Clone, Copy)]
pub struct TcpOption<'a> {
    pub kind: TcpOptionKind,
    /// Raw data bytes — empty for EOL and NOP.
    pub data: &'a [u8],
}

impl<'a> TcpOption<'a> {
    /// For MSS option (kind=2, length=4): returns the MSS value.
    pub fn mss(&self) -> Option<u16> {
        if self.kind == TcpOptionKind::Mss && self.data.len() == 2 {
            Some(u16::from_be_bytes([self.data[0], self.data[1]]))
        } else {
            None
        }
    }

    /// For WindowScale option (kind=3, length=3): returns the shift count.
    pub fn window_scale(&self) -> Option<u8> {
        if self.kind == TcpOptionKind::WindowScale && self.data.len() == 1 {
            Some(self.data[0])
        } else {
            None
        }
    }

    /// For Timestamp option (kind=8, length=10): returns (ts_val, ts_ecr).
    pub fn timestamp(&self) -> Option<(u32, u32)> {
        if self.kind == TcpOptionKind::Timestamp && self.data.len() == 8 {
            let val = u32::from_be_bytes([
                self.data[0], self.data[1], self.data[2], self.data[3],
            ]);
            let ecr = u32::from_be_bytes([
                self.data[4], self.data[5], self.data[6], self.data[7],
            ]);
            Some((val, ecr))
        } else {
            None
        }
    }
}

/// Lazy iterator over TCP options. Parses one option at a time.
pub struct TcpOptions<'a> {
    pub(super) remaining: &'a [u8],
    pub(super) errored: bool,
    pub(super) done: bool,
}

impl<'a> Iterator for TcpOptions<'a> {
    type Item = Result<TcpOption<'a>, PacketError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.errored || self.done || self.remaining.is_empty() {
            return None;
        }

        let kind = TcpOptionKind::from(self.remaining[0]);

        // Single byte options — no length byte follows
        match kind {
            TcpOptionKind::Eol => {
                self.done = true;
                self.remaining = &self.remaining[1..];
                return Some(Ok(TcpOption { kind, data: &[] }));
            }
            TcpOptionKind::Nop => {
                self.remaining = &self.remaining[1..];
                return Some(Ok(TcpOption { kind, data: &[] }));
            }
            _ => {}
        }

        // Multi-byte options — kind + length + data
        if self.remaining.len() < 2 {
            self.errored = true;
            return Some(Err(PacketError::TooShort {
                needed: 2,
                actual: self.remaining.len(),
            }));
        }

        let length = self.remaining[1] as usize;

        // length field includes the kind and length bytes themselves
        if length < 2 {
            self.errored = true;
            return Some(Err(PacketError::InvalidTcpOptionLength {
                kind: self.remaining[0],
                length: self.remaining[1],
            }));
        }

        if self.remaining.len() < length {
            self.errored = true;
            return Some(Err(PacketError::TooShort {
                needed: length,
                actual: self.remaining.len(),
            }));
        }

        let data = &self.remaining[2..length];
        let option = TcpOption { kind, data };

        self.remaining = &self.remaining[length..];

        Some(Ok(option))
    }
}