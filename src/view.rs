use core::marker::PhantomData;
use crate::PacketError;

pub trait PacketSpec {
    fn validate(bytes: &[u8]) -> Result<(), PacketError>;
    fn header_len(bytes: &[u8]) -> usize;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PacketView<'a, P: PacketSpec> {
    bytes: &'a [u8],
    _packet: PhantomData<P>,
}

impl<'a, P: PacketSpec> PacketView<'a, P> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, PacketError> {
        P::validate(bytes)?;
        Ok(Self {
            bytes,
            _packet: PhantomData,
        })
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn header_bytes(&self) -> &'a [u8] {
        &self.bytes[..P::header_len(self.bytes)]
    }
}

#[derive(Debug)]
pub struct PacketViewMut<'a, P: PacketSpec> {
    bytes: &'a mut [u8],
    _packet: PhantomData<P>,
}

impl<'a, P: PacketSpec> PacketViewMut<'a, P> {
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, PacketError> {
        P::validate(bytes)?;
        Ok(Self {
            bytes,
            _packet: PhantomData,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    pub fn header_bytes(&self) -> &[u8] {
        &self.bytes[..P::header_len(self.bytes)]
    }
}