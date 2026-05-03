#![no_std]

pub mod ipv4;
pub mod ipv6;
pub mod error;

pub use error::PacketError;
pub use ipv4::Ipv4Header;
pub use ipv6::Ipv6Header;



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
