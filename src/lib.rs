#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod view;
pub mod ipv4;
pub mod ipv6;
pub mod ethernet;
pub mod checksum;
pub mod udp;
pub mod tcp;

pub use tcp::{Tcp, TcpPacket};
pub use tcp::{tcp_checksum_ipv4, tcp_checksum_ipv6};
pub use tcp::options::{TcpOption, TcpOptionKind, TcpOptions};
pub use tcp::seq::{
    wrapping_after, wrapping_after_or_eq,
    wrapping_before, wrapping_before_or_eq,
    wrapping_distance,
};

pub use udp::{Udp, UdpPacket};
pub use udp::{udp_checksum_ipv4, udp_checksum_ipv6};

pub use error::PacketError;
pub use view::{PacketView, PacketViewMut};

pub use ipv4::{Ipv4, Ipv4Packet};
pub use ipv6::{Ipv6, Ipv6Packet};

pub type TcpHeader<'a>    = PacketView<'a, Tcp>;
pub type TcpHeaderMut<'a> = PacketViewMut<'a, Tcp>;

pub type UdpHeader<'a>    = PacketView<'a, Udp>;
pub type UdpHeaderMut<'a> = PacketViewMut<'a, Udp>;

pub type Ipv4Header<'a> = PacketView<'a, Ipv4>;
pub type Ipv4HeaderMut<'a> = PacketViewMut<'a, Ipv4>;
pub type Ipv6Header<'a> = PacketView<'a, Ipv6>;
pub type Ipv6HeaderMut<'a> = PacketViewMut<'a, Ipv6>;

#[cfg(test)]
mod tests {
    //use super::*;

    #[test]
    fn it_works() {
    }
}