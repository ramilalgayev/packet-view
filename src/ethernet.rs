pub enum IpProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Other(u16),
}