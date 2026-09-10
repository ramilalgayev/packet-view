use packet_view::{Ipv4Header, Ipv4Packet, TcpHeader, TcpPacket};

fn main() {
    let packet = include_bytes!("data/ipv4_tcp.bin");

    let ipv4 = Ipv4Header::new_verified(packet)
        .expect("captured IPv4 packet should have a valid checksum");

    println!("IPv4 packet");
    println!("version: {}", ipv4.version());
    println!("header length: {} bytes", ipv4.header_len());
    println!("total length: {} bytes", ipv4.total_len());
    println!("ttl: {}", ipv4.ttl());
    println!("protocol: {}", ipv4.protocol());
    println!("source: {:?}", ipv4.src());
    println!("destination: {:?}", ipv4.dst());
    println!("payload len: {} bytes", ipv4.payload().len());

    let tcp =
        TcpHeader::new(ipv4.payload()).expect("IPv4 payload should contain a valid TCP header");

    println!();
    println!("TCP segment");
    println!("source port: {}", tcp.src_port());
    println!("destination port: {}", tcp.dst_port());
    println!("sequence: {}", tcp.seq_number());
    println!("acknowledgment: {}", tcp.ack_number());
    println!("header length: {} bytes", tcp.header_len());
    println!("SYN: {}", tcp.is_syn());
    println!("ACK: {}", tcp.is_ack());
    println!("FIN: {}", tcp.is_fin());
}
