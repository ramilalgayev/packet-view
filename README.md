# packet-view

A safe, `no_std` Rust library for parsing and modifying network protocol headers directly from byte slices.

`packet-view` provides typed, borrowed views over network packets while validating packet structure before exposing protocol-specific fields. It is designed for low-level networking code where predictable parsing and memory safety matter. Mutable views (`*Mut`) allow direct access to the underlying byte slice and can skip validation when needed, though this is not recommended.

[![no_std](https://img.shields.io/badge/no__std-compatible-blue.svg)](#no_std)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](#safety)

## Table of contents

- [Why packet-view?](#why-packet-view)
- [Features](#features)
- [Quick start](#quick-start)
- [Example](#example)
- [API design](#api-design)
- [Supported protocols](#supported-protocols)
- [Safety](#safety)
- [Error handling](#error-handling)
- [Planned](#planned)
- [Project status](#project-status)
- [License](#license)

## Why packet-view?

- **Safe by default** — `#![forbid(unsafe_code)]`
- **Zero-copy** — views borrow the original packet bytes; no allocations or copies.
- **Validated construction** — malformed packets return `PacketError` instead of causing out-of-bounds access.
- **`no_std` ready** — usable in embedded and OS-level environments.
- **Mutable views** — modify headers in place when needed.
- **Composable API** — parse layer by layer, from IPv4/IPv6 to TCP/UDP.

## Features

- Safe Rust only — `#![forbid(unsafe_code)]`
- `no_std` compatible
- Borrowed packet views without copying packet data
- Validation before constructing typed packet views
- IPv4 and IPv6 support
- TCP and UDP support
- Mutable packet views for modifying headers in place
- IPv4 and transport-layer checksum support
- TCP option parsing
- TCP sequence-number arithmetic
- Comprehensive parser and mutation tests

## Quick start

Add `packet-view` to your `Cargo.toml`:

```toml
[dependencies]
packet-view = "0.1"
```

For `no_std` environments, disable default features if necessary:

```toml
[dependencies]
packet-view = { version = "0.1", default-features = false }
```

A minimal parsing example:

```rust
use packet_view::{Ipv4Header, TcpHeader};

fn inspect(packet: &[u8]) -> Result<(), packet_view::PacketError> {
    let ipv4 = Ipv4Header::new(packet)?;
    let tcp = TcpHeader::new(ipv4.payload())?;

    // Inspect validated IPv4/TCP fields here.
    let _ = tcp;

    Ok(())
}
```

> See the API documentation(planned) and [`examples/inspect_packet.rs`](examples/inspect_packet.rs) for a current example.

## Example

A complete working example is available in [`examples/inspect_packet.rs`](examples/inspect_packet.rs).

It parses a real captured IPv4/TCP packet and demonstrates how `packet-view` can validate and inspect layered protocol headers without copying the packet data.

The example uses [`examples/data/ipv4_tcp.bin`](examples/data/ipv4_tcp.bin), an IPv4/TCP packet extracted from a real packet capture randomly selected from my PC.

Run it with:

```bash
cargo run --example inspect_packet
```

## API design

Packet types are represented as borrowed views over the original byte slice:

```rust
pub type Ipv4Header<'a> = PacketView<'a, Ipv4>;
pub type TcpHeader<'a> = PacketView<'a, Tcp>;
```

Construction validates the underlying bytes before the typed view is returned:

```rust
let ipv4 = Ipv4Header::new(packet)?;
let tcp = TcpHeader::new(ipv4.payload())?;
```

For code that needs to modify packet headers, mutable views are available:

```rust
let mut ipv4 = Ipv4HeaderMut::new(packet)?;

ipv4.set_ttl(64);
ipv4.set_checksum();
```

The library keeps the parsing layer separate from the raw byte representation while avoiding unnecessary allocation or copying.

## Supported protocols

| Protocol | Parsing | Mutation | Checksums |
| -------- | :-----: | :------: | :-------: |
| IPv4     |    ✓    |     ✓    |     ✓     |
| IPv6     |    ✓    |     ✓    |     ✓     |
| TCP      |    ✓    |     ✓    |     ✓     |
| UDP      |    ✓    |     ✓    |     ✓     |

TCP support also includes:

- Header flags
- Sequence and acknowledgment numbers
- TCP options
- Data-offset validation
- Sequence-number arithmetic

## Safety

`packet-view` is built entirely with safe Rust:

```rust
#![no_std]
#![forbid(unsafe_code)]
```

Protocol headers are never exposed as typed views until their structural requirements have been validated.

For example, the TCP parser validates the minimum header size and TCP data offset before accessing fields beyond the basic header.

This makes malformed or truncated packet data return a `PacketError` rather than causing an out-of-bounds access.

The library does not attempt to enforce every semantic property of a packet after a mutable view has been created. Mutable access is intentionally low-level and allows callers to modify the underlying packet bytes.

## Error handling

Parsing failures are represented by a dedicated error type:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    // ...
}
```

Errors cover malformed or incomplete packet data, including:

- Truncated packets
- Invalid protocol versions
- Invalid IPv4 header lengths
- Invalid IPv4 total lengths
- Fragmented packets
- Invalid checksums
- Invalid UDP lengths
- Invalid TCP options
- Invalid TCP header lengths

## Planned

The long-term goal is to grow `packet-view` into a **general-purpose, safe, zero-copy packet processing library for Rust**, covering the full path from raw link-layer frames to higher-level protocols.

Planned areas include:

- Builder and macro patterns for building packets
- Ethernet and VLAN support
- More complete IPv4/IPv6 protocol stacks
- Additional transport and application-layer protocols
- Packet construction and composable builders
- More powerful packet mutation and rewriting
- PCAP/PCAPNG parsing and packet inspection
- Fuzzing and property-based testing
- Proper documentation and publishing on cargo
- Extensive real-world packet corpus testing
- Performance benchmarking and optimization
- A command-line packet inspection tool

The project will continue to prioritize **safe Rust, `no_std` compatibility, zero-copy parsing, explicit validation, and a "small", composable API**.

## Project status

The current implementation is quite primitive and I wouldn't say I am exactly happy with it. Life and other projects got into the way, but it is in no way discontinued. 

## License

See the repository for licensing information.
