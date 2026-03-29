# VCL Protocol

**Verified Commit Link** — Cryptographically chained packet transport protocol

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## About

VCL Protocol is a transport protocol where each packet cryptographically links to the previous one, creating an immutable chain of data transmission.

## Features

| Feature | Description |
|---------|-------------|
| Cryptographic Chain | Each packet references hash of previous packet |
| Ed25519 Signatures | Fast and secure digital signatures |
| Chain Validation | Automatic integrity checking |
| UDP Transport | Low latency, high performance |
| Tamper-Evident | Any modification is immediately detectable |

## Architecture

    Packet N        Packet N+1      Packet N+2
    +--------+     +--------+     +--------+
    | hash   |     | prev   |     | prev   |
    | 0x00.. | --> | 0x00.. | --> | 0x3a.. |
    | sig    |     | sig    |     | sig    |
    +--------+     +--------+     +--------+

    hash(Packet N) -> stored in prev_hash of Packet N+1
    hash(Packet N+1) -> stored in prev_hash of Packet N+2

## Quick Start

    git clone https://github.com/ultrakill148852-collab/vcl-protocol.git
    cd vcl-protocol
    cargo run

### Expected Output

    === VCL Protocol Demo ===
    Server started on 127.0.0.1:8080
    Client connected
    Client sent: Message 1
    Server received packet 1: Message 1
    Server received packet 2: Message 2
    === Demo Complete ===

## Packet Structure

    pub struct VCLPacket {
        pub version: u8,
        pub sequence: u64,
        pub prev_hash: Vec<u8>,
        pub payload: Vec<u8>,
        pub signature: Vec<u8>,
    }

## Use Cases

- **Financial Transactions** — Immutable audit log
- **Anti-Cheat Systems** — Verify game event integrity
- **Audit Logging** — Cryptographically proven integrity
- **Secure Communications** — Authenticated channel

## Technical Details

**Cryptography:** SHA-256, Ed25519, CSPRNG  
**Transport:** UDP, Tokio async, 65535 bytes max packet  
**Serialization:** Bincode

## Development

    cargo test      # Run tests
    cargo fmt       # Format code
    cargo clippy    # Linting

## License

MIT License

## Author

ultrakill148852-collab

---

Made with ❤️ using Rust
