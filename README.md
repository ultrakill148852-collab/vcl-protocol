# VCL Protocol

**Verified Commit Link** — Cryptographically chained packet transport protocol

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Prototype-yellow.svg)]()

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

    Packet N          Packet N+1        Packet N+2
    ┌─────────┐      ┌─────────┐      ┌─────────┐
    │ hash    │─────▶│ prev    │      │ prev    │
    │ 0x00    │      │ 0x3a    │─────▶│ 0x7f    │
    │ sig     │      │ sig     │      │ sig     │
    └─────────      └─────────┘      └─────────

## Quick Start

    # Clone repository
    git clone https://github.com/ultrakill148852-collab/vcl-protocol.git
    cd vcl-protocol

    # Run demo
    cargo run

Expected output:

    === VCL Protocol Demo ===
    Server started on 127.0.0.1:8080
    Client connected
    Client sent: Message 1
    Server received packet 1: Message 1
    ...
    === Demo Complete ===

## Packet Structure

    pub struct VCLPacket {
        pub version: u8,           // Protocol version
        pub sequence: u64,         // Packet sequence number
        pub prev_hash: Vec<u8>,    // SHA-256 hash of previous packet
        pub payload: Vec<u8>,      // Data payload
        pub signature: Vec<u8>,    // Ed25519 signature
    }

## Use Cases

- **Financial Transactions** — Immutable audit log of all transactions
- **Anti-Cheat Systems** — Verify integrity of game events
- **Audit Logging** — Cryptographically proven data integrity
- **Secure Communications** — Protected channel with authentication

## Technical Details

**Cryptography:**
- Hashing: SHA-256
- Signatures: Ed25519
- Key Generation: CSPRNG

**Transport:**
- Protocol: UDP
- Runtime: Tokio async
- Max Packet Size: 65535 bytes

**Serialization:**
- Format: Bincode
- Efficiency: Minimal overhead

## Development

    # Run tests
    cargo test

    # Format code
    cargo fmt

    # Linting
    cargo clippy

## License

MIT License — see LICENSE file for details

## Author

ultrakill148852-collab

---

Made with ❤️ using Rust
