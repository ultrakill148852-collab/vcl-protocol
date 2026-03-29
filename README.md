# VCL Protocol

**Verified Commit Link** — Cryptographically chained packet transport protocol

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Prototype-yellow.svg)]()

---

## 📖 About

VCL Protocol is a transport protocol where each packet cryptographically links to the previous one, creating an immutable chain of data transmission. Inspired by blockchain principles, optimized for real-time networking.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 Cryptographic Chain | Each packet references hash of previous packet |
| ✍️ Ed25519 Signatures | Fast and secure digital signatures |
| ✅ Chain Validation | Automatic integrity checking |
| ⚡ UDP Transport | Low latency, high performance |
| 🛡️ Tamper-Evident | Any modification is immediately detectable |

## 🏗️ Architecture

    Packet N        Packet N+1      Packet N+2
    +--------+     +--------+     +--------+
    | hash   |     | prev   |     | prev   |
    | 0x00.. | --> | 0x00.. | --> | 0x3a.. |
    | sig    |     | sig    |     | sig    |
    +--------+     +--------+     +--------+

    hash(Packet N) -> stored in prev_hash of Packet N+1
    hash(Packet N+1) -> stored in prev_hash of Packet N+2

## 🚀 Quick Start

### Installation

    # Install Rust (if not already installed)
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

    # Clone repository
    git clone https://github.com/ultrakill148852-collab/vcl-protocol.git
    cd vcl-protocol

### Run Demo

    cargo run

### Expected Output

    === VCL Protocol Demo ===

    Server started on 127.0.0.1:8080
    Client connected
    Client sent: Message 1
    Server received packet 1: Message 1
    Client sent: Message 2
    Server received packet 2: Message 2
    Client sent: Message 3
    Server received packet 3: Message 3

    === Demo Complete ===

## 📦 Packet Structure

    pub struct VCLPacket {
        pub version: u8,           // Protocol version
        pub sequence: u64,         // Packet sequence number
        pub prev_hash: Vec<u8>,    // SHA-256 hash of previous packet
        pub payload: Vec<u8>,      // Data payload
        pub signature: Vec<u8>,    // Ed25519 signature
    }

## 🎯 Use Cases

### 💰 Financial Transactions
Immutable audit log of all transactions with cryptographic proof of integrity.

### 🎮 Anti-Cheat Systems
Verify integrity of game events and detect tampering in real-time.

### 📋 Audit Logging
Cryptographically proven data integrity for compliance and debugging.

### 🔐 Secure Communications
Authenticated channel with end-to-end verification.

## 🔬 Technical Details

### Cryptography
- **Hashing:** SHA-256
- **Signatures:** Ed25519 (Edwards-curve Digital Signature Algorithm)
- **Key Generation:** CSPRNG (Cryptographically Secure PRNG)

### Transport
- **Protocol:** UDP
- **Runtime:** Tokio async
- **Max Packet Size:** 65535 bytes

### Serialization
- **Format:** Bincode
- **Efficiency:** Minimal overhead, fast serialization

## 🛠️ Development

    # Run tests
    cargo test

    # Format code
    cargo fmt

    # Linting
    cargo clippy

    # Build release
    cargo build --release

## 📄 License

MIT License — see [LICENSE](LICENSE) file for details.

## 👤 Author

**ultrakill148852-collab**

GitHub: [@ultrakill148852-collab](https://github.com/ultrakill148852-collab)

## 🙏 Acknowledgments

- **Ed25519** — Fast and secure cryptography
- **Tokio** — Asynchronous runtime for Rust
- **Rust** — The language that makes the impossible possible

---

<div align="center">

**Made with ❤️ using Rust**

[⬆️ Back to top](#vcl-protocol)

</div>
