# VCL Protocol

**Verified Commit Link** — Cryptographically chained packet transport protocol

---

## 📚 Documentation

**[README](README.md)** | **[Usage Guide](USAGE.md)** | **[API Reference](docs/api.md)** | **[Examples](docs/examples.md)**

---

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Prototype-yellow.svg)]()

---

## 📖 About

VCL Protocol is a transport protocol where each packet cryptographically links to the previous one, creating an immutable chain of data transmission. Inspired by blockchain principles, optimized for real-time networking.

**Now with X25519 Handshake + XChaCha20-Poly1305 Encryption** — secure key exchange and authenticated encryption without pre-shared secrets!

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 Cryptographic Chain | Each packet references hash of previous packet |
| ✍️ Ed25519 Signatures | Fast and secure digital signatures |
| 🔑 X25519 Handshake | Ephemeral key exchange, no pre-shared keys needed |
| 🔒 XChaCha20-Poly1305 | Authenticated encryption for all payloads |
| ✅ Chain Validation | Automatic integrity checking |
| ⚡ UDP Transport | Low latency, high performance |
| 🛡️ Tamper-Evident | Any modification is immediately detectable |

---

## 🏗️ Architecture

    Packet N        Packet N+1      Packet N+2
    +--------+     +--------+     +--------+
    | hash   |     | prev   |     | prev   |
    | 0x00.. | --> | 0x00.. | --> | 0x3a.. |
    | sig    |     | sig    |     | sig    |
    +--------+     +--------+     +--------+

    hash(Packet N) -> stored in prev_hash of Packet N+1
    hash(Packet N+1) -> stored in prev_hash of Packet N+2

### Handshake Flow

    Client                          Server
       |                               |
       | -- ClientHello (pubkey) ----> |
       |                               |
       | <---- ServerHello (pubkey) -- |
       |                               |
       | [Shared secret computed]      |
       | [Secure channel established]  |

### Encryption Flow

    Send: plaintext → encrypt(XChaCha20) → sign(Ed25519) → send
    Recv: receive → verify(Ed25519) → decrypt(XChaCha20) → plaintext

---

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
    Handshake completed
    Client connected (handshake complete)
    Client sent: Message 1
    Server received packet 1: Message 1
    Client sent: Message 2
    Server received packet 2: Message 2
    Client sent: Message 3
    Server received packet 3: Message 3
    Client sent: Message 4
    Server received packet 4: Message 4
    Client sent: Message 5
    Server received packet 5: Message 5

    === Demo Complete ===

---

## 📦 Packet Structure

    pub struct VCLPacket {
        pub version: u8,           // Protocol version
        pub sequence: u64,         // Packet sequence number
        pub prev_hash: Vec<u8>,    // SHA-256 hash of previous packet
        pub nonce: [u8; 24],       // XChaCha20 nonce for encryption
        pub payload: Vec<u8>,      // Encrypted data payload
        pub signature: Vec<u8>,    // Ed25519 signature
    }

---

## 🎯 Use Cases

### 💰 Financial Transactions
Immutable audit log of all transactions with cryptographic proof of integrity.

### 🎮 Anti-Cheat Systems
Verify integrity of game events and detect tampering in real-time.

### 📋 Audit Logging
Cryptographically proven data integrity for compliance and debugging.

### 🔐 Secure Communications
Authenticated and encrypted channel with end-to-end verification and ephemeral key exchange.

---

## 🔬 Technical Details

### Cryptography
- **Hashing:** SHA-256
- **Signatures:** Ed25519 (Edwards-curve Digital Signature Algorithm)
- **Key Exchange:** X25519 (Elliptic-curve Diffie-Hellman)
- **Encryption:** XChaCha20-Poly1305 (AEAD)
- **Key Generation:** CSPRNG (Cryptographically Secure PRNG)

### Transport
- **Protocol:** UDP
- **Runtime:** Tokio async
- **Max Packet Size:** 65535 bytes

### Serialization
- **Format:** Bincode
- **Efficiency:** Minimal overhead, fast serialization

### Dependencies
- `ed25519-dalek` — Ed25519 signatures
- `x25519-dalek` — X25519 key exchange
- `chacha20poly1305` — XChaCha20-Poly1305 AEAD encryption
- `sha2` — SHA-256 hashing
- `tokio` — Async runtime
- `serde` + `bincode` — Serialization

---

## 🛠️ Development

    # Run tests
    cargo test

    # Format code
    cargo fmt

    # Linting
    cargo clippy

    # Build release
    cargo build --release

    # Generate docs
    cargo doc --open

---

## 📄 License

MIT License — see [LICENSE](LICENSE) file for details.

---

## 👤 Author

**ultrakill148852-collab** — Creator of the VCL Protocol

GitHub: [@ultrakill148852-collab](https://github.com/ultrakill148852-collab)

---

## 🙏 Acknowledgments

- **Ed25519** — Fast and secure cryptography
- **X25519** — Efficient elliptic-curve key exchange
- **XChaCha20-Poly1305** — Modern authenticated encryption
- **Tokio** — Asynchronous runtime for Rust
- **Rust** — The language that makes the impossible possible

---

<div align="center">

**Made with ❤️ using Rust**

[⬆️ Back to top](#vcl-protocol)

</div>
