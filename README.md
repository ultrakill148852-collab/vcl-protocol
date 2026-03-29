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

**Now with X25519 Handshake + XChaCha20-Poly1305 Encryption + Replay Protection** — secure key exchange, authenticated encryption, and protection against packet replay attacks!

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 Cryptographic Chain | Each packet references hash of previous packet |
| ✍️ Ed25519 Signatures | Fast and secure digital signatures |
| 🔑 X25519 Handshake | Ephemeral key exchange, no pre-shared keys needed |
| 🔒 XChaCha20-Poly1305 | Authenticated encryption for all payloads |
| 🛡️ Replay Protection | Sequence number + nonce tracking prevents packet replay |
| ✅ Chain Validation | Automatic integrity checking |
| ⚡ UDP Transport | Low latency, high performance |
| 🧪 Full Test Suite | 14 passing tests (unit + integration) |

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

### Replay Protection

    1. Check sequence number (must be > last received)
    2. Check nonce (must not be in seen_nonces set)
    3. Store nonce in sliding window (1000 entries)
    4. Reject packet if either check fails

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

### Run Tests

    cargo test

### Expected Output (Demo)

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

### Expected Output (Tests)

    running 10 tests
    test crypto::tests::test_hash_data ... ok
    test crypto::tests::test_decrypt_wrong_key_fails ... ok
    ...
    test result: ok. 10 passed; 0 failed

    running 4 tests
    test test_client_server_basic ... ok
    test test_encryption_integrity ... ok
    test test_chain_validation ... ok
    test test_replay_protection ... ok
    test result: ok. 4 passed; 0 failed

---

## 📦 Packet Structure

    pub struct VCLPacket {
        pub version: u8,           // Protocol version
        pub sequence: u64,         // Packet sequence number (monotonic)
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
Authenticated and encrypted channel with end-to-end verification, ephemeral key exchange, and replay protection.

---

## 🔬 Technical Details

### Cryptography
- **Hashing:** SHA-256
- **Signatures:** Ed25519 (Edwards-curve Digital Signature Algorithm)
- **Key Exchange:** X25519 (Elliptic-curve Diffie-Hellman)
- **Encryption:** XChaCha20-Poly1305 (AEAD)
- **Key Generation:** CSPRNG (Cryptographically Secure PRNG)
- **Replay Protection:** Sequence number validation + nonce tracking (1000-entry window)

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

    # Run all tests
    cargo test

    # Run unit tests only
    cargo test --lib

    # Run integration tests only
    cargo test --test integration_test

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
