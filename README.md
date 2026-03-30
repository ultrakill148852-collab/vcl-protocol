# VCL Protocol

[![Crates.io](https://img.shields.io/crates/v/vcl-protocol.svg)](https://crates.io/crates/vcl-protocol)
[![Docs.rs](https://docs.rs/vcl-protocol/badge.svg)](https://docs.rs/vcl-protocol)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![Tests](https://img.shields.io/badge/tests-17/17%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Verified Commit Link** — Cryptographically chained packet transport protocol

---

## 📚 Documentation

**[README](README.md)** | **[Usage Guide](USAGE.md)** | **[API Reference](https://docs.rs/vcl-protocol)** | **[Examples](examples/)** | **[Crates.io](https://crates.io/crates/vcl-protocol)**

---

## 📖 About

VCL Protocol is a transport protocol where each packet cryptographically links to the previous one, creating an immutable chain of data transmission. Inspired by blockchain principles, optimized for real-time networking.

**v0.1.0 — Production Ready** with X25519 Handshake, XChaCha20-Poly1305 Encryption, Replay Protection, and Session Management!

**Published on crates.io:** https://crates.io/crates/vcl-protocol

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 Cryptographic Chain | Each packet references hash of previous packet via SHA-256 |
| ✍️ Ed25519 Signatures | Fast and secure digital signatures |
| 🔑 X25519 Handshake | Ephemeral key exchange, no pre-shared keys needed |
| 🔒 XChaCha20-Poly1305 | Authenticated encryption for all payloads |
| 🛡️ Replay Protection | Sequence numbers + nonce tracking prevent packet replay |
| 🚪 Session Management | close(), is_closed(), timeout handling |
| ⏱️ Inactivity Timeout | Auto-close idle connections (configurable) |
| ✅ Chain Validation | Automatic integrity checking on every packet |
| ⚡ UDP Transport | Low latency, high performance |
| 🧪 Full Test Suite | 17 passing tests (unit + integration) |

---

## 🏗️ Architecture

```
Packet N        Packet N+1      Packet N+2
+--------+     +--------+     +--------+
| hash   |     | prev   |     | prev   |
| 0x00.. | --> | 0x00.. | --> | 0x3a.. |
| sig    |     | sig    |     | sig    |
+--------+     +--------+     +--------+

hash(Packet N) -> stored in prev_hash of Packet N+1
hash(Packet N+1) -> stored in prev_hash of Packet N+2
```

### Handshake Flow

```
Client                          Server
   |                               |
   | -- ClientHello (pubkey) ----> |
   |                               |
   | <---- ServerHello (pubkey) -- |
   |                               |
   | [Shared secret computed]      |
   | [Secure channel established]  |
```

### Encryption Flow

```
Send: plaintext → encrypt(XChaCha20) → sign(Ed25519) → send
Recv: receive → verify(Ed25519) → decrypt(XChaCha20) → plaintext
```

### Session Management

```
- close()        → Gracefully close connection, clear state
- is_closed()    → Check if connection is closed
- set_timeout()  → Configure inactivity timeout (default: 60s)
- last_activity()→ Get timestamp of last send/recv
```

---

## 🚀 Quick Start

### Installation

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add to your project
cargo add vcl-protocol

# Or clone repository
git clone https://github.com/ultrakill148852-collab/vcl-protocol.git
cd vcl-protocol
```

### Run Demo

```bash
cargo run
```

### Run Tests

```bash
cargo test
```

### Expected Output (Tests)

```
running 10 tests
test crypto::tests::test_hash_data ... ok
...
test result: ok. 10 passed; 0 failed

running 7 tests
test test_client_server_basic ... ok
test test_close ... ok
test test_timeout_getters ... ok
...
test result: ok. 7 passed; 0 failed
```

---

## 📦 Packet Structure

```rust
pub struct VCLPacket {
    pub version: u8,           // Protocol version
    pub sequence: u64,         // Monotonic packet sequence number
    pub prev_hash: Vec<u8>,    // SHA-256 hash of previous packet
    pub nonce: [u8; 24],       // XChaCha20 nonce for encryption
    pub payload: Vec<u8>,      // Encrypted data payload
    pub signature: Vec<u8>,    // Ed25519 signature
}
```

---

## 🎯 Use Cases

### 💰 Financial Transactions
Immutable audit log of all transactions with cryptographic proof of integrity.

### 🎮 Anti-Cheat Systems
Verify integrity of game events and detect tampering in real-time.

### 📋 Audit Logging
Cryptographically proven data integrity for compliance and debugging.

### 🔐 Secure Communications
Authenticated, encrypted channel with replay protection and session management.

### 🌐 VPN Tunnels
Additional layer of packet integrity and replay protection for VPN protocols.

---

## 🔬 Technical Details

### Cryptography
- **Hashing:** SHA-256
- **Signatures:** Ed25519 (Edwards-curve Digital Signature Algorithm)
- **Key Exchange:** X25519 (Elliptic-curve Diffie-Hellman)
- **Encryption:** XChaCha20-Poly1305 (AEAD)
- **Key Generation:** CSPRNG (Cryptographically Secure PRNG)
- **Replay Protection:** Sequence validation + nonce tracking (1000-entry window)

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

```bash
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
```

### Test Coverage (17/17 passing)

**Unit Tests (10):**
- crypto: key generation, encryption/decryption, hashing
- packet: creation, signing, verification, serialization, chain validation

**Integration Tests (7):**
- client-server basic communication
- encryption integrity
- chain validation
- replay protection
- close() functionality
- send after close
- timeout getters

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
