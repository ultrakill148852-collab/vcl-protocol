# VCL Protocol

⚠️ **Development Branch**
>
> You're viewing the `main` branch which is under active development.
> Code here may be unstable or incomplete.
>
> ✅ **For stable version:** [crates.io/vcl-protocol](https://crates.io/crates/vcl-protocol)

[![Crates.io](https://img.shields.io/crates/v/vcl-protocol.svg)](https://crates.io/crates/vcl-protocol)
[![Docs.rs](https://docs.rs/vcl-protocol/badge.svg)](https://docs.rs/vcl-protocol)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![Tests](https://img.shields.io/badge/tests-33%2F33%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-v0.3.0%20Stable-green.svg)]()

**Verified Commit Link** — Cryptographically chained packet transport protocol

---

## 📚 Documentation

**[README](README.md)** | **[Usage Guide](USAGE.md)** | **[Crates.io](https://crates.io/crates/vcl-protocol)** | **[Docs.rs](https://docs.rs/vcl-protocol)** | **[GitHub](https://github.com/ultrakill148852-collab/vcl-protocol)**

---

## 📖 About

VCL Protocol is a transport protocol where each packet cryptographically links to the previous one, creating an immutable chain of data transmission. Inspired by blockchain principles, optimized for real-time networking.

**v0.3.0** adds full API documentation on docs.rs, tracing-based logging, criterion benchmarks, and a Connection Pool for managing multiple peers simultaneously.

**Published on crates.io:** https://crates.io/crates/vcl-protocol
**API Documentation:** https://docs.rs/vcl-protocol

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
| 🚫 Custom Error Types | Typed `VCLError` enum with full `std::error::Error` impl |
| 📡 Connection Events | Subscribe to lifecycle & data events via async mpsc channel |
| 🏓 Ping / Heartbeat | Built-in ping/pong with automatic round-trip latency measurement |
| 🔄 Key Rotation | Rotate encryption keys mid-session without reconnecting |
| 🏊 Connection Pool | Manage multiple connections under a single `VCLPool` manager |
| 📝 Tracing Logs | Structured logging via `tracing` crate |
| 📊 Benchmarks | Performance benchmarks via `criterion` |
| 📖 Full API Docs | Complete documentation on [docs.rs](https://docs.rs/vcl-protocol) |
| 🧪 Full Test Suite | 33/33 tests passing (unit + integration + doc) |

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
- close()         → Gracefully close connection, clear state
- is_closed()     → Check if connection is closed
- set_timeout()   → Configure inactivity timeout (default: 60s)
- last_activity() → Get timestamp of last send/recv
```

### Event Flow
```
conn.subscribe() → mpsc::Receiver<VCLEvent>

Events:
  Connected          → handshake completed
  Disconnected       → close() called
  PacketReceived     → data packet arrived { sequence, size }
  PingReceived       → peer pinged us (pong sent automatically)
  PongReceived       → our ping was answered { latency: Duration }
  KeyRotated         → key rotation completed
  Error(msg)         → non-fatal internal error
```

### Key Rotation Flow
```
Client                              Server
   |                                   |
   | -- KeyRotation(new_pubkey) -----> |
   |                                   |
   | <--- KeyRotation(new_pubkey) ---- |
   |                                   |
   | [both sides now use new key]      |
```

### Connection Pool
```
VCLPool::new(max)
   |
   ├── bind("addr") → ConnectionId(0)
   ├── bind("addr") → ConnectionId(1)
   ├── bind("addr") → ConnectionId(2)
   |
   ├── connect(id, peer)
   ├── send(id, data)
   ├── recv(id) → VCLPacket
   ├── ping(id)
   ├── rotate_keys(id)
   ├── close(id)
   └── close_all()
```

---

## 🚀 Quick Start

### Installation
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo add vcl-protocol
```

### Run Demo
```bash
cargo run
```

### Run Tests
```bash
cargo test
```

### Run Benchmarks
```bash
cargo bench
```

### Event Subscription Example
```rust
use vcl_protocol::connection::VCLConnection;
use vcl_protocol::VCLEvent;

#[tokio::main]
async fn main() {
    let mut conn = VCLConnection::bind("127.0.0.1:0").await.unwrap();
    let mut events = conn.subscribe();

    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                VCLEvent::Connected              => println!("Connected!"),
                VCLEvent::PongReceived { latency } => println!("Latency: {:?}", latency),
                VCLEvent::KeyRotated             => println!("Keys rotated!"),
                VCLEvent::Disconnected           => break,
                _                                => {}
            }
        }
    });

    conn.connect("127.0.0.1:8080").await.unwrap();
}
```

### Connection Pool Example
```rust
use vcl_protocol::VCLPool;

#[tokio::main]
async fn main() {
    let mut pool = VCLPool::new(10);

    let id = pool.bind("127.0.0.1:0").await.unwrap();
    pool.connect(id, "127.0.0.1:8080").await.unwrap();
    pool.send(id, b"Hello from pool!").await.unwrap();

    let packet = pool.recv(id).await.unwrap();
    println!("{}", String::from_utf8_lossy(&packet.payload));

    pool.close(id).unwrap();
}
```

---

## 📦 Packet Structure
```rust
pub struct VCLPacket {
    pub version: u8,             // Protocol version (2)
    pub packet_type: PacketType, // Data | Ping | Pong | KeyRotation
    pub sequence: u64,           // Monotonic packet sequence number
    pub prev_hash: Vec<u8>,      // SHA-256 hash of previous packet
    pub nonce: [u8; 24],         // XChaCha20 nonce for encryption
    pub payload: Vec<u8>,        // Decrypted data payload (after recv())
    pub signature: Vec<u8>,      // Ed25519 signature
}
```

---

## 📊 Benchmarks

Measured on WSL2 Debian, optimized build (`cargo bench`):

| Operation | Time |
|-----------|------|
| keypair_generate | ~13 µs |
| encrypt 64B | ~1.5 µs |
| encrypt 16KB | ~12 µs |
| decrypt 64B | ~1.4 µs |
| decrypt 16KB | ~13 µs |
| packet_sign | ~32 µs |
| packet_verify | ~36 µs |
| packet_serialize | ~0.8 µs |
| packet_deserialize | ~1.1 µs |
| full pipeline 64B | ~38 µs |
| full pipeline 4KB | ~48 µs |

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
- **Signatures:** Ed25519
- **Key Exchange:** X25519
- **Encryption:** XChaCha20-Poly1305 (AEAD)
- **Key Generation:** CSPRNG
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
- `tracing` — Structured logging
- `tracing-subscriber` — Log output

---

## 🛠️ Development
```bash
cargo test                         # Run all tests (33/33)
cargo test --lib                   # Unit tests only
cargo test --test integration_test # Integration tests only
cargo bench                        # Run benchmarks
cargo run --example server         # Run example server
cargo run --example client         # Run example client
cargo fmt                          # Format code
cargo clippy                       # Linting
cargo build --release              # Release build
cargo doc --open                   # Generate and open docs locally
```

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
