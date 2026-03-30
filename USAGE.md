# VCL Protocol — Usage Guide 📖

## Overview

VCL Protocol is a cryptographically chained packet transport protocol. It ensures data integrity through SHA-256 hashing, authenticates packets using Ed25519 signatures, and encrypts all payloads with XChaCha20-Poly1305.

**Key Features:** ✨

- Immutable packet chain (each packet links to previous via SHA-256)
- X25519 ephemeral handshake (no pre-shared keys needed)
- Ed25519 digital signatures for authentication
- XChaCha20-Poly1305 authenticated encryption for all payloads
- Replay protection via sequence numbers + nonce tracking
- Session management: close(), timeout, activity tracking
- UDP transport with Tokio async runtime

---

## Installation 🚀

### Add to Cargo.toml

```toml
[dependencies]
vcl-protocol = { git = "https://github.com/ultrakill148852-collab/vcl-protocol.git" }
tokio = { version = "1", features = ["full"] }
```

### Or clone manually

```bash
git clone https://github.com/ultrakill148852-collab/vcl-protocol.git
cd vcl-protocol
cargo build
```

---

## Quick Start 📝

### Server Example

```rust
use vcl_protocol::connection::VCLConnection;

#[tokio::main]
async fn main() {
    let mut server = VCLConnection::bind("127.0.0.1:8080").await.unwrap();
    println!("Server started on 127.0.0.1:8080");
    
    server.accept_handshake().await.unwrap();
    println!("Client connected!");
    
    loop {
        match server.recv().await {
            Ok(packet) => {
                println!("Received: {}", String::from_utf8_lossy(&packet.payload));
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}
```

### Client Example

```rust
use vcl_protocol::connection::VCLConnection;

#[tokio::main]
async fn main() {
    let mut client = VCLConnection::bind("127.0.0.1:0").await.unwrap();
    
    client.connect("127.0.0.1:8080").await.unwrap();
    println!("Connected to server!");
    
    for i in 1..=5 {
        let msg = format!("Message {}", i);
        client.send(msg.as_bytes()).await.unwrap();
        println!("Sent: {}", msg);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    
    client.close().unwrap();
}
```

---

## API Reference 🔧

### VCLConnection

| Method | Description |
|--------|-------------|
| `bind(addr)` | Create connection bound to local address |
| `connect(addr)` | Connect to remote peer (includes handshake) |
| `accept_handshake()` | Accept incoming connection (server side) |
| `send(data)` | Encrypt, sign, and send packet |
| `recv()` | Receive, verify, decrypt, and validate packet |
| `close()` | Gracefully close connection and clear state |
| `is_closed()` | Check if connection is closed |
| `set_timeout(secs)` | Set inactivity timeout in seconds |
| `get_timeout()` | Get current timeout value |
| `last_activity()` | Get timestamp of last send/recv |
| `get_public_key()` | Get local Ed25519 public key |
| `get_shared_secret()` | Get current X25519 shared secret |
| `set_shared_key(key)` | Set pre-shared key for testing |

### VCLPacket

| Field | Type | Description |
|-------|------|-------------|
| `version` | `u8` | Protocol version |
| `sequence` | `u64` | Monotonic packet sequence number |
| `prev_hash` | `Vec<u8>` | SHA-256 hash of previous packet |
| `nonce` | `[u8; 24]` | XChaCha20 nonce for encryption |
| `payload` | `Vec<u8>` | Encrypted data payload |
| `signature` | `Vec<u8>` | Ed25519 signature |

---

## Security Model 🔐

### 1. Handshake (X25519)
- Ephemeral key exchange per connection
- No pre-shared keys required
- Forward secrecy

### 2. Chain Integrity (SHA-256)
- Each packet contains hash of previous packet
- Tampering breaks the chain
- Validated on every `recv()`

### 3. Authentication (Ed25519)
- Every packet is digitally signed
- Signature verified before decryption
- Prevents spoofing

### 4. Encryption (XChaCha20-Poly1305)
- All payloads encrypted with AEAD cipher
- Unique nonce per packet
- Authentication tag ensures integrity

### 5. Replay Protection
- Sequence numbers must be strictly increasing
- Nonces tracked in sliding window (1000 entries)
- Duplicate or old packets rejected

### 6. Session Management
- `close()` clears sensitive state (keys, nonces, hashes)
- Timeout prevents resource leaks from idle connections
- `is_closed()` prevents operations on closed connections

---

## Configuration ⚙️

### Inactivity Timeout

```rust
// Set timeout to 30 seconds
conn.set_timeout(30);

// Get current timeout
let timeout = conn.get_timeout(); // Returns 30

// Check last activity time
let last = conn.last_activity();
```

Default timeout: 60 seconds. Set to 0 to disable.

### Testing with pre-shared keys

```rust
let shared_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
server.set_shared_key(&shared_key);
client.set_shared_key(&shared_key);
```

**Warning:** ⚠️ Never use pre-shared keys in production!

---

## Testing 🧪

```bash
# Run all tests
cargo test

# Run unit tests only
cargo test --lib

# Run integration tests only
cargo test --test integration_test

# Run with output
cargo test -- --nocapture

# Build release
cargo build --release
```

### Test Coverage
- Crypto: key generation, encryption/decryption, hashing
- Packets: creation, signing, verification, serialization, chain validation
- Handshake: X25519 key exchange, shared secret derivation
- Session: close(), timeout, state clearing
- Integration: client-server communication, replay protection

---

## Project Structure 📦

```
vcl-protocol/
├── src/
│   ├── main.rs          # Demo application
│   ├── lib.rs           # Library entry point
│   ├── connection.rs    # Connection API with session management
│   ├── packet.rs        # Packet structure and validation
│   ├── crypto.rs        # KeyPair and encryption helpers
│   └── handshake.rs     # X25519 handshake implementation
├── tests/
│   └── integration_test.rs
├── Cargo.toml
├── README.md
├── USAGE.md
└── LICENSE
```

---

## Contributing 🤝

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run tests: `cargo test`
6. Run linter: `cargo clippy`
7. Format code: `cargo fmt`
8. Submit a pull request

---

## License 📄

MIT License — see LICENSE file for details.

---

## Support 📬

- Issues: https://github.com/ultrakill148852-collab/vcl-protocol/issues
- Discussions: https://github.com/ultrakill148852-collab/vcl-protocol/discussions

---

## Changelog 🔄

### v0.1.0 (Current) — Production Ready ✨
- Cryptographic chain with SHA-256
- Ed25519 signatures + X25519 handshake
- XChaCha20-Poly1305 authenticated encryption
- Replay protection (sequence + nonce tracking)
- Session management: close(), is_closed(), timeout
- Full test suite: 17 passing tests (10 unit + 7 integration)
- Documentation: README + USAGE + API reference

### Planned for v0.2.0
- Custom error types (VCLError enum)
- Key rotation support
- Connection pooling
- WebSocket transport option

---

<div align="center">

**Made with ❤️ using Rust**

*Secure • Chained • Verified • Production Ready*

</div>
