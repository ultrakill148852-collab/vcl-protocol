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
- **[v0.2.0]** Connection Events via async mpsc channel
- **[v0.2.0]** Ping / Heartbeat with round-trip latency measurement
- **[v0.2.0]** Mid-session Key Rotation via X25519

---

## Installation 🚀

### Add to Cargo.toml
```toml
[dependencies]
vcl-protocol = "0.2.0"
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
            Err(e) => { eprintln!("Error: {}", e); break; }
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

## Connection Events 📡

Subscribe to `VCLEvent` to react to connection lifecycle and data events.
Call `subscribe()` **before** `connect()` / `accept_handshake()` to receive all events.
```rust
use vcl_protocol::{connection::VCLConnection, VCLEvent};

#[tokio::main]
async fn main() {
    let mut conn = VCLConnection::bind("127.0.0.1:0").await.unwrap();

    // Returns an async mpsc receiver — channel size is 64
    let mut events = conn.subscribe();

    // Handle events in a background task
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                VCLEvent::Connected =>
                    println!("Handshake complete, secure channel ready"),
                VCLEvent::Disconnected =>
                    println!("Connection closed"),
                VCLEvent::PacketReceived { sequence, size } =>
                    println!("Packet #{} received ({} bytes)", sequence, size),
                VCLEvent::PingReceived =>
                    println!("Ping received — pong sent automatically"),
                VCLEvent::PongReceived { latency } =>
                    println!("Round-trip latency: {:?}", latency),
                VCLEvent::KeyRotated =>
                    println!("Key rotation complete — new shared secret active"),
                VCLEvent::Error(msg) =>
                    eprintln!("Internal error: {}", msg),
            }
        }
    });

    conn.connect("127.0.0.1:8080").await.unwrap();
    // ... use conn normally
}
```

### Event Reference

| Event | When emitted |
|-------|-------------|
| `Connected` | Handshake completed (connect / accept_handshake) |
| `Disconnected` | close() called |
| `PacketReceived { sequence, size }` | Data packet received in recv() |
| `PingReceived` | Peer pinged us — pong was sent automatically |
| `PongReceived { latency }` | Our ping was answered, includes round-trip time |
| `KeyRotated` | Key rotation exchange completed successfully |
| `Error(msg)` | Non-fatal internal error |

---

## Ping / Heartbeat 🏓

Use `ping()` to check peer liveness and measure round-trip latency.
The pong is handled **transparently inside `recv()`** — the user never sees Pong packets directly.
```rust
// Client side — send a ping
client.ping().await.unwrap();

// Keep calling recv() — pong will be handled internally
// PongReceived { latency } will be emitted on your event channel
loop {
    match client.recv().await {
        Ok(packet) => { /* handle data */ }
        Err(e)     => { eprintln!("{}", e); break; }
    }
}
```
```rust
// Server side — nothing special needed
// recv() automatically replies to pings and continues waiting for data
loop {
    match server.recv().await {
        Ok(packet) => { /* handle data — pings are invisible */ }
        Err(e)     => { eprintln!("{}", e); break; }
    }
}
```

> **Note:** `ping_sent_at` is tracked with `Instant` — latency is wall-clock accurate regardless of packet payload.

---

## Key Rotation 🔄

Rotate the shared encryption key mid-session without dropping the connection.
Uses a fresh X25519 ephemeral exchange, identical in security to the initial handshake.
```rust
// Initiator (e.g. client) — initiates the rotation
client.rotate_keys().await.unwrap();
// After this line both sides are using the new shared secret

// Responder (e.g. server) — handled automatically inside recv()
// When server calls recv() and receives the rotation request,
// it responds and switches keys transparently.
// A KeyRotated event is emitted on both sides.
```

### Key Rotation Flow
```
Client                               Server
   | -- KeyRotation(client_pubkey) --> |   encrypted with OLD key
   |                                   |   server generates new ephemeral
   |                                   |   computes new shared secret
   | <-- KeyRotation(server_pubkey) -- |   encrypted with OLD key
   |                                   |   server switches to NEW key
   | computes new shared secret        |
   | switches to NEW key               |
```

> ⚠️ **Limitation (v0.2.0):** Do not call `send()` while `rotate_keys()` is awaiting
> a response. The server must be actively calling `recv()` during rotation.
> Full concurrent-safe rotation is planned for v0.3.0.

---

## API Reference 🔧

### VCLConnection

| Method | Returns | Description |
|--------|---------|-------------|
| `bind(addr)` | `Result<Self, VCLError>` | Create connection bound to local address |
| `connect(addr)` | `Result<(), VCLError>` | Connect to remote peer (X25519 handshake) |
| `accept_handshake()` | `Result<(), VCLError>` | Accept incoming connection (server side) |
| `subscribe()` | `mpsc::Receiver<VCLEvent>` | Subscribe to connection events |
| `send(data)` | `Result<(), VCLError>` | Encrypt, sign, and send a data packet |
| `recv()` | `Result<VCLPacket, VCLError>` | Receive, verify, decrypt next data packet |
| `ping()` | `Result<(), VCLError>` | Send a ping; pong handled inside recv() |
| `rotate_keys()` | `Result<(), VCLError>` | Initiate mid-session key rotation |
| `close()` | `Result<(), VCLError>` | Gracefully close connection and clear state |
| `is_closed()` | `bool` | Check if connection is closed |
| `set_timeout(secs)` | `()` | Set inactivity timeout in seconds |
| `get_timeout()` | `u64` | Get current timeout value |
| `last_activity()` | `Instant` | Get timestamp of last send/recv |
| `get_public_key()` | `Vec<u8>` | Get local Ed25519 public key |
| `get_shared_secret()` | `Option<[u8; 32]>` | Get current X25519 shared secret |
| `set_shared_key(key)` | `()` | Set pre-shared key (testing only) |

### VCLPacket

| Field | Type | Description |
|-------|------|-------------|
| `version` | `u8` | Protocol version (2 in v0.2.0) |
| `packet_type` | `PacketType` | Data / Ping / Pong / KeyRotation |
| `sequence` | `u64` | Monotonic packet sequence number |
| `prev_hash` | `Vec<u8>` | SHA-256 hash of previous packet (directional) |
| `nonce` | `[u8; 24]` | XChaCha20 nonce for encryption |
| `payload` | `Vec<u8>` | Decrypted data payload (after recv()) |
| `signature` | `Vec<u8>` | Ed25519 signature |

### VCLError

| Variant | When |
|---------|------|
| `CryptoError(msg)` | Encryption/decryption failure |
| `SignatureInvalid` | Ed25519 signature verification failed |
| `InvalidKey(msg)` | Key has wrong length or format |
| `ChainValidationFailed` | prev_hash mismatch — chain broken |
| `ReplayDetected(msg)` | Duplicate sequence number or nonce |
| `InvalidPacket(msg)` | Malformed or unexpected packet |
| `ConnectionClosed` | Operation on a closed connection |
| `Timeout` | No activity for longer than timeout_secs |
| `NoPeerAddress` | send() called before peer address is known |
| `NoSharedSecret` | send()/recv() called before handshake |
| `HandshakeFailed(msg)` | X25519 key exchange failed |
| `ExpectedClientHello` | Server received wrong handshake message |
| `ExpectedServerHello` | Client received wrong handshake message |
| `SerializationError(msg)` | bincode serialization/deserialization failed |
| `IoError(msg)` | UDP socket or address parse error |

---

## Security Model 🔐

### 1. Handshake (X25519)
- Ephemeral key exchange per connection
- No pre-shared keys required
- Forward secrecy

### 2. Chain Integrity (SHA-256)
- Each packet contains hash of previous packet **in the same direction**
- Send chain and receive chain are tracked independently (v0.2.0)
- Tampering breaks the chain; validated on every recv()

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

### 7. Key Rotation (v0.2.0)
- Fresh X25519 ephemeral exchange per rotation
- Old key used to encrypt rotation messages (no plaintext exposure)
- Both sides switch atomically after exchange completes

---

## Configuration ⚙️

### Inactivity Timeout
```rust
conn.set_timeout(30);           // Set timeout to 30 seconds
let timeout = conn.get_timeout(); // Returns 30
let last = conn.last_activity();  // Returns Instant of last activity
```

Default timeout: 60 seconds.

### Testing with pre-shared keys
```rust
let shared_key = hex::decode(
    "0000000000000000000000000000000000000000000000000000000000000001"
).unwrap();
server.set_shared_key(&shared_key);
client.set_shared_key(&shared_key);
```

**Warning:** ⚠️ Never use pre-shared keys in production!

---

## Testing 🧪
```bash
cargo test                        # Run all tests
cargo test --lib                  # Unit tests only
cargo test --test integration_test # Integration tests only
cargo test -- --nocapture         # With output
cargo run --example server        # Run example server
cargo run --example client        # Run example client
cargo build --release             # Release build
```

---

## Project Structure 📦
```
vcl-protocol/
├── src/
│   ├── main.rs          # Demo application
│   ├── lib.rs           # Library entry point
│   ├── connection.rs    # Connection API (events, ping, key rotation)
│   ├── event.rs         # VCLEvent enum
│   ├── packet.rs        # Packet structure, PacketType, validation
│   ├── crypto.rs        # KeyPair and encryption helpers
│   ├── error.rs         # VCLError typed error enum
│   └── handshake.rs     # X25519 handshake implementation
├── examples/
│   ├── client.rs
│   └── server.rs
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

### v0.2.0 (Current) — Feature Release ✨
- **Connection Events** — `VCLEvent` enum + `subscribe()` → async mpsc channel
- **Ping / Heartbeat** — `ping()` with automatic pong and latency measurement
- **Key Rotation** — `rotate_keys()` with X25519 mid-session key exchange
- **Custom Error Types** — `VCLError` enum with full `std::error::Error` impl
- **Bidirectional chain fix** — send/recv hash chains now tracked independently
- All `unwrap()` removed from public code paths — full `Result` propagation

### v0.1.0 — Production Ready ✅
- Cryptographic chain with SHA-256
- Ed25519 signatures + X25519 handshake
- XChaCha20-Poly1305 authenticated encryption
- Replay protection (sequence + nonce tracking)
- Session management: close(), is_closed(), timeout
- Full test suite: 17 passing tests (10 unit + 7 integration)
- Documentation: README + USAGE + API reference

### Planned for v0.3.0
- Concurrent-safe key rotation (two-phase commit)
- Connection pooling
- WebSocket transport option
- Connection multiplexing

---

<div align="center">

**Made with ❤️ using Rust**

*Secure • Chained • Verified • Production Ready*

</div>
