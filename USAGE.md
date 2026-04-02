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
- **[v0.3.0]** Connection Pool via `VCLPool`
- **[v0.3.0]** Structured logging via `tracing`
- **[v0.3.0]** Performance benchmarks via `criterion`
- **[v0.3.0]** Full API docs on [docs.rs](https://docs.rs/vcl-protocol)

---

## Installation 🚀

### Add to Cargo.toml
```toml
[dependencies]
vcl-protocol = "0.3.0"
tokio = { version = "1", features = ["full"] }
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

## Connection Pool 🏊

`VCLPool` manages multiple connections under a single manager.
```rust
use vcl_protocol::VCLPool;

#[tokio::main]
async fn main() {
    // Create pool with max 10 connections
    let mut pool = VCLPool::new(10);

    // Bind connections
    let id1 = pool.bind("127.0.0.1:0").await.unwrap();
    let id2 = pool.bind("127.0.0.1:0").await.unwrap();

    // Connect them
    pool.connect(id1, "127.0.0.1:8080").await.unwrap();
    pool.connect(id2, "127.0.0.1:8081").await.unwrap();

    // Send on specific connection
    pool.send(id1, b"Hello server 1!").await.unwrap();
    pool.send(id2, b"Hello server 2!").await.unwrap();

    // Receive
    let packet = pool.recv(id1).await.unwrap();
    println!("{}", String::from_utf8_lossy(&packet.payload));

    // Pool info
    println!("Active connections: {}", pool.len());
    println!("Is full: {}", pool.is_full());
    println!("IDs: {:?}", pool.connection_ids());

    // Close one or all
    pool.close(id1).unwrap();
    pool.close_all();
}
```

### VCLPool API

| Method | Returns | Description |
|--------|---------|-------------|
| `new(max)` | `VCLPool` | Create pool with max connection limit |
| `bind(addr)` | `Result<ConnectionId, VCLError>` | Bind new connection, add to pool |
| `connect(id, addr)` | `Result<(), VCLError>` | Connect to remote peer |
| `accept_handshake(id)` | `Result<(), VCLError>` | Accept incoming handshake |
| `send(id, data)` | `Result<(), VCLError>` | Send data on connection |
| `recv(id)` | `Result<VCLPacket, VCLError>` | Receive data on connection |
| `ping(id)` | `Result<(), VCLError>` | Send ping on connection |
| `rotate_keys(id)` | `Result<(), VCLError>` | Rotate keys on connection |
| `close(id)` | `Result<(), VCLError>` | Close and remove connection |
| `close_all()` | `()` | Close all connections |
| `len()` | `usize` | Number of active connections |
| `is_empty()` | `bool` | True if no connections |
| `is_full()` | `bool` | True if at max capacity |
| `contains(id)` | `bool` | True if ID exists in pool |
| `connection_ids()` | `Vec<ConnectionId>` | List all active IDs |

---

## Logging 📝

VCL Protocol uses the `tracing` crate for structured logging.
Add one line to your `main()` to enable log output:
```rust
tracing_subscriber::fmt::init();
```

Log levels used:
- `INFO` — handshake, connection open/close, key rotation
- `DEBUG` — packet send/receive, ping/pong, nonce window
- `WARN` — replay attacks, chain failures, signature errors, timeouts
- `ERROR` — operations on closed connections

Example output:
```
2024-01-01T00:00:00Z  INFO vcl_protocol::connection: VCLConnection bound addr=127.0.0.1:8080
2024-01-01T00:00:00Z  INFO vcl_protocol::connection: Handshake complete (server) peer=127.0.0.1:12345
2024-01-01T00:00:00Z DEBUG vcl_protocol::connection: Packet sent seq=0 size=11 packet_type=Data
```

---

## Connection Events 📡
```rust
use vcl_protocol::{connection::VCLConnection, VCLEvent};

#[tokio::main]
async fn main() {
    let mut conn = VCLConnection::bind("127.0.0.1:0").await.unwrap();
    let mut events = conn.subscribe();

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
}
```

---

## Ping / Heartbeat 🏓
```rust
client.ping().await.unwrap();

loop {
    match client.recv().await {
        Ok(packet) => { /* handle data */ }
        Err(e)     => { eprintln!("{}", e); break; }
    }
}
```

---

## Key Rotation 🔄
```rust
// Initiator
client.rotate_keys().await.unwrap();

// Responder — handled automatically inside recv()
```

---

## Benchmarks 📊
```bash
cargo bench
```

Results (WSL2 Debian, optimized):

| Operation | Time |
|-----------|------|
| keypair_generate | ~13 µs |
| encrypt 64B | ~1.5 µs |
| encrypt 16KB | ~12 µs |
| decrypt 64B | ~1.4 µs |
| packet_sign | ~32 µs |
| packet_verify | ~36 µs |
| full pipeline 64B | ~38 µs |

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

### VCLError

| Variant | When |
|---------|------|
| `CryptoError(msg)` | Encryption/decryption failure |
| `SignatureInvalid` | Ed25519 signature verification failed |
| `InvalidKey(msg)` | Key has wrong length or format |
| `ChainValidationFailed` | prev_hash mismatch |
| `ReplayDetected(msg)` | Duplicate sequence number or nonce |
| `InvalidPacket(msg)` | Malformed or unexpected packet |
| `ConnectionClosed` | Operation on a closed connection |
| `Timeout` | No activity for longer than timeout_secs |
| `NoPeerAddress` | send() called before peer address is known |
| `NoSharedSecret` | send()/recv() called before handshake |
| `HandshakeFailed(msg)` | X25519 key exchange failed |
| `ExpectedClientHello` | Server received wrong handshake message |
| `ExpectedServerHello` | Client received wrong handshake message |
| `SerializationError(msg)` | bincode failed |
| `IoError(msg)` | UDP socket or address parse error |

---

## Security Model 🔐

### 1. Handshake (X25519)
- Ephemeral key exchange per connection
- No pre-shared keys required
- Forward secrecy

### 2. Chain Integrity (SHA-256)
- Send and receive chains tracked independently
- Tampering breaks the chain

### 3. Authentication (Ed25519)
- Every packet is digitally signed
- Prevents spoofing

### 4. Encryption (XChaCha20-Poly1305)
- All payloads encrypted with AEAD cipher
- Unique nonce per packet

### 5. Replay Protection
- Sequence numbers strictly increasing
- Nonces tracked in sliding window (1000 entries)

### 6. Session Management
- close() clears all sensitive state
- Timeout prevents resource leaks

### 7. Key Rotation
- Fresh X25519 per rotation
- Old key encrypts rotation messages

---

## Testing 🧪
```bash
cargo test                         # All 33 tests
cargo test --lib                   # Unit tests
cargo test --test integration_test # Integration tests
cargo bench                        # Benchmarks
cargo run --example server         # Example server
cargo run --example client         # Example client
```

---

## Project Structure 📦
```
vcl-protocol/
├── src/
│   ├── main.rs          # Demo application
│   ├── lib.rs           # Library entry point
│   ├── connection.rs    # Connection API
│   ├── event.rs         # VCLEvent enum
│   ├── pool.rs          # VCLPool — connection manager
│   ├── packet.rs        # VCLPacket + PacketType
│   ├── crypto.rs        # KeyPair, encrypt, decrypt
│   ├── error.rs         # VCLError
│   └── handshake.rs     # X25519 handshake
├── benches/
│   └── vcl_benchmarks.rs
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
5. Run `cargo test` and `cargo clippy`
6. Submit a pull request

---

## License 📄

MIT License — see LICENSE file for details.

---

## Support 📬

- Issues: https://github.com/ultrakill148852-collab/vcl-protocol/issues
- Discussions: https://github.com/ultrakill148852-collab/vcl-protocol/discussions

---

## Changelog 🔄

### v0.3.0 (Current) ✨
- **Connection Pool** — `VCLPool` for managing multiple connections
- **Tracing logs** — structured `INFO/DEBUG/WARN/ERROR` via `tracing`
- **Benchmarks** — `criterion` benchmarks for all crypto and packet ops
- **Full API docs** — complete `///` doc comments, published on [docs.rs](https://docs.rs/vcl-protocol)
- **33/33 tests passing**

### v0.2.0 ✅
- Connection Events (`VCLEvent` + `subscribe()`)
- Ping / Heartbeat with latency measurement
- Mid-session Key Rotation
- Custom Error Types (`VCLError`)
- Bidirectional chain fix

### v0.1.0 ✅
- Cryptographic chain with SHA-256
- Ed25519 signatures + X25519 handshake
- XChaCha20-Poly1305 authenticated encryption
- Replay protection
- Session management
- 17/17 tests passing

### Planned for v0.4.0
- VPN support (TUN/TAP interface)
- IP packets inside VCL packets
- Routing

---

<div align="center">

**Made with ❤️ using Rust**

*Secure • Chained • Verified • Production Ready*

</div>
