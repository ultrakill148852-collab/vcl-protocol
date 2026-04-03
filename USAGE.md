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
- UDP and TCP transport with Tokio async runtime
- **[v0.2.0]** Connection Events via async mpsc channel
- **[v0.2.0]** Ping / Heartbeat with round-trip latency measurement
- **[v0.2.0]** Mid-session Key Rotation via X25519
- **[v0.3.0]** Connection Pool via `VCLPool`
- **[v0.3.0]** Structured logging via `tracing`
- **[v0.3.0]** Performance benchmarks via `criterion`
- **[v0.3.0]** Full API docs on [docs.rs](https://docs.rs/vcl-protocol)
- **[v0.4.0]** TCP/UDP Transport Abstraction via `VCLTransport`
- **[v0.4.0]** Automatic packet fragmentation and reassembly
- **[v0.4.0]** Sliding window flow control with RTT estimation
- **[v0.4.0]** Config presets: VPN, Gaming, Streaming, Auto

---

## Installation 🚀

### Add to Cargo.toml
```toml
[dependencies]
vcl-protocol = "0.4.0"
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

## Config Presets ⚙️

`VCLConfig` controls transport, reliability, fragmentation, and flow control.
```rust
use vcl_protocol::connection::VCLConnection;
use vcl_protocol::config::VCLConfig;

#[tokio::main]
async fn main() {
    // VPN mode — TCP + reliable delivery
    let mut conn = VCLConnection::bind_with_config(
        "127.0.0.1:0",
        VCLConfig::vpn()
    ).await.unwrap();

    // Gaming mode — UDP + partial reliability
    let mut conn = VCLConnection::bind_with_config(
        "127.0.0.1:0",
        VCLConfig::gaming()
    ).await.unwrap();

    // Streaming mode — UDP + no retransmission
    let mut conn = VCLConnection::bind_with_config(
        "127.0.0.1:0",
        VCLConfig::streaming()
    ).await.unwrap();

    // Auto mode (default) — adapts to network conditions
    let mut conn = VCLConnection::bind("127.0.0.1:0").await.unwrap();
}
```

### Preset Reference

| Preset | Transport | Reliability | Fragment size | Window | Use case |
|--------|-----------|-------------|---------------|--------|----------|
| `vpn()` | TCP | Reliable | 1200B | 64 | VPN, secure comms |
| `gaming()` | UDP | Partial | 1400B | 128 | Real-time games |
| `streaming()` | UDP | Unreliable | 1400B | 256 | Video/audio |
| `auto()` | Auto | Adaptive | 1200B | 64 | Unknown/mixed |

### Custom Config
```rust
use vcl_protocol::config::{VCLConfig, TransportMode, ReliabilityMode};

let config = VCLConfig {
    transport: TransportMode::Udp,
    reliability: ReliabilityMode::Partial,
    max_retries: 3,
    retry_interval_ms: 50,
    fragment_size: 800,
    flow_window_size: 32,
};
```

---

## Fragmentation 🧩

Large payloads are automatically split and reassembled — no manual steps needed.
```rust
// Sender — payload > fragment_size is split automatically
let large_data = vec![0u8; 50_000];
client.send(&large_data).await.unwrap();

// Receiver — recv() returns the complete reassembled payload
let packet = server.recv().await.unwrap();
assert_eq!(packet.payload.len(), 50_000);
```

Fragmentation behaviour is controlled by `VCLConfig::fragment_size` (default 1200 bytes).
Out-of-order fragment arrival is handled automatically.

---

## Flow Control 🌊

The sliding window flow controller is built into every connection.
```rust
// Inspect flow stats
let conn = VCLConnection::bind("127.0.0.1:0").await.unwrap();

println!("Can send: {}", conn.flow().can_send());
println!("In flight: {}", conn.flow().in_flight_count());
println!("Loss rate: {:.2}%", conn.flow().loss_rate() * 100.0);

if let Some(rtt) = conn.flow().srtt() {
    println!("RTT estimate: {:?}", rtt);
}

// Manually ack a packet (advanced use)
conn.ack_packet(sequence_number);
```

Window size is configured via `VCLConfig::flow_window_size`.

---

## Transport Abstraction 🔌

Use `VCLTransport` directly for low-level TCP/UDP control.
```rust
use vcl_protocol::transport::VCLTransport;
use vcl_protocol::config::VCLConfig;

// UDP
let mut udp = VCLTransport::bind_udp("127.0.0.1:0").await.unwrap();

// TCP server
let listener = VCLTransport::bind_tcp("127.0.0.1:8080").await.unwrap();
let mut conn = listener.accept().await.unwrap();

// TCP client
let mut client = VCLTransport::connect_tcp("127.0.0.1:8080").await.unwrap();

// From config
let transport = VCLTransport::from_config_server("127.0.0.1:0", &VCLConfig::vpn()).await.unwrap();
assert!(transport.is_tcp());
```

---

## Connection Pool 🏊
```rust
use vcl_protocol::VCLPool;

#[tokio::main]
async fn main() {
    let mut pool = VCLPool::new(10);

    let id1 = pool.bind("127.0.0.1:0").await.unwrap();
    let id2 = pool.bind("127.0.0.1:0").await.unwrap();

    pool.connect(id1, "127.0.0.1:8080").await.unwrap();
    pool.connect(id2, "127.0.0.1:8081").await.unwrap();

    pool.send(id1, b"Hello server 1!").await.unwrap();
    pool.send(id2, b"Hello server 2!").await.unwrap();

    let packet = pool.recv(id1).await.unwrap();
    println!("{}", String::from_utf8_lossy(&packet.payload));

    println!("Active connections: {}", pool.len());
    println!("Is full: {}", pool.is_full());

    pool.close(id1).unwrap();
    pool.close_all();
}
```

---

## Logging 📝
```rust
tracing_subscriber::fmt::init();
```

Log levels:
- `INFO` — handshake, open/close, key rotation, fragmentation complete
- `DEBUG` — packet send/receive, fragments, flow window
- `WARN` — replay attacks, chain failures, flow window full, timeouts
- `ERROR` — operations on closed connections

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
                    println!("Handshake complete"),
                VCLEvent::Disconnected =>
                    println!("Connection closed"),
                VCLEvent::PacketReceived { sequence, size } =>
                    println!("Packet #{} ({} bytes)", sequence, size),
                VCLEvent::PingReceived =>
                    println!("Ping — pong sent automatically"),
                VCLEvent::PongReceived { latency } =>
                    println!("RTT: {:?}", latency),
                VCLEvent::KeyRotated =>
                    println!("Key rotation complete"),
                VCLEvent::Error(msg) =>
                    eprintln!("Error: {}", msg),
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
| `bind(addr)` | `Result<Self, VCLError>` | Bind with default config |
| `bind_with_config(addr, config)` | `Result<Self, VCLError>` | Bind with custom config |
| `connect(addr)` | `Result<(), VCLError>` | Connect + X25519 handshake |
| `accept_handshake()` | `Result<(), VCLError>` | Accept incoming connection |
| `subscribe()` | `mpsc::Receiver<VCLEvent>` | Subscribe to events |
| `send(data)` | `Result<(), VCLError>` | Send data (auto-fragments if large) |
| `recv()` | `Result<VCLPacket, VCLError>` | Receive next data packet |
| `ping()` | `Result<(), VCLError>` | Send ping |
| `rotate_keys()` | `Result<(), VCLError>` | Mid-session key rotation |
| `close()` | `Result<(), VCLError>` | Close connection |
| `is_closed()` | `bool` | Connection closed? |
| `set_timeout(secs)` | `()` | Set inactivity timeout |
| `get_timeout()` | `u64` | Get timeout value |
| `last_activity()` | `Instant` | Last send/recv timestamp |
| `get_config()` | `&VCLConfig` | Current config |
| `flow()` | `&FlowController` | Flow control stats |
| `ack_packet(seq)` | `bool` | Manually ack a packet |
| `get_public_key()` | `Vec<u8>` | Local Ed25519 public key |
| `get_shared_secret()` | `Option<[u8; 32]>` | Current shared secret |
| `set_shared_key(key)` | `()` | Pre-shared key (testing only) |

### VCLError

| Variant | When |
|---------|------|
| `CryptoError(msg)` | Encryption/decryption failure |
| `SignatureInvalid` | Ed25519 verification failed |
| `InvalidKey(msg)` | Key wrong length or format |
| `ChainValidationFailed` | prev_hash mismatch |
| `ReplayDetected(msg)` | Duplicate sequence or nonce |
| `InvalidPacket(msg)` | Malformed or unexpected packet |
| `ConnectionClosed` | Operation on closed connection |
| `Timeout` | Inactivity timeout exceeded |
| `NoPeerAddress` | send() before peer known |
| `NoSharedSecret` | send()/recv() before handshake |
| `HandshakeFailed(msg)` | X25519 exchange failed |
| `ExpectedClientHello` | Wrong handshake message |
| `ExpectedServerHello` | Wrong handshake message |
| `SerializationError(msg)` | bincode failed |
| `IoError(msg)` | Socket or address error |

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
- Every packet signed
- Prevents spoofing

### 4. Encryption (XChaCha20-Poly1305)
- All payloads encrypted with AEAD
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
cargo test                         # All 89 tests
cargo test --lib                   # Unit tests
cargo test --test integration_test # Integration tests
cargo bench                        # Benchmarks
cargo run --example server         # Example server
cargo run --example client         # Example client
```

---

## Project Structure 📦
vcl-protocol/
├── src/
│   ├── main.rs          # Demo application
│   ├── lib.rs           # Library entry point
│   ├── connection.rs    # VCLConnection — main API
│   ├── event.rs         # VCLEvent enum
│   ├── pool.rs          # VCLPool — connection manager
│   ├── packet.rs        # VCLPacket + PacketType
│   ├── crypto.rs        # KeyPair, encrypt, decrypt
│   ├── error.rs         # VCLError
│   ├── handshake.rs     # X25519 handshake
│   ├── config.rs        # VCLConfig + presets
│   ├── transport.rs     # VCLTransport (TCP/UDP abstraction)
│   ├── fragment.rs      # Fragmenter + Reassembler
│   └── flow.rs          # FlowController
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

### v0.4.0 (Current) ✨
- **TCP/UDP Transport Abstraction** — `VCLTransport` with unified send/recv API
- **Packet Fragmentation** — automatic split and reassembly for large payloads
- **Flow Control** — sliding window with RTT estimation and retransmission detection
- **Config Presets** — `VCLConfig::vpn()`, `gaming()`, `streaming()`, `auto()`
- **`bind_with_config()`** — configure connection at bind time
- **89/89 tests passing**

### v0.3.0 ✅
- Connection Pool (`VCLPool`)
- Tracing logs
- Benchmarks (criterion)
- Full API docs on docs.rs
- 33/33 tests passing

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

---

<div align="center">

**Made with ❤️ using Rust**

*Secure • Chained • Verified • Production Ready*

</div>
