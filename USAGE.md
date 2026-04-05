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
- **[v0.5.0]** WebSocket transport via `tokio-tungstenite`
- **[v0.5.0]** AIMD congestion control with slow start
- **[v0.5.0]** Automatic retransmission with exponential backoff
- **[v0.5.0]** `VCLMetrics` API for performance monitoring

---

## Installation 🚀

### Add to Cargo.toml
```toml
[dependencies]
vcl-protocol = "0.5.0"
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

## WebSocket Transport 🌐

Browser-compatible transport that works through HTTP proxies and firewalls.
```rust
use vcl_protocol::transport::VCLTransport;

#[tokio::main]
async fn main() {
    // Server side
    let listener = VCLTransport::bind_ws("127.0.0.1:8080").await.unwrap();
    let mut server_conn = listener.accept().await.unwrap();

    // Client side
    let mut client = VCLTransport::connect_ws("ws://127.0.0.1:8080").await.unwrap();

    client.send_raw(b"hello from browser").await.unwrap();
    let (data, _) = server_conn.recv_raw().await.unwrap();
    println!("{}", String::from_utf8_lossy(&data));
}
```

WebSocket transport uses binary frames. Ping, pong, text, and close frames are handled automatically — only binary data is exposed to the user.

---

## Retransmission & Congestion Control 📉

Built into `FlowController` — no extra setup needed. Retransmission requests are returned by `timed_out_packets()` with the original data payload ready to resend.
```rust
use vcl_protocol::flow::FlowController;

let mut fc = FlowController::new(64);

// Register sent packet with its data
fc.on_send(0, b"important data".to_vec());

// Check for timed-out packets periodically
let requests = fc.timed_out_packets();
for req in requests {
    println!("Retransmit seq={} attempt={}", req.sequence, req.retransmit_count);
    // resend req.data here
}

// AIMD stats
println!("cwnd: {:.1}", fc.cwnd());
println!("in slow start: {}", fc.in_slow_start());
println!("total retransmits: {}", fc.total_retransmits());
```

AIMD algorithm:
- **Slow start:** cwnd grows by 1 per ack until ssthresh
- **Congestion avoidance:** cwnd grows by 1/cwnd per ack
- **On loss:** cwnd reset to 1, ssthresh halved, RTO doubled

---

## Metrics API 📊

`VCLMetrics` collects performance and health statistics for a connection or pool.
```rust
use vcl_protocol::metrics::VCLMetrics;
use std::time::Duration;

let mut m = VCLMetrics::new();

// Record events
m.record_sent(1024);
m.record_received(512);
m.record_retransmit();
m.record_rtt_sample(Duration::from_millis(42));
m.record_cwnd(32);
m.record_handshake();
m.record_key_rotation();

// Read stats
println!("Loss rate:    {:.2}%", m.loss_rate() * 100.0);
println!("Avg RTT:      {:?}", m.avg_rtt());
println!("Min RTT:      {:?}", m.min_rtt());
println!("Max RTT:      {:?}", m.max_rtt());
println!("Current cwnd: {:?}", m.current_cwnd());
println!("Throughput:   {:.0} B/s sent", m.throughput_sent_bps());
println!("Uptime:       {:?}", m.uptime());
println!("Total dropped:{}", m.total_dropped());
```

### Pool-level aggregation
```rust
let mut pool_metrics = VCLMetrics::new();
let conn_metrics = VCLMetrics::new(); // from individual connection
pool_metrics.merge(&conn_metrics);
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
let conn = VCLConnection::bind("127.0.0.1:0").await.unwrap();

println!("Can send:      {}", conn.flow().can_send());
println!("In flight:     {}", conn.flow().in_flight_count());
println!("cwnd:          {:.1}", conn.flow().cwnd());
println!("Effective win: {}", conn.flow().effective_window());
println!("Loss rate:     {:.2}%", conn.flow().loss_rate() * 100.0);
println!("Retransmits:   {}", conn.flow().total_retransmits());

if let Some(rtt) = conn.flow().srtt() {
    println!("SRTT: {:?}", rtt);
}
if let Some(rttvar) = conn.flow().rttvar() {
    println!("RTTVAR: {:?}", rttvar);
}

// Manually ack a packet (advanced use)
conn.ack_packet(sequence_number);
```

---

## Transport Abstraction 🔌

Use `VCLTransport` directly for low-level TCP/UDP/WebSocket control.
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

// WebSocket server
let ws_listener = VCLTransport::bind_ws("127.0.0.1:8081").await.unwrap();
let mut ws_conn = ws_listener.accept().await.unwrap();

// WebSocket client
let mut ws_client = VCLTransport::connect_ws("ws://127.0.0.1:8081").await.unwrap();

// From config
let transport = VCLTransport::from_config_server("127.0.0.1:0", &VCLConfig::vpn()).await.unwrap();
assert!(transport.is_tcp());
assert!(ws_client.is_websocket());
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
- `INFO` — handshake, open/close, key rotation, fragmentation complete, slow start exit
- `DEBUG` — packet send/receive, fragments, flow window, AIMD cwnd changes
- `WARN` — replay attacks, chain failures, flow window full, timeouts, retransmissions, AIMD decrease
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
| `flow()` | `&FlowController` | Flow control + congestion stats |
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
| `IoError(msg)` | Socket, WebSocket, or address error |

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
cargo test                         # All 113 tests
cargo test --lib                   # Unit tests
cargo test --test integration_test # Integration tests
cargo bench                        # Benchmarks
cargo run --example server         # Example server
cargo run --example client         # Example client
```

---

## Project Structure 📦
```text
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
│   ├── transport.rs     # VCLTransport (UDP/TCP/WebSocket)
│   ├── fragment.rs      # Fragmenter + Reassembler
│   ├── flow.rs          # FlowController + AIMD + Retransmission
│   └── metrics.rs       # VCLMetrics
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

### v0.5.0 (Current) ✨
- **WebSocket Transport** — `bind_ws()`, `connect_ws()`, binary frames via `tokio-tungstenite`
- **Congestion Control (AIMD)** — slow start + congestion avoidance + multiplicative decrease
- **Retransmission** — `RetransmitRequest` with data payload, exponential RTO backoff
- **RFC 6298 RTT** — SRTT + RTTVAR estimation, dynamic RTO
- **Metrics API** — `VCLMetrics` with merge() for pool aggregation
- **113/113 tests passing**

### v0.4.0 ✅
- TCP/UDP Transport Abstraction (`VCLTransport`)
- Packet Fragmentation (Fragmenter + Reassembler)
- Flow Control (sliding window)
- Config Presets (`VCLConfig::vpn()`, `gaming()`, `streaming()`, `auto()`)
- `bind_with_config()`
- 89/89 tests passing

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
