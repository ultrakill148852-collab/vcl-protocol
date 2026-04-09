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
[![Tests](https://img.shields.io/badge/tests-257%2F257%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-v1.0.0%20Stable-green.svg)]()

**Verified Commit Link** — Cryptographically chained packet transport protocol

---

## 📚 Documentation

**[README](README.md)** | **[Usage Guide](USAGE.md)** | **[Crates.io](https://crates.io/crates/vcl-protocol)** | **[Docs.rs](https://docs.rs/vcl-protocol)** | **[GitHub](https://github.com/ultrakill148852-collab/vcl-protocol)**

---

## 📖 About

VCL Protocol is a transport protocol where each packet cryptographically links to the previous one, creating an immutable chain of data transmission. Inspired by blockchain principles, optimized for real-time networking.

**v1.0.0** is the production release — adds TUN interface for IP packet capture, full IP/TCP/UDP/ICMP parsing, multipath routing across multiple network interfaces, automatic MTU negotiation, NAT keepalive, automatic reconnection, DNS leak protection, and traffic obfuscation to bypass DPI censorship.

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
| 🔌 TCP Transport | Reliable ordered delivery for VPN scenarios |
| 🌐 WebSocket Transport | Browser-compatible, works through HTTP proxies |
| 🔀 Transport Abstraction | Single API works with UDP, TCP, and WebSocket |
| 🚫 Custom Error Types | Typed `VCLError` enum with full `std::error::Error` impl |
| 📡 Connection Events | Subscribe to lifecycle & data events via async mpsc channel |
| 🏓 Ping / Heartbeat | Built-in ping/pong with automatic round-trip latency measurement |
| 🔄 Key Rotation | Rotate encryption keys mid-session without reconnecting |
| 🏊 Connection Pool | Manage multiple connections under a single `VCLPool` manager |
| 🧩 Packet Fragmentation | Automatic split and reassembly for large payloads |
| 🌊 Flow Control | Sliding window with RFC 6298 RTT estimation |
| 📉 Congestion Control | AIMD algorithm with slow start and retransmission |
| 🔁 Retransmission | Automatic retransmit on timeout with exponential backoff |
| 📊 Metrics API | `VCLMetrics` aggregates stats across connections and pools |
| ⚙️ Config Presets | VPN, Gaming, Streaming, Auto — one line setup |
| 📝 Tracing Logs | Structured logging via `tracing` crate |
| 📈 Benchmarks | Performance benchmarks via `criterion` |
| 🖥️ TUN Interface | Capture IP packets from OS network stack (Linux) |
| 📦 IP Packet Parser | Full IPv4/IPv6/TCP/UDP/ICMP header parsing |
| 🔀 Multipath | Send across multiple interfaces (WiFi + LTE) simultaneously |
| 📐 MTU Negotiation | Automatic path MTU discovery via binary search |
| 💓 Keepalive | NAT keepalive presets for Mobile/Home/Corporate networks |
| 🔌 Reconnect | Exponential backoff reconnection with jitter |
| 🛡️ DNS Leak Protection | Intercept DNS, blocklist, split DNS, response caching |
| 🎭 Traffic Obfuscation | TLS/HTTP2 mimicry to bypass DPI censorship (МТС, Beeline) |
| 📖 Full API Docs | Complete documentation on [docs.rs](https://docs.rs/vcl-protocol) |
| 🧪 Full Test Suite | 257/257 tests passing (unit + integration + doc) |

---

## 🏗️ Architecture

```text
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

```text
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

```text
Send: plaintext → obfuscate? → fragment? → encrypt(XChaCha20) → sign(Ed25519) → send
Recv: receive → verify(Ed25519) → decrypt(XChaCha20) → reassemble? → deobfuscate? → plaintext
```

### Session Management

```text
- close()         → Gracefully close connection, clear state
- is_closed()     → Check if connection is closed
- set_timeout()   → Configure inactivity timeout (default: 60s)
- last_activity() → Get timestamp of last send/recv
```

### Event Flow

```text
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

```text
Client                              Server
   |                                   |
   | -- KeyRotation(new_pubkey) -----> |
   |                                   |
   | <--- KeyRotation(new_pubkey) ---- |
   |                                   |
   | [both sides now use new key]      |
```

### Connection Pool

```text
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

### Fragmentation Flow

```text
send(large_payload)
   |
   ├── payload > fragment_size?
   |     YES → Fragmenter::split → [Frag0][Frag1][Frag2]...
   |            each fragment encrypted + signed separately
   |     NO  → single Data packet
   |
recv()
   |
   ├── PacketType::Fragment → Reassembler::add(frag)
   |     incomplete → loop, wait for more fragments
   |     complete   → return reassembled VCLPacket
   └── PacketType::Data → return directly
```

### Flow Control & Congestion Control

```text
FlowController (sliding window + AIMD)
   |
   ├── can_send()            → effective window has space?
   ├── on_send(seq, data)    → register packet as in-flight
   ├── on_ack(seq)           → remove from window, update RTT (RFC 6298)
   ├── timed_out_packets()   → RetransmitRequest[] with data to resend
   ├── loss_rate()           → f64 packet loss rate
   ├── cwnd()                → current congestion window
   └── in_slow_start()       → slow start phase active?

AIMD:
  No loss → cwnd += 1/cwnd per ack   (additive increase)
  Loss    → cwnd = 1, ssthresh /= 2  (multiplicative decrease)
  RTO     → doubles on loss, min 50ms, max 60s
```

### WebSocket Transport

```text
VCLTransport::bind_ws("addr")     → WebSocketListener
VCLTransport::connect_ws("url")   → WebSocketClient
listener.accept()                 → WebSocketServer

All send/recv via binary frames — same API as TCP/UDP
Works through HTTP proxies and firewalls
```

### TUN Interface (v1.0.0)

```text
OS Network Stack
   ↓ (routing table)
TUN interface (vcl0) ← VCLTun::create(TunConfig)
   ↓ VCLTun::read_packet()
IP Packet → parse_ip_packet() → ParsedPacket { src, dst, protocol, ... }
   ↓ encrypt + send via VCLConnection
   ↓ recv + decrypt
VCLTun::write_packet() → inject back into OS stack
```

### Multipath (v1.0.0)

```text
MultipathSender (scheduling policies):
  BestPath          → highest bandwidth/latency score
  RoundRobin        → alternate across all active paths
  WeightedRoundRobin→ more traffic to higher-bandwidth paths
  Redundant         → send on ALL paths simultaneously
  LowestLatency     → always pick fastest path

MultipathReceiver:
  Reordering buffer → delivers packets in sequence order
  Duplicate detection → silently drops redundant copies
```

### Traffic Obfuscation (v1.0.0)

```text
ObfuscationMode::TlsMimicry   → looks like TLS 1.3 HTTPS
ObfuscationMode::Http2Mimicry → looks like HTTP/2 DATA frames
ObfuscationMode::Full         → TLS + size normalization + jitter
ObfuscationMode::Padding      → random padding only

recommended_mode("mts")    → Full
recommended_mode("home")   → TlsMimicry
recommended_mode("office") → Http2Mimicry
```

### Config Presets

```text
VCLConfig::vpn()       → TCP + Reliable   (VPN, file transfer)
VCLConfig::gaming()    → UDP + Partial    (games, real-time)
VCLConfig::streaming() → UDP + Unreliable (video, audio)
VCLConfig::auto()      → Auto + Adaptive  (recommended default)
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

### Obfuscation Example (v1.0.0)

```rust
use vcl_protocol::obfuscation::{Obfuscator, ObfuscationConfig, recommended_mode, ObfuscationMode};

// For МТС/Beeline mobile networks
let mode = recommended_mode("mts"); // → Full
let mut obf = Obfuscator::new(ObfuscationConfig::full());

let data = b"vcl packet payload";
let obfuscated = obf.obfuscate(data);   // looks like TLS to DPI
let restored = obf.deobfuscate(&obfuscated).unwrap();
assert_eq!(restored, data);

println!("Overhead: {:.1}%", obf.overhead_ratio() * 100.0);
```

### Keepalive Example (v1.0.0)

```rust
use vcl_protocol::keepalive::{KeepaliveManager, KeepalivePreset, KeepaliveAction};

// Mobile preset — keeps NAT alive on МТС/Beeline (30s timeout)
let mut keepalive = KeepaliveManager::from_preset(KeepalivePreset::Mobile);

loop {
    match keepalive.check() {
        KeepaliveAction::SendPing => {
            keepalive.record_keepalive_sent();
            // conn.ping().await?;
        }
        KeepaliveAction::PongTimeout    => { keepalive.record_pong_missed(); }
        KeepaliveAction::ConnectionDead => { break; /* reconnect */ }
        KeepaliveAction::Idle           => {}
    }
    // tokio::time::sleep(Duration::from_secs(1)).await;
}
```

### DNS Protection Example (v1.0.0)

```rust
use vcl_protocol::dns::{DnsFilter, DnsConfig, DnsAction, DnsQueryType};

let config = DnsConfig::cloudflare()
    .with_blocked_domain("ads.example.com")
    .with_split_domain("corp.internal");

let mut filter = DnsFilter::new(config);

match filter.decide("ads.example.com", &DnsQueryType::A) {
    DnsAction::Block               => { /* return NXDOMAIN */ }
    DnsAction::ForwardThroughTunnel => { /* send via VCL */ }
    DnsAction::AllowDirect         => { /* use OS resolver */ }
    DnsAction::ReturnCached(addr)  => { /* return cached IP */ }
}
```

---

## 📦 Packet Structure

```rust
pub struct VCLPacket {
    pub version: u8,             // Protocol version (2)
    pub packet_type: PacketType, // Data | Ping | Pong | KeyRotation | Fragment
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

### 🌐 VPN Infrastructure
TUN interface + multipath + keepalive + reconnect + DNS protection — complete VPN protocol foundation.

### 🌍 Censorship Circumvention
Traffic obfuscation (TLS/HTTP2 mimicry) bypasses DPI used by ISPs like МТС and Beeline.

### 🖥️ Browser Clients
WebSocket transport allows VCL Protocol to work from browsers and through corporate HTTP proxies.

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
- **UDP** — low latency, default
- **TCP** — reliable, ordered (VPN mode)
- **WebSocket** — browser-compatible, HTTP proxy-friendly
- **Runtime:** Tokio async
- **Max Packet Size:** 65535 bytes
- **TCP/WS Framing:** 4-byte big-endian length prefix (TCP), binary frames (WS)

### TUN Interface (v1.0.0)
- **Platform:** Linux only (requires `CAP_NET_ADMIN` or root)
- **Default MTU:** 1420 bytes
- **IP versions:** IPv4 and IPv6
- **Crate:** `tun` with async feature

### IP Parsing (v1.0.0)
- **IPv4/IPv6** header parsing via `etherparse`
- **Protocols:** TCP, UDP, ICMP, ICMPv6, and any other protocol number
- **Helpers:** `is_dns()`, `is_ping()`, `summary()`

### Multipath (v1.0.0)
- **Scheduling:** BestPath, RoundRobin, WeightedRoundRobin, Redundant, LowestLatency
- **Reorder buffer:** up to 256 out-of-order packets
- **Duplicate detection:** sequence-based

### MTU Negotiation (v1.0.0)
- **Algorithm:** Binary search probing
- **Range:** 576–1500 bytes (configurable up to 9000 for jumbo frames)
- **VCL overhead:** 149 bytes (Ed25519 + hash + nonce + headers)

### Keepalive (v1.0.0)
- **Mobile preset:** 20s interval (МТС/Beeline 30s NAT timeout)
- **Adaptive:** adjusts interval based on measured RTT
- **Dead detection:** configurable missed pong count

### DNS Protection (v1.0.0)
- **Upstream:** Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9)
- **Cache:** TTL-based, up to 1024 entries
- **Blocklist:** wildcard subdomain matching
- **Split DNS:** per-domain bypass rules

### Traffic Obfuscation (v1.0.0)
- **TLS Mimicry:** Content-Type 0x17, Version 0x0303 (TLS 1.3 compat)
- **HTTP/2 Mimicry:** DATA frame (type 0x00) with stream ID rotation
- **Size Normalization:** pads to common HTTPS sizes (64–1460 bytes)
- **XOR Scrambling:** lightweight payload scrambling
- **Timing Jitter:** pseudo-random delay to disguise traffic patterns

### Fragmentation
- **Threshold:** configurable via `VCLConfig::fragment_size` (default 1200 bytes)
- **Out-of-order reassembly:** supported
- **Duplicate fragments:** silently ignored
- **Max pending messages:** 256 (configurable)

### Flow Control & Congestion Control
- **Algorithm:** Sliding window + AIMD
- **Slow start:** exponential cwnd growth until ssthresh
- **Congestion avoidance:** additive increase 1/cwnd per ack
- **Loss response:** cwnd = 1, ssthresh halved, back to slow start
- **RTT estimation:** RFC 6298 (SRTT + RTTVAR)
- **RTO:** dynamic, doubles on loss, min 50ms, max 60s

### Serialization
- **Format:** Bincode
- **Efficiency:** Minimal overhead, fast serialization

### Dependencies
- `ed25519-dalek` — Ed25519 signatures
- `x25519-dalek` — X25519 key exchange
- `chacha20poly1305` — XChaCha20-Poly1305 AEAD encryption
- `sha2` — SHA-256 hashing
- `tokio` — Async runtime
- `tokio-tungstenite` — WebSocket transport
- `futures-util` — async stream utilities
- `tun` — TUN virtual network interface
- `etherparse` — IP/TCP/UDP packet parsing
- `serde` + `bincode` — Serialization
- `tracing` — Structured logging
- `tracing-subscriber` — Log output

---

## 🛠️ Development

```bash
cargo test                         # Run all tests (257/257)
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
