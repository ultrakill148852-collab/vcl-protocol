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
- **[v1.0.0]** TUN interface for IP packet capture (Linux)
- **[v1.0.0]** Full IP/TCP/UDP/ICMP packet parser
- **[v1.0.0]** Multipath with 5 scheduling policies
- **[v1.0.0]** Automatic MTU negotiation via binary search
- **[v1.0.0]** NAT Keepalive (Mobile/Home/Corporate presets)
- **[v1.0.0]** Automatic reconnection with exponential backoff
- **[v1.0.0]** DNS leak protection with blocklist and split DNS
- **[v1.0.0]** Traffic obfuscation — TLS/HTTP2 mimicry for DPI bypass

---

## Installation 🚀

### Add to Cargo.toml

```toml
[dependencies]
vcl-protocol = "1.0.0"
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

## Traffic Obfuscation 🎭

Bypass DPI censorship used by ISPs like МТС and Beeline.

```rust
use vcl_protocol::obfuscation::{Obfuscator, ObfuscationConfig, recommended_mode};

// Auto-select based on network
let mode = recommended_mode("mts");      // → Full (TLS + size norm + jitter)
let mode = recommended_mode("home");     // → TlsMimicry
let mode = recommended_mode("office");   // → Http2Mimicry

// Use full obfuscation for mobile censored networks
let mut obf = Obfuscator::new(ObfuscationConfig::full());

let data = b"secret vcl packet";
let obfuscated = obf.obfuscate(data);        // → looks like TLS to DPI
let restored   = obf.deobfuscate(&obfuscated).unwrap();
assert_eq!(restored, data);

println!("Overhead: {:.1}%", obf.overhead_ratio() * 100.0);
println!("Jitter:   {}ms",   obf.jitter_ms());
```

### Obfuscation Mode Reference

| Mode | What it looks like | Overhead | Use case |
|------|-------------------|----------|----------|
| `None` | Raw VCL | 0% | Trusted networks |
| `Padding` | Random size | ~5% | Basic protection |
| `SizeNormalization` | Common HTTPS sizes | ~10% | Size fingerprinting |
| `TlsMimicry` | TLS 1.3 HTTPS | ~3% | Home/ISP blocks |
| `Http2Mimicry` | HTTP/2 DATA | ~6% | Corporate firewalls |
| `Full` | TLS + normalized + jitter | ~15% | МТС/Beeline DPI |

---

## TUN Interface 🖥️

Capture and inject IP packets from the OS network stack. **Linux only, requires root or `CAP_NET_ADMIN`.**

```rust
use vcl_protocol::tun_device::{VCLTun, TunConfig};
use vcl_protocol::ip_packet::{parse_ip_packet, ParsedPacket};

#[tokio::main]
async fn main() {
    let config = TunConfig {
        name: "vcl0".to_string(),
        address: "10.0.0.1".parse().unwrap(),
        destination: "10.0.0.2".parse().unwrap(),
        netmask: "255.255.255.0".parse().unwrap(),
        mtu: 1420,
    };

    let mut tun = VCLTun::create(config).unwrap();

    loop {
        let raw = tun.read_packet().await.unwrap();
        let packet = parse_ip_packet(raw).unwrap();
        println!("{}", packet.summary());
        // encrypt and forward via VCLConnection...
    }
}
```

---

## IP Packet Parser 📦

```rust
use vcl_protocol::ip_packet::{ParsedPacket, TransportProtocol};

let raw = vec![/* raw IP packet bytes */];
let pkt = ParsedPacket::parse(raw).unwrap();

println!("{}",   pkt.summary());       // "TCP 192.168.1.1:80 → 10.0.0.1:8080 SYN (40 bytes)"
println!("{}",   pkt.src_ip);
println!("{}",   pkt.dst_ip);
println!("{}",   pkt.ttl);
println!("{}",   pkt.is_dns());        // UDP dst port 53?
println!("{}",   pkt.is_ping());       // ICMP echo request?

if let TransportProtocol::Tcp { src_port, dst_port, syn, .. } = &pkt.transport {
    println!("TCP {}→{} syn={}", src_port, dst_port, syn);
}
```

---

## Multipath 🔀

Send traffic across multiple interfaces simultaneously.

```rust
use vcl_protocol::multipath::{MultipathSender, MultipathReceiver, PathInfo, SchedulingPolicy};

// Define paths
let paths = vec![
    PathInfo::new("wifi",     "192.168.1.100", 100, 10),  // 100Mbps, 10ms
    PathInfo::new("lte",      "10.0.0.50",      50, 30),  // 50Mbps, 30ms
    PathInfo::new("ethernet", "172.16.0.1",    200,  5),  // 200Mbps, 5ms
];

let mut sender = MultipathSender::new(paths, SchedulingPolicy::WeightedRoundRobin);
let mut receiver = MultipathReceiver::new();

// Send — select best path
if let Some(idx) = sender.select_path_index(data.len()) {
    let path = sender.path(idx).unwrap();
    println!("Sending via {}", path.local_addr);
    // connect to peer via path.local_addr and send
}

// Redundant mode — send on ALL paths
let all_paths = sender.select_all_paths();

// Receive — reorder buffer
let result = receiver.add(seq, "wifi", data);
if let Some((path_id, payload)) = result {
    // in-order delivery
    let drained = receiver.drain_ordered(); // get any buffered packets
}

// Deactivate a failed path
sender.deactivate_path(1);
sender.activate_path(1); // when it comes back

// Stats
println!("Loss rate wifi: {:.2}%", sender.path(0).unwrap().loss_rate() * 100.0);
```

---

## MTU Negotiation 📐

```rust
use vcl_protocol::mtu::{MtuNegotiator, MtuConfig};

// Auto-detect for mobile (inside WireGuard tunnel)
let mut neg = MtuNegotiator::new(MtuConfig::inside_wireguard());

// Start probing
let mut probe_size = neg.start_discovery();

loop {
    // Send probe packet of probe_size bytes and check if it arrives
    let success = true; // result of your probe
    match neg.record_probe(probe_size, success) {
        Some(next) => probe_size = next,
        None       => break, // discovery complete
    }
}

println!("Path MTU:      {}", neg.current_mtu());
println!("fragment_size: {}", neg.recommended_fragment_size());

// Apply to config
// config.fragment_size = neg.recommended_fragment_size();
```

---

## Keepalive 💓

Keep NAT entries alive — especially important on mobile networks.

```rust
use vcl_protocol::keepalive::{KeepaliveManager, KeepalivePreset, KeepaliveAction};

// Mobile preset: 20s interval, max 3 missed pongs
let mut keepalive = KeepaliveManager::from_preset(KeepalivePreset::Mobile);

loop {
    match keepalive.check() {
        KeepaliveAction::SendPing => {
            keepalive.record_keepalive_sent();
            // conn.ping().await?;
        }
        KeepaliveAction::PongTimeout => {
            keepalive.record_pong_missed();
        }
        KeepaliveAction::ConnectionDead => {
            println!("Connection dead — reconnecting");
            break;
        }
        KeepaliveAction::Idle => {}
    }
    // Record activity when data is received
    // keepalive.record_activity();
    // keepalive.record_pong_received(); // when pong arrives

    // tokio::time::sleep(Duration::from_secs(1)).await;
}
```

### Keepalive Preset Reference

| Preset | Interval | Timeout | Max missed | Network |
|--------|----------|---------|------------|---------|
| `Mobile` | 20s | 5s | 3 | МТС/Beeline/МегаФон |
| `Home` | 60s | 10s | 3 | Home broadband |
| `Corporate` | 120s | 15s | 2 | Office firewall |
| `DataCenter` | 30s | 10s | 5 | Server-to-server |
| `Disabled` | — | — | — | No keepalive |

---

## Automatic Reconnect 🔄

```rust
use vcl_protocol::reconnect::{ReconnectManager, ReconnectConfig, ReconnectState};

// Mobile preset: fast retry, no max attempts
let mut reconnect = ReconnectManager::mobile();

// Connection dropped
reconnect.on_disconnect();

loop {
    if reconnect.should_reconnect() {
        reconnect.on_attempt_start();
        let success = true; // result of reconnect attempt

        if success {
            reconnect.on_connect();
            println!("Reconnected after {} attempts", reconnect.attempts());
            break;
        } else {
            reconnect.on_failure();
            if reconnect.is_giving_up() {
                println!("Gave up after {} attempts", reconnect.attempts());
                break;
            }
            println!("Next retry in {:?}", reconnect.time_until_reconnect());
        }
    }

    // Check if stable connection (resets backoff counter)
    reconnect.check_stability();

    // tokio::time::sleep(Duration::from_secs(1)).await;
}
```

---

## DNS Leak Protection 🛡️

```rust
use vcl_protocol::dns::{DnsFilter, DnsConfig, DnsAction, DnsQueryType, DnsFilter};

let config = DnsConfig::cloudflare()              // upstream: 1.1.1.1
    .with_blocked_domain("ads.com")               // block ads
    .with_blocked_domain("tracking.io")
    .with_split_domain("corp.internal");           // corp stays local

let mut filter = DnsFilter::new(config);

// When you receive a UDP packet on port 53:
if DnsFilter::is_dns_packet(&udp_payload) {
    let domain = "ads.com";
    match filter.decide(domain, &DnsQueryType::A) {
        DnsAction::Block               => { /* return NXDOMAIN */ }
        DnsAction::ForwardThroughTunnel => {
            // forward to filter.primary_upstream() via VCL tunnel
        }
        DnsAction::AllowDirect         => { /* use OS resolver */ }
        DnsAction::ReturnCached(addr)  => { /* return cached addr */ }
    }
    // After getting response, cache it:
    filter.cache_response(domain, addr);
}

// Stats
println!("Intercepted: {}", filter.total_intercepted());
println!("Blocked:     {}", filter.total_blocked());
println!("Cache hits:  {}", filter.total_cache_hits());
```

---

## Config Presets ⚙️

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

    // Auto mode (default)
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

```rust
use vcl_protocol::transport::VCLTransport;

#[tokio::main]
async fn main() {
    let listener = VCLTransport::bind_ws("127.0.0.1:8080").await.unwrap();
    let mut server_conn = listener.accept().await.unwrap();

    let mut client = VCLTransport::connect_ws("ws://127.0.0.1:8080").await.unwrap();

    client.send_raw(b"hello from browser").await.unwrap();
    let (data, _) = server_conn.recv_raw().await.unwrap();
    println!("{}", String::from_utf8_lossy(&data));
}
```

---

## Retransmission & Congestion Control 📉

```rust
use vcl_protocol::flow::FlowController;

let mut fc = FlowController::new(64);
fc.on_send(0, b"important data".to_vec());

let requests = fc.timed_out_packets();
for req in requests {
    println!("Retransmit seq={} attempt={}", req.sequence, req.retransmit_count);
}

println!("cwnd: {:.1}", fc.cwnd());
println!("in slow start: {}", fc.in_slow_start());
println!("total retransmits: {}", fc.total_retransmits());
```

---

## Metrics API 📊

```rust
use vcl_protocol::metrics::VCLMetrics;
use std::time::Duration;

let mut m = VCLMetrics::new();
m.record_sent(1024);
m.record_received(512);
m.record_retransmit();
m.record_rtt_sample(Duration::from_millis(42));
m.record_cwnd(32);

println!("Loss rate:  {:.2}%", m.loss_rate() * 100.0);
println!("Avg RTT:    {:?}", m.avg_rtt());
println!("Throughput: {:.0} B/s", m.throughput_sent_bps());
println!("Dropped:    {}", m.total_dropped());

// Pool aggregation
let mut pool_metrics = VCLMetrics::new();
pool_metrics.merge(&m);
```

---

## Fragmentation 🧩

```rust
let large_data = vec![0u8; 50_000];
client.send(&large_data).await.unwrap();

let packet = server.recv().await.unwrap();
assert_eq!(packet.payload.len(), 50_000);
```

---

## Flow Control 🌊

```rust
let conn = VCLConnection::bind("127.0.0.1:0").await.unwrap();

println!("Can send:  {}", conn.flow().can_send());
println!("In flight: {}", conn.flow().in_flight_count());
println!("cwnd:      {:.1}", conn.flow().cwnd());
println!("Loss:      {:.2}%", conn.flow().loss_rate() * 100.0);

if let Some(rtt) = conn.flow().srtt() {
    println!("SRTT: {:?}", rtt);
}

conn.ack_packet(sequence_number);
```

---

## Transport Abstraction 🔌

```rust
use vcl_protocol::transport::VCLTransport;
use vcl_protocol::config::VCLConfig;

let udp       = VCLTransport::bind_udp("127.0.0.1:0").await.unwrap();
let tcp_srv   = VCLTransport::bind_tcp("127.0.0.1:8080").await.unwrap();
let tcp_conn  = tcp_srv.accept().await.unwrap();
let tcp_cli   = VCLTransport::connect_tcp("127.0.0.1:8080").await.unwrap();
let ws_srv    = VCLTransport::bind_ws("127.0.0.1:8081").await.unwrap();
let ws_conn   = ws_srv.accept().await.unwrap();
let ws_cli    = VCLTransport::connect_ws("ws://127.0.0.1:8081").await.unwrap();
let from_cfg  = VCLTransport::from_config_server("127.0.0.1:0", &VCLConfig::vpn()).await.unwrap();
```

---

## Connection Pool 🏊

```rust
use vcl_protocol::VCLPool;

let mut pool = VCLPool::new(10);
let id1 = pool.bind("127.0.0.1:0").await.unwrap();
let id2 = pool.bind("127.0.0.1:0").await.unwrap();

pool.connect(id1, "127.0.0.1:8080").await.unwrap();
pool.send(id1, b"Hello!").await.unwrap();

let packet = pool.recv(id1).await.unwrap();
println!("Active: {} / Full: {}", pool.len(), pool.is_full());

pool.close(id1).unwrap();
pool.close_all();
```

---

## Logging 📝

```rust
tracing_subscriber::fmt::init();
```

Log levels:
- `INFO` — handshake, open/close, key rotation, MTU found, reconnect success
- `DEBUG` — packet send/receive, fragments, flow window, AIMD changes, DNS cache
- `WARN` — replay attacks, chain failures, timeouts, retransmits, pong missed, DNS blocked
- `ERROR` — operations on closed connections

---

## Connection Events 📡

```rust
use vcl_protocol::{connection::VCLConnection, VCLEvent};

let mut conn = VCLConnection::bind("127.0.0.1:0").await.unwrap();
let mut events = conn.subscribe();

tokio::spawn(async move {
    while let Some(event) = events.recv().await {
        match event {
            VCLEvent::Connected                => println!("Handshake complete"),
            VCLEvent::Disconnected             => println!("Connection closed"),
            VCLEvent::PacketReceived { sequence, size } => println!("#{} ({} bytes)", sequence, size),
            VCLEvent::PingReceived             => println!("Ping — pong sent"),
            VCLEvent::PongReceived { latency } => println!("RTT: {:?}", latency),
            VCLEvent::KeyRotated               => println!("Keys rotated"),
            VCLEvent::Error(msg)               => eprintln!("Error: {}", msg),
        }
    }
});

conn.connect("127.0.0.1:8080").await.unwrap();
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
| `IoError(msg)` | Socket, WebSocket, TUN, or address error |

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

### 8. Traffic Obfuscation (v1.0.0)
- TLS 1.3 record format mimicry
- HTTP/2 DATA frame mimicry
- Size normalization to common HTTPS sizes
- Timing jitter to defeat timing analysis

### 9. DNS Protection (v1.0.0)
- All DNS routed through VCL tunnel
- Blocklist prevents ad/tracking DNS leaks
- Split DNS for local corporate domains

---

## Testing 🧪

```bash
cargo test                         # All 257 tests
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
│   ├── metrics.rs       # VCLMetrics
│   ├── tun_device.rs    # VCLTun — TUN interface (Linux)
│   ├── ip_packet.rs     # IP/TCP/UDP/ICMP parser
│   ├── multipath.rs     # MultipathSender + MultipathReceiver
│   ├── mtu.rs           # MtuNegotiator
│   ├── keepalive.rs     # KeepaliveManager
│   ├── reconnect.rs     # ReconnectManager
│   ├── dns.rs           # DnsFilter + DnsConfig
│   └── obfuscation.rs   # Obfuscator + ObfuscationMode
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

### v1.0.0 (Current) 🎉
- **TUN Interface** — `VCLTun` for IP packet capture (Linux, `CAP_NET_ADMIN`)
- **IP Parser** — full IPv4/IPv6/TCP/UDP/ICMP parsing via `etherparse`
- **Multipath** — `MultipathSender` + `MultipathReceiver` with 5 scheduling policies
- **MTU Negotiation** — binary search path MTU discovery
- **Keepalive** — NAT keepalive with Mobile/Home/Corporate presets
- **Reconnect** — exponential backoff with jitter and stability detection
- **DNS Protection** — `DnsFilter` with blocklist, split DNS, response cache
- **Traffic Obfuscation** — TLS mimicry, HTTP/2 mimicry, size normalization
- **257/257 tests passing**

### v0.5.0 ✅
- WebSocket Transport
- Congestion Control (AIMD)
- Retransmission with exponential RTO backoff
- RFC 6298 RTT estimation
- Metrics API (`VCLMetrics`)
- 113/113 tests passing

### v0.4.0 ✅
- TCP/UDP Transport Abstraction
- Packet Fragmentation
- Flow Control (sliding window)
- Config Presets
- 89/89 tests passing

### v0.3.0 ✅
- Connection Pool, Tracing, Benchmarks, docs.rs
- 33/33 tests passing

### v0.2.0 ✅
- Connection Events, Ping/Heartbeat, Key Rotation, Custom Errors
- 29/29 tests passing

### v0.1.0 ✅
- Cryptographic chain, Ed25519, X25519, XChaCha20-Poly1305
- Replay protection, Session management
- 17/17 tests passing

---

<div align="center">

**Made with ❤️ using Rust**

*Secure • Chained • Verified • Production Ready*

</div>
