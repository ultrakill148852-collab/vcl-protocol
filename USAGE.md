# VCL Protocol — Usage Guide

## 📖 Overview

VCL Protocol is a cryptographically chained packet transport protocol. It ensures data integrity through SHA-256 hashing and authenticates packets using Ed25519 signatures.

**Key Features:**

- Immutable packet chain (each packet links to previous)
- X25519 handshake (no pre-shared keys needed)
- Ed25519 signatures
- UDP transport with Tokio async

---

## 🚀 Installation

### Add to Cargo.toml

    [dependencies]
    vcl-protocol = { git = "https://github.com/ultrakill148852-collab/vcl-protocol.git" }
    tokio = { version = "1", features = ["full"] }

### Or clone manually

    git clone https://github.com/ultrakill148852-collab/vcl-protocol.git
    cd vcl-protocol
    cargo build

---

## 📝 Quick Start

### Server Example

    use vcl_protocol::connection::VCLConnection;

    #[tokio::main]
    async fn main() {
        // Bind to port 8080
        let mut server = VCLConnection::bind("127.0.0.1:8080").await.unwrap();
        println!("Server started on 127.0.0.1:8080");

        // Accept handshake from client
        server.accept_handshake().await.unwrap();
        println!("Client connected!");

        // Receive messages
        loop {
            match server.recv().await {
                Ok(packet) => {
                    println!("Received: {}", String::from_utf8_lossy(&packet.payload));
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
    }

### Client Example

    use vcl_protocol::connection::VCLConnection;

    #[tokio::main]
    async fn main() {
        // Bind to random port
        let mut client = VCLConnection::bind("127.0.0.1:0").await.unwrap();

        // Connect to server (includes handshake)
        client.connect("127.0.0.1:8080").await.unwrap();
        println!("Connected to server!");

        // Send messages
        for i in 1..=5 {
            let msg = format!("Message {}", i);
            client.send(msg.as_bytes()).await.unwrap();
            println!("Sent: {}", msg);
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

---

## 🔧 API Reference

### VCLConnection

Main struct for managing connections.

| Method | Description |
|--------|-------------|
| bind(addr: &str) | Create a new connection bound to local address |
| connect(addr: &str) | Connect to remote peer (includes handshake) |
| accept_handshake() | Accept incoming connection (server side) |
| send(&[u8]) | Send encrypted signed packet |
| recv() | Receive and validate packet |
| get_public_key() | Get local public key |
| get_shared_secret() | Get handshake shared secret |

### VCLPacket

Represents a single packet in the chain.

| Field | Type | Description |
|-------|------|-------------|
| version | u8 | Protocol version |
| sequence | u64 | Packet sequence number |
| prev_hash | Vec<u8> | Hash of previous packet |
| payload | Vec<u8> | Data payload |
| signature | Vec<u8> | Ed25519 signature |

---

## 🔐 Security Model

### 1. Handshake (X25519)

- Ephemeral key exchange
- No pre-shared keys required
- Forward secrecy

### 2. Chain Integrity (SHA-256)

- Each packet contains hash of previous packet
- Tampering breaks the chain
- Validated on every recv()

### 3. Authentication (Ed25519)

- Every packet is signed
- Signature verified on receive
- Prevents spoofing

---

## ⚙️ Configuration

Currently configured via code. Future versions will support:

- Config files (TOML/YAML)
- Environment variables
- Key management systems

---

## 🧪 Testing

    # Run tests
    cargo test

    # Run with output
    cargo test -- --nocapture

    # Build release
    cargo build --release

---

## 📦 Project Structure

    vcl-protocol/
    ├── src/
    │   ├── main.rs          # Demo application
    │   ├── connection.rs    # High-level connection API
    │   ├── packet.rs        # Packet structure & validation
    │   ├── crypto.rs        # Key generation & helpers
    │   └── handshake.rs     # X25519 handshake protocol
    ├── Cargo.toml
    ├── README.md
    └── USAGE.md             # This file

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests (cargo test)
5. Submit a pull request

---

## 📄 License

MIT License — see LICENSE for details.

---

## 📬 Support

- Issues: https://github.com/ultrakill148852-collab/vcl-protocol/issues
- Discussions: https://github.com/ultrakill148852-collab/vcl-protocol/discussions
