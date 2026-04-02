//! # VCL Protocol
//!
//! Cryptographically chained packet transport protocol with:
//! - SHA-256 integrity chain
//! - Ed25519 digital signatures
//! - X25519 ephemeral key exchange
//! - XChaCha20-Poly1305 authenticated encryption
//! - Replay protection
//! - Connection events, ping/heartbeat, mid-session key rotation
//!
//! ## Quick Start
//!
//! ```no_run
//! use vcl_protocol::connection::VCLConnection;
//!
//! #[tokio::main]
//! async fn main() {
//!     let mut server = VCLConnection::bind("127.0.0.1:8080").await.unwrap();
//!     server.accept_handshake().await.unwrap();
//!
//!     let packet = server.recv().await.unwrap();
//!     println!("Received: {}", String::from_utf8_lossy(&packet.payload));
//! }
//! ```

pub mod error;
pub mod event;
pub mod packet;
pub mod crypto;
pub mod connection;
pub mod handshake;

pub use error::VCLError;
pub use event::VCLEvent;
