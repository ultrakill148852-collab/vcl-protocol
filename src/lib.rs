//! # VCL Protocol
//!
//! Cryptographically chained packet transport protocol with:
//! - SHA-256 integrity chain
//! - Ed25519 digital signatures
//! - X25519 ephemeral key exchange
//! - XChaCha20-Poly1305 authenticated encryption
//! - Replay protection
//! - Connection events, ping/heartbeat, mid-session key rotation
//! - Connection pool for managing multiple peers
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
pub mod pool;
pub mod config;
pub mod transport;
pub mod fragment;
pub mod flow;
pub mod metrics;
pub mod tun_device;
pub mod ip_packet;
pub mod multipath;
pub mod mtu;
pub mod keepalive;
pub mod reconnect;
pub mod dns;

pub use error::VCLError;
pub use event::VCLEvent;
pub use pool::VCLPool;
pub use config::VCLConfig;
pub use transport::VCLTransport;
pub use fragment::{Fragmenter, Reassembler, Fragment};
pub use flow::FlowController;
pub use metrics::VCLMetrics;
pub use tun_device::{VCLTun, TunConfig, IpPacket, IpVersion};
pub use ip_packet::{ParsedPacket, TransportProtocol};
pub use multipath::{MultipathSender, MultipathReceiver, PathInfo, SchedulingPolicy};
pub use mtu::{MtuNegotiator, MtuConfig, PathMtu, MtuState};
pub use keepalive::{KeepaliveManager, KeepaliveConfig, KeepaliveAction, KeepalivePreset};
pub use reconnect::{ReconnectManager, ReconnectConfig, ReconnectState};
pub use dns::{DnsFilter, DnsConfig, DnsAction, DnsPacket};
