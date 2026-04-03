//! # VCL Transport Abstraction
//!
//! Provides a unified [`VCLTransport`] enum that abstracts over TCP and UDP sockets.
//! This allows [`VCLConnection`] to work with either transport transparently.
//!
//! ## Example
//!
//! ```no_run
//! use vcl_protocol::transport::VCLTransport;
//!
//! #[tokio::main]
//! async fn main() {
//!     // UDP transport
//!     let udp = VCLTransport::bind_udp("127.0.0.1:8080").await.unwrap();
//!
//!     // TCP transport (server)
//!     let tcp = VCLTransport::bind_tcp("127.0.0.1:8081").await.unwrap();
//! }
//! ```
//!
//! [`VCLConnection`]: crate::connection::VCLConnection

use crate::error::VCLError;
use crate::config::{TransportMode, VCLConfig};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use tracing::{debug, info};

/// Maximum size of a single UDP datagram.
const UDP_MAX_SIZE: usize = 65535;

/// 4-byte length prefix for TCP framing (big-endian u32).
const TCP_HEADER_SIZE: usize = 4;

/// Unified transport layer for VCL Protocol.
///
/// Abstracts over TCP and UDP sockets so that higher-level code
/// (connection, pool, etc.) does not need to care about the underlying protocol.
///
/// - **UDP** — low latency, no connection state, best for gaming/streaming
/// - **TCP** — reliable, ordered, best for VPN/file transfer
pub enum VCLTransport {
    /// UDP transport backed by [`tokio::net::UdpSocket`].
    Udp {
        socket: UdpSocket,
        peer_addr: Option<SocketAddr>,
    },
    /// TCP transport backed by [`tokio::net::TcpStream`].
    Tcp {
        stream: TcpStream,
        peer_addr: SocketAddr,
    },
    /// TCP listener — server side, waiting for incoming connections.
    /// Call [`VCLTransport::accept`] to get a connected [`VCLTransport::Tcp`].
    TcpListener {
        listener: TcpListener,
        local_addr: SocketAddr,
    },
}

impl VCLTransport {
    // ─── Constructors ─────────────────────────────────────────────────────────

    /// Bind a UDP socket to a local address.
    ///
    /// Use `"127.0.0.1:0"` to let the OS assign a port.
    ///
    /// # Errors
    /// Returns [`VCLError::IoError`] if the socket cannot be bound.
    pub async fn bind_udp(addr: &str) -> Result<Self, VCLError> {
        let socket = UdpSocket::bind(addr).await?;
        let local = socket.local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| addr.to_string());
        info!(addr = %local, "UDP transport bound");
        Ok(VCLTransport::Udp {
            socket,
            peer_addr: None,
        })
    }

    /// Bind a TCP listener to a local address (server side).
    ///
    /// Call [`accept()`](VCLTransport::accept) to wait for an incoming connection.
    ///
    /// # Errors
    /// Returns [`VCLError::IoError`] if the listener cannot be bound.
    pub async fn bind_tcp(addr: &str) -> Result<Self, VCLError> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        info!(addr = %local_addr, "TCP transport bound");
        Ok(VCLTransport::TcpListener { listener, local_addr })
    }

    /// Connect a TCP stream to a remote address (client side).
    ///
    /// # Errors
    /// Returns [`VCLError::IoError`] if the connection fails.
    pub async fn connect_tcp(addr: &str) -> Result<Self, VCLError> {
        let parsed: SocketAddr = addr.parse()?;
        let stream = TcpStream::connect(parsed).await?;
        let peer_addr = stream.peer_addr()?;
        info!(peer = %peer_addr, "TCP transport connected");
        Ok(VCLTransport::Tcp { stream, peer_addr })
    }

    /// Accept an incoming TCP connection (server side).
    ///
    /// Only valid on [`VCLTransport::TcpListener`].
    ///
    /// # Errors
    /// Returns [`VCLError::IoError`] if accept fails.
    /// Returns [`VCLError::InvalidPacket`] if called on a non-listener transport.
    pub async fn accept(&self) -> Result<Self, VCLError> {
        match self {
            VCLTransport::TcpListener { listener, .. } => {
                let (stream, peer_addr) = listener.accept().await?;
                info!(peer = %peer_addr, "TCP connection accepted");
                Ok(VCLTransport::Tcp { stream, peer_addr })
            }
            _ => Err(VCLError::InvalidPacket(
                "accept() called on non-listener transport".to_string(),
            )),
        }
    }

    /// Create the appropriate transport from a [`VCLConfig`] for a client.
    ///
    /// - `Tcp` or `Auto`+`Reliable` → TCP
    /// - `Udp` or others → UDP
    pub async fn from_config_client(
        local_addr: &str,
        peer_addr: &str,
        config: &VCLConfig,
    ) -> Result<Self, VCLError> {
        if config.is_tcp() {
            info!("Config selected TCP transport (client)");
            VCLTransport::connect_tcp(peer_addr).await
        } else {
            info!("Config selected UDP transport (client)");
            let t = VCLTransport::bind_udp(local_addr).await?;
            Ok(t)
        }
    }

    /// Create the appropriate transport from a [`VCLConfig`] for a server.
    pub async fn from_config_server(
        local_addr: &str,
        config: &VCLConfig,
    ) -> Result<Self, VCLError> {
        if config.is_tcp() {
            info!("Config selected TCP transport (server)");
            VCLTransport::bind_tcp(local_addr).await
        } else {
            info!("Config selected UDP transport (server)");
            VCLTransport::bind_udp(local_addr).await
        }
    }

    // ─── Send / Recv ──────────────────────────────────────────────────────────

    /// Send raw bytes to the peer.
    ///
    /// - UDP: sends a single datagram to `peer_addr`
    /// - TCP: sends with a 4-byte length prefix (framing)
    ///
    /// # Errors
    /// Returns [`VCLError::IoError`] on socket error.
    /// Returns [`VCLError::NoPeerAddress`] if UDP peer address is not set.
    pub async fn send_raw(&mut self, data: &[u8]) -> Result<(), VCLError> {
        match self {
            VCLTransport::Udp { socket, peer_addr } => {
                let addr = peer_addr.ok_or(VCLError::NoPeerAddress)?;
                socket.send_to(data, addr).await?;
                debug!(peer = %addr, size = data.len(), "UDP send");
                Ok(())
            }
            VCLTransport::Tcp { stream, peer_addr } => {
                // TCP framing: 4-byte big-endian length prefix + data
                let len = data.len() as u32;
                let mut frame = Vec::with_capacity(TCP_HEADER_SIZE + data.len());
                frame.extend_from_slice(&len.to_be_bytes());
                frame.extend_from_slice(data);
                stream.write_all(&frame).await?;
                debug!(peer = %peer_addr, size = data.len(), "TCP send");
                Ok(())
            }
            VCLTransport::TcpListener { .. } => Err(VCLError::InvalidPacket(
                "send_raw() called on TcpListener — call accept() first".to_string(),
            )),
        }
    }

    /// Receive raw bytes from the peer.
    ///
    /// - UDP: receives a single datagram, sets peer address on first receive
    /// - TCP: reads framed message (4-byte length prefix + data)
    ///
    /// Returns `(data, sender_addr)`.
    ///
    /// # Errors
    /// Returns [`VCLError::IoError`] on socket error.
    /// Returns [`VCLError::InvalidPacket`] if TCP frame is malformed.
    pub async fn recv_raw(&mut self) -> Result<(Vec<u8>, SocketAddr), VCLError> {
        match self {
            VCLTransport::Udp { socket, peer_addr } => {
                let mut buf = vec![0u8; UDP_MAX_SIZE];
                let (len, addr) = socket.recv_from(&mut buf).await?;
                buf.truncate(len);
                if peer_addr.is_none
