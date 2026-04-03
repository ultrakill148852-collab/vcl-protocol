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
                if peer_addr.is_none() {
                    *peer_addr = Some(addr);
                }
                debug!(peer = %addr, size = len, "UDP recv");
                Ok((buf, addr))
            }
            VCLTransport::Tcp { stream, peer_addr } => {
                // Read 4-byte length prefix
                let mut header = [0u8; TCP_HEADER_SIZE];
                stream.read_exact(&mut header).await
                    .map_err(|e| VCLError::IoError(format!("TCP read header: {}", e)))?;

                let msg_len = u32::from_be_bytes(header) as usize;
                if msg_len == 0 || msg_len > UDP_MAX_SIZE {
                    return Err(VCLError::InvalidPacket(format!(
                        "TCP frame length out of range: {}",
                        msg_len
                    )));
                }

                // Read payload
                let mut buf = vec![0u8; msg_len];
                stream.read_exact(&mut buf).await
                    .map_err(|e| VCLError::IoError(format!("TCP read body: {}", e)))?;

                debug!(peer = %peer_addr, size = msg_len, "TCP recv");
                Ok((buf, *peer_addr))
            }
            VCLTransport::TcpListener { .. } => Err(VCLError::InvalidPacket(
                "recv_raw() called on TcpListener — call accept() first".to_string(),
            )),
        }
    }

    // ─── Info ─────────────────────────────────────────────────────────────────

    /// Returns the local address this transport is bound to.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            VCLTransport::Udp { socket, .. } => socket.local_addr().ok(),
            VCLTransport::Tcp { stream, .. } => stream.local_addr().ok(),
            VCLTransport::TcpListener { local_addr, .. } => Some(*local_addr),
        }
    }

    /// Returns the remote peer address if known.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            VCLTransport::Udp { peer_addr, .. } => *peer_addr,
            VCLTransport::Tcp { peer_addr, .. } => Some(*peer_addr),
            VCLTransport::TcpListener { .. } => None,
        }
    }

    /// Set the peer address for UDP transport.
    ///
    /// Has no effect on TCP (peer address is fixed at connect time).
    pub fn set_peer_addr(&mut self, addr: SocketAddr) {
        if let VCLTransport::Udp { peer_addr, .. } = self {
            *peer_addr = Some(addr);
        }
    }

    /// Returns the [`TransportMode`] of this transport.
    pub fn mode(&self) -> TransportMode {
        match self {
            VCLTransport::Udp { .. } => TransportMode::Udp,
            VCLTransport::Tcp { .. } | VCLTransport::TcpListener { .. } => TransportMode::Tcp,
        }
    }

    /// Returns `true` if this is a TCP transport.
    pub fn is_tcp(&self) -> bool {
        self.mode() == TransportMode::Tcp
    }

    /// Returns `true` if this is a UDP transport.
    pub fn is_udp(&self) -> bool {
        self.mode() == TransportMode::Udp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_bind() {
        let t = VCLTransport::bind_udp("127.0.0.1:0").await.unwrap();
        assert!(t.is_udp());
        assert!(!t.is_tcp());
        assert!(t.local_addr().is_some());
        assert!(t.peer_addr().is_none());
    }

    #[tokio::test]
    async fn test_tcp_bind() {
        let t = VCLTransport::bind_tcp("127.0.0.1:0").await.unwrap();
        assert!(t.is_tcp());
        assert!(!t.is_udp());
        assert!(t.local_addr().is_some());
    }

    #[tokio::test]
    async fn test_udp_send_recv() {
        let mut server = VCLTransport::bind_udp("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut client = VCLTransport::bind_udp("127.0.0.1:0").await.unwrap();
        client.set_peer_addr(server_addr);

        client.send_raw(b"hello vcl").await.unwrap();
        let (data, _) = server.recv_raw().await.unwrap();
        assert_eq!(data, b"hello vcl");
    }

    #[tokio::test]
    async fn test_tcp_send_recv() {
        let server_listener = VCLTransport::bind_tcp("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();

        let (server_result, client_result) = tokio::join!(
            server_listener.accept(),
            VCLTransport::connect_tcp(&server_addr.to_string()),
        );

        let mut server_conn = server_result.unwrap();
        let mut client_conn = client_result.unwrap();

        client_conn.send_raw(b"hello tcp vcl").await.unwrap();
        let (data, _) = server_conn.recv_raw().await.unwrap();
        assert_eq!(data, b"hello tcp vcl");
    }

    #[tokio::test]
    async fn test_tcp_multiple_messages() {
        let server_listener = VCLTransport::bind_tcp("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();

        let (server_result, client_result) = tokio::join!(
            server_listener.accept(),
            VCLTransport::connect_tcp(&server_addr.to_string()),
        );

        let mut server_conn = server_result.unwrap();
        let mut client_conn = client_result.unwrap();

        for i in 0..5u8 {
            let msg = vec![i; 100];
            client_conn.send_raw(&msg).await.unwrap();
            let (data, _) = server_conn.recv_raw().await.unwrap();
            assert_eq!(data, msg);
        }
    }

    #[tokio::test]
    async fn test_from_config_udp() {
        let config = VCLConfig::gaming();
        let t = VCLTransport::from_config_server("127.0.0.1:0", &config).await.unwrap();
        assert!(t.is_udp());
    }

    #[tokio::test]
    async fn test_from_config_tcp() {
        let config = VCLConfig::vpn();
        let t = VCLTransport::from_config_server("127.0.0.1:0", &config).await.unwrap();
        assert!(t.is_tcp());
    }

    #[tokio::test]
    async fn test_mode() {
        let udp = VCLTransport::bind_udp("127.0.0.1:0").await.unwrap();
        assert_eq!(udp.mode(), TransportMode::Udp);

        let tcp = VCLTransport::bind_tcp("127.0.0.1:0").await.unwrap();
        assert_eq!(tcp.mode(), TransportMode::Tcp);
    }
}
