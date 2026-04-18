
//! # VCL Transport Abstraction
//!
//! Provides a unified [`VCLTransport`] enum that abstracts over TCP, UDP, WebSocket, and QUIC.
//! This allows [`VCLConnection`] to work with any transport transparently.
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
//!
//!     // WebSocket transport (server)
//!     let ws = VCLTransport::bind_ws("127.0.0.1:8082").await.unwrap();
//!
//!     // QUIC transport (server) - Requires "quic" feature
//!     #[cfg(feature = "quic")]
//!     let quic = VCLTransport::bind_quic("127.0.0.1:8083").await.unwrap();
//! }
//! ```
//!
//! [`VCLConnection`]: crate::connection::VCLConnection

use crate::error::VCLError;
use crate::config::{TransportMode, VCLConfig};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{
    accept_async, connect_async,
    tungstenite::Message,
    WebSocketStream, MaybeTlsStream,
};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info};

// QUIC Dependencies
#[cfg(feature = "quic")]
use quinn::{Endpoint, Connection, RecvStream, SendStream, ServerConfig, ClientConfig};
#[cfg(feature = "quic")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
#[cfg(feature = "quic")]
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
#[cfg(feature = "quic")]
use rcgen::generate_simple_self_signed;

const UDP_MAX_SIZE: usize = 65535;
const TCP_HEADER_SIZE: usize = 4;

/// Unified transport layer for VCL Protocol.
///
/// Abstracts over UDP, TCP, WebSocket, and QUIC so that higher-level code
/// does not need to care about the underlying protocol.
///
/// - **UDP** — low latency, no connection state, best for gaming/streaming
/// - **TCP** — reliable, ordered, best for VPN/file transfer
/// - **WebSocket** — browser-compatible, works through HTTP proxies
/// - **QUIC** — 0-RTT reconnect, multiplexing, built-in congestion control (feature-gated)
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
    TcpListener {
        listener: TcpListener,
        local_addr: SocketAddr,
    },
    /// WebSocket client connection.
    WebSocketClient {
        stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
        peer_addr: String,
    },
    /// WebSocket server connection (accepted from a listener).
    WebSocketServer {
        stream: WebSocketStream<TcpStream>,
        peer_addr: SocketAddr,
    },
    /// WebSocket listener — server side, waiting for incoming WS connections.
    WebSocketListener {
        listener: TcpListener,
        local_addr: SocketAddr,
    },
    /// QUIC transport backed by [`quinn`] (requires `quic` feature).
    #[cfg(feature = "quic")]
    Quic {
        endpoint: Endpoint,
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
    },
    /// QUIC listener — server side, waiting for incoming QUIC connections (requires `quic` feature).
    #[cfg(feature = "quic")]
    QuicListener {
        endpoint: Endpoint,
        local_addr: SocketAddr,
    },
}

impl VCLTransport {
    // ─── Constructors ────────────────────────────────────────────────────────

    /// Bind a UDP socket to a local address.
    pub async fn bind_udp(addr: &str) -> Result<Self, VCLError> {
        let socket = UdpSocket::bind(addr).await?;
        let local = socket.local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| addr.to_string());
        info!(addr = %local, "UDP transport bound");
        Ok(VCLTransport::Udp { socket, peer_addr: None })
    }

    /// Bind a TCP listener to a local address (server side).
    pub async fn bind_tcp(addr: &str) -> Result<Self, VCLError> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        info!(addr = %local_addr, "TCP transport bound");
        Ok(VCLTransport::TcpListener { listener, local_addr })
    }

    /// Connect a TCP stream to a remote address (client side).
    pub async fn connect_tcp(addr: &str) -> Result<Self, VCLError> {
        let parsed: SocketAddr = addr.parse()?;
        let stream = TcpStream::connect(parsed).await?;
        let peer_addr = stream.peer_addr()?;
        info!(peer = %peer_addr, "TCP transport connected");
        Ok(VCLTransport::Tcp { stream, peer_addr })
    }

    /// Bind a WebSocket listener to a local address (server side).
    ///
    /// Call [`accept()`](VCLTransport::accept) to wait for an incoming WS connection.
    pub async fn bind_ws(addr: &str) -> Result<Self, VCLError> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        info!(addr = %local_addr, "WebSocket transport bound");
        Ok(VCLTransport::WebSocketListener { listener, local_addr })
    }

    /// Connect a WebSocket client to a remote URL.
    ///
    /// `url` should be in the form `ws://host:port/path` or `wss://host:port/path`.
    pub async fn connect_ws(url: &str) -> Result<Self, VCLError> {
        let peer_addr = url.to_string();
        let (stream, _response) = connect_async(url)
            .await
            .map_err(|e| VCLError::IoError(format!("WebSocket connect failed: {}", e)))?;
        info!(url = %url, "WebSocket transport connected");
        Ok(VCLTransport::WebSocketClient { stream, peer_addr })
    }

    /// Bind a QUIC endpoint to a local address (server side).
    ///
    /// Generates a self-signed certificate for TLS handshake.
    /// Returns a [`QuicListener`](VCLTransport::QuicListener) which must be passed to [`accept()`](VCLTransport::accept).
    /// Requires the `quic` feature to be enabled in `Cargo.toml`.
    ///
    /// # Example
    /// ```no_run
    /// #[cfg(feature = "quic")]
    /// # async fn example() {
    /// use vcl_protocol::transport::VCLTransport;
    /// let listener = VCLTransport::bind_quic("127.0.0.1:8083").await.unwrap();
    /// let server_conn = listener.accept().await.unwrap();
    /// # }
    /// ```
    #[cfg(feature = "quic")]
    pub async fn bind_quic(addr: &str) -> Result<Self, VCLError> {
        let bind_addr: SocketAddr = addr.parse()?;
        
        // Generate self-signed certificate
        let cert = generate_simple_self_signed(vec!["vcl.local".into()])
            .map_err(|e| VCLError::CryptoError(e.to_string()))?;
        let cert_der = CertificateDer::from(cert.cert.der().clone());
        let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der())
            .map_err(|e| VCLError::CryptoError(e.to_string()))?;

        let rustls_server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| VCLError::CryptoError(e.to_string()))?;

        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server_config)
            .map_err(|e| VCLError::CryptoError(e.to_string()))?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_uni_streams(0u8.into());
        server_config.transport_config(Arc::new(transport_config));

        let endpoint = Endpoint::server(server_config, bind_addr)
            .map_err(|e| VCLError::IoError(e.to_string()))?;

        info!(addr = %bind_addr, "QUIC transport bound (listener)");
        Ok(VCLTransport::QuicListener { endpoint, local_addr: bind_addr })
    }

    /// Connect a QUIC client to a remote address.
    ///
    /// Uses insecure certificate verification (skips CA check) for development.
    /// Requires the `quic` feature.
    #[cfg(feature = "quic")]
    pub async fn connect_quic(server_addr: &str) -> Result<Self, VCLError> {
        let addr: SocketAddr = server_addr.parse()?;
        let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));

        let rustls_client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client_config)
            .map_err(|e| VCLError::CryptoError(e.to_string()))?;

        let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_uni_streams(0u8.into());
        client_config.transport_config(Arc::new(transport_config));

        let endpoint = Endpoint::client(local_addr)
            .map_err(|e| VCLError::IoError(e.to_string()))?;

        let connecting = endpoint.connect(addr, "vcl.local")
            .map_err(|e| VCLError::IoError(e.to_string()))?;
        
        let conn = connecting.await
            .map_err(|e| VCLError::IoError(format!("QUIC connect failed: {}", e)))?;

        let (send, recv) = conn.open_bi().await
            .map_err(|e| VCLError::IoError(format!("QUIC stream open failed: {}", e)))?;

        info!(server = %server_addr, "QUIC transport connected");
        Ok(VCLTransport::Quic { endpoint, connection: conn, send, recv })
    }

    /// Accept an incoming connection (server side).
    ///
    /// Works for [`TcpListener`](VCLTransport::TcpListener),
    /// [`WebSocketListener`](VCLTransport::WebSocketListener), and
    /// [`QuicListener`](VCLTransport::QuicListener).
    pub async fn accept(&self) -> Result<Self, VCLError> {
        match self {
            VCLTransport::TcpListener { listener, .. } => {
                let (stream, peer_addr) = listener.accept().await?;
                info!(peer = %peer_addr, "TCP connection accepted");
                Ok(VCLTransport::Tcp { stream, peer_addr })
            }
            VCLTransport::WebSocketListener { listener, .. } => {
                let (tcp_stream, peer_addr) = listener.accept().await?;
                let ws_stream = accept_async(tcp_stream)
                    .await
                    .map_err(|e| VCLError::IoError(format!("WebSocket handshake failed: {}", e)))?;
                info!(peer = %peer_addr, "WebSocket connection accepted");
                Ok(VCLTransport::WebSocketServer { stream: ws_stream, peer_addr })
            }
            #[cfg(feature = "quic")]
            VCLTransport::QuicListener { endpoint, .. } => {
                let connecting = endpoint.accept().await
                    .ok_or_else(|| VCLError::IoError("QUIC endpoint closed".into()))?;
                
                let conn = connecting.await
                    .map_err(|e| VCLError::IoError(format!("QUIC connection failed: {}", e)))?;
                
                let (send, recv) = conn.open_bi().await
                    .map_err(|e| VCLError::IoError(format!("QUIC stream open failed: {}", e)))?;

                info!("QUIC connection accepted");
                Ok(VCLTransport::Quic { endpoint: endpoint.clone(), connection: conn, send, recv })
            }
            _ => Err(VCLError::InvalidPacket(
                "accept() called on non-listener transport".to_string(),
            )),
        }
    }

    /// Create the appropriate transport from a [`VCLConfig`] for a client.
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
            VCLTransport::bind_udp(local_addr).await
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

    // ─── Send / Recv ─────────────────────────────────────────────────────────

    /// Send raw bytes to the peer.
    ///
    /// - UDP: single datagram to `peer_addr`
    /// - TCP: 4-byte length prefix + data
    /// - WebSocket: binary message
    /// - QUIC: writes to bidirectional stream
    pub async fn send_raw(&mut self,  &[u8]) -> Result<(), VCLError> {
        match self {
            VCLTransport::Udp { socket, peer_addr } => {
                let addr = peer_addr.ok_or(VCLError::NoPeerAddress)?;
                socket.send_to(data, addr).await?;
                debug!(peer = %addr, size = data.len(), "UDP send");
                Ok(())
            }
            VCLTransport::Tcp { stream, peer_addr } => {
                let len = data.len() as u32;
                let mut frame = Vec::with_capacity(TCP_HEADER_SIZE + data.len());
                frame.extend_from_slice(&len.to_be_bytes());
                frame.extend_from_slice(data);
                stream.write_all(&frame).await?;
                debug!(peer = %peer_addr, size = data.len(), "TCP send");
                Ok(())
            }
            VCLTransport::WebSocketClient { stream, peer_addr } => {
                stream
                    .send(Message::Binary(data.to_vec()))
                    .await
                    .map_err(|e| VCLError::IoError(format!("WebSocket send failed: {}", e)))?;
                debug!(peer = %peer_addr, size = data.len(), "WebSocket client send");
                Ok(())
            }
            VCLTransport::WebSocketServer { stream, peer_addr } => {
                stream
                    .send(Message::Binary(data.to_vec()))
                    .await
                    .map_err(|e| VCLError::IoError(format!("WebSocket send failed: {}", e)))?;
                debug!(peer = %peer_addr, size = data.len(), "WebSocket server send");
                Ok(())
            }
            #[cfg(feature = "quic")]
            VCLTransport::Quic { send, .. } => {
                send.write_all(data).await
                    .map_err(|e| VCLError::IoError(format!("QUIC send failed: {}", e)))?;
                debug!(size = data.len(), "QUIC send");
                Ok(())
            }
            VCLTransport::TcpListener { .. } 
            | VCLTransport::WebSocketListener { .. } => {
                Err(VCLError::InvalidPacket(
                    "send_raw() called on listener — call accept() first".to_string(),
                ))
            }
            #[cfg(feature = "quic")]
            VCLTransport::QuicListener { .. } => {
                Err(VCLError::InvalidPacket(
                    "send_raw() called on listener — call accept() first".to_string(),
                ))
            }
        }
    }

    /// Receive raw bytes from the peer.
    ///
    /// - UDP: single datagram, sets peer address on first receive
    /// - TCP: reads framed message (4-byte length prefix + data)
    /// - WebSocket: reads next binary message (skips ping/pong/text frames)
    /// - QUIC: reads from bidirectional stream until EOF or error
    ///
    /// Returns `(data, sender_addr_string)`. For QUIC/WebSocket clients, address may be placeholder.
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
                let mut header = [0u8; TCP_HEADER_SIZE];
                stream.read_exact(&mut header).await
                    .map_err(|e| VCLError::IoError(format!("TCP read header: {}", e)))?;
                let msg_len = u32::from_be_bytes(header) as usize;
                if msg_len == 0 || msg_len > UDP_MAX_SIZE {
                    return Err(VCLError::InvalidPacket(format!(
                        "TCP frame length out of range: {}", msg_len
                    )));
                }
                let mut buf = vec![0u8; msg_len];
                stream.read_exact(&mut buf).await
                    .map_err(|e| VCLError::IoError(format!("TCP read body: {}", e)))?;
                debug!(peer = %peer_addr, size = msg_len, "TCP recv");
                Ok((buf, *peer_addr))
            }
            VCLTransport::WebSocketClient { stream, peer_addr } => {
                loop {
                    let msg = stream.next().await
                        .ok_or_else(|| VCLError::IoError("WebSocket stream closed".to_string()))?
                        .map_err(|e| VCLError::IoError(format!("WebSocket recv failed: {}", e)))?;
                    match msg {
                        Message::Binary(data) => {
                            let size = data.len();
                            debug!(peer = %peer_addr, size, "WebSocket client recv");
                            let placeholder: SocketAddr = "0.0.0.0:0".parse().unwrap();
                            return Ok((data, placeholder));
                        }
                        Message::Close(_) => {
                            return Err(VCLError::IoError("WebSocket connection closed".to_string()));
                        }
                        _ => continue,
                    }
                }
            }
            VCLTransport::WebSocketServer { stream, peer_addr } => {
                loop {
                    let msg = stream.next().await
                        .ok_or_else(|| VCLError::IoError("WebSocket stream closed".to_string()))?
                        .map_err(|e| VCLError::IoError(format!("WebSocket recv failed: {}", e)))?;
                    match msg {
                        Message::Binary(data) => {
                            let size = data.len();
                            debug!(peer = %peer_addr, size, "WebSocket server recv");
                            return Ok((data, *peer_addr));
                        }
                        Message::Close(_) => {
                            return Err(VCLError::IoError("WebSocket connection closed".to_string()));
                        }
                        _ => continue,
                    }
                }
            }
            #[cfg(feature = "quic")]
            VCLTransport::Quic { recv, .. } => {
                let mut buf = vec![0u8; UDP_MAX_SIZE];
                let n: Option<usize> = recv.read(&mut buf).await
                    .map_err(|e| VCLError::IoError(format!("QUIC recv failed: {}", e)))?;
                
                match n {
                    Some(0) => return Err(VCLError::IoError("QUIC stream closed by peer".to_string())),
                    Some(n) => buf.truncate(n),
                    None => return Err(VCLError::IoError("QUIC stream closed unexpectedly".to_string())),
                }
                
                debug!(size = buf.len(), "QUIC recv");
                let placeholder: SocketAddr = "0.0.0.0:0".parse().unwrap();
                Ok((buf, placeholder))
            }
            VCLTransport::TcpListener { .. } 
            | VCLTransport::WebSocketListener { .. } => {
                Err(VCLError::InvalidPacket(
                    "recv_raw() called on listener — call accept() first".to_string(),
                ))
            }
            #[cfg(feature = "quic")]
            VCLTransport::QuicListener { .. } => {
                Err(VCLError::InvalidPacket(
                    "recv_raw() called on listener — call accept() first".to_string(),
                ))
            }
        }
    }

    // ─── Info ─────────────────────────────────────────────────────────────────

    /// Returns the local address this transport is bound to.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            VCLTransport::Udp { socket, .. }          => socket.local_addr().ok(),
            VCLTransport::Tcp { stream, .. }           => stream.local_addr().ok(),
            VCLTransport::TcpListener { local_addr, .. } => Some(*local_addr),
            VCLTransport::WebSocketListener { local_addr, .. } => Some(*local_addr),
            VCLTransport::WebSocketServer { peer_addr, .. } => Some(*peer_addr),
            VCLTransport::WebSocketClient { .. }       => None,
            #[cfg(feature = "quic")]
            VCLTransport::Quic { endpoint, .. } => endpoint.local_addr().ok(),
            #[cfg(feature = "quic")]
            VCLTransport::QuicListener { local_addr, .. } => Some(*local_addr),
        }
    }

    /// Returns the remote peer address if known.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            VCLTransport::Udp { peer_addr, .. }        => *peer_addr,
            VCLTransport::Tcp { peer_addr, .. }        => Some(*peer_addr),
            VCLTransport::WebSocketServer { peer_addr, .. } => Some(*peer_addr),
            VCLTransport::TcpListener { .. }
            | VCLTransport::WebSocketListener { .. }
            | VCLTransport::WebSocketClient { .. }     => None,
            #[cfg(feature = "quic")]
            VCLTransport::Quic { .. } => None,
            #[cfg(feature = "quic")]
            VCLTransport::QuicListener { .. } => None,
        }
    }

    /// Set the peer address for UDP transport.
    pub fn set_peer_addr(&mut self, addr: SocketAddr) {
        if let VCLTransport::Udp { peer_addr, .. } = self {
            *peer_addr = Some(addr);
        }
    }

    /// Returns the [`TransportMode`] of this transport.
    pub fn mode(&self) -> TransportMode {
        match self {
            VCLTransport::Udp { .. } => TransportMode::Udp,
            VCLTransport::Tcp { .. }
            | VCLTransport::TcpListener { .. } => TransportMode::Tcp,
            VCLTransport::WebSocketClient { .. }
            | VCLTransport::WebSocketServer { .. }
            | VCLTransport::WebSocketListener { .. } => TransportMode::Tcp,
            #[cfg(feature = "quic")]
            VCLTransport::Quic { .. } 
            | VCLTransport::QuicListener { .. } => TransportMode::Udp,
        }
    }

    /// Returns `true` if this is a TCP transport.
    pub fn is_tcp(&self) -> bool {
        matches!(
            self,
            VCLTransport::Tcp { .. } | VCLTransport::TcpListener { .. }
        )
    }

    /// Returns `true` if this is a UDP transport.
    pub fn is_udp(&self) -> bool {
        matches!(self, VCLTransport::Udp { .. })
    }

    /// Returns `true` if this is a WebSocket transport.
    pub fn is_websocket(&self) -> bool {
        matches!(
            self,
            VCLTransport::WebSocketClient { .. }
                | VCLTransport::WebSocketServer { .. }
                | VCLTransport::WebSocketListener { .. }
        )
    }

    /// Returns `true` if this is a QUIC transport.
    #[cfg(feature = "quic")]
    pub fn is_quic(&self) -> bool {
        matches!(self, VCLTransport::Quic { .. } | VCLTransport::QuicListener { .. })
    }
}

#[cfg(feature = "quic")]
#[derive(Debug)]
struct SkipServerVerification;

#[cfg(feature = "quic")]
impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
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
        assert!(!t.is_websocket());
        assert!(t.local_addr().is_some());
        assert!(t.peer_addr().is_none());
    }

    #[tokio::test]
    async fn test_tcp_bind() {
        let t = VCLTransport::bind_tcp("127.0.0.1:0").await.unwrap();
        assert!(t.is_tcp());
        assert!(!t.is_udp());
        assert!(!t.is_websocket());
        assert!(t.local_addr().is_some());
    }

    #[tokio::test]
    async fn test_ws_bind() {
        let t = VCLTransport::bind_ws("127.0.0.1:0").await.unwrap();
        assert!(t.is_websocket());
        assert!(!t.is_udp());
        assert!(!t.is_tcp());
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
        let server_addr = server_listener.local_addr().unwrap().to_string();
        let (server_result, client_result) = tokio::join!(
            server_listener.accept(),
            VCLTransport::connect_tcp(&server_addr),
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
        let server_addr = server_listener.local_addr().unwrap().to_string();
        let (server_result, client_result) = tokio::join!(
            server_listener.accept(),
            VCLTransport::connect_tcp(&server_addr),
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
    async fn test_ws_send_recv() {
        let server_listener = VCLTransport::bind_ws("127.0.0.1:0").await.unwrap();
        let server_addr = format!("ws://{}", server_listener.local_addr().unwrap());
        let (server_result, client_result) = tokio::join!(
            server_listener.accept(),
            VCLTransport::connect_ws(&server_addr),
        );
        let mut server_conn = server_result.unwrap();
        let mut client_conn = client_result.unwrap();
        client_conn.send_raw(b"hello websocket vcl").await.unwrap();
        let (data, _) = server_conn.recv_raw().await.unwrap();
        assert_eq!(data, b"hello websocket vcl");
    }

    #[tokio::test]
    async fn test_ws_multiple_messages() {
        let server_listener = VCLTransport::bind_ws("127.0.0.1:0").await.unwrap();
        let server_addr = format!("ws://{}", server_listener.local_addr().unwrap());
        let (server_result, client_result) = tokio::join!(
            server_listener.accept(),
            VCLTransport::connect_ws(&server_addr),
        );
        let mut server_conn = server_result.unwrap();
        let mut client_conn = client_result.unwrap();
        for i in 0..5u8 {
            let msg = vec![i; 200];
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
        let ws = VCLTransport::bind_ws("127.0.0.1:0").await.unwrap();
        assert_eq!(ws.mode(), TransportMode::Tcp);
    }

    #[tokio::test]
    async fn test_set_peer_addr() {
        let mut t = VCLTransport::bind_udp("127.0.0.1:0").await.unwrap();
        assert!(t.peer_addr().is_none());
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        t.set_peer_addr(addr);
        assert_eq!(t.peer_addr(), Some(addr));
    }

    // ─── QUIC TESTS ────────────────────────────────────────────────────────

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn test_quic_bind_and_accept() {
        let listener = VCLTransport::bind_quic("127.0.0.1:0").await.unwrap();
        assert!(listener.is_quic());
        let local_addr = listener.local_addr().unwrap();
        let addr_str = local_addr.to_string();

        let server_handle = tokio::spawn(async move {
            listener.accept().await.unwrap()
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let mut client = VCLTransport::connect_quic(&addr_str).await.unwrap();
        let mut server = server_handle.await.unwrap();

        client.send_raw(b"hello quic").await.unwrap();
        let (data, _) = server.recv_raw().await.unwrap();
        assert_eq!(data, b"hello quic");
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn test_quic_multiple_messages() {
        let listener = VCLTransport::bind_quic("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let addr_str = local_addr.to_string();

        let server_handle = tokio::spawn(async move {
            listener.accept().await.unwrap()
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let mut client = VCLTransport::connect_quic(&addr_str).await.unwrap();
        let mut server = server_handle.await.unwrap();

        for i in 0..5u8 {
            let msg = vec![i; 150];
            client.send_raw(&msg).await.unwrap();
            let (data, _) = server.recv_raw().await.unwrap();
            assert_eq!(data, msg);
        }
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn test_quic_large_payload() {
        let listener = VCLTransport::bind_quic("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let addr_str = local_addr.to_string();

        let server_handle = tokio::spawn(async move {
            listener.accept().await.unwrap()
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let mut client = VCLTransport::connect_quic(&addr_str).await.unwrap();
        let mut server = server_handle.await.unwrap();

        let payload = vec![0xABu8; 8192];
        client.send_raw(&payload).await.unwrap();
        let (data, _) = server.recv_raw().await.unwrap();
        assert_eq!(data, payload);
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn test_quic_send_on_listener_fails() {
        let mut listener = VCLTransport::bind_quic("127.0.0.1:0").await.unwrap();
        assert!(listener.send_raw(b"test").await.is_err());
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn test_quic_recv_on_listener_fails() {
        let mut listener = VCLTransport::bind_quic("127.0.0.1:0").await.unwrap();
        assert!(listener.recv_raw().await.is_err());
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn test_quic_local_and_peer_addr() {
        let listener = VCLTransport::bind_quic("127.0.0.1:0").await.unwrap();
        assert!(listener.local_addr().is_some());
        assert!(listener.peer_addr().is_none());

        let local_addr = listener.local_addr().unwrap();
        let addr_str = local_addr.to_string();

        let server_handle = tokio::spawn(async move {
            listener.accept().await.unwrap()
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let client = VCLTransport::connect_quic(&addr_str).await.unwrap();
        let server = server_handle.await.unwrap();

        assert!(server.local_addr().is_some());
        assert!(server.peer_addr().is_none());
        assert!(client.local_addr().is_some());
        assert!(client.peer_addr().is_none());
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn test_quic_mode_returns_udp() {
        let listener = VCLTransport::bind_quic("127.0.0.1:0").await.unwrap();
        assert_eq!(listener.mode(), TransportMode::Udp);

        let local_addr = listener.local_addr().unwrap();
        let addr_str = local_addr.to_string();

        let server_handle = tokio::spawn(async move {
            listener.accept().await.unwrap()
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let _ = VCLTransport::connect_quic(&addr_str).await.unwrap();
        let server = server_handle.await.unwrap();
        assert_eq!(server.mode(), TransportMode::Udp);
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn test_quic_connect_invalid_addr_fails() {
        let result = VCLTransport::connect_quic("127.0.0.1:99999").await;
        assert!(result.is_err());
    }
}
