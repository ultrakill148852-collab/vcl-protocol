//! # VCL Connection
//!
//! [`VCLConnection`] is the main entry point for VCL Protocol.
//! It manages the full lifecycle of a secure UDP connection:
//!
//! - X25519 ephemeral handshake
//! - Packet encryption, signing, and chain validation
//! - Replay protection
//! - Session management (close, timeout)
//! - Connection events via async mpsc channel
//! - Ping / heartbeat with latency measurement
//! - Mid-session key rotation

use crate::packet::{VCLPacket, PacketType};
use crate::crypto::{KeyPair, encrypt_payload, decrypt_payload};
use crate::handshake::{HandshakeMessage, create_client_hello, process_client_hello, process_server_hello};
use crate::error::VCLError;
use crate::event::VCLEvent;
use ed25519_dalek::SigningKey;
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use std::net::SocketAddr;
use std::collections::HashSet;
use std::time::Instant;

/// A secure VCL Protocol connection over UDP.
///
/// Each connection manages its own cryptographic state:
/// independent send/receive hash chains, nonce tracking,
/// shared secret, and Ed25519 key pair.
///
/// # Example — Server
///
/// ```no_run
/// use vcl_protocol::connection::VCLConnection;
///
/// #[tokio::main]
/// async fn main() {
///     let mut server = VCLConnection::bind("127.0.0.1:8080").await.unwrap();
///     server.accept_handshake().await.unwrap();
///
///     loop {
///         match server.recv().await {
///             Ok(packet) => println!("{}", String::from_utf8_lossy(&packet.payload)),
///             Err(e)     => { eprintln!("{}", e); break; }
///         }
///     }
/// }
/// ```
///
/// # Example — Client
///
/// ```no_run
/// use vcl_protocol::connection::VCLConnection;
///
/// #[tokio::main]
/// async fn main() {
///     let mut client = VCLConnection::bind("127.0.0.1:0").await.unwrap();
///     client.connect("127.0.0.1:8080").await.unwrap();
///     client.send(b"Hello!").await.unwrap();
///     client.close().unwrap();
/// }
/// ```
pub struct VCLConnection {
    socket: UdpSocket,
    keypair: KeyPair,
    send_sequence: u64,
    send_hash: Vec<u8>,
    recv_hash: Vec<u8>,
    last_sequence: u64,
    seen_nonces: HashSet<[u8; 24]>,
    peer_addr: Option<SocketAddr>,
    peer_public_key: Option<Vec<u8>>,
    shared_secret: Option<[u8; 32]>,
    #[allow(dead_code)]
    is_server: bool,
    closed: bool,
    last_activity: Instant,
    timeout_secs: u64,
    event_tx: Option<mpsc::Sender<VCLEvent>>,
    ping_sent_at: Option<Instant>,
}

impl VCLConnection {
    /// Bind a new VCL connection to a local UDP address.
    ///
    /// Use `"127.0.0.1:0"` to let the OS assign a port (typical for clients).
    ///
    /// # Errors
    /// Returns [`VCLError::IoError`] if the socket cannot be bound.
    pub async fn bind(addr: &str) -> Result<Self, VCLError> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(VCLConnection {
            socket,
            keypair: KeyPair::generate(),
            send_sequence: 0,
            send_hash: vec![0; 32],
            recv_hash: vec![0; 32],
            last_sequence: 0,
            seen_nonces: HashSet::new(),
            peer_addr: None,
            peer_public_key: None,
            shared_secret: None,
            is_server: false,
            closed: false,
            last_activity: Instant::now(),
            timeout_secs: 60,
            event_tx: None,
            ping_sent_at: None,
        })
    }

    // ─── Events ──────────────────────────────────────────────────────────────

    /// Subscribe to connection events.
    ///
    /// Returns an async `mpsc::Receiver<VCLEvent>` with a channel capacity of 64.
    /// Call this **before** `connect()` or `accept_handshake()` to receive
    /// the [`VCLEvent::Connected`] event.
    ///
    /// Events are sent with `try_send` — if the channel is full, events are dropped silently.
    pub fn subscribe(&mut self) -> mpsc::Receiver<VCLEvent> {
        let (tx, rx) = mpsc::channel(64);
        self.event_tx = Some(tx);
        rx
    }

    fn emit(&self, event: VCLEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.try_send(event);
        }
    }

    // ─── Configuration ────────────────────────────────────────────────────────

    /// Set the inactivity timeout in seconds (default: 60).
    ///
    /// If no `send()` or `recv()` occurs within this duration,
    /// the next operation returns [`VCLError::Timeout`].
    /// Set to `0` to disable the timeout.
    pub fn set_timeout(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }

    /// Get the current inactivity timeout in seconds.
    pub fn get_timeout(&self) -> u64 {
        self.timeout_secs
    }

    /// Get the [`Instant`] of the last `send()` or `recv()` activity.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Override the Ed25519 signing key with a pre-shared key.
    ///
    /// ⚠️ **For testing only.** Never use a pre-shared key in production.
    pub fn set_shared_key(&mut self, private_key: &[u8]) {
        let key_bytes: &[u8; 32] = private_key.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(key_bytes);
        let verifying_key = signing_key.verifying_key();
        self.keypair.private_key = private_key.to_vec();
        self.keypair.public_key = verifying_key.to_bytes().to_vec();
    }

    // ─── Handshake ────────────────────────────────────────────────────────────

    /// Connect to a remote VCL server and perform the X25519 handshake.
    ///
    /// After this returns `Ok(())`, the connection is ready to `send()` and `recv()`.
    /// Emits [`VCLEvent::Connected`] if subscribed.
    ///
    /// # Errors
    /// - [`VCLError::IoError`] — socket or address error
    /// - [`VCLError::HandshakeFailed`] — key exchange failed
    /// - [`VCLError::ExpectedServerHello`] — unexpected handshake message
    pub async fn connect(&mut self, addr: &str) -> Result<(), VCLError> {
        let parsed: SocketAddr = addr.parse()?;
        self.peer_addr = Some(parsed);

        let (hello_msg, ephemeral) = create_client_hello();
        let hello_bytes = bincode::serialize(&hello_msg)?;
        self.socket.send_to(&hello_bytes, parsed).await?;

        let mut buf = vec![0u8; 65535];
        let (len, _) = self.socket.recv_from(&mut buf).await?;
        let server_hello: HandshakeMessage = bincode::deserialize(&buf[..len])?;

        match server_hello {
            HandshakeMessage::ServerHello { public_key } => {
                let shared = process_server_hello(ephemeral, public_key)
                    .ok_or_else(|| VCLError::HandshakeFailed("Key exchange failed".to_string()))?;
                self.shared_secret = Some(shared);
            }
            _ => return Err(VCLError::ExpectedServerHello),
        }

        self.last_activity = Instant::now();
        self.emit(VCLEvent::Connected);
        Ok(())
    }

    /// Accept an incoming X25519 handshake from a client (server side).
    ///
    /// Blocks until a `ClientHello` is received.
    /// After this returns `Ok(())`, the connection is ready to `send()` and `recv()`.
    /// Emits [`VCLEvent::Connected`] if subscribed.
    ///
    /// # Errors
    /// - [`VCLError::IoError`] — socket error
    /// - [`VCLError::HandshakeFailed`] — key exchange failed
    /// - [`VCLError::ExpectedClientHello`] — unexpected handshake message
    pub async fn accept_handshake(&mut self) -> Result<(), VCLError> {
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);

        let mut buf = vec![0u8; 65535];
        let (len, addr) = self.socket.recv_from(&mut buf).await?;
        self.peer_addr = Some(addr);

        let client_hello: HandshakeMessage = bincode::deserialize(&buf[..len])?;

        match client_hello {
            HandshakeMessage::ClientHello { public_key } => {
                let (server_hello, shared) = process_client_hello(ephemeral, public_key);
                let hello_bytes = bincode::serialize(&server_hello)?;
                self.socket.send_to(&hello_bytes, addr).await?;
                self.shared_secret = Some(
                    shared.ok_or_else(|| VCLError::HandshakeFailed("Key exchange failed".to_string()))?
                );
                self.is_server = true;
            }
            _ => return Err(VCLError::ExpectedClientHello),
        }

        self.last_activity = Instant::now();
        self.emit(VCLEvent::Connected);
        Ok(())
    }

    // ─── Internal send ────────────────────────────────────────────────────────

    async fn send_internal(&mut self, data: &[u8], packet_type: PacketType) -> Result<(), VCLError> {
        let key = self.shared_secret.ok_or(VCLError::NoSharedSecret)?;
        let (encrypted_payload, nonce) = encrypt_payload(data, &key)?;

        let mut packet = VCLPacket::new_typed(
            self.send_sequence,
            self.send_hash.clone(),
            encrypted_payload,
            nonce,
            packet_type,
        );
        packet.sign(&self.keypair.private_key)?;

        let serialized = packet.serialize();
        let addr = self.peer_addr.ok_or(VCLError::NoPeerAddress)?;
        self.socket.send_to(&serialized, addr).await?;

        self.send_hash = packet.compute_hash();
        self.send_sequence += 1;
        self.last_activity = Instant::now();
        Ok(())
    }

    // ─── Public send ──────────────────────────────────────────────────────────

    /// Encrypt, sign, and send a data packet to the peer.
    ///
    /// # Errors
    /// - [`VCLError::ConnectionClosed`] — connection was closed
    /// - [`VCLError::Timeout`] — inactivity timeout exceeded
    /// - [`VCLError::NoSharedSecret`] — handshake not completed
    /// - [`VCLError::NoPeerAddress`] — peer address unknown
    /// - [`VCLError::IoError`] — socket error
    pub async fn send(&mut self, data: &[u8]) -> Result<(), VCLError> {
        if self.closed { return Err(VCLError::ConnectionClosed); }
        self.check_timeout()?;
        self.send_internal(data, PacketType::Data).await
    }

    // ─── Ping / Heartbeat ─────────────────────────────────────────────────────

    /// Send a ping to the peer to check liveness and measure round-trip latency.
    ///
    /// The pong reply is handled **transparently inside `recv()`** — you never
    /// see Pong packets directly. Subscribe to events to receive
    /// [`VCLEvent::PongReceived { latency }`](VCLEvent::PongReceived).
    ///
    /// ⚠️ You must keep calling `recv()` for the pong to be processed.
    ///
    /// # Errors
    /// Same as [`send()`](VCLConnection::send).
    pub async fn ping(&mut self) -> Result<(), VCLError> {
        if self.closed { return Err(VCLError::ConnectionClosed); }
        self.check_timeout()?;
        self.ping_sent_at = Some(Instant::now());
        self.send_internal(&[], PacketType::Ping).await
    }

    async fn handle_ping(&mut self) -> Result<(), VCLError> {
        self.send_internal(&[], PacketType::Pong).await?;
        self.emit(VCLEvent::PingReceived);
        Ok(())
    }

    fn handle_pong(&mut self) {
        if let Some(sent_at) = self.ping_sent_at.take() {
            self.emit(VCLEvent::PongReceived { latency: sent_at.elapsed() });
        }
    }

    // ─── Key Rotation ──────────────────────────────────────────────────────────

    /// Initiate a mid-session key rotation using a fresh X25519 ephemeral exchange.
    ///
    /// Sends our new public key to the peer (encrypted with the **current** key),
    /// waits for the peer's new public key, and atomically switches to the new
    /// shared secret on both sides.
    ///
    /// Emits [`VCLEvent::KeyRotated`] on success.
    ///
    /// ⚠️ The peer must be actively calling `recv()` during rotation.
    /// ⚠️ Do not call `send()` while `rotate_keys()` is awaiting a response.
    ///
    /// # Errors
    /// - [`VCLError::ConnectionClosed`] / [`VCLError::Timeout`]
    /// - [`VCLError::ChainValidationFailed`] / [`VCLError::SignatureInvalid`]
    /// - [`VCLError::HandshakeFailed`] — unexpected packet type in response
    /// - [`VCLError::InvalidPacket`] — malformed public key payload
    pub async fn rotate_keys(&mut self) -> Result<(), VCLError> {
        if self.closed { return Err(VCLError::ConnectionClosed); }
        self.check_timeout()?;

        let our_ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let our_public = PublicKey::from(&our_ephemeral);

        self.send_internal(&our_public.to_bytes(), PacketType::KeyRotation).await?;

        let mut buf = vec![0u8; 65535];
        let (len, _) = self.socket.recv_from(&mut buf).await?;
        let packet = VCLPacket::deserialize(&buf[..len])?;

        if self.seen_nonces.contains(&packet.nonce) {
            return Err(VCLError::ReplayDetected("Duplicate nonce in key rotation".to_string()));
        }
        self.seen_nonces.insert(packet.nonce);

        if !packet.validate_chain(&self.recv_hash) {
            return Err(VCLError::ChainValidationFailed);
        }

        let verify_key = self.peer_public_key.as_ref().unwrap_or(&self.keypair.public_key);
        if !packet.verify(verify_key)? {
            return Err(VCLError::SignatureInvalid);
        }

        self.recv_hash = packet.compute_hash();
        self.last_sequence = packet.sequence;
        self.last_activity = Instant::now();

        let old_key = self.shared_secret.ok_or(VCLError::NoSharedSecret)?;
        let decrypted = decrypt_payload(&packet.payload, &old_key, &packet.nonce)?;

        if packet.packet_type != PacketType::KeyRotation {
            return Err(VCLError::HandshakeFailed("Expected KeyRotation response".to_string()));
        }
        if decrypted.len() != 32 {
            return Err(VCLError::InvalidPacket("KeyRotation payload must be 32 bytes".to_string()));
        }

        let their_bytes: [u8; 32] = decrypted
            .try_into()
            .map_err(|_| VCLError::InvalidPacket("Invalid peer pubkey".to_string()))?;
        let their_pubkey = PublicKey::from(their_bytes);
        let new_secret = our_ephemeral.diffie_hellman(&their_pubkey);
        self.shared_secret = Some(new_secret.to_bytes());
        self.emit(VCLEvent::KeyRotated);
        Ok(())
    }

    async fn handle_key_rotation_request(&mut self, their_pubkey_bytes: &[u8]) -> Result<(), VCLError> {
        if their_pubkey_bytes.len() != 32 {
            return Err(VCLError::InvalidPacket("KeyRotation payload must be 32 bytes".to_string()));
        }

        let their_bytes: [u8; 32] = their_pubkey_bytes
            .try_into()
            .map_err(|_| VCLError::InvalidPacket("Invalid peer pubkey".to_string()))?;
        let their_pubkey = PublicKey::from(their_bytes);

        let our_ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let our_public = PublicKey::from(&our_ephemeral);
        let new_secret = our_ephemeral.diffie_hellman(&their_pubkey);

        self.send_internal(&our_public.to_bytes(), PacketType::KeyRotation).await?;

        self.shared_secret = Some(new_secret.to_bytes());
        self.emit(VCLEvent::KeyRotated);
        Ok(())
    }

    // ─── Receive ──────────────────────────────────────────────────────────────

    /// Receive the next data packet from the peer.
    ///
    /// Control packets (`Ping`, `Pong`, `KeyRotation`) are handled
    /// **transparently** — this method loops internally until a `Data` packet arrives.
    ///
    /// On success, `packet.payload` contains the **decrypted** data.
    ///
    /// # Errors
    /// - [`VCLError::ConnectionClosed`] — connection was closed
    /// - [`VCLError::Timeout`] — inactivity timeout exceeded
    /// - [`VCLError::ReplayDetected`] — duplicate sequence or nonce
    /// - [`VCLError::ChainValidationFailed`] — hash chain broken
    /// - [`VCLError::SignatureInvalid`] — Ed25519 signature mismatch
    /// - [`VCLError::CryptoError`] — decryption failed
    /// - [`VCLError::IoError`] — socket error
    pub async fn recv(&mut self) -> Result<VCLPacket, VCLError> {
        if self.closed { return Err(VCLError::ConnectionClosed); }

        loop {
            self.check_timeout()?;

            let mut buf = vec![0u8; 65535];
            let (len, addr) = self.socket.recv_from(&mut buf).await?;
            if self.peer_addr.is_none() {
                self.peer_addr = Some(addr);
            }

            let packet = VCLPacket::deserialize(&buf[..len])?;

            if self.last_sequence > 0 && packet.sequence <= self.last_sequence {
                return Err(VCLError::ReplayDetected("Old sequence number".to_string()));
            }
            if self.seen_nonces.contains(&packet.nonce) {
                return Err(VCLError::ReplayDetected("Duplicate nonce".to_string()));
            }
            self.seen_nonces.insert(packet.nonce);
            if self.seen_nonces.len() > 1000 {
                self.seen_nonces.clear();
            }

            if !packet.validate_chain(&self.recv_hash) {
                return Err(VCLError::ChainValidationFailed);
            }

            let verify_key = self.peer_public_key.as_ref().unwrap_or(&self.keypair.public_key);
            if !packet.verify(verify_key)? {
                return Err(VCLError::SignatureInvalid);
            }

            self.recv_hash = packet.compute_hash();
            self.last_sequence = packet.sequence;
            self.last_activity = Instant::now();

            let key = self.shared_secret.ok_or(VCLError::NoSharedSecret)?;
            let decrypted = decrypt_payload(&packet.payload, &key, &packet.nonce)?;

            match packet.packet_type {
                PacketType::Data => {
                    self.emit(VCLEvent::PacketReceived {
                        sequence: packet.sequence,
                        size: decrypted.len(),
                    });
                    return Ok(VCLPacket {
                        version: packet.version,
                        packet_type: PacketType::Data,
                        sequence: packet.sequence,
                        prev_hash: packet.prev_hash,
                        nonce: packet.nonce,
                        payload: decrypted,
                        signature: packet.signature,
                    });
                }
                PacketType::Ping => { self.handle_ping().await?; }
                PacketType::Pong => { self.handle_pong(); }
                PacketType::KeyRotation => {
                    self.handle_key_rotation_request(&decrypted).await?;
                }
            }
        }
    }

    // ─── Session management ───────────────────────────────────────────────────

    fn check_timeout(&self) -> Result<(), VCLError> {
        if self.last_activity.elapsed().as_secs() > self.timeout_secs {
            return Err(VCLError::Timeout);
        }
        Ok(())
    }

    /// Gracefully close the connection and clear all cryptographic state.
    ///
    /// After calling `close()`, all further operations return [`VCLError::ConnectionClosed`].
    /// Emits [`VCLEvent::Disconnected`] if subscribed.
    ///
    /// # Errors
    /// Returns [`VCLError::ConnectionClosed`] if already closed.
    pub fn close(&mut self) -> Result<(), VCLError> {
        if self.closed {
            return Err(VCLError::ConnectionClosed);
        }
        self.closed = true;
        self.send_sequence = 0;
        self.send_hash = vec![0; 32];
        self.recv_hash = vec![0; 32];
        self.last_sequence = 0;
        self.seen_nonces.clear();
        self.shared_secret = None;
        self.ping_sent_at = None;
        self.emit(VCLEvent::Disconnected);
        Ok(())
    }

    /// Returns `true` if the connection has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Get the local Ed25519 public key (32 bytes).
    pub fn get_public_key(&self) -> Vec<u8> {
        self.keypair.public_key.clone()
    }

    /// Get the current X25519 shared secret, or `None` if the handshake
    /// has not completed or the connection is closed.
    pub fn get_shared_secret(&self) -> Option<[u8; 32]> {
        self.shared_secret
    }
}
