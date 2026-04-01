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

    /// Subscribe to connection events. Returns an async receiver channel.
    /// Call before connect() / accept_handshake() to catch Connected event.
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

    pub fn set_timeout(&mut self, secs: u64) {
        self.timeout_secs = secs;
    }

    pub fn get_timeout(&self) -> u64 {
        self.timeout_secs
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    pub fn set_shared_key(&mut self, private_key: &[u8]) {
        let key_bytes: &[u8; 32] = private_key.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(key_bytes);
        let verifying_key = signing_key.verifying_key();
        self.keypair.private_key = private_key.to_vec();
        self.keypair.public_key = verifying_key.to_bytes().to_vec();
    }

    // ─── Handshake ────────────────────────────────────────────────────────────

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

    pub async fn send(&mut self, data: &[u8]) -> Result<(), VCLError> {
        if self.closed { return Err(VCLError::ConnectionClosed); }
        self.check_timeout()?;
        self.send_internal(data, PacketType::Data).await
    }

    // ─── Ping / Heartbeat ─────────────────────────────────────────────────────

    /// Send a ping to the peer. The pong reply is handled automatically inside
    /// recv() — subscribe to events to receive PongReceived { latency }.
    /// You must keep calling recv() for the pong to be processed.
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

    /// Initiate a key rotation. Generates a new X25519 ephemeral key pair,
    /// sends the public key to the peer, and waits for the peer's response.
    /// Both sides atomically switch to the new shared secret.
    /// The peer must be in an active recv() loop to handle the rotation.
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
                PacketType::Ping => {
                    self.handle_ping().await?;
                }
                PacketType::Pong => {
                    self.handle_pong();
                }
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

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.keypair.public_key.clone()
    }

    pub fn get_shared_secret(&self) -> Option<[u8; 32]> {
        self.shared_secret
    }
}
