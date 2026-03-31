use crate::packet::VCLPacket;
use crate::crypto::{KeyPair, encrypt_payload, decrypt_payload};
use crate::handshake::{HandshakeMessage, create_client_hello, process_client_hello, process_server_hello};
use crate::error::VCLError;
use ed25519_dalek::SigningKey;
use x25519_dalek::EphemeralSecret;
use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use std::net::SocketAddr;
use std::collections::HashSet;
use std::time::Instant;

pub struct VCLConnection {
    socket: UdpSocket,
    keypair: KeyPair,
    sequence: u64,
    last_hash: Vec<u8>,
    peer_addr: Option<SocketAddr>,
    peer_public_key: Option<Vec<u8>>,
    shared_secret: Option<[u8; 32]>,
    is_server: bool,
    last_sequence: u64,
    seen_nonces: HashSet<[u8; 24]>,
    closed: bool,
    last_activity: Instant,
    timeout_secs: u64,
}

impl VCLConnection {
    pub async fn bind(addr: &str) -> Result<Self, VCLError> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(VCLConnection {
            socket,
            keypair: KeyPair::generate(),
            sequence: 0,
            last_hash: vec![0; 32],
            peer_addr: None,
            peer_public_key: None,
            shared_secret: None,
            is_server: false,
            last_sequence: 0,
            seen_nonces: HashSet::new(),
            closed: false,
            last_activity: Instant::now(),
            timeout_secs: 60,
        })
    }

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
        Ok(())
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<(), VCLError> {
        if self.closed {
            return Err(VCLError::ConnectionClosed);
        }
        self.check_timeout()?;

        let key = self.shared_secret.ok_or(VCLError::NoSharedSecret)?;
        let (encrypted_payload, nonce) = encrypt_payload(data, &key)?;

        let mut packet = VCLPacket::new(self.sequence, self.last_hash.clone(), encrypted_payload, nonce);
        packet.sign(&self.keypair.private_key)?;

        let serialized = packet.serialize();
        let addr = self.peer_addr.ok_or(VCLError::NoPeerAddress)?;
        self.socket.send_to(&serialized, addr).await?;

        self.last_hash = packet.compute_hash();
        self.sequence += 1;
        self.last_activity = Instant::now();
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<VCLPacket, VCLError> {
        if self.closed {
            return Err(VCLError::ConnectionClosed);
        }
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

        if !packet.validate_chain(&self.last_hash) {
            return Err(VCLError::ChainValidationFailed);
        }

        let verify_key = self.peer_public_key.as_ref().unwrap_or(&self.keypair.public_key);
        if !packet.verify(verify_key)? {
            return Err(VCLError::SignatureInvalid);
        }

        self.last_hash = packet.compute_hash();
        self.last_sequence = packet.sequence;
        self.last_activity = Instant::now();

        let key = self.shared_secret.ok_or(VCLError::NoSharedSecret)?;
        let decrypted = decrypt_payload(&packet.payload, &key, &packet.nonce)?;

        Ok(VCLPacket {
            version: packet.version,
            sequence: packet.sequence,
            prev_hash: packet.prev_hash,
            nonce: packet.nonce,
            payload: decrypted,
            signature: packet.signature,
        })
    }

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
        self.sequence = 0;
        self.last_hash = vec![0; 32];
        self.last_sequence = 0;
        self.seen_nonces.clear();
        self.shared_secret = None;
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
