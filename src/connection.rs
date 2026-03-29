use crate::packet::VCLPacket;
use crate::crypto::KeyPair;
use crate::handshake::{HandshakeState, HandshakeMessage};
use ed25519_dalek::SigningKey;
use tokio::net::UdpSocket;
use std::net::SocketAddr;

pub struct VCLConnection {
    socket: UdpSocket,
    keypair: KeyPair,
    sequence: u64,
    last_hash: Vec<u8>,
    peer_addr: Option<SocketAddr>,
    peer_public_key: Option<Vec<u8>>,
    shared_secret: Option<[u8; 32]>,
    is_server: bool,
}

impl VCLConnection {
    pub async fn bind(addr: &str) -> Result<Self, String> {
        let socket = UdpSocket::bind(addr).await.map_err(|e| e.to_string())?;
        Ok(VCLConnection {
            socket,
            keypair: KeyPair::generate(),
            sequence: 0,
            last_hash: vec![0; 32],
            peer_addr: None,
            peer_public_key: None,
            shared_secret: None,
            is_server: false,
        })
    }

    pub fn set_shared_key(&mut self, private_key: &[u8]) {
        let key_bytes: &[u8; 32] = private_key.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(key_bytes);
        let verifying_key = signing_key.verifying_key();
        
        self.keypair.private_key = private_key.to_vec();
        self.keypair.public_key = verifying_key.to_bytes().to_vec();
    }

    pub async fn connect(&mut self, addr: &str) -> Result<(), String> {
        let parsed: SocketAddr = addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?;
        self.peer_addr = Some(parsed);
        
        // HANDSHAKE: Client
        let (hello_msg, ephemeral) = HandshakeState::create_client_hello();
        
        // Отправляем ClientHello
        let hello_bytes = bincode::serialize(&hello_msg).map_err(|e| e.to_string())?;
        self.socket.send_to(&hello_bytes, parsed).await.map_err(|e| e.to_string())?;
        
        // Ждём ServerHello
        let mut buf = vec![0u8; 65535];
        let (len, _) = self.socket.recv_from(&mut buf).await.map_err(|e| e.to_string())?;
        let server_hello: HandshakeMessage = bincode::deserialize(&buf[..len]).map_err(|e| e.to_string())?;
        
        if let HandshakeMessage::ServerHello { public_key } = server_hello {
            let shared = HandshakeState::process_server_hello(ephemeral, public_key);
            if let Some(secret) = shared {
                self.shared_secret = Some(secret);
            } else {
                return Err("Handshake failed".to_string());
            }
        } else {
            return Err("Expected ServerHello".to_string());
        }
        
        Ok(())
    }

    pub async fn accept_handshake(&mut self) -> Result<(), String> {
        // HANDSHAKE: Server
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        
        // Ждём ClientHello
        let mut buf = vec![0u8; 65535];
        let (len, addr) = self.socket.recv_from(&mut buf).await.map_err(|e| e.to_string())?;
        self.peer_addr = Some(addr);
        
        let client_hello: HandshakeMessage = bincode::deserialize(&buf[..len]).map_err(|e| e.to_string())?;
        
        if let HandshakeMessage::ClientHello { public_key } = client_hello {
            let (server_hello, shared) = HandshakeState::process_client_hello(ephemeral, public_key);
            
            // Отправляем ServerHello
            let hello_bytes = bincode::serialize(&server_hello).map_err(|e| e.to_string())?;
            self.socket.send_to(&hello_bytes, addr).await.map_err(|e| e.to_string())?;
            
            // Сохраняем shared_secret
            if let Some(secret) = shared {
                self.shared_secret = Some(secret);
                self.is_server = true;
            } else {
                return Err("Handshake failed".to_string());
            }
        } else {
            return Err("Expected ClientHello".to_string());
        }
        
        Ok(())
    }

    pub async fn send(&mut self,  &[u8]) -> Result<(), String> {
        let mut packet = VCLPacket::new(self.sequence, self.last_hash.clone(), data.to_vec());
        packet.sign(&self.keypair.private_key);
        let serialized = packet.serialize();
        let addr = self.peer_addr.ok_or("No peer address")?;
        self.socket.send_to(&serialized, addr).await.map_err(|e| e.to_string())?;
        self.last_hash = packet.compute_hash();
        self.sequence += 1;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<VCLPacket, String> {
        let mut buf = vec![0u8; 65535];
        let (len, addr) = self.socket.recv_from(&mut buf).await.map_err(|e| e.to_string())?;
        if self.peer_addr.is_none() {
            self.peer_addr = Some(addr);
        }
        let packet = VCLPacket::deserialize(&buf[..len])?;
        if !packet.validate_chain(&self.last_hash) {
            return Err("Chain validation failed".to_string());
        }
        let verify_key = self.peer_public_key.as_ref().unwrap_or(&self.keypair.public_key);
        if !packet.verify(verify_key) {
            return Err("Signature validation failed".to_string());
        }
        self.last_hash = packet.compute_hash();
        Ok(packet)
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.keypair.public_key.clone()
    }

    pub fn get_shared_secret(&self) -> Option<[u8; 32]> {
        self.shared_secret
    }
}
