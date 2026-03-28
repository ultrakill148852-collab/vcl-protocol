use crate::packet::VCLPacket;
use crate::crypto::KeyPair;
use tokio::net::UdpSocket;
use std::net::SocketAddr;

pub struct VCLConnection {
    socket: UdpSocket,
    keypair: KeyPair,
    sequence: u64,
    last_hash: Vec<u8>,
    peer_addr: Option<SocketAddr>,
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
        })
    }

    pub async fn connect(&mut self, addr: &str) -> Result<(), String> {
       self.peer_addr = Some(addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?);
        Ok(())
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<(), String> {
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
        
        if !packet.verify(&self.keypair.public_key) {
            return Err("Signature validation failed".to_string());
        }
        
        self.last_hash = packet.compute_hash();
        
        Ok(packet)
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.keypair.public_key.clone()
    }
}
