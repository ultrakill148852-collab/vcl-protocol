//! # VCL Packet
//!
//! Defines [`VCLPacket`] — the core unit of data transmission in VCL Protocol —
//! and [`PacketType`] which determines how the connection layer routes each packet.
//!
//! Every packet is:
//! - **Chained** — contains the SHA-256 hash of the previous packet in the same direction
//! - **Signed** — Ed25519 signature over the packet hash
//! - **Encrypted** — payload encrypted with XChaCha20-Poly1305

use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use serde::{Serialize, Deserialize};
use crate::error::VCLError;

/// Determines how a [`VCLPacket`] is routed by the connection layer.
///
/// Users only interact with `Data` packets directly.
/// `Ping`, `Pong`, `KeyRotation`, and `Fragment` are handled transparently inside `recv()`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PacketType {
    /// A regular data packet — returned by [`VCLConnection::recv()`](crate::connection::VCLConnection::recv).
    Data,
    /// Liveness check sent by [`VCLConnection::ping()`](crate::connection::VCLConnection::ping).
    Ping,
    /// Automatic reply to a [`Ping`](PacketType::Ping). Handled inside `recv()`.
    Pong,
    /// Mid-session key rotation initiated by [`VCLConnection::rotate_keys()`](crate::connection::VCLConnection::rotate_keys).
    KeyRotation,
    /// A fragment of a larger message. Payload contains a serialized [`crate::fragment::Fragment`].
    /// Reassembly is handled transparently inside `recv()`.
    Fragment,
}

/// A single unit of data transmission in VCL Protocol.
///
/// Packets are created, signed, and serialized internally by [`VCLConnection`].
/// After `recv()` returns, `payload` contains the **decrypted** data.
///
/// [`VCLConnection`]: crate::connection::VCLConnection
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VCLPacket {
    /// Protocol version. Currently `2`.
    pub version: u8,
    /// Routing type — see [`PacketType`].
    pub packet_type: PacketType,
    /// Monotonically increasing sequence number (per direction).
    pub sequence: u64,
    /// SHA-256 hash of the previous packet in the same direction.
    /// All-zeros for the first packet.
    pub prev_hash: Vec<u8>,
    /// 24-byte XChaCha20 nonce used to encrypt this packet's payload.
    pub nonce: [u8; 24],
    /// After `recv()`: decrypted payload. On the wire: XChaCha20-Poly1305 ciphertext.
    pub payload: Vec<u8>,
    /// 64-byte Ed25519 signature over the packet hash.
    pub signature: Vec<u8>,
}

impl VCLPacket {
    /// Create a new [`PacketType::Data`] packet.
    pub fn new(sequence: u64, prev_hash: Vec<u8>, payload: Vec<u8>, nonce: [u8; 24]) -> Self {
        Self::new_typed(sequence, prev_hash, payload, nonce, PacketType::Data)
    }

    /// Create a packet with a specific [`PacketType`].
    /// Used internally for Ping, Pong, KeyRotation, and Fragment packets.
    pub fn new_typed(
        sequence: u64,
        prev_hash: Vec<u8>,
        payload: Vec<u8>,
        nonce: [u8; 24],
        packet_type: PacketType,
    ) -> Self {
        VCLPacket {
            version: 2,
            packet_type,
            sequence,
            prev_hash,
            nonce,
            payload,
            signature: Vec::new(),
        }
    }

    /// Compute the SHA-256 hash of this packet.
    /// Used for chain linking and signature generation.
    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.version.to_be_bytes());
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.nonce);
        hasher.update(&self.payload);
        hasher.finalize().to_vec()
    }

    /// Sign this packet with an Ed25519 `private_key` (32 bytes).
    ///
    /// # Errors
    /// Returns [`VCLError::InvalidKey`] if `private_key` is not 32 bytes.
    pub fn sign(&mut self, private_key: &[u8]) -> Result<(), VCLError> {
        let key_bytes: &[u8; 32] = private_key
            .try_into()
            .map_err(|_| VCLError::InvalidKey("Private key must be 32 bytes".to_string()))?;
        let signing_key = SigningKey::from_bytes(key_bytes);
        let hash = self.compute_hash();
        let signature: Signature = signing_key.sign(&hash);
        self.signature = signature.to_bytes().to_vec();
        Ok(())
    }

    /// Verify the Ed25519 signature against `public_key` (32 bytes).
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if the signature does not match.
    ///
    /// # Errors
    /// Returns [`VCLError::InvalidKey`] if `public_key` is malformed.
    pub fn verify(&self, public_key: &[u8]) -> Result<bool, VCLError> {
        if self.signature.len() != 64 {
            return Ok(false);
        }
        let key_bytes: &[u8; 32] = public_key
            .try_into()
            .map_err(|_| VCLError::InvalidKey("Public key must be 32 bytes".to_string()))?;
        let verifying_key = VerifyingKey::from_bytes(key_bytes)
            .map_err(|e| VCLError::InvalidKey(format!("Invalid public key: {}", e)))?;
        let sig_bytes: &[u8; 64] = self.signature
            .as_slice()
            .try_into()
            .map_err(|_| VCLError::InvalidKey("Signature must be 64 bytes".to_string()))?;
        let signature = Signature::from_bytes(sig_bytes);
        let hash = self.compute_hash();
        Ok(verifying_key.verify(&hash, &signature).is_ok())
    }

    /// Returns `true` if `self.prev_hash` matches `expected_prev_hash`.
    pub fn validate_chain(&self, expected_prev_hash: &[u8]) -> bool {
        self.prev_hash == expected_prev_hash
    }

    /// Serialize this packet to bytes using bincode.
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    /// Deserialize a packet from bytes.
    ///
    /// # Errors
    /// Returns [`VCLError::SerializationError`] if the bytes are malformed.
    pub fn deserialize(data: &[u8]) -> Result<Self, VCLError> {
        bincode::deserialize(data).map_err(|e| VCLError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::KeyPair;
    use super::*;

    fn test_keypair() -> KeyPair {
        KeyPair::generate()
    }

    #[test]
    fn test_packet_new() {
        let packet = VCLPacket::new(1, vec![0; 32], b"test".to_vec(), [0; 24]);
        assert_eq!(packet.version, 2);
        assert_eq!(packet.sequence, 1);
        assert_eq!(packet.payload, b"test");
        assert_eq!(packet.packet_type, PacketType::Data);
    }

    #[test]
    fn test_compute_hash() {
        let p1 = VCLPacket::new(1, vec![0; 32], b"A".to_vec(), [0; 24]);
        let p2 = VCLPacket::new(1, vec![0; 32], b"B".to_vec(), [0; 24]);
        assert_ne!(p1.compute_hash(), p2.compute_hash());
    }

    #[test]
    fn test_sign_verify() {
        let kp = test_keypair();
        let mut packet = VCLPacket::new(1, vec![0; 32], b"test".to_vec(), [0; 24]);
        packet.sign(&kp.private_key).unwrap();
        assert!(packet.verify(&kp.public_key).unwrap());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let kp1 = test_keypair();
        let kp2 = test_keypair();
        let mut packet = VCLPacket::new(1, vec![0; 32], b"test".to_vec(), [0; 24]);
        packet.sign(&kp1.private_key).unwrap();
        assert!(!packet.verify(&kp2.public_key).unwrap());
    }

    #[test]
    fn test_validate_chain() {
        let prev = vec![1, 2, 3];
        let packet = VCLPacket::new(1, prev.clone(), b"test".to_vec(), [0; 24]);
        assert!(packet.validate_chain(&prev));
        assert!(!packet.validate_chain(&[4, 5, 6]));
    }

    #[test]
    fn test_serialize_deserialize() {
        let original = VCLPacket::new(42, vec![9; 32], b"payload".to_vec(), [7; 24]);
        let bytes = original.serialize();
        let restored = VCLPacket::deserialize(&bytes).unwrap();
        assert_eq!(original.sequence, restored.sequence);
        assert_eq!(original.payload, restored.payload);
        assert_eq!(original.nonce, restored.nonce);
        assert_eq!(restored.packet_type, PacketType::Data);
    }

    #[test]
    fn test_packet_types() {
        let ping = VCLPacket::new_typed(0, vec![0; 32], vec![], [0; 24], PacketType::Ping);
        let pong = VCLPacket::new_typed(0, vec![0; 32], vec![], [0; 24], PacketType::Pong);
        let rot  = VCLPacket::new_typed(0, vec![0; 32], vec![], [0; 24], PacketType::KeyRotation);
        let frag = VCLPacket::new_typed(0, vec![0; 32], vec![], [0; 24], PacketType::Fragment);
        assert_eq!(ping.packet_type, PacketType::Ping);
        assert_eq!(pong.packet_type, PacketType::Pong);
        assert_eq!(rot.packet_type,  PacketType::KeyRotation);
        assert_eq!(frag.packet_type, PacketType::Fragment);
    }
}
