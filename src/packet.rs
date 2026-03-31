use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use serde::{Serialize, Deserialize};
use crate::error::VCLError;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VCLPacket {
    pub version: u8,
    pub sequence: u64,
    pub prev_hash: Vec<u8>,
    pub nonce: [u8; 24],
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl VCLPacket {
    pub fn new(sequence: u64, prev_hash: Vec<u8>, payload: Vec<u8>, nonce: [u8; 24]) -> Self {
        VCLPacket {
            version: 1,
            sequence,
            prev_hash,
            nonce,
            payload,
            signature: Vec::new(),
        }
    }

    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.version.to_be_bytes());
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.nonce);
        hasher.update(&self.payload);
        hasher.finalize().to_vec()
    }

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

    pub fn validate_chain(&self, expected_prev_hash: &[u8]) -> bool {
        self.prev_hash == expected_prev_hash
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

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
        assert_eq!(packet.version, 1);
        assert_eq!(packet.sequence, 1);
        assert_eq!(packet.payload, b"test");
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
    }
}
