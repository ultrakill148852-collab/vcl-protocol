//! # VCL Post-Quantum Cryptography
//!
//! Hybrid key exchange combining classical X25519 with post-quantum
//! CRYSTALS-Kyber768 (ML-KEM). Even if quantum computers break X25519,
//! the Kyber layer keeps the session secure.
//!
//! ## How hybrid KEM works
//!
//! ```text
//! Client                                    Server
//!    |                                         |
//!    | -- X25519 pubkey + Kyber768 pubkey ---> |
//!    |                                         |
//!    | <-- X25519 pubkey + Kyber ciphertext -- |
//!    |                                         |
//! shared_secret = SHA-256(x25519_secret || kyber_secret)
//! ```
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::pq_crypto::{PqKeyPair, PqHandshake};
//!
//! // Client side
//! let mut client_kp = PqKeyPair::generate();
//! let client_hello = client_kp.client_hello();
//!
//! // Server side
//! let mut server_kp = PqKeyPair::generate();
//!
//! // Client finalizes
//! let client_secret = client_kp.client_finalize(&server_hello).unwrap();
//!
//! assert_eq!(client_secret, server_secret);
//! ```

use crate::error::VCLError;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret};
use sha2::{Sha256, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use rand::rngs::OsRng;
use tracing::{debug, info};

/// Size of the combined hybrid shared secret.
pub const HYBRID_SECRET_SIZE: usize = 32;

/// Public key bundle sent during handshake (X25519 + Kyber768).
#[derive(Debug, Clone)]
pub struct PqPublicBundle {
    /// X25519 public key (32 bytes).
    pub x25519_pub: [u8; 32],
    /// Kyber768 public key.
    pub kyber_pub: Vec<u8>,
}

impl PqPublicBundle {
    /// Serialize to bytes: [x25519_pub (32)] [kyber_pub_len (4 BE)] [kyber_pub]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + self.kyber_pub.len());
        out.extend_from_slice(&self.x25519_pub);
        let klen = self.kyber_pub.len() as u32;
        out.extend_from_slice(&klen.to_be_bytes());
        out.extend_from_slice(&self.kyber_pub);
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, VCLError> {
        if data.len() < 36 {
            return Err(VCLError::InvalidPacket(
                "PqPublicBundle: too short".to_string()
            ));
        }
        let mut x25519_pub = [0u8; 32];
        x25519_pub.copy_from_slice(&data[0..32]);
        let klen = u32::from_be_bytes([data[32], data[33], data[34], data[35]]) as usize;
        if data.len() < 36 + klen {
            return Err(VCLError::InvalidPacket(
                "PqPublicBundle: kyber key truncated".to_string()
            ));
        }
        let kyber_pub = data[36..36 + klen].to_vec();
        Ok(PqPublicBundle { x25519_pub, kyber_pub })
    }
}

/// Server response bundle: X25519 public key + Kyber ciphertext.
#[derive(Debug, Clone)]
pub struct PqServerResponse {
    /// Server X25519 public key (32 bytes).
    pub x25519_pub: [u8; 32],
    /// Kyber768 ciphertext encapsulating the Kyber shared secret.
    pub kyber_ciphertext: Vec<u8>,
}

impl PqServerResponse {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + self.kyber_ciphertext.len());
        out.extend_from_slice(&self.x25519_pub);
        let clen = self.kyber_ciphertext.len() as u32;
        out.extend_from_slice(&clen.to_be_bytes());
        out.extend_from_slice(&self.kyber_ciphertext);
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, VCLError> {
        if data.len() < 36 {
            return Err(VCLError::InvalidPacket(
                "PqServerResponse: too short".to_string()
            ));
        }
        let mut x25519_pub = [0u8; 32];
        x25519_pub.copy_from_slice(&data[0..32]);
        let clen = u32::from_be_bytes([data[32], data[33], data[34], data[35]]) as usize;
        if data.len() < 36 + clen {
            return Err(VCLError::InvalidPacket(
                "PqServerResponse: ciphertext truncated".to_string()
            ));
        }
        let kyber_ciphertext = data[36..36 + clen].to_vec();
        Ok(PqServerResponse { x25519_pub, kyber_ciphertext })
    }
}

/// Post-quantum hybrid key pair (X25519 + Kyber768).
pub struct PqKeyPair {
    /// X25519 ephemeral secret (consumed during finalize).
    x25519_secret: Option<EphemeralSecret>,
    /// X25519 public key.
    x25519_pub: X25519PublicKey,
    /// Kyber768 public key.
    kyber_pub: kyber768::PublicKey,
    /// Kyber768 secret key.
    kyber_sec: kyber768::SecretKey,
}

impl PqKeyPair {
    /// Generate a new hybrid key pair.
    pub fn generate() -> Self {
        let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let x25519_pub = X25519PublicKey::from(&x25519_secret);
        let (kyber_pub, kyber_sec) = kyber768::keypair();

        debug!("PqKeyPair generated (X25519 + Kyber768)");

        PqKeyPair {
            x25519_secret: Some(x25519_secret),
            x25519_pub,
            kyber_pub,
            kyber_sec,
        }
    }

    /// Build the client hello bundle (public keys to send to server).
    pub fn client_hello(&self) -> PqPublicBundle {
        PqPublicBundle {
            x25519_pub: *self.x25519_pub.as_bytes(),
            kyber_pub: self.kyber_pub.as_bytes().to_vec(),
        }
    }

    /// Server: receive client hello, produce response and derive shared secret.
    ///
    /// Returns `(PqServerResponse, shared_secret_32_bytes)`.
    pub fn server_respond(
        &mut self,
        client_hello: &PqPublicBundle,
    ) -> Result<(PqServerResponse, [u8; HYBRID_SECRET_SIZE]), VCLError> {
        // X25519 server side
        let x25519_secret = self.x25519_secret.take().ok_or_else(|| {
            VCLError::HandshakeFailed("X25519 secret already consumed".to_string())
        })?;
        let client_x25519 = X25519PublicKey::from(
            TryInto::<[u8; 32]>::try_into(client_hello.x25519_pub)
                .map_err(|_| VCLError::InvalidKey("X25519 pubkey wrong size".to_string()))?
        );
        let x25519_shared = x25519_secret.diffie_hellman(&client_x25519);

        // Kyber encapsulation — server encapsulates to client's public key
        let client_kyber_pub = kyber768::PublicKey::from_bytes(&client_hello.kyber_pub)
            .map_err(|_| VCLError::InvalidKey("Kyber public key invalid".to_string()))?;
        let (kyber_shared, kyber_ct) = kyber768::encapsulate(&client_kyber_pub);

        // Hybrid: SHA-256(x25519_shared || kyber_shared)
        let secret = hybrid_secret(x25519_shared.as_bytes(), kyber_shared.as_bytes());

        let response = PqServerResponse {
            x25519_pub: *self.x25519_pub.as_bytes(),
            kyber_ciphertext: kyber_ct.as_bytes().to_vec(),
        };

        info!("PQ server handshake complete (hybrid X25519+Kyber768)");
        Ok((response, secret))
    }

    /// Client: receive server response, derive shared secret.
    pub fn client_finalize(
        &mut self,
        server_response: &PqServerResponse,
    ) -> Result<[u8; HYBRID_SECRET_SIZE], VCLError> {
        // X25519 client side
        let x25519_secret = self.x25519_secret.take().ok_or_else(|| {
            VCLError::HandshakeFailed("X25519 secret already consumed".to_string())
        })?;
        let server_x25519 = X25519PublicKey::from(
            TryInto::<[u8; 32]>::try_into(server_response.x25519_pub)
                .map_err(|_| VCLError::InvalidKey("X25519 pubkey wrong size".to_string()))?
        );
        let x25519_shared = x25519_secret.diffie_hellman(&server_x25519);

        // Kyber decapsulation — client decapsulates with its secret key
        let kyber_ct = kyber768::Ciphertext::from_bytes(&server_response.kyber_ciphertext)
            .map_err(|_| VCLError::InvalidPacket("Kyber ciphertext invalid".to_string()))?;
        let kyber_shared = kyber768::decapsulate(&kyber_ct, &self.kyber_sec);

        // Hybrid: SHA-256(x25519_shared || kyber_shared)
        let secret = hybrid_secret(x25519_shared.as_bytes(), kyber_shared.as_bytes());

        info!("PQ client handshake complete (hybrid X25519+Kyber768)");
        Ok(secret)
    }
}

/// Combine X25519 and Kyber shared secrets into a single 32-byte key.
/// Uses SHA-256(x25519_bytes || kyber_bytes).
fn hybrid_secret(x25519: &[u8], kyber: &[u8]) -> [u8; HYBRID_SECRET_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(x25519);
    hasher.update(kyber);
    let result = hasher.finalize();
    let mut out = [0u8; HYBRID_SECRET_SIZE];
    out.copy_from_slice(&result);
    out
}

/// Convenience struct for a complete PQ handshake.
pub struct PqHandshake;

impl PqHandshake {
    /// Run a full client+server handshake and return both secrets.
    /// They must be equal. Useful for testing.
    pub fn run_local() -> Result<([u8; 32], [u8; 32]), VCLError> {
        let mut client = PqKeyPair::generate();
        let mut server = PqKeyPair::generate();

        let hello = client.client_hello();
        let (response, server_secret) = server.server_respond(&hello)?;
        let client_secret = client.client_finalize(&response)?;

        Ok((client_secret, server_secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generate() {
        let kp = PqKeyPair::generate();
        assert_eq!(kp.x25519_pub.as_bytes().len(), 32);
    }

    #[test]
    fn test_client_hello_serialization() {
        let kp = PqKeyPair::generate();
        let hello = kp.client_hello();
        let bytes = hello.to_bytes();
        let restored = PqPublicBundle::from_bytes(&bytes).unwrap();
        assert_eq!(restored.x25519_pub, hello.x25519_pub);
        assert_eq!(restored.kyber_pub, hello.kyber_pub);
    }

    #[test]
    fn test_server_response_serialization() {
        let mut client = PqKeyPair::generate();
        let mut server = PqKeyPair::generate();
        let hello = client.client_hello();
        let (response, _) = server.server_respond(&hello).unwrap();
        let bytes = response.to_bytes();
        let restored = PqServerResponse::from_bytes(&bytes).unwrap();
        assert_eq!(restored.x25519_pub, response.x25519_pub);
        assert_eq!(restored.kyber_ciphertext, response.kyber_ciphertext);
    }

    #[test]
    fn test_full_handshake_secrets_match() {
        let (client_secret, server_secret) = PqHandshake::run_local().unwrap();
        assert_eq!(client_secret, server_secret);
        assert_eq!(client_secret.len(), 32);
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let (s1, _) = PqHandshake::run_local().unwrap();
        let (s2, _) = PqHandshake::run_local().unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_secret_not_all_zeros() {
        let (secret, _) = PqHandshake::run_local().unwrap();
        assert_ne!(secret, [0u8; 32]);
    }

    #[test]
    fn test_secret_is_32_bytes() {
        let (secret, _) = PqHandshake::run_local().unwrap();
        assert_eq!(secret.len(), HYBRID_SECRET_SIZE);
    }

    #[test]
    fn test_public_bundle_from_bytes_too_short() {
        let result = PqPublicBundle::from_bytes(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_server_response_from_bytes_too_short() {
        let result = PqServerResponse::from_bytes(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_secret_consumed_once() {
        let mut client = PqKeyPair::generate();
        let mut server = PqKeyPair::generate();
        let hello = client.client_hello();
        let (response, _) = server.server_respond(&hello).unwrap();
        client.client_finalize(&response).unwrap();
        // Second call should fail — secret consumed
        let mut server2 = PqKeyPair::generate();
        let hello2 = PqKeyPair::generate().client_hello();
        let (response2, _) = server2.server_respond(&hello2).unwrap();
        let result = client.client_finalize(&response2);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_secret_deterministic() {
        let x = [1u8; 32];
        let k = [2u8; 32];
        let s1 = hybrid_secret(&x, &k);
        let s2 = hybrid_secret(&x, &k);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_hybrid_secret_different_inputs() {
        let s1 = hybrid_secret(&[1u8; 32], &[2u8; 32]);
        let s2 = hybrid_secret(&[3u8; 32], &[4u8; 32]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_client_hello_has_kyber_key() {
        let kp = PqKeyPair::generate();
        let hello = kp.client_hello();
        assert!(!hello.kyber_pub.is_empty());
    }
}
