use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, AeadCore};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::XNonce;
use crate::error::VCLError;

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        
        KeyPair {
            public_key: verifying_key.to_bytes().to_vec(),
            private_key: signing_key.to_bytes().to_vec(),
        }
    }
}

pub fn encrypt_payload(data: &[u8], key: &[u8; 32]) -> (Vec<u8>, [u8; 24]) {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(nonce.as_slice());
    
    let ciphertext = cipher.encrypt(&nonce, data).unwrap();
    
    (ciphertext, nonce_bytes)
}

pub fn decrypt_payload(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> Result<Vec<u8>, VCLError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let nonce = XNonce::from_slice(nonce);
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| VCLError::CryptoError(format!("Decryption failed: {}", e)))?;
    
    Ok(plaintext)
}

pub fn hash_data(data: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    Sha256::new().chain_update(data).finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generate() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        assert_eq!(kp1.public_key.len(), 32);
        assert_eq!(kp1.private_key.len(), 32);
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [1u8; 32];
        let data = b"Hello, VCL!";
        
        let (ciphertext, nonce) = encrypt_payload(data, &key);
        let decrypted = decrypt_payload(&ciphertext, &key, &nonce).unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let data = b"Secret message";
        
        let (ciphertext, nonce) = encrypt_payload(data, &key1);
        let result = decrypt_payload(&ciphertext, &key2, &nonce);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_data() {
        let h1 = hash_data(b"test");
        let h2 = hash_data(b"test");
        let h3 = hash_data(b"Test");
        
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 32);
    }
}
