use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::{Aead, Nonce};
use chacha20poly1305::XNonce;

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl KeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        KeyPair {
            public_key: verifying_key.to_bytes().to_vec(),
            private_key: signing_key.to_bytes().to_vec(),
        }
    }
}

/// Encrypts payload using XChaCha20-Poly1305
/// 
/// Returns: (ciphertext, nonce)
pub fn encrypt_payload(data: &[u8], key: &[u8; 32]) -> (Vec<u8>, [u8; 24]) {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let nonce_bytes: [u8; 24] = nonce.as_ref().try_into().unwrap();
    
    let ciphertext = cipher.encrypt(&nonce, data).unwrap();
    
    (ciphertext, nonce_bytes)
}

/// Decrypts payload using XChaCha20-Poly1305
pub fn decrypt_payload(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let nonce = XNonce::from_slice(nonce);
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    
    Ok(plaintext)
}

pub fn hash_data(data: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    Sha256::new().chain_update(data).finalize().to_vec()
}
