use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub struct KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        
        KeyPair {
            private_key: signing_key.to_bytes().to_vec(),
            public_key: verifying_key.to_bytes().to_vec(),
        }
    }
}

pub fn hash_data(data: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    Sha256::new().chain_update(data).finalize().to_vec()
}
