use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VCLPacket {
    pub version: u8,
    pub sequence: u64,
    pub prev_hash: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl VCLPacket {
    pub fn new(sequence: u64, prev_hash: Vec<u8>, payload: Vec<u8>) -> Self {
        VCLPacket {
            version: 1,
            sequence,
            prev_hash,
            payload,
            signature: Vec::new(),
        }
    }

    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.version.to_be_bytes());
        hasher.update(&self.sequence.to_be_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.payload);
        hasher.finalize().to_vec()
    }

    pub fn sign(&mut self, private_key: &[u8]) {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(private_key.try_into().unwrap());
        let hash = self.compute_hash();
        self.signature = signing_key.sign(&hash).to_bytes().to_vec();
    }

    pub fn verify(&self, public_key: &[u8]) -> bool {
        use ed25519_dalek::{Verifier, VerifyingKey};
        let verifying_key = VerifyingKey::from_bytes(public_key.try_into().unwrap()).unwrap();
        let hash = self.compute_hash();
        let signature = ed25519_dalek::Signature::from_bytes(self.signature.as_slice().try_into().unwrap());
        verifying_key.verify(&hash, &signature).is_ok()
    }

    pub fn validate_chain(&self, expected_prev_hash: &[u8]) -> bool {
        self.prev_hash == expected_prev_hash
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| e.to_string())
    }
}
