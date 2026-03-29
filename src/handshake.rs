use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum HandshakeMessage {
    ClientHello { public_key: [u8; 32] },
    ServerHello { public_key: [u8; 32] },
    Ack,
}

pub struct HandshakeState {
    ephemeral_secret: Option<EphemeralSecret>,
    shared_secret: Option<[u8; 32]>,
    is_initiator: bool,
}

impl HandshakeState {
    pub fn new(initiator: bool) -> Self {
        HandshakeState {
            ephemeral_secret: None,
            shared_secret: None,
            is_initiator: initiator,
        }
    }

    pub fn create_client_hello() -> (HandshakeMessage, EphemeralSecret) {
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&ephemeral);
        let msg = HandshakeMessage::ClientHello {
            public_key: public.to_bytes(),
        };
        (msg, ephemeral)
    }

    pub fn process_client_hello(&mut self, client_public: [u8; 32]) -> HandshakeMessage {
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&ephemeral);
        
        if let Ok(client_pk) = PublicKey::try_from(client_public) {
            let shared: SharedSecret = ephemeral.diffie_hellman(&client_pk);
            self.shared_secret = Some(shared.to_bytes());
        }
        
        self.ephemeral_secret = Some(ephemeral);
        
        HandshakeMessage::ServerHello {
            public_key: server_public.to_bytes(),
        }
    }

    pub fn process_server_hello(&mut self, server_public: [u8; 32]) -> bool {
        if let Some(secret) = &self.ephemeral_secret {
            if let Ok(server_pk) = PublicKey::try_from(server_public) {
                let shared: SharedSecret = secret.diffie_hellman(&server_pk);
                self.shared_secret = Some(shared.to_bytes());
                return true;
            }
        }
        false
    }

    pub fn get_shared_secret(&self) -> Option<[u8; 32]> {
        self.shared_secret
    }

    pub fn is_complete(&self) -> bool {
        self.shared_secret.is_some()
    }
}
