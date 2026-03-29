use x25519_dalek::{EphemeralSecret, PublicKey};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum HandshakeMessage {
    ClientHello { public_key: Vec<u8> },
    ServerHello { public_key: Vec<u8> },
    Ack,
}

pub struct HandshakeState {
    ephemeral_secret: Option<EphemeralSecret>,
    remote_public_key: Option<PublicKey>,
    shared_secret: Option<[u8; 32]>,
    is_initiator: bool,
}

impl HandshakeState {
    pub fn new(initiator: bool) -> Self {
        HandshakeState {
            ephemeral_secret: None,
            remote_public_key: None,
            shared_secret: None,
            is_initiator: initiator,
        }
    }

    pub fn create_client_hello() -> (HandshakeMessage, EphemeralSecret) {
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let public = ephemeral.diffie_hellman_public_key();
        let msg = HandshakeMessage::ClientHello {
            public_key: public.as_bytes().to_vec(),
        };
        (msg, ephemeral)
    }

    pub fn process_client_hello(&mut self, client_public: &[u8]) -> HandshakeMessage {
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let server_public = ephemeral.diffie_hellman_public_key();
        
        if let Ok(client_pk) = PublicKey::from_bytes(client_public.try_into().unwrap()) {
            self.shared_secret = Some(*ephemeral.diffie_hellman(&client_pk));
        }
        
        self.ephemeral_secret = Some(ephemeral);
        
        HandshakeMessage::ServerHello {
            public_key: server_public.as_bytes().to_vec(),
        }
    }

    pub fn process_server_hello(&mut self, server_public: &[u8]) -> bool {
        if let Some(secret) = &self.ephemeral_secret {
            if let Ok(server_pk) = PublicKey::from_bytes(server_public.try_into().unwrap()) {
                self.shared_secret = Some(*secret.diffie_hellman(&server_pk));
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
