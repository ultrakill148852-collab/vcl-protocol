use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum HandshakeMessage {
    ClientHello { public_key: [u8; 32] },
    ServerHello { public_key: [u8; 32] },
    Ack,
}

#[allow(dead_code)]
pub struct HandshakeState {
    shared_secret: Option<[u8; 32]>,
}

#[allow(dead_code)]
impl HandshakeState {
    pub fn new() -> Self {
        HandshakeState { shared_secret: None }
    }

    pub fn get_shared_secret(&self) -> Option<[u8; 32]> {
        self.shared_secret
    }

    pub fn set_shared_secret(&mut self, secret: [u8; 32]) {
        self.shared_secret = Some(secret);
    }

    pub fn is_complete(&self) -> bool {
        self.shared_secret.is_some()
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

pub fn process_client_hello(
    ephemeral: EphemeralSecret,
    client_public: [u8; 32],
) -> (HandshakeMessage, Option<[u8; 32]>) {
    let server_public = PublicKey::from(&ephemeral);
    let client_pk = PublicKey::from(client_public);
    let shared: SharedSecret = ephemeral.diffie_hellman(&client_pk);
    let msg = HandshakeMessage::ServerHello {
        public_key: server_public.to_bytes(),
    };
    (msg, Some(shared.to_bytes()))
}

pub fn process_server_hello(ephemeral: EphemeralSecret, server_public: [u8; 32]) -> Option<[u8; 32]> {
    let server_pk = PublicKey::from(server_public);
    let shared: SharedSecret = ephemeral.diffie_hellman(&server_pk);
    Some(shared.to_bytes())
}
