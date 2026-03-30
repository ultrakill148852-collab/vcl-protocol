use std::fmt;

#[derive(Debug)]
pub enum VCLError {
    CryptoError(String),
    SignatureInvalid,
    InvalidKey(String),
    ChainValidationFailed,
    ReplayDetected(String),
    InvalidPacket(String),
    ConnectionClosed,
    Timeout,
    NoPeerAddress,
    NoSharedSecret,
    HandshakeFailed(String),
    ExpectedClientHello,
    ExpectedServerHello,
    SerializationError(String),
    IoError(String),
}

impl fmt::Display for VCLError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VCLError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            VCLError::SignatureInvalid => write!(f, "Signature validation failed"),
            VCLError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            VCLError::ChainValidationFailed => write!(f, "Chain validation failed"),
            VCLError::ReplayDetected(msg) => write!(f, "Replay detected: {}", msg),
            VCLError::InvalidPacket(msg) => write!(f, "Invalid packet: {}", msg),
            VCLError::ConnectionClosed => write!(f, "Connection closed"),
            VCLError::Timeout => write!(f, "Connection timeout"),
            VCLError::NoPeerAddress => write!(f, "No peer address"),
            VCLError::NoSharedSecret => write!(f, "No shared secret"),
            VCLError::HandshakeFailed(msg) => write!(f, "Handshake failed: {}", msg),
            VCLError::ExpectedClientHello => write!(f, "Expected ClientHello"),
            VCLError::ExpectedServerHello => write!(f, "Expected ServerHello"),
            VCLError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            VCLError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for VCLError {}

impl From<VCLError> for String {
    fn from(err: VCLError) -> Self {
        err.to_string()
    }
}

impl From<String> for VCLError {
    fn from(err: String) -> Self {
        VCLError::CryptoError(err)
    }
}
