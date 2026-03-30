use std::fmt;

#[derive(Debug)]
pub enum VCLError {
    // Crypto errors
    CryptoError(String),
    SignatureInvalid,
    InvalidKey(String),
    
    // Packet errors
    ChainValidationFailed,
    ReplayDetected(String),
    InvalidPacket(String),
    
    // Connection errors
    ConnectionClosed,
    Timeout,
    NoPeerAddress,
    NoSharedSecret,
    
    // Handshake errors
    HandshakeFailed(String),
    ExpectedClientHello,
    ExpectedServerHello,
    
    // Serialization errors
    SerializationError(String),
    
    // IO errors
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

// ← ДОБАВЛЕНО: конвертация в String для совместимости с ? в connection.rs
impl From<VCLError> for String {
    fn from(err: VCLError) -> Self {
        err.to_string()
    }
}

// Конвертация из String для удобства
impl From<String> for VCLError {
    fn from(err: String) -> Self {
        VCLError::CryptoError(err)
    }
}
