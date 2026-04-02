//! # VCL Error Types
//!
//! All errors returned by VCL Protocol operations are represented
//! as variants of [`VCLError`]. It implements [`std::error::Error`]
//! and can be used with the `?` operator throughout.

use std::fmt;

/// The main error type for VCL Protocol operations.
///
/// Every public method that can fail returns `Result<_, VCLError>`.
///
/// # Example
///
/// ```no_run
/// use vcl_protocol::VCLError;
///
/// fn handle(err: VCLError) {
///     match err {
///         VCLError::ConnectionClosed => println!("Connection was closed"),
///         VCLError::Timeout          => println!("Timed out"),
///         other                      => println!("Other error: {}", other),
///     }
/// }
/// ```
#[derive(Debug)]
pub enum VCLError {
    /// Encryption or decryption operation failed.
    CryptoError(String),
    /// Ed25519 signature verification failed — packet may be tampered.
    SignatureInvalid,
    /// A key has wrong length or invalid format.
    InvalidKey(String),
    /// The `prev_hash` field does not match the expected value — chain is broken.
    ChainValidationFailed,
    /// A packet with this sequence number or nonce was already received.
    ReplayDetected(String),
    /// Packet has unexpected structure or payload.
    InvalidPacket(String),
    /// Operation attempted on a closed connection.
    ConnectionClosed,
    /// No activity for longer than the configured `timeout_secs`.
    Timeout,
    /// `send()` called before a peer address is known.
    NoPeerAddress,
    /// `send()` or `recv()` called before the handshake completed.
    NoSharedSecret,
    /// X25519 handshake could not be completed.
    HandshakeFailed(String),
    /// Server received a non-ClientHello message during handshake.
    ExpectedClientHello,
    /// Client received a non-ServerHello message during handshake.
    ExpectedServerHello,
    /// Bincode serialization or deserialization failed.
    SerializationError(String),
    /// UDP socket error or address parse failure.
    IoError(String),
}

impl fmt::Display for VCLError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VCLError::CryptoError(msg)       => write!(f, "Crypto error: {}", msg),
            VCLError::SignatureInvalid        => write!(f, "Signature validation failed"),
            VCLError::InvalidKey(msg)         => write!(f, "Invalid key: {}", msg),
            VCLError::ChainValidationFailed   => write!(f, "Chain validation failed"),
            VCLError::ReplayDetected(msg)     => write!(f, "Replay detected: {}", msg),
            VCLError::InvalidPacket(msg)      => write!(f, "Invalid packet: {}", msg),
            VCLError::ConnectionClosed        => write!(f, "Connection closed"),
            VCLError::Timeout                 => write!(f, "Connection timeout"),
            VCLError::NoPeerAddress           => write!(f, "No peer address"),
            VCLError::NoSharedSecret          => write!(f, "No shared secret"),
            VCLError::HandshakeFailed(msg)    => write!(f, "Handshake failed: {}", msg),
            VCLError::ExpectedClientHello     => write!(f, "Expected ClientHello"),
            VCLError::ExpectedServerHello     => write!(f, "Expected ServerHello"),
            VCLError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            VCLError::IoError(msg)            => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for VCLError {}

impl From<std::io::Error> for VCLError {
    fn from(err: std::io::Error) -> Self {
        VCLError::IoError(err.to_string())
    }
}

impl From<bincode::Error> for VCLError {
    fn from(err: bincode::Error) -> Self {
        VCLError::SerializationError(err.to_string())
    }
}

impl From<std::net::AddrParseError> for VCLError {
    fn from(err: std::net::AddrParseError) -> Self {
        VCLError::IoError(err.to_string())
    }
}

impl From<VCLError> for String {
    fn from(err: VCLError) -> Self {
        err.to_string()
    }
}
