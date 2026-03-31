use std::time::Duration;

/// Events emitted by VCLConnection.
/// Subscribe via `connection.subscribe()` to receive an async channel.
#[derive(Debug, Clone)]
pub enum VCLEvent {
    /// Handshake completed — connection is ready
    Connected,
    /// Connection was closed (via close())
    Disconnected,
    /// A data packet was received
    PacketReceived { sequence: u64, size: usize },
    /// Peer sent us a Ping — we responded with Pong automatically
    PingReceived,
    /// Pong received in response to our ping, with measured round-trip latency
    PongReceived { latency: Duration },
    /// Key rotation completed successfully (both sides switched to new key)
    KeyRotated,
    /// A non-fatal error occurred internally
    Error(String),
}
