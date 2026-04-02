//! # VCL Connection Events
//!
//! [`VCLEvent`] represents lifecycle and data events emitted by a [`VCLConnection`].
//!
//! Subscribe with [`VCLConnection::subscribe`] before calling `connect()` or
//! `accept_handshake()` to ensure you receive all events including [`VCLEvent::Connected`].
//!
//! [`VCLConnection`]: crate::connection::VCLConnection
//! [`VCLConnection::subscribe`]: crate::connection::VCLConnection::subscribe

use std::time::Duration;

/// Events emitted by a [`VCLConnection`](crate::connection::VCLConnection).
///
/// Received via the `mpsc::Receiver<VCLEvent>` returned by
/// [`VCLConnection::subscribe()`](crate::connection::VCLConnection::subscribe).
///
/// # Example
///
/// ```no_run
/// use vcl_protocol::{VCLEvent, connection::VCLConnection};
///
/// #[tokio::main]
/// async fn main() {
///     let mut conn = VCLConnection::bind("127.0.0.1:0").await.unwrap();
///     let mut events = conn.subscribe();
///
///     tokio::spawn(async move {
///         while let Some(event) = events.recv().await {
///             match event {
///                 VCLEvent::Connected => println!("Ready!"),
///                 VCLEvent::PongReceived { latency } =>
///                     println!("Latency: {:?}", latency),
///                 VCLEvent::Disconnected => break,
///                 _ => {}
///             }
///         }
///     });
/// }
/// ```
#[derive(Debug, Clone)]
pub enum VCLEvent {
    /// Handshake completed — the connection is ready to send and receive data.
    Connected,

    /// `close()` was called — connection is now shut down.
    Disconnected,

    /// A data packet was successfully received and decrypted.
    PacketReceived {
        /// Sequence number of the received packet.
        sequence: u64,
        /// Size of the decrypted payload in bytes.
        size: usize,
    },

    /// The peer sent a Ping — a Pong was sent back automatically.
    PingReceived,

    /// A Pong was received in response to our `ping()` call.
    PongReceived {
        /// Measured round-trip time from `ping()` to pong receipt.
        latency: Duration,
    },

    /// Mid-session key rotation completed — both sides now use the new shared secret.
    KeyRotated,

    /// A non-fatal internal error occurred.
    Error(String),
}
