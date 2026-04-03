//! # VCL Connection Configuration
//!
//! [`VCLConfig`] controls how a [`VCLConnection`] handles transport and reliability.
//!
//! Use one of the preset constructors for common scenarios, or build your own:
//!
//! ```rust
//! use vcl_protocol::config::{VCLConfig, TransportMode, ReliabilityMode};
//!
//! // Use a preset
//! let vpn_config = VCLConfig::vpn();
//! let gaming_config = VCLConfig::gaming();
//!
//! // Or build custom
//! let custom = VCLConfig {
//!     transport: TransportMode::Udp,
//!     reliability: ReliabilityMode::Partial,
//!     max_retries: 3,
//!     retry_interval_ms: 50,
//!     fragment_size: 1200,
//!     flow_window_size: 32,
//! };
//! ```
//!
//! [`VCLConnection`]: crate::connection::VCLConnection

/// Transport protocol used by the connection.
///
/// Controls whether VCL uses TCP or UDP as the underlying transport.
/// In `Auto` mode, VCL selects the transport based on the [`ReliabilityMode`].
#[derive(Debug, Clone, PartialEq)]
pub enum TransportMode {
    /// TCP transport — reliable, ordered delivery.
    /// Best for VPN tunnels, file transfer, audit logging.
    Tcp,

    /// UDP transport — low latency, unordered.
    /// Best for gaming, real-time audio/video, telemetry.
    Udp,

    /// VCL automatically selects TCP or UDP based on [`ReliabilityMode`]:
    /// - `Reliable` → TCP
    /// - `Partial` / `Unreliable` → UDP
    /// - `Adaptive` → starts UDP, upgrades to TCP on packet loss
    Auto,
}

/// Reliability guarantee for packet delivery.
///
/// Controls retransmission behaviour and how VCL reacts to packet loss.
#[derive(Debug, Clone, PartialEq)]
pub enum ReliabilityMode {
    /// Every packet is delivered exactly once, in order.
    /// Lost packets are retransmitted up to [`VCLConfig::max_retries`] times.
    /// Best for VPN, file transfer, financial transactions.
    Reliable,

    /// Only packets marked as critical are retransmitted.
    /// Non-critical packets (e.g. position updates) are dropped on loss.
    /// Best for gaming where old state is irrelevant.
    Partial,

    /// No retransmission. Lost packets are dropped silently.
    /// Best for video/audio streaming where latency matters more than completeness.
    Unreliable,

    /// VCL monitors network conditions and adjusts retransmission dynamically.
    /// Starts in `Unreliable` mode, ramps up reliability on detected loss.
    /// Recommended default for unknown network conditions.
    Adaptive,
}

/// Full configuration for a VCL connection.
///
/// Controls transport, reliability, fragmentation, and flow control behaviour.
/// Use one of the preset constructors or build a custom config.
///
/// # Presets
///
/// | Preset | Transport | Reliability | Use case |
/// |--------|-----------|-------------|----------|
/// | `vpn()` | TCP | Reliable | VPN tunnels, secure comms |
/// | `gaming()` | UDP | Partial | Real-time games |
/// | `streaming()` | UDP | Unreliable | Video/audio streaming |
/// | `auto()` | Auto | Adaptive | Unknown / mixed traffic |
#[derive(Debug, Clone)]
pub struct VCLConfig {
    /// Transport protocol to use.
    pub transport: TransportMode,

    /// Reliability guarantee for packet delivery.
    pub reliability: ReliabilityMode,

    /// Maximum number of retransmission attempts for lost packets.
    /// Only used when `reliability` is `Reliable` or `Partial`.
    /// Default: `5`
    pub max_retries: u32,

    /// Time in milliseconds between retransmission attempts.
    /// Default: `100`
    pub retry_interval_ms: u64,

    /// Maximum payload size per fragment in bytes.
    /// Packets larger than this are split into multiple fragments.
    /// Default: `1200` (safe for most networks including VPN overhead)
    pub fragment_size: usize,

    /// Number of packets that can be in-flight simultaneously (flow control window).
    /// Default: `64`
    pub flow_window_size: usize,
}

impl VCLConfig {
    /// **VPN mode** — reliability over speed.
    ///
    /// Uses TCP with guaranteed delivery. Every packet is retransmitted on loss.
    /// Suitable for VPN tunnels, secure communications, financial transactions.
    ///
    /// ```rust
    /// use vcl_protocol::config::{VCLConfig, TransportMode, ReliabilityMode};
    ///
    /// let config = VCLConfig::vpn();
    /// assert_eq!(config.transport, TransportMode::Tcp);
    /// assert_eq!(config.reliability, ReliabilityMode::Reliable);
    /// ```
    pub fn vpn() -> Self {
        VCLConfig {
            transport: TransportMode::Tcp,
            reliability: ReliabilityMode::Reliable,
            max_retries: 10,
            retry_interval_ms: 100,
            fragment_size: 1200,
            flow_window_size: 64,
        }
    }

    /// **Gaming mode** — speed over reliability.
    ///
    /// Uses UDP with partial reliability. Only critical packets are retransmitted.
    /// Suitable for real-time games, position updates, input events.
    ///
    /// ```rust
    /// use vcl_protocol::config::{VCLConfig, TransportMode, ReliabilityMode};
    ///
    /// let config = VCLConfig::gaming();
    /// assert_eq!(config.transport, TransportMode::Udp);
    /// assert_eq!(config.reliability, ReliabilityMode::Partial);
    /// ```
    pub fn gaming() -> Self {
        VCLConfig {
            transport: TransportMode::Udp,
            reliability: ReliabilityMode::Partial,
            max_retries: 2,
            retry_interval_ms: 16,
            fragment_size: 1400,
            flow_window_size: 128,
        }
    }

    /// **Streaming mode** — lowest latency, no retransmission.
    ///
    /// Uses UDP with no reliability guarantees. Lost packets are dropped silently.
    /// Suitable for video/audio streaming where a missed frame is better than lag.
    ///
    /// ```rust
    /// use vcl_protocol::config::{VCLConfig, TransportMode, ReliabilityMode};
    ///
    /// let config = VCLConfig::streaming();
    /// assert_eq!(config.transport, TransportMode::Udp);
    /// assert_eq!(config.reliability, ReliabilityMode::Unreliable);
    /// ```
    pub fn streaming() -> Self {
        VCLConfig {
            transport: TransportMode::Udp,
            reliability: ReliabilityMode::Unreliable,
            max_retries: 0,
            retry_interval_ms: 0,
            fragment_size: 1400,
            flow_window_size: 256,
        }
    }

    /// **Auto mode** — recommended default.
    ///
    /// VCL selects transport and reliability dynamically based on network conditions.
    /// Starts with UDP, upgrades to TCP on detected packet loss.
    ///
    /// ```rust
    /// use vcl_protocol::config::{VCLConfig, TransportMode, ReliabilityMode};
    ///
    /// let config = VCLConfig::auto();
    /// assert_eq!(config.transport, TransportMode::Auto);
    /// assert_eq!(config.reliability, ReliabilityMode::Adaptive);
    /// ```
    pub fn auto() -> Self {
        VCLConfig {
            transport: TransportMode::Auto,
            reliability: ReliabilityMode::Adaptive,
            max_retries: 5,
            retry_interval_ms: 100,
            fragment_size: 1200,
            flow_window_size: 64,
        }
    }

    /// Returns `true` if this config uses TCP transport or will select TCP in Auto mode.
    pub fn is_tcp(&self) -> bool {
        self.transport == TransportMode::Tcp
            || (self.transport == TransportMode::Auto
                && self.reliability == ReliabilityMode::Reliable)
    }

    /// Returns `true` if retransmission is enabled for this config.
    pub fn has_retransmission(&self) -> bool {
        matches!(
            self.reliability,
            ReliabilityMode::Reliable | ReliabilityMode::Partial | ReliabilityMode::Adaptive
        )
    }

    /// Returns `true` if fragmentation is needed for a payload of `size` bytes.
    pub fn needs_fragmentation(&self, size: usize) -> bool {
        size > self.fragment_size
    }
}

impl Default for VCLConfig {
    /// Default config is [`VCLConfig::auto()`].
    fn default() -> Self {
        Self::auto()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vpn_preset() {
        let c = VCLConfig::vpn();
        assert_eq!(c.transport, TransportMode::Tcp);
        assert_eq!(c.reliability, ReliabilityMode::Reliable);
        assert!(c.has_retransmission());
        assert!(c.is_tcp());
    }

    #[test]
    fn test_gaming_preset() {
        let c = VCLConfig::gaming();
        assert_eq!(c.transport, TransportMode::Udp);
        assert_eq!(c.reliability, ReliabilityMode::Partial);
        assert!(c.has_retransmission());
        assert!(!c.is_tcp());
    }

    #[test]
    fn test_streaming_preset() {
        let c = VCLConfig::streaming();
        assert_eq!(c.transport, TransportMode::Udp);
        assert_eq!(c.reliability, ReliabilityMode::Unreliable);
        assert!(!c.has_retransmission());
        assert!(!c.is_tcp());
    }

    #[test]
    fn test_auto_preset() {
        let c = VCLConfig::auto();
        assert_eq!(c.transport, TransportMode::Auto);
        assert_eq!(c.reliability, ReliabilityMode::Adaptive);
        assert!(c.has_retransmission());
    }

    #[test]
    fn test_default_is_auto() {
        let c = VCLConfig::default();
        assert_eq!(c.transport, TransportMode::Auto);
    }

    #[test]
    fn test_needs_fragmentation() {
        let c = VCLConfig::vpn(); // fragment_size = 1200
        assert!(!c.needs_fragmentation(1000));
        assert!(!c.needs_fragmentation(1200));
        assert!(c.needs_fragmentation(1201));
        assert!(c.needs_fragmentation(65535));
    }

    #[test]
    fn test_custom_config() {
        let c = VCLConfig {
            transport: TransportMode::Udp,
            reliability: ReliabilityMode::Partial,
            max_retries: 3,
            retry_interval_ms: 50,
            fragment_size: 800,
            flow_window_size: 32,
        };
        assert_eq!(c.transport, TransportMode::Udp);
        assert!(c.needs_fragmentation(801));
        assert!(!c.needs_fragmentation(800));
    }
}
