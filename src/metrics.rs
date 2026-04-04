//! # VCL Metrics
//!
//! [`VCLMetrics`] aggregates performance and health statistics
//! across a single connection or an entire [`VCLPool`].
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::metrics::VCLMetrics;
//!
//! let mut m = VCLMetrics::new();
//! m.record_sent(1024);
//! m.record_received(512);
//! m.record_rtt_sample(std::time::Duration::from_millis(42));
//!
//! println!("Loss rate: {:.2}%", m.loss_rate() * 100.0);
//! println!("Avg RTT: {:?}", m.avg_rtt());
//! ```
//!
//! [`VCLPool`]: crate::pool::VCLPool

use std::time::{Duration, Instant};
use tracing::debug;

/// Aggregated performance and health metrics for a VCL connection.
///
/// All counters are monotonically increasing since the last [`reset()`](VCLMetrics::reset).
/// RTT samples are kept in a sliding window of the last 64 measurements.
#[derive(Debug, Clone)]
pub struct VCLMetrics {
    /// Total bytes sent (payload only, not including headers).
    pub bytes_sent: u64,
    /// Total bytes received (payload only, not including headers).
    pub bytes_received: u64,
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_received: u64,
    /// Total packets retransmitted.
    pub packets_retransmitted: u64,
    /// Total packets dropped due to replay detection.
    pub packets_dropped_replay: u64,
    /// Total packets dropped due to chain validation failure.
    pub packets_dropped_chain: u64,
    /// Total packets dropped due to signature failure.
    pub packets_dropped_signature: u64,
    /// Total fragmented messages sent.
    pub fragments_sent: u64,
    /// Total fragmented messages fully reassembled.
    pub fragments_reassembled: u64,
    /// Total key rotations completed.
    pub key_rotations: u64,
    /// Total handshakes completed.
    pub handshakes: u64,
    /// When metrics collection started.
    pub started_at: Instant,
    /// RTT samples sliding window (last 64).
    rtt_samples: Vec<Duration>,
    /// Congestion window size samples (last 64).
    cwnd_samples: Vec<usize>,
}

impl VCLMetrics {
    /// Create a new zeroed metrics instance.
    pub fn new() -> Self {
        debug!("VCLMetrics initialized");
        VCLMetrics {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            packets_retransmitted: 0,
            packets_dropped_replay: 0,
            packets_dropped_chain: 0,
            packets_dropped_signature: 0,
            fragments_sent: 0,
            fragments_reassembled: 0,
            key_rotations: 0,
            handshakes: 0,
            started_at: Instant::now(),
            rtt_samples: Vec::with_capacity(64),
            cwnd_samples: Vec::with_capacity(64),
        }
    }

    // ─── Recording ────────────────────────────────────────────────────────────

    /// Record a sent packet of `bytes` payload size.
    pub fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Record a received packet of `bytes` payload size.
    pub fn record_received(&mut self, bytes: usize) {
        self.packets_received += 1;
        self.bytes_received += bytes as u64;
    }

    /// Record a retransmitted packet.
    pub fn record_retransmit(&mut self) {
        self.packets_retransmitted += 1;
    }

    /// Record a packet dropped due to replay detection.
    pub fn record_drop_replay(&mut self) {
        self.packets_dropped_replay += 1;
    }

    /// Record a packet dropped due to chain validation failure.
    pub fn record_drop_chain(&mut self) {
        self.packets_dropped_chain += 1;
    }

    /// Record a packet dropped due to signature validation failure.
    pub fn record_drop_signature(&mut self) {
        self.packets_dropped_signature += 1;
    }

    /// Record a fragmented message send (counts the whole message, not individual fragments).
    pub fn record_fragment_sent(&mut self) {
        self.fragments_sent += 1;
    }

    /// Record a successfully reassembled fragmented message.
    pub fn record_fragment_reassembled(&mut self) {
        self.fragments_reassembled += 1;
    }

    /// Record a completed key rotation.
    pub fn record_key_rotation(&mut self) {
        self.key_rotations += 1;
    }

    /// Record a completed handshake.
    pub fn record_handshake(&mut self) {
        self.handshakes += 1;
    }

    /// Record an RTT sample. Kept in a sliding window of 64.
    pub fn record_rtt_sample(&mut self, rtt: Duration) {
        if self.rtt_samples.len() >= 64 {
            self.rtt_samples.remove(0);
        }
        self.rtt_samples.push(rtt);
    }

    /// Record a congestion window size sample. Kept in a sliding window of 64.
    pub fn record_cwnd(&mut self, cwnd: usize) {
        if self.cwnd_samples.len() >= 64 {
            self.cwnd_samples.remove(0);
        }
        self.cwnd_samples.push(cwnd);
    }

    // ─── Derived stats ────────────────────────────────────────────────────────

    /// Packet loss rate: retransmitted / sent. Returns 0.0 if no packets sent.
    pub fn loss_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        self.packets_retransmitted as f64 / self.packets_sent as f64
    }

    /// Average RTT from the sliding window. Returns `None` if no samples.
    pub fn avg_rtt(&self) -> Option<Duration> {
        if self.rtt_samples.is_empty() {
            return None;
        }
        let total: u128 = self.rtt_samples.iter().map(|d| d.as_nanos()).sum();
        Some(Duration::from_nanos((total / self.rtt_samples.len() as u128) as u64))
    }

    /// Minimum RTT from the sliding window. Returns `None` if no samples.
    pub fn min_rtt(&self) -> Option<Duration> {
        self.rtt_samples.iter().copied().min()
    }

    /// Maximum RTT from the sliding window. Returns `None` if no samples.
    pub fn max_rtt(&self) -> Option<Duration> {
        self.rtt_samples.iter().copied().max()
    }

    /// Latest congestion window size. Returns `None` if no samples.
    pub fn current_cwnd(&self) -> Option<usize> {
        self.cwnd_samples.last().copied()
    }

    /// Average congestion window size. Returns `None` if no samples.
    pub fn avg_cwnd(&self) -> Option<f64> {
        if self.cwnd_samples.is_empty() {
            return None;
        }
        let total: usize = self.cwnd_samples.iter().sum();
        Some(total as f64 / self.cwnd_samples.len() as f64)
    }

    /// Total dropped packets (all reasons combined).
    pub fn total_dropped(&self) -> u64 {
        self.packets_dropped_replay
            + self.packets_dropped_chain
            + self.packets_dropped_signature
    }

    /// Throughput in bytes/sec since metrics started.
    pub fn throughput_sent_bps(&self) -> f64 {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        if elapsed == 0.0 {
            return 0.0;
        }
        self.bytes_sent as f64 / elapsed
    }

    /// Throughput in bytes/sec received since metrics started.
    pub fn throughput_recv_bps(&self) -> f64 {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        if elapsed == 0.0 {
            return 0.0;
        }
        self.bytes_received as f64 / elapsed
    }

    /// How long metrics have been collected.
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Reset all counters and samples. Resets the start time.
    pub fn reset(&mut self) {
        debug!("VCLMetrics reset");
        *self = VCLMetrics::new();
    }

    /// Merge another metrics instance into this one (for pool aggregation).
    ///
    /// Counters are summed. RTT samples are merged (capped at 64).
    pub fn merge(&mut self, other: &VCLMetrics) {
        self.bytes_sent += other.bytes_sent;
        self.bytes_received += other.bytes_received;
        self.packets_sent += other.packets_sent;
        self.packets_received += other.packets_received;
        self.packets_retransmitted += other.packets_retransmitted;
        self.packets_dropped_replay += other.packets_dropped_replay;
        self.packets_dropped_chain += other.packets_dropped_chain;
        self.packets_dropped_signature += other.packets_dropped_signature;
        self.fragments_sent += other.fragments_sent;
        self.fragments_reassembled += other.fragments_reassembled;
        self.key_rotations += other.key_rotations;
        self.handshakes += other.handshakes;

        for sample in &other.rtt_samples {
            self.record_rtt_sample(*sample);
        }
        for sample in &other.cwnd_samples {
            self.record_cwnd(*sample);
        }
    }
}

impl Default for VCLMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let m = VCLMetrics::new();
        assert_eq!(m.packets_sent, 0);
        assert_eq!(m.bytes_sent, 0);
        assert_eq!(m.loss_rate(), 0.0);
        assert!(m.avg_rtt().is_none());
    }

    #[test]
    fn test_record_sent_received() {
        let mut m = VCLMetrics::new();
        m.record_sent(1024);
        m.record_sent(512);
        m.record_received(256);
        assert_eq!(m.packets_sent, 2);
        assert_eq!(m.bytes_sent, 1536);
        assert_eq!(m.packets_received, 1);
        assert_eq!(m.bytes_received, 256);
    }

    #[test]
    fn test_loss_rate() {
        let mut m = VCLMetrics::new();
        m.record_sent(100);
        m.record_sent(100);
        m.record_sent(100);
        m.record_sent(100);
        m.record_retransmit();
        assert!((m.loss_rate() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rtt_samples() {
        let mut m = VCLMetrics::new();
        m.record_rtt_sample(Duration::from_millis(10));
        m.record_rtt_sample(Duration::from_millis(20));
        m.record_rtt_sample(Duration::from_millis(30));
        assert_eq!(m.avg_rtt(), Some(Duration::from_millis(20)));
        assert_eq!(m.min_rtt(), Some(Duration::from_millis(10)));
        assert_eq!(m.max_rtt(), Some(Duration::from_millis(30)));
    }

    #[test]
    fn test_rtt_window_capped_at_64() {
        let mut m = VCLMetrics::new();
        for i in 0..100 {
            m.record_rtt_sample(Duration::from_millis(i));
        }
        assert_eq!(m.rtt_samples.len(), 64);
    }

    #[test]
    fn test_total_dropped() {
        let mut m = VCLMetrics::new();
        m.record_drop_replay();
        m.record_drop_chain();
        m.record_drop_signature();
        assert_eq!(m.total_dropped(), 3);
    }

    #[test]
    fn test_cwnd_samples() {
        let mut m = VCLMetrics::new();
        m.record_cwnd(10);
        m.record_cwnd(20);
        m.record_cwnd(30);
        assert_eq!(m.current_cwnd(), Some(30));
        assert!((m.avg_cwnd().unwrap() - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_merge() {
        let mut m1 = VCLMetrics::new();
        m1.record_sent(1000);
        m1.record_received(500);
        m1.record_rtt_sample(Duration::from_millis(10));

        let mut m2 = VCLMetrics::new();
        m2.record_sent(2000);
        m2.record_received(1000);
        m2.record_rtt_sample(Duration::from_millis(20));

        m1.merge(&m2);
        assert_eq!(m1.bytes_sent, 3000);
        assert_eq!(m1.bytes_received, 1500);
        assert_eq!(m1.packets_sent, 2);
        assert_eq!(m1.rtt_samples.len(), 2);
    }

    #[test]
    fn test_reset() {
        let mut m = VCLMetrics::new();
        m.record_sent(1000);
        m.record_rtt_sample(Duration::from_millis(10));
        m.reset();
        assert_eq!(m.packets_sent, 0);
        assert!(m.avg_rtt().is_none());
    }

    #[test]
    fn test_throughput_zero_elapsed() {
        let m = VCLMetrics::new();
        assert_eq!(m.throughput_sent_bps(), 0.0);
    }

    #[test]
    fn test_uptime() {
        let m = VCLMetrics::new();
        std::thread::sleep(Duration::from_millis(10));
        assert!(m.uptime() >= Duration::from_millis(10));
    }

    #[test]
    fn test_default() {
        let m = VCLMetrics::default();
        assert_eq!(m.packets_sent, 0);
    }

    #[test]
    fn test_fragments() {
        let mut m = VCLMetrics::new();
        m.record_fragment_sent();
        m.record_fragment_sent();
        m.record_fragment_reassembled();
        assert_eq!(m.fragments_sent, 2);
        assert_eq!(m.fragments_reassembled, 1);
    }

    #[test]
    fn test_handshake_and_rotation() {
        let mut m = VCLMetrics::new();
        m.record_handshake();
        m.record_key_rotation();
        m.record_key_rotation();
        assert_eq!(m.handshakes, 1);
        assert_eq!(m.key_rotations, 2);
    }
}
