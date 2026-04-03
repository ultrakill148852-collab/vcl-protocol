//! # VCL Flow Control
//!
//! Sliding window flow control for VCL Protocol.
//!
//! Prevents the sender from overwhelming the receiver by limiting
//! the number of unacknowledged packets in flight simultaneously.
//!
//! ## How it works
//!
//! ```text
//! window_size = 4
//!
//! Sent but unacked:  [0] [1] [2] [3]   <- window full, must wait
//! Acked:             [0]               <- window slides, can send [4]
//! Sent but unacked:      [1] [2] [3] [4]
//! ```
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::flow::FlowController;
//!
//! let mut fc = FlowController::new(4);
//!
//! // Send packets
//! assert!(fc.can_send());
//! fc.on_send(0);
//! fc.on_send(1);
//! fc.on_send(2);
//! fc.on_send(3);
//! assert!(!fc.can_send()); // window full
//!
//! // Acknowledge packets
//! fc.on_ack(0);
//! assert!(fc.can_send()); // window has space again
//! ```

use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

const DEFAULT_RTO_MS: u64 = 200;

/// Tracks a sent-but-unacknowledged packet.
#[derive(Debug, Clone)]
pub struct InFlightPacket {
    /// Sequence number of the packet.
    pub sequence: u64,
    /// When this packet was sent.
    pub sent_at: Instant,
    /// Number of times this packet has been retransmitted.
    pub retransmit_count: u32,
}

impl InFlightPacket {
    fn new(sequence: u64) -> Self {
        InFlightPacket {
            sequence,
            sent_at: Instant::now(),
            retransmit_count: 0,
        }
    }

    /// Returns `true` if this packet has exceeded the retransmission timeout.
    pub fn is_timed_out(&self, rto: Duration) -> bool {
        self.sent_at.elapsed() > rto
    }
}

/// Sliding window flow controller.
///
/// Tracks in-flight packets and controls send rate based on window size.
/// Supports acknowledgements, retransmission detection, and RTT estimation.
pub struct FlowController {
    window_size: usize,
    in_flight: Vec<InFlightPacket>,
    acked: BTreeSet<u64>,
    rto: Duration,
    srtt: Option<Duration>,
    total_sent: u64,
    total_acked: u64,
    total_lost: u64,
}

impl FlowController {
    /// Create a new flow controller with the given window size.
    pub fn new(window_size: usize) -> Self {
        debug!(window_size, "FlowController created");
        FlowController {
            window_size,
            in_flight: Vec::new(),
            acked: BTreeSet::new(),
            rto: Duration::from_millis(DEFAULT_RTO_MS),
            srtt: None,
            total_sent: 0,
            total_acked: 0,
            total_lost: 0,
        }
    }

    /// Create a flow controller with a custom retransmission timeout.
    pub fn with_rto(window_size: usize, rto_ms: u64) -> Self {
        let mut fc = Self::new(window_size);
        fc.rto = Duration::from_millis(rto_ms);
        fc
    }

    // ─── Window control ───────────────────────────────────────────────────────

    /// Returns `true` if the window has space to send another packet.
    pub fn can_send(&self) -> bool {
        self.in_flight.len() < self.window_size
    }

    /// Returns how many more packets can be sent right now.
    pub fn available_slots(&self) -> usize {
        self.window_size.saturating_sub(self.in_flight.len())
    }

    /// Returns the current window size.
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Dynamically adjust the window size.
    pub fn set_window_size(&mut self, size: usize) {
        debug!(old = self.window_size, new = size, "Window size updated");
        self.window_size = size;
    }

    /// Returns the number of packets currently in flight.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Returns the sequence number of the oldest unacknowledged sent packet,
    /// or `None` if there are no packets in flight.
    pub fn oldest_unacked_sequence(&self) -> Option<u64> {
        self.in_flight.first().map(|p| p.sequence)
    }

    // ─── Send / Ack ───────────────────────────────────────────────────────────

    /// Register a packet as sent.
    ///
    /// Returns `false` if the window is full.
    pub fn on_send(&mut self, sequence: u64) -> bool {
        if !self.can_send() {
            warn!(sequence, "on_send() called but window is full");
            return false;
        }
        self.in_flight.push(InFlightPacket::new(sequence));
        self.total_sent += 1;
        debug!(
            sequence,
            in_flight = self.in_flight.len(),
            window = self.window_size,
            "Packet sent"
        );
        true
    }

    /// Register a packet as acknowledged.
    ///
    /// Updates RTT estimate. Returns `true` if the packet was found.
    pub fn on_ack(&mut self, sequence: u64) -> bool {
        if let Some(pos) = self.in_flight.iter().position(|p| p.sequence == sequence) {
            let packet = self.in_flight.remove(pos);
            let rtt = packet.sent_at.elapsed();

            self.srtt = Some(match self.srtt {
                None => rtt,
                Some(srtt) => {
                    let srtt_ns = srtt.as_nanos() as u64;
                    let rtt_ns = rtt.as_nanos() as u64;
                    Duration::from_nanos(srtt_ns / 8 * 7 + rtt_ns / 8)
                }
            });

            if let Some(srtt) = self.srtt {
                self.rto = (srtt * 2).max(Duration::from_millis(50));
            }

            self.acked.insert(sequence);
            self.total_acked += 1;
            debug!(sequence, rtt_ms = rtt.as_millis(), in_flight = self.in_flight.len(), "Packet acked");
            true
        } else {
            warn!(sequence, "on_ack() for unknown or duplicate sequence");
            false
        }
    }

    /// Returns all in-flight packets that have exceeded the retransmission timeout.
    ///
    /// Resets `sent_at` for each timed-out packet.
    pub fn timed_out_packets(&mut self) -> Vec<u64> {
        let rto = self.rto;
        let mut timed_out = Vec::new();
        for packet in self.in_flight.iter_mut() {
            if packet.is_timed_out(rto) {
                warn!(
                    sequence = packet.sequence,
                    retransmit_count = packet.retransmit_count,
                    rto_ms = rto.as_millis(),
                    "Packet timed out"
                );
                timed_out.push(packet.sequence);
                packet.retransmit_count += 1;
                packet.sent_at = Instant::now();
                self.total_lost += 1;
            }
        }
        timed_out
    }

    // ─── Stats ────────────────────────────────────────────────────────────────

    /// Returns the current smoothed RTT estimate.
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// Returns the current retransmission timeout.
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Returns total packets sent.
    pub fn total_sent(&self) -> u64 {
        self.total_sent
    }

    /// Returns total packets acknowledged.
    pub fn total_acked(&self) -> u64 {
        self.total_acked
    }

    /// Returns total packets detected as lost.
    pub fn total_lost(&self) -> u64 {
        self.total_lost
    }

    /// Returns the packet loss rate as a value between 0.0 and 1.0.
    pub fn loss_rate(&self) -> f64 {
        if self.total_sent == 0 { return 0.0; }
        self.total_lost as f64 / self.total_sent as f64
    }

    /// Returns `true` if a sequence number has been acknowledged.
    pub fn is_acked(&self, sequence: u64) -> bool {
        self.acked.contains(&sequence)
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        debug!("FlowController reset");
        self.in_flight.clear();
        self.acked.clear();
        self.srtt = None;
        self.total_sent = 0;
        self.total_acked = 0;
        self.total_lost = 0;
    }
}

impl Default for FlowController {
    fn default() -> Self {
        Self::new(64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let fc = FlowController::new(4);
        assert_eq!(fc.window_size(), 4);
        assert_eq!(fc.in_flight_count(), 0);
        assert!(fc.can_send());
        assert_eq!(fc.available_slots(), 4);
    }

    #[test]
    fn test_window_full() {
        let mut fc = FlowController::new(3);
        assert!(fc.on_send(0));
        assert!(fc.on_send(1));
        assert!(fc.on_send(2));
        assert!(!fc.can_send());
        assert_eq!(fc.available_slots(), 0);
        assert_eq!(fc.in_flight_count(), 3);
    }

    #[test]
    fn test_ack_opens_window() {
        let mut fc = FlowController::new(2);
        fc.on_send(0);
        fc.on_send(1);
        assert!(!fc.can_send());
        fc.on_ack(0);
        assert!(fc.can_send());
        assert_eq!(fc.available_slots(), 1);
    }

    #[test]
    fn test_ack_unknown_sequence() {
        let mut fc = FlowController::new(4);
        fc.on_send(0);
        assert!(!fc.on_ack(99));
        assert_eq!(fc.in_flight_count(), 1);
    }

    #[test]
    fn test_is_acked() {
        let mut fc = FlowController::new(4);
        fc.on_send(0);
        assert!(!fc.is_acked(0));
        fc.on_ack(0);
        assert!(fc.is_acked(0));
    }

    #[test]
    fn test_stats() {
        let mut fc = FlowController::new(10);
        fc.on_send(0);
        fc.on_send(1);
        fc.on_send(2);
        fc.on_ack(0);
        fc.on_ack(1);
        assert_eq!(fc.total_sent(), 3);
        assert_eq!(fc.total_acked(), 2);
        assert_eq!(fc.in_flight_count(), 1);
    }

    #[test]
    fn test_loss_rate_zero() {
        let fc = FlowController::new(4);
        assert_eq!(fc.loss_rate(), 0.0);
    }

    #[test]
    fn test_set_window_size() {
        let mut fc = FlowController::new(4);
        fc.set_window_size(8);
        assert_eq!(fc.window_size(), 8);
        assert_eq!(fc.available_slots(), 8);
    }

    #[test]
    fn test_reset() {
        let mut fc = FlowController::new(4);
        fc.on_send(0);
        fc.on_send(1);
        fc.on_ack(0);
        fc.reset();
        assert_eq!(fc.in_flight_count(), 0);
        assert_eq!(fc.total_sent(), 0);
        assert_eq!(fc.total_acked(), 0);
        assert!(fc.srtt().is_none());
    }

    #[test]
    fn test_timed_out_packets() {
        let mut fc = FlowController::with_rto(4, 1);
        fc.on_send(0);
        fc.on_send(1);
        std::thread::sleep(Duration::from_millis(5));
        let timed_out = fc.timed_out_packets();
        assert_eq!(timed_out.len(), 2);
        assert!(timed_out.contains(&0));
        assert!(timed_out.contains(&1));
        assert_eq!(fc.total_lost(), 2);
    }

    #[test]
    fn test_srtt_updated_on_ack() {
        let mut fc = FlowController::new(4);
        fc.on_send(0);
        assert!(fc.srtt().is_none());
        fc.on_ack(0);
        assert!(fc.srtt().is_some());
    }

    #[test]
    fn test_default() {
        let fc = FlowController::default();
        assert_eq!(fc.window_size(), 64);
    }

    #[test]
    fn test_on_send_full_window_returns_false() {
        let mut fc = FlowController::new(1);
        assert!(fc.on_send(0));
        assert!(!fc.on_send(1));
    }

    #[test]
    fn test_multiple_acks() {
        let mut fc = FlowController::new(10);
        for i in 0..10 { fc.on_send(i); }
        for i in 0..10 { assert!(fc.on_ack(i)); }
        assert_eq!(fc.total_acked(), 10);
        assert_eq!(fc.in_flight_count(), 0);
        assert_eq!(fc.available_slots(), 10);
    }

    #[test]
    fn test_oldest_unacked_sequence() {
        let mut fc = FlowController::new(4);
        assert!(fc.oldest_unacked_sequence().is_none());
        fc.on_send(5);
        fc.on_send(6);
        assert_eq!(fc.oldest_unacked_sequence(), Some(5));
        fc.on_ack(5);
        assert_eq!(fc.oldest_unacked_sequence(), Some(6));
    }
}
