//! # VCL Flow Control & Congestion Control
//!
//! [`FlowController`] implements sliding window flow control with
//! AIMD (Additive Increase Multiplicative Decrease) congestion control
//! and retransmission support.
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
//! ## Congestion Control (AIMD)
//!
//! ```text
//! No loss:  cwnd += 1 per RTT    (additive increase)
//! Loss:     cwnd *= 0.5          (multiplicative decrease)
//! Min cwnd: 1
//! Max cwnd: bounded by window_size
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
use tracing::{debug, info, warn};

/// Default retransmission timeout in milliseconds.
const DEFAULT_RTO_MS: u64 = 200;

/// AIMD additive increase step — cwnd grows by this per ack.
const AIMD_INCREASE_STEP: f64 = 1.0;

/// AIMD multiplicative decrease factor — cwnd halved on loss.
const AIMD_DECREASE_FACTOR: f64 = 0.5;

/// Minimum congestion window size (always at least 1).
const CWND_MIN: f64 = 1.0;

/// A packet that has been sent but not yet acknowledged.
#[derive(Debug, Clone)]
pub struct InFlightPacket {
    /// Sequence number of the packet.
    pub sequence: u64,
    /// When this packet was last sent or retransmitted.
    pub sent_at: Instant,
    /// Number of times this packet has been retransmitted.
    pub retransmit_count: u32,
    /// Original data payload — stored for retransmission.
    pub data: Vec<u8>,
}

impl InFlightPacket {
    fn new(sequence: u64, data: Vec<u8>) -> Self {
        InFlightPacket {
            sequence,
            sent_at: Instant::now(),
            retransmit_count: 0,
            data,
        }
    }

    /// Returns `true` if this packet has exceeded the retransmission timeout.
    pub fn is_timed_out(&self, rto: Duration) -> bool {
        self.sent_at.elapsed() > rto
    }
}

/// A packet that needs to be retransmitted.
#[derive(Debug, Clone)]
pub struct RetransmitRequest {
    /// Sequence number of the packet to retransmit.
    pub sequence: u64,
    /// Original data payload to resend.
    pub data: Vec<u8>,
    /// How many times this packet has already been retransmitted.
    pub retransmit_count: u32,
}

/// Sliding window flow controller with AIMD congestion control
/// and retransmission support.
///
/// Tracks in-flight packets, controls send rate, detects losses,
/// and provides packets that need retransmission.
pub struct FlowController {
    /// Hard maximum — set at construction, never exceeded.
    window_size: usize,
    /// Congestion window — dynamically adjusted by AIMD.
    cwnd: f64,
    /// Slow start threshold.
    ssthresh: f64,
    /// Whether we are in slow start phase.
    in_slow_start: bool,
    /// Currently in-flight packets.
    in_flight: Vec<InFlightPacket>,
    /// Sequence numbers that have been acknowledged.
    acked: BTreeSet<u64>,
    /// Retransmission timeout.
    rto: Duration,
    /// Smoothed round-trip time estimate.
    srtt: Option<Duration>,
    /// RTT variance estimate.
    rttvar: Option<Duration>,
    /// Total packets sent (including retransmissions).
    total_sent: u64,
    /// Total packets acknowledged.
    total_acked: u64,
    /// Total packets detected as lost.
    total_lost: u64,
    /// Total retransmissions performed.
    total_retransmits: u64,
}

impl FlowController {
    /// Create a new flow controller with the given maximum window size.
    ///
    /// The congestion window starts at 1 and grows via slow start / AIMD.
    pub fn new(window_size: usize) -> Self {
        debug!(window_size, "FlowController created");
        FlowController {
            window_size,
            cwnd: 1.0,
            ssthresh: window_size as f64 / 2.0,
            in_slow_start: true,
            in_flight: Vec::new(),
            acked: BTreeSet::new(),
            rto: Duration::from_millis(DEFAULT_RTO_MS),
            srtt: None,
            rttvar: None,
            total_sent: 0,
            total_acked: 0,
            total_lost: 0,
            total_retransmits: 0,
        }
    }

    /// Create a flow controller with a custom retransmission timeout.
    pub fn with_rto(window_size: usize, rto_ms: u64) -> Self {
        let mut fc = Self::new(window_size);
        fc.rto = Duration::from_millis(rto_ms);
        fc
    }

    // ─── Window control ───────────────────────────────────────────────────────

    /// Returns `true` if the effective window (min of cwnd and window_size)
    /// has space to send another packet.
    pub fn can_send(&self) -> bool {
        let effective = self.effective_window();
        self.in_flight.len() < effective
    }

    /// Returns how many more packets can be sent right now.
    pub fn available_slots(&self) -> usize {
        let effective = self.effective_window();
        effective.saturating_sub(self.in_flight.len())
    }

    /// Returns the hard maximum window size set at construction.
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Returns the current congestion window size (float, AIMD-adjusted).
    pub fn cwnd(&self) -> f64 {
        self.cwnd
    }

    /// Returns the effective window: min(cwnd as usize, window_size), at least 1.
    pub fn effective_window(&self) -> usize {
        let cwnd_int = self.cwnd as usize;
        cwnd_int.min(self.window_size).max(1)
    }

    /// Returns `true` if currently in slow start phase.
    pub fn in_slow_start(&self) -> bool {
        self.in_slow_start
    }

    /// Dynamically adjust the hard maximum window size.
    pub fn set_window_size(&mut self, size: usize) {
        debug!(old = self.window_size, new = size, "Window size updated");
        self.window_size = size;
    }

    /// Returns the number of packets currently in flight.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Returns the sequence number of the oldest unacknowledged packet,
    /// or `None` if there are no packets in flight.
    pub fn oldest_unacked_sequence(&self) -> Option<u64> {
        self.in_flight.first().map(|p| p.sequence)
    }

    // ─── Send / Ack ───────────────────────────────────────────────────────────

    /// Register a packet as sent with its data payload (for retransmission).
    ///
    /// Returns `false` if the effective window is full.
    pub fn on_send(&mut self, sequence: u64, data: Vec<u8>) -> bool {
        if !self.can_send() {
            warn!(
                sequence,
                in_flight = self.in_flight.len(),
                cwnd = self.cwnd,
                "on_send() called but window is full"
            );
            return false;
        }
        self.in_flight.push(InFlightPacket::new(sequence, data));
        self.total_sent += 1;
        debug!(
            sequence,
            in_flight = self.in_flight.len(),
            cwnd = self.cwnd,
            effective_window = self.effective_window(),
            "Packet sent"
        );
        true
    }

    /// Register a packet as acknowledged.
    ///
    /// Updates RTT estimate and advances the congestion window via AIMD.
    /// Returns `true` if the packet was found and removed.
    pub fn on_ack(&mut self, sequence: u64) -> bool {
        if let Some(pos) = self.in_flight.iter().position(|p| p.sequence == sequence) {
            let packet = self.in_flight.remove(pos);
            let rtt = packet.sent_at.elapsed();

            // RFC 6298 RTT estimation
            self.update_rtt(rtt);

            self.acked.insert(sequence);
            self.total_acked += 1;

            // AIMD congestion control
            self.on_ack_cwnd();

            debug!(
                sequence,
                rtt_ms = rtt.as_millis(),
                in_flight = self.in_flight.len(),
                cwnd = self.cwnd,
                in_slow_start = self.in_slow_start,
                "Packet acked"
            );
            true
        } else {
            warn!(sequence, "on_ack() for unknown or duplicate sequence");
            false
        }
    }

    /// Returns all in-flight packets that have exceeded the retransmission timeout,
    /// as [`RetransmitRequest`]s containing the data to resend.
    ///
    /// Resets `sent_at` for each timed-out packet and increments `retransmit_count`.
    /// Also triggers AIMD multiplicative decrease (congestion detected).
    pub fn timed_out_packets(&mut self) -> Vec<RetransmitRequest> {
        let rto = self.rto;
        let mut requests = Vec::new();
        let mut had_loss = false;

        for packet in self.in_flight.iter_mut() {
            if packet.is_timed_out(rto) {
                warn!(
                    sequence = packet.sequence,
                    retransmit_count = packet.retransmit_count,
                    rto_ms = rto.as_millis(),
                    "Packet timed out — queuing retransmission"
                );
                requests.push(RetransmitRequest {
                    sequence: packet.sequence,
                    data: packet.data.clone(),
                    retransmit_count: packet.retransmit_count,
                });
                packet.retransmit_count += 1;
                packet.sent_at = Instant::now();
                self.total_lost += 1;
                self.total_retransmits += 1;
                had_loss = true;
            }
        }

        if had_loss {
            self.on_loss_cwnd();
        }

        requests
    }

    // ─── AIMD internals ───────────────────────────────────────────────────────

    fn on_ack_cwnd(&mut self) {
        if self.in_slow_start {
            // Slow start: exponential growth
            self.cwnd += AIMD_INCREASE_STEP;
            if self.cwnd >= self.ssthresh {
                self.in_slow_start = false;
                info!(cwnd = self.cwnd, ssthresh = self.ssthresh, "Exiting slow start");
            }
        } else {
            // Congestion avoidance: additive increase (1/cwnd per ack ≈ 1 per RTT)
            self.cwnd += AIMD_INCREASE_STEP / self.cwnd;
        }
        self.cwnd = self.cwnd.min(self.window_size as f64);
        debug!(cwnd = self.cwnd, "AIMD: cwnd increased");
    }

    fn on_loss_cwnd(&mut self) {
        // Multiplicative decrease
        self.ssthresh = (self.cwnd * AIMD_DECREASE_FACTOR).max(CWND_MIN);
        self.cwnd = CWND_MIN;
        self.in_slow_start = true;
        // Double RTO on loss (exponential backoff)
        self.rto = (self.rto * 2).min(Duration::from_secs(60));
        warn!(
            cwnd = self.cwnd,
            ssthresh = self.ssthresh,
            rto_ms = self.rto.as_millis(),
            "AIMD: multiplicative decrease on loss"
        );
    }

    // ─── RTT estimation (RFC 6298) ────────────────────────────────────────────

    fn update_rtt(&mut self, rtt: Duration) {
        match (self.srtt, self.rttvar) {
            (None, None) => {
                // First sample
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2);
            }
            (Some(srtt), Some(rttvar)) => {
                // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
                // SRTT   = (1 - alpha) * SRTT + alpha * R
                // alpha = 1/8, beta = 1/4
                let rtt_ns = rtt.as_nanos() as i128;
                let srtt_ns = srtt.as_nanos() as i128;
                let rttvar_ns = rttvar.as_nanos() as i128;

                let new_rttvar = (rttvar_ns * 3 / 4 + (srtt_ns - rtt_ns).abs() / 4)
                    .max(0) as u64;
                let new_srtt = (srtt_ns * 7 / 8 + rtt_ns / 8).max(1) as u64;

                self.rttvar = Some(Duration::from_nanos(new_rttvar));
                self.srtt = Some(Duration::from_nanos(new_srtt));

                // RTO = SRTT + max(G, 4 * RTTVAR), min 50ms, max 60s
                let rto_ns = new_srtt + (new_rttvar * 4).max(1_000_000);
                self.rto = Duration::from_nanos(rto_ns)
                    .max(Duration::from_millis(50))
                    .min(Duration::from_secs(60));
            }
            _ => {}
        }
    }

    // ─── Stats ────────────────────────────────────────────────────────────────

    /// Returns the current smoothed RTT estimate.
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// Returns the current RTT variance estimate.
    pub fn rttvar(&self) -> Option<Duration> {
        self.rttvar
    }

    /// Returns the current retransmission timeout.
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Returns total packets sent (including retransmissions).
    pub fn total_sent(&self) -> u64 {
        self.total_sent
    }

    /// Returns total packets acknowledged.
    pub fn total_acked(&self) -> u64 {
        self.total_acked
    }

    /// Returns total packets detected as lost (timed out).
    pub fn total_lost(&self) -> u64 {
        self.total_lost
    }

    /// Returns total retransmissions performed.
    pub fn total_retransmits(&self) -> u64 {
        self.total_retransmits
    }

    /// Returns the packet loss rate: lost / sent. Returns 0.0 if nothing sent.
    pub fn loss_rate(&self) -> f64 {
        if self.total_sent == 0 {
            return 0.0;
        }
        self.total_lost as f64 / self.total_sent as f64
    }

    /// Returns `true` if a sequence number has been acknowledged.
    pub fn is_acked(&self, sequence: u64) -> bool {
        self.acked.contains(&sequence)
    }

    /// Reset all state. Call when a connection is re-established.
    pub fn reset(&mut self) {
        debug!("FlowController reset");
        let window_size = self.window_size;
        *self = Self::new(window_size);
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
        assert_eq!(fc.available_slots(), 1); // cwnd starts at 1
        assert!(fc.in_slow_start());
    }

    #[test]
    fn test_window_full() {
        let mut fc = FlowController::new(4);
        // cwnd starts at 1, so only 1 slot
        assert!(fc.on_send(0, vec![0]));
        assert!(!fc.can_send());
        assert_eq!(fc.in_flight_count(), 1);
    }

    #[test]
    fn test_ack_opens_window_and_grows_cwnd() {
        let mut fc = FlowController::new(4);
        assert!(fc.on_send(0, vec![0]));
        assert!(!fc.can_send());
        let cwnd_before = fc.cwnd();
        fc.on_ack(0);
        assert!(fc.cwnd() > cwnd_before);
        assert!(fc.can_send());
    }

    #[test]
    fn test_ack_unknown_sequence() {
        let mut fc = FlowController::new(4);
        fc.on_send(0, vec![0]);
        assert!(!fc.on_ack(99));
        assert_eq!(fc.in_flight_count(), 1);
    }

    #[test]
    fn test_is_acked() {
        let mut fc = FlowController::new(4);
        fc.on_send(0, vec![0]);
        assert!(!fc.is_acked(0));
        fc.on_ack(0);
        assert!(fc.is_acked(0));
    }

    #[test]
    fn test_stats() {
        let mut fc = FlowController::new(10);
        // Grow cwnd first
        for i in 0..5 {
            fc.on_send(i, vec![0]);
            fc.on_ack(i);
        }
        fc.on_send(5, vec![0]);
        fc.on_send(6, vec![0]);
        fc.on_send(7, vec![0]);
        assert_eq!(fc.total_acked(), 5);
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
    }

    #[test]
    fn test_reset() {
        let mut fc = FlowController::new(4);
        fc.on_send(0, vec![0]);
        fc.on_ack(0);
        fc.reset();
        assert_eq!(fc.in_flight_count(), 0);
        assert_eq!(fc.total_sent(), 0);
        assert_eq!(fc.total_acked(), 0);
        assert!(fc.srtt().is_none());
        assert!(fc.in_slow_start());
        assert_eq!(fc.cwnd(), 1.0);
    }

    #[test]
    fn test_timed_out_packets_returns_retransmit_requests() {
        let mut fc = FlowController::with_rto(4, 1); // 1ms RTO
        fc.on_send(0, b"hello".to_vec());
        fc.on_send(1, b"world".to_vec());
        // Grow cwnd first so we can send 2
        // Actually with cwnd=1 we can only send 1, let's ack first to grow
        // Reset and try differently
        let mut fc = FlowController::with_rto(4, 1);
        // Send one packet
        fc.on_send(0, b"hello".to_vec());
        std::thread::sleep(Duration::from_millis(5));
        let requests = fc.timed_out_packets();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].sequence, 0);
        assert_eq!(requests[0].data, b"hello");
        assert_eq!(requests[0].retransmit_count, 0);
        assert_eq!(fc.total_lost(), 1);
        assert_eq!(fc.total_retransmits(), 1);
    }

    #[test]
    fn test_aimd_multiplicative_decrease_on_loss() {
        let mut fc = FlowController::with_rto(16, 1);
        // Grow cwnd by acking many packets
        for i in 0..20u64 {
            if fc.can_send() {
                fc.on_send(i, vec![0]);
                fc.on_ack(i);
            }
        }
        let cwnd_before = fc.cwnd();
        assert!(cwnd_before > 1.0);

        // Now cause a loss
        if fc.can_send() {
            fc.on_send(100, vec![0]);
        }
        std::thread::sleep(Duration::from_millis(5));
        fc.timed_out_packets();

        assert_eq!(fc.cwnd(), 1.0); // reset to min
        assert!(fc.in_slow_start()); // back in slow start
    }

    #[test]
    fn test_slow_start_exits_at_ssthresh() {
        let mut fc = FlowController::new(64);
        let ssthresh = fc.ssthresh;

        // Ack packets until cwnd exceeds ssthresh
        let mut i = 0u64;
        loop {
            if fc.can_send() {
                fc.on_send(i, vec![0]);
                fc.on_ack(i);
                i += 1;
            }
            if !fc.in_slow_start() {
                break;
            }
            if i > 1000 { break; }
        }

        assert!(!fc.in_slow_start());
        assert!(fc.cwnd() >= ssthresh);
    }

    #[test]
    fn test_srtt_updated_on_ack() {
        let mut fc = FlowController::new(4);
        fc.on_send(0, vec![0]);
        assert!(fc.srtt().is_none());
        fc.on_ack(0);
        assert!(fc.srtt().is_some());
        assert!(fc.rttvar().is_some());
    }

    #[test]
    fn test_default() {
        let fc = FlowController::default();
        assert_eq!(fc.window_size(), 64);
    }

    #[test]
    fn test_on_send_full_window_returns_false() {
        let mut fc = FlowController::new(4);
        // cwnd=1 so window is effectively 1
        assert!(fc.on_send(0, vec![0]));
        assert!(!fc.on_send(1, vec![0]));
    }

    #[test]
    fn test_multiple_acks_grow_cwnd() {
        let mut fc = FlowController::new(64);
        let initial_cwnd = fc.cwnd();
        for i in 0..10u64 {
            if fc.can_send() {
                fc.on_send(i, vec![0]);
                fc.on_ack(i);
            }
        }
        assert!(fc.cwnd() > initial_cwnd);
        assert_eq!(fc.total_acked(), 10);
    }

    #[test]
    fn test_oldest_unacked_sequence() {
        let mut fc = FlowController::new(4);
        assert!(fc.oldest_unacked_sequence().is_none());
        fc.on_send(5, vec![0]);
        assert_eq!(fc.oldest_unacked_sequence(), Some(5));
    }

    #[test]
    fn test_effective_window_bounded_by_cwnd_and_max() {
        let fc = FlowController::new(4);
        // cwnd=1, window_size=4 → effective=1
        assert_eq!(fc.effective_window(), 1);
    }

    #[test]
    fn test_rto_doubles_on_loss() {
        let mut fc = FlowController::with_rto(4, 1);
        let rto_before = fc.rto();
        fc.on_send(0, vec![0]);
        std::thread::sleep(Duration::from_millis(5));
        fc.timed_out_packets();
        assert!(fc.rto() > rto_before);
    }

    #[test]
    fn test_total_retransmits() {
        let mut fc = FlowController::with_rto(4, 1);
        fc.on_send(0, vec![0]);
        std::thread::sleep(Duration::from_millis(5));
        fc.timed_out_packets();
        assert_eq!(fc.total_retransmits(), 1);

        std::thread::sleep(Duration::from_millis(10));
        fc.timed_out_packets();
        assert_eq!(fc.total_retransmits(), 2);
    }
}
