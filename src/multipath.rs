//! # VCL Multipath
//!
//! [`MultipathSender`] splits traffic across multiple network interfaces
//! simultaneously (e.g. WiFi + LTE) and [`MultipathReceiver`] reassembles
//! packets on the other side.
//!
//! ## How it works
//!
//! ```text
//! Application → MultipathSender
//!                   │
//!         ┌─────────┼─────────┐
//!         ↓         ↓         ↓
//!     Interface0  Interface1  Interface2
//!     (WiFi)      (LTE)       (Ethernet)
//!         ↓         ↓         ↓
//!         └─────────┼─────────┘
//!                   │
//!             MultipathReceiver
//!                   │
//!             Reordering buffer
//!                   │
//!             Application
//! ```
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::multipath::{MultipathSender, MultipathReceiver, PathInfo, SchedulingPolicy};
//!
//! let paths = vec![
//!     PathInfo::new("wifi",     "192.168.1.100", 100, 10),
//!     PathInfo::new("lte",      "10.0.0.50",     50,  30),
//!     PathInfo::new("ethernet", "172.16.0.1",    200, 5),
//! ];
//!
//! let sender = MultipathSender::new(paths, SchedulingPolicy::WeightedRoundRobin);
//! let mut receiver = MultipathReceiver::new();
//!
//! // sender.select_path(&data) → PathInfo to send on
//! // receiver.add(seq, path_id, data) → Some(data) when reordered
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Information about a single network path (interface).
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Human-readable name (e.g. "wifi", "lte", "eth0").
    pub name: String,
    /// Local IP address bound to this interface.
    pub local_addr: String,
    /// Estimated bandwidth in Mbps.
    pub bandwidth_mbps: u32,
    /// Estimated latency in milliseconds.
    pub latency_ms: u32,
    /// Whether this path is currently active.
    pub active: bool,
    /// Number of packets sent on this path.
    pub packets_sent: u64,
    /// Number of packets lost on this path (estimated).
    pub packets_lost: u64,
    /// Smoothed RTT for this path.
    pub srtt: Option<Duration>,
    /// When this path was last used.
    pub last_used: Option<Instant>,
}

impl PathInfo {
    /// Create a new path with name, local address, bandwidth, and latency.
    pub fn new(name: &str, local_addr: &str, bandwidth_mbps: u32, latency_ms: u32) -> Self {
        PathInfo {
            name: name.to_string(),
            local_addr: local_addr.to_string(),
            bandwidth_mbps,
            latency_ms,
            active: true,
            packets_sent: 0,
            packets_lost: 0,
            srtt: None,
            last_used: None,
        }
    }

    /// Compute a score for path selection — higher is better.
    /// Score = bandwidth / latency, penalized by loss rate.
    pub fn score(&self) -> f64 {
        if !self.active || self.latency_ms == 0 {
            return 0.0;
        }
        let base = self.bandwidth_mbps as f64 / self.latency_ms as f64;
        let loss_penalty = 1.0 - self.loss_rate();
        base * loss_penalty
    }

    /// Packet loss rate for this path (0.0 – 1.0).
    pub fn loss_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        self.packets_lost as f64 / self.packets_sent as f64
    }

    /// Update SRTT for this path using RFC 6298 smoothing.
    pub fn update_srtt(&mut self, rtt: Duration) {
        self.srtt = Some(match self.srtt {
            None => rtt,
            Some(srtt) => {
                let srtt_ns = srtt.as_nanos() as u64;
                let rtt_ns = rtt.as_nanos() as u64;
                Duration::from_nanos(srtt_ns / 8 * 7 + rtt_ns / 8)
            }
        });
    }

    /// Mark this path as having sent a packet.
    pub fn record_sent(&mut self) {
        self.packets_sent += 1;
        self.last_used = Some(Instant::now());
    }

    /// Mark a packet as lost on this path.
    pub fn record_loss(&mut self) {
        self.packets_lost += 1;
    }
}

/// Strategy for selecting which path to send a packet on.
#[derive(Debug, Clone, PartialEq)]
pub enum SchedulingPolicy {
    /// Always use the path with the highest score (bandwidth/latency).
    BestPath,
    /// Round-robin across all active paths.
    RoundRobin,
    /// Weighted round-robin — paths with higher bandwidth get more packets.
    WeightedRoundRobin,
    /// Redundant — send every packet on ALL active paths simultaneously.
    /// Highest reliability, highest bandwidth usage.
    Redundant,
    /// Lowest latency — always pick the path with smallest latency_ms.
    LowestLatency,
}

/// Sends packets across multiple paths according to a [`SchedulingPolicy`].
pub struct MultipathSender {
    paths: Vec<PathInfo>,
    policy: SchedulingPolicy,
    /// Current index for round-robin.
    rr_index: usize,
    /// Weighted round-robin counters.
    rr_weights: Vec<u32>,
    /// Total packets scheduled.
    total_scheduled: u64,
}

impl MultipathSender {
    /// Create a new sender with the given paths and scheduling policy.
    ///
    /// # Panics
    /// Panics if `paths` is empty.
    pub fn new(paths: Vec<PathInfo>, policy: SchedulingPolicy) -> Self {
        assert!(!paths.is_empty(), "MultipathSender requires at least one path");
        let rr_weights = paths.iter().map(|_| 0).collect();
        info!(
            paths = paths.len(),
            policy = ?policy,
            "MultipathSender created"
        );
        MultipathSender {
            paths,
            policy,
            rr_index: 0,
            rr_weights,
            total_scheduled: 0,
        }
    }

    /// Select the best path index for the next packet based on the policy.
    ///
    /// Returns `None` if no active paths are available.
    pub fn select_path_index(&mut self, data_len: usize) -> Option<usize> {
        let active: Vec<usize> = self.paths.iter()
            .enumerate()
            .filter(|(_, p)| p.active)
            .map(|(i, _)| i)
            .collect();

        if active.is_empty() {
            warn!("No active paths available");
            return None;
        }

        let idx = match &self.policy {
            SchedulingPolicy::BestPath => {
                active.iter()
                    .max_by(|&&a, &&b| {
                        self.paths[a].score()
                            .partial_cmp(&self.paths[b].score())
                            .unwrap()
                    })
                    .copied()
            }
            SchedulingPolicy::RoundRobin => {
                let pos = self.rr_index % active.len();
                self.rr_index += 1;
                Some(active[pos])
            }
            SchedulingPolicy::WeightedRoundRobin => {
                // Pick path with lowest sent/bandwidth ratio
                active.iter()
                    .min_by(|&&a, &&b| {
                        let ra = self.paths[a].packets_sent as f64
                            / self.paths[a].bandwidth_mbps.max(1) as f64;
                        let rb = self.paths[b].packets_sent as f64
                            / self.paths[b].bandwidth_mbps.max(1) as f64;
                        ra.partial_cmp(&rb).unwrap()
                    })
                    .copied()
            }
            SchedulingPolicy::Redundant => {
                // Return first — caller should use select_all_paths for redundant
                Some(active[0])
            }
            SchedulingPolicy::LowestLatency => {
                active.iter()
                    .min_by_key(|&&i| self.paths[i].latency_ms)
                    .copied()
            }
        };

        if let Some(i) = idx {
            self.paths[i].record_sent();
            self.total_scheduled += 1;
            debug!(
                path = %self.paths[i].name,
                data_len,
                policy = ?self.policy,
                "Path selected"
            );
        }
        idx
    }

    /// For `Redundant` policy — returns ALL active path indices.
    ///
    /// Each path should receive a copy of the packet.
    pub fn select_all_paths(&mut self) -> Vec<usize> {
        let active: Vec<usize> = self.paths.iter()
            .enumerate()
            .filter(|(_, p)| p.active)
            .map(|(i, _)| i)
            .collect();

        for &i in &active {
            self.paths[i].record_sent();
        }
        self.total_scheduled += 1;
        active
    }

    /// Get an immutable reference to a path by index.
    pub fn path(&self, index: usize) -> Option<&PathInfo> {
        self.paths.get(index)
    }

    /// Get a mutable reference to a path by index.
    pub fn path_mut(&mut self, index: usize) -> Option<&mut PathInfo> {
        self.paths.get_mut(index)
    }

    /// Returns all paths.
    pub fn paths(&self) -> &[PathInfo] {
        &self.paths
    }

    /// Returns the number of active paths.
    pub fn active_path_count(&self) -> usize {
        self.paths.iter().filter(|p| p.active).count()
    }

    /// Mark a path as inactive (e.g. interface went down).
    pub fn deactivate_path(&mut self, index: usize) {
        if let Some(path) = self.paths.get_mut(index) {
            warn!(name = %path.name, "Path deactivated");
            path.active = false;
        }
    }

    /// Mark a path as active again (e.g. interface came back up).
    pub fn activate_path(&mut self, index: usize) {
        if let Some(path) = self.paths.get_mut(index) {
            info!(name = %path.name, "Path reactivated");
            path.active = true;
        }
    }

    /// Record a packet loss on a specific path.
    pub fn record_loss(&mut self, index: usize) {
        if let Some(path) = self.paths.get_mut(index) {
            path.record_loss();
        }
    }

    /// Update RTT estimate for a specific path.
    pub fn update_rtt(&mut self, index: usize, rtt: Duration) {
        if let Some(path) = self.paths.get_mut(index) {
            path.update_srtt(rtt);
        }
    }

    /// Total packets scheduled across all paths.
    pub fn total_scheduled(&self) -> u64 {
        self.total_scheduled
    }

    /// Change the scheduling policy at runtime.
    pub fn set_policy(&mut self, policy: SchedulingPolicy) {
        info!(policy = ?policy, "Scheduling policy changed");
        self.policy = policy;
    }

    /// Returns the current scheduling policy.
    pub fn policy(&self) -> &SchedulingPolicy {
        &self.policy
    }
}

/// A reordering buffer for packets received on multiple paths.
///
/// Packets may arrive out of order when using multipath — this buffer
/// holds them and releases them in sequence order.
pub struct MultipathReceiver {
    /// Pending out-of-order packets: seq → (path_id, data).
    pending: HashMap<u64, (String, Vec<u8>)>,
    /// Next expected sequence number.
    next_seq: u64,
    /// Maximum number of out-of-order packets to buffer.
    max_buffer: usize,
    /// Total packets received.
    total_received: u64,
    /// Total packets delivered in order.
    total_delivered: u64,
    /// Total duplicate packets dropped.
    total_duplicates: u64,
}

impl MultipathReceiver {
    /// Create a new receiver with default buffer size (256).
    pub fn new() -> Self {
        MultipathReceiver {
            pending: HashMap::new(),
            next_seq: 0,
            max_buffer: 256,
            total_received: 0,
            total_delivered: 0,
            total_duplicates: 0,
        }
    }

    /// Create a receiver with a custom reorder buffer size.
    pub fn with_buffer_size(max_buffer: usize) -> Self {
        MultipathReceiver {
            pending: HashMap::new(),
            next_seq: 0,
            max_buffer,
            total_received: 0,
            total_delivered: 0,
            total_duplicates: 0,
        }
    }

    /// Add a received packet.
    ///
    /// Returns `Some((path_id, data))` if this completes an in-order sequence,
    /// or `None` if the packet is buffered waiting for earlier packets.
    ///
    /// Duplicate packets (same seq already seen) are silently dropped.
    pub fn add(&mut self, seq: u64, path_id: &str, data: Vec<u8>) -> Option<(String, Vec<u8>)> {
        self.total_received += 1;

        // Already delivered
        if seq < self.next_seq {
            warn!(seq, path = %path_id, "Duplicate/old multipath packet dropped");
            self.total_duplicates += 1;
            return None;
        }

        // In-order delivery
        if seq == self.next_seq {
            self.next_seq += 1;
            self.total_delivered += 1;
            debug!(seq, path = %path_id, "In-order multipath packet delivered");
            return Some((path_id.to_string(), data));
        }

        // Out of order — buffer it
        if self.pending.len() >= self.max_buffer {
            warn!(
                seq,
                pending = self.pending.len(),
                max = self.max_buffer,
                "Reorder buffer full, dropping packet"
            );
            return None;
        }

        // Check for duplicate in pending
        if self.pending.contains_key(&seq) {
            warn!(seq, "Duplicate multipath packet in pending buffer");
            self.total_duplicates += 1;
            return None;
        }

        debug!(seq, path = %path_id, pending = self.pending.len(), "Buffering out-of-order packet");
        self.pending.insert(seq, (path_id.to_string(), data));
        None
    }

    /// Try to drain buffered packets that are now in order.
    ///
    /// Call after `add()` returns `Some(...)` to flush any buffered packets.
    /// Returns packets in sequence order.
    pub fn drain_ordered(&mut self) -> Vec<(u64, String, Vec<u8>)> {
        let mut result = Vec::new();
        while let Some((path_id, data)) = self.pending.remove(&self.next_seq) {
            debug!(seq = self.next_seq, path = %path_id, "Drained buffered packet");
            result.push((self.next_seq, path_id, data));
            self.next_seq += 1;
            self.total_delivered += 1;
        }
        result
    }

    /// Returns the next expected sequence number.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Returns the number of packets currently buffered.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Clear all buffered packets.
    pub fn clear(&mut self) {
        let dropped = self.pending.len();
        if dropped > 0 {
            warn!(dropped, "Multipath receiver buffer cleared");
        }
        self.pending.clear();
    }

    /// Total packets received (including duplicates and out-of-order).
    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    /// Total packets delivered in order.
    pub fn total_delivered(&self) -> u64 {
        self.total_delivered
    }

    /// Total duplicate packets dropped.
    pub fn total_duplicates(&self) -> u64 {
        self.total_duplicates
    }
}

impl Default for MultipathReceiver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_paths() -> Vec<PathInfo> {
        vec![
            PathInfo::new("wifi",     "192.168.1.100", 100, 10),
            PathInfo::new("lte",      "10.0.0.50",     50,  30),
        ]
    }

    fn three_paths() -> Vec<PathInfo> {
        vec![
            PathInfo::new("wifi",     "192.168.1.100", 100, 10),
            PathInfo::new("lte",      "10.0.0.50",     50,  30),
            PathInfo::new("ethernet", "172.16.0.1",    200, 5),
        ]
    }

    // ─── PathInfo tests ───────────────────────────────────────────────────────

    #[test]
    fn test_path_info_new() {
        let p = PathInfo::new("wifi", "192.168.1.1", 100, 10);
        assert_eq!(p.name, "wifi");
        assert_eq!(p.bandwidth_mbps, 100);
        assert_eq!(p.latency_ms, 10);
        assert!(p.active);
        assert_eq!(p.loss_rate(), 0.0);
    }

    #[test]
    fn test_path_score() {
        let p = PathInfo::new("fast", "1.1.1.1", 100, 10);
        let slow = PathInfo::new("slow", "2.2.2.2", 10, 100);
        assert!(p.score() > slow.score());
    }

    #[test]
    fn test_path_score_inactive() {
        let mut p = PathInfo::new("wifi", "1.1.1.1", 100, 10);
        p.active = false;
        assert_eq!(p.score(), 0.0);
    }

    #[test]
    fn test_path_loss_rate() {
        let mut p = PathInfo::new("wifi", "1.1.1.1", 100, 10);
        p.packets_sent = 100;
        p.packets_lost = 10;
        assert!((p.loss_rate() - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_path_update_srtt() {
        let mut p = PathInfo::new("wifi", "1.1.1.1", 100, 10);
        assert!(p.srtt.is_none());
        p.update_srtt(Duration::from_millis(20));
        assert!(p.srtt.is_some());
        p.update_srtt(Duration::from_millis(10));
        assert!(p.srtt.unwrap() < Duration::from_millis(20));
    }

    #[test]
    fn test_path_record_sent() {
        let mut p = PathInfo::new("wifi", "1.1.1.1", 100, 10);
        p.record_sent();
        assert_eq!(p.packets_sent, 1);
        assert!(p.last_used.is_some());
    }

    // ─── MultipathSender tests ────────────────────────────────────────────────

    #[test]
    fn test_sender_best_path() {
        let mut s = MultipathSender::new(three_paths(), SchedulingPolicy::BestPath);
        // ethernet has highest score (200/5 = 40)
        let idx = s.select_path_index(100).unwrap();
        assert_eq!(s.paths()[idx].name, "ethernet");
    }

    #[test]
    fn test_sender_lowest_latency() {
        let mut s = MultipathSender::new(three_paths(), SchedulingPolicy::LowestLatency);
        let idx = s.select_path_index(100).unwrap();
        assert_eq!(s.paths()[idx].name, "ethernet"); // latency=5
    }

    #[test]
    fn test_sender_round_robin() {
        let mut s = MultipathSender::new(two_paths(), SchedulingPolicy::RoundRobin);
        let i0 = s.select_path_index(100).unwrap();
        let i1 = s.select_path_index(100).unwrap();
        let i2 = s.select_path_index(100).unwrap();
        // Should alternate
        assert_ne!(i0, i1);
        assert_eq!(i0, i2);
    }

    #[test]
    fn test_sender_weighted_round_robin() {
        let mut s = MultipathSender::new(two_paths(), SchedulingPolicy::WeightedRoundRobin);
        // wifi has higher bandwidth so should be selected more often
        let mut wifi_count = 0;
        let mut lte_count = 0;
        for _ in 0..20 {
            let idx = s.select_path_index(100).unwrap();
            if s.paths()[idx].name == "wifi" {
                wifi_count += 1;
            } else {
                lte_count += 1;
            }
        }
        assert!(wifi_count > lte_count);
    }

    #[test]
    fn test_sender_redundant_all_paths() {
        let mut s = MultipathSender::new(three_paths(), SchedulingPolicy::Redundant);
        let indices = s.select_all_paths();
        assert_eq!(indices.len(), 3);
    }

    #[test]
    fn test_sender_deactivate_path() {
        let mut s = MultipathSender::new(two_paths(), SchedulingPolicy::BestPath);
        assert_eq!(s.active_path_count(), 2);
        s.deactivate_path(0);
        assert_eq!(s.active_path_count(), 1);
        let idx = s.select_path_index(100).unwrap();
        assert_eq!(s.paths()[idx].name, "lte");
    }

    #[test]
    fn test_sender_activate_path() {
        let mut s = MultipathSender::new(two_paths(), SchedulingPolicy::BestPath);
        s.deactivate_path(0);
        assert_eq!(s.active_path_count(), 1);
        s.activate_path(0);
        assert_eq!(s.active_path_count(), 2);
    }

    #[test]
    fn test_sender_no_active_paths() {
        let mut s = MultipathSender::new(two_paths(), SchedulingPolicy::BestPath);
        s.deactivate_path(0);
        s.deactivate_path(1);
        assert!(s.select_path_index(100).is_none());
    }

    #[test]
    fn test_sender_record_loss() {
        let mut s = MultipathSender::new(two_paths(), SchedulingPolicy::BestPath);
        s.select_path_index(100);
        s.record_loss(0);
        assert_eq!(s.paths()[0].packets_lost, 1);
    }

    #[test]
    fn test_sender_update_rtt() {
        let mut s = MultipathSender::new(two_paths(), SchedulingPolicy::BestPath);
        s.update_rtt(0, Duration::from_millis(15));
        assert!(s.paths()[0].srtt.is_some());
    }

    #[test]
    fn test_sender_set_policy() {
        let mut s = MultipathSender::new(two_paths(), SchedulingPolicy::BestPath);
        assert_eq!(s.policy(), &SchedulingPolicy::BestPath);
        s.set_policy(SchedulingPolicy::RoundRobin);
        assert_eq!(s.policy(), &SchedulingPolicy::RoundRobin);
    }

    #[test]
    fn test_sender_total_scheduled() {
        let mut s = MultipathSender::new(two_paths(), SchedulingPolicy::RoundRobin);
        s.select_path_index(100);
        s.select_path_index(100);
        s.select_path_index(100);
        assert_eq!(s.total_scheduled(), 3);
    }

    // ─── MultipathReceiver tests ──────────────────────────────────────────────

    #[test]
    fn test_receiver_in_order() {
        let mut r = MultipathReceiver::new();
        let result = r.add(0, "wifi", b"hello".to_vec());
        assert!(result.is_some());
        let (path, data) = result.unwrap();
        assert_eq!(path, "wifi");
        assert_eq!(data, b"hello");
        assert_eq!(r.next_seq(), 1);
    }

    #[test]
    fn test_receiver_out_of_order() {
        let mut r = MultipathReceiver::new();
        // seq=1 arrives before seq=0
        let r1 = r.add(1, "lte", b"second".to_vec());
        assert!(r1.is_none()); // buffered
        assert_eq!(r.pending_count(), 1);

        let r0 = r.add(0, "wifi", b"first".to_vec());
        assert!(r0.is_some()); // delivered
        let (_, data) = r0.unwrap();
        assert_eq!(data, b"first");

        // Now drain seq=1
        let drained = r.drain_ordered();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 1);
        assert_eq!(drained[0].2, b"second");
        assert_eq!(r.next_seq(), 2);
        assert_eq!(r.pending_count(), 0);
    }

    #[test]
    fn test_receiver_duplicate() {
        let mut r = MultipathReceiver::new();
        r.add(0, "wifi", b"first".to_vec());
        // Same seq again from different path (redundant mode)
        let dup = r.add(0, "lte", b"first".to_vec());
        assert!(dup.is_none());
        assert_eq!(r.total_duplicates(), 1);
    }

    #[test]
    fn test_receiver_drain_multiple() {
        let mut r = MultipathReceiver::new();
        r.add(3, "wifi", b"d".to_vec());
        r.add(2, "lte",  b"c".to_vec());
        r.add(1, "wifi", b"b".to_vec());
        r.add(0, "lte",  b"a".to_vec());

        // seq=0 triggers drain of 1,2,3
        let drained = r.drain_ordered();
        assert_eq!(drained.len(), 3); // 1, 2, 3
        assert_eq!(r.next_seq(), 4);
        assert_eq!(r.pending_count(), 0);
    }

    #[test]
    fn test_receiver_buffer_full() {
        let mut r = MultipathReceiver::with_buffer_size(2);
        r.add(1, "wifi", b"b".to_vec());
        r.add(2, "wifi", b"c".to_vec());
        // Buffer full — seq=3 should be dropped
        let result = r.add(3, "wifi", b"d".to_vec());
        assert!(result.is_none());
        assert_eq!(r.pending_count(), 2); // not 3
    }

    #[test]
    fn test_receiver_clear() {
        let mut r = MultipathReceiver::new();
        r.add(1, "wifi", b"b".to_vec());
        r.add(2, "wifi", b"c".to_vec());
        assert_eq!(r.pending_count(), 2);
        r.clear();
        assert_eq!(r.pending_count(), 0);
    }

    #[test]
    fn test_receiver_stats() {
        let mut r = MultipathReceiver::new();
        r.add(0, "wifi", b"a".to_vec());
        r.add(1, "lte",  b"b".to_vec());
        r.add(0, "eth",  b"a".to_vec()); // duplicate
        assert_eq!(r.total_received(), 3);
        assert_eq!(r.total_delivered(), 2);
        assert_eq!(r.total_duplicates(), 1);
    }

    #[test]
    fn test_receiver_default() {
        let r = MultipathReceiver::default();
        assert_eq!(r.next_seq(), 0);
        assert_eq!(r.pending_count(), 0);
    }
}
