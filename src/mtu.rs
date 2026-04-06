//! # VCL MTU Negotiation
//!
//! Automatic MTU (Maximum Transmission Unit) discovery and negotiation
//! for VCL connections.
//!
//! ## Why MTU matters for VPN
//!
//! ```text
//! Physical MTU:  1500 bytes (Ethernet)
//! IP header:       20 bytes
//! UDP header:       8 bytes
//! VCL header:      ~64 bytes
//! ─────────────────────────
//! Usable payload: 1408 bytes  ← this is what fragment_size should be
//! ```
//!
//! If packets are larger than the path MTU they get fragmented by the OS
//! or silently dropped — causing mysterious slowdowns in VPN tunnels.
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::mtu::{MtuConfig, MtuNegotiator, PathMtu};
//!
//! let config = MtuConfig::default();
//! let mut negotiator = MtuNegotiator::new(config);
//!
//! // Probe results come in as you send test packets
//! negotiator.record_probe(1400, true);
//! negotiator.record_probe(1450, false); // dropped — too large
//!
//! let mtu = negotiator.current_mtu();
//! println!("Path MTU: {}", mtu);
//!
//! let vcl_payload = negotiator.recommended_fragment_size();
//! println!("Use fragment_size: {}", vcl_payload);
//! ```

use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Overhead added by VCL Protocol headers on top of IP+UDP.
/// Ed25519 sig(64) + prev_hash(32) + nonce(24) + sequence(8) + version(1) + bincode overhead(~20)
pub const VCL_HEADER_OVERHEAD: usize = 149;

/// Standard Ethernet MTU.
pub const ETHERNET_MTU: usize = 1500;

/// IPv4 header size (minimum, no options).
pub const IPV4_HEADER: usize = 20;

/// IPv6 header size (fixed).
pub const IPV6_HEADER: usize = 40;

/// UDP header size.
pub const UDP_HEADER: usize = 8;

/// Minimum safe MTU — guaranteed to work everywhere (RFC 791).
pub const MIN_MTU: usize = 576;

/// Maximum MTU we will ever probe.
pub const MAX_MTU: usize = 9000; // jumbo frames

/// Configuration for MTU negotiation.
#[derive(Debug, Clone)]
pub struct MtuConfig {
    /// Starting MTU to probe from (default: 1500).
    pub start_mtu: usize,
    /// Minimum acceptable MTU (default: 576).
    pub min_mtu: usize,
    /// Maximum MTU to probe (default: 1500).
    pub max_mtu: usize,
    /// Step size for binary search (default: 8 bytes).
    pub step: usize,
    /// How long to wait for a probe response before declaring loss.
    pub probe_timeout: Duration,
    /// Use IPv6 (adds 40 bytes header instead of 20).
    pub ipv6: bool,
    /// Extra overhead from other encapsulation layers (e.g. WireGuard inside VCL).
    pub extra_overhead: usize,
}

impl Default for MtuConfig {
    fn default() -> Self {
        MtuConfig {
            start_mtu: ETHERNET_MTU,
            min_mtu: MIN_MTU,
            max_mtu: ETHERNET_MTU,
            step: 8,
            probe_timeout: Duration::from_secs(2),
            ipv6: false,
            extra_overhead: 0,
        }
    }
}

impl MtuConfig {
    /// Config for a connection running over IPv4/UDP.
    pub fn ipv4_udp() -> Self {
        MtuConfig::default()
    }

    /// Config for a connection running over IPv6/UDP.
    pub fn ipv6_udp() -> Self {
        MtuConfig {
            ipv6: true,
            ..Default::default()
        }
    }

    /// Config for a connection inside a WireGuard tunnel (adds 60 bytes overhead).
    pub fn inside_wireguard() -> Self {
        MtuConfig {
            max_mtu: 1420,
            start_mtu: 1420,
            extra_overhead: 60,
            ..Default::default()
        }
    }
}

/// The result of MTU discovery for a network path.
#[derive(Debug, Clone)]
pub struct PathMtu {
    /// The discovered path MTU in bytes.
    pub mtu: usize,
    /// Recommended VCL fragment_size for this path.
    pub fragment_size: usize,
    /// When this MTU was last confirmed.
    pub measured_at: Instant,
    /// Whether this value was actively probed or is a safe default.
    pub is_probed: bool,
}

impl PathMtu {
    /// Create a new PathMtu.
    pub fn new(mtu: usize, fragment_size: usize, is_probed: bool) -> Self {
        PathMtu {
            mtu,
            fragment_size,
            measured_at: Instant::now(),
            is_probed,
        }
    }

    /// Returns `true` if this measurement is older than `max_age`.
    pub fn is_stale(&self, max_age: Duration) -> bool {
        self.measured_at.elapsed() > max_age
    }
}

/// State of the MTU negotiation process.
#[derive(Debug, Clone, PartialEq)]
pub enum MtuState {
    /// Initial state — no probing done yet.
    Initial,
    /// Binary search in progress.
    Probing {
        low: usize,
        high: usize,
        current: usize,
    },
    /// MTU confirmed — discovery complete.
    Confirmed(usize),
    /// Fell back to minimum safe MTU after all probes failed.
    FallbackToMin,
}

/// Manages MTU discovery via binary search probing.
///
/// The caller is responsible for actually sending probe packets —
/// this struct tracks state and interprets results.
pub struct MtuNegotiator {
    config: MtuConfig,
    state: MtuState,
    /// Current best confirmed MTU.
    current_mtu: usize,
    /// Pending probe: (probe_size, sent_at).
    pending_probe: Option<(usize, Instant)>,
    /// History of probe results: (size, success).
    probe_history: Vec<(usize, bool)>,
    /// Total probes sent.
    total_probes: u64,
    /// Total successful probes.
    successful_probes: u64,
}

impl MtuNegotiator {
    /// Create a new negotiator with the given config.
    pub fn new(config: MtuConfig) -> Self {
        let start = config.start_mtu;
        let min = config.min_mtu;
        let max = config.max_mtu;
        MtuNegotiator {
            state: MtuState::Initial,
            current_mtu: start.min(max),
            pending_probe: None,
            probe_history: Vec::new(),
            total_probes: 0,
            successful_probes: 0,
            config: MtuConfig { start_mtu: start, min_mtu: min, max_mtu: max, ..config },
        }
    }

    /// Start MTU discovery. Returns the size of the first probe packet to send.
    ///
    /// The caller should send a packet of exactly this size and then call
    /// `record_probe()` with the result.
    pub fn start_discovery(&mut self) -> usize {
        let low = self.config.min_mtu;
        let high = self.config.max_mtu;
        let current = (low + high) / 2;
        self.state = MtuState::Probing { low, high, current };
        self.pending_probe = Some((current, Instant::now()));
        self.total_probes += 1;
        info!(low, high, probe_size = current, "MTU discovery started");
        current
    }

    /// Record the result of a probe.
    ///
    /// `size` — the probe packet size that was sent.
    /// `success` — `true` if the probe was acknowledged, `false` if it was dropped/timed out.
    ///
    /// Returns the next probe size to send, or `None` if discovery is complete.
    pub fn record_probe(&mut self, size: usize, success: bool) -> Option<usize> {
        self.probe_history.push((size, success));
        self.pending_probe = None;

        if success {
            self.successful_probes += 1;
            debug!(size, "MTU probe succeeded");
        } else {
            warn!(size, "MTU probe failed (packet dropped)");
        }

        match self.state.clone() {
            MtuState::Probing { low, high, current } => {
                let (new_low, new_high) = if success {
                    self.current_mtu = current;
                    (current, high)
                } else {
                    (low, current - self.config.step)
                };

                // Check convergence
                if new_high <= new_low || new_high - new_low <= self.config.step {
                    // Discovery complete
                    let final_mtu = if success { current } else { self.current_mtu };
                    let final_mtu = final_mtu.max(self.config.min_mtu);
                    self.current_mtu = final_mtu;
                    self.state = MtuState::Confirmed(final_mtu);
                    info!(mtu = final_mtu, "MTU discovery complete");
                    return None;
                }

                let next = (new_low + new_high) / 2;
                self.state = MtuState::Probing {
                    low: new_low,
                    high: new_high,
                    current: next,
                };
                self.pending_probe = Some((next, Instant::now()));
                self.total_probes += 1;
                debug!(next_probe = next, low = new_low, high = new_high, "Next MTU probe");
                Some(next)
            }
            _ => {
                // Record probe even in non-probing states
                if success && size > self.current_mtu {
                    self.current_mtu = size;
                }
                None
            }
        }
    }

    /// Check if a pending probe has timed out.
    ///
    /// If it has, call `record_probe(size, false)` to register the failure.
    /// Returns the timed-out probe size if applicable.
    pub fn check_probe_timeout(&self) -> Option<usize> {
        if let Some((size, sent_at)) = self.pending_probe {
            if sent_at.elapsed() > self.config.probe_timeout {
                return Some(size);
            }
        }
        None
    }

    /// Returns the current best known MTU.
    pub fn current_mtu(&self) -> usize {
        self.current_mtu
    }

    /// Returns the current negotiation state.
    pub fn state(&self) -> &MtuState {
        &self.state
    }

    /// Returns `true` if MTU discovery is complete.
    pub fn is_complete(&self) -> bool {
        matches!(self.state, MtuState::Confirmed(_) | MtuState::FallbackToMin)
    }

    /// Returns the recommended `fragment_size` for [`VCLConfig`] based on
    /// the current MTU, subtracting all protocol headers.
    ///
    /// [`VCLConfig`]: crate::config::VCLConfig
    pub fn recommended_fragment_size(&self) -> usize {
        let ip_header = if self.config.ipv6 { IPV6_HEADER } else { IPV4_HEADER };
        let overhead = ip_header
            + UDP_HEADER
            + VCL_HEADER_OVERHEAD
            + self.config.extra_overhead;

        if self.current_mtu <= overhead {
            warn!(
                mtu = self.current_mtu,
                overhead,
                "MTU smaller than overhead — using minimum fragment size"
            );
            return 64; // absolute minimum
        }

        let fragment_size = self.current_mtu - overhead;
        // Align down to nearest 8 bytes for efficiency
        (fragment_size / 8) * 8
    }

    /// Force-set the MTU without probing (e.g. from OS PMTUD or known config).
    pub fn set_mtu(&mut self, mtu: usize) {
        let clamped = mtu.clamp(self.config.min_mtu, MAX_MTU);
        info!(mtu = clamped, "MTU manually set");
        self.current_mtu = clamped;
        self.state = MtuState::Confirmed(clamped);
    }

    /// Fall back to the minimum safe MTU.
    pub fn fallback_to_min(&mut self) {
        warn!(min = self.config.min_mtu, "MTU falling back to minimum");
        self.current_mtu = self.config.min_mtu;
        self.state = MtuState::FallbackToMin;
    }

    /// Returns a [`PathMtu`] snapshot of the current state.
    pub fn path_mtu(&self) -> PathMtu {
        PathMtu::new(
            self.current_mtu,
            self.recommended_fragment_size(),
            self.successful_probes > 0,
        )
    }

    /// Returns total probes sent.
    pub fn total_probes(&self) -> u64 {
        self.total_probes
    }

    /// Returns total successful probes.
    pub fn successful_probes(&self) -> u64 {
        self.successful_probes
    }

    /// Returns the full probe history as (size, success) pairs.
    pub fn probe_history(&self) -> &[(usize, bool)] {
        &self.probe_history
    }
}

/// Compute the recommended fragment size for a known MTU and transport.
///
/// Convenience function for when you already know the MTU.
///
/// ```rust
/// use vcl_protocol::mtu::fragment_size_for_mtu;
///
/// let fs = fragment_size_for_mtu(1500, false, 0);
/// assert!(fs > 0 && fs < 1500);
/// ```
pub fn fragment_size_for_mtu(mtu: usize, ipv6: bool, extra_overhead: usize) -> usize {
    let ip_header = if ipv6 { IPV6_HEADER } else { IPV4_HEADER };
    let overhead = ip_header + UDP_HEADER + VCL_HEADER_OVERHEAD + extra_overhead;
    if mtu <= overhead {
        return 64;
    }
    ((mtu - overhead) / 8) * 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let c = MtuConfig::default();
        assert_eq!(c.start_mtu, 1500);
        assert_eq!(c.min_mtu, 576);
        assert!(!c.ipv6);
    }

    #[test]
    fn test_ipv6_config() {
        let c = MtuConfig::ipv6_udp();
        assert!(c.ipv6);
    }

    #[test]
    fn test_wireguard_config() {
        let c = MtuConfig::inside_wireguard();
        assert_eq!(c.max_mtu, 1420);
        assert_eq!(c.extra_overhead, 60);
    }

    #[test]
    fn test_negotiator_new() {
        let n = MtuNegotiator::new(MtuConfig::default());
        assert_eq!(n.state(), &MtuState::Initial);
        assert_eq!(n.current_mtu(), 1500);
        assert!(!n.is_complete());
    }

    #[test]
    fn test_start_discovery() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        let probe = n.start_discovery();
        assert!(probe > 576 && probe < 1500);
        assert!(matches!(n.state(), MtuState::Probing { .. }));
        assert_eq!(n.total_probes(), 1);
    }

    #[test]
    fn test_record_probe_success() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        n.start_discovery();
        let next = n.record_probe(1038, true);
        // Should continue probing or complete
        assert!(n.current_mtu() >= 1038);
    }

    #[test]
    fn test_record_probe_failure() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        n.start_discovery();
        let _ = n.record_probe(1038, false);
        // MTU should stay at start value since probe failed
        assert!(n.current_mtu() <= 1500);
    }

    #[test]
    fn test_full_discovery_converges() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        let mut probe = n.start_discovery();

        // Simulate: anything <= 1400 succeeds, > 1400 fails
        for _ in 0..20 {
            let success = probe <= 1400;
            match n.record_probe(probe, success) {
                Some(next) => probe = next,
                None => break,
            }
        }

        assert!(n.is_complete());
        assert!(n.current_mtu() <= 1400);
        assert!(n.current_mtu() >= 576);
    }

    #[test]
    fn test_recommended_fragment_size() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        n.set_mtu(1500);
        let fs = n.recommended_fragment_size();
        assert!(fs > 0);
        assert!(fs < 1500);
        // Should be aligned to 8
        assert_eq!(fs % 8, 0);
    }

    #[test]
    fn test_fragment_size_for_mtu_fn() {
        let fs = fragment_size_for_mtu(1500, false, 0);
        assert!(fs > 0 && fs < 1500);
        assert_eq!(fs % 8, 0);

        let fs_v6 = fragment_size_for_mtu(1500, true, 0);
        assert!(fs_v6 < fs); // IPv6 header is larger
    }

    #[test]
    fn test_set_mtu() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        n.set_mtu(1280);
        assert_eq!(n.current_mtu(), 1280);
        assert!(n.is_complete());
        assert!(matches!(n.state(), MtuState::Confirmed(1280)));
    }

    #[test]
    fn test_set_mtu_clamped() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        n.set_mtu(100); // below min (576)
        assert_eq!(n.current_mtu(), 576);
    }

    #[test]
    fn test_fallback_to_min() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        n.fallback_to_min();
        assert_eq!(n.current_mtu(), 576);
        assert_eq!(n.state(), &MtuState::FallbackToMin);
        assert!(n.is_complete());
    }

    #[test]
    fn test_path_mtu() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        n.set_mtu(1400);
        let pm = n.path_mtu();
        assert_eq!(pm.mtu, 1400);
        assert!(pm.fragment_size < 1400);
        assert!(!pm.is_probed); // no probes done, just set_mtu
    }

    #[test]
    fn test_probe_history() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        n.start_discovery();
        n.record_probe(1038, true);
        assert_eq!(n.probe_history().len(), 1);
        assert_eq!(n.probe_history()[0], (1038, true));
    }

    #[test]
    fn test_check_probe_timeout_no_pending() {
        let n = MtuNegotiator::new(MtuConfig::default());
        assert!(n.check_probe_timeout().is_none());
    }

    #[test]
    fn test_check_probe_timeout_not_yet() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        n.start_discovery();
        // Probe just sent, shouldn't timeout yet
        assert!(n.check_probe_timeout().is_none());
    }

    #[test]
    fn test_mtu_smaller_than_overhead() {
        let config = MtuConfig {
            start_mtu: 100,
            min_mtu: 64,
            max_mtu: 100,
            ..Default::default()
        };
        let mut n = MtuNegotiator::new(config);
        n.set_mtu(100);
        // overhead > 100, should return 64 minimum
        assert_eq!(n.recommended_fragment_size(), 64);
    }

    #[test]
    fn test_extra_overhead() {
        let fs1 = fragment_size_for_mtu(1500, false, 0);
        let fs2 = fragment_size_for_mtu(1500, false, 60); // WireGuard overhead
        assert!(fs2 < fs1);
    }

    #[test]
    fn test_total_probes_counted() {
        let mut n = MtuNegotiator::new(MtuConfig::default());
        n.start_discovery();
        assert_eq!(n.total_probes(), 1);
        n.record_probe(1038, true);
        assert!(n.total_probes() >= 1);
    }
}
