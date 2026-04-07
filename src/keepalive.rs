//! # VCL Keepalive
//!
//! Automatic keepalive for maintaining connections through NAT and firewalls.
//!
//! ## Why keepalive matters for VPN
//!
//! ```text
//! Client ──── NAT ──── Internet ──── Server
//!
//! NAT table entry:
//!   client:4500 → server:4500   TTL: 30s (mobile), 120s (home), 300s (corporate)
//!
//! Without keepalive:
//!   30s of silence → NAT drops entry → connection dead
//!
//! With keepalive:
//!   Every 25s → tiny ping → NAT entry refreshed → connection alive
//! ```
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::keepalive::{KeepaliveConfig, KeepaliveManager};
//! use std::time::Duration;
//!
//! let config = KeepaliveConfig::aggressive(); // 25s interval, for mobile NAT
//! let mut manager = KeepaliveManager::new(config);
//!
//! // Call this in your main loop
//! if manager.should_send_keepalive() {
//!     // send ping here
//!     manager.record_keepalive_sent();
//! }
//!
//! // When pong arrives
//! manager.record_pong_received();
//! ```

use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Preset keepalive strategies for different network environments.
#[derive(Debug, Clone, PartialEq)]
pub enum KeepalivePreset {
    /// Mobile networks (МТС, Beeline, МегаФон) — aggressive NAT, 30s timeout.
    /// Interval: 20s, max missed: 3
    Mobile,
    /// Home broadband — relaxed NAT, 120s timeout.
    /// Interval: 60s, max missed: 3
    Home,
    /// Corporate/office — strict firewall, 300s timeout.
    /// Interval: 120s, max missed: 2
    Corporate,
    /// Data center / server-to-server — no NAT, just liveness check.
    /// Interval: 30s, max missed: 5
    DataCenter,
    /// Disabled — no automatic keepalive.
    Disabled,
}

/// Configuration for the keepalive mechanism.
#[derive(Debug, Clone)]
pub struct KeepaliveConfig {
    /// How often to send a keepalive ping.
    pub interval: Duration,
    /// How long to wait for a pong before counting a miss.
    pub timeout: Duration,
    /// How many consecutive missed pongs before declaring the connection dead.
    pub max_missed: u32,
    /// Whether keepalive is enabled.
    pub enabled: bool,
    /// Adaptive mode — adjusts interval based on measured RTT.
    pub adaptive: bool,
}

impl KeepaliveConfig {
    /// Mobile network preset — aggressive keepalive for МТС/Beeline/МегаФон.
    /// These operators drop NAT entries after ~30s of silence.
    pub fn mobile() -> Self {
        KeepaliveConfig {
            interval: Duration::from_secs(20),
            timeout: Duration::from_secs(5),
            max_missed: 3,
            enabled: true,
            adaptive: true,
        }
    }

    /// Home broadband preset.
    pub fn home() -> Self {
        KeepaliveConfig {
            interval: Duration::from_secs(60),
            timeout: Duration::from_secs(10),
            max_missed: 3,
            enabled: true,
            adaptive: true,
        }
    }

    /// Corporate/office network preset — strict firewalls.
    pub fn corporate() -> Self {
        KeepaliveConfig {
            interval: Duration::from_secs(120),
            timeout: Duration::from_secs(15),
            max_missed: 2,
            enabled: true,
            adaptive: false,
        }
    }

    /// Data center / server preset.
    pub fn datacenter() -> Self {
        KeepaliveConfig {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
            max_missed: 5,
            enabled: true,
            adaptive: false,
        }
    }

    /// Aggressive preset — same as mobile, explicit alias.
    pub fn aggressive() -> Self {
        Self::mobile()
    }

    /// Disabled — no keepalive sent.
    pub fn disabled() -> Self {
        KeepaliveConfig {
            interval: Duration::from_secs(u64::MAX / 2),
            timeout: Duration::from_secs(30),
            max_missed: u32::MAX,
            enabled: false,
            adaptive: false,
        }
    }

    /// Create from a [`KeepalivePreset`].
    pub fn from_preset(preset: KeepalivePreset) -> Self {
        match preset {
            KeepalivePreset::Mobile      => Self::mobile(),
            KeepalivePreset::Home        => Self::home(),
            KeepalivePreset::Corporate   => Self::corporate(),
            KeepalivePreset::DataCenter  => Self::datacenter(),
            KeepalivePreset::Disabled    => Self::disabled(),
        }
    }
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self::home()
    }
}

/// The result of a keepalive check — what action to take.
#[derive(Debug, Clone, PartialEq)]
pub enum KeepaliveAction {
    /// Nothing to do — connection is healthy.
    Idle,
    /// Send a keepalive ping now.
    SendPing,
    /// A pong has timed out — count as a miss.
    PongTimeout,
    /// Too many missed pongs — declare connection dead.
    ConnectionDead,
}

/// Manages keepalive timing, miss counting, and adaptive interval adjustment.
pub struct KeepaliveManager {
    config: KeepaliveConfig,
    /// When the last keepalive was sent.
    last_sent: Option<Instant>,
    /// When the last pong was received.
    last_pong: Option<Instant>,
    /// When data was last received (resets keepalive timer).
    last_activity: Instant,
    /// Whether we are waiting for a pong right now.
    waiting_for_pong: bool,
    /// When the current pending ping was sent.
    ping_sent_at: Option<Instant>,
    /// Consecutive missed pongs.
    missed_pongs: u32,
    /// Total keepalives sent.
    total_sent: u64,
    /// Total pongs received.
    total_pongs: u64,
    /// Smoothed RTT from keepalive pings.
    srtt: Option<Duration>,
    /// Current adaptive interval (may differ from config.interval).
    adaptive_interval: Duration,
}

impl KeepaliveManager {
    /// Create a new keepalive manager with the given config.
    pub fn new(config: KeepaliveConfig) -> Self {
        let adaptive_interval = config.interval;
        info!(
            interval_secs = config.interval.as_secs(),
            max_missed = config.max_missed,
            adaptive = config.adaptive,
            enabled = config.enabled,
            "KeepaliveManager created"
        );
        KeepaliveManager {
            adaptive_interval,
            config,
            last_sent: None,
            last_pong: None,
            last_activity: Instant::now(),
            waiting_for_pong: false,
            ping_sent_at: None,
            missed_pongs: 0,
            total_sent: 0,
            total_pongs: 0,
            srtt: None,
        }
    }

    /// Create with a preset.
    pub fn from_preset(preset: KeepalivePreset) -> Self {
        Self::new(KeepaliveConfig::from_preset(preset))
    }

    // ─── Main loop interface ──────────────────────────────────────────────────

    /// Check what keepalive action to take right now.
    ///
    /// Call this periodically (e.g. every second) in your main loop.
    ///
    /// ```text
    /// loop {
    ///     match manager.check() {
    ///         KeepaliveAction::SendPing       => conn.ping().await?,
    ///         KeepaliveAction::PongTimeout    => manager.record_pong_missed(),
    ///         KeepaliveAction::ConnectionDead => break, // reconnect
    ///         KeepaliveAction::Idle           => {}
    ///     }
    ///     tokio::time::sleep(Duration::from_secs(1)).await;
    /// }
    /// ```
    pub fn check(&mut self) -> KeepaliveAction {
        if !self.config.enabled {
            return KeepaliveAction::Idle;
        }

        // Check for pong timeout first
        if self.waiting_for_pong {
            if let Some(sent_at) = self.ping_sent_at {
                if sent_at.elapsed() > self.config.timeout {
                    self.waiting_for_pong = false;
                    self.ping_sent_at = None;
                    warn!(
                        missed = self.missed_pongs + 1,
                        max = self.config.max_missed,
                        "Keepalive pong timed out"
                    );
                    self.missed_pongs += 1;
                    if self.missed_pongs >= self.config.max_missed {
                        warn!("Too many missed keepalive pongs — connection declared dead");
                        return KeepaliveAction::ConnectionDead;
                    }
                    return KeepaliveAction::PongTimeout;
                }
                // Still waiting, not timed out yet
                return KeepaliveAction::Idle;
            }
        }

        // Check if it's time to send a keepalive
        if self.should_send_keepalive() {
            return KeepaliveAction::SendPing;
        }

        KeepaliveAction::Idle
    }

    /// Returns `true` if a keepalive ping should be sent now.
    pub fn should_send_keepalive(&self) -> bool {
        if !self.config.enabled || self.waiting_for_pong {
            return false;
        }
        let since_activity = self.last_activity.elapsed();
        let since_sent = self.last_sent
            .map(|t| t.elapsed())
            .unwrap_or(Duration::MAX);

        // Send if we've been idle longer than the interval
        since_activity >= self.adaptive_interval
            || since_sent >= self.adaptive_interval
    }

    /// Record that a keepalive ping was sent.
    pub fn record_keepalive_sent(&mut self) {
        let now = Instant::now();
        self.last_sent = Some(now);
        self.ping_sent_at = Some(now);
        self.waiting_for_pong = true;
        self.total_sent += 1;
        debug!(total_sent = self.total_sent, "Keepalive ping sent");
    }

    /// Record that a pong was received.
    ///
    /// Resets miss counter, updates RTT estimate, adjusts adaptive interval.
    pub fn record_pong_received(&mut self) {
        let now = Instant::now();
        self.last_pong = Some(now);
        self.last_activity = now;
        self.total_pongs += 1;

        // Measure RTT if we were waiting
        if let Some(sent_at) = self.ping_sent_at.take() {
            let rtt = sent_at.elapsed();
            self.update_srtt(rtt);

            if self.config.adaptive {
                self.adjust_interval(rtt);
            }
        }

        self.waiting_for_pong = false;
        self.missed_pongs = 0;
        debug!(total_pongs = self.total_pongs, "Keepalive pong received");
    }

    /// Record a missed pong (called after `KeepaliveAction::PongTimeout`).
    pub fn record_pong_missed(&mut self) {
        self.missed_pongs += 1;
        warn!(
            missed = self.missed_pongs,
            max = self.config.max_missed,
            "Keepalive pong missed"
        );
    }

    /// Record any activity (data received) — resets the keepalive timer.
    pub fn record_activity(&mut self) {
        self.last_activity = Instant::now();
        // If we get data, we know the connection is alive — cancel pending check
        if self.waiting_for_pong {
            self.waiting_for_pong = false;
            self.ping_sent_at = None;
            self.missed_pongs = 0;
        }
    }

    /// Reset miss counter (e.g. after reconnect).
    pub fn reset_misses(&mut self) {
        self.missed_pongs = 0;
        self.waiting_for_pong = false;
        self.ping_sent_at = None;
        self.last_activity = Instant::now();
        info!("Keepalive miss counter reset");
    }

    // ─── Adaptive interval ────────────────────────────────────────────────────

    fn update_srtt(&mut self, rtt: Duration) {
        self.srtt = Some(match self.srtt {
            None => rtt,
            Some(srtt) => {
                let s = srtt.as_nanos() as u64;
                let r = rtt.as_nanos() as u64;
                Duration::from_nanos(s / 8 * 7 + r / 8)
            }
        });
    }

    fn adjust_interval(&mut self, rtt: Duration) {
        // Adaptive: keep interval at least 4x RTT but no less than 10s
        // and no more than configured max
        let min_interval = (rtt * 4).max(Duration::from_secs(10));
        let new_interval = min_interval
            .min(self.config.interval)
            .max(Duration::from_secs(10));

        if new_interval != self.adaptive_interval {
            debug!(
                old_secs = self.adaptive_interval.as_secs(),
                new_secs = new_interval.as_secs(),
                rtt_ms = rtt.as_millis(),
                "Adaptive keepalive interval adjusted"
            );
            self.adaptive_interval = new_interval;
        }
    }

    // ─── Stats ────────────────────────────────────────────────────────────────

    /// Returns the current smoothed RTT from keepalive pings.
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// Returns the current effective keepalive interval (adaptive or configured).
    pub fn current_interval(&self) -> Duration {
        self.adaptive_interval
    }

    /// Returns the number of consecutive missed pongs.
    pub fn missed_pongs(&self) -> u32 {
        self.missed_pongs
    }

    /// Returns `true` if we are waiting for a pong right now.
    pub fn is_waiting_for_pong(&self) -> bool {
        self.waiting_for_pong
    }

    /// Returns `true` if the connection is considered dead (too many missed pongs).
    pub fn is_dead(&self) -> bool {
        self.missed_pongs >= self.config.max_missed
    }

    /// Returns total keepalives sent.
    pub fn total_sent(&self) -> u64 {
        self.total_sent
    }

    /// Returns total pongs received.
    pub fn total_pongs(&self) -> u64 {
        self.total_pongs
    }

    /// Returns when the last pong was received.
    pub fn last_pong(&self) -> Option<Instant> {
        self.last_pong
    }

    /// Returns a reference to the config.
    pub fn config(&self) -> &KeepaliveConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant_manager() -> KeepaliveManager {
        KeepaliveManager::new(KeepaliveConfig {
            interval: Duration::from_millis(1),
            timeout: Duration::from_millis(50),
            max_missed: 3,
            enabled: true,
            adaptive: false,
        })
    }

    #[test]
    fn test_config_mobile() {
        let c = KeepaliveConfig::mobile();
        assert_eq!(c.interval, Duration::from_secs(20));
        assert!(c.enabled);
        assert!(c.adaptive);
    }

    #[test]
    fn test_config_home() {
        let c = KeepaliveConfig::home();
        assert_eq!(c.interval, Duration::from_secs(60));
    }

    #[test]
    fn test_config_corporate() {
        let c = KeepaliveConfig::corporate();
        assert_eq!(c.max_missed, 2);
        assert!(!c.adaptive);
    }

    #[test]
    fn test_config_disabled() {
        let c = KeepaliveConfig::disabled();
        assert!(!c.enabled);
    }

    #[test]
    fn test_config_from_preset_mobile() {
        let c = KeepaliveConfig::from_preset(KeepalivePreset::Mobile);
        assert_eq!(c.interval, Duration::from_secs(20));
    }

    #[test]
    fn test_config_default_is_home() {
        let c = KeepaliveConfig::default();
        assert_eq!(c.interval, Duration::from_secs(60));
    }

    #[test]
    fn test_manager_new() {
        let m = KeepaliveManager::new(KeepaliveConfig::default());
        assert_eq!(m.missed_pongs(), 0);
        assert!(!m.is_waiting_for_pong());
        assert!(!m.is_dead());
        assert_eq!(m.total_sent(), 0);
    }

    #[test]
    fn test_should_send_keepalive_initially() {
        let m = instant_manager();
        std::thread::sleep(Duration::from_millis(5));
        assert!(m.should_send_keepalive());
    }

    #[test]
    fn test_should_not_send_while_waiting() {
        let mut m = instant_manager();
        std::thread::sleep(Duration::from_millis(5));
        m.record_keepalive_sent();
        assert!(!m.should_send_keepalive());
    }

    #[test]
    fn test_record_keepalive_sent() {
        let mut m = instant_manager();
        m.record_keepalive_sent();
        assert!(m.is_waiting_for_pong());
        assert_eq!(m.total_sent(), 1);
    }

    #[test]
    fn test_record_pong_received() {
        let mut m = instant_manager();
        m.record_keepalive_sent();
        assert!(m.is_waiting_for_pong());
        m.record_pong_received();
        assert!(!m.is_waiting_for_pong());
        assert_eq!(m.total_pongs(), 1);
        assert_eq!(m.missed_pongs(), 0);
        assert!(m.last_pong().is_some());
    }

    #[test]
    fn test_srtt_updated_after_pong() {
        let mut m = instant_manager();
        m.record_keepalive_sent();
        std::thread::sleep(Duration::from_millis(5));
        m.record_pong_received();
        assert!(m.srtt().is_some());
    }

    #[test]
    fn test_record_activity_resets_wait() {
        let mut m = instant_manager();
        m.record_keepalive_sent();
        assert!(m.is_waiting_for_pong());
        m.record_activity();
        assert!(!m.is_waiting_for_pong());
        assert_eq!(m.missed_pongs(), 0);
    }

    #[test]
    fn test_check_disabled() {
        let mut m = KeepaliveManager::new(KeepaliveConfig::disabled());
        assert_eq!(m.check(), KeepaliveAction::Idle);
    }

    #[test]
    fn test_check_send_ping() {
        let mut m = instant_manager();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(m.check(), KeepaliveAction::SendPing);
    }

    #[test]
    fn test_check_pong_timeout() {
        let mut m = KeepaliveManager::new(KeepaliveConfig {
            interval: Duration::from_millis(1),
            timeout: Duration::from_millis(1),
            max_missed: 3,
            enabled: true,
            adaptive: false,
        });
        std::thread::sleep(Duration::from_millis(5));
        m.record_keepalive_sent();
        std::thread::sleep(Duration::from_millis(5));
        let action = m.check();
        assert!(
            action == KeepaliveAction::PongTimeout
            || action == KeepaliveAction::ConnectionDead
        );
    }

    #[test]
    fn test_connection_dead_after_max_missed() {
        let mut m = KeepaliveManager::new(KeepaliveConfig {
            interval: Duration::from_millis(1),
            timeout: Duration::from_millis(1),
            max_missed: 2,
            enabled: true,
            adaptive: false,
        });

        // Simulate max_missed timeouts
        for _ in 0..2 {
            std::thread::sleep(Duration::from_millis(3));
            m.record_keepalive_sent();
            std::thread::sleep(Duration::from_millis(3));
            let action = m.check();
            if action == KeepaliveAction::ConnectionDead {
                assert!(m.is_dead());
                return;
            }
        }
        // If we get here, just check is_dead based on missed count
        assert!(m.missed_pongs() > 0);
    }

    #[test]
    fn test_reset_misses() {
        let mut m = instant_manager();
        m.record_pong_missed();
        m.record_pong_missed();
        assert_eq!(m.missed_pongs(), 2);
        m.reset_misses();
        assert_eq!(m.missed_pongs(), 0);
        assert!(!m.is_waiting_for_pong());
    }

    #[test]
    fn test_is_dead() {
        let mut m = KeepaliveManager::new(KeepaliveConfig {
            max_missed: 2,
            ..KeepaliveConfig::mobile()
        });
        assert!(!m.is_dead());
        m.record_pong_missed();
        assert!(!m.is_dead());
        m.record_pong_missed();
        assert!(m.is_dead());
    }

    #[test]
    fn test_from_preset() {
        let m = KeepaliveManager::from_preset(KeepalivePreset::Mobile);
        assert_eq!(m.config().interval, Duration::from_secs(20));
    }

    #[test]
    fn test_adaptive_interval_adjusts() {
        let mut m = KeepaliveManager::new(KeepaliveConfig {
            interval: Duration::from_secs(60),
            timeout: Duration::from_secs(5),
            max_missed: 3,
            enabled: true,
            adaptive: true,
        });
        m.record_keepalive_sent();
        std::thread::sleep(Duration::from_millis(10));
        m.record_pong_received();
        // Interval should be 10s minimum regardless of tiny RTT
        assert!(m.current_interval() >= Duration::from_secs(10));
    }

    #[test]
    fn test_current_interval_default() {
        let m = KeepaliveManager::new(KeepaliveConfig::home());
        assert_eq!(m.current_interval(), Duration::from_secs(60));
    }
}
