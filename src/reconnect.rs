//! # VCL Reconnect
//!
//! Automatic reconnection with exponential backoff for VCL connections.
//!
//! ## How it works
//!
//! ```text
//! Connection drops
//!     ↓
//! ReconnectManager::on_disconnect()
//!     ↓
//! Wait: backoff_interval (1s → 2s → 4s → 8s → ... → max_interval)
//!     ↓
//! ReconnectManager::should_reconnect() == true
//!     ↓
//! Attempt reconnect
//!     ↓
//! Success → ReconnectManager::on_connect() → reset backoff
//! Failure → ReconnectManager::on_failure() → increase backoff
//! ```
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::reconnect::{ReconnectManager, ReconnectConfig};
//!
//! let mut manager = ReconnectManager::new(ReconnectConfig::default());
//!
//! // Connection dropped
//! manager.on_disconnect();
//!
//! loop {
//!     if manager.should_reconnect() {
//!         // attempt reconnect here...
//!         let success = true; // result of reconnect attempt
//!         if success {
//!             manager.on_connect();
//!             break;
//!         } else {
//!             manager.on_failure();
//!             if manager.is_giving_up() {
//!                 println!("Giving up after {} attempts", manager.attempts());
//!                 break;
//!             }
//!         }
//!     }
//! }
//! ```

use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Configuration for automatic reconnection.
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Initial backoff interval before first reconnect attempt.
    pub initial_interval: Duration,
    /// Maximum backoff interval — exponential growth is capped here.
    pub max_interval: Duration,
    /// Backoff multiplier (default: 2.0 — doubles each failure).
    pub multiplier: f64,
    /// Random jitter factor 0.0–1.0 added to backoff to avoid thundering herd.
    /// e.g. 0.2 adds ±20% random variation.
    pub jitter: f64,
    /// Maximum number of reconnect attempts before giving up.
    /// `None` means retry forever.
    pub max_attempts: Option<u32>,
    /// How long a connection must stay up to be considered stable
    /// (resets the backoff counter).
    pub stable_threshold: Duration,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        ReconnectConfig {
            initial_interval: Duration::from_secs(1),
            max_interval: Duration::from_secs(60),
            multiplier: 2.0,
            jitter: 0.2,
            max_attempts: None,
            stable_threshold: Duration::from_secs(30),
        }
    }
}

impl ReconnectConfig {
    /// Aggressive reconnect — for mobile networks.
    /// Fast first retry, shorter max backoff.
    pub fn mobile() -> Self {
        ReconnectConfig {
            initial_interval: Duration::from_millis(500),
            max_interval: Duration::from_secs(30),
            multiplier: 1.5,
            jitter: 0.3,
            max_attempts: None,
            stable_threshold: Duration::from_secs(10),
        }
    }

    /// Conservative reconnect — for stable networks.
    pub fn stable() -> Self {
        ReconnectConfig {
            initial_interval: Duration::from_secs(2),
            max_interval: Duration::from_secs(120),
            multiplier: 2.0,
            jitter: 0.1,
            max_attempts: Some(10),
            stable_threshold: Duration::from_secs(60),
        }
    }

    /// Instant reconnect — for testing or LAN connections.
    pub fn instant() -> Self {
        ReconnectConfig {
            initial_interval: Duration::from_millis(10),
            max_interval: Duration::from_millis(100),
            multiplier: 1.5,
            jitter: 0.0,
            max_attempts: Some(5),
            stable_threshold: Duration::from_millis(100),
        }
    }
}

/// State of the reconnect manager.
#[derive(Debug, Clone, PartialEq)]
pub enum ReconnectState {
    /// Connection is up and healthy.
    Connected,
    /// Waiting for backoff interval before next attempt.
    WaitingBackoff,
    /// Ready to attempt reconnect right now.
    ReadyToReconnect,
    /// Reconnect attempt in progress.
    Reconnecting,
    /// Gave up — max attempts reached.
    GaveUp,
}

/// Manages automatic reconnection with exponential backoff and jitter.
pub struct ReconnectManager {
    config: ReconnectConfig,
    state: ReconnectState,
    /// Total reconnect attempts since last successful connect.
    attempts: u32,
    /// Total successful reconnects.
    total_reconnects: u64,
    /// Current backoff interval.
    current_interval: Duration,
    /// When we disconnected.
    disconnected_at: Option<Instant>,
    /// When we started waiting for this backoff.
    backoff_started: Option<Instant>,
    /// When we last successfully connected.
    connected_at: Option<Instant>,
    /// Cumulative downtime.
    total_downtime: Duration,
}

impl ReconnectManager {
    /// Create a new reconnect manager.
    pub fn new(config: ReconnectConfig) -> Self {
        let initial = config.initial_interval;
        ReconnectManager {
            config,
            state: ReconnectState::Connected,
            attempts: 0,
            total_reconnects: 0,
            current_interval: initial,
            disconnected_at: None,
            backoff_started: None,
            connected_at: Some(Instant::now()),
            total_downtime: Duration::ZERO,
        }
    }

    /// Create with mobile preset.
    pub fn mobile() -> Self {
        Self::new(ReconnectConfig::mobile())
    }

    /// Create with stable preset.
    pub fn stable() -> Self {
        Self::new(ReconnectConfig::stable())
    }

    // ─── State transitions ────────────────────────────────────────────────────

    /// Call when the connection drops.
    ///
    /// Starts the backoff timer and transitions to `WaitingBackoff`.
    pub fn on_disconnect(&mut self) {
        let now = Instant::now();
        self.disconnected_at = Some(now);
        self.backoff_started = Some(now);
        self.state = ReconnectState::WaitingBackoff;

        warn!(
            attempts = self.attempts,
            backoff_ms = self.current_interval.as_millis(),
            "Connection lost — starting reconnect backoff"
        );
    }

    /// Call when a reconnect attempt succeeds.
    ///
    /// Resets backoff if connection was stable, or keeps reduced backoff
    /// if we reconnected quickly.
    pub fn on_connect(&mut self) {
        let now = Instant::now();

        // Accumulate downtime
        if let Some(disc) = self.disconnected_at.take() {
            self.total_downtime += now.duration_since(disc);
        }

        self.total_reconnects += 1;
        self.connected_at = Some(now);
        self.state = ReconnectState::Connected;
        self.backoff_started = None;

        info!(
            attempts = self.attempts,
            total_reconnects = self.total_reconnects,
            "Reconnect successful — resetting backoff"
        );

        // Reset backoff fully
        self.attempts = 0;
        self.current_interval = self.config.initial_interval;
    }

    /// Call when a reconnect attempt fails.
    ///
    /// Increases backoff interval exponentially with jitter.
    pub fn on_failure(&mut self) {
        self.attempts += 1;
        self.state = ReconnectState::WaitingBackoff;

        // Exponential backoff
        let new_interval_secs = self.current_interval.as_secs_f64()
            * self.config.multiplier;

        // Add jitter
        let jitter_range = new_interval_secs * self.config.jitter;
        let jitter = if jitter_range > 0.0 {
            // Deterministic pseudo-jitter based on attempt count
            let j = (self.attempts as f64 * 0.618) % 1.0; // golden ratio
            (j * 2.0 - 1.0) * jitter_range
        } else {
            0.0
        };

        let final_secs = (new_interval_secs + jitter)
            .max(0.1)
            .min(self.config.max_interval.as_secs_f64());

        self.current_interval = Duration::from_secs_f64(final_secs);
        self.backoff_started = Some(Instant::now());

        warn!(
            attempt = self.attempts,
            next_backoff_ms = self.current_interval.as_millis(),
            max_attempts = ?self.config.max_attempts,
            "Reconnect failed — backing off"
        );

        // Check if we should give up
        if let Some(max) = self.config.max_attempts {
            if self.attempts >= max {
                warn!(attempts = self.attempts, "Max reconnect attempts reached — giving up");
                self.state = ReconnectState::GaveUp;
            }
        }
    }

    /// Call when a reconnect attempt is starting.
    pub fn on_attempt_start(&mut self) {
        self.state = ReconnectState::Reconnecting;
        debug!(attempt = self.attempts + 1, "Reconnect attempt starting");
    }

    // ─── Polling interface ────────────────────────────────────────────────────

    /// Returns `true` if it's time to attempt a reconnect right now.
    ///
    /// Call this periodically in your main loop.
    pub fn should_reconnect(&mut self) -> bool {
        if self.state == ReconnectState::GaveUp
            || self.state == ReconnectState::Connected
            || self.state == ReconnectState::Reconnecting
        {
            return false;
        }

        if let Some(started) = self.backoff_started {
            if started.elapsed() >= self.current_interval {
                self.state = ReconnectState::ReadyToReconnect;
                return true;
            }
        }

        false
    }

    /// Returns how long until the next reconnect attempt.
    /// Returns `Duration::ZERO` if ready now.
    pub fn time_until_reconnect(&self) -> Duration {
        if let Some(started) = self.backoff_started {
            let elapsed = started.elapsed();
            if elapsed >= self.current_interval {
                return Duration::ZERO;
            }
            return self.current_interval - elapsed;
        }
        Duration::ZERO
    }

    // ─── Stability check ──────────────────────────────────────────────────────

    /// Check if the current connection has been stable long enough
    /// to fully reset the backoff counter.
    ///
    /// Call periodically while connected.
    pub fn check_stability(&mut self) {
        if self.state != ReconnectState::Connected {
            return;
        }
        if let Some(connected_at) = self.connected_at {
            if connected_at.elapsed() >= self.config.stable_threshold && self.attempts > 0 {
                info!("Connection stable — resetting backoff counter");
                self.attempts = 0;
                self.current_interval = self.config.initial_interval;
            }
        }
    }

    // ─── Stats ────────────────────────────────────────────────────────────────

    /// Returns the current reconnect state.
    pub fn state(&self) -> &ReconnectState {
        &self.state
    }

    /// Returns `true` if the connection is currently up.
    pub fn is_connected(&self) -> bool {
        self.state == ReconnectState::Connected
    }

    /// Returns `true` if we have given up reconnecting.
    pub fn is_giving_up(&self) -> bool {
        self.state == ReconnectState::GaveUp
    }

    /// Returns the number of failed attempts since last successful connect.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Returns total successful reconnects.
    pub fn total_reconnects(&self) -> u64 {
        self.total_reconnects
    }

    /// Returns the current backoff interval.
    pub fn current_interval(&self) -> Duration {
        self.current_interval
    }

    /// Returns total accumulated downtime.
    pub fn total_downtime(&self) -> Duration {
        self.total_downtime
    }

    /// Returns a reference to the config.
    pub fn config(&self) -> &ReconnectConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant_manager() -> ReconnectManager {
        ReconnectManager::new(ReconnectConfig::instant())
    }

    #[test]
    fn test_new() {
        let m = ReconnectManager::new(ReconnectConfig::default());
        assert_eq!(m.state(), &ReconnectState::Connected);
        assert!(m.is_connected());
        assert!(!m.is_giving_up());
        assert_eq!(m.attempts(), 0);
        assert_eq!(m.total_reconnects(), 0);
    }

    #[test]
    fn test_on_disconnect() {
        let mut m = instant_manager();
        m.on_disconnect();
        assert_eq!(m.state(), &ReconnectState::WaitingBackoff);
        assert!(!m.is_connected());
    }

    #[test]
    fn test_should_reconnect_after_backoff() {
        let mut m = instant_manager();
        m.on_disconnect();
        std::thread::sleep(Duration::from_millis(20));
        assert!(m.should_reconnect());
        assert_eq!(m.state(), &ReconnectState::ReadyToReconnect);
    }

    #[test]
    fn test_should_not_reconnect_before_backoff() {
        let mut m = ReconnectManager::new(ReconnectConfig {
            initial_interval: Duration::from_secs(60),
            ..ReconnectConfig::default()
        });
        m.on_disconnect();
        assert!(!m.should_reconnect());
    }

    #[test]
    fn test_on_connect_resets_backoff() {
        let mut m = instant_manager();
        m.on_disconnect();
        m.on_failure();
        m.on_failure();
        assert!(m.attempts() > 0);
        m.on_connect();
        assert_eq!(m.attempts(), 0);
        assert_eq!(m.current_interval(), ReconnectConfig::instant().initial_interval);
        assert!(m.is_connected());
        assert_eq!(m.total_reconnects(), 1);
    }

    #[test]
    fn test_on_failure_increases_backoff() {
        let mut m = instant_manager();
        m.on_disconnect();
        let before = m.current_interval();
        m.on_failure();
        assert!(m.current_interval() >= before);
        assert_eq!(m.attempts(), 1);
    }

    #[test]
    fn test_max_attempts_gives_up() {
        let mut m = ReconnectManager::new(ReconnectConfig {
            max_attempts: Some(3),
            ..ReconnectConfig::instant()
        });
        m.on_disconnect();
        m.on_failure();
        m.on_failure();
        assert!(!m.is_giving_up());
        m.on_failure();
        assert!(m.is_giving_up());
        assert_eq!(m.state(), &ReconnectState::GaveUp);
    }

    #[test]
    fn test_no_reconnect_when_gave_up() {
        let mut m = ReconnectManager::new(ReconnectConfig {
            max_attempts: Some(1),
            ..ReconnectConfig::instant()
        });
        m.on_disconnect();
        m.on_failure();
        assert!(m.is_giving_up());
        assert!(!m.should_reconnect());
    }

    #[test]
    fn test_no_reconnect_when_connected() {
        let mut m = instant_manager();
        assert!(!m.should_reconnect());
    }

    #[test]
    fn test_no_reconnect_when_reconnecting() {
        let mut m = instant_manager();
        m.on_disconnect();
        m.on_attempt_start();
        assert_eq!(m.state(), &ReconnectState::Reconnecting);
        assert!(!m.should_reconnect());
    }

    #[test]
    fn test_total_downtime_accumulated() {
        let mut m = instant_manager();
        m.on_disconnect();
        std::thread::sleep(Duration::from_millis(20));
        m.on_connect();
        assert!(m.total_downtime() >= Duration::from_millis(10));
    }

    #[test]
    fn test_time_until_reconnect() {
        let mut m = ReconnectManager::new(ReconnectConfig {
            initial_interval: Duration::from_secs(60),
            ..ReconnectConfig::default()
        });
        m.on_disconnect();
        let remaining = m.time_until_reconnect();
        assert!(remaining > Duration::from_secs(50));
    }

    #[test]
    fn test_time_until_reconnect_zero_when_ready() {
        let mut m = instant_manager();
        m.on_disconnect();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(m.time_until_reconnect(), Duration::ZERO);
    }

    #[test]
    fn test_backoff_capped_at_max() {
        let mut m = ReconnectManager::new(ReconnectConfig {
            initial_interval: Duration::from_millis(10),
            max_interval: Duration::from_millis(100),
            multiplier: 10.0,
            jitter: 0.0,
            max_attempts: None,
            stable_threshold: Duration::from_secs(30),
        });
        m.on_disconnect();
        for _ in 0..10 {
            m.on_failure();
        }
        assert!(m.current_interval() <= Duration::from_millis(100));
    }

    #[test]
    fn test_mobile_preset() {
        let m = ReconnectManager::mobile();
        assert_eq!(m.config().initial_interval, Duration::from_millis(500));
        assert!(m.config().max_attempts.is_none());
    }

    #[test]
    fn test_stable_preset() {
        let m = ReconnectManager::stable();
        assert_eq!(m.config().max_attempts, Some(10));
    }

    #[test]
    fn test_check_stability_resets_counter() {
        let mut m = ReconnectManager::new(ReconnectConfig {
            stable_threshold: Duration::from_millis(10),
            ..ReconnectConfig::instant()
        });
        m.on_disconnect();
        m.on_failure();
        m.on_connect();
        assert_eq!(m.attempts(), 0); // on_connect resets too
    }

    #[test]
    fn test_multiple_reconnect_cycles() {
        let mut m = instant_manager();
        for _ in 0..3 {
            m.on_disconnect();
            std::thread::sleep(Duration::from_millis(20));
            assert!(m.should_reconnect());
            m.on_connect();
        }
        assert_eq!(m.total_reconnects(), 3);
        assert!(m.is_connected());
    }
}
