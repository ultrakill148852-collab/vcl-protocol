//! # VCL Tunnel
//!
//! [`VCLTunnel`] is a high-level facade that combines all VCL components
//! into a single easy-to-use object for building VPN applications.
//!
//! Instead of manually wiring together `VCLConnection`, `VCLTun`,
//! `KeepaliveManager`, `ReconnectManager`, `DnsFilter`, `Obfuscator`,
//! and `MtuNegotiator` — just create a `VCLTunnel`.
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::tunnel::{VCLTunnel, TunnelConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = TunnelConfig::mobile("10.0.0.1", "10.0.0.2");
//!     println!("Tunnel config created: {:?}", config.obfuscation_mode);
//! }
//! ```

use crate::error::VCLError;
use crate::keepalive::{KeepaliveConfig, KeepaliveManager, KeepaliveAction, KeepalivePreset};
use crate::reconnect::{ReconnectConfig, ReconnectManager};
use crate::dns::{DnsConfig, DnsFilter, DnsAction, DnsQueryType};
use crate::obfuscation::{ObfuscationConfig, ObfuscationMode, Obfuscator, recommended_mode};
use crate::mtu::{MtuConfig, MtuNegotiator};
use crate::metrics::VCLMetrics;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// High-level tunnel configuration.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Local TUN interface IP address.
    pub local_ip: String,
    /// Remote peer IP address.
    pub remote_ip: String,
    /// MTU for the tunnel interface.
    pub mtu: u16,
    /// Obfuscation mode for DPI bypass.
    pub obfuscation_mode: ObfuscationMode,
    /// Keepalive preset.
    pub keepalive: KeepalivePreset,
    /// Whether to enable DNS leak protection.
    pub dns_protection: bool,
    /// DNS upstream servers.
    pub dns_servers: Vec<String>,
    /// Domains to block via DNS.
    pub blocked_domains: Vec<String>,
    /// Domains that bypass the tunnel (split DNS).
    pub split_domains: Vec<String>,
    /// Maximum reconnect attempts (None = infinite).
    pub max_reconnect_attempts: Option<u32>,
}

impl TunnelConfig {
    /// Configuration optimised for mobile networks (МТС, Beeline).
    /// Full obfuscation, aggressive keepalive, mobile reconnect.
    pub fn mobile(local_ip: &str, remote_ip: &str) -> Self {
        TunnelConfig {
            local_ip: local_ip.to_string(),
            remote_ip: remote_ip.to_string(),
            mtu: 1380,
            obfuscation_mode: ObfuscationMode::Full,
            keepalive: KeepalivePreset::Mobile,
            dns_protection: true,
            dns_servers: vec![
                "1.1.1.1:53".to_string(),
                "1.0.0.1:53".to_string(),
            ],
            blocked_domains: Vec::new(),
            split_domains: Vec::new(),
            max_reconnect_attempts: Option::None,
        }
    }

    /// Configuration for home broadband.
    pub fn home(local_ip: &str, remote_ip: &str) -> Self {
        TunnelConfig {
            local_ip: local_ip.to_string(),
            remote_ip: remote_ip.to_string(),
            mtu: 1420,
            obfuscation_mode: ObfuscationMode::TlsMimicry,
            keepalive: KeepalivePreset::Home,
            dns_protection: true,
            dns_servers: vec![
                "1.1.1.1:53".to_string(),
            ],
            blocked_domains: Vec::new(),
            split_domains: Vec::new(),
            max_reconnect_attempts: Some(10),
        }
    }

    /// Configuration for corporate/office networks.
    pub fn corporate(local_ip: &str, remote_ip: &str) -> Self {
        TunnelConfig {
            local_ip: local_ip.to_string(),
            remote_ip: remote_ip.to_string(),
            mtu: 1400,
            obfuscation_mode: ObfuscationMode::Http2Mimicry,
            keepalive: KeepalivePreset::Corporate,
            dns_protection: true,
            dns_servers: vec![
                "8.8.8.8:53".to_string(),
            ],
            blocked_domains: Vec::new(),
            split_domains: Vec::new(),
            max_reconnect_attempts: Some(5),
        }
    }

    /// Auto-detect configuration from network hint string.
    pub fn auto(local_ip: &str, remote_ip: &str, network_hint: &str) -> Self {
        let mode = recommended_mode(network_hint);
        let keepalive = match network_hint.to_lowercase().as_str() {
            "mobile" | "mts" | "beeline" | "megafon" => KeepalivePreset::Mobile,
            "corporate" | "office"                    => KeepalivePreset::Corporate,
            _                                         => KeepalivePreset::Home,
        };
        TunnelConfig {
            local_ip: local_ip.to_string(),
            remote_ip: remote_ip.to_string(),
            mtu: 1400,
            obfuscation_mode: mode,
            keepalive,
            dns_protection: true,
            dns_servers: vec!["1.1.1.1:53".to_string()],
            blocked_domains: Vec::new(),
            split_domains: Vec::new(),
            max_reconnect_attempts: Option::None,
        }
    }

    /// Add a domain to block via DNS.
    pub fn block_domain(mut self, domain: &str) -> Self {
        self.blocked_domains.push(domain.to_string());
        self
    }

    /// Add a split DNS domain (bypasses tunnel).
    pub fn split_domain(mut self, domain: &str) -> Self {
        self.split_domains.push(domain.to_string());
        self
    }

    /// Set custom DNS servers.
    pub fn with_dns(mut self, servers: Vec<&str>) -> Self {
        self.dns_servers = servers.iter().map(|s| s.to_string()).collect();
        self
    }
}

/// Current state of the tunnel.
#[derive(Debug, Clone, PartialEq)]
pub enum TunnelState {
    /// Tunnel is stopped.
    Stopped,
    /// Tunnel is connecting.
    Connecting,
    /// Tunnel is active and passing traffic.
    Connected,
    /// Tunnel lost connection and is attempting to reconnect.
    Reconnecting,
    /// Tunnel has permanently failed.
    Failed,
}

/// Statistics snapshot from the tunnel.
#[derive(Debug, Clone)]
pub struct TunnelStats {
    /// Current tunnel state.
    pub state: TunnelState,
    /// Total bytes sent through the tunnel.
    pub bytes_sent: u64,
    /// Total bytes received through the tunnel.
    pub bytes_received: u64,
    /// Current packet loss rate (0.0–1.0).
    pub loss_rate: f64,
    /// Average RTT measured by keepalive pings.
    pub keepalive_rtt: Option<Duration>,
    /// Number of reconnections since tunnel started.
    pub reconnect_count: u64,
    /// Number of DNS queries intercepted.
    pub dns_intercepted: u64,
    /// Number of DNS queries blocked.
    pub dns_blocked: u64,
    /// Obfuscation overhead ratio.
    pub obfuscation_overhead: f64,
    /// How long the tunnel has been running.
    pub uptime: Duration,
    /// Current MTU in use.
    pub mtu: u16,
}

/// High-level VPN tunnel facade.
///
/// Combines `KeepaliveManager`, `ReconnectManager`, `DnsFilter`,
/// `Obfuscator`, `MtuNegotiator`, and `VCLMetrics` into one object.
pub struct VCLTunnel {
    config: TunnelConfig,
    state: TunnelState,
    keepalive: KeepaliveManager,
    reconnect: ReconnectManager,
    dns: DnsFilter,
    obfuscator: Obfuscator,
    mtu: MtuNegotiator,
    metrics: VCLMetrics,
    started_at: Option<Instant>,
    reconnect_count: u64,
}

impl VCLTunnel {
    /// Create a new tunnel with the given configuration.
    pub fn new(config: TunnelConfig) -> Self {
        let keepalive = KeepaliveManager::from_preset(config.keepalive.clone());

        let reconnect_config = ReconnectConfig {
            max_attempts: config.max_reconnect_attempts,
            ..match config.keepalive {
                KeepalivePreset::Mobile     => ReconnectConfig::mobile(),
                KeepalivePreset::Corporate  => ReconnectConfig::stable(),
                _                           => ReconnectConfig::default(),
            }
        };
        let reconnect = ReconnectManager::new(reconnect_config);

        let mut dns_config = DnsConfig {
            upstream_servers: config.dns_servers.clone(),
            split_dns_domains: config.split_domains.clone(),
            blocked_domains: config.blocked_domains.clone(),
            enable_cache: true,
            cache_ttl: Duration::from_secs(300),
            max_cache_size: 1024,
        };
        let dns = DnsFilter::new(dns_config);

        let obf_config = match &config.obfuscation_mode {
            ObfuscationMode::None             => ObfuscationConfig::none(),
            ObfuscationMode::Padding          => ObfuscationConfig::padding(),
            ObfuscationMode::SizeNormalization => ObfuscationConfig::size_normalization(),
            ObfuscationMode::TlsMimicry       => ObfuscationConfig::tls_mimicry(),
            ObfuscationMode::Http2Mimicry     => ObfuscationConfig::http2_mimicry(),
            ObfuscationMode::Full             => ObfuscationConfig::full(),
        };
        let obfuscator = Obfuscator::new(obf_config);

        let mtu_config = MtuConfig {
            start_mtu: config.mtu as usize,
            max_mtu: config.mtu as usize,
            ..MtuConfig::default()
        };
        let mut mtu = MtuNegotiator::new(mtu_config);
        mtu.set_mtu(config.mtu as usize);

        info!(
            local = %config.local_ip,
            remote = %config.remote_ip,
            mtu = config.mtu,
            obfuscation = ?config.obfuscation_mode,
            "VCLTunnel created"
        );

        VCLTunnel {
            config,
            state: TunnelState::Stopped,
            keepalive,
            reconnect,
            dns,
            obfuscator,
            mtu,
            metrics: VCLMetrics::new(),
            started_at: Option::None,
            reconnect_count: 0,
        }
    }

    // ─── Lifecycle ────────────────────────────────────────────────────────────

    /// Mark the tunnel as connecting.
    pub fn on_connecting(&mut self) {
        self.state = TunnelState::Connecting;
        self.started_at = Some(Instant::now());
        info!(remote = %self.config.remote_ip, "VCLTunnel connecting");
    }

    /// Mark the tunnel as connected. Resets reconnect backoff.
    pub fn on_connected(&mut self) {
        self.state = TunnelState::Connected;
        self.reconnect.on_connect();
        self.metrics.record_handshake();
        info!(remote = %self.config.remote_ip, "VCLTunnel connected");
    }

    /// Mark the tunnel as disconnected. Starts reconnect backoff.
    pub fn on_disconnected(&mut self) {
        self.state = TunnelState::Reconnecting;
        self.reconnect.on_disconnect();
        warn!(remote = %self.config.remote_ip, "VCLTunnel disconnected");
    }

    /// Mark the tunnel as permanently failed.
    pub fn on_failed(&mut self) {
        self.state = TunnelState::Failed;
        warn!("VCLTunnel permanently failed");
    }

    /// Stop the tunnel.
    pub fn stop(&mut self) {
        self.state = TunnelState::Stopped;
        info!("VCLTunnel stopped");
    }

    // ─── Keepalive ────────────────────────────────────────────────────────────

    /// Check keepalive — call every second in your main loop.
    ///
    /// Returns the action to take.
    pub fn check_keepalive(&mut self) -> KeepaliveAction {
        self.keepalive.check()
    }

    /// Record that a keepalive ping was sent.
    pub fn keepalive_sent(&mut self) {
        self.keepalive.record_keepalive_sent();
    }

    /// Record that a pong was received.
    pub fn keepalive_pong_received(&mut self) {
        self.keepalive.record_pong_received();
        if let Some(rtt) = self.keepalive.srtt() {
            debug!(rtt_ms = rtt.as_millis(), "Keepalive RTT updated");
        }
    }

    /// Record any data activity — resets keepalive timer.
    pub fn record_activity(&mut self) {
        self.keepalive.record_activity();
    }

    // ─── Reconnect ────────────────────────────────────────────────────────────

    /// Returns true if it's time to attempt reconnection.
    pub fn should_reconnect(&mut self) -> bool {
        self.reconnect.should_reconnect()
    }

    /// Call when a reconnect attempt starts.
    pub fn reconnect_attempt_start(&mut self) {
        self.reconnect.on_attempt_start();
        self.reconnect_count += 1;
        info!(attempt = self.reconnect.attempts(), "Reconnect attempt starting");
    }

    /// Call when a reconnect attempt fails.
    pub fn reconnect_failed(&mut self) {
        self.reconnect.on_failure();
        if self.reconnect.is_giving_up() {
            self.on_failed();
        }
    }

    /// Returns true if the reconnect manager has given up.
    pub fn is_giving_up(&self) -> bool {
        self.reconnect.is_giving_up()
    }

    /// How long until next reconnect attempt.
    pub fn time_until_reconnect(&self) -> Duration {
        self.reconnect.time_until_reconnect()
    }

    // ─── Obfuscation ──────────────────────────────────────────────────────────

    /// Obfuscate outgoing packet data.
    pub fn obfuscate(&mut self, data: &[u8]) -> Vec<u8> {
        let result = self.obfuscator.obfuscate(data);
        self.metrics.record_sent(data.len());
        result
    }

    /// Deobfuscate incoming packet data.
    pub fn deobfuscate(&mut self, data: &[u8]) -> Result<Vec<u8>, VCLError> {
        let result = self.obfuscator.deobfuscate(data)?;
        self.metrics.record_received(result.len());
        Ok(result)
    }

    /// Returns jitter delay in ms to apply before sending.
    pub fn jitter_ms(&self) -> u64 {
        self.obfuscator.jitter_ms()
    }

    // ─── DNS ──────────────────────────────────────────────────────────────────

    /// Decide what to do with a DNS query for the given domain.
    pub fn dns_decide(&mut self, domain: &str) -> DnsAction {
        self.dns.decide(domain, &DnsQueryType::A)
    }

    /// Cache a DNS response.
    pub fn dns_cache(&mut self, domain: &str, addr: IpAddr) {
        self.dns.cache_response(domain, addr);
    }

    /// Returns true if a raw UDP payload looks like a DNS packet.
    pub fn is_dns_packet(data: &[u8]) -> bool {
        DnsFilter::is_dns_packet(data)
    }

    /// Block a domain at runtime.
    pub fn block_domain(&mut self, domain: &str) {
        self.dns.block_domain(domain);
    }

    /// Add a split DNS domain at runtime.
    pub fn add_split_domain(&mut self, domain: &str) {
        self.dns.add_split_domain(domain);
    }

    // ─── MTU ──────────────────────────────────────────────────────────────────

    /// Returns the current recommended fragment size.
    pub fn fragment_size(&self) -> usize {
        self.mtu.recommended_fragment_size()
    }

    /// Returns the current path MTU.
    pub fn current_mtu(&self) -> usize {
        self.mtu.current_mtu()
    }

    /// Update MTU from external discovery.
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu.set_mtu(mtu);
        info!(mtu, "VCLTunnel MTU updated");
    }

    // ─── Metrics ──────────────────────────────────────────────────────────────

    /// Record a retransmitted packet.
    pub fn record_retransmit(&mut self) {
        self.metrics.record_retransmit();
    }

    /// Returns a statistics snapshot.
    pub fn stats(&self) -> TunnelStats {
        TunnelStats {
            state: self.state.clone(),
            bytes_sent: self.metrics.bytes_sent,
            bytes_received: self.metrics.bytes_received,
            loss_rate: self.metrics.loss_rate(),
            keepalive_rtt: self.keepalive.srtt(),
            reconnect_count: self.reconnect_count,
            dns_intercepted: self.dns.total_intercepted(),
            dns_blocked: self.dns.total_blocked(),
            obfuscation_overhead: self.obfuscator.overhead_ratio(),
            uptime: self.started_at.map(|t| t.elapsed()).unwrap_or(Duration::ZERO),
            mtu: self.mtu.current_mtu() as u16,
        }
    }

    /// Returns the current tunnel state.
    pub fn state(&self) -> &TunnelState {
        &self.state
    }

    /// Returns true if the tunnel is currently connected.
    pub fn is_connected(&self) -> bool {
        self.state == TunnelState::Connected
    }

    /// Returns a reference to the config.
    pub fn config(&self) -> &TunnelConfig {
        &self.config
    }

    /// Returns a reference to the raw metrics.
    pub fn metrics(&self) -> &VCLMetrics {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mobile_tunnel() -> VCLTunnel {
        VCLTunnel::new(TunnelConfig::mobile("10.0.0.1", "10.0.0.2"))
    }

    fn home_tunnel() -> VCLTunnel {
        VCLTunnel::new(TunnelConfig::home("10.0.0.1", "10.0.0.2"))
    }

    fn corporate_tunnel() -> VCLTunnel {
        VCLTunnel::new(TunnelConfig::corporate("10.0.0.1", "10.0.0.2"))
    }

    // ─── Config tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_mobile_config() {
        let c = TunnelConfig::mobile("10.0.0.1", "10.0.0.2");
        assert_eq!(c.local_ip, "10.0.0.1");
        assert_eq!(c.remote_ip, "10.0.0.2");
        assert_eq!(c.mtu, 1380);
        assert_eq!(c.obfuscation_mode, ObfuscationMode::Full);
        assert!(c.dns_protection);
        assert!(c.max_reconnect_attempts.is_none());
    }

    #[test]
    fn test_home_config() {
        let c = TunnelConfig::home("10.0.0.1", "10.0.0.2");
        assert_eq!(c.mtu, 1420);
        assert_eq!(c.obfuscation_mode, ObfuscationMode::TlsMimicry);
        assert_eq!(c.max_reconnect_attempts, Some(10));
    }

    #[test]
    fn test_corporate_config() {
        let c = TunnelConfig::corporate("10.0.0.1", "10.0.0.2");
        assert_eq!(c.obfuscation_mode, ObfuscationMode::Http2Mimicry);
        assert_eq!(c.max_reconnect_attempts, Some(5));
    }

    #[test]
    fn test_auto_config_mobile() {
        let c = TunnelConfig::auto("10.0.0.1", "10.0.0.2", "mts");
        assert_eq!(c.obfuscation_mode, ObfuscationMode::Full);
    }

    #[test]
    fn test_auto_config_home() {
        let c = TunnelConfig::auto("10.0.0.1", "10.0.0.2", "home");
        assert_eq!(c.obfuscation_mode, ObfuscationMode::TlsMimicry);
    }

    #[test]
    fn test_config_block_domain() {
        let c = TunnelConfig::mobile("10.0.0.1", "10.0.0.2")
            .block_domain("ads.com")
            .block_domain("tracking.io");
        assert_eq!(c.blocked_domains.len(), 2);
    }

    #[test]
    fn test_config_split_domain() {
        let c = TunnelConfig::mobile("10.0.0.1", "10.0.0.2")
            .split_domain("corp.internal");
        assert_eq!(c.split_domains.len(), 1);
    }

    #[test]
    fn test_config_with_dns() {
        let c = TunnelConfig::mobile("10.0.0.1", "10.0.0.2")
            .with_dns(vec!["8.8.8.8:53", "8.8.4.4:53"]);
        assert_eq!(c.dns_servers.len(), 2);
    }

    // ─── Lifecycle tests ───────────────────────────────────────────────────────

    #[test]
    fn test_initial_state() {
        let t = mobile_tunnel();
        assert_eq!(t.state(), &TunnelState::Stopped);
        assert!(!t.is_connected());
    }

    #[test]
    fn test_on_connecting() {
        let mut t = mobile_tunnel();
        t.on_connecting();
        assert_eq!(t.state(), &TunnelState::Connecting);
    }

    #[test]
    fn test_on_connected() {
        let mut t = mobile_tunnel();
        t.on_connecting();
        t.on_connected();
        assert_eq!(t.state(), &TunnelState::Connected);
        assert!(t.is_connected());
    }

    #[test]
    fn test_on_disconnected() {
        let mut t = mobile_tunnel();
        t.on_connecting();
        t.on_connected();
        t.on_disconnected();
        assert_eq!(t.state(), &TunnelState::Reconnecting);
        assert!(!t.is_connected());
    }

    #[test]
    fn test_stop() {
        let mut t = mobile_tunnel();
        t.on_connecting();
        t.on_connected();
        t.stop();
        assert_eq!(t.state(), &TunnelState::Stopped);
    }

    #[test]
    fn test_on_failed() {
        let mut t = mobile_tunnel();
        t.on_failed();
        assert_eq!(t.state(), &TunnelState::Failed);
    }

    // ─── Obfuscation tests ─────────────────────────────────────────────────────

    #[test]
    fn test_obfuscate_deobfuscate() {
        let mut t = mobile_tunnel();
        let data = b"secret tunnel data";
        let obfuscated = t.obfuscate(data);
        let restored = t.deobfuscate(&obfuscated).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_obfuscate_records_metrics() {
        let mut t = mobile_tunnel();
        t.obfuscate(b"hello");
        t.obfuscate(b"world");
        assert_eq!(t.metrics().bytes_sent, 10);
    }

    #[test]
    fn test_deobfuscate_records_metrics() {
        let mut t = mobile_tunnel();
        let obf = t.obfuscate(b"hello");
        t.deobfuscate(&obf).unwrap();
        assert_eq!(t.metrics().bytes_received, 5);
    }

    #[test]
    fn test_jitter_ms() {
        let t = mobile_tunnel();
        assert!(t.jitter_ms() <= 15); // full mode max jitter
    }

    // ─── DNS tests ─────────────────────────────────────────────────────────────

    #[test]
    fn test_dns_forward() {
        let mut t = home_tunnel();
        let action = t.dns_decide("example.com");
        assert_eq!(action, DnsAction::ForwardThroughTunnel);
    }

    #[test]
    fn test_dns_block_runtime() {
        let mut t = home_tunnel();
        t.block_domain("evil.com");
        let action = t.dns_decide("evil.com");
        assert_eq!(action, DnsAction::Block);
    }

    #[test]
    fn test_dns_block_from_config() {
        let config = TunnelConfig::home("10.0.0.1", "10.0.0.2")
            .block_domain("ads.com");
        let mut t = VCLTunnel::new(config);
        assert_eq!(t.dns_decide("ads.com"), DnsAction::Block);
    }

    #[test]
    fn test_dns_split_from_config() {
        let config = TunnelConfig::home("10.0.0.1", "10.0.0.2")
            .split_domain("corp.internal");
        let mut t = VCLTunnel::new(config);
        assert_eq!(t.dns_decide("host.corp.internal"), DnsAction::AllowDirect);
    }

    #[test]
    fn test_dns_cache() {
        let mut t = home_tunnel();
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        t.dns_cache("cached.com", addr);
        let action = t.dns_decide("cached.com");
        assert_eq!(action, DnsAction::ReturnCached(addr));
    }

    #[test]
    fn test_is_dns_packet() {
        let pkt = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(VCLTunnel::is_dns_packet(&pkt));
        assert!(!VCLTunnel::is_dns_packet(&[0u8; 4]));
    }

    // ─── MTU tests ─────────────────────────────────────────────────────────────

    #[test]
    fn test_mtu_initial() {
        let t = mobile_tunnel();
        assert_eq!(t.current_mtu(), 1380);
        assert!(t.fragment_size() > 0);
        assert!(t.fragment_size() < 1380);
    }

    #[test]
    fn test_set_mtu() {
        let mut t = home_tunnel();
        t.set_mtu(1280);
        assert_eq!(t.current_mtu(), 1280);
    }

    // ─── Stats tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_stats_initial() {
        let t = mobile_tunnel();
        let s = t.stats();
        assert_eq!(s.bytes_sent, 0);
        assert_eq!(s.bytes_received, 0);
        assert_eq!(s.reconnect_count, 0);
        assert_eq!(s.dns_intercepted, 0);
        assert_eq!(s.loss_rate, 0.0);
        assert_eq!(s.mtu, 1380);
    }

    #[test]
    fn test_stats_after_traffic() {
        let mut t = mobile_tunnel();
        t.on_connecting();
        t.on_connected();
        let obf = t.obfuscate(b"hello world");
        t.deobfuscate(&obf).unwrap();
        let s = t.stats();
        assert_eq!(s.bytes_sent, 11);
        assert_eq!(s.bytes_received, 11);
        assert_eq!(s.state, TunnelState::Connected);
        assert!(s.uptime > Duration::ZERO);
    }

    #[test]
    fn test_stats_dns_counts() {
        let mut t = home_tunnel();
        t.block_domain("bad.com");
        t.dns_decide("good.com");
        t.dns_decide("bad.com");
        let s = t.stats();
        assert_eq!(s.dns_intercepted, 2);
        assert_eq!(s.dns_blocked, 1);
    }

    #[test]
    fn test_reconnect_count_increments() {
        let mut t = mobile_tunnel();
        t.on_connected();
        t.on_disconnected();
        t.reconnect_attempt_start();
        t.reconnect_attempt_start();
        assert_eq!(t.reconnect_count, 2);
    }

    // ─── Reconnect tests ───────────────────────────────────────────────────────

    #[test]
    fn test_reconnect_after_disconnect() {
        let mut t = VCLTunnel::new(TunnelConfig {
            max_reconnect_attempts: Some(3),
            ..TunnelConfig::home("10.0.0.1", "10.0.0.2")
        });
        t.on_connected();
        t.on_disconnected();
        assert!(!t.is_giving_up());
    }

    #[test]
    fn test_giving_up_after_max_attempts() {
        let mut t = VCLTunnel::new(TunnelConfig {
            max_reconnect_attempts: Some(1),
            ..TunnelConfig::home("10.0.0.1", "10.0.0.2")
        });
        t.on_connected();
        t.on_disconnected();
        t.reconnect_failed();
        assert!(t.is_giving_up());
        assert_eq!(t.state(), &TunnelState::Failed);
    }

    #[test]
    fn test_config_ref() {
        let t = mobile_tunnel();
        assert_eq!(t.config().local_ip, "10.0.0.1");
        assert_eq!(t.config().remote_ip, "10.0.0.2");
    }

    #[test]
    fn test_all_three_presets_create_ok() {
        let _m = mobile_tunnel();
        let _h = home_tunnel();
        let _c = corporate_tunnel();
    }
}
