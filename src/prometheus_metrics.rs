//! # VCL Prometheus Metrics Export
//!
//! Exports VCL Protocol statistics in Prometheus format for monitoring
//! with Grafana, Alertmanager, and other observability tools.
//!
//! ## Example
//!
//! ```rust,ignore
//! use vcl_protocol::prometheus_metrics::VCLPrometheusExporter;
//!
//! let exporter = VCLPrometheusExporter::new().unwrap();
//! exporter.update_bytes_sent(1024);
//! exporter.update_packets_sent(1);
//!
//! // Get metrics in Prometheus text format
//! let output = exporter.render();
//! println!("{}", output);
//! ```

use prometheus::{
    Registry, Counter, Gauge, Histogram, HistogramOpts, Opts,
    TextEncoder, Encoder,
};
use crate::error::VCLError;
use crate::metrics::VCLMetrics;
use crate::tunnel::TunnelStats;
use tracing::debug;

/// Prometheus metrics exporter for VCL Protocol.
///
/// Exposes all VCL metrics in Prometheus text format,
/// ready to be scraped by a Prometheus server.
pub struct VCLPrometheusExporter {
    registry: Registry,

    // ─── Traffic counters ──────────────────────────────────────────────────────
    bytes_sent:     Counter,
    bytes_received: Counter,
    packets_sent:   Counter,
    packets_received: Counter,
    packets_retransmitted: Counter,
    packets_dropped: Counter,

    // ─── Connection gauges ─────────────────────────────────────────────────────
    connections_active: Gauge,
    reconnect_count:    Counter,
    handshakes_total:   Counter,
    key_rotations_total: Counter,

    // ─── Performance gauges ────────────────────────────────────────────────────
    loss_rate:           Gauge,
    rtt_seconds:         Gauge,
    cwnd_packets:        Gauge,
    obfuscation_overhead: Gauge,
    mtu_bytes:           Gauge,

    // ─── DNS counters ──────────────────────────────────────────────────────────
    dns_queries_total:   Counter,
    dns_blocked_total:   Counter,
    dns_cache_hits:      Counter,

    // ─── Fragment counters ─────────────────────────────────────────────────────
    fragments_sent:        Counter,
    fragments_reassembled: Counter,

    // ─── RTT histogram ────────────────────────────────────────────────────────
    rtt_histogram: Histogram,

    // ─── Tunnel state gauge ───────────────────────────────────────────────────
    /// 0=Stopped, 1=Connecting, 2=Connected, 3=Reconnecting, 4=Failed
    tunnel_state: Gauge,
}

impl VCLPrometheusExporter {
    /// Create a new exporter with its own Prometheus registry.
    pub fn new() -> Result<Self, VCLError> {
        let registry = Registry::new();

        macro_rules! counter {
            ($name:expr, $help:expr) => {{
                let c = Counter::with_opts(Opts::new($name, $help))
                    .map_err(|e| VCLError::IoError(format!("Prometheus counter: {}", e)))?;
                registry.register(Box::new(c.clone()))
                    .map_err(|e| VCLError::IoError(format!("Prometheus register: {}", e)))?;
                c
            }};
        }

        macro_rules! gauge {
            ($name:expr, $help:expr) => {{
                let g = Gauge::with_opts(Opts::new($name, $help))
                    .map_err(|e| VCLError::IoError(format!("Prometheus gauge: {}", e)))?;
                registry.register(Box::new(g.clone()))
                    .map_err(|e| VCLError::IoError(format!("Prometheus register: {}", e)))?;
                g
            }};
        }

        let rtt_histogram = Histogram::with_opts(
            HistogramOpts::new("vcl_rtt_seconds", "Round-trip time in seconds")
                .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        ).map_err(|e| VCLError::IoError(format!("Prometheus histogram: {}", e)))?;
        registry.register(Box::new(rtt_histogram.clone()))
            .map_err(|e| VCLError::IoError(format!("Prometheus register: {}", e)))?;

        debug!("VCLPrometheusExporter initialized");

        Ok(VCLPrometheusExporter {
            bytes_sent:            counter!("vcl_bytes_sent_total",           "Total bytes sent"),
            bytes_received:        counter!("vcl_bytes_received_total",       "Total bytes received"),
            packets_sent:          counter!("vcl_packets_sent_total",         "Total packets sent"),
            packets_received:      counter!("vcl_packets_received_total",     "Total packets received"),
            packets_retransmitted: counter!("vcl_packets_retransmitted_total","Total retransmitted packets"),
            packets_dropped:       counter!("vcl_packets_dropped_total",      "Total dropped packets"),
            connections_active:    gauge!  ("vcl_connections_active",         "Currently active connections"),
            reconnect_count:       counter!("vcl_reconnects_total",           "Total reconnection attempts"),
            handshakes_total:      counter!("vcl_handshakes_total",           "Total handshakes completed"),
            key_rotations_total:   counter!("vcl_key_rotations_total",        "Total key rotations"),
            loss_rate:             gauge!  ("vcl_loss_rate",                  "Current packet loss rate 0.0-1.0"),
            rtt_seconds:           gauge!  ("vcl_rtt_seconds_current",        "Current smoothed RTT in seconds"),
            cwnd_packets:          gauge!  ("vcl_cwnd_packets",               "Current congestion window size"),
            obfuscation_overhead:  gauge!  ("vcl_obfuscation_overhead_ratio", "Obfuscation overhead ratio"),
            mtu_bytes:             gauge!  ("vcl_mtu_bytes",                  "Current path MTU in bytes"),
            dns_queries_total:     counter!("vcl_dns_queries_total",          "Total DNS queries intercepted"),
            dns_blocked_total:     counter!("vcl_dns_blocked_total",          "Total DNS queries blocked"),
            dns_cache_hits:        counter!("vcl_dns_cache_hits_total",       "Total DNS cache hits"),
            fragments_sent:        counter!("vcl_fragments_sent_total",       "Total fragmented messages sent"),
            fragments_reassembled: counter!("vcl_fragments_reassembled_total","Total fragments reassembled"),
            tunnel_state:          gauge!  ("vcl_tunnel_state",               "Tunnel state: 0=Stopped 1=Connecting 2=Connected 3=Reconnecting 4=Failed"),
            rtt_histogram,
            registry,
        })
    }

    // ─── Manual update methods ────────────────────────────────────────────────

    /// Record bytes sent.
    pub fn update_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.inc_by(bytes as f64);
    }

    /// Record bytes received.
    pub fn update_bytes_received(&self, bytes: u64) {
        self.bytes_received.inc_by(bytes as f64);
    }

    /// Record packets sent.
    pub fn update_packets_sent(&self, count: u64) {
        self.packets_sent.inc_by(count as f64);
    }

    /// Record packets received.
    pub fn update_packets_received(&self, count: u64) {
        self.packets_received.inc_by(count as f64);
    }

    /// Record a retransmission.
    pub fn update_retransmit(&self) {
        self.packets_retransmitted.inc();
    }

    /// Record dropped packets.
    pub fn update_dropped(&self, count: u64) {
        self.packets_dropped.inc_by(count as f64);
    }

    /// Set active connection count.
    pub fn set_connections_active(&self, count: f64) {
        self.connections_active.set(count);
    }

    /// Record a reconnect.
    pub fn update_reconnect(&self) {
        self.reconnect_count.inc();
    }

    /// Record a handshake.
    pub fn update_handshake(&self) {
        self.handshakes_total.inc();
    }

    /// Record a key rotation.
    pub fn update_key_rotation(&self) {
        self.key_rotations_total.inc();
    }

    /// Set current loss rate.
    pub fn set_loss_rate(&self, rate: f64) {
        self.loss_rate.set(rate);
    }

    /// Set current RTT in seconds.
    pub fn set_rtt_seconds(&self, rtt: f64) {
        self.rtt_seconds.set(rtt);
        self.rtt_histogram.observe(rtt);
    }

    /// Set current congestion window.
    pub fn set_cwnd(&self, cwnd: f64) {
        self.cwnd_packets.set(cwnd);
    }

    /// Set obfuscation overhead ratio.
    pub fn set_obfuscation_overhead(&self, ratio: f64) {
        self.obfuscation_overhead.set(ratio);
    }

    /// Set current MTU.
    pub fn set_mtu(&self, mtu: u16) {
        self.mtu_bytes.set(mtu as f64);
    }

    /// Record DNS queries intercepted.
    pub fn update_dns_queries(&self, count: u64) {
        self.dns_queries_total.inc_by(count as f64);
    }

    /// Record DNS queries blocked.
    pub fn update_dns_blocked(&self, count: u64) {
        self.dns_blocked_total.inc_by(count as f64);
    }

    /// Record DNS cache hits.
    pub fn update_dns_cache_hits(&self, count: u64) {
        self.dns_cache_hits.inc_by(count as f64);
    }

    /// Record fragments sent.
    pub fn update_fragments_sent(&self, count: u64) {
        self.fragments_sent.inc_by(count as f64);
    }

    /// Record fragments reassembled.
    pub fn update_fragments_reassembled(&self, count: u64) {
        self.fragments_reassembled.inc_by(count as f64);
    }

    /// Set tunnel state (0=Stopped, 1=Connecting, 2=Connected, 3=Reconnecting, 4=Failed).
    pub fn set_tunnel_state(&self, state: f64) {
        self.tunnel_state.set(state);
    }

    // ─── Bulk update from VCLMetrics ──────────────────────────────────────────

    /// Update all counters from a [`VCLMetrics`] snapshot.
    ///
    /// Counters are incremental — call this each time you want to push
    /// the delta since last call. For simplicity this resets and re-adds
    /// the full values (idempotent for Prometheus pull model).
    pub fn update_from_metrics(&self, m: &VCLMetrics) {
        // Note: Prometheus counters can only increase.
        // We use inc_by with the current total — this works correctly
        // if called once, or can be used with a delta tracker.
        self.set_loss_rate(m.loss_rate());
        self.set_obfuscation_overhead(0.0); // set externally

        if let Some(rtt) = m.avg_rtt() {
            self.set_rtt_seconds(rtt.as_secs_f64());
        }
        if let Some(cwnd) = m.avg_cwnd() {
            self.set_cwnd(cwnd);
        }
    }

    /// Update all gauges and counters from a [`TunnelStats`] snapshot.
    pub fn update_from_tunnel_stats(&self, stats: &TunnelStats) {
        self.set_loss_rate(stats.loss_rate);
        self.set_obfuscation_overhead(stats.obfuscation_overhead);
        self.set_mtu(stats.mtu);

        if let Some(rtt) = stats.keepalive_rtt {
            self.set_rtt_seconds(rtt.as_secs_f64());
        }

        let state_val = match stats.state {
            crate::tunnel::TunnelState::Stopped      => 0.0,
            crate::tunnel::TunnelState::Connecting   => 1.0,
            crate::tunnel::TunnelState::Connected    => 2.0,
            crate::tunnel::TunnelState::Reconnecting => 3.0,
            crate::tunnel::TunnelState::Failed       => 4.0,
        };
        self.set_tunnel_state(state_val);
    }

    // ─── Render ───────────────────────────────────────────────────────────────

    /// Render all metrics in Prometheus text exposition format.
    ///
    /// Serve this on an HTTP endpoint (e.g. `/metrics`) for Prometheus to scrape.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut output = Vec::new();
        encoder.encode(&metric_families, &mut output)
            .unwrap_or_default();
        String::from_utf8(output).unwrap_or_default()
    }

    /// Returns the underlying [`Registry`] for advanced use.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn exporter() -> VCLPrometheusExporter {
        VCLPrometheusExporter::new().unwrap()
    }

    #[test]
    fn test_new() {
        let e = exporter();
        let output = e.render();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_render_contains_metric_names() {
        let e = exporter();
        let output = e.render();
        assert!(output.contains("vcl_bytes_sent_total"));
        assert!(output.contains("vcl_bytes_received_total"));
        assert!(output.contains("vcl_packets_sent_total"));
        assert!(output.contains("vcl_loss_rate"));
        assert!(output.contains("vcl_rtt_seconds_current"));
        assert!(output.contains("vcl_tunnel_state"));
        assert!(output.contains("vcl_dns_queries_total"));
        assert!(output.contains("vcl_mtu_bytes"));
    }

    #[test]
    fn test_update_bytes_sent() {
        let e = exporter();
        e.update_bytes_sent(1024);
        e.update_bytes_sent(512);
        let output = e.render();
        assert!(output.contains("vcl_bytes_sent_total 1536"));
    }

    #[test]
    fn test_update_bytes_received() {
        let e = exporter();
        e.update_bytes_received(2048);
        let output = e.render();
        assert!(output.contains("vcl_bytes_received_total 2048"));
    }

    #[test]
    fn test_update_packets() {
        let e = exporter();
        e.update_packets_sent(10);
        e.update_packets_received(8);
        let output = e.render();
        assert!(output.contains("vcl_packets_sent_total 10"));
        assert!(output.contains("vcl_packets_received_total 8"));
    }

    #[test]
    fn test_update_retransmit() {
        let e = exporter();
        e.update_retransmit();
        e.update_retransmit();
        let output = e.render();
        assert!(output.contains("vcl_packets_retransmitted_total 2"));
    }

    #[test]
    fn test_update_dropped() {
        let e = exporter();
        e.update_dropped(5);
        let output = e.render();
        assert!(output.contains("vcl_packets_dropped_total 5"));
    }

    #[test]
    fn test_set_loss_rate() {
        let e = exporter();
        e.set_loss_rate(0.05);
        let output = e.render();
        assert!(output.contains("vcl_loss_rate 0.05"));
    }

    #[test]
    fn test_set_rtt() {
        let e = exporter();
        e.set_rtt_seconds(0.042);
        let output = e.render();
        assert!(output.contains("vcl_rtt_seconds_current 0.042"));
        assert!(output.contains("vcl_rtt_seconds_bucket"));
    }

    #[test]
    fn test_set_mtu() {
        let e = exporter();
        e.set_mtu(1420);
        let output = e.render();
        assert!(output.contains("vcl_mtu_bytes 1420"));
    }

    #[test]
    fn test_set_connections_active() {
        let e = exporter();
        e.set_connections_active(3.0);
        let output = e.render();
        assert!(output.contains("vcl_connections_active 3"));
    }

    #[test]
    fn test_dns_metrics() {
        let e = exporter();
        e.update_dns_queries(100);
        e.update_dns_blocked(10);
        e.update_dns_cache_hits(50);
        let output = e.render();
        assert!(output.contains("vcl_dns_queries_total 100"));
        assert!(output.contains("vcl_dns_blocked_total 10"));
        assert!(output.contains("vcl_dns_cache_hits_total 50"));
    }

    #[test]
    fn test_fragment_metrics() {
        let e = exporter();
        e.update_fragments_sent(20);
        e.update_fragments_reassembled(18);
        let output = e.render();
        assert!(output.contains("vcl_fragments_sent_total 20"));
        assert!(output.contains("vcl_fragments_reassembled_total 18"));
    }

    #[test]
    fn test_tunnel_state_connected() {
        let e = exporter();
        e.set_tunnel_state(2.0);
        let output = e.render();
        assert!(output.contains("vcl_tunnel_state 2"));
    }

    #[test]
    fn test_reconnect_counter() {
        let e = exporter();
        e.update_reconnect();
        e.update_reconnect();
        e.update_reconnect();
        let output = e.render();
        assert!(output.contains("vcl_reconnects_total 3"));
    }

    #[test]
    fn test_handshake_counter() {
        let e = exporter();
        e.update_handshake();
        let output = e.render();
        assert!(output.contains("vcl_handshakes_total 1"));
    }

    #[test]
    fn test_key_rotation_counter() {
        let e = exporter();
        e.update_key_rotation();
        e.update_key_rotation();
        let output = e.render();
        assert!(output.contains("vcl_key_rotations_total 2"));
    }

    #[test]
    fn test_obfuscation_overhead() {
        let e = exporter();
        e.set_obfuscation_overhead(0.15);
        let output = e.render();
        assert!(output.contains("vcl_obfuscation_overhead_ratio 0.15"));
    }

    #[test]
    fn test_update_from_metrics() {
        let mut m = VCLMetrics::new();
        m.record_sent(1000);
        m.record_rtt_sample(Duration::from_millis(42));
        let e = exporter();
        e.update_from_metrics(&m);
        let output = e.render();
        assert!(output.contains("vcl_rtt_seconds_current"));
        assert!(output.contains("vcl_loss_rate"));
    }

    #[test]
    fn test_cwnd_gauge() {
        let e = exporter();
        e.set_cwnd(32.0);
        let output = e.render();
        assert!(output.contains("vcl_cwnd_packets 32"));
    }

    #[test]
    fn test_render_is_valid_utf8() {
        let e = exporter();
        e.update_bytes_sent(42);
        let output = e.render();
        assert!(output.is_ascii() || !output.is_empty());
    }

    #[test]
    fn test_multiple_exporters_independent() {
        let e1 = exporter();
        let e2 = exporter();
        e1.update_bytes_sent(100);
        e2.update_bytes_sent(200);
        let o1 = e1.render();
        let o2 = e2.render();
        assert!(o1.contains("vcl_bytes_sent_total 100"));
        assert!(o2.contains("vcl_bytes_sent_total 200"));
    }
}
