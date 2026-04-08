//! # VCL DNS Leak Protection
//!
//! Prevents DNS queries from leaking outside the VCL tunnel.
//!
//! ## The problem
//!
//! ```text
//! Without DNS protection:
//!   App → DNS query → OS resolver → ISP DNS → LEAK!
//!   App → data → VCL tunnel → OK
//!
//! With DNS protection:
//!   App → DNS query → VCLDnsFilter → VCL tunnel → private DNS → OK
//!   App → data → VCL tunnel → OK
//! ```
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::dns::{DnsConfig, DnsFilter, DnsPacket};
//!
//! let config = DnsConfig::default();
//! let mut filter = DnsFilter::new(config);
//!
//! // Check if a UDP packet is a DNS query that should be intercepted
//! let raw = vec![0u8; 12]; // minimal DNS header
//! if DnsFilter::is_dns_packet(&raw) {
//!     // route through tunnel instead of OS resolver
//! }
//!
//! println!("Upstream DNS: {:?}", filter.config().upstream_servers);
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Well-known privacy-respecting DNS servers.
pub const CLOUDFLARE_DNS:  &str = "1.1.1.1:53";
pub const CLOUDFLARE_DNS2: &str = "1.0.0.1:53";
pub const GOOGLE_DNS:      &str = "8.8.8.8:53";
pub const GOOGLE_DNS2:     &str = "8.8.4.4:53";
pub const QUAD9_DNS:       &str = "9.9.9.9:53";

/// DNS query type.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsQueryType {
    A,       // IPv4 address
    AAAA,    // IPv6 address
    CNAME,   // Canonical name
    MX,      // Mail exchange
    TXT,     // Text record
    PTR,     // Reverse lookup
    NS,      // Name server
    Other(u16),
}

impl DnsQueryType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1  => DnsQueryType::A,
            28 => DnsQueryType::AAAA,
            5  => DnsQueryType::CNAME,
            15 => DnsQueryType::MX,
            16 => DnsQueryType::TXT,
            12 => DnsQueryType::PTR,
            2  => DnsQueryType::NS,
            o  => DnsQueryType::Other(o),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            DnsQueryType::A        => 1,
            DnsQueryType::AAAA     => 28,
            DnsQueryType::CNAME    => 5,
            DnsQueryType::MX       => 15,
            DnsQueryType::TXT      => 16,
            DnsQueryType::PTR      => 12,
            DnsQueryType::NS       => 2,
            DnsQueryType::Other(o) => *o,
        }
    }
}

/// A parsed DNS packet (header + first question only).
#[derive(Debug, Clone)]
pub struct DnsPacket {
    /// Transaction ID.
    pub id: u16,
    /// True if this is a query (QR bit = 0), false if response.
    pub is_query: bool,
    /// Query domain name (e.g. "example.com").
    pub domain: String,
    /// Query type.
    pub query_type: DnsQueryType,
    /// Raw packet bytes.
    pub raw: Vec<u8>,
}

impl DnsPacket {
    /// Parse a raw DNS packet.
    ///
    /// Returns `None` if the packet is too short or malformed.
    pub fn parse(raw: Vec<u8>) -> Option<Self> {
        if raw.len() < 12 {
            return None;
        }

        let id = u16::from_be_bytes([raw[0], raw[1]]);
        let flags = u16::from_be_bytes([raw[2], raw[3]]);
        let is_query = (flags >> 15) == 0;
        let qdcount = u16::from_be_bytes([raw[4], raw[5]]);

        if qdcount == 0 {
            return Some(DnsPacket {
                id,
                is_query,
                domain: String::new(),
                query_type: DnsQueryType::A,
                raw,
            });
        }

        // Parse first question
        let (domain, offset) = parse_dns_name(&raw, 12)?;
        if offset + 4 > raw.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([raw[offset], raw[offset + 1]]);

        debug!(id, domain = %domain, is_query, "DNS packet parsed");

        Some(DnsPacket {
            id,
            is_query,
            domain,
            query_type: DnsQueryType::from_u16(qtype),
            raw,
        })
    }

    /// Returns `true` if this is a query (not a response).
    pub fn is_query(&self) -> bool {
        self.is_query
    }
}

/// Parse a DNS name from a packet at the given offset.
/// Returns (name, offset_after_name).
fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut iterations = 0;

    loop {
        if offset >= data.len() || iterations > 128 {
            return None;
        }
        iterations += 1;

        let len = data[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        // Compression pointer
        if len & 0xC0 == 0xC0 {
            offset += 2;
            break;
        }
        offset += 1;
        if offset + len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[offset..offset + len]).ok()?;
        labels.push(label.to_string());
        offset += len;
    }

    Some((labels.join("."), offset))
}

/// Action to take for a DNS query.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsAction {
    /// Forward through the VCL tunnel to upstream DNS.
    ForwardThroughTunnel,
    /// Block this query (return NXDOMAIN).
    Block,
    /// Return a cached response.
    ReturnCached(IpAddr),
    /// Allow this query to go directly (split DNS for local domains).
    AllowDirect,
}

/// A cached DNS entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    addr: IpAddr,
    expires_at: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Configuration for DNS leak protection.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Upstream DNS servers to use (inside the tunnel).
    pub upstream_servers: Vec<String>,
    /// Local/split DNS domains that bypass the tunnel (e.g. "corp.internal").
    pub split_dns_domains: Vec<String>,
    /// Domains to block completely (ad/tracking blocklist).
    pub blocked_domains: Vec<String>,
    /// Whether to cache DNS responses.
    pub enable_cache: bool,
    /// TTL for cached entries.
    pub cache_ttl: Duration,
    /// Maximum cache size.
    pub max_cache_size: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            upstream_servers: vec![
                CLOUDFLARE_DNS.to_string(),
                CLOUDFLARE_DNS2.to_string(),
            ],
            split_dns_domains: Vec::new(),
            blocked_domains: Vec::new(),
            enable_cache: true,
            cache_ttl: Duration::from_secs(300),
            max_cache_size: 1024,
        }
    }
}

impl DnsConfig {
    /// Config using Cloudflare DNS (1.1.1.1).
    pub fn cloudflare() -> Self {
        DnsConfig::default()
    }

    /// Config using Google DNS (8.8.8.8).
    pub fn google() -> Self {
        DnsConfig {
            upstream_servers: vec![
                GOOGLE_DNS.to_string(),
                GOOGLE_DNS2.to_string(),
            ],
            ..Default::default()
        }
    }

    /// Config using Quad9 DNS (9.9.9.9) — blocks malware domains.
    pub fn quad9() -> Self {
        DnsConfig {
            upstream_servers: vec![QUAD9_DNS.to_string()],
            ..Default::default()
        }
    }

    /// Add a split DNS domain (goes directly, not through tunnel).
    pub fn with_split_domain(mut self, domain: &str) -> Self {
        self.split_dns_domains.push(domain.to_string());
        self
    }

    /// Add a blocked domain.
    pub fn with_blocked_domain(mut self, domain: &str) -> Self {
        self.blocked_domains.push(domain.to_string());
        self
    }
}

/// DNS leak protection filter.
///
/// Intercepts DNS queries, checks the blocklist and cache,
/// and decides whether to forward through the tunnel or block.
pub struct DnsFilter {
    config: DnsConfig,
    cache: HashMap<String, CacheEntry>,
    /// Total queries intercepted.
    total_intercepted: u64,
    /// Total queries blocked.
    total_blocked: u64,
    /// Total cache hits.
    total_cache_hits: u64,
    /// Total queries forwarded through tunnel.
    total_forwarded: u64,
}

impl DnsFilter {
    /// Create a new DNS filter with the given config.
    pub fn new(config: DnsConfig) -> Self {
        info!(
            upstream = ?config.upstream_servers,
            blocked_count = config.blocked_domains.len(),
            "DnsFilter created"
        );
        DnsFilter {
            config,
            cache: HashMap::new(),
            total_intercepted: 0,
            total_blocked: 0,
            total_cache_hits: 0,
            total_forwarded: 0,
        }
    }

    /// Returns `true` if a raw UDP payload looks like a DNS packet.
    ///
    /// Checks minimum length and QR/opcode field sanity.
    pub fn is_dns_packet(data: &[u8]) -> bool {
        if data.len() < 12 {
            return false;
        }
        // Opcode should be 0 (standard query) or 1 (inverse)
        let opcode = (data[2] >> 3) & 0x0F;
        opcode <= 2
    }

    /// Decide what to do with a DNS query for the given domain.
    ///
    /// Checks in order: cache → blocklist → split DNS → forward.
    pub fn decide(&mut self, domain: &str, query_type: &DnsQueryType) -> DnsAction {
        self.total_intercepted += 1;

        // Clean expired cache entries periodically
        if self.total_intercepted % 100 == 0 {
            self.evict_expired();
        }

        // Check cache first
        if self.config.enable_cache {
            if let Some(entry) = self.cache.get(domain) {
                if !entry.is_expired() {
                    self.total_cache_hits += 1;
                    debug!(domain, "DNS cache hit");
                    return DnsAction::ReturnCached(entry.addr);
                }
            }
        }

        // Check blocklist
        if self.is_blocked(domain) {
            self.total_blocked += 1;
            warn!(domain, "DNS query blocked");
            return DnsAction::Block;
        }

        // Check split DNS
        if self.is_split_dns(domain) {
            debug!(domain, "DNS split — allowing direct");
            return DnsAction::AllowDirect;
        }

        // Forward through tunnel
        self.total_forwarded += 1;
        debug!(domain, query_type = ?query_type, "DNS forwarding through tunnel");
        DnsAction::ForwardThroughTunnel
    }

    /// Cache a DNS response for a domain.
    pub fn cache_response(&mut self, domain: &str, addr: IpAddr) {
        if !self.config.enable_cache {
            return;
        }
        if self.cache.len() >= self.config.max_cache_size {
            self.evict_expired();
            // If still full, remove oldest entry
            if self.cache.len() >= self.config.max_cache_size {
                if let Some(key) = self.cache.keys().next().cloned() {
                    self.cache.remove(&key);
                }
            }
        }
        self.cache.insert(domain.to_string(), CacheEntry {
            addr,
            expires_at: Instant::now() + self.config.cache_ttl,
        });
        debug!(domain, addr = %addr, "DNS response cached");
    }

    /// Returns `true` if the domain is in the blocklist.
    ///
    /// Supports wildcard suffix matching: blocking "ads.com" also blocks "sub.ads.com".
    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.config.blocked_domains.iter().any(|blocked| {
            let b = blocked.to_lowercase();
            domain_lower == b || domain_lower.ends_with(&format!(".{}", b))
        })
    }

    /// Returns `true` if the domain should use split DNS (bypass tunnel).
    pub fn is_split_dns(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.config.split_dns_domains.iter().any(|split| {
            let s = split.to_lowercase();
            domain_lower == s || domain_lower.ends_with(&format!(".{}", s))
        })
    }

    /// Add a domain to the blocklist at runtime.
    pub fn block_domain(&mut self, domain: &str) {
        info!(domain, "DNS domain blocked");
        self.config.blocked_domains.push(domain.to_string());
    }

    /// Add a split DNS domain at runtime.
    pub fn add_split_domain(&mut self, domain: &str) {
        info!(domain, "DNS split domain added");
        self.config.split_dns_domains.push(domain.to_string());
    }

    /// Get the first upstream DNS server address.
    pub fn primary_upstream(&self) -> Option<&str> {
        self.config.upstream_servers.first().map(|s| s.as_str())
    }

    /// Remove expired entries from the cache.
    pub fn evict_expired(&mut self) {
        let before = self.cache.len();
        self.cache.retain(|_, v| !v.is_expired());
        let removed = before - self.cache.len();
        if removed > 0 {
            debug!(removed, "DNS cache eviction");
        }
    }

    /// Clear the entire DNS cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        debug!("DNS cache cleared");
    }

    /// Returns the number of entries currently in the cache.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Returns total queries intercepted.
    pub fn total_intercepted(&self) -> u64 {
        self.total_intercepted
    }

    /// Returns total queries blocked.
    pub fn total_blocked(&self) -> u64 {
        self.total_blocked
    }

    /// Returns total cache hits.
    pub fn total_cache_hits(&self) -> u64 {
        self.total_cache_hits
    }

    /// Returns total queries forwarded through tunnel.
    pub fn total_forwarded(&self) -> u64 {
        self.total_forwarded
    }

    /// Returns a reference to the config.
    pub fn config(&self) -> &DnsConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_dns_query(domain: &str) -> Vec<u8> {
        // Build a minimal DNS query packet for domain
        let mut pkt = vec![
            0x00, 0x01, // ID = 1
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        // Encode domain name
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00); // end of name
        pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        pkt
    }

    #[test]
    fn test_is_dns_packet_valid() {
        let pkt = minimal_dns_query("example.com");
        assert!(DnsFilter::is_dns_packet(&pkt));
    }

    #[test]
    fn test_is_dns_packet_too_short() {
        assert!(!DnsFilter::is_dns_packet(&[0u8; 5]));
        assert!(!DnsFilter::is_dns_packet(&[]));
    }

    #[test]
    fn test_dns_packet_parse() {
        let raw = minimal_dns_query("example.com");
        let pkt = DnsPacket::parse(raw).unwrap();
        assert_eq!(pkt.id, 1);
        assert!(pkt.is_query());
        assert_eq!(pkt.domain, "example.com");
        assert_eq!(pkt.query_type, DnsQueryType::A);
    }

    #[test]
    fn test_dns_packet_parse_too_short() {
        assert!(DnsPacket::parse(vec![0u8; 5]).is_none());
    }

    #[test]
    fn test_dns_config_default() {
        let c = DnsConfig::default();
        assert!(c.upstream_servers.contains(&CLOUDFLARE_DNS.to_string()));
        assert!(c.enable_cache);
    }

    #[test]
    fn test_dns_config_google() {
        let c = DnsConfig::google();
        assert!(c.upstream_servers.contains(&GOOGLE_DNS.to_string()));
    }

    #[test]
    fn test_dns_config_quad9() {
        let c = DnsConfig::quad9();
        assert!(c.upstream_servers.contains(&QUAD9_DNS.to_string()));
    }

    #[test]
    fn test_dns_config_with_blocked() {
        let c = DnsConfig::default().with_blocked_domain("ads.com");
        assert!(c.blocked_domains.contains(&"ads.com".to_string()));
    }

    #[test]
    fn test_dns_config_with_split() {
        let c = DnsConfig::default().with_split_domain("corp.internal");
        assert!(c.split_dns_domains.contains(&"corp.internal".to_string()));
    }

    #[test]
    fn test_filter_forward() {
        let mut f = DnsFilter::new(DnsConfig::default());
        let action = f.decide("example.com", &DnsQueryType::A);
        assert_eq!(action, DnsAction::ForwardThroughTunnel);
        assert_eq!(f.total_forwarded(), 1);
    }

    #[test]
    fn test_filter_block() {
        let config = DnsConfig::default().with_blocked_domain("ads.com");
        let mut f = DnsFilter::new(config);
        let action = f.decide("ads.com", &DnsQueryType::A);
        assert_eq!(action, DnsAction::Block);
        assert_eq!(f.total_blocked(), 1);
    }

    #[test]
    fn test_filter_block_subdomain() {
        let config = DnsConfig::default().with_blocked_domain("ads.com");
        let mut f = DnsFilter::new(config);
        let action = f.decide("tracker.ads.com", &DnsQueryType::A);
        assert_eq!(action, DnsAction::Block);
    }

    #[test]
    fn test_filter_split_dns() {
        let config = DnsConfig::default().with_split_domain("corp.internal");
        let mut f = DnsFilter::new(config);
        let action = f.decide("server.corp.internal", &DnsQueryType::A);
        assert_eq!(action, DnsAction::AllowDirect);
    }

    #[test]
    fn test_filter_cache_hit() {
        let mut f = DnsFilter::new(DnsConfig::default());
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        f.cache_response("example.com", addr);
        let action = f.decide("example.com", &DnsQueryType::A);
        assert_eq!(action, DnsAction::ReturnCached(addr));
        assert_eq!(f.total_cache_hits(), 1);
    }

    #[test]
    fn test_filter_cache_size() {
        let mut f = DnsFilter::new(DnsConfig::default());
        f.cache_response("a.com", "1.1.1.1".parse().unwrap());
        f.cache_response("b.com", "2.2.2.2".parse().unwrap());
        assert_eq!(f.cache_size(), 2);
    }

    #[test]
    fn test_filter_clear_cache() {
        let mut f = DnsFilter::new(DnsConfig::default());
        f.cache_response("a.com", "1.1.1.1".parse().unwrap());
        f.clear_cache();
        assert_eq!(f.cache_size(), 0);
    }

    #[test]
    fn test_filter_block_runtime() {
        let mut f = DnsFilter::new(DnsConfig::default());
        f.block_domain("evil.com");
        assert_eq!(f.decide("evil.com", &DnsQueryType::A), DnsAction::Block);
    }

    #[test]
    fn test_filter_split_runtime() {
        let mut f = DnsFilter::new(DnsConfig::default());
        f.add_split_domain("local.net");
        assert_eq!(f.decide("host.local.net", &DnsQueryType::A), DnsAction::AllowDirect);
    }

    #[test]
    fn test_is_blocked_exact() {
        let config = DnsConfig::default().with_blocked_domain("bad.com");
        let f = DnsFilter::new(config);
        assert!(f.is_blocked("bad.com"));
        assert!(!f.is_blocked("good.com"));
    }

    #[test]
    fn test_is_blocked_subdomain() {
        let config = DnsConfig::default().with_blocked_domain("bad.com");
        let f = DnsFilter::new(config);
        assert!(f.is_blocked("sub.bad.com"));
        assert!(f.is_blocked("deep.sub.bad.com"));
    }

    #[test]
    fn test_is_split_dns() {
        let config = DnsConfig::default().with_split_domain("internal");
        let f = DnsFilter::new(config);
        assert!(f.is_split_dns("host.internal"));
        assert!(!f.is_split_dns("external.com"));
    }

    #[test]
    fn test_primary_upstream() {
        let f = DnsFilter::new(DnsConfig::cloudflare());
        assert_eq!(f.primary_upstream(), Some(CLOUDFLARE_DNS));
    }

    #[test]
    fn test_stats() {
        let mut f = DnsFilter::new(
            DnsConfig::default().with_blocked_domain("bad.com")
        );
        f.decide("example.com", &DnsQueryType::A);
        f.decide("bad.com", &DnsQueryType::A);
        assert_eq!(f.total_intercepted(), 2);
        assert_eq!(f.total_blocked(), 1);
        assert_eq!(f.total_forwarded(), 1);
    }

    #[test]
    fn test_query_type_from_u16() {
        assert_eq!(DnsQueryType::from_u16(1),  DnsQueryType::A);
        assert_eq!(DnsQueryType::from_u16(28), DnsQueryType::AAAA);
        assert_eq!(DnsQueryType::from_u16(99), DnsQueryType::Other(99));
    }

    #[test]
    fn test_query_type_to_u16() {
        assert_eq!(DnsQueryType::A.to_u16(), 1);
        assert_eq!(DnsQueryType::AAAA.to_u16(), 28);
        assert_eq!(DnsQueryType::Other(99).to_u16(), 99);
    }

    #[test]
    fn test_evict_expired() {
        let config = DnsConfig {
            cache_ttl: Duration::from_millis(1),
            ..DnsConfig::default()
        };
        let mut f = DnsFilter::new(config);
        f.cache_response("a.com", "1.1.1.1".parse().unwrap());
        std::thread::sleep(Duration::from_millis(5));
        f.evict_expired();
        assert_eq!(f.cache_size(), 0);
    }
}
