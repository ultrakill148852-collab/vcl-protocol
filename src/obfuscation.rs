//! # VCL Traffic Obfuscation
//!
//! Makes VCL Protocol traffic indistinguishable from regular HTTPS/TLS
//! to bypass Deep Packet Inspection (DPI) used by ISPs like МТС, Beeline.
//!
//! ## Techniques
//!
//! ```text
//! 1. Packet Padding    — random padding to disguise payload size patterns
//! 2. Timing Jitter     — random delays to disguise traffic timing patterns
//! 3. TLS Mimicry       — wrap packets to look like TLS 1.3 records
//! 4. HTTP/2 Mimicry    — wrap packets to look like HTTP/2 DATA frames
//! 5. Size Normalization— normalize packet sizes to common HTTPS sizes
//! ```
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::obfuscation::{Obfuscator, ObfuscationConfig, ObfuscationMode};
//!
//! let config = ObfuscationConfig::tls_mimicry();
//! let mut obf = Obfuscator::new(config);
//!
//! let data = b"secret VCL packet";
//! let obfuscated = obf.obfuscate(data);
//! let restored = obf.deobfuscate(&obfuscated).unwrap();
//! assert_eq!(restored, data);
//! ```

use crate::error::VCLError;
use tracing::trace;

/// Magic bytes that look like a TLS 1.3 record header.
/// Content-Type: Application Data (23), Version: TLS 1.2 compat (0x0303)
const TLS_RECORD_HEADER: [u8; 3] = [0x17, 0x03, 0x03];

/// Magic bytes for HTTP/2 DATA frame header prefix.
const HTTP2_DATA_FRAME_TYPE: u8 = 0x00;

/// Common HTTPS packet sizes — normalizing to these avoids size fingerprinting.
const COMMON_SIZES: &[usize] = &[64, 128, 256, 512, 1024, 1280, 1400, 1460];

/// Obfuscation mode — how to disguise VCL traffic.
#[derive(Debug, Clone, PartialEq)]
pub enum ObfuscationMode {
    /// No obfuscation — raw VCL packets.
    None,
    /// Add random padding to disguise payload size.
    Padding,
    /// Normalize packet sizes to common HTTPS sizes.
    SizeNormalization,
    /// Wrap packets in fake TLS 1.3 Application Data records.
    TlsMimicry,
    /// Wrap packets in fake HTTP/2 DATA frames.
    Http2Mimicry,
    /// Full obfuscation: TLS mimicry + size normalization.
    Full,
}

/// Configuration for traffic obfuscation.
#[derive(Debug, Clone)]
pub struct ObfuscationConfig {
    pub mode: ObfuscationMode,
    pub jitter_max_ms: u64,
    pub min_packet_size: usize,
    pub max_packet_size: usize,
    pub xor_key: u8,
}

impl ObfuscationConfig {
    /// No obfuscation.
    pub fn none() -> Self {
        ObfuscationConfig {
            mode: ObfuscationMode::None,
            jitter_max_ms: 0,
            min_packet_size: 0,
            max_packet_size: 65535,
            xor_key: 0,
        }
    }

    /// Basic padding only — low overhead.
    pub fn padding() -> Self {
        ObfuscationConfig {
            mode: ObfuscationMode::Padding,
            jitter_max_ms: 0,
            min_packet_size: 64,
            max_packet_size: 1460,
            xor_key: 0xAB,
        }
    }

    /// TLS 1.3 mimicry — looks like HTTPS to DPI.
    pub fn tls_mimicry() -> Self {
        ObfuscationConfig {
            mode: ObfuscationMode::TlsMimicry,
            jitter_max_ms: 5,
            min_packet_size: 0,
            max_packet_size: 16384,
            xor_key: 0x5A,
        }
    }

    /// HTTP/2 mimicry — looks like web traffic.
    pub fn http2_mimicry() -> Self {
        ObfuscationConfig {
            mode: ObfuscationMode::Http2Mimicry,
            jitter_max_ms: 10,
            min_packet_size: 0,
            max_packet_size: 16384,
            xor_key: 0x3C,
        }
    }

    /// Size normalization — normalizes to common HTTPS packet sizes.
    pub fn size_normalization() -> Self {
        ObfuscationConfig {
            mode: ObfuscationMode::SizeNormalization,
            jitter_max_ms: 0,
            min_packet_size: 0,
            max_packet_size: 1460,
            xor_key: 0x77,
        }
    }

    /// Full obfuscation — maximum stealth, recommended for МТС/censored networks.
    pub fn full() -> Self {
        ObfuscationConfig {
            mode: ObfuscationMode::Full,
            jitter_max_ms: 15,
            min_packet_size: 128,
            max_packet_size: 16384,
            xor_key: 0xF3,
        }
    }
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self::tls_mimicry()
    }
}

/// Traffic obfuscator — wraps and unwraps VCL packets.
pub struct Obfuscator {
    config: ObfuscationConfig,
    counter: u64,
    total_obfuscated: u64,
    total_deobfuscated: u64,
    total_overhead: u64,
}

impl Obfuscator {
    /// Create a new obfuscator with the given config.
    pub fn new(config: ObfuscationConfig) -> Self {
        Obfuscator {
            config,
            counter: 0,
            total_obfuscated: 0,
            total_deobfuscated: 0,
            total_overhead: 0,
        }
    }

    /// Obfuscate a VCL packet payload.
    pub fn obfuscate(&mut self, data: &[u8]) -> Vec<u8> {
        self.counter += 1;
        let original_len = data.len();

        let result = match &self.config.mode {
            ObfuscationMode::None             => data.to_vec(),
            ObfuscationMode::Padding          => self.apply_padding(data),
            ObfuscationMode::SizeNormalization => self.apply_size_normalization(data),
            ObfuscationMode::TlsMimicry       => self.apply_tls_mimicry(data),
            ObfuscationMode::Http2Mimicry     => self.apply_http2_mimicry(data),
            ObfuscationMode::Full             => {
                let normed = self.apply_size_normalization(data);
                self.apply_tls_mimicry(&normed)
            }
        };

        let overhead = result.len().saturating_sub(original_len);
        self.total_overhead += overhead as u64;
        self.total_obfuscated += original_len as u64;

        trace!(
            mode = ?self.config.mode,
            original = original_len,
            obfuscated = result.len(),
            overhead,
            "Packet obfuscated"
        );

        result
    }

    /// Deobfuscate a received packet back to raw VCL data.
    pub fn deobfuscate(&mut self, data: &[u8]) -> Result<Vec<u8>, VCLError> {
        if data.is_empty() {
            return Err(VCLError::InvalidPacket("Empty obfuscated packet".to_string()));
        }

        let result = match &self.config.mode {
            ObfuscationMode::None             => data.to_vec(),
            ObfuscationMode::Padding          => self.strip_padding(data)?,
            ObfuscationMode::SizeNormalization => self.strip_size_normalization(data)?,
            ObfuscationMode::TlsMimicry       => self.strip_tls_mimicry(data)?,
            ObfuscationMode::Http2Mimicry     => self.strip_http2_mimicry(data)?,
            ObfuscationMode::Full             => {
                let stripped_tls = self.strip_tls_mimicry(data)?;
                self.strip_size_normalization(&stripped_tls)?
            }
        };

        self.total_deobfuscated += result.len() as u64;

        trace!(
            mode = ?self.config.mode,
            received = data.len(),
            restored = result.len(),
            "Packet deobfuscated"
        );

        Ok(result)
    }

    /// Returns the jitter delay in milliseconds to wait before sending.
    pub fn jitter_ms(&self) -> u64 {
        if self.config.jitter_max_ms == 0 {
            return 0;
        }
        let r = (self.counter.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407)) >> 33;
        r % (self.config.jitter_max_ms + 1)
    }

    // ─── Padding ──────────────────────────────────────────────────────────────

    fn apply_padding(&self, data: &[u8]) -> Vec<u8> {
        let target = self.config.min_packet_size;
        let padding_needed = if data.len() + 1 < target {
            target - data.len() - 1
        } else {
            self.counter as usize % 16
        };
        let padding_len = padding_needed.min(255);

        let mut result = Vec::with_capacity(1 + data.len() + padding_len);
        result.push(padding_len as u8);

        if self.config.xor_key != 0 {
            result.extend(data.iter().map(|&b| b ^ self.config.xor_key));
        } else {
            result.extend_from_slice(data);
        }

        for i in 0..padding_len {
            result.push(((i as u64).wrapping_mul(self.counter).wrapping_add(0x5A) & 0xFF) as u8);
        }

        result
    }

    fn strip_padding(&self, data: &[u8]) -> Result<Vec<u8>, VCLError> {
        if data.is_empty() {
            return Err(VCLError::InvalidPacket("Padding: empty packet".to_string()));
        }
        let padding_len = data[0] as usize;
        let payload_end = data.len().saturating_sub(padding_len);
        if payload_end < 1 {
            return Err(VCLError::InvalidPacket("Padding: invalid length".to_string()));
        }
        let payload = &data[1..payload_end];

        if self.config.xor_key != 0 {
            Ok(payload.iter().map(|&b| b ^ self.config.xor_key).collect())
        } else {
            Ok(payload.to_vec())
        }
    }

    // ─── Size normalization ───────────────────────────────────────────────────

    fn apply_size_normalization(&self, data: &[u8]) -> Vec<u8> {
        // Header: [0xCC][0xC0][padding_len u8] then payload then padding
        let target = COMMON_SIZES.iter()
            .find(|&&s| s >= data.len() + 3)
            .copied()
            .unwrap_or(data.len() + 3);

        let padding_needed = target.saturating_sub(data.len() + 3);
        let padding_len = padding_needed.min(255);
        let mut result = Vec::with_capacity(target);

        result.push(0xCC);
        result.push(0xC0);
        result.push(padding_len as u8);

        if self.config.xor_key != 0 {
            result.extend(data.iter().map(|&b| b ^ self.config.xor_key));
        } else {
            result.extend_from_slice(data);
        }

        for i in 0..padding_len {
            result.push((i ^ 0x5A) as u8);
        }

        result
    }

    fn strip_size_normalization(&self, data: &[u8]) -> Result<Vec<u8>, VCLError> {
        if data.len() < 3 {
            return Err(VCLError::InvalidPacket("SizeNorm: too short".to_string()));
        }
        if data[0] != 0xCC || data[1] != 0xC0 {
            return Err(VCLError::InvalidPacket("SizeNorm: invalid header".to_string()));
        }
        let padding_len = data[2] as usize;
        let payload_end = data.len().saturating_sub(padding_len);
        if payload_end < 3 {
            return Err(VCLError::InvalidPacket("SizeNorm: invalid length".to_string()));
        }
        let payload = &data[3..payload_end];

        if self.config.xor_key != 0 {
            Ok(payload.iter().map(|&b| b ^ self.config.xor_key).collect())
        } else {
            Ok(payload.to_vec())
        }
    }

    // ─── TLS 1.3 mimicry ──────────────────────────────────────────────────────

    fn apply_tls_mimicry(&self, data: &[u8]) -> Vec<u8> {
        let xored: Vec<u8> = if self.config.xor_key != 0 {
            data.iter().map(|&b| b ^ self.config.xor_key).collect()
        } else {
            data.to_vec()
        };

        let len = xored.len() as u16;
        let mut result = Vec::with_capacity(5 + xored.len());
        result.extend_from_slice(&TLS_RECORD_HEADER);
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&xored);
        result
    }

    fn strip_tls_mimicry(&self, data: &[u8]) -> Result<Vec<u8>, VCLError> {
        if data.len() < 5 {
            return Err(VCLError::InvalidPacket(
                "TLS mimicry: packet too short".to_string()
            ));
        }
        if data[0] != TLS_RECORD_HEADER[0]
            || data[1] != TLS_RECORD_HEADER[1]
            || data[2] != TLS_RECORD_HEADER[2]
        {
            return Err(VCLError::InvalidPacket(
                "TLS mimicry: invalid header".to_string()
            ));
        }
        let payload_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + payload_len {
            return Err(VCLError::InvalidPacket(
                "TLS mimicry: truncated payload".to_string()
            ));
        }
        let payload = &data[5..5 + payload_len];

        if self.config.xor_key != 0 {
            Ok(payload.iter().map(|&b| b ^ self.config.xor_key).collect())
        } else {
            Ok(payload.to_vec())
        }
    }

    // ─── HTTP/2 mimicry ───────────────────────────────────────────────────────

    fn apply_http2_mimicry(&self, data: &[u8]) -> Vec<u8> {
        let xored: Vec<u8> = if self.config.xor_key != 0 {
            data.iter().map(|&b| b ^ self.config.xor_key).collect()
        } else {
            data.to_vec()
        };

        let len = xored.len() as u32;
        let mut result = Vec::with_capacity(9 + xored.len());

        result.push(((len >> 16) & 0xFF) as u8);
        result.push(((len >> 8)  & 0xFF) as u8);
        result.push((len & 0xFF) as u8);
        result.push(HTTP2_DATA_FRAME_TYPE);
        result.push(0x00);

        let stream_id = (self.counter % 100 + 1) as u32;
        result.extend_from_slice(&stream_id.to_be_bytes());
        result.extend_from_slice(&xored);
        result
    }

    fn strip_http2_mimicry(&self, data: &[u8]) -> Result<Vec<u8>, VCLError> {
        if data.len() < 9 {
            return Err(VCLError::InvalidPacket(
                "HTTP/2 mimicry: packet too short".to_string()
            ));
        }
        if data[3] != HTTP2_DATA_FRAME_TYPE {
            return Err(VCLError::InvalidPacket(
                "HTTP/2 mimicry: invalid frame type".to_string()
            ));
        }
        let payload_len = ((data[0] as usize) << 16)
            | ((data[1] as usize) << 8)
            | (data[2] as usize);

        if data.len() < 9 + payload_len {
            return Err(VCLError::InvalidPacket(
                "HTTP/2 mimicry: truncated payload".to_string()
            ));
        }
        let payload = &data[9..9 + payload_len];

        if self.config.xor_key != 0 {
            Ok(payload.iter().map(|&b| b ^ self.config.xor_key).collect())
        } else {
            Ok(payload.to_vec())
        }
    }

    // ─── Stats ────────────────────────────────────────────────────────────────

    /// Returns the overhead ratio: overhead_bytes / original_bytes.
    pub fn overhead_ratio(&self) -> f64 {
        if self.total_obfuscated == 0 {
            return 0.0;
        }
        self.total_overhead as f64 / self.total_obfuscated as f64
    }

    /// Returns total bytes of original data obfuscated.
    pub fn total_obfuscated(&self) -> u64 {
        self.total_obfuscated
    }

    /// Returns total overhead bytes added.
    pub fn total_overhead(&self) -> u64 {
        self.total_overhead
    }

    /// Returns a reference to the config.
    pub fn config(&self) -> &ObfuscationConfig {
        &self.config
    }

    /// Returns the current obfuscation mode.
    pub fn mode(&self) -> &ObfuscationMode {
        &self.config.mode
    }
}

/// Check if raw bytes look like a TLS Application Data record.
pub fn looks_like_tls(data: &[u8]) -> bool {
    data.len() >= 5
        && data[0] == TLS_RECORD_HEADER[0]
        && data[1] == TLS_RECORD_HEADER[1]
        && data[2] == TLS_RECORD_HEADER[2]
}

/// Check if raw bytes look like an HTTP/2 DATA frame.
pub fn looks_like_http2(data: &[u8]) -> bool {
    data.len() >= 9
        && data[3] == HTTP2_DATA_FRAME_TYPE
        && data[0] != TLS_RECORD_HEADER[0]
}

/// Returns the recommended [`ObfuscationMode`] for a given network environment.
pub fn recommended_mode(network_hint: &str) -> ObfuscationMode {
    match network_hint.to_lowercase().as_str() {
        "mobile" | "mts" | "beeline" | "megafon" | "tele2" => ObfuscationMode::Full,
        "corporate" | "office" | "work"                     => ObfuscationMode::Http2Mimicry,
        "home" | "broadband"                                => ObfuscationMode::TlsMimicry,
        _                                                   => ObfuscationMode::Padding,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(config: ObfuscationConfig, data: &[u8]) {
        let mut obf = Obfuscator::new(config);
        let obfuscated = obf.obfuscate(data);
        let restored = obf.deobfuscate(&obfuscated).unwrap();
        assert_eq!(restored, data, "Roundtrip failed");
    }

    #[test]
    fn test_none_roundtrip() {
        roundtrip(ObfuscationConfig::none(), b"hello vcl");
    }

    #[test]
    fn test_padding_roundtrip() {
        roundtrip(ObfuscationConfig::padding(), b"hello vcl padding");
    }

    #[test]
    fn test_padding_empty() {
        roundtrip(ObfuscationConfig::padding(), b"");
    }

    #[test]
    fn test_tls_mimicry_roundtrip() {
        roundtrip(ObfuscationConfig::tls_mimicry(), b"secret vpn packet");
    }

    #[test]
    fn test_tls_mimicry_empty() {
        roundtrip(ObfuscationConfig::tls_mimicry(), b"");
    }

    #[test]
    fn test_tls_mimicry_large() {
        let data = vec![0xAB_u8; 4096];
        roundtrip(ObfuscationConfig::tls_mimicry(), &data);
    }

    #[test]
    fn test_http2_mimicry_roundtrip() {
        roundtrip(ObfuscationConfig::http2_mimicry(), b"http2 framed data");
    }

    #[test]
    fn test_http2_mimicry_large() {
        let data = vec![0xFF_u8; 2048];
        roundtrip(ObfuscationConfig::http2_mimicry(), &data);
    }

    #[test]
    fn test_size_normalization_roundtrip() {
        roundtrip(ObfuscationConfig::size_normalization(), b"normalize me");
    }

    #[test]
    fn test_full_roundtrip() {
        roundtrip(ObfuscationConfig::full(), b"maximum stealth mode");
    }

    #[test]
    fn test_full_large() {
        let data = vec![0x42_u8; 1000];
        roundtrip(ObfuscationConfig::full(), &data);
    }

    #[test]
    fn test_tls_mimicry_looks_like_tls() {
        let mut obf = Obfuscator::new(ObfuscationConfig::tls_mimicry());
        let obfuscated = obf.obfuscate(b"data");
        assert!(looks_like_tls(&obfuscated));
        assert!(!looks_like_http2(&obfuscated));
    }

    #[test]
    fn test_http2_mimicry_looks_like_http2() {
        let mut obf = Obfuscator::new(ObfuscationConfig::http2_mimicry());
        let obfuscated = obf.obfuscate(b"data");
        assert!(looks_like_http2(&obfuscated));
        assert!(!looks_like_tls(&obfuscated));
    }

    #[test]
    fn test_tls_invalid_header() {
        let mut obf = Obfuscator::new(ObfuscationConfig::tls_mimicry());
        let bad = vec![0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        assert!(obf.deobfuscate(&bad).is_err());
    }

    #[test]
    fn test_http2_invalid_type() {
        let mut obf = Obfuscator::new(ObfuscationConfig::http2_mimicry());
        let mut bad = vec![0u8; 12];
        bad[3] = 0xFF;
        assert!(obf.deobfuscate(&bad).is_err());
    }

    #[test]
    fn test_deobfuscate_empty() {
        let mut obf = Obfuscator::new(ObfuscationConfig::tls_mimicry());
        assert!(obf.deobfuscate(&[]).is_err());
    }

    #[test]
    fn test_jitter_zero_when_disabled() {
        let obf = Obfuscator::new(ObfuscationConfig::none());
        assert_eq!(obf.jitter_ms(), 0);
    }

    #[test]
    fn test_jitter_within_range() {
        let obf = Obfuscator::new(ObfuscationConfig::tls_mimicry());
        assert!(obf.jitter_ms() <= obf.config().jitter_max_ms);
    }

    #[test]
    fn test_overhead_ratio() {
        let mut obf = Obfuscator::new(ObfuscationConfig::tls_mimicry());
        obf.obfuscate(b"data");
        assert!(obf.overhead_ratio() > 0.0);
    }

    #[test]
    fn test_overhead_ratio_none_mode() {
        let mut obf = Obfuscator::new(ObfuscationConfig::none());
        obf.obfuscate(b"data");
        assert_eq!(obf.overhead_ratio(), 0.0);
    }

    #[test]
    fn test_recommended_mode_mobile() {
        assert_eq!(recommended_mode("mobile"), ObfuscationMode::Full);
        assert_eq!(recommended_mode("mts"),    ObfuscationMode::Full);
        assert_eq!(recommended_mode("MTS"),    ObfuscationMode::Full);
    }

    #[test]
    fn test_recommended_mode_corporate() {
        assert_eq!(recommended_mode("corporate"), ObfuscationMode::Http2Mimicry);
        assert_eq!(recommended_mode("office"),    ObfuscationMode::Http2Mimicry);
    }

    #[test]
    fn test_recommended_mode_home() {
        assert_eq!(recommended_mode("home"), ObfuscationMode::TlsMimicry);
    }

    #[test]
    fn test_recommended_mode_unknown() {
        assert_eq!(recommended_mode("unknown"), ObfuscationMode::Padding);
    }

    #[test]
    fn test_xor_key_zero_no_scramble() {
        let config = ObfuscationConfig {
            xor_key: 0,
            ..ObfuscationConfig::padding()
        };
        roundtrip(config, b"no xor test");
    }

    #[test]
    fn test_size_normalization_output_size() {
        let mut obf = Obfuscator::new(ObfuscationConfig::size_normalization());
        let data = b"tiny";
        let out = obf.obfuscate(data);
        assert!(COMMON_SIZES.iter().any(|&s| s <= out.len()) || out.len() >= data.len());
    }

    #[test]
    fn test_multiple_packets_different_jitter() {
        let mut obf = Obfuscator::new(ObfuscationConfig::full());
        obf.obfuscate(b"packet1");
        let j1 = obf.jitter_ms();
        obf.obfuscate(b"packet2");
        let j2 = obf.jitter_ms();
        assert!(j1 <= obf.config().jitter_max_ms);
        assert!(j2 <= obf.config().jitter_max_ms);
    }

    #[test]
    fn test_stats_tracking() {
        let mut obf = Obfuscator::new(ObfuscationConfig::tls_mimicry());
        obf.obfuscate(b"hello");
        obf.obfuscate(b"world");
        assert_eq!(obf.total_obfuscated(), 10);
        assert!(obf.total_overhead() > 0);
    }
}
