//! # VCL TUN Interface
//!
//! Provides [`VCLTun`] — a TUN virtual network interface that captures
//! IP packets from the OS network stack and injects them back after
//! decryption/routing through a VCL tunnel.
//!
//! ## How it works
//!
//! ```text
//! Application
//!     ↓ (writes to TCP/UDP socket)
//! OS Network Stack
//!     ↓ (routes via routing table)
//! TUN interface (vcl0)
//!     ↓ (VCLTun::read_packet)
//! VCL Protocol (encrypt + send)
//!     ↓ (network)
//! Remote VCL (recv + decrypt)
//!     ↓ (VCLTun::write_packet)
//! TUN interface (remote vcl0)
//!     ↓ (inject into OS network stack)
//! Remote application
//! ```
//!
//! ## Requirements
//!
//! - Linux only (TUN/TAP is a Linux kernel feature)
//! - Requires root or `CAP_NET_ADMIN` capability
//! - Does NOT work in WSL2 without custom kernel
//!
//! ## Example
//!
//! ```no_run
//! use vcl_protocol::tun_device::{VCLTun, TunConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = TunConfig {
//!         name: "vcl0".to_string(),
//!         address: "10.0.0.1".parse().unwrap(),
//!         destination: "10.0.0.2".parse().unwrap(),
//!         netmask: "255.255.255.0".parse().unwrap(),
//!         mtu: 1420,
//!     };
//!
//!     let mut tun = VCLTun::create(config).unwrap();
//!
//!     loop {
//!         let packet = tun.read_packet().await.unwrap();
//!         println!("Captured {} bytes", packet.len());
//!         // encrypt and send via VCL connection
//!     }
//! }
//! ```

use std::net::Ipv4Addr;
use crate::error::VCLError;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use tracing::{debug, info, warn};

/// Configuration for a TUN virtual network interface.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Interface name (e.g. "vcl0"). Max 15 chars on Linux.
    pub name: String,
    /// Local IP address assigned to the TUN interface.
    pub address: Ipv4Addr,
    /// Remote end of the point-to-point link.
    pub destination: Ipv4Addr,
    /// Netmask for the TUN interface.
    pub netmask: Ipv4Addr,
    /// MTU in bytes. Default 1420 leaves room for VCL headers over UDP.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        TunConfig {
            name: "vcl0".to_string(),
            address: "10.0.0.1".parse().unwrap(),
            destination: "10.0.0.2".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
            mtu: 1420,
        }
    }
}

/// IP protocol version detected in a packet.
#[derive(Debug, Clone, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
    Unknown(u8),
}

/// A parsed IP packet read from the TUN interface.
#[derive(Debug, Clone)]
pub struct IpPacket {
    /// Raw packet bytes (including IP header).
    pub raw: Vec<u8>,
    /// IP version.
    pub version: IpVersion,
    /// Source IP (as string for both v4 and v6).
    pub src: String,
    /// Destination IP (as string for both v4 and v6).
    pub dst: String,
    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP, etc).
    pub protocol: u8,
    /// Total packet length in bytes.
    pub len: usize,
}

/// A TUN virtual network interface for capturing and injecting IP packets.
///
/// Requires root or `CAP_NET_ADMIN`. Linux only.
pub struct VCLTun {
    #[cfg(target_os = "linux")]
    dev: tun::AsyncDevice,
    config: TunConfig,
}

impl VCLTun {
    /// Create and configure a new TUN interface.
    ///
    /// # Errors
    /// Returns [`VCLError::IoError`] if:
    /// - Not running as root / missing `CAP_NET_ADMIN`
    /// - Interface name is invalid or already in use
    /// - TUN driver not available
    #[cfg(target_os = "linux")]
    pub fn create(config: TunConfig) -> Result<Self, VCLError> {
        let mut tun_config = tun::Configuration::default();
        
        // Use tun_name instead of deprecated name
        tun_config.tun_name(&config.name);
        
        tun_config
            .address(config.address)
            .destination(config.destination)
            .netmask(config.netmask)
            // FIX: mtu() now expects u16 in tun 0.7.x
            .mtu(config.mtu)
            .up();

        let dev = tun::create_as_async(&tun_config)
            .map_err(|e| VCLError::IoError(format!("Failed to create TUN device: {}", e)))?;

        info!(
            name = %config.name,
            address = %config.address,
            destination = %config.destination,
            mtu = config.mtu,
            "TUN interface created"
        );

        Ok(VCLTun { dev, config })
    }

    /// Stub for non-Linux platforms — TUN is not supported.
    #[cfg(not(target_os = "linux"))]
    pub fn create(_config: TunConfig) -> Result<Self, VCLError> {
        Err(VCLError::IoError(
            "TUN interface is only supported on Linux".to_string(),
        ))
    }

    /// Read the next IP packet from the TUN interface.
    ///
    /// Blocks asynchronously until a packet is available.
    /// Returns raw bytes including the IP header.
    ///
    /// # Errors
    /// Returns [`VCLError::IoError`] on read failure.
    #[cfg(target_os = "linux")]
    pub async fn read_packet(&mut self) -> Result<Vec<u8>, VCLError> {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; self.config.mtu as usize + 4];
        let n = self.dev.read(&mut buf).await
            .map_err(|e| VCLError::IoError(format!("TUN read failed: {}", e)))?;
        buf.truncate(n);
        debug!(size = n, "TUN packet read");
        Ok(buf)
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn read_packet(&mut self) -> Result<Vec<u8>, VCLError> {
        Err(VCLError::IoError("TUN not supported on this platform".to_string()))
    }

    /// Write (inject) a raw IP packet into the TUN interface.
    ///
    /// The packet will appear as if it came from the network
    /// and will be delivered to the appropriate local socket.
    ///
    /// # Errors
    /// Returns [`VCLError::IoError`] on write failure.
    #[cfg(target_os = "linux")]
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<(), VCLError> {
        use tokio::io::AsyncWriteExt;
        self.dev.write_all(packet).await
            .map_err(|e| VCLError::IoError(format!("TUN write failed: {}", e)))?;
        debug!(size = packet.len(), "TUN packet injected");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn write_packet(&mut self, _packet: &[u8]) -> Result<(), VCLError> {
        Err(VCLError::IoError("TUN not supported on this platform".to_string()))
    }

    /// Returns the name of the TUN interface (e.g. "vcl0").
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Returns the MTU configured for this interface.
    pub fn mtu(&self) -> u16 {
        self.config.mtu
    }

    /// Returns the local IP address of the TUN interface.
    pub fn address(&self) -> Ipv4Addr {
        self.config.address
    }

    /// Returns the remote destination IP of the TUN interface.
    pub fn destination(&self) -> Ipv4Addr {
        self.config.destination
    }

    /// Returns a reference to the full [`TunConfig`].
    pub fn config(&self) -> &TunConfig {
        &self.config
    }
}

// ─── IP Packet Parsing ────────────────────────────────────────────────────────

/// Parse raw bytes from a TUN read into an [`IpPacket`].
///
/// Supports IPv4 and IPv6. Returns an error if the packet is too short
/// or the IP version byte is missing.
///
/// # Errors
/// Returns [`VCLError::InvalidPacket`] if the packet is malformed.
pub fn parse_ip_packet(raw: Vec<u8>) -> Result<IpPacket, VCLError> {
    if raw.is_empty() {
        return Err(VCLError::InvalidPacket("Empty IP packet".to_string()));
    }

    let version_byte = raw[0] >> 4;
    let len = raw.len();

    match version_byte {
        4 => parse_ipv4(raw, len),
        6 => parse_ipv6(raw, len),
        v => {
            warn!(version = v, "Unknown IP version in TUN packet");
            Ok(IpPacket {
                raw,
                version: IpVersion::Unknown(v),
                src: String::new(),
                dst: String::new(),
                protocol: 0,
                len,
            })
        }
    }
}

fn parse_ipv4(raw: Vec<u8>, len: usize) -> Result<IpPacket, VCLError> {
    let header = Ipv4HeaderSlice::from_slice(&raw)
        .map_err(|e| VCLError::InvalidPacket(format!("IPv4 parse error: {}", e)))?;

    let src = format!(
        "{}.{}.{}.{}",
        header.source()[0], header.source()[1],
        header.source()[2], header.source()[3]
    );
    let dst = format!(
        "{}.{}.{}.{}",
        header.destination()[0], header.destination()[1],
        header.destination()[2], header.destination()[3]
    );
    let protocol = header.protocol().0;

    debug!(src = %src, dst = %dst, protocol, size = len, "IPv4 packet parsed");

    Ok(IpPacket {
        raw,
        version: IpVersion::V4,
        src,
        dst,
        protocol,
        len,
    })
}

fn parse_ipv6(raw: Vec<u8>, len: usize) -> Result<IpPacket, VCLError> {
    let header = Ipv6HeaderSlice::from_slice(&raw)
        .map_err(|e| VCLError::InvalidPacket(format!("IPv6 parse error: {}", e)))?;

    let src = format!("{:?}", header.source_addr());
    let dst = format!("{:?}", header.destination_addr());
    let protocol = header.next_header().0;

    debug!(src = %src, dst = %dst, protocol, size = len, "IPv6 packet parsed");

    Ok(IpPacket {
        raw,
        version: IpVersion::V6,
        src,
        dst,
        protocol,
        len,
    })
}

/// Check if a raw packet is IPv4.
pub fn is_ipv4(raw: &[u8]) -> bool {
    raw.first().map(|b| b >> 4 == 4).unwrap_or(false)
}

/// Check if a raw packet is IPv6.
pub fn is_ipv6(raw: &[u8]) -> bool {
    raw.first().map(|b| b >> 4 == 6).unwrap_or(false)
}

/// Returns the IP version of a raw packet, or `None` if empty.
pub fn ip_version(raw: &[u8]) -> Option<IpVersion> {
    raw.first().map(|b| match b >> 4 {
        4 => IpVersion::V4,
        6 => IpVersion::V6,
        v => IpVersion::Unknown(v),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_packet() -> Vec<u8> {
        // Minimal valid IPv4 header (20 bytes) + 4 bytes payload
        vec![
            0x45, // version=4, IHL=5
            0x00, // DSCP/ECN
            0x00, 0x18, // total length = 24
            0x00, 0x01, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // TTL = 64
            0x06, // protocol = TCP (6)
            0x00, 0x00, // checksum (not validated here)
            192, 168, 1, 1,   // src
            10, 0, 0, 1,      // dst
            0x00, 0x00, 0x00, 0x00, // payload
        ]
    }

    fn make_ipv6_packet() -> Vec<u8> {
        // Minimal IPv6 header (40 bytes)
        let mut pkt = vec![
            0x60, 0x00, 0x00, 0x00, // version=6, TC, flow label
            0x00, 0x08,             // payload length = 8
            0x11,                   // next header = UDP (17)
            0x40,                   // hop limit = 64
        ];
        // src addr (16 bytes) = ::1
        pkt.extend_from_slice(&[0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1]);
        // dst addr (16 bytes) = ::2
        pkt.extend_from_slice(&[0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2]);
        // payload (8 bytes)
        pkt.extend_from_slice(&[0u8; 8]);
        pkt
    }

    #[test]
    fn test_tun_config_default() {
        let c = TunConfig::default();
        assert_eq!(c.name, "vcl0");
        assert_eq!(c.mtu, 1420);
        assert_eq!(c.address, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_parse_ipv4_packet() {
        let raw = make_ipv4_packet();
        let pkt = parse_ip_packet(raw).unwrap();
        assert_eq!(pkt.version, IpVersion::V4);
        assert_eq!(pkt.src, "192.168.1.1");
        assert_eq!(pkt.dst, "10.0.0.1");
        assert_eq!(pkt.protocol, 6); // TCP
    }

    #[test]
    fn test_parse_ipv6_packet() {
        let raw = make_ipv6_packet();
        let pkt = parse_ip_packet(raw).unwrap();
        assert_eq!(pkt.version, IpVersion::V6);
        assert_eq!(pkt.protocol, 17); // UDP
    }

    #[test]
    fn test_parse_empty_packet() {
        let result = parse_ip_packet(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unknown_version() {
        let raw = vec![0x30, 0x00, 0x00, 0x00]; // version = 3
        let pkt = parse_ip_packet(raw).unwrap();
        assert_eq!(pkt.version, IpVersion::Unknown(3));
    }

    #[test]
    fn test_is_ipv4() {
        assert!(is_ipv4(&make_ipv4_packet()));
        assert!(!is_ipv4(&make_ipv6_packet()));
        assert!(!is_ipv4(&[]));
    }

    #[test]
    fn test_is_ipv6() {
        assert!(is_ipv6(&make_ipv6_packet()));
        assert!(!is_ipv6(&make_ipv4_packet()));
        assert!(!is_ipv6(&[]));
    }

    #[test]
    fn test_ip_version() {
        assert_eq!(ip_version(&make_ipv4_packet()), Some(IpVersion::V4));
        assert_eq!(ip_version(&make_ipv6_packet()), Some(IpVersion::V6));
        assert_eq!(ip_version(&[0x30]), Some(IpVersion::Unknown(3)));
        assert_eq!(ip_version(&[]), None);
    }

    #[test]
    fn test_tun_create_non_linux() {
        #[cfg(not(target_os = "linux"))]
        {
            let result = VCLTun::create(TunConfig::default());
            assert!(result.is_err());
        }
        #[cfg(target_os = "linux")]
        {
            let c = TunConfig::default();
            assert_eq!(c.mtu, 1420);
        }
    }

    #[test]
    fn test_ip_packet_len() {
        let raw = make_ipv4_packet();
        let expected_len = raw.len();
        let pkt = parse_ip_packet(raw).unwrap();
        assert_eq!(pkt.len, expected_len);
    }
}
