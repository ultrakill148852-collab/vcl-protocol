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
//! - **Linux**: TUN/TAP kernel feature, requires root or `CAP_NET_ADMIN`
//! - **Windows**: Wintun driver, requires administrator privileges
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
    /// Interface name (e.g. "vcl0"). Max 15 chars on Linux, arbitrary on Windows.
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
/// Requires root or `CAP_NET_ADMIN` on Linux, administrator privileges on Windows.
pub struct VCLTun {
    #[cfg(target_os = "linux")]
    dev: tun::AsyncDevice,
    #[cfg(target_os = "windows")]
    dev: wintun::Adapter,
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    _marker: std::marker::PhantomData<()>,
    config: TunConfig,
}

impl VCLTun {
    /// Create and configure a new TUN interface.
    ///
    /// # Errors
    /// Returns [`VCLError::IoError`] if:
    /// - Not running as root / missing `CAP_NET_ADMIN` (Linux)
    /// - Not running as administrator (Windows)
    /// - Interface name is invalid or already in use
    /// - TUN/Wintun driver not available
    #[cfg(target_os = "linux")]
    pub fn create(config: TunConfig) -> Result<Self, VCLError> {
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(&config.name);
        tun_config
            .address(config.address)
            .destination(config.destination)
            .netmask(config.netmask)
            .mtu(config.mtu)
            .up();

        let dev = tun::create_as_async(&tun_config)
            .map_err(|e| VCLError::IoError(format!("Failed to create TUN device: {}", e)))?;

        info!(
            name = %config.name,
            address = %config.address,
            destination = %config.destination,
            mtu = config.mtu,
            platform = "linux",
            "TUN interface created"
        );

        Ok(VCLTun { dev, config })
    }

    /// Create and configure a new TUN interface on Windows using Wintun.
    #[cfg(target_os = "windows")]
    pub fn create(config: TunConfig) -> Result<Self, VCLError> {
        let adapter = wintun::Adapter::open(&config.name)
            .or_else(|_| wintun::Adapter::create(&config.name, "VCL", None))
            .map_err(|e| VCLError::IoError(format!("Failed to create Wintun adapter: {}", e)))?;

        adapter
            .set_address(config.address)
            .map_err(|e| VCLError::IoError(format!("Failed to set adapter address: {}", e)))?;
        adapter
            .set_gateway(config.destination)
            .map_err(|e| VCLError::IoError(format!("Failed to set adapter gateway: {}", e)))?;
        adapter
            .set_netmask(config.netmask)
            .map_err(|e| VCLError::IoError(format!("Failed to set adapter netmask: {}", e)))?;

        info!(
            name = %config.name,
            address = %config.address,
            destination = %config.destination,
            mtu = config.mtu,
            platform = "windows",
            "Wintun interface created"
        );

        Ok(VCLTun { dev: adapter, config })
    }

    /// Stub for unsupported platforms.
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub fn create(_config: TunConfig) -> Result<Self, VCLError> {
        Err(VCLError::IoError(
            "TUN interface is only supported on Linux and Windows".to_string(),
        ))
    }

    /// Read the next IP packet from the TUN interface.
    #[cfg(target_os = "linux")]
    pub async fn read_packet(&mut self) -> Result<Vec<u8>, VCLError> {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; self.config.mtu as usize + 4];
        let n = self.dev.read(&mut buf).await
            .map_err(|e| VCLError::IoError(format!("TUN read failed: {}", e)))?;
        buf.truncate(n);
        debug!(size = n, platform = "linux", "TUN packet read");
        Ok(buf)
    }

    #[cfg(target_os = "windows")]
    pub async fn read_packet(&mut self) -> Result<Vec<u8>, VCLError> {
        let adapter = self.dev.clone();
        let mtu = self.config.mtu as usize;
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; mtu + 4];
            let n = adapter.receive_packet(&mut buf)
                .map_err(|e| VCLError::IoError(format!("Wintun read failed: {}", e)))?;
            buf.truncate(n);
            Ok(buf)
        })
        .await
        .map_err(|e| VCLError::IoError(format!("Wintun read task failed: {}", e)))?
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub async fn read_packet(&mut self) -> Result<Vec<u8>, VCLError> {
        Err(VCLError::IoError("TUN not supported on this platform".to_string()))
    }

    /// Write (inject) a raw IP packet into the TUN interface.
    #[cfg(target_os = "linux")]
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<(), VCLError> {
        use tokio::io::AsyncWriteExt;
        self.dev.write_all(packet).await
            .map_err(|e| VCLError::IoError(format!("TUN write failed: {}", e)))?;
        debug!(size = packet.len(), platform = "linux", "TUN packet injected");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<(), VCLError> {
        let adapter = self.dev.clone();
        let packet = packet.to_vec();
        tokio::task::spawn_blocking(move || {
            adapter.send_packet(&packet)
                .map_err(|e| VCLError::IoError(format!("Wintun write failed: {}", e)))?;
            Ok(())
        })
        .await
        .map_err(|e| VCLError::IoError(format!("Wintun write task failed: {}", e)))?
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub async fn write_packet(&mut self, _packet: &[u8]) -> Result<(), VCLError> {
        Err(VCLError::IoError("TUN not supported on this platform".to_string()))
    }

    /// Returns the name of the TUN interface.
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
        vec![
            0x45, 0x00, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 1, 10, 0, 0, 1,
            0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn make_ipv6_packet() -> Vec<u8> {
        let mut pkt = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40];
        pkt.extend_from_slice(&[0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1]);
        pkt.extend_from_slice(&[0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2]);
        pkt.extend_from_slice(&[0u8; 8]);
        pkt
    }

    #[test]
    fn test_tun_config_default() {
        let c = TunConfig::default();
        assert_eq!(c.name, "vcl0");
        assert_eq!(c.mtu, 1420);
    }

    #[test]
    fn test_parse_ipv4_packet() {
        let pkt = parse_ip_packet(make_ipv4_packet()).unwrap();
        assert_eq!(pkt.version, IpVersion::V4);
        assert_eq!(pkt.src, "192.168.1.1");
        assert_eq!(pkt.dst, "10.0.0.1");
        assert_eq!(pkt.protocol, 6);
    }

    #[test]
    fn test_parse_ipv6_packet() {
        let pkt = parse_ip_packet(make_ipv6_packet()).unwrap();
        assert_eq!(pkt.version, IpVersion::V6);
        assert_eq!(pkt.protocol, 17);
    }

    #[test]
    fn test_parse_empty_packet() {
        assert!(parse_ip_packet(vec![]).is_err());
    }

    #[test]
    fn test_is_ipv4_ipv6() {
        assert!(is_ipv4(&make_ipv4_packet()));
        assert!(!is_ipv4(&make_ipv6_packet()));
        assert!(is_ipv6(&make_ipv6_packet()));
        assert!(!is_ipv6(&make_ipv4_packet()));
    }

    #[test]
    fn test_tun_create_unsupported_platform() {
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let result = VCLTun::create(TunConfig::default());
            assert!(result.is_err());
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
