//! # VCL IP Packet Parser
//!
//! Full parsing of IPv4/IPv6 packets captured from the TUN interface.
//! Extracts transport layer headers (TCP, UDP, ICMP) for routing decisions.
//!
//! ## Example
//!
//! ```rust
//! use vcl_protocol::ip_packet::{ParsedPacket, TransportProtocol};
//!
//! // Minimal IPv4/TCP packet
//! let raw = vec![
//!     0x45, 0x00, 0x00, 0x28,
//!     0x00, 0x01, 0x00, 0x00,
//!     0x40, 0x06, 0x00, 0x00,
//!     192, 168, 1, 1,
//!     10, 0, 0, 1,
//!     0x00, 0x50, 0x1F, 0x90, // src=80, dst=8080
//!     0x00, 0x00, 0x00, 0x01,
//!     0x00, 0x00, 0x00, 0x01,
//!     0x50, 0x02, 0x20, 0x00,
//!     0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let packet = ParsedPacket::parse(raw).unwrap();
//! assert!(matches!(packet.transport, TransportProtocol::Tcp { .. }));
//! ```

use crate::error::VCLError;
use etherparse::{
    Ipv4HeaderSlice, Ipv6HeaderSlice,
    TcpHeaderSlice, UdpHeaderSlice,
};
use tracing::debug;

/// IP version of a parsed packet.
#[derive(Debug, Clone, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Transport layer protocol extracted from an IP packet.
#[derive(Debug, Clone, PartialEq)]
pub enum TransportProtocol {
    /// TCP segment with source/destination ports and flags.
    Tcp {
        src_port: u16,
        dst_port: u16,
        syn: bool,
        ack: bool,
        fin: bool,
        rst: bool,
        payload_offset: usize,
    },
    /// UDP datagram with source/destination ports.
    Udp {
        src_port: u16,
        dst_port: u16,
        payload_offset: usize,
    },
    /// ICMP message with type and code.
    Icmp {
        icmp_type: u8,
        code: u8,
    },
    /// ICMPv6 message.
    Icmpv6 {
        icmp_type: u8,
        code: u8,
    },
    /// Any other protocol (GRE, ESP, etc).
    Other {
        protocol_number: u8,
    },
}

impl TransportProtocol {
    /// Returns the source port if this is TCP or UDP.
    pub fn src_port(&self) -> Option<u16> {
        match self {
            TransportProtocol::Tcp { src_port, .. } => Some(*src_port),
            TransportProtocol::Udp { src_port, .. } => Some(*src_port),
            _ => None,
        }
    }

    /// Returns the destination port if this is TCP or UDP.
    pub fn dst_port(&self) -> Option<u16> {
        match self {
            TransportProtocol::Tcp { dst_port, .. } => Some(*dst_port),
            TransportProtocol::Udp { dst_port, .. } => Some(*dst_port),
            _ => None,
        }
    }

    /// Returns `true` if this is a TCP SYN (connection initiation).
    pub fn is_syn(&self) -> bool {
        matches!(self, TransportProtocol::Tcp { syn: true, ack: false, .. })
    }

    /// Returns `true` if this is a TCP FIN (connection close).
    pub fn is_fin(&self) -> bool {
        matches!(self, TransportProtocol::Tcp { fin: true, .. })
    }

    /// Returns `true` if this is a TCP RST (connection reset).
    pub fn is_rst(&self) -> bool {
        matches!(self, TransportProtocol::Tcp { rst: true, .. })
    }

    /// Returns the protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6).
    pub fn protocol_number(&self) -> u8 {
        match self {
            TransportProtocol::Tcp { .. }   => 6,
            TransportProtocol::Udp { .. }   => 17,
            TransportProtocol::Icmp { .. }  => 1,
            TransportProtocol::Icmpv6 { .. } => 58,
            TransportProtocol::Other { protocol_number } => *protocol_number,
        }
    }
}

/// A fully parsed IP packet with IP and transport layer information.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /// Raw bytes of the original packet.
    pub raw: Vec<u8>,
    /// IP version.
    pub ip_version: IpVersion,
    /// Source IP address as string.
    pub src_ip: String,
    /// Destination IP address as string.
    pub dst_ip: String,
    /// TTL (IPv4) or hop limit (IPv6).
    pub ttl: u8,
    /// Total packet length in bytes.
    pub total_len: usize,
    /// Byte offset where the IP payload starts (after IP header).
    pub ip_payload_offset: usize,
    /// Parsed transport layer.
    pub transport: TransportProtocol,
}

impl ParsedPacket {
    /// Parse a raw IP packet (IPv4 or IPv6) into a [`ParsedPacket`].
    ///
    /// # Errors
    /// Returns [`VCLError::InvalidPacket`] if:
    /// - The packet is empty or too short
    /// - The IP header is malformed
    pub fn parse(raw: Vec<u8>) -> Result<Self, VCLError> {
        if raw.is_empty() {
            return Err(VCLError::InvalidPacket("Empty packet".to_string()));
        }
        match raw[0] >> 4 {
            4 => Self::parse_ipv4(raw),
            6 => Self::parse_ipv6(raw),
            v => Err(VCLError::InvalidPacket(format!("Unknown IP version: {}", v))),
        }
    }

    fn parse_ipv4(raw: Vec<u8>) -> Result<Self, VCLError> {
        let header = Ipv4HeaderSlice::from_slice(&raw)
            .map_err(|e| VCLError::InvalidPacket(format!("IPv4 header error: {}", e)))?;

        let src_ip = format!(
            "{}.{}.{}.{}",
            header.source()[0], header.source()[1],
            header.source()[2], header.source()[3]
        );
        let dst_ip = format!(
            "{}.{}.{}.{}",
            header.destination()[0], header.destination()[1],
            header.destination()[2], header.destination()[3]
        );
        let ttl = header.ttl();
        let protocol = header.protocol().0;
        let ip_payload_offset = (header.ihl() as usize) * 4;
        let total_len = raw.len();

        let transport = parse_transport(protocol, &raw, ip_payload_offset)?;

        debug!(
            src = %src_ip, dst = %dst_ip,
            protocol, ttl, total_len,
            "IPv4 packet parsed"
        );

        Ok(ParsedPacket {
            raw,
            ip_version: IpVersion::V4,
            src_ip,
            dst_ip,
            ttl,
            total_len,
            ip_payload_offset,
            transport,
        })
    }

    fn parse_ipv6(raw: Vec<u8>) -> Result<Self, VCLError> {
        let header = Ipv6HeaderSlice::from_slice(&raw)
            .map_err(|e| VCLError::InvalidPacket(format!("IPv6 header error: {}", e)))?;

        let src_ip = format!("{}", header.source_addr());
        let dst_ip = format!("{}", header.destination_addr());
        let ttl = header.hop_limit();
        let protocol = header.next_header().0;
        let ip_payload_offset = 40; // IPv6 fixed header size
        let total_len = raw.len();

        let transport = parse_transport(protocol, &raw, ip_payload_offset)?;

        debug!(
            src = %src_ip, dst = %dst_ip,
            protocol, ttl, total_len,
            "IPv6 packet parsed"
        );

        Ok(ParsedPacket {
            raw,
            ip_version: IpVersion::V6,
            src_ip,
            dst_ip,
            ttl,
            total_len,
            ip_payload_offset,
            transport,
        })
    }

    /// Returns `true` if this packet is IPv4.
    pub fn is_ipv4(&self) -> bool {
        self.ip_version == IpVersion::V4
    }

    /// Returns `true` if this packet is IPv6.
    pub fn is_ipv6(&self) -> bool {
        self.ip_version == IpVersion::V6
    }

    /// Returns `true` if the destination IP matches `ip`.
    pub fn is_destined_for(&self, ip: &str) -> bool {
        self.dst_ip == ip
    }

    /// Returns `true` if the source IP matches `ip`.
    pub fn is_from(&self, ip: &str) -> bool {
        self.src_ip == ip
    }

    /// Returns the payload slice — bytes after the IP header.
    pub fn ip_payload(&self) -> &[u8] {
        if self.ip_payload_offset < self.raw.len() {
            &self.raw[self.ip_payload_offset..]
        } else {
            &[]
        }
    }

    /// Returns `true` if this is a DNS query (UDP dst port 53).
    pub fn is_dns(&self) -> bool {
        matches!(&self.transport, TransportProtocol::Udp { dst_port: 53, .. })
    }

    /// Returns `true` if this is an ICMP echo request (ping).
    pub fn is_ping(&self) -> bool {
        matches!(&self.transport,
            TransportProtocol::Icmp { icmp_type: 8, .. } |
            TransportProtocol::Icmpv6 { icmp_type: 128, .. }
        )
    }

    /// Returns a human-readable summary of this packet.
    pub fn summary(&self) -> String {
        match &self.transport {
            TransportProtocol::Tcp { src_port, dst_port, syn, fin, rst, .. } => {
                let flags = if *syn { " SYN" } else if *fin { " FIN" } else if *rst { " RST" } else { "" };
                format!("TCP {}:{} → {}:{}{} ({} bytes)",
                    self.src_ip, src_port, self.dst_ip, dst_port, flags, self.total_len)
            }
            TransportProtocol::Udp { src_port, dst_port, .. } => {
                format!("UDP {}:{} → {}:{} ({} bytes)",
                    self.src_ip, src_port, self.dst_ip, dst_port, self.total_len)
            }
            TransportProtocol::Icmp { icmp_type, code } => {
                format!("ICMP {} → {} type={} code={} ({} bytes)",
                    self.src_ip, self.dst_ip, icmp_type, code, self.total_len)
            }
            TransportProtocol::Icmpv6 { icmp_type, code } => {
                format!("ICMPv6 {} → {} type={} code={} ({} bytes)",
                    self.src_ip, self.dst_ip, icmp_type, code, self.total_len)
            }
            TransportProtocol::Other { protocol_number } => {
                format!("Proto#{} {} → {} ({} bytes)",
                    protocol_number, self.src_ip, self.dst_ip, self.total_len)
            }
        }
    }
}

fn parse_transport(
    protocol: u8,
    raw: &[u8],
    offset: usize,
) -> Result<TransportProtocol, VCLError> {
    match protocol {
        6 => parse_tcp(raw, offset),
        17 => parse_udp(raw, offset),
        1 => parse_icmp(raw, offset),
        58 => parse_icmpv6(raw, offset),
        p => Ok(TransportProtocol::Other { protocol_number: p }),
    }
}

fn parse_tcp(raw: &[u8], offset: usize) -> Result<TransportProtocol, VCLError> {
    if offset >= raw.len() {
        return Ok(TransportProtocol::Other { protocol_number: 6 });
    }
    let tcp = TcpHeaderSlice::from_slice(&raw[offset..])
        .map_err(|e| VCLError::InvalidPacket(format!("TCP header error: {}", e)))?;
    let payload_offset = offset + (tcp.data_offset() as usize) * 4;
    Ok(TransportProtocol::Tcp {
        src_port: tcp.source_port(),
        dst_port: tcp.destination_port(),
        syn: tcp.syn(),
        ack: tcp.ack(),
        fin: tcp.fin(),
        rst: tcp.rst(),
        payload_offset,
    })
}

fn parse_udp(raw: &[u8], offset: usize) -> Result<TransportProtocol, VCLError> {
    if offset >= raw.len() {
        return Ok(TransportProtocol::Other { protocol_number: 17 });
    }
    let udp = UdpHeaderSlice::from_slice(&raw[offset..])
        .map_err(|e| VCLError::InvalidPacket(format!("UDP header error: {}", e)))?;
    let payload_offset = offset + 8; // UDP header is always 8 bytes
    Ok(TransportProtocol::Udp {
        src_port: udp.source_port(),
        dst_port: udp.destination_port(),
        payload_offset,
    })
}

fn parse_icmp(raw: &[u8], offset: usize) -> Result<TransportProtocol, VCLError> {
    if offset + 2 > raw.len() {
        return Ok(TransportProtocol::Other { protocol_number: 1 });
    }
    Ok(TransportProtocol::Icmp {
        icmp_type: raw[offset],
        code: raw[offset + 1],
    })
}

fn parse_icmpv6(raw: &[u8], offset: usize) -> Result<TransportProtocol, VCLError> {
    if offset + 2 > raw.len() {
        return Ok(TransportProtocol::Other { protocol_number: 58 });
    }
    Ok(TransportProtocol::Icmpv6 {
        icmp_type: raw[offset],
        code: raw[offset + 1],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp_packet() -> Vec<u8> {
        vec![
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x28, // version=4 ihl=5 total=40
            0x00, 0x01, 0x00, 0x00, // id=1 flags=0
            0x40, 0x06, 0x00, 0x00, // ttl=64 proto=TCP(6) checksum=0
            192, 168, 1, 1,          // src
            10,  0,   0, 1,          // dst
            // TCP header (20 bytes)
            0x00, 0x50,              // src_port=80
            0x1F, 0x90,              // dst_port=8080
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x01, // ack
            0x50, 0x02,              // data_offset=5 flags=SYN
            0x20, 0x00,              // window
            0x00, 0x00, 0x00, 0x00, // checksum+urgent
        ]
    }

    fn ipv4_udp_packet() -> Vec<u8> {
        vec![
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x1C,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x11, 0x00, 0x00, // proto=UDP(17)
            10, 0, 0, 1,
            8, 8, 8, 8,             // dst=8.8.8.8
            // UDP header (8 bytes)
            0x04, 0x00,             // src_port=1024
            0x00, 0x35,             // dst_port=53 (DNS)
            0x00, 0x08,             // length=8
            0x00, 0x00,             // checksum
        ]
    }

    fn ipv4_icmp_packet() -> Vec<u8> {
        vec![
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x1C,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x01, 0x00, 0x00, // proto=ICMP(1)
            10, 0, 0, 1,
            10, 0, 0, 2,
            // ICMP (4 bytes)
            0x08, 0x00,             // type=8 (echo request), code=0
            0x00, 0x00,             // checksum
        ]
    }

    #[test]
    fn test_parse_tcp() {
        let pkt = ParsedPacket::parse(ipv4_tcp_packet()).unwrap();
        assert!(pkt.is_ipv4());
        assert_eq!(pkt.src_ip, "192.168.1.1");
        assert_eq!(pkt.dst_ip, "10.0.0.1");
        assert_eq!(pkt.ttl, 64);
        assert!(matches!(pkt.transport, TransportProtocol::Tcp {
            src_port: 80, dst_port: 8080, syn: true, ..
        }));
        assert!(pkt.transport.is_syn());
        assert!(!pkt.transport.is_fin());
        assert_eq!(pkt.transport.src_port(), Some(80));
        assert_eq!(pkt.transport.dst_port(), Some(8080));
        assert_eq!(pkt.transport.protocol_number(), 6);
    }

    #[test]
    fn test_parse_udp_dns() {
        let pkt = ParsedPacket::parse(ipv4_udp_packet()).unwrap();
        assert!(pkt.is_ipv4());
        assert_eq!(pkt.dst_ip, "8.8.8.8");
        assert!(matches!(pkt.transport, TransportProtocol::Udp {
            src_port: 1024, dst_port: 53, ..
        }));
        assert!(pkt.is_dns());
        assert_eq!(pkt.transport.protocol_number(), 17);
    }

    #[test]
    fn test_parse_icmp_ping() {
        let pkt = ParsedPacket::parse(ipv4_icmp_packet()).unwrap();
        assert!(pkt.is_ping());
        assert!(matches!(pkt.transport, TransportProtocol::Icmp {
            icmp_type: 8, code: 0
        }));
        assert_eq!(pkt.transport.protocol_number(), 1);
    }

    #[test]
    fn test_parse_empty() {
        assert!(ParsedPacket::parse(vec![]).is_err());
    }

    #[test]
    fn test_parse_unknown_version() {
        let raw = vec![0x30u8; 20];
        assert!(ParsedPacket::parse(raw).is_err());
    }

    #[test]
    fn test_is_destined_for() {
        let pkt = ParsedPacket::parse(ipv4_tcp_packet()).unwrap();
        assert!(pkt.is_destined_for("10.0.0.1"));
        assert!(!pkt.is_destined_for("1.2.3.4"));
    }

    #[test]
    fn test_is_from() {
        let pkt = ParsedPacket::parse(ipv4_tcp_packet()).unwrap();
        assert!(pkt.is_from("192.168.1.1"));
        assert!(!pkt.is_from("1.2.3.4"));
    }

    #[test]
    fn test_ip_payload() {
        let pkt = ParsedPacket::parse(ipv4_tcp_packet()).unwrap();
        // IPv4 IHL=5 → offset=20
        assert_eq!(pkt.ip_payload_offset, 20);
        assert!(!pkt.ip_payload().is_empty());
    }

    #[test]
    fn test_summary_tcp() {
        let pkt = ParsedPacket::parse(ipv4_tcp_packet()).unwrap();
        let s = pkt.summary();
        assert!(s.contains("TCP"));
        assert!(s.contains("192.168.1.1"));
        assert!(s.contains("10.0.0.1"));
        assert!(s.contains("80"));
        assert!(s.contains("8080"));
        assert!(s.contains("SYN"));
    }

    #[test]
    fn test_summary_udp() {
        let pkt = ParsedPacket::parse(ipv4_udp_packet()).unwrap();
        let s = pkt.summary();
        assert!(s.contains("UDP"));
        assert!(s.contains("53"));
    }

    #[test]
    fn test_tcp_flags() {
        let pkt = ParsedPacket::parse(ipv4_tcp_packet()).unwrap();
        assert!(pkt.transport.is_syn());
        assert!(!pkt.transport.is_fin());
        assert!(!pkt.transport.is_rst());
    }

    #[test]
    fn test_other_protocol() {
        let mut raw = vec![0u8; 24];
        raw[0] = 0x45; // IPv4, IHL=5
        raw[9] = 0x2F; // GRE = 47
        raw[12..16].copy_from_slice(&[10, 0, 0, 1]);
        raw[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let pkt = ParsedPacket::parse(raw).unwrap();
        assert!(matches!(pkt.transport, TransportProtocol::Other { protocol_number: 47 }));
        assert_eq!(pkt.transport.protocol_number(), 47);
    }

    #[test]
    fn test_is_not_dns_for_tcp() {
        let pkt = ParsedPacket::parse(ipv4_tcp_packet()).unwrap();
        assert!(!pkt.is_dns());
    }

    #[test]
    fn test_is_not_ping_for_udp() {
        let pkt = ParsedPacket::parse(ipv4_udp_packet()).unwrap();
        assert!(!pkt.is_ping());
    }
}
