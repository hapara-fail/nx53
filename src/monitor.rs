use crate::firewall::FirewallBackend;
use crate::logic::PacketInspector;
use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use pcap::{Capture, Device};
use std::sync::Arc;
use tokio::task;

/// Default snap length for packet capture (capture full packets up to 65535 bytes).
const SNAPLEN_MAX: i32 = 65535;

/// Capture timeout in milliseconds.
const CAPTURE_TIMEOUT_MS: i32 = 1000;

/// Structured return type for parsed DNS packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDnsPacket {
    pub source_ip: String,
    pub domain: String,
    pub query_type: String,
    pub is_tcp: bool,
}

pub struct TrafficMonitor {
    inspector: Arc<PacketInspector>,
    interface_name: String,
    firewall: Arc<dyn FirewallBackend + Send + Sync>,
}

/// Validate an interface name before passing it to libpcap.
/// This ensures the name is non-empty, reasonably sized, and only
/// contains typical interface name characters.
fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("Interface name must not be empty"));
    }

    // Reasonable upper bound to avoid excessively long or malicious input.
    if name.len() > 256 {
        return Err(anyhow!("Interface name is too long"));
    }

    // Allow common interface name characters: letters, digits, '_', '-', '.', ':'.
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':')
    {
        return Err(anyhow!(
            "Interface name '{}' contains invalid characters",
            name
        ));
    }

    Ok(())
}

impl TrafficMonitor {
    pub fn new(
        inspector: Arc<PacketInspector>,
        interface_name: Option<String>,
        firewall: Arc<dyn FirewallBackend + Send + Sync>,
    ) -> Result<Self> {
        let device = if let Some(name) = interface_name {
            // Validate the provided interface name before using it with pcap.
            validate_interface_name(&name)?;
            Device::list()?
                .into_iter()
                .find(|d| d.name == name)
                .ok_or_else(|| anyhow!("Device {} not found", name))?
        } else {
            Device::lookup()?.ok_or_else(|| anyhow!("No default device found"))?
        };

        info!("Initialized monitor on interface: {}", device.name);

        Ok(Self {
            inspector,
            interface_name: device.name,
            firewall,
        })
    }

    pub async fn start(&self) -> Result<()> {
        let interface_name = self.interface_name.clone();
        let inspector = Arc::clone(&self.inspector);
        let firewall = Arc::clone(&self.firewall);

        // Run blocking pcap capture in a dedicated blocking thread so we don't
        // block the async runtime.
        let handle = task::spawn_blocking(move || -> Result<()> {
            let mut cap = Capture::from_device(interface_name.as_str())?
                .promisc(true)
                .snaplen(SNAPLEN_MAX)
                .timeout(CAPTURE_TIMEOUT_MS)
                .open()?;

            // Filter for DNS (UDP port 53)
            // TCP is also mentioned in spec, adding "port 53" covers both usually unless qualified
            cap.filter("udp port 53 or tcp port 53", true)?;

            info!("Starting packet capture loop...");

            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        // Parse packet to extract Source IP and Query Domain
                        // This requires parsing Ethernet -> IP -> UDP/TCP -> DNS
                        // For brevity/simplicity in this MVP, we will attempt basic extraction.
                        // Doing full packet parsing manually is complex.
                        // We'll trust the logic structure for now and add a TODO for robust parsing.

                        if let Some(parsed) = parse_dns_packet(packet.data) {
                            debug!(
                                "Query: {} -> {} ({}) [{}]",
                                parsed.source_ip,
                                parsed.domain,
                                parsed.query_type,
                                if parsed.is_tcp { "TCP" } else { "UDP" }
                            );

                            // TCP Source Validation: IPs that complete TCP handshake are proven non-spoofed
                            // Mark them as validated before inspection so they get trusted status
                            if parsed.is_tcp {
                                inspector.mark_tcp_validated(&parsed.source_ip);
                            }

                            let should_block = inspector.inspect(
                                &parsed.source_ip,
                                &parsed.domain,
                                Some(&parsed.query_type),
                                packet.data.len(),
                            );
                            if should_block {
                                if let Err(e) = firewall.block_ip(&parsed.source_ip) {
                                    error!("Failed to block IP {}: {}", parsed.source_ip, e);
                                } else {
                                    warn!(
                                        "Blocked hostile IP: {} (Query: {})",
                                        parsed.source_ip, parsed.domain
                                    );
                                }
                            }
                        } else {
                            debug!(
                                "Failed to parse DNS packet (length: {} bytes); ignoring packet",
                                packet.data.len()
                            );
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Continue on timeouts; they are expected when no packets arrive within the timeout window.
                    }
                    Err(e) => {
                        error!("Packet capture error: {}", e);
                        // Break out of the capture loop on non-timeout errors to avoid infinite error loops.
                        break;
                    }
                }
                // This loop intentionally runs in a blocking thread; it no longer
                // blocks the async runtime.
            }

            Ok(())
        });

        let join_result = handle
            .await
            .map_err(|e| anyhow!("spawn_blocking task failed: {}", e))?;
        join_result?;

        Ok(())
    }
}

/// Parse a DNS packet from raw Ethernet frame data.
/// Returns a structured ParsedDnsPacket on success or None if parsing fails.
pub fn parse_dns_packet(data: &[u8]) -> Option<ParsedDnsPacket> {
    use dns_parser::Packet;
    use etherparse::{NetHeaders, PacketHeaders, TransportHeader};

    // Parse headers
    let headers = PacketHeaders::from_ethernet_slice(data).ok()?;

    // Extract Source IP
    let src_ip = match headers.net? {
        NetHeaders::Ipv4(ipv4, _) => std::net::IpAddr::V4(ipv4.source.into()).to_string(),
        NetHeaders::Ipv6(ipv6, _) => std::net::IpAddr::V6(ipv6.source.into()).to_string(),
        // ARP and other network headers don't apply to DNS packet parsing
        _ => return None,
    };

    // Check transport layer to determine if TCP or UDP
    let is_tcp = matches!(headers.transport, Some(TransportHeader::Tcp(_)));

    // Extract Query Domain using dns-parser
    let payload = headers.payload.slice();

    // For TCP DNS, skip the 2-byte length prefix (RFC 1035)
    let dns_payload = if is_tcp && payload.len() > 2 {
        &payload[2..]
    } else {
        payload
    };

    // Attempt to parse DNS packet
    match Packet::parse(dns_payload) {
        Ok(dns) => {
            // Only process Queries, ignore Responses to avoid self-blocking or RRL complexity for now
            if !dns.header.query {
                return None;
            }

            // We are interested in the first question
            if let Some(question) = dns.questions.first() {
                // qname comes out as "google.com" directly, no trailing dot usually in display
                return Some(ParsedDnsPacket {
                    source_ip: src_ip,
                    domain: question.qname.to_string(),
                    query_type: format!("{:?}", question.qtype),
                    is_tcp,
                });
            }
        }
        Err(e) => {
            debug!("Failed to parse DNS packet from {}: {}", src_ip, e);
            return None;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_short_packet() {
        let data = [0u8; 10]; // Too short
        assert_eq!(parse_dns_packet(&data), None);
    }

    // Note: constructing a full valid packet for unit testing without a packet builder dependency
    // (like etherparse with Write capabilities or pcap-file) is verbose.
    // For now, we verify it doesn't panic on garbage.
    #[test]
    fn test_parse_garbage() {
        let data = [0xff; 100];
        // Should return None, not panic
        assert_eq!(parse_dns_packet(&data), None);
    }

    #[test]
    fn test_validate_interface_name_valid() {
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("wlan0").is_ok());
        assert!(validate_interface_name("enp0s3").is_ok());
        assert!(validate_interface_name("docker0").is_ok());
        assert!(validate_interface_name("lo").is_ok());
    }

    #[test]
    fn test_validate_interface_name_invalid() {
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("eth0; rm -rf /").is_err());
        assert!(validate_interface_name("a".repeat(300).as_str()).is_err());
    }
}
