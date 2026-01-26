use crate::firewall::FirewallBackend;
use crate::logic::PacketInspector;
use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use pcap::{Capture, Device};
use std::sync::Arc;
use tokio::task;

pub struct TrafficMonitor {
    inspector: Arc<PacketInspector>,
    interface_name: String,
    firewall: Arc<dyn FirewallBackend + Send + Sync>,
}

impl TrafficMonitor {
    pub fn new(
        inspector: Arc<PacketInspector>,
        interface_name: Option<String>,
        firewall: Arc<dyn FirewallBackend + Send + Sync>,
    ) -> Result<Self> {
        let device = if let Some(name) = interface_name {
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
        task::spawn_blocking(move || -> Result<()> {
            let mut cap = Capture::from_device(interface_name.as_str())?
                .promisc(true)
                .snaplen(65535)
                .timeout(1000)
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

                        if let Some((src_ip, query_domain, qtype, is_tcp)) =
                            parse_dns_packet(packet.data)
                        {
                            debug!(
                                "Query: {} -> {} ({}) [{}]",
                                src_ip,
                                query_domain,
                                qtype,
                                if is_tcp { "TCP" } else { "UDP" }
                            );

                            // TCP Source Validation: IPs that complete TCP handshake are proven non-spoofed
                            // Mark them as validated before inspection so they get trusted status
                            if is_tcp {
                                inspector.mark_tcp_validated(&src_ip);
                            }

                            let should_block = inspector.inspect(
                                &src_ip,
                                &query_domain,
                                Some(&qtype),
                                packet.data.len(),
                            );
                            if should_block {
                                if let Err(e) = firewall.block_ip(&src_ip) {
                                    error!("Failed to block IP {}: {}", src_ip, e);
                                } else {
                                    warn!(
                                        "Blocked hostile IP: {} (Query: {})",
                                        src_ip, query_domain
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
        })
        .await??;

        Ok(())
    }
}

// Parsing helper - exposed for testing
// Returns (source_ip, domain, query_type, is_tcp)
pub fn parse_dns_packet(data: &[u8]) -> Option<(String, String, String, bool)> {
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
                return Some((
                    src_ip,
                    question.qname.to_string(),
                    format!("{:?}", question.qtype),
                    is_tcp,
                ));
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
}
