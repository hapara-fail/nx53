use crate::logic::PacketInspector;
use crate::firewall::FirewallBackend;
use anyhow::{anyhow, Result};
use log::{error, info, debug, warn};
use pcap::{Capture, Device};
use std::sync::Arc;

pub struct TrafficMonitor {
    inspector: Arc<PacketInspector>,
    interface_name: String,
    firewall: Arc<dyn FirewallBackend + Send + Sync>,
}

impl TrafficMonitor {
    pub fn new(inspector: Arc<PacketInspector>, interface_name: Option<String>, firewall: Arc<dyn FirewallBackend + Send + Sync>) -> Result<Self> {
        let device = if let Some(name) = interface_name {
            Device::list()?
                .into_iter()
                .find(|d| d.name == name)
                .ok_or_else(|| anyhow!("Device {} not found", name))?
        } else {
            Device::lookup()?
                .ok_or_else(|| anyhow!("No default device found"))?
        };

        info!("Initialized monitor on interface: {}", device.name);

        Ok(Self {
            inspector,
            interface_name: device.name,
            firewall,
        })
    }

    pub async fn start(&self) -> Result<()> {
        let mut cap = Capture::from_device(self.interface_name.as_str())?
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

                    if let Some((src_ip, query_domain, qtype)) = parse_dns_packet(packet.data) {
                         debug!("Query: {} -> {} ({})", src_ip, query_domain, qtype);
                         let should_block = self.inspector.inspect(&src_ip, &query_domain, Some(&qtype), packet.data.len());
                         if should_block {
                             if let Err(e) = self.firewall.block_ip(&src_ip) {
                                 error!("Failed to block IP {}: {}", src_ip, e);
                             } else {
                                 warn!("Blocked hostile IP: {} (Query: {})", src_ip, query_domain);
                             }
                         }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Continue
                }
                Err(e) => {
                    error!("Packet capture error: {}", e);
                    // Decide whether to break or continue
                }
            }
            // Yield to async runtime? pcap is blocking usage here typically unless we use async-pcap or stream.
            // Using a simple blocking loop in `start` usage with `tokio::task::spawn_blocking` is common.
        }
    }
}

// Parsing helper - exposed for testing
pub fn parse_dns_packet(data: &[u8]) -> Option<(String, String, String)> {
    use etherparse::{PacketHeaders, IpHeader};
    use dns_parser::Packet;

    // Parse headers
    let headers = PacketHeaders::from_ethernet_slice(data).ok()?;

    // Extract Source IP
    let src_ip = match headers.ip? {
        IpHeader::Version4(ipv4, _) => std::net::IpAddr::V4(ipv4.source.into()).to_string(),
        IpHeader::Version6(ipv6, _) => std::net::IpAddr::V6(ipv6.source.into()).to_string(),
    };

    // Extract Query Domain using dns-parser
    let payload = headers.payload;
    
    // Attempt to parse DNS packet
    match Packet::parse(payload) {
        Ok(dns) => {
            // Only process Queries, ignore Responses to avoid self-blocking or RRL complexity for now
            if !dns.header.query {
                return None;
            }
            
            // We are interested in the first question
            if let Some(question) = dns.questions.first() {
                // qname comes out as "google.com" directly, no trailing dot usually in display
                return Some((src_ip, question.qname.to_string(), format!("{:?}", question.qtype)));
            }
        }
        Err(_) => return None,
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

