#[cfg(target_os = "linux")]
use anyhow::anyhow;
use anyhow::Result;
#[cfg(target_os = "linux")]
use log::info;
#[cfg(not(target_os = "linux"))]
use log::{info, warn};

/// Trait defining firewall operations.
pub trait FirewallBackend {
    fn block_ip(&self, ip: &str) -> Result<()>;
    fn allow_ip(&self, ip: &str) -> Result<()>;
    fn flush(&self, target: FlushTarget) -> Result<()>;
}

#[derive(Debug, Copy, Clone)]
pub enum FlushTarget {
    All,
    Banned,
}

/// Linux-specific iptables backend
#[cfg(target_os = "linux")]
pub struct IptablesBackend {
    ipt: iptables::IPTables,
}

#[cfg(target_os = "linux")]
impl IptablesBackend {
    pub fn new() -> Result<Self> {
        let ipt = iptables::new(false).map_err(|e| anyhow!("{}", e))?;
        Ok(Self { ipt })
    }

    fn ensure_chain(&self) -> Result<()> {
        // Simple check/create logic for NX53_INPUT chain
        if !self
            .ipt
            .chain_exists("filter", "NX53_INPUT")
            .map_err(|e| anyhow!("{}", e))?
        {
            self.ipt
                .new_chain("filter", "NX53_INPUT")
                .map_err(|e| anyhow!("{}", e))?;
            // Insert jump from INPUT to NX53_INPUT if not exists
            self.ipt
                .append_unique("filter", "INPUT", "-j NX53_INPUT")
                .map_err(|e| anyhow!("{}", e))?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl FirewallBackend for IptablesBackend {
    fn block_ip(&self, ip: &str) -> Result<()> {
        self.ensure_chain()?;
        // Append drop rule
        self.ipt
            .append("filter", "NX53_INPUT", &format!("-s {} -j DROP", ip))
            .map_err(|e| anyhow!("{}", e))?;
        info!("(Iptables) Blocked IP: {}", ip);
        Ok(())
    }

    fn allow_ip(&self, ip: &str) -> Result<()> {
        self.ensure_chain()?;
        // Append accept rule (allowlist)
        self.ipt
            .append("filter", "NX53_INPUT", &format!("-s {} -j ACCEPT", ip))
            .map_err(|e| anyhow!("{}", e))?;
        info!("(Iptables) Allowed IP: {}", ip);
        Ok(())
    }

    fn flush(&self, target: FlushTarget) -> Result<()> {
        match target {
            FlushTarget::All => {
                if self
                    .ipt
                    .chain_exists("filter", "NX53_INPUT")
                    .map_err(|e| anyhow!("{}", e))?
                {
                    self.ipt
                        .flush_chain("filter", "NX53_INPUT")
                        .map_err(|e| anyhow!("{}", e))?;
                }
                info!("(Iptables) Flushed all rules");
            }
            FlushTarget::Banned => {
                // Flush only DROP rules (banned IPs) from the chain, keeping ACCEPT rules (whitelist)
                if self
                    .ipt
                    .chain_exists("filter", "NX53_INPUT")
                    .map_err(|e| anyhow!("{}", e))?
                {
                    // Get all rules in the chain
                    let rules = self
                        .ipt
                        .list("filter", "NX53_INPUT")
                        .map_err(|e| anyhow!("{}", e))?;

                    // Delete DROP rules (banned IPs) in reverse order to avoid index shifting
                    for rule in rules.iter().rev() {
                        if rule.contains("-j DROP") {
                            // Extract the rule specification (skip the -A chain_name prefix)
                            if let Some(rule_spec) = rule.strip_prefix("-A NX53_INPUT ") {
                                let _ = self.ipt.delete("filter", "NX53_INPUT", rule_spec);
                            }
                        }
                    }
                }
                info!("(Iptables) Flushed banned IPs (DROP rules removed, whitelist preserved)");
            }
        }
        Ok(())
    }
}

/// Stub backend for non-Linux platforms (development/testing only)
#[cfg(not(target_os = "linux"))]
pub struct StubBackend;

#[cfg(not(target_os = "linux"))]
impl StubBackend {
    pub fn new() -> Result<Self> {
        warn!("Using stub firewall backend - no actual firewall rules will be applied");
        warn!("This is for development purposes only. Deploy on Linux for production use.");
        Ok(Self)
    }
}

#[cfg(not(target_os = "linux"))]
impl FirewallBackend for StubBackend {
    fn block_ip(&self, ip: &str) -> Result<()> {
        info!("(Stub) Would block IP: {}", ip);
        Ok(())
    }

    fn allow_ip(&self, ip: &str) -> Result<()> {
        info!("(Stub) Would allow IP: {}", ip);
        Ok(())
    }

    fn flush(&self, target: FlushTarget) -> Result<()> {
        match target {
            FlushTarget::All => info!("(Stub) Would flush all rules"),
            FlushTarget::Banned => info!("(Stub) Would flush banned IPs"),
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn get_backend() -> Result<Box<dyn FirewallBackend + Send + Sync>> {
    Ok(Box::new(IptablesBackend::new()?))
}

#[cfg(not(target_os = "linux"))]
pub fn get_backend() -> Result<Box<dyn FirewallBackend + Send + Sync>> {
    Ok(Box::new(StubBackend::new()?))
}
