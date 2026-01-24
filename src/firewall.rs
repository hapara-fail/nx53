use anyhow::Result;
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
        let ipt = iptables::new(false)?;
        Ok(Self { ipt })
    }

    fn ensure_chain(&self) -> Result<()> {
        // Simple check/create logic for NX53_INPUT chain
        if !self.ipt.chain_exists("filter", "NX53_INPUT")? {
            self.ipt.new_chain("filter", "NX53_INPUT")?;
            // Insert jump from INPUT to NX53_INPUT if not exists
            self.ipt.append_unique("filter", "INPUT", "-j NX53_INPUT")?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl FirewallBackend for IptablesBackend {
    fn block_ip(&self, ip: &str) -> Result<()> {
        self.ensure_chain()?;
        // Append drop rule
        self.ipt.append("filter", "NX53_INPUT", &format!("-s {} -j DROP", ip))?;
        info!("(Iptables) Blocked IP: {}", ip);
        Ok(())
    }

    fn allow_ip(&self, ip: &str) -> Result<()> {
        self.ensure_chain()?;
        // Append accept rule (allowlist)
        self.ipt.append("filter", "NX53_INPUT", &format!("-s {} -j ACCEPT", ip))?;
        info!("(Iptables) Allowed IP: {}", ip);
        Ok(())
    }

    fn flush(&self, target: FlushTarget) -> Result<()> {
        match target {
            FlushTarget::All => {
                if self.ipt.chain_exists("filter", "NX53_INPUT")? {
                    self.ipt.flush_chain("filter", "NX53_INPUT")?;
                }
                info!("(Iptables) Flushed all rules");
            }
            FlushTarget::Banned => {
                // In a real implementation, we might label rules with comments to distinguish them.
                // For now, flush all as a simplification or specific implementation needed.
                info!("(Iptables) Flushed banned IPs (Not fully implemented specific filtering)");
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
