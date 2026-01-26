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

/// Linux-specific nftables backend
#[cfg(target_os = "linux")]
pub struct NftablesBackend;

#[cfg(target_os = "linux")]
impl NftablesBackend {
    const TABLE_NAME: &'static str = "nx53";
    const CHAIN_NAME: &'static str = "input";

    pub fn new() -> Result<Self> {
        use nftables::{batch::Batch, helper, schema, types};

        // Create table and chain if they don't exist
        let mut batch = Batch::new();

        // Add table (inet family for IPv4/IPv6)
        batch.add_cmd(schema::NfCmd::Add(schema::NfListObject::Table(
            schema::Table {
                family: types::NfFamily::INet,
                name: Self::TABLE_NAME.to_string(),
                handle: None,
            },
        )));

        // Add chain
        batch.add_cmd(schema::NfCmd::Add(schema::NfListObject::Chain(
            schema::Chain::new(
                types::NfFamily::INet,
                Self::TABLE_NAME.to_string(),
                Self::CHAIN_NAME.to_string(),
                Some(schema::NfChainType::Filter),
                Some(schema::NfHook::Input),
                Some(0),
                None,
                Some(schema::NfChainPolicy::Accept),
            ),
        )));

        helper::apply_ruleset(&batch.to_nftables(), None, None).map_err(|e| anyhow!("{}", e))?;
        info!("(nftables) Initialized nx53 table and input chain");
        Ok(Self)
    }

    fn create_ip_rule(ip: &str, action: &str) -> nftables::schema::Rule {
        use nftables::{expr, schema, stmt, types};

        // Determine if IPv4 or IPv6
        let (protocol, addr_field) = if ip.contains(':') {
            ("ip6", "saddr")
        } else {
            ("ip", "saddr")
        };

        schema::Rule {
            family: types::NfFamily::INet,
            table: Self::TABLE_NAME.to_string(),
            chain: Self::CHAIN_NAME.to_string(),
            expr: vec![
                stmt::Statement::Match(stmt::Match {
                    left: expr::Expression::Named(expr::NamedExpression::Payload(
                        expr::Payload::PayloadField(expr::PayloadField {
                            protocol: protocol.to_string(),
                            field: addr_field.to_string(),
                        }),
                    )),
                    right: expr::Expression::String(ip.to_string()),
                    op: stmt::Operator::EQ,
                }),
                if action == "drop" {
                    stmt::Statement::Drop(None)
                } else {
                    stmt::Statement::Accept(None)
                },
            ],
            handle: None,
            index: None,
            comment: Some(format!("nx53: {} {}", action, ip)),
        }
    }
}

#[cfg(target_os = "linux")]
impl FirewallBackend for NftablesBackend {
    fn block_ip(&self, ip: &str) -> Result<()> {
        use nftables::{batch::Batch, helper, schema};

        let mut batch = Batch::new();
        batch.add_cmd(schema::NfCmd::Add(schema::NfListObject::Rule(
            Self::create_ip_rule(ip, "drop"),
        )));

        helper::apply_ruleset(&batch.to_nftables(), None, None).map_err(|e| anyhow!("{}", e))?;
        info!("(nftables) Blocked IP: {}", ip);
        Ok(())
    }

    fn allow_ip(&self, ip: &str) -> Result<()> {
        use nftables::{batch::Batch, helper, schema};

        let mut batch = Batch::new();
        batch.add_cmd(schema::NfCmd::Add(schema::NfListObject::Rule(
            Self::create_ip_rule(ip, "accept"),
        )));

        helper::apply_ruleset(&batch.to_nftables(), None, None).map_err(|e| anyhow!("{}", e))?;
        info!("(nftables) Allowed IP: {}", ip);
        Ok(())
    }

    fn flush(&self, target: FlushTarget) -> Result<()> {
        use nftables::{batch::Batch, helper, schema, types};

        match target {
            FlushTarget::All => {
                // Flush all rules from the chain
                let mut batch = Batch::new();
                batch.add_cmd(schema::NfCmd::Flush(schema::NfListObject::Chain(
                    schema::Chain::new(
                        types::NfFamily::INet,
                        Self::TABLE_NAME.to_string(),
                        Self::CHAIN_NAME.to_string(),
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                )));
                helper::apply_ruleset(&batch.to_nftables(), None, None)
                    .map_err(|e| anyhow!("{}", e))?;
                info!("(nftables) Flushed all rules");
            }
            FlushTarget::Banned => {
                // Get current ruleset and delete only DROP rules
                let ruleset =
                    helper::get_current_ruleset(None, None).map_err(|e| anyhow!("{}", e))?;

                let mut batch = Batch::new();
                for obj in &ruleset.objects {
                    if let schema::NfObject::ListObject(schema::NfListObject::Rule(rule)) = obj {
                        if rule.table == Self::TABLE_NAME && rule.chain == Self::CHAIN_NAME {
                            // Check if this is a DROP rule by looking at comment or statements
                            let is_drop = rule.comment.as_ref().is_some_and(|c| c.contains("drop"))
                                || rule
                                    .expr
                                    .iter()
                                    .any(|s| matches!(s, nftables::stmt::Statement::Drop(_)));

                            if is_drop {
                                if let Some(handle) = rule.handle {
                                    batch.add_cmd(schema::NfCmd::Delete(
                                        schema::NfListObject::Rule(schema::Rule {
                                            family: rule.family.clone(),
                                            table: rule.table.clone(),
                                            chain: rule.chain.clone(),
                                            expr: vec![],
                                            handle: Some(handle),
                                            index: None,
                                            comment: None,
                                        }),
                                    ));
                                }
                            }
                        }
                    }
                }

                if !batch.is_empty() {
                    helper::apply_ruleset(&batch.to_nftables(), None, None)
                        .map_err(|e| anyhow!("{}", e))?;
                }
                info!("(nftables) Flushed banned IPs (DROP rules removed, whitelist preserved)");
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
    Ok(Box::new(NftablesBackend::new()?))
}

#[cfg(not(target_os = "linux"))]
pub fn get_backend() -> Result<Box<dyn FirewallBackend + Send + Sync>> {
    Ok(Box::new(StubBackend::new()?))
}
