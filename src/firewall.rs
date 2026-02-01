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
#[derive(Copy, Clone, Debug)]
enum RuleAction {
    Drop,
    Accept,
}

#[cfg(target_os = "linux")]
impl NftablesBackend {
    const TABLE_NAME: &'static str = "nx53";
    const CHAIN_NAME: &'static str = "input";
    const ACTION_DROP: &'static str = "drop";
    const ACTION_ACCEPT: &'static str = "accept";

    pub fn new() -> Result<Self> {
        use nftables::{batch::Batch, helper, schema, types};

        // Create table and chain if they don't exist
        let mut batch = Batch::new();

        // Add table (inet family for IPv4/IPv6)
        batch.add_cmd(schema::NfCmd::Add(schema::NfListObject::Table(
            schema::Table {
                family: types::NfFamily::INet,
                name: Self::TABLE_NAME.into(),
                handle: None,
            },
        )));

        // Add chain with struct initialization
        batch.add_cmd(schema::NfCmd::Add(schema::NfListObject::Chain(
            schema::Chain {
                family: types::NfFamily::INet,
                table: Self::TABLE_NAME.into(),
                name: Self::CHAIN_NAME.into(),
                newname: None,
                handle: None,
                _type: Some(types::NfChainType::Filter),
                hook: Some(types::NfHook::Input),
                prio: Some(0),
                dev: None,
                policy: Some(types::NfChainPolicy::Accept),
            },
        )));

        helper::apply_ruleset(&batch.to_nftables()).map_err(|e| anyhow!("{}", e))?;
        info!("(nftables) Initialized nx53 table and input chain");
        Ok(Self)
    }

    fn create_ip_rule<'a>(ip: &'a str, action: RuleAction) -> Result<nftables::schema::Rule<'a>> {
        use nftables::{expr, schema, stmt, types};
        use std::borrow::Cow;
        use std::net::IpAddr;

        // Parse and validate IP address
        let parsed_ip: IpAddr = ip
            .parse()
            .map_err(|e| anyhow!("Invalid IP address: {}", e))?;
        let (protocol, addr_field) = match parsed_ip {
            IpAddr::V4(_) => ("ip", "saddr"),
            IpAddr::V6(_) => ("ip6", "saddr"),
        };

        let (action_str, action_stmt) = match action {
            RuleAction::Drop => (Self::ACTION_DROP, stmt::Statement::Drop(None)),
            RuleAction::Accept => (Self::ACTION_ACCEPT, stmt::Statement::Accept(None)),
        };

        Ok(schema::Rule {
            family: types::NfFamily::INet,
            table: Self::TABLE_NAME.into(),
            chain: Self::CHAIN_NAME.into(),
            expr: Cow::Owned(vec![
                stmt::Statement::Match(stmt::Match {
                    left: expr::Expression::Named(expr::NamedExpression::Payload(
                        expr::Payload::PayloadField(expr::PayloadField {
                            protocol: protocol.into(),
                            field: addr_field.into(),
                        }),
                    )),
                    right: expr::Expression::String(Cow::Borrowed(ip)),
                    op: stmt::Operator::EQ,
                }),
                action_stmt,
            ]),
            handle: None,
            index: None,
            comment: Some(format!("nx53: {} {}", action_str, ip).into()),
        })
    }
}

#[cfg(target_os = "linux")]
impl FirewallBackend for NftablesBackend {
    fn block_ip(&self, ip: &str) -> Result<()> {
        use nftables::{batch::Batch, helper, schema};

        let mut batch = Batch::new();
        batch.add_cmd(schema::NfCmd::Add(schema::NfListObject::Rule(
            Self::create_ip_rule(ip, RuleAction::Drop)?,
        )));

        helper::apply_ruleset(&batch.to_nftables()).map_err(|e| anyhow!("{}", e))?;
        info!("(nftables) Blocked IP: {}", ip);
        Ok(())
    }

    fn allow_ip(&self, ip: &str) -> Result<()> {
        use nftables::{batch::Batch, helper, schema};

        let mut batch = Batch::new();
        batch.add_cmd(schema::NfCmd::Add(schema::NfListObject::Rule(
            Self::create_ip_rule(ip, RuleAction::Accept)?,
        )));

        helper::apply_ruleset(&batch.to_nftables()).map_err(|e| anyhow!("{}", e))?;
        info!("(nftables) Allowed IP: {}", ip);
        Ok(())
    }

    fn flush(&self, target: FlushTarget) -> Result<()> {
        use nftables::{batch::Batch, helper, schema, types};

        match target {
            FlushTarget::All => {
                // Flush all rules from the chain
                let mut batch = Batch::new();
                batch.add_cmd(schema::NfCmd::Flush(schema::FlushObject::Chain(
                    schema::Chain {
                        family: types::NfFamily::INet,
                        table: Self::TABLE_NAME.into(),
                        name: Self::CHAIN_NAME.into(),
                        newname: None,
                        handle: None,
                        _type: None,
                        hook: None,
                        prio: None,
                        dev: None,
                        policy: None,
                    },
                )));
                helper::apply_ruleset(&batch.to_nftables()).map_err(|e| anyhow!("{}", e))?;
                info!("(nftables) Flushed all rules");
            }
            FlushTarget::Banned => {
                // Get current ruleset and delete only DROP rules
                let ruleset = helper::get_current_ruleset().map_err(|e| anyhow!("{}", e))?;

                let mut batch = Batch::new();
                for obj in ruleset.objects.iter() {
                    if let schema::NfObject::ListObject(schema::NfListObject::Rule(rule)) = obj {
                        let rule_table = rule.table.as_ref();
                        if rule_table == Self::TABLE_NAME {
                            let rule_chain = rule.chain.as_ref();
                            if rule_chain == Self::CHAIN_NAME {
                                // Check if this is a DROP rule primarily by statements, then by comment
                                let is_drop =
                                    rule.expr
                                        .iter()
                                        .any(|s| matches!(s, nftables::stmt::Statement::Drop(_)))
                                        || rule.comment.as_ref().is_some_and(|c| {
                                            c.to_ascii_lowercase().contains("drop")
                                        });

                                if is_drop {
                                    if let Some(handle) = rule.handle {
                                        batch.add_cmd(schema::NfCmd::Delete(
                                            schema::NfListObject::Rule(schema::Rule {
                                                family: rule.family,
                                                table: rule.table.clone(),
                                                chain: rule.chain.clone(),
                                                expr: std::borrow::Cow::Owned(vec![]),
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
                }

                if !batch.commands().is_empty() {
                    helper::apply_ruleset(&batch.to_nftables()).map_err(|e| anyhow!("{}", e))?;
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
