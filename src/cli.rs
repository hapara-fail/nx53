use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
/// nx53 - High-Performance DNS Firewall & Amplification Mitigation Engine
///
/// nx53 protects DNS servers from amplification attacks by monitoring traffic
/// and dynamically blocking abusive IPs using heuristic analysis and kernel-level
/// dropping via iptables.
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Operational mode
    ///
    /// - Intelligent: Only heuristic filtering is active.
    /// - Manual: Only static block/allow lists are active.
    /// - Hybrid: Both heuristic detection and static rules are active (Default).
    #[arg(short, long, value_enum, default_value_t = Mode::Hybrid)]
    pub mode: Mode,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Mode {
    Intelligent,
    Manual,
    Hybrid,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Adds a static rule to drop all packets from an IP or specific domain queries.
    ///
    /// Blocked IPs are added to the 'nx53-blacklist' ipset/chain and dropped
    /// before they reach the application.
    Block {
        /// The IP address (e.g., 192.168.1.1) or Domain (e.g., example.com) to block.
        target: String,
    },
    /// Adds a static rule to whitelist an IP or domain (bypasses all checks).
    ///
    /// Trusted IPs bypass the heuristic engine entirely.
    Allow {
        /// The IP address or Domain to whitelist.
        target: String,
    },
    /// Toggles the active status of the heuristic engine or manual rulesets independently.
    Toggle {
        /// The feature to toggle (Intelligent or Manual).
        feature: ToggleFeature,
    },
    /// Displays real-time telemetry.
    ///
    /// Shows current packet rates, total dropped packets, and active bans.
    Stats {
        /// Output statistics in JSON format for parsing.
        #[arg(long)]
        json: bool,
    },
    /// Clears current iptables chains managed by nx53.
    ///
    /// Useful for resetting the state or clearing all rules during shutdown.
    Flush {
        /// The scope of rules to flush.
        #[arg(value_enum)]
        target: FlushTarget,
    },
    /// Updates nx53 to the latest version from GitHub.
    Update,
    /// Displays the current version.
    Version,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ToggleFeature {
    Intelligent,
    Manual,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum FlushTarget {
    /// Flush ALL nx53 chains (reset firewall).
    All,
    /// Flush only the dynamic banned IPs list (keep whitelist).
    Banned,
}
