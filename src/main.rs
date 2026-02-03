mod cli;
mod config;
mod firewall;
mod logic;
mod monitor;
mod update;

use anyhow::{Result, bail};
use clap::Parser;
use cli::{Args, Commands};
use env_logger::Env;
use log::{error, info, warn};
use std::sync::Arc;

// Helper to check for root privileges
#[cfg(target_os = "linux")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(target_os = "linux"))]
fn is_root() -> bool {
    true // Assuming non-Linux environments don't need strict root checks for dev/stub
}

fn root_required_error() -> Result<()> {
    bail!("This command requires root privileges. Please run with sudo.");
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // Initialize Core Components
    // Firewall backend is now initialized lazily per-command to avoid requiring root for all commands

    // Load Config: Check local first, then /etc/nx53/config.toml
    let config = if let Ok(c) = config::AppConfig::load_from_file("config.toml") {
        c
    } else if let Ok(c) = config::AppConfig::load_from_file("/etc/nx53/config.toml") {
        c
    } else {
        warn!(
            "No config file found (checked ./config.toml and /etc/nx53/config.toml). Using defaults."
        );
        config::AppConfig::default()
    };
    info!(
        "Using config: Mode={}, Threshold={}",
        config.mode,
        config.get_threshold()
    );

    let inspector = Arc::new(logic::PacketInspector::new(
        config.get_threshold(),
        config.rate_limit.clone(),
        config.filters.clone(),
        config.auto_whitelist_days.unwrap_or(7),
    ));

    match &args.command {
        Some(Commands::Block { target }) => {
            if !is_root() {
                return root_required_error();
            }
            let firewall = firewall::get_backend()?;
            info!("Blocking target: {}", target);
            firewall.block_ip(target)?;
        }
        Some(Commands::Allow { target }) => {
            if !is_root() {
                return root_required_error();
            }
            let firewall = firewall::get_backend()?;
            info!("Allowing target: {}", target);
            firewall.allow_ip(target)?;
        }
        Some(Commands::Toggle { feature }) => {
            info!("Toggling feature: {:?}", feature);
        }
        Some(Commands::Stats { json }) => {
            info!("Showing stats (json: {})", json);
        }
        Some(Commands::Flush { target }) => {
            if !is_root() {
                return root_required_error();
            }
            let firewall = firewall::get_backend()?;
            info!("Flushing rules: {:?}", target);
            let fw_target = match target {
                cli::FlushTarget::All => firewall::FlushTarget::All,
                cli::FlushTarget::Banned => firewall::FlushTarget::Banned,
            };
            firewall.flush(fw_target)?;
        }
        Some(Commands::Update) => {
            if !is_root() {
                warn!("Update may require root privileges if checking system paths.");
            }
            update::update()?;
        }
        Some(Commands::Version) => {
            update::print_version();
        }
        None => {
            if !is_root() {
                error!("Daemon requires root privileges. Please run with sudo.");
                std::process::exit(1);
            }
            info!("Starting nx53 daemon in {:?} mode...", args.mode);

            let firewall = match firewall::get_backend() {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to initialize firewall backend: {}", e);
                    return Err(e);
                }
            };

            // Wrap firewall in Arc to share with monitor thread
            let firewall_arc: Arc<dyn firewall::FirewallBackend + Send + Sync> =
                Arc::from(firewall);

            // Start update check in background on the Tokio runtime
            // Start update check in background on the Tokio runtime
            // Use spawn_blocking because check_for_updates performs blocking blocking I/O (network + file)
            tokio::task::spawn_blocking(|| {
                if let Err(e) = update::check_for_updates() {
                    log::debug!("Failed to check for updates: {}", e);
                }
            });

            let monitor_inspector = inspector.clone();
            let monitor_firewall = firewall_arc.clone();

            // Initialize monitor and spawn the capture loop as an async task
            let monitor =
                match monitor::TrafficMonitor::new(monitor_inspector, None, monitor_firewall) {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Traffic Monitor failed to initialize: {}", e);
                        return Err(e);
                    }
                };

            // Spawn the monitor as an async task - it internally uses spawn_blocking for pcap
            // Spawn the monitor as an async task - it internally uses spawn_blocking for pcap
            tokio::spawn(async move {
                if let Err(e) = monitor.start().await {
                    error!("Monitor loop crashed: {}", e);
                    // If the monitor dies, the daemon is useless. Crash so systemd/supervisor restarts us.
                    std::process::exit(1);
                }
            });

            // Keep main alive
            tokio::signal::ctrl_c().await?;
            info!("Shutting down.");
        }
    }

    Ok(())
}
