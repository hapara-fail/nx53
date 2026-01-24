mod cli;
mod config;
mod firewall;
mod logic;
mod monitor;

use anyhow::Result;
use clap::Parser;
use cli::{Args, Commands};
use env_logger::Env;
use log::{info, error, warn};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    
    // Initialize Core Components
    let firewall = match firewall::get_backend() {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to initialize firewall backend: {}", e);
            return Err(e);
        }
    };
    
    // Load Config: Check local first, then /etc/nx53/config.toml
    let config = if let Ok(c) = config::AppConfig::load_from_file("config.toml") {
        c
    } else if let Ok(c) = config::AppConfig::load_from_file("/etc/nx53/config.toml") {
        c
    } else {
        warn!("No config file found (checked ./config.toml and /etc/nx53/config.toml). Using defaults.");
        config::AppConfig::default()
    };
    info!("Using config: Mode={}, Threshold={}", config.mode, config.get_threshold());

    let inspector = Arc::new(logic::PacketInspector::new(
        config.get_threshold(),
        config.rate_limit.clone(),
        config.filters.clone(),
        config.auto_whitelist_days.unwrap_or(7),
    ));

    match &args.command {
        Some(Commands::Block { target }) => {
            info!("Blocking target: {}", target);
            firewall.block_ip(target)?;
        }
        Some(Commands::Allow { target }) => {
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
            info!("Flushing rules: {:?}", target);
            let fw_target = match target {
                cli::FlushTarget::All => firewall::FlushTarget::All,
                cli::FlushTarget::Banned => firewall::FlushTarget::Banned,
            };
            firewall.flush(fw_target)?;
        }
        None => {
            info!("Starting nx53 daemon in {:?} mode...", args.mode);
            
            // Wrap firewall in Arc to share with monitor thread
            let firewall_arc: Arc<dyn firewall::FirewallBackend + Send + Sync> = Arc::from(firewall);

            // Start Monitor in background
            let monitor_inspector = inspector.clone();
            let monitor_firewall = firewall_arc.clone();
            
            tokio::task::spawn_blocking(move || {
                let monitor = match monitor::TrafficMonitor::new(monitor_inspector, None, monitor_firewall) {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Traffic Monitor failed to initialize: {}", e);
                        return;
                    }
                };
                
                if let Err(e) = tokio::runtime::Handle::current().block_on(monitor.start()) {
                     error!("Monitor loop crashed: {}", e);
                }
            });

            // Keep main alive
            tokio::signal::ctrl_c().await?;
            info!("Shutting down.");
        }
    }

    Ok(())
}
