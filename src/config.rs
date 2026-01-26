use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Profile {
    Home,       // 10k
    School,     // 50k
    Enterprise, // 100k
    Datacenter, // 1M
    Custom(u64),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_sec: u64,
    pub burst: u64,
    pub first_offense_duration_secs: u64,
    pub second_offense_duration_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_sec: 10,
            burst: 20,
            first_offense_duration_secs: 60,   // 1 minute
            second_offense_duration_secs: 300, // 5 minutes
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FilterConfig {
    pub block_any_queries: bool,
    pub block_large_txt: bool,
    pub txt_max_size: usize,

    // Enhanced amplification mitigation
    /// Additional query types to block (e.g., "AXFR", "IXFR")
    /// DNSSEC types (RRSIG, DNSKEY) are allowed by default for validation
    #[serde(default)]
    pub blocked_query_types: Vec<String>,

    /// Maximum UDP response size before forcing TCP (RFC 1035: 512 bytes)
    #[serde(default = "default_max_udp_response")]
    pub max_udp_response_size: usize,

    /// Enable Response Rate Limiting (RRL)
    #[serde(default = "default_true")]
    pub enable_rrl: bool,

    /// Max identical responses per second per source
    #[serde(default = "default_rrl_rate")]
    pub rrl_responses_per_sec: u64,

    /// Slip ratio: respond to 1/N requests when rate limited (0 = drop all)
    #[serde(default = "default_slip_ratio")]
    pub rrl_slip_ratio: u8,

    /// Force TCP for responses larger than max_udp_response_size
    #[serde(default = "default_true")]
    pub force_tcp_for_large: bool,

    /// Enable TCP source validation (trust IPs that complete TCP handshake)
    #[serde(default = "default_true")]
    pub tcp_validation_enabled: bool,

    /// Hours to trust a TCP-validated IP for UDP queries
    #[serde(default = "default_tcp_ttl")]
    pub tcp_validation_ttl_hours: u64,

    /// Block if response size exceeds query size by this factor
    #[serde(default = "default_amp_ratio")]
    pub amplification_ratio_limit: u64,

    /// Entropy threshold for random subdomain attack detection (0 = disabled)
    #[serde(default = "default_entropy_threshold")]
    pub subdomain_entropy_threshold: f64,

    /// Enable reflection pattern detection
    #[serde(default = "default_true")]
    pub detect_reflection_patterns: bool,
}

fn default_true() -> bool {
    true
}
fn default_max_udp_response() -> usize {
    512
}
fn default_rrl_rate() -> u64 {
    5
}
fn default_slip_ratio() -> u8 {
    2
}
fn default_tcp_ttl() -> u64 {
    24
}
fn default_amp_ratio() -> u64 {
    10
}
fn default_entropy_threshold() -> f64 {
    3.5
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            block_any_queries: true,
            block_large_txt: true,
            txt_max_size: 1024,
            // Block zone transfers by default (massive amplification)
            blocked_query_types: vec!["AXFR".to_string(), "IXFR".to_string()],
            max_udp_response_size: 512,
            enable_rrl: true,
            rrl_responses_per_sec: 5,
            rrl_slip_ratio: 2,
            force_tcp_for_large: true,
            tcp_validation_enabled: true,
            tcp_validation_ttl_hours: 24,
            amplification_ratio_limit: 10,
            subdomain_entropy_threshold: 3.5,
            detect_reflection_patterns: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
    pub mode: String,
    pub profile: Option<Profile>,
    /// Optional manual override. If set, this takes precedence over profile defaults.
    pub threshold_override: Option<u64>,

    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    #[serde(default)]
    pub filters: FilterConfig,

    /// Auto-whitelist IPs after this many days of clean traffic
    pub auto_whitelist_days: Option<u64>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            mode: "normal".to_string(),
            profile: Some(Profile::School),
            threshold_override: None,
            rate_limit: RateLimitConfig::default(),
            filters: FilterConfig::default(),
            auto_whitelist_days: Some(7),
        }
    }
}

impl AppConfig {
    pub fn get_threshold(&self) -> u64 {
        if let Some(t) = self.threshold_override {
            return t;
        }
        match &self.profile {
            Some(Profile::Home) => 10_000,
            Some(Profile::School) => 50_000,
            Some(Profile::Enterprise) => 100_000,
            Some(Profile::Datacenter) => 1_000_000,
            Some(Profile::Custom(v)) => *v,
            None => 50_000, // Default if nothing specified
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read config file")?;
        let config: AppConfig = toml::from_str(&content).context("Failed to parse config file")?;
        Ok(config)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;
        fs::write(path, content).context("Failed to write config file")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.get_threshold(), 50_000);
    }

    #[test]
    fn test_profile_logic() {
        let mut config = AppConfig::default();
        config.profile = Some(Profile::Home);
        assert_eq!(config.get_threshold(), 10_000);

        config.profile = Some(Profile::Datacenter);
        assert_eq!(config.get_threshold(), 1_000_000);
    }

    #[test]
    fn test_override_logic() {
        let mut config = AppConfig::default();
        config.profile = Some(Profile::Home); // 10k
        config.threshold_override = Some(999);
        // Override wins
        assert_eq!(config.get_threshold(), 999);
    }

    #[test]
    fn test_serialization() {
        let config = AppConfig {
            mode: "strict".to_string(),
            profile: Some(Profile::School),
            threshold_override: None,
            rate_limit: RateLimitConfig::default(),
            filters: FilterConfig::default(),
            auto_whitelist_days: Some(7),
        };
        let toml = toml::to_string(&config).unwrap();
        // Should contain profile = "School"
        assert!(toml.contains("profile = \"School\""));

        let loaded: AppConfig = toml::from_str(&toml).unwrap();
        assert_eq!(loaded.get_threshold(), 50_000);
    }

    #[test]
    fn test_save_and_load_file() {
        let config = AppConfig {
            mode: "test".to_string(),
            profile: Some(Profile::Enterprise),
            threshold_override: None,
            rate_limit: RateLimitConfig::default(),
            filters: FilterConfig::default(),
            auto_whitelist_days: Some(14),
        };

        let temp_path = std::env::temp_dir().join("nx53_test_config.toml");
        config.save_to_file(&temp_path).unwrap();

        let loaded = AppConfig::load_from_file(&temp_path).unwrap();
        assert_eq!(loaded.mode, "test");
        assert_eq!(loaded.profile, Some(Profile::Enterprise));
        assert_eq!(loaded.get_threshold(), 100_000);
        assert_eq!(loaded.auto_whitelist_days, Some(14));

        // Cleanup
        let _ = std::fs::remove_file(&temp_path);
    }
}
