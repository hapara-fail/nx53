use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};

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
            first_offense_duration_secs: 60, // 1 minute
            second_offense_duration_secs: 300, // 5 minutes
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FilterConfig {
    pub block_any_queries: bool,
    pub block_large_txt: bool,
    pub txt_max_size: usize,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            block_any_queries: true,
            block_large_txt: true,
            txt_max_size: 1024,
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

    #[allow(dead_code)]
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
}
