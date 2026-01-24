use dashmap::DashMap;
use log::{info, warn};
use std::sync::Arc;
use std::time::{Instant, Duration};
use crate::config::{RateLimitConfig, FilterConfig};

#[derive(Debug, Clone)]
pub struct PacketInspector {
    // Map of Domain -> Request Count
    domain_stats: Arc<DashMap<String, u64>>,
    // Map of Source IP -> State
    ip_states: Arc<DashMap<String, IpState>>,
    // Configurable thresholds
    threshold_domain_reqs: u64,
    rate_limit_config: RateLimitConfig,
    filter_config: FilterConfig,
    auto_whitelist_days: u64,
}

#[derive(Debug, Clone)]
struct IpState {
    first_seen: Instant,
    last_seen: Instant,
    first_query: String,
    is_legit: bool,
    is_blocked: bool,
    banned_until: Option<Instant>,
    offense_count: u32,
    
    // Rate limiting bucket
    last_rate_check: Instant,
    current_window_requests: u64,
}

impl PacketInspector {
    pub fn new(threshold_domain_reqs: u64, rate_limit_config: RateLimitConfig, filter_config: FilterConfig, auto_whitelist_days: u64) -> Self {
        Self {
            domain_stats: Arc::new(DashMap::new()),
            ip_states: Arc::new(DashMap::new()),
            threshold_domain_reqs,
            rate_limit_config,
            filter_config,
            auto_whitelist_days,
        }
    }

    /// Process a DNS query.
    /// Returns true if the packet should be BLOCKED, false otherwise.
    /// Now accepts optional query type and packet size for filtering.
    pub fn inspect(&self, source_ip: &str, query_domain: &str, query_type: Option<&str>, packet_size: usize) -> bool {
        // 0. Filter Checks (Statelessish)
        if let Some(qtype) = query_type {
            if self.filter_config.block_any_queries && qtype == "ANY" {
                warn!("Blocking ANY query from {}", source_ip);
                return true;
            }
            if self.filter_config.block_large_txt && qtype == "TXT" && packet_size > self.filter_config.txt_max_size {
                warn!("Blocking large TXT query from {} (size: {})", source_ip, packet_size);
                return true;
            }
        }
        // 1. Volumetric Analysis
        let mut domain_count = 0;
        self.domain_stats
            .entry(query_domain.to_string())
            .and_modify(|c| {
                *c += 1;
                domain_count = *c;
            })
            .or_insert(1);

        let is_high_volume = domain_count > self.threshold_domain_reqs;

        // 2. IP State Management
        let now = Instant::now();
        let mut should_block = false;

        self.ip_states.entry(source_ip.to_string())
            .and_modify(|state| {
                state.last_seen = now;
                
                // Check if ban expired
                if let Some(until) = state.banned_until {
                    if now > until {
                        info!("Ban expired for IP {}", source_ip);
                        state.banned_until = None;
                        state.is_blocked = false;
                        // Don't reset offense count to remember history? Or reset?
                        // For now, keep offense count to escalate if they do it again immediately.
                    } else {
                        should_block = true;
                        return;
                    }
                }

                // Legitimacy Validation (The "Escape Hatch") - MUST check before is_blocked
                // This allows blocked IPs to prove they are legitimate by querying a different safe domain
                if state.is_blocked && query_domain != state.first_query && !is_high_volume {
                    state.is_legit = true;
                    state.is_blocked = false; 
                    info!("IP {} validated as legitimate via escape hatch (query: {})", source_ip, query_domain);
                    should_block = false;
                    return;
                }

                if state.is_blocked {
                    should_block = true;
                    return;
                }
                
                // Auto Whitelist check
                if !state.is_legit && now.duration_since(state.first_seen).as_secs() > (self.auto_whitelist_days * 86400) {
                     info!("Auto-whitelisting clean IP {}", source_ip);
                     state.is_legit = true;
                }

                // Rate Limiting Logic - applies to ALL IPs including legit ones
                if self.rate_limit_config.enabled {
                     // Simple token bucket / fixed window
                     match now.checked_duration_since(state.last_rate_check) {
                         Some(d) if d.as_secs() >= 1 => {
                             state.last_rate_check = now;
                             state.current_window_requests = 0;
                         }
                         _ => {}
                     }
                     state.current_window_requests += 1;
                     
                     // Allow a burst? effectively encoded in limit if specific burst not implemented independently
                     if state.current_window_requests > self.rate_limit_config.requests_per_sec {
                         let duration_secs = if state.offense_count == 0 {
                             self.rate_limit_config.first_offense_duration_secs
                         } else {
                             self.rate_limit_config.second_offense_duration_secs
                         };
                         
                         state.offense_count += 1;
                         state.banned_until = Some(now + Duration::from_secs(duration_secs));
                         state.is_blocked = true;
                         warn!("Rate limit exceeded for {} (Offense #{}). Banning for {}s", source_ip, state.offense_count, duration_secs);
                         should_block = true;
                         return;
                     }
                }

                if state.is_legit {
                    // Already validated user.
                    should_block = false;
                    return;
                }
                
                // Legitimacy Validation for non-blocked IPs querying different safe domain
                if query_domain != state.first_query && !is_high_volume {
                     state.is_legit = true;
                     state.is_blocked = false; 
                     info!("IP {} validated as legitimate (query: {})", source_ip, query_domain);
                     should_block = false;
                }
            })
            .or_insert_with(|| {
                // First Packet Rule
                let block = is_high_volume;
                if block {
                    warn!("New IP {} detected querying high-volume domain {}. Marking hostile.", source_ip, query_domain);
                }
                should_block = block;

                IpState {
                    first_seen: now,
                    last_seen: now,
                    first_query: query_domain.to_string(),
                    is_legit: !block,
                    is_blocked: block,
                    banned_until: None,
                    offense_count: 0,
                    last_rate_check: now,
                    current_window_requests: 1,
                }
            });

        should_block
    }

    #[allow(dead_code)]
    pub fn reset_stats(&self) {
        self.domain_stats.clear();
        self.ip_states.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_inspector(threshold: u64) -> PacketInspector {
        PacketInspector::new(
            threshold, 
            RateLimitConfig::default(), 
            FilterConfig::default(),
            7
        )
    }

    #[test]
    fn test_volumetric_trigger() {
        let inspector = get_test_inspector(100);
        let domain = "attack.com";
        
        // 1. Pump up volume
        for _ in 0..101 {
            inspector.inspect("1.1.1.1", domain, None, 0);
        }
        
        // 2. New IP hits it
        let blocked = inspector.inspect("2.2.2.2", domain, None, 0);
        assert!(blocked, "New IP should be blocked when hitting high volume domain first");
    }

    #[test]
    fn test_normal_traffic() {
        let inspector = get_test_inspector(100);
        let domain = "google.com";

        // Low volume
        let blocked = inspector.inspect("3.3.3.3", domain, None, 0);
        assert!(!blocked, "Normal first packet should not be blocked");
    }

    #[test]
    fn test_escape_hatch() {
        let inspector = get_test_inspector(100);
        let attack_domain = "flood.com";
        let safe_domain = "safe.com";

        // 1. Pump volume
        for _ in 0..101 {
            inspector.inspect("10.0.0.1", attack_domain, None, 0);
        }

        // 2. Victim IP gets blocked initially
        let blocked = inspector.inspect("5.5.5.5", attack_domain, None, 0);
        assert!(blocked, "Should be blocked initially");

        // 3. User queries safe domain -> should validate
        let blocked_safe = inspector.inspect("5.5.5.5", safe_domain, None, 0);
        assert!(!blocked_safe, "Should be allowed on safe domain");

        // 4. User queries attack domain again -> should be allowed now (whitelist)
        let blocked_retry = inspector.inspect("5.5.5.5", attack_domain, None, 0);
        assert!(!blocked_retry, "Should be allowed on attack domain after validation");
    }
    
    #[test]
    fn test_rate_limiting() {
        let mut config = RateLimitConfig::default();
        config.requests_per_sec = 5;
        config.first_offense_duration_secs = 10;
        
        let inspector = PacketInspector::new(1000, config, FilterConfig::default(), 7);
        let domain = "fast.com";
        
        // Send 5 requests (allowed)
        for _ in 0..5 {
            let blocked = inspector.inspect("6.6.6.6", domain, None, 0);
            assert!(!blocked);
        }
        
        // 6th request (blocked)
        let blocked = inspector.inspect("6.6.6.6", domain, None, 0);
        assert!(blocked, "Should be blocked by rate limit");
    }
    
    #[test]
    fn test_filter_any() {
        let inspector = get_test_inspector(100);
        let blocked = inspector.inspect("7.7.7.7", "any.com", Some("ANY"), 50);
        assert!(blocked, "Should block ANY query");
    }
}

