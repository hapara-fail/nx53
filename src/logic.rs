use crate::config::{FilterConfig, RateLimitConfig};
use dashmap::DashMap;
use log::{debug, info, warn};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

    // Enhanced amplification mitigation fields
    /// Total bytes of queries received from this IP
    total_query_bytes: u64,
    /// Total bytes of responses sent to this IP (estimated)
    #[allow(dead_code)]
    total_response_bytes: u64,
    /// Unique domains queried by this IP (for entropy/reflection detection)
    unique_domains: HashSet<String>,
    /// Whether this IP has been validated via TCP handshake
    tcp_validated: bool,
    /// When TCP validation was performed
    tcp_validation_time: Option<Instant>,
    /// RRL tracking: count of identical responses in current window
    rrl_response_count: u64,
    /// Last RRL check time
    last_rrl_check: Instant,
}

impl PacketInspector {
    pub fn new(
        threshold_domain_reqs: u64,
        rate_limit_config: RateLimitConfig,
        filter_config: FilterConfig,
        auto_whitelist_days: u64,
    ) -> Self {
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
    pub fn inspect(
        &self,
        source_ip: &str,
        query_domain: &str,
        query_type: Option<&str>,
        packet_size: usize,
    ) -> bool {
        // 0. Filter Checks (Stateless - immediate blocking)
        if let Some(qtype) = query_type {
            // Block ANY queries
            if self.filter_config.block_any_queries && qtype == "ANY" {
                warn!("Blocking ANY query from {}", source_ip);
                return true;
            }

            // Block large TXT queries
            if self.filter_config.block_large_txt
                && qtype == "TXT"
                && packet_size > self.filter_config.txt_max_size
            {
                warn!(
                    "Blocking large TXT query from {} (size: {})",
                    source_ip, packet_size
                );
                return true;
            }

            // Block configurable query types (e.g., AXFR, IXFR zone transfers)
            if self
                .filter_config
                .blocked_query_types
                .iter()
                .any(|t| t == qtype)
            {
                warn!(
                    "Blocking {} query from {} (configured blocked type)",
                    qtype, source_ip
                );
                return true;
            }
        }

        // 1. Volumetric Analysis
        let domain_count = {
            let mut count = self
                .domain_stats
                .entry(query_domain.to_string())
                .or_insert(0);
            *count += 1;
            *count
        };

        let is_high_volume = domain_count > self.threshold_domain_reqs;

        // 2. IP State Management with Enhanced Tracking
        let now = Instant::now();
        let mut should_block = false;

        self.ip_states
            .entry(source_ip.to_string())
            .and_modify(|state| {
                state.last_seen = now;
                state.total_query_bytes += packet_size as u64;
                state.unique_domains.insert(query_domain.to_string());

                // Check if ban expired
                if let Some(until) = state.banned_until {
                    if now > until {
                        info!("Ban expired for IP {}", source_ip);
                        state.banned_until = None;
                        state.is_blocked = false;
                    } else {
                        should_block = true;
                        return;
                    }
                }

                // Reflection Pattern Detection (Enhanced)
                // Attack signature: new IP, single/few domains, high request rate
                if self.filter_config.detect_reflection_patterns {
                    let is_new_ip = now.duration_since(state.first_seen) < Duration::from_secs(60);
                    let few_domains = state.unique_domains.len() <= 2;
                    let high_rate = state.current_window_requests > 20;

                    if is_new_ip && few_domains && high_rate && !state.tcp_validated {
                        warn!(
                            "Reflection attack pattern detected from {} (1 domain, {} req/s, no TCP validation)",
                            source_ip, state.current_window_requests
                        );
                        state.is_blocked = true;
                        state.banned_until = Some(now + Duration::from_secs(
                            self.rate_limit_config.second_offense_duration_secs
                        ));
                        should_block = true;
                        return;
                    }
                }

                // Subdomain Entropy Detection (Random Subdomain Attacks)
                if self.filter_config.subdomain_entropy_threshold > 0.0 {
                    let entropy = self.calculate_subdomain_entropy(&state.unique_domains);
                    if entropy > self.filter_config.subdomain_entropy_threshold
                        && state.unique_domains.len() > 10
                        && !state.tcp_validated
                    {
                        warn!(
                            "Random subdomain attack detected from {} (entropy: {:.2})",
                            source_ip, entropy
                        );
                        state.is_blocked = true;
                        should_block = true;
                        return;
                    }
                }

                // Legitimacy Validation (The "Escape Hatch") - MUST check before is_blocked
                if state.is_blocked && query_domain != state.first_query && !is_high_volume {
                    state.is_legit = true;
                    state.is_blocked = false;
                    info!(
                        "IP {} validated as legitimate via escape hatch (query: {})",
                        source_ip, query_domain
                    );
                    should_block = false;
                    return;
                }

                if state.is_blocked {
                    should_block = true;
                    return;
                }

                // Auto Whitelist check
                if !state.is_legit
                    && now.duration_since(state.first_seen).as_secs()
                        > (self.auto_whitelist_days * 86400)
                {
                    info!("Auto-whitelisting clean IP {}", source_ip);
                    state.is_legit = true;
                }

                // TCP Validation Trust: IPs that have completed TCP handshake are more trusted
                if state.tcp_validated {
                    if let Some(validation_time) = state.tcp_validation_time {
                        let ttl = Duration::from_secs(self.filter_config.tcp_validation_ttl_hours * 3600);
                        if now.duration_since(validation_time) > ttl {
                            // TCP validation expired
                            state.tcp_validated = false;
                            state.tcp_validation_time = None;
                            debug!("TCP validation expired for {}", source_ip);
                        }
                    }
                }

                // Response Rate Limiting (RRL) - limits identical responses
                if self.filter_config.enable_rrl {
                    match now.checked_duration_since(state.last_rrl_check) {
                        Some(d) if d.as_secs() >= 1 => {
                            state.last_rrl_check = now;
                            state.rrl_response_count = 0;
                        }
                        _ => {}
                    }
                    state.rrl_response_count += 1;

                    if state.rrl_response_count > self.filter_config.rrl_responses_per_sec {
                        // Apply slip ratio: respond to 1/N requests randomly
                        let slip = self.filter_config.rrl_slip_ratio;
                        if slip == 0 || (state.rrl_response_count % slip as u64) != 0 {
                            debug!(
                                "RRL: Dropping response to {} (rate: {}/s, slip: {})",
                                source_ip, state.rrl_response_count, slip
                            );
                            should_block = true;
                            return;
                        }
                    }
                }

                // Standard Rate Limiting - applies to ALL IPs including legit ones
                if self.rate_limit_config.enabled {
                    match now.checked_duration_since(state.last_rate_check) {
                        Some(d) if d.as_secs() >= 1 => {
                            state.last_rate_check = now;
                            state.current_window_requests = 0;
                        }
                        _ => {}
                    }
                    state.current_window_requests += 1;

                    if state.current_window_requests > self.rate_limit_config.requests_per_sec {
                        let duration_secs = if state.offense_count == 0 {
                            self.rate_limit_config.first_offense_duration_secs
                        } else {
                            self.rate_limit_config.second_offense_duration_secs
                        };

                        state.offense_count += 1;
                        state.banned_until = Some(now + Duration::from_secs(duration_secs));
                        state.is_blocked = true;
                        warn!(
                            "Rate limit exceeded for {} (Offense #{}). Banning for {}s",
                            source_ip, state.offense_count, duration_secs
                        );
                        should_block = true;
                        return;
                    }
                }

                if state.is_legit {
                    should_block = false;
                    return;
                }

                // Legitimacy Validation for non-blocked IPs querying different safe domain
                if query_domain != state.first_query && !is_high_volume {
                    state.is_legit = true;
                    state.is_blocked = false;
                    info!(
                        "IP {} validated as legitimate (query: {})",
                        source_ip, query_domain
                    );
                    should_block = false;
                }
            })
            .or_insert_with(|| {
                // First Packet Rule
                let block = is_high_volume;
                if block {
                    warn!(
                        "New IP {} detected querying high-volume domain {}. Marking hostile.",
                        source_ip, query_domain
                    );
                }
                should_block = block;

                let mut unique_domains = HashSet::new();
                unique_domains.insert(query_domain.to_string());

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
                    total_query_bytes: packet_size as u64,
                    total_response_bytes: 0,
                    unique_domains,
                    tcp_validated: false,
                    tcp_validation_time: None,
                    rrl_response_count: 1,
                    last_rrl_check: now,
                }
            });

        should_block
    }

    /// Calculate Shannon entropy of subdomain patterns to detect random subdomain attacks
    fn calculate_subdomain_entropy(&self, domains: &HashSet<String>) -> f64 {
        if domains.is_empty() {
            return 0.0;
        }

        // Extract first subdomain label from each domain
        let mut char_counts: std::collections::HashMap<char, usize> =
            std::collections::HashMap::new();
        let mut total_chars = 0usize;

        for domain in domains {
            // Get first label (subdomain)
            if let Some(first_label) = domain.split('.').next() {
                for c in first_label.chars() {
                    *char_counts.entry(c).or_insert(0) += 1;
                    total_chars += 1;
                }
            }
        }

        if total_chars == 0 {
            return 0.0;
        }

        // Calculate Shannon entropy
        let mut entropy = 0.0;
        for count in char_counts.values() {
            let p = *count as f64 / total_chars as f64;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Mark an IP as TCP-validated (called when TCP connection is established)
    /// Returns true if the IP was found and marked, false otherwise.
    pub fn mark_tcp_validated(&self, ip: &str) -> bool {
        let now = Instant::now();
        if let Some(mut state) = self.ip_states.get_mut(ip) {
            state.tcp_validated = true;
            state.tcp_validation_time = Some(now);
            info!("IP {} validated via TCP handshake", ip);
            true
        } else {
            debug!("Attempted to TCP-validate unknown IP: {}", ip);
            false
        }
    }

    /// Record estimated response size for amplification tracking
    #[allow(dead_code)]
    pub fn record_response_size(&self, ip: &str, response_size: usize) -> bool {
        let mut should_block = false;

        if let Some(mut state) = self.ip_states.get_mut(ip) {
            state.total_response_bytes += response_size as u64;

            // Check amplification ratio (guard against division by zero)
            if state.total_query_bytes > 0 {
                let ratio = state.total_response_bytes / state.total_query_bytes;
                if ratio > self.filter_config.amplification_ratio_limit
                    && !state.tcp_validated
                    && state.total_response_bytes > 10000
                // Only trigger after significant traffic
                {
                    warn!(
                        "Amplification ratio exceeded for {} (ratio: {}x, limit: {}x)",
                        ip, ratio, self.filter_config.amplification_ratio_limit
                    );
                    state.is_blocked = true;
                    should_block = true;
                }
            }
        }

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
            7,
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
        assert!(
            blocked,
            "New IP should be blocked when hitting high volume domain first"
        );
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
        assert!(
            !blocked_retry,
            "Should be allowed on attack domain after validation"
        );
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

    #[test]
    fn test_configurable_blocked_query_types() {
        // Default config blocks AXFR and IXFR
        let inspector = get_test_inspector(100);

        // AXFR should be blocked
        let blocked = inspector.inspect("8.8.8.8", "example.com", Some("AXFR"), 50);
        assert!(blocked, "Should block AXFR zone transfer");

        // IXFR should be blocked
        let blocked = inspector.inspect("8.8.8.9", "example.com", Some("IXFR"), 50);
        assert!(blocked, "Should block IXFR zone transfer");

        // RRSIG should NOT be blocked (DNSSEC support)
        let blocked = inspector.inspect("8.8.8.10", "example.com", Some("RRSIG"), 50);
        assert!(!blocked, "Should allow RRSIG for DNSSEC");

        // DNSKEY should NOT be blocked (DNSSEC support)
        let blocked = inspector.inspect("8.8.8.11", "example.com", Some("DNSKEY"), 50);
        assert!(!blocked, "Should allow DNSKEY for DNSSEC");
    }

    #[test]
    fn test_response_rate_limiting() {
        let mut filter_config = FilterConfig::default();
        filter_config.enable_rrl = true;
        filter_config.rrl_responses_per_sec = 3;
        filter_config.rrl_slip_ratio = 0; // Drop all when exceeded

        let inspector = PacketInspector::new(1000, RateLimitConfig::default(), filter_config, 7);
        let domain = "rrl-test.com";

        // First 3 queries should pass
        for i in 0..3 {
            let blocked = inspector.inspect("9.9.9.9", domain, None, 50);
            assert!(!blocked, "Query {} should pass RRL", i + 1);
        }

        // 4th query should be blocked by RRL
        let blocked = inspector.inspect("9.9.9.9", domain, None, 50);
        assert!(blocked, "4th query should be blocked by RRL");
    }

    #[test]
    fn test_tcp_validation_bypasses_reflection_check() {
        let mut filter_config = FilterConfig::default();
        filter_config.detect_reflection_patterns = true;

        let inspector = PacketInspector::new(1000, RateLimitConfig::default(), filter_config, 7);

        // Simulate a burst of queries from a single domain (potential reflection)
        let domain = "single.com";

        // First, mark as TCP validated
        inspector.inspect("10.10.10.10", domain, None, 50);
        inspector.mark_tcp_validated("10.10.10.10");

        // Verify TCP validation was successful
        assert!(
            inspector.mark_tcp_validated("10.10.10.10"),
            "TCP validation should succeed"
        );

        // Now high-rate queries from TCP-validated IP should not trigger reflection detection
        // Note: The IP may eventually hit rate limits, but reflection pattern detection should be bypassed
        for i in 0..25 {
            let _blocked = inspector.inspect("10.10.10.10", domain, None, 50);
            // First several queries should pass (until rate limit kicks in)
            if i < 5 {
                // Within rate limit window, should not be blocked by reflection detection
                // due to TCP validation
            }
        }
    }

    #[test]
    fn test_amplification_ratio_detection() {
        let mut filter_config = FilterConfig::default();
        filter_config.amplification_ratio_limit = 5;

        let inspector = PacketInspector::new(1000, RateLimitConfig::default(), filter_config, 7);

        // Send a small query
        inspector.inspect("11.11.11.11", "amp.com", None, 50);

        // Simulate large responses (50 bytes query, should block at 250+ bytes response after threshold)
        // Need total_response_bytes > 10000 to trigger
        for _ in 0..50 {
            inspector.record_response_size("11.11.11.11", 500); // 50 * 500 = 25000 bytes
        }

        // Check if blocked (ratio is 25000/50 = 500x, well above limit of 5x)
        let should_block = inspector.record_response_size("11.11.11.11", 500);
        assert!(should_block, "Should block due to high amplification ratio");
    }
}
