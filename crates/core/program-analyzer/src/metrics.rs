//! Metrics and observability module
//!
//! Provides instrumentation for monitoring analysis performance and health.
//!
//! # Thread-safety
//!
//! The previous implementation used `RwLock<HashMap<String, AtomicU64>>` with a
//! read-then-write pattern for counter insertion. This pattern has a TOCTOU race:
//! two threads can both observe a key is absent under the read lock, both upgrade
//! to a write lock, and both insert a new `AtomicU64` for the same name. The
//! second insert silently resets the first thread's increments to zero.
//!
//! This is replaced with `DashMap`, a concurrent hash map that performs
//! fine-grained per-shard locking. The `entry().or_insert_with()` operation is
//! atomic within the shard, eliminating the race entirely.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Global metrics registry
pub static METRICS: once_cell::sync::Lazy<MetricsRegistry> =
    once_cell::sync::Lazy::new(MetricsRegistry::new);

/// Registry for all metrics
pub struct MetricsRegistry {
    counters: DashMap<String, AtomicU64>,
    histograms: DashMap<String, HistogramData>,
    start_time: Instant,
}

/// Histogram data for latency tracking
#[derive(Default)]
pub struct HistogramData {
    count: AtomicU64,
    sum_ms: AtomicU64,
    min_ms: AtomicU64,
    max_ms: AtomicU64,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
            histograms: DashMap::new(),
            start_time: Instant::now(),
        }
    }

    /// Increment a counter by 1.
    pub fn inc(&self, name: &str) {
        self.inc_by(name, 1);
    }

    /// Increment a counter by a specific amount.
    ///
    /// The `entry().or_insert_with()` on DashMap is atomic within the shard:
    /// if two threads race to insert the same key, exactly one wins and the
    /// other sees the already-inserted value. Both `fetch_add` calls then
    /// operate on the same `AtomicU64`.
    pub fn inc_by(&self, name: &str, amount: u64) {
        self.counters
            .entry(name.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(amount, Ordering::Relaxed);
    }

    /// Record a duration observation.
    pub fn observe(&self, name: &str, duration: Duration) {
        let ms = duration.as_millis() as u64;
        let hist = self.histograms
            .entry(name.to_string())
            .or_insert_with(|| HistogramData {
                count: AtomicU64::new(0),
                sum_ms: AtomicU64::new(0),
                min_ms: AtomicU64::new(u64::MAX),
                max_ms: AtomicU64::new(0),
            });
        hist.count.fetch_add(1, Ordering::Relaxed);
        hist.sum_ms.fetch_add(ms, Ordering::Relaxed);
        hist.min_ms.fetch_min(ms, Ordering::Relaxed);
        hist.max_ms.fetch_max(ms, Ordering::Relaxed);
    }

    /// Time a closure and record the duration.
    pub fn time<F, T>(&self, name: &str, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        let start = Instant::now();
        let result = f();
        self.observe(name, start.elapsed());
        result
    }

    /// Get current counter value.
    pub fn get_counter(&self, name: &str) -> u64 {
        self.counters
            .get(name)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get histogram statistics.
    pub fn get_histogram_stats(&self, name: &str) -> Option<HistogramStats> {
        self.histograms.get(name).map(|h| {
            let count = h.count.load(Ordering::Relaxed);
            let sum = h.sum_ms.load(Ordering::Relaxed);
            HistogramStats {
                count,
                sum_ms: sum,
                avg_ms: if count > 0 { sum / count } else { 0 },
                min_ms: h.min_ms.load(Ordering::Relaxed),
                max_ms: h.max_ms.load(Ordering::Relaxed),
            }
        })
    }

    /// Get uptime.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Export all metrics as JSON.
    pub fn export_json(&self) -> serde_json::Value {
        let counters: std::collections::HashMap<String, u64> = self
            .counters
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().load(Ordering::Relaxed)))
            .collect();

        let histograms: std::collections::HashMap<String, serde_json::Value> = self
            .histograms
            .iter()
            .map(|entry| {
                let h = entry.value();
                let count = h.count.load(Ordering::Relaxed);
                let sum = h.sum_ms.load(Ordering::Relaxed);
                (
                    entry.key().clone(),
                    serde_json::json!({
                        "count": count,
                        "sum_ms": sum,
                        "avg_ms": if count > 0 { sum / count } else { 0 },
                        "min_ms": h.min_ms.load(Ordering::Relaxed),
                        "max_ms": h.max_ms.load(Ordering::Relaxed),
                    }),
                )
            })
            .collect();

        serde_json::json!({
            "uptime_seconds": self.uptime().as_secs(),
            "counters": counters,
            "histograms": histograms,
        })
    }

    /// Reset all metrics.
    pub fn reset(&self) {
        for entry in self.counters.iter() {
            entry.value().store(0, Ordering::Relaxed);
        }
        for entry in self.histograms.iter() {
            let h = entry.value();
            h.count.store(0, Ordering::Relaxed);
            h.sum_ms.store(0, Ordering::Relaxed);
            h.min_ms.store(u64::MAX, Ordering::Relaxed);
            h.max_ms.store(0, Ordering::Relaxed);
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics from a histogram
#[derive(Debug, Clone)]
pub struct HistogramStats {
    pub count: u64,
    pub sum_ms: u64,
    pub avg_ms: u64,
    pub min_ms: u64,
    pub max_ms: u64,
}

/// Metric names used throughout the codebase
pub mod metric_names {
    pub const FILES_ANALYZED: &str = "files_analyzed_total";
    pub const FINDINGS_DETECTED: &str = "findings_detected_total";
    pub const PARSE_ERRORS: &str = "parse_errors_total";
    pub const ANALYSIS_DURATION: &str = "analysis_duration_ms";
    pub const PATTERN_CHECKS: &str = "pattern_checks_total";
    pub const LLM_CALLS: &str = "llm_api_calls_total";
    pub const LLM_TOKENS: &str = "llm_tokens_used_total";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_increment() {
        let registry = MetricsRegistry::new();
        registry.inc("test_counter");
        registry.inc("test_counter");
        registry.inc_by("test_counter", 5);

        assert_eq!(registry.get_counter("test_counter"), 7);
    }

    #[test]
    fn test_histogram_observation() {
        let registry = MetricsRegistry::new();
        registry.observe("test_latency", Duration::from_millis(100));
        registry.observe("test_latency", Duration::from_millis(200));
        registry.observe("test_latency", Duration::from_millis(150));

        let stats = registry.get_histogram_stats("test_latency").unwrap();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.sum_ms, 450);
        assert_eq!(stats.avg_ms, 150);
        assert_eq!(stats.min_ms, 100);
        assert_eq!(stats.max_ms, 200);
    }

    #[test]
    fn test_time_function() {
        let registry = MetricsRegistry::new();

        let result = registry.time("test_op", || {
            std::thread::sleep(Duration::from_millis(10));
            42
        });

        assert_eq!(result, 42);

        let stats = registry.get_histogram_stats("test_op").unwrap();
        assert_eq!(stats.count, 1);
        assert!(stats.sum_ms >= 10);
    }

    #[test]
    fn test_export_json() {
        let registry = MetricsRegistry::new();
        registry.inc("counter1");
        registry.observe("hist1", Duration::from_millis(100));

        let json = registry.export_json();
        assert!(json["counters"]["counter1"].as_u64().unwrap() >= 1);
        assert!(json["histograms"]["hist1"]["count"].as_u64().unwrap() >= 1);
    }

    /// Regression test for the TOCTOU race in the old RwLock pattern.
    ///
    /// Spawns 50 threads each incrementing the same counter 100 times.
    /// With the old implementation, concurrent inserts could create duplicate
    /// AtomicU64 entries, silently resetting prior increments. The final value
    /// must equal exactly 5000.
    #[test]
    fn test_concurrent_increment_no_race() {
        use std::sync::Arc;

        let registry = Arc::new(MetricsRegistry::new());
        let mut handles = Vec::new();

        for _ in 0..50 {
            let r = Arc::clone(&registry);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    r.inc("race_counter");
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(registry.get_counter("race_counter"), 5000);
    }
}
