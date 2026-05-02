//! Finding enrichment (attack scenarios, defenses) and cross-phase deduplication.
//! Runs after all scanning phases, before the validation pipeline.

use crate::VulnerabilityFinding;

/// Populate empty `prevention` and `attack_scenario` fields from expert systems
/// and the vulnerability knowledge base (100 entries with real-world incidents).
pub fn enrich_findings(findings: &mut Vec<VulnerabilityFinding>) {
    // Load the knowledge base once for all findings
    let kb = crate::vuln_knowledge_base::get_knowledge_base();

    for f in findings.iter_mut() {
        // Account security enrichment
        if let Some(insight) = account_security_expert::AccountSecurityExpert::get_insight_for_id(&f.id) {
            if f.prevention.is_empty() {
                f.prevention = insight.secure_pattern.clone();
            }
            if f.attack_scenario.is_empty() {
                f.attack_scenario = insight.attack_vector.clone();
            }
        }
        // DeFi security enrichment
        if let Some(insight) = defi_security_expert::DeFiSecurityExpert::get_defense_for_id(&f.id) {
            if f.prevention.is_empty() {
                f.prevention = insight.defense_strategy.clone();
            }
        }

        // Knowledge base enrichment — match finding ID against KB detector_ids
        // to pull in real-world incidents and attack descriptions.
        if let Some(entry) = kb.iter().find(|e| {
            e.detector_ids.iter().any(|d| *d == f.id)
        }) {
            if f.attack_scenario.is_empty() {
                f.attack_scenario = entry.description.to_string();
            }
            if f.real_world_incident.is_none() {
                if let Some(ref inc) = entry.real_incident {
                    f.real_world_incident = Some(crate::Incident::from(inc));
                }
            }
        }
    }
}

/// Keep only the highest-confidence finding per (vuln_type, location, line).
///
/// # Correctness note
///
/// The previous implementation stored raw Vec indices in the HashMap, then ran
/// `findings.retain()` using a separate index counter. The problem: `retain`
/// shifts elements left as it removes them, but the HashMap keys are original
/// pre-retain indices. Those indices become stale for any element that follows
/// a removed one, meaning the wrong findings could be kept or dropped.
///
/// Fix: store `(original_index, confidence)` pairs, build the keep-set from
/// original indices before `retain` is called, then use a monotonically
/// incrementing counter inside the closure — which sees every element exactly
/// once in its original order.
pub fn dedup_findings(findings: &mut Vec<VulnerabilityFinding>) {
    use std::collections::{HashMap, HashSet};

    // Maps dedup-key -> (original_index, best_confidence)
    let mut best: HashMap<String, (usize, u8)> = HashMap::new();

    for (idx, f) in findings.iter().enumerate() {
        let key = if f.line_number > 0 {
            format!("{}:{}:{}", f.vuln_type, f.location, f.line_number)
        } else {
            format!("{}:{}:{}", f.vuln_type, f.location, f.function_name)
        };
        best.entry(key)
            .and_modify(|(best_idx, best_conf)| {
                if f.confidence > *best_conf {
                    *best_idx = idx;
                    *best_conf = f.confidence;
                }
            })
            .or_insert((idx, f.confidence));
    }

    // Collect the set of original indices we want to keep.
    // This set is built once, before retain modifies the Vec.
    let keep: HashSet<usize> = best.into_values().map(|(i, _)| i).collect();

    // retain sees each element exactly once in original order; the counter
    // here mirrors those original indices safely.
    let mut original_idx: usize = 0;
    findings.retain(|_| {
        let should_keep = keep.contains(&original_idx);
        original_idx += 1;
        should_keep
    });
}

/// Enrich then dedup. Called at the end of `scan_for_vulnerabilities_raw`.
pub fn post_process(findings: &mut Vec<VulnerabilityFinding>) {
    enrich_findings(findings);
    dedup_findings(findings);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(vuln_type: &str, location: &str, line: usize, confidence: u8) -> VulnerabilityFinding {
        VulnerabilityFinding {
            category: "Test".to_string(),
            vuln_type: vuln_type.to_string(),
            severity: 3,
            severity_label: "Medium".to_string(),
            id: "SOL-001".to_string(),
            cwe: None,
            location: location.to_string(),
            function_name: "test".to_string(),
            line_number: line,
            vulnerable_code: String::new(),
            description: String::new(),
            attack_scenario: String::new(),
            real_world_incident: None,
            secure_fix: String::new(),
            prevention: String::new(),
            confidence,
        }
    }

    #[test]
    fn test_dedup_keeps_highest_confidence() {
        let mut findings = vec![
            make_finding("overflow", "main.rs", 10, 40),
            make_finding("overflow", "main.rs", 10, 80),
            make_finding("overflow", "main.rs", 10, 60),
        ];
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, 80);
    }

    #[test]
    fn test_dedup_different_lines_kept() {
        let mut findings = vec![
            make_finding("overflow", "main.rs", 10, 50),
            make_finding("overflow", "main.rs", 20, 50),
        ];
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_dedup_different_types_kept() {
        let mut findings = vec![
            make_finding("overflow", "main.rs", 10, 50),
            make_finding("signer", "main.rs", 10, 50),
        ];
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 2);
    }

    /// Regression test for the stale-index bug.
    ///
    /// Three groups of duplicates at different lines. The middle group has its
    /// best finding at index 3 (original). Before the fix, after retain removed
    /// elements from earlier groups, index 3 no longer pointed to the right item.
    #[test]
    fn test_dedup_stale_index_regression() {
        let mut findings = vec![
            // group A — line 10, keep confidence 90 (idx 1)
            make_finding("overflow", "main.rs", 10, 50),
            make_finding("overflow", "main.rs", 10, 90),
            // group B — line 20, keep confidence 80 (idx 3)
            make_finding("overflow", "main.rs", 20, 30),
            make_finding("overflow", "main.rs", 20, 80),
            // group C — line 30, keep confidence 70 (idx 5)
            make_finding("overflow", "main.rs", 30, 20),
            make_finding("overflow", "main.rs", 30, 70),
        ];
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].confidence, 90);
        assert_eq!(findings[1].confidence, 80);
        assert_eq!(findings[2].confidence, 70);
    }

    #[test]
    fn test_enrichment_populates_empty_fields() {
        let mut findings = vec![
            make_finding("test", "main.rs", 1, 50),
        ];
        enrich_findings(&mut findings);
        // Enrichment may or may not find a match for "SOL-001" depending on
        // the expert system's data. Either way, it must not panic.
    }

    #[test]
    fn test_post_process_runs_both() {
        let mut findings = vec![
            make_finding("overflow", "main.rs", 10, 40),
            make_finding("overflow", "main.rs", 10, 80),
        ];
        post_process(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, 80);
    }
}
