//! IOC signature database: known C2 domains, malicious ports, and stealer
//! process indicators. Ships with an embedded baseline that can be overridden
//! or extended from a user-supplied JSON file (signature updates).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// The baseline signature set, compiled into the binary.
const EMBEDDED: &str = include_str!("signatures/default.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDb {
    pub version: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub c2_domains: Vec<String>,
    /// Anonymous file/paste hosts that stealers abuse to upload stolen data.
    /// Legitimate apps rarely need these, so they are safe to null-route.
    #[serde(default)]
    pub exfil_hosts: Vec<String>,
    #[serde(default)]
    pub c2_ports: Vec<u16>,
    #[serde(default)]
    pub stealer_process_names: Vec<String>,
    #[serde(default)]
    pub stealer_name_fragments: Vec<String>,
}

impl ThreatDb {
    /// Load the embedded baseline. Infallible in practice (the JSON is
    /// validated at build via tests), but returns Result for symmetry.
    pub fn embedded() -> Result<Self> {
        serde_json::from_str(EMBEDDED).context("parsing embedded signature set")
    }

    /// Load from a user file, falling back to the embedded baseline if the
    /// file is missing. A present-but-invalid file is an error (don't run
    /// silently unprotected on a typo).
    pub fn load_or_embedded(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) if p.exists() => {
                let raw = std::fs::read_to_string(p)
                    .with_context(|| format!("reading signatures {}", p.display()))?;
                serde_json::from_str(&raw)
                    .with_context(|| format!("parsing signatures {}", p.display()))
            }
            _ => Self::embedded(),
        }
    }

    /// Merge another set into this one (user set extends the baseline).
    pub fn merge(&mut self, other: &ThreatDb) {
        extend_unique(&mut self.c2_domains, &other.c2_domains);
        extend_unique(&mut self.exfil_hosts, &other.exfil_hosts);
        extend_unique(&mut self.stealer_process_names, &other.stealer_process_names);
        extend_unique(&mut self.stealer_name_fragments, &other.stealer_name_fragments);
        for p in &other.c2_ports {
            if !self.c2_ports.contains(p) {
                self.c2_ports.push(*p);
            }
        }
    }

    /// Does this process (by file name) match a stealer indicator?
    /// Matches an exact known name or a suspicious fragment, case-insensitively.
    pub fn is_suspicious_process(&self, process_name: &str) -> Option<String> {
        let lc = process_name.to_ascii_lowercase();
        if self
            .stealer_process_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case(&lc))
        {
            return Some(format!("known stealer binary '{process_name}'"));
        }
        for frag in &self.stealer_name_fragments {
            if lc.contains(&frag.to_ascii_lowercase()) {
                return Some(format!("name contains stealer fragment '{frag}'"));
            }
        }
        None
    }

    /// Is this host a known C2 domain (exact or subdomain match)?
    pub fn is_c2_domain(&self, host: &str) -> bool {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        self.c2_domains.iter().any(|d| {
            let d = d.to_ascii_lowercase();
            h == d || h.ends_with(&format!(".{d}"))
        })
    }

    /// Set of all C2 domains for bulk operations (hosts-file writing).
    pub fn c2_domain_set(&self) -> HashSet<String> {
        self.c2_domains
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .collect()
    }

    /// Every domain that should be blocked outbound: C2 command servers plus
    /// anonymous exfil/upload hosts. This is what the hosts null-route writes.
    pub fn all_block_domains(&self) -> Vec<String> {
        let mut v = self.c2_domains.clone();
        for h in &self.exfil_hosts {
            if !v.iter().any(|x| x.eq_ignore_ascii_case(h)) {
                v.push(h.clone());
            }
        }
        v
    }
}

fn extend_unique(dst: &mut Vec<String>, src: &[String]) {
    for s in src {
        if !dst.iter().any(|x| x.eq_ignore_ascii_case(s)) {
            dst.push(s.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_parses() {
        let db = ThreatDb::embedded().expect("embedded signatures must parse");
        assert!(!db.c2_domains.is_empty());
        assert!(!db.c2_ports.is_empty());
        assert!(!db.version.is_empty());
    }

    #[test]
    fn process_matching() {
        let db = ThreatDb::embedded().unwrap();
        assert!(db.is_suspicious_process("grabber.exe").is_some());
        assert!(db.is_suspicious_process("GRABBER.EXE").is_some());
        assert!(db.is_suspicious_process("my-grabber-tool").is_some()); // fragment
        assert!(db.is_suspicious_process("chrome.exe").is_none());
        assert!(db.is_suspicious_process("explorer.exe").is_none());
    }

    #[test]
    fn c2_domain_matching() {
        let db = ThreatDb::embedded().unwrap();
        assert!(db.is_c2_domain("exo-api.tf"));
        assert!(db.is_c2_domain("sub.exo-api.tf")); // subdomain
        assert!(db.is_c2_domain("EXO-API.TF")); // case
        assert!(db.is_c2_domain("exo-api.tf.")); // trailing dot
        assert!(!db.is_c2_domain("exo-api.tfood")); // not a suffix match
        assert!(!db.is_c2_domain("google.com"));
    }

    #[test]
    fn merge_dedups() {
        let mut a = ThreatDb::embedded().unwrap();
        let before = a.c2_domains.len();
        let b = ThreatDb {
            version: "x".into(),
            note: String::new(),
            c2_domains: vec!["exo-api.tf".into(), "newbad.example".into()],
            exfil_hosts: vec![],
            c2_ports: vec![4444, 9001],
            stealer_process_names: vec![],
            stealer_name_fragments: vec![],
        };
        a.merge(&b);
        assert_eq!(a.c2_domains.len(), before + 1); // only newbad added
        assert!(a.c2_domains.iter().any(|d| d == "newbad.example"));
        assert!(a.c2_ports.contains(&9001));
    }
}
