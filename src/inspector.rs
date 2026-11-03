//! Static file inspection — look inside a suspect file without running it.
//!
//! * SHA-256 digest (identity / threat-intel lookups)
//! * Shannon entropy (packed/encrypted payload detection)
//! * Embedded IOC extraction (Discord webhooks, http(s) C2 URLs)

use anyhow::{Context, Result};
use regex::bytes::Regex;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::OnceLock;

/// Result of inspecting a file.
#[derive(Debug, Clone)]
pub struct Report {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    /// Shannon entropy over the whole file, 0.0..=8.0 bits/byte.
    pub entropy: f64,
    /// Discord webhook URLs found embedded in the bytes.
    pub webhooks: Vec<String>,
    /// Other http(s) URLs found (potential C2 / exfil endpoints).
    pub urls: Vec<String>,
}

impl Report {
    /// Entropy above this strongly suggests packing/encryption (UPX, Themida,
    /// a custom cryptor). Plain code/text usually lands around 4.5–6.5.
    pub const HIGH_ENTROPY: f64 = 7.0;

    pub fn is_high_entropy(&self) -> bool {
        self.entropy >= Self::HIGH_ENTROPY
    }

    /// A short human verdict line.
    pub fn verdict(&self) -> String {
        let mut flags = Vec::new();
        if self.is_high_entropy() {
            flags.push(format!("PACKED/ENCRYPTED (entropy {:.2})", self.entropy));
        }
        if !self.webhooks.is_empty() {
            flags.push(format!("{} embedded Discord webhook(s)", self.webhooks.len()));
        }
        if !self.urls.is_empty() {
            flags.push(format!("{} embedded URL(s)", self.urls.len()));
        }
        if flags.is_empty() {
            "no static red flags".to_string()
        } else {
            flags.join("; ")
        }
    }
}

/// The canonical webhook URL pattern, shared with the `webhook` module so
/// detection and parsing never drift apart.
pub fn webhook_regex_str() -> &'static str {
    r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api(?:/v\d+)?/webhooks/\d+/[A-Za-z0-9_\-]+"
}

fn webhook_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Discord / Discordapp webhook URLs (ptb/canary subdomains included).
        Regex::new(webhook_regex_str()).expect("valid webhook regex")
    })
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+").expect("valid url regex")
    })
}

/// Shannon entropy in bits/byte over a byte slice.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

/// Extract embedded webhooks and other URLs from raw bytes.
pub fn extract_iocs(data: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut webhooks = Vec::new();
    for m in webhook_re().find_iter(data) {
        if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
            let s = s.to_string();
            if !webhooks.contains(&s) {
                webhooks.push(s);
            }
        }
    }
    let mut urls = Vec::new();
    for m in url_re().find_iter(data) {
        if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
            // Don't double-report webhooks as generic URLs.
            if webhooks.iter().any(|w| s.starts_with(w.as_str())) {
                continue;
            }
            let s = trim_url(s);
            if !s.is_empty() && !urls.contains(&s) {
                urls.push(s);
            }
        }
    }
    (webhooks, urls)
}

/// Trim trailing punctuation that regex greedily captured from surrounding
/// bytes (common when a URL is embedded next to other data).
fn trim_url(s: &str) -> String {
    s.trim_end_matches(['.', ',', ')', ']', '"', '\'', '>', ';', ':'])
        .to_string()
}

/// Inspect a file on disk. Reads the whole file into memory; intended for
/// executables/documents, not multi-gigabyte blobs.
pub fn inspect(path: &Path) -> Result<Report> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(inspect_bytes(&path.display().to_string(), &data))
}

/// Inspect in-memory bytes (used by disk/temp scanners that already hold data).
pub fn inspect_bytes(path: &str, data: &[u8]) -> Report {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256 = hex(&hasher.finalize());
    let (webhooks, urls) = extract_iocs(data);
    Report {
        path: path.to_string(),
        size: data.len() as u64,
        sha256,
        entropy: shannon_entropy(data),
        webhooks,
        urls,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        // All-same byte => zero entropy.
        assert_eq!(shannon_entropy(&[0u8; 1000]), 0.0);
        // Every byte value equally => 8 bits.
        let uniform: Vec<u8> = (0..=255u16).cycle().take(256 * 4).map(|b| b as u8).collect();
        let h = shannon_entropy(&uniform);
        assert!((h - 8.0).abs() < 1e-9, "uniform entropy was {h}");
    }

    #[test]
    fn plain_text_is_mid_entropy() {
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(50);
        let h = shannon_entropy(text.as_bytes());
        assert!(h > 3.5 && h < 5.5, "english text entropy {h}");
    }

    #[test]
    fn known_sha256() {
        // SHA-256("abc")
        let r = inspect_bytes("mem", b"abc");
        assert_eq!(
            r.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(r.size, 3);
    }

    #[test]
    fn finds_webhook() {
        let blob = b"junk\x00\x01https://discord.com/api/webhooks/123456789012345678/AbCdEf_-gHiJkLmNoP more junk";
        let (wh, _urls) = extract_iocs(blob);
        assert_eq!(wh.len(), 1);
        assert!(wh[0].contains("/webhooks/123456789012345678/"));
    }

    #[test]
    fn finds_canary_webhook_and_dedups() {
        let blob = b"https://canary.discord.com/api/v10/webhooks/111/AAA https://canary.discord.com/api/v10/webhooks/111/AAA";
        let (wh, _) = extract_iocs(blob);
        assert_eq!(wh.len(), 1, "duplicates should collapse");
    }

    #[test]
    fn webhook_not_double_counted_as_url() {
        let blob = b"https://discord.com/api/webhooks/123456789012345678/tok http://evil.example/c2";
        let (wh, urls) = extract_iocs(blob);
        assert_eq!(wh.len(), 1);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "http://evil.example/c2");
    }

    #[test]
    fn trims_trailing_punctuation() {
        let blob = b"see http://evil.example/path).";
        let (_wh, urls) = extract_iocs(blob);
        assert_eq!(urls[0], "http://evil.example/path");
    }
}
