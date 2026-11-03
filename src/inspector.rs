//! Static file inspection — look inside a suspect file without running it.
//!
//! * SHA-256 digest (identity / threat-intel lookups)
//! * Shannon entropy (packed/encrypted payload detection)
//! * Embedded IOC extraction (Discord webhooks, http(s) C2 URLs)

use anyhow::{Context, Result};
use regex::bytes::Regex;
use sha2::{Digest, Sha256};
use std::io::Read;
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
    let mut counts = [0u64; 256];
    count_bytes(&mut counts, data);
    entropy_from_counts(&counts, data.len() as u64)
}

fn count_bytes(counts: &mut [u64; 256], data: &[u8]) {
    for &b in data {
        counts[b as usize] += 1;
    }
}

fn entropy_from_counts(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let len = total as f64;
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

/// Bytes read per chunk when streaming a file.
const CHUNK: usize = 64 * 1024;
/// Bytes carried from one window into the next so an IOC split across a chunk
/// boundary is still matched whole. Longer than any URL worth reporting.
const OVERLAP: usize = 4 * 1024;

/// Collects IOCs over successive, overlapping windows of a byte stream.
#[derive(Default)]
struct IocCollector {
    webhooks: Vec<String>,
    urls: Vec<String>,
    /// Absolute offset where the last accepted match of each kind ended, so
    /// the re-read overlap never yields the tail of a match as a new one.
    webhook_end: u64,
    url_end: u64,
}

impl IocCollector {
    /// Scan `window`, which starts at absolute offset `base`. Unless `last`,
    /// matches starting in its final [`OVERLAP`] bytes are left for the next
    /// window (which re-reads those bytes), so none is reported truncated.
    fn feed(&mut self, window: &[u8], base: u64, last: bool) {
        let limit = if last { window.len() } else { window.len().saturating_sub(OVERLAP) };
        for m in webhook_re().find_iter(window) {
            if m.start() >= limit {
                break;
            }
            if base + (m.start() as u64) < self.webhook_end {
                continue;
            }
            self.webhook_end = base + m.end() as u64;
            if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                let s = s.to_string();
                if !self.webhooks.contains(&s) {
                    self.webhooks.push(s);
                }
            }
        }
        for m in url_re().find_iter(window) {
            if m.start() >= limit {
                break;
            }
            if base + (m.start() as u64) < self.url_end {
                continue;
            }
            self.url_end = base + m.end() as u64;
            if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                // Don't double-report webhooks as generic URLs.
                if self.webhooks.iter().any(|w| s.starts_with(w.as_str())) {
                    continue;
                }
                let s = trim_url(s);
                if !s.is_empty() && !self.urls.contains(&s) {
                    self.urls.push(s);
                }
            }
        }
    }
}

/// Extract embedded webhooks and other URLs from raw bytes.
pub fn extract_iocs(data: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut c = IocCollector::default();
    c.feed(data, 0, true);
    (c.webhooks, c.urls)
}

/// Fill `buf` from `r` unless EOF comes first; returns the bytes read.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Stream a file through the IOC collector in fixed-size chunks; `on_chunk`
/// sees every byte exactly once (for hashing / entropy). Memory stays around
/// two chunks whatever the file size. Returns the byte count and the IOCs.
fn stream_file(path: &Path, mut on_chunk: impl FnMut(&[u8])) -> std::io::Result<(u64, IocCollector)> {
    let mut f = std::fs::File::open(path)?;
    let mut iocs = IocCollector::default();
    let mut buf = vec![0u8; CHUNK];
    let mut window: Vec<u8> = Vec::with_capacity(OVERLAP + CHUNK);
    let mut base = 0u64; // absolute offset of window[0]
    let mut size = 0u64;
    loop {
        let n = read_full(&mut f, &mut buf)?;
        let last = n < CHUNK;
        on_chunk(&buf[..n]);
        size += n as u64;
        window.extend_from_slice(&buf[..n]);
        iocs.feed(&window, base, last);
        if last {
            return Ok((size, iocs));
        }
        let drop = window.len().saturating_sub(OVERLAP);
        window.drain(..drop);
        base += drop as u64;
    }
}

/// Extract embedded webhooks and other URLs from a file, streaming it.
pub fn extract_iocs_from_file(path: &Path) -> std::io::Result<(Vec<String>, Vec<String>)> {
    let (_, c) = stream_file(path, |_| {})?;
    Ok((c.webhooks, c.urls))
}

/// Trim trailing punctuation that regex greedily captured from surrounding
/// bytes (common when a URL is embedded next to other data).
fn trim_url(s: &str) -> String {
    s.trim_end_matches(['.', ',', ')', ']', '"', '\'', '>', ';', ':'])
        .to_string()
}

/// Inspect a file on disk, streaming it in chunks so memory use does not grow
/// with the file size.
pub fn inspect(path: &Path) -> Result<Report> {
    let mut hasher = Sha256::new();
    let mut counts = [0u64; 256];
    let (size, iocs) = stream_file(path, |chunk| {
        hasher.update(chunk);
        count_bytes(&mut counts, chunk);
    })
    .with_context(|| format!("reading {}", path.display()))?;
    Ok(Report {
        path: path.display().to_string(),
        size,
        sha256: hex(&hasher.finalize()),
        entropy: entropy_from_counts(&counts, size),
        webhooks: iocs.webhooks,
        urls: iocs.urls,
    })
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

    #[test]
    fn streaming_matches_in_memory_across_chunk_boundaries() {
        // IOCs deliberately straddling the chunk and overlap boundaries.
        let mut data: Vec<u8> = (0..CHUNK * 3 + 777).map(|i| (i * 31 % 251) as u8).collect();
        let place = |data: &mut Vec<u8>, at: usize, s: &[u8]| data[at..at + s.len()].copy_from_slice(s);
        place(&mut data, CHUNK - 10, b" https://exo-api.tf/gate/abc ");
        place(&mut data, 2 * CHUNK - OVERLAP - 5, b" https://discord.com/api/webhooks/123456789012345678/Tok_en-1 ");
        place(&mut data, 3 * CHUNK - 3, b" https://evil.example/x?u=https://b.example ");

        for len in [data.len(), CHUNK * 2] {
            let data = &data[..len];
            let dir = tempfile::tempdir().unwrap();
            let f = dir.path().join("blob.bin");
            std::fs::write(&f, data).unwrap();

            let streamed = inspect(&f).unwrap();
            let whole = inspect_bytes(&f.display().to_string(), data);
            assert_eq!(whole.webhooks.len(), 1, "fixture must contain the webhook");
            assert!(whole.urls.iter().any(|u| u == "https://exo-api.tf/gate/abc"));
            assert_eq!(streamed.size, whole.size);
            assert_eq!(streamed.sha256, whole.sha256);
            assert!((streamed.entropy - whole.entropy).abs() < 1e-12);
            assert_eq!(streamed.webhooks, whole.webhooks);
            assert_eq!(streamed.urls, whole.urls);
            assert_eq!(extract_iocs_from_file(&f).unwrap(), (whole.webhooks, whole.urls));
        }
    }
}
