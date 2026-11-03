//! Deep disk / temp scanner — hunt for embedded exfiltration hooks (Discord
//! webhooks, C2 URLs) left behind in files across the system.

use crate::inspector;
use crate::log::EventLog;
use crate::threat_db::ThreatDb;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// A file that contains at least one embedded IOC.
#[derive(Debug, Clone)]
pub struct Hit {
    pub path: String,
    pub webhooks: Vec<String>,
    pub c2_urls: Vec<String>,
}

/// Scanner configuration.
pub struct ScanConfig {
    /// Skip files larger than this (bytes). Default 32 MiB.
    pub max_file_size: u64,
    /// Maximum directory depth.
    pub max_depth: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self { max_file_size: 32 * 1024 * 1024, max_depth: 12 }
    }
}

/// Sensible default scan roots per platform (where droppers stage payloads and
/// leave exfil hooks).
pub fn default_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            roots.push(PathBuf::from(appdata));
        }
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            roots.push(PathBuf::from(local));
        }
        if let Ok(temp) = std::env::var("TEMP") {
            roots.push(PathBuf::from(temp));
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let home = PathBuf::from(home);
            roots.push(home.join("Library/Caches"));
            roots.push(home.join("Downloads"));
            roots.push(home.join(".config"));
        }
        roots.push(PathBuf::from("/tmp"));
    }
    roots.retain(|p| p.exists());
    roots
}

/// Scan a single root, returning files that contain embedded IOCs.
pub fn scan_root(root: &Path, cfg: &ScanConfig, db: &ThreatDb, log: &EventLog) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut scanned = 0u64;
    for entry in WalkDir::new(root)
        .max_depth(cfg.max_depth)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        // Ask the file itself, not the directory listing: on Windows walkdir's
        // entry metadata comes from the directory, where NTFS may still show
        // 0 bytes for a file another process has open (e.g. a dropper still
        // writing its payload), and the file would be skipped as empty.
        let meta = match std::fs::metadata(entry.path()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.len() == 0 || meta.len() > cfg.max_file_size {
            continue;
        }
        // Streamed in chunks, so memory stays flat even near max_file_size.
        let (webhooks, urls) = match inspector::extract_iocs_from_file(entry.path()) {
            Ok(iocs) => iocs,
            Err(_) => continue, // locked / permission denied — skip quietly
        };
        scanned += 1;
        // Keep only webhooks, plus URLs whose host is a known C2 domain.
        let c2_urls: Vec<String> = urls
            .into_iter()
            .filter(|u| url_host(u).map(|h| db.is_c2_domain(&h)).unwrap_or(false))
            .collect();
        if webhooks.is_empty() && c2_urls.is_empty() {
            continue;
        }
        let path = entry.path().display().to_string();
        if !webhooks.is_empty() {
            log.alert(
                "scanner",
                format!("{} embedded webhook(s) in {path}", webhooks.len()),
            );
        }
        if !c2_urls.is_empty() {
            log.alert("scanner", format!("{} known-C2 URL(s) in {path}", c2_urls.len()));
        }
        hits.push(Hit { path, webhooks, c2_urls });
    }
    log.info("scanner", format!("scanned {scanned} file(s) under {}", root.display()));
    hits
}

/// Scan multiple roots.
pub fn scan_roots(roots: &[PathBuf], cfg: &ScanConfig, db: &ThreatDb, log: &EventLog) -> Vec<Hit> {
    let mut all = Vec::new();
    for r in roots {
        all.extend(scan_root(r, cfg, db, log));
    }
    all
}

/// Extract the host portion of an http(s) URL (cheap parser — no dep).
fn url_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let hostport = authority.rsplit('@').next()?; // strip userinfo
    let host = hostport.split(':').next()?; // strip port
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn host_parsing() {
        assert_eq!(url_host("https://exo-api.tf/path").as_deref(), Some("exo-api.tf"));
        assert_eq!(url_host("http://user:pw@evil.example:8080/x").as_deref(), Some("evil.example"));
        assert_eq!(url_host("https://sub.exo-api.tf").as_deref(), Some("sub.exo-api.tf"));
        assert_eq!(url_host("ftp://nope"), None);
    }

    #[test]
    fn finds_webhook_in_tree() {
        let dir = tempfile::tempdir().unwrap();
        let clean = dir.path().join("notes.txt");
        std::fs::write(&clean, b"just some harmless notes").unwrap();

        let dirty = dir.path().join("payload.bin");
        let mut f = std::fs::File::create(&dirty).unwrap();
        f.write_all(b"GET / HTTP\x00https://discord.com/api/webhooks/987654321098765432/ZzTok_-9")
            .unwrap();

        let db = ThreatDb::embedded().unwrap();
        let log = EventLog::new(false);
        let hits = scan_root(dir.path(), &ScanConfig::default(), &db, &log);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].path.ends_with("payload.bin"));
        assert_eq!(hits[0].webhooks.len(), 1);
    }

    #[test]
    fn finds_c2_url_only_for_known_domain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.bin"), b"beacon https://exo-api.tf/gate").unwrap();
        std::fs::write(dir.path().join("b.bin"), b"link https://github.com/foo").unwrap();

        let db = ThreatDb::embedded().unwrap();
        let log = EventLog::new(false);
        let hits = scan_root(dir.path(), &ScanConfig::default(), &db, &log);
        // Only the known-C2 file should hit; github.com is not flagged.
        assert_eq!(hits.len(), 1);
        assert!(hits[0].path.ends_with("a.bin"));
        assert_eq!(hits[0].c2_urls.len(), 1);
    }

    #[test]
    fn respects_size_cap() {
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big.bin");
        std::fs::write(&big, vec![0u8; 1024]).unwrap();
        let cfg = ScanConfig { max_file_size: 100, max_depth: 4 };
        let db = ThreatDb::embedded().unwrap();
        let log = EventLog::new(false);
        let hits = scan_root(dir.path(), &cfg, &db, &log);
        assert!(hits.is_empty());
    }
}
