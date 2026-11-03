//! Host-level C2 null-routing via the system hosts file.
//!
//! Known C2 domains are pointed at 0.0.0.0 so that even if malware is already
//! running, its callbacks resolve to nowhere. The entries live inside a clearly
//! delimited managed block, so we can add/remove them without touching the
//! user's own hosts entries, and restore cleanly ("DNS factory reset").

use crate::threat_db::ThreatDb;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const BEGIN: &str = "# >>> 667-SHIELD BEGIN (managed C2 null-route — do not edit inside) >>>";
const END: &str = "# <<< 667-SHIELD END <<<";

/// Platform hosts-file path.
pub fn hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        // %SystemRoot% is almost always C:\Windows.
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// Build the managed block text for the given domains (both IPv4 and IPv6
/// sinkholes, so a domain can't slip through over v6).
fn render_block(domains: &[String]) -> String {
    let mut s = String::new();
    s.push_str(BEGIN);
    s.push('\n');
    for d in domains {
        let d = d.trim().to_ascii_lowercase();
        if d.is_empty() {
            continue;
        }
        s.push_str(&format!("0.0.0.0 {d}\n"));
        s.push_str(&format!("0.0.0.0 www.{d}\n"));
        s.push_str(&format!("::  {d}\n"));
    }
    s.push_str(END);
    s.push('\n');
    s
}

/// Remove any existing managed block from hosts content, returning the content
/// without it. Idempotent and safe if no block is present.
fn strip_block(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut skipping = false;
    for line in content.lines() {
        let t = line.trim();
        if t == BEGIN {
            skipping = true;
            continue;
        }
        if t == END {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Compute the new hosts content with the managed block applied (or removed if
/// `domains` is empty). Pure function — the core of the module, unit-tested
/// without touching the real filesystem.
pub fn apply_to_content(existing: &str, domains: &[String]) -> String {
    let base = strip_block(existing);
    let base = base.trim_end_matches('\n');
    if domains.is_empty() {
        return format!("{base}\n");
    }
    format!("{base}\n\n{}", render_block(domains))
}

/// Count managed entries currently present in hosts content.
pub fn managed_domain_count(content: &str) -> usize {
    let mut n = 0;
    let mut inside = false;
    for line in content.lines() {
        let t = line.trim();
        if t == BEGIN {
            inside = true;
            continue;
        }
        if t == END {
            inside = false;
            continue;
        }
        if inside && t.starts_with("0.0.0.0 ") && !t.starts_with("0.0.0.0 www.") {
            n += 1;
        }
    }
    n
}

/// Path of the pristine-hosts backup kept next to the hosts file.
fn backup_path(path: &Path) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "hosts".into());
    path.with_file_name(format!("{name}.667shield.bak"))
}

/// Enable null-routing for all C2 domains in the DB. Writes the hosts file;
/// requires administrator/root privileges. Returns the number of domains routed.
/// On first enable it saves a pristine backup for the "DNS factory reset".
pub fn enable(db: &ThreatDb, path: &Path) -> Result<usize> {
    let existing = std::fs::read_to_string(path)
        .with_context(|| format!("reading hosts file {}", path.display()))?;
    // Save the pristine hosts (our block stripped) once, for factory reset.
    // Without it the reset would silently degrade, so don't go on without one.
    let bak = backup_path(path);
    if !bak.exists() {
        std::fs::write(&bak, strip_block(&existing))
            .with_context(|| format!("writing hosts backup {}", bak.display()))?;
    }
    let domains = db.all_block_domains();
    let updated = apply_to_content(&existing, &domains);
    write_atomic(path, &updated)?;
    Ok(domains.len())
}

/// Where [`factory_reset`] keeps the hosts file it replaced.
pub fn previous_path(path: &Path) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "hosts".into());
    path.with_file_name(format!("{name}.667shield.prev"))
}

/// DNS factory reset: restore the hosts file to its pristine backup if we have
/// one, otherwise just strip our managed block. Reversing all our changes —
/// including entries malware added since. Anything else added since (the
/// user's own edits too) is kept in [`previous_path`], whose path is returned.
pub fn factory_reset(path: &Path) -> Result<Option<PathBuf>> {
    let bak = backup_path(path);
    if bak.exists() {
        let content = std::fs::read_to_string(&bak)
            .with_context(|| format!("reading backup {}", bak.display()))?;
        let current = std::fs::read_to_string(path)
            .with_context(|| format!("reading hosts file {}", path.display()))?;
        let prev = previous_path(path);
        std::fs::write(&prev, current).with_context(|| format!("saving current hosts to {}", prev.display()))?;
        write_atomic(path, &content)?;
        let _ = std::fs::remove_file(&bak);
        Ok(Some(prev))
    } else {
        disable(path).map(|()| None)
    }
}

/// Remove the managed block entirely ("DNS factory reset").
pub fn disable(path: &Path) -> Result<()> {
    let existing = std::fs::read_to_string(path)
        .with_context(|| format!("reading hosts file {}", path.display()))?;
    let updated = apply_to_content(&existing, &[]);
    write_atomic(path, &updated)
}

/// Write via a temp file + rename where possible so a crash can't leave a
/// half-written hosts file. Falls back to direct write (e.g. cross-device).
fn write_atomic(path: &Path, content: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(".667-shield-hosts.tmp");
    if std::fs::write(&tmp, content).is_ok() && std::fs::rename(&tmp, path).is_ok() {
        return Ok(());
    }
    let _ = std::fs::remove_file(&tmp);
    std::fs::write(path, content).with_context(|| format!("writing hosts file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doms() -> Vec<String> {
        vec!["exo-api.tf".into(), "darkside.cy".into()]
    }

    #[test]
    fn apply_then_strip_roundtrips() {
        let original = "127.0.0.1 localhost\n255.255.255.255 broadcasthost\n";
        let with = apply_to_content(original, &doms());
        assert!(with.contains("0.0.0.0 exo-api.tf"));
        assert!(with.contains("0.0.0.0 www.darkside.cy"));
        assert!(with.contains(BEGIN) && with.contains(END));
        // User's own entries preserved.
        assert!(with.contains("127.0.0.1 localhost"));

        // Removing the block restores the original (modulo trailing newline).
        let without = apply_to_content(&with, &[]);
        assert!(!without.contains(BEGIN));
        assert!(without.contains("127.0.0.1 localhost"));
        assert!(!without.contains("exo-api.tf"));
    }

    #[test]
    fn reapply_is_idempotent() {
        let original = "127.0.0.1 localhost\n";
        let once = apply_to_content(original, &doms());
        let twice = apply_to_content(&once, &doms());
        assert_eq!(once, twice, "re-applying must not stack blocks");
        assert_eq!(once.matches(BEGIN).count(), 1);
    }

    #[test]
    fn counts_managed_domains() {
        let with = apply_to_content("127.0.0.1 localhost\n", &doms());
        assert_eq!(managed_domain_count(&with), 2);
        assert_eq!(managed_domain_count("127.0.0.1 localhost\n"), 0);
    }

    #[test]
    fn enable_disable_on_temp_file() {
        let db = ThreatDb::embedded().unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "127.0.0.1 localhost\n").unwrap();

        let n = enable(&db, tmp.path()).unwrap();
        assert_eq!(n, db.all_block_domains().len());
        let after = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(after.contains("0.0.0.0 exo-api.tf"));
        assert!(after.contains("0.0.0.0 gofile.io")); // exfil host also blocked

        disable(tmp.path()).unwrap();
        let after = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(!after.contains("exo-api.tf"));
        assert!(after.contains("127.0.0.1 localhost"));
    }

    #[test]
    fn factory_reset_keeps_replaced_file() {
        let db = ThreatDb::embedded().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\n").unwrap();

        enable(&db, &hosts).unwrap();
        // Edits made while the shield is on: one by the user, one by malware.
        let mut c = std::fs::read_to_string(&hosts).unwrap();
        c.push_str("10.0.0.5 nas.home\n0.0.0.0 antivirus.example\n");
        std::fs::write(&hosts, c).unwrap();

        let prev = factory_reset(&hosts).unwrap().expect("backup was restored");
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), "127.0.0.1 localhost\n");
        let kept = std::fs::read_to_string(&prev).unwrap();
        assert!(kept.contains("10.0.0.5 nas.home"), "user's edits must be recoverable");

        // No backup left: a second reset only strips our block.
        assert_eq!(factory_reset(&hosts).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn enable_fails_without_backup_and_leaves_hosts_alone() {
        use std::os::unix::fs::PermissionsExt;
        let db = ThreatDb::embedded().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\n").unwrap();
        // Hosts itself is writable but nothing new can be created beside it, so
        // the backup can't be saved (the direct-write fallback still could).
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

        let r = enable(&db, &hosts);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(r.is_err());
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), "127.0.0.1 localhost\n");
    }
}
