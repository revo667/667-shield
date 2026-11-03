//! Deception / "vaccination" layer.
//!
//! Many commodity stealers refuse to run if they think they're inside a malware
//! analyst's sandbox or virtual machine — they check for tell-tale VM artifacts
//! and self-terminate to avoid being studied. This layer plants a small set of
//! those artifacts so that such malware bails out on a real machine too.
//!
//! Properties, by design:
//!   * **Windows only** — these checks are Windows-specific.
//!   * **Reversible** — every marker is removed again when the layer is turned
//!     off. We record what we created and remove only that: keys we created are
//!     deleted, pre-existing keys keep everything but our value, and values that
//!     already existed (e.g. a real VMware install) are never touched.
//!   * **Off by default** — it is best-effort, not a guarantee, and some VM
//!     markers can trip game anti-cheat (e.g. Roblox). The caller surfaces that
//!     warning before enabling it.

use crate::log::EventLog;
#[cfg(not(windows))]
use anyhow::anyhow;
use anyhow::Result;

/// A registry marker: (key, value name, value type, value data). Chosen from
/// classic VM-presence checks that live under SOFTWARE (not hardware/ACPI), so
/// they are clean to add and remove.
#[cfg_attr(not(windows), allow(dead_code))]
struct Marker {
    key: &'static str,
    name: &'static str,
    kind: &'static str,
    data: &'static str,
}

const MARKERS: &[Marker] = &[
    Marker { key: r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools", name: "InstallPath", kind: "REG_SZ", data: r"C:\Program Files\VMware\VMware Tools\" },
    Marker { key: r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions", name: "Version", kind: "REG_SZ", data: "7.0.0" },
    Marker { key: r"HKLM\SOFTWARE\Wine", name: "Version", kind: "REG_SZ", data: "stable" },
];

/// Sentinel we own, so status() can tell whether the layer is currently applied.
#[cfg_attr(not(windows), allow(dead_code))]
const SENTINEL_KEY: &str = r"HKCU\Software\667Shield";
#[cfg_attr(not(windows), allow(dead_code))]
const SENTINEL_NAME: &str = "Deception";

#[derive(Debug, Clone, Default)]
pub struct DeceptionStatus {
    pub supported: bool,
    pub active: bool,
    pub marker_count: usize,
}

pub fn status() -> DeceptionStatus {
    DeceptionStatus {
        supported: cfg!(windows),
        active: is_active(),
        marker_count: MARKERS.len(),
    }
}

#[cfg(windows)]
fn is_active() -> bool {
    std::process::Command::new("reg")
        .args(["query", SENTINEL_KEY, "/v", SENTINEL_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn is_active() -> bool {
    false
}

/// Name of the record (under [`SENTINEL_KEY`]) noting what we created for
/// marker `i`: the top-most key we created, or empty if we only added the value.
#[cfg_attr(not(windows), allow(dead_code))]
fn record_name(i: usize) -> String {
    format!("{SENTINEL_NAME}.M{i}")
}

/// The top-most key `reg add` would create for `key`, i.e. what revert must
/// delete; `None` if `key` already exists. Never climbs to a hive or its direct
/// child (`HKLM\SOFTWARE`), so a failed existence check can't widen the delete.
#[cfg_attr(not(windows), allow(dead_code))]
fn created_root(key: &str, exists: impl Fn(&str) -> bool) -> Option<String> {
    if exists(key) {
        return None;
    }
    let mut root = key;
    while let Some((parent, _)) = root.rsplit_once('\\') {
        if parent.split('\\').count() <= 2 || exists(parent) {
            break;
        }
        root = parent;
    }
    Some(root.to_string())
}

/// Pull the data of REG_SZ value `name` out of `reg query` output.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_reg_sz(output: &str, name: &str) -> Option<String> {
    output.lines().find_map(|l| {
        let rest = l.trim_start().strip_prefix(name)?;
        let data = rest.trim_start().strip_prefix("REG_SZ")?;
        Some(data.trim().to_string())
    })
}

#[cfg(windows)]
fn reg_ok(args: &[&str]) -> bool {
    std::process::Command::new("reg")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn reg_query_sz(key: &str, name: &str) -> Option<String> {
    let out = std::process::Command::new("reg").args(["query", key, "/v", name]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_reg_sz(&String::from_utf8_lossy(&out.stdout), name)
}

/// Plant the deception markers. Requires administrator rights (HKLM writes).
/// A value that already exists (e.g. real VMware Tools) is left untouched.
#[cfg(windows)]
pub fn apply(log: &EventLog) -> Result<usize> {
    let mut planted = 0;
    for (i, m) in MARKERS.iter().enumerate() {
        if reg_ok(&["query", m.key, "/v", m.name]) {
            log.info("deception", format!(r"{}\{} already present — left untouched", m.key, m.name));
            continue;
        }
        let root = created_root(m.key, |k| reg_ok(&["query", k]));
        if !reg_ok(&["add", m.key, "/v", m.name, "/t", m.kind, "/d", m.data, "/f"]) {
            log.warn("deception", format!("could not plant marker {} (need admin?)", m.key));
            continue;
        }
        // Remember exactly what we created, so revert removes only that.
        let rec = root.unwrap_or_default();
        if !reg_ok(&["add", SENTINEL_KEY, "/v", &record_name(i), "/t", "REG_SZ", "/d", &rec, "/f"]) {
            log.warn("deception", format!("planted {} but could not record it for revert", m.key));
        }
        planted += 1;
    }
    // Drop the sentinel so we know the layer is on (and can report it).
    reg_ok(&["add", SENTINEL_KEY, "/v", SENTINEL_NAME, "/t", "REG_DWORD", "/d", "1", "/f"]);
    log.action("deception", format!("planted {planted} fake analysis-environment marker(s)"));
    Ok(planted)
}

#[cfg(not(windows))]
pub fn apply(log: &EventLog) -> Result<usize> {
    log.warn("deception", "deception layer is Windows-only (VM/sandbox artifacts)");
    Err(anyhow!("deception layer runs on Windows only"))
}

/// Remove the markers again: only what [`apply`] recorded as created by us.
#[cfg(windows)]
pub fn revert(log: &EventLog) -> Result<usize> {
    let mut removed = 0;
    for (i, m) in MARKERS.iter().enumerate() {
        let rec_name = record_name(i);
        let Some(root) = reg_query_sz(SENTINEL_KEY, &rec_name) else {
            continue; // not planted by us
        };
        let ok = if root.is_empty() {
            reg_ok(&["delete", m.key, "/v", m.name, "/f"])
        } else {
            reg_ok(&["delete", &root, "/f"])
        };
        if ok {
            removed += 1;
            reg_ok(&["delete", SENTINEL_KEY, "/v", &rec_name, "/f"]);
        } else {
            log.warn("deception", format!("could not remove marker {} (need admin?)", m.key));
        }
    }
    reg_ok(&["delete", SENTINEL_KEY, "/v", SENTINEL_NAME, "/f"]);
    log.action("deception", format!("removed {removed} deception marker(s)"));
    Ok(removed)
}

#[cfg(not(windows))]
pub fn revert(_log: &EventLog) -> Result<usize> {
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_matches_platform() {
        let s = status();
        assert_eq!(s.supported, cfg!(windows));
        assert_eq!(s.marker_count, MARKERS.len());
        assert!(s.marker_count >= 2);
    }

    #[test]
    fn created_root_finds_topmost_missing_key() {
        let existing = [r"HKLM\SOFTWARE", r"HKLM\SOFTWARE\Oracle"];
        let exists = |k: &str| existing.contains(&k);
        // Whole vendor key is ours to remove.
        assert_eq!(
            created_root(r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools", exists).as_deref(),
            Some(r"HKLM\SOFTWARE\VMware, Inc.")
        );
        // Parent pre-existed: only the leaf key is ours.
        assert_eq!(
            created_root(r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions", exists).as_deref(),
            Some(r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions")
        );
        // Key already there: we add a value only.
        assert_eq!(created_root(r"HKLM\SOFTWARE\Oracle", exists), None);
    }

    #[test]
    fn created_root_never_reaches_hive() {
        // Even if every existence check fails, the delete stays below SOFTWARE.
        assert_eq!(
            created_root(r"HKLM\SOFTWARE\Wine", |_| false).as_deref(),
            Some(r"HKLM\SOFTWARE\Wine")
        );
        assert_eq!(
            created_root(r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools", |_| false).as_deref(),
            Some(r"HKLM\SOFTWARE\VMware, Inc.")
        );
    }

    #[test]
    fn parses_reg_query_output() {
        let out = "\r\nHKEY_CURRENT_USER\\Software\\667Shield\r\n    Deception.M0    REG_SZ    HKLM\\SOFTWARE\\Wine\r\n    Deception.M1    REG_SZ    \r\n";
        assert_eq!(parse_reg_sz(out, "Deception.M0").as_deref(), Some(r"HKLM\SOFTWARE\Wine"));
        assert_eq!(parse_reg_sz(out, "Deception.M1").as_deref(), Some(""));
        assert_eq!(parse_reg_sz(out, "Deception.M2"), None);
    }

    #[test]
    fn non_windows_apply_is_error_and_revert_noop() {
        // On the dev machine (macOS) apply must not pretend to work.
        if !cfg!(windows) {
            let log = EventLog::new(false);
            assert!(apply(&log).is_err());
            assert_eq!(revert(&log).unwrap(), 0);
        }
    }
}
