//! DPI bypass — drives the vendored GoodbyeDPI engine so users (in Turkey and
//! elsewhere) can reach sites their ISP blocks via deep packet inspection, such
//! as Discord, Roblox and Wattpad.
//!
//! The engine binaries live under `vendor/goodbyedpi/` (shipped next to the
//! shield executable). We run `goodbyedpi.exe -5 --blacklist blacklist.txt`,
//! exactly as the upstream GoodbyeDPI service script does, with a blacklist
//! limited to the sites we want to unblock. Windows only (GoodbyeDPI uses the
//! WinDivert driver); on other platforms the calls return a clear message.
//!
//! Engine: GoodbyeDPI 0.2.2 by ValdikSS (Apache-2.0). Turkey focus & default
//! blacklist inspired by SplitWire-Turkey by cagritaskn (MIT). See README.

use crate::log::EventLog;
use anyhow::{anyhow, Result};
use std::path::PathBuf;

pub const ENGINE: &str = "GoodbyeDPI 0.2.2";

/// Default engine preset (GoodbyeDPI mode -5, as used by its own service script).
pub const DEFAULT_PRESET: &str = "-5";

/// Sites this feature unblocks by default (from `vendor/goodbyedpi/blacklist.txt`).
pub const UNBLOCKS: &[&str] = &["Discord", "Roblox", "Wattpad"];

/// Current DPI-bypass state.
#[derive(Debug, Clone, Default)]
pub struct DpiStatus {
    /// Platform can run the engine (Windows).
    pub supported: bool,
    /// Vendored engine files are present.
    pub files_present: bool,
    /// Our GoodbyeDPI process is currently running.
    pub running: bool,
}

/// Locate the vendored engine directory, trying locations relative to the
/// executable first (release layout) then the working dir (dev).
pub fn vendor_dir() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("vendor/goodbyedpi"));
            candidates.push(dir.join("../vendor/goodbyedpi"));
            // target/debug/exe -> project root
            candidates.push(dir.join("../../vendor/goodbyedpi"));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("vendor/goodbyedpi"));
    }
    candidates.into_iter().find(|p| p.join("blacklist.txt").exists())
}

fn engine_exe(dir: &std::path::Path) -> PathBuf {
    dir.join("x86_64").join("goodbyedpi.exe")
}

/// Is the GoodbyeDPI engine process currently running?
pub fn is_running() -> bool {
    use sysinfo::{ProcessesToUpdate, System};
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    sys.processes().values().any(|p| {
        let n = p.name().to_string_lossy().to_ascii_lowercase();
        n == "goodbyedpi.exe" || n == "goodbyedpi"
    })
}

/// Report the current DPI-bypass status.
pub fn status() -> DpiStatus {
    let dir = vendor_dir();
    let files_present = dir
        .as_ref()
        .map(|d| engine_exe(d).exists() && d.join("blacklist.txt").exists())
        .unwrap_or(false);
    DpiStatus {
        supported: cfg!(windows),
        files_present,
        running: is_running(),
    }
}

/// Start the DPI-bypass engine. Returns the child process so the caller can
/// stop it later. Requires administrator rights (the WinDivert driver).
#[cfg(windows)]
pub fn start(preset: &str, log: &EventLog) -> Result<std::process::Child> {
    use std::process::Command;
    let dir = vendor_dir().ok_or_else(|| anyhow!("vendored GoodbyeDPI engine not found"))?;
    let exe = engine_exe(&dir);
    if !exe.exists() {
        return Err(anyhow!("engine missing at {}", exe.display()));
    }
    let blacklist = dir.join("blacklist.txt");
    let preset = if preset.trim().is_empty() { DEFAULT_PRESET } else { preset.trim() };
    log.action(
        "dpi",
        format!("starting DPI bypass ({ENGINE} {preset}) for {}", UNBLOCKS.join(", ")),
    );
    let child = Command::new(&exe)
        .args(preset.split_whitespace())
        .arg("--blacklist")
        .arg(&blacklist)
        .current_dir(&dir)
        .spawn()
        .map_err(|e| anyhow!("failed to launch engine (run as administrator?): {e}"))?;
    log.action("dpi", format!("DPI bypass active (pid {})", child.id()));
    Ok(child)
}

#[cfg(not(windows))]
pub fn start(_preset: &str, log: &EventLog) -> Result<std::process::Child> {
    log.warn("dpi", "DPI bypass runs on Windows only (GoodbyeDPI/WinDivert)");
    Err(anyhow!(
        "DPI bypass is Windows-only; build and run 667 Shield on Windows to use it"
    ))
}

/// Stop a running engine child started by [`start`].
pub fn stop(child: &mut std::process::Child, log: &EventLog) -> Result<()> {
    child.kill().map_err(|e| anyhow!("failed to stop engine: {e}"))?;
    let _ = child.wait();
    log.action("dpi", "DPI bypass stopped");
    Ok(())
}

/// Read available preset names from the vendored presets.txt (name:args lines).
pub fn presets() -> Vec<(String, String)> {
    let Some(dir) = vendor_dir() else { return default_presets() };
    match std::fs::read_to_string(dir.join("presets.txt")) {
        Ok(s) => {
            let v: Vec<(String, String)> = s
                .lines()
                .filter_map(|l| l.split_once(':'))
                .map(|(n, a)| (n.trim().to_string(), a.trim().to_string()))
                .collect();
            if v.is_empty() {
                default_presets()
            } else {
                v
            }
        }
        Err(_) => default_presets(),
    }
}

fn default_presets() -> Vec<(String, String)> {
    vec![("Standart".into(), "-5".into())]
}

/// The blacklisted (i.e. unblocked) domains currently configured.
pub fn blacklist_domains() -> Vec<String> {
    let Some(dir) = vendor_dir() else { return vec![] };
    std::fs::read_to_string(dir.join("blacklist.txt"))
        .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_files_are_found_in_dev() {
        // Running `cargo test` from the project root, the vendored engine
        // should be discoverable and the blacklist should list our sites.
        if let Some(dir) = vendor_dir() {
            let domains = blacklist_domains();
            assert!(domains.iter().any(|d| d.contains("discord")));
            assert!(domains.iter().any(|d| d.contains("roblox")));
            assert!(domains.iter().any(|d| d.contains("wattpad")));
            assert!(dir.join("licenses").exists(), "engine licenses must be vendored");
        }
    }

    #[test]
    fn presets_never_empty() {
        assert!(!presets().is_empty());
    }

    #[test]
    fn status_supported_matches_platform() {
        assert_eq!(status().supported, cfg!(windows));
    }
}
