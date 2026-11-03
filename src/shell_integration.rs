//! Windows Explorer right-click integration.
//!
//! Adds a "667 Shield: Derin Analiz" entry to the context menu of every file,
//! which runs `shield667 inspect "<file>"` on the clicked file. Installed under
//! HKCU (no administrator rights needed) and fully removable.
//!
//! Windows only; on other platforms the calls report that clearly.

use crate::log::EventLog;
use anyhow::{anyhow, Result};

/// Registry key for the per-user "all files" context-menu verb.
#[cfg(windows)]
const VERB_KEY: &str = r"HKCU\Software\Classes\*\shell\667ShieldInspect";
#[cfg_attr(not(windows), allow(dead_code))]
const MENU_LABEL: &str = "667 Shield: Derin Analiz";

#[derive(Debug, Clone, Default)]
pub struct ShellStatus {
    pub supported: bool,
    pub installed: bool,
}

pub fn status() -> ShellStatus {
    ShellStatus {
        supported: cfg!(windows),
        installed: is_installed(),
    }
}

#[cfg(windows)]
fn is_installed() -> bool {
    std::process::Command::new("reg")
        .args(["query", VERB_KEY])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn is_installed() -> bool {
    false
}

/// Install the context-menu entry pointing at this executable.
#[cfg(windows)]
pub fn install(log: &EventLog) -> Result<()> {
    use std::process::Command;
    let exe = std::env::current_exe()
        .map_err(|e| anyhow!("cannot locate own executable: {e}"))?;
    let exe = exe.display().to_string();
    // Keep a console window open so the user can read the report.
    let command = format!("cmd /k \"\"{exe}\" inspect \"%1\"\"");
    let command_key = format!("{VERB_KEY}\\command");

    let reg_add = |args: &[&str]| -> bool {
        Command::new("reg").arg("add").args(args).output().map(|o| o.status.success()).unwrap_or(false)
    };
    if !reg_add(&[VERB_KEY, "/ve", "/d", MENU_LABEL, "/f"]) {
        return Err(anyhow!("failed to write {VERB_KEY}"));
    }
    if !reg_add(&[&command_key, "/ve", "/d", &command, "/f"]) {
        return Err(anyhow!("failed to write {command_key}"));
    }
    log.action("shell", "installed Explorer right-click: Derin Analiz");
    Ok(())
}

#[cfg(not(windows))]
pub fn install(log: &EventLog) -> Result<()> {
    log.warn("shell", "Explorer integration is Windows-only");
    Err(anyhow!("Explorer right-click integration runs on Windows only"))
}

/// Remove the context-menu entry.
#[cfg(windows)]
pub fn uninstall(log: &EventLog) -> Result<()> {
    use std::process::Command;
    let ok = Command::new("reg")
        .args(["delete", VERB_KEY, "/f"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok {
        log.action("shell", "removed Explorer right-click integration");
        Ok(())
    } else {
        Err(anyhow!("failed to remove context-menu entry"))
    }
}

#[cfg(not(windows))]
pub fn uninstall(_log: &EventLog) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_matches_platform() {
        assert_eq!(status().supported, cfg!(windows));
    }

    #[test]
    fn non_windows_install_errors() {
        if !cfg!(windows) {
            let log = EventLog::new(false);
            assert!(install(&log).is_err());
            assert!(uninstall(&log).is_ok());
        }
    }
}
