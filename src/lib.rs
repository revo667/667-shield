//! 667 Shield — cross-platform anti-stealer / anti-RAT defensive guard.
//!
//! Protects Chrome (and other browser) cookies, tokens and passwords from
//! infostealers and RATs by combining several independent defensive layers:
//!
//! * [`hosts`]          — null-route known C2 domains at the host level
//! * [`watchdog`]       — detect & (on confirmation) kill known stealer processes
//! * [`inspector`]      — static analysis of suspect files (hash, entropy, IOCs)
//! * [`webhook`]        — detect & delete Discord exfiltration webhooks
//! * [`clipboard`]      — guard against clipboard crypto-address hijacking
//! * [`scanner`]        — deep disk/temp scan for embedded exfil hooks
//! * [`browsers`]       — detect installed browsers and their secret stores
//! * [`browser_shield`] — watch a browser's cookie/password files for non-browser readers
//!
//! Platform-specific layers (firewall rules, process freeze, the panic switch)
//! live in [`platform`] and are selected at compile time.
//!
//! Every subsystem reports into a shared [`log::EventLog`] — the backend behind
//! the "l0g" screen in the GUI and the live output in the CLI.

pub mod browser_shield;
pub mod browsers;
pub mod clipboard;
pub mod deception;
pub mod dpi;
pub mod hosts;
pub mod shell_integration;
pub mod inspector;
pub mod log;
pub mod platform;
pub mod scanner;
pub mod threat_db;
pub mod watchdog;
pub mod webhook;
pub mod webui;

pub use log::{EventLog, Severity};
pub use threat_db::ThreatDb;

/// Build/version banner.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// This process's current resident memory (RSS) in bytes, if available.
/// Used by the GUI to show the shield's own footprint — the low-RAM promise,
/// made verifiable at a glance.
pub fn process_rss_bytes() -> Option<u64> {
    use sysinfo::{get_current_pid, ProcessesToUpdate, System};
    let pid = get_current_pid().ok()?;
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    sys.process(pid).map(|p| p.memory())
}

/// Refresh the process table with only what the guards use: names and exe
/// paths (an exe is read once per process, then kept). The default sysinfo
/// refresh also samples CPU, memory and disk I/O of every process on each
/// call, which no guard needs — and they run every second or two.
pub fn refresh_process_table(sys: &mut sysinfo::System) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
}

/// A one-line description of the current platform target, for the banner.
pub fn platform_label() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}
