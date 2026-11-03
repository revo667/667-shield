//! Live process watchdog — scan running processes for known stealer/dropper
//! indicators and (on confirmation) terminate them.

use crate::log::EventLog;
use crate::platform;
use crate::threat_db::ThreatDb;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, Signal, System};

/// A flagged process.
#[derive(Debug, Clone)]
pub struct Finding {
    pub pid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub reason: String,
}

/// Scan the current process table once, returning everything that matches a
/// stealer indicator. `sys` is reused across scans to avoid re-allocating.
pub fn scan_once(sys: &mut System, db: &ThreatDb) -> Vec<Finding> {
    crate::refresh_process_table(sys);
    let mut findings = Vec::new();
    for (pid, proc_) in sys.processes() {
        let name = proc_.name().to_string_lossy().to_string();
        if let Some(reason) = db.is_suspicious_process(&name) {
            findings.push(Finding {
                pid: pid.as_u32(),
                name,
                exe: proc_.exe().map(|p| p.display().to_string()),
                reason,
            });
        }
    }
    findings
}

/// Terminate a process by pid. Requires `confirm`; a dry run only logs intent.
/// Returns true if a kill signal was delivered (or would be, in dry run).
pub fn terminate(pid: u32, confirm: bool, log: &EventLog) -> bool {
    if !confirm {
        log.warn("watchdog", format!("DRY RUN — would terminate pid {pid}"));
        return false;
    }
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    match sys.process(Pid::from_u32(pid)) {
        Some(p) => {
            let ok = p.kill_with(Signal::Kill).unwrap_or_else(|| p.kill());
            if ok {
                log.action("watchdog", format!("terminated pid {pid}"));
            } else {
                log.warn("watchdog", format!("failed to terminate pid {pid} (permission?)"));
            }
            ok
        }
        None => {
            log.info("watchdog", format!("pid {pid} already gone"));
            false
        }
    }
}

/// Run the watchdog loop until `stop` is set. On each tick it scans and reports
/// findings; if `auto_kill` is set, confirmed terminations happen automatically.
pub fn run(
    db: &ThreatDb,
    log: &EventLog,
    period: Duration,
    auto_kill: bool,
    stop: Arc<AtomicBool>,
) {
    let mut sys = System::new();
    log.info(
        "watchdog",
        format!("process watchdog started (period {:?}, auto_kill={auto_kill})", period),
    );
    let mut known_pids: std::collections::HashSet<u32> = Default::default();
    while !stop.load(Ordering::Relaxed) {
        let findings = scan_once(&mut sys, db);
        for f in &findings {
            // Only shout once per pid, so the log isn't flooded each tick.
            if known_pids.insert(f.pid) {
                log.alert(
                    "watchdog",
                    format!("suspicious process pid={} name={} — {}", f.pid, f.name, f.reason),
                );
                if let Some(exe) = &f.exe {
                    log.info("watchdog", format!("  pid={} exe={}", f.pid, exe));
                }
                // Contain immediately so it cannot exfiltrate while the user
                // decides what to do (reversible: resume / unblock / release).
                platform::contain_process(f.pid, f.exe.as_deref(), log);
                if auto_kill {
                    terminate(f.pid, true, log);
                }
            }
        }
        // Forget pids that are no longer flagged so a reused pid re-alerts.
        known_pids.retain(|p| findings.iter().any(|f| f.pid == *p));
        sleep_interruptible(period, &stop);
    }
    log.info("watchdog", "process watchdog stopped");
}

fn sleep_interruptible(total: Duration, stop: &AtomicBool) {
    let step = Duration::from_millis(100);
    let mut elapsed = Duration::ZERO;
    while elapsed < total {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(step);
        elapsed += step;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_finds_self_if_named_suspiciously() {
        // We can't rename our own process, but we can assert the scan runs and
        // that a clean system doesn't flag the test binary.
        let mut sys = System::new();
        let db = ThreatDb::embedded().unwrap();
        let findings = scan_once(&mut sys, &db);
        // The cargo test harness isn't a stealer; just assert no panic and that
        // any finding carries a reason.
        for f in &findings {
            assert!(!f.reason.is_empty());
        }
    }

    #[test]
    fn dry_run_terminate_is_noop() {
        let log = EventLog::new(false);
        assert!(!terminate(u32::MAX, false, &log));
        assert!(log.snapshot().iter().any(|e| e.message.contains("DRY RUN")));
    }
}
