//! Platform-specific defensive actions, selected at compile time.
//!
//! Where a capability has a safe, built-in system command it is driven through
//! that (kept auditable and dependency-light). Where a capability genuinely
//! requires native OS APIs not yet wired up (e.g. suspending a process on
//! Windows via `ntdll!NtSuspendProcess`), the function returns a clear
//! "planned" error rather than pretending to act.

use crate::log::EventLog;
use crate::threat_db::ThreatDb;
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use sysinfo::{ProcessesToUpdate, Signal, System};

/// Process names (without extension) killed by the panic switch.
const BROWSERS_AND_MESSENGERS: &[&str] = &[
    "chrome", "msedge", "edge", "brave", "opera", "opera_gx", "firefox", "vivaldi",
    "discord", "discordptb", "discordcanary", "telegram",
];

// ------------------------------------------------------------------ browsers

/// Kill all running browsers and messengers (panic-switch step 2). Returns how
/// many processes were signalled.
pub fn kill_browsers_and_messengers(log: &EventLog) -> usize {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut killed = 0;
    for proc_ in sys.processes().values() {
        let name = proc_.name().to_string_lossy().to_ascii_lowercase();
        let stem = name.strip_suffix(".exe").unwrap_or(&name);
        if BROWSERS_AND_MESSENGERS.contains(&stem)
            && proc_.kill_with(Signal::Kill).unwrap_or_else(|| proc_.kill())
        {
            killed += 1;
        }
    }
    log.action("panic", format!("terminated {killed} browser/messenger process(es)"));
    killed
}

// -------------------------------------------------------------- session lock

/// Candidate session-store paths worth locking during a panic (best effort;
/// only those that exist are touched).
pub fn session_store_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let a = PathBuf::from(&appdata);
            v.push(a.join(r"discord\Local Storage\leveldb"));
            v.push(a.join(r"Telegram Desktop\tdata"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let h = PathBuf::from(&home);
            v.push(h.join("Library/Application Support/discord/Local Storage/leveldb"));
            v.push(h.join("Library/Application Support/Telegram Desktop/tdata"));
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let h = PathBuf::from(&home);
            v.push(h.join(".config/discord/Local Storage/leveldb"));
            v.push(h.join(".local/share/TelegramDesktop/tdata"));
        }
    }
    v.retain(|p| p.exists());
    v
}

/// Make session stores read-only (panic step 3) so nothing can tamper with or
/// replace them while quarantined. This does not stop a process from reading
/// them. Returns how many paths were locked.
pub fn lock_session_files(log: &EventLog) -> usize {
    set_session_readonly(true, log)
}

/// Restore write access to session stores (panic release).
pub fn unlock_session_files(log: &EventLog) -> usize {
    set_session_readonly(false, log)
}

fn set_session_readonly(readonly: bool, log: &EventLog) -> usize {
    let mut n = 0;
    for p in session_store_paths() {
        match set_readonly_recursive(&p, readonly) {
            Ok(c) => {
                n += c;
                log.action(
                    "panic",
                    format!("{} {} ({c} entries)", if readonly { "locked" } else { "unlocked" }, p.display()),
                );
            }
            Err(e) => log.warn("panic", format!("could not set perms on {}: {e}", p.display())),
        }
    }
    n
}

fn set_readonly_recursive(path: &Path, readonly: bool) -> Result<usize> {
    let mut count = 0;
    for entry in walkdir::WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if std::fs::set_permissions(entry.path(), toggled_perms(meta.permissions(), readonly)).is_ok() {
            count += 1;
        }
    }
    if count == 0 {
        return Err(anyhow!("no entries adjusted"));
    }
    Ok(count)
}

/// Remove write access (`readonly`) or give it back. On Unix
/// `Permissions::set_readonly(false)` would make the entry world-writable, so
/// only the owner's write bit is restored there.
fn toggled_perms(mut perms: std::fs::Permissions, readonly: bool) -> std::fs::Permissions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = perms.mode();
        perms.set_mode(if readonly { mode & !0o222 } else { mode | 0o200 });
    }
    #[cfg(not(unix))]
    perms.set_readonly(readonly);
    perms
}

// -------------------------------------------------------------------- network

/// Drop network connectivity (panic step 1).
pub fn network_release(log: &EventLog) -> Result<()> {
    #[cfg(windows)]
    {
        run("ipconfig", &["/release"], log)
    }
    #[cfg(target_os = "macos")]
    {
        // Power down Wi-Fi; en0 is the usual airport device on Macs.
        run("networksetup", &["-setairportpower", "en0", "off"], log)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        run("nmcli", &["networking", "off"], log)
    }
}

/// Restore network connectivity (panic release).
pub fn network_restore(log: &EventLog) -> Result<()> {
    #[cfg(windows)]
    {
        run("ipconfig", &["/renew"], log)
    }
    #[cfg(target_os = "macos")]
    {
        run("networksetup", &["-setairportpower", "en0", "on"], log)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        run("nmcli", &["networking", "on"], log)
    }
}

/// Flush the DNS resolver cache.
pub fn flush_dns(log: &EventLog) -> Result<()> {
    #[cfg(windows)]
    {
        run("ipconfig", &["/flushdns"], log)
    }
    #[cfg(target_os = "macos")]
    {
        run("dscacheutil", &["-flushcache"], log)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // No universal command; resolved is common.
        run("resolvectl", &["flush-caches"], log)
    }
}

// ------------------------------------------------------------------- firewall

/// Add outbound-block firewall rules for known C2 ports.
pub fn firewall_block_c2_ports(db: &ThreatDb, log: &EventLog) -> Result<usize> {
    #[cfg(windows)]
    {
        let mut n = 0;
        for port in &db.c2_ports {
            let name = format!("667Shield-Block-{port}");
            let remote = format!("remoteport={port}");
            let ok = run(
                "netsh",
                &[
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={name}"),
                    "dir=out", "action=block", "protocol=TCP", &remote,
                ],
                log,
            )
            .is_ok();
            if ok {
                n += 1;
            }
        }
        log.action("firewall", format!("added {n} outbound C2 port-block rule(s)"));
        Ok(n)
    }
    #[cfg(not(windows))]
    {
        let _ = (db, log);
        Err(anyhow!(
            "port-level firewall blocking on this platform requires a pf/nftables module (planned); \
             hosts-level C2 null-routing is active in the meantime"
        ))
    }
}

/// Remove the firewall rules added by [`firewall_block_c2_ports`].
pub fn firewall_reset(db: &ThreatDb, log: &EventLog) -> Result<usize> {
    #[cfg(windows)]
    {
        let mut n = 0;
        for port in &db.c2_ports {
            let name = format!("667Shield-Block-{port}");
            if run("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={name}")], log).is_ok() {
                n += 1;
            }
        }
        Ok(n)
    }
    #[cfg(not(windows))]
    {
        let _ = (db, log);
        Ok(0)
    }
}

// ------------------------------------------------------------- containment

/// Fully contain a process caught stealing: freeze it so it cannot continue,
/// and cut its internet so anything it already read cannot be sent out. On
/// macOS/Linux the freeze alone stops all transmission; on Windows the
/// per-program firewall block cuts the network even before the freeze module
/// lands. Returns true if at least one containment action succeeded.
pub fn contain_process(pid: u32, exe_path: Option<&str>, log: &EventLog) -> bool {
    let mut ok = false;
    match suspend_process(pid, log) {
        Ok(()) => ok = true,
        Err(e) => log.info("response", format!("freeze pid {pid}: {e}")),
    }
    if let Some(exe) = exe_path {
        match block_process_network(exe, log) {
            Ok(()) => ok = true,
            Err(e) => log.info("response", format!("per-process net block: {e}")),
        }
    }
    if ok {
        log.action("response", format!("contained pid {pid} — it can no longer send data out"));
    } else {
        log.warn("response", format!("could not contain pid {pid}"));
    }
    ok
}

/// Build a deterministic, filesystem-safe firewall rule name for an exe path.
/// (Used by the Windows firewall path and by tests.)
#[cfg_attr(not(windows), allow(dead_code))]
fn net_rule_name(exe_path: &str) -> String {
    let safe: String = exe_path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("667Shield-NetBlock-{safe}")
}

/// Block all network traffic for a specific program (by full exe path).
pub fn block_process_network(exe_path: &str, log: &EventLog) -> Result<()> {
    #[cfg(windows)]
    {
        let name = net_rule_name(exe_path);
        // Outbound block (stop exfil) and inbound block (stop reverse shells).
        run("netsh", &["advfirewall", "firewall", "add", "rule", &format!("name={name}"), "dir=out", "action=block", &format!("program={exe_path}"), "enable=yes"], log)?;
        let _ = run("netsh", &["advfirewall", "firewall", "add", "rule", &format!("name={name}"), "dir=in", "action=block", &format!("program={exe_path}"), "enable=yes"], log);
        log.action("response", format!("cut all internet access for {exe_path}"));
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (exe_path, log);
        Err(anyhow!("handled by freeze on this platform (a suspended process transmits nothing)"))
    }
}

/// Restore network access for a program previously blocked.
pub fn unblock_process_network(exe_path: &str, log: &EventLog) -> Result<()> {
    #[cfg(windows)]
    {
        let name = net_rule_name(exe_path);
        run("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={name}")], log)?;
        log.action("response", format!("restored internet access for {exe_path}"));
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (exe_path, log);
        Ok(())
    }
}

// ----------------------------------------------------------------------- EDR

/// Suspend (freeze) a process without killing it, so e.g. ransomware stops
/// encrypting while it is analysed.
pub fn suspend_process(pid: u32, log: &EventLog) -> Result<()> {
    #[cfg(unix)]
    {
        run("kill", &["-STOP", &pid.to_string()], log)?;
        log.action("edr", format!("suspended pid {pid} (SIGSTOP)"));
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = (pid, log);
        Err(anyhow!(
            "process freeze on Windows requires the native ntdll!NtSuspendProcess module (planned)"
        ))
    }
}

/// Resume a previously suspended process.
pub fn resume_process(pid: u32, log: &EventLog) -> Result<()> {
    #[cfg(unix)]
    {
        run("kill", &["-CONT", &pid.to_string()], log)?;
        log.action("edr", format!("resumed pid {pid} (SIGCONT)"));
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = (pid, log);
        Err(anyhow!(
            "process resume on Windows requires the native ntdll!NtResumeProcess module (planned)"
        ))
    }
}

// --------------------------------------------------------------------- helper

/// Run a system command, logging the invocation and surfacing non-zero exits.
fn run(cmd: &str, args: &[&str], log: &EventLog) -> Result<()> {
    log.info("platform", format!("$ {cmd} {}", args.join(" ")));
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow!("failed to launch {cmd}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(anyhow!("{cmd} exited with {}: {}", out.status, stderr.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_rule_name_is_safe_and_deterministic() {
        let a = net_rule_name(r"C:\Users\x\AppData\Local\Temp\stealer.exe");
        let b = net_rule_name(r"C:\Users\x\AppData\Local\Temp\stealer.exe");
        assert_eq!(a, b, "same path must map to same rule name");
        assert!(a.starts_with("667Shield-NetBlock-"));
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn session_paths_do_not_panic() {
        // Just exercising path construction; most won't exist in CI.
        let _ = session_store_paths();
    }

    #[test]
    fn readonly_roundtrip_on_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("sess.dat");
        std::fs::write(&f, b"token").unwrap();

        let n = set_readonly_recursive(dir.path(), true).unwrap();
        assert!(n >= 1);
        let md = std::fs::metadata(&f).unwrap();
        assert!(md.permissions().readonly());

        set_readonly_recursive(dir.path(), false).unwrap();
        let md = std::fs::metadata(&f).unwrap();
        assert!(!md.permissions().readonly());
    }

    #[cfg(unix)]
    #[test]
    fn unlock_never_grants_group_or_world_write() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("sess.dat");
        std::fs::write(&f, b"token").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();

        set_readonly_recursive(dir.path(), true).unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o400);

        set_readonly_recursive(dir.path(), false).unwrap();
        for p in [dir.path(), f.as_path()] {
            let mode = std::fs::metadata(p).unwrap().permissions().mode();
            assert_eq!(mode & 0o022, 0, "{} must not be group/world-writable", p.display());
        }
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
