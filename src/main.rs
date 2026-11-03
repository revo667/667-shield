//! 667 Shield — command-line interface.
//!
//! Deliberately dependency-light (no arg-parser crate) to keep the binary and
//! its resident footprint small. The GUI lives behind the `gui` cargo feature
//! so the default build stays lean.
//!
//! Started with no arguments (e.g. double-clicking the exe) it runs `run`:
//! background protection plus the dashboard.

use shield667::{
    browser_shield, browsers, clipboard, hosts, inspector, platform, scanner, watchdog,
    EventLog, ThreatDb,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::System;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("run");
    let rest = &args[args.len().min(1)..];
    let log = EventLog::new(true); // echo events to stderr in CLI mode

    let db = match ThreatDb::embedded() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("fatal: could not load signatures: {e}");
            std::process::exit(2);
        }
    };

    let code = match cmd {
        "run" => cmd_run(args.is_empty()),
        "ui" => cmd_ui(),
        "status" => cmd_status(&db),
        "inspect" => cmd_inspect(rest),
        "scan" => cmd_scan(rest, &db, &log),
        "procs" => cmd_procs(&db),
        "hosts" => cmd_hosts(rest, &db, &log),
        "webhook" => cmd_webhook(rest, &log),
        "browsers" => cmd_browsers(),
        "shield" => cmd_shield(rest, &log),
        "watch" => cmd_watch(rest, &db, &log),
        "clipper" => cmd_clipper(rest, &log),
        "freeze" => cmd_freeze(rest, &log, true),
        "resume" => cmd_freeze(rest, &log, false),
        "contain" => cmd_contain(rest, &log),
        "unblock" => cmd_unblock(rest, &log),
        "panic" => cmd_panic(rest, &db, &log),
        "help" | "-h" | "--help" => {
            print_help();
            0
        }
        other => {
            eprintln!("unknown command: {other}\n");
            print_help();
            2
        }
    };
    std::process::exit(code);
}

fn has_flag(rest: &[String], flag: &str) -> bool {
    rest.iter().any(|a| a == flag)
}

fn positional(rest: &[String]) -> Vec<&String> {
    rest.iter().filter(|a| !a.starts_with("--")).collect()
}

fn banner() {
    println!(
        "667 Shield v{} — anti-stealer guard [{}]",
        shield667::VERSION,
        shield667::platform_label()
    );
}

/// Background protection plus the dashboard. `launched_bare` is true when
/// started with no arguments, as by a double-click: then the console window
/// closes as soon as we exit, so an error waits for Enter to stay readable.
fn cmd_run(launched_bare: bool) -> i32 {
    let opts = shield667::webui::ServeOptions { open_browser: true, start_guards: true, echo_log: true };
    match shield667::webui::serve(opts) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("667 Shield could not start: {e:#}");
            if launched_bare {
                eprintln!("Press Enter to close.");
                let _ = std::io::stdin().read_line(&mut String::new());
            }
            1
        }
    }
}

fn cmd_ui() -> i32 {
    let opts = shield667::webui::ServeOptions { open_browser: true, start_guards: false, echo_log: false };
    match shield667::webui::serve(opts) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("UI failed: {e:#}");
            1
        }
    }
}

fn cmd_status(db: &ThreatDb) -> i32 {
    banner();
    println!("signatures: v{} ({} C2 domains, {} ports)", db.version, db.c2_domains.len(), db.c2_ports.len());

    let hp = hosts::hosts_path();
    match std::fs::read_to_string(&hp) {
        Ok(c) => println!("hosts null-route: {} domain(s) active at {}", hosts::managed_domain_count(&c), hp.display()),
        Err(_) => println!("hosts null-route: (hosts file not readable)"),
    }

    let installed = browsers::detect_installed();
    println!("browsers with secrets: {}", installed.len());
    for b in &installed {
        println!("  - {} ({} secret file(s))", b.name, b.secret_files.len());
    }

    let mut sys = System::new();
    let findings = watchdog::scan_once(&mut sys, db);
    if findings.is_empty() {
        println!("process watchdog: no suspicious processes right now");
    } else {
        println!("process watchdog: {} SUSPICIOUS process(es):", findings.len());
        for f in &findings {
            println!("  ! pid={} {} — {}", f.pid, f.name, f.reason);
        }
    }
    0
}

fn cmd_inspect(rest: &[String]) -> i32 {
    let pos = positional(rest);
    let Some(path) = pos.first() else {
        eprintln!("usage: shield667 inspect <file>");
        return 2;
    };
    match inspector::inspect(std::path::Path::new(path.as_str())) {
        Ok(r) => {
            println!("file:    {}", r.path);
            println!("size:    {} bytes", r.size);
            println!("sha256:  {}", r.sha256);
            println!("entropy: {:.3} / 8.000{}", r.entropy, if r.is_high_entropy() { "  [PACKED/ENCRYPTED]" } else { "" });
            if !r.webhooks.is_empty() {
                println!("embedded Discord webhooks:");
                for w in &r.webhooks {
                    println!("  ! {w}");
                }
            }
            if !r.urls.is_empty() {
                println!("embedded URLs: {}", r.urls.len());
                for u in r.urls.iter().take(20) {
                    println!("  - {u}");
                }
            }
            println!("verdict: {}", r.verdict());
            0
        }
        Err(e) => {
            eprintln!("inspect failed: {e:#}");
            1
        }
    }
}

fn cmd_scan(rest: &[String], db: &ThreatDb, log: &EventLog) -> i32 {
    let pos = positional(rest);
    let roots: Vec<PathBuf> = if pos.is_empty() {
        scanner::default_roots()
    } else {
        pos.iter().map(|s| PathBuf::from(s.as_str())).collect()
    };
    if roots.is_empty() {
        eprintln!("no scan roots available");
        return 1;
    }
    println!("scanning {} root(s)…", roots.len());
    let hits = scanner::scan_roots(&roots, &scanner::ScanConfig::default(), db, log);
    println!("\n{} file(s) with embedded exfil indicators:", hits.len());
    for h in &hits {
        println!("  {}", h.path);
        for w in &h.webhooks {
            println!("    webhook: {w}");
        }
        for u in &h.c2_urls {
            println!("    c2:      {u}");
        }
    }
    if hits.is_empty() {
        0
    } else {
        1
    }
}

fn cmd_procs(db: &ThreatDb) -> i32 {
    let mut sys = System::new();
    let findings = watchdog::scan_once(&mut sys, db);
    if findings.is_empty() {
        println!("no suspicious processes");
        return 0;
    }
    for f in &findings {
        println!("pid={} name={} exe={} — {}", f.pid, f.name, f.exe.as_deref().unwrap_or("?"), f.reason);
    }
    1
}

fn cmd_hosts(rest: &[String], db: &ThreatDb, log: &EventLog) -> i32 {
    let pos = positional(rest);
    let sub = pos.first().map(|s| s.as_str()).unwrap_or("status");
    let path = hosts::hosts_path();
    match sub {
        "enable" => match hosts::enable(db, &path) {
            Ok(n) => {
                log.action("hosts", format!("null-routed {n} C2 domain(s)"));
                0
            }
            Err(e) => {
                eprintln!("hosts enable failed (need admin/root?): {e:#}");
                1
            }
        },
        "disable" => match hosts::disable(&path) {
            Ok(()) => {
                log.action("hosts", "removed managed C2 null-route block (DNS factory reset)");
                0
            }
            Err(e) => {
                eprintln!("hosts disable failed (need admin/root?): {e:#}");
                1
            }
        },
        _ => {
            match std::fs::read_to_string(&path) {
                Ok(c) => println!("{} managed domain(s) at {}", hosts::managed_domain_count(&c), path.display()),
                Err(e) => eprintln!("cannot read {}: {e}", path.display()),
            }
            0
        }
    }
}

fn cmd_webhook(rest: &[String], log: &EventLog) -> i32 {
    let pos = positional(rest);
    let Some(sub) = pos.first().map(|s| s.as_str()) else {
        eprintln!("usage: shield667 webhook check|delete <url> [--confirm]");
        return 2;
    };
    let Some(url) = pos.get(1) else {
        eprintln!("usage: shield667 webhook {sub} <url>");
        return 2;
    };
    let Some(wh) = shield667::webhook::parse(url) else {
        eprintln!("not a valid Discord webhook URL");
        return 2;
    };
    match sub {
        "check" => {
            match shield667::webhook::probe(&wh) {
                shield667::webhook::Probe::Live { name } => {
                    println!("LIVE webhook id={} name={}", wh.id, name.as_deref().unwrap_or("?"));
                }
                shield667::webhook::Probe::Dead => println!("dead/invalid webhook id={}", wh.id),
                shield667::webhook::Probe::Unknown(e) => println!("could not determine (id={}): {e}", wh.id),
            }
            0
        }
        "delete" => {
            let confirm = has_flag(rest, "--confirm");
            match shield667::webhook::delete(&wh, confirm, log) {
                Ok(true) => 0,
                Ok(false) => {
                    eprintln!("(dry run — pass --confirm to actually neutralize)");
                    0
                }
                Err(e) => {
                    eprintln!("delete failed: {e:#}");
                    1
                }
            }
        }
        _ => {
            eprintln!("unknown webhook subcommand: {sub}");
            2
        }
    }
}

fn cmd_browsers() -> i32 {
    let installed = browsers::detect_installed();
    if installed.is_empty() {
        println!("no browsers with on-disk secrets detected");
        return 0;
    }
    println!("installed browsers (protectable):");
    for b in &installed {
        println!("  {} [{:?}] — {} secret file(s)", b.name, b.family, b.secret_files.len());
        for f in &b.secret_files {
            println!("      {}", f.display());
        }
    }
    0
}

fn cmd_shield(rest: &[String], log: &EventLog) -> i32 {
    let pos = positional(rest);
    let installed = browsers::detect_installed();
    let Some(want) = pos.first() else {
        eprintln!("usage: shield667 shield <browser-name> [--arm]");
        eprintln!("available:");
        for b in &installed {
            eprintln!("  {}", b.name);
        }
        return 2;
    };
    let Some(browser) = installed.into_iter().find(|b| b.name.eq_ignore_ascii_case(want) || b.name.to_lowercase().contains(&want.to_lowercase())) else {
        eprintln!("browser '{want}' not found among installed browsers");
        return 2;
    };
    let armed = has_flag(rest, "--arm");
    let stop = install_stop_on_enter(log);
    println!("Browser Shield active for {} (armed={armed}). Press Enter to stop.", browser.name);
    browser_shield::run(browser, armed, log, Duration::from_secs(2), stop);
    0
}

fn cmd_watch(rest: &[String], db: &ThreatDb, log: &EventLog) -> i32 {
    let auto_kill = has_flag(rest, "--auto-kill");
    let stop = install_stop_on_enter(log);
    println!("Process watchdog active (auto_kill={auto_kill}). Press Enter to stop.");
    watchdog::run(db, log, Duration::from_secs(1), auto_kill, stop);
    0
}

fn cmd_clipper(rest: &[String], log: &EventLog) -> i32 {
    let restore = has_flag(rest, "--restore");
    let stop = install_stop_on_enter(log);
    println!("Clipboard clipper guard active (restore={restore}). Press Enter to stop.");
    clipboard::run(log, restore, stop);
    0
}

fn cmd_freeze(rest: &[String], log: &EventLog, freeze: bool) -> i32 {
    let pos = positional(rest);
    let Some(pid) = pos.first().and_then(|s| s.parse::<u32>().ok()) else {
        eprintln!("usage: shield667 {} <pid>", if freeze { "freeze" } else { "resume" });
        return 2;
    };
    let r = if freeze {
        platform::suspend_process(pid, log)
    } else {
        platform::resume_process(pid, log)
    };
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    }
}

fn cmd_contain(rest: &[String], log: &EventLog) -> i32 {
    let pos = positional(rest);
    let Some(pid) = pos.first().and_then(|s| s.parse::<u32>().ok()) else {
        eprintln!("usage: shield667 contain <pid> [exe-path]");
        return 2;
    };
    let exe = pos.get(1).map(|s| s.as_str());
    if platform::contain_process(pid, exe, log) {
        0
    } else {
        1
    }
}

fn cmd_unblock(rest: &[String], log: &EventLog) -> i32 {
    let pos = positional(rest);
    let Some(exe) = pos.first() else {
        eprintln!("usage: shield667 unblock <exe-path>");
        return 2;
    };
    match platform::unblock_process_network(exe, log) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    }
}

fn cmd_panic(rest: &[String], db: &ThreatDb, log: &EventLog) -> i32 {
    let pos = positional(rest);
    let release = pos.first().map(|s| s.as_str()) == Some("release");
    if release {
        println!("PANIC RELEASE — restoring…");
        let _ = platform::network_restore(log);
        let n = platform::unlock_session_files(log);
        let _ = platform::firewall_reset(db, log);
        println!("restored network, unlocked {n} session path(s)");
        return 0;
    }
    if !has_flag(rest, "--confirm") {
        eprintln!("PANIC will drop network, kill browsers/messengers and lock session stores.");
        eprintln!("Re-run with --confirm to proceed, or 'panic release' to undo later.");
        return 2;
    }
    println!("!!! PANIC QUARANTINE ENGAGED !!!");
    let _ = platform::network_release(log);
    let _ = platform::flush_dns(log);
    let killed = platform::kill_browsers_and_messengers(log);
    let locked = platform::lock_session_files(log);
    let _ = platform::firewall_block_c2_ports(db, log);
    println!("network down, {killed} app(s) killed, {locked} session path(s) locked");
    println!("run 'shield667 panic release' to restore");
    0
}

/// Spawn a thread that sets a stop flag when the user presses Enter, so loop
/// commands can be stopped cleanly from a terminal.
fn install_stop_on_enter(_log: &EventLog) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        s2.store(true, Ordering::Relaxed);
    });
    stop
}

fn print_help() {
    banner();
    println!(
        r#"
usage: shield667 [command] [args]

  (no command) / run         start background protection and open the dashboard
                             (watchdog, Browser Shield, clipboard guard)
  ui                         open the dashboard only, all guards off

inspection & detection
  status                     overview: signatures, hosts, browsers, live threats
  inspect <file>             static analysis (sha256, entropy, embedded IOCs)
  scan [roots...]            deep scan for embedded webhooks / C2 (default: temp/appdata)
  procs                      list currently-running suspicious processes
  browsers                   list installed browsers that have secrets to protect

active guards (run until Enter)
  shield <browser> [--arm]   Browser Shield: watch a browser's secret files; --arm freezes intruders
  watch [--auto-kill]        process watchdog loop
  clipper [--restore]        clipboard crypto-address hijack guard

containment / response
  hosts enable|disable       C2 domain null-routing (needs admin/root)
  webhook check <url>        probe a Discord webhook
  webhook delete <url> --confirm   neutralize (delete) a Discord webhook
  freeze <pid> / resume <pid>      suspend/resume a process
  contain <pid> [exe]        freeze a process AND cut its internet (stop exfil)
  unblock <exe-path>         restore internet for a program contained earlier
  panic --confirm            emergency quarantine; 'panic release' to undo
"#
    );
}
