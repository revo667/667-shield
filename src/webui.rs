//! Local web UI — a small HTTP server that serves the modern dashboard and a
//! JSON API wired to the shield's modules.
//!
//! Chosen over a bundled GUI toolkit on purpose: the interface renders in the
//! browser the user already has open, so the shield process itself stays a few
//! MB resident — far below a commercial antivirus. All protection logic lives
//! in the library modules; this file is only presentation + control.

use crate::browsers::Installed;
use crate::log::EventLog;
use crate::{
    browser_shield, browsers, clipboard, deception, dpi, hosts, inspector, platform,
    shell_integration, watchdog, ThreatDb,
};
use serde_json::{json, Value};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Response, Server};

const INDEX_HTML: &str = include_str!("webui_index.html");
/// Replaced in [`INDEX_HTML`] with the per-run session token.
const TOKEN_PLACEHOLDER: &str = "__SHIELD_TOKEN__";
/// Header the dashboard sends the token in on every API call.
const TOKEN_HEADER: &str = "X-Shield-Token";

/// A background guard thread plus its stop flag.
#[derive(Default)]
struct Guard {
    stop: Option<Arc<AtomicBool>>,
    handle: Option<JoinHandle<()>>,
}
impl Guard {
    fn running(&self) -> bool {
        self.stop.is_some()
    }
    fn start<F: FnOnce(Arc<AtomicBool>) + Send + 'static>(&mut self, body: F) {
        if self.running() {
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        self.handle = Some(std::thread::spawn(move || body(s)));
        self.stop = Some(stop);
    }
    fn stop(&mut self) {
        if let Some(s) = self.stop.take() {
            s.store(true, Ordering::Relaxed);
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// How long status that another program can change (DPI engine started
/// elsewhere, hosts edited by hand) may be served from cache.
const SLOW_STATUS_TTL: Duration = Duration::from_secs(10);

/// Status that is expensive to query — a process-table scan, `reg.exe` runs,
/// a file read. The dashboard polls every 1.5 s, so this is read at startup,
/// right after the user changes one of these, and otherwise at most every
/// [`SLOW_STATUS_TTL`].
struct SlowStatus {
    at: Instant,
    dpi: dpi::DpiStatus,
    deception: deception::DeceptionStatus,
    shell: shell_integration::ShellStatus,
    hosts_count: usize,
}

impl SlowStatus {
    fn read() -> Self {
        Self {
            at: Instant::now(),
            dpi: dpi::status(),
            deception: deception::status(),
            shell: shell_integration::status(),
            hosts_count: std::fs::read_to_string(hosts::hosts_path())
                .map(|c| hosts::managed_domain_count(&c))
                .unwrap_or(0),
        }
    }
}

struct App {
    log: EventLog,
    db: ThreatDb,
    browsers: Vec<Installed>,
    selected: usize,
    shield: Guard,
    shield_armed: bool,
    watchdog: Guard,
    watchdog_autokill: bool,
    clipper: Guard,
    clipper_restore: bool,
    dpi_child: Option<Child>,
    quarantined: bool,
    slow: SlowStatus,
}

impl App {
    fn new(echo_log: bool) -> Self {
        let log = EventLog::new(echo_log);
        let db = ThreatDb::embedded().unwrap_or_else(|_| ThreatDb {
            version: "none".into(),
            note: String::new(),
            c2_domains: vec![],
            exfil_hosts: vec![],
            c2_ports: vec![],
            stealer_process_names: vec![],
            stealer_name_fragments: vec![],
        });
        let browsers = browsers::detect_installed();
        log.info("ui", format!("{} browser(s) with protectable secrets", browsers.len()));
        Self {
            log,
            db,
            browsers,
            selected: 0,
            shield: Guard::default(),
            shield_armed: true,
            watchdog: Guard::default(),
            watchdog_autokill: false,
            clipper: Guard::default(),
            clipper_restore: true,
            dpi_child: None,
            quarantined: false,
            slow: SlowStatus::read(),
        }
    }

    /// The protection a double-clicked exe turns on by itself: only guards that
    /// need no administrator rights and leave normal use untouched. System-wide
    /// changes (hosts, deception, DPI, panic) stay one click away in the UI.
    fn start_default_guards(&mut self) {
        self.set_watchdog(true);
        self.set_clipper(true);
        let mut on = vec!["process watchdog", "clipboard guard"];
        match self.browsers.get(self.selected) {
            Some(_) => {
                self.set_shield(true);
                on.push("Browser Shield");
            }
            None => self.log.info("ui", "no browser with saved secrets found — Browser Shield idle"),
        }
        self.log.action("ui", format!("background protection on: {}", on.join(", ")));
    }

    /// Re-read [`SlowStatus`] now, after an action that changed it.
    fn refresh_slow_status(&mut self) {
        self.slow = SlowStatus::read();
    }

    fn set_shield(&mut self, on: bool) {
        if on {
            let Some(b) = self.browsers.get(self.selected).cloned() else {
                self.log.warn("ui", "select a browser before enabling Browser Shield");
                return;
            };
            let log = self.log.clone();
            let armed = self.shield_armed;
            self.shield
                .start(move |stop| browser_shield::run(b, armed, &log, Duration::from_secs(2), stop));
        } else {
            self.shield.stop();
        }
    }

    fn set_watchdog(&mut self, on: bool) {
        if on {
            let log = self.log.clone();
            let db = self.db.clone();
            let auto = self.watchdog_autokill;
            self.watchdog
                .start(move |stop| watchdog::run(&db, &log, Duration::from_secs(1), auto, stop));
        } else {
            self.watchdog.stop();
        }
    }

    fn set_clipper(&mut self, on: bool) {
        if on {
            let log = self.log.clone();
            let restore = self.clipper_restore;
            self.clipper.start(move |stop| clipboard::run(&log, restore, stop));
        } else {
            self.clipper.stop();
        }
    }

    fn dpi_running(&mut self) -> bool {
        if let Some(c) = &mut self.dpi_child {
            match c.try_wait() {
                Ok(Some(_)) => {
                    self.dpi_child = None;
                    false
                }
                _ => true,
            }
        } else {
            false
        }
    }

    fn dpi_start(&mut self) {
        if self.dpi_running() {
            return;
        }
        match dpi::start(dpi::DEFAULT_PRESET, &self.log) {
            Ok(c) => self.dpi_child = Some(c),
            Err(e) => self.log.warn("dpi", e.to_string()),
        }
    }

    fn dpi_stop(&mut self) {
        if let Some(mut c) = self.dpi_child.take() {
            let _ = dpi::stop(&mut c, &self.log);
        }
    }

    fn panic_engage(&mut self) {
        self.log.alert("ui", "PANIC — engaging quarantine");
        let _ = platform::network_release(&self.log);
        let _ = platform::flush_dns(&self.log);
        platform::kill_browsers_and_messengers(&self.log);
        platform::lock_session_files(&self.log);
        let _ = platform::firewall_block_c2_ports(&self.db, &self.log);
        self.quarantined = true;
    }

    fn panic_release(&mut self) {
        self.log.action("ui", "releasing quarantine");
        let _ = platform::network_restore(&self.log);
        platform::unlock_session_files(&self.log);
        let _ = platform::firewall_reset(&self.db, &self.log);
        self.quarantined = false;
    }

    fn state_json(&mut self) -> Value {
        let rss = crate::process_rss_bytes().map(|b| b as f64 / 1048576.0).unwrap_or(0.0);
        let dpi_running = self.dpi_running();
        if self.slow.at.elapsed() >= SLOW_STATUS_TTL {
            self.refresh_slow_status();
        }
        let SlowStatus { dpi: dpi_status, deception: decep, shell, hosts_count, .. } = &self.slow;
        let hosts_count = *hosts_count;
        let sel = self.selected;
        let browsers: Vec<Value> = self
            .browsers
            .iter()
            .map(|b| {
                json!({
                    "name": b.name,
                    "family": format!("{:?}", b.family),
                    "files": b.secret_files.len(),
                    "secret_files": b.secret_files.iter().map(|f| f.display().to_string()).collect::<Vec<_>>(),
                })
            })
            .collect();
        let log: Vec<Value> = self
            .log
            .tail(300)
            .iter()
            .map(|e| {
                json!({
                    "time": e.at.format("%H:%M:%S").to_string(),
                    "sev": e.severity.tag(),
                    "source": e.source,
                    "msg": e.message,
                })
            })
            .collect();
        json!({
            "version": crate::VERSION,
            "platform": crate::platform_label(),
            "rss_mb": rss,
            "signatures": { "c2": self.db.c2_domains.len(), "exfil": self.db.exfil_hosts.len(), "ports": self.db.c2_ports.len() },
            "guards": {
                "shield": { "on": self.shield.running(), "armed": self.shield_armed },
                "watchdog": { "on": self.watchdog.running(), "autokill": self.watchdog_autokill },
                "clipper": { "on": self.clipper.running(), "restore": self.clipper_restore },
                "deception": { "on": decep.active, "supported": decep.supported },
                "hosts": { "on": hosts_count > 0, "count": hosts_count },
            },
            "shell": { "supported": shell.supported, "installed": shell.installed },
            "browsers": browsers,
            "selected": sel,
            "dpi": {
                "supported": dpi_status.supported,
                "files_present": dpi_status.files_present,
                "running": dpi_running || dpi_status.running,
                "engine": dpi::ENGINE,
                "unblocks": dpi::UNBLOCKS,
            },
            "quarantined": self.quarantined,
            "log": log,
        })
    }
}

fn body_json(req: &mut tiny_http::Request) -> Value {
    let mut s = String::new();
    let _ = req.as_reader().read_to_string(&mut s);
    serde_json::from_str(&s).unwrap_or(Value::Null)
}

fn json_response(v: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let data = v.to_string().into_bytes();
    let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json; charset=utf-8"[..]).unwrap();
    Response::from_data(data).with_header(h)
}

/// Random per-run secret, embedded only in the dashboard page we serve.
fn new_token() -> anyhow::Result<String> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("no OS randomness for the UI token: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn header_value<'a>(req: &'a tiny_http::Request, name: &'static str) -> Option<&'a str> {
    req.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Gate every request so that only the dashboard we served can drive the API.
/// Any web page the user visits can reach 127.0.0.1, so without this a hostile
/// site could engage panic, freeze arbitrary PIDs or switch the guards off.
///
/// * `Host` must be our loopback address — defeats DNS rebinding, where an
///   attacker's domain resolves to 127.0.0.1 but still sends its own name.
/// * `Origin`, when present, must be ours — rejects cross-site requests.
/// * `/api/*` must carry the per-run token from the page; a foreign origin can
///   neither read that page nor attach a custom header without a CORS preflight
///   we never approve.
fn request_allowed(host: Option<&str>, origin: Option<&str>, token: Option<&str>, path: &str, port: u16, expected: &str) -> bool {
    let local = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    if !host.is_some_and(|h| local.iter().any(|l| l == h)) {
        return false;
    }
    if let Some(o) = origin {
        if !local.iter().any(|l| o == format!("http://{l}")) {
            return false;
        }
    }
    if !path.starts_with("/api/") {
        return true;
    }
    token.is_some_and(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()))
}

/// Ports the UI may listen on (the first free one is used).
fn ui_ports() -> std::ops::Range<u16> {
    6670..6680
}

/// Does this HTTP body look like our dashboard page?
fn is_dashboard_page(body: &str) -> bool {
    body.contains("<title>667 Shield</title>") && body.contains("const TOKEN=\"")
}

/// URL of a 667 Shield dashboard already running on this machine, if any, so a
/// second launch just shows it instead of starting a second, competing shield.
pub fn running_instance() -> Option<String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_millis(500)).build();
    ui_ports().find_map(|p| {
        let url = format!("http://127.0.0.1:{p}");
        let body = agent.get(&url).call().ok()?.into_string().ok()?;
        is_dashboard_page(&body).then_some(url)
    })
}

/// How [`serve`] starts.
pub struct ServeOptions {
    /// Open the dashboard in the default browser once the server is up.
    pub open_browser: bool,
    /// Turn on the default background guards right away (double-click mode).
    pub start_guards: bool,
    /// Print events to the console as they happen.
    pub echo_log: bool,
}

/// Start the UI server and open it in the browser. Blocks until the process
/// exits. If a shield is already running, just shows its dashboard.
pub fn serve(opts: ServeOptions) -> anyhow::Result<()> {
    if let Some(url) = running_instance() {
        println!("667 Shield is already running → {url}");
        if opts.open_browser {
            open_browser(&url);
        }
        return Ok(());
    }

    let mut app = App::new(opts.echo_log);
    let token = new_token()?;
    let index_html = INDEX_HTML.replace(TOKEN_PLACEHOLDER, &token);

    // Bind the first free port in a small range, in case one is taken.
    let server = ui_ports()
        .find_map(|p| Server::http(("127.0.0.1", p)).ok())
        .ok_or_else(|| anyhow::anyhow!("no free port in 6670..6680 for the UI"))?;
    let addr = server.server_addr();
    let port = addr.to_ip().map(|a| a.port()).unwrap_or(6670);
    let url = format!("http://127.0.0.1:{port}");

    if opts.start_guards {
        app.start_default_guards();
        println!("667 Shield is protecting this computer in the background.");
        println!("Dashboard → {url}");
        println!("Keep this window open; closing it stops the protection.");
    } else {
        println!("667 Shield UI → {url}");
        println!("(Press Ctrl+C to stop)");
    }
    if opts.open_browser {
        open_browser(&url);
    }

    for mut req in server.incoming_requests() {
        let method = req.method().clone();
        let raw = req.url().to_string();
        let path = raw.split('?').next().unwrap_or("/").to_string();

        let allowed = request_allowed(
            header_value(&req, "Host"),
            header_value(&req, "Origin"),
            header_value(&req, TOKEN_HEADER),
            &path,
            port,
            &token,
        );
        if !allowed {
            let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
            let _ = req.respond(Response::from_string("{\"error\":\"forbidden\"}").with_header(h).with_status_code(403));
            continue;
        }

        let resp = match (&method, path.as_str()) {
            (Method::Get, "/") | (Method::Get, "/index.html") => {
                let h = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap();
                // The page carries the session token; keep it out of caches.
                let nc = Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).unwrap();
                let _ = req.respond(Response::from_string(index_html.as_str()).with_header(h).with_header(nc));
                continue;
            }
            (Method::Get, "/api/state") => json_response(&app.state_json()),
            (Method::Post, "/api/select") => {
                let b = body_json(&mut req);
                if let Some(i) = b.get("index").and_then(|v| v.as_u64()) {
                    if (i as usize) < app.browsers.len() {
                        app.selected = i as usize;
                    }
                }
                json_response(&json!({"ok": true}))
            }
            (Method::Post, "/api/guard") => {
                let b = body_json(&mut req);
                let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
                match name {
                    "shield" => {
                        if let Some(a) = b.get("set_armed").and_then(|v| v.as_bool()) {
                            app.shield_armed = a;
                        }
                        if let Some(a) = b.get("armed").and_then(|v| v.as_bool()) {
                            app.shield_armed = a;
                        }
                        if let Some(on) = b.get("on").and_then(|v| v.as_bool()) {
                            app.set_shield(on);
                        }
                    }
                    "watchdog" => {
                        if let Some(a) = b.get("autokill").and_then(|v| v.as_bool()) {
                            app.watchdog_autokill = a;
                        }
                        if let Some(on) = b.get("on").and_then(|v| v.as_bool()) {
                            app.set_watchdog(on);
                        }
                    }
                    "clipper" => {
                        if let Some(a) = b.get("restore").and_then(|v| v.as_bool()) {
                            app.clipper_restore = a;
                        }
                        if let Some(on) = b.get("on").and_then(|v| v.as_bool()) {
                            app.set_clipper(on);
                        }
                    }
                    "deception" => {
                        if let Some(on) = b.get("on").and_then(|v| v.as_bool()) {
                            let r = if on { deception::apply(&app.log) } else { deception::revert(&app.log) };
                            if let Err(e) = r {
                                app.log.warn("deception", e.to_string());
                            }
                            app.refresh_slow_status();
                        }
                    }
                    "hosts" => {
                        if let Some(on) = b.get("on").and_then(|v| v.as_bool()) {
                            let path = hosts::hosts_path();
                            let r = if on {
                                hosts::enable(&app.db, &path).map(|_| ())
                            } else {
                                hosts::disable(&path)
                            };
                            match r {
                                Ok(()) => app.log.action("hosts", if on { "C2 null-routing enabled" } else { "C2 null-routing disabled" }),
                                Err(e) => app.log.warn("hosts", format!("{e} (need admin/root?)")),
                            }
                            app.refresh_slow_status();
                        }
                    }
                    _ => {}
                }
                json_response(&json!({"ok": true}))
            }
            (Method::Post, "/api/dpi") => {
                let b = body_json(&mut req);
                match b.get("action").and_then(|v| v.as_str()) {
                    Some("start") => app.dpi_start(),
                    Some("stop") => app.dpi_stop(),
                    _ => {}
                }
                app.refresh_slow_status();
                json_response(&json!({"ok": true}))
            }
            (Method::Post, "/api/freeze") => {
                let b = body_json(&mut req);
                let action = b.get("action").and_then(|v| v.as_str()).unwrap_or("freeze");
                if let Some(pid) = b.get("pid").and_then(|v| v.as_u64()) {
                    let pid = pid as u32;
                    let r = if action == "resume" {
                        platform::resume_process(pid, &app.log)
                    } else {
                        platform::suspend_process(pid, &app.log)
                    };
                    if let Err(e) = r {
                        app.log.warn("edr", e.to_string());
                    }
                }
                json_response(&json!({"ok": true}))
            }
            (Method::Post, "/api/shell") => {
                let b = body_json(&mut req);
                let r = match b.get("action").and_then(|v| v.as_str()) {
                    Some("install") => shell_integration::install(&app.log),
                    Some("uninstall") => shell_integration::uninstall(&app.log),
                    _ => Ok(()),
                };
                if let Err(e) = r {
                    app.log.warn("shell", e.to_string());
                }
                app.refresh_slow_status();
                json_response(&json!({"ok": true}))
            }
            (Method::Post, "/api/dns-reset") => {
                let path = hosts::hosts_path();
                match hosts::factory_reset(&path) {
                    Ok(Some(prev)) => app.log.action(
                        "hosts",
                        format!("DNS factory reset — hosts restored (replaced file kept at {})", prev.display()),
                    ),
                    Ok(None) => app.log.action("hosts", "DNS factory reset — managed block removed"),
                    Err(e) => app.log.warn("hosts", format!("{e} (need admin/root?)")),
                }
                app.refresh_slow_status();
                json_response(&json!({"ok": true}))
            }
            (Method::Post, "/api/panic") => {
                let b = body_json(&mut req);
                match b.get("action").and_then(|v| v.as_str()) {
                    Some("engage") => app.panic_engage(),
                    Some("release") => app.panic_release(),
                    _ => {}
                }
                json_response(&json!({"ok": true}))
            }
            (Method::Post, "/api/inspect") => {
                let b = body_json(&mut req);
                let path = b.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let v = match inspector::inspect(std::path::Path::new(path)) {
                    Ok(r) => {
                        let mut t = format!(
                            "sha256:  {}\nboyut:   {} bayt\nentropi: {:.3} / 8.000{}\nsonuç:   {}",
                            r.sha256,
                            r.size,
                            r.entropy,
                            if r.is_high_entropy() { "  [PAKETLİ/ŞİFRELİ]" } else { "" },
                            r.verdict()
                        );
                        for w in &r.webhooks {
                            t.push_str(&format!("\nwebhook: {w}"));
                        }
                        json!({"ok": true, "text": t})
                    }
                    Err(e) => json!({"ok": false, "error": e.to_string()}),
                };
                json_response(&v)
            }
            _ => {
                let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
                let _ = req.respond(Response::from_string("{\"error\":\"not found\"}").with_header(h).with_status_code(404));
                continue;
            }
        };
        let _ = req.respond(resp);
    }
    Ok(())
}

fn open_browser(url: &str) {
    use std::process::Command;
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg(url).spawn();
    #[cfg(windows)]
    let _ = Command::new("cmd").args(["/C", "start", "", url]).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = Command::new("xdg-open").arg(url).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "secret-token";
    const HOST: Option<&str> = Some("127.0.0.1:6670");
    const ORIGIN: Option<&str> = Some("http://127.0.0.1:6670");

    #[test]
    fn dashboard_requests_pass() {
        assert!(request_allowed(HOST, None, None, "/", 6670, T));
        assert!(request_allowed(HOST, ORIGIN, Some(T), "/api/panic", 6670, T));
        assert!(request_allowed(Some("localhost:6670"), Some("http://localhost:6670"), Some(T), "/api/state", 6670, T));
    }

    #[test]
    fn cross_site_request_is_rejected() {
        // A hostile page posting to the API, with or without guessing a token.
        assert!(!request_allowed(HOST, Some("https://evil.example"), Some(T), "/api/panic", 6670, T));
        assert!(!request_allowed(HOST, Some("null"), Some(T), "/api/freeze", 6670, T));
        assert!(!request_allowed(HOST, None, None, "/api/panic", 6670, T));
        assert!(!request_allowed(HOST, ORIGIN, Some("wrong"), "/api/panic", 6670, T));
    }

    #[test]
    fn dns_rebinding_is_rejected() {
        assert!(!request_allowed(Some("evil.example:6670"), None, Some(T), "/api/state", 6670, T));
        assert!(!request_allowed(Some("evil.example:6670"), None, None, "/", 6670, T));
        assert!(!request_allowed(None, None, Some(T), "/api/state", 6670, T));
        assert!(!request_allowed(Some("127.0.0.1:6671"), None, Some(T), "/api/state", 6670, T));
    }

    #[test]
    fn recognises_only_our_dashboard() {
        assert!(is_dashboard_page(&INDEX_HTML.replace(TOKEN_PLACEHOLDER, "abc")));
        assert!(!is_dashboard_page("<html><title>Some other app</title></html>"));
        assert!(!is_dashboard_page("{\"error\":\"forbidden\"}"));
    }

    #[test]
    fn page_carries_token_placeholder_and_tokens_are_unique() {
        assert!(INDEX_HTML.contains(TOKEN_PLACEHOLDER));
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }
}
