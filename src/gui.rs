//! 667 Shield — desktop GUI (egui/eframe).
//!
//! Built only with `--features gui`. Keeps a tiny resident footprint: guards
//! run on background threads, the UI only repaints a few times a second, and
//! the shield's own RAM usage is shown live in the header so the low-memory
//! promise is verifiable at a glance.

use eframe::egui;
use egui::{Color32, RichText};
use shield667::browsers::Installed;
use shield667::log::Severity;
use shield667::{
    browser_shield, browsers, clipboard, platform, watchdog, EventLog, ThreatDb,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([940.0, 680.0])
            .with_min_inner_size([760.0, 520.0])
            .with_title("667 Shield"),
        ..Default::default()
    };
    eframe::run_native(
        "667 Shield",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(ShieldApp::new()))
        }),
    )
}

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

    fn start<F>(&mut self, body: F)
    where
        F: FnOnce(Arc<AtomicBool>) + Send + 'static,
    {
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

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Dashboard,
    BrowserShield,
    Guards,
    Response,
}

struct ShieldApp {
    log: EventLog,
    db: ThreatDb,
    browsers: Vec<Installed>,
    selected: usize,
    tab: Tab,

    shield_armed: bool,
    shield: Guard,
    watchdog_autokill: bool,
    watchdog: Guard,
    clipper_restore: bool,
    clipper: Guard,

    rss_mb: f64,
    last_rss: Instant,
    quarantined: bool,
}

impl ShieldApp {
    fn new() -> Self {
        let log = EventLog::new(false);
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
        log.info("gui", format!("667 Shield GUI started on {}", shield667::platform_label()));
        log.info("gui", format!("{} browser(s) with protectable secrets detected", browsers.len()));
        Self {
            log,
            db,
            browsers,
            selected: 0,
            tab: Tab::Dashboard,
            shield_armed: true,
            shield: Guard::default(),
            watchdog_autokill: false,
            watchdog: Guard::default(),
            clipper_restore: true,
            clipper: Guard::default(),
            rss_mb: 0.0,
            last_rss: Instant::now() - Duration::from_secs(10),
            quarantined: false,
        }
    }

    fn refresh_rss(&mut self) {
        if self.last_rss.elapsed() >= Duration::from_secs(2) {
            if let Some(b) = shield667::process_rss_bytes() {
                self.rss_mb = b as f64 / (1024.0 * 1024.0);
            }
            self.last_rss = Instant::now();
        }
    }

    // ----- guard toggles -------------------------------------------------

    fn toggle_shield(&mut self) {
        if self.shield.running() {
            self.shield.stop();
            return;
        }
        let Some(browser) = self.browsers.get(self.selected).cloned() else {
            self.log.warn("gui", "no browser selected to shield");
            return;
        };
        let log = self.log.clone();
        let armed = self.shield_armed;
        self.shield.start(move |stop| {
            browser_shield::run(browser, armed, &log, Duration::from_secs(2), stop);
        });
    }

    fn toggle_watchdog(&mut self) {
        if self.watchdog.running() {
            self.watchdog.stop();
            return;
        }
        let log = self.log.clone();
        let db = self.db.clone();
        let auto = self.watchdog_autokill;
        self.watchdog.start(move |stop| {
            watchdog::run(&db, &log, Duration::from_secs(1), auto, stop);
        });
    }

    fn toggle_clipper(&mut self) {
        if self.clipper.running() {
            self.clipper.stop();
            return;
        }
        let log = self.log.clone();
        let restore = self.clipper_restore;
        self.clipper.start(move |stop| {
            clipboard::run(&log, restore, stop);
        });
    }

    fn do_panic(&mut self) {
        self.log.alert("gui", "PANIC switch pressed — engaging quarantine");
        let _ = platform::network_release(&self.log);
        let _ = platform::flush_dns(&self.log);
        platform::kill_browsers_and_messengers(&self.log);
        platform::lock_session_files(&self.log);
        let _ = platform::firewall_block_c2_ports(&self.db, &self.log);
        self.quarantined = true;
    }

    fn do_release(&mut self) {
        self.log.action("gui", "releasing quarantine");
        let _ = platform::network_restore(&self.log);
        platform::unlock_session_files(&self.log);
        let _ = platform::firewall_reset(&self.db, &self.log);
        self.quarantined = false;
    }
}

impl eframe::App for ShieldApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.refresh_rss();

        // Header: identity, RAM gauge, panic button.
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading(RichText::new("🛡 667 Shield").strong());
                ui.label(RichText::new(format!("[{}]", shield667::platform_label())).weak());
                ui.separator();
                let ram_color = if self.rss_mb < 80.0 { Color32::LIGHT_GREEN } else { Color32::YELLOW };
                ui.label(RichText::new(format!("RAM: {:.1} MB", self.rss_mb)).color(ram_color).strong());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.quarantined {
                        if ui.button(RichText::new("↩ RELEASE").color(Color32::BLACK).strong())
                            .on_hover_text("Ağı ve oturumları geri yükle")
                            .clicked()
                        {
                            self.do_release();
                        }
                        ui.label(RichText::new("● QUARANTINED").color(Color32::RED).strong());
                    } else {
                        let panic = egui::Button::new(RichText::new("🚨 PANIC").color(Color32::WHITE).strong())
                            .fill(Color32::from_rgb(170, 20, 20));
                        if ui.add(panic).on_hover_text("Ağı kes, tarayıcıları kapat, oturum dosyalarını kilitle").clicked() {
                            self.do_panic();
                        }
                    }
                });
            });
            ui.add_space(4.0);
        });

        // Tab bar.
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Dashboard, "Panel");
                ui.selectable_value(&mut self.tab, Tab::BrowserShield, "Browser Shield");
                ui.selectable_value(&mut self.tab, Tab::Guards, "Kalkanlar");
                ui.selectable_value(&mut self.tab, Tab::Response, "Müdahale");
            });
        });

        // Live l0g at the bottom.
        egui::TopBottomPanel::bottom("l0g")
            .resizable(true)
            .default_height(220.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("l0g").strong());
                    ui.label(RichText::new(format!("{} event(s)", self.log.len())).weak());
                });
                ui.separator();
                egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                    for ev in &self.log.tail(300) {
                        let color = match ev.severity {
                            Severity::Info => Color32::GRAY,
                            Severity::Warn => Color32::from_rgb(230, 200, 60),
                            Severity::Alert => Color32::from_rgb(235, 80, 80),
                            Severity::Action => Color32::from_rgb(90, 200, 120),
                        };
                        ui.label(RichText::new(ev.to_string()).monospace().color(color));
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Dashboard => self.ui_dashboard(ui),
            Tab::BrowserShield => self.ui_browser_shield(ui),
            Tab::Guards => self.ui_guards(ui),
            Tab::Response => self.ui_response(ui),
        });

        // Live-ish refresh for the log without burning CPU at idle.
        ctx.request_repaint_after(Duration::from_millis(600));
    }
}

impl ShieldApp {
    fn ui_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.heading("Durum");
        ui.label(format!("İmza seti: v{}  ({} C2 alan adı, {} port)", self.db.version, self.db.c2_domains.len(), self.db.c2_ports.len()));
        ui.separator();
        ui.label(format!("Korunabilir tarayıcı: {}", self.browsers.len()));
        for b in &self.browsers {
            ui.label(format!("   • {} — {} gizli dosya", b.name, b.secret_files.len()));
        }
        ui.separator();
        ui.horizontal(|ui| {
            status_dot(ui, "Browser Shield", self.shield.running());
            status_dot(ui, "Process Watchdog", self.watchdog.running());
            status_dot(ui, "Clipboard Guard", self.clipper.running());
        });
        ui.add_space(8.0);
        ui.label(RichText::new(format!("Kendi bellek kullanımı: {:.1} MB", self.rss_mb)).weak());
        ui.label(RichText::new("(Ticari antivirüslerin aksine arka planda minimum RAM hedeflenir.)").weak().italics());
    }

    fn ui_browser_shield(&mut self, ui: &mut egui::Ui) {
        ui.heading("Browser Shield");
        ui.label("Seçili tarayıcının cookie / parola / anahtar dosyalarını korur. Tarayıcının kendisi dışında bir program bu dosyalara dokunduğu anda, o programı dondurur VE internetini keser — dosyayı okumuş olsa bile veriyi dışarı gönderemez.");
        ui.add_space(8.0);

        if self.browsers.is_empty() {
            ui.colored_label(Color32::YELLOW, "Gizli verisi olan tarayıcı bulunamadı.");
            if ui.button("Yeniden tara").clicked() {
                self.browsers = browsers::detect_installed();
            }
            return;
        }

        ui.horizontal(|ui| {
            let sel_name = self.browsers.get(self.selected).map(|b| b.name.clone()).unwrap_or_default();
            egui::ComboBox::from_label("Korunacak tarayıcı")
                .selected_text(sel_name)
                .show_ui(ui, |ui| {
                    for (i, b) in self.browsers.iter().enumerate() {
                        ui.selectable_value(&mut self.selected, i, &b.name);
                    }
                });
            if ui.button("⟳").on_hover_text("Tarayıcıları yeniden tara").clicked() {
                self.browsers = browsers::detect_installed();
                self.selected = 0;
            }
        });

        if let Some(b) = self.browsers.get(self.selected) {
            ui.add_space(6.0);
            ui.label(RichText::new("Korunan dosyalar:").strong());
            for f in &b.secret_files {
                ui.label(RichText::new(format!("   {}", f.display())).monospace().weak());
            }
        }

        ui.add_space(10.0);
        ui.checkbox(&mut self.shield_armed, "Koruma modu — izinsiz programı anında dondur ve internetini kes");

        ui.add_space(8.0);
        let running = self.shield.running();
        let (label, color) = if running {
            ("■ Korumayı Durdur", Color32::from_rgb(170, 20, 20))
        } else {
            ("▶ Korumayı Başlat", Color32::from_rgb(30, 120, 60))
        };
        if ui.add(egui::Button::new(RichText::new(label).color(Color32::WHITE).strong()).fill(color)).clicked() {
            self.toggle_shield();
        }
        ui.label(if running {
            RichText::new("● Browser Shield AKTİF").color(Color32::LIGHT_GREEN)
        } else {
            RichText::new("○ pasif").weak()
        });
    }

    fn ui_guards(&mut self, ui: &mut egui::Ui) {
        ui.heading("Arka Plan Kalkanları");

        ui.group(|ui| {
            ui.label(RichText::new("Process Watchdog").strong());
            ui.label("Çalışan süreçleri bilinen stealer/dropper imzalarına karşı tarar.");
            ui.checkbox(&mut self.watchdog_autokill, "Otomatik sonlandır (aksi halde yalnızca uyarır)");
            if ui.button(if self.watchdog.running() { "Durdur" } else { "Başlat" }).clicked() {
                self.toggle_watchdog();
            }
        });

        ui.add_space(8.0);
        ui.group(|ui| {
            ui.label(RichText::new("Clipboard Clipper Guard").strong());
            ui.label("Panoya kopyalanan kripto cüzdan adreslerinin aniden değiştirilmesini (clipper virüsü) tespit eder.");
            ui.checkbox(&mut self.clipper_restore, "Tespit edilince orijinal adresi geri yaz");
            if ui.button(if self.clipper.running() { "Durdur" } else { "Başlat" }).clicked() {
                self.toggle_clipper();
            }
        });
    }

    fn ui_response(&mut self, ui: &mut egui::Ui) {
        ui.heading("Müdahale & Karantina");
        ui.label("Acil durum şalteri üstteki kırmızı PANIC butonundadır. Bastığında:");
        ui.label("   1) Ağ bağlantısı düşürülür ve DNS önbelleği temizlenir");
        ui.label("   2) Tüm tarayıcılar ve mesajlaşma uygulamaları kapatılır");
        ui.label("   3) Discord / Telegram oturum dosyaları salt-okunur yapılır");
        ui.label("   4) (Windows) bilinen C2 portları için giden-engel kuralları eklenir");
        ui.add_space(8.0);
        if self.quarantined {
            ui.colored_label(Color32::RED, "● Sistem şu anda KARANTİNADA.");
            if ui.button("Karantinayı kaldır (geri yükle)").clicked() {
                self.do_release();
            }
        } else {
            ui.colored_label(Color32::LIGHT_GREEN, "○ Karantina aktif değil.");
        }
    }
}

fn status_dot(ui: &mut egui::Ui, label: &str, on: bool) {
    let c = if on { Color32::LIGHT_GREEN } else { Color32::DARK_GRAY };
    ui.label(RichText::new(format!("● {label}")).color(c));
}

impl Drop for ShieldApp {
    fn drop(&mut self) {
        self.shield.stop();
        self.watchdog.stop();
        self.clipper.stop();
    }
}
