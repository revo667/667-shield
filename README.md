# 667 Shield

Cross-platform, low-footprint **anti-stealer / anti-RAT guard**. It defends
browser secrets — Chrome/Chromium & Firefox cookies, saved passwords and
encryption keys — plus crypto clipboard and Discord exfiltration channels,
against infostealers and RATs. It also includes a **DPI-bypass** feature so
users (in Turkey and elsewhere) can reach ISP-blocked sites like Discord,
Roblox and Wattpad. Written in Rust; the modern UI runs in your own browser, so
the shield process itself idles around ~15 MB — a fraction of a commercial AV.

> Defensive only. It detects and contains threats to **your own** machine. It
> deliberately does **not** attack anyone's infrastructure (no webhook
> "poisoning" / flooding) — it only neutralizes exfil channels found locally.

## Layers

| Layer | What it does |
|-------|--------------|
| **Browser Shield** | Watches a selected browser's secret files (Cookies, Login Data, Local State, …). If any process that is *not* the browser opens them, it **contains** that process — freezes it *and* cuts its internet — so even a file it already read cannot be sent out. Installed browsers are auto-detected. |
| **Process Watchdog** | Scans running processes against a known stealer/dropper signature set; on a match it contains the process (freeze + internet cut) immediately, and optionally terminates it. |
| **Exfil block** | Known anonymous upload/paste hosts that stealers use to ship stolen data (gofile, transfer.sh, api.telegram.org, …) are null-routed system-wide, alongside C2 domains. |
| **Clipboard Clipper Guard** | Detects "clipper" malware swapping a copied BTC/ETH/TRON address for the attacker's, and restores the original. |
| **Static Inspector** | SHA-256, Shannon entropy (packer/cryptor detection), and extraction of embedded Discord webhooks / C2 URLs — without running the file. |
| **Deep Scanner** | Walks temp/AppData/cache dirs for files carrying embedded webhooks or known-C2 URLs. |
| **Webhook Neutralizer** | Probes and (on `--confirm`) **deletes** Discord webhooks found embedded in local malware. Detect + delete only. |
| **C2 Null-Routing** | Points known C2 domains at `0.0.0.0` in the hosts file (reversible "DNS factory reset"). |
| **Panic Switch** | Drops the network, flushes DNS, kills browsers/messengers, locks Discord/Telegram session stores read-only, and (Windows) adds outbound C2 port blocks. Fully reversible. |
| **EDR freeze** | Suspend/resume a process for analysis (SIGSTOP/SIGCONT on Unix). |
| **DPI Bypass** | Runs the vendored GoodbyeDPI engine (`-5 --blacklist`) so ISP deep-packet-inspection can't keep you off Discord / Roblox / Wattpad. Windows only. See [Credits](#credits--thanks). |

## Build & run

```sh
cargo build --release
```

On Windows this produces `target\release\shield667.exe`. **Double-click it**:
background protection starts (process watchdog, Browser Shield for the first
detected browser, clipboard guard) and the dashboard opens in your browser. A
console window stays open showing what the shield does; closing it stops the
protection. Opening the exe again while it runs just shows the dashboard of
the running shield instead of starting a second one. Guards that change the
system (hosts null-routing, deception, DPI bypass, panic) stay off until you
turn them on in the dashboard.

```sh
# Same from a terminal (any platform)
./target/release/shield667            # = shield667 run
./target/release/shield667 ui         # dashboard only, all guards off

# Or drive it from the command line
./target/release/shield667 status
./target/release/shield667 browsers
./target/release/shield667 inspect ./suspect.exe
./target/release/shield667 shield "Google Chrome" --arm   # Browser Shield, foreground
./target/release/shield667 scan                           # temp/appdata webhook hunt
```

The UI is a small local web server (127.0.0.1:6670) serving a single dashboard;
it renders in a browser you already have open, which is why the shield stays
tiny in RAM. A legacy native window is still available behind a cargo feature
(`cargo run --release --features gui --bin shield667-gui`).

Some actions need elevated rights: `hosts enable/disable`, the panic switch and
Windows firewall rules require admin/root.

## Platform status

| Capability | macOS / Linux | Windows |
|------------|---------------|---------|
| Browser detection, inspector, scanner, clipper, watchdog, webhook, hosts | ✅ | ✅ |
| Browser Shield open-handle detection | ✅ (`lsof`) | ✅ (Restart Manager) |
| Process freeze/resume | ✅ (SIGSTOP/CONT) | ✅ (`NtSuspendProcess`/`NtResumeProcess`) |
| Panic network/DNS/session-lock | ✅ | ✅ |
| Firewall C2 port block | ⏳ pf/nftables module planned | ✅ (`netsh`) |
| DPI bypass (Discord/Roblox/Wattpad) | — (not applicable) | ✅ (GoodbyeDPI + WinDivert, needs admin) |

"⏳ planned" items return a clear error rather than pretending to act.

## Low-RAM design

- One shared `sysinfo::System` reused across scans, refreshing only process
  names and exe paths (no per-process CPU/memory/disk sampling); bounded (5k)
  ring-buffer log.
- Guards poll on intervals (watchdog 1 s, shield/clipper ~0.4–2 s) rather than
  hooking everything; no continuous full-disk scanning.
- Files are inspected and scanned in 64 KB chunks, so memory stays flat no
  matter how large the file is.
- The dashboard poll is cheap: slow status (process scan, registry, hosts) is
  cached and re-read only after a change or every 10 s, only the newest 300
  log lines are sent, and polling pauses while the tab is hidden.
- The UI renders in your existing browser via a tiny local server, so the
  shield process holds ~15 MB resident instead of bundling a GUI runtime.
- The legacy native window is behind the `gui` cargo feature; the default build
  pulls no desktop-GUI crates.

## Signatures

`src/signatures/default.json` is the embedded baseline (C2 domains, ports,
stealer process indicators). It is a starting point, not an exhaustive
blocklist, and can be extended/overridden with a runtime JSON file.

## Tests

`cargo test` — 64 unit tests cover the pure logic (entropy, hashing, IOC
extraction, hosts-file editing and factory reset, clipper state machine, lsof
parsing, browser file selection and legitimate-process checks, deception
revert bookkeeping, session-lock permissions, UI request gating, DPI vendor
resolution). Network-dependent tests are `#[ignore]`d.

## Credits & thanks

The DPI-bypass feature stands entirely on other people's open-source work, and
we're grateful for it:

- **[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)** by **ValdikSS**
  (Apache-2.0) — the DPI-circumvention engine. Its binaries (and the bundled
  **WinDivert** driver by Basil00, LGPLv3/GPLv3) are vendored unmodified under
  [`vendor/goodbyedpi/`](vendor/goodbyedpi/VENDOR.md).
- **[SplitWire-Turkey](https://github.com/cagritaskn/SplitWire-Turkey)** by
  **cagritaskn** (MIT) — the Turkey-focused restriction-bypass tool that
  inspired this feature and its Discord/Roblox/Wattpad default list.

Teşekkürler **ValdikSS** ve **cagritaskn** — lütfen asıl projelerini de
destekleyin. Full upstream licenses are kept in `vendor/goodbyedpi/licenses/`.
