//! Clipboard clipper guard.
//!
//! "Clipper" malware watches the clipboard and, the instant the user copies a
//! crypto wallet address, silently swaps it for the attacker's address so funds
//! are sent to the wrong place. We defend by watching the clipboard ourselves:
//! when an address is replaced by a *different* address of the same kind within
//! a superhuman time window, that is the clipper signature — we flag it and can
//! restore the original address.
//!
//! The detection state machine ([`ClipperGuard`]) is pure and unit-tested; the
//! [`run`] loop wires it to the real clipboard via `arboard`.

use crate::log::EventLog;
use regex::Regex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Bitcoin,
    Ethereum,
    Tron,
}

impl Chain {
    fn label(self) -> &'static str {
        match self {
            Chain::Bitcoin => "BTC",
            Chain::Ethereum => "ETH",
            Chain::Tron => "TRON",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub chain: Chain,
    pub value: String,
}

fn btc_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^(bc1[a-z0-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$").unwrap())
}
fn eth_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^0x[a-fA-F0-9]{40}$").unwrap())
}
fn tron_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^T[A-Za-z1-9]{33}$").unwrap())
}

/// Classify clipboard text as a crypto address, if it is exactly one.
pub fn classify(text: &str) -> Option<Address> {
    let t = text.trim();
    if eth_re().is_match(t) {
        return Some(Address { chain: Chain::Ethereum, value: t.to_string() });
    }
    if tron_re().is_match(t) {
        return Some(Address { chain: Chain::Tron, value: t.to_string() });
    }
    if btc_re().is_match(t) {
        return Some(Address { chain: Chain::Bitcoin, value: t.to_string() });
    }
    None
}

/// What the guard decides after observing a clipboard change.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Nothing interesting.
    Ignore,
    /// A crypto address was copied; now being tracked.
    Tracking(Address),
    /// A clipper swap was detected: `original` should be restored in place of
    /// `swapped`.
    Hijack { original: Address, swapped: Address },
}

/// Pure clipper-detection state machine, parameterized by a monotonic clock so
/// it can be tested deterministically.
pub struct ClipperGuard {
    last_addr: Option<(Address, u128)>, // (address, timestamp_ms)
    /// Maximum gap between copy and swap to count as a clipper (ms).
    window_ms: u128,
}

impl ClipperGuard {
    pub fn new(window: Duration) -> Self {
        Self { last_addr: None, window_ms: window.as_millis() }
    }

    /// Feed a new clipboard value observed at `now_ms` (monotonic ms).
    pub fn observe(&mut self, content: &str, now_ms: u128) -> Decision {
        match classify(content) {
            None => {
                // Non-address content clears tracking (user copied something else).
                self.last_addr = None;
                Decision::Ignore
            }
            Some(addr) => {
                let decision = match &self.last_addr {
                    Some((prev, t0))
                        if prev.chain == addr.chain
                            && prev.value != addr.value
                            && now_ms.saturating_sub(*t0) <= self.window_ms =>
                    {
                        Decision::Hijack { original: prev.clone(), swapped: addr.clone() }
                    }
                    _ => Decision::Tracking(addr.clone()),
                };
                self.last_addr = Some((addr, now_ms));
                decision
            }
        }
    }
}

/// Run the clipboard guard loop until `stop` is set. On a detected hijack it
/// logs the event and, if `restore` is set, writes the original address back.
pub fn run(log: &EventLog, restore: bool, stop: Arc<AtomicBool>) {
    let mut clip = match arboard::Clipboard::new() {
        Ok(c) => c,
        Err(e) => {
            log.warn("clipper", format!("clipboard unavailable: {e}"));
            return;
        }
    };
    let mut guard = ClipperGuard::new(Duration::from_millis(1500));
    let t0 = Instant::now();
    let mut last_text = String::new();
    log.info("clipper", format!("clipboard clipper guard started (restore={restore})"));
    while !stop.load(Ordering::Relaxed) {
        if let Ok(text) = clip.get_text() {
            if text != last_text {
                last_text = text.clone();
                let now_ms = t0.elapsed().as_millis();
                match guard.observe(&text, now_ms) {
                    Decision::Hijack { original, swapped } => {
                        log.alert(
                            "clipper",
                            format!(
                                "CLIPBOARD HIJACK ({}) — {} swapped to {}",
                                original.chain.label(),
                                short(&original.value),
                                short(&swapped.value)
                            ),
                        );
                        if restore {
                            if clip.set_text(original.value.clone()).is_ok() {
                                last_text = original.value.clone();
                                log.action("clipper", "restored original wallet address");
                            } else {
                                log.warn("clipper", "failed to restore clipboard");
                            }
                        }
                    }
                    Decision::Tracking(a) => {
                        log.info("clipper", format!("tracking {} address {}", a.chain.label(), short(&a.value)));
                    }
                    Decision::Ignore => {}
                }
            }
        }
        sleep_interruptible(Duration::from_millis(400), &stop);
    }
    log.info("clipper", "clipboard clipper guard stopped");
}

fn short(s: &str) -> String {
    if s.len() <= 14 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..8], &s[s.len() - 6..])
    }
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

    const BTC_A: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    const BTC_B: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    const ETH_A: &str = "0x52908400098527886E0F7030069857D2E4169EE7";
    const SEGWIT: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    #[test]
    fn classifies_chains() {
        assert_eq!(classify(BTC_A).unwrap().chain, Chain::Bitcoin);
        assert_eq!(classify(SEGWIT).unwrap().chain, Chain::Bitcoin);
        assert_eq!(classify(ETH_A).unwrap().chain, Chain::Ethereum);
        assert_eq!(classify("TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbeV9").unwrap().chain, Chain::Tron);
        assert!(classify("hello world").is_none());
        assert!(classify("just some text 0x123").is_none());
    }

    #[test]
    fn detects_fast_swap_as_hijack() {
        let mut g = ClipperGuard::new(Duration::from_millis(1500));
        assert_eq!(g.observe(BTC_A, 0), Decision::Tracking(classify(BTC_A).unwrap()));
        match g.observe(BTC_B, 300) {
            Decision::Hijack { original, swapped } => {
                assert_eq!(original.value, BTC_A);
                assert_eq!(swapped.value, BTC_B);
            }
            other => panic!("expected hijack, got {other:?}"),
        }
    }

    #[test]
    fn slow_change_is_not_hijack() {
        let mut g = ClipperGuard::new(Duration::from_millis(1500));
        g.observe(BTC_A, 0);
        // 5 seconds later — a human deliberately copying a new address.
        assert!(matches!(g.observe(BTC_B, 5000), Decision::Tracking(_)));
    }

    #[test]
    fn cross_chain_change_is_not_hijack() {
        let mut g = ClipperGuard::new(Duration::from_millis(1500));
        g.observe(BTC_A, 0);
        // A clipper swaps like-for-like; BTC->ETH within window is not the signature.
        assert!(matches!(g.observe(ETH_A, 100), Decision::Tracking(_)));
    }

    #[test]
    fn non_address_clears_tracking() {
        let mut g = ClipperGuard::new(Duration::from_millis(1500));
        g.observe(BTC_A, 0);
        assert_eq!(g.observe("some note", 100), Decision::Ignore);
        // Now a different BTC address should be fresh tracking, not a hijack.
        assert!(matches!(g.observe(BTC_B, 200), Decision::Tracking(_)));
    }
}
