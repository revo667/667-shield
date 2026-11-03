//! Discord webhook neutralizer — **detect + delete only**.
//!
//! When a Discord webhook URL is found embedded in malware on *this* machine,
//! it is an exfiltration channel pointed at the user. This module can:
//!   * parse a webhook URL into its id/token,
//!   * probe whether it is still live (GET),
//!   * delete it (DELETE) to close the channel — only when explicitly confirmed.
//!
//! It intentionally does NOT flood or "poison" the endpoint: sending fabricated
//! traffic to third-party infrastructure is an offensive act and out of scope
//! for a defensive tool.

use crate::log::EventLog;
use anyhow::{anyhow, Result};
use std::time::Duration;

/// A parsed Discord webhook reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookRef {
    pub id: String,
    pub token: String,
    /// Full canonical delete/probe URL.
    pub url: String,
}

/// Outcome of probing a webhook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// 2xx — the webhook exists and is accepting data.
    Live { name: Option<String> },
    /// 401/404 — already invalid or deleted.
    Dead,
    /// Network/other error — could not determine.
    Unknown(String),
}

/// Parse a Discord webhook URL. Accepts discord.com / discordapp.com and the
/// ptb/canary subdomains, with or without an API version segment.
pub fn parse(url: &str) -> Option<WebhookRef> {
    let re = crate::inspector::webhook_regex_str();
    let re = regex::Regex::new(re).ok()?;
    if !re.is_match(url) {
        return None;
    }
    // Pull id/token from the tail: .../webhooks/{id}/{token}
    let idx = url.find("/webhooks/")? + "/webhooks/".len();
    let tail = &url[idx..];
    let mut parts = tail.splitn(2, '/');
    let id = parts.next()?.to_string();
    let token = parts.next()?.to_string();
    if id.is_empty() || token.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    // Canonicalize to the stable API host/path for our own requests.
    let canonical = format!("https://discord.com/api/webhooks/{id}/{token}");
    Some(WebhookRef {
        id,
        token,
        url: canonical,
    })
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(8))
        .timeout_read(Duration::from_secs(10))
        .user_agent("667-Shield/0.1 (defensive)")
        .build()
}

/// Probe a webhook without altering it (GET).
pub fn probe(wh: &WebhookRef) -> Probe {
    match agent().get(&wh.url).call() {
        Ok(resp) => {
            let name = resp
                .into_json::<serde_json::Value>()
                .ok()
                .and_then(|v| v.get("name").and_then(|n| n.as_str().map(String::from)));
            Probe::Live { name }
        }
        Err(ureq::Error::Status(401 | 404, _)) => Probe::Dead,
        Err(ureq::Error::Status(code, _)) => Probe::Unknown(format!("HTTP {code}")),
        Err(ureq::Error::Transport(t)) => Probe::Unknown(t.to_string()),
    }
}

/// Delete (neutralize) a webhook. Requires `confirm = true`; a dry run only
/// logs what it *would* do. Returns Ok(true) if the channel is now gone.
pub fn delete(wh: &WebhookRef, confirm: bool, log: &EventLog) -> Result<bool> {
    if !confirm {
        log.warn(
            "webhook",
            format!("DRY RUN — would DELETE webhook id={} (channel left intact)", wh.id),
        );
        return Ok(false);
    }
    match agent().delete(&wh.url).call() {
        Ok(_) => {
            log.action("webhook", format!("neutralized webhook id={} (HTTP 2xx)", wh.id));
            Ok(true)
        }
        Err(ureq::Error::Status(401 | 404, _)) => {
            log.action(
                "webhook",
                format!("webhook id={} already dead/invalid — channel closed", wh.id),
            );
            Ok(true)
        }
        Err(ureq::Error::Status(code, _)) => {
            log.warn("webhook", format!("delete id={} returned HTTP {code}", wh.id));
            Err(anyhow!("unexpected HTTP {code} deleting webhook {}", wh.id))
        }
        Err(ureq::Error::Transport(t)) => {
            log.warn("webhook", format!("delete id={} transport error: {t}", wh.id));
            Err(anyhow!("transport error deleting webhook {}: {t}", wh.id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let wh = parse("https://discord.com/api/webhooks/123456789012345678/AbC-_dEf").unwrap();
        assert_eq!(wh.id, "123456789012345678");
        assert_eq!(wh.token, "AbC-_dEf");
        assert_eq!(
            wh.url,
            "https://discord.com/api/webhooks/123456789012345678/AbC-_dEf"
        );
    }

    #[test]
    fn parse_canary_with_version_canonicalizes() {
        let wh = parse("https://canary.discord.com/api/v10/webhooks/111/TOKEN").unwrap();
        assert_eq!(wh.id, "111");
        assert_eq!(wh.token, "TOKEN");
        // Canonical host/path regardless of input subdomain/version.
        assert_eq!(wh.url, "https://discord.com/api/webhooks/111/TOKEN");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse("https://discord.com/api/webhooks/notanumber/tok").is_none());
        assert!(parse("https://example.com/api/webhooks/1/2").is_none());
        assert!(parse("not a url").is_none());
        assert!(parse("https://discord.com/api/webhooks/123").is_none()); // no token
    }

    #[test]
    fn dry_run_does_not_claim_deletion() {
        let log = EventLog::new(false);
        let wh = parse("https://discord.com/api/webhooks/123456789012345678/tok").unwrap();
        let gone = delete(&wh, false, &log).unwrap();
        assert!(!gone);
        assert!(log.snapshot().iter().any(|e| e.message.contains("DRY RUN")));
    }

    // Live network tests are opt-in (require internet + a real webhook).
    #[test]
    #[ignore = "requires network"]
    fn probe_nonexistent_is_dead() {
        let wh = parse("https://discord.com/api/webhooks/1/definitelyinvalidtoken").unwrap();
        assert_eq!(probe(&wh), Probe::Dead);
    }
}
