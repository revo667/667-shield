//! Thread-safe event log — the backend behind the "l0g" screen.
//!
//! Every subsystem reports here. The GUI (later) subscribes by draining
//! `snapshot()`; the CLI prints events as they are pushed.

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    /// Routine activity, no action needed.
    Info,
    /// Something worth a human glance.
    Warn,
    /// Confirmed or strongly-suspected malicious activity.
    Alert,
    /// A defensive action the shield just took.
    Action,
}

impl Severity {
    pub fn tag(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Alert => "ALERT",
            Severity::Action => "ACTION",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub at: DateTime<Local>,
    pub severity: Severity,
    /// Subsystem that produced the event, e.g. "watchdog", "clipper".
    pub source: String,
    pub message: String,
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {:<6} {:<10} {}",
            self.at.format("%H:%M:%S"),
            self.severity.tag(),
            self.source,
            self.message
        )
    }
}

/// Clonable handle to a shared event log. Cheap to clone; all clones share
/// one buffer, so subsystems on different threads report into the same log.
#[derive(Clone)]
pub struct EventLog {
    /// Ring buffer: dropping the oldest event is O(1) once at capacity.
    inner: Arc<Mutex<VecDeque<Event>>>,
    /// When true, events are also printed to stderr as they arrive (CLI mode).
    echo: bool,
    cap: usize,
}

impl EventLog {
    pub fn new(echo: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            echo,
            cap: 5000,
        }
    }

    pub fn push(&self, severity: Severity, source: &str, message: impl Into<String>) {
        let ev = Event {
            at: Local::now(),
            severity,
            source: source.to_string(),
            message: message.into(),
        };
        if self.echo {
            eprintln!("{ev}");
        }
        // A poisoned lock means another thread panicked while holding it; the
        // log is non-critical, so recover the guard and keep running.
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.push_back(ev);
        while g.len() > self.cap {
            g.pop_front();
        }
    }

    pub fn info(&self, source: &str, m: impl Into<String>) {
        self.push(Severity::Info, source, m)
    }
    pub fn warn(&self, source: &str, m: impl Into<String>) {
        self.push(Severity::Warn, source, m)
    }
    pub fn alert(&self, source: &str, m: impl Into<String>) {
        self.push(Severity::Alert, source, m)
    }
    pub fn action(&self, source: &str, m: impl Into<String>) {
        self.push(Severity::Action, source, m)
    }

    /// A copy of all buffered events (for the GUI to render).
    pub fn snapshot(&self) -> Vec<Event> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// A copy of only the newest `n` events, oldest first — what a polling
    /// view needs, without cloning the whole buffer each time.
    pub fn tail(&self, n: usize) -> Vec<Event> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.iter().skip(g.len().saturating_sub(n)).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_snapshot() {
        let log = EventLog::new(false);
        log.info("test", "hello");
        log.alert("test", "danger");
        let snap = log.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].severity, Severity::Info);
        assert_eq!(snap[1].severity, Severity::Alert);
        assert_eq!(snap[1].message, "danger");
    }

    #[test]
    fn shared_across_clones() {
        let a = EventLog::new(false);
        let b = a.clone();
        a.info("a", "from a");
        b.info("b", "from b");
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn respects_capacity() {
        let mut log = EventLog::new(false);
        log.cap = 10;
        for i in 0..25 {
            log.info("t", format!("{i}"));
        }
        assert_eq!(log.len(), 10);
        // Oldest dropped: first remaining should be "15".
        assert_eq!(log.snapshot()[0].message, "15");
    }

    #[test]
    fn tail_returns_newest_in_order() {
        let log = EventLog::new(false);
        for i in 0..5 {
            log.info("t", format!("{i}"));
        }
        let msgs: Vec<String> = log.tail(2).into_iter().map(|e| e.message).collect();
        assert_eq!(msgs, ["3", "4"]);
        assert_eq!(log.tail(50).len(), 5);
    }
}
