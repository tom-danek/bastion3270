//! Operational metrics in the Prometheus text exposition format (version 0.0.4).
//!
//! Hand-written on atomics instead of a metrics library: a handful of counters and histograms
//! need no dependency, and every series is visible here. Labels come only from fixed sets
//! (result codes, close reasons, limit names, audit event names): never a subject, an address,
//! a profile description or screen content, so the endpoint cannot leak personal data.
//!
//! Served on the separate `server.metrics_bind` listener, never on the browser-facing port.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// A monotonically increasing count.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Adds one.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Current value.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Counters for a fixed set of label values; anything else counts as the last value
/// (`other`), so an unexpected value cannot create new series.
#[derive(Debug)]
pub struct LabeledCounter {
    label: &'static str,
    values: &'static [&'static str],
    counts: Box<[AtomicU64]>,
}

impl LabeledCounter {
    fn new(label: &'static str, values: &'static [&'static str]) -> Self {
        Self {
            label,
            values,
            counts: values.iter().map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// Adds one to the series of `value` (or of the last, catch-all value).
    pub fn inc(&self, value: &str) {
        let index = self
            .values
            .iter()
            .position(|v| *v == value)
            .unwrap_or(self.values.len().saturating_sub(1));
        if let Some(c) = self.counts.get(index) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Current value of one series.
    #[must_use]
    pub fn get(&self, value: &str) -> u64 {
        self.values
            .iter()
            .position(|v| *v == value)
            .and_then(|i| self.counts.get(i))
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }
}

/// A distribution of durations over fixed bucket bounds (seconds).
#[derive(Debug)]
pub struct Histogram {
    bounds: &'static [f64],
    /// One count per bound (observations `<=` that bound, not cumulative) plus `+Inf`.
    buckets: Box<[AtomicU64]>,
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            buckets: (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Records one observation.
    pub fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        let index = self
            .bounds
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(self.bounds.len());
        if let Some(b) = self.buckets.get(index) {
            b.fetch_add(1, Ordering::Relaxed);
        }
        let micros = u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of observations.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

/// Close reasons as series (the reaper's and the user's; host errors are one series).
pub const CLOSE_REASONS: &[&str] = &[
    "user",
    "expired",
    "idle",
    "lifetime",
    "identity_expired",
    "shutdown",
    "host",
    "host_error",
    "other",
];

/// Outcome of `open` as series: `ok` or the wire error code.
pub const OPEN_RESULTS: &[&str] = &[
    "ok",
    "unknown_profile",
    "forbidden",
    "limit_exceeded",
    "auth_failed",
    "connect_failed",
    "store_failed",
    "internal_error",
    "shutting_down",
    "invalid_options",
    "other",
];

/// Limits that refused something.
pub const LIMITS: &[&str] = &[
    "sessions",
    "sessions_per_identity",
    "connections",
    "pending_handshakes",
    "message_rate",
    "other",
];

/// Audit event names (see `SessionAuditKind::name`).
pub const AUDIT_EVENTS: &[&str] = &[
    "auth_failed",
    "auth_succeeded",
    "policy_denied",
    "opened",
    "resumed",
    "detached",
    "auto_logon",
    "closed",
    "connect_failed",
    "messages_rejected",
    "audit_suppressed",
    "screen_printed",
    "other",
];

/// All metrics of one gateway process.
#[derive(Debug)]
pub struct Metrics {
    /// `open` outcomes.
    pub sessions_opened: LabeledCounter,
    /// Successful resumes.
    pub sessions_resumed: Counter,
    /// Closed sessions by reason.
    pub sessions_closed: LabeledCounter,
    /// Time to connect and negotiate with the host when opening a session.
    pub host_connect: Histogram,
    /// Inbound WebSocket messages after the handshake.
    pub ws_messages: Counter,
    /// Frames sent to browsers.
    pub frames_sent: Counter,
    /// AIDs (Enter, PF keys …) sent to hosts.
    pub aids: Counter,
    /// Operator AID until the keyboard is unlocked again (the host answered).
    pub aid_response: Histogram,
    /// Refusals by limit.
    pub limit_rejections: LabeledCounter,
    /// Audit records by event (after the failure cap).
    pub audit_events: LabeledCounter,
    /// Open WebSocket connections (handshake or attached).
    ws_connections: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            sessions_opened: LabeledCounter::new("result", OPEN_RESULTS),
            sessions_resumed: Counter::default(),
            sessions_closed: LabeledCounter::new("reason", CLOSE_REASONS),
            host_connect: Histogram::new(&[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            ws_messages: Counter::default(),
            frames_sent: Counter::default(),
            aids: Counter::default(),
            aid_response: Histogram::new(&[
                0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            ]),
            limit_rejections: LabeledCounter::new("limit", LIMITS),
            audit_events: LabeledCounter::new("event", AUDIT_EVENTS),
            ws_connections: AtomicU64::new(0),
        }
    }
}

/// Counts an open WebSocket connection while it lives.
#[derive(Debug)]
pub struct ConnectionGuard<'a>(&'a Metrics);

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        // Paired with the increment in `ws_connection`; never below zero.
        let _ = self
            .0
            .ws_connections
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }
}

/// Values read at scrape time from the gateway.
#[derive(Debug, Clone, Copy, Default)]
pub struct Live {
    /// Sessions with an attached browser.
    pub attached: usize,
    /// Sessions waiting in the detach grace period.
    pub detached: usize,
}

impl Metrics {
    /// Counts an open WebSocket connection until the guard is dropped.
    #[must_use]
    pub fn ws_connection(&self) -> ConnectionGuard<'_> {
        self.ws_connections.fetch_add(1, Ordering::Relaxed);
        ConnectionGuard(self)
    }

    /// The close reason as a series name (free-text error reasons collapse to `host_error`).
    #[must_use]
    pub fn close_reason(reason: &str) -> &'static str {
        if reason.starts_with("error:") {
            return "host_error";
        }
        if reason == "host disconnected" {
            return "host";
        }
        if reason == "server shutdown" {
            return "shutdown";
        }
        CLOSE_REASONS
            .iter()
            .find(|r| **r == reason)
            .copied()
            .unwrap_or("other")
    }

    /// Renders every series in the Prometheus text format.
    #[must_use]
    pub fn render(&self, live: Live, version: &str) -> String {
        let mut out = String::with_capacity(4096);
        gauge(&mut out, "bastion3270_build_info", "Build information.");
        let _ = writeln!(out, "bastion3270_build_info{{version=\"{version}\"}} 1");
        gauge(&mut out, "bastion3270_sessions", "Live mainframe sessions.");
        let _ = writeln!(
            out,
            "bastion3270_sessions{{state=\"attached\"}} {}",
            live.attached
        );
        let _ = writeln!(
            out,
            "bastion3270_sessions{{state=\"detached\"}} {}",
            live.detached
        );
        gauge(
            &mut out,
            "bastion3270_websocket_connections",
            "Open WebSocket connections.",
        );
        let _ = writeln!(
            out,
            "bastion3270_websocket_connections {}",
            self.ws_connections.load(Ordering::Relaxed)
        );
        labeled(
            &mut out,
            "bastion3270_sessions_opened_total",
            "Session opens by result.",
            &self.sessions_opened,
        );
        counter(
            &mut out,
            "bastion3270_sessions_resumed_total",
            "Successful session resumes.",
            &self.sessions_resumed,
        );
        labeled(
            &mut out,
            "bastion3270_sessions_closed_total",
            "Closed sessions by reason.",
            &self.sessions_closed,
        );
        histogram(
            &mut out,
            "bastion3270_host_connect_seconds",
            "Time to connect to the host and negotiate when opening a session.",
            &self.host_connect,
        );
        counter(
            &mut out,
            "bastion3270_websocket_messages_total",
            "Inbound WebSocket messages after the handshake.",
            &self.ws_messages,
        );
        counter(
            &mut out,
            "bastion3270_frames_sent_total",
            "Frames sent to browsers.",
            &self.frames_sent,
        );
        counter(
            &mut out,
            "bastion3270_aids_total",
            "AIDs sent to hosts.",
            &self.aids,
        );
        histogram(
            &mut out,
            "bastion3270_aid_response_seconds",
            "From an operator AID until the keyboard is unlocked again (the host answered).",
            &self.aid_response,
        );
        labeled(
            &mut out,
            "bastion3270_limit_rejections_total",
            "Refusals by limit.",
            &self.limit_rejections,
        );
        labeled(
            &mut out,
            "bastion3270_audit_events_total",
            "Audit records written, by event.",
            &self.audit_events,
        );
        out
    }
}

fn gauge(out: &mut String, name: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge");
}

fn counter(out: &mut String, name: &str, help: &str, c: &Counter) {
    let _ = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}",
        c.get()
    );
}

fn labeled(out: &mut String, name: &str, help: &str, c: &LabeledCounter) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
    for (value, count) in c.values.iter().zip(c.counts.iter()) {
        let _ = writeln!(
            out,
            "{name}{{{}=\"{value}\"}} {}",
            c.label,
            count.load(Ordering::Relaxed)
        );
    }
}

fn histogram(out: &mut String, name: &str, help: &str, h: &Histogram) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} histogram");
    let mut cumulative: u64 = 0;
    for (bound, bucket) in h.bounds.iter().zip(h.buckets.iter()) {
        cumulative = cumulative.saturating_add(bucket.load(Ordering::Relaxed));
        let _ = writeln!(out, "{name}_bucket{{le=\"{bound}\"}} {cumulative}");
    }
    if let Some(inf) = h.buckets.get(h.bounds.len()) {
        cumulative = cumulative.saturating_add(inf.load(Ordering::Relaxed));
    }
    let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {cumulative}");
    // Microseconds as seconds; precision of a float is plenty for a sum of latencies.
    #[allow(clippy::cast_precision_loss)]
    let sum = h.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let _ = writeln!(out, "{name}_sum {sum}\n{name}_count {}", h.count());
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_histogram_buckets_are_cumulative() {
        let m = Metrics::default();
        m.aid_response.observe(Duration::from_micros(500)); // <= 0.001
        m.aid_response.observe(Duration::from_millis(30)); // <= 0.05
        m.aid_response.observe(Duration::from_secs(9)); // +Inf
        let text = m.render(Live::default(), "1.2.3");
        assert!(text.contains("bastion3270_aid_response_seconds_bucket{le=\"0.001\"} 1\n"));
        assert!(text.contains("bastion3270_aid_response_seconds_bucket{le=\"0.05\"} 2\n"));
        assert!(text.contains("bastion3270_aid_response_seconds_bucket{le=\"2.5\"} 2\n"));
        assert!(text.contains("bastion3270_aid_response_seconds_bucket{le=\"+Inf\"} 3\n"));
        assert!(text.contains("bastion3270_aid_response_seconds_count 3\n"));
        assert!(text.contains("bastion3270_aid_response_seconds_sum 9.0305\n"));
    }

    #[test]
    fn test_unknown_label_values_do_not_create_series() {
        let m = Metrics::default();
        m.sessions_closed.inc(Metrics::close_reason(
            "error: TLS alert from lpar1.internal",
        ));
        m.sessions_closed.inc(Metrics::close_reason("idle"));
        m.sessions_closed
            .inc(Metrics::close_reason("something new"));
        let text = m.render(Live::default(), "1");
        assert!(text.contains("bastion3270_sessions_closed_total{reason=\"host_error\"} 1\n"));
        assert!(text.contains("bastion3270_sessions_closed_total{reason=\"idle\"} 1\n"));
        assert!(text.contains("bastion3270_sessions_closed_total{reason=\"other\"} 1\n"));
        assert!(!text.contains("lpar1"), "free text never becomes a label");
    }

    #[test]
    fn test_connection_gauge_follows_guards() {
        let m = Metrics::default();
        let a = m.ws_connection();
        let b = m.ws_connection();
        assert!(m
            .render(Live::default(), "1")
            .contains("bastion3270_websocket_connections 2\n"));
        drop(a);
        drop(b);
        assert!(m
            .render(Live::default(), "1")
            .contains("bastion3270_websocket_connections 0\n"));
    }
}
