//! Bounds how many failure records one source can write to the audit trail.
//!
//! Unauthenticated callers can provoke failure events at the connection rate (wrong token,
//! wrong origin, malformed messages). Each kind of failure from one address is recorded at most
//! [`PER_WINDOW`] times per [`WINDOW`]; the rest are counted and reported in one
//! `AuditSuppressed` record when the window ends, so the trail stays readable and still shows
//! that the flood happened.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Length of one counting window.
pub(crate) const WINDOW: Duration = Duration::from_secs(60);
/// Records per kind and address and window.
pub(crate) const PER_WINDOW: u32 = 20;
/// Addresses tracked per window; beyond that all new addresses share one counter (`None`), so
/// a spray of addresses cannot grow the table without bound.
const MAX_SOURCES: usize = 10_000;

/// Failures of one kind from one source that were not recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Suppressed {
    pub(crate) kind: &'static str,
    pub(crate) source: Option<IpAddr>,
    pub(crate) count: u32,
}

#[derive(Debug)]
struct Window {
    started: Instant,
    counts: HashMap<(&'static str, Option<IpAddr>), u32>,
}

/// Per-gateway failure throttle.
#[derive(Debug)]
pub(crate) struct FailureThrottle {
    window: Mutex<Window>,
}

impl FailureThrottle {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            window: Mutex::new(Window {
                started: now,
                counts: HashMap::new(),
            }),
        }
    }

    /// Counts one failure; `true` if it is to be recorded. Also returns what the previous
    /// window suppressed, when this call starts a new window.
    pub(crate) fn admit(
        &self,
        kind: &'static str,
        source: Option<IpAddr>,
        now: Instant,
    ) -> (bool, Vec<Suppressed>) {
        let Ok(mut w) = self.window.lock() else {
            return (true, Vec::new());
        };
        let summary = Self::roll(&mut w, now);
        let key = if w.counts.len() >= MAX_SOURCES && !w.counts.contains_key(&(kind, source)) {
            (kind, None)
        } else {
            (kind, source)
        };
        let count = w.counts.entry(key).or_insert(0);
        *count = count.saturating_add(1);
        (*count <= PER_WINDOW, summary)
    }

    /// Ends the window if it is over (called by the reaper, so a summary also appears when no
    /// further failure arrives).
    pub(crate) fn flush(&self, now: Instant) -> Vec<Suppressed> {
        self.window
            .lock()
            .map_or_default(|mut w| Self::roll(&mut w, now))
    }

    fn roll(w: &mut Window, now: Instant) -> Vec<Suppressed> {
        if now.saturating_duration_since(w.started) < WINDOW {
            return Vec::new();
        }
        w.started = now;
        w.counts
            .drain()
            .filter(|(_, c)| *c > PER_WINDOW)
            .map(|((kind, source), c)| Suppressed {
                kind,
                source,
                count: c.saturating_sub(PER_WINDOW),
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_floods_are_capped_per_source_and_summarised() {
        let t0 = Instant::now();
        let throttle = FailureThrottle::new(t0);
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();

        let admitted = (0..30)
            .filter(|_| throttle.admit("auth_failed", Some(a), t0).0)
            .count();
        assert_eq!(admitted, 20, "capped per window");
        assert!(
            throttle.admit("auth_failed", Some(b), t0).0,
            "other sources unaffected"
        );
        assert!(
            throttle.admit("policy_denied", Some(a), t0).0,
            "other kinds unaffected"
        );

        assert!(
            throttle.flush(t0 + Duration::from_secs(30)).is_empty(),
            "window not over"
        );
        let summary = throttle.flush(t0 + WINDOW);
        assert_eq!(
            summary,
            vec![Suppressed {
                kind: "auth_failed",
                source: Some(a),
                count: 10
            }]
        );
        assert!(
            throttle.admit("auth_failed", Some(a), t0 + WINDOW).0,
            "new window"
        );
    }

    #[test]
    fn test_address_spray_shares_one_counter() {
        let t0 = Instant::now();
        let throttle = FailureThrottle::new(t0);
        for i in 0..MAX_SOURCES {
            let ip = IpAddr::from(u32::try_from(i).unwrap().to_be_bytes());
            let _ = throttle.admit("auth_failed", Some(ip), t0);
        }
        let fresh: IpAddr = "198.51.100.7".parse().unwrap();
        let admitted = (0..50)
            .filter(|_| throttle.admit("auth_failed", Some(fresh), t0).0)
            .count();
        assert_eq!(
            admitted, 20,
            "beyond the table every new source shares one counter"
        );
    }
}
