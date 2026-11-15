//! Shared counters and latency samples of one load run.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Collected by all simulated browsers.
#[derive(Debug, Default)]
pub struct Stats {
    pub(crate) opened: AtomicU64,
    pub(crate) active: AtomicU64,
    pub(crate) failed: Mutex<BTreeMap<String, u64>>,
    pub(crate) ended: Mutex<BTreeMap<String, u64>>,
    pub(crate) latencies_us: Mutex<Vec<u64>>,
    pub(crate) frames: AtomicU64,
}

impl Stats {
    pub(crate) fn fail(&self, why: &str) {
        if let Ok(mut f) = self.failed.lock() {
            *f.entry(why.to_owned()).or_insert(0) += 1;
        }
    }

    /// The gateway ended a session (`closed`) with `reason`.
    pub(crate) fn end(&self, reason: &str) {
        if let Ok(mut e) = self.ended.lock() {
            *e.entry(reason.to_owned()).or_insert(0) += 1;
        }
    }

    pub(crate) fn latency(&self, d: Duration) {
        if let Ok(mut l) = self.latencies_us.lock() {
            l.push(u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
        }
    }

    /// The measurements so far.
    #[must_use]
    pub fn report(&self, elapsed: Duration) -> Report {
        let mut lat = self.latencies_us.lock().map_or_default(|l| l.clone());
        lat.sort_unstable();
        let pct = |p: usize| -> Duration {
            let i = (lat.len().saturating_mul(p) / 100).min(lat.len().saturating_sub(1));
            Duration::from_micros(lat.get(i).copied().unwrap_or(0))
        };
        Report {
            elapsed,
            opened: self.opened.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            failed: self.failed.lock().map_or_default(|f| f.clone()),
            ended: self.ended.lock().map_or_default(|e| e.clone()),
            actions: lat.len() as u64,
            frames: self.frames.load(Ordering::Relaxed),
            p50: pct(50),
            p95: pct(95),
            p99: pct(99),
            max: Duration::from_micros(lat.last().copied().unwrap_or(0)),
        }
    }
}

/// Result of a run (or a sample during it).
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Time since the start.
    pub elapsed: Duration,
    /// Sessions that were opened successfully.
    pub opened: u64,
    /// Sessions open right now.
    pub active: u64,
    /// Failures by kind (error code from the gateway, `connect`, `timeout`, `dropped` …).
    pub failed: BTreeMap<String, u64>,
    /// Sessions the gateway ended (`closed`), by its reason (`lifetime`, `idle`, …).
    pub ended: BTreeMap<String, u64>,
    /// Measured Enter → screen round trips.
    pub actions: u64,
    /// Frames received.
    pub frames: u64,
    /// Latency percentiles of the round trips.
    pub p50: Duration,
    /// 95th percentile.
    pub p95: Duration,
    /// 99th percentile.
    pub p99: Duration,
    /// Slowest round trip.
    pub max: Duration,
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let failed: u64 = self.failed.values().sum();
        write!(
            f,
            "t={:>5.0}s opened={} active={} failed={} actions={} frames={} \
             enter->screen p50={:.1}ms p95={:.1}ms p99={:.1}ms max={:.1}ms",
            self.elapsed.as_secs_f64(),
            self.opened,
            self.active,
            failed,
            self.actions,
            self.frames,
            ms(self.p50),
            ms(self.p95),
            ms(self.p99),
            ms(self.max)
        )?;
        if !self.failed.is_empty() {
            write!(f, " {:?}", self.failed)?;
        }
        if !self.ended.is_empty() {
            write!(f, " ended={:?}", self.ended)?;
        }
        Ok(())
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
