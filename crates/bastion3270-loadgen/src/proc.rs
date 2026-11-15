//! Samples another process (the gateway under test) from `/proc` (Linux).

use std::time::{Duration, Instant};

/// One sample of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// Resident memory in KiB.
    pub rss_kib: u64,
    /// User + system CPU time used so far, in clock ticks.
    pub cpu_ticks: u64,
    /// Open file descriptors.
    pub fds: u64,
}

/// Reads one sample of `pid`; `None` if the process is gone or `/proc` is not available.
#[must_use]
pub fn sample(pid: u32) -> Option<Sample> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let rss_kib = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())?;
    // Fields 14 and 15 of /proc/<pid>/stat (utime, stime), after the parenthesised name.
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_name = stat.rsplit_once(')').map(|(_, rest)| rest)?;
    let fields: Vec<&str> = after_name.split_whitespace().collect();
    let tick = |i: usize| fields.get(i).and_then(|v| v.parse::<u64>().ok());
    let cpu_ticks = tick(11)?.saturating_add(tick(12)?);
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd")).map_or(0, |d| d.count() as u64);
    Some(Sample {
        rss_kib,
        cpu_ticks,
        fds,
    })
}

/// CPU usage between two samples, in cores (1.0 = one core busy), assuming 100 ticks/s.
#[must_use]
pub fn cpu_cores(before: (Instant, Sample), after: (Instant, Sample)) -> f64 {
    let wall = after.0.saturating_duration_since(before.0);
    if wall == Duration::ZERO {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let ticks = after.1.cpu_ticks.saturating_sub(before.1.cpu_ticks) as f64;
    ticks / 100.0 / wall.as_secs_f64()
}

/// The soft limit of open files of this process, if readable.
#[must_use]
pub fn open_files_limit() -> Option<u64> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    limits
        .lines()
        .find(|l| l.starts_with("Max open files"))
        .and_then(|l| l.split_whitespace().nth(3))
        .and_then(|v| v.parse().ok())
}
