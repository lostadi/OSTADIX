//! Best-effort process-lifecycle tracing shared by every root.
//!
//! `O_LIFECYCLE_TRACE` names the trace file. This root depends only on the
//! progress writer, so low roots can trace without reaching up into process.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
#[cfg(not(unix))]
use std::sync::OnceLock;
#[cfg(not(unix))]
use std::time::Instant;

static LIFECYCLE_TRACE_LOCK: Mutex<()> = Mutex::new(());

/// Append one best-effort process-lifecycle event when diagnostics are enabled.
///
/// `O_LIFECYCLE_TRACE` names the trace file. Events intentionally contain no
/// source or value payloads, and tracing failure never changes execution.
pub(crate) fn lifecycle_trace(event: &str, detail: impl AsRef<str>) {
    let Some(path) = std::env::var_os("O_LIFECYCLE_TRACE") else {
        return;
    };
    let detail = detail.as_ref().replace(['\n', '\r'], " ");
    let line = format!(
        "monotonic_ns={} pid={} thread={:?} event={} {}\n",
        monotonic_nanos(),
        std::process::id(),
        std::thread::current().id(),
        event,
        detail,
    );
    // a trace aimed at stderr goes through the one status writer, so it never
    // lands inside the spinner line.
    if path == "-" || path == "/dev/stderr" || path == "/proc/self/fd/2" {
        crate::progress::line(line.trim_end_matches('\n'));
        return;
    }
    let _guard = LIFECYCLE_TRACE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(parent) = Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(line.as_bytes());
    }
}

#[cfg(unix)]
pub(crate) fn monotonic_nanos() -> u128 {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `timestamp` is valid writable storage for one `timespec`, and
    // CLOCK_MONOTONIC requires no additional caller-managed lifetime.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timestamp) } == 0 {
        (timestamp.tv_sec as u128)
            .saturating_mul(1_000_000_000)
            .saturating_add(timestamp.tv_nsec as u128)
    } else {
        0
    }
}

#[cfg(not(unix))]
pub(crate) fn monotonic_nanos() -> u128 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos()
}
