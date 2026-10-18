//! The opt-in step limit and the hang-warning knobs, shared by backend step
//! waits (process) and native leaf child waits (native_leaf).
//!
//! why its own root: native_leaf sits below process, so the parsing both need
//! lives here, with no crate dependencies. every knob is parsed once per
//! process; a malformed, zero or oversized value is a hard error rather than
//! a silent fallback, because a knob the user set and the runtime ignored is
//! a silent failure.

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};

// why there is no default per-step limit: steps may legitimately run for
// days, so a silent step is never killed unless the user opts in with
// O_BACKEND_STEP_TIMEOUT_MS. a hang is surfaced instead by the heartbeat
// watchdog (warn, never kill) and a crash by reader eof or the leader-exit
// poll, which fail fast.
pub(crate) const BACKEND_STEP_TIMEOUT_ENV: &str = "O_BACKEND_STEP_TIMEOUT_MS";
// shims send a heartbeat this often while a step runs (passed to the backend
// as O_BACKEND_HEARTBEAT_INTERVAL_MS). tests shrink it.
pub(crate) const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const HEARTBEAT_INTERVAL_ENV: &str = "O_BACKEND_HEARTBEAT_INTERVAL_MS";
// one warning after this long without a heartbeat (or this long in state D
// for a bash child, or this long in a native leaf child). tests shrink it
// with O_BACKEND_HEARTBEAT_WARN_MS.
pub(crate) const DEFAULT_HEARTBEAT_WARNING: Duration = Duration::from_secs(30);
pub(crate) const HEARTBEAT_WARNING_ENV: &str = "O_BACKEND_HEARTBEAT_WARN_MS";
pub(crate) const MAXIMUM_BACKEND_STEP_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

type Cached<T> = OnceLock<std::result::Result<T, String>>;

/// Parse one millisecond knob. Unset means `None`. Anything set must be a
/// whole number of milliseconds in `1..=MAXIMUM`.
pub(crate) fn parse_timeout_knob(
    name: &str,
    raw: Option<&std::ffi::OsStr>,
) -> Result<Option<Duration>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let text = raw
        .to_str()
        .ok_or_else(|| anyhow!("{name} is not valid UTF-8"))?;
    let millis = text
        .trim()
        .parse::<u64>()
        .map_err(|_| anyhow!("{name}={text:?} is not a whole number of milliseconds"))?;
    if millis == 0 {
        bail!("{name}=0 is invalid: the limit must be at least 1 ms");
    }
    let limit = Duration::from_millis(millis);
    if limit > MAXIMUM_BACKEND_STEP_TIMEOUT {
        bail!(
            "{name}={millis} exceeds the maximum of {} ms",
            MAXIMUM_BACKEND_STEP_TIMEOUT.as_millis()
        );
    }
    Ok(Some(limit))
}

fn cached(cell: &'static Cached<Option<Duration>>, name: &str) -> Result<Option<Duration>> {
    cell.get_or_init(|| {
        parse_timeout_knob(name, std::env::var_os(name).as_deref())
            .map_err(|error| format!("{error:#}"))
    })
    .clone()
    .map_err(anyhow::Error::msg)
}

/// The opt-in per-step limit, or `None` when `O_BACKEND_STEP_TIMEOUT_MS` is
/// unset.
pub(crate) fn step_timeout() -> Result<Option<Duration>> {
    static STEP: Cached<Option<Duration>> = OnceLock::new();
    cached(&STEP, BACKEND_STEP_TIMEOUT_ENV)
}

/// How often shims send heartbeats.
pub(crate) fn heartbeat_interval() -> Result<Duration> {
    static INTERVAL: Cached<Option<Duration>> = OnceLock::new();
    Ok(cached(&INTERVAL, HEARTBEAT_INTERVAL_ENV)?.unwrap_or(DEFAULT_HEARTBEAT_INTERVAL))
}

/// How long a silent step or native leaf child runs before one warning.
pub(crate) fn heartbeat_warning() -> Result<Duration> {
    static WARNING: Cached<Option<Duration>> = OnceLock::new();
    Ok(cached(&WARNING, HEARTBEAT_WARNING_ENV)?.unwrap_or(DEFAULT_HEARTBEAT_WARNING))
}
