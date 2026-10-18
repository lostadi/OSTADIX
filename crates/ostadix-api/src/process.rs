use anyhow::{anyhow, bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::fmt;
use std::io::{self, BufReader, BufWriter, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::backend_state::{
    ensure_evaluator_snapshot_bound, sandbox_policy_sha256, BackendCheckpointV1,
    BackendRestoreReceiptV1, BackendStateCapabilitiesV1, BackendStateTierV1, BackendWireCommandV2,
    BackendWireResponseV2, EvaluatorActorCheckpointV1, EvaluatorStateSnapshotV1,
};
use crate::capability::BackendSandboxPolicy;
use crate::step_knobs::parse_timeout_knob;
pub(crate) use crate::step_knobs::{
    BACKEND_STEP_TIMEOUT_ENV, DEFAULT_HEARTBEAT_WARNING, HEARTBEAT_INTERVAL_ENV,
};
use crate::value::OValue;
use crate::wire;

static BACKEND_SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);
const DEFAULT_BACKEND_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
// why 2 s: after sigkill the kernel must tear down the whole address space
// before the leader is waitable and stdout hits eof. with no swap and a large
// python heap that teardown can take longer than 250 ms, which turned a clean
// kill into "forced termination also failed". 2 s matches the default shutdown
// budget. it is a budget, not a sleep: a healthy kill returns as soon as the
// leader, reader and group settle. it is spent on kill paths only (timeouts,
// cancellation, drop of a non-terminal actor, spawn-failure cleanup), and
// registry teardown shares one budget across all actors (force_terminate_all).
const BACKEND_FALLBACK_REAP_TIMEOUT: Duration = Duration::from_secs(2);
// how often a step wait wakes to poll for leader exit, check heartbeats and
// redraw the spinner. bounds crash detection when a grandchild keeps the
// response pipe open.
const STEP_WATCH_TICK: Duration = Duration::from_millis(100);
// why 64 KiB: linux pipe capacity. a frame at or below it fits in an empty
// pipe, so the existing blocking write cannot wedge on it; only larger frames
// pay for the nonblocking, deadline-bounded write.
pub(crate) const BOUNDED_WRITE_THRESHOLD: usize = 64 * 1024;
const DEFAULT_MAX_OPEN_BACKEND_SESSIONS: usize = 128;
const DEFAULT_MAX_OPEN_BACKEND_SESSIONS_PER_BACKEND: usize = 32;

/// Marker carried through `anyhow` so the worker pool can distinguish a
/// physical execution failure from a language-level backend error.
#[derive(Debug)]
struct BackendInfrastructureError {
    source: anyhow::Error,
}

impl fmt::Display for BackendInfrastructureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.source)
    }
}

impl StdError for BackendInfrastructureError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug)]
struct BackendSemanticError(String);

impl fmt::Display for BackendSemanticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl StdError for BackendSemanticError {}

/// A checkpoint was refused without damaging the live session. Callers may
/// continue on the same actor, but must not claim restart or migration.
#[derive(Debug)]
pub(crate) struct BackendStatePinned {
    pub(crate) backend: String,
    pub(crate) path: String,
    pub(crate) message: String,
}

impl fmt::Display for BackendStatePinned {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "state.pin-required: backend={} path={} message={}",
            self.backend, self.path, self.message
        )
    }
}

impl StdError for BackendStatePinned {}

/// A one-shot compatibility backend completed its semantic operation but
/// could not participate in the explicit shutdown handshake.  This marker is
/// intentionally narrower than "the process is now terminal": protocol-shape
/// errors and acknowledged shutdowns with lingering descendants must remain
/// failures even when forced cleanup eventually succeeds.
#[derive(Debug)]
struct BackendShutdownUnacknowledged(String);

impl fmt::Display for BackendShutdownUnacknowledged {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl StdError for BackendShutdownUnacknowledged {}

pub(crate) fn infrastructure_error(error: anyhow::Error) -> anyhow::Error {
    if error.is::<BackendInfrastructureError>() {
        error
    } else {
        anyhow::Error::new(BackendInfrastructureError { source: error })
    }
}

pub(crate) fn is_infrastructure_error(error: &anyhow::Error) -> bool {
    error.is::<BackendInfrastructureError>()
}

pub(crate) use crate::lifecycle_trace::lifecycle_trace;
use crate::lifecycle_trace::monotonic_nanos;

#[cfg(test)]
const PYTHON_POLICY_BOOTSTRAP: &str = r#"
import json, os, runpy, sys
_o_permissions = frozenset(json.loads(os.environ.pop("O_BACKEND_AUTHORITIES", "[]")))
_o_runtime_candidates = json.loads(os.environ.pop("O_BACKEND_RUNTIME_ROOTS", "[]"))
_o_import_roots = list(_o_runtime_candidates)
_o_runtime_candidates.extend(path for path in sys.path if path)
_o_runtime_candidates.extend((sys.prefix, sys.base_prefix, os.path.dirname(sys.executable)))

def _o_realpath_or_none(path):
    try:
        return os.path.realpath(os.fspath(path))
    except (TypeError, ValueError, OSError):
        return None

_o_runtime_roots = tuple(sorted({
    real
    for path in _o_runtime_candidates
    if path
    for real in [_o_realpath_or_none(path)]
    if real
}))

def _o_under(path, roots):
    try:
        real = os.path.realpath(os.fspath(path))
    except (TypeError, ValueError, OSError):
        return False
    return any(real == root or real.startswith(root + os.sep) for root in roots)

for _o_root in reversed(_o_import_roots):
    _o_real_root = _o_realpath_or_none(_o_root)
    if _o_real_root and _o_real_root not in sys.path:
        sys.path.insert(0, _o_real_root)

def _o_audit(event, args):
    if event == "open" and args:
        path = args[0]
        if isinstance(path, int):
            return
        mode = args[1] if len(args) > 1 else "r"
        flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
        writing = (
            isinstance(mode, str) and any(marker in mode for marker in "wax+")
        ) or bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        if writing and "fs_write" not in _o_permissions:
            raise PermissionError("O backend capability denies filesystem write")
        if (
            not writing
            and "fs_read" not in _o_permissions
            and not _o_under(path, _o_runtime_roots)
        ):
            raise PermissionError("O backend capability denies filesystem read")
    if event in {
        "os.listdir", "os.scandir"
    } and "fs_read" not in _o_permissions and args and not _o_under(args[0], _o_runtime_roots):
        raise PermissionError("O backend capability denies filesystem read")
    if event in {
        "os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.chmod",
        "os.chown", "os.link", "os.symlink", "os.truncate", "os.utime"
    } and "fs_write" not in _o_permissions:
        raise PermissionError("O backend capability denies filesystem write")
    if (event in {
        "os.system", "os.fork", "os.forkpty", "os.posix_spawn",
        "os.posix_spawnp", "subprocess.Popen", "pty.spawn"
    } or event.startswith("os.exec") or event.startswith("os.spawn")) and "process" not in _o_permissions:
        raise PermissionError("O backend capability denies process spawn")
    if (event.startswith("socket.") or event.startswith("ssl.")) and "network" not in _o_permissions:
        raise PermissionError("O backend capability denies network access")
    if event == "ctypes.dlopen" and set(_o_permissions) != {"fs_read", "fs_write", "network", "process"}:
        raise PermissionError("O backend capability denies native-library loading under a restricted policy")

sys.addaudithook(_o_audit)
runpy.run_path(sys.argv[1], run_name="__main__")
"#;

/// One step in the exec-reply cycle.
///
/// After sending an `Exec` command to a shim, the runtime reads one response.
/// If the shim is done, it sends `Ok` or `Err`. If the shim's user code called
/// `O.eval(q)`, the shim sends `EvalRequest` and expects the runtime to
/// evaluate the quoted source and reply with an `EvalResult` command before
/// the shim resumes execution and eventually sends `Ok`/`Err`.
#[derive(Debug)]
pub enum ExecStep {
    /// The shim finished executing and returned a value.
    Done(OValue),
    /// The shim needs the runtime to evaluate an O source fragment. `scope` is
    /// an optional explicit OValue::Scope supplied by user code.
    EvalRequest { src: String, scope: Option<OValue> },
}

struct PendingMorphismV1 {
    contract: crate::backend_morphism::BackendCrossingContractV1,
    request_id: String,
    bindings: HashMap<String, OValue>,
}

struct BackendProcess {
    language: String,
    // "python[1]" for numbered sessions, the language otherwise; used in
    // status lines.
    label: String,
    pulse: Arc<Mutex<Pulse>>,
    // the request's cancellation token while a command is written, so a
    // large write to a shim that stopped reading ends on cancel.
    write_cancellation: Option<crate::cancellation::CancellationToken>,
    session_id: String,
    native_instance: String,
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    responses: mpsc::Receiver<std::result::Result<BackendWireResponseV2, String>>,
    reader: Option<JoinHandle<()>>,
    terminal: bool,
    exec_pending: bool,
    pending_morphism: Option<PendingMorphismV1>,
    awaiting_callback: bool,
    native_operation_depth: usize,
    // set on a plain bash helper: where it is parked again after a block.
    plain_bash_key: Option<PlainBashHelperKey>,
    // set for one exec: the plan has another plain bash block ahead.
    plain_bash_next: bool,
    // a forced kill began with SIGTERM to a plain bash helper.
    graceful_term_sent: bool,
}

// why no default: an operation (an ephemeral exec, a state checkpoint or
// restore, a native operation) may run as long as a step may, so it is only
// bounded when the user opts in with O_BACKEND_OPERATION_TIMEOUT_MS. the
// value is validated like O_BACKEND_STEP_TIMEOUT_MS.
pub(crate) const BACKEND_OPERATION_TIMEOUT_ENV: &str = "O_BACKEND_OPERATION_TIMEOUT_MS";

pub(crate) fn backend_operation_timeout() -> Result<Option<Duration>> {
    parse_timeout_knob(
        BACKEND_OPERATION_TIMEOUT_ENV,
        std::env::var_os(BACKEND_OPERATION_TIMEOUT_ENV).as_deref(),
    )
}

/// Parse the opt-in `O_BACKEND_STEP_TIMEOUT_MS`. Unset means no limit.
/// Anything set must be a whole number of milliseconds in `1..=MAXIMUM`; a
/// malformed, zero or oversized value is a hard error rather than a silent
/// fallback, because a knob the user set and the runtime ignored is a silent
/// failure.
#[cfg(test)]
fn parse_backend_step_timeout(raw: Option<&std::ffi::OsStr>) -> Result<Option<Duration>> {
    parse_timeout_knob(BACKEND_STEP_TIMEOUT_ENV, raw)
}

// why cached: the value is fixed for the process lifetime, so it is parsed
// once and a bad value fails every step the same way instead of drifting.
pub(crate) fn backend_step_timeout() -> Result<Option<Duration>> {
    #[cfg(test)]
    if let Some(timeout) = STEP_TIMEOUT_OVERRIDE.with(std::cell::Cell::get) {
        return Ok(Some(timeout));
    }
    crate::step_knobs::step_timeout()
}

/// "N s" for whole or fractional seconds, "N ms" below one second.
pub(crate) fn step_limit_text(limit: Duration) -> String {
    if limit < Duration::from_secs(1) {
        format!("{} ms", limit.as_millis())
    } else {
        format!("{} s", limit.as_secs_f64())
    }
}

fn session_label(lang: &str, env_id: u32) -> String {
    if env_id <= crate::environment::MAX_PERSISTENT_ENV_ID {
        format!("{lang}[{env_id}]")
    } else {
        lang.to_string()
    }
}

pub(crate) fn step_limit_exceeded_message(language: &str, limit: Duration) -> String {
    format!("backend `{language}` {}", step_limit_exceeded_reason(limit))
}

/// The reason alone, for callers that already name the backend.
fn step_limit_exceeded_reason(limit: Duration) -> String {
    format!(
        "step exceeded {} (opt-in per-step limit {BACKEND_STEP_TIMEOUT_ENV})",
        step_limit_text(limit)
    )
}

/// "30 s" for whole seconds, "400 ms" otherwise (test timings).
fn warning_text(duration: Duration) -> String {
    if duration.subsec_millis() == 0 {
        format!("{} s", duration.as_secs())
    } else {
        format!("{} ms", duration.as_millis())
    }
}

pub(crate) fn heartbeat_interval() -> Result<Duration> {
    #[cfg(test)]
    if let Some(timing) = HEARTBEAT_OVERRIDE.with(std::cell::Cell::get) {
        return Ok(timing.0);
    }
    crate::step_knobs::heartbeat_interval()
}

/// The protocol feature a shim lists in `hello_v1` when it sends heartbeats.
pub(crate) const HEARTBEAT_CAPABILITY: &str = "heartbeat_v1";

/// Set to `1` on a bash backend that serves plain blocks: it gives each block
/// a fresh shell and ends that shell and its jobs before answering.
pub(crate) const PLAIN_BASH_HELPER_ENV: &str = "O_BACKEND_PLAIN_BASH_HELPER";

/// The bash backend's job cleanup window (JOB_CLEANUP_WINDOW in backend.rs).
const PLAIN_BASH_CLEANUP_WINDOW: Duration = Duration::from_secs(2);

/// Inside a backend: the interval the host asked for, or None when the host
/// did not set `O_BACKEND_HEARTBEAT_INTERVAL_MS`. Without it a shim sends no
/// hello or heartbeat frames, so hosts that predate them see no change.
pub(crate) fn shim_heartbeat_interval() -> Option<Duration> {
    std::env::var(HEARTBEAT_INTERVAL_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|millis| *millis > 0)
        .map(Duration::from_millis)
}

pub(crate) fn heartbeat_warning() -> Result<Duration> {
    #[cfg(test)]
    if let Some(timing) = HEARTBEAT_OVERRIDE.with(std::cell::Cell::get) {
        return Ok(timing.1);
    }
    crate::step_knobs::heartbeat_warning()
}

/// Liveness observed by the response reader from heartbeat frames.
#[derive(Default)]
struct Pulse {
    // the shim listed heartbeat_v1 in its hello frame. an old shim never
    // does, so it is never warned about.
    capable: bool,
    last: Option<Instant>,
    beats: u64,
    child: Option<crate::backend_state::BackendHeartbeatChildV1>,
    child_d_since: Option<Instant>,
}

/// Watchdog for one step wait: warns once on a missing heartbeat, once more
/// if heartbeats resume, and draws the spinner. It never kills.
struct StepWatch {
    started: Instant,
    warning: Duration,
    silent_warned: bool,
    beats_at_warning: u64,
    child_warned: bool,
    last_draw: Option<Instant>,
    spinner: bool,
}

/// Time between spinner frames, and before the first one.
const SPINNER_FRAME: Duration = Duration::from_millis(200);

impl StepWatch {
    fn new(pulse: &Mutex<Pulse>) -> Self {
        // child state seen during an earlier wait (say a shell that exited at
        // the end of the previous block) must not trigger a warning now.
        {
            let mut pulse = pulse.lock().unwrap_or_else(|poison| poison.into_inner());
            pulse.child = None;
            pulse.child_d_since = None;
        }
        Self {
            started: Instant::now(),
            // the knob was validated when the backend was spawned, so an
            // error cannot appear here; the default only satisfies the type.
            warning: heartbeat_warning().unwrap_or(DEFAULT_HEARTBEAT_WARNING),
            silent_warned: false,
            beats_at_warning: 0,
            child_warned: false,
            last_draw: None,
            spinner: crate::progress::spinner_enabled(),
        }
    }

    fn observe(&mut self, label: &str, pulse: &Mutex<Pulse>) {
        let now = Instant::now();
        let pulse = pulse.lock().unwrap_or_else(|poison| poison.into_inner());
        // an old shim has no heartbeat capability, so it is never warned about.
        if pulse.capable {
            let since = pulse
                .last
                .map_or(self.started, |last| last.max(self.started));
            let silent = now.saturating_duration_since(since);
            if !self.silent_warned && silent >= self.warning {
                self.silent_warned = true;
                self.beats_at_warning = pulse.beats;
                crate::progress::line(&format!(
                    "no heartbeat from {label} for {}; it may be hanging (still running)",
                    warning_text(self.warning)
                ));
            } else if self.silent_warned && pulse.beats > self.beats_at_warning {
                self.silent_warned = false;
                crate::progress::line(&format!(
                    "{label} resumed sending heartbeats (still running)"
                ));
            }
        }
        if !self.child_warned {
            if let Some(child) = &pulse.child {
                if child.state == "gone" {
                    self.child_warned = true;
                    crate::progress::line(&format!(
                        "{label} child process {} is gone while the backend is still running",
                        child.pid
                    ));
                } else if pulse
                    .child_d_since
                    .is_some_and(|since| now.saturating_duration_since(since) >= self.warning)
                {
                    self.child_warned = true;
                    crate::progress::line(&format!(
                        "{label} child process {} has been in uninterruptible wait (state D) for {}; it may be hanging (still running)",
                        child.pid,
                        warning_text(self.warning)
                    ));
                }
            }
        }
        drop(pulse);
        // why the first draw waits a frame: a step shorter than that would
        // only draw and erase a line.
        if self.spinner
            && now.saturating_duration_since(self.started) >= SPINNER_FRAME
            && self
                .last_draw
                .is_none_or(|drawn| now.saturating_duration_since(drawn) >= SPINNER_FRAME)
        {
            self.last_draw = Some(now);
            crate::progress::spinner(label, now.saturating_duration_since(self.started));
        }
    }

    fn finish(&self) {
        if self.last_draw.is_some() {
            crate::progress::clear_spinner();
        }
    }
}

/// Marker for "a backend was killed mid-step" (deadline, cancellation, or it
/// exited). A persistent session that ends this way is recorded as lost (see
/// `ProcessRegistry::lost_sessions`); `cause` completes "terminated after ...".
#[derive(Debug)]
pub(crate) struct BackendSessionKilled {
    cause: &'static str,
    message: String,
    // the request's own execution deadline (not a per-step limit) ended it.
    request_deadline: bool,
}

impl fmt::Display for BackendSessionKilled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl StdError for BackendSessionKilled {}

pub(crate) const KILLED_BY_TIMEOUT: &str = "a timeout";
const KILLED_BY_CANCELLATION: &str = "cancellation";
const KILLED_BY_EXIT: &str = "its backend exited";

fn session_killed(cause: &'static str, message: String) -> anyhow::Error {
    anyhow::Error::new(BackendSessionKilled {
        cause,
        message,
        request_deadline: false,
    })
}

pub(crate) fn is_request_deadline_kill(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<BackendSessionKilled>())
        .any(|killed| killed.request_deadline)
}

pub(crate) fn session_killed_cause(error: &anyhow::Error) -> Option<&'static str> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<BackendSessionKilled>())
        .map(|killed| killed.cause)
}

/// Which deadline a response read runs under; only the step limit names the
/// knob that raises it.
#[derive(Clone, Copy)]
enum ResponseLimit {
    Other,
}

/// Shrink the step bound for the calling thread only, for tests in other roots.
#[cfg(test)]
pub(crate) fn set_step_timeout_override(timeout: Option<Duration>) {
    STEP_TIMEOUT_OVERRIDE.with(|cell| cell.set(timeout));
}

#[cfg(test)]
thread_local! {
    // lets a test shrink the step bound for its own thread without touching
    // the process environment shared by parallel tests.
    static STEP_TIMEOUT_OVERRIDE: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
    // (heartbeat interval sent to new backends, warning threshold).
    static HEARTBEAT_OVERRIDE: std::cell::Cell<Option<(Duration, Duration)>> =
        const { std::cell::Cell::new(None) };
    // records kill and settle order so a test can prove teardown signals
    // every actor before it waits on any of them.
    static KILL_TRACE: std::cell::RefCell<Option<Vec<&'static str>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn kill_trace(event: &'static str) {
    KILL_TRACE.with(|trace| {
        if let Some(trace) = trace.borrow_mut().as_mut() {
            trace.push(event);
        }
    });
}

/// Write `bytes` to a pipe without blocking past `limit` of no progress. The
/// fd is nonblocking only for the duration of this call. Returns `Ok(false)`
/// when the reader made no progress for `limit`.
#[cfg(unix)]
pub(crate) fn write_all_bounded(
    fd: std::os::fd::RawFd,
    bytes: &[u8],
    limit: Duration,
) -> io::Result<bool> {
    write_all_polled(fd, bytes, Some(limit), &|| false).map(|outcome| outcome == PolledWrite::Done)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PolledWrite {
    Done,
    // no byte was taken for `limit`.
    Stalled,
    Cancelled,
}

/// Write all of `bytes` to a pipe in poll slices of at most 100 ms. Stops
/// when no byte is taken for `limit` (when set) or when `cancelled` turns
/// true. The idle timer restarts on every byte written.
#[cfg(unix)]
pub(crate) fn write_all_polled(
    fd: std::os::fd::RawFd,
    bytes: &[u8],
    limit: Option<Duration>,
    cancelled: &dyn Fn() -> bool,
) -> io::Result<PolledWrite> {
    // SAFETY: fcntl on a caller-owned open fd only reads/sets status flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let outcome = (|| {
        let mut written = 0;
        let mut deadline = limit.map(|limit| Instant::now() + limit);
        while written < bytes.len() {
            if cancelled() {
                return Ok(PolledWrite::Cancelled);
            }
            // SAFETY: the pointer/length pair stays inside `bytes`.
            let n =
                unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
            if n > 0 {
                written += n as usize;
                deadline = limit.map(|limit| Instant::now() + limit);
                continue;
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    let remaining = deadline.map_or(STEP_WATCH_TICK, |deadline| {
                        deadline.saturating_duration_since(Instant::now())
                    });
                    if remaining.is_zero() {
                        return Ok(PolledWrite::Stalled);
                    }
                    let remaining = remaining.min(STEP_WATCH_TICK);
                    let mut poll = libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
                    // SAFETY: one valid pollfd for the duration of the call.
                    if unsafe { libc::poll(&mut poll, 1, millis) } < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
                _ => return Err(error),
            }
        }
        Ok(PolledWrite::Done)
    })();
    // SAFETY: restores the flags read above on the same fd.
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    outcome
}

const BACKEND_SHUTDOWN_TIMEOUT_ENV: &str = "O_BACKEND_SHUTDOWN_TIMEOUT_MS";
const MAXIMUM_BACKEND_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OPEN_SESSIONS_ENV: &str = "O_BACKEND_MAX_OPEN_SESSIONS";
const MAX_OPEN_SESSIONS_PER_BACKEND_ENV: &str = "O_BACKEND_MAX_OPEN_SESSIONS_PER_BACKEND";

/// The teardown budget: `O_BACKEND_SHUTDOWN_TIMEOUT_MS`, or the default when
/// unset. parsed once; a malformed value is an error at every read, never the
/// default.
pub(crate) fn backend_shutdown_timeout() -> Result<Duration> {
    static TIMEOUT: OnceLock<std::result::Result<Option<Duration>, String>> = OnceLock::new();
    let value = TIMEOUT
        .get_or_init(|| {
            checked_duration_from_env(
                BACKEND_SHUTDOWN_TIMEOUT_ENV,
                MAXIMUM_BACKEND_SHUTDOWN_TIMEOUT,
            )
            .map_err(|error| format!("{error:#}"))
        })
        .clone()
        .map_err(anyhow::Error::msg)?;
    Ok(value.unwrap_or(DEFAULT_BACKEND_SHUTDOWN_TIMEOUT))
}

/// The knob's value, None when unset, or an error naming the bad value.
fn checked_duration_from_env(name: &str, maximum: Duration) -> Result<Option<Duration>> {
    let Some(raw) = std::env::var_os(name) else {
        return Ok(None);
    };
    duration_knob(name, &raw, maximum).map(Some)
}

fn duration_knob(name: &str, raw: &std::ffi::OsStr, maximum: Duration) -> Result<Duration> {
    let millis = positive_integer_knob(name, raw)?;
    let duration = Duration::from_millis(millis as u64);
    if duration > maximum {
        bail!(
            "{name}={millis} exceeds the maximum of {} ms",
            maximum.as_millis()
        );
    }
    Ok(duration)
}

fn positive_integer_knob(name: &str, raw: &std::ffi::OsStr) -> Result<usize> {
    let text = raw
        .to_str()
        .ok_or_else(|| anyhow!("{name} is not valid UTF-8"))?;
    // the same whitespace rule as the step knobs: surrounding blanks are
    // trimmed, anything else is a malformed value.
    let value = text
        .trim()
        .parse::<usize>()
        .map_err(|_| anyhow!("{name}={text:?} is not a positive whole number"))?;
    if value == 0 {
        bail!("{name}={text:?} is invalid: it must be at least 1");
    }
    Ok(value)
}

/// Validate the teardown budget and the session caps, so a malformed value
/// fails the spawn instead of silently becoming the default.
fn check_process_knobs() -> Result<()> {
    backend_shutdown_timeout()?;
    BackendSessionLimits::from_env()?;
    Ok(())
}

fn bounded_deadline(timeout: Duration, subject: &str) -> Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| anyhow!("{subject} deadline overflowed"))
}

/// Return true when a non-authoritative `/proc` observation raced with normal
/// process exit. Callers must continue to surface every other I/O error.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn linux_process_observation_disappeared(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

/// Ostadix POSIX v1 containment governs descendants that remain in the
/// backend's inherited process group. A descendant that deliberately creates
/// a new session or process group (for example with `setsid`) escapes this v1
/// boundary; complete containment requires a stronger OS facility such as a
/// Linux cgroup or a Windows job object.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn owned_group_has_no_active_descendants(group: i32) -> io::Result<bool> {
    for entry in std::fs::read_dir("/proc")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if linux_process_observation_disappeared(&error) => continue,
            Err(error) => return Err(error),
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        if pid == group {
            continue;
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if linux_process_observation_disappeared(&error) => continue,
            Err(error) => return Err(error),
        };
        let close = stat.rfind(')').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed /proc process stat")
        })?;
        let mut fields = stat[close + 1..].split_whitespace();
        let state = fields.next();
        let _parent = fields.next();
        let candidate_group = fields
            .next()
            .and_then(|field| field.parse::<i32>().ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "malformed /proc process group")
            })?;
        // Orphaned grandchildren cannot be waited by this process. Zombies
        // and Linux's transient dead states have no executable state and
        // cannot retain backend protocol descriptors, so they are terminal
        // for this physical-completion boundary.
        if candidate_group == group && !matches!(state, Some("Z" | "X" | "x")) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
fn owned_group_has_no_active_descendants(group: i32) -> io::Result<bool> {
    // SAFETY: a null buffer asks libproc for a conservative PID capacity and
    // does not dereference memory.
    let capacity = unsafe { libc::proc_listpgrppids(group, std::ptr::null_mut(), 0) };
    if capacity <= 0 {
        let enumeration_error = io::Error::last_os_error();
        // After the anchored leader is reaped, libproc can report no result
        // without a useful errno. Confirm absence through the process-group
        // namespace before treating that as quiescence.
        // SAFETY: signal zero performs existence/permission checks only.
        if unsafe { libc::kill(-group, 0) } != 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            return Ok(true);
        }
        return Err(enumeration_error);
    }
    let mut members = vec![0 as libc::pid_t; capacity as usize];
    let bytes = members
        .len()
        .checked_mul(std::mem::size_of::<libc::pid_t>())
        .and_then(|size| i32::try_from(size).ok())
        .ok_or_else(|| io::Error::other("Darwin process-group buffer is too large"))?;
    // SAFETY: `members` owns `bytes` writable bytes and remains alive for the
    // complete libproc call.
    let count = unsafe { libc::proc_listpgrppids(group, members.as_mut_ptr().cast(), bytes) };
    if count <= 0 {
        let enumeration_error = io::Error::last_os_error();
        // SAFETY: signal zero performs existence/permission checks only.
        if unsafe { libc::kill(-group, 0) } != 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            return Ok(true);
        }
        return Err(enumeration_error);
    }
    let count = usize::try_from(count)
        .map_err(|_| io::Error::other("Darwin process-group count does not fit usize"))?;
    if count > members.len() {
        return Err(io::Error::other(
            "Darwin process-group enumeration exceeded its buffer",
        ));
    }
    members.truncate(count);
    for member in members.into_iter().filter(|member| *member != group) {
        // SAFETY: `information` is valid writable storage of the exact size
        // supplied to libproc for the queried PID.
        let mut information: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let information_size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
            .map_err(|_| io::Error::other("Darwin process info buffer is too large"))?;
        let read = unsafe {
            libc::proc_pidinfo(
                member,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut information as *mut libc::proc_bsdinfo).cast(),
                information_size,
            )
        };
        if read <= 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(error);
        }
        if read != information_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Darwin returned a partial process info record",
            ));
        }
        // Revalidate the PGID after enumeration to reject PID reuse. Zombies
        // are inert and cannot retain backend protocol descriptors.
        if information.pbi_pgid == group as u32 && information.pbi_status != libc::SZOMB {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "macos"))
))]
fn owned_group_has_no_active_descendants(_group: i32) -> io::Result<bool> {
    // POSIX exposes group signalling but no portable membership-enumeration
    // API. The shutdown path still kills the inherited group on failure, but
    // the stronger active-descendant proof is currently Linux/Android/Darwin only.
    Ok(true)
}

#[cfg(not(unix))]
fn owned_group_has_no_active_descendants(_group: i32) -> io::Result<bool> {
    Ok(true)
}

fn signal_owned_process_group(child: &mut Child) -> Result<()> {
    #[cfg(unix)]
    {
        if let Ok(group) = i32::try_from(child.id()) {
            // SAFETY: backend children are created as leaders of their own
            // process groups; a negative PID addresses only that owned group.
            if unsafe { libc::kill(-group, libc::SIGKILL) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    let _ = child.kill();
                    return Err(error).context("failed to terminate backend process group");
                }
            }
        }
    }
    let _ = child.kill();
    Ok(())
}

fn kill_and_reap_process_group(child: &mut Child, timeout: Duration) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    let signal_result = signal_owned_process_group(child);
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| anyhow!("backend reap deadline overflowed"))?;
    loop {
        if child.try_wait()?.is_some() {
            return signal_result;
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "backend process {} did not become waitable within {} ms",
                child.id(),
                timeout.as_millis()
            ));
        }
        thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
fn python_shim_command(shim_path: &Path, sandbox: &BackendSandboxPolicy) -> Result<Command> {
    let python = which::which("python3").context("python3 is required for backend shims")?;
    let shim = shim_path
        .canonicalize()
        .unwrap_or_else(|_| shim_path.to_path_buf());
    let runtime_root = shim
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    #[cfg(target_os = "macos")]
    let mut command = macos_sandbox_command(&python, sandbox, &runtime_root)?;
    #[cfg(not(target_os = "macos"))]
    let mut command = Command::new(&python);

    // A no-file-read macOS profile denies metadata traversal of the caller's
    // arbitrary working directory. Python asks for getcwd() during bootstrap,
    // so anchor it inside the already admitted immutable shim runtime root.
    // Relative user-file access remains unavailable under the same profile.
    #[cfg(target_os = "macos")]
    if !sandbox.contains(crate::value::BackendAuthority::FileRead) {
        command.current_dir(&runtime_root);
    }

    command
        .arg("-c")
        .arg(PYTHON_POLICY_BOOTSTRAP)
        .arg(&shim)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env(
            "O_BACKEND_AUTHORITIES",
            serde_json::to_string(&sandbox.names())?,
        )
        .env(
            "O_BACKEND_RUNTIME_ROOTS",
            serde_json::to_string(std::slice::from_ref(&runtime_root))?,
        );
    Ok(command)
}

#[cfg(test)]
fn direct_shim_command(shim_path: &Path, sandbox: &BackendSandboxPolicy) -> Command {
    #[cfg(not(target_os = "macos"))]
    let _ = sandbox;
    #[cfg(target_os = "macos")]
    if let Ok(command) = macos_sandbox_command(
        shim_path,
        sandbox,
        shim_path.parent().unwrap_or_else(|| Path::new(".")),
    ) {
        return command;
    }
    Command::new(shim_path)
}

#[cfg(not(test))]
fn rust_backend_command(
    lang: &str,
    shim_path: &Path,
    sandbox: &BackendSandboxPolicy,
    executable_leases: &crate::runtime_exec::ExecutableLeaseSet,
) -> Result<Command> {
    executable_leases.verify_backend(lang)?;
    #[cfg(target_os = "macos")]
    let executable = executable_leases.current_o_path()?.to_path_buf();
    #[cfg(not(target_os = "macos"))]
    let executable = executable_leases.current_o_invocation_path()?.to_path_buf();
    let runtime_root = if shim_path.exists() {
        shim_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        executable
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };

    #[cfg(target_os = "macos")]
    let mut command = macos_sandbox_command_with_launcher(
        executable_leases
            .sandbox_exec_path()?
            .ok_or_else(|| anyhow!("admission omitted the macOS sandbox-exec artifact"))?,
        &executable,
        sandbox,
        &runtime_root,
    )?;
    #[cfg(not(target_os = "macos"))]
    let mut command = executable_leases.current_o_command()?;

    command
        .arg("--o-backend")
        .arg(lang)
        .env(
            crate::runtime_exec::ADMITTED_EXECUTABLE_MANIFEST_ENV,
            executable_leases.backend_manifest_json(lang)?,
        )
        .env(
            "O_BACKEND_AUTHORITIES",
            serde_json::to_string(&sandbox.names())?,
        );
    if shim_path.exists() {
        command.env("O_BACKEND_LEGACY_SHIM", shim_path);
        command.env(
            "O_BACKEND_RUNTIME_ROOTS",
            serde_json::to_string(&[runtime_root])?,
        );
    }
    Ok(command)
}

#[cfg(test)]
fn legacy_backend_command(shim_path: &Path, sandbox: &BackendSandboxPolicy) -> Result<Command> {
    if !shim_path.exists() {
        return Err(anyhow!("backend shim not found: {}", shim_path.display()));
    }
    if shim_path.extension().and_then(|s| s.to_str()) == Some("py") {
        python_shim_command(shim_path, sandbox)
    } else {
        Ok(direct_shim_command(shim_path, sandbox))
    }
}

#[cfg(all(test, target_os = "macos"))]
fn macos_sandbox_command(
    executable: &Path,
    sandbox: &BackendSandboxPolicy,
    runtime_root: &Path,
) -> Result<Command> {
    macos_sandbox_command_with_launcher(
        Path::new("/usr/bin/sandbox-exec"),
        executable,
        sandbox,
        runtime_root,
    )
}

#[cfg(target_os = "macos")]
fn macos_sandbox_command_with_launcher(
    sandbox_launcher: &Path,
    executable: &Path,
    sandbox: &BackendSandboxPolicy,
    runtime_root: &Path,
) -> Result<Command> {
    let executable = executable
        .canonicalize()
        .unwrap_or_else(|_| executable.to_path_buf());
    let mut profile = String::from("(version 1)\n(allow default)\n");
    if !sandbox.contains(crate::value::BackendAuthority::Network) {
        profile.push_str("(deny network*)\n");
    }
    if !sandbox.contains(crate::value::BackendAuthority::Process) {
        profile.push_str("(deny process-fork)\n(deny process-exec)\n");
        let executable_root = executable
            .ancestors()
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("python@"))
            })
            .unwrap_or(&executable);
        profile.push_str(&format!(
            "(allow process-exec (literal \"{}\") (subpath \"{}\"))\n",
            sandbox_quote(&executable),
            sandbox_quote(executable_root)
        ));
    }
    if !sandbox.contains(crate::value::BackendAuthority::FileWrite) {
        profile.push_str("(deny file-write*)\n");
    }
    if !sandbox.contains(crate::value::BackendAuthority::FileRead) {
        profile.push_str(
            "(deny file-read-data (subpath \"/Users\") (subpath \"/home\") (subpath \"/root\"))\n",
        );
        profile.push_str(&format!(
            "(allow file-read-data (subpath \"{}\"))\n",
            sandbox_quote(runtime_root)
        ));
    }

    let mut command = Command::new(sandbox_launcher);
    command.arg("-p").arg(profile).arg(executable);
    Ok(command)
}

#[cfg(target_os = "macos")]
fn sandbox_quote(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

impl BackendProcess {
    fn new(
        lang: &str,
        shim_path: &Path,
        sandbox: &BackendSandboxPolicy,
        executable_leases: Option<&crate::runtime_exec::ExecutableLeaseSet>,
    ) -> Result<Self> {
        Self::new_ephemeral(lang, shim_path, sandbox, executable_leases, false)
    }

    fn new_ephemeral(
        lang: &str,
        shim_path: &Path,
        sandbox: &BackendSandboxPolicy,
        executable_leases: Option<&crate::runtime_exec::ExecutableLeaseSet>,
        plain_bash_helper: bool,
    ) -> Result<Self> {
        let ordinal = BACKEND_SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        let session_id = hex::encode(Sha256::digest(format!(
            "ostadix-ephemeral-session-v1\0{}\0{}\0{}",
            std::process::id(),
            ordinal,
            lang
        )));
        Self::spawn(
            lang,
            shim_path,
            sandbox,
            executable_leases,
            &session_id,
            "unmanaged",
            lang == "bash" && plain_bash_helper,
        )
    }

    fn new_with_session(
        lang: &str,
        shim_path: &Path,
        sandbox: &BackendSandboxPolicy,
        executable_leases: Option<&crate::runtime_exec::ExecutableLeaseSet>,
        session_id: &str,
        launch_generation: &str,
    ) -> Result<Self> {
        Self::spawn(
            lang,
            shim_path,
            sandbox,
            executable_leases,
            session_id,
            launch_generation,
            false,
        )
    }

    fn spawn(
        lang: &str,
        shim_path: &Path,
        sandbox: &BackendSandboxPolicy,
        executable_leases: Option<&crate::runtime_exec::ExecutableLeaseSet>,
        session_id: &str,
        launch_generation: &str,
        plain_bash_helper: bool,
    ) -> Result<Self> {
        if session_id.len() != 64 || !session_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("backend session identity must be a 64-character SHA-256 digest");
        }
        #[cfg(test)]
        let mut command = legacy_backend_command(shim_path, sandbox)?;
        #[cfg(test)]
        if let Some(executable_leases) = executable_leases {
            executable_leases.verify_backend(lang)?;
            command.env(
                crate::runtime_exec::ADMITTED_EXECUTABLE_MANIFEST_ENV,
                executable_leases.backend_manifest_json(lang)?,
            );
        }

        #[cfg(not(test))]
        let mut command = rust_backend_command(
            lang,
            shim_path,
            sandbox,
            executable_leases.ok_or_else(|| {
                anyhow!("backend `{lang}` has no admitted executable lease authority")
            })?,
        )?;

        let native_instance = fresh_registry_identity();
        let heartbeat = heartbeat_interval()?;
        // checked here so a bad warning knob fails the spawn, not a later wait.
        heartbeat_warning()?;
        check_process_knobs()?;
        command
            .env("O_BACKEND_SESSION_ID", session_id)
            .env("O_BACKEND_LAUNCH_GENERATION", launch_generation)
            .env("O_BACKEND_NATIVE_INSTANCE_ID", &native_instance)
            .env(HEARTBEAT_INTERVAL_ENV, heartbeat.as_millis().to_string());
        if plain_bash_helper {
            command.env(PLAIN_BASH_HELPER_ENV, "1");
        } else {
            command.env_remove(PLAIN_BASH_HELPER_ENV);
        }

        #[cfg(unix)]
        command.process_group(0);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if plain_bash_helper {
            // a pooled helper outlives the block that started it, so it must
            // not outlive O: it gets SIGTERM, and stops its jobs, when we die.
            let parent = std::process::id() as libc::pid_t;
            // SAFETY: the hook runs between fork and exec and calls only
            // prctl and getppid, which are async-signal-safe.
            unsafe {
                command.pre_exec(move || arm_parent_death_signal(parent));
            }
        }

        // while the spinner is on, backend stderr goes through the one
        // status writer so a block's stderr never lands inside the spinner
        // line. otherwise it is inherited exactly as before.
        let route_stderr = crate::progress::spinner_enabled();
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(if route_stderr {
                Stdio::piped()
            } else {
                Stdio::inherit()
            });
        // a pooled helper is forked from one long-lived thread: the parent
        // death signal fires when the forking thread exits, and a worker
        // thread may exit while its helper is parked for the next block.
        let spawned = if plain_bash_helper {
            spawn_from_long_lived_thread(command)
        } else {
            command.spawn()
        };
        let mut child =
            spawned.with_context(|| format!("failed to spawn backend process for `{lang}`"))?;
        if let Some(mut stderr) = child.stderr.take() {
            let _ = thread::Builder::new()
                .name(format!("ostadix-backend-stderr-{}", child.id()))
                .spawn(move || {
                    use std::io::Read;
                    let mut buffer = [0u8; 8192];
                    while let Ok(read) = stderr.read(&mut buffer) {
                        if read == 0 {
                            break;
                        }
                        crate::progress::backend_stderr(&buffer[..read]);
                    }
                });
        }

        lifecycle_trace(
            "worker.backend_spawned",
            format!("language={lang} backend_pid={}", child.id()),
        );

        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let cleanup =
                    kill_and_reap_process_group(&mut child, BACKEND_FALLBACK_REAP_TIMEOUT);
                return match cleanup {
                    Ok(()) => Err(anyhow!("backend process did not provide stdin")),
                    Err(cleanup) => Err(anyhow!(
                        "backend process did not provide stdin; backend cleanup also failed: {cleanup:#}"
                    )),
                };
            }
        };

        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                drop(stdin);
                let cleanup =
                    kill_and_reap_process_group(&mut child, BACKEND_FALLBACK_REAP_TIMEOUT);
                return match cleanup {
                    Ok(()) => Err(anyhow!("backend process did not provide stdout")),
                    Err(cleanup) => Err(anyhow!(
                        "backend process did not provide stdout; backend cleanup also failed: {cleanup:#}"
                    )),
                };
            }
        };

        // The protocol permits one response per command. Capacity one keeps a
        // faulty backend from converting the reader thread into an unbounded
        // memory queue while retaining timeout-capable receives.
        let (responses_tx, responses) = mpsc::sync_channel(1);
        let reader_name = format!("ostadix-backend-reader-{}", child.id());
        let pulse = Arc::new(Mutex::new(Pulse::default()));
        let reader_pulse = Arc::clone(&pulse);
        let reader = match thread::Builder::new().name(reader_name).spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                match wire::read_frame::<_, BackendWireResponseV2>(&mut stdout) {
                    Ok(Some(BackendWireResponseV2::HelloV1 { capabilities })) => {
                        // capability negotiation only, never queued as a reply.
                        reader_pulse
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .capable = capabilities.iter().any(|name| name == HEARTBEAT_CAPABILITY);
                    }
                    Ok(Some(BackendWireResponseV2::HeartbeatV1 { child })) => {
                        // liveness only: consumed here, never queued as a reply.
                        let now = Instant::now();
                        let mut pulse = reader_pulse
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner());
                        pulse.last = Some(now);
                        pulse.beats += 1;
                        let in_d = child.as_ref().is_some_and(|child| child.state == "D");
                        pulse.child_d_since = match (in_d, pulse.child_d_since) {
                            (true, Some(since)) => Some(since),
                            (true, None) => Some(now),
                            (false, _) => None,
                        };
                        pulse.child = child;
                    }
                    Ok(Some(response)) => {
                        if responses_tx.send(Ok(response)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        let _ = responses_tx.send(Err(format!(
                            "failed to read backend wire response: {error:#}"
                        )));
                        return;
                    }
                }
            }
        }) {
            Ok(reader) => reader,
            Err(error) => {
                let cleanup =
                    kill_and_reap_process_group(&mut child, BACKEND_FALLBACK_REAP_TIMEOUT);
                return match cleanup {
                    Ok(()) => Err(error).context("failed to create backend response reader"),
                    Err(cleanup) => Err(anyhow!(
                        "failed to create backend response reader: {error}; backend cleanup also failed: {cleanup:#}"
                    )),
                };
            }
        };

        Ok(Self {
            language: lang.to_string(),
            session_id: session_id.to_owned(),
            native_instance,
            child,
            stdin: Some(BufWriter::new(stdin)),
            responses,
            reader: Some(reader),
            terminal: false,
            exec_pending: false,
            pending_morphism: None,
            awaiting_callback: false,
            native_operation_depth: 0,
            plain_bash_key: None,
            plain_bash_next: false,
            graceful_term_sent: false,
            label: lang.to_string(),
            pulse,
            write_cancellation: None,
        })
    }

    fn send_command(&mut self, command: &BackendWireCommandV2) -> Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("backend command channel is closed"))?;
        let payload =
            wire::encode_message(command).context("failed to write backend wire command")?;
        // the plain blocking write unless the frame can outgrow the pipe and
        // something can end the wait (the opt-in limit or a cancellation
        // token). an empty pipe always holds a small frame; without either an
        // unbounded write is no worse than the unbounded wait that follows.
        if payload.len() + 4 <= BOUNDED_WRITE_THRESHOLD
            || (backend_step_timeout()?.is_none() && self.write_cancellation.is_none())
        {
            return wire::write_frame_payload(stdin, &payload)
                .context("failed to write backend wire command");
        }
        self.send_large_frame(&payload)
    }

    // why: a frame larger than the pipe buffer blocks in write until the shim
    // reads, and a shim stalled before reading would hang the caller with no
    // step limit running yet. bound the write by the same per-step limit.
    #[cold]
    fn send_large_frame(&mut self, payload: &[u8]) -> Result<()> {
        let limit = backend_step_timeout()?;
        let cancellation = self.write_cancellation.clone();
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("backend command channel is closed"))?;
        stdin
            .flush()
            .context("failed to flush backend wire command")?;
        let length =
            u32::try_from(payload.len()).context("wire payload exceeded u32 frame length")?;
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(payload);
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let fd = stdin.get_ref().as_raw_fd();
            let cancelled = || {
                cancellation
                    .as_ref()
                    .is_some_and(crate::cancellation::CancellationToken::is_cancelled)
            };
            match write_all_polled(fd, &frame, limit, &cancelled) {
                Ok(PolledWrite::Done) => Ok(()),
                Ok(PolledWrite::Stalled) => Err(self.retire_after_timeout(anyhow!(
                    "backend `{}` read no input for {} (opt-in per-step limit {BACKEND_STEP_TIMEOUT_ENV})",
                    self.language,
                    step_limit_text(limit.unwrap_or_default())
                ))),
                Ok(PolledWrite::Cancelled) => Err(self.retire_after_write_cancel()),
                Err(error) => Err(anyhow::Error::new(error).context("failed to write backend wire command")),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = limit;
            stdin
                .get_mut()
                .write_all(&frame)
                .context("failed to write backend wire command")
        }
    }

    fn recv_step(&mut self) -> Result<ExecStep> {
        let response = self.recv_response()?;
        let step = self.response_step(response);
        if !matches!(&step, Ok(ExecStep::EvalRequest { .. })) {
            self.exec_pending = false;
        }
        step
    }

    fn recv_response(&mut self) -> Result<BackendWireResponseV2> {
        let limit = backend_step_timeout().map_err(infrastructure_error)?;
        self.recv_response_watched(limit)
    }

    /// Wait for one response in `STEP_WATCH_TICK` slices. Each slice checks
    /// the opt-in limit (kill and evict), leader exit (fail fast even when a
    /// grandchild holds the pipe), heartbeats (warn only) and the spinner.
    fn recv_response_watched(&mut self, limit: Option<Duration>) -> Result<BackendWireResponseV2> {
        let deadline = match limit {
            Some(limit) => Some(bounded_deadline(limit, "backend step")?),
            None => None,
        };
        let mut watch = StepWatch::new(&self.pulse);
        let outcome =
            loop {
                let wait = deadline.map_or(STEP_WATCH_TICK, |deadline| {
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(STEP_WATCH_TICK)
                });
                match self.responses.recv_timeout(wait) {
                    Ok(response) => break response.map_err(anyhow::Error::msg),
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        // reader eof mid-step: the backend died. fail now, and
                        // record the session lost (fail closed).
                        break Err(self.retire_after_exit());
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                if let (Some(limit), Some(deadline)) = (limit, deadline) {
                    if Instant::now() >= deadline {
                        break Err(self.retire_after_timeout(anyhow!(
                            step_limit_exceeded_message(&self.language, limit)
                        )));
                    }
                }
                if let Err(error) = self.watch_tick(&mut watch) {
                    break Err(error);
                }
            };
        watch.finish();
        outcome
    }

    /// One watchdog tick during a step wait. Fails fast when the backend
    /// leader has exited even though a grandchild keeps the response pipe
    /// open (so reader eof never comes); otherwise only warns and redraws.
    fn watch_tick(&mut self, watch: &mut StepWatch) -> Result<()> {
        if self.leader_exited_without_reaping()? {
            // a final answer may be in flight just ahead of the exit.
            if let Ok(Ok(response)) = self.responses.recv_timeout(Duration::from_millis(50)) {
                lifecycle_trace("worker.late_answer_after_exit", format!("{response:?}"));
            }
            return Err(self.retire_after_exit());
        }
        watch.observe(&self.label, &self.pulse);
        Ok(())
    }

    #[cold]
    fn retire_after_write_cancel(&mut self) -> anyhow::Error {
        let stalled = format!(
            "request cancelled while backend `{}` was still reading its command",
            self.language
        );
        let message = match self.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT) {
            Ok(()) => stalled,
            Err(termination) => format!("{stalled}; backend cleanup also failed: {termination:#}"),
        };
        infrastructure_error(session_killed(KILLED_BY_CANCELLATION, message))
    }

    #[cold]
    fn retire_after_exit(&mut self) -> anyhow::Error {
        let stalled = format!("backend `{}` exited during the step", self.label);
        let message = match self.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT) {
            Ok(()) => stalled,
            Err(termination) => format!("{stalled}; backend cleanup also failed: {termination:#}"),
        };
        infrastructure_error(session_killed(KILLED_BY_EXIT, message))
    }

    fn recv_step_timeout(&mut self, timeout: Duration) -> Result<ExecStep> {
        let response = self.recv_response_timeout(timeout)?;
        let step = self.response_step(response);
        if !matches!(&step, Ok(ExecStep::EvalRequest { .. })) {
            self.exec_pending = false;
        }
        step
    }

    /// Poll one execution step without changing actor state on an ordinary
    /// timeout. A caller that owns cancellation/deadline policy decides when a
    /// series of empty polls becomes terminal and then reaps the actor.
    fn poll_step(&mut self, timeout: Duration) -> Result<Option<ExecStep>> {
        let response = match self.responses.recv_timeout(timeout) {
            Ok(response) => response.map_err(anyhow::Error::msg)?,
            Err(mpsc::RecvTimeoutError::Timeout) => return Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(self.retire_after_exit());
            }
        };
        let step = self.response_step(response);
        if !matches!(&step, Ok(ExecStep::EvalRequest { .. })) {
            self.exec_pending = false;
        }
        step.map(Some)
    }

    /// Read the answer to a state or native operation: bounded only by the
    /// opt-in operation limit, otherwise watched like a step (exit detection
    /// and heartbeat warning) for as long as it runs.
    fn recv_operation_response(&mut self) -> Result<BackendWireResponseV2> {
        match backend_operation_timeout().map_err(infrastructure_error)? {
            Some(timeout) => self.recv_response_timeout(timeout),
            None => self.recv_response_watched(None),
        }
    }

    fn recv_response_timeout(&mut self, timeout: Duration) -> Result<BackendWireResponseV2> {
        self.recv_response_limited(timeout, ResponseLimit::Other)
    }

    fn recv_response_limited(
        &mut self,
        timeout: Duration,
        limit: ResponseLimit,
    ) -> Result<BackendWireResponseV2> {
        match self.responses.recv_timeout(timeout) {
            Ok(response) => response.map_err(anyhow::Error::msg),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let ResponseLimit::Other = limit;
                let message = format!(
                    "backend `{}` did not answer within {} ms",
                    self.language,
                    timeout.as_millis()
                );
                Err(self.retire_after_timeout(anyhow!(message)))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(anyhow!("backend process closed stdout unexpectedly"))
            }
        }
    }

    // why: a timed-out step leaves an answer in flight. if this actor stayed
    // live, that late answer would be read as the reply to the next request,
    // so the timeout kills it here rather than trusting every caller (or drop)
    // to evict, and a failed kill is reported instead of swallowed.
    // force_terminate takes stdin first, so even a failed kill leaves the actor
    // unable to accept another command: it fails closed either way.
    #[cold]
    fn retire_after_timeout(&mut self, stalled: anyhow::Error) -> anyhow::Error {
        let stalled = format!("{stalled:#}");
        let message = match self.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT) {
            Ok(()) => format!("{stalled}; stalled backend was forcibly reaped"),
            Err(termination) => {
                format!("{stalled}; stalled backend termination also failed: {termination:#}")
            }
        };
        infrastructure_error(session_killed(KILLED_BY_TIMEOUT, message))
    }

    fn response_step(&mut self, response: BackendWireResponseV2) -> Result<ExecStep> {
        self.awaiting_callback = matches!(response, BackendWireResponseV2::EvalRequest { .. });
        if !matches!(response, BackendWireResponseV2::EvalRequest { .. }) {
            if let Some(PendingMorphismV1 {
                contract,
                request_id,
                bindings,
            }) = self.pending_morphism.take()
            {
                return match response {
                    BackendWireResponseV2::MorphismResultV1 { receipt } => {
                        receipt.verify(contract, &request_id, &bindings).map_err(anyhow::Error::msg)?;
                        Ok(ExecStep::Done(receipt.value))
                    }
                    BackendWireResponseV2::Err { message } => Err(anyhow::Error::new(BackendSemanticError(message))),
                    _ => bail!("morphism.missing-receipt: enforced execution returned an unverified response"),
                };
            }
        }
        match response {
            BackendWireResponseV2::HeartbeatV1 { .. } | BackendWireResponseV2::HelloV1 { .. } => {
                bail!("backend heartbeat reached a request; the reader must consume it")
            }
            BackendWireResponseV2::NativeOperationResultV1 { .. } => {
                bail!("native.unexpected-receipt: no native operation is pending")
            }
            BackendWireResponseV2::MorphismResultV1 { .. } => {
                bail!("morphism.unexpected-receipt: no enforced execution is pending")
            }
            BackendWireResponseV2::Ok { value } => Ok(ExecStep::Done(value)),
            BackendWireResponseV2::Err { message } => {
                Err(anyhow::Error::new(BackendSemanticError(message)))
            }
            BackendWireResponseV2::EvalRequest { src, scope } => {
                Ok(ExecStep::EvalRequest { src, scope })
            }
            BackendWireResponseV2::StateCapabilitiesV1 { .. }
            | BackendWireResponseV2::CheckpointV1 { .. }
            | BackendWireResponseV2::RestoreV1 { .. }
            | BackendWireResponseV2::StatePinRequiredV1 { .. }
            | BackendWireResponseV2::StateErrorV1 { .. } => {
                bail!("backend returned a state-protocol response during execution")
            }
        }
    }

    fn send_eval_result(&mut self, value: OValue) -> Result<()> {
        if !self.exec_pending && self.native_operation_depth == 0 {
            bail!("backend has no pending execution awaiting eval_result");
        }
        self.send_command(&BackendWireCommandV2::EvalResult { value })?;
        self.awaiting_callback = false;
        Ok(())
    }

    /// Between operations with a live, unread pipe: safe to hand to another
    /// caller.
    fn idle(&self) -> bool {
        !self.terminal
            && !self.exec_pending
            && !self.awaiting_callback
            && self.native_operation_depth == 0
            && self.pending_morphism.is_none()
    }

    fn begin_exec_with_morphism(
        &mut self,
        code: &str,
        bindings: HashMap<String, OValue>,
        contract: Option<crate::backend_morphism::BackendCrossingContractV1>,
    ) -> Result<()> {
        if self.exec_pending || self.native_operation_depth > 0 {
            bail!("backend already has a pending execution");
        }
        if let Some(contract) = contract {
            contract
                .validate_bindings(&self.language, &bindings)
                .map_err(anyhow::Error::msg)?;
            let request_id = fresh_registry_identity();
            self.send_command(&BackendWireCommandV2::ExecMorphismV1 {
                code: code.to_string(),
                bindings: bindings.clone(),
                contract,
                request_id: request_id.clone(),
            })?;
            self.pending_morphism = Some(PendingMorphismV1 {
                contract,
                request_id,
                bindings,
            });
        } else {
            let plain_next =
                std::mem::take(&mut self.plain_bash_next) && self.plain_bash_key.is_some();
            self.send_command(&BackendWireCommandV2::Exec {
                code: code.to_string(),
                bindings,
                plain_next,
            })?;
        }
        self.exec_pending = true;
        Ok(())
    }

    #[cfg(test)]
    fn exec(&mut self, code: &str, bindings: HashMap<String, OValue>) -> Result<OValue> {
        self.exec_with_morphism(code, bindings, None)
    }

    fn exec_with_morphism(
        &mut self,
        code: &str,
        bindings: HashMap<String, OValue>,
        contract: Option<crate::backend_morphism::BackendCrossingContractV1>,
    ) -> Result<OValue> {
        self.begin_exec_with_morphism(code, bindings, contract)?;
        match self.recv_step()? {
            ExecStep::Done(v) => Ok(v),
            ExecStep::EvalRequest { src, .. } => Err(anyhow!(
                "unexpected eval_request from shim (src: {:?}): \
                 O.eval is only supported when the evaluator uses the \
                 exec_with_eval_callback path",
                &src[..src.len().min(60)]
            )),
        }
    }

    fn state_capabilities(&mut self) -> Result<BackendStateCapabilitiesV1> {
        self.ensure_state_boundary()?;
        self.send_command(&BackendWireCommandV2::StateCapabilitiesV1)?;
        match self.recv_operation_response()? {
            BackendWireResponseV2::StateCapabilitiesV1 { capabilities } => {
                capabilities.validate()?;
                Ok(capabilities)
            }
            response => Err(unexpected_state_response("state_capabilities_v1", response)),
        }
    }

    fn checkpoint(&mut self, max_bytes: u64) -> Result<BackendCheckpointV1> {
        self.ensure_state_boundary()?;
        self.send_command(&BackendWireCommandV2::CheckpointV1 { max_bytes })?;
        match self.recv_operation_response()? {
            BackendWireResponseV2::CheckpointV1 { checkpoint } => {
                checkpoint.validate()?;
                crate::backend_state::ensure_checkpoint_bound(&checkpoint, max_bytes)?;
                Ok(checkpoint)
            }
            BackendWireResponseV2::StatePinRequiredV1 { reason } => {
                Err(anyhow::Error::new(BackendStatePinned {
                    backend: reason.backend,
                    path: reason.path,
                    message: reason.message,
                }))
            }
            BackendWireResponseV2::StateErrorV1 { error } => bail!(
                "{}: backend={} message={}",
                error.code,
                error.backend,
                error.message
            ),
            response => Err(unexpected_state_response("checkpoint_v1", response)),
        }
    }

    fn restore(&mut self, checkpoint: BackendCheckpointV1) -> Result<BackendRestoreReceiptV1> {
        self.ensure_state_boundary()?;
        checkpoint.validate()?;
        self.send_command(&BackendWireCommandV2::RestoreV1 {
            checkpoint: checkpoint.clone(),
        })?;
        match self.recv_operation_response()? {
            BackendWireResponseV2::RestoreV1 { receipt } => {
                if !receipt.restored
                    || receipt.backend != checkpoint.backend
                    || receipt.checkpoint_sha256 != checkpoint.checkpoint_sha256()?
                {
                    bail!("backend returned an invalid restore receipt");
                }
                Ok(receipt)
            }
            BackendWireResponseV2::StatePinRequiredV1 { reason } => {
                Err(anyhow::Error::new(BackendStatePinned {
                    backend: reason.backend,
                    path: reason.path,
                    message: reason.message,
                }))
            }
            BackendWireResponseV2::StateErrorV1 { error } => bail!(
                "{}: backend={} message={}",
                error.code,
                error.backend,
                error.message
            ),
            response => Err(unexpected_state_response("restore_v1", response)),
        }
    }

    fn ensure_state_boundary(&self) -> Result<()> {
        if self.exec_pending || self.native_operation_depth > 0 {
            bail!("state.not-settled: backend execution is still pending");
        }
        Ok(())
    }

    fn shutdown(&mut self, timeout: Duration) -> Result<()> {
        // Retirement cancels publication of any unfinished execution. Its
        // shutdown acknowledgement is not an execution result or receipt.
        self.pending_morphism = None;
        let deadline = bounded_deadline(timeout, "backend shutdown")?;
        if let Err(error) = self.send_command(&BackendWireCommandV2::Shutdown) {
            let termination = self.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT);
            return match termination {
                Ok(()) => Err(anyhow::Error::new(BackendShutdownUnacknowledged(
                    format!("failed to send backend shutdown: {error:#}"),
                ))),
                Err(termination) => Err(anyhow!(
                    "failed to send backend shutdown: {error:#}; forced termination also failed: {termination:#}"
                )),
            };
        }
        lifecycle_trace(
            "worker.shutdown_sent",
            format!("language={} backend_pid={}", self.language, self.child.id()),
        );
        // The complete framed command has been flushed. Closing the command
        // pipe now guarantees EOF even for an older proxy or shim.
        self.stdin.take();

        match self.recv_shutdown_step_before(deadline, timeout) {
            Ok(ExecStep::Done(OValue::Null)) => lifecycle_trace(
                "worker.shutdown_acknowledged",
                format!("language={} backend_pid={}", self.language, self.child.id()),
            ),
            Ok(ExecStep::Done(other)) => {
                let termination = self.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT);
                return Err(anyhow!(
                    "backend `{}` acknowledged shutdown with {}, expected null{}",
                    self.language,
                    other.type_name(),
                    termination
                        .err()
                        .map(|error| format!("; forced termination failed: {error:#}"))
                        .unwrap_or_default()
                ));
            }
            Ok(ExecStep::EvalRequest { .. }) => {
                let termination = self.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT);
                return Err(anyhow!(
                    "backend `{}` requested O.eval while acknowledging shutdown{}",
                    self.language,
                    termination
                        .err()
                        .map(|error| format!("; forced termination failed: {error:#}"))
                        .unwrap_or_default()
                ));
            }
            Err(error) => {
                let termination = self.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT);
                return match termination {
                    Ok(()) => Err(anyhow::Error::new(BackendShutdownUnacknowledged(
                        format!("backend shutdown was not acknowledged: {error:#}"),
                    ))),
                    Err(termination) => Err(anyhow!(
                        "backend shutdown was not acknowledged: {error:#}; forced termination also failed: {termination:#}"
                    )),
                };
            }
        }

        // An acknowledgement is the backend's final protocol action. A
        // conforming backend exits naturally after it; avoiding an eager
        // signal also avoids conflating Darwin's zombie-only process-group
        // race with successful shutdown. The same absolute deadline governs
        // acknowledgement, leader exit, reader completion, and proof that no
        // active descendant remains in the owned process group.
        if let Err(natural_exit) = self.finish_graceful_shutdown(deadline, timeout) {
            let termination = self.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT);
            return match termination {
                Ok(()) => Err(natural_exit.context(
                    "backend acknowledged shutdown but did not terminate cleanly",
                )),
                Err(termination) => Err(anyhow!(
                    "backend acknowledged shutdown but did not terminate cleanly: {natural_exit:#}; forced termination also failed: {termination:#}"
                )),
            };
        }
        Ok(())
    }

    /// Retire a one-shot backend after a fresh environment completes.
    ///
    /// `shutdown` deliberately reports a missing protocol acknowledgement,
    /// even when its bounded fallback has already killed and reaped the owned
    /// process group. That strict diagnostic is useful for explicit lifecycle
    /// checks, but older compatibility shims do not implement the shutdown
    /// verb. Fresh-environment isolation requires physical retirement, not a
    /// particular acknowledgement. Accept the fallback only when `shutdown`
    /// proved the process, response reader, and owned group fully terminal.
    fn retire_fresh_attempt(&mut self, timeout: Duration) -> Result<()> {
        match self.shutdown(timeout) {
            Ok(()) => Ok(()),
            Err(graceful_error)
                if self.terminal && graceful_error.is::<BackendShutdownUnacknowledged>() =>
            {
                lifecycle_trace(
                    "worker.shutdown_forced_compatible",
                    format!(
                        "language={} backend_pid={} reason={graceful_error:#}",
                        self.language,
                        self.child.id()
                    ),
                );
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn recv_shutdown_step_before(
        &mut self,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<ExecStep> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                anyhow!(
                    "backend `{}` did not answer within {} ms",
                    self.language,
                    timeout.as_millis()
                )
            })?;
        let response = self
            .responses
            .recv_timeout(remaining)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => anyhow!(
                    "backend `{}` did not answer within {} ms",
                    self.language,
                    timeout.as_millis()
                ),
                mpsc::RecvTimeoutError::Disconnected => {
                    anyhow!("backend process closed stdout unexpectedly")
                }
            })?
            .map_err(anyhow::Error::msg)?;
        self.response_step(response)
    }

    fn finish_graceful_shutdown(&mut self, deadline: Instant, timeout: Duration) -> Result<()> {
        self.wait_for_leader_exit_before(deadline, timeout)?;
        self.finish_reader_before(deadline, timeout)?;
        self.wait_for_owned_group_quiescence_before(deadline, timeout)?;
        self.reap_leader_and_mark_terminal()
    }

    fn force_terminate(&mut self, timeout: Duration) -> Result<()> {
        if self.terminal {
            return self.finish_reader_bounded(timeout);
        }
        let deadline = bounded_deadline(timeout, "forced backend termination")?;
        let failures = self.send_forced_kill();
        self.settle_forced_kill(deadline, timeout, failures)
    }

    /// First half of a forced termination: close stdin and SIGKILL the owned
    /// group, without waiting.
    fn send_forced_kill(&mut self) -> Vec<String> {
        #[cfg(test)]
        kill_trace("kill");
        self.stdin.take();
        let mut failures = Vec::new();
        // a plain bash helper is its jobs' subreaper; a group SIGKILL would
        // end it first and hand its setsid jobs to init. it gets SIGTERM,
        // stops its shell and jobs, and exits; the group kill follows only
        // if it does not.
        #[cfg(unix)]
        if self.plain_bash_key.is_some() {
            // SAFETY: the pid is our own unreaped child, the group leader.
            if unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) } == 0 {
                self.graceful_term_sent = true;
                return failures;
            }
        }
        if let Err(error) = signal_owned_process_group(&mut self.child) {
            failures.push(format!("backend SIGKILL failed: {error:#}"));
        }
        failures
    }

    /// Second half: wait for leader, reader and group against `deadline`.
    fn settle_forced_kill(
        &mut self,
        deadline: Instant,
        timeout: Duration,
        mut failures: Vec<String>,
    ) -> Result<()> {
        #[cfg(test)]
        kill_trace("settle");

        let mut deadline = deadline;
        if std::mem::take(&mut self.graceful_term_sent) {
            // the helper's own cleanup gets the window a normal block end
            // gets, plus a little to exit; it is cleanup, not a step limit.
            // only then is its group killed, and the reap gets its own
            // budget after that.
            let window = PLAIN_BASH_CLEANUP_WINDOW + Duration::from_millis(500);
            if self
                .wait_for_leader_exit_before(Instant::now() + window, window)
                .is_err()
            {
                eprintln!(
                    "bash helper {} did not finish stopping its jobs within {} ms; \
                     its process group was killed, and a job that left that group \
                     (setsid) may still be alive",
                    self.child.id(),
                    window.as_millis()
                );
            }
            if let Err(error) = signal_owned_process_group(&mut self.child) {
                failures.push(format!("backend SIGKILL failed: {error:#}"));
            }
            deadline = Instant::now() + timeout;
        }

        let leader_exited = match self.wait_for_leader_exit_before(deadline, timeout) {
            Ok(()) => true,
            Err(error) => {
                failures.push(format!("backend leader wait failed: {error:#}"));
                false
            }
        };
        let reader_finished = match self.finish_reader_before(deadline, timeout) {
            Ok(()) => true,
            Err(error) => {
                failures.push(format!("backend response-reader wait failed: {error:#}"));
                false
            }
        };
        let group_quiescent = match self.wait_for_owned_group_quiescence_before(deadline, timeout) {
            Ok(()) => true,
            Err(error) => {
                failures.push(format!("backend process-group wait failed: {error:#}"));
                false
            }
        };
        if leader_exited && reader_finished && group_quiescent {
            if let Err(error) = self.reap_leader_and_mark_terminal() {
                failures.push(format!("backend leader reap failed: {error:#}"));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(failures.join("; ")))
        }
    }

    fn wait_for_leader_exit_before(&mut self, deadline: Instant, timeout: Duration) -> Result<()> {
        loop {
            if self.leader_exited_without_reaping()? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(anyhow!(
                    "backend `{}` process {} did not terminate within {} ms",
                    self.language,
                    self.child.id(),
                    timeout.as_millis()
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            thread::sleep(Duration::from_millis(2).min(remaining));
        }
    }

    #[cfg(unix)]
    fn leader_exited_without_reaping(&mut self) -> Result<bool> {
        loop {
            // SAFETY: `waitid` initializes siginfo for this exact direct child.
            // WNOWAIT observes exit without releasing the PID that anchors the
            // owned process-group identity while descendants are inspected.
            let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let status = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    &mut information,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if status == 0 {
                // SAFETY: successful waitid initialized `information`; si_pid
                // is zero when WNOHANG found no waitable state.
                return Ok(unsafe { information.si_pid() } != 0);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("failed to inspect backend leader state");
            }
        }
    }

    #[cfg(not(unix))]
    fn leader_exited_without_reaping(&mut self) -> Result<bool> {
        self.child
            .try_wait()
            .context("failed to inspect backend leader state")
            .map(|status| status.is_some())
    }

    fn wait_for_owned_group_quiescence_before(
        &self,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<()> {
        let group = i32::try_from(self.child.id())
            .map_err(|_| anyhow!("backend pid does not fit process-group identifier"))?;
        loop {
            if owned_group_has_no_active_descendants(group).with_context(|| {
                format!(
                    "failed to inspect backend `{}` process group {group}",
                    self.language
                )
            })? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(anyhow!(
                    "backend `{}` process group {} still contains an active descendant after {} ms",
                    self.language,
                    group,
                    timeout.as_millis()
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            thread::sleep(Duration::from_millis(2).min(remaining));
        }
    }

    fn reap_leader_and_mark_terminal(&mut self) -> Result<()> {
        self.child
            .wait()
            .context("failed to reap backend leader after termination")?;
        self.terminal = true;
        lifecycle_trace(
            "worker.backend_wait_returned",
            format!("language={} backend_pid={}", self.language, self.child.id()),
        );
        Ok(())
    }

    fn finish_reader_bounded(&mut self, timeout: Duration) -> Result<()> {
        let deadline = bounded_deadline(timeout, "backend response-reader")?;
        self.finish_reader_before(deadline, timeout)
    }

    fn finish_reader_before(&mut self, deadline: Instant, timeout: Duration) -> Result<()> {
        while self
            .reader
            .as_ref()
            .is_some_and(|reader| !reader.is_finished())
        {
            while self.responses.try_recv().is_ok() {}
            if Instant::now() >= deadline {
                return Err(anyhow!(
                    "backend `{}` response reader did not terminate within {} ms",
                    self.language,
                    timeout.as_millis()
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            thread::sleep(Duration::from_millis(2).min(remaining));
        }
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .map_err(|_| anyhow!("backend response reader panicked"))?;
        }
        Ok(())
    }
}

fn unexpected_state_response(operation: &str, response: BackendWireResponseV2) -> anyhow::Error {
    let kind = match response {
        BackendWireResponseV2::HeartbeatV1 { .. } => "heartbeat_v1",
        BackendWireResponseV2::HelloV1 { .. } => "hello_v1",
        BackendWireResponseV2::NativeOperationResultV1 { .. } => "native_operation_result_v1",
        BackendWireResponseV2::MorphismResultV1 { .. } => "morphism_result_v1",
        BackendWireResponseV2::Ok { .. } => "ok",
        BackendWireResponseV2::Err { .. } => "err",
        BackendWireResponseV2::EvalRequest { .. } => "eval_request",
        BackendWireResponseV2::StateCapabilitiesV1 { .. } => "state_capabilities_v1",
        BackendWireResponseV2::CheckpointV1 { .. } => "checkpoint_v1",
        BackendWireResponseV2::RestoreV1 { .. } => "restore_v1",
        BackendWireResponseV2::StatePinRequiredV1 { .. } => "state_pin_required_v1",
        BackendWireResponseV2::StateErrorV1 { .. } => "state_error_v1",
    };
    anyhow!("backend returned `{kind}` while answering `{operation}`")
}

/// Kill many actors against one shared budget: SIGKILL every group first so
/// the kernel tears them down in parallel, then reap each against the same
/// deadline. N stuck actors cost one budget, not N.
fn force_terminate_all(processes: &mut [BackendProcess], timeout: Duration) -> Vec<String> {
    let mut failures = Vec::new();
    let deadline = match bounded_deadline(timeout, "forced backend teardown") {
        Ok(deadline) => deadline,
        Err(error) => return vec![format!("{error:#}")],
    };
    let pending = processes
        .iter_mut()
        .map(|process| (!process.terminal).then(|| process.send_forced_kill()))
        .collect::<Vec<_>>();
    for (process, kill_failures) in processes.iter_mut().zip(pending) {
        let outcome = match kill_failures {
            Some(kill_failures) => process.settle_forced_kill(deadline, timeout, kill_failures),
            None => process.finish_reader_before(deadline, timeout),
        };
        if let Err(error) = outcome {
            failures.push(format!("{error:#}"));
        }
    }
    failures
}

impl Drop for BackendProcess {
    fn drop(&mut self) {
        if self.terminal {
            let _ = self.finish_reader_bounded(BACKEND_FALLBACK_REAP_TIMEOUT);
            return;
        }
        lifecycle_trace(
            "worker.backend_drop_fallback",
            format!("language={} backend_pid={}", self.language, self.child.id()),
        );
        // Never run a request/response protocol from a destructor. Closing the
        // pipe, killing the owned process group, and briefly polling for reap
        // are bounded best-effort fallback actions only.
        let _ = self.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT);
    }
}

/// Execute one cancellation-aware ephemeral backend operation and close its
/// physical process before returning the semantic result to the worker pool.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_ephemeral_with_eval_callback_controlled<F>(
    language: &str,
    code: &str,
    bindings: HashMap<String, OValue>,
    launch: BackendLaunchContext<'_>,
    morphism_contract: Option<crate::backend_morphism::BackendCrossingContractV1>,
    cancellation: Option<&crate::cancellation::CancellationToken>,
    plain_bash_next: bool,
    mut evaluate: F,
) -> Result<OValue>
where
    F: FnMut(String, Option<OValue>, Option<Duration>) -> Result<OValue>,
{
    if let Some(contract) = morphism_contract {
        contract
            .validate_bindings(language, &bindings)
            .map_err(anyhow::Error::msg)?;
    }
    let mut process = if language == "bash" && morphism_contract.is_none() {
        let key = PlainBashHelperKey::new(&launch, None).map_err(infrastructure_error)?;
        plain_bash_helper(key, || {
            BackendProcess::new_ephemeral(
                language,
                launch.shim_path,
                launch.sandbox,
                launch.executable_leases.map(AsRef::as_ref),
                true,
            )
        })
    } else {
        BackendProcess::new(
            language,
            launch.shim_path,
            launch.sandbox,
            launch.executable_leases.map(AsRef::as_ref),
        )
    }
    .with_context(|| format!("failed to start ephemeral backend `{language}`"))
    .map_err(infrastructure_error)?;
    let operation_timeout = backend_operation_timeout().map_err(infrastructure_error)?;
    let operation_deadline = match operation_timeout {
        Some(timeout) => Some(Instant::now().checked_add(timeout).ok_or_else(|| {
            infrastructure_error(anyhow!("backend operation deadline overflowed"))
        })?),
        None => None,
    };
    let mut watch = StepWatch::new(&process.pulse);
    let mut last_watch = Instant::now();

    process.plain_bash_next = plain_bash_next;
    let execution = (|| {
        process
            .begin_exec_with_morphism(code, bindings, morphism_contract)
            .map_err(infrastructure_error)?;
        lifecycle_trace(
            "worker.exec_sent",
            format!("language={language} environment=ephemeral"),
        );
        loop {
            if cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled) {
                return Err(infrastructure_error(anyhow::Error::new(
                    crate::cancellation::RequestCancellationObserved(format!(
                        "request cancelled while autonomous ephemeral backend `{language}` was running"
                    )),
                )));
            }
            let remaining = match (operation_deadline, operation_timeout) {
                (Some(deadline), Some(timeout)) => Some(
                    deadline.checked_duration_since(Instant::now()).ok_or_else(|| {
                        infrastructure_error(anyhow!(
                            "backend `{language}` operation exceeded {} ms (opt-in limit {BACKEND_OPERATION_TIMEOUT_ENV})",
                            timeout.as_millis()
                        ))
                    })?,
                ),
                _ => None,
            };
            if last_watch.elapsed() >= STEP_WATCH_TICK {
                last_watch = Instant::now();
                process
                    .watch_tick(&mut watch)
                    .map_err(infrastructure_error)?;
            }
            let step = process
                .poll_step(remaining.map_or(Duration::from_millis(25), |remaining| {
                    remaining.min(Duration::from_millis(25))
                }))
                .map_err(|error| {
                    if error.is::<BackendSemanticError>() {
                        error
                    } else {
                        infrastructure_error(error)
                    }
                })?;
            let Some(step) = step else { continue };
            match step {
                ExecStep::Done(value) => {
                    lifecycle_trace(
                        "worker.done_received",
                        format!("language={language} environment=ephemeral"),
                    );
                    return Ok(value);
                }
                ExecStep::EvalRequest { src, scope } => {
                    let value = evaluate(src, scope, remaining)?;
                    process
                        .send_eval_result(value)
                        .map_err(infrastructure_error)?;
                }
            }
        }
    })();
    watch.finish();

    // a plain bash helper already ended the block's shell and jobs before it
    // answered, so after a plain answer, value or bash error, it is as fresh
    // as a new one and goes back for the next plain block.
    let answered = match &execution {
        Ok(_) => true,
        Err(error) => error.is::<BackendSemanticError>(),
    };
    if answered && process.plain_bash_key.is_some() && process.idle() {
        park_plain_bash_helper(process);
        return execution;
    }
    match execution {
        Ok(value) => {
            process
                .retire_fresh_attempt(backend_shutdown_timeout().map_err(infrastructure_error)?)
                .with_context(|| {
                    format!(
                        "ephemeral backend `{language}` returned a value but could not be retired"
                    )
                })
                .map_err(infrastructure_error)?;
            Ok(value)
        }
        Err(error) => match process.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT) {
            Ok(()) => Err(error),
            Err(termination) => {
                let diagnostic = format!(
                    "{error:#}; ephemeral backend termination also failed: {termination:#}"
                );
                let error = if crate::cancellation::is_request_cancellation(&error) {
                    anyhow::Error::new(crate::cancellation::RequestCancellationObserved(diagnostic))
                } else {
                    anyhow!(diagnostic)
                };
                Err(infrastructure_error(error))
            }
        },
    }
}

// ############################################################################
// plain bash helpers
// ############################################################################

// why reuse: starting a backend process cost more than most plain blocks
// themselves. the helper keeps no shell between blocks, so reuse shares only
// the launch identity below, which is what a fresh helper would get anyway.
const PLAIN_BASH_HELPER_IDLE_MAX: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
struct PlainBashHelperKey {
    shim_path: PathBuf,
    sandbox: BackendSandboxPolicy,
    // the admitted bash executables; a different admission never reuses one.
    executables: Option<String>,
    // the registry's launch generation; None for autonomous ephemeral runs.
    launch_generation: Option<String>,
}

impl PlainBashHelperKey {
    fn new(launch: &BackendLaunchContext<'_>, launch_generation: Option<&str>) -> Result<Self> {
        Ok(Self {
            shim_path: launch.shim_path.to_path_buf(),
            sandbox: launch.sandbox.clone(),
            executables: launch
                .executable_leases
                .map(|leases| leases.backend_manifest_json("bash"))
                .transpose()?,
            launch_generation: launch_generation.map(str::to_string),
        })
    }
}

static PLAIN_BASH_HELPERS: Mutex<Vec<BackendProcess>> = Mutex::new(Vec::new());

/// A parked helper for `key`, or a new one from `spawn`.
/// PR_SET_PDEATHSIG with SIGTERM, then a check that the parent is still
/// `expected_parent`. why the check: a parent that died before the prctl
/// sends no signal, so a helper that finds itself reparented stops at once.
/// async-signal-safe, for a pre_exec hook.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn arm_parent_death_signal(expected_parent: libc::pid_t) -> io::Result<()> {
    // SAFETY: prctl with an integer signal number affects only this process.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getppid has no preconditions.
    if unsafe { libc::getppid() } != expected_parent {
        // no allocation here: this runs between fork and exec.
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

type SpawnRequest = (Command, mpsc::Sender<io::Result<Child>>);

/// Spawn `command` from one thread that lives as long as the process.
fn spawn_from_long_lived_thread(command: Command) -> io::Result<Child> {
    static SPAWNER: OnceLock<std::result::Result<Mutex<mpsc::Sender<SpawnRequest>>, String>> =
        OnceLock::new();
    let spawner = SPAWNER
        .get_or_init(|| {
            let (requests, incoming) = mpsc::channel::<SpawnRequest>();
            thread::Builder::new()
                .name("ostadix-plain-bash-spawner".into())
                .spawn(move || {
                    for (mut command, reply) in incoming {
                        let _ = reply.send(command.spawn());
                    }
                })
                .map(|_| Mutex::new(requests))
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| io::Error::other(format!("no helper spawner thread: {error}")))?;
    let (reply, answer) = mpsc::channel();
    spawner
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .send((command, reply))
        .map_err(|_| io::Error::other("the helper spawner thread is gone"))?;
    answer
        .recv()
        .map_err(|_| io::Error::other("the helper spawner thread is gone"))?
}

fn plain_bash_helper(
    key: PlainBashHelperKey,
    spawn: impl FnOnce() -> Result<BackendProcess>,
) -> Result<BackendProcess> {
    {
        let mut idle = PLAIN_BASH_HELPERS.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(index) = idle
            .iter()
            .position(|held| held.plain_bash_key.as_ref() == Some(&key))
        {
            let mut process = idle.swap_remove(index);
            // a helper that died while parked is reported and dropped, which
            // reaps it; a fresh one replaces it.
            let gone = match process.child.try_wait() {
                Ok(None) => return Ok(process),
                Ok(Some(status)) => format!("exited ({status})"),
                Err(error) => format!("could not be checked ({error})"),
            };
            lifecycle_trace(
                "worker.plain_bash_helper_dead",
                format!("backend_pid={} {gone}", process.child.id()),
            );
            eprintln!(
                "a parked bash helper (pid {}) {gone}; a new helper runs this block",
                process.child.id()
            );
        }
    }
    let mut process = spawn()?;
    process.plain_bash_key = Some(key);
    Ok(process)
}

fn park_plain_bash_helper(process: BackendProcess) {
    let mut idle = PLAIN_BASH_HELPERS.lock().unwrap_or_else(|e| e.into_inner());
    if idle.len() < PLAIN_BASH_HELPER_IDLE_MAX {
        idle.push(process);
    }
    // over the cap the helper drops here, which kills and reaps its group.
}

/// Stop every parked plain bash helper. Called when a process registry is
/// torn down, so no helper outlives the evaluation that started it.
pub(crate) fn retire_plain_bash_helpers() {
    let processes =
        std::mem::take(&mut *PLAIN_BASH_HELPERS.lock().unwrap_or_else(|e| e.into_inner()));
    // why graceful first: an idle helper answers shutdown at once, after
    // stopping its spare shell itself, while a forced kill polls the leader
    // and the group in 2 ms steps, which a one-block program paid at exit.
    // a malformed budget cannot be honoured, so the helpers are force-killed.
    let timeout = backend_shutdown_timeout().ok();
    let mut stuck = Vec::new();
    for mut process in processes {
        let outcome = match timeout {
            Some(timeout) => process.retire_fresh_attempt(timeout),
            None => Err(anyhow!("no valid {BACKEND_SHUTDOWN_TIMEOUT_ENV}")),
        };
        if let Err(error) = outcome {
            lifecycle_trace(
                "worker.plain_bash_helper_shutdown_failed",
                format!("{error:#}"),
            );
            if !process.terminal {
                stuck.push(process);
            }
        }
    }
    for error in force_terminate_all(&mut stuck, BACKEND_FALLBACK_REAP_TIMEOUT) {
        lifecycle_trace("worker.plain_bash_helper_cleanup_failed", error);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BackendSessionLimits {
    pub(crate) total: usize,
    pub(crate) per_backend: usize,
}

impl BackendSessionLimits {
    /// The session caps, parsed once. a malformed cap is an error at every
    /// read instead of silently becoming the default.
    fn from_env() -> Result<Self> {
        static LIMITS: OnceLock<std::result::Result<BackendSessionLimits, String>> =
            OnceLock::new();
        LIMITS
            .get_or_init(|| {
                (|| -> Result<Self> {
                    let total = positive_usize_from_env(
                        MAX_OPEN_SESSIONS_ENV,
                        DEFAULT_MAX_OPEN_BACKEND_SESSIONS,
                    )?;
                    let per_backend = positive_usize_from_env(
                        MAX_OPEN_SESSIONS_PER_BACKEND_ENV,
                        DEFAULT_MAX_OPEN_BACKEND_SESSIONS_PER_BACKEND,
                    )?
                    .min(total);
                    Ok(Self { total, per_backend })
                })()
                .map_err(|error| format!("{error:#}"))
            })
            .clone()
            .map_err(anyhow::Error::msg)
    }
}

fn positive_usize_from_env(name: &str, default: usize) -> Result<usize> {
    match std::env::var_os(name) {
        Some(raw) => positive_integer_knob(name, &raw),
        None => Ok(default),
    }
}

pub struct ProcessRegistry {
    registry: HashMap<(String, u32, BackendSandboxPolicy, String), BackendProcess>,
    suspended_fresh: Vec<SuspendedFreshActor>,
    // Ownership tombstones survive cleanup and prevent the old evaluator
    // from silently recreating actors after an acknowledged migration.
    migrated_actors: HashSet<(String, u32, BackendSandboxPolicy)>,
    // a malformed cap fails the first session that needs it.
    session_limits: std::result::Result<BackendSessionLimits, String>,
    registry_identity_sha256: String,
    morphism_contract: Option<crate::backend_morphism::BackendCrossingContractV1>,
    // persistent sessions killed by a response deadline. their interpreter
    // state is gone, and silently starting a fresh session under the same id
    // would turn that loss into a far-away NameError or a wrong default, so
    // later blocks on the id fail instead. kept for the registry lifetime.
    lost_sessions: HashMap<(String, u32, BackendSandboxPolicy), &'static str>,
    request_cancellation: Option<crate::cancellation::CancellationToken>,
    // for the next send_exec only; see [`Self::set_plain_bash_next`].
    plain_bash_next: bool,
}

pub(crate) struct FreshActorSuspension(String);

pub(crate) struct NativeOperationTicket {
    instance: String,
    request_id: String,
    previous_callback: bool,
    pub(crate) settled: bool,
}

struct SuspendedFreshActor {
    token: String,
    key: (String, u32, BackendSandboxPolicy, String),
    process: BackendProcess,
}

/// Admission-scoped physical launch authority shared by persistent and
/// ephemeral registry entry points. Grouping these immutable launch facts
/// keeps the semantic execution arguments separate from process authority.
pub(crate) struct BackendLaunchContext<'a> {
    pub(crate) shim_path: &'a Path,
    pub(crate) sandbox: &'a BackendSandboxPolicy,
    pub(crate) executable_leases: Option<&'a Arc<crate::runtime_exec::ExecutableLeaseSet>>,
    /// Canonical admission projection over this backend's exact executable
    /// set, consumed shim artifact, and child launch context. Persistent
    /// actors may be reused only within one such generation.
    pub(crate) launch_generation_sha256: Option<&'a str>,
}

impl Default for ProcessRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessRegistry {
    fn native_process_mut(&mut self, instance: &str) -> Result<&mut BackendProcess> {
        if let Some(process) = self
            .registry
            .values_mut()
            .find(|p| p.native_instance == instance)
        {
            return Ok(process);
        }
        self.suspended_fresh
            .iter_mut()
            .find(|p| p.process.native_instance == instance)
            .map(|p| &mut p.process)
            .context("native.owner-expired: exact physical owner is no longer live")
    }

    pub(crate) fn begin_native_operation(
        &mut self,
        handle: OValue,
        operation: &str,
        arguments: Vec<OValue>,
    ) -> Result<NativeOperationTicket> {
        if self.morphism_contract.is_some() {
            bail!("morphism.unsupported-native: native operations are outside the plain-data contract");
        }
        let OValue::Native { v } = &handle else {
            bail!("native.invalid-handle: expected an owner-resident native descriptor");
        };
        if v.lang != "python" || v.codec != "ostadix.python-owner-handle/v1" {
            bail!("native.unsupported-owner: only Python owner handles support these operations");
        }
        let metadata = |key: &str| -> Result<String> {
            match v.metadata.get(key) {
                Some(OValue::Text { v }) => Ok(v.utf8.clone()),
                _ => bail!("native.invalid-handle: missing owner {key}"),
            }
        };
        let instance = metadata("instance")?;
        let session = metadata("session")?;
        let generation = metadata("generation")?;
        let matching = self.registry.iter().any(|(key, process)| {
            key.0 == "python"
                && key.3 == generation
                && process.session_id == session
                && process.native_instance == instance
        }) || self.suspended_fresh.iter().any(|entry| {
            entry.key.0 == "python"
                && entry.key.3 == generation
                && entry.process.session_id == session
                && entry.process.native_instance == instance
        });
        if !matching {
            bail!(
                "native.owner-expired: no exact owner/session/generation is live in this evaluator"
            );
        }
        let process = self.native_process_mut(&instance)?;
        if process.terminal
            || ((process.exec_pending || process.native_operation_depth > 0)
                && !process.awaiting_callback)
        {
            bail!("native.owner-busy: owner is not idle or suspended at a callback boundary");
        }
        if process.native_operation_depth >= 64 {
            bail!("native.recursion-limit: owner operation nesting exceeds 64");
        }
        let request_id = fresh_registry_identity();
        let previous_callback = process.awaiting_callback;
        process.send_command(&BackendWireCommandV2::NativeOperationV1 {
            request_id: request_id.clone(),
            handle,
            operation: operation.to_owned(),
            arguments,
        })?;
        process.native_operation_depth += 1;
        process.awaiting_callback = false;
        Ok(NativeOperationTicket {
            instance,
            request_id,
            previous_callback,
            settled: false,
        })
    }

    pub(crate) fn recv_native_operation(
        &mut self,
        ticket: &mut NativeOperationTicket,
        timeout: Option<Duration>,
    ) -> Result<ExecStep> {
        let process = self.native_process_mut(&ticket.instance)?;
        let response = match timeout {
            Some(timeout) => process.recv_response_timeout(timeout)?,
            None => process.recv_response_watched(None)?,
        };
        match response {
            BackendWireResponseV2::NativeOperationResultV1 { request_id, value }
                if request_id == ticket.request_id =>
            {
                process.native_operation_depth -= 1;
                process.awaiting_callback = ticket.previous_callback;
                ticket.settled = true;
                Ok(ExecStep::Done(value))
            }
            BackendWireResponseV2::EvalRequest { src, scope } => {
                process.awaiting_callback = true;
                Ok(ExecStep::EvalRequest { src, scope })
            }
            _ => bail!("native.invalid-receipt: owner returned an unmatched operation response"),
        }
    }

    pub(crate) fn send_native_callback_result(
        &mut self,
        ticket: &NativeOperationTicket,
        value: OValue,
    ) -> Result<()> {
        self.native_process_mut(&ticket.instance)?
            .send_eval_result(value)
    }

    pub(crate) fn abort_native_operation(&mut self, ticket: &NativeOperationTicket) {
        if ticket.settled {
            return;
        }
        if let Some(key) = self
            .registry
            .iter()
            .find(|(_, p)| p.native_instance == ticket.instance)
            .map(|(key, _)| key.clone())
        {
            self.registry.remove(&key);
        }
        if let Some(index) = self
            .suspended_fresh
            .iter()
            .position(|p| p.process.native_instance == ticket.instance)
        {
            self.suspended_fresh.remove(index);
        }
    }

    /// Remove an actor after a non-semantic failure. A persistent session
    /// that a response deadline killed is recorded as lost.
    fn evict_failed(
        &mut self,
        key: &(String, u32, BackendSandboxPolicy, String),
        error: &anyhow::Error,
    ) -> Option<BackendProcess> {
        if let Some(cause) = session_killed_cause(error) {
            self.mark_session_lost(key, cause);
        }
        self.registry.remove(key)
    }

    fn mark_session_lost(
        &mut self,
        key: &(String, u32, BackendSandboxPolicy, String),
        cause: &'static str,
    ) {
        if key.1 <= crate::environment::MAX_PERSISTENT_ENV_ID {
            self.lost_sessions
                .insert((key.0.clone(), key.1, key.2.clone()), cause);
        }
    }

    fn reject_lost_session(
        &self,
        lang: &str,
        env_id: u32,
        sandbox: &BackendSandboxPolicy,
    ) -> Result<()> {
        if let Some(cause) = self
            .lost_sessions
            .get(&(lang.to_string(), env_id, sandbox.clone()))
        {
            return Err(infrastructure_error(anyhow!(
                "session {lang}[{env_id}] was terminated after {cause}; its state is gone"
            )));
        }
        Ok(())
    }

    pub(crate) fn set_morphism_contract(
        &mut self,
        contract: crate::backend_morphism::BackendCrossingContractV1,
    ) {
        self.morphism_contract = Some(contract);
    }

    pub(crate) fn morphism_contract(
        &self,
    ) -> Option<crate::backend_morphism::BackendCrossingContractV1> {
        self.morphism_contract
    }

    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
            suspended_fresh: Vec::new(),
            migrated_actors: HashSet::new(),
            session_limits: BackendSessionLimits::from_env().map_err(|error| format!("{error:#}")),
            registry_identity_sha256: fresh_registry_identity(),
            morphism_contract: None,
            lost_sessions: HashMap::new(),
            request_cancellation: None,
            plain_bash_next: false,
        }
    }

    #[cfg(test)]
    fn with_session_limits(total: usize, per_backend: usize) -> Self {
        assert!(total > 0 && per_backend > 0 && per_backend <= total);
        Self {
            registry: HashMap::new(),
            suspended_fresh: Vec::new(),
            migrated_actors: HashSet::new(),
            session_limits: Ok(BackendSessionLimits { total, per_backend }),
            registry_identity_sha256: fresh_registry_identity(),
            morphism_contract: None,
            lost_sessions: HashMap::new(),
            request_cancellation: None,
            plain_bash_next: false,
        }
    }

    /// Ensure the process for `(lang, env_id)` is running and send the Exec
    /// command. The caller must then drive the reply cycle with
    /// `recv_exec_step` / `send_eval_result` until a `Done` step arrives.
    pub(crate) fn send_exec(
        &mut self,
        lang: &str,
        env_id: u32,
        code: &str,
        bindings: HashMap<String, OValue>,
        launch: BackendLaunchContext<'_>,
    ) -> Result<()> {
        if let Some(contract) = self.morphism_contract {
            contract
                .validate_bindings(lang, &bindings)
                .map_err(anyhow::Error::msg)?;
        }
        self.reject_lost_session(lang, env_id, launch.sandbox)?;
        let launch_generation_sha256 = actor_launch_generation(&launch, lang)?;
        self.reject_generation_conflict(lang, env_id, launch.sandbox, &launch_generation_sha256)?;
        let key = (
            lang.to_string(),
            env_id,
            launch.sandbox.clone(),
            launch_generation_sha256,
        );
        if !self.registry.contains_key(&key) {
            self.ensure_session_capacity(lang)?;
            let session_id = fresh_or_persistent_session_identity(
                &self.registry_identity_sha256,
                lang,
                env_id,
                launch.sandbox,
            );
            let mut process = self
                .spawn_actor(lang, env_id, &launch, &session_id, &key.3)
                .with_context(|| format!("failed to start backend for language `{lang}`"))?;
            process.label = session_label(lang, env_id);
            self.registry.insert(key.clone(), process);
        }
        let morphism_contract = self.morphism_contract;
        let process = self
            .registry
            .get_mut(&key)
            .expect("backend was just inserted but is missing");
        process.write_cancellation = self.request_cancellation.clone();
        process.plain_bash_next = std::mem::take(&mut self.plain_bash_next);
        let sent = process.begin_exec_with_morphism(code, bindings, morphism_contract);
        process.write_cancellation = None;
        if let Err(error) = &sent {
            // a write ended by the opt-in limit or cancellation killed the
            // backend: evict it and record a numbered session as lost.
            if session_killed_cause(error).is_some() {
                drop(self.evict_failed(&key, error));
            }
        }
        sent.with_context(|| format!("failed to send Exec to backend `{lang}`"))?;
        lifecycle_trace(
            "worker.exec_sent",
            format!("language={lang} environment={env_id}"),
        );
        Ok(())
    }

    /// The request cancellation token that bounds large command writes
    /// (see `BackendProcess::send_command`). Set by the evaluator for the
    /// duration of a cancellable request.
    pub(crate) fn set_request_cancellation(
        &mut self,
        token: Option<crate::cancellation::CancellationToken>,
    ) {
        self.request_cancellation = token;
    }

    /// Tell the next `send_exec` that the plan has another plain bash block
    /// ahead. a hint only: a wrong value costs a spare shell or one inline
    /// fork, never a result.
    pub(crate) fn set_plain_bash_next(&mut self, ahead: bool) {
        self.plain_bash_next = ahead;
    }

    /// Read the next step from the shim for `(lang, env_id)`.
    pub(crate) fn recv_exec_step(
        &mut self,
        lang: &str,
        env_id: u32,
        sandbox: &BackendSandboxPolicy,
    ) -> Result<ExecStep> {
        let key = self.process_key(lang, env_id, sandbox)?;
        let step = self
            .registry
            .get_mut(&key)
            .ok_or_else(|| anyhow!("no live backend process for `{lang}[{env_id}]`"))?
            .recv_step();

        if let Err(error) = step.as_ref() {
            if !error.is::<BackendSemanticError>() {
                self.evict_failed(&key, error);
            }
        }
        let step = step.with_context(|| format!("backend `{lang}[{env_id}]` recv_step failed"))?;
        if matches!(step, ExecStep::Done(_)) {
            lifecycle_trace(
                "worker.done_received",
                format!("language={lang} environment={env_id}"),
            );
        }
        Ok(step)
    }

    /// Read one backend step under a caller-owned deadline. This is used by
    /// coordinator-side work nested inside an admitted worker callback so the
    /// outer operation cannot time out while recursive hosted execution waits
    /// forever in the coordinator.
    pub(crate) fn recv_exec_step_timeout(
        &mut self,
        lang: &str,
        env_id: u32,
        sandbox: &BackendSandboxPolicy,
        timeout: Duration,
    ) -> Result<ExecStep> {
        let key = self.process_key(lang, env_id, sandbox)?;
        let step = self
            .registry
            .get_mut(&key)
            .ok_or_else(|| anyhow!("no live backend process for `{lang}[{env_id}]`"))?
            .recv_step_timeout(timeout);
        let step = match step {
            Ok(step) => step,
            Err(error) if error.is::<BackendSemanticError>() => {
                return Err(error).with_context(|| {
                    format!("backend `{lang}[{env_id}]` returned an execution error")
                });
            }
            Err(error) => {
                self.mark_session_lost(&key, KILLED_BY_TIMEOUT);
                let mut process = self
                    .registry
                    .remove(&key)
                    .expect("timed receive process was present before removal");
                let termination = process.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT);
                let error = error.context(format!(
                    "backend `{lang}[{env_id}]` did not settle within the inherited callback deadline"
                ));
                return match termination {
                    Err(termination) => Err(infrastructure_error(anyhow!(
                        "{error:#}; backend termination also failed: {termination:#}"
                    ))),
                    Ok(()) if error.is::<BackendSemanticError>() => Err(error),
                    Ok(()) => Err(infrastructure_error(error)),
                };
            }
        };
        if matches!(step, ExecStep::Done(_)) {
            lifecycle_trace(
                "worker.done_received",
                format!("language={lang} environment={env_id}"),
            );
        }
        Ok(step)
    }

    /// Wait for a backend step while observing caller-owned cancellation and
    /// deadline state. Poll timeouts are non-terminal; cancellation, deadline,
    /// disconnection, or protocol failure removes and forcibly reaps the actor
    /// so request-private state can never leak into a subsequent request.
    pub(crate) fn recv_exec_step_controlled<F>(
        &mut self,
        lang: &str,
        env_id: u32,
        sandbox: &BackendSandboxPolicy,
        deadline: Option<Instant>,
        mut is_cancelled: F,
    ) -> Result<ExecStep>
    where
        F: FnMut() -> bool,
    {
        const POLL_INTERVAL: Duration = Duration::from_millis(25);
        let key = self.process_key(lang, env_id, sandbox)?;
        // the opt-in per-step limit applies here too. one call reads one
        // response, so the limit restarts per response exactly as on the
        // uncontrolled path. without it only cancellation, the request
        // deadline or a backend exit end the wait.
        let step_limit = backend_step_timeout().map_err(infrastructure_error)?;
        let step_deadline = match step_limit {
            Some(limit) => {
                Some(bounded_deadline(limit, "backend step").map_err(infrastructure_error)?)
            }
            None => None,
        };
        let mut watch = StepWatch::new(
            &self
                .registry
                .get(&key)
                .ok_or_else(|| anyhow!("no live backend process for `{lang}[{env_id}]`"))?
                .pulse,
        );
        let mut last_watch = Instant::now();
        let outcome = loop {
            let request_cancelled = is_cancelled();
            let now = Instant::now();
            let mut timed_out = false;
            let mut request_deadline = false;
            let terminal_reason = if request_cancelled {
                Some("request cancellation was observed".to_string())
            } else if deadline.is_some_and(|deadline| now >= deadline) {
                timed_out = true;
                request_deadline = true;
                Some(crate::cancellation::RequestDeadlineExpired("during execution").to_string())
            } else if let (Some(limit), Some(step_deadline)) = (step_limit, step_deadline) {
                (now >= step_deadline).then(|| {
                    timed_out = true;
                    step_limit_exceeded_reason(limit)
                })
            } else {
                None
            };
            if let Some(reason) = terminal_reason {
                self.mark_session_lost(
                    &key,
                    if timed_out {
                        KILLED_BY_TIMEOUT
                    } else {
                        KILLED_BY_CANCELLATION
                    },
                );
                let mut process = self
                    .registry
                    .remove(&key)
                    .expect("controlled receive process was present before removal");
                let termination = process.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT);
                let error = match termination {
                    Ok(()) => anyhow!("backend `{lang}[{env_id}]` {reason}; actor forcibly reaped"),
                    Err(termination) => anyhow!(
                        "backend `{lang}[{env_id}]` {reason}; actor termination also failed: {termination:#}"
                    ),
                };
                let error = if request_cancelled {
                    anyhow::Error::new(crate::cancellation::RequestCancellationObserved(format!(
                        "{error:#}"
                    )))
                } else {
                    anyhow::Error::new(BackendSessionKilled {
                        cause: KILLED_BY_TIMEOUT,
                        message: format!("{error:#}"),
                        request_deadline,
                    })
                };
                break Err(infrastructure_error(error));
            }

            let wait = match (deadline, step_deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
            .map_or(POLL_INTERVAL, |until| {
                until
                    .saturating_duration_since(Instant::now())
                    .min(POLL_INTERVAL)
            });
            let step = self
                .registry
                .get_mut(&key)
                .ok_or_else(|| anyhow!("no live backend process for `{lang}[{env_id}]`"))?
                .poll_step(wait);
            let step = match step {
                Ok(None) if last_watch.elapsed() < STEP_WATCH_TICK => continue,
                Ok(None) => {
                    last_watch = Instant::now();
                    let process = self
                        .registry
                        .get_mut(&key)
                        .ok_or_else(|| anyhow!("no live backend process for `{lang}[{env_id}]`"))?;
                    match process.watch_tick(&mut watch) {
                        Ok(()) => continue,
                        Err(error) => Err(error),
                    }
                }
                other => other.map(|step| step.expect("empty poll handled above")),
            };
            match step {
                Ok(step) => {
                    if matches!(step, ExecStep::Done(_)) {
                        lifecycle_trace(
                            "worker.done_received",
                            format!("language={lang} environment={env_id}"),
                        );
                    }
                    break Ok(step);
                }
                Err(error) if error.is::<BackendSemanticError>() => {
                    break Err(error).with_context(|| {
                        format!("backend `{lang}[{env_id}]` returned an execution error")
                    });
                }
                Err(error) => {
                    let mut process = self
                        .evict_failed(&key, &error)
                        .expect("failed controlled receive process was present before removal");
                    let termination = process.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT);
                    break match termination {
                        Ok(()) => Err(infrastructure_error(error.context(format!(
                            "backend `{lang}[{env_id}]` controlled receive failed"
                        )))),
                        Err(termination) => Err(infrastructure_error(anyhow!(
                            "backend `{lang}[{env_id}]` controlled receive failed: {error:#}; actor termination also failed: {termination:#}"
                        ))),
                    };
                }
            }
        };
        watch.finish();
        outcome
    }

    /// Send an eval_result back to the shim so it can resume execution.
    pub(crate) fn send_eval_result(
        &mut self,
        lang: &str,
        env_id: u32,
        value: OValue,
        sandbox: &BackendSandboxPolicy,
    ) -> Result<()> {
        let key = self.process_key(lang, env_id, sandbox)?;
        self.registry
            .get_mut(&key)
            .ok_or_else(|| anyhow!("no live backend process for `{lang}[{env_id}]`"))?
            .send_eval_result(value)
            .with_context(|| format!("failed to send eval_result to backend `{lang}`"))
    }

    /// Whether an exact logical actor/sandbox still has a published physical
    /// process, independent of its launch generation. Used only to classify a
    /// failed split-protocol settlement as a semantic refusal (actor retained)
    /// or ambiguous infrastructure loss (actor no longer usable).
    pub(crate) fn has_live_env(
        &self,
        lang: &str,
        env_id: u32,
        sandbox: &BackendSandboxPolicy,
    ) -> bool {
        self.registry
            .keys()
            .any(|(candidate_lang, candidate_env, candidate_sandbox, _)| {
                candidate_lang == lang && *candidate_env == env_id && candidate_sandbox == sandbox
            })
    }

    /// Park a fresh invocation while it awaits O.eval. Nested fresh calls may
    /// use the same public environment tag but own different physical actors.
    pub(crate) fn suspend_fresh_actor(
        &mut self,
        lang: &str,
        env_id: u32,
        sandbox: &BackendSandboxPolicy,
    ) -> Result<FreshActorSuspension> {
        if env_id <= crate::environment::MAX_PERSISTENT_ENV_ID {
            bail!("only fresh actors can be detached for callback recursion");
        }
        let key = self.process_key(lang, env_id, sandbox)?;
        let process = self
            .registry
            .remove(&key)
            .expect("resolved fresh actor exists");
        let token = fresh_registry_identity();
        self.suspended_fresh.push(SuspendedFreshActor {
            token: token.clone(),
            key,
            process,
        });
        Ok(FreshActorSuspension(token))
    }

    pub(crate) fn resume_fresh_actor(&mut self, token: FreshActorSuspension) -> Result<()> {
        if self
            .suspended_fresh
            .last()
            .map(|actor| actor.token.as_str())
            != Some(token.0.as_str())
        {
            bail!("fresh callback actor suspension stack is inconsistent");
        }
        let actor = self
            .suspended_fresh
            .pop()
            .expect("checked suspension exists");
        // Normally the nested invocation has already retired. Still reclaim
        // every residual inner actor before restoring the outer full key.
        let residual = self
            .registry
            .keys()
            .filter(|key| key.0 == actor.key.0 && key.1 == actor.key.1 && key.2 == actor.key.2)
            .cloned()
            .collect::<Vec<_>>();
        let mut residual = residual
            .into_iter()
            .filter_map(|key| self.registry.remove(&key))
            .collect::<Vec<_>>();
        let failures = force_terminate_all(&mut residual, BACKEND_FALLBACK_REAP_TIMEOUT);
        self.registry.insert(actor.key, actor.process);
        if !failures.is_empty() {
            bail!(
                "fresh callback residual actor cleanup failed: {}",
                failures.join(" | ")
            );
        }
        Ok(())
    }

    /// An unwinding callback cannot publish a result or leave its parked
    /// actors consuming capacity after a caller catches the Rust panic.
    pub(crate) fn cancel_fresh_callback_after_panic(&mut self, token: FreshActorSuspension) {
        let Some(index) = self
            .suspended_fresh
            .iter()
            .position(|actor| actor.token == token.0)
        else {
            return;
        };
        let mut processes = self
            .suspended_fresh
            .split_off(index)
            .into_iter()
            .map(|actor| actor.process)
            .collect::<Vec<_>>();
        let active = self
            .registry
            .keys()
            .filter(|key| key.1 > crate::environment::MAX_PERSISTENT_ENV_ID)
            .cloned()
            .collect::<Vec<_>>();
        for key in active {
            if let Some(process) = self.registry.remove(&key) {
                processes.push(process);
            }
        }
        for error in force_terminate_all(&mut processes, BACKEND_FALLBACK_REAP_TIMEOUT) {
            lifecycle_trace("callback.panic_cleanup_failed", error);
        }
    }

    pub(crate) fn exec(
        &mut self,
        lang: &str,
        env_id: u32,
        code: &str,
        bindings: HashMap<String, OValue>,
        launch: BackendLaunchContext<'_>,
    ) -> Result<OValue> {
        if let Some(contract) = self.morphism_contract {
            contract
                .validate_bindings(lang, &bindings)
                .map_err(anyhow::Error::msg)?;
        }
        self.reject_lost_session(lang, env_id, launch.sandbox)?;
        let launch_generation_sha256 = actor_launch_generation(&launch, lang)?;
        self.reject_generation_conflict(lang, env_id, launch.sandbox, &launch_generation_sha256)?;
        let key = (
            lang.to_string(),
            env_id,
            launch.sandbox.clone(),
            launch_generation_sha256,
        );

        if !self.registry.contains_key(&key) {
            self.ensure_session_capacity(lang)?;
            let session_id = fresh_or_persistent_session_identity(
                &self.registry_identity_sha256,
                lang,
                env_id,
                launch.sandbox,
            );
            let mut process = self
                .spawn_actor(lang, env_id, &launch, &session_id, &key.3)
                .with_context(|| format!("failed to start backend for language `{lang}`"))?;
            process.label = session_label(lang, env_id);
            self.registry.insert(key.clone(), process);
        }

        let result = self
            .registry
            .get_mut(&key)
            .expect("backend was just inserted but is missing")
            .exec_with_morphism(code, bindings, self.morphism_contract);

        if let Err(error) = result.as_ref() {
            if !error.is::<BackendSemanticError>() {
                self.evict_failed(&key, error);
            }
        }

        result.with_context(|| {
            let env_label = if env_id == u32::MAX {
                "*ephemeral*".to_string()
            } else {
                env_id.to_string()
            };

            format!(
                "backend `{}` env [{}] failed while executing code",
                lang, env_label
            )
        })
    }

    pub(crate) fn state_capabilities(
        &mut self,
        lang: &str,
        env_id: u32,
        sandbox: &BackendSandboxPolicy,
    ) -> Result<BackendStateCapabilitiesV1> {
        let key = self.process_key(lang, env_id, sandbox)?;
        self.registry
            .get_mut(&key)
            .expect("resolved backend process is missing")
            .state_capabilities()
            .with_context(|| {
                format!("failed to query backend state capabilities for `{lang}[{env_id}]`")
            })
    }

    pub(crate) fn checkpoint_env(
        &mut self,
        lang: &str,
        env_id: u32,
        sandbox: &BackendSandboxPolicy,
        max_bytes: u64,
    ) -> Result<BackendCheckpointV1> {
        let key = self.process_key(lang, env_id, sandbox)?;
        self.registry
            .get_mut(&key)
            .expect("resolved backend process is missing")
            .checkpoint(max_bytes)
            .with_context(|| format!("failed to checkpoint backend `{lang}[{env_id}]`"))
    }

    /// Capture every settled persistent actor without removing, replacing, or
    /// shutting down any registry entry. A refusal or protocol error aborts
    /// the whole aggregate, while actors already queried remain live.
    pub(crate) fn checkpoint_persistent_actors(
        &mut self,
        max_total_bytes: u64,
    ) -> Result<EvaluatorStateSnapshotV1> {
        if max_total_bytes == 0 {
            bail!("evaluator snapshot byte limit must be non-zero");
        }
        let mut ordered = self
            .registry
            .keys()
            .filter(|(_, env_id, _, _)| *env_id <= crate::environment::MAX_PERSISTENT_ENV_ID)
            .map(|key| {
                sandbox_policy_sha256(key.2.permissions()).map(|digest| (key.clone(), digest))
            })
            .collect::<Result<Vec<_>>>()?;
        ordered.sort_by(|(left, left_sandbox), (right, right_sandbox)| {
            (&left.0, left.1, left_sandbox, &left.3).cmp(&(
                &right.0,
                right.1,
                right_sandbox,
                &right.3,
            ))
        });

        let mut actors = Vec::with_capacity(ordered.len());
        let empty = EvaluatorStateSnapshotV1::new(Vec::new())?;
        ensure_evaluator_snapshot_bound(&empty, max_total_bytes)?;
        for ((lang, env_id, sandbox, launch_generation_sha256), _) in ordered {
            let partial = EvaluatorStateSnapshotV1::new(actors.clone())?;
            let used = u64::try_from(partial.encoded_len()?)
                .context("partial evaluator snapshot length exceeds u64")?;
            let remaining = max_total_bytes.checked_sub(used).ok_or_else(|| {
                anyhow!("evaluator snapshot metadata exhausted its aggregate byte limit")
            })?;
            if remaining == 0 {
                bail!("evaluator snapshot metadata exhausted its aggregate byte limit");
            }

            let capabilities = self.state_capabilities(&lang, env_id, &sandbox)?;
            if capabilities.backend != lang {
                bail!(
                    "backend `{lang}[{env_id}]` reported state identity `{}`",
                    capabilities.backend
                );
            }
            if capabilities.tier == BackendStateTierV1::ExternalPinned
                || !capabilities.restore_supported
            {
                return Err(anyhow::Error::new(BackendStatePinned {
                    backend: lang,
                    path: "$actor".to_string(),
                    message:
                        "backend state is pinned to external resources and has no portable restore"
                            .to_string(),
                }));
            }
            let checkpoint = self.checkpoint_env(&lang, env_id, &sandbox, remaining)?;
            if checkpoint.tier != capabilities.tier || checkpoint.codec != capabilities.codec {
                bail!(
                    "backend `{lang}[{env_id}]` checkpoint disagrees with its advertised state capabilities"
                );
            }
            actors.push(EvaluatorActorCheckpointV1::new(
                lang,
                env_id,
                sandbox.permissions().to_vec(),
                launch_generation_sha256,
                checkpoint,
            )?);
            let partial = EvaluatorStateSnapshotV1::new(actors.clone())?;
            ensure_evaluator_snapshot_bound(&partial, max_total_bytes)?;
        }

        let snapshot = EvaluatorStateSnapshotV1::new(actors)?;
        ensure_evaluator_snapshot_bound(&snapshot, max_total_bytes)?;
        Ok(snapshot)
    }

    /// Validate a staged restore set against the live registry without
    /// mutating either side. This makes multi-actor staging all-or-nothing.
    pub(crate) fn ensure_restore_targets_vacant(
        &self,
        actors: &[EvaluatorActorCheckpointV1],
    ) -> Result<()> {
        for actor in actors {
            let sandbox = BackendSandboxPolicy::new(actor.sandbox_permissions.iter().copied());
            self.ensure_actor_not_migrated(
                &actor.canonical_backend,
                actor.environment_id,
                &sandbox,
            )?;
            if self
                .registry
                .keys()
                .any(|(candidate_lang, candidate_env, candidate_sandbox, _)| {
                    candidate_lang == &actor.canonical_backend
                        && *candidate_env == actor.environment_id
                        && candidate_sandbox == &sandbox
                })
            {
                bail!(
                    "state.restore-conflict: backend `{}[{}]` already owns an open session for sandbox {}",
                    actor.canonical_backend,
                    actor.environment_id,
                    actor.sandbox_policy_sha256
                );
            }
        }
        Ok(())
    }

    /// Restore a checkpoint into a new physical actor and publish it only
    /// after the backend returns a matching receipt. An already-open logical
    /// session is never evicted or overwritten.
    pub(crate) fn restore_env(
        &mut self,
        lang: &str,
        env_id: u32,
        checkpoint: BackendCheckpointV1,
        launch: BackendLaunchContext<'_>,
    ) -> Result<BackendRestoreReceiptV1> {
        self.ensure_actor_not_migrated(lang, env_id, launch.sandbox)?;
        checkpoint.validate()?;
        if checkpoint.backend != lang {
            bail!(
                "state.restore-incompatible: checkpoint backend `{}` cannot restore as `{lang}`",
                checkpoint.backend
            );
        }
        if self
            .registry
            .keys()
            .any(|(candidate_lang, candidate_env, candidate_sandbox, _)| {
                candidate_lang == lang
                    && *candidate_env == env_id
                    && candidate_sandbox == launch.sandbox
            })
        {
            bail!(
                "state.restore-conflict: backend `{lang}[{env_id}]` already owns an open session"
            );
        }
        self.ensure_session_capacity(lang)?;
        let launch_generation_sha256 = actor_launch_generation(&launch, lang)?;
        let key = (
            lang.to_string(),
            env_id,
            launch.sandbox.clone(),
            launch_generation_sha256,
        );
        let session_id =
            actor_session_identity(&self.registry_identity_sha256, lang, env_id, launch.sandbox);
        let mut process = BackendProcess::new_with_session(
            lang,
            launch.shim_path,
            launch.sandbox,
            launch.executable_leases.map(AsRef::as_ref),
            &session_id,
            &key.3,
        )
        .with_context(|| format!("failed to start restore target for `{lang}[{env_id}]`"))?;
        match process.restore(checkpoint) {
            Ok(receipt) => {
                self.registry.insert(key, process);
                Ok(receipt)
            }
            Err(error) => {
                let termination = process.force_terminate(BACKEND_FALLBACK_REAP_TIMEOUT);
                match termination {
                    Ok(()) => Err(error),
                    Err(termination) => Err(anyhow!(
                        "{error:#}; failed restore target termination also failed: {termination:#}"
                    )),
                }
            }
        }
    }

    /// Start the backend for one registry key. a plain bash block (a fresh
    /// environment) runs in a reusable helper; numbered sessions and every
    /// other language get their own backend.
    fn spawn_actor(
        &self,
        lang: &str,
        env_id: u32,
        launch: &BackendLaunchContext<'_>,
        session_id: &str,
        launch_generation: &str,
    ) -> Result<BackendProcess> {
        let spawn = |plain_bash_helper| {
            BackendProcess::spawn(
                lang,
                launch.shim_path,
                launch.sandbox,
                launch.executable_leases.map(AsRef::as_ref),
                session_id,
                launch_generation,
                plain_bash_helper,
            )
        };
        if lang == "bash"
            && env_id > crate::environment::MAX_PERSISTENT_ENV_ID
            && self.morphism_contract.is_none()
        {
            let key = PlainBashHelperKey::new(launch, Some(launch_generation))?;
            plain_bash_helper(key, || spawn(true))
        } else {
            spawn(false)
        }
    }

    pub fn cleanup_env(&mut self, lang: &str, env_id: u32) -> Result<()> {
        let keys = self
            .registry
            .keys()
            .filter(|(candidate_lang, candidate_env, _, _)| {
                candidate_lang == lang && *candidate_env == env_id
            })
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(mut process) = self.registry.remove(&key) {
                // a plain bash helper ended the block's shell and jobs before
                // it answered; it goes back for the next plain block.
                if process.plain_bash_key.is_some() && process.idle() {
                    park_plain_bash_helper(process);
                    continue;
                }
                process.retire_fresh_attempt(backend_shutdown_timeout()?)?;
            }
        }
        Ok(())
    }

    /// Explicitly shut down every persistent backend, attempting all entries
    /// and reporting the combined physical teardown failures to the caller.
    pub fn shutdown_all(&mut self, timeout: Duration) -> Result<()> {
        let processes: Vec<_> = self
            .registry
            .drain()
            .map(|(_, process)| process)
            .chain(self.suspended_fresh.drain(..).map(|actor| actor.process))
            .collect();
        let mut failures = Vec::new();
        for mut process in processes {
            if let Err(error) = process.shutdown(timeout) {
                failures.push(format!("{error:#}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "one or more backend processes failed explicit shutdown: {}",
                failures.join(" | ")
            ))
        }
    }

    fn process_key(
        &self,
        lang: &str,
        env_id: u32,
        sandbox: &BackendSandboxPolicy,
    ) -> Result<(String, u32, BackendSandboxPolicy, String)> {
        let mut matching =
            self.registry
                .keys()
                .filter(|(candidate_lang, candidate_env, candidate_sandbox, _)| {
                    candidate_lang == lang
                        && *candidate_env == env_id
                        && candidate_sandbox == sandbox
                });
        let key = matching
            .next()
            .cloned()
            .ok_or_else(|| anyhow!("no live backend process for `{lang}[{env_id}]`"))?;
        if matching.next().is_some() {
            bail!("multiple launch generations are live for backend `{lang}[{env_id}]`");
        }
        Ok(key)
    }

    fn ensure_session_capacity(&self, lang: &str) -> Result<()> {
        let limits = self.session_limits.clone().map_err(anyhow::Error::msg)?;
        if self.registry.len() + self.suspended_fresh.len() >= limits.total {
            bail!(
                "session.capacity-exhausted: open backend sessions reached configured total quota {}",
                limits.total
            );
        }
        let backend_count = self
            .registry
            .keys()
            .filter(|(candidate_lang, _, _, _)| candidate_lang == lang)
            .count()
            + self
                .suspended_fresh
                .iter()
                .filter(|actor| actor.key.0 == lang)
                .count();
        if backend_count >= limits.per_backend {
            bail!(
                "session.capacity-exhausted: backend `{lang}` reached configured per-backend quota {}",
                limits.per_backend
            );
        }
        Ok(())
    }

    fn reject_generation_conflict(
        &self,
        lang: &str,
        env_id: u32,
        sandbox: &BackendSandboxPolicy,
        launch_generation_sha256: &str,
    ) -> Result<()> {
        self.ensure_actor_not_migrated(lang, env_id, sandbox)?;
        let conflicting_generation = self
            .registry
            .keys()
            .find(
                |(candidate_lang, candidate_env, candidate_sandbox, candidate_digest)| {
                    candidate_lang == lang
                        && *candidate_env == env_id
                        && candidate_sandbox == sandbox
                        && candidate_digest != launch_generation_sha256
                },
            )
            .map(|(_, _, _, digest)| digest);
        if let Some(conflicting_generation) = conflicting_generation {
            bail!(
                "session.generation-conflict: backend `{lang}[{env_id}]` remains pinned to launch generation `{conflicting_generation}`; explicitly checkpoint/cleanup/restore before using `{launch_generation_sha256}`"
            );
        }
        Ok(())
    }

    fn ensure_actor_not_migrated(
        &self,
        lang: &str,
        env_id: u32,
        sandbox: &BackendSandboxPolicy,
    ) -> Result<()> {
        if self
            .migrated_actors
            .contains(&(lang.to_string(), env_id, sandbox.clone()))
        {
            bail!("state.actor-migrated: backend `{lang}[{env_id}]` ownership left this evaluator");
        }
        Ok(())
    }

    pub(crate) fn migration_origin(&self) -> &str {
        &self.registry_identity_sha256
    }

    /// Remove exactly the transaction's actors. During commit, fence every
    /// source actor before physical teardown; rollback removes only restored
    /// destination actors and leaves their logical identities reusable.
    pub(crate) fn retire_migration_actors(
        &mut self,
        actors: &[EvaluatorActorCheckpointV1],
        fence: bool,
    ) -> Vec<String> {
        let mut retired = Vec::new();
        for actor in actors {
            let sandbox = BackendSandboxPolicy::new(actor.sandbox_permissions.iter().copied());
            if fence {
                self.migrated_actors.insert((
                    actor.canonical_backend.clone(),
                    actor.environment_id,
                    sandbox.clone(),
                ));
            }
            let key = (
                actor.canonical_backend.clone(),
                actor.environment_id,
                sandbox,
                actor.launch_generation_sha256.clone(),
            );
            if let Some(process) = self.registry.remove(&key) {
                retired.push(process);
            }
        }
        let mut failures = Vec::new();
        for mut process in retired {
            let outcome = backend_shutdown_timeout().and_then(|timeout| process.shutdown(timeout));
            if let Err(error) = outcome {
                failures.push(format!("{error:#}"));
            }
        }
        failures
    }
}

fn actor_launch_generation(launch: &BackendLaunchContext<'_>, lang: &str) -> Result<String> {
    if let Some(executable_leases) = launch.executable_leases {
        executable_leases.verify_backend(lang)?;
        let generation = launch.launch_generation_sha256.with_context(|| {
            format!("backend `{lang}` has no admitted launch-generation identity")
        })?;
        if generation.is_empty() {
            bail!("backend `{lang}` has an empty admitted launch-generation identity");
        }
        return Ok(generation.to_string());
    }
    #[cfg(test)]
    {
        Ok(launch
            .launch_generation_sha256
            .unwrap_or("unit-test-legacy-shim")
            .to_string())
    }
    #[cfg(not(test))]
    {
        bail!("backend `{lang}` has no admitted executable lease authority")
    }
}

fn fresh_registry_identity() -> String {
    let mut random = [0_u8; 32];
    if getrandom::fill(&mut random).is_ok() {
        return hex::encode(random);
    }
    let ordinal = BACKEND_SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    hex::encode(Sha256::digest(format!(
        "ostadix-registry-fallback/v1\0{}\0{}\0{}",
        std::process::id(),
        monotonic_nanos(),
        ordinal
    )))
}

fn actor_session_identity(
    registry_identity_sha256: &str,
    lang: &str,
    env_id: u32,
    sandbox: &BackendSandboxPolicy,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ostadix-backend-session/v1\0");
    digest.update(registry_identity_sha256.as_bytes());
    digest.update([0]);
    digest.update(lang.as_bytes());
    digest.update([0]);
    digest.update(env_id.to_be_bytes());
    for authority in sandbox.names() {
        digest.update([0]);
        digest.update(authority.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn fresh_or_persistent_session_identity(
    registry: &str,
    lang: &str,
    env_id: u32,
    sandbox: &BackendSandboxPolicy,
) -> String {
    if env_id > crate::environment::MAX_PERSISTENT_ENV_ID {
        fresh_registry_identity()
    } else {
        actor_session_identity(registry, lang, env_id, sandbox)
    }
}

impl Drop for ProcessRegistry {
    fn drop(&mut self) {
        // bounded best-effort local termination only. explicit protocol
        // shutdown belongs to callers such as `cleanup_env`, never to this
        // destructor. every actor is killed before any is waited on, so N
        // stuck actors share one reap budget instead of costing N of them.
        let mut processes = self
            .registry
            .drain()
            .map(|(_, process)| process)
            .chain(self.suspended_fresh.drain(..).map(|actor| actor.process))
            .collect::<Vec<_>>();
        for error in force_terminate_all(&mut processes, BACKEND_FALLBACK_REAP_TIMEOUT) {
            lifecycle_trace("worker.registry_drop_cleanup_failed", error);
        }
        retire_plain_bash_helpers();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_teardown_and_session_knobs_are_errors_not_defaults() {
        use std::ffi::OsStr;
        let max = MAXIMUM_BACKEND_SHUTDOWN_TIMEOUT;
        assert_eq!(
            duration_knob("K", OsStr::new("2500"), max).unwrap(),
            Duration::from_millis(2500)
        );
        // surrounding blanks are trimmed as the step knobs do.
        assert_eq!(positive_integer_knob("K", OsStr::new(" 5 ")).unwrap(), 5);
        assert_eq!(
            duration_knob("K", OsStr::new("\t2500\n"), max).unwrap(),
            Duration::from_millis(2500)
        );
        for bad in ["", " ", "abc", "0", "-1", "1.5", "5 5"] {
            assert!(duration_knob("K", OsStr::new(bad), max).is_err(), "{bad:?}");
            assert!(
                positive_integer_knob("K", OsStr::new(bad)).is_err(),
                "{bad:?}"
            );
        }
        assert!(duration_knob("K", OsStr::new("60001"), max).is_err());
        assert_eq!(positive_integer_knob("K", OsStr::new("8")).unwrap(), 8);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_helper_whose_parent_is_already_gone_stops_at_once() {
        // a live parent: armed, nothing to do.
        let parent = std::process::id() as libc::pid_t;
        // SAFETY: the child calls only async-signal-safe functions, then _exit.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let code = if arm_parent_death_signal(parent).is_ok() {
                0
            } else {
                1
            };
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);

        // a parent that died before the prctl: the helper is told to stop.
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: as above; the middle process only forks and exits.
        let middle = unsafe { libc::fork() };
        assert!(middle >= 0);
        if middle == 0 {
            let middle_pid = unsafe { libc::getpid() };
            if unsafe { libc::fork() } == 0 {
                while unsafe { libc::getppid() } == middle_pid {
                    unsafe { libc::usleep(1000) };
                }
                let byte: u8 = match arm_parent_death_signal(middle_pid) {
                    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => b'y',
                    _ => b'n',
                };
                unsafe {
                    libc::write(fds[1], (&byte as *const u8).cast(), 1);
                    libc::_exit(0);
                }
            }
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::close(fds[1]) };
        assert_eq!(unsafe { libc::waitpid(middle, &mut status, 0) }, middle);
        let mut byte = 0u8;
        let read = unsafe { libc::read(fds[0], (&mut byte as *mut u8).cast(), 1) };
        unsafe { libc::close(fds[0]) };
        assert_eq!((read, byte), (1, b'y'));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_procfs_vanished_entry_errors_are_narrowly_classified() {
        let not_found = io::Error::new(io::ErrorKind::NotFound, "vanished proc entry");
        let esrch = io::Error::from_raw_os_error(libc::ESRCH);
        let permission_denied = io::Error::from_raw_os_error(libc::EACCES);
        let malformed = io::Error::new(io::ErrorKind::InvalidData, "malformed stat");

        assert!(linux_process_observation_disappeared(&not_found));
        assert!(linux_process_observation_disappeared(&esrch));
        assert!(!linux_process_observation_disappeared(&permission_denied));
        assert!(!linux_process_observation_disappeared(&malformed));
    }

    fn python_shim_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("backends/python_shim.py")
    }

    fn test_launch_context<'a>(
        shim_path: &'a Path,
        sandbox: &'a BackendSandboxPolicy,
        launch_generation_sha256: &'a str,
    ) -> BackendLaunchContext<'a> {
        BackendLaunchContext {
            shim_path,
            sandbox,
            executable_leases: None,
            launch_generation_sha256: Some(launch_generation_sha256),
        }
    }

    #[test]
    fn suspended_fresh_actor_preserves_identity_pending_state_and_capacity() -> Result<()> {
        let mut registry = ProcessRegistry::with_session_limits(2, 1);
        let shim = python_shim_path();
        let sandbox = BackendSandboxPolicy::none();
        registry.send_exec(
            "python",
            u32::MAX,
            "O.eval('callback')",
            HashMap::new(),
            test_launch_context(&shim, &sandbox, &"ab".repeat(32)),
        )?;
        assert!(matches!(
            registry.recv_exec_step("python", u32::MAX, &sandbox)?,
            ExecStep::EvalRequest { .. }
        ));
        let pid = registry.registry.values().next().unwrap().child.id();
        let token = registry.suspend_fresh_actor("python", u32::MAX, &sandbox)?;
        assert!(registry.registry.is_empty());
        assert!(registry
            .ensure_session_capacity("python")
            .unwrap_err()
            .to_string()
            .contains("session.capacity-exhausted"));
        registry.ensure_session_capacity("javascript")?;
        registry.resume_fresh_actor(token)?;
        assert_eq!(registry.registry.values().next().unwrap().child.id(), pid);
        registry.send_eval_result("python", u32::MAX, OValue::int(42), &sandbox)?;
        assert!(
            matches!(registry.recv_exec_step("python", u32::MAX, &sandbox)?, ExecStep::Done(value) if value == OValue::int(42))
        );
        registry.cleanup_env("python", u32::MAX)?;
        registry.ensure_session_capacity("python")?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn suspended_fresh_panic_cancellation_reaps_process_and_releases_capacity() -> Result<()> {
        let mut registry = ProcessRegistry::with_session_limits(1, 1);
        let shim = python_shim_path();
        let sandbox = BackendSandboxPolicy::none();
        registry.send_exec(
            "python",
            u32::MAX,
            "O.eval('callback')",
            HashMap::new(),
            test_launch_context(&shim, &sandbox, &"cd".repeat(32)),
        )?;
        assert!(matches!(
            registry.recv_exec_step("python", u32::MAX, &sandbox)?,
            ExecStep::EvalRequest { .. }
        ));
        let pid = registry.registry.values().next().unwrap().child.id() as i32;
        let token = registry.suspend_fresh_actor("python", u32::MAX, &sandbox)?;
        registry.cancel_fresh_callback_after_panic(token);
        assert!(registry.registry.is_empty());
        assert!(registry.suspended_fresh.is_empty());
        registry.ensure_session_capacity("python")?;
        // SAFETY: signal zero only observes this exact owned child PID.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        Ok(())
    }

    fn spawn_python_shim() -> Result<BackendProcess> {
        BackendProcess::new(
            "python",
            &python_shim_path(),
            &BackendSandboxPolicy::none(),
            None,
        )
    }

    fn spawn_python_shim_with(
        permissions: impl IntoIterator<Item = crate::value::BackendAuthority>,
    ) -> Result<BackendProcess> {
        BackendProcess::new(
            "python",
            &python_shim_path(),
            &BackendSandboxPolicy::new(permissions),
            None,
        )
    }

    fn expect_done(step: ExecStep) -> OValue {
        match step {
            ExecStep::Done(value) => value,
            ExecStep::EvalRequest { src, .. } => {
                panic!("expected Done step from shim, got EvalRequest({src:?})")
            }
        }
    }

    #[test]
    fn ping_round_trip_returns_null() -> Result<()> {
        let mut process = spawn_python_shim()?;

        process.send_command(&BackendWireCommandV2::Ping)?;
        let value = expect_done(process.recv_step()?);

        assert_eq!(value, OValue::Null);
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn exec_without_bindings_returns_int_result() -> Result<()> {
        let mut process = spawn_python_shim()?;

        let value = process.exec("__oval_result__ = 42", HashMap::new())?;

        assert_eq!(value, OValue::int(42));
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn exec_python_big_int_result_uses_number_ovalue() -> Result<()> {
        use crate::value::ONumber;

        let mut process = spawn_python_shim()?;

        let value = process.exec("__oval_result__ = 2 ** 100", HashMap::new())?;

        match value {
            OValue::Number {
                v: ONumber::Int { v },
            } => {
                let expected = num_bigint::BigInt::from(1_u8) << 100_u32;
                assert_eq!(v, expected);
            }
            other => panic!("expected number/int OValue, got {other:?}"),
        }
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn exec_python_huge_numbers_bypass_decimal_digit_limits() -> Result<()> {
        use crate::backend_catalog::SpliceRenderer;
        use crate::eval_core::render_with;
        use crate::value::ONumber;

        let mut process = spawn_python_shim()?;
        let digits = "9".repeat(5_000);
        let decimal_coefficient = num_bigint::BigInt::parse_bytes(digits.as_bytes(), 10).unwrap();
        let hex_digits = "f".repeat(5_000);
        let integer_value =
            OValue::big_int(num_bigint::BigInt::parse_bytes(hex_digits.as_bytes(), 16).unwrap());
        let integer_source = render_with(SpliceRenderer::Python, &integer_value);

        let integer = process.exec(
            &format!("int = None\n__oval_result__ = {integer_source}"),
            HashMap::new(),
        )?;
        assert_eq!(integer, integer_value.clone());

        let decimal_value = OValue::number(ONumber::Decimal {
            coeff: decimal_coefficient,
            exp10: 0,
            special: None,
        });
        let decimal_source = render_with(SpliceRenderer::Python, &decimal_value);
        let decimal = process.exec(
            &format!("__oval_result__ = {decimal_source}"),
            HashMap::new(),
        )?;
        assert_eq!(decimal, decimal_value);

        let bindings = HashMap::from([("huge".to_string(), integer_value)]);
        assert_eq!(
            process.exec(
                &format!("__oval_result__ = huge == {integer_source}"),
                bindings,
            )?,
            OValue::bool_(true),
        );

        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn python_scope_with_invalid_nested_numbers_round_trips_without_crashing() -> Result<()> {
        use crate::backend_catalog::SpliceRenderer;
        use crate::eval_core::render_with;
        use crate::value::{FloatFormat, ONumber};

        let scope = OValue::scope(HashMap::from([
            (
                "zero_denominator".to_string(),
                OValue::number(ONumber::Rational {
                    num: 1.into(),
                    den: 0.into(),
                }),
            ),
            (
                "malformed_float".to_string(),
                OValue::number(ONumber::BinaryFloat {
                    format: FloatFormat::F64,
                    bits: vec![0],
                }),
            ),
            (
                "malformed_blob".to_string(),
                OValue::Blob {
                    v: "a".to_string(),
                    mime: "application/octet-stream".to_string(),
                },
            ),
        ]));
        let source = render_with(SpliceRenderer::Python, &scope);
        let mut process = spawn_python_shim()?;

        assert_eq!(
            process.exec(&format!("__oval_result__ = {source}"), HashMap::new())?,
            scope,
        );

        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn exec_python_bytes_result_uses_structural_bytes() -> Result<()> {
        let mut process = spawn_python_shim()?;

        let value = process.exec("__oval_result__ = bytes([0, 1, 255])", HashMap::new())?;

        match value {
            OValue::Bytes { v } => {
                assert_eq!(v.bytes, vec![0, 1, 255]);
                assert_eq!(v.media_type.as_deref(), Some("application/octet-stream"));
            }
            other => panic!("expected bytes OValue, got {other:?}"),
        }
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn exec_python_set_result_uses_structural_unordered_set() -> Result<()> {
        use crate::value::SetKind;

        let mut process = spawn_python_shim()?;

        let value = process.exec("__oval_result__ = {1, 2}", HashMap::new())?;

        match value {
            OValue::Set { kind, mut items } => {
                assert_eq!(kind, SetKind::Unordered);
                items.sort_by_key(OValue::canonical_bytes);
                assert_eq!(items, vec![OValue::int(1), OValue::int(2)]);
            }
            other => panic!("expected structural set OValue, got {other:?}"),
        }
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn exec_python_unsupported_object_fails_instead_of_stringifying() -> Result<()> {
        let mut process = spawn_python_shim()?;

        let error = process
            .exec(
                concat!(
                    "class HiddenState:\n",
                    "    def __str__(self):\n",
                    "        return 'silently-erased-object'\n",
                    "__oval_result__ = HiddenState()\n",
                ),
                HashMap::new(),
            )
            .expect_err("an unsupported Python object must not cross as O text");
        let message = format!("{error:#}");

        assert!(
            message.contains("unsupported Python value for OValue projection:")
                && message.contains("HiddenState"),
            "{message}"
        );
        assert!(!message.contains("silently-erased-object"), "{message}");
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn exec_with_string_binding_round_trips_through_shim() -> Result<()> {
        let mut process = spawn_python_shim()?;
        let bindings = HashMap::from([("msg".to_string(), OValue::str_("hello"))]);

        let value = process.exec("__oval_result__ = msg.upper()", bindings)?;

        assert_eq!(value, OValue::str_("HELLO"));
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn exec_reports_backend_errors_without_panicking() -> Result<()> {
        let mut process = spawn_python_shim()?;

        let err = process
            .exec("raise RuntimeError('boom from shim')", HashMap::new())
            .unwrap_err();

        assert!(err.to_string().contains("boom from shim"));
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn cleanup_command_returns_ok_null() -> Result<()> {
        let mut process = spawn_python_shim()?;

        process.send_command(&BackendWireCommandV2::Cleanup)?;
        let value = expect_done(process.recv_step()?);

        assert_eq!(value, OValue::Null);
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn python_checkpoint_restore_preserves_mutable_alias_cycle() -> Result<()> {
        let mut source = spawn_python_shim()?;
        source.exec(
            "x = []\nx.append(x)\ny = x\n__oval_result__ = 'ready'",
            HashMap::new(),
        )?;
        let checkpoint = source.checkpoint(1024 * 1024)?;
        source.shutdown(backend_shutdown_timeout()?)?;

        let mut target = spawn_python_shim()?;
        let receipt = target.restore(checkpoint.clone())?;
        assert!(receipt.restored);
        assert_eq!(receipt.checkpoint_sha256, checkpoint.checkpoint_sha256()?);
        assert_eq!(
            target.exec("__oval_result__ = x is y and x[0] is x", HashMap::new())?,
            OValue::bool_(true)
        );
        target.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn python_checkpoint_restore_preserves_unbounded_integers_and_fractions() -> Result<()> {
        let mut source = spawn_python_shim()?;
        source.exec(
            concat!(
                "huge = 10 ** 5000\n",
                "ratio = __import__('fractions').Fraction(huge, 3)\n",
                "__oval_result__ = 'ready'",
            ),
            HashMap::new(),
        )?;
        let checkpoint = source.checkpoint(1024 * 1024)?;
        source.shutdown(backend_shutdown_timeout()?)?;

        let mut target = spawn_python_shim()?;
        target.restore(checkpoint)?;
        assert_eq!(
            target.exec(
                concat!(
                    "__oval_result__ = (\n",
                    "    huge == 10 ** 5000\n",
                    "    and ratio.numerator == huge\n",
                    "    and ratio.denominator == 3\n",
                    ")",
                ),
                HashMap::new(),
            )?,
            OValue::bool_(true)
        );
        target.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn unsupported_python_checkpoint_pins_and_keeps_actor_live() -> Result<()> {
        let mut process = spawn_python_shim()?;
        process.exec("f = lambda: 42\n__oval_result__ = 'ready'", HashMap::new())?;
        let error = process
            .checkpoint(1024 * 1024)
            .expect_err("functions are outside the constrained graph codec");
        let pin = error
            .downcast_ref::<BackendStatePinned>()
            .expect("checkpoint refusal must retain a typed pin reason");
        assert_eq!(pin.path, "$globals['f']");
        assert_eq!(
            process.exec("__oval_result__ = f()", HashMap::new())?,
            OValue::int(42)
        );
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn shutdown_is_acknowledged_and_process_is_reaped() -> Result<()> {
        let mut process = spawn_python_shim()?;
        let pid = process.child.id();
        // A completed exchange proves protocol readiness before the unchanged
        // two-second acknowledgement and shutdown budget starts.
        assert_eq!(
            process.exec("__oval_result__ = None", HashMap::new())?,
            OValue::Null
        );

        process.shutdown(Duration::from_secs(2))?;

        assert!(process.terminal, "backend {pid} was not marked terminal");
        assert!(
            process.child.try_wait()?.is_some(),
            "backend {pid} was not reaped"
        );
        Ok(())
    }

    #[test]
    fn shutdown_timeout_is_one_deadline_across_acknowledgement_and_exit() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let shim = temp.path().join("delayed_shutdown.py");
        let common = Path::new(env!("CARGO_MANIFEST_DIR")).join("backends/o_shim_common.py");
        std::fs::copy(python_shim_path(), &shim)?;
        for &support in crate::shims::BUNDLED_SHIM_SUPPORT_NAMES {
            if support != "o_shim_common.py" {
                std::fs::copy(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("backends")
                        .join(support),
                    temp.path().join(support),
                )?;
            }
        }

        let source = std::fs::read_to_string(&common)?;
        let original = concat!(
            "            elif tag == \"shutdown\":\n",
            "                send_ok({\"t\": \"null\"})\n",
            "                break\n",
        );
        let delayed = concat!(
            "            elif tag == \"shutdown\":\n",
            "                __import__(\"time\").sleep(0.2)\n",
            "                send_ok({\"t\": \"null\"})\n",
            "                __import__(\"time\").sleep(0.4)\n",
            "                break\n",
        );
        assert!(
            source.contains(original),
            "shared shim shutdown branch changed; update the deadline fixture"
        );
        std::fs::write(
            temp.path().join("o_shim_common.py"),
            source.replacen(original, delayed, 1),
        )?;

        let mut process =
            BackendProcess::new("python", &shim, &BackendSandboxPolicy::none(), None)?;
        // Isolate acknowledgement and exit from interpreter startup. The
        // completed exchange proves the delayed-shutdown fixture is ready
        // before its original 500 ms shutdown budget starts.
        assert_eq!(
            process.exec("__oval_result__ = None", HashMap::new())?,
            OValue::Null
        );
        let started = Instant::now();
        let error = process
            .shutdown(Duration::from_millis(500))
            .expect_err("acknowledgement and exit must share one 500 ms deadline");

        assert!(started.elapsed() < Duration::from_secs(2), "{error:#}");
        assert!(
            format!("{error:#}").contains("did not terminate within 500 ms"),
            "{error:#}"
        );
        assert!(process.terminal, "forced termination did not reap backend");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn graceful_shutdown_force_kills_lingering_same_group_descendant() -> Result<()> {
        use crate::value::BackendAuthority;

        // DEVNULL is opened read/write by Python's subprocess module, so the
        // fixture needs FileWrite in addition to the Process authority that
        // permits the descendant spawn itself.
        let mut process =
            spawn_python_shim_with([BackendAuthority::Process, BackendAuthority::FileWrite])?;
        let group = i32::try_from(process.child.id())?;
        let value = process.exec(
            concat!(
                "import subprocess\n",
                "_o_lingering_child = subprocess.Popen(\n",
                "    ['/bin/sleep', '60'],\n",
                "    stdin=subprocess.DEVNULL,\n",
                "    stdout=subprocess.DEVNULL,\n",
                "    stderr=subprocess.DEVNULL,\n",
                ")\n",
                "__oval_result__ = _o_lingering_child.pid",
            ),
            HashMap::new(),
        )?;
        let descendant = i32::try_from(value.as_int()?)?;
        // SAFETY: `getpgid` only inspects the live PID returned by Popen.
        assert_eq!(unsafe { libc::getpgid(descendant) }, group);

        let error = process
            .shutdown(Duration::from_millis(500))
            .expect_err("a lingering active descendant must fail graceful shutdown");

        assert!(
            format!("{error:#}").contains("still contains an active descendant"),
            "{error:#}"
        );
        assert!(process.terminal, "forced group termination did not settle");
        assert!(
            owned_group_has_no_active_descendants(group)?,
            "backend group {group} retained an active descendant after forced shutdown"
        );
        assert!(
            process.child.try_wait()?.is_some(),
            "backend group leader was not reaped"
        );
        Ok(())
    }

    #[test]
    fn registry_shutdown_all_is_explicit_and_drains_every_process() -> Result<()> {
        let mut registry = ProcessRegistry::new();
        let sandbox = BackendSandboxPolicy::none();
        for env_id in [0, 1] {
            registry.send_exec(
                "python",
                env_id,
                "__oval_result__ = 'done'",
                HashMap::new(),
                BackendLaunchContext {
                    shim_path: &python_shim_path(),
                    sandbox: &sandbox,
                    executable_leases: None,
                    launch_generation_sha256: None,
                },
            )?;
            assert!(matches!(
                registry.recv_exec_step("python", env_id, &sandbox)?,
                ExecStep::Done(value) if value == OValue::str_("done")
            ));
        }

        registry.shutdown_all(Duration::from_secs(2))?;
        assert!(registry.registry.is_empty());
        Ok(())
    }

    #[test]
    fn session_quota_refuses_new_actor_without_evicting_open_session() -> Result<()> {
        let mut registry = ProcessRegistry::with_session_limits(1, 1);
        let sandbox = BackendSandboxPolicy::none();
        let shim = python_shim_path();
        registry.exec(
            "python",
            1,
            "retained = 42\n'created'",
            HashMap::new(),
            test_launch_context(&shim, &sandbox, "quota-test-generation"),
        )?;

        let error = registry
            .exec(
                "python",
                2,
                "'must-not-run'",
                HashMap::new(),
                test_launch_context(&shim, &sandbox, "quota-test-generation"),
            )
            .expect_err("a second actor must exceed the configured quota");
        assert!(
            format!("{error:#}").contains("session.capacity-exhausted"),
            "{error:#}"
        );

        assert_eq!(
            registry.exec(
                "python",
                1,
                "retained",
                HashMap::new(),
                test_launch_context(&shim, &sandbox, "quota-test-generation"),
            )?,
            OValue::int(42)
        );
        registry.shutdown_all(Duration::from_secs(2))?;
        Ok(())
    }

    #[test]
    fn semantic_error_does_not_retire_session_owned_actor() -> Result<()> {
        let mut registry = ProcessRegistry::new();
        let sandbox = BackendSandboxPolicy::none();
        let shim = python_shim_path();
        registry.exec(
            "python",
            3,
            "retained = 42\n'created'",
            HashMap::new(),
            test_launch_context(&shim, &sandbox, "semantic-error-generation"),
        )?;
        registry
            .exec(
                "python",
                3,
                "raise RuntimeError('expected')",
                HashMap::new(),
                test_launch_context(&shim, &sandbox, "semantic-error-generation"),
            )
            .expect_err("the language-level error must surface");
        assert_eq!(
            registry.exec(
                "python",
                3,
                "retained",
                HashMap::new(),
                test_launch_context(&shim, &sandbox, "semantic-error-generation"),
            )?,
            OValue::int(42)
        );
        registry.shutdown_all(Duration::from_secs(2))?;
        Ok(())
    }

    #[test]
    fn persistent_actor_refuses_implicit_launch_generation_replacement() -> Result<()> {
        let mut registry = ProcessRegistry::new();
        let sandbox = BackendSandboxPolicy::none();
        let shim = python_shim_path();
        let first_generation = "admitted-launch-generation-v1";
        let second_generation = "admitted-launch-generation-v2";

        let first = registry.exec(
            "python",
            7,
            concat!(
                "import os\n",
                "retained_across_commands = 'present'\n",
                "__oval_result__ = str(os.getpid())",
            ),
            HashMap::new(),
            BackendLaunchContext {
                shim_path: &shim,
                sandbox: &sandbox,
                executable_leases: None,
                launch_generation_sha256: Some(first_generation),
            },
        )?;
        let first_pid = first.as_str()?.to_string();

        let same_generation = registry.exec(
            "python",
            7,
            "__oval_result__ = retained_across_commands",
            HashMap::new(),
            BackendLaunchContext {
                shim_path: &shim,
                sandbox: &sandbox,
                executable_leases: None,
                launch_generation_sha256: Some(first_generation),
            },
        )?;
        assert_eq!(same_generation, OValue::str_("present"));

        let error = registry
            .exec(
                "python",
                7,
                "__oval_result__ = 'must-not-run'",
                HashMap::new(),
                BackendLaunchContext {
                    shim_path: &shim,
                    sandbox: &sandbox,
                    executable_leases: None,
                    launch_generation_sha256: Some(second_generation),
                },
            )
            .expect_err("an open session must not be implicitly retired");
        assert!(
            format!("{error:#}").contains("session.generation-conflict"),
            "{error:#}"
        );

        let retained = registry.exec(
            "python",
            7,
            "import os\n__oval_result__ = str(os.getpid()) + ':' + retained_across_commands",
            HashMap::new(),
            BackendLaunchContext {
                shim_path: &shim,
                sandbox: &sandbox,
                executable_leases: None,
                launch_generation_sha256: Some(first_generation),
            },
        )?;
        assert_eq!(retained.as_str()?, format!("{first_pid}:present"));

        registry.shutdown_all(Duration::from_secs(2))?;
        Ok(())
    }

    #[test]
    fn nonresponsive_shutdown_is_bounded_and_fails_explicitly() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let shim = temp.path().join("nonresponsive.py");
        // a short sleep: if the kill under test ever regresses, the child
        // still exits on its own instead of outliving the test run.
        std::fs::write(&shim, "import time\ntime.sleep(5)\n")?;
        let mut process =
            BackendProcess::new("python", &shim, &BackendSandboxPolicy::none(), None)?;
        let started = Instant::now();

        let error = process
            .shutdown(Duration::from_millis(100))
            .expect_err("a nonresponsive backend must fail shutdown");

        assert!(started.elapsed() < Duration::from_secs(2), "{error:#}");
        assert!(
            format!("{error:#}").contains("did not answer within 100 ms"),
            "{error:#}"
        );
        assert!(process.terminal, "forced termination did not reap backend");
        Ok(())
    }

    #[test]
    fn stalled_backend_step_fails_closed_instead_of_hanging() -> Result<()> {
        // regression: recv_response used an untimed recv, so a backend that
        // stopped answering mid-step hung the caller with no error at all. the
        // timeout itself must retire the actor: this test never kills it, and a
        // late answer from the stalled actor must not reach any later request.
        let temp = tempfile::tempdir()?;
        let hex = |value: &str| -> Result<String> {
            let mut frame = Vec::new();
            wire::write_frame(
                &mut frame,
                &BackendWireResponseV2::Ok {
                    value: OValue::str_(value),
                },
            )?;
            Ok(frame.iter().map(|byte| format!("{byte:02x}")).collect())
        };
        let stale_hex = hex("stale")?;
        let fresh_hex = hex("fresh")?;
        // while the stall marker exists, a launch stalls past the deadline and
        // then emits the stale answer. once the marker is removed, a launch is
        // a responder that answers every command with "fresh". backend
        // sandboxes deny file access, so the test owns the marker and frames.
        let stalling_shim = |name: &str| -> Result<(std::path::PathBuf, std::path::PathBuf)> {
            let marker = temp.path().join(format!("{name}.stall"));
            std::fs::write(&marker, b"")?;
            let shim = temp.path().join(format!("{name}.py"));
            std::fs::write(
                &shim,
                format!(
                    "import os, sys, time\n\
                     marker = {marker:?}\n\
                     if not os.path.exists(marker):\n    \
                         while True:\n        \
                             head = sys.stdin.buffer.read(4)\n        \
                             if len(head) < 4: sys.exit(0)\n        \
                             sys.stdin.buffer.read(int.from_bytes(head, 'big'))\n        \
                             sys.stdout.buffer.write(bytes.fromhex('{fresh_hex}'))\n        \
                             sys.stdout.buffer.flush()\n\
                     sys.stdin.buffer.read(4)\n\
                     time.sleep(0.8)\n\
                     sys.stdout.buffer.write(bytes.fromhex('{stale_hex}'))\n\
                     sys.stdout.buffer.flush()\n\
                     time.sleep(5)\n",
                    marker = marker.display().to_string(),
                ),
            )?;
            Ok((shim, marker))
        };
        let alive = |pid: i32| std::path::Path::new(&format!("/proc/{pid}")).exists();
        let (direct_shim, direct_marker) = stalling_shim("direct")?;
        let (pooled_shim, pooled_marker) = stalling_shim("pooled")?;

        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            STEP_TIMEOUT_OVERRIDE.with(|cell| cell.set(Some(Duration::from_millis(300))));
            let outcome = (|| -> Result<()> {
                // the actor itself: error, dead, and unusable for a later request.
                let mut process = BackendProcess::new(
                    "python",
                    &direct_shim,
                    &BackendSandboxPolicy::none(),
                    None,
                )?;
                let pid = process.child.id() as i32;
                let error = process
                    .exec("__oval_result__ = 1", HashMap::new())
                    .expect_err("a stalled backend must not produce a value");
                let message = format!("{error:#}");
                assert!(
                    message.contains(
                        "step exceeded 300 ms (opt-in per-step limit O_BACKEND_STEP_TIMEOUT_MS)"
                    ),
                    "{message}"
                );
                assert!(
                    process.terminal,
                    "step timeout did not reap the stalled backend"
                );
                assert!(!alive(pid), "stalled backend {pid} is still alive");
                std::fs::remove_file(&direct_marker)?;
                thread::sleep(Duration::from_millis(1200));
                let reused = process.exec("__oval_result__ = 'fresh'", HashMap::new());
                assert!(
                    !matches!(&reused, Ok(value) if value == &OValue::str_("stale")),
                    "late answer from the stalled backend reached a later request"
                );
                assert!(reused.is_err(), "retired backend accepted another request");

                // the pool: the later request gets a fresh actor, never the stale answer.
                // a fresh (non-persistent) environment, because a killed persistent
                // session is reported lost instead (see the session-lost test).
                let sandbox = BackendSandboxPolicy::none();
                let mut registry = ProcessRegistry::new();
                let pid_code = "__oval_result__ = 'fresh'";
                registry.send_exec(
                    "python",
                    u32::MAX,
                    pid_code,
                    HashMap::new(),
                    test_launch_context(&pooled_shim, &sandbox, "stall-gen"),
                )?;
                let pid = registry
                    .registry
                    .values()
                    .map(|process| process.child.id() as i32)
                    .next()
                    .expect("pooled backend was published");
                let error = registry
                    .recv_exec_step("python", u32::MAX, &sandbox)
                    .expect_err("a stalled pooled backend must not produce a value");
                assert!(
                    format!("{error:#}").contains(
                        "step exceeded 300 ms (opt-in per-step limit O_BACKEND_STEP_TIMEOUT_MS)"
                    ),
                    "{error:#}"
                );
                assert!(!alive(pid), "stalled pooled backend {pid} is still alive");
                std::fs::remove_file(&pooled_marker)?;
                assert!(
                    registry.registry.is_empty(),
                    "stalled backend stayed in the pool"
                );
                thread::sleep(Duration::from_millis(1200));
                let next = registry.exec(
                    "python",
                    u32::MAX,
                    pid_code,
                    HashMap::new(),
                    test_launch_context(&pooled_shim, &sandbox, "stall-gen"),
                )?;
                assert_eq!(
                    next,
                    OValue::str_("fresh"),
                    "late answer reached the next pooled request"
                );
                let next_pid = registry
                    .registry
                    .values()
                    .map(|process| process.child.id() as i32)
                    .next()
                    .expect("next request published a backend");
                assert_ne!(next_pid, pid, "next request reused the stalled backend");
                // the stand-in responder has no shutdown verb; dropping the
                // registry reaps it through the ordinary drop fallback.
                drop(registry);
                Ok(())
            })();
            let _ = done_tx.send(outcome);
        });
        match done_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("stalled backend read hung past its deadline")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("test body panicked; see the assertion above")
            }
        }
    }

    /// Run `body` on a thread whose per-step limit is 300 ms, guarded so a
    /// regression fails instead of hanging.
    fn with_short_step_limit(body: impl FnOnce() -> Result<()> + Send + 'static) -> Result<()> {
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            STEP_TIMEOUT_OVERRIDE.with(|cell| cell.set(Some(Duration::from_millis(300))));
            let _ = done_tx.send(body());
        });
        match done_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("backend wait hung past the per-step limit")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("test body panicked; see the assertion above")
            }
        }
    }

    /// A shim that reads one frame header and then stays silent for 5 s.
    fn silent_shim(dir: &Path, name: &str, reads_stdin: bool) -> Result<std::path::PathBuf> {
        let shim = dir.join(format!("{name}.py"));
        let read = if reads_stdin {
            "sys.stdin.buffer.read(4)\n"
        } else {
            ""
        };
        std::fs::write(&shim, format!("import sys, time\n{read}time.sleep(5)\n"))?;
        Ok(shim)
    }

    const STEP_LIMIT_300_MS: &str =
        "step exceeded 300 ms (opt-in per-step limit O_BACKEND_STEP_TIMEOUT_MS)";

    #[test]
    fn cancellation_polled_step_is_bounded_without_a_deadline() -> Result<()> {
        // y-d-02: a request with a cancellation token and no deadline used to
        // poll a silent backend forever.
        let temp = tempfile::tempdir()?;
        let shim = silent_shim(temp.path(), "controlled", true)?;
        with_short_step_limit(move || {
            let sandbox = BackendSandboxPolicy::none();
            let mut registry = ProcessRegistry::new();
            registry.send_exec(
                "python",
                4,
                "x = 1",
                HashMap::new(),
                test_launch_context(&shim, &sandbox, "ctl-gen"),
            )?;
            let error = registry
                .recv_exec_step_controlled("python", 4, &sandbox, None, || false)
                .expect_err("a silent backend must not be polled forever");
            assert!(
                format!("{error:#}").contains(STEP_LIMIT_300_MS),
                "{error:#}"
            );
            assert!(
                registry.registry.is_empty(),
                "stalled backend stayed in the pool"
            );
            Ok(())
        })
    }

    #[test]
    fn session_killed_by_step_limit_is_reported_lost_not_recreated() -> Result<()> {
        // y-d-03: python[1] killed by the limit must not come back as a fresh
        // empty session under the same id.
        let temp = tempfile::tempdir()?;
        let shim = silent_shim(temp.path(), "lost", true)?;
        with_short_step_limit(move || {
            let sandbox = BackendSandboxPolicy::none();
            let mut registry = ProcessRegistry::new();
            let launch = || test_launch_context(&shim, &sandbox, "lost-gen");
            let error = registry
                .exec("python", 1, "x = 1", HashMap::new(), launch())
                .expect_err("a silent backend must not produce a value");
            assert!(
                format!("{error:#}").contains(STEP_LIMIT_300_MS),
                "{error:#}"
            );
            let error = registry
                .exec("python", 1, "x", HashMap::new(), launch())
                .expect_err("a lost session must not be recreated silently");
            assert!(
                format!("{error:#}").contains(
                    "session python[1] was terminated after a timeout; its state is gone"
                ),
                "{error:#}"
            );
            assert!(
                registry.registry.is_empty(),
                "a fresh session was started under a lost id"
            );
            Ok(())
        })
    }

    #[test]
    fn step_limit_knob_rejects_invalid_values() {
        // y-d-04: unset is the default; anything set must be valid.
        use std::ffi::OsStr;
        assert_eq!(parse_backend_step_timeout(None).unwrap(), None);
        assert_eq!(
            parse_backend_step_timeout(Some(OsStr::new("2000"))).unwrap(),
            Some(Duration::from_secs(2))
        );
        for bad in ["0", "", "abc", "-5", "1.5", "604800001"] {
            let error = parse_backend_step_timeout(Some(OsStr::new(bad))).expect_err(bad);
            assert!(
                format!("{error:#}").contains("O_BACKEND_STEP_TIMEOUT_MS"),
                "{error:#}"
            );
        }
        assert_eq!(step_limit_text(Duration::from_millis(300)), "300 ms");
        assert_eq!(step_limit_text(Duration::from_secs(2)), "2 s");
        assert_eq!(step_limit_text(Duration::from_millis(1500)), "1.5 s");
    }

    #[test]
    fn registry_teardown_kills_every_actor_before_reaping_any() -> Result<()> {
        // y-d-05: serial kill-then-reap cost n reap budgets for n stuck actors.
        let temp = tempfile::tempdir()?;
        let shim = silent_shim(temp.path(), "teardown", true)?;
        let sandbox = BackendSandboxPolicy::none();
        let mut registry = ProcessRegistry::new();
        for env_id in 0..3 {
            registry.send_exec(
                "python",
                env_id,
                "x = 1",
                HashMap::new(),
                test_launch_context(&shim, &sandbox, "td-gen"),
            )?;
        }
        KILL_TRACE.with(|trace| *trace.borrow_mut() = Some(Vec::new()));
        drop(registry);
        let trace = KILL_TRACE
            .with(|trace| trace.borrow_mut().take())
            .unwrap_or_default();
        assert_eq!(
            trace,
            ["kill", "kill", "kill", "settle", "settle", "settle"]
        );
        Ok(())
    }

    #[test]
    fn large_command_to_backend_that_never_reads_is_bounded() -> Result<()> {
        // y-d-06: a frame larger than the pipe buffer blocked in write_all
        // before any step limit was running.
        let temp = tempfile::tempdir()?;
        let shim = silent_shim(temp.path(), "deaf", false)?;
        with_short_step_limit(move || {
            let mut process =
                BackendProcess::new("python", &shim, &BackendSandboxPolicy::none(), None)?;
            let bindings = HashMap::from([("big".to_string(), OValue::str_("x".repeat(1 << 20)))]);
            let error = process
                .exec("__oval_result__ = 1", bindings)
                .expect_err("a backend that never reads must not wedge the writer");
            assert!(
                format!("{error:#}").contains(
                    "read no input for 300 ms (opt-in per-step limit O_BACKEND_STEP_TIMEOUT_MS)"
                ),
                "{error:#}"
            );
            assert!(process.terminal, "deaf backend was not reaped");
            Ok(())
        })
    }

    #[test]
    fn small_command_keeps_the_blocking_write_path() -> Result<()> {
        // the hot path is unchanged: small frames still answer normally.
        let mut process = spawn_python_shim()?;
        assert_eq!(
            process.exec("__oval_result__ = 41 + 1", HashMap::new())?,
            OValue::int(42)
        );
        process.shutdown(Duration::from_secs(2))?;
        Ok(())
    }

    fn frame_hex(response: &BackendWireResponseV2) -> Result<String> {
        let mut frame = Vec::new();
        wire::write_frame(&mut frame, response)?;
        Ok(frame.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    /// Run `body` with fast heartbeat timing (50 ms beats, 400 ms warning) and
    /// captured status lines; returns the body's result and the lines.
    fn with_fast_heartbeats<T: Send + 'static>(
        body: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<(T, Vec<String>)> {
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            HEARTBEAT_OVERRIDE.with(|cell| {
                cell.set(Some((
                    Duration::from_millis(50),
                    Duration::from_millis(400),
                )))
            });
            crate::progress::capture_lines_for_test(true);
            let outcome = body();
            let lines = crate::progress::capture_lines_for_test(false);
            let _ = done_tx.send(outcome.map(|value| (value, lines)));
        });
        match done_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("step wait hung"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("test body panicked; see the assertion above")
            }
        }
    }

    #[test]
    fn heartbeats_keep_a_long_step_free_of_warnings() -> Result<()> {
        // the real shim beats while time.sleep releases the gil: a step that
        // runs far past the warning threshold stays quiet.
        let (value, lines) = with_fast_heartbeats(|| {
            let mut process = spawn_python_shim()?;
            let value = process.exec(
                "import time\ntime.sleep(1.5)\n__oval_result__ = 7",
                HashMap::new(),
            )?;
            process.shutdown(Duration::from_secs(2))?;
            Ok(value)
        })?;
        assert_eq!(value, OValue::int(7));
        assert!(lines.is_empty(), "{lines:?}");
        Ok(())
    }

    #[test]
    fn gil_holding_step_warns_once_and_still_completes() -> Result<()> {
        // a c call that keeps the gil starves the heartbeat thread, which is
        // the hang signal: one warning, no kill, the answer still arrives.
        let (value, lines) = with_fast_heartbeats(|| {
            let mut process = spawn_python_shim()?;
            // one sum() call is a single c call that never yields the gil;
            // size it from a short calibration call to last about 1.5 s.
            let value = process.exec(
                "import time\nt = time.time()\nsum(range(10**6))\n\
                 per = max(time.time() - t, 1e-4)\n\
                 sum(range(int(10**6 * 1.5 / per)))\n\
                 __oval_result__ = 1",
                HashMap::new(),
            )?;
            process.shutdown(Duration::from_secs(2))?;
            Ok(value)
        })?;
        assert_eq!(value, OValue::int(1));
        let warnings = lines
            .iter()
            .filter(|line| line.contains("no heartbeat from"))
            .count();
        assert_eq!(warnings, 1, "{lines:?}");
        Ok(())
    }

    #[test]
    fn stalled_heartbeat_warns_once_resumes_once_and_completes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let hello = frame_hex(&BackendWireResponseV2::HelloV1 {
            capabilities: vec![HEARTBEAT_CAPABILITY.to_string()],
        })?;
        let beat = frame_hex(&BackendWireResponseV2::HeartbeatV1 { child: None })?;
        let done = frame_hex(&BackendWireResponseV2::Ok {
            value: OValue::int(5),
        })?;
        let shim = temp.path().join("stall_then_resume.py");
        std::fs::write(
            &shim,
            format!(
                "import sys, time\n\
                 head = sys.stdin.buffer.read(4)\n\
                 sys.stdin.buffer.read(int.from_bytes(head, 'big'))\n\
                 out = sys.stdout.buffer\n\
                 out.write(bytes.fromhex('{hello}')); out.flush()\n\
                 def beats(n):\n    \
                     for _ in range(n):\n        \
                         out.write(bytes.fromhex('{beat}')); out.flush(); time.sleep(0.05)\n\
                 beats(4)\n\
                 time.sleep(1.0)\n\
                 beats(6)\n\
                 out.write(bytes.fromhex('{done}')); out.flush()\n\
                 time.sleep(5)\n"
            ),
        )?;
        let (value, lines) = with_fast_heartbeats(move || {
            let mut process =
                BackendProcess::new("python", &shim, &BackendSandboxPolicy::none(), None)?;
            process.exec("x = 1", HashMap::new())
        })?;
        assert_eq!(value, OValue::int(5));
        assert_eq!(
            lines,
            [
                "no heartbeat from python for 400 ms; it may be hanging (still running)",
                "python resumed sending heartbeats (still running)"
            ]
        );
        Ok(())
    }

    #[test]
    fn old_shim_without_heartbeats_never_warns() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let done = frame_hex(&BackendWireResponseV2::Ok {
            value: OValue::int(3),
        })?;
        let shim = temp.path().join("old.py");
        std::fs::write(
            &shim,
            format!(
                "import sys, time\n\
                 head = sys.stdin.buffer.read(4)\n\
                 sys.stdin.buffer.read(int.from_bytes(head, 'big'))\n\
                 time.sleep(1.0)\n\
                 sys.stdout.buffer.write(bytes.fromhex('{done}')); sys.stdout.buffer.flush()\n\
                 time.sleep(5)\n"
            ),
        )?;
        let (value, lines) = with_fast_heartbeats(move || {
            let mut process =
                BackendProcess::new("python", &shim, &BackendSandboxPolicy::none(), None)?;
            process.exec("x = 1", HashMap::new())
        })?;
        assert_eq!(value, OValue::int(3));
        assert!(lines.is_empty(), "{lines:?}");
        Ok(())
    }

    #[test]
    fn backend_killed_mid_step_fails_fast_even_with_the_pipe_held_open() -> Result<()> {
        // y-d-10: no default limit, so a dead backend must be noticed. here a
        // background child keeps the response pipe open, so reader eof never
        // comes; only the leader-exit poll can see the death.
        let temp = tempfile::tempdir()?;
        let shim = temp.path().join("holder");
        std::fs::write(&shim, "#!/bin/sh\nsleep 5 &\nexec sleep 5\n")?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))?;
        let sandbox = BackendSandboxPolicy::none();
        let mut registry = ProcessRegistry::new();
        registry.send_exec(
            "python",
            2,
            "x",
            HashMap::new(),
            test_launch_context(&shim, &sandbox, "exit-gen"),
        )?;
        let pid = registry
            .registry
            .values()
            .map(|process| process.child.id() as i32)
            .next()
            .expect("backend was published");
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            // SAFETY: signals the test's own backend leader.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        });
        let started = Instant::now();
        let error = registry
            .recv_exec_step("python", 2, &sandbox)
            .expect_err("a killed backend must fail the step");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        assert!(
            format!("{error:#}").contains("exited during the step"),
            "{error:#}"
        );
        assert!(registry.registry.is_empty());
        let error = registry
            .exec(
                "python",
                2,
                "x",
                HashMap::new(),
                test_launch_context(&shim, &sandbox, "exit-gen"),
            )
            .expect_err("the lost session must not restart silently");
        assert!(
            format!("{error:#}").contains(
                "session python[2] was terminated after its backend exited; its state is gone"
            ),
            "{error:#}"
        );
        Ok(())
    }

    /// Run `body` on its own thread (so thread-local overrides start clean)
    /// with a guard that fails instead of hanging.
    fn guarded<T: Send + 'static>(body: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = done_tx.send(body());
        });
        match done_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("step wait hung"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("test body panicked; see the assertion above")
            }
        }
    }

    #[test]
    fn no_default_limit_lets_a_long_silent_step_finish() -> Result<()> {
        // lee's rule: steps may run for days, so nothing is killed unless the
        // user opts in. no override and no knob set here.
        assert_eq!(parse_backend_step_timeout(None)?, None);
        assert_eq!(
            parse_timeout_knob(BACKEND_OPERATION_TIMEOUT_ENV, None)?,
            None
        );
        let value = guarded(|| {
            let mut process = spawn_python_shim()?;
            let value = process.exec(
                "import time\ntime.sleep(1.5)\n__oval_result__ = 'finished'",
                HashMap::new(),
            )?;
            process.shutdown(Duration::from_secs(2))?;
            Ok(value)
        })?;
        assert_eq!(value, OValue::str_("finished"));
        Ok(())
    }

    #[test]
    fn operation_timeout_knob_rejects_invalid_values() {
        use std::ffi::OsStr;
        for bad in ["0", "abc", "604800001"] {
            let error = parse_timeout_knob(BACKEND_OPERATION_TIMEOUT_ENV, Some(OsStr::new(bad)))
                .expect_err(bad);
            assert!(
                format!("{error:#}").contains(BACKEND_OPERATION_TIMEOUT_ENV),
                "{error:#}"
            );
        }
    }

    #[test]
    fn cancellation_kills_evicts_and_loses_the_session_without_a_limit() -> Result<()> {
        // cancel ends a silent step with no opt-in limit; the killed python[4]
        // is reported lost on its next block.
        let temp = tempfile::tempdir()?;
        let shim = silent_shim(temp.path(), "cancelled", true)?;
        guarded(move || {
            let sandbox = BackendSandboxPolicy::none();
            let mut registry = ProcessRegistry::new();
            let launch = || test_launch_context(&shim, &sandbox, "cancel-gen");
            registry.send_exec("python", 4, "x = 1", HashMap::new(), launch())?;
            let pid = registry
                .registry
                .values()
                .map(|process| process.child.id() as i32)
                .next()
                .expect("backend was published");
            let started = Instant::now();
            let error = registry
                .recv_exec_step_controlled("python", 4, &sandbox, None, || {
                    started.elapsed() >= Duration::from_millis(300)
                })
                .expect_err("a cancelled step must fail");
            assert!(
                format!("{error:#}").contains("request cancellation was observed"),
                "{error:#}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "{:?}",
                started.elapsed()
            );
            assert!(
                registry.registry.is_empty(),
                "cancelled backend stayed in the pool"
            );
            assert!(
                !std::path::Path::new(&format!("/proc/{pid}")).exists() || {
                    // a zombie-free check: the leader must at least not be running.
                    std::fs::read_to_string(format!("/proc/{pid}/stat"))
                        .map(|stat| stat.contains(") Z "))
                        .unwrap_or(true)
                },
                "cancelled backend {pid} is still alive"
            );
            let error = registry
                .exec("python", 4, "x", HashMap::new(), launch())
                .expect_err("a cancelled session must not restart silently");
            assert!(
                format!("{error:#}").contains(
                    "session python[4] was terminated after cancellation; its state is gone"
                ),
                "{error:#}"
            );
            Ok(())
        })
    }

    #[test]
    fn large_write_to_a_deaf_backend_ends_on_cancellation() -> Result<()> {
        // w3: a frame above the pipe size to a shim that never reads blocks
        // the write; under a cancellation token the write is polled and the
        // backend is killed and evicted when the request is cancelled.
        let temp = tempfile::tempdir()?;
        let shim = silent_shim(temp.path(), "deaf", false)?;
        guarded(move || {
            let sandbox = BackendSandboxPolicy::none();
            let mut registry = ProcessRegistry::new();
            let token = crate::cancellation::CancellationToken::new();
            registry.set_request_cancellation(Some(token.clone()));
            let canceller = token.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(300));
                canceller.cancel();
            });
            let bindings = HashMap::from([("big".to_string(), OValue::str_("x".repeat(1 << 20)))]);
            let started = Instant::now();
            let error = registry
                .send_exec(
                    "python",
                    5,
                    "x = 1",
                    bindings,
                    test_launch_context(&shim, &sandbox, "deaf-gen"),
                )
                .expect_err("a cancelled write must fail");
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "{:?}",
                started.elapsed()
            );
            assert!(
                format!("{error:#}").contains(
                    "request cancelled while backend `python` was still reading its command"
                ),
                "{error:#}"
            );
            assert!(
                registry.registry.is_empty(),
                "deaf backend stayed in the pool"
            );
            Ok(())
        })
    }

    #[test]
    fn spinner_does_not_change_step_results() -> Result<()> {
        // stdout is never written by the status writer; a step returns the
        // same value with the spinner forced on and off.
        let run = |spinner: bool| {
            guarded(move || {
                crate::progress::force_spinner_for_test(Some(spinner));
                let mut process = spawn_python_shim()?;
                let value = process.exec(
                    "import sys, time\nprint('out line')\nsys.stderr.write('err line\\n')\ntime.sleep(0.5)\n__oval_result__ = 'same'",
                    HashMap::new(),
                )?;
                process.shutdown(Duration::from_secs(2))?;
                crate::progress::force_spinner_for_test(None);
                Ok(value)
            })
        };
        assert_eq!(run(true)?, run(false)?);
        Ok(())
    }

    #[test]
    fn restricted_python_shim_denies_process_spawn() -> Result<()> {
        let mut process = spawn_python_shim()?;
        let error = process
            .exec(
                "import os\n__oval_result__ = os.system('echo forbidden')",
                HashMap::new(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("denies process spawn"));
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn restricted_python_shim_denies_filesystem_write() -> Result<()> {
        let mut process = spawn_python_shim()?;
        let error = process
            .exec(
                "open('/tmp/o-backend-forbidden', 'w').write('no')",
                HashMap::new(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("denies filesystem write"));
        assert!(!Path::new("/tmp/o-backend-forbidden").exists());
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn restricted_python_shim_denies_filesystem_read_outside_runtime() -> Result<()> {
        let mut process = spawn_python_shim()?;
        let error = process
            .exec(
                "__oval_result__ = open('/etc/hosts').read()",
                HashMap::new(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("denies filesystem read"));
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn declared_filesystem_read_authority_changes_the_sandbox_policy() -> Result<()> {
        use crate::value::BackendAuthority;

        let mut process = spawn_python_shim_with([BackendAuthority::FileRead])?;
        let value = process.exec(
            "__oval_result__ = len(open('/etc/hosts').read()) > 0",
            HashMap::new(),
        )?;
        assert_eq!(value, OValue::bool_(true));
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn restricted_python_shim_denies_network_socket_creation() -> Result<()> {
        let mut process = spawn_python_shim()?;
        let error = process
            .exec(
                "import socket\n__oval_result__ = socket.socket()",
                HashMap::new(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("denies network access"));
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn declared_process_authority_changes_the_sandbox_policy() -> Result<()> {
        use crate::value::BackendAuthority;

        let mut process = spawn_python_shim_with([BackendAuthority::Process])?;
        let value = process.exec(
            "import os\n__oval_result__ = os.system('true')",
            HashMap::new(),
        )?;
        assert_eq!(value, OValue::int(0));
        process.shutdown(backend_shutdown_timeout()?)?;
        Ok(())
    }

    #[test]
    fn python_bootstrap_skips_runtime_candidates_that_cannot_be_resolved() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let probe = temp.path().join("probe.py");
        std::fs::write(&probe, "print('bootstrap-ok')\n")?;

        let denied_candidate = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or_else(|| Path::new("/Users"))
            .to_path_buf();

        let python = which::which("python3").context("python3 is required for backend shims")?;

        #[cfg(target_os = "macos")]
        let mut command =
            macos_sandbox_command(&python, &BackendSandboxPolicy::none(), temp.path())?;

        #[cfg(not(target_os = "macos"))]
        let mut command = Command::new(&python);

        let output = command
            .arg("-c")
            .arg(PYTHON_POLICY_BOOTSTRAP)
            .arg(&probe)
            .env("O_BACKEND_AUTHORITIES", "[]")
            .env(
                "O_BACKEND_RUNTIME_ROOTS",
                serde_json::to_string(&[temp.path(), &denied_candidate])?,
            )
            .output()
            .context("failed to run Python policy bootstrap probe")?;

        assert!(
            output.status.success(),
            "bootstrap failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("bootstrap-ok"));
        Ok(())
    }
}
