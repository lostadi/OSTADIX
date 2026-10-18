//! Watched waits for native leaf children: clang, ld and the sealed leaf.
//!
//! every child runs as the leader of its own process group. while it runs the
//! wait warns once after the hang-warning threshold, and it kills the whole
//! group when the opt-in step limit passes or the request is cancelled. after
//! the leader exits the group is killed too, so nothing it started outlives it.

use std::io::Read;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::cancellation::CancellationToken;
use crate::step_knobs::BACKEND_STEP_TIMEOUT_ENV;

// why a growing tick: a leaf usually exits within a millisecond, so the first
// polls are short; a long compile settles at the slower tick.
const FIRST_TICK: Duration = Duration::from_micros(200);
const LAST_TICK: Duration = Duration::from_millis(50);

/// The bounds one native child wait observes.
pub(crate) struct ChildWatch<'a> {
    /// The opt-in per-step limit; `None` means the child may run as long as
    /// it needs.
    pub(crate) limit: Option<Duration>,
    /// One stderr warning after this long, never a kill.
    pub(crate) warning: Duration,
    pub(crate) cancellation: Option<&'a CancellationToken>,
}

impl<'a> ChildWatch<'a> {
    /// The process-wide knobs (`O_BACKEND_STEP_TIMEOUT_MS`,
    /// `O_BACKEND_HEARTBEAT_WARN_MS`), plus the request's cancellation.
    pub(crate) fn from_knobs(cancellation: Option<&'a CancellationToken>) -> Result<Self> {
        Ok(Self {
            limit: crate::step_knobs::step_timeout()?,
            warning: crate::step_knobs::heartbeat_warning()?,
            cancellation,
        })
    }
}

/// Read a child pipe on its own thread so a full pipe never blocks the child
/// while the wait is polling.
pub(crate) fn capture<R: Read + Send + 'static>(
    mut pipe: R,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

/// Join a capture thread started by [`capture`].
pub(crate) fn captured(
    handle: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    what: &str,
) -> Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("native leaf {what} capture panicked"))?
        .with_context(|| format!("read native leaf {what}"))
}

/// Wait for `child`, which must lead its own process group, under `watch`.
pub(crate) fn wait(child: &mut Child, label: &str, watch: &ChildWatch<'_>) -> Result<ExitStatus> {
    let started = Instant::now();
    let mut tick = FIRST_TICK;
    let mut warned = false;
    loop {
        if leader_exited(child)? {
            // the zombie leader still holds the group id, so this cannot hit a
            // recycled group.
            kill_group(child);
            return child
                .wait()
                .with_context(|| format!("reap native leaf {label}"));
        }
        let elapsed = started.elapsed();
        let stop = if watch.cancellation.is_some_and(|token| token.is_cancelled()) {
            Some("was cancelled with the request".to_string())
        } else {
            watch.limit.filter(|limit| elapsed >= *limit).map(|limit| {
                format!(
                    "exceeded {} ms (opt-in per-step limit {BACKEND_STEP_TIMEOUT_ENV})",
                    limit.as_millis()
                )
            })
        };
        if let Some(reason) = stop {
            kill_group(child);
            let _ = child.wait();
            bail!("native leaf {label} {reason}; its process group was killed");
        }
        if !warned && elapsed >= watch.warning {
            warned = true;
            let seconds = elapsed.as_secs();
            crate::progress::line(&format!(
                "native leaf {label} has run for {seconds} s; it may be hanging (still running)"
            ));
        }
        std::thread::sleep(tick);
        tick = (tick * 2).min(LAST_TICK);
    }
}

/// Whether the leader exited, without reaping it.
fn leader_exited(child: &Child) -> Result<bool> {
    // SAFETY: zeroed siginfo_t is valid storage for waitid to fill.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let flags = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT;
    // SAFETY: the pid names our own unreaped child and `info` is writable.
    let status = unsafe { libc::waitid(libc::P_PID, child.id(), &mut info, flags) };
    if status != 0 {
        return Err(std::io::Error::last_os_error()).context("poll native leaf child");
    }
    // SAFETY: waitid filled `info`; si_pid is 0 when the child is still running.
    Ok(unsafe { info.si_pid() } != 0)
}

fn kill_group(child: &Child) {
    let group = child.id() as libc::pid_t;
    // SAFETY: killpg only sends a signal; the group is the unreaped child's.
    unsafe {
        libc::killpg(group, libc::SIGKILL);
    }
}

#[cfg(test)]
mod tests {
    use super::{wait, ChildWatch};
    use crate::cancellation::CancellationToken;
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    // a shell that leaves a background grandchild and prints its pid.
    fn orphan_maker() -> std::process::Child {
        Command::new("sh")
            .args(["-c", "sleep 30 & echo $!; sleep 30"])
            .stdout(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap()
    }

    fn grandchild(child: &mut std::process::Child) -> libc::pid_t {
        let mut line = Vec::new();
        let mut byte = [0u8];
        let stdout = child.stdout.as_mut().unwrap();
        while stdout.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
            line.push(byte[0]);
        }
        String::from_utf8(line).unwrap().trim().parse().unwrap()
    }

    fn gone(pid: libc::pid_t) -> bool {
        // the grandchild is reparented and reaped by init; poll briefly.
        for _ in 0..100 {
            // SAFETY: signal 0 only probes for existence.
            if unsafe { libc::kill(pid, 0) } != 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn step_limit_kills_the_child_and_everything_it_started() {
        let mut child = orphan_maker();
        let orphan = grandchild(&mut child);
        let watch = ChildWatch {
            limit: Some(Duration::from_millis(200)),
            warning: Duration::from_secs(3600),
            cancellation: None,
        };
        let error = wait(&mut child, "clang", &watch).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("native leaf clang exceeded 200 ms"), "{text}");
        assert!(text.contains("O_BACKEND_STEP_TIMEOUT_MS"), "{text}");
        assert!(gone(orphan), "background grandchild {orphan} survived");
    }

    #[test]
    fn cancellation_kills_the_child_group() {
        let mut child = orphan_maker();
        let orphan = grandchild(&mut child);
        let token = CancellationToken::new();
        token.cancel();
        let watch = ChildWatch {
            limit: None,
            warning: Duration::from_secs(3600),
            cancellation: Some(&token),
        };
        let error = wait(&mut child, "ld", &watch).unwrap_err();
        assert!(format!("{error:#}").contains("cancelled"), "{error:#}");
        assert!(gone(orphan), "background grandchild {orphan} survived");
    }

    #[test]
    fn a_long_child_warns_once_and_keeps_running() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 0.4"])
            .process_group(0)
            .spawn()
            .unwrap();
        let watch = ChildWatch {
            limit: None,
            warning: Duration::from_millis(50),
            cancellation: None,
        };
        crate::progress::capture_lines_for_test(true);
        let status = wait(&mut child, "ld", &watch);
        let lines = crate::progress::capture_lines_for_test(false);
        assert!(status.unwrap().success());
        let warnings: Vec<_> = lines
            .iter()
            .filter(|line| line.contains("native leaf ld has run for"))
            .collect();
        assert_eq!(warnings.len(), 1, "{lines:?}");
        assert!(warnings[0].contains("still running"), "{lines:?}");
    }

    #[test]
    fn a_normal_exit_still_kills_what_the_child_left_behind() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30 & echo $!"])
            .stdout(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let orphan = grandchild(&mut child);
        let watch = ChildWatch {
            limit: None,
            warning: Duration::from_secs(3600),
            cancellation: None,
        };
        assert!(wait(&mut child, "leaf", &watch).unwrap().success());
        assert!(gone(orphan), "background grandchild {orphan} survived");
    }
}
