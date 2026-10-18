//! A plain bash block's jobs end with O: on a cancel during the block, and
//! when O itself is killed. the job here calls setsid, so only the helper's
//! own cleanup reaches it, never a process-group kill.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod support;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// A program whose block starts a setsid job, records its pid, and then
/// waits, so a signal lands while the block runs.
fn start_blocked_program(workdir: &Path) -> (Child, PathBuf) {
    let pidfile = workdir.join("job.pid");
    let program = workdir.join("main.o");
    std::fs::write(
        &program,
        format!(
            "bash^(\n\
             setsid sleep 300 >/dev/null 2>&1 < /dev/null &\n\
             echo $! > {pidfile}\n\
             sleep 60\n\
             )_bash\n",
            pidfile = pidfile.display()
        ),
    )
    .unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let child = support::spawn_private_executable(
        Command::new(env!("CARGO_BIN_EXE_O"))
            .env_remove("O_EXECUTOR")
            .arg(&program)
            .arg(root.join("backends"))
            .current_dir(workdir)
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    )
    .unwrap();
    (child, pidfile)
}

fn wait_for_job(child: &mut Child, pidfile: &Path) -> i32 {
    let started = Instant::now();
    loop {
        if let Ok(text) = std::fs::read_to_string(pidfile) {
            if let Ok(pid) = text.trim().parse::<i32>() {
                return pid;
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the job never started"
        );
        if let Some(status) = child.try_wait().unwrap() {
            panic!("O ended before the job started: {status}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Whether `pid` is a live process (a zombie counts as gone).
fn alive(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|state| state != "Z" && state != "X"),
        Err(_) => false,
    }
}

fn assert_gone_soon(pid: i32) {
    let started = Instant::now();
    while alive(pid) {
        if started.elapsed() > Duration::from_secs(10) {
            // SAFETY: the test stops the job it started.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            panic!("the setsid job {pid} outlived O");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_bounded(child: &mut Child) -> std::process::ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if started.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("O did not stop within 30s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[test]
fn a_cancel_during_a_plain_block_stops_its_setsid_job() {
    if !support::require_runtime("bash") {
        return;
    }
    let workdir = tempfile::tempdir().unwrap();
    let (mut child, pidfile) = start_blocked_program(workdir.path());
    let job = wait_for_job(&mut child, &pidfile);
    assert!(alive(job));
    // SAFETY: kill only signals the O process spawned above.
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) },
        0
    );
    let status = wait_bounded(&mut child);
    assert!(!status.success());
    assert_gone_soon(job);
}

#[test]
fn killing_o_during_a_plain_block_stops_its_setsid_job() {
    if !support::require_runtime("bash") {
        return;
    }
    let workdir = tempfile::tempdir().unwrap();
    let (mut child, pidfile) = start_blocked_program(workdir.path());
    let job = wait_for_job(&mut child, &pidfile);
    assert!(alive(job));
    // the helper's parent death signal is the only path left to the job.
    child.kill().unwrap();
    child.wait().unwrap();
    assert_gone_soon(job);
}

#[test]
fn no_spinner_is_drawn_when_stderr_is_not_a_terminal() {
    if !support::require_runtime("bash") {
        return;
    }
    let workdir = tempfile::tempdir().unwrap();
    let program = workdir.path().join("main.o");
    // long enough for several spinner frames, had one been drawn.
    std::fs::write(&program, "bash^(sleep 0.7; echo done)_bash\n").unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = support::output_private_executable(
        Command::new(env!("CARGO_BIN_EXE_O"))
            .env_remove("O_EXECUTOR")
            .env_remove("CI")
            .env_remove("NO_COLOR")
            .env_remove("O_QUIET")
            .arg(&program)
            .arg(root.join("backends"))
            .current_dir(workdir.path()),
    )
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        !stderr.contains('\r') && !stderr.contains('\u{1b}'),
        "a spinner was drawn on a piped stderr: {stderr:?}"
    );
}
