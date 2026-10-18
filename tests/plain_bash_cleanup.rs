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
    let source = format!(
        "bash^(\n\
         setsid sleep 300 >/dev/null 2>&1 < /dev/null &\n\
         echo $! > {pidfile}\n\
         sleep 60\n\
         )_bash\n",
        pidfile = pidfile.display()
    );
    (start_program(workdir, &source), pidfile)
}

/// A program whose bash[1] block starts a setsid job and ends, so bash[1]
/// sits idle holding the job while a later plain block waits for a signal.
fn start_idle_session_program(workdir: &Path) -> (Child, PathBuf) {
    let pidfile = workdir.join("job.pid");
    let source = format!(
        "bash[1]^(\n\
         setsid sleep 300 >/dev/null 2>&1 < /dev/null &\n\
         echo $! > {pidfile}\n\
         )_bash[1]\n\
         bash^(sleep 60)_bash\n",
        pidfile = pidfile.display()
    );
    (start_program(workdir, &source), pidfile)
}

/// The jobs of `pipeline_source`: a backgrounded two-process pipeline (two
/// processes, one group) and a setsid job (its own group).
const PIPELINE_JOBS: &str = "sleep 900 >/dev/null 2>&1 < /dev/null | sleep 901 >/dev/null 2>&1 &\n\
     setsid sleep 902 >/dev/null 2>&1 < /dev/null &\n";

fn pipeline_source(pidfile: &Path, tail: &str) -> String {
    format!(
        "bash^(\n{PIPELINE_JOBS}echo $! > {pidfile}\n{tail})_bash\n",
        pidfile = pidfile.display()
    )
}

fn start_program(workdir: &Path, source: &str) -> Child {
    let program = workdir.join("main.o");
    std::fs::write(&program, source).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    support::spawn_private_executable(
        Command::new(env!("CARGO_BIN_EXE_O"))
            .env_remove("O_EXECUTOR")
            .arg(&program)
            .arg(root.join("backends"))
            .current_dir(workdir)
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    )
    .unwrap()
}

/// Everything O and its helpers wrote to stderr, once every writer is gone.
fn stderr_of(child: &mut Child) -> String {
    use std::io::Read;
    let mut text = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    text
}

/// The pids of every process whose command line is exactly `sleep <arg>`.
fn sleeps(arg: &str) -> Vec<i32> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        if cmdline == format!("sleep\0{arg}\0").as_bytes() && alive(pid) {
            found.push(pid);
        }
    }
    found
}

fn assert_pipeline_jobs_gone() {
    for arg in ["900", "901", "902"] {
        for pid in sleeps(arg) {
            assert_gone_soon(pid);
        }
    }
}

/// Signal O while its block runs the pipeline jobs plus a foreground sleep,
/// and return what was said.
fn signal_during_pipeline_block(signal: libc::c_int) -> String {
    let workdir = tempfile::tempdir().unwrap();
    let pidfile = workdir.path().join("job.pid");
    let mut child = start_program(workdir.path(), &pipeline_source(&pidfile, "sleep 60\n"));
    wait_for_job(&mut child, &pidfile);
    // SAFETY: kill only signals the O process spawned above.
    assert_eq!(unsafe { libc::kill(child.id() as libc::pid_t, signal) }, 0);
    let stderr = stderr_of(&mut child);
    wait_bounded(&mut child);
    assert_pipeline_jobs_gone();
    stderr
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

// the count is every process the block left, not every group: the pipeline
// is two of them in one group, the setsid job a third. on a cancel the
// block's foreground sleep is a fourth.

#[test]
fn a_block_end_counts_each_process_it_left() {
    if !support::require_runtime("bash") {
        return;
    }
    for _ in 0..3 {
        let workdir = tempfile::tempdir().unwrap();
        let pidfile = workdir.path().join("job.pid");
        let mut child = start_program(workdir.path(), &pipeline_source(&pidfile, ""));
        let stderr = stderr_of(&mut child);
        assert!(wait_bounded(&mut child).success(), "{stderr}");
        assert!(
            stderr.contains("bash block left 3 background process(es); they were stopped"),
            "{stderr}"
        );
        assert_pipeline_jobs_gone();
    }
}

#[test]
fn a_cancel_counts_each_process_the_block_had() {
    if !support::require_runtime("bash") {
        return;
    }
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGINT, libc::SIGTERM] {
        let stderr = signal_during_pipeline_block(signal);
        assert!(
            stderr.contains("bash block cancelled; stopped 4 process(es)"),
            "signal {signal}: {stderr}"
        );
        assert_eq!(
            stderr.matches("process(es) were stopped").count(),
            1,
            "{stderr}"
        );
    }
}

#[test]
fn killing_o_counts_each_process_the_block_had() {
    if !support::require_runtime("bash") {
        return;
    }
    for _ in 0..2 {
        // the helper still holds O's stderr, so its notice arrives.
        let stderr = signal_during_pipeline_block(libc::SIGKILL);
        assert!(
            stderr.contains("bash block cancelled; stopped 4 process(es)"),
            "{stderr}"
        );
    }
}

#[test]
fn a_cancel_stops_an_idle_session_s_setsid_job() {
    if !support::require_runtime("bash") {
        return;
    }
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let workdir = tempfile::tempdir().unwrap();
        let (mut child, pidfile) = start_idle_session_program(workdir.path());
        let job = wait_for_job(&mut child, &pidfile);
        // let bash[1] go idle and the plain block start.
        std::thread::sleep(Duration::from_millis(300));
        assert!(alive(job));
        // SAFETY: kill only signals the O process spawned above.
        assert_eq!(unsafe { libc::kill(child.id() as libc::pid_t, signal) }, 0);
        assert!(!wait_bounded(&mut child).success());
        assert_gone_soon(job);
    }
}

#[test]
fn killing_o_stops_an_idle_session_s_setsid_job() {
    if !support::require_runtime("bash") {
        return;
    }
    let workdir = tempfile::tempdir().unwrap();
    let (mut child, pidfile) = start_idle_session_program(workdir.path());
    let job = wait_for_job(&mut child, &pidfile);
    std::thread::sleep(Duration::from_millis(300));
    assert!(alive(job));
    // stdin closes before the parent death signal arrives; both paths stop it.
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
