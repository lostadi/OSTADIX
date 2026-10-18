//! now(batch(...)) seen from the O command line: a failed member fails the
//! run with status 1, and a real cancellation is never absorbed as a member
//! failure.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod support;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn o_command(program: &Path, workdir: &Path) -> Command {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new(env!("CARGO_BIN_EXE_O"));
    command
        .env_remove("O_EXECUTOR")
        .arg(program)
        .arg(root.join("backends"))
        .current_dir(workdir)
        .env("PYTHONDONTWRITEBYTECODE", "1");
    command
}

fn write_program(workdir: &Path, source: &str) -> std::path::PathBuf {
    let program = workdir.join("main.o");
    std::fs::write(&program, source).unwrap();
    program
}

// ---------------------------------------------------------------------------
// failed member
// ---------------------------------------------------------------------------

#[test]
fn o_exits_1_when_a_forced_batch_member_failed() {
    if !support::require_runtime("python3") {
        return;
    }
    let workdir = tempfile::tempdir().unwrap();
    let program = write_program(
        workdir.path(),
        "let g = lazy(batch(\n\
         python^(__oval_result__ = 42)_python,\n\
         python^(raise KeyError('missing'))_python\n\
         ))\n\
         now($g)\n",
    );
    let output =
        support::output_private_executable(&mut o_command(&program, workdir.path())).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    // the member index is zero-based (SPEC.md:762-787).
    assert!(stderr.contains("batch member 1 failed"), "{stderr}");
    assert!(stderr.contains("missing"), "{stderr}");
}

// ---------------------------------------------------------------------------
// real cancellation
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_real_cancel_during_now_batch_is_not_a_member_failure() {
    if !support::require_runtime("python3") {
        return;
    }
    let workdir = tempfile::tempdir().unwrap();
    let marker = workdir.path().join("started");
    let program = write_program(
        workdir.path(),
        &format!(
            "let g = lazy(batch(\n\
             python^(\n\
             import time\n\
             open({marker:?}, 'w').close()\n\
             time.sleep(60)\n\
             __oval_result__ = 1\n\
             )_python,\n\
             python^(__oval_result__ = 2)_python\n\
             ))\n\
             now($g)\n",
            marker = marker.display().to_string()
        ),
    );
    let mut child = support::spawn_private_executable(
        o_command(&program, workdir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .unwrap();

    // cancel only once the member is really running.
    let started = Instant::now();
    while !marker.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the batch member never started"
        );
        if let Some(status) = child.try_wait().unwrap() {
            panic!("O ended before the member started: {status}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let cancelled_at = Instant::now();
    // SAFETY: kill only signals the child spawned above.
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) },
        0
    );

    let mut status = None;
    while cancelled_at.elapsed() < Duration::from_secs(30) {
        if let Some(done) = child.try_wait().unwrap() {
            status = Some(done);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("O did not stop within 30s of SIGINT");
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();

    assert!(!status.success(), "{stderr}");
    assert!(cancelled_at.elapsed() < Duration::from_secs(30));
    // the cancel stops the run; it is not one member's error inside a list.
    assert!(!stderr.contains("batch member"), "{stderr}");
    assert!(!stdout.contains('2'), "the batch yielded a value: {stdout}");
}
