use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use num_bigint::BigInt;
use serde_json::Value;

/// Compatibility projection over the canonical backend-state protocol.
///
/// The implementation is compiled exactly once as [`crate::backend_state`];
/// this historical path preserves source and type identity for existing users.
pub use crate::backend_state as state;

use crate::backend_catalog::{BackendAdapterKind, BackendRegistry};
use crate::backend_state::{
    self, BackendCheckpointV1, BackendRestoreReceiptV1, BackendStateCapabilitiesV1,
    BackendStateErrorV1, BackendStateReasonV1, BackendStateTierV1, BackendWireCommandV2,
    BackendWireResponseV2, SQL_CLI_CODEC_V1,
};
use crate::runtime_exec::BackendToolchain;
use crate::value::{FloatFormat, ONumber, OValue};
use crate::wire;

#[cfg(test)]
const NATIVE_BACKEND_HANDLERS: &[&str] = &[
    "bash",
    "shell",
    "javascript",
    "ruby",
    "rust",
    "c",
    "cpp",
    "java",
    "nix",
    "nix_expr",
    "nix_store",
    "sql",
    "haskell",
    "ocaml",
    "racket",
    "lisp",
    "common_lisp",
    "csharp",
    "matlab",
    "mathematica",
    "webassembly",
];

pub fn run_backend_from_env_args() -> Result<bool> {
    let mut args = std::env::args();
    let _program = args.next();
    if args.next().as_deref() != Some("--o-backend") {
        return Ok(false);
    }

    let lang = args
        .next()
        .context("--o-backend requires a language name")?;
    if let Some(extra) = args.next() {
        bail!("unexpected argument after --o-backend {lang}: {extra}");
    }

    run_backend(&lang)?;
    Ok(true)
}

pub fn has_native_backend(lang: &str) -> bool {
    BackendRegistry::global().adapter_for(lang) == BackendAdapterKind::NativeRust
}

pub fn run_backend(lang: &str) -> Result<()> {
    let tools = BackendToolchain::from_env(lang)?;
    tools.verify_all()?;
    if lang == "bash" {
        // fail closed: without the subreaper bit a setsid or double-forked
        // job escapes to init and outlives its block.
        become_bash_subreaper()
            .context("the bash backend could not become the subreaper of its jobs")?;
    }
    // a SIGTERM, from the host's cancel or from our parent's death, stops
    // the backend's children (and for bash, its shell and reparented jobs)
    // before this process exits.
    install_backend_termination(lang == "bash")
        .context("could not install the backend's SIGTERM cleanup")?;
    // armed only after the handler: from here our parent's death runs
    // the cleanup. a parent already gone sent no signal, so stop now.
    #[cfg(target_os = "linux")]
    if let Some(parent) = std::env::var_os(crate::process::BACKEND_PARENT_PID_ENV) {
        let parent = parent
            .to_str()
            .and_then(|text| text.parse::<libc::pid_t>().ok())
            .context("O_BACKEND_PARENT_PID is not a pid")?;
        match crate::process::arm_parent_death_signal(parent) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                if lang == "bash" {
                    terminate_bash_now();
                } else {
                    terminate_non_bash_backend_now();
                }
            }
            Err(error) => {
                return Err(error).context("could not arm the backend's parent death signal")
            }
        }
    }
    if !has_native_backend(lang) {
        return proxy_legacy_backend(lang, &tools);
    }
    let mut backend = RustBackend::new(tools);
    if lang == "bash" {
        backend.bash_backend = true;
        backend.plain_bash = std::env::var_os(crate::process::PLAIN_BASH_HELPER_ENV)
            .is_some_and(|value| value == "1");
        // the shell is spawned before the first request, so no block waits
        // for a fork.
        backend.prespawn_bash()?;
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    if crate::process::shim_heartbeat_interval().is_some() {
        let heartbeat = crate::process::HEARTBEAT_CAPABILITY.to_string();
        wire::write_frame(
            &mut stdout.lock(),
            &BackendWireResponseV2::HelloV1 {
                capabilities: vec![heartbeat],
            },
        )?;
    }

    // started by the first step that needs it.
    let mut heartbeat: Option<Heartbeat> = None;
    let mut shutdown_walked = false;
    let loop_result: Result<()> = (|| {
        while let Some(command) = wire::read_frame::<_, BackendWireCommandV2>(&mut reader)? {
            if matches!(&command, BackendWireCommandV2::Shutdown) {
                match backend.shutdown() {
                    Ok(()) => {
                        shutdown_walked = true;
                        wire::write_frame(
                            &mut stdout.lock(),
                            &BackendWireResponseV2::ok(OValue::Null),
                        )?;
                        crate::process::lifecycle_trace(
                            "backend.shutdown_acknowledged",
                            format!("language={lang}"),
                        );
                        return Ok(());
                    }
                    Err(error) => {
                        shutdown_walked = true;
                        wire::write_frame(
                            &mut stdout.lock(),
                            &BackendWireResponseV2::err(format!(
                                "backend shutdown failed: {error:#}"
                            )),
                        )?;
                        return Err(error).context("backend shutdown failed");
                    }
                }
            }
            let response = match command {
            BackendWireCommandV2::ExecMorphismV1 { .. } => BackendWireResponseV2::err(
                "morphism.unsupported-backend: this native adapter has no executable morphism contract",
            ),
            BackendWireCommandV2::Exec {
                code,
                bindings,
                plain_next,
            } => {
                let result = if lang == "javascript" && (code.contains("O.native_")
                    || bindings.values().any(|value| matches!(value, OValue::Native { .. }))) {
                    run_javascript_native_bridge(&backend.tools, &code, &bindings, &mut reader, &mut stdout.lock())
                } else {
                    if heartbeat.is_none() {
                        if let Some(interval) = crate::process::shim_heartbeat_interval() {
                            heartbeat = Some(Heartbeat::start(backend.child_pid.clone(), interval)?);
                        }
                    }
                    let _pulse = match &heartbeat {
                        Some(heartbeat) => heartbeat.step(),
                        None => HeartbeatStep { heartbeat: None },
                    };
                    backend.exec(lang, &code, bindings)
                };
                // the next plain block's shell, spawned before the answer so
                // the host's next request finds it ready. only when the plan
                // has another plain block ahead: a one-block program spawns
                // exactly one shell.
                if backend.plain_bash && plain_next {
                    if let Err(error) = backend.prespawn_bash() {
                        // the block itself succeeded or failed on its own; the
                        // next block starts its shell inline and reports a
                        // real failure there.
                        crate::process::lifecycle_trace(
                            "backend.plain_bash_prespawn_failed",
                            format!("{error:#}"),
                        );
                    }
                }
                match result {
                    Ok(value) => BackendWireResponseV2::ok(value),
                    Err(error) => BackendWireResponseV2::err(format!("{error:#}")),
                }
            }
            BackendWireCommandV2::Cleanup => match backend.cleanup() {
                Ok(()) => BackendWireResponseV2::ok(OValue::Null),
                Err(error) => BackendWireResponseV2::err(format!("{error:#}")),
            },
            BackendWireCommandV2::Shutdown => unreachable!("shutdown handled before dispatch"),
            BackendWireCommandV2::Ping => BackendWireResponseV2::ok(OValue::Null),
            BackendWireCommandV2::EvalResult { .. } => BackendWireResponseV2::err(
                "backend received eval_result without a pending eval request",
            ),
            BackendWireCommandV2::NativeOperationV1 { .. } => BackendWireResponseV2::err(
                "native.unsupported-owner: this adapter does not retain Python objects",
            ),
            BackendWireCommandV2::StateCapabilitiesV1 => {
                BackendWireResponseV2::StateCapabilitiesV1 {
                    capabilities: backend.state_capabilities(lang),
                }
            }
            BackendWireCommandV2::CheckpointV1 { max_bytes } => {
                backend.checkpoint_response(lang, max_bytes)
            }
            BackendWireCommandV2::RestoreV1 { checkpoint } => {
                backend.restore_response(lang, checkpoint)
            }
        };
            wire::write_frame(&mut stdout.lock(), &response)?;
        }
        Ok(())
    })();

    // stdin EOF or a broken pipe: the host is gone or closing us without a
    // Shutdown frame (which already walked in backend.shutdown()). a bash
    // backend still has its shell and maybe a session's jobs, so it stops
    // them before it exits. a SIGTERM's walk that is already running ends
    // the process itself; this waits on its lock meanwhile.
    if lang == "bash" && !shutdown_walked {
        let shell = SHELL_PID.load(std::sync::atomic::Ordering::SeqCst);
        let mut sweep = stop_backend_descendants(JOB_CLEANUP_WINDOW, (shell != 0).then_some(shell));
        sweep.quiet = true;
        let report = sweep.report();
        loop_result?;
        report?;
        return Ok(());
    }
    loop_result
}

/// Sends `heartbeat_v1` frames on stdout while a native step runs, so the
/// host can tell a long step from a hung one. For bash it reports the session
/// shell's kernel state.
///
/// why one long-lived thread: a thread per step cost every short block a
/// spawn and a join. the thread starts with the first step, and each step
/// only flips a flag under a lock; the first frame of a step comes one
/// interval after it began, so a short step sends none. the heartbeat always
/// runs, since it is how the host tells a dead backend from a slow one.
struct Heartbeat {
    shared: std::sync::Arc<(std::sync::Mutex<HeartbeatState>, std::sync::Condvar)>,
}

#[derive(Default)]
struct HeartbeatState {
    // the step now running, if any; numbered so a frame due for an earlier
    // step is never sent for a later one.
    step: Option<u64>,
    next_step: u64,
}

/// Ends the step's heartbeat on drop, before the step's answer is written.
/// the flag is cleared under the lock the thread writes under, so no frame
/// can follow the answer.
struct HeartbeatStep<'a> {
    heartbeat: Option<&'a Heartbeat>,
}

impl Heartbeat {
    fn start(
        child_pid: std::sync::Arc<std::sync::atomic::AtomicU32>,
        interval: Duration,
    ) -> io::Result<Self> {
        let shared = std::sync::Arc::new((
            std::sync::Mutex::new(HeartbeatState::default()),
            std::sync::Condvar::new(),
        ));
        let watched = std::sync::Arc::clone(&shared);
        thread::Builder::new()
            .name("ostadix-backend-heartbeat".into())
            .spawn(move || {
                let (state, wake) = &*watched;
                let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    let Some(step) = guard.step else {
                        guard = wake.wait(guard).unwrap_or_else(|e| e.into_inner());
                        continue;
                    };
                    // armed: one interval after the step began, then each
                    // interval while the same step still runs.
                    let (next, _) = wake
                        .wait_timeout_while(guard, interval, |state| state.step == Some(step))
                        .unwrap_or_else(|e| e.into_inner());
                    guard = next;
                    if guard.step != Some(step) {
                        continue;
                    }
                    let pid = child_pid.load(std::sync::atomic::Ordering::Relaxed);
                    let child = (pid != 0).then(|| heartbeat_child(pid));
                    let frame = BackendWireResponseV2::HeartbeatV1 { child };
                    if wire::write_frame(&mut io::stdout().lock(), &frame).is_err() {
                        return;
                    }
                }
            })?;
        Ok(Self { shared })
    }

    fn step(&self) -> HeartbeatStep<'_> {
        let (state, wake) = &*self.shared;
        let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
        guard.next_step = guard.next_step.wrapping_add(1);
        guard.step = Some(guard.next_step);
        wake.notify_all();
        HeartbeatStep {
            heartbeat: Some(self),
        }
    }
}

impl Drop for HeartbeatStep<'_> {
    fn drop(&mut self) {
        if let Some(heartbeat) = self.heartbeat.take() {
            let (state, wake) = &*heartbeat.shared;
            state.lock().unwrap_or_else(|e| e.into_inner()).step = None;
            wake.notify_all();
        }
    }
}

/// `/proc/<pid>/stat` state letter and utime+stime ticks, or `"gone"`.
fn heartbeat_child(pid: u32) -> crate::backend_state::BackendHeartbeatChildV1 {
    let sampled = fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let fields = stat
                .rsplit_once(')')?
                .1
                .split_whitespace()
                .collect::<Vec<_>>();
            let state = fields.first()?.to_string();
            let utime = fields.get(11)?.parse::<u64>().ok()?;
            let stime = fields.get(12)?.parse::<u64>().ok()?;
            Some((state, utime + stime))
        });
    let (state, cpu_ticks) = match sampled {
        Some((state, ticks)) if state != "Z" && state != "X" => (state, ticks),
        _ => ("gone".to_string(), 0),
    };
    crate::backend_state::BackendHeartbeatChildV1 {
        pid,
        state,
        cpu_ticks,
    }
}

struct RustBackend {
    sql: Option<SqlState>,
    bash: Option<BashSession>,
    // pid of the process a step drives (the bash session shell or sqlite3;
    // 0 when none), reported in heartbeats.
    // signal that killed the bash session shell mid-block; later blocks fail.
    bash_killed: Option<i32>,
    // a plain-block helper: every block gets a fresh shell, ended (with its
    // jobs) before the answer is written, and the next shell is spawned after.
    plain_bash: bool,
    // this backend serves bash, so it is the subreaper of bash's jobs.
    bash_backend: bool,
    child_pid: std::sync::Arc<std::sync::atomic::AtomicU32>,
    tools: BackendToolchain,
}

/// Helper-only variables a plain block's shell never inherits.
const PLAIN_HELPER_PRIVATE_ENV: [&str; 4] = [
    "O_BACKEND_SESSION_ID",
    "O_BACKEND_LAUNCH_GENERATION",
    "O_BACKEND_NATIVE_INSTANCE_ID",
    crate::process::PLAIN_BASH_HELPER_ENV,
];

/// Persistent `bash` session for one backend process.
///
/// A backend process serves exactly one (language, environment) pair. Plain
/// `bash^(...)_bash` blocks run in a reusable helper backend that gives every
/// block a fresh shell and ends it, with its jobs, before answering, so their
/// variables vanish when the block finishes. Numbered environments such as
/// `bash[0]^(...)_bash[0]` reuse one backend process, and this session keeps
/// shell variables, functions, options, and the working directory across the
/// blocks of that environment only. Each block runs through `source` in the
/// session shell with stdout and stderr redirected to per-block files; a
/// sentinel line on the session's own stdout reports the block's status. A
/// block that exits the shell ends the session, reports that exit status, and
/// the next block of the environment starts a fresh session.
struct BashSession {
    dir: TempDir,
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    stdout: BufReader<ChildStdout>,
    serial: u64,
}

const BASH_SESSION_SENTINEL: &str = "__O_BASH_BLOCK_DONE__";

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

// ############################################################################
// bash let injection
// ############################################################################

/// Shell text that assigns the received `let` values before a block, and
/// shell text that undoes it after the block.
///
/// An ordinary name is assigned with `declare +x`, so it is never exported
/// even when the session or the O process already exported that name, and it
/// is unset afterwards. A writable bash special such as `PATH`, `HOME`, or
/// `IFS` is assigned with `declare --`, which keeps its export flag,
/// and is left as it is afterwards: in a `bash[N]` session the let value
/// persists for later blocks exactly as the block left it, and a plain block
/// starts a fresh session anyway. Readonly specials never get here; the plan
/// rejects them. Every assignment is checked: one that fails, for example
/// on a name an earlier `bash[N]` block made readonly, clears
/// `__o_inject_ok` and the block does not run.
fn bash_injection(env: &[(String, String)]) -> (String, String) {
    let mut inject = String::new();
    let mut unset = Vec::new();
    for (name, value) in env {
        let quoted = shell_single_quote(value);
        let special = crate::ir::bash_special_name(name);
        if special == Some(crate::ir::BashSpecial::Writable) {
            // session state such as PATH stays assigned, so later blocks of
            // the session see the let value from the first block naming it.
            inject.push_str(&format!("declare -- {name}={quoted} || __o_inject_ok=0; "));
        } else {
            inject.push_str(&format!("declare +x {name}={quoted} || __o_inject_ok=0; "));
            unset.push(name.as_str());
        }
    }
    let restore = if unset.is_empty() {
        String::new()
    } else {
        // a readonly name refuses the unset; `|| :` keeps a persisted
        // `set -e` from ending the session on that.
        format!("unset -v {} 2>/dev/null || :; ", unset.join(" "))
    };
    (inject, restore)
}

/// Shell text for each `let` value a bash block receives, sorted by name.
/// The evaluator already rendered structured values and rejected NUL bytes
/// (`eval_core::bash_let_value`); this repeats the checks for direct callers.
/// It cannot call that helper: eval_core sits on backend's own layer.
fn bash_values(bindings: HashMap<String, OValue>) -> Result<Vec<(String, String)>> {
    let mut values = Vec::with_capacity(bindings.len());
    for (name, value) in bindings {
        let special = crate::ir::bash_special_name(&name).is_some();
        if special && !matches!(value, OValue::Text { .. }) {
            let type_name = value.type_name();
            bail!(
                "let `{name}` names a bash special variable, so a bash block can only receive \
                 it as text, got {type_name}"
            );
        }
        let text = scalar_string(&value).unwrap_or_else(|| value.splice_repr());
        if text.contains('\0') {
            bail!("let `{name}` contains a NUL byte, which a bash variable cannot hold");
        }
        values.push((name, text));
    }
    values.sort();
    Ok(values)
}

impl BashSession {
    fn start(tools: &BackendToolchain, plain: bool) -> Result<Self> {
        let dir = TempDir::new("o-bash-session")?;
        let mut command = tools.command("bash")?;
        // the host's pid is for this backend only.
        command.env_remove(crate::process::BACKEND_PARENT_PID_ENV);
        if plain {
            // a helper serves many plain blocks; its own identity is not the
            // block's, so the shell does not see it.
            for name in PLAIN_HELPER_PRIVATE_ENV {
                command.env_remove(name);
            }
        }
        // the shell stays in the backend's process group: the host kills
        // that group on cancellation or the opt-in limit, and the group kill
        // must reach the shell and the jobs it started.
        let mut child = command
            .args(["--noprofile", "--norc", "-s"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to launch admitted `bash` executable")?;
        if let Ok(pid) = i32::try_from(child.id()) {
            SHELL_PID.store(pid, std::sync::atomic::Ordering::SeqCst);
        }
        let stdin = child.stdin.take().context("bash session has no stdin")?;
        let stdout = child.stdout.take().context("bash session has no stdout")?;
        Ok(Self {
            dir,
            child,
            stdin: Some(BufWriter::new(stdin)),
            stdout: BufReader::new(stdout),
            serial: 0,
        })
    }

    /// Run one block and return its captured output and exit status, plus
    /// whether the session shell is still alive afterwards.
    fn run(&mut self, code: &str, env: &[(String, String)]) -> Result<(Output, bool)> {
        use std::os::unix::process::ExitStatusExt;
        self.serial += 1;
        let base = self.dir.path().join(format!("block-{}", self.serial));
        let code_path = base.with_extension("sh");
        let out_path = base.with_extension("out");
        let err_path = base.with_extension("err");
        // the block file holds only the user's code, so bash's line numbers
        // in error messages match the block; injection happens on the
        // request line instead.
        let mut script = String::with_capacity(code.len() + 1);
        script.push_str(code);
        script.push('\n');
        fs::write(&code_path, script)?;
        let (inject, restore) = bash_injection(env);
        let request = format!(
            // the injection runs inside the block's capture, so a failed
            // assignment's message reaches the user, and `||` keeps a
            // persisted `set -e` from killing the session on it.
            // the refusal sets the status instead of failing a command, so a
            // persisted `set -e` cannot end the session on it.
            "__o_status=125; {{ __o_inject_ok=1; {inject}if (( __o_inject_ok )); then source {}; __o_status=$?; else printf 'o: a let value could not be assigned, so the block did not run\\n' >&2; fi; }} </dev/null >{} 2>{}; unset -v __o_inject_ok; {restore}printf '\\n{BASH_SESSION_SENTINEL}%d\\n' \"$__o_status\"; unset -v __o_status\n",
            shell_single_quote(&code_path.to_string_lossy()),
            shell_single_quote(&out_path.to_string_lossy()),
            shell_single_quote(&err_path.to_string_lossy()),
        );
        let stdin = self.stdin.as_mut().context("bash session stdin closed")?;
        stdin.write_all(request.as_bytes())?;
        stdin.flush()?;
        let mut status_code = None;
        let mut line = String::new();
        loop {
            line.clear();
            if self.stdout.read_line(&mut line)? == 0 {
                break;
            }
            if let Some(rest) = line.trim_end().strip_prefix(BASH_SESSION_SENTINEL) {
                status_code = Some(rest.parse::<i32>().unwrap_or(1));
                break;
            }
        }
        let alive = status_code.is_some();
        let status = match status_code {
            Some(code) => std::process::ExitStatus::from_raw((code & 0xff) << 8),
            None => {
                self.stdin.take();
                self.child.wait()?
            }
        };
        // bash names the sourced file in its messages; the session's temp
        // path is an implementation detail, so it reads as `bash` instead.
        // the shell created the capture files before the block ran, so once
        // it has answered, a missing or unreadable one means the output is
        // unknown, never empty. a shell that died before answering already
        // fails the block, and may have died before creating them.
        let capture = |path: &Path, stream: &str| -> Result<Vec<u8>> {
            match fs::read(path) {
                Ok(bytes) => Ok(bytes),
                Err(_) if !alive => Ok(Vec::new()),
                Err(error) => Err(error).with_context(|| {
                    format!("bash block {stream} capture is missing or unreadable")
                }),
            }
        };
        let stderr = capture(&err_path, "stderr")?;
        let stderr = String::from_utf8_lossy(&stderr)
            .replace(&*code_path.to_string_lossy(), "bash")
            .replace(&*self.dir.path().to_string_lossy(), "<bash session>")
            .into_bytes();
        let output = Output {
            status,
            stdout: capture(&out_path, "stdout")?,
            stderr,
        };
        for path in [&code_path, &out_path, &err_path] {
            let _ = fs::remove_file(path);
        }
        Ok((output, alive))
    }

    /// End the shell and every job it left. an error means the jobs could
    /// not be enumerated, so some may still run.
    fn shutdown(&mut self) -> Result<()> {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        // jobs the blocks left behind, including setsid, nohup, and
        // double-forked ones, were reparented to this backend, which is
        // their subreaper; stop them so nothing outlives the block (plain
        // bash) or the session (bash[N]).
        let shell = i32::try_from(self.child.id()).ok();
        stop_backend_descendants(JOB_CLEANUP_WINDOW, shell).report()
    }
}

// ############################################################################
// bash background jobs
// ############################################################################

/// Make this backend process the subreaper of everything bash starts, so a
/// job that leaves its process group or session (`setsid`, `nohup`, a double
/// fork) is reparented here instead of to init. Only the bash backend
/// process does this, never the O process, so other backends' orphans are
/// not mixed in. A descendant that makes itself a subreaper, or that a
/// service manager starts, still escapes; only a cgroup could hold those.
#[cfg(target_os = "linux")]
fn become_bash_subreaper() -> io::Result<()> {
    // SAFETY: PR_SET_CHILD_SUBREAPER takes one integer flag and changes only
    // this process's reparenting attribute.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn become_bash_subreaper() -> io::Result<()> {
    Ok(())
}

/// How long job cleanup may keep killing and reaping before it reports the
/// jobs still alive. it bounds cleanup only, never a block.
const JOB_CLEANUP_WINDOW: Duration = Duration::from_secs(2);

/// The live children of this process, from `/proc/self/task/*/children`.
///
/// why not a /proc scan: reading every process's stat cost a few ms per plain
/// block on a busy host. as the subreaper this process inherits every orphan
/// bash leaves, so its own children are all that cleanup has to visit; killing
/// one reparents its children here for the next pass. an empty children file
/// is the whole check when nothing is left.
///
/// a task that exited between the listing and the read is skipped; any other
/// unreadable file is an error, since a child it hides would escape cleanup.
/// a kernel without the children files (CONFIG_PROC_CHILDREN off) falls back
/// to the /proc scan, after a one-time warning.
#[cfg(target_os = "linux")]
fn backend_descendants() -> io::Result<Vec<i32>> {
    children_of(None)
}

/// The children of `pid`, or of this process for None; see
/// [`backend_descendants`].
#[cfg(target_os = "linux")]
fn children_of(pid: Option<i32>) -> io::Result<Vec<i32>> {
    let root = match pid {
        Some(pid) => format!("/proc/{pid}/task"),
        None => "/proc/self/task".to_string(),
    };
    let mut children = Vec::new();
    for task in fs::read_dir(&root)? {
        let task = task?;
        let path = task.path().join("children");
        let list = match fs::read_to_string(&path) {
            Ok(list) => list,
            // the task is there but the file is not: no children files on
            // this kernel.
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && task.path().join("stat").exists() =>
            {
                warn_no_children_files();
                let parent = pid.unwrap_or_else(|| std::process::id() as i32);
                return children_by_scan(parent);
            }
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                continue
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{}: {error}", path.display()),
                ))
            }
        };
        for child in list.split_whitespace() {
            children.push(child.parse::<i32>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unreadable child pid `{child}` in {root}"),
                )
            })?);
        }
    }
    children.sort_unstable();
    children.dedup();
    Ok(children)
}

/// The children of `parent` from every /proc/*/stat: the slow path, only
/// for a kernel without the children files.
#[cfg(target_os = "linux")]
fn children_by_scan(parent: i32) -> io::Result<Vec<i32>> {
    let mut children = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if crate::process::linux_process_observation_disappeared(&error) => continue,
            Err(error) => return Err(error),
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let stat = match fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if crate::process::linux_process_observation_disappeared(&error) => continue,
            Err(error) => return Err(error),
        };
        // fields after the parenthesised command: state, ppid.
        let ppid = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(1))
            .and_then(|field| field.parse::<i32>().ok());
        if ppid == Some(parent) {
            children.push(pid);
        }
    }
    children.sort_unstable();
    Ok(children)
}

/// Said once per backend: this kernel has no /proc/<pid>/task/*/children.
#[cfg(target_os = "linux")]
fn warn_no_children_files() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "bash backend: /proc/<pid>/task/*/children is missing (CONFIG_PROC_CHILDREN off); \
             job cleanup scans /proc instead"
        );
    });
}

#[cfg(not(target_os = "linux"))]
fn backend_descendants() -> io::Result<Vec<i32>> {
    Ok(Vec::new())
}

/// What one cleanup pass did.
#[derive(Debug, Default)]
struct JobSweep {
    // background jobs stopped: every live (non-zombie) descendant of this
    // backend except the block's own bash, as one snapshot taken before
    // the first kill. why a snapshot: counting what each pass happened to
    // kill or reap depended on timing (a job's children reach this
    // subreaper only as the job dies). `sleep 1 | sleep 2 &` is two jobs; a
    // setsid job is one.
    stopped: usize,
    // children still present when the window ran out.
    survivors: Vec<i32>,
    // why the children could not be listed or reaped, if they could not.
    error: Option<String>,
    // a walk at stdin EOF: the session's jobs were never a block's to
    // report, so only a failure is said.
    quiet: bool,
    // a SIGTERM's walk: the count includes the block's foreground command,
    // so the notice does not call them background processes.
    cancelled: bool,
}

impl JobSweep {
    /// The stderr notice for the block, and an error when cleanup could not
    /// see every job.
    fn report(self) -> Result<()> {
        // one line, written once the walk has finished.
        if self.stopped > 0 && !self.quiet {
            if self.cancelled {
                eprintln!("bash block cancelled; stopped {} process(es)", self.stopped);
            } else {
                eprintln!(
                    "bash block left {} background process(es); they were stopped",
                    self.stopped
                );
            }
        }
        let failed = crate::process::JOB_CLEANUP_FAILED;
        if let Some(error) = self.error {
            bail!("{failed}: {error}");
        }
        // a job that outlived the window means cleanup failed: the block
        // fails, and the host retires this backend instead of reusing it.
        if !self.survivors.is_empty() {
            let pids = self
                .survivors
                .iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            bail!(
                "{failed}: {} job(s) still alive after {} ms: pid {pids}",
                self.survivors.len(),
                JOB_CLEANUP_WINDOW.as_millis()
            );
        }
        Ok(())
    }
}

/// SIGKILL every child and its process group and reap, until waitpid says
/// no child is left (ECHILD) or `budget` runs out. `shell` is the block's own
/// bash, which the job count leaves out.
///
/// why ECHILD and not an empty scan: a job killed in this pass reparents its
/// own children here only as it dies, so a scan can come back empty while a
/// grandchild is still on its way.
fn stop_backend_descendants(budget: Duration, shell: Option<i32>) -> JobSweep {
    // why one lock over the whole walk: a SIGTERM's walk and the block-end
    // walk can overlap; they run one after the other.
    let _walk = WALK.lock().unwrap_or_else(|poison| poison.into_inner());
    let deadline = std::time::Instant::now() + budget;
    let mut sweep = JobSweep::default();
    // a snapshot that cannot be read fails the cleanup, but the kill loop
    // still runs: it kills what it can list.
    let mut initial_empty = false;
    match live_descendant_tree() {
        Ok(tree) => {
            initial_empty = tree.is_empty();
            sweep.stopped = tree.iter().filter(|pid| Some(**pid) != shell).count();
        }
        Err(error) => sweep.error = Some(format!("cannot list the jobs: {error}")),
    }
    let mut walk_error = None;
    // when the initial snapshot saw no live children at all and waitpid(-1)
    // confirms ECHILD, no child or zombie exists, saving a second /proc walk
    // on every plain bash block exit.
    if initial_empty {
        let mut status = 0;
        let reaped = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if reaped < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
            return finish_walk(sweep);
        }
    }
    loop {
        let live = match backend_descendants() {
            Ok(live) => live,
            Err(error) => {
                walk_error = Some(error.to_string());
                break;
            }
        };
        for pid in &live {
            // a job that called setsid leads its own group; killing the group
            // takes its pipeline down in one pass.
            // SAFETY: killpg and kill only signal a pid found as our child.
            unsafe {
                libc::killpg(*pid, libc::SIGKILL);
                libc::kill(*pid, libc::SIGKILL);
            }
        }
        // reap every child that has exited, including reparented ones.
        let mut no_children = false;
        loop {
            let mut status = 0;
            // SAFETY: waitpid with WNOHANG on any child of this process.
            let reaped = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if reaped > 0 {
                continue;
            }
            if reaped < 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::ECHILD) => no_children = true,
                    _ => walk_error = Some(format!("waitpid: {error}")),
                }
            }
            break;
        }
        if no_children || walk_error.is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            sweep.survivors = backend_descendants().unwrap_or(live);
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if sweep.error.is_none() {
        sweep.error = walk_error;
    }
    finish_walk(sweep)
}

/// The one exit of a cleanup walk. a SIGTERM that landed during the walk
/// reuses it: this walk already signalled every job, so it reports and
/// exits here, still holding the lock, instead of the SIGTERM waiting for
/// it and walking again. that keeps the whole cleanup inside one window,
/// and inside the host's.
fn finish_walk(mut sweep: JobSweep) -> JobSweep {
    if TERMINATING.load(std::sync::atomic::Ordering::SeqCst) {
        sweep.quiet = false;
        sweep.cancelled = true;
        if let Err(error) = sweep.report() {
            eprintln!("{error:#}");
        }
        std::process::exit(128 + libc::SIGTERM);
    }
    sweep
}

/// Every live descendant of this process: its children, theirs, and so on.
/// a pid that exits during the walk is skipped.
#[cfg(target_os = "linux")]
fn live_descendant_tree() -> io::Result<Vec<i32>> {
    #[cfg(test)]
    if FAIL_SNAPSHOT.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(io::Error::other("injected /proc read failure"));
    }
    let mut found = Vec::new();
    let mut pending = backend_descendants()?;
    while let Some(pid) = pending.pop() {
        if found.contains(&pid) {
            continue;
        }
        if live_process_group(pid).is_some() {
            found.push(pid);
        }
        // a pid that exits meanwhile has no children left to list.
        if let Ok(children) = children_of(Some(pid)) {
            pending.extend(children);
        }
    }
    Ok(found)
}

#[cfg(not(target_os = "linux"))]
fn live_descendant_tree() -> io::Result<Vec<i32>> {
    backend_descendants()
}

/// Test-only: makes the next job snapshots fail as a /proc read would.
#[cfg(test)]
static FAIL_SNAPSHOT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Serializes the cleanup walks; see [`stop_backend_descendants`].
static WALK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set once a SIGTERM is being handled.
static TERMINATING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The pid of the bash this backend started last, left out of the job count
/// of a SIGTERM's walk.
static SHELL_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// The process group of `pid`, or None for a zombie or a vanished pid.
#[cfg(target_os = "linux")]
fn live_process_group(pid: i32) -> Option<i32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // fields after the parenthesised command: state, ppid, pgrp.
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let state = fields.next()?;
    if state == "Z" || state == "X" {
        return None;
    }
    fields.nth(1)?.parse().ok()
}

#[cfg(not(target_os = "linux"))]
fn live_process_group(pid: i32) -> Option<i32> {
    Some(pid)
}

// ############################################################################
// bash backend termination
// ############################################################################

/// SIGTERM cleanup for the bash backend. the host's cancel and our parent's
/// death (PR_SET_PDEATHSIG) both send SIGTERM; the handler only wakes a
/// thread, which stops the shell and every job and then exits. a SIGKILL
/// would end this subreaper first and hand its setsid jobs to init.
#[cfg(target_os = "linux")]
static BASH_SIGTERM_WAKE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

#[cfg(target_os = "linux")]
extern "C" fn on_bash_sigterm(_: libc::c_int) {
    let fd = BASH_SIGTERM_WAKE.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        let byte = 1u8;
        // SAFETY: write is async-signal-safe; fd is our pipe's write end.
        unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
    }
}

#[cfg(target_os = "linux")]
fn install_backend_termination(bash_subreaper: bool) -> io::Result<()> {
    use std::io::Read;
    use std::os::fd::FromRawFd;
    use std::sync::atomic::Ordering;
    if BASH_SIGTERM_WAKE.load(Ordering::Relaxed) >= 0 {
        return Ok(());
    }
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two fds; O_CLOEXEC keeps them from child processes.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fds[0] is a fresh fd owned from here on.
    let mut wake = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    BASH_SIGTERM_WAKE.store(fds[1], Ordering::Relaxed);
    std::thread::Builder::new()
        .name("ostadix-backend-sigterm".into())
        .spawn(move || {
            let mut byte = [0u8; 1];
            loop {
                match wake.read(&mut byte) {
                    Ok(1) => {
                        if bash_subreaper {
                            terminate_bash_now()
                        } else {
                            terminate_non_bash_backend_now()
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    _ => return,
                }
            }
        })?;
    // SAFETY: a zeroed sigaction with a plain handler and an empty mask.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_bash_sigterm as *const () as usize;
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: sigemptyset and sigaction on a local struct.
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    if unsafe { libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Stop the shell and every job, say what was left, and exit.
#[cfg(target_os = "linux")]
fn terminate_bash_now() -> ! {
    TERMINATING.store(true, std::sync::atomic::Ordering::SeqCst);
    let shell = SHELL_PID.load(std::sync::atomic::Ordering::SeqCst);
    // a walk already running sees TERMINATING when it ends, reports and
    // exits, so this only gets the lock if that walk had finished. the
    // walk exits too; should it ever return, say so and exit anyway.
    let _ = stop_backend_descendants(JOB_CLEANUP_WINDOW, (shell != 0).then_some(shell));
    eprintln!("bash job cleanup failed: the SIGTERM walk returned instead of exiting");
    std::process::exit(128 + libc::SIGTERM)
}

/// Stop a non-bash backend and its owned process group when its parent dies.
#[cfg(target_os = "linux")]
fn terminate_non_bash_backend_now() -> ! {
    // every backend runs in its own process group (`process_group(0)`), so
    // killing group 0 takes down any legacy shim (`python3`) or tool child
    // in the group as well as this proxy process.
    unsafe {
        libc::kill(0, libc::SIGKILL);
        libc::_exit(128 + libc::SIGTERM);
    }
}

#[cfg(not(target_os = "linux"))]
fn install_backend_termination(_bash_subreaper: bool) -> std::io::Result<()> {
    Ok(())
}

/// Persistent `sqlite3` CLI session.
///
/// Earlier this backend spawned a fresh `sqlite3 -json <db> <sql>` process per
/// block. That correctly preserved `CREATE TABLE` (file-backed) but dropped
/// connection-local state such as `ATTACH DATABASE … AS alias` between blocks.
/// Keep one interactive session for the lifetime of the backend process so
/// multi-block `sql[0]^(…)_sql[0]` programs match the Python shim semantics.
struct SqlState {
    _dir: TempDir,
    db_path: PathBuf,
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    // why a reader thread: an untimed read_line on the session stdout hung
    // the backend forever on a locked or runaway query. lines arrive over a
    // channel so the wait can be bounded by the per-step limit.
    stdout_rx: Receiver<io::Result<String>>,
    stderr_rx: Receiver<String>,
    checkpoint_safe: bool,
    // set once a per-step limit killed the session; its state is gone.
    lost: bool,
}

impl RustBackend {
    fn new(tools: BackendToolchain) -> Self {
        Self {
            sql: None,
            bash: None,
            child_pid: Default::default(),
            bash_killed: None,
            plain_bash: false,
            bash_backend: false,
            tools,
        }
    }

    /// Spawn the shell the next block will use, so the block itself never
    /// waits for a fork.
    fn prespawn_bash(&mut self) -> Result<()> {
        if self.bash.is_none() {
            let session = BashSession::start(&self.tools, self.plain_bash)?;
            // the heartbeat watches this shell from its block on.
            self.child_pid
                .store(session.child.id(), std::sync::atomic::Ordering::Relaxed);
            self.bash = Some(session);
        }
        Ok(())
    }

    fn exec(
        &mut self,
        lang: &str,
        code: &str,
        bindings: HashMap<String, OValue>,
    ) -> Result<OValue> {
        match lang {
            "bash" => {
                if let Some(signal) = self.bash_killed {
                    bail!(
                        "bash session was killed by signal {signal} during an earlier block; its state is gone"
                    );
                }
                let env = bash_values(bindings)?;
                // a bare `$name` splice renders its value into the block text;
                // bash would silently drop a NUL there, so it is an error like
                // a NUL in an injected let.
                if code.contains('\0') {
                    bail!(
                        "bash block contains a NUL byte, probably from a spliced value; \
                         bash cannot hold NUL, so the block did not run"
                    );
                }
                if self.bash.is_none() {
                    let session = BashSession::start(&self.tools, self.plain_bash)?;
                    self.child_pid
                        .store(session.child.id(), std::sync::atomic::Ordering::Relaxed);
                    self.bash = Some(session);
                }
                let session = self.bash.as_mut().expect("bash session started");
                let (output, alive) = session.run(code, &env)?;
                if self.plain_bash {
                    return self.finish_plain_bash_block(output, alive);
                }
                if !alive {
                    self.child_pid
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                    // a shell killed by a signal lost its state without any
                    // block asking for that: fail this block and every later
                    // one (fail closed) instead of starting a fresh shell.
                    // latched before cleanup, so a failed cleanup cannot
                    // leave the session looking alive.
                    use std::os::unix::process::ExitStatusExt;
                    if let Some(signal) = output.status.signal() {
                        self.bash_killed = Some(signal);
                    }
                    if let Some(mut ended) = self.bash.take() {
                        ended.shutdown()?;
                    }
                    if let Some(signal) = output.status.signal() {
                        bail!(
                            "bash session was killed by signal {signal} during this block; its state is gone"
                        );
                    }
                    // a failing block that ends the session, for example
                    // under a persisted `set -e`, also drops every variable,
                    // function, and option; say so instead of resetting
                    // silently.
                    return output_to_value(
                        "bash session ended during this block, dropping its \
                         variables, functions, and options; the next block starts \
                         a fresh session. bash",
                        output,
                    );
                }
                output_to_value("bash", output)
            }
            "shell" => run_shell(&self.tools, "sh", &["-c", code], Some(scalar_env(bindings))),
            "javascript" => run_script(
                &self.tools,
                "javascript",
                "node",
                "js",
                &javascript_preamble(&bindings),
                code,
            ),
            "ruby" => run_script(
                &self.tools,
                "ruby",
                "ruby",
                "rb",
                &ruby_preamble(&bindings),
                code,
            ),
            "rust" => run_rust(&self.tools, code),
            "c" => run_c(&self.tools, code),
            "cpp" => run_cpp(&self.tools, code),
            "java" => run_java(&self.tools, code),
            "nix" | "nix_expr" => run_nix(&self.tools, code),
            "nix_store" => run_nix_store(&self.tools, code),
            "sql" => self.run_sql(code),
            "haskell" => run_haskell(&self.tools, code),
            "ocaml" => run_ocaml(&self.tools, code),
            "racket" => run_file_command(&self.tools, "racket", "racket", "rkt", code, &["{file}"]),
            "lisp" | "common_lisp" => run_common_lisp(&self.tools, code),
            "csharp" => run_csharp(&self.tools, code),
            "matlab" => run_matlab(&self.tools, code),
            "mathematica" => run_mathematica(&self.tools, code),
            "webassembly" => run_webassembly(&self.tools, code),
            other => bail!("backend `{other}` is not implemented by the Rust backend runner"),
        }
    }

    fn run_sql(&mut self, code: &str) -> Result<OValue> {
        let code = code.trim();
        if code.is_empty() {
            return Ok(OValue::Null);
        }

        let child_pid = std::sync::Arc::clone(&self.child_pid);
        let state = self.sql_state()?;
        // heartbeats report the sqlite3 process, as they report the bash shell.
        child_pid.store(state.child.id(), std::sync::atomic::Ordering::Relaxed);
        state.exec(code)
    }

    fn sql_state(&mut self) -> Result<&mut SqlState> {
        if self.sql.is_none() {
            self.sql = Some(SqlState::spawn(&self.tools)?);
        }
        Ok(self.sql.as_mut().expect("sql state was just initialized"))
    }

    fn cleanup(&mut self) -> Result<()> {
        if let Some(mut bash) = self.bash.take() {
            bash.shutdown()?;
        } else if self.bash_backend {
            // no shell now, but a job an earlier block left may still be
            // ours; the walk is one read of an empty children file when not.
            let mut sweep = stop_backend_descendants(JOB_CLEANUP_WINDOW, None);
            sweep.quiet = true;
            sweep.report()?;
        }
        if let Some(mut sql) = self.sql.take() {
            sql.shutdown(crate::process::backend_shutdown_timeout()?)?;
        }
        Ok(())
    }

    fn state_capabilities(&self, lang: &str) -> BackendStateCapabilitiesV1 {
        if lang == "sql" {
            BackendStateCapabilitiesV1::new(
                lang,
                BackendStateTierV1::SemanticSnapshot,
                SQL_CLI_CODEC_V1,
                true,
            )
        } else {
            backend_state::empty_state_capabilities(lang)
        }
    }

    fn checkpoint_response(&mut self, lang: &str, max_bytes: u64) -> BackendWireResponseV2 {
        let checkpoint = if lang == "sql" {
            self.sql_checkpoint()
        } else {
            backend_state::empty_checkpoint(lang, self.tools.executable_set_sha256())
        };
        match checkpoint {
            Ok(checkpoint) => {
                match backend_state::ensure_checkpoint_bound(&checkpoint, max_bytes) {
                    Ok(()) => BackendWireResponseV2::CheckpointV1 { checkpoint },
                    Err(error) => BackendWireResponseV2::StateErrorV1 {
                        error: BackendStateErrorV1::new(
                            lang,
                            "state.checkpoint-too-large",
                            format!("{error:#}"),
                        ),
                    },
                }
            }
            Err(error) => {
                if let Some(pin) = error.downcast_ref::<BackendStatePinRequired>() {
                    BackendWireResponseV2::StatePinRequiredV1 {
                        reason: BackendStateReasonV1::pin_required(
                            lang,
                            pin.path.clone(),
                            pin.message.clone(),
                        ),
                    }
                } else {
                    BackendWireResponseV2::StateErrorV1 {
                        error: BackendStateErrorV1::new(
                            lang,
                            "state.checkpoint-failed",
                            format!("{error:#}"),
                        ),
                    }
                }
            }
        }
    }

    fn restore_response(
        &mut self,
        lang: &str,
        checkpoint: BackendCheckpointV1,
    ) -> BackendWireResponseV2 {
        let result = if lang == "sql" {
            self.restore_sql(&checkpoint)
        } else {
            backend_state::validate_empty_restore(
                lang,
                self.tools.executable_set_sha256(),
                &checkpoint,
            )
        };
        match result.and_then(|()| BackendRestoreReceiptV1::restored(lang, &checkpoint)) {
            Ok(receipt) => BackendWireResponseV2::RestoreV1 { receipt },
            Err(error) => BackendWireResponseV2::StateErrorV1 {
                error: BackendStateErrorV1::new(
                    lang,
                    "state.restore-incompatible",
                    format!("{error:#}"),
                ),
            },
        }
    }

    fn sql_checkpoint(&mut self) -> Result<BackendCheckpointV1> {
        let runtime_binding = self.tools.executable_set_sha256().to_string();
        let sql = self.sql_state()?;
        if !sql.checkpoint_safe {
            return Err(anyhow::Error::new(BackendStatePinRequired {
                path: "$sql.connection".to_string(),
                message: "SQL history used transaction-, attachment-, TEMP-, PRAGMA-, extension-, or connection-local state outside the constrained main-database codec"
                    .to_string(),
            }));
        }
        let database = fs::read(&sql.db_path).with_context(|| {
            format!(
                "failed to read SQL state database {}",
                sql.db_path.display()
            )
        })?;
        BackendCheckpointV1::new(
            "sql",
            BackendStateTierV1::SemanticSnapshot,
            SQL_CLI_CODEC_V1,
            runtime_binding,
            serde_json::json!({
                "profile": "autocommit-main-only",
                "database_b64": BASE64_STANDARD.encode(database),
            }),
            Vec::new(),
        )
    }

    fn restore_sql(&mut self, checkpoint: &BackendCheckpointV1) -> Result<()> {
        checkpoint.validate()?;
        if self.sql.is_some() {
            bail!("state.restore-conflict: SQL actor already owns an open session");
        }
        if checkpoint.backend != "sql"
            || checkpoint.tier != BackendStateTierV1::SemanticSnapshot
            || checkpoint.codec != SQL_CLI_CODEC_V1
            || checkpoint.runtime_binding_sha256 != self.tools.executable_set_sha256()
            || !checkpoint.external_resources.is_empty()
        {
            bail!("SQL checkpoint is incompatible with this backend implementation");
        }
        let object = checkpoint
            .payload
            .as_object()
            .context("SQL checkpoint payload is not an object")?;
        if object.get("profile").and_then(Value::as_str) != Some("autocommit-main-only") {
            bail!("SQL checkpoint has an unsupported connection profile");
        }
        let encoded = object
            .get("database_b64")
            .and_then(Value::as_str)
            .context("SQL checkpoint omitted database_b64")?;
        let database = BASE64_STANDARD
            .decode(encoded)
            .context("SQL checkpoint database is not valid base64")?;
        let mut replacement = SqlState::spawn_with_database(&self.tools, Some(&database))?;
        let integrity = replacement.exec_untracked("PRAGMA integrity_check;")?;
        match integrity {
            OValue::Text { v } if v.utf8 == "ok" => {}
            other => bail!("SQL checkpoint failed integrity_check: {other}"),
        }
        self.sql = Some(replacement);
        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        self.cleanup()
    }

    /// End a plain block's shell and every job it left, then report the
    /// block. a plain block never shares a shell, so nothing latches: a shell
    /// killed by a signal fails only its own block.
    fn finish_plain_bash_block(&mut self, output: Output, alive: bool) -> Result<OValue> {
        self.child_pid
            .store(0, std::sync::atomic::Ordering::Relaxed);
        if let Some(mut ended) = self.bash.take() {
            ended.shutdown()?;
        }
        use std::os::unix::process::ExitStatusExt;
        if !alive {
            if let Some(signal) = output.status.signal() {
                bail!(
                    "bash session was killed by signal {signal} during this block; its state is gone"
                );
            }
            // the same words a plain block got from its own backend before.
            return output_to_value(
                "bash session ended during this block, dropping its \
                 variables, functions, and options; the next block starts \
                 a fresh session. bash",
                output,
            );
        }
        output_to_value("bash", output)
    }
}

#[derive(Debug)]
struct BackendStatePinRequired {
    path: String,
    message: String,
}

impl std::fmt::Display for BackendStatePinRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for BackendStatePinRequired {}

impl SqlState {
    fn spawn(tools: &BackendToolchain) -> Result<Self> {
        Self::spawn_with_database(tools, None)
    }

    fn spawn_with_database(tools: &BackendToolchain, database: Option<&[u8]>) -> Result<Self> {
        let dir = TempDir::new("o-backend-sql")?;
        let db_path = dir.path().join("state.sqlite3");
        match database {
            Some(database) => fs::write(&db_path, database)
                .with_context(|| format!("failed to restore sql state db {}", db_path.display()))?,
            None => {
                // Ensure the file exists so sqlite3 opens a durable on-disk DB.
                fs::File::create(&db_path).with_context(|| {
                    format!("failed to create sql state db {}", db_path.display())
                })?;
            }
        }

        let mut command = tools.command("sqlite3")?;
        let mut child = command
            .arg("-batch")
            .arg(&db_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to launch admitted sqlite3 executable")?;

        let stdin = BufWriter::new(
            child
                .stdin
                .take()
                .context("sqlite3 session did not provide stdin")?,
        );
        let stdout = BufReader::new(
            child
                .stdout
                .take()
                .context("sqlite3 session did not provide stdout")?,
        );
        let stderr = BufReader::new(
            child
                .stderr
                .take()
                .context("sqlite3 session did not provide stderr")?,
        );

        let (stderr_tx, stderr_rx): (Sender<String>, Receiver<String>) = mpsc::channel();
        thread::spawn(move || {
            let mut stderr = stderr;
            let mut line = String::new();
            while stderr.read_line(&mut line).ok().is_some_and(|n| n > 0) {
                let _ = stderr_tx.send(std::mem::take(&mut line));
            }
        });

        let stdout_rx = spawn_line_reader(stdout);
        let mut state = Self {
            _dir: dir,
            db_path,
            child,
            stdin: Some(stdin),
            stdout_rx,
            stderr_rx,
            checkpoint_safe: true,
            lost: false,
        };
        // JSON row output for SELECT/WITH/PRAGMA, matching the old -json flag.
        state.write_raw(".mode json\n")?;
        // Drain any mode-switch chatter (usually none).
        let _ = state.drain_stderr();
        Ok(state)
    }

    fn write_raw(&mut self, text: &str) -> Result<()> {
        if self.lost {
            bail!("sqlite3 session was terminated after a timeout; its state is gone");
        }
        if text.len() > crate::process::BOUNDED_WRITE_THRESHOLD {
            if let Some(limit) = crate::process::backend_step_timeout()? {
                return self.write_large(text, limit);
            }
        }
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("sqlite3 session command pipe is closed"))?;
        stdin
            .write_all(text.as_bytes())
            .context("failed to write to sqlite3 session")?;
        stdin.flush().context("failed to flush sqlite3 session")?;
        Ok(())
    }

    // why: a payload larger than the pipe buffer blocks until sqlite3 reads,
    // which it never does while a previous statement is stuck.
    #[cold]
    fn write_large(&mut self, text: &str, limit: Duration) -> Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("sqlite3 session command pipe is closed"))?;
        stdin.flush().context("failed to flush sqlite3 session")?;
        use std::os::fd::AsRawFd;
        let fd = stdin.get_ref().as_raw_fd();
        match crate::process::write_all_bounded(fd, text.as_bytes(), limit) {
            Ok(true) => Ok(()),
            Ok(false) => Err(self.kill_after_step_limit(limit, "read no input for")),
            Err(error) => {
                Err(anyhow::Error::new(error).context("failed to write to sqlite3 session"))
            }
        }
    }

    #[cold]
    fn kill_after_step_limit(&mut self, limit: Duration, what: &str) -> anyhow::Error {
        self.lost = true;
        self.stdin.take();
        let _ = self.child.kill();
        let reaped = reap_legacy_child(&mut self.child, Duration::from_secs(2));
        let limit_text = crate::process::step_limit_text(limit);
        let limit_env = crate::process::BACKEND_STEP_TIMEOUT_ENV;
        let mut message = format!(
            "backend `sql` {what} {limit_text} (opt-in per-step limit {limit_env}); sqlite3 session was killed",
        );
        if let Err(error) = reaped {
            message.push_str(&format!("; sqlite3 reap also failed: {error:#}"));
        }
        anyhow!(message)
    }

    fn shutdown(&mut self, timeout: Duration) -> Result<()> {
        self.stdin.take();
        let status = reap_legacy_child(&mut self.child, timeout)?;
        if status.success() {
            Ok(())
        } else {
            bail!("sqlite3 session exited with status {status} during shutdown")
        }
    }

    fn drain_stderr(&self) -> String {
        // Give the stderr collector a brief window after stdout completes.
        thread::sleep(Duration::from_millis(5));
        let mut acc = String::new();
        while let Ok(chunk) = self.stderr_rx.try_recv() {
            acc.push_str(&chunk);
        }
        acc
    }

    fn exec(&mut self, code: &str) -> Result<OValue> {
        if !sql_checkpoint_profile_accepts(code) {
            // This is a monotone downgrade for the current actor generation.
            // Later SQL cannot prove that an attachment, open transaction, or
            // connection-local mutation was completely undone.
            self.checkpoint_safe = false;
        }
        self.exec_untracked(code)
    }

    fn exec_untracked(&mut self, code: &str) -> Result<OValue> {
        // Clear stale stderr from prior statements.
        let _ = self.drain_stderr();

        // Feed the full block, then a sentinel print so we can delimit replies
        // without closing the session (which would lose ATTACH state).
        let mut payload = code.to_string();
        if !payload.trim_end().ends_with(';') {
            payload.push(';');
        }
        payload.push('\n');
        payload.push_str(".print __O_SQL_DONE__\n");
        self.write_raw(&payload)?;

        // without the opt-in limit the read waits as long as sqlite3 runs;
        // cancellation still ends it, because the host kills this backend's
        // whole process group, sqlite3 included.
        let limit = crate::process::backend_step_timeout()?;
        let deadline = limit.map(|limit| std::time::Instant::now() + limit);
        let mut out = String::new();
        loop {
            let received = match deadline {
                Some(deadline) => self
                    .stdout_rx
                    .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())),
                None => self
                    .stdout_rx
                    .recv()
                    .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
            };
            let line = match received {
                Ok(line) => line.context("failed to read sqlite3 session stdout")?,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let limit = limit.expect("a timeout implies a limit");
                    return Err(self.kill_after_step_limit(limit, "step exceeded"));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => String::new(),
            };
            if line.is_empty() {
                let err = self.drain_stderr();
                bail!(
                    "sqlite3 session closed unexpectedly{}",
                    if err.is_empty() {
                        String::new()
                    } else {
                        format!(": {err}")
                    }
                );
            }
            if line.trim_end_matches(['\r', '\n']) == "__O_SQL_DONE__" {
                break;
            }
            out.push_str(&line);
        }

        let err = self.drain_stderr();
        if sql_stderr_is_error(&err) {
            // Preserve the historical error envelope from the one-shot CLI path
            // so existing triage / test string matches keep working.
            bail!("sqlite3 execution failed (code 1)\n{}", err.trim_end());
        }

        let trimmed = out.trim();
        if trimmed.is_empty() {
            if sql_has_query_result(code) {
                return Ok(OValue::list(Vec::new()));
            }
            return Ok(OValue::str_("Statement executed successfully"));
        }

        let json: Value = serde_json::from_str(trimmed).context("sqlite3 returned non-JSON")?;
        sqlite_json_to_ovalue(json)
    }
}

/// Conservative profile accepted by the first SQL semantic codec.
///
/// False positives only pin a session. Missing a stateful construct would lose
/// state, so unfamiliar connection control is rejected by broad token checks.
fn sql_checkpoint_profile_accepts(code: &str) -> bool {
    let lower = code.to_ascii_lowercase();
    const PINNING_TOKENS: &[&str] = &[
        "attach",
        "detach",
        "begin",
        "commit",
        "rollback",
        "savepoint",
        "release",
        "pragma",
        " temp ",
        "temporary",
        "load_extension",
        ".load",
        ".open",
        ".restore",
        ".backup",
        "create virtual table",
        "last_insert_rowid",
        "changes(",
        "total_changes(",
        "random(",
        "randomblob(",
    ];
    !PINNING_TOKENS.iter().any(|token| lower.contains(token))
        && !lower.trim_start().starts_with('.')
        && !lower.contains("\n.")
}

/// Forward lines from `reader` over a channel; EOF ends the channel.
fn spawn_line_reader<R: io::Read + Send + 'static>(reader: R) -> Receiver<io::Result<String>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => return,
                Ok(_) => {
                    if sender.send(Ok(line)).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(error));
                    return;
                }
            }
        }
    });
    receiver
}

impl Drop for SqlState {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = reap_legacy_child(&mut self.child, Duration::from_millis(250));
    }
}

fn sql_stderr_is_error(err: &str) -> bool {
    let trimmed = err.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower.contains("error")
        || lower.contains("parse error")
        || lower.contains("incomplete sql")
        || lower.starts_with("usage:")
}

fn proxy_legacy_backend(lang: &str, tools: &BackendToolchain) -> Result<()> {
    let shim = std::env::var_os("O_BACKEND_LEGACY_SHIM")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("backend `{lang}` has no Rust adapter and no legacy shim path"))?;
    if !shim.exists() {
        bail!(
            "backend `{lang}` has no Rust adapter and legacy shim does not exist: {}",
            shim.display()
        );
    }

    let mut command = tools.command("python3")?;
    command.env(
        crate::process::BACKEND_PARENT_PID_ENV,
        std::process::id().to_string(),
    );
    let mut child = command
        .arg(&shim)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "failed to launch admitted Python executable for legacy backend shim: {}",
                shim.display()
            )
        })?;
    crate::process::lifecycle_trace(
        "proxy.shim_spawned",
        format!("language={lang} shim_pid={}", child.id()),
    );

    let child_stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => {
            let cleanup = reap_legacy_child(&mut child, Duration::from_millis(250));
            return match cleanup {
                Ok(_) => Err(anyhow!("legacy backend did not provide stdin")),
                Err(cleanup) => Err(anyhow!(
                    "legacy backend did not provide stdin; cleanup also failed: {cleanup:#}"
                )),
            };
        }
    };
    let child_stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            drop(child_stdin);
            let cleanup = reap_legacy_child(&mut child, Duration::from_millis(250));
            return match cleanup {
                Ok(_) => Err(anyhow!("legacy backend did not provide stdout")),
                Err(cleanup) => Err(anyhow!(
                    "legacy backend did not provide stdout; cleanup also failed: {cleanup:#}"
                )),
            };
        }
    };
    let mut child_stdin = Some(BufWriter::new(child_stdin));
    // why a reader thread: a grandchild of the shim can hold the shim's
    // stdout open after the shim died, so a blocking read would never see
    // eof. frames arrive over a channel and the wait polls the shim's exit.
    let (frames_tx, frames) = mpsc::channel();
    thread::Builder::new()
        .name("ostadix-proxy-reader".into())
        .spawn(move || {
            let mut child_stdout = BufReader::new(child_stdout);
            loop {
                let frame = wire::read_frame::<_, BackendWireResponseV2>(&mut child_stdout);
                let last = !matches!(frame, Ok(Some(_)));
                if frames_tx.send(frame).is_err() || last {
                    return;
                }
            }
        })
        .context("failed to create legacy backend reader")?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    while let Some(command) = wire::read_frame::<_, BackendWireCommandV2>(&mut reader)? {
        if matches!(&command, BackendWireCommandV2::Shutdown) {
            crate::process::lifecycle_trace(
                "proxy.shutdown_received",
                format!("language={lang} shim_pid={}", child.id()),
            );
            // Legacy shims already exit on command-channel EOF. The proxy owns
            // that compatibility translation, so every shim gets one uniform
            // terminal command without duplicating protocol branches.
            child_stdin.take();
            let status =
                reap_legacy_child(&mut child, crate::process::backend_shutdown_timeout()?)?;
            if !status.success() {
                wire::write_frame(
                    &mut writer,
                    &BackendWireResponseV2::err(format!(
                        "legacy backend shim exited with status {status} during shutdown"
                    )),
                )?;
                bail!("legacy backend shim exited with status {status} during shutdown");
            }
            crate::process::lifecycle_trace(
                "proxy.shim_reaped",
                format!("language={lang} shim_pid={}", child.id()),
            );
            wire::write_frame(&mut writer, &BackendWireResponseV2::ok(OValue::Null))?;
            crate::process::lifecycle_trace(
                "proxy.shutdown_acknowledged",
                format!("language={lang}"),
            );
            return Ok(());
        }

        wire::write_frame(
            child_stdin
                .as_mut()
                .context("legacy backend command pipe is closed")?,
            &command,
        )?;
        // hello and heartbeat frames are forwarded as they arrive; the
        // command's answer is the first frame that is neither.
        loop {
            let response = match frames.recv_timeout(Duration::from_millis(100)) {
                Ok(frame) => frame?
                    .ok_or_else(|| anyhow!("legacy backend shim closed stdout unexpectedly"))?,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("legacy backend shim closed stdout unexpectedly")
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(status) = child.try_wait()? {
                        // a last answer may have been read just before the exit.
                        if let Ok(Ok(Some(response))) =
                            frames.recv_timeout(Duration::from_millis(50))
                        {
                            if !matches!(
                                response,
                                BackendWireResponseV2::HeartbeatV1 { .. }
                                    | BackendWireResponseV2::HelloV1 { .. }
                            ) {
                                wire::write_frame(&mut writer, &response)?;
                                break;
                            }
                        }
                        bail!("legacy backend shim exited with status {status} during the step");
                    }
                    continue;
                }
            };
            let heartbeat = matches!(
                response,
                BackendWireResponseV2::HeartbeatV1 { .. } | BackendWireResponseV2::HelloV1 { .. }
            );
            wire::write_frame(&mut writer, &response)?;
            if !heartbeat {
                break;
            }
        }
    }

    child_stdin.take();
    let status = reap_legacy_child(&mut child, Duration::from_millis(250))?;
    if status.success() {
        Ok(())
    } else {
        bail!("legacy backend shim exited with status {status}")
    }
}

fn reap_legacy_child(child: &mut Child, grace: Duration) -> Result<std::process::ExitStatus> {
    let deadline = std::time::Instant::now()
        .checked_add(grace)
        .ok_or_else(|| anyhow!("legacy backend shutdown deadline overflowed"))?;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let forced_deadline = std::time::Instant::now()
                .checked_add(Duration::from_millis(250))
                .ok_or_else(|| anyhow!("legacy backend forced-reap deadline overflowed"))?;
            loop {
                if let Some(status) = child.try_wait()? {
                    return Ok(status);
                }
                if std::time::Instant::now() >= forced_deadline {
                    bail!(
                        "legacy backend shim {} did not become waitable after termination",
                        child.id()
                    );
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn run_shell(
    tools: &BackendToolchain,
    program: &str,
    args: &[&str],
    env: Option<HashMap<String, String>>,
) -> Result<OValue> {
    let mut command = tools.command(program)?;
    command.args(args);
    if let Some(env) = env {
        command.envs(env);
    }
    output_to_value(
        program,
        command
            .output()
            .with_context(|| format!("failed to launch admitted `{program}` executable"))?,
    )
}

fn run_script(
    tools: &BackendToolchain,
    lang: &str,
    program: &str,
    suffix: &str,
    preamble: &str,
    code: &str,
) -> Result<OValue> {
    let temp = TempDir::new("o-backend-script")?;
    let source = temp.path().join(format!("main.{suffix}"));
    let mut source_file = fs::File::create(&source)?;
    source_file.write_all(preamble.as_bytes())?;
    source_file.write_all(code.as_bytes())?;
    drop(source_file);
    let mut command = tools.command(program)?;
    output_to_value(
        lang,
        command
            .arg(&source)
            .output()
            .with_context(|| format!("failed to launch admitted `{program}` executable"))?,
    )
}

// A dedicated inherited socket carries callbacks; ordinary stdout/stderr keep
// their existing meanings and can contain arbitrary bytes without impersonating
// protocol frames. The parent evaluator remains the operation coordinator.
#[cfg(unix)]
fn run_javascript_native_bridge(
    tools: &BackendToolchain,
    code: &str,
    bindings: &HashMap<String, OValue>,
    host_input: &mut impl io::Read,
    host_output: &mut impl Write,
) -> Result<OValue> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    let temp = TempDir::new("o-native-javascript")?;
    let source = temp.path().join("main.js");
    fs::write(
        &source,
        format!(
            "{JAVASCRIPT_NATIVE_BRIDGE}\n{}\n{code}",
            javascript_preamble(bindings)
        ),
    )?;
    let (socket, child_socket) = UnixStream::pair()?;
    let child_fd = child_socket.as_raw_fd();
    let mut command = tools.command("node")?;
    command
        .arg(source)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: dup2/fcntl are async-signal-safe; no allocation or locks in the
    // child hook. FD3 is reserved only in this child's native bridge process.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(child_fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    drop(child_socket);
    let output = thread::spawn(move || child.wait_with_output());
    let mut socket_reader = BufReader::new(socket.try_clone()?);
    let mut socket_writer = socket;
    let bridge = (|| -> Result<()> {
        loop {
            use std::io::Read as _;
            let mut line = Vec::new();
            let read = (&mut socket_reader)
                .take(16 * 1024 * 1024 + 1)
                .read_until(b'\n', &mut line)?;
            if read == 0 {
                return Ok(());
            }
            if read > 16 * 1024 * 1024 || line.last() != Some(&b'\n') {
                bail!("native.request-too-large: JavaScript bridge frame exceeds 16 MiB");
            }
            let request: BackendWireResponseV2 = serde_json::from_slice(&line)?;
            if !matches!(request, BackendWireResponseV2::EvalRequest { .. }) {
                bail!("native.invalid-request: bridge accepts only evaluator callbacks");
            }
            wire::write_frame(host_output, &request)?;
            let response = wire::read_frame::<_, BackendWireCommandV2>(host_input)?
                .context("native.coordinator-closed: callback did not receive a result")?;
            let BackendWireCommandV2::EvalResult { value } = response else {
                bail!("native.invalid-response: callback expected eval_result");
            };
            serde_json::to_writer(&mut socket_writer, &value)?;
            socket_writer.write_all(b"\n")?;
        }
    })();
    // EOF also wakes a consumer blocked on an operation when the coordinator
    // rejects a frame. The outer owned process group/deadline handles programs
    // that deliberately ignore that failure or retain a duplicate socket.
    let _ = socket_writer.shutdown(std::net::Shutdown::Both);
    let result = output
        .join()
        .map_err(|_| anyhow!("JavaScript output reader panicked"))??;
    bridge?;
    output_to_value("javascript", result)
}

#[cfg(not(unix))]
fn run_javascript_native_bridge(
    _tools: &BackendToolchain,
    _code: &str,
    _bindings: &HashMap<String, OValue>,
    _host_input: &mut impl io::Read,
    _host_output: &mut impl Write,
) -> Result<OValue> {
    bail!(
        "native.unsupported-transport: JavaScript owner operations currently require Unix sockets"
    )
}

const JAVASCRIPT_NATIVE_BRIDGE: &str = r#"
(() => {
  const fs = require('fs');
  const wire = (value, seen = new Set(), depth = 0) => {
    if (depth > 64) throw Error('native.argument-depth');
    if (value === null) return {t:'null'};
    if (typeof value === 'boolean') return {t:'bool',v:value};
    if (typeof value === 'string') return {t:'text',v:{utf8:value,encoding:'utf-8'}};
    if (typeof value === 'bigint') return {t:'number',v:{kind:'int',v:value.toString()}};
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw Error('native.nonfinite-argument');
      if (Number.isSafeInteger(value) && !Object.is(value,-0))
        return {t:'number',v:{kind:'int',v:value.toString()}};
      const bits=Buffer.alloc(8); bits.writeDoubleBE(value);
      return {t:'number',v:{kind:'binary_float',format:'f64',bits:[...bits]}};
    }
    if (typeof value !== 'object') throw Error('native.unsupported-argument');
    if (value.t === 'native') return value;
    if (seen.has(value)) throw Error('native.aliased-argument: pass a native handle for identity');
    seen.add(value);
    if (Array.isArray(value)) return {t:'list',v:value.map(v=>wire(v,seen,depth+1))};
    if (![Object.prototype,null].includes(Object.getPrototypeOf(value))) throw Error('native.unsupported-argument');
    const result={};
    for (const key of Reflect.ownKeys(value)) {
      const entry=Object.getOwnPropertyDescriptor(value,key);
      if (typeof key!=='string' || !('value' in entry)) throw Error('native.unsupported-argument');
      Object.defineProperty(result,key,{value:wire(entry.value,seen,depth+1),enumerable:true});
    }
    return {t:'map',v:result};
  };
  const lift = value => {
    if (value.t==='error') throw Error(value.msg);
    if (value.t==='native') return value;
    if (value.t==='null') return null;
    if (value.t==='bool') return value.v;
    if (value.t==='text') return value.v.utf8;
    if (value.t==='number' && value.v.kind==='int') {
      const n=BigInt(value.v.v); return n>=BigInt(Number.MIN_SAFE_INTEGER)&&n<=BigInt(Number.MAX_SAFE_INTEGER)?Number(n):n;
    }
    if (value.t==='number' && value.v.kind==='binary_float' && value.v.format==='f64')
      return Buffer.from(value.v.bits).readDoubleBE();
    throw Error('native.unsupported-result');
  };
  const invoke=(name,bindings) => {
    const names=Object.keys(bindings), scope={};
    for(const key of names) scope[key]=wire(bindings[key]);
    const request={status:'eval_request',src:name+'('+names.map(n=>'$'+n).join(',')+')',scope:{t:'scope',bindings:scope}};
    const encoded=Buffer.from(JSON.stringify(request)+'\n');
    if(encoded.length>16*1024*1024) throw Error('native.request-too-large');
    let offset=0; while(offset<encoded.length) offset+=fs.writeSync(3,encoded,offset);
    const bytes=[], byte=Buffer.alloc(1);
    while(true) {
      if(fs.readSync(3,byte,0,1,null)===0) throw Error('native.coordinator-closed');
      if(byte[0]===10) break;
      if(bytes.length>=16*1024*1024) throw Error('native.response-too-large');
      bytes.push(byte[0]);
    }
    return lift(JSON.parse(Buffer.from(bytes).toString('utf8')));
  };
  globalThis.O=Object.freeze({
    native_call:(handle,...args)=>invoke('native_call',{handle,args}),
    native_get:(handle,name)=>invoke('native_get',{handle,name}),
    native_set:(handle,name,value)=>invoke('native_set',{handle,name,value}),
    native_release:handle=>invoke('native_release',{handle})
  });
})();
"#;

fn run_file_command(
    tools: &BackendToolchain,
    label: &str,
    program: &str,
    suffix: &str,
    code: &str,
    args: &[&str],
) -> Result<OValue> {
    let temp = TempDir::new("o-backend-file")?;
    let source = temp.path().join(format!("main.{suffix}"));
    fs::write(&source, code)?;
    let source_text = source.to_string_lossy();
    let mut command = tools.command(program)?;
    for arg in args {
        if *arg == "{file}" {
            command.arg(source_text.as_ref());
        } else {
            command.arg(arg);
        }
    }
    output_to_value(
        label,
        command
            .output()
            .with_context(|| format!("failed to launch admitted `{program}` executable"))?,
    )
}

fn run_rust(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let temp = TempDir::new("o-backend-rust")?;
    let source = temp.path().join("main.rs");
    let binary = temp.path().join("main");
    fs::write(&source, code)?;
    let mut compiler = tools.command("rustc")?;
    expect_success(
        "rustc compilation failed",
        &compiler
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .context("failed to launch admitted rustc executable")?,
    )?;
    output_to_value(
        "rust program",
        Command::new(&binary)
            .output()
            .context("failed to execute compiled Rust program")?,
    )
}

fn run_c(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let temp = TempDir::new("o-backend-c")?;
    let source = temp.path().join("main.c");
    let binary = temp.path().join("main");
    fs::write(&source, code)?;
    let mut compiler = tools.command("cc")?;
    expect_success(
        "cc compilation failed",
        &compiler
            .arg("-std=c17")
            .arg("-o")
            .arg(&binary)
            .arg(&source)
            .output()
            .context("failed to launch admitted cc executable")?,
    )?;
    output_to_value(
        "C program",
        Command::new(&binary)
            .output()
            .context("failed to execute compiled C program")?,
    )
}

fn run_cpp(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let temp = TempDir::new("o-backend-cpp")?;
    let source = temp.path().join("main.cpp");
    let binary = temp.path().join("main");
    fs::write(&source, code)?;
    let mut compiler = tools.command("g++")?;
    expect_success(
        "g++ compilation failed",
        &compiler
            .arg("-std=c++17")
            .arg("-o")
            .arg(&binary)
            .arg(&source)
            .output()
            .context("failed to launch admitted g++ executable")?,
    )?;
    output_to_value(
        "C++ program",
        Command::new(&binary)
            .output()
            .context("failed to execute compiled C++ program")?,
    )
}

fn run_java(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let temp = TempDir::new("o-backend-java")?;
    let class_name = java_class_name(code);
    let source = temp.path().join(format!("{class_name}.java"));
    fs::write(&source, code)?;
    let mut compiler = tools.command("javac")?;
    expect_success(
        "javac compilation failed",
        &compiler
            .arg(&source)
            .output()
            .context("failed to launch admitted javac executable")?,
    )?;
    let mut runtime = tools.command("java")?;
    output_to_value(
        "java",
        runtime
            .arg("-cp")
            .arg(temp.path())
            .arg(class_name)
            .output()
            .context("failed to launch admitted java executable")?,
    )
}

fn run_nix(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let mut command = tools.command("nix")?;
    let output = command
        .args([
            "--extra-experimental-features",
            "nix-command",
            "eval",
            "--json",
            "--impure",
            "--expr",
            code,
        ])
        .output()
        .context("failed to launch admitted nix executable")?;
    expect_success("nix eval failed", &output)?;
    let json: Value =
        serde_json::from_slice(&output.stdout).context("nix eval returned non-JSON")?;
    json_value_to_ovalue(json)
}

fn run_nix_store(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let mut command = tools.command("nix")?;
    let output = command
        .args([
            "--extra-experimental-features",
            "nix-command",
            "eval",
            "--raw",
            "--impure",
            "--expr",
            code,
        ])
        .output()
        .context("failed to launch admitted nix executable")?;
    expect_success("nix eval --raw failed", &output)?;
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !path.starts_with("/nix/store/") {
        bail!("expression did not evaluate to a Nix store path: {path:?}");
    }
    Ok(OValue::store_path(path))
}

fn run_haskell(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let temp = TempDir::new("o-backend-haskell")?;
    let source = temp.path().join("Main.hs");
    fs::write(&source, code)?;
    if tools.contains("runghc") {
        let mut command = tools.command("runghc")?;
        return output_to_value(
            "Haskell",
            command
                .arg(&source)
                .output()
                .context("failed to launch admitted runghc executable")?,
        );
    }
    if tools.contains("ghc") {
        let binary = temp.path().join("Main");
        let mut compiler = tools.command("ghc")?;
        expect_success(
            "ghc compilation failed",
            &compiler
                .arg("-o")
                .arg(&binary)
                .arg(&source)
                .output()
                .context("failed to launch admitted ghc executable")?,
        )?;
        return output_to_value(
            "Haskell",
            Command::new(&binary)
                .output()
                .context("failed to execute compiled Haskell program")?,
        );
    }
    bail!("admitted Haskell runtime alternative contains neither `runghc` nor `ghc`")
}

fn run_ocaml(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let temp = TempDir::new("o-backend-ocaml")?;
    let source = temp.path().join("main.ml");
    fs::write(&source, code)?;
    if tools.contains("ocaml") {
        let mut command = tools.command("ocaml")?;
        return output_to_value(
            "OCaml",
            command
                .arg(&source)
                .output()
                .context("failed to launch admitted ocaml executable")?,
        );
    }
    let compiler = if tools.contains("ocamlopt") {
        Some("ocamlopt")
    } else if tools.contains("ocamlc") {
        Some("ocamlc")
    } else {
        None
    };
    let Some(compiler) = compiler else {
        bail!("admitted OCaml runtime alternative contains no supported executable");
    };
    let binary = temp.path().join("main");
    let mut compiler_command = tools.command(compiler)?;
    expect_success(
        format!("{compiler} compilation failed"),
        &compiler_command
            .arg("-o")
            .arg(&binary)
            .arg(&source)
            .output()
            .with_context(|| format!("failed to launch admitted {compiler} executable"))?,
    )?;
    output_to_value(
        "OCaml",
        Command::new(&binary)
            .output()
            .context("failed to execute compiled OCaml program")?,
    )
}

fn run_common_lisp(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let temp = TempDir::new("o-backend-lisp")?;
    let source = temp.path().join("main.lisp");
    fs::write(&source, code)?;
    if tools.contains("sbcl") {
        let mut command = tools.command("sbcl")?;
        return output_to_value(
            "Common Lisp",
            command
                .arg("--script")
                .arg(&source)
                .output()
                .context("failed to launch admitted sbcl executable")?,
        );
    }
    if tools.contains("clisp") {
        let mut command = tools.command("clisp")?;
        return output_to_value(
            "Common Lisp",
            command
                .arg(&source)
                .output()
                .context("failed to launch admitted clisp executable")?,
        );
    }
    bail!("admitted Common Lisp runtime alternative contains neither `sbcl` nor `clisp`")
}

fn run_csharp(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let temp = TempDir::new("o-backend-csharp")?;
    if tools.contains("dotnet") {
        let mut project_command = tools.command("dotnet")?;
        // Build servers must not outlive this task's owned process group.
        project_command
            .env("MSBUILDDISABLENODEREUSE", "1")
            .env("DOTNET_CLI_USE_MSBUILD_SERVER", "0")
            .env("UseSharedCompilation", "false");
        expect_success(
            "dotnet project creation failed",
            &project_command
                .args(["new", "console", "--force", "-o"])
                .arg(temp.path())
                .output()
                .context("failed to launch admitted dotnet executable")?,
        )?;
        fs::write(temp.path().join("Program.cs"), code)?;
        let mut run_command = tools.command("dotnet")?;
        run_command
            .env("MSBUILDDISABLENODEREUSE", "1")
            .env("DOTNET_CLI_USE_MSBUILD_SERVER", "0")
            .env("UseSharedCompilation", "false");
        return output_to_value(
            "C#",
            run_command
                .arg("run")
                .arg("--project")
                .arg(temp.path())
                .output()
                .context("failed to launch admitted dotnet executable for `dotnet run`")?,
        );
    }
    if tools.contains("mcs") && tools.contains("mono") {
        let source = temp.path().join("Program.cs");
        let binary = temp.path().join("Program.exe");
        fs::write(&source, code)?;
        let mut compiler = tools.command("mcs")?;
        expect_success(
            "mcs compilation failed",
            &compiler
                .arg(format!("-out:{}", binary.display()))
                .arg(&source)
                .output()
                .context("failed to launch admitted mcs executable")?,
        )?;
        let mut runtime = tools.command("mono")?;
        return output_to_value(
            "C#",
            runtime
                .arg(&binary)
                .output()
                .context("failed to launch admitted mono executable")?,
        );
    }
    bail!("admitted C# runtime alternative is neither `dotnet` nor `mcs + mono`")
}

fn run_matlab(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let temp = TempDir::new("o-backend-matlab")?;
    let source = temp.path().join("script.m");
    fs::write(&source, code)?;
    if tools.contains("octave") {
        let mut command = tools.command("octave")?;
        return output_to_value(
            "MATLAB/Octave",
            command
                .args(["--no-gui", "--norc", "--silent"])
                .arg(&source)
                .output()
                .context("failed to launch admitted octave executable")?,
        );
    }
    if tools.contains("matlab") {
        let script_dir = temp.path().to_string_lossy();
        let mut command = tools.command("matlab")?;
        return output_to_value(
            "MATLAB",
            command
                .arg("-batch")
                .arg(format!("addpath('{script_dir}'); script"))
                .output()
                .context("failed to launch admitted matlab executable")?,
        );
    }
    bail!("admitted MATLAB runtime alternative contains neither `octave` nor `matlab`")
}

fn run_mathematica(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    run_file_command(
        tools,
        "Mathematica",
        "wolframscript",
        "wls",
        code,
        &["-file", "{file}"],
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WebAssemblyTextConverter {
    Wat2Wasm,
    WasmTools,
}

impl WebAssemblyTextConverter {
    const fn logical_command(self) -> &'static str {
        match self {
            Self::Wat2Wasm => "wat2wasm",
            Self::WasmTools => "wasm-tools",
        }
    }

    const fn failure_label(self) -> &'static str {
        match self {
            Self::Wat2Wasm => "wat2wasm failed",
            Self::WasmTools => "wasm-tools parse failed",
        }
    }

    fn configure(self, command: &mut Command, wat: &Path, wasm: &Path) {
        match self {
            Self::Wat2Wasm => {
                command.arg(wat).arg("-o").arg(wasm);
            }
            Self::WasmTools => {
                command.arg("parse").arg(wat).arg("-o").arg(wasm);
            }
        }
    }
}

fn select_webassembly_text_converter(
    has_wat2wasm: bool,
    has_wasm_tools: bool,
) -> Result<WebAssemblyTextConverter> {
    if has_wat2wasm {
        Ok(WebAssemblyTextConverter::Wat2Wasm)
    } else if has_wasm_tools {
        Ok(WebAssemblyTextConverter::WasmTools)
    } else {
        bail!("admitted WebAssembly alternative contains no WAT text converter")
    }
}

fn run_webassembly(tools: &BackendToolchain, code: &str) -> Result<OValue> {
    let temp = TempDir::new("o-backend-wasm")?;
    let wasm = temp.path().join("module.wasm");
    if code.trim_start().starts_with("(module") || code.trim_start().starts_with("(func") {
        let wat = temp.path().join("module.wat");
        fs::write(&wat, code)?;
        let converter_kind = select_webassembly_text_converter(
            tools.contains("wat2wasm"),
            tools.contains("wasm-tools"),
        )?;
        let converter_name = converter_kind.logical_command();
        let mut converter = tools.command(converter_name)?;
        converter_kind.configure(&mut converter, &wat, &wasm);
        expect_success(
            converter_kind.failure_label(),
            &converter.output().with_context(|| {
                format!("failed to launch admitted {converter_name} executable")
            })?,
        )?;
    } else {
        fs::write(&wasm, code.as_bytes())?;
    }

    if tools.contains("wasmtime") {
        let mut command = tools.command("wasmtime")?;
        return output_to_value(
            "wasmtime",
            command
                .arg(&wasm)
                .output()
                .context("failed to launch admitted wasmtime executable")?,
        );
    }
    if tools.contains("wasmer") {
        let mut command = tools.command("wasmer")?;
        return output_to_value(
            "wasmer",
            command
                .arg("run")
                .arg(&wasm)
                .output()
                .context("failed to launch admitted wasmer executable")?,
        );
    }
    bail!("admitted WebAssembly runtime alternative contains neither `wasmtime` nor `wasmer`")
}

fn output_to_value(label: &str, output: Output) -> Result<OValue> {
    expect_success(format!("{label} exited with failure"), &output)?;
    let stdout = match String::from_utf8(output.stdout) {
        Ok(stdout) => stdout,
        Err(error) => String::from_utf8_lossy(&error.into_bytes()).into_owned(),
    };
    Ok(stdout_to_ovalue(stdout))
}

fn expect_success(label: impl AsRef<str>, output: &Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let code = output
        .status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "signal".to_string());
    if stdout.trim().is_empty() {
        bail!("{} (code {code})\n{}", label.as_ref(), stderr.trim());
    }
    bail!(
        "{} (code {code})\nSTDERR:\n{}\nSTDOUT:\n{}",
        label.as_ref(),
        stderr.trim(),
        stdout.trim()
    )
}

fn stdout_to_ovalue(mut text: String) -> OValue {
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    let stripped = text.trim();
    if !stripped.is_empty() {
        if let Ok(json) = serde_json::from_str::<Value>(stripped) {
            if let Ok(value) = json_value_to_ovalue(json) {
                return value;
            }
        }

        if is_integer_literal(stripped) {
            if let Ok(int) = stripped.parse::<i64>() {
                return OValue::int(int);
            }
            if let Some(big) = BigInt::parse_bytes(stripped.as_bytes(), 10) {
                return OValue::big_int(big);
            }
        }

        if is_float_literal(stripped) {
            if let Ok(float) = stripped.parse::<f64>() {
                return float_to_ovalue(float);
            }
        }
    }
    OValue::str_(text)
}

fn json_value_to_ovalue(value: Value) -> Result<OValue> {
    Ok(match value {
        Value::Null => OValue::Null,
        Value::Bool(v) => OValue::bool_(v),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                OValue::int(value)
            } else if let Some(value) = number.as_u64() {
                match i64::try_from(value) {
                    Ok(value) => OValue::int(value),
                    Err(_) => OValue::big_int(BigInt::from(value)),
                }
            } else if let Some(value) = number.as_f64() {
                float_to_ovalue(value)
            } else {
                OValue::str_(number.to_string())
            }
        }
        Value::String(v) => OValue::str_(v),
        Value::Array(values) => OValue::list(
            values
                .into_iter()
                .map(json_value_to_ovalue)
                .collect::<Result<Vec<_>>>()?,
        ),
        Value::Object(map) => {
            let tagged = map
                .get("t")
                .and_then(Value::as_str)
                .is_some_and(|tag| !tag.is_empty());
            let value = Value::Object(map);
            if tagged {
                serde_json::from_value(value).context("tagged JSON is not a valid OValue")?
            } else if let Value::Object(map) = value {
                OValue::map(
                    map.into_iter()
                        .map(|(key, value)| Ok((key, json_value_to_ovalue(value)?)))
                        .collect::<Result<HashMap<_, _>>>()?,
                )
            } else {
                unreachable!()
            }
        }
    })
}

fn sqlite_json_to_ovalue(value: Value) -> Result<OValue> {
    let Value::Array(rows) = value else {
        return json_value_to_ovalue(value);
    };
    if rows.len() == 1 {
        if let Some(object) = rows[0].as_object() {
            if object.len() == 1 {
                if let Some((_, value)) = object.iter().next() {
                    return json_value_to_ovalue(value.clone());
                }
            }
        }
    }
    json_value_to_ovalue(Value::Array(rows))
}

fn sql_has_query_result(code: &str) -> bool {
    code.split(';')
        .map(str::trim)
        .rfind(|stmt| !stmt.is_empty())
        .is_some_and(|stmt| {
            let upper = stmt
                .chars()
                .take_while(|ch| !ch.is_whitespace() && *ch != '(')
                .collect::<String>()
                .to_ascii_uppercase();
            matches!(upper.as_str(), "SELECT" | "WITH" | "PRAGMA")
        })
}

fn float_to_ovalue(value: f64) -> OValue {
    if value.is_finite() {
        OValue::float(value)
    } else {
        OValue::number(ONumber::BinaryFloat {
            format: FloatFormat::F64,
            bits: value.to_bits().to_be_bytes().to_vec(),
        })
    }
}

fn is_integer_literal(value: &str) -> bool {
    let rest = value
        .strip_prefix('+')
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or(value);
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

fn is_float_literal(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    (lower.contains('.') || lower.contains('e')) && lower.parse::<f64>().is_ok()
}

fn scalar_env(bindings: HashMap<String, OValue>) -> HashMap<String, String> {
    bindings
        .into_iter()
        .filter_map(|(name, value)| scalar_string(&value).map(|value| (name, value)))
        .collect()
}

fn scalar_string(value: &OValue) -> Option<String> {
    match value {
        OValue::Text {
            v: crate::value::OText { utf8: v, .. },
        } => Some(v.clone()),
        OValue::Number { v } => number_scalar_string(v),
        OValue::Bool { v } => Some(v.to_string()),
        _ => None,
    }
}

fn number_scalar_string(value: &ONumber) -> Option<String> {
    match value {
        ONumber::Int { v } => Some(v.to_string()),
        ONumber::BinaryFloat {
            format: FloatFormat::F32,
            bits,
        } if bits.len() == 4 => {
            let mut raw = [0_u8; 4];
            raw.copy_from_slice(bits);
            let value = f32::from_bits(u32::from_be_bytes(raw)) as f64;
            value.is_finite().then(|| value.to_string())
        }
        ONumber::BinaryFloat {
            format: FloatFormat::F64,
            bits,
        } if bits.len() == 8 => {
            let mut raw = [0_u8; 8];
            raw.copy_from_slice(bits);
            let value = f64::from_bits(u64::from_be_bytes(raw));
            value.is_finite().then(|| value.to_string())
        }
        _ => None,
    }
}

fn javascript_preamble(bindings: &HashMap<String, OValue>) -> String {
    let mut preamble = String::new();
    for (name, value) in bindings {
        if !is_identifier(name) {
            continue;
        }
        match value {
            OValue::Text { v } => {
                preamble.push_str(&format!(
                    "const {name} = {};\n",
                    serde_json::to_string(&v.utf8).unwrap_or_else(|_| "null".to_string())
                ));
            }
            OValue::Number { v } => {
                if let Some(value) = number_scalar_string(v) {
                    preamble.push_str(&format!("const {name} = {value};\n"));
                }
            }
            OValue::Bool { v } => {
                preamble.push_str(&format!(
                    "const {name} = {};\n",
                    if *v { "true" } else { "false" }
                ));
            }
            OValue::Null => preamble.push_str(&format!("const {name} = null;\n")),
            OValue::List { v } => push_json_const(&mut preamble, name, v),
            OValue::Map { v } => push_json_const(&mut preamble, name, v),
            OValue::Native { .. } => push_json_const(&mut preamble, name, value),
            _ => {}
        }
    }
    preamble
}

fn push_json_const<T: serde::Serialize>(preamble: &mut String, name: &str, value: &T) {
    if let Ok(json) = serde_json::to_string(value) {
        preamble.push_str(&format!("const {name} = {json};\n"));
    }
}

fn ruby_preamble(bindings: &HashMap<String, OValue>) -> String {
    let mut preamble = String::new();
    for (name, value) in bindings {
        if !is_identifier(name) {
            continue;
        }
        match value {
            OValue::Text { v } => {
                preamble.push_str(&format!(
                    "{name} = {}\n",
                    serde_json::to_string(&v.utf8).unwrap_or_else(|_| "nil".to_string())
                ));
            }
            OValue::Number { v } => {
                if let Some(value) = number_scalar_string(v) {
                    preamble.push_str(&format!("{name} = {value}\n"));
                }
            }
            OValue::Bool { v } => {
                preamble.push_str(&format!("{name} = {}\n", if *v { "true" } else { "false" }));
            }
            OValue::Null => preamble.push_str(&format!("{name} = nil\n")),
            _ => {}
        }
    }
    preamble
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn java_class_name(code: &str) -> String {
    find_class_after(code, "public class")
        .or_else(|| find_class_after(code, "class"))
        .unwrap_or_else(|| "Main".to_string())
}

fn find_class_after(code: &str, marker: &str) -> Option<String> {
    let idx = code.find(marker)?;
    let after = &code[idx + marker.len()..];
    let name = after.split_whitespace().next()?;
    let name = name
        .chars()
        .take_while(|ch| *ch == '_' || ch.is_ascii_alphanumeric())
        .collect::<String>();
    (!name.is_empty()).then_some(name)
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// A fresh directory only this user can enter: block files hold user code.
    /// the name is random and `create` refuses an existing path, symlinks
    /// included, so honouring TMPDIR cannot hand the files to someone else.
    fn new(prefix: &str) -> Result<Self> {
        let base = std::env::temp_dir();
        let mut builder = fs::DirBuilder::new();
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        for _ in 0..16 {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).map_err(|error| anyhow!("{error}"))?;
            let path = base.join(format!(
                "{prefix}-{}-{}",
                std::process::id(),
                hex::encode(random)
            ));
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error).context("failed to create backend temp dir"),
            }
        }
        bail!("failed to create unique backend temp dir")
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {

    // the /proc scan that stands in for missing children files finds the
    // same child as the children files do.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_children_scan_fallback_finds_what_the_children_files_list() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let listed = super::children_of(None).unwrap();
        let scanned = super::children_by_scan(std::process::id() as i32).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(listed.contains(&pid), "{listed:?}");
        assert!(scanned.contains(&pid), "{scanned:?}");
    }

    // 08c-M2: a job snapshot that cannot be read must not stop the SIGTERM
    // walk. the walk still kills the setsid job, reports the failure, and
    // exits 143; nothing panics. it runs in a child copy of this test
    // binary, because the walk reaps every child of its process and exits.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_job_snapshot_still_stops_the_jobs_on_sigterm() {
        use std::time::{Duration, Instant};
        const CHILD: &str = "O_TEST_FAILED_SNAPSHOT_CHILD";
        if let Some(pidfile) = std::env::var_os(CHILD) {
            super::become_bash_subreaper().unwrap();
            let pidfile = std::path::PathBuf::from(pidfile);
            let status = std::process::Command::new("bash")
                .arg("-c")
                .arg(format!(
                    "setsid sleep 7996 >/dev/null 2>&1 </dev/null & echo $! > {}",
                    pidfile.display()
                ))
                .status()
                .unwrap();
            assert!(status.success());
            // bash has exited, so the setsid job is now this process's child.
            super::FAIL_SNAPSHOT.store(true, std::sync::atomic::Ordering::SeqCst);
            super::terminate_bash_now();
        }
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("job.pid");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::tests::a_failed_job_snapshot_still_stops_the_jobs_on_sigterm",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, &pidfile)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > Duration::from_secs(20) {
                let _ = child.kill();
                panic!("the SIGTERM walk did not exit");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut stderr = String::new();
        std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
        let job: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let alive = |pid: i32| {
            std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().next())
                    .is_some_and(|state| state != "Z" && state != "X")
            })
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(job) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let survived = alive(job);
        if survived {
            // SAFETY: the test stops the job its child started.
            unsafe { libc::kill(job, libc::SIGKILL) };
        }
        assert!(!stderr.contains("panicked"), "the walk panicked: {stderr}");
        assert!(
            !survived,
            "the setsid job {job} outlived the SIGTERM walk: {stderr}"
        );
        assert_eq!(status.code(), Some(128 + libc::SIGTERM), "{stderr}");
        assert!(
            stderr.contains("bash job cleanup failed: cannot list the jobs"),
            "{stderr}"
        );
    }

    #[test]
    fn backend_temp_dirs_are_private_and_unpredictable() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let first = super::TempDir::new("o-backend-mode-test")?;
        let second = super::TempDir::new("o-backend-mode-test")?;
        let mode = std::fs::metadata(first.path())?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "backend temp dir is {mode:o}");
        // the random part is 32 hex digits, so a planted name cannot be guessed.
        let name = first
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let random = name.rsplit('-').next().unwrap();
        assert_eq!(random.len(), 32, "{name}");
        assert_ne!(first.path(), second.path());
        Ok(())
    }

    #[test]
    fn sqlite_session_read_is_bounded_by_the_step_limit() -> anyhow::Result<()> {
        // y-d-08: the session read_line had no bound; a stuck statement hung
        // the backend forever. a stand-in child that never answers plays a
        // locked sqlite3.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            crate::process::set_step_timeout_override(Some(std::time::Duration::from_millis(300)));
            let outcome = (|| -> anyhow::Result<()> {
                let dir = super::TempDir::new("o-backend-sql-test")?;
                let mut child = std::process::Command::new("sh")
                    .args(["-c", "exec sleep 5"])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?;
                let stdin = std::io::BufWriter::new(child.stdin.take().unwrap());
                let stdout_rx = super::spawn_line_reader(child.stdout.take().unwrap());
                let (_stderr_tx, stderr_rx) = std::sync::mpsc::channel();
                let mut state = super::SqlState {
                    db_path: dir.path().join("state.sqlite3"),
                    _dir: dir,
                    child,
                    stdin: Some(stdin),
                    stdout_rx,
                    stderr_rx,
                    checkpoint_safe: true,
                    lost: false,
                };
                let error = state
                    .exec("SELECT 1;")
                    .expect_err("a silent sqlite3 must not hang");
                assert!(
                    format!("{error:#}").contains(
                        "step exceeded 300 ms (opt-in per-step limit O_BACKEND_STEP_TIMEOUT_MS)"
                    ),
                    "{error:#}"
                );
                let error = state
                    .exec("SELECT 1;")
                    .expect_err("a killed session must stay dead");
                assert!(
                    format!("{error:#}").contains("its state is gone"),
                    "{error:#}"
                );
                Ok(())
            })();
            let _ = done_tx.send(outcome);
        });
        match done_rx.recv_timeout(std::time::Duration::from_secs(20)) {
            Ok(outcome) => outcome,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("sqlite session read hung past the per-step limit")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("test body panicked; see the assertion above")
            }
        }
    }

    use std::path::Path;
    use std::process::Command;

    use super::{
        has_native_backend, select_webassembly_text_converter, sql_checkpoint_profile_accepts,
        stdout_to_ovalue, WebAssemblyTextConverter,
    };
    use crate::value::OValue;

    #[test]
    fn webassembly_text_converter_selection_and_argv_are_fail_closed() {
        assert_eq!(
            select_webassembly_text_converter(true, true).unwrap(),
            WebAssemblyTextConverter::Wat2Wasm
        );
        assert_eq!(
            select_webassembly_text_converter(false, true).unwrap(),
            WebAssemblyTextConverter::WasmTools
        );
        assert!(select_webassembly_text_converter(false, false)
            .unwrap_err()
            .to_string()
            .contains("no WAT text converter"));

        let wat = Path::new("module.wat");
        let wasm = Path::new("module.wasm");
        let mut wabt = Command::new("wat2wasm");
        WebAssemblyTextConverter::Wat2Wasm.configure(&mut wabt, wat, wasm);
        assert_eq!(
            wabt.get_args().collect::<Vec<_>>(),
            [wat.as_os_str(), "-o".as_ref(), wasm.as_os_str()]
        );

        let mut wasm_tools = Command::new("wasm-tools");
        WebAssemblyTextConverter::WasmTools.configure(&mut wasm_tools, wat, wasm);
        assert_eq!(
            wasm_tools.get_args().collect::<Vec<_>>(),
            [
                "parse".as_ref(),
                wat.as_os_str(),
                "-o".as_ref(),
                wasm.as_os_str(),
            ]
        );
    }

    #[test]
    fn sql_checkpoint_profile_is_portable_only_for_main_autocommit_state() {
        assert!(sql_checkpoint_profile_accepts(
            "CREATE TABLE items(value INTEGER); INSERT INTO items VALUES (42);"
        ));
        assert!(sql_checkpoint_profile_accepts(
            "SELECT value FROM items ORDER BY value;"
        ));
        for source in [
            "ATTACH DATABASE 'other.db' AS other;",
            "BEGIN; INSERT INTO items VALUES (1);",
            "CREATE TEMP TABLE transient(value INTEGER);",
            "PRAGMA foreign_keys = ON;",
            "SELECT last_insert_rowid();",
            ".load './extension'",
        ] {
            assert!(!sql_checkpoint_profile_accepts(source), "{source}");
        }
    }

    #[test]
    fn stdout_conversion_preserves_text_and_terminal_newline_semantics() {
        assert_eq!(stdout_to_ovalue("42\n".into()), OValue::int(42));
        assert_eq!(
            stdout_to_ovalue("  plain text  \r\n".into()),
            OValue::str_("  plain text  ")
        );
        assert_eq!(
            stdout_to_ovalue("plain text\n\n".into()),
            OValue::str_("plain text\n")
        );
        assert_eq!(stdout_to_ovalue("\n".into()), OValue::str_(""));
    }

    #[test]
    fn production_native_launches_cannot_reselect_from_ambient_path() {
        let source = include_str!("backend.rs");
        let (production, _) = source
            .rsplit_once("#[cfg(test)]\nmod tests")
            .expect("backend unit-test module remains the final source section");

        assert!(
            !production.contains("which::which"),
            "production backend dispatch must never reselect an executable from PATH"
        );
        for (offset, _) in production.match_indices("Command::new(") {
            let launch = &production[offset..];
            assert!(
                launch.starts_with("Command::new(&binary)"),
                "only freshly compiled absolute temp binaries may bypass the admitted toolchain: {}",
                launch.lines().next().unwrap_or_default()
            );
        }
    }

    #[test]
    fn native_backend_dispatch_is_projected_from_the_canonical_catalog() {
        let catalog_native = crate::backend_catalog::BackendRegistry::global()
            .canonical_specs()
            .iter()
            .filter(|spec| spec.adapter == crate::backend_catalog::BackendAdapterKind::NativeRust)
            .map(|spec| spec.name)
            .collect::<std::collections::BTreeSet<_>>();
        let implemented = super::NATIVE_BACKEND_HANDLERS
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(catalog_native, implemented);

        for backend in super::NATIVE_BACKEND_HANDLERS {
            assert!(has_native_backend(backend), "{backend}");
        }

        for backend in [
            "O",
            "quote",
            "html",
            "markdown",
            "latex",
            "text",
            "python",
            "py",
            "nixos_test",
            "ubuntu_vm",
            "unknown",
        ] {
            assert!(!has_native_backend(backend), "{backend}");
        }
    }
}
