//! Shared, read-only runtime identity for the native CLI and MCP server.
//! Build metadata and observed checkout metadata are deliberately distinct.
//! Configuration contents and arbitrary environment variables are never returned.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub const SCHEMA: &str = "ostadix.runtime-provenance/v1";
pub const PROBE_SOURCE: &str = "python^(\n__oval_result__ = 1 + 1\n)_python";
const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 1024 * 1024 * 1024;
const PROBE_OUTPUT_BYTES: usize = 64 * 1024;

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn architecture(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x7fELF") && bytes.len() >= 20 {
        let machine = if bytes[5] == 1 {
            u16::from_le_bytes([bytes[18], bytes[19]])
        } else if bytes[5] == 2 {
            u16::from_be_bytes([bytes[18], bytes[19]])
        } else {
            return None;
        };
        return match machine {
            62 => Some("x86_64"),
            183 => Some("aarch64"),
            243 if bytes[4] == 2 => Some("riscv64"),
            40 => Some("arm"),
            3 => Some("x86"),
            _ => None,
        };
    }
    if bytes.len() >= 8 {
        let cpu = match &bytes[..4] {
            b"\xcf\xfa\xed\xfe" | b"\xce\xfa\xed\xfe" => {
                u32::from_le_bytes(bytes[4..8].try_into().ok()?)
            }
            b"\xfe\xed\xfa\xcf" | b"\xfe\xed\xfa\xce" => {
                u32::from_be_bytes(bytes[4..8].try_into().ok()?)
            }
            _ => return None,
        };
        return match cpu {
            0x0100_0007 => Some("x86_64"),
            0x0100_000c => Some("aarch64"),
            _ => None,
        };
    }
    None
}

/// Hash an opened regular file, retaining no file contents. A changing file is
/// explicitly unverified instead of receiving a misleading successful hash.
fn file_identity_at(display: &Path, opened: &Path, max_bytes: u64) -> Value {
    let mut result = json!({"path":display,"exists":display.exists()});
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let Ok(mut file) = options.open(opened) else {
        result["status"] = "unavailable".into();
        return result;
    };
    let Ok(before) = file.metadata() else {
        result["status"] = "metadata_unavailable".into();
        return result;
    };
    result["exists"] = true.into();
    result["bytes"] = before.len().into();
    if !before.is_file() || before.len() > max_bytes {
        result["status"] = "not_regular_or_exceeds_hash_limit".into();
        return result;
    }
    let mut hasher = Sha256::new();
    let mut prefix = Vec::new();
    let mut buffer = [0; 64 * 1024];
    let mut observed = 0u64;
    loop {
        let count = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(_) => {
                result["status"] = "read_failed".into();
                return result;
            }
        };
        observed += count as u64;
        if observed > max_bytes {
            result["status"] = "changed_or_exceeds_hash_limit".into();
            return result;
        }
        if prefix.len() < 64 {
            prefix.extend_from_slice(&buffer[..count.min(64 - prefix.len())]);
        }
        hasher.update(&buffer[..count]);
    }
    let unchanged = file.metadata().ok().is_some_and(|after| {
        after.len() == before.len()
            && after.modified().ok() == before.modified().ok()
            && observed == before.len()
    });
    if !unchanged {
        result["status"] = "changed_while_reading".into();
        return result;
    }
    result["status"] = "hashed".into();
    result["sha256"] = format!("{:x}", hasher.finalize()).into();
    result["architecture"] = architecture(&prefix).into();
    result["canonicalPath"] = json!(display.canonicalize().ok());
    result
}

pub fn file_identity(path: &Path) -> Value {
    file_identity_at(path, path, MAX_BINARY_BYTES)
}

fn executable_path(path: &Path) -> PathBuf {
    if path.is_absolute() || path.components().count() > 1 {
        path.to_owned()
    } else {
        which::which(path).unwrap_or_else(|_| path.to_owned())
    }
}

pub fn current_binary() -> Value {
    let path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("<unavailable>"));
    // A running Linux executable may have been atomically replaced or unlinked.
    // /proc/self/exe opens the running inode, never the replacement at its path.
    #[cfg(target_os = "linux")]
    let opened = Path::new("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let opened = path.as_path();
    let mut result = file_identity_at(&path, opened, MAX_BINARY_BYTES);
    result["runningArchitecture"] = std::env::consts::ARCH.into();
    result["runningOs"] = std::env::consts::OS.into();
    result["hashSource"] = if cfg!(target_os = "linux") {
        "running_process_inode"
    } else {
        "current_executable_path"
    }
    .into();
    result
}

#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
    observed: usize,
    complete: bool,
}

impl Capture {
    fn read_available(&mut self, stream: &mut impl Read, limit: usize) -> io::Result<()> {
        let mut buffer = [0; 4096];
        // A noisy child must not monopolize the loop and postpone its deadline.
        for _ in 0..64 {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    self.complete = true;
                    break;
                }
                Ok(count) => {
                    self.observed = self.observed.saturating_add(count);
                    self.bytes.extend_from_slice(
                        &buffer[..count.min(limit.saturating_sub(self.bytes.len()))],
                    );
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn metadata(&self) -> Value {
        json!({"observedBytes":self.observed,"retainedBytes":self.bytes.len(),
            "retainedSha256":hash(&self.bytes),"complete":self.complete,
            "truncated":self.observed > self.bytes.len() || !self.complete})
    }
}

struct BoundedOutput {
    status: ExitStatus,
    stdout: Capture,
    stderr: Capture,
    timed_out: bool,
    elapsed_ms: u128,
}

#[cfg(unix)]
fn bounded_output(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
) -> io::Result<BoundedOutput> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let started = Instant::now();
    let mut child = command.spawn()?;
    let group = child.id() as i32;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let terminate = |child: &mut std::process::Child| {
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
        let _ = child.kill();
    };
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            let error = io::Error::last_os_error();
            terminate(&mut child);
            let _ = child.wait();
            return Err(error);
        }
    }
    let mut out = Capture::default();
    let mut err = Capture::default();
    let mut timed_out = false;
    let result: io::Result<ExitStatus> = (|| loop {
        out.read_available(&mut stdout, limit)?;
        err.read_available(&mut stderr, limit)?;
        if let Some(status) = child.try_wait()? {
            terminate(&mut child);
            out.read_available(&mut stdout, limit)?;
            err.read_available(&mut stderr, limit)?;
            return Ok(status);
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            terminate(&mut child);
            let status = child.wait()?;
            out.read_available(&mut stdout, limit)?;
            err.read_available(&mut stderr, limit)?;
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(5));
    })();
    terminate(&mut child);
    let _ = child.wait();
    Ok(BoundedOutput {
        status: result?,
        stdout: out,
        stderr: err,
        timed_out,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

#[cfg(not(unix))]
fn bounded_output(
    _command: &mut Command,
    _timeout: Duration,
    _limit: usize,
) -> io::Result<BoundedOutput> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bounded process probe is unavailable on this platform",
    ))
}

fn git(root: &Path, arguments: &[&str]) -> Option<String> {
    let mut command = Command::new("git");
    // Editors and embedded clients may inherit a repository context belonging
    // to another checkout. Metadata must describe only the selected root.
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|name| name.starts_with("GIT_")) {
            command.env_remove(name);
        }
    }
    command
        .args(["-c", "core.fsmonitor=false", "-C"])
        .arg(root)
        .args(arguments)
        .env("GIT_OPTIONAL_LOCKS", "0");
    let result = bounded_output(&mut command, Duration::from_secs(1), 512 * 1024).ok()?;
    (result.status.success()
        && !result.timed_out
        && result.stdout.complete
        && result.stdout.observed == result.stdout.bytes.len())
    .then(|| {
        String::from_utf8_lossy(&result.stdout.bytes)
            .trim()
            .to_owned()
    })
}

pub fn source_identity(root: &Path) -> Value {
    let canonical = root.canonicalize().ok();
    let mut result = json!({"root":root,"canonicalRoot":canonical,"commit":null,"dirty":null,"status":"unavailable"});
    result["sourceManifest"] = declared_manifest(&root.join("SOURCE-MANIFEST.json"));
    let marker = root.join(".git");
    if !marker.is_dir() && !marker.is_file() {
        result["status"] = "not_repository".into();
        return result;
    }
    let Some(top) = git(root, &["rev-parse", "--show-toplevel"]) else {
        return result;
    };
    if Path::new(&top).canonicalize().ok() != canonical {
        result["status"] = "not_repository_root".into();
        return result;
    }
    let commit = git(root, &["rev-parse", "HEAD"]).filter(|value| {
        matches!(value.len(), 40 | 64) && value.bytes().all(|c| c.is_ascii_hexdigit())
    });
    let dirty = git(
        root,
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )
    .map(|status| !status.is_empty());
    result["status"] = if commit.is_some() && dirty.is_some() {
        "observed"
    } else {
        "incomplete"
    }
    .into();
    result["commit"] = commit.into();
    result["dirty"] = dirty.into();
    result["dirtyScope"] = "tracked_and_nonignored_untracked".into();
    result
}

/// Compile-time observations supplied by the executing tool, not this engine
/// dependency. Each CLI/MCP caller expands its own option_env! values; an
/// independently packaged engine needs no external build-script helper.
#[derive(Clone, Copy, Default)]
pub struct BuildIdentity {
    pub source_root: Option<&'static str>,
    pub commit: Option<&'static str>,
    pub dirty: Option<&'static str>,
    pub target: Option<&'static str>,
    pub host: Option<&'static str>,
    pub profile: Option<&'static str>,
}

pub fn build_identity(identity: BuildIdentity) -> Value {
    let commit = identity.commit.filter(|value| *value != "unknown");
    let dirty = match identity.dirty {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    };
    json!({"sourceRoot":identity.source_root,"commit":commit,"dirty":dirty,
        "target":identity.target,"host":identity.host,
        "profile":identity.profile,"dirtyScope":"tracked_and_nonignored_untracked_when_build_script_ran",
        "note":"Build metadata identifies source observed during compilation; it does not identify another selected executable or qualify a runtime."})
}

fn config_metadata(path: &Path) -> Value {
    let mut value = file_identity_at(path, path, MAX_CONFIG_BYTES);
    value["contentsReturned"] = false.into();
    value
}

/// Release/installation manifests provide declared identity, never a substitute
/// for freshly observed Git state or re-verification of the complete bundle.
fn declared_manifest(path: &Path) -> Value {
    let mut report = config_metadata(path);
    report.as_object_mut().unwrap().remove("contentsReturned");
    report["rawContentsReturned"] = false.into();
    report["claimsVerifiedByThisReport"] = false.into();
    if report["status"] != "hashed" {
        return report;
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let Some(bytes) = options.open(path).ok().and_then(|file| {
        let meta = file.metadata().ok()?;
        if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() as u64 <= MAX_CONFIG_BYTES).then_some(bytes)
    }) else {
        return report;
    };
    if report["sha256"] != hash(&bytes) {
        report["status"] = "changed_while_reading".into();
        return report;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return report;
    };
    let commit = value["source_commit"]
        .as_str()
        .or(value["commit"].as_str())
        .or(value["source"]["commit"].as_str())
        .filter(|value| {
            matches!(value.len(), 40 | 64) && value.bytes().all(|c| c.is_ascii_hexdigit())
        });
    let bundle_hash = value["bundle_sha256"]
        .as_str()
        .filter(|value| value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit()));
    let profile = value["profile"].as_str().filter(|value| {
        matches!(
            *value,
            "runtime-only" | "minimal" | "full" | "front-door-only"
        )
    });
    report["declaredSourceCommit"] = commit.into();
    report["declaredBundleSha256"] = bundle_hash.into();
    report["declaredProfile"] = profile.into();
    report["note"]="Declared manifest fields are identified by this file hash. This diagnostic does not re-verify its complete source inventory or archive.".into();
    report
}

pub fn client_configuration(root: Option<&Path>, home: Option<&Path>) -> Value {
    let mut paths = Vec::new();
    if let Some(root) = root {
        paths.push(root.join(".mcp.json"));
    }
    if let Some(home) = home {
        for relative in [
            ".mcp.json",
            ".codex/config.toml",
            ".gemini/settings.json",
            ".claude.json",
            ".config/Claude/claude_desktop_config.json",
            "Library/Application Support/Claude/claude_desktop_config.json",
        ] {
            paths.push(home.join(relative));
        }
    }
    paths.sort();
    paths.dedup();
    json!({"files":paths.iter().map(|path| config_metadata(path)).collect::<Vec<_>>(),
        "scope":"Known local client configuration paths and exact file hashes only. Their presence does not prove which client configuration launched this process; contents, arguments, tokens, and arbitrary environment values are not returned."})
}

pub fn collect(
    root: Option<&Path>,
    backends: Option<&Path>,
    tools: &[(&str, PathBuf)],
    home: Option<&Path>,
    compiled: BuildIdentity,
) -> Value {
    let source = root.map(source_identity).unwrap_or_else(
        || json!({"status":"not_configured","root":null,"commit":null,"dirty":null}),
    );
    let build = build_identity(compiled);
    let same_commit = build["commit"]
        .as_str()
        .zip(source["commit"].as_str())
        .map(|(a, b)| a == b);
    let executable = std::env::current_exe().ok();
    json!({"schema":SCHEMA,"binary":current_binary(),"buildSource":build,"runtimeSource":source,
        "buildCommitMatchesRuntimeSource":same_commit,
        "backendRoot":backends,"backendRootExists":backends.map(Path::is_dir),
        "tools":tools.iter().map(|(name,path)|json!({"name":name,"binary":file_identity(&executable_path(path))})).collect::<Vec<_>>(),
        "configuredPaths":{"O_LANG_ROOT":std::env::var_os("O_LANG_ROOT").map(PathBuf::from),
            "O_BACKENDS_DIR":std::env::var_os("O_BACKENDS_DIR").map(PathBuf::from),
            "BACKENDS_DIR":std::env::var_os("BACKENDS_DIR").map(PathBuf::from)},
        "installationManifest":executable.as_ref().and_then(|path|path.parent()).map(|path|declared_manifest(&path.join("ostadix-install.json"))),
        "clientConfiguration":client_configuration(root,home),
        "executionCheck":{"status":"not_requested","executed":false,"requested":false},
        "limits":{"binaryHashBytes":MAX_BINARY_BYTES,"configurationHashBytes":MAX_CONFIG_BYTES,
            "gitCommandTimeoutMs":1000,"qualification":"Identity and a fixed Python smoke are separate from native admission, every-runtime health, and cross-architecture qualification."}})
}

/// The only execution accepted by this helper is a fixed Python 1+1 program.
/// Outputs are bounded and represented by hashes/counts instead of leaking a
/// backend's diagnostic contents into an environment report.
pub fn python_probe(evaluator: &Path, backends: &Path, timeout: Duration) -> Value {
    let evaluator = executable_path(evaluator);
    let expected = json!({"t":"number","v":{"kind":"int","v":"2"}});
    let mut result = json!({"executed":false,"requested":true,"status":"unavailable","programSha256":hash(PROBE_SOURCE.as_bytes()),
        "program":"fixed Python 1 + 1","evaluator":file_identity(&evaluator),"backendRoot":backends,
        "identityScope":"Selected evaluator entrypoint; independently spawned backend processes are not attested.",
        "timeoutMs":timeout.as_millis(),"outputLimitPerStreamBytes":PROBE_OUTPUT_BYTES,"expectedValue":expected});
    if timeout.is_zero() || timeout > Duration::from_secs(10) {
        result["status"] = "invalid_timeout".into();
        return result;
    }
    let mut command = Command::new(&evaluator);
    command
        .args(["--json", "--eval", PROBE_SOURCE])
        .env("O_BACKENDS_DIR", backends);
    let output = match bounded_output(&mut command, timeout, PROBE_OUTPUT_BYTES) {
        Ok(output) => output,
        Err(error) => {
            result["errorKind"] = format!("{:?}", error.kind()).into();
            return result;
        }
    };
    let decoded = serde_json::from_slice::<Value>(&output.stdout.bytes).ok();
    let passed = output.status.success()
        && !output.timed_out
        && output.stdout.complete
        && output.stdout.observed == output.stdout.bytes.len()
        && decoded
            .as_ref()
            .is_some_and(|value| value["ok"] == true && value["value"] == expected);
    result["executed"] = true.into();
    result["status"] = if output.timed_out {
        "timed_out"
    } else if passed {
        "passed"
    } else {
        "failed"
    }
    .into();
    result["passed"] = passed.into();
    result["exitCode"] = output.status.code().into();
    result["elapsedMs"] = json!(output.elapsed_ms);
    result["stdout"] = output.stdout.metadata();
    result["stderr"] = output.stderr.metadata();
    result["observedExpectedValue"] = passed.into();
    result
}

/// Text-only clients receive the same identity distinctions as structured
/// clients. JSON formatting escapes control characters in configured paths.
pub fn summary(report: &Value) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    writeln!(
        text,
        "runtime-binary={} sha256={} architecture={} os={}",
        report["binary"]["path"],
        report["binary"]["sha256"],
        report["binary"]["runningArchitecture"],
        report["binary"]["runningOs"]
    )
    .unwrap();
    writeln!(
        text,
        "build-source={} commit={} dirty={} target={}",
        report["buildSource"]["sourceRoot"],
        report["buildSource"]["commit"],
        report["buildSource"]["dirty"],
        report["buildSource"]["target"]
    )
    .unwrap();
    writeln!(
        text,
        "runtime-source={} commit={} dirty={} status={}",
        report["runtimeSource"]["root"],
        report["runtimeSource"]["commit"],
        report["runtimeSource"]["dirty"],
        report["runtimeSource"]["status"]
    )
    .unwrap();
    writeln!(
        text,
        "build-commit-matches-runtime-source={} backend-root={}",
        report["buildCommitMatchesRuntimeSource"], report["backendRoot"]
    )
    .unwrap();
    if let Some(files) = report["clientConfiguration"]["files"].as_array() {
        for file in files.iter().filter(|file| file["exists"] == true) {
            writeln!(
                text,
                "client-configuration={} status={} sha256={} (contents omitted)",
                file["path"], file["status"], file["sha256"]
            )
            .unwrap();
        }
    }
    writeln!(
        text,
        "execution-check={} executed={} (fixed Python smoke only; other runtimes not qualified)",
        report["executionCheck"]["status"], report["executionCheck"]["executed"]
    )
    .unwrap();
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_build_identity_is_explicit_and_unknown_is_not_dependency_metadata() {
        let identity = build_identity(BuildIdentity {
            source_root: Some("/independent/caller"),
            commit: Some("caller-compiled-source"),
            dirty: Some("false"),
            target: Some("caller-target"),
            host: Some("caller-host"),
            profile: Some("caller-profile"),
        });
        assert_eq!(identity["sourceRoot"], "/independent/caller");
        assert_eq!(identity["commit"], "caller-compiled-source");
        assert_eq!(identity["dirty"], false);
        assert_eq!(identity["target"], "caller-target");
        assert_eq!(identity["host"], "caller-host");
        assert_eq!(identity["profile"], "caller-profile");
        let absent = build_identity(BuildIdentity::default());
        for field in ["sourceRoot", "commit", "dirty", "target", "host", "profile"] {
            assert!(absent[field].is_null());
        }
    }

    fn directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ostadix-provenance-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn recognizes_elf_and_macho_architecture_without_executing_files() {
        let mut elf = vec![0; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[18..20].copy_from_slice(&183u16.to_le_bytes());
        assert_eq!(architecture(&elf), Some("aarch64"));
        elf[18..20].copy_from_slice(&243u16.to_le_bytes());
        assert_eq!(architecture(&elf), Some("riscv64"));
        let mut macho = vec![0; 64];
        macho[..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
        macho[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        assert_eq!(architecture(&macho), Some("aarch64"));
        assert_eq!(architecture(b"#!/bin/sh"), None);
    }

    #[test]
    fn configuration_reports_identity_without_content_or_secret_arguments() {
        let home = directory("config");
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::write(
            home.join(".codex/config.toml"),
            "secret_token = 'DO_NOT_RETURN_THIS_TOKEN'",
        )
        .unwrap();
        let value = client_configuration(None, Some(&home));
        let encoded = value.to_string();
        assert!(!encoded.contains("DO_NOT_RETURN_THIS_TOKEN"));
        assert!(!encoded.contains("secret_token"));
        assert!(value["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["status"] == "hashed"
                && file["sha256"].as_str().is_some_and(|hash| hash.len() == 64)));
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn snapshot_without_git_does_not_inherit_parent_repository_identity() {
        let parent = directory("source");
        fs::create_dir_all(parent.join("snapshot")).unwrap();
        assert!(Command::new("git")
            .arg("init")
            .arg(&parent)
            .output()
            .unwrap()
            .status
            .success());
        let source = source_identity(&parent.join("snapshot"));
        assert!(source["commit"].is_null());
        assert_eq!(source["status"], "not_repository");
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn process_probe_times_out_and_bounds_both_streams() {
        let mut command = Command::new("sh");
        command.args(["-c","while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; printf 'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy' >&2; done"]);
        let output = bounded_output(&mut command, Duration::from_millis(100), 64).unwrap();
        assert!(output.timed_out);
        assert!(output.elapsed_ms < 2000);
        assert_eq!(output.stdout.bytes.len(), 64);
        assert_eq!(output.stderr.bytes.len(), 64);
        assert!(output.stdout.metadata()["truncated"] == true);
        assert!(output.stderr.metadata()["truncated"] == true);
    }

    #[test]
    fn current_binary_hash_identifies_this_process() {
        let value = current_binary();
        assert_eq!(value["status"], "hashed");
        assert!(value["sha256"].as_str().unwrap().len() == 64);
        assert_eq!(value["runningArchitecture"], std::env::consts::ARCH);
    }

    #[cfg(unix)]
    #[test]
    fn fixed_probe_retains_status_and_hashes_without_returning_child_secrets() {
        use std::os::unix::fs::PermissionsExt;
        let dir = directory("probe");
        let evaluator = dir.join("evaluator");
        fs::write(&evaluator,"#!/bin/sh\nprintf '%s' '{\"ok\":true,\"value\":{\"t\":\"number\",\"v\":{\"kind\":\"int\",\"v\":\"2\"}}}'\nprintf 'PRIVATE_BACKEND_DIAGNOSTIC' >&2\n").unwrap();
        fs::set_permissions(&evaluator, fs::Permissions::from_mode(0o700)).unwrap();
        let result = python_probe(&evaluator, &dir, Duration::from_secs(1));
        assert_eq!(result["status"], "passed");
        assert_eq!(result["executed"], true);
        assert!(!result.to_string().contains("PRIVATE_BACKEND_DIAGNOSTIC"));
        assert_eq!(result["stderr"]["observedBytes"], 26);
        fs::write(&evaluator,"#!/bin/sh\nprintf '%s' '{\"ok\":true,\"value\":{\"t\":\"string\",\"v\":\"PRIVATE_RESULT\"}}'\n").unwrap();
        let result = python_probe(&evaluator, &dir, Duration::from_secs(1));
        assert_eq!(result["status"], "failed");
        assert!(!result.to_string().contains("PRIVATE_RESULT"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_child_holding_a_pipe_cannot_keep_the_probe_waiting_after_leader_exit() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10 & printf done"]);
        let result = bounded_output(&mut command, Duration::from_secs(1), 64).unwrap();
        assert!(result.status.success());
        assert!(result.elapsed_ms < 1000);
        assert_eq!(result.stdout.bytes, b"done");
    }

    #[cfg(unix)]
    #[test]
    fn configuration_named_pipe_is_rejected_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let dir = directory("fifo");
        let fifo = dir.join("config");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        let value = config_metadata(&fifo);
        assert_eq!(value["status"], "not_regular_or_exceeds_hash_limit");
        assert!(start.elapsed() < Duration::from_secs(1));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn selected_checkout_commit_and_dirty_state_are_independently_observed() {
        let dir = directory("git");
        assert!(Command::new("git")
            .arg("init")
            .arg(&dir)
            .output()
            .unwrap()
            .status
            .success());
        fs::write(dir.join("source"), "first").unwrap();
        assert!(Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["add", "source"])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "fixture"
            ])
            .status()
            .unwrap()
            .success());
        let clean = source_identity(&dir);
        assert_eq!(clean["status"], "observed");
        assert_eq!(clean["dirty"], false);
        assert!(clean["commit"]
            .as_str()
            .is_some_and(|value| value.len() == 40 || value.len() == 64));
        fs::write(dir.join("source"), "changed").unwrap();
        let dirty = source_identity(&dir);
        assert_eq!(dirty["commit"], clean["commit"]);
        assert_eq!(dirty["dirty"], true);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn git_context_child() {
        let Some(root) = std::env::var_os("OSTADIX_PROVENANCE_TEST_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let source = source_identity(&root);
        assert_eq!(source["status"], "observed");
        assert_eq!(
            source["commit"],
            std::env::var("OSTADIX_PROVENANCE_TEST_COMMIT").unwrap()
        );
        let snapshot = source_identity(&root.join("snapshot"));
        assert_eq!(snapshot["status"], "not_repository");
        assert!(snapshot["commit"].is_null());
    }

    #[test]
    fn inherited_editor_git_context_cannot_redirect_selected_checkout_identity() {
        let root = directory("git-context-root");
        let foreign = directory("git-context-foreign");
        for (directory, text) in [(&root, "selected"), (&foreign, "unrelated")] {
            assert!(Command::new("git")
                .arg("init")
                .arg(directory)
                .output()
                .unwrap()
                .status
                .success());
            fs::write(directory.join("source"), text).unwrap();
            assert!(Command::new("git")
                .arg("-C")
                .arg(directory)
                .args(["add", "source"])
                .status()
                .unwrap()
                .success());
            assert!(Command::new("git")
                .arg("-C")
                .arg(directory)
                .args([
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-qm",
                    "fixture"
                ])
                .status()
                .unwrap()
                .success());
        }
        let expected = source_identity(&root)["commit"]
            .as_str()
            .unwrap()
            .to_owned();
        fs::create_dir(root.join("snapshot")).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "runtime_provenance::tests::git_context_child"])
            .env("OSTADIX_PROVENANCE_TEST_ROOT", &root)
            .env("OSTADIX_PROVENANCE_TEST_COMMIT", expected)
            .env("GIT_DIR", foreign.join(".git"))
            .env("GIT_COMMON_DIR", foreign.join(".git"))
            .env("GIT_WORK_TREE", &root)
            .env("GIT_INDEX_FILE", foreign.join(".git/index"))
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "core.bare")
            .env("GIT_CONFIG_VALUE_0", "true")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "child assertion must actually run"
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(foreign).unwrap();
    }

    #[test]
    fn source_snapshot_manifest_is_a_declaration_not_observed_git_state() {
        let directory = directory("declared-source");
        let commit = "a".repeat(40);
        fs::write(
            directory.join("SOURCE-MANIFEST.json"),
            json!({"commit":commit,"token":"PRIVATE_MANIFEST_FIELD"}).to_string(),
        )
        .unwrap();
        let report = source_identity(&directory);
        assert!(report["commit"].is_null());
        assert!(report["dirty"].is_null());
        assert_eq!(report["sourceManifest"]["declaredSourceCommit"], commit);
        assert_eq!(
            report["sourceManifest"]["claimsVerifiedByThisReport"],
            false
        );
        assert!(!report.to_string().contains("PRIVATE_MANIFEST_FIELD"));
        fs::remove_dir_all(directory).unwrap();
    }
}
