//! Native command routing. Specialist tools retain their own argument grammar.
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

static SHIMS: Mutex<Option<o_lang::shims::ExtractedShims>> = Mutex::new(None);

#[derive(Deserialize)]
struct Installation {
    repo_root: PathBuf,
    #[serde(default)]
    backends_dir: Option<PathBuf>,
}

fn installation(executable: &Path) -> Option<Installation> {
    let bytes = fs::read(executable.parent()?.join("ostadix-install.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn root_from(executable: &Path, configured: Option<PathBuf>) -> Option<PathBuf> {
    configured
        .or_else(|| installation(executable).map(|value| value.repo_root))
        .or_else(|| {
            executable
                .ancestors()
                .skip(1)
                .find(|path| path.join("Cargo.toml").is_file() && path.join("backends").is_dir())
                .map(Path::to_path_buf)
        })
}

pub(super) fn repository_root() -> Option<PathBuf> {
    root_from(
        &env::current_exe().ok()?,
        env::var_os("O_LANG_ROOT").map(PathBuf::from),
    )
}

pub(super) fn default_shim_dir() -> Result<PathBuf> {
    if let Some(path) = env::var_os("O_BACKENDS_DIR").or_else(|| env::var_os("BACKENDS_DIR")) {
        return Ok(path.into());
    }
    if let Some(root) = env::var_os("O_LANG_ROOT") {
        let path = PathBuf::from(root).join("backends");
        if path.is_dir() {
            return Ok(path);
        }
    }
    let executable = env::current_exe()?;
    if let Some(path) = installation(&executable).and_then(|value| value.backends_dir) {
        if path.is_dir() {
            return Ok(path);
        }
    }
    if let Some(root) = root_from(&executable, None) {
        let path = root.join("backends");
        if path.is_dir() {
            return Ok(path);
        }
    }
    let mut guard = SHIMS
        .lock()
        .map_err(|_| anyhow::anyhow!("bundled shim storage lock poisoned"))?;
    if guard.is_none() {
        *guard = Some(o_lang::shims::extract_bundled_shims("ostadix-cli-shims")?);
    }
    Ok(guard
        .as_ref()
        .expect("initialized above")
        .path()
        .to_path_buf())
}

pub(super) fn cleanup_shims() {
    if let Ok(mut guard) = SHIMS.lock() {
        *guard = None;
    }
}

fn same_file(left: &Path, right: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(left), Ok(right)) = (fs::metadata(left), fs::metadata(right)) {
            if left.dev() == right.dev() && left.ino() == right.ino() {
                return true;
            }
            if left.len() != right.len() {
                return false;
            }
        }
    }
    if left
        .canonicalize()
        .ok()
        .zip(right.canonicalize().ok())
        .is_some_and(|(a, b)| a == b)
    {
        return true;
    }
    // Installations may copy the front door to O/o rather than link it. An
    // identical executable is still recursive even when its inode differs.
    match (fs::read(left), fs::read(right)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn tool(name: &str, override_name: &str) -> Result<PathBuf> {
    let current = env::current_exe()?;
    if let Some(path) = env::var_os(override_name).map(PathBuf::from) {
        if same_file(&path, &current) {
            bail!("{override_name} points back to the native front door; refusing recursive execution");
        }
        if !executable(&path) {
            bail!("{override_name} is not executable: {}", path.display());
        }
        return Ok(path);
    }
    let names: &[&str] = if name == "ostadix-evaluator" {
        &["ostadix-evaluator", "O"]
    } else {
        &[name]
    };
    let mut directories = current
        .parent()
        .map(Path::to_path_buf)
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(root) = repository_root() {
        directories.extend([root.join("target/release"), root.join("target/debug")]);
    }
    for directory in directories {
        for name in names {
            let path = directory.join(name);
            if executable(&path) && !same_file(&path, &current) {
                return Ok(path);
            }
        }
    }
    bail!("native tool `{name}` is not installed beside this executable; run setup.sh --minimal or set {override_name}")
}

fn run(path: PathBuf, args: &[OsString]) -> Result<()> {
    let mut command = Command::new(&path);
    command.args(args);
    if env::var_os("O_BACKENDS_DIR").is_none() {
        if let Some(root) = repository_root() {
            if root.join("backends").is_dir() {
                command.env("O_BACKENDS_DIR", root.join("backends"));
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(command.exec()).with_context(|| format!("could not execute {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let status = command
            .status()
            .with_context(|| format!("could not execute {}", path.display()))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn delegate(name: &str, override_name: &str, args: &[OsString]) -> Result<()> {
    run(tool(name, override_name)?, args)
}

fn workflow(relative: &str, override_name: &str, args: &[OsString]) -> Result<()> {
    let path = match env::var_os(override_name) {
        Some(path) => PathBuf::from(path),
        None => repository_root().context("this workflow needs the source checkout; set O_LANG_ROOT or reinstall with setup.sh")?.join(relative),
    };
    run(path, args)
}

fn prepend(head: &[&str], tail: &[OsString]) -> Vec<OsString> {
    head.iter()
        .map(OsString::from)
        .chain(tail.iter().cloned())
        .collect()
}

fn output_alias(arguments: &[OsString]) -> Vec<OsString> {
    if arguments.len() >= 2
        && !arguments[0].to_string_lossy().starts_with('-')
        && !arguments[1].to_string_lossy().starts_with('-')
    {
        let mut result = vec![arguments[0].clone(), "-o".into(), arguments[1].clone()];
        result.extend_from_slice(&arguments[2..]);
        result
    } else {
        arguments.to_vec()
    }
}

const HELLO: &str = "python^(\n__oval_result__ = 1 + 1\n)_python";
const TOOLS: &[(&str, &str)] = &[
    ("ostadix-evaluator", "O_LANG_EVALUATOR_BIN"),
    ("olangc", "O_LANG_OLANGC_BIN"),
    ("ocorec", "O_LANG_OCOREC_BIN"),
    ("o-link", "O_LANG_LINK_BIN"),
    ("o-unlink", "O_LANG_UNLINK_BIN"),
    ("o-node", "O_LANG_NODE_BIN"),
    ("octl", "O_LANG_OCTL_BIN"),
    ("o-live-host", "O_LANG_LIVE_BIN"),
    ("ogit", "O_LANG_OGIT_BIN"),
    ("o-registry", "O_LANG_REGISTRY_BIN"),
    ("o-info", "O_LANG_INFO_BIN"),
    ("ostadix-device", "O_LANG_DEVICE_BIN"),
];

fn python_smoke(shims: &Path) -> Result<std::process::Output> {
    Command::new(tool("ostadix-evaluator", "O_LANG_EVALUATOR_BIN")?)
        .args(["--json", "--eval", HELLO])
        .env("O_BACKENDS_DIR", shims)
        .output()
        .context("could not run Python backend smoke")
}

fn smoke_passed(output: &std::process::Output) -> bool {
    if !output.status.success() {
        return false;
    }
    let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return false;
    };
    envelope["ok"] == true
        && envelope["value"] == serde_json::json!({"t":"number", "v":{"kind":"int", "v":"2"}})
}

fn inspect_installation(mode: &str, arguments: &[OsString]) -> Result<()> {
    if arguments == [OsString::from("--help")] || arguments == [OsString::from("-h")] {
        println!("Usage: o {mode} [--json]\nInspect installed native tools. Doctor also runs the Python backend smoke; other runtimes are not probed.");
        std::process::exit(0);
    }
    let json = arguments == [OsString::from("--json")];
    if !arguments.is_empty() && !json {
        bail!("usage: o {mode} [--json]");
    }
    let mut ready = true;
    let mut rows = Vec::new();
    for (name, override_name) in TOOLS {
        let resolved = tool(name, override_name);
        ready &= resolved.is_ok();
        rows.push(match resolved {
            Ok(path) => serde_json::json!({"name": name, "path": path, "available": true}),
            Err(error) => {
                serde_json::json!({"name": name, "available": false, "detail": error.to_string()})
            }
        });
    }
    let mut report = serde_json::json!({"schema": "ostadix.installation-check/v1", "root": repository_root(), "tools": rows});
    if mode == "doctor" {
        let shims = default_shim_dir()?;
        let shim_count = fs::read_dir(&shims)
            .with_context(|| format!("backend directory is unavailable: {}", shims.display()))?
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with("_shim.py"))
            .count();
        let probe = python_smoke(&shims);
        let (passed, detail) = match probe {
            Ok(output) => (
                smoke_passed(&output),
                format!(
                    "exit={}; stdout={:?}; stderr={:?}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ),
            Err(error) => (false, error.to_string()),
        };
        ready &= passed && shim_count > 0;
        report["backends"] = serde_json::json!({"directory": shims, "shim_count": shim_count, "python_smoke_passed": passed, "probe_detail": detail, "other_runtimes": "not probed"});
        report["ready"] = ready.into();
    } else if mode == "editions" {
        report["editions"] = serde_json::json!({"rust": true, "c17": repository_root().is_some_and(|root| executable(&root.join("c_cpp/O"))), "python_source": repository_root().is_some_and(|root| root.join("o_lang/__init__.py").is_file())});
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("OSTADIX {mode}");
        println!(
            "Source: {}",
            report["root"]
                .as_str()
                .unwrap_or("not configured; bundled runtime remains available")
        );
        for row in report["tools"].as_array().expect("tools array") {
            println!(
                "{}: {}",
                row["name"].as_str().unwrap_or("tool"),
                row["path"]
                    .as_str()
                    .unwrap_or("missing; reinstall with setup.sh --minimal")
            );
        }
        if mode == "doctor" {
            println!(
                "Backend shims: {} in {}",
                report["backends"]["shim_count"],
                report["backends"]["directory"]
                    .as_str()
                    .unwrap_or("unknown")
            );
            println!(
                "Python backend smoke (1 + 1 -> 2): {}",
                if report["backends"]["python_smoke_passed"] == true {
                    "passed"
                } else {
                    "failed"
                }
            );
            println!("Other backend runtimes: not probed");
            if !ready {
                eprintln!("{}", report["backends"]["probe_detail"]);
            }
        } else if mode == "editions" {
            println!("{}", report["editions"]);
        }
    }
    cleanup_shims();
    std::process::exit(if mode == "doctor" && !ready { 1 } else { 0 });
}

/// Returns only when the arguments belong to the in-process intent CLI.
pub(super) fn dispatch() -> Result<()> {
    dispatch_arguments(&env::args_os().skip(1).collect::<Vec<_>>())
}

fn dispatch_arguments(arguments: &[OsString]) -> Result<()> {
    let Some(first) = arguments.first() else {
        if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
            return delegate("ostadix-evaluator", "O_LANG_EVALUATOR_BIN", &[]);
        }
        return Ok(());
    };
    let Some(command) = first.to_str() else {
        return delegate("ostadix-evaluator", "O_LANG_EVALUATOR_BIN", arguments);
    };
    let tail = &arguments[1..];
    if matches!(command, "e" | "eval" | "repl" | "check")
        && (tail == [OsString::from("--help")] || tail == [OsString::from("-h")])
    {
        return delegate(
            "ostadix-evaluator",
            "O_LANG_EVALUATOR_BIN",
            &["--help".into()],
        );
    }
    match command {
        "run" | "routes" | "optimize" | "plan" | "explain" | "inspect" | "computation"
        | "object" | "operation" | "realizations" | "observe" | "replan" | "--help" | "-h"
        | "--version" | "-V" => Ok(()),
        "help" if tail.is_empty() => Ok(()),
        "help" => {
            let mut args = tail.to_vec();
            args.push("--help".into());
            dispatch_arguments(&args)
        }
        "root" => {
            if !tail.is_empty() {
                bail!("usage: o root");
            }
            println!(
                "{}",
                repository_root()
                    .context("source checkout not configured; set O_LANG_ROOT")?
                    .display()
            );
            std::process::exit(0);
        }
        "doctor" | "which" | "editions" => inspect_installation(command, tail),
        "smoke" => {
            if !tail.is_empty() {
                bail!("usage: o smoke (runs the Python backend and expects 2)");
            }
            let output = python_smoke(&default_shim_dir()?)?;
            cleanup_shims();
            std::io::stderr().write_all(&output.stderr)?;
            if !smoke_passed(&output) {
                std::io::stdout().write_all(&output.stdout)?;
                bail!(
                    "Python backend smoke did not produce the expected value 2 ({}); run o doctor",
                    output.status
                );
            }
            println!("2");
            std::process::exit(0);
        }
        "node" => match tail.first().and_then(|arg| arg.to_str()) {
            Some(
                "start" | "stop" | "status" | "restart" | "pair" | "serve" | "pki" | "identity"
                | "admin",
            ) => delegate("o-node", "O_LANG_NODE_BIN", tail),
            Some("host") => delegate("o-node", "O_LANG_NODE_BIN", &tail[1..]),
            _ => delegate("octl", "O_LANG_OCTL_BIN", &prepend(&["node"], tail)),
        },
        "node-host" => delegate("o-node", "O_LANG_NODE_BIN", tail),
        "device" => delegate("ostadix-device", "O_LANG_DEVICE_BIN", tail),
        "registry" => delegate("o-registry", "O_LANG_REGISTRY_BIN", tail),
        "info" => delegate("o-info", "O_LANG_INFO_BIN", tail),
        "live" => delegate("o-live-host", "O_LANG_LIVE_BIN", tail),
        "receipt" => delegate(
            "ogit",
            "O_LANG_OGIT_BIN",
            &if tail.is_empty() {
                prepend(&["demo", "semantic-receipt"], tail)
            } else {
                tail.to_vec()
            },
        ),
        "git" => delegate("ogit", "O_LANG_OGIT_BIN", tail),
        "kernel" => workflow("scripts/o-kernel.sh", "O_LANG_KERNEL_CLI_BIN", tail),
        "capacity" => workflow("scripts/ostadix_capacity.py", "O_LANG_CAPACITY_BIN", tail),
        "build" => workflow(
            "setup.sh",
            "O_LANG_SETUP_BIN",
            &if tail.is_empty() {
                prepend(&["-y", "--minimal"], tail)
            } else {
                tail.to_vec()
            },
        ),
        "why" => {
            if tail.len() < 2 {
                bail!("usage: o why FILE.O P<N> [compiler options]");
            }
            let mut args = vec![
                tail[0].clone(),
                "--target".into(),
                "ir".into(),
                "--why".into(),
                tail[1].clone(),
            ];
            args.extend_from_slice(&tail[2..]);
            delegate("olangc", "O_LANG_OLANGC_BIN", &args)
        }
        "e" | "eval" => delegate(
            "ostadix-evaluator",
            "O_LANG_EVALUATOR_BIN",
            &prepend(&["--eval"], tail),
        ),
        "repl" => delegate(
            "ostadix-evaluator",
            "O_LANG_EVALUATOR_BIN",
            &prepend(&["--repl"], tail),
        ),
        "check" => {
            let core = tail
                .iter()
                .any(|arg| Path::new(arg).extension() == Some(OsStr::new("oc")));
            delegate(
                if core { "ocorec" } else { "ostadix-evaluator" },
                if core {
                    "O_LANG_OCOREC_BIN"
                } else {
                    "O_LANG_EVALUATOR_BIN"
                },
                &prepend(&["--check"], tail),
            )
        }
        "ir" | "script" => delegate(
            "olangc",
            "O_LANG_OLANGC_BIN",
            &prepend(&["--target", command], tail),
        ),
        "graph" | "dot" => delegate(
            "olangc",
            "O_LANG_OLANGC_BIN",
            &prepend(&["--target", "dot"], tail),
        ),
        "wasm" => delegate(
            "olangc",
            "O_LANG_OLANGC_BIN",
            &prepend(&["--target", "wasm"], &output_alias(tail)),
        ),
        "bin" | "aot" | "ship" => delegate("olangc", "O_LANG_OLANGC_BIN", &output_alias(tail)),
        "compile" => delegate("olangc", "O_LANG_OLANGC_BIN", tail),
        "link" => delegate("o-link", "O_LANG_LINK_BIN", tail),
        "link-project" => delegate("o-link", "O_LANG_LINK_BIN", &prepend(&["--project"], tail)),
        "link-run" => delegate("o-link", "O_LANG_LINK_BIN", &prepend(&["--run"], tail)),
        "unlink" => delegate("o-unlink", "O_LANG_UNLINK_BIN", tail),
        "mir" | "hir" | "asm" | "obj" | "ast" => {
            let mut args = prepend(&["--emit", command], tail);
            if command != "obj"
                && !tail.iter().any(|arg| {
                    arg == "-o"
                        || arg == "--output"
                        || arg.to_str().is_some_and(|v| {
                            v.starts_with("--output=") || (v.starts_with("-o") && v.len() > 2)
                        })
                })
            {
                args.extend(["--output".into(), "-".into()]);
            }
            delegate("ocorec", "O_LANG_OCOREC_BIN", &args)
        }
        "core" => delegate("ocorec", "O_LANG_OCOREC_BIN", tail),
        "banner" | "pulse" | "dash" | "fortune" | "flex" | "orbit" | "boxing" | "medieval"
        | "arena" | "demo" | "radar" => {
            let directory = env::var_os("O_TERM_DIR")
                .or_else(|| env::var_os("OSTADIX_TERM_DIR"))
                .map(PathBuf::from)
                .or_else(|| {
                    env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/ostadix/term"))
                })
                .context("terminal program directory is not configured; set O_TERM_DIR")?;
            let source = directory.join(format!("{command}.O"));
            if !source.is_file() {
                bail!("terminal program is not installed: {}", source.display());
            }
            let terminal = std::io::stdout().is_terminal()
                && env::var("TERM").is_ok_and(|term| term != "dumb");
            for key in ["OSTADIX_COLOR", "OSTADIX_ANIMATE"] {
                if env::var(key).unwrap_or_else(|_| "auto".into()) == "auto" {
                    env::set_var(
                        key,
                        if terminal && env::var_os("NO_COLOR").is_none() {
                            "1"
                        } else {
                            "0"
                        },
                    );
                }
            }
            if env::var_os("NO_COLOR").is_some() {
                env::set_var("OSTADIX_COLOR", "0");
            }
            let mut tail = tail;
            if command == "arena" {
                if let Some(mode) = tail.first().and_then(|arg| arg.to_str()) {
                    if !matches!(mode, "boxing" | "medieval") {
                        bail!("usage: o arena [boxing|medieval]");
                    }
                    env::set_var("OSTADIX_ARENA", mode);
                    tail = &tail[1..];
                }
            }
            if matches!(command, "boxing" | "medieval" | "arena")
                && env::var_os("OSTADIX_ARENA_OUT").is_none()
            {
                if let Some(home) = env::var_os("HOME") {
                    env::set_var(
                        "OSTADIX_ARENA_OUT",
                        PathBuf::from(home).join(".local/state/ostadix/arena"),
                    );
                }
            }
            let mut args = vec![source.into_os_string()];
            args.extend_from_slice(tail);
            delegate("ostadix-evaluator", "O_LANG_EVALUATOR_BIN", &args)
        }
        _ => delegate("ostadix-evaluator", "O_LANG_EVALUATOR_BIN", arguments),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_metadata_and_explicit_root_override_are_self_relative() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("o");
        fs::write(dir.path().join("ostadix-install.json"), r#"{"schema":"ostadix.install/v1","repo_root":"/relocated/source","backends_dir":"/relocated/source/backends"}"#).unwrap();
        assert_eq!(
            root_from(&binary, None),
            Some(PathBuf::from("/relocated/source"))
        );
        assert_eq!(
            root_from(&binary, Some("/explicit/source".into())),
            Some(PathBuf::from("/explicit/source"))
        );
    }

    #[test]
    fn checkout_root_is_found_from_binary_location_without_build_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        fs::create_dir(dir.path().join("backends")).unwrap();
        assert_eq!(
            root_from(&dir.path().join("target/debug/o-cli"), None),
            Some(dir.path().to_path_buf())
        );
    }

    #[cfg(unix)]
    #[test]
    fn evaluator_recursion_recognizes_hardlinks() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("o");
        let alias = dir.path().join("evaluator-alias");
        fs::write(&original, "native").unwrap();
        fs::hard_link(&original, &alias).unwrap();
        assert!(same_file(&original, &alias));
    }
}
