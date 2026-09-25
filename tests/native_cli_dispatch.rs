//! Actual native front-door process routing and installed-location contracts.
#![cfg(unix)]
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

const FRONT: &str = env!("CARGO_BIN_EXE_o-cli");

fn executable(path: &std::path::Path, source: &str) {
    fs::write(path, source).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn shared_discovery_is_inert_and_available_without_optional_runtimes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("source with spaces");
    let bin = root.join("target/release");
    fs::create_dir_all(&bin).unwrap();
    // A discoverable executable must never be launched by catalog/guide reads.
    let marker = dir.path().join("unexpected-execution");
    executable(
        &bin.join("o-cli"),
        &format!("#!/bin/sh\ntouch '{}'\nexit 91\n", marker.display()),
    );
    let output = Command::new(FRONT)
        .args(["capabilities", "operation", "--json"])
        .env("O_LANG_ROOT", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let catalog: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(catalog["schema"], "ostadix.mcp-capabilities/v1");
    assert_eq!(catalog["runtime_readiness_verified"], false);
    assert!(catalog["recipes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|recipe| recipe["id"] == "operation-run" && recipe["mcp"]["tool"] == "o_operation"));
    let guide = Command::new(FRONT)
        .args(["guide", "operations", "--json"])
        .env("O_LANG_ROOT", &root)
        .output()
        .unwrap();
    assert!(guide.status.success());
    let guide: serde_json::Value = serde_json::from_slice(&guide.stdout).unwrap();
    assert_eq!(guide["topic"], "operations");
    assert!(guide["guide"]
        .as_str()
        .unwrap()
        .contains("without dispatching"));
    assert!(!marker.exists());
    let alias = Command::new(FRONT)
        .args(["discover", "operation", "--json"])
        .env("O_LANG_ROOT", &root)
        .output()
        .unwrap();
    assert!(alias.status.success());
    assert_eq!(alias.stdout, output.stdout);
}

#[test]
fn typed_operation_guard_rejects_unmarked_input_before_planning_or_execution() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("ordinary.O");
    fs::write(&source, "text^(must not execute)_text").unwrap();
    for target in [source.as_path(), dir.path()] {
        for command in ["plan", "run"] {
            let output = Command::new(FRONT)
                .arg(command)
                .arg(target)
                .args(["--operation-required", "--json"])
                .env("XDG_STATE_HOME", dir.path().join("state"))
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(
                    "--operation-required needs an existing marked operation-project directory"
                ),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    assert!(!dir.path().join("state").exists());
}

#[test]
fn typed_operation_plan_preserves_structured_stale_implementation_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("operation");
    fs::create_dir(&project).unwrap();
    let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/normalize");
    for file in [
        "olang.project.toml",
        "operation-planning-request.json",
        "input.json",
        "normalize_chunked.py",
        "normalize_scalar.py",
    ] {
        fs::copy(example.join(file), project.join(file)).unwrap();
    }
    fs::write(
        project.join("normalize_chunked.py"),
        "raise RuntimeError('must not execute')\n",
    )
    .unwrap();
    let output = Command::new(FRONT)
        .arg("plan")
        .arg(&project)
        .args(["--operation-required", "--json"])
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "ostadix.operation-command-error/v1");
    assert_eq!(report["command"], "plan");
    assert_eq!(report["error"]["kind"], "validation_failed");
    assert!(report["error"]["message"]
        .as_str()
        .unwrap()
        .contains("implementation"));
    assert!(!dir.path().join("state").exists());
}

#[test]
fn catalog_tool_preserves_binary_and_script_argv_environment_cwd_stdin_and_status() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("catalog root");
    let bin = root.join("target/release");
    let interpreters = dir.path().join("interpreter bin");
    let working = dir.path().join("working directory");
    for path in [&bin, &interpreters, &working, &root.join("scripts")] {
        fs::create_dir_all(path).unwrap();
    }
    // Some shells resolve printf externally; this fixture deliberately replaces PATH.
    let printf = ["/usr/bin/printf", "/bin/printf"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .expect("test host must provide printf at a standard absolute path");
    let capture = format!(
        "#!/bin/sh\n'{printf}' '%s\\0' \"$PWD\" \"$CATALOG_LITERAL_ENV\" \"$@\"\n/bin/cat\nexit 29\n"
    );
    executable(&bin.join("olangc"), &capture);
    executable(&interpreters.join("python3"), &capture);
    fs::write(
        root.join("scripts/ostadix_capacity.py"),
        "# interpreter owns this script\n",
    )
    .unwrap();
    let args = [
        OsString::from("--help"),
        OsString::from("file with spaces"),
        OsString::from("$(touch unrequested); * $HOME"),
        OsString::from_vec(b"non-utf8-\xff".to_vec()),
    ];
    for id in ["olangc", "capacity"] {
        let mut child = Command::new(FRONT)
            .args(["tool", id])
            .args(&args)
            .env("O_LANG_ROOT", &root)
            .env("PATH", &interpreters)
            .env("CATALOG_LITERAL_ENV", "value with $literal ; symbols")
            .current_dir(&working)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"literal stdin\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(29),
            "{id}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut expected = vec![
            working.canonicalize().unwrap().into_os_string(),
            OsString::from("value with $literal ; symbols"),
        ];
        if id == "capacity" {
            expected.push(
                root.join("scripts/ostadix_capacity.py")
                    .canonicalize()
                    .unwrap()
                    .into_os_string(),
            );
        }
        expected.extend_from_slice(&args);
        let mut bytes = expected
            .iter()
            .flat_map(|arg| arg.as_bytes().iter().copied().chain([0]))
            .collect::<Vec<_>>();
        bytes.extend_from_slice(b"literal stdin\n");
        assert_eq!(output.stdout, bytes, "{id}");
        assert!(!working.join("unrequested").exists());
    }
}

#[test]
fn catalog_tool_rejects_unknown_ids_and_recursive_aliases_but_allows_native_o() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("target/release");
    fs::create_dir_all(&bin).unwrap();
    for name in ["o-cli", "olangc"] {
        std::os::unix::fs::symlink(FRONT, bin.join(name)).unwrap();
    }
    let run = |args: &[&str]| {
        Command::new(FRONT)
            .args(args)
            .env("O_LANG_ROOT", dir.path())
            .output()
            .unwrap()
    };
    let unknown = run(&["tool", "sh", "-c", "exit 0"]);
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown Ostadix command"));
    let recursive = run(&["tool", "olangc", "--help"]);
    assert!(!recursive.status.success());
    assert!(String::from_utf8_lossy(&recursive.stderr).contains("refusing recursive execution"));
    let native = run(&["tool", "o", "--help"]);
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(String::from_utf8_lossy(&native.stdout).contains("capabilities"));
    let own_help = run(&["tool", "--help"]);
    assert!(own_help.status.success());
    assert!(String::from_utf8_lossy(&own_help.stdout).contains("o tool COMMAND [ARGS]..."));
    let non_utf8_id = Command::new(FRONT)
        .arg("tool")
        .arg(OsString::from_vec(b"invalid-\xff".to_vec()))
        .output()
        .unwrap();
    assert!(!non_utf8_id.status.success());
    assert!(String::from_utf8_lossy(&non_utf8_id.stderr)
        .contains("catalog command ID must be valid UTF-8"));
    let help = run(&["capabilities", "capacity"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Help: o tool capacity --help"));
}

#[test]
fn operational_aliases_preserve_exact_argv_and_native_exit_status() {
    let dir = tempfile::tempdir().unwrap();
    let capture = dir.path().join("capture");
    executable(&capture, "#!/bin/sh\nprintf '%s\\0' \"$@\"\nexit 23\n");
    let cases: &[(&[&str], &str, &[&str])] = &[
        (
            &["node", "pair", "some node", "-a", "100.1.2.3:7340"],
            "O_LANG_NODE_BIN",
            &["pair", "some node", "-a", "100.1.2.3:7340"],
        ),
        (
            &[
                "node",
                "run",
                "file with spaces.O",
                "-n",
                "rack",
                "-a",
                "100.1.2.3:7337",
            ],
            "O_LANG_OCTL_BIN",
            &[
                "node",
                "run",
                "file with spaces.O",
                "-n",
                "rack",
                "-a",
                "100.1.2.3:7337",
            ],
        ),
        (
            &["eval", "python^(1 + 1)_python"],
            "O_LANG_EVALUATOR_BIN",
            &["--eval", "python^(1 + 1)_python"],
        ),
        (
            &["check", "program.O"],
            "O_LANG_EVALUATOR_BIN",
            &["--check", "program.O"],
        ),
        (
            &["check", "program.oc"],
            "O_LANG_OCOREC_BIN",
            &["--check", "program.oc"],
        ),
        (
            &["ir", "program.O"],
            "O_LANG_OLANGC_BIN",
            &["--target", "ir", "program.O"],
        ),
        (
            &["graph", "program.O"],
            "O_LANG_OLANGC_BIN",
            &["--target", "dot", "program.O"],
        ),
        (
            &["dot", "program with spaces.O", "-o", "full graph.dot"],
            "O_LANG_OLANGC_BIN",
            &[
                "--target",
                "dot",
                "program with spaces.O",
                "-o",
                "full graph.dot",
            ],
        ),
        (
            &["graph", "--help"],
            "O_LANG_OLANGC_BIN",
            &["--target", "dot", "--help"],
        ),
        (
            &["ship", "program.O", "standalone-app"],
            "O_LANG_OLANGC_BIN",
            &["program.O", "-o", "standalone-app"],
        ),
        (
            &["ship", "program.O", "-o", "standalone-app"],
            "O_LANG_OLANGC_BIN",
            &["program.O", "-o", "standalone-app"],
        ),
        (
            &["mir", "module.oc"],
            "O_LANG_OCOREC_BIN",
            &["--emit", "mir", "module.oc", "--output", "-"],
        ),
        (
            &["asm", "module.oc", "-o", "custom.s"],
            "O_LANG_OCOREC_BIN",
            &["--emit", "asm", "module.oc", "-o", "custom.s"],
        ),
        (
            &["receipt"],
            "O_LANG_OGIT_BIN",
            &["demo", "semantic-receipt"],
        ),
        (
            &["why", "program.O", "P7", "--json"],
            "O_LANG_OLANGC_BIN",
            &["program.O", "--target", "ir", "--why", "P7", "--json"],
        ),
        (
            &["link-project", "project"],
            "O_LANG_LINK_BIN",
            &["--project", "project"],
        ),
        (
            &["file with spaces.O", "backends"],
            "O_LANG_EVALUATOR_BIN",
            &["file with spaces.O", "backends"],
        ),
    ];
    for (args, variable, expected) in cases {
        let output = Command::new(FRONT)
            .args(*args)
            .env(variable, &capture)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(23),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes: Vec<u8> = expected
            .iter()
            .flat_map(|arg| arg.as_bytes().iter().copied().chain([0]))
            .collect();
        assert_eq!(output.stdout, bytes, "{args:?}");
    }
}

#[test]
fn non_utf8_paths_are_forwarded_without_shell_reinterpretation() {
    let dir = tempfile::tempdir().unwrap();
    let capture = dir.path().join("capture");
    executable(&capture, "#!/bin/sh\nprintf '%s\\0' \"$@\"\n");
    let path = OsString::from_vec(b"bad-\xff path.O".to_vec());
    let output = Command::new(FRONT)
        .arg(&path)
        .env("O_LANG_EVALUATOR_BIN", capture)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, [path.as_bytes(), &[0]].concat());
}

#[test]
fn backend_multicall_precedes_dispatch_and_recursive_evaluator_is_rejected() {
    let result = Command::new(FRONT)
        .args(["--o-backend", "no-such-backend"])
        .env("O_LANG_EVALUATOR_BIN", FRONT)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!result.status.success());
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains("no-such-backend"), "{error}");
    assert!(!error.contains("recursive execution"), "{error}");
    let result = Command::new(FRONT)
        .arg("program.O")
        .env("O_LANG_EVALUATOR_BIN", FRONT)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("recursive execution"));
}

#[test]
fn copied_frontdoor_resolves_installed_siblings_and_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let front = dir.path().join("o");
    fs::copy(FRONT, &front).unwrap();
    executable(
        &dir.path().join("ostadix-evaluator"),
        "#!/bin/sh\nprintf '%s\\0' \"$@\"\n",
    );
    fs::write(dir.path().join("ostadix-install.json"), r#"{"schema":1,"repo_root":"/relocated/OSTADIX","backends_dir":"/relocated/OSTADIX/backends"}"#).unwrap();
    let result = Command::new(&front)
        .arg("root")
        .env_remove("O_LANG_ROOT")
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(result.stdout, b"/relocated/OSTADIX\n");
    let result = Command::new(front)
        .args(["eval", "1"])
        .env_remove("O_LANG_ROOT")
        .env_remove("O_LANG_EVALUATOR_BIN")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"--eval\x001\x00");
}

#[test]
fn failed_explicit_peer_request_does_not_replace_preferred_identity() {
    let dir = tempfile::tempdir().unwrap();
    let peers = dir.path().join("ostadix/peers");
    let pem = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";
    let key = b"-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n";
    o_lang::hosted_remote::store_paired_lan_peer(
        &peers,
        "127.0.0.1:1".parse().unwrap(),
        "unreachable-dispatch-test",
        "localhost",
        1,
        false,
        pem,
        pem,
        key,
        None,
    )
    .unwrap();
    fs::write(peers.join("_preferred"), "selected-rack\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_octl"))
        .args([
            "node",
            "profile",
            "-n",
            "unreachable-dispatch-test",
            "--connect-timeout-seconds",
            "1",
            "--io-timeout-seconds",
            "1",
        ])
        .env("XDG_CONFIG_HOME", dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(peers.join("_preferred")).unwrap(),
        "selected-rack\n"
    );
}

#[test]
fn ordinary_run_human_errors_include_source_graph_without_changing_json_protocol() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("broken.O");
    fs::write(
        &source,
        "python^(\n__oval_result__ = unknown_native_cli_value\n)_python\n",
    )
    .unwrap();
    let invoke = |json: bool| {
        let mut command = Command::new(FRONT);
        command.arg("run").arg(&source).arg("--no-record").env(
            "O_BACKENDS_DIR",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("backends"),
        );
        if json {
            command.arg("--json");
        }
        command.output().unwrap()
    };
    let human = invoke(false);
    assert!(!human.status.success());
    let error = String::from_utf8_lossy(&human.stderr);
    assert!(error.contains("broken.O"), "{error}");
    assert!(error.contains("HGraph"), "{error}");
    let json = invoke(true);
    assert!(!json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert!(
        value["schema"]
            .as_str()
            .is_some_and(|schema| schema.contains("run-summary")),
        "{value}"
    );
    assert!(!String::from_utf8_lossy(&json.stdout).contains("HGraph inspection"));
}

#[test]
fn real_evaluator_smoke_and_relocated_bundled_shims_use_typed_value_protocol() {
    let dir = tempfile::tempdir().unwrap();
    let front = dir.path().join("o");
    fs::copy(FRONT, &front).unwrap();
    fs::copy(
        env!("CARGO_BIN_EXE_O"),
        dir.path().join("ostadix-evaluator"),
    )
    .unwrap();
    let invoke = |args: &[&str]| {
        Command::new(&front)
            .args(args)
            .current_dir(dir.path())
            .env_remove("O_LANG_ROOT")
            .env_remove("O_BACKENDS_DIR")
            .env_remove("BACKENDS_DIR")
            .env_remove("O_LANG_EVALUATOR_BIN")
            .output()
            .unwrap()
    };
    let smoke = invoke(&["smoke"]);
    assert!(
        smoke.status.success(),
        "{}{}",
        String::from_utf8_lossy(&smoke.stdout),
        String::from_utf8_lossy(&smoke.stderr)
    );
    assert_eq!(smoke.stdout, b"2\n");
    let doctor = invoke(&["doctor", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(report["backends"]["python_smoke_passed"], true, "{report}");
    let extracted = std::path::Path::new(report["backends"]["directory"].as_str().unwrap());
    assert!(extracted
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("ostadix-cli-shims_"));
    assert!(
        !extracted.exists(),
        "temporary bundled shims were not cleaned up"
    );
}
