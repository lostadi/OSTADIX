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
