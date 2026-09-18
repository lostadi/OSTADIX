//! Real CLI failures: human stderr must be informative while stdout and exit
//! status remain usable by shells, MCP callers, and source-checking tools.

use std::path::Path;
use std::process::{Command, Output};

fn run(binary: &str, arguments: &[&str], directory: &Path) -> Output {
    Command::new(binary)
        .args(arguments)
        .current_dir(directory)
        .env_remove("O_EXECUTOR")
        .env_remove("O_BACKENDS_DIR")
        .env_remove("BACKENDS_DIR")
        .env_remove("O_LANG_ROOT")
        .output()
        .expect("start native CLI")
}

fn failure(output: &Output) -> String {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "failure polluted stdout: {output:?}"
    );
    let text = String::from_utf8(output.stderr.clone()).unwrap();
    assert!(
        !text.contains('\x1b'),
        "redirected stderr contains terminal escapes: {text}"
    );
    text
}

#[test]
fn o_parse_failure_marks_original_shebang_coordinates_and_never_invents_a_graph() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("broken é.O"),
        "#!/usr/bin/env O\npython^(\n",
    )
    .unwrap();
    let output = run(
        env!("CARGO_BIN_EXE_O"),
        &["--check", "broken é.O"],
        directory.path(),
    );
    let error = failure(&output);
    assert!(error.contains("phase: parse"), "{error}");
    assert!(error.contains("broken é.O:3:1"), "{error}");
    assert!(error.contains("expected )_python"), "{error}");
    assert!(error.contains("HGraph: not constructed"), "{error}");
    assert!(!error.contains("failed P"), "{error}");
}

#[test]
fn json_failure_remains_one_machine_readable_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(
        env!("CARGO_BIN_EXE_O"),
        &["--json", "--check", "--eval", "python^("],
        directory.path(),
    );
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["stage"], "parse");
    assert!(value["error"]
        .as_str()
        .unwrap()
        .contains("Unclosed expression"));
    assert_eq!(value.as_object().unwrap().len(), 3);
}

#[test]
fn json_execution_evidence_preserves_submitted_and_parsed_source_identities() {
    let directory = tempfile::tempdir().unwrap();
    let executable = "text^(héllo)_text\n";
    for (file, source) in [
        ("ordinary.O", executable.to_string()),
        ("shebang.O", format!("#!/usr/bin/env O\n{executable}")),
    ] {
        std::fs::write(directory.path().join(file), &source).unwrap();
        for mode in ["graph", "serial"] {
            let output = run(
                env!("CARGO_BIN_EXE_O"),
                &["--json", "--executor", mode, file],
                directory.path(),
            );
            assert!(output.status.success(), "{output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["ok"], true);
            let evidence = &value["execution_evidence"];
            assert_eq!(evidence["schema"], "ostadix.native-execution-evidence/v1");
            assert_eq!(evidence["execution_mode"], mode);
            assert_eq!(
                evidence["source_sha256"],
                o_lang::evidence::source_sha256(source.as_bytes())
            );
            assert_eq!(
                evidence["parsed_source_sha256"],
                o_lang::evidence::source_sha256(executable.as_bytes())
            );
            assert_eq!(
                evidence["source_identity_scope"],
                "submitted_utf8_before_shebang_removal"
            );
            assert!(evidence["source_intent_gate"].is_null());
            assert!(evidence["admission"].is_object());
            if file == "shebang.O" {
                assert_ne!(evidence["source_sha256"], evidence["parsed_source_sha256"]);
            }
        }
    }
}

#[test]
fn o_runtime_failure_reports_the_real_failed_operation_and_directed_hyperedge() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("failure.O"),
        "#!/usr/bin/env O\n$missing\n",
    )
    .unwrap();
    let output = run(env!("CARGO_BIN_EXE_O"), &["failure.O"], directory.path());
    let error = failure(&output);
    assert!(error.contains("Undefined variable"), "{error}");
    assert!(error.contains("failure.O:2:1"), "{error}");
    assert!(error.contains("failed P0 -> e"), "{error}");
    assert!(error.contains("inputs:"), "{error}");
    assert!(error.contains("outputs:"), "{error}");
    assert!(error.contains("Completion"), "{error}");
    assert!(error.contains("--target dot"), "{error}");
}

#[test]
fn olangc_parse_and_script_failures_keep_source_and_graph_context() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("bad.O"), "python^(\n").unwrap();
    let error = failure(&run(
        env!("CARGO_BIN_EXE_olangc"),
        &["bad.O", "--target", "ir"],
        directory.path(),
    ));
    assert!(error.contains("phase: parse"), "{error}");
    assert!(error.contains("bad.O:2:1"), "{error}");
    std::fs::write(directory.path().join("runtime.O"), "$missing").unwrap();
    let error = failure(&run(
        env!("CARGO_BIN_EXE_olangc"),
        &["runtime.O", "--target", "script"],
        directory.path(),
    ));
    assert!(error.contains("phase: execute script"), "{error}");
    assert!(error.contains("failed P0 -> e"), "{error}");
}

#[test]
fn ocore_type_failure_identifies_native_pipeline_and_the_correct_compilation_unit() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("valid.oc"),
        "module valid;\nfn ok() -> u64 { return 1; }\n",
    )
    .unwrap();
    std::fs::write(
        directory.path().join("bad.oc"),
        "module bad;\nfn wrong() -> u64 { return true; }\n",
    )
    .unwrap();
    let output = run(
        env!("CARGO_BIN_EXE_ocorec"),
        &["valid.oc", "bad.oc", "--emit", "mir", "--output", "-"],
        directory.path(),
    );
    let error = failure(&output);
    assert!(error.contains("bad.oc:2:"), "{error}");
    assert!(error.contains("return true"), "{error}");
    assert!(error.contains("typed HIR -> SSA MIR"), "{error}");
    assert!(
        error.contains("does not construct a hosted O HGraph"),
        "{error}"
    );
    assert!(!error.contains("failed P"), "{error}");
}

#[test]
fn ocore_check_is_parse_only_and_never_writes_an_artifact() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("type_error.oc"),
        "module bad;\nfn wrong() -> u64 { return true; }\n",
    )
    .unwrap();
    let output = run(
        env!("CARGO_BIN_EXE_ocorec"),
        &["--check", "type_error.oc"],
        directory.path(),
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"ok\n");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    std::fs::write(
        directory.path().join("syntax_error.oc"),
        "module bad;\nfn broken( -> u64 { return 0; }\n",
    )
    .unwrap();
    let error = failure(&run(
        env!("CARGO_BIN_EXE_ocorec"),
        &["--check", "syntax_error.oc"],
        directory.path(),
    ));
    assert!(error.contains("phase: parse only"), "{error}");
    assert!(error.contains("syntax_error.oc:2:"), "{error}");
    let output = run(
        env!("CARGO_BIN_EXE_ocorec"),
        &["--check", "type_error.oc", "--emit", "mir"],
        directory.path(),
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}
