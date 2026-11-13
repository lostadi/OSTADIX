//! Exact review witnesses and hosted value/code separation regressions.
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use o_lang::eval::Evaluator;
use o_lang::ir::{BackendRegistry, OIr, OIrProgram};
use o_lang::parser::Parser;
use o_lang::value::OValue;
use serde_json::Value;

mod support;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Capture into private regular files: an escaped actor retaining a pipe must
/// not turn the timeout's diagnostic collection into an unbounded reader join.
fn run(source: &str, executor: &str, check: bool) -> (bool, Value, String) {
    let stdout = tempfile::NamedTempFile::new().unwrap();
    let stderr = tempfile::NamedTempFile::new().unwrap();
    let lifecycle = tempfile::NamedTempFile::new().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_O"));
    command.env("O_LIFECYCLE_TRACE", lifecycle.path());
    command.args(["--json", "--executor", executor]);
    if check {
        command.arg("--check");
    }
    command
        .args(["--eval", source])
        .arg(root().join("backends"));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.reopen().unwrap()))
        .stderr(Stdio::from(stderr.reopen().unwrap()));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().expect("launch freshly compiled O");
    let start = Instant::now();
    let mut timed_out = false;
    #[cfg(target_os = "linux")]
    let mut timeout_diagnostics = String::new();
    #[cfg(not(target_os = "linux"))]
    let timeout_diagnostics = "owned process state requires Linux";
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() >= Duration::from_secs(5) {
            timed_out = true;
            #[cfg(target_os = "linux")]
            let descendants = owned_descendants(child.id());
            // Sample the exact owned processes before cancellation destroys
            // the evidence. Never inspect unrelated args or environments.
            #[cfg(target_os = "linux")]
            {
                timeout_diagnostics = format!(
                    "owned_processes_before_kill={}",
                    owned_process_snapshot(child.id(), &descendants)
                );
            }
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            #[cfg(not(unix))]
            child.kill().unwrap();
            #[cfg(target_os = "linux")]
            for (pid, started) in descendants.into_iter().rev() {
                if process_identity(pid).is_some_and(|(_, current)| current == started) {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                }
            }
            break child.wait().unwrap();
        }
        thread::sleep(Duration::from_millis(10));
    };
    let read = |file: &tempfile::NamedTempFile| {
        let mut data = Vec::new();
        file.reopen()
            .unwrap()
            .take(4 * 1024 * 1024)
            .read_to_end(&mut data)
            .unwrap();
        data
    };
    let out = read(&stdout);
    let err = read(&stderr);
    let err = String::from_utf8_lossy(&err).into_owned();
    let trace = if timed_out {
        use std::io::{Seek, SeekFrom};
        let mut file = lifecycle.reopen().unwrap();
        let size = file.metadata().unwrap().len();
        file.seek(SeekFrom::Start(size.saturating_sub(64 * 1024)))
            .unwrap();
        let mut trace = Vec::new();
        file.take(64 * 1024).read_to_end(&mut trace).unwrap();
        trace
    } else {
        Vec::new()
    };
    assert!(
        !timed_out,
        "guest exceeded 5s ({executor}): {source}\nstdout={}\nstderr={err}\n{timeout_diagnostics}\nlifecycle_trace={} ",
        String::from_utf8_lossy(&out),
        String::from_utf8_lossy(&trace),
    );
    let json = serde_json::from_slice(&out).unwrap_or(Value::Null);
    (status.success(), json, err)
}

#[cfg(target_os = "linux")]
fn process_identity(pid: u32) -> Option<(u32, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = stat
        .get(stat.rfind(')')? + 2..)?
        .split_whitespace()
        .collect();
    Some((fields.get(1)?.parse().ok()?, fields.get(19)?.parse().ok()?))
}

/// Cleanup is restricted to descendants observed under this freshly spawned
/// test process; start-time checks refuse a PID reused during cancellation.
#[cfg(target_os = "linux")]
fn owned_descendants(parent: u32) -> Vec<(u32, u64)> {
    let processes: Vec<_> = std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|entry| {
            let pid = entry.ok()?.file_name().to_str()?.parse::<u32>().ok()?;
            let (ppid, started) = process_identity(pid)?;
            Some((pid, ppid, started))
        })
        .collect();
    let mut parents = vec![parent];
    let mut result = Vec::new();
    let mut cursor = 0;
    while cursor < parents.len() {
        let parent = parents[cursor];
        for &(pid, ppid, started) in &processes {
            if ppid == parent {
                parents.push(pid);
                result.push((pid, started));
            }
        }
        cursor += 1;
    }
    result
}

/// Bounded diagnostics for already-observed owned identities. A raced or
/// reused PID is omitted; data is limited to kernel state and task names.
#[cfg(target_os = "linux")]
fn owned_process_snapshot(parent: u32, descendants: &[(u32, u64)]) -> Value {
    let mut identities = Vec::new();
    if let Some((_, started)) = process_identity(parent) {
        identities.push((parent, started));
    }
    identities.extend_from_slice(descendants);
    let total = identities.len();
    let mut rows = Vec::new();
    let snapshot_started = Instant::now();
    let mut sample_limit_reached = false;
    for (pid, started) in identities.into_iter().take(32) {
        if snapshot_started.elapsed() >= Duration::from_millis(100) {
            sample_limit_reached = true;
            break;
        }
        if !process_identity(pid).is_some_and(|(_, actual)| actual == started) {
            continue;
        }
        let directory = Path::new("/proc").join(pid.to_string());
        let stat = std::fs::read_to_string(directory.join("stat"))
            .ok()
            .and_then(|stat| {
                let open = stat.find('(')?;
                let close = stat.rfind(')')?;
                let fields = stat
                    .get(close + 2..)?
                    .split_whitespace()
                    .collect::<Vec<_>>();
                Some(serde_json::json!({
                    "comm": stat.get(open + 1..close)?,
                    "state": fields.first()?,
                    "ppid": fields.get(1)?.parse::<u32>().ok()?,
                    "pgrp": fields.get(2)?.parse::<u32>().ok()?,
                    "utime_ticks": fields.get(11)?.parse::<u64>().ok()?,
                    "stime_ticks": fields.get(12)?.parse::<u64>().ok()?,
                    "num_threads": fields.get(17)?.parse::<u32>().ok()?,
                    "starttime": fields.get(19)?.parse::<u64>().ok()?,
                }))
            });
        let wchan = std::fs::read_to_string(directory.join("wchan")).ok();
        let mut tasks = Vec::new();
        let mut tasks_truncated = false;
        if let Ok(entries) = std::fs::read_dir(directory.join("task")) {
            for (index, entry) in entries.flatten().enumerate() {
                if index >= 8 || snapshot_started.elapsed() >= Duration::from_millis(100) {
                    tasks_truncated = true;
                    break;
                }
                tasks.push(serde_json::json!({
                    "tid": entry.file_name().to_string_lossy(),
                    "comm": std::fs::read_to_string(entry.path().join("comm")).ok(),
                    "wchan": std::fs::read_to_string(entry.path().join("wchan")).ok(),
                }));
            }
        }
        if process_identity(pid).is_some_and(|(_, actual)| actual == started) {
            rows.push(serde_json::json!({
                "pid": pid,
                "starttime": started,
                "stat": stat,
                "wchan": wchan,
                "tasks_up_to_8": tasks,
                "tasks_truncated": tasks_truncated,
            }));
        }
    }
    serde_json::json!({
        "observed_count": total,
        "processes_truncated": total > rows.len() || sample_limit_reached,
        "snapshot_elapsed_ms": snapshot_started.elapsed().as_millis(),
        "processes_up_to_32": rows,
    })
}

fn value(source: &str, executor: &str) -> OValue {
    let (ok, json, error) = run(source, executor, false);
    assert!(ok, "{executor}: {source}\n{json}\n{error}");
    serde_json::from_value(json["value"].clone()).expect("tagged OValue result")
}

fn producer(payload: &str) -> String {
    format!(
        "let payload = python^(__import__('base64').b64decode('{}').decode('utf-8'))_python\n",
        STANDARD.encode(payload.as_bytes())
    )
}

#[test]
fn shell_quote_and_comment_boundaries_precede_all_producer_effects() {
    if !support::require_runtimes(&["python3", "bash"]) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("must-not-exist");
    let first = format!(
        "python^(__import__('pathlib').Path({:?}).write_text('effect'))_python\n",
        marker.to_str().unwrap()
    );
    let payload = "; printf QUOTE_BOUNDARY_CHANGED; # $(printf QUOTE_BOUNDARY_CHANGED)";
    for (prefix, suffix) in [
        (r"\$'a\'b' ", " '"),
        (r"\\\$'a\'b' ", " '"),
        (r"$$'a\'b' ", " '"),
        (r"$$$$'a\'b' ", " '"),
        ("$\\\n'a\\' ", "'"),
        ("printf \"%s\" \"$\\\n(printf \"%s\" \"", "\")\""),
        ("printf ignored x#\"\n ", "\n\""),
        ("printf ignored x\\ #\"\n ", "\n\""),
        ("printf ignored x\u{a0}#\"\n ", "\n\""),
    ] {
        // Rust's O parser consumes backslash-dollar escapes. Preserve the
        // exact guest prefix independently of the receiver's quote rules.
        let prefix = prefix.replace('$', "\\$");
        let source = format!(
            "{first}{}bash^({prefix}$payload{suffix})_bash",
            producer(payload)
        );
        for executor in ["serial", "graph"] {
            for check in [true, false] {
                let (ok, _, error) = run(&source, executor, check);
                assert!(
                    !ok && error.contains("foreign value splice"),
                    "{source}\n{error}"
                );
                assert!(!marker.exists(), "producer ran before refusal: {source}");
            }
        }
    }
    for prefix in [
        r"$'a\'b'",
        r"\\$'a\'b'",
        r"\\\\$'a\'b'",
        r"$$$'a\'b'",
        r"\$'a\b'",
        "$$'plain'",
    ] {
        let prefix = prefix.replace('$', "\\$");
        let source = format!(
            "{}bash^(: {prefix}; printf '%s' $payload)_bash",
            producer(payload)
        );
        for executor in ["serial", "graph"] {
            assert_eq!(value(&source, executor), OValue::str_(payload));
        }
    }
    let source = format!(
        "{first}{}shell^(: \\$'a\\'b'; printf '%s' $payload)_shell",
        producer(payload)
    );
    for executor in ["serial", "graph"] {
        let (ok, _, error) = run(&source, executor, false);
        assert!(!ok && error.contains("foreign value splice"), "{error}");
        assert!(!marker.exists());
        let source = format!("{}shell^(printf '%s' $payload)_shell", producer(payload));
        assert_eq!(value(&source, executor), OValue::str_(payload));
    }
}

#[test]
fn exact_seven_review_witnesses_are_data_or_rejected_before_execution() {
    if !support::require_runtimes(&["python3", "sqlite3", "bash"]) {
        return;
    }
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/foreign-splice-witnesses.json")).unwrap();
    assert_eq!(fixtures["witnesses"].as_array().unwrap().len(), 7);
    for witness in fixtures["witnesses"].as_array().unwrap() {
        let source = witness["source"].as_str().unwrap();
        for executor in ["serial", "graph"] {
            let accepted = witness["ordinary_contract_accepts"].as_bool().unwrap();
            let (ok, _, error) = run(source, executor, true);
            assert_eq!(
                ok, accepted,
                "check witness {} {executor}: {error}",
                witness["number"]
            );
            if !accepted {
                assert!(error.contains("foreign value splice"), "{error}");
                let (ok, _, error) = run(source, executor, false);
                assert!(!ok && error.contains("foreign value splice"), "{error}");
                continue;
            }
            match witness["number"].as_u64().unwrap() {
                1 => assert_eq!(
                    value(source, executor),
                    OValue::list(vec![OValue::int(7), OValue::str_("O'Brien")])
                ),
                6 => assert_eq!(
                    value(source, executor),
                    OValue::str_("[a\"; echo SPLICED-AS-CODE; echo \"]")
                ),
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn corrected_unquoted_holes_and_native_bash_bindings_preserve_adversarial_text() {
    if !support::require_runtimes(&["python3", "sqlite3", "bash", "node"]) {
        return;
    }
    let mut payloads = vec![
        "O'Brien".to_string(),
        "nobody' UNION SELECT 'spliced-as-code".into(),
        "a\"; echo SPLICED-AS-CODE; echo \"".into(),
        "$(printf SPLICED-AS-CODE)`printf no`".into(),
        "line1\n.line2\r\t\\\"'${name} λ😀".into(),
        "/* */ -- # \\\nquote\"".into(),
    ];
    // Fixed seed makes each failing payload replayable without shrinking away
    // control bytes or quoting characters that caused the failure.
    let alphabet: Vec<char> = "ab09'\"\\$`();#/*-={}[]\n\r\t λ😀".chars().collect();
    let mut random = 0x4f5f53504c494345_u64;
    for _ in 0..18 {
        let mut text = String::new();
        for _ in 0..48 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            text.push(alphabet[(random as usize) % alphabet.len()]);
        }
        payloads.push(text);
    }
    for payload in payloads {
        let expected = OValue::str_(hex::encode(payload.as_bytes()));
        for executor in ["serial", "graph"] {
            let prefix = producer(&payload);
            assert_eq!(
                value(
                    &(prefix.clone() + "python^( $payload.encode('utf-8').hex() )_python"),
                    executor
                ),
                expected
            );
            let sql = value(
                &(prefix.clone() + "sql^( SELECT lower(hex($payload)) AS h; )_sql"),
                executor,
            );
            assert_eq!(sql, expected, "SQLite payload {payload:?}");
            let tail = " | od -An -v -tx1 | tr -d ' \\n' )_bash";
            assert_eq!(
                value(
                    &(prefix.clone() + "bash^( printf '%s' $payload" + tail),
                    executor
                ),
                expected
            );
            assert_eq!(
                value(
                    &(prefix.clone() + "bash^( printf '%s' \"${payload}\"" + tail),
                    executor
                ),
                expected
            );
            assert_eq!(value(&(prefix + "javascript^( console.log(Buffer.from($payload, 'utf8').toString('hex')) )_javascript"), executor), expected);
        }
    }
}

#[test]
fn native_nix_literal_profile_keeps_interpolation_and_quotes_inert() {
    if !support::require_runtimes(&["python3", "nix"]) {
        return;
    }
    for payload in [
        "O'Brien",
        "${builtins.abort \"SPLICED-AS-CODE\"}",
        "a\"\\\nλ😀",
    ] {
        for executor in ["serial", "graph"] {
            assert_eq!(
                value(&(producer(payload) + "nix^( $payload )_nix"), executor),
                OValue::str_(payload)
            );
        }
    }
}

#[test]
fn javascript_value_map_keys_do_not_mutate_the_object_prototype() {
    if !support::require_runtimes(&["python3", "node"]) {
        return;
    }
    let source = r#"let payload = python^({'__proto__': {'polluted': True}, 'constructor': 'ordinary', 'quote"key': 'text'})_python
javascript^( const obj = $payload; console.log(JSON.stringify([Object.prototype.hasOwnProperty.call(obj, '__proto__'), Object.getPrototypeOf(obj) === Object.prototype, obj['__proto__'].polluted, obj.constructor, obj['quote"key']])); )_javascript"#;
    for executor in ["serial", "graph"] {
        assert_eq!(
            value(source, executor),
            OValue::list(vec![
                OValue::bool_(true),
                OValue::bool_(true),
                OValue::bool_(true),
                OValue::str_("ordinary"),
                OValue::str_("text"),
            ])
        );
    }
}

#[test]
fn finite_numeric_values_remain_numeric_in_sql_and_javascript() {
    if !support::require_runtimes(&["python3", "sqlite3", "node"]) {
        return;
    }
    for executor in ["serial", "graph"] {
        let prefix = "let payload = python^(1.25)_python\n";
        assert_eq!(
            value(
                &(prefix.to_owned() + "sql^( SELECT typeof($payload) AS kind; )_sql"),
                executor
            ),
            OValue::str_("real")
        );
        assert_eq!(value(&(prefix.to_owned() + "javascript^( console.log(typeof $payload + ':' + ($payload + 1)); )_javascript"), executor), OValue::str_("number:2.25"));
    }
}

#[test]
fn nul_is_data_in_python_sql_javascript_and_refused_by_shell_words() {
    if !support::require_runtimes(&["python3", "sqlite3", "bash", "node"]) {
        return;
    }
    let payload = "before\0after'\"; echo SPLICED-AS-CODE";
    let expected = OValue::str_(hex::encode(payload.as_bytes()));
    for executor in ["serial", "graph"] {
        let prefix = producer(payload);
        assert_eq!(
            value(
                &(prefix.clone() + "python^( $payload.encode('utf-8').hex() )_python"),
                executor
            ),
            expected
        );
        assert_eq!(
            value(
                &(prefix.clone() + "sql^( SELECT lower(hex($payload)) AS h; )_sql"),
                executor
            ),
            expected
        );
        assert_eq!(value(&(prefix.clone() + "javascript^( console.log(Buffer.from($payload, 'utf8').toString('hex')) )_javascript"), executor), expected);
        let (ok, _, error) = run(
            &(prefix + "bash^( printf '%s' $payload )_bash"),
            executor,
            false,
        );
        assert!(!ok && error.to_ascii_lowercase().contains("nul"), "{error}");
    }
}

#[test]
fn explicit_code_marker_is_plan_visible_and_does_not_stick_to_stored_text() {
    if !support::require_runtime("python3") {
        return;
    }
    for executor in ["serial", "graph"] {
        let source = "let source = text^(40 + 2)_text\npython^( $!source )_python";
        let (ok, result, error) = run(source, executor, false);
        assert!(ok, "{error}");
        assert_eq!(
            serde_json::from_value::<OValue>(result["value"].clone()).unwrap(),
            OValue::int(42)
        );
        let records = result["execution_evidence"]["trace"]["source_renderings"]
            .as_array()
            .unwrap();
        let code = records
            .iter()
            .find(|record| record["role"] == "explicit_code")
            .unwrap();
        assert_eq!(code["phase"], "prepared");
        assert_eq!(code["scope"], "rendered_fragment_not_guest_execution");
        assert_eq!(code["value_type"], "text");
        assert_eq!(code["fidelity"], "reinterpretation");
        assert_eq!(code["reinterpreted_as_code"], true);
        assert_eq!(
            code["value_sha256"],
            o_lang::backend_morphism::observed_value_sha256(&OValue::str_("40 + 2"))
        );
        use sha2::{Digest, Sha256};
        assert_eq!(
            code["rendered_fragment_sha256"],
            hex::encode(Sha256::digest(b"40 + 2"))
        );
        assert_eq!(
            code["final_body_sha256"],
            hex::encode(Sha256::digest(b" 40 + 2 "))
        );
        let ordinary_source = "let source = text^(40 + 2)_text\nlet ordinary = code($source)\npython^( $ordinary )_python";
        let (ok, ordinary, error) = run(ordinary_source, executor, false);
        assert!(ok, "{error}");
        let records = ordinary["execution_evidence"]["trace"]["source_renderings"]
            .as_array()
            .unwrap();
        let literal = records
            .iter()
            .find(|record| record["language"] == "python")
            .unwrap();
        assert_eq!(literal["role"], "value");
        assert_eq!(literal["value_type"], "text");
        assert_eq!(literal["fidelity"], "structural");
        assert_eq!(literal["reinterpreted_as_code"], false);
        assert_eq!(
            literal["rendered_fragment_sha256"],
            hex::encode(Sha256::digest(b"\"40 + 2\""))
        );
        assert_eq!(value("let source = text^(40 + 2)_text\nlet ordinary = code($source)\npython^( $ordinary )_python", executor), OValue::str_("40 + 2"));
    }
    let tags: HashSet<_> = ["text", "python"].into_iter().map(str::to_owned).collect();
    let nodes = Parser::new(
        "let source = text^(40 + 2)_text\npython^( $!source )_python",
        &tags,
    )
    .parse()
    .unwrap();
    let program = OIrProgram::lower(&nodes);
    assert!(program
        .to_text()
        .contains("reinterpretation only as immediate foreign splice; no authority grant"));
    assert!(program.to_text().contains("code"));
}

#[test]
fn code_marker_does_not_create_a_backend_authority_grant() {
    if !support::require_runtime("bash") {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("must-not-exist");
    // Hosted rights are ambient by contract; an arbitrary {cap=absent}
    // attribute is not a required grant. Test the real boundary instead:
    // code cannot stringify a live capability, or alter the supplied scope.
    let source = format!(
        "bash^( $!cap; printf effect > '{}' )_bash",
        marker.display()
    );
    let tags = HashSet::from(["bash".to_owned()]);
    let nodes = Parser::new(&source, &tags).parse().unwrap();
    let program = OIrProgram::lower(&nodes);
    let cap = OValue::capability(
        o_lang::value::CapabilityKind::File,
        "splice-regression-file",
        HashMap::new(),
    );
    for graph in [false, true] {
        let mut evaluator = Evaluator::new(root().join("backends"));
        let mut scope = HashMap::from([("cap".to_owned(), cap.clone())]);
        let error = if graph {
            evaluator.eval_ir_program_graph_with_scope(&program, &mut scope)
        } else {
            evaluator.eval_ir_program_serial_with_scope(&program, &mut scope)
        }
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(
            error.contains("explicit code splice") && error.contains("capability"),
            "{error}"
        );
        assert!(!marker.exists());
        assert_eq!(scope.len(), 1);
        assert_eq!(scope.get("cap"), Some(&cap));
    }
}

#[test]
fn prepared_code_observations_survive_guest_failure_but_quotes_remain_unused() {
    if !support::require_runtime("python3") {
        return;
    }
    for executor in ["serial", "graph"] {
        let (ok, result, _) = run(
            "let source = text^(if !!!)_text\npython^( $!source )_python",
            executor,
            false,
        );
        assert!(!ok);
        assert!(result["execution_evidence"]["trace"]["source_renderings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["role"] == "explicit_code" && record["phase"] == "prepared"));
        let (ok, result, error) = run("quote^(python^($!unused)_python)_quote", executor, false);
        assert!(ok, "{error}");
        assert!(result["execution_evidence"]["trace"]["source_renderings"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}

#[test]
fn autonomous_code_and_inline_code_both_record_actual_preparation() {
    if !support::require_runtime("python3") {
        return;
    }
    for executor in ["serial", "graph"] {
        for source in [
            "let source = text^(40 + 2)_text\nautonomous(all(python^( $!source )_python))",
            "let source = text^(<b>raw</b>)_text\nhtml^( $!source )_html",
        ] {
            let (ok, result, error) = run(source, executor, false);
            assert!(ok, "{error}");
            assert!(result["execution_evidence"]["trace"]["source_renderings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|record| record["role"] == "explicit_code"
                    && record["fidelity"] == "reinterpretation"));
        }
    }
}

#[test]
fn trace_api_exposes_typed_preparation_records_for_actual_inline_code() {
    let tags: HashSet<_> = ["text", "html"].into_iter().map(str::to_owned).collect();
    let nodes = Parser::new(
        "let source = text^(<b>raw</b>)_text\nhtml^( $!source )_html",
        &tags,
    )
    .parse()
    .unwrap();
    let program = OIrProgram::lower(&nodes);
    for graph in [false, true] {
        let mut evaluator = Evaluator::new(root().join("backends"));
        let mut scope = HashMap::new();
        let result = if graph {
            evaluator.eval_ir_program_graph_with_scope(&program, &mut scope)
        } else {
            evaluator.eval_ir_program_serial_with_scope(&program, &mut scope)
        }
        .unwrap();
        assert_eq!(result, OValue::html(" <b>raw</b> "));
        let record = evaluator
            .last_execution_trace()
            .unwrap()
            .source_renderings
            .iter()
            .find(|record| record.role == "explicit_code")
            .unwrap();
        assert_eq!(
            record.fidelity,
            o_lang::eval::RenderFidelity::Reinterpretation
        );
        assert_eq!(record.phase, "prepared");
        assert!(record.reinterpreted_as_code && record.final_body_sha256.is_some());
    }
}

#[test]
fn failed_receiver_preparation_retains_fragments_without_a_completed_body_claim() {
    if !support::require_runtimes(&["python3", "bash"]) {
        return;
    }
    let source = "let a = text^(safe)_text\nlet payload = python^(chr(0))_python\nbash^(printf '%s%s' $a $payload)_bash";
    for executor in ["serial", "graph"] {
        let (ok, result, error) = run(source, executor, false);
        assert!(!ok && error.to_ascii_lowercase().contains("nul"), "{error}");
        let records = result["execution_evidence"]["trace"]["source_renderings"]
            .as_array()
            .unwrap();
        let shell: Vec<_> = records
            .iter()
            .filter(|record| record["language"] == "bash")
            .collect();
        assert_eq!(shell.len(), 2);
        assert!(shell
            .iter()
            .all(|record| record["phase"] == "prepared" && record["final_body_sha256"].is_null()));
    }
}

#[test]
fn direct_oir_lexical_rejection_precedes_an_earlier_host_effect() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("must-not-exist");
    let effect = format!(
        "__import__('pathlib').Path({:?}).write_text('effect')",
        marker.to_str().unwrap()
    );
    let exec = |lang: &str, body| OIr::Exec {
        lang: lang.into(),
        env_id: u32::MAX,
        attr: None,
        backend: BackendRegistry::global().interface_for(lang),
        body,
    };
    let cases = [
        (
            "sql",
            vec![
                OIr::Text("SELECT '".into()),
                OIr::Load("payload".into()),
                OIr::Text("';".into()),
            ],
        ),
        (
            "python",
            vec![
                OIr::Text("t\"{ \"prefix ".into()),
                OIr::Load("payload".into()),
                OIr::Text(" suffix\" }\"".into()),
            ],
        ),
        (
            "bash",
            vec![
                OIr::Text("printf '%s' \\".into()),
                OIr::Load("payload".into()),
                OIr::Text("\n".into()),
            ],
        ),
        (
            "bash",
            vec![
                OIr::Text("[[ ".into()),
                OIr::Load("payload".into()),
                OIr::Text(" -gt 0 ]]".into()),
            ],
        ),
    ];
    for (language, body) in cases {
        for graph in [false, true] {
            let program = OIrProgram {
                nodes: vec![
                    exec("python", vec![OIr::Text(effect.clone())]),
                    exec(language, body.clone()),
                ],
            };
            let mut evaluator = Evaluator::new(root().join("backends"));
            let mut scope = HashMap::from([("payload".into(), OValue::str_("unsafe"))]);
            let error = if graph {
                evaluator.eval_ir_program_graph_with_scope(&program, &mut scope)
            } else {
                evaluator.eval_ir_program_serial_with_scope(&program, &mut scope)
            }
            .unwrap_err();
            assert!(
                error.to_string().contains("foreign value splice"),
                "{error:#}"
            );
            assert!(
                !marker.exists(),
                "validation must precede every guest effect"
            );
            assert!(evaluator.last_execution_admission().is_none());
        }
    }
}

#[test]
fn unsupported_nested_guest_grammars_are_rejected_before_host_effects() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("must-not-exist");
    let first = format!(
        "python^(__import__('pathlib').Path({:?}).write_text('effect'))_python\n",
        marker.to_str().unwrap()
    );
    let cases = [
        "python^( f\"{ \"prefix $payload suffix\" }\" )_python",
        "python^( t\"{ \"prefix $payload suffix\" }\" )_python",
        "python^( T\"{ \"prefix $payload suffix\" }\" )_python",
        "python^( tr\"{ \"prefix $payload suffix\" }\" )_python",
        "py^( rT\"{ \"prefix $payload suffix\" }\" )_py",
        "nix^( \"${ \"prefix $payload suffix\" }\" )_nix",
        "javascript^( `outer${`inner $payload suffix`}` )_javascript",
        "bash^( printf '%s' \"$(printf \"$payload\")\" )_bash",
        "bash^( printf '%s' $(( $payload )) )_bash",
        "bash^( [[ $payload -gt 0 ]] )_bash",
        "bash^( printf '%s' array[$payload] )_bash",
        "bash^( printf '%s' \"${array[$payload]}\" )_bash",
        "javascript^( <!-- $payload\n42 )_javascript",
        "javascript^( --> $payload\n42 )_javascript",
        "javascript^( #! interpreter $payload\n42 )_javascript",
        "javascript^( \\u{61}$payload )_javascript",
        "python^( prefix\\\n$payload )_python",
        "nix^( /tmp/$payload )_nix",
        "nix^( <$payload> )_nix",
    ];
    for source in cases {
        for executor in ["serial", "graph"] {
            let (ok, _, error) = run(&(first.clone() + source), executor, false);
            assert!(
                !ok && error.contains("foreign value splice"),
                "{source}: {error}"
            );
            assert!(
                !marker.exists(),
                "nested grammar must reject before earlier effects"
            );
        }
    }
}

#[test]
fn bare_shell_special_parameters_preserve_native_syntax_and_status() {
    let tags = HashSet::from(["bash".to_owned(), "shell".to_owned()]);
    let body = " printf '%s' \"$!\" \"$?\" ";
    for language in ["bash", "shell"] {
        let source = format!("{language}^({body})_{language}");
        let nodes = Parser::new(&source, &tags).parse().unwrap();
        let [o_lang::parser::ONode::TypedExpr { body: parsed, .. }] = nodes.as_slice() else {
            panic!("guest special parameters changed the typed-expression shape")
        };
        assert_eq!(parsed, &vec![o_lang::parser::ONode::RawText(body.into())]);
        assert_eq!(o_lang::parser::reconstruct_source(&nodes), source);
    }
    if !support::require_runtime("bash") {
        return;
    }
    for executor in ["serial", "graph"] {
        assert_eq!(
            value("bash^( (exit 0) & wait $!; printf '%s' $? )_bash", executor),
            OValue::int(0)
        );
        assert_eq!(
            value(
                "bash^( if false; then :; else printf '%s' $?; fi )_bash",
                executor
            ),
            OValue::int(1)
        );
    }
}

#[cfg(target_os = "linux")]
fn timeout_snapshot(diagnostic: &str) -> Value {
    let snapshot = diagnostic
        .split("owned_processes_before_kill=")
        .nth(1)
        .and_then(|text| text.split('\n').next())
        .expect("owned process snapshot before kill");
    serde_json::from_str(snapshot).expect("structured process snapshot")
}

/// These controls exercise the same five-second CLI watchdog and prove that
/// its retained pre-kill evidence distinguishes the two real guest stages.
#[cfg(target_os = "linux")]
fn expected_stage_timeout(source: &str) -> String {
    let panic = std::panic::catch_unwind(|| run(source, "serial", false))
        .expect_err("deliberately stalled guest must hit the unchanged five-second watchdog");
    let diagnostic = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| text.to_string()))
        .expect("timeout must retain a textual diagnostic");
    assert!(
        diagnostic.contains("guest exceeded 5s (serial)"),
        "{diagnostic}"
    );
    let snapshot = timeout_snapshot(&diagnostic);
    let rows = snapshot["processes_up_to_32"].as_array().unwrap();
    assert!(!rows.is_empty(), "{diagnostic}");
    // SIGKILL delivery and VM teardown of a descendant can complete after
    // the already-waited root. This separate assertion budget does not alter
    // the guest's original five-second execution deadline.
    let cleanup_deadline = Instant::now() + Duration::from_secs(2);
    for row in rows {
        let pid = row["pid"].as_u64().unwrap() as u32;
        let started = row["starttime"].as_u64().unwrap();
        while let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            let fields = stat
                .get(stat.rfind(')').unwrap() + 2..)
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>();
            let current = fields[19].parse::<u64>().unwrap();
            if current != started || matches!(fields[0], "Z" | "X") {
                break;
            }
            assert!(
                Instant::now() < cleanup_deadline,
                "owned process {pid} starttime={started} remains active after cleanup: state={}",
                fields[0]
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    diagnostic
}

#[cfg(target_os = "linux")]
#[test]
fn timeout_diagnostics_identify_python_before_javascript_launch() {
    if !support::require_runtimes(&["python3", "node"]) {
        return;
    }
    let source = "let payload = python^(__import__('time').sleep(6))_python\njavascript^( console.log('unreached') )_javascript";
    let diagnostic = expected_stage_timeout(source);
    assert!(
        diagnostic.contains("event=proxy.shim_spawned language=python"),
        "{diagnostic}"
    );
    assert!(
        !diagnostic.contains("event=worker.backend_spawned language=javascript"),
        "{diagnostic}"
    );
    assert!(diagnostic.contains("python3"), "{diagnostic}");
}

#[cfg(target_os = "linux")]
#[test]
fn timeout_diagnostics_identify_native_javascript_after_python_retirement() {
    if !support::require_runtimes(&["python3", "node"]) {
        return;
    }
    let source = producer("O'Brien") + "javascript^( Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 6000); console.log(Buffer.from($payload, 'utf8').toString('hex')); )_javascript";
    let diagnostic = expected_stage_timeout(&source);
    assert!(
        diagnostic.contains("event=worker.backend_wait_returned language=python"),
        "{diagnostic}"
    );
    assert!(
        diagnostic
            .contains("event=backend.script_spawned language=javascript command=node child_pid="),
        "{diagnostic}"
    );
    assert!(
        !diagnostic.contains("event=backend.script_output_collected language=javascript"),
        "{diagnostic}"
    );
    // Node versions choose different kernel thread names (for example
    // `node` or `MainThread`). Bind the observed owned row to the launch
    // event's PID; this diagnostic comparison grants no process authority.
    let child_pid = diagnostic
        .lines()
        .find_map(|line| {
            if !line.contains(" event=backend.script_spawned language=javascript command=node ") {
                return None;
            }
            line.split_whitespace()
                .find_map(|field| field.strip_prefix("child_pid=")?.parse::<u64>().ok())
        })
        .expect("native JavaScript launch event retains its child PID");
    let snapshot = timeout_snapshot(&diagnostic);
    let row = snapshot["processes_up_to_32"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["pid"].as_u64() == Some(child_pid))
        .expect("launched Node PID is present in the identity-checked owned snapshot");
    assert_eq!(row["stat"]["starttime"], row["starttime"], "{diagnostic}");
}
