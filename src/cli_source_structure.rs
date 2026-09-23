//! Descriptive source checks using the runtime's canonical OIR plan.
//! These do not execute, admit, or prove the intent of a program.

use o_lang::ir::{OIrProgram, PlanEdgeKind, PlanNodeKind};
use o_lang::parser::ONode;
use std::collections::BTreeSet;

pub fn describe(nodes: &[ONode]) -> serde_json::Value {
    let program = OIrProgram::lower(nodes);
    let plan = program.plan();
    let stored_loads = plan
        .edges
        .iter()
        .filter_map(|edge| {
            (edge.kind == PlanEdgeKind::Data
                && matches!(plan.nodes[edge.from.0].kind, PlanNodeKind::Store { .. }))
            .then_some(edge.to)
        })
        .collect::<BTreeSet<_>>();
    let mut required = BTreeSet::new();
    let mut languages = BTreeSet::new();
    for node in &plan.nodes {
        match &node.kind {
            PlanNodeKind::Load { name } if !stored_loads.contains(&node.id) => {
                required.insert(name.clone());
            }
            PlanNodeKind::Exec { lang, .. } => {
                languages.insert(lang.clone());
            }
            _ => {}
        }
    }
    serde_json::json!({
        "schema": "ostadix.source-structure/v1",
        "required_initial_bindings": required,
        "languages": languages,
        "top_level_literal_text": nodes.iter().any(|node| matches!(node,
            ONode::RawText(text) if !text.trim().is_empty())),
        "plan_nodes": plan.nodes.len(),
        "backend_syntax_checks": python_syntax_checks(&program),
        "meaning": "static plan structure; no execution or semantic correctness claim"
    })
}

// This diagnostic budget does not limit parsing or executing the O program.
// Bodies outside it are explicitly skipped, preserving the complete plan.
const PYTHON_CHECK_INPUT_BYTES: usize = 1024 * 1024;
const PYTHON_CHECK_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const PYTHON_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

// Candidate source is only passed to ast.parse. Match Python backend source
// normalization, and never import, compile for execution, or evaluate it.
const PYTHON_SYNTAX_CHECK: &str = r#"
import ast, json, sys, textwrap

def binds_result(target):
    if isinstance(target, ast.Name):
        return target.id == "__oval_result__"
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(binds_result(item) for item in target.elts)
    if isinstance(target, ast.Starred):
        return binds_result(target.value)
    return False

def result_capture(module):
    # Describe the shim's publication syntax, not the value or whether a
    # statement will finish. Function/class-local assignments are not module
    # result assignments. Unknown is intentionally permissive for dynamic
    # publication, imports, calls, control flow and persistent backend state.
    for statement in module.body:
        if isinstance(statement, ast.Assign) and any(binds_result(t) for t in statement.targets):
            return "explicit_result"
        if isinstance(statement, (ast.AnnAssign, ast.AugAssign)) and binds_result(statement.target):
            if not isinstance(statement, ast.AnnAssign) or statement.value is not None:
                return "explicit_result"
    if module.body and isinstance(module.body[-1], ast.Expr):
        return "trailing_expression"
    for statement in module.body:
        if (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Name) and statement.value.func.id == "print"
                and not any(keyword.arg in (None, "file") for keyword in statement.value.keywords)):
            return "stdout"
    for statement in module.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = statement.args
            annotated = any(arg.annotation is not None for arg in
                            args.posonlyargs + args.args + args.kwonlyargs
                            + ([args.vararg] if args.vararg else [])
                            + ([args.kwarg] if args.kwarg else []))
            if (statement.name == "__oval_result__" or statement.decorator_list
                    or args.defaults or any(value is not None for value in args.kw_defaults)
                    or statement.returns is not None or annotated
                    or getattr(statement, "type_params", [])):
                return "unknown"
            continue
        if not isinstance(statement, (ast.Assign, ast.AnnAssign, ast.Expr, ast.Pass)):
            return "unknown"
        for node in ast.walk(statement):
            if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript, ast.NamedExpr,
                                 ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp,
                                 ast.GeneratorExp, ast.Await, ast.Yield, ast.YieldFrom)):
                return "unknown"
            if isinstance(node, ast.Name) and node.id == "__oval_result__":
                return "unknown"
    return "none"

records = json.load(sys.stdin)
results = []
for record in records:
    result = {"index": record["index"], "result_capture": "unknown"}
    try:
        module = ast.parse(textwrap.dedent(record["source"]).strip("\n"), filename="<O-python>", mode="exec")
        result["state"] = "valid"
        result["result_capture"] = result_capture(module)
    except SyntaxError as error:
        result.update(state="invalid", message=str(error.msg)[:160], line=error.lineno, column=error.offset)
    except (MemoryError, RecursionError, ValueError) as error:
        result.update(state="unavailable", reason="parser_resource_error", message=type(error).__name__)
    results.append(result)
json.dump(results, sys.stdout, separators=(",", ":"))
"#;

fn python_syntax_checks(program: &OIrProgram) -> Vec<serde_json::Value> {
    use o_lang::ir::OIr;
    let mut checks = Vec::new();
    let mut pending = Vec::new();
    let mut request_bytes = 2usize;
    for (plan_node, node) in program.flatten_for_plan().into_iter().enumerate() {
        let OIr::Exec { backend, body, .. } = node else {
            continue;
        };
        if backend.canonical != "python" {
            continue;
        }
        let mut check = serde_json::json!({
            "language": "python", "plan_node": plan_node, "state": "pending",
            "result_capture": "unknown"
        });
        if body.iter().any(|child| !matches!(child, OIr::Text(_))) {
            check["state"] = "skipped".into();
            check["reason"] = "dynamic_body".into();
        } else {
            let size = body
                .iter()
                .map(|child| match child {
                    OIr::Text(text) => text.len(),
                    _ => 0,
                })
                .sum::<usize>();
            if size > PYTHON_CHECK_INPUT_BYTES.saturating_sub(request_bytes) {
                check["state"] = "skipped".into();
                check["reason"] = "diagnostic_budget".into();
            } else {
                let source = body
                    .iter()
                    .filter_map(|child| match child {
                        OIr::Text(text) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<String>();
                let record = serde_json::json!({"index": checks.len(), "source": source});
                let encoded_size = record.to_string().len() + 1;
                if encoded_size > PYTHON_CHECK_INPUT_BYTES.saturating_sub(request_bytes) {
                    check["state"] = "skipped".into();
                    check["reason"] = "diagnostic_budget".into();
                } else {
                    request_bytes += encoded_size;
                    pending.push(record);
                }
            }
        }
        checks.push(check);
    }
    if pending.is_empty() {
        return checks;
    }
    match run_python_syntax_check(&pending) {
        Ok(results) => {
            for (request, result) in pending.iter().zip(results) {
                let index = request["index"].as_u64().expect("generated index") as usize;
                let check = checks[index].as_object_mut().expect("generated diagnostic");
                for (key, value) in result.as_object().expect("validated diagnostic") {
                    if key != "index" {
                        check.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        Err(error) => {
            for check in &mut checks {
                if check["state"] == "pending" {
                    check["state"] = "unavailable".into();
                    check["reason"] = "checker_unavailable".into();
                    check["message"] = error.to_string().into();
                }
            }
        }
    }
    checks
}

struct SyntaxCheckFiles(std::path::PathBuf);
impl Drop for SyntaxCheckFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_python_syntax_check(
    records: &[serde_json::Value],
) -> anyhow::Result<Vec<serde_json::Value>> {
    use anyhow::{bail, Context};
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::process::{Command, Stdio};
    use std::time::Instant;

    // Use the same PATH-selected Python executable as the hosted Python shim.
    // -I and -S disable local/user imports and site startup customizations.
    let python = which::which("python3").context("python3 was not found for syntax checking")?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).context("syntax check temporary-directory entropy failed")?;
    let directory =
        std::env::temp_dir().join(format!("ostadix-source-check-{}", hex::encode(random)));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&directory)
        .context("could not create syntax check temporary directory")?;
    let files = SyntaxCheckFiles(directory);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut input = options.open(files.0.join("input.json"))?;
    serde_json::to_writer(&mut input, records)?;
    input.flush()?;
    input.seek(SeekFrom::Start(0))?;
    let output = options.open(files.0.join("output.json"))?;
    let mut command = Command::new(python);
    command
        .args(["-I", "-S", "-c", PYTHON_SYNTAX_CHECK])
        .current_dir(&files.0)
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .context("could not start isolated Python syntax checker")?;
    let deadline = Instant::now() + PYTHON_CHECK_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            outcome => {
                // No candidate code runs in this process. Reap the owned
                // checker before returning diagnostics or deleting its files.
                #[cfg(unix)]
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.kill();
                child
                    .wait()
                    .context("could not reap Python syntax checker")?;
                match outcome {
                    Err(error) => {
                        return Err(error).context("could not observe Python syntax checker")
                    }
                    _ => bail!("Python syntax check exceeded its 2-second diagnostic deadline"),
                }
            }
        }
    };
    if !status.success() {
        bail!("Python syntax checker exited unsuccessfully: {status}");
    }
    let mut bytes = Vec::new();
    let mut output = output;
    output.seek(SeekFrom::Start(0))?;
    output
        .take((PYTHON_CHECK_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > PYTHON_CHECK_OUTPUT_BYTES {
        bail!("Python syntax checker exceeded its diagnostic response budget");
    }
    let results: Vec<serde_json::Value> = serde_json::from_slice(&bytes)
        .context("Python syntax checker returned invalid diagnostics")?;
    if results.len() != records.len()
        || results.iter().zip(records).any(|(result, record)| {
            !result.is_object()
                || result["index"] != record["index"]
                || !matches!(
                    result["state"].as_str(),
                    Some("valid" | "invalid" | "unavailable")
                )
        })
    {
        bail!("Python syntax checker returned mismatched diagnostics");
    }
    Ok(results)
}
