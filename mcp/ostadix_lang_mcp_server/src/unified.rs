//! Source-first computation. Native runtimes retain responsibility for
//! admission, scheduling, placement, and the meaning of their evidence.

use super::schemars;
use super::*;
use serde_json::{json, Value};
use std::io::Write;

// These bound transport and argv use, never source size or execution capacity.
const MAX_PROJECTED_RESULT_BYTES: u64 = 1024 * 1024;
const MAX_INLINE_ARG_BYTES: usize = 64 * 1024;

mod project_input {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/ostadix-api/src/project/input_kind.inc.rs"
    ));
}

#[path = "selected_node.rs"]
mod selected_node;

#[derive(Clone, Copy, Debug, Default, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Action {
    #[default]
    Execute,
    Check,
    Plan,
    Compile,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Placement {
    #[default]
    Auto,
    Local,
    MeshRequired,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    #[default]
    Direct,
    Admitted,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecuteArgs {
    /// Complete O source. Supply exactly one of source or path.
    source: Option<String>,
    /// Existing .O file or project directory. Absolute paths default cwd to
    /// the file's parent or the project directory; relative paths use cwd/root.
    path: Option<String>,
    /// execute (default), check (parse only), plan (non-executing schedule), or compile.
    #[serde(default)]
    action: Action,
    /// auto uses the local O runtime for ordinary source and native mesh-prefer
    /// placement for projects. mesh-required is supported only for project execution.
    #[serde(default)]
    placement: Placement,
    /// admitted executes through native fresh admission. Ordinary source also
    /// binds an internally analyzed source/intent digest; no client handle is needed.
    #[serde(default)]
    mode: Mode,
    /// For compile: ir, dot, binary (default), or wasm. script is an execution
    /// target and belongs to action execute or the expert o_cli interface.
    target: Option<String>,
    /// Required destination for binary/wasm compilation, relative to cwd.
    /// ir/dot return their text in result and do not accept output.
    output: Option<String>,
    /// Explicit project route or route-set for execute, plan, or IR/DOT output.
    /// Marked operation projects retain their native planner's route selection.
    route: Option<String>,
    /// Send an ordinary complete document to this native node. This is not
    /// graph partitioning. env/cwd configure the local client, not the remote
    /// workspace. Cancelling the client cannot cancel remote effects.
    node: Option<String>,
    cwd: Option<String>,
    /// Per-child environment overrides, isolated from other calls.
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// Initial stdin. Foreground sends EOF; background keeps the pipe open.
    stdin: Option<String>,
    /// Overall operation budget in seconds. Foreground default 120; background
    /// default unlimited. Zero disables the local deadline. Selected-node
    /// execution also retains native IO/publication deadlines (see its result).
    timeout_secs: Option<u64>,
    /// Return the managed execution job immediately after any required analysis.
    #[serde(default)]
    background: bool,
    /// Positive ordinary-O graph worker capacity; also supported for ordinary plans.
    workers: Option<usize>,
}

impl ExecuteArgs {
    fn validate(&self) -> Result<(), String> {
        if self.source.is_some() == self.path.is_some() {
            return Err("supply exactly one of source or path".into());
        }
        if self.source.as_deref().is_some_and(|s| s.contains('\0')) {
            return Err("source must not contain NUL bytes".into());
        }
        if self.workers == Some(0) {
            return Err("workers must be at least 1".into());
        }
        validate_child_input(&[], &self.env)?;
        if let Some(route) = &self.route {
            if route.is_empty() || route.contains('\0') {
                return Err("route must be nonempty and contain no NUL bytes".into());
            }
            if self.action == Action::Check
                || (self.action == Action::Compile
                    && !matches!(self.target.as_deref(), Some("ir" | "dot")))
            {
                return Err("route is supported for project execute, plan, and IR/DOT; compiled project binaries select their route at runtime".into());
            }
        }
        if let Some(node) = &self.node {
            if node.is_empty() || node.contains('\0') {
                return Err("node must be nonempty and contain no NUL bytes".into());
            }
            if self.action != Action::Execute
                || self.mode != Mode::Direct
                || self.placement != Placement::Auto
                || self.workers.is_some()
                || self.stdin.is_some()
                || self.route.is_some()
            {
                return Err("node accepts ordinary execute with native remote admission; local intent binding, placement overrides, workers, application stdin and project routes are unsupported".into());
            }
        }
        if self.mode == Mode::Admitted && self.action != Action::Execute {
            return Err("mode admitted is supported only for action execute".into());
        }
        if self.placement != Placement::Auto && self.action != Action::Execute {
            return Err("placement is supported only for action execute".into());
        }
        if self.action != Action::Compile && (self.target.is_some() || self.output.is_some()) {
            return Err("target and output apply only to action compile".into());
        }
        if self.action == Action::Compile {
            match self.target.as_deref().unwrap_or("binary") {
                "binary" | "wasm" if self.output.as_deref().is_none_or(str::is_empty) => {
                    return Err("binary/wasm compilation requires an explicit output path".into());
                }
                "ir" | "dot" if self.output.is_some() => {
                    return Err("ir/dot compilation returns text in result; native olangc does not write these targets to output".into());
                }
                "ir" | "dot" | "binary" | "wasm" => {}
                "script" => return Err("target script executes code; use action execute or o_cli for the native compiler execution target".into()),
                _ => return Err("compile target must be ir, dot, binary, or wasm".into()),
            }
        }
        if self.workers.is_some() && !matches!(self.action, Action::Execute | Action::Plan) {
            return Err("workers applies only to execute or plan".into());
        }
        Ok(())
    }
}

/// A private, immutable snapshot for native commands that require a filename.
/// Its last owner removes the directory; background jobs retain an owner until
/// their normal completion/cancellation cleanup has finished.
#[derive(Debug)]
struct SourceSnapshot {
    directory: PathBuf,
    path: PathBuf,
}

impl SourceSnapshot {
    fn new(source: &str) -> Result<Arc<Self>, String> {
        let directory =
            std::env::temp_dir().join(format!("ostadix-mcp-source-{}", random_intent_handle()?));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&directory)
            .map_err(|e| format!("create source snapshot: {e}"))?;
        let snapshot = Self {
            path: directory.join("computation.O"),
            directory,
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&snapshot.path)
            .map_err(|e| format!("open source snapshot: {e}"))?;
        file.write_all(source.as_bytes())
            .map_err(|e| format!("write source snapshot: {e}"))?;
        let mut permissions = file.metadata().map_err(|e| e.to_string())?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions)
            .map_err(|e| format!("protect source snapshot: {e}"))?;
        Ok(Arc::new(snapshot))
    }
}

impl Drop for SourceSnapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn is_project_source(source: &str) -> bool {
    project_input::has_embedded_bundle(source)
}

struct Input {
    cwd: PathBuf,
    path: Option<PathBuf>,
    project: bool,
    snapshot: Option<Arc<SourceSnapshot>>,
}

impl Input {
    fn resolve(root: &Path, args: &ExecuteArgs) -> Result<Self, String> {
        if let Some(source) = &args.source {
            let cwd = resolve_directory(root, args.cwd.as_deref(), "working directory")?;
            let project = is_project_source(source);
            let needs_file = project
                || args.node.is_some()
                || args.mode == Mode::Admitted
                || matches!(args.action, Action::Plan | Action::Compile)
                || source.len() > MAX_INLINE_ARG_BYTES;
            let snapshot = needs_file
                .then(|| SourceSnapshot::new(source))
                .transpose()?;
            return Ok(Self {
                cwd,
                path: snapshot.as_ref().map(|s| s.path.clone()),
                project,
                snapshot,
            });
        }
        let requested = args.path.as_deref().ok_or("missing input")?;
        if requested.is_empty() || requested.contains('\0') {
            return Err("path must be nonempty and must not contain NUL bytes".into());
        }
        let requested_path = Path::new(requested);
        let cwd = match args.cwd.as_deref() {
            Some(cwd) => resolve_directory(root, Some(cwd), "working directory")?,
            None if requested_path.is_absolute() => {
                let base = if requested_path.is_dir() {
                    requested_path
                } else {
                    requested_path
                        .parent()
                        .ok_or("input has no parent directory")?
                };
                resolve_directory(base, None, "working directory")?
            }
            None => resolve_directory(root, None, "working directory")?,
        };
        let path = if requested_path.is_absolute() {
            requested_path.to_owned()
        } else {
            cwd.join(requested_path)
        };
        let path = path
            .canonicalize()
            .map_err(|e| format!("resolve input {}: {e}", path.display()))?;
        let project = if path.is_dir() {
            true
        } else if path.is_file() {
            is_project_source(
                &std::fs::read_to_string(&path).map_err(|e| format!("read source: {e}"))?,
            )
        } else {
            return Err("input must be a source file or project directory".into());
        };
        Ok(Self {
            cwd,
            path: Some(path),
            project,
            snapshot: None,
        })
    }
}

fn remaining_timeout(deadline: Option<Instant>) -> Result<Option<u64>, String> {
    match deadline {
        None => Ok(Some(0)),
        Some(deadline) => {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or("computation timeout elapsed before dispatch")?;
            Ok(Some(
                remaining
                    .as_secs()
                    .saturating_add(u64::from(remaining.subsec_nanos() > 0))
                    .max(1),
            ))
        }
    }
}

fn native_json(stdout: &str) -> Result<Value, String> {
    if let Ok(value) = serde_json::from_str(stdout) {
        return Ok(value);
    }
    // O emits its final JSON document on one line. Hosted code may have written
    // ordinary stdout first; retain that output in the raw log and parse only
    // the final nonempty line. Never search for a success-shaped earlier line.
    let last = stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or("native command produced no structured output")?;
    serde_json::from_str(last)
        .map_err(|e| format!("native command did not end with valid JSON: {e}"))
}

fn call_value(result: CallToolResult) -> Result<Value, String> {
    result
        .structured_content
        .ok_or("native command returned no structured job evidence".into())
}

fn completed(value: &Value) -> bool {
    value["state"] == "completed" && value["exit_code"] == 0
}

impl OstadixMcp {
    /// Dispatch through the same session-owned concurrent job machinery as
    /// o_cli. The monitor owns snapshots before the first post-spawn await.
    async fn unified_job(
        &self,
        mut args: CliArgs,
        snapshot: Option<Arc<SourceSnapshot>>,
    ) -> Result<Value, String> {
        let background = args.background;
        args.background = true;
        let started = call_value(
            self.execute_cli_retained(args, snapshot)
                .await
                .map_err(|e| e.to_string())?,
        )?;
        let Some(id) = started["job_id"].as_str().map(str::to_owned) else {
            return Ok(started);
        };
        let mut guard = ForegroundJobGuard {
            jobs: self.jobs.clone(),
            id: id.clone(),
            active: true,
        };
        if background {
            guard.active = false;
            return Ok(started);
        }
        let _ = self.jobs.write(&id, "", true).await;
        let mut result = self.jobs.wait(&id).await?;
        guard.active = false;
        for stream in ["stdout", "stderr"] {
            result[stream] = self.jobs.read(&id, stream, 0, 65536).await?;
        }
        Ok(result)
    }

    pub(super) async fn execute_computation(
        &self,
        args: ExecuteArgs,
    ) -> Result<CallToolResult, McpError> {
        if let Err(error) = args.validate() {
            return structured_failure(error);
        }
        match self.computation(args).await {
            Ok(value)
                if (value["state"] == "running" || completed(&value))
                    && value.get("error").is_none_or(Value::is_null) =>
            {
                structured_result(value)
            }
            Ok(value) => Ok(CallToolResult::structured_error(value)),
            Err(error) => structured_failure(error),
        }
    }

    async fn computation(&self, args: ExecuteArgs) -> Result<Value, String> {
        let timeout = args
            .timeout_secs
            .or(if args.background { None } else { Some(120) });
        let deadline = timeout
            .filter(|seconds| *seconds != 0)
            .map(|seconds| {
                Instant::now()
                    .checked_add(Duration::from_secs(seconds))
                    .ok_or("timeout_secs exceeds the supported clock range")
            })
            .transpose()?;
        let root = resolve_lang_root();
        let backends = resolve_backends(&root);
        let input = Input::resolve(&root, &args)?;
        if let Some(node) = &args.node {
            if input.project {
                return Err("node sends ordinary complete O documents; use native project mesh for project inputs".into());
            }
            return self
                .execute_selected_node(&args, &input, node, deadline)
                .await;
        }
        if input.project {
            if args.action == Action::Check {
                return Err("project inputs support execute, plan, and compile; use plan for a non-executing project validation".into());
            }
            if args.workers.is_some() {
                return Err("project inputs use native project scheduling and do not accept workers; use o_cli for project-specific controls".into());
            }
        } else if args.placement == Placement::MeshRequired {
            return Err("mesh-required needs a native project directory or project bundle; ordinary O currently executes locally".into());
        } else if args.route.is_some() {
            return Err("route requires a project directory or lifted project bundle".into());
        }
        let mut env = args.env.clone();
        let mut analysis = None;
        let mut project_probe = None;
        let mut operation_project = false;
        if input.project
            && args.action == Action::Execute
            && matches!(args.placement, Placement::Auto | Placement::Local)
            && input.path.as_ref().is_some_and(|path| path.is_dir())
        {
            let probe = self
                .unified_job(
                    CliArgs {
                        command: "o-cli".into(),
                        args: vec![
                            "operation".into(),
                            input.path.as_ref().unwrap().display().to_string(),
                            "--json".into(),
                        ],
                        cwd: Some(input.cwd.display().to_string()),
                        env: env.clone(),
                        stdin: None,
                        timeout_secs: remaining_timeout(deadline)?,
                        background: false,
                        pty: false,
                    },
                    None,
                )
                .await?;
            if completed(&probe) {
                if let Ok(description) = bounded_stdout(&probe, false)
                    .await
                    .and_then(|stdout| native_json(&stdout))
                {
                    operation_project = description["schema"]
                        == "ostadix.operation-project-description/v1"
                        && description["status"] == "valid_marked_operation_project";
                }
            }
            project_probe = Some(probe);
        }
        let mut argv = Vec::new();
        let command;
        let json_output;
        let route;
        if input.project && args.action != Action::Compile {
            command = "o-cli";
            json_output = true;
            argv.push(
                if args.action == Action::Plan {
                    "plan"
                } else {
                    "run"
                }
                .into(),
            );
            argv.push(input.path.as_ref().unwrap().display().to_string());
            argv.push("--json".into());
            if let Some(selected) = &args.route {
                argv.push(format!("--route={selected}"));
            }
            route = if args.action == Action::Plan {
                "project-plan"
            } else if operation_project {
                // The marked operation's native planner chooses placement;
                // it rejects external mesh/parallel overrides by design.
                "project-operation"
            } else {
                match args.placement {
                    Placement::Auto => {
                        argv.push("--mesh=prefer".into());
                        "project-mesh-prefer"
                    }
                    Placement::Local => "project-local",
                    Placement::MeshRequired => {
                        argv.push("--mesh=required".into());
                        "project-mesh-required"
                    }
                }
            };
            if args.mode == Mode::Admitted {
                env.insert("O_PROJECT_EXECUTOR".into(), "hgraph".into());
            }
        } else if matches!(args.action, Action::Execute | Action::Check) {
            command = "O";
            json_output = true;
            route = "ordinary-local";
            argv.push("--json".into());
            if args.action == Action::Check {
                argv.push("--check".into());
            } else {
                argv.extend(["--executor".into(), "graph".into()]);
            }
            if let Some(workers) = args.workers {
                argv.extend(["--workers".into(), workers.to_string()]);
            }
            if args.mode == Mode::Admitted {
                let analysis_job = self
                    .unified_job(
                        CliArgs {
                            command: "olangc".into(),
                            args: vec![
                                input.path.as_ref().unwrap().display().to_string(),
                                "--target".into(),
                                "ir".into(),
                                "--shim-dir".into(),
                                backends.display().to_string(),
                                "--execution-intent-json".into(),
                            ],
                            cwd: Some(input.cwd.display().to_string()),
                            env: env.clone(),
                            stdin: None,
                            timeout_secs: remaining_timeout(deadline)?,
                            background: false,
                            pty: false,
                        },
                        input.snapshot.clone(),
                    )
                    .await?;
                if !completed(&analysis_job) {
                    let mut failure = analysis_job;
                    failure["phase"] = json!("analysis");
                    return Ok(failure);
                }
                let document_output = async {
                    let stdout = bounded_stdout(&analysis_job, false).await?;
                    let document = parse_execution_intent(&stdout)?;
                    Ok::<_, String>((stdout, document))
                }
                .await;
                let (stdout, document) = match document_output {
                    Ok(result) => result,
                    Err(error) => {
                        let mut failure = analysis_job;
                        failure["phase"] = json!("analysis");
                        failure["error"] = json!(error);
                        return Ok(failure);
                    }
                };
                argv.extend([
                    "--require-source-sha256".into(),
                    document.source_sha256,
                    "--require-execution-intent-sha256".into(),
                    document.execution_intent_sha256,
                ]);
                analysis = Some(
                    json!({ "intent": native_json(&stdout)?, "job": analysis_job,
                    "meaning": "source and intent binding; execution performs fresh native admission" }),
                );
            }
            if let Some(path) = &input.path {
                argv.push(path.display().to_string());
            } else {
                argv.extend(["--eval".into(), args.source.as_ref().unwrap().clone()]);
            }
            argv.push(backends.display().to_string());
        } else {
            command = "olangc";
            route = if input.project {
                "project-compiler"
            } else {
                "ordinary-compiler"
            };
            let target = if args.action == Action::Plan {
                "ir"
            } else {
                args.target.as_deref().unwrap_or("binary")
            };
            argv.extend([
                input.path.as_ref().unwrap().display().to_string(),
                "--target".into(),
                target.into(),
                "--shim-dir".into(),
                backends.display().to_string(),
            ]);
            json_output = args.action == Action::Plan;
            if args.action == Action::Plan {
                argv.extend([
                    "--explain-schedule".into(),
                    "--format".into(),
                    "json".into(),
                ]);
                if let Some(workers) = args.workers {
                    argv.extend(["--workers".into(), workers.to_string()]);
                }
            }
            if let Some(output) = &args.output {
                argv.extend([
                    "-o".into(),
                    absolute_output(&input.cwd, output)?.display().to_string(),
                ]);
            }
            if let Some(selected) = &args.route {
                argv.push(format!("--route={selected}"));
            }
        }
        let mut result = self
            .unified_job(
                CliArgs {
                    command: command.into(),
                    args: argv,
                    cwd: Some(input.cwd.display().to_string()),
                    env: env.clone(),
                    stdin: args.stdin.clone(),
                    timeout_secs: remaining_timeout(deadline)?,
                    background: args.background,
                    pty: false,
                },
                input.snapshot.clone(),
            )
            .await?;
        result["action"] = json!(match args.action {
            Action::Execute => "execute",
            Action::Check => "check",
            Action::Plan => "plan",
            Action::Compile => "compile",
        });
        result["mode"] = json!(if args.mode == Mode::Admitted {
            "admitted"
        } else {
            "direct"
        });
        result["placement"] = json!({ "requested": match args.placement { Placement::Auto => "auto", Placement::Local => "local", Placement::MeshRequired => "mesh-required" }, "route": route });
        result["input"] = json!({ "kind": if input.project { "project" } else { "ordinary" },
            "source_inline": args.source.is_some(), "path": input.path, "cwd": input.cwd,
            "temporary_source": input.snapshot.is_some() });
        if let Some(analysis) = analysis {
            result["analysis"] = analysis;
        }
        if let Some(probe) = project_probe {
            result["project_probe"] = probe;
        }
        if input.project && args.mode == Mode::Admitted {
            result["admission"] = json!({ "contract": if operation_project {
                "native-operation-planner"
            } else { "native-project-hgraph-or-mesh" }, "source_intent_binding": false });
        }
        if result["state"] != "running" && result["stdout"]["path"].is_string() {
            let projection = bounded_stdout(&result, command == "O")
                .await
                .and_then(|stdout| {
                    if json_output {
                        native_json(&stdout)
                    } else {
                        Ok(json!(stdout))
                    }
                });
            match projection {
                Ok(native) => result["result"] = native,
                Err(error) => {
                    result["result"] = Value::Null;
                    result["result_projection_error"] = json!(error);
                    result["result_retrieval"] = json!({ "tool": "o_job_read", "job_id": result["job_id"],
                        "stream": "stdout", "offset": 0, "full_output_retained": true });
                }
            }
            if let Some(output) = &args.output {
                let target = args.target.as_deref().unwrap_or("binary");
                let path = artifact_output(&input.cwd, output, target)?;
                let metadata = std::fs::metadata(&path).ok();
                result["artifact"] = json!({ "path": path, "target": target,
                    "exists": metadata.as_ref().is_some_and(|m| m.is_file()), "bytes": metadata.map(|m| m.len()) });
            }
        }
        if input.project && args.action == Action::Execute && !args.background && completed(&result)
        {
            if let Some(run_id) = result["result"]["run_id"].as_str().map(str::to_owned) {
                let inspection = async {
                    let job = self
                        .unified_job(
                            CliArgs {
                                command: "o-cli".into(),
                                args: vec!["inspect".into(), run_id.clone(), "--json".into()],
                                cwd: Some(input.cwd.display().to_string()),
                                env,
                                stdin: None,
                                timeout_secs: remaining_timeout(deadline)?,
                                background: false,
                                pty: false,
                            },
                            None,
                        )
                        .await?;
                    let native = bounded_stdout(&job, false)
                        .await
                        .and_then(|stdout| native_json(&stdout));
                    Ok::<_, String>((job, native))
                }
                .await;
                match inspection {
                    Ok((job, Ok(native)))
                        if completed(&job)
                            && native["state"] == "terminal"
                            && native["record"]["run_id"] == run_id =>
                    {
                        if let Some(value) = native["record"].get("decoded_value") {
                            result["value"] = value.clone();
                        }
                        result["record"] = native;
                        result["record_job"] = job;
                    }
                    Ok((job, native)) => {
                        result["record_projection_error"] = json!(native.err().unwrap_or_else(||
                            "native record inspection did not return a terminal record matching this run_id".into()));
                        result["record_job"] = job;
                    }
                    Err(error) => result["record_projection_error"] = json!(error),
                }
            }
        }
        Ok(result)
    }
}

fn absolute_output(cwd: &Path, output: &str) -> Result<PathBuf, String> {
    if output.is_empty() || output.contains('\0') {
        return Err("output must be nonempty and must not contain NUL bytes".into());
    }
    let path = Path::new(output);
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    })
}

fn artifact_output(cwd: &Path, output: &str, target: &str) -> Result<PathBuf, String> {
    let mut path = absolute_output(cwd, output)?;
    // Match both ordinary and project olangc wasm output normalization.
    if target == "wasm" {
        path.set_extension("wasm");
    }
    Ok(path)
}

async fn bounded_stdout(job: &Value, allow_final_line: bool) -> Result<String, String> {
    use tokio::io::AsyncSeekExt;
    let path = job["stdout"]["path"]
        .as_str()
        .ok_or("native command returned no stdout log path")?;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("open native stdout: {e}"))?;
    let bytes = file.metadata().await.map_err(|e| e.to_string())?.len();
    let tail = bytes > MAX_PROJECTED_RESULT_BYTES;
    if tail && !allow_final_line {
        return Err(format!("native output is {bytes} bytes, beyond the {MAX_PROJECTED_RESULT_BYTES}-byte inline projection; retrieve full output with o_job_read"));
    }
    if tail {
        file.seek(std::io::SeekFrom::Start(bytes - MAX_PROJECTED_RESULT_BYTES))
            .await
            .map_err(|e| e.to_string())?;
    }
    let mut buffer = Vec::new();
    file.take(MAX_PROJECTED_RESULT_BYTES)
        .read_to_end(&mut buffer)
        .await
        .map_err(|e| e.to_string())?;
    if tail {
        // Drop the first, potentially partial UTF-8 / JSON line in the tail.
        let first_newline = buffer.iter().position(|byte| *byte == b'\n').ok_or(
            "native final result exceeds the inline projection; retrieve full output with o_job_read")?;
        buffer.drain(..=first_newline);
    }
    String::from_utf8(buffer).map_err(|e| format!("native stdout is not UTF-8: {e}; lossless bytes remain available with o_job_read encoding base64"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(value: Value) -> ExecuteArgs {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn validates_source_path_modes_and_artifact_intent() {
        for value in [
            json!({}),
            json!({"source":"1", "path":"a.O"}),
            json!({"source":"1", "workers":0}),
            json!({"source":"1", "action":"check", "mode":"admitted"}),
            json!({"source":"1", "action":"compile"}),
            json!({"source":"1", "action":"compile", "target":"script"}),
            json!({"source":"1", "action":"compile", "target":"dot", "output":"graph.dot"}),
        ] {
            assert!(args(value).validate().is_err());
        }
        for value in [
            json!({"source":"1"}),
            json!({"source":"1", "mode":"admitted", "workers":2}),
            json!({"source":"1", "action":"compile", "target":"dot"}),
            json!({"path":"a.O", "action":"compile", "target":"wasm", "output":"app.wasm"}),
        ] {
            assert!(args(value).validate().is_ok());
        }
        assert!(
            serde_json::from_value::<ExecuteArgs>(json!({"source":"1", "placement":"meshh"}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<ExecuteArgs>(json!({"source":"1", "unexpected":true}))
                .is_err()
        );
    }

    #[test]
    fn project_detection_matches_native_sentinels() {
        assert!(!is_project_source("# O-PROJECT-BUNDLE-V1 BEGIN"));
        assert!(!is_project_source("#olang-bundle-payload-begin"));
        assert!(is_project_source(
            "# O-PROJECT-BUNDLE-V1 BEGIN\n#olang-bundle-payload-begin"
        ));
    }

    #[test]
    fn selected_node_rejects_unsupported_contracts_before_execution() {
        for extra in [
            json!({"node":""}),
            json!({"node":"bad\u{0000}name"}),
            json!({"mode":"admitted"}),
            json!({"placement":"local"}),
            json!({"placement":"mesh-required"}),
            json!({"workers":2}),
            json!({"stdin":"input"}),
            json!({"route":"main"}),
            json!({"action":"check"}),
            json!({"action":"plan"}),
            json!({"action":"compile", "target":"dot"}),
        ] {
            let mut value = json!({"source":"1", "node":"test-node"});
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(args(value.clone()).validate().is_err(), "{value}");
        }
        assert!(
            args(json!({"source":"1", "node":"test-node", "background":true,
            "env":{"XDG_CONFIG_HOME":"/tmp/fixture"}}))
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn route_selection_preserves_native_compile_time_boundary() {
        for extra in [
            json!({"route":""}),
            json!({"route":"bad\u{0000}route"}),
            json!({"action":"check"}),
            json!({"action":"compile", "target":"binary", "output":"app"}),
            json!({"action":"compile", "target":"wasm", "output":"app"}),
        ] {
            let mut value = json!({"path":"project", "route":"secondary"});
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(args(value.clone()).validate().is_err(), "{value}");
        }
        for extra in [
            json!({}),
            json!({"action":"plan"}),
            json!({"action":"compile", "target":"ir"}),
            json!({"action":"compile", "target":"dot"}),
        ] {
            let mut value = json!({"path":"project", "route":"secondary"});
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(args(value.clone()).validate().is_ok(), "{value}");
        }
    }

    #[test]
    fn projects_json_after_stdout_without_inventing_values() {
        assert_eq!(
            native_json("ordinary output\n{\"ok\":true,\"value\":{\"Int\":2}}\n").unwrap()["value"]
                ["Int"],
            2
        );
        assert_eq!(
            native_json("{\n\"schema\":\"native\"\n}").unwrap()["schema"],
            "native"
        );
        assert!(native_json("{\"ok\":true}\ntrailing corruption").is_err());
        assert!(
            !native_json("{\"ok\":false,\"error\":\"failed\"}").unwrap()["ok"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn snapshot_is_private_and_removed_by_final_owner() {
        let snapshot = SourceSnapshot::new("1 + 1").unwrap();
        let path = snapshot.path.clone();
        let directory = snapshot.directory.clone();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "1 + 1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
        let retained = snapshot.clone();
        drop(snapshot);
        assert!(path.is_file());
        drop(retained);
        assert!(!directory.exists());
    }

    #[test]
    fn large_source_switches_transport_without_changing_content_or_cwd() {
        let source = format!("#{}\n1", "x".repeat(MAX_INLINE_ARG_BYTES + 1));
        let args = args(json!({"source": source}));
        let root = std::env::temp_dir().canonicalize().unwrap();
        let input = Input::resolve(&root, &args).unwrap();
        assert_eq!(input.cwd, root);
        assert_eq!(
            std::fs::read_to_string(input.path.unwrap()).unwrap(),
            source
        );
        assert!(input.snapshot.is_some());
        assert_eq!(
            artifact_output(&root, "app.data", "wasm").unwrap(),
            root.join("app.wasm")
        );
        assert_eq!(
            artifact_output(&root, "app.data", "binary").unwrap(),
            root.join("app.data")
        );
    }

    #[tokio::test]
    async fn bounded_projection_keeps_small_final_value_after_large_stdout() {
        let snapshot = SourceSnapshot::new(&format!(
            "{}\n{{\"ok\":true,\"value\":2}}\n",
            "x".repeat(MAX_PROJECTED_RESULT_BYTES as usize + 64)
        ))
        .unwrap();
        let job = json!({"stdout":{"path":snapshot.path}});
        assert_eq!(
            native_json(&bounded_stdout(&job, true).await.unwrap()).unwrap()["value"],
            2
        );
        assert!(bounded_stdout(&job, false)
            .await
            .unwrap_err()
            .contains("o_job_read"));
        let snapshot = SourceSnapshot::new(&format!(
            "{{\"value\":\"{}\"}}\n",
            "x".repeat(MAX_PROJECTED_RESULT_BYTES as usize + 64)
        ))
        .unwrap();
        let job = json!({"stdout":{"path":snapshot.path}});
        assert!(native_json(&bounded_stdout(&job, true).await.unwrap()).is_err());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn snapshot_retention_cleans_after_cancellation_without_retaining_session() {
        let jobs = execution::JobManager::new();
        let snapshot = SourceSnapshot::new("1").unwrap();
        let path = snapshot.path.clone();
        let started = jobs
            .start_retained(
                execution::ExecutionRequest {
                    program: PathBuf::from("/bin/sh"),
                    args: vec!["-c".into(), "sleep 30".into()],
                    cwd: std::env::temp_dir(),
                    env: BTreeMap::new(),
                    stdin: None,
                    timeout_secs: Some(5),
                    pty: false,
                },
                snapshot,
            )
            .await
            .unwrap();
        assert!(started["job_id"].is_string());
        assert!(path.is_file());
        drop(jobs);
        tokio::time::timeout(Duration::from_secs(5), async {
            while path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("retained input must not keep the manager/session alive");
    }
}
