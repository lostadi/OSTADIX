//! Structured operation-project lifecycle over the authoritative native CLI.
//!
//! This module constructs literal arguments and projects retained JSON output.
//! Native operation records, planner checks, execution and observation remain
//! owned by o-cli; the MCP does not maintain another planner or success model.

use super::schemars;
use super::*;
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, Default, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Action {
    #[default]
    Describe,
    Realizations,
    Plan,
    Explain,
    Run,
    Observe,
    Replan,
}

impl Action {
    fn token(self) -> &'static str {
        match self {
            Self::Describe => "describe",
            Self::Realizations => "realizations",
            Self::Plan => "plan",
            Self::Explain => "explain",
            Self::Run => "run",
            Self::Observe => "observe",
            Self::Replan => "replan",
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationArgs {
    /// Existing operation-project directory containing olang.project.toml with
    /// an explicit [operation] section. Relative paths use cwd or O_LANG_ROOT.
    path: String,
    /// describe (default), realizations, plan, explain (plan with causal
    /// reasons), run (the only action that dispatches), observe, or replan.
    #[serde(default)]
    action: Action,
    /// Retained run ID or last-run; accepted only by observe and replan.
    /// Omission uses native last-run. Exact IDs avoid ambiguity between runs.
    run: Option<String>,
    /// Exact declared target IDs to exclude. Required only for replan, which
    /// computes an alternative without dispatching it.
    #[serde(default)]
    without_targets: Vec<String>,
    /// Working directory. An absolute path defaults this to the project;
    /// relative paths default to O_LANG_ROOT, matching o_execute.
    cwd: Option<String>,
    /// Per-child environment overrides, isolated from other jobs and calls.
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// Foreground default 120 seconds; background default no deadline.
    /// Zero disables the local deadline. Native execution limits still apply.
    timeout_secs: Option<u64>,
    /// Return a managed job immediately. Use o_job_status/read to inspect its
    /// result. Full native JSON and stderr remain in the retained job logs.
    #[serde(default)]
    background: bool,
}

impl OperationArgs {
    fn validate(&self) -> Result<(), String> {
        nonempty_token(&self.path, "path")?;
        if let Some(cwd) = &self.cwd {
            nonempty_token(cwd, "cwd")?;
        }
        if let Some(run) = &self.run {
            if !matches!(self.action, Action::Observe | Action::Replan) {
                return Err("run is accepted only for observe and replan".into());
            }
            nonempty_token(run, "run")?;
        }
        if self.action == Action::Replan {
            if self.without_targets.is_empty() {
                return Err("replan requires at least one without_targets entry".into());
            }
            let mut seen = std::collections::BTreeSet::new();
            for target in &self.without_targets {
                nonempty_token(target, "without_targets entry")?;
                if !seen.insert(target) {
                    return Err(format!(
                        "without_targets contains a duplicate target: {target:?}"
                    ));
                }
            }
        } else if !self.without_targets.is_empty() {
            return Err("without_targets is accepted only for replan".into());
        }
        validate_child_input(&[], &self.env)
    }

    fn native_args(&self, path: &Path) -> Vec<String> {
        let mut args = vec![match self.action {
            Action::Describe => "operation",
            Action::Realizations => "realizations",
            Action::Plan | Action::Explain => "plan",
            Action::Run => "run",
            Action::Observe => "observe",
            Action::Replan => "replan",
        }
        .into()];
        args.push(path.display().to_string());
        args.push("--json".into());
        // The native marker requirement applies in the same invocation that
        // plans or dispatches, so an unmarked project cannot become a generic
        // project execution after an earlier read-only marker probe.
        if matches!(self.action, Action::Plan | Action::Explain | Action::Run) {
            args.push("--operation-required".into());
        }
        if self.action == Action::Explain {
            args.push("--explain".into());
        }
        if let Some(run) = &self.run {
            args.push(format!("--run={run}"));
        }
        for target in &self.without_targets {
            args.push(format!("--without-target={target}"));
        }
        args
    }
}

fn nonempty_token(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() || value.contains('\0') {
        return Err(format!("{label} must be nonempty and contain no NUL bytes"));
    }
    Ok(())
}

fn resolve_input(root: &Path, args: &OperationArgs) -> Result<(PathBuf, PathBuf), String> {
    let requested = Path::new(&args.path);
    let cwd = match args.cwd.as_deref() {
        Some(cwd) => resolve_directory(root, Some(cwd), "working directory")?,
        None if requested.is_absolute() => resolve_directory(requested, None, "operation project")?,
        None => resolve_directory(root, None, "working directory")?,
    };
    let path = resolve_directory(&cwd, Some(&args.path), "operation project")?;
    if path.to_str().is_none() || cwd.to_str().is_none() {
        return Err("operation project and working directory must be valid UTF-8".into());
    }
    Ok((cwd, path))
}

impl OstadixMcp {
    pub(super) async fn execute_operation(
        &self,
        args: OperationArgs,
        context: &RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(error) = args.validate() {
            return structured_failure(error);
        }
        let root = resolve_lang_root();
        let (cwd, path) = match resolve_input(&root, &args) {
            Ok(input) => input,
            Err(error) => return structured_failure(error),
        };
        let argv = args.native_args(&path);
        // native_job has request-token cancellation and the same session-owned
        // concurrent job manager as o_execute/o_cli. No global serialization.
        let mut result = match self
            .native_job(
                CliArgs {
                    command: "o-cli".into(),
                    args: argv.clone(),
                    cwd: Some(cwd.display().to_string()),
                    env: args.env,
                    stdin: None,
                    timeout_secs: args.timeout_secs.or(if args.background {
                        None
                    } else {
                        Some(120)
                    }),
                    background: args.background,
                    pty: false,
                },
                context,
            )
            .await
        {
            Ok(result) => result,
            Err(error) => return structured_failure(error),
        };
        result["action"] = json!(args.action.token());
        result["input"] = json!({"kind": "operation-project", "path": path, "cwd": cwd});
        result["native_command"] = json!({"command": "o-cli", "args": argv});
        if result["state"] != "running" && result["stdout"]["path"].is_string() {
            let projection = super::unified::bounded_stdout(&result, false)
                .await
                .and_then(|stdout| super::unified::native_json(&stdout));
            match projection {
                Ok(native) => result["result"] = native,
                Err(error) => {
                    result["result"] = Value::Null;
                    result["result_projection_error"] = json!(error);
                    result["result_retrieval"] = json!({
                        "tool": "o_job_read", "job_id": result["job_id"],
                        "stream": "stdout", "offset": 0, "full_output_retained": true,
                    });
                }
            }
        }
        if (result["state"] == "running"
            || (result["state"] == "completed" && result["exit_code"] == 0))
            && result.get("error").is_none_or(Value::is_null)
        {
            structured_result(result)
        } else {
            Ok(CallToolResult::structured_error(result))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn request(value: Value) -> OperationArgs {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn default_is_read_only_description_and_fields_are_strict() {
        let args = request(json!({"path": "/project"}));
        args.validate().unwrap();
        assert_eq!(args.action, Action::Describe);
        assert_eq!(
            args.native_args(Path::new("/project")),
            ["operation", "/project", "--json"]
        );
        assert!(serde_json::from_value::<OperationArgs>(json!({
            "path": "/project", "action": "execute"
        }))
        .is_err());
        assert!(serde_json::from_value::<OperationArgs>(json!({
            "path": "/project", "route": "unreviewed"
        }))
        .is_err());
    }

    #[test]
    fn planning_and_execution_require_native_operation_marker() {
        for action in ["plan", "explain", "run"] {
            let args = request(json!({"path": "/project", "action": action}));
            args.validate().unwrap();
            let argv = args.native_args(Path::new("/project"));
            assert!(argv.iter().any(|value| value == "--operation-required"));
            assert_eq!(
                argv.iter().any(|value| value == "--explain"),
                action == "explain"
            );
            assert_eq!(argv[0], if action == "run" { "run" } else { "plan" });
        }
    }

    #[test]
    fn replan_and_observe_keep_selectors_literal() {
        let args = request(json!({
            "path": "/project with spaces", "action": "replan",
            "run": "--help", "without_targets": ["-local", "target $(literal)"]
        }));
        args.validate().unwrap();
        assert_eq!(
            args.native_args(Path::new("/project with spaces")),
            [
                "replan",
                "/project with spaces",
                "--json",
                "--run=--help",
                "--without-target=-local",
                "--without-target=target $(literal)"
            ]
        );
        let observe = request(json!({"path": "/project", "action": "observe", "run": "exact-id"}));
        observe.validate().unwrap();
        assert_eq!(
            observe.native_args(Path::new("/project")),
            ["observe", "/project", "--json", "--run=exact-id"]
        );
    }

    #[test]
    fn irrelevant_or_ambiguous_constraints_are_rejected() {
        for value in [
            json!({"path": ""}),
            json!({"path": "/project", "cwd": ""}),
            json!({"path": "/project", "action": "run", "run": "last-run"}),
            json!({"path": "/project", "action": "plan", "without_targets": ["local"]}),
            json!({"path": "/project", "action": "replan"}),
            json!({"path": "/project", "action": "replan", "without_targets": [""]}),
            json!({"path": "/project", "action": "replan", "without_targets": ["same", "same"]}),
            json!({"path": "/project", "action": "observe", "run": ""}),
            json!({"path": "/project", "env": {"INVALID=KEY": "value"}}),
        ] {
            let args = request(value.clone());
            assert!(
                args.validate().is_err(),
                "accepted invalid arguments: {value}"
            );
        }
    }

    #[test]
    fn project_and_cwd_resolution_matches_source_first_interface() {
        let fixture = crate::tests::Fixture::new();
        let root = &fixture.0;
        let project = root.join("project");
        let workspace = root.join("workspace");
        fs::create_dir(&project).unwrap();
        fs::create_dir(&workspace).unwrap();
        let root_path = root.canonicalize().unwrap();
        let project_path = project.canonicalize().unwrap();
        let workspace_path = workspace.canonicalize().unwrap();
        let relative = request(json!({"path": "project"}));
        assert_eq!(
            resolve_input(root, &relative).unwrap(),
            (root_path, project_path.clone())
        );
        let absolute = request(json!({"path": project}));
        assert_eq!(
            resolve_input(root, &absolute).unwrap(),
            (project_path.clone(), project_path.clone())
        );
        let explicit = request(json!({"path": "../project", "cwd": "workspace"}));
        assert_eq!(
            resolve_input(root, &explicit).unwrap(),
            (workspace_path, project_path)
        );
        let file = root.join("not-directory");
        fs::write(&file, b"text").unwrap();
        assert!(resolve_input(root, &request(json!({"path": file}))).is_err());
    }
}
