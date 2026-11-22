use rmcp::{model::CallToolResult, ErrorData as McpError};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const LEAN_BIN_ENV: &str = "OSTADIX_LEAN";
const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_DECLARATIONS: usize = 64;
const DEFAULT_TIMEOUT_SECS: u64 = 120;
const MAX_TIMEOUT_SECS: u64 = 900;
const STANDARD_AXIOMS: [&str; 3] = ["propext", "Classical.choice", "Quot.sound"];

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckArgs {
    /// Complete Lean 4 module source. Supply exactly one of source or path.
    source: Option<String>,
    /// Existing Lean 4 source file. Relative paths resolve against cwd, then O_LANG_ROOT.
    path: Option<String>,
    /// Working directory used for imports and relative paths.
    cwd: Option<String>,
    /// Bounded compiler deadline in seconds, from 1 through 900; default 120.
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifyArgs {
    /// Complete Lean 4 module source containing every named declaration and its proof.
    source: Option<String>,
    /// Existing Lean 4 source file containing every named declaration and its proof.
    path: Option<String>,
    /// Working directory used for imports and relative paths.
    cwd: Option<String>,
    /// Nonempty list of fully qualified ASCII declaration names to inspect with #print axioms.
    declarations: Vec<String>,
    /// Complete permitted axiom set. Omit for propext, Classical.choice, and Quot.sound; pass [] to require axiom-free proofs. sorryAx is always rejected.
    #[serde(default = "default_allowed_axioms")]
    allowed_axioms: Vec<String>,
    /// Bounded compiler deadline in seconds, from 1 through 900; default 120.
    timeout_secs: Option<u64>,
}

fn default_allowed_axioms() -> Vec<String> {
    STANDARD_AXIOMS.map(str::to_string).to_vec()
}

struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn new() -> Result<Self, String> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("read clock for Lean workspace: {error}"))?
            .as_nanos();
        for attempt in 0..100_u8 {
            let path = std::env::temp_dir().join(format!(
                "ostadix-lean-{}-{unique}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                            .map_err(|error| format!("secure Lean workspace: {error}"))?;
                    }
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("create Lean workspace: {error}")),
            }
        }
        Err("could not allocate a unique Lean workspace".to_string())
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct PreparedSource {
    _workspace: Workspace,
    snapshot: PathBuf,
    display_path: String,
    source_kind: &'static str,
    source_sha256: String,
    source_bytes: usize,
    cwd: PathBuf,
    text: String,
}

fn timeout_secs(requested: Option<u64>) -> Result<u64, String> {
    let value = requested.unwrap_or(DEFAULT_TIMEOUT_SECS);
    if !(1..=MAX_TIMEOUT_SECS).contains(&value) {
        return Err(format!(
            "timeout_secs must be between 1 and {MAX_TIMEOUT_SECS}"
        ));
    }
    Ok(value)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.split('.').all(|component| {
            let mut characters = component.chars();
            characters
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
                && characters.all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '\'')
                })
        })
}

fn validate_names(names: &[String], label: &str) -> Result<(), String> {
    if names.len() > MAX_DECLARATIONS {
        return Err(format!("{label} accepts at most {MAX_DECLARATIONS} names"));
    }
    let unique = names.iter().collect::<BTreeSet<_>>();
    if unique.len() != names.len() {
        return Err(format!("{label} must not contain duplicates"));
    }
    if let Some(name) = names.iter().find(|name| !valid_name(name)) {
        return Err(format!(
            "invalid fully qualified ASCII Lean name in {label}: {name:?}"
        ));
    }
    Ok(())
}

fn prepare_source(
    source: Option<String>,
    path: Option<String>,
    cwd: Option<String>,
) -> Result<PreparedSource, String> {
    let root = super::resolve_lang_root();
    let (text, cwd, display_path, source_kind) = match (source, path) {
        (Some(_), Some(_)) | (None, None) => {
            return Err("supply exactly one of source or path".to_string())
        }
        (Some(text), None) => {
            let cwd = super::resolve_directory(&root, cwd.as_deref(), "Lean cwd")?;
            (text, cwd, "<inline>".to_string(), "inline")
        }
        (None, Some(path)) => {
            let (source_path, cwd) = super::resolve_run_target(&root, &path, cwd.as_deref())?;
            let bytes = std::fs::read(&source_path)
                .map_err(|error| format!("read Lean source {}: {error}", source_path.display()))?;
            let text = String::from_utf8(bytes)
                .map_err(|_| "Lean source must be valid UTF-8".to_string())?;
            (text, cwd, source_path.display().to_string(), "path")
        }
    };
    if text.is_empty() {
        return Err("Lean source must not be empty".to_string());
    }
    if text.len() > MAX_SOURCE_BYTES {
        return Err(format!(
            "Lean source exceeds the {} byte limit",
            MAX_SOURCE_BYTES
        ));
    }
    let source_sha256 = hex::encode(Sha256::digest(text.as_bytes()));
    let workspace = Workspace::new()?;
    let snapshot = workspace.path.join("OstadixCheck.lean");
    std::fs::write(&snapshot, text.as_bytes())
        .map_err(|error| format!("write private Lean source snapshot: {error}"))?;
    Ok(PreparedSource {
        _workspace: workspace,
        snapshot,
        display_path,
        source_kind,
        source_sha256,
        source_bytes: text.len(),
        cwd,
        text,
    })
}

fn resolve_lean(cwd: &Path, runtime_search: &super::RuntimeSearchPath) -> Result<PathBuf, String> {
    if let Some(configured) = std::env::var_os(LEAN_BIN_ENV) {
        if configured.is_empty() {
            return Err(format!("{LEAN_BIN_ENV} must not be empty"));
        }
        let path = PathBuf::from(configured);
        if !path.is_absolute() {
            return Err(format!("{LEAN_BIN_ENV} must be an absolute path"));
        }
        return which::which(&path)
            .map_err(|error| format!("configured Lean 4 is unavailable: {error}"));
    }
    which::which_in("lean", Some(&runtime_search.encoded), cwd).map_err(|_| {
        "Lean 4 is unavailable; install lean on PATH or set OSTADIX_LEAN to its absolute path"
            .to_string()
    })
}

fn base_result(prepared: &PreparedSource, version: &str, lean: &Path) -> Value {
    json!({
        "source": {
            "kind": prepared.source_kind,
            "path": prepared.display_path,
            "bytes": prepared.source_bytes,
            "sha256": prepared.source_sha256,
        },
        "toolchain": {
            "name": "Lean 4",
            "version": version,
            "executable": lean,
        },
        "scope": "Lean checks only the submitted formal module; natural-language claims and unconstrained agent inference are not proved"
    })
}

fn diagnostics(stdout: &str, stderr: &str, prepared: &PreparedSource) -> Value {
    let clean = |text: &str| {
        text.replace(
            &prepared.snapshot.display().to_string(),
            &prepared.display_path,
        )
    };
    json!({"stdout": clean(stdout), "stderr": clean(stderr)})
}

async fn version(lean: &Path, cwd: &Path, timeout: u64) -> Result<String, String> {
    let (code, stdout, stderr) =
        super::run_structured_cmd(lean, &["--version"], Some(cwd), &[], timeout.min(10)).await?;
    if code != 0 {
        return Err(format!("lean --version failed: {stdout}{stderr}"));
    }
    let version = stdout.trim();
    if version.is_empty() || !version.to_ascii_lowercase().contains("lean") {
        return Err("lean --version returned an unrecognized toolchain identity".to_string());
    }
    Ok(version.to_string())
}

fn infrastructure_failure(schema: &str, error: impl Into<String>) -> Value {
    json!({
        "schema": schema,
        "status": "infrastructure_failed",
        "checked": false,
        "verified": false,
        "error": error.into(),
    })
}

fn respond(value: Value, accepted: bool) -> Result<CallToolResult, McpError> {
    if accepted {
        super::structured_result(value)
    } else {
        Ok(CallToolResult::structured_error(value))
    }
}

pub(crate) async fn check(
    args: CheckArgs,
    runtime_search: &super::RuntimeSearchPath,
) -> Result<CallToolResult, McpError> {
    match check_inner(args, runtime_search).await {
        Ok((value, checked)) => respond(value, checked),
        Err(error) => respond(
            infrastructure_failure("ostadix.lean-check/v1", error),
            false,
        ),
    }
}

async fn check_inner(
    args: CheckArgs,
    runtime_search: &super::RuntimeSearchPath,
) -> Result<(Value, bool), String> {
    let timeout = timeout_secs(args.timeout_secs)?;
    let prepared = prepare_source(args.source, args.path, args.cwd)?;
    let lean = resolve_lean(&prepared.cwd, runtime_search)?;
    let version = version(&lean, &prepared.cwd, timeout).await?;
    let snapshot = prepared
        .snapshot
        .to_str()
        .ok_or("Lean snapshot path is not UTF-8")?;
    let (code, stdout, stderr) = super::run_structured_cmd(
        &lean,
        &["--trust=0", "--json", snapshot],
        Some(&prepared.cwd),
        &[(
            "PATH",
            runtime_search.encoded.to_string_lossy().into_owned(),
        )],
        timeout,
    )
    .await?;
    let checked = code == 0;
    let mut result = base_result(&prepared, &version, &lean);
    result["schema"] = "ostadix.lean-check/v1".into();
    result["status"] = if checked { "checked" } else { "rejected" }.into();
    result["checked"] = checked.into();
    result["verified"] = false.into();
    result["exit_code"] = code.into();
    result["diagnostics"] = diagnostics(&stdout, &stderr, &prepared);
    Ok((result, checked))
}

pub(crate) async fn verify(
    args: VerifyArgs,
    runtime_search: &super::RuntimeSearchPath,
) -> Result<CallToolResult, McpError> {
    match verify_inner(args, runtime_search).await {
        Ok((value, verified)) => respond(value, verified),
        Err(error) => respond(
            infrastructure_failure("ostadix.lean-verification/v1", error),
            false,
        ),
    }
}

fn parse_axiom_dependencies(output: &str, declaration: &str) -> Result<Vec<String>, String> {
    let depends = format!("'{declaration}' depends on axioms: [");
    let independent = format!("'{declaration}' does not depend on any axioms");
    let mut found = None;
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let message: Value = serde_json::from_str(line).map_err(|error| {
            format!("Lean returned non-JSON diagnostic output during verification: {error}")
        })?;
        let Some(report) = message.get("data").and_then(Value::as_str) else {
            continue;
        };
        let report = report.trim();
        let axioms = if report == independent {
            Vec::new()
        } else if let Some(rest) = report.strip_prefix(&depends) {
            let rest = rest
                .strip_suffix(']')
                .ok_or_else(|| format!("malformed axiom report for {declaration}"))?;
            if rest.trim().is_empty() {
                Vec::new()
            } else {
                rest.split(',')
                    .map(|name| name.trim().to_string())
                    .collect()
            }
        } else {
            continue;
        };
        if axioms.iter().any(|name| !valid_name(name)) {
            return Err(format!("invalid axiom name in report for {declaration}"));
        }
        if found.replace(axioms).is_some() {
            return Err(format!("duplicate #print axioms report for {declaration}"));
        }
    }
    found.ok_or_else(|| format!("Lean returned no exact #print axioms report for {declaration}"))
}

pub(crate) async fn verify_claim(
    source: Option<String>,
    path: Option<String>,
    cwd: Option<String>,
    declarations: Vec<String>,
    allowed_axioms: Option<Vec<String>>,
    timeout_secs: Option<u64>,
    runtime_search: &super::RuntimeSearchPath,
) -> Result<(Value, bool), String> {
    verify_inner(
        VerifyArgs {
            source,
            path,
            cwd,
            declarations,
            allowed_axioms: allowed_axioms.unwrap_or_else(default_allowed_axioms),
            timeout_secs,
        },
        runtime_search,
    )
    .await
}

async fn verify_inner(
    args: VerifyArgs,
    runtime_search: &super::RuntimeSearchPath,
) -> Result<(Value, bool), String> {
    let timeout = timeout_secs(args.timeout_secs)?;
    if args.declarations.is_empty() {
        return Err("declarations must name at least one proved declaration".to_string());
    }
    validate_names(&args.declarations, "declarations")?;
    validate_names(&args.allowed_axioms, "allowed_axioms")?;
    let allowed = args
        .allowed_axioms
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut prepared = prepare_source(args.source, args.path, args.cwd)?;
    for declaration in &args.declarations {
        prepared
            .text
            .push_str(&format!("\n#print axioms {declaration}\n"));
    }
    std::fs::write(&prepared.snapshot, prepared.text.as_bytes())
        .map_err(|error| format!("write Lean verification snapshot: {error}"))?;
    let lean = resolve_lean(&prepared.cwd, runtime_search)?;
    let version = version(&lean, &prepared.cwd, timeout).await?;
    let snapshot = prepared
        .snapshot
        .to_str()
        .ok_or("Lean snapshot path is not UTF-8")?;
    let (code, stdout, stderr) = super::run_structured_cmd(
        &lean,
        &["--trust=0", "--json", snapshot],
        Some(&prepared.cwd),
        &[(
            "PATH",
            runtime_search.encoded.to_string_lossy().into_owned(),
        )],
        timeout,
    )
    .await?;
    let combined = format!("{stdout}\n{stderr}");
    let mut declarations = Vec::new();
    let mut verified = code == 0;
    for declaration in &args.declarations {
        match parse_axiom_dependencies(&combined, declaration) {
            Ok(axioms) => {
                let disallowed = axioms
                    .iter()
                    .filter(|name| name.as_str() == "sorryAx" || !allowed.contains(name.as_str()))
                    .cloned()
                    .collect::<Vec<_>>();
                if !disallowed.is_empty() {
                    verified = false;
                }
                declarations.push(json!({
                    "name": declaration,
                    "axioms": axioms,
                    "disallowed_axioms": disallowed,
                    "verified": disallowed.is_empty() && code == 0,
                }));
            }
            Err(error) => {
                verified = false;
                declarations.push(json!({
                    "name": declaration,
                    "verified": false,
                    "error": error,
                }));
            }
        }
    }
    let mut result = base_result(&prepared, &version, &lean);
    result["schema"] = "ostadix.lean-verification/v1".into();
    result["status"] = if verified { "verified" } else { "rejected" }.into();
    result["checked"] = (code == 0).into();
    result["verified"] = verified.into();
    result["exit_code"] = code.into();
    result["declarations"] = declarations.into();
    result["allowed_axioms"] = args.allowed_axioms.into();
    result["diagnostics"] = diagnostics(&stdout, &stderr, &prepared);
    Ok((result, verified))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_cannot_inject_lean_commands() {
        for valid in ["theorem_one", "Nat.add_succ", "Foo._private.bar'"] {
            assert!(valid_name(valid), "valid name rejected: {valid}");
        }
        for invalid in [
            "",
            ".foo",
            "foo.",
            "foo..bar",
            "foo\n#print axioms sorryAx",
            "foo bar",
            "1foo",
            "foo-bar",
        ] {
            assert!(!valid_name(invalid), "invalid name accepted: {invalid}");
        }
    }

    #[test]
    fn axiom_reports_require_exact_declarations() {
        let report = |data: &str| serde_json::json!({"data": data}).to_string();
        assert_eq!(
            parse_axiom_dependencies(&report("'proof' does not depend on any axioms"), "proof")
                .unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            parse_axiom_dependencies(
                &report("'proof' depends on axioms: [propext, Classical.choice, Quot.sound]"),
                "proof"
            )
            .unwrap(),
            ["propext", "Classical.choice", "Quot.sound"]
        );
        assert!(parse_axiom_dependencies(
            &report("'other' does not depend on any axioms"),
            "proof"
        )
        .is_err());
        assert!(
            parse_axiom_dependencies(&report("'proof' depends on axioms: [sorryAx]"), "other")
                .is_err()
        );
        assert!(
            parse_axiom_dependencies("'proof' does not depend on any axioms", "proof").is_err()
        );
        assert!(parse_axiom_dependencies(
            &format!(
                "{}\n{}",
                report("'proof' does not depend on any axioms"),
                report("'proof' depends on axioms: [sorryAx]")
            ),
            "proof"
        )
        .is_err());
    }

    #[test]
    fn sorry_is_never_an_allowed_axiom() {
        let allowed = BTreeSet::from(["sorryAx".to_string()]);
        let axioms = ["sorryAx".to_string()];
        let disallowed = axioms
            .iter()
            .filter(|name| name.as_str() == "sorryAx" || !allowed.contains(name.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(disallowed.len(), 1);
    }

    #[test]
    fn verification_requires_bounded_time_and_explicit_declarations() {
        assert_eq!(timeout_secs(None).unwrap(), DEFAULT_TIMEOUT_SECS);
        assert!(timeout_secs(Some(0)).is_err());
        assert!(timeout_secs(Some(MAX_TIMEOUT_SECS + 1)).is_err());
        let allowed = default_allowed_axioms();
        assert_eq!(allowed, STANDARD_AXIOMS);
    }
}
