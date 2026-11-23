use rmcp::{model::CallToolResult, ErrorData as McpError};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MAX_STATEMENT_BYTES: usize = 4_096;
const MAX_EXCERPT_BYTES: usize = 8_192;
const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimArgs {
    /// Conclusion being offered. Formal mode marks it verified only when it is exactly Lean's reported proposition.
    statement: String,
    /// `formal` runs Lean verification. `citation` reads one file. Omit it and the claim stays unproved.
    mode: Option<String>,
    /// Lean module source. Formal mode accepts exactly one of source or path.
    source: Option<String>,
    /// File to verify or cite. Relative paths resolve against cwd, then O_LANG_ROOT.
    path: Option<String>,
    /// Working directory for relative paths and Lean imports.
    cwd: Option<String>,
    /// Formal mode: fully qualified Lean declarations to audit.
    declarations: Option<Vec<String>>,
    /// Formal mode: permitted axioms. Omit for the Lean default; [] requires axiom-free proofs.
    allowed_axioms: Option<Vec<String>>,
    /// Formal mode: Lean deadline in seconds. Omitted or zero means unlimited.
    timeout_secs: Option<u64>,
    /// Citation mode: exact contiguous excerpt that must occur in the file.
    excerpt: Option<String>,
}

struct Citation {
    path: String,
    bytes: usize,
    sha256: String,
    occurrences: usize,
}

fn validate_statement(statement: &str) -> Result<(), String> {
    if statement.trim().is_empty() {
        return Err("statement must not be empty".to_string());
    }
    if statement.len() > MAX_STATEMENT_BYTES {
        return Err(format!(
            "statement exceeds the {MAX_STATEMENT_BYTES} byte limit"
        ));
    }
    Ok(())
}

fn count_excerpt(text: &str, excerpt: &str) -> Result<usize, String> {
    if excerpt.is_empty() {
        return Err("excerpt must not be empty".to_string());
    }
    if excerpt.len() > MAX_EXCERPT_BYTES {
        return Err(format!("excerpt exceeds the {MAX_EXCERPT_BYTES} byte limit"));
    }
    Ok(text.match_indices(excerpt).count())
}

fn citation_file(path: &str, cwd: Option<&str>) -> Result<PathBuf, String> {
    let root = super::resolve_lang_root();
    let input = Path::new(path);
    let base = if let Some(cwd) = cwd {
        super::resolve_directory(&root, Some(cwd), "citation cwd")?
    } else if input.is_absolute() {
        let parent = input.parent().filter(|parent| !parent.as_os_str().is_empty()).ok_or_else(|| {
            format!("citation path has no parent directory: {}", input.display())
        })?;
        super::resolve_directory(parent, None, "citation cwd")?
    } else {
        super::resolve_directory(&root, None, "citation cwd")?
    };
    let candidate = if input.is_absolute() {
        input.to_path_buf()
    } else {
        base.join(input)
    };
    let metadata = std::fs::symlink_metadata(&candidate).map_err(|error| {
        format!("read citation {}: {error}", candidate.display())
    })?;
    if metadata.file_type().is_symlink() {
        return Err("citation path must not be a symlink".to_string());
    }
    if !metadata.is_file() {
        return Err(format!(
            "citation path is not a file: {}",
            candidate.display()
        ));
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(format!(
            "citation file exceeds the {MAX_FILE_BYTES} byte limit"
        ));
    }
    Ok(candidate)
}

fn read_citation(path: &str, cwd: Option<&str>, excerpt: &str) -> Result<Citation, String> {
    let file = citation_file(path, cwd)?;
    let bytes = std::fs::read(&file)
        .map_err(|error| format!("read citation {}: {error}", file.display()))?;
    let text = String::from_utf8(bytes).map_err(|_| "citation file must be valid UTF-8".to_string())?;
    let occurrences = count_excerpt(&text, excerpt)?;
    Ok(Citation {
        path: file.display().to_string(),
        bytes: text.len(),
        sha256: hex::encode(Sha256::digest(text.as_bytes())),
        occurrences,
    })
}

fn envelope(statement: &str, status: &str, scope: &str) -> Value {
    json!({
        "schema": "ostadix.claim/v1",
        "status": status,
        "statement": statement,
        "statement_verified": false,
        "scope": scope,
    })
}

fn respond(value: Value, accepted: bool) -> Result<CallToolResult, McpError> {
    if accepted {
        super::structured_result(value)
    } else {
        Ok(CallToolResult::structured_error(value))
    }
}

fn statement_matches_propositions(statement: &str, propositions: &[String]) -> bool {
    !propositions.is_empty() && statement.trim() == propositions.join("\n")
}

fn reported_propositions(formal: &Value) -> Option<Vec<String>> {
    let declarations = formal.get("declarations")?.as_array()?;
    let mut propositions = Vec::with_capacity(declarations.len());
    for declaration in declarations {
        propositions.push(declaration.get("proposition")?.as_str()?.to_string());
    }
    Some(propositions)
}

fn fail(statement: &str, error: String) -> Result<CallToolResult, McpError> {
    let mut value = envelope(
        statement,
        "unproved",
        "No checker accepted this claim. The English statement remains unproved.",
    );
    value["error"] = error.into();
    respond(value, false)
}

pub(crate) async fn judge(
    args: ClaimArgs,
    runtime_search: &super::RuntimeSearchPath,
) -> Result<CallToolResult, McpError> {
    if let Err(error) = validate_statement(&args.statement) {
        return fail(&args.statement, error);
    }
    let mode = match args.mode.as_deref() {
        None => Mode::Bare,
        Some("formal") => Mode::Formal,
        Some("citation") => Mode::Citation,
        Some(other) => {
            return fail(
                &args.statement,
                format!("mode must be formal or citation, not {other:?}"),
            )
        }
    };
    match mode {
        Mode::Bare => bare(args),
        Mode::Formal => formal(args, runtime_search).await,
        Mode::Citation => citation(args),
    }
}

enum Mode {
    Bare,
    Formal,
    Citation,
}

fn bare(args: ClaimArgs) -> Result<CallToolResult, McpError> {
    if args.source.is_some()
        || args.path.is_some()
        || args.excerpt.is_some()
        || args.declarations.is_some()
        || args.allowed_axioms.is_some()
        || args.timeout_secs.is_some()
        || args.cwd.is_some()
    {
        return fail(
            &args.statement,
            "a bare statement cannot carry checker fields; set mode to formal or citation".to_string(),
        );
    }
    respond(
        envelope(
            &args.statement,
            "unproved",
            "An English statement has no checker. Set mode formal for Lean or mode citation for an exact file excerpt.",
        ),
        false,
    )
}

async fn formal(
    args: ClaimArgs,
    runtime_search: &super::RuntimeSearchPath,
) -> Result<CallToolResult, McpError> {
    if args.excerpt.is_some() {
        return fail(
            &args.statement,
            "formal mode cannot include an excerpt".to_string(),
        );
    }
    let Some(declarations) = args.declarations.filter(|names| !names.is_empty()) else {
        return fail(
            &args.statement,
            "formal mode requires at least one declaration".to_string(),
        );
    };
    match crate::lean::verify_claim(
        args.source,
        args.path,
        args.cwd,
        declarations,
        args.allowed_axioms,
        args.timeout_secs,
        runtime_search,
    )
    .await
    {
        Ok((formal, verified)) => {
            let propositions = reported_propositions(&formal);
            let proved = verified
                && propositions
                    .as_ref()
                    .is_some_and(|items| statement_matches_propositions(&args.statement, items));
            let scope = if proved {
                "The statement is exactly the proposition Lean reported for the named declarations."
            } else if verified {
                "status verified covers the named Lean declarations and their reported axioms. The statement is not that proposition."
            } else {
                "The named Lean declarations were not verified. The statement remains unproved."
            };
            let status = if verified { "verified" } else { "unproved" };
            let mut value = envelope(&args.statement, status, scope);
            value["statement_verified"] = proved.into();
            value["formal"] = formal;
            respond(value, verified)
        }
        Err(error) => fail(&args.statement, error),
    }
}

fn citation(args: ClaimArgs) -> Result<CallToolResult, McpError> {
    if args.source.is_some()
        || args.declarations.is_some()
        || args.allowed_axioms.is_some()
        || args.timeout_secs.is_some()
    {
        return fail(
            &args.statement,
            "citation mode accepts only path, cwd, and excerpt".to_string(),
        );
    }
    let Some(path) = args.path.as_deref() else {
        return fail(&args.statement, "citation mode requires a path".to_string());
    };
    let Some(excerpt) = args.excerpt.as_deref() else {
        return fail(
            &args.statement,
            "citation mode requires an exact excerpt".to_string(),
        );
    };
    match read_citation(path, args.cwd.as_deref(), excerpt) {
        Ok(citation) if citation.occurrences > 0 => {
            let mut value = envelope(
                &args.statement,
                "cited",
                "The server found the exact excerpt in the cited file. That does not prove the English statement.",
            );
            value["citation"] = json!({
                "path": citation.path,
                "bytes": citation.bytes,
                "sha256": citation.sha256,
                "occurrences": citation.occurrences,
            });
            respond(value, true)
        }
        Ok(citation) => {
            let mut value = envelope(
                &args.statement,
                "unproved",
                "The server read the file and did not find the exact excerpt. The English statement remains unproved.",
            );
            value["citation"] = json!({
                "path": citation.path,
                "bytes": citation.bytes,
                "sha256": citation.sha256,
                "occurrences": 0,
            });
            respond(value, false)
        }
        Err(error) => fail(&args.statement, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excerpt_counts_are_exact_and_bounded() {
        assert_eq!(count_excerpt("alpha beta alpha", "alpha").unwrap(), 2);
        assert_eq!(count_excerpt("alpha beta", "gamma").unwrap(), 0);
        assert_eq!(count_excerpt("aaa", "aa").unwrap(), 1);
        assert!(count_excerpt("alpha", "").is_err());
        assert!(count_excerpt("alpha", &"x".repeat(MAX_EXCERPT_BYTES + 1)).is_err());
    }

    #[test]
    fn citation_reads_a_regular_file_and_rejects_a_symlink() {
        let directory = std::env::temp_dir().join(format!(
            "ostadix-claim-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("note.txt");
        std::fs::write(&file, "Keep the cited sentence intact.").unwrap();
        let found = read_citation(file.to_str().unwrap(), None, "cited sentence").unwrap();
        assert_eq!(found.occurrences, 1);
        assert_eq!(found.bytes, "Keep the cited sentence intact.".len());
        let missing = read_citation(file.to_str().unwrap(), None, "missing sentence").unwrap();
        assert_eq!(missing.occurrences, 0);

        let link = directory.join("alias.txt");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_citation(link.to_str().unwrap(), None, "cited sentence").is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn only_the_exact_proposition_verifies_the_statement() {
        let propositions = vec!["p ∧ q → q ∧ p".to_string()];
        assert!(statement_matches_propositions(
            "p ∧ q → q ∧ p",
            &propositions
        ));
        assert!(statement_matches_propositions(
            "  p ∧ q → q ∧ p\n",
            &propositions
        ));
        assert!(!statement_matches_propositions(
            "Conjunction commutes, so every English conclusion about it is proved.",
            &propositions
        ));
        assert!(!statement_matches_propositions("p ∧ q → q ∧ p", &[]));
        let joined = vec!["p ∧ q → q ∧ p".to_string(), "True".to_string()];
        assert!(statement_matches_propositions(
            "p ∧ q → q ∧ p\nTrue",
            &joined
        ));
        assert!(!statement_matches_propositions("p ∧ q → q ∧ p", &joined));
    }

    #[test]
    fn statements_must_be_present_and_bounded() {
        assert!(validate_statement("  ").is_err());
        assert!(validate_statement("The file contains the sentence.").is_ok());
        assert!(validate_statement(&"x".repeat(MAX_STATEMENT_BYTES + 1)).is_err());
    }
}
