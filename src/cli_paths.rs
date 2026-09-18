//! Optional runtime paths for installed native command-line tools.
//! Relocation never depends on the checkout used to compile the executable.

use std::path::{Path, PathBuf};

/// Resolve a configured shim directory without creating files. Explicit
/// environment values retain precedence even when invalid, so caller errors
/// identify the selected configuration instead of silently choosing another.
/// An absent or stale installation manifest falls back to bundled adapters.
pub fn configured_shim_dir() -> Option<PathBuf> {
    if let Some(path) =
        std::env::var_os("O_BACKENDS_DIR").or_else(|| std::env::var_os("BACKENDS_DIR"))
    {
        return Some(path.into());
    }
    installed_shim_dir(&std::env::current_exe().ok()?)
}

fn installed_shim_dir(executable: &Path) -> Option<PathBuf> {
    let directory = executable.parent()?;
    let bytes = std::fs::read(directory.join("ostadix-install.json")).ok()?;
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    if manifest.get("schema") != Some(&serde_json::json!(1))
        && manifest.get("schema").and_then(|value| value.as_str()) != Some("ostadix.install/v1")
    {
        return None;
    }
    let candidate = if let Some(path) = manifest
        .get("backends_dir")
        .and_then(|value| value.as_str())
    {
        PathBuf::from(path)
    } else {
        PathBuf::from(manifest.get("repo_root")?.as_str()?).join("backends")
    };
    let candidate = if candidate.is_absolute() {
        candidate
    } else {
        directory.join(candidate)
    };
    candidate.is_dir().then_some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjacent_manifest_resolves_relative_paths_after_relocation() {
        let directory = tempfile::tempdir().unwrap();
        let backend = directory.path().join("runtime with spaces/backends");
        std::fs::create_dir_all(&backend).unwrap();
        std::fs::write(directory.path().join("ostadix-install.json"), r#"{"schema":1,"repo_root":"runtime with spaces","backends_dir":"runtime with spaces/backends"}"#).unwrap();
        assert_eq!(
            installed_shim_dir(&directory.path().join("O")),
            Some(backend)
        );
    }

    #[test]
    fn absent_stale_or_unknown_manifest_retains_bundled_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("olangc");
        assert!(installed_shim_dir(&executable).is_none());
        for manifest in [
            r#"{"schema":1,"repo_root":"missing"}"#,
            r#"{"schema":9,"repo_root":"."}"#,
            "invalid",
        ] {
            std::fs::write(directory.path().join("ostadix-install.json"), manifest).unwrap();
            assert!(installed_shim_dir(&executable).is_none());
        }
    }
}
