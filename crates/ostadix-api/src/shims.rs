use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const BUNDLED_SHIMS: &[(&str, &[u8])] = &[
    ("bash_shim.py", include_bytes!("../backends/bash_shim.py")),
    (
        "common_lisp_shim.py",
        include_bytes!("../backends/common_lisp_shim.py"),
    ),
    ("cpp_shim.py", include_bytes!("../backends/cpp_shim.py")),
    (
        "csharp_shim.py",
        include_bytes!("../backends/csharp_shim.py"),
    ),
    (
        "haskell_shim.py",
        include_bytes!("../backends/haskell_shim.py"),
    ),
    ("java_shim.py", include_bytes!("../backends/java_shim.py")),
    (
        "javascript_shim.py",
        include_bytes!("../backends/javascript_shim.py"),
    ),
    ("lisp_shim.py", include_bytes!("../backends/lisp_shim.py")),
    (
        "mathematica_shim.py",
        include_bytes!("../backends/mathematica_shim.py"),
    ),
    (
        "matlab_shim.py",
        include_bytes!("../backends/matlab_shim.py"),
    ),
    ("nix_shim.py", include_bytes!("../backends/nix_shim.py")),
    (
        "nix_store_shim.py",
        include_bytes!("../backends/nix_store_shim.py"),
    ),
    (
        "nixos_test_shim.py",
        include_bytes!("../backends/nixos_test_shim.py"),
    ),
    (
        "o_shim_common.py",
        include_bytes!("../backends/o_shim_common.py"),
    ),
    (
        "o_native_objects.py",
        include_bytes!("../backends/o_native_objects.py"),
    ),
    ("ocaml_shim.py", include_bytes!("../backends/ocaml_shim.py")),
    (
        "python_shim.py",
        include_bytes!("../backends/python_shim.py"),
    ),
    (
        "ubuntu_vm_shim.py",
        include_bytes!("../backends/ubuntu_vm_shim.py"),
    ),
    (
        "racket_shim.py",
        include_bytes!("../backends/racket_shim.py"),
    ),
    ("ruby_shim.py", include_bytes!("../backends/ruby_shim.py")),
    ("rust_shim.py", include_bytes!("../backends/rust_shim.py")),
    ("shell_shim.py", include_bytes!("../backends/shell_shim.py")),
    ("sql_shim.py", include_bytes!("../backends/sql_shim.py")),
    (
        "webassembly_shim.py",
        include_bytes!("../backends/webassembly_shim.py"),
    ),
];

pub(crate) const BUNDLED_SHIM_SUPPORT_NAMES: &[&str] = &["o_shim_common.py", "o_native_objects.py"];

/// Truthful restart boundary for every executable bundled compatibility shim.
/// This catalog describes backend-owned process state only; it does not turn
/// files, services, or VM instances into portable values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundledShimStateClass {
    Stateless,
    SemanticSnapshot,
    ExternalPinned,
}

pub fn bundled_shim_state_class(name: &str) -> Option<BundledShimStateClass> {
    match name {
        "python_shim.py" | "sql_shim.py" => Some(BundledShimStateClass::SemanticSnapshot),
        "ubuntu_vm_shim.py" => Some(BundledShimStateClass::ExternalPinned),
        "bash_shim.py"
        | "common_lisp_shim.py"
        | "cpp_shim.py"
        | "csharp_shim.py"
        | "haskell_shim.py"
        | "java_shim.py"
        | "javascript_shim.py"
        | "lisp_shim.py"
        | "mathematica_shim.py"
        | "matlab_shim.py"
        | "nix_shim.py"
        | "nix_store_shim.py"
        | "nixos_test_shim.py"
        | "ocaml_shim.py"
        | "racket_shim.py"
        | "ruby_shim.py"
        | "rust_shim.py"
        | "shell_shim.py"
        | "webassembly_shim.py" => Some(BundledShimStateClass::Stateless),
        // The common module is shipped beside executable shims but is not a
        // backend actor and therefore has no independent state tier.
        "o_shim_common.py" | "o_native_objects.py" => None,
        _ => None,
    }
}

pub struct ExtractedShims {
    path: PathBuf,
}

impl ExtractedShims {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ExtractedShims {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn read_shims(override_dir: Option<&Path>) -> Result<Vec<(String, Vec<u8>)>> {
    let mut by_name: BTreeMap<String, Vec<u8>> = BUNDLED_SHIMS
        .iter()
        .map(|(name, bytes)| ((*name).to_string(), bytes.to_vec()))
        .collect();

    if let Some(dir) = override_dir {
        if !dir.exists() {
            bail!(
                "shim directory '{}' does not exist (omit the override to use bundled shims)",
                dir.display()
            );
        }
        for entry in fs::read_dir(dir)
            .with_context(|| format!("failed to read shim directory: {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                let content = fs::read(&path)
                    .with_context(|| format!("failed to read shim: {}", path.display()))?;
                by_name.insert(name, content);
            }
        }
    }

    Ok(by_name.into_iter().collect())
}

pub fn extract_bundled_shims(prefix: &str) -> Result<ExtractedShims> {
    extract_shims(prefix, &read_shims(None)?)
}

// ### private shim dir ###
// a fixed or guessable name under a shared /tmp lets another user plant a
// symlink or swap an adapter before it runs. the name is random, create (not
// create_dir_all) refuses any existing path, symlinks included, and 0700 keeps
// other users out.

/// Create a fresh private directory `<temp>/<prefix>_<pid>_<random>`.
pub fn create_private_dir(prefix: &str) -> Result<PathBuf> {
    let base = std::env::temp_dir();
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    for _ in 0..16 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|error| anyhow::anyhow!("{error}"))?;
        let dir = base.join(format!(
            "{prefix}_{}_{}",
            std::process::id(),
            hex::encode(random)
        ));
        match builder.create(&dir) {
            Ok(()) => return Ok(dir),
            // only reuse or a planted name collides; draw another.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create private directory {}", dir.display()))
            }
        }
    }
    anyhow::bail!("no free private directory name under {}", base.display())
}

pub fn extract_shims(prefix: &str, shims: &[(String, Vec<u8>)]) -> Result<ExtractedShims> {
    let dir = create_private_dir(prefix)?;
    // the guard owns the directory from here, so a failed write removes it.
    let extracted = ExtractedShims { path: dir.clone() };

    for (name, content) in shims {
        let dest = dir.join(name);
        fs::write(&dest, content).with_context(|| format!("failed to extract shim {name}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&dest, fs::Permissions::from_mode(0o755))
                .with_context(|| format!("failed to mark shim executable: {}", dest.display()))?;
        }
    }

    Ok(extracted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn extracted_shims_live_in_a_fresh_private_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let first = extract_shims("o_test_private", &[("a.py".into(), b"x".to_vec())]).unwrap();
        let second = extract_shims("o_test_private", &[]).unwrap();
        assert_ne!(first.path(), second.path(), "names must not be predictable");
        let meta = fs::symlink_metadata(first.path()).unwrap();
        assert!(meta.is_dir() && !meta.file_type().is_symlink());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        let path = first.path().to_path_buf();
        drop(first);
        assert!(!path.exists(), "the guard removes the directory");
    }

    #[test]
    fn bundled_shims_include_python_runtime_pair() {
        let names = BUNDLED_SHIMS
            .iter()
            .map(|(name, _)| *name)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(names.contains("python_shim.py"));
        assert!(names.contains("o_shim_common.py"));
        assert!(names.contains("o_native_objects.py"));
    }

    #[test]
    fn every_executable_bundled_shim_has_one_state_class() {
        let classified = BUNDLED_SHIMS
            .iter()
            .filter(|(name, _)| !BUNDLED_SHIM_SUPPORT_NAMES.contains(name))
            .map(|(name, _)| (*name, bundled_shim_state_class(name)))
            .collect::<Vec<_>>();
        assert_eq!(classified.len(), 22);
        assert!(classified.iter().all(|(_, class)| class.is_some()));
        assert_eq!(
            classified
                .iter()
                .filter(|(_, class)| { *class == Some(BundledShimStateClass::SemanticSnapshot) })
                .count(),
            2
        );
        assert_eq!(
            classified
                .iter()
                .filter(|(_, class)| *class == Some(BundledShimStateClass::ExternalPinned))
                .count(),
            1
        );
    }

    #[test]
    fn extracted_shims_are_readable_by_name() {
        let extracted = extract_bundled_shims("o_test_shims").unwrap();
        assert!(extracted.path().join("python_shim.py").is_file());
        assert!(extracted.path().join("o_shim_common.py").is_file());
    }
}
