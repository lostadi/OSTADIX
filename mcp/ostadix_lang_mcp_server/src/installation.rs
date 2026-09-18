//! Relocatable installation defaults; explicit caller configuration wins.

use std::path::{Path, PathBuf};

pub(crate) fn metadata(executable: &Path) -> Option<serde_json::Value> {
    let path = executable.parent()?.join("ostadix-install.json");
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    (value["schema"] == 1 || value["schema"] == "ostadix.install/v1").then_some(value)
}

pub(crate) fn root(
    configured: Option<&Path>,
    executable: Option<&Path>,
    current: Option<&Path>,
    home: &Path,
) -> PathBuf {
    let installed = executable
        .and_then(metadata)
        .and_then(|value| value["repo_root"].as_str().map(PathBuf::from));
    let candidates = configured
        .into_iter()
        .map(Path::to_path_buf)
        .chain(installed)
        .chain(
            current
                .into_iter()
                .flat_map(Path::ancestors)
                .map(Path::to_path_buf),
        )
        .chain([
            PathBuf::from("/usr/src/ostadix"),
            home.join("OSTADIX"),
            home.join("Ostadix-lang"),
            home.join("O-lang"),
        ]);
    for candidate in candidates {
        if super::is_lang_root(&candidate) {
            return candidate.canonicalize().unwrap_or(candidate);
        }
    }
    current
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join("OSTADIX"))
}

pub(crate) fn backends(root: &Path, executable: &Path) -> Option<PathBuf> {
    let value = metadata(executable)?;
    let installed_root = Path::new(value["repo_root"].as_str()?)
        .canonicalize()
        .ok()?;
    if installed_root != root.canonicalize().ok()? {
        return None;
    }
    super::canonical_directory(Path::new(value["backends_dir"].as_str()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::Fixture;

    #[test]
    fn explicit_root_precedes_installation_which_precedes_working_directory() {
        let installed = Fixture::new();
        let explicit = Fixture::new();
        let working = Fixture::new();
        let bin = installed.0.join("bin/ostadix-mcp");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        let external_backends = installed.0.join("installed-backends");
        std::fs::create_dir(&external_backends).unwrap();
        std::fs::write(bin.parent().unwrap().join("ostadix-install.json"),
            serde_json::to_vec(&serde_json::json!({"schema":1,"repo_root":installed.0,"backends_dir":external_backends})).unwrap()).unwrap();
        assert_eq!(
            root(None, Some(&bin), Some(&working.0), &working.0),
            installed.0.canonicalize().unwrap()
        );
        assert_eq!(
            root(Some(&explicit.0), Some(&bin), Some(&working.0), &working.0),
            explicit.0.canonicalize().unwrap()
        );
        assert_eq!(
            backends(&installed.0, &bin),
            Some(external_backends.canonicalize().unwrap())
        );
        assert_eq!(backends(&explicit.0, &bin), None);
        std::fs::write(
            bin.parent().unwrap().join("ostadix-install.json"),
            "not json",
        )
        .unwrap();
        assert_eq!(
            root(None, Some(&bin), Some(&working.0), &working.0),
            working.0.canonicalize().unwrap()
        );
    }

    #[test]
    fn canonical_home_checkout_precedes_legacy_name() {
        let home = Fixture::new();
        for name in ["OSTADIX", "Ostadix-lang"] {
            let path = home.0.join(name);
            std::fs::create_dir_all(path.join("backends")).unwrap();
            std::fs::create_dir_all(path.join("examples")).unwrap();
            for name in ["Cargo.toml", "backends/python_shim.py", "examples/hello.O"] {
                std::fs::write(path.join(name), "fixture").unwrap();
            }
        }
        assert_eq!(
            root(None, None, None, &home.0),
            home.0.join("OSTADIX").canonicalize().unwrap()
        );
    }
}
