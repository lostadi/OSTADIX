//! Shared build-script helper. No network access and no generated source files.
use std::path::{Path, PathBuf};
use std::process::Command;

fn watch_target(path: &Path, missing_ref: bool) -> Option<PathBuf> {
    if path.exists() {
        return Some(path.to_owned());
    }
    // A packed current branch can acquire a loose ref without changing HEAD,
    // index, or packed-refs. Watch its nearest existing ref directory so that
    // creation is observed, rather than giving Cargo a permanently missing file.
    missing_ref
        .then(|| {
            path.ancestors()
                .skip(1)
                .find(|parent| parent.is_dir())
                .map(Path::to_owned)
        })
        .flatten()
}

fn watch(path: &Path, missing_ref: bool) {
    if let Some(path) = watch_target(path, missing_ref) {
        if !path.to_string_lossy().contains(['\r', '\n']) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let mut command = Command::new("git");
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|name| name.starts_with("GIT_")) {
            command.env_remove(name);
        }
    }
    let output = command
        .args(["-c", "core.fsmonitor=false", "-C"])
        .arg(root)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub fn capture(root: &Path) {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    watch(&root.join("scripts/capture_build_identity.rs"), false);
    for name in [
        "src",
        "crates",
        "ostadix-core/src",
        "mcp/ostadix_lang_mcp_server/src",
        "Cargo.toml",
        "Cargo.lock",
    ] {
        watch(&root.join(name), false);
    }
    let marker = root.join(".git");
    let has_git = marker.is_file() || marker.is_dir();
    if marker.is_file() {
        watch(&marker, false);
    }
    // Worktrees store .git as a file. Ask Git for the real metadata paths.
    // A loose branch ref can change without modifying HEAD or index.
    let mut git_paths = vec![
        ("HEAD".to_owned(), false),
        ("index".to_owned(), false),
        ("packed-refs".to_owned(), false),
    ];
    if has_git {
        if let Some(symbolic) = git(&root, &["symbolic-ref", "-q", "HEAD"]) {
            git_paths.push((symbolic, true));
        }
    }
    for (name, missing_ref) in git_paths.iter().filter(|_| has_git) {
        if let Some(path) = git(&root, &["rev-parse", "--git-path", name]) {
            let path = Path::new(&path);
            let path = if path.is_absolute() {
                path.to_owned()
            } else {
                root.join(path)
            };
            watch(&path, *missing_ref);
        }
    }
    if let Some(paths) = has_git.then(|| git(&root, &["ls-files", "-z"])).flatten() {
        for path in paths
            .split('\0')
            .filter(|path| !path.is_empty() && !path.contains(['\r', '\n']))
        {
            watch(&root.join(path), false);
        }
    }
    let is_root = has_git
        && git(&root, &["rev-parse", "--show-toplevel"])
            .is_some_and(|path| Path::new(&path).canonicalize().ok().as_ref() == Some(&root));
    let commit = is_root
        .then(|| git(&root, &["rev-parse", "HEAD"]))
        .flatten()
        .filter(|value| {
            matches!(value.len(), 40 | 64) && value.bytes().all(|c| c.is_ascii_hexdigit())
        });
    let dirty = if is_root {
        git(
            &root,
            &["status", "--porcelain=v1", "--untracked-files=normal"],
        )
        .map(|status| if status.is_empty() { "false" } else { "true" })
        .unwrap_or("unknown")
    } else {
        "unknown"
    };
    println!(
        "cargo:rustc-env=OSTADIX_BUILD_SOURCE_ROOT={}",
        root.display()
    );
    println!(
        "cargo:rustc-env=OSTADIX_BUILD_COMMIT={}",
        commit.as_deref().unwrap_or("unknown")
    );
    println!("cargo:rustc-env=OSTADIX_BUILD_DIRTY={dirty}");
    for (cargo, identity) in [
        ("TARGET", "OSTADIX_BUILD_TARGET"),
        ("HOST", "OSTADIX_BUILD_HOST"),
        ("PROFILE", "OSTADIX_BUILD_PROFILE"),
    ] {
        println!(
            "cargo:rustc-env={identity}={}",
            std::env::var(cargo).unwrap_or_else(|_| "unknown".into())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_packed_refs_are_not_permanent_missing_cargo_dependencies() {
        let root = std::env::temp_dir().join(format!(
            "ostadix-build-watch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir_all(root.join("refs/heads")).unwrap();
        assert_eq!(watch_target(&root.join("packed-refs"), false), None);
        assert_eq!(
            watch_target(&root.join("refs/heads/topic/branch"), true),
            Some(root.join("refs/heads"))
        );
        std::fs::write(root.join("refs/heads/main"), "commit\n").unwrap();
        assert_eq!(
            watch_target(&root.join("refs/heads/main"), true),
            Some(root.join("refs/heads/main"))
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
