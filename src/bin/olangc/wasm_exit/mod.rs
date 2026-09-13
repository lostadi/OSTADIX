//! Frozen, hash-checked build overlay for the amd64 Linux-to-WASI exit channel.
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const DOCKERFILE: &[u8] = include_bytes!("Dockerfile");
const FILES: &[(&str, &[u8])] = &[
    ("apply.sh", include_bytes!("apply.sh")),
    ("init.patch", include_bytes!("init.patch")),
    ("bochs.patch", include_bytes!("bochs.patch")),
    ("bochs-network.patch", include_bytes!("bochs-network.patch")),
    (
        "exit_status_linux_amd64.go",
        include_bytes!("exit_status_linux_amd64.go"),
    ),
    (
        "LICENSE.container2wasm",
        include_bytes!("LICENSE.container2wasm"),
    ),
    ("README.md", include_bytes!("README.md")),
    (
        "browser_guix_state_linux_amd64.go",
        include_bytes!("browser_guix_state_linux_amd64.go"),
    ),
];

#[derive(Debug)]
pub struct Assets {
    pub dockerfile: PathBuf,
    pub context: PathBuf,
}

impl Assets {
    pub fn browser_guix(&self) -> Result<bool> {
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(self.context.join("state-profile.json"))?)?;
        Ok(value["schema"] == "ostadix.guix-state/v1")
    }
    pub fn manifest(&self) -> Result<serde_json::Value> {
        let mut overlay = BTreeMap::new();
        for (name, _) in FILES {
            overlay.insert(
                *name,
                hex::encode(Sha256::digest(fs::read(self.context.join(name))?)),
            );
        }
        overlay.insert(
            "state-profile.json",
            hex::encode(Sha256::digest(fs::read(
                self.context.join("state-profile.json"),
            )?)),
        );
        Ok(serde_json::json!({
            "profile": "amd64-bochs-cold-boot-exit-status-v1",
            "container2wasm_source": "6ed3d98882a2b22eafc1334f574c364a5b2b8c47",
            "dockerfile_sha256": hex::encode(Sha256::digest(fs::read(&self.dockerfile)?)),
            "overlay_sha256": overlay,
            "browser_guix": self.browser_guix()?,
        }))
    }

    pub fn add_to_command(&self, command: &mut Command) -> Result<()> {
        let context = self
            .context
            .to_str()
            .context("c2w overlay path must be UTF-8")?;
        // c2w's repeated string-slice flag also splits comma-separated values.
        if context.contains([',', '\n', '\r']) {
            bail!("c2w overlay path cannot contain commas or line breaks");
        }
        command.arg("--dockerfile").arg(&self.dockerfile);
        command
            .arg("--extra-flag")
            .arg(format!("--build-context=ostadix-exit={context}"));
        if self.browser_guix()? {
            command.args(["--build-arg", "OSTADIX_GUIX_STATE=1"]);
        }
        Ok(())
    }
}

fn directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(path)?.is_dir() {
                bail!(
                    "exit overlay directory is not a regular directory: {}",
                    path.display()
                );
            }
            Ok(())
        }
        Err(error) => Err(error).context("create exit overlay directory"),
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => file.write_all(bytes).context("write exit overlay asset"),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(path)?.is_file() || fs::read(path)? != bytes {
                bail!(
                    "refusing to replace a different exit overlay asset: {}",
                    path.display()
                );
            }
            Ok(())
        }
        Err(error) => Err(error).context("create exit overlay asset"),
    }
}

/// Materialize exact assets without fetching sources, applying patches, or
/// starting Docker. The caller must use a Buildx-capable converter invocation.
#[cfg(test)]
pub fn write_assets(build_dir: &Path) -> Result<Assets> {
    write_assets_for_state(build_dir, None)
}

pub fn write_assets_for_state(
    build_dir: &Path,
    state: Option<&serde_json::Value>,
) -> Result<Assets> {
    let root = build_dir
        .canonicalize()
        .context("resolve exit overlay build directory")?
        .join("wasm-exit");
    directory(&root)?;
    let context = root.join("overlay");
    directory(&context)?;
    let dockerfile = root.join("Dockerfile");
    write_file(&dockerfile, DOCKERFILE)?;
    for (name, contents) in FILES {
        write_file(&context.join(name), contents)?;
    }
    write_file(
        &context.join("state-profile.json"),
        &serde_json::to_vec_pretty(&state.cloned().unwrap_or_else(|| serde_json::json!({})))?,
    )?;
    Ok(Assets {
        dockerfile,
        context,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_exact_assets_idempotently_without_running_builders() {
        let root = tempfile::tempdir().unwrap();
        let assets = write_assets(root.path()).unwrap();
        write_assets(root.path()).unwrap();
        assert_eq!(fs::read(&assets.dockerfile).unwrap(), DOCKERFILE);
        for (name, bytes) in FILES {
            assert_eq!(fs::read(assets.context.join(name)).unwrap(), *bytes);
        }
        let manifest = assets.manifest().unwrap();
        assert_eq!(
            manifest["dockerfile_sha256"],
            hex::encode(Sha256::digest(DOCKERFILE))
        );
        assert_eq!(
            manifest["overlay_sha256"].as_object().unwrap().len(),
            FILES.len() + 1
        );
        fs::write(assets.context.join("init.patch"), "changed").unwrap();
        assert!(write_assets(root.path()).is_err());
        assert_eq!(
            fs::read(assets.context.join("init.patch")).unwrap(),
            b"changed"
        );
    }

    #[test]
    fn converter_arguments_bind_the_local_overlay_without_shell_splitting() {
        let root = tempfile::tempdir().unwrap();
        let context = root.path().join("build with spaces");
        fs::create_dir(&context).unwrap();
        fs::write(context.join("state-profile.json"), b"{}").unwrap();
        let assets = Assets {
            dockerfile: "/build with spaces/Dockerfile".into(),
            context: context.clone(),
        };
        let mut command = Command::new("c2w");
        assets.add_to_command(&mut command).unwrap();
        let args = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "--dockerfile",
                "/build with spaces/Dockerfile",
                "--extra-flag",
                &format!("--build-context=ostadix-exit={}", context.display())
            ]
        );
        let invalid = Assets {
            context: "/build,extra/overlay".into(),
            ..assets
        };
        assert!(invalid.add_to_command(&mut Command::new("c2w")).is_err());
    }

    #[test]
    fn recipe_applies_only_the_two_paired_amd64_patches() {
        let recipe = std::str::from_utf8(DOCKERFILE).unwrap();
        assert_eq!(
            recipe.matches("RUN sh /ostadix-exit/apply.sh init").count(),
            1
        );
        assert_eq!(
            recipe
                .matches("RUN sh /ostadix-exit/apply.sh bochs")
                .count(),
            1
        );
        assert!(recipe.contains("ARG SOURCE_REPO=https://github.com/container2wasm/container2wasm"));
        assert!(recipe.contains("ARG SOURCE_REPO_VERSION=6ed3d98882a2b22eafc1334f574c364a5b2b8c47"));
        assert!(recipe.contains("ARG BOCHS_REPO_VERSION=a88d1f687ec83ff82b5318f59dcecb8dab44fc83"));
        let script = include_str!("apply.sh");
        assert!(script.contains("git apply --check --whitespace=error"));
        assert!(script.contains("d6a53a0acbfbe58ddb57dd262c3af7d768354d620ca72914a79aae0768658fac"));
        assert!(script.contains("bb07a42be89d27e2f857aae7c9af9a06435be22f5719baf55129ca7d8022ca21"));
        assert!(script.contains("config_source=bochs/config.cc"));
        assert!(script.contains("2932eb64b3e1290c136c768ca5e6b334f8bd227d835e81450a743c39705ef63a"));
        assert!(script.contains("msr_source=bochs/cpu/msr.cc"));
        assert!(script.contains("4d7fde6fa6869e462eedf2a9d8b223e8cb2a2aed1e56c28619e1e8cd226fbc09"));
    }

    #[test]
    fn amd64_packer_writes_its_export_path_in_one_layer() {
        let recipe = std::str::from_utf8(DOCKERFILE).unwrap();
        let stage = recipe
            .split("FROM bochs-dev-native AS bochs-dev-packed\n")
            .nth(1)
            .unwrap()
            .split("\nFROM scratch AS wasi-amd64")
            .next()
            .unwrap();
        assert!(stage.starts_with("ARG OUTPUT_NAME\n"));
        assert_eq!(stage.matches("RUN ").count(), 1);
        assert!(stage.contains("RUN mkdir /out &&"));
        assert!(stage.contains("--mapdir /pack::/minpack -o \"/out/${OUTPUT_NAME}\""));
        assert!(!stage.contains("mv packed"));
    }

    #[test]
    fn bochs_config_read_errors_fail_before_using_the_line_buffer() {
        let patch = include_str!("bochs.patch");
        let config = patch.split("diff --git a/bochs/config.cc").nth(1).unwrap();
        let check = config.find("if (ret == NULL)").unwrap();
        let use_line = config.find("line[sizeof(line) - 1]").unwrap();
        assert!(check < use_line);
        assert!(config.contains("if (ferror(fd))"));
        assert!(config.contains("const int read_errno = errno;"));
        assert!(config.contains("cannot read configuration %s (fd=%d): %s (errno=%d)"));
        assert!(config.contains("+#ifdef WASI"));
        assert!(config.contains("+        exit(125);"));
        assert!(config.contains("+      break;"));
    }

    #[test]
    fn optional_msr_file_is_disabled_before_open_and_read_errors_fail_closed() {
        let patch = include_str!("bochs.patch");
        let msr = patch.split("diff --git a/bochs/cpu/msr.cc").nth(1).unwrap();
        let empty_check = msr.find("if (file == NULL || file[0] == '\\0')").unwrap();
        let buffer = msr.find("char line[512]").unwrap();
        assert!(empty_check < buffer);
        assert!(msr.contains("+    return -1;"));
        let read_check = msr.find("if (ret == NULL)").unwrap();
        let use_line = msr.find("line[sizeof(line) - 1]").unwrap();
        assert!(read_check < use_line);
        assert!(msr.contains("if (ferror(fd))"));
        assert!(msr.contains("const int read_errno = errno;"));
        assert!(msr.contains("cannot read MSR configuration %s (fd=%d): %s (errno=%d)"));
        assert!(msr.contains("+#ifdef WASI"));
        assert!(msr.contains("+        exit(125);"));
        assert!(msr.contains("+      break;"));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_overlay_directory_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(other.path(), root.path().join("wasm-exit")).unwrap();
        assert!(write_assets(root.path()).is_err());
        assert_eq!(fs::read_dir(other.path()).unwrap().count(), 0);
    }
}
