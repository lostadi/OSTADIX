//! Build a native O execution closure inside a container2wasm Linux guest.
//!
//! The caller explicitly trusts the pinned builder and runtime images. This
//! checks build completion and the core-Wasm header, not runtime qualification.
use anyhow::{bail, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[path = "wasm_exit/mod.rs"]
mod wasm_exit;

const RECIPE: &str = "Dockerfile.wasm-container";
const IGNORE: &str = "Dockerfile.wasm-container.dockerignore";
const IGNORE_CONTENTS: &str =
    "**\n!Dockerfile.wasm-container\n!cargo/\n!cargo/**\ncargo/target/\ncargo/target/**\n";

#[derive(Clone, Debug)]
pub struct Options {
    pub runtime_image: String,
    pub builder_image: String,
    pub browser_guix: bool,
}

fn lower_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn repository_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || !lower_alphanumeric(bytes[0])
        || !lower_alphanumeric(bytes[bytes.len() - 1])
    {
        return false;
    }
    let mut position = 0;
    while position < bytes.len() {
        if lower_alphanumeric(bytes[position]) {
            position += 1;
            continue;
        }
        let separator = bytes[position];
        let start = position;
        while position < bytes.len() && bytes[position] == separator {
            position += 1;
        }
        if !matches!(separator, b'.' | b'_' | b'-')
            || (separator == b'.' && position - start != 1)
            || (separator == b'_' && position - start > 2)
            || position == bytes.len()
            || !lower_alphanumeric(bytes[position])
        {
            return false;
        }
    }
    true
}

fn registry(value: &str) -> bool {
    let (host, port) = match value.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (value, None),
    };
    if port.is_some_and(|port| {
        port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || !matches!(port.parse::<u16>(), Ok(1..=u16::MAX))
    }) {
        return false;
    }
    host.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && lower_alphanumeric(bytes[0])
            && lower_alphanumeric(bytes[bytes.len() - 1])
            && bytes
                .iter()
                .all(|byte| lower_alphanumeric(*byte) || *byte == b'-')
    })
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_image(value: &str, label: &str) -> Result<()> {
    let invalid = || {
        anyhow::anyhow!(
            "{label} must be a Docker image reference pinned as repository@sha256:<64 lowercase hex digits> (an optional tag and registry port are supported)"
        )
    };
    let (name, hash) = value.split_once("@sha256:").ok_or_else(invalid)?;
    if name.len() > 255 || !digest(hash) {
        return Err(invalid());
    }
    let mut parts = name.split('/').collect::<Vec<_>>();
    let last = parts.pop().ok_or_else(invalid)?;
    let repository = match last.split_once(':') {
        Some((repository, tag)) => {
            let bytes = tag.as_bytes();
            if bytes.is_empty()
                || bytes.len() > 128
                || !(bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
                || !bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(byte))
            {
                return Err(invalid());
            }
            repository
        }
        None => last,
    };
    if !repository_component(repository) {
        return Err(invalid());
    }
    for (index, part) in parts.iter().enumerate() {
        let is_registry = index == 0 && (part.contains(['.', ':']) || *part == "localhost");
        if !(if is_registry {
            registry(part)
        } else {
            repository_component(part)
        }) {
            return Err(invalid());
        }
    }
    Ok(())
}

pub fn validate_images(options: &Options) -> Result<()> {
    validate_image(&options.runtime_image, "WASM runtime image")?;
    validate_image(&options.builder_image, "WASM builder image")
}

fn recipe(options: &Options) -> Result<String> {
    let channel = super::pinned_toolchain_channel()?;
    if !channel
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        bail!("embedded Rust toolchain channel is unsafe for the build recipe");
    }
    Ok(format!(
        "FROM --platform=linux/amd64 {} AS ostadix-build\n\
         USER 0\n\
         WORKDIR /ostadix-build\n\
         COPY cargo/ ./\n\
         ENV RUSTC=rustc RUSTDOC=rustdoc RUSTFLAGS= CARGO_ENCODED_RUSTFLAGS= RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER=\n\
         RUN rustup run {channel} cargo build --release --locked --bin o-program --target x86_64-unknown-linux-gnu --target-dir /ostadix-build/target\n\
         FROM --platform=linux/amd64 {}\n\
         COPY --from=ostadix-build /ostadix-build/target/x86_64-unknown-linux-gnu/release/o-program /ostadix/program\n\
         WORKDIR /tmp\n\
         ENTRYPOINT [\"/ostadix/program\"]\n\
         CMD []\n",
        options.builder_image, options.runtime_image
    ))
}

fn write_identical_or_new(path: &Path, contents: &[u8]) -> Result<()> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => file.write_all(contents).context("write WASM build recipe"),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_file() || fs::read(path)? != contents {
                bail!(
                    "refusing to replace a different build recipe: {}",
                    path.display()
                );
            }
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("create {}", path.display())),
    }
}

/// Materialize an inspectable recipe without running a builder or fetching images.
pub fn write_recipe(build_dir: &Path, options: &Options) -> Result<()> {
    validate_images(options)?;
    write_identical_or_new(&build_dir.join(RECIPE), recipe(options)?.as_bytes())?;
    write_identical_or_new(&build_dir.join(IGNORE), IGNORE_CONTENTS.as_bytes())?;
    let state = options
        .browser_guix
        .then(|| super::browser_guix::state_profile(&options.runtime_image));
    wasm_exit::write_assets_for_state(build_dir, state.as_ref())?;
    if options.browser_guix {
        super::browser_guix::materialize_assets(build_dir, &options.runtime_image)?;
    }
    Ok(())
}

pub fn converter_manifest(build_dir: &Path, options: &Options) -> Result<serde_json::Value> {
    let state = options
        .browser_guix
        .then(|| super::browser_guix::state_profile(&options.runtime_image));
    wasm_exit::write_assets_for_state(build_dir, state.as_ref())?.manifest()
}

fn ensure_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect WASM output path"),
        Ok(_) => bail!(
            "refusing to overwrite existing WASM output: {}",
            path.display()
        ),
    }
}

fn output_path(output: &Path) -> Result<PathBuf> {
    let name = output.file_name().context("WASM output must name a file")?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .context("WASM output parent directory must already exist")?;
    // c2w embeds its staging directory in Docker's comma-separated
    // `--output type=local,dest=...` option without escaping delimiters.
    if parent
        .as_os_str()
        .to_string_lossy()
        .contains([',', '\n', '\r'])
    {
        bail!("WASM output parent directory cannot contain commas or line breaks");
    }
    let output = parent.join(name);
    ensure_absent(&output)?;
    Ok(output)
}

struct Scratch(PathBuf);

impl Scratch {
    fn create(parent: &Path) -> Result<Self> {
        for _ in 0..8 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|error| anyhow::anyhow!("WASM build entropy: {error}"))?;
            let path = parent.join(format!(".ostadix-wasm-{}", hex::encode(random)));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error).context("create private WASM build staging"),
            }
        }
        bail!("could not allocate a unique WASM build staging directory")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(command: &mut Command, description: &str) -> Result<()> {
    let status = command
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("{description}: could not start command"))?;
    if !status.success() {
        bail!("{description} failed ({status})");
    }
    Ok(())
}

fn docker_build(docker: &Path, build_dir: &Path, iid: &Path, tag: &str) -> Command {
    let mut command = Command::new(docker);
    command
        .args([
            "buildx",
            "build",
            "--load",
            "--platform=linux/amd64",
            "--file",
        ])
        .arg(build_dir.join(RECIPE))
        .arg("--tag")
        .arg(tag)
        .arg("--iidfile")
        .arg(iid)
        .arg(build_dir);
    command
}

fn convert(
    c2w: &Path,
    docker: &Path,
    assets: &wasm_exit::Assets,
    tag: &str,
    output: &Path,
) -> Result<Command> {
    let mut command = Command::new(c2w);
    command.arg("--builder").arg(docker).args([
        "--target-arch=amd64",
        "--build-arg",
        if assets.browser_guix()? {
            "VM_MEMORY_SIZE_MB=1024"
        } else {
            "VM_MEMORY_SIZE_MB=512"
        },
        "--build-arg",
        "OPTIMIZATION_MODE=native",
    ]);
    assets.add_to_command(&mut command)?;
    command.arg(tag).arg(output);
    Ok(command)
}

fn validate_platform(platform: &str) -> Result<()> {
    if platform.trim() != "linux/amd64" {
        bail!(
            "source-bound image must be linux/amd64 before WASM conversion; Docker reported {:?}",
            platform.trim()
        );
    }
    Ok(())
}

fn verify_image_platform(docker: &Path, tag: &str) -> Result<()> {
    let inspected = Command::new(docker)
        .args([
            "image",
            "inspect",
            "--format",
            "{{.Os}}/{{.Architecture}}",
            tag,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .context("inspect source-bound Linux image architecture")?;
    if !inspected.status.success() {
        bail!(
            "inspect source-bound Linux image architecture failed ({})",
            inspected.status
        );
    }
    validate_platform(
        std::str::from_utf8(&inspected.stdout)
            .context("Docker reported a non-UTF-8 image platform")?,
    )
}

struct TemporaryImage {
    docker: PathBuf,
    tag: String,
    iid: PathBuf,
}

impl Drop for TemporaryImage {
    fn drop(&mut self) {
        // The random tag alone is insufficient ownership evidence: bind it to
        // Docker's successful-build IID, then remove only that tag, never a
        // base image, an arbitrary image ID, or the builder's shared cache.
        let Ok(expected) = fs::read_to_string(&self.iid) else {
            return;
        };
        let expected = expected.trim();
        if !expected.strip_prefix("sha256:").is_some_and(digest) {
            return;
        }
        let inspected = Command::new(&self.docker)
            .args(["image", "inspect", "--format", "{{.Id}}", &self.tag])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();
        let Ok(inspected) = inspected else { return };
        if !inspected.status.success()
            || String::from_utf8_lossy(&inspected.stdout).trim() != expected
        {
            eprintln!(
                "temporary WASM image tag changed; leaving {} untouched",
                self.tag
            );
            return;
        }
        let removed = Command::new(&self.docker)
            .args(["image", "rm", "--no-prune", &self.tag])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status();
        if !matches!(removed, Ok(status) if status.success()) {
            eprintln!("could not remove temporary WASM image tag {}", self.tag);
        }
    }
}

fn validate_module(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.is_file() {
        bail!("container2wasm output is not a regular file");
    }
    let mut file = File::open(path)?;
    let mut header = [0_u8; 8];
    file.read_exact(&mut header)
        .context("container2wasm output has no complete WASM header")?;
    if header != *b"\0asm\x01\0\0\0" {
        bail!("container2wasm output is not a core WASM v1 module");
    }
    Ok(())
}

fn publish(staged: &Path, output: &Path) -> Result<()> {
    validate_module(staged)?;
    // Staging is on the destination filesystem. A hard link atomically creates
    // the destination without replacing an existing file or dangling symlink.
    File::open(staged)?.sync_all()?;
    fs::hard_link(staged, output).with_context(|| {
        format!(
            "publish WASM output without overwriting {}",
            output.display()
        )
    })
}

/// Execute explicitly supplied build images. Requires installed Docker (with a
/// running Linux builder) and container2wasm; it never installs either tool.
pub fn build(build_dir: &Path, output: &Path, options: &Options) -> Result<()> {
    validate_images(options)?;
    let output = output_path(output)?;
    let build_dir = build_dir
        .canonicalize()
        .context("resolve WASM build directory")?;
    for name in ["Cargo.toml", "Cargo.lock"] {
        let path = build_dir.join("cargo").join(name);
        if !fs::symlink_metadata(&path)
            .with_context(|| format!("WASM build requires generated cargo/{name}"))?
            .is_file()
        {
            bail!(
                "WASM build input must be a regular file: {}",
                path.display()
            );
        }
    }
    let docker = which::which("docker")
        .context("WASM container build requires Docker on PATH; install/start a Linux Docker builder, then retry (check: docker info)")?;
    let c2w = which::which("c2w")
        .context("WASM container build requires container2wasm's c2w on PATH; install it explicitly from https://github.com/container2wasm/container2wasm/releases, then retry (check: c2w --version)")?;
    run(
        Command::new(&docker).args(["info", "--format", "{{.ServerVersion}}"]),
        "Docker preflight (start a Linux Docker builder and check docker info)",
    )?;
    run(
        Command::new(&c2w).arg("--version"),
        "container2wasm preflight",
    )?;
    run(
        Command::new(&docker).args(["buildx", "version"]),
        "Docker Buildx preflight (required for the paired guest exit-status overlay)",
    )?;
    write_recipe(&build_dir, options)?;
    let state = options
        .browser_guix
        .then(|| super::browser_guix::state_profile(&options.runtime_image));
    let assets = wasm_exit::write_assets_for_state(&build_dir, state.as_ref())?;
    let scratch = Scratch::create(output.parent().context("WASM output has no parent")?)?;
    let nonce = scratch.0.file_name().unwrap().to_string_lossy();
    let image = TemporaryImage {
        docker: docker.clone(),
        tag: format!("ostadix-wasm-build:build-{}", nonce.trim_start_matches('.')),
        iid: scratch.0.join("image.id"),
    };
    run(
        &mut docker_build(&docker, &build_dir, &image.iid, &image.tag),
        "build source-bound Linux/amd64 O image (the declared builder/runtime images must supply compatible Rust, system libraries, and foreign runtimes)",
    )?;
    verify_image_platform(&docker, &image.tag)?;
    let staged = scratch.0.join("program.wasm");
    run(
        &mut convert(&c2w, &docker, &assets, &image.tag, &staged)?,
        "convert Linux O image to WASI with container2wasm",
    )?;
    publish(&staged, &output)?;
    eprintln!(
        "compiled -> {} (Linux-in-WASI envelope; execution not yet qualified)",
        output.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Options {
        Options {
            runtime_image: format!(
                "registry.example:5000/o/runtime:v1@sha256:{}",
                "a".repeat(64)
            ),
            builder_image: format!("rust:1.93.1@sha256:{}", "b".repeat(64)),
            browser_guix: false,
        }
    }

    #[test]
    fn accepts_only_pinned_safe_image_references() {
        validate_images(&options()).unwrap();
        for prefix in [
            "alpine",
            "docker.io/library/rust:1.93.1",
            "localhost:5000/a/b",
            "a__b/c---d:T_1",
        ] {
            validate_image(&format!("{prefix}@sha256:{}", "0".repeat(64)), "test").unwrap();
        }
        for value in [
            "rust:latest".to_owned(),
            format!("rust@sha256:{}", "A".repeat(64)),
            format!("rust@sha256:{}", "a".repeat(63)),
            format!("--flag@sha256:{}", "a".repeat(64)),
            format!("rust\nRUN false@sha256:{}", "a".repeat(64)),
            format!("https://example.com/o@sha256:{}", "a".repeat(64)),
            format!("example.com:0/o@sha256:{}", "a".repeat(64)),
            format!("example.com:65536/o@sha256:{}", "a".repeat(64)),
            format!("a//b@sha256:{}", "a".repeat(64)),
            format!("a/../b@sha256:{}", "a".repeat(64)),
            format!("a..b@sha256:{}", "a".repeat(64)),
            format!("A/b@sha256:{}", "a".repeat(64)),
            format!("a@sha256:{} trailing", "a".repeat(64)),
        ] {
            assert!(validate_image(&value, "test").is_err(), "accepted {value}");
        }
    }

    #[test]
    fn recipe_is_pinned_native_source_bound_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        write_recipe(directory.path(), &options()).unwrap();
        write_recipe(directory.path(), &options()).unwrap();
        let written = fs::read_to_string(directory.path().join(RECIPE)).unwrap();
        assert_eq!(written, recipe(&options()).unwrap());
        assert_eq!(written.matches("FROM --platform=linux/amd64 ").count(), 2);
        assert!(written.contains("COPY cargo/ ./"));
        assert!(written.contains("cargo build --release --locked --bin o-program"));
        assert!(written.contains("WORKDIR /tmp\nENTRYPOINT"));
        assert_eq!(written.matches("USER 0").count(), 1);
        assert!(written.ends_with("ENTRYPOINT [\"/ostadix/program\"]\nCMD []\n"));
        assert_eq!(
            fs::read_to_string(directory.path().join(IGNORE)).unwrap(),
            IGNORE_CONTENTS
        );
        fs::write(directory.path().join(RECIPE), "user recipe").unwrap();
        assert!(write_recipe(directory.path(), &options()).is_err());
        assert_eq!(
            fs::read_to_string(directory.path().join(RECIPE)).unwrap(),
            "user recipe"
        );
    }

    #[test]
    fn command_arguments_keep_paths_separate_and_select_embedded_wasi() {
        let command = docker_build(
            Path::new("/tools/docker"),
            Path::new("/build with spaces"),
            Path::new("/stage/image.id"),
            "temporary:tag",
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(command.get_program(), "/tools/docker");
        assert_eq!(
            args,
            [
                "buildx",
                "build",
                "--load",
                "--platform=linux/amd64",
                "--file",
                "/build with spaces/Dockerfile.wasm-container",
                "--tag",
                "temporary:tag",
                "--iidfile",
                "/stage/image.id",
                "/build with spaces"
            ]
        );
        let root = tempfile::tempdir().unwrap();
        let context = root.path().join("build with spaces");
        fs::create_dir(&context).unwrap();
        fs::write(context.join("state-profile.json"), b"{}").unwrap();
        let command = convert(
            Path::new("/tools/c2w"),
            Path::new("/tools/docker"),
            &wasm_exit::Assets {
                dockerfile: "/build with spaces/wasm-exit/Dockerfile".into(),
                context: context.clone(),
            },
            "temporary:tag",
            Path::new("/output with spaces/program.wasm"),
        )
        .unwrap();
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "--builder",
                "/tools/docker",
                "--target-arch=amd64",
                "--build-arg",
                "VM_MEMORY_SIZE_MB=512",
                "--build-arg",
                "OPTIMIZATION_MODE=native",
                "--dockerfile",
                "/build with spaces/wasm-exit/Dockerfile",
                "--extra-flag",
                &format!("--build-context=ostadix-exit={}", context.display()),
                "temporary:tag",
                "/output with spaces/program.wasm"
            ]
        );
    }

    #[test]
    fn rejects_non_linux_amd64_images_before_conversion() {
        validate_platform("linux/amd64\n").unwrap();
        for platform in [
            "linux/arm64",
            "windows/amd64",
            "",
            "linux/amd64\nlinux/arm64",
        ] {
            assert!(validate_platform(platform).is_err());
        }
    }

    #[test]
    fn rejects_existing_output_before_external_commands() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("program.wasm");
        fs::write(&output, "existing artifact").unwrap();
        let error = build(directory.path(), &output, &options()).unwrap_err();
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(fs::read(&output).unwrap(), b"existing artifact");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_output_parent_delimiters_before_external_commands() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["with,comma", "with\nnewline", "with\rcarriage-return"] {
            let parent = directory.path().join(name);
            fs::create_dir(&parent).unwrap();
            let output = parent.join("program.wasm");
            let error = build(directory.path(), &output, &options()).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("output parent directory cannot contain commas or line breaks"),
                "unexpected error: {error:#}"
            );
            assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
        }
        // Only the staging parent enters c2w's exporter option. Publication
        // can still use a comma in the final output filename.
        assert!(output_path(&directory.path().join("program,allowed.wasm")).is_ok());
    }

    #[test]
    fn malformed_or_missing_inputs_fail_without_running_builders() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("program.wasm");
        assert!(build(directory.path(), &output, &options())
            .unwrap_err()
            .to_string()
            .contains("cargo/Cargo.toml"));
        let mut invalid = options();
        invalid.builder_image = "rust:latest".to_owned();
        assert!(write_recipe(directory.path(), &invalid).is_err());
        assert!(!directory.path().join(RECIPE).exists());
        assert!(!output.exists());
    }

    #[test]
    fn checks_core_wasm_header_and_publishes_without_clobbering() {
        let directory = tempfile::tempdir().unwrap();
        let staged = directory.path().join("staged.wasm");
        let output = directory.path().join("program.wasm");
        for bytes in [b"".as_slice(), b"\0asm", b"\0asm\x0d\0\x01\0", b"not wasm"] {
            fs::write(&staged, bytes).unwrap();
            assert!(publish(&staged, &output).is_err());
            assert!(!output.exists());
        }
        fs::write(&staged, b"\0asm\x01\0\0\0").unwrap();
        publish(&staged, &output).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"\0asm\x01\0\0\0");
        assert!(publish(&staged, &output).is_err());
        assert!(validate_module(directory.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_inputs_and_dangling_output_links() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("program.wasm");
        let target = directory.path().join("absent");
        symlink(&target, &output).unwrap();
        assert!(output_path(&output).is_err());
        let staged = directory.path().join("staged.wasm");
        fs::write(&staged, b"\0asm\x01\0\0\0").unwrap();
        assert!(publish(&staged, &output).is_err());
        assert!(!target.exists());
        assert!(validate_module(&output).is_err());
        let recipe_target = directory.path().join("real-recipe");
        fs::write(&recipe_target, recipe(&options()).unwrap()).unwrap();
        symlink(&recipe_target, directory.path().join(RECIPE)).unwrap();
        assert!(write_recipe(directory.path(), &options()).is_err());
    }
}
