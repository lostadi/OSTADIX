//! Original-source recipe orchestration through the existing capture protocol.
//!
//! Build products are reference/capture evidence. Only the subsequent verified
//! O-core importer produces the native module set; neither stage qualifies a
//! complete runtime, dependency closure, or OSTADIX execution environment.

use super::*;
use std::path::Component;

pub(super) const RECIPE_FORMAT: &str = "ocore-runtime-recipe-v1";
const RECEIPT_SCHEMA: &str = "ocore-native-source-recipe-v1";
const CAPTURE_WORKER: &str = include_str!("../../../../scripts/ocore_runtime_capture.py");
const PRODUCER_REGISTRY: &str = include_str!("../../../../scripts/ocore_producer_registry.json");
const RUST_PAYLOAD: &str =
    include_str!("../../../../tools/ocore-runtime/rust/payload_inventory.py");

#[derive(Default)]
pub(crate) struct NativeSourceOptions<'a> {
    pub(crate) source: Option<&'a Path>,
    pub(crate) cc: Option<&'a Path>,
    pub(crate) cxx: Option<&'a Path>,
    pub(crate) rustc: Option<&'a Path>,
    pub(crate) cargo: Option<&'a Path>,
    pub(crate) llvm_nm: Option<&'a Path>,
    pub(crate) llvm_dis: Option<&'a Path>,
    pub(crate) unit_inventory: Option<&'a Path>,
    pub(crate) jobs: Option<usize>,
}

impl NativeSourceOptions<'_> {
    pub(super) fn requested(&self) -> bool {
        self.source.is_some()
            || self.cc.is_some()
            || self.cxx.is_some()
            || self.rustc.is_some()
            || self.cargo.is_some()
            || self.llvm_nm.is_some()
            || self.llvm_dis.is_some()
            || self.unit_inventory.is_some()
            || self.jobs.is_some()
    }
}

/// Resolve an as-yet nonexistent output against its real existing parent.
/// In particular, never create missing ancestors before detecting source aliases.
fn new_output(path: &Path, source: &Path, recipe: &Path) -> Result<PathBuf> {
    // Compare filesystem identities on both sides. A source path may use a
    // symlinked ancestor (including macOS /var -> /private/var) even when the
    // output's parent has already been resolved to its physical location.
    let source = source
        .canonicalize()
        .context("resolve original source checkout")?;
    let recipe = recipe.canonicalize().context("resolve source recipe")?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let name = absolute
        .file_name()
        .context("source recipe output requires a new directory name")?;
    let parent = absolute
        .parent()
        .context("source recipe output has no parent")?
        .canonicalize()
        .context("source recipe output parent must already exist")?;
    let output = parent.join(name);
    if output.starts_with(&source)
        || source.starts_with(&output)
        || recipe.starts_with(&output)
        || output.starts_with(&recipe)
    {
        bail!("source recipe output must be separate from the source checkout and input recipe");
    }
    match fs::symlink_metadata(&output) {
        Ok(_) => bail!(
            "source recipe output must be a new directory: {}",
            output.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect source recipe output"),
    }
    Ok(output)
}

fn inventory_path(build: &Path, requested: Option<&Path>) -> Result<PathBuf> {
    let requested = requested.unwrap_or_else(|| Path::new("unit-inventory.json"));
    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        build.join(requested)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!("source recipe unit inventory escapes its build directory");
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    if normalized == build || !normalized.starts_with(build) {
        bail!(
            "source recipe unit inventory must be a generated file inside the new build directory"
        );
    }
    Ok(normalized)
}

fn artifact_record(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read artifact {}", path.display()))?;
    Ok(json!({"path":path,"sha256":digest(&bytes),"bytes":bytes.len()}))
}

fn write_receipt(output: &Path, receipt: &Value) -> Result<()> {
    fs::write(
        output.join("source-recipe.json"),
        serde_json::to_vec_pretty(receipt)?,
    )
    .context("write original-source orchestration receipt")
}

fn immutable_driver(
    recipe: &Path,
    bytes: &[u8],
    worker: &Path,
    helper: &Path,
    registry: &Path,
) -> Result<()> {
    if fs::read(recipe)? != bytes
        || fs::read(worker)? != CAPTURE_WORKER.as_bytes()
        || fs::read(helper)? != RUST_PAYLOAD.as_bytes()
        || fs::read(registry)? != PRODUCER_REGISTRY.as_bytes()
    {
        bail!("source recipe or embedded capture implementation changed during orchestration");
    }
    Ok(())
}

// Keep source bytes, output contract, both option sets, and compiler identity
// explicit at the shared native-runtime orchestration boundary.
#[allow(clippy::too_many_arguments)]
pub(super) fn compile(
    recipe_input: &Path,
    recipe_bytes: &[u8],
    target: &str,
    output_kind: &str,
    requested_output: &Path,
    import_options: NativeImportOptions<'_>,
    options: NativeSourceOptions<'_>,
    compiler: &Path,
) -> Result<()> {
    // Reject configuration/path mistakes before creating any output or running
    // the user-selected original build. Pins remain the capture worker's check.
    architecture(target)?;
    if !matches!(output_kind, "ir" | "obj") {
        bail!("native runtime output must be ir or obj");
    }
    if import_options.llvm_library.is_some() != import_options.llvm_sha256.is_some() {
        bail!("explicit LLVM parser library and SHA-256 must be supplied together");
    }
    let jobs = options.jobs.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
    });
    if jobs == 0 {
        bail!("--native-runtime-jobs must be positive");
    }
    let source = options
        .source
        .context("original-source recipe requires --native-runtime-source CHECKOUT")?
        .canonicalize()
        .context("resolve original source checkout")?;
    if !source.is_dir() {
        bail!("original source checkout must be a directory");
    }
    let recipe = recipe_input
        .canonicalize()
        .context("resolve source recipe")?;
    if !recipe.is_file() || fs::read(&recipe)? != recipe_bytes {
        bail!("input source recipe changed before capture");
    }
    let output = new_output(requested_output, &source, &recipe)?;
    let build = output.join("build");
    let capture = output.join("capture");
    let lowered = output.join("lowered");
    let inventory = inventory_path(&build, options.unit_inventory)?;
    fs::create_dir(&output).context("create new original-source output directory")?;

    // Preserve the registered helper's script-relative lookup without relying
    // on a repository checkout next to the installed olangc executable.
    let worker = output.join("driver/scripts/ocore_runtime_capture.py");
    let registry = output.join("driver/scripts/ocore_producer_registry.json");
    let helper = output.join("driver/tools/ocore-runtime/rust/payload_inventory.py");
    let mut receipt = json!({"schema":RECEIPT_SCHEMA,"stage":"capture","success":false,
        "recipe":{"path":recipe,"sha256":digest(recipe_bytes),"bytes":recipe_bytes.len()},
        "source":source,"build":build,"capture_directory":capture,"lowered_directory":lowered,
        "requested_target":target,"output_kind":output_kind,"unit_inventory":inventory,
        "capture_worker":{"path":worker,"sha256":digest(CAPTURE_WORKER.as_bytes()),"bytes":CAPTURE_WORKER.len()},
        "producer_registry":{"path":registry,"sha256":digest(PRODUCER_REGISTRY.as_bytes()),"bytes":PRODUCER_REGISTRY.len()},
        "rust_payload_helper":{"path":helper,"sha256":digest(RUST_PAYLOAD.as_bytes()),"bytes":RUST_PAYLOAD.len()},
        "capture_process":null,"capture_report":null,"lowering_receipt":null,
        "worker_capture_complete":false,"capture_complete":false,"lowering_complete":false,
        "dependency_closure_complete":false,"artifact_complete":false,"link_performed":false,
        "native_execution_qualified":false,"runtime_complete":false,
        "scope":"original source build capture followed by independently verified O-core unit lowering; reference build products do not qualify owned native runtime execution"});
    write_receipt(&output, &receipt)?;
    let result = (|| -> Result<()> {
        fs::create_dir_all(worker.parent().unwrap())?;
        fs::create_dir_all(helper.parent().unwrap())?;
        fs::write(&worker, CAPTURE_WORKER.as_bytes())?;
        fs::write(&registry, PRODUCER_REGISTRY.as_bytes())?;
        fs::write(&helper, RUST_PAYLOAD.as_bytes())?;
        let log = output.join("capture.log");
        let log_file = fs::File::create(&log)?;
        let mut command = Command::new("python3");
        command
            .arg("-I")
            .arg(&worker)
            .arg("capture")
            .arg(&recipe)
            .arg("--source")
            .arg(&source)
            .arg("--build")
            .arg(&build)
            .arg("--output")
            .arg(&capture)
            .arg("--jobs")
            .arg(jobs.to_string())
            .arg("--unit-inventory")
            .arg(&inventory);
        for (flag, value, default) in [
            ("--cc", options.cc, "clang"),
            ("--cxx", options.cxx, "clang++"),
            ("--rustc", options.rustc, "rustc"),
            ("--cargo", options.cargo, "cargo"),
            ("--llvm-nm", options.llvm_nm, "llvm-nm"),
            ("--llvm-dis", options.llvm_dis, "llvm-dis"),
        ] {
            command
                .arg(flag)
                .arg(value.unwrap_or_else(|| Path::new(default)));
        }
        let argv = command
            .get_args()
            .map(|arg| {
                arg.to_str()
                    .context("source capture arguments must be UTF-8")
            })
            .collect::<Result<Vec<_>>>()?;
        receipt["capture_process"] = json!({"program":"python3",
            "argv":argv,"log":log,
            "exit_code":null,"success":false});
        write_receipt(&output, &receipt)?;
        let status = command
            .stdout(log_file.try_clone()?)
            .stderr(log_file)
            .status()
            .context("execute embedded original-source capture worker")?;
        receipt["capture_process"]["exit_code"] = json!(status.code());
        receipt["capture_process"]["success"] = json!(status.success());
        let report = capture.join("report.json");
        if report.is_file() {
            receipt["capture_report"] = artifact_record(&report)?;
            let captured: Value = serde_json::from_slice(&fs::read(&report)?)?;
            receipt["worker_capture_complete"] = json!(captured["capture_complete"] == true);
        }
        immutable_driver(&recipe, recipe_bytes, &worker, &helper, &registry)?;
        if !status.success() {
            bail!(
                "original-source capture failed ({status}); see {}",
                log.display()
            );
        }
        if receipt["worker_capture_complete"] != true {
            bail!("capture worker did not produce a complete source-build report");
        }
        // An inventory locator must not become an ambient/prebuilt file through
        // a symlink introduced by a build step. The worker still verifies its
        // actual unit/producer/build ownership independently.
        if !inventory.canonicalize()?.starts_with(build.canonicalize()?) {
            bail!("generated unit inventory resolved outside the new build directory");
        }
        // Keep the exact report identity recorded immediately after capture.
        // Even a valid JSON replacement must not silently rebind this receipt.
        let report_bytes = checked_evidence(&receipt["capture_report"])
            .context("captured source-build report changed before native lowering")?;
        receipt["stage"] = json!("lowering");
        write_receipt(&output, &receipt)?;
        let lowering = compile_with_compiler(
            &report,
            target,
            output_kind,
            &lowered,
            import_options,
            compiler,
        );
        let coverage = lowered.join("coverage.json");
        if coverage.is_file() {
            receipt["lowering_receipt"] = artifact_record(&coverage)?;
        }
        let replay = lowered.join("capture-reverification.json");
        if replay.is_file() {
            let verified: Value = serde_json::from_slice(&fs::read(&replay)?)?;
            receipt["capture_complete"] = json!(
                verified["schema"] == "ocore-runtime-capture-verification-v1"
                    && verified["verified"] == true
                    && verified["admitted_report"]["sha256"] == digest(&report_bytes)
            );
            receipt["capture_reverification"] = artifact_record(&replay)?;
        }
        immutable_driver(&recipe, recipe_bytes, &worker, &helper, &registry)?;
        if fs::read(&report)? != report_bytes {
            bail!("captured source-build report changed during native lowering");
        }
        lowering?;
        if receipt["capture_complete"] != true {
            bail!("native lowering did not independently verify the source capture");
        }
        receipt["lowering_complete"] = json!(true);
        receipt["stage"] = json!("complete");
        receipt["success"] = json!(true);
        Ok(())
    })();
    if let Err(error) = &result {
        receipt["error"] = json!(format!("{error:#}"));
    }
    write_receipt(&output, &receipt)?;
    result?;
    eprintln!(
        "olangc: original-source recipe completed verified unit lowering; receipt {}",
        output.join("source-recipe.json").display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_output_aliases_and_inventory_escapes_fail_before_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        fs::create_dir(&source).unwrap();
        let recipe = directory.path().join("recipe.json");
        fs::write(&recipe, b"{}").unwrap();
        for output in [source.join("output"), source.join("../source/output")] {
            assert!(new_output(&output, &source, &recipe).is_err());
            assert!(!source.join("output").exists());
        }
        let output = directory.path().join("output");
        let build = output.join("build");
        for inventory in [Path::new("../outside.json"), Path::new("/tmp/outside.json")] {
            assert!(inventory_path(&build, Some(inventory)).is_err());
        }
        assert_eq!(
            inventory_path(&build, None).unwrap(),
            build.join("unit-inventory.json")
        );
        assert!(!output.exists());
        #[cfg(unix)]
        {
            let link = directory.path().join("source-alias");
            std::os::unix::fs::symlink(&source, &link).unwrap();
            assert!(new_output(&link.join("output"), &source, &recipe).is_err());
            assert!(!source.join("output").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_output_checks_resolve_symlinked_input_ancestors() {
        let directory = tempfile::tempdir().unwrap();
        let physical = directory.path().canonicalize().unwrap();
        let source = physical.join("source");
        fs::create_dir(&source).unwrap();
        let recipe = physical.join("recipe.json");
        fs::write(&recipe, b"{}").unwrap();
        let alias = physical.join("alias");
        std::os::unix::fs::symlink(&physical, &alias).unwrap();

        let aliased_source = alias.join("source");
        let aliased_recipe = alias.join("recipe.json");
        for output in [source.join("output"), aliased_source.join("output")] {
            assert!(new_output(&output, &aliased_source, &aliased_recipe).is_err());
            assert!(!source.join("output").exists());
        }

        // Resolving inputs must still allow a genuinely separate new output,
        // without creating it or accepting a missing parent directory.
        assert_eq!(
            new_output(&alias.join("output"), &aliased_source, &aliased_recipe).unwrap(),
            physical.join("output")
        );
        assert!(!physical.join("output").exists());
        assert!(new_output(
            &alias.join("missing/output"),
            &aliased_source,
            &aliased_recipe
        )
        .is_err());
        assert!(!physical.join("missing").exists());
    }
}
