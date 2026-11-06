use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::hir::{HirProgram, Type};
use super::{codegen, codegen_aarch64, codegen_riscv64};
use super::{mir, parser, typeck, Diagnostic, Span};

pub use super::Target;

#[path = "native_machine_object_diagnostic.rs"]
pub mod machine_object_diagnostic;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitKind {
    Ast,
    Hir,
    Mir,
    Assembly,
    Object,
}

#[derive(Debug, Clone)]
pub struct CompileOptions {
    pub target: Target,
    pub emit: EmitKind,
    pub output: PathBuf,
    pub keep_assembly: bool,
}

#[derive(Debug, Clone)]
pub struct CompileOutput {
    pub output: PathBuf,
    pub assembly: Option<PathBuf>,
}

pub fn compile(inputs: &[PathBuf], options: &CompileOptions) -> Result<CompileOutput, Diagnostic> {
    compile_with_function_sections(inputs, options, false)
}

/// Compile a complete imported module through O-core's own ISA emitter.
/// Textual MIR output here is a reloadable, verified native module.
pub fn compile_native_module(
    input: &Path,
    options: &CompileOptions,
) -> Result<CompileOutput, Diagnostic> {
    compile_native_module_with_map(input, options, None)
}

/// Descriptive correspondence between a verified imported module, its own
/// assembly emission, and the exact output artifact. This carries no admission
/// authority, runtime observations, machine-address map, or source-level map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactMap {
    pub format: String,
    pub module_file_sha256: String,
    /// Exact module snapshot, recoverable even when the LLVM worker's input
    /// module existed only in a private temporary. This is not source authority.
    pub native_module_json: String,
    pub artifact_kind: String,
    pub artifact_sha256: String,
    pub artifact_bytes: usize,
    pub assembly: super::native_map::NativeAssemblyMap,
    /// Computed frame/continuation correspondence for original returns_twice
    /// effects. This does not qualify providers or Rust/OValue exposure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonlocal_control: Option<super::native_nonlocal::NativeNonlocalReport>,
}

pub const NATIVE_ARTIFACT_MAP_FORMAT: &str = "ocore-native-artifact-map-v1";

/// Compile with an optional artifact-bound instruction-to-assembly sidecar.
/// Existing emission is unchanged when no sidecar is requested.
pub fn compile_native_module_with_map(
    input: &Path,
    options: &CompileOptions,
    map_output: Option<&Path>,
) -> Result<CompileOutput, Diagnostic> {
    if let Some(map_output) = map_output {
        prepare_native_map_output(&[input.to_path_buf()], options, map_output)?;
    }
    let bytes = fs::read(input)
        .map_err(|e| driver_error(format!("failed to read {}: {e}", input.display())))?;
    let module = super::native_ir::NativeModule::from_json(&bytes)?;
    if options.emit == EmitKind::Mir {
        let json = module.to_json()?;
        write_text(&options.output, std::str::from_utf8(&json).unwrap())?;
        return Ok(CompileOutput {
            output: options.output.clone(),
            assembly: None,
        });
    }
    if matches!(options.emit, EmitKind::Ast | EmitKind::Hir) {
        return Err(driver_error(
            "imported native modules have no .oc AST/HIR; use --emit mir",
        ));
    }
    let (assembly, map, nonlocal_control) = if map_output.is_some()
        && module.has_nonlocal_control_effects()
    {
        let (assembly, map, report) =
            super::native_codegen::emit_with_map_and_nonlocal_report(&module, options.target)?;
        (assembly, Some(map), Some(report))
    } else if map_output.is_some() {
        let (assembly, map) = super::native_codegen::emit_with_map(&module, options.target)?;
        (assembly, Some(map), None)
    } else {
        (super::native_codegen::emit(&module, options.target)?, None, None)
    };
    let output = if options.emit == EmitKind::Assembly {
        write_text(&options.output, &assembly)?;
        CompileOutput {
            output: options.output.clone(),
            assembly: Some(options.output.clone()),
        }
    } else {
        emit_object(
            options,
            &assembly,
            module.target.abi.as_deref(),
            native_block_labels_required(&module),
        )?
    };
    if let (Some(path), Some(map)) = (map_output, map) {
        let artifact = fs::read(&output.output)
            .map_err(|error| driver_error(format!("failed to bind native output: {error}")))?;
        let record = NativeArtifactMap {
            format: NATIVE_ARTIFACT_MAP_FORMAT.into(),
            module_file_sha256: hex::encode(Sha256::digest(&bytes)),
            native_module_json: String::from_utf8(bytes.clone())
                .map_err(|error| driver_error(format!("native module is not UTF-8: {error}")))?,
            artifact_kind: if options.emit == EmitKind::Assembly {
                "assembly"
            } else {
                "object"
            }
            .into(),
            artifact_sha256: hex::encode(Sha256::digest(&artifact)),
            artifact_bytes: artifact.len(),
            assembly: map,
            nonlocal_control,
        };
        let json = serde_json::to_string_pretty(&record)
            .map_err(|error| driver_error(format!("failed to serialize native map: {error}")))?;
        write_text(path, &json)?;
    }
    Ok(output)
}

/// Check all original inputs before import or stale-map removal. The CLI must
/// include original LLVM inputs here because the driver's imported JSON is a
/// separate temporary snapshot. A failed import must invalidate an old map too.
pub fn prepare_native_map_output(
    inputs: &[PathBuf],
    options: &CompileOptions,
    map_output: &Path,
) -> Result<(), Diagnostic> {
    if !matches!(options.emit, EmitKind::Assembly | EmitKind::Object) {
        return Err(driver_error(
            "a native map requires assembly or object emission",
        ));
    }
    if map_output == Path::new("-") || options.output == Path::new("-") {
        return Err(driver_error(
            "native maps require explicit artifact and map files",
        ));
    }
    let mut artifacts = vec![options.output.clone()];
    if options.keep_assembly && options.emit == EmitKind::Object {
        let assembly = options.output.with_extension("s");
        if paths_alias(&options.output, &assembly)? {
            return Err(driver_error(
                "native output and retained assembly must be distinct files",
            ));
        }
        artifacts.push(assembly);
    }
    for path in inputs.iter().chain(&artifacts) {
        if paths_alias(map_output, path)? {
            return Err(driver_error(
                "native map must not overwrite the input, output, or retained assembly",
            ));
        }
    }
    for input in inputs {
        for path in &artifacts {
            if paths_alias(input, path)? {
                return Err(driver_error(
                    "native artifacts must not overwrite the input module",
                ));
            }
        }
    }
    match fs::remove_file(map_output) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(driver_error(format!(
            "failed to remove stale native map: {error}"
        ))),
    }
}

/// Recompute every assembly site from the verified module, then check the
/// exact artifact digest. An object digest identifies bytes; it does not prove
/// assembler correctness, linking, execution, or graph-to-native preservation.
pub fn verify_native_artifact_map(
    input: Option<&Path>,
    map_input: &Path,
    assembly_input: &Path,
    artifact_input: &Path,
    target: Target,
) -> Result<NativeArtifactMap, Diagnostic> {
    let read = |path: &Path| {
        fs::read(path)
            .map_err(|error| driver_error(format!("failed to read {}: {error}", path.display())))
    };
    let record: NativeArtifactMap = serde_json::from_slice(&read(map_input)?)
        .map_err(|error| driver_error(format!("invalid native artifact map: {error}")))?;
    let bytes = match input {
        Some(input) => read(input)?,
        None => record.native_module_json.as_bytes().to_vec(),
    };
    let module = super::native_ir::NativeModule::from_json(&bytes)?;
    if record.format != NATIVE_ARTIFACT_MAP_FORMAT
        || record.module_file_sha256 != hex::encode(Sha256::digest(&bytes))
        || record.native_module_json.as_bytes() != bytes
        || !matches!(record.artifact_kind.as_str(), "assembly" | "object")
    {
        return Err(driver_error(
            "native artifact map format or module binding mismatch",
        ));
    }
    let assembly_bytes = read(assembly_input)?;
    let assembly = std::str::from_utf8(&assembly_bytes)
        .map_err(|error| driver_error(format!("native assembly is not UTF-8: {error}")))?;
    record.assembly.verify(&module, target, assembly)?;
    match (&record.nonlocal_control, module.has_nonlocal_control_effects()) {
        (Some(report), true) => {
            let raw = serde_json::to_vec(report)
                .map_err(|error| driver_error(format!("invalid native nonlocal report: {error}")))?;
            super::native_nonlocal::verify_report_json(&raw, &module, target, assembly)?;
        }
        (None, false) => {}
        _ => {
            return Err(driver_error(
                "native artifact map nonlocal-control report presence mismatch",
            ));
        }
    }
    let artifact = read(artifact_input)?;
    if record.artifact_bytes != artifact.len()
        || record.artifact_sha256 != hex::encode(Sha256::digest(&artifact))
        || (record.artifact_kind == "assembly" && artifact != assembly_bytes)
    {
        return Err(driver_error("native artifact map output binding mismatch"));
    }
    Ok(record)
}

fn paths_alias(left: &Path, right: &Path) -> Result<bool, Diagnostic> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(left), Ok(right)) = (fs::metadata(left), fs::metadata(right)) {
            if left.dev() == right.dev() && left.ino() == right.ino() {
                return Ok(true);
            }
        }
    }
    fn resolve(path: &Path) -> Result<PathBuf, Diagnostic> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| driver_error(format!("resolve artifact path: {error}")))?
                .join(path)
        };
        let mut ancestor = absolute.as_path();
        let mut tail = Vec::new();
        let mut resolved = loop {
            if let Ok(resolved) = ancestor.canonicalize() {
                break resolved;
            }
            let name = ancestor
                .file_name()
                .ok_or_else(|| driver_error("cannot resolve native artifact path"))?;
            tail.push(name.to_os_string());
            ancestor = ancestor
                .parent()
                .ok_or_else(|| driver_error("native artifact path has no parent"))?;
        };
        for component in tail.iter().rev() {
            resolved.push(component);
        }
        Ok(resolved)
    }
    Ok(resolve(left)? == resolve(right)?)
}

pub fn compile_with_function_sections(
    inputs: &[PathBuf],
    options: &CompileOptions,
    function_sections: bool,
) -> Result<CompileOutput, Diagnostic> {
    if inputs.is_empty() {
        return Err(driver_error("at least one .oc input is required"));
    }
    let mut parsed = Vec::new();
    for path in inputs {
        let source = fs::read_to_string(path).map_err(|error| Diagnostic {
            file: path.display().to_string(),
            span: Span::default(),
            message: format!("failed to read source: {error}"),
        })?;
        let file = path.display().to_string();
        parsed.push((file.clone(), parser::parse(&file, &source)?));
    }

    if options.emit == EmitKind::Ast {
        write_text(&options.output, &format!("{parsed:#?}"))?;
        return Ok(CompileOutput {
            output: options.output.clone(),
            assembly: None,
        });
    }

    let hir = typeck::check(&parsed)?;
    if options.emit == EmitKind::Hir {
        write_text(&options.output, &hir_text(&hir))?;
        return Ok(CompileOutput {
            output: options.output.clone(),
            assembly: None,
        });
    }

    let mir = mir::lower(&hir)?;
    if options.emit == EmitKind::Mir {
        write_text(&options.output, &mir.to_text(&hir))?;
        return Ok(CompileOutput {
            output: options.output.clone(),
            assembly: None,
        });
    }

    let assembly = match options.target {
        Target::X86_64UnknownNone => {
            codegen::emit_assembly_with_function_sections(&hir, &mir, function_sections)?
        }
        Target::Aarch64UnknownNone => {
            codegen_aarch64::emit_assembly_with_function_sections(&hir, &mir, function_sections)?
        }
        Target::Riscv64UnknownNone => {
            codegen_riscv64::emit_assembly_with_function_sections(&hir, &mir, function_sections)?
        }
    };
    if options.emit == EmitKind::Assembly {
        write_text(&options.output, &assembly)?;
        return Ok(CompileOutput {
            output: options.output.clone(),
            assembly: Some(options.output.clone()),
        });
    }

    emit_object(options, &assembly, None, false)
}

fn native_block_labels_required(module: &super::native_ir::NativeModule) -> bool {
    use super::native_ir::{Operand, Terminator};
    fn contains_block(value: &Operand) -> bool {
        let mut pending = vec![value];
        while let Some(value) = pending.pop() {
            match value {
                Operand::BlockAddress { .. } => return true,
                Operand::Aggregate { elements, .. } => pending.extend(elements),
                _ => {}
            }
        }
        false
    }
    module.globals.iter().any(|global| {
        global.initializer.as_ref().is_some_and(|initializer| {
            initializer
                .relocations
                .iter()
                .any(|relocation| relocation.block.is_some())
        })
    }) || module
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .any(|block| {
            matches!(block.terminator, Terminator::IndirectBranch { .. })
                || block.instructions.iter().any(|instruction| {
                    super::native_verify::instruction_operands(&instruction.operation)
                        .into_iter()
                        .any(contains_block)
                })
                || super::native_verify::terminator_operands(&block.terminator)
                    .into_iter()
                    .any(contains_block)
        })
}

fn object_assembler_abi(
    target: Target,
    imported_abi: Option<&str>,
) -> Result<Option<&'static str>, Diagnostic> {
    match (target, imported_abi) {
        (Target::Riscv64UnknownNone, None | Some("lp64")) => Ok(Some("lp64")),
        (Target::Riscv64UnknownNone, Some("lp64d")) => Ok(Some("lp64d")),
        (_, None) => Ok(None),
        (_, Some(abi)) => Err(driver_error(format!(
            "unsupported imported assembler ABI `{abi}` for {}",
            target.architecture()
        ))),
    }
}

fn emit_object(
    options: &CompileOptions,
    assembly: &str,
    imported_abi: Option<&str>,
    retain_block_labels: bool,
) -> Result<CompileOutput, Diagnostic> {
    let abi = object_assembler_abi(options.target, imported_abi)?;
    if let Some(parent) = options.output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| driver_error(format!("failed to create {}: {e}", parent.display())))?;
        }
    }
    let assembly_path = if options.keep_assembly {
        options.output.with_extension("s")
    } else {
        std::env::temp_dir().join(format!(
            "ocorec-{}-{}.s",
            std::process::id(),
            monotonic_nonce()
        ))
    };
    fs::write(&assembly_path, assembly)
        .map_err(|e| driver_error(format!("failed to write {}: {e}", assembly_path.display())))?;

    let clang = which::which("clang").map_err(|_| {
        driver_error(format!(
            "clang is required to assemble {} ELF objects",
            options.target.architecture()
        ))
    })?;
    let mut command = object_assembler_command(&clang, options.target, abi, retain_block_labels);
    let output = command
        .arg(&assembly_path)
        .arg("-o")
        .arg(&options.output)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| driver_error(format!("failed to run {}: {e}", clang.display())))?;

    if !options.keep_assembly {
        let _ = fs::remove_file(&assembly_path);
    }
    if !output.status.success() {
        return Err(driver_error(format!(
            "{} assembler failed:\n{}",
            options.target.architecture(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(CompileOutput {
        output: options.output.clone(),
        assembly: options.keep_assembly.then_some(assembly_path),
    })
}

fn object_assembler_command(
    clang: &Path,
    target: Target,
    abi: Option<&str>,
    retain_block_labels: bool,
) -> Command {
    let mut command = Command::new(clang);
    command.args([
        "-target",
        target.triple(),
        "-ffreestanding",
        "-fno-stack-protector",
        "-c",
        "-x",
        "assembler",
    ]);
    if retain_block_labels {
        // The independent object inventory binds verified BlockLabel map sites
        // to local ELF identities. A folded section offset alone cannot identify
        // an original block. Keep the ordinary emission command unchanged.
        command.arg("-Wa,-L");
    }
    if let Some(abi) = abi {
        // Preserve the imported scalar module's ABI marker. LP64D integer
        // arguments use the same integer convention; FP values remain rejected
        // by native_codegen rather than silently converted to an integer ABI.
        command.arg("-march=rv64gc").arg(format!("-mabi={abi}"));
    }
    command
}

/// In-process authority minted only by exact object reproduction below. There
/// is deliberately no Deserialize implementation or public field constructor.
/// This binds an artifact to the selected assembler's result; it does not prove
/// the assembler's correctness or its shared-library/dependency closure.
pub struct NativeObjectReproduction {
    target: Target,
    module_json: Vec<u8>,
    assembly: String,
    input_directory: PathBuf,
    inputs_before: ReproductionInputSnapshot,
    inputs_after: ReproductionInputSnapshot,
    object: Vec<u8>,
    assembler_invoked: PathBuf,
    assembler_resolved: PathBuf,
    assembler_sha256: String,
    environment: (Option<std::ffi::OsString>, Option<std::ffi::OsString>),
    receipt: serde_json::Value,
}

#[derive(serde::Serialize)]
struct ReproductionInputObservation {
    path: PathBuf,
    expected_sha256: String,
    expected_bytes: usize,
    observed_sha256: Option<String>,
    observed_bytes: Option<usize>,
    read_error: Option<String>,
    exact_match: bool,
    retained_mismatch: Option<PathBuf>,
}

#[derive(serde::Serialize)]
struct ReproductionInputSnapshot {
    module: ReproductionInputObservation,
    assembly: ReproductionInputObservation,
}

impl ReproductionInputSnapshot {
    fn matches(&self) -> bool {
        self.module.exact_match && self.assembly.exact_match
    }
}

/// Observe full bytes, not merely the expected in-memory digest. These checks
/// do not seal the files or prevent a change-and-restore race during assembly.
fn observe_reproduction_inputs(
    directory: &Path,
    module: &[u8],
    assembly: &[u8],
    phase: &str,
) -> Result<ReproductionInputSnapshot, Diagnostic> {
    fn observe(
        path: PathBuf,
        expected: &[u8],
        mismatch: PathBuf,
    ) -> Result<ReproductionInputObservation, Diagnostic> {
        let mut observation = ReproductionInputObservation {
            path: path.clone(),
            expected_sha256: hex::encode(Sha256::digest(expected)),
            expected_bytes: expected.len(),
            observed_sha256: None,
            observed_bytes: None,
            read_error: None,
            exact_match: false,
            retained_mismatch: None,
        };
        match fs::read(&path) {
            Ok(bytes) => {
                observation.observed_sha256 = Some(hex::encode(Sha256::digest(&bytes)));
                observation.observed_bytes = Some(bytes.len());
                observation.exact_match = bytes == expected;
                if !observation.exact_match {
                    fs::write(&mismatch, &bytes).map_err(|error| {
                        driver_error(format!("retain changed reproduction input: {error}"))
                    })?;
                    observation.retained_mismatch = Some(mismatch);
                }
            }
            Err(error) => observation.read_error = Some(error.to_string()),
        }
        Ok(observation)
    }
    let snapshot = ReproductionInputSnapshot {
        module: observe(
            directory.join("module.native.json"),
            module,
            directory.join(format!("{phase}-module.observed.json")),
        )?,
        assembly: observe(
            directory.join("module.s"),
            assembly,
            directory.join(format!("{phase}-assembly.observed.s")),
        )?,
    };
    fs::write(
        directory.join(format!("inputs-{phase}.json")),
        serde_json::to_vec_pretty(&snapshot).map_err(|error| {
            driver_error(format!(
                "serialize reproduction input observations: {error}"
            ))
        })?,
    )
    .map_err(|error| driver_error(format!("retain reproduction input observations: {error}")))?;
    Ok(snapshot)
}

fn selected_object_assembler() -> Result<(PathBuf, PathBuf, String), Diagnostic> {
    // This is the existing compiler-owned selection policy, not an executable
    // or expected digest supplied by a witness/receipt caller.
    let invoked = which::which("clang")
        .map_err(|_| driver_error("clang is required for independent object reproduction"))?;
    let resolved = invoked
        .canonicalize()
        .map_err(|error| driver_error(format!("resolve selected assembler: {error}")))?;
    let bytes = fs::read(&resolved)
        .map_err(|error| driver_error(format!("pin selected assembler: {error}")))?;
    Ok((invoked, resolved, hex::encode(Sha256::digest(&bytes))))
}

impl NativeObjectReproduction {
    pub fn receipt(&self) -> &serde_json::Value {
        &self.receipt
    }

    /// Rebind private observed bytes, never a supplied success flag/digest.
    pub fn verify(
        &self,
        module: &super::native_ir::NativeModule,
        target: Target,
        object: &[u8],
    ) -> Result<(), Diagnostic> {
        if target != self.target || module.to_json()? != self.module_json || object != self.object {
            return Err(driver_error(
                "independent object reproduction module/target/object mismatch",
            ));
        }
        let (assembly, _) = super::native_codegen::emit_with_map(module, target)?;
        if assembly != self.assembly {
            return Err(driver_error(
                "independent object reproduction assembly changed",
            ));
        }
        if !self.inputs_before.matches() || !self.inputs_after.matches() {
            return Err(driver_error(
                "independent object reproduction has unbound input observations",
            ));
        }
        let current_inputs = observe_reproduction_inputs(
            &self.input_directory,
            &self.module_json,
            self.assembly.as_bytes(),
            &format!("verify-{}", monotonic_nonce()),
        )?;
        if !current_inputs.matches() {
            return Err(driver_error(format!(
                "on-disk reproduction inputs changed; see {}",
                self.input_directory.display()
            )));
        }
        let (invoked, resolved, sha256) = selected_object_assembler()?;
        if invoked != self.assembler_invoked
            || resolved != self.assembler_resolved
            || sha256 != self.assembler_sha256
            || self.environment
                != (
                    std::env::var_os("PATH"),
                    std::env::var_os("LD_LIBRARY_PATH"),
                )
        {
            return Err(driver_error(
                "independent object reproduction assembler/environment changed",
            ));
        }
        Ok(())
    }
}

/// Independently regenerate verified MIR assembly and reproduce exact object
/// bytes under the compiler-owned selected/pinned assembler and ABI. Every
/// attempted invocation and its raw output remain in a fresh evidence directory.
/// A mismatch is an unmet gate; no symbol/section/path normalization is allowed.
pub fn reproduce_native_object(
    module: &super::native_ir::NativeModule,
    target: Target,
    supplied_object: &[u8],
    evidence_root: &Path,
) -> Result<NativeObjectReproduction, Diagnostic> {
    let (assembly, map) = super::native_codegen::emit_with_map(module, target)?;
    let module_json = module.to_json()?;
    let abi = object_assembler_abi(target, module.target.abi.as_deref())?;
    let (invoked, resolved, assembler_sha256) = selected_object_assembler()?;
    let environment = (
        std::env::var_os("PATH"),
        std::env::var_os("LD_LIBRARY_PATH"),
    );
    let directory = evidence_root.join(format!(
        "attempt-{}-{}",
        std::process::id(),
        monotonic_nonce()
    ));
    fs::create_dir_all(&directory)
        .map_err(|error| driver_error(format!("create object reproduction evidence: {error}")))?;
    let directory = directory
        .canonicalize()
        .map_err(|error| driver_error(format!("resolve object reproduction evidence: {error}")))?;
    let assembly_path = directory.join("module.s");
    let object_path = directory.join("module.o");
    fs::write(directory.join("module.native.json"), &module_json)
        .and_then(|_| fs::write(&assembly_path, &assembly))
        .map_err(|error| driver_error(format!("retain object reproduction inputs: {error}")))?;
    let mut command =
        object_assembler_command(&invoked, target, abi, native_block_labels_required(module));
    command.arg(&assembly_path).arg("-o").arg(&object_path);
    let argv: Vec<_> = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|arg| {
            arg.to_str()
                .map(str::to_owned)
                .ok_or_else(|| driver_error("object reproduction argv must be lossless UTF-8"))
        })
        .collect::<Result<_, _>>()?;
    let cwd = std::env::current_dir()
        .map_err(|error| driver_error(format!("resolve object reproduction cwd: {error}")))?;
    command.current_dir(&cwd);
    let inputs_before =
        observe_reproduction_inputs(&directory, &module_json, assembly.as_bytes(), "before")?;
    let invocation = serde_json::json!({
        "format":"ocore-independent-object-invocation-v1",
        "module_sha256":hex::encode(Sha256::digest(&module_json)),
        "module_path":directory.join("module.native.json"),"target":target.name(),
        "frontend_target_and_profiles":module.target,"semantics":module.semantics,
        "assembly_sha256":map.assembly_sha256,"assembly_path":assembly_path,
        "assembler_selection_policy":"ocore-driver-which-clang-v1",
        "assembler_invoked":invoked,"assembler_resolved":resolved,"assembler_sha256":assembler_sha256,
        "argv":argv,"cwd":cwd,"PATH":environment.0,"LD_LIBRARY_PATH":environment.1,
        "object_path":object_path,"supplied_object_sha256":hex::encode(Sha256::digest(supplied_object)),
        "evidence_directory":directory,"inputs_before":inputs_before,
        "input_file_guard_scope":"full-byte observations; no sealed-file or TOCTOU protection"
    });
    fs::write(
        directory.join("invocation.json"),
        serde_json::to_vec_pretty(&invocation)
            .map_err(|error| driver_error(format!("serialize object invocation: {error}")))?,
    )
    .map_err(|error| driver_error(format!("retain object invocation before launch: {error}")))?;
    if !inputs_before.matches() {
        let failure = serde_json::json!({"format":"ocore-independent-object-reproduction-v1",
            "status":"not_launched_input_drift","invocation":"invocation.json",
            "inputs_before":inputs_before,"proof_minted":false,
            "input_file_guard_scope":"full-byte observations; no sealed-file or TOCTOU protection"});
        fs::write(
            directory.join("receipt.json"),
            serde_json::to_vec_pretty(&failure).map_err(|error| {
                driver_error(format!("serialize changed-input receipt: {error}"))
            })?,
        )
        .map_err(|error| driver_error(format!("retain changed-input receipt: {error}")))?;
        return Err(driver_error(format!(
            "on-disk reproduction inputs changed before launch; see {}",
            directory.display()
        )));
    }
    let launched = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    let output = match launched {
        Ok(output) => output,
        Err(error) => {
            let inputs_after = observe_reproduction_inputs(
                &directory,
                &module_json,
                assembly.as_bytes(),
                "after-launch-error",
            )?;
            let failure = serde_json::json!({"format":"ocore-independent-object-launch-failure-v1",
                "status":"spawn_failed","error":error.to_string(),"kind":format!("{:?}",error.kind()),
                "raw_os_error":error.raw_os_error(),"invocation":"invocation.json","proof_minted":false,
                "inputs_before":inputs_before,"inputs_after":inputs_after});
            fs::write(
                directory.join("launch-error.json"),
                serde_json::to_vec_pretty(&failure).map_err(|error| {
                    driver_error(format!("serialize object launch failure: {error}"))
                })?,
            )
            .map_err(|error| driver_error(format!("retain object launch failure: {error}")))?;
            return Err(driver_error(format!(
                "launch independent object reproduction failed: {error}; see {}",
                directory.display()
            )));
        }
    };
    let inputs_after =
        observe_reproduction_inputs(&directory, &module_json, assembly.as_bytes(), "after")?;
    fs::write(directory.join("stdout"), &output.stdout)
        .and_then(|_| fs::write(directory.join("stderr"), &output.stderr))
        .map_err(|error| driver_error(format!("retain object reproduction output: {error}")))?;
    let reproduced = fs::read(&object_path).ok();
    let stable = selected_object_assembler().is_ok_and(|identity| {
        identity == (invoked.clone(), resolved.clone(), assembler_sha256.clone())
    }) && environment
        == (
            std::env::var_os("PATH"),
            std::env::var_os("LD_LIBRARY_PATH"),
        );
    let exact = reproduced.as_deref() == Some(supplied_object);
    let receipt = serde_json::json!({
        "format":"ocore-independent-object-reproduction-v1",
        "module_sha256":hex::encode(Sha256::digest(&module_json)),"target":target.name(),
        "frontend_target_and_profiles":module.target,"semantics":module.semantics,
        "assembly_sha256":map.assembly_sha256,"assembly_map":map,
        "assembler_selection_policy":"ocore-driver-which-clang-v1",
        "assembler_invoked":invoked,"assembler_resolved":resolved,"assembler_sha256":assembler_sha256,
        "argv":argv,"cwd":cwd,"PATH":environment.0,"LD_LIBRARY_PATH":environment.1,
        "status":output.status.code(),"assembler_stable":stable,
        "stdout_sha256":hex::encode(Sha256::digest(&output.stdout)),
        "stderr_sha256":hex::encode(Sha256::digest(&output.stderr)),
        "supplied_object_sha256":hex::encode(Sha256::digest(supplied_object)),
        "reproduced_object_sha256":reproduced.as_ref().map(|bytes| hex::encode(Sha256::digest(bytes))),
        "exact_byte_identity":exact,"evidence_directory":directory,
        "inputs_before":inputs_before,"inputs_after":inputs_after,
        "input_files_match_verified_bytes":inputs_before.matches() && inputs_after.matches(),
        "input_file_guard_scope":"full-byte observations; no sealed-file or TOCTOU protection",
        "assembler_correctness_qualified":false,"assembler_shared_library_closure_qualified":false,
        "native_execution_qualified":false
    });
    fs::write(
        directory.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).map_err(|error| {
            driver_error(format!("serialize object reproduction receipt: {error}"))
        })?,
    )
    .map_err(|error| driver_error(format!("retain object reproduction receipt: {error}")))?;
    if !output.status.success()
        || !stable
        || !exact
        || !inputs_before.matches()
        || !inputs_after.matches()
    {
        return Err(driver_error(format!(
            "independent exact object reproduction failed; see {}",
            directory.display()
        )));
    }
    Ok(NativeObjectReproduction {
        target,
        module_json,
        assembly,
        input_directory: directory,
        inputs_before,
        inputs_after,
        object: reproduced.unwrap(),
        assembler_invoked: invoked,
        assembler_resolved: resolved,
        assembler_sha256,
        environment,
        receipt,
    })
}

fn write_text(path: &Path, text: &str) -> Result<(), Diagnostic> {
    if path == Path::new("-") {
        print!("{text}");
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| driver_error(format!("failed to create {}: {e}", parent.display())))?;
        }
    }
    fs::write(path, text)
        .map_err(|e| driver_error(format!("failed to write {}: {e}", path.display())))
}

fn hir_text(hir: &HirProgram) -> String {
    let mut out = String::from("; O-core resolved typed HIR\n; layouts\n");
    for def in &hir.types.structs {
        out.push_str(&format!(
            "struct {} size={} align={}{}\n",
            def.name,
            def.layout.size,
            def.layout.align,
            if def.packed { " packed" } else { "" }
        ));
        for field in &def.fields {
            out.push_str(&format!(
                "  +{} {}: {}\n",
                field.offset,
                field.name,
                hir.types.name(field.ty)
            ));
        }
    }
    for def in &hir.types.enums {
        out.push_str(&format!(
            "enum {} size={} align={} tag={} payload_offset={}\n",
            def.name, def.layout.size, def.layout.align, def.tag_size, def.payload_offset
        ));
    }
    out.push_str("; functions\n");
    for function in &hir.functions {
        out.push_str(&format!(
            "{}fn {}({}) -> {} abi={:?} symbol={}\n",
            if function.unsafe_ { "unsafe " } else { "" },
            function.qualified_name,
            function
                .params
                .iter()
                .map(|id| {
                    let local = &function.locals[*id];
                    format!("{}: {}", local.name, hir.types.name(local.ty))
                })
                .collect::<Vec<_>>()
                .join(", "),
            hir.types.name(function.result),
            function.abi,
            function.symbol
        ));
    }
    out.push_str("; static types\n");
    for static_ in &hir.statics {
        let class = match hir.types.types[static_.ty] {
            Type::Array { .. } => "aggregate",
            _ => "scalar",
        };
        out.push_str(&format!(
            "static {}: {} ({class}) symbol={}\n",
            static_.qualified_name,
            hir.types.name(static_.ty),
            static_.symbol
        ));
    }
    out
}

static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);

fn monotonic_nonce() -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let sequence = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    format!("{timestamp}-{sequence}")
}

fn driver_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic {
        file: "<ocorec>".into(),
        span: Span::default(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_an_elf64_relocatable_object() {
        let dir = std::env::temp_dir().join(format!("ocore-driver-test-{}", monotonic_nonce()));
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("kernel.oc");
        let object = dir.join("kernel.o");
        fs::write(
            &source,
            r#"
module kernel;
@export @no_mangle
unsafe fn kernel_main() -> never {
    unsafe { outb(0x3f8, b'O'); }
    loop { unsafe { halt(); } }
}
"#,
        )
        .unwrap();
        compile(
            &[source],
            &CompileOptions {
                target: Target::X86_64UnknownNone,
                emit: EmitKind::Object,
                output: object.clone(),
                keep_assembly: false,
            },
        )
        .unwrap();
        let bytes = fs::read(object).unwrap();
        assert_eq!(&bytes[..4], b"\x7fELF");
        assert_eq!(bytes[4], 2); // ELFCLASS64
        assert_eq!(u16::from_le_bytes([bytes[18], bytes[19]]), 62); // EM_X86_64
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn accepts_both_freestanding_target_aliases() {
        assert_eq!(
            Target::parse("x86_64-unknown-none-elf"),
            Some(Target::X86_64UnknownNone)
        );
        assert_eq!(
            Target::parse("aarch64-unknown-none"),
            Some(Target::Aarch64UnknownNone)
        );
        assert_eq!(
            Target::parse("aarch64-unknown-none-elf"),
            Some(Target::Aarch64UnknownNone)
        );
        assert_eq!(Target::parse("aarch64-linux-gnu"), None);
        for alias in [
            "riscv64-unknown-none",
            "riscv64-unknown-none-elf",
            "riscv64gc-unknown-none-elf",
        ] {
            assert_eq!(Target::parse(alias), Some(Target::Riscv64UnknownNone));
        }
        assert_eq!(Target::parse("riscv32-unknown-none"), None);
    }

    #[test]
    fn imported_rv64_integer_objects_preserve_declared_float_abi_marker() {
        let dir = std::env::temp_dir().join(format!(
            "ocore-riscv64-imported-abi-test-{}",
            monotonic_nonce()
        ));
        fs::create_dir_all(&dir).unwrap();
        for (name, abi, expected_flags) in [
            ("unspecified", None, 0),
            ("lp64", Some("lp64"), 0),
            ("lp64d", Some("lp64d"), 4),
        ] {
            let source = dir.join(format!("{name}.json"));
            let object = dir.join(format!("{name}.o"));
            fs::write(
                &source,
                serde_json::to_vec(&serde_json::json!({
                    "format":"ocore-native-module-v1", "name":"integer-abi-profile",
                    "target":{"triple":"riscv64-unknown-linux-gnu",
                              "data_layout":"e-p:64:64-i64:64", "pointer_bits":64,
                              "little_endian":true, "abi":abi},
                    "semantics":"llvm_defined_behavior_v1",
                    "types":[{"kind":"void"},{"kind":"int","bits":64}],
                    "globals":[],
                    "functions":[{"name":"answer", "linkage":"external",
                                  "signature":{"params":[], "result":1, "abi":"c",
                                               "variadic":false},
                                  "params":[], "entry":0,
                                  "blocks":[{"id":0, "instructions":[],
                                             "terminator":{"op":"return", "value":{
                                                 "kind":"int", "ty":1, "bits":"42"}}}]}],
                    "provenance":{"input_sha256":"0".repeat(64), "frontend":"test",
                                  "frontend_version":"1", "importer":"test",
                                  "importer_version":"1", "source_function_count":1,
                                  "source_global_count":0, "refinements":[]}
                }))
                .unwrap(),
            )
            .unwrap();
            compile_native_module(
                &source,
                &CompileOptions {
                    target: Target::Riscv64UnknownNone,
                    emit: EmitKind::Object,
                    output: object.clone(),
                    keep_assembly: false,
                },
            )
            .unwrap();
            let bytes = fs::read(object).unwrap();
            assert_eq!(u16::from_le_bytes(bytes[18..20].try_into().unwrap()), 243);
            let flags = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
            assert_eq!(flags & !1, expected_flags, "lost imported {name} ABI");
        }
        let source = dir.join("ordinary.oc");
        let object = dir.join("ordinary.o");
        fs::write(
            &source,
            "module ordinary; @export @no_mangle fn answer() -> u64 { return 42; }",
        )
        .unwrap();
        compile(
            &[source],
            &CompileOptions {
                target: Target::Riscv64UnknownNone,
                emit: EmitKind::Object,
                output: object.clone(),
                keep_assembly: false,
            },
        )
        .unwrap();
        let bytes = fs::read(object).unwrap();
        let flags = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
        assert_eq!(flags & !1, 0, "ordinary .oc changed from LP64");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn assembler_abi_selection_rejects_unsupported_profiles() {
        for abi in ["lp64f", "lp64q", "ilp32", "LP64D", "", "lp64d "] {
            assert!(object_assembler_abi(Target::Riscv64UnknownNone, Some(abi)).is_err());
        }
        for target in [Target::X86_64UnknownNone, Target::Aarch64UnknownNone] {
            assert_eq!(object_assembler_abi(target, None).unwrap(), None);
            assert!(object_assembler_abi(target, Some("lp64d")).is_err());
        }
    }

    #[test]
    fn compiles_an_aarch64_elf64_relocatable_object() {
        let dir =
            std::env::temp_dir().join(format!("ocore-aarch64-driver-test-{}", monotonic_nonce()));
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("answer.oc");
        let object = dir.join("answer.o");
        fs::write(
            &source,
            r#"
module answer;
static ANSWER: u64 = 42;
@export @no_mangle
fn answer() -> u64 {
    return ANSWER;
}
"#,
        )
        .unwrap();
        compile(
            &[source],
            &CompileOptions {
                target: Target::Aarch64UnknownNone,
                emit: EmitKind::Object,
                output: object.clone(),
                keep_assembly: false,
            },
        )
        .unwrap();
        let bytes = fs::read(object).unwrap();
        assert_eq!(&bytes[..4], b"\x7fELF");
        assert_eq!(bytes[4], 2); // ELFCLASS64
        assert_eq!(u16::from_le_bytes([bytes[18], bytes[19]]), 183); // EM_AARCH64
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn assembles_aarch64_calls_control_flow_memory_and_privileged_intrinsics() {
        let dir = std::env::temp_dir().join(format!(
            "ocore-aarch64-corpus-driver-test-{}",
            monotonic_nonce()
        ));
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("corpus.oc");
        let object = dir.join("corpus.o");
        fs::write(
            &source,
            r#"
module corpus;
static mut CELL: u64 = 7;

fn add(left: u64, right: u64) -> u64 {
    return left + right;
}

@export @no_mangle
unsafe fn exercise(pointer: *mut u64, left: u64, right: u64) -> u64 {
    let current: u64 = volatile_load(pointer);
    volatile_store(pointer, current + 1);
    let result: u64 = syscall1(9, current);
    if left < right {
        return add(result, left);
    }
    return result - right;
}

@export @no_mangle
unsafe fn idle() -> never {
    disable_interrupts();
    enable_interrupts();
    loop { halt(); }
}
"#,
        )
        .unwrap();
        compile(
            &[source],
            &CompileOptions {
                target: Target::Aarch64UnknownNone,
                emit: EmitKind::Object,
                output: object.clone(),
                keep_assembly: false,
            },
        )
        .unwrap();
        let bytes = fs::read(object).unwrap();
        assert_eq!(&bytes[..4], b"\x7fELF");
        assert_eq!(bytes[4], 2); // ELFCLASS64
        assert_eq!(u16::from_le_bytes([bytes[18], bytes[19]]), 183); // EM_AARCH64
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn aarch64_object_is_byte_reproducible_across_source_directories() {
        let dir =
            std::env::temp_dir().join(format!("ocore-aarch64-repro-test-{}", monotonic_nonce()));
        let first_dir = dir.join("first-root");
        let second_dir = dir.join("second-root");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let source_text = r#"
module reproducible_aarch64;
static ANSWER: u64 = 42;
@export @no_mangle
fn answer() -> u64 {
    return ANSWER;
}
"#;
        let first_source = first_dir.join("input.oc");
        let second_source = second_dir.join("renamed.oc");
        let first_object = first_dir.join("first.o");
        let second_object = second_dir.join("second.o");
        fs::write(&first_source, source_text).unwrap();
        fs::write(&second_source, source_text).unwrap();

        for (source, output) in [
            (first_source, first_object.clone()),
            (second_source, second_object.clone()),
        ] {
            compile(
                &[source],
                &CompileOptions {
                    target: Target::Aarch64UnknownNone,
                    emit: EmitKind::Object,
                    output,
                    keep_assembly: false,
                },
            )
            .unwrap();
        }

        assert_eq!(
            fs::read(first_object).unwrap(),
            fs::read(second_object).unwrap(),
            "identical O-core modules emitted different AArch64 object bytes"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn ocore_object_is_byte_reproducible_across_source_directories() {
        let dir = std::env::temp_dir().join(format!("ocore-repro-test-{}", monotonic_nonce()));
        let first_dir = dir.join("first-root");
        let second_dir = dir.join("second-root");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let source_text = r#"
module reproducible;
static ANSWER: u64 = 42;
@export @no_mangle
fn answer() -> u64 {
    return ANSWER;
}
"#;
        let first_source = first_dir.join("input.oc");
        let second_source = second_dir.join("renamed.oc");
        let first_object = first_dir.join("first.o");
        let second_object = second_dir.join("second.o");
        fs::write(&first_source, source_text).unwrap();
        fs::write(&second_source, source_text).unwrap();

        for (source, output) in [
            (first_source, first_object.clone()),
            (second_source, second_object.clone()),
        ] {
            compile(
                &[source],
                &CompileOptions {
                    target: Target::X86_64UnknownNone,
                    emit: EmitKind::Object,
                    output,
                    keep_assembly: false,
                },
            )
            .unwrap();
        }

        assert_eq!(
            fs::read(first_object).unwrap(),
            fs::read(second_object).unwrap(),
            "identical O-core modules emitted different object bytes"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_float_miscompilation_before_object_emission() {
        let dir =
            std::env::temp_dir().join(format!("ocore-float-regression-test-{}", monotonic_nonce()));
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("float.oc");
        let object = dir.join("float.o");
        fs::write(
            &source,
            r#"
module floats;
fn compare() -> bool {
    let x: f64 = 1 as f64;
    let y: f64 = 2 as f64;
    return x < y;
}
"#,
        )
        .unwrap();

        let error = compile(
            &[source],
            &CompileOptions {
                target: Target::X86_64UnknownNone,
                emit: EmitKind::Object,
                output: object.clone(),
                keep_assembly: false,
            },
        )
        .unwrap_err();

        assert!(error.message.contains("floating-point cast"));
        assert!(!object.exists(), "invalid float program emitted an object");
        let _ = fs::remove_dir_all(dir);
    }
}
