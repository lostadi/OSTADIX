use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::hir::{HirProgram, Type};
use super::{codegen, codegen_aarch64, codegen_riscv64};
use super::{mir, parser, typeck, Diagnostic, Span};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    X86_64UnknownNone,
    Aarch64UnknownNone,
    Riscv64UnknownNone,
}

impl Target {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "x86_64-unknown-none" | "x86_64-unknown-none-elf" => Some(Target::X86_64UnknownNone),
            "aarch64-unknown-none" | "aarch64-unknown-none-elf" => Some(Target::Aarch64UnknownNone),
            "riscv64-unknown-none" | "riscv64-unknown-none-elf" | "riscv64gc-unknown-none-elf" => {
                Some(Target::Riscv64UnknownNone)
            }
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Target::X86_64UnknownNone => "x86_64-unknown-none",
            Target::Aarch64UnknownNone => "aarch64-unknown-none",
            Target::Riscv64UnknownNone => "riscv64-unknown-none",
        }
    }

    pub fn triple(self) -> &'static str {
        match self {
            Target::X86_64UnknownNone => "x86_64-unknown-none-elf",
            Target::Aarch64UnknownNone => "aarch64-unknown-none-elf",
            Target::Riscv64UnknownNone => "riscv64-unknown-none-elf",
        }
    }

    fn architecture(self) -> &'static str {
        match self {
            Target::X86_64UnknownNone => "x86_64",
            Target::Aarch64UnknownNone => "aarch64",
            Target::Riscv64UnknownNone => "riscv64",
        }
    }
}

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
    pub artifact_kind: String,
    pub artifact_sha256: String,
    pub artifact_bytes: usize,
    pub assembly: super::native_map::NativeAssemblyMap,
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
    let (assembly, map) = if map_output.is_some() {
        let (assembly, map) = super::native_codegen::emit_with_map(&module, options.target)?;
        (assembly, Some(map))
    } else {
        (super::native_codegen::emit(&module, options.target)?, None)
    };
    let output = if options.emit == EmitKind::Assembly {
        write_text(&options.output, &assembly)?;
        CompileOutput {
            output: options.output.clone(),
            assembly: Some(options.output.clone()),
        }
    } else {
        emit_object(options, &assembly, module.target.abi.as_deref())?
    };
    if let (Some(path), Some(map)) = (map_output, map) {
        let artifact = fs::read(&output.output)
            .map_err(|error| driver_error(format!("failed to bind native output: {error}")))?;
        let record = NativeArtifactMap {
            format: NATIVE_ARTIFACT_MAP_FORMAT.into(),
            module_file_sha256: hex::encode(Sha256::digest(&bytes)),
            artifact_kind: if options.emit == EmitKind::Assembly {
                "assembly"
            } else {
                "object"
            }
            .into(),
            artifact_sha256: hex::encode(Sha256::digest(&artifact)),
            artifact_bytes: artifact.len(),
            assembly: map,
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
    input: &Path,
    map_input: &Path,
    assembly_input: &Path,
    artifact_input: &Path,
    target: Target,
) -> Result<NativeArtifactMap, Diagnostic> {
    let read = |path: &Path| {
        fs::read(path)
            .map_err(|error| driver_error(format!("failed to read {}: {error}", path.display())))
    };
    let bytes = read(input)?;
    let module = super::native_ir::NativeModule::from_json(&bytes)?;
    let record: NativeArtifactMap = serde_json::from_slice(&read(map_input)?)
        .map_err(|error| driver_error(format!("invalid native artifact map: {error}")))?;
    if record.format != NATIVE_ARTIFACT_MAP_FORMAT
        || record.module_file_sha256 != hex::encode(Sha256::digest(&bytes))
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

    emit_object(options, &assembly, None)
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
    let mut command = Command::new(&clang);
    command.args([
        "-target",
        options.target.triple(),
        "-ffreestanding",
        "-fno-stack-protector",
        "-c",
        "-x",
        "assembler",
    ]);
    if let Some(abi) = abi {
        // Preserve the imported scalar module's ABI marker. LP64D integer
        // arguments use the same integer convention; FP values remain rejected
        // by native_codegen rather than silently converted to an integer ABI.
        command.arg("-march=rv64gc").arg(format!("-mabi={abi}"));
    }
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
