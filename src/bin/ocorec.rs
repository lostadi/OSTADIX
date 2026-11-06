use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use o_lang::ocore::{compile_with_object_sections, CompileOptions, EmitKind, Target};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum InputKind {
    Ocore,
    NativeIr,
    LlvmIr,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Emit {
    Ast,
    Hir,
    Mir,
    Asm,
    Obj,
}

#[derive(Debug, Parser)]
#[command(
    name = "ocorec",
    version,
    about = "Compile statically typed O-core to freestanding native objects"
)]
struct Cli {
    /// .oc sources, or one complete imported native module.
    #[arg(required_unless_present_any = ["verify_native_map", "list_targets"])]
    inputs: Vec<PathBuf>,

    /// Print the canonical target catalog as JSON without compiling or executing.
    /// Catalog membership alone does not qualify target health or semantics.
    #[arg(long, conflicts_with_all = ["inputs", "input_kind", "llvm_library", "llvm_sha256", "tls_profile", "atomic_profile", "wide_volatile_profile", "linux_syscall_profile", "verify_native", "receipt", "emit", "target", "output", "keep_asm", "native_map", "verify_native_map", "map_assembly", "map_artifact", "function_sections", "data_sections", "llvm_metadata_diagnostics", "check"])]
    list_targets: bool,

    /// Input representation. Imported IR is verified before all output.
    #[arg(long, value_enum, default_value_t = InputKind::Ocore)]
    input_kind: InputKind,

    /// Matching, digest-pinned LLVM parser shared library for LLVM import.
    #[arg(long)]
    llvm_library: Option<PathBuf>,

    /// SHA-256 pin for an explicitly selected LLVM parser library.
    #[arg(long, requires = "llvm_library")]
    llvm_sha256: Option<String>,

    /// Retain exact raw LLVM metadata printer diagnostics in a separate JSON
    /// sidecar. These process-specific bytes never enter canonical module
    /// equality and do not constitute native or runtime admission.
    #[arg(long, conflicts_with_all = ["verify_native", "check", "verify_native_map"])]
    llvm_metadata_diagnostics: Option<PathBuf>,

    /// Explicit native TLS realization for a complete static Linux ELF image.
    /// Requested LLVM models remain in IR; genuine TLS storage/providers and
    /// a nonpreemptive static final link are required separately.
    #[arg(long, value_parser = ["linux-elf-static-nonpreemptive-v1"], conflicts_with_all = ["verify_native", "check"])]
    tls_profile: Option<String>,

    /// Explicit ordinary coherent RAM contract for native atomic lowering.
    /// Device memory is excluded; RV64 masked subword operations require their
    /// entire containing word to be accessible coherent RAM and the execution
    /// environment to provide LR/SC eventuality for that region.
    #[arg(long, value_parser = ["coherent-ram-v1"], conflicts_with_all = ["verify_native", "check"])]
    atomic_profile: Option<String>,

    /// Explicit wide volatile ordinary-RAM access contract. Target-sized
    /// ordered parts are permitted; MMIO and atomicity are excluded.
    #[arg(long, value_parser = ["ordinary-ram-split-v1"], conflicts_with_all = ["verify_native", "check"])]
    wide_volatile_profile: Option<String>,

    /// Ordered raw Linux userspace syscalls with a required external Linux provider.
    #[arg(long, value_parser = ["linux-user-raw-v1"], conflicts_with_all = ["verify_native", "check"])]
    linux_syscall_profile: Option<String>,

    /// Verify a complete native module without generating machine code.
    #[arg(long, conflicts_with = "check")]
    verify_native: bool,

    /// Write a SHA-256-bound native verification receipt after successful verification.
    #[arg(long, requires = "verify_native")]
    receipt: Option<PathBuf>,

    /// Output kind.
    #[arg(long, value_enum, default_value_t = Emit::Obj)]
    emit: Emit,

    /// Compilation target.
    #[arg(long, default_value = "x86_64-unknown-none")]
    target: String,

    /// Output path, or `-` for textual output on stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Retain generated assembly next to an object output.
    #[arg(long)]
    keep_asm: bool,

    /// Write an artifact-bound imported-IR instruction-to-assembly map.
    /// Offsets describe assembly UTF-8 bytes, not machine PCs or HGraph nodes.
    #[arg(long, conflicts_with_all = ["check", "verify_native", "verify_native_map"])]
    native_map: Option<PathBuf>,

    /// Verify a native map against its module, exact assembly and artifact.
    #[arg(long, requires_all = ["map_assembly", "map_artifact"], conflicts_with_all = ["check", "verify_native", "native_map", "output", "emit", "keep_asm", "function_sections", "data_sections"])]
    verify_native_map: Option<PathBuf>,

    /// Exact generated assembly associated with --verify-native-map.
    #[arg(long, requires = "verify_native_map")]
    map_assembly: Option<PathBuf>,

    /// Output object or assembly associated with --verify-native-map.
    #[arg(long, requires = "verify_native_map")]
    map_artifact: Option<PathBuf>,

    /// Place ordinary functions in separate ELF sections for linker GC.
    #[arg(long)]
    function_sections: bool,

    /// Place ordinary O-core statics in separate ELF sections for linker GC.
    /// Explicit source link sections are preserved exactly.
    #[arg(long, conflicts_with = "verify_native")]
    data_sections: bool,

    /// Parse each input module without typechecking, executing, or writing artifacts.
    #[arg(long, conflicts_with_all = ["emit", "target", "output", "keep_asm", "function_sections", "data_sections"])]
    check: bool,
}

/// Descriptive inventory; acceptance binds the selected binary/source/build
/// identities and separately checks target profiles, runners and semantic oracles.
fn target_catalog() -> serde_json::Value {
    let targets: Vec<_> = Target::ALL
        .iter()
        .map(|target| {
            serde_json::json!({
                "id": target.id(),
                "architecture": target.architecture(),
                "target": target.name(),
                "assembler_triple": target.triple(),
                "aliases": target.aliases(),
            })
        })
        .collect();
    serde_json::json!({
        "schema": "ocore-target-catalog-v1",
        "scope": "canonical-target-declarations-only",
        "targets": targets,
    })
}

fn main() {
    let cli = Cli::parse();
    if cli.list_targets {
        println!(
            "{}",
            serde_json::to_string_pretty(&target_catalog())
                .expect("target catalog is serializable")
        );
        return;
    }
    if cli.llvm_metadata_diagnostics.is_some()
        && (cli.input_kind != InputKind::LlvmIr
            || !matches!(cli.emit, Emit::Mir | Emit::Asm | Emit::Obj))
    {
        eprintln!(
            "ocorec: --llvm-metadata-diagnostics requires LLVM import with --emit mir, asm or obj"
        );
        std::process::exit(2);
    }
    if cli.input_kind != InputKind::Ocore && (cli.function_sections || cli.data_sections) {
        eprintln!("ocorec: imported native function/data sections are not implemented");
        std::process::exit(2);
    }
    if cli.data_sections && !matches!(cli.emit, Emit::Asm | Emit::Obj) {
        eprintln!("ocorec: --data-sections requires --emit asm or obj");
        std::process::exit(2);
    }
    if cli.native_map.is_some() && cli.input_kind == InputKind::Ocore {
        eprintln!("ocorec: native maps currently require --input-kind native-ir or llvm-ir");
        std::process::exit(2);
    }
    if cli.native_map.is_some() && !matches!(cli.emit, Emit::Asm | Emit::Obj) {
        eprintln!("ocorec: --native-map requires --emit asm or obj");
        std::process::exit(2);
    }
    if cli.verify_native_map.is_some()
        && (cli.input_kind == InputKind::LlvmIr
            || (!cli.inputs.is_empty() && cli.input_kind != InputKind::NativeIr))
    {
        eprintln!("ocorec: --verify-native-map requires the exact --input-kind native-ir module");
        std::process::exit(2);
    }
    if cli.tls_profile.is_some() && cli.input_kind != InputKind::LlvmIr {
        eprintln!("ocorec: --tls-profile selects LLVM import; native IR preserves its own explicit profile");
        std::process::exit(2);
    }
    if cli.atomic_profile.is_some() && cli.input_kind != InputKind::LlvmIr {
        eprintln!("ocorec: --atomic-profile selects LLVM import; native IR preserves its own explicit profile");
        std::process::exit(2);
    }
    if cli.wide_volatile_profile.is_some() && cli.input_kind != InputKind::LlvmIr {
        eprintln!("ocorec: --wide-volatile-profile selects LLVM import; native IR preserves its own explicit profile");
        std::process::exit(2);
    }
    if cli.linux_syscall_profile.is_some() && cli.input_kind != InputKind::LlvmIr {
        eprintln!("ocorec: --linux-syscall-profile selects LLVM import; native IR preserves its own explicit profile");
        std::process::exit(2);
    }
    if cli.verify_native {
        if let Err(error) = verify_native(&cli.inputs, cli.receipt.as_deref()) {
            eprintln!(
                "{}",
                o_lang::cli_diagnostics::render_error("ocorec", &error)
            );
            std::process::exit(1);
        }
        return;
    }
    if cli.check {
        for input in &cli.inputs {
            let file = input.display().to_string();
            let source = match std::fs::read_to_string(input) {
                Ok(source) => source,
                Err(error) => {
                    let error = anyhow::Error::new(error).context(format!("failed to read {file}"));
                    eprintln!(
                        "{}",
                        o_lang::cli_diagnostics::render_error("ocorec", &error)
                    );
                    std::process::exit(1);
                }
            };
            if let Err(error) = o_lang::ocore::parser::parse(&file, &source) {
                eprintln!("{}", render_diagnostic(&error, Some(&source), "parse only"));
                std::process::exit(1);
            }
        }
        println!("ok");
        return;
    }
    let Some(target) = Target::parse(&cli.target) else {
        eprintln!(
            "ocorec: unsupported target `{}`; expected x86_64-unknown-none, aarch64-unknown-none or riscv64-unknown-none",
            cli.target
        );
        std::process::exit(2);
    };
    if let Some(map) = &cli.verify_native_map {
        let result = if cli.inputs.len() <= 1 {
            o_lang::ocore::driver::verify_native_artifact_map(
                cli.inputs.first().map(|input| input.as_path()),
                map,
                cli.map_assembly.as_deref().unwrap(),
                cli.map_artifact.as_deref().unwrap(),
                target,
            )
        } else {
            Err(o_lang::ocore::Diagnostic {
                file: "<ocorec>".into(),
                span: o_lang::ocore::Span::default(),
                message: "native map verification accepts at most one external module".into(),
            })
        };
        match result {
            Ok(_) => println!("ok: native assembly correspondence and artifact bindings"),
            Err(error) => {
                eprintln!(
                    "{}",
                    render_diagnostic(&error, None, "native map verification")
                );
                std::process::exit(1);
            }
        }
        return;
    }
    let emit = match cli.emit {
        Emit::Ast => EmitKind::Ast,
        Emit::Hir => EmitKind::Hir,
        Emit::Mir => EmitKind::Mir,
        Emit::Asm => EmitKind::Assembly,
        Emit::Obj => EmitKind::Object,
    };
    let output = cli
        .output
        .clone()
        .unwrap_or_else(|| default_output(&cli.inputs[0], emit));
    let options = CompileOptions {
        target,
        emit,
        output,
        keep_assembly: cli.keep_asm,
    };
    if let Some(diagnostics) = &cli.llvm_metadata_diagnostics {
        let mut reserved = cli.inputs.clone();
        if let Some(library) = &cli.llvm_library {
            reserved.push(library.clone());
        }
        if let Ok(executable) = std::env::current_exe() {
            reserved.push(executable);
        }
        reserved.push(options.output.clone());
        if options.keep_assembly {
            reserved.push(options.output.with_extension("s"));
        }
        if let Some(map) = &cli.native_map {
            reserved.push(map.clone());
        }
        let valid = resolved_import_output(diagnostics).and_then(|destination| {
            for path in reserved {
                if destination == resolved_import_output(&path)? {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                        "metadata diagnostics must not replace source, selected tools, module, assembly or map output"));
                }
            }
            Ok(())
        });
        if let Err(error) = valid {
            eprintln!("ocorec: invalid metadata diagnostic destination: {error}");
            std::process::exit(2);
        }
    }
    if let Some(map) = &cli.native_map {
        if let Err(error) =
            o_lang::ocore::driver::prepare_native_map_output(&cli.inputs, &options, map)
        {
            eprintln!(
                "{}",
                render_diagnostic(&error, None, "native map output validation")
            );
            std::process::exit(1);
        }
    }
    let imported;
    let native_input = if cli.input_kind == InputKind::LlvmIr {
        imported = match import_llvm(&cli) {
            Ok(input) => input,
            Err(error) => {
                eprintln!(
                    "{}",
                    o_lang::cli_diagnostics::render_error("ocorec", &error)
                );
                std::process::exit(1);
            }
        };
        Some(imported.0.as_path())
    } else if cli.input_kind == InputKind::NativeIr {
        Some(cli.inputs[0].as_path())
    } else {
        None
    };
    let compiled = if let Some(native_input) = native_input {
        if cli.inputs.len() != 1 {
            eprintln!("ocorec: native IR input requires exactly one complete module");
            std::process::exit(2);
        }
        o_lang::ocore::driver::compile_native_module_with_map(
            native_input,
            &options,
            cli.native_map.as_deref(),
        )
    } else {
        compile_with_object_sections(
            &cli.inputs,
            &options,
            cli.function_sections,
            cli.data_sections,
        )
    };
    match compiled {
        Ok(result) => {
            if result.output.as_path() != std::path::Path::new("-") {
                eprintln!("ocorec: wrote {}", result.output.display());
            }
            if let Some(assembly) = result.assembly.filter(|p| p != &result.output) {
                eprintln!("ocorec: kept {}", assembly.display());
            }
            if let Some(map) = &cli.native_map {
                eprintln!("ocorec: wrote native assembly map {}", map.display());
            }
        }
        Err(error) => {
            let source = if error.file.starts_with('<') {
                None
            } else {
                std::fs::read_to_string(&error.file).ok()
            };
            eprintln!(
                "{}",
                render_diagnostic(&error, source.as_deref(), "native compilation")
            );
            std::process::exit(1);
        }
    }
}

// Resolve existing prefixes, including symlinks, without creating artifacts.
// Ambiguous nonexistent '..' paths are rejected rather than guessed.
fn resolved_import_output(path: &std::path::Path) -> std::io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut ancestor = absolute.as_path();
    let mut tail = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut resolved) => {
                for name in tail.iter().rev() {
                    resolved.push(name);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor.file_name().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cannot resolve diagnostic output path",
                    )
                })?;
                tail.push(name.to_os_string());
                ancestor = ancestor.parent().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "diagnostic output has no parent",
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}

struct ImportedFile(PathBuf);
impl Drop for ImportedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn import_llvm(cli: &Cli) -> anyhow::Result<ImportedFile> {
    use anyhow::{bail, Context};
    use std::io::Write;
    if cli.inputs.len() != 1 {
        bail!("LLVM import requires exactly one whole module");
    }
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).context("generate importer temporary identity")?;
    let temporary = ImportedFile(
        std::env::temp_dir().join(format!("ocore-import-{}.json", hex::encode(nonce))),
    );
    // Compile each embedded worker separately so their future imports remain
    // legal; share globals without relying on files next to an installed CLI.
    let script = format!(
        "exec({}); exec({})",
        serde_json::to_string(include_str!("../../scripts/ocore_llvm_bitcode.py"))?,
        serde_json::to_string(include_str!("../../scripts/ocore_llvm_import.py"))?
    );
    let mut command = std::process::Command::new("python3");
    command
        // The combined embedded workers can exceed the OS limit for ONE argv
        // string. Stream their exact source independently of the input path.
        .args(["-I", "-"])
        .arg(&cli.inputs[0])
        .arg("--output")
        .arg(&temporary.0);
    if let Some(library) = &cli.llvm_library {
        command.arg("--llvm-library").arg(library);
    }
    if let Some(digest) = &cli.llvm_sha256 {
        command.arg("--llvm-sha256").arg(digest);
    }
    if let Some(diagnostics) = &cli.llvm_metadata_diagnostics {
        command.arg("--metadata-diagnostics").arg(diagnostics);
    }
    if let Some(profile) = &cli.tls_profile {
        command.arg("--tls-profile").arg(profile);
    }
    if let Some(profile) = &cli.atomic_profile {
        command.arg("--atomic-profile").arg(profile);
    }
    if let Some(profile) = &cli.wide_volatile_profile {
        command.arg("--wide-volatile-profile").arg(profile);
    }
    if let Some(profile) = &cli.linux_syscall_profile {
        command.arg("--linux-syscall-profile").arg(profile);
    }
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("launch version-pinned LLVM import worker")?;
    let write = child
        .stdin
        .take()
        .context("LLVM import worker stdin missing")?
        .write_all(script.as_bytes());
    if let Err(error) = write {
        let _ = child.kill();
        let diagnostic = child
            .wait_with_output()
            .map(|output| {
                format!(
                    "{}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                )
            })
            .unwrap_or_else(|error| format!("cannot read child result: {error}"));
        return Err(error).context(format!("stream embedded LLVM import worker; {diagnostic}"));
    }
    let result = child
        .wait_with_output()
        .context("read LLVM import worker result")?;
    if !result.status.success() {
        bail!(
            "LLVM import failed: child {}; {}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        );
    }
    if cli.native_map.is_some() {
        // Use the same reloadable bytes that `--emit mir` publishes. The
        // worker's JSON spelling otherwise exists only in a private temporary.
        let module = o_lang::ocore::native_ir::NativeModule::from_json(
            &std::fs::read(&temporary.0).context("read imported native map input")?,
        )?;
        std::fs::write(&temporary.0, module.to_json()?)
            .context("normalize imported native map input")?;
    }
    Ok(temporary)
}

fn verify_native(inputs: &[PathBuf], receipt: Option<&std::path::Path>) -> anyhow::Result<()> {
    use anyhow::{bail, Context};
    // A failed recheck must not leave evidence of an earlier successful input.
    if let Some(path) = receipt {
        if let Ok(resolved) = path.canonicalize() {
            if inputs
                .iter()
                .any(|input| input.canonicalize().is_ok_and(|p| p == resolved))
            {
                bail!("verification receipt must not overwrite the input module");
            }
        }
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("remove stale native verification receipt"),
        }
    }
    if inputs.len() != 1 {
        bail!("native verification requires exactly one complete module");
    }
    let bytes = std::fs::read(&inputs[0]).context("read native module")?;
    let module = o_lang::ocore::native_ir::NativeModule::from_json(&bytes)?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    if let Some(path) = receipt {
        let functions: Vec<_> = module.functions.iter().map(|f| serde_json::json!({
            "name": f.name, "definition": f.entry.is_some(), "managed_method": f.managed_method,
            "intrinsic": f.intrinsic
        })).collect();
        let mut record = serde_json::json!({
            "format": "ocore-native-verification-v1",
            "module_sha256": sha256,
            "verifier": "ocore-native-v1",
            "verified": true,
            "scope": "structural_ir_verification",
            "functions": functions,
            "global_count": module.globals.len(),
            "target": module.target,
        });
        if let Some(requirement) = o_lang::ocore::native_platform::requirement(&module)? {
            record["required_platform_interfaces"] = serde_json::json!([requirement]);
            record["platform_resource_closure_complete"] = serde_json::json!(false);
        }
        std::fs::write(path, serde_json::to_vec_pretty(&record)?)
            .context("write native verification receipt")?;
    }
    println!("ok {sha256}");
    Ok(())
}

fn render_diagnostic(
    diagnostic: &o_lang::ocore::Diagnostic,
    source: Option<&str>,
    phase: &str,
) -> String {
    let span = diagnostic.span;
    let location = (span.line > 0).then_some(o_lang::parser::SourceSpanV1 {
        start_byte: span.start,
        end_byte: span.end,
        start_line: span.line,
        start_column: span.column,
        end_line: span.line,
        end_column: span.column,
    });
    o_lang::cli_diagnostics::render_native_error(
        "ocorec",
        &diagnostic.message,
        &diagnostic.file,
        source,
        location,
        phase,
    )
}

fn default_output(input: &std::path::Path, emit: EmitKind) -> PathBuf {
    let mut output = PathBuf::from(input.file_stem().and_then(|s| s.to_str()).unwrap_or("a"));
    output.set_extension(match emit {
        EmitKind::Ast => "ast",
        EmitKind::Hir => "hir",
        EmitKind::Mir => "mir",
        EmitKind::Assembly => "s",
        EmitKind::Object => "o",
    });
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_catalog_needs_no_fake_source_and_preserves_input_requirements() {
        let cli = Cli::try_parse_from(["ocorec", "--list-targets"]).unwrap();
        assert!(cli.list_targets);
        assert!(cli.inputs.is_empty());
        assert!(Cli::try_parse_from(["ocorec"]).is_err());
        let ordinary = Cli::try_parse_from(["ocorec", "input.oc"]).unwrap();
        assert!(!ordinary.list_targets);
        assert_eq!(ordinary.inputs, vec![PathBuf::from("input.oc")]);
        for args in [
            vec!["ocorec", "--list-targets", "input.oc"],
            vec![
                "ocorec",
                "--list-targets",
                "--target",
                "x86_64-unknown-none",
            ],
            vec!["ocorec", "--list-targets", "--emit", "mir"],
            vec!["ocorec", "--list-targets", "--check"],
            vec!["ocorec", "--list-targets", "--verify-native"],
            vec!["ocorec", "--list-targets", "--input-kind", "llvm-ir"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn machine_readable_catalog_is_derived_from_every_canonical_target() {
        let catalog = target_catalog();
        assert_eq!(catalog["schema"], "ocore-target-catalog-v1");
        assert_eq!(catalog["scope"], "canonical-target-declarations-only");
        let rows = catalog["targets"].as_array().unwrap();
        assert_eq!(rows.len(), Target::ALL.len());
        for (&target, row) in Target::ALL.iter().zip(rows) {
            assert_eq!(row["id"], target.id());
            assert_eq!(row["architecture"], target.architecture());
            assert_eq!(row["target"], target.name());
            assert_eq!(row["assembler_triple"], target.triple());
            assert_eq!(row["aliases"], serde_json::json!(target.aliases()));
        }
    }

    #[test]
    fn embedded_llvm_worker_streams_source_and_literal_paths_before_library_admission() {
        let directory = tempfile::tempdir().unwrap();
        // Win32 rejects control characters in filenames; Unix also exercises
        // a literal newline, which must remain part of one argument.
        let separator = if cfg!(windows) { " " } else { "\n" };
        let input = directory.path().join(format!(
            "literal 'quotes' $dollar `ticks` λ{separator}module.ll"
        ));
        let library = directory.path().join(format!(
            "parser 'quotes' $dollar `ticks` λ{separator}library.fake"
        ));
        std::fs::write(
            &input,
            b"define i64 @identity(i64 %value) { ret i64 %value }\n",
        )
        .unwrap();
        let parser_bytes = b"deliberately not an ELF shared library";
        std::fs::write(&library, parser_bytes).unwrap();
        let cli = Cli::try_parse_from([
            std::ffi::OsString::from("ocorec"),
            input.as_os_str().into(),
            "--input-kind".into(),
            "llvm-ir".into(),
            "--llvm-library".into(),
            library.as_os_str().into(),
            "--llvm-sha256".into(),
            hex::encode(Sha256::digest(parser_bytes)).into(),
        ])
        .unwrap();
        let error = match import_llvm(&cli) {
            Ok(_) => panic!("a non-ELF parser must not be admitted"),
            Err(error) => error.to_string(),
        };
        // The real embedded worker reads the input, opens the selected parser,
        // and verifies its digest before checking ELF magic. Reaching this
        // diagnostic exercises streaming and literal argv on every host.
        assert!(error.contains("LLVM import failed: child"), "{error}");
        assert!(error.contains("\"stage\": \"toolchain\""), "{error}");
        assert!(
            error.contains("LLVM library is not an ELF shared library"),
            "{error}"
        );
    }

    // Successful parsing requires the pinned ELF LLVM library; the companion
    // test above retains real embedded-worker transport coverage on other hosts.
    #[cfg(target_os = "linux")]
    #[test]
    fn embedded_whole_llvm_import_streams_large_workers_and_literal_path_arguments() {
        let directory = std::env::temp_dir().join(format!(
            "ostadix-streamed-llvm-worker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let input = directory.join("literal 'quotes' $dollar `ticks` λ\nmodule.ll");
        let source = b"target triple = \"x86_64-unknown-linux-gnu\"\ntarget datalayout = \"e-p:64:64-i64:64\"\ndefine i64 @original_whole_unit(i64 %value) { ret i64 %value }\n";
        std::fs::write(&input, source).unwrap();
        let cli = Cli::try_parse_from([
            std::ffi::OsString::from("ocorec"),
            input.as_os_str().into(),
            "--input-kind".into(),
            "llvm-ir".into(),
        ])
        .unwrap();
        let imported = import_llvm(&cli).unwrap();
        let module =
            o_lang::ocore::native_ir::NativeModule::from_json(&std::fs::read(&imported.0).unwrap())
                .unwrap();
        assert_eq!(
            module.provenance.input_sha256,
            hex::encode(Sha256::digest(source))
        );
        assert_eq!(module.provenance.source_function_count, 1);
        assert_eq!(module.functions.len(), 1);
        assert_eq!(module.functions[0].name, "original_whole_unit");
        assert!(module.functions[0].entry.is_some());
        assert_eq!(module.functions[0].params.len(), 1);
        let imported_path = imported.0.clone();
        drop(imported);
        assert!(!imported_path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
