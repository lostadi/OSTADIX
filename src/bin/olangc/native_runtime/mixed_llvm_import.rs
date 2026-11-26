//! Complete-occurrence structural LLVM import from a held mixed input stage.
//! No source admission, ABI/provider closure, link order or runtime exposure.
//! Parsed modules live only in this owned operation; no global or path cache.
use super::{MixedCaptureStage, MixedUnitRepresentation, VerifiedLineageModule};
use super::super::{
    architecture, captured_ir_format, checked_ir_bytes, control_inventory, digest,
    floating_requirements, provider_group, retained_metadata_diagnostics,
    validate_metadata_diagnostics, NativeImportOptions, RAW_METADATA_OPTION,
};
use anyhow::{bail, Context, Result};
use o_lang::ocore::native_ir::{
    AtomicProfile, NativeModule, TlsProfile, WideVolatileProfile,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, OnceLock};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

#[derive(Clone, Debug)]
struct ObservedFile {
    path: PathBuf,
    sha256: String,
    bytes: u64,
    header: Vec<u8>,
}
impl ObservedFile {
    // Streaming observations bound retained hash memory, not spool storage.
    fn read(path: &Path) -> Result<Self> {
        if !path.is_absolute() || !path.canonicalize()?.is_file() {
            bail!("mixed import requires an absolute regular file: {}", path.display());
        }
        let mut file = File::open(path)?;
        if !file.metadata()?.is_file() { bail!("mixed import input is not regular"); }
        let mut hash = Sha256::new();
        let mut bytes = 0u64;
        let mut header = Vec::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 { break; }
            if header.len() < 64 {
                let take = count.min(64 - header.len());
                header.extend_from_slice(&buffer[..take]);
            }
            bytes = bytes.checked_add(count as u64).context("observed byte count overflow")?;
            hash.update(&buffer[..count]);
        }
        Ok(Self { path:path.to_owned(), sha256:hex::encode(hash.finalize()), bytes, header })
    }
    fn check(&self) -> Result<()> {
        let now = Self::read(&self.path)?;
        if now.sha256 != self.sha256 || now.bytes != self.bytes {
            bail!("mixed import observed file changed: {}", self.path.display());
        }
        Ok(())
    }
    fn value(&self) -> Value {
        json!({"path":self.path,"sha256":self.sha256,"bytes":self.bytes})
    }
}
#[derive(Clone, Copy)]
struct NativeHost { machine: u16 }
impl NativeHost {
    fn observe() -> Result<(Self, Value)> {
        if !cfg!(target_os = "linux") {
            bail!("mixed compiler tool execution requires the actual Linux host profile");
        }
        let machine = match std::env::consts::ARCH {
            "x86_64" => 62,
            "aarch64" => 183,
            "riscv64" => 243,
            other => bail!("mixed compiler native host ISA is unsupported: {other}"),
        };
        let ostype = fs::read("/proc/sys/kernel/ostype")
            .context("observe actual Linux kernel type")?;
        if ostype.as_slice() != b"Linux\n" && ostype.as_slice() != b"Linux" {
            bail!("mixed compiler actual kernel observation is not Linux");
        }
        let mut current = File::open("/proc/self/exe")
            .context("observe running compiler host ELF")?;
        let mut header = [0u8;64];
        current.read_exact(&mut header)?;
        let host = Self { machine };
        let envelope = host.elf(&header, false)?;
        Ok((host, json!({"os":"linux","compiled_arch":std::env::consts::ARCH,
            "running_process_elf":envelope,
            "scope":"Linux host and running-process ELF envelope; no physical hardware or transitive loader qualification"})))
    }
    fn elf(&self, h: &[u8], library: bool) -> Result<Value> {
        if h.len() < 64 || &h[..4] != b"\x7fELF" || h[4] != 2 || h[5] != 1
            || h[6] != 1 || u32::from_le_bytes([h[20],h[21],h[22],h[23]]) != 1
            || u16::from_le_bytes([h[18],h[19]]) != self.machine
            || u16::from_le_bytes([h[52],h[53]]) < 64
        {
            bail!("mixed selected native tool/library ELF class/endian/machine differs from host");
        }
        let kind = u16::from_le_bytes([h[16],h[17]]);
        if (library && kind != 3) || (!library && kind != 2 && kind != 3) {
            bail!("mixed selected native tool/library ELF type is unsupported");
        }
        Ok(json!({"class":2,"data":1,"e_machine":self.machine,"e_type":kind,
            "osabi_byte":h[7],"linux_proof_from_osabi":false}))
    }
    fn pin(&self, pin: &provider_group::Pin, library: bool) -> Result<(ObservedFile, Value)> {
        let actual = ObservedFile::read(&pin.path)?;
        if actual.sha256 != pin.sha256 {
            bail!("mixed selected native tool/library bytes differ: {}", pin.path.display());
        }
        let elf = self.elf(&actual.header, library)?;
        Ok((actual, elf))
    }
}
fn write_new(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(raw)?;
    file.sync_all()?;
    if fs::read(path)? != raw { bail!("mixed import new output readback differs"); }
    Ok(())
}
fn retain(path: &Path, raw: &[u8], guards: &mut Vec<ObservedFile>) -> Result<Value> {
    write_new(path, raw)?;
    let observed = ObservedFile::read(path)?;
    if observed.sha256 != digest(raw) || observed.bytes != raw.len() as u64 {
        bail!("mixed import retained buffer differs");
    }
    let result = observed.value();
    guards.push(observed);
    Ok(result)
}
fn process_start(pid: u32) -> Result<u64> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let open = raw.find('(').context("process stat command delimiter absent")?;
    let close = raw.rfind(')').context("process stat closing delimiter absent")?;
    if raw[..open].trim().parse::<u32>()? != pid || close <= open {
        bail!("process stat PID binding differs");
    }
    raw[close+1..].split_whitespace().nth(19)
        .context("process start ticks absent")?.parse::<u64>().context("process start ticks invalid")
}
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum PhaseState { Unattempted, KnownFailed, Passed, Unknown }
#[derive(Clone, serde::Serialize)]
struct PhaseOutcome {
    // attempted means this Rust phase was entered. Native dispatch/terminal
    // facts live separately in the referenced command, never in a default code.
    attempted: bool,
    state: PhaseState,
    command_index: Option<usize>,
    evidence_field: Option<&'static str>,
    detail: Option<String>,
}
impl PhaseOutcome {
    fn unattempted(reason: &str) -> Self {
        Self { attempted:false,state:PhaseState::Unattempted,command_index:None,
            evidence_field:None,detail:Some(reason.to_owned()) }
    }
    fn begin(&mut self) {
        self.attempted=true; self.state=PhaseState::KnownFailed;
        self.detail=Some("phase entered without known completion".into());
    }
    fn pass(&mut self, field: &'static str) {
        self.state=PhaseState::Passed; self.evidence_field=Some(field); self.detail=None;
    }
    fn fail(&mut self, error: &str, unknown: bool) {
        self.attempted=true;
        self.state=if unknown {PhaseState::Unknown} else {PhaseState::KnownFailed};
        self.detail=Some(error.to_owned());
    }
    fn block(&mut self, reason: &str) {
        if matches!(self.state,PhaseState::Unattempted) { self.detail=Some(reason.to_owned()); }
    }
    fn passed(&self) -> bool { matches!(self.state,PhaseState::Passed) }
}
#[derive(Clone, serde::Serialize)]
struct UnitPhases {
    import: PhaseOutcome,
    structural_verification: PhaseOutcome,
    control_inventory: PhaseOutcome,
    floating_diagnostics: PhaseOutcome,
    source_native_inventory: PhaseOutcome,
}
#[derive(Clone, Copy)]
enum PhaseKind { Import, Structural, Control, Floating, SourceInventory }
impl PhaseKind {
    fn name(self) -> &'static str { match self {
        Self::Import=>"import",Self::Structural=>"structural_verification",
        Self::Control=>"control_inventory",Self::Floating=>"floating_diagnostics",
        Self::SourceInventory=>"source_native_inventory",
    }}
}
impl UnitPhases {
    fn unattempted(reason: &str) -> Self {
        Self {import:PhaseOutcome::unattempted(reason),
            structural_verification:PhaseOutcome::unattempted(reason),
            control_inventory:PhaseOutcome::unattempted(reason),
            floating_diagnostics:PhaseOutcome::unattempted(reason),
            source_native_inventory:PhaseOutcome::unattempted(reason)}
    }
    fn get_mut(&mut self, phase: PhaseKind) -> &mut PhaseOutcome { match phase {
        PhaseKind::Import=>&mut self.import,PhaseKind::Structural=>&mut self.structural_verification,
        PhaseKind::Control=>&mut self.control_inventory,PhaseKind::Floating=>&mut self.floating_diagnostics,
        PhaseKind::SourceInventory=>&mut self.source_native_inventory,
    }}
    fn block_unattempted(&mut self, reason: &str) {
        self.import.block(reason); self.structural_verification.block(reason);
        self.control_inventory.block(reason); self.floating_diagnostics.block(reason);
        self.source_native_inventory.block(reason);
    }
    fn all_passed(&self) -> bool {
        self.import.passed() && self.structural_verification.passed()
            && self.control_inventory.passed() && self.floating_diagnostics.passed()
            && self.source_native_inventory.passed()
    }
}
#[derive(Clone, serde::Serialize)]
struct KnownTerminal {
    exit_code: Option<i32>,
    signal: Option<i32>,
    success: bool,
}
impl KnownTerminal {
    fn observed(status: &std::process::ExitStatus) -> Self {
        #[cfg(unix)] let signal=status.signal();
        #[cfg(not(unix))] let signal=None;
        Self {exit_code:status.code(),signal,success:status.success()}
    }
}
// Only a real wait/try_wait Some branch supplies this private token.
struct KnownReaped<'a>(&'a std::process::ExitStatus);
struct TerminalFiles {
    program: ObservedFile,
    program_elf: Value,
    stdout: ObservedFile,
    stderr: ObservedFile,
}
fn known_terminal_files(
    host: NativeHost, program: &provider_group::Pin, stdout: &Path, stderr: &Path,
    known: &KnownReaped<'_>,
) -> Result<TerminalFiles> {
    // Keep the actual status reference in the contract; a JSON bool is no token.
    let _status = known.0;
    let (program,program_elf)=host.pin(program,false)?;
    Ok(TerminalFiles {program,program_elf,
        stdout:ObservedFile::read(stdout)?,stderr:ObservedFile::read(stderr)?})
}
struct PendingAttempt {
    command_index: usize,
    child: Child,
    program: provider_group::Pin,
    stdout: PathBuf,
    stderr: PathBuf,
    directory: PathBuf,
    label: String,
    pid: u32,
    start_ticks: Option<u64>,
    terminal: Option<KnownTerminal>,
    observation_count: usize,
    observed_guards: Vec<ObservedFile>,
}

struct Executor {
    host: Option<NativeHost>,
    commands: Vec<Value>,
    guards: Vec<ObservedFile>,
    pending: Vec<PendingAttempt>,
    terminal_observations: Vec<Value>,
    unknown_without_handle: Vec<usize>,
    halted: bool,
    unknown: bool,
    custody_issues: Vec<String>,
}
impl Executor {
    fn new() -> Self {
        Self { host:None, commands:Vec::new(), guards:Vec::new(), pending:Vec::new(),
            terminal_observations:Vec::new(), unknown_without_handle:Vec::new(),
            halted:false, unknown:false, custody_issues:Vec::new() }
    }
    fn precondition_failure(&mut self, index: usize, error: &anyhow::Error) {
        self.halted = true;
        self.commands[index]["state"] = json!("not_dispatched_precondition_failure");
        self.commands[index]["failure"] = json!(format!("{error:#}"));
    }
    // Every attempted command retains separate full file-backed streams.
    // No deadline, signals, retry, shell, environment changes or binfmt route.
    fn run(&mut self, program: &provider_group::Pin, argv: &[String],
           directory: &Path, label: &str) -> Result<bool> {
        if self.halted { bail!("mixed import dispatch halted"); }
        let index = self.commands.len();
        let stdout = directory.join(format!("{label}.stdout.log"));
        let stderr = directory.join(format!("{label}.stderr.log"));
        self.commands.push(json!({"index":index,"program":program.path,
            "program_sha256":program.sha256,"argv":argv,"stdin":"null",
            "cwd":"inherited","environment":"inherited-not-captured",
            "stdout_path":stdout,"stderr_path":stderr,"state":"preparing",
            "deadline":null,"signals_sent":[],"full_session_quiescence_qualified":false}));
        let prepared = (|| -> Result<(File,File)> {
            let host = self.host.context("native host observation missing")?;
            let (before, elf) = host.pin(program, false)?;
            self.commands[index]["native_program_before"] = json!({"file":before.value(),"elf":elf});
            self.guards.push(before);
            Ok((OpenOptions::new().write(true).create_new(true).open(&stdout)?,
                OpenOptions::new().write(true).create_new(true).open(&stderr)?))
        })();
        let (out, err) = match prepared {
            Ok(files) => files,
            Err(error) => { self.precondition_failure(index,&error); return Err(error); }
        };
        self.commands[index]["state"] = json!("constructor_entered");
        let child = Command::new(&program.path).args(argv)
            .stdin(Stdio::null()).stdout(Stdio::from(out)).stderr(Stdio::from(err)).spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(error) => {
                self.halted = true; self.unknown = true;
                self.unknown_without_handle.push(index);
                self.commands[index]["state"] = json!("constructor_entered_no_handle_unknown");
                self.commands[index]["failure"] = json!(error.to_string());
                // The constructor returned no handle. Do not fabricate not-dispatched,
                // terminal code, output consumption or retry permission.
                return Err(error.into());
            }
        };
        let pid = child.id();
        self.commands[index]["pid"] = json!(pid);
        let mut observed_start = None;
        match process_start(pid) {
            Ok(start) => { observed_start=Some(start); self.commands[index]["start_ticks"] = json!(start); },
            Err(error) => self.commands[index]["start_observation_error"] = json!(error.to_string()),
        }
        match ObservedFile::read(&PathBuf::from(format!("/proc/{pid}/exe"))) {
            Ok(image) => {
                self.commands[index]["running_image_observation"] = image.value();
                if image.sha256 != program.sha256 {
                    self.custody_issues.push(format!("command {index} observed running image differs"));
                }
            }
            Err(error) => self.commands[index]["running_image_observation_error"] = json!(error.to_string()),
        }
        let status = match child.wait() {
            Ok(status) => status,
            Err(error) => {
                self.halted = true; self.unknown = true;
                self.commands[index]["state"] = json!("wait_error_owned_child_pending");
                self.commands[index]["failure"] = json!(error.to_string());
                self.pending.push(PendingAttempt {
                    command_index:index,child,program:program.clone(),
                    stdout,stderr,directory:directory.to_owned(),label:label.to_owned(),
                    pid,start_ticks:observed_start,terminal:None,observation_count:0,
                    observed_guards:Vec::new(),
                });
                // Keep the actual Child. No logs/results/post-output guards are read.
                return Err(error.into());
            }
        };
        let signal: Option<i32>;
        #[cfg(unix)] { signal = status.signal(); }
        #[cfg(not(unix))] { signal = None; }
        self.commands[index]["state"] = json!("known_reaped");
        self.commands[index]["exit_code"] = json!(status.code());
        self.commands[index]["signal"] = json!(signal);
        self.commands[index]["success"] = json!(status.success());
        let post = (|| -> Result<()> {
            let host = self.host.context("native host observation missing")?;
            let known=KnownReaped(&status);
            let files=known_terminal_files(host,program,&stdout,&stderr,&known)?;
            self.commands[index]["native_program_after"] =
                json!({"file":files.program.value(),"elf":files.program_elf});
            self.commands[index]["stdout"]=files.stdout.value();
            self.commands[index]["stderr"]=files.stderr.value();
            self.guards.extend([files.program,files.stdout,files.stderr]);
            if !self.custody_issues.is_empty() {
                bail!("observed command image custody differs");
            }
            let raw = serde_json::to_vec_pretty(&self.commands[index])?;
            let path = directory.join(format!("{label}.process.json"));
            write_new(&path,&raw)?;
            self.guards.push(ObservedFile::read(&path)?);
            Ok(())
        })();
        if let Err(error) = post {
            self.halted = true;
            self.custody_issues.push(format!("command {index} postguard: {error:#}"));
            return Err(error);
        }
        Ok(status.success())
    }
}
struct ImportedUnit {
    record: Value,
    snapshot: Option<Arc<VerifiedLineageModule>>,
    original_representation: Option<String>,
    phases: UnitPhases,
}
impl ImportedUnit {
    fn value(&self) -> Value {
        let mut value=self.record.clone();
        value["original_representation"]=json!(self.original_representation);
        value["phases"]=json!(self.phases);
        value
    }
    fn original_llvm(&self) -> bool { self.original_representation.as_deref()==Some("llvm") }
    fn classification_valid(&self) -> bool {
        matches!(self.original_representation.as_deref(),
            Some("llvm" | "configured-assembly" | "unsupported"))
    }
}
/// A distinct immutable-input/owned-process operation, not StagedComponent.
/// No Deserialize/Clone or caller-supplied verified flag can reconstruct it.
pub(crate) struct MixedImportedCohort {
    stage: MixedCaptureStage,
    units: Vec<ImportedUnit>,
    executor: Executor,
    guards: Vec<ObservedFile>,
    observed_custody_failure: OnceLock<String>,
    custody_issues: Vec<String>,
    classification_issues: Vec<String>,
    issues: Vec<String>,
    native_tools: Vec<Value>,
    host: Value,
    dependencies: Vec<PathBuf>,
    output: PathBuf,
    // Set only after this operation actually creates its fresh private directory.
    output_created: bool,
    summary_write_error: Option<String>,
}

// Shared structural import/verification/inventory only; caller-specific capability construction is separate.
fn held_llvm_phases<S>(
    unit: &Value, held_path: &Path, held_bytes: &[u8], arch: &str, ordinal: usize, index: usize,
    output: &Path, host: NativeHost, compiler: &provider_group::Pin,
    python: &provider_group::Pin, library: &provider_group::Pin,
    selected_library: &Path, selected_sha: &str,
    tls_profile: Option<&str>, atomic_profile: Option<&str>, wide_volatile_profile: Option<&str>, linux_syscall_profile: Option<&str>,
    expected_tls_profile: &Option<TlsProfile>, expected_atomic_profile: &Option<AtomicProfile>,
    expected_wide_volatile_profile: &Option<WideVolatileProfile>,
    expected_linux_syscall_profile: &Option<o_lang::ocore::native_ir::LinuxSyscallProfile>,
    shared_tool_guard_count: usize, executor: &mut Executor, guards: &mut Vec<ObservedFile>,
    custody_issues: &mut Vec<String>, record: &mut Value, phases: &mut UnitPhases,
    active: &mut Option<PhaseKind>, module_target: &mut Option<Value>,
    inventory_passed: &mut bool, snapshot: &mut Option<S>,
    check_original: impl Fn() -> Result<()>,
    capture_verified: impl FnOnce(Arc<NativeModule>, &[u8]) -> Result<S>,
) -> Result<()> {
    let (original_path,input_bytes) = checked_ir_bytes(unit,arch)?;
    if original_path.as_path() != held_path || input_bytes.as_slice() != held_bytes {
        bail!("current LLVM differs from same owned mixed-stage input");
    }
    let original = ObservedFile::read(&original_path)?;
    if original.sha256 != digest(held_bytes) || original.bytes != held_bytes.len() as u64 {
        bail!("mixed original LLVM observed identity differs");
    }
    record["original_input"] = original.value();
    guards.push(original);
    let directory = output.join(format!("unit-{ordinal:06}"));
    fs::create_dir(&directory)?;
    let input = directory.join(if captured_ir_format(&unit["ir"])? == "llvm-bitcode" {
        "original-input.bc"
    } else { "original-input.ll" });
    record["consumed_input"] = retain(&input,held_bytes,guards)?;
    let imported = directory.join("module.native-ir.json");
    let diagnostics = directory.join("llvm-metadata-diagnostics.json");
    let mut arguments = vec![input.display().to_string(),"--input-kind".into(),"llvm-ir".into(),
        "--emit".into(),"mir".into(),"--target".into(),format!("{arch}-unknown-none"),
        "-o".into(),imported.display().to_string(),
        "--llvm-library".into(),selected_library.display().to_string(),
        "--llvm-sha256".into(),selected_sha.to_owned()];
    for (flag,value) in [("--tls-profile",tls_profile),("--atomic-profile",atomic_profile),
        ("--linux-syscall-profile",linux_syscall_profile),
        ("--wide-volatile-profile",wide_volatile_profile)] {
        if let Some(value) = value { arguments.extend([flag.to_owned(),value.to_owned()]); }
    }
    arguments.extend([RAW_METADATA_OPTION.to_owned(),diagnostics.display().to_string()]);
    phases.import.command_index=Some(executor.commands.len());
    let import_ok = executor.run(compiler,&arguments,&directory,"import")?;
    // Only a known reaped attempt permits consumption of its outputs.
    record["metadata_diagnostics"] = retained_metadata_diagnostics(&diagnostics);
    if !import_ok { bail!("native LLVM import failed; retained full separate command streams"); }
    let raw = fs::read(&imported).context("read mixed imported native MIR")?;
    phases.import.pass("module");
    *active =Some(PhaseKind::Structural);phases.structural_verification.begin();
    let module = NativeModule::from_json(&raw).map_err(|error|
        anyhow::anyhow!("independent native verification: {}",error.message))?;
    if module.provenance.input_sha256 != unit["ir"]["sha256"]
        || module.target.triple != unit["ir"]["target_triple"]
        || module.target.data_layout != unit["ir"]["data_layout"]
        || &module.target.tls_profile != expected_tls_profile
        || &module.target.atomic_profile != expected_atomic_profile
        || &module.target.wide_volatile_profile != expected_wide_volatile_profile
        || &module.target.linux_syscall_profile != expected_linux_syscall_profile
    { bail!("mixed native import changed original input/target/profile"); }
    record["metadata_diagnostics"] = validate_metadata_diagnostics(
        Some(&diagnostics),&module,held_bytes,Some(selected_sha))?;
    guards.push(ObservedFile::read(&diagnostics)?);
    let current_target = serde_json::to_value(&module.target)?;
    if module_target.as_ref().is_some_and(|expected| expected != &current_target) {
        bail!("mixed imported modules have conflicting full target layouts/profiles");
    }
    if module_target.is_none() { *module_target = Some(current_target); }
    let mir = ObservedFile::read(&imported)?;
    if mir.sha256 != digest(&raw) || mir.bytes != raw.len() as u64 {
        bail!("mixed imported MIR changed after consumed parse");
    }
    record["module"] = mir.value();
    guards.push(mir);
    let verification = directory.join("verification.json");
    let verify_argv = vec![imported.display().to_string(),"--input-kind".into(),
        "native-ir".into(),"--verify-native".into(),"--receipt".into(),
        verification.display().to_string()];
    phases.structural_verification.command_index=Some(executor.commands.len());
    let verify_ok = executor.run(compiler,&verify_argv,&directory,"verify")?;
    if !verify_ok { bail!("mixed independent native verification subprocess failed"); }
    let receipt_raw = fs::read(&verification)?;
    let receipt: Value = serde_json::from_slice(&receipt_raw)?;
    if receipt["format"] != "ocore-native-verification-v1"
        || receipt["verifier"] != "ocore-native-v1"
        || receipt["scope"] != "structural_ir_verification"
        || receipt["verified"] != true
        || receipt["module_sha256"] != digest(&raw)
    { bail!("mixed native verification receipt differs from exact MIR"); }
    let receipt_pin = ObservedFile::read(&verification)?;
    if receipt_pin.sha256 != digest(&receipt_raw) {
        bail!("mixed native verification receipt changed");
    }
    record["verification"] = receipt_pin.value();
    guards.push(receipt_pin);
    let module = Arc::new(module);
    *snapshot = Some(capture_verified(Arc::clone(&module),&raw)?);
    record["structural_verification"] = json!("passed");
    phases.structural_verification.pass("verification");
    phases.control_inventory.begin();
    match control_inventory::collect(&format!("mixed-{index}"),&raw)
        .and_then(|value|serde_json::to_value(value).map_err(anyhow::Error::from)) {
        Ok(value)=>{record["control_inventory"]=value;phases.control_inventory.pass("control_inventory");}
        Err(error)=>{phases.control_inventory.fail(&format!("{error:#}"),false);
            record["control_inventory"]=json!({"failure":format!("{error:#}")});}
    }
    phases.floating_diagnostics.begin();
    match floating_requirements(&module) {
        Ok(value)=>{record["generated_floating_helper_requirements"]=json!(value);
            phases.floating_diagnostics.pass("generated_floating_helper_requirements");}
        Err(error)=>{phases.floating_diagnostics.fail(&format!("{error:#}"),false);
            record["generated_floating_helper_requirements"]=json!({"failure":format!("{error:#}")});}
    }
    // Auxiliary errors remain errors, but cannot suppress this independent check.
    *active =None;
    if let Err(error)=check_original().and_then(|()| {
        for guard in &guards[..shared_tool_guard_count] {guard.check()?;}
        Ok(())
    }) {
        custody_issues.push(format!("before independent inventory {ordinal}: {error:#}"));
        executor.halted=true;
        phases.source_native_inventory.block("custody refusal before independent inventory");
        return Err(error);
    }
    *active =Some(PhaseKind::SourceInventory);phases.source_native_inventory.begin();
    let inventory_dir = directory.join("source-inventory");
    fs::create_dir(&inventory_dir)?;
    let helper = inventory_dir.join("source_inventory.py");
    let inventory_input = inventory_dir.join("original.ll");
    let inventory_native = inventory_dir.join("module.native-ir.json");
    let inventory_result = inventory_dir.join("inventory.json");
    record["inventory_inputs"] = json!({
        "helper":retain(&helper,provider_group::INVENTORY.as_bytes(),guards)?,
        "original":retain(&inventory_input,held_bytes,guards)?,
        "native":retain(&inventory_native,&raw,guards)?});
    host.pin(python,false)?; host.pin(library,true)?;
    let inventory_argv = vec!["-I".into(),"-c".into(),
        provider_group::INVENTORY_DRIVER.into(),helper.display().to_string(),
        digest(provider_group::INVENTORY.as_bytes()),library.path.display().to_string(),
        library.sha256.clone(),inventory_input.display().to_string(),
        inventory_native.display().to_string(),inventory_result.display().to_string(),
        python.sha256.clone()];
    phases.source_native_inventory.command_index=Some(executor.commands.len());
    let inventory_ok = executor.run(python,&inventory_argv,&inventory_dir,"inventory")?;
    // Preserve the existing driver's external before/after and exact-buffer guards.
    host.pin(python,false)?; host.pin(library,true)?;
    if fs::read(&helper)? != provider_group::INVENTORY.as_bytes()
        || fs::read(&inventory_input)? != held_bytes
        || fs::read(&inventory_native)? != raw
    { bail!("mixed independent source inventory buffers changed"); }
    if !inventory_ok { bail!("mixed independent source inventory subprocess failed"); }
    let inventory_raw = fs::read(&inventory_result)?;
    let preservation: Value = serde_json::from_slice(&inventory_raw)?;
    if preservation["schema"] != "ocore-independent-source-inventory-v1"
        || preservation["source"]["sha256"] != digest(held_bytes)
        || preservation["llvm_library"]["sha256"] != library.sha256
    { bail!("mixed independent source inventory receipt identity differs"); }
    let inventory_pin = ObservedFile::read(&inventory_result)?;
    if inventory_pin.sha256 != digest(&inventory_raw) {
        bail!("mixed independent source inventory receipt changed");
    }
    record["independent_inventory"] = json!({"receipt":inventory_pin.value(),
        "preservation":preservation,
        "scope":"bounded independent definitions/declarations/globals/initializer and intrinsic-site inventory; not executable equivalence or external provider proof"});
    guards.push(inventory_pin);
    *inventory_passed = true;
    phases.source_native_inventory.pass("independent_inventory");
    Ok(())
}

impl MixedImportedCohort {
    pub(crate) fn pending_process_count(&self) -> usize {
        self.executor.pending.iter().filter(|attempt|attempt.terminal.is_none()).count()
    }
    pub(crate) fn check_custody(&self) -> Result<()> {
        if let Some(error)=self.observed_custody_failure.get() {
            bail!("mixed import permanently refused after observed custody failure: {error}");
        }
        if self.executor.unknown || !self.executor.pending.is_empty() {
            bail!("mixed import has historical UNKNOWN; owned handles and observations retained");
        }
        if !self.custody_issues.is_empty() || !self.executor.custody_issues.is_empty() {
            bail!("mixed import custody failed; private module views withheld");
        }
        let observed=(|| -> Result<()> {
            self.stage.check_custody()?;
            for guard in self.guards.iter().chain(self.executor.guards.iter()) { guard.check()?; }
            Ok(())
        })();
        if let Err(error)=&observed {
            let _=self.observed_custody_failure.set(format!("{error:#}"));
        }
        observed
    }
    /// Structural-only view, including units whose separate inventory failed.
    /// The Arc and mutable module never escape; fresh custody gates both sides.
    pub(crate) fn with_verified_module<T>(
        &self, occurrence: usize, use_module: impl FnOnce(&NativeModule) -> Result<T>,
    ) -> Result<T> {
        self.check_custody()?;
        let snapshot = self.units.get(occurrence)
            .and_then(|unit|unit.snapshot.as_ref())
            .context("mixed unit has no independently verified structural module")?;
        if snapshot.mir_sha256 != self.units[occurrence].record["module"]["sha256"] {
            let _=self.observed_custody_failure.set("mixed retained snapshot diagnostic binding differs".into());
            let _=self.observed_custody_failure.set(
                "retained mixed module snapshot binding differs".into());
            bail!("mixed retained snapshot diagnostic binding differs");
        }
        let result = use_module(&snapshot.module);
        self.check_custody()?;
        result
    }
    pub(crate) fn summary(&self) -> Value {
        let stable=self.check_custody().is_ok();
        let llvm_count=self.units.iter().filter(|unit|unit.original_llvm()).count();
        let classified=self.units.iter().all(ImportedUnit::classification_valid)
            && self.classification_issues.is_empty();
        let safe=stable && classified && llvm_count>0;
        let structural=safe && self.units.iter().filter(|unit|unit.original_llvm())
            .all(|unit|unit.snapshot.is_some() && unit.phases.structural_verification.passed());
        let inventory=safe && self.units.iter().filter(|unit|unit.original_llvm())
            .all(|unit|unit.phases.source_native_inventory.passed());
        let all_phases=safe && self.units.iter().filter(|unit|unit.original_llvm())
            .all(|unit|unit.phases.all_passed());
        let mut summary = serde_json::Map::new();
        summary.insert("schema".into(), json!("ocore-mixed-llvm-import-cohort-v2"));
        summary.insert("scope".into(), json!("held original mixed membership; distinct structural, inventory and diagnostic phase observations"));
        summary.insert("shared_inputs".into(), json!({"raw_report_sha256":digest(self.stage.raw_report()),
                "raw_context_sha256":digest(self.stage.raw_context()),
                "member_policy_sha256":digest(self.stage.member_policy()),
                "original_order_policy_sha256":digest(self.stage.original_order_policy())}));
        summary.insert("order_scope".into(), json!("original checked member index/order; not native link order"));
        summary.insert("host".into(), json!(self.host));
        summary.insert("native_tools".into(), json!(self.native_tools));
        summary.insert("declared_dependencies_unresolved".into(), json!(self.dependencies));
        summary.insert("units".into(), json!(self.units.iter().map(ImportedUnit::value).collect::<Vec<_>>()));
        summary.insert("commands".into(), json!(self.executor.commands));
        summary.insert("stage_issues".into(), json!(self.stage.issues()));
        summary.insert("issues".into(), json!(self.issues));
        summary.insert("classification_issues".into(), json!(self.classification_issues));
        summary.insert("custody_issues".into(), json!(self.custody_issues));
        summary.insert("observed_custody_failure".into(), json!(self.observed_custody_failure.get()));
        summary.insert("command_custody_issues".into(), json!(self.executor.custody_issues));
        summary.insert("historical_unknown_boundary".into(), json!(self.executor.unknown));
        summary.insert("unknown_without_owned_handle".into(), json!(self.executor.unknown_without_handle));
        summary.insert("owned_pending_child_count".into(), json!(self.pending_process_count()));
        summary.insert("retained_child_handle_count".into(), json!(self.executor.pending.len()));
        summary.insert("terminal_observations".into(), json!(self.executor.terminal_observations));
        summary.insert("observed_custody_stable".into(), json!(stable));
        summary.insert("original_member_count".into(), json!(self.units.len()));
        summary.insert("original_llvm_count".into(), json!(llvm_count));
        summary.insert("original_classification_complete".into(), json!(classified));
        summary.insert("llvm_cohort_state".into(), json!(if llvm_count==0 {"no_original_llvm_occurrences"} else {"observed"}));
        summary.insert("original_llvm_structural_verification_complete".into(), json!(structural));
        summary.insert("original_llvm_independent_inventory_complete".into(), json!(inventory));
        summary.insert("original_llvm_required_phases_complete".into(), json!(all_phases));
        summary.insert("exclusive_output_created".into(), json!(self.output_created));
        summary.insert("summary_write_error".into(), json!(self.summary_write_error));
        summary.insert("source_capture_complete".into(), json!(false));
        summary.insert("unit_lowering_complete".into(), json!(false));
        summary.insert("artifact_complete".into(), json!(false));
        summary.insert("runtime_complete".into(), json!(false));
        summary.insert("qualifications".into(), json!({"original_source_authority":false,"original_order_meaning":false,
                "abi":false,"providers":false,"native_execution":false,"all_isa":false,
                "physical_file_identity":false,"preexec_tool_closure":false,
                "transitive_libraries":false,"full_session_quiescence":false,
                "generated_application_source_inclusion":false}));
        Value::Object(summary)
    }
    /// Observe only retained original Child handles. Never dispatch or resume work.
    /// Historical UNKNOWN and all qualification refusal remain permanent.
    /// Wait only the already retained original children. This does not resume
    /// import, clear historical UNKNOWN, or consume outputs before a known wait.
    /// Repeated wait errors retain bounded first/last/count accounting in this
    /// owned call; they never create a replacement process or a deadline.
    pub(crate) fn wait_pending_original(&mut self) -> Value {
        let mut wait_errors = Vec::new();
        for (pending_index, attempt) in self.executor.pending.iter_mut().enumerate() {
            if attempt.terminal.is_some() {
                continue;
            }
            let mut count = 0_u64;
            let mut first_error: Option<String> = None;
            let mut last_error: Option<String> = None;
            loop {
                match attempt.child.wait() {
                    Ok(_) => break,
                    Err(error) => {
                        let message = error.to_string();
                        if first_error.is_none() {
                            first_error = Some(message.clone());
                        }
                        last_error = Some(message);
                        count = count.saturating_add(1);
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }
                }
            }
            if count != 0 {
                wait_errors.push(json!({
                    "pending_index": pending_index,
                    "state": "original_child_blocking_wait_errors",
                    "wait_error_count": count,
                    "first_error": first_error,
                    "last_error": last_error,
                    "historical_unknown_cleared": false,
                    "import_resumed": false
                }));
            }
        }
        // Child::wait caches the known terminal status. Reuse the existing
        // observer's exact guards, terminal record, file reads and publication.
        let terminal_observation = self.observe_pending();
        json!({
            "schema": "ocore-runtime-mixed-original-child-wait-v1",
            "terminal_observation": terminal_observation,
            "bounded_wait_error_accounting": wait_errors,
            "historical_unknown_cleared": false,
            "import_resumed": false,
            "descendant_quiescence_qualified": false
        })
    }

    pub(crate) fn observe_pending(&mut self) -> Value {
        let stage=&self.stage;
        let guards=&self.guards;
        let latch=&self.observed_custody_failure;
        let custody=&mut self.custody_issues;
        let Executor {host,pending,guards:command_guards,terminal_observations,
            unknown_without_handle,..}=&mut self.executor;
        let mut latest=Vec::new();
        for attempt in pending.iter_mut() {
            if attempt.terminal.is_some() { continue; }
            attempt.observation_count+=1;
            let mut row=json!({"schema":"ocore-mixed-original-child-observation-v1",
                "command_index":attempt.command_index,"pid":attempt.pid,
                "original_start_ticks":attempt.start_ticks,"observation":attempt.observation_count,
                "deadline":null,"signals_sent":[],"historical_unknown_qualification_refusal":true,
                "descendant_quiescence_qualified":false});
            let mut identity_conflict=false;
            match process_start(attempt.pid) {
                Ok(now)=>{
                    row["current_start_ticks"]=json!(now);
                    if attempt.start_ticks.is_some_and(|original|original!=now) {
                        identity_conflict=true;
                        row["state"]=json!("original_process_identity_conflict_unknown");
                        let message=format!("pending command {} process start differs",attempt.command_index);
                        let _=latch.set(message.clone());custody.push(message);
                    }
                }
                Err(error)=>row["process_metadata_error"]=json!(error.to_string()),
            }
            if !identity_conflict {
                match attempt.child.try_wait() {
                    Ok(None)=>row["state"]=json!("still_running_unknown"),
                    Err(error)=>{
                        row["state"]=json!("original_child_try_wait_error_unknown");
                        row["failure"]=json!(error.to_string());
                    }
                    Ok(Some(status))=>{
                        let terminal=KnownTerminal::observed(&status);
                        // Retain known terminal facts before any postguard/publication I/O.
                        attempt.terminal=Some(terminal.clone());
                        row["state"]=json!("original_child_known_reaped_after_unknown");
                        row["terminal"]=json!(terminal);
                        let post=(|| -> Result<Value> {
                            stage.check_custody()?;
                            for guard in guards.iter().chain(command_guards.iter()) {guard.check()?;}
                            let known=KnownReaped(&status);
                            let files=known_terminal_files(
                                (*host).context("pending original native host missing")?,
                                &attempt.program,&attempt.stdout,&attempt.stderr,&known)?;
                            let evidence=json!({"native_program_after":{"file":files.program.value(),
                                "elf":files.program_elf},"stdout":files.stdout.value(),
                                "stderr":files.stderr.value(),
                                "scope":"known direct-child terminal and observed raw file pins only"});
                            attempt.observed_guards.extend([files.program,files.stdout,files.stderr]);
                            Ok(evidence)
                        })();
                        match post {
                            Ok(evidence)=>{row["postguard"]="passed".into();row["raw_evidence"]=evidence;}
                            Err(error)=>{
                                let message=format!("pending command {} terminal postguard: {error:#}",attempt.command_index);
                                let _=latch.set(message.clone());custody.push(message.clone());
                                row["postguard"]="known_failed".into();row["postguard_failure"]=json!(message);
                            }
                        }
                    }
                }
            }
            let path=attempt.directory.join(format!(
                "{}.pending-observation-{:06}.json",attempt.label,attempt.observation_count));
            let publication=(|| -> Result<Value> {
                let raw=serde_json::to_vec_pretty(&row)?;
                write_new(&path,&raw)?;
                let pin=ObservedFile::read(&path)?;
                if pin.sha256!=digest(&raw) {bail!("pending observation readback pin differs");}
                Ok(pin.value())
            })();
            match publication {
                Ok(pin)=>row["publication"]=pin,
                Err(error)=>row["publication_error"]=json!(format!("{error:#}")),
            }
            terminal_observations.push(row.clone());latest.push(row);
        }
        json!({"schema":"ocore-mixed-pending-observation-result-v1","observations":latest,
            "unknown_without_owned_handle":unknown_without_handle,
            "historical_unknown_qualification_refusal":true,
            "automatic_reimport":false,"automatic_continuation":false,
            "native_module_minted":false,"full_session_quiescence_qualified":false})
    }

    #[allow(clippy::too_many_arguments)]
    fn run_body(&mut self, target: &str, import_options: NativeImportOptions<'_>,
        compiler: &provider_group::Pin, python: &provider_group::Pin,
        library: &provider_group::Pin) -> Result<()> {
    let NativeImportOptions {
        llvm_library,
        llvm_sha256,
        tls_profile,
        atomic_profile,
        wide_volatile_profile,
        linux_syscall_profile,
        dependencies: dependency_paths,
    } = import_options;
    let expected_tls_profile = match tls_profile {
        None => None,
        Some("linux-elf-static-nonpreemptive-v1") => {
            Some(TlsProfile::LinuxElfStaticNonpreemptiveV1)
        }
        Some(_) => bail!("unsupported native TLS realization profile"),
    };
    let expected_atomic_profile = match atomic_profile {
        None => None,
        Some("coherent-ram-v1") => Some(AtomicProfile::CoherentRamV1),
        Some(_) => bail!("unsupported native atomic realization profile"),
    };
    let expected_wide_volatile_profile = match wide_volatile_profile {
        None => None,
        Some("ordinary-ram-split-v1") => Some(WideVolatileProfile::OrdinaryRamSplitV1),
        Some(_) => bail!("unsupported native wide volatile realization profile"),
    };
    let expected_linux_syscall_profile = match linux_syscall_profile {
        None => None,
        Some("linux-user-raw-v1") => {
            Some(o_lang::ocore::native_ir::LinuxSyscallProfile::LinuxUserRawV1)
        }
        Some(_) => bail!("unsupported native Linux syscall realization profile"),
    };
        self.dependencies = dependency_paths.to_vec();
        let arch = architecture(target)?;
        let selected_library = llvm_library.context("mixed import requires explicit selected LLVM library")?;
        let selected_sha = llvm_sha256.context("mixed import requires explicit selected LLVM library SHA")?;
        if selected_library != library.path.as_path() || selected_sha != library.sha256.as_str() {
            bail!("mixed import and independent inventory LLVM selections differ");
        }
        self.stage.check_custody()?;
        if self.stage.units().len()!=self.stage.original_member_count() {
            bail!("mixed stage does not cover all original member occurrences");
        }
        for (index,unit) in self.stage.units().iter().enumerate() {
            if unit.index()!=index {
                bail!("mixed stage original member index/order is not dense and exact");
            }
            let tag=self.stage.original_representation(index);
            let relation=match (tag,unit.representation()) {
                (Some("llvm"),MixedUnitRepresentation::LlvmInput{..})
                |(Some("configured-assembly"),MixedUnitRepresentation::ConfiguredAssemblyInput{..})
                |(Some("llvm"|"configured-assembly"|"unsupported"),MixedUnitRepresentation::Refused{..})=>true,
                _=>false,
            };
            if !relation {
                self.classification_issues.push(format!(
                    "original member {index} tag/staging relation unsupported: {tag:?}"));
                self.units[index].record["status"]=json!("refused_original_classification");
            }
        }
        let (host, host_value) = NativeHost::observe()?;
        self.host = host_value;
        self.executor.host = Some(host);
        for (role,pin,is_library) in [("compiler",compiler,false),("inventory_python",python,false),
                                     ("llvm_library",library,true)] {
            let (file,elf) = host.pin(pin,is_library)?;
            self.native_tools.push(json!({"role":role,"file":file.value(),"elf":elf}));
            self.guards.push(file);
        }
        let shared_tool_guard_count = self.guards.len();
        if !self.output.is_absolute() { bail!("mixed import output must be absolute"); }
        fs::create_dir(&self.output).context("mixed import output must be a new directory")?;
        self.output = self.output.canonicalize()?;
        self.output_created = true;
        let mut module_target: Option<Value> = None;
        for ordinal in 0..self.stage.units().len() {
            let staged = &self.stage.units()[ordinal];
            let index = staged.index();
            if self.units[ordinal].original_representation.as_deref()!=Some("llvm") {
                continue;
            }
            let (held_path,held_bytes) = match staged.representation() {
                MixedUnitRepresentation::LlvmInput { path,bytes } => (path,bytes),
                // Assembly and refused inputs retain their exact original outcomes.
                _ => continue,
            };
            if self.executor.halted {
                self.units[ordinal].record["status"] = json!("unattempted_after_dispatch_halt");
                self.units[ordinal].phases.block_unattempted("global dispatch halt; no new attempt");
                continue;
            }
            if let Err(error) = self.stage.check_custody().and_then(|()| {
                for guard in &self.guards[..shared_tool_guard_count] { guard.check()?; }
                Ok(())
            }) {
                self.custody_issues.push(format!("before occurrence {ordinal}: {error:#}"));
                self.executor.halted = true;
                self.units[ordinal].record["status"] = json!("unattempted_custody_failure");
                self.units[ordinal].phases.block_unattempted("global custody failure before dispatch");
                continue;
            }
            // New outputs are checked at this unit's boundary. Prior immutable
            // module outputs are rechecked once at finalization and at every view,
            // not cumulatively rehashed before unrelated later imports.
            let unit_guard_start = self.guards.len();
            let command_guard_start = self.executor.guards.len();
            let command_start = self.executor.commands.len();
            let mut record = self.units[ordinal].record.clone();
            let mut snapshot = None;
            let mut inventory_passed = false;
            let mut phases=self.units[ordinal].phases.clone();
            let mut active=Some(PhaseKind::Import);
            phases.import.begin();
            let result = (|| -> Result<()> {
                let stage = &self.stage;
                let unit = stage.unit(index).context("mixed stage original member absent")?;
                held_llvm_phases(unit,held_path.as_path(),held_bytes.as_slice(),arch,ordinal,index,
                    &self.output,host,compiler,python,library,selected_library,selected_sha,
                    tls_profile,atomic_profile,wide_volatile_profile,linux_syscall_profile,
                    &expected_tls_profile,&expected_atomic_profile,&expected_wide_volatile_profile,&expected_linux_syscall_profile,
                    shared_tool_guard_count,&mut self.executor,&mut self.guards,&mut self.custody_issues,
                    &mut record,&mut phases,&mut active,&mut module_target,&mut inventory_passed,&mut snapshot,
                    || stage.check_custody(),
                    |module,raw| Ok(Arc::new(VerifiedLineageModule::from_verified(&module,raw)?)))
            })();
            record["command_indices"] = json!((command_start..self.executor.commands.len()).collect::<Vec<_>>());
            record["independent_inventory_passed"] = json!(inventory_passed);
            match result {
                Ok(())=>record["status"]=json!(if phases.all_passed() {
                    "all_required_llvm_phases_passed"
                } else {"known_auxiliary_failure_with_independent_inventory_result"}),
                Err(error)=>{
                    if let Some(phase)=active {
                        phases.get_mut(phase).fail(&format!("{error:#}"),self.executor.unknown);
                        record["failed_phase"]=json!(phase.name());
                    } else {record["failed_phase"]=json!("global_custody_boundary");}
                    phases.block_unattempted("preceding phase/global process boundary did not complete");
                    record["status"]=json!(if self.executor.unknown {"phase_unknown"} else {"phase_known_failed"});
                    record["failure"]=json!(format!("{error:#}"));
                }
            }
            let original_representation=self.units[ordinal].original_representation.clone();
            self.units[ordinal] = ImportedUnit { record,snapshot,original_representation,phases };
            // Never read any generated output after an unknown constructor/wait.
            if !self.executor.unknown {
                let post = self.stage.check_custody().and_then(|()| {
                    for guard in &self.guards[..shared_tool_guard_count] { guard.check()?; }
                    for guard in self.guards[unit_guard_start..].iter()
                        .chain(self.executor.guards[command_guard_start..].iter()) {
                        guard.check()?;
                    }
                    Ok(())
                });
                if let Err(error) = post {
                    self.custody_issues.push(format!("after occurrence {ordinal}: {error:#}"));
                    self.executor.halted = true;
                }
            }
        }
        // Observe every retained output before returning any private success view.
        // A failed observation remains a permanent refusal even if bytes later revert.
        if !self.executor.unknown {
            if let Err(error) = self.check_custody() {
                self.custody_issues.push(format!("final cohort guard: {error:#}"));
                self.executor.halted = true;
            }
        }
        Ok(())
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) fn import_stage(
    stage: MixedCaptureStage, target: &str, output: &Path,
    import_options: NativeImportOptions<'_>, compiler: &provider_group::Pin,
    inventory_python: &provider_group::Pin, inventory_library: &provider_group::Pin,
) -> MixedImportedCohort {
    let units=(0..stage.original_member_count()).map(|ordinal| {
        let original_representation=stage.original_representation(ordinal).map(str::to_owned);
        let staged=stage.units().get(ordinal).filter(|unit|unit.index()==ordinal);
        let (representation,status,reasons)=match staged.map(|unit|unit.representation()) {
            Some(MixedUnitRepresentation::LlvmInput{..})=>
                ("llvm-input","not_attempted",Vec::<String>::new()),
            Some(MixedUnitRepresentation::ConfiguredAssemblyInput{..})=>
                ("configured-assembly-input","pending-assembly",vec![
                    "independent source/function/ABI/PC/memory authority remains required".into()]),
            Some(MixedUnitRepresentation::Refused{reasons})=>("refused","refused",reasons.clone()),
            None=>("refused","refused_missing_original_stage_mapping",
                vec!["complete dense original stage occurrence is missing".into()]),
        };
        let phases=UnitPhases::unattempted(if representation=="llvm-input" {
            "cohort/import prerequisites not reached"
        } else {"original required input is refused, unsupported or pending assembly"});
        ImportedUnit {record:json!({"occurrence":ordinal,"member_index":ordinal,
            "representation":representation,"status":status,"reasons":reasons,
            "structural_verification":"not_performed","independent_inventory_passed":false,
            "command_indices":[]}),snapshot:None,original_representation,phases}
    }).collect();
    let mut cohort = MixedImportedCohort { stage,units,executor:Executor::new(),guards:Vec::new(),
        observed_custody_failure:OnceLock::new(),custody_issues:Vec::new(),
        classification_issues:Vec::new(),issues:Vec::new(),native_tools:Vec::new(),host:Value::Null,
        dependencies:Vec::new(),output:output.to_owned(),output_created:false,summary_write_error:None };
    if let Err(error) = cohort.run_body(target,import_options,compiler,inventory_python,inventory_library) {
        cohort.issues.push(format!("cohort precondition/operation: {error:#}"));
    }
    // Publication is exclusive. A failed summary write never discards the owned
    // cohort, raw stage, known outcomes or pending Child handles.
    let saved = (|| -> Result<()> {
        if !cohort.output_created {
            bail!("exclusive mixed output directory was not created; no receipt publication attempted");
        }
        let raw = serde_json::to_vec_pretty(&cohort.summary())?;
        write_new(&cohort.output.join("mixed-llvm-import.json"),&raw)
    })();
    if let Err(error) = saved { cohort.summary_write_error = Some(error.to_string()); }
    cohort
}

#[path="mixed_incomplete_llvm_import.rs"]
mod incomplete_diagnostic;
pub(crate) use incomplete_diagnostic::{MixedIncompleteImportedCohort,prepare_diagnostic_session};
