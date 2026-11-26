//! Normal held-report diagnostic routing. No capture JSON flag mints admission.
use super::super::{provider_group, NativeImportOptions, NativeSourceOptions};
use super as source_action;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const INPUT_FORMAT: &str = "ocore-runtime-mixed-diagnostic-inputs-v1";
const OUTPUT_FORMAT: &str = "ocore-runtime-mixed-diagnostic-delivery-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeIdentity {
    bytes: u64,
    #[cfg(unix)] device: u64,
    #[cfg(unix)] inode: u64,
    #[cfg(unix)] mode: u32,
    #[cfg(unix)] mtime: i64,
    #[cfg(unix)] mtime_nsec: i64,
    #[cfg(unix)] ctime: i64,
    #[cfg(unix)] ctime_nsec: i64,
}
impl NativeIdentity {
    fn of(metadata: &Metadata) -> Result<Self> {
        if !metadata.is_file() { bail!("mixed diagnostic input is not a regular file"); }
        Ok(Self {
            bytes: metadata.len(),
            #[cfg(unix)] device: metadata.dev(),
            #[cfg(unix)] inode: metadata.ino(),
            #[cfg(unix)] mode: metadata.mode(),
            #[cfg(unix)] mtime: metadata.mtime(),
            #[cfg(unix)] mtime_nsec: metadata.mtime_nsec(),
            #[cfg(unix)] ctime: metadata.ctime(),
            #[cfg(unix)] ctime_nsec: metadata.ctime_nsec(),
        })
    }
}
#[derive(Clone)]
struct ExpectedInput { path: PathBuf, bytes: u64, sha256: String }
#[derive(Clone)]
struct HeldInput {
    expected: ExpectedInput,
    physical: PathBuf,
    native: NativeIdentity,
}
fn hash(raw: &[u8]) -> String { format!("{:x}", Sha256::digest(raw)) }
fn fields(value: &Value, allowed: &[&str], label: &str) -> Result<()> {
    let object = value.as_object().ok_or_else(|| anyhow!("{label} must be an object"))?;
    if object.len() != allowed.len()
        || object.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{label} has missing or unknown fields");
    }
    Ok(())
}
fn expected(value: &Value, label: &str) -> Result<ExpectedInput> {
    fields(value, &["path", "bytes", "sha256"], label)?;
    let path = PathBuf::from(value["path"].as_str()
        .ok_or_else(|| anyhow!("{label}.path must be a string"))?);
    let bytes = value["bytes"].as_u64()
        .ok_or_else(|| anyhow!("{label}.bytes must be an unsigned JSON integer"))?;
    let sha256 = value["sha256"].as_str()
        .ok_or_else(|| anyhow!("{label}.sha256 must be a string"))?.to_owned();
    if !path.is_absolute() || sha256.len() != 64
        || !sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        bail!("{label} needs an absolute path and lowercase SHA-256");
    }
    Ok(ExpectedInput { path, bytes, sha256 })
}
fn read_held(selected: ExpectedInput, keep_bytes: bool) -> Result<(HeldInput, Vec<u8>, Vec<u8>)> {
    let physical = selected.path.canonicalize().with_context(|| format!("resolve {}", selected.path.display()))?;
    let mut file = File::open(&selected.path)?;
    let native = NativeIdentity::of(&file.metadata()?)?;
    let mut retained = Vec::new();
    let mut header = Vec::new();
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        total = total.checked_add(count as u64).ok_or_else(|| anyhow!("input length overflow"))?;
        if total > selected.bytes { bail!("mixed diagnostic input exceeds selected byte length"); }
        hasher.update(&buffer[..count]);
        if header.len() < 64 {
            header.extend_from_slice(&buffer[..count.min(64 - header.len())]);
        }
        if keep_bytes { retained.extend_from_slice(&buffer[..count]); }
    }
    let observed = format!("{:x}", hasher.finalize());
    if total != selected.bytes || observed != selected.sha256
        || NativeIdentity::of(&file.metadata()?)? != native
        || NativeIdentity::of(&fs::metadata(&selected.path)?)? != native
        || selected.path.canonicalize()? != physical {
        bail!("mixed diagnostic consumed input differs from selected bytes or native identity: {}", selected.path.display());
    }
    Ok((HeldInput { expected: selected, physical, native }, retained, header))
}
impl HeldInput {
    fn check(&self) -> Result<()> {
        let (current, _, _) = read_held(self.expected.clone(), false)?;
        if current.physical != self.physical || current.native != self.native {
            bail!("held mixed diagnostic input native identity changed: {}", self.expected.path.display());
        }
        Ok(())
    }
    fn pin(&self) -> Value {
        json!({"path": self.expected.path, "bytes": self.expected.bytes,
            "sha256": self.expected.sha256, "physical_path": self.physical})
    }
    fn mixed_pin(&self) -> Result<source_action::MixedInputPin> {
        source_action::MixedInputPin::declared(self.expected.path.clone(), self.expected.bytes, self.expected.sha256.clone())
    }
    fn tool_pin(&self) -> provider_group::Pin {
        provider_group::Pin { path: self.expected.path.clone(), sha256: self.expected.sha256.clone() }
    }
}
fn selected_sidecar(path: &Path) -> Result<(HeldInput, Vec<u8>)> {
    let path = path.canonicalize()?;
    let mut file = File::open(&path)?;
    let native = NativeIdentity::of(&file.metadata()?)?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    if NativeIdentity::of(&file.metadata()?)? != native
        || NativeIdentity::of(&fs::metadata(&path)?)? != native {
        bail!("mixed diagnostic sidecar changed while consumed");
    }
    let selected = ExpectedInput { path: path.clone(), bytes: raw.len() as u64, sha256: hash(&raw) };
    Ok((HeldInput { expected: selected, physical: path, native }, raw))
}
fn host_machine() -> Result<u16> {
    if !cfg!(target_os = "linux") { bail!("mixed diagnostic execution requires the actual supported Linux host"); }
    match std::env::consts::ARCH {
        "x86_64" => Ok(62), "aarch64" => Ok(183), "riscv64" => Ok(243),
        _ => bail!("mixed diagnostic actual host ISA is unsupported"),
    }
}
fn host_elf(header: &[u8], host: u16, library: bool) -> Result<()> {
    if header.len() != 64 || &header[..4] != b"\x7fELF"
        || header[4] != 2 || header[5] != 1 || header[6] != 1
        || u16::from_le_bytes([header[18],header[19]]) != host
        || u32::from_le_bytes([header[20],header[21],header[22],header[23]]) != 1 {
        bail!("mixed diagnostic selected execution input is not a matching ELF64 little-endian host image");
    }
    let kind = u16::from_le_bytes([header[16],header[17]]);
    if (library && kind != 3) || (!library && !matches!(kind, 2 | 3)) {
        bail!("mixed diagnostic selected execution input has an unsupported ELF type");
    }
    Ok(())
}
struct HeldRequest {
    guards: BTreeMap<&'static str, HeldInput>,
    report_raw: Vec<u8>,
    sidecar_raw: Vec<u8>,
    policy: Option<source_action::MixedCapturePolicy>,
    refusal: OnceLock<String>,
}
impl HeldRequest {
    fn hold(report: &Path, sidecar: &Path) -> Result<Self> {
        let host = host_machine()?;
        let (sidecar_guard, sidecar_raw) = selected_sidecar(sidecar)?;
        let document = super::super::provider_order::checked_json(&sidecar_raw)?;
        fields(&document, &["schema","report","context","member_policy","original_order_policy",
            "python","compiler","inventory_python","inventory_library","required_members"], "mixed diagnostic sidecar")?;
        if document["schema"].as_str() != Some(INPUT_FORMAT) {
            bail!("unsupported mixed diagnostic input schema");
        }
        let mut guards = BTreeMap::new();
        guards.insert("sidecar", sidecar_guard);
        let mut raw_inputs = BTreeMap::new();
        for role in ["report","context","member_policy","original_order_policy",
            "python","compiler","inventory_python","inventory_library"] {
            let keep = matches!(role,"report"|"context"|"member_policy"|"original_order_policy");
            let (guard, raw, header) = read_held(expected(&document[role],role)?,keep)?;
            if matches!(role,"python"|"compiler"|"inventory_python"|"inventory_library") {
                host_elf(&header,host,role=="inventory_library")?;
            }
            guards.insert(role,guard);
            if keep { raw_inputs.insert(role,raw); }
        }
        if report.canonicalize()? != guards["report"].physical {
            bail!("CLI report and externally selected report pin identify different files");
        }
        let report_raw = raw_inputs.remove("report").expect("held report role");
        let capture = super::super::provider_order::checked_json(&report_raw)?;
        if capture["schema"].as_str() != Some("ocore-runtime-capture-v2") {
            bail!("mixed diagnostic requires a genuine v2 capture report; a fresh recipe needs a separate prior context/member capability and cannot infer one from its outputs");
        }
        let rows = document["required_members"].as_array()
            .ok_or_else(|| anyhow!("required_members must be an array"))?;
        let mut required_members = BTreeSet::new();
        for row in rows {
            let id = row.as_str().ok_or_else(|| anyhow!("required member identity must be a string"))?;
            if id.is_empty() || id.contains('\0') || !required_members.insert(id.to_owned()) {
                bail!("required member identities are empty, invalid or duplicated");
            }
        }
        let policy = source_action::MixedCapturePolicy::hold(
            guards["context"].mixed_pin()?, raw_inputs.remove("context").expect("held context role"),
            guards["member_policy"].mixed_pin()?, raw_inputs.remove("member_policy").expect("held member policy role"),
            guards["original_order_policy"].mixed_pin()?, raw_inputs.remove("original_order_policy").expect("held order policy role"),
            guards["python"].mixed_pin()?, required_members)?;
        let request = Self { guards, report_raw, sidecar_raw, policy:Some(policy), refusal:OnceLock::new() };
        request.check()?;
        Ok(request)
    }
    fn check(&self) -> Result<()> {
        if let Some(reason) = self.refusal.get() { bail!("permanent mixed diagnostic refusal: {reason}"); }
        for (role,guard) in &self.guards {
            if let Err(error) = guard.check() {
                let reason = format!("{role}: {error}");
                let _ = self.refusal.set(reason.clone());
                bail!("mixed diagnostic custody failed: {reason}");
            }
        }
        Ok(())
    }
    fn shared(&self) -> Value {
        let pins: BTreeMap<_,_> = self.guards.iter().map(|(role,guard)|(*role,guard.pin())).collect();
        json!({"inputs":pins,"sidecar_consumed_bytes":self.sidecar_raw.len(),
            "membership_and_original_order_policy_scope":"held opaque identities only; no native-order meaning or fresh selector authority"})
    }
}
enum OwnedDisposition {
    Imported(source_action::MixedImportedCohort),
    Incomplete(source_action::MixedCaptureOutcome),
}
struct MixedDiagnosticDelivery {
    request: HeldRequest,
    disposition: OwnedDisposition,
    output: PathBuf,
    issues: Vec<String>,
    pending_observation: Option<Value>,
    refusal: OnceLock<String>,
}
impl MixedDiagnosticDelivery {
    fn check(&self) -> Result<()> {
        if let Some(reason)=self.refusal.get() { bail!("permanent mixed delivery refusal: {reason}"); }
        let result = self.request.check().and_then(|()| match &self.disposition {
            OwnedDisposition::Imported(cohort) => cohort.check_custody(),
            OwnedDisposition::Incomplete(outcome) => {
                if !matches!(outcome, source_action::MixedCaptureOutcome::Incomplete(_)) {
                    bail!("invalid owned incomplete disposition");
                }
                outcome.check_custody()
            },
        });
        if let Err(error)=result {
            let reason=error.to_string();
            let _=self.refusal.set(reason.clone());
            bail!("mixed delivery custody failed: {reason}");
        }
        Ok(())
    }
    fn wait_original(&mut self) {
        if let OwnedDisposition::Imported(cohort)=&mut self.disposition {
            if cohort.pending_process_count()!=0 {
                self.pending_observation=Some(cohort.wait_pending_original());
            }
        }
    }
    fn finalization_failure_preview(value: &str) -> Value {
        // This bounds metadata only. The complete original UTF-8 bytes are saved separately.
        let mut end = value.len().min(512);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        json!({
            "text": &value[..end],
            "preview_bytes": end,
            "full_text_bytes": value.len(),
            "preview_is_complete": end == value.len(),
        })
    }

    fn finalization_failure_text(
        receipt: &Path,
        relative_name: &str,
        value: &str,
    ) -> Result<Value> {
        // Borrow the full bytes. save_exclusive fsyncs and stream-compares the reopened file.
        save_exclusive(&receipt.with_file_name(relative_name), value.as_bytes())?;
        Ok(json!({
            "path": relative_name,
            "relative_to": "failure-index-directory",
            "bytes": value.len(),
            "sha256": format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(value.as_bytes())),
            "exclusive_saved_byte_readback_completed": true,
            "preview": Self::finalization_failure_preview(value),
        }))
    }

    fn finalization_failure_index(
        &self,
        phase: &str,
        error: &str,
        receipt: &Path,
        intended_receipt_raw: &[u8],
        receipt_publication_returned_ok: bool,
    ) -> Result<Value> {
        if receipt.file_name().and_then(|name| name.to_str())
            != Some("mixed-diagnostic-delivery.json")
        {
            bail!("unexpected mixed diagnostic delivery receipt basename");
        }
        let (error_name, refusal_name) = match phase {
            "receipt_publication" => (
                "mixed-diagnostic-publication-error.utf8",
                "mixed-diagnostic-publication-first-refusal.utf8",
            ),
            "post_publication_custody" => (
                "mixed-diagnostic-finalization-error.utf8",
                "mixed-diagnostic-finalization-first-refusal.utf8",
            ),
            _ => bail!("unsupported mixed diagnostic finalization failure phase"),
        };
        let error_reference = Self::finalization_failure_text(receipt, error_name, error)?;
        let first_permanent_refusal = match self.refusal.get() {
            Some(value) if value.as_bytes() == error.as_bytes() => Some(error_reference.clone()),
            Some(value) => Some(Self::finalization_failure_text(receipt, refusal_name, value)?),
            None => None,
        };
        Ok(json!({
            "schema": "ocore-runtime-mixed-diagnostic-finalization-failure-v2",
            "phase": phase,
            "error": error_reference,
            "first_permanent_refusal": first_permanent_refusal,
            "full_delivery_evidence": {
                "path": "mixed-diagnostic-delivery.json",
                "relative_to": "failure-index-directory",
                "bytes": intended_receipt_raw.len(),
                "sha256": format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(intended_receipt_raw)),
                "publication_returned_ok": receipt_publication_returned_ok,
                "reference_scope": "exact intended raw delivery/cohort evidence; verify referenced bytes before use",
            },
            "required_cli_outcome": "nonzero",
            "operation_complete": false,
            "artifact_complete": false,
            "runtime_complete": false,
            "native_execution_qualified": false,
            "native_order_meaning_checked": false,
        }))
    }

    fn finalization_failure_index_bytes(index: Value) -> Result<Vec<u8>> {
        // Serialize exactly once, then check the exact bytes that will be published.
        let raw = serde_json::to_vec_pretty(&index)?;
        if raw.len() > 8192 {
            bail!("mixed diagnostic failure index exceeds its 8192-byte metadata budget: {}", raw.len());
        }
        Ok(raw)
    }

    fn summary(&self) -> Value {
        let custody_safe=self.check().is_ok();
        let mut shared=self.request.shared();
        if let OwnedDisposition::Incomplete(source_action::MixedCaptureOutcome::Incomplete(owner))=&self.disposition {
            shared["incomplete_verifier_receipt"]=json!({
                "bytes":owner.raw_receipt().len(),
                "sha256":hash(owner.raw_receipt()),
                "scope":"exact raw receipt retained by the distinct incomplete owner"
            });
        }
        let shared_sha256=hash(&serde_json::to_vec(&shared).expect("serializable shared evidence"));
        let (kind,mut disposition)=match &self.disposition {
            OwnedDisposition::Imported(cohort)=>("mixed_llvm_import",cohort.summary()),
            OwnedDisposition::Incomplete(source_action::MixedCaptureOutcome::Incomplete(owner))=>
                ("incomplete_capture",owner.receipt().clone()),
            OwnedDisposition::Incomplete(_)=>
                ("invalid_owned_disposition",json!({"state":"refused","issues":["invalid owned incomplete disposition"]})),
        };
        // Attach only one digest per row; the complete table and policies stay shared.
        if let Some(rows)=disposition.get_mut("units").and_then(Value::as_array_mut) {
            for row in rows {
                if let Some(object)=row.as_object_mut() {
                    object.insert("delivery_shared_inputs_ref".into(),json!(shared_sha256));
                }
            }
        }
        json!({
            "schema":OUTPUT_FORMAT,
            "operation":"mixed LLVM diagnostic disposition",
            "exit_scope":"known CLI exit 0 records this diagnostic operation; individual phase results are separate and no complete artifact is qualified",
            "shared_inputs":shared,
            "shared_inputs_sha256":shared_sha256,
            "disposition_kind":kind,
            "disposition":disposition,
            "original_child_observation":self.pending_observation,
            "issues":self.issues,
            "custody_safe":custody_safe,
            "permanent_refusal":self.refusal.get(),
            "shared_reference_scope":"delivery_shared_inputs_ref resolves to this receipt's single shared_inputs table",
            "source_recipe_capture_performed":false,
            "native_order_meaning_checked":false,
            "source_function_attribution_qualified":false,
            "abi_qualified":false,
            "provider_closure_complete":false,
            "artifact_complete":false,
            "runtime_complete":false,
            "native_execution_qualified":false,
            "generated_application_source_inclusion_qualified":false,
            "receipt_finalization_requires_known_cli_exit_0_and_no_publication_or_finalization_failure":true
        })
    }
    fn finish_cli(mut self) -> Result<()> {
        // No fallible early return after a cohort is owned: retain and naturally
        // observe every original Child even on a permanent custody refusal.
        if let Err(error)=self.check() { self.issues.push(error.to_string()); }
        self.wait_original();
        if let Err(error)=self.check() { self.issues.push(error.to_string()); }
        let incomplete=matches!(&self.disposition,OwnedDisposition::Incomplete(_));
        let receipt=self.output.join("mixed-diagnostic-delivery.json");
        let raw=serde_json::to_vec_pretty(&self.summary())?;
        let publication=save_exclusive(&receipt,&raw);
        if let Err(error)=publication {
            let message=format!("mixed diagnostic receipt publication: {error}");
            let _=self.refusal.set(message.clone());
            self.issues.push(message.clone());
            let failure=self.finalization_failure_index(
                "receipt_publication",&message,&receipt,&raw,false);
            let failure_path=self.output.join("mixed-diagnostic-publication-failure.json");
            let saved=failure.and_then(Self::finalization_failure_index_bytes)
                .map_err(anyhow::Error::from)
                .and_then(|bytes|save_exclusive(&failure_path,&bytes));
            match saved {
                Ok(())=>bail!("{message}; failure index {}",failure_path.display()),
                Err(index_error)=>bail!("{message}; also failed to publish failure index {}: {index_error}",failure_path.display()),
            }
        }
        // Always retain this exact fresh Result. Incomplete outcomes and earlier
        // errors must not short-circuit the final guard or discard its error.
        let final_custody=self.check();
        if let Err(error)=final_custody {
            let message=format!("mixed diagnostic post-publication custody: {error}");
            let _=self.refusal.set(message.clone());
            self.issues.push(message.clone());
            let failure=self.finalization_failure_index(
                "post_publication_custody",&message,&receipt,&raw,true);
            let failure_path=self.output.join("mixed-diagnostic-finalization-failure.json");
            let saved=failure.and_then(Self::finalization_failure_index_bytes)
                .map_err(anyhow::Error::from)
                .and_then(|bytes|save_exclusive(&failure_path,&bytes));
            match saved {
                Ok(())=>bail!("{message}; failure index {}",failure_path.display()),
                Err(index_error)=>bail!("{message}; also failed to publish failure index {}: {index_error}",failure_path.display()),
            }
        }
        if incomplete || !self.issues.is_empty() {
            bail!("mixed diagnostic remains incomplete or refused; see {}",receipt.display());
        }
        eprintln!("olangc: recorded mixed LLVM diagnostic dispositions; no complete artifact qualified; receipt {}",receipt.display());
        Ok(())
    }
}
fn save_exclusive(path:&Path,raw:&[u8])->Result<()> {
    let mut file=OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(raw)?;
    file.sync_all()?;
    let before=NativeIdentity::of(&file.metadata()?)?;
    let mut reopened=File::open(path)?;
    let mut position=0usize;
    let mut buffer=[0u8;65536];
    loop {
        let count=reopened.read(&mut buffer)?;
        if count==0 { break; }
        if position.checked_add(count).is_none() || position+count>raw.len()
            || raw[position..position+count]!=buffer[..count] {
            bail!("mixed diagnostic publication readback differs");
        }
        position+=count;
    }
    if position!=raw.len() || NativeIdentity::of(&reopened.metadata()?)?!=before
        || NativeIdentity::of(&fs::metadata(path)?)?!=before {
        bail!("mixed diagnostic publication native identity/readback differs");
    }
    if let Some(parent)=path.parent() { File::open(parent)?.sync_all()?; }
    Ok(())
}
/// The normal CLI caller consumes an owning prior-policy request and keeps the
/// disposition/Child owner until known diagnostic publication or retained refusal.
pub(crate) fn compile_runtime_mixed_diagnostic(
    report:&Path,sidecar:&Path,target:&str,output_kind:&str,output:&Path,
    import_options:NativeImportOptions<'_>,source_options:NativeSourceOptions<'_>,
)->Result<()> {
    if output_kind!="mixed-diagnostic" {
        bail!("held mixed inputs require --native-runtime-output mixed-diagnostic; ordinary ir/obj and complete-artifact delivery are not implemented by this operation");
    }
    if source_options.requested() {
        bail!("mixed diagnostic consumes an existing genuine report and prior held policy; fresh source/provider options require an independently held pre-capture context capability");
    }
    super::super::architecture(target)?;
    let mut request=HeldRequest::hold(report,sidecar)?;
    let library=&request.guards["inventory_library"];
    match (import_options.llvm_library,import_options.llvm_sha256) {
        (None,None)=>{},
        (Some(path),Some(sha)) if path.canonicalize()?==library.physical
            && sha==library.expected.sha256.as_str()=>{},
        _=>bail!("explicit LLVM import options must match the externally selected inventory/parser library pin"),
    }
    request.check()?;
    fs::create_dir(output).with_context(||format!("mixed diagnostic output must be a new directory: {}",output.display()))?;
    let output=output.canonicalize()?;
    let capture_output=output.join("capture-reverification");
    let policy=request.policy.take().expect("held policy consumed once");
    let outcome=super::super::observe_held_mixed_capture_with_python(
        &request.guards["report"].expected.path,&request.report_raw,&capture_output,
        &request.guards["python"].expected.path,policy)?;
    // No import effects until the caller-selected inputs still agree after
    // independent journal reconstruction.
    request.check()?;
    let disposition=match outcome {
        source_action::MixedCaptureOutcome::Reconstructed(stage)=>{
            let compiler=request.guards["compiler"].tool_pin();
            let python=request.guards["inventory_python"].tool_pin();
            let library=request.guards["inventory_library"].tool_pin();
            let effective=NativeImportOptions {
                llvm_library:Some(&library.path),llvm_sha256:Some(&library.sha256),
                tls_profile:import_options.tls_profile,atomic_profile:import_options.atomic_profile,
                wide_volatile_profile:import_options.wide_volatile_profile,
                linux_syscall_profile:import_options.linux_syscall_profile,
                dependencies:import_options.dependencies,
            };
            OwnedDisposition::Imported(source_action::import_mixed_llvm_stage(
                stage,target,&output.join("mixed-llvm-import"),effective,
                &compiler,&python,&library))
        },
        incomplete @ source_action::MixedCaptureOutcome::Incomplete(_)=>
            OwnedDisposition::Incomplete(incomplete),
    };
    // From this point every error remains in the owner; no ? drops a Child.
    let mut delivery=MixedDiagnosticDelivery {request,disposition,output,
        issues:Vec::new(),pending_observation:None,refusal:OnceLock::new()};
    if let Err(error)=delivery.check() { delivery.issues.push(error.to_string()); }
    delivery.finish_cli()
}
