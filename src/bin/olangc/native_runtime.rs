//! Compile every captured foreign unit through the verified O-core import boundary.
//! Unit lowering, symbol closure and native runtime qualification are separate facts.

use anyhow::{bail, Context, Result};
use o_lang::ocore::native_ir::{
    AtomicProfile, NativeModule, Signature, TlsProfile, Type, Visibility,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CAPTURE_FORMAT: &str = "ocore-runtime-capture-v1";
const RECEIPT_FORMAT: &str = "ocore-runtime-lowering-v1";

#[cfg(test)]
#[path = "native_runtime/object_inventory_tests.rs"]
mod object_inventory_tests;

#[path = "native_runtime/exception_inventory.rs"]
mod exception_inventory;

#[path = "native_runtime/tls_inventory.rs"]
mod tls_inventory;

#[cfg(test)]
#[path = "native_runtime/exception_tests.rs"]
mod exception_tests;

#[cfg(test)]
#[path = "native_runtime/atomic_tests.rs"]
mod atomic_tests;

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn architecture(target: &str) -> Result<&'static str> {
    match target {
        "x86_64" | "x86_64-unknown-none" | "x86_64-unknown-none-elf" => Ok("x86_64"),
        "aarch64" | "aarch64-unknown-none" | "aarch64-unknown-none-elf" => Ok("aarch64"),
        "riscv64"
        | "riscv64-unknown-none"
        | "riscv64-unknown-none-elf"
        | "riscv64gc-unknown-none-elf" => Ok("riscv64"),
        _ => bail!("unsupported native ISA {target:?}"),
    }
}

fn array<'a>(object: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    object
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("capture field {field:?} must be an array"))
}

fn string<'a>(object: &'a Value, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("capture field {field:?} must be a string"))
}

fn checked_evidence(record: &Value) -> Result<Vec<u8>> {
    let path = Path::new(string(record, "path")?);
    if !path.is_absolute() {
        bail!("evidence path must be absolute");
    }
    let bytes = fs::read(path).with_context(|| format!("read evidence {}", path.display()))?;
    if digest(&bytes) != string(record, "sha256")?
        || record["bytes"].as_u64() != Some(bytes.len() as u64)
    {
        bail!("evidence hash/size mismatch: {}", path.display());
    }
    Ok(bytes)
}

/// Independently recheck the exact runtime/probe partition before skipping units.
fn lowering_partition(capture: &Value) -> Result<BTreeSet<String>> {
    if capture["unit_roles_complete"] != true
        || !array(capture, "unclassified_unit_ids")?.is_empty()
    {
        bail!("captured unit roles are incomplete");
    }
    let inventory = &capture["unit_inventory"];
    let actual: Value = serde_json::from_slice(&checked_evidence(&inventory["file"])?)?;
    if actual != inventory["definition"]
        || actual["schema"] != "ocore-runtime-unit-inventory-v1"
        || actual["complete"] != true
        || array(&actual, "units")?.is_empty()
    {
        bail!("build inventory definition differs from its bound artifact");
    }
    let known: BTreeSet<_> = array(capture, "units")?
        .iter()
        .map(|unit| string(unit, "id").map(str::to_owned))
        .collect::<Result<_>>()?;
    let mut selected = BTreeSet::new();
    for id in array(capture, "lowering_unit_ids")? {
        let id = id.as_str().context("lowering unit ID must be a string")?;
        if !known.contains(id) || !selected.insert(id.to_owned()) {
            bail!("unknown or duplicate lowering unit ID: {id}");
        }
    }
    if selected.is_empty() {
        bail!("capture has no required lowering units");
    }
    let required: BTreeSet<_> = array(capture, "required_units")?
        .iter()
        .flat_map(|item| item["captured_unit_ids"].as_array().into_iter().flatten())
        .map(|id| {
            id.as_str()
                .map(str::to_owned)
                .context("required unit ID must be a string")
        })
        .collect::<Result<_>>()?;
    if !selected.is_subset(&required) {
        bail!("lowering selection is outside the required source inventory");
    }
    let rules = actual["non_lowering_units"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut rule_ids = BTreeSet::new();
    for rule in &rules {
        if !rule_ids.insert(string(rule, "id")?) {
            bail!("duplicate non-lowering rule ID");
        }
    }
    let mut assigned = selected.clone();
    let mut glob_checks = Vec::new();
    let mut checked_files = BTreeSet::new();
    let mut recheck = |record: &Value| -> Result<()> {
        let key = (
            string(record, "path")?.to_owned(),
            string(record, "sha256")?.to_owned(),
            record["bytes"]
                .as_u64()
                .context("evidence byte count missing")?,
        );
        if checked_files.insert(key) {
            checked_evidence(record)?;
        }
        Ok(())
    };
    for excluded in array(capture, "non_lowering_units")? {
        let id = string(excluded, "unit_id")?;
        if !known.contains(id) || !assigned.insert(id.to_owned()) {
            bail!("unknown, duplicate or conflicting non-lowering unit: {id}");
        }
        let role = string(excluded, "role")?;
        if !matches!(role, "configure_probe" | "host_build_tool") {
            bail!("unsupported non-lowering role: {role}");
        }
        let rule = rules
            .iter()
            .find(|rule| rule["id"] == excluded["rule_id"])
            .context("non-lowering unit has no bound inventory rule")?;
        let evidence = &excluded["evidence"];
        if rule["role"] != excluded["role"]
            || rule["evidence"]["reason"] != evidence["reason"]
            || string(evidence, "reason")?.trim().is_empty()
            || evidence["inventory"] != inventory["file"]
        {
            bail!("non-lowering unit evidence differs from inventory rule");
        }
        let artifacts = array(evidence, "artifacts")?;
        let declared_artifacts = array(&rule["evidence"], "artifacts")?;
        if artifacts.is_empty() || artifacts.len() != declared_artifacts.len() {
            bail!("non-lowering unit lacks complete artifact evidence");
        }
        for (artifact, declared) in artifacts.iter().zip(declared_artifacts) {
            if artifact["path"] != declared["path"] || artifact["sha256"] != declared["sha256"] {
                bail!("non-lowering artifact differs from bound inventory");
            }
            recheck(artifact)?;
        }
        let step = &evidence["build_step"];
        let step_index = usize::try_from(
            step["index"]
                .as_u64()
                .context("non-lowering build step lacks an index")?,
        )?;
        let original = array(capture, "build_steps")?
            .get(step_index)
            .context("non-lowering build step is missing")?;
        if ["name", "argv", "cwd", "exit_code"]
            .iter()
            .any(|field| step[*field] != original[*field])
            || step["log"]["path"] != original["log"]
            || step["exit_code"] != 0
        {
            bail!("non-lowering build step differs from recorded execution");
        }
        recheck(&step["log"])?;
        let owner = array(capture, "invocations")?
            .iter()
            .find(|event| {
                event["units"]
                    .as_array()
                    .is_some_and(|units| units.iter().any(|unit| unit["id"] == id))
            })
            .context("non-lowering unit has no compiler invocation")?;
        let start = owner["started_ns"]
            .as_u64()
            .context("invocation start missing")?;
        let end = owner["finished_ns"]
            .as_u64()
            .context("invocation completion missing")?;
        if start > end
            || start
                < original["started_ns"]
                    .as_u64()
                    .context("build start missing")?
            || end
                > original["finished_ns"]
                    .as_u64()
                    .context("build completion missing")?
        {
            bail!("non-lowering compiler call is outside the bound build step");
        }
        if let Some(ids) = rule["unit_ids"].as_array() {
            if !ids.iter().any(|candidate| candidate == id) {
                bail!("excluded unit not selected by inventory rule");
            }
        } else {
            let unit = array(capture, "units")?
                .iter()
                .find(|unit| unit["id"] == id)
                .unwrap();
            if rule["kind"] != unit["kind"] || rule["build_step"] != step["name"] {
                bail!("excluded unit kind/build step differs from inventory selector");
            }
            let path = Path::new(string(&unit["source"], "path")?);
            let root = Path::new(string(&capture["source"], "path")?);
            let source = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_str()
                .context("non-UTF8 unit path")?;
            glob_checks.push(json!([source, string(rule, "source")?]));
        }
    }
    if assigned != known {
        bail!("unit role partition does not cover the complete captured inventory");
    }
    if !glob_checks.is_empty() {
        use std::io::Write;
        let mut child = Command::new("python3").args(["-I", "-c",
            "import fnmatch,json,sys; pairs=json.load(sys.stdin); sys.exit(0 if all(fnmatch.fnmatchcase(s,p) for s,p in pairs) else 1)"])
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).spawn()?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&glob_checks)?)?;
        if !child.wait()?.success() {
            bail!("non-lowering source selectors do not match their units");
        }
    }
    Ok(selected)
}

fn capture_admission(capture: &Value) -> Result<BTreeSet<String>> {
    if capture.get("schema").and_then(Value::as_str) != Some(CAPTURE_FORMAT) {
        bail!("expected {CAPTURE_FORMAT}");
    }
    if capture.get("capture_complete") != Some(&Value::Bool(true)) {
        bail!("source-unit capture is incomplete");
    }
    if capture.get("unit_inventory_complete") != Some(&Value::Bool(true)) {
        bail!("complete build-generated unit inventory is required");
    }
    if !array(capture, "issues")?.is_empty()
        || !array(capture, "failed_required_units")?.is_empty()
        || !array(capture, "uncaptured_outputs")?.is_empty()
    {
        bail!("capture contains failures or uncaptured outputs");
    }
    let units = array(capture, "units")?;
    if units.is_empty() {
        bail!("capture has no LLVM units");
    }
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for unit in units {
        let id = string(unit, "id")?;
        if !ids.insert(id) || !paths.insert(string(&unit["ir"], "path")?) {
            bail!("duplicate captured unit identity or artifact path: {id}");
        }
        captured_ir_format(&unit["ir"])
            .with_context(|| format!("captured IR representation for {id}"))?;
    }
    let requirements = array(capture, "required_units")?;
    if requirements.is_empty() {
        bail!("capture has no required source-unit inventory");
    }
    for requirement in requirements {
        if requirement["complete"] != true
            || !array(requirement, "failed_invocation_ids")?.is_empty()
        {
            bail!("required unit is incomplete: {}", requirement["id"]);
        }
        let captured = array(requirement, "captured_unit_ids")?;
        if captured.is_empty()
            || captured
                .iter()
                .any(|id| id.as_str().is_none_or(|id| !ids.contains(id)))
        {
            bail!(
                "required unit refers to missing LLVM artifacts: {}",
                requirement["id"]
            );
        }
    }
    let mut invocation_units = BTreeMap::new();
    for invocation in array(capture, "invocations")? {
        if invocation["state"] != "finished" || !array(invocation, "capture_errors")?.is_empty() {
            bail!(
                "unfinished or failed compiler capture: {}",
                invocation["id"]
            );
        }
        for unit in array(invocation, "units")? {
            if unit.get("ir").is_some() {
                let id = string(unit, "id")?;
                if invocation_units.insert(id, unit).is_some() {
                    bail!("duplicate invocation unit identity: {id}");
                }
            }
        }
    }
    if invocation_units.len() != units.len()
        || units.iter().any(|unit| {
            unit["id"]
                .as_str()
                .and_then(|id| invocation_units.get(id))
                .is_none_or(|record| *record != unit)
        })
    {
        bail!("capture unit list does not match the complete compiler invocation inventory");
    }
    lowering_partition(capture)
}

/// Reconstruct the partition from the original journal and hashed build artifacts.
/// The embedded verifier only reads evidence; it never reruns the runtime build.
fn reverify_capture(report: &Path, bytes: &[u8], output: &Path) -> Result<Value> {
    use std::io::Write;
    let source = include_str!("../../../scripts/ocore_runtime_capture.py");
    // Keep argv bounded even as the verifier grows. The exact original report
    // bytes and trusted source travel as distinct JSON values over stdin.
    let program = "import json,sys\npayload=json.load(sys.stdin)\nnamespace={'__name__':'ocore_capture_readmission'}\nexec(payload['source'],namespace)\nprint(json.dumps(namespace['verify_report'](payload['report'],expected_worker_sha256=payload['worker_sha256'])))\n";
    let prefix = format!(
        "{{\"source\":{},\"worker_sha256\":{},\"report\":",
        serde_json::to_string(source)?,
        serde_json::to_string(&digest(source.as_bytes()))?
    );
    let mut child = Command::new("python3")
        .args(["-I", "-c", program])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("launch embedded capture evidence verifier")?;
    let write = (|| -> std::io::Result<()> {
        let mut input = child.stdin.take().expect("piped capture verifier stdin");
        input.write_all(prefix.as_bytes())?;
        input.write_all(bytes)?;
        input.write_all(b"}")
    })();
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
        return Err(error).context(format!("stream capture evidence verifier; {diagnostic}"));
    }
    let result = child.wait_with_output()?;
    fs::write(output.join("capture-reverification.log"), &result.stderr)?;
    if !result.status.success() {
        bail!(
            "capture reconstruction failed ({}): {}",
            result.status,
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    let receipt: Value = serde_json::from_slice(&result.stdout)
        .context("decode independent capture reconstruction receipt")?;
    if receipt["schema"] != "ocore-runtime-capture-verification-v1" || receipt["verified"] != true {
        bail!("capture reconstruction receipt does not bind the admitted report");
    }
    let mut receipt = receipt;
    receipt["admitted_report"] = json!({"path":report,"sha256":digest(bytes),"bytes":bytes.len()});
    fs::write(
        output.join("capture-reverification.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    Ok(receipt)
}

#[cfg(test)]
fn capture_issues(capture: &Value) -> Vec<String> {
    capture_admission(capture)
        .err()
        .into_iter()
        .map(|error| error.to_string())
        .collect()
}

fn captured_ir_format(ir: &Value) -> Result<&str> {
    match string(ir, "format")? {
        format @ ("llvm-text" | "llvm-bitcode") => Ok(format),
        format => bail!("unsupported captured IR representation: {format}"),
    }
}

fn checked_ir(unit: &Value, arch: &str) -> Result<PathBuf> {
    let ir = &unit["ir"];
    let format = captured_ir_format(ir)?;
    let path = PathBuf::from(string(ir, "path")?);
    if !path.is_absolute() {
        bail!("captured LLVM paths must be absolute: {}", path.display());
    }
    let bytes =
        fs::read(&path).with_context(|| format!("read captured LLVM unit {}", path.display()))?;
    if digest(&bytes) != string(ir, "sha256")? {
        bail!("captured LLVM digest mismatch: {}", path.display());
    }
    if ir["bytes"].as_u64() != Some(bytes.len() as u64) {
        bail!("captured LLVM size mismatch: {}", path.display());
    }
    let bitcode = bytes.starts_with(b"BC\xc0\xde") || bytes.starts_with(b"\xde\xc0\x17\x0b");
    if (format == "llvm-bitcode") != bitcode {
        bail!(
            "captured LLVM representation differs from its bytes: {}",
            path.display()
        );
    }
    let triple = string(ir, "target_triple")?;
    if triple.split('-').next() != Some(arch) {
        bail!("frontend target {triple:?} cannot be retargeted to {arch}");
    }
    if string(ir, "data_layout")?.is_empty() {
        bail!("captured LLVM DataLayout is missing");
    }
    Ok(path)
}

fn type_contract(module: &NativeModule, id: usize, active: &mut BTreeSet<usize>) -> Result<Value> {
    if !active.insert(id) {
        bail!("recursive ABI type lacks a canonical layout contract");
    }
    let ty = module.types.get(id).context("invalid ABI type index")?;
    let result = match ty {
        Type::Void => json!({"kind":"void"}),
        Type::Metadata {} => json!({"kind":"metadata"}),
        Type::Int { bits } => json!({"kind":"int", "bits":bits}),
        Type::Float { bits } => json!({"kind":"float", "bits":bits}),
        Type::Pointer { address_space } => json!({"kind":"pointer", "address_space":address_space}),
        Type::Array { element, len } => {
            json!({"kind":"array", "len":len, "element":type_contract(module,*element,active)?})
        }
        Type::Struct { fields, packed } => {
            let fields: Result<Vec<_>> = fields
                .iter()
                .map(|id| type_contract(module, *id, active))
                .collect();
            json!({"kind":"struct", "packed":packed, "fields":fields?})
        }
        Type::Function { signature } => signature_contract(module, signature, active)?,
    };
    active.remove(&id);
    Ok(result)
}

fn signature_contract(
    module: &NativeModule,
    signature: &Signature,
    active: &mut BTreeSet<usize>,
) -> Result<Value> {
    let parameters: Result<Vec<_>> = signature
        .params
        .iter()
        .map(|id| type_contract(module, *id, active))
        .collect();
    let attributes: Vec<Vec<String>> = (0..signature.params.len())
        .map(|index| {
            let mut attributes = signature
                .param_attributes
                .get(index)
                .cloned()
                .unwrap_or_default();
            attributes.sort();
            attributes
        })
        .collect();
    let mut result_attributes = signature.result_attributes.clone();
    result_attributes.sort();
    let return_storage = signature
        .return_storage
        .as_ref()
        .map(|storage| {
            Ok::<_, anyhow::Error>(json!({"param":storage.param,
            "ty":storage_contract(module, storage.ty, active)?}))
        })
        .transpose()?;
    Ok(
        json!({"kind":"function", "params":parameters?, "result":type_contract(module,signature.result,active)?,
              "abi":signature.abi, "variadic":signature.variadic, "param_attributes":attributes,
              "result_attributes":result_attributes, "return_storage":return_storage}),
    )
}

/// Return-storage ABI identity includes memory layout, not module-local type
/// indices or the spelling of an otherwise equivalent LLVM DataLayout.
fn storage_contract(
    module: &NativeModule,
    id: usize,
    active: &mut BTreeSet<usize>,
) -> Result<Value> {
    use o_lang::ocore::native_verify::{type_alignment, type_size};
    if !active.insert(id) {
        bail!("recursive return-storage type lacks a canonical layout contract");
    }
    let size = type_size(module, id)?;
    let alignment = type_alignment(module, id)?;
    let ty = module
        .types
        .get(id)
        .context("invalid return-storage type index")?;
    let shape = match ty {
        Type::Array { element, len } => json!({"kind":"array", "len":len,
            "element":storage_contract(module,*element,active)?}),
        Type::Struct { fields, packed } => {
            let fields: Result<Vec<_>> = fields
                .iter()
                .map(|id| storage_contract(module, *id, active))
                .collect();
            json!({"kind":"struct", "packed":packed, "fields":fields?})
        }
        Type::Int { bits } => json!({"kind":"int", "bits":bits}),
        Type::Float { bits } => json!({"kind":"float", "bits":bits}),
        Type::Pointer { address_space } => json!({"kind":"pointer", "address_space":address_space}),
        Type::Void | Type::Metadata {} | Type::Function { .. } => {
            bail!("unsized return-storage type")
        }
    };
    active.remove(&id);
    Ok(json!({"shape":shape,"size":size,"alignment":alignment}))
}

#[derive(Clone, Debug)]
struct Symbol {
    unit: String,
    name: String,
    linkage: String,
    visibility: Visibility,
    definition: bool,
    contract: Value,
    alignment: u64,
    intrinsic: Option<String>,
    alias_of: Option<String>,
    comdat: Option<GroupMembership>,
    references: BTreeSet<String>,
    /// Source metadata ABI adaptation or an explicit compiler-generated helper
    /// interface. The original native module and signature remain unchanged.
    abi_adaptation: Option<Value>,
}

fn itanium_personality_contract() -> Value {
    json!({"kind":"function", "params":[{"kind":"int","bits":32},{"kind":"int","bits":32},
        {"kind":"int","bits":64},{"kind":"pointer","address_space":0},{"kind":"pointer","address_space":0}],
        "result":{"kind":"int","bits":32},"abi":"c","variadic":false,
        "param_attributes":[[],[],[],[],[]],"result_attributes":[],"return_storage":null})
}

fn itanium_resume_contract() -> Value {
    json!({"kind":"function", "params":[{"kind":"pointer","address_space":0}],
        "result":{"kind":"void"},"abi":"c","variadic":false,
        "param_attributes":[[]],"result_attributes":[],"return_storage":null})
}

fn requires_unwind_resume(module: &NativeModule) -> bool {
    module
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .any(|block| {
            matches!(
                block.terminator,
                o_lang::ocore::native_ir::Terminator::Resume { .. }
            )
        })
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct GroupMembership {
    name: String,
    selection: o_lang::ocore::native_ir::ComdatSelection,
}

fn group_membership(module: &NativeModule, name: Option<&str>) -> Result<Option<GroupMembership>> {
    name.map(|name| {
        let group = module
            .comdats
            .iter()
            .find(|group| group.name == name)
            .with_context(|| format!("missing verified COMDAT group {name}"))?;
        Ok(GroupMembership {
            name: name.into(),
            selection: group.selection,
        })
    })
    .transpose()
}

fn symbols(id: &str, module: &NativeModule) -> Result<Vec<Symbol>> {
    let mut result = Vec::new();
    let metadata_personalities =
        o_lang::ocore::native_eh::metadata_personality_declarations(module);
    for function in &module.functions {
        let original_contract =
            signature_contract(module, &function.signature, &mut BTreeSet::new())?;
        let metadata_personality = metadata_personalities.contains(&function.name);
        let noalias_declaration =
            function.intrinsic.as_deref() == Some(o_lang::ocore::native_ir::NOALIAS_SCOPE_DECL);
        result.push(Symbol {
            unit: id.into(),
            name: function.name.clone(),
            linkage: function.linkage.clone(),
            visibility: function.visibility,
            definition: function.entry.is_some(),
            alignment: function.alignment,
            intrinsic: function.intrinsic.clone(),
            alias_of: None,
            comdat: group_membership(module, function.comdat.as_deref())?,
            references: function_references(function),
            contract: if metadata_personality {
                itanium_personality_contract()
            } else {
                original_contract.clone()
            },
            abi_adaptation: if noalias_declaration {
                Some(json!({"kind":"noalias_scope_decl_metadata_declaration",
                    "original_contract":original_contract,
                    "runtime_abi_required":false,"native_symbol_required":false,
                    "alias_promises_used_for_optimization":false}))
            } else {
                metadata_personality.then(|| {
                    json!({"kind":"itanium_personality_metadata_declaration",
                    "profile":"itanium_dwarf_v1", "original_contract":original_contract,
                    "ordinary_variadic_calls_supported":false})
                })
            },
        });
    }
    for global in &module.globals {
        result.push(Symbol { unit:id.into(), name:global.name.clone(), linkage:global.linkage.clone(), visibility:global.visibility, intrinsic:None, alias_of:None,
            comdat:group_membership(module,global.comdat.as_deref())?,
            references:global.initializer.iter().flat_map(|init| init.relocations.iter().flat_map(|relocation|
                std::iter::once(relocation.symbol.clone()).chain(relocation.relative_to.iter().cloned()))).collect(),
            definition:global.initializer.is_some(), alignment:if global.alignment == 0 {
                o_lang::ocore::native_verify::type_alignment(module, global.ty)?
            } else { global.alignment },
            abi_adaptation:global.thread_local.then(|| json!({
                "kind":"static_nonpreemptive_tls_realization", "profile":module.target.tls_profile,
                "source_access_model":global.tls_model,"native_access_model":"local_exec",
                "static_image_binding_required":true,"tls_platform_execution_qualified":false})),
            contract:json!({"kind":"global", "type":type_contract(module,global.ty,&mut BTreeSet::new())?,
                           "constant":global.constant, "thread_local":global.thread_local}) });
    }
    for alias in &module.aliases {
        let mut symbol = result
            .iter()
            .find(|symbol| symbol.name == alias.aliasee)
            .with_context(|| format!("alias {} has no included direct provider", alias.name))?
            .clone();
        symbol.name = alias.name.clone();
        symbol.linkage = alias.linkage.clone();
        symbol.visibility = alias.visibility;
        symbol.alias_of = Some(alias.aliasee.clone());
        result.push(symbol);
    }
    if requires_unwind_resume(module) {
        result.push(Symbol {
            unit: id.into(),
            name: "_Unwind_Resume".into(),
            linkage: "external".into(),
            visibility: Visibility::Default,
            definition: false,
            contract: itanium_resume_contract(),
            alignment: 0,
            intrinsic: None,
            alias_of: None,
            comdat: None,
            references: BTreeSet::new(),
            abi_adaptation: Some(
                json!({"kind":"compiler_generated_interface", "profile":"itanium_dwarf_v1",
                "source_operation":"resume", "source_function_inventory_changed":false}),
            ),
        });
    }
    Ok(result)
}

fn function_references(function: &o_lang::ocore::native_ir::Function) -> BTreeSet<String> {
    use o_lang::ocore::native_ir::{Operand, Operation, Terminator};
    let mut references = BTreeSet::new();
    let mut tls_references = BTreeSet::new();
    fn constant_references(value: &Operand, references: &mut BTreeSet<String>) {
        let mut pending = vec![value];
        while let Some(value) = pending.pop() {
            match value {
                Operand::Symbol { name, .. } | Operand::SymbolOffset { name, .. } => {
                    references.insert(name.clone());
                }
                Operand::Aggregate { elements, .. } => pending.extend(elements),
                _ => {}
            }
        }
    }
    let mut operand = |value: &Operand| constant_references(value, &mut references);
    if let Some(eh) = &function.exception_handling {
        operand(&eh.personality);
    }
    for block in &function.blocks {
        for instruction in &block.instructions {
            match &instruction.operation {
                Operation::Assume { condition } => operand(condition),
                Operation::Lifetime { pointer, .. }
                | Operation::Load { pointer, .. }
                | Operation::AtomicLoad { pointer, .. } => operand(pointer),
                Operation::MemorySet {
                    destination,
                    value,
                    length,
                    ..
                } => {
                    operand(destination);
                    operand(value);
                    operand(length);
                }
                Operation::MemoryCopy {
                    destination,
                    source,
                    length,
                    ..
                } => {
                    operand(destination);
                    operand(source);
                    operand(length);
                }
                Operation::Binary { lhs, rhs, .. }
                | Operation::IntegerOverflow { lhs, rhs, .. }
                | Operation::IntegerMinMax { lhs, rhs, .. }
                | Operation::ICmp { lhs, rhs, .. } => {
                    operand(lhs);
                    operand(rhs);
                }
                Operation::Cast { value, .. } | Operation::Freeze { value } => operand(value),
                Operation::ExtractValue { aggregate, .. } => operand(aggregate),
                Operation::InsertValue {
                    aggregate, value, ..
                } => {
                    operand(aggregate);
                    operand(value);
                }
                Operation::Select {
                    condition,
                    on_true,
                    on_false,
                } => {
                    operand(condition);
                    operand(on_true);
                    operand(on_false);
                }
                Operation::Trap {}
                | Operation::Alloca { .. }
                | Operation::AtomicFence { .. }
                | Operation::NoAliasScopeDecl { .. } => {}
                Operation::ThreadLocalAddress { global } => {
                    tls_references.insert(global.clone());
                }
                Operation::Gep { base, offset, .. } => {
                    operand(base);
                    operand(offset);
                }
                Operation::Store { pointer, value, .. }
                | Operation::AtomicStore { pointer, value, .. }
                | Operation::AtomicRmw { pointer, value, .. } => {
                    operand(pointer);
                    operand(value);
                }
                Operation::AtomicCompareExchange {
                    pointer,
                    expected,
                    replacement,
                    ..
                } => {
                    operand(pointer);
                    operand(expected);
                    operand(replacement);
                }
                Operation::Call { callee, args, .. } => {
                    operand(callee);
                    for arg in args {
                        operand(arg);
                    }
                }
                Operation::LandingPad { clauses, .. } => {
                    for clause in clauses {
                        match clause {
                            o_lang::ocore::native_ir::ExceptionClause::Catch { typeinfo } => {
                                operand(typeinfo)
                            }
                            o_lang::ocore::native_ir::ExceptionClause::Filter { typeinfos } => {
                                for typeinfo in typeinfos {
                                    operand(typeinfo);
                                }
                            }
                        }
                    }
                }
                Operation::EhTypeId { typeinfo } => operand(typeinfo),
                Operation::Phi { incoming } => {
                    for edge in incoming {
                        operand(&edge.value);
                    }
                }
            }
        }
        match &block.terminator {
            Terminator::Invoke { callee, args, .. } => {
                operand(callee);
                for arg in args {
                    operand(arg);
                }
            }
            Terminator::Resume { value } => operand(value),
            Terminator::Return { value } => {
                if let Some(value) = value {
                    operand(value);
                }
            }
            Terminator::Branch { condition, .. } | Terminator::Switch { condition, .. } => {
                operand(condition)
            }
            Terminator::Jump { .. } | Terminator::Unreachable => {}
        }
    }
    references.extend(tls_references);
    if function
        .blocks
        .iter()
        .any(|block| matches!(block.terminator, Terminator::Resume { .. }))
    {
        references.insert("_Unwind_Resume".into());
    }
    references
}

fn resolve_symbols(symbols: &[Symbol]) -> (Value, Vec<String>) {
    use o_lang::ocore::native_ir::ComdatSelection;
    let mut issues = Vec::new();
    let mut groups: BTreeMap<&str, Vec<(&str, ComdatSelection)>> = BTreeMap::new();
    for symbol in symbols {
        if let Some(group) = &symbol.comdat {
            let candidates = groups.entry(&group.name).or_default();
            let candidate = (symbol.unit.as_str(), group.selection);
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
    }
    let mut retained_groups = BTreeSet::new();
    let mut group_resolutions = Vec::new();
    for (name, candidates) in &groups {
        let uniform = candidates
            .iter()
            .all(|candidate| candidate.1 == candidates[0].1);
        let selection = uniform.then_some(candidates[0].1);
        let compatible = candidates.iter().all(|candidate| {
            matches!(
                candidate.1,
                ComdatSelection::Any | ComdatSelection::NoDeduplicate
            )
        });
        if !compatible {
            issues.push(format!("incompatible COMDAT selection contracts: {name}"));
        }
        // ELF groups without GRP_COMDAT do not participate in signature-key
        // deduplication. They remain even when an Any group uses the same key.
        let mut selected_units = Vec::new();
        let mut selected_any = false;
        if compatible {
            for (unit, kind) in candidates {
                if *kind == ComdatSelection::NoDeduplicate || !selected_any {
                    selected_units.push(*unit);
                }
                selected_any |= *kind == ComdatSelection::Any;
            }
        }
        for unit in &selected_units {
            retained_groups.insert((*unit, *name));
        }
        group_resolutions.push(json!({"group":name,"selection":selection,"compatible":compatible,
            "candidates":candidates.iter().map(|(unit,kind)| json!({"unit":unit,"selection":kind,
                "members":symbols.iter().filter(|symbol| symbol.unit == *unit && symbol.comdat.as_ref().is_some_and(|group| group.name == *name))
                    .map(|symbol| &symbol.name).collect::<Vec<_>>()})).collect::<Vec<_>>(),
            "selected_units":selected_units,"rule":match selection {
                Some(ComdatSelection::Any) => "first whole group in supplied module order",
                Some(ComdatSelection::NoDeduplicate) => "retain every group without deduplication",
                _ => "retain every non-deduplicating group and the first any group",
            }}));
    }
    let retained = |symbol: &Symbol| {
        symbol.comdat.as_ref().is_none_or(|group| {
            retained_groups.contains(&(symbol.unit.as_str(), group.name.as_str()))
        })
    };
    let mut definitions: BTreeMap<&str, Vec<&Symbol>> = BTreeMap::new();
    // A static image combines each external reference's visibility constraint;
    // a hidden declaration may resolve to a default-visibility definition.
    let mut image_visibility = BTreeMap::new();
    for symbol in symbols.iter().filter(|symbol| {
        !matches!(symbol.linkage.as_str(), "internal" | "private") && symbol.intrinsic.is_none()
    }) {
        let rank = match symbol.visibility {
            Visibility::Default => 0,
            Visibility::Protected => 1,
            Visibility::Hidden => 2,
        };
        image_visibility
            .entry(symbol.name.as_str())
            .and_modify(|current: &mut u8| *current = (*current).max(rank))
            .or_insert(rank);
    }
    for symbol in symbols.iter().filter(|symbol| {
        symbol.definition && !matches!(symbol.linkage.as_str(), "internal" | "private")
    }) {
        definitions.entry(&symbol.name).or_default().push(symbol);
    }
    let mut selected = BTreeMap::new();
    let mut resolutions = Vec::new();
    for (name, candidates) in &definitions {
        // This is the explicitly supplied module order, not an inference about
        // archive extraction or the original frontend's complete link command.
        // All bodies and storage remain in the included module inventory.
        let active: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|candidate| retained(candidate))
            .collect();
        let strong: Vec<_> = active
            .iter()
            .copied()
            .filter(|candidate| candidate.linkage == "external")
            .collect();
        let supported = candidates.iter().all(|candidate| {
            matches!(
                candidate.linkage.as_str(),
                "external" | "weak" | "linkonce" | "linkonce_odr" | "weak_odr"
            )
        });
        let winner = if !supported || strong.len() > 1 {
            issues.push(format!(
                "multiple exported definitions require explicit linkage resolution: {name}"
            ));
            None
        } else {
            strong.first().copied().or_else(|| active.first().copied())
        };
        // Even an overridden definition may contain calls/accesses compiled
        // under its original signature or storage alignment. The selected
        // provider must satisfy those contracts as well as declarations.
        let compatible = winner.is_some_and(|winner| {
            candidates.iter().all(|candidate| {
                candidate.contract == winner.contract && candidate.alignment <= winner.alignment
            })
        });
        if winner.is_some() && !compatible {
            issues.push(format!(
                "incompatible exported definition contracts or alignment: {name}"
            ));
        }
        if let Some(winner) = winner.filter(|_| compatible) {
            selected.insert(*name, winner);
        }
        resolutions.push(json!({
            "symbol":name,
            "candidates":candidates.iter().enumerate().map(|(ordinal,candidate)| json!({
                "ordinal":ordinal,"unit":candidate.unit,"linkage":candidate.linkage,
                "contract":candidate.contract,"alignment":candidate.alignment,"alias_of":candidate.alias_of,
                "comdat":candidate.comdat,"retained_group":retained(candidate)
            })).collect::<Vec<_>>(),
            "selected_unit":winner.filter(|_|compatible).map(|winner|&winner.unit),
            "selected_linkage":winner.filter(|_|compatible).map(|winner|&winner.linkage),
            "rule":if !strong.is_empty() {"strong definition overrides weak definitions"} else {"first weak definition in supplied module order"},
            "compatible":compatible
        }));
    }
    let mut references = Vec::new();
    for declaration in symbols.iter().filter(|symbol| !symbol.definition) {
        if declaration
            .intrinsic
            .as_deref()
            .is_some_and(o_lang::ocore::native_verify::is_builtin_intrinsic)
        {
            references.push(json!({"unit":declaration.unit,"symbol":declaration.name,"contract":declaration.contract,
                "abi_adaptation":declaration.abi_adaptation,
                "resolved_provider":"ocore-native-v1","resolution":"verified owned intrinsic lowering","compatible":true}));
            continue;
        }
        let definition = selected.get(declaration.name.as_str()).copied();
        let compatible = definition.is_some_and(|definition| {
            definition.contract == declaration.contract
                && definition.alignment >= declaration.alignment
        });
        if !compatible {
            issues.push(format!(
                "unresolved or incompatible declaration {} in {}",
                declaration.name, declaration.unit
            ));
        }
        references.push(json!({"unit":declaration.unit, "symbol":declaration.name, "contract":declaration.contract,
                              "abi_adaptation":declaration.abi_adaptation,
                              "resolved_unit":definition.filter(|_|compatible).map(|definition|&definition.unit),
                              "compatible":compatible}));
    }
    let mut definition_references = Vec::new();
    for source in symbols
        .iter()
        .filter(|symbol| symbol.definition && retained(symbol))
    {
        if let Some(root) = &source.alias_of {
            if !symbols.iter().any(|symbol| {
                symbol.unit == source.unit
                    && symbol.name == *root
                    && symbol.definition
                    && retained(symbol)
            }) {
                issues.push(format!(
                    "retained alias {} lost its original unit provider {root}",
                    source.name
                ));
            }
        }
        for name in &source.references {
            let local = symbols.iter().find(|symbol| {
                symbol.unit == source.unit
                    && symbol.name == *name
                    && matches!(symbol.linkage.as_str(), "internal" | "private")
            });
            let provider = if let Some(local) = local {
                Some(local).filter(|symbol| symbol.definition && retained(symbol))
            } else {
                selected.get(name.as_str()).copied()
            };
            let builtin = symbols.iter().any(|symbol| {
                symbol.unit == source.unit
                    && symbol.name == *name
                    && symbol
                        .intrinsic
                        .as_deref()
                        .is_some_and(o_lang::ocore::native_verify::is_builtin_intrinsic)
            });
            if provider.is_none() && !builtin {
                issues.push(format!(
                    "retained definition {} in {} has an unresolved group/symbol reference {name}",
                    source.name, source.unit
                ));
            }
            definition_references.push(json!({"unit":source.unit,"definition":source.name,"symbol":name,
                "resolved_unit":provider.map(|provider|&provider.unit),"builtin":builtin,"resolved":provider.is_some() || builtin}));
        }
    }
    let definitions: Vec<_> = symbols
        .iter()
        .filter(|symbol| symbol.definition)
        .map(|symbol| {
            json!({"unit":symbol.unit,"symbol":symbol.name,"linkage":symbol.linkage,
               "contract":symbol.contract,"alignment":symbol.alignment,"alias_of":symbol.alias_of,
               "comdat":symbol.comdat,"retained_group":retained(symbol)})
        })
        .collect();
    (
        json!({"definitions":definitions,"declarations":references,"definition_references":definition_references,
               "export_resolutions":resolutions,"comdat_resolutions":group_resolutions,"resolution_order":"supplied module order; original link membership remains separately qualified",
               "image_visibility":image_visibility.into_iter().map(|(name,rank)| (name, match rank { 0 => "default", 1 => "protected", _ => "hidden" })).collect::<BTreeMap<_,_>>(),
               "closed":issues.is_empty()}),
        issues,
    )
}

fn invoke(compiler: &Path, args: &[String], log: &Path) -> Result<()> {
    let result = Command::new(compiler)
        .args(args)
        .output()
        .with_context(|| format!("launch native compiler {}", compiler.display()))?;
    fs::write(
        log,
        [result.stdout.as_slice(), result.stderr.as_slice()].concat(),
    )?;
    if !result.status.success() {
        bail!(
            "O-core compiler failed ({}); see {}",
            result.status,
            log.display()
        );
    }
    Ok(())
}

struct Section {
    kind: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: usize,
    info: usize,
    alignment: u64,
    stride: u64,
}

struct Definition {
    kind: u8,
    binding: u8,
    visibility: u8,
    size: u64,
    value: u64,
    section: usize,
}

struct ObjectSymbol {
    name: String,
    kind: u8,
    binding: u8,
    visibility: u8,
    section: usize,
    value: u64,
    size: u64,
}

fn object_inventory(bytes: &[u8], arch: &str, module: &NativeModule) -> Result<Value> {
    fn field<const N: usize>(bytes: &[u8], offset: u64) -> Result<[u8; N]> {
        let start = usize::try_from(offset)?;
        let end = start.checked_add(N).context("ELF extent overflow")?;
        Ok(bytes
            .get(start..end)
            .context("truncated ELF field")?
            .try_into()?)
    }
    let u16_at = |offset| field(bytes, offset).map(u16::from_le_bytes);
    let u32_at = |offset| field(bytes, offset).map(u32::from_le_bytes);
    let u64_at = |offset| field(bytes, offset).map(u64::from_le_bytes);
    let machine = match arch {
        "x86_64" => 62,
        "aarch64" => 183,
        "riscv64" => 243,
        _ => bail!("unknown ELF ISA"),
    };
    if !bytes.starts_with(b"\x7fELF\x02\x01\x01")
        || u16_at(16)? != 1
        || u16_at(18)? != machine
        || u32_at(20)? != 1
        || u16_at(52)? != 64
        || u16_at(58)? != 64
    {
        bail!("own-emitter object is not a relocatable little-endian ELF64 for the selected ISA");
    }
    let flags = u32_at(48)?;
    let expected_riscv_flags = match module.target.abi.as_deref() {
        None | Some("lp64") => 0,
        Some("lp64d") => 4, // EF_RISCV_FLOAT_ABI_DOUBLE.
        Some(abi) if arch == "riscv64" => {
            bail!("unsupported imported RISC-V ABI `{abi}` in object inventory")
        }
        Some(_) => 0,
    };
    if (arch == "riscv64" && flags & !1 != expected_riscv_flags)
        || (arch != "riscv64" && flags != 0)
    {
        bail!("ELF flags differ from the owned native ABI profile");
    }
    let shoff = u64_at(40)?;
    let count = u16_at(60)? as u64;
    if count == 0 {
        bail!("ELF object lacks ordinary section inventory");
    }
    let mut sections = Vec::new();
    for index in 0..count {
        let offset = shoff
            .checked_add(index.checked_mul(64).context("ELF section overflow")?)
            .context("ELF section overflow")?;
        if offset.checked_add(64).context("ELF section overflow")? > bytes.len() as u64 {
            bail!("truncated ELF section header");
        }
        let kind = u32_at(offset + 4)?;
        let data = u64_at(offset + 24)?;
        let size = u64_at(offset + 32)?;
        if kind != 8
            && data
                .checked_add(size)
                .context("ELF section extent overflow")?
                > bytes.len() as u64
        {
            bail!("ELF section is outside object bytes");
        }
        let alignment = u64_at(offset + 48)?;
        if alignment > 1 && !alignment.is_power_of_two() {
            bail!("invalid ELF section alignment");
        }
        sections.push(Section {
            kind,
            flags: u64_at(offset + 8)?,
            offset: data,
            size,
            link: u32_at(offset + 40)? as usize,
            info: u32_at(offset + 44)? as usize,
            alignment: alignment.max(1),
            stride: u64_at(offset + 56)?,
        });
    }
    let mut definitions = BTreeMap::new();
    let mut known_symbols: BTreeMap<_, _> = module
        .functions
        .iter()
        .filter(|function| function.intrinsic.is_none())
        .map(|function| {
            (
                function.name.as_str(),
                (function.visibility, function.linkage.as_str()),
            )
        })
        .chain(module.globals.iter().map(|global| {
            (
                global.name.as_str(),
                (global.visibility, global.linkage.as_str()),
            )
        }))
        .chain(module.aliases.iter().map(|alias| {
            (
                alias.name.as_str(),
                (alias.visibility, alias.linkage.as_str()),
            )
        }))
        .collect();
    let tls_names: BTreeSet<_> = module
        .globals
        .iter()
        .filter(|global| global.thread_local)
        .map(|global| global.name.as_str())
        .collect();
    let compiler_only_names: BTreeSet<_> = module
        .functions
        .iter()
        .filter(|function| {
            function.intrinsic.as_deref() == Some(o_lang::ocore::native_ir::NOALIAS_SCOPE_DECL)
        })
        .map(|function| function.name.as_str())
        .collect();
    if requires_unwind_resume(module) {
        known_symbols
            .entry("_Unwind_Resume")
            .or_insert((Visibility::Default, "external"));
    }
    let mut undefined_symbols = BTreeSet::new();
    let mut symbol_tables = BTreeMap::new();
    for (table_index, table) in sections.iter().enumerate() {
        if table.kind != 2 {
            continue;
        }
        let names_section = sections
            .get(table.link)
            .context("ELF symbol string section missing")?;
        if names_section.kind != 3 || table.stride != 24 || table.size % 24 != 0 {
            bail!("invalid ELF symbol table");
        }
        let names = bytes
            .get(
                usize::try_from(names_section.offset)?
                    ..usize::try_from(
                        names_section
                            .offset
                            .checked_add(names_section.size)
                            .context("ELF strings overflow")?,
                    )?,
            )
            .context("truncated ELF strings")?;
        let mut symbols = Vec::new();
        for index in 0..table.size / 24 {
            let symbol = table
                .offset
                .checked_add(index * 24)
                .context("ELF symbol extent overflow")?;
            let name_offset = u32_at(symbol)? as usize;
            let tail = names
                .get(name_offset..)
                .context("ELF symbol name is out of range")?;
            let end = tail
                .iter()
                .position(|byte| *byte == 0)
                .context("unterminated ELF symbol name")?;
            let name = std::str::from_utf8(&tail[..end])?;
            let info = field::<1>(bytes, symbol + 4)?[0];
            let section = u16_at(symbol + 6)?;
            symbols.push(ObjectSymbol {
                name: name.to_owned(),
                kind: info & 15,
                binding: info >> 4,
                visibility: field::<1>(bytes, symbol + 5)?[0],
                section: section as usize,
                value: u64_at(symbol + 8)?,
                size: u64_at(symbol + 16)?,
            });
            if name.is_empty() {
                continue;
            }
            // Source compiler metadata cannot gain an address through a local
            // untyped label, an exported definition, or a linker dependency.
            // STT_FILE is descriptive provenance, without a runtime address.
            if compiler_only_names.contains(name) && info & 15 != 4 {
                bail!("ELF gives a compiler-only metadata declaration a runtime symbol: {name}");
            }
            if section == 0 {
                let (expected_visibility, linkage) =
                    known_symbols.get(name).with_context(|| {
                        format!("ELF introduces an undeclared native dependency: {name}")
                    })?;
                match *linkage {
                    "internal" | "private" => {
                        bail!(
                            "ELF introduces an undefined reference to a verified local symbol: {name}"
                        )
                    }
                    "external" => {}
                    _ => bail!("unsupported native dependency linkage: {name}"),
                }
                if info >> 4 != 1 {
                    bail!("ELF dependency binding differs from supported external linkage: {name}");
                }
                if tls_names.contains(name) && info & 15 != 6 {
                    bail!("ELF TLS dependency must retain STT_TLS: {name}");
                }
                if !tls_names.contains(name) && info & 15 == 6 {
                    bail!("ELF introduces TLS for a verified ordinary dependency: {name}");
                }
                if field::<1>(bytes, symbol + 5)?[0] != visibility_bits(*expected_visibility) {
                    bail!("ELF dependency visibility differs from verified module: {name}");
                }
                undefined_symbols.insert(name.to_owned());
                continue;
            }
            if !matches!(info & 15, 1 | 2 | 6) {
                if info >> 4 != 0 {
                    bail!("ELF introduces an untyped exported definition: {name}");
                }
                continue;
            }
            if section as usize >= sections.len() || section >= 0xff00 {
                bail!("definition has invalid ELF section");
            }
            let value = u64_at(symbol + 8)?;
            let size = u64_at(symbol + 16)?;
            if value
                .checked_add(size)
                .context("ELF definition extent overflow")?
                > sections[section as usize].size
            {
                bail!("ELF definition exceeds its section");
            }
            if definitions
                .insert(
                    name.to_owned(),
                    Definition {
                        kind: info & 15,
                        binding: info >> 4,
                        visibility: field::<1>(bytes, symbol + 5)?[0],
                        size,
                        value,
                        section: section as usize,
                    },
                )
                .is_some()
            {
                bail!("duplicate ELF definition: {name}");
            }
        }
        symbol_tables.insert(table_index, symbols);
    }
    let expected_count = module
        .functions
        .iter()
        .filter(|f| f.entry.is_some())
        .count()
        + module
            .globals
            .iter()
            .filter(|g| g.initializer.is_some())
            .count()
        + module.aliases.len();
    if definitions.len() != expected_count {
        bail!("ELF definition inventory differs from verified module");
    }
    let check_binding = |definition: &Definition, linkage: &str| -> Result<()> {
        let expected = match linkage {
            "external" => 1,
            "weak" | "linkonce" | "linkonce_odr" | "weak_odr" => 2,
            "internal" | "private" => 0,
            _ => bail!("unsupported definition linkage"),
        };
        if definition.binding != expected {
            bail!("ELF symbol binding differs from verified linkage");
        }
        Ok(())
    };
    for function in module.functions.iter().filter(|f| f.entry.is_some()) {
        let name = &function.name;
        let definition = definitions
            .get(name)
            .with_context(|| format!("ELF omitted verified definition {name}"))?;
        let section = &sections[definition.section];
        if definition.kind != 2 || definition.size == 0 {
            bail!("ELF definition type/size mismatch: {name}");
        }
        if section.kind != 1 || section.flags & 6 != 6 || section.flags & 0x400 != 0 {
            bail!("ELF function lacks allocated executable bytes: {name}");
        }
        let instruction_alignment = match arch {
            "aarch64" => 4,
            "riscv64" if flags & 1 == 0 => 4,
            "riscv64" => 2,
            _ => 1,
        };
        if section.alignment < instruction_alignment
            || definition.value % instruction_alignment != 0
        {
            bail!("ELF function start violates instruction alignment: {name}");
        }
        if function.alignment != 0
            && (section.alignment < function.alignment
                || definition.value % function.alignment != 0)
        {
            bail!("ELF function alignment differs from verified source alignment: {name}");
        }
        check_binding(definition, &function.linkage)?;
        if definition.visibility != visibility_bits(function.visibility) {
            bail!("ELF function visibility differs from verified module: {name}");
        }
    }
    for global in module.globals.iter().filter(|g| g.initializer.is_some()) {
        let name = &global.name;
        let definition = definitions
            .get(name)
            .with_context(|| format!("ELF omitted verified definition {name}"))?;
        let section = &sections[definition.section];
        if definition.kind != if global.thread_local { 6 } else { 1 }
            || definition.size != global.initializer.as_ref().unwrap().bytes.len() as u64
        {
            bail!("ELF definition type/size mismatch: {name}");
        }
        let valid_storage = if global.thread_local {
            matches!(section.kind, 1 | 8) && section.flags & !0x200 == 0x403
        } else {
            section.kind == 1
                && section.flags & 2 != 0
                && section.flags & 0x400 == 0
                && (section.flags & 1 != 0) != global.constant
        };
        if !valid_storage {
            bail!("ELF global storage differs from verified mutability: {name}");
        }
        let alignment = if global.alignment == 0 {
            o_lang::ocore::native_verify::type_alignment(module, global.ty)?
        } else {
            global.alignment
        };
        if section.alignment < alignment || definition.value % alignment != 0 {
            bail!("ELF global alignment differs from verified layout: {name}");
        }
        check_binding(definition, &global.linkage)?;
        if definition.visibility != visibility_bits(global.visibility) {
            bail!("ELF global visibility differs from verified module: {name}");
        }
    }
    for alias in &module.aliases {
        let definition = definitions
            .get(&alias.name)
            .with_context(|| format!("ELF omitted verified alias {}", alias.name))?;
        let aliasee = definitions.get(&alias.aliasee).with_context(|| {
            format!(
                "ELF alias has no included defined aliasee {}",
                alias.aliasee
            )
        })?;
        if definition.kind != aliasee.kind
            || definition.size != aliasee.size
            || definition.value != aliasee.value
            || definition.section != aliasee.section
        {
            bail!(
                "ELF alias identity/type/extent differs from verified aliasee: {}",
                alias.name
            );
        }
        check_binding(definition, &alias.linkage)?;
        if definition.visibility != visibility_bits(alias.visibility) {
            bail!(
                "ELF alias visibility differs from verified module: {}",
                alias.name
            );
        }
    }
    // Initializers have an exact source contract. RELA overwrites each declared
    // eight-byte pointer slot, so compare all other bytes and then check the
    // relocation's type, destination, symbol identity and explicit addend.
    // Code and CFI relocations retain the separate structural checks below.
    let mut initializer_sections = BTreeSet::new();
    let mut initializer_ranges: BTreeMap<usize, Vec<(u64, u64)>> = BTreeMap::new();
    let mut expected_relocations = BTreeMap::new();
    let mut initializer_bytes = 0u64;
    let mut resolved_relative_initializers = 0usize;
    let mut relative_initializer_count = 0usize;
    let mut expected_relocation_records = 0usize;
    for global in module.globals.iter().filter(|g| g.initializer.is_some()) {
        let definition = &definitions[&global.name];
        let section = &sections[definition.section];
        let initializer = global.initializer.as_ref().unwrap();
        initializer_sections.insert(definition.section);
        let end = definition
            .value
            .checked_add(definition.size)
            .context("ELF initializer extent overflow")?;
        initializer_ranges
            .entry(definition.section)
            .or_default()
            .push((definition.value, end));
        let actual = if section.kind == 8 {
            if !global.thread_local
                || !initializer.relocations.is_empty()
                || initializer.bytes.iter().any(|byte| *byte != 0)
            {
                bail!(
                    "ELF TLS NOBITS template must exactly represent relocation-free source zeros"
                );
            }
            // SHT_NOBITS contributes zero-fill extent to PT_TLS, not bytes from
            // the section's nominal file offset. Extent and alignment were
            // independently checked above; the original zero template stays IR.
            initializer.bytes.as_slice()
        } else {
            let start = section
                .offset
                .checked_add(definition.value)
                .context("ELF initializer file extent overflow")?;
            let file_end = start
                .checked_add(definition.size)
                .context("ELF initializer file extent overflow")?;
            bytes
                .get(usize::try_from(start)?..usize::try_from(file_end)?)
                .context("truncated ELF initializer")?
        };
        let mut relocations: Vec<_> = initializer.relocations.iter().collect();
        relocations.sort_by_key(|relocation| relocation.offset);
        let mut cursor = 0usize;
        for relocation in relocations {
            if !matches!(
                (relocation.width, relocation.relative_to.is_some()),
                (64, false) | (32, true)
            ) {
                bail!(
                    "unsupported ELF initializer relocation width: {}",
                    global.name
                );
            }
            let offset = usize::try_from(relocation.offset)?;
            let end = offset
                .checked_add(usize::from(relocation.width) / 8)
                .context("ELF initializer relocation overflow")?;
            if offset < cursor || end > actual.len() {
                bail!(
                    "invalid verified initializer relocation extent: {}",
                    global.name
                );
            }
            if actual[cursor..offset] != initializer.bytes[cursor..offset] {
                bail!(
                    "ELF initializer bytes differ from verified source: {}",
                    global.name
                );
            }
            let target_offset = definition
                .value
                .checked_add(relocation.offset)
                .context("ELF initializer relocation overflow")?;
            if let Some(base_name) = &relocation.relative_to {
                relative_initializer_count += 1;
                let base = definitions
                    .get(base_name)
                    .context("relative initializer base has no owned ELF definition")?;
                let fixed_target =
                    known_symbols
                        .get(relocation.symbol.as_str())
                        .is_some_and(|(_, linkage)| {
                            matches!(*linkage, "internal" | "private" | "external")
                        });
                if let Some(target) = definitions
                    .get(&relocation.symbol)
                    .filter(|target| fixed_target && target.section == base.section)
                {
                    let expected = target
                        .value
                        .wrapping_add(relocation.addend as u64)
                        .wrapping_sub(base.value) as u32;
                    if actual[offset..end] != expected.to_le_bytes() {
                        bail!("ELF resolved relative initializer differs from source symbol difference: {}", global.name);
                    }
                    resolved_relative_initializers += 1;
                    cursor = end;
                    continue;
                }
                // ADD32/SUB32 add into this word instead of replacing it.
                if arch == "riscv64" && actual[offset..end].iter().any(|byte| *byte != 0) {
                    bail!("ELF RV64 relative initializer accumulator is nonzero");
                }
            }
            if expected_relocations
                .insert((definition.section, target_offset), relocation)
                .is_some()
            {
                bail!("overlapping ELF initializer relocations");
            }
            expected_relocation_records += if arch == "riscv64" && relocation.relative_to.is_some()
            {
                2
            } else {
                1
            };
            cursor = end;
        }
        if actual[cursor..] != initializer.bytes[cursor..] {
            bail!(
                "ELF initializer bytes differ from verified source: {}",
                global.name
            );
        }
        initializer_bytes = initializer_bytes
            .checked_add(definition.size)
            .context("ELF initializer byte count overflow")?;
    }
    for ranges in initializer_ranges.values_mut() {
        ranges.sort_unstable();
        let mut previous_end = 0;
        for &(start, end) in ranges.iter().filter(|(start, end)| start != end) {
            if start < previous_end {
                bail!("ELF verified global initializers overlap without an alias");
            }
            previous_end = end;
        }
    }
    let mut matched_relocations = BTreeSet::new();
    // Check group metadata against the verified source membership, not merely
    // the weak symbol bindings. The linker must discard code, data and their
    // relocation sections together.
    let expected_groups: BTreeMap<_, _> = module
        .comdats
        .iter()
        .map(|group| (group.name.as_str(), group.selection))
        .collect();
    let mut actual_groups: BTreeMap<String, (u32, BTreeSet<usize>)> = BTreeMap::new();
    let mut section_groups: BTreeMap<usize, String> = BTreeMap::new();
    for (group_index, section) in sections
        .iter()
        .enumerate()
        .filter(|(_, section)| section.kind == 17)
    {
        if section.stride != 4
            || section.size < 8
            || section.size % 4 != 0
            || section.alignment != 4
            || section.flags != 0
        {
            bail!("invalid ELF section group geometry");
        }
        let name = symbol_tables
            .get(&section.link)
            .and_then(|symbols| symbols.get(section.info))
            .map(|symbol| &symbol.name)
            .context("ELF group signature does not resolve in its symbol table")?;
        let selection = expected_groups
            .get(name.as_str())
            .with_context(|| format!("ELF introduces undeclared section group {name}"))?;
        let expected_flag = match selection {
            o_lang::ocore::native_ir::ComdatSelection::Any => 1,
            o_lang::ocore::native_ir::ComdatSelection::NoDeduplicate => 0,
            _ => bail!("unsupported native COMDAT selection"),
        };
        let actual_flag = u32_at(section.offset)?;
        if actual_flag != expected_flag {
            bail!("ELF group selection differs from verified COMDAT");
        }
        let mut members = BTreeSet::new();
        for offset in (4..section.size).step_by(4) {
            let index = u32_at(section.offset + offset)? as usize;
            let member = sections
                .get(index)
                .context("ELF group member section is missing")?;
            if index == 0
                || index == group_index
                || member.kind == 17
                || member.flags & 0x200 == 0
                || !members.insert(index)
                || section_groups.insert(index, name.clone()).is_some()
            {
                bail!("invalid or multiply owned ELF group member");
            }
        }
        if actual_groups
            .insert(name.clone(), (actual_flag, members))
            .is_some()
        {
            bail!("duplicate ELF group signature");
        }
    }
    for (index, section) in sections.iter().enumerate() {
        if (section.flags & 0x200 != 0) != section_groups.contains_key(&index) {
            bail!("ELF group flag and member inventory disagree");
        }
        if matches!(section.kind, 4 | 9) {
            let stride = if section.kind == 4 { 24 } else { 16 };
            let table = symbol_tables
                .get(&section.link)
                .context("ELF relocation symbol table is missing")?;
            let target = sections
                .get(section.info)
                .filter(|_| section.info != 0)
                .context("ELF relocation target section is missing")?;
            // The x86 assembler uses this processor-specific kind for .eh_frame.
            // Admission remains structural: this does not validate CFI semantics.
            let x86_unwind_target = arch == "x86_64"
                && target.kind == 0x7000_0001
                && target.flags == 2
                && target.alignment >= 8
                && target.stride == 0
                && target.size >= 4;
            if section.stride != stride
                || section.size % stride != 0
                || section.alignment < 8
                || !(matches!(target.kind, 1 | 8) || x86_unwind_target)
            {
                bail!("invalid ELF relocation section geometry or target");
            }
            for offset in (0..section.size).step_by(stride as usize) {
                let relocation_offset = u64_at(section.offset + offset)?;
                let info = u64_at(section.offset + offset + 8)?;
                if relocation_offset >= target.size || (info >> 32) >= table.len() as u64 {
                    bail!("ELF relocation offset or symbol is outside its target inventory");
                }
                if compiler_only_names.contains(table[(info >> 32) as usize].name.as_str()) {
                    bail!("ELF relocation addresses a compiler-only metadata declaration");
                }
                if initializer_sections.contains(&section.info) {
                    let key = (section.info, relocation_offset);
                    let expected = expected_relocations
                        .get(&key)
                        .context("ELF initializer relocation is extra or misplaced")?;
                    if section.kind != 4 {
                        bail!("ELF initializer requires explicit-addend RELA relocation");
                    }
                    let kind = info as u32;
                    let (expected_symbol, expected_addend) = if let Some(base_name) =
                        &expected.relative_to
                    {
                        let base = &definitions[base_name];
                        match (arch, kind) {
                            ("x86_64", 2) | ("aarch64", 261) => (
                                expected.symbol.as_str(),
                                (expected.addend as u64)
                                    .wrapping_add(relocation_offset)
                                    .wrapping_sub(base.value),
                            ),
                            ("riscv64", 35) => (expected.symbol.as_str(), expected.addend as u64),
                            ("riscv64", 39) => (base_name.as_str(), 0),
                            _ => bail!(
                                "ELF initializer relocation type differs from verified relative32"
                            ),
                        }
                    } else {
                        let absolute_type = match arch {
                            "x86_64" => 1,    // R_X86_64_64.
                            "aarch64" => 257, // R_AARCH64_ABS64.
                            "riscv64" => 2,   // R_RISCV_64.
                            _ => unreachable!(),
                        };
                        if kind != absolute_type {
                            bail!("ELF initializer relocation type differs from verified ABS64");
                        }
                        (expected.symbol.as_str(), expected.addend as u64)
                    };
                    let symbol = &table[(info >> 32) as usize];
                    let addend = u64_at(section.offset + offset + 16)?;
                    let direct_identity = if let Some(definition) = definitions.get(expected_symbol)
                    {
                        symbol.kind == definition.kind
                            && symbol.binding == definition.binding
                            && symbol.visibility == definition.visibility
                            && symbol.size == definition.size
                            && symbol.value == definition.value
                            && symbol.section == definition.section
                    } else {
                        symbol.section == 0 && symbol.binding == 1
                    };
                    let direct = symbol.name == expected_symbol
                        && direct_identity
                        && addend == expected_addend;
                    // The assembler can fold only a local source symbol into
                    // its section plus symbol offset. Exported and weak aliases
                    // retain their independent linker identity, even when the
                    // underlying definition is local.
                    let local = known_symbols
                        .get(expected_symbol)
                        .is_some_and(|(_, linkage)| matches!(*linkage, "internal" | "private"));
                    let folded = local
                        && definitions.get(expected_symbol).is_some_and(|definition| {
                            symbol.kind == 3
                                && symbol.binding == 0
                                && symbol.visibility == 0
                                && symbol.size == 0
                                && symbol.value == 0
                                && symbol.section == definition.section
                                && addend == definition.value.wrapping_add(expected_addend)
                        });
                    if !(direct || folded) {
                        bail!(
                            "ELF initializer relocation symbol/addend differs from verified source"
                        );
                    }
                    if !matched_relocations.insert((key, kind)) {
                        bail!("duplicate ELF initializer relocation");
                    }
                }
            }
            let target_group = section_groups.get(&section.info);
            if target_group != section_groups.get(&index) {
                bail!("ELF relocation section does not share its target's group");
            }
        }
    }
    if matched_relocations.len() != expected_relocation_records {
        bail!("ELF omitted verified initializer relocation");
    }
    let exception_inventory =
        exception_inventory::inspect(bytes, arch, module, &sections, &definitions, &symbol_tables)?;
    let tls_inventory =
        tls_inventory::inspect(bytes, arch, module, &sections, &definitions, &symbol_tables)?;
    let mut expected_members: BTreeMap<&str, BTreeSet<usize>> = BTreeMap::new();
    let members = module
        .functions
        .iter()
        .filter(|f| f.entry.is_some())
        .map(|f| (f.name.as_str(), f.comdat.as_deref()))
        .chain(
            module
                .globals
                .iter()
                .filter(|g| g.initializer.is_some())
                .map(|g| (g.name.as_str(), g.comdat.as_deref())),
        );
    for (name, group) in members {
        let index = definitions[name].section;
        if section_groups.get(&index).map(String::as_str) != group {
            bail!("ELF definition group differs from verified membership: {name}");
        }
        if let Some(group) = group {
            expected_members.entry(group).or_default().insert(index);
        }
    }
    for (index, function) in &exception_inventory.sections {
        let group = module
            .functions
            .iter()
            .find(|candidate| candidate.name == *function)
            .context("ELF exception table has no original source owner")?
            .comdat
            .as_deref();
        if section_groups.get(index).map(String::as_str) != group {
            bail!("ELF exception table group differs from its source function");
        }
        if let Some(group) = group {
            expected_members.entry(group).or_default().insert(*index);
        }
    }
    if actual_groups.len() != expected_members.len() {
        bail!("ELF group inventory differs from verified module");
    }
    for (name, members) in &actual_groups {
        let expected = expected_members
            .get(name.as_str())
            .context("ELF group has no verified definitions")?;
        let primary: BTreeSet<_> = members
            .1
            .iter()
            .copied()
            .filter(|index| !matches!(sections[*index].kind, 4 | 9))
            .collect();
        if &primary != expected {
            bail!("ELF whole-group members differ from verified definitions");
        }
    }
    Ok(
        json!({"definitions": definitions.iter().map(|(name,def)| json!({"name":name,"kind":def.kind,"binding":def.binding,"visibility":def.visibility,"bytes":def.size,"comdat":section_groups.get(&def.section)})).collect::<Vec<_>>(),"undefined_symbols":undefined_symbols,
            "section_groups":actual_groups.iter().map(|(name,(flags,members))| json!({"name":name,"flags":flags,"members":members})).collect::<Vec<_>>(),
            "initializer_checks":{"globals":module.globals.iter().filter(|g|g.initializer.is_some()).count(),"bytes":initializer_bytes,
                "absolute_relocations":expected_relocations.values().filter(|r|r.relative_to.is_none()).count(),
                "relative32_initializers":relative_initializer_count,"resolved_relative32_initializers":resolved_relative_initializers,
                "relocation_records":matched_relocations.len(),"scope":"source_defined_globals"},
            "exception_tables":exception_inventory.receipt,
            "thread_local_storage":tls_inventory,
            "code_and_cfi_relocations":"structural_only" }),
    )
}

fn visibility_bits(visibility: Visibility) -> u8 {
    match visibility {
        Visibility::Default => 0,
        Visibility::Hidden => 2,
        Visibility::Protected => 3,
    }
}

/// Output is a new directory of verified modules/objects and a completeness receipt.
/// Successful unit lowering never claims a complete native runtime or .O execution.
pub(super) fn compile_capture(
    report: &Path,
    target: &str,
    output_kind: &str,
    output: &Path,
    import_options: NativeImportOptions<'_>,
) -> Result<()> {
    let compiler = std::env::current_exe()?
        .parent()
        .context("olangc executable has no parent")?
        .join("ocorec");
    compile_with_compiler(
        report,
        target,
        output_kind,
        output,
        import_options,
        &compiler,
    )
}

pub(super) struct NativeImportOptions<'a> {
    pub(super) llvm_library: Option<&'a Path>,
    pub(super) llvm_sha256: Option<&'a str>,
    pub(super) tls_profile: Option<&'a str>,
    pub(super) atomic_profile: Option<&'a str>,
}

fn compile_with_compiler(
    report: &Path,
    target: &str,
    output_kind: &str,
    output: &Path,
    import_options: NativeImportOptions<'_>,
    compiler: &Path,
) -> Result<()> {
    let NativeImportOptions {
        llvm_library,
        llvm_sha256,
        tls_profile,
        atomic_profile,
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
    let arch = architecture(target)?;
    if !matches!(output_kind, "ir" | "obj") {
        bail!("native runtime output must be ir or obj");
    }
    if llvm_library.is_some() != llvm_sha256.is_some() {
        bail!("explicit LLVM parser library and SHA-256 must be supplied together");
    }
    let bytes =
        fs::read(report).with_context(|| format!("read runtime capture {}", report.display()))?;
    let capture: Value = serde_json::from_slice(&bytes).context("decode runtime capture report")?;
    fs::create_dir(output).with_context(|| {
        format!(
            "native runtime output must be a new directory: {}",
            output.display()
        )
    })?;
    let output = output.canonicalize()?;
    let (selected, mut issues) = match capture_admission(&capture) {
        Ok(selected) => (selected, Vec::new()),
        Err(error) => (BTreeSet::new(), vec![error.to_string()]),
    };
    let mut records = Vec::new();
    let mut collected_symbols = Vec::new();
    let mut profile: Option<(String, String)> = None;
    let mut unit_ids = BTreeSet::new();
    let units = capture
        .get("units")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut preflight_ok = issues.is_empty();
    let capture_reverification = if preflight_ok {
        match reverify_capture(report, &bytes, &output) {
            Ok(receipt) => Some(receipt),
            Err(error) => {
                issues.push(error.to_string());
                preflight_ok = false;
                None
            }
        }
    } else {
        None
    };
    let compiler_digest = if preflight_ok {
        match fs::read(compiler) {
            Ok(bytes) => Some(digest(&bytes)),
            Err(error) => {
                issues.push(format!("read actual O-core compiler: {error}"));
                preflight_ok = false;
                None
            }
        }
    } else {
        None
    };
    for (index, unit) in units.iter().enumerate() {
        let id = unit
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("<invalid-unit>");
        let mut record = json!({"id":id,"input":unit.get("ir"),"verified":false,"lowered":false});
        if !preflight_ok {
            record["failure"] = json!("capture admission failed; unit not attempted");
            records.push(record);
            continue;
        }
        record["required_for_lowering"] = json!(selected.contains(id));
        if !selected.contains(id) {
            record["scope"] = json!("explicit non-runtime unit; retained in capture provenance");
            records.push(record);
            continue;
        }
        let result = (|| -> Result<()> {
            let input = checked_ir(unit, arch)?;
            let directory = output.join(format!("unit-{index:06}"));
            fs::create_dir(&directory)?;
            let imported = directory.join("module.native-ir.json");
            let mut arguments = vec![
                input.display().to_string(),
                "--input-kind".into(),
                "llvm-ir".into(),
                "--emit".into(),
                "mir".into(),
                "--target".into(),
                format!("{arch}-unknown-none"),
                "-o".into(),
                imported.display().to_string(),
            ];
            if let (Some(library), Some(sha256)) = (llvm_library, llvm_sha256) {
                arguments.extend([
                    "--llvm-library".into(),
                    library.display().to_string(),
                    "--llvm-sha256".into(),
                    sha256.into(),
                ]);
            }
            if let Some(profile) = tls_profile {
                arguments.extend(["--tls-profile".into(), profile.into()]);
            }
            if let Some(profile) = atomic_profile {
                arguments.extend(["--atomic-profile".into(), profile.into()]);
            }
            record["import_argv"] = json!(arguments);
            invoke(compiler, &arguments, &directory.join("import.log"))?;
            let imported_bytes = fs::read(&imported)?;
            let module = NativeModule::from_json(&imported_bytes).map_err(|error| {
                anyhow::anyhow!("independent native verification: {}", error.message)
            })?;
            if module.provenance.input_sha256 != string(&unit["ir"], "sha256")?
                || module.target.triple != string(&unit["ir"], "target_triple")?
                || module.target.data_layout != string(&unit["ir"], "data_layout")?
                || module.target.tls_profile != expected_tls_profile
                || module.target.atomic_profile != expected_atomic_profile
            {
                bail!("imported module provenance/target differs from the captured input");
            }
            let mut triple = module.target.triple.split('-');
            let architecture = triple.next().unwrap_or_default();
            let _vendor = triple.next();
            let platform = format!("{architecture}-{}", triple.collect::<Vec<_>>().join("-"));
            let current = (
                format!("{platform}:{:?}", module.target.abi),
                module.target.data_layout.clone(),
            );
            if profile.as_ref().is_some_and(|profile| profile != &current) {
                bail!("cross-module frontend platform/DataLayout mismatch");
            }
            profile = Some(current);
            let verification = directory.join("verification.json");
            invoke(
                compiler,
                &[
                    imported.display().to_string(),
                    "--input-kind".into(),
                    "native-ir".into(),
                    "--verify-native".into(),
                    "--receipt".into(),
                    verification.display().to_string(),
                ],
                &directory.join("verify.log"),
            )?;
            let receipt: Value = serde_json::from_slice(&fs::read(&verification)?)?;
            if receipt["format"] != "ocore-native-verification-v1"
                || receipt["verifier"] != "ocore-native-v1"
                || receipt["scope"] != "structural_ir_verification"
                || receipt["verified"] != true
                || receipt["module_sha256"] != digest(&imported_bytes)
            {
                bail!("native verification receipt is not bound to the imported bytes");
            }
            record["verified"] = json!(true);
            record["module"] = json!({"path":imported,"sha256":digest(&imported_bytes),"target":module.target,
                                      "provenance":module.provenance});
            record["verification_receipt"] = json!(verification);
            record["verification_sha256"] = json!(digest(&fs::read(&verification)?));
            if output_kind == "obj" {
                let object = directory.join("module.o");
                invoke(
                    compiler,
                    &[
                        imported.display().to_string(),
                        "--input-kind".into(),
                        "native-ir".into(),
                        "--emit".into(),
                        "obj".into(),
                        "--target".into(),
                        format!("{arch}-unknown-none"),
                        "-o".into(),
                        object.display().to_string(),
                    ],
                    &directory.join("emit.log"),
                )?;
                let object_bytes = fs::read(&object)?;
                record["object_inventory"] = object_inventory(&object_bytes, arch, &module)?;
                record["object"] = json!({"path":object,"sha256":digest(&object_bytes),"bytes":object_bytes.len()});
            }
            collected_symbols.extend(symbols(id, &module)?);
            if digest(&fs::read(&imported)?) != digest(&imported_bytes) {
                bail!("imported module changed during lowering");
            }
            unit_ids.insert(id.to_owned());
            record["lowered"] = json!(true);
            Ok(())
        })();
        if let Err(error) = result {
            record["failure"] = json!(error.to_string());
            issues.push(format!("unit {id}: {error}"));
        }
        records.push(record);
    }
    if let Some(expected) = &compiler_digest {
        if fs::read(compiler).map(|bytes| digest(&bytes)).ok().as_ref() != Some(expected) {
            issues.push("actual O-core compiler changed during lowering".into());
        }
    }
    if fs::read(report)
        .map(|current| digest(&current))
        .ok()
        .as_ref()
        != Some(&digest(&bytes))
    {
        issues.push("source capture report changed during lowering".into());
    }
    let (mut closure, closure_issues) = resolve_symbols(&collected_symbols);
    let symbol_closure_complete = closure_issues.is_empty();
    issues.extend(closure_issues);
    if let Some(dependencies) = capture["dependencies"]["declared"].as_array() {
        for dependency in dependencies {
            if dependency["status"] != "verified-ocore-closure" {
                issues.push(format!(
                    "declared source dependency is not a verified included O-core closure: {}",
                    dependency["name"]
                ));
            } else {
                // A status label alone is insufficient; only definitions in these modules are admitted.
                issues.push(format!(
                    "dependency receipt/reference verification is not implemented: {}",
                    dependency["name"]
                ));
            }
        }
    }
    issues.sort();
    issues.dedup();
    let unit_complete = !selected.is_empty()
        && selected.len() == unit_ids.len()
        && records
            .iter()
            .filter(|record| record["required_for_lowering"] == true)
            .all(|record| record["lowered"] == true);
    closure["inventory_complete"] = json!(unit_complete);
    if !unit_complete {
        closure["closed"] = json!(false);
    }
    let complete = unit_complete && issues.is_empty();
    let receipt = json!({"schema":RECEIPT_FORMAT,"capture_report":report,"capture_sha256":digest(&bytes),
        "tls_profile":expected_tls_profile,"tls_platform_execution_qualified":false,
        "atomic_profile":expected_atomic_profile,"atomic_hardware_memory_order_qualified":false,
        "name":capture["name"],"requested_target":target,"architecture":arch,"output_kind":output_kind,
        "compiler":compiler,"compiler_sha256":compiler_digest,"source":capture["source"],"manifest":capture["manifest"],
        "capture_reverification":capture_reverification,
        "capture_complete":preflight_ok,"captured_unit_count":units.len(),"lowered_unit_count":unit_ids.len(),
        "required_lowering_unit_count":selected.len(),"non_lowering_units":capture["non_lowering_units"],
        "units":records,"symbol_inventory":closure,"issues":issues,
        "unit_lowering_complete":unit_complete,"lowering_complete":complete,
        "symbol_closure_complete":unit_complete && symbol_closure_complete,"dependency_closure_complete":false,
        "module_set_complete":complete,"artifact_complete":false,"link_performed":false,"native_execution_qualified":false,"runtime_complete":false,
        "remaining_runtime_requirements":capture["remaining_runtime_requirements"],
        "scope":"verified native modules and own-emitter relocatable objects; no script/runtime orchestration or native qualification"});
    let receipt_path = output.join("coverage.json");
    fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt)?)?;
    if !complete {
        bail!(
            "native runtime lowering incomplete; {} units lowered of {}; see {}",
            unit_ids.len(),
            selected.len(),
            receipt_path.display()
        );
    }
    eprintln!(
        "olangc: lowered {} complete captured units; receipt {}",
        unit_ids.len(),
        receipt_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol(unit: &str, name: &str, definition: bool, linkage: &str) -> Symbol {
        Symbol {
            unit: unit.into(),
            name: name.into(),
            definition,
            linkage: linkage.into(),
            visibility: Visibility::Default,
            alignment: 0,
            contract: json!({"kind":"function","params":[],"result":{"kind":"int","bits":64},"abi":"c"}),
            intrinsic: None,
            alias_of: None,
            comdat: None,
            references: BTreeSet::new(),
            abi_adaptation: None,
        }
    }

    #[test]
    fn nested_aggregate_constant_symbols_require_included_providers() {
        use o_lang::ocore::native_ir::{Instruction, Operand, Operation, Type, Value};
        let mut source = object_inventory_tests::module();
        let pointer = source.types.len();
        source.types.push(Type::Pointer { address_space: 0 });
        let array = source.types.len();
        source.types.push(Type::Array {
            element: pointer,
            len: 2,
        });
        let aggregate = source.types.len();
        source.types.push(Type::Struct {
            fields: vec![array],
            packed: true,
        });
        source.functions[0].blocks[0]
            .instructions
            .push(Instruction {
                result: Some(Value {
                    id: 100,
                    ty: aggregate,
                }),
                operation: Operation::Freeze {
                    value: Operand::Aggregate {
                        ty: aggregate,
                        elements: vec![Operand::Aggregate {
                            ty: array,
                            elements: vec![
                                Operand::Null { ty: pointer },
                                Operand::SymbolOffset {
                                    ty: pointer,
                                    name: "g".into(),
                                    addend: 7,
                                },
                            ],
                        }],
                    },
                },
            });
        o_lang::ocore::native_verify::verify(&source).unwrap();
        assert_eq!(
            function_references(&source.functions[0]),
            BTreeSet::from(["g".to_owned()])
        );
        let initializer = source.globals[0].initializer.take();
        let (receipt, issues) = resolve_symbols(&symbols("source", &source).unwrap());
        assert!(!issues.is_empty());
        assert_eq!(receipt["definition_references"][0]["symbol"], "g");
        assert_eq!(receipt["definition_references"][0]["resolved"], false);
        source.globals[0].initializer = initializer;
        let (receipt, issues) = resolve_symbols(&symbols("source", &source).unwrap());
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(receipt["definition_references"][0]["resolved"], true);
    }

    #[test]
    fn symbolic_offset_operands_require_an_included_named_provider() {
        use o_lang::ocore::native_ir::{Operand, Terminator, Type};
        let mut source = object_inventory_tests::module();
        let pointer = source.types.len();
        source.types.push(Type::Pointer { address_space: 0 });
        source.functions[0].signature.result = pointer;
        source.functions[0].blocks[0].terminator = Terminator::Return {
            value: Some(Operand::SymbolOffset {
                ty: pointer,
                name: "g".into(),
                addend: i64::MIN,
            }),
        };
        let initializer = source.globals[0].initializer.take();
        o_lang::ocore::native_verify::verify(&source).unwrap();
        assert_eq!(
            function_references(&source.functions[0]),
            BTreeSet::from(["g".to_owned()])
        );
        let (receipt, issues) = resolve_symbols(&symbols("source", &source).unwrap());
        assert!(!issues.is_empty());
        assert_eq!(receipt["definition_references"][0]["symbol"], "g");
        assert_eq!(receipt["definition_references"][0]["resolved"], false);
        source.globals[0].initializer = initializer;
        let (receipt, issues) = resolve_symbols(&symbols("source", &source).unwrap());
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(receipt["definition_references"][0]["resolved"], true);
    }

    #[test]
    fn comdat_selects_code_data_and_aliases_as_one_group_in_both_orders() {
        use o_lang::ocore::native_ir::ComdatSelection;
        let members = |unit: &str| {
            let mut code = symbol(unit, "engine", true, "external");
            let mut data = symbol(unit, "table", true, "weak_odr");
            let group = Some(GroupMembership {
                name: "runtime-group".into(),
                selection: ComdatSelection::Any,
            });
            code.comdat = group.clone();
            data.comdat = group;
            let mut alias = code.clone();
            alias.name = "entry_alias".into();
            alias.alias_of = Some("engine".into());
            vec![code, data, alias]
        };
        for order in [["a", "b"], ["b", "a"]] {
            let inputs: Vec<_> = order.iter().flat_map(|unit| members(unit)).collect();
            let (receipt, issues) = resolve_symbols(&inputs);
            assert!(issues.is_empty(), "{issues:?}");
            assert_eq!(receipt["definitions"].as_array().unwrap().len(), 6);
            assert_eq!(
                receipt["comdat_resolutions"][0]["selected_units"],
                json!([order[0]])
            );
            for resolution in receipt["export_resolutions"].as_array().unwrap() {
                assert_eq!(resolution["selected_unit"], order[0]);
                assert_eq!(resolution["candidates"][0]["retained_group"], true);
                assert_eq!(resolution["candidates"][1]["retained_group"], false);
            }
        }
    }

    #[test]
    fn discarded_group_cannot_supply_a_retained_local_reference_or_alias() {
        use o_lang::ocore::native_ir::ComdatSelection;
        let mut first = symbol("first", "engine", true, "external");
        first.comdat = Some(GroupMembership {
            name: "runtime-group".into(),
            selection: ComdatSelection::Any,
        });
        let mut second = first.clone();
        second.unit = "second".into();
        let mut helper = second.clone();
        helper.name = "private-helper".into();
        helper.linkage = "private".into();
        let mut caller = symbol("second", "caller", true, "external");
        caller.references.insert(helper.name.clone());
        let (receipt, issues) = resolve_symbols(&[
            first.clone(),
            second.clone(),
            helper.clone(),
            caller.clone(),
        ]);
        assert_eq!(receipt["definition_references"][0]["resolved"], false);
        assert!(issues
            .iter()
            .any(|issue| issue.contains("unresolved group/symbol reference")));
        assert!(resolve_symbols(&[second, helper, first, caller])
            .1
            .is_empty());
        let mut alias = symbol("second", "alias", true, "external");
        alias.alias_of = Some("missing-original".into());
        assert!(resolve_symbols(&[alias])
            .1
            .iter()
            .any(|issue| issue.contains("lost its original unit provider")));
    }

    #[test]
    fn non_deduplicating_groups_remain_whole_and_do_not_hide_strong_collisions() {
        use o_lang::ocore::native_ir::ComdatSelection;
        let mut a = symbol("a", "engine", true, "external");
        a.comdat = Some(GroupMembership {
            name: "keep-group".into(),
            selection: ComdatSelection::NoDeduplicate,
        });
        let mut b = a.clone();
        b.unit = "b".into();
        assert!(!resolve_symbols(&[a.clone(), b.clone()]).1.is_empty());
        b.name = "another-engine".into();
        let (receipt, issues) = resolve_symbols(&[a.clone(), b.clone()]);
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(
            receipt["comdat_resolutions"][0]["selected_units"],
            json!(["a", "b"])
        );
        b.comdat.as_mut().unwrap().selection = ComdatSelection::Largest;
        assert!(resolve_symbols(&[a, b])
            .1
            .iter()
            .any(|issue| issue.contains("incompatible COMDAT")));
    }

    #[test]
    fn mixed_any_and_non_deduplicating_groups_keep_every_non_deduplicating_group() {
        use o_lang::ocore::native_ir::ComdatSelection;
        let grouped = |unit: &str, name: &str, selection| {
            let mut member = symbol(unit, name, true, "external");
            member.comdat = Some(GroupMembership {
                name: "mixed-group".into(),
                selection,
            });
            member
        };
        let keep_a = grouped("keep-a", "keep-a-engine", ComdatSelection::NoDeduplicate);
        let keep_b = grouped("keep-b", "keep-b-engine", ComdatSelection::NoDeduplicate);
        let any_a = grouped("any-a", "engine", ComdatSelection::Any);
        let any_b = grouped("any-b", "engine", ComdatSelection::Any);
        for (inputs, selected, provider) in [
            (
                vec![keep_a.clone(), any_a.clone(), keep_b.clone(), any_b.clone()],
                json!(["keep-a", "any-a", "keep-b"]),
                "any-a",
            ),
            (
                vec![any_b.clone(), keep_b.clone(), any_a.clone(), keep_a.clone()],
                json!(["any-b", "keep-b", "keep-a"]),
                "any-b",
            ),
        ] {
            let (receipt, issues) = resolve_symbols(&inputs);
            assert!(issues.is_empty(), "{issues:?}");
            assert!(receipt["comdat_resolutions"][0]["selection"].is_null());
            assert_eq!(receipt["comdat_resolutions"][0]["selected_units"], selected);
            let resolution = receipt["export_resolutions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["symbol"] == "engine")
                .unwrap();
            assert_eq!(resolution["selected_unit"], provider);
        }
        let conflicting_keep = grouped("keep-c", "engine", ComdatSelection::NoDeduplicate);
        for inputs in [
            vec![any_a.clone(), conflicting_keep.clone()],
            vec![conflicting_keep, any_a],
        ] {
            let (receipt, issues) = resolve_symbols(&inputs);
            assert!(!issues.is_empty());
            assert_eq!(receipt["closed"], false);
            assert_eq!(
                receipt["comdat_resolutions"][0]["selected_units"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
        }
    }

    #[test]
    fn odr_and_linkonce_linkage_remain_distinct_in_resolution_receipts() {
        for linkage in ["linkonce", "linkonce_odr", "weak_odr"] {
            let first = symbol("first", "engine", true, linkage);
            let second = symbol("second", "engine", true, linkage);
            let (receipt, issues) = resolve_symbols(&[first.clone(), second.clone()]);
            assert!(issues.is_empty());
            assert_eq!(receipt["export_resolutions"][0]["selected_unit"], "first");
            assert_eq!(
                receipt["export_resolutions"][0]["selected_linkage"],
                linkage
            );
            let strong = symbol("strong", "engine", true, "external");
            assert_eq!(
                resolve_symbols(&[first, strong, second]).0["export_resolutions"][0]
                    ["selected_unit"],
                "strong"
            );
        }
    }

    #[test]
    fn cross_module_closure_resolves_only_exported_compatible_definitions() {
        let declaration = symbol("caller", "engine", false, "external");
        let definition = symbol("engine", "engine", true, "external");
        let (closure, issues) = resolve_symbols(&[declaration.clone(), definition.clone()]);
        assert!(issues.is_empty());
        assert_eq!(closure["declarations"][0]["resolved_unit"], "engine");
        let mut private = definition.clone();
        private.linkage = "internal".into();
        assert!(!resolve_symbols(&[declaration.clone(), private])
            .1
            .is_empty());
        let mut wrong = definition;
        wrong.contract["result"]["bits"] = json!(32);
        assert!(!resolve_symbols(&[declaration, wrong]).1.is_empty());
    }

    #[test]
    fn duplicate_exports_fail_while_module_local_names_remain_independent() {
        let definitions = [
            symbol("a", "helper", true, "external"),
            symbol("b", "helper", true, "external"),
        ];
        assert!(!resolve_symbols(&definitions).1.is_empty());
        let locals = [
            symbol("a", "helper", true, "internal"),
            symbol("b", "helper", true, "private"),
        ];
        assert!(resolve_symbols(&locals).1.is_empty());
    }

    #[test]
    fn strong_definition_overrides_weak_in_either_supplied_order() {
        let declaration = symbol("consumer", "engine", false, "external");
        let weak = symbol("weak-provider", "engine", true, "weak");
        let strong = symbol("strong-provider", "engine", true, "external");
        for providers in [
            vec![weak.clone(), strong.clone()],
            vec![strong.clone(), weak.clone()],
        ] {
            let mut inputs = vec![declaration.clone()];
            inputs.extend(providers);
            let (receipt, issues) = resolve_symbols(&inputs);
            assert!(issues.is_empty(), "{issues:?}");
            assert_eq!(receipt["definitions"].as_array().unwrap().len(), 2);
            assert_eq!(
                receipt["declarations"][0]["resolved_unit"],
                "strong-provider"
            );
            assert_eq!(
                receipt["export_resolutions"][0]["selected_unit"],
                "strong-provider"
            );
            assert_eq!(
                receipt["export_resolutions"][0]["selected_linkage"],
                "external"
            );
            assert_eq!(
                receipt["export_resolutions"][0]["candidates"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
        }
        // A weak provider must not hide an ordinary duplicate-definition error.
        assert!(!resolve_symbols(&[
            weak,
            strong,
            symbol("another-strong", "engine", true, "external")
        ])
        .1
        .is_empty());
    }

    #[test]
    fn weak_only_resolution_retains_every_definition_and_selects_first() {
        for order in [["a", "b"], ["b", "a"]] {
            let inputs = [
                symbol("consumer", "engine", false, "external"),
                symbol(order[0], "engine", true, "weak"),
                symbol(order[1], "engine", true, "weak"),
            ];
            let (receipt, issues) = resolve_symbols(&inputs);
            assert!(issues.is_empty(), "{issues:?}");
            assert_eq!(receipt["declarations"][0]["resolved_unit"], order[0]);
            assert_eq!(receipt["export_resolutions"][0]["selected_unit"], order[0]);
            assert_eq!(
                receipt["export_resolutions"][0]["candidates"][0]["unit"],
                order[0]
            );
            assert_eq!(
                receipt["export_resolutions"][0]["candidates"][1]["unit"],
                order[1]
            );
            assert_eq!(receipt["definitions"].as_array().unwrap().len(), 2);
        }
    }

    #[test]
    fn weak_resolution_checks_overridden_abi_and_storage_contracts() {
        let weak = symbol("weak", "engine", true, "weak");
        let mut incompatible = symbol("strong", "engine", true, "external");
        incompatible.contract["result"]["bits"] = json!(32);
        for candidates in [
            vec![weak.clone(), incompatible.clone()],
            vec![incompatible, weak],
        ] {
            let (receipt, issues) = resolve_symbols(&candidates);
            assert!(issues
                .iter()
                .any(|issue| issue.contains("incompatible exported definition")));
            assert_eq!(receipt["closed"], false);
            assert!(receipt["export_resolutions"][0]["selected_unit"].is_null());
        }
        let mut aligned_weak = symbol("weak", "storage", true, "weak");
        aligned_weak.alignment = 64;
        let mut strong = symbol("strong", "storage", true, "external");
        strong.alignment = 8;
        assert!(!resolve_symbols(&[aligned_weak.clone(), strong.clone()])
            .1
            .is_empty());
        strong.alignment = 64;
        assert!(resolve_symbols(&[aligned_weak, strong]).1.is_empty());
        let (receipt, issues) = resolve_symbols(&[symbol(
            "unsupported",
            "engine",
            true,
            "available_externally",
        )]);
        assert!(!issues.is_empty());
        assert_eq!(receipt["closed"], false);
    }

    #[test]
    fn alias_provider_identity_does_not_follow_aliasee_export_selection() {
        let mut source = object_inventory_tests::module();
        source.functions[0].linkage = "weak".into();
        source.types.push(o_lang::ocore::native_ir::Type::Function {
            signature: source.functions[0].signature.clone(),
        });
        source.aliases.push(o_lang::ocore::native_ir::Alias {
            name: "facade".into(),
            ty: 2,
            aliasee: "f".into(),
            linkage: "external".into(),
            visibility: Visibility::Default,
        });
        source.provenance.source_alias_count = 1;
        let mut inputs = symbols("original-body", &source).unwrap();
        let mut replacement = inputs
            .iter()
            .find(|symbol| symbol.name == "f")
            .unwrap()
            .clone();
        replacement.unit = "replacement-body".into();
        replacement.linkage = "external".into();
        inputs.push(replacement);
        let (receipt, issues) = resolve_symbols(&inputs);
        assert!(issues.is_empty(), "{issues:?}");
        let resolutions = receipt["export_resolutions"].as_array().unwrap();
        assert_eq!(
            resolutions
                .iter()
                .find(|entry| entry["symbol"] == "f")
                .unwrap()["selected_unit"],
            "replacement-body"
        );
        let alias = resolutions
            .iter()
            .find(|entry| entry["symbol"] == "facade")
            .unwrap();
        assert_eq!(alias["selected_unit"], "original-body");
        assert_eq!(alias["candidates"][0]["alias_of"], "f");
        assert_eq!(alias["candidates"][0]["unit"], "original-body");
    }

    #[test]
    fn static_image_merges_visibility_constraints_without_losing_closure() {
        let definition = symbol("engine", "engine", true, "external");
        let mut protected = symbol("consumer_a", "engine", false, "external");
        protected.visibility = Visibility::Protected;
        let mut hidden = symbol("consumer_b", "engine", false, "external");
        hidden.visibility = Visibility::Hidden;
        let (closure, issues) = resolve_symbols(&[definition.clone(), protected.clone()]);
        assert!(issues.is_empty());
        assert_eq!(closure["image_visibility"]["engine"], "protected");
        let (closure, issues) = resolve_symbols(&[definition, protected, hidden.clone()]);
        assert!(issues.is_empty());
        assert_eq!(closure["image_visibility"]["engine"], "hidden");
        assert!(!resolve_symbols(&[hidden]).1.is_empty());
    }

    #[test]
    fn verified_owned_intrinsics_resolve_without_ambient_native_symbols() {
        for name in ["llvm.assume", "llvm.trap"] {
            let mut declaration = symbol("unit", name, false, "external");
            declaration.intrinsic = Some(name.into());
            let (receipt, issues) = resolve_symbols(&[declaration.clone()]);
            assert!(issues.is_empty());
            assert_eq!(
                receipt["declarations"][0]["resolved_provider"],
                "ocore-native-v1"
            );
            declaration.intrinsic = Some("llvm.unknown".into());
            assert!(!resolve_symbols(&[declaration]).1.is_empty());
        }
    }

    #[test]
    fn checked_integer_intrinsics_resolve_only_with_implemented_widths() {
        for arithmetic in ["add", "sub", "mul"] {
            for signedness in ["s", "u"] {
                for width in 1..=64 {
                    let name = format!("llvm.{signedness}{arithmetic}.with.overflow.i{width}");
                    let mut declaration = symbol("unit", &name, false, "external");
                    declaration.intrinsic = Some(name);
                    let (receipt, issues) = resolve_symbols(&[declaration]);
                    assert!(issues.is_empty(), "{issues:?}");
                    assert_eq!(
                        receipt["declarations"][0]["resolved_provider"],
                        "ocore-native-v1"
                    );
                }
                for suffix in ["i0", "i65", "i128", "v2i64", "i064"] {
                    let name = format!("llvm.{signedness}{arithmetic}.with.overflow.{suffix}");
                    let mut declaration = symbol("unit", &name, false, "external");
                    declaration.intrinsic = Some(name);
                    assert!(!resolve_symbols(&[declaration]).1.is_empty());
                }
            }
        }
    }

    #[test]
    fn global_definition_must_satisfy_declared_alignment() {
        let mut declaration = symbol("a", "storage", false, "external");
        declaration.alignment = 64;
        let mut definition = symbol("b", "storage", true, "external");
        definition.alignment = 8;
        assert!(!resolve_symbols(&[declaration.clone(), definition.clone()])
            .1
            .is_empty());
        definition.alignment = 64;
        assert!(resolve_symbols(&[declaration, definition]).1.is_empty());
    }

    #[test]
    fn abi_comparison_normalizes_module_local_type_ids() {
        let module = |types: Value, result: usize| -> NativeModule {
            let bytes = serde_json::to_vec(&json!({
                "format":"ocore-native-module-v1","name":"declaration",
                "target":{"triple":"x86_64-unknown-none","data_layout":"e-p:64:64-i64:64","pointer_bits":64,"little_endian":true},
                "semantics":"llvm_defined_behavior_v1","types":types,"globals":[],
                "functions":[{"name":"engine","linkage":"external","signature":{"params":[],"result":result,"abi":"c","variadic":false},"params":[],"entry":null,"blocks":[]}],
                "provenance":{"input_sha256":"0".repeat(64),"frontend":"test","frontend_version":"1","importer":"test","importer_version":"1","source_function_count":1,"source_global_count":0,"refinements":[]}
            })).unwrap();
            NativeModule::from_json(&bytes).unwrap()
        };
        let first = module(json!([{"kind":"void"},{"kind":"int","bits":64}]), 1);
        let reordered = module(json!([{"kind":"int","bits":64},{"kind":"void"}]), 0);
        assert_eq!(
            symbols("a", &first).unwrap()[0].contract,
            symbols("b", &reordered).unwrap()[0].contract
        );
        let incompatible = module(json!([{"kind":"int","bits":32},{"kind":"void"}]), 0);
        assert_ne!(
            symbols("a", &first).unwrap()[0].contract,
            symbols("b", &incompatible).unwrap()[0].contract
        );
    }

    #[test]
    fn return_storage_contract_preserves_layout_and_normalizes_type_ids() {
        let module = |reordered: bool, layout: &str| -> NativeModule {
            let (types, void, ptr, integer, storage) = if reordered {
                (
                    json!([{"kind":"struct","fields":[4,2],"packed":false},
                    {"kind":"pointer","address_space":0},{"kind":"int","bits":64},
                    {"kind":"void"},{"kind":"int","bits":8}]),
                    3,
                    1,
                    2,
                    0,
                )
            } else {
                (
                    json!([{"kind":"void"},{"kind":"int","bits":8},
                    {"kind":"int","bits":64},{"kind":"pointer","address_space":0},
                    {"kind":"struct","fields":[1,2],"packed":false}]),
                    0,
                    3,
                    2,
                    4,
                )
            };
            serde_json::from_value(json!({
                "format":"ocore-native-module-v1","name":"sret-contract",
                "target":{"triple":"x86_64-unknown-none","data_layout":layout,"pointer_bits":64,"little_endian":true},
                "semantics":"llvm_defined_behavior_v1","types":types,"globals":[],
                "functions":[{"name":"engine","linkage":"external",
                    "signature":{"params":[ptr,integer],"result":void,"abi":"c","variadic":false,
                        "return_storage":{"param":0,"ty":storage}},"params":[],"entry":null,"blocks":[]}],
                "provenance":{"input_sha256":"0".repeat(64),"frontend":"test","frontend_version":"1",
                    "importer":"test","importer_version":"1","source_function_count":1,"source_global_count":0,"refinements":[]}
            })).unwrap()
        };
        let first = module(false, "e-p:64:64-i64:64");
        let reordered = module(true, "e-p:64:64-i64:64");
        let contract = |m: &NativeModule| symbols("unit", m).unwrap()[0].contract.clone();
        assert_eq!(contract(&first), contract(&reordered));
        assert_ne!(
            contract(&first),
            contract(&module(false, "e-p:64:64-i64:32"))
        );
        let mut erased = first.clone();
        erased.functions[0].signature.return_storage = None;
        assert_ne!(contract(&first), contract(&erased));
        let mut moved = first.clone();
        moved.functions[0].signature.params = vec![3, 3];
        let original_position = moved.clone();
        moved.functions[0]
            .signature
            .return_storage
            .as_mut()
            .unwrap()
            .param = 1;
        assert_ne!(contract(&moved), contract(&original_position));
        let mut different_storage = first.clone();
        different_storage.functions[0]
            .signature
            .return_storage
            .as_mut()
            .unwrap()
            .ty = 2;
        assert_ne!(contract(&first), contract(&different_storage));
    }

    #[test]
    fn capture_cannot_drop_invocation_units_or_required_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let inventory_path = directory.path().join("inventory.json");
        let inventory = json!({"schema":"ocore-runtime-unit-inventory-v1","complete":true,
            "units":[{"id":"r","kind":"clang","source":"u.c"}]});
        let bytes = serde_json::to_vec(&inventory).unwrap();
        fs::write(&inventory_path, &bytes).unwrap();
        let unit = json!({"id":"u","ir":{"path":"/input/u.ll","format":"llvm-text"}});
        let mut capture = json!({"schema":CAPTURE_FORMAT,"capture_complete":true,"unit_inventory_complete":true,
            "issues":[],"failed_required_units":[],"uncaptured_outputs":[],"units":[unit.clone()],
            "unit_roles_complete":true,"unclassified_unit_ids":[],"lowering_unit_ids":["u"],"non_lowering_units":[],
            "unit_inventory":{"file":{"path":inventory_path,"sha256":digest(&bytes),"bytes":bytes.len()},"definition":inventory},
            "required_units":[{"id":"r","complete":true,"failed_invocation_ids":[],"captured_unit_ids":["u"]}],
            "invocations":[{"id":"i","state":"finished","capture_errors":[],"units":[unit]}]});
        assert!(capture_issues(&capture).is_empty());
        let mut bitcode = capture.clone();
        bitcode["units"][0]["ir"]["format"] = json!("llvm-bitcode");
        bitcode["invocations"][0]["units"][0]["ir"]["format"] = json!("llvm-bitcode");
        assert!(capture_issues(&bitcode).is_empty());
        bitcode["invocations"][0]["units"] = json!([]);
        assert!(!capture_issues(&bitcode).is_empty());
        for format in [json!("native-object"), json!(""), Value::Null, json!(true)] {
            let mut invalid = capture.clone();
            invalid["units"][0]["ir"]["format"] = format.clone();
            invalid["invocations"][0]["units"][0]["ir"]["format"] = format;
            assert!(!capture_issues(&invalid).is_empty());
        }
        let mut invalid = capture.clone();
        invalid["lowering_unit_ids"] = json!([]);
        assert!(!capture_issues(&invalid).is_empty());
        invalid = capture.clone();
        invalid["non_lowering_units"] = json!([{"unit_id":"u","role":"configure_probe"}]);
        assert!(!capture_issues(&invalid).is_empty());
        invalid = capture.clone();
        invalid["unit_inventory"]["definition"]["units"][0]["source"] = json!("other.c");
        assert!(!capture_issues(&invalid).is_empty());
        capture["units"] = json!([]);
        assert!(!capture_issues(&capture).is_empty());
        capture["units"] =
            json!([{"id":"different","ir":{"path":"/input/u.ll","format":"llvm-text"}}]);
        assert!(!capture_issues(&capture).is_empty());
    }

    #[test]
    fn hash_and_isa_mismatch_fail_before_import() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unit.ll");
        let bytes = b"target triple = \"x86_64-unknown-none\"\n";
        fs::write(&path, bytes).unwrap();
        let mut unit = json!({"ir":{"path":path,"format":"llvm-text","sha256":digest(bytes),
            "bytes":bytes.len(),"target_triple":"x86_64-unknown-none","data_layout":"e-p:64:64"}});
        assert!(checked_ir(&unit, "x86_64").is_ok());
        assert!(checked_ir(&unit, "aarch64").is_err());
        unit["ir"]["sha256"] = json!("0".repeat(64));
        assert!(checked_ir(&unit, "x86_64").is_err());
    }

    #[test]
    fn captured_bitcode_requires_matching_bytes_and_retains_hash_size_and_target_guards() {
        let directory = tempfile::tempdir().unwrap();
        // These headers exercise admission only. The LLVM importer independently
        // parses the complete module before any native verification or emission.
        let path = directory.path().join("unit.input");
        for bytes in [b"BC\xc0\xde".as_slice(), b"\xde\xc0\x17\x0b".as_slice()] {
            fs::write(&path, bytes).unwrap();
            let unit = json!({"ir":{"path":path,"format":"llvm-bitcode",
                "sha256":digest(bytes),"bytes":bytes.len(),
                "target_triple":"x86_64-unknown-none","data_layout":"e-p:64:64"}});
            assert!(checked_ir(&unit, "x86_64").is_ok());
            assert!(checked_ir(&unit, "aarch64").is_err());
            for (field, value) in [
                ("format", json!("llvm-text")),
                ("format", json!("native-object")),
                ("sha256", json!("0".repeat(64))),
                ("bytes", json!(bytes.len() + 1)),
                ("data_layout", json!("")),
            ] {
                let mut invalid = unit.clone();
                invalid["ir"][field] = value;
                assert!(checked_ir(&invalid, "x86_64").is_err(), "{field}");
            }
        }
        for bytes in [
            b"not LLVM bitcode".as_slice(),
            b"BC\xc0".as_slice(),
            b"".as_slice(),
        ] {
            fs::write(&path, bytes).unwrap();
            let unit = json!({"ir":{"path":path,"format":"llvm-bitcode",
                "sha256":digest(bytes),"bytes":bytes.len(),
                "target_triple":"x86_64-unknown-none","data_layout":"e-p:64:64"}});
            assert!(checked_ir(&unit, "x86_64").is_err());
        }
    }

    #[test]
    fn captured_ir_representation_cannot_be_omitted_or_inferred_from_filename() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unit.bc");
        let bytes = b"target triple = \"x86_64-unknown-none\"\n";
        fs::write(&path, bytes).unwrap();
        let unit = json!({"ir":{"path":path,"format":"llvm-text","sha256":digest(bytes),
            "bytes":bytes.len(),"target_triple":"x86_64-unknown-none","data_layout":"e-p:64:64"}});
        assert!(checked_ir(&unit, "x86_64").is_ok());
        let mut invalid = unit.clone();
        invalid["ir"].as_object_mut().unwrap().remove("format");
        assert!(checked_ir(&invalid, "x86_64").is_err());
        invalid = unit;
        invalid["ir"]["format"] = json!("llvm-bitcode");
        assert!(checked_ir(&invalid, "x86_64").is_err());
    }

    #[test]
    fn incomplete_capture_retains_fail_closed_receipt_and_never_launches_compiler() {
        let directory = tempfile::tempdir().unwrap();
        let report = directory.path().join("report.json");
        fs::write(
            &report,
            serde_json::to_vec(&json!({"schema":CAPTURE_FORMAT,"capture_complete":false,
            "units":[{"id":"u","ir":{"path":"/absent.ll"}}]}))
            .unwrap(),
        )
        .unwrap();
        let output = directory.path().join("result");
        assert!(compile_with_compiler(
            &report,
            "x86_64",
            "ir",
            &output,
            NativeImportOptions {
                llvm_library: None,
                llvm_sha256: None,
                tls_profile: None,
                atomic_profile: None,
            },
            Path::new("/compiler-must-not-run")
        )
        .is_err());
        let receipt: Value =
            serde_json::from_slice(&fs::read(output.join("coverage.json")).unwrap()).unwrap();
        assert_eq!(receipt["captured_unit_count"], 1);
        assert_eq!(receipt["lowered_unit_count"], 0);
        assert_eq!(receipt["artifact_complete"], false);
        assert_eq!(receipt["runtime_complete"], false);
    }
}
