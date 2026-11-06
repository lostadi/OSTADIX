//! Exact original capture/action -> consumed LLVM -> verified MIR -> object lineage.
//!
//! This is a private compiler-owned contract, not an artifact admission token.
//! Only `reverify` constructs AdmittedCapture in production. Serialized diagnostics
//! cannot reconstruct it, grant frontend-default completeness, or prove final link.
//! File rechecks below establish byte identity at the observed reads only. They
//! follow paths and do not establish inode/no-alias, mode, or pre-exec tool custody.

use super::*;
use serde::Serialize;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

const FORMAT: &str = "ocore-source-action-unit-lineage-v1";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct BytesIdentity {
    path: String,
    sha256: String,
    bytes: u64,
}

impl BytesIdentity {
    fn consumed(path: &Path, bytes: &[u8]) -> Self {
        Self { path: path.display().to_string(), sha256: digest(bytes), bytes: bytes.len() as u64 }
    }
    fn check(&self) -> Result<()> {
        let raw = fs::read(&self.path).with_context(|| format!("lineage evidence unavailable: {}", self.path))?;
        if Self::consumed(Path::new(&self.path), &raw) != *self {
            bail!("lineage evidence changed: {}", self.path);
        }
        Ok(())
    }
}

fn strings(value: &Value, context: &str) -> Result<Vec<String>> {
    value.as_array().with_context(|| format!("{context} must be an array"))?.iter()
        .map(|v| v.as_str().map(str::to_owned).with_context(|| format!("{context} contains a non-string")))
        .collect()
}
fn unique_ids(value: &Value, context: &str) -> Result<BTreeSet<String>> {
    let ids = strings(value, context)?;
    let result: BTreeSet<_> = ids.iter().cloned().collect();
    if ids.len() != result.len() || ids.iter().any(String::is_empty) {
        bail!("{context} contains duplicate or empty IDs");
    }
    Ok(result)
}
fn file_record(value: &Value, context: &str) -> Result<()> {
    let path = string(value, "path")?;
    let sha = string(value, "sha256")?;
    if !Path::new(path).is_absolute() || sha.len() != 64
        || !sha.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || value["bytes"].as_u64().is_none() {
        bail!("{context} is not an exact original file identity");
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct UnitOwner {
    unit: Value,
    action: Value,
}

// Deliberately no Serialize/Deserialize implementation: no claimed receipt or
// caller boolean can create the production capability used by the lowering loop.
pub(super) struct AdmittedCapture {
    path: PathBuf,
    raw: Vec<u8>,
    receipt: Value,
    capture: Value,
    selected: BTreeSet<String>,
    units: BTreeMap<String, UnitOwner>,
}

impl AdmittedCapture {
    pub(super) fn reverify(
        path: &Path, raw: &[u8], selected: &BTreeSet<String>, output: &Path, python: &Path,
    ) -> Result<Self> {
        let receipt = reverify_capture_with_python(path, raw, output, python)?;
        Self::bind_reverified(path, raw, selected, receipt)
    }

    // Private and called after the actual embedded capture verifier above.
    // Tests below exercise this binding layer with explicitly authored receipts.
    fn bind_reverified(path: &Path, raw: &[u8], selected: &BTreeSet<String>, receipt: Value) -> Result<Self> {
        let capture: Value = serde_json::from_slice(raw).context("decode held capture bytes")?;
        if capture["schema"] != CAPTURE_FORMAT
            || receipt["schema"] != "ocore-runtime-capture-verification-v1"
            || receipt["verified"] != true
            || receipt["scope"] != "source-capture-unit-role-partition-and-observed-native-output-membership"
            || receipt["admitted_report"] != json!({"path":path,"sha256":digest(raw),"bytes":raw.len()}) {
            bail!("capture verifier receipt differs from the held report bytes");
        }
        if receipt["capture_worker_sha256"] != digest(include_str!("../../../../scripts/ocore_runtime_capture.py").as_bytes())
            || receipt["producer_registry_sha256"] != digest(include_str!("../../../../scripts/ocore_producer_registry.json").as_bytes()) {
            bail!("capture verifier worker/producer implementation differs");
        }
        let original_units = array(&capture, "units")?;
        if original_units.is_empty() || receipt["provenance_unit_count"].as_u64() != Some(original_units.len() as u64)
            || receipt["inventory"] != capture["unit_inventory"]["file"] {
            bail!("capture verifier inventory binding differs");
        }
        if unique_ids(&capture["lowering_unit_ids"], "capture lowering IDs")? != *selected
            || unique_ids(&receipt["lowering_unit_ids"], "verified lowering IDs")? != *selected {
            bail!("capture verified lowering selection differs");
        }
        for key in ["source", "manifest", "capture_worker", "producer_capabilities", "tools", "unit_inventory"] {
            if !capture[key].is_object() { bail!("capture original provenance is unavailable: {key}"); }
        }
        let mut flattened = BTreeMap::new();
        for unit in original_units {
            let id = string(unit, "id")?;
            if id.is_empty() || flattened.insert(id.to_owned(), unit).is_some() {
                bail!("duplicate or empty flattened captured unit ID");
            }
        }
        let mut actions = BTreeSet::new();
        let mut units = BTreeMap::new();
        for action in array(&capture, "invocations")? {
            let action_id = string(action, "id")?;
            if action_id.is_empty() || !actions.insert(action_id.to_owned()) {
                bail!("duplicate or empty original action ID");
            }
            for unit in array(action, "units")? {
                if unit.get("ir").is_none() { continue; }
                let id = string(unit, "id")?;
                if flattened.get(id).copied() != Some(unit) {
                    bail!("original action unit differs from flattened capture: {id}");
                }
                if action["state"] != "finished" || action["exit_code"] != 0
                    || !array(action, "capture_errors")?.is_empty() {
                    bail!("original producing action did not complete: {action_id}");
                }
                for key in ["producer", "kind", "driver_kind", "compiler", "cwd"] {
                    if string(action, key)?.is_empty() { bail!("original action provenance unavailable: {key}"); }
                }
                if !Path::new(string(action, "cwd")?).is_absolute()
                    || strings(&action["argv"], "original action argv")?.is_empty()
                    || !action["frontend"].is_object() || !action["build_environment"].is_object() {
                    bail!("original action command/frontend provenance unavailable: {action_id}");
                }
                if unit["kind"] != action["kind"] { bail!("original action/unit producer kind differs: {id}"); }
                file_record(&unit["source"], "original source")?;
                file_record(&unit["ir"], "original LLVM input")?;
                array(unit, "dependencies")?;
                if units.insert(id.to_owned(), UnitOwner { unit: unit.clone(), action: action.clone() }).is_some() {
                    bail!("duplicate original unit owner: {id}");
                }
            }
        }
        if units.keys().cloned().collect::<BTreeSet<_>>() != flattened.keys().cloned().collect::<BTreeSet<_>>()
            || !selected.iter().all(|id| units.contains_key(id)) {
            bail!("missing or extra original action/unit ownership");
        }
        Ok(Self { path: path.to_owned(), raw: raw.to_vec(), receipt, capture, selected: selected.clone(), units })
    }

    pub(super) fn receipt(&self) -> &Value { &self.receipt }

    pub(super) fn begin(
        &self, id: &str, unit: &Value, raw: &[u8], owned_input: &Path, compiler: &Path, compiler_sha: &str,
    ) -> Result<UnitLineage> {
        let owner = self.units.get(id).context("unit has no admitted producing action")?;
        if !self.selected.contains(id) || &owner.unit != unit {
            bail!("lowered unit differs from the admitted action selection");
        }
        if unit["ir"]["sha256"] != digest(raw) || unit["ir"]["bytes"].as_u64() != Some(raw.len() as u64) {
            bail!("consumed LLVM buffer differs from admitted original unit");
        }
        let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(owned_input)?;
        file.write_all(raw)?;
        file.sync_all()?;
        drop(file);
        let consumed = BytesIdentity::consumed(owned_input, raw);
        consumed.check()?;
        let compiler_raw = fs::read(compiler).context("read lineage compiler")?;
        if digest(&compiler_raw) != compiler_sha { bail!("lineage compiler changed before import"); }
        let original = BytesIdentity {
            path: string(&unit["ir"], "path")?.to_owned(), sha256: digest(raw), bytes: raw.len() as u64,
        };
        let compiler = BytesIdentity::consumed(compiler, &compiler_raw);
        let capture = json!({"report":{"path":self.path,"sha256":digest(&self.raw),"bytes":self.raw.len()},
            "manifest":self.capture["manifest"],"source":self.capture["source"],
            "capture_worker":self.capture["capture_worker"],"producer_capabilities":self.capture["producer_capabilities"],
            "inventory":self.capture["unit_inventory"],"verification":self.receipt});
        Ok(UnitLineage { schema: FORMAT, capture, original_action: owner.action.clone(), original_unit: owner.unit.clone(),
            original_llvm: original.clone(), consumed_llvm: consumed.clone(), compiler: compiler.clone(),
            imported_mir: None, verification: None, imported_target: None, emitted_object: None, emission_argv: None,
            object_inventory: None, final_byte_identity_stable: false, original_frontend_defaults_qualified: false,
            original_abi_qualified: false, final_link_qualified: false, runtime_qualified: false,
            physical_file_identity_qualified: false, preexec_tool_closure_qualified: false,
            guards: vec![original, consumed, compiler] })
    }

    pub(super) fn postguard(&self, output: &Path, python: &Path) -> Result<Value> {
        if fs::read(&self.path)? != self.raw { bail!("held source capture changed before final reverification"); }
        let directory = output.join("source-action-capture-postguard");
        fs::create_dir(&directory)?;
        let after = Self::reverify(&self.path, &self.raw, &self.selected, &directory, python)?;
        if after.capture != self.capture || after.units.keys().collect::<Vec<_>>() != self.units.keys().collect::<Vec<_>>() {
            bail!("source action ownership changed during lowering");
        }
        if fs::read(&self.path)? != self.raw { bail!("held source capture changed during final reverification"); }
        Ok(after.receipt)
    }
}

#[derive(Debug, Serialize)]
pub(super) struct UnitLineage {
    schema: &'static str,
    capture: Value,
    original_action: Value,
    original_unit: Value,
    original_llvm: BytesIdentity,
    consumed_llvm: BytesIdentity,
    compiler: BytesIdentity,
    imported_mir: Option<BytesIdentity>,
    verification: Option<BytesIdentity>,
    imported_target: Option<Value>,
    emitted_object: Option<BytesIdentity>,
    emission_argv: Option<Vec<String>>,
    object_inventory: Option<Value>,
    final_byte_identity_stable: bool,
    // Retaining selected records is not proof of these independent mechanisms.
    original_frontend_defaults_qualified: bool,
    original_abi_qualified: bool,
    final_link_qualified: bool,
    runtime_qualified: bool,
    physical_file_identity_qualified: bool,
    preexec_tool_closure_qualified: bool,
    #[serde(skip)]
    guards: Vec<BytesIdentity>,
}

impl UnitLineage {
    fn join_verified(
        &mut self, input_sha: &str, target: Value, mir_path: &Path, mir: &[u8], receipt_path: &Path, receipt_raw: &[u8],
    ) -> Result<()> {
        if self.imported_mir.is_some() { bail!("verified MIR lineage cannot be rebound"); }
        let receipt: Value = serde_json::from_slice(receipt_raw).context("decode consumed native verification receipt")?;
        if input_sha != self.original_llvm.sha256
            || target["triple"] != self.original_unit["ir"]["target_triple"]
            || target["data_layout"] != self.original_unit["ir"]["data_layout"] {
            bail!("verified MIR lineage input/target differs from original LLVM");
        }
        if receipt["format"] != "ocore-native-verification-v1" || receipt["verifier"] != "ocore-native-v1"
            || receipt["scope"] != "structural_ir_verification" || receipt["verified"] != true
            || receipt["module_sha256"] != digest(mir) {
            bail!("verified MIR lineage receipt differs from consumed MIR");
        }
        let imported = BytesIdentity::consumed(mir_path, mir);
        let verification = BytesIdentity::consumed(receipt_path, receipt_raw);
        self.guards.extend([imported.clone(), verification.clone()]);
        self.imported_mir = Some(imported);
        self.verification = Some(verification);
        self.imported_target = Some(target);
        Ok(())
    }

    pub(super) fn verified(
        &mut self, module: &NativeModule, mir_path: &Path, mir: &[u8], receipt_path: &Path, receipt_raw: &[u8],
    ) -> Result<()> {
        self.join_verified(&module.provenance.input_sha256, serde_json::to_value(&module.target)?,
            mir_path, mir, receipt_path, receipt_raw)
    }

    pub(super) fn observe_object(&mut self, path: &Path, raw: &[u8], argv: &[String]) -> Result<()> {
        if self.imported_mir.is_none() { bail!("object lineage requires the verified MIR join"); }
        if self.emitted_object.is_some() { bail!("object lineage cannot be rebound"); }
        let identity = BytesIdentity::consumed(path, raw);
        self.guards.push(identity.clone());
        self.emitted_object = Some(identity);
        self.emission_argv = Some(argv.to_vec());
        Ok(())
    }

    pub(super) fn checked_object_inventory(&mut self, inventory: &Value) -> Result<()> {
        if self.emitted_object.is_none() || self.object_inventory.is_some() {
            bail!("object inventory has no unique observed emission");
        }
        self.object_inventory = Some(inventory.clone());
        Ok(())
    }

    pub(super) fn postguard(&mut self) -> Result<()> {
        self.final_byte_identity_stable = false;
        for identity in &self.guards { identity.check()?; }
        self.final_byte_identity_stable = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, BTreeSet<String>) {
        let unit = json!({"id":"action-1:0","kind":"clang","source":{"path":"/original/a.c","sha256":"a".repeat(64),"bytes":9},
            "ir":{"path":"/capture/units/a/input.ll","sha256":digest(b"original LLVM"),"bytes":13,"format":"llvm-ir","target_triple":"riscv64-unknown-linux-gnu","data_layout":"e-m:e-p:64:64-i64:64-n32:64-S128"},
            "dependencies":[],"replay_argv":["/tool/clang","-O2","-emit-llvm","a.c"],"replay_exit_code":0});
        let action = json!({"id":"action-1","kind":"clang","producer":"clang-llvm","driver_kind":"clang","compiler":"/tool/clang","cwd":"/original",
            "argv":["-O2","-fPIC","-c","a.c","-o","a.o"],"frontend":{"path":"/tool/clang","version":"22","target":"riscv64-unknown-linux-gnu"},
            "build_environment":{"CFLAGS":"-O2 -fPIC"},"state":"finished","exit_code":0,"capture_errors":[],"units":[unit.clone()]});
        let capture = json!({"schema":CAPTURE_FORMAT,"source":{"commit":"original"},"manifest":{"path":"/original/recipe.json"},"capture_worker":{},
            "producer_capabilities":{},"tools":{},"unit_inventory":{"file":{"path":"/capture/inventory.json","sha256":"b".repeat(64),"bytes":7}},
            "units":[unit],"invocations":[action],"lowering_unit_ids":["action-1:0"]});
        (capture, BTreeSet::from(["action-1:0".to_owned()]))
    }
    fn receipt(raw: &[u8], capture: &Value) -> Value {
        json!({"schema":"ocore-runtime-capture-verification-v1","verified":true,
            "scope":"source-capture-unit-role-partition-and-observed-native-output-membership",
            "admitted_report":{"path":"/capture/report.json","sha256":digest(raw),"bytes":raw.len()},
            "capture_worker_sha256":digest(include_str!("../../../../scripts/ocore_runtime_capture.py").as_bytes()),
            "producer_registry_sha256":digest(include_str!("../../../../scripts/ocore_producer_registry.json").as_bytes()),
            "provenance_unit_count":capture["units"].as_array().unwrap().len(),"inventory":capture["unit_inventory"]["file"],
            "lowering_unit_ids":capture["lowering_unit_ids"]})
    }
    fn bind(capture: &Value, selected: &BTreeSet<String>) -> Result<AdmittedCapture> {
        let raw = serde_json::to_vec(capture)?;
        AdmittedCapture::bind_reverified(Path::new("/capture/report.json"), &raw, selected, receipt(&raw, capture))
    }
    fn error(capture: &Value, selected: &BTreeSet<String>, why: &str) {
        match bind(capture, selected) { Ok(_) => panic!("mutated fixture unexpectedly admitted"), Err(e) => assert!(e.to_string().contains(why),"{e}") }
    }
    fn lineage() -> UnitLineage {
        let (capture, _) = fixture();
        let original = BytesIdentity::consumed(Path::new("/original/input.ll"), b"original LLVM");
        UnitLineage { schema:FORMAT,capture:Value::Null,original_action:capture["invocations"][0].clone(),original_unit:capture["units"][0].clone(),
            original_llvm:original.clone(),consumed_llvm:original.clone(),compiler:original,
            imported_mir:None,verification:None,imported_target:None,emitted_object:None,emission_argv:None,object_inventory:None,
            final_byte_identity_stable:false,original_frontend_defaults_qualified:false,original_abi_qualified:false,final_link_qualified:false,runtime_qualified:false,physical_file_identity_qualified:false,preexec_tool_closure_qualified:false,guards:Vec::new() }
    }
    fn target() -> Value { let (c,_) = fixture();json!({"triple":c["units"][0]["ir"]["target_triple"],"data_layout":c["units"][0]["ir"]["data_layout"],"abi":"lp64d"}) }
    fn verification(mir: &[u8]) -> Vec<u8> { serde_json::to_vec(&json!({"format":"ocore-native-verification-v1","verifier":"ocore-native-v1","scope":"structural_ir_verification","verified":true,"module_sha256":digest(mir)})).unwrap() }
    #[test]
    fn serialized_capture_preserves_action_unit_command_and_unqualified_boundaries() {
        let (c,s) = fixture();let raw=serde_json::to_vec(&c).unwrap();let decoded:Value=serde_json::from_slice(&raw).unwrap();
        let got=bind(&decoded,&s).unwrap();let owner=&got.units["action-1:0"];
        assert_eq!(owner.action["argv"],json!(["-O2","-fPIC","-c","a.c","-o","a.o"]));
        assert_eq!(owner.action["producer"],"clang-llvm");assert_eq!(owner.unit["replay_argv"],c["units"][0]["replay_argv"]);
        let l=serde_json::to_value(lineage()).unwrap();for key in ["original_frontend_defaults_qualified","original_abi_qualified","final_link_qualified","runtime_qualified","physical_file_identity_qualified","preexec_tool_closure_qualified"] {assert_eq!(l[key],false);}
    }
    #[test]
    fn held_capture_receipt_hash_cannot_be_rebound_by_serialization() {
        let (c,s)=fixture();let raw=serde_json::to_vec(&c).unwrap();let mut r=receipt(&raw,&c);r["admitted_report"]["sha256"]=json!("0".repeat(64));
        assert_ne!(r["admitted_report"]["sha256"],digest(&raw));
        let e=AdmittedCapture::bind_reverified(Path::new("/capture/report.json"),&raw,&s,r).err().unwrap();assert!(e.to_string().contains("held report bytes"));
    }
    #[test]
    fn duplicate_original_action_and_unit_owners_are_rejected() {
        let (mut c,s)=fixture();let a=c["invocations"][0].clone();c["invocations"].as_array_mut().unwrap().push(a);assert_eq!(c["invocations"].as_array().unwrap().len(),2);error(&c,&s,"duplicate or empty original action ID");
        c["invocations"][1]["id"]=json!("action-2");assert_eq!(c["invocations"][1]["units"][0]["id"],"action-1:0");error(&c,&s,"duplicate original unit owner");
    }
    #[test]
    fn missing_extra_and_changed_original_unit_joins_are_rejected() {
        let (base,s)=fixture();let mut c=base.clone();c["invocations"][0]["units"]=json!([]);assert!(c["invocations"][0]["units"].as_array().unwrap().is_empty());error(&c,&s,"missing or extra original action/unit ownership");
        c=base.clone();c["invocations"][0]["units"][0]["id"]=json!("unlisted:0");assert_ne!(c["invocations"][0]["units"][0]["id"],base["units"][0]["id"]);error(&c,&s,"differs from flattened capture");
        c=base.clone();c["units"][0]["ir"]["sha256"]=json!("f".repeat(64));assert_ne!(c["units"][0],c["invocations"][0]["units"][0]);error(&c,&s,"differs from flattened capture");
    }
    #[test]
    fn selected_units_and_missing_action_provenance_fail_closed() {
        let (c,_) = fixture();error(&c,&BTreeSet::new(),"verified lowering selection differs");
        let (_,s)=fixture();let mut c=c;c["invocations"][0].as_object_mut().unwrap().remove("producer");assert!(c["invocations"][0].get("producer").is_none());error(&c,&s,"producer");
    }
    #[test]
    fn consumed_mir_receipt_input_and_target_have_exact_independent_joins() {
        let mir=b"verified MIR";let r=verification(mir);let mut l=lineage();let sha=l.original_llvm.sha256.clone();
        l.join_verified(&sha,target(),Path::new("/owned/module.json"),mir,Path::new("/owned/verify.json"),&r).unwrap();
        let v=serde_json::to_value(&l).unwrap();assert_eq!(v["imported_mir"]["sha256"],digest(mir));assert_eq!(v["verification"]["sha256"],digest(&r));
        let mut bad=lineage();let e=bad.join_verified(&"0".repeat(64),target(),Path::new("/m"),mir,Path::new("/v"),&r).unwrap_err();assert!(e.to_string().contains("input/target differs"));
        let mut t=target();t["triple"]=json!("x86_64-unknown-linux-gnu");assert_ne!(t,target());let mut bad=lineage();assert!(bad.join_verified(&sha,t,Path::new("/m"),mir,Path::new("/v"),&r).unwrap_err().to_string().contains("input/target differs"));
        let mut t=target();t["data_layout"]=json!("e-p:32:32");assert_ne!(t,target());let mut bad=lineage();assert!(bad.join_verified(&sha,t,Path::new("/m"),mir,Path::new("/v"),&r).unwrap_err().to_string().contains("input/target differs"));
        let wrong=verification(b"different MIR");assert_ne!(wrong,r);let mut bad=lineage();assert!(bad.join_verified(&sha,target(),Path::new("/m"),mir,Path::new("/v"),&wrong).unwrap_err().to_string().contains("receipt differs"));
    }
    #[test]
    fn wrong_consumed_llvm_buffer_rejects_before_owned_copy_or_compiler_access() {
        let (c,s)=fixture();let admitted=bind(&c,&s).unwrap();
        let dir=std::env::temp_dir().join(format!("ostadix-source-input-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&dir).unwrap();let owned=dir.join("input.ll");let wrong=b"wrong LLVM";
        assert_ne!(digest(wrong),c["units"][0]["ir"]["sha256"]);assert!(!owned.exists());
        let e=admitted.begin("action-1:0",&c["units"][0],wrong,&owned,Path::new("/not-an-observed-compiler"),"unused").unwrap_err();
        assert!(e.to_string().contains("consumed LLVM buffer differs"));assert!(!owned.exists());fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn object_observation_requires_unique_verified_mir_and_keeps_failure_stage_bytes() {
        let mut l=lineage();let args=vec!["--emit".into(),"obj".into()];assert!(l.observe_object(Path::new("/object"),b"object",&args).unwrap_err().to_string().contains("verified MIR join"));
        let sha=l.original_llvm.sha256.clone();l.join_verified(&sha,target(),Path::new("/m"),b"MIR",Path::new("/v"),&verification(b"MIR")).unwrap();
        l.observe_object(Path::new("/object"),b"object",&args).unwrap();let v=serde_json::to_value(&l).unwrap();assert_eq!(v["emitted_object"]["sha256"],digest(b"object"));assert!(v["object_inventory"].is_null());assert_eq!(v["final_byte_identity_stable"],false);
        assert!(l.observe_object(Path::new("/object"),b"changed",&args).unwrap_err().to_string().contains("cannot be rebound"));
    }
    #[test]
    fn late_byte_identity_failure_revokes_lineage_without_erasing_observed_stages() {
        let dir=std::env::temp_dir().join(format!("ostadix-source-lineage-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));fs::create_dir(&dir).unwrap();let path=dir.join("evidence");fs::write(&path,b"before").unwrap();
        let mut l=lineage();l.guards.push(BytesIdentity::consumed(&path,b"before"));l.postguard().unwrap();assert!(l.final_byte_identity_stable);
        fs::write(&path,b"after!").unwrap();assert_eq!(fs::read(&path).unwrap(),b"after!");let e=l.postguard().unwrap_err();assert!(e.to_string().contains("lineage evidence changed"));assert!(!l.final_byte_identity_stable);
        assert_eq!(l.original_action["producer"],"clang-llvm");fs::remove_file(path).unwrap();fs::remove_dir(dir).unwrap();
    }
}
