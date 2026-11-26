//! Checked held-journal reconstruction and distinct representation staging.
//!
//! This owner is not AdmittedCapture, NativeModule, a source-consumption grant,
//! a fresh native-output selector, or an original-link-order authority. Policy
//! buffers are held independently and checked for identity/membership only.
//! The executing Python/worker checks are observed before/after byte custody,
//! not a proof of the child runtime/library closure or of path race freedom.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

const REPORT_SCHEMA: &str = "ocore-runtime-capture-v2";
const CONTEXT_SCHEMA: &str = "ocore-held-mixed-capture-context-v1";
const RECEIPT_SCHEMA: &str = "ocore-runtime-held-mixed-capture-verification-v1";
const RECEIPT_SCOPE: &str = "held-journal-mixed-representation-reconstruction";
// Literal extracted as DATA from the exact selected worker source; the child
// independently checks that its executing compiled worker retains this value.
const REGISTRY_SNAPSHOT_BASENAME: &str = "ocore_producer_registry.json";
const COMPLETION_KEYS: &[&str] = &[
    "reconstruction_complete", "capture_complete", "inventory_complete",
    "inventory_roles_complete", "required_representation_complete",
    "scoped_capture_complete", "input_custody_checked",
];
const QUALIFICATION_KEYS: &[&str] = &[
    "source_consumption_authority", "native_module_verified",
    "native_order_meaning", "abi", "provider_closure", "link_performed",
    "runtime_complete", "native_execution_qualified", "all_isa_qualified",
    "opaque_capture_admission",
];

fn exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<()> {
    let object = value.as_object().with_context(|| format!("{label} is not an object"))?;
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if keys != expected.iter().copied().collect::<BTreeSet<_>>() {
        bail!("{label} has missing or unexpected fields");
    }
    Ok(())
}

fn valid_sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn pin(value: &Value, label: &str) -> Result<BytesIdentity> {
    exact_keys(value, &["path", "bytes", "sha256"], label)?;
    let path = string(value, "path")?;
    let sha256 = string(value, "sha256")?;
    let bytes = value["bytes"].as_u64().with_context(|| format!("{label} byte count is not u64"))?;
    if !Path::new(path).is_absolute() || path.contains('\0') || !valid_sha(sha256) {
        bail!("{label} has an invalid absolute path or SHA256");
    }
    Ok(BytesIdentity { path: path.to_owned(), bytes, sha256: sha256.to_owned() })
}

fn check_raw(expected: &BytesIdentity, raw: &[u8]) -> Result<()> {
    let bytes = u64::try_from(raw.len()).context("mixed input is larger than u64")?;
    if expected.bytes != bytes || expected.sha256 != digest(raw) {
        bail!("mixed held bytes differ: {}", expected.path);
    }
    Ok(())
}

fn write_new(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(path).with_context(|| format!("create new mixed evidence {}", path.display()))?;
    file.write_all(raw)?;
    file.sync_all()?;
    Ok(())
}

fn false_qualifications() -> Value {
    let mut result = serde_json::Map::new();
    for key in QUALIFICATION_KEYS {
        result.insert((*key).to_owned(), Value::Bool(false));
    }
    Value::Object(result)
}

fn insert_guard(guards: &mut BTreeMap<String, BytesIdentity>, value: BytesIdentity) -> Result<()> {
    if let Some(held) = guards.get(&value.path) {
        if held != &value { bail!("conflicting mixed input identities for {}", value.path); }
    } else {
        guards.insert(value.path.clone(), value);
    }
    Ok(())
}

fn registry_snapshot_guard(worker: &BytesIdentity, registry: &BytesIdentity) -> Result<BytesIdentity> {
    let actual_worker = Path::new(&worker.path).canonicalize()
        .context("resolve held worker snapshot")?;
    let default_registry = actual_worker.with_file_name(REGISTRY_SNAPSHOT_BASENAME);
    if default_registry.canonicalize().context("resolve worker snapshot registry")?
        != Path::new(&registry.path).canonicalize().context("resolve held registry")?
    {
        bail!("worker default registry does not resolve to the held registry");
    }
    let compiled = include_str!("../../../../scripts/ocore_producer_registry.json");
    let guard = BytesIdentity::consumed(&default_registry, compiled.as_bytes());
    guard.check()?;
    Ok(guard)
}

/// A declared byte identity, not a capability or an execution qualification.
#[derive(Debug, Clone)]
pub(crate) struct MixedInputPin { identity: BytesIdentity }
impl MixedInputPin {
    pub(crate) fn declared(path: PathBuf, bytes: u64, sha256: String) -> Result<Self> {
        if !path.is_absolute() || path.to_str().is_none() || !valid_sha(&sha256) {
            bail!("mixed input requires an absolute UTF-8 path and SHA256");
        }
        Ok(Self { identity: BytesIdentity { path: path.display().to_string(), bytes, sha256 } })
    }
    pub(crate) fn from_held(path: &Path, raw: &[u8]) -> Result<Self> {
        Self::declared(path.to_owned(), u64::try_from(raw.len())?, digest(raw))
    }
}

/// Prior caller-held policy buffers. Their exact bytes are retained, while
/// native-order meaning and temporal selection authority remain unestablished.
/// No bool in this type can construct CheckedMixedCapture.
pub(crate) struct MixedCapturePolicy {
    context: MixedInputPin,
    context_raw: Vec<u8>,
    member_policy: MixedInputPin,
    member_policy_raw: Vec<u8>,
    original_order_policy: MixedInputPin,
    original_order_policy_raw: Vec<u8>,
    python: MixedInputPin,
    required_members: BTreeSet<String>,
}
impl MixedCapturePolicy {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn hold(
        context: MixedInputPin, context_raw: Vec<u8>,
        member_policy: MixedInputPin, member_policy_raw: Vec<u8>,
        original_order_policy: MixedInputPin, original_order_policy_raw: Vec<u8>,
        python: MixedInputPin, required_members: BTreeSet<String>,
    ) -> Result<Self> {
        check_raw(&context.identity, &context_raw)?;
        check_raw(&member_policy.identity, &member_policy_raw)?;
        check_raw(&original_order_policy.identity, &original_order_policy_raw)?;
        if required_members.iter().any(|id| id.is_empty() || id.contains('\0')) {
            bail!("mixed required membership has an empty or NUL-containing ID");
        }
        Ok(Self { context, context_raw, member_policy, member_policy_raw,
            original_order_policy, original_order_policy_raw, python, required_members })
    }
    fn check_files(&self) -> Result<()> {
        self.context.identity.check()?;
        self.member_policy.identity.check()?;
        self.original_order_policy.identity.check()?;
        self.python.identity.check()?;
        Ok(())
    }
}

struct Member {
    id: String,
    source_index: usize,
    receipt_index: usize,
    action_index: usize,
    representation: String,
    disposition: String,
    input: Option<BytesIdentity>,
}
enum ActionInputs {
    Unneeded,
    Checked(BTreeMap<String, ProducerInput>),
    Refused(String),
}
struct Action { source_index: usize, inputs: ActionInputs }

/// Private immutable reconstruction owner. There is deliberately no
/// Serialize/Deserialize implementation, public field, or bool constructor.
pub(crate) struct CheckedMixedCapture {
    report_pin: BytesIdentity,
    raw_report: Vec<u8>,
    capture: Value,
    receipt: Value,
    policy: MixedCapturePolicy,
    members: Vec<Member>,
    member_index: BTreeMap<String, usize>,
    actions: Vec<Action>,
    action_index: BTreeMap<String, usize>,
    guards: BTreeMap<String, BytesIdentity>,
}

pub(crate) enum MixedUnitRepresentation {
    /// Producer-contract consistency plus exact consumed LLVM bytes only.
    /// This is not an admitted NativeModule or a fresh-output selector.
    LlvmInput { path: PathBuf, bytes: Vec<u8> },
    /// Source bytes only; separately selected complete floors/commitment,
    /// original source/object authority and actual consumer lowering are needed.
    ConfiguredAssemblyInput { path: PathBuf, bytes: Vec<u8> },
    Refused { reasons: Vec<String> },
}
pub(crate) struct MixedUnitStage {
    index: usize,
    representation: MixedUnitRepresentation,
}
impl MixedUnitStage {
    pub(crate) fn index(&self) -> usize { self.index }
    pub(crate) fn representation(&self) -> &MixedUnitRepresentation { &self.representation }
}

/// The actual representation dispatcher result retains its complete immutable
/// owner and every unit outcome, including failures. It is not StagedComponent.
pub(crate) struct MixedCaptureStage {
    owner: CheckedMixedCapture,
    units: Vec<MixedUnitStage>,
    issues: Vec<String>,
}
impl MixedCaptureStage {
    pub(crate) fn raw_report(&self) -> &[u8] { &self.owner.raw_report }
    pub(crate) fn raw_context(&self) -> &[u8] { &self.owner.policy.context_raw }
    pub(crate) fn receipt(&self) -> &Value { &self.owner.receipt }
    pub(crate) fn capture(&self) -> &Value { &self.owner.capture }
    pub(crate) fn units(&self) -> &[MixedUnitStage] { &self.units }
    pub(crate) fn issues(&self) -> &[String] { &self.issues }
    pub(crate) fn unit_index(&self, id: &str) -> Option<usize> { self.owner.member_index.get(id).copied() }
    pub(crate) fn action_index(&self, id: &str) -> Option<usize> { self.owner.action_index.get(id).copied() }
    pub(crate) fn unit(&self, index: usize) -> Option<&Value> {
        self.owner.members.get(index).and_then(|member|
            self.owner.capture["units"].as_array().and_then(|units| units.get(member.source_index)))
    }
    pub(crate) fn member_policy(&self) -> &[u8] { &self.owner.policy.member_policy_raw }
    pub(crate) fn original_order_policy(&self) -> &[u8] { &self.owner.policy.original_order_policy_raw }
    pub(crate) fn write_summary(&self, output: &Path) -> Result<()> {
        let units = self.units.iter().map(|stage| {
            let member = &self.owner.members[stage.index];
            let (tag, reasons) = match &stage.representation {
                MixedUnitRepresentation::LlvmInput { .. } => ("llvm-input", Vec::<String>::new()),
                MixedUnitRepresentation::ConfiguredAssemblyInput { .. } =>
                    ("configured-assembly-input", vec!["caller-held complete floors/commitment and original producer authority remain required".to_owned()]),
                MixedUnitRepresentation::Refused { reasons } => ("refused", reasons.clone()),
            };
            serde_json::json!({"index":stage.index,"id":member.id,"stage":tag,"reasons":reasons})
        }).collect::<Vec<_>>();
        let summary = serde_json::json!({
            "schema":"ocore-runtime-mixed-representation-stage-v1",
            "scope":"checked-input-staging-only",
            "report":self.owner.report_pin,
            "context":self.owner.policy.context.identity,
            "units":units,"issues":self.issues,
            "source_capture_complete":false,"unit_lowering_complete":false,
            "native_artifact_dispatch":"unsupported",
            "order_binding_scope":"opaque-held-policy-identity-only",
            "qualifications":false_qualifications()
        });
        write_new(&output.join("mixed-representation-stage.json"), &serde_json::to_vec_pretty(&summary)?)
    }
}

impl CheckedMixedCapture {
    fn check_shared(&self) -> Result<()> {
        self.report_pin.check()?;
        self.policy.check_files()?;
        for value in self.guards.values() { value.check()?; }
        Ok(())
    }

    fn invoke(
        report: &Path, raw_report: &[u8], output: &Path, python: &Path,
        policy: &MixedCapturePolicy,
    ) -> Result<Value> {
        write_new(&output.join("mixed-held-report.json"), raw_report)?;
        write_new(&output.join("mixed-held-context.json"), &policy.context_raw)?;
        write_new(&output.join("mixed-held-member-policy"), &policy.member_policy_raw)?;
        write_new(&output.join("mixed-held-original-order-policy"), &policy.original_order_policy_raw)?;
        if python != Path::new(&policy.python.identity.path) || !python.is_absolute() {
            bail!("selected mixed verifier Python differs from the held executable path");
        }
        let worker = include_str!("../../../../scripts/ocore_runtime_capture.py");
        let registry = include_str!("../../../../scripts/ocore_producer_registry.json");
        let context: Value = serde_json::from_slice(&policy.context_raw)?;
        if context["schema"] != CONTEXT_SCHEMA { bail!("unsupported held mixed context schema"); }
        exact_keys(&context, &["schema","journal","report","session","recipe","capture_worker",
            "producer_registry","inventory","member_policy","original_order_policy"], "mixed context")?;
        let report_pin = BytesIdentity::consumed(report, raw_report);
        if pin(&context["report"], "mixed context report")? != report_pin
            || pin(&context["member_policy"], "mixed member policy")? != policy.member_policy.identity
            || pin(&context["original_order_policy"], "mixed original order policy")? != policy.original_order_policy.identity
        { bail!("mixed context does not bind the independently held report/policy buffers"); }
        let worker_pin = pin(&context["capture_worker"], "mixed worker")?;
        let registry_pin = pin(&context["producer_registry"], "mixed registry")?;
        check_raw(&worker_pin, worker.as_bytes())?;
        check_raw(&registry_pin, registry.as_bytes())?;
        report_pin.check()?;
        policy.check_files()?;
        worker_pin.check()?;
        registry_pin.check()?;
        let default_registry_pin = registry_snapshot_guard(&worker_pin, &registry_pin)?;
        let payload = serde_json::json!({
            "source":worker, "report":report, "context":policy.context.identity.path,
            "context_bytes":policy.context.identity.bytes,
            "context_sha256":policy.context.identity.sha256,
            "worker_sha256":digest(worker.as_bytes()),
            "worker_snapshot":worker_pin.path,
            "registry_filename":REGISTRY_SNAPSHOT_BASENAME,
        });
        let program = "import json,sys\nfrom pathlib import Path\npayload=json.load(sys.stdin)\nnamespace={'__name__':'ocore_mixed_capture_readmission','__file__':payload['worker_snapshot']}\nexec(compile(payload['source'],payload['worker_snapshot'],'exec'),namespace)\nif namespace.get('PRODUCER_REGISTRY_FILE') != payload['registry_filename']: raise RuntimeError('selected worker registry basename changed')\nreceipt=namespace['verify_held_mixed_report'](Path(payload['report']),Path(payload['context']),expected_context_bytes=payload['context_bytes'],expected_context_sha256=payload['context_sha256'],expected_worker_sha256=payload['worker_sha256'])\nprint(json.dumps(receipt))\nkeys=('reconstruction_complete','capture_complete','inventory_complete','inventory_roles_complete','required_representation_complete','scoped_capture_complete','input_custody_checked')\nsys.exit(0 if all(receipt.get(key) is True for key in keys) else 2)\n";
        let mut child = python_command(python).args(["-c",program])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().context("spawn selected held mixed capture verifier")?;
        let write_result = (|| -> std::io::Result<()> {
            let mut input = child.stdin.take().ok_or_else(||
                std::io::Error::other("mixed verifier stdin is unavailable"))?;
            input.write_all(&serde_json::to_vec(&payload).map_err(std::io::Error::other)?)?;
            Ok(())
        })();
        // Closing stdin on write failure lets this verifier observe EOF. There is
        // no deadline, background replay, retry, or substitute Python.
        let observed = child.wait_with_output();
        let post = (|| -> Result<()> {
            report_pin.check()?; policy.check_files()?;
            worker_pin.check()?; registry_pin.check()?; default_registry_pin.check()?; Ok(())
        })();
        let result = observed.context("wait for original held mixed capture verifier")?;
        write_new(&output.join("mixed-verifier.stdout"), &result.stdout)?;
        write_new(&output.join("mixed-verifier.stderr"), &result.stderr)?;
        let status = serde_json::json!({
            "schema":"ocore-runtime-mixed-verifier-observation-v1",
            "exit_code":result.status.code(),"success":result.status.success(),
            "stdin_write_error":write_result.as_ref().err().map(ToString::to_string),
            "postcheck_error":post.as_ref().err().map(ToString::to_string),
            "python":policy.python.identity,"worker":worker_pin,"registry":registry_pin,
            "worker_default_registry":default_registry_pin,
            "qualifications":false_qualifications(),
        });
        write_new(&output.join("mixed-verifier-observation.json"), &serde_json::to_vec_pretty(&status)?)?;
        write_result.context("write held mixed verifier payload")?;
        post?;
        if !result.status.success() {
            bail!("held mixed verifier did not complete scoped reconstruction: {:?}; full cohort/output retained",result.status.code());
        }
        let receipt: Value = serde_json::from_slice(&result.stdout).context("decode held mixed verifier result")?;
        write_new(&output.join("mixed-reverification.json"), &serde_json::to_vec_pretty(&receipt)?)?;
        Ok(receipt)
    }

    fn verify(
        report: &Path, raw_report: &[u8], output: &Path, python: &Path,
        policy: MixedCapturePolicy,
    ) -> Result<Self> {
        let receipt = Self::invoke(report, raw_report, output, python, &policy)?;
        if receipt["schema"] != RECEIPT_SCHEMA || receipt["scope"] != RECEIPT_SCOPE
            || COMPLETION_KEYS.iter().any(|key| receipt[*key] != true)
        { bail!("mixed verifier receipt scope/completion differs"); }
        exact_keys(&receipt["qualifications"], QUALIFICATION_KEYS, "mixed qualifications")?;
        if QUALIFICATION_KEYS.iter().any(|key| receipt["qualifications"][*key] != false) {
            bail!("mixed reconstruction cannot grant native/source/runtime qualifications");
        }
        let report_pin = BytesIdentity::consumed(report, raw_report);
        exact_keys(&receipt["raw_inputs"], &["report","context"], "mixed raw inputs")?;
        if pin(&receipt["raw_inputs"]["report"], "mixed receipt report")? != report_pin
            || pin(&receipt["raw_inputs"]["context"], "mixed receipt context")? != policy.context.identity
        { bail!("mixed verifier result differs from consumed raw inputs"); }
        let context: Value = serde_json::from_slice(&policy.context_raw)?;
        exact_keys(&receipt["shared_inputs"], &["journal","session","recipe","capture_worker",
            "producer_registry","inventory","member_policy","original_order_policy"], "mixed shared inputs")?;
        let mut guards = BTreeMap::new();
        for role in ["journal","session","recipe","capture_worker","producer_registry",
            "inventory","member_policy","original_order_policy"] {
            if receipt["shared_inputs"][role] != context[role] {
                bail!("mixed verifier shared role differs: {role}");
            }
            if role != "journal" { insert_guard(&mut guards, pin(&context[role], role)?)?; }
        }
        let worker_pin = pin(&context["capture_worker"], "mixed worker")?;
        let registry_pin = pin(&context["producer_registry"], "mixed registry")?;
        insert_guard(&mut guards, registry_snapshot_guard(&worker_pin, &registry_pin)?)?;
        // A held journal is a reconstructed snapshot. Preserve every event pin;
        // sorted event membership is not promoted into native link order.
        for event in array(&context["journal"], "events")? {
            insert_guard(&mut guards, pin(event, "mixed journal event")?)?;
        }
        let capture: Value = serde_json::from_slice(raw_report)?;
        if capture["schema"] != REPORT_SCHEMA { bail!("mixed owner requires the v2 capture report"); }
        let raw_units = array(&capture, "units")?;
        let rows = array(&receipt, "units")?;
        if rows.len() != raw_units.len() { bail!("mixed receipt lost or added a unit"); }
        let mut member_index = BTreeMap::new();
        for (index, unit) in raw_units.iter().enumerate() {
            let id = string(unit, "id")?;
            if id.is_empty() || member_index.insert(id.to_owned(), index).is_some() {
                bail!("mixed captured membership repeats an empty/duplicate unit ID");
            }
        }
        if member_index.keys().cloned().collect::<BTreeSet<_>>() != policy.required_members {
            bail!("mixed complete membership differs from the independently held member set");
        }
        let partition = &receipt["partition"];
        exact_keys(partition, &["lowering_unit_ids","non_lowering_unit_ids","unclassified_unit_ids"], "mixed partition")?;
        let mut partition_ids = BTreeSet::new();
        for role in ["lowering_unit_ids","non_lowering_unit_ids","unclassified_unit_ids"] {
            for id in strings(&partition[role], role)? {
                if !partition_ids.insert(id) { bail!("mixed partition repeats a unit ID"); }
            }
        }
        if partition_ids != policy.required_members { bail!("mixed partition does not retain complete membership"); }
        let raw_actions = array(&capture, "invocations")?;
        let mut action_index = BTreeMap::new();
        let mut owners = BTreeMap::new();
        for (index, action) in raw_actions.iter().enumerate() {
            let id = string(action,"id")?;
            if id.is_empty() || action_index.insert(id.to_owned(),index).is_some() {
                bail!("mixed capture repeats an original action ID");
            }
            for unit in array(action,"units")? {
                let unit_id = string(unit,"id")?;
                let flat = member_index.get(unit_id).context("mixed action unit is absent from complete inventory")?;
                if &raw_units[*flat] != unit || owners.insert(unit_id.to_owned(),index).is_some() {
                    bail!("mixed action unit differs or has duplicate ownership: {unit_id}");
                }
            }
        }
        if owners.len() != raw_units.len() { bail!("mixed capture has orphan units"); }
        let mut members = Vec::with_capacity(rows.len());
        let mut llvm_actions = BTreeSet::new();
        for (index, row) in rows.iter().enumerate() {
            exact_keys(row, &["index","id","representation","disposition","invocation_ids","kind",
                "producer","source","target_triple","input","input_role","input_state","reasons"], "mixed unit result")?;
            let id = string(row,"id")?;
            if row["index"].as_u64() != Some(u64::try_from(index)?)
                || raw_units[index]["id"] != id { bail!("mixed receipt changed unit order/identity"); }
            let action = *owners.get(id).context("mixed unit has no producing action")?;
            let ids = strings(&row["invocation_ids"], "mixed unit invocation IDs")?;
            if ids != vec![string(&raw_actions[action],"id")?.to_owned()] {
                bail!("mixed receipt action association differs: {id}");
            }
            let representation = string(row,"representation")?;
            let disposition = string(row,"disposition")?;
            let _ = strings(&row["reasons"],"mixed unit reasons")?;
            if !matches!(representation,"llvm"|"configured-assembly"|"unsupported")
                || !matches!(disposition,"checked"|"refused") { bail!("invalid mixed unit tag"); }
            let input = if disposition == "checked" {
                let role = match representation {
                    "llvm" => { llvm_actions.insert(action); "llvm_ir" },
                    "configured-assembly" => "configured_assembly",
                    _ => bail!("unsupported representation cannot be checked"),
                };
                if row["input_role"] != role || row["input_state"] != "consumed_and_checked" {
                    bail!("mixed checked representation has no consumed input contract");
                }
                Some(pin(&row["input"],"mixed checked unit input")?)
            } else {
                if !row["input"].is_null() || row["input_state"] != "not_checked" {
                    bail!("refused mixed unit claims consumed output");
                }
                None
            };
            members.push(Member { id:id.to_owned(),source_index:index,receipt_index:index,
                action_index:action,representation:representation.to_owned(),
                disposition:disposition.to_owned(),input });
        }
        let mut actions = Vec::with_capacity(raw_actions.len());
        for (index, action) in raw_actions.iter().enumerate() {
            let inputs = if llvm_actions.contains(&index) {
                match (|| -> Result<BTreeMap<String, ProducerInput>> {
                    if action["state"] != "finished" || action["exit_code"] != 0
                        || !array(action,"capture_errors")?.is_empty() {
                        bail!("original producing action did not complete");
                    }
                    for role in ["producer","kind","driver_kind","compiler","cwd"] {
                        if string(action,role)?.is_empty() { bail!("original action provenance is absent: {role}"); }
                    }
                    if !Path::new(string(action,"cwd")?).is_absolute()
                        || strings(&action["argv"],"original action argv")?.is_empty()
                        || !action["frontend"].is_object() || !action["build_environment"].is_object() {
                        bail!("original action command/frontend provenance is absent");
                    }
                    ProducerInput::bind_action(action)
                })() {
                    Ok(inputs) => {
                        for input in inputs.values() {
                            for guard in input.guard_files() { insert_guard(&mut guards, guard.clone())?; }
                        }
                        ActionInputs::Checked(inputs)
                    },
                    Err(error) => ActionInputs::Refused(error.to_string()),
                }
            } else { ActionInputs::Unneeded };
            actions.push(Action { source_index:index, inputs });
        }
        let owner = Self { report_pin,raw_report:raw_report.to_vec(),capture,receipt,policy,
            members,member_index,actions,action_index,guards };
        owner.check_shared()?;
        Ok(owner)
    }

    fn stage_member(&self, member: &Member) -> Result<MixedUnitRepresentation> {
        let row = &self.receipt["units"][member.receipt_index];
        if member.disposition != "checked" {
            return Ok(MixedUnitRepresentation::Refused {
                reasons:strings(&row["reasons"],"mixed refused reasons")? });
        }
        let expected = member.input.as_ref().context("checked mixed unit has no input pin")?;
        match member.representation.as_str() {
            "llvm" => {
                let action = &self.actions[member.action_index];
                // Refused/unknown producer contracts are an observation barrier:
                // do not open any candidate LLVM output before this exact gate.
                let inputs = match &action.inputs {
                    ActionInputs::Checked(inputs) => inputs,
                    ActionInputs::Refused(reason) => bail!("mixed LLVM producer contract refused: {reason}"),
                    ActionInputs::Unneeded => bail!("mixed LLVM input has no producing contract"),
                };
                let input = inputs.get(&member.id).context("mixed LLVM unit has no producer-specific input")?;
                if input.original() != expected { bail!("mixed LLVM receipt differs from original producer input"); }
                let raw_action = &self.capture["invocations"][action.source_index];
                let raw_unit = &self.capture["units"][member.source_index];
                if raw_unit["kind"] != raw_action["kind"] { bail!("mixed LLVM action/unit kind differs"); }
                file_record(&raw_unit["source"],"mixed original LLVM source")?;
                array(raw_unit,"dependencies")?;
                let bytes = fs::read(&expected.path).with_context(|| format!("read mixed input {}",expected.path))?;
                check_raw(expected,&bytes)?;
                input.check_consumed(raw_action,raw_unit,&bytes)?;
                Ok(MixedUnitRepresentation::LlvmInput { path:PathBuf::from(&expected.path),bytes })
            },
            "configured-assembly" => {
                let bytes = fs::read(&expected.path).with_context(|| format!("read mixed input {}",expected.path))?;
                check_raw(expected,&bytes)?;
                Ok(MixedUnitRepresentation::ConfiguredAssemblyInput { path:PathBuf::from(&expected.path),bytes })
            },
            _ => bail!("unsupported mixed representation cannot be consumed"),
        }
    }

    pub(crate) fn into_stage(self) -> MixedCaptureStage {
        let mut issues = Vec::new();
        if let Err(error) = self.check_shared() { issues.push(error.to_string()); }
        let mut units = Vec::with_capacity(self.members.len());
        for (index, member) in self.members.iter().enumerate() {
            let representation = if issues.is_empty() {
                self.stage_member(member).unwrap_or_else(|error|
                    MixedUnitRepresentation::Refused { reasons:vec![error.to_string()] })
            } else {
                MixedUnitRepresentation::Refused { reasons:vec!["shared held input custody check failed".to_owned()] }
            };
            units.push(MixedUnitStage { index,representation });
        }
        if let Err(error) = self.check_shared() { issues.push(error.to_string()); }
        if !issues.is_empty() {
            for unit in &mut units {
                unit.representation = MixedUnitRepresentation::Refused {
                    reasons:vec!["shared held input custody check failed; no consumed buffer is exposed".to_owned()] };
            }
        }
        MixedCaptureStage { owner:self,units,issues }
    }
}

pub(super) fn preflight(
    report: &Path, raw_report: &[u8], output: &Path, python: &Path,
    policy: Option<MixedCapturePolicy>,
) -> Result<Option<CheckedMixedCapture>> {
    let capture: Value = serde_json::from_slice(raw_report)?;
    if capture["schema"] != REPORT_SCHEMA { return Ok(None); }
    match policy {
        Some(policy) => CheckedMixedCapture::verify(report,raw_report,output,python,policy).map(Some),
        None => {
            write_new(&output.join("mixed-held-report.json"),raw_report)?;
            let refusal = serde_json::json!({
                "schema":"ocore-runtime-mixed-representation-stage-v1",
                "scope":"retained-unsupported-mixed-preflight",
                "report":BytesIdentity::consumed(report,raw_report),
                "retained_report":"mixed-held-report.json",
                "units":capture.get("units").unwrap_or(&Value::Null),
                "issues":["separately caller-held context, complete member policy, original-order policy and selected Python pin are required"],
                "source_capture_complete":false,"unit_lowering_complete":false,
                "native_artifact_dispatch":"unsupported",
                "qualifications":false_qualifications()
            });
            write_new(&output.join("mixed-representation-stage.json"),&serde_json::to_vec_pretty(&refusal)?)?;
            bail!("mixed capture requires independently held reconstruction policy; full inventory retained, native/artifact lowering is not admitted");
        }
    }
}
