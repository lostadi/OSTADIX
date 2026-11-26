//! Checked held-journal reconstruction and distinct representation staging.
//!
//! This owner is not AdmittedCapture, NativeModule, a source-consumption grant,
//! a fresh native-output selector, or an original-link-order authority. Policy
//! buffers are held independently and checked for identity/membership only.
//! The executing Python/worker checks are observed before/after byte custody,
//! not a proof of the child runtime/library closure or of path race freedom.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::process::Stdio;

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

// Diagnostic metadata only, matching the exact selected worker helpers
// is_identity_assembly_unit/captured_unit_target. Presence of the configured
// key selects that payload even when null/non-object; never fall back to IR or
// a top-level target. This is not an ISA, producer or ABI authorization.
fn diagnostic_captured_unit_target(unit: &Value) -> Result<&Value> {
    let object = unit.as_object().context("incomplete raw unit is not an object")?;
    let configured = object.get("representation").and_then(Value::as_str)
        == Some("configured-assembly") || object.contains_key("configured_assembly");
    let payload = object.get(if configured { "configured_assembly" } else { "ir" });
    Ok(payload.and_then(Value::as_object)
        .and_then(|payload| payload.get("target_triple")).unwrap_or(&Value::Null))
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
    /// Original checked membership survives per-member staging refusal.
    /// This is the same owner/index mapping used by unit(), not fresh selection.
    pub(crate) fn original_member_count(&self) -> usize { self.owner.members.len() }
    pub(crate) fn original_representation(&self, index: usize) -> Option<&str> {
        self.owner.members.get(index).map(|member| member.representation.as_str())
    }
    pub(crate) fn unit_index(&self, id: &str) -> Option<usize> { self.owner.member_index.get(id).copied() }
    pub(crate) fn action_index(&self, id: &str) -> Option<usize> { self.owner.action_index.get(id).copied() }
    pub(crate) fn unit(&self, index: usize) -> Option<&Value> {
        self.owner.members.get(index).and_then(|member|
            self.owner.capture["units"].as_array().and_then(|units| units.get(member.source_index)))
    }
    pub(crate) fn member_policy(&self) -> &[u8] { &self.owner.policy.member_policy_raw }
    pub(crate) fn original_order_policy(&self) -> &[u8] { &self.owner.policy.original_order_policy_raw }
    /// Recheck the original observed custody guards without exposing the owner.
    /// This grants no source, producer, ABI or native-order authority.
    pub(crate) fn check_custody(&self) -> Result<()> { self.owner.check_shared() }
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

/// A terminal observation, not an admission or a lowering-complete result.
/// Both variants keep all cohort occurrences; only Reconstructed can stage inputs.
pub(crate) enum MixedCaptureOutcome {
    Reconstructed(MixedCaptureStage),
    Incomplete(IncompleteMixedCapture),
}
impl MixedCaptureOutcome {
    pub(crate) fn check_custody(&self) -> Result<()> {
        match self {
            Self::Reconstructed(stage) => stage.check_custody(),
            Self::Incomplete(incomplete) => incomplete.check_custody(),
        }
    }
    pub(crate) fn write_summary(&self, output: &Path) -> Result<()> {
        match self {
            Self::Reconstructed(stage) => stage.write_summary(output),
            Self::Incomplete(incomplete) => incomplete.write_summary(output),
        }
    }
}

/// An occurrence-indexed diagnostic view. IDs may repeat or be malformed in an
/// incomplete cohort; neither the ID nor this view is a producer capability.
pub(crate) struct IncompleteMixedUnit<'a> {
    index: usize,
    raw: &'a Value,
    outcome: &'a Value,
}
impl<'a> IncompleteMixedUnit<'a> {
    pub(crate) fn index(&self) -> usize { self.index }
    pub(crate) fn raw(&self) -> &'a Value { self.raw }
    pub(crate) fn outcome(&self) -> &'a Value { self.outcome }
}
pub(crate) struct IncompleteMixedInvocation<'a> {
    index: usize,
    raw: &'a Value,
    status: &'a Value,
}
impl<'a> IncompleteMixedInvocation<'a> {
    pub(crate) fn index(&self) -> usize { self.index }
    pub(crate) fn raw(&self) -> &'a Value { self.raw }
    pub(crate) fn status(&self) -> &'a Value { self.status }
}

/// Exact held incomplete reconstruction, deliberately without into_stage,
/// ProducerInput, output-buffer getters, or any admission conversion.
/// There is no caller-boolean or serialized constructor. All original raw rows,
/// diagnostics and multiplicity are retained once, not copied per unit.
pub(crate) struct IncompleteMixedCapture {
    report_pin: BytesIdentity,
    raw_report: Vec<u8>,
    capture: Value,
    raw_receipt: Vec<u8>,
    receipt: Value,
    policy: MixedCapturePolicy,
    guards: BTreeMap<String, BytesIdentity>,
    evidence: Vec<BytesIdentity>,
    unit_count: usize,
    invocation_count: usize,
}
impl IncompleteMixedCapture {
    pub(crate) fn raw_report(&self) -> &[u8] { &self.raw_report }
    pub(crate) fn raw_context(&self) -> &[u8] { &self.policy.context_raw }
    pub(crate) fn raw_receipt(&self) -> &[u8] { &self.raw_receipt }
    pub(crate) fn capture(&self) -> &Value { &self.capture }
    pub(crate) fn receipt(&self) -> &Value { &self.receipt }
    pub(crate) fn diagnostics(&self) -> &Value { &self.receipt["diagnostics"] }
    pub(crate) fn member_policy(&self) -> &[u8] { &self.policy.member_policy_raw }
    pub(crate) fn original_order_policy(&self) -> &[u8] { &self.policy.original_order_policy_raw }
    pub(crate) fn held_required_members(&self) -> &BTreeSet<String> { &self.policy.required_members }
    pub(crate) fn units(&self) -> impl ExactSizeIterator<Item = IncompleteMixedUnit<'_>> {
        // Equal counts and exact indices are validated before construction.
        // Private immutable JSON cannot change those checked occurrence bounds.
        (0..self.unit_count).map(move |index| IncompleteMixedUnit {
            index, raw:&self.capture["units"][index], outcome:&self.receipt["units"][index],
        })
    }
    pub(crate) fn invocations(&self) -> impl ExactSizeIterator<Item = IncompleteMixedInvocation<'_>> {
        (0..self.invocation_count).map(move |index| IncompleteMixedInvocation {
            index, raw:&self.capture["invocations"][index],
            status:&self.receipt["invocation_statuses"][index],
        })
    }
    pub(crate) fn evidence_paths(&self) -> impl ExactSizeIterator<Item = &Path> {
        self.evidence.iter().map(|pin| Path::new(&pin.path))
    }
    pub(crate) fn check_custody(&self) -> Result<()> {
        self.report_pin.check()?;
        self.policy.check_files()?;
        for guard in self.guards.values().chain(self.evidence.iter()) { guard.check()?; }
        Ok(())
    }
    fn from_observation(
        report: &Path, raw_report: &[u8], policy: MixedCapturePolicy,
        observed: ObservedMixedReceipt,
    ) -> Result<Self> {
        let ObservedMixedReceipt { receipt,raw_receipt,exit_code,evidence } = observed;
        if exit_code != 2 { bail!("incomplete mixed owner requires actual verifier exit 2"); }
        exact_keys(&receipt, &[
            "schema","scope","raw_inputs","shared_inputs","journal_membership_order",
            "invocation_statuses","units","partition","diagnostics",
            "reconstruction_complete","capture_complete","inventory_complete",
            "inventory_roles_complete","required_representation_complete",
            "scoped_capture_complete","input_custody_checked","order_binding_scope",
            "qualifications",
        ], "incomplete mixed receipt")?;
        if receipt["schema"] != RECEIPT_SCHEMA || receipt["scope"] != RECEIPT_SCOPE {
            bail!("incomplete mixed receipt schema/scope differs");
        }
        for key in COMPLETION_KEYS {
            if receipt[*key].as_bool().is_none() {
                bail!("incomplete mixed receipt has a non-boolean flag: {key}");
            }
        }
        if receipt["scoped_capture_complete"] != false
            || receipt["reconstruction_complete"] != true
            || receipt["input_custody_checked"] != true
        {
            bail!("exit 2 is not an intact incomplete mixed reconstruction");
        }
        if receipt["journal_membership_order"] != "capture_event_filename_order_not_native_order"
            || receipt["order_binding_scope"] != "raw_prior_policy_identity_consistency_only_not_native_order_meaning"
        { bail!("incomplete mixed receipt changed its order scope"); }
        exact_keys(&receipt["qualifications"], QUALIFICATION_KEYS, "incomplete mixed qualifications")?;
        if QUALIFICATION_KEYS.iter().any(|key| receipt["qualifications"][*key] != false) {
            bail!("incomplete reconstruction cannot grant source/native/runtime qualifications");
        }
        let report_pin = BytesIdentity::consumed(report, raw_report);
        exact_keys(&receipt["raw_inputs"], &["report","context"], "incomplete mixed raw inputs")?;
        if pin(&receipt["raw_inputs"]["report"], "incomplete mixed report")? != report_pin
            || pin(&receipt["raw_inputs"]["context"], "incomplete mixed context")? != policy.context.identity
        { bail!("incomplete receipt differs from the consumed raw report/context"); }
        let context: Value = serde_json::from_slice(&policy.context_raw)?;
        exact_keys(&context, &["schema","journal","report","session","recipe","capture_worker",
            "producer_registry","inventory","member_policy","original_order_policy"], "incomplete mixed context")?;
        if context["schema"] != CONTEXT_SCHEMA
            || pin(&context["report"], "incomplete context report")? != report_pin
            || pin(&context["member_policy"], "incomplete member policy")? != policy.member_policy.identity
            || pin(&context["original_order_policy"], "incomplete order policy")? != policy.original_order_policy.identity
        { bail!("incomplete context differs from the separately held policies"); }
        exact_keys(&receipt["shared_inputs"], &["journal","session","recipe","capture_worker",
            "producer_registry","inventory","member_policy","original_order_policy"], "incomplete mixed shared inputs")?;
        let mut guards = BTreeMap::new();
        for role in ["journal","session","recipe","capture_worker","producer_registry",
            "inventory","member_policy","original_order_policy"] {
            if receipt["shared_inputs"][role] != context[role] {
                bail!("incomplete mixed shared identity differs: {role}");
            }
            if role != "journal" { insert_guard(&mut guards, pin(&context[role], role)?)?; }
        }
        let worker_pin = pin(&context["capture_worker"], "incomplete worker")?;
        let registry_pin = pin(&context["producer_registry"], "incomplete registry")?;
        check_raw(&worker_pin, include_str!("../../../../scripts/ocore_runtime_capture.py").as_bytes())?;
        check_raw(&registry_pin, include_str!("../../../../scripts/ocore_producer_registry.json").as_bytes())?;
        insert_guard(&mut guards, registry_snapshot_guard(&worker_pin, &registry_pin)?)?;
        for event in array(&context["journal"], "events")? {
            insert_guard(&mut guards, pin(event, "incomplete mixed journal event")?)?;
        }
        exact_keys(&receipt["partition"], &["lowering_unit_ids","non_lowering_unit_ids",
            "unclassified_unit_ids"], "incomplete mixed partition")?;
        for role in ["lowering_unit_ids","non_lowering_unit_ids","unclassified_unit_ids"] {
            if !receipt["partition"][role].is_array() {
                bail!("incomplete partition field is not an array: {role}");
            }
        }
        exact_keys(&receipt["diagnostics"], &["issues","failed_required_units","uncaptured_outputs"],
            "incomplete mixed diagnostics")?;
        let capture: Value = serde_json::from_slice(raw_report)?;
        if capture["schema"] != REPORT_SCHEMA { bail!("incomplete owner requires capture v2"); }
        let raw_units = array(&capture,"units")?;
        let rows = array(&receipt,"units")?;
        if raw_units.len() != rows.len() { bail!("incomplete receipt lost or added a unit occurrence"); }
        for (index, (raw,row)) in raw_units.iter().zip(rows).enumerate() {
            if !raw.is_object() { bail!("incomplete raw unit is not an object"); }
            exact_keys(row, &["index","id","representation","disposition","invocation_ids","kind",
                "producer","source","target_triple","input","input_role","input_state","reasons"],
                "incomplete mixed unit result")?;
            if row["index"].as_u64() != Some(u64::try_from(index)?)
                || row["id"] != raw["id"]
            { bail!("incomplete receipt changed a unit occurrence index/ID"); }
            for role in ["kind","producer","source"] {
                if row[role] != raw[role] { bail!("incomplete unit metadata differs: {role}"); }
            }
            if &row["target_triple"] != diagnostic_captured_unit_target(raw)? {
                bail!("incomplete unit target differs from its original representation payload");
            }
            if !row["invocation_ids"].is_array() { bail!("incomplete unit has no invocation occurrence list"); }
            let _ = strings(&row["reasons"], "incomplete unit reasons")?;
            let representation = string(row,"representation")?;
            let disposition = string(row,"disposition")?;
            if !matches!(representation,"llvm"|"configured-assembly"|"unsupported")
                || !matches!(disposition,"checked"|"refused")
            { bail!("incomplete unit has an invalid diagnostic tag"); }
            if disposition == "checked" {
                let role = match representation {
                    "llvm" => "llvm_ir",
                    "configured-assembly" => "configured_assembly",
                    _ => bail!("unsupported incomplete unit claims a checked input"),
                };
                if row["input_role"] != role || row["input_state"] != "consumed_and_checked" {
                    bail!("incomplete checked input has inconsistent diagnostic state");
                }
                // Validate identity syntax only. NEVER open this candidate path,
                // bind a ProducerInput, or expose its bytes from this owner.
                let _ = pin(&row["input"], "incomplete diagnostic input")?;
            } else if !row["input"].is_null() || row["input_state"] != "not_checked"
                || !(row["input_role"].is_null() || row["input_role"] == "llvm_ir"
                    || row["input_role"] == "configured_assembly")
            { bail!("incomplete refused unit claims a consumed output"); }
        }
        let raw_actions = array(&capture,"invocations")?;
        let statuses = array(&receipt,"invocation_statuses")?;
        if statuses.len() != raw_actions.len() {
            bail!("incomplete receipt lost or added an invocation occurrence");
        }
        for (index,(raw,status)) in raw_actions.iter().zip(statuses).enumerate() {
            if !raw.is_object() { bail!("incomplete original invocation is not an object"); }
            exact_keys(status, &["index","id","state","exit_code","execution","capture_errors"],
                "incomplete invocation status")?;
            if status["index"].as_u64() != Some(u64::try_from(index)?) {
                bail!("incomplete invocation index differs");
            }
            // Preserve actual values, including null/malformed failure evidence.
            // No default exit code, state coercion, ID map or deduplication.
            for role in ["id","state","exit_code","execution","capture_errors"] {
                if status[role] != raw[role] { bail!("incomplete invocation evidence differs: {role}"); }
            }
        }
        let unit_count = raw_units.len();
        let invocation_count = raw_actions.len();
        let owner = Self { report_pin,raw_report:raw_report.to_vec(),capture,raw_receipt,
            receipt,policy,guards,evidence,unit_count,invocation_count };
        owner.check_custody()?;
        Ok(owner)
    }
    fn write_summary(&self, output: &Path) -> Result<()> {
        let summary = serde_json::json!({
            "schema":"ocore-runtime-incomplete-mixed-reconstruction-v1",
            "scope":"retained-incomplete-cohort-only","verifier_exit_code":2,
            "report":self.report_pin,"context":self.policy.context.identity,
            "retained_raw_report":"mixed-held-report.json",
            "retained_raw_context":"mixed-held-context.json",
            "retained_raw_receipt":"mixed-verifier.stdout",
            "retained_receipt":"mixed-reverification.json",
            "retained_stderr":"mixed-verifier.stderr",
            "retained_observation":"mixed-verifier-observation.json",
            "unit_occurrences":self.unit_count,"invocation_occurrences":self.invocation_count,
            "source_capture_complete":false,"unit_lowering_complete":false,
            "native_artifact_dispatch":"unsupported",
            "order_binding_scope":"opaque-held-policy-identity-only",
            "qualifications":false_qualifications(),
        });
        write_new(&output.join("mixed-incomplete-reconstruction.json"),
            &serde_json::to_vec_pretty(&summary)?)
    }
}

/// Private terminal evidence; only the actual child wait result supplies code.
/// The raw stdout is retained unchanged, separate from its parsed receipt.

// Exit-2 observations remain incomplete. This session owns the original
// observation and only lends scoped, original LLVM buffers to diagnostics.
struct DiagnosticMember {
    id: Option<String>,
    action: Option<usize>,
    input: Option<BytesIdentity>,
    reasons: Vec<String>,
    closed: std::cell::Cell<bool>,
}
struct DiagnosticAction {
    inputs: Option<BTreeMap<String, ProducerInput>>,
    guards: BTreeMap<String, BytesIdentity>,
    issues: Vec<String>,
    closed: std::cell::Cell<bool>,
}
struct DiagnosticAttempt {
    index: usize,
    state: &'static str,
    issues: Vec<String>,
}

/// A borrowed diagnostic view, never a staged or admitted native module.
/// The higher-ranked callback cannot return a borrow of this local buffer.
pub(crate) struct MixedDiagnosticLlvmInput<'input> {
    index: usize,
    id: &'input str,
    path: &'input Path,
    bytes: &'input [u8],
    unit: &'input Value,
    action: &'input Value,
    target_triple: &'input str,
    member_policy: &'input [u8],
    original_order_policy: &'input [u8],
}
impl MixedDiagnosticLlvmInput<'_> {
    pub(crate) fn index(&self) -> usize { self.index }
    pub(crate) fn id(&self) -> &str { self.id }
    pub(crate) fn path(&self) -> &Path { self.path }
    pub(crate) fn bytes(&self) -> &[u8] { self.bytes }
    pub(crate) fn original_unit(&self) -> &Value { self.unit }
    pub(crate) fn original_action(&self) -> &Value { self.action }
    pub(crate) fn target_triple(&self) -> &str { self.target_triple }
    pub(crate) fn member_policy(&self) -> &[u8] { self.member_policy }
    pub(crate) fn original_order_policy(&self) -> &[u8] { self.original_order_policy }
}

/// An owned diagnostic result is distinct from capture or native admission.
pub(crate) enum MixedDiagnosticInputResult<T> {
    Refused { index: usize, reasons: Vec<String> },
    Observed { index: usize, result: std::result::Result<T, String> },
}

/// The actual exit-2 owner is retained once. There is no owner-return,
/// Serialize/Deserialize, caller-boolean, stage or admission constructor.
pub(crate) struct MixedDiagnosticSession {
    owner: IncompleteMixedCapture,
    members: Vec<DiagnosticMember>,
    actions: Vec<DiagnosticAction>,
    missing_required: Vec<String>,
    closed: std::cell::Cell<bool>,
    shared_failures: std::cell::RefCell<Vec<String>>,
    attempts: std::cell::RefCell<Vec<DiagnosticAttempt>>,
}
impl IncompleteMixedCapture {
    /// Move the intact observation, including every failure occurrence, into a
    /// diagnostic lifetime. Even an initial custody failure retains the owner.
    pub(crate) fn into_diagnostic_inputs(self) -> MixedDiagnosticSession {
        MixedDiagnosticSession::new(self)
    }
}
impl MixedDiagnosticSession {
    fn new(owner: IncompleteMixedCapture) -> Self {
        let initial_failure = owner.check_custody().err().map(|error| error.to_string());
        let (members, actions, missing_required) =
            Self::index(&owner, initial_failure.is_none());
        Self {
            owner, members, actions, missing_required,
            closed: std::cell::Cell::new(initial_failure.is_some()),
            shared_failures: std::cell::RefCell::new(initial_failure.into_iter().collect()),
            attempts: std::cell::RefCell::new(Vec::new()),
        }
    }

    // These are indexes of occurrences, not Cartesian copies of ambiguous
    // relations. All original arrays remain in the immutable actual-2 owner.
    fn index(owner: &IncompleteMixedCapture, may_bind: bool)
        -> (Vec<DiagnosticMember>, Vec<DiagnosticAction>, Vec<String>)
    {
        let units = owner.units().map(|row| row.raw).collect::<Vec<_>>();
        let rows = owner.units().map(|row| row.outcome).collect::<Vec<_>>();
        let raw_actions = owner.invocations().map(|row| row.raw).collect::<Vec<_>>();
        let mut unit_ids = BTreeMap::<String, Vec<usize>>::new();
        let mut action_ids = BTreeMap::<String, Vec<usize>>::new();
        let mut claims = BTreeMap::<String, Vec<(usize, usize)>>::new();
        let mut action_issues = vec![Vec::<String>::new(); raw_actions.len()];
        for (index, unit) in units.iter().enumerate() {
            if let Some(id) = unit["id"].as_str().filter(|id| !id.is_empty()) {
                unit_ids.entry(id.to_owned()).or_default().push(index);
            }
        }
        for (index, action) in raw_actions.iter().enumerate() {
            if let Some(id) = action["id"].as_str().filter(|id| !id.is_empty()) {
                action_ids.entry(id.to_owned()).or_default().push(index);
            } else {
                action_issues[index].push("original action has no nonempty string ID".to_owned());
            }
            match action["units"].as_array() {
                Some(owned) => for (position, unit) in owned.iter().enumerate() {
                    if let Some(id) = unit["id"].as_str().filter(|id| !id.is_empty()) {
                        claims.entry(id.to_owned()).or_default().push((index, position));
                    } else {
                        action_issues[index].push(format!(
                            "original action unit occurrence {position} has no nonempty string ID"));
                    }
                },
                None => action_issues[index].push("original action units is not an array".to_owned()),
            }
        }
        for (index, action) in raw_actions.iter().enumerate() {
            if let Some(id) = action["id"].as_str() {
                if action_ids.get(id).is_none_or(|group| group.len() != 1) {
                    action_issues[index].push("original action ID has ambiguous occurrences".to_owned());
                }
            }
            if let Some(owned) = action["units"].as_array() {
                for (position, unit) in owned.iter().enumerate() {
                    let Some(id) = unit["id"].as_str().filter(|id| !id.is_empty()) else { continue; };
                    match unit_ids.get(id) {
                        Some(flat) if flat.len() == 1 => {
                            if units[flat[0]] != unit {
                                action_issues[index].push(format!(
                                    "original action unit occurrence {position} differs from flat inventory"));
                            }
                        },
                        _ => action_issues[index].push(format!(
                            "original action unit occurrence {position} has missing/ambiguous flat membership")),
                    }
                    if claims.get(id).is_none_or(|group| group.len() != 1) {
                        action_issues[index].push(format!(
                            "original action unit occurrence {position} has ambiguous ownership"));
                    }
                }
            }
        }

        let mut members = Vec::with_capacity(units.len());
        let mut needed_actions = BTreeSet::new();
        for (index, (unit, row)) in units.iter().zip(&rows).enumerate() {
            let mut reasons = Vec::new();
            let id = unit["id"].as_str().filter(|id| !id.is_empty()).map(str::to_owned);
            let mut action_index = None;
            if let Some(id) = id.as_deref() {
                if !owner.policy.required_members.contains(id) {
                    reasons.push("original occurrence is outside the prior held required membership".to_owned());
                }
                if unit_ids.get(id).is_none_or(|group| group.len() != 1) {
                    reasons.push("original unit ID has ambiguous flat occurrences".to_owned());
                }
                match claims.get(id) {
                    Some(group) if group.len() == 1 => {
                        let (action, position) = group[0];
                        action_index = Some(action);
                        if &raw_actions[action]["units"][position] != *unit {
                            reasons.push("original action/unit value differs".to_owned());
                        }
                        match strings(&row["invocation_ids"], "diagnostic original invocation IDs") {
                            Ok(ids) if raw_actions[action]["id"].as_str()
                                .is_some_and(|action_id| ids == [action_id.to_owned()]) => {},
                            _ => reasons.push("receipt has missing/ambiguous original action association".to_owned()),
                        }
                    },
                    _ => reasons.push("original occurrence has missing/ambiguous ownership".to_owned()),
                }
            } else {
                reasons.push("original occurrence has no nonempty string ID".to_owned());
            }
            if row["representation"] != "llvm" {
                reasons.push("original representation is not an eligible LLVM diagnostic input".to_owned());
            }
            if row["disposition"] != "checked" {
                reasons.push("original occurrence was refused by held reconstruction".to_owned());
                if let Ok(original) = strings(&row["reasons"], "diagnostic original refusal reasons") {
                    reasons.extend(original);
                }
            }
            let expected = (|| -> Result<BytesIdentity> {
                if row["input_role"] != "llvm_ir" || row["input_state"] != "consumed_and_checked" {
                    bail!("original occurrence has no checked LLVM input contract");
                }
                let expected = pin(&row["input"], "diagnostic LLVM receipt input")?;
                if declared_identity(&unit["ir"], "diagnostic original LLVM input")? != expected {
                    bail!("receipt LLVM pin differs from original unit");
                }
                file_record(&unit["source"], "diagnostic original LLVM source")?;
                array(unit, "dependencies")?;
                if let Some(action) = action_index {
                    if unit["kind"] != raw_actions[action]["kind"]
                        || unit["producer"] != raw_actions[action]["producer"] {
                        bail!("original action/unit kind or producer differs");
                    }
                }
                Ok(expected)
            })();
            let input = match expected {
                Ok(expected) => Some(expected),
                Err(error) => { reasons.push(error.to_string()); None },
            };
            if reasons.is_empty() {
                if let Some(action) = action_index { needed_actions.insert(action); }
            }
            members.push(DiagnosticMember {
                id, action: action_index, input, reasons,
                closed: std::cell::Cell::new(false),
            });
            debug_assert_eq!(members.len(), index + 1);
        }

        let mut actions = Vec::with_capacity(raw_actions.len());
        for (index, action) in raw_actions.iter().enumerate() {
            let mut issues = std::mem::take(&mut action_issues[index]);
            let mut guards = BTreeMap::new();
            let mut inputs = None;
            if needed_actions.contains(&index) {
                if !may_bind {
                    issues.push("shared custody failed; producer binding was not attempted".to_owned());
                } else if issues.is_empty() {
                    // Full-value ownership and known status precede any
                    // producer-specific binding or candidate output read.
                    let bound = (|| -> Result<BTreeMap<String, ProducerInput>> {
                        if action["state"] != "finished" || action["exit_code"] != 0
                            || !array(action, "capture_errors")?.is_empty() {
                            bail!("original producing action did not complete");
                        }
                        for role in ["producer","kind","driver_kind","compiler","cwd"] {
                            if string(action, role)?.is_empty() {
                                bail!("original action provenance is absent: {role}");
                            }
                        }
                        if !Path::new(string(action, "cwd")?).is_absolute()
                            || strings(&action["argv"], "original action argv")?.is_empty()
                            || !action["frontend"].is_object()
                            || !action["build_environment"].is_object() {
                            bail!("original action command/frontend provenance is absent");
                        }
                        // Native/replay Rust actions cannot select a passing CGU
                        // while a sibling remains refused or outside prior policy.
                        // This metadata-only gate precedes bind_action and every
                        // original-output/bitcode guard or candidate read.
                        if action["producer"] == "rustc-llvm-v1" && action["kind"] == "rustc" {
                            let original_units = array(action, "units")?;
                            let native = action["rust_capture"]["policy"] == "rust-embedded-bc-v1"
                                || original_units.iter().any(|unit|
                                    unit["capture_policy"] == "rust-embedded-bc-v1");
                            let records = if native { Some(array(action, "saved_cgus")?) } else { None };
                            let mut cgu_indices = BTreeSet::new();
                            for original in original_units {
                                if original.get("ir").is_none() { continue; }
                                let id = string(original, "id")?;
                                let flat = unit_ids.get(id)
                                    .context("Rust CGU has no original flat occurrence")?;
                                if flat.len() != 1 {
                                    bail!("Rust CGU has ambiguous original flat occurrences");
                                }
                                let sibling = &members[flat[0]];
                                if !sibling.reasons.is_empty() || sibling.action != Some(index)
                                    || units[flat[0]] != original
                                    || sibling.id.as_deref() != Some(id)
                                {
                                    bail!("Rust CGU sibling is not an eligible uniquely owned checked LLVM occurrence");
                                }
                                let identity = declared_identity(&original["ir"], "original Rust CGU input")?;
                                if sibling.input.as_ref() != Some(&identity) {
                                    bail!("Rust CGU sibling receipt differs from its original LLVM input");
                                }
                                if let Some(records) = records {
                                    let cgu = original["saved_cgu_index"].as_u64()
                                        .and_then(|value| usize::try_from(value).ok())
                                        .context("Rust CGU original index is unavailable")?;
                                    if cgu >= records.len() || !cgu_indices.insert(cgu) {
                                        bail!("Rust CGU original index is outside or repeated in the held action");
                                    }
                                    if identity != declared_identity(&records[cgu]["bitcode"],
                                        "original Rust CGU saved bitcode")? {
                                        bail!("Rust CGU sibling receipt differs from saved bitcode");
                                    }
                                }
                            }
                            if let Some(records) = records {
                                if records.is_empty()
                                    || cgu_indices != (0..records.len()).collect::<BTreeSet<_>>() {
                                    bail!("Rust action has incomplete checked sibling CGU coverage");
                                }
                            }
                        }
                        let inputs = ProducerInput::bind_action(action)?;
                        // One immutable action-evidence slice can be shared by
                        // every Rust CGU. Normalize it once; these local pointer
                        // identities never escape or become pathname caches.
                        let mut seen_guard_slices = BTreeSet::new();
                        for input in inputs.values() {
                            let action_guards = input.guard_files();
                            if !seen_guard_slices.insert((action_guards.as_ptr() as usize,
                                action_guards.len())) { continue; }
                            for guard in action_guards {
                                // Shared guards are already indexed by path.
                                if owner.guards.get(&guard.path).is_some_and(|held| held != guard) {
                                    bail!("original action guard conflicts with held shared identity");
                                }
                                // Only the fixed evidence/implicit pin list needs
                                // this scan; never rescan the journal guard map.
                                for held in owner.evidence.iter()
                                    .chain([&owner.report_pin, &owner.policy.context.identity,
                                        &owner.policy.member_policy.identity,
                                        &owner.policy.original_order_policy.identity,
                                        &owner.policy.python.identity]) {
                                    if held.path == guard.path && held != guard {
                                        bail!("original action guard conflicts with held shared identity");
                                    }
                                }
                                insert_guard(&mut guards, guard.clone())?;
                            }
                        }
                        Ok(inputs)
                    })();
                    match bound {
                        Ok(bound) => inputs = Some(bound),
                        Err(error) => issues.push(error.to_string()),
                    }
                }
            }
            actions.push(DiagnosticAction {
                inputs, guards, issues, closed: std::cell::Cell::new(false),
            });
        }
        for member in &mut members {
            if !member.reasons.is_empty() { continue; }
            let checked = (|| -> Result<()> {
                let action = member.action.context("original diagnostic action is unavailable")?;
                if !actions[action].issues.is_empty() {
                    bail!("original action occurrence {action} is refused; full action issues are retained");
                }
                let id = member.id.as_deref().context("original diagnostic unit ID is unavailable")?;
                let inputs = actions[action].inputs.as_ref()
                    .context("original action has no checked producer contract")?;
                let input = inputs.get(id).context("original unit has no producer-specific input")?;
                if member.input.as_ref() != Some(input.original()) {
                    bail!("diagnostic receipt differs from original producer input");
                }
                Ok(())
            })();
            if let Err(error) = checked { member.reasons.push(error.to_string()); }
        }
        let missing_required = owner.policy.required_members.iter()
            .filter(|id| !unit_ids.contains_key(id.as_str())).cloned().collect();
        (members, actions, missing_required)
    }

    pub(crate) fn raw_report(&self) -> &[u8] { self.owner.raw_report() }
    pub(crate) fn raw_context(&self) -> &[u8] { self.owner.raw_context() }
    pub(crate) fn raw_receipt(&self) -> &[u8] { self.owner.raw_receipt() }
    pub(crate) fn capture(&self) -> &Value { self.owner.capture() }
    pub(crate) fn receipt(&self) -> &Value { self.owner.receipt() }
    pub(crate) fn original_units(&self) -> impl ExactSizeIterator<Item = IncompleteMixedUnit<'_>> {
        self.owner.units()
    }
    pub(crate) fn original_invocations(&self)
        -> impl ExactSizeIterator<Item = IncompleteMixedInvocation<'_>> {
        self.owner.invocations()
    }
    pub(crate) fn evidence_paths(&self) -> impl ExactSizeIterator<Item = &Path> {
        self.owner.evidence_paths()
    }
    pub(crate) fn member_policy(&self) -> &[u8] { self.owner.member_policy() }
    pub(crate) fn original_order_policy(&self) -> &[u8] { self.owner.original_order_policy() }
    pub(crate) fn member_count(&self) -> usize { self.members.len() }

    pub(crate) fn check_custody(&self) -> Result<()> {
        if self.closed.get() { bail!("diagnostic session is permanently closed after shared custody failure"); }
        if let Err(error) = self.owner.check_custody() {
            self.closed.set(true);
            self.shared_failures.borrow_mut().push(error.to_string());
            return Err(error.context("diagnostic session shared custody failed"));
        }
        Ok(())
    }
    fn check_action(&self, index: usize) -> Result<()> {
        let action = &self.actions[index];
        if action.closed.get() { bail!("diagnostic action is permanently closed after action custody failure"); }
        let mut errors = Vec::new();
        for guard in action.guards.values() {
            if let Err(error) = guard.check() { errors.push(error.to_string()); }
        }
        if !errors.is_empty() {
            action.closed.set(true);
            bail!("diagnostic action custody failed: {}", errors.join("; "));
        }
        Ok(())
    }
    fn record(&self, index: usize, state: &'static str, issues: Vec<String>) {
        self.attempts.borrow_mut().push(DiagnosticAttempt { index, state, issues });
    }
    fn refused<T>(&self, index: usize, reasons: Vec<String>) -> MixedDiagnosticInputResult<T> {
        self.record(index, "refused", reasons.clone());
        MixedDiagnosticInputResult::Refused { index, reasons }
    }

    /// Diagnose one original occurrence under the prior member selection.
    /// expected_target is consistency only, not ABI/purity/provider authority.
    /// T may own diagnostics; the higher-ranked input lifetime cannot escape.
    pub(crate) fn with_llvm_input<T, F>(
        &self, index: usize, expected_target: &str, operation: F,
    ) -> Result<MixedDiagnosticInputResult<T>>
    where F: for<'input> FnOnce(MixedDiagnosticLlvmInput<'input>) -> Result<T> {
        self.check_custody()?;
        let Some(member) = self.members.get(index) else {
            self.check_custody()?;
            bail!("diagnostic original occurrence index is outside the retained cohort");
        };
        if !member.reasons.is_empty() || member.closed.get() {
            let mut reasons = member.reasons.clone();
            if member.closed.get() { reasons.push("original input validation previously failed".to_owned()); }
            self.check_custody()?;
            return Ok(self.refused(index, reasons));
        }
        let unit = &self.owner.capture["units"][index];
        let target = diagnostic_captured_unit_target(unit).ok().and_then(Value::as_str);
        if expected_target.is_empty() || expected_target.contains('\0')
            || target != Some(expected_target) {
            self.check_custody()?;
            return Ok(self.refused(index, vec![
                "caller-selected diagnostic target differs from original nested LLVM target".to_owned()]));
        }
        let (Some(action_index), Some(id), Some(expected)) =
            (member.action, member.id.as_deref(), member.input.as_ref()) else {
                self.check_custody()?;
                return Ok(self.refused(index, vec!["original diagnostic binding is unavailable".to_owned()]));
            };
        let action = &self.actions[action_index];
        let Some(input) = action.inputs.as_ref().and_then(|inputs| inputs.get(id)) else {
            self.check_custody()?;
            return Ok(self.refused(index, vec!["original producer input is unavailable".to_owned()]));
        };
        if let Err(error) = self.check_action(action_index) {
            self.check_custody()?;
            return Ok(self.refused(index, vec![error.to_string()]));
        }
        let raw_action = &self.owner.capture["invocations"][action_index];
        let validated = (|| -> Result<Vec<u8>> {
            // The known action contract and exact original pin precede this
            // only candidate read; UNKNOWN/refused actions cannot reach it.
            if input.original() != expected {
                bail!("diagnostic original producer input differs from receipt");
            }
            let bytes = fs::read(&expected.path)
                .with_context(|| format!("read original diagnostic LLVM input {}", expected.path))?;
            check_raw(expected, &bytes)?;
            input.check_consumed(raw_action, unit, &bytes)?;
            Ok(bytes)
        })();
        let mut validation_error = None;
        let observed = match validated {
            Ok(bytes) => Some(operation(MixedDiagnosticLlvmInput {
                index, id, path:Path::new(&expected.path), bytes:&bytes, unit,
                action:raw_action, target_triple:expected_target,
                member_policy:&self.owner.policy.member_policy_raw,
                original_order_policy:&self.owner.policy.original_order_policy_raw,
            }).map_err(|error| error.to_string())),
            Err(error) => {
                member.closed.set(true);
                validation_error = Some(error.to_string());
                None
            },
        };
        // Both paths are evaluated, even after validation/operation failure.
        let action_post = self.check_action(action_index);
        let shared_post = self.check_custody();
        let mut errors = validation_error.into_iter().collect::<Vec<_>>();
        if let Some(Err(error)) = &observed { errors.push(error.clone()); }
        if let Err(error) = &action_post { errors.push(error.to_string()); }
        if let Err(error) = shared_post {
            errors.push(error.to_string());
            self.record(index, "shared-custody-failed", errors);
            return Err(error);
        }
        if action_post.is_err() || observed.is_none() {
            return Ok(self.refused(index, errors));
        }
        match observed {
            Some(result) => {
                self.record(index, if result.is_ok() { "observed" } else { "operation-error" }, errors);
                Ok(MixedDiagnosticInputResult::Observed { index, result })
            },
            None => unreachable!("validated diagnostic path records either refusal or an operation"),
        }
    }

    pub(crate) fn summary(&self) -> Value {
        let units = self.members.iter().enumerate().map(|(index, member)|
            serde_json::json!({
                "index":index,"id":self.owner.capture["units"][index]["id"],
                "representation":self.owner.receipt["units"][index]["representation"],
                "action_occurrence":member.action,"reasons":member.reasons,
                "input_validation_closed":member.closed.get(),
                "eligibility":if member.reasons.is_empty() {"eligible"} else {"refused"},
            })).collect::<Vec<_>>();
        let actions = self.actions.iter().enumerate().map(|(index, action)|
            serde_json::json!({"index":index,"id":self.owner.capture["invocations"][index]["id"],
                "issues":action.issues,"action_custody_closed":action.closed.get(),
                "producer_contract_bound":action.inputs.is_some(),"guard_count":action.guards.len()}))
            .collect::<Vec<_>>();
        let attempts = self.attempts.borrow().iter().map(|attempt|
            serde_json::json!({"index":attempt.index,"state":attempt.state,"issues":attempt.issues}))
            .collect::<Vec<_>>();
        serde_json::json!({
            "schema":"ocore-runtime-incomplete-llvm-diagnostic-input-session-v1",
            "scope":"per-original-occurrence-diagnostic-inputs-only","verifier_exit_code":2,
            "report":self.owner.report_pin,"context":self.owner.policy.context.identity,
            "shared_custody_closed":self.closed.get(),"shared_failures":*self.shared_failures.borrow(),
            "held_required_members":self.owner.policy.required_members,
            "missing_required_members":self.missing_required,
            "units":units,"actions":actions,"attempts":attempts,
            "source_capture_complete":false,"unit_lowering_complete":false,
            "native_artifact_dispatch":"unsupported",
            "order_binding_scope":"opaque-held-policy-identity-only",
            "qualifications":false_qualifications(),
        })
    }
}

struct ObservedMixedReceipt {
    receipt: Value,
    raw_receipt: Vec<u8>,
    exit_code: i32,
    evidence: Vec<BytesIdentity>,
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
        policy: &MixedCapturePolicy, allow_incomplete: bool,
    ) -> Result<ObservedMixedReceipt> {
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
        let observation_raw = serde_json::to_vec_pretty(&status)?;
        write_new(&output.join("mixed-verifier-observation.json"), &observation_raw)?;
        write_result.context("write held mixed verifier payload")?;
        post?;
        let exit_code = result.status.code();
        if !result.status.success() && !(allow_incomplete && exit_code == Some(2)) {
            bail!("held mixed verifier did not complete scoped reconstruction: {:?}; full cohort/output retained",result.status.code());
        }
        let receipt: Value = serde_json::from_slice(&result.stdout).context("decode held mixed verifier result")?;
        let receipt_raw = serde_json::to_vec_pretty(&receipt)?;
        write_new(&output.join("mixed-reverification.json"), &receipt_raw)?;
        let evidence = vec![
            BytesIdentity::consumed(&output.join("mixed-held-report.json"),raw_report),
            BytesIdentity::consumed(&output.join("mixed-held-context.json"),&policy.context_raw),
            BytesIdentity::consumed(&output.join("mixed-held-member-policy"),&policy.member_policy_raw),
            BytesIdentity::consumed(&output.join("mixed-held-original-order-policy"),&policy.original_order_policy_raw),
            BytesIdentity::consumed(&output.join("mixed-verifier.stdout"),&result.stdout),
            BytesIdentity::consumed(&output.join("mixed-verifier.stderr"),&result.stderr),
            BytesIdentity::consumed(&output.join("mixed-verifier-observation.json"),&observation_raw),
            BytesIdentity::consumed(&output.join("mixed-reverification.json"),&receipt_raw),
        ];
        Ok(ObservedMixedReceipt { receipt,raw_receipt:result.stdout,
            exit_code:exit_code.context("mixed verifier has no terminal exit code")?,evidence })
    }

    fn verify(
        report: &Path, raw_report: &[u8], output: &Path, python: &Path,
        policy: MixedCapturePolicy,
    ) -> Result<Self> {
        let observed = Self::invoke(report, raw_report, output, python, &policy, false)?;
        Self::from_receipt(report, raw_report, policy, observed.receipt)
    }

    // The actual-zero observe path enters this validator directly; it must not
    // call verify() and dispatch the worker a second time.
    fn from_receipt(
        report: &Path, raw_report: &[u8], policy: MixedCapturePolicy, receipt: Value,
    ) -> Result<Self> {
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

/// Invoke the genuine selected verifier exactly once. Actual exit 2 can retain
/// an incomplete diagnostic owner, but can never stage inputs or mint admission.
pub(super) fn observe(
    report: &Path, raw_report: &[u8], output: &Path, python: &Path,
    policy: MixedCapturePolicy,
) -> Result<MixedCaptureOutcome> {
    let observed = CheckedMixedCapture::invoke(report,raw_report,output,python,&policy,true)?;
    match observed.exit_code {
        0 => {
            let owner = CheckedMixedCapture::from_receipt(
                report,raw_report,policy,observed.receipt)?;
            let stage = owner.into_stage();
            if !stage.issues().is_empty() {
                stage.write_summary(output)?;
                bail!("mixed input staging failed shared custody; full cohort retained");
            }
            stage.check_custody()?;
            Ok(MixedCaptureOutcome::Reconstructed(stage))
        },
        2 => IncompleteMixedCapture::from_observation(report,raw_report,policy,observed)
            .map(MixedCaptureOutcome::Incomplete),
        _ => bail!("mixed verifier returned an unsupported terminal status"),
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
