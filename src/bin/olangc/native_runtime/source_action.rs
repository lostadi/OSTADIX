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

// Separate MachineUnit handoff: existing admitted LLVM lineage is unchanged.
#[path = "configured_assembly_consumer.rs"]
mod configured_assembly_consumer;
pub(super) use configured_assembly_consumer::{
    ConfiguredOriginalFunctionCfiBodyResult, ConfiguredOriginalFunctionCfiReport,
    RequiredOriginalFunctionCfi,
    ConfiguredAssemblyCommitment, ConfiguredOutputObservation, ConfiguredOutputResult,
    RequiredConfiguredOutput, UnadmittedConfiguredAction, WholeOutputSelector,
};

// Compiler preparation only; existing admitted LLVM capture is unchanged.
#[path = "configured_assembly_producer.rs"]
mod configured_assembly_producer;
pub(super) use configured_assembly_producer::{
    IdentityAssemblyCommitment, IdentityAssemblyFunctionPolicy,
    IdentityAssemblyIssue, IdentityAssemblyObservation,
};

/// Seal caller-held original outputs/order/floors before current observations.
/// The actual compiled registry is context, never a packaged admission token.
pub(super) fn hold_configured_assembly_action<'f>(
    producer: &str,
    action_selector: String,
    original_action: &[u8],
    required: Vec<RequiredConfiguredOutput<'f>>,
    occurrences: Vec<WholeOutputSelector>,
    target: o_lang::ocore::Target,
) -> std::result::Result<ConfiguredAssemblyCommitment<'f>, String> {
    ConfiguredAssemblyCommitment::seal(
        source_recipe::order_producer_registry().as_bytes(), producer, action_selector,
        original_action, required, occurrences, target,
    )
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct BytesIdentity {
    path: String,
    sha256: String,
    bytes: u64,
}

impl BytesIdentity {
    fn consumed(path: &Path, bytes: &[u8]) -> Self {
        Self {
            path: path.display().to_string(),
            sha256: digest(bytes),
            bytes: bytes.len() as u64,
        }
    }
    fn check(&self) -> Result<()> {
        let raw = fs::read(&self.path)
            .with_context(|| format!("lineage evidence unavailable: {}", self.path))?;
        if Self::consumed(Path::new(&self.path), &raw) != *self {
            bail!("lineage evidence changed: {}", self.path);
        }
        Ok(())
    }
}

fn strings(value: &Value, context: &str) -> Result<Vec<String>> {
    value
        .as_array()
        .with_context(|| format!("{context} must be an array"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .with_context(|| format!("{context} contains a non-string"))
        })
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
    if !Path::new(path).is_absolute()
        || sha.len() != 64
        || !sha
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || value["bytes"].as_u64().is_none()
    {
        bail!("{context} is not an exact original file identity");
    }
    Ok(())
}

// A registered verifier, not this JSON binding layer, establishes native byte
// edges. These private types keep its producer-specific evidence attached to
// every consumed unit. They cannot be deserialized into an admission capability.
#[derive(Debug, Clone)]
struct NativeActionEvidence {
    action_id: String,
    outputs: Vec<Value>,
    saved_cgus: Vec<Value>,
    resources: Vec<Value>,
    units: Vec<Value>,
    guard_files: Vec<BytesIdentity>,
}

// Rust frontend replay is one actual compiler action producing several LLVM
// files. Hold that original action once; never synthesize per-unit commands.
#[derive(Debug, Clone)]
struct ReplayActionEvidence {
    action: Value,
    replay_argv: Vec<String>,
    output_directory: PathBuf,
}

#[derive(Debug, Clone)]
enum ProducerInput {
    FrontendReplay {
        producer: &'static str,
        original: BytesIdentity,
        replay_argv: Vec<String>,
    },
    ActionFrontendReplay {
        original: BytesIdentity,
        emitted_filename: String,
        evidence: std::sync::Arc<ReplayActionEvidence>,
    },
    RustNativeEdges {
        original: BytesIdentity,
        // This is an association inside ONE admitted action, not a selector for
        // a fresh capture. The order join owns stable container/member selectors.
        saved_cgu_index: usize,
        evidence: std::sync::Arc<NativeActionEvidence>,
    },
}

fn declared_identity(value: &Value, context: &str) -> Result<BytesIdentity> {
    file_record(value, context)?;
    Ok(BytesIdentity {
        path: string(value, "path")?.to_owned(),
        sha256: string(value, "sha256")?.to_owned(),
        bytes: value["bytes"]
            .as_u64()
            .context("file byte count unavailable")?,
    })
}

fn retain_guard(rows: &mut Vec<BytesIdentity>, identity: BytesIdentity) -> Result<()> {
    if let Some(previous) = rows.iter().find(|row| row.path == identity.path) {
        if previous != &identity {
            bail!("producer evidence reuses a path with a different byte identity");
        }
    } else {
        rows.push(identity);
    }
    Ok(())
}

fn has_replay(value: &Value) -> bool {
    ["replay_argv", "replay_exit_code"]
        .iter()
        .any(|key| value.get(*key).is_some_and(|value| !value.is_null()))
}

impl ProducerInput {
    fn bind_action(action: &Value) -> Result<BTreeMap<String, Self>> {
        match (string(action, "producer")?, string(action, "kind")?) {
            ("clang-llvm-v1", "clang") => Self::bind_replay(action, "clang-llvm-v1"),
            ("rustc-llvm-v1", "rustc") => {
                let native = action["rust_capture"]["policy"] == "rust-embedded-bc-v1"
                    || array(action, "units")?
                        .iter()
                        .any(|unit| unit["capture_policy"] == "rust-embedded-bc-v1");
                if native {
                    Self::bind_native_edges(action)
                } else {
                    Self::bind_action_replay(action)
                }
            }
            _ => bail!("unsupported registered producer contract"),
        }
    }

    fn bind_replay(action: &Value, producer: &'static str) -> Result<BTreeMap<String, Self>> {
        if ["rust_capture", "saved_cgus", "rust_native_resources"]
            .iter()
            .any(|key| action.get(*key).is_some_and(|value| !value.is_null()))
        {
            bail!("frontend replay cannot substitute native-edge evidence");
        }
        let mut result = BTreeMap::new();
        for unit in array(action, "units")? {
            if unit.get("ir").is_none() {
                continue;
            }
            if unit
                .get("capture_policy")
                .is_some_and(|value| value != "frontend-replay-v1")
                || unit
                    .get("saved_cgu_index")
                    .is_some_and(|value| !value.is_null())
                || unit["ir"]["format"] != "llvm-text"
            {
                bail!("frontend replay unit has a different producer policy or format");
            }
            let replay_argv = strings(&unit["replay_argv"], "frontend replay argv")?;
            if replay_argv.is_empty() || unit["replay_exit_code"] != 0 {
                bail!("frontend replay did not complete successfully");
            }
            let id = string(unit, "id")?.to_owned();
            let input = Self::FrontendReplay {
                producer,
                original: declared_identity(&unit["ir"], "original replay LLVM input")?,
                replay_argv,
            };
            if result.insert(id, input).is_some() {
                bail!("producer contract repeats an original unit ID");
            }
        }
        Ok(result)
    }

    fn bind_action_replay(action: &Value) -> Result<BTreeMap<String, Self>> {
        // This is the existing registered rustc replay producer contract, not a
        // language-name fallback. Native-edge policy is dispatched separately.
        if action["producer"] != "rustc-llvm-v1" || action["kind"] != "rustc" {
            bail!("action-scoped replay requires its registered rustc producer");
        }
        if action.get("executed_argv").is_some()
            || ["rust_capture", "saved_cgus", "rust_native_resources"]
                .iter()
                .any(|key| action.get(*key).is_some_and(|value| !value.is_null()))
        {
            bail!(
                "action-scoped replay cannot substitute native-edge or executed-command evidence"
            );
        }
        if action["replay_exit_code"].as_i64() != Some(0) {
            bail!("action-scoped Rust frontend replay did not complete successfully");
        }
        let replay_argv = strings(
            &action["replay_argv"],
            "action-scoped Rust frontend replay argv",
        )?;
        if replay_argv.len() < 4
            || replay_argv.first().map(String::as_str) != Some(string(action, "compiler")?)
            || replay_argv[replay_argv.len() - 3..replay_argv.len() - 1]
                != ["--emit=llvm-ir,dep-info", "--out-dir"]
            || replay_argv
                .iter()
                .filter(|arg| arg.starts_with("--emit"))
                .count()
                != 1
            || replay_argv
                .iter()
                .filter(|arg| arg.starts_with("--out-dir"))
                .count()
                != 1
            || replay_argv.iter().any(|arg| arg.starts_with("-o"))
        {
            bail!("action-scoped Rust replay command differs from its registered output contract");
        }
        let output_directory =
            PathBuf::from(replay_argv.last().context("Rust replay directory absent")?);
        let normalized = output_directory.components().collect::<PathBuf>();
        if !output_directory.is_absolute()
            || normalized.as_os_str() != output_directory.as_os_str()
            || output_directory.components().any(|part| {
                !matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            bail!("action-scoped Rust replay output directory is not canonical and absolute");
        }
        let version = string(&action["frontend"], "version")?;
        if version.is_empty() {
            bail!("action-scoped Rust replay frontend version is unavailable");
        }
        let sources = array(action, "sources")?;
        let units = array(action, "units")?;
        if units.is_empty() {
            bail!("action-scoped Rust replay emitted unit inventory is empty");
        }
        let evidence = std::sync::Arc::new(ReplayActionEvidence {
            action: action.clone(),
            replay_argv,
            output_directory,
        });
        let mut filenames = BTreeSet::new();
        let mut result = BTreeMap::new();
        for unit in units {
            if has_replay(unit) {
                bail!("action-scoped Rust replay unit cannot invent a per-unit command");
            }
            if unit["producer"] != "rustc-llvm-v1"
                || unit["kind"] != "rustc"
                || unit["frontend_version"] != version
                || unit
                    .get("capture_policy")
                    .is_some_and(|policy| policy != "frontend-replay-v1")
                || unit
                    .get("saved_cgu_index")
                    .is_some_and(|value| !value.is_null())
                || !sources.contains(&unit["source"])
            {
                bail!("action-scoped Rust replay unit producer/frontend/source/policy differs from owner");
            }
            let original = declared_identity(&unit["ir"], "action-scoped Rust emitted LLVM input")?;
            let path = Path::new(&original.path);
            let normalized = path.components().collect::<PathBuf>();
            if unit["ir"]["format"] != "llvm-text"
                || normalized.as_os_str() != path.as_os_str()
                || path.components().any(|part| {
                    !matches!(
                        part,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                })
                || path.parent() != Some(evidence.output_directory.as_path())
                || path.extension().is_none_or(|extension| extension != "ll")
            {
                bail!("action-scoped Rust replay unit is outside its owning LLVM output directory");
            }
            let emitted_filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .context("action-scoped Rust emitted filename is unavailable")?
                .to_owned();
            if !filenames.insert(emitted_filename.clone()) {
                bail!("action-scoped Rust replay output selector is ambiguous");
            }
            let input = Self::ActionFrontendReplay {
                original,
                emitted_filename,
                evidence: std::sync::Arc::clone(&evidence),
            };
            if result
                .insert(string(unit, "id")?.to_owned(), input)
                .is_some()
            {
                bail!("producer contract repeats an original unit ID");
            }
        }
        Ok(result)
    }

    fn bind_native_edges(action: &Value) -> Result<BTreeMap<String, Self>> {
        if has_replay(action)
            || action["rust_capture"]["policy"] != "rust-embedded-bc-v1"
            || action["rust_capture"]["applied"] != true
            || action["rust_capture"]["frontend_replay_used"] != false
        {
            bail!("native-edge Rust capture cannot substitute a frontend replay");
        }
        if !array(action, "rust_cgu_gaps")?.is_empty() {
            bail!("native-edge Rust capture retains unsupported CGU gaps");
        }
        let outputs = array(action, "outputs")?.to_vec();
        let records = array(action, "saved_cgus")?.to_vec();
        let resources = array(action, "rust_native_resources")?.to_vec();
        let units = array(action, "units")?.to_vec();
        if outputs.is_empty() || records.is_empty() {
            bail!("native-edge original output/CGU inventory is empty");
        }
        let mut output_ids = Vec::new();
        let mut output_paths = BTreeSet::new();
        let mut guards = Vec::new();
        for output in &outputs {
            let identity = declared_identity(output, "original Rust native output")?;
            if !output_paths.insert(identity.path.clone()) {
                bail!("native-edge original output path is duplicated");
            }
            retain_guard(&mut guards, identity.clone())?;
            output_ids.push(identity);
        }
        let mut covered = vec![false; outputs.len()];
        for record in &records {
            if record["schema"] != "ocore-rust-native-bitcode-edge-v1"
                || record["compiler_invocation_id"] != action["id"]
                || record["cargo_parent_invocation_id"] != action["cargo_parent_invocation_id"]
                || !record["edge"].is_object()
            {
                bail!("native-edge compiler action/parent lineage differs");
            }
            let object = declared_identity(&record["object"], "saved native object")?;
            let bitcode = declared_identity(&record["bitcode"], "saved native bitcode")?;
            retain_guard(&mut guards, object.clone())?;
            retain_guard(&mut guards, bitcode)?;
            let original = if let Some(container) = record.get("container") {
                if !container["member"].is_object() {
                    bail!("native-edge original archive member evidence is unavailable");
                }
                declared_identity(&container["artifact"], "original native container")?
            } else {
                object
            };
            let index = output_ids
                .iter()
                .position(|output| output == &original)
                .context("native-edge object/container is not an original output")?;
            covered[index] = true;
        }
        for resource in &resources {
            let original = declared_identity(&resource["artifact"], "original Rust resource")?;
            let index = output_ids
                .iter()
                .position(|output| output == &original)
                .context("native-edge resource is not an original output")?;
            covered[index] = true;
        }
        if covered.iter().any(|covered| !covered) {
            bail!("native-edge original output inventory is incomplete");
        }
        let evidence = std::sync::Arc::new(NativeActionEvidence {
            action_id: string(action, "id")?.to_owned(),
            outputs,
            saved_cgus: records,
            resources,
            units,
            guard_files: guards,
        });
        let mut indices = BTreeSet::new();
        let mut result = BTreeMap::new();
        for unit in &evidence.units {
            if unit.get("ir").is_none() {
                continue;
            }
            if has_replay(unit) {
                bail!("native-edge Rust unit cannot substitute a frontend replay");
            }
            if unit["kind"] != "rustc"
                || unit["capture_policy"] != "rust-embedded-bc-v1"
                || unit["ir"]["format"] != "llvm-bitcode"
                || [
                    "source_production_ownership_verified",
                    "native_machine_equivalence_verified",
                    "post_lto_equivalence_verified",
                ]
                .iter()
                .any(|key| unit[*key] != false)
            {
                bail!("native-edge unit policy/format or qualification flags differ");
            }
            let index = unit["saved_cgu_index"]
                .as_u64()
                .and_then(|index| usize::try_from(index).ok())
                .context("native-edge CGU index is unavailable")?;
            if index >= evidence.saved_cgus.len() {
                bail!("native-edge CGU index is outside the held action");
            }
            if !indices.insert(index) {
                bail!("native-edge CGU ownership is duplicated");
            }
            let original = declared_identity(&unit["ir"], "original embedded LLVM input")?;
            if original
                != declared_identity(
                    &evidence.saved_cgus[index]["bitcode"],
                    "saved native bitcode",
                )?
            {
                bail!("native-edge unit/bitcode identity differs");
            }
            let input = Self::RustNativeEdges {
                original,
                saved_cgu_index: index,
                evidence: std::sync::Arc::clone(&evidence),
            };
            if result
                .insert(string(unit, "id")?.to_owned(), input)
                .is_some()
            {
                bail!("producer contract repeats an original unit ID");
            }
        }
        if indices != (0..evidence.saved_cgus.len()).collect::<BTreeSet<_>>() {
            bail!("native-edge CGU inventory is incomplete");
        }
        Ok(result)
    }

    fn original(&self) -> &BytesIdentity {
        match self {
            Self::FrontendReplay { original, .. }
            | Self::ActionFrontendReplay { original, .. }
            | Self::RustNativeEdges { original, .. } => original,
        }
    }

    fn check_consumed(&self, action: &Value, unit: &Value, raw: &[u8]) -> Result<()> {
        match self {
            Self::FrontendReplay {
                producer,
                replay_argv,
                ..
            } => {
                if action["producer"] != *producer
                    || unit["replay_exit_code"] != 0
                    || strings(&unit["replay_argv"], "consumed frontend replay argv")?
                        != *replay_argv
                    || unit["ir"]["format"] != "llvm-text"
                {
                    bail!("consumed frontend replay contract changed");
                }
            }
            Self::ActionFrontendReplay {
                emitted_filename,
                evidence,
                ..
            } => {
                if action != &evidence.action
                    || strings(&action["replay_argv"], "consumed action-scoped replay argv")?
                        != evidence.replay_argv
                    || action["replay_exit_code"].as_i64() != Some(0)
                    || has_replay(unit)
                    || array(&evidence.action, "units")?
                        .iter()
                        .find(|expected| expected["id"] == unit["id"])
                        != Some(unit)
                    || Path::new(string(&unit["ir"], "path")?)
                        .file_name()
                        .and_then(|name| name.to_str())
                        != Some(emitted_filename.as_str())
                {
                    bail!("consumed action-scoped replay evidence changed");
                }
            }
            Self::RustNativeEdges {
                saved_cgu_index,
                evidence,
                ..
            } => {
                if action["id"] != evidence.action_id
                    || action["producer"] != "rustc-llvm-v1"
                    || action["outputs"].as_array() != Some(&evidence.outputs)
                    || action["saved_cgus"].as_array() != Some(&evidence.saved_cgus)
                    || action["rust_native_resources"].as_array() != Some(&evidence.resources)
                    || action["units"].as_array() != Some(&evidence.units)
                    || has_replay(action)
                    || has_replay(unit)
                    || unit["saved_cgu_index"].as_u64() != Some(*saved_cgu_index as u64)
                    || unit["ir"]["format"] != "llvm-bitcode"
                {
                    bail!("consumed native-edge evidence changed");
                }
            }
        }
        if declared_identity(&unit["ir"], "consumed original LLVM input")? != *self.original()
            || self.original().sha256 != digest(raw)
            || self.original().bytes != raw.len() as u64
        {
            bail!("consumed LLVM buffer differs from admitted original unit");
        }
        Ok(())
    }

    fn guard_files(&self) -> &[BytesIdentity] {
        match self {
            Self::FrontendReplay { .. } | Self::ActionFrontendReplay { .. } => &[],
            Self::RustNativeEdges { evidence, .. } => &evidence.guard_files,
        }
    }
}

#[derive(Debug, Clone)]
struct UnitOwner {
    unit: Value,
    action: Value,
    input: ProducerInput,
}

// Deliberately no Serialize/Deserialize implementation: no claimed receipt or
// caller boolean can create the production capability used by the lowering loop.
pub(super) struct AdmittedCapture {
    path: PathBuf,
    raw: Vec<u8>,
    raw_sha256: String,
    receipt: Value,
    capture: Value,
    selected: BTreeSet<String>,
    units: BTreeMap<String, UnitOwner>,
}

// Borrowed only from the private, actually reverified owner. In particular this
// has no Deserialize implementation and cannot be made from packaged JSON.
#[derive(Clone, Copy)]
pub(super) struct AdmittedCaptureView<'a> {
    owner: &'a AdmittedCapture,
}
impl<'a> AdmittedCaptureView<'a> {
    pub(super) fn raw(&self) -> &'a [u8] {
        &self.owner.raw
    }
    pub(super) fn selected(&self) -> &'a BTreeSet<String> {
        &self.owner.selected
    }
    pub(super) fn check_report_bytes(&self) -> Result<()> {
        if fs::read(&self.owner.path)? != self.owner.raw {
            bail!("held admitted order capture changed");
        }
        Ok(())
    }
    pub(super) fn postguard(&self, output: &Path, python: &Path) -> Result<Value> {
        self.check_report_bytes()?;
        self.owner.postguard(output, python)
    }
}

impl AdmittedCapture {
    pub(super) fn checked_view<'a>(
        &'a self,
        path: &Path,
        raw: &[u8],
        selected: &BTreeSet<String>,
    ) -> Result<AdmittedCaptureView<'a>> {
        if path != self.path || raw != self.raw || selected != &self.selected {
            bail!("staged order capture differs from its admitted owner");
        }
        Ok(AdmittedCaptureView { owner: self })
    }

    pub(super) fn reverify(
        path: &Path,
        raw: &[u8],
        selected: &BTreeSet<String>,
        output: &Path,
        python: &Path,
    ) -> Result<Self> {
        let receipt = reverify_capture_with_python(path, raw, output, python)?;
        Self::bind_reverified(path, raw, selected, receipt)
    }

    // Private and called after the actual embedded capture verifier above.
    // Tests below exercise this binding layer with explicitly authored receipts.
    fn bind_reverified(
        path: &Path,
        raw: &[u8],
        selected: &BTreeSet<String>,
        receipt: Value,
    ) -> Result<Self> {
        let raw = raw.to_vec();
        let raw_sha256 = digest(&raw);
        let capture: Value = serde_json::from_slice(&raw).context("decode held capture bytes")?;
        if capture["schema"] != CAPTURE_FORMAT
            || receipt["schema"] != "ocore-runtime-capture-verification-v1"
            || receipt["verified"] != true
            || receipt["scope"]
                != "source-capture-unit-role-partition-and-observed-native-output-membership"
            || receipt["admitted_report"]
                != json!({"path":path,"sha256":raw_sha256,"bytes":raw.len()})
        {
            bail!("capture verifier receipt differs from the held report bytes");
        }
        if receipt["capture_worker_sha256"]
            != digest(include_str!("../../../../scripts/ocore_runtime_capture.py").as_bytes())
            || receipt["producer_registry_sha256"]
                != digest(
                    include_str!("../../../../scripts/ocore_producer_registry.json").as_bytes(),
                )
        {
            bail!("capture verifier worker/producer implementation differs");
        }
        let original_units = array(&capture, "units")?;
        if original_units.is_empty()
            || receipt["provenance_unit_count"].as_u64() != Some(original_units.len() as u64)
            || receipt["inventory"] != capture["unit_inventory"]["file"]
        {
            bail!("capture verifier inventory binding differs");
        }
        if unique_ids(&capture["lowering_unit_ids"], "capture lowering IDs")? != *selected
            || unique_ids(&receipt["lowering_unit_ids"], "verified lowering IDs")? != *selected
        {
            bail!("capture verified lowering selection differs");
        }
        for key in [
            "source",
            "manifest",
            "capture_worker",
            "producer_capabilities",
            "tools",
            "unit_inventory",
        ] {
            if !capture[key].is_object() {
                bail!("capture original provenance is unavailable: {key}");
            }
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
            let mut producer_inputs: Option<BTreeMap<String, ProducerInput>> = None;
            for unit in array(action, "units")? {
                if unit.get("ir").is_none() {
                    continue;
                }
                let id = string(unit, "id")?;
                if flattened.get(id).copied() != Some(unit) {
                    bail!("original action unit differs from flattened capture: {id}");
                }
                if action["state"] != "finished"
                    || action["exit_code"] != 0
                    || !array(action, "capture_errors")?.is_empty()
                {
                    bail!("original producing action did not complete: {action_id}");
                }
                for key in ["producer", "kind", "driver_kind", "compiler", "cwd"] {
                    if string(action, key)?.is_empty() {
                        bail!("original action provenance unavailable: {key}");
                    }
                }
                if !Path::new(string(action, "cwd")?).is_absolute()
                    || strings(&action["argv"], "original action argv")?.is_empty()
                    || !action["frontend"].is_object()
                    || !action["build_environment"].is_object()
                {
                    bail!("original action command/frontend provenance unavailable: {action_id}");
                }
                if unit["kind"] != action["kind"] {
                    bail!("original action/unit producer kind differs: {id}");
                }
                file_record(&unit["source"], "original source")?;
                file_record(&unit["ir"], "original LLVM input")?;
                array(unit, "dependencies")?;
                if producer_inputs.is_none() {
                    producer_inputs = Some(ProducerInput::bind_action(action)?);
                }
                let input = producer_inputs
                    .as_ref()
                    .and_then(|inputs| inputs.get(id))
                    .cloned()
                    .context("unit has no admitted producer-specific input contract")?;
                if units
                    .insert(
                        id.to_owned(),
                        UnitOwner {
                            unit: unit.clone(),
                            action: action.clone(),
                            input,
                        },
                    )
                    .is_some()
                {
                    bail!("duplicate original unit owner: {id}");
                }
            }
        }
        if units.keys().cloned().collect::<BTreeSet<_>>()
            != flattened.keys().cloned().collect::<BTreeSet<_>>()
            || !selected.iter().all(|id| units.contains_key(id))
        {
            bail!("missing or extra original action/unit ownership");
        }
        Ok(Self {
            path: path.to_owned(),
            raw,
            raw_sha256,
            receipt,
            capture,
            selected: selected.clone(),
            units,
        })
    }

    fn raw_sha256(&self) -> &str {
        &self.raw_sha256
    }

    pub(super) fn receipt(&self) -> &Value {
        &self.receipt
    }

    pub(super) fn begin(
        &self,
        id: &str,
        unit: &Value,
        raw: &[u8],
        owned_input: &Path,
        compiler: &Path,
        compiler_sha: &str,
    ) -> Result<UnitLineage> {
        let owner = self
            .units
            .get(id)
            .context("unit has no admitted producing action")?;
        if !self.selected.contains(id) || &owner.unit != unit {
            bail!("lowered unit differs from the admitted action selection");
        }
        owner.input.check_consumed(&owner.action, unit, raw)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(owned_input)?;
        file.write_all(raw)?;
        file.sync_all()?;
        drop(file);
        let consumed = BytesIdentity::consumed(owned_input, raw);
        consumed.check()?;
        let compiler_raw = fs::read(compiler).context("read lineage compiler")?;
        if digest(&compiler_raw) != compiler_sha {
            bail!("lineage compiler changed before import");
        }
        let original = owner.input.original().clone();
        let compiler = BytesIdentity::consumed(compiler, &compiler_raw);
        let capture = json!({"report":{"path":self.path,"sha256":self.raw_sha256(),"bytes":self.raw.len()},
            "manifest":self.capture["manifest"],"source":self.capture["source"],
            "capture_worker":self.capture["capture_worker"],"producer_capabilities":self.capture["producer_capabilities"],
            "inventory":self.capture["unit_inventory"],"verification":self.receipt});
        let mut guards = vec![original.clone(), consumed.clone(), compiler.clone()];
        guards.extend_from_slice(owner.input.guard_files());
        Ok(UnitLineage {
            schema: FORMAT,
            capture,
            original_action: owner.action.clone(),
            original_unit: owner.unit.clone(),
            original_llvm: original.clone(),
            consumed_llvm: consumed.clone(),
            compiler: compiler.clone(),
            imported_mir: None,
            verification: None,
            imported_target: None,
            emitted_object: None,
            emission_argv: None,
            object_inventory: None,
            final_byte_identity_stable: false,
            original_frontend_defaults_qualified: false,
            original_abi_qualified: false,
            final_link_qualified: false,
            runtime_qualified: false,
            physical_file_identity_qualified: false,
            preexec_tool_closure_qualified: false,
            guards,
        })
    }

    pub(super) fn postguard(&self, output: &Path, python: &Path) -> Result<Value> {
        if fs::read(&self.path)? != self.raw {
            bail!("held source capture changed before final reverification");
        }
        let directory = output.join("source-action-capture-postguard");
        fs::create_dir(&directory)?;
        let after = Self::reverify(&self.path, &self.raw, &self.selected, &directory, python)?;
        if after.capture != self.capture
            || after.units.keys().collect::<Vec<_>>() != self.units.keys().collect::<Vec<_>>()
        {
            bail!("source action ownership changed during lowering");
        }
        if fs::read(&self.path)? != self.raw {
            bail!("held source capture changed during final reverification");
        }
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
        &mut self,
        input_sha: &str,
        target: Value,
        mir_path: &Path,
        mir: &[u8],
        receipt_path: &Path,
        receipt_raw: &[u8],
    ) -> Result<()> {
        if self.imported_mir.is_some() {
            bail!("verified MIR lineage cannot be rebound");
        }
        let receipt: Value = serde_json::from_slice(receipt_raw)
            .context("decode consumed native verification receipt")?;
        if input_sha != self.original_llvm.sha256
            || target["triple"] != self.original_unit["ir"]["target_triple"]
            || target["data_layout"] != self.original_unit["ir"]["data_layout"]
        {
            bail!("verified MIR lineage input/target differs from original LLVM");
        }
        if receipt["format"] != "ocore-native-verification-v1"
            || receipt["verifier"] != "ocore-native-v1"
            || receipt["scope"] != "structural_ir_verification"
            || receipt["verified"] != true
            || receipt["module_sha256"] != digest(mir)
        {
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
        &mut self,
        module: &NativeModule,
        mir_path: &Path,
        mir: &[u8],
        receipt_path: &Path,
        receipt_raw: &[u8],
    ) -> Result<()> {
        self.join_verified(
            &module.provenance.input_sha256,
            serde_json::to_value(&module.target)?,
            mir_path,
            mir,
            receipt_path,
            receipt_raw,
        )
    }

    pub(super) fn observe_object(
        &mut self,
        path: &Path,
        raw: &[u8],
        argv: &[String],
    ) -> Result<()> {
        if self.imported_mir.is_none() {
            bail!("object lineage requires the verified MIR join");
        }
        if self.emitted_object.is_some() {
            bail!("object lineage cannot be rebound");
        }
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
        for identity in &self.guards {
            identity.check()?;
        }
        self.final_byte_identity_stable = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, BTreeSet<String>) {
        let unit = json!({"id":"action-1:0","kind":"clang","source":{"path":"/original/a.c","sha256":"a".repeat(64),"bytes":9},
            "ir":{"path":"/capture/units/a/input.ll","sha256":digest(b"original LLVM"),"bytes":13,"format":"llvm-text","target_triple":"riscv64-unknown-linux-gnu","data_layout":"e-m:e-p:64:64-i64:64-n32:64-S128"},
            "dependencies":[],"replay_argv":["/tool/clang","-O2","-emit-llvm","a.c"],"replay_exit_code":0});
        let action = json!({"id":"action-1","kind":"clang","producer":"clang-llvm-v1","driver_kind":"clang","compiler":"/tool/clang","cwd":"/original",
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
        AdmittedCapture::bind_reverified(
            Path::new("/capture/report.json"),
            &raw,
            selected,
            receipt(&raw, capture),
        )
    }
    fn error(capture: &Value, selected: &BTreeSet<String>, why: &str) {
        match bind(capture, selected) {
            Ok(_) => panic!("mutated fixture unexpectedly admitted"),
            Err(e) => assert!(e.to_string().contains(why), "{e}"),
        }
    }
    // Authored private binding fixtures only: no actual capture verifier,
    // compiler, provider or native execution is established by these controls.
    fn order_stage_fixture() -> StagedComponent {
        let (capture, selected) = fixture();
        let raw = serde_json::to_vec(&capture).unwrap();
        let admitted = bind(&capture, &selected).unwrap();
        StagedComponent {
            capture_path: PathBuf::from("/capture/report.json"),
            capture_bytes: raw,
            capture: capture.clone(),
            selected,
            admitted_capture: Some(admitted),
            modules: vec![("action-1:0".into(), b"authored MIR DATA".to_vec())],
            original_inputs: BTreeMap::from([(
                "action-1:0".into(),
                (capture["units"][0]["ir"].clone(), b"original LLVM".to_vec()),
            )]),
            source_capture_complete: true,
            unit_lowering_complete: true,
            compiler_sha256: None,
            coverage_path: PathBuf::from("/capture/coverage.json"),
        }
    }
    #[test]
    fn admitted_order_view_borrows_exact_capture_and_required_floor() {
        let stage = order_stage_fixture();
        let view = stage.admitted_order_capture().unwrap();
        assert_eq!(view.raw(), stage.capture_bytes);
        assert_eq!(view.selected(), &stage.selected);
        assert!(std::ptr::eq(
            view.raw().as_ptr(),
            stage.admitted_capture.as_ref().unwrap().raw.as_ptr()
        ));
        let decoded: Value = serde_json::from_slice(view.raw()).unwrap();
        assert_eq!(decoded["invocations"], stage.capture["invocations"]);
    }
    #[test]
    fn admitted_order_view_rejects_substituted_path_bytes_and_floor() {
        let (capture, selected) = fixture();
        let owner = bind(&capture, &selected).unwrap();
        let raw = serde_json::to_vec(&capture).unwrap();
        let other_path = Path::new("/different/report.json");
        assert_ne!(other_path, owner.path);
        let mut changed_raw = raw.clone();
        changed_raw.push(b' ');
        assert_ne!(changed_raw, raw);
        let mut changed_floor = selected.clone();
        assert!(changed_floor.insert("not-the-admitted-unit".into()));
        for result in [
            owner.checked_view(other_path, &raw, &selected),
            owner.checked_view(&owner.path, &changed_raw, &selected),
            owner.checked_view(&owner.path, &raw, &changed_floor),
        ] {
            let error = result.err().expect("changed owner binding was accepted");
            assert!(
                error
                    .to_string()
                    .contains("differs from its admitted owner"),
                "{error:#}"
            );
        }
    }
    #[test]
    fn staged_order_view_rejects_completion_flags_without_private_owner() {
        let mut stage = order_stage_fixture();
        assert!(stage.source_capture_complete && stage.unit_lowering_complete);
        assert!(stage.admitted_capture.take().is_some());
        assert!(stage.admitted_capture.is_none());
        let error = stage
            .admitted_order_capture()
            .err()
            .expect("claimed flags created an owner");
        assert!(
            error
                .to_string()
                .contains("actual staged capture admission owner"),
            "{error:#}"
        );
    }
    #[test]
    fn staged_order_view_rejects_incomplete_or_unbound_stage_inventory() {
        for mutation in ["unit_flag", "module_id", "original_input", "parsed_capture"] {
            let mut stage = order_stage_fixture();
            match mutation {
                "unit_flag" => {
                    stage.unit_lowering_complete = false;
                    assert!(!stage.unit_lowering_complete);
                }
                "module_id" => {
                    stage.modules[0].0 = "different-lowered-unit".into();
                    assert!(!stage.selected.contains(&stage.modules[0].0));
                }
                "original_input" => {
                    assert!(stage.original_inputs.remove("action-1:0").is_some());
                    assert!(stage.original_inputs.is_empty());
                }
                "parsed_capture" => {
                    stage.capture["name"] = json!("changed-after-admission");
                    let held: Value = serde_json::from_slice(&stage.capture_bytes).unwrap();
                    assert_ne!(held, stage.capture);
                }
                _ => unreachable!(),
            }
            let error = stage
                .admitted_order_capture()
                .err()
                .expect("unbound stage accepted");
            assert!(
                error.to_string().contains("complete bound staged capture"),
                "{mutation}: {error:#}"
            );
        }
    }
    #[test]
    fn admitted_order_report_byte_guard_observes_and_rejects_changed_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.json");
        let (capture, selected) = fixture();
        let raw = serde_json::to_vec(&capture).unwrap();
        fs::write(&path, &raw).unwrap();
        let mut proof = receipt(&raw, &capture);
        proof["admitted_report"]["path"] = json!(path);
        let owner = AdmittedCapture::bind_reverified(&path, &raw, &selected, proof).unwrap();
        let view = owner.checked_view(&path, &raw, &selected).unwrap();
        view.check_report_bytes().unwrap();
        let mut changed = raw.clone();
        changed.push(b' ');
        fs::write(&path, &changed).unwrap();
        let observed = fs::read(&path).unwrap();
        assert_eq!(observed, changed);
        assert_ne!(digest(&observed), digest(&raw));
        let error = view.check_report_bytes().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("held admitted order capture changed"),
            "{error:#}"
        );
    }
    #[test]
    fn order_finalization_rechecks_all_owners_after_later_helper_failure() {
        let directory = tempfile::tempdir().unwrap();
        let mut owners = Vec::new();
        let mut raws = Vec::new();
        for name in ["earlier", "later"] {
            let path = directory.path().join(format!("{name}.json"));
            let (capture, selected) = fixture();
            let raw = serde_json::to_vec(&capture).unwrap();
            fs::write(&path, &raw).unwrap();
            let mut proof = receipt(&raw, &capture);
            proof["admitted_report"]["path"] = json!(path);
            owners.push(AdmittedCapture::bind_reverified(&path, &raw, &selected, proof).unwrap());
            raws.push(raw);
        }
        let captures = owners
            .iter()
            .enumerate()
            .map(|(index, owner)| {
                (
                    format!("component-{index}"),
                    owner
                        .checked_view(&owner.path, &owner.raw, &owner.selected)
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let mut baseline = Vec::new();
        let value = provider_order::finalize_order_resolution(Ok(17usize), || {
            provider_order::check_order_capture_views(&captures, |index, capture| {
                baseline.push(index);
                capture.check_report_bytes()
            })
        })
        .unwrap();
        assert_eq!(value, 17);
        assert_eq!(baseline, vec![0, 1]);
        let mut later_helper_entered = false;
        let mut changed = raws[0].clone();
        changed.push(b' ');
        let helper: Result<()> = (|| {
            later_helper_entered = true;
            fs::write(&owners[0].path, &changed)?;
            Err(anyhow::anyhow!("authored later helper failure"))
        })();
        assert!(later_helper_entered);
        assert!(helper.is_err());
        let observed = fs::read(&owners[0].path).unwrap();
        assert_eq!(observed, changed);
        assert_ne!(digest(&observed), digest(&raws[0]));
        assert_eq!(fs::read(&owners[1].path).unwrap(), raws[1]);
        let mut final_checked = Vec::new();
        let error = provider_order::finalize_order_resolution(helper, || {
            provider_order::check_order_capture_views(&captures, |index, capture| {
                final_checked.push(index);
                capture.check_report_bytes()
            })
        })
        .unwrap_err();
        assert_eq!(final_checked, vec![0, 1]);
        let causes = format!("{error:#}");
        assert!(causes.contains("authored later helper failure"), "{causes}");
        assert!(causes.contains("component-0"), "{causes}");
        assert!(
            causes.contains("held admitted order capture changed"),
            "{causes}"
        );
    }
    fn lineage() -> UnitLineage {
        let (capture, _) = fixture();
        let original = BytesIdentity::consumed(Path::new("/original/input.ll"), b"original LLVM");
        UnitLineage {
            schema: FORMAT,
            capture: Value::Null,
            original_action: capture["invocations"][0].clone(),
            original_unit: capture["units"][0].clone(),
            original_llvm: original.clone(),
            consumed_llvm: original.clone(),
            compiler: original,
            imported_mir: None,
            verification: None,
            imported_target: None,
            emitted_object: None,
            emission_argv: None,
            object_inventory: None,
            final_byte_identity_stable: false,
            original_frontend_defaults_qualified: false,
            original_abi_qualified: false,
            final_link_qualified: false,
            runtime_qualified: false,
            physical_file_identity_qualified: false,
            preexec_tool_closure_qualified: false,
            guards: Vec::new(),
        }
    }
    fn target() -> Value {
        let (c, _) = fixture();
        json!({"triple":c["units"][0]["ir"]["target_triple"],"data_layout":c["units"][0]["ir"]["data_layout"],"abi":"lp64d"})
    }
    fn verification(mir: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({"format":"ocore-native-verification-v1","verifier":"ocore-native-v1","scope":"structural_ir_verification","verified":true,"module_sha256":digest(mir)})).unwrap()
    }
    #[test]
    fn serialized_capture_preserves_action_unit_command_and_unqualified_boundaries() {
        let (c, s) = fixture();
        let raw = serde_json::to_vec(&c).unwrap();
        let decoded: Value = serde_json::from_slice(&raw).unwrap();
        let got = bind(&decoded, &s).unwrap();
        let owner = &got.units["action-1:0"];
        assert_eq!(
            owner.action["argv"],
            json!(["-O2", "-fPIC", "-c", "a.c", "-o", "a.o"])
        );
        assert_eq!(owner.action["producer"], "clang-llvm-v1");
        assert_eq!(owner.unit["replay_argv"], c["units"][0]["replay_argv"]);
        let l = serde_json::to_value(lineage()).unwrap();
        for key in [
            "original_frontend_defaults_qualified",
            "original_abi_qualified",
            "final_link_qualified",
            "runtime_qualified",
            "physical_file_identity_qualified",
            "preexec_tool_closure_qualified",
        ] {
            assert_eq!(l[key], false);
        }
    }
    #[test]
    fn held_capture_receipt_hash_cannot_be_rebound_by_serialization() {
        let (c, s) = fixture();
        let raw = serde_json::to_vec(&c).unwrap();
        let mut r = receipt(&raw, &c);
        r["admitted_report"]["sha256"] = json!("0".repeat(64));
        assert_ne!(r["admitted_report"]["sha256"], digest(&raw));
        let e = AdmittedCapture::bind_reverified(Path::new("/capture/report.json"), &raw, &s, r)
            .err()
            .unwrap();
        assert!(e.to_string().contains("held report bytes"));
    }
    #[test]
    fn duplicate_original_action_and_unit_owners_are_rejected() {
        let (mut c, s) = fixture();
        let a = c["invocations"][0].clone();
        c["invocations"].as_array_mut().unwrap().push(a);
        assert_eq!(c["invocations"].as_array().unwrap().len(), 2);
        error(&c, &s, "duplicate or empty original action ID");
        c["invocations"][1]["id"] = json!("action-2");
        assert_eq!(c["invocations"][1]["units"][0]["id"], "action-1:0");
        error(&c, &s, "duplicate original unit owner");
    }
    #[test]
    fn missing_extra_and_changed_original_unit_joins_are_rejected() {
        let (base, s) = fixture();
        let mut c = base.clone();
        c["invocations"][0]["units"] = json!([]);
        assert!(c["invocations"][0]["units"].as_array().unwrap().is_empty());
        error(&c, &s, "missing or extra original action/unit ownership");
        c = base.clone();
        c["invocations"][0]["units"][0]["id"] = json!("unlisted:0");
        assert_ne!(
            c["invocations"][0]["units"][0]["id"],
            base["units"][0]["id"]
        );
        error(&c, &s, "differs from flattened capture");
        c = base.clone();
        c["units"][0]["ir"]["sha256"] = json!("f".repeat(64));
        assert_ne!(c["units"][0], c["invocations"][0]["units"][0]);
        error(&c, &s, "differs from flattened capture");
    }
    #[test]
    fn selected_units_and_missing_action_provenance_fail_closed() {
        let (c, _) = fixture();
        error(&c, &BTreeSet::new(), "verified lowering selection differs");
        let (_, s) = fixture();
        let mut c = c;
        c["invocations"][0]
            .as_object_mut()
            .unwrap()
            .remove("producer");
        assert!(c["invocations"][0].get("producer").is_none());
        error(&c, &s, "producer");
    }
    #[test]
    fn consumed_mir_receipt_input_and_target_have_exact_independent_joins() {
        let mir = b"verified MIR";
        let r = verification(mir);
        let mut l = lineage();
        let sha = l.original_llvm.sha256.clone();
        l.join_verified(
            &sha,
            target(),
            Path::new("/owned/module.json"),
            mir,
            Path::new("/owned/verify.json"),
            &r,
        )
        .unwrap();
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(v["imported_mir"]["sha256"], digest(mir));
        assert_eq!(v["verification"]["sha256"], digest(&r));
        let mut bad = lineage();
        let e = bad
            .join_verified(
                &"0".repeat(64),
                target(),
                Path::new("/m"),
                mir,
                Path::new("/v"),
                &r,
            )
            .unwrap_err();
        assert!(e.to_string().contains("input/target differs"));
        let mut t = target();
        t["triple"] = json!("x86_64-unknown-linux-gnu");
        assert_ne!(t, target());
        let mut bad = lineage();
        assert!(bad
            .join_verified(&sha, t, Path::new("/m"), mir, Path::new("/v"), &r)
            .unwrap_err()
            .to_string()
            .contains("input/target differs"));
        let mut t = target();
        t["data_layout"] = json!("e-p:32:32");
        assert_ne!(t, target());
        let mut bad = lineage();
        assert!(bad
            .join_verified(&sha, t, Path::new("/m"), mir, Path::new("/v"), &r)
            .unwrap_err()
            .to_string()
            .contains("input/target differs"));
        let wrong = verification(b"different MIR");
        assert_ne!(wrong, r);
        let mut bad = lineage();
        assert!(bad
            .join_verified(
                &sha,
                target(),
                Path::new("/m"),
                mir,
                Path::new("/v"),
                &wrong
            )
            .unwrap_err()
            .to_string()
            .contains("receipt differs"));
    }
    #[test]
    fn wrong_consumed_llvm_buffer_rejects_before_owned_copy_or_compiler_access() {
        let (c, s) = fixture();
        let admitted = bind(&c, &s).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "ostadix-source-input-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let owned = dir.join("input.ll");
        let wrong = b"wrong LLVM";
        assert_ne!(digest(wrong), c["units"][0]["ir"]["sha256"]);
        assert!(!owned.exists());
        let e = admitted
            .begin(
                "action-1:0",
                &c["units"][0],
                wrong,
                &owned,
                Path::new("/not-an-observed-compiler"),
                "unused",
            )
            .unwrap_err();
        assert!(e.to_string().contains("consumed LLVM buffer differs"));
        assert!(!owned.exists());
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn object_observation_requires_unique_verified_mir_and_keeps_failure_stage_bytes() {
        let mut l = lineage();
        let args = vec!["--emit".into(), "obj".into()];
        assert!(l
            .observe_object(Path::new("/object"), b"object", &args)
            .unwrap_err()
            .to_string()
            .contains("verified MIR join"));
        let sha = l.original_llvm.sha256.clone();
        l.join_verified(
            &sha,
            target(),
            Path::new("/m"),
            b"MIR",
            Path::new("/v"),
            &verification(b"MIR"),
        )
        .unwrap();
        l.observe_object(Path::new("/object"), b"object", &args)
            .unwrap();
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(v["emitted_object"]["sha256"], digest(b"object"));
        assert!(v["object_inventory"].is_null());
        assert_eq!(v["final_byte_identity_stable"], false);
        assert!(l
            .observe_object(Path::new("/object"), b"changed", &args)
            .unwrap_err()
            .to_string()
            .contains("cannot be rebound"));
    }
    #[test]
    fn late_byte_identity_failure_revokes_lineage_without_erasing_observed_stages() {
        let dir = std::env::temp_dir().join(format!(
            "ostadix-source-lineage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("evidence");
        fs::write(&path, b"before").unwrap();
        let mut l = lineage();
        l.guards.push(BytesIdentity::consumed(&path, b"before"));
        l.postguard().unwrap();
        assert!(l.final_byte_identity_stable);
        fs::write(&path, b"after!").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"after!");
        let e = l.postguard().unwrap_err();
        assert!(e.to_string().contains("lineage evidence changed"));
        assert!(!l.final_byte_identity_stable);
        assert_eq!(l.original_action["producer"], "clang-llvm-v1");
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    // Inert post-verifier binding controls. The byte-edge records below are
    // authored DATA, not genuine ELF extraction, actual admission or execution.
    fn sync_producer_units(capture: &mut Value) -> BTreeSet<String> {
        capture["units"] = capture["invocations"][0]["units"].clone();
        let ids = capture["units"]
            .as_array()
            .unwrap()
            .iter()
            .map(|unit| unit["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        capture["lowering_unit_ids"] = json!(ids);
        ids.into_iter().collect()
    }

    fn native_edge_fixture() -> (Value, BTreeSet<String>, Vec<Vec<u8>>) {
        let (mut capture, _) = fixture();
        let identity =
            |path: &str, raw: &[u8]| json!({"path":path,"bytes":raw.len(),"sha256":digest(raw)});
        let outputs = vec![
            identity("/native/first.o", b"authored object zero"),
            identity("/native/second.rlib", b"authored archive one"),
            identity("/native/build.d", b"authored dependency resource"),
        ];
        let raw = vec![
            b"authored native bitcode zero".to_vec(),
            b"authored native bitcode one".to_vec(),
        ];
        let mut units = Vec::new();
        let mut records = Vec::new();
        for (index, bytes) in raw.iter().enumerate() {
            let bitcode = identity(&format!("/capture/cgu-{index}.bc"), bytes);
            let object = if index == 0 {
                outputs[0].clone()
            } else {
                identity("/capture/cgu-1.o", b"authored retained member")
            };
            let mut record = json!({"schema":"ocore-rust-native-bitcode-edge-v1",
                "compiler_invocation_id":"action-1","cargo_parent_invocation_id":"held-parent",
                "object":object,"bitcode":bitcode,"edge":{"authored_binding_control":true}});
            if index == 1 {
                record["container"] = json!({"artifact":outputs[1],"member":{
                    "index":9,"name":"original.member.o","name_bytes":[111,46,111],
                    "authored_other_metadata":"preserved"}});
            }
            let mut unit = capture["units"][0].clone();
            unit["id"] = json!(format!("action-1:{index}"));
            unit["kind"] = json!("rustc");
            unit["ir"] = bitcode;
            unit["ir"]["format"] = json!("llvm-bitcode");
            unit["ir"]["target_triple"] = json!("riscv64-unknown-linux-gnu");
            unit["ir"]["data_layout"] = json!("e-m:e-p:64:64-i64:64-n32:64-S128");
            unit.as_object_mut().unwrap().remove("replay_argv");
            unit.as_object_mut().unwrap().remove("replay_exit_code");
            unit["saved_cgu_index"] = json!(index);
            unit["capture_policy"] = json!("rust-embedded-bc-v1");
            unit["source_production_ownership_verified"] = json!(false);
            unit["native_machine_equivalence_verified"] = json!(false);
            unit["post_lto_equivalence_verified"] = json!(false);
            records.push(record);
            units.push(unit);
        }
        let action = &mut capture["invocations"][0];
        action["kind"] = json!("rustc");
        action["producer"] = json!("rustc-llvm-v1");
        action["driver_kind"] = json!("rustc");
        action["compiler"] = json!("/tool/rustc");
        action["cargo_parent_invocation_id"] = json!("held-parent");
        action["rust_capture"] = json!({"policy":"rust-embedded-bc-v1","applied":true,
            "frontend_replay_used":false,"post_lto_equivalence_verified":false});
        action["outputs"] = json!(outputs);
        action["saved_cgus"] = json!(records);
        action["rust_cgu_gaps"] = json!([]);
        action["rust_native_resources"] = json!([{"artifact":action["outputs"][2],
            "kind":"rust_dependency_file","native_code":false,"ownership_qualified":false}]);
        action["units"] = json!(units);
        let selected = sync_producer_units(&mut capture);
        (capture, selected, raw)
    }

    #[test]
    fn registered_clang_replay_consumes_its_successful_llvm_text_contract() {
        let (capture, selected) = fixture();
        let owner = bind(&capture, &selected).unwrap();
        let input = &owner.units["action-1:0"].input;
        assert!(matches!(
            input,
            ProducerInput::FrontendReplay {
                producer: "clang-llvm-v1",
                ..
            }
        ));
        input
            .check_consumed(
                &capture["invocations"][0],
                &capture["units"][0],
                b"original LLVM",
            )
            .unwrap();
        assert!(input.guard_files().is_empty());
    }

    #[test]
    fn registered_rust_replay_preserves_the_replay_contract() {
        let (capture, selected, _) = rust_action_replay_fixture(1);
        let owner = bind(&capture, &selected).unwrap();
        assert!(matches!(
            &owner.units["action-1:0"].input,
            ProducerInput::ActionFrontendReplay { .. }
        ));
        assert!(capture["units"][0].get("replay_argv").is_none());
        assert!(capture["units"][0].get("replay_exit_code").is_none());
        assert_eq!(capture["invocations"][0]["replay_exit_code"], 0);
    }

    #[test]
    fn registered_rust_native_edges_consume_all_cgus_without_frontend_replay() {
        let (capture, selected, raw) = native_edge_fixture();
        let owner = bind(&capture, &selected).unwrap();
        assert_eq!(owner.units.len(), 2);
        let directory = tempfile::tempdir().unwrap();
        let compiler = directory.path().join("authored-compiler");
        fs::write(&compiler, b"compiler binding control").unwrap();
        let compiler_sha = digest(b"compiler binding control");
        for (index, bytes) in raw.iter().enumerate() {
            let unit = &capture["units"][index];
            assert!(unit.get("replay_argv").is_none() && unit.get("replay_exit_code").is_none());
            let path = directory.path().join(format!("owned-{index}.bc"));
            let lineage = owner
                .begin(
                    unit["id"].as_str().unwrap(),
                    unit,
                    bytes,
                    &path,
                    &compiler,
                    &compiler_sha,
                )
                .unwrap();
            assert_eq!(fs::read(&path).unwrap(), *bytes);
            assert_eq!(lineage.original_action, capture["invocations"][0]);
            assert!(!lineage.runtime_qualified && !lineage.original_abi_qualified);
        }
    }

    #[test]
    fn registered_rust_native_edges_preserve_complete_output_member_and_resource_order() {
        let (capture, selected, _) = native_edge_fixture();
        let owner = bind(&capture, &selected).unwrap();
        let ProducerInput::RustNativeEdges {
            evidence,
            saved_cgu_index,
            ..
        } = &owner.units["action-1:1"].input
        else {
            panic!("native contract not selected")
        };
        assert_eq!(*saved_cgu_index, 1);
        assert_eq!(
            evidence.outputs,
            capture["invocations"][0]["outputs"]
                .as_array()
                .unwrap()
                .clone()
        );
        assert_eq!(
            evidence.saved_cgus,
            capture["invocations"][0]["saved_cgus"]
                .as_array()
                .unwrap()
                .clone()
        );
        assert_eq!(evidence.resources.len(), 1);
        assert_eq!(evidence.saved_cgus[1]["container"]["member"]["index"], 9);
        assert_eq!(
            evidence.saved_cgus[1]["container"]["member"]["name"],
            "original.member.o"
        );
        assert_eq!(evidence.guard_files.len(), 6);
        assert!(evidence
            .guard_files
            .iter()
            .any(|file| file.path == "/native/build.d"));
    }

    #[test]
    fn rust_native_edges_reject_any_replay_substitution() {
        for (scope, field, value) in [
            ("action", "replay_argv", json!(["rustc", "--emit=llvm-bc"])),
            ("action", "replay_exit_code", json!(0)),
            ("unit", "replay_argv", json!(["rustc"])),
            ("unit", "replay_exit_code", json!(0)),
        ] {
            let (mut capture, _, _) = native_edge_fixture();
            if scope == "action" {
                capture["invocations"][0][field] = value;
            } else {
                capture["invocations"][0]["units"][1][field] = value;
            }
            let selected = sync_producer_units(&mut capture);
            assert!(has_replay(if scope == "action" {
                &capture["invocations"][0]
            } else {
                &capture["units"][1]
            }));
            error(&capture, &selected, "cannot substitute a frontend replay");
        }
    }

    #[test]
    fn rust_native_edges_reject_missing_duplicate_or_out_of_range_cgu_units() {
        for mutation in ["missing", "duplicate", "outside"] {
            let (mut capture, _, _) = native_edge_fixture();
            let expected = match mutation {
                "missing" => {
                    capture["invocations"][0]["units"]
                        .as_array_mut()
                        .unwrap()
                        .pop();
                    "CGU inventory is incomplete"
                }
                "duplicate" => {
                    capture["invocations"][0]["units"][1]["saved_cgu_index"] = json!(0);
                    "CGU ownership is duplicated"
                }
                "outside" => {
                    capture["invocations"][0]["units"][1]["saved_cgu_index"] = json!(99);
                    "CGU index is outside"
                }
                _ => unreachable!(),
            };
            let selected = sync_producer_units(&mut capture);
            error(&capture, &selected, expected);
        }
    }

    #[test]
    fn rust_native_edges_reject_bitcode_identity_or_origin_output_substitution() {
        for mutation in ["bitcode", "object"] {
            let (mut capture, _, _) = native_edge_fixture();
            if mutation == "bitcode" {
                capture["invocations"][0]["units"][1]["ir"]["sha256"] = json!("e".repeat(64));
            } else {
                capture["invocations"][0]["saved_cgus"][0]["object"]["path"] =
                    json!("/not-an-original-output.o");
            }
            let selected = sync_producer_units(&mut capture);
            error(
                &capture,
                &selected,
                if mutation == "bitcode" {
                    "unit/bitcode identity differs"
                } else {
                    "object/container is not an original output"
                },
            );
        }
    }

    #[test]
    fn rust_native_edges_reject_unclassified_or_missing_native_outputs() {
        for mutation in ["unclassified", "missing_resource"] {
            let (mut capture, _, _) = native_edge_fixture();
            if mutation == "unclassified" {
                capture["invocations"][0]["outputs"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                    "path":"/native/unaccounted.o","bytes":4,"sha256":"d".repeat(64)}));
            } else {
                capture["invocations"][0]["rust_native_resources"] = json!([]);
            }
            let selected = sync_producer_units(&mut capture);
            error(
                &capture,
                &selected,
                "original output inventory is incomplete",
            );
        }
    }

    #[test]
    fn rust_native_edges_reject_broken_original_action_and_parent_lineage() {
        for field in [
            "compiler_invocation_id",
            "cargo_parent_invocation_id",
            "schema",
        ] {
            let (mut capture, selected, _) = native_edge_fixture();
            capture["invocations"][0]["saved_cgus"][1][field] = json!("different-original");
            assert_eq!(
                capture["invocations"][0]["saved_cgus"][1][field],
                "different-original"
            );
            error(
                &capture,
                &selected,
                "compiler action/parent lineage differs",
            );
        }
    }

    #[test]
    fn registered_contracts_reject_unknown_producers_or_policy_substitution() {
        for mutation in ["producer", "kind", "policy"] {
            let (mut capture, _) = fixture();
            match mutation {
                "producer" => {
                    capture["invocations"][0]["producer"] = json!("unregistered-producer")
                }
                "kind" => {
                    capture["invocations"][0]["kind"] = json!("rustc");
                    capture["invocations"][0]["units"][0]["kind"] = json!("rustc");
                }
                "policy" => {
                    capture["invocations"][0]["units"][0]["capture_policy"] =
                        json!("rust-embedded-bc-v1")
                }
                _ => unreachable!(),
            }
            let selected = sync_producer_units(&mut capture);
            error(
                &capture,
                &selected,
                if mutation == "policy" {
                    "different producer policy or format"
                } else {
                    "unsupported registered producer contract"
                },
            );
        }
    }

    #[test]
    fn replay_contract_checks_every_unit_in_a_multi_output_action() {
        let (mut capture, _) = fixture();
        let mut later = capture["invocations"][0]["units"][0].clone();
        later["id"] = json!("action-1:later");
        later["replay_exit_code"] = json!(1);
        capture["invocations"][0]["units"]
            .as_array_mut()
            .unwrap()
            .push(later);
        let selected = sync_producer_units(&mut capture);
        assert_eq!(capture["units"].as_array().unwrap().len(), 2);
        assert_eq!(capture["units"][0]["replay_exit_code"], 0);
        error(
            &capture,
            &selected,
            "frontend replay did not complete successfully",
        );
    }

    #[test]
    fn typed_native_input_rechecks_consumed_bytes_before_owned_copy() {
        let (capture, selected, _) = native_edge_fixture();
        let owner = bind(&capture, &selected).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("must-not-exist.bc");
        let error = owner
            .begin(
                "action-1:1",
                &capture["units"][1],
                b"wrong native bitcode",
                &output,
                Path::new("/not-a-compiler"),
                "unused",
            )
            .unwrap_err();
        assert!(error.to_string().contains("consumed LLVM buffer differs"));
        assert!(!output.exists());
    }

    #[test]
    fn typed_native_input_rechecks_complete_evidence_before_owned_copy() {
        let (capture, selected, raw) = native_edge_fixture();
        let mut owner = bind(&capture, &selected).unwrap();
        owner.units.get_mut("action-1:1").unwrap().action["outputs"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert_ne!(
            owner.units["action-1:1"].action["outputs"],
            capture["invocations"][0]["outputs"]
        );
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("must-not-exist.bc");
        let error = owner
            .begin(
                "action-1:1",
                &capture["units"][1],
                &raw[1],
                &output,
                Path::new("/not-a-compiler"),
                "unused",
            )
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("consumed native-edge evidence changed"));
        assert!(!output.exists());
    }

    #[test]
    fn native_contract_rejects_mixed_policy_and_promoted_qualification_flags() {
        for mutation in ["policy", "qualification"] {
            let (mut capture, _, _) = native_edge_fixture();
            if mutation == "policy" {
                capture["invocations"][0]["units"][1]["capture_policy"] =
                    json!("frontend-replay-v1");
            } else {
                capture["invocations"][0]["units"][1]["source_production_ownership_verified"] =
                    json!(true);
            }
            let selected = sync_producer_units(&mut capture);
            error(
                &capture,
                &selected,
                "policy/format or qualification flags differ",
            );
        }
    }
    #[test]
    fn capture_digest_cache_borrows_owned_identity_after_caller_changes() {
        let (c, selected) = fixture();
        let mut raw = serde_json::to_vec(&c).unwrap();
        let original = raw.clone();
        let owner = AdmittedCapture::bind_reverified(
            Path::new("/capture/report.json"),
            &raw,
            &selected,
            receipt(&raw, &c),
        )
        .unwrap();
        let view = owner.checked_view(&owner.path, &raw, &selected).unwrap();
        assert!(std::ptr::eq(
            owner.raw_sha256().as_ptr(),
            owner.raw_sha256.as_ptr()
        ));
        assert!(std::ptr::eq(view.raw().as_ptr(), owner.raw.as_ptr()));
        assert_ne!(view.raw().as_ptr(), raw.as_ptr());
        raw.push(b' ');
        assert_ne!(raw, original);
        assert_eq!(view.raw(), original);
        assert_eq!(owner.raw_sha256(), digest(&original));
        assert_ne!(owner.raw_sha256(), digest(&raw));
    }
    #[test]
    fn capture_digest_cache_rejects_changed_raw_despite_correct_claimed_length() {
        let (c, selected) = fixture();
        let raw = serde_json::to_vec(&c).unwrap();
        let mut proof = receipt(&raw, &c);
        let mut changed = raw.clone();
        changed.push(b' ');
        proof["admitted_report"]["bytes"] = json!(changed.len());
        assert_eq!(serde_json::from_slice::<Value>(&changed).unwrap(), c);
        assert_ne!(proof["admitted_report"]["sha256"], digest(&changed));
        let e = AdmittedCapture::bind_reverified(
            Path::new("/capture/report.json"),
            &changed,
            &selected,
            proof,
        )
        .err()
        .expect("stale digest admitted");
        assert!(e.to_string().contains("held report bytes"), "{e:#}");
    }
    #[test]
    fn capture_digest_cache_keeps_identical_report_for_every_native_unit() {
        let (c, selected, inputs) = native_edge_fixture();
        let raw = serde_json::to_vec(&c).unwrap();
        let owner = bind(&c, &selected).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let compiler = dir.path().join("compiler");
        fs::write(&compiler, b"authored compiler DATA").unwrap();
        let sha = digest(b"authored compiler DATA");
        let expected = json!({"report":{"path":"/capture/report.json","sha256":digest(&raw),"bytes":raw.len()},"manifest":c["manifest"],"source":c["source"],"capture_worker":c["capture_worker"],"producer_capabilities":c["producer_capabilities"],"inventory":c["unit_inventory"],"verification":owner.receipt()});
        assert_eq!(owner.raw_sha256(), digest(&raw));
        assert_eq!(inputs.len(), 2);
        for (i, input) in inputs.iter().enumerate() {
            let unit = &c["units"][i];
            let out = dir.path().join(format!("unit-{i}.bc"));
            let lineage = owner
                .begin(
                    unit["id"].as_str().unwrap(),
                    unit,
                    input,
                    &out,
                    &compiler,
                    &sha,
                )
                .unwrap();
            assert_eq!(lineage.capture, expected);
            assert_eq!(fs::read(out).unwrap(), *input);
            assert!(!lineage.runtime_qualified);
            assert!(!lineage.final_link_qualified);
        }
    }
    #[test]
    fn capture_digest_cache_does_not_authorize_wrong_replay_or_native_input() {
        for native in [false, true] {
            let (c, selected) = if native {
                let (c, s, _) = native_edge_fixture();
                (c, s)
            } else {
                fixture()
            };
            let owner = bind(&c, &selected).unwrap();
            assert_eq!(owner.raw_sha256(), digest(&owner.raw));
            let dir = tempfile::tempdir().unwrap();
            let output = dir.path().join("must-not-exist");
            let unit = &c["units"][0];
            let wrong = b"different from admitted LLVM DATA";
            assert_ne!(unit["ir"]["sha256"], digest(wrong));
            let e = owner
                .begin(
                    unit["id"].as_str().unwrap(),
                    unit,
                    wrong,
                    &output,
                    Path::new("/not-a-compiler"),
                    "unused",
                )
                .unwrap_err();
            assert!(
                e.to_string()
                    .contains("consumed LLVM buffer differs from admitted original unit"),
                "{native}: {e:#}"
            );
            assert!(!output.exists());
        }
    }
    include!("source_action_replay_tests.rs");
}
