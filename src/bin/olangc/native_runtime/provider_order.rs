//! V3 original occurrence commitment and original-to-fresh action consistency.
//! The caller-selected policy is sealed before fresh staging. It is not proof
//! of an authentic original-order producer, archive extraction/linker semantics,
//! final initializer order, provider closure, or runtime execution.
use super::*;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub(super) const PLAN_V3: &str = "ocore-native-provider-plan-v3";
const POLICY: &str = "ocore-original-provider-order-v3";
const PACKAGE: &str = "ocore-original-provider-order-binding-v3";
const PACKAGE_GENERAL: &str = "ocore-original-provider-order-binding-v4";
const GENERAL_JOIN: &str = include_str!("general_source_order_join.py");
const JOIN: &str = include_str!("source_order_join.py");
const DRIVER: &str = r#"import hashlib,json,pathlib,sys
helper,helper_sha,request,request_sha,python_sha=sys.argv[1:]
assert hashlib.sha256(pathlib.Path('/proc/self/exe').read_bytes()).hexdigest()==python_sha, 'actual Python image differs'
source=pathlib.Path(helper).read_bytes();raw=pathlib.Path(request).read_bytes()
assert hashlib.sha256(source).hexdigest()==helper_sha, 'embedded order helper differs'
assert hashlib.sha256(raw).hexdigest()==request_sha, 'order request differs'
namespace={'__name__':'ocore_embedded_order_join','__file__':helper}
exec(compile(source,helper,'exec'),namespace)
result=namespace['bridge'](json.loads(raw))
assert type(result) is dict, 'order helper result is not an object'
assert pathlib.Path(helper).read_bytes()==source and pathlib.Path(request).read_bytes()==raw, 'order helper/request changed'
print(json.dumps(result,sort_keys=True,separators=(',',':')))
"#;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OrderPin {
    pub(super) path: PathBuf,
    pub(super) bytes: u64,
    pub(super) sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Occurrence {
    pub(super) component: String,
    pub(super) unit_id: String,
}

// Optional, explicitly versioned selection within the independently held policy.
// This chooses a consistency protocol, never a capture admission capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum EvidencePolicy {
    #[serde(rename = "frontend-replay-v1")]
    FrontendReplay,
    #[serde(rename = "rust-embedded-bc-v1")]
    RustEmbedded,
}
impl EvidencePolicy {
    fn name(self) -> &'static str {
        match self {
            Self::FrontendReplay => "frontend-replay-v1",
            Self::RustEmbedded => "rust-embedded-bc-v1",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum SelectorProfile {
    #[serde(rename = "replay-source-command-v1")]
    ReplaySourceCommand,
    #[serde(rename = "native-container-member-name-v1")]
    NativeContainerMemberName,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentIdentity {
    bytes: u64,
    sha256: String,
}
impl ContentIdentity {
    fn of(raw: &str) -> Self {
        Self {
            bytes: raw.len() as u64,
            sha256: digest(raw.as_bytes()),
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerSelection {
    schema: String,
    registry: ContentIdentity,
    selected_profiles: BTreeMap<String, BTreeMap<EvidencePolicy, SelectorProfile>>,
}
impl ProducerSelection {
    fn check(&self) -> Result<()> {
        let raw = source_recipe::order_producer_registry();
        if self.schema != "ocore-order-producer-selection-v2"
            || self.registry != ContentIdentity::of(raw)
            || self.selected_profiles.is_empty()
        {
            bail!("general order producer selection or actual embedded registry differs");
        }
        let registry = checked_json(raw.as_bytes())?;
        if registry["schema"] != "ocore-producer-registry-v1" {
            bail!("order producer registry schema differs");
        }
        let mut table = BTreeMap::new();
        for item in array(&registry, "producers")? {
            let id = string(item, "id")?;
            if table.insert(id, item).is_some() {
                bail!("duplicate actual registered producer");
            }
        }
        for (id, policies) in &self.selected_profiles {
            identity(id)?;
            let producer = table
                .get(id.as_str())
                .context("order producer is not actually registered")?;
            if policies.is_empty() || producer["capture"]["available"] != true {
                bail!("order producer capture is not available");
            }
            for (policy, selector) in policies {
                let expected = match policy {
                    EvidencePolicy::FrontendReplay => SelectorProfile::ReplaySourceCommand,
                    EvidencePolicy::RustEmbedded => SelectorProfile::NativeContainerMemberName,
                };
                let registered = &producer["capture"]["policies"][policy.name()];
                if *selector != expected
                    || !registered.is_object()
                    || registered["frontend_replay"]
                        != json!(*policy == EvidencePolicy::FrontendReplay)
                    || registered["format"].as_str().is_none_or(|s| s.is_empty())
                {
                    bail!("order evidence policy or selector profile is not registered");
                }
                if *policy == EvidencePolicy::RustEmbedded
                    && (producer["adapter"] != "rustc"
                        || producer["unit_kind"] != "rustc"
                        || registered["format"] != "llvm-bitcode")
                {
                    bail!("native order policy requires actual registered rustc embedded-bitcode adapter");
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneralHelperBinding {
    schema: String,
    helper: ContentIdentity,
    registry: ContentIdentity,
}
fn general_binding(policy: &Policy) -> Option<GeneralHelperBinding> {
    policy
        .components
        .iter()
        .any(|c| c.producer_selection.is_some())
        .then(|| GeneralHelperBinding {
            schema: "ocore-order-general-helper-binding-v2".into(),
            helper: ContentIdentity::of(GENERAL_JOIN),
            registry: ContentIdentity::of(source_recipe::order_producer_registry()),
        })
}
fn package_schema(policy: &Policy) -> &'static str {
    if policy
        .components
        .iter()
        .any(|c| c.producer_selection.is_some())
    {
        PACKAGE_GENERAL
    } else {
        PACKAGE
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentPolicy {
    component: String,
    original_capture: OrderPin,
    required_unit_ids: Vec<String>,
    original_roots: BTreeMap<String, String>,
    fresh_roots: BTreeMap<String, String>,
    #[serde(default)]
    producer_selection: Option<ProducerSelection>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    components: Vec<ComponentPolicy>,
    module_occurrences: Vec<Occurrence>,
}

// No Deserialize: only an independently selected, checked external file can
// construct this production capability. Package::policy_json is not authority.
pub(super) struct SealedOrder {
    pin: OrderPin,
    raw: Vec<u8>,
    policy: Policy,
}
pub(super) struct PreparedOrder {
    sealed: SealedOrder,
    evidence: Vec<ComponentEvidence>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentEvidence {
    component: String,
    original_capture_json: String,
    commitment_json: String,
    resolution: Option<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PackagedOrder {
    schema: String,
    policy_pin: OrderPin,
    policy_json: String,
    helper_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    general_helper: Option<GeneralHelperBinding>,
    components: Vec<ComponentEvidence>,
    resolved_occurrences: Vec<Occurrence>,
}
pub(super) struct CaptureInput<'a> {
    pub(super) component: &'a str,
    pub(super) raw: &'a [u8],
    pub(super) selected: &'a BTreeSet<String>,
}

fn identity(value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        bail!("invalid original-order identity");
    }
    Ok(())
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("original-order requires lowercase SHA-256");
    }
    Ok(())
}
// Reject duplicate object keys recursively before converting any raw policy,
// embedded JSON, capture, or helper result into Value or a typed structure.
fn checked_json(bytes: &[u8]) -> Result<Value> {
    struct Unique(Value);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("JSON without duplicate object keys")
                }
                fn visit_bool<E: serde::de::Error>(
                    self,
                    v: bool,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                    serde_json::Number::from_f64(v)
                        .map(|n| Unique(Value::Number(n)))
                        .ok_or_else(|| E::custom("nonfinite JSON"))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_string<E: serde::de::Error>(
                    self,
                    v: String,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
                fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut out = Vec::new();
                    while let Some(v) = a.next_element::<Unique>()? {
                        out.push(v.0);
                    }
                    Ok(Unique(Value::Array(out)))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut out = serde_json::Map::new();
                    while let Some((k, v)) = a.next_entry::<String, Unique>()? {
                        if out.insert(k, v.0).is_some() {
                            return Err(serde::de::Error::custom(
                                "duplicate original-order JSON key",
                            ));
                        }
                    }
                    Ok(Unique(Value::Object(out)))
                }
            }
            d.deserialize_any(Visitor)
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Unique::deserialize(&mut decoder)?.0;
    decoder.end()?;
    Ok(value)
}
pub(super) fn check_json(bytes: &[u8]) -> Result<()> {
    checked_json(bytes)?;
    Ok(())
}

fn parse_policy(bytes: &[u8]) -> Result<Policy> {
    let policy: Policy = serde_json::from_value(checked_json(bytes)?)?;
    if policy.schema != POLICY
        || policy.components.is_empty()
        || policy.module_occurrences.is_empty()
    {
        bail!("unsupported or empty original-order policy");
    }
    let mut expected = BTreeMap::new();
    for c in &policy.components {
        identity(&c.component)?;
        hash(&c.original_capture.sha256)?;
        let units: BTreeSet<_> = c.required_unit_ids.iter().cloned().collect();
        if c.original_capture.bytes == 0
            || units.is_empty()
            || units.len() != c.required_unit_ids.len()
            || expected.insert(c.component.clone(), units).is_some()
            || c.original_roots.is_empty()
            || c.original_roots.keys().ne(c.fresh_roots.keys())
        {
            bail!("invalid original-order component/floor/root inventory");
        }
        for id in &c.required_unit_ids {
            identity(id)?;
        }
        if let Some(selection) = &c.producer_selection {
            selection.check()?;
        }
    }
    let mut observed = BTreeMap::<String, BTreeSet<String>>::new();
    for o in &policy.module_occurrences {
        identity(&o.component)?;
        identity(&o.unit_id)?;
        if !expected
            .get(&o.component)
            .is_some_and(|ids| ids.contains(&o.unit_id))
        {
            bail!("original occurrence names an unknown component/unit");
        }
        observed
            .entry(o.component.clone())
            .or_default()
            .insert(o.unit_id.clone());
    }
    if observed != expected {
        bail!("original occurrence sequence omits a required component/unit");
    }
    Ok(policy)
}
fn metadata_id(s: &fs::Metadata) -> (u64, u64, u64, u32, u64, u32, u32, i64, i64, i64, i64) {
    (
        s.dev(),
        s.ino(),
        s.len(),
        s.mode(),
        s.nlink(),
        s.uid(),
        s.gid(),
        s.mtime(),
        s.mtime_nsec(),
        s.ctime(),
        s.ctime_nsec(),
    )
}
fn read_pin(pin: &OrderPin) -> Result<Vec<u8>> {
    hash(&pin.sha256)?;
    if !pin.path.is_absolute() || pin.path.canonicalize()? != pin.path {
        bail!("original-order pin requires canonical absolute file");
    }
    let before = fs::symlink_metadata(&pin.path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        bail!("original-order pin is not a regular file");
    }
    let mut file = fs::File::open(&pin.path)?;
    let opened = file.metadata()?;
    if metadata_id(&before) != metadata_id(&opened) {
        bail!("original-order pin changed during open");
    }
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    if metadata_id(&opened) != metadata_id(&file.metadata()?)
        || metadata_id(&opened) != metadata_id(&fs::symlink_metadata(&pin.path)?)
        || raw.len() as u64 != pin.bytes
        || digest(&raw) != pin.sha256
    {
        bail!("original-order held file identity/bytes differ");
    }
    Ok(raw)
}
fn selected(capture: &Value) -> Result<BTreeSet<String>> {
    let ids = array(capture, "lowering_unit_ids")?
        .iter()
        .map(|id| {
            id.as_str()
                .map(str::to_owned)
                .context("invalid order capture unit ID")
        })
        .collect::<Result<Vec<_>>>()?;
    let set: BTreeSet<_> = ids.iter().cloned().collect();
    if ids.is_empty() || set.len() != ids.len() {
        bail!("empty/duplicate order capture unit selection");
    }
    Ok(set)
}
fn events(raw: &[u8], required: &BTreeSet<String>) -> Result<Vec<String>> {
    let capture = checked_json(raw)?;
    if capture["schema"] != CAPTURE_FORMAT || selected(&capture)? != *required {
        bail!("original-order complete capture floor differs");
    }
    let mut result = Vec::new();
    for action in array(&capture, "invocations")? {
        if array(action, "units")?
            .iter()
            .any(|u| u["id"].as_str().is_some_and(|id| required.contains(id)))
        {
            // Preserve the complete owning action. A multi-unit/CGU producer is
            // explicitly rejected by the helper until a real selector exists.
            result.push(serde_json::to_string(action)?);
        }
    }
    if result.is_empty() {
        bail!("original-order owning action inventory absent");
    }
    Ok(result)
}
fn original_occurrences(policy: &Policy, component: &str) -> Vec<String> {
    policy
        .module_occurrences
        .iter()
        .filter(|o| o.component == component)
        .map(|o| o.unit_id.clone())
        .collect()
}
fn request(
    policy_raw: &[u8],
    policy: &Policy,
    c: &ComponentPolicy,
    original: &[u8],
) -> Result<Value> {
    let required = c.required_unit_ids.iter().cloned().collect();
    let mut request = json!({"schema":"Main-source-order-helper-request/v1","operation":"commit",
        "original_events":events(original,&required)?,"required_unit_ids":c.required_unit_ids,
        "original_roots":c.original_roots,"original_occurrences":original_occurrences(policy,&c.component),
        "original_order_raw":std::str::from_utf8(policy_raw)?});
    if let Some(selection) = &c.producer_selection {
        selection.check()?;
        request["schema"] = json!("Main-source-order-helper-request/v2");
        request["registry_raw"] = json!(source_recipe::order_producer_registry());
        request["selected_profiles"] = serde_json::to_value(&selection.selected_profiles)?;
    }
    Ok(request)
}
fn write_new(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(raw)?;
    file.sync_all()?;
    drop(file);
    if fs::read(path)? != raw {
        bail!("order helper evidence changed during publication");
    }
    Ok(())
}
fn bridge(python: &provider_group::Pin, request: &Value, output: &Path) -> Result<Value> {
    python.checked()?;
    fs::create_dir(output)?;
    let (source, name) = match request["schema"].as_str() {
        Some("Main-source-order-helper-request/v1") => (JOIN, "source_order_join.py"),
        Some("Main-source-order-helper-request/v2") => {
            (GENERAL_JOIN, "general_source_order_join.py")
        }
        _ => bail!("unsupported order helper request protocol"),
    };
    let helper = output.join(name);
    let input = output.join("request.json");
    let raw = serde_json::to_vec(request)?;
    write_new(&helper, source.as_bytes())?;
    write_new(&input, &raw)?;
    let argv = vec![
        "-I".into(),
        "-B".into(),
        "-c".into(),
        DRIVER.into(),
        helper.display().to_string(),
        digest(source.as_bytes()),
        input.display().to_string(),
        digest(&raw),
        python.sha256.clone(),
    ];
    write_new(
        &output.join("command.json"),
        &serde_json::to_vec(&json!({"program":python.path,"sha256":python.sha256,"argv":argv}))?,
    )?;
    let result = Command::new(&python.path)
        .args(&argv)
        .output()
        .context("run embedded checked-buffer order consistency helper")?;
    write_new(&output.join("stdout.log"), &result.stdout)?;
    write_new(&output.join("stderr.log"), &result.stderr)?;
    write_new(
        &output.join("process.json"),
        &serde_json::to_vec(
            &json!({"exit_code":result.status.code(),"success":result.status.success(),"scope":"consistency helper only; no original-order/build/provider/runtime authority"}),
        )?,
    )?;
    python.checked()?;
    if fs::read(&helper)? != source.as_bytes() || fs::read(&input)? != raw {
        bail!("order helper/request changed");
    }
    if !result.status.success() {
        bail!("order consistency helper failed; see {}", output.display());
    }
    let value = checked_json(&result.stdout)?;
    if !value.is_object() {
        bail!("order helper returned non-object");
    }
    Ok(value)
}
impl SealedOrder {
    pub(super) fn read(pin: &OrderPin, components: &[String]) -> Result<Self> {
        let raw = read_pin(pin)?;
        let policy = parse_policy(&raw)?;
        if policy
            .components
            .iter()
            .map(|c| &c.component)
            .collect::<Vec<_>>()
            != components.iter().collect::<Vec<_>>()
        {
            bail!("original-order component sequence differs from selected plan");
        }
        Ok(Self {
            pin: pin.clone(),
            raw,
            policy,
        })
    }
    pub(super) fn check_unchanged(&self) -> Result<()> {
        if read_pin(&self.pin)? != self.raw {
            bail!("externally selected original order changed");
        }
        Ok(())
    }
    pub(super) fn prepare(
        self,
        python: &provider_group::Pin,
        output: &Path,
    ) -> Result<PreparedOrder> {
        self.check_unchanged()?;
        fs::create_dir(output)?;
        let mut evidence = Vec::new();
        for (index, c) in self.policy.components.iter().enumerate() {
            let raw = read_pin(&c.original_capture)?;
            let capture = checked_json(&raw)?;
            let ids = c.required_unit_ids.iter().cloned().collect();
            if selected(&capture)? != ids {
                bail!("original-order required unit floor differs from original capture");
            }
            let directory = output.join(format!("original-{index:06}"));
            fs::create_dir(&directory)?;
            // This is an actual original capture re-admission, not a receipt bit.
            let admitted = source_action::AdmittedCapture::reverify(
                &c.original_capture.path,
                &raw,
                &ids,
                &directory,
                &python.path,
            )?;
            let committed = bridge(
                python,
                &request(&self.raw, &self.policy, c, &raw)?,
                &directory.join("commit"),
            )?;
            let commitment = string(&committed, "commitment")?.to_owned();
            checked_json(commitment.as_bytes())?;
            admitted.postguard(&directory, &python.path)?;
            if read_pin(&c.original_capture)? != raw {
                bail!("original capture changed after order commitment");
            }
            evidence.push(ComponentEvidence {
                component: c.component.clone(),
                original_capture_json: String::from_utf8(raw)?,
                commitment_json: commitment,
                resolution: None,
            });
        }
        self.check_unchanged()?;
        Ok(PreparedOrder {
            sealed: self,
            evidence,
        })
    }
}
impl PreparedOrder {
    pub(super) fn check_unchanged(&self) -> Result<()> {
        self.sealed.check_unchanged()
    }
    pub(super) fn resolve(
        self,
        inputs: &[CaptureInput<'_>],
        python: &provider_group::Pin,
        output: &Path,
    ) -> Result<PackagedOrder> {
        self.check_unchanged()?;
        fs::create_dir(output)?;
        let mut evidence = self.evidence;
        if inputs.len() != evidence.len() {
            bail!("fresh order component count differs");
        }
        for (index, ((c, e), fresh)) in self
            .sealed
            .policy
            .components
            .iter()
            .zip(&mut evidence)
            .zip(inputs)
            .enumerate()
        {
            if fresh.component != c.component {
                bail!("fresh order component sequence differs");
            }
            let capture = checked_json(fresh.raw)?;
            if selected(&capture)? != *fresh.selected {
                bail!("fresh order selected capture differs from actual stage");
            }
            let mut req = request(
                &self.sealed.raw,
                &self.sealed.policy,
                c,
                e.original_capture_json.as_bytes(),
            )?;
            req["operation"] = json!("resolve");
            req["commitment"] = json!(e.commitment_json);
            req["fresh_events"] = json!(events(fresh.raw, fresh.selected)?);
            req["fresh_roots"] = json!(c.fresh_roots);
            e.resolution = Some(bridge(
                python,
                &req,
                &output.join(format!("resolve-{index:06}")),
            )?);
        }
        let mut package = PackagedOrder {
            schema: package_schema(&self.sealed.policy).into(),
            policy_pin: self.sealed.pin.clone(),
            policy_json: String::from_utf8(self.sealed.raw.clone())?,
            helper_sha256: digest(JOIN.as_bytes()),
            general_helper: general_binding(&self.sealed.policy),
            components: evidence,
            resolved_occurrences: Vec::new(),
        };
        package.resolved_occurrences = package.expected_occurrences(inputs)?;
        package.check_internal(inputs)?;
        self.sealed.check_unchanged()?;
        Ok(package)
    }
}
impl PackagedOrder {
    fn expected_occurrences(&self, inputs: &[CaptureInput<'_>]) -> Result<Vec<Occurrence>> {
        let policy = parse_policy(self.policy_json.as_bytes())?;
        if self.components.len() != policy.components.len()
            || inputs.len() != policy.components.len()
        {
            bail!("packaged order component inventory differs");
        }
        let mut maps = BTreeMap::<String, BTreeMap<String, String>>::new();
        for ((c, e), fresh) in policy.components.iter().zip(&self.components).zip(inputs) {
            if c.component != e.component || c.component != fresh.component {
                bail!("packaged order component order differs");
            }
            if e.original_capture_json.len() as u64 != c.original_capture.bytes
                || digest(e.original_capture_json.as_bytes()) != c.original_capture.sha256
            {
                bail!("packaged original capture pin differs");
            }
            let required: BTreeSet<_> = c.required_unit_ids.iter().cloned().collect();
            events(e.original_capture_json.as_bytes(), &required)?;
            events(fresh.raw, fresh.selected)?;
            let resolution = e
                .resolution
                .as_ref()
                .context("packaged fresh action resolution absent")?;
            let mapping: BTreeMap<String, String> =
                serde_json::from_value(resolution["unit_mapping"].clone())?;
            let values: BTreeSet<_> = mapping.values().cloned().collect();
            let old = original_occurrences(&policy, &c.component);
            let new = old
                .iter()
                .map(|id| {
                    mapping
                        .get(id)
                        .cloned()
                        .context("occurrence mapping absent")
                })
                .collect::<Result<Vec<_>>>()?;
            let order_pin = json!({"bytes":self.policy_json.len(),"sha256":digest(self.policy_json.as_bytes())});
            let protocol_matches = if let Some(selection) = &c.producer_selection {
                let committed = checked_json(e.commitment_json.as_bytes())?;
                resolution["schema"] == "ocore-original-ordered-multi-output-join-v2"
                    && resolution["commitment_sha256"] == digest(e.commitment_json.as_bytes())
                    && committed["schema"] == "ocore-original-ordered-multi-output-commitment-v2"
                    && committed["registry"] == serde_json::to_value(&selection.registry)?
                    && committed["selected_profiles"]
                        == serde_json::to_value(&selection.selected_profiles)?
                    && committed["required_unit_ids"] == json!(c.required_unit_ids)
                    && committed["original_occurrences"] == json!(old)
                    && committed["original_order"] == order_pin
                    && resolution["consistency_join_complete"] == true
                    && resolution["capture_admitted"] == false
                    && resolution["Cargo_parent_semantic_join_supported"] == false
                    && resolution["original_order_producer_qualified"] == false
                    && resolution["provider_closure_qualified"] == false
                    && resolution["runtime_qualified"] == false
            } else {
                resolution["schema"] == "ocore-original-ordered-action-fresh-unit-join-v1"
                    && resolution["order_commitment_sha256"] == digest(e.commitment_json.as_bytes())
                    && resolution["original_order"] == order_pin
            };
            if !protocol_matches
                || resolution["original_occurrences"] != json!(old)
                || resolution["fresh_occurrences"] != json!(new)
                || mapping.keys().cloned().collect::<BTreeSet<_>>() != required
                || values.len() != mapping.len()
                || &values != fresh.selected
            {
                bail!("packaged action/order/floor mapping differs");
            }
            maps.insert(c.component.clone(), mapping);
        }
        policy
            .module_occurrences
            .iter()
            .map(|o| {
                Ok(Occurrence {
                    component: o.component.clone(),
                    unit_id: maps
                        .get(&o.component)
                        .and_then(|m| m.get(&o.unit_id))
                        .cloned()
                        .context("global occurrence resolution absent")?,
                })
            })
            .collect()
    }
    pub(super) fn check_internal(&self, inputs: &[CaptureInput<'_>]) -> Result<()> {
        let policy = parse_policy(self.policy_json.as_bytes())?;
        if self.schema != package_schema(&policy)
            || self.general_helper != general_binding(&policy)
            || self.policy_json.len() as u64 != self.policy_pin.bytes
            || digest(self.policy_json.as_bytes()) != self.policy_pin.sha256
            || self.helper_sha256 != digest(JOIN.as_bytes())
            || self.resolved_occurrences != self.expected_occurrences(inputs)?
        {
            bail!("source group original-order consistency differs");
        }
        Ok(())
    }
    /// Return the complete fresh occurrence vector recomputed from the sealed
    /// global policy and its exact original-to-fresh action mapping. Do not
    /// project to a set: the Artifact resolver must reject unsupported repeated
    /// occurrences explicitly rather than silently changing a native plan.
    pub(super) fn fresh_module_order(
        &self,
        inputs: &[CaptureInput<'_>],
    ) -> Result<Vec<(String, String)>> {
        self.check_internal(inputs)?;
        Ok(self
            .expected_occurrences(inputs)?
            .into_iter()
            .map(|occurrence| (occurrence.component, occurrence.unit_id))
            .collect())
    }
    pub(super) fn check_external(&self, selected: &SealedOrder) -> Result<()> {
        selected.check_unchanged()?;
        if self.policy_pin != selected.pin || self.policy_json.as_bytes() != selected.raw {
            bail!("source group differs from independently held original-order pin");
        }
        Ok(())
    }
    pub(super) fn require_external(&self, selected: Option<&SealedOrder>) -> Result<()> {
        self.check_external(
            selected.context("V3 source group requires an external original-order selection")?,
        )
    }
    /// Detached consistency never opens old source/capture paths from the package.
    /// It consumes embedded raw captures only after the same external policy pin
    /// has been selected. This is not a fresh original build/capture admission.
    pub(super) fn recheck(
        &self,
        selected: &SealedOrder,
        inputs: &[CaptureInput<'_>],
        python: &provider_group::Pin,
        output: &Path,
    ) -> Result<()> {
        self.check_external(selected)?;
        self.check_internal(inputs)?;
        fs::create_dir(output)?;
        for (index, ((c, e), fresh)) in selected
            .policy
            .components
            .iter()
            .zip(&self.components)
            .zip(inputs)
            .enumerate()
        {
            let req = request(
                &selected.raw,
                &selected.policy,
                c,
                e.original_capture_json.as_bytes(),
            )?;
            let committed = bridge(python, &req, &output.join(format!("commit-{index:06}")))?;
            if string(&committed, "commitment")? != e.commitment_json {
                bail!("detached original action/order commitment differs");
            }
            let mut req = req;
            req["operation"] = json!("resolve");
            req["commitment"] = json!(e.commitment_json);
            req["fresh_events"] = json!(events(fresh.raw, fresh.selected)?);
            req["fresh_roots"] = json!(c.fresh_roots);
            if Some(bridge(
                python,
                &req,
                &output.join(format!("resolve-{index:06}")),
            )?) != e.resolution
            {
                bail!("detached exact fresh action resolution differs");
            }
        }
        self.check_external(selected)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "provider_order_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "provider_order_general_tests.rs"]
mod general_tests;
