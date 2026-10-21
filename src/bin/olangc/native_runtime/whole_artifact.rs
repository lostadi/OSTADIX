//! Self-contained source-library group. This is a verified-IR delivery contract,
//! not a whole-program resource/realization artifact. Its public reader proves
//! internal consistency; original checkout/build origin requires fresh staging.
use super::*;
use serde::{Deserialize, Serialize};
pub(super) const FORMAT: &str = "ocore-native-source-group-v1";
pub(super) const FILE_NAME: &str = "source-group.native-ir.json";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceUnit {
    id: String,
    original_ir_hex: String,
    input: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceComponent {
    name: String,
    recipe_json: String,
    recipe_sha256: String,
    capture_json: String,
    capture_sha256: String,
    inventory_json: String,
    dependencies: BTreeMap<String, String>,
    units: Vec<SourceUnit>,
}
impl SourceComponent {
    pub(super) fn from_stage(
        name: &str,
        recipe: &[u8],
        dependencies: &BTreeMap<String, String>,
        stage: &StagedComponent,
    ) -> Result<Self> {
        if !stage.source_capture_complete || !stage.unit_lowering_complete {
            bail!("cannot publish an incomplete staged source component");
        }
        if stage.modules.len() != stage.selected.len() {
            bail!("staged source module inventory is incomplete");
        }
        Ok(Self {
            name: name.into(),
            recipe_json: String::from_utf8(recipe.to_vec())?,
            recipe_sha256: digest(recipe),
            capture_json: String::from_utf8(stage.capture_bytes.clone())?,
            capture_sha256: digest(&stage.capture_bytes),
            inventory_json: String::from_utf8(checked_evidence(
                &stage.capture["unit_inventory"]["file"],
            )?)?,
            dependencies: dependencies.clone(),
            units: stage
                .original_inputs
                .iter()
                .map(|(id, (input, bytes))| SourceUnit {
                    id: id.clone(),
                    input: input.clone(),
                    original_ir_hex: hex::encode(bytes),
                })
                .collect(),
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceGroup {
    format: String,
    root: String,
    plan_sha256: String,
    module_set: artifact::Artifact,
    components: Vec<SourceComponent>,
}
impl SourceGroup {
    pub(super) fn new(
        root: &str,
        plan_sha256: String,
        module_set: artifact::Artifact,
        components: Vec<SourceComponent>,
    ) -> Result<Self> {
        let value = Self {
            format: FORMAT.into(),
            root: root.into(),
            plan_sha256,
            module_set,
            components,
        };
        value.check()?;
        Ok(value)
    }
    fn check(&self) -> Result<()> {
        if self.format != FORMAT
            || self.root != self.module_set.name
            || self.plan_sha256.len() != 64
        {
            bail!("invalid source group identity");
        }
        artifact::Artifact::from_bytes(&serde_json::to_vec(&self.module_set)?)?;
        let mut names = BTreeSet::new();
        let mut expected = BTreeSet::new();
        for component in &self.components {
            if !names.insert(&component.name)
                || digest(component.recipe_json.as_bytes()) != component.recipe_sha256
                || digest(component.capture_json.as_bytes()) != component.capture_sha256
            {
                bail!("duplicate or unbound source component");
            }
            let recipe: Value = serde_json::from_str(&component.recipe_json)?;
            let capture: Value = serde_json::from_str(&component.capture_json)?;
            if recipe["schema"] != source_recipe::RECIPE_FORMAT
                || capture["schema"] != CAPTURE_FORMAT
                || capture["name"] != recipe["name"]
            {
                bail!("source group recipe/capture identity differs");
            }
            let finalized: Value = serde_json::from_str(&component.inventory_json)?;
            if finalized != capture["unit_inventory"]["definition"]
                || finalized["schema"] != "ocore-runtime-unit-inventory-v1"
                || finalized["complete"] != true
                || capture["unit_inventory"]["file"]["sha256"]
                    != digest(component.inventory_json.as_bytes())
                || capture["unit_inventory"]["file"]["bytes"].as_u64()
                    != Some(component.inventory_json.len() as u64)
            {
                bail!("embedded finalized source inventory differs");
            }
            check_original_selection(&recipe, &finalized, &capture)?;
            let mut expected_dependencies = Vec::new();
            let mut labels = BTreeSet::new();
            for dependency in array(&recipe, "dependencies")? {
                let label = string(dependency, "name")?;
                if !labels.insert(label) {
                    bail!("duplicate original recipe dependency");
                }
                let name = component
                    .dependencies
                    .get(label)
                    .context("original recipe dependency has no source component")?;
                let provider = self
                    .components
                    .iter()
                    .find(|c| &c.name == name)
                    .context("source dependency component absent")?;
                let provider_recipe: Value = serde_json::from_str(&provider.recipe_json)?;
                if dependency
                    .get("source_pin")
                    .is_some_and(|p| !p.is_null() && p != &provider_recipe["source"])
                {
                    bail!("source dependency original pin differs");
                }
                expected_dependencies
                    .push((provider.name.clone(), provider.capture_sha256.clone()));
            }
            if component
                .dependencies
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != labels
            {
                bail!("extra source dependency mapping");
            }
            self.module_set
                .check_component_dependencies(&component.name, &expected_dependencies)?;
            let selected: BTreeSet<_> = array(&capture, "lowering_unit_ids")?
                .iter()
                .map(|v| v.as_str().context("invalid source unit ID"))
                .collect::<Result<_>>()?;
            let mut actual = BTreeSet::new();
            for unit in &component.units {
                if !actual.insert(unit.id.as_str()) || !selected.contains(unit.id.as_str()) {
                    bail!("duplicate or unexpected original source unit");
                }
                let original = hex::decode(&unit.original_ir_hex)?;
                if unit.input["sha256"] != digest(&original)
                    || unit.input["bytes"].as_u64() != Some(original.len() as u64)
                {
                    bail!("embedded original source unit bytes differ");
                }
                let captured = array(&capture, "units")?
                    .iter()
                    .find(|u| u["id"].as_str() == Some(unit.id.as_str()))
                    .context("original unit absent from capture")?;
                if captured["ir"] != unit.input {
                    bail!("original source unit does not match embedded capture");
                }
                let native = self
                    .module_set
                    .modules
                    .iter()
                    .find(|m| m.component == component.name && m.unit_id == unit.id)
                    .context("missing owned source module")?;
                let module = native.verify()?;
                if module.provenance.input_sha256 != digest(&original)
                    || module.target.triple != string(&unit.input, "target_triple")?
                    || module.target.data_layout != string(&unit.input, "data_layout")?
                {
                    bail!("native source module provenance/target differs");
                }
                expected.insert((component.name.as_str(), unit.id.as_str()));
            }
            if actual != selected {
                bail!("source group omitted selected original units");
            }
            self.module_set
                .check_component(&component.name, &component.capture_sha256, &actual)?;
            // The module-set graph is independently recomputed below; the
            // source policy maps logical dependency labels at construction.
        }
        let actual: BTreeSet<_> = self
            .module_set
            .modules
            .iter()
            .map(|m| (m.component.as_str(), m.unit_id.as_str()))
            .collect();
        if actual != expected {
            bail!("source group module/component membership differs");
        }
        Ok(())
    }
    pub(super) fn check_policy(
        &self,
        root: &str,
        sha: &str,
        recipes: &BTreeMap<String, (String, BTreeMap<String, String>)>,
    ) -> Result<()> {
        let actual: BTreeMap<_, _> = self
            .components
            .iter()
            .map(|c| {
                (
                    c.name.clone(),
                    (c.recipe_sha256.clone(), c.dependencies.clone()),
                )
            })
            .collect();
        if self.root != root || self.plan_sha256 != sha || &actual != recipes {
            bail!("source group differs from independently selected original recipe policy");
        }
        Ok(())
    }
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let group: Self =
            serde_json::from_slice(bytes).context("decode source-backed native IR group")?;
        group.check()?;
        Ok(group)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compile_package(
    bytes: &[u8],
    target: &str,
    kind: &str,
    output: &Path,
    compiler: &Path,
    python: &provider_group::Pin,
    library: &provider_group::Pin,
    options: NativeImportOptions<'_>,
) -> Result<()> {
    let group = SourceGroup::from_bytes(bytes)?;
    architecture(target)?;
    if !matches!(kind, "ir" | "obj") || !options.dependencies.is_empty() {
        bail!("invalid source group output/options");
    }
    python.checked()?;
    library.checked()?;
    fs::create_dir(output)?;
    let output = output.canonicalize()?;
    let mut records = Vec::new();
    let mut issues = Vec::new();
    for (component_index, component) in group.components.iter().enumerate() {
        for (unit_index, unit) in component.units.iter().enumerate() {
            let result = (|| -> Result<Value> {
                let directory = output.join(format!("source-{component_index:06}-{unit_index:06}"));
                fs::create_dir(&directory)?;
                let original = hex::decode(&unit.original_ir_hex)?;
                let original_path = directory.join("original.ll");
                fs::write(&original_path, &original)?;
                let native = group
                    .module_set
                    .modules
                    .iter()
                    .find(|m| m.component == component.name && m.unit_id == unit.id)
                    .context("source module vanished")?;
                let inventory = provider_group::inventory(
                    python,
                    library,
                    &original,
                    native.native_ir.as_bytes(),
                    &directory.join("inventory"),
                )?;
                // Source inventory alone cannot establish body preservation. A
                // fresh complete typed import must match every canonical field.
                let fresh = directory.join("fresh.native-ir.json");
                let mut args = vec![
                    original_path.display().to_string(),
                    "--input-kind".into(),
                    "llvm-ir".into(),
                    "--emit".into(),
                    "mir".into(),
                    "--target".into(),
                    format!("{}-unknown-none", architecture(target)?),
                    "--llvm-library".into(),
                    library.path.display().to_string(),
                    "--llvm-sha256".into(),
                    library.sha256.clone(),
                    "-o".into(),
                    fresh.display().to_string(),
                ];
                let module = native.verify()?;
                if module.target.tls_profile.is_some() {
                    args.extend([
                        "--tls-profile".into(),
                        "linux-elf-static-nonpreemptive-v1".into(),
                    ]);
                }
                if module.target.atomic_profile.is_some() {
                    args.extend(["--atomic-profile".into(), "coherent-ram-v1".into()]);
                }
                if module.target.wide_volatile_profile.is_some() {
                    args.extend([
                        "--wide-volatile-profile".into(),
                        "ordinary-ram-split-v1".into(),
                    ]);
                }
                fs::write(
                    directory.join("import-command.json"),
                    serde_json::to_vec_pretty(
                        &json!({"program":compiler,"sha256":digest(&fs::read(compiler)?),"argv":args}),
                    )?,
                )?;
                invoke(compiler, &args, &directory.join("import.log"))?;
                let fresh = NativeModule::from_json(&fs::read(fresh)?)
                    .map_err(|e| anyhow::anyhow!(e.message))?;
                if serde_json::to_value(&fresh)? != serde_json::to_value(&module)? {
                    bail!("fresh original LLVM import does not match embedded typed NativeModule");
                }
                Ok(
                    json!({"component":component.name,"id":unit.id,"source_inventory":inventory,"fresh_typed_import_match":true}),
                )
            })();
            match result {
                Ok(record) => records.push(record),
                Err(error) => {
                    issues.push(format!("{}:{}: {error:#}", component.name, unit.id));
                }
            }
        }
    }
    let complete = issues.is_empty();
    let receipt = json!({"schema":"ocore-source-group-readmission-v1","source_group_sha256":digest(bytes),"units":records,"issues":issues,
        "included_original_ir_body_consistency":complete,"original_checkout_build_reverified":false,
        "artifact_complete":false,"platform_resource_closure_complete":false,"native_execution_qualified":false,"runtime_complete":false});
    fs::write(
        output.join("source-readmission.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    if !complete {
        bail!("source group readmission failed; see {}", output.display());
    }
    artifact::compile_package(
        &serde_json::to_vec_pretty(&group.module_set)?,
        target,
        kind,
        &output.join("lowered"),
        compiler,
    )?;
    fs::write(output.join(FILE_NAME), bytes)?;
    Ok(())
}

// Reconstruct recipe-floor plus complete build-finalized requirements. The floor
// is a subset, never equality with the generated inventory. This does not claim
// the embedded capture is a fresh checkout/build replay.
fn check_original_selection(recipe: &Value, finalized: &Value, capture: &Value) -> Result<()> {
    let mut required = BTreeMap::<String, Value>::new();
    for rule in array(&recipe["coverage"], "required_units")?
        .iter()
        .chain(array(finalized, "units")?)
    {
        let id = string(rule, "id")?.to_owned();
        if let Some(previous) = required.get_mut(&id) {
            let previous = previous
                .as_object_mut()
                .context("source rule must be an object")?;
            for (key, value) in rule.as_object().context("source rule must be an object")? {
                if previous.get(key).is_some_and(|old| old != value) {
                    bail!("ambiguous original source requirement");
                }
                previous.insert(key.clone(), value.clone());
            }
        } else {
            required.insert(id, rule.clone());
        }
    }
    if required.is_empty() {
        bail!("empty original source requirement inventory");
    }
    let known: BTreeSet<_> = array(capture, "units")?
        .iter()
        .map(|u| string(u, "id"))
        .collect::<Result<_>>()?;
    if known.len() != array(capture, "units")?.len() {
        bail!("duplicate captured original unit");
    }
    let mut actual_rules = BTreeSet::new();
    let mut lowering = BTreeSet::new();
    let mut assigned = BTreeSet::new();
    for bound in array(capture, "required_units")? {
        let id = string(bound, "id")?;
        let rule = required
            .get(id)
            .context("capture added an unfinalized original requirement")?;
        if !actual_rules.insert(id)
            || bound["complete"] != true
            || !array(bound, "failed_invocation_ids")?.is_empty()
        {
            bail!("original source requirement is incomplete");
        }
        for (key, value) in rule.as_object().context("source rule must be an object")? {
            if bound.get(key) != Some(value) {
                bail!("original source rule changed: {id}/{key}");
            }
        }
        let ids = array(bound, "captured_unit_ids")?;
        if ids.is_empty() {
            bail!("original source rule has no captured unit");
        }
        for unit in ids {
            let unit = unit.as_str().context("invalid captured unit assignment")?;
            if !known.contains(unit) {
                bail!("unknown original unit assignment");
            }
            assigned.insert(unit);
            if rule
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("runtime")
                == "runtime"
            {
                lowering.insert(unit);
            }
        }
    }
    if actual_rules != required.keys().map(String::as_str).collect() || assigned != known {
        bail!("partial original recipe/finalized unit inventory");
    }
    let selected: BTreeSet<_> = array(capture, "lowering_unit_ids")?
        .iter()
        .map(|v| v.as_str().context("invalid lowering ID"))
        .collect::<Result<_>>()?;
    if selected != lowering || selected.len() != array(capture, "lowering_unit_ids")?.len() {
        bail!("original runtime/probe partition changed");
    }
    Ok(())
}

#[cfg(test)]
#[path = "whole_artifact_tests.rs"]
mod tests;
