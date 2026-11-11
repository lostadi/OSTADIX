//! Self-contained source-library group. This is a verified-IR delivery contract,
//! not a whole-program resource/realization artifact. Its public reader proves
//! internal consistency; original checkout/build origin requires fresh staging.
use super::*;
use serde::{Deserialize, Serialize};
pub(super) const FORMAT: &str = "ocore-native-source-group-v1";
pub(super) const FORMAT_V3: &str = "ocore-native-source-group-v3";
pub(super) const FORMAT_V5: &str = "ocore-native-source-group-v5";
pub(super) fn is_format(format: &str) -> bool {
    matches!(format, FORMAT | FORMAT_V3 | FORMAT_V5)
}
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    compound_dependencies: provider_membership::CompoundBindings,
    units: Vec<SourceUnit>,
}
impl SourceComponent {
    pub(super) fn from_stage_compound(
        name: &str,
        recipe: &[u8],
        dependencies: &BTreeMap<String, String>,
        compound_dependencies: &provider_membership::CompoundBindings,
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
            compound_dependencies: compound_dependencies.clone(),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_order: Option<provider_order::PackagedOrder>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_membership: Option<provider_membership::PackagedMembership>,
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
            original_order: None,
            original_membership: None,
        };
        value.check()?;
        Ok(value)
    }
    pub(super) fn new_v3(
        root: &str,
        plan_sha256: String,
        module_set: artifact::Artifact,
        components: Vec<SourceComponent>,
        order: provider_order::PackagedOrder,
    ) -> Result<Self> {
        let value = Self {
            format: FORMAT_V3.into(),
            root: root.into(),
            plan_sha256,
            module_set,
            components,
            original_order: Some(order),
            original_membership: None,
        };
        value.check()?;
        Ok(value)
    }
    pub(super) fn new_v5(
        root: &str,
        plan_sha256: String,
        module_set: artifact::Artifact,
        components: Vec<SourceComponent>,
        order: Option<provider_order::PackagedOrder>,
        membership: provider_membership::PackagedMembership,
    ) -> Result<Self> {
        let value = Self {
            format: FORMAT_V5.into(),
            root: root.into(),
            plan_sha256,
            module_set,
            components,
            original_order: order,
            original_membership: Some(membership),
        };
        value.check()?;
        Ok(value)
    }
    fn with_membership_inputs<T>(
        &self,
        apply: impl FnOnce(&[provider_membership::Input<'_>]) -> Result<T>,
    ) -> Result<T> {
        let inputs = self
            .components
            .iter()
            .map(|c| provider_membership::Input {
                name: &c.name,
                recipe: c.recipe_json.as_bytes(),
                dependencies: &c.dependencies,
                compound: &c.compound_dependencies,
            })
            .collect::<Vec<_>>();
        apply(&inputs)
    }
    pub(super) fn select_membership(
        &self,
        pin: &provider_order::OrderPin,
    ) -> Result<provider_membership::SelectedMembership> {
        if self.format != FORMAT_V5 {
            bail!("membership selection requires V5 source group");
        }
        self.with_membership_inputs(|inputs| {
            provider_membership::SelectedMembership::read(pin, inputs)
        })
    }
    fn require_membership(
        &self,
        selected: Option<&provider_membership::SelectedMembership>,
    ) -> Result<()> {
        match (&self.original_membership, selected) {
            (None, None) if self.format != FORMAT_V5 => Ok(()),
            (Some(embedded), selected) if self.format == FORMAT_V5 => {
                self.with_membership_inputs(|inputs| embedded.require_external(selected, inputs))
            }
            _ => bail!("source group requires the same independently selected original membership"),
        }
    }
    fn with_order_inputs<T>(
        &self,
        apply: impl FnOnce(&[provider_order::CaptureInput<'_>]) -> Result<T>,
    ) -> Result<T> {
        let selections = self
            .components
            .iter()
            .map(|c| {
                c.units
                    .iter()
                    .map(|u| u.id.clone())
                    .collect::<BTreeSet<_>>()
            })
            .collect::<Vec<_>>();
        let inputs = self
            .components
            .iter()
            .zip(&selections)
            .map(|(c, selected)| provider_order::CaptureInput {
                component: &c.name,
                raw: c.capture_json.as_bytes(),
                selected,
            })
            .collect::<Vec<_>>();
        apply(&inputs)
    }
    fn check_embedded_order(&self, order: &provider_order::PackagedOrder) -> Result<()> {
        self.with_order_inputs(|inputs| {
            self.module_set
                .check_module_order(&order.fresh_module_order(inputs)?)
        })
    }
    pub(super) fn required_platform_interfaces(&self) -> Result<Vec<Value>> {
        self.module_set.required_platform_interfaces()
    }
    fn check(&self) -> Result<()> {
        if !is_format(&self.format)
            || self.root != self.module_set.name
            || self.plan_sha256.len() != 64
        {
            bail!("invalid source group identity");
        }
        match (self.format.as_str(), &self.original_order) {
            (FORMAT | FORMAT_V5, None) => {}
            (FORMAT_V3 | FORMAT_V5, Some(order)) => self.check_embedded_order(order)?,
            _ => bail!("source group original-order/schema version differs"),
        }
        match (&self.original_membership, self.format.as_str()) {
            (Some(membership), FORMAT_V5) => {
                self.with_membership_inputs(|inputs| membership.check(inputs))?
            }
            (None, FORMAT | FORMAT_V3)
                if self
                    .components
                    .iter()
                    .all(|c| c.compound_dependencies.is_empty()) => {}
            _ => bail!("source group compound membership/schema version differs"),
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
                match (
                    component.dependencies.get(label),
                    component.compound_dependencies.get(label),
                ) {
                    (Some(name), None) => {
                        let provider = self
                            .components
                            .iter()
                            .find(|c| &c.name == name)
                            .context("source dependency component absent")?;
                        let recipe: Value = serde_json::from_str(&provider.recipe_json)?;
                        if dependency
                            .get("source_pin")
                            .is_some_and(|p| !p.is_null() && p != &recipe["source"])
                        {
                            bail!("source dependency original pin differs");
                        }
                        expected_dependencies
                            .push((provider.name.clone(), provider.capture_sha256.clone()));
                    }
                    (None, Some(members)) if self.format == FORMAT_V5 => {
                        for name in members.values() {
                            let provider = self
                                .components
                                .iter()
                                .find(|c| &c.name == name)
                                .context("compound source dependency component absent")?;
                            expected_dependencies
                                .push((provider.name.clone(), provider.capture_sha256.clone()));
                        }
                    }
                    _ => bail!("original recipe dependency has no unique source binding"),
                }
            }
            if component
                .dependencies
                .keys()
                .chain(component.compound_dependencies.keys())
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
        if self.root != root
            || self.plan_sha256 != sha
            || &actual != recipes
            || self.format == FORMAT_V5
            || self
                .components
                .iter()
                .any(|c| !c.compound_dependencies.is_empty())
        {
            bail!("source group differs from independently selected original recipe policy");
        }
        Ok(())
    }
    pub(super) fn check_selected_policy(
        &self,
        root: &str,
        sha: &str,
        recipes: &BTreeMap<String, (String, BTreeMap<String, String>)>,
        order: Option<&provider_order::SealedOrder>,
    ) -> Result<()> {
        self.check_policy(root, sha, recipes)?;
        match (&self.original_order, order) {
            (None, None) if self.format == FORMAT => Ok(()),
            (Some(embedded), selected) if self.format == FORMAT_V3 => {
                embedded.require_external(selected)?;
                self.check_embedded_order(embedded)
            }
            _ => bail!(
                "V3 source readmission requires the same independently held original-order pin"
            ),
        }
    }
    pub(super) fn check_selected_policy_v5(
        &self,
        root: &str,
        sha: &str,
        recipes: &BTreeMap<
            String,
            (
                String,
                BTreeMap<String, String>,
                provider_membership::CompoundBindings,
            ),
        >,
        order: Option<&provider_order::SealedOrder>,
        membership: Option<&provider_membership::SelectedMembership>,
    ) -> Result<()> {
        let actual = self
            .components
            .iter()
            .map(|c| {
                (
                    c.name.clone(),
                    (
                        c.recipe_sha256.clone(),
                        c.dependencies.clone(),
                        c.compound_dependencies.clone(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if self.format != FORMAT_V5
            || self.root != root
            || self.plan_sha256 != sha
            || &actual != recipes
        {
            bail!("V5 source group differs from independently selected original recipe policy");
        }
        self.require_membership(membership)?;
        match (&self.original_order, order) {
            (None, None) => Ok(()),
            (Some(embedded), selected) => {
                embedded.require_external(selected)?;
                self.check_embedded_order(embedded)
            }
            _ => bail!("V5 source readmission original-order selection differs"),
        }
    }
    fn recheck_selected_order(
        &self,
        selected: Option<&provider_order::SealedOrder>,
        python: &provider_group::Pin,
        output: &Path,
    ) -> Result<()> {
        match (&self.original_order, selected) {
            (None, None) if matches!(self.format.as_str(), FORMAT | FORMAT_V5) => Ok(()),
            (Some(order), Some(selected))
                if matches!(self.format.as_str(), FORMAT_V3 | FORMAT_V5) =>
            {
                self.with_order_inputs(|inputs| order.recheck(selected, inputs, python, output))?;
                self.check_embedded_order(order)
            }
            _ => bail!("missing or mismatched external original-order selection"),
        }
    }
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        provider_order::check_json(bytes)?;
        let value: Value = serde_json::from_slice(bytes)?;
        if matches!(value["format"].as_str(), Some(FORMAT | FORMAT_V3))
            && (value.get("original_membership").is_some()
                || array(&value, "components")?
                    .iter()
                    .any(|c| c.get("compound_dependencies").is_some()))
        {
            bail!("legacy source group cannot carry compound membership fields");
        }
        let group: Self =
            serde_json::from_slice(bytes).context("decode source-backed native IR group")?;
        group.check()?;
        Ok(group)
    }
}

fn compare_relocated_import(
    mut fresh: NativeModule,
    captured: &NativeModule,
    original_path: &Path,
) -> Result<Value> {
    // The compiler derives this nonexecutable diagnostic label from the
    // invoked input pathname. Detached readmission deliberately relocates the
    // exact original LLVM bytes; component/unit IDs and original hashes remain
    // the source, symbol and provider identities checked by the caller.
    o_lang::ocore::native_verify::verify(captured).map_err(|e| anyhow::anyhow!(e.message))?;
    o_lang::ocore::native_verify::verify(&fresh).map_err(|e| anyhow::anyhow!(e.message))?;
    let observed = fresh.name.clone();
    if !original_path.is_absolute() || observed != original_path.display().to_string() {
        bail!("fresh original LLVM diagnostic label differs from trusted staged input pathname");
    }
    fresh.name = captured.name.clone();
    if serde_json::to_value(&fresh)? != serde_json::to_value(captured)? {
        bail!("fresh original LLVM import does not match embedded typed NativeModule");
    }
    Ok(json!({"captured":captured.name,"fresh":observed,
        "rebound_field":"name",
        "scope":"nonexecutable diagnostic input pathname only; every other canonical typed field compared exactly"}))
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn compile_package_selected(
    bytes: &[u8],
    target: &str,
    kind: &str,
    output: &Path,
    compiler: &Path,
    python: &provider_group::Pin,
    library: &provider_group::Pin,
    options: NativeImportOptions<'_>,
    selected_order: Option<&provider_order::SealedOrder>,
) -> Result<()> {
    compile_package_selected_membership(
        bytes,
        target,
        kind,
        output,
        compiler,
        python,
        library,
        options,
        selected_order,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compile_package_selected_membership(
    bytes: &[u8],
    target: &str,
    kind: &str,
    output: &Path,
    compiler: &Path,
    python: &provider_group::Pin,
    library: &provider_group::Pin,
    options: NativeImportOptions<'_>,
    selected_order: Option<&provider_order::SealedOrder>,
    selected_membership: Option<&provider_membership::SelectedMembership>,
) -> Result<()> {
    let group = SourceGroup::from_bytes(bytes)?;
    group.require_membership(selected_membership)?;
    match (&group.original_order, selected_order) {
        (None, None) if matches!(group.format.as_str(), FORMAT | FORMAT_V5) => {}
        (Some(embedded), selected) if matches!(group.format.as_str(), FORMAT_V3 | FORMAT_V5) => {
            embedded.require_external(selected)?;
            group.check_embedded_order(embedded)?;
        }
        _ => bail!("V3 source group cannot emit without externally selected original-order policy"),
    }
    architecture(target)?;
    if !matches!(kind, "ir" | "obj") || !options.dependencies.is_empty() {
        bail!("invalid source group output/options");
    }
    python.checked()?;
    library.checked()?;
    fs::create_dir(output)?;
    let output = output.canonicalize()?;
    // Recompute commitments/resolution before original IR import/emission.
    // Detached consistency consumes embedded captures, not old source pathnames.
    group.recheck_selected_order(
        selected_order,
        python,
        &output.join("source-order-readmission"),
    )?;
    let mut records = Vec::new();
    let mut issues = Vec::new();
    let (metadata_sidecars, metadata_capability) =
        metadata_diagnostics_capability(compiler, &output)?;
    for (component_index, component) in group.components.iter().enumerate() {
        for (unit_index, unit) in component.units.iter().enumerate() {
            let mut diagnostic_record = Value::Null;
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
                // Source inventory alone cannot establish body preservation.
                // Compare the complete canonical import, accounting explicitly
                // for its verified relocated diagnostic input pathname only.
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
                if module.target.linux_syscall_profile.is_some() {
                    args.extend(["--linux-syscall-profile".into(), "linux-user-raw-v1".into()]);
                }
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
                let diagnostics =
                    metadata_sidecars.then(|| directory.join("llvm-metadata-diagnostics.json"));
                if let Some(path) = &diagnostics {
                    args.extend([RAW_METADATA_OPTION.into(), path.display().to_string()]);
                }
                fs::write(
                    directory.join("import-command.json"),
                    serde_json::to_vec_pretty(
                        &json!({"program":compiler,"sha256":digest(&fs::read(compiler)?),"argv":args}),
                    )?,
                )?;
                let import_result = invoke(compiler, &args, &directory.join("import.log"));
                if let Some(path) = &diagnostics {
                    diagnostic_record = retained_metadata_diagnostics(path);
                }
                import_result?;
                let fresh = NativeModule::from_json(&fs::read(fresh)?)
                    .map_err(|e| anyhow::anyhow!(e.message))?;
                diagnostic_record = validate_metadata_diagnostics(
                    diagnostics.as_deref(),
                    &fresh,
                    &original,
                    Some(&library.sha256),
                )?;
                let diagnostic_name = compare_relocated_import(fresh, &module, &original_path)?;
                metadata_diagnostics_postguard(&diagnostic_record)?;
                Ok(
                    json!({"component":component.name,"id":unit.id,"source_inventory":inventory,
                        "diagnostic_name_rebinding":diagnostic_name,"fresh_typed_import_match":true,
                        "metadata_diagnostics":diagnostic_record}),
                )
            })();
            match result {
                Ok(record) => records.push(record),
                Err(error) => {
                    issues.push(format!("{}:{}: {error:#}", component.name, unit.id));
                    records.push(json!({"component":component.name,"id":unit.id,
                        "fresh_typed_import_match":false,"failure":format!("{error:#}"),
                        "metadata_diagnostics":diagnostic_record}));
                }
            }
        }
    }
    let complete = issues.is_empty();
    let mut receipt = json!({"schema":"ocore-source-group-readmission-v1","source_group_sha256":digest(bytes),"units":records,"issues":issues,
        "metadata_diagnostics_capability":metadata_capability,
        "included_original_ir_body_consistency":complete,"original_checkout_build_reverified":false,
        "artifact_complete":false,"platform_resource_closure_complete":false,"native_execution_qualified":false,"runtime_complete":false});
    let required_platforms = group.module_set.required_platform_interfaces()?;
    if !required_platforms.is_empty() {
        receipt["required_platform_interfaces"] = json!(required_platforms);
    }
    fs::write(
        output.join("source-readmission.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    if !complete {
        bail!("source group readmission failed; see {}", output.display());
    }
    group.require_membership(selected_membership)?;
    if let Some(order) = selected_order {
        order.check_unchanged()?;
    }
    if let Some(order) = &group.original_order {
        group.check_embedded_order(order)?;
    }
    artifact::compile_package(
        &serde_json::to_vec_pretty(&group.module_set)?,
        target,
        kind,
        &output.join("lowered"),
        compiler,
    )?;
    group.require_membership(selected_membership)?;
    if let Some(order) = selected_order {
        order.check_unchanged()?;
    }
    fs::write(output.join(FILE_NAME), bytes)?;
    if let Err(error) = group.require_membership(selected_membership) {
        fs::remove_file(output.join(FILE_NAME))?;
        return Err(error);
    }
    Ok(())
}

// Reconstruct recipe-floor plus complete build-finalized requirements. The floor
// is a subset, never equality with the generated inventory. This does not claim
// the embedded capture is a fresh checkout/build replay.
fn check_original_selection(recipe: &Value, finalized: &Value, capture: &Value) -> Result<()> {
    // The worker appends finalized requirements to the recipe floor and emits
    // one bound record for every declaration. Preserve that multiplicity and
    // order, including compatible repeated IDs; never collapse their evidence.
    let required: Vec<_> = array(&recipe["coverage"], "required_units")?
        .iter()
        .chain(array(finalized, "units")?)
        .collect();
    let mut definitions = BTreeMap::<String, Value>::new();
    for rule in &required {
        let id = string(rule, "id")?.to_owned();
        if let Some(previous) = definitions.get_mut(&id) {
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
            definitions.insert(id, (*rule).clone());
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
    let bound_rules = array(capture, "required_units")?;
    if bound_rules.len() != required.len() {
        bail!("partial original recipe/finalized unit inventory");
    }
    let mut lowering = BTreeSet::new();
    let mut assigned = BTreeSet::new();
    for (bound, rule) in bound_rules.iter().zip(required) {
        let id = string(rule, "id")?;
        if string(bound, "id")? != id
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
    if assigned != known {
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
