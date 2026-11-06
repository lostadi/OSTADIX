//! Relocatable, self-contained sets of verified native modules.
//!
//! These packages establish native IR and declared module dependency closure.
//! They do not establish platform/resource closure, reference execution, or a
//! complete runtime. Reading a package never opens its original capture files.

use super::*;
use o_lang::ocore::native_ir::TargetLayout;
use serde::{Deserialize, Serialize};

pub(super) const FORMAT: &str = "ocore-native-module-set-v1";
pub(super) const FILE_NAME: &str = "runtime.native-ir.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Dependency {
    name: String,
    capture_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Component {
    name: String,
    capture_sha256: String,
    unit_ids: Vec<String>,
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct EmbeddedModule {
    pub(super) component: String,
    pub(super) unit_id: String,
    pub(super) sha256: String,
    /// Preserve the exact independently verified bytes and their digest.
    pub(super) native_ir: String,
}

impl EmbeddedModule {
    pub(super) fn identity(&self) -> String {
        module_identity(&self.component, &self.unit_id)
    }

    pub(super) fn verify(&self) -> Result<NativeModule> {
        if self.sha256 != digest(self.native_ir.as_bytes()) {
            bail!("embedded native module hash differs: {}", self.identity());
        }
        let module = NativeModule::from_json(self.native_ir.as_bytes()).map_err(|error| {
            anyhow::anyhow!(
                "embedded native module {}: {}",
                self.identity(),
                error.message
            )
        })?;
        if module.has_nonlocal_control_effects() {
            bail!("returns_twice module-set admission requires verified nonlocal control/provider contracts; complete artifact is not admitted");
        }
        Ok(module)
    }
}

pub(super) fn module_identity(component: &str, unit_id: &str) -> String {
    // A tuple encoding remains unambiguous for arbitrary component/unit names.
    serde_json::to_string(&(component, unit_id)).unwrap()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifact {
    format: String,
    pub(super) name: String,
    target: TargetLayout,
    components: Vec<Component>,
    pub(super) modules: Vec<EmbeddedModule>,
    symbol_inventory: Value,
}

pub(super) struct GroupComponent {
    pub(super) name: String,
    pub(super) capture_sha256: String,
    pub(super) modules: Vec<(String, Vec<u8>)>,
    pub(super) dependencies: Vec<(String, String)>,
}

pub(super) struct LoadedArtifact {
    pub(super) artifact: Artifact,
    pub(super) sha256: String,
}

fn identifier(value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        bail!("empty, padded or control-containing native module-set identity");
    }
    Ok(())
}

fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("native module-set provenance requires a lowercase SHA-256");
    }
    Ok(())
}

impl Artifact {
    fn root(&self) -> Result<&Component> {
        self.components
            .iter()
            .find(|component| component.name == self.name)
            .context("native module-set has no root component")
    }

    fn inventory(&self) -> Result<Value> {
        if self.format != FORMAT {
            bail!("unsupported native module-set format");
        }
        identifier(&self.name)?;
        if self.modules.is_empty() || self.components.is_empty() {
            bail!("native module-set cannot be empty");
        }
        let mut components = BTreeMap::new();
        for component in &self.components {
            identifier(&component.name)?;
            hash(&component.capture_sha256)?;
            if components
                .insert(component.name.as_str(), component)
                .is_some()
            {
                bail!("duplicate native module-set component: {}", component.name);
            }
            let units: BTreeSet<_> = component.unit_ids.iter().collect();
            if units.is_empty() || units.len() != component.unit_ids.len() {
                bail!("empty or duplicate native module-set unit inventory");
            }
            for unit in &component.unit_ids {
                identifier(unit)?;
            }
            let mut dependencies = BTreeSet::new();
            for dependency in &component.dependencies {
                identifier(&dependency.name)?;
                hash(&dependency.capture_sha256)?;
                if !dependencies.insert(&dependency.name) {
                    bail!("duplicate component dependency: {}", dependency.name);
                }
            }
        }
        self.root()?;
        for component in &self.components {
            for dependency in &component.dependencies {
                let provider = components.get(dependency.name.as_str()).with_context(|| {
                    format!("missing included dependency component {}", dependency.name)
                })?;
                if dependency.capture_sha256 != provider.capture_sha256 {
                    bail!(
                        "included dependency capture hash differs: {}",
                        dependency.name
                    );
                }
            }
        }
        // Traverse iteratively so a large dependency graph cannot exhaust the stack.
        let mut visited = BTreeSet::new();
        let mut pending = vec![self.name.as_str()];
        while let Some(name) = pending.pop() {
            if !visited.insert(name) {
                continue;
            }
            for dependency in components[name].dependencies.iter().rev() {
                pending.push(dependency.name.as_str());
            }
        }
        if visited.len() != components.len() {
            bail!("unused or unreachable native module-set dependency component");
        }
        let target = serde_json::to_value(&self.target)?;
        let mut actual = BTreeMap::<&str, BTreeSet<&str>>::new();
        let mut collected = Vec::new();
        for embedded in &self.modules {
            if !components.contains_key(embedded.component.as_str()) {
                bail!("native module has no included component");
            }
            identifier(&embedded.unit_id)?;
            if !actual
                .entry(&embedded.component)
                .or_default()
                .insert(&embedded.unit_id)
            {
                bail!("duplicate embedded native module identity");
            }
            let module = embedded.verify()?;
            if serde_json::to_value(&module.target)? != target {
                bail!("native module-set target/DataLayout/execution profiles differ");
            }
            collected.extend(symbols(&embedded.identity(), &module)?);
        }
        for component in &self.components {
            if actual.get(component.name.as_str())
                != Some(&component.unit_ids.iter().map(String::as_str).collect())
            {
                bail!(
                    "embedded native module inventory differs for {}",
                    component.name
                );
            }
        }
        let (inventory, issues) = resolve_symbols(&collected);
        if !issues.is_empty() {
            bail!(
                "native module-set symbol closure failed: {}",
                issues.join("; ")
            );
        }
        Ok(inventory)
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut artifact: Self =
            serde_json::from_slice(bytes).context("decode native module-set")?;
        let inventory = artifact.inventory()?;
        if artifact.symbol_inventory != inventory {
            // V1 predates the independently derived storage diagnostics. A
            // legacy packet may omit those new fields, but cannot contradict
            // any field or omit a non-null opaque-provider proof. Module
            // verification and the full current closure already ran above.
            let mut upgraded = artifact.symbol_inventory.clone();
            for (category, field) in [
                ("definitions", "storage_layout"),
                ("declarations", "storage_refinement"),
            ] {
                let old = upgraded[category]
                    .as_array_mut()
                    .context("legacy native symbol inventory has no category array")?;
                let new = inventory[category]
                    .as_array()
                    .context("recomputed native symbol inventory has no category array")?;
                if old.len() != new.len() {
                    bail!("legacy native symbol inventory category length differs");
                }
                for (old, new) in old.iter_mut().zip(new) {
                    if old["unit"] != new["unit"] || old["symbol"] != new["symbol"] {
                        bail!("legacy native symbol inventory identity/order differs");
                    }
                    let entry = old
                        .as_object_mut()
                        .context("legacy native symbol inventory entry is not an object")?;
                    if !entry.contains_key(field) {
                        // Owned intrinsic entries have no storage diagnostic
                        // in either version. Do not invent a field for them.
                        if let Some(value) = new.get(field) {
                            if field == "storage_refinement" && !value.is_null() {
                                bail!("legacy native symbol inventory cannot omit a non-null opaque-provider proof");
                            }
                            entry.insert(field.into(), value.clone());
                        }
                    }
                }
            }
            if upgraded != inventory {
                bail!(
                    "native module-set symbol inventory differs from independently recomputed closure"
                );
            }
            artifact.symbol_inventory = inventory;
        }
        Ok(artifact)
    }

    pub(super) fn check_component_dependencies(
        &self,
        name: &str,
        expected: &[(String, String)],
    ) -> Result<()> {
        let component = self
            .components
            .iter()
            .find(|c| c.name == name)
            .context("source component absent")?;
        let actual: BTreeSet<_> = component
            .dependencies
            .iter()
            .map(|d| (d.name.clone(), d.capture_sha256.clone()))
            .collect();
        // Original logical labels remain in SourceComponent and its pinned
        // recipe. Multiple labels may name the same physical provider edge.
        if actual != expected.iter().cloned().collect() {
            bail!("source dependency graph differs from original recipe/policy");
        }
        Ok(())
    }

    pub(super) fn check_component(
        &self,
        name: &str,
        capture_sha256: &str,
        units: &BTreeSet<&str>,
    ) -> Result<()> {
        let component = self
            .components
            .iter()
            .find(|c| c.name == name)
            .context("source group component absent")?;
        if component.capture_sha256 != capture_sha256
            || component
                .unit_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != *units
        {
            bail!("source group component capture/unit binding differs");
        }
        Ok(())
    }

    fn group_body(root: &str, sources: &[GroupComponent]) -> Result<Self> {
        let first = sources
            .first()
            .and_then(|s| s.modules.first())
            .context("empty source group")?;
        let first = NativeModule::from_json(&first.1).map_err(|e| anyhow::anyhow!(e.message))?;
        let mut artifact = Self {
            format: FORMAT.into(),
            name: root.into(),
            target: first.target,
            components: Vec::new(),
            modules: Vec::new(),
            symbol_inventory: Value::Null,
        };
        for source in sources {
            artifact.components.push(Component {
                name: source.name.clone(),
                capture_sha256: source.capture_sha256.clone(),
                unit_ids: source.modules.iter().map(|(id, _)| id.clone()).collect(),
                dependencies: source
                    .dependencies
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(|(name, capture_sha256)| Dependency {
                        name,
                        capture_sha256,
                    })
                    .collect(),
            });
            for (id, bytes) in &source.modules {
                artifact.modules.push(EmbeddedModule {
                    component: source.name.clone(),
                    unit_id: id.clone(),
                    sha256: digest(bytes),
                    native_ir: String::from_utf8(bytes.clone())?,
                });
            }
        }
        Ok(artifact)
    }

    pub(super) fn build_group(root: &str, sources: &[GroupComponent]) -> Result<Self> {
        let mut artifact = Self::group_body(root, sources)?;
        artifact.symbol_inventory = artifact.inventory()?;
        Ok(artifact)
    }

    // Complete unique IR bodies are distinct from an original native link's
    // object/archive occurrences. This current all-units resolver does not
    // implement repeated object definitions, archive extraction or rescanning.
    // Refuse those plans explicitly; never project them to first occurrences.
    fn validate_module_resolution_order(&self, order: &[(String, String)]) -> Result<()> {
        if order.is_empty() {
            bail!("source module resolution order is empty");
        }
        let mut selected = BTreeSet::new();
        for (component, unit) in order {
            identifier(component)?;
            identifier(unit)?;
            if !selected.insert((component.as_str(), unit.as_str())) {
                bail!("repeated source-module occurrences require an explicit native link realization; not admitted");
            }
        }
        let mut available = BTreeSet::new();
        for module in &self.modules {
            if !available.insert((module.component.as_str(), module.unit_id.as_str())) {
                bail!("duplicate source module body inventory");
            }
        }
        if selected != available {
            bail!("source module resolution order differs from complete module body inventory");
        }
        Ok(())
    }

    pub(super) fn build_group_ordered(
        root: &str,
        sources: &[GroupComponent],
        order: &[(String, String)],
    ) -> Result<Self> {
        // Do not run the old-order resolver first: it could choose an
        // incompatible weak definition before the selected order is applied.
        let mut artifact = Self::group_body(root, sources)?;
        artifact.validate_module_resolution_order(order)?;
        let mut bodies: BTreeMap<_, _> = std::mem::take(&mut artifact.modules)
            .into_iter()
            .map(|module| ((module.component.clone(), module.unit_id.clone()), module))
            .collect();
        artifact.modules = order
            .iter()
            .map(|identity| {
                bodies
                    .remove(identity)
                    .context("selected source module body absent")
            })
            .collect::<Result<Vec<_>>>()?;
        artifact.check_module_order(order)?;
        // The same real resolver used by V1 now consumes the selected order.
        // Its strong/weak/linkage, ABI, initializer and nonlocal guards remain.
        artifact.symbol_inventory = artifact.inventory()?;
        Ok(artifact)
    }

    /// Order consistency only. Callers must also retain normal Artifact and
    /// original-source/admission checks and the independently held policy.
    pub(super) fn check_module_order(&self, expected: &[(String, String)]) -> Result<()> {
        self.validate_module_resolution_order(expected)?;
        let actual: Vec<_> = self
            .modules
            .iter()
            .map(|module| (module.component.clone(), module.unit_id.clone()))
            .collect();
        if actual.as_slice() != expected {
            bail!("serialized native module order differs from selected source resolution order");
        }
        Ok(())
    }

    pub(super) fn build(
        name: &str,
        capture_sha256: &str,
        modules: &[(String, Vec<u8>)],
        dependencies: &[LoadedArtifact],
    ) -> Result<Self> {
        let first = modules
            .first()
            .context("native module-set has no captured modules")?;
        let first =
            NativeModule::from_json(&first.1).map_err(|error| anyhow::anyhow!(error.message))?;
        let mut artifact = Self {
            format: FORMAT.into(),
            name: name.into(),
            target: first.target,
            components: vec![Component {
                name: name.into(),
                capture_sha256: capture_sha256.into(),
                unit_ids: modules.iter().map(|(id, _)| id.clone()).collect(),
                dependencies: dependencies
                    .iter()
                    .map(|dependency| {
                        Ok(Dependency {
                            name: dependency.artifact.name.clone(),
                            capture_sha256: dependency.artifact.root()?.capture_sha256.clone(),
                        })
                    })
                    .collect::<Result<_>>()?,
            }],
            modules: modules
                .iter()
                .map(|(id, bytes)| {
                    Ok(EmbeddedModule {
                        component: name.into(),
                        unit_id: id.clone(),
                        sha256: digest(bytes),
                        native_ir: String::from_utf8(bytes.clone())
                            .context("native module is not UTF-8")?,
                    })
                })
                .collect::<Result<_>>()?,
            symbol_inventory: Value::Null,
        };
        let mut component_positions: BTreeMap<_, _> = artifact
            .components
            .iter()
            .enumerate()
            .map(|(index, component)| (component.name.clone(), index))
            .collect();
        let mut module_positions: BTreeMap<_, _> = artifact
            .modules
            .iter()
            .enumerate()
            .map(|(index, module)| ((module.component.clone(), module.unit_id.clone()), index))
            .collect();
        for dependency in dependencies {
            for component in &dependency.artifact.components {
                match component_positions.get(&component.name) {
                    Some(index)
                        if &artifact.components[*index] == component && component.name != name => {}
                    Some(_) => bail!("ambiguous native dependency component: {}", component.name),
                    None => {
                        component_positions
                            .insert(component.name.clone(), artifact.components.len());
                        artifact.components.push(component.clone());
                    }
                }
            }
            for module in &dependency.artifact.modules {
                let identity = (module.component.clone(), module.unit_id.clone());
                match module_positions.get(&identity) {
                    Some(index) if &artifact.modules[*index] == module => {}
                    Some(_) => bail!("conflicting included dependency module"),
                    None => {
                        module_positions.insert(identity, artifact.modules.len());
                        artifact.modules.push(module.clone());
                    }
                }
            }
        }
        artifact.symbol_inventory = artifact.inventory()?;
        Ok(artifact)
    }
}

/// Re-emit an admitted native module-set without reopening foreign source, LLVM
/// input, original capture receipts, or a frontend/parser installation.
pub(super) fn compile_package(
    bytes: &[u8],
    target: &str,
    output_kind: &str,
    output: &Path,
    compiler: &Path,
) -> Result<()> {
    let artifact = Artifact::from_bytes(bytes)?;
    let arch = architecture(target)?;
    if !matches!(output_kind, "ir" | "obj") {
        bail!("native module-set output must be ir or obj");
    }
    if artifact.target.triple.split('-').next() != Some(arch) {
        bail!("native module-set architecture differs from requested ISA; implicit retargeting is not supported");
    }
    let compiler_sha256 = if output_kind == "obj" {
        Some(digest(
            &fs::read(compiler).context("read actual O-core compiler")?,
        ))
    } else {
        None
    };
    fs::create_dir(output).with_context(|| {
        format!(
            "native module-set output must be a new directory: {}",
            output.display()
        )
    })?;
    let output = output.canonicalize()?;
    let package_path = output.join(FILE_NAME);
    fs::write(&package_path, bytes)?;
    let mut records = Vec::new();
    let mut issues = Vec::new();
    for (index, embedded) in artifact.modules.iter().enumerate() {
        let mut record = json!({"id":embedded.identity(),"component":embedded.component,
            "unit_id":embedded.unit_id,"verified":true,"lowered":false,
            "verification_mode":"in_process"});
        let result = (|| -> Result<()> {
            let module = embedded.verify()?;
            let directory = output.join(format!("unit-{index:06}"));
            fs::create_dir(&directory)?;
            let imported = directory.join("module.native-ir.json");
            fs::write(&imported, embedded.native_ir.as_bytes())?;
            record["module"] = json!({"path":imported,"sha256":embedded.sha256});
            record["generated_floating_helper_requirements"] =
                json!(floating_requirements(&module)?);
            if output_kind == "obj" {
                let object = directory.join("module.o");
                let emission_arguments = vec![
                    imported.display().to_string(),
                    "--input-kind".into(),
                    "native-ir".into(),
                    "--emit".into(),
                    "obj".into(),
                    "--target".into(),
                    format!("{arch}-unknown-none"),
                    "-o".into(),
                    object.display().to_string(),
                ];
                record["emit_argv"] = json!(emission_arguments);
                invoke(compiler, &emission_arguments, &directory.join("emit.log"))?;
                let object_bytes = fs::read(&object)?;
                record["object_inventory"] = object_inventory(&object_bytes, arch, &module)?;
                record["object"] = json!({"path":object,"sha256":digest(&object_bytes),"bytes":object_bytes.len()});
            }
            if fs::read(&imported)? != embedded.native_ir.as_bytes() {
                bail!("embedded module changed during native lowering");
            }
            record["lowered"] = json!(true);
            Ok(())
        })();
        if let Err(error) = result {
            record["failure"] = json!(error.to_string());
            issues.push(format!("native module {}: {error}", embedded.identity()));
        }
        records.push(record);
    }
    if let Some(expected) = &compiler_sha256 {
        if fs::read(compiler).map(|bytes| digest(&bytes)).ok().as_ref() != Some(expected) {
            issues.push("actual O-core compiler changed during native lowering".into());
        }
    }
    if fs::read(&package_path)? != bytes {
        issues.push("native module-set changed during native lowering".into());
    }
    let complete = issues.is_empty();
    let receipt = json!({"schema":RECEIPT_FORMAT,"input_kind":"native_module_set",
        "input_sha256":digest(bytes),"name":artifact.name,"requested_target":target,"architecture":arch,
        "output_kind":output_kind,"compiler":(output_kind == "obj").then_some(compiler),
        "compiler_sha256":compiler_sha256,
        "source_capture_reverification_performed":false,"units":records,"issues":issues,
        "module_set_artifact":{"path":package_path,"sha256":digest(bytes),"bytes":bytes.len(),
            "format":FORMAT,"module_count":artifact.modules.len()},
        "symbol_inventory":artifact.symbol_inventory,
        "unit_lowering_complete":complete,"lowering_complete":complete,
        "module_set_complete":true,"symbol_closure_complete":true,"native_module_dependency_closure_complete":true,
        "dependency_closure_complete":false,"artifact_complete":false,"link_performed":false,
        "native_execution_qualified":false,"runtime_complete":false,
        "scope":"reverified self-contained native module-set; no fresh source capture, linked runtime, or native execution qualification"});
    let receipt_path = output.join("coverage.json");
    fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt)?)?;
    if !complete {
        bail!(
            "native module-set lowering incomplete; see {}",
            receipt_path.display()
        );
    }
    eprintln!(
        "olangc: lowered {} self-contained native modules; receipt {}",
        artifact.modules.len(),
        receipt_path.display()
    );
    Ok(())
}

pub(super) fn load_dependencies(capture: &Value, paths: &[PathBuf]) -> Result<Vec<LoadedArtifact>> {
    let mut expected = BTreeSet::new();
    for dependency in array(&capture["dependencies"], "declared")? {
        let name = string(dependency, "name")?;
        identifier(name)?;
        if dependency
            .get("source_pin")
            .is_some_and(|pin| !pin.is_null())
        {
            bail!("declared dependency {name} has a source_pin that this native module-set schema cannot independently bind; pinned source identity support is required");
        }
        if !expected.insert(name) {
            bail!("duplicate declared source dependency: {name}");
        }
    }
    let mut actual = BTreeSet::new();
    let mut loaded = Vec::new();
    for path in paths {
        let bytes = fs::read(path)
            .with_context(|| format!("read included native dependency {}", path.display()))?;
        let artifact = Artifact::from_bytes(&bytes)?;
        if !expected.contains(artifact.name.as_str()) {
            bail!(
                "unused or undeclared native dependency package: {}",
                artifact.name
            );
        }
        if !actual.insert(artifact.name.clone()) {
            bail!(
                "duplicate supplied native dependency package: {}",
                artifact.name
            );
        }
        loaded.push(LoadedArtifact {
            artifact,
            sha256: digest(&bytes),
        });
    }
    if expected.iter().any(|name| !actual.contains(*name)) {
        bail!("declared source dependency lacks a verified included native module-set");
    }
    Ok(loaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(name: &str, definition: bool) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "format":"ocore-native-module-v1", "name":name,
            "target":{"triple":"x86_64-unknown-none","data_layout":"e-p:64:64-i64:64","pointer_bits":64,"little_endian":true},
            "semantics":"llvm_defined_behavior_v1","types":[{"kind":"void"}],"globals":[],
            "functions":[{"name":name,"linkage":"external","signature":{"params":[],"result":0,"abi":"c","variadic":false},
                "params":[],"entry":if definition {json!(0)} else {Value::Null},
                "blocks":if definition {json!([{"id":0,"instructions":[],"terminator":{"op":"return","value":null}}])} else {json!([])}}],
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"authored-test","frontend_version":"1",
                "importer":"test","importer_version":"1","source_function_count":1,"source_global_count":0,"refinements":[]}
        })).unwrap()
    }

    fn package(name: &str) -> Artifact {
        Artifact::build(
            name,
            &"a".repeat(64),
            &[("unit".into(), module(name, true))],
            &[],
        )
        .unwrap()
    }

    fn loaded(artifact: Artifact) -> LoadedArtifact {
        LoadedArtifact {
            sha256: digest(&serde_json::to_vec(&artifact).unwrap()),
            artifact,
        }
    }

    #[test]
    fn legacy_inventory_can_derive_only_missing_storage_diagnostics() {
        let mut provider_module: Value = serde_json::from_slice(&module("provider", true)).unwrap();
        provider_module["functions"]
            .as_array_mut()
            .unwrap()
            .push(json!({
            "name":"llvm.trap","linkage":"external","intrinsic":"llvm.trap",
            "signature":{"params":[],"result":0,"abi":"c","variadic":false},
            "params":[],"entry":null,"blocks":[]}));
        provider_module["provenance"]["source_function_count"] = json!(2);
        let provider = Artifact::build(
            "provider",
            &"a".repeat(64),
            &[("unit".into(), serde_json::to_vec(&provider_module).unwrap())],
            &[],
        )
        .unwrap();
        let source = Artifact::build(
            "consumer",
            &"b".repeat(64),
            &[("consumer".into(), module("provider", false))],
            &[loaded(provider)],
        )
        .unwrap();
        let mut old = source.clone();
        for entry in old.symbol_inventory["definitions"].as_array_mut().unwrap() {
            entry.as_object_mut().unwrap().remove("storage_layout");
        }
        for entry in old.symbol_inventory["declarations"].as_array_mut().unwrap() {
            assert!(entry["storage_refinement"].is_null());
            entry.as_object_mut().unwrap().remove("storage_refinement");
        }
        let restored = Artifact::from_bytes(&serde_json::to_vec(&old).unwrap()).unwrap();
        assert_eq!(restored.symbol_inventory, source.symbol_inventory);
        assert_eq!(restored.modules[0].native_ir, source.modules[0].native_ir);
        for field in ["unknown", "storage_layout"] {
            let mut altered = old.clone();
            altered.symbol_inventory["definitions"][0][field] = json!({"invented":true});
            assert!(Artifact::from_bytes(&serde_json::to_vec(&altered).unwrap()).is_err());
        }
        let mut altered = old;
        altered.symbol_inventory["declarations"][0]["compatible"] = json!(false);
        assert!(Artifact::from_bytes(&serde_json::to_vec(&altered).unwrap()).is_err());
    }

    #[test]
    fn legacy_inventory_never_synthesizes_a_required_opaque_provider_proof() {
        let original = |opaque| {
            let m = super::super::tests::opaque_storage_module(opaque, false);
            m.to_json().unwrap()
        };
        let provider = Artifact::build(
            "provider",
            &"a".repeat(64),
            &[("definition".into(), original(false))],
            &[],
        )
        .unwrap();
        let source = Artifact::build(
            "consumer",
            &"b".repeat(64),
            &[("declaration".into(), original(true))],
            &[loaded(provider)],
        )
        .unwrap();
        assert!(source.symbol_inventory["declarations"][0]["storage_refinement"].is_object());
        let mut missing = source.clone();
        missing.symbol_inventory["declarations"][0]
            .as_object_mut()
            .unwrap()
            .remove("storage_refinement");
        assert!(Artifact::from_bytes(&serde_json::to_vec(&missing).unwrap()).is_err());
        let mut wrong = source.clone();
        wrong.symbol_inventory["declarations"][0]["storage_refinement"]
            ["provider_storage_layout"]["size"] = json!(9);
        assert!(Artifact::from_bytes(&serde_json::to_vec(&wrong).unwrap()).is_err());
        let mut legacy_layout = source.clone();
        for entry in legacy_layout.symbol_inventory["definitions"]
            .as_array_mut()
            .unwrap()
        {
            entry.as_object_mut().unwrap().remove("storage_layout");
        }
        let restored = Artifact::from_bytes(&serde_json::to_vec(&legacy_layout).unwrap()).unwrap();
        assert_eq!(restored.symbol_inventory, source.symbol_inventory);
    }

    #[test]
    fn package_reuses_complete_modules_without_original_input_files() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("original.native-ir.json");
        fs::write(&input, module("provider", true)).unwrap();
        let artifact = Artifact::build(
            "provider",
            &"a".repeat(64),
            &[("source".into(), fs::read(&input).unwrap())],
            &[],
        )
        .unwrap();
        fs::remove_file(input).unwrap();
        let bytes = serde_json::to_vec(&artifact).unwrap();
        let imported = Artifact::from_bytes(&bytes).unwrap();
        let combined = Artifact::build(
            "consumer",
            &"b".repeat(64),
            &[("consumer".into(), module("provider", false))],
            &[loaded(imported)],
        )
        .unwrap();
        assert_eq!(combined.modules.len(), 2);
        assert!(Artifact::from_bytes(&serde_json::to_vec(&combined).unwrap()).is_ok());
        assert_eq!(combined.symbol_inventory["closed"], true);
    }

    #[test]
    fn package_rechecks_hashes_bodies_inventories_profiles_and_closure() {
        let source = package("provider");
        for case in 0..10 {
            let mut altered = source.clone();
            match case {
                0 => altered.modules[0].sha256 = "0".repeat(64),
                1 => {
                    let mut ir: Value =
                        serde_json::from_str(&altered.modules[0].native_ir).unwrap();
                    ir["functions"][0]["blocks"][0]["terminator"]["op"] = json!("invented");
                    altered.modules[0].native_ir = ir.to_string();
                    altered.modules[0].sha256 = digest(altered.modules[0].native_ir.as_bytes());
                }
                2 => altered.components[0].unit_ids.push("missing".into()),
                3 => altered.components.push(altered.components[0].clone()),
                4 => altered.modules.push(altered.modules[0].clone()),
                5 => altered.target.atomic_profile = Some(AtomicProfile::CoherentRamV1),
                6 => altered.symbol_inventory["closed"] = json!(false),
                7 => {
                    altered.modules[0] = EmbeddedModule {
                        component: "provider".into(),
                        unit_id: "unit".into(),
                        native_ir: String::from_utf8(module("missing", false)).unwrap(),
                        sha256: digest(&module("missing", false)),
                    }
                }
                8 => altered.components[0].dependencies.push(Dependency {
                    name: "absent".into(),
                    capture_sha256: "a".repeat(64),
                }),
                9 => {
                    altered.target.wide_volatile_profile =
                        Some(WideVolatileProfile::OrdinaryRamSplitV1)
                }
                _ => unreachable!(),
            }
            assert!(
                Artifact::from_bytes(&serde_json::to_vec(&altered).unwrap()).is_err(),
                "case {case}"
            );
        }
        for path in [
            vec!["unknown"],
            vec!["components", "0", "unknown"],
            vec!["modules", "0", "unknown"],
        ] {
            let mut value = serde_json::to_value(&source).unwrap();
            let mut current = &mut value;
            for key in &path[..path.len() - 1] {
                current = if let Ok(index) = key.parse::<usize>() {
                    &mut current[index]
                } else {
                    &mut current[*key]
                };
            }
            current[*path.last().unwrap()] = json!(true);
            assert!(Artifact::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn dependencies_reject_unused_duplicate_conflicting_and_missing_bindings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.json");
        fs::write(&path, serde_json::to_vec(&package("provider")).unwrap()).unwrap();
        let capture = json!({"dependencies":{"declared":[{"name":"provider"}]}});
        assert!(load_dependencies(&capture, std::slice::from_ref(&path)).is_ok());
        assert!(load_dependencies(&capture, &[]).is_err());
        assert!(load_dependencies(&capture, &[path.clone(), path.clone()]).is_err());
        assert!(load_dependencies(&json!({"dependencies":{"declared":[]}}), &[path]).is_err());
        assert!(load_dependencies(
            &json!({"dependencies":{"declared":[{"name":"provider"},{"name":"provider"}]}}),
            &[]
        )
        .is_err());
        assert!(Artifact::build(
            "provider",
            &"b".repeat(64),
            &[("unit".into(), module("other", true))],
            &[loaded(package("provider"))]
        )
        .is_err());
    }

    #[test]
    fn transitive_packages_preserve_shared_components_and_cyclic_dependency_edges() {
        let leaf = package("leaf");
        let middle = Artifact::build(
            "middle",
            &"b".repeat(64),
            &[("unit".into(), module("middle", true))],
            &[loaded(leaf.clone())],
        )
        .unwrap();
        let root = Artifact::build(
            "root",
            &"c".repeat(64),
            &[("unit".into(), module("root", true))],
            &[loaded(middle), loaded(leaf)],
        )
        .unwrap();
        assert_eq!(root.modules.len(), 3);
        let mut unused = root.clone();
        unused.components[0].dependencies.clear();
        assert!(unused.inventory().is_err());
        let mut cyclic = root;
        cyclic
            .components
            .iter_mut()
            .find(|component| component.name == "leaf")
            .unwrap()
            .dependencies
            .push(Dependency {
                name: "root".into(),
                capture_sha256: "c".repeat(64),
            });
        assert!(cyclic.inventory().is_ok());
    }

    fn ordered_choice_sources(strong_b: bool) -> Vec<GroupComponent> {
        let choice = |bits: &str, linkage: &str| {
            let mut ir: Value = serde_json::from_slice(&module("choice", true)).unwrap();
            ir["types"]
                .as_array_mut()
                .unwrap()
                .push(json!({"kind":"int", "bits":32}));
            ir["functions"][0]["signature"]["result"] = json!(1);
            ir["functions"][0]["linkage"] = json!(linkage);
            ir["functions"][0]["blocks"][0]["terminator"]["value"] =
                json!({"kind":"int", "ty":1, "bits":bits});
            serde_json::to_vec(&ir).unwrap()
        };
        vec![
            GroupComponent {
                name: "root".into(),
                capture_sha256: "c".repeat(64),
                modules: vec![("r".into(), module("root", true))],
                dependencies: vec![("A".into(), "a".repeat(64)), ("B".into(), "b".repeat(64))],
            },
            GroupComponent {
                name: "A".into(),
                capture_sha256: "a".repeat(64),
                modules: vec![("a".into(), choice("101", "weak"))],
                dependencies: vec![],
            },
            GroupComponent {
                name: "B".into(),
                capture_sha256: "b".repeat(64),
                modules: vec![(
                    "b".into(),
                    choice("202", if strong_b { "external" } else { "weak" }),
                )],
                dependencies: vec![],
            },
        ]
    }

    fn order_b_before_a() -> Vec<(String, String)> {
        vec![
            ("root".into(), "r".into()),
            ("B".into(), "b".into()),
            ("A".into(), "a".into()),
        ]
    }

    fn selected_choice(artifact: &Artifact) -> String {
        artifact.symbol_inventory["export_resolutions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["symbol"] == "choice")
            .unwrap()["selected_unit"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn ordered_source_group_changes_actual_weak_choice_and_selected_body() {
        let sources = ordered_choice_sources(false);
        let legacy = Artifact::build_group("root", &sources).unwrap();
        assert_eq!(selected_choice(&legacy), module_identity("A", "a"));
        let order = order_b_before_a();
        let selected = Artifact::build_group_ordered("root", &sources, &order).unwrap();
        assert_eq!(selected_choice(&selected), module_identity("B", "b"));
        assert_ne!(selected_choice(&selected), selected_choice(&legacy));
        selected.check_module_order(&order).unwrap();
        let selected_body: Value = serde_json::from_str(&selected.modules[1].native_ir).unwrap();
        let legacy_body: Value = serde_json::from_str(&legacy.modules[1].native_ir).unwrap();
        assert_eq!(
            selected_body["functions"][0]["blocks"][0]["terminator"]["value"]["bits"],
            "202"
        );
        assert_eq!(
            legacy_body["functions"][0]["blocks"][0]["terminator"]["value"]["bits"],
            "101"
        );
        Artifact::from_bytes(&serde_json::to_vec(&selected).unwrap())
            .unwrap()
            .check_module_order(&order)
            .unwrap();
    }

    #[test]
    fn internally_valid_reordered_package_still_fails_external_module_order() {
        let order = order_b_before_a();
        let mut changed =
            Artifact::build_group_ordered("root", &ordered_choice_sources(false), &order).unwrap();
        assert_eq!(selected_choice(&changed), module_identity("B", "b"));
        changed.modules.swap(1, 2);
        assert_eq!(changed.modules[1].component, "A");
        changed.symbol_inventory = changed.inventory().unwrap();
        assert_eq!(selected_choice(&changed), module_identity("A", "a"));
        // This mutant passes the ordinary module-set reader: only the held
        // original-order boundary can reject this internally consistent swap.
        let read = Artifact::from_bytes(&serde_json::to_vec(&changed).unwrap()).unwrap();
        let error = read.check_module_order(&order).unwrap_err().to_string();
        assert!(error.contains("serialized native module order differs"));
    }

    #[test]
    fn ordered_group_refuses_missing_extra_and_repeated_occurrences() {
        let sources = ordered_choice_sources(false);
        let valid = order_b_before_a();
        Artifact::build_group_ordered("root", &sources, &valid).unwrap();
        let mut missing = valid.clone();
        missing.pop();
        assert_ne!(missing, valid);
        assert!(Artifact::build_group_ordered("root", &sources, &missing)
            .err()
            .unwrap()
            .to_string()
            .contains("complete module body inventory"));
        let mut extra = valid.clone();
        extra.push(("B".into(), "unknown".into()));
        assert_eq!(extra.len(), valid.len() + 1);
        assert!(Artifact::build_group_ordered("root", &sources, &extra)
            .err()
            .unwrap()
            .to_string()
            .contains("complete module body inventory"));
        let mut repeated = valid.clone();
        repeated.push(valid[1].clone());
        assert_eq!(
            repeated
                .iter()
                .filter(|identity| *identity == &valid[1])
                .count(),
            2
        );
        assert!(Artifact::build_group_ordered("root", &sources, &repeated)
            .err()
            .unwrap()
            .to_string()
            .contains(
                "repeated source-module occurrences require an explicit native link realization"
            ));
    }

    #[test]
    fn ordered_group_preserves_strong_definition_precedence() {
        let sources = ordered_choice_sources(true);
        let order = order_b_before_a();
        let mut a_before_b = order.clone();
        a_before_b.swap(1, 2);
        for selected in [&order, &a_before_b] {
            let artifact = Artifact::build_group_ordered("root", &sources, selected).unwrap();
            assert_eq!(selected_choice(&artifact), module_identity("B", "b"));
            artifact.check_module_order(selected).unwrap();
        }
    }

    #[test]
    fn weak_provider_selection_preserves_explicit_dependency_order() {
        let weak = |name: &str| {
            let mut ir: Value = serde_json::from_slice(&module("choice", true)).unwrap();
            ir["functions"][0]["linkage"] = json!("weak");
            loaded(
                Artifact::build(
                    name,
                    &"a".repeat(64),
                    &[("unit".into(), serde_json::to_vec(&ir).unwrap())],
                    &[],
                )
                .unwrap(),
            )
        };
        let artifact = Artifact::build(
            "root",
            &"b".repeat(64),
            &[("unit".into(), module("root", true))],
            &[weak("z-first"), weak("a-second")],
        )
        .unwrap();
        let resolution = artifact.symbol_inventory["export_resolutions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|resolution| resolution["symbol"] == "choice")
            .unwrap();
        assert_eq!(
            resolution["selected_unit"],
            serde_json::to_string(&("z-first", "unit")).unwrap()
        );
        assert_eq!(artifact.modules[1].component, "z-first");
        assert_eq!(artifact.modules[2].component, "a-second");
    }

    #[test]
    fn standalone_package_ir_lowering_needs_no_compiler_frontend_or_capture() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("portable.native-ir.json");
        let bytes = serde_json::to_vec(&package("provider")).unwrap();
        fs::write(&path, &bytes).unwrap();
        let output = directory.path().join("lowered");
        compile_with_compiler(
            &path,
            "x86_64",
            "ir",
            &output,
            NativeImportOptions {
                llvm_library: None,
                llvm_sha256: None,
                tls_profile: None,
                atomic_profile: None,
                wide_volatile_profile: None,
                dependencies: &[],
            },
            Path::new("/compiler-must-not-run"),
        )
        .unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(fs::read(output.join(FILE_NAME)).unwrap(), bytes);
        let receipt: Value =
            serde_json::from_slice(&fs::read(output.join("coverage.json")).unwrap()).unwrap();
        assert_eq!(receipt["input_kind"], "native_module_set");
        assert_eq!(receipt["lowering_complete"], true);
        assert_eq!(receipt["source_capture_reverification_performed"], false);
        assert_eq!(receipt["runtime_complete"], false);
        assert_eq!(receipt["native_execution_qualified"], false);
        assert!(receipt["compiler"].is_null());
        for unit in receipt["units"].as_array().unwrap() {
            assert_eq!(unit["verification_mode"], "in_process");
            for field in ["import_argv", "verify_argv", "emit_argv"] {
                assert!(unit.get(field).is_none(), "unattempted command {field}");
            }
        }
        let module = fs::read(output.join("unit-000000/module.native-ir.json")).unwrap();
        assert!(NativeModule::from_json(&module).is_ok());
    }

    #[test]
    fn dependency_name_cannot_satisfy_an_unchecked_explicit_source_pin() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.json");
        fs::write(&path, serde_json::to_vec(&package("provider")).unwrap()).unwrap();
        for pin in [
            json!("a".repeat(40)),
            json!({"revision":"a".repeat(40)}),
            json!({}),
            json!(false),
        ] {
            let capture =
                json!({"dependencies":{"declared":[{"name":"provider","source_pin":pin}]}});
            let error = load_dependencies(&capture, std::slice::from_ref(&path))
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("source_pin"), "{error}");
        }
        assert!(load_dependencies(
            &json!({"dependencies":{"declared":[{"name":"provider","source_pin":null}]}}),
            &[path]
        )
        .is_ok());
    }

    #[test]
    fn captured_unit_text_cannot_collide_with_a_dependency_private_scope() {
        let private_module = |export: &str| {
            let mut ir: Value = serde_json::from_slice(&module("helper", true)).unwrap();
            ir["types"]
                .as_array_mut()
                .unwrap()
                .push(json!({"kind":"pointer","address_space":0}));
            ir["functions"][0]["linkage"] = json!("private");
            let mut caller = ir["functions"][0].clone();
            caller["name"] = json!(export);
            caller["linkage"] = json!("external");
            caller["blocks"][0]["instructions"] = json!([{"result":null,"operation":{
                "op":"call","callee":{"kind":"symbol","ty":1,"name":"helper"},
                "signature":{"params":[],"result":0,"abi":"c","variadic":false},"args":[]}}]);
            ir["functions"].as_array_mut().unwrap().push(caller);
            ir["provenance"]["source_function_count"] = json!(2);
            NativeModule::from_json(&serde_json::to_vec(&ir).unwrap()).unwrap()
        };
        let dependency_id = module_identity("provider", "unit");
        let captured_id = module_identity("consumer", &dependency_id);
        let mut all = symbols(&captured_id, &private_module("consumer_entry")).unwrap();
        all.extend(symbols(&dependency_id, &private_module("provider_entry")).unwrap());
        let (inventory, issues) = resolve_symbols(&all);
        assert!(issues.is_empty(), "{issues:?}");
        let references = inventory["definition_references"].as_array().unwrap();
        for (export, expected) in [
            ("consumer_entry", captured_id),
            ("provider_entry", dependency_id),
        ] {
            let reference = references
                .iter()
                .find(|reference| reference["definition"] == export)
                .unwrap();
            assert_eq!(reference["resolved_unit"], expected);
        }
    }

    #[test]
    fn standalone_package_rejects_retargeting_and_import_overrides_before_emission() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("portable.native-ir.json");
        let bytes = serde_json::to_vec(&package("provider")).unwrap();
        fs::write(&path, &bytes).unwrap();
        let output = directory.path().join("must-not-exist");
        for (target, atomic_profile) in [("aarch64", None), ("x86_64", Some("coherent-ram-v1"))] {
            assert!(compile_with_compiler(
                &path,
                target,
                "ir",
                &output,
                NativeImportOptions {
                    llvm_library: None,
                    llvm_sha256: None,
                    tls_profile: None,
                    atomic_profile,
                    wide_volatile_profile: None,
                    dependencies: &[],
                },
                Path::new("/compiler-must-not-run")
            )
            .is_err());
            assert!(!output.exists());
        }
    }
    #[test]
    fn package_keeps_wide_volatile_profile_and_rejects_removal_from_either_target() {
        let old = package("provider");
        assert!(serde_json::to_value(&old.target)
            .unwrap()
            .get("wide_volatile_profile")
            .is_none());
        let mut module: Value = serde_json::from_slice(&module("provider", true)).unwrap();
        module["target"]["wide_volatile_profile"] = json!("ordinary_ram_split_v1");
        let unit = serde_json::to_vec(&module).unwrap();
        let profiled =
            Artifact::build("provider", &"a".repeat(64), &[("unit".into(), unit)], &[]).unwrap();
        assert!(Artifact::from_bytes(&serde_json::to_vec(&profiled).unwrap()).is_ok());
        let mut missing_header = profiled.clone();
        missing_header.target.wide_volatile_profile = None;
        assert!(Artifact::from_bytes(&serde_json::to_vec(&missing_header).unwrap()).is_err());
        let mut missing_module = profiled.clone();
        let mut ir: Value = serde_json::from_str(&missing_module.modules[0].native_ir).unwrap();
        ir["target"]
            .as_object_mut()
            .unwrap()
            .remove("wide_volatile_profile");
        missing_module.modules[0].native_ir = ir.to_string();
        missing_module.modules[0].sha256 = digest(missing_module.modules[0].native_ir.as_bytes());
        assert!(Artifact::from_bytes(&serde_json::to_vec(&missing_module).unwrap()).is_err());
        let mut unknown = serde_json::to_value(&profiled).unwrap();
        unknown["target"]["wide_volatile_profile"] = json!("ordinary_mmio");
        assert!(Artifact::from_bytes(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }
    fn effectful_module(unused: bool) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(&module("provider", true)).unwrap();
        if unused {
            let mut declaration = value["functions"][0].clone();
            declaration["name"] = json!("unused_checkpoint");
            declaration["entry"] = Value::Null;
            declaration["blocks"] = json!([]);
            declaration["control_effects"] = json!({"returns_twice":true});
            value["functions"].as_array_mut().unwrap().push(declaration);
            value["provenance"]["source_function_count"] = json!(2);
        } else {
            value["functions"][0]["control_effects"] = json!({"returns_twice":true});
        }
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn nonlocal_effects_never_enter_symbol_closure_or_artifact_construction() {
        for unused in [false, true] {
            let bytes = effectful_module(unused);
            let parsed = NativeModule::from_json(&bytes).unwrap();
            assert!(parsed.has_nonlocal_control_effects());
            assert!(symbols("unit", &parsed)
                .unwrap_err()
                .to_string()
                .contains("returns_twice symbol closure"));
            assert!(
                Artifact::build("provider", &"a".repeat(64), &[("unit".into(), bytes)], &[])
                    .is_err()
            );
        }
    }

    #[test]
    fn nonlocal_effects_are_rejected_by_public_read_even_with_recomputed_hashes() {
        for unused in [false, true] {
            let mut candidate = package("provider");
            let bytes = effectful_module(unused);
            candidate.modules[0].sha256 = digest(&bytes);
            candidate.modules[0].native_ir = String::from_utf8(bytes).unwrap();
            let error = Artifact::from_bytes(&serde_json::to_vec(&candidate).unwrap()).unwrap_err();
            assert!(error
                .to_string()
                .contains("returns_twice module-set admission"));
        }
    }
}
