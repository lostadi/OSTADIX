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
        NativeModule::from_json(self.native_ir.as_bytes()).map_err(|error| {
            anyhow::anyhow!(
                "embedded native module {}: {}",
                self.identity(),
                error.message
            )
        })
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
        let artifact: Self = serde_json::from_slice(bytes).context("decode native module-set")?;
        let inventory = artifact.inventory()?;
        if artifact.symbol_inventory != inventory {
            bail!(
                "native module-set symbol inventory differs from independently recomputed closure"
            );
        }
        Ok(artifact)
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
            "unit_id":embedded.unit_id,"verified":true,"lowered":false});
        let result = (|| -> Result<()> {
            let module = embedded.verify()?;
            let directory = output.join(format!("unit-{index:06}"));
            fs::create_dir(&directory)?;
            let imported = directory.join("module.native-ir.json");
            fs::write(&imported, embedded.native_ir.as_bytes())?;
            record["module"] = json!({"path":imported,"sha256":embedded.sha256});
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
        "output_kind":output_kind,"compiler_sha256":compiler_sha256,
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
        for case in 0..9 {
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
                    dependencies: &[],
                },
                Path::new("/compiler-must-not-run")
            )
            .is_err());
            assert!(!output.exists());
        }
    }
}
