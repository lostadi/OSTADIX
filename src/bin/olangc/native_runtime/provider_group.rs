//! Source-backed group orchestration. A plan selects original recipes and pinned
//! tools; it cannot supply an engine executable, prebuilt object, or a claimed
//! admission result. Source-library cycles are finalized after all builds stage.
use super::*;
use serde::{Deserialize, Serialize};

const PLAN_FORMAT: &str = "ocore-native-provider-plan-v1";
const INVENTORY: &str = include_str!("source_inventory.py");
const INVENTORY_DRIVER: &str = r#"import hashlib,json,pathlib,sys
helper,expected,library,library_sha,original,native,output,python_sha=sys.argv[1:]
interpreter=pathlib.Path("/proc/self/exe").read_bytes()
assert hashlib.sha256(interpreter).hexdigest()==python_sha, "actual running Python image differs"
paths=[pathlib.Path(x) for x in (helper,library,original,native)]
before=[p.read_bytes() for p in paths]
assert hashlib.sha256(before[0]).hexdigest()==expected, 'embedded source inventory helper changed'
assert hashlib.sha256(before[1]).hexdigest()==library_sha, 'LLVM parser changed'
namespace={'__name__':'ocore_embedded_source_inventory','__file__':helper}
exec(compile(before[0],helper,'exec'),namespace)
reader=namespace['Reader'](library,library_sha)
source=reader.read(original)
receipt=namespace['check_inventory'](source,json.loads(before[3]))
receipt['interpreter']={'invoked_path':sys.executable,'running_image':'/proc/self/exe','sha256':hashlib.sha256(interpreter).hexdigest()}

assert all(p.read_bytes()==b for p,b in zip(paths,before)), 'inventory input/tool changed'
pathlib.Path(output).write_text(json.dumps(receipt,sort_keys=True))
"#;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pin {
    pub(super) path: PathBuf,
    pub(super) sha256: String,
}
impl Pin {
    pub(super) fn checked(&self) -> Result<Vec<u8>> {
        if !self.path.is_absolute() || !self.path.canonicalize()?.is_file() {
            bail!("provider plan file paths must be absolute and resolve to regular files");
        }
        let bytes = fs::read(&self.path)?;
        if digest(&bytes) != self.sha256 {
            bail!("provider plan file pin differs: {}", self.path.display());
        }
        Ok(bytes)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tools {
    python: Pin,
    llvm_library: Pin,
    cc: Pin,
    cxx: Pin,
    rustc: Pin,
    cargo: Pin,
    llvm_nm: Pin,
    llvm_dis: Pin,
    compiler_sha256: String,
}
impl Tools {
    fn pins(&self) -> [&Pin; 8] {
        [
            &self.python,
            &self.llvm_library,
            &self.cc,
            &self.cxx,
            &self.rustc,
            &self.cargo,
            &self.llvm_nm,
            &self.llvm_dis,
        ]
    }
    fn check(&self, compiler: &Path) -> Result<()> {
        for pin in self.pins() {
            pin.checked()?;
        }
        if digest(&fs::read(compiler)?) != self.compiler_sha256 {
            bail!("provider plan O-core compiler pin differs");
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceNode {
    id: String,
    recipe: Pin,
    source: PathBuf,
    /// Map each original declared dependency label to a source node. A logical
    /// OS capability is not satisfied by naming an arbitrary library here.
    dependencies: BTreeMap<String, String>,
    #[serde(default)]
    unit_inventory: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    root: String,
    tools: Tools,
    components: Vec<SourceNode>,
}

pub(super) fn inventory(
    python: &Pin,
    library: &Pin,
    original: &[u8],
    native: &[u8],
    output: &Path,
) -> Result<Value> {
    python.checked()?;
    library.checked()?;
    // A fresh private directory keeps every attempted check and its exact input
    // buffers. Neither Python module search nor a mutable tests tree is used.
    fs::create_dir(output)?;
    let helper = output.join("source_inventory.py");
    let input = output.join("original.ll");
    let module = output.join("module.native-ir.json");
    let result = output.join("inventory.json");
    fs::write(&helper, INVENTORY)?;
    fs::write(&input, original)?;
    fs::write(&module, native)?;
    let args = vec![
        "-I".into(),
        "-c".into(),
        INVENTORY_DRIVER.into(),
        helper.display().to_string(),
        digest(INVENTORY.as_bytes()),
        library.path.display().to_string(),
        library.sha256.clone(),
        input.display().to_string(),
        module.display().to_string(),
        result.display().to_string(),
        python.sha256.clone(),
    ];
    let actual = Command::new(&python.path)
        .args(&args)
        .output()
        .context("run embedded independent source inventory")?;
    fs::write(output.join("stdout.log"), &actual.stdout)?;
    fs::write(output.join("stderr.log"), &actual.stderr)?;
    let process = json!({"program":python.path,"program_sha256":python.sha256,"argv":args,
        "exit_code":actual.status.code(),"success":actual.status.success(),
        "python":python,"llvm_library":library,"helper_sha256":digest(INVENTORY.as_bytes()),
        "original_sha256":digest(original),"native_sha256":digest(native)});
    fs::write(
        output.join("process.json"),
        serde_json::to_vec_pretty(&process)?,
    )?;
    python.checked()?;
    library.checked()?;
    if fs::read(&helper)? != INVENTORY.as_bytes()
        || fs::read(&input)? != original
        || fs::read(&module)? != native
    {
        bail!("independent source inventory buffers changed");
    }
    if !actual.status.success() {
        bail!(
            "independent source inventory failed ({}); see {}",
            actual.status,
            output.display()
        );
    }
    let receipt: Value = serde_json::from_slice(&fs::read(result)?)?;
    if receipt["schema"] != "ocore-independent-source-inventory-v1"
        || receipt["source"]["sha256"] != digest(original)
        || receipt["llvm_library"]["sha256"] != library.sha256
    {
        bail!("independent source inventory receipt identity differs");
    }
    Ok(json!({"process":process,"preservation":receipt,
        "scope":"bounded independent definitions/declarations/globals/initializer and intrinsic-site inventory; not executable equivalence or external provider proof"}))
}

fn preflight(
    plan: &Plan,
    input: &Path,
    recipe_bytes: &[u8],
    source: &Path,
    output: &Path,
    compiler: &Path,
) -> Result<(Vec<Vec<u8>>, PathBuf)> {
    if plan.schema != PLAN_FORMAT || plan.components.is_empty() {
        bail!("unsupported or empty provider plan");
    }
    plan.tools.check(compiler)?;
    let mut names = BTreeSet::new();
    let mut recipes = Vec::new();
    let mut canonical_output = None;
    for node in &plan.components {
        if node.id.is_empty()
            || node.id.trim() != node.id
            || node.id.chars().any(char::is_control)
            || !names.insert(&node.id)
        {
            bail!("duplicate or invalid provider component identity");
        }
        if !node.source.is_absolute()
            || node.source.canonicalize()? != node.source
            || !node.source.is_dir()
        {
            bail!("provider source must be a canonical original checkout directory");
        }
        // Validate every output/source relationship before creating any output.
        canonical_output = Some(source_recipe::new_output(
            output,
            &node.source,
            &node.recipe.path,
        )?);
        let bytes = node.recipe.checked()?;
        let recipe: Value = serde_json::from_slice(&bytes)?;
        if recipe["schema"] != source_recipe::RECIPE_FORMAT {
            bail!("provider component requires an original source recipe");
        }
        if node.unit_inventory.as_ref().is_some_and(|p| {
            p.is_absolute()
                || p.components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
        }) {
            bail!("provider inventory must be relative within its own new build");
        }
        let mut declared = BTreeSet::new();
        for dep in array(&recipe, "dependencies")? {
            if !declared.insert(string(dep, "name")?) {
                bail!("duplicate original dependency");
            }
        }
        // Missing edges remain a measured closure failure after staging. Extra
        // edges are invalid configuration and never authorize extra code.
        if node
            .dependencies
            .keys()
            .any(|name| !declared.contains(name.as_str()))
        {
            bail!("provider plan adds an undeclared source dependency");
        }
        recipes.push(bytes);
    }
    let index = plan
        .components
        .iter()
        .position(|n| n.id == plan.root)
        .context("provider plan root is absent")?;
    if plan.components[index].recipe.path != input.canonicalize()?
        || recipes[index] != recipe_bytes
        || plan.components[index].source != source.canonicalize()?
    {
        bail!("provider plan root differs from the requested original recipe/source");
    }
    if plan
        .components
        .iter()
        .any(|n| n.dependencies.values().any(|name| !names.contains(name)))
    {
        bail!("provider plan edge names a missing source component");
    }
    // Library groups can be cyclic; iterative reachability has no depth limit.
    let by_name: BTreeMap<_, _> = plan.components.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut seen = BTreeSet::new();
    let mut pending = vec![plan.root.as_str()];
    while let Some(name) = pending.pop() {
        if seen.insert(name) {
            pending.extend(by_name[name].dependencies.values().map(String::as_str));
        }
    }
    if seen.len() != names.len() {
        bail!("provider plan contains an unreachable source component");
    }
    Ok((
        recipes,
        canonical_output.context("provider plan has no output")?,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compile(
    plan_path: &Path,
    input: &Path,
    recipe_bytes: &[u8],
    target: &str,
    output_kind: &str,
    output: &Path,
    imports: NativeImportOptions<'_>,
    options: NativeSourceOptions<'_>,
    compiler: &Path,
) -> Result<()> {
    architecture(target)?;
    if !matches!(output_kind, "ir" | "obj") || !imports.dependencies.is_empty() {
        bail!("provider groups require ir/obj output and source-backed plan dependencies");
    }
    let plan_bytes = fs::read(plan_path)?;
    let plan: Plan =
        serde_json::from_slice(&plan_bytes).context("decode pinned provider source plan")?;
    if imports.llvm_library != Some(plan.tools.llvm_library.path.as_path())
        || imports.llvm_sha256 != Some(plan.tools.llvm_library.sha256.as_str())
    {
        bail!("provider plan LLVM parser must match the explicit command-line parser pin");
    }
    for (requested, pin) in [
        (options.cc, &plan.tools.cc),
        (options.cxx, &plan.tools.cxx),
        (options.rustc, &plan.tools.rustc),
        (options.cargo, &plan.tools.cargo),
        (options.llvm_nm, &plan.tools.llvm_nm),
        (options.llvm_dis, &plan.tools.llvm_dis),
    ] {
        if requested.is_some_and(|p| p != pin.path.as_path()) {
            bail!("provider plan tool differs from explicit source option");
        }
    }
    if options.unit_inventory.is_some() {
        bail!("provider group unit inventories belong to each plan component");
    }
    if options.jobs == Some(0) {
        bail!("provider group jobs must be positive");
    }
    let (recipes, output) = preflight(
        &plan,
        input,
        recipe_bytes,
        options
            .source
            .context("provider plan requires original root source")?,
        output,
        compiler,
    )?;
    fs::create_dir(&output)?;
    let output = output.canonicalize()?;
    fs::write(output.join("provider-plan.json"), &plan_bytes)?;
    let mut records = Vec::new();
    let mut staged = BTreeMap::new();
    let mut issues = Vec::new();
    for (index, node) in plan.components.iter().enumerate() {
        let directory = output.join(format!("component-{index:06}"));
        let mut record = json!({"id":node.id,"recipe":node.recipe,"source":node.source,"staged":false,"source_inventory_complete":false});
        let result = (|| -> Result<()> {
            plan.tools.check(compiler)?;
            node.recipe.checked()?;
            let component = source_recipe::stage_for_group(
                &node.recipe.path,
                &recipes[index],
                target,
                &directory,
                NativeImportOptions {
                    llvm_library: Some(&plan.tools.llvm_library.path),
                    llvm_sha256: Some(&plan.tools.llvm_library.sha256),
                    tls_profile: imports.tls_profile,
                    atomic_profile: imports.atomic_profile,
                    wide_volatile_profile: imports.wide_volatile_profile,
                    dependencies: &[],
                },
                NativeSourceOptions {
                    source: Some(&node.source),
                    cc: Some(&plan.tools.cc.path),
                    cxx: Some(&plan.tools.cxx.path),
                    rustc: Some(&plan.tools.rustc.path),
                    cargo: Some(&plan.tools.cargo.path),
                    llvm_nm: Some(&plan.tools.llvm_nm.path),
                    llvm_dis: Some(&plan.tools.llvm_dis.path),
                    unit_inventory: node.unit_inventory.as_deref(),
                    jobs: options.jobs,
                    provider_plan: None,
                },
                compiler,
                &plan.tools.python.path,
            )?;
            record["staged"] =
                json!(component.source_capture_complete && component.unit_lowering_complete);
            record["capture_complete"] = json!(component.source_capture_complete);
            record["unit_lowering_complete"] = json!(component.unit_lowering_complete);
            record["coverage"] = json!(component.coverage_path);
            if !component.source_capture_complete || !component.unit_lowering_complete {
                bail!("original source component staging is incomplete");
            }
            let mut inventories = Vec::new();
            for (ordinal, (id, native)) in component.modules.iter().enumerate() {
                let (_, original) = component
                    .original_inputs
                    .get(id)
                    .context("staged unit has no original input")?;
                inventories.push(json!({"id":id,"evidence":inventory(&plan.tools.python,&plan.tools.llvm_library,original,native,&directory.join(format!("inventory-{ordinal:06}")))?}));
            }
            record["source_inventory_complete"] = json!(true);
            record["source_inventories"] = json!(inventories);
            staged.insert(node.id.clone(), component);
            Ok(())
        })();
        if let Err(error) = result {
            record["failure"] = json!(format!("{error:#}"));
            issues.push(format!("{}: {error:#}", node.id));
        }
        records.push(record);
    }
    let mut package = None;
    if issues.is_empty() {
        let result = (|| -> Result<Value> {
            let mut components = Vec::new();
            let mut evidence = Vec::new();
            for (index, node) in plan.components.iter().enumerate() {
                let component = &staged[&node.id];
                let mut dependencies = Vec::new();
                let recipe: Value = serde_json::from_slice(&recipes[index])?;
                for declared in array(&recipe, "dependencies")? {
                    let label = string(declared, "name")?;
                    let provider = node
                        .dependencies
                        .get(label)
                        .with_context(|| format!("unresolved original dependency {label}"))?;
                    let provider_index = plan
                        .components
                        .iter()
                        .position(|n| &n.id == provider)
                        .context("provider vanished")?;
                    let provider_recipe: Value = serde_json::from_slice(&recipes[provider_index])?;
                    if declared
                        .get("source_pin")
                        .is_some_and(|p| !p.is_null() && p != &provider_recipe["source"])
                    {
                        bail!("original dependency source pin differs for {label}");
                    }
                    dependencies.push((provider.clone(), digest(&staged[provider].capture_bytes)));
                }
                components.push(artifact::GroupComponent {
                    name: node.id.clone(),
                    capture_sha256: digest(&component.capture_bytes),
                    modules: component.modules.clone(),
                    dependencies,
                });
                evidence.push(whole_artifact::SourceComponent::from_stage(
                    &node.id,
                    &recipes[index],
                    &node.dependencies,
                    component,
                )?);
            }
            let module_set = artifact::Artifact::build_group(&plan.root, &components)?;
            let group = whole_artifact::SourceGroup::new(
                &plan.root,
                digest(&plan_bytes),
                module_set,
                evidence,
            )?;
            let bytes = serde_json::to_vec_pretty(&group)?;
            whole_artifact::SourceGroup::from_bytes(&bytes)?;
            let path = output.join(whole_artifact::FILE_NAME);
            fs::write(&path, &bytes)?;
            if fs::read(&path)? != bytes {
                bail!("source group changed during publication");
            }
            Ok(
                json!({"path":path,"sha256":digest(&bytes),"bytes":bytes.len(),"format":whole_artifact::FORMAT}),
            )
        })();
        match result {
            Ok(value) => package = Some(value),
            Err(error) => issues.push(format!("{error:#}")),
        }
    }
    if fs::read(plan_path)? != plan_bytes {
        issues.push("provider plan changed during orchestration".into());
    }
    for (index, node) in plan.components.iter().enumerate() {
        if node.recipe.checked().ok().as_ref() != Some(&recipes[index]) {
            issues.push(format!("original recipe changed: {}", node.id));
        }
    }
    if let Err(error) = plan.tools.check(compiler) {
        issues.push(format!("{error:#}"));
    }
    // Never leave an admitted-looking product if final immutable-input checks fail.
    if !issues.is_empty() {
        if package.is_some() {
            fs::remove_file(output.join(whole_artifact::FILE_NAME))?;
        }
        package = None;
    }
    let ir_complete = issues.is_empty() && package.is_some();
    let mut object_reemission_complete = false;
    if ir_complete && output_kind == "obj" {
        match whole_artifact::compile_package(
            &fs::read(output.join(whole_artifact::FILE_NAME))?,
            target,
            "obj",
            &output.join("objects"),
            compiler,
            &plan.tools.python,
            &plan.tools.llvm_library,
            NativeImportOptions {
                llvm_library: imports.llvm_library,
                llvm_sha256: imports.llvm_sha256,
                tls_profile: imports.tls_profile,
                atomic_profile: imports.atomic_profile,
                wide_volatile_profile: imports.wide_volatile_profile,
                dependencies: &[],
            },
        ) {
            Ok(()) => object_reemission_complete = true,
            Err(error) => issues.push(format!("source-group object re-emission: {error:#}")),
        }
        if let Err(error) = plan.tools.check(compiler) {
            issues.push(format!("{error:#}"));
        }
    }
    let complete = issues.is_empty() && package.is_some();
    let receipt = json!({"schema":"ocore-native-provider-group-v1","plan_sha256":digest(&plan_bytes),"components":records,"issues":issues,
        "source_group_complete":ir_complete,"lowering_complete":complete,"source_group_artifact":package,
        "requested_output_kind":output_kind,"object_reemission_complete":object_reemission_complete,
        "artifact_complete":false,"original_program_graph_complete":false,"platform_resource_closure_complete":false,
        "native_execution_qualified":false,"runtime_complete":false,
        "scope":"original source-library group capture, bounded independent source inventory and verified native IR symbol/ABI closure; no complete program/CRT/platform/resource or runtime qualification"});
    fs::write(
        output.join("provider-group.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    if !complete {
        bail!(
            "provider source group incomplete; see {}",
            output.join("provider-group.json").display()
        );
    }

    Ok(())
}

/// Public group consistency readmission never repeats a foreign build or opens
/// source/capture pathnames from the package. The caller supplies the exact
/// independently selected plan/tool policy; embedded provenance is not authority.
#[allow(clippy::too_many_arguments)]
pub(super) fn read_package(
    input: &Path,
    target: &str,
    kind: &str,
    output: &Path,
    imports: NativeImportOptions<'_>,
    options: NativeSourceOptions<'_>,
    compiler: &Path,
) -> Result<()> {
    let plan_path = options
        .provider_plan
        .context("source-group readmission requires --native-runtime-provider-plan POLICY")?;
    if options.source.is_some()
        || options.cc.is_some()
        || options.cxx.is_some()
        || options.rustc.is_some()
        || options.cargo.is_some()
        || options.llvm_nm.is_some()
        || options.llvm_dis.is_some()
        || options.unit_inventory.is_some()
        || options.jobs.is_some()
    {
        bail!("source-group readmission accepts a pinned policy, not source-build options");
    }
    if imports.tls_profile.is_some()
        || imports.atomic_profile.is_some()
        || imports.wide_volatile_profile.is_some()
    {
        bail!("source groups already bind execution profiles");
    }
    let policy = fs::read(plan_path)?;
    let plan: Plan = serde_json::from_slice(&policy)?;
    if plan.schema != PLAN_FORMAT {
        bail!("unsupported source-group policy");
    }
    let names: BTreeSet<_> = plan.components.iter().map(|n| n.id.as_str()).collect();
    if names.is_empty()
        || names.len() != plan.components.len()
        || !names.contains(plan.root.as_str())
        || plan.components.iter().any(|n| {
            n.dependencies
                .values()
                .any(|id| !names.contains(id.as_str()))
        })
    {
        bail!("invalid source-group policy component graph");
    }
    plan.tools.check(compiler)?;
    if imports.llvm_library != Some(plan.tools.llvm_library.path.as_path())
        || imports.llvm_sha256 != Some(plan.tools.llvm_library.sha256.as_str())
    {
        bail!("source-group parser differs from explicitly selected policy");
    }
    for node in &plan.components {
        source_recipe::new_output(output, &node.source, &node.recipe.path)?;
    }
    let bytes = fs::read(input)?;
    let group = whole_artifact::SourceGroup::from_bytes(&bytes)?;
    group.check_policy(
        &plan.root,
        &digest(&policy),
        &plan
            .components
            .iter()
            .map(|n| {
                (
                    n.id.clone(),
                    (n.recipe.sha256.clone(), n.dependencies.clone()),
                )
            })
            .collect(),
    )?;
    whole_artifact::compile_package(
        &bytes,
        target,
        kind,
        output,
        compiler,
        &plan.tools.python,
        &plan.tools.llvm_library,
        imports,
    )?;
    plan.tools.check(compiler)?;
    if fs::read(input)? != bytes || fs::read(plan_path)? != policy {
        bail!("source group or selected policy changed during readmission");
    }
    Ok(())
}
