//! Authored structural controls for the V5 compound-membership contract.
//! These use real package readers and real selected-policy files. They do not
//! claim original-provider production, native linking, or runtime qualification.
use super::*;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

const COMPOUND_LABEL: &str = "zlib-bzip2-xz";
const ROOT: &str = "root";
const MEMBERS: [(&str, &str); 3] = [
    ("original-zlib", "zlib"),
    ("original-bzip2", "bzip2"),
    ("original-xz", "xz"),
];
static NEXT_POLICY: AtomicU64 = AtomicU64::new(0);

type RecipePolicy = BTreeMap<
    String,
    (String, BTreeMap<String, String>, provider_membership::CompoundBindings),
>;

struct PolicyFile {
    directory: PathBuf,
    raw: Vec<u8>,
    pin: provider_order::OrderPin,
}
impl PolicyFile {
    fn new(policy: &Value) -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let sequence = NEXT_POLICY.fetch_add(1, Ordering::Relaxed);
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = base.join(format!(
            "ostadix-whole-compound-{}-{epoch}-{sequence}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        let path = directory.join("selected-membership.json");
        let raw = serde_json::to_vec(policy).unwrap();
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&raw).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(fs::read(&path).unwrap(), raw);
        let pin = provider_order::OrderPin {
            path,
            bytes: raw.len() as u64,
            sha256: digest(&raw),
        };
        Self { directory, raw, pin }
    }
}
impl Drop for PolicyFile {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn reject<T>(result: anyhow::Result<T>, reason: &str) {
    match result {
        Ok(_) => panic!("expected refusal containing {reason:?}"),
        Err(error) => {
            let actual = format!("{error:#}");
            assert!(actual.contains(reason), "expected {reason:?}, got {actual}");
        }
    }
}

fn original_source(components: &[SourceComponent], name: &str) -> Value {
    let component = components.iter().find(|c| c.name == name).unwrap();
    let recipe: Value = serde_json::from_str(&component.recipe_json).unwrap();
    recipe["source"].clone()
}

fn components_and_modules() -> (Vec<SourceComponent>, Vec<artifact::GroupComponent>) {
    // The third compound member supplies root's declared reference. Together
    // the four unchanged authored native bodies form a legitimate cycle.
    let (mut root, mut root_modules) = super::component(ROOT, "xz");
    let (mut zlib, mut zlib_modules) = super::component("zlib", "bzip2");
    let (mut bzip2, mut bzip2_modules) = super::component("bzip2", ROOT);
    let (mut xz, mut xz_modules) = super::component("xz", "zlib");
    for component in [&mut root, &mut zlib, &mut bzip2, &mut xz] {
        let mut recipe: Value = serde_json::from_str(&component.recipe_json).unwrap();
        recipe["source"] = json!({"revision": format!("authored-{}", component.name)});
        if component.name == ROOT {
            recipe["dependencies"] = json!([{"name": COMPOUND_LABEL}]);
        }
        component.recipe_json = serde_json::to_string(&recipe).unwrap();
        component.recipe_sha256 = digest(component.recipe_json.as_bytes());
    }
    root.dependencies.clear();
    root.compound_dependencies.insert(
        COMPOUND_LABEL.into(),
        MEMBERS.iter().map(|(member, provider)| ((*member).into(), (*provider).into())).collect(),
    );
    root_modules.dependencies = [&zlib, &bzip2, &xz]
        .into_iter()
        .map(|c| (c.name.clone(), c.capture_sha256.clone()))
        .collect();
    zlib_modules.dependencies = vec![(bzip2.name.clone(), bzip2.capture_sha256.clone())];
    bzip2_modules.dependencies = vec![(root.name.clone(), root.capture_sha256.clone())];
    xz_modules.dependencies = vec![(zlib.name.clone(), zlib.capture_sha256.clone())];
    (
        vec![root, zlib, bzip2, xz],
        vec![root_modules, zlib_modules, bzip2_modules, xz_modules],
    )
}

fn inputs(components: &[SourceComponent]) -> Vec<provider_membership::Input<'_>> {
    components.iter().map(|c| provider_membership::Input {
        name: &c.name,
        recipe: c.recipe_json.as_bytes(),
        dependencies: &c.dependencies,
        compound: &c.compound_dependencies,
    }).collect()
}

fn policy_for(components: &[SourceComponent]) -> Value {
    let entries = components.iter().map(|component| {
        let recipe: Value = serde_json::from_str(&component.recipe_json).unwrap();
        let mut compounds = serde_json::Map::new();
        for (label, bindings) in &component.compound_dependencies {
            let declaration = recipe["dependencies"].as_array().unwrap().iter()
                .find(|d| d["name"].as_str() == Some(label.as_str())).unwrap().clone();
            let members = bindings.iter().map(|(member, provider)| {
                (member.clone(), original_source(components, provider))
            }).collect::<serde_json::Map<String, Value>>();
            compounds.insert(label.clone(), json!({
                "declaration": declaration,
                "members": members,
            }));
        }
        json!({
            "component": component.name,
            "recipe": {
                "bytes": component.recipe_json.len(),
                "sha256": component.recipe_sha256,
            },
            "compound_dependencies": compounds,
        })
    }).collect::<Vec<_>>();
    json!({"schema": "ocore-original-provider-membership-v1", "components": entries})
}

fn root_policy(policy: &mut Value) -> &mut Value {
    policy["components"].as_array_mut().unwrap().iter_mut()
        .find(|c| c["component"] == ROOT).unwrap()
}

fn component_value<'a>(group: &'a mut Value, name: &str) -> &'a mut Value {
    group["components"].as_array_mut().unwrap().iter_mut()
        .find(|c| c["name"] == name).unwrap()
}

fn recipes(group: &SourceGroup) -> RecipePolicy {
    group.components.iter().map(|c| (
        c.name.clone(),
        (c.recipe_sha256.clone(), c.dependencies.clone(), c.compound_dependencies.clone()),
    )).collect()
}

struct CompoundFixture {
    policy: PolicyFile,
    selected: provider_membership::SelectedMembership,
    group: SourceGroup,
}
fn compound_fixture() -> CompoundFixture {
    let (components, modules) = components_and_modules();
    let policy = PolicyFile::new(&policy_for(&components));
    let selected = provider_membership::SelectedMembership::read(&policy.pin, &inputs(&components)).unwrap();
    let module_set = artifact::Artifact::build_group(ROOT, &modules).unwrap();
    let group = SourceGroup::new_v5(
        ROOT, "d".repeat(64), module_set, components, None, selected.package(),
    ).unwrap();
    group.check_selected_policy_v5(
        ROOT, &"d".repeat(64), &recipes(&group), None, Some(&selected),
    ).unwrap();
    CompoundFixture { policy, selected, group }
}

#[test]
fn compound_three_original_members_construct_roundtrip_and_reselect() {
    let fixture = compound_fixture();
    assert_eq!(fixture.group.format, FORMAT_V5);
    assert_eq!(fixture.group.components.len(), 4);
    assert_eq!(fixture.group.module_set.modules.len(), 4);
    let root = fixture.group.components.iter().find(|c| c.name == ROOT).unwrap();
    assert!(root.dependencies.is_empty());
    assert_eq!(root.compound_dependencies[COMPOUND_LABEL].len(), 3);
    let sources = fixture.group.components.iter().map(|c| {
        serde_json::to_string(&original_source(&fixture.group.components, &c.name)).unwrap()
    }).collect::<BTreeSet<_>>();
    assert_eq!(sources.len(), 4, "all original source descriptors must be distinct");
    let root_ir = String::from_utf8(hex::decode(&root.units[0].original_ir_hex).unwrap()).unwrap();
    assert!(root_ir.contains("declare void @xz()"));
    let third = fixture.group.components.iter().find(|c| c.name == "xz").unwrap();
    let third_ir = String::from_utf8(hex::decode(&third.units[0].original_ir_hex).unwrap()).unwrap();
    assert!(third_ir.contains("define void @xz()"));
    let raw = serde_json::to_vec(&fixture.group).unwrap();
    let detached = SourceGroup::from_bytes(&raw).unwrap();
    let selected = detached.select_membership(&fixture.policy.pin).unwrap();
    detached.check_selected_policy_v5(
        ROOT, &"d".repeat(64), &recipes(&detached), None, Some(&selected),
    ).unwrap();
    assert_eq!(fs::read(&fixture.policy.pin.path).unwrap(), fixture.policy.raw);
}

#[test]
fn compound_each_original_member_omission_reaches_membership_guard() {
    let fixture = compound_fixture();
    for (member, provider) in MEMBERS {
        let mut components: Vec<SourceComponent> = serde_json::from_slice(
            &serde_json::to_vec(&fixture.group.components).unwrap(),
        ).unwrap();
        let root = components.iter_mut().find(|c| c.name == ROOT).unwrap();
        let members = root.compound_dependencies.get_mut(COMPOUND_LABEL).unwrap();
        assert_eq!(members.remove(member).as_deref(), Some(provider));
        assert_eq!(members.len(), 2);
        assert!(!members.contains_key(member));
        reject(provider_membership::SelectedMembership::read(
            &fixture.policy.pin, &inputs(&components),
        ), "compound member set differs: root/zlib-bzip2-xz");
        let modules = artifact::Artifact::from_bytes(
            &serde_json::to_vec(&fixture.group.module_set).unwrap(),
        ).unwrap();
        reject(SourceGroup::new_v5(
            ROOT, "d".repeat(64), modules, components, None, fixture.selected.package(),
        ), "compound member set differs: root/zlib-bzip2-xz");
    }
}

#[test]
fn compound_external_policy_extra_member_reaches_exact_set_guard() {
    let fixture = compound_fixture();
    let mut policy: Value = serde_json::from_slice(&fixture.policy.raw).unwrap();
    let members = root_policy(&mut policy)["compound_dependencies"][COMPOUND_LABEL]["members"]
        .as_object_mut().unwrap();
    assert!(members.insert("unselected-extra-original".into(),
        json!({"revision": "authored-extra-original"})).is_none());
    assert_eq!(members.len(), 4);
    assert!(members.contains_key("unselected-extra-original"));
    let changed = PolicyFile::new(&policy);
    reject(fixture.group.select_membership(&changed.pin),
        "compound member set differs: root/zlib-bzip2-xz");
}

#[test]
fn compound_unknown_member_provider_reaches_component_guard() {
    let fixture = compound_fixture();
    let mut value = serde_json::to_value(&fixture.group).unwrap();
    let bindings = component_value(&mut value, ROOT)["compound_dependencies"][COMPOUND_LABEL]
        .as_object_mut().unwrap();
    assert!(bindings.insert("unselected-extra-original".into(), json!("unknown-component")).is_none());
    assert_eq!(bindings["unselected-extra-original"], "unknown-component");
    assert_eq!(bindings.len(), 4);
    reject(SourceGroup::from_bytes(&serde_json::to_vec(&value).unwrap()),
        "membership binding names unknown provider component");
}

#[test]
fn compound_wrong_original_source_reaches_source_binding_guard() {
    let fixture = compound_fixture();
    let mut policy: Value = serde_json::from_slice(&fixture.policy.raw).unwrap();
    let original = root_policy(&mut policy)["compound_dependencies"][COMPOUND_LABEL]["members"]
        ["original-zlib"].clone();
    let wrong = original_source(&fixture.group.components, "xz");
    assert_ne!(original, wrong);
    root_policy(&mut policy)["compound_dependencies"][COMPOUND_LABEL]["members"]
        ["original-zlib"] = wrong.clone();
    assert_eq!(root_policy(&mut policy)["compound_dependencies"][COMPOUND_LABEL]["members"]
        ["original-zlib"], wrong);
    let changed = PolicyFile::new(&policy);
    reject(fixture.group.select_membership(&changed.pin),
        "compound member source differs: root/zlib-bzip2-xz/original-zlib");
}

#[test]
fn compound_internally_consistent_package_forgery_fails_held_external_policy() {
    let fixture = compound_fixture();
    let mut value = serde_json::to_value(&fixture.group).unwrap();
    let root = component_value(&mut value, ROOT);
    assert_eq!(root["compound_dependencies"][COMPOUND_LABEL]["original-zlib"], "zlib");
    assert_eq!(root["compound_dependencies"][COMPOUND_LABEL]["original-bzip2"], "bzip2");
    root["compound_dependencies"][COMPOUND_LABEL]["original-zlib"] = json!("bzip2");
    root["compound_dependencies"][COMPOUND_LABEL]["original-bzip2"] = json!("zlib");
    assert_eq!(root["compound_dependencies"][COMPOUND_LABEL]["original-zlib"], "bzip2");
    assert_eq!(root["compound_dependencies"][COMPOUND_LABEL]["original-bzip2"], "zlib");
    let mut policy: Value = serde_json::from_str(
        value["original_membership"]["policy_raw"].as_str().unwrap(),
    ).unwrap();
    root_policy(&mut policy)["compound_dependencies"][COMPOUND_LABEL]["members"]
        ["original-zlib"] = original_source(&fixture.group.components, "bzip2");
    root_policy(&mut policy)["compound_dependencies"][COMPOUND_LABEL]["members"]
        ["original-bzip2"] = original_source(&fixture.group.components, "zlib");
    assert_eq!(root_policy(&mut policy)["compound_dependencies"][COMPOUND_LABEL]["members"]
        ["original-zlib"], original_source(&fixture.group.components, "bzip2"));
    assert_eq!(root_policy(&mut policy)["compound_dependencies"][COMPOUND_LABEL]["members"]
        ["original-bzip2"], original_source(&fixture.group.components, "zlib"));
    let forged_raw = serde_json::to_string(&policy).unwrap();
    assert_ne!(forged_raw.as_bytes(), fixture.policy.raw.as_slice());
    let forged_sha = digest(forged_raw.as_bytes());
    value["original_membership"]["policy_raw"] = json!(forged_raw);
    value["original_membership"]["policy_sha256"] = json!(forged_sha.clone());
    value["original_membership"]["policy_pin"]["sha256"] = json!(forged_sha);
    value["original_membership"]["policy_pin"]["bytes"] =
        json!(value["original_membership"]["policy_raw"].as_str().unwrap().len());
    assert_eq!(value["original_membership"]["policy_pin"]["path"],
        serde_json::to_value(&fixture.policy.pin.path).unwrap());
    let forged = SourceGroup::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
    let forged_root = forged.components.iter().find(|c| c.name == ROOT).unwrap();
    assert_eq!(forged_root.compound_dependencies[COMPOUND_LABEL]["original-zlib"], "bzip2");
    assert_eq!(forged_root.compound_dependencies[COMPOUND_LABEL]["original-bzip2"], "zlib");
    // Even a recipe-policy map selected to match the forged package does not
    // replace the independently held original raw membership capability.
    reject(forged.check_selected_policy_v5(
        ROOT, &"d".repeat(64), &recipes(&forged), None, Some(&fixture.selected),
    ), "external membership policy pin/raw differs");
    reject(forged.select_membership(&fixture.policy.pin),
        "compound member source differs: root/zlib-bzip2-xz/original-bzip2");
    assert_eq!(fs::read(&fixture.policy.pin.path).unwrap(), fixture.policy.raw);
}

#[test]
fn compound_legacy_v1_v3_reject_explicit_empty_new_fields_at_reader_boundary() {
    let legacy = super::group();
    let raw = serde_json::to_vec(&legacy).unwrap();
    SourceGroup::from_bytes(&raw).unwrap();
    for format in [FORMAT, FORMAT_V3] {
        for field in ["original_membership", "compound_dependencies"] {
            let mut value: Value = serde_json::from_slice(&raw).unwrap();
            value["format"] = json!(format);
            if field == "original_membership" {
                assert!(value.get(field).is_none());
                value[field] = Value::Null;
                assert!(value.get(field).is_some());
                assert!(value[field].is_null());
            } else {
                let component = value["components"].as_array_mut().unwrap().first_mut().unwrap();
                assert!(component.get(field).is_none());
                component[field] = json!({});
                assert!(component.get(field).is_some());
                assert!(component[field].as_object().unwrap().is_empty());
            }
            // V3 here is a raw schema envelope: this assertion specifically
            // requires the new-field guard before V3's separate order guard.
            reject(SourceGroup::from_bytes(&serde_json::to_vec(&value).unwrap()),
                "legacy source group cannot carry compound membership fields");
        }
    }
}

#[test]
fn compound_third_original_unit_omission_reaches_full_selection_guard() {
    let fixture = compound_fixture();
    let mut value = serde_json::to_value(&fixture.group).unwrap();
    let third = component_value(&mut value, "xz");
    assert_eq!(third["units"].as_array().unwrap().len(), 1);
    let original_capture: Value = serde_json::from_str(third["capture_json"].as_str().unwrap()).unwrap();
    assert_eq!(original_capture["lowering_unit_ids"], json!(["u"]));
    third["units"] = json!([]);
    assert!(third["units"].as_array().unwrap().is_empty());
    assert_eq!(value["module_set"]["modules"].as_array().unwrap().len(), 4);
    reject(SourceGroup::from_bytes(&serde_json::to_vec(&value).unwrap()),
        "source group omitted selected original units");
}

#[test]
fn compound_legacy_compile_wrapper_requires_selection_before_tools_for_ir_and_obj() {
    let fixture = compound_fixture();
    let raw = serde_json::to_vec(&fixture.group).unwrap();
    let compiler = fixture.policy.directory.join("absent-compiler");
    let python = provider_group::Pin {
        path: fixture.policy.directory.join("absent-python"), sha256: "0".repeat(64),
    };
    let library = provider_group::Pin {
        path: fixture.policy.directory.join("absent-library"), sha256: "0".repeat(64),
    };
    for kind in ["ir", "obj"] {
        let output = fixture.policy.directory.join(format!("uncreated-{kind}"));
        assert!(!output.exists() && !compiler.exists() && !python.path.exists() && !library.path.exists());
        reject(compile_package_selected(
            &raw, "x86_64-unknown-none", kind, &output, &compiler, &python, &library,
            NativeImportOptions {
                llvm_library: None, llvm_sha256: None, tls_profile: None,
                atomic_profile: None, wide_volatile_profile: None, linux_syscall_profile: None, dependencies: &[],
            },
            None,
        ), "separately selected membership policy required");
        assert!(!output.exists() && !compiler.exists() && !python.path.exists() && !library.path.exists());
    }
}
