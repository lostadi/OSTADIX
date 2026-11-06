//! Authored structural fixtures exercise the real constructor/read path. They
//! do not qualify upstream source builds or executable behavior.
use super::*;

#[test]
fn relocated_readmission_rebinds_only_the_verified_diagnostic_pathname() {
    let captured = NativeModule::from_json(&native("engine", "provider", b"original")).unwrap();
    let staged = Path::new("/trusted/private/original.ll");
    let mut fresh = captured.clone();
    fresh.name = staged.display().to_string();
    let record = compare_relocated_import(fresh.clone(), &captured, staged).unwrap();
    assert_eq!(record["captured"], captured.name);
    assert_eq!(record["fresh"], staged.display().to_string());
    assert_eq!(record["rebound_field"], "name");
    for wrong in ["/different/original.ll", "invented", ""] {
        let mut changed = fresh.clone();
        changed.name = wrong.into();
        assert!(compare_relocated_import(changed, &captured, staged).is_err());
    }
    assert!(compare_relocated_import(fresh.clone(), &captured, Path::new("relative.ll")).is_err());
    let mut changed = fresh.clone();
    changed.functions[0].blocks[0].terminator = o_lang::ocore::native_ir::Terminator::Unreachable;
    assert!(compare_relocated_import(changed, &captured, staged).is_err());
    let mut changed = fresh;
    changed.provenance.input_sha256 = "f".repeat(64);
    assert!(compare_relocated_import(changed, &captured, staged).is_err());
}

#[test]
fn relocated_readmission_keeps_global_initializer_and_profile_contracts_exact() {
    let mut body: Value =
        serde_json::from_slice(&native("engine", "provider", b"original")).unwrap();
    body["types"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind":"int","bits":8}));
    body["globals"] = json!([{"name":"observable","ty":1,"linkage":"external","alignment":1,
        "constant":false,"thread_local":false,"initializer":{"bytes":[7],"relocations":[]}}]);
    body["provenance"]["source_global_count"] = json!(1);
    let captured = NativeModule::from_json(&serde_json::to_vec(&body).unwrap()).unwrap();
    let staged = Path::new("/trusted/private/original.ll");
    let mut fresh = captured.clone();
    fresh.name = staged.display().to_string();
    assert!(compare_relocated_import(fresh.clone(), &captured, staged).is_ok());
    fresh.globals[0].initializer.as_mut().unwrap().bytes[0] = 8;
    assert!(compare_relocated_import(fresh, &captured, staged).is_err());
    let mut fresh = captured.clone();
    fresh.name = staged.display().to_string();
    fresh.target.strict_fp_profile = Some(o_lang::ocore::native_ir::StrictFpProfile::IntegerOnlyV1);
    assert!(compare_relocated_import(fresh, &captured, staged).is_err());
}

fn native(name: &str, reference: &str, input: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&json!({"format":"ocore-native-module-v1","name":name,
        "target":{"triple":"x86_64-unknown-none","data_layout":"e-p:64:64-i64:64","pointer_bits":64,"little_endian":true},
        "semantics":"llvm_defined_behavior_v1","types":[{"kind":"void"}],"globals":[],
        "functions":[{"name":name,"linkage":"external","signature":{"params":[],"result":0,"abi":"c","variadic":false},
            "params":[],"entry":0,"blocks":[{"id":0,"instructions":[],"terminator":{"op":"return","value":null}}]},
            {"name":reference,"linkage":"external","signature":{"params":[],"result":0,"abi":"c","variadic":false},"params":[],"entry":null,"blocks":[]}],
        "provenance":{"input_sha256":digest(input),"frontend":"authored-test","frontend_version":"1","importer":"test","importer_version":"1","source_function_count":2,"source_global_count":0,"refinements":[]}})).unwrap()
}
fn component(name: &str, other: &str) -> (SourceComponent, artifact::GroupComponent) {
    let input=format!("target datalayout = \"e-p:64:64-i64:64\"\ntarget triple = \"x86_64-unknown-none\"\ndefine void @{name}() {{ ret void }}\ndeclare void @{other}()\n").into_bytes();
    let unit = json!({"path":"/authored/original.ll","sha256":digest(&input),"bytes":input.len(),"format":"llvm-text","target_triple":"x86_64-unknown-none","data_layout":"e-p:64:64-i64:64"});
    let floor = json!({"id":"floor","kind":"clang","source":"original.c","role":"runtime"});
    let extra =
        json!({"id":"inventory:original","kind":"clang","source":"original.c","role":"runtime"});
    let inventory =
        json!({"schema":"ocore-runtime-unit-inventory-v1","complete":true,"units":[extra.clone()]});
    let inventory_bytes = serde_json::to_vec(&inventory).unwrap();
    let mut floor_bound = floor.clone();
    let mut extra_bound = extra;
    for rule in [&mut floor_bound, &mut extra_bound] {
        rule["complete"] = json!(true);
        rule["failed_invocation_ids"] = json!([]);
        rule["captured_unit_ids"] = json!(["u"]);
    }
    let capture = json!({"schema":CAPTURE_FORMAT,"name":name,"lowering_unit_ids":["u"],"units":[{"id":"u","ir":unit}],
        "required_units":[floor_bound,extra_bound],"unit_inventory":{"definition":inventory,"file":{"path":"/authored/inventory.json","sha256":digest(&inventory_bytes),"bytes":inventory_bytes.len()}}});
    let recipe = json!({"schema":source_recipe::RECIPE_FORMAT,"name":name,"coverage":{"required_units":[floor]},"source":{"revision":"authored"},"dependencies":[{"name":"other"}]});
    let capture_bytes = serde_json::to_vec(&capture).unwrap();
    let recipe_bytes = serde_json::to_vec(&recipe).unwrap();
    let module = native(name, other, &input);
    (
        SourceComponent {
            name: name.into(),
            recipe_json: String::from_utf8(recipe_bytes.clone()).unwrap(),
            recipe_sha256: digest(&recipe_bytes),
            capture_json: String::from_utf8(capture_bytes.clone()).unwrap(),
            capture_sha256: digest(&capture_bytes),
            inventory_json: String::from_utf8(inventory_bytes).unwrap(),
            dependencies: BTreeMap::from([("other".into(), other.into())]),
            compound_dependencies: BTreeMap::new(),
            units: vec![SourceUnit {
                id: "u".into(),
                original_ir_hex: hex::encode(input),
                input: unit,
            }],
        },
        artifact::GroupComponent {
            name: name.into(),
            capture_sha256: digest(&capture_bytes),
            modules: vec![("u".into(), module)],
            dependencies: Vec::new(),
        },
    )
}
fn group() -> SourceGroup {
    let (a, mut ga) = component("alpha", "beta");
    let (b, mut gb) = component("beta", "alpha");
    ga.dependencies = vec![("beta".into(), b.capture_sha256.clone())];
    gb.dependencies = vec![("alpha".into(), a.capture_sha256.clone())];
    let modules = artifact::Artifact::build_group("alpha", &[ga, gb]).unwrap();
    SourceGroup::new("alpha", "a".repeat(64), modules, vec![a, b]).unwrap()
}
#[test]
fn source_group_constructs_a_closed_mutual_source_library_group() {
    let group = group();
    let bytes = serde_json::to_vec(&group).unwrap();
    let imported = SourceGroup::from_bytes(&bytes).unwrap();
    assert_eq!(imported.module_set.modules.len(), 2);
}
#[test]
fn source_group_preserves_recipe_floor_and_finalized_inventory_additions() {
    let group = group();
    let component = &group.components[0];
    let recipe: Value = serde_json::from_str(&component.recipe_json).unwrap();
    let capture: Value = serde_json::from_str(&component.capture_json).unwrap();
    let finalized: Value = serde_json::from_str(&component.inventory_json).unwrap();
    check_original_selection(&recipe, &finalized, &capture).unwrap();
    let mut omitted = capture.clone();
    omitted["required_units"].as_array_mut().unwrap().pop();
    assert!(check_original_selection(&recipe, &finalized, &omitted).is_err());
    let mut omitted = capture;
    omitted["required_units"][0]["captured_unit_ids"] = json!([]);
    assert!(check_original_selection(&recipe, &finalized, &omitted).is_err());
}
#[test]
fn source_group_rejects_partial_units_and_changed_finalized_inventory() {
    for case in 0..3 {
        let mut value = serde_json::to_value(group()).unwrap();
        match case {
            0 => value["components"][0]["units"] = json!([]),
            1 => value["components"][0]["inventory_json"] = json!("{}"),
            _ => {
                value["module_set"]["modules"].as_array_mut().unwrap().pop();
            }
        }
        assert!(
            SourceGroup::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn source_group_rejects_changed_source_edges_and_target_profiles() {
    for case in 0..3 {
        let mut value = serde_json::to_value(group()).unwrap();
        match case {
            0 => value["components"][0]["dependencies"]["other"] = json!("alpha"),
            1 => value["module_set"]["components"][0]["dependencies"] = json!([]),
            _ => value["module_set"]["target"]["abi"] = json!("lp64d"),
        }
        assert!(
            SourceGroup::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn source_group_requires_independently_selected_recipe_policy() {
    let group = group();
    let recipes = group
        .components
        .iter()
        .map(|c| {
            (
                c.name.clone(),
                (c.recipe_sha256.clone(), c.dependencies.clone()),
            )
        })
        .collect();
    group
        .check_policy("alpha", &"a".repeat(64), &recipes)
        .unwrap();
    assert!(group
        .check_policy("beta", &"a".repeat(64), &recipes)
        .is_err());
    assert!(group
        .check_policy("alpha", &"b".repeat(64), &recipes)
        .is_err());
    assert!(group
        .check_policy("alpha", &"a".repeat(64), &BTreeMap::new())
        .is_err());
}
#[test]
fn source_group_cannot_admit_opaque_executables_or_claimed_completion_flags() {
    assert!(SourceGroup::from_bytes(b"\x7fELFopaque engine").is_err());
    let mut value = serde_json::to_value(group()).unwrap();
    value["runtime_complete"] = json!(true);
    assert!(SourceGroup::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn source_group_preserves_compatible_repeated_requirement_records() {
    let group = group();
    let component = &group.components[0];
    let recipe: Value = serde_json::from_str(&component.recipe_json).unwrap();
    let mut finalized: Value = serde_json::from_str(&component.inventory_json).unwrap();
    let mut capture: Value = serde_json::from_str(&component.capture_json).unwrap();
    finalized["units"][0]["id"] = json!("floor");
    finalized["units"][0]["build_step"] = json!("compile");
    capture["required_units"][1]["id"] = json!("floor");
    capture["required_units"][1]["build_step"] = json!("compile");
    check_original_selection(&recipe, &finalized, &capture).unwrap();
    let mut omitted = capture.clone();
    omitted["required_units"].as_array_mut().unwrap().pop();
    assert!(check_original_selection(&recipe, &finalized, &omitted).is_err());
    let mut changed = capture;
    changed["required_units"][1]["build_step"] = json!("other");
    assert!(check_original_selection(&recipe, &finalized, &changed).is_err());
}

#[test]
fn source_group_rejects_contradictory_repeated_requirement_conditions() {
    let group = group();
    let component = &group.components[0];
    let recipe: Value = serde_json::from_str(&component.recipe_json).unwrap();
    let mut finalized: Value = serde_json::from_str(&component.inventory_json).unwrap();
    let mut capture: Value = serde_json::from_str(&component.capture_json).unwrap();
    finalized["units"][0]["id"] = json!("floor");
    finalized["units"][0]["source"] = json!("contradictory.c");
    capture["required_units"][1]["id"] = json!("floor");
    capture["required_units"][1]["source"] = json!("contradictory.c");
    assert!(check_original_selection(&recipe, &finalized, &capture)
        .unwrap_err()
        .to_string()
        .contains("ambiguous original source requirement"));
}

#[test]
fn source_group_deduplicates_physical_edges_without_dropping_labels_or_pins() {
    let (mut a, mut ga) = component("alpha", "beta");
    let (b, mut gb) = component("beta", "alpha");
    let provider_recipe: Value = serde_json::from_str(&b.recipe_json).unwrap();
    let mut recipe: Value = serde_json::from_str(&a.recipe_json).unwrap();
    recipe["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"other-alias","source_pin":provider_recipe["source"]}));
    a.recipe_json = serde_json::to_string(&recipe).unwrap();
    a.recipe_sha256 = digest(a.recipe_json.as_bytes());
    a.dependencies.insert("other-alias".into(), "beta".into());
    ga.capture_sha256 = a.capture_sha256.clone();
    ga.dependencies = vec![("beta".into(), b.capture_sha256.clone()); 2];
    gb.dependencies = vec![("alpha".into(), a.capture_sha256.clone())];
    let modules = artifact::Artifact::build_group("alpha", &[ga, gb]).unwrap();
    let group = SourceGroup::new("alpha", "a".repeat(64), modules, vec![a, b]).unwrap();
    assert_eq!(group.components[0].dependencies.len(), 2);
    let value = serde_json::to_value(&group).unwrap();
    assert_eq!(
        value["module_set"]["components"][0]["dependencies"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let mut wrong_pin = group;
    let component = &mut wrong_pin.components[0];
    let mut recipe: Value = serde_json::from_str(&component.recipe_json).unwrap();
    recipe["dependencies"][1]["source_pin"] = json!({"revision":"wrong"});
    component.recipe_json = serde_json::to_string(&recipe).unwrap();
    component.recipe_sha256 = digest(component.recipe_json.as_bytes());
    assert!(SourceGroup::from_bytes(&serde_json::to_vec(&wrong_pin).unwrap()).is_err());
    let (_, mut a) = self::component("alpha", "beta");
    let (_, b) = self::component("beta", "alpha");
    a.dependencies = vec![
        ("beta".into(), b.capture_sha256.clone()),
        ("beta".into(), "f".repeat(64)),
    ];
    assert!(artifact::Artifact::build_group("alpha", &[a, b]).is_err());
}

#[path = "whole_artifact_compound_tests.rs"]
mod compound;
