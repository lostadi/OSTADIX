//! Authored metadata/consistency controls of the actual production v2 bridge.
//! No original compiler/capture/native object admission. Explicit Python required.
use super::*;
use std::sync::OnceLock;
fn artifact(path: String, bytes: u64, nibble: &str) -> Value {
    json!({"path":path,"bytes":bytes,"sha256":nibble.repeat(64)})
}
fn native_capture(fresh: bool) -> Vec<u8> {
    let root = if fresh { "/fresh" } else { "/old" };
    let invocation = if fresh {
        "new-action"
    } else {
        "original-action"
    };
    let source = artifact(format!("{root}/source/lib.rs"), 24, "1");
    let mut output = artifact(format!("{root}/build/libengine.a"), 512, "9");
    output["artifact_kind"] = json!("archive");
    let argv = json!([
        "/tool/rustc",
        "--crate-name",
        "engine",
        source["path"],
        "-o",
        output["path"]
    ]);
    let mut executed = argv.as_array().unwrap().clone();
    executed.extend([json!("-C"), json!("embed-bitcode=yes")]);
    let mut records = Vec::new();
    let mut units = Vec::new();
    for index in 0..2usize {
        let bitcode = artifact(
            format!("{root}/capture/cgu-{index}.bc"),
            8,
            if index == 0 { "5" } else { "6" },
        );
        let object = artifact(
            format!("{root}/capture/cgu-{index}.o"),
            64,
            if index == 0 { "7" } else { "8" },
        );
        let name = if index == 0 {
            "engine.main.rcgu.o"
        } else {
            "engine.cold.rcgu.o"
        };
        let offset = 68 + index * 124;
        let member = json!({"index":index,"physical_index":index,"name":name,"name_bytes":name.as_bytes(),
            "header_offset":8+index*124,"data_offset":offset,"raw_data_offset":offset,
            "raw_bytes":64,"bytes":64,"sha256":object["sha256"]});
        let edge = json!({"kind":"elf_embedded_bitcode","section_index":1,"section_name":".llvmbc",
            "section_name_bytes":b".llvmbc".as_slice(),"object_offset":16,"container_offset":offset+16,
            "bytes":8,"sha256":bitcode["sha256"],"bitcode_header":{"kind":"raw"}});
        records.push(
            json!({"schema":"ocore-rust-native-bitcode-edge-v1","compiler_invocation_id":invocation,
            "cargo_parent_invocation_id":null,"object":object,"bitcode":bitcode,"edge":edge,
            "container":{"artifact":output,"member":member}}),
        );
        let local_index = if fresh { 1 - index } else { index };
        units.push(json!({"id":format!("{}-{local_index}",if fresh{"fresh"}else{"old"}),"kind":"rustc",
            "source":source,"ir":{ "path":bitcode["path"],"bytes":bitcode["bytes"],"sha256":bitcode["sha256"],
                "format":"llvm-bitcode","target_triple":"riscv64-unknown-linux-gnu",
                "data_layout":"e-m:e-p:64:64-i64:64-n32:64-S128"},
            "frontend_version":"rustc 1.97.1","dependencies":[source],"saved_cgu_index":local_index,
            "capture_policy":"rust-embedded-bc-v1","source_production_ownership_verified":false,
            "native_machine_equivalence_verified":false,"post_lto_equivalence_verified":false}));
    }
    if fresh {
        records.reverse();
        units.reverse();
    }
    let event = json!({"id":invocation,"state":"finished","exit_code":0,"capture_errors":[],
        "producer":"rustc-llvm-v1","kind":"rustc","driver_kind":"rustc","compiler":"/tool/rustc",
        "cwd":format!("{root}/source"),"argv":argv,"expanded_argv":argv,"executed_argv":executed,
        "build_environment":{"LANG":"C"},"build_step":{"name":"compile-original","index":0},
        "capture_worker":artifact("/tool/capture.py".into(),154484,"a"),
        "frontend":{"path":"/tool/rustc","bytes":1024,"sha256":"4".repeat(64),
            "version":"rustc 1.97.1","llvm_version":"22.1.6"},
        "sources":[source],"response_files":[],"outputs":[output],"cargo_parent_invocation_id":null,
        "rust_capture":{"policy":"rust-embedded-bc-v1","applied":true,"transformations":[],
            "original_command_executed":false,"frontend_replay_used":false,
            "post_lto_equivalence_verified":false,"argfile_gap":null},
        "rust_cgu_gaps":[],"rust_native_resources":[],"saved_cgus":records,"units":units});
    let ids = event["units"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["id"].clone())
        .collect::<Vec<_>>();
    serde_json::to_vec(
        &json!({"schema":CAPTURE_FORMAT,"name":"authored-native-DATA",
        "lowering_unit_ids":ids,"units":event["units"],"invocations":[event]}),
    )
    .unwrap()
}
fn pin(path: &Path, raw: &[u8]) -> OrderPin {
    OrderPin {
        path: path.to_owned(),
        bytes: raw.len() as u64,
        sha256: digest(raw),
    }
}
fn python() -> provider_group::Pin {
    let path = std::env::var_os("OCORE_ORDER_TEST_PYTHON").expect("required pinned Python absent");
    let sha256 =
        std::env::var("OCORE_ORDER_TEST_PYTHON_SHA256").expect("required Python SHA absent");
    hash(&sha256).unwrap();
    let pin = provider_group::Pin {
        path: PathBuf::from(path),
        sha256,
    };
    pin.checked().unwrap();
    pin
}
struct NativeFixture {
    directory: tempfile::TempDir,
    policy_pin: OrderPin,
    policy_raw: Vec<u8>,
    original: Vec<u8>,
    fresh: Vec<u8>,
    selected: BTreeSet<String>,
    package_raw: Vec<u8>,
}
impl NativeFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let original = native_capture(false);
        let original_path = directory.path().join("original.json");
        fs::write(&original_path, &original).unwrap();
        let policy_raw=serde_json::to_vec(&json!({"schema":POLICY,
            "components":[{"component":"engine","original_capture":pin(&original_path,&original),
                "required_unit_ids":["old-0","old-1"],
                "original_roots":{"source":"/old/source","build":"/old/build","capture":"/old/capture"},
                "fresh_roots":{"source":"/fresh/source","build":"/fresh/build","capture":"/fresh/capture"},
                "producer_selection":{"schema":"ocore-order-producer-selection-v2",
                    "registry":ContentIdentity::of(source_recipe::order_producer_registry()),
                    "selected_profiles":{"rustc-llvm-v1":{"rust-embedded-bc-v1":"native-container-member-name-v1"}}}}],
            "module_occurrences":[{"component":"engine","unit_id":"old-1"},
                {"component":"engine","unit_id":"old-0"},{"component":"engine","unit_id":"old-1"}]})).unwrap();
        let path = directory.path().join("policy.json");
        fs::write(&path, &policy_raw).unwrap();
        let policy_pin = pin(&path, &policy_raw);
        let seal = SealedOrder::read(&policy_pin, &["engine".into()]).unwrap();
        let component = &seal.policy.components[0];
        let req = request(&seal.raw, &seal.policy, component, &original).unwrap();
        assert_eq!(req["schema"], "Main-source-order-helper-request/v2");
        let tool = python();
        let committed = bridge(&tool, &req, &directory.path().join("commit")).unwrap();
        let commitment = string(&committed, "commitment").unwrap().to_owned();
        let fresh = native_capture(true);
        let selected = ["fresh-0".into(), "fresh-1".into()].into_iter().collect();
        let mut req = req;
        req["operation"] = json!("resolve");
        req["commitment"] = json!(commitment);
        req["fresh_events"] = json!(events(&fresh, &selected).unwrap());
        req["fresh_roots"] = json!(component.fresh_roots);
        let resolution = bridge(&tool, &req, &directory.path().join("resolve")).unwrap();
        let mut package = PackagedOrder {
            schema: PACKAGE_GENERAL.into(),
            policy_pin: policy_pin.clone(),
            policy_json: String::from_utf8(policy_raw.clone()).unwrap(),
            helper_sha256: digest(JOIN.as_bytes()),
            general_helper: general_binding(&seal.policy),
            components: vec![ComponentEvidence {
                component: "engine".into(),
                original_capture_json: String::from_utf8(original.clone()).unwrap(),
                commitment_json: commitment,
                resolution: Some(resolution),
            }],
            resolved_occurrences: Vec::new(),
        };
        let inputs = [CaptureInput {
            component: "engine",
            raw: &fresh,
            selected: &selected,
        }];
        package.resolved_occurrences = package.expected_occurrences(&inputs).unwrap();
        package.check_internal(&inputs).unwrap();
        package.check_external(&seal).unwrap();
        Self {
            directory,
            policy_pin,
            policy_raw,
            original,
            fresh,
            selected,
            package_raw: serde_json::to_vec(&package).unwrap(),
        }
    }
    fn package(&self) -> PackagedOrder {
        serde_json::from_slice(&self.package_raw).unwrap()
    }
    fn inputs(&self) -> [CaptureInput<'_>; 1] {
        [CaptureInput {
            component: "engine",
            raw: &self.fresh,
            selected: &self.selected,
        }]
    }
    fn resolve_request(&self, fresh: &[u8]) -> Value {
        let seal = SealedOrder::read(&self.policy_pin, &["engine".into()]).unwrap();
        let mut req = request(
            &seal.raw,
            &seal.policy,
            &seal.policy.components[0],
            &self.original,
        )
        .unwrap();
        req["operation"] = json!("resolve");
        req["commitment"] = json!(self.package().components[0].commitment_json);
        req["fresh_events"] = json!(events(fresh, &self.selected).unwrap());
        req["fresh_roots"] = json!(seal.policy.components[0].fresh_roots);
        req
    }
}
fn fixture() -> &'static NativeFixture {
    static FIXTURE: OnceLock<NativeFixture> = OnceLock::new();
    FIXTURE.get_or_init(NativeFixture::new)
}
#[test]
fn general_native_bridge_maps_permuted_members_without_replay() {
    let f = fixture();
    let package = f.package();
    let resolution = package.components[0].resolution.as_ref().unwrap();
    assert_eq!(
        resolution["unit_mapping"],
        json!({"old-0":"fresh-1","old-1":"fresh-0"})
    );
    assert_eq!(
        package.fresh_module_order(&f.inputs()).unwrap(),
        vec![
            ("engine".into(), "fresh-0".into()),
            ("engine".into(), "fresh-1".into()),
            ("engine".into(), "fresh-0".into())
        ]
    );
    let captured = checked_json(&f.original).unwrap();
    assert!(captured["invocations"][0].get("replay_argv").is_none());
    assert!(captured["units"][0].get("replay_argv").is_none());
    assert_eq!(resolution["capture_admitted"], false);
    assert_eq!(resolution["runtime_qualified"], false);
    assert_eq!(package.schema, PACKAGE_GENERAL);
    assert!(package.general_helper.is_some());
}
#[test]
fn general_events_retain_complete_multi_output_owner() {
    let f = fixture();
    let floor = ["old-0".into(), "old-1".into()].into_iter().collect();
    let actions = events(&f.original, &floor).unwrap();
    assert_eq!(actions.len(), 1);
    let action = checked_json(actions[0].as_bytes()).unwrap();
    assert_eq!(action["units"].as_array().unwrap().len(), 2);
    assert_eq!(action["saved_cgus"].as_array().unwrap().len(), 2);
}
#[test]
fn general_registry_selection_refuses_changed_actual_registry_pin() {
    let f = fixture();
    let mut value = checked_json(&f.policy_raw).unwrap();
    let before = value["components"][0]["producer_selection"]["registry"]["sha256"].clone();
    value["components"][0]["producer_selection"]["registry"]["sha256"] = json!("f".repeat(64));
    assert_ne!(
        before,
        value["components"][0]["producer_selection"]["registry"]["sha256"]
    );
    let raw = serde_json::to_vec(&value).unwrap();
    let error = parse_policy(&raw).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("actual embedded registry differs"),
        "{error:#}"
    );
}
#[test]
fn general_helper_binding_mutation_reaches_internal_rejection() {
    let f = fixture();
    let mut package = f.package();
    let binding = package.general_helper.as_mut().unwrap();
    assert_eq!(binding.helper, ContentIdentity::of(GENERAL_JOIN));
    binding.helper.sha256 = "f".repeat(64);
    assert_ne!(binding.helper, ContentIdentity::of(GENERAL_JOIN));
    let error = package.check_internal(&f.inputs()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("source group original-order consistency differs"),
        "{error:#}"
    );
}
#[test]
fn general_protocol_cannot_accept_legacy_result_schema() {
    let f = fixture();
    let mut package = f.package();
    let result = package.components[0].resolution.as_mut().unwrap();
    assert_eq!(
        result["schema"],
        "ocore-original-ordered-multi-output-join-v2"
    );
    result["schema"] = json!("ocore-original-ordered-action-fresh-unit-join-v1");
    assert_eq!(
        result["schema"],
        "ocore-original-ordered-action-fresh-unit-join-v1"
    );
    let error = package.check_internal(&f.inputs()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("packaged action/order/floor mapping differs"),
        "{error:#}"
    );
}
#[test]
fn general_native_cargo_parent_stays_explicitly_unsupported() {
    let f = fixture();
    let mut fresh = checked_json(&f.fresh).unwrap();
    fresh["invocations"][0]["cargo_parent_invocation_id"] = json!("new-unsupported-parent");
    assert_eq!(
        fresh["invocations"][0]["cargo_parent_invocation_id"],
        "new-unsupported-parent"
    );
    let req = f.resolve_request(&serde_json::to_vec(&fresh).unwrap());
    let output = f.directory.path().join("mutant-parent");
    let error = bridge(&python(), &req, &output).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("order consistency helper failed"),
        "{error:#}"
    );
    let stderr = fs::read_to_string(output.join("stderr.log")).unwrap();
    assert!(
        stderr.contains("Cargo parent semantic context unsupported"),
        "{stderr}"
    );
}
#[test]
fn general_bridge_missing_contract_field_reaches_exact_request_rejection() {
    let f = fixture();
    let mut req = f.resolve_request(&f.fresh);
    assert!(req
        .as_object_mut()
        .unwrap()
        .remove("selected_profiles")
        .is_some());
    assert!(req.get("selected_profiles").is_none());
    let output = f.directory.path().join("mutant-request");
    let error = bridge(&python(), &req, &output).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("order consistency helper failed"),
        "{error:#}"
    );
    let stderr = fs::read_to_string(output.join("stderr.log")).unwrap();
    assert!(stderr.contains("bridge request fields differ"), "{stderr}");
}
#[test]
fn general_binding_does_not_supply_external_policy_authority() {
    let package = fixture().package();
    assert!(package.general_helper.is_some());
    let error = package.require_external(None).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("requires an external original-order selection"),
        "{error:#}"
    );
}

// These remain metadata/consistency controls. They do not admit capture, native
// object bytes, source ownership, Cargo parent semantics or runtime behavior.
fn registered_selection(
    producer: &str,
    policy: EvidencePolicy,
    selector: SelectorProfile,
) -> ProducerSelection {
    ProducerSelection {
        schema: "ocore-order-producer-selection-v2".into(),
        registry: ContentIdentity::of(source_recipe::order_producer_registry()),
        selected_profiles: [(
            producer.to_owned(),
            [(policy, selector)].into_iter().collect(),
        )]
        .into_iter()
        .collect(),
    }
}

#[test]
fn general_registered_selectors_match_rust_replay_clang_and_native_contracts() {
    for (producer, policy, selector, name) in [
        (
            "rustc-llvm-v1",
            EvidencePolicy::FrontendReplay,
            SelectorProfile::RustReplayEmittedModuleName,
            "rust-replay-emitted-module-name-v1",
        ),
        (
            "clang-llvm-v1",
            EvidencePolicy::FrontendReplay,
            SelectorProfile::ReplaySourceCommand,
            "replay-source-command-v1",
        ),
        (
            "rustc-llvm-v1",
            EvidencePolicy::RustEmbedded,
            SelectorProfile::NativeContainerMemberName,
            "native-container-member-name-v1",
        ),
    ] {
        assert_eq!(serde_json::to_value(selector).unwrap(), json!(name));
        registered_selection(producer, policy, selector)
            .check()
            .unwrap();
    }
}

#[test]
fn general_rust_replay_refuses_clang_source_command_selector() {
    let selected = registered_selection(
        "rustc-llvm-v1",
        EvidencePolicy::FrontendReplay,
        SelectorProfile::ReplaySourceCommand,
    );
    let error = selected.check().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("order evidence policy or selector profile is not registered"),
        "{error:#}"
    );
}

#[test]
fn general_clang_replay_refuses_rust_emitted_module_selector() {
    let selected = registered_selection(
        "clang-llvm-v1",
        EvidencePolicy::FrontendReplay,
        SelectorProfile::RustReplayEmittedModuleName,
    );
    let error = selected.check().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("order evidence policy or selector profile is not registered"),
        "{error:#}"
    );
}

#[test]
fn general_native_edges_refuse_both_replay_selectors() {
    for selector in [
        SelectorProfile::ReplaySourceCommand,
        SelectorProfile::RustReplayEmittedModuleName,
    ] {
        let selected =
            registered_selection("rustc-llvm-v1", EvidencePolicy::RustEmbedded, selector);
        let error = selected.check().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("order evidence policy or selector profile is not registered"),
            "{error:#}"
        );
    }
}

fn rust_replay_capture(fresh: bool) -> Vec<u8> {
    let root = if fresh { "/fresh" } else { "/old" };
    let directory = format!("{root}/capture/rust-replay");
    let mut capture = checked_json(&native_capture(fresh)).unwrap();
    let event = &mut capture["invocations"][0];
    for field in [
        "executed_argv",
        "rust_capture",
        "rust_cgu_gaps",
        "rust_native_resources",
        "saved_cgus",
    ] {
        assert!(event.as_object_mut().unwrap().remove(field).is_some());
    }
    event["replay_argv"] = json!([
        "/tool/rustc",
        "--crate-name",
        "engine",
        format!("{root}/source/lib.rs"),
        "--emit=llvm-ir,dep-info",
        "--out-dir",
        directory
    ]);
    event["replay_exit_code"] = json!(0);
    for unit in event["units"].as_array_mut().unwrap() {
        let name = match unit["id"].as_str().unwrap() {
            "old-0" | "fresh-1" => "engine.main.ll",
            "old-1" | "fresh-0" => "engine.cold.ll",
            other => panic!("unexpected authored unit {other}"),
        };
        for field in [
            "saved_cgu_index",
            "capture_policy",
            "source_production_ownership_verified",
            "native_machine_equivalence_verified",
            "post_lto_equivalence_verified",
        ] {
            assert!(unit.as_object_mut().unwrap().remove(field).is_some());
        }
        unit["producer"] = json!("rustc-llvm-v1");
        unit["ir"]["path"] = json!(format!("{directory}/{name}"));
        unit["ir"]["format"] = json!("llvm-text");
        assert!(unit.get("replay_argv").is_none());
        assert!(unit.get("replay_exit_code").is_none());
    }
    let units = event["units"].clone();
    capture["units"] = units;
    capture["name"] = json!("authored-Rust-replay-DATA");
    serde_json::to_vec(&capture).unwrap()
}

#[test]
fn general_rust_replay_selector_joins_actual_python_multi_output_contract() {
    let directory = tempfile::tempdir().unwrap();
    let original = rust_replay_capture(false);
    let original_path = directory.path().join("original.json");
    fs::write(&original_path, &original).unwrap();
    let selection = registered_selection(
        "rustc-llvm-v1",
        EvidencePolicy::FrontendReplay,
        SelectorProfile::RustReplayEmittedModuleName,
    );
    selection.check().unwrap();
    let policy_raw = serde_json::to_vec(&json!({
        "schema":POLICY,
        "components":[{
            "component":"engine", "original_capture":pin(&original_path,&original),
            "required_unit_ids":["old-0","old-1"],
            "original_roots":{"source":"/old/source","build":"/old/build","capture":"/old/capture"},
            "fresh_roots":{"source":"/fresh/source","build":"/fresh/build","capture":"/fresh/capture"},
            "producer_selection":{
                "schema":selection.schema,"registry":selection.registry,
                "selected_profiles":selection.selected_profiles
            }
        }],
        "module_occurrences":[
            {"component":"engine","unit_id":"old-1"},
            {"component":"engine","unit_id":"old-0"},
            {"component":"engine","unit_id":"old-1"}
        ]
    })).unwrap();
    let policy_path = directory.path().join("policy.json");
    fs::write(&policy_path, &policy_raw).unwrap();
    let policy_pin = pin(&policy_path, &policy_raw);
    let seal = SealedOrder::read(&policy_pin, &["engine".into()]).unwrap();
    let component = &seal.policy.components[0];
    let mut req = request(&seal.raw, &seal.policy, component, &original).unwrap();
    assert_eq!(req["schema"], "Main-source-order-helper-request/v2");
    assert_eq!(
        req["selected_profiles"]["rustc-llvm-v1"]["frontend-replay-v1"],
        "rust-replay-emitted-module-name-v1"
    );
    let tool = python();
    let committed = bridge(&tool, &req, &directory.path().join("commit")).unwrap();
    let commitment = string(&committed, "commitment").unwrap().to_owned();
    let data = checked_json(commitment.as_bytes()).unwrap();
    let outputs = data["actions"][0]["units"].as_array().unwrap();
    assert_eq!(outputs.len(), 2);
    for output in outputs {
        assert_eq!(
            output["selector"]["profile"],
            "rust-replay-emitted-module-name-v1"
        );
        assert_eq!(
            output["selector"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            ["profile".into(), "emitted_filename".into()]
                .into_iter()
                .collect()
        );
    }
    let fresh = rust_replay_capture(true);
    let selected = ["fresh-0".into(), "fresh-1".into()].into_iter().collect();
    req["operation"] = json!("resolve");
    req["commitment"] = json!(commitment);
    req["fresh_events"] = json!(events(&fresh, &selected).unwrap());
    req["fresh_roots"] = json!(component.fresh_roots);
    let resolution = bridge(&tool, &req, &directory.path().join("resolve")).unwrap();
    assert_eq!(
        resolution["unit_mapping"],
        json!({"old-0":"fresh-1","old-1":"fresh-0"})
    );
    assert_eq!(resolution["capture_admitted"], false);
    assert_eq!(resolution["runtime_qualified"], false);
    let mut package = PackagedOrder {
        schema: PACKAGE_GENERAL.into(),
        policy_pin,
        policy_json: String::from_utf8(policy_raw).unwrap(),
        helper_sha256: digest(JOIN.as_bytes()),
        general_helper: general_binding(&seal.policy),
        components: vec![ComponentEvidence {
            component: "engine".into(),
            original_capture_json: String::from_utf8(original).unwrap(),
            commitment_json: commitment,
            resolution: Some(resolution),
        }],
        resolved_occurrences: Vec::new(),
    };
    let inputs = [CaptureInput {
        component: "engine",
        raw: &fresh,
        selected: &selected,
    }];
    package.resolved_occurrences = package.expected_occurrences(&inputs).unwrap();
    package.check_internal(&inputs).unwrap();
    package.check_external(&seal).unwrap();
    assert_eq!(
        package.fresh_module_order(&inputs).unwrap(),
        vec![
            ("engine".into(), "fresh-0".into()),
            ("engine".into(), "fresh-1".into()),
            ("engine".into(), "fresh-0".into()),
        ]
    );
}
