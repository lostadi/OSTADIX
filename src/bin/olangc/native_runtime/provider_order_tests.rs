//! Authored DATA controls of the real Rust order consumer. No original build,
//! O-core import, native target execution, or provider authority is established.
//! The bridge fixture runs only when an explicitly pinned Python is supplied;
//! missing prerequisites fail rather than skipping or selecting an ambient tool.
use super::*;
use std::sync::OnceLock;

fn pin(path: &Path, raw: &[u8]) -> OrderPin {
    OrderPin {
        path: path.to_owned(),
        bytes: raw.len() as u64,
        sha256: digest(raw),
    }
}
fn artifact(path: String, raw: &[u8]) -> Value {
    json!({"path":path,"bytes":raw.len(),"sha256":digest(raw)})
}
fn event(root: &str, invocation: &str, unit_id: &str, stem: &str) -> Value {
    let source = artifact(format!("{root}/src/{stem}.c"), stem.as_bytes());
    let mut ir = artifact(format!("{root}/capture/{unit_id}.ll"), b"authored IR DATA");
    ir["format"] = json!("llvm-ir");
    ir["target_triple"] = json!("riscv64-unknown-linux-gnu");
    ir["data_layout"] = json!("e-m:e-p:64:64-i64:64-n32:64-S128");
    let mut frontend = artifact("/compiler/clang".into(), b"authored tool identity DATA");
    frontend["version"] = json!("authored version");
    frontend["llvm_version"] = json!("22");
    let mut output = artifact(format!("{root}/objects/{stem}.o"), b"authored object DATA");
    output["artifact_kind"] = json!("object");
    let argv = json!([
        "/compiler/clang",
        "-c",
        source["path"],
        "-o",
        output["path"]
    ]);
    json!({"id":invocation,"state":"finished","exit_code":0,"capture_errors":[],
        "kind":"clang","producer":"clang","driver_kind":"clang","compiler":"/compiler/clang",
        "capture_worker":artifact("/compiler/capture.py".into(),b"authored worker DATA"),
        "cwd":format!("{root}/build"),"argv":argv,"expanded_argv":argv,
        "frontend":frontend,"build_environment":{"LANG":"C"},
        "build_step":{"name":"compile","index":0},"sources":[source],
        "response_files":[],"outputs":[output],
        "units":[{"id":unit_id,"kind":"clang","producer":"clang","source":source,"ir":ir,
            "replay_argv":["/compiler/clang","-S","-emit-llvm",source["path"],"-o",ir["path"],
                "-MF",format!("{root}/capture/{unit_id}.d")],
            "replay_exit_code":0,"dependencies":[source]}]})
}
fn capture(root: &str, fresh: bool) -> Vec<u8> {
    let (a, b, ia, ib) = if fresh {
        ("uuid-A", "uuid-B", "new-action-A", "new-action-B")
    } else {
        ("old-A", "old-B", "old-action-A", "old-action-B")
    };
    let actions = vec![event(root, ia, a, "A"), event(root, ib, b, "B")];
    let units = actions
        .iter()
        .map(|a| a["units"][0].clone())
        .collect::<Vec<_>>();
    serde_json::to_vec(&json!({"schema":CAPTURE_FORMAT,"name":"authored-engine",
        "lowering_unit_ids":[a,b],"invocations":actions,"units":units}))
    .unwrap()
}
fn policy_value(original: &OrderPin) -> Value {
    json!({"schema":POLICY,
        "components":[{"component":"engine","original_capture":original,
            "required_unit_ids":["old-A","old-B"],
            "original_roots":{"Build":"/original"},"fresh_roots":{"Build":"/fresh"}}],
        "module_occurrences":[{"component":"engine","unit_id":"old-B"},
            {"component":"engine","unit_id":"old-A"},{"component":"engine","unit_id":"old-B"}]})
}
struct LocalPolicy {
    directory: tempfile::TempDir,
    pin: OrderPin,
    raw: Vec<u8>,
    original: Vec<u8>,
}
impl LocalPolicy {
    fn new(original: Vec<u8>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let original_path = directory.path().join("original-capture.json");
        fs::write(&original_path, &original).unwrap();
        let original_pin = pin(&original_path, &original);
        let raw = serde_json::to_vec(&policy_value(&original_pin)).unwrap();
        let path = directory.path().join("original-order.json");
        fs::write(&path, &raw).unwrap();
        Self {
            directory,
            pin: pin(&path, &raw),
            raw,
            original,
        }
    }
    fn seal(&self) -> SealedOrder {
        SealedOrder::read(&self.pin, &["engine".into()]).unwrap()
    }
}
fn selected_python() -> provider_group::Pin {
    let path = std::env::var_os("OCORE_ORDER_TEST_PYTHON")
        .expect("required pinned OCORE_ORDER_TEST_PYTHON is absent");
    let sha256 = std::env::var("OCORE_ORDER_TEST_PYTHON_SHA256")
        .expect("required OCORE_ORDER_TEST_PYTHON_SHA256 is absent");
    hash(&sha256).unwrap();
    let python = provider_group::Pin {
        path: PathBuf::from(path),
        sha256,
    };
    python.checked().expect("selected Python bytes differ");
    python
}
struct BridgeFixture {
    local: LocalPolicy,
    package_json: Vec<u8>,
    fresh: Vec<u8>,
    selected: BTreeSet<String>,
}
impl BridgeFixture {
    fn new() -> Self {
        let local = LocalPolicy::new(capture("/original", false));
        let seal = local.seal();
        let python = selected_python();
        let directory = local.directory.path().join("bridge");
        fs::create_dir(&directory).unwrap();
        let mut req = request(
            &seal.raw,
            &seal.policy,
            &seal.policy.components[0],
            &local.original,
        )
        .unwrap();
        let committed = bridge(&python, &req, &directory.join("commit")).unwrap();
        let commitment = string(&committed, "commitment").unwrap().to_owned();
        let fresh = capture("/fresh", true);
        let selected = ["uuid-A".into(), "uuid-B".into()].into_iter().collect();
        req["operation"] = json!("resolve");
        req["commitment"] = json!(commitment);
        req["fresh_events"] = json!(events(&fresh, &selected).unwrap());
        req["fresh_roots"] = json!({"Build":"/fresh"});
        let resolution = bridge(&python, &req, &directory.join("resolve")).unwrap();
        assert_eq!(resolution["consistency_join_complete"], true);
        assert_eq!(resolution["capture_admitted"], false);
        assert_eq!(resolution["runtime_qualified"], false);
        let mut package = PackagedOrder {
            schema: PACKAGE.into(),
            policy_pin: local.pin.clone(),
            policy_json: String::from_utf8(local.raw.clone()).unwrap(),
            helper_sha256: digest(JOIN.as_bytes()),
            general_helper: None,
            components: vec![ComponentEvidence {
                component: "engine".into(),
                original_capture_json: String::from_utf8(local.original.clone()).unwrap(),
                commitment_json: commitment,
                resolution: Some(resolution),
            }],
            resolved_occurrences: vec![],
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
            local,
            package_json: serde_json::to_vec(&package).unwrap(),
            fresh,
            selected,
        }
    }
    fn package(&self) -> PackagedOrder {
        serde_json::from_slice(&self.package_json).unwrap()
    }
    fn inputs(&self) -> [CaptureInput<'_>; 1] {
        [CaptureInput {
            component: "engine",
            raw: &self.fresh,
            selected: &self.selected,
        }]
    }
}
fn fixture() -> &'static BridgeFixture {
    // One genuine consistency-helper positive, then independent copies for
    // mutations. No original capture is admitted by this authored DATA fixture.
    static FIXTURE: OnceLock<BridgeFixture> = OnceLock::new();
    FIXTURE.get_or_init(BridgeFixture::new)
}
fn counts(items: &[Occurrence]) -> BTreeMap<(String, String), usize> {
    let mut counts = BTreeMap::new();
    for o in items {
        *counts
            .entry((o.component.clone(), o.unit_id.clone()))
            .or_default() += 1;
    }
    counts
}

#[test]
fn original_order_consumer_actual_bridge_positive_preserves_bab_multiplicity() {
    let f = fixture();
    let package = f.package();
    package.check_internal(&f.inputs()).unwrap();
    assert_eq!(
        package
            .resolved_occurrences
            .iter()
            .map(|o| o.unit_id.as_str())
            .collect::<Vec<_>>(),
        vec!["uuid-B", "uuid-A", "uuid-B"]
    );
    assert_eq!(package.resolved_occurrences.len(), 3);
    assert_eq!(counts(&package.resolved_occurrences).len(), 2);
}

#[test]
fn original_order_consumer_mutated_seal_refuses_before_prepare_outputs() {
    let local = LocalPolicy::new(capture("/original", false));
    let sealed = local.seal();
    let mut changed: Value = serde_json::from_slice(&local.raw).unwrap();
    changed["module_occurrences"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    let mutated = serde_json::to_vec(&changed).unwrap();
    assert_ne!(mutated, local.raw);
    fs::write(&local.pin.path, &mutated).unwrap();
    assert_eq!(fs::read(&local.pin.path).unwrap(), mutated);
    assert_ne!(digest(&mutated), local.pin.sha256);
    let output = local.directory.path().join("must-not-exist");
    let unused = provider_group::Pin {
        path: local.directory.path().join("not-an-executable"),
        sha256: "0".repeat(64),
    };
    let error = sealed
        .prepare(&unused, &output)
        .err()
        .expect("changed seal must reject");
    assert!(
        error
            .to_string()
            .contains("original-order held file identity/bytes differ"),
        "{error:#}"
    );
    assert!(!output.exists());
}

#[test]
fn original_order_consumer_same_counter_bab_to_bba_is_not_equivalent_order() {
    let f = fixture();
    let mut package = f.package();
    let before = package.resolved_occurrences.clone();
    package.resolved_occurrences.swap(1, 2);
    assert_ne!(package.resolved_occurrences, before);
    assert_eq!(counts(&package.resolved_occurrences), counts(&before));
    assert_eq!(
        package
            .resolved_occurrences
            .iter()
            .map(|o| o.unit_id.as_str())
            .collect::<Vec<_>>(),
        vec!["uuid-B", "uuid-B", "uuid-A"]
    );
    let error = package.check_internal(&f.inputs()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("source group original-order consistency differs"),
        "{error:#}"
    );
}

#[test]
fn original_order_consumer_embedded_policy_cannot_supply_external_selection() {
    let f = fixture();
    let package = f.package();
    package.check_internal(&f.inputs()).unwrap();
    assert!(!package.policy_json.is_empty());
    let error = package.require_external(None).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("requires an external original-order selection"),
        "{error:#}"
    );
}

#[test]
fn original_order_consumer_identical_bytes_at_different_external_pin_are_refused() {
    let f = fixture();
    let package = f.package();
    let copy = tempfile::tempdir().unwrap();
    let path = copy.path().join("other-policy.json");
    fs::write(&path, &f.local.raw).unwrap();
    let other = pin(&path, &f.local.raw);
    assert_eq!(other.sha256, f.local.pin.sha256);
    assert_ne!(other.path, f.local.pin.path);
    let selected = SealedOrder::read(&other, &["engine".into()]).unwrap();
    assert_eq!(selected.raw, f.local.raw);
    let error = package.require_external(Some(&selected)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("differs from independently held original-order pin"),
        "{error:#}"
    );
}

#[test]
fn original_order_consumer_changed_unit_map_reaches_bijection_rejection() {
    let f = fixture();
    let mut package = f.package();
    let resolution = package.components[0].resolution.as_mut().unwrap();
    assert_eq!(resolution["unit_mapping"]["old-A"], "uuid-A");
    resolution["unit_mapping"]["old-A"] = json!("uuid-B");
    assert_eq!(resolution["unit_mapping"]["old-A"], "uuid-B");
    // Keep the per-occurrence projection consistent with the injected map so
    // rejection is not merely a stale fresh_occurrences array.
    resolution["fresh_occurrences"] = json!(["uuid-B", "uuid-B", "uuid-B"]);
    let injected: BTreeMap<String, String> =
        serde_json::from_value(resolution["unit_mapping"].clone()).unwrap();
    assert_eq!(injected.len(), 2);
    assert_eq!(injected.values().collect::<BTreeSet<_>>().len(), 1);
    let error = package.check_internal(&f.inputs()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("packaged action/order/floor mapping differs"),
        "{error:#}"
    );
}

#[test]
fn original_order_consumer_semantically_equal_changed_raw_policy_refuses_stale_pin() {
    let local = LocalPolicy::new(capture("/original", false));
    let sealed = local.seal();
    let mut changed = local.raw.clone();
    changed.push(b'\n');
    fs::write(&local.pin.path, &changed).unwrap();
    assert_eq!(
        checked_json(&changed).unwrap(),
        checked_json(&local.raw).unwrap()
    );
    assert_ne!(digest(&changed), local.pin.sha256);
    assert_eq!(fs::read(&local.pin.path).unwrap(), changed);
    let error = sealed.check_unchanged().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("original-order held file identity/bytes differ"),
        "{error:#}"
    );
}

#[test]
fn original_order_consumer_claimed_admission_booleans_cannot_fill_missing_unit_floor() {
    // This is the real prepare/floor guard, not a full worker-admission proof.
    let original = serde_json::to_vec(&json!({"schema":CAPTURE_FORMAT,
        "lowering_unit_ids":[],"invocations":[],"units":[],
        "capture_complete":true,"verified":true,"source_capture_complete":true,
        "unit_inventory":{"definition":{"complete":true}}}))
    .unwrap();
    let local = LocalPolicy::new(original);
    let sealed = local.seal();
    let observed = checked_json(&local.original).unwrap();
    assert_eq!(observed["verified"], true);
    assert_eq!(observed["unit_inventory"]["definition"]["complete"], true);
    assert!(observed["lowering_unit_ids"].as_array().unwrap().is_empty());
    let output = local.directory.path().join("floor-refusal");
    let unused = provider_group::Pin {
        path: local.directory.path().join("not-an-executable"),
        sha256: "0".repeat(64),
    };
    let error = sealed
        .prepare(&unused, &output)
        .err()
        .expect("claimed booleans must not create a floor");
    assert!(
        error
            .to_string()
            .contains("empty/duplicate order capture unit selection"),
        "{error:#}"
    );
    assert!(output.exists());
    assert!(!output.join("original-000000").exists());
}

#[test]
fn original_order_consumer_resolver_input_retains_repeated_occurrences() {
    let fixture = fixture();
    let package = fixture.package();
    let actual = package.fresh_module_order(&fixture.inputs()).unwrap();
    assert_eq!(
        actual,
        vec![
            ("engine".into(), "uuid-B".into()),
            ("engine".into(), "uuid-A".into()),
            ("engine".into(), "uuid-B".into())
        ]
    );
    assert_eq!(actual.len(), 3);
    assert_eq!(actual.iter().collect::<BTreeSet<_>>().len(), 2);
}
