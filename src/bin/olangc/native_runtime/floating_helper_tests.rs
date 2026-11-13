//! Structural admission tests; these providers do not qualify helper arithmetic.
use super::*;

#[test]
fn constrained_multiply_artifacts_keep_compiler_metadata_without_a_fake_provider() {
    // Authored structural fixture. Original-source custody and arithmetic are
    // established by the separate unchanged-source differential tests.
    for arch in ["x86_64", "aarch64", "riscv64"] {
        let value = json!({
            "format":"ocore-native-module-v1", "name":"constrained-artifact-fixture",
            "target":{"triple":format!("{arch}-unknown-linux-gnu"),
                "data_layout":"e-p:64:64-i64:64-f64:64", "pointer_bits":64,
                "little_endian":true, "abi":(arch == "riscv64").then_some("lp64d"),
                "strict_fp_profile":"scalar_dynamic_mul_v1"},
            "semantics":"llvm_defined_behavior_v1",
            "types":[{"kind":"void"},{"kind":"float","bits":64},{"kind":"metadata"}],
            "globals":[],
            "functions":[
                {"name":"native_mul","linkage":"external",
                    "signature":{"params":[1,1],"result":1,"abi":"c","variadic":false},
                    "params":[{"id":0,"ty":1},{"id":1,"ty":1}],"entry":0,
                    "blocks":[{"id":0,"instructions":[{"result":{"id":2,"ty":1},
                        "operation":{"op":"constrained_float_binary","kind":"mul",
                            "lhs":{"kind":"value","id":0},"rhs":{"kind":"value","id":1},
                            "rounding":"dynamic","exceptions":"ignore"}}],
                        "terminator":{"op":"return","value":{"kind":"value","id":2}}}]},
                {"name":"llvm.experimental.constrained.fmul.f64","linkage":"external",
                    "intrinsic":"llvm.experimental.constrained.fmul.f64",
                    "signature":{"params":[1,1,2,2],"result":1,"abi":"c","variadic":false},
                    "params":[{"id":0,"ty":1},{"id":1,"ty":1},
                        {"id":2,"ty":2},{"id":3,"ty":2}],"entry":null,"blocks":[]}
            ],
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"authored-test",
                "frontend_version":"1","importer":"authored-test","importer_version":"1",
                "source_function_count":2,"source_global_count":0,"refinements":[]}
        });
        let module = NativeModule::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        let inventory = symbols("fixture", &module).unwrap();
        let intrinsic = inventory
            .iter()
            .find(|symbol| symbol.name == "llvm.experimental.constrained.fmul.f64")
            .unwrap();
        assert!(!intrinsic.definition);
        assert_eq!(
            intrinsic.intrinsic.as_deref(),
            Some(intrinsic.name.as_str())
        );
        let (closed, issues) = resolve_symbols(&inventory);
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(closed["closed"], true);
        let package = artifact::Artifact::build(
            "fixture",
            &"0".repeat(64),
            &[("fixture".into(), module.to_json().unwrap())],
            &[],
        )
        .unwrap();
        artifact::Artifact::from_bytes(&serde_json::to_vec(&package).unwrap()).unwrap();

        let mut missing = module.clone();
        missing.functions.pop();
        missing.provenance.source_function_count = 1;
        let error = NativeModule::from_json(&serde_json::to_vec(&missing).unwrap()).unwrap_err();
        assert!(error
            .message
            .contains("included exact intrinsic declaration"));
        let mut ordinary_abi = module.clone();
        ordinary_abi.functions[1].signature.params[2] = 1;
        ordinary_abi.functions[1].params[2].ty = 1;
        let error =
            NativeModule::from_json(&serde_json::to_vec(&ordinary_abi).unwrap()).unwrap_err();
        assert!(
            error
                .message
                .contains("invalid compiler-only metadata intrinsic signature"),
            "{}",
            error.message
        );
    }
}

fn provider(consumer: &NativeModule) -> NativeModule {
    use o_lang::ocore::native_ir::{Operand, Terminator, Value};
    let mut provider = consumer.clone();
    provider.name = "helper-interface-provider".into();
    provider.globals.clear();
    provider.provenance.source_global_count = 0;
    let function = &mut provider.functions[0];
    function.name = "__addtf3".into();
    function.signature.params = vec![2, 2];
    function.signature.result = 2;
    function.params = vec![Value { id: 0, ty: 2 }, Value { id: 1, ty: 2 }];
    function.blocks[0].instructions.clear();
    function.blocks[0].terminator = Terminator::Return {
        value: Some(Operand::Float {
            ty: 2,
            bits: "0".into(),
        }),
    };
    NativeModule::from_json(&serde_json::to_vec(&provider).unwrap()).unwrap()
}

#[test]
fn generated_floating_helpers_are_explicit_required_provider_interfaces() {
    for arch in ["x86_64", "aarch64", "riscv64"] {
        let consumer = object_inventory_tests::floating_helper_module(arch);
        let original = serde_json::to_vec(&consumer).unwrap();
        let mut inventory = symbols("consumer", &consumer).unwrap();
        let helper = inventory
            .iter()
            .find(|symbol| symbol.name == "__addtf3")
            .unwrap();
        assert!(!helper.definition);
        assert_eq!(
            helper.abi_adaptation.as_ref().unwrap()["provider_required"],
            true
        );
        assert_eq!(
            helper.abi_adaptation.as_ref().unwrap()["source_function_inventory_changed"],
            false
        );
        let (unclosed, issues) = resolve_symbols(&inventory);
        assert_eq!(unclosed["closed"], false);
        assert!(issues
            .iter()
            .any(|issue| issue.contains("unresolved or incompatible declaration __addtf3")));
        let valid = provider(&consumer);
        inventory.extend(symbols("provider", &valid).unwrap());
        let (closed, issues) = resolve_symbols(&inventory);
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(closed["closed"], true);
        assert_eq!(serde_json::to_vec(&consumer).unwrap(), original);
        let mut wrong = valid.clone();
        wrong.functions[0].signature.params = vec![1, 1];
        wrong.functions[0].params[0].ty = 1;
        wrong.functions[0].params[1].ty = 1;
        NativeModule::from_json(&serde_json::to_vec(&wrong).unwrap()).unwrap();
        let mut mismatched = symbols("consumer", &consumer).unwrap();
        mismatched.extend(symbols("wrong-provider", &wrong).unwrap());
        let (failed, issues) = resolve_symbols(&mismatched);
        assert_eq!(failed["closed"], false);
        assert!(issues.iter().any(|issue| issue.contains("__addtf3")));
    }
}

#[test]
fn module_packages_recompute_generated_helper_closure_and_reject_inventory_forgery() {
    let consumer = object_inventory_tests::floating_helper_module("riscv64");
    let consumer_bytes = serde_json::to_vec(&consumer).unwrap();
    let no_provider = artifact::Artifact::build(
        "fixture",
        &"0".repeat(64),
        &[("consumer".into(), consumer_bytes.clone())],
        &[],
    );
    assert!(no_provider.unwrap_err().to_string().contains("__addtf3"));
    let provider_bytes = serde_json::to_vec(&provider(&consumer)).unwrap();
    let package = artifact::Artifact::build(
        "fixture",
        &"0".repeat(64),
        &[
            ("consumer".into(), consumer_bytes),
            ("provider".into(), provider_bytes),
        ],
        &[],
    )
    .unwrap();
    let bytes = serde_json::to_vec(&package).unwrap();
    artifact::Artifact::from_bytes(&bytes).unwrap();
    let mut forged: Value = serde_json::from_slice(&bytes).unwrap();
    let declarations = forged["symbol_inventory"]["declarations"]
        .as_array_mut()
        .unwrap();
    let declaration = declarations
        .iter_mut()
        .find(|record| record["symbol"] == "__addtf3")
        .unwrap();
    declaration["abi_adaptation"]["requirement"]["name"] = json!("__subtf3");
    let error = artifact::Artifact::from_bytes(&serde_json::to_vec(&forged).unwrap()).unwrap_err();
    assert!(error
        .to_string()
        .contains("independently recomputed closure"));
}

#[test]
fn ordered_fp_register_barrier_artifact_has_no_fake_provider_or_pure_profile() {
    let source = json!({"schema":"ocore.llvm-fp-register-barrier-source/v1",
                    "site":{"function":"barrier","block":0,"source_instruction":0},
                    "original_target":"aarch64-unknown-linux-musl","assembly":[],"constraints":[61,119,44,48],
                    "side_effects":true,"align_stack":false,"dialect":0,"can_unwind":false,
                    "calling_convention":0,"tail_kind":1,"fast_math":0,"operand_bundles":0,"call_opcode":45,
                    "signature":{"params":[1],"result":1,"abi":"c","variadic":false},
                    "attributes":[],"srcloc":null});

    // Authored MIR structural fixture, distinct from original-source admission.
    let mut value = json!({
        "format":"ocore-native-module-v1", "name":"ordered-barrier-artifact",
        "target":{"triple":"aarch64-unknown-linux-musl", "data_layout":"e-p:64:64-i64:64-f64:64",
            "pointer_bits":64,"little_endian":true,"strict_fp_profile":"scalar_dynamic_mul_register_barrier_v1"},
        "semantics":"llvm_defined_behavior_v1", "types":[{"kind":"void"},{"kind":"float","bits":64}],
        "globals":[],"functions":[{"name":"barrier","linkage":"external",
            "signature":{"params":[1],"result":1,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":1}],"entry":0,
            "blocks":[{"id":0,"instructions":[{"result":{"id":1,"ty":1},"operation":{
                "op":"fp_register_barrier","value":{"kind":"value","id":0},
                "source":source}}],
                "terminator":{"op":"return","value":{"kind":"value","id":1}}}]}],
        "provenance":{"input_sha256":"0".repeat(64),"frontend":"authored-test","frontend_version":"1",
            "importer":"authored-test","importer_version":"1","source_function_count":1,"source_global_count":0,"refinements":[]}
    });
    let module = NativeModule::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let error = o_lang::ocore::native_interpret::evaluate(&module, "barrier", &[]).unwrap_err();
    assert!(error
        .message
        .contains("ordered FP register barrier execution is not implemented by the integer reference interpreter"));
    let inventory = symbols("barrier", &module).unwrap();
    assert!(inventory.iter().all(|symbol| symbol.definition));
    let (_, issues) = resolve_symbols(&inventory);
    assert!(issues.is_empty(), "{issues:?}");
    let package = artifact::Artifact::build(
        "barrier",
        &"0".repeat(64),
        &[("barrier".into(), module.to_json().unwrap())],
        &[],
    )
    .unwrap();
    artifact::Artifact::from_bytes(&serde_json::to_vec(&package).unwrap()).unwrap();
    value["target"]["strict_fp_profile"] = json!("scalar_dynamic_mul_v1");
    assert!(NativeModule::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
}
