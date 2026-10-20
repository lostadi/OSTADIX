//! Structural admission tests; these providers do not qualify helper arithmetic.
use super::*;

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
