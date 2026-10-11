//! Structural native-closure conformance for the explicit Itanium interface.
//!
//! These are authored, verified NativeModules. Provider bodies are ABI test
//! skeletons, not implementations of an unwinder or an upstream runtime. The
//! tests qualify inventory, callback adaptation and dependency checking only.

use super::*;
use o_lang::ocore::native_ir::{
    Function, Instruction, Operand, Operation, Terminator, Value as NativeValue,
};

fn source_module(target: &str) -> NativeModule {
    // There is no i64 source type; callback adaptation must not invent one.
    // Parse a literal fixture to avoid macro recursion from nested aggregates.
    let mut fixture: serde_json::Value = serde_json::from_str(r#"{
        "format":"ocore-native-module-v1", "name":"exception-consumer",
        "target":{"triple":"x86_64-unknown-none","data_layout":"e-p:64:64-i32:32-i64:64",
            "pointer_bits":64,"little_endian":true},
        "semantics":"llvm_defined_behavior_v1",
        "types":[{"kind":"void"},{"kind":"int","bits":32},
            {"kind":"pointer","address_space":0},
            {"kind":"struct","fields":[2,1],"packed":false},
            {"kind":"array","element":2,"len":2},
            {"kind":"struct","fields":[4],"packed":true}],
        "globals":[
            {"name":"catch_tag","ty":1,"linkage":"external","alignment":4,
                "constant":true,"thread_local":false,"initializer":null},
            {"name":"filter_tag","ty":1,"linkage":"external","alignment":4,
                "constant":true,"thread_local":false,"initializer":null},
            {"name":"cold_typeid_tag","ty":1,"linkage":"external","alignment":4,
                "constant":true,"thread_local":false,"initializer":null},
            {"name":"cold_argument","ty":1,"linkage":"external","alignment":4,
                "constant":true,"thread_local":false,"initializer":null},
            {"name":"cold_phi_tag","ty":1,"linkage":"external","alignment":4,
                "constant":true,"thread_local":false,"initializer":null},
            {"name":"cold_nested_tag","ty":1,"linkage":"external","alignment":4,
                "constant":true,"thread_local":false,"initializer":null},
            {"name":"local_tag","ty":1,"linkage":"internal","alignment":4,
                "constant":true,"thread_local":false,
                "initializer":{"bytes":[7,0,0,0],"relocations":[]}},
            {"name":"cold_callback","ty":2,"linkage":"internal","alignment":8,
                "constant":true,"thread_local":false,
                "initializer":{"bytes":[0,0,0,0,0,0,0,0],
                    "relocations":[{"offset":0,"width":64,"symbol":"cold_provider","addend":0}]}}
        ],
        "aliases":[{"name":"local_tag_alias","ty":1,"aliasee":"local_tag",
            "linkage":"external"}],
        "functions":[
            {"name":"consumer","linkage":"external",
                "signature":{"params":[],"result":0,"abi":"c","variadic":false},
                "params":[],"entry":10,
                "exception_handling":{"model":"itanium_dwarf_v1",
                    "personality":{"kind":"symbol","ty":2,"name":"source_personality"}},
                "blocks":[
                    {"id":10,"instructions":[],"terminator":{"op":"invoke",
                        "callee":{"kind":"symbol","ty":2,"name":"may_throw"},
                        "signature":{"params":[],"result":0,"abi":"c","variadic":false},
                        "args":[],"result":null,"normal":20,"unwind":30}},
                    {"id":20,"instructions":[],"terminator":{"op":"return","value":null}},
                    {"id":30,"instructions":[{"result":{"id":0,"ty":3},
                        "operation":{"op":"landing_pad","cleanup":true,"clauses":[
                            {"kind":"catch","typeinfo":{"kind":"symbol","ty":2,"name":"catch_tag"}},
                            {"kind":"filter","typeinfos":[
                                {"kind":"symbol","ty":2,"name":"filter_tag"},
                                {"kind":"symbol","ty":2,"name":"filter_tag"}]},
                            {"kind":"catch","typeinfo":{"kind":"null","ty":2}},
                            {"kind":"filter","typeinfos":[]},
                            {"kind":"catch","typeinfo":{"kind":"symbol","ty":2,"name":"local_tag_alias"}}
                        ]}}],"terminator":{"op":"resume","value":{"kind":"value","id":0}}},
                    {"id":40,"instructions":[
                        {"result":{"id":1,"ty":1},"operation":{"op":"eh_type_id",
                            "typeinfo":{"kind":"symbol","ty":2,"name":"cold_typeid_tag"}}},
                        {"result":{"id":2,"ty":5},"operation":{"op":"freeze",
                            "value":{"kind":"aggregate","ty":5,"elements":[
                                {"kind":"aggregate","ty":4,"elements":[
                                    {"kind":"symbol","ty":2,"name":"cold_nested_tag"},
                                    {"kind":"symbol","ty":2,"name":"local_tag_alias"}]}]}}}
                        ],"terminator":{"op":"invoke",
                        "callee":{"kind":"symbol","ty":2,"name":"cold_provider"},
                        "signature":{"params":[2],"result":0,"abi":"c","variadic":false},
                        "args":[{"kind":"symbol","ty":2,"name":"cold_argument"}],
                        "result":null,"normal":50,"unwind":30}},
                    {"id":50,"instructions":[],"terminator":{"op":"return","value":null}},
                    {"id":60,"instructions":[],"terminator":{"op":"jump","target":70}},
                    {"id":70,"instructions":[{"result":{"id":3,"ty":2},
                        "operation":{"op":"phi","incoming":[{"block":60,
                            "value":{"kind":"symbol","ty":2,"name":"cold_phi_tag"}}]}}],
                        "terminator":{"op":"return","value":null}}
                ]},
            {"name":"source_personality","linkage":"external",
                "signature":{"params":[],"result":1,"abi":"c","variadic":true},
                "params":[],"entry":null,"blocks":[]},
            {"name":"may_throw","linkage":"external",
                "signature":{"params":[],"result":0,"abi":"c","variadic":false},
                "params":[],"entry":null,"blocks":[]},
            {"name":"cold_provider","linkage":"external",
                "signature":{"params":[2],"result":0,"abi":"c","variadic":false},
                "params":[{"id":0,"ty":2}],"entry":null,"blocks":[]}
        ],
        "provenance":{"input_sha256":"0000000000000000000000000000000000000000000000000000000000000000","frontend":"authored-structural-test",
            "frontend_version":"1","importer":"authored-structural-test","importer_version":"1",
            "source_function_count":4,"source_global_count":8,"source_alias_count":1,
            "refinements":[]}
    }"#).unwrap();
    fixture["target"]["triple"] = json!(target);
    NativeModule::from_json(&serde_json::to_vec(&fixture).unwrap()).unwrap()
}

fn provider_module(target: &str) -> NativeModule {
    let mut source = source_module(target);
    // Reordered types deliberately demonstrate module-local type-ID isolation.
    source.types = vec![
        Type::Pointer { address_space: 0 },
        Type::Int { bits: 64 },
        Type::Void,
        Type::Int { bits: 32 },
    ];
    source.name = "callback-provider-structural-skeleton".into();
    source.aliases.clear();
    source.globals.retain(|global| global.initializer.is_none());
    for (index, global) in source.globals.iter_mut().enumerate() {
        global.ty = 3;
        global.initializer = Some(o_lang::ocore::native_ir::Initializer {
            bytes: vec![index as u8, 0, 0, 0],
            relocations: vec![],
        });
    }
    let functions = json!([
        {"name":"source_personality","linkage":"external",
            "signature":{"params":[3,3,1,0,0],"result":3,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":3},{"id":1,"ty":3},{"id":2,"ty":1},
                {"id":3,"ty":0},{"id":4,"ty":0}],"entry":10,
            "blocks":[{"id":10,"instructions":[],"terminator":{"op":"return",
                "value":{"kind":"int","ty":3,"bits":"0"}}}]},
        {"name":"may_throw","linkage":"external",
            "signature":{"params":[],"result":2,"abi":"c","variadic":false},
            "params":[],"entry":10,"blocks":[{"id":10,"instructions":[],
                "terminator":{"op":"return","value":null}}]},
        {"name":"cold_provider","linkage":"external",
            "signature":{"params":[0],"result":2,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":0}],"entry":10,"blocks":[{"id":10,"instructions":[],
                "terminator":{"op":"return","value":null}}]},
        {"name":"_Unwind_Resume","linkage":"external",
            "signature":{"params":[0],"result":2,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":0}],"entry":10,"blocks":[{"id":10,"instructions":[],
                "terminator":{"op":"unreachable"}}]}
    ]);
    source.functions = serde_json::from_value(functions).unwrap();
    synchronize_inventory(&mut source);
    o_lang::ocore::native_verify::verify(&source).unwrap();
    source
}

fn synchronize_inventory(module: &mut NativeModule) {
    module.provenance.source_function_count = module.functions.len();
    module.provenance.source_global_count = module.globals.len();
    module.provenance.source_alias_count = module.aliases.len();
}

fn named<'a>(module: &'a mut NativeModule, name: &str) -> &'a mut Function {
    module
        .functions
        .iter_mut()
        .find(|function| function.name == name)
        .unwrap()
}

fn closed(source: &NativeModule, provider: &NativeModule) -> (Value, Vec<String>) {
    o_lang::ocore::native_verify::verify(source).unwrap();
    o_lang::ocore::native_verify::verify(provider).unwrap();
    let mut inputs = symbols("consumer-unit", source).unwrap();
    inputs.extend(symbols("provider-unit", provider).unwrap());
    resolve_symbols(&inputs)
}

fn declaration<'a>(receipt: &'a Value, name: &str) -> &'a Value {
    receipt["declarations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["unit"] == "consumer-unit" && record["symbol"] == name)
        .unwrap()
}

#[test]
fn metadata_personality_is_separately_adapted_without_rewriting_any_source_inventory() {
    for target in [
        "x86_64-unknown-none",
        "aarch64-unknown-none",
        "riscv64-unknown-none",
    ] {
        let source = source_module(target);
        let provider = provider_module(target);
        let source_before = source.to_json().unwrap();
        let provider_before = provider.to_json().unwrap();
        assert!(!source
            .types
            .iter()
            .any(|ty| matches!(ty, Type::Int { bits: 64 })));
        let original = source
            .functions
            .iter()
            .find(|f| f.name == "source_personality")
            .unwrap();
        assert!(original.signature.variadic);
        assert!(original.signature.params.is_empty());
        let original_contract =
            signature_contract(&source, &original.signature, &mut BTreeSet::new()).unwrap();
        let inputs = symbols("consumer-unit", &source).unwrap();
        let adapted = inputs
            .iter()
            .find(|s| s.name == "source_personality")
            .unwrap();
        assert_eq!(adapted.contract, itanium_personality_contract());
        assert_eq!(
            adapted.contract["params"][2],
            json!({"kind":"int","bits":64})
        );
        assert_eq!(
            adapted.abi_adaptation.as_ref().unwrap()["original_contract"],
            original_contract
        );
        assert_eq!(
            adapted.abi_adaptation.as_ref().unwrap()["ordinary_variadic_calls_supported"],
            false
        );
        let (receipt, issues) = closed(&source, &provider);
        assert!(issues.is_empty(), "{target}: {issues:?}");
        assert_eq!(receipt["closed"], true);
        let reference = declaration(&receipt, "source_personality");
        assert_eq!(reference["compatible"], true);
        assert_eq!(reference["resolved_unit"], "provider-unit");
        assert_eq!(
            reference["abi_adaptation"]["kind"],
            "itanium_personality_metadata_declaration"
        );
        assert_eq!(
            reference["abi_adaptation"]["original_contract"],
            original_contract
        );
        assert_eq!(source.to_json().unwrap(), source_before);
        assert_eq!(provider.to_json().unwrap(), provider_before);
        assert_eq!(source.provenance.source_function_count, 4);
        assert_eq!(source.provenance.source_global_count, 8);
        assert_eq!(source.provenance.source_alias_count, 1);
    }
}

#[test]
fn personality_closure_rejects_missing_or_wrong_callback_abi_without_inferred_providers() {
    let source = source_module("x86_64-unknown-none");
    for mutation in [
        "missing",
        "abi",
        "version_width",
        "class_width",
        "result_width",
        "param_attribute",
        "result_attribute",
        "parameter_count",
    ] {
        let mut provider = provider_module("x86_64-unknown-none");
        if mutation == "missing" {
            provider
                .functions
                .retain(|f| f.name != "source_personality");
        } else {
            let function = named(&mut provider, "source_personality");
            match mutation {
                "abi" => function.signature.abi = "fast".into(),
                "version_width" => {
                    function.signature.params[0] = 1;
                    function.params[0].ty = 1;
                }
                "class_width" => {
                    function.signature.params[2] = 3;
                    function.params[2].ty = 3;
                }
                "result_width" => {
                    function.signature.result = 1;
                    function.blocks[0].terminator = Terminator::Return {
                        value: Some(Operand::Int {
                            ty: 1,
                            bits: "0".into(),
                        }),
                    };
                }
                "param_attribute" => {
                    function.signature.param_attributes = vec![vec![]; 5];
                    function.signature.param_attributes[0] = vec!["signext".into()];
                }
                "result_attribute" => function.signature.result_attributes = vec!["zeroext".into()],
                "parameter_count" => {
                    function.signature.params.pop();
                    function.params.pop();
                }
                _ => unreachable!(),
            }
        }
        synchronize_inventory(&mut provider);
        let before = source.to_json().unwrap();
        let (receipt, issues) = closed(&source, &provider);
        assert!(!issues.is_empty(), "{mutation} unexpectedly closed");
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("source_personality")),
            "{mutation}: {issues:?}"
        );
        assert_eq!(receipt["closed"], false);
        assert_eq!(
            declaration(&receipt, "source_personality")["compatible"],
            false
        );
        assert!(declaration(&receipt, "source_personality")["resolved_unit"].is_null());
        assert_eq!(source.to_json().unwrap(), before);
    }
}

#[test]
fn explicit_fixed_personality_is_an_ordinary_contract_without_metadata_adaptation() {
    let mut source = source_module("aarch64-unknown-none");
    source.types.push(Type::Int { bits: 64 });
    let function = named(&mut source, "source_personality");
    function.signature.params = vec![1, 1, 6, 2, 2];
    function.signature.variadic = false;
    function.params = [1, 1, 6, 2, 2]
        .into_iter()
        .enumerate()
        .map(|(id, ty)| NativeValue { id, ty })
        .collect();
    let signature = function.signature.clone();
    source.functions[0].blocks[0]
        .instructions
        .push(Instruction {
            result: Some(NativeValue { id: 90, ty: 1 }),
            operation: Operation::Call {
                callee: Operand::Symbol {
                    ty: 2,
                    name: "source_personality".into(),
                },
                signature,
                args: vec![
                    Operand::Int {
                        ty: 1,
                        bits: "1".into(),
                    },
                    Operand::Int {
                        ty: 1,
                        bits: "2".into(),
                    },
                    Operand::Int {
                        ty: 6,
                        bits: "0".into(),
                    },
                    Operand::Null { ty: 2 },
                    Operand::Null { ty: 2 },
                ],
            },
        });
    let before = source.to_json().unwrap();
    let (receipt, issues) = closed(&source, &provider_module("aarch64-unknown-none"));
    assert!(issues.is_empty(), "{issues:?}");
    assert!(declaration(&receipt, "source_personality")["abi_adaptation"].is_null());
    assert_eq!(
        declaration(&receipt, "source_personality")["contract"],
        itanium_personality_contract()
    );
    assert_eq!(source.to_json().unwrap(), before);
}

#[test]
fn resume_adds_one_explicit_interface_only_for_actual_resume_operations() {
    let mut source = source_module("riscv64-unknown-none");
    let original = source.to_json().unwrap();
    let inputs = symbols("consumer-unit", &source).unwrap();
    let helper = inputs.iter().find(|s| s.name == "_Unwind_Resume").unwrap();
    assert!(!helper.definition);
    assert_eq!(helper.contract, itanium_resume_contract());
    assert_eq!(
        helper.abi_adaptation.as_ref().unwrap()["kind"],
        "compiler_generated_interface"
    );
    assert_eq!(
        helper.abi_adaptation.as_ref().unwrap()["source_operation"],
        "resume"
    );
    assert_eq!(
        helper.abi_adaptation.as_ref().unwrap()["source_function_inventory_changed"],
        false
    );
    assert!(!source.functions.iter().any(|f| f.name == "_Unwind_Resume"));
    assert_eq!(source.to_json().unwrap(), original);
    let mut provider = provider_module("riscv64-unknown-none");
    provider.functions.retain(|f| f.name != "_Unwind_Resume");
    synchronize_inventory(&mut provider);
    let (receipt, issues) = closed(&source, &provider);
    assert!(!issues.is_empty());
    assert_eq!(declaration(&receipt, "_Unwind_Resume")["compatible"], false);
    source.functions[0].blocks[2].terminator = Terminator::Return { value: None };
    assert!(!requires_unwind_resume(&source));
    assert!(symbols("consumer-unit", &source)
        .unwrap()
        .iter()
        .all(|s| s.name != "_Unwind_Resume"));
    let (receipt, issues) = closed(&source, &provider);
    assert!(issues.is_empty(), "{issues:?}");
    assert_eq!(receipt["closed"], true);
}

#[test]
fn unreachable_resume_still_requires_the_real_interface_and_declared_source_abi_is_retained() {
    let mut source = source_module("x86_64-unknown-none");
    source.functions[0].blocks[2].terminator = Terminator::Return { value: None };
    source.functions[0]
        .blocks
        .push(o_lang::ocore::native_ir::Block {
            id: 80,
            instructions: vec![],
            terminator: Terminator::Resume {
                value: Operand::Undef { ty: 3 },
            },
        });
    source.functions.push(
        serde_json::from_value(json!({
            "name":"_Unwind_Resume","linkage":"external",
            "signature":{"params":[2],"result":0,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":2}],"entry":null,"blocks":[]
        }))
        .unwrap(),
    );
    synchronize_inventory(&mut source);
    let before = source.to_json().unwrap();
    let (receipt, issues) = closed(&source, &provider_module("x86_64-unknown-none"));
    assert!(issues.is_empty(), "{issues:?}");
    let declarations: Vec<_> = receipt["declarations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["unit"] == "consumer-unit" && d["symbol"] == "_Unwind_Resume")
        .collect();
    assert_eq!(declarations.len(), 2); // Original declaration plus generated interface.
    assert_eq!(
        declarations
            .iter()
            .filter(|d| d["abi_adaptation"].is_null())
            .count(),
        1
    );
    assert_eq!(
        declarations
            .iter()
            .filter(|d| d["abi_adaptation"]["kind"] == "compiler_generated_interface")
            .count(),
        1
    );
    assert!(declarations.iter().all(|d| d["compatible"] == true));
    assert_eq!(source.to_json().unwrap(), before);
    assert_eq!(source.provenance.source_function_count, 5);
}

#[test]
fn all_clause_typeid_invoke_phi_nested_constant_and_initializer_references_survive_cold_code() {
    let source = source_module("aarch64-unknown-none");
    let expected: BTreeSet<_> = [
        "source_personality",
        "may_throw",
        "cold_provider",
        "catch_tag",
        "filter_tag",
        "local_tag_alias",
        "cold_typeid_tag",
        "cold_argument",
        "cold_phi_tag",
        "cold_nested_tag",
        "_Unwind_Resume",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(function_references(&source.functions[0]), expected);
    let source_before = source.to_json().unwrap();
    let mut provider = provider_module("aarch64-unknown-none");
    let (receipt, issues) = closed(&source, &provider);
    assert!(issues.is_empty(), "{issues:?}");
    let edges = receipt["definition_references"].as_array().unwrap();
    for name in expected {
        assert!(
            edges.iter().any(|edge| edge["unit"] == "consumer-unit"
                && edge["definition"] == "consumer"
                && edge["symbol"] == name
                && edge["resolved"] == true),
            "missing reference {name}"
        );
    }
    assert!(edges
        .iter()
        .any(|edge| edge["definition"] == "cold_callback"
            && edge["symbol"] == "cold_provider"
            && edge["resolved"] == true));
    assert_eq!(source.to_json().unwrap(), source_before); // Including clause order/duplicates.
    for name in [
        "cold_typeid_tag",
        "cold_argument",
        "cold_phi_tag",
        "cold_nested_tag",
        "filter_tag",
        "cold_provider",
    ] {
        let mut missing = provider.clone();
        missing.globals.retain(|g| g.name != name);
        missing.functions.retain(|f| f.name != name);
        synchronize_inventory(&mut missing);
        let (receipt, issues) = closed(&source, &missing);
        assert!(!issues.is_empty(), "missing {name} unexpectedly closed");
        assert!(
            issues.iter().any(|issue| issue.contains(name)),
            "{issues:?}"
        );
        assert!(receipt["definition_references"]
            .as_array()
            .unwrap()
            .iter()
            .any(|edge| edge["definition"] == "consumer"
                && edge["symbol"] == name
                && edge["resolved"] == false));
    }
    // A provider that remains merely a declaration cannot qualify storage.
    provider.globals[0].initializer = None;
    let (receipt, issues) = closed(&source, &provider);
    assert!(!issues.is_empty());
    assert_eq!(declaration(&receipt, "catch_tag")["compatible"], false);
}

#[test]
fn whole_unused_declaration_inventory_requires_real_providers_without_body_filtering() {
    let mut source = source_module("x86_64-unknown-none");
    source.functions.push(
        serde_json::from_value(json!({
            "name":"unused_source_function","linkage":"external",
            "signature":{"params":[],"result":0,"abi":"c","variadic":false},
            "params":[],"entry":null,"blocks":[]
        }))
        .unwrap(),
    );
    source.globals.push(
        serde_json::from_value(json!({
            "name":"unused_source_storage","ty":1,"linkage":"external","alignment":4,
            "constant":true,"thread_local":false,"initializer":null
        }))
        .unwrap(),
    );
    synchronize_inventory(&mut source);
    let mut provider = provider_module("x86_64-unknown-none");
    provider.functions.push(
        serde_json::from_value(json!({
            "name":"unused_source_function","linkage":"external",
            "signature":{"params":[],"result":2,"abi":"c","variadic":false},
            "params":[],"entry":10,"blocks":[{"id":10,"instructions":[],
                "terminator":{"op":"return","value":null}}]
        }))
        .unwrap(),
    );
    provider.globals.push(
        serde_json::from_value(json!({
            "name":"unused_source_storage","ty":3,"linkage":"external","alignment":4,
            "constant":true,"thread_local":false,
            "initializer":{"bytes":[13,0,0,0],"relocations":[]}
        }))
        .unwrap(),
    );
    synchronize_inventory(&mut provider);
    let before = source.to_json().unwrap();
    let references = function_references(&source.functions[0]);
    let (receipt, issues) = closed(&source, &provider);
    assert!(issues.is_empty(), "{issues:?}");
    for name in ["unused_source_function", "unused_source_storage"] {
        assert!(!references.contains(name));
        assert_eq!(declaration(&receipt, name)["compatible"], true);
        let mut missing = provider.clone();
        missing.functions.retain(|function| function.name != name);
        missing.globals.retain(|global| global.name != name);
        synchronize_inventory(&mut missing);
        let (receipt, issues) = closed(&source, &missing);
        assert!(
            !issues.is_empty(),
            "unused declaration {name} was silently omitted"
        );
        assert_eq!(declaration(&receipt, name)["compatible"], false);
    }
    assert_eq!(source.to_json().unwrap(), before);
    assert_eq!(source.provenance.source_function_count, 5);
    assert_eq!(source.provenance.source_global_count, 9);
}

#[test]
fn ordinary_personality_address_escape_is_rejected_even_when_hidden_in_a_cold_constant() {
    let mut source = source_module("x86_64-unknown-none");
    let Operation::Freeze {
        value: Operand::Aggregate { elements, .. },
    } = &mut source.functions[0].blocks[3].instructions[1].operation
    else {
        unreachable!()
    };
    let Operand::Aggregate { elements, .. } = &mut elements[0] else {
        unreachable!()
    };
    elements[0] = Operand::Symbol {
        ty: 2,
        name: "source_personality".into(),
    };
    assert!(o_lang::ocore::native_eh::metadata_personality_declarations(&source).is_empty());
    let error = o_lang::ocore::native_verify::verify(&source).unwrap_err();
    assert!(
        error.message.contains("metadata-only i32(...)"),
        "{}",
        error.message
    );
}

#[test]
fn source_unwind_resume_shadow_requires_the_actual_external_typed_interface() {
    let mut source = source_module("x86_64-unknown-none");
    source.functions.push(
        serde_json::from_value(json!({
            "name":"_Unwind_Resume","linkage":"external",
            "signature":{"params":[2],"result":0,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":2}],"entry":null,"blocks":[]
        }))
        .unwrap(),
    );
    synchronize_inventory(&mut source);
    o_lang::ocore::native_verify::verify(&source).unwrap();
    for mutation in ["abi", "width", "attributes", "local", "visibility"] {
        let mut wrong = source.clone();
        let function = named(&mut wrong, "_Unwind_Resume");
        match mutation {
            "abi" => function.signature.abi = "fast".into(),
            "width" => {
                function.signature.params[0] = 1;
                function.params[0].ty = 1;
            }
            "attributes" => function.signature.result_attributes = vec!["zeroext".into()],
            "local" => function.linkage = "internal".into(),
            "visibility" => function.visibility = Visibility::Hidden,
            _ => unreachable!(),
        }
        let error = o_lang::ocore::native_verify::verify(&wrong).unwrap_err();
        assert!(
            error.message.contains("_Unwind_Resume requires"),
            "{mutation}: {}",
            error.message
        );
    }
}
