//! Compiler-only noalias metadata at the native-runtime admission boundary.
//!
//! The NativeModules and ELF bytes below are independently authored structural
//! fixtures. They qualify inventory/link admission and the absence of marker
//! emission, not frontend import, machine execution, providers, or a runtime.

use super::*;
use o_lang::ocore::driver::Target;
use o_lang::ocore::native_ir::{
    Block, Instruction, NoAliasAttachment, NoAliasDomain, NoAliasIdentity, NoAliasMetadata,
    NoAliasNodeStorage, NoAliasScope, NoAliasScopeList, NoAliasSite, Operand, Operation,
    Terminator, Value as NativeValue, NOALIAS_SCOPE_DECL,
};

const METADATA: usize = 2;
const POINTER: usize = 3;

fn noalias_module(arch: &str) -> NativeModule {
    let mut module = module();
    module.target.triple = format!("{arch}-unknown-none");
    module.types.push(Type::Metadata {});
    module.types.push(Type::Pointer { address_space: 0 });
    module.functions.push(
        serde_json::from_value(json!({
            "name":NOALIAS_SCOPE_DECL,"linkage":"external","intrinsic":NOALIAS_SCOPE_DECL,
            "signature":{"params":[METADATA],"result":0,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":METADATA}],"entry":null,"blocks":[]
        }))
        .unwrap(),
    );
    module.provenance.source_function_count += 1;
    module.noalias_metadata = NoAliasMetadata {
        domains: vec![
            NoAliasDomain {
                id: 0,
                storage: NoAliasNodeStorage::Distinct,
                identity: NoAliasIdentity::SelfReference {},
                description: Some(b"missing_native_provider\0\xff".to_vec()),
            },
            // An unused original node still belongs to the retained graph. Its
            // string identity is neither a symbol nor the self-referential ID.
            NoAliasDomain {
                id: 3,
                storage: NoAliasNodeStorage::Uniqued,
                identity: NoAliasIdentity::Bytes {
                    bytes: vec![0, 255, b'f', b'g'],
                },
                description: None,
            },
        ],
        scopes: vec![NoAliasScope {
            id: 1,
            storage: NoAliasNodeStorage::Distinct,
            identity: NoAliasIdentity::SelfReference {},
            domain: 0,
            description: Some(Vec::new()),
        }],
        lists: vec![NoAliasScopeList {
            id: 2,
            storage: NoAliasNodeStorage::Uniqued,
            scopes: vec![1],
        }],
        attachments: vec![NoAliasAttachment {
            site: NoAliasSite {
                function: "f".into(),
                block: 0,
                instruction: 1,
                instruction_count: 1,
                source_instruction: 1,
            },
            alias_scope: Some(2),
            noalias: None,
        }],
    };
    module.functions[0].blocks[0].instructions = vec![
        Instruction {
            result: None,
            operation: Operation::NoAliasScopeDecl {
                scope_list: 2,
                source_instruction: 0,
            },
        },
        Instruction {
            result: Some(NativeValue { id: 0, ty: 1 }),
            operation: Operation::Freeze {
                value: Operand::Int {
                    ty: 1,
                    bits: "7".into(),
                },
            },
        },
    ];
    module.functions[0].blocks[0].terminator = Terminator::Return {
        value: Some(Operand::Value { id: 0 }),
    };
    module
}

fn verified(module: &NativeModule) {
    o_lang::ocore::native_verify::verify(module).unwrap();
}

fn append_marker_symbol(elf: &mut Elf, binding: u8) -> usize {
    let index = elf.append_alias(NOALIAS_SCOPE_DECL, 1, binding, 0);
    if binding != 0 {
        return index;
    }
    // ELF locals precede globals; do not depend on the admission parser
    // overlooking sh_info while testing a local compiler-only address.
    let first_global = elf.symbols + SYMBOL_BYTES;
    let appended = elf.symbols + index * SYMBOL_BYTES;
    let global = elf.bytes[first_global..first_global + SYMBOL_BYTES].to_vec();
    let local = elf.bytes[appended..appended + SYMBOL_BYTES].to_vec();
    elf.bytes[first_global..first_global + SYMBOL_BYTES].copy_from_slice(&local);
    elf.bytes[appended..appended + SYMBOL_BYTES].copy_from_slice(&global);
    elf.section32(SYMBOLS, 44, 2);
    1
}

fn rejected_before_emission(module: &NativeModule, expected: &str) {
    let diagnostic = o_lang::ocore::native_verify::verify(module).unwrap_err();
    assert!(
        diagnostic.message.contains(expected),
        "expected {expected:?}, got {}",
        diagnostic.message
    );
    for target in [
        Target::X86_64UnknownNone,
        Target::Aarch64UnknownNone,
        Target::Riscv64UnknownNone,
    ] {
        let diagnostic = o_lang::ocore::native_codegen::emit(module, target).unwrap_err();
        assert!(
            diagnostic.message.contains(expected),
            "emitter did not fail at the intended boundary: {}",
            diagnostic.message
        );
    }
}

#[test]
fn retained_metadata_declaration_has_no_runtime_abi_or_native_provider() {
    let module = noalias_module("x86_64");
    verified(&module);
    let source_symbols = symbols("whole-unit", &module).unwrap();
    assert_eq!(source_symbols.len(), 3);
    let marker = source_symbols
        .iter()
        .find(|symbol| symbol.name == NOALIAS_SCOPE_DECL)
        .unwrap();
    assert!(!marker.definition);
    assert!(marker.references.is_empty());
    assert_eq!(marker.contract["params"], json!([{"kind":"metadata"}]));
    assert_eq!(marker.contract["result"], json!({"kind":"void"}));
    let (receipt, issues) = resolve_symbols(&source_symbols);
    assert!(issues.is_empty(), "{issues:?}");
    assert_eq!(receipt["closed"], true);
    assert_eq!(receipt["definitions"].as_array().unwrap().len(), 2);
    let declarations = receipt["declarations"].as_array().unwrap();
    assert_eq!(declarations.len(), 1);
    let declaration = &declarations[0];
    assert_eq!(declaration["symbol"], NOALIAS_SCOPE_DECL);
    assert_eq!(declaration["resolved_provider"], "ocore-native-v1");
    assert_eq!(
        declaration["abi_adaptation"]["kind"],
        "noalias_scope_decl_metadata_declaration"
    );
    for key in [
        "runtime_abi_required",
        "native_symbol_required",
        "alias_promises_used_for_optimization",
    ] {
        assert_eq!(declaration["abi_adaptation"][key], false);
    }
    assert_eq!(
        declaration["abi_adaptation"]["original_contract"],
        marker.contract
    );
    assert!(receipt["definition_references"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(module.functions[1].blocks.is_empty());
    assert_eq!(module.functions[1].params[0].ty, METADATA);
    assert_eq!(module.provenance.source_function_count, 2);
}

#[test]
fn module_local_graph_ids_and_arbitrary_string_bytes_never_link_symbols() {
    let mut a = noalias_module("x86_64");
    let mut b = noalias_module("x86_64");
    for (module, function, global) in [(&mut a, "fa", "ga"), (&mut b, "fb", "gb")] {
        module.functions[0].name = function.into();
        module.globals[0].name = global.into();
        module.noalias_metadata.attachments[0].site.function = function.into();
        verified(module);
        assert!(function_references(&module.functions[0]).is_empty());
    }
    // Each module independently uses domain 0 / scope 1 / list 2. Descriptions
    // and byte identities deliberately resemble unresolved runtime names.
    b.noalias_metadata.domains[0].description = Some(b"another_missing_provider".to_vec());
    verified(&b);
    let roundtrip = NativeModule::from_json(&serde_json::to_vec(&a).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(&roundtrip.noalias_metadata).unwrap(),
        serde_json::to_value(&a.noalias_metadata).unwrap()
    );
    let mut both = symbols("a", &a).unwrap();
    both.extend(symbols("b", &b).unwrap());
    let (receipt, issues) = resolve_symbols(&both);
    assert!(issues.is_empty(), "{issues:?}");
    assert_eq!(receipt["definitions"].as_array().unwrap().len(), 4);
    assert_eq!(receipt["declarations"].as_array().unwrap().len(), 2);
    assert!(receipt["definition_references"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn matching_metadata_description_cannot_satisfy_a_real_native_dependency() {
    let mut module = noalias_module("x86_64");
    module.functions.push(
        serde_json::from_value(json!({
            "name":"missing_native_provider","linkage":"external",
            "signature":{"params":[],"result":0,"abi":"c","variadic":false},
            "params":[],"entry":null,"blocks":[]
        }))
        .unwrap(),
    );
    module.provenance.source_function_count += 1;
    verified(&module);
    let (receipt, issues) = resolve_symbols(&symbols("consumer", &module).unwrap());
    assert_eq!(receipt["closed"], false);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].contains("unresolved or incompatible declaration missing_native_provider"));
}

#[test]
fn metadata_does_not_expand_or_drop_any_native_object_definition() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let module = noalias_module(arch);
        verified(&module);
        let elf = Elf::new(machine, 8, 8);
        let receipt = object_inventory(&elf.bytes, arch, &module).unwrap();
        let definitions = receipt["definitions"].as_array().unwrap();
        assert_eq!(definitions.len(), 2);
        let names: BTreeSet<_> = definitions
            .iter()
            .map(|row| row["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, BTreeSet::from(["f", "g"]));
        assert!(receipt["undefined_symbols"].as_array().unwrap().is_empty());
        assert_eq!(module.functions.len(), 2);
        assert_eq!(module.noalias_metadata.domains.len(), 2);
        let mut omitted = elf.clone();
        omitted.symbol32(1, 0, 0);
        group_rejected(
            &omitted,
            arch,
            &module,
            "ELF definition inventory differs from verified module",
        );
    }
}

#[test]
fn metadata_marker_has_no_extra_code_data_symbols_fixups_or_cfi() {
    for (arch, target) in [
        ("x86_64", Target::X86_64UnknownNone),
        ("aarch64", Target::Aarch64UnknownNone),
        ("riscv64", Target::Riscv64UnknownNone),
    ] {
        let marker = noalias_module(arch);
        verified(&marker);
        let mut executable_only = marker.clone();
        executable_only.functions.pop();
        executable_only.provenance.source_function_count -= 1;
        executable_only.functions[0].blocks[0]
            .instructions
            .remove(0);
        executable_only.noalias_metadata = NoAliasMetadata::default();
        verified(&executable_only);
        // Complete output equality includes CFI, symbol directives, data and
        // fixup expressions. This is an emission invariant, not an execution
        // oracle or a substitute for independent ELF/CFI qualification.
        assert_eq!(
            o_lang::ocore::native_codegen::emit(&marker, target).unwrap(),
            o_lang::ocore::native_codegen::emit(&executable_only, target).unwrap(),
            "compiler-only metadata changed owned output on {arch}"
        );
    }
}

#[test]
fn noalias_decl_cannot_gain_an_undefined_defined_or_local_untyped_elf_address() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let module = noalias_module(arch);
        verified(&module);
        // binding, type, section, size: all records are well formed before the
        // compiler-only-name guard, including the otherwise ignored local label.
        for (binding, kind, section, size) in [
            (1, 0, 0, 0),
            (2, 0, 0, 0),
            (1, 2, TEXT, 8),
            (1, 1, DATA, 8),
            (0, 0, TEXT, 0),
            (0, 2, TEXT, 8),
            (0, 3, TEXT, 0),
        ] {
            let mut elf = Elf::new(machine, 8, 8);
            let symbol = append_marker_symbol(&mut elf, binding);
            elf.symbol8(symbol, 4, (binding << 4) | kind);
            elf.symbol16(symbol, 6, section as u16);
            elf.symbol64(symbol, 16, size);
            group_rejected(
                &elf,
                arch,
                &module,
                "compiler-only metadata declaration a runtime symbol",
            );
        }
    }
}

#[test]
fn descriptive_file_record_cannot_be_used_as_a_metadata_runtime_relocation() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let module = noalias_module(arch);
        verified(&module);
        let mut elf = Elf::new(machine, 8, 8);
        let symbol = append_marker_symbol(&mut elf, 0);
        elf.symbol8(symbol, 4, 4); // Local STT_FILE: descriptive, not executable.
        elf.symbol16(symbol, 6, 0xfff1); // SHN_ABS, ELF's ordinary file-record form.
        elf.symbol64(symbol, 8, 0);
        elf.symbol64(symbol, 16, 0);
        object_inventory(&elf.bytes, arch, &module).unwrap();
        let records = relocation_entry(0, symbol, absolute_relocation_type(machine), 0);
        elf.append_section(4, 0x40, &records, SYMBOLS as u32, TEXT as u32, 8, 24);
        group_rejected(&elf, arch, &module, "compiler-only metadata");
    }
}

#[test]
fn metadata_remains_unsized_even_in_zero_length_storage_and_ordinary_signatures() {
    let module = noalias_module("x86_64");
    verified(&module);
    assert!(o_lang::ocore::native_verify::type_size(&module, METADATA).is_err());
    assert!(o_lang::ocore::native_verify::type_alignment(&module, METADATA).is_err());
    let mut ordinary = module.clone();
    let mut declaration = ordinary.functions[1].clone();
    declaration.name = "ordinary_metadata_consumer".into();
    declaration.intrinsic = None;
    ordinary.functions.push(declaration);
    ordinary.provenance.source_function_count += 1;
    rejected_before_emission(&ordinary, "unsized");
    let mut result = module.clone();
    result.functions[0].signature.result = METADATA;
    rejected_before_emission(&result, "unsized");
    let mut storage = module.clone();
    storage.globals[0].ty = METADATA;
    rejected_before_emission(&storage, "unsized");
    let mut zero_array = module;
    zero_array.types.push(Type::Array {
        element: METADATA,
        len: 0,
    });
    zero_array.globals[0].ty = zero_array.types.len() - 1;
    zero_array.globals[0]
        .initializer
        .as_mut()
        .unwrap()
        .bytes
        .clear();
    rejected_before_emission(&zero_array, "unsized");
}

#[test]
fn compiler_only_declaration_contract_is_not_inferred_from_its_name_alone() {
    let module = noalias_module("x86_64");
    verified(&module);
    for mutate in 0..7 {
        let mut invalid = module.clone();
        let declaration = &mut invalid.functions[1];
        let expected = match mutate {
            0 => {
                declaration.intrinsic = None;
                "intrinsic declaration"
            }
            1 => {
                declaration.signature.abi = "fast".into();
                "metadata intrinsic signature"
            }
            2 => {
                declaration.signature.variadic = true;
                "metadata intrinsic signature"
            }
            3 => {
                declaration.signature.params[0] = POINTER;
                declaration.params[0].ty = POINTER;
                "metadata intrinsic signature"
            }
            4 => {
                declaration.entry = Some(0);
                declaration.blocks = vec![Block {
                    id: 0,
                    instructions: vec![],
                    terminator: Terminator::Return { value: None },
                }];
                "intrinsic declaration"
            }
            5 => {
                declaration.signature.result_attributes = vec!["zeroext".into()];
                "metadata intrinsic signature"
            }
            6 => {
                declaration.visibility = Visibility::Hidden;
                "intrinsic declaration"
            }
            _ => unreachable!(),
        };
        rejected_before_emission(&invalid, expected);
    }
}

#[test]
fn noalias_address_cannot_escape_through_cold_operands_aliases_or_initializers() {
    let module = noalias_module("x86_64");
    verified(&module);
    let mut cold = module.clone();
    cold.functions[0].blocks.push(Block {
        id: 1,
        instructions: vec![Instruction {
            result: Some(NativeValue { id: 9, ty: POINTER }),
            operation: Operation::Freeze {
                value: Operand::Symbol {
                    ty: POINTER,
                    name: NOALIAS_SCOPE_DECL.into(),
                },
            },
        }],
        terminator: Terminator::Unreachable,
    });
    rejected_before_emission(&cold, "intrinsic address");
    let mut alias = module.clone();
    alias.types.push(Type::Function {
        signature: alias.functions[1].signature.clone(),
    });
    alias.aliases.push(Alias {
        name: "address_of_metadata".into(),
        ty: alias.types.len() - 1,
        linkage: "external".into(),
        visibility: Visibility::Default,
        aliasee: NOALIAS_SCOPE_DECL.into(),
    });
    alias.provenance.source_alias_count += 1;
    // An exact retained intrinsic is a declaration. The alias rule rejects
    // this attempt at its requirement for an included emitted definition.
    rejected_before_emission(&alias, "alias target must be an emitted definition");
    let mut initializer = module;
    initializer.globals[0].ty = POINTER;
    initializer.globals[0]
        .initializer
        .as_mut()
        .unwrap()
        .relocations = vec![Relocation {
        offset: 0,
        width: 64,
        symbol: NOALIAS_SCOPE_DECL.into(),
        addend: 0,
        relative_to: None,
    }];
    rejected_before_emission(&initializer, "intrinsic address");
}
