//! Independent scalar min/max wire, ownership, SSA and reference contracts.
//!
//! Authored NativeModules only: these tests do not qualify frontend import,
//! native machine execution, provider closure, or an original compiler engine.
//! LLVM's poison/undef behavior is retained under the existing permitted
//! LlvmDefinedBehaviorV1 concretization, not claimed as literal preservation.

use num_bigint::BigUint;

use crate::ocore::native_interpret;
use crate::ocore::native_ir::{
    Alias, Block, Instruction, IntegerMinMaxKind, NativeModule, Operand, Operation, PhiIncoming,
    ReturnStorage, Terminator, Type, TypeId, Value, ValueId, Visibility, FORMAT,
};
use crate::ocore::native_verify::{integer_minmax_intrinsic, is_builtin_intrinsic, verify};
use serde_json::{json, Value as JsonValue};

const VOID: TypeId = 0;
const I1: TypeId = 1;
const INT: TypeId = 2;
const PTR: TypeId = 3;
const FLOAT: TypeId = 4;
const FUNCTION: TypeId = 5;
const PAIR: TypeId = 6;
const OUTPUT: ValueId = 2;

const KINDS: [(IntegerMinMaxKind, &str); 4] = [
    (IntegerMinMaxKind::Smin, "smin"),
    (IntegerMinMaxKind::Smax, "smax"),
    (IntegerMinMaxKind::Umin, "umin"),
    (IntegerMinMaxKind::Umax, "umax"),
];

fn fixture(bits: u16, kind: IntegerMinMaxKind) -> NativeModule {
    let spelling = KINDS.iter().find(|(value, _)| *value == kind).unwrap().1;
    let name = format!("llvm.{spelling}.i{bits}");
    serde_json::from_value(json!({
        "format":FORMAT,"name":"authored-integer-minmax-contract",
        "target":{"triple":"x86_64-unknown-linux-gnu",
            "data_layout":"e-p:64:64-i64:64","pointer_bits":64,"little_endian":true},
        "semantics":"llvm_defined_behavior_v1",
        "types":[
            {"kind":"void"},{"kind":"int","bits":1},{"kind":"int","bits":bits},
            {"kind":"pointer","address_space":0},{"kind":"float","bits":64},
            {"kind":"function","signature":{"params":[INT,INT],"result":INT,"abi":"c","variadic":false}},
            {"kind":"struct","fields":[INT,I1],"packed":false}
        ],
        "globals":[],
        "functions":[{
            "name":"calculate","linkage":"external",
            "signature":{"params":[INT,INT],"result":INT,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":INT},{"id":1,"ty":INT}],"entry":10,
            "blocks":[{"id":10,"instructions":[{
                "result":{"id":OUTPUT,"ty":INT},
                "operation":{"op":"integer_min_max","kind":spelling,
                    "lhs":{"kind":"value","id":0},"rhs":{"kind":"value","id":1}}
            }],"terminator":{"op":"return","value":{"kind":"value","id":OUTPUT}}}]
        },{
            "name":name,"intrinsic":name,"linkage":"external",
            "signature":{"params":[INT,INT],"result":INT,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":INT},{"id":1,"ty":INT}],"entry":null,"blocks":[]
        }],
        "provenance":{"input_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
            "frontend":"authored-structural-fixture","frontend_version":"1",
            "importer":"authored-structural-fixture","importer_version":"1",
            "source_function_count":2,"source_global_count":0,"refinements":[]}
    }))
    .unwrap()
}

fn value(id: ValueId) -> Operand {
    Operand::Value { id }
}

fn integer(ty: TypeId, bits: u64) -> Operand {
    Operand::Int {
        ty,
        bits: bits.to_string(),
    }
}

fn operation(module: &mut NativeModule) -> &mut Operation {
    &mut module.functions[0].blocks[0].instructions[0].operation
}

fn accepted(module: &NativeModule) {
    verify(module)
        .unwrap_or_else(|error| panic!("valid min/max contract rejected: {}", error.message));
}

fn rejected(module: &NativeModule, expected: &str) {
    let error = verify(module).expect_err("invalid min/max contract was accepted");
    assert!(
        error.message.contains(expected),
        "expected {expected:?}, got {}",
        error.message
    );
}

fn mask(bits: u16) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1_u64 << bits) - 1
    }
}

fn signed(bits: u16, value: u64) -> i128 {
    let modulus = 1_i128 << bits;
    let value = i128::from(value);
    if value >= modulus / 2 {
        value - modulus
    } else {
        value
    }
}

fn expected(kind: IntegerMinMaxKind, bits: u16, lhs: u64, rhs: u64) -> u64 {
    // Independent host mathematics: no verifier/interpreter comparison helper
    // or production predicate enum supplies the expected ordering.
    let chosen = match kind {
        IntegerMinMaxKind::Smin => std::cmp::min(signed(bits, lhs), signed(bits, rhs)),
        IntegerMinMaxKind::Smax => std::cmp::max(signed(bits, lhs), signed(bits, rhs)),
        IntegerMinMaxKind::Umin => i128::from(std::cmp::min(lhs, rhs)),
        IntegerMinMaxKind::Umax => i128::from(std::cmp::max(lhs, rhs)),
    };
    (chosen as u128 & u128::from(mask(bits))) as u64
}

fn calculate(module: &NativeModule, lhs: u64, rhs: u64) -> BigUint {
    native_interpret::evaluate(
        module,
        "calculate",
        &[BigUint::from(lhs), BigUint::from(rhs)],
    )
    .unwrap()
    .unwrap()
}

#[test]
fn all_four_operations_retain_every_width_declaration_and_original_inventory() {
    for bits in 1..=64 {
        for (kind, spelling) in KINDS {
            let module = fixture(bits, kind);
            let name = format!("llvm.{spelling}.i{bits}");
            assert_eq!(integer_minmax_intrinsic(&name), Some((kind, bits)));
            assert!(is_builtin_intrinsic(&name));
            accepted(&module);
            let restored = NativeModule::from_json(&module.to_json().unwrap()).unwrap();
            assert_eq!(restored.provenance.source_function_count, 2);
            assert_eq!(restored.functions.len(), 2);
            assert_eq!(restored.functions[1].name, name);
            assert_eq!(
                restored.functions[1].intrinsic.as_deref(),
                Some(name.as_str())
            );
            assert!(restored.functions[1].entry.is_none());
            assert!(
                matches!(restored.functions[0].blocks[0].instructions[0].operation,
                Operation::IntegerMinMax { kind: actual, .. } if actual == kind)
            );
            assert_eq!(serde_json::to_value(kind).unwrap(), json!(spelling));
        }
    }
}

#[test]
fn canonical_names_are_required_and_legal_but_unrealized_llvm_widths_stay_distinct() {
    for (_, spelling) in KINDS {
        for suffix in [
            "i0",
            "i65",
            "i128",
            "i65535",
            "i01",
            "i064",
            "i+21",
            "i-1",
            "i21.trailing",
            "i21.i21",
            "v4i21",
            "nxv4i21",
            "i",
            "I21",
        ] {
            let name = format!("llvm.{spelling}.{suffix}");
            assert_eq!(integer_minmax_intrinsic(&name), None, "{name}");
            let mut invalid = fixture(21, IntegerMinMaxKind::Umin);
            invalid.functions[1].name = name.clone();
            invalid.functions[1].intrinsic = Some(name);
            rejected(
                &invalid,
                if suffix.contains('+') || suffix.contains('-') {
                    "assembler-safe spelling"
                } else {
                    "intrinsic declaration"
                },
            );
        }
    }
    for name in [
        "smin.i21",
        "llvm.min.i21",
        "llvm.max.i21",
        "llvm.fmin.i21",
        "llvm.Smin.i21",
        "llvm.smin.i21extra",
        "llvm.smin.i21\0",
    ] {
        assert_eq!(integer_minmax_intrinsic(name), None, "{name:?}");
    }
}

#[test]
fn scalar_operations_preserve_the_original_width_instead_of_allocation_size() {
    for (kind, _) in KINDS {
        for bits in [1, 9, 16, 17, 21, 24, 33, 40, 63, 64] {
            let mut module = fixture(bits, kind);
            // Legal integer ABI padding does not change comparison width.
            module.target.data_layout = "e-p:64:64-i16:64-i24:32-i64:64".into();
            accepted(&module);
            let sign = 1_u64 << (bits - 1);
            assert_eq!(
                calculate(&module, sign, 0),
                BigUint::from(expected(kind, bits, sign, 0))
            );
        }
    }
}

#[test]
fn operands_and_result_require_the_same_integer_type() {
    for (kind, _) in KINDS {
        let module = fixture(21, kind);
        for side in [false, true] {
            let mut invalid = module.clone();
            let Operation::IntegerMinMax { lhs, rhs, .. } = operation(&mut invalid) else {
                unreachable!()
            };
            *if side { lhs } else { rhs } = integer(I1, 0);
            rejected(&invalid, "type mismatch");
        }
        let mut invalid = module;
        invalid.functions[0].blocks[0].instructions[0]
            .result
            .as_mut()
            .unwrap()
            .ty = I1;
        invalid.functions[0].signature.result = I1;
        rejected(&invalid, "type mismatch");
    }
}

#[test]
fn equal_structural_integer_types_do_not_require_one_inventory_index() {
    let mut module = fixture(21, IntegerMinMaxKind::Smax);
    let equivalent = module.types.len();
    module.types.push(Type::Int { bits: 21 });
    let Operation::IntegerMinMax { lhs, rhs, .. } = operation(&mut module) else {
        unreachable!()
    };
    *lhs = integer(equivalent, 1);
    *rhs = integer(INT, 2);
    accepted(&module);
    assert_eq!(calculate(&module, 0, 0), BigUint::from(2_u8));
}

#[test]
fn wide_pointer_float_and_aggregate_operands_do_not_become_integer_minmax() {
    for (kind, _) in KINDS {
        let original = fixture(21, kind);
        for ty in [PTR, FLOAT, PAIR] {
            let mut invalid = original.clone();
            invalid.functions[0].signature.params = vec![ty, ty];
            invalid.functions[0].signature.result = ty;
            invalid.functions[0]
                .params
                .iter_mut()
                .for_each(|value| value.ty = ty);
            invalid.functions[0].blocks[0].instructions[0]
                .result
                .as_mut()
                .unwrap()
                .ty = ty;
            rejected(
                &invalid,
                "integer min/max requires same-type scalar i1..i64",
            );
        }
        for bits in [65, 128, 256] {
            let mut invalid = original.clone();
            let ty = invalid.types.len();
            invalid.types.push(Type::Int { bits });
            invalid.functions[0].signature.params = vec![ty, ty];
            invalid.functions[0].signature.result = ty;
            invalid.functions[0]
                .params
                .iter_mut()
                .for_each(|value| value.ty = ty);
            invalid.functions[0].blocks[0].instructions[0]
                .result
                .as_mut()
                .unwrap()
                .ty = ty;
            rejected(
                &invalid,
                "integer min/max requires same-type scalar i1..i64",
            );
        }
    }
}

#[test]
fn metadata_and_function_values_have_no_executable_minmax_storage() {
    for ty in [
        Type::Metadata {},
        Type::Function {
            signature: fixture(21, IntegerMinMaxKind::Umin).functions[0]
                .signature
                .clone(),
        },
    ] {
        let mut invalid = fixture(21, IntegerMinMaxKind::Umin);
        let id = invalid.types.len();
        invalid.types.push(ty);
        invalid.functions[0].blocks[0].instructions[0]
            .result
            .as_mut()
            .unwrap()
            .ty = id;
        rejected(&invalid, "unsized");
    }
}

#[test]
fn zero_width_and_out_of_range_literal_bits_are_rejected() {
    let mut invalid = fixture(1, IntegerMinMaxKind::Smin);
    invalid.types[INT] = Type::Int { bits: 0 };
    rejected(&invalid, "zero-width integer");
    for bits in 1..=64 {
        let mut invalid = fixture(bits, IntegerMinMaxKind::Umax);
        let Operation::IntegerMinMax { lhs, .. } = operation(&mut invalid) else {
            unreachable!()
        };
        *lhs = Operand::Int {
            ty: INT,
            bits: (1_u128 << bits).to_string(),
        };
        rejected(&invalid, "integer constant exceeds its bit width");
    }
}

#[test]
fn intrinsic_declarations_are_exactly_owned_not_optional_native_providers() {
    for (kind, _) in KINDS {
        let original = fixture(21, kind);
        for mutation in 0..12 {
            let mut invalid = original.clone();
            let declaration = &mut invalid.functions[1];
            match mutation {
                0 => declaration.intrinsic = None,
                1 => declaration.intrinsic = Some("llvm.smin.i1".into()),
                2 => declaration.signature.params[0] = I1,
                3 => declaration.signature.result = I1,
                4 => declaration.signature.params.truncate(1),
                5 => declaration.signature.params.push(INT),
                6 => declaration.signature.variadic = true,
                7 => declaration.signature.abi = "fastcc".into(),
                8 => declaration.linkage = "weak".into(),
                9 => declaration.visibility = Visibility::Hidden,
                10 => declaration.signature.param_attributes = vec![vec!["zeroext".into()], vec![]],
                11 => declaration.signature.result_attributes = vec!["signext".into()],
                _ => unreachable!(),
            }
            rejected(&invalid, "intrinsic declaration");
        }
    }
}

#[test]
fn declarations_cannot_supply_implementations_or_hidden_return_storage() {
    for (kind, _) in KINDS {
        let original = fixture(21, kind);
        let mut invalid = original.clone();
        invalid.functions[1].entry = Some(10);
        invalid.functions[1].blocks = original.functions[0].blocks.clone();
        rejected(&invalid, "intrinsic declaration");
        let mut invalid = original.clone();
        invalid.functions[1].blocks = original.functions[0].blocks.clone();
        rejected(&invalid, "declaration has a body");
        let mut invalid = original;
        let declaration = &mut invalid.functions[1];
        declaration.signature.params = vec![PTR, INT];
        declaration.signature.result = VOID;
        declaration.signature.return_storage = Some(ReturnStorage { param: 0, ty: PAIR });
        declaration.params = vec![Value { id: 0, ty: PTR }, Value { id: 1, ty: INT }];
        rejected(&invalid, "intrinsic declaration");
    }
}

#[test]
fn ordinary_calls_and_global_relocations_cannot_escape_intrinsic_addresses() {
    for (kind, _) in KINDS {
        let original = fixture(21, kind);
        let name = original.functions[1].name.clone();
        let mut invalid = original.clone();
        invalid.functions[0].blocks[0].instructions[0].operation = Operation::Call {
            callee: Operand::Symbol {
                ty: PTR,
                name: name.clone(),
            },
            signature: original.functions[1].signature.clone(),
            args: vec![value(0), value(1)],
        };
        rejected(&invalid, "intrinsic address");
        let mut invalid = original;
        invalid.globals.push(
            serde_json::from_value(json!({
                "name":"escaped_intrinsic","ty":PTR,"linkage":"external","alignment":8,
                "constant":true,"thread_local":false,
                "initializer":{"bytes":[0,0,0,0,0,0,0,0],
                    "relocations":[{"offset":0,"width":64,"symbol":name,"addend":0}]}
            }))
            .unwrap(),
        );
        invalid.provenance.source_global_count = 1;
        rejected(&invalid, "relocation cannot reference an intrinsic address");
    }
}

#[test]
fn cold_nested_constants_terminators_and_aliases_cannot_escape_intrinsics() {
    let original = fixture(21, IntegerMinMaxKind::Smax);
    let name = original.functions[1].name.clone();
    let mut invalid = original.clone();
    let nested = invalid.types.len();
    invalid.types.push(Type::Struct {
        fields: vec![PTR, INT],
        packed: true,
    });
    invalid.functions[0].blocks.push(Block {
        id: 90,
        instructions: vec![Instruction {
            result: Some(Value { id: 90, ty: nested }),
            operation: Operation::Freeze {
                value: Operand::Aggregate {
                    ty: nested,
                    elements: vec![
                        Operand::Symbol {
                            ty: PTR,
                            name: name.clone(),
                        },
                        integer(INT, 0),
                    ],
                },
            },
        }],
        terminator: Terminator::Unreachable,
    });
    rejected(&invalid, "intrinsic address");
    let mut invalid = original.clone();
    invalid.functions[0].signature.result = PTR;
    invalid.functions[0].blocks[0].terminator = Terminator::Return {
        value: Some(Operand::SymbolOffset {
            ty: PTR,
            name: name.clone(),
            addend: 0,
        }),
    };
    rejected(&invalid, "intrinsic address");
    let mut invalid = original.clone();
    invalid.functions[0].blocks.push(Block {
        id: 90,
        instructions: vec![Instruction {
            result: Some(Value { id: 90, ty: PTR }),
            operation: Operation::Phi {
                incoming: vec![PhiIncoming {
                    block: 90,
                    value: Operand::Symbol {
                        ty: PTR,
                        name: name.clone(),
                    },
                }],
            },
        }],
        terminator: Terminator::Jump { target: 90 },
    });
    rejected(&invalid, "intrinsic address");
    let mut invalid = original;
    invalid.aliases.push(Alias {
        name: "escaped_alias".into(),
        ty: FUNCTION,
        aliasee: name,
        linkage: "external".into(),
        visibility: Visibility::Default,
    });
    invalid.provenance.source_alias_count = 1;
    // An owned declaration has no emitted body to which an alias can attach.
    rejected(&invalid, "alias target must be an emitted definition");
}

#[test]
fn unused_intrinsic_declarations_and_unreachable_operations_are_audited() {
    let mut valid = fixture(21, IntegerMinMaxKind::Umin);
    valid.functions[0].blocks.push(Block {
        id: 90,
        instructions: vec![Instruction {
            result: Some(Value { id: 90, ty: INT }),
            operation: Operation::IntegerMinMax {
                kind: IntegerMinMaxKind::Smax,
                lhs: value(0),
                rhs: value(1),
            },
        }],
        terminator: Terminator::Unreachable,
    });
    accepted(&valid);
    let mut invalid = valid.clone();
    let Operation::IntegerMinMax { rhs, .. } =
        &mut invalid.functions[0].blocks[1].instructions[0].operation
    else {
        unreachable!()
    };
    *rhs = value(999);
    rejected(&invalid, "undefined SSA value 999");
    let mut invalid = valid.clone();
    invalid.functions[1].signature.result = I1;
    rejected(&invalid, "intrinsic declaration");
    let mut invalid = valid;
    invalid.functions.pop();
    rejected(&invalid, "source declaration/definition inventory");
}

#[test]
fn output_presence_parameter_inventory_and_unique_ssa_ids_are_checked() {
    let original = fixture(21, IntegerMinMaxKind::Smin);
    let mut invalid = original.clone();
    invalid.functions[0].blocks[0].instructions[0].result = None;
    // Make the return independent, so the missing result guard is isolated.
    invalid.functions[0].blocks[0].terminator = Terminator::Return {
        value: Some(integer(INT, 0)),
    };
    rejected(&invalid, "requires an SSA result");
    let mut invalid = original.clone();
    invalid.functions[0].params[0].ty = PTR;
    rejected(&invalid, "type mismatch");
    let mut invalid = original;
    invalid.functions[0].blocks[0].instructions[0]
        .result
        .as_mut()
        .unwrap()
        .id = 0;
    rejected(&invalid, "duplicate SSA definition");
}

#[test]
fn self_reference_forward_reference_and_unknown_operands_cannot_pass_ssa_checks() {
    let original = fixture(21, IntegerMinMaxKind::Umax);
    for (id, diagnostic) in [(OUTPUT, "does not dominate"), (999, "undefined SSA value")] {
        let mut invalid = original.clone();
        let Operation::IntegerMinMax { lhs, .. } = operation(&mut invalid) else {
            unreachable!()
        };
        *lhs = value(id);
        rejected(&invalid, diagnostic);
    }
    let mut invalid = original;
    let Operation::IntegerMinMax { rhs, .. } = operation(&mut invalid) else {
        unreachable!()
    };
    *rhs = value(4);
    invalid.functions[0].blocks[0]
        .instructions
        .push(Instruction {
            result: Some(Value { id: 4, ty: INT }),
            operation: Operation::Freeze { value: value(0) },
        });
    rejected(&invalid, "does not dominate");
}

#[test]
fn branch_values_require_phi_edges_before_a_join_minmax_operation() {
    let mut module = fixture(21, IntegerMinMaxKind::Smin);
    let function = &mut module.functions[0];
    function.signature.params.push(I1);
    function.params.push(Value { id: 7, ty: I1 });
    function.blocks = vec![
        Block {
            id: 10,
            instructions: vec![],
            terminator: Terminator::Branch {
                condition: value(7),
                on_true: 20,
                on_false: 30,
            },
        },
        Block {
            id: 20,
            instructions: vec![Instruction {
                result: Some(Value { id: 20, ty: INT }),
                operation: Operation::IntegerMinMax {
                    kind: IntegerMinMaxKind::Smin,
                    lhs: value(0),
                    rhs: value(1),
                },
            }],
            terminator: Terminator::Jump { target: 40 },
        },
        Block {
            id: 30,
            instructions: vec![Instruction {
                result: Some(Value { id: 30, ty: INT }),
                operation: Operation::IntegerMinMax {
                    kind: IntegerMinMaxKind::Smax,
                    lhs: value(0),
                    rhs: value(1),
                },
            }],
            terminator: Terminator::Jump { target: 40 },
        },
        Block {
            id: 40,
            instructions: vec![
                Instruction {
                    result: Some(Value { id: 35, ty: INT }),
                    operation: Operation::Phi {
                        incoming: vec![
                            PhiIncoming {
                                block: 20,
                                value: value(20),
                            },
                            PhiIncoming {
                                block: 30,
                                value: value(30),
                            },
                        ],
                    },
                },
                Instruction {
                    result: Some(Value { id: 40, ty: INT }),
                    operation: Operation::IntegerMinMax {
                        kind: IntegerMinMaxKind::Umax,
                        lhs: value(35),
                        rhs: value(0),
                    },
                },
            ],
            terminator: Terminator::Return {
                value: Some(value(40)),
            },
        },
    ];
    accepted(&module);
    let mut invalid = module.clone();
    let Operation::IntegerMinMax { lhs, .. } =
        &mut invalid.functions[0].blocks[3].instructions[1].operation
    else {
        unreachable!()
    };
    *lhs = value(20);
    rejected(&invalid, "does not dominate");
    let mut invalid = module;
    let Operation::Phi { incoming } = &mut invalid.functions[0].blocks[3].instructions[0].operation
    else {
        unreachable!()
    };
    incoming[1].value = value(20);
    rejected(&invalid, "does not dominate");
}

#[test]
fn strict_operation_wire_rejects_unrelated_arithmetic_and_atomic_fields() {
    let valid = json!({"op":"integer_min_max","kind":"smin",
        "lhs":{"kind":"int","ty":INT,"bits":"0"},"rhs":{"kind":"int","ty":INT,"bits":"1"}});
    for (key, value) in [
        ("signed", json!(true)),
        ("predicate", json!("slt")),
        ("flags", json!(["nsw"])),
        ("width", json!(21)),
        ("ordering", json!("seq_cst")),
        ("volatile", json!(false)),
        ("pointer", json!({"kind":"null","ty":PTR})),
    ] {
        let mut input = valid.clone();
        input[key] = value;
        assert!(
            serde_json::from_value::<Operation>(input).is_err(),
            "accepted extraneous min/max {key}"
        );
    }
    for key in ["kind", "lhs", "rhs"] {
        let mut input = valid.clone();
        input.as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<Operation>(input).is_err(),
            "accepted missing {key}"
        );
    }
    for kind in ["min", "max", "fmin", "sMin", "Smin", "saturating_min"] {
        let mut input = valid.clone();
        input["kind"] = json!(kind);
        assert!(
            serde_json::from_value::<Operation>(input).is_err(),
            "accepted unowned kind {kind}"
        );
    }
}

#[test]
fn strict_module_wire_cannot_relabel_minmax_as_a_profile_or_override_its_type() {
    let original = fixture(21, IntegerMinMaxKind::Umin);
    let wire = serde_json::to_value(&original).unwrap();
    for (key, value) in [
        ("signed", json!(true)),
        ("flags", json!([])),
        ("result_type", json!(I1)),
    ] {
        let mut input = wire.clone();
        input["functions"][0]["blocks"][0]["instructions"][0]["operation"][key] = value;
        let error = NativeModule::from_json(&serde_json::to_vec(&input).unwrap()).unwrap_err();
        assert!(
            error.message.contains("invalid native module"),
            "{}",
            error.message
        );
    }
    let mut input = wire;
    input["semantics"] = JsonValue::String("literal_poison_preservation".into());
    assert!(NativeModule::from_json(&serde_json::to_vec(&input).unwrap()).is_err());
}

#[test]
fn signed_i1_has_or_and_identities_while_unsigned_i1_has_and_or_identities() {
    for lhs in 0..=1_u64 {
        for rhs in 0..=1_u64 {
            for (kind, result) in [
                (IntegerMinMaxKind::Smin, lhs | rhs),
                (IntegerMinMaxKind::Smax, lhs & rhs),
                (IntegerMinMaxKind::Umin, lhs & rhs),
                (IntegerMinMaxKind::Umax, lhs | rhs),
            ] {
                assert_eq!(
                    calculate(&fixture(1, kind), lhs, rhs),
                    BigUint::from(result)
                );
            }
        }
    }
}

#[test]
fn interpreter_matches_independent_integer_order_for_every_supported_width() {
    for bits in 1..=64 {
        let full = mask(bits);
        let mut values = if bits <= 5 {
            (0..=full).collect::<Vec<_>>()
        } else {
            let sign = 1_u64 << (bits - 1);
            vec![0, 1, 2, full, full - 1, sign, sign - 1, (sign + 1) & full]
        };
        if bits > 5 {
            let mut noise = 0x243f_6a88_85a3_08d3_u64 ^ u64::from(bits);
            for _ in 0..4 {
                noise = noise.wrapping_mul(0x9e37_79b1_85eb_ca87).rotate_left(17);
                values.push(noise & full);
            }
        }
        values.sort_unstable();
        values.dedup();
        for (kind, _) in KINDS {
            let module = fixture(bits, kind);
            for &lhs in &values {
                for &rhs in &values {
                    assert_eq!(
                        calculate(&module, lhs, rhs),
                        BigUint::from(expected(kind, bits, lhs, rhs)),
                        "{kind:?} i{bits} ({lhs},{rhs})"
                    );
                }
            }
        }
    }
}

#[test]
fn equal_inputs_commutation_and_defined_extremal_bounds_preserve_input_bits() {
    for bits in 1..=64 {
        let full = mask(bits);
        let sign = 1_u64 << (bits - 1);
        for (kind, _) in KINDS {
            let module = fixture(bits, kind);
            for value in [0, 1, full, sign, sign - 1] {
                assert_eq!(calculate(&module, value, value), BigUint::from(value));
                assert_eq!(
                    calculate(&module, value, sign),
                    calculate(&module, sign, value)
                );
                let bound = match kind {
                    IntegerMinMaxKind::Smin => sign,
                    IntegerMinMaxKind::Smax => sign - 1,
                    IntegerMinMaxKind::Umin => 0,
                    IntegerMinMaxKind::Umax => full,
                };
                assert_eq!(calculate(&module, value, bound), BigUint::from(bound));
            }
        }
    }
}

#[test]
fn undef_and_poison_are_typed_operands_with_a_permitted_stable_zero_refinement() {
    for bits in [1, 9, 21, 33, 63, 64] {
        for (kind, _) in KINDS {
            for poison in [false, true] {
                for side in [false, true] {
                    let mut module = fixture(bits, kind);
                    let source = if poison {
                        Operand::Poison { ty: INT }
                    } else {
                        Operand::Undef { ty: INT }
                    };
                    let Operation::IntegerMinMax { lhs, rhs, .. } = operation(&mut module) else {
                        unreachable!()
                    };
                    *if side { lhs } else { rhs } = source;
                    accepted(&module);
                    let restored = NativeModule::from_json(&module.to_json().unwrap()).unwrap();
                    let Operation::IntegerMinMax { lhs, rhs, .. } =
                        &restored.functions[0].blocks[0].instructions[0].operation
                    else {
                        unreachable!()
                    };
                    assert!(
                        matches!(if side { lhs } else { rhs }, Operand::Poison { ty: INT })
                            == poison
                    );
                    assert!(
                        matches!(if side { lhs } else { rhs }, Operand::Undef { ty: INT })
                            != poison
                    );
                    for other in [0, 1, mask(bits), 1_u64 << (bits - 1)] {
                        let result = calculate(&restored, other, other);
                        assert_eq!(result, BigUint::from(expected(kind, bits, 0, other)));
                        // For undef, this concrete result respects the bound on
                        // the defined operand. Poison may refine to these bits;
                        // no assertion claims the source intrinsically returns
                        // a defined bit pattern instead of propagating poison.
                    }
                }
            }
        }
    }
}

#[test]
fn explicitly_frozen_undef_is_materialized_once_before_minmax_use() {
    for (kind, _) in KINDS {
        let mut module = fixture(21, kind);
        let Operation::IntegerMinMax { lhs, .. } = operation(&mut module) else {
            unreachable!()
        };
        *lhs = value(4);
        module.functions[0].blocks[0].instructions.insert(
            0,
            Instruction {
                result: Some(Value { id: 4, ty: INT }),
                operation: Operation::Freeze {
                    value: Operand::Undef { ty: INT },
                },
            },
        );
        accepted(&module);
        for bound in [0, 1, (1 << 20) - 1, 1 << 20, (1 << 21) - 1] {
            assert_eq!(
                calculate(&module, 0, bound),
                BigUint::from(expected(kind, 21, 0, bound))
            );
        }
    }
}
