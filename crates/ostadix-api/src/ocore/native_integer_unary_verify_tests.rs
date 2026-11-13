//! Authored structural/reference assertions for exact scalar ctlz and abs.
//! These do not qualify any original runtime, linked provider or native ISA.
use super::*;
use crate::ocore::{native_codegen, native_interpret, Target};
use serde_json::json;

fn fixture(bits: u16, count: bool, flag: bool) -> NativeModule {
    let family = if count { "ctlz" } else { "abs" };
    let name = format!("llvm.{family}.i{bits}");
    let operation = if count {
        json!({"op":"integer_count_leading_zeros","value":{"kind":"value","id":0},"zero_is_poison":flag})
    } else {
        json!({"op":"integer_abs","value":{"kind":"value","id":0},"int_min_is_poison":flag})
    };
    serde_json::from_value(json!({
        "format":"ocore-native-module-v1","name":"authored-integer-unary",
        "target":{"triple":"x86_64-unknown-linux-gnu","data_layout":"e-p:64:64-i64:64","pointer_bits":64,"little_endian":true},
        "semantics":"llvm_defined_behavior_v1",
        "types":[{"kind":"void"},{"kind":"int","bits":1},{"kind":"int","bits":bits}],
        "globals":[],"functions":[{
            "name":"calculate","linkage":"external",
            "signature":{"params":[2],"result":2,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":2}],"entry":0,
            "blocks":[{"id":0,"instructions":[{"result":{"id":1,"ty":2},"operation":operation}],
                "terminator":{"op":"return","value":{"kind":"value","id":1}}}]
        },{
            "name":name,"intrinsic":name,"linkage":"external",
            "signature":{"params":[2,1],"result":2,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":2},{"id":1,"ty":1}],"entry":null,"blocks":[]
        }],
        "provenance":{"input_sha256":"0".repeat(64),"frontend":"authored structural fixture","frontend_version":"1",
            "importer":"authored structural fixture","importer_version":"1","source_function_count":2,"source_global_count":0,"refinements":[]}
    })).unwrap()
}

#[test]
fn integer_unary_exact_wire_flags_and_canonical_declarations_are_required() {
    for bits in [32, 64] {
        for count in [false, true] {
            for flag in [false, true] {
                let module = fixture(bits, count, flag);
                verify(&module).unwrap();
                let name = &module.functions[1].name;
                assert_eq!(integer_unary_intrinsic(name), Some((count, bits)));
                assert!(is_builtin_intrinsic(name));
                let mut wire = serde_json::to_value(&module).unwrap();
                let field = if count {
                    "zero_is_poison"
                } else {
                    "int_min_is_poison"
                };
                wire["functions"][0]["blocks"][0]["instructions"][0]["operation"]
                    .as_object_mut()
                    .unwrap()
                    .remove(field);
                assert!(serde_json::from_value::<NativeModule>(wire).is_err());
            }
        }
    }
    for name in [
        "llvm.ctlz.i032",
        "llvm.abs.i064",
        "llvm.ctlz.i16",
        "llvm.abs.i128",
        "llvm.ctlz.v2i32",
    ] {
        assert_eq!(integer_unary_intrinsic(name), None);
        assert!(!is_builtin_intrinsic(name));
    }
}

#[test]
fn integer_unary_defined_boundaries_and_permitted_poison_refinement_match_mathematics() {
    for bits in [32u16, 64] {
        for count in [false, true] {
            for flag in [false, true] {
                let module = fixture(bits, count, flag);
                let mask = if bits == 64 {
                    u64::MAX
                } else {
                    (1u64 << bits) - 1
                };
                let mut values = vec![
                    0,
                    1,
                    2,
                    3,
                    mask,
                    mask >> 1,
                    1u64 << (bits - 1),
                    (1u64 << (bits - 1)) + 1,
                ];
                for shift in 0..bits {
                    let power = 1u64 << shift;
                    values.extend([power, power.wrapping_sub(1), power.wrapping_add(1) & mask]);
                }
                let mut seed = 0x1f4826a995ea713bu64;
                for _ in 0..128 {
                    seed = seed
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    values.push(seed & mask);
                }
                for value in values {
                    // Host integer primitives form the independent mathematical oracle.
                    // At true-flag boundaries this checks the explicitly chosen allowed
                    // concretization, not equality to a source poison bit pattern.
                    let expected = if count {
                        u64::from(value.leading_zeros()) - (64 - u64::from(bits))
                    } else {
                        let signed = if value & (1u64 << (bits - 1)) != 0 {
                            i128::from(value) - (1i128 << bits)
                        } else {
                            i128::from(value)
                        };
                        (signed.unsigned_abs() as u64) & mask
                    };
                    let actual =
                        native_interpret::evaluate(&module, "calculate", &[BigUint::from(value)])
                            .unwrap()
                            .unwrap();
                    assert_eq!(
                        actual,
                        BigUint::from(expected),
                        "bits={bits} count={count} flag={flag} value={value}"
                    );
                }
            }
        }
    }
}

#[test]
fn integer_unary_rejects_unsupported_widths_result_types_and_unknown_ssa_even_when_dead() {
    for bits in [1, 16, 33, 128] {
        for count in [false, true] {
            assert!(verify(&fixture(bits, count, false)).is_err());
        }
    }
    for count in [false, true] {
        let mut module = fixture(64, count, false);
        module.functions[0].blocks[0].instructions[0]
            .result
            .as_mut()
            .unwrap()
            .ty = 1;
        assert!(verify(&module).is_err());
        let mut module = fixture(64, count, false);
        match &mut module.functions[0].blocks[0].instructions[0].operation {
            Operation::IntegerAbs { value, .. }
            | Operation::IntegerCountLeadingZeros { value, .. } => {
                *value = Operand::Value { id: 99 }
            }
            _ => unreachable!(),
        }
        assert!(verify(&module).is_err());
        let mut module = fixture(64, count, false);
        let ty = module.types.len();
        module.types.push(Type::Int { bits: 16 });
        module.functions[0].blocks.push(Block {
            id: 7,
            instructions: vec![Instruction {
                result: Some(Value { id: 99, ty }),
                operation: if count {
                    Operation::IntegerCountLeadingZeros {
                        value: Operand::Int {
                            ty,
                            bits: "0".into(),
                        },
                        zero_is_poison: false,
                    }
                } else {
                    Operation::IntegerAbs {
                        value: Operand::Int {
                            ty,
                            bits: "1".into(),
                        },
                        int_min_is_poison: false,
                    }
                },
            }],
            terminator: Terminator::Return {
                value: Some(Operand::Int {
                    ty: 2,
                    bits: "0".into(),
                }),
            },
        });
        let error = verify(&module).unwrap_err();
        assert!(
            error.message.contains("integer ctlz/abs"),
            "{}",
            error.message
        );
    }
}

#[test]
fn integer_unary_declarations_cannot_change_the_type_cc_or_become_ordinary_calls() {
    for count in [false, true] {
        for mutation in 0..4 {
            let mut module = fixture(32, count, false);
            let declaration = &mut module.functions[1];
            match mutation {
                0 => declaration.signature.result = 1,
                1 => declaration.signature.params[1] = 2,
                2 => declaration.signature.abi = "fastcc".into(),
                _ => declaration.signature.variadic = true,
            }
            assert!(verify(&module).is_err());
        }
        let mut module = fixture(64, count, false);
        let declaration = &module.functions[1];
        let signature = declaration.signature.clone();
        let name = declaration.name.clone();
        module.types.push(Type::Pointer { address_space: 0 });
        module.functions[0].blocks[0].instructions[0].operation = Operation::Call {
            callee: Operand::Symbol { ty: 3, name },
            signature,
            args: vec![
                Operand::Value { id: 0 },
                Operand::Int {
                    ty: 1,
                    bits: "0".into(),
                },
            ],
        };
        assert!(
            verify(&module).is_err(),
            "unlowered ordinary intrinsic call was accepted"
        );
    }
}

#[test]
fn integer_unary_owned_emission_covers_all_three_realizations_without_helpers() {
    for (target, triple) in [
        (Target::X86_64UnknownNone, "x86_64-unknown-linux-gnu"),
        (Target::Aarch64UnknownNone, "aarch64-unknown-linux-gnu"),
        (Target::Riscv64UnknownNone, "riscv64-unknown-linux-gnu"),
    ] {
        for bits in [32, 64] {
            for count in [false, true] {
                let mut module = fixture(bits, count, false);
                module.target.triple = triple.into();
                let assembly = native_codegen::emit(&module, target).unwrap();
                assert!(!assembly.contains("call llvm.") && !assembly.contains("bl llvm."));
                if count {
                    assert!(assembly.contains(match target {
                        Target::X86_64UnknownNone => "bsr ",
                        Target::Aarch64UnknownNone => "clz ",
                        Target::Riscv64UnknownNone => "and t4, t0, t3",
                    }));
                } else {
                    assert!(assembly.contains(match target {
                        Target::X86_64UnknownNone => "sar rcx, 63",
                        Target::Aarch64UnknownNone => "asr x10, x9, #63",
                        Target::Riscv64UnknownNone => "srai t1, t0, 63",
                    }));
                }
                assert!(
                    crate::ocore::native_floating_helpers::requirements(&module, target)
                        .unwrap()
                        .is_empty()
                );
            }
        }
    }
}

fn population_fixture(bits: u16) -> NativeModule {
    let mut module = fixture(bits, false, false);
    module.functions[0].blocks[0].instructions[0].operation = Operation::IntegerPopulationCount {
        value: Operand::Value { id: 0 },
    };
    let declaration = &mut module.functions[1];
    declaration.name = format!("llvm.ctpop.i{bits}");
    declaration.intrinsic = Some(declaration.name.clone());
    declaration.signature.params.truncate(1);
    declaration.params.truncate(1);
    module
}

#[test]
fn integer_population_count_has_one_operand_no_poison_flag_and_exact_overloads() {
    for bits in [32, 64] {
        let module = population_fixture(bits);
        verify(&module).unwrap();
        assert_eq!(
            integer_population_count_intrinsic(&module.functions[1].name),
            Some(bits)
        );
        assert!(is_builtin_intrinsic(&module.functions[1].name));
        let wire = serde_json::to_value(&module).unwrap();
        let op = wire["functions"][0]["blocks"][0]["instructions"][0]["operation"]
            .as_object()
            .unwrap();
        assert_eq!(op.len(), 2);
        assert_eq!(op["op"], "integer_population_count");
        assert!(op.contains_key("value"));
    }
    for name in [
        "llvm.ctpop.i032",
        "llvm.ctpop.i16",
        "llvm.ctpop.i128",
        "llvm.ctpop.v2i32",
    ] {
        assert_eq!(integer_population_count_intrinsic(name), None);
        assert!(!is_builtin_intrinsic(name));
    }
}

#[test]
fn integer_population_count_reference_matches_independent_bit_counts() {
    for bits in [32u16, 64] {
        let module = population_fixture(bits);
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let mut values = vec![0, 1, mask, mask >> 1, 1u64 << (bits - 1)];
        for shift in 0..bits {
            values.extend([1u64 << shift, (1u64 << shift).wrapping_sub(1)]);
        }
        let mut seed = 0x91d3_4652_8abc_ef07u64;
        for _ in 0..256 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            values.push(seed & mask);
        }
        for value in values {
            let actual = native_interpret::evaluate(&module, "calculate", &[BigUint::from(value)])
                .unwrap()
                .unwrap();
            assert_eq!(
                actual,
                BigUint::from(u64::from(value.count_ones())),
                "i{bits} value={value}"
            );
        }
    }
}

#[test]
fn integer_population_count_rejects_wrong_shapes_and_dead_unsupported_uses() {
    for bits in [16, 33, 128] {
        assert!(verify(&population_fixture(bits)).is_err());
    }
    let mut module = population_fixture(64);
    module.functions[0].blocks[0].instructions[0]
        .result
        .as_mut()
        .unwrap()
        .ty = 1;
    assert!(verify(&module).is_err());
    let mut module = population_fixture(64);
    module.functions[0].blocks[0].instructions[0].operation = Operation::IntegerPopulationCount {
        value: Operand::Value { id: 99 },
    };
    assert!(verify(&module).is_err());
    let mut module = population_fixture(64);
    let ty = module.types.len();
    module.types.push(Type::Int { bits: 16 });
    module.functions[0].blocks.push(Block {
        id: 7,
        instructions: vec![Instruction {
            result: Some(Value { id: 99, ty }),
            operation: Operation::IntegerPopulationCount {
                value: Operand::Int {
                    ty,
                    bits: "0".into(),
                },
            },
        }],
        terminator: Terminator::Return {
            value: Some(Operand::Int {
                ty: 2,
                bits: "0".into(),
            }),
        },
    });
    assert!(verify(&module)
        .unwrap_err()
        .message
        .contains("population count"));
}

#[test]
fn integer_population_count_declarations_preserve_arity_abi_and_result_contracts() {
    let module = population_fixture(32);
    for (field, value) in [
        ("abi", json!("fastcc")),
        ("result", json!(1)),
        ("result_attributes", json!(["signext"])),
    ] {
        let mut wire = serde_json::to_value(&module).unwrap();
        wire["functions"][1]["signature"][field] = value;
        let wrong: NativeModule = serde_json::from_value(wire).unwrap();
        assert!(verify(&wrong).is_err());
    }
    let mut module = population_fixture(64);
    module.functions[1].signature.params.push(1);
    module.functions[1].params.push(Value { id: 1, ty: 1 });
    assert!(verify(&module).is_err());
}
