//! Exact compiler-generated dependencies of the scalar floating-point profile.
//!
//! Source declarations, type IDs and provenance inventories remain unchanged.
//! The emitter and native-runtime admission both use this selector, including
//! instructions in cold or unreachable blocks. These are required interfaces,
//! not implicit providers or permission to accept other undefined symbols.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::native_ir::{
    error_diagnostic, CastOp, FloatBinaryOp, Instruction, NativeModule, Operand, Operation,
    Signature, Terminator, Type, TypeId, ValueId, Visibility,
};
use super::{Diagnostic, Target};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperType {
    Int { bits: u16 },
    Float { bits: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperRequirement {
    pub name: String,
    pub result: HelperType,
    pub params: Vec<HelperType>,
}

fn fail(message: impl std::fmt::Display) -> Diagnostic {
    error_diagnostic(format!("native floating helpers: {message}"))
}

fn helper(name: &str, result: HelperType, params: &[HelperType]) -> HelperRequirement {
    HelperRequirement {
        name: name.into(),
        result,
        params: params.into(),
    }
}

fn ty(module: &NativeModule, id: TypeId) -> Result<HelperType, Diagnostic> {
    match module.types.get(id) {
        Some(Type::Int { bits }) if (1..=64).contains(bits) => Ok(HelperType::Int { bits: *bits }),
        Some(Type::Float {
            bits: 32 | 64 | 80 | 128,
        }) => {
            let Type::Float { bits } = &module.types[id] else {
                unreachable!()
            };
            Ok(HelperType::Float { bits: *bits })
        }
        _ => Err(fail("unsupported or missing scalar numeric type")),
    }
}

fn operand_type(
    module: &NativeModule,
    operand: &Operand,
    values: &BTreeMap<ValueId, TypeId>,
) -> Result<HelperType, Diagnostic> {
    let id = match operand {
        Operand::Value { id } => *values
            .get(id)
            .ok_or_else(|| fail("undefined SSA operand"))?,
        Operand::Int { ty, .. }
        | Operand::Float { ty, .. }
        | Operand::PointerBits { ty, .. }
        | Operand::Null { ty }
        | Operand::Symbol { ty, .. }
        | Operand::SymbolOffset { ty, .. }
        | Operand::Aggregate { ty, .. }
        | Operand::AggregateZero { ty }
        | Operand::Undef { ty }
        | Operand::Poison { ty } => *ty,
    };
    ty(module, id)
}

fn target_profile(module: &NativeModule, target: Target) -> Result<(), Diagnostic> {
    let architecture = module.target.triple.split('-').next().unwrap_or_default();
    let correct = match target {
        Target::X86_64UnknownNone => architecture == "x86_64",
        Target::Aarch64UnknownNone => architecture == "aarch64",
        Target::Riscv64UnknownNone => architecture == "riscv64",
    };
    if !correct {
        return Err(fail(
            "helper target differs from the original module architecture",
        ));
    }
    if target == Target::Riscv64UnknownNone
        && !matches!(module.target.abi.as_deref(), Some("lp64" | "lp64d"))
    {
        return Err(fail(
            "RISC-V floating helpers require an explicit lp64 or lp64d ABI",
        ));
    }
    Ok(())
}

/// Select the exact external interface emitted for this verified instruction.
/// A numeric cast's destination comes from its original SSA result, not a
/// guessed source type. `None` means owned hardware/bit-pattern lowering.
/// Unsupported numeric operations fail here even when their results are dead.
pub fn operation_requirement(
    module: &NativeModule,
    target: Target,
    instruction: &Instruction,
    value_types: &BTreeMap<ValueId, TypeId>,
) -> Result<Option<HelperRequirement>, Diagnostic> {
    use HelperType::{Float, Int};
    let result_type = || {
        ty(
            module,
            instruction
                .result
                .ok_or_else(|| fail("numeric operation has no SSA result"))?
                .ty,
        )
    };
    let requirement = match &instruction.operation {
        Operation::FloatBinary { kind, lhs, rhs, .. } => {
            let numeric = operand_type(module, lhs, value_types)?;
            if numeric != operand_type(module, rhs, value_types)? || numeric != result_type()? {
                return Err(fail("floating binary operand/result type mismatch"));
            }
            match numeric {
                Float { bits: 80 } => return Err(fail("x87 arithmetic is not implemented")),
                Float { bits: 32 | 64 } => {
                    if *kind == FloatBinaryOp::Rem {
                        return Err(fail(
                            "floating remainder has no admitted runtime provider profile",
                        ));
                    }
                    None
                }
                Float { bits: 128 } => {
                    let name = match kind {
                        FloatBinaryOp::Add => "__addtf3",
                        FloatBinaryOp::Sub => "__subtf3",
                        FloatBinaryOp::Mul => "__multf3",
                        FloatBinaryOp::Div => "__divtf3",
                        FloatBinaryOp::Rem => {
                            return Err(fail("binary128 remainder is not implemented"))
                        }
                    };
                    Some(helper(name, numeric, &[numeric, numeric]))
                }
                _ => {
                    return Err(fail(
                        "floating operation requires a supported floating type",
                    ))
                }
            }
        }
        Operation::FloatNeg { value, .. } => {
            let numeric = operand_type(module, value, value_types)?;
            if numeric != result_type()? {
                return Err(fail("floating negation operand/result type mismatch"));
            }
            match numeric {
                Float {
                    bits: 32 | 64 | 128,
                } => None,
                Float { bits: 80 } if target == Target::X86_64UnknownNone => None,
                Float { bits: 80 } => return Err(fail("x87 transport requires x86-64")),
                _ => return Err(fail("floating negation requires a floating type")),
            }
        }
        Operation::FCmp { lhs, rhs, .. } => {
            let numeric = operand_type(module, lhs, value_types)?;
            if numeric != operand_type(module, rhs, value_types)? {
                return Err(fail("floating comparison operand type mismatch"));
            }
            match numeric {
                Float { bits: 32 | 64 } => None,
                Float { bits: 80 | 128 } => {
                    return Err(fail("wide floating comparison is not implemented"))
                }
                _ => return Err(fail("floating comparison requires a floating type")),
            }
        }
        Operation::Cast { kind, value }
            if matches!(
                kind,
                CastOp::FpTrunc
                    | CastOp::FpExt
                    | CastOp::FpToUi
                    | CastOp::FpToSi
                    | CastOp::UiToFp
                    | CastOp::SiToFp
            ) =>
        {
            let source = operand_type(module, value, value_types)?;
            let destination = result_type()?;
            if source == (Float { bits: 80 }) || destination == (Float { bits: 80 }) {
                return Err(fail("x87 numeric conversion is not implemented"));
            }
            match (*kind, source, destination) {
                (CastOp::FpTrunc, Float { bits: 128 }, Float { bits: 32 }) => {
                    Some(helper("__trunctfsf2", destination, &[source]))
                }
                (CastOp::FpTrunc, Float { bits: 128 }, Float { bits: 64 }) => {
                    Some(helper("__trunctfdf2", destination, &[source]))
                }
                (CastOp::FpExt, Float { bits: 32 }, Float { bits: 128 }) => {
                    Some(helper("__extendsftf2", destination, &[source]))
                }
                (CastOp::FpExt, Float { bits: 64 }, Float { bits: 128 }) => {
                    Some(helper("__extenddftf2", destination, &[source]))
                }
                (CastOp::FpToSi, Float { bits: 128 }, Int { bits: 1..=64 }) => {
                    Some(helper("__fixtfdi", Int { bits: 64 }, &[source]))
                }
                (CastOp::FpToUi, Float { bits: 128 }, Int { bits: 1..=64 }) => {
                    Some(helper("__fixunstfdi", Int { bits: 64 }, &[source]))
                }
                (CastOp::SiToFp, Int { bits: 1..=64 }, Float { bits: 128 }) => {
                    Some(helper("__floatditf", destination, &[Int { bits: 64 }]))
                }
                (CastOp::UiToFp, Int { bits: 1..=64 }, Float { bits: 128 }) => {
                    Some(helper("__floatunditf", destination, &[Int { bits: 64 }]))
                }
                (CastOp::FpTrunc, Float { bits: 64 }, Float { bits: 32 })
                | (CastOp::FpExt, Float { bits: 32 }, Float { bits: 64 })
                | (
                    CastOp::FpToSi | CastOp::FpToUi,
                    Float { bits: 32 | 64 },
                    Int { bits: 1..=64 },
                )
                | (
                    CastOp::SiToFp | CastOp::UiToFp,
                    Int { bits: 1..=64 },
                    Float { bits: 32 | 64 },
                ) => None,
                _ => return Err(fail("unsupported scalar floating conversion")),
            }
        }
        _ => None,
    };
    if requirement.is_some() {
        target_profile(module, target)?;
    }
    Ok(requirement)
}

impl HelperRequirement {
    /// Exact C interface, independent of original module-local type IDs.
    pub fn matches_signature(&self, module: &NativeModule, signature: &Signature) -> bool {
        signature.abi == "c"
            && !signature.variadic
            && signature.return_storage.is_none()
            && signature.result_attributes.is_empty()
            && (signature.param_attributes.is_empty()
                || (signature.param_attributes.len() == signature.params.len()
                    && signature.param_attributes.iter().all(Vec::is_empty)))
            && ty(module, signature.result).ok() == Some(self.result)
            && signature.params.len() == self.params.len()
            && signature
                .params
                .iter()
                .zip(&self.params)
                .all(|(id, expected)| ty(module, *id).ok().as_ref() == Some(expected))
    }
}

/// Recompute all requirements from original instructions; no serialized helper
/// labels are trusted. Source functions with the same name must expose exactly
/// this ordinary C interface, and source storage/aliases cannot impersonate it.
pub fn requirements(
    module: &NativeModule,
    target: Target,
) -> Result<Vec<HelperRequirement>, Diagnostic> {
    let mut selected = BTreeMap::<String, HelperRequirement>::new();
    for function in &module.functions {
        let mut values = BTreeMap::new();
        for value in function
            .params
            .iter()
            .chain(
                function
                    .blocks
                    .iter()
                    .flat_map(|block| &block.instructions)
                    .filter_map(|instruction| instruction.result.as_ref()),
            )
            .chain(
                function
                    .blocks
                    .iter()
                    .filter_map(|block| match &block.terminator {
                        Terminator::Invoke { result, .. } => result.as_ref(),
                        _ => None,
                    }),
            )
        {
            if values.insert(value.id, value.ty).is_some() {
                return Err(fail(format!("duplicate SSA identity in {}", function.name)));
            }
        }
        for instruction in function.blocks.iter().flat_map(|block| &block.instructions) {
            if let Some(requirement) = operation_requirement(module, target, instruction, &values)?
            {
                if selected
                    .get(&requirement.name)
                    .is_some_and(|previous| previous != &requirement)
                {
                    return Err(fail("conflicting generated helper signatures"));
                }
                selected.insert(requirement.name.clone(), requirement);
            }
        }
    }
    let nonfunction_names: BTreeSet<_> = module
        .globals
        .iter()
        .map(|global| global.name.as_str())
        .chain(module.aliases.iter().map(|alias| alias.name.as_str()))
        .collect();
    for requirement in selected.values() {
        if nonfunction_names.contains(requirement.name.as_str()) {
            return Err(fail(format!(
                "generated helper name conflicts with source storage/alias: {}",
                requirement.name
            )));
        }
        if let Some(function) = module
            .functions
            .iter()
            .find(|function| function.name == requirement.name)
        {
            if !requirement.matches_signature(module, &function.signature)
                || function.intrinsic.is_some()
                || function.visibility != Visibility::Default
                || matches!(function.linkage.as_str(), "internal" | "private")
            {
                return Err(fail(format!(
                    "generated helper conflicts with the source function interface: {}",
                    requirement.name
                )));
            }
        }
    }
    Ok(selected.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::super::native_ir::{
        Block, FastMathFlags, FloatPredicate, Function, Terminator, Value,
    };
    use super::*;
    use serde_json::json;

    fn module(target: Target, abi: Option<&str>) -> NativeModule {
        serde_json::from_value(json!({
            "format":"ocore-native-module-v1","name":"helper-inventory",
            "target":{"triple":match target {
                Target::X86_64UnknownNone => "x86_64-unknown-linux-gnu",
                Target::Aarch64UnknownNone => "aarch64-unknown-linux-gnu",
                Target::Riscv64UnknownNone => "riscv64-unknown-linux-gnu",
            },"data_layout":"e-p:64:64-i64:64-f32:32-f64:64-f80:128-f128:128-S128",
                "pointer_bits":64,"little_endian":true,"abi":abi},
            "semantics":"llvm_defined_behavior_v1",
            "types":[{"kind":"void"},{"kind":"int","bits":8},{"kind":"int","bits":32},
                {"kind":"int","bits":64},{"kind":"float","bits":32},
                {"kind":"float","bits":64},{"kind":"float","bits":128}],
            "globals":[],"functions":[{"name":"f","linkage":"external",
                "signature":{"params":[],"result":0,"abi":"c","variadic":false},
                "params":[],"entry":0,"blocks":[{"id":0,"instructions":[],"terminator":{"op":"return","value":null}}]}],
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"LLVM22 reference",
                "frontend_version":"22.1.6","importer":"fixture","importer_version":"1",
                "source_function_count":1,"source_global_count":0}
        })).unwrap()
    }

    fn constant(ty: TypeId) -> Operand {
        Operand::Float {
            ty,
            bits: "0".into(),
        }
    }

    fn binary(kind: FloatBinaryOp, ty: TypeId, id: ValueId) -> Instruction {
        Instruction {
            result: Some(Value { id, ty }),
            operation: Operation::FloatBinary {
                kind,
                lhs: constant(ty),
                rhs: constant(ty),
                flags: FastMathFlags::default(),
            },
        }
    }

    fn cast(kind: CastOp, source: TypeId, destination: TypeId, id: ValueId) -> Instruction {
        Instruction {
            result: Some(Value {
                id,
                ty: destination,
            }),
            operation: Operation::Cast {
                kind,
                value: if source == 1 || source == 3 {
                    Operand::Int {
                        ty: source,
                        bits: "1".into(),
                    }
                } else {
                    constant(source)
                },
            },
        }
    }

    #[test]
    fn catalog_preserves_direct_quad_rounding_and_signed_integer_bridges_all_profiles() {
        use HelperType::{Float, Int};
        for (target, abi) in [
            (Target::X86_64UnknownNone, None),
            (Target::Aarch64UnknownNone, None),
            (Target::Riscv64UnknownNone, Some("lp64")),
            (Target::Riscv64UnknownNone, Some("lp64d")),
        ] {
            let m = module(target, abi);
            for (kind, name) in [
                (FloatBinaryOp::Add, "__addtf3"),
                (FloatBinaryOp::Sub, "__subtf3"),
                (FloatBinaryOp::Mul, "__multf3"),
                (FloatBinaryOp::Div, "__divtf3"),
            ] {
                assert_eq!(
                    operation_requirement(&m, target, &binary(kind, 6, 0), &BTreeMap::new())
                        .unwrap(),
                    Some(helper(name, Float { bits: 128 }, &[Float { bits: 128 }; 2]))
                );
            }
            for (kind, source, destination, name, result, params) in [
                (
                    CastOp::FpTrunc,
                    6,
                    4,
                    "__trunctfsf2",
                    Float { bits: 32 },
                    vec![Float { bits: 128 }],
                ),
                (
                    CastOp::FpTrunc,
                    6,
                    5,
                    "__trunctfdf2",
                    Float { bits: 64 },
                    vec![Float { bits: 128 }],
                ),
                (
                    CastOp::FpExt,
                    4,
                    6,
                    "__extendsftf2",
                    Float { bits: 128 },
                    vec![Float { bits: 32 }],
                ),
                (
                    CastOp::FpExt,
                    5,
                    6,
                    "__extenddftf2",
                    Float { bits: 128 },
                    vec![Float { bits: 64 }],
                ),
                (
                    CastOp::FpToSi,
                    6,
                    1,
                    "__fixtfdi",
                    Int { bits: 64 },
                    vec![Float { bits: 128 }],
                ),
                (
                    CastOp::FpToUi,
                    6,
                    1,
                    "__fixunstfdi",
                    Int { bits: 64 },
                    vec![Float { bits: 128 }],
                ),
                (
                    CastOp::SiToFp,
                    1,
                    6,
                    "__floatditf",
                    Float { bits: 128 },
                    vec![Int { bits: 64 }],
                ),
                (
                    CastOp::UiToFp,
                    1,
                    6,
                    "__floatunditf",
                    Float { bits: 128 },
                    vec![Int { bits: 64 }],
                ),
            ] {
                assert_eq!(
                    operation_requirement(
                        &m,
                        target,
                        &cast(kind, source, destination, 0),
                        &BTreeMap::new()
                    )
                    .unwrap(),
                    Some(helper(name, result, &params))
                );
            }
        }
    }

    #[test]
    fn owned_math_and_sign_flips_have_no_hidden_providers_and_unsupported_math_fails() {
        let target = Target::X86_64UnknownNone;
        let mut m = module(target, None);
        m.types.push(Type::Float { bits: 80 });
        for ty in [4, 5] {
            for kind in [
                FloatBinaryOp::Add,
                FloatBinaryOp::Sub,
                FloatBinaryOp::Mul,
                FloatBinaryOp::Div,
            ] {
                assert_eq!(
                    operation_requirement(&m, target, &binary(kind, ty, 0), &BTreeMap::new())
                        .unwrap(),
                    None
                );
            }
            let cmp = Instruction {
                result: Some(Value { id: 0, ty: 1 }),
                operation: Operation::FCmp {
                    predicate: FloatPredicate::Uno,
                    lhs: constant(ty),
                    rhs: constant(ty),
                    flags: FastMathFlags::default(),
                },
            };
            assert_eq!(
                operation_requirement(&m, target, &cmp, &BTreeMap::new()).unwrap(),
                None
            );
        }
        for ty in [4, 5, 6, 7] {
            let neg = Instruction {
                result: Some(Value { id: 0, ty }),
                operation: Operation::FloatNeg {
                    value: constant(ty),
                    flags: FastMathFlags::default(),
                },
            };
            assert_eq!(
                operation_requirement(&m, target, &neg, &BTreeMap::new()).unwrap(),
                None
            );
        }
        for ty in [4, 5, 6, 7] {
            assert!(operation_requirement(
                &m,
                target,
                &binary(FloatBinaryOp::Rem, ty, 0),
                &BTreeMap::new()
            )
            .is_err());
        }
        for ty in [6, 7] {
            let cmp = Instruction {
                result: Some(Value { id: 0, ty: 1 }),
                operation: Operation::FCmp {
                    predicate: FloatPredicate::Oeq,
                    lhs: constant(ty),
                    rhs: constant(ty),
                    flags: FastMathFlags::default(),
                },
            };
            assert!(operation_requirement(&m, target, &cmp, &BTreeMap::new()).is_err());
        }
        assert!(operation_requirement(
            &m,
            target,
            &binary(FloatBinaryOp::Add, 7, 0),
            &BTreeMap::new()
        )
        .is_err());
        assert!(operation_requirement(
            &m,
            target,
            &cast(CastOp::FpTrunc, 7, 5, 0),
            &BTreeMap::new()
        )
        .is_err());
    }

    #[test]
    fn whole_inventory_visits_cold_blocks_deduplicates_and_preserves_source_counts() {
        let target = Target::Riscv64UnknownNone;
        let mut m = module(target, Some("lp64d"));
        m.functions[0].blocks[0].instructions = vec![
            binary(FloatBinaryOp::Sub, 6, 0),
            cast(CastOp::FpTrunc, 6, 4, 1),
            cast(CastOp::FpTrunc, 6, 4, 2),
        ];
        m.functions[0].blocks.push(Block {
            id: 1,
            instructions: vec![cast(CastOp::FpTrunc, 6, 5, 3)],
            terminator: Terminator::Return { value: None },
        });
        let original = serde_json::to_vec(&m).unwrap();
        NativeModule::from_json(&original).unwrap();
        let selected = requirements(&m, target).unwrap();
        assert_eq!(
            selected.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["__subtf3", "__trunctfdf2", "__trunctfsf2"]
        );
        assert_eq!(serde_json::to_vec(&m).unwrap(), original);
        assert_eq!(
            (m.functions.len(), m.provenance.source_function_count),
            (1, 1)
        );
        m.functions[0].blocks[1]
            .instructions
            .push(binary(FloatBinaryOp::Rem, 6, 4));
        NativeModule::from_json(&serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(requirements(&m, target)
            .unwrap_err()
            .message
            .contains("remainder"));
    }

    #[test]
    fn helper_interfaces_do_not_invent_source_type_ids_or_mask_source_name_conflicts() {
        let target = Target::X86_64UnknownNone;
        let mut m = module(target, None);
        m.types[3] = Type::Int { bits: 8 };
        m.functions[0].blocks[0].instructions = vec![cast(CastOp::FpToSi, 6, 1, 0)];
        NativeModule::from_json(&serde_json::to_vec(&m).unwrap()).unwrap();
        let before = serde_json::to_vec(&m).unwrap();
        let selected = requirements(&m, target).unwrap();
        assert_eq!(selected[0].result, HelperType::Int { bits: 64 });
        assert!(!m
            .types
            .iter()
            .any(|ty| matches!(ty, Type::Int { bits: 64 })));
        assert_eq!(before, serde_json::to_vec(&m).unwrap());
        let mut declaration: Function = m.functions[0].clone();
        declaration.name = "__fixtfdi".into();
        declaration.entry = None;
        declaration.blocks.clear();
        declaration.signature.params = vec![6];
        declaration.signature.result = 1;
        m.functions.push(declaration);
        m.provenance.source_function_count = 2;
        NativeModule::from_json(&serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(requirements(&m, target)
            .unwrap_err()
            .message
            .contains("source function interface"));
        let i64 = m.types.len();
        m.types.push(Type::Int { bits: 64 });
        m.functions[1].signature.result = i64;
        assert!(requirements(&m, target).is_ok());
        m.functions[1].signature.abi = "fast".into();
        assert!(requirements(&m, target).is_err());
    }

    #[test]
    fn helper_selection_uses_actual_ssa_types_and_refuses_target_or_type_substitution() {
        let target = Target::Riscv64UnknownNone;
        let mut m = module(target, Some("lp64d"));
        let mut operation = cast(CastOp::FpTrunc, 6, 5, 0);
        if let Operation::Cast { value, .. } = &mut operation.operation {
            *value = Operand::Value { id: 42 };
        }
        assert!(operation_requirement(&m, target, &operation, &BTreeMap::new()).is_err());
        let values = BTreeMap::from([(42, 6)]);
        assert_eq!(
            operation_requirement(&m, target, &operation, &values)
                .unwrap()
                .unwrap()
                .name,
            "__trunctfdf2"
        );
        assert!(operation_requirement(&m, Target::X86_64UnknownNone, &operation, &values).is_err());
        m.target.abi = None;
        assert!(operation_requirement(&m, target, &operation, &values).is_err());
        m.target.abi = Some("lp64d".into());
        operation.result.as_mut().unwrap().ty = 1;
        assert!(operation_requirement(&m, target, &operation, &values).is_err());
    }
}
