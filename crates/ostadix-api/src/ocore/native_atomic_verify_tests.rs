//! Independent structural contracts for LLVM's five atomic instruction families.
//!
//! These authored NativeModules qualify verification and the strict wire only.
//! They do not establish frontend import, atomic machine execution, inter-thread
//! memory ordering, supported providers, or completion of a compiler/runtime.

use super::*;
use serde_json::{json, Value as JsonValue};

const VOID: TypeId = 0;
const I1: TypeId = 1;
const I8: TypeId = 2;
const I32: TypeId = 4;
const I64: TypeId = 5;
const PTR: TypeId = 6;
const OUTPUT: ValueId = 20;

const ORDERS: [AtomicOrdering; 6] = [
    AtomicOrdering::Unordered,
    AtomicOrdering::Monotonic,
    AtomicOrdering::Acquire,
    AtomicOrdering::Release,
    AtomicOrdering::AcquireRelease,
    AtomicOrdering::SequentiallyConsistent,
];

const RMW_OPERATIONS: [(AtomicRmwOp, &str); 21] = [
    (AtomicRmwOp::Xchg, "xchg"),
    (AtomicRmwOp::Add, "add"),
    (AtomicRmwOp::Sub, "sub"),
    (AtomicRmwOp::And, "and"),
    (AtomicRmwOp::Nand, "nand"),
    (AtomicRmwOp::Or, "or"),
    (AtomicRmwOp::Xor, "xor"),
    (AtomicRmwOp::Max, "max"),
    (AtomicRmwOp::Min, "min"),
    (AtomicRmwOp::Umax, "umax"),
    (AtomicRmwOp::Umin, "umin"),
    (AtomicRmwOp::Fadd, "fadd"),
    (AtomicRmwOp::Fsub, "fsub"),
    (AtomicRmwOp::Fmax, "fmax"),
    (AtomicRmwOp::Fmin, "fmin"),
    (AtomicRmwOp::Fmaximum, "fmaximum"),
    (AtomicRmwOp::Fminimum, "fminimum"),
    (AtomicRmwOp::UincWrap, "uinc_wrap"),
    (AtomicRmwOp::UdecWrap, "udec_wrap"),
    (AtomicRmwOp::UsubCond, "usub_cond"),
    (AtomicRmwOp::UsubSat, "usub_sat"),
];

#[derive(Clone, Copy, Debug)]
enum Family {
    Load,
    Store,
    Fence,
    Rmw,
    CompareExchange,
}

const FAMILIES: [Family; 5] = [
    Family::Load,
    Family::Store,
    Family::Fence,
    Family::Rmw,
    Family::CompareExchange,
];

const MEMORY_FAMILIES: [Family; 4] = [
    Family::Load,
    Family::Store,
    Family::Rmw,
    Family::CompareExchange,
];

fn module() -> NativeModule {
    // Separate from the parent's pre-existing integer CFG fixture. Each atomic
    // result is present even when unused, as it is in the original LLVM IR.
    serde_json::from_value(json!({
        "format": FORMAT,
        "name": "authored-atomic-verifier-contract",
        "target": {
            "triple": "x86_64-unknown-linux-gnu",
            "data_layout": "e-p:64:64-i64:64-i128:128-f80:128",
            "pointer_bits": 64,
            "little_endian": true
        },
        "semantics": "llvm_defined_behavior_v1",
        "types": [
            {"kind":"void"}, {"kind":"int","bits":1},
            {"kind":"int","bits":8}, {"kind":"int","bits":16},
            {"kind":"int","bits":32}, {"kind":"int","bits":64},
            {"kind":"pointer","address_space":0}
        ],
        "globals": [],
        "functions": [{
            "name":"atomic_fixture", "linkage":"external",
            "signature":{"params":[PTR,I64,I64,I1],"result":VOID,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":PTR},{"id":1,"ty":I64},{"id":2,"ty":I64},{"id":3,"ty":I1}],
            "entry":10,
            "blocks":[{"id":10,"instructions":[],"terminator":{"op":"return","value":null}}]
        }],
        "atomic_sync_scopes": [
            {"id":0,"name":[115,105,110,103,108,101,116,104,114,101,97,100]},
            {"id":1,"name":[]}
        ],
        "provenance":{
            "input_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
            "frontend":"authored-structural-fixture","frontend_version":"1",
            "importer":"authored-structural-fixture","importer_version":"1",
            "source_function_count":1,"source_global_count":0,"refinements":[]
        }
    }))
    .unwrap()
}

fn value(ty: TypeId) -> Operand {
    // Undef retains a valid typed source operand without inventing a floating
    // literal representation or making any defined-execution claim.
    Operand::Undef { ty }
}

fn add_type(module: &mut NativeModule, ty: Type) -> TypeId {
    let id = module.types.len();
    module.types.push(ty);
    id
}

fn instruction(module: &mut NativeModule, family: Family, ty: TypeId) -> Instruction {
    let pointer = Operand::Value { id: 0 };
    let output = Some(Value { id: OUTPUT, ty });
    let (result, operation) = match family {
        Family::Load => (
            output,
            Operation::AtomicLoad {
                pointer,
                alignment: 8,
                volatile: false,
                ordering: AtomicOrdering::Monotonic,
                sync_scope: 1,
            },
        ),
        Family::Store => (
            None,
            Operation::AtomicStore {
                pointer,
                value: value(ty),
                alignment: 8,
                volatile: false,
                ordering: AtomicOrdering::Monotonic,
                sync_scope: 1,
            },
        ),
        Family::Fence => (
            None,
            Operation::AtomicFence {
                ordering: AtomicOrdering::Acquire,
                sync_scope: 1,
            },
        ),
        Family::Rmw => (
            output,
            Operation::AtomicRmw {
                kind: AtomicRmwOp::Xchg,
                pointer,
                value: value(ty),
                alignment: 8,
                volatile: false,
                ordering: AtomicOrdering::Monotonic,
                sync_scope: 1,
            },
        ),
        Family::CompareExchange => {
            let result_ty = add_type(
                module,
                Type::Struct {
                    fields: vec![ty, I1],
                    packed: false,
                },
            );
            (
                Some(Value {
                    id: OUTPUT,
                    ty: result_ty,
                }),
                Operation::AtomicCompareExchange {
                    pointer,
                    expected: value(ty),
                    replacement: value(ty),
                    alignment: 8,
                    volatile: false,
                    weak: false,
                    success_ordering: AtomicOrdering::Monotonic,
                    failure_ordering: AtomicOrdering::Monotonic,
                    sync_scope: 1,
                },
            )
        }
    };
    Instruction { result, operation }
}

fn fixture(family: Family, ty: TypeId) -> NativeModule {
    let mut module = module();
    let instruction = instruction(&mut module, family, ty);
    module.functions[0].blocks[0].instructions.push(instruction);
    module
}

fn operation(module: &mut NativeModule) -> &mut Operation {
    &mut module.functions[0].blocks[0].instructions[0].operation
}

fn set_order(operation: &mut Operation, order: AtomicOrdering) {
    match operation {
        Operation::AtomicLoad { ordering, .. }
        | Operation::AtomicStore { ordering, .. }
        | Operation::AtomicFence { ordering, .. }
        | Operation::AtomicRmw { ordering, .. } => *ordering = order,
        _ => panic!("single-order atomic required"),
    }
}

fn set_scope(operation: &mut Operation, id: u32) {
    match operation {
        Operation::AtomicLoad { sync_scope, .. }
        | Operation::AtomicStore { sync_scope, .. }
        | Operation::AtomicFence { sync_scope, .. }
        | Operation::AtomicRmw { sync_scope, .. }
        | Operation::AtomicCompareExchange { sync_scope, .. } => *sync_scope = id,
        _ => panic!("atomic required"),
    }
}

fn set_alignment(operation: &mut Operation, align: u64) {
    match operation {
        Operation::AtomicLoad { alignment, .. }
        | Operation::AtomicStore { alignment, .. }
        | Operation::AtomicRmw { alignment, .. }
        | Operation::AtomicCompareExchange { alignment, .. } => *alignment = align,
        _ => panic!("atomic memory operation required"),
    }
}

fn memory_operands(operation: &mut Operation) -> Vec<&mut Operand> {
    match operation {
        Operation::AtomicLoad { pointer, .. } => vec![pointer],
        Operation::AtomicStore { pointer, value, .. }
        | Operation::AtomicRmw { pointer, value, .. } => vec![pointer, value],
        Operation::AtomicCompareExchange {
            pointer,
            expected,
            replacement,
            ..
        } => vec![pointer, expected, replacement],
        _ => panic!("atomic memory operation required"),
    }
}

fn accepted(module: &NativeModule) {
    verify(module)
        .unwrap_or_else(|error| panic!("valid atomic contract rejected: {}", error.message));
}

fn rejected(module: &NativeModule, expected: &str) {
    let error = verify(module).expect_err("invalid atomic contract was accepted");
    assert!(
        error.message.contains(expected),
        "expected {expected:?}; got {}",
        error.message
    );
}

#[test]
fn every_single_order_family_matches_the_pinned_llvm_contract() {
    // Explicit tables describe the source contract, not a numeric enum lattice.
    for (family, legal, reason) in [
        (
            Family::Load,
            [true, true, true, false, false, true],
            "atomic load ordering",
        ),
        (
            Family::Store,
            [true, true, false, true, false, true],
            "atomic store ordering",
        ),
        (
            Family::Fence,
            [false, false, true, true, true, true],
            "atomic fence ordering",
        ),
        (
            Family::Rmw,
            [false, true, true, true, true, true],
            "atomic RMW ordering",
        ),
    ] {
        for (index, order) in ORDERS.into_iter().enumerate() {
            let mut module = fixture(family, I64);
            set_order(operation(&mut module), order);
            if legal[index] {
                accepted(&module);
            } else {
                rejected(&module, reason);
            }
        }
    }
}

#[test]
fn compare_exchange_checks_all_36_pairs_and_accepts_all_15_valid_pairs() {
    let mut admitted = 0;
    let mut refused = 0;
    for (success_index, success) in ORDERS.into_iter().enumerate() {
        for (failure_index, failure) in ORDERS.into_iter().enumerate() {
            let mut module = fixture(Family::CompareExchange, I64);
            let Operation::AtomicCompareExchange {
                success_ordering,
                failure_ordering,
                ..
            } = operation(&mut module)
            else {
                unreachable!()
            };
            *success_ordering = success;
            *failure_ordering = failure;
            // Failure is independent of success strength in LLVM22. In
            // particular monotonic/seq_cst and release/acquire must survive.
            if success_index != 0 && [1, 2, 5].contains(&failure_index) {
                accepted(&module);
                admitted += 1;
            } else {
                rejected(&module, "atomic compare-exchange ordering");
                refused += 1;
            }
        }
    }
    assert_eq!((admitted, refused), (15, 21));
}

#[test]
fn all_21_rmw_names_preserve_integer_float_and_pointer_compatibility() {
    for (kind, _) in RMW_OPERATIONS {
        let fp_operation = matches!(
            kind,
            AtomicRmwOp::Fadd
                | AtomicRmwOp::Fsub
                | AtomicRmwOp::Fmax
                | AtomicRmwOp::Fmin
                | AtomicRmwOp::Fmaximum
                | AtomicRmwOp::Fminimum
        );
        for class in 0..3 {
            let mut module = module();
            let ty = match class {
                0 => I64,
                1 => add_type(&mut module, Type::Float { bits: 32 }),
                2 => PTR,
                _ => unreachable!(),
            };
            let mut instruction = instruction(&mut module, Family::Rmw, ty);
            let Operation::AtomicRmw {
                kind: operation, ..
            } = &mut instruction.operation
            else {
                unreachable!()
            };
            *operation = kind;
            module.functions[0].blocks[0].instructions.push(instruction);
            let legal = match class {
                0 => !fp_operation,
                1 => fp_operation || kind == AtomicRmwOp::Xchg,
                2 => kind == AtomicRmwOp::Xchg,
                _ => unreachable!(),
            };
            if legal {
                accepted(&module);
            } else {
                rejected(&module, "atomic RMW operation/value type mismatch");
            }
        }
    }
}

#[test]
fn every_integer_width_through_256_uses_value_bits_not_storage_rounding() {
    for bits in 1..=256 {
        for family in MEMORY_FAMILIES {
            let mut module = module();
            let ty = add_type(&mut module, Type::Int { bits });
            let instruction = instruction(&mut module, family, ty);
            module.functions[0].blocks[0].instructions.push(instruction);
            if [8, 16, 32, 64, 128, 256].contains(&bits) {
                // Wide source contracts remain structurally valid. This does
                // not assert a wide-integer native ISA realization exists.
                accepted(&module);
            } else {
                rejected(&module, "atomic value width");
            }
        }
    }
}

#[test]
fn pointer_width_comes_from_its_address_space_without_allocation_padding() {
    for (pointer_bits, expected_size, legal) in [(32, 4, true), (24, 4, false), (64, 8, true)] {
        for family in MEMORY_FAMILIES {
            let mut module = module();
            module
                .target
                .data_layout
                .push_str(&format!("-p1:{pointer_bits}:32"));
            let ty = add_type(&mut module, Type::Pointer { address_space: 1 });
            assert_eq!(type_size(&module, ty).unwrap(), expected_size);
            let instruction = instruction(&mut module, family, ty);
            module.functions[0].blocks[0].instructions.push(instruction);
            if legal {
                accepted(&module);
            } else {
                rejected(&module, "atomic value width");
            }
        }
    }
}

#[test]
fn padded_integer_layout_never_changes_atomic_value_width() {
    for (bits, expected_size, legal) in [
        (16, 8, true),
        (24, 4, false),
        (63, 8, false),
        (128, 16, true),
    ] {
        for family in MEMORY_FAMILIES {
            let mut module = module();
            module.target.data_layout.push_str("-i16:64-i24:32-i63:64");
            let ty = add_type(&mut module, Type::Int { bits });
            assert_eq!(type_size(&module, ty).unwrap(), expected_size);
            let instruction = instruction(&mut module, family, ty);
            module.functions[0].blocks[0].instructions.push(instruction);
            if legal {
                accepted(&module);
            } else {
                rejected(&module, "atomic value width");
            }
        }
    }
}

#[test]
fn floating_storage_contracts_are_retained_without_floating_backend_claims() {
    for bits in [16, 32, 64, 80, 128] {
        for family in [Family::Load, Family::Store, Family::Rmw] {
            let mut module = module();
            let ty = add_type(&mut module, Type::Float { bits });
            let instruction = instruction(&mut module, family, ty);
            module.functions[0].blocks[0].instructions.push(instruction);
            if bits == 80 {
                // x86_fp80 may allocate sixteen bytes but carries eighty bits.
                assert_eq!(type_size(&module, ty).unwrap(), 16);
                rejected(&module, "atomic value width");
            } else {
                accepted(&module);
            }
        }
        let mut module = module();
        let ty = add_type(&mut module, Type::Float { bits });
        let instruction = instruction(&mut module, Family::CompareExchange, ty);
        module.functions[0].blocks[0].instructions.push(instruction);
        rejected(
            &module,
            "atomic compare-exchange value type requires integer or pointer",
        );
    }
}

#[test]
fn atomic_memory_requires_scalar_types_even_when_aggregate_storage_is_sized() {
    for ty in [
        Type::Struct {
            fields: vec![I64],
            packed: false,
        },
        Type::Array {
            element: I8,
            len: 8,
        },
        Type::Struct {
            fields: Vec::new(),
            packed: true,
        },
    ] {
        for family in MEMORY_FAMILIES {
            let mut module = module();
            let ty = add_type(&mut module, ty.clone());
            let instruction = instruction(&mut module, family, ty);
            module.functions[0].blocks[0].instructions.push(instruction);
            rejected(
                &module,
                if matches!(family, Family::CompareExchange) {
                    "atomic compare-exchange value type requires integer or pointer"
                } else {
                    "atomic value type"
                },
            );
        }
    }
    for ty in [Type::Void, Type::Metadata {}] {
        for family in [Family::Load, Family::Store, Family::Rmw] {
            let mut module = module();
            let ty = add_type(&mut module, ty.clone());
            let instruction = instruction(&mut module, family, ty);
            module.functions[0].blocks[0].instructions.push(instruction);
            rejected(&module, "unsized");
        }
    }
}

#[test]
fn explicit_atomic_alignments_are_positive_and_preserve_underalignment() {
    for family in MEMORY_FAMILIES {
        for align in [1, 2, 4, 8, 16, 1u64 << 32] {
            let mut module = fixture(family, I64);
            set_alignment(operation(&mut module), align);
            accepted(&module);
        }
        for align in [0, 3, 6, (1u64 << 32) + 1, 1u64 << 33, u64::MAX] {
            let mut module = fixture(family, I64);
            set_alignment(operation(&mut module), align);
            rejected(
                &module,
                "alignment must be a power of two, at most 2^32 bytes",
            );
        }
    }
}

#[test]
fn atomic_load_rmw_and_compare_exchange_require_their_original_results() {
    for family in [Family::Load, Family::Rmw, Family::CompareExchange] {
        let mut module = fixture(family, I64);
        module.functions[0].blocks[0].instructions[0].result = None;
        rejected(&module, "instruction requires an SSA result");
    }
    for family in [Family::Store, Family::Fence] {
        let mut module = fixture(family, I64);
        module.functions[0].blocks[0].instructions[0].result = Some(Value {
            id: OUTPUT,
            ty: I64,
        });
        rejected(&module, "atomic store/fence cannot define an SSA result");
    }
    let mut module = fixture(Family::Rmw, I64);
    module.functions[0].blocks[0].instructions[0]
        .result
        .as_mut()
        .unwrap()
        .ty = I32;
    rejected(&module, "type mismatch");
}

#[test]
fn compare_exchange_keeps_exact_unpacked_old_value_and_i1_shape() {
    for shape in [
        Type::Int { bits: 64 },
        Type::Array {
            element: I64,
            len: 2,
        },
        Type::Struct {
            fields: vec![I64, I1],
            packed: true,
        },
        Type::Struct {
            fields: vec![I64],
            packed: false,
        },
        Type::Struct {
            fields: vec![I64, I1, I1],
            packed: false,
        },
        Type::Struct {
            fields: vec![I1, I64],
            packed: false,
        },
        Type::Struct {
            fields: vec![I32, I1],
            packed: false,
        },
        Type::Struct {
            fields: vec![I64, I8],
            packed: false,
        },
    ] {
        let mut module = fixture(Family::CompareExchange, I64);
        let bad = add_type(&mut module, shape.clone());
        module.functions[0].blocks[0].instructions[0]
            .result
            .as_mut()
            .unwrap()
            .ty = bad;
        let reason = match shape {
            Type::Struct {
                fields,
                packed: false,
            } if fields.len() == 2 => {
                if fields[0] != I64 {
                    "type mismatch"
                } else {
                    "condition/result requires i1"
                }
            }
            _ => "atomic compare-exchange result requires original unpacked {T,i1}",
        };
        rejected(&module, reason);
    }
    let mut module = fixture(Family::CompareExchange, I64);
    let Operation::AtomicCompareExchange { replacement, .. } = operation(&mut module) else {
        unreachable!()
    };
    *replacement = value(I32);
    rejected(&module, "type mismatch");
}

#[test]
fn every_atomic_memory_address_requires_a_pointer_and_checks_each_operand() {
    for family in MEMORY_FAMILIES {
        let mut module = fixture(family, I64);
        *memory_operands(operation(&mut module))[0] = value(I64);
        rejected(&module, "memory address requires pointer type");

        let count = memory_operands(operation(&mut fixture(family, I64))).len();
        for index in 0..count {
            let mut module = fixture(family, I64);
            *memory_operands(operation(&mut module))[index] = Operand::Value { id: 999 };
            rejected(&module, "undefined SSA value 999");
        }
    }
}

#[test]
fn every_atomic_operand_obeys_full_cfg_dominance_and_source_order() {
    for family in MEMORY_FAMILIES {
        let count = memory_operands(operation(&mut fixture(family, I64))).len();
        for index in 0..count {
            let mut module = fixture(family, I64);
            let mut atomic = module.functions[0].blocks[0].instructions.remove(0);
            *memory_operands(&mut atomic.operation)[index] = Operand::Value { id: 50 };
            let definition = if index == 0 {
                Instruction {
                    result: Some(Value { id: 50, ty: PTR }),
                    operation: Operation::Gep {
                        base: Operand::Value { id: 0 },
                        offset: Operand::Int {
                            ty: I64,
                            bits: "0".into(),
                        },
                        inbounds: false,
                    },
                }
            } else {
                Instruction {
                    result: Some(Value { id: 50, ty: I64 }),
                    operation: Operation::Freeze { value: value(I64) },
                }
            };
            // Both values exist and have correct types; the sibling definition
            // does not dominate the atomic use. No missing-value guard masks it.
            module.functions[0].blocks = vec![
                Block {
                    id: 10,
                    instructions: Vec::new(),
                    terminator: Terminator::Branch {
                        condition: Operand::Value { id: 3 },
                        on_true: 30,
                        on_false: 40,
                    },
                },
                Block {
                    id: 30,
                    instructions: vec![definition.clone()],
                    terminator: Terminator::Return { value: None },
                },
                Block {
                    id: 40,
                    instructions: vec![atomic.clone()],
                    terminator: Terminator::Return { value: None },
                },
            ];
            rejected(&module, "SSA value 50 does not dominate its use");
            // The same typed definition after the operation in its own block is
            // invalid as well; reversing their source order makes it valid.
            module.functions[0].blocks = vec![Block {
                id: 10,
                instructions: vec![atomic.clone(), definition.clone()],
                terminator: Terminator::Return { value: None },
            }];
            rejected(&module, "SSA value 50 does not dominate its use");
            module.functions[0].blocks[0].instructions = vec![definition, atomic];
            accepted(&module);
        }
    }
}

#[test]
fn atomic_scope_ids_preserve_context_local_bytes_and_builtin_identities() {
    for family in FAMILIES {
        let mut module = fixture(family, I64);
        module.atomic_sync_scopes.extend([
            AtomicSyncScope {
                id: 255,
                name: vec![0, 255, b'x'],
            },
            AtomicSyncScope {
                id: 2,
                name: b"target-scope".to_vec(),
            },
        ]);
        // The wire is a table keyed by original ID, not an array-position ABI.
        module.atomic_sync_scopes.swap(0, 3);
        for id in [0, 1, 2, 255] {
            set_scope(operation(&mut module), id);
            accepted(&module);
        }
        let mut other = module.clone();
        other
            .atomic_sync_scopes
            .iter_mut()
            .find(|scope| scope.id == 2)
            .unwrap()
            .name = vec![255, 0, b'y'];
        set_scope(operation(&mut other), 2);
        accepted(&other);
        set_scope(operation(&mut module), 2);
        accepted(&module);
        assert_ne!(
            module
                .atomic_sync_scopes
                .iter()
                .find(|scope| scope.id == 2)
                .unwrap()
                .name,
            other
                .atomic_sync_scopes
                .iter()
                .find(|scope| scope.id == 2)
                .unwrap()
                .name
        );
    }
}

#[test]
fn invalid_scope_tables_fail_even_for_unused_entries_and_cold_operations() {
    let mut duplicate_id = fixture(Family::Fence, I64);
    duplicate_id.atomic_sync_scopes.push(AtomicSyncScope {
        id: 1,
        name: b"different".to_vec(),
    });
    rejected(&duplicate_id, "duplicate synchronization scope ID or name");
    let mut duplicate_name = fixture(Family::Fence, I64);
    duplicate_name.atomic_sync_scopes.extend([
        AtomicSyncScope {
            id: 2,
            name: vec![0, 255],
        },
        AtomicSyncScope {
            id: 3,
            name: vec![0, 255],
        },
    ]);
    rejected(
        &duplicate_name,
        "duplicate synchronization scope ID or name",
    );
    for (id, bytes) in [(0, b"system".to_vec()), (1, b"single-thread".to_vec())] {
        let mut module = fixture(Family::Fence, I64);
        module.atomic_sync_scopes[id].name = bytes;
        rejected(
            &module,
            "synchronization scope built-in identity/name mismatch",
        );
    }
    for reserved in [b"".to_vec(), b"singlethread".to_vec()] {
        let mut module = fixture(Family::Fence, I64);
        module.atomic_sync_scopes = vec![AtomicSyncScope {
            id: 2,
            name: reserved,
        }];
        rejected(
            &module,
            "synchronization scope built-in identity/name mismatch",
        );
    }
    for removed in [0, 1] {
        let mut module = fixture(Family::Fence, I64);
        module.atomic_sync_scopes.remove(removed);
        rejected(
            &module,
            "nonempty synchronization scope inventory requires both LLVM built-ins",
        );
    }
    for id in [256, u32::MAX] {
        let mut module = fixture(Family::Fence, I64);
        module.atomic_sync_scopes.push(AtomicSyncScope {
            id,
            name: vec![0, 255],
        });
        rejected(
            &module,
            "synchronization scope ID exceeds LLVM22's uint8_t identity",
        );
    }
    for family in FAMILIES {
        let mut module = fixture(family, I64);
        set_scope(operation(&mut module), 2);
        rejected(
            &module,
            "atomic synchronization scope is missing from the module inventory",
        );
        let cold = module.functions[0].blocks[0].instructions.remove(0);
        module.functions[0].blocks.push(Block {
            id: 100,
            instructions: vec![cold],
            terminator: Terminator::Return { value: None },
        });
        rejected(
            &module,
            "atomic synchronization scope is missing from the module inventory",
        );
    }
}

#[test]
fn cold_atomic_contracts_remain_fully_typed_and_order_checked() {
    for (family, order, reason) in [
        (
            Family::Load,
            AtomicOrdering::Release,
            "atomic load ordering",
        ),
        (
            Family::Store,
            AtomicOrdering::Acquire,
            "atomic store ordering",
        ),
        (
            Family::Fence,
            AtomicOrdering::Monotonic,
            "atomic fence ordering",
        ),
        (
            Family::Rmw,
            AtomicOrdering::Unordered,
            "atomic RMW ordering",
        ),
    ] {
        let mut module = fixture(family, I64);
        set_order(operation(&mut module), order);
        let cold = module.functions[0].blocks[0].instructions.remove(0);
        module.functions[0].blocks.push(Block {
            id: 100,
            instructions: vec![cold],
            terminator: Terminator::Return { value: None },
        });
        rejected(&module, reason);
    }
    let mut module = fixture(Family::CompareExchange, I64);
    let Operation::AtomicCompareExchange {
        failure_ordering, ..
    } = operation(&mut module)
    else {
        unreachable!()
    };
    *failure_ordering = AtomicOrdering::Release;
    let cold = module.functions[0].blocks[0].instructions.remove(0);
    module.functions[0].blocks.push(Block {
        id: 100,
        instructions: vec![cold],
        terminator: Terminator::Return { value: None },
    });
    rejected(&module, "atomic compare-exchange ordering");
}

#[test]
fn weak_and_volatile_flags_survive_strict_wire_roundtrips() {
    for family in MEMORY_FAMILIES {
        for volatile in [false, true] {
            for weak in [false, true] {
                let mut module = fixture(family, I64);
                match operation(&mut module) {
                    Operation::AtomicLoad { volatile: flag, .. }
                    | Operation::AtomicStore { volatile: flag, .. }
                    | Operation::AtomicRmw { volatile: flag, .. } => *flag = volatile,
                    Operation::AtomicCompareExchange {
                        volatile: flag,
                        weak: flag_weak,
                        ..
                    } => {
                        *flag = volatile;
                        *flag_weak = weak;
                    }
                    _ => unreachable!(),
                }
                let bytes = module.to_json().unwrap();
                let restored = NativeModule::from_json(&bytes).unwrap();
                assert_eq!(
                    serde_json::to_value(module).unwrap(),
                    serde_json::to_value(restored).unwrap()
                );
            }
        }
    }
}

#[test]
fn atomic_wire_uses_exact_source_names_and_rejects_alias_spellings() {
    for (order, spelling) in ORDERS.into_iter().zip([
        "unordered",
        "monotonic",
        "acquire",
        "release",
        "acq_rel",
        "seq_cst",
    ]) {
        assert_eq!(serde_json::to_value(order).unwrap(), json!(spelling));
        assert_eq!(
            serde_json::from_value::<AtomicOrdering>(json!(spelling)).unwrap(),
            order
        );
    }
    for spelling in [
        "not_atomic",
        "consume",
        "relaxed",
        "acquire_release",
        "sequentially_consistent",
        "",
        "system",
    ] {
        assert!(serde_json::from_value::<AtomicOrdering>(json!(spelling)).is_err());
    }
    for (kind, spelling) in RMW_OPERATIONS {
        assert_eq!(serde_json::to_value(kind).unwrap(), json!(spelling));
        assert_eq!(
            serde_json::from_value::<AtomicRmwOp>(json!(spelling)).unwrap(),
            kind
        );
    }
    for spelling in [
        "exchange",
        "cmpxchg",
        "fmaximum_num",
        "u_inc_wrap",
        "bad_binop",
        "",
    ] {
        assert!(serde_json::from_value::<AtomicRmwOp>(json!(spelling)).is_err());
    }
    for number in [0, 1, 2, 3, 7, 255] {
        assert!(serde_json::from_value::<AtomicOrdering>(json!(number)).is_err());
        assert!(serde_json::from_value::<AtomicRmwOp>(json!(number)).is_err());
    }
}

#[test]
fn atomic_wire_requires_all_contract_fields_and_rejects_invented_fields() {
    for family in FAMILIES {
        let module = fixture(family, I64);
        let original = serde_json::to_value(
            module.functions[0].blocks[0].instructions[0]
                .operation
                .clone(),
        )
        .unwrap();
        let fields: Vec<_> = original.as_object().unwrap().keys().cloned().collect();
        for field in fields.into_iter().filter(|field| field != "op") {
            let mut incomplete = original.clone();
            incomplete.as_object_mut().unwrap().remove(&field);
            assert!(
                serde_json::from_value::<Operation>(incomplete).is_err(),
                "{family:?} omitted {field}"
            );
        }
        for field in [
            "scope_name",
            "atomic",
            "memory_order",
            "runtime_provider",
            "flags",
        ] {
            let mut extended = original.clone();
            extended[field] = json!(0);
            assert!(
                serde_json::from_value::<Operation>(extended).is_err(),
                "{family:?} invented {field}"
            );
        }
        for field in ["sync_scope", "alignment"] {
            if original.get(field).is_some() {
                let mut wrong_type = original.clone();
                wrong_type[field] = json!("1");
                assert!(serde_json::from_value::<Operation>(wrong_type).is_err());
            }
        }
        for field in ["weak", "volatile"] {
            if original.get(field).is_some() {
                let mut wrong_type = original.clone();
                wrong_type[field] = json!(1);
                assert!(serde_json::from_value::<Operation>(wrong_type).is_err());
            }
        }
    }
    for original in [
        json!({"op":"load","pointer":{"kind":"value","id":0},"alignment":8,"volatile":false}),
        json!({"op":"store","pointer":{"kind":"value","id":0},"value":{"kind":"undef","ty":I64},"alignment":8,"volatile":false}),
    ] {
        for field in ["ordering", "sync_scope", "weak"] {
            let mut ordinary = original.clone();
            ordinary[field] = json!("monotonic");
            assert!(serde_json::from_value::<Operation>(ordinary).is_err());
        }
    }
    for invalid in [
        json!({"id":1,"name":[],"pointer":0}),
        json!({"id":-1,"name":[]}),
        json!({"id":1,"name":"system"}),
        json!({"id":1,"name":[256]}),
        json!({"id":1}),
    ] {
        assert!(serde_json::from_value::<AtomicSyncScope>(invalid).is_err());
    }
}

#[test]
fn legacy_modules_need_no_scope_table_but_atomic_operations_do() {
    let original = serde_json::to_value(module()).unwrap();
    let mut legacy = original;
    legacy.as_object_mut().unwrap().remove("atomic_sync_scopes");
    let legacy: NativeModule = serde_json::from_value(legacy).unwrap();
    assert!(legacy.atomic_sync_scopes.is_empty());
    accepted(&legacy);
    for family in FAMILIES {
        let mut module = fixture(family, I64);
        module.atomic_sync_scopes.clear();
        rejected(
            &module,
            "atomic synchronization scope is missing from the module inventory",
        );
    }
}

#[test]
fn target_profiles_are_explicit_and_are_not_atomic_source_validity() {
    for arch in ["x86_64", "aarch64", "riscv64"] {
        for family in FAMILIES {
            let mut module = fixture(family, I64);
            module.target.triple = format!("{arch}-unknown-none");
            // Structural validity does not silently invent an execution profile.
            accepted(&module);
            let mut source = serde_json::to_value(&module).unwrap();
            source["target"]["atomic_profile"] = json!("coherent_ram_v1");
            let profiled: NativeModule = serde_json::from_value(source).unwrap();
            accepted(&profiled);
        }
    }
    let mut bad_wire = serde_json::to_value(fixture(Family::Fence, I64)).unwrap();
    bad_wire["target"]["atomic_profile"] = json!("device_memory_v1");
    assert!(serde_json::from_value::<NativeModule>(bad_wire).is_err());
    // No vector type is represented in this schema. A vector storage contract
    // must fail at that explicit boundary, rather than become a scalar/array.
    let vector: JsonValue = json!({"kind":"vector","element":I32,"len":2});
    assert!(serde_json::from_value::<Type>(vector).is_err());
}

#[test]
fn coherent_ram_profile_rejects_incompatible_layouts_without_reclassifying_source() {
    // An unused nonintegral address space does not change the integral AS0
    // contract of this explicitly declared execution profile.
    let mut allowed = serde_json::to_value(fixture(Family::Fence, I64)).unwrap();
    allowed["target"]["data_layout"] = json!("e-p:64:64-i64:64-ni:1");
    allowed["target"]["atomic_profile"] = json!("coherent_ram_v1");
    let allowed: NativeModule = serde_json::from_value(allowed).unwrap();
    accepted(&allowed);

    // LLVM's DataLayout contract forbids nonintegral AS0 independently of
    // whether an atomic execution profile is declared.
    for profiled in [false, true] {
        let mut invalid = serde_json::to_value(fixture(Family::Fence, I64)).unwrap();
        invalid["target"]["data_layout"] = json!("e-p:64:64-i64:64-ni:0");
        if profiled {
            invalid["target"]["atomic_profile"] = json!("coherent_ram_v1");
        }
        let invalid: NativeModule = serde_json::from_value(invalid).unwrap();
        rejected(&invalid, "invalid non-integral address space");
    }

    for (layout, pointer_bits, little_endian) in [
        ("E-p:64:64-i64:64", 64, false),
        ("e-p:32:32-i64:64", 32, true),
        ("e-p:64:64:64:32-i64:64", 64, true),
        ("e-p:64:64-i64:64-A1", 64, true),
        ("e-p:64:64-i64:64-P1", 64, true),
        ("e-p:64:64-i64:64-G1", 64, true),
    ] {
        let mut source = serde_json::to_value(fixture(Family::Fence, I64)).unwrap();
        source["target"]["data_layout"] = json!(layout);
        source["target"]["pointer_bits"] = json!(pointer_bits);
        source["target"]["little_endian"] = json!(little_endian);
        let unprofiled: NativeModule = serde_json::from_value(source.clone()).unwrap();
        accepted(&unprofiled);
        source["target"]["atomic_profile"] = json!("coherent_ram_v1");
        let profiled: NativeModule = serde_json::from_value(source).unwrap();
        rejected(
            &profiled,
            "coherent RAM atomic profile requires integral AS0 little-endian 64-bit pointers/indices and default address spaces",
        );
    }
}

#[test]
fn scalar_reference_execution_explicitly_rejects_all_five_families_including_cold_code() {
    for family in FAMILIES {
        for cold in [false, true] {
            let mut module = fixture(family, I64);
            if cold {
                let atomic = module.functions[0].blocks[0].instructions.remove(0);
                module.functions[0].blocks.push(Block {
                    id: 100,
                    instructions: vec![atomic],
                    terminator: Terminator::Return { value: None },
                });
            }
            accepted(&module);
            // A zero budget also proves that the unsupported-profile audit
            // precedes scalar execution. This does not simulate atomic memory.
            let diagnostic = super::super::native_interpret::evaluate_with_step_limit(
                &module,
                "atomic_fixture",
                &[],
                0,
            )
            .unwrap_err();
            assert!(
                diagnostic.message.contains(
                    "atomic memory and synchronization execution is not implemented by the scalar reference interpreter"
                ),
                "{}",
                diagnostic.message
            );
        }
    }
}
