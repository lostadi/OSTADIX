//! Atomic operands remain ordinary dependency edges. Scope names and ordering
//! labels are compiler contracts, never implicit native symbol providers.
use super::*;
use o_lang::ocore::native_ir::Value as NativeValue;
use o_lang::ocore::native_ir::*;

fn atomic_module() -> NativeModule {
    let mut module = super::object_inventory_tests::module();
    module.target.atomic_profile = Some(AtomicProfile::CoherentRamV1);
    module.types.extend([
        Type::Pointer { address_space: 0 },
        Type::Int { bits: 1 },
        Type::Struct {
            fields: vec![2, 3],
            packed: false,
        },
    ]);
    module.atomic_sync_scopes = vec![
        AtomicSyncScope {
            id: 0,
            name: b"singlethread".to_vec(),
        },
        AtomicSyncScope {
            id: 1,
            name: vec![],
        },
        AtomicSyncScope {
            id: 2,
            name: b"scope_not_a_symbol\0\xff".to_vec(),
        },
    ];
    for name in ["atomic_cell", "atomic_expected", "atomic_replacement"] {
        let mut global = module.globals[0].clone();
        global.name = name.into();
        global.ty = 2;
        global.initializer = None;
        module.globals.push(global);
    }
    module.provenance.source_global_count = module.globals.len();
    let symbol = |name: &str| Operand::Symbol {
        ty: 2,
        name: name.into(),
    };
    module.functions[0].blocks[0].instructions = vec![
        Instruction {
            result: Some(NativeValue { id: 10, ty: 2 }),
            operation: Operation::AtomicLoad {
                pointer: symbol("atomic_cell"),
                alignment: 8,
                volatile: true,
                ordering: AtomicOrdering::Acquire,
                sync_scope: 1,
            },
        },
        Instruction {
            result: None,
            operation: Operation::AtomicStore {
                pointer: symbol("atomic_cell"),
                value: symbol("atomic_expected"),
                alignment: 8,
                volatile: false,
                ordering: AtomicOrdering::Release,
                sync_scope: 1,
            },
        },
        Instruction {
            result: None,
            operation: Operation::AtomicFence {
                ordering: AtomicOrdering::SequentiallyConsistent,
                sync_scope: 2,
            },
        },
        Instruction {
            result: Some(NativeValue { id: 11, ty: 2 }),
            operation: Operation::AtomicRmw {
                kind: AtomicRmwOp::Xchg,
                pointer: symbol("atomic_cell"),
                value: symbol("atomic_replacement"),
                alignment: 8,
                volatile: false,
                ordering: AtomicOrdering::AcquireRelease,
                sync_scope: 1,
            },
        },
        Instruction {
            result: Some(NativeValue { id: 12, ty: 4 }),
            operation: Operation::AtomicCompareExchange {
                pointer: symbol("atomic_cell"),
                expected: symbol("atomic_expected"),
                replacement: symbol("atomic_replacement"),
                alignment: 8,
                volatile: true,
                weak: true,
                success_ordering: AtomicOrdering::Monotonic,
                failure_ordering: AtomicOrdering::SequentiallyConsistent,
                sync_scope: 1,
            },
        },
    ];
    o_lang::ocore::native_verify::verify(&module).unwrap();
    module
}

#[test]
fn all_atomic_symbol_operands_are_dependencies_and_scope_bytes_are_not() {
    let module = atomic_module();
    assert_eq!(
        function_references(&module.functions[0]),
        BTreeSet::from([
            "atomic_cell".into(),
            "atomic_expected".into(),
            "atomic_replacement".into(),
        ])
    );
    let (receipt, issues) = resolve_symbols(&symbols("original-unit", &module).unwrap());
    assert!(!issues.is_empty());
    assert_eq!(receipt["closed"], false);
    assert!(issues
        .iter()
        .any(|issue| issue.contains("atomic_replacement")));
    assert!(issues
        .iter()
        .all(|issue| !issue.contains("scope_not_a_symbol")));
}

#[test]
fn included_atomic_storage_closes_edges_without_fabricated_atomic_helpers() {
    let mut module = atomic_module();
    let initializer = module.globals[0].initializer.clone();
    for global in module.globals.iter_mut().skip(1) {
        global.initializer = initializer.clone();
    }
    o_lang::ocore::native_verify::verify(&module).unwrap();
    let (receipt, issues) = resolve_symbols(&symbols("original-unit", &module).unwrap());
    assert!(issues.is_empty(), "{issues:?}");
    assert_eq!(receipt["closed"], true);
}

#[test]
fn cold_atomic_replacement_and_address_edges_are_retained() {
    let mut module = atomic_module();
    let mut cold = module.functions[0].blocks[0].clone();
    cold.id = 7;
    module.functions[0].blocks[0].instructions.clear();
    module.functions[0].blocks.push(cold);
    o_lang::ocore::native_verify::verify(&module).unwrap();
    assert_eq!(function_references(&module.functions[0]).len(), 3);
    let (_, issues) = resolve_symbols(&symbols("original-unit", &module).unwrap());
    assert!(issues
        .iter()
        .any(|issue| issue.contains("atomic_replacement")));
}
