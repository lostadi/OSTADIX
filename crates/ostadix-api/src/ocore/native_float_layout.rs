// Binary128 storage is not a first-class floating-point realization. This
// audit runs before leaf expansion or emission, including dead SSA values.
use super::*;

fn failure(message: &str) -> Diagnostic {
    error_diagnostic(format!("native binary128 storage: {message}"))
}

pub(super) fn audit(module: &NativeModule, executable: &[TypeId]) -> Result<(), Diagnostic> {
    let mut parents = vec![Vec::new(); module.types.len()];
    let mut pending = Vec::new();
    for (id, ty) in module.types.iter().enumerate() {
        match ty {
            Type::Float { bits: 128 } => pending.push(id),
            Type::Struct { fields, .. } => {
                for field in fields {
                    parents[*field].push(id);
                }
            }
            Type::Array { element, .. } => parents[*element].push(id),
            _ => {}
        }
    }
    if pending.is_empty() {
        return Ok(());
    }
    let layouts = type_layouts(module)?;
    for id in &pending {
        if layouts[*id] != Some((16, 16)) {
            return Err(failure("requires exactly 16-byte ABI size and alignment"));
        }
    }
    let mut containing = vec![false; module.types.len()];
    while let Some(id) = pending.pop() {
        if !containing[id] {
            containing[id] = true;
            pending.extend(parents[id].iter().copied());
        }
    }
    // Include every executable type root and its complete structural contract,
    // even a zero-length array or an instruction whose result has no uses.
    if executable.iter().any(|id| containing[*id]) {
        return Err(failure("first-class SSA and ABI values are unsupported, including nested aggregates and zero-length arrays"));
    }
    for global in &module.globals {
        if !containing[global.ty] {
            continue;
        }
        let Some(initializer) = &global.initializer else {
            continue;
        };
        // Compact zero storage needs no per-element traversal, irrespective of
        // array size. Nonzero integer/pointer fields remain supported below.
        if initializer.relocations.is_empty() && initializer.bytes.iter().all(|byte| *byte == 0) {
            continue;
        }
        audit_initializer(module, &layouts, &containing, global.ty, initializer)?;
    }
    Ok(())
}

fn aligned(value: u64, alignment: u64) -> Result<u64, Diagnostic> {
    value
        .checked_add(alignment - 1)
        .map(|n| n & !(alignment - 1))
        .ok_or_else(|| failure("storage layout offset overflow"))
}

enum Visit {
    Type(TypeId, u64),
    Array {
        element: TypeId,
        base: u64,
        stride: u64,
        index: u64,
        len: u64,
    },
}

fn audit_initializer(
    module: &NativeModule,
    layouts: &[Option<(u64, u64)>],
    containing: &[bool],
    root: TypeId,
    initializer: &Initializer,
) -> Result<(), Diagnostic> {
    let mut pending = vec![Visit::Type(root, 0)];
    while let Some(visit) = pending.pop() {
        let (ty, offset) = match visit {
            Visit::Type(ty, offset) => (ty, offset),
            Visit::Array {
                element,
                base,
                stride,
                index,
                len,
            } => {
                if index == len {
                    continue;
                }
                let offset = index
                    .checked_mul(stride)
                    .and_then(|n| base.checked_add(n))
                    .ok_or_else(|| failure("array storage offset overflow"))?;
                pending.push(Visit::Array {
                    element,
                    base,
                    stride,
                    index: index + 1,
                    len,
                });
                (element, offset)
            }
        };
        if !containing[ty] {
            continue;
        }
        match &module.types[ty] {
            Type::Float { bits: 128 } => {
                let end = offset
                    .checked_add(16)
                    .ok_or_else(|| failure("storage extent overflow"))?;
                let start = usize::try_from(offset)
                    .map_err(|_| failure("storage offset exceeds address space"))?;
                let end_index = usize::try_from(end)
                    .map_err(|_| failure("storage extent exceeds address space"))?;
                let bytes = initializer
                    .bytes
                    .get(start..end_index)
                    .ok_or_else(|| failure("binary128 initializer extent is missing"))?;
                if bytes.iter().any(|byte| *byte != 0) {
                    return Err(failure(
                        "initializer requires exact positive-zero binary128 bytes",
                    ));
                }
                for relocation in &initializer.relocations {
                    let relocation_end = relocation
                        .offset
                        .checked_add(u64::from(relocation.width.div_ceil(8)))
                        .ok_or_else(|| failure("initializer relocation extent overflow"))?;
                    if relocation.offset < end && offset < relocation_end {
                        return Err(failure(
                            "relocations cannot populate binary128 storage fields",
                        ));
                    }
                }
            }
            Type::Array { element, len } => {
                let (size, alignment) =
                    layouts[*element].ok_or_else(|| failure("unsized storage element"))?;
                // A sized array may have an enormous count but no storage.
                // There is no binary128 byte interval to validate in that case.
                if *len == 0 || size == 0 {
                    continue;
                }
                pending.push(Visit::Array {
                    element: *element,
                    base: offset,
                    stride: aligned(size, alignment)?,
                    index: 0,
                    len: *len,
                });
            }
            Type::Struct { fields, packed } => {
                let mut cursor = 0;
                for field in fields {
                    let (size, alignment) =
                        layouts[*field].ok_or_else(|| failure("unsized storage field"))?;
                    cursor = aligned(cursor, if *packed { 1 } else { alignment })?;
                    let field_offset = offset
                        .checked_add(cursor)
                        .ok_or_else(|| failure("structure storage offset overflow"))?;
                    pending.push(Visit::Type(*field, field_offset));
                    cursor = cursor
                        .checked_add(size)
                        .ok_or_else(|| failure("structure storage extent overflow"))?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn module(triple: &str) -> NativeModule {
        let mut bytes = vec![0; 80];
        bytes[0] = 7;
        bytes[64] = 42;
        serde_json::from_value(json!({
            "format":FORMAT,"name":"binary128-storage",
            "target":{"triple":triple,"data_layout":"e-p:64:64-i64:64-f128:128-S128",
                "pointer_bits":64,"little_endian":true},
            "semantics":"llvm_defined_behavior_v1",
            "types":[{"kind":"void"},{"kind":"int","bits":64},{"kind":"pointer","address_space":0},
                {"kind":"float","bits":128},{"kind":"array","element":3,"len":0},
                {"kind":"struct","fields":[4],"packed":false},{"kind":"int","bits":8},
                {"kind":"array","element":3,"len":2},{"kind":"int","bits":32},
                {"kind":"struct","fields":[6,3,7,8],"packed":false},
                {"kind":"struct","fields":[6,3,8],"packed":true}],
            "globals":[{"name":"storage","ty":9,"linkage":"external","constant":false,"thread_local":false,
                "alignment":16,"initializer":{"bytes":bytes,"relocations":[]}},
                {"name":"packed_storage","ty":10,"linkage":"external","constant":false,"thread_local":false,
                "alignment":1,"initializer":{"bytes":vec![0;21],"relocations":[]}}],
            "functions":[{"name":"entry","linkage":"external",
                "signature":{"params":[],"result":0,"abi":"c","variadic":false},"params":[],"entry":0,
                "blocks":[{"id":0,"instructions":[],"terminator":{"op":"return","value":null}}]}],
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"authored-test","frontend_version":"1",
                "importer":"test","importer_version":"1","source_function_count":1,"source_global_count":2,"refinements":[]}
        })).unwrap()
    }

    fn targets() -> [(Target, &'static str); 3] {
        [
            (Target::X86_64UnknownNone, "x86_64-unknown-linux-gnu"),
            (Target::Aarch64UnknownNone, "aarch64-unknown-linux-gnu"),
            (Target::Riscv64UnknownNone, "riscv64-unknown-linux-gnu"),
        ]
    }

    #[test]
    fn zero_storage_preserves_unpacked_packed_and_array_layout_on_each_isa() {
        for (target, triple) in targets() {
            let module = module(triple);
            let layouts = type_layouts(&module).unwrap();
            assert_eq!(layouts[3], Some((16, 16)));
            assert_eq!(layouts[7], Some((32, 16)));
            assert_eq!(layouts[9], Some((80, 16)));
            assert_eq!(layouts[10], Some((21, 1)));
            let assembly = emit(&module, target).unwrap();
            let (mapped, map) = emit_with_map(&module, target).unwrap();
            assert_eq!(assembly, mapped);
            map.verify(&module, target, &assembly).unwrap();
            assert!(assembly.contains("storage:"));
            assert!(assembly.contains("packed_storage:"));
        }
    }

    #[test]
    fn dead_first_class_values_nested_zero_arrays_and_unused_abi_are_rejected() {
        for (target, triple) in targets() {
            for ty in [3, 4, 5] {
                let mut module = module(triple);
                module.functions[0].blocks[0]
                    .instructions
                    .push(Instruction {
                        result: Some(Value { id: 0, ty }),
                        operation: Operation::Freeze {
                            value: Operand::Undef { ty },
                        },
                    });
                super::super::super::native_verify::verify(&module).unwrap();
                let error = emit(&module, target).unwrap_err();
                assert!(
                    error.message.contains("first-class SSA and ABI"),
                    "{}",
                    error.message
                );
                module.functions[0].blocks[0].instructions.clear();
                module.functions[0].signature.params.push(ty);
                module.functions[0].params.push(Value { id: 0, ty });
                module.functions[0].entry = None;
                module.functions[0].blocks.clear();
                assert!(emit(&module, target).is_err());
            }
        }
    }

    #[test]
    fn nonzero_float_fields_and_relocations_cannot_hide_among_integer_bytes() {
        for (target, triple) in targets() {
            for offset in [16, 32, 48] {
                let mut module = module(triple);
                module.globals[0].initializer.as_mut().unwrap().bytes[offset] = 1;
                assert!(emit(&module, target)
                    .unwrap_err()
                    .message
                    .contains("positive-zero"));
            }
            let mut module = module(triple);
            module.globals[0]
                .initializer
                .as_mut()
                .unwrap()
                .relocations
                .push(Relocation {
                    offset: 16,
                    width: 64,
                    symbol: "storage".into(),
                    addend: 0,
                    relative_to: None,
                });
            assert!(emit(&module, target).is_err());
        }
    }

    #[test]
    fn huge_arrays_of_zero_sized_float_storage_do_not_expand() {
        for (target, triple) in targets() {
            let mut module = module(triple);
            let array = module.types.len();
            module.types.push(Type::Array {
                element: 4,
                len: u64::MAX,
            });
            let structure = module.types.len();
            module.types.push(Type::Struct {
                fields: vec![6, array],
                packed: false,
            });
            module.globals.truncate(1);
            module.provenance.source_global_count = 1;
            module.globals[0].ty = structure;
            let initializer = module.globals[0].initializer.as_mut().unwrap();
            initializer.bytes = vec![0; 16];
            initializer.bytes[0] = 7;
            assert_eq!(type_layouts(&module).unwrap()[structure], Some((16, 16)));
            assert!(emit(&module, target).is_ok());
        }
    }

    #[test]
    fn alternate_binary128_abi_layout_is_rejected_even_without_storage_values() {
        for (target, triple) in targets() {
            for alignment in [64, 256] {
                let mut module = module(triple);
                module.globals.clear();
                module.provenance.source_global_count = 0;
                module.target.data_layout = format!("e-p:64:64-i64:64-f128:{alignment}-S128");
                assert!(emit(&module, target)
                    .unwrap_err()
                    .message
                    .contains("16-byte ABI"));
            }
        }
    }
}
