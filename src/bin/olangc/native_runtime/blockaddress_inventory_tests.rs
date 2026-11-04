//! Admission controls, not whole-runtime or native semantic qualification.
//! Pure label-bound controls deliberately demonstrate why an in-owner address
//! forgery needs a private exact-object reproduction witness as well.
use super::*;
use o_lang::ocore::native_ir::{Block, BlockAddressRef, Operand, Relocation, Terminator};

fn module(arch: &str, abi: Option<&str>) -> NativeModule {
    let mut module = object_inventory_tests::module();
    module.target.triple = format!("{arch}-unknown-none");
    module.target.abi = abi.map(str::to_owned);
    module.types.push(Type::Pointer { address_space: 0 });
    module.globals[0].ty = 2;
    module.globals[0].initializer.as_mut().unwrap().relocations = vec![Relocation {
        offset: 0,
        width: 64,
        symbol: String::new(),
        addend: 7,
        block: Some(BlockAddressRef {
            function: "f".into(),
            block: 1,
        }),
        relative_to: None,
    }];
    let entry = &mut module.functions[0].blocks[0];
    entry.terminator = Terminator::IndirectBranch {
        address: Operand::BlockAddress {
            ty: 2,
            function: "f".into(),
            block: 1,
            addend: 0,
        },
        destinations: vec![1, 2, 1],
    };
    for id in [1, 2] {
        module.functions[0].blocks.push(Block {
            id,
            instructions: vec![],
            terminator: Terminator::Return {
                value: Some(Operand::Int {
                    ty: 1,
                    bits: id.to_string(),
                }),
            },
        });
    }
    NativeModule::from_json(&module.to_json().unwrap()).unwrap()
}

#[test]
fn code_block_dependencies_keep_same_unit_owners_and_whole_group_retention() {
    let module = module("x86_64", None);
    let records = symbols("original", &module).unwrap();
    for record in &records {
        assert!(
            record.references.is_empty(),
            "code labels are not ordinary providers"
        );
        assert!(!record.references.contains(""));
        assert!(record.block_references.contains(&("f".into(), 1)));
    }
    assert!(resolve_symbols(&records).1.is_empty());
    let mut missing = records.clone();
    missing[0].blocks.remove(&1);
    assert!(resolve_symbols(&missing)
        .1
        .iter()
        .any(|issue| issue.contains("owned code block")));
    let mut other_unit = records.clone();
    other_unit[0].unit = "substitute".into();
    assert!(resolve_symbols(&other_unit)
        .1
        .iter()
        .any(|issue| issue.contains("owned code block")));

    let mut overridden = records.clone();
    overridden[0].linkage = "weak".into();
    let mut winner = overridden[0].clone();
    winner.unit = "other".into();
    winner.linkage = "external".into();
    winner.block_references.clear();
    overridden.push(winner);
    let (receipt, issues) = resolve_symbols(&overridden);
    assert!(issues.is_empty(), "{issues:?}");
    assert!(receipt["definition_references"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| {
            item["kind"] == "owned_code_block"
                && item["unit"] == "original"
                && item["resolved_unit"] == "original"
        }));

    let group = GroupMembership {
        name: "selection".into(),
        selection: o_lang::ocore::native_ir::ComdatSelection::Any,
    };
    let mut discarded = records.clone();
    discarded[0].comdat = Some(group.clone());
    discarded[0].linkage = "weak".into();
    let mut first = discarded[0].clone();
    first.unit = "first".into();
    first.block_references.clear();
    discarded.insert(0, first);
    assert!(resolve_symbols(&discarded)
        .1
        .iter()
        .any(|issue| issue.contains("owned code block")));
}

fn mapped_label(module: &NativeModule, target: o_lang::ocore::Target, block: usize) -> String {
    let (assembly, map) = o_lang::ocore::native_codegen::emit_with_map(module, target).unwrap();
    let site = map
        .sites
        .iter()
        .find(|site| {
            site.function == "f"
                && site.block == Some(block)
                && site.kind == o_lang::ocore::native_map::NativeAssemblySiteKind::BlockLabel
        })
        .unwrap();
    assembly[site.assembly_start..site.assembly_end]
        .strip_suffix(":\n")
        .unwrap()
        .into()
}

#[test]
fn retained_label_identity_checks_reject_missing_ambiguous_and_wrong_owner_labels() {
    for arch in ["x86_64", "aarch64", "riscv64"] {
        let module = module(arch, None);
        let target = object_target(arch).unwrap();
        let section = |flags| Section {
            kind: 1,
            flags,
            offset: 0,
            size: 128,
            link: 0,
            info: 0,
            alignment: 4,
            stride: 0,
        };
        let sections = vec![section(0), section(6), section(3)];
        let definitions = BTreeMap::from([(
            "f".into(),
            Definition {
                kind: 2,
                binding: 1,
                visibility: 0,
                size: 128,
                value: 0,
                section: 1,
            },
        )]);
        let table = || {
            BTreeMap::from([(
                3,
                [1, 2]
                    .into_iter()
                    .map(|block| ObjectSymbol {
                        name: mapped_label(&module, target, block),
                        kind: 0,
                        binding: 0,
                        visibility: 0,
                        section: 1,
                        value: 16 * block as u64,
                        size: 0,
                    })
                    .collect::<Vec<_>>(),
            )])
        };
        assert!(owned_block_bindings(arch, &module, &definitions, &sections, &table()).is_ok());
        let mut missing = table();
        missing.get_mut(&3).unwrap().remove(0);
        assert!(owned_block_bindings(arch, &module, &definitions, &sections, &missing).is_err());
        let mut duplicate = table();
        duplicate.get_mut(&3).unwrap().push(ObjectSymbol {
            name: mapped_label(&module, target, 1),
            kind: 0,
            binding: 0,
            visibility: 0,
            section: 1,
            value: 16,
            size: 0,
        });
        assert!(owned_block_bindings(arch, &module, &definitions, &sections, &duplicate).is_err());
        for (section, value, binding, kind, size) in [
            (2, 16, 0, 0, 0),
            (1, 128, 0, 0, 0),
            (1, 16, 1, 0, 0),
            (1, 16, 0, 2, 0),
            (1, 16, 0, 0, 8),
        ] {
            let mut forged = table();
            let label = &mut forged.get_mut(&3).unwrap()[0];
            label.section = section;
            label.value = value;
            label.binding = binding;
            label.kind = kind;
            label.size = size;
            assert!(owned_block_bindings(arch, &module, &definitions, &sections, &forged).is_err());
        }
        let mut swapped = table();
        swapped.get_mut(&3).unwrap().swap(0, 1);
        // Table order carries no meaning: exact names still bind the right owners.
        assert!(owned_block_bindings(arch, &module, &definitions, &sections, &swapped).is_ok());
        let mut coherent = table();
        coherent.get_mut(&3).unwrap()[0].value += 4;
        assert!(
            owned_block_bindings(arch, &module, &definitions, &sections, &coherent).is_ok(),
            "bounds alone cannot detect coherent in-owner machine-offset forgeries"
        );
        let error = object_inventory(b"coherently forged object", arch, &module)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("independent exact object reproduction"),
            "{error}"
        );
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// This test really assembles when executed. Missing assembler/profile support
/// is a failure, never a skip. It does not execute target machine code.
#[test]
fn exact_reproduction_rejects_coherent_in_owner_label_and_relocation_forgery() {
    use o_lang::ocore::{driver, CompileOptions, EmitKind};
    for (arch, abi, name) in [
        ("x86_64", None, "x86_64"),
        ("aarch64", None, "aarch64"),
        ("riscv64", Some("lp64"), "rv64-lp64"),
        ("riscv64", Some("lp64d"), "rv64-lp64d"),
    ] {
        let module = module(arch, abi);
        let target = object_target(arch).unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ostadix-block-object-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let input = directory.join("module.native.json");
        let artifact = directory.join("module.o");
        fs::write(&input, module.to_json().unwrap()).unwrap();
        driver::compile_native_module(
            &input,
            &CompileOptions {
                target,
                emit: EmitKind::Object,
                output: artifact.clone(),
                keep_assembly: true,
            },
        )
        .unwrap();
        let original = fs::read(&artifact).unwrap();
        let proof = driver::reproduce_native_object(
            &module,
            target,
            &original,
            &directory.join("reproduction"),
        )
        .unwrap();
        assert!(object_inventory_with_reproduction(&original, arch, &module, Some(&proof)).is_ok());
        let assembly_path =
            PathBuf::from(proof.receipt()["evidence_directory"].as_str().unwrap()).join("module.s");
        let verified_assembly = fs::read(&assembly_path).unwrap();
        let first = format!(".quad {}+7", mapped_label(&module, target, 1));
        let second = format!(".quad {}+7", mapped_label(&module, target, 2));
        let changed_assembly = std::str::from_utf8(&verified_assembly)
            .unwrap()
            .replacen(&first, &second, 1);
        assert_ne!(changed_assembly.as_bytes(), verified_assembly.as_slice());
        // Mutate the actual file observed by the same guard used before/after
        // assembly. The supplied object and private in-memory source stay fixed.
        fs::write(&assembly_path, changed_assembly.as_bytes()).unwrap();
        assert_ne!(fs::read(&assembly_path).unwrap(), verified_assembly);
        let error = object_inventory_with_reproduction(&original, arch, &module, Some(&proof))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("on-disk reproduction inputs changed"),
            "{error}"
        );
        fs::write(&assembly_path, &verified_assembly).unwrap();
        assert!(object_inventory_with_reproduction(&original, arch, &module, Some(&proof)).is_ok());
        assert!(object_inventory(&original, arch, &module)
            .unwrap_err()
            .to_string()
            .contains("independent exact object reproduction"));
        let mut forged = original.clone();
        let headers = u64_at(&original, 40) as usize;
        let count = u16_at(&original, 60) as usize;
        let symbol_header = (0..count)
            .map(|i| headers + i * 64)
            .find(|&h| u32_at(&original, h + 4) == 2)
            .unwrap();
        let symbols = u64_at(&original, symbol_header + 24) as usize;
        let symbol_count = u64_at(&original, symbol_header + 32) as usize / 24;
        let names_header = headers + u32_at(&original, symbol_header + 40) as usize * 64;
        let names = u64_at(&original, names_header + 24) as usize;
        let label = mapped_label(&module, target, 1);
        let symbol_name = |index: usize| {
            let start = names + u32_at(&original, symbols + index * 24) as usize;
            let end = start + original[start..].iter().position(|&b| b == 0).unwrap();
            std::str::from_utf8(&original[start..end]).unwrap()
        };
        let label_index = (0..symbol_count)
            .find(|&index| symbol_name(index) == label)
            .unwrap();
        let owner_index = (0..symbol_count)
            .find(|&index| symbol_name(index) == "f")
            .unwrap();
        let global_index = (0..symbol_count)
            .find(|&index| symbol_name(index) == "g")
            .unwrap();
        let label_offset = symbols + label_index * 24 + 8;
        let old = u64_at(&original, label_offset);
        let owner = symbols + owner_index * 24;
        let global = symbols + global_index * 24;
        let changed = old.checked_add(4).unwrap();
        assert!(changed < u64_at(&original, owner + 8) + u64_at(&original, owner + 16));
        put64(&mut forged, label_offset, changed);
        let data_section = u16_at(&original, global + 6) as usize;
        let rela_header = (0..count)
            .map(|i| headers + i * 64)
            .find(|&h| {
                u32_at(&original, h + 4) == 4 && u32_at(&original, h + 44) as usize == data_section
            })
            .unwrap();
        let records = u64_at(&original, rela_header + 24) as usize;
        let relocation = (0..u64_at(&original, rela_header + 32) as usize / 24)
            .map(|i| records + i * 24)
            .find(|&r| u64_at(&original, r) == u64_at(&original, global + 8))
            .unwrap();
        let target_index = (u64_at(&original, relocation + 8) >> 32) as usize;
        if original[symbols + target_index * 24 + 4] & 15 == 3 {
            let addend = u64_at(&original, relocation + 16);
            assert_eq!(addend, old.wrapping_add(7));
            put64(&mut forged, relocation + 16, addend.wrapping_add(4));
        } else {
            assert_eq!(target_index, label_index);
            assert_eq!(u64_at(&original, relocation + 16), 7);
        }
        // The local identity and relocation still agree within the original
        // function extent. Only exact reproduced object bytes are authority.
        let error = object_inventory_with_reproduction(&forged, arch, &module, Some(&proof))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("object reproduction module/target/object mismatch"),
            "{error}"
        );
        fs::write(directory.join("coherent-forgery.o"), forged).unwrap();
    }
}
