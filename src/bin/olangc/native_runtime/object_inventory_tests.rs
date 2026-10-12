//! Independent ELF fixtures for the native-runtime object admission boundary.
//!
//! These fixtures exercise the parser without depending on a host assembler or
//! accepting its output as the oracle. They are inventories, not executable
//! witnesses; execution qualification remains a separate native platform gate.

use super::*;
use o_lang::ocore::native_ir::{Alias, Comdat, ComdatSelection, Relocation};

struct TlsFixture {
    elf: Elf,
    module: NativeModule,
    rela: usize,
}

impl TlsFixture {
    fn new(machine: u16, arch: &str) -> Self {
        use o_lang::ocore::native_ir::{Instruction, Operation, TlsModel, TlsProfile, Value};
        let mut module = module();
        module.target.triple = format!("{arch}-unknown-linux-musl");
        module.target.tls_profile = Some(TlsProfile::LinuxElfStaticNonpreemptiveV1);
        module.types.push(Type::Pointer { address_space: 0 });
        module.globals[0].thread_local = true;
        module.globals[0].tls_model = Some(TlsModel::GeneralDynamic);
        module.functions[0].blocks[0]
            .instructions
            .push(Instruction {
                result: Some(Value { id: 0, ty: 2 }),
                operation: Operation::ThreadLocalAddress { global: "g".into() },
            });
        // Independently authored machine words and relocations, not parsed from
        // this compiler's assembly. These witnesses qualify object admission.
        let (code, fixups) = match arch {
            "x86_64" => (
                vec![
                    0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80, 0, 0, 0, 0,
                ],
                vec![(12, 23)],
            ),
            "aarch64" => (
                [0xd53b_d049u32, 0x9140_0129, 0x9100_0129]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
                vec![(4, 549), (8, 551)],
            ),
            "riscv64" => (
                [0x0000_02b7u32, 0x0042_82b3, 0x0002_8293]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
                vec![(0, 29), (4, 32), (8, 30)],
            ),
            _ => unreachable!(),
        };
        let mut elf = Elf::with_text_size(machine, 8, 8, code.len());
        elf.replace_section_payload(TEXT, &code, 4);
        elf.symbol64(1, 16, code.len() as u64);
        elf.symbol8(2, 4, 0x16); // STB_GLOBAL | STT_TLS.
        elf.section64(DATA, 8, 0x403); // WRITE | ALLOC | TLS.
        let records: Vec<_> = fixups
            .into_iter()
            .flat_map(|(offset, kind)| relocation_entry(offset, 2, kind, 0))
            .collect();
        let rela = elf.append_section(4, 0x40, &records, SYMBOLS as u32, TEXT as u32, 8, 24);
        Self { elf, module, rela }
    }
}

#[test]
fn tls_objects_preserve_models_storage_and_exact_owned_tp_sequences() {
    use o_lang::ocore::native_ir::TlsModel;
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut fixture = TlsFixture::new(machine, arch);
        for model in [
            TlsModel::GeneralDynamic,
            TlsModel::LocalDynamic,
            TlsModel::InitialExec,
            TlsModel::LocalExec,
        ] {
            fixture.module.globals[0].tls_model = Some(model);
            // LLVM constant metadata does not make per-thread physical storage
            // read-only. A thread still receives its own initialized template.
            for constant in [false, true] {
                fixture.module.globals[0].constant = constant;
                let receipt = object_inventory(&fixture.elf.bytes, arch, &fixture.module).unwrap();
                assert_eq!(
                    receipt["thread_local_storage"]["addresses"][0]["source_model"],
                    json!(model)
                );
                assert_eq!(
                    receipt["thread_local_storage"]["tls_platform_execution_qualified"],
                    false
                );
            }
        }
        for flags in [3, 0x402, 0x407] {
            let mut mutant = fixture.elf.clone();
            mutant.section64(DATA, 8, flags);
            group_rejected(&mutant, arch, &fixture.module, "global storage differs");
        }
        let mut ordinary = fixture.elf.clone();
        ordinary.symbol8(2, 4, 0x11);
        group_rejected(
            &ordinary,
            arch,
            &fixture.module,
            "definition type/size mismatch",
        );
    }
}

#[test]
fn tls_nobits_is_exact_source_zero_fill_without_reading_nominal_file_bytes() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut fixture = TlsFixture::new(machine, arch);
        fixture.elf.section32(DATA, 4, 8);
        fixture.elf.section64(DATA, 24, u64::MAX);
        assert!(object_inventory(&fixture.elf.bytes, arch, &fixture.module).is_ok());
        fixture.module.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .bytes[0] = 7;
        group_rejected(
            &fixture.elf,
            arch,
            &fixture.module,
            "NOBITS template must exactly",
        );
        fixture.module.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .bytes[0] = 0;
        fixture.elf.section64(DATA, 32, 7);
        assert!(object_inventory(&fixture.elf.bytes, arch, &fixture.module).is_err());
    }
}

#[test]
fn tls_address_fixups_cannot_change_tp_symbol_addend_opcode_or_inventory() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let fixture = TlsFixture::new(machine, arch);
        let relocation = fixture.elf.section_value(fixture.rela, 24) as usize;
        let code = fixture.elf.section_value(TEXT, 24) as usize;
        for mutate in 0..6 {
            let mut mutant = fixture.elf.clone();
            match mutate {
                0 => put64(&mut mutant.bytes, relocation + 16, 1),
                1 => put64(
                    &mut mutant.bytes,
                    relocation + 8,
                    (1u64 << 32) | absolute_relocation_type(machine) as u64,
                ),
                2 => mutant.bytes[code] ^= 1,
                3 => mutant.section64(fixture.rela, 32, 0),
                4 => {
                    let size = mutant.section_value(fixture.rela, 32) as usize;
                    let mut records = mutant.bytes[relocation..relocation + size].to_vec();
                    records.extend_from_within(..24);
                    mutant.replace_section_payload(fixture.rela, &records, 8);
                }
                5 => {
                    let info = u64::from_le_bytes(
                        mutant.bytes[relocation + 8..relocation + 16]
                            .try_into()
                            .unwrap(),
                    );
                    put64(
                        &mut mutant.bytes,
                        relocation + 8,
                        (info & !0xffff_ffff) | absolute_relocation_type(machine) as u64,
                    );
                }
                _ => unreachable!(),
            }
            assert!(
                object_inventory(&mutant.bytes, arch, &fixture.module).is_err(),
                "TLS mutant {mutate} admitted for {arch}"
            );
        }
    }
}

#[test]
fn tls_external_references_remain_typed_dependencies_and_close_across_models() {
    use o_lang::ocore::native_ir::TlsModel;
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut fixture = TlsFixture::new(machine, arch);
        let mut provider = fixture.module.clone();
        provider.functions.clear();
        provider.globals[0].tls_model = Some(TlsModel::LocalExec);
        fixture.module.globals[0].initializer = None;
        fixture.elf.symbol16(2, 6, 0);
        fixture.elf.symbol64(2, 16, 0);
        // The consumer contains only an undefined TLS symbol and address code;
        // it contributes no source TLS template to PT_TLS.
        fixture.elf.section64(DATA, 8, 3);
        object_inventory(&fixture.elf.bytes, arch, &fixture.module).unwrap();
        let refs = function_references(&fixture.module.functions[0]);
        assert_eq!(refs, BTreeSet::from(["g".into()]));
        let consumers = symbols("consumer", &fixture.module).unwrap();
        assert!(!resolve_symbols(&consumers).1.is_empty());
        let mut all = consumers;
        all.extend(symbols("provider", &provider).unwrap());
        assert!(resolve_symbols(&all).1.is_empty());
        fixture.elf.symbol8(2, 4, 0x10);
        group_rejected(
            &fixture.elf,
            arch,
            &fixture.module,
            "TLS dependency must retain STT_TLS",
        );
    }
}

#[test]
fn tls_comdat_storage_retains_the_entire_original_group() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut fixture = TlsFixture::new(machine, arch);
        fixture.module.globals[0].comdat = Some("g".into());
        fixture.module.globals[0].linkage = "weak_odr".into();
        fixture.module.comdats.push(Comdat {
            name: "g".into(),
            selection: ComdatSelection::Any,
        });
        fixture.module.provenance.referenced_comdat_count = 1;
        fixture.elf.symbol8(2, 4, 0x26);
        fixture.elf.section64(DATA, 8, 0x403 | SHF_GROUP);
        let group =
            fixture
                .elf
                .append_section(17, 0, &group_payload(1, &[DATA]), SYMBOLS as u32, 2, 4, 4);
        assert!(object_inventory(&fixture.elf.bytes, arch, &fixture.module).is_ok());
        fixture
            .elf
            .replace_section_payload(group, &group_payload(1, &[TEXT]), 4);
        assert!(object_inventory(&fixture.elf.bytes, arch, &fixture.module).is_err());
    }
}

#[test]
fn tls_templates_preserve_absolute_pointers_to_ordinary_source_code() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut fixture = TlsFixture::new(machine, arch);
        fixture.module.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .relocations
            .push(Relocation {
                offset: 0,
                width: 64,
                symbol: "f".into(),
                addend: 0,
                relative_to: None,
            });
        let rela = fixture.elf.append_section(
            4,
            0x40,
            &relocation_entry(0, 1, absolute_relocation_type(machine), 0),
            SYMBOLS as u32,
            DATA as u32,
            8,
            24,
        );
        assert!(object_inventory(&fixture.elf.bytes, arch, &fixture.module).is_ok());
        let start = fixture.elf.section_value(rela, 24) as usize;
        put64(&mut fixture.elf.bytes, start + 16, 1);
        group_rejected(
            &fixture.elf,
            arch,
            &fixture.module,
            "initializer relocation symbol/addend differs",
        );
    }
}

#[test]
fn tls_storage_sections_cannot_invent_unowned_templates_or_tail_bytes() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let fixture = TlsFixture::new(machine, arch);
        for kind in [1, 8] {
            let mut extra = fixture.elf.clone();
            extra.append_section(kind, 0x403, &[1; 8], 0, 0, 8, 0);
            group_rejected(
                &extra,
                arch,
                &fixture.module,
                "without original source-owned storage",
            );
            let mut ordinary = Elf::new(machine, 8, 8);
            ordinary.append_section(kind, 0x403, &[0; 8], 0, 0, 8, 0);
            group_rejected(
                &ordinary,
                arch,
                &module(),
                "outside the explicit source profile",
            );
        }
        let mut tail = fixture.elf.clone();
        tail.replace_section_payload(DATA, &[0; 16], 8);
        group_rejected(
            &tail,
            arch,
            &fixture.module,
            "outside original source storage",
        );
        let mut prefix = fixture.elf.clone();
        prefix.replace_section_payload(DATA, &[0; 16], 8);
        prefix.symbol64(2, 8, 8);
        group_rejected(&prefix, arch, &fixture.module, "placement differs");
    }
}

#[test]
fn tls_tp_sequences_cannot_be_overwritten_by_extra_ordinary_linker_fixups() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut fixture = TlsFixture::new(machine, arch);
        let code = fixture.elf.section_value(TEXT, 24) as usize;
        let size = fixture.elf.section_value(TEXT, 32) as usize;
        let mut padded = vec![0; 8];
        padded.extend_from_slice(&fixture.elf.bytes[code..code + size]);
        fixture.elf.replace_section_payload(TEXT, &padded, 4);
        fixture.elf.symbol64(1, 16, padded.len() as u64);
        let rela = fixture.elf.section_value(fixture.rela, 24) as usize;
        let relbytes = fixture.elf.section_value(fixture.rela, 32) as usize;
        for index in (0..relbytes).step_by(24) {
            let offset = u64::from_le_bytes(
                fixture.elf.bytes[rela + index..rela + index + 8]
                    .try_into()
                    .unwrap(),
            );
            put64(&mut fixture.elf.bytes, rela + index, offset + 8);
        }
        object_inventory(&fixture.elf.bytes, arch, &fixture.module).unwrap();
        for (offset, kind, reason) in [
            (
                8,
                absolute_relocation_type(machine),
                "extra code relocation overwrites",
            ),
            (
                1,
                absolute_relocation_type(machine),
                "extra code relocation overwrites",
            ),
            (0, 0xfe26, "unknown code relocation write footprint"),
            (
                padded.len() as u64 - 1,
                absolute_relocation_type(machine),
                "write exceeds",
            ),
        ] {
            let mut mutant = fixture.elf.clone();
            mutant.append_section(
                4,
                0x40,
                &relocation_entry(offset, 1, kind, 0),
                SYMBOLS as u32,
                TEXT as u32,
                8,
                24,
            );
            group_rejected(&mutant, arch, &fixture.module, reason);
        }
    }
}

#[test]
fn x86_unwind_relocations_accept_owned_section_kind_without_widening_other_isas() {
    let mut elf = Elf::new(62, 8, 8);
    let unwind = elf.append_section(0x7000_0001, 2, &[0; 32], 0, 0, 8, 0);
    let mut entry = vec![0; 24];
    put64(&mut entry, 8, (1 << 32) | 2); // R_X86_64_PC32 to f.
    elf.append_section(4, 0x40, &entry, SYMBOLS as u32, unwind as u32, 8, 24);
    assert!(object_inventory(&elf.bytes, "x86_64", &module()).is_ok());
    for (field, value) in [(8, 0), (8, 3), (8, 6), (48, 4), (56, 8)] {
        let mut mutant = elf.clone();
        mutant.section64(unwind, field, value);
        assert!(object_inventory(&mutant.bytes, "x86_64", &module())
            .unwrap_err()
            .to_string()
            .contains("relocation section geometry or target"));
    }
    for (machine, arch) in [(183, "aarch64"), (243, "riscv64")] {
        let mut mutant = elf.clone();
        put16(&mut mutant.bytes, 18, machine);
        assert!(object_inventory(&mutant.bytes, arch, &module())
            .unwrap_err()
            .to_string()
            .contains("relocation section geometry or target"));
    }
}

#[test]
fn object_cannot_introduce_an_ambient_undefined_symbol() {
    let mut elf = Elf::new(62, 8, 8);
    elf.bytes[elf.strings + 1] = b'x';
    elf.symbol16(1, 6, 0);
    let error = object_inventory(&elf.bytes, "x86_64", &module()).unwrap_err();
    assert!(error.to_string().contains("undeclared native dependency"));
}

#[test]
fn object_cannot_hide_an_export_as_an_untyped_assembler_symbol() {
    let mut elf = Elf::new(62, 8, 8);
    elf.symbol8(1, 4, 0x10);
    let error = object_inventory(&elf.bytes, "x86_64", &module()).unwrap_err();
    assert!(error.to_string().contains("untyped exported definition"));
}

#[test]
fn weak_definitions_require_exact_elf_binding_type_extent_and_visibility() {
    for (machine, arch, triple) in [
        (62, "x86_64", "x86_64-unknown-none"),
        (183, "aarch64", "aarch64-unknown-none"),
        (243, "riscv64", "riscv64-unknown-none"),
    ] {
        let mut module = module();
        module.target.triple = triple.into();
        module.functions[0].linkage = "weak".into();
        module.globals[0].linkage = "weak".into();
        for visibility in [
            Visibility::Default,
            Visibility::Hidden,
            Visibility::Protected,
        ] {
            module.functions[0].visibility = visibility;
            module.globals[0].visibility = visibility;
            let mut elf = Elf::new(machine, 8, 8);
            elf.symbol8(1, 4, 0x22); // STB_WEAK | STT_FUNC.
            elf.symbol8(2, 4, 0x21); // STB_WEAK | STT_OBJECT.
            elf.symbol8(1, 5, visibility_bits(visibility));
            elf.symbol8(2, 5, visibility_bits(visibility));
            assert!(object_inventory(&elf.bytes, arch, &module).is_ok());
            for (index, kind) in [(1, 2), (2, 1)] {
                for binding in [0, 1, 3] {
                    let mut mutant = elf.bytes.clone();
                    mutant[elf.symbols + index * SYMBOL_BYTES + 4] = (binding << 4) | kind;
                    assert!(object_inventory(&mutant, arch, &module)
                        .unwrap_err()
                        .to_string()
                        .contains("binding differs"));
                }
                let mut mutant = elf.bytes.clone();
                mutant[elf.symbols + index * SYMBOL_BYTES + 5] =
                    (visibility_bits(visibility) + 1) & 3;
                assert!(object_inventory(&mutant, arch, &module)
                    .unwrap_err()
                    .to_string()
                    .contains("visibility differs"));
            }
            elf.symbol64(1, 16, 0);
            assert!(object_inventory(&elf.bytes, arch, &module).is_err());
            elf.symbol64(1, 16, 8);
            elf.symbol64(2, 16, 4);
            assert!(object_inventory(&elf.bytes, arch, &module).is_err());
        }
    }
}

const TEXT: usize = 1;
const DATA: usize = 2;
const STRINGS: usize = 3;
const SYMBOLS: usize = 4;
const SECTION_COUNT: usize = 5;
const SECTION_BYTES: usize = 64;
const SYMBOL_BYTES: usize = 24;

pub(super) fn module() -> NativeModule {
    let bytes = serde_json::to_vec(&json!({
        "format":"ocore-native-module-v1","name":"object-admission-fixture",
        "target":{"triple":"x86_64-unknown-none","data_layout":"e-p:64:64-i64:64",
                  "pointer_bits":64,"little_endian":true},
        "semantics":"llvm_defined_behavior_v1",
        "types":[{"kind":"void"},{"kind":"int","bits":64}],
        "globals":[{"name":"g","ty":1,"linkage":"external","alignment":8,
                    "constant":false,"thread_local":false,
                    "initializer":{"bytes":[0,0,0,0,0,0,0,0],"relocations":[]}}],
        "functions":[{"name":"f","linkage":"external",
                      "signature":{"params":[],"result":1,"abi":"c","variadic":false},
                      "params":[],"entry":0,"blocks":[{"id":0,"instructions":[],
                        "terminator":{"op":"return","value":{"kind":"int","ty":1,"bits":"0"}}}]}],
        "provenance":{"input_sha256":"0".repeat(64),"frontend":"test","frontend_version":"1",
                      "importer":"test","importer_version":"1","source_function_count":1,
                      "source_global_count":1,"refinements":[]}
    }))
    .unwrap();
    NativeModule::from_json(&bytes).unwrap()
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn aligned_payload(bytes: &mut Vec<u8>, payload: &[u8], alignment: usize) -> usize {
    let padding = (alignment - bytes.len() % alignment) % alignment;
    bytes.resize(bytes.len() + padding, 0);
    let offset = bytes.len();
    bytes.extend_from_slice(payload);
    offset
}

#[derive(Clone)]
struct Elf {
    bytes: Vec<u8>,
    headers: usize,
    strings: usize,
    symbols: usize,
}

impl Elf {
    fn new(machine: u16, data_size: usize, data_alignment: u64) -> Self {
        Self::with_text_size(machine, data_size, data_alignment, 8)
    }

    fn with_text_size(
        machine: u16,
        data_size: usize,
        data_alignment: u64,
        text_size: usize,
    ) -> Self {
        let mut bytes = vec![0; 64];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, 1); // ET_REL.
        put16(&mut bytes, 18, machine);
        put32(&mut bytes, 20, 1); // EV_CURRENT.
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 58, SECTION_BYTES as u16);
        put16(&mut bytes, 60, SECTION_COUNT as u16);

        let text = aligned_payload(&mut bytes, &vec![0xc3; text_size], 4);
        let data = aligned_payload(&mut bytes, &vec![0; data_size], data_alignment as usize);
        let strings = aligned_payload(&mut bytes, b"\0f\0g\0", 1);
        let symbols = aligned_payload(&mut bytes, &[0; 3 * SYMBOL_BYTES], 8);
        let headers = aligned_payload(&mut bytes, &[0; SECTION_COUNT * SECTION_BYTES], 8);
        put64(&mut bytes, 40, headers as u64);
        let mut elf = Self {
            bytes,
            headers,
            strings,
            symbols,
        };
        elf.section(TEXT, 1, 6, text as u64, text_size as u64, 0, 4, 0); // ALLOC | EXECINSTR.
        elf.section(
            DATA,
            1,
            3,
            data as u64,
            data_size as u64,
            0,
            data_alignment,
            0,
        );
        elf.section(STRINGS, 3, 0, strings as u64, 5, 0, 1, 0);
        elf.section(SYMBOLS, 2, 0, symbols as u64, 72, STRINGS as u32, 8, 24);
        elf.section32(SYMBOLS, 44, 1); // Null symbol is the last local symbol.
        elf.symbol32(1, 0, 1); // f.
        elf.symbol8(1, 4, 0x12); // STB_GLOBAL | STT_FUNC.
        elf.symbol16(1, 6, TEXT as u16);
        elf.symbol64(1, 16, 8);
        elf.symbol32(2, 0, 3); // g.
        elf.symbol8(2, 4, 0x11); // STB_GLOBAL | STT_OBJECT.
        elf.symbol16(2, 6, DATA as u16);
        elf.symbol64(2, 16, 8);
        elf
    }

    #[allow(clippy::too_many_arguments)]
    fn section(
        &mut self,
        index: usize,
        kind: u32,
        flags: u64,
        offset: u64,
        size: u64,
        link: u32,
        alignment: u64,
        stride: u64,
    ) {
        self.section32(index, 4, kind);
        self.section64(index, 8, flags);
        self.section64(index, 24, offset);
        self.section64(index, 32, size);
        self.section32(index, 40, link);
        self.section64(index, 48, alignment);
        self.section64(index, 56, stride);
    }

    fn section32(&mut self, index: usize, field: usize, value: u32) {
        put32(
            &mut self.bytes,
            self.headers + index * SECTION_BYTES + field,
            value,
        );
    }

    fn section64(&mut self, index: usize, field: usize, value: u64) {
        put64(
            &mut self.bytes,
            self.headers + index * SECTION_BYTES + field,
            value,
        );
    }

    fn symbol8(&mut self, index: usize, field: usize, value: u8) {
        self.bytes[self.symbols + index * SYMBOL_BYTES + field] = value;
    }

    fn symbol16(&mut self, index: usize, field: usize, value: u16) {
        put16(
            &mut self.bytes,
            self.symbols + index * SYMBOL_BYTES + field,
            value,
        );
    }

    fn symbol32(&mut self, index: usize, field: usize, value: u32) {
        put32(
            &mut self.bytes,
            self.symbols + index * SYMBOL_BYTES + field,
            value,
        );
    }

    fn symbol64(&mut self, index: usize, field: usize, value: u64) {
        put64(
            &mut self.bytes,
            self.symbols + index * SYMBOL_BYTES + field,
            value,
        );
    }

    fn append_undefined(&mut self, name_offset: u32, binding: u8) {
        let mut symbols = self.bytes[self.symbols..self.symbols + 3 * SYMBOL_BYTES].to_vec();
        symbols.extend_from_slice(&[0; SYMBOL_BYTES]);
        self.symbols = aligned_payload(&mut self.bytes, &symbols, 8);
        self.section64(SYMBOLS, 24, self.symbols as u64);
        self.section64(SYMBOLS, 32, symbols.len() as u64);
        self.symbol32(3, 0, name_offset);
        self.symbol8(3, 4, binding << 4); // Undefined assembler reference has STT_NOTYPE.
    }

    fn append_alias(
        &mut self,
        name: &str,
        aliasee_index: usize,
        binding: u8,
        visibility: u8,
    ) -> usize {
        let names_size = u64::from_le_bytes(
            self.bytes[self.headers + STRINGS * SECTION_BYTES + 32..][..8]
                .try_into()
                .unwrap(),
        ) as usize;
        let mut names = self.bytes[self.strings..self.strings + names_size].to_vec();
        let name_offset = names.len() as u32;
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        self.strings = aligned_payload(&mut self.bytes, &names, 1);
        self.section64(STRINGS, 24, self.strings as u64);
        self.section64(STRINGS, 32, names.len() as u64);
        let symbols_size = u64::from_le_bytes(
            self.bytes[self.headers + SYMBOLS * SECTION_BYTES + 32..][..8]
                .try_into()
                .unwrap(),
        ) as usize;
        let mut symbols = self.bytes[self.symbols..self.symbols + symbols_size].to_vec();
        let mut alias =
            symbols[aliasee_index * SYMBOL_BYTES..(aliasee_index + 1) * SYMBOL_BYTES].to_vec();
        put32(&mut alias, 0, name_offset);
        alias[4] = (binding << 4) | (alias[4] & 15);
        alias[5] = visibility;
        let index = symbols.len() / SYMBOL_BYTES;
        symbols.extend_from_slice(&alias);
        self.symbols = aligned_payload(&mut self.bytes, &symbols, 8);
        self.section64(SYMBOLS, 24, self.symbols as u64);
        self.section64(SYMBOLS, 32, symbols.len() as u64);
        index
    }

    fn section_value(&self, index: usize, field: usize) -> u64 {
        u64::from_le_bytes(
            self.bytes[self.headers + index * SECTION_BYTES + field..][..8]
                .try_into()
                .unwrap(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_section(
        &mut self,
        kind: u32,
        flags: u64,
        payload: &[u8],
        link: u32,
        info: u32,
        alignment: u64,
        stride: u64,
    ) -> usize {
        let count = u16::from_le_bytes(self.bytes[60..62].try_into().unwrap()) as usize;
        let mut headers = self.bytes[self.headers..self.headers + count * SECTION_BYTES].to_vec();
        headers.extend_from_slice(&[0; SECTION_BYTES]);
        let offset = aligned_payload(&mut self.bytes, payload, alignment.max(1) as usize);
        self.headers = aligned_payload(&mut self.bytes, &headers, 8);
        put64(&mut self.bytes, 40, self.headers as u64);
        put16(&mut self.bytes, 60, (count + 1) as u16);
        self.section(
            count,
            kind,
            flags,
            offset as u64,
            payload.len() as u64,
            link,
            alignment,
            stride,
        );
        self.section32(count, 44, info);
        count
    }

    fn replace_section_payload(&mut self, section: usize, payload: &[u8], alignment: usize) {
        let offset = aligned_payload(&mut self.bytes, payload, alignment);
        self.section64(section, 24, offset as u64);
        self.section64(section, 32, payload.len() as u64);
    }

    fn append_section_symbol(&mut self, section: usize) -> usize {
        let size = self.section_value(SYMBOLS, 32) as usize;
        let mut symbols = self.bytes[self.symbols..self.symbols + size].to_vec();
        let index = symbols.len() / SYMBOL_BYTES;
        let mut symbol = [0; SYMBOL_BYTES];
        symbol[4] = 3; // STB_LOCAL | STT_SECTION, unnamed, zero section base.
        put16(&mut symbol, 6, section as u16);
        symbols.extend_from_slice(&symbol);
        self.symbols = aligned_payload(&mut self.bytes, &symbols, 8);
        self.section64(SYMBOLS, 24, self.symbols as u64);
        self.section64(SYMBOLS, 32, symbols.len() as u64);
        index
    }
}

fn absolute_relocation_type(machine: u16) -> u32 {
    match machine {
        62 => 1,
        183 => 257,
        243 => 2,
        _ => panic!("unsupported fixture machine"),
    }
}

fn relocation_entry(offset: u64, symbol: usize, kind: u32, addend: i64) -> Vec<u8> {
    let mut entry = vec![0; 24];
    put64(&mut entry, 0, offset);
    put64(&mut entry, 8, ((symbol as u64) << 32) | kind as u64);
    put64(&mut entry, 16, addend as u64);
    entry
}

struct InitializerFixture {
    elf: Elf,
    module: NativeModule,
    rela: usize,
}

impl InitializerFixture {
    fn new(machine: u16, arch: &str) -> Self {
        let mut module = module();
        module.target.triple = format!("{arch}-unknown-none");
        module.types.push(Type::Int { bits: 8 });
        module.types.push(Type::Array {
            element: 2,
            len: 32,
        });
        module.globals[0].ty = 3;
        let initializer = module.globals[0].initializer.as_mut().unwrap();
        initializer.bytes = (0..32).map(|n| (n * 7 + 3) as u8).collect();
        initializer.relocations = vec![Relocation {
            offset: 8,
            width: 64,
            symbol: "f".into(),
            addend: -9,
            relative_to: None,
        }];
        let module = NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
        let mut elf = Elf::with_text_size(machine, 48, 8, 32);
        elf.symbol64(1, 8, 8);
        elf.symbol64(2, 8, 8);
        elf.symbol64(2, 16, 32);
        let data = elf.section_value(DATA, 24) as usize;
        elf.bytes[data + 8..data + 40]
            .copy_from_slice(&module.globals[0].initializer.as_ref().unwrap().bytes);
        let rela = elf.append_section(
            4,
            0,
            &relocation_entry(16, 1, absolute_relocation_type(machine), -9),
            SYMBOLS as u32,
            DATA as u32,
            8,
            24,
        );
        Self { elf, module, rela }
    }

    fn set_entry(&mut self, offset: u64, symbol: usize, kind: u32, addend: i64) {
        self.elf.replace_section_payload(
            self.rela,
            &relocation_entry(offset, symbol, kind, addend),
            8,
        );
    }

    fn reverify(&mut self) {
        self.module = NativeModule::from_json(&serde_json::to_vec(&self.module).unwrap()).unwrap();
    }
}

fn relative_initializer_fixture(machine: u16, arch: &str, resolved: bool) -> InitializerFixture {
    let mut fixture = InitializerFixture::new(machine, arch);
    fixture.module.globals[0].linkage = "private".into();
    fixture.elf.symbol8(2, 4, 0x01);
    let relocation = &mut fixture.module.globals[0]
        .initializer
        .as_mut()
        .unwrap()
        .relocations[0];
    relocation.width = 32;
    relocation.relative_to = Some("g".into());
    if resolved {
        relocation.symbol = "g".into();
    }
    let data = fixture.elf.section_value(DATA, 24) as usize;
    fixture.elf.bytes[data + 16..data + 20].copy_from_slice(&if resolved {
        (-9i32).to_le_bytes()
    } else {
        [0; 4]
    });
    let entries = if resolved {
        vec![]
    } else if machine == 243 {
        [
            relocation_entry(16, 1, 35, -9),
            relocation_entry(16, 2, 39, 0),
        ]
        .concat()
    } else {
        relocation_entry(16, 1, if machine == 62 { 2 } else { 261 }, -1)
    };
    fixture
        .elf
        .replace_section_payload(fixture.rela, &entries, 8);
    fixture.reverify();
    fixture
}

#[test]
fn relative_initializer_exact_pcrel_or_rv_pair_preserves_source_base_and_addend() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let fixture = relative_initializer_fixture(machine, arch, false);
        let inventory = object_inventory(&fixture.elf.bytes, arch, &fixture.module).unwrap();
        assert_eq!(
            inventory["initializer_checks"]["relative32_initializers"],
            1
        );
        assert_eq!(
            inventory["initializer_checks"]["resolved_relative32_initializers"],
            0
        );
        assert_eq!(
            inventory["initializer_checks"]["relocation_records"],
            if machine == 243 { 2 } else { 1 }
        );
        for (kind, addend, target) in [
            (absolute_relocation_type(machine), -1, 1),
            (
                if machine == 62 {
                    2
                } else if machine == 183 {
                    261
                } else {
                    35
                },
                0,
                1,
            ),
            (
                if machine == 62 {
                    2
                } else if machine == 183 {
                    261
                } else {
                    35
                },
                -1,
                2,
            ),
        ] {
            let mut mutant = fixture.elf.clone();
            mutant.replace_section_payload(
                fixture.rela,
                &relocation_entry(16, target, kind, addend),
                8,
            );
            assert!(object_inventory(&mutant.bytes, arch, &fixture.module).is_err());
        }
        if machine == 243 {
            for entries in [
                relocation_entry(16, 1, 35, -9),
                [
                    relocation_entry(16, 1, 35, -9),
                    relocation_entry(16, 1, 39, 0),
                ]
                .concat(),
                [
                    relocation_entry(16, 1, 35, -9),
                    relocation_entry(16, 2, 39, 1),
                ]
                .concat(),
                [
                    relocation_entry(16, 1, 35, -9),
                    relocation_entry(16, 2, 39, 0),
                    relocation_entry(16, 2, 39, 0),
                ]
                .concat(),
            ] {
                let mut mutant = fixture.elf.clone();
                mutant.replace_section_payload(fixture.rela, &entries, 8);
                assert!(object_inventory(&mutant.bytes, arch, &fixture.module).is_err());
            }
            let mut mutant = fixture.elf.clone();
            let data = mutant.section_value(DATA, 24) as usize;
            mutant.bytes[data + 16] = 1;
            assert!(object_inventory(&mutant.bytes, arch, &fixture.module)
                .unwrap_err()
                .to_string()
                .contains("accumulator is nonzero"));
        }
        let references = symbols("source", &fixture.module).unwrap();
        let global = references.iter().find(|symbol| symbol.name == "g").unwrap();
        assert_eq!(
            global.references,
            ["f".into(), "g".into()].into_iter().collect()
        );
    }
}

#[test]
fn same_section_relative_initializer_requires_exact_resolved_bits_and_no_fixup() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let fixture = relative_initializer_fixture(machine, arch, true);
        let inventory = object_inventory(&fixture.elf.bytes, arch, &fixture.module).unwrap();
        assert_eq!(
            inventory["initializer_checks"]["resolved_relative32_initializers"],
            1
        );
        assert_eq!(inventory["initializer_checks"]["relocation_records"], 0);
        let mut mutant = fixture.elf.clone();
        let data = mutant.section_value(DATA, 24) as usize;
        mutant.bytes[data + 16] ^= 1;
        assert!(object_inventory(&mutant.bytes, arch, &fixture.module)
            .unwrap_err()
            .to_string()
            .contains("resolved relative initializer"));
        let mut mutant = fixture.elf.clone();
        mutant.replace_section_payload(
            fixture.rela,
            &relocation_entry(16, 2, absolute_relocation_type(machine), -9),
            8,
        );
        assert!(object_inventory(&mutant.bytes, arch, &fixture.module)
            .unwrap_err()
            .to_string()
            .contains("extra or misplaced"));
    }
}

#[test]
fn exact_initializer_bytes_and_abs64_rela_contract_are_checked_on_all_three_isas() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let fixture = InitializerFixture::new(machine, arch);
        let inventory = object_inventory(&fixture.elf.bytes, arch, &fixture.module).unwrap();
        assert_eq!(inventory["initializer_checks"]["globals"], 1);
        assert_eq!(inventory["initializer_checks"]["bytes"], 32);
        assert_eq!(inventory["initializer_checks"]["absolute_relocations"], 1);
        assert_eq!(inventory["code_and_cfi_relocations"], "structural_only");
        let data = fixture.elf.section_value(DATA, 24) as usize + 8;
        for offset in [0, 7, 16, 31] {
            let mut mutant = fixture.elf.clone();
            mutant.bytes[data + offset] ^= 1;
            group_rejected(&mutant, arch, &fixture.module, "initializer bytes differ");
        }
        // A RELA ABS64 overwrites all eight pointer bytes; their pre-link
        // contents cannot affect the initializer's relocated value.
        let mut overwritten = fixture.elf.clone();
        overwritten.bytes[data + 8..data + 16].fill(0xff);
        assert!(object_inventory(&overwritten.bytes, arch, &fixture.module).is_ok());
        let mut literal = fixture.module.clone();
        literal.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .relocations
            .clear();
        let mut literal_elf = fixture.elf.clone();
        literal_elf.replace_section_payload(fixture.rela, &[], 8);
        assert!(object_inventory(&literal_elf.bytes, arch, &literal).is_ok());
        literal_elf.bytes[data + 9] ^= 1;
        group_rejected(&literal_elf, arch, &literal, "initializer bytes differ");
    }
}

#[test]
fn initializer_relocations_cannot_be_missing_extra_duplicated_or_misplaced() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let fixture = InitializerFixture::new(machine, arch);
        let mut missing = fixture.elf.clone();
        missing.replace_section_payload(fixture.rela, &[], 8);
        group_rejected(
            &missing,
            arch,
            &fixture.module,
            "omitted verified initializer relocation",
        );
        let entry = relocation_entry(16, 1, absolute_relocation_type(machine), -9);
        let mut duplicate = fixture.elf.clone();
        duplicate.replace_section_payload(
            fixture.rela,
            &[entry.clone(), entry.clone()].concat(),
            8,
        );
        group_rejected(
            &duplicate,
            arch,
            &fixture.module,
            "duplicate ELF initializer relocation",
        );
        let mut duplicate = fixture.elf.clone();
        duplicate.append_section(4, 0, &entry, SYMBOLS as u32, DATA as u32, 8, 24);
        group_rejected(
            &duplicate,
            arch,
            &fixture.module,
            "duplicate ELF initializer relocation",
        );
        for offset in [0, 8, 17, 24, 40, 47] {
            let mut extra = fixture.elf.clone();
            let extra_entry = relocation_entry(offset, 1, absolute_relocation_type(machine), -9);
            extra.replace_section_payload(fixture.rela, &[entry.clone(), extra_entry].concat(), 8);
            group_rejected(&extra, arch, &fixture.module, "extra or misplaced");
        }
        let mut wrong_target = fixture.elf.clone();
        wrong_target.section32(fixture.rela, 44, TEXT as u32);
        group_rejected(
            &wrong_target,
            arch,
            &fixture.module,
            "omitted verified initializer relocation",
        );
    }
}

#[test]
fn initializer_relocations_require_exact_type_symbol_addend_and_explicit_rela() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        for kind in [0, 3, 258, u32::MAX] {
            let mut fixture = InitializerFixture::new(machine, arch);
            fixture.set_entry(16, 1, kind, -9);
            group_rejected(
                &fixture.elf,
                arch,
                &fixture.module,
                "relocation type differs",
            );
        }
        for addend in [0, -8, -10, i64::MIN, i64::MAX] {
            let mut fixture = InitializerFixture::new(machine, arch);
            fixture.set_entry(16, 1, absolute_relocation_type(machine), addend);
            group_rejected(&fixture.elf, arch, &fixture.module, "symbol/addend differs");
        }
        let mut wrong_symbol = InitializerFixture::new(machine, arch);
        wrong_symbol.set_entry(16, 2, absolute_relocation_type(machine), -9);
        group_rejected(
            &wrong_symbol.elf,
            arch,
            &wrong_symbol.module,
            "symbol/addend differs",
        );
        let mut implicit = InitializerFixture::new(machine, arch);
        let entry = relocation_entry(16, 1, absolute_relocation_type(machine), -9);
        implicit.elf.section32(implicit.rela, 4, 9);
        implicit.elf.section64(implicit.rela, 56, 16);
        implicit
            .elf
            .replace_section_payload(implicit.rela, &entry[..16], 8);
        group_rejected(
            &implicit.elf,
            arch,
            &implicit.module,
            "explicit-addend RELA",
        );
    }
}

#[test]
fn local_initializer_targets_accept_section_folding_with_exact_offset_and_modular_addend() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        for (target, section, definition, linkage) in
            [("f", TEXT, 1, "internal"), ("g", DATA, 2, "private")]
        {
            let mut fixture = InitializerFixture::new(machine, arch);
            if target == "f" {
                fixture.module.functions[0].linkage = linkage.into();
            } else {
                fixture.module.globals[0].linkage = linkage.into();
            }
            fixture.module.globals[0]
                .initializer
                .as_mut()
                .unwrap()
                .relocations[0]
                .symbol = target.into();
            fixture
                .elf
                .symbol8(definition, 4, if target == "f" { 2 } else { 1 });
            fixture.reverify();
            let section_symbol = fixture.elf.append_section_symbol(section);
            for addend in [-9, 0, 17, i64::MAX, i64::MIN] {
                fixture.module.globals[0]
                    .initializer
                    .as_mut()
                    .unwrap()
                    .relocations[0]
                    .addend = addend;
                fixture.set_entry(
                    16,
                    section_symbol,
                    absolute_relocation_type(machine),
                    8u64.wrapping_add(addend as u64) as i64,
                );
                assert!(object_inventory(&fixture.elf.bytes, arch, &fixture.module).is_ok());
            }
            fixture.set_entry(
                16,
                section_symbol,
                absolute_relocation_type(machine),
                i64::MIN,
            );
            group_rejected(&fixture.elf, arch, &fixture.module, "symbol/addend differs");
            fixture.set_entry(
                16,
                section_symbol,
                absolute_relocation_type(machine),
                8u64.wrapping_add(i64::MIN as u64) as i64,
            );
            for (field, value) in [(8, 1), (16, 8)] {
                let mut malformed = fixture.elf.clone();
                malformed.symbol64(section_symbol, field, value);
                group_rejected(&malformed, arch, &fixture.module, "symbol/addend differs");
            }
            let mut malformed = fixture.elf.clone();
            malformed.symbol16(
                section_symbol,
                6,
                if section == TEXT { DATA } else { TEXT } as u16,
            );
            group_rejected(&malformed, arch, &fixture.module, "symbol/addend differs");
        }
    }
}

#[test]
fn exported_and_weak_alias_initializer_identity_cannot_be_folded_to_equal_address_roots() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        for (linkage, binding) in [("external", 1), ("weak", 2)] {
            let mut fixture = InitializerFixture::new(machine, arch);
            fixture.module.functions[0].linkage = "internal".into();
            fixture.elf.symbol8(1, 4, 2);
            fixture.module.types.push(Type::Function {
                signature: fixture.module.functions[0].signature.clone(),
            });
            fixture.module.aliases.push(Alias {
                name: "alias".into(),
                ty: 4,
                aliasee: "f".into(),
                linkage: linkage.into(),
                visibility: Visibility::Default,
            });
            fixture.module.provenance.source_alias_count = 1;
            fixture.module.globals[0]
                .initializer
                .as_mut()
                .unwrap()
                .relocations[0]
                .symbol = "alias".into();
            fixture.reverify();
            let alias = fixture.elf.append_alias("alias", 1, binding, 0);
            fixture.set_entry(16, alias, absolute_relocation_type(machine), -9);
            assert!(object_inventory(&fixture.elf.bytes, arch, &fixture.module).is_ok());
            fixture.set_entry(16, 1, absolute_relocation_type(machine), -9);
            group_rejected(&fixture.elf, arch, &fixture.module, "symbol/addend differs");
            let section_symbol = fixture.elf.append_section_symbol(TEXT);
            fixture.set_entry(16, section_symbol, absolute_relocation_type(machine), -1);
            group_rejected(&fixture.elf, arch, &fixture.module, "symbol/addend differs");
        }
    }
}

#[test]
fn same_name_untyped_local_symbol_cannot_spoof_a_relocation_target() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut fixture = InitializerFixture::new(machine, arch);
        let spoof = fixture.elf.append_alias("f", 1, 0, 0);
        fixture.elf.symbol8(spoof, 4, 0); // A marker, ignored by typed-definition inventory.
        fixture.elf.symbol64(spoof, 8, 24);
        fixture.set_entry(16, spoof, absolute_relocation_type(machine), -9);
        group_rejected(&fixture.elf, arch, &fixture.module, "symbol/addend differs");
    }
}

#[test]
fn local_alias_folding_and_declared_external_initializer_references_preserve_contracts() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut local = InitializerFixture::new(machine, arch);
        local.module.types.push(Type::Function {
            signature: local.module.functions[0].signature.clone(),
        });
        local.module.aliases.push(Alias {
            name: "local_alias".into(),
            ty: 4,
            aliasee: "f".into(),
            linkage: "private".into(),
            visibility: Visibility::Default,
        });
        local.module.provenance.source_alias_count = 1;
        local.module.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .relocations[0]
            .symbol = "local_alias".into();
        local.reverify();
        let alias = local.elf.append_alias("local_alias", 1, 0, 0);
        local.set_entry(16, alias, absolute_relocation_type(machine), -9);
        assert!(object_inventory(&local.elf.bytes, arch, &local.module).is_ok());
        let section = local.elf.append_section_symbol(TEXT);
        local.set_entry(16, section, absolute_relocation_type(machine), -1);
        assert!(object_inventory(&local.elf.bytes, arch, &local.module).is_ok());

        let mut external = InitializerFixture::new(machine, arch);
        external.module.functions[0].entry = None;
        external.module.functions[0].blocks.clear();
        external.reverify();
        external.elf.symbol8(1, 4, 0x10); // Declared, GLOBAL/NOTYPE undefined reference.
        external.elf.symbol16(1, 6, 0);
        external.elf.symbol64(1, 8, 0);
        external.elf.symbol64(1, 16, 0);
        let inventory = object_inventory(&external.elf.bytes, arch, &external.module).unwrap();
        assert_eq!(inventory["undefined_symbols"], json!(["f"]));
    }
}

#[test]
fn zero_sized_global_initializers_may_coincide_without_fabricated_overlap() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut module = module();
        module.types.push(Type::Int { bits: 8 });
        module.types.push(Type::Array { element: 2, len: 0 });
        module.globals[0].ty = 3;
        module.globals[0].alignment = 1;
        module.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .bytes
            .clear();
        let mut second = module.globals[0].clone();
        second.name = "h".into();
        module.globals.push(second);
        module.provenance.source_global_count = 2;
        let module = NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
        let mut elf = Elf::new(machine, 0, 1);
        elf.symbol64(2, 16, 0);
        elf.append_alias("h", 2, 1, 0);
        let inventory = object_inventory(&elf.bytes, arch, &module).unwrap();
        assert_eq!(inventory["initializer_checks"]["globals"], 2);
        assert_eq!(inventory["initializer_checks"]["bytes"], 0);
    }
}

#[test]
fn independent_source_globals_cannot_share_initializer_storage_without_declared_aliases() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut module = module();
        let mut second = module.globals[0].clone();
        second.name = "h".into();
        module.globals.push(second);
        module.provenance.source_global_count = 2;
        let module = NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
        let mut elf = Elf::new(machine, 8, 8);
        elf.append_alias("h", 2, 1, 0);
        group_rejected(&elf, arch, &module, "initializers overlap without an alias");
    }
}

const SHF_GROUP: u64 = 0x200;

fn group_payload(flag: u32, sections: &[usize]) -> Vec<u8> {
    std::iter::once(flag)
        .chain(sections.iter().map(|index| *index as u32))
        .flat_map(u32::to_le_bytes)
        .collect()
}

struct GroupFixture {
    elf: Elf,
    module: NativeModule,
    group: usize,
    function_alias: usize,
    global_alias: usize,
}

impl GroupFixture {
    fn new(machine: u16, arch: &str, selection: ComdatSelection) -> Self {
        let mut module = module();
        module.target.triple = format!("{arch}-unknown-none");
        module.functions[0].linkage = "linkonce_odr".into();
        module.functions[0].comdat = Some("f".into());
        module.globals[0].linkage = "weak_odr".into();
        module.globals[0].visibility = Visibility::Protected;
        module.globals[0].comdat = Some("f".into());
        module.comdats = vec![Comdat {
            name: "f".into(),
            selection,
        }];
        module.provenance.referenced_comdat_count = 1;
        module.types.push(Type::Function {
            signature: module.functions[0].signature.clone(),
        });
        module.aliases = vec![
            Alias {
                name: "function_alias".into(),
                ty: 2,
                aliasee: "f".into(),
                linkage: "external".into(),
                visibility: Visibility::Hidden,
            },
            Alias {
                name: "global_alias".into(),
                ty: 1,
                aliasee: "g".into(),
                linkage: "weak".into(),
                visibility: Visibility::Default,
            },
        ];
        module.provenance.source_alias_count = 2;
        let module = NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
        let mut elf = Elf::new(machine, 8, 8);
        elf.symbol8(1, 4, 0x22);
        elf.symbol8(2, 4, 0x21);
        elf.symbol8(2, 5, 3);
        let function_alias = elf.append_alias("function_alias", 1, 1, 2);
        let global_alias = elf.append_alias("global_alias", 2, 2, 0);
        elf.section64(TEXT, 8, 6 | SHF_GROUP);
        elf.section64(DATA, 8, 3 | SHF_GROUP);
        let flag = if selection == ComdatSelection::Any {
            1
        } else {
            0
        };
        let group = elf.append_section(
            17,
            0,
            &group_payload(flag, &[TEXT, DATA]),
            SYMBOLS as u32,
            1,
            4,
            4,
        );
        Self {
            elf,
            module,
            group,
            function_alias,
            global_alias,
        }
    }

    fn add_relocation(&mut self, machine: u16) -> usize {
        // The source initializer really contains this pointer-sized relocation;
        // the fixture is not inventing an unrelated grouped RELA section.
        self.module.globals[0]
            .initializer
            .as_mut()
            .unwrap()
            .relocations = vec![Relocation {
            offset: 0,
            width: 64,
            symbol: "f".into(),
            addend: 0,
            relative_to: None,
        }];
        self.module = NativeModule::from_json(&serde_json::to_vec(&self.module).unwrap()).unwrap();
        let kind = match machine {
            62 => 1,
            183 => 257,
            243 => 2,
            _ => unreachable!(),
        };
        let mut rela = vec![0; 24];
        put64(&mut rela, 8, (1_u64 << 32) | kind);
        let section =
            self.elf
                .append_section(4, SHF_GROUP, &rela, SYMBOLS as u32, DATA as u32, 8, 24);
        self.set_members(&[TEXT, DATA, section]);
        section
    }

    fn set_members(&mut self, members: &[usize]) {
        let flag = if self.module.comdats[0].selection == ComdatSelection::Any {
            1
        } else {
            0
        };
        self.elf
            .replace_section_payload(self.group, &group_payload(flag, members), 4);
    }
}

fn group_rejected(elf: &Elf, arch: &str, module: &NativeModule, reason: &str) {
    let outcome = std::panic::catch_unwind(|| object_inventory(&elf.bytes, arch, module));
    assert!(
        outcome.is_ok(),
        "ELF admission panicked for {arch}: {reason}"
    );
    let error = outcome
        .unwrap()
        .expect_err("hostile ELF group was admitted");
    assert!(
        error.to_string().contains(reason),
        "wrong {arch} rejection: expected {reason:?}, got {error}"
    );
}

#[test]
fn comdat_inventory_maps_mixed_code_data_and_aliases_on_all_three_isas() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        for selection in [ComdatSelection::Any, ComdatSelection::NoDeduplicate] {
            let fixture = GroupFixture::new(machine, arch, selection);
            let inventory = object_inventory(&fixture.elf.bytes, arch, &fixture.module).unwrap();
            assert_eq!(inventory["definitions"].as_array().unwrap().len(), 4);
            assert_eq!(inventory["section_groups"][0]["name"], "f");
            assert_eq!(
                inventory["section_groups"][0]["flags"],
                if selection == ComdatSelection::Any {
                    1
                } else {
                    0
                }
            );
            assert_eq!(
                inventory["section_groups"][0]["members"],
                json!([TEXT, DATA])
            );
            for definition in inventory["definitions"].as_array().unwrap() {
                assert_eq!(definition["comdat"], "f");
            }
            // Alias symbols are distinct, yet refer to exactly the same root
            // sections, positions and extents; their bindings remain separate.
            assert_ne!(fixture.function_alias, 1);
            assert_ne!(fixture.global_alias, 2);
            assert_eq!(inventory["definitions"][1]["name"], "function_alias");
            assert_eq!(inventory["definitions"][1]["binding"], 1);
            assert_eq!(inventory["definitions"][1]["visibility"], 2);
            assert_eq!(inventory["definitions"][2]["binding"], 2);
            assert_eq!(inventory["definitions"][2]["visibility"], 3);
        }
    }
}

#[test]
fn comdat_missing_extra_duplicate_and_multiply_owned_groups_fail_closed() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let fixture = GroupFixture::new(machine, arch, ComdatSelection::Any);
        let mut mutant = fixture.elf.clone();
        mutant.section32(fixture.group, 4, 1);
        mutant.section64(TEXT, 8, 6);
        mutant.section64(DATA, 8, 3);
        group_rejected(&mutant, arch, &fixture.module, "definition group differs");
        let mut mutant = fixture.elf.clone();
        mutant.section32(fixture.group, 44, 2); // g is not the declared group signature.
        group_rejected(&mutant, arch, &fixture.module, "undeclared section group g");
        let mut mutant = fixture.elf.clone();
        mutant.append_section(17, 0, &group_payload(1, &[TEXT]), SYMBOLS as u32, 2, 4, 4);
        group_rejected(&mutant, arch, &fixture.module, "undeclared section group g");
        let mut mutant = fixture.elf.clone();
        mutant.section64(STRINGS, 8, SHF_GROUP);
        mutant.append_section(
            17,
            0,
            &group_payload(1, &[STRINGS]),
            SYMBOLS as u32,
            1,
            4,
            4,
        );
        group_rejected(
            &mutant,
            arch,
            &fixture.module,
            "duplicate ELF group signature",
        );
        let mut mutant = fixture.elf.clone();
        mutant.replace_section_payload(fixture.group, &group_payload(1, &[TEXT, DATA, TEXT]), 4);
        group_rejected(
            &mutant,
            arch,
            &fixture.module,
            "invalid or multiply owned ELF group member",
        );
        let mut source = fixture.module.clone();
        source.comdats.push(Comdat {
            name: "g".into(),
            selection: ComdatSelection::Any,
        });
        source.provenance.referenced_comdat_count = 2;
        source.globals[0].comdat = Some("g".into());
        let source = NativeModule::from_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        let mut mutant = fixture.elf.clone();
        mutant.append_section(17, 0, &group_payload(1, &[DATA]), SYMBOLS as u32, 2, 4, 4);
        group_rejected(
            &mutant,
            arch,
            &source,
            "invalid or multiply owned ELF group member",
        );
    }
}

#[test]
fn comdat_flags_selection_and_primary_member_inventory_match_the_source() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        for selection in [ComdatSelection::Any, ComdatSelection::NoDeduplicate] {
            let fixture = GroupFixture::new(machine, arch, selection);
            let expected = if selection == ComdatSelection::Any {
                1
            } else {
                0
            };
            for flag in [0, 1, 2, 3, u32::MAX] {
                let mut mutant = fixture.elf.clone();
                put32(
                    &mut mutant.bytes,
                    fixture.elf.section_value(fixture.group, 24) as usize,
                    flag,
                );
                if flag == expected {
                    assert!(object_inventory(&mutant.bytes, arch, &fixture.module).is_ok());
                } else {
                    group_rejected(&mutant, arch, &fixture.module, "group selection differs");
                }
            }
            for section in [TEXT, DATA] {
                let mut mutant = fixture.elf.clone();
                mutant.section64(section, 8, if section == TEXT { 6 } else { 3 });
                group_rejected(
                    &mutant,
                    arch,
                    &fixture.module,
                    "invalid or multiply owned ELF group member",
                );
            }
            let mut mutant = fixture.elf.clone();
            mutant.section64(STRINGS, 8, SHF_GROUP);
            group_rejected(
                &mutant,
                arch,
                &fixture.module,
                "group flag and member inventory disagree",
            );
            mutant.replace_section_payload(
                fixture.group,
                &group_payload(expected, &[TEXT, DATA, STRINGS]),
                4,
            );
            group_rejected(&mutant, arch, &fixture.module, "whole-group members differ");
            let mut source = fixture.module.clone();
            source.globals[0].comdat = None;
            let source = NativeModule::from_json(&serde_json::to_vec(&source).unwrap()).unwrap();
            group_rejected(&fixture.elf, arch, &source, "definition group differs");
        }
    }
}

#[test]
fn comdat_source_members_cannot_be_reshuffled_between_intact_groups() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut fixture = GroupFixture::new(machine, arch, ComdatSelection::Any);
        fixture.module.comdats.push(Comdat {
            name: "g".into(),
            selection: ComdatSelection::Any,
        });
        fixture.module.provenance.referenced_comdat_count = 2;
        fixture.module.globals[0].comdat = Some("g".into());
        fixture.set_members(&[TEXT]);
        fixture
            .elf
            .append_section(17, 0, &group_payload(1, &[DATA]), SYMBOLS as u32, 2, 4, 4);
        fixture.module =
            NativeModule::from_json(&serde_json::to_vec(&fixture.module).unwrap()).unwrap();
        assert!(object_inventory(&fixture.elf.bytes, arch, &fixture.module).is_ok());
        let mut source = fixture.module.clone();
        source.functions[0].comdat = Some("g".into());
        source.globals[0].comdat = Some("f".into());
        let source = NativeModule::from_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        group_rejected(&fixture.elf, arch, &source, "definition group differs");
    }
}

#[test]
fn comdat_signature_link_and_symbol_index_must_resolve_exactly() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let fixture = GroupFixture::new(machine, arch, ComdatSelection::Any);
        for link in [0, TEXT as u32, STRINGS as u32, u32::MAX] {
            let mut mutant = fixture.elf.clone();
            mutant.section32(fixture.group, 40, link);
            group_rejected(
                &mutant,
                arch,
                &fixture.module,
                "group signature does not resolve",
            );
        }
        for info in [5, u32::MAX] {
            let mut mutant = fixture.elf.clone();
            mutant.section32(fixture.group, 44, info);
            group_rejected(
                &mutant,
                arch,
                &fixture.module,
                "group signature does not resolve",
            );
        }
        for info in [
            0,
            2,
            fixture.function_alias as u32,
            fixture.global_alias as u32,
        ] {
            let mut mutant = fixture.elf.clone();
            mutant.section32(fixture.group, 44, info);
            group_rejected(&mutant, arch, &fixture.module, "undeclared section group");
        }
    }
}

#[test]
fn comdat_payload_geometry_member_indices_and_every_prefix_are_checked() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let fixture = GroupFixture::new(machine, arch, ComdatSelection::Any);
        for (field, value) in [
            (56, 0),
            (56, 8),
            (32, 0),
            (32, 4),
            (32, 9),
            (48, 1),
            (48, 8),
            (8, SHF_GROUP),
        ] {
            let mut mutant = fixture.elf.clone();
            mutant.section64(fixture.group, field, value);
            group_rejected(
                &mutant,
                arch,
                &fixture.module,
                "invalid ELF section group geometry",
            );
        }
        for (offset, size) in [
            (u64::MAX, 12),
            (0, u64::MAX),
            (fixture.elf.bytes.len() as u64, 12),
        ] {
            let mut mutant = fixture.elf.clone();
            mutant.section64(fixture.group, 24, offset);
            mutant.section64(fixture.group, 32, size);
            let outcome =
                std::panic::catch_unwind(|| object_inventory(&mutant.bytes, arch, &fixture.module));
            assert!(outcome.is_ok());
            assert!(outcome.unwrap().is_err());
        }
        for member in [0, fixture.group, usize::from(u16::MAX)] {
            let mut mutant = fixture.elf.clone();
            mutant.replace_section_payload(
                fixture.group,
                &group_payload(1, &[TEXT, DATA, member]),
                4,
            );
            let outcome =
                std::panic::catch_unwind(|| object_inventory(&mutant.bytes, arch, &fixture.module));
            assert!(outcome.is_ok());
            assert!(outcome.unwrap().is_err());
        }
        for length in 0..fixture.elf.bytes.len() {
            let outcome = std::panic::catch_unwind(|| {
                object_inventory(&fixture.elf.bytes[..length], arch, &fixture.module)
            });
            assert!(
                outcome.is_ok(),
                "group parser panicked for {arch} prefix {length}"
            );
            assert!(
                outcome.unwrap().is_err(),
                "truncated group object admitted for {arch} prefix {length}"
            );
        }
    }
}

#[test]
fn comdat_relocations_share_their_real_target_group_and_cannot_escape_membership() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        for selection in [ComdatSelection::Any, ComdatSelection::NoDeduplicate] {
            let mut fixture = GroupFixture::new(machine, arch, selection);
            let rela = fixture.add_relocation(machine);
            let inventory = object_inventory(&fixture.elf.bytes, arch, &fixture.module).unwrap();
            assert_eq!(
                inventory["section_groups"][0]["members"],
                json!([TEXT, DATA, rela])
            );
            let mut missing = fixture.elf.clone();
            let flag = if selection == ComdatSelection::Any {
                1
            } else {
                0
            };
            missing.replace_section_payload(fixture.group, &group_payload(flag, &[TEXT, DATA]), 4);
            group_rejected(
                &missing,
                arch,
                &fixture.module,
                "group flag and member inventory disagree",
            );
            missing.section64(rela, 8, 0);
            group_rejected(
                &missing,
                arch,
                &fixture.module,
                "relocation section does not share its target's group",
            );
            let mut mutant = fixture.elf.clone();
            let extra = mutant.append_section(1, 2, &[0; 8], 0, 0, 8, 0);
            mutant.section32(rela, 44, extra as u32);
            group_rejected(
                &mutant,
                arch,
                &fixture.module,
                "relocation section does not share its target's group",
            );
            let mut split = fixture.module.clone();
            split.comdats.push(Comdat {
                name: "g".into(),
                selection,
            });
            split.provenance.referenced_comdat_count = 2;
            split.globals[0].comdat = Some("g".into());
            let split = NativeModule::from_json(&serde_json::to_vec(&split).unwrap()).unwrap();
            let mut mutant = fixture.elf.clone();
            mutant.replace_section_payload(fixture.group, &group_payload(flag, &[TEXT, rela]), 4);
            mutant.append_section(
                17,
                0,
                &group_payload(flag, &[DATA]),
                SYMBOLS as u32,
                2,
                4,
                4,
            );
            group_rejected(
                &mutant,
                arch,
                &split,
                "relocation section does not share its target's group",
            );
        }
    }
}

#[test]
fn grouped_relocation_geometry_links_targets_symbols_and_extents_are_validated() {
    for (machine, arch) in [(62, "x86_64"), (183, "aarch64"), (243, "riscv64")] {
        let mut fixture = GroupFixture::new(machine, arch, ComdatSelection::Any);
        let rela = fixture.add_relocation(machine);
        for (field, value) in [(56, 0), (56, 16), (32, 23), (32, 25), (48, 4)] {
            let mut mutant = fixture.elf.clone();
            mutant.section64(rela, field, value);
            group_rejected(&mutant, arch, &fixture.module, "relocation");
        }
        for link in [0, DATA as u32, STRINGS as u32, u32::MAX] {
            let mut mutant = fixture.elf.clone();
            mutant.section32(rela, 40, link);
            group_rejected(&mutant, arch, &fixture.module, "relocation");
        }
        for target in [
            0,
            STRINGS as u32,
            SYMBOLS as u32,
            fixture.group as u32,
            u32::MAX,
        ] {
            let mut mutant = fixture.elf.clone();
            mutant.section32(rela, 44, target);
            group_rejected(&mutant, arch, &fixture.module, "relocation");
        }
        for offset in [8, u64::MAX] {
            let mut mutant = fixture.elf.clone();
            put64(
                &mut mutant.bytes,
                fixture.elf.section_value(rela, 24) as usize,
                offset,
            );
            group_rejected(&mutant, arch, &fixture.module, "relocation");
        }
        for symbol in [5_u64, u64::from(u32::MAX)] {
            let mut mutant = fixture.elf.clone();
            put64(
                &mut mutant.bytes,
                fixture.elf.section_value(rela, 24) as usize + 8,
                symbol << 32,
            );
            group_rejected(&mutant, arch, &fixture.module, "relocation");
        }
    }
}

#[test]
fn aliases_require_exact_same_object_identity_with_independent_binding_and_visibility() {
    for (machine, arch, triple) in [
        (62, "x86_64", "x86_64-unknown-none"),
        (183, "aarch64", "aarch64-unknown-none"),
        (243, "riscv64", "riscv64-unknown-none"),
    ] {
        let mut module = module();
        module.target.triple = triple.into();
        module.types.push(o_lang::ocore::native_ir::Type::Function {
            signature: module.functions[0].signature.clone(),
        });
        module.aliases = vec![
            o_lang::ocore::native_ir::Alias {
                name: "function_alias".into(),
                ty: 2,
                aliasee: "f".into(),
                linkage: "weak".into(),
                visibility: Visibility::Hidden,
            },
            o_lang::ocore::native_ir::Alias {
                name: "global_alias".into(),
                ty: 1,
                aliasee: "g".into(),
                linkage: "external".into(),
                visibility: Visibility::Protected,
            },
        ];
        module.provenance.source_alias_count = 2;
        let mut elf = Elf::new(machine, 8, 8);
        let function = elf.append_alias("function_alias", 1, 2, 2);
        let global = elf.append_alias("global_alias", 2, 1, 3);
        assert!(object_inventory(&elf.bytes, arch, &module).is_ok());
        for index in [function, global] {
            for (field, value) in [(8, 1), (16, 4)] {
                let mut mutant = elf.bytes.clone();
                put64(
                    &mut mutant,
                    elf.symbols + index * SYMBOL_BYTES + field,
                    value,
                );
                if field == 8 {
                    // Keep the mutant within its section so this reaches the
                    // alias identity boundary rather than the extent guard.
                    put64(&mut mutant, elf.symbols + index * SYMBOL_BYTES + 16, 7);
                }
                assert!(object_inventory(&mutant, arch, &module)
                    .unwrap_err()
                    .to_string()
                    .contains("alias identity/type/extent"));
            }
            let mut mutant = elf.bytes.clone();
            put16(
                &mut mutant,
                elf.symbols + index * SYMBOL_BYTES + 6,
                if index == function {
                    DATA as u16
                } else {
                    TEXT as u16
                },
            );
            assert!(object_inventory(&mutant, arch, &module).is_err());
            let mut mutant = elf.bytes.clone();
            mutant[elf.symbols + index * SYMBOL_BYTES + 4] ^= 0x30;
            assert!(object_inventory(&mutant, arch, &module)
                .unwrap_err()
                .to_string()
                .contains("binding differs"));
            let mut mutant = elf.bytes.clone();
            mutant[elf.symbols + index * SYMBOL_BYTES + 5] = 0;
            assert!(object_inventory(&mutant, arch, &module)
                .unwrap_err()
                .to_string()
                .contains("alias visibility differs"));
        }
    }
}

#[test]
fn source_function_alignment_is_checked_against_actual_code_storage() {
    let mut module = module();
    let mut elf = Elf::new(62, 8, 8);
    module.functions[0].alignment = 64;
    assert!(object_inventory(&elf.bytes, "x86_64", &module)
        .unwrap_err()
        .to_string()
        .contains("source alignment"));
    elf.section64(TEXT, 48, 64);
    assert!(object_inventory(&elf.bytes, "x86_64", &module).is_ok());
    elf.symbol64(1, 8, 4);
    elf.symbol64(1, 16, 4);
    assert!(object_inventory(&elf.bytes, "x86_64", &module)
        .unwrap_err()
        .to_string()
        .contains("source alignment"));
}

fn rejected(elf: &Elf, module: &NativeModule, case: &str) {
    assert!(
        object_inventory(&elf.bytes, "x86_64", module).is_err(),
        "accepted malformed or incompatible fixture: {case}"
    );
}

#[test]
fn inventory_maps_verified_functions_and_globals_on_each_isa() {
    for (arch, machine) in [("x86_64", 62), ("aarch64", 183), ("riscv64", 243)] {
        let mut module = module();
        module.target.triple = format!("{arch}-unknown-none");
        let elf = Elf::new(machine, 8, 8);
        let inventory = object_inventory(&elf.bytes, arch, &module).unwrap();
        assert_eq!(inventory["definitions"].as_array().unwrap().len(), 2);
        assert_eq!(inventory["definitions"][0]["name"], "f");
        assert_eq!(inventory["definitions"][0]["kind"], 2);
        assert_eq!(inventory["definitions"][0]["bytes"], 8);
        assert_eq!(inventory["definitions"][1]["name"], "g");
        assert_eq!(inventory["definitions"][1]["kind"], 1);
        assert_eq!(inventory["definitions"][1]["bytes"], 8);
    }
}

#[test]
fn definition_visibility_matches_the_exact_elf_st_other_byte_on_each_isa() {
    let styles = [
        (Visibility::Default, 0),
        (Visibility::Hidden, 2),
        (Visibility::Protected, 3),
    ];
    for (arch, machine) in [("x86_64", 62), ("aarch64", 183), ("riscv64", 243)] {
        for (function_visibility, function_other) in styles {
            for (global_visibility, global_other) in styles {
                let mut module = module();
                module.target.triple = format!("{arch}-unknown-none");
                module.functions[0].visibility = function_visibility;
                module.globals[0].visibility = global_visibility;
                let module =
                    NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
                let mut elf = Elf::new(machine, 8, 8);
                elf.symbol8(1, 5, function_other);
                elf.symbol8(2, 5, global_other);
                let inventory = object_inventory(&elf.bytes, arch, &module).unwrap();
                assert_eq!(inventory["definitions"][0]["visibility"], function_other);
                assert_eq!(inventory["definitions"][1]["visibility"], global_other);
                for (symbol, expected) in [(1, function_other), (2, global_other)] {
                    for other in [0, 1, 2, 3, 4, 0x80, 0x82, 0xff] {
                        elf.symbol8(symbol, 5, other);
                        let result = object_inventory(&elf.bytes, arch, &module);
                        assert_eq!(
                            result.is_ok(),
                            other == expected,
                            "definition visibility mismatch for {arch}, symbol={symbol}, expected={expected}, actual={other}"
                        );
                        if let Err(error) = result {
                            assert!(error.to_string().contains("visibility differs"));
                        }
                    }
                    elf.symbol8(symbol, 5, expected);
                }
            }
        }
    }
}

#[test]
fn declaration_visibility_matches_the_exact_elf_st_other_byte_on_each_isa() {
    let styles = [
        (Visibility::Default, 0),
        (Visibility::Hidden, 2),
        (Visibility::Protected, 3),
    ];
    for (arch, machine) in [("x86_64", 62), ("aarch64", 183), ("riscv64", 243)] {
        for (function_visibility, function_other) in styles {
            for (global_visibility, global_other) in styles {
                let mut module = module();
                module.target.triple = format!("{arch}-unknown-none");
                module.functions[0].visibility = function_visibility;
                module.functions[0].entry = None;
                module.functions[0].blocks.clear();
                module.globals[0].visibility = global_visibility;
                module.globals[0].initializer = None;
                let module =
                    NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
                let mut elf = Elf::new(machine, 8, 8);
                for (symbol, other) in [(1, function_other), (2, global_other)] {
                    elf.symbol16(symbol, 6, 0); // SHN_UNDEF.
                    elf.symbol64(symbol, 16, 0);
                    elf.symbol8(symbol, 5, other);
                }
                let inventory = object_inventory(&elf.bytes, arch, &module).unwrap();
                assert!(inventory["definitions"].as_array().unwrap().is_empty());
                assert_eq!(inventory["undefined_symbols"], json!(["f", "g"]));
                for (symbol, expected) in [(1, function_other), (2, global_other)] {
                    for other in [0, 1, 2, 3, 4, 0x80, 0x82, 0xff] {
                        elf.symbol8(symbol, 5, other);
                        let result = object_inventory(&elf.bytes, arch, &module);
                        assert_eq!(
                            result.is_ok(),
                            other == expected,
                            "declaration visibility mismatch for {arch}, symbol={symbol}, expected={expected}, actual={other}"
                        );
                        if let Err(error) = result {
                            assert!(error.to_string().contains("dependency visibility differs"));
                        }
                    }
                    elf.symbol8(symbol, 5, expected);
                }
            }
        }
    }
}

#[test]
fn builtin_assume_cannot_become_an_undefined_elf_dependency() {
    let mut module = module();
    module.types.push(Type::Int { bits: 1 });
    module.functions[0] = serde_json::from_value(json!({
        "name":"llvm.assume","linkage":"external","intrinsic":"llvm.assume",
        "signature":{"params":[2],"result":0,"abi":"c","variadic":false},
        "params":[{"id":0,"ty":2}],"entry":null,"blocks":[]
    }))
    .unwrap();
    let module = NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
    let mut elf = Elf::new(62, 8, 8);
    let names = b"\0llvm.assume\0g\0";
    let strings = aligned_payload(&mut elf.bytes, names, 1);
    elf.section64(STRINGS, 24, strings as u64);
    elf.section64(STRINGS, 32, names.len() as u64);
    elf.symbol32(2, 0, 13);
    elf.symbol16(1, 6, 0);
    elf.symbol64(1, 16, 0);
    let error = object_inventory(&elf.bytes, "x86_64", &module).unwrap_err();
    assert!(error
        .to_string()
        .contains("undeclared native dependency: llvm.assume"));
}

#[test]
fn undefined_global_cannot_shadow_a_same_name_local_definition() {
    for local_linkage in ["internal", "private"] {
        let mut module = module();
        module.functions[0].linkage = local_linkage.into();
        module.globals[0].linkage = local_linkage.into();
        let module = NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
        for (name_offset, name) in [(1, "f"), (3, "g")] {
            let mut elf = Elf::new(62, 8, 8);
            elf.symbol8(1, 4, 0x02);
            elf.symbol8(2, 4, 0x01);
            elf.section32(SYMBOLS, 44, 3);
            assert!(object_inventory(&elf.bytes, "x86_64", &module).is_ok());
            // ELF global references cannot bind to these STB_LOCAL definitions.
            // Retaining both definitions must not hide the extra dependency.
            elf.append_undefined(name_offset, 1);
            let error = object_inventory(&elf.bytes, "x86_64", &module).unwrap_err();
            assert!(
                error.to_string().contains("local symbol"),
                "wrong {local_linkage} undefined-dependency rejection for {name}: {error}"
            );
        }
    }
}

#[test]
fn external_undefined_symbols_require_global_binding() {
    let mut module = module();
    module.functions[0].entry = None;
    module.functions[0].blocks.clear();
    module.globals[0].initializer = None;
    let module = NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
    for symbol in [1, 2] {
        for binding in [0, 2, 3, 10, 15] {
            let mut elf = Elf::new(62, 8, 8);
            for declaration in [1, 2] {
                elf.symbol16(declaration, 6, 0);
                elf.symbol64(declaration, 16, 0);
            }
            assert!(object_inventory(&elf.bytes, "x86_64", &module).is_ok());
            elf.symbol8(symbol, 4, binding << 4);
            let error = object_inventory(&elf.bytes, "x86_64", &module).unwrap_err();
            assert!(error.to_string().contains("binding differs"));
        }
    }
}

#[test]
fn rv64_object_flags_must_match_the_lp64_rv64gc_profile() {
    let mut module = module();
    module.target.triple = "riscv64-unknown-none".into();
    module.target.abi = Some("lp64".into());
    // Compressed-instruction permission is independent of the floating ABI.
    for flags in [0, 1] {
        let mut elf = Elf::new(243, 8, 8);
        put32(&mut elf.bytes, 48, flags);
        assert!(object_inventory(&elf.bytes, "riscv64", &module).is_ok());
    }
    for flags in [2, 4, 6, 8, 16, 32, 64, 1 << 31] {
        let mut elf = Elf::new(243, 8, 8);
        put32(&mut elf.bytes, 48, flags);
        assert!(
            object_inventory(&elf.bytes, "riscv64", &module).is_err(),
            "accepted flags outside the own-emitter LP64/RV64GC profile: {flags:#x}"
        );
    }
}

#[test]
fn rv64_scalar_object_flags_preserve_the_exact_declared_lp64_or_lp64d_abi() {
    for (abi, expected_flags) in [(None, 0), (Some("lp64"), 0), (Some("lp64d"), 4)] {
        let mut module = module();
        module.target.triple = "riscv64-unknown-linux-gnu".into();
        module.target.abi = abi.map(str::to_owned);
        let module = NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
        // Exercise every encoded floating ABI, RVE, TSO and unknown flags.
        for flags in (0..64).chain([1 << 31, u32::MAX]) {
            let mut elf = Elf::new(243, 8, 8);
            put32(&mut elf.bytes, 48, flags);
            let result = object_inventory(&elf.bytes, "riscv64", &module);
            if flags == expected_flags || flags == expected_flags | 1 {
                assert!(
                    result.is_ok(),
                    "rejected {abi:?} flags {flags:#x}: {result:?}"
                );
            } else {
                let error = result.unwrap_err();
                assert!(
                    error.to_string().contains("ELF flags differ"),
                    "wrong rejection for {abi:?} flags {flags:#x}: {error}"
                );
            }
        }
    }
}

#[test]
fn rv64_unknown_declared_abi_cannot_be_laundered_through_valid_elf_flags() {
    for abi in ["lp64f", "lp64q", "ilp32", "LP64D", "", "lp64d "] {
        let mut module = module();
        module.target.triple = "riscv64-unknown-linux-gnu".into();
        module.target.abi = Some(abi.into());
        let module = NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
        for flags in [0, 1, 4, 5] {
            let mut elf = Elf::new(243, 8, 8);
            put32(&mut elf.bytes, 48, flags);
            let error = object_inventory(&elf.bytes, "riscv64", &module).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("unsupported imported RISC-V ABI"),
                "wrong rejection for {abi:?} flags {flags:#x}: {error}"
            );
        }
    }
}

#[test]
fn variant_calling_convention_symbols_cannot_satisfy_standard_native_signatures() {
    for (arch, machine) in [("aarch64", 183), ("riscv64", 243)] {
        let mut module = module();
        module.target.triple = format!("{arch}-unknown-none");
        let mut elf = Elf::new(machine, 8, 8);
        elf.symbol8(1, 5, 0x80);
        assert!(object_inventory(&elf.bytes, arch, &module).is_err());
    }
}

#[test]
fn every_truncated_prefix_is_rejected_without_panicking() {
    let module = module();
    let elf = Elf::new(62, 8, 8);
    for length in 0..elf.bytes.len() {
        let result =
            std::panic::catch_unwind(|| object_inventory(&elf.bytes[..length], "x86_64", &module));
        assert!(result.is_ok(), "parser panicked at prefix length {length}");
        assert!(
            result.unwrap().is_err(),
            "accepted truncated prefix {length}"
        );
    }
}

#[test]
fn header_only_wrong_isa_and_wrong_header_geometry_fail_closed() {
    let module = module();
    let elf = Elf::new(62, 8, 8);
    assert!(object_inventory(&elf.bytes[..64], "x86_64", &module).is_err());
    assert!(object_inventory(&elf.bytes, "aarch64", &module).is_err());
    assert!(object_inventory(&elf.bytes, "unknown", &module).is_err());
    for (offset, value) in [(16, 2), (52, 63), (58, 63), (60, 0)] {
        let mut elf = Elf::new(62, 8, 8);
        put16(&mut elf.bytes, offset, value);
        rejected(&elf, &module, "wrong header geometry or object kind");
    }
    for version in [0, 2] {
        let mut elf = Elf::new(62, 8, 8);
        put32(&mut elf.bytes, 20, version);
        rejected(&elf, &module, "unsupported ELF header version");
    }
}

#[test]
fn hostile_section_table_offsets_never_overflow_or_panic() {
    let module = module();
    for offset in [u64::MAX, u64::MAX - 31, u64::MAX - 63, 1 << 63, 4096] {
        let mut elf = Elf::new(62, 8, 8);
        put64(&mut elf.bytes, 40, offset);
        let result = std::panic::catch_unwind(|| object_inventory(&elf.bytes, "x86_64", &module));
        assert!(result.is_ok(), "parser panicked at section offset {offset}");
        assert!(result.unwrap().is_err());
    }
    let mut elf = Elf::new(62, 8, 8);
    put16(&mut elf.bytes, 60, u16::MAX);
    rejected(&elf, &module, "section count extends past object");
}

#[test]
fn file_backed_section_extents_are_checked_before_symbol_reads() {
    let module = module();
    for section in [TEXT, DATA, STRINGS, SYMBOLS] {
        for (offset, size) in [(u64::MAX, 8), (4096, 8), (0, u64::MAX)] {
            let mut elf = Elf::new(62, 8, 8);
            elf.section64(section, 24, offset);
            elf.section64(section, 32, size);
            rejected(&elf, &module, "section extent overflow or out of bounds");
        }
    }
}

#[test]
fn symbol_table_requires_valid_strings_link_stride_and_extent() {
    let module = module();
    for link in [TEXT as u32, u32::MAX] {
        let mut elf = Elf::new(62, 8, 8);
        elf.section32(SYMBOLS, 40, link);
        rejected(&elf, &module, "invalid string-table link");
    }
    for stride in [0, 16, 25, u64::MAX] {
        let mut elf = Elf::new(62, 8, 8);
        elf.section64(SYMBOLS, 56, stride);
        rejected(&elf, &module, "wrong ELF64 symbol stride");
    }
    let mut elf = Elf::new(62, 8, 8);
    elf.section64(SYMBOLS, 32, 71);
    rejected(&elf, &module, "partial symbol record");
}

#[test]
fn symbol_names_must_be_in_range_utf8_and_nul_terminated() {
    let module = module();
    for name in [5, u32::MAX] {
        let mut elf = Elf::new(62, 8, 8);
        elf.symbol32(1, 0, name);
        rejected(&elf, &module, "symbol name offset outside strings");
    }
    let mut elf = Elf::new(62, 8, 8);
    elf.bytes[elf.strings + 2] = b'x';
    elf.bytes[elf.strings + 4] = b'y';
    rejected(&elf, &module, "unterminated string");
    let mut elf = Elf::new(62, 8, 8);
    elf.bytes[elf.strings + 1] = 0xff;
    rejected(&elf, &module, "invalid UTF-8 symbol name");
}

#[test]
fn omitted_renamed_extra_and_duplicate_definitions_are_rejected() {
    let module = module();
    let mut elf = Elf::new(62, 8, 8);
    elf.symbol16(1, 6, 0);
    rejected(&elf, &module, "required function left undefined");
    let mut elf = Elf::new(62, 8, 8);
    elf.bytes[elf.strings + 1] = b'h';
    rejected(&elf, &module, "same count with wrong function name");
    let mut elf = Elf::new(62, 8, 8);
    elf.symbol32(2, 0, 1);
    rejected(&elf, &module, "duplicate definition name");
    let mut only_function = module.clone();
    only_function.globals.clear();
    only_function.provenance.source_global_count = 0;
    let elf = Elf::new(62, 8, 8);
    rejected(
        &elf,
        &only_function,
        "object includes unverified global definition",
    );
}

#[test]
fn definition_kind_size_and_section_reference_must_match() {
    let module = module();
    for (symbol, info) in [(1, 0x11), (2, 0x12)] {
        let mut elf = Elf::new(62, 8, 8);
        elf.symbol8(symbol, 4, info);
        rejected(&elf, &module, "wrong function/global type");
    }
    for section in [SECTION_COUNT as u16, 0xff00, 0xfff1, u16::MAX] {
        let mut elf = Elf::new(62, 8, 8);
        elf.symbol16(1, 6, section);
        rejected(&elf, &module, "invalid or reserved section index");
    }
    let mut elf = Elf::new(62, 8, 8);
    elf.symbol64(1, 16, 0);
    rejected(&elf, &module, "zero-byte function definition");
    for size in [0, 7, 9, u64::MAX] {
        let mut elf = Elf::new(62, 8, 8);
        elf.symbol64(2, 16, size);
        rejected(
            &elf,
            &module,
            "global storage does not match verified initializer size",
        );
    }
}

#[test]
fn definition_extents_cannot_escape_storage_or_wrap() {
    let module = module();
    for symbol in [1, 2] {
        for offset in [1, 8, u64::MAX - 3, u64::MAX] {
            let mut elf = Elf::new(62, 8, 8);
            elf.symbol64(symbol, 8, offset);
            rejected(
                &elf,
                &module,
                "definition extent out of bounds or overflowing",
            );
        }
    }
}

#[test]
fn function_inventory_requires_actual_allocated_executable_bytes() {
    let module = module();
    for kind in [2, 3, 8] {
        let mut elf = Elf::new(62, 8, 8);
        elf.section32(TEXT, 4, kind);
        rejected(
            &elf,
            &module,
            "function placed in symbol/string table or NOBITS",
        );
    }
    for flags in [0, 2, 4] {
        let mut elf = Elf::new(62, 8, 8);
        elf.section64(TEXT, 8, flags);
        rejected(
            &elf,
            &module,
            "function is not both allocated and executable",
        );
    }
}

#[test]
fn function_alignment_follows_each_isa_and_rv_compression_flag() {
    for (arch, machine, flags, alignment) in [
        ("x86_64", 62, 0, 1),
        ("aarch64", 183, 0, 4),
        ("riscv64", 243, 0, 4),
        ("riscv64", 243, 1, 2),
    ] {
        let mut module = module();
        module.target.triple = format!("{arch}-unknown-none");
        for offset in 0..4 {
            let mut elf = Elf::with_text_size(machine, 8, 8, 16);
            put32(&mut elf.bytes, 48, flags);
            elf.symbol64(1, 8, offset);
            assert_eq!(
                object_inventory(&elf.bytes, arch, &module).is_ok(),
                offset % alignment == 0,
                "wrong instruction alignment decision for {arch}, flags={flags}, offset={offset}"
            );
        }
        for actual_alignment in [1, 2, 4] {
            let mut elf = Elf::with_text_size(machine, 8, 8, 16);
            put32(&mut elf.bytes, 48, flags);
            elf.section64(TEXT, 48, actual_alignment);
            assert_eq!(
                object_inventory(&elf.bytes, arch, &module).is_ok(),
                actual_alignment >= alignment,
                "wrong section alignment decision for {arch}, flags={flags}, alignment={actual_alignment}"
            );
        }
    }
}

#[test]
fn bss_cannot_represent_a_nonzero_verified_initializer() {
    let mut module = module();
    module.globals[0].initializer.as_mut().unwrap().bytes[0] = 1;
    let module = NativeModule::from_json(&serde_json::to_vec(&module).unwrap()).unwrap();
    let mut elf = Elf::new(62, 8, 8);
    elf.section32(DATA, 4, 8);
    rejected(
        &elf,
        &module,
        "nonzero initializer replaced with NOBITS zero storage",
    );
}

#[test]
fn actual_symbol_binding_matches_verified_export_visibility() {
    let module = module();
    for (symbol, info) in [(1, 0x02), (2, 0x01), (1, 0x22), (2, 0x21)] {
        let mut elf = Elf::new(62, 8, 8);
        elf.symbol8(symbol, 4, info);
        rejected(
            &elf,
            &module,
            "export replaced with local or weak definition",
        );
    }
    let mut private = module.clone();
    private.functions[0].linkage = "internal".into();
    private.globals[0].linkage = "private".into();
    let mut elf = Elf::new(62, 8, 8);
    elf.symbol8(1, 4, 0x02);
    elf.symbol8(2, 4, 0x01);
    elf.section32(SYMBOLS, 44, 3);
    assert!(object_inventory(&elf.bytes, "x86_64", &private).is_ok());
    let elf = Elf::new(62, 8, 8);
    rejected(&elf, &private, "private IR definition exported by object");
}

#[test]
fn actual_global_alignment_must_satisfy_verified_layout() {
    let module = module();
    let mut elf = Elf::new(62, 8, 8);
    elf.section64(DATA, 48, 1);
    rejected(&elf, &module, "section alignment below global alignment");
    let mut elf = Elf::new(62, 16, 8);
    elf.symbol64(2, 8, 1);
    rejected(
        &elf,
        &module,
        "misaligned global offset within sufficiently large section",
    );
    let mut over_aligned = module.clone();
    over_aligned.globals[0].alignment = 64;
    let elf = Elf::new(62, 8, 64);
    assert!(object_inventory(&elf.bytes, "x86_64", &over_aligned).is_ok());
    let elf = Elf::new(62, 8, 8);
    rejected(
        &elf,
        &over_aligned,
        "IR promises alignment beyond actual section alignment",
    );
}

#[test]
fn mutable_global_requires_allocated_writable_storage() {
    let module = module();
    for flags in [0, 1, 2] {
        let mut elf = Elf::new(62, 8, 8);
        elf.section64(DATA, 8, flags);
        rejected(
            &elf,
            &module,
            "mutable global missing allocated writable storage",
        );
    }
    let mut constant = module.clone();
    constant.globals[0].constant = true;
    let mut elf = Elf::new(62, 8, 8);
    elf.section64(DATA, 8, 2);
    assert!(object_inventory(&elf.bytes, "x86_64", &constant).is_ok());
}
#[path = "noalias_tests.rs"]
mod noalias_tests;
