//! Direct assembly emission for verified imported scalar IR.
//!
//! LLVM poison/undef are deterministically refined, rather than eagerly trapped.
//! Backend coverage is audited for the entire module before assembly is written.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use super::native_abi::{AbiClass, AbiContext, AbiLocation, AbiPart, AbiPlan, Extension};
use super::native_exception_codegen::{CallSite, ExceptionTables};
use super::native_ir::*;
use super::native_map::{NativeAssemblyMap, NativeAssemblySite, NativeAssemblySiteKind};
use super::native_nonlocal::{
    self, FrameRegion, FunctionFrameProof, NativeNonlocalReport, NonlocalCallSiteProof,
    SavedFrameRegister, SpillChunk,
};
use super::native_verify::{
    fixed_vector_layout, instruction_operands, type_alignment, type_layouts, value_leaf_layouts,
};
use super::Diagnostic;
use super::Target;

// Keep the exclusive-loop implementation beside the emitter. As a child
// module it can use the private spill/operand helpers without exposing them
// as a second public backend API.
mod atomic {
    include!("native_atomic_codegen.rs");
}

mod float_layout {
    include!("native_float_layout.rs");
}

mod variadic {
    include!("native_variadic_codegen.rs");
}
mod floating_transport {
    include!("native_floating_transport.rs");
}
mod floating {
    use crate::ocore::native_codegen::*;
    include!("native_floating_codegen.rs");
}
mod wide_integer {
    use crate::ocore::native_codegen::*;
    include!("native_wide_integer_codegen.rs");
}
mod wide_volatile {
    use crate::ocore::native_codegen::*;
    include!("native_wide_volatile_codegen.rs");
}
mod vector {
    use crate::ocore::native_codegen::*;
    include!("native_vector_codegen.rs");
}

pub fn emit(module: &NativeModule, target: Target) -> Result<String, Diagnostic> {
    let (assembly, _) = emit_impl(module, target, None)?;
    Ok(assembly)
}

/// Emit the identical assembly together with descriptive IR-to-assembly byte ranges.
/// The ranges identify UTF-8 assembly bytes, never machine addresses or executions.
pub fn emit_with_map(
    module: &NativeModule,
    target: Target,
) -> Result<(String, NativeAssemblyMap), Diagnostic> {
    let mut sites = Vec::new();
    let (assembly, _) = emit_impl(module, target, Some(&mut sites))?;
    let map = NativeAssemblyMap::from_emission(module, target, &assembly, sites)?;
    Ok((assembly, map))
}

/// Emit the same fixed-frame realization and its computed continuation report.
/// This does not admit original jump providers or managed-frame exposure.
pub fn emit_with_nonlocal_report(
    module: &NativeModule,
    target: Target,
) -> Result<(String, NativeNonlocalReport), Diagnostic> {
    let (assembly, frames) = emit_impl(module, target, None)?;
    let report = NativeNonlocalReport::from_emission(module, target, &assembly, frames)?;
    Ok((assembly, report))
}

pub fn emit_with_map_and_nonlocal_report(
    module: &NativeModule,
    target: Target,
) -> Result<(String, NativeAssemblyMap, NativeNonlocalReport), Diagnostic> {
    let mut sites = Vec::new();
    let (assembly, frames) = emit_impl(module, target, Some(&mut sites))?;
    let map = NativeAssemblyMap::from_emission(module, target, &assembly, sites)?;
    let report = NativeNonlocalReport::from_emission(module, target, &assembly, frames)?;
    Ok((assembly, map, report))
}

fn emit_impl(
    module: &NativeModule,
    target: Target,
    mut sites: Option<&mut Vec<NativeAssemblySite>>,
) -> Result<(String, Vec<FunctionFrameProof>), Diagnostic> {
    // Retain the verifier's ordinary C/direct-AS0/fixed-alloca/no-EH constraints.
    // Every exposed emitter then computes its actual non-reused frame proof.
    super::native_verify::verify(module)?;
    audit(module, target)?;
    let leaf_layouts = value_leaf_layouts(module, &executable_value_types(module))?;
    let layouts = type_layouts(module)?;
    let abi = AbiContext::new(module, target, &leaf_layouts, &layouts)?;
    let metadata_personalities = super::native_eh::metadata_personality_declarations(module);
    for function in &module.functions {
        let types: BTreeMap<_, _> = function_values(function).map(|v| (v.id, v.ty)).collect();
        if !metadata_personalities.contains(&function.name)
            && !function
                .intrinsic
                .as_deref()
                .is_some_and(super::native_verify::is_metadata_builtin_intrinsic)
            && !vector::is_reduction_declaration(function)
            && (function.entry.is_some()
                || !super::native_abi::is_fast_float_signature(module, &function.signature))
        {
            abi.plan_function(function)?;
        }
        for instruction in function.blocks.iter().flat_map(|b| &b.instructions) {
            if let Operation::Call {
                signature, args, ..
            } = &instruction.operation
            {
                abi.plan_call_from(
                    function,
                    signature,
                    &argument_types(args, &types),
                    &signature.param_attributes,
                )?;
            }
        }
        for block in &function.blocks {
            if let Terminator::Invoke {
                signature, args, ..
            } = &block.terminator
            {
                abi.plan_call_from(
                    function,
                    signature,
                    &argument_types(args, &types),
                    &signature.param_attributes,
                )?;
            }
        }
    }
    let external_weak: BTreeSet<_> = module
        .globals
        .iter()
        .filter(|g| g.linkage == "extern_weak")
        .map(|g| g.name.clone())
        .chain(
            module
                .functions
                .iter()
                .filter(|f| f.linkage == "extern_weak")
                .map(|f| f.name.clone()),
        )
        .collect();
    let mut out = String::new();
    let mut frames = Vec::new();
    let mut namespace = 0usize;
    let label_prefix = loop {
        let candidate = format!(".Locore_native_{namespace}_");
        if !module
            .functions
            .iter()
            .map(|f| &f.name)
            .chain(module.globals.iter().map(|g| &g.name))
            .chain(module.aliases.iter().map(|a| &a.name))
            .chain(module.comdats.iter().map(|group| &group.name))
            .any(|name| name.starts_with(&candidate))
        {
            break candidate;
        }
        namespace += 1;
    };
    if target == Target::X86_64UnknownNone {
        out.push_str(".intel_syntax noprefix\n");
    } else if target == Target::Riscv64UnknownNone {
        // Materialize source function alignment in the relocatable object.
        // R_RISCV_ALIGN otherwise leaves padding for the linker to remove;
        // relaxing earlier instructions could also move later aligned symbols.
        // Keep the whole owned module fixed while its ELF inventory is checked.
        out.push_str(".option push\n.option norelax\n");
    }
    for (index, global) in module.globals.iter().enumerate() {
        elf_visibility(&mut out, &global.name, global.visibility);
        if global.thread_local {
            writeln!(out, ".type {}, @tls_object", global.name).unwrap();
            if global.initializer.is_none() {
                visibility(&mut out, &global.name, &global.linkage);
            }
        }
        if !matches!(
            global.linkage.as_str(),
            "external"
                | "extern_weak"
                | "internal"
                | "private"
                | "weak"
                | "linkonce"
                | "linkonce_odr"
                | "weak_odr"
        ) {
            return Err(error_diagnostic(format!(
                "imported native backend does not implement linkage `{}` for {}",
                global.linkage, global.name
            )));
        }
        let Some(init) = &global.initializer else {
            if global.linkage == "extern_weak" {
                visibility(&mut out, &global.name, &global.linkage);
                writeln!(out, ".type {}, @object", global.name).unwrap();
            }
            continue;
        };
        let zero_tls = global.thread_local
            && init.relocations.is_empty()
            && init.bytes.iter().all(|byte| *byte == 0);
        let section = if global.thread_local {
            if zero_tls {
                ".tbss"
            } else {
                ".tdata"
            }
        } else if global.constant {
            ".rodata"
        } else {
            ".data"
        };
        emit_section(
            &mut out,
            module,
            section,
            if global.thread_local {
                "awT"
            } else if global.constant {
                "a"
            } else {
                "aw"
            },
            global.comdat.as_deref(),
            &format!("{label_prefix}global_{index}"),
        );
        visibility(&mut out, &global.name, &global.linkage);
        let alignment = if global.alignment == 0 {
            type_alignment(module, global.ty)?
        } else {
            global.alignment
        };
        writeln!(
            out,
            ".balign {}\n.type {}, @{}\n{}:",
            alignment,
            global.name,
            if global.thread_local {
                "tls_object"
            } else {
                "object"
            },
            global.name
        )
        .unwrap();
        if zero_tls {
            writeln!(
                out,
                "  .zero {}\n.size {}, .-{}",
                init.bytes.len(),
                global.name,
                global.name
            )
            .unwrap();
            continue;
        }
        let mut offset = 0;
        while offset < init.bytes.len() {
            if let Some(reloc) = init
                .relocations
                .iter()
                .find(|r| r.offset as usize == offset)
            {
                if let Some(base) = &reloc.relative_to {
                    writeln!(out, "  .long {} - {}{:+}", reloc.symbol, base, reloc.addend).unwrap();
                    offset += 4;
                } else {
                    let target = reloc.block.as_ref().map_or_else(
                        || reloc.symbol.clone(),
                        |block| {
                            block_address_label(module, &label_prefix, &block.function, block.block)
                        },
                    );
                    writeln!(out, "  .quad {target}{:+}", reloc.addend).unwrap();
                    offset += 8;
                }
            } else {
                writeln!(out, "  .byte {}", init.bytes[offset]).unwrap();
                offset += 1;
            }
        }
        writeln!(out, ".size {}, .-{}", global.name, global.name).unwrap();
    }
    for (index, function) in module.functions.iter().enumerate() {
        elf_visibility(&mut out, &function.name, function.visibility);
        if function.entry.is_none() && function.linkage == "extern_weak" {
            visibility(&mut out, &function.name, &function.linkage);
            writeln!(out, ".type {}, @function", function.name).unwrap();
        }
        if function.entry.is_some() {
            if let Some(proof) = Emitter::new(
                module,
                function,
                index,
                target,
                &label_prefix,
                &external_weak,
                &leaf_layouts,
                &abi,
            )?
            .emit(&mut out, sites.as_deref_mut())?
            {
                frames.push(proof);
            }
        }
    }
    for alias in &module.aliases {
        visibility(&mut out, &alias.name, &alias.linkage);
        elf_visibility(&mut out, &alias.name, alias.visibility);
        let kind = if matches!(module.types[alias.ty], Type::Function { .. }) {
            "function"
        } else {
            "object"
        };
        // ELF assembler aliases inherit the aliasee's extent and position.
        // Keep the alias symbol in every operand/relocation: linker selection
        // may override it independently from the original aliasee symbol.
        writeln!(
            out,
            ".type {}, @{kind}\n.set {}, {}",
            alias.name, alias.name, alias.aliasee
        )
        .unwrap();
    }
    if let Some(requirement) = super::native_platform::requirement(module)? {
        // Allocated ELF note carries the mandatory external provider interface
        // even when ordinary ELF symbol resolution reports zero UND symbols.
        let payload = serde_json::to_vec(&requirement)
            .map_err(|error| error_diagnostic(format!("Linux platform note: {error}")))?;
        writeln!(out, ".section .note.ocore.platform,\"a\",@note\n.p2align 2\n.long 6\n.long {}\n.long 1\n.byte 79,99,111,114,101,0\n.p2align 2", payload.len()).unwrap();
        for chunk in payload.chunks(32) {
            writeln!(
                out,
                ".byte {}",
                chunk
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )
            .unwrap();
        }
        out.push_str(".p2align 2\n");
    }
    out.push_str(".section .note.GNU-stack,\"\",@progbits\n");
    if target == Target::Riscv64UnknownNone {
        out.push_str(".option pop\n");
    }
    Ok((out, frames))
}

fn visibility(out: &mut String, name: &str, linkage: &str) {
    match linkage {
        "internal" | "private" => writeln!(out, ".local {name}").unwrap(),
        "weak" | "extern_weak" | "linkonce" | "linkonce_odr" | "weak_odr" => {
            writeln!(out, ".weak {name}").unwrap()
        }
        _ => writeln!(out, ".global {name}").unwrap(),
    }
}

fn native_block_label(prefix: &str, function: usize, block: BlockId) -> String {
    format!("{prefix}{function}_b{block}")
}

/// Block references use the same local code labels as block emission. They are
/// not ordinary function/global symbols and must retain their owning function.
fn block_address_label(
    module: &NativeModule,
    prefix: &str,
    function: &str,
    block: BlockId,
) -> String {
    let index = module
        .functions
        .iter()
        .position(|candidate| candidate.name == function)
        .expect("verified block-address function");
    native_block_label(prefix, index, block)
}

fn emit_section(
    out: &mut String,
    module: &NativeModule,
    section: &str,
    flags: &str,
    group: Option<&str>,
    member: &str,
) {
    let kind = if section == ".tbss" {
        "nobits"
    } else {
        "progbits"
    };
    if let Some(group) = group {
        let selection = module
            .comdats
            .iter()
            .find(|candidate| candidate.name == group)
            .expect("verified COMDAT membership")
            .selection;
        let suffix = if selection == ComdatSelection::Any {
            ",comdat"
        } else {
            ""
        };
        // Distinct sections preserve the entire group and each relocation
        // section. Ordinary weak binding alone cannot express this contract.
        writeln!(
            out,
            ".section {section}.{member},\"{flags}G\",@{kind},{group}{suffix}"
        )
        .unwrap();
    } else {
        if section == ".tdata" || section == ".tbss" {
            writeln!(out, ".section {section},\"{flags}\",@{kind}").unwrap();
        } else {
            writeln!(out, ".section {section}").unwrap();
        }
    }
}

fn elf_visibility(out: &mut String, name: &str, visibility: Visibility) {
    match visibility {
        Visibility::Default => {}
        Visibility::Hidden => writeln!(out, ".hidden {name}").unwrap(),
        Visibility::Protected => writeln!(out, ".protected {name}").unwrap(),
    }
}

/// Request layouts only for executable values. An unused giant global array
/// has storage, but does not require one spill slot per element.
fn executable_value_types(module: &NativeModule) -> Vec<TypeId> {
    let mut types = BTreeSet::new();
    for function in &module.functions {
        // The verified metadata-only declaration has no executable parameter
        // leaves. It is retained in inventory without fabricating an ABI slot.
        if function
            .intrinsic
            .as_deref()
            .is_some_and(super::native_verify::is_metadata_builtin_intrinsic)
            || vector::is_reduction_declaration(function)
        {
            continue;
        }
        types.extend(function.signature.params.iter().copied());
        if !matches!(module.types[function.signature.result], Type::Void) {
            types.insert(function.signature.result);
        }
        types.extend(function.params.iter().map(|value| value.ty));
        for block in &function.blocks {
            for instruction in &block.instructions {
                if let Operation::Call { signature, .. } = &instruction.operation {
                    types.extend(signature.params.iter().copied());
                    if !matches!(module.types[signature.result], Type::Void) {
                        types.insert(signature.result);
                    }
                }
                types.extend(instruction.result.map(|value| value.ty));
                for operand in instruction_operands(&instruction.operation) {
                    if let Some(ty) = constant_type(operand) {
                        types.insert(ty);
                    }
                }
            }
            match &block.terminator {
                Terminator::Return { value: Some(value) }
                | Terminator::Branch {
                    condition: value, ..
                }
                | Terminator::Switch {
                    condition: value, ..
                }
                | Terminator::IndirectBranch { address: value, .. }
                | Terminator::Resume { value, .. } => {
                    if let Some(ty) = constant_type(value) {
                        types.insert(ty);
                    }
                }
                Terminator::Invoke {
                    callee,
                    signature,
                    args,
                    result,
                    ..
                } => {
                    types.extend(signature.params.iter().copied());
                    if !matches!(module.types[signature.result], Type::Void) {
                        types.insert(signature.result);
                    }
                    types.extend(result.map(|value| value.ty));
                    for operand in std::iter::once(callee).chain(args) {
                        if let Some(ty) = constant_type(operand) {
                            types.insert(ty);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    types.into_iter().collect()
}

fn function_values(function: &Function) -> impl Iterator<Item = &Value> {
    function
        .params
        .iter()
        .chain(function.blocks.iter().flat_map(|block| {
            block
                .instructions
                .iter()
                .filter_map(|instruction| instruction.result.as_ref())
                .chain(match &block.terminator {
                    Terminator::Invoke { result, .. } => result.as_ref(),
                    _ => None,
                })
        }))
}

fn constant_type(value: &Operand) -> Option<TypeId> {
    match value {
        Operand::Value { .. } => None,
        Operand::Float { ty, .. }
        | Operand::Int { ty, .. }
        | Operand::PointerBits { ty, .. }
        | Operand::PointerToInteger { ty, .. }
        | Operand::Null { ty }
        | Operand::Symbol { ty, .. }
        | Operand::SymbolOffset { ty, .. }
        | Operand::BlockAddress { ty, .. }
        | Operand::Aggregate { ty, .. }
        | Operand::AggregateZero { ty }
        | Operand::Undef { ty }
        | Operand::Poison { ty } => Some(*ty),
    }
}

fn argument_types(args: &[Operand], types: &BTreeMap<ValueId, TypeId>) -> Vec<TypeId> {
    args.iter()
        .map(|arg| match arg {
            Operand::Value { id } => types[id],
            _ => constant_type(arg).expect("verified typed argument"),
        })
        .collect()
}

fn audit(module: &NativeModule, target: Target) -> Result<(), Diagnostic> {
    let metadata_personalities = super::native_eh::metadata_personality_declarations(module);
    let prefix = match target {
        Target::X86_64UnknownNone => "x86_64",
        Target::Aarch64UnknownNone => "aarch64",
        Target::Riscv64UnknownNone => "riscv64",
    };
    if module.target.triple.split('-').next() != Some(prefix) {
        return Err(error_diagnostic(format!(
            "frontend target `{}` does not match {}; regenerate frontend IR for this ISA",
            module.target.triple,
            target.name()
        )));
    }
    let bare_rv = module.target.triple == "riscv64"
        && matches!(module.target.abi.as_deref(), Some("lp64" | "lp64d"));
    if module
        .target
        .abi
        .as_deref()
        .is_some_and(|abi| prefix != "riscv64" || !matches!(abi, "lp64" | "lp64d"))
    {
        return Err(error_diagnostic("unsupported explicit frontend ABI"));
    }
    let parts: Vec<_> = module.target.triple.split('-').collect();
    let elf_profile = matches!(parts.as_slice(), [_, vendor, "linux", "gnu" | "musl"] if !vendor.is_empty())
        || matches!(parts.as_slice(), [_, vendor, "none"] if !vendor.is_empty())
        || matches!(parts.as_slice(), [_, vendor, "none", "elf" | "eabi"] if !vendor.is_empty());
    if !bare_rv && !elf_profile {
        return Err(error_diagnostic(
            "imported scalar C ABI is implemented for Linux/ELF frontend profiles only",
        ));
    }
    if module.target.pointer_bits != 64 || !module.target.little_endian {
        return Err(error_diagnostic(
            "imported scalar backend requires little-endian LP64",
        ));
    }
    for (ty_id, ty) in module.types.iter().enumerate() {
        match ty {
            Type::Int { bits: 1..=64 | 128 }
            | Type::Pointer { address_space: 0 }
            | Type::Void
            | Type::Metadata {}
            | Type::OpaqueStruct { .. } // verified address-only external declarations
            | Type::Float {
                bits: 32 | 64 | 80 | 128,
            }
            | Type::Array { .. }
            | Type::Struct { .. }
            | Type::Function { .. } => {}
            Type::Vector { .. } => { leaf_bits(module, ty_id)?; }
            _ => {
                return Err(error_diagnostic(format!(
                    "imported ISA lowering is not implemented for type {ty:?}"
                )))
            }
        }
    }
    float_layout::audit(module, &executable_value_types(module))?;
    // This required source profile is separate from default FP support.
    // Recheck it at emission as well as ordinary NativeIR admission.
    super::native_verify::verify_strict_fp_profile(module)?;
    for alias in &module.aliases {
        if !matches!(
            alias.linkage.as_str(),
            "external" | "internal" | "private" | "weak" | "linkonce" | "linkonce_odr" | "weak_odr"
        ) {
            return Err(error_diagnostic(format!(
                "imported native backend does not implement alias linkage `{}` for {}",
                alias.linkage, alias.name
            )));
        }
    }
    for global in &module.globals {
        if !matches!(
            global.linkage.as_str(),
            "external"
                | "extern_weak"
                | "internal"
                | "private"
                | "weak"
                | "linkonce"
                | "linkonce_odr"
                | "weak_odr"
        ) {
            return Err(error_diagnostic(format!(
                "imported native backend does not implement linkage `{}` for {}",
                global.linkage, global.name
            )));
        }
        if global.thread_local
            && module.target.tls_profile != Some(TlsProfile::LinuxElfStaticNonpreemptiveV1)
        {
            return Err(error_diagnostic(format!(
                "TLS lowering is not implemented: {}",
                global.name
            )));
        }
        if let Some(init) = &global.initializer {
            let alignment = if global.alignment == 0 {
                type_alignment(module, global.ty)?
            } else {
                global.alignment
            };
            // LLVM IR can express a 2^32-byte alignment, but the native
            // assembler cannot realize it with either .balign or .p2align.
            // Keep the source contract in IR and reject before emitting an
            // assembly artifact that purports to implement this storage.
            if alignment >= (1u64 << 32) {
                return Err(error_diagnostic(format!(
                    "global storage alignment {alignment} cannot be realized by the native assembler: {}",
                    global.name
                )));
            }
            for r in &init.relocations {
                if r.block.is_some() && (r.width != 64 || r.relative_to.is_some()) {
                    return Err(error_diagnostic(
                        "only absolute64 block-address initializer relocations are implemented",
                    ));
                }
                if !matches!((r.width, r.relative_to.is_some()), (64, false) | (32, true)) {
                    return Err(error_diagnostic(
                        "only absolute64 and source-relative32 initializer relocations are implemented",
                    ));
                }
                if target == Target::Aarch64UnknownNone
                    && r.relative_to.is_some()
                    && (module
                        .globals
                        .iter()
                        .any(|g| g.name == r.symbol && g.linkage == "extern_weak")
                        || module
                            .functions
                            .iter()
                            .any(|f| f.name == r.symbol && f.linkage == "extern_weak"))
                {
                    // AAELF64 PREL uses the place for an absent weak symbol;
                    // LLVM's source pointer arithmetic instead requires zero.
                    return Err(error_diagnostic("AArch64 source-relative initializer targeting extern_weak cannot preserve absent-provider zero semantics"));
                }
            }
        }
    }
    for function in &module.functions {
        if !matches!(
            function.linkage.as_str(),
            "external"
                | "extern_weak"
                | "internal"
                | "private"
                | "weak"
                | "linkonce"
                | "linkonce_odr"
                | "weak_odr"
        ) {
            return Err(error_diagnostic(format!(
                "imported native backend does not implement linkage `{}` for {}",
                function.linkage, function.name
            )));
        }
        if function.entry.is_some() && function.alignment >= (1u64 << 32) {
            return Err(error_diagnostic(format!(
                "function code alignment {} cannot be realized by the native assembler: {}",
                function.alignment, function.name
            )));
        }
        if !metadata_personalities.contains(&function.name)
            && !function
                .intrinsic
                .as_deref()
                .is_some_and(super::native_verify::is_metadata_builtin_intrinsic)
            && !vector::is_reduction_declaration(function)
        {
            super::native_abi::audit_signature(module, target, &function.signature)?;
        }
        let value_types: BTreeMap<_, _> = function_values(function).map(|v| (v.id, v.ty)).collect();
        for block in &function.blocks {
            if let Terminator::Invoke {
                signature, args, ..
            } = &block.terminator
            {
                super::native_abi::audit_call_signature(
                    module,
                    target,
                    signature,
                    &argument_types(args, &value_types),
                    &signature.param_attributes,
                )?;
            }
            for instruction in &block.instructions {
                atomic::audit_instruction(module, instruction, &value_types)?;
                super::native_floating_helpers::operation_requirement(
                    module,
                    target,
                    instruction,
                    &value_types,
                )?;
                if let Some(result) = instruction.result {
                    // Every component type was audited above. Reject an
                    // unsupported ABI before expanding any aggregate spills.
                    if !matches!(
                        module.types[result.ty],
                        Type::Array { .. } | Type::Struct { .. } | Type::Vector { .. }
                    ) {
                        scalar_bits(module, result.ty)?;
                    }
                }
                match &instruction.operation {
                    Operation::Call {
                        signature, args, ..
                    } => {
                        super::native_abi::audit_call_signature(
                            module,
                            target,
                            signature,
                            &argument_types(args, &value_types),
                            &signature.param_attributes,
                        )?;
                    }
                    Operation::Alloca { .. } if Some(block.id) != function.entry => {
                        return Err(error_diagnostic(format!("non-entry allocation in {} needs per-execution stack allocation lowering", function.name)));
                    }
                    Operation::Alloca { alignment, .. } if *alignment > 16 => {
                        return Err(error_diagnostic(
                            "over-aligned imported stack allocations need extended frame lowering",
                        ))
                    }
                    Operation::Load {
                        alignment,
                        volatile: true,
                        ..
                    } => {
                        volatile_audit(module, target, instruction.result.unwrap().ty, *alignment)?;
                    }
                    Operation::Store {
                        value,
                        alignment,
                        volatile: true,
                        ..
                    } => {
                        let ty = match value {
                            Operand::Value { id } => value_types[id],
                            Operand::Float { ty, .. }
                            | Operand::Int { ty, .. }
                            | Operand::PointerBits { ty, .. }
                            | Operand::PointerToInteger { ty, .. }
                            | Operand::Null { ty }
                            | Operand::Symbol { ty, .. }
                            | Operand::SymbolOffset { ty, .. }
                            | Operand::BlockAddress { ty, .. }
                            | Operand::Aggregate { ty, .. }
                            | Operand::AggregateZero { ty }
                            | Operand::Undef { ty }
                            | Operand::Poison { ty } => *ty,
                        };
                        volatile_audit(module, target, ty, *alignment)?;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn volatile_audit(
    module: &NativeModule,
    target: Target,
    ty: TypeId,
    alignment: u64,
) -> Result<(), Diagnostic> {
    if matches!(module.types[ty], Type::Array { .. } | Type::Struct { .. }) {
        return Err(error_diagnostic(
            "volatile aggregate accesses require an explicit target-specific access contract",
        ));
    }
    let alignment = if alignment == 0 {
        type_alignment(module, ty)?
    } else {
        alignment
    };
    if scalar_bits(module, ty)? > 64 {
        if module.target.wide_volatile_profile != Some(WideVolatileProfile::OrdinaryRamSplitV1) {
            return Err(error_diagnostic(
                "wide volatile accesses require the explicit ordinary-RAM wide-volatile profile; generic and MMIO accesses remain unsupported",
            ));
        }
        // No byte splitting or widened external access is hidden in this
        // profile. x86 uses one f128/x87 memory operation where applicable;
        // scalar i128 and non-native f128 use ordered low/high64 RAM accesses.
        if target != Target::X86_64UnknownNone && alignment < 8 {
            return Err(error_diagnostic(
                "wide volatile RAM accesses require at least eight-byte alignment on this target",
            ));
        }
        return Ok(());
    }
    let bytes = u64::from(scalar_bits(module, ty)?.div_ceil(8));
    if !bytes.is_power_of_two() {
        return Err(error_diagnostic("odd-byte volatile access requires a target-specific access-width contract; byte splitting is forbidden"));
    }
    if target != Target::X86_64UnknownNone && alignment < bytes {
        return Err(error_diagnostic("unaligned volatile access requires a target-specific access-width contract; byte splitting is forbidden"));
    }
    Ok(())
}

fn scalar_bits(module: &NativeModule, ty: TypeId) -> Result<u16, Diagnostic> {
    match module.types[ty] {
        Type::Int {
            bits: bits @ (1..=64 | 128),
        } => Ok(bits),
        Type::Pointer { address_space: 0 } => Ok(64),
        Type::Float {
            bits: bits @ (32 | 64 | 80 | 128),
        } => Ok(bits),
        _ => Err(error_diagnostic(format!(
            "imported scalar value/ABI cannot represent type {}",
            ty
        ))),
    }
}

// A vector is one typed packed leaf, irrespective of source allocation padding.
// Physical SSA storage is a checked sequence of eight-byte chunks, not a
// scalar-element byte stride or an implicit single machine word.
fn leaf_bits(module: &NativeModule, ty: TypeId) -> Result<u64, Diagnostic> {
    let bits = if matches!(module.types[ty], Type::Vector { .. }) {
        fixed_vector_layout(module, ty)?.bit_width
    } else {
        u64::from(scalar_bits(module, ty)?)
    };
    let bytes = bits
        .div_ceil(64)
        .checked_mul(8)
        .ok_or_else(|| error_diagnostic("packed leaf spill extent overflow"))?;
    i64::try_from(bytes)
        .map_err(|_| error_diagnostic("packed leaf spill exceeds physical frame address space"))?;
    usize::try_from(bits.div_ceil(64))
        .map_err(|_| error_diagnostic("packed leaf chunk count exceeds compiler address space"))?;
    Ok(bits)
}

struct Emitter<'a> {
    module: &'a NativeModule,
    function: &'a Function,
    index: usize,
    target: Target,
    slots: BTreeMap<ValueId, i64>,
    leaf_spill_offsets: BTreeMap<TypeId, Vec<i64>>,
    types: BTreeMap<ValueId, TypeId>,
    allocations: BTreeMap<ValueId, i64>,
    call_return_storage: BTreeMap<ValueId, i64>,
    return_pointer: Option<i64>,
    /// x86/AArch64 register-save area, below the ordinary fixed frame.
    /// RV64 instead saves a0..a7 immediately below the incoming stack area.
    variadic_save: Option<i64>,
    /// A private 16-byte bit-pattern bridge for x87 ABI transport.
    floating_scratch: i64,
    abi_plan: AbiPlan,
    abi: &'a AbiContext<'a>,
    /// Packed leaf chunks use eight-byte spills, independent of memory padding.
    /// Original aggregate types and DataLayout offsets remain the memory ABI.
    leaf_layouts: &'a BTreeMap<TypeId, Vec<(TypeId, u64)>>,
    phi_slots: Vec<i64>,
    frame: i64,
    label_counter: usize,
    label_prefix: &'a str,
    external_weak: &'a BTreeSet<String>,
    exception_tables: Option<ExceptionTables<'a>>,
    call_sites: Vec<CallSite>,
    nonlocal_calls: Vec<NonlocalCallSiteProof>,
}

impl<'a> Emitter<'a> {
    // Keep verified source, target, leaf-layout and ABI contexts explicit at
    // construction; grouping them would obscure their separate ownership.
    #[allow(clippy::too_many_arguments)]
    fn new(
        module: &'a NativeModule,
        function: &'a Function,
        index: usize,
        target: Target,
        label_prefix: &'a str,
        external_weak: &'a BTreeSet<String>,
        leaf_layouts: &'a BTreeMap<TypeId, Vec<(TypeId, u64)>>,
        abi: &'a AbiContext<'a>,
    ) -> Result<Self, Diagnostic> {
        let mut result = Self {
            module,
            function,
            index,
            target,
            slots: BTreeMap::new(),
            leaf_spill_offsets: BTreeMap::new(),
            types: BTreeMap::new(),
            allocations: BTreeMap::new(),
            call_return_storage: BTreeMap::new(),
            return_pointer: None,
            variadic_save: None,
            floating_scratch: 0,
            abi_plan: abi.plan_function(function)?,
            abi,
            leaf_layouts,
            phi_slots: Vec::new(),
            frame: 0,
            label_counter: 0,
            label_prefix,
            external_weak,
            exception_tables: (function.exception_handling.is_some()
                || function
                    .blocks
                    .iter()
                    .flat_map(|block| &block.instructions)
                    .any(|instruction| {
                        matches!(instruction.operation, Operation::EhTypeId { .. })
                    }))
            .then(|| ExceptionTables::new(function))
            .transpose()?,
            call_sites: Vec::new(),
            nonlocal_calls: Vec::new(),
        };
        for value in function_values(function) {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                result.leaf_spill_offsets.entry(value.ty)
            {
                let mut cursor = 0i64;
                let mut offsets = Vec::new();
                for (field, _) in &leaf_layouts[&value.ty] {
                    offsets.push(cursor);
                    cursor = cursor
                        .checked_add(
                            i64::try_from(leaf_bits(module, *field)?.div_ceil(64))
                                .ok()
                                .and_then(|parts| parts.checked_mul(8))
                                .ok_or_else(|| {
                                    error_diagnostic("packed leaf spill extent overflow")
                                })?,
                        )
                        .ok_or_else(|| error_diagnostic("aggregate spill offset overflow"))?;
                }
                entry.insert(offsets);
            }
            result.frame = result
                .frame
                .checked_add(
                    i64::try_from(result.value_chunks(value.ty).len().max(1))
                        .ok()
                        .and_then(|parts| parts.checked_mul(8))
                        .ok_or_else(|| error_diagnostic("value spill extent overflow"))?,
                )
                .ok_or_else(|| error_diagnostic("frame layout overflow"))?;
            result.slots.insert(value.id, -result.frame);
            result.types.insert(value.id, value.ty);
        }
        for block in &function.blocks {
            if let Terminator::Invoke {
                signature,
                args,
                result: value,
                ..
            } = &block.terminator
            {
                let plan = abi.plan_call_from(
                    function,
                    signature,
                    &argument_types(args, &result.types),
                    &signature.param_attributes,
                )?;
                if let Some(storage) = plan
                    .storage
                    .filter(|storage| storage.explicit_param.is_none())
                {
                    if storage.alignment > 16 {
                        return Err(error_diagnostic("over-aligned implicit invoke result storage requires extended frame lowering"));
                    }
                    result.frame = align(
                        result
                            .frame
                            .checked_add(i64::try_from(storage.size).map_err(|_| {
                                error_diagnostic("implicit invoke return storage extent overflow")
                            })?)
                            .ok_or_else(|| {
                                error_diagnostic("implicit invoke return frame overflow")
                            })?,
                        storage.alignment.max(1) as i64,
                    )?;
                    result
                        .call_return_storage
                        .insert(value.unwrap().id, -result.frame);
                }
            }
        }
        if result
            .abi_plan
            .storage
            .as_ref()
            .is_some_and(|storage| storage.explicit_param.is_none())
        {
            result.frame = result
                .frame
                .checked_add(8)
                .ok_or_else(|| error_diagnostic("return pointer spill overflow"))?;
            result.return_pointer = Some(-result.frame);
        }
        for instruction in function.blocks.iter().flat_map(|b| &b.instructions) {
            if let Operation::Alloca { size, alignment } = instruction.operation {
                result.frame = align(
                    result
                        .frame
                        .checked_add(
                            i64::try_from(size)
                                .map_err(|_| error_diagnostic("allocation extent overflow"))?,
                        )
                        .ok_or_else(|| error_diagnostic("allocation extent overflow"))?,
                    alignment.max(1) as i64,
                )?;
                result
                    .allocations
                    .insert(instruction.result.unwrap().id, -result.frame);
            }
            if let Operation::Call {
                signature, args, ..
            } = &instruction.operation
            {
                let plan = abi.plan_call_from(
                    function,
                    signature,
                    &argument_types(args, &result.types),
                    &signature.param_attributes,
                )?;
                if let Some(storage) = plan.storage.filter(|s| s.explicit_param.is_none()) {
                    if storage.alignment > 16 {
                        return Err(error_diagnostic(
                            "over-aligned implicit result storage requires extended frame lowering",
                        ));
                    }
                    result.frame = align(
                        result
                            .frame
                            .checked_add(i64::try_from(storage.size).map_err(|_| {
                                error_diagnostic("implicit return storage extent overflow")
                            })?)
                            .ok_or_else(|| error_diagnostic("implicit return frame overflow"))?,
                        storage.alignment.max(1) as i64,
                    )?;
                    result
                        .call_return_storage
                        .insert(instruction.result.unwrap().id, -result.frame);
                }
            }
        }
        let max_phi = function
            .blocks
            .iter()
            .map(|b| {
                b.instructions
                    .iter()
                    .filter(|i| matches!(i.operation, Operation::Phi { .. }))
                    .try_fold(0usize, |count, i| {
                        count.checked_add(result.value_chunks(i.result.unwrap().ty).len())
                    })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| error_diagnostic("phi spill extent overflow"))?
            .into_iter()
            .max()
            .unwrap_or(0);
        for _ in 0..max_phi {
            result.frame = result
                .frame
                .checked_add(8)
                .ok_or_else(|| error_diagnostic("phi frame overflow"))?;
            result.phi_slots.push(-result.frame);
        }
        if function.signature.variadic && target != Target::Riscv64UnknownNone {
            let bytes = if target == Target::X86_64UnknownNone {
                176
            } else {
                192
            };
            result.frame = align(
                result
                    .frame
                    .checked_add(bytes)
                    .ok_or_else(|| error_diagnostic("variadic register save area overflow"))?,
                16,
            )?;
            result.variadic_save = Some(-result.frame);
        }
        if module
            .types
            .iter()
            .any(|ty| matches!(ty, Type::Float { bits: 80 }))
        {
            result.frame = align(
                result
                    .frame
                    .checked_add(16)
                    .ok_or_else(|| error_diagnostic("floating scratch extent overflow"))?,
                16,
            )?;
            result.floating_scratch = -result.frame;
        }
        result.frame = align(result.frame, 16)?;
        Ok(result)
    }

    fn nonlocal_frame_proof(&self) -> Result<Option<FunctionFrameProof>, Diagnostic> {
        let exposed = self.function.control_effects.returns_twice
            || self
                .function
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .any(|instruction| {
                    matches!(&instruction.operation, Operation::Call { callee, control_effects, .. }
                    if self.module.effective_returns_twice(callee, *control_effects))
                });
        if !exposed {
            return Ok(None);
        }
        // These are physical restrictions of this realization, in addition to
        // the independent native verifier's original source-effect checks.
        if self.function.signature.abi != "c"
            || self.exception_tables.is_some()
            || self.abi_plan.stack_alignment > 16
        {
            return Err(error_diagnostic("nonlocal fixed-frame realization requires the ordinary C ABI without EH or extended stack alignment"));
        }
        let mut regions = Vec::new();
        for (&value, &offset) in &self.slots {
            let ty = self.types[&value];
            let parts = self.value_chunks(ty);
            let bytes = u64::try_from(parts.len().max(1))
                .ok()
                .and_then(|n| n.checked_mul(8))
                .ok_or_else(|| error_diagnostic("nonlocal SSA spill extent overflow"))?;
            let mut chunks = Vec::new();
            for (leaf, bit) in parts {
                let field = self.leaf_layouts[&ty][leaf].0;
                let chunk_offset = offset
                    .checked_add(self.leaf_spill_offsets[&ty][leaf])
                    .and_then(|n| n.checked_add(i64::try_from(bit / 8).ok()?))
                    .ok_or_else(|| error_diagnostic("nonlocal SSA spill offset overflow"))?;
                chunks.push(SpillChunk {
                    leaf,
                    bit_offset: bit,
                    value_bits: (leaf_bits(self.module, field)? - bit).min(64) as u16,
                    offset_from_fp: chunk_offset,
                    storage_bytes: 8,
                });
            }
            regions.push(FrameRegion {
                role: "ssa_spill".into(),
                value: Some(value),
                ty: Some(ty),
                offset_from_fp: offset,
                bytes,
                alignment: 8,
                chunks,
            });
        }
        for block in &self.function.blocks {
            for instruction in &block.instructions {
                if let Operation::Alloca { size, alignment } = instruction.operation {
                    let value = instruction
                        .result
                        .ok_or_else(|| error_diagnostic("nonlocal allocation result missing"))?;
                    let offset = *self
                        .allocations
                        .get(&value.id)
                        .ok_or_else(|| error_diagnostic("nonlocal fixed allocation missing"))?;
                    regions.push(FrameRegion {
                        role: "fixed_original_alloca".into(),
                        value: Some(value.id),
                        ty: Some(value.ty),
                        offset_from_fp: offset,
                        bytes: size,
                        alignment: alignment.max(1),
                        chunks: Vec::new(),
                    });
                }
            }
        }
        // Use the exact plan used to reserve each implicit result object. Do
        // not confuse the object's memory bytes with the result's SSA spills.
        let mut result_storage = |signature: &Signature,
                                  args: &[Operand],
                                  value: Option<Value>|
         -> Result<(), Diagnostic> {
            let plan = self.abi.plan_call_from(
                self.function,
                signature,
                &argument_types(args, &self.types),
                &signature.param_attributes,
            )?;
            if let Some(storage) = plan
                .storage
                .as_ref()
                .filter(|storage| storage.explicit_param.is_none())
            {
                let value =
                    value.ok_or_else(|| error_diagnostic("nonlocal implicit result missing"))?;
                let offset = *self
                    .call_return_storage
                    .get(&value.id)
                    .ok_or_else(|| error_diagnostic("nonlocal actual result storage missing"))?;
                regions.push(FrameRegion {
                    role: "implicit_call_result".into(),
                    value: Some(value.id),
                    ty: Some(storage.ty),
                    offset_from_fp: offset,
                    bytes: storage.size,
                    alignment: storage.alignment.max(1),
                    chunks: Vec::new(),
                });
            }
            Ok(())
        };
        for block in &self.function.blocks {
            for instruction in &block.instructions {
                if let Operation::Call {
                    signature, args, ..
                } = &instruction.operation
                {
                    result_storage(signature, args, instruction.result)?;
                }
            }
            if let Terminator::Invoke {
                signature,
                args,
                result,
                ..
            } = &block.terminator
            {
                result_storage(signature, args, *result)?;
            }
        }
        if regions
            .iter()
            .filter(|region| region.role == "implicit_call_result")
            .count()
            != self.call_return_storage.len()
        {
            return Err(error_diagnostic(
                "nonlocal result storage membership differs from emitter layout",
            ));
        }
        if let Some(offset) = self.return_pointer {
            regions.push(FrameRegion {
                role: "hidden_result_pointer".into(),
                value: None,
                ty: None,
                offset_from_fp: offset,
                bytes: 8,
                alignment: 8,
                chunks: Vec::new(),
            });
        }
        for &offset in &self.phi_slots {
            regions.push(FrameRegion {
                role: "phi_parallel_copy".into(),
                value: None,
                ty: None,
                offset_from_fp: offset,
                bytes: 8,
                alignment: 8,
                chunks: Vec::new(),
            });
        }
        if let Some(offset) = self.variadic_save {
            regions.push(FrameRegion {
                role: "variadic_register_save".into(),
                value: None,
                ty: None,
                offset_from_fp: offset,
                bytes: if self.target == Target::X86_64UnknownNone {
                    176
                } else {
                    192
                },
                alignment: 16,
                chunks: Vec::new(),
            });
        }
        if self.floating_scratch != 0 {
            regions.push(FrameRegion {
                role: "x87_bit_pattern_bridge".into(),
                value: None,
                ty: None,
                offset_from_fp: self.floating_scratch,
                bytes: 16,
                alignment: 16,
                chunks: Vec::new(),
            });
        }
        let (fp, sp, entry_sp, saved): (&str, &str, i64, Vec<(&str, i64)>) = match self.target {
            Target::X86_64UnknownNone => ("rbp", "rsp", 8, vec![("rbp", 0), ("rip", 8)]),
            Target::Aarch64UnknownNone => ("x29", "sp", 16, vec![("x29", 0), ("x30", 8)]),
            Target::Riscv64UnknownNone => (
                "s0",
                "sp",
                self.incoming_stack_base(),
                vec![("s0", 0), ("ra", 8)],
            ),
        };
        let mut saved_frame_registers: Vec<_> = saved
            .into_iter()
            .map(|(register, offset)| SavedFrameRegister {
                register: register.into(),
                offset_from_fp: offset,
                bytes: 8,
            })
            .collect();
        if self.function.signature.variadic && self.target == Target::Riscv64UnknownNone {
            for (index, register) in ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
                .into_iter()
                .enumerate()
            {
                saved_frame_registers.push(SavedFrameRegister {
                    register: register.into(),
                    offset_from_fp: 16 + index as i64 * 8,
                    bytes: 8,
                });
            }
        }
        let proof = FunctionFrameProof { function_index: self.index, function: self.function.name.clone(),
            declaration_effects: self.function.control_effects, signature: self.function.signature.clone(),
            source_abi: native_nonlocal::snapshot(&self.function.source_abi)?,
            entry_abi_plan: native_nonlocal::snapshot(&self.abi_plan)?, frame_pointer: fp.into(),
            stack_pointer: sp.into(), entry_sp_from_fp: entry_sp,
            incoming_stack_base: self.incoming_stack_base(), fixed_frame_bytes: self.frame,
            steady_sp_from_fp: -self.frame, stack_alignment: 16, saved_frame_registers, regions,
            call_sites: Vec::new(),
            state_strategy: "all SSA chunks, original mutable allocas, implicit results and PHI scratch use distinct fixed FP-relative storage; every return captures results after the resume label before restoring the outgoing area".into() };
        proof.validate_regions()?;
        Ok(Some(proof))
    }

    fn reg(&self, number: usize) -> &'static str {
        match self.target {
            Target::X86_64UnknownNone => ["rax", "rcx", "rdx"][number],
            Target::Aarch64UnknownNone => ["x9", "x10", "x11"][number],
            Target::Riscv64UnknownNone => ["t0", "t1", "t2"][number],
        }
    }
    fn block_label(&self, block: BlockId) -> String {
        native_block_label(self.label_prefix, self.index, block)
    }
    fn label(&mut self) -> String {
        let n = self.label_counter;
        self.label_counter += 1;
        format!("{}{}_s{}", self.label_prefix, self.index, n)
    }
    fn ty(&self, value: &Operand) -> TypeId {
        match value {
            Operand::Value { id } => self.types[id],
            Operand::Float { ty, .. }
            | Operand::Int { ty, .. }
            | Operand::PointerBits { ty, .. }
            | Operand::PointerToInteger { ty, .. }
            | Operand::Null { ty }
            | Operand::Symbol { ty, .. }
            | Operand::SymbolOffset { ty, .. }
            | Operand::BlockAddress { ty, .. }
            | Operand::Aggregate { ty, .. }
            | Operand::AggregateZero { ty }
            | Operand::Undef { ty }
            | Operand::Poison { ty } => *ty,
        }
    }
    /// The bit pattern of an integer constant operand, truncated to `width`,
    /// or `None` when the operand is not a constant known here.
    fn constant_bits(&self, operand: &Operand, width: u16) -> Option<u64> {
        let Operand::Int { bits, .. } = operand else {
            return None;
        };
        let value = bits.parse::<u128>().ok()?;
        let mask = if width >= 64 {
            u64::MAX as u128
        } else {
            (1u128 << width) - 1
        };
        Some((value & mask) as u64)
    }
    fn bits(&self, operand: &Operand) -> u16 {
        scalar_bits(self.module, self.ty(operand)).unwrap()
    }
    fn immediate(&self, out: &mut String, reg: usize, value: u64) {
        let r = self.reg(reg);
        match self.target {
            Target::X86_64UnknownNone => writeln!(out, "  mov {r}, {value}").unwrap(),
            Target::Aarch64UnknownNone => {
                writeln!(out, "  movz {r}, #{}", value & 65535).unwrap();
                for shift in [16, 32, 48] {
                    let part = (value >> shift) & 65535;
                    if part != 0 {
                        writeln!(out, "  movk {r}, #{part}, lsl #{shift}").unwrap();
                    }
                }
            }
            Target::Riscv64UnknownNone => writeln!(out, "  li {r}, {value}").unwrap(),
        }
    }
    fn mov(&self, out: &mut String, dst: &str, src: &str) {
        writeln!(
            out,
            "  {} {dst}, {src}",
            if self.target == Target::Riscv64UnknownNone {
                "mv"
            } else {
                "mov"
            }
        )
        .unwrap();
    }
    fn stack_address(&self, out: &mut String, offset: i64) {
        match self.target {
            Target::X86_64UnknownNone if i32::try_from(offset).is_ok() => {
                writeln!(out, "  lea r11, [rbp + {offset}]").unwrap();
            }
            Target::X86_64UnknownNone => {
                writeln!(out, "  mov r11, {offset}\n  add r11, rbp").unwrap()
            }
            Target::Aarch64UnknownNone if (-4095..=4095).contains(&offset) => {
                let operation = if offset < 0 { "sub" } else { "add" };
                writeln!(out, "  {operation} x17, x29, #{}", offset.unsigned_abs()).unwrap();
            }
            Target::Aarch64UnknownNone => {
                arm_immediate(out, "x17", offset as u64);
                out.push_str("  add x17, x29, x17\n");
            }
            Target::Riscv64UnknownNone if (-2048..=2047).contains(&offset) => {
                writeln!(out, "  addi ra, s0, {offset}").unwrap();
            }
            Target::Riscv64UnknownNone => {
                writeln!(out, "  li ra, {offset}\n  add ra, s0, ra").unwrap();
            }
        }
    }
    fn stack_load(&self, out: &mut String, reg: usize, offset: i64) {
        let r = self.reg(reg);
        // Loads/stores promise only their value or memory result. Callers that
        // need the address scratch explicitly use stack_address instead. The
        // direct forms do not clobber any additional register or condition code.
        match self.target {
            Target::X86_64UnknownNone if i32::try_from(offset).is_ok() => {
                writeln!(out, "  mov {r}, qword ptr [rbp + {offset}]").unwrap();
                return;
            }
            Target::Aarch64UnknownNone if (-256..=255).contains(&offset) => {
                writeln!(out, "  ldur {r}, [x29, #{offset}]").unwrap();
                return;
            }
            Target::Aarch64UnknownNone if (0..=32760).contains(&offset) && offset % 8 == 0 => {
                writeln!(out, "  ldr {r}, [x29, #{offset}]").unwrap();
                return;
            }
            Target::Riscv64UnknownNone if (-2048..=2047).contains(&offset) => {
                writeln!(out, "  ld {r}, {offset}(s0)").unwrap();
                return;
            }
            _ => {}
        }
        self.stack_address(out, offset);
        match self.target {
            Target::X86_64UnknownNone => writeln!(out, "  mov {r}, qword ptr [r11]").unwrap(),
            Target::Aarch64UnknownNone => writeln!(out, "  ldr {r}, [x17]").unwrap(),
            Target::Riscv64UnknownNone => writeln!(out, "  ld {r}, 0(ra)").unwrap(),
        }
    }
    fn stack_store(&self, out: &mut String, reg: usize, offset: i64) {
        let r = self.reg(reg);
        match self.target {
            Target::X86_64UnknownNone if i32::try_from(offset).is_ok() => {
                writeln!(out, "  mov qword ptr [rbp + {offset}], {r}").unwrap();
                return;
            }
            Target::Aarch64UnknownNone if (-256..=255).contains(&offset) => {
                writeln!(out, "  stur {r}, [x29, #{offset}]").unwrap();
                return;
            }
            Target::Aarch64UnknownNone if (0..=32760).contains(&offset) && offset % 8 == 0 => {
                writeln!(out, "  str {r}, [x29, #{offset}]").unwrap();
                return;
            }
            Target::Riscv64UnknownNone if (-2048..=2047).contains(&offset) => {
                writeln!(out, "  sd {r}, {offset}(s0)").unwrap();
                return;
            }
            _ => {}
        }
        self.stack_address(out, offset);
        match self.target {
            Target::X86_64UnknownNone => writeln!(out, "  mov qword ptr [r11], {r}").unwrap(),
            Target::Aarch64UnknownNone => writeln!(out, "  str {r}, [x17]").unwrap(),
            Target::Riscv64UnknownNone => writeln!(out, "  sd {r}, 0(ra)").unwrap(),
        }
    }
    fn operand(&self, out: &mut String, reg: usize, value: &Operand) {
        self.operand_leaf(out, reg, value, 0);
    }

    fn operand_leaf(&self, out: &mut String, reg: usize, value: &Operand, leaf: usize) {
        self.operand_chunk(out, reg, value, leaf, 0);
    }
    // Preserve the scalar/ABI helper interface; packed vector offsets are u64.
    fn operand_chunk(
        &self,
        out: &mut String,
        reg: usize,
        value: &Operand,
        leaf: usize,
        bit_offset: u16,
    ) {
        self.operand_packed_chunk(out, reg, value, leaf, u64::from(bit_offset));
    }

    fn operand_packed_chunk(
        &self,
        out: &mut String,
        reg: usize,
        mut value: &Operand,
        mut leaf: usize,
        bit_offset: u64,
    ) {
        // Constants retain their nested source shape. Descend iteratively so
        // aggregate nesting does not consume the compiler's native call stack.
        while let Operand::Aggregate { ty, elements } = value {
            if matches!(self.module.types[*ty], Type::Vector { .. }) {
                self.vector_constant_chunk(out, reg, *ty, elements, bit_offset);
                return;
            }
            let mut selected = None;
            for element in elements {
                let count = self.leaf_layouts[&self.ty(element)].len();
                if leaf < count {
                    selected = Some(element);
                    break;
                }
                leaf -= count;
            }
            value = selected.expect("verified aggregate constant leaf");
        }
        match value {
            Operand::Value { id } => self.stack_load(
                out,
                reg,
                self.slots[id]
                    + self.leaf_spill_offsets[&self.types[id]][leaf]
                    + i64::try_from(bit_offset / 8).expect("audited packed spill offset"),
            ),
            Operand::Float { bits, .. } => self.immediate(
                out,
                reg,
                (bits.parse::<u128>().unwrap() >> bit_offset) as u64,
            ),
            Operand::Aggregate { .. } => unreachable!("aggregate descent completed"),
            Operand::Int { bits, .. } | Operand::PointerBits { bits, .. } => {
                self.immediate(
                    out,
                    reg,
                    (bits.parse::<u128>().unwrap() >> bit_offset) as u64,
                );
            }
            Operand::Null { .. }
            | Operand::AggregateZero { .. }
            | Operand::Undef { .. }
            | Operand::Poison { .. } => self.immediate(out, reg, 0),
            Operand::PointerToInteger { ty, pointer } => {
                if bit_offset >= 64 {
                    // AS0 has exactly64 representation bits, including when
                    // bit63 is set. Widening always supplies a zero high word.
                    self.immediate(out, reg, 0);
                } else {
                    self.operand(out, reg, pointer);
                    let Type::Int { bits } = self.module.types[*ty] else {
                        unreachable!("verified constant ptrtoint integer result");
                    };
                    self.mask(out, reg, bits.min(64));
                    if bit_offset != 0 {
                        let register = self.reg(reg);
                        match self.target {
                            Target::X86_64UnknownNone => {
                                writeln!(out, "  shr {register}, {bit_offset}").unwrap()
                            }
                            Target::Aarch64UnknownNone => {
                                writeln!(out, "  lsr {register}, {register}, #{bit_offset}")
                                    .unwrap()
                            }
                            Target::Riscv64UnknownNone => {
                                writeln!(out, "  srli {register}, {register}, {bit_offset}")
                                    .unwrap()
                            }
                        }
                    }
                }
            }
            Operand::Symbol { name, .. } => self.symbol_address(out, reg, name, 0),
            Operand::SymbolOffset { name, addend, .. } => {
                self.symbol_address(out, reg, name, *addend)
            }
            Operand::BlockAddress {
                function,
                block,
                addend,
                ..
            } => {
                let label = block_address_label(self.module, self.label_prefix, function, *block);
                self.block_address(out, reg, &label, *addend);
            }
        }
    }

    /// Locate an aggregate subvalue in the scalar-field spill sequence. The
    /// verifier has already checked the original constant index path.
    fn aggregate_span(&self, mut ty: TypeId, indices: &[u64]) -> (usize, usize) {
        let mut first = 0;
        for &index in indices {
            match &self.module.types[ty] {
                Type::Array { element, .. } => {
                    first += index as usize * self.leaf_layouts[element].len();
                    ty = *element;
                }
                Type::Struct { fields, .. } => {
                    first += fields[..index as usize]
                        .iter()
                        .map(|field| self.leaf_layouts[field].len())
                        .sum::<usize>();
                    ty = fields[index as usize];
                }
                _ => unreachable!("verified aggregate index path"),
            }
        }
        (first, self.leaf_layouts[&ty].len())
    }

    fn value_chunks(&self, ty: TypeId) -> Vec<(usize, u64)> {
        self.leaf_layouts[&ty]
            .iter()
            .enumerate()
            .flat_map(|(leaf, (field, _))| {
                let bits = leaf_bits(self.module, *field).expect("audited packed leaf");
                (0..bits).step_by(64).map(move |bit| (leaf, bit))
            })
            .collect()
    }
    fn spill_leaf(&self, out: &mut String, result: Value, leaf: usize) {
        self.spill_chunk(out, result, leaf, 0);
    }
    fn spill_chunk(&self, out: &mut String, result: Value, leaf: usize, bit_offset: u16) {
        self.spill_packed_chunk(out, result, leaf, u64::from(bit_offset));
    }

    fn spill_packed_chunk(&self, out: &mut String, result: Value, leaf: usize, bit_offset: u64) {
        let ty = self.leaf_layouts[&result.ty][leaf].0;
        self.mask(
            out,
            0,
            (leaf_bits(self.module, ty).unwrap() - bit_offset).min(64) as u16,
        );
        self.stack_store(
            out,
            0,
            self.slots[&result.id]
                + self.leaf_spill_offsets[&result.ty][leaf]
                + i64::try_from(bit_offset / 8).expect("audited packed spill offset"),
        );
    }

    /// Reg 1 holds an original memory address, and reg 0 may hold a store
    /// value. Reg 2 is the reserved address-offset scratch.
    fn address_offset(&self, out: &mut String, offset: u64) {
        if offset == 0 {
            return;
        }
        self.immediate(out, 2, offset);
        let address = self.reg(1);
        let scratch = self.reg(2);
        if self.target == Target::X86_64UnknownNone {
            writeln!(out, "  add {address}, {scratch}").unwrap();
        } else {
            writeln!(out, "  add {address}, {address}, {scratch}").unwrap();
        }
    }
    fn symbol_address(&self, out: &mut String, reg: usize, name: &str, addend: i64) {
        let r = self.reg(reg);
        // Undefined-weak references must retain the final linker's real zero
        // or provider address. In particular, an AArch64 unresolved weak ADRP
        // relocation can resolve to the place's page, rather than address 0.
        // Use the target's genuine GOT relocation sequence for this contract;
        // the compiler does not create a fallback object or guess absence.
        let optional = self.external_weak.contains(name);
        match self.target {
            Target::X86_64UnknownNone => {
                if optional {
                    writeln!(out, "  mov {r}, qword ptr [rip + {name}@GOTPCREL]").unwrap();
                } else {
                    writeln!(out, "  lea {r}, [rip + {name}]").unwrap();
                }
                if addend != 0 {
                    writeln!(out, "  mov r11, {}\n  add {r}, r11", addend as u64).unwrap();
                }
            }
            Target::Aarch64UnknownNone => {
                if optional {
                    writeln!(
                        out,
                        "  adrp {r}, :got:{name}\n  ldr {r}, [{r}, :got_lo12:{name}]"
                    )
                    .unwrap();
                } else {
                    writeln!(out, "  adrp {r}, {name}\n  add {r}, {r}, :lo12:{name}").unwrap();
                }
                if addend != 0 {
                    arm_immediate(out, "x17", addend as u64);
                    writeln!(out, "  add {r}, {r}, x17").unwrap();
                }
            }
            Target::Riscv64UnknownNone => {
                if optional {
                    writeln!(
                        out,
                        "  .option push\n  .option pic\n  la {r}, {name}\n  .option pop"
                    )
                    .unwrap();
                } else {
                    writeln!(out, "  lla {r}, {name}").unwrap();
                }
                if addend != 0 {
                    writeln!(out, "  li ra, {addend}\n  add {r}, {r}, ra").unwrap();
                }
            }
        }
    }
    /// Code block addresses use full64 relocations even when a function is too
    /// large for a PC-relative reference to its distant target block. Only the
    /// adjacent literal and the branch around it need PC-relative reach. Output
    /// byte offsets provide a unique namespace without mutating operand state.
    fn block_address(&self, out: &mut String, reg: usize, label: &str, addend: i64) {
        let literal = format!("{}{}_a{}", self.label_prefix, self.index, out.len());
        let next = format!("{literal}_after");
        self.jump(out, &next);
        writeln!(
            out,
            "  .balign 8\n{literal}:\n  .quad {label}{addend:+}\n{next}:"
        )
        .unwrap();
        let r = self.reg(reg);
        match self.target {
            Target::X86_64UnknownNone => {
                writeln!(out, "  mov {r}, qword ptr [rip + {literal}]").unwrap();
            }
            Target::Aarch64UnknownNone => {
                writeln!(out, "  ldr {r}, {literal}").unwrap();
            }
            Target::Riscv64UnknownNone => {
                writeln!(out, "  lla ra, {literal}\n  ld {r}, 0(ra)").unwrap();
            }
        }
    }
    fn mask(&self, out: &mut String, reg: usize, bits: u16) {
        if bits == 64 {
            return;
        }
        let r = self.reg(reg);
        match self.target {
            Target::X86_64UnknownNone => {
                if bits == 32 {
                    let r32 = ["eax", "ecx", "edx"][reg];
                    writeln!(out, "  mov {r32}, {r32}").unwrap();
                } else if bits > 32 {
                    // AND r64 has only a sign-extended imm32 encoding. Shifts
                    // clear the upper bits without clobbering another value.
                    writeln!(out, "  shl {r}, {}\n  shr {r}, {}", 64 - bits, 64 - bits).unwrap();
                } else {
                    writeln!(out, "  and {r}, {}", (1u64 << bits) - 1).unwrap();
                }
            }
            Target::Aarch64UnknownNone => writeln!(out, "  ubfx {r}, {r}, #0, #{bits}").unwrap(),
            Target::Riscv64UnknownNone => writeln!(
                out,
                "  slli {r}, {r}, {}\n  srli {r}, {r}, {}",
                64 - bits,
                64 - bits
            )
            .unwrap(),
        }
    }
    fn signed(&self, out: &mut String, reg: usize, bits: u16) {
        if bits == 64 {
            return;
        }
        let r = self.reg(reg);
        match self.target {
            Target::X86_64UnknownNone => {
                writeln!(out, "  shl {r}, {}\n  sar {r}, {}", 64 - bits, 64 - bits).unwrap()
            }
            Target::Aarch64UnknownNone => writeln!(out, "  sbfx {r}, {r}, #0, #{bits}").unwrap(),
            Target::Riscv64UnknownNone => writeln!(
                out,
                "  slli {r}, {r}, {}\n  srai {r}, {r}, {}",
                64 - bits,
                64 - bits
            )
            .unwrap(),
        }
    }

    fn jump(&self, out: &mut String, label: &str) {
        if self.target == Target::Riscv64UnknownNone {
            writeln!(out, "  lla ra, {label}\n  jr ra").unwrap();
            return;
        }
        writeln!(
            out,
            "  {} {label}",
            match self.target {
                Target::X86_64UnknownNone => "jmp",
                Target::Aarch64UnknownNone => "b",
                Target::Riscv64UnknownNone => "j",
            }
        )
        .unwrap();
    }
    /// Indirect edges may cross arbitrarily large PHI-copy stubs. Load a full
    /// address from an adjacent literal instead of imposing a direct-branch
    /// range on those edges. The literal belongs to this function's section
    /// (and COMDAT, if any), and neither path can fall through into its bytes.
    /// Absolute64 code relocations use the existing static ELF profile.
    fn indirect_edge_jump(&mut self, out: &mut String, label: &str) {
        let literal = self.label();
        match self.target {
            Target::X86_64UnknownNone => {
                writeln!(out, "  jmp qword ptr [rip + {literal}]").unwrap();
            }
            Target::Aarch64UnknownNone => {
                writeln!(out, "  ldr x17, {literal}\n  br x17").unwrap();
            }
            Target::Riscv64UnknownNone => {
                writeln!(out, "  lla ra, {literal}\n  ld ra, 0(ra)\n  jr ra").unwrap();
            }
        }
        writeln!(out, "  .balign 8\n{literal}:\n  .quad {label}").unwrap();
    }
    fn zero_jump(&self, out: &mut String, reg: usize, label: &str, zero: bool) {
        let r = self.reg(reg);
        match self.target {
            Target::X86_64UnknownNone => writeln!(
                out,
                "  test {r}, {r}\n  {} {label}",
                if zero { "jz" } else { "jnz" }
            )
            .unwrap(),
            Target::Aarch64UnknownNone => {
                let next = format!("{label}_skip_{}", out.len());
                writeln!(out, "  {} {r}, {next}", if zero { "cbnz" } else { "cbz" }).unwrap();
                self.jump(out, label);
                writeln!(out, "{next}:").unwrap();
            }
            Target::Riscv64UnknownNone => {
                let next = format!("{label}_skip_{}", out.len());
                writeln!(out, "  {} {r}, {next}", if zero { "bnez" } else { "beqz" }).unwrap();
                self.jump(out, label);
                writeln!(out, "{next}:").unwrap();
            }
        }
    }
    fn adjust_stack(&mut self, out: &mut String, size: i64, allocate: bool) {
        if size == 0 {
            return;
        }
        let count = match self.target {
            Target::X86_64UnknownNone => "r11",
            Target::Aarch64UnknownNone => "x17",
            // The return address is already saved in the frame. Reserving ra
            // as address scratch preserves LLVM fastcc's t3-t6 arguments.
            Target::Riscv64UnknownNone => "ra",
        };
        if self.target == Target::Aarch64UnknownNone {
            arm_immediate(out, count, size as u64);
        } else {
            writeln!(
                out,
                "  {} {count}, {size}",
                if self.target == Target::X86_64UnknownNone {
                    "mov"
                } else {
                    "li"
                }
            )
            .unwrap();
        }
        if !allocate {
            if self.target == Target::X86_64UnknownNone {
                writeln!(out, "  add rsp, {count}").unwrap();
            } else {
                writeln!(out, "  add sp, sp, {count}").unwrap();
            }
            return;
        }
        // Preserve incoming argument registers and touch every intervening page.
        let again = self.label();
        let tail = self.label();
        let done = self.label();
        writeln!(out, "{again}:").unwrap();
        match self.target {
            Target::X86_64UnknownNone => writeln!(out, "  cmp r11, 4096\n  jb {tail}\n  sub rsp, 4096\n  mov byte ptr [rsp], 0\n  sub r11, 4096\n  jmp {again}\n{tail}:\n  sub rsp, r11\n  test r11, r11\n  jz {done}\n  mov byte ptr [rsp], 0\n{done}:").unwrap(),
            Target::Aarch64UnknownNone => writeln!(out, "  cmp x17, #1, lsl #12\n  b.lo {tail}\n  sub sp, sp, #1, lsl #12\n  strb wzr, [sp]\n  sub x17, x17, #1, lsl #12\n  b {again}\n{tail}:\n  sub sp, sp, x17\n  cbz x17, {done}\n  strb wzr, [sp]\n{done}:").unwrap(),
            Target::Riscv64UnknownNone => writeln!(out, "  li t2, 4096\n  bltu ra, t2, {tail}\n  sub sp, sp, t2\n  sb zero, 0(sp)\n  sub ra, ra, t2\n  j {again}\n{tail}:\n  sub sp, sp, ra\n  beqz ra, {done}\n  sb zero, 0(sp)\n{done}:").unwrap(),
        }
    }

    fn emit(
        mut self,
        out: &mut String,
        mut sites: Option<&mut Vec<NativeAssemblySite>>,
    ) -> Result<Option<FunctionFrameProof>, Diagnostic> {
        // Compute from the final actual allocation/ABI plan before any assembly.
        let mut frame_proof = self.nonlocal_frame_proof()?;
        let prologue_start = out.len();
        emit_section(
            out,
            self.module,
            ".text",
            "ax",
            self.function.comdat.as_deref(),
            &format!("{}function_{}", self.label_prefix, self.index),
        );
        visibility(out, &self.function.name, &self.function.linkage);
        writeln!(
            out,
            ".balign {}\n.type {}, @function\n{}:",
            self.function.alignment.max(4),
            self.function.name,
            self.function.name
        )
        .unwrap();
        out.push_str("  .cfi_startproc\n");
        if let Some(eh) = &self.function.exception_handling {
            let personality = match &eh.personality {
                Operand::Symbol { name, .. }
                | Operand::SymbolOffset {
                    name, addend: 0, ..
                } => name,
                _ => return Err(error_diagnostic("unsupported EH personality relocation")),
            };
            // Full-width absolute references belong to the verified static,
            // nonpreemptive ELF profile, with actual providers required at link.
            writeln!(
                out,
                "  .cfi_personality 0, {personality}\n  .cfi_lsda 0, {}",
                self.lsda_label()
            )
            .unwrap();
        }
        match self.target {
            Target::X86_64UnknownNone => out.push_str("  .cfi_def_cfa rsp, 8\n  .cfi_offset rip, -8\n  .cfi_same_value rbp\n  push rbp\n  .cfi_def_cfa_offset 16\n  .cfi_offset rbp, -16\n  mov rbp, rsp\n  .cfi_def_cfa_register rbp\n"),
            Target::Aarch64UnknownNone => {
                out.push_str("  .cfi_def_cfa sp, 0\n  .cfi_same_value x29\n  .cfi_same_value x30\n  stp x29, x30, [sp, #-16]!\n  .cfi_def_cfa_offset 16\n  .cfi_offset x29, -16\n  .cfi_offset x30, -8\n  mov x29, sp\n  .cfi_def_cfa_register x29\n")
            }
            Target::Riscv64UnknownNone => {
                let header = self.incoming_stack_base();
                writeln!(out, "  .cfi_def_cfa sp, 0\n  .cfi_same_value s0\n  .cfi_same_value ra\n  addi sp, sp, -{header}\n  .cfi_def_cfa_offset {header}\n  sd ra, 8(sp)\n  .cfi_offset ra, {}\n  sd s0, 0(sp)\n  .cfi_offset s0, -{header}\n  mv s0, sp\n  .cfi_def_cfa_register s0", 8-header).unwrap();
            }
        }
        self.adjust_stack(out, self.frame, true);
        self.save_variadic_registers(out);
        if let Some(pointer) = self.return_pointer {
            self.incoming(
                out,
                self.abi_plan.storage.as_ref().unwrap().pointer_location,
            )?;
            self.stack_store(out, 0, pointer);
        }
        for part in &self.abi_plan.args {
            let param = self.function.params[part.param.unwrap()];
            self.capture_abi_part(out, part, param)?;
        }
        self.jump(out, &self.block_label(self.function.entry.unwrap()));
        self.map_site(
            &mut sites,
            NativeAssemblySiteKind::FunctionPrologue,
            None,
            None,
            prologue_start,
            out.len(),
        );
        for block in &self.function.blocks {
            let label_start = out.len();
            writeln!(out, "{}:", self.block_label(block.id)).unwrap();
            self.map_site(
                &mut sites,
                NativeAssemblySiteKind::BlockLabel,
                Some(block.id),
                None,
                label_start,
                out.len(),
            );
            for (index, instruction) in block.instructions.iter().enumerate() {
                let instruction_start = out.len();
                self.instruction(out, instruction, block.id, index)?;
                self.map_site(
                    &mut sites,
                    NativeAssemblySiteKind::Instruction,
                    Some(block.id),
                    Some(index),
                    instruction_start,
                    out.len(),
                );
            }
            let terminator_start = out.len();
            match &block.terminator {
                Terminator::Invoke {
                    callee,
                    signature,
                    args,
                    result,
                    normal,
                    unwind,
                } => {
                    let landing = self.unwind_label(block.id);
                    let action = self.exception_tables.as_ref().unwrap().action(*unwind)?;
                    self.call(
                        out,
                        callee,
                        signature,
                        args,
                        *result,
                        Some((landing, action)),
                        None,
                    )?;
                    self.phis(out, block.id, *normal);
                    self.jump(out, &self.block_label(*normal));
                }
                Terminator::Resume { value } => {
                    self.operand_leaf(out, 0, value, 0);
                    self.mov(
                        out,
                        match self.target {
                            Target::X86_64UnknownNone => "rdi",
                            Target::Aarch64UnknownNone => "x0",
                            Target::Riscv64UnknownNone => "a0",
                        },
                        self.reg(0),
                    );
                    let start = self.label();
                    let end = self.label();
                    writeln!(
                        out,
                        "{start}:\n  {} _Unwind_Resume\n{end}:",
                        match self.target {
                            Target::X86_64UnknownNone | Target::Riscv64UnknownNone => "call",
                            Target::Aarch64UnknownNone => "bl",
                        }
                    )
                    .unwrap();
                    self.call_sites.push(CallSite {
                        start,
                        end,
                        landing: None,
                        action: 0,
                    });
                    out.push_str(match self.target {
                        Target::X86_64UnknownNone => "  ud2\n",
                        Target::Aarch64UnknownNone => "  brk #0\n",
                        Target::Riscv64UnknownNone => "  unimp\n",
                    });
                }
                Terminator::Jump { target } => {
                    self.phis(out, block.id, *target);
                    self.jump(out, &self.block_label(*target));
                }
                Terminator::IndirectBranch {
                    address,
                    destinations,
                } => {
                    self.operand(out, 0, address);
                    // Select an edge before running any PHI copies: copies may
                    // overwrite the address value or registers used to compare
                    // it. Keep duplicate destinations in their original order.
                    let edges: Vec<_> = destinations
                        .iter()
                        .map(|&destination| (destination, self.label()))
                        .collect();
                    for (destination, edge) in &edges {
                        let next = self.label();
                        self.block_address(out, 1, &self.block_label(*destination), 0);
                        // The conditional only skips an unconditional jump,
                        // independent of the size of later PHI-copy stubs.
                        match self.target {
                            Target::X86_64UnknownNone => {
                                writeln!(out, "  cmp rax, rcx\n  jne {next}").unwrap();
                            }
                            Target::Aarch64UnknownNone => {
                                writeln!(out, "  cmp x9, x10\n  b.ne {next}").unwrap();
                            }
                            Target::Riscv64UnknownNone => {
                                writeln!(out, "  bne t0, t1, {next}").unwrap();
                            }
                        }
                        self.indirect_edge_jump(out, edge);
                        writeln!(out, "{next}:").unwrap();
                    }
                    // LLVM indirectbr is undefined unless the recovered code
                    // address names one of its listed destinations. An empty
                    // destination list therefore has no defined outgoing edge.
                    out.push_str(match self.target {
                        Target::X86_64UnknownNone => "  ud2\n",
                        Target::Aarch64UnknownNone => "  brk #0\n",
                        Target::Riscv64UnknownNone => "  unimp\n",
                    });
                    for (destination, edge) in edges {
                        writeln!(out, "{edge}:").unwrap();
                        self.phis(out, block.id, destination);
                        self.indirect_edge_jump(out, &self.block_label(destination));
                    }
                }
                Terminator::Branch {
                    condition,
                    on_true,
                    on_false,
                } => {
                    self.operand(out, 0, condition);
                    let false_label = self.label();
                    self.zero_jump(out, 0, &false_label, true);
                    self.phis(out, block.id, *on_true);
                    self.jump(out, &self.block_label(*on_true));
                    writeln!(out, "{false_label}:").unwrap();
                    self.phis(out, block.id, *on_false);
                    self.jump(out, &self.block_label(*on_false));
                }
                Terminator::Switch {
                    condition,
                    default,
                    cases,
                } => {
                    self.operand(out, 0, condition);
                    for case in cases {
                        let matched = self.label();
                        let next = self.label();
                        if self.is_i128(condition) {
                            self.wide_inputs(out, condition, &case.value);
                            self.wide_compare(out, IntPredicate::Eq);
                            self.zero_jump(out, 0, &matched, false);
                        } else {
                            self.operand(out, 1, &case.value);
                            match self.target {
                                Target::X86_64UnknownNone => {
                                    writeln!(out, "  cmp rax, rcx\n  je {matched}").unwrap()
                                }
                                Target::Aarch64UnknownNone => {
                                    writeln!(out, "  cmp x9, x10\n  b.eq {matched}").unwrap()
                                }
                                Target::Riscv64UnknownNone => {
                                    writeln!(out, "  beq t0, t1, {matched}").unwrap()
                                }
                            }
                        }
                        // Keep conditional reach independent of the edge-copy size.
                        self.jump(out, &next);
                        writeln!(out, "{matched}:").unwrap();
                        self.phis(out, block.id, case.target);
                        self.jump(out, &self.block_label(case.target));
                        writeln!(out, "{next}:").unwrap();
                    }
                    self.phis(out, block.id, *default);
                    self.jump(out, &self.block_label(*default));
                }
                Terminator::Return { value } => {
                    if let Some(value) = value {
                        // rax is also the x86 value scratch. Install its result
                        // last so later aggregate fields cannot overwrite it.
                        for part in self.abi_plan.results.iter().rev() {
                            if !matches!(part.location, AbiLocation::IndirectResult { .. }) {
                                self.place_abi_part(out, part, value)?;
                                continue;
                            }
                            self.operand_leaf(out, 0, value, part.leaf);
                            self.extend_abi_part(out, part)?;
                            match part.location {
                                AbiLocation::Register(reg) => self.mov(out, reg, self.reg(0)),
                                AbiLocation::IndirectResult { offset } => {
                                    self.stack_load(out, 1, self.return_pointer.unwrap());
                                    self.address_offset(out, offset);
                                    let alignment =
                                        self.abi_plan.storage.as_ref().unwrap().alignment;
                                    self.store(
                                        out,
                                        u64::from(scalar_bits(self.module, part.ty)?.div_ceil(8)),
                                        offset_alignment(alignment, offset),
                                    );
                                }
                                AbiLocation::Stack { .. } => {
                                    unreachable!("verified result placement")
                                }
                            }
                        }
                    }
                    if let Some(storage) = &self.abi_plan.storage {
                        if let Some(reg) = storage.pointer_return {
                            let offset = storage.explicit_param.map_or_else(
                                || self.return_pointer.unwrap(),
                                |index| self.slots[&self.function.params[index].id],
                            );
                            self.stack_load(out, 0, offset);
                            self.mov(out, reg, self.reg(0));
                        }
                    }
                    out.push_str("  .cfi_remember_state\n");
                    match self.target {
                        Target::X86_64UnknownNone => out.push_str("  mov rsp, rbp\n  .cfi_def_cfa rsp, 16\n  pop rbp\n  .cfi_def_cfa_offset 8\n  .cfi_same_value rbp\n  ret\n"),
                        Target::Aarch64UnknownNone => out.push_str("  mov sp, x29\n  .cfi_def_cfa sp, 16\n  ldp x29, x30, [sp], #16\n  .cfi_def_cfa_offset 0\n  .cfi_same_value x29\n  .cfi_same_value x30\n  ret\n"),
                        Target::Riscv64UnknownNone => {
                            let header = self.incoming_stack_base();
                            writeln!(out, "  mv sp, s0\n  .cfi_def_cfa sp, {header}\n  ld ra, 8(sp)\n  .cfi_same_value ra\n  ld s0, 0(sp)\n  .cfi_same_value s0\n  addi sp, sp, {header}\n  .cfi_def_cfa_offset 0\n  ret").unwrap();
                        }
                    }
                    out.push_str("  .cfi_restore_state\n");
                }
                Terminator::Unreachable => out.push_str(match self.target {
                    Target::X86_64UnknownNone => "  ud2\n",
                    Target::Aarch64UnknownNone => "  brk #0\n",
                    Target::Riscv64UnknownNone => "  unimp\n",
                }),
            }
            // Edge copies implement successor PHIs and belong to the retained
            // predecessor terminator, including conditional/switch edge code.
            self.map_site(
                &mut sites,
                NativeAssemblySiteKind::Terminator,
                Some(block.id),
                None,
                terminator_start,
                out.len(),
            );
        }
        for block in &self.function.blocks {
            if let Terminator::Invoke { unwind, .. } = &block.terminator {
                let landing_start = out.len();
                writeln!(out, "{}:", self.unwind_label(block.id)).unwrap();
                let landing = self
                    .function
                    .blocks
                    .iter()
                    .find(|candidate| candidate.id == *unwind)
                    .unwrap();
                let result = landing
                    .instructions
                    .iter()
                    .find(|instruction| {
                        matches!(instruction.operation, Operation::LandingPad { .. })
                    })
                    .unwrap()
                    .result
                    .unwrap();
                // Save the incoming exception registers before PHI/address
                // scratch can overwrite them. Each invoke retains its own
                // predecessor identity even when it shares a landing block.
                match self.target {
                    Target::X86_64UnknownNone => {
                        self.spill_leaf(out, result, 0);
                        self.mov(out, "rax", "rdx");
                    }
                    Target::Aarch64UnknownNone => {
                        self.mov(out, "x9", "x0");
                        self.spill_leaf(out, result, 0);
                        self.mov(out, "x9", "x1");
                    }
                    Target::Riscv64UnknownNone => {
                        self.mov(out, "t0", "a0");
                        self.spill_leaf(out, result, 0);
                        self.mov(out, "t0", "a1");
                    }
                }
                self.mask(out, 0, 32);
                self.spill_leaf(out, result, 1);
                // The throw may occur with outgoing stack arguments installed.
                // The fixed frame pointer survives the unwind; discard only
                // that outgoing area before entering the retained source CFG.
                // Reconstruct the address without probing/writing live allocas.
                self.stack_address(out, -self.frame);
                self.mov(
                    out,
                    match self.target {
                        Target::X86_64UnknownNone => "rsp",
                        Target::Aarch64UnknownNone => "sp",
                        Target::Riscv64UnknownNone => "sp",
                    },
                    match self.target {
                        Target::X86_64UnknownNone => "r11",
                        Target::Aarch64UnknownNone => "x17",
                        Target::Riscv64UnknownNone => "ra",
                    },
                );
                self.phis(out, block.id, *unwind);
                self.jump(out, &self.block_label(*unwind));
                self.map_site(
                    &mut sites,
                    NativeAssemblySiteKind::ExceptionLanding,
                    Some(block.id),
                    None,
                    landing_start,
                    out.len(),
                );
            }
        }
        let epilogue_start = out.len();
        out.push_str("  .cfi_endproc\n");
        writeln!(
            out,
            ".size {}, .-{}",
            self.function.name, self.function.name
        )
        .unwrap();
        if self.target == Target::Aarch64UnknownNone {
            out.push_str("  .ltorg\n");
        }
        self.map_site(
            &mut sites,
            NativeAssemblySiteKind::FunctionEpilogue,
            None,
            None,
            epilogue_start,
            out.len(),
        );
        if let Some(tables) = self
            .exception_tables
            .as_ref()
            .filter(|_| self.function.exception_handling.is_some())
        {
            let table_start = out.len();
            emit_section(
                out,
                self.module,
                ".gcc_except_table",
                "a",
                self.function.comdat.as_deref(),
                &format!("{}exception_{}", self.label_prefix, self.index),
            );
            tables.emit(
                out,
                &self.function.name,
                &self.lsda_label(),
                &self.call_sites,
            );
            self.map_site(
                &mut sites,
                NativeAssemblySiteKind::ExceptionTable,
                None,
                None,
                table_start,
                out.len(),
            );
        }
        if let Some(proof) = &mut frame_proof {
            proof.call_sites = self.nonlocal_calls;
        }
        Ok(frame_proof)
    }

    fn map_site(
        &self,
        sites: &mut Option<&mut Vec<NativeAssemblySite>>,
        kind: NativeAssemblySiteKind,
        block: Option<BlockId>,
        instruction: Option<usize>,
        assembly_start: usize,
        assembly_end: usize,
    ) {
        if let Some(sites) = sites {
            sites.push(NativeAssemblySite {
                function_index: self.index,
                function: self.function.name.clone(),
                block,
                instruction,
                kind,
                assembly_start,
                assembly_end,
            });
        }
    }

    fn lsda_label(&self) -> String {
        format!("{}function_{}_lsda", self.label_prefix, self.index)
    }

    fn unwind_label(&self, block: BlockId) -> String {
        format!(
            "{}function_{}_invoke_{}_unwind",
            self.label_prefix, self.index, block
        )
    }

    fn incoming(&self, out: &mut String, location: AbiLocation) -> Result<(), Diagnostic> {
        match location {
            AbiLocation::Register(reg) => self.mov(out, self.reg(0), reg),
            AbiLocation::Stack { offset } => self.stack_load(
                out,
                0,
                i64::try_from(offset)
                    .ok()
                    .and_then(|offset| offset.checked_add(self.incoming_stack_base()))
                    .ok_or_else(|| error_diagnostic("incoming ABI stack offset overflow"))?,
            ),
            AbiLocation::IndirectResult { .. } => {
                return Err(error_diagnostic(
                    "indirect result is not an argument location",
                ))
            }
        }
        Ok(())
    }
    fn extend_abi_part(&self, out: &mut String, part: &AbiPart) -> Result<(), Diagnostic> {
        let bits = part.value_bits.min(64);
        self.mask(out, 0, bits);
        if part.extension == Extension::Sign {
            self.signed(out, 0, bits);
        }
        if part.location_bits < 64 {
            self.mask(out, 0, part.location_bits);
        }
        Ok(())
    }
    fn phis(&self, out: &mut String, from: BlockId, to: BlockId) {
        let block = self.function.blocks.iter().find(|b| b.id == to).unwrap();
        let phis: Vec<_> = block
            .instructions
            .iter()
            .filter_map(|i| {
                if let Operation::Phi { incoming } = &i.operation {
                    Some((
                        i.result.unwrap(),
                        incoming.iter().find(|e| e.block == from).unwrap(),
                    ))
                } else {
                    None
                }
            })
            .collect();
        let mut temporary = 0;
        for (value, incoming) in &phis {
            for (leaf, bit) in self.value_chunks(value.ty) {
                self.operand_packed_chunk(out, 0, &incoming.value, leaf, bit);
                self.stack_store(out, 0, self.phi_slots[temporary]);
                temporary += 1;
            }
        }
        temporary = 0;
        for (value, _) in &phis {
            for (leaf, bit) in self.value_chunks(value.ty) {
                self.stack_load(out, 0, self.phi_slots[temporary]);
                self.spill_packed_chunk(out, *value, leaf, bit);
                temporary += 1;
            }
        }
    }

    fn instruction(
        &mut self,
        out: &mut String,
        instruction: &Instruction,
        block: BlockId,
        ordinal: usize,
    ) -> Result<(), Diagnostic> {
        if self.vector_instruction(out, instruction)?
            || self.wide_volatile_instruction(out, instruction)?
            || self.floating_instruction(out, instruction)?
            || self.wide_integer_instruction(out, instruction)?
        {
            return Ok(());
        }
        match &instruction.operation {
            Operation::ExtractElement { .. }
            | Operation::InsertElement { .. }
            | Operation::VectorReduceAdd { .. } => unreachable!("fixed vector instruction handled"),
            Operation::FloatBinary { .. }
            | Operation::ConstrainedFloatBinary { .. }
            | Operation::FloatNeg { .. }
            | Operation::FloatAbs { .. }
            | Operation::FCmp { .. } => {
                unreachable!("floating instruction handled")
            }
            Operation::AtomicLoad { .. }
            | Operation::AtomicStore { .. }
            | Operation::AtomicFence { .. }
            | Operation::AtomicRmw { .. }
            | Operation::AtomicCompareExchange { .. } => {
                self.atomic_instruction(out, instruction)?;
                return Ok(());
            }
            Operation::LinuxSyscall {
                number, arguments, ..
            } => {
                // Every input comes from fixed SSA/PHI spills or a constant.
                // Loading through scratch0 cannot clobber any earlier ABI arg.
                let registers: &[&str] = match self.target {
                    Target::X86_64UnknownNone => &["rdi", "rsi", "rdx", "r10", "r8", "r9"],
                    Target::Aarch64UnknownNone => &["x0", "x1", "x2", "x3", "x4", "x5"],
                    Target::Riscv64UnknownNone => &["a0", "a1", "a2", "a3", "a4", "a5"],
                };
                for (argument, register) in arguments.iter().zip(registers) {
                    self.operand(out, 0, argument);
                    match self.target {
                        Target::X86_64UnknownNone => {
                            writeln!(out, "  mov {register}, rax").unwrap()
                        }
                        Target::Aarch64UnknownNone => {
                            writeln!(out, "  mov {register}, x9").unwrap()
                        }
                        Target::Riscv64UnknownNone => writeln!(out, "  mv {register}, t0").unwrap(),
                    }
                }
                self.operand(out, 0, number);
                out.push_str(match self.target {
                    Target::X86_64UnknownNone => "  syscall\n",
                    Target::Aarch64UnknownNone => "  mov x8, x9\n  svc #0\n  mov x9, x0\n",
                    Target::Riscv64UnknownNone => "  mv a7, t0\n  ecall\n  mv t0, a0\n",
                });
            }
            Operation::Trap {} => {
                out.push_str(match self.target {
                    Target::X86_64UnknownNone => "  ud2\n",
                    Target::Aarch64UnknownNone => "  brk #1\n",
                    Target::Riscv64UnknownNone => "  unimp\n",
                });
                return Ok(());
            }
            Operation::Assume { .. } => return Ok(()),
            // Alias promises are unused throughout this nonoptimizing emitter.
            // Preserve the verified scope marker in IR, with no runtime code.
            Operation::NoAliasScopeDecl { .. } => return Ok(()),
            // Fixed, non-reused stack slots preserve defined object-lifetime
            // behavior without using lifetime promises for optimization.
            Operation::Lifetime { .. } => return Ok(()),
            Operation::MemorySet {
                destination,
                value,
                length,
                ..
            } => {
                self.memory_set(out, destination, value, length);
                return Ok(());
            }
            Operation::MemoryCopy {
                destination,
                source,
                length,
                allow_overlap,
                ..
            } => {
                self.memory_copy(out, destination, source, length, *allow_overlap);
                return Ok(());
            }
            Operation::Phi { .. } => return Ok(()),
            Operation::Binary { kind, lhs, rhs, .. } => self.binary(out, *kind, lhs, rhs),
            Operation::IntegerOverflow {
                kind,
                signed,
                lhs,
                rhs,
            } => {
                self.integer_overflow(out, *kind, *signed, lhs, rhs, instruction.result.unwrap());
                return Ok(());
            }
            Operation::IntegerMinMax { kind, lhs, rhs } => {
                self.integer_min_max(out, *kind, lhs, rhs)
            }
            Operation::IntegerPopulationCount { value } => {
                self.integer_population_count(out, value)
            }
            Operation::IntegerCountLeadingZeros { value, .. } => {
                self.integer_count_leading_zeros(out, value)
            }
            Operation::IntegerAbs { value, .. } => self.integer_abs(out, value),
            Operation::ICmp {
                predicate,
                lhs,
                rhs,
            } => self.compare(out, *predicate, lhs, rhs),
            Operation::Cast { kind, value } => {
                self.operand(out, 0, value);
                if *kind == CastOp::SExt {
                    self.signed(out, 0, self.bits(value));
                }
            }
            Operation::Freeze { value } => {
                let result = instruction.result.unwrap();
                for (leaf, bit) in self.value_chunks(result.ty) {
                    self.operand_packed_chunk(out, 0, value, leaf, bit);
                    self.spill_packed_chunk(out, result, leaf, bit);
                }
                return Ok(());
            }
            Operation::ExtractValue { aggregate, indices } => {
                let result = instruction.result.unwrap();
                let (first, _) = self.aggregate_span(self.ty(aggregate), indices);
                for (leaf, bit) in self.value_chunks(result.ty) {
                    self.operand_packed_chunk(out, 0, aggregate, first + leaf, bit);
                    self.spill_packed_chunk(out, result, leaf, bit);
                }
                return Ok(());
            }
            Operation::InsertValue {
                aggregate,
                value,
                indices,
            } => {
                let result = instruction.result.unwrap();
                let (first, count) = self.aggregate_span(self.ty(aggregate), indices);
                for (leaf, bit) in self.value_chunks(result.ty) {
                    if (first..first + count).contains(&leaf) {
                        self.operand_packed_chunk(out, 0, value, leaf - first, bit);
                    } else {
                        self.operand_packed_chunk(out, 0, aggregate, leaf, bit);
                    }
                    self.spill_packed_chunk(out, result, leaf, bit);
                }
                return Ok(());
            }
            Operation::Select {
                condition,
                on_true,
                on_false,
            } => {
                let result = instruction.result.unwrap();
                let aggregate = matches!(
                    self.module.types[result.ty],
                    Type::Array { .. }
                        | Type::Struct { .. }
                        | Type::Float { bits: 80 | 128 }
                        | Type::Int { bits: 128 }
                        | Type::Vector { .. }
                );
                self.operand(out, 0, condition);
                let no = self.label();
                let done = self.label();
                self.zero_jump(out, 0, &no, true);
                if aggregate {
                    for (leaf, bit) in self.value_chunks(result.ty) {
                        self.operand_packed_chunk(out, 0, on_true, leaf, bit);
                        self.spill_packed_chunk(out, result, leaf, bit);
                    }
                } else {
                    self.operand(out, 0, on_true);
                }
                self.jump(out, &done);
                writeln!(out, "{no}:").unwrap();
                if aggregate {
                    for (leaf, bit) in self.value_chunks(result.ty) {
                        self.operand_packed_chunk(out, 0, on_false, leaf, bit);
                        self.spill_packed_chunk(out, result, leaf, bit);
                    }
                } else {
                    self.operand(out, 0, on_false);
                }
                writeln!(out, "{done}:").unwrap();
                if aggregate {
                    return Ok(());
                }
            }
            Operation::Alloca { .. } => {
                self.stack_address(out, self.allocations[&instruction.result.unwrap().id]);
                self.mov(
                    out,
                    self.reg(0),
                    match self.target {
                        Target::X86_64UnknownNone => "r11",
                        Target::Aarch64UnknownNone => "x17",
                        Target::Riscv64UnknownNone => "ra",
                    },
                );
            }
            Operation::ThreadLocalAddress { global } => {
                // All original access models are retained in IR. This direct
                // realization requires the explicitly selected static Linux
                // image profile and its genuine per-thread ABI setup. Linker
                // range failures remain failures, never truncated offsets.
                match self.target {
                    Target::X86_64UnknownNone => {
                        writeln!(
                            out,
                            "  mov rax, qword ptr fs:[0]\n  lea rax, [rax + {global}@TPOFF]"
                        )
                        .unwrap();
                    }
                    Target::Aarch64UnknownNone => {
                        writeln!(out, "  mrs x9, tpidr_el0\n  add x9, x9, :tprel_hi12:{global}\n  add x9, x9, :tprel_lo12_nc:{global}").unwrap();
                    }
                    Target::Riscv64UnknownNone => {
                        writeln!(out, "  .option push\n  .option norvc\n  lui t0, %tprel_hi({global})\n  add t0, t0, tp, %tprel_add({global})\n  addi t0, t0, %tprel_lo({global})\n  .option pop").unwrap();
                    }
                }
            }
            Operation::PtrMask { pointer, mask, .. } => {
                // Verified integral64/64 AS0: retain source provenance in IR;
                // target address bits are the base pointer AND the exact mask.
                self.operand(out, 0, pointer);
                self.operand(out, 1, mask);
                self.simple_binary(out, "and");
            }
            Operation::Gep { base, offset, .. } => {
                self.operand(out, 0, base);
                self.operand(out, 1, offset);
                self.simple_binary(out, "add");
            }
            Operation::Load {
                pointer, alignment, ..
            } => {
                let result = instruction.result.unwrap();
                let ty = result.ty;
                let alignment = if *alignment == 0 {
                    type_alignment(self.module, ty)?
                } else {
                    *alignment
                };
                for (leaf, bit) in self.value_chunks(ty) {
                    let (field, base) = self.leaf_layouts[&ty][leaf];
                    let offset = base + bit / 8;
                    self.operand(out, 1, pointer);
                    self.address_offset(out, offset);
                    self.load(
                        out,
                        (leaf_bits(self.module, field)? - bit).min(64).div_ceil(8),
                        offset_alignment(alignment, offset),
                    );
                    self.spill_packed_chunk(out, result, leaf, bit);
                }
                return Ok(());
            }
            Operation::Store {
                pointer,
                value,
                alignment,
                ..
            } => {
                let ty = self.ty(value);
                let alignment = if *alignment == 0 {
                    type_alignment(self.module, self.ty(value))?
                } else {
                    *alignment
                };
                for (leaf, bit) in self.value_chunks(ty) {
                    let (field, base) = self.leaf_layouts[&ty][leaf];
                    let offset = base + bit / 8;
                    self.operand_packed_chunk(out, 0, value, leaf, bit);
                    self.operand(out, 1, pointer);
                    self.address_offset(out, offset);
                    self.store(
                        out,
                        (leaf_bits(self.module, field)? - bit).min(64).div_ceil(8),
                        offset_alignment(alignment, offset),
                    );
                }
                return Ok(());
            }
            Operation::Call {
                callee,
                signature,
                args,
                control_effects,
            } => {
                self.call(
                    out,
                    callee,
                    signature,
                    args,
                    instruction.result,
                    None,
                    Some((block, ordinal, *control_effects)),
                )?;
                return Ok(());
            }
            Operation::LandingPad { .. } => {
                // The per-invoke landing entry has already saved both leaves.
                return Ok(());
            }
            Operation::EhTypeId { typeinfo } => {
                let index = self.exception_tables.as_ref().unwrap().type_id(typeinfo)?;
                self.immediate(out, 0, index as u64);
            }
        }
        if let Some(result) = instruction.result {
            self.mask(out, 0, scalar_bits(self.module, result.ty)?);
            self.stack_store(out, 0, self.slots[&result.id]);
        }
        Ok(())
    }

    fn memory_set(
        &mut self,
        out: &mut String,
        destination: &Operand,
        value: &Operand,
        length: &Operand,
    ) {
        self.operand(out, 0, destination);
        self.operand(out, 1, value);
        self.operand(out, 2, length);
        let done = self.label();
        let loop_ = self.label();
        self.zero_jump(out, 2, &done, true);
        writeln!(out, "{loop_}:").unwrap();
        match self.target {
            Target::X86_64UnknownNone => {
                out.push_str("  mov byte ptr [rax], cl\n  inc rax\n  dec rdx\n")
            }
            Target::Aarch64UnknownNone => {
                out.push_str("  strb w10, [x9]\n  add x9, x9, #1\n  sub x11, x11, #1\n")
            }
            Target::Riscv64UnknownNone => {
                out.push_str("  sb t1, 0(t0)\n  addi t0, t0, 1\n  addi t2, t2, -1\n")
            }
        }
        self.zero_jump(out, 2, &loop_, false);
        writeln!(out, "{done}:").unwrap();
    }

    fn memory_copy(
        &mut self,
        out: &mut String,
        destination: &Operand,
        source: &Operand,
        length: &Operand,
        allow_overlap: bool,
    ) {
        self.operand(out, 0, destination);
        self.operand(out, 1, source);
        self.operand(out, 2, length);
        let done = self.label();
        let forward = self.label();
        let backward = self.label();
        self.zero_jump(out, 2, &done, true);
        if allow_overlap {
            // Unsigned address comparison chooses a safe direction even for
            // disjoint spans. Indexed backward accesses avoid computing an
            // overflowing one-past-the-end address before the first access.
            match self.target {
                Target::X86_64UnknownNone => {
                    writeln!(out, "  cmp rax, rcx\n  jbe {forward}").unwrap()
                }
                Target::Aarch64UnknownNone => {
                    writeln!(out, "  cmp x9, x10\n  b.ls {forward}").unwrap()
                }
                Target::Riscv64UnknownNone => writeln!(out, "  bgeu t1, t0, {forward}").unwrap(),
            }
            writeln!(out, "{backward}:").unwrap();
            match self.target {
                Target::X86_64UnknownNone => out.push_str("  dec rdx\n  mov r8b, byte ptr [rcx + rdx]\n  mov byte ptr [rax + rdx], r8b\n"),
                Target::Aarch64UnknownNone => out.push_str("  sub x11, x11, #1\n  ldrb w12, [x10, x11]\n  strb w12, [x9, x11]\n"),
                Target::Riscv64UnknownNone => out.push_str("  addi t2, t2, -1\n  add t3, t1, t2\n  lbu t3, 0(t3)\n  add t5, t0, t2\n  sb t3, 0(t5)\n"),
            }
            self.zero_jump(out, 2, &backward, false);
            self.jump(out, &done);
        }
        writeln!(out, "{forward}:").unwrap();
        match self.target {
            Target::X86_64UnknownNone => out.push_str("  mov r8b, byte ptr [rcx]\n  mov byte ptr [rax], r8b\n  inc rax\n  inc rcx\n  dec rdx\n"),
            Target::Aarch64UnknownNone => out.push_str("  ldrb w12, [x10]\n  strb w12, [x9]\n  add x9, x9, #1\n  add x10, x10, #1\n  sub x11, x11, #1\n"),
            Target::Riscv64UnknownNone => out.push_str("  lbu t3, 0(t1)\n  sb t3, 0(t0)\n  addi t0, t0, 1\n  addi t1, t1, 1\n  addi t2, t2, -1\n"),
        }
        self.zero_jump(out, 2, &forward, false);
        writeln!(out, "{done}:").unwrap();
    }

    fn simple_binary(&self, out: &mut String, operation: &str) {
        let a = self.reg(0);
        let b = self.reg(1);
        if self.target == Target::X86_64UnknownNone {
            writeln!(out, "  {operation} {a}, {b}").unwrap();
        } else {
            writeln!(out, "  {operation} {a}, {a}, {b}").unwrap();
        }
    }

    fn integer_population_count(&mut self, out: &mut String, value: &Operand) {
        // Each iteration removes exactly one set bit. RV64GC needs no Zbb,
        // x86-64 needs no POPCNT, and no vector/FP register bank is touched.
        self.operand(out, 0, value);
        let bits = self.bits(value);
        let again = self.label();
        let done = self.label();
        match self.target {
            Target::X86_64UnknownNone => {
                if bits == 32 {
                    out.push_str("  mov eax, eax\n");
                }
                out.push_str("  xor ecx, ecx\n");
                writeln!(out, "{again}:\n  test rax, rax\n  jz {done}\n  mov rdx, rax\n  sub rdx, 1\n  and rax, rdx\n  add rcx, 1\n  jmp {again}\n{done}:\n  mov rax, rcx").unwrap();
            }
            Target::Aarch64UnknownNone => {
                if bits == 32 {
                    out.push_str("  mov w9, w9\n");
                }
                out.push_str("  mov x10, #0\n");
                writeln!(out, "{again}:\n  cbz x9, {done}\n  sub x11, x9, #1\n  and x9, x9, x11\n  add x10, x10, #1\n  b {again}\n{done}:\n  mov x9, x10").unwrap();
            }
            Target::Riscv64UnknownNone => {
                if bits == 32 {
                    out.push_str("  slli t0, t0, 32\n  srli t0, t0, 32\n");
                }
                out.push_str("  li t1, 0\n");
                writeln!(out, "{again}:\n  beqz t0, {done}\n  addi t2, t0, -1\n  and t0, t0, t2\n  addi t1, t1, 1\n  j {again}\n{done}:\n  mv t0, t1").unwrap();
            }
        }
    }

    fn integer_count_leading_zeros(&mut self, out: &mut String, value: &Operand) {
        self.operand(out, 0, value);
        let bits = self.bits(value);
        match self.target {
            Target::X86_64UnknownNone => {
                // BSR has an undefined destination for zero: branch around it.
                let zero = self.label();
                let done = self.label();
                let source = if bits == 32 { "eax" } else { "rax" };
                writeln!(out, "  test {source}, {source}\n  jz {zero}").unwrap();
                if bits == 32 {
                    out.push_str("  bsr eax, eax\n  xor eax, 31\n");
                } else {
                    out.push_str("  bsr rax, rax\n  xor rax, 63\n");
                }
                writeln!(out, "  jmp {done}\n{zero}:\n  mov rax, {bits}\n{done}:").unwrap();
            }
            Target::Aarch64UnknownNone => out.push_str(if bits == 32 {
                "  clz w9, w9\n"
            } else {
                "  clz x9, x9\n"
            }),
            Target::Riscv64UnknownNone => {
                // RV64GC does not imply Zbb. Count exact source-width bits with
                // a bounded owned loop; zero terminates after exactly N steps.
                let again = self.label();
                let done = self.label();
                self.immediate(out, 1, u64::from(bits));
                self.immediate(out, 2, 0);
                writeln!(out, "  li t3, {}", (1u64 << (bits - 1)) as i64).unwrap();
                writeln!(out, "{again}:\n  and t4, t0, t3\n  bnez t4, {done}\n  addi t2, t2, 1\n  beq t2, t1, {done}\n  slli t0, t0, 1\n  j {again}\n{done}:\n  mv t0, t2").unwrap();
            }
        }
    }

    fn integer_abs(&mut self, out: &mut String, value: &Operand) {
        self.operand(out, 0, value);
        self.signed(out, 0, self.bits(value));
        // Unsigned two's-complement magnitude, then normal original-width
        // result masking. INT_MIN never invokes signed host overflow.
        out.push_str(match self.target {
            Target::X86_64UnknownNone => {
                "  mov rcx, rax\n  sar rcx, 63\n  xor rax, rcx\n  sub rax, rcx\n"
            }
            Target::Aarch64UnknownNone => {
                "  asr x10, x9, #63\n  eor x9, x9, x10\n  sub x9, x9, x10\n"
            }
            Target::Riscv64UnknownNone => "  srai t1, t0, 63\n  xor t0, t0, t1\n  sub t0, t0, t1\n",
        });
    }

    fn integer_min_max(
        &mut self,
        out: &mut String,
        kind: IntegerMinMaxKind,
        lhs: &Operand,
        rhs: &Operand,
    ) {
        // Materialize each source input once. A compare followed by Select
        // operand evaluation would choose a second value for undef/poison.
        self.operand(out, 0, lhs);
        self.operand(out, 1, rhs);
        if matches!(kind, IntegerMinMaxKind::Smin | IntegerMinMaxKind::Smax) {
            let bits = self.bits(lhs);
            self.signed(out, 0, bits);
            self.signed(out, 1, bits);
        }
        match self.target {
            Target::X86_64UnknownNone => writeln!(
                out,
                "  cmp rax, rcx\n  cmov{} rax, rcx",
                match kind {
                    IntegerMinMaxKind::Smin => "g",
                    IntegerMinMaxKind::Smax => "l",
                    IntegerMinMaxKind::Umin => "a",
                    IntegerMinMaxKind::Umax => "b",
                }
            )
            .unwrap(),
            Target::Aarch64UnknownNone => writeln!(
                out,
                "  cmp x9, x10\n  csel x9, x9, x10, {}",
                match kind {
                    IntegerMinMaxKind::Smin => "le",
                    IntegerMinMaxKind::Smax => "ge",
                    IntegerMinMaxKind::Umin => "ls",
                    IntegerMinMaxKind::Umax => "hs",
                }
            )
            .unwrap(),
            Target::Riscv64UnknownNone => {
                // Baseline RV64GC has no mandatory Zbb min/max instruction.
                let done = self.label();
                let (branch, a, b) = match kind {
                    IntegerMinMaxKind::Smin => ("bge", "t1", "t0"),
                    IntegerMinMaxKind::Smax => ("bge", "t0", "t1"),
                    IntegerMinMaxKind::Umin => ("bgeu", "t1", "t0"),
                    IntegerMinMaxKind::Umax => ("bgeu", "t0", "t1"),
                };
                writeln!(out, "  {branch} {a}, {b}, {done}\n  mv t0, t1\n{done}:").unwrap();
            }
        }
        // The normal instruction result path masks back to the original iN.
        // This also implements signed i1: true is -1, so smin is OR and smax AND.
    }

    fn integer_overflow(
        &mut self,
        out: &mut String,
        kind: BinaryOp,
        signed: bool,
        lhs: &Operand,
        rhs: &Operand,
        result: Value,
    ) {
        let bits = self.bits(lhs);
        if kind == BinaryOp::Mul {
            self.operand(out, 0, lhs);
            self.operand(out, 1, rhs);
            if signed {
                self.signed(out, 0, bits);
                self.signed(out, 1, bits);
            }
            // Keep the full 128-bit product until representability has been
            // checked. The overflow flag is defined even for 64-bit MIN * -1.
            match self.target {
                Target::X86_64UnknownNone => {
                    writeln!(
                        out,
                        "  {} rcx\n  mov rcx, rax",
                        if signed { "imul" } else { "mul" }
                    )
                    .unwrap();
                }
                Target::Aarch64UnknownNone => {
                    writeln!(
                        out,
                        "  {} x11, x9, x10\n  mul x9, x9, x10\n  mov x10, x9",
                        if signed { "smulh" } else { "umulh" }
                    )
                    .unwrap();
                }
                Target::Riscv64UnknownNone => {
                    writeln!(
                        out,
                        "  {} t2, t0, t1\n  mul t0, t0, t1\n  mv t1, t0",
                        if signed { "mulh" } else { "mulhu" }
                    )
                    .unwrap();
                }
            }
            if signed {
                self.signed(out, 1, bits);
            } else {
                self.mask(out, 1, bits);
            }
            // Reg0 is still the full low half, reg1 the source-width result
            // extended to 64 bits, and reg2 the full high half. Both halves
            // must agree with the extended result for there to be no overflow.
            match (self.target, signed) {
                (Target::X86_64UnknownNone, true) => out.push_str("  mov r8, rcx\n  sar r8, 63\n  cmp rdx, r8\n  setne r8b\n  cmp rax, rcx\n  setne r9b\n  or r8b, r9b\n  movzx r8d, r8b\n"),
                (Target::X86_64UnknownNone, false) => out.push_str("  test rdx, rdx\n  setne r8b\n  cmp rax, rcx\n  setne r9b\n  or r8b, r9b\n  movzx r8d, r8b\n"),
                (Target::Aarch64UnknownNone, true) => out.push_str("  asr x13, x10, #63\n  cmp x11, x13\n  cset x12, ne\n  cmp x9, x10\n  cset x13, ne\n  orr x12, x12, x13\n"),
                (Target::Aarch64UnknownNone, false) => out.push_str("  cmp x11, #0\n  cset x12, ne\n  cmp x9, x10\n  cset x13, ne\n  orr x12, x12, x13\n"),
                (Target::Riscv64UnknownNone, true) => out.push_str("  srai t4, t1, 63\n  xor t3, t2, t4\n  snez t3, t3\n  xor t4, t0, t1\n  snez t4, t4\n  or t3, t3, t4\n"),
                (Target::Riscv64UnknownNone, false) => out.push_str("  snez t3, t2\n  xor t4, t0, t1\n  snez t4, t4\n  or t3, t3, t4\n"),
            }
            self.spill_leaf(out, result, 0);
            self.mov(
                out,
                self.reg(0),
                match self.target {
                    Target::X86_64UnknownNone => "r8",
                    Target::Aarch64UnknownNone => "x12",
                    Target::Riscv64UnknownNone => "t3",
                },
            );
        } else {
            self.binary(out, kind, lhs, rhs);
            self.spill_leaf(out, result, 0);
            self.operand(out, 0, lhs);
            if signed {
                self.operand(out, 1, rhs);
                self.stack_load(out, 2, self.slots[&result.id]);
                // Signed add: (A ^ R) & (B ^ R). Signed subtract:
                // (A ^ R) & (A ^ B). The original sign bit is the flag.
                match (self.target, kind) {
                    (Target::X86_64UnknownNone, BinaryOp::Add) => {
                        out.push_str("  xor rax, rdx\n  xor rcx, rdx\n  and rax, rcx\n")
                    }
                    (Target::X86_64UnknownNone, BinaryOp::Sub) => {
                        out.push_str("  xor rcx, rax\n  xor rax, rdx\n  and rax, rcx\n")
                    }
                    (Target::Aarch64UnknownNone, BinaryOp::Add) => {
                        out.push_str("  eor x9, x9, x11\n  eor x10, x10, x11\n  and x9, x9, x10\n")
                    }
                    (Target::Aarch64UnknownNone, BinaryOp::Sub) => {
                        out.push_str("  eor x10, x10, x9\n  eor x9, x9, x11\n  and x9, x9, x10\n")
                    }
                    (Target::Riscv64UnknownNone, BinaryOp::Add) => {
                        out.push_str("  xor t0, t0, t2\n  xor t1, t1, t2\n  and t0, t0, t1\n")
                    }
                    (Target::Riscv64UnknownNone, BinaryOp::Sub) => {
                        out.push_str("  xor t1, t1, t0\n  xor t0, t0, t2\n  and t0, t0, t1\n")
                    }
                    _ => unreachable!("verified overflow arithmetic"),
                }
                match self.target {
                    Target::X86_64UnknownNone => writeln!(out, "  shr rax, {}", bits - 1).unwrap(),
                    Target::Aarch64UnknownNone => {
                        writeln!(out, "  lsr x9, x9, #{}", bits - 1).unwrap()
                    }
                    Target::Riscv64UnknownNone => {
                        writeln!(out, "  srli t0, t0, {}", bits - 1).unwrap()
                    }
                }
            } else {
                if kind == BinaryOp::Add {
                    self.stack_load(out, 1, self.slots[&result.id]);
                } else {
                    self.operand(out, 1, rhs);
                }
                // Addition overflow iff its modular result is less than A;
                // subtraction overflow iff A is less than B.
                match self.target {
                    Target::X86_64UnknownNone => writeln!(
                        out,
                        "  cmp rax, rcx\n  set{} al\n  movzx eax, al",
                        if kind == BinaryOp::Add { "a" } else { "b" }
                    )
                    .unwrap(),
                    Target::Aarch64UnknownNone => writeln!(
                        out,
                        "  cmp x9, x10\n  cset x9, {}",
                        if kind == BinaryOp::Add { "hi" } else { "lo" }
                    )
                    .unwrap(),
                    Target::Riscv64UnknownNone if kind == BinaryOp::Add => {
                        out.push_str("  sltu t0, t1, t0\n")
                    }
                    Target::Riscv64UnknownNone => out.push_str("  sltu t0, t0, t1\n"),
                }
            }
        }
        self.spill_leaf(out, result, 1);
    }

    fn binary(&mut self, out: &mut String, kind: BinaryOp, lhs: &Operand, rhs: &Operand) {
        self.operand(out, 0, lhs);
        self.operand(out, 1, rhs);
        match kind {
            BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::And
            | BinaryOp::Or
            | BinaryOp::Xor => {
                let op = match kind {
                    BinaryOp::Add => "add",
                    BinaryOp::Sub => "sub",
                    BinaryOp::Mul => {
                        if self.target == Target::X86_64UnknownNone {
                            "imul"
                        } else {
                            "mul"
                        }
                    }
                    BinaryOp::And => "and",
                    BinaryOp::Or => {
                        if self.target == Target::Aarch64UnknownNone {
                            "orr"
                        } else {
                            "or"
                        }
                    }
                    BinaryOp::Xor => {
                        if self.target == Target::Aarch64UnknownNone {
                            "eor"
                        } else {
                            "xor"
                        }
                    }
                    _ => unreachable!(),
                };
                self.simple_binary(out, op);
            }
            BinaryOp::Shl | BinaryOp::LShr | BinaryOp::AShr => {
                if kind == BinaryOp::AShr {
                    self.signed(out, 0, self.bits(lhs));
                }
                let a = self.reg(0);
                let b = self.reg(1);
                let width = self.bits(lhs);
                let mask = width - 1;
                // Over-wide LLVM shifts are poison. Only those counts use the
                // explicit width-1 refinement; legal non-power-of-two shifts
                // must retain their original count.
                let legal_count = (!width.is_power_of_two()).then(|| self.label());
                if let Some(label) = &legal_count {
                    match self.target {
                        Target::X86_64UnknownNone => {
                            writeln!(out, "  cmp rcx, {width}\n  jb {label}").unwrap()
                        }
                        Target::Aarch64UnknownNone => {
                            writeln!(out, "  cmp x10, #{width}\n  b.lo {label}").unwrap()
                        }
                        Target::Riscv64UnknownNone => {
                            writeln!(out, "  li t2, {width}\n  bltu t1, t2, {label}").unwrap()
                        }
                    }
                }
                match self.target {
                    Target::X86_64UnknownNone => writeln!(out, "  and rcx, {mask}").unwrap(),
                    Target::Aarch64UnknownNone => {
                        self.immediate(out, 2, mask as u64);
                        writeln!(out, "  and {b}, {b}, x11").unwrap();
                    }
                    Target::Riscv64UnknownNone => writeln!(out, "  andi {b}, {b}, {mask}").unwrap(),
                }
                if let Some(label) = legal_count {
                    writeln!(out, "{label}:").unwrap();
                }
                match self.target {
                    Target::X86_64UnknownNone => writeln!(
                        out,
                        "  {} rax, cl",
                        match kind {
                            BinaryOp::Shl => "shl",
                            BinaryOp::LShr => "shr",
                            _ => "sar",
                        }
                    )
                    .unwrap(),
                    Target::Aarch64UnknownNone => {
                        writeln!(
                            out,
                            "  {} {a}, {a}, {b}",
                            match kind {
                                BinaryOp::Shl => "lsl",
                                BinaryOp::LShr => "lsr",
                                _ => "asr",
                            }
                        )
                        .unwrap();
                    }
                    Target::Riscv64UnknownNone => writeln!(
                        out,
                        "  {} {a}, {a}, {b}",
                        match kind {
                            BinaryOp::Shl => "sll",
                            BinaryOp::LShr => "srl",
                            _ => "sra",
                        }
                    )
                    .unwrap(),
                }
            }
            BinaryOp::UDiv | BinaryOp::SDiv | BinaryOp::URem | BinaryOp::SRem => {
                // ### division refinements ###
                // only division by zero traps, at every width. signed MIN / -1
                // does not trap: sdiv yields MIN (the wrapped quotient) and
                // srem yields 0. both guards are explicit branches emitted
                // before the divide instruction, so the hardware never sees
                // a zero divisor or MIN / -1 (x86 idiv faults on both) and
                // nothing depends on what an assembler or cpu does there.
                let signed = matches!(kind, BinaryOp::SDiv | BinaryOp::SRem);
                let remainder = matches!(kind, BinaryOp::URem | BinaryOp::SRem);
                let width = self.bits(lhs);
                if signed {
                    self.signed(out, 0, width);
                    self.signed(out, 1, width);
                }
                let trap = self.label();
                let done = self.label();
                let divisor = self.constant_bits(rhs, width);
                let dividend = self.constant_bits(lhs, width);
                // a divisor known to be non-zero needs no zero check.
                if divisor.is_none_or(|bits| bits == 0) {
                    self.zero_jump(out, 1, &trap, true);
                }
                // the MIN / -1 branch is dropped only when the divisor is known
                // not to be -1 or the dividend is known not to be MIN. at i1,
                // MIN and -1 are the same bit pattern.
                let all_ones = if width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                };
                let minimum = 1u64 << (width - 1);
                let may_overflow = signed
                    && divisor.is_none_or(|bits| bits == all_ones)
                    && dividend.is_none_or(|bits| bits == minimum);
                if may_overflow {
                    let normal = self.label();
                    self.immediate(out, 2, 0u64.wrapping_sub(minimum));
                    match self.target {
                        Target::X86_64UnknownNone => writeln!(
                            out,
                            "  cmp rax, rdx\n  jne {normal}\n  cmp rcx, -1\n  jne {normal}"
                        )
                        .unwrap(),
                        Target::Aarch64UnknownNone => writeln!(
                            out,
                            "  cmp x9, x11\n  b.ne {normal}\n  cmn x10, #1\n  b.ne {normal}"
                        )
                        .unwrap(),
                        Target::Riscv64UnknownNone => writeln!(
                            out,
                            "  bne t0, t2, {normal}\n  li t2, -1\n  bne t1, t2, {normal}"
                        )
                        .unwrap(),
                    }
                    // the dividend register already holds MIN, the sdiv result.
                    if remainder {
                        self.immediate(out, 0, 0);
                    }
                    self.jump(out, &done);
                    writeln!(out, "{normal}:").unwrap();
                }
                match self.target {
                    Target::X86_64UnknownNone => {
                        out.push_str(if signed {
                            "  cqo\n  idiv rcx\n"
                        } else {
                            "  xor edx, edx\n  div rcx\n"
                        });
                        if remainder {
                            out.push_str("  mov rax, rdx\n");
                        }
                    }
                    Target::Aarch64UnknownNone => {
                        writeln!(
                            out,
                            "  {} x11, x9, x10",
                            if signed { "sdiv" } else { "udiv" }
                        )
                        .unwrap();
                        if remainder {
                            out.push_str("  msub x9, x11, x10, x9\n");
                        } else {
                            out.push_str("  mov x9, x11\n");
                        }
                    }
                    Target::Riscv64UnknownNone => writeln!(
                        out,
                        "  {} t0, t0, t1",
                        match (signed, remainder) {
                            (true, false) => "div",
                            (false, false) => "divu",
                            (true, true) => "rem",
                            (false, true) => "remu",
                        }
                    )
                    .unwrap(),
                }
                self.jump(out, &done);
                // the same instruction an explicit llvm.trap lowers to.
                writeln!(out, "{trap}:").unwrap();
                out.push_str(match self.target {
                    Target::X86_64UnknownNone => "  ud2\n",
                    Target::Aarch64UnknownNone => "  brk #1\n",
                    Target::Riscv64UnknownNone => "  unimp\n",
                });
                writeln!(out, "{done}:").unwrap();
            }
        }
    }
    fn compare(&self, out: &mut String, predicate: IntPredicate, lhs: &Operand, rhs: &Operand) {
        self.operand(out, 0, lhs);
        self.operand(out, 1, rhs);
        if matches!(
            predicate,
            IntPredicate::Sgt | IntPredicate::Sge | IntPredicate::Slt | IntPredicate::Sle
        ) {
            self.signed(out, 0, self.bits(lhs));
            self.signed(out, 1, self.bits(rhs));
        }
        match self.target {
            Target::X86_64UnknownNone => writeln!(
                out,
                "  cmp rax, rcx\n  set{} al\n  movzx eax, al",
                match predicate {
                    IntPredicate::Eq => "e",
                    IntPredicate::Ne => "ne",
                    IntPredicate::Ugt => "a",
                    IntPredicate::Uge => "ae",
                    IntPredicate::Ult => "b",
                    IntPredicate::Ule => "be",
                    IntPredicate::Sgt => "g",
                    IntPredicate::Sge => "ge",
                    IntPredicate::Slt => "l",
                    IntPredicate::Sle => "le",
                }
            )
            .unwrap(),
            Target::Aarch64UnknownNone => writeln!(
                out,
                "  cmp x9, x10\n  cset x9, {}",
                match predicate {
                    IntPredicate::Eq => "eq",
                    IntPredicate::Ne => "ne",
                    IntPredicate::Ugt => "hi",
                    IntPredicate::Uge => "hs",
                    IntPredicate::Ult => "lo",
                    IntPredicate::Ule => "ls",
                    IntPredicate::Sgt => "gt",
                    IntPredicate::Sge => "ge",
                    IntPredicate::Slt => "lt",
                    IntPredicate::Sle => "le",
                }
            )
            .unwrap(),
            Target::Riscv64UnknownNone => match predicate {
                IntPredicate::Eq | IntPredicate::Ne => writeln!(
                    out,
                    "  xor t0, t0, t1\n  {} t0, t0",
                    if predicate == IntPredicate::Eq {
                        "seqz"
                    } else {
                        "snez"
                    }
                )
                .unwrap(),
                _ => {
                    let signed = matches!(
                        predicate,
                        IntPredicate::Sgt
                            | IntPredicate::Sge
                            | IntPredicate::Slt
                            | IntPredicate::Sle
                    );
                    let reversed = matches!(
                        predicate,
                        IntPredicate::Ugt
                            | IntPredicate::Ule
                            | IntPredicate::Sgt
                            | IntPredicate::Sle
                    );
                    writeln!(
                        out,
                        "  {} t0, {}, {}",
                        if signed { "slt" } else { "sltu" },
                        if reversed { "t1" } else { "t0" },
                        if reversed { "t0" } else { "t1" }
                    )
                    .unwrap();
                    if matches!(
                        predicate,
                        IntPredicate::Uge
                            | IntPredicate::Ule
                            | IntPredicate::Sge
                            | IntPredicate::Sle
                    ) {
                        out.push_str("  xori t0, t0, 1\n");
                    }
                }
            },
        }
    }

    fn load(&self, out: &mut String, bytes: u64, alignment: u64) {
        if !bytes.is_power_of_two()
            || (alignment < bytes && self.target != Target::X86_64UnknownNone)
        {
            self.immediate(out, 0, 0);
            for byte in 0..bytes {
                match self.target {
                    Target::X86_64UnknownNone => {
                        writeln!(
                            out,
                            "  movzx edx, byte ptr [rcx + {byte}]\n  shl rdx, {}\n  or rax, rdx",
                            byte * 8
                        )
                        .unwrap();
                    }
                    Target::Aarch64UnknownNone => {
                        writeln!(
                            out,
                            "  ldrb w11, [x10, #{byte}]\n  orr x9, x9, x11, lsl #{}",
                            byte * 8
                        )
                        .unwrap();
                    }
                    Target::Riscv64UnknownNone => {
                        writeln!(
                            out,
                            "  lbu t2, {byte}(t1)\n  slli t2, t2, {}\n  or t0, t0, t2",
                            byte * 8
                        )
                        .unwrap();
                    }
                }
            }
            return;
        }
        match self.target {
            Target::X86_64UnknownNone => out.push_str(match bytes {
                1 => "  movzx eax, byte ptr [rcx]\n",
                2 => "  movzx eax, word ptr [rcx]\n",
                4 => "  mov eax, dword ptr [rcx]\n",
                8 => "  mov rax, qword ptr [rcx]\n",
                _ => unreachable!(),
            }),
            Target::Aarch64UnknownNone => out.push_str(match bytes {
                1 => "  ldrb w9, [x10]\n",
                2 => "  ldrh w9, [x10]\n",
                4 => "  ldr w9, [x10]\n",
                8 => "  ldr x9, [x10]\n",
                _ => unreachable!(),
            }),
            Target::Riscv64UnknownNone => writeln!(
                out,
                "  {} t0, 0(t1)",
                match bytes {
                    1 => "lbu",
                    2 => "lhu",
                    4 => "lwu",
                    8 => "ld",
                    _ => unreachable!(),
                }
            )
            .unwrap(),
        }
    }
    fn store(&self, out: &mut String, bytes: u64, alignment: u64) {
        if !bytes.is_power_of_two()
            || (alignment < bytes && self.target != Target::X86_64UnknownNone)
        {
            for byte in 0..bytes {
                match self.target {
                    Target::X86_64UnknownNone => writeln!(
                        out,
                        "  mov rdx, rax\n  shr rdx, {}\n  mov byte ptr [rcx + {byte}], dl",
                        byte * 8
                    )
                    .unwrap(),
                    Target::Aarch64UnknownNone => writeln!(
                        out,
                        "  lsr x11, x9, #{}\n  strb w11, [x10, #{byte}]",
                        byte * 8
                    )
                    .unwrap(),
                    Target::Riscv64UnknownNone => {
                        writeln!(out, "  srli t2, t0, {}\n  sb t2, {byte}(t1)", byte * 8).unwrap()
                    }
                }
            }
            return;
        }
        match self.target {
            Target::X86_64UnknownNone => out.push_str(match bytes {
                1 => "  mov byte ptr [rcx], al\n",
                2 => "  mov word ptr [rcx], ax\n",
                4 => "  mov dword ptr [rcx], eax\n",
                8 => "  mov qword ptr [rcx], rax\n",
                _ => unreachable!(),
            }),
            Target::Aarch64UnknownNone => out.push_str(match bytes {
                1 => "  strb w9, [x10]\n",
                2 => "  strh w9, [x10]\n",
                4 => "  str w9, [x10]\n",
                8 => "  str x9, [x10]\n",
                _ => unreachable!(),
            }),
            Target::Riscv64UnknownNone => writeln!(
                out,
                "  {} t0, 0(t1)",
                match bytes {
                    1 => "sb",
                    2 => "sh",
                    4 => "sw",
                    8 => "sd",
                    _ => unreachable!(),
                }
            )
            .unwrap(),
        }
    }

    // ABI operands, exception continuation and source-site proof are distinct
    // call inputs; preserve their existing signature and validation order.
    #[allow(clippy::too_many_arguments)]
    fn call(
        &mut self,
        out: &mut String,
        callee: &Operand,
        signature: &Signature,
        args: &[Operand],
        result: Option<Value>,
        exception_target: Option<(String, u64)>,
        site: Option<(BlockId, usize, ControlEffects)>,
    ) -> Result<(), Diagnostic> {
        if let Operand::Symbol { name, .. } = callee {
            if let Some(intrinsic) = super::native_verify::variadic_intrinsic(name) {
                return self.variadic_intrinsic(out, intrinsic, args);
            }
        }
        let plan = self.abi.plan_call_from(
            self.function,
            signature,
            &argument_types(args, &self.types),
            &signature.param_attributes,
        )?;
        if plan.stack_alignment > 16 {
            return Err(error_diagnostic(
                "extended call stack alignment is unsupported",
            ));
        }
        let stack = align(
            i64::try_from(plan.stack_bytes)
                .map_err(|_| error_diagnostic("call argument extent overflow"))?,
            16,
        )?;
        self.adjust_stack(out, stack, true);
        // Stack args first: writing register args afterward cannot overwrite them.
        for part in &plan.args {
            let AbiLocation::Stack { offset } = part.location else {
                continue;
            };
            let _ = offset;
            self.place_abi_part(out, part, &args[part.param.unwrap()])?;
        }
        // LLVM inserts this storage pointer during target lowering. It is not
        // added to the source signature or represented as a fabricated SSA arg.
        if let Some(storage) = plan.storage.as_ref().filter(|s| s.explicit_param.is_none()) {
            let offset = self.call_return_storage[&result.unwrap().id];
            self.stack_address(out, offset);
            let AbiLocation::Register(reg) = storage.pointer_location else {
                return Err(error_diagnostic(
                    "implicit result pointer requires a register location",
                ));
            };
            self.mov(
                out,
                reg,
                match self.target {
                    Target::X86_64UnknownNone => "r11",
                    Target::Aarch64UnknownNone => "x17",
                    Target::Riscv64UnknownNone => "ra",
                },
            );
        }
        // x86 rcx/rdx are also scratch regs: use only rax while loading args.
        for part in &plan.args {
            let AbiLocation::Register(reg) = part.location else {
                continue;
            };
            let _ = reg;
            self.place_abi_part(out, part, &args[part.param.unwrap()])?;
        }
        let call_start = self
            .function
            .exception_handling
            .is_some()
            .then(|| self.label());
        let actual_call_start;
        match callee {
            Operand::Symbol { name, .. } if !self.external_weak.contains(name) => {
                if signature.variadic && self.target == Target::X86_64UnknownNone {
                    writeln!(
                        out,
                        "  mov eax, {}",
                        plan.variadic.as_ref().unwrap().vector_register_count
                    )
                    .unwrap();
                }
                if let Some(start) = &call_start {
                    writeln!(out, "{start}:").unwrap();
                }
                actual_call_start = out.len();
                writeln!(
                    out,
                    "  {} {name}",
                    match self.target {
                        Target::X86_64UnknownNone => "call",
                        Target::Aarch64UnknownNone => "bl",
                        Target::Riscv64UnknownNone => "call",
                    }
                )
                .unwrap();
            }
            _ => {
                self.operand(out, 0, callee);
                if signature.variadic && self.target == Target::X86_64UnknownNone {
                    // AL carries the vector count; preserve the indirect target
                    // outside RAX before installing that implicit ABI argument.
                    out.push_str("  mov r11, rax\n");
                    writeln!(
                        out,
                        "  mov eax, {}",
                        plan.variadic.as_ref().unwrap().vector_register_count
                    )
                    .unwrap();
                }
                if let Some(start) = &call_start {
                    writeln!(out, "{start}:").unwrap();
                }
                actual_call_start = out.len();
                writeln!(
                    out,
                    "  {} {}",
                    match self.target {
                        Target::X86_64UnknownNone => "call",
                        Target::Aarch64UnknownNone => "blr",
                        Target::Riscv64UnknownNone => "jalr",
                    },
                    if signature.variadic && self.target == Target::X86_64UnknownNone {
                        "r11"
                    } else {
                        self.reg(0)
                    }
                )
                .unwrap();
            }
        }
        // A restored provider resumes here, with the original call's outgoing
        // area still installed. Do not put result capture, SP restoration or
        // any destructive scratch instruction before this physical label.
        if let Some((block, ordinal, effects)) = site {
            if self.module.effective_returns_twice(callee, effects) {
                let Operand::Symbol { name, .. } = callee else {
                    return Err(error_diagnostic(
                        "nonlocal continuation requires a direct original symbol",
                    ));
                };
                let (index, declaration) = self
                    .module
                    .functions
                    .iter()
                    .enumerate()
                    .find(|(_, function)| function.name == *name)
                    .ok_or_else(|| error_diagnostic("nonlocal original declaration missing"))?;
                let call_end = out.len();
                let label = format!(
                    "{}{}_nonlocal_b{}_i{}",
                    self.label_prefix, self.index, block, ordinal
                );
                let continuation_sp = self
                    .frame
                    .checked_add(stack)
                    .and_then(|n| n.checked_neg())
                    .ok_or_else(|| {
                        error_diagnostic("nonlocal continuation stack extent overflow")
                    })?;
                writeln!(out, "{label}:").unwrap();
                let resume_end = out.len();
                let proof = NonlocalCallSiteProof {
                    block,
                    instruction: ordinal,
                    callee: name.clone(),
                    callee_function_index: index,
                    declaration_effects: declaration.control_effects,
                    call_effects: effects,
                    signature: signature.clone(),
                    arguments: native_nonlocal::snapshot(&args)?,
                    result: native_nonlocal::snapshot(&result)?,
                    abi_plan: native_nonlocal::snapshot(&plan)?,
                    outgoing_stack_bytes: stack,
                    continuation_sp_from_fp: continuation_sp,
                    call_assembly_start: actual_call_start,
                    call_assembly_end: call_end,
                    resume_label: label.clone(),
                    resume_assembly_start: call_end,
                    resume_assembly_end: resume_end,
                    result_capture_after_resume: true,
                    stack_restore_after_resume: true,
                };
                self.nonlocal_calls.push(proof);
            }
        }
        if let Some(start) = call_start {
            let end = self.label();
            writeln!(out, "{end}:").unwrap();
            let (landing, action) =
                exception_target.map_or((None, 0), |(label, action)| (Some(label), action));
            self.call_sites.push(CallSite {
                start,
                end,
                landing,
                action,
            });
        }
        if let Some(result) = result {
            // Capture rax first on x86 before using it to spill rdx/rcx.
            // Address scratch is outside every supported return register set.
            for part in &plan.results {
                if !matches!(part.location, AbiLocation::IndirectResult { .. }) {
                    self.capture_abi_part(out, part, result)?;
                    continue;
                }
                match part.location {
                    AbiLocation::Register(reg) => self.mov(out, self.reg(0), reg),
                    AbiLocation::IndirectResult { offset } => {
                        self.stack_address(out, self.call_return_storage[&result.id]);
                        self.mov(
                            out,
                            self.reg(1),
                            match self.target {
                                Target::X86_64UnknownNone => "r11",
                                Target::Aarch64UnknownNone => "x17",
                                Target::Riscv64UnknownNone => "ra",
                            },
                        );
                        self.address_offset(out, offset);
                        let alignment = plan.storage.as_ref().unwrap().alignment;
                        self.load(
                            out,
                            u64::from(scalar_bits(self.module, part.ty)?.div_ceil(8)),
                            offset_alignment(alignment, offset),
                        );
                    }
                    AbiLocation::Stack { .. } => unreachable!("verified result placement"),
                }
                self.spill_leaf(out, result, part.leaf);
            }
        }
        self.adjust_stack(out, stack, false);
        Ok(())
    }
}

fn offset_alignment(base: u64, offset: u64) -> u64 {
    if offset == 0 {
        base
    } else {
        base.min(1_u64 << offset.trailing_zeros())
    }
}

fn align(value: i64, alignment: i64) -> Result<i64, Diagnostic> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
        .ok_or_else(|| error_diagnostic("native frame alignment overflow"))
}

fn arm_immediate(out: &mut String, register: &str, value: u64) {
    writeln!(out, "  movz {register}, #{}", value & 65535).unwrap();
    for shift in [16, 32, 48] {
        let part = (value >> shift) & 65535;
        if part != 0 {
            writeln!(out, "  movk {register}, #{part}, lsl #{shift}").unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn noalias_scalar_module(triple: &str) -> NativeModule {
        serde_json::from_value(json!({
            "format":FORMAT,"name":"noalias-native-realization",
            "target":{"triple":triple,"data_layout":"e-p:64:64-i64:64-S128",
                "pointer_bits":64,"little_endian":true},
            "semantics":"llvm_defined_behavior_v1",
            "types":[{"kind":"void"},{"kind":"metadata"},{"kind":"int","bits":64},
                {"kind":"function","signature":{"params":[1],"result":0,"abi":"c","variadic":false}}],
            "globals":[],"functions":[
                {"name":"compute","linkage":"external",
                    "signature":{"params":[2,2],"result":2,"abi":"c","variadic":false},
                    "params":[{"id":0,"ty":2},{"id":1,"ty":2}],"entry":0,
                    "blocks":[{"id":0,"instructions":[
                        {"result":null,"operation":{"op":"no_alias_scope_decl","scope_list":3,"source_instruction":0}},
                        {"result":{"id":2,"ty":2},"operation":{"op":"binary","kind":"add",
                            "lhs":{"kind":"value","id":0},"rhs":{"kind":"value","id":1},"flags":[]}}
                    ],"terminator":{"op":"return","value":{"kind":"value","id":2}}}]},
                {"name":NOALIAS_SCOPE_DECL,"intrinsic":NOALIAS_SCOPE_DECL,"linkage":"external",
                    "signature":{"params":[1],"result":0,"abi":"c","variadic":false},
                    "params":[{"id":0,"ty":1}],"entry":null,"blocks":[]}
            ],
            "noalias_metadata":{
                "domains":[{"id":1,"storage":"distinct","identity":{"kind":"self_reference"},"description":[0,255]}],
                "scopes":[{"id":2,"storage":"uniqued","identity":{"kind":"bytes","bytes":[255,0]},"domain":1,"description":[]}],
                "lists":[{"id":3,"storage":"distinct","scopes":[2]}],"attachments":[]},
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"unit-test","frontend_version":"1",
                "importer":"unit-test","importer_version":"1","source_function_count":2,"source_global_count":0,"refinements":[]}
        })).unwrap()
    }

    #[test]
    fn noalias_marker_emits_identical_code_without_metadata_abi_on_all_targets() {
        for (target, triple) in [
            (Target::X86_64UnknownNone, "x86_64-unknown-linux-gnu"),
            (Target::Aarch64UnknownNone, "aarch64-unknown-linux-gnu"),
            (Target::Riscv64UnknownNone, "riscv64-unknown-linux-gnu"),
        ] {
            let original = noalias_scalar_module(triple);
            let original_asm = emit(&original, target).unwrap();
            let mut without_marker = original.clone();
            without_marker.functions[0].blocks[0].instructions.remove(0);
            assert_eq!(original_asm, emit(&without_marker, target).unwrap());
            assert!(!original_asm.contains(NOALIAS_SCOPE_DECL));
            // Even in a verified module with a compiler-only declaration,
            // ordinary ABI planning must never allocate a metadata argument.
            assert!(super::super::native_abi::audit_signature(
                &original,
                target,
                &original.functions[1].signature
            )
            .is_err());
        }
    }

    #[test]
    fn scalar_reference_executes_scope_marker_without_fake_metadata_bits() {
        use num_bigint::BigUint;
        let module = noalias_scalar_module("x86_64-unknown-linux-gnu");
        for (a, b) in [(0, 0), (1, 2), (u64::MAX, 1), (u64::MAX, u64::MAX)] {
            assert_eq!(
                super::super::native_interpret::evaluate(
                    &module,
                    "compute",
                    &[BigUint::from(a), BigUint::from(b)]
                )
                .unwrap(),
                Some(BigUint::from(a.wrapping_add(b)))
            );
        }
        assert!(super::super::native_interpret::evaluate(
            &module,
            NOALIAS_SCOPE_DECL,
            &[BigUint::from(0_u8)]
        )
        .unwrap_err()
        .message
        .contains("not an executable entry point"));
    }

    fn overflow_corpus(triple: &str) -> NativeModule {
        let mut types = vec![
            json!({"kind":"void"}),
            json!({"kind":"int","bits":1}),
            json!({"kind":"int","bits":64}),
            json!({"kind":"pointer","address_space":0}),
        ];
        let mut functions = Vec::new();
        for bits in 1..=64 {
            let integer = types.len();
            types.push(json!({"kind":"int","bits":bits}));
            let pair = types.len();
            types.push(json!({"kind":"struct","fields":[integer,1],"packed":false}));
            for operation in ["add", "sub", "mul"] {
                for signed in [false, true] {
                    let mut instructions = Vec::new();
                    let (a, b) = if bits == 64 {
                        (0, 1)
                    } else {
                        for (id, source) in [(3, 0), (4, 1)] {
                            instructions.push(json!({"result":{"id":id,"ty":integer},
                                "operation":{"op":"cast","kind":"trunc","value":{"kind":"value","id":source}}}));
                        }
                        (3, 4)
                    };
                    instructions.push(json!({"result":{"id":5,"ty":pair},"operation":{
                        "op":"integer_overflow","kind":operation,"signed":signed,
                        "lhs":{"kind":"value","id":a},"rhs":{"kind":"value","id":b}}}));
                    instructions.push(json!({"result":{"id":6,"ty":integer},"operation":{
                        "op":"extract_value","aggregate":{"kind":"value","id":5},"indices":[0]}}));
                    instructions.push(json!({"result":{"id":7,"ty":1},"operation":{
                        "op":"extract_value","aggregate":{"kind":"value","id":5},"indices":[1]}}));
                    let low = if bits == 64 {
                        6
                    } else {
                        instructions.push(json!({"result":{"id":8,"ty":2},"operation":{
                            "op":"cast","kind":"z_ext","value":{"kind":"value","id":6}}}));
                        8
                    };
                    instructions.push(json!({"result":{"id":9,"ty":2},"operation":{
                        "op":"cast","kind":"z_ext","value":{"kind":"value","id":7}}}));
                    instructions.push(json!({"result":null,"operation":{"op":"store",
                        "pointer":{"kind":"value","id":2},"value":{"kind":"value","id":low},"alignment":8,"volatile":false}}));
                    instructions.push(json!({"result":{"id":10,"ty":3},"operation":{"op":"gep",
                        "base":{"kind":"value","id":2},"offset":{"kind":"int","ty":2,"bits":"8"},"inbounds":false}}));
                    instructions.push(json!({"result":null,"operation":{"op":"store",
                        "pointer":{"kind":"value","id":10},"value":{"kind":"value","id":9},"alignment":8,"volatile":false}}));
                    functions.push(json!({"name":format!("overflow_{bits}_{operation}_{}",if signed {"s"} else {"u"}),
                        "linkage":"external","signature":{"params":[2,2,3],"result":0,"abi":"c","variadic":false},
                        "params":[{"id":0,"ty":2},{"id":1,"ty":2},{"id":2,"ty":3}],"entry":0,
                        "blocks":[{"id":0,"instructions":instructions,"terminator":{"op":"return","value":null}}]}));
                }
            }
        }
        serde_json::from_value(json!({"format":FORMAT,"name":"integer-overflow-backend-qa",
            "target":{"triple":triple,"data_layout":"e-p:64:64-i64:64-S128","pointer_bits":64,"little_endian":true},
            "semantics":"llvm_defined_behavior_v1","types":types,"globals":[],"functions":functions,
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"backend QA","frontend_version":"1",
                "importer":"unit test","importer_version":"1","source_function_count":384,"source_global_count":0,"refinements":[]}})).unwrap()
    }

    #[test]
    fn overflow_corpus_emits_all_supported_widths_and_families_on_each_target() {
        for (target, triple) in [
            (Target::X86_64UnknownNone, "x86_64-unknown-linux-gnu"),
            (Target::Aarch64UnknownNone, "aarch64-unknown-linux-gnu"),
            (Target::Riscv64UnknownNone, "riscv64-unknown-linux-gnu"),
        ] {
            let assembly = emit(&overflow_corpus(triple), target).unwrap();
            assert_eq!(assembly.matches(".cfi_startproc\n").count(), 384);
        }
    }

    fn minmax_corpus(triple: &str) -> NativeModule {
        let mut types = vec![json!({"kind":"void"}), json!({"kind":"int","bits":64})];
        let mut functions = Vec::new();
        for bits in 1..=64 {
            let integer = types.len();
            types.push(json!({"kind":"int","bits":bits}));
            for kind in ["smin", "smax", "umin", "umax"] {
                let mut instructions = Vec::new();
                let (lhs, rhs) = if bits == 64 {
                    (0, 1)
                } else {
                    for (id, source) in [(2, 0), (3, 1)] {
                        instructions.push(json!({"result":{"id":id,"ty":integer},"operation":{
                            "op":"cast","kind":"trunc","value":{"kind":"value","id":source}}}));
                    }
                    (2, 3)
                };
                instructions.push(json!({"result":{"id":4,"ty":integer},"operation":{
                    "op":"integer_min_max","kind":kind,"lhs":{"kind":"value","id":lhs},
                    "rhs":{"kind":"value","id":rhs}}}));
                let result = if bits == 64 {
                    4
                } else {
                    instructions.push(json!({"result":{"id":5,"ty":1},"operation":{
                        "op":"cast","kind":"z_ext","value":{"kind":"value","id":4}}}));
                    5
                };
                functions.push(
                    json!({"name":format!("minmax_{bits}_{kind}"),"linkage":"external",
                    "signature":{"params":[1,1],"result":1,"abi":"c","variadic":false},
                    "params":[{"id":0,"ty":1},{"id":1,"ty":1}],"entry":0,
                    "blocks":[{"id":0,"instructions":instructions,
                        "terminator":{"op":"return","value":{"kind":"value","id":result}}}]}),
                );
            }
        }
        serde_json::from_value(json!({"format":FORMAT,"name":"integer-minmax-backend-qa",
            "target":{"triple":triple,"data_layout":"e-p:64:64-i64:64-S128","pointer_bits":64,"little_endian":true},
            "semantics":"llvm_defined_behavior_v1","types":types,"globals":[],"functions":functions,
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"backend QA","frontend_version":"1",
                "importer":"unit test","importer_version":"1","source_function_count":256,"source_global_count":0,"refinements":[]}})).unwrap()
    }

    #[test]
    fn minmax_corpus_emits_original_width_comparisons_on_each_target() {
        for (target, triple) in [
            (Target::X86_64UnknownNone, "x86_64-unknown-linux-gnu"),
            (Target::Aarch64UnknownNone, "aarch64-unknown-linux-gnu"),
            (Target::Riscv64UnknownNone, "riscv64-unknown-linux-gnu"),
        ] {
            let assembly = emit(&minmax_corpus(triple), target).unwrap();
            assert_eq!(assembly.matches(".cfi_startproc\n").count(), 256);
        }
    }

    /// Execute every original bit width against mathematical signed/unsigned
    /// ordering, including i1's -1/0 domain. The corrupted oracle must fail.
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn native_integer_minmax_matches_independent_full_width_c_oracle() {
        use std::{
            fs,
            process::Command,
            time::{SystemTime, UNIX_EPOCH},
        };
        let directory = std::env::temp_dir().join(format!(
            "ostadix-integer-minmax-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let module = minmax_corpus("x86_64-unknown-linux-gnu");
        fs::write(
            directory.join("own.s"),
            emit(&module, Target::X86_64UnknownNone).unwrap(),
        )
        .unwrap();
        let mut source = String::from(
            "#include <stdint.h>\n#include <stdio.h>\ntypedef uint64_t (*Fn)(uint64_t,uint64_t);\n",
        );
        for function in &module.functions {
            writeln!(
                source,
                "extern uint64_t {}(uint64_t,uint64_t);",
                function.name
            )
            .unwrap();
        }
        source.push_str("static Fn functions[]={\n");
        for function in &module.functions {
            writeln!(source, "{},", function.name).unwrap();
        }
        source.push_str(r#"};
typedef unsigned __int128 U128;
typedef __int128 I128;
static uint64_t rng(uint64_t *state) { *state ^= *state << 13; *state ^= *state >> 7; *state ^= *state << 17; return *state; }
int main(int argc, char **argv) {
  (void)argv;
  uint64_t state=UINT64_C(0x613e4379c98aade1), checks=0;
  for (unsigned fn=0;fn<256;fn++) {
    unsigned width=fn/4+1, kind=fn%4;
    uint64_t mask=width==64?UINT64_MAX:(UINT64_C(1)<<width)-1, high=UINT64_C(1)<<(width-1);
    uint64_t corners[]={0,1,mask,mask>>1,high,mask-1,high-1,(high+1)&mask};
    for (unsigned sample=0;sample<1088;sample++) {
      uint64_t a=sample<64?corners[sample/8]:rng(&state), b=sample<64?corners[sample%8]:rng(&state);
      uint64_t ua=a&mask, ub=b&mask;
      I128 sa=(I128)ua-((ua&high)?(I128)((U128)1<<width):0);
      I128 sb=(I128)ub-((ub&high)?(I128)((U128)1<<width):0);
      uint64_t expected=kind==0?(sa<sb?ua:ub):kind==1?(sa>sb?ua:ub):kind==2?(ua<ub?ua:ub):(ua>ub?ua:ub);
      if(argc>1&&checks==0)expected^=1;
      uint64_t actual=functions[fn](a,b);
      if(actual!=expected) {
        fprintf(stderr,"minmax mismatch fn=%u width=%u sample=%u a=%llu b=%llu expected=%llu actual=%llu\n",fn,width,sample,(unsigned long long)a,(unsigned long long)b,(unsigned long long)expected,(unsigned long long)actual);return 1;
      }
      checks++;
    }
  }
  printf("%llu exact values\n",(unsigned long long)checks);return checks==278528?0:2;
}
"#);
        fs::write(directory.join("oracle.c"), source).unwrap();
        let compiler = std::env::var_os("OCORE_TEST_CLANG").unwrap_or_else(|| "clang".into());
        let output = Command::new(&compiler)
            .current_dir(&directory)
            .args(["-O2", "oracle.c", "own.s", "-o", "oracle"])
            .output()
            .expect("native minmax QA requires clang; set OCORE_TEST_CLANG if needed");
        fs::write(directory.join("compile.stdout"), &output.stdout).unwrap();
        fs::write(directory.join("compile.stderr"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{}: {}",
            directory.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(directory.join("oracle")).output().unwrap();
        fs::write(directory.join("execution.stdout"), &output.stdout).unwrap();
        fs::write(directory.join("execution.stderr"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{}: {}",
            directory.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "278528 exact values\n"
        );
        let corrupted = Command::new(directory.join("oracle"))
            .arg("corrupt")
            .output()
            .unwrap();
        fs::write(directory.join("corrupt.stdout"), &corrupted.stdout).unwrap();
        fs::write(directory.join("corrupt.stderr"), &corrupted.stderr).unwrap();
        assert!(
            !corrupted.status.success(),
            "corrupted minmax oracle unexpectedly passed"
        );
        assert!(String::from_utf8_lossy(&corrupted.stderr)
            .contains("minmax mismatch fn=0 width=1 sample=0"));
        println!(
            "minmax backend QA: 278528 exact values and corrupted-oracle rejection; artifacts {}",
            directory.display()
        );
    }

    /// A real emitted x86 object against an independent 128-bit C arithmetic
    /// oracle. This verifies backend semantics, not imported engine coverage.
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn native_integer_overflow_matches_independent_full_width_c_oracle() {
        use std::{
            fs,
            process::Command,
            time::{SystemTime, UNIX_EPOCH},
        };
        let directory = std::env::temp_dir().join(format!(
            "ostadix-integer-overflow-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let module = overflow_corpus("x86_64-unknown-linux-gnu");
        fs::write(
            directory.join("own.s"),
            emit(&module, Target::X86_64UnknownNone).unwrap(),
        )
        .unwrap();
        let mut source = String::from("#include <stdint.h>\n#include <stdio.h>\ntypedef void (*Fn)(uint64_t,uint64_t,uint64_t*);\n");
        for function in &module.functions {
            writeln!(
                source,
                "extern void {}(uint64_t,uint64_t,uint64_t*);",
                function.name
            )
            .unwrap();
        }
        source.push_str("static Fn functions[]={\n");
        for function in &module.functions {
            writeln!(source, "{},", function.name).unwrap();
        }
        source.push_str(r#"};
typedef unsigned __int128 U128;
typedef __int128 I128;
static uint64_t rng(uint64_t *state) { *state ^= *state << 13; *state ^= *state >> 7; *state ^= *state << 17; return *state; }
int main(void) {
  uint64_t state=UINT64_C(0x23948acde784ce51), checks=0;
  for (unsigned fn=0;fn<384;fn++) {
    unsigned width=fn/6+1, op=(fn%6)/2, sign=fn%2;
    uint64_t mask=width==64?UINT64_MAX:(UINT64_C(1)<<width)-1, high=UINT64_C(1)<<(width-1);
    uint64_t corners[]={0,1,mask,mask>>1,high,mask-1,high-1,(high+1)&mask};
    for (unsigned sample=0;sample<1088;sample++) {
      uint64_t a=sample<64?corners[sample/8]:rng(&state), b=sample<64?corners[sample%8]:rng(&state), actual[2]={~0ULL,~0ULL};
      U128 ua=a&mask, ub=b&mask, exactu=op==0?ua+ub:op==1?ua-ub:ua*ub;
      uint64_t expected=(uint64_t)exactu&mask, overflow;
      if (sign) {
        I128 sa=(I128)ua-((ua&high)?(I128)((U128)1<<width):0);
        I128 sb=(I128)ub-((ub&high)?(I128)((U128)1<<width):0);
        I128 exact=op==0?sa+sb:op==1?sa-sb:sa*sb, boundary=(I128)1<<(width-1);
        expected=(uint64_t)exact&mask; overflow=exact < -boundary || exact >= boundary;
      } else overflow=op==1?ua<ub:exactu>(U128)mask;
      functions[fn](a,b,actual);
      if (actual[0]!=expected || actual[1]!=overflow) {
        fprintf(stderr,"fn=%u width=%u sample=%u a=%llu b=%llu expected=%llu/%llu actual=%llu/%llu\n",fn,width,sample,(unsigned long long)a,(unsigned long long)b,(unsigned long long)expected,(unsigned long long)overflow,(unsigned long long)actual[0],(unsigned long long)actual[1]); return 1;
      }
      checks++;
    }
  }
  printf("%llu exact pairs\n",(unsigned long long)checks); return checks==417792?0:2;
}
"#);
        fs::write(directory.join("oracle.c"), source).unwrap();
        let compiler = std::env::var_os("OCORE_TEST_CLANG").unwrap_or_else(|| "clang".into());
        let output = Command::new(&compiler)
            .current_dir(&directory)
            .args(["-O2", "oracle.c", "own.s", "-o", "oracle"])
            .output()
            .expect("native overflow QA requires clang; set OCORE_TEST_CLANG if needed");
        fs::write(directory.join("compile.stdout"), &output.stdout).unwrap();
        fs::write(directory.join("compile.stderr"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{}: {}",
            directory.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(directory.join("oracle")).output().unwrap();
        fs::write(directory.join("execution.stdout"), &output.stdout).unwrap();
        fs::write(directory.join("execution.stderr"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{}: {}",
            directory.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "417792 exact pairs\n"
        );
        println!(
            "overflow backend QA: 417792 exact pairs; artifacts {}",
            directory.display()
        );
    }

    // These fixtures exercise native emission directly. They are authored MIR,
    // not imported original-engine or provider-closure qualification.
    fn vector_qa_value(id: usize) -> serde_json::Value {
        json!({"kind":"value","id":id})
    }
    fn vector_qa_int(ty: usize, value: u64) -> serde_json::Value {
        json!({"kind":"int","ty":ty,"bits":value.to_string()})
    }
    fn vector_qa_instruction(
        id: usize,
        ty: usize,
        operation: serde_json::Value,
    ) -> serde_json::Value {
        json!({"result":{"id":id,"ty":ty},"operation":operation})
    }
    fn vector_qa_push(
        instructions: &mut Vec<serde_json::Value>,
        next: &mut usize,
        ty: usize,
        operation: serde_json::Value,
    ) -> usize {
        let id = *next;
        *next += 1;
        instructions.push(vector_qa_instruction(id, ty, operation));
        id
    }
    fn vector_qa_store(
        instructions: &mut Vec<serde_json::Value>,
        next: &mut usize,
        base: usize,
        offset: u64,
        value: serde_json::Value,
    ) {
        let pointer = if offset == 0 {
            vector_qa_value(base)
        } else {
            let id = vector_qa_push(
                instructions,
                next,
                6,
                json!({"op":"gep",
                "base":vector_qa_value(base),"offset":vector_qa_int(5,offset),"inbounds":false}),
            );
            vector_qa_value(id)
        };
        instructions.push(json!({"result":null,"operation":{"op":"store",
            "pointer":pointer,"value":value,"alignment":1,"volatile":false}}));
    }
    fn vector_qa_function(
        name: &str,
        params: &[usize],
        result: usize,
        blocks: Vec<serde_json::Value>,
    ) -> serde_json::Value {
        let values: Vec<_> = params
            .iter()
            .enumerate()
            .map(|(id, ty)| json!({"id":id,"ty":ty}))
            .collect();
        json!({"name":name,"linkage":"external",
            "signature":{"params":params,"result":result,"abi":"c","variadic":false},
            "params":values,"entry":0,"blocks":blocks})
    }
    fn vector_qa_module(triple: &str, functions: Vec<serde_json::Value>) -> NativeModule {
        let count = functions.len();
        serde_json::from_value(json!({"format":FORMAT,"name":"fixed-vector-native-qa",
            "target":{"triple":triple,"data_layout":"e-p:64:64-i64:64-S128","pointer_bits":64,"little_endian":true},
            "semantics":"llvm_defined_behavior_v1",
            "types":[
                {"kind":"void"},{"kind":"int","bits":1},{"kind":"int","bits":8},
                {"kind":"int","bits":16},{"kind":"int","bits":32},{"kind":"int","bits":64},
                {"kind":"pointer","address_space":0},
                {"kind":"vector","element":4,"len":4},{"kind":"vector","element":1,"len":4},
                {"kind":"vector","element":1,"len":9},{"kind":"vector","element":2,"len":3},
                {"kind":"vector","element":2,"len":9},
                {"kind":"struct","fields":[2,10,2],"packed":false},
                {"kind":"array","element":10,"len":2},
                {"kind":"vector","element":5,"len":1},{"kind":"vector","element":5,"len":2},
                {"kind":"vector","element":1,"len":65537},
                {"kind":"vector","element":2,"len":4},{"kind":"vector","element":3,"len":4},
                {"kind":"vector","element":5,"len":4}
            ],"globals":[],"functions":functions,
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"native backend QA","frontend_version":"1",
                "importer":"authored MIR","importer_version":"1","source_function_count":count,
                "source_global_count":0,"refinements":[]}})).unwrap()
    }

    fn vector_qa_phi_function() -> serde_json::Value {
        // Loop PHIs swap two distinct multiword vectors simultaneously.
        // Iteration zero preserves both; each odd iteration exchanges them.
        vector_qa_function(
            "qa_vector_phi",
            &[6, 6, 6, 5],
            0,
            vec![
                json!({"id":0,"instructions":[
                vector_qa_instruction(4,7,json!({"op":"load","pointer":vector_qa_value(0),"alignment":1,"volatile":false})),
                vector_qa_instruction(5,7,json!({"op":"load","pointer":vector_qa_value(1),"alignment":1,"volatile":false}))
            ],"terminator":{"op":"jump","target":1}}),
                json!({"id":1,"instructions":[
                vector_qa_instruction(6,7,json!({"op":"phi","incoming":[
                    {"block":0,"value":vector_qa_value(4)},{"block":2,"value":vector_qa_value(7)}]})),
                vector_qa_instruction(7,7,json!({"op":"phi","incoming":[
                    {"block":0,"value":vector_qa_value(5)},{"block":2,"value":vector_qa_value(6)}]})),
                vector_qa_instruction(8,5,json!({"op":"phi","incoming":[
                    {"block":0,"value":vector_qa_int(5,0)},{"block":2,"value":vector_qa_value(10)}]})),
                vector_qa_instruction(9,1,json!({"op":"i_cmp","predicate":"ult","lhs":vector_qa_value(8),"rhs":vector_qa_value(3)}))
            ],"terminator":{"op":"branch","condition":vector_qa_value(9),"on_true":2,"on_false":3}}),
                json!({"id":2,"instructions":[
                vector_qa_instruction(10,5,json!({"op":"binary","kind":"add","lhs":vector_qa_value(8),"rhs":vector_qa_int(5,1),"flags":[]}))
            ],"terminator":{"op":"jump","target":1}}),
                json!({"id":3,"instructions":[
                {"result":null,"operation":{"op":"store","pointer":vector_qa_value(2),"value":vector_qa_value(6),"alignment":1,"volatile":false}},
                vector_qa_instruction(11,6,json!({"op":"gep","base":vector_qa_value(2),"offset":vector_qa_int(5,16),"inbounds":false})),
                {"result":null,"operation":{"op":"store","pointer":vector_qa_value(11),"value":vector_qa_value(7),"alignment":1,"volatile":false}}
            ],"terminator":{"op":"return","value":null}}),
            ],
        )
    }

    #[test]
    fn fixed_vector_physical_frames_and_parallel_phi_scratch_cover_packed_values() {
        for (target, triple) in [
            (Target::X86_64UnknownNone, "x86_64-unknown-linux-gnu"),
            (Target::Aarch64UnknownNone, "aarch64-unknown-linux-gnu"),
            (Target::Riscv64UnknownNone, "riscv64-unknown-linux-gnu"),
        ] {
            let mut module = vector_qa_module(triple, vec![vector_qa_phi_function()]);
            module.functions[0].control_effects.returns_twice = true;
            let (assembly, report) = emit_with_nonlocal_report(&module, target).unwrap();
            assert!(!assembly.is_empty());
            assert!(report.has_nonlocal_effects);
            assert!(!report.provider_qualified);
            assert!(!report.library_exposure_admitted);
            assert_eq!(report.functions.len(), 1);
            let frame = &report.functions[0];
            for value in [4, 5, 6, 7] {
                let region = frame
                    .regions
                    .iter()
                    .find(|r| r.role == "ssa_spill" && r.value == Some(value))
                    .unwrap();
                assert_eq!(region.bytes, 16, "target {target:?}, value {value}");
                let chunks: Vec<_> = region
                    .chunks
                    .iter()
                    .map(|c| (c.leaf, c.bit_offset, c.value_bits, c.storage_bytes))
                    .collect();
                assert_eq!(chunks, vec![(0, 0, 64, 8), (0, 64, 64, 8)]);
                assert_eq!(region.chunks[0].offset_from_fp, region.offset_from_fp);
                assert_eq!(region.chunks[1].offset_from_fp, region.offset_from_fp + 8);
            }
            // Two 128-bit vector PHIs and one 64-bit loop counter require
            // five distinct simultaneous incoming snapshots.
            let scratch: Vec<_> = frame
                .regions
                .iter()
                .filter(|r| r.role == "phi_parallel_copy")
                .collect();
            assert_eq!(scratch.len(), 5);
            assert!(scratch.iter().all(|r| r.bytes == 8 && r.alignment == 8));
            let mut spans: Vec<_> = frame
                .regions
                .iter()
                .map(|r| {
                    (
                        r.offset_from_fp,
                        r.offset_from_fp + i64::try_from(r.bytes).unwrap(),
                    )
                })
                .collect();
            spans.sort();
            assert!(spans.windows(2).all(|w| w[0].1 <= w[1].0));
            assert_eq!(frame.fixed_frame_bytes % 16, 0);
            assert_eq!(frame.steady_sp_from_fp, -frame.fixed_frame_bytes);
        }
    }

    #[test]
    fn fixed_vector_nonlocal_offsets_preserve_the_first_bit_above_u16() {
        for (target, triple) in [
            (Target::X86_64UnknownNone, "x86_64-unknown-linux-gnu"),
            (Target::Aarch64UnknownNone, "aarch64-unknown-linux-gnu"),
            (Target::Riscv64UnknownNone, "riscv64-unknown-linux-gnu"),
        ] {
            let function = vector_qa_function(
                "qa_wide_mask_frame",
                &[],
                0,
                vec![json!({
                "id":0,"instructions":[vector_qa_instruction(0,16,json!({"op":"freeze",
                    "value":{"kind":"aggregate_zero","ty":16}}))],
                "terminator":{"op":"return","value":null}})],
            );
            let mut module = vector_qa_module(triple, vec![function]);
            module.functions[0].control_effects.returns_twice = true;
            let (_, report) = emit_with_nonlocal_report(&module, target).unwrap();
            assert!(!report.provider_qualified);
            let frame = &report.functions[0];
            let region = frame
                .regions
                .iter()
                .find(|r| r.role == "ssa_spill" && r.value == Some(0))
                .unwrap();
            // Literal endpoints come from 65537 source bits, not the
            // implementation's chunk iterator. A u16 offset loses the last bit.
            assert_eq!(region.bytes, 8200);
            assert_eq!(region.offset_from_fp, -8200);
            assert_eq!(frame.fixed_frame_bytes, 8208);
            assert_eq!(region.chunks.len(), 1025);
            assert_eq!(
                (
                    region.chunks[1023].bit_offset,
                    region.chunks[1023].value_bits,
                    region.chunks[1023].offset_from_fp
                ),
                (65472, 64, -16)
            );
            assert_eq!(
                (
                    region.chunks[1024].bit_offset,
                    region.chunks[1024].value_bits,
                    region.chunks[1024].offset_from_fp
                ),
                (65536, 1, -8)
            );
            assert!(region.chunks.iter().all(|c| c.storage_bytes == 8));
        }
    }

    #[test]
    fn fixed_vector_layout_uses_vector_overrides_packed_bits_and_allocation_stride() {
        use super::super::native_verify::value_leaf_layout;
        let mut module = vector_qa_module("x86_64-unknown-linux-gnu", vec![]);
        let layout = fixed_vector_layout(&module, 10).unwrap();
        assert_eq!(
            (
                layout.store_size,
                layout.abi_alignment,
                layout.allocation_size
            ),
            (3, 4, 4)
        );
        let mask = fixed_vector_layout(&module, 9).unwrap();
        assert_eq!(
            (
                mask.bit_width,
                mask.store_size,
                mask.abi_alignment,
                mask.allocation_size
            ),
            (9, 2, 2, 2)
        );
        assert_eq!(value_leaf_layout(&module, 9).unwrap(), vec![(9, 0)]);
        assert_eq!(
            value_leaf_layout(&module, 13).unwrap(),
            vec![(10, 0), (10, 4)]
        );
        assert_eq!(
            value_leaf_layout(&module, 12).unwrap(),
            vec![(2, 0), (10, 4), (2, 8)]
        );
        module.target.data_layout = "e-p:64:64-i64:128-S128".into();
        assert_eq!(type_layouts(&module).unwrap()[5], Some((16, 16)));
        let one = fixed_vector_layout(&module, 14).unwrap();
        assert_eq!(
            (one.store_size, one.abi_alignment, one.allocation_size),
            (8, 8, 8)
        );
        module.target.data_layout = "e-p:64:64-i64:64-v128:256-S128".into();
        let wide = fixed_vector_layout(&module, 15).unwrap();
        assert_eq!(
            (wide.store_size, wide.abi_alignment, wide.allocation_size),
            (16, 32, 32)
        );
        let array = module.types.len();
        module.types.push(Type::Array {
            element: 15,
            len: 2,
        });
        assert_eq!(type_layouts(&module).unwrap()[array], Some((64, 32)));
        assert_eq!(
            value_leaf_layout(&module, array).unwrap(),
            vec![(15, 0), (15, 32)]
        );
        for (alignment_bits, expected_alloc, expected_align) in [(8, 3, 1), (64, 8, 8)] {
            module.target.data_layout = format!("e-p:64:64-i64:64-v24:{alignment_bits}-S128");
            let overridden = fixed_vector_layout(&module, 10).unwrap();
            assert_eq!(
                (
                    overridden.store_size,
                    overridden.allocation_size,
                    overridden.abi_alignment
                ),
                (3, expected_alloc, expected_align)
            );
            assert_eq!(
                value_leaf_layout(&module, 13).unwrap(),
                vec![(10, 0), (10, expected_alloc)]
            );
        }
    }

    fn vector_qa_execution_module() -> NativeModule {
        let mut functions = Vec::new();
        for (bits, scalar, vector) in [
            (1u16, 1usize, 8usize),
            (8, 2, 17),
            (16, 3, 18),
            (32, 4, 7),
            (64, 5, 19),
        ] {
            let mut instructions = Vec::new();
            let mut next = 3usize;
            let a = vector_qa_push(
                &mut instructions,
                &mut next,
                vector,
                json!({"op":"load","pointer":vector_qa_value(0),"alignment":1,"volatile":false}),
            );
            let b = vector_qa_push(
                &mut instructions,
                &mut next,
                vector,
                json!({"op":"load","pointer":vector_qa_value(1),"alignment":1,"volatile":false}),
            );
            let sub = vector_qa_push(
                &mut instructions,
                &mut next,
                vector,
                json!({"op":"binary","kind":"sub","lhs":vector_qa_value(a),"rhs":vector_qa_value(b),"flags":[]}),
            );
            let less = vector_qa_push(
                &mut instructions,
                &mut next,
                8,
                json!({"op":"i_cmp","predicate":"slt","lhs":vector_qa_value(a),"rhs":vector_qa_value(b)}),
            );
            let selected = vector_qa_push(
                &mut instructions,
                &mut next,
                vector,
                json!({"op":"select","condition":vector_qa_value(less),"on_true":vector_qa_value(a),"on_false":vector_qa_value(b)}),
            );
            let sum = vector_qa_push(
                &mut instructions,
                &mut next,
                vector,
                json!({"op":"binary","kind":"add","lhs":vector_qa_value(a),"rhs":vector_qa_value(b),"flags":[]}),
            );
            let lane_masks: Vec<_> = (0..4)
                .map(|_| vector_qa_int(scalar, u64::from(bits - 1)))
                .collect();
            let counts = vector_qa_push(
                &mut instructions,
                &mut next,
                vector,
                json!({"op":"binary","kind":"and","lhs":vector_qa_value(b),
                "rhs":{"kind":"aggregate","ty":vector,"elements":lane_masks},"flags":[]}),
            );
            let shifted = vector_qa_push(
                &mut instructions,
                &mut next,
                vector,
                json!({"op":"binary","kind":"a_shr","lhs":vector_qa_value(a),"rhs":vector_qa_value(counts),"flags":[]}),
            );
            let extended = if bits == 1 {
                less
            } else {
                vector_qa_push(
                    &mut instructions,
                    &mut next,
                    vector,
                    json!({"op":"cast","kind":"s_ext","value":vector_qa_value(less)}),
                )
            };
            let conjunction = vector_qa_push(
                &mut instructions,
                &mut next,
                vector,
                json!({"op":"binary","kind":"and","lhs":vector_qa_value(a),"rhs":vector_qa_value(b),"flags":[]}),
            );
            for (ordinal, value) in [sub, selected, sum, shifted, extended, conjunction]
                .into_iter()
                .enumerate()
            {
                vector_qa_store(
                    &mut instructions,
                    &mut next,
                    2,
                    ordinal as u64 * 32,
                    vector_qa_value(value),
                );
            }
            functions.push(vector_qa_function(&format!("qa_vector_math_{bits}"),&[6,6,6],0,
                vec![json!({"id":0,"instructions":instructions,"terminator":{"op":"return","value":null}})]));
        }
        let mut instructions = Vec::new();
        let mut next = 1usize;
        let bytes: Vec<_> = [0xa1u64, 0xb2, 0xc3]
            .into_iter()
            .map(|v| vector_qa_int(2, v))
            .collect();
        vector_qa_store(
            &mut instructions,
            &mut next,
            0,
            0,
            json!({"kind":"aggregate","ty":10,"elements":bytes}),
        );
        functions.push(vector_qa_function("qa_vector_store3",&[6],0,vec![json!({"id":0,"instructions":instructions,"terminator":{"op":"return","value":null}})]));

        let mut instructions = Vec::new();
        let mut next = 3usize;
        let a = vector_qa_push(
            &mut instructions,
            &mut next,
            9,
            json!({"op":"load","pointer":vector_qa_value(0),"alignment":1,"volatile":false}),
        );
        let b = vector_qa_push(
            &mut instructions,
            &mut next,
            9,
            json!({"op":"load","pointer":vector_qa_value(1),"alignment":1,"volatile":false}),
        );
        let xor = vector_qa_push(
            &mut instructions,
            &mut next,
            9,
            json!({"op":"binary","kind":"xor","lhs":vector_qa_value(a),"rhs":vector_qa_value(b),"flags":[]}),
        );
        vector_qa_store(&mut instructions, &mut next, 2, 0, vector_qa_value(xor));
        let extended = vector_qa_push(
            &mut instructions,
            &mut next,
            11,
            json!({"op":"cast","kind":"z_ext","value":vector_qa_value(xor)}),
        );
        vector_qa_store(
            &mut instructions,
            &mut next,
            2,
            4,
            vector_qa_value(extended),
        );
        let parity = vector_qa_push(
            &mut instructions,
            &mut next,
            1,
            json!({"op":"vector_reduce_add","value":vector_qa_value(xor)}),
        );
        let returned = vector_qa_push(
            &mut instructions,
            &mut next,
            5,
            json!({"op":"cast","kind":"z_ext","value":vector_qa_value(parity)}),
        );
        functions.push(vector_qa_function("qa_vector_mask9",&[6,6,6],5,vec![json!({"id":0,"instructions":instructions,"terminator":{"op":"return","value":vector_qa_value(returned)}})]));

        let partial = json!({"kind":"aggregate","ty":7,"elements":[vector_qa_int(4,7),{"kind":"poison","ty":4},vector_qa_int(4,9),vector_qa_int(4,11)]});
        let mut instructions = Vec::new();
        let mut next = 1usize;
        let frozen = vector_qa_push(
            &mut instructions,
            &mut next,
            7,
            json!({"op":"freeze","value":partial.clone()}),
        );
        for (slot, lane) in [0u64, 2, 3].into_iter().enumerate() {
            let value = vector_qa_push(
                &mut instructions,
                &mut next,
                4,
                json!({"op":"extract_element","vector":vector_qa_value(frozen),"index":vector_qa_int(5,lane)}),
            );
            vector_qa_store(
                &mut instructions,
                &mut next,
                0,
                slot as u64 * 4,
                vector_qa_value(value),
            );
        }
        let unknown_a = vector_qa_push(
            &mut instructions,
            &mut next,
            4,
            json!({"op":"extract_element","vector":vector_qa_value(frozen),"index":vector_qa_int(5,1)}),
        );
        let unknown_b = vector_qa_push(
            &mut instructions,
            &mut next,
            4,
            json!({"op":"extract_element","vector":vector_qa_value(frozen),"index":vector_qa_int(5,1)}),
        );
        let cancellation = vector_qa_push(
            &mut instructions,
            &mut next,
            4,
            json!({"op":"binary","kind":"xor","lhs":vector_qa_value(unknown_a),"rhs":vector_qa_value(unknown_b),"flags":[]}),
        );
        vector_qa_store(
            &mut instructions,
            &mut next,
            0,
            12,
            vector_qa_value(cancellation),
        );
        let replaced = vector_qa_push(
            &mut instructions,
            &mut next,
            7,
            json!({"op":"insert_element","vector":partial,"value":vector_qa_int(4,3),"index":vector_qa_int(5,1)}),
        );
        let total = vector_qa_push(
            &mut instructions,
            &mut next,
            4,
            json!({"op":"vector_reduce_add","value":vector_qa_value(replaced)}),
        );
        vector_qa_store(&mut instructions, &mut next, 0, 16, vector_qa_value(total));
        functions.push(vector_qa_function("qa_vector_poison_defined",&[6],0,vec![json!({"id":0,"instructions":instructions,"terminator":{"op":"return","value":null}})]));

        let mut instructions = Vec::new();
        let mut next = 3usize;
        let input = vector_qa_push(
            &mut instructions,
            &mut next,
            7,
            json!({"op":"load","pointer":vector_qa_value(0),"alignment":1,"volatile":false}),
        );
        let extracted = vector_qa_push(
            &mut instructions,
            &mut next,
            4,
            json!({"op":"extract_element","vector":vector_qa_value(input),"index":vector_qa_value(1)}),
        );
        let valid = vector_qa_push(
            &mut instructions,
            &mut next,
            1,
            json!({"op":"i_cmp","predicate":"ult","lhs":vector_qa_value(1),"rhs":vector_qa_int(5,4)}),
        );
        let result = vector_qa_push(
            &mut instructions,
            &mut next,
            4,
            json!({"op":"select","condition":vector_qa_value(valid),"on_true":vector_qa_value(extracted),"on_false":vector_qa_int(4,71)}),
        );
        let inserted = vector_qa_push(
            &mut instructions,
            &mut next,
            7,
            json!({"op":"insert_element","vector":vector_qa_value(input),"value":vector_qa_int(4,0xdeadbeef),"index":vector_qa_value(1)}),
        );
        let safe = vector_qa_push(
            &mut instructions,
            &mut next,
            7,
            json!({"op":"select","condition":vector_qa_value(valid),"on_true":vector_qa_value(inserted),"on_false":vector_qa_value(input)}),
        );
        vector_qa_store(&mut instructions, &mut next, 2, 0, vector_qa_value(safe));
        functions.push(vector_qa_function("qa_vector_dynamic",&[6,5,6],4,vec![json!({"id":0,"instructions":instructions,"terminator":{"op":"return","value":vector_qa_value(result)}})]));
        functions.push(vector_qa_phi_function());
        vector_qa_module("x86_64-unknown-linux-gnu", functions)
    }

    /// Execute only on the actual matching native host, like the existing
    /// integer C oracles. Other-target frame tests above do not execute code.
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn native_fixed_vector_defined_results_match_independent_c_oracle() {
        use std::{
            fs,
            process::Command,
            time::{SystemTime, UNIX_EPOCH},
        };
        let directory = std::env::temp_dir().join(format!(
            "ostadix-fixed-vector-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let module = vector_qa_execution_module();
        fs::write(
            directory.join("module.json"),
            serde_json::to_vec_pretty(&module).unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join("own.s"),
            emit(&module, Target::X86_64UnknownNone).unwrap(),
        )
        .unwrap();
        let source = r#"#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void qa_vector_math_1(const unsigned char*,const unsigned char*,unsigned char*);
extern void qa_vector_math_8(const unsigned char*,const unsigned char*,unsigned char*);
extern void qa_vector_math_16(const unsigned char*,const unsigned char*,unsigned char*);
extern void qa_vector_math_32(const unsigned char*,const unsigned char*,unsigned char*);
extern void qa_vector_math_64(const unsigned char*,const unsigned char*,unsigned char*);
extern void qa_vector_store3(unsigned char*);
extern uint64_t qa_vector_mask9(const unsigned char*,const unsigned char*,unsigned char*);
extern void qa_vector_poison_defined(uint32_t*);
extern uint32_t qa_vector_dynamic(const uint32_t*,uint64_t,uint32_t*);
extern void qa_vector_phi(const uint32_t*,const uint32_t*,uint32_t*,uint64_t);
typedef void (*Math)(const unsigned char*,const unsigned char*,unsigned char*);
static Math math_functions[]={qa_vector_math_1,qa_vector_math_8,qa_vector_math_16,qa_vector_math_32,qa_vector_math_64};
static const unsigned widths[]={1,8,16,32,64};
static uint64_t state=UINT64_C(0xf137a5294bd3c681);
static uint64_t rng(void){state^=state<<13;state^=state>>7;state^=state<<17;return state;}
/* The oracle packs one bit at a time, independently of native spill/chunk code. */
static void put(unsigned char *p,unsigned width,unsigned lane,uint64_t value){
 for(unsigned bit=0;bit<width;bit++)if((value>>bit)&1)p[(lane*width+bit)/8]|=(unsigned char)(1u<<((lane*width+bit)%8));
}
static uint64_t get(const unsigned char*p,unsigned width,unsigned lane){
 uint64_t value=0;for(unsigned bit=0;bit<width;bit++)value|=(uint64_t)((p[(lane*width+bit)/8]>>((lane*width+bit)%8))&1)<<bit;return value;
}
#define CHECK(tag,condition) do{if(!(condition)){fprintf(stderr,"%s mismatch line=%d\n",tag,__LINE__);return 1;}checks++;}while(0)
int main(int argc,char**argv){
 (void)argv;uint64_t checks=0;
 for(unsigned wi=0;wi<5;wi++){
  unsigned width=widths[wi],bytes=(width*4+7)/8;
  uint64_t mask=width==64?UINT64_MAX:(UINT64_C(1)<<width)-1,high=UINT64_C(1)<<(width-1);
  uint64_t corners[]={0,1,mask,mask>>1,high,mask-1,high-1,(high+1)&mask};
  for(unsigned sample=0;sample<128;sample++){
   unsigned char a[32]={0},b[32]={0},out[200];uint64_t av[4],bv[4];memset(out,0xaa,sizeof(out));
   for(unsigned lane=0;lane<4;lane++){
    av[lane]=(sample<64?corners[(sample/8+lane)%8]:rng())&mask;
    bv[lane]=(sample<64?corners[(sample%8+3*lane)%8]:rng())&mask;
    put(a,width,lane,av[lane]);put(b,width,lane,bv[lane]);
   }
   math_functions[wi](a,b,out);
   for(unsigned lane=0;lane<4;lane++){
    uint64_t ua=av[lane],ub=bv[lane],count=ub&(width-1);
    __int128 sa=(__int128)ua-((ua&high)?(__int128)((unsigned __int128)1<<width):0);
    __int128 sb=(__int128)ub-((ub&high)?(__int128)((unsigned __int128)1<<width):0);
    uint64_t shifted=count?((ua>>count)|((ua&high)?(mask^(mask>>count)):0)):ua;
    uint64_t expected[]={ (ua-ub)&mask,sa<sb?ua:ub,(ua+ub)&mask,shifted&mask,sa<sb?mask:0,ua&ub };
    for(unsigned op=0;op<6;op++){
     if(argc>1&&wi==0&&sample==0&&lane==0&&op==0)expected[op]^=1;
     uint64_t actual=get(out+32*op,width,lane);
     if(actual!=expected[op]){fprintf(stderr,"math mismatch width=%u sample=%u lane=%u operation=%u expected=%llu actual=%llu\n",width,sample,lane,op,(unsigned long long)expected[op],(unsigned long long)actual);return 1;}
     checks++;
    }
   }
   for(unsigned op=0;op<6;op++)for(unsigned byte=bytes;byte<32;byte++)CHECK("math extent",out[32*op+byte]==0xaa);
   for(unsigned byte=192;byte<200;byte++)CHECK("math suffix",out[byte]==0xaa);
  }
 }
 unsigned char canary[16];memset(canary,0xaa,sizeof(canary));qa_vector_store3(canary+5);
 for(unsigned byte=0;byte<16;byte++){unsigned expected=byte==5?0xa1:byte==6?0xb2:byte==7?0xc3:0xaa;CHECK("v3i8 extent",canary[byte]==expected);}
 for(unsigned pattern=0;pattern<512;pattern++){
  unsigned other=(pattern*73+19)&511,expected=pattern^other;
  unsigned char a[2]={(unsigned char)pattern,(unsigned char)(pattern>>8)},b[2]={(unsigned char)other,(unsigned char)(other>>8)},out[20];memset(out,0xaa,sizeof(out));
  uint64_t parity=qa_vector_mask9(a,b,out);unsigned sum=0;
  for(unsigned lane=0;lane<9;lane++){unsigned bit=(expected>>lane)&1;CHECK("v9i1 packed",get(out,1,lane)==bit);CHECK("v9i1 zext",out[4+lane]==bit);sum+=bit;}
  CHECK("v9i1 parity",parity==(sum&1));
  /* Unused bits in the final packed byte are deliberately not compared. */
  for(unsigned byte=0;byte<20;byte++)if(byte==2||byte==3||byte>=13)CHECK("v9i1 extent",out[byte]==0xaa);
 }
 uint32_t poison[5]={0};const uint32_t poison_expected[]={7,9,11,0,30};qa_vector_poison_defined(poison);
 for(unsigned i=0;i<5;i++)CHECK("defined poison/freeze",poison[i]==poison_expected[i]);
 uint32_t input[]={7,UINT32_C(0x80000001),91,UINT32_C(0xffffffff)},out[8];
 const uint64_t indexes[]={0,1,2,3,4,5,UINT64_MAX};
 for(unsigned sample=0;sample<7;sample++){
  uint64_t index=indexes[sample];uint32_t result=qa_vector_dynamic(input,index,out);
  CHECK("dynamic extract selected poison away",result==(index<4?input[index]:71));
  for(unsigned lane=0;lane<4;lane++)CHECK("dynamic insert selected poison away",out[lane]==(index==lane?UINT32_C(0xdeadbeef):input[lane]));
 }
 const uint32_t a[]={1,2,UINT32_C(0x80000003),4},b[]={41,52,63,UINT32_C(0xfffffff4)};
 for(unsigned iterations=0;iterations<8;iterations++){
  memset(out,0,sizeof(out));qa_vector_phi(a,b,out,iterations);
  for(unsigned lane=0;lane<4;lane++){CHECK("parallel phi A",out[lane]==((iterations&1)?b[lane]:a[lane]));CHECK("parallel phi B",out[4+lane]==((iterations&1)?a[lane]:b[lane]));}
 }
 printf("%llu defined vector observations\n",(unsigned long long)checks);return checks==110968?0:2;
}
"#;
        fs::write(directory.join("oracle.c"), source).unwrap();
        let compiler = std::env::var_os("OCORE_TEST_CLANG").unwrap_or_else(|| "clang".into());
        let compile = Command::new(&compiler)
            .current_dir(&directory)
            .args(["-O2", "oracle.c", "own.s", "-o", "oracle"])
            .output()
            .expect("native fixed-vector QA requires clang; set OCORE_TEST_CLANG if needed");
        fs::write(directory.join("compile.stdout"), &compile.stdout).unwrap();
        fs::write(directory.join("compile.stderr"), &compile.stderr).unwrap();
        assert!(
            compile.status.success(),
            "{}: {}",
            directory.display(),
            String::from_utf8_lossy(&compile.stderr)
        );
        let output = Command::new(directory.join("oracle")).output().unwrap();
        fs::write(directory.join("execution.stdout"), &output.stdout).unwrap();
        fs::write(directory.join("execution.stderr"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{}: {}",
            directory.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "110968 defined vector observations\n"
        );
        let corrupted = Command::new(directory.join("oracle"))
            .arg("corrupt")
            .output()
            .unwrap();
        fs::write(directory.join("corrupt.stdout"), &corrupted.stdout).unwrap();
        fs::write(directory.join("corrupt.stderr"), &corrupted.stderr).unwrap();
        assert!(
            !corrupted.status.success(),
            "corrupted vector oracle unexpectedly passed"
        );
        assert!(String::from_utf8_lossy(&corrupted.stderr)
            .contains("math mismatch width=1 sample=0 lane=0 operation=0"));
        println!("fixed-vector QA: 110968 defined observations and corrupted-oracle rejection; artifacts {}",directory.display());
    }
}
