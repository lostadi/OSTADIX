//! Raw original-object CIE facts to the actual core source-CFI evaluator.
//! A selected raw FDE backreference is not a source-function or emitted-PC proof.
use super::cie_raw_decoder::{self, RawCieObject, RawRecord, RawSpan, RegisterRule};
use anyhow::{bail, Context, Result};
use o_lang::ocore::native_machine_ir::{
    ArtifactIdentity, DirectTailTarget, MachineBodyContract, SelectedInstructionInventory, SourceSpan,
};
use o_lang::ocore::native_machine_verify::{
    self, CfiInitialCfa, CfiInitialCie, CfiRegisterRule, CfiRegisterState,
    CfiSourceProgramWithInitialCie, CfiSourceScope,
};
use o_lang::ocore::Target;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OriginalFdeSelection {
    /// Caller-declared function association, checked but not authenticated.
    pub source_scope: CfiSourceScope,
    pub frame_section_index: usize,
    pub fde_section_offset: usize,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct OriginalCieSourceProgram {
    pub raw_object: RawCieObject,
    pub selected_fde: OriginalFdeSelection,
    pub source_program: CfiSourceProgramWithInitialCie,
}
fn object_span(raw: &RawSpan) -> Result<SourceSpan> {
    Ok(SourceSpan {
        start: raw.object_offset,
        end: raw
            .object_offset
            .checked_add(u64::try_from(raw.bytes.len())?)
            .context("CIE adapter object span overflow")?,
    })
}
/// Convert checked raw facts only. Complete source structural/initial-rule
/// validation is performed by verify_source_cfi_from_original_fde below.
pub(crate) fn decode_initial_cie(
    bytes: &[u8],
    selected: &OriginalFdeSelection,
) -> Result<(RawCieObject, CfiInitialCie)> {
    let object = cie_raw_decoder::decode_elf64_le_rel(bytes)?;
    let initial = initial_cie_from_object(&object, selected)?;
    Ok((object, initial))
}

fn initial_cie_from_object(
    object: &RawCieObject,
    selected: &OriginalFdeSelection,
) -> Result<CfiInitialCie> {
    let architecture = native_machine_verify::cfi_elf_architecture(object.machine)
        .map_err(|error| anyhow::anyhow!(error.message))?;
    if architecture != selected.source_scope.profile.architecture {
        bail!("original CIE ELF machine differs from source profile architecture");
    }
    let section = object
        .sections
        .iter()
        .find(|section| section.index == selected.frame_section_index)
        .context("selected original FDE frame section is absent")?;
    let fde = section
        .records
        .iter()
        .find_map(|record| match record {
            RawRecord::Fde(fde) if fde.range.section_offset == selected.fde_section_offset => {
                Some(fde)
            }
            _ => None,
        })
        .context("selected original FDE record is absent")?;
    let cie_offset = fde
        .cie_section_offset
        .context("selected original FDE has no checked CIE backreference")?;
    let cie = section
        .records
        .iter()
        .find_map(|record| match record {
            RawRecord::Cie(cie) if cie.range.section_offset == cie_offset => Some(cie),
            _ => None,
        })
        .context("selected original FDE CIE is absent")?;
    let header = cie
        .header
        .as_ref()
        .context("original CIE header is absent")?;
    let initial_bytes = cie
        .initial_instructions
        .as_ref()
        .context("original CIE initial instructions are absent")?;
    let rules = cie
        .initial_rules
        .as_ref()
        .context("original CIE initial rules are absent")?;
    if rules.machine != object.machine {
        bail!("original CIE initial-rule machine differs from ELF header");
    }
    let cfa = rules.require_cfa()?;
    let register = |column| {
        native_machine_verify::cfi_dwarf_register(architecture, column)
            .map_err(|error| anyhow::anyhow!(error.message))
    };
    let mut registers = Vec::new();
    for (&column, rule) in &rules.registers {
        let rule = match rule {
            RegisterRule::Undefined => CfiRegisterRule::Undefined,
            RegisterRule::SameValue => CfiRegisterRule::SameValue,
            RegisterRule::CfaOffset(offset) => CfiRegisterRule::CfaOffset { offset: *offset },
            RegisterRule::CfaValueOffset(offset) => {
                CfiRegisterRule::CfaValueOffset { offset: *offset }
            }
            RegisterRule::Register(source) => CfiRegisterRule::Register {
                register: register(*source)?,
            },
        };
        registers.push(CfiRegisterState {
            register: register(column)?,
            rule,
        });
    }
    // The raw decoder has already applied signed data-alignment scaling.
    let initial = CfiInitialCie {
        source_scope: selected.source_scope.clone(),
        object: ArtifactIdentity {
            bytes: u64::try_from(object.object_bytes)?,
            sha256: object.object_sha256.clone(),
        },
        architecture,
        elf_machine: object.machine,
        elf_flags: object.elf_flags,
        frame_section_index: u64::try_from(section.index)?,
        cie_section_offset: u64::try_from(cie.range.section_offset)?,
        fde_section_offset: u64::try_from(fde.range.section_offset)?,
        cie_record: object_span(&cie.range)?,
        fde_record: object_span(&fde.range)?,
        initial_instructions: object_span(initial_bytes)?,
        code_alignment: header.code_alignment,
        data_alignment: header.data_alignment,
        return_column: header.return_column,
        cfa: Some(CfiInitialCfa {
            register: register(cfa.register)?,
            offset: cfa.offset,
        }),
        registers,
    };
    Ok(initial)
}
/// Actual decoder -> typed adapter -> same complete shared structural verifier.
/// Neither an arbitrary selected FDE nor its unresolved pointer establishes
/// function/source association, emitted instruction PCs, ABI or unwind execution.
pub(crate) fn verify_source_cfi_from_original_fde(
    bytes: &[u8],
    selected: &OriginalFdeSelection,
    body: &MachineBodyContract,
    inventory: &SelectedInstructionInventory,
    target: Target,
) -> Result<OriginalCieSourceProgram> {
    let (raw_object, initial) = decode_initial_cie(bytes, selected)?;
    let source_program = native_machine_verify::verify_cfi_source_program_with_initial_cie(
        body, inventory, target, &initial,
    )
    .map_err(|error| anyhow::anyhow!("source CFI initial-rule verification: {}", error.message))?;
    Ok(OriginalCieSourceProgram {
        raw_object,
        selected_fde: selected.clone(),
        source_program,
    })
}


/// Caller-held original object and symbol selection. The body/source relation
/// is externally selected; same-object ELF range consistency is checked here.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct OriginalFunctionSelection {
    pub source_scope: CfiSourceScope,
    pub object_identity: ArtifactIdentity,
    pub function: cie_raw_decoder::fde_function::SymbolKey,
}
/// Reuse one immutable checked object for multiple independently held function
/// choices. No object serialization/reparse, fresh path cache, CIE defaults or
/// source-production authority is introduced. Existing CIE/body checks remain.
pub(crate) fn verify_source_cfi_from_checked_original_function(
    object_functions: &cie_raw_decoder::fde_function::CheckedObjectFunctions,
    selected: &OriginalFunctionSelection,
    body: &MachineBodyContract,
    inventory: &SelectedInstructionInventory,
    target: Target,
) -> Result<(OriginalFdeSelection, CfiSourceProgramWithInitialCie)> {
    let locator = object_functions.selected_fde(&selected.object_identity, selected.function)?;
    object_functions.require_initial_rules_decoded()?;
    let selected_fde = OriginalFdeSelection {
        source_scope: selected.source_scope.clone(),
        frame_section_index: locator.frame_section_index,
        fde_section_offset: locator.fde_section_offset,
    };
    let initial = initial_cie_from_object(object_functions.raw_object(), &selected_fde)?;
    let source_program = native_machine_verify::verify_cfi_source_program_with_initial_cie(body, inventory, target, &initial)?;
    Ok((selected_fde, source_program))
}

/// Held-policy overload preserving original object/FDE/initial-rule checks.
/// Complete-unit/callee verification remains with the caller; this source-CFI
/// adapter grants neither same-produced association nor native unwind authority.
pub(crate) fn verify_source_cfi_from_checked_original_function_with_tail_targets(
    object_functions: &cie_raw_decoder::fde_function::CheckedObjectFunctions,
    selected: &OriginalFunctionSelection,
    body: &MachineBodyContract,
    inventory: &SelectedInstructionInventory,
    target: Target,
    tail_targets: &[DirectTailTarget],
) -> Result<(OriginalFdeSelection, CfiSourceProgramWithInitialCie)> {
    let locator = object_functions.selected_fde(&selected.object_identity, selected.function)?;
    object_functions.require_initial_rules_decoded()?;
    let selected_fde = OriginalFdeSelection {
        source_scope: selected.source_scope.clone(),
        frame_section_index: locator.frame_section_index,
        fde_section_offset: locator.fde_section_offset,
    };
    let initial = initial_cie_from_object(object_functions.raw_object(), &selected_fde)?;
    let source_program = native_machine_verify::verify_cfi_source_program_with_initial_cie_and_tail_targets(
        body, inventory, target, &initial, tail_targets)?;
    Ok((selected_fde, source_program))
}

// Callers retain CheckedObjectFunctions across selection/body failures. No
// bytes-to-success-only wrapper consumes and discards the full failure inventory.

#[cfg(test)]
#[path = "cie_source_adapter_tests.rs"]
mod tests;
