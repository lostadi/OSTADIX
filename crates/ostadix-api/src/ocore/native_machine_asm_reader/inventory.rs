//! Select complete configured-text membership before owned construction.
//!
//! This is a source-selection prerequisite, not capture admission. The caller
//! must already hold the original bytes, configured bytes, build/event selection
//! and target profile independently of any newly constructed machine artifact.
//! No interface, body, symbol declaration, dependency or ABI is inferred here.
//!
//! The implemented origin policy is exact byte identity with a selected original
//! file. It also works for an unchanged `.S` input; suffixes grant no authority.
//! A transformed `.S` stage needs a real producer-held expansion map. CPP line
//! directives, a retained stage candidate, or an artifact's own metadata do not
//! supply that map, so this factory explicitly refuses nonidentity origins.

use super::{
    check_floor, identity, kind, profile, read_configured_assembly, statements, ParsedAssembly,
    ReadError, ReadSelection, RequiredRecord, SyntaxInventory, SYNTAX_INVENTORY_FORMAT,
};
use crate::ocore::common::Target;
use crate::ocore::native_machine_ir::{MachineProfile, OriginalSpan, SourceWitness};

/// An exact, caller-held configured-text floor. There is deliberately no public
/// field constructor or Deserialize implementation. Its records are enumerated
/// from all original configured statements, never from successful parse/lift
/// results or from a newly supplied machine artifact.
///
/// This does not authenticate the caller's source/build claims. The existing
/// reader consequently leaves source, admission and qualification flags false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedSyntaxFloor {
    configured: Vec<u8>,
    selection: ReadSelection,
    inventory_json: Vec<u8>,
    identity_origin_file: u64,
}

impl SelectedSyntaxFloor {
    pub fn configured_assembly(&self) -> &[u8] {
        &self.configured
    }

    pub fn selection(&self) -> &ReadSelection {
        &self.selection
    }

    pub fn inventory_json(&self) -> &[u8] {
        &self.inventory_json
    }

    pub fn identity_origin_file(&self) -> u64 {
        self.identity_origin_file
    }

    /// Consume the originally selected buffers through the real syntax reader.
    /// Unsupported records remain in the result and keep syntax support false.
    pub fn read(&self, target: Target) -> Result<ParsedAssembly, ReadError> {
        self.read_configured(self.configured_assembly(), target)
    }

    /// Check another consumed buffer against the held original floor. This does
    /// not select a new floor or permit a fresh result to redefine membership.
    pub fn read_configured(
        &self,
        configured: &[u8],
        target: Target,
    ) -> Result<ParsedAssembly, ReadError> {
        read_configured_assembly(configured, &self.selection, &self.inventory_json, target)
    }
}

/// Derive every record's ID, kind, span and identity origin from the held source.
/// Comments/trivia retain their byte positions through the existing lexer;
/// unsupported directives and instructions are not filtered out.
///
/// The two byte arguments are separately checked against their selected claims
/// and compared in full. This establishes only an identity origin mapping. It
/// cannot establish frontend consumption, expansion attribution, include/incbin
/// closure, a complete original unit, machine interfaces or native admission.
pub fn select_identity_mapped_source(
    configured: &[u8],
    original_file: &[u8],
    original_file_id: u64,
    source: &SourceWitness,
    selected_profile: &MachineProfile,
    target: Target,
) -> Result<SelectedSyntaxFloor, ReadError> {
    let mut matching = source.files.iter().filter(|file| file.id == original_file_id);
    let selected_file = matching.next().ok_or_else(|| {
        ReadError::Inventory("selected identity-origin original file is absent".into())
    })?;
    if matching.next().is_some() {
        return Err(ReadError::Inventory(
            "selected identity-origin original file is duplicated".into(),
        ));
    }
    if identity(original_file) != selected_file.identity {
        return Err(ReadError::Identity(
            "held original file bytes differ from selected original file".into(),
        ));
    }
    if identity(configured) != source.decoded_assembly {
        return Err(ReadError::Identity(
            "held configured bytes differ from selected configured input".into(),
        ));
    }
    if configured != original_file {
        return Err(ReadError::Inventory(
            "nonidentity configured-source origins require an independently established expansion mapping; CPP line directives do not establish one".into(),
        ));
    }

    // Validate the target before invoking the target-specific lexer. The final
    // inventory identity is assigned only after every lexical record exists.
    let mut selection = ReadSelection {
        source: source.clone(),
        profile: selected_profile.clone(),
        inventory: identity(&[]),
    };
    profile(&selection, target)?;
    let mut records = Vec::new();
    for (index, (span, text)) in
        statements(configured, selected_profile.architecture)?.into_iter().enumerate()
    {
        let id = u64::try_from(index)
            .map_err(|_| ReadError::Inventory("syntax record ID exceeds u64".into()))?;
        records.push(RequiredRecord {
            id,
            kind: kind(&text),
            span,
            origins: vec![OriginalSpan {
                file: original_file_id,
                span,
            }],
        });
    }
    let inventory = SyntaxInventory {
        format: SYNTAX_INVENTORY_FORMAT.into(),
        source: source.clone(),
        profile: selected_profile.clone(),
        records,
    };
    let inventory_json = serde_json::to_vec(&inventory)
        .map_err(|error| ReadError::Inventory(format!("cannot encode syntax inventory: {error}")))?;
    selection.inventory = identity(&inventory_json);
    // Reuse the consumer's complete source/file/span/version checks. In
    // particular, empty inventories and malformed source claims do not pass.
    check_floor(configured, &selection, &inventory_json)?;
    Ok(SelectedSyntaxFloor {
        configured: configured.to_vec(),
        selection,
        inventory_json,
        identity_origin_file: original_file_id,
    })
}

#[cfg(test)]
mod tests;
