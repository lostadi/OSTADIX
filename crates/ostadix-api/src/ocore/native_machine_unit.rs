//! Whole-unit typed foundation, not an assembler lifter or native admission.
//!
//! The independently selected raw inventory is consumed and SHA-bound. Matching
//! it is relative structural coverage, never proof that its author inventoried
//! the original implementation completely. Configured bytes are identity input,
//! not an executable payload. There is no opaque assembly/native/blob operation.
//! Existing MachineBody semantics/entry/provider guards remain unchanged.
use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use super::common::Target;
use super::native_machine_ir::*;
use super::native_machine_verify;

pub const UNIT_FORMAT: &str = "ocore-machine-whole-unit-contract-v1";
pub const UNIT_INVENTORY_FORMAT: &str = "ocore-selected-machine-whole-unit-inventory-v1";
pub type SectionId = u64;
pub type SymbolId = u64;
pub type InitializerId = u64;
pub type RelocationId = u64;
pub type BodyId = u64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SectionKind { ProgramBits, NoBits, Note }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitSection {
    pub id: SectionId, pub name: String, pub kind: SectionKind,
    /// Exact declared ELF-style flags; their platform realization is unproved.
    pub flags: Vec<u8>, pub alignment: u64,
    /// None preserves an explicit unresolved target-layout obligation.
    pub byte_size: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "name", rename_all = "snake_case", deny_unknown_fields)]
pub enum SymbolName {
    Named { value: String },
    NumericLocal { number: u64, definition_record: SourceItemId },
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SymbolBinding { Local, Global, Weak }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SymbolVisibility { Default, Hidden, Protected }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind { NoType, Object, Function, TlsObject }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "anchor", rename_all = "snake_case", deny_unknown_fields)]
pub enum SizeAnchor {
    Symbol { symbol: SymbolId },
    CurrentLocation { record: SourceItemId, section: SectionId },
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "size", rename_all = "snake_case", deny_unknown_fields)]
pub enum SymbolSize {
    Unspecified, Bytes { bytes: u64 },
    Difference { end: SizeAnchor, start: SizeAnchor, addend: i64 },
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "definition", rename_all = "snake_case", deny_unknown_fields)]
pub enum SymbolDefinition {
    Undefined,
    InSection { section: SectionId, offset: u64 },
    Body { section: SectionId, body: BodyId },
    Alias { target: SymbolId, addend: i64 },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitSymbol {
    pub id: SymbolId, pub name: SymbolName, pub binding: SymbolBinding,
    pub visibility: SymbolVisibility, pub kind: SymbolKind,
    pub size: SymbolSize, pub definition: SymbolDefinition,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelocationKind {
    Absolute, PcRelative, GotPcRelative, GotPcRelativeRelaxed,
    RexGotPcRelativeRelaxed, Got, Plt, TlsTpOffset, GlobalPointerOffset,
    PcRelativeHigh, PcRelativeLow, AbsoluteHigh, AbsoluteLow,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitRelocation {
    pub id: RelocationId, pub section: SectionId, pub offset: u64,
    pub architecture: Architecture, pub bytes: u8,
    pub kind: RelocationKind, pub target: SymbolId,
    pub addend: i64,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "layout", rename_all = "snake_case", deny_unknown_fields)]
pub enum AlignmentLayout {
    Applied { offset: u64, padding: u64 },
    Skipped { offset: u64, required_padding: u64 },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "initializer", rename_all = "snake_case", deny_unknown_fields)]
pub enum InitializerValue {
    Bytes { value: Vec<u8> },
    RepeatByte { byte: u8, count: u64 },
    /// Explicit loader zero-fill, distinct from file-backed zero bytes.
    ZeroFill { bytes: u64 },
    /// A typed unresolved reference, not a supplied address or native blob.
    Relocation { relocation: RelocationId, bytes: u8 },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitInitializer {
    pub id: InitializerId, pub section: SectionId, pub offset: u64,
    pub value: InitializerValue,
}
impl InitializerValue {
    fn extent(&self) -> u64 { match self {
        Self::Bytes { value } => value.len() as u64,
        Self::RepeatByte { count, .. } => *count,
        Self::ZeroFill { bytes } => *bytes,
        Self::Relocation { bytes, .. } => u64::from(*bytes),
    }}
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitAlignment {
    pub id: u64, pub section: SectionId,
    pub boundary: u64, pub fill: Option<u8>, pub maximum_skip: Option<u64>,
    /// These bytes must also appear as explicit initializer storage if layout
    /// is resolved. None retains an unresolved padding/layout obligation.
    pub layout: Option<AlignmentLayout>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequiredBody {
    pub id: BodyId, pub symbol: SymbolId,
    /// Raw JSON identity and its separate embedded legacy claim are distinct;
    /// demanding that JSON contain its own full raw SHA would be circular.
    pub inventory: ArtifactIdentity, pub machine_inventory_claim: ArtifactIdentity,
    pub record_ids: Vec<SourceItemId>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitBody {
    pub id: BodyId, pub symbol: SymbolId,
    pub contract: MachineBodyContract,
    /// Consumed as selected JSON; not imported as a dynamic helper or executed.
    pub selected_inventory_json: Vec<u8>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnitRecordKind {
    Instruction, Label, Section, Symbol, Data, Relocation, Alignment,
    Cfi, Debug, Preprocessor,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "effect", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordEffect {
    SelectSection { section: SectionId },
    DefineSymbol { symbol: SymbolId },
    Binding { symbol: SymbolId, binding: SymbolBinding },
    Visibility { symbol: SymbolId, visibility: SymbolVisibility },
    SymbolType { symbol: SymbolId, kind: SymbolKind },
    SymbolSize { symbol: SymbolId, size: SymbolSize },
    Alias { symbol: SymbolId, target: SymbolId, addend: i64, equ: bool },
    Initialize { initializer: InitializerId },
    Relocate { relocation: RelocationId },
    Alignment { alignment: u64 },
    BodyItem { body: BodyId },
    /// Typed debug/source-mapping payload; no numeric instruction effect.
    File { number: Option<u64>, path: Vec<u8> },
    Location { file: u64, line: u64, column: u64 },
    PreprocessorMarker { line: u64, path: Vec<u8>, flags: Vec<u8> },
    /// Required records never disappear when an implementation is absent.
    Unrepresented { feature: String, reason: String },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitRecord {
    pub id: SourceItemId, pub kind: UnitRecordKind,
    pub span: SourceSpan, pub origins: Vec<OriginalSpan>,
    pub effects: Vec<RecordEffect>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "use", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalUse {
    Declaration, Relocation { relocation: RelocationId },
    Alias { symbol: SymbolId }, Size { symbol: SymbolId },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalObligation {
    pub symbol: SymbolId, pub uses: Vec<ExternalUse>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitDeclarations {
    pub sections: Vec<UnitSection>, pub symbols: Vec<UnitSymbol>,
    pub initializers: Vec<UnitInitializer>, pub relocations: Vec<UnitRelocation>,
    pub alignments: Vec<UnitAlignment>, pub records: Vec<UnitRecord>,
    pub external_obligations: Vec<ExternalObligation>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelectedUnitInventory {
    pub format: String, pub source: SourceWitness, pub profile: MachineProfile,
    /// Exact independent required declarations/records, including cold bodies.
    pub required: UnitDeclarations, pub bodies: Vec<RequiredBody>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineUnit {
    pub format: String, pub selected_inventory: ArtifactIdentity,
    pub source: SourceWitness, pub profile: MachineProfile,
    pub declarations: UnitDeclarations, pub bodies: Vec<UnitBody>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSelection {
    pub source: SourceWitness, pub profile: MachineProfile,
    /// Selected by the owning source/build producer OUTSIDE the consumed JSON.
    pub inventory: ArtifactIdentity,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitError(pub String);
impl std::fmt::Display for UnitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for UnitError {}
type Result<T> = std::result::Result<T, UnitError>;
fn require(ok: bool, message: &str) -> Result<()> { if ok { Ok(()) } else { Err(UnitError(message.into())) } }
fn artifact(raw: &[u8]) -> ArtifactIdentity { ArtifactIdentity { bytes: raw.len() as u64, sha256: format!("{:x}", Sha256::digest(raw)) } }
fn identity(i: &ArtifactIdentity) -> Result<()> {
    require(i.bytes > 0 && i.sha256.len() == 64 && i.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "invalid nonempty selected artifact identity")
}
fn unique<'a, T>(rows: &'a [T], key: impl Fn(&T) -> u64, what: &str) -> Result<BTreeMap<u64, &'a T>> {
    let mut out = BTreeMap::new();
    for row in rows { require(out.insert(key(row), row).is_none(), what)?; }
    Ok(out)
}
fn named(n: &SymbolName) -> bool { match n {
    SymbolName::Named { value } => !value.is_empty() && !value.as_bytes()[0].is_ascii_digit() && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.$".contains(&b)),
    SymbolName::NumericLocal { .. } => true,
}}
fn compatible(profile: &MachineProfile, target: Target) -> Result<()> {
    let (architecture, abi, remainder) = match target {
        Target::X86_64UnknownNone => (Architecture::X86_64, vec![MachineAbi::SysvAmd64], 8),
        Target::Aarch64UnknownNone => (Architecture::Aarch64, vec![MachineAbi::Aapcs64], 0),
        Target::Riscv64UnknownNone => (Architecture::Rv64, vec![MachineAbi::RiscvLp64, MachineAbi::RiscvLp64d], 0),
    };
    require(profile.architecture == architecture && abi.contains(&profile.abi) && profile.address_bits == 64 && profile.byte_order == ByteOrder::Little, "unit target/ABI/address layout mismatch; i686/ARMv7 are unsupported")?;
    require(profile.entry_stack_alignment == 16 && profile.entry_stack_remainder == remainder, "unit stack ABI profile mismatch")?;
    require(profile.features == vec![StateFeature::UserRegisterBits], "unit requires an unimplemented platform/security/floating state realization")
}
fn source(s: &SourceWitness) -> Result<()> {
    require(s.format == SOURCE_FORMAT && s.input_form == MachineInputForm::ConfiguredAssemblyText && !s.unit_id.is_empty() && !s.files.is_empty(), "missing original unit/source claim")?;
    identity(&s.decoded_assembly)?; identity(&s.build_configuration)?; identity(&s.frontend_event)?;
    let mut ids=BTreeSet::new(); let mut paths=BTreeSet::new();
    for f in &s.files {
        identity(&f.identity)?;
        require(ids.insert(f.id) && paths.insert(&f.logical_path) && !f.logical_path.starts_with('/') && !f.logical_path.contains(['\\','\0']) && f.logical_path.split('/').all(|p| !p.is_empty() && p != "." && p != ".."), "duplicate/invalid original source file claim")?;
    }
    Ok(())
}
fn interval(offset: u64, bytes: u64, size: Option<u64>) -> Result<u64> {
    let end=offset.checked_add(bytes).ok_or_else(||UnitError("section interval overflow".into()))?;
    require(size.is_none_or(|n| end<=n), "initializer/relocation/symbol outside selected section extent")?; Ok(end)
}
fn alias_graph(symbols: &BTreeMap<u64,&UnitSymbol>) -> Result<()> {
    for &id in symbols.keys() {
        let mut seen=BTreeSet::new(); let mut next=id;
        loop {
            require(seen.insert(next), "symbol alias cycle")?;
            let s=symbols.get(&next).ok_or_else(||UnitError("alias references missing symbol".into()))?;
            if let SymbolDefinition::Alias {target,..}=s.definition { next=target; } else { break; }
        }
    }
    Ok(())
}
#[derive(Debug, Clone, Serialize)]
pub struct UnitReport {
    pub format: &'static str, pub target: &'static str,
    pub checked_records: usize, pub checked_symbols: usize,
    pub checked_initializers: usize, pub checked_relocations: usize,
    pub checked_bodies: usize, pub unresolved_external_symbols: usize,
    pub unresolved_layout_sections: usize,
    pub structural_coverage_relative_to_selected_inventory: bool,
    pub source_custody_verified: bool, pub inventory_authority_verified: bool,
    pub original_unit_completeness_verified: bool,
    pub instruction_semantics_verified: bool, pub directive_semantics_verified: bool,
    pub target_relocation_realization_verified: bool,
    pub native_realization_verified: bool, pub provider_qualified: bool,
    pub artifact_qualified: bool, pub runtime_qualified: bool,
    pub isa_equivalence_qualified: bool, pub ordinary_native_admission: bool,
}

/// Verify typed references/storage and EXACT required membership from consumed,
/// independently selected inventory bytes. No production importer may synthesize
/// that inventory by enumerating only successes. This API proves no ISA meaning.
pub fn verify_unit(unit: &MachineUnit, selection: &UnitSelection, required_inventory_json: &[u8], configured_assembly: &[u8], target: Target) -> Result<UnitReport> {
    require(unit.format == UNIT_FORMAT, "unit format mismatch")?;
    compatible(&unit.profile,target)?; source(&unit.source)?; identity(&selection.inventory)?;
    require(artifact(required_inventory_json)==selection.inventory && unit.selected_inventory==selection.inventory, "consumed selected unit inventory bytes differ")?;
    require(artifact(configured_assembly)==unit.source.decoded_assembly, "consumed configured source bytes differ")?;
    let floor:SelectedUnitInventory=serde_json::from_slice(required_inventory_json).map_err(|e|UnitError(format!("invalid typed selected unit inventory: {e}")))?;
    require(floor.format==UNIT_INVENTORY_FORMAT && floor.source==unit.source && floor.profile==unit.profile && selection.source==unit.source && selection.profile==unit.profile, "selected unit source/profile/target differs")?;
    let d=&unit.declarations;
    let sections=unique(&d.sections,|v|v.id,"duplicate section id")?;
    let symbols=unique(&d.symbols,|v|v.id,"duplicate symbol id")?;
    let initializers=unique(&d.initializers,|v|v.id,"duplicate initializer id")?;
    let relocations=unique(&d.relocations,|v|v.id,"duplicate relocation id")?;
    let alignments=unique(&d.alignments,|v|v.id,"duplicate alignment id")?;
    let records=unique(&d.records,|v|v.id,"duplicate original record id")?;
    let bodies=unique(&unit.bodies,|v|v.id,"duplicate body id")?;
    require(symbols.keys().copied().collect::<BTreeSet<_>>()==floor.required.symbols.iter().map(|v|v.id).collect(),"required original symbol membership differs")?;
    require(initializers.keys().copied().collect::<BTreeSet<_>>()==floor.required.initializers.iter().map(|v|v.id).collect(),"required initializer membership differs")?;
    require(relocations.keys().copied().collect::<BTreeSet<_>>()==floor.required.relocations.iter().map(|v|v.id).collect(),"required relocation membership differs")?;
    require(!sections.is_empty() && !records.is_empty(), "empty complete unit section/record inventory")?;
    let mut section_names=BTreeSet::new();let mut symbol_names=BTreeSet::new();
    for s in &d.sections {
        require(!s.name.is_empty() && !s.name.contains(['\0','\\']) && section_names.insert(&s.name) && s.alignment.is_power_of_two(), "invalid/duplicate section name/alignment")?;
        let flags:BTreeSet<_>=s.flags.iter().collect();require(flags.len()==s.flags.len(),"duplicate section flag")?;
    }
    for s in &d.symbols {
        require(named(&s.name)&&symbol_names.insert(&s.name), "invalid/duplicate symbol name")?;
        match s.definition {
            SymbolDefinition::Undefined=>{},
            SymbolDefinition::InSection{section,offset}=>{let sec=sections.get(&section).ok_or_else(||UnitError("symbol references missing section".into()))?;let bytes=if let SymbolSize::Bytes{bytes}=s.size{bytes}else{0};interval(offset,bytes,sec.byte_size)?;},
            SymbolDefinition::Body{section,body}=>{require(sections.contains_key(&section),"body symbol references missing section")?;let b=bodies.get(&body).ok_or_else(||UnitError("symbol references missing body".into()))?;require(s.kind==SymbolKind::Function&&b.symbol==s.id,"body symbol type/identity mismatch")?;},
            SymbolDefinition::Alias{target,..}=>require(symbols.contains_key(&target),"alias references missing symbol")?,
        }
        if let SymbolName::NumericLocal{definition_record,..}=&s.name {let r=records.get(definition_record).ok_or_else(||UnitError("numeric label definition record missing".into()))?;require(r.kind==UnitRecordKind::Label,"numeric label source record kind mismatch")?;require(r.effects.iter().any(|e|matches!(e,RecordEffect::DefineSymbol{symbol}if *symbol==s.id)),"numeric label definition record does not define this symbol")?;}
        if let SymbolSize::Difference{end,start,..}=s.size {for a in [end,start]{match a{
            SizeAnchor::Symbol{symbol}=>require(symbols.contains_key(&symbol),"symbol size references missing original symbol")?,
            SizeAnchor::CurrentLocation{record,section}=>require(records.contains_key(&record)&&sections.contains_key(&section),"size current-location anchor missing")?,
        }}}
    }
    alias_graph(&symbols)?;
    // Every typed body has a converse, exact symbol owner. A plain InSection
    // declaration is not a substitute for the Body definition of that function.
    let mut body_sections_by_id=BTreeMap::<BodyId,SectionId>::new();
    for b in &unit.bodies {
        let owner=symbols.get(&b.symbol).ok_or_else(||UnitError("body references missing symbol".into()))?;
        let section=match owner.definition {
            SymbolDefinition::Body{section,body}if body==b.id&&owner.kind==SymbolKind::Function=>section,
            _=>return Err(UnitError("body lacks exact converse symbol/body definition".into())),
        };
        require(sections.contains_key(&section),"body owner references missing section")?;
        body_sections_by_id.insert(b.id,section);
    }
    let mut intervals:BTreeMap<SectionId,Vec<(u64,u64)>>=BTreeMap::new();let mut relocation_uses=BTreeMap::<u64,usize>::new();
    for i in &d.initializers {
        let sec=sections.get(&i.section).ok_or_else(||UnitError("initializer references missing section".into()))?;
        let extent=i.value.extent();let end=interval(i.offset,extent,sec.byte_size)?;
        if extent>0 {intervals.entry(i.section).or_default().push((i.offset,end));}
        match &i.value {
            InitializerValue::ZeroFill{..}=>require(sec.kind==SectionKind::NoBits,"loader zero-fill requires NOBITS section")?,
            InitializerValue::Bytes{..}|InitializerValue::RepeatByte{..}=>require(matches!(sec.kind,SectionKind::ProgramBits|SectionKind::Note),"file-backed initializer cannot disappear into NOBITS")?,
            InitializerValue::Relocation{relocation,bytes}=>{let r=relocations.get(relocation).ok_or_else(||UnitError("initializer references missing relocation".into()))?;require(sec.kind==SectionKind::ProgramBits&&r.section==i.section&&r.offset==i.offset&&r.bytes==*bytes,"initializer/relocation section/offset/width mismatch")?;*relocation_uses.entry(*relocation).or_default()+=1;},
        }
    }
    for ranges in intervals.values_mut() {ranges.sort_unstable();for pair in ranges.windows(2){require(pair[0].1<=pair[1].0,"overlapping initializer storage")?;}}
    for r in &d.relocations {
        let s=sections.get(&r.section).ok_or_else(||UnitError("relocation references missing section".into()))?;
        require(r.architecture==unit.profile.architecture,"relocation target architecture mismatch")?;
        require([1,2,4,8,16].contains(&r.bytes)&&symbols.contains_key(&r.target),"relocation width/target is unsupported or missing")?;interval(r.offset,u64::from(r.bytes),s.byte_size)?;
        require(relocation_uses.get(&r.id)==Some(&1),"relocation lacks exactly one typed initializer slot")?;
    }
    // Resolved data sections cannot hide missing original storage in gaps.
    let body_sections:BTreeSet<_>=d.symbols.iter().filter_map(|s|if let SymbolDefinition::Body{section,..}=s.definition{Some(section)}else{None}).collect();
    for s in &d.sections {if let Some(size)=s.byte_size {if !body_sections.contains(&s.id){let mut end=0;for &(a,b) in intervals.get(&s.id).into_iter().flatten(){require(a==end,"resolved section has unaccounted storage gap")?;end=b;}require(end==size,"resolved section has missing initializer/zero-fill storage")?;}}}
    for a in &d.alignments {
        let s=sections.get(&a.section).ok_or_else(||UnitError("alignment references missing section".into()))?;require(a.boundary.is_power_of_two(),"invalid byte alignment boundary")?;
        if let Some(layout)=a.layout {
            let offset=match layout{AlignmentLayout::Applied{offset,..}|AlignmentLayout::Skipped{offset,..}=>offset};
            let required=(a.boundary-offset%a.boundary)%a.boundary;
            match layout {
                AlignmentLayout::Applied{padding,..}=>{
                    interval(offset,padding,s.byte_size)?;require(padding==required&&a.maximum_skip.is_none_or(|n|padding<=n),"resolved alignment padding/max-skip mismatch")?;
                    let end=offset+padding;let mut covered=offset;
                    for &(lo,hi)in intervals.get(&a.section).into_iter().flatten(){if hi<=covered{continue;}if lo>covered||covered==end{break;}covered=hi.min(end);}
                    require(covered==end,"alignment padding has missing explicit storage")?;
                    if let Some(fill)=a.fill {
                        for i in &d.initializers {if i.section==a.section {let hi=i.offset+i.value.extent();let lo=i.offset.max(offset);let stop=hi.min(end);if lo<stop {
                            let same=match &i.value {
                                InitializerValue::Bytes{value}=>value[(lo-i.offset)as usize..(stop-i.offset)as usize].iter().all(|b|*b==fill),
                                InitializerValue::RepeatByte{byte,..}=>*byte==fill,
                                InitializerValue::ZeroFill{..}=>fill==0,
                                InitializerValue::Relocation{..}=>false,
                            };require(same,"explicit alignment fill differs from saved padding storage")?;
                        }}}
                    }
                },
                AlignmentLayout::Skipped{required_padding,..}=>{
                    interval(offset,0,s.byte_size)?;require(required_padding==required&&a.maximum_skip.is_some_and(|n|required_padding>n),"alignment skip does not follow original max-skip")?;
                },
            }
        }
    }
    let mut external=BTreeMap::<SymbolId,BTreeSet<ExternalUse>>::new();
    for s in &d.symbols {if s.definition==SymbolDefinition::Undefined{external.entry(s.id).or_default().insert(ExternalUse::Declaration);}}
    for r in &d.relocations {if let Some(v)=external.get_mut(&r.target){v.insert(ExternalUse::Relocation{relocation:r.id});}}
    for s in &d.symbols {
        if let SymbolDefinition::Alias{target,..}=s.definition {if let Some(v)=external.get_mut(&target){v.insert(ExternalUse::Alias{symbol:s.id});}}
        if let SymbolSize::Difference{end,start,..}=s.size {for a in [end,start]{if let SizeAnchor::Symbol{symbol:target}=a{if let Some(v)=external.get_mut(&target){v.insert(ExternalUse::Size{symbol:s.id});}}}}
    }
    let mut actual_external=BTreeMap::new();
    for e in &d.external_obligations {let uses:BTreeSet<_>=e.uses.iter().cloned().collect();require(uses.len()==e.uses.len()&&actual_external.insert(e.symbol,uses).is_none(),"duplicate external obligation/use")?;}
    require(actual_external==external,"unresolved external obligations omit/add original dependency uses")?;
    let source_files:BTreeMap<_,_>=unit.source.files.iter().map(|f|(f.id,f.identity.bytes)).collect();let mut prior=0;let mut init_records=BTreeSet::new();let mut reloc_records=BTreeSet::new();let mut align_records=BTreeSet::new();let mut body_records=BTreeMap::<BodyId,BTreeSet<u64>>::new();let mut unsupported=Vec::new();
    let mut definitions=BTreeSet::new();let mut bindings=BTreeMap::new();let mut visibilities=BTreeMap::new();let mut types=BTreeMap::new();let mut sizes=BTreeMap::new();let mut aliases=BTreeMap::new();let mut current_section=None;
    for r in &d.records {
        require(r.span.start>=prior&&r.span.start<r.span.end&&r.span.end<=configured_assembly.len()as u64&&!r.origins.is_empty()&&!r.effects.is_empty(),"original record span/order/origin/effects missing")?;prior=r.span.end;
        for o in &r.origins {require(o.span.start<o.span.end&&source_files.get(&o.file).is_some_and(|n|o.span.end<=*n),"record original source reference out of range")?;}
        for e in &r.effects {
            let kind_ok=match e {
                RecordEffect::SelectSection{section}=>{require(sections.contains_key(section),"record references missing section")?;current_section=Some(*section);r.kind==UnitRecordKind::Section},
                RecordEffect::DefineSymbol{symbol}=>{let s=symbols.get(symbol).ok_or_else(||UnitError("label record references missing symbol".into()))?;require(!matches!(s.definition,SymbolDefinition::Undefined|SymbolDefinition::Alias{..})&&definitions.insert(*symbol),"label definition is missing or duplicated")?;let section=match s.definition{SymbolDefinition::InSection{section,..}|SymbolDefinition::Body{section,..}=>section,_=>return Err(UnitError("label definition has no section".into()))};require(current_section==Some(section),"symbol definition/current section mismatch")?;if let SymbolName::NumericLocal{definition_record,..}=&s.name{require(*definition_record==r.id,"numeric label definition source owner mismatch")?;}r.kind==UnitRecordKind::Label},
                RecordEffect::Binding{symbol,binding}=>{require(symbols.contains_key(symbol),"binding references missing symbol")?;bindings.insert(*symbol,*binding);r.kind==UnitRecordKind::Symbol},
                RecordEffect::Visibility{symbol,visibility}=>{require(symbols.contains_key(symbol),"visibility references missing symbol")?;visibilities.insert(*symbol,*visibility);r.kind==UnitRecordKind::Symbol},
                RecordEffect::SymbolType{symbol,kind}=>{require(symbols.contains_key(symbol),"type references missing symbol")?;types.insert(*symbol,*kind);r.kind==UnitRecordKind::Symbol},
                RecordEffect::SymbolSize{symbol,size}=>{require(symbols.contains_key(symbol),"size references missing symbol")?;if let SymbolSize::Difference{end,start,..}=size{for a in [end,start]{if let SizeAnchor::CurrentLocation{record,section}=a{require(*record==r.id&&current_section==Some(*section),"size current-location record/section mismatch")?;}}}sizes.insert(*symbol,*size);r.kind==UnitRecordKind::Symbol},
                RecordEffect::Alias{symbol,target,addend,..}=>{require(symbols.contains_key(symbol)&&symbols.contains_key(target),"alias record references missing symbol")?;aliases.insert(*symbol,(*target,*addend));r.kind==UnitRecordKind::Symbol},
                RecordEffect::Initialize{initializer}=>{let i=initializers.get(initializer).ok_or_else(||UnitError("missing/duplicate initializer source record".into()))?;require(init_records.insert(*initializer),"missing/duplicate initializer source record")?;require(current_section==Some(i.section),"initializer/current section mismatch")?;matches!(r.kind,UnitRecordKind::Data|UnitRecordKind::Alignment)},
                RecordEffect::Relocate{relocation}=>{let relocation=relocations.get(relocation).ok_or_else(||UnitError("missing/duplicate relocation source record".into()))?;require(reloc_records.insert(relocation.id),"missing/duplicate relocation source record")?;require(current_section==Some(relocation.section),"relocation/current section mismatch")?;matches!(r.kind,UnitRecordKind::Data|UnitRecordKind::Relocation)},
                RecordEffect::Alignment{alignment}=>{let alignment=alignments.get(alignment).ok_or_else(||UnitError("missing/duplicate alignment source record".into()))?;require(align_records.insert(alignment.id),"missing/duplicate alignment source record")?;require(current_section==Some(alignment.section),"alignment/current section mismatch")?;r.kind==UnitRecordKind::Alignment},
                RecordEffect::BodyItem{body}=>{let section=body_sections_by_id.get(body).ok_or_else(||UnitError("record references missing body".into()))?;require(current_section==Some(*section),"body item/current section mismatch")?;body_records.entry(*body).or_default().insert(r.id);matches!(r.kind,UnitRecordKind::Instruction|UnitRecordKind::Label|UnitRecordKind::Cfi|UnitRecordKind::Alignment|UnitRecordKind::Symbol|UnitRecordKind::Data|UnitRecordKind::Relocation)},
                RecordEffect::File{path,..}=>{require(!path.contains(&0),"NUL in debug source path")?;r.kind==UnitRecordKind::Debug},
                RecordEffect::Location{..}=>r.kind==UnitRecordKind::Debug,
                RecordEffect::PreprocessorMarker{path,..}=>{require(!path.contains(&0),"NUL in preprocessor source path")?;r.kind==UnitRecordKind::Preprocessor},
                RecordEffect::Unrepresented{feature,reason}=>{require(!feature.is_empty()&&!reason.is_empty(),"unrepresented record lacks typed diagnostic")?;unsupported.push(r.id);true},
            };require(kind_ok,"source record kind/effect mismatch")?;
        }
    }
    // Keep every original attribute/assignment in order; final declarations
    // are checked against the last applicable directive, not every earlier one.
    for s in &d.symbols {
        let default_binding=if s.definition==SymbolDefinition::Undefined{SymbolBinding::Global}else{SymbolBinding::Local};
        require(bindings.get(&s.id).copied().unwrap_or(default_binding)==s.binding,"final original symbol binding mismatch")?;
        require(visibilities.get(&s.id).copied().unwrap_or(SymbolVisibility::Default)==s.visibility,"final original symbol visibility mismatch")?;
        require(types.get(&s.id).copied().unwrap_or(SymbolKind::NoType)==s.kind,"final original symbol type mismatch")?;
        require(sizes.get(&s.id).copied().unwrap_or(SymbolSize::Unspecified)==s.size,"final original symbol size mismatch")?;
        match s.definition {
            SymbolDefinition::Undefined=>require(!definitions.contains(&s.id)&&!aliases.contains_key(&s.id),"undefined symbol acquired definition")?,
            SymbolDefinition::Alias{target,addend}=>require(aliases.get(&s.id)==Some(&(target,addend))&&!definitions.contains(&s.id),"final original alias assignment mismatch")?,
            _=>require(definitions.contains(&s.id)&&!aliases.contains_key(&s.id),"original symbol definition lacks source record")?,
        }
    }
    require(init_records==initializers.keys().copied().collect(),"original initializer missing source-record accounting")?;require(reloc_records==relocations.keys().copied().collect(),"original relocation missing source-record accounting")?;require(align_records==alignments.keys().copied().collect(),"original alignment missing source-record accounting")?;
    // Explicit unsupported records are retained but never turn a unit GREEN.
    require(unsupported.is_empty(),&format!("unrepresented required original records: {unsupported:?}"))?;
    let expected=unique(&floor.bodies,|b|b.id,"duplicate required body id")?;
    require(bodies.keys().eq(expected.keys()),"required original body membership differs")?;
    for (&id,b) in &bodies {
        let f=expected[&id];identity(&f.inventory)?;require(b.symbol==f.symbol&&artifact(&b.selected_inventory_json)==f.inventory,"body selected inventory/raw identity mismatch")?;
        let inv:SelectedInstructionInventory=serde_json::from_slice(&b.selected_inventory_json).map_err(|e|UnitError(format!("invalid selected body inventory: {e}")))?;
        let symbol=symbols.get(&b.symbol).ok_or_else(||UnitError("body references missing symbol".into()))?;identity(&f.machine_inventory_claim)?;
        require(matches!(&symbol.name,SymbolName::Named{value}if value==&b.contract.symbol)&&b.contract.source==unit.source&&b.contract.profile==unit.profile&&inv.identity==f.machine_inventory_claim&&b.contract.selected_inventory==f.machine_inventory_claim,"body symbol/source/profile/inventory mismatch")?;
        let ids:BTreeSet<_>=f.record_ids.iter().copied().collect();require(ids.len()==f.record_ids.len()&&ids==inv.items.iter().map(|i|i.id).collect()&&body_records.get(&id)==Some(&ids),"complete original body record membership differs")?;
        for item in &inv.items {
            let r=records.get(&item.id).ok_or_else(||UnitError("body item missing whole-unit original record".into()))?;
            let kind=match item.kind{SourceItemKind::Instruction=>UnitRecordKind::Instruction,SourceItemKind::Label=>UnitRecordKind::Label,SourceItemKind::CfiDirective=>UnitRecordKind::Cfi,SourceItemKind::AlignmentDirective=>UnitRecordKind::Alignment,SourceItemKind::SymbolDirective=>UnitRecordKind::Symbol,SourceItemKind::DataDirective=>UnitRecordKind::Data,SourceItemKind::RelocationDirective=>UnitRecordKind::Relocation};
            require(r.span==item.decoded_span&&r.origins==item.origins&&r.kind==kind,"body/whole-unit original span/origin/kind mismatch")?;
        }
        native_machine_verify::verify(&b.contract,&inv,target).map_err(|e|UnitError(format!("existing machine-body guard: {}",e.message)))?;
    }
    // Exact required declarations and order are externally selected, never
    // recovered from only the records this candidate happened to lower.
    require(d.sections==floor.required.sections,"required section payload/membership differs")?;
    require(d.symbols==floor.required.symbols,"required original symbol/alias payload/membership differs")?;
    require(d.initializers==floor.required.initializers,"required initializer payload/membership differs")?;
    require(d.relocations==floor.required.relocations,"required relocation payload/membership differs")?;
    require(d.alignments==floor.required.alignments,"required alignment payload/membership differs")?;
    require(d.records==floor.required.records,"required original record/effect membership differs")?;
    require(d.external_obligations==floor.required.external_obligations,"required unresolved dependency membership differs")?;
    Ok(UnitReport{format:"ocore-whole-machine-unit-relative-structure-v1",target:target.id(),checked_records:d.records.len(),checked_symbols:d.symbols.len(),checked_initializers:d.initializers.len(),checked_relocations:d.relocations.len(),checked_bodies:unit.bodies.len(),unresolved_external_symbols:external.len(),unresolved_layout_sections:d.sections.iter().filter(|s|s.byte_size.is_none()).count(),structural_coverage_relative_to_selected_inventory:true,source_custody_verified:false,inventory_authority_verified:false,original_unit_completeness_verified:false,instruction_semantics_verified:false,directive_semantics_verified:false,target_relocation_realization_verified:false,native_realization_verified:false,provider_qualified:false,artifact_qualified:false,runtime_qualified:false,isa_equivalence_qualified:false,ordinary_native_admission:false})
}

#[cfg(test)]
mod tests {
    use super::*;
    // Authored typed foundation fixtures. No unchanged GNU engine or object is
    // imported/executed here; the floor is chosen before each adversarial edit.
    struct Case { target:Target, unit:MachineUnit, selection:UnitSelection, floor:Vec<u8>, source:Vec<u8> }
    fn targets()->Vec<(Target,MachineAbi)> {vec![(Target::X86_64UnknownNone,MachineAbi::SysvAmd64),(Target::Aarch64UnknownNone,MachineAbi::Aapcs64),(Target::Riscv64UnknownNone,MachineAbi::RiscvLp64),(Target::Riscv64UnknownNone,MachineAbi::RiscvLp64d)]}
    fn profile(t:Target,abi:MachineAbi)->MachineProfile {
        MachineProfile{architecture:match t{Target::X86_64UnknownNone=>Architecture::X86_64,Target::Aarch64UnknownNone=>Architecture::Aarch64,Target::Riscv64UnknownNone=>Architecture::Rv64},abi,address_bits:64,byte_order:ByteOrder::Little,entry_stack_alignment:16,entry_stack_remainder:if t==Target::X86_64UnknownNone{8}else{0},features:vec![StateFeature::UserRegisterBits],cfi:CfiPolicy::NoCfiDeclared}
    }
    fn symbol(id:u64,name:&str,definition:SymbolDefinition,kind:SymbolKind,size:SymbolSize)->UnitSymbol {UnitSymbol{id,name:SymbolName::Named{value:name.into()},binding:SymbolBinding::Global,visibility:SymbolVisibility::Default,kind,size,definition}}
    fn lines(rows:Vec<(&str,UnitRecordKind,Vec<RecordEffect>)>)->(Vec<u8>,Vec<UnitRecord>) {
        let mut raw=Vec::new();let mut records=Vec::new();
        for (text,kind,effects)in rows {let start=raw.len()as u64;raw.extend(text.as_bytes());let end=raw.len()as u64;raw.push(b'\n');records.push(UnitRecord{id:records.len()as u64,kind,span:SourceSpan{start,end},origins:vec![OriginalSpan{file:0,span:SourceSpan{start,end}}],effects});}
        (raw,records)
    }
    fn claim(raw:&[u8])->SourceWitness {SourceWitness{format:SOURCE_FORMAT.into(),input_form:MachineInputForm::ConfiguredAssemblyText,unit_id:"authored-complete-unit-fixture".into(),files:vec![SourceFile{id:0,logical_path:"authored.S".into(),identity:artifact(raw)}],decoded_assembly:artifact(raw),build_configuration:artifact(b"authored-target-profile"),frontend_event:artifact(b"authored-no-subprocess-event")}}
    fn freeze(t:Target,p:MachineProfile,d:UnitDeclarations,bodies:Vec<UnitBody>,required_bodies:Vec<RequiredBody>,raw:Vec<u8>)->Case {
        let source=claim(&raw);
        let floor=SelectedUnitInventory{format:UNIT_INVENTORY_FORMAT.into(),source:source.clone(),profile:p.clone(),required:d.clone(),bodies:required_bodies};let floor=serde_json::to_vec(&floor).unwrap();let selection=UnitSelection{source:source.clone(),profile:p.clone(),inventory:artifact(&floor)};let unit=MachineUnit{format:UNIT_FORMAT.into(),selected_inventory:selection.inventory.clone(),source,profile:p,declarations:d,bodies};Case{target:t,unit,selection,floor,source:raw}
    }
    fn data(t:Target,abi:MachineAbi,external:bool,alias:bool)->Case {
        let mut rows=vec![(".data",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]),(".globl object",UnitRecordKind::Symbol,vec![RecordEffect::Binding{symbol:0,binding:SymbolBinding::Global}]),(".type object,@object",UnitRecordKind::Symbol,vec![RecordEffect::SymbolType{symbol:0,kind:SymbolKind::Object}]),("object:",UnitRecordKind::Label,vec![RecordEffect::DefineSymbol{symbol:0}])];
        rows.push((if external{".quad external+4"}else{".quad 42"},UnitRecordKind::Data,if external{vec![RecordEffect::Initialize{initializer:0},RecordEffect::Relocate{relocation:0}]}else{vec![RecordEffect::Initialize{initializer:0}]}));rows.push((".size object,8",UnitRecordKind::Symbol,vec![RecordEffect::SymbolSize{symbol:0,size:SymbolSize::Bytes{bytes:8}}]));
        if alias{rows.push((".set alias,object+4",UnitRecordKind::Symbol,vec![RecordEffect::Alias{symbol:2,target:0,addend:4,equ:false}]));}
        let(raw,records)=lines(rows);let p=profile(t,abi);let mut symbols=vec![symbol(0,"object",SymbolDefinition::InSection{section:0,offset:0},SymbolKind::Object,SymbolSize::Bytes{bytes:8})];if external{symbols.push(symbol(1,"external",SymbolDefinition::Undefined,SymbolKind::NoType,SymbolSize::Unspecified));}if alias{let mut alias=symbol(2,"alias",SymbolDefinition::Alias{target:0,addend:4},SymbolKind::NoType,SymbolSize::Unspecified);alias.binding=SymbolBinding::Local;symbols.push(alias);}
        let d=UnitDeclarations{sections:vec![UnitSection{id:0,name:".data".into(),kind:SectionKind::ProgramBits,flags:b"aw".to_vec(),alignment:8,byte_size:Some(8)}],symbols,initializers:vec![UnitInitializer{id:0,section:0,offset:0,value:if external{InitializerValue::Relocation{relocation:0,bytes:8}}else{InitializerValue::Bytes{value:42_u64.to_le_bytes().to_vec()}}}],relocations:if external{vec![UnitRelocation{id:0,section:0,offset:0,architecture:p.architecture,bytes:8,kind:RelocationKind::Absolute,target:1,addend:4}]}else{vec![]},alignments:vec![],records,external_obligations:if external{vec![ExternalObligation{symbol:1,uses:vec![ExternalUse::Declaration,ExternalUse::Relocation{relocation:0}]}]}else{vec![]}};freeze(t,p,d,vec![],vec![],raw)
    }
    fn check(c:&Case)->Result<UnitReport>{verify_unit(&c.unit,&c.selection,&c.floor,&c.source,c.target)}
    fn rejected(c:&Case,text:&str){let e=check(c).unwrap_err();assert!(e.0.contains(text),"wanted {text:?}, actual {:?}",e.0);}
    fn unqualified(r:&UnitReport){assert!(r.structural_coverage_relative_to_selected_inventory);assert!(!r.source_custody_verified&&!r.inventory_authority_verified&&!r.original_unit_completeness_verified&&!r.instruction_semantics_verified&&!r.directive_semantics_verified&&!r.target_relocation_realization_verified&&!r.native_realization_verified&&!r.provider_qualified&&!r.artifact_qualified&&!r.runtime_qualified&&!r.isa_equivalence_qualified&&!r.ordinary_native_admission);}
    #[test]fn whole_unit_data_storage_and_alias_positive_on_all_three_isas_and_four_abis(){for(t,a)in targets(){let c=data(t,a,false,true);let r=check(&c).unwrap();assert_eq!((r.checked_symbols,r.checked_initializers,r.checked_records),(2,1,7));unqualified(&r);}}
    #[test]fn missing_original_symbol_rejected_against_unchanged_selected_floor(){let mut c=data(Target::X86_64UnknownNone,MachineAbi::SysvAmd64,false,false);c.unit.declarations.symbols.clear();assert!(c.unit.declarations.symbols.is_empty());rejected(&c,"required original symbol membership differs");}
    #[test]fn missing_initializer_rejected_without_zero_case_success(){let mut c=data(Target::Aarch64UnknownNone,MachineAbi::Aapcs64,false,false);c.unit.declarations.initializers.clear();assert!(c.unit.declarations.initializers.is_empty());rejected(&c,"required initializer membership differs");}
    #[test]fn changed_initializer_bytes_rejected_even_with_same_extent(){let mut c=data(Target::Riscv64UnknownNone,MachineAbi::RiscvLp64d,false,false);c.unit.declarations.initializers[0].value=InitializerValue::Bytes{value:43_u64.to_le_bytes().to_vec()};assert!(matches!(&c.unit.declarations.initializers[0].value,InitializerValue::Bytes{value}if value==&43_u64.to_le_bytes()));rejected(&c,"required initializer payload/membership differs");}
    #[test]fn original_relocation_preserves_external_obligation_and_never_qualifies_provider(){for(t,a)in targets(){let c=data(t,a,true,false);let r=check(&c).unwrap();assert_eq!((r.checked_relocations,r.unresolved_external_symbols),(1,1));unqualified(&r);}}
    #[test]fn missing_original_relocation_cannot_be_silently_dropped(){let mut c=data(Target::Riscv64UnknownNone,MachineAbi::RiscvLp64,true,false);c.unit.declarations.relocations.clear();assert!(c.unit.declarations.relocations.is_empty());rejected(&c,"required relocation membership differs");}
    #[test]fn wrong_relocation_width_has_actual_initializer_consistency_failure(){let mut c=data(Target::X86_64UnknownNone,MachineAbi::SysvAmd64,true,false);c.unit.declarations.relocations[0].bytes=4;assert_eq!(c.unit.declarations.relocations[0].bytes,4);rejected(&c,"initializer/relocation section/offset/width mismatch");}
    #[test]fn relocation_for_wrong_isa_is_explicitly_rejected(){let mut c=data(Target::Riscv64UnknownNone,MachineAbi::RiscvLp64d,true,false);c.unit.declarations.relocations[0].architecture=Architecture::X86_64;assert_eq!(c.unit.declarations.relocations[0].architecture,Architecture::X86_64);rejected(&c,"relocation target architecture mismatch");}
    #[test]fn missing_external_provider_obligation_is_not_inferred_resolved(){let mut c=data(Target::Aarch64UnknownNone,MachineAbi::Aapcs64,true,false);c.unit.declarations.external_obligations.clear();assert!(c.unit.declarations.external_obligations.is_empty());rejected(&c,"unresolved external obligations omit/add original dependency uses");}
    #[test]fn alias_cycle_mutation_reaches_real_graph_guard(){let mut c=data(Target::X86_64UnknownNone,MachineAbi::SysvAmd64,false,true);c.unit.declarations.symbols[1].definition=SymbolDefinition::Alias{target:2,addend:4};assert!(matches!(c.unit.declarations.symbols[1].definition,SymbolDefinition::Alias{target:2,..}));rejected(&c,"symbol alias cycle");}
    #[test]fn alias_missing_target_mutation_reaches_reference_guard(){let mut c=data(Target::Aarch64UnknownNone,MachineAbi::Aapcs64,false,true);c.unit.declarations.symbols[1].definition=SymbolDefinition::Alias{target:99,addend:4};assert!(matches!(c.unit.declarations.symbols[1].definition,SymbolDefinition::Alias{target:99,..}));rejected(&c,"alias references missing symbol");}
    #[test]fn wrong_target_or_32_bit_foundation_cannot_inherit_64_bit_results(){let mut c=data(Target::Riscv64UnknownNone,MachineAbi::RiscvLp64d,false,false);c.unit.profile.architecture=Architecture::I686;assert_eq!(c.unit.profile.architecture,Architecture::I686);rejected(&c,"unit target/ABI/address layout mismatch");}
    #[test]fn inventory_and_configured_source_raw_bytes_are_independently_checked(){let c=data(Target::X86_64UnknownNone,MachineAbi::SysvAmd64,false,false);let mut floor=c.floor.clone();floor.push(b' ');assert_ne!(artifact(&floor),c.selection.inventory);let e=verify_unit(&c.unit,&c.selection,&floor,&c.source,c.target).unwrap_err();assert!(e.0.contains("consumed selected unit inventory bytes differ"));let mut raw=c.source.clone();raw.push(b' ');assert_ne!(artifact(&raw),c.unit.source.decoded_assembly);let e=verify_unit(&c.unit,&c.selection,&c.floor,&raw,c.target).unwrap_err();assert!(e.0.contains("consumed configured source bytes differ"));}
    #[test]fn removing_original_record_does_not_turn_it_into_trivia(){let mut c=data(Target::Aarch64UnknownNone,MachineAbi::Aapcs64,false,false);let removed=c.unit.declarations.records.remove(4);assert_eq!(removed.kind,UnitRecordKind::Data);assert!(!c.unit.declarations.records.iter().any(|r|r.id==removed.id));rejected(&c,"original initializer missing source-record accounting");}
    #[test]fn explicit_unsupported_record_is_red_not_passing_rejection_coverage(){let mut c=data(Target::X86_64UnknownNone,MachineAbi::SysvAmd64,false,false);let start=c.source.len()as u64;c.source.extend(b"call external\n");c.unit.source.decoded_assembly=artifact(&c.source);c.unit.source.files[0].identity=artifact(&c.source);c.selection.source=c.unit.source.clone();c.unit.declarations.records.push(UnitRecord{id:6,kind:UnitRecordKind::Instruction,span:SourceSpan{start,end:start+13},origins:vec![OriginalSpan{file:0,span:SourceSpan{start,end:start+13}}],effects:vec![RecordEffect::Unrepresented{feature:"direct call state/ABI transition".into(),reason:"not implemented by the unchanged MachineBody contract".into()}]});let floor=SelectedUnitInventory{format:UNIT_INVENTORY_FORMAT.into(),source:c.unit.source.clone(),profile:c.unit.profile.clone(),required:c.unit.declarations.clone(),bodies:vec![]};c.floor=serde_json::to_vec(&floor).unwrap();c.selection.inventory=artifact(&c.floor);c.unit.selected_inventory=c.selection.inventory.clone();assert!(matches!(&c.unit.declarations.records[6].effects[0],RecordEffect::Unrepresented{feature,..}if feature.contains("direct call")));rejected(&c,"unrepresented required original records: [6]");}
    #[test]fn nobits_zero_fill_is_distinct_from_file_backed_zero_bytes(){let base=data(Target::Riscv64UnknownNone,MachineAbi::RiscvLp64d,false,false);let mut d=base.unit.declarations;let(raw,records)=lines(vec![(".bss",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]),(".globl object",UnitRecordKind::Symbol,vec![RecordEffect::Binding{symbol:0,binding:SymbolBinding::Global}]),(".type object,@object",UnitRecordKind::Symbol,vec![RecordEffect::SymbolType{symbol:0,kind:SymbolKind::Object}]),("object:",UnitRecordKind::Label,vec![RecordEffect::DefineSymbol{symbol:0}]),(".zero 8",UnitRecordKind::Data,vec![RecordEffect::Initialize{initializer:0}]),(".size object,8",UnitRecordKind::Symbol,vec![RecordEffect::SymbolSize{symbol:0,size:SymbolSize::Bytes{bytes:8}}])]);d.records=records;d.sections[0].name=".bss".into();d.sections[0].kind=SectionKind::NoBits;d.initializers[0].value=InitializerValue::ZeroFill{bytes:8};let mut c=freeze(base.target,base.unit.profile,d,vec![],vec![],raw);unqualified(&check(&c).unwrap());c.unit.declarations.initializers[0].value=InitializerValue::RepeatByte{byte:0,count:8};assert!(matches!(c.unit.declarations.initializers[0].value,InitializerValue::RepeatByte{byte:0,count:8}));rejected(&c,"file-backed initializer cannot disappear into NOBITS");}
    fn body_case(t:Target,abi:MachineAbi)->Case { body_case_with_section_probe(t,abi,false) }
    fn body_case_with_section_probe(t:Target,abi:MachineAbi,probe:bool)->Case {
        let p=profile(t,abi);let (arg,out,sp,pc,text)=match t {
            Target::X86_64UnknownNone=>(PhysicalRegister::X86Gpr{name:X86Gpr::Rdi},PhysicalRegister::X86Gpr{name:X86Gpr::Rax},PhysicalRegister::X86Gpr{name:X86Gpr::Rsp},PhysicalRegister::X86Pc,"movq %rdi,%rax"),
            Target::Aarch64UnknownNone=>(PhysicalRegister::Aarch64Gpr{index:1},PhysicalRegister::Aarch64Gpr{index:0},PhysicalRegister::Aarch64Sp,PhysicalRegister::Aarch64Pc,"mov x0,x1"),
            Target::Riscv64UnknownNone=>(PhysicalRegister::RiscvGpr{index:11},PhysicalRegister::RiscvGpr{index:10},PhysicalRegister::RiscvGpr{index:2},PhysicalRegister::RiscvPc,"mv a0,a1"),
        };let view=|register|RegisterView{register,low_bit:0,bits:64};
        let mut rows=vec![(".text",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]),(".globl f",UnitRecordKind::Symbol,vec![RecordEffect::Binding{symbol:0,binding:SymbolBinding::Global}]),("f:",UnitRecordKind::Label,vec![RecordEffect::DefineSymbol{symbol:0},RecordEffect::BodyItem{body:0}])];
        if probe{rows.push((".text",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]));}
        let instruction_id=rows.len()as u64;rows.push((text,UnitRecordKind::Instruction,vec![RecordEffect::BodyItem{body:0}]));
        let return_id=rows.len()as u64;rows.push(("ret",UnitRecordKind::Instruction,vec![RecordEffect::BodyItem{body:0}]));rows.push((".type f,@function",UnitRecordKind::Symbol,vec![RecordEffect::SymbolType{symbol:0,kind:SymbolKind::Function}]));
        let body_ids=vec![2,instruction_id,return_id];let(raw,records)=lines(rows);let source=claim(&raw);let interface=MachineInterface{entry:EntryInterface{policy:EntryPolicy::NoImplicitFrameOrScratch,initialized:vec![view(arg),view(sp),view(pc)],memory:MemoryInterface::None},exits:vec![ExitInterface{id:0,kind:ExitKind::OrdinaryReturn,outputs:vec![view(out)],preserved:vec![]}]};let legacy_claim=artifact(b"independently-selected-authored-body-contract-claim");
        let inv=SelectedInstructionInventory{format:INVENTORY_FORMAT.into(),identity:legacy_claim.clone(),source:source.clone(),symbol:"f".into(),profile:p.clone(),interface:interface.clone(),items:records.iter().filter(|r|body_ids.contains(&r.id)).map(|r|SourceItem{id:r.id,kind:if r.kind==UnitRecordKind::Label{SourceItemKind::Label}else{SourceItemKind::Instruction},decoded_span:r.span,origins:r.origins.clone()}).collect()};let inv_raw=serde_json::to_vec(&inv).unwrap();
        let contract=MachineBodyContract{format:FORMAT.into(),selected_inventory:legacy_claim.clone(),source,symbol:"f".into(),profile:p.clone(),interface,entry:0,blocks:vec![MachineBlock{id:0,source_label:Some(2),state_parameter:0,parameters:vec![],instructions:vec![MachineInstruction{source_item:instruction_id,state_in:0,state_out:1,result:Some(Scalar{id:0,bits:64}),operation:MachineOperation::ReadRegister{view:view(arg)}},MachineInstruction{source_item:instruction_id,state_in:1,state_out:2,result:None,operation:MachineOperation::WriteRegister{view:view(out),value:0,mode:WriteMode::WholeStorage}}],terminator:MachineTerminator{source_item:return_id,state:2,control:MachineControl::Return{exit:0}}}],directives:vec![]};
        let required=RequiredBody{id:0,symbol:0,inventory:artifact(&inv_raw),machine_inventory_claim:legacy_claim,record_ids:body_ids};let body=UnitBody{id:0,symbol:0,contract,selected_inventory_json:inv_raw};let mut sections=vec![UnitSection{id:0,name:".text".into(),kind:SectionKind::ProgramBits,flags:b"ax".to_vec(),alignment:4,byte_size:None}];if probe{sections.push(empty_other_section());}let d=UnitDeclarations{sections,symbols:vec![symbol(0,"f",SymbolDefinition::Body{section:0,body:0},SymbolKind::Function,SymbolSize::Unspecified)],initializers:vec![],relocations:vec![],alignments:vec![],records,external_obligations:vec![]};freeze(t,p,d,vec![body],vec![required],raw)
    }
    #[test]fn body_raw_identity_and_legacy_claim_are_distinct_without_self_hash_cycle(){for(t,a)in targets(){let c=body_case(t,a);let raw=&c.unit.bodies[0].selected_inventory_json;let inv:SelectedInstructionInventory=serde_json::from_slice(raw).unwrap();assert_ne!(artifact(raw),inv.identity);let r=check(&c).unwrap();assert_eq!(r.checked_bodies,1);assert_eq!(r.unresolved_layout_sections,1);unqualified(&r);}}
    #[test]fn required_function_body_cannot_be_omitted(){let mut c=body_case(Target::Aarch64UnknownNone,MachineAbi::Aapcs64);c.unit.bodies.clear();assert!(c.unit.bodies.is_empty());rejected(&c,"symbol references missing body");}
    #[test]fn whole_unit_does_not_bypass_existing_stack_pointer_write_guard(){let mut c=body_case(Target::X86_64UnknownNone,MachineAbi::SysvAmd64);let view=RegisterView{register:PhysicalRegister::X86Gpr{name:X86Gpr::Rsp},low_bit:0,bits:64};c.unit.bodies[0].contract.blocks[0].instructions[1].operation=MachineOperation::WriteRegister{view,value:0,mode:WriteMode::WholeStorage};assert!(matches!(c.unit.bodies[0].contract.blocks[0].instructions[1].operation,MachineOperation::WriteRegister{view:v,..}if v==view));rejected(&c,"existing machine-body guard: SP/PC/zero/flags register writes");}
    #[test]fn whole_unit_does_not_bypass_existing_restored_context_guard(){let mut c=body_case(Target::Riscv64UnknownNone,MachineAbi::RiscvLp64d);c.unit.bodies[0].contract.blocks[0].terminator.control=MachineControl::RestoreContext{stack_pointer:0,program_counter:0};assert!(matches!(c.unit.bodies[0].contract.blocks[0].terminator.control,MachineControl::RestoreContext{..}));rejected(&c,"existing machine-body guard: restored SP/PC transfer is unsupported");}
    #[test]fn original_attribute_order_is_retained_and_final_binding_is_checked(){
        let base=data(Target::X86_64UnknownNone,MachineAbi::SysvAmd64,false,false);let mut d=base.unit.declarations;
        let(raw,records)=lines(vec![(".data",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]),(".local object",UnitRecordKind::Symbol,vec![RecordEffect::Binding{symbol:0,binding:SymbolBinding::Local}]),(".globl object",UnitRecordKind::Symbol,vec![RecordEffect::Binding{symbol:0,binding:SymbolBinding::Global}]),(".type object,@object",UnitRecordKind::Symbol,vec![RecordEffect::SymbolType{symbol:0,kind:SymbolKind::Object}]),("object:",UnitRecordKind::Label,vec![RecordEffect::DefineSymbol{symbol:0}]),(".quad 42",UnitRecordKind::Data,vec![RecordEffect::Initialize{initializer:0}]),(".size object,8",UnitRecordKind::Symbol,vec![RecordEffect::SymbolSize{symbol:0,size:SymbolSize::Bytes{bytes:8}}])]);d.records=records;let mut c=freeze(base.target,base.unit.profile,d,vec![],vec![],raw);unqualified(&check(&c).unwrap());assert!(matches!(c.unit.declarations.records[1].effects[0],RecordEffect::Binding{binding:SymbolBinding::Local,..}));c.unit.declarations.records[2].effects[0]=RecordEffect::Binding{symbol:0,binding:SymbolBinding::Local};assert!(matches!(c.unit.declarations.records[2].effects[0],RecordEffect::Binding{binding:SymbolBinding::Local,..}));rejected(&c,"final original symbol binding mismatch");
    }
    #[test]fn source_current_location_size_anchor_preserves_record_and_section(){
        let base=data(Target::X86_64UnknownNone,MachineAbi::SysvAmd64,false,false);let mut d=base.unit.declarations;let size=SymbolSize::Difference{end:SizeAnchor::CurrentLocation{record:5,section:0},start:SizeAnchor::Symbol{symbol:0},addend:0};d.symbols[0].size=size;
        let(raw,records)=lines(vec![(".data",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]),(".globl object",UnitRecordKind::Symbol,vec![RecordEffect::Binding{symbol:0,binding:SymbolBinding::Global}]),(".type object,@object",UnitRecordKind::Symbol,vec![RecordEffect::SymbolType{symbol:0,kind:SymbolKind::Object}]),("object:",UnitRecordKind::Label,vec![RecordEffect::DefineSymbol{symbol:0}]),(".quad 42",UnitRecordKind::Data,vec![RecordEffect::Initialize{initializer:0}]),(".size object,.-object",UnitRecordKind::Symbol,vec![RecordEffect::SymbolSize{symbol:0,size}])]);d.records=records;let mut c=freeze(base.target,base.unit.profile,d,vec![],vec![],raw);unqualified(&check(&c).unwrap());let wrong=SymbolSize::Difference{end:SizeAnchor::CurrentLocation{record:4,section:0},start:SizeAnchor::Symbol{symbol:0},addend:0};c.unit.declarations.records[5].effects[0]=RecordEffect::SymbolSize{symbol:0,size:wrong};assert!(matches!(c.unit.declarations.records[5].effects[0],RecordEffect::SymbolSize{size:SymbolSize::Difference{end:SizeAnchor::CurrentLocation{record:4,..},..},..}));rejected(&c,"size current-location record/section mismatch");
    }
    fn alignment_case(skipped:bool)->Case {
        let base=data(Target::Aarch64UnknownNone,MachineAbi::Aapcs64,false,false);let mut d=base.unit.declarations;d.sections[0].alignment=16;d.sections[0].byte_size=Some(if skipped{8}else{16});if !skipped{d.initializers.push(UnitInitializer{id:1,section:0,offset:8,value:InitializerValue::RepeatByte{byte:0,count:8}});}
        d.alignments=vec![UnitAlignment{id:0,section:0,boundary:16,fill:Some(0),maximum_skip:if skipped{Some(4)}else{None},layout:Some(if skipped{AlignmentLayout::Skipped{offset:8,required_padding:8}}else{AlignmentLayout::Applied{offset:8,padding:8}})}];let effects=if skipped{vec![RecordEffect::Alignment{alignment:0}]}else{vec![RecordEffect::Alignment{alignment:0},RecordEffect::Initialize{initializer:1}]};
        let(raw,records)=lines(vec![(".data",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]),(".globl object",UnitRecordKind::Symbol,vec![RecordEffect::Binding{symbol:0,binding:SymbolBinding::Global}]),(".type object,@object",UnitRecordKind::Symbol,vec![RecordEffect::SymbolType{symbol:0,kind:SymbolKind::Object}]),("object:",UnitRecordKind::Label,vec![RecordEffect::DefineSymbol{symbol:0}]),(".quad 42",UnitRecordKind::Data,vec![RecordEffect::Initialize{initializer:0}]),(if skipped{".balign 16,0,4"}else{".balign 16,0"},UnitRecordKind::Alignment,effects),(".size object,8",UnitRecordKind::Symbol,vec![RecordEffect::SymbolSize{symbol:0,size:SymbolSize::Bytes{bytes:8}}])]);d.records=records;freeze(base.target,base.unit.profile,d,vec![],vec![],raw)
    }
    #[test]fn maximum_skip_alignment_is_explicitly_skipped_not_fabricated_padding(){let mut c=alignment_case(true);unqualified(&check(&c).unwrap());assert!(matches!(c.unit.declarations.alignments[0].layout,Some(AlignmentLayout::Skipped{required_padding:8,..})));c.unit.declarations.alignments[0].maximum_skip=Some(8);assert_eq!(c.unit.declarations.alignments[0].maximum_skip,Some(8));rejected(&c,"alignment skip does not follow original max-skip");}
    #[test]fn explicit_alignment_fill_is_checked_against_actual_initializer_payload(){let mut c=alignment_case(false);unqualified(&check(&c).unwrap());c.unit.declarations.initializers[1].value=InitializerValue::RepeatByte{byte:1,count:8};assert!(matches!(c.unit.declarations.initializers[1].value,InitializerValue::RepeatByte{byte:1,count:8}));rejected(&c,"explicit alignment fill differs from saved padding storage");}

    // R2: the independent floor remains unchanged throughout each mutation.
    // Every negative first accepts the exact valid baseline, observes the actual
    // changed field, then requires the intended structural rejection reason.
    fn empty_other_section()->UnitSection {UnitSection{id:1,name:".other".into(),kind:SectionKind::ProgramBits,flags:b"aw".to_vec(),alignment:8,byte_size:Some(0)}}
    fn section_probe_case(t:Target,abi:MachineAbi,external:bool,relocation_first:bool)->Case {
        let base=data(t,abi,external,false);let mut d=base.unit.declarations;d.sections.push(empty_other_section());
        let mut data_effects=vec![RecordEffect::Initialize{initializer:0}];
        if external {if relocation_first{data_effects.insert(0,RecordEffect::Relocate{relocation:0});}else{data_effects.push(RecordEffect::Relocate{relocation:0});}}
        let(raw,records)=lines(vec![(".data",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]),(".globl object",UnitRecordKind::Symbol,vec![RecordEffect::Binding{symbol:0,binding:SymbolBinding::Global}]),(".type object,@object",UnitRecordKind::Symbol,vec![RecordEffect::SymbolType{symbol:0,kind:SymbolKind::Object}]),("object:",UnitRecordKind::Label,vec![RecordEffect::DefineSymbol{symbol:0}]),(".data",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]),(if external{".quad external+4"}else{".quad 42"},UnitRecordKind::Data,data_effects),(".size object,8",UnitRecordKind::Symbol,vec![RecordEffect::SymbolSize{symbol:0,size:SymbolSize::Bytes{bytes:8}}])]);
        d.records=records;freeze(t,base.unit.profile,d,vec![],vec![],raw)
    }
    fn alignment_section_probe_case(t:Target,abi:MachineAbi)->Case {
        let base=alignment_case(true);let mut d=base.unit.declarations;d.sections.push(empty_other_section());
        let(raw,records)=lines(vec![(".data",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]),(".globl object",UnitRecordKind::Symbol,vec![RecordEffect::Binding{symbol:0,binding:SymbolBinding::Global}]),(".type object,@object",UnitRecordKind::Symbol,vec![RecordEffect::SymbolType{symbol:0,kind:SymbolKind::Object}]),("object:",UnitRecordKind::Label,vec![RecordEffect::DefineSymbol{symbol:0}]),(".quad 42",UnitRecordKind::Data,vec![RecordEffect::Initialize{initializer:0}]),(".data",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]),(".balign 16,0,4",UnitRecordKind::Alignment,vec![RecordEffect::Alignment{alignment:0}]),(".size object,8",UnitRecordKind::Symbol,vec![RecordEffect::SymbolSize{symbol:0,size:SymbolSize::Bytes{bytes:8}}])]);
        d.records=records;freeze(t,profile(t,abi),d,vec![],vec![],raw)
    }
    fn numeric_labels_case(t:Target,abi:MachineAbi)->Case {
        let base=data(t,abi,false,false);let mut d=base.unit.declarations;
        let(raw,records)=lines(vec![(".data",UnitRecordKind::Section,vec![RecordEffect::SelectSection{section:0}]),("1:",UnitRecordKind::Label,vec![RecordEffect::DefineSymbol{symbol:0}]),(".quad 42",UnitRecordKind::Data,vec![RecordEffect::Initialize{initializer:0}]),("2:",UnitRecordKind::Label,vec![RecordEffect::DefineSymbol{symbol:1}])]);
        d.symbols=vec![UnitSymbol{id:0,name:SymbolName::NumericLocal{number:1,definition_record:1},binding:SymbolBinding::Local,visibility:SymbolVisibility::Default,kind:SymbolKind::NoType,size:SymbolSize::Unspecified,definition:SymbolDefinition::InSection{section:0,offset:0}},UnitSymbol{id:1,name:SymbolName::NumericLocal{number:2,definition_record:3},binding:SymbolBinding::Local,visibility:SymbolVisibility::Default,kind:SymbolKind::NoType,size:SymbolSize::Unspecified,definition:SymbolDefinition::InSection{section:0,offset:8}}];
        d.records=records;freeze(t,base.unit.profile,d,vec![],vec![],raw)
    }
    #[test]fn section_scoped_records_accept_matching_sections_on_all_primary_profiles(){for(t,a)in targets(){for c in [section_probe_case(t,a,false,false),section_probe_case(t,a,true,true),alignment_section_probe_case(t,a),body_case_with_section_probe(t,a,true)]{assert_eq!(c.unit.declarations.sections.len(),2);unqualified(&check(&c).unwrap());}}}
    #[test]fn symbol_definition_rejects_absent_selected_section(){for(t,a)in targets(){let mut c=section_probe_case(t,a,false,false);unqualified(&check(&c).unwrap());let removed=c.unit.declarations.records.remove(0);assert!(matches!(removed.effects[0],RecordEffect::SelectSection{section:0}));assert!(!c.unit.declarations.records[..3].iter().any(|r|r.effects.iter().any(|e|matches!(e,RecordEffect::SelectSection{..}))));rejected(&c,"symbol definition/current section mismatch");}}
    #[test]fn symbol_definition_rejects_different_selected_section(){for(t,a)in targets(){let mut c=section_probe_case(t,a,false,false);unqualified(&check(&c).unwrap());c.unit.declarations.records[0].effects[0]=RecordEffect::SelectSection{section:1};assert!(matches!(c.unit.declarations.records[0].effects[0],RecordEffect::SelectSection{section:1}));assert!(matches!(c.unit.declarations.symbols[0].definition,SymbolDefinition::InSection{section:0,..}));rejected(&c,"symbol definition/current section mismatch");}}
    #[test]fn initializer_record_rejects_different_selected_section(){for(t,a)in targets(){let mut c=section_probe_case(t,a,false,false);unqualified(&check(&c).unwrap());c.unit.declarations.records[4].effects[0]=RecordEffect::SelectSection{section:1};assert!(matches!(c.unit.declarations.records[4].effects[0],RecordEffect::SelectSection{section:1}));assert!(matches!(c.unit.declarations.records[5].effects[0],RecordEffect::Initialize{initializer:0}));assert_eq!(c.unit.declarations.initializers[0].section,0);rejected(&c,"initializer/current section mismatch");}}
    #[test]fn relocation_record_rejects_different_selected_section_before_initializer(){for(t,a)in targets(){let mut c=section_probe_case(t,a,true,true);unqualified(&check(&c).unwrap());c.unit.declarations.records[4].effects[0]=RecordEffect::SelectSection{section:1};assert!(matches!(c.unit.declarations.records[4].effects[0],RecordEffect::SelectSection{section:1}));assert!(matches!(c.unit.declarations.records[5].effects[0],RecordEffect::Relocate{relocation:0}));assert_eq!(c.unit.declarations.relocations[0].section,0);rejected(&c,"relocation/current section mismatch");}}
    #[test]fn alignment_record_rejects_different_selected_section(){for(t,a)in targets(){let mut c=alignment_section_probe_case(t,a);unqualified(&check(&c).unwrap());c.unit.declarations.records[5].effects[0]=RecordEffect::SelectSection{section:1};assert!(matches!(c.unit.declarations.records[5].effects[0],RecordEffect::SelectSection{section:1}));assert_eq!(c.unit.declarations.alignments[0].section,0);rejected(&c,"alignment/current section mismatch");}}
    #[test]fn body_item_rejects_section_switch_without_changing_its_symbol_owner(){for(t,a)in targets(){let mut c=body_case_with_section_probe(t,a,true);unqualified(&check(&c).unwrap());let inventory_before=c.unit.bodies[0].selected_inventory_json.clone();c.unit.declarations.records[3].effects[0]=RecordEffect::SelectSection{section:1};assert!(matches!(c.unit.declarations.records[3].effects[0],RecordEffect::SelectSection{section:1}));assert!(matches!(c.unit.declarations.symbols[0].definition,SymbolDefinition::Body{section:0,body:0}));assert_eq!(c.unit.bodies[0].selected_inventory_json,inventory_before);assert!(matches!(c.unit.declarations.records[4].effects[0],RecordEffect::BodyItem{body:0}));rejected(&c,"body item/current section mismatch");}}
    #[test]fn body_requires_exact_converse_symbol_body_definition(){for(t,a)in targets(){let mut c=body_case(t,a);unqualified(&check(&c).unwrap());c.unit.declarations.symbols[0].definition=SymbolDefinition::InSection{section:0,offset:0};assert!(matches!(c.unit.declarations.symbols[0].definition,SymbolDefinition::InSection{section:0,offset:0}));assert_eq!((c.unit.bodies[0].id,c.unit.bodies[0].symbol),(0,0));rejected(&c,"body lacks exact converse symbol/body definition");}}
    #[test]fn numeric_labels_have_exact_defining_record_owners_on_all_primary_profiles(){for(t,a)in targets(){let c=numeric_labels_case(t,a);assert!(matches!(c.unit.declarations.symbols[0].name,SymbolName::NumericLocal{definition_record:1,..}));assert!(matches!(c.unit.declarations.records[1].effects[0],RecordEffect::DefineSymbol{symbol:0}));assert!(matches!(c.unit.declarations.symbols[1].name,SymbolName::NumericLocal{definition_record:3,..}));assert!(matches!(c.unit.declarations.records[3].effects[0],RecordEffect::DefineSymbol{symbol:1}));unqualified(&check(&c).unwrap());}}
    #[test]fn numeric_label_cannot_point_at_another_symbols_label_record(){for(t,a)in targets(){let mut c=numeric_labels_case(t,a);unqualified(&check(&c).unwrap());c.unit.declarations.symbols[0].name=SymbolName::NumericLocal{number:1,definition_record:3};assert!(matches!(c.unit.declarations.symbols[0].name,SymbolName::NumericLocal{definition_record:3,..}));assert!(matches!(c.unit.declarations.records[3].effects[0],RecordEffect::DefineSymbol{symbol:1}));rejected(&c,"numeric label definition record does not define this symbol");}}
    #[test]fn numeric_label_exact_record_must_really_define_that_symbol(){for(t,a)in targets(){let mut c=numeric_labels_case(t,a);unqualified(&check(&c).unwrap());c.unit.declarations.records[1].effects[0]=RecordEffect::DefineSymbol{symbol:1};c.unit.declarations.records[3].effects[0]=RecordEffect::DefineSymbol{symbol:0};assert!(matches!(c.unit.declarations.symbols[0].name,SymbolName::NumericLocal{definition_record:1,..}));assert!(matches!(c.unit.declarations.records[1].effects[0],RecordEffect::DefineSymbol{symbol:1}));assert!(matches!(c.unit.declarations.records[3].effects[0],RecordEffect::DefineSymbol{symbol:0}));rejected(&c,"numeric label definition record does not define this symbol");}}
}
