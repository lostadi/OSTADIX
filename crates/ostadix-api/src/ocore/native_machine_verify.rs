//! Structural checks relative to an EXTERNALLY SUPPLIED inventory contract.
//!
//! This module neither authenticates that inventory nor proves any original ISA
//! instruction meaning, entry realization, provider compatibility or execution.
//! Definite register-bit initialization is solved across the complete CFG by
//! predecessor intersection. Invalidation survives edges and loop backedges;
//! entry also meets its independently declared external entry facts. These are
//! definedness facts only, never proofs of original ISA or native realization.
use std::collections::{BTreeMap, BTreeSet};
use serde::Serialize;
use super::common::{Diagnostic, Span, Target};
use super::native_machine_ir::*;
use super::native_machine_ir::X86Gpr as Gpr;

type Result<T> = std::result::Result<T, Diagnostic>;
fn fail(message: impl Into<String>) -> Diagnostic {
    Diagnostic { file: "<machine-body-contract>".into(), span: Span::default(), message: message.into() }
}
fn require(ok: bool, message: &str) -> Result<()> { if ok { Ok(()) } else { Err(fail(message)) } }
#[derive(Debug, Clone, Serialize)]
pub struct StructuralReport {
    pub format: &'static str,
    pub target: &'static str,
    pub checked_inventory_items: usize,
    pub checked_instruction_sites: usize,
    pub structural_coverage_relative_to_supplied_inventory: bool,
    pub source_custody_verified: bool,
    pub inventory_authority_verified: bool,
    pub original_unit_completeness_verified: bool,
    pub instruction_semantics_verified: bool,
    pub native_realization_verified: bool,
    pub cfi_semantics_verified: bool,
    pub memory_access_validity_verified: bool,
    pub entry_state_realization_verified: bool,
    pub provider_qualified: bool,
    pub runtime_qualified: bool,
    pub isa_equivalence_qualified: bool,
    pub ordinary_native_admission: bool,
}
fn architecture(target: Target) -> Architecture {
    // Exhaustive over the actual Source C Target enum: a new backend must make
    // an explicit source change here, not acquire this contract accidentally.
    match target {
        Target::X86_64UnknownNone => Architecture::X86_64,
        Target::Aarch64UnknownNone => Architecture::Aarch64,
        Target::Riscv64UnknownNone => Architecture::Rv64,
    }
}
fn identity(value: &ArtifactIdentity) -> Result<()> {
    require(value.bytes > 0 && value.sha256.len() == 64 && value.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "artifact identity requires nonempty extent and lowercase SHA256")
}
fn source(value: &SourceWitness) -> Result<()> {
    require(value.format == SOURCE_FORMAT && value.input_form == MachineInputForm::ConfiguredAssemblyText, "original source claim version/form differs")?;
    require(!value.unit_id.is_empty() && !value.files.is_empty(), "source unit/files are required")?;
    let mut ids = BTreeSet::new(); let mut paths = BTreeSet::new();
    for file in &value.files {
        identity(&file.identity)?;
        require(ids.insert(file.id) && paths.insert(file.logical_path.clone()), "duplicate source file identity/path")?;
        require(!file.logical_path.starts_with('/') && !file.logical_path.contains('\0') && file.logical_path.split('/').all(|p| !p.is_empty() && p != "." && p != ".."), "source path must be a normalized logical path")?;
    }
    identity(&value.decoded_assembly)?; identity(&value.build_configuration)?; identity(&value.frontend_event)
}
fn profile(value: &MachineProfile, target: Target) -> Result<()> {
    require(!matches!(value.architecture, Architecture::I686 | Architecture::Armv7), "i686/ARMv7 machine-state foundations are not implemented")?;
    require(value.architecture == architecture(target), "machine profile differs from selected canonical target")?;
    let abi = matches!((value.architecture, value.abi),
        (Architecture::X86_64, MachineAbi::SysvAmd64) | (Architecture::Aarch64, MachineAbi::Aapcs64) |
        (Architecture::Rv64, MachineAbi::RiscvLp64 | MachineAbi::RiscvLp64d));
    require(abi && value.address_bits == 64 && value.byte_order == ByteOrder::Little, "unsupported machine ABI/address layout")?;
    let remainder = if value.architecture == Architecture::X86_64 { 8 } else { 0 };
    require(value.entry_stack_alignment == 16 && value.entry_stack_remainder == remainder, "entry stack ABI alignment/remainder differs")?;
    require(value.features == vec![StateFeature::UserRegisterBits], "required platform/security/floating state feature is not implemented")
}
/// Structural branch-class/profile agreement only; not source or native proof.
pub(super) fn return_mechanism(profile: &MachineProfile, mechanism: ReturnMechanism) -> Result<()> {
    require(matches!((profile.architecture, mechanism),
        (Architecture::Rv64, ReturnMechanism::Rv64Jalr) |
        (Architecture::Aarch64, ReturnMechanism::Aarch64Ret)),
        "return mechanism differs from machine architecture")
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Role { General, Floating, Flags, Stack, Pc, Zero }
#[derive(Clone, Copy)]
pub(super) struct Layout { pub(super) width: u16, pub(super) role: Role, pub(super) zero_extend_32: bool }
pub(super) fn view(profile: &MachineProfile, value: RegisterView) -> Result<(Layout, u128)> {
    use PhysicalRegister::*;
    let a = profile.architecture;
    let (layout, allowed) = match value.register {
        X86Gpr { name } if a == Architecture::X86_64 => {
            let high = matches!(name, Gpr::Rax | Gpr::Rbx | Gpr::Rcx | Gpr::Rdx);
            (Layout { width: 64, role: if name == Gpr::Rsp { Role::Stack } else { Role::General }, zero_extend_32: true },
             (value.low_bit == 0 && [8,16,32,64].contains(&value.bits)) || (high && value.low_bit == 8 && value.bits == 8))
        }
        X86Xmm { index } if a == Architecture::X86_64 && index < 16 =>
            (Layout { width: 128, role: Role::Floating, zero_extend_32: false }, value.low_bit == 0 && [32,64,128].contains(&value.bits)),
        X86Flags if a == Architecture::X86_64 => (Layout { width: 64, role: Role::Flags, zero_extend_32: false }, value.low_bit == 0 && value.bits == 64),
        X86Pc if a == Architecture::X86_64 => (Layout { width: 64, role: Role::Pc, zero_extend_32: false }, value.low_bit == 0 && value.bits == 64),
        Aarch64Gpr { index } if a == Architecture::Aarch64 && index <= 30 =>
            (Layout { width: 64, role: Role::General, zero_extend_32: true }, value.low_bit == 0 && [32,64].contains(&value.bits)),
        Aarch64Vector { index } if a == Architecture::Aarch64 && index < 32 =>
            (Layout { width: 128, role: Role::Floating, zero_extend_32: false }, value.low_bit == 0 && [8,16,32,64,128].contains(&value.bits)),
        Aarch64Sp if a == Architecture::Aarch64 => (Layout { width: 64, role: Role::Stack, zero_extend_32: true }, value.low_bit == 0 && [32,64].contains(&value.bits)),
        Aarch64Pc if a == Architecture::Aarch64 => (Layout { width: 64, role: Role::Pc, zero_extend_32: false }, value.low_bit == 0 && value.bits == 64),
        Aarch64Nzcv if a == Architecture::Aarch64 => (Layout { width: 4, role: Role::Flags, zero_extend_32: false }, value.low_bit == 0 && value.bits == 4),
        RiscvGpr { index } if a == Architecture::Rv64 && index < 32 =>
            (Layout { width: 64, role: if index == 0 { Role::Zero } else if index == 2 { Role::Stack } else { Role::General }, zero_extend_32: false }, value.low_bit == 0 && value.bits == 64),
        RiscvFpr { index } if a == Architecture::Rv64 && index < 32 =>
            (Layout { width: 64, role: Role::Floating, zero_extend_32: false }, value.low_bit == 0 && value.bits == 64),
        RiscvPc if a == Architecture::Rv64 => (Layout { width: 64, role: Role::Pc, zero_extend_32: false }, value.low_bit == 0 && value.bits == 64),
        _ => return Err(fail("unknown/noncanonical register bank or cross-target register")),
    };
    require(allowed && value.bits > 0 && u32::from(value.low_bit) + u32::from(value.bits) <= u32::from(layout.width), "register alias/width is not canonical")?;
    let mask = if value.bits == 128 { u128::MAX } else { ((1_u128 << value.bits) - 1) << value.low_bit };
    Ok((layout, mask))
}
/// Arithmetic-condition flags only, excluding privileged/reserved state.
pub(super) fn flag_view(profile: &MachineProfile, value: RegisterView) -> Result<(Layout,u128)> {
    let valid=match (profile.architecture,value.register) {
        (Architecture::X86_64,PhysicalRegister::X86Flags)=>value.bits==1 && [0,2,4,6,7,11].contains(&value.low_bit),
        (Architecture::Aarch64,PhysicalRegister::Aarch64Nzcv)=>value.low_bit==0 && value.bits==4,
        _=>false,
    };
    require(valid,"noncanonical arithmetic-flag view or cross-target flag bank")?;
    let width=if profile.architecture==Architecture::X86_64 {64}else{4};
    let mask=((1u128<<value.bits)-1)<<value.low_bit;
    Ok((Layout {width,role:Role::Flags,zero_extend_32:false},mask))
}
fn stack_pc(a: Architecture) -> Result<(PhysicalRegister, PhysicalRegister)> {
    use PhysicalRegister::*;
    match a {
        Architecture::X86_64 => Ok((X86Gpr { name: Gpr::Rsp }, X86Pc)),
        Architecture::Aarch64 => Ok((Aarch64Sp, Aarch64Pc)),
        Architecture::Rv64 => Ok((RiscvGpr { index: 2 }, RiscvPc)),
        _ => Err(fail("unsupported stack/PC register bank")),
    }
}
fn scalar(value: Scalar) -> Result<()> { require((1..=128).contains(&value.bits), "scalar width is outside the supported register-bit contract") }
fn full_mask(width: u16) -> u128 { if width == 128 { u128::MAX } else { (1_u128 << width) - 1 } }
fn masks(profile: &MachineProfile, values: &[RegisterView]) -> Result<BTreeMap<PhysicalRegister,u128>> {
    let mut out = BTreeMap::new();
    for &v in values {
        let (layout, bits) = view(profile, v)?; require(layout.role != Role::Zero, "zero register cannot be an external input")?;
        let previous = out.entry(v.register).or_insert(0); require(*previous & bits == 0, "overlapping/duplicate register input aliases")?; *previous |= bits;
    }
    Ok(out)
}
fn available(values: &BTreeMap<usize,u16>, id: usize) -> Result<u16> { values.get(&id).copied().ok_or_else(|| fail("SSA value is not defined earlier in this block/explicit parameters")) }
fn result(ins: &MachineInstruction, width: u16) -> Result<()> {
    require(ins.result.map(|v| v.bits) == Some(width), "operation result width/presence differs")
}
fn no_result(ins: &MachineInstruction) -> Result<()> { require(ins.result.is_none(), "effect-only operation cannot define a scalar result") }
fn initialized(state: &BTreeMap<PhysicalRegister,u128>, p: &MachineProfile, v: RegisterView) -> Result<()> {
    let (layout, bits) = view(p, v)?;
    require(layout.role == Role::Zero || state.get(&v.register).copied().unwrap_or(0) & bits == bits, "register read/exit uses undeclared uninitialized entry bits")
}
fn aligned(alignment: u64) -> Result<()> { require(alignment.is_power_of_two(), "memory/directive alignment must be a nonzero power of two") }
fn symbol(value: &str) -> Result<()> { require(!value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.$@".contains(&b)), "symbol contains unsupported characters") }
fn span(value: SourceSpan, extent: u64) -> Result<()> { require(value.start < value.end && value.end <= extent, "source item span is empty/out of selected source extent") }
fn directive_kind(d: &MachineDirective) -> SourceItemKind {
    match d {
        MachineDirective::CfiStart | MachineDirective::CfiEnd | MachineDirective::CfiDefCfa {..} | MachineDirective::CfiSaved {..} | MachineDirective::CfiRestore {..} => SourceItemKind::CfiDirective,
        MachineDirective::Alignment {..} => SourceItemKind::AlignmentDirective,
        MachineDirective::Symbol {..} => SourceItemKind::SymbolDirective,
        MachineDirective::UnsupportedData => SourceItemKind::DataDirective,
        MachineDirective::UnsupportedRelocation => SourceItemKind::RelocationDirective,
    }
}
fn coverage(items: &BTreeMap<SourceItemId,&SourceItem>, used: &mut BTreeMap<SourceItemId,usize>, id: SourceItemId, kind: SourceItemKind) -> Result<()> {
    let item = items.get(&id).ok_or_else(|| fail("body site has no independently selected inventory item"))?;
    require(item.kind == kind, "body site/inventory item kinds differ")?;
    let count = used.entry(id).or_insert(0); *count = count.checked_add(1).ok_or_else(|| fail("source site count overflow"))?;
    require(kind == SourceItemKind::Instruction || *count == 1, "duplicate directive/label coverage")
}
fn cfi(body: &MachineBodyContract, inventory: &SelectedInstructionInventory) -> Result<()> {
    let records: BTreeMap<_,_> = body.directives.iter().map(|d| (d.source_item, &d.directive)).collect();
    let mut active = false; let mut ended = false; let mut cfa = false; let mut saved = BTreeSet::new();
    for item in &inventory.items {
        // Required CFI must structurally cover each selected instruction site,
        // including control transfers. A balanced empty region elsewhere is
        // not coverage. This does not establish any unwind-rule semantics.
        if body.profile.cfi == CfiPolicy::Required && item.kind == SourceItemKind::Instruction {
            require(active, "machine instruction is outside the active required CFI region")?;
        }
        let Some(d) = records.get(&item.id) else { continue };
        match d {
            MachineDirective::CfiStart => { require(body.profile.cfi == CfiPolicy::Required && !active && !ended, "CFI start is repeated or not declared")?; active = true; }
            MachineDirective::CfiEnd => { require(active && cfa && !ended, "CFI end lacks active CFA state")?; active = false; ended = true; }
            MachineDirective::CfiDefCfa {register,..} => { let (l,_) = view(&body.profile,*register)?; require(active && register.bits == 64 && register.low_bit == 0 && matches!(l.role,Role::General|Role::Stack), "CFI CFA must use an active canonical address register")?; cfa = true; }
            MachineDirective::CfiSaved {register,..} => { view(&body.profile,*register)?; require(active && cfa && saved.insert(*register), "CFI saved-register rule lacks CFA or is duplicated")?; }
            MachineDirective::CfiRestore {register} => {
                view(&body.profile,*register)?;
                require(active && cfa, "CFI restore requires active CFA state")?;
                require(saved.remove(register), "CFI restore has no prior saved-register rule")?;
            }
            MachineDirective::Alignment {bytes} => aligned(*bytes)?,
            MachineDirective::Symbol {name} => symbol(name)?,
            MachineDirective::UnsupportedData | MachineDirective::UnsupportedRelocation => return Err(fail("data/relocation directive semantics are not implemented")),
        }
    }
    require(!active && (ended || body.profile.cfi == CfiPolicy::NoCfiDeclared), "required CFI region is missing or remains open")
}
/// Compute register-bit definedness before validating individual reads. Starting
/// reachable nonentry blocks at the register domain's top and intersecting all
/// predecessors gives the definite-assignment fixed point, including loops.
/// No iteration/node cap substitutes for convergence. Unreachable blocks retain
/// the declared entry floor for local structural checking; they are still fully
/// checked and inventoried, and acquire no additional external entry interface.
fn register_entry_facts(body:&MachineBodyContract,seed:&BTreeMap<PhysicalRegister,u128>)
    ->Result<BTreeMap<usize,BTreeMap<PhysicalRegister,u128>>> {
    type Facts=BTreeMap<PhysicalRegister,u128>;
    fn intersect(left:&mut Facts,right:&Facts) {
        left.retain(|register,mask| { *mask &= right.get(register).copied().unwrap_or(0); *mask!=0 });
    }
    fn transfer(body:&MachineBodyContract,block:&MachineBlock,mut facts:Facts)->Result<Facts> {
        for ins in &block.instructions {
            match &ins.operation {
                MachineOperation::WriteRegister {view:v,mode,..}=> {
                    let (layout,mask)=view(&body.profile,*v)?;
                    let affected=if *mode==WriteMode::ZeroExtendStorage {full_mask(layout.width)}else{mask};
                    *facts.entry(v.register).or_insert(0)|=affected;
                }
                MachineOperation::WriteFlags {view:v,..}=> {
                    let (_,mask)=flag_view(&body.profile,*v)?;
                    *facts.entry(v.register).or_insert(0)|=mask;
                }
                MachineOperation::InvalidateRegister {view:v}=> {
                    let (_,mask)=if matches!(v.register,PhysicalRegister::X86Flags|PhysicalRegister::Aarch64Nzcv) {
                        flag_view(&body.profile,*v)?
                    }else{view(&body.profile,*v)?};
                    if let Some(bits)=facts.get_mut(&v.register) { *bits &= !mask; }
                }
                _=>{},
            }
        }
        facts.retain(|_,mask|*mask!=0);Ok(facts)
    }
    let blocks:BTreeMap<_,_>=body.blocks.iter().map(|b|(b.id,b)).collect();
    let mut predecessors:BTreeMap<usize,BTreeSet<usize>>=blocks.keys().map(|id|(*id,BTreeSet::new())).collect();
    let mut successors=BTreeMap::<usize,Vec<usize>>::new();
    let mut top=Facts::new();
    {
        let mut add=|v:RegisterView,flags:bool|->Result<()> {
            let (layout,_)=if flags {flag_view(&body.profile,v)?}else{view(&body.profile,v)?};
            top.insert(v.register,full_mask(layout.width));Ok(())
        };
        for &v in &body.interface.entry.initialized {add(v,false)?;}
        for exit in &body.interface.exits {
            for &v in exit.outputs.iter().chain(&exit.preserved) {add(v,false)?;}
        }
        for block in &body.blocks {
            for ins in &block.instructions {
                match &ins.operation {
                    MachineOperation::ReadRegister {view:v}|MachineOperation::WriteRegister {view:v,..}=>add(*v,false)?,
                    MachineOperation::ReadFlags {view:v}|MachineOperation::WriteFlags {view:v,..}=>add(*v,true)?,
                    MachineOperation::InvalidateRegister {view:v}=>add(*v,matches!(v.register,PhysicalRegister::X86Flags|PhysicalRegister::Aarch64Nzcv))?,
                    _=>{},
                }
            }
        }
    }
    for block in &body.blocks {
        let next=match &block.terminator.control {
            MachineControl::Jump {edge}=>vec![edge.target],
            MachineControl::Branch {on_true,on_false,..}=>vec![on_true.target,on_false.target],
            MachineControl::Return {..}|MachineControl::ReturnTo {..}|MachineControl::RestoreContext {..}=>vec![],
        };
        for id in &next {
            let Some(preds)=predecessors.get_mut(id) else {return Err(fail("control edge target is missing"));};
            preds.insert(block.id);
        }
        successors.insert(block.id,next);
    }
    let mut reachable=BTreeSet::new();let mut pending=vec![body.entry];
    while let Some(id)=pending.pop() {
        if reachable.insert(id) {
            pending.extend(successors.get(&id).ok_or_else(||fail("missing machine entry block"))?.iter().copied());
        }
    }
    let mut incoming=BTreeMap::new();let mut outgoing=BTreeMap::new();
    for (&id,block) in &blocks {
        let facts=if id==body.entry || !reachable.contains(&id) {seed.clone()}else{top.clone()};
        outgoing.insert(id,transfer(body,block,facts.clone())?);incoming.insert(id,facts);
    }
    loop {
        let mut changed=false;
        for (&id,block) in &blocks {
            if !reachable.contains(&id) {continue;}
            // External entry is a real predecessor, also when a loop returns
            // to the entry block. Backedge writes cannot invent entry facts.
            let mut facts=if id==body.entry {seed.clone()}else{top.clone()};
            let mut has_predecessor=id==body.entry;
            for pred in &predecessors[&id] {
                if reachable.contains(pred) {
                    intersect(&mut facts,&outgoing[pred]);has_predecessor=true;
                }
            }
            require(has_predecessor,"reachable nonentry block has no predecessor")?;
            let out=transfer(body,block,facts.clone())?;
            if incoming.get(&id)!=Some(&facts) || outgoing.get(&id)!=Some(&out) {changed=true;}
            incoming.insert(id,facts);outgoing.insert(id,out);
        }
        if !changed {break;}
    }
    Ok(incoming)
}
/// Structural coverage ONLY. Both inputs remain unauthenticated claims until a
/// separate original-source producer and semantic lift are independently proven.
pub fn verify(body: &MachineBodyContract, inventory: &SelectedInstructionInventory, target: Target) -> Result<StructuralReport> {
    let computed_control = body.format == COMPUTED_CONTROL_FORMAT;
    require((body.format == FORMAT || computed_control) && inventory.format == INVENTORY_FORMAT, "machine/inventory contract version differs")?;
    identity(&inventory.identity)?; source(&body.source)?; profile(&body.profile,target)?; symbol(&body.symbol)?;
    require(body.selected_inventory == inventory.identity && body.source == inventory.source && body.symbol == inventory.symbol && body.profile == inventory.profile && body.interface == inventory.interface, "body differs from separately selected inventory/source/profile/interface contract")?;
    require(body.interface.entry.policy == EntryPolicy::NoImplicitFrameOrScratch, "ordinary prologue/unverified entry snapshot cannot realize machine entry state")?;
    let seed = masks(&body.profile, &body.interface.entry.initialized)?;
    let (sp, pc) = stack_pc(body.profile.architecture)?;
    for register in [sp,pc] { initialized(&seed,&body.profile,RegisterView {register,low_bit:0,bits:64})?; }
    let mut exits = BTreeMap::new(); let mut protected = BTreeMap::<PhysicalRegister,u128>::new();
    for exit in &body.interface.exits {
        require(exits.insert(exit.id,exit).is_none(), "duplicate exit interface")?;
        require(exit.kind == ExitKind::OrdinaryReturn, "restored SP/PC exit requires unimplemented semantic/provider proof")?;
        masks(&body.profile,&exit.preserved)?; masks(&body.profile,&exit.outputs)?;
        for &v in &exit.preserved { initialized(&seed,&body.profile,v)?; let (_,m)=view(&body.profile,v)?; *protected.entry(v.register).or_insert(0) |= m; }
    }
    require(!exits.is_empty(), "explicit exit interface is required")?;
    let files: BTreeMap<_,_> = body.source.files.iter().map(|f|(f.id,f)).collect();
    let mut items = BTreeMap::new(); let mut previous = 0;
    for item in &inventory.items {
        require(items.insert(item.id,item).is_none(), "duplicate independently selected source item")?;
        span(item.decoded_span,body.source.decoded_assembly.bytes)?; require(item.decoded_span.start >= previous, "selected source item spans overlap/out of order")?; previous=item.decoded_span.end;
        require(!item.origins.is_empty(), "selected item lacks original-source origin")?;
        for origin in &item.origins { let file=files.get(&origin.file).ok_or_else(||fail("selected item references unknown original source file"))?; span(origin.span,file.identity.bytes)?; }
    }
    require(!items.is_empty(), "separately selected source inventory is empty")?;
    let mut blocks = BTreeMap::new(); let mut states = BTreeSet::new(); let mut definitions = BTreeSet::new();
    for b in &body.blocks {
        require(blocks.insert(b.id,b).is_none(), "duplicate machine block")?;
        require(states.insert(b.state_parameter), "duplicate state SSA definition")?;
        for v in &b.parameters { scalar(*v)?; require(definitions.insert(v.id), "duplicate scalar SSA definition")?; }
        for i in &b.instructions {
            require(states.insert(i.state_out), "duplicate state SSA definition")?;
            if let Some(v)=i.result { scalar(v)?; require(definitions.insert(v.id), "duplicate scalar SSA definition")?; }
        }
    }
    let entry=blocks.get(&body.entry).ok_or_else(||fail("missing machine entry block"))?;
    require(entry.parameters.is_empty(), "machine entry scalar parameters must arrive through explicit register interface")?;
    let register_inputs=register_entry_facts(body,&seed)?;
    let mut used=BTreeMap::new(); let mut sites=0_usize;
    for d in &body.directives { coverage(&items,&mut used,d.source_item,directive_kind(&d.directive))?; }
    for b in &body.blocks {
        if let Some(label)=b.source_label { coverage(&items,&mut used,label,SourceItemKind::Label)?; }
        let mut values: BTreeMap<_,_>=b.parameters.iter().map(|v|(v.id,v.bits)).collect();
        let mut state=b.state_parameter; let mut registers=register_inputs[&b.id].clone();
        for i in &b.instructions {
            coverage(&items,&mut used,i.source_item,SourceItemKind::Instruction)?; sites=sites.checked_add(1).ok_or_else(||fail("instruction site count overflow"))?;
            require(i.state_in == state && i.state_out != state, "state SSA chain is stale/missing/out of order")?;
            match &i.operation {
                MachineOperation::Constant {little_endian} => { let out=i.result.ok_or_else(||fail("constant requires result"))?; let bytes=usize::from(out.bits.div_ceil(8)); require(little_endian.len()==bytes,"constant byte extent differs from scalar width")?; if out.bits%8!=0 { require(little_endian[bytes-1] >> (out.bits%8) == 0,"constant has nonzero undefined high padding bits")?; } }
                MachineOperation::ReadRegister {view:v} => { initialized(&registers,&body.profile,*v)?; result(i,v.bits)?; }
                MachineOperation::WriteRegister {view:v,value,mode} => {
                    no_result(i)?; let (layout,mask)=view(&body.profile,*v)?;
                    require(!matches!(layout.role,Role::Stack|Role::Pc|Role::Zero|Role::Flags), "SP/PC/zero/flags register writes require an unimplemented state realization")?;
                    require(available(&values,*value)?==v.bits,"register write scalar width differs")?;
                    let whole=v.low_bit==0 && v.bits==layout.width;
                    let valid=if layout.zero_extend_32 && v.bits==32 && v.low_bit==0 { *mode==WriteMode::ZeroExtendStorage } else if whole { *mode==WriteMode::WholeStorage } else { *mode==WriteMode::PreserveOtherBits || (layout.role==Role::Floating && *mode==WriteMode::ZeroExtendStorage) };
                    require(valid,"register alias write/zero-extension mode differs")?;
                    let affected=if *mode==WriteMode::ZeroExtendStorage {full_mask(layout.width)} else {mask};
                    require(protected.get(&v.register).copied().unwrap_or(0)&affected==0,"write overlaps readonly exit-preserved register bits")?;
                    *registers.entry(v.register).or_insert(0)|=affected;
                }
                MachineOperation::ReadFlags {view:v} => {
                    let (_,mask)=flag_view(&body.profile,*v)?;
                    require(registers.get(&v.register).copied().unwrap_or(0)&mask==mask,"arithmetic flag read uses undefined/uninitialized bits")?;
                    result(i,v.bits)?;
                }
                MachineOperation::WriteFlags {view:v,value} => {
                    no_result(i)?;let (_,mask)=flag_view(&body.profile,*v)?;
                    require(available(&values,*value)?==v.bits,"flag write scalar width differs")?;
                    require(protected.get(&v.register).copied().unwrap_or(0)&mask==0,"flag write overlaps readonly exit-preserved register bits")?;
                    *registers.entry(v.register).or_insert(0)|=mask;
                }
                MachineOperation::InvalidateRegister {view:v} => {
                    no_result(i)?;
                    let (layout,mask)=if matches!(v.register,PhysicalRegister::X86Flags|PhysicalRegister::Aarch64Nzcv) {flag_view(&body.profile,*v)?} else {view(&body.profile,*v)?};
                    require(!matches!(layout.role,Role::Stack|Role::Pc|Role::Zero),"SP/PC/zero invalidation is forbidden")?;
                    require(protected.get(&v.register).copied().unwrap_or(0)&mask==0,"invalidation overlaps readonly exit-preserved register bits")?;
                    *registers.entry(v.register).or_insert(0)&=!mask;
                }
                MachineOperation::Cast {kind,value} => {
                    let input=available(&values,*value)?;
                    let output=i.result.ok_or_else(||fail("cast requires scalar result"))?.bits;
                    let valid=match kind {ExtensionKind::Truncate=>output<input,ExtensionKind::ZeroExtend|ExtensionKind::SignExtend=>output>input};
                    require(valid,"integer cast direction/width differs from declared extension kind")?;
                }
                MachineOperation::Binary {lhs,rhs,..} => { let bits=available(&values,*lhs)?; require(bits==available(&values,*rhs)?,"binary operands differ in width")?; result(i,bits)?; }
                MachineOperation::Compare {lhs,rhs,..} => { require(available(&values,*lhs)?==available(&values,*rhs)?,"comparison operands differ in width")?; result(i,1)?; }
                MachineOperation::Load {address,alignment} => { require(body.interface.entry.memory==MemoryInterface::OrderedProcessData,"load requires explicit ordered process-memory interface")?; require(available(&values,*address)?==64,"memory address must be 64-bit")?; aligned(*alignment)?; let out=i.result.ok_or_else(||fail("load requires scalar result"))?; require([8,16,32,64,128].contains(&out.bits),"unsupported exact-byte load width")?; }
                MachineOperation::Store {address,value,alignment} => { no_result(i)?; require(body.interface.entry.memory==MemoryInterface::OrderedProcessData,"store requires explicit ordered process-memory interface")?; require(available(&values,*address)?==64,"memory address must be 64-bit")?; require([8,16,32,64,128].contains(&available(&values,*value)?),"unsupported exact-byte store width")?; aligned(*alignment)?; }
            }
            if let Some(v)=i.result { values.insert(v.id,v.bits); } state=i.state_out;
        }
        coverage(&items,&mut used,b.terminator.source_item,SourceItemKind::Instruction)?; sites=sites.checked_add(1).ok_or_else(||fail("instruction site count overflow"))?;
        require(b.terminator.state==state,"control transfer must consume final state SSA token")?;
        let edge=|e:&Edge|->Result<()> { let next=blocks.get(&e.target).ok_or_else(||fail("control edge target is missing"))?; require(e.arguments.len()==next.parameters.len(),"edge/block-parameter membership differs")?; for (argument,param) in e.arguments.iter().zip(&next.parameters) { require(available(&values,*argument)?==param.bits,"edge/block-parameter width differs")?; } Ok(()) };
        match &b.terminator.control {
            MachineControl::Jump {edge:e} => edge(e)?,
            MachineControl::Branch {condition,on_true,on_false} => { require(available(&values,*condition)?==1,"branch condition must be exactly one bit")?; edge(on_true)?; edge(on_false)?; }
            MachineControl::Return {exit} => {
                require(!computed_control,"legacy return marker is only a v2 structural contract")?;
                let e=exits.get(exit).ok_or_else(||fail("return has no selected exit interface"))?;
                for &v in e.preserved.iter().chain(&e.outputs) { initialized(&registers,&body.profile,v)?; }
            }
            MachineControl::ReturnTo {exit,target,mechanism} => {
                require(computed_control,"computed return requires v3 machine contract")?;
                require(available(&values,*target)? == body.profile.address_bits,"return target must have exact profile address width")?;
                return_mechanism(&body.profile,*mechanism)?;
                let e=exits.get(exit).ok_or_else(||fail("return has no selected exit interface"))?;
                for &v in e.preserved.iter().chain(&e.outputs) { initialized(&registers,&body.profile,v)?; }
            }
            MachineControl::RestoreContext {..} => return Err(fail("restored SP/PC transfer is unsupported without semantic/provider proof")),
        }
    }
    for item in items.values() { require(used.get(&item.id).copied().unwrap_or(0)>0,"missing independently selected original instruction/directive/label coverage")?; }
    cfi(body,inventory)?;
    Ok(StructuralReport { format:if computed_control {"ocore-machine-structure-relative-inventory-v3"} else {"ocore-machine-structure-relative-inventory-v2"},target:target.id(),checked_inventory_items:items.len(),checked_instruction_sites:sites,structural_coverage_relative_to_supplied_inventory:true,source_custody_verified:false,inventory_authority_verified:false,original_unit_completeness_verified:false,instruction_semantics_verified:false,native_realization_verified:false,cfi_semantics_verified:false,memory_access_validity_verified:false,entry_state_realization_verified:false,provider_qualified:false,runtime_qualified:false,isa_equivalence_qualified:false,ordinary_native_admission:false })
}

#[cfg(test)]
#[path = "native_machine_verify_tests.rs"]
mod tests;
