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
mod tests {
    use super::*;
    fn identity_fixture(digit: char) -> ArtifactIdentity { ArtifactIdentity {bytes:1024,sha256:digit.to_string().repeat(64)} }
    fn register(register: PhysicalRegister, bits: u16) -> RegisterView { RegisterView {register,low_bit:0,bits} }
    fn registers(t: Target) -> (PhysicalRegister,PhysicalRegister,PhysicalRegister,PhysicalRegister) {
        use PhysicalRegister::*;
        match t {
            Target::X86_64UnknownNone => (X86Gpr{name:Gpr::Rdi},X86Gpr{name:Gpr::Rax},X86Gpr{name:Gpr::Rsp},X86Pc),
            Target::Aarch64UnknownNone => (Aarch64Gpr{index:0},Aarch64Gpr{index:9},Aarch64Sp,Aarch64Pc),
            Target::Riscv64UnknownNone => (RiscvGpr{index:10},RiscvGpr{index:5},RiscvGpr{index:2},RiscvPc),
        }
    }
    /// Inert metadata fixture only. No assembly text, GNU provenance, parser or
    /// original-source completeness proof is manufactured by this constructor.
    fn fixture(t: Target) -> (MachineBodyContract,SelectedInstructionInventory) {
        let (arg,scratch,sp,pc)=registers(t);
        let profile=MachineProfile {architecture:architecture(t),abi:match t {Target::X86_64UnknownNone=>MachineAbi::SysvAmd64,Target::Aarch64UnknownNone=>MachineAbi::Aapcs64,Target::Riscv64UnknownNone=>MachineAbi::RiscvLp64d},address_bits:64,byte_order:ByteOrder::Little,entry_stack_alignment:16,entry_stack_remainder:if t==Target::X86_64UnknownNone {8}else{0},features:vec![StateFeature::UserRegisterBits],cfi:CfiPolicy::Required};
        let interface=MachineInterface {entry:EntryInterface {policy:EntryPolicy::NoImplicitFrameOrScratch,initialized:vec![register(arg,64),register(sp,64),register(pc,64)],memory:MemoryInterface::None},exits:vec![ExitInterface {id:0,kind:ExitKind::OrdinaryReturn,outputs:vec![register(scratch,64)],preserved:vec![register(sp,64)]}]};
        let source=SourceWitness {format:SOURCE_FORMAT.into(),input_form:MachineInputForm::ConfiguredAssemblyText,unit_id:"inert-metadata-fixture".into(),files:vec![SourceFile{id:0,logical_path:"inert-metadata-only.source".into(),identity:identity_fixture('1')}],decoded_assembly:identity_fixture('2'),build_configuration:identity_fixture('3'),frontend_event:identity_fixture('4')};
        let items=(0_u64..6).map(|id|SourceItem{id,kind:if [2,3,4].contains(&id){SourceItemKind::Instruction}else{SourceItemKind::CfiDirective},decoded_span:SourceSpan{start:id*8,end:id*8+8},origins:vec![OriginalSpan{file:0,span:SourceSpan{start:id*8,end:id*8+8}}]}).collect();
        let inventory=SelectedInstructionInventory {format:INVENTORY_FORMAT.into(),identity:identity_fixture('5'),source:source.clone(),symbol:"inert_fixture".into(),profile:profile.clone(),interface:interface.clone(),items};
        let body=MachineBodyContract {format:FORMAT.into(),selected_inventory:inventory.identity.clone(),source,symbol:"inert_fixture".into(),profile,interface,entry:0,blocks:vec![MachineBlock{id:0,source_label:None,state_parameter:0,parameters:vec![],instructions:vec![MachineInstruction{source_item:2,state_in:0,state_out:1,result:Some(Scalar{id:0,bits:64}),operation:MachineOperation::ReadRegister{view:register(arg,64)}},MachineInstruction{source_item:3,state_in:1,state_out:2,result:None,operation:MachineOperation::WriteRegister{view:register(scratch,64),value:0,mode:WriteMode::WholeStorage}}],terminator:MachineTerminator{source_item:4,state:2,control:MachineControl::Return{exit:0}}}],directives:vec![DirectiveRecord{source_item:0,directive:MachineDirective::CfiStart},DirectiveRecord{source_item:1,directive:MachineDirective::CfiDefCfa{register:register(sp,64),offset:0}},DirectiveRecord{source_item:5,directive:MachineDirective::CfiEnd}]};
        (body,inventory)
    }
    fn rejected(body:&MachineBodyContract,floor:&SelectedInstructionInventory,t:Target,message:&str) {
        let error=verify(body,floor,t).unwrap_err(); assert!(error.message.contains(message),"{} did not contain {message}",error.message);
    }
    #[test]
    fn all_canonical_targets_have_only_relative_structural_coverage() {
        for &t in Target::ALL {
            let (b,i)=fixture(t);let report=verify(&b,&i,t).unwrap();
            assert_eq!(report.checked_inventory_items,6);assert_eq!(report.checked_instruction_sites,3);
            assert!(report.structural_coverage_relative_to_supplied_inventory);
            assert!(!report.source_custody_verified && !report.inventory_authority_verified && !report.original_unit_completeness_verified);
            assert!(!report.instruction_semantics_verified && !report.native_realization_verified && !report.entry_state_realization_verified);
            assert!(!report.cfi_semantics_verified && !report.memory_access_validity_verified);
            assert!(!report.provider_qualified && !report.runtime_qualified && !report.isa_equivalence_qualified && !report.ordinary_native_admission);
        }
    }
    #[test]
    fn x86_high_byte_alias_is_not_available_on_rsi() {
        let (mut b,i)=fixture(Target::X86_64UnknownNone);let bad=RegisterView{register:PhysicalRegister::X86Gpr{name:Gpr::Rsi},low_bit:8,bits:8};
        b.blocks[0].instructions[0].operation=MachineOperation::ReadRegister{view:bad};assert_eq!(bad.low_bit,8);
        rejected(&b,&i,Target::X86_64UnknownNone,"alias/width");
    }
    #[test]
    fn overlapping_entry_aliases_do_not_create_independent_storage() {
        let (mut b,mut i)=fixture(Target::X86_64UnknownNone);let reg=PhysicalRegister::X86Gpr{name:Gpr::Rax};b.interface.entry.initialized.extend([register(reg,64),register(reg,32)]);i.interface=b.interface.clone();
        assert_eq!(b.interface.entry.initialized.len(),5);rejected(&b,&i,Target::X86_64UnknownNone,"overlapping/duplicate");
    }
    #[test]
    fn invalid_view_width_is_refused_before_any_realization() {
        let (mut b,i)=fixture(Target::Riscv64UnknownNone);let bad=register(PhysicalRegister::RiscvGpr{index:10},65);b.blocks[0].instructions[0].operation=MachineOperation::ReadRegister{view:bad};assert_eq!(bad.bits,65);
        rejected(&b,&i,Target::Riscv64UnknownNone,"alias/width");
    }
    #[test]
    fn x86_32bit_write_requires_upper_storage_zero_extension() {
        let (mut b,i)=fixture(Target::X86_64UnknownNone);let (arg,temp,_,_)=registers(Target::X86_64UnknownNone);
        b.blocks[0].instructions[0].operation=MachineOperation::ReadRegister{view:register(arg,32)};b.blocks[0].instructions[0].result=Some(Scalar{id:0,bits:32});
        b.blocks[0].instructions[1].operation=MachineOperation::WriteRegister{view:register(temp,32),value:0,mode:WriteMode::PreserveOtherBits};
        rejected(&b,&i,Target::X86_64UnknownNone,"alias write/zero-extension");
        b.blocks[0].instructions[1].operation=MachineOperation::WriteRegister{view:register(temp,32),value:0,mode:WriteMode::ZeroExtendStorage};assert!(verify(&b,&i,Target::X86_64UnknownNone).is_ok());
    }
    #[test]
    fn undeclared_entry_register_bits_cannot_be_read() {
        for &t in Target::ALL {let (mut b,mut i)=fixture(t);let arg=registers(t).0;b.interface.entry.initialized.retain(|v|v.register!=arg);i.interface=b.interface.clone();assert_eq!(b.interface.entry.initialized.len(),2);rejected(&b,&i,t,"uninitialized entry bits");}
    }
    #[test]
    fn ordinary_prologue_and_unverified_snapshot_are_not_entry_preservation_proofs() {
        for policy in [EntryPolicy::OrdinaryCompilerPrologue,EntryPolicy::UnverifiedEntrySnapshot] {let (mut b,mut i)=fixture(Target::Aarch64UnknownNone);b.interface.entry.policy=policy;i.interface=b.interface.clone();assert_eq!(b.interface.entry.policy,policy);rejected(&b,&i,Target::Aarch64UnknownNone,"ordinary prologue/unverified entry snapshot");}
    }
    #[test]
    fn state_tokens_must_follow_each_instruction_and_final_transfer() {
        let t=Target::X86_64UnknownNone;let (base,i)=fixture(t);let mut b=base.clone();b.blocks[0].instructions[1].state_in=0;assert_ne!(b.blocks[0].instructions[1].state_in,b.blocks[0].instructions[0].state_out);rejected(&b,&i,t,"state SSA chain");
        b=base;b.blocks[0].terminator.state=0;assert_ne!(b.blocks[0].terminator.state,b.blocks[0].instructions[1].state_out);rejected(&b,&i,t,"final state SSA token");
    }
    #[test]
    fn duplicate_state_and_scalar_definitions_are_rejected() {
        let t=Target::Riscv64UnknownNone;let (base,i)=fixture(t);let mut b=base.clone();b.blocks[0].instructions[1].state_out=1;rejected(&b,&i,t,"duplicate state SSA");
        b=base;b.blocks[0].instructions[1].result=Some(Scalar{id:0,bits:64});rejected(&b,&i,t,"duplicate scalar SSA");
    }
    #[test]
    fn scalar_use_before_definition_is_rejected() {
        let t=Target::Aarch64UnknownNone;let (mut b,i)=fixture(t);let temp=registers(t).1;b.blocks[0].instructions[1].operation=MachineOperation::WriteRegister{view:register(temp,64),value:99,mode:WriteMode::WholeStorage};
        assert!(matches!(b.blocks[0].instructions[1].operation,MachineOperation::WriteRegister{value:99,..}));rejected(&b,&i,t,"SSA value is not defined earlier");
    }
    #[test]
    fn ordered_memory_interface_is_required_for_loads() {
        let t=Target::Riscv64UnknownNone;let (mut b,i)=fixture(t);b.blocks[0].instructions[1].operation=MachineOperation::Load{address:0,alignment:8};b.blocks[0].instructions[1].result=Some(Scalar{id:1,bits:64});assert_eq!(b.interface.entry.memory,MemoryInterface::None);rejected(&b,&i,t,"load requires explicit ordered process-memory");
    }
    #[test]
    fn control_edges_need_existing_targets_and_one_bit_conditions() {
        let t=Target::Aarch64UnknownNone;let (base,i)=fixture(t);let mut b=base.clone();b.blocks[0].terminator.control=MachineControl::Jump{edge:Edge{target:999,arguments:vec![]}};rejected(&b,&i,t,"edge target is missing");
        b=base;b.blocks[0].terminator.control=MachineControl::Branch{condition:0,on_true:Edge{target:0,arguments:vec![]},on_false:Edge{target:0,arguments:vec![]}};rejected(&b,&i,t,"exactly one bit");
    }
    #[test]
    fn cross_block_values_require_explicit_parameters_and_unique_state_interface() {
        for &t in Target::ALL {
            let (mut b,mut i)=fixture(t);let temporary=registers(t).1;
            b.blocks[0].terminator.control=MachineControl::Jump{edge:Edge{target:1,arguments:vec![0]}};
            b.blocks.push(MachineBlock{id:1,source_label:None,state_parameter:3,parameters:vec![Scalar{id:1,bits:64}],instructions:vec![MachineInstruction{source_item:6,state_in:3,state_out:4,result:None,operation:MachineOperation::WriteRegister{view:register(temporary,64),value:1,mode:WriteMode::WholeStorage}}],terminator:MachineTerminator{source_item:7,state:4,control:MachineControl::Return{exit:0}}});
            let end=i.items.pop().unwrap();
            for id in [6,7] {let mut item=i.items[2].clone();item.id=id;i.items.push(item);}
            i.items.push(end);
            for (index,item) in i.items.iter_mut().enumerate() {item.decoded_span=SourceSpan{start:index as u64*8,end:index as u64*8+8};item.origins[0].span=item.decoded_span;}
            let report=verify(&b,&i,t).unwrap();assert_eq!(report.checked_inventory_items,8);assert_eq!(report.checked_instruction_sites,5);assert!(!report.instruction_semantics_verified);
            let mut bad=b.clone();bad.blocks[1].instructions[0].operation=MachineOperation::WriteRegister{view:register(temporary,64),value:0,mode:WriteMode::WholeStorage};rejected(&bad,&i,t,"SSA value is not defined earlier");
            bad=b.clone();bad.blocks[1].parameters[0].bits=32;rejected(&bad,&i,t,"edge/block-parameter width differs");
            bad=b;bad.blocks[1].state_parameter=1;rejected(&bad,&i,t,"duplicate state SSA definition");
        }
    }
    #[test]
    fn separately_selected_floor_catches_missing_instruction_and_directive() {
        let t=Target::X86_64UnknownNone;let (base,mut floor)=fixture(t);let mut extra=floor.items[2].clone();extra.id=6;extra.decoded_span=SourceSpan{start:48,end:56};floor.items.push(extra);assert_eq!(floor.items.len(),7);rejected(&base,&floor,t,"missing independently selected original instruction");
        let (mut b,i)=fixture(t);b.directives.pop();assert_eq!(b.directives.len(),2);rejected(&b,&i,t,"missing independently selected original instruction/directive");
    }
    #[test]
    fn duplicate_inventory_ids_and_duplicate_directive_coverage_are_not_counts() {
        let t=Target::X86_64UnknownNone;let (base,mut i)=fixture(t);let mut dupe=i.items[2].clone();dupe.decoded_span=SourceSpan{start:48,end:56};i.items.push(dupe);rejected(&base,&i,t,"duplicate independently selected source item");
        let (mut b,i)=fixture(t);b.directives.push(b.directives[0].clone());assert_eq!(b.directives.len(),4);rejected(&b,&i,t,"duplicate directive/label coverage");
    }
    #[test]
    fn inactive_cfi_restore_and_unclosed_region_are_rejected() {
        let t=Target::X86_64UnknownNone;let (base,i)=fixture(t);let mut b=base.clone();b.directives[0].directive=MachineDirective::CfiRestore{register:register(registers(t).0,64)};rejected(&b,&i,t,"CFI restore requires active CFA state");
        b=base;b.directives[2].directive=MachineDirective::CfiDefCfa{register:register(registers(t).2,64),offset:0};rejected(&b,&i,t,"required CFI region is missing or remains open");
    }
    #[test]
    fn cfi_cfa_cannot_be_a_floating_register_view() {
        let t=Target::Aarch64UnknownNone;let (mut b,i)=fixture(t);b.directives[1].directive=MachineDirective::CfiDefCfa{register:register(PhysicalRegister::Aarch64Vector{index:0},64),offset:0};rejected(&b,&i,t,"CFI CFA must use");
    }
    #[test]
    fn source_spans_and_original_file_bindings_are_required() {
        let t=Target::Riscv64UnknownNone;let (b,mut i)=fixture(t);i.items[2].origins[0].file=99;assert_eq!(i.items[2].origins[0].file,99);rejected(&b,&i,t,"unknown original source file");
        let (b,mut i)=fixture(t);i.items[2].decoded_span.end=2000;rejected(&b,&i,t,"out of selected source extent");
    }
    #[test]
    fn cross_target_profile_abi_and_registers_are_rejected() {
        let t=Target::X86_64UnknownNone;let (base,i)=fixture(t);rejected(&base,&i,Target::Aarch64UnknownNone,"selected canonical target");
        let mut b=base.clone();b.blocks[0].instructions[0].operation=MachineOperation::ReadRegister{view:register(PhysicalRegister::Aarch64Gpr{index:0},64)};rejected(&b,&i,t,"cross-target register");
        b=base;let mut i=i;b.profile.abi=MachineAbi::RiscvLp64d;i.profile=b.profile.clone();rejected(&b,&i,t,"unsupported machine ABI");
    }
    #[test]
    fn i686_armv7_and_security_or_tls_states_remain_explicitly_unsupported() {
        let t=Target::X86_64UnknownNone;
        for arch in [Architecture::I686,Architecture::Armv7] {let (mut b,mut i)=fixture(t);b.profile.architecture=arch;i.profile=b.profile.clone();rejected(&b,&i,t,"foundations are not implemented");}
        for feature in [StateFeature::ThreadPointer,StateFeature::TlsPointerMangling,StateFeature::CetShadowStack,StateFeature::PointerAuthentication,StateFeature::GuardedControlStack,StateFeature::ScalableMatrixZa,StateFeature::FloatingEnvironment] {let (mut b,mut i)=fixture(t);b.profile.features.push(feature);i.profile=b.profile.clone();assert_eq!(b.profile.features.len(),2);rejected(&b,&i,t,"state feature is not implemented");}
    }
    #[test]
    fn direct_sp_pc_writes_and_restored_control_remain_closed() {
        for &t in Target::ALL {
            let (base,i)=fixture(t);
            for target in [registers(t).2,registers(t).3] {let mut b=base.clone();b.blocks[0].instructions[1].operation=MachineOperation::WriteRegister{view:register(target,64),value:0,mode:WriteMode::WholeStorage};rejected(&b,&i,t,"SP/PC/zero/flags");}
            let mut b=base;b.blocks[0].terminator.control=MachineControl::RestoreContext{stack_pointer:0,program_counter:0};rejected(&b,&i,t,"restored SP/PC transfer is unsupported");
        }
    }
    #[test]
    fn readonly_exit_preservation_blocks_overlapping_alias_writes() {
        let t=Target::X86_64UnknownNone;let (mut b,mut i)=fixture(t);let temp=registers(t).1;b.interface.entry.initialized.push(register(temp,64));b.interface.exits[0].preserved.push(register(temp,8));i.interface=b.interface.clone();assert_eq!(b.interface.exits[0].preserved.len(),2);rejected(&b,&i,t,"write overlaps readonly exit-preserved");
    }
    #[test]
    fn changed_selected_provenance_cannot_be_relabelled_as_the_same_source() {
        let t=Target::X86_64UnknownNone;let (mut b,i)=fixture(t);b.source.files[0].identity.sha256="a".repeat(64);assert_ne!(b.source,i.source);rejected(&b,&i,t,"separately selected inventory/source/profile/interface");
    }
    #[test]
    fn data_directives_cannot_escape_as_unchecked_machine_bytes() {
        let t=Target::X86_64UnknownNone;let (mut b,mut i)=fixture(t);i.items[5].kind=SourceItemKind::DataDirective;b.directives[2].directive=MachineDirective::UnsupportedData;rejected(&b,&i,t,"data/relocation directive semantics are not implemented");
    }
    #[test]
    fn exit_output_bits_must_be_initialized_by_entry_or_body() {
        let t=Target::Aarch64UnknownNone;let (mut b,i)=fixture(t);b.blocks[0].instructions[1].operation=MachineOperation::Constant{little_endian:vec![0;8]};b.blocks[0].instructions[1].result=Some(Scalar{id:1,bits:64});
        assert_eq!(b.interface.exits[0].outputs,vec![register(registers(t).1,64)]);rejected(&b,&i,t,"uninitialized entry bits");
    }
    #[test]
    fn unknown_opcodes_architectures_and_fields_cannot_be_deserialized() {
        assert!(serde_json::from_str::<MachineOperation>(r#"{"op":"raw_assembly","text":"untrusted"}"#).is_err());
        assert!(serde_json::from_str::<Architecture>(r#""unknown_isa""#).is_err());
        let (b,_)=fixture(Target::X86_64UnknownNone);let mut value=serde_json::to_value(b).unwrap();value["qualified"]=serde_json::json!(true);assert!(serde_json::from_value::<MachineBodyContract>(value).is_err());
    }

    // Authored inert metadata controls. These do not authenticate an original
    // source inventory, interpret CFI offsets, or realize machine entry state.
    fn relative_cfi_only(report: &StructuralReport) {
        assert!(report.structural_coverage_relative_to_supplied_inventory);
        assert!(!report.source_custody_verified && !report.inventory_authority_verified && !report.original_unit_completeness_verified);
        assert!(!report.instruction_semantics_verified && !report.native_realization_verified && !report.cfi_semantics_verified);
        assert!(!report.memory_access_validity_verified && !report.entry_state_realization_verified);
        assert!(!report.provider_qualified && !report.runtime_qualified && !report.isa_equivalence_qualified && !report.ordinary_native_admission);
    }
    fn respan_cfi_fixture(inventory: &mut SelectedInstructionInventory) {
        for (index,item) in inventory.items.iter_mut().enumerate() {
            assert_eq!(item.origins.len(),1);
            let start=index as u64*8;
            item.decoded_span=SourceSpan{start,end:start+8};
            item.origins[0].span=item.decoded_span;
        }
    }
    fn cfi_saved_fixture(t: Target) -> (MachineBodyContract,SelectedInstructionInventory) {
        let (mut body,mut inventory)=fixture(t);
        let arg=register(registers(t).0,64);
        body.directives.insert(2,DirectiveRecord{source_item:6,directive:MachineDirective::CfiSaved{register:arg,offset:-8}});
        body.directives.insert(3,DirectiveRecord{source_item:7,directive:MachineDirective::CfiRestore{register:arg}});
        let mut saved=inventory.items[0].clone();saved.id=6;
        let mut restored=saved.clone();restored.id=7;
        inventory.items.insert(2,saved);inventory.items.insert(3,restored);
        respan_cfi_fixture(&mut inventory);
        (body,inventory)
    }
    #[test]
    fn required_cfi_region_covers_instructions_and_return_not_an_empty_region() {
        for &t in Target::ALL {
            let (body,baseline)=fixture(t);
            relative_cfi_only(&verify(&body,&baseline,t).unwrap());
            assert_eq!(body.profile.cfi,CfiPolicy::Required);
            assert!(matches!(body.blocks[0].terminator.control,MachineControl::Return{..}));
            // Empty closed region before the whole body; instruction before
            // Start; Return after End. Every original ID remains selected.
            for order in [[0,1,5,2,3,4],[2,0,1,3,4,5],[0,1,2,3,5,4]] {
                let mut inventory=baseline.clone();
                inventory.items=order.iter().map(|id|baseline.items.iter().find(|item|item.id==*id).unwrap().clone()).collect();
                respan_cfi_fixture(&mut inventory);
                assert_eq!(inventory.items.iter().map(|item|item.id).collect::<Vec<_>>(),order.to_vec());
                assert_eq!(inventory.items.iter().map(|item|item.id).collect::<BTreeSet<_>>(),baseline.items.iter().map(|item|item.id).collect::<BTreeSet<_>>());
                assert_eq!(body.source,inventory.source);assert_eq!(body.profile,inventory.profile);assert_eq!(body.interface,inventory.interface);
                assert_eq!(body.selected_inventory,inventory.identity);
                let error=verify(&body,&inventory,t).unwrap_err();
                assert_eq!(error.message,"machine instruction is outside the active required CFI region");
            }
        }
    }
    #[test]
    fn cfi_restore_missing_saved_rule_reaches_the_active_cfa_guard() {
        for &t in Target::ALL {
            let (baseline,inventory)=cfi_saved_fixture(t);
            let report=verify(&baseline,&inventory,t).unwrap();relative_cfi_only(&report);
            assert_eq!(report.checked_inventory_items,8);assert_eq!(report.checked_instruction_sites,3);
            let arg=register(registers(t).0,64);let scratch=register(registers(t).1,64);assert_ne!(arg,scratch);
            assert_eq!(baseline.directives[0].directive,MachineDirective::CfiStart);
            assert!(matches!(baseline.directives[1].directive,MachineDirective::CfiDefCfa{..}));
            assert_eq!(baseline.directives[2].directive,MachineDirective::CfiSaved{register:arg,offset:-8});
            assert_eq!(baseline.directives[3].directive,MachineDirective::CfiRestore{register:arg});
            let mut bad=baseline.clone();
            // ONLY the saved register changes. Start/CFA/Restore, source floor,
            // all source spans, scalar/state chain and entry/exit remain valid.
            bad.directives[2].directive=MachineDirective::CfiSaved{register:scratch,offset:-8};
            assert_eq!(&bad.directives[..2],&baseline.directives[..2]);assert_eq!(&bad.directives[3..],&baseline.directives[3..]);
            assert_eq!(bad.blocks,baseline.blocks);assert_eq!(bad.interface,baseline.interface);assert_eq!(bad.source,baseline.source);
            assert_eq!(bad.directives[2].directive,MachineDirective::CfiSaved{register:scratch,offset:-8});
            let error=verify(&bad,&inventory,t).unwrap_err();
            assert_eq!(error.message,"CFI restore has no prior saved-register rule");
        }
    }
    #[test]
    fn required_cfi_points_keep_exact_missing_duplicate_and_span_guards() {
        for &t in Target::ALL {
            let (baseline,floor)=cfi_saved_fixture(t);relative_cfi_only(&verify(&baseline,&floor,t).unwrap());
            let mut bad=baseline.clone();let removed=bad.directives.remove(2);assert_eq!(removed.source_item,6);
            assert!(floor.items.iter().any(|item|item.id==6 && item.kind==SourceItemKind::CfiDirective));
            rejected(&bad,&floor,t,"missing independently selected original instruction/directive/label coverage");
            let mut missing=floor.clone();missing.items.retain(|item|item.id!=6);
            assert!(!missing.items.iter().any(|item|item.id==6));assert_eq!(baseline.directives[2].source_item,6);
            rejected(&baseline,&missing,t,"body site has no independently selected inventory item");
            bad=baseline.clone();bad.directives.push(baseline.directives[2].clone());
            assert_eq!(bad.directives.iter().filter(|d|d.source_item==6).count(),2);
            rejected(&bad,&floor,t,"duplicate directive/label coverage");
            let mut duplicate=floor.clone();let mut extra=duplicate.items.iter().find(|item|item.id==6).unwrap().clone();
            extra.decoded_span=SourceSpan{start:64,end:72};extra.origins[0].span=extra.decoded_span;duplicate.items.push(extra);
            assert_eq!(duplicate.items.iter().filter(|item|item.id==6 && item.kind==SourceItemKind::CfiDirective).count(),2);
            rejected(&baseline,&duplicate,t,"duplicate independently selected source item");
            let mut outside=floor.clone();let item=outside.items.iter_mut().find(|item|item.id==6).unwrap();
            assert_eq!(item.kind,SourceItemKind::CfiDirective);item.decoded_span.end=baseline.source.decoded_assembly.bytes+1;
            assert!(item.decoded_span.end>baseline.source.decoded_assembly.bytes);
            rejected(&baseline,&outside,t,"out of selected source extent");
        }
    }
    #[test]
    fn no_cfi_declared_does_not_require_a_synthetic_region() {
        for &t in Target::ALL {
            let (mut body,mut inventory)=fixture(t);
            body.profile.cfi=CfiPolicy::NoCfiDeclared;inventory.profile=body.profile.clone();
            body.directives.clear();inventory.items.retain(|item|item.kind==SourceItemKind::Instruction);
            respan_cfi_fixture(&mut inventory);
            assert!(body.directives.is_empty());assert_eq!(inventory.items.iter().map(|item|item.id).collect::<Vec<_>>(),vec![2,3,4]);
            let report=verify(&body,&inventory,t).unwrap();relative_cfi_only(&report);
            assert_eq!(report.checked_inventory_items,3);assert_eq!(report.checked_instruction_sites,3);
        }
    }
    include!("native_machine_cfg_initialization_tests.rs");
    include!("native_machine_return_target_tests.rs");
}
