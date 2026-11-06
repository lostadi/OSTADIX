//! Original assembly semantics expressed as explicit register/state SSA.
//!
//! This builder emits typed machine IR, never executable assembly or an opaque
//! object. Entry realization, complete source selection, CFI, relocations,
//! provider admission and native code generation are separate required steps.
//! A graph produced here is not an authenticated or executable original unit.
use std::collections::BTreeMap;
use super::native_machine_asm_reader as syntax;
use super::native_machine_ir::*;
use super::native_machine_verify::{flag_view, return_mechanism, view, Role};
pub use super::native_machine_ir::ExtensionKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftError { pub source_item: SourceItemId, pub reason: String }
impl std::fmt::Display for LiftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "assembly item {}: {}", self.source_item, self.reason)
    }
}
impl std::error::Error for LiftError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftFlow {
    Continue,
    Jump(syntax::Expression),
    Branch { condition: Scalar, target: syntax::Expression },
    /// Actual computed continuation and architectural branch class.
    /// No C prototype, stack protocol or native realization is inferred.
    ReturnTo { target: Scalar, mechanism: ReturnMechanism },
}

pub struct LiftIds { next_value: usize, next_state: usize }
impl LiftIds {
    pub fn new(next_value: usize, next_state: usize) -> Self {
        Self { next_value, next_state }
    }
}

pub struct BlockLifter<'a> {
    profile: &'a MachineProfile,
    source_item: SourceItemId,
    state: StateId,
    ids: &'a mut LiftIds,
    instructions: &'a mut Vec<MachineInstruction>,
    values: BTreeMap<usize, u16>,
}
impl<'a> BlockLifter<'a> {
    pub fn new(profile: &'a MachineProfile, source_item: SourceItemId,
        state_in: StateId, ids: &'a mut LiftIds,
        instructions: &'a mut Vec<MachineInstruction>) -> Self {
        let values = instructions.iter().filter_map(|i| i.result.map(|v| (v.id,v.bits))).collect();
        Self { profile, source_item, state: state_in, ids, instructions, values }
    }
    pub fn profile(&self) -> &MachineProfile { self.profile }
    pub fn source_item(&self) -> SourceItemId { self.source_item }
    pub fn state(&self) -> StateId { self.state }
    /// Preserve the actual lifted target in the final typed control. This is only
    /// builder-local availability/profile checking. Whole-body SSA, state, exit,
    /// version and inventory verification remain mandatory; no native admission.
    pub fn return_control(&self, flow: &LiftFlow, exit: u32) -> Result<MachineControl, LiftError> {
        let LiftFlow::ReturnTo { target, mechanism } = flow else {
            return Err(self.fail("flow has no explicit computed return target"));
        };
        self.known(*target)?;
        if target.bits != self.profile.address_bits {
            return Err(self.fail("return target must have exact profile address width"));
        }
        return_mechanism(self.profile, *mechanism).map_err(|e| self.fail(e.message))?;
        Ok(MachineControl::ReturnTo { exit, target: target.id, mechanism: *mechanism })
    }
    pub fn fail(&self, reason: impl Into<String>) -> LiftError {
        LiftError { source_item: self.source_item, reason: reason.into() }
    }
    fn known(&self, v: Scalar) -> Result<(), LiftError> {
        if !(1..=128).contains(&v.bits) || self.values.get(&v.id) != Some(&v.bits) {
            return Err(self.fail("scalar is absent or its declared width differs from emitted SSA"));
        }
        Ok(())
    }
    fn emit(&mut self, operation: MachineOperation, bits: Option<u16>) -> Result<Option<Scalar>, LiftError> {
        if bits.is_some_and(|n| !(1..=128).contains(&n)) {
            return Err(self.fail("result scalar width must be between 1 and 128"));
        }
        let state_out = self.ids.next_state;
        let next_state = state_out.checked_add(1).ok_or_else(|| self.fail("state ID overflow"))?;
        if state_out == self.state || self.instructions.iter().any(|i| i.state_out == state_out) {
            return Err(self.fail("state allocator collides with existing state SSA"));
        }
        let result = if let Some(bits) = bits {
            let id = self.ids.next_value;
            if self.values.contains_key(&id) { return Err(self.fail("scalar allocator collides with existing SSA")); }
            let next = id.checked_add(1).ok_or_else(|| self.fail("scalar ID overflow"))?;
            self.ids.next_value = next;
            Some(Scalar { id, bits })
        } else { None };
        self.instructions.push(MachineInstruction { source_item:self.source_item,
            state_in:self.state, state_out, result, operation });
        self.state = state_out;
        self.ids.next_state = next_state;
        if let Some(v) = result { self.values.insert(v.id,v.bits); }
        Ok(result)
    }
    fn scalar(&mut self, operation: MachineOperation, bits: u16) -> Result<Scalar, LiftError> {
        self.emit(operation,Some(bits))?.ok_or_else(|| self.fail("internal scalar emission omitted result"))
    }
    pub fn constant(&mut self, bits: u16, value: u128) -> Result<Scalar, LiftError> {
        if !(1..=128).contains(&bits) { return Err(self.fail("constant width must be between 1 and 128")); }
        let n = usize::from(bits.div_ceil(8));
        let mut little_endian = value.to_le_bytes()[..n].to_vec();
        if bits % 8 != 0 { little_endian[n-1] &= (1u8 << (bits%8))-1; }
        self.scalar(MachineOperation::Constant {little_endian},bits)
    }
    pub fn read_register(&mut self, register: RegisterView) -> Result<Scalar, LiftError> {
        let flag = matches!(register.register,PhysicalRegister::X86Flags|PhysicalRegister::Aarch64Nzcv);
        if flag {
            flag_view(self.profile,register).map_err(|e| self.fail(e.message))?;
            self.scalar(MachineOperation::ReadFlags {view:register},register.bits)
        } else {
            view(self.profile,register).map_err(|e| self.fail(e.message))?;
            self.scalar(MachineOperation::ReadRegister {view:register},register.bits)
        }
    }
    pub fn write_register(&mut self, register: RegisterView, value: Scalar, mode: WriteMode) -> Result<(), LiftError> {
        self.known(value)?;
        if value.bits != register.bits { return Err(self.fail("register/value width mismatch")); }
        if matches!(register.register,PhysicalRegister::X86Flags|PhysicalRegister::Aarch64Nzcv) {
            flag_view(self.profile,register).map_err(|e| self.fail(e.message))?;
            if !matches!(mode,WriteMode::WholeStorage|WriteMode::PreserveOtherBits) {
                return Err(self.fail("flags cannot zero-extend architectural storage"));
            }
            return self.emit(MachineOperation::WriteFlags {view:register,value:value.id},None).map(|_|());
        }
        let (layout,_) = view(self.profile,register).map_err(|e| self.fail(e.message))?;
        if matches!(layout.role,Role::Stack|Role::Pc|Role::Zero) {
            return Err(self.fail("SP/PC/zero writes require separate state realization"));
        }
        let whole=register.low_bit==0 && register.bits==layout.width;
        let valid=if layout.zero_extend_32 && register.bits==32 && register.low_bit==0 {
            mode==WriteMode::ZeroExtendStorage
        } else if whole { mode==WriteMode::WholeStorage }
        else { mode==WriteMode::PreserveOtherBits || (layout.role==Role::Floating && mode==WriteMode::ZeroExtendStorage) };
        if !valid { return Err(self.fail("register alias write mode differs from original architecture")); }
        self.emit(MachineOperation::WriteRegister {view:register,value:value.id,mode},None).map(|_|())
    }
    pub fn invalidate_register(&mut self, register: RegisterView) -> Result<(), LiftError> {
        let layout = if matches!(register.register,PhysicalRegister::X86Flags|PhysicalRegister::Aarch64Nzcv) {
            flag_view(self.profile,register)
        } else { view(self.profile,register) }.map_err(|e| self.fail(e.message))?.0;
        if matches!(layout.role,Role::Stack|Role::Pc|Role::Zero) {
            return Err(self.fail("SP/PC/zero invalidation is forbidden"));
        }
        self.emit(MachineOperation::InvalidateRegister {view:register},None).map(|_|())
    }
    pub fn binary(&mut self, kind: BinaryKind, lhs: Scalar, rhs: Scalar) -> Result<Scalar, LiftError> {
        self.known(lhs)?; self.known(rhs)?;
        if lhs.bits!=rhs.bits { return Err(self.fail("binary operand widths differ")); }
        self.scalar(MachineOperation::Binary {kind,lhs:lhs.id,rhs:rhs.id},lhs.bits)
    }
    pub fn compare(&mut self, kind: CompareKind, lhs: Scalar, rhs: Scalar) -> Result<Scalar, LiftError> {
        self.known(lhs)?; self.known(rhs)?;
        if lhs.bits!=rhs.bits { return Err(self.fail("comparison operand widths differ")); }
        self.scalar(MachineOperation::Compare {kind,lhs:lhs.id,rhs:rhs.id},1)
    }
    pub fn cast(&mut self, value: Scalar, to_bits: u16, kind: ExtensionKind) -> Result<Scalar, LiftError> {
        self.known(value)?;
        let valid=(1..=128).contains(&to_bits) && match kind {
            ExtensionKind::Truncate => to_bits<value.bits,
            ExtensionKind::ZeroExtend|ExtensionKind::SignExtend => to_bits>value.bits,
        };
        if !valid { return Err(self.fail("cast direction/width differs from selected extension kind")); }
        self.scalar(MachineOperation::Cast {kind,value:value.id},to_bits)
    }
    pub fn load(&mut self, address: Scalar, bits: u16, alignment: u64) -> Result<Scalar, LiftError> {
        self.known(address)?;
        if address.bits!=64 || ![8,16,32,64,128].contains(&bits) || !alignment.is_power_of_two() {
            return Err(self.fail("invalid exact-width load address/extent/alignment"));
        }
        self.scalar(MachineOperation::Load {address:address.id,alignment},bits)
    }
    pub fn store(&mut self, address: Scalar, value: Scalar, alignment: u64) -> Result<(), LiftError> {
        self.known(address)?; self.known(value)?;
        if address.bits!=64 || ![8,16,32,64,128].contains(&value.bits) || !alignment.is_power_of_two() {
            return Err(self.fail("invalid exact-width store address/extent/alignment"));
        }
        self.emit(MachineOperation::Store {address:address.id,value:value.id,alignment},None).map(|_|())
    }
}

/// Constant arithmetic only. Symbols, local labels, location counters and
/// relocation expressions require a selected relocation/address binding.
pub fn integer_expression(expression: &syntax::Expression) -> Result<i128,LiftError> {
    let error=|reason:&str| LiftError {source_item:0,reason:reason.into()};
    let syntax::ExprAtom::Integer(mut value)=expression.first else {
        return Err(error("expression requires an authenticated symbol/relocation binding"));
    };
    for (operation,atom) in &expression.rest {
        let syntax::ExprAtom::Integer(rhs)=atom else {
            return Err(error("expression requires an authenticated symbol/relocation binding"));
        };
        value=match operation {
            syntax::AddSub::Add=>value.checked_add(*rhs),
            syntax::AddSub::Subtract=>value.checked_sub(*rhs),
        }.ok_or_else(||error("integer expression overflows signed 128-bit arithmetic"))?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> MachineProfile {
        MachineProfile {architecture:Architecture::X86_64,abi:MachineAbi::SysvAmd64,
            address_bits:64,byte_order:ByteOrder::Little,entry_stack_alignment:16,
            entry_stack_remainder:8,features:vec![StateFeature::UserRegisterBits],
            cfi:CfiPolicy::NoCfiDeclared}
    }
    #[test]
    fn cast_uses_exact_result_width_and_consumes_original_scalar() {
        let p=profile();let mut ids=LiftIds::new(1,1);let mut ops=vec![];
        let mut b=BlockLifter::new(&p,17,0,&mut ids,&mut ops);
        let a=b.constant(32,u32::MAX as u128).unwrap();
        let out=b.cast(a,64,ExtensionKind::SignExtend).unwrap();
        assert_eq!(out.bits,64);assert_eq!(b.state(),2);drop(b);
        assert!(matches!(ops[1].operation,MachineOperation::Cast {kind:ExtensionKind::SignExtend,value} if value==a.id));
        assert_eq!(ops[1].result,Some(out));assert!(ops.iter().all(|i|i.source_item==17));
    }
    #[test]
    fn cast_direction_and_forged_scalar_width_are_rejected_before_emission() {
        let p=profile();let mut ids=LiftIds::new(1,1);let mut ops=vec![];
        let mut b=BlockLifter::new(&p,1,0,&mut ids,&mut ops);
        let a=b.constant(32,7).unwrap();
        assert!(b.cast(a,64,ExtensionKind::Truncate).unwrap_err().reason.contains("direction/width"));
        let forged=Scalar {id:a.id,bits:64};
        assert!(b.cast(forged,8,ExtensionKind::Truncate).unwrap_err().reason.contains("declared width differs"));
        assert_eq!(b.state(),1);drop(b);assert_eq!(ops.len(),1);
    }
    #[test]
    fn arithmetic_flags_have_explicit_write_and_undefinedness_operations() {
        let p=profile();let mut ids=LiftIds::new(1,1);let mut ops=vec![];
        let mut b=BlockLifter::new(&p,1,0,&mut ids,&mut ops);
        let cf=RegisterView {register:PhysicalRegister::X86Flags,low_bit:0,bits:1};
        let af=RegisterView {low_bit:4,..cf};let one=b.constant(1,1).unwrap();
        b.write_register(cf,one,WriteMode::PreserveOtherBits).unwrap();
        b.invalidate_register(af).unwrap();drop(b);
        assert!(matches!(ops[1].operation,MachineOperation::WriteFlags {view,value} if view==cf && value==one.id));
        assert!(matches!(ops[2].operation,MachineOperation::InvalidateRegister {view} if view==af));
        assert!(!ops.iter().any(|i|matches!(i.operation,MachineOperation::WriteRegister {..})));
    }
    #[test]
    fn privileged_flags_and_stack_writes_do_not_acquire_a_generic_write_path() {
        let p=profile();let mut ids=LiftIds::new(1,1);let mut ops=vec![];
        let mut b=BlockLifter::new(&p,1,0,&mut ids,&mut ops);
        let one=b.constant(1,1).unwrap();
        let interrupt=RegisterView {register:PhysicalRegister::X86Flags,low_bit:9,bits:1};
        assert!(b.write_register(interrupt,one,WriteMode::PreserveOtherBits).unwrap_err().reason.contains("noncanonical arithmetic-flag"));
        let sp=RegisterView {register:PhysicalRegister::X86Gpr {name:X86Gpr::Rsp},low_bit:0,bits:64};
        let v=b.constant(64,0x1000).unwrap();
        assert!(b.write_register(sp,v,WriteMode::WholeStorage).unwrap_err().reason.contains("SP/PC/zero"));
        drop(b);assert_eq!(ops.len(),2);
    }
    #[test]
    fn narrow_constants_clear_padding_without_changing_selected_width() {
        let p=profile();let mut ids=LiftIds::new(1,1);let mut ops=vec![];
        let mut b=BlockLifter::new(&p,1,0,&mut ids,&mut ops);
        let v=b.constant(9,u128::MAX).unwrap();assert_eq!(v.bits,9);drop(b);
        assert!(matches!(&ops[0].operation,MachineOperation::Constant {little_endian} if little_endian==&vec![255,1]));
    }
    #[test]
    fn overflow_and_colliding_ids_cannot_be_published_as_new_ssa() {
        let p=profile();let mut ids=LiftIds::new(usize::MAX,1);let mut ops=vec![];
        let mut b=BlockLifter::new(&p,1,0,&mut ids,&mut ops);
        assert!(b.constant(64,1).unwrap_err().reason.contains("scalar ID overflow"));drop(b);assert!(ops.is_empty());
        let mut ids=LiftIds::new(1,0);let mut b=BlockLifter::new(&p,1,0,&mut ids,&mut ops);
        assert!(b.constant(64,1).unwrap_err().reason.contains("state allocator collides"));drop(b);assert!(ops.is_empty());
    }
}
