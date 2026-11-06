// Compile-time scalarization of verified fixed integer vectors. Source lanes
// remain packed at lane_index * lane_bits, including i1 masks. This emits only
// the owned target instructions; no vector runtime, ABI surrogate or IR executor.
use super::super::native_verify::FixedVectorLayout;

pub(super) fn is_reduction_declaration(function: &Function) -> bool {
    function.entry.is_none()
        && super::super::native_verify::vector_reduce_add_intrinsic(&function.name).is_some()
}

impl Emitter<'_> {
    fn vector_layout(&self, ty: TypeId) -> FixedVectorLayout {
        fixed_vector_layout(self.module, ty).expect("audited fixed vector layout")
    }

    fn is_vector(&self, ty: TypeId) -> bool {
        matches!(self.module.types[ty], Type::Vector { .. })
    }

    // Only the lane payload is represented here; source allocation tail padding
    // never becomes a defined lane or an additional spill component.
    pub(super) fn vector_constant_chunk(
        &self,
        out: &mut String,
        reg: usize,
        ty: TypeId,
        elements: &[Operand],
        bit_offset: u64,
    ) {
        let layout = self.vector_layout(ty);
        let lane_bits = u64::from(layout.lane_bits);
        let first = bit_offset / lane_bits;
        let end = layout.len.min(first + 64 / lane_bits);
        let mask = if layout.lane_bits == 64 {
            u64::MAX
        } else {
            (1u64 << layout.lane_bits) - 1
        };
        let mut word = 0u64;
        for lane in first..end {
            let value = match &elements[usize::try_from(lane).expect("audited vector lane")] {
                Operand::Int { bits, .. } => bits.parse::<u64>().expect("verified integer lane"),
                Operand::AggregateZero { .. } | Operand::Undef { .. } | Operand::Poison { .. } => 0,
                _ => unreachable!("verified fixed integer vector constant lane"),
            };
            word |= (value & mask) << ((lane - first) * lane_bits);
        }
        self.immediate(out, reg, word);
    }

    fn vector_lane(
        &self,
        out: &mut String,
        reg: usize,
        vector: &Operand,
        lane: u64,
    ) {
        let layout = self.vector_layout(self.ty(vector));
        let bit = lane.checked_mul(u64::from(layout.lane_bits))
            .expect("audited vector lane bit offset");
        self.operand_packed_chunk(out, reg, vector, 0, bit / 64 * 64);
        let shift = bit % 64;
        if shift != 0 {
            let r = self.reg(reg);
            match self.target {
                Target::X86_64UnknownNone => writeln!(out, "  shr {r}, {shift}").unwrap(),
                Target::Aarch64UnknownNone => writeln!(out, "  lsr {r}, {r}, #{shift}").unwrap(),
                Target::Riscv64UnknownNone => writeln!(out, "  srli {r}, {r}, {shift}").unwrap(),
            }
        }
        self.mask(out, reg, layout.lane_bits);
    }

    fn vector_zero(&self, out: &mut String, result: Value) {
        for (leaf, bit) in self.value_chunks(result.ty) {
            self.immediate(out, 0, 0);
            self.spill_packed_chunk(out, result, leaf, bit);
        }
    }

    // Every caller initializes the complete result first and visits each lane
    // once. OR accumulation therefore preserves all earlier defined neighbors,
    // without reading any uninitialized physical spill bits.
    fn vector_spill_lane(&self, out: &mut String, result: Value, lane: u64) {
        let layout = self.vector_layout(result.ty);
        let bit = lane.checked_mul(u64::from(layout.lane_bits))
            .expect("audited result lane bit offset");
        let offset = self.slots[&result.id]
            + i64::try_from(bit / 64 * 8).expect("audited vector physical offset");
        self.mask(out, 0, layout.lane_bits);
        let shift = bit % 64;
        if shift != 0 {
            let r = self.reg(0);
            match self.target {
                Target::X86_64UnknownNone => writeln!(out, "  shl {r}, {shift}").unwrap(),
                Target::Aarch64UnknownNone => writeln!(out, "  lsl {r}, {r}, #{shift}").unwrap(),
                Target::Riscv64UnknownNone => writeln!(out, "  slli {r}, {r}, {shift}").unwrap(),
            }
        }
        self.stack_load(out, 1, offset);
        self.simple_binary(out, if self.target == Target::Aarch64UnknownNone { "orr" } else { "or" });
        self.stack_store(out, 0, offset);
    }

    fn vector_compare_registers(&self, out: &mut String, predicate: IntPredicate, bits: u16) {
        if matches!(predicate, IntPredicate::Sgt | IntPredicate::Sge | IntPredicate::Slt | IntPredicate::Sle) {
            self.signed(out, 0, bits);
            self.signed(out, 1, bits);
        }
        match self.target {
            Target::X86_64UnknownNone => writeln!(
                out, "  cmp rax, rcx\n  set{} al\n  movzx eax, al",
                match predicate {
                    IntPredicate::Eq => "e", IntPredicate::Ne => "ne",
                    IntPredicate::Ugt => "a", IntPredicate::Uge => "ae",
                    IntPredicate::Ult => "b", IntPredicate::Ule => "be",
                    IntPredicate::Sgt => "g", IntPredicate::Sge => "ge",
                    IntPredicate::Slt => "l", IntPredicate::Sle => "le",
                }
            ).unwrap(),
            Target::Aarch64UnknownNone => writeln!(
                out, "  cmp x9, x10\n  cset x9, {}",
                match predicate {
                    IntPredicate::Eq => "eq", IntPredicate::Ne => "ne",
                    IntPredicate::Ugt => "hi", IntPredicate::Uge => "hs",
                    IntPredicate::Ult => "lo", IntPredicate::Ule => "ls",
                    IntPredicate::Sgt => "gt", IntPredicate::Sge => "ge",
                    IntPredicate::Slt => "lt", IntPredicate::Sle => "le",
                }
            ).unwrap(),
            Target::Riscv64UnknownNone => match predicate {
                IntPredicate::Eq | IntPredicate::Ne => writeln!(
                    out, "  xor t0, t0, t1\n  {} t0, t0",
                    if predicate == IntPredicate::Eq { "seqz" } else { "snez" }
                ).unwrap(),
                _ => {
                    let signed = matches!(predicate, IntPredicate::Sgt | IntPredicate::Sge | IntPredicate::Slt | IntPredicate::Sle);
                    let reversed = matches!(predicate, IntPredicate::Ugt | IntPredicate::Ule | IntPredicate::Sgt | IntPredicate::Sle);
                    writeln!(out, "  {} t0, {}, {}",
                        if signed { "slt" } else { "sltu" },
                        if reversed { "t1" } else { "t0" },
                        if reversed { "t0" } else { "t1" }).unwrap();
                    if matches!(predicate, IntPredicate::Uge | IntPredicate::Ule | IntPredicate::Sge | IntPredicate::Sle) {
                        out.push_str("  xori t0, t0, 1\n");
                    }
                }
            },
        }
    }

    fn vector_binary_registers(
        &mut self,
        out: &mut String,
        kind: BinaryOp,
        bits: u16,
    ) -> Result<(), Diagnostic> {
        match kind {
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::And | BinaryOp::Or | BinaryOp::Xor => {
                let op = match kind {
                    BinaryOp::Add => "add", BinaryOp::Sub => "sub",
                    BinaryOp::Mul if self.target == Target::X86_64UnknownNone => "imul",
                    BinaryOp::Mul => "mul", BinaryOp::And => "and",
                    BinaryOp::Or if self.target == Target::Aarch64UnknownNone => "orr",
                    BinaryOp::Or => "or",
                    BinaryOp::Xor if self.target == Target::Aarch64UnknownNone => "eor",
                    BinaryOp::Xor => "xor", _ => unreachable!(),
                };
                self.simple_binary(out, op);
            }
            BinaryOp::Shl | BinaryOp::LShr | BinaryOp::AShr => {
                // Invalid source shift counts are poison, refined to zero.
                // Do not expose hardware modulo-count behavior as a source fact.
                let poison = self.label();
                let done = self.label();
                if kind == BinaryOp::AShr { self.signed(out, 0, bits); }
                match self.target {
                    Target::X86_64UnknownNone => {
                        writeln!(out, "  cmp rcx, {bits}\n  jae {poison}").unwrap();
                        let op = if kind == BinaryOp::Shl { "shl" } else if kind == BinaryOp::LShr { "shr" } else { "sar" };
                        writeln!(out, "  {op} rax, cl").unwrap();
                    }
                    Target::Aarch64UnknownNone => {
                        writeln!(out, "  cmp x10, #{bits}\n  b.hs {poison}").unwrap();
                        let op = if kind == BinaryOp::Shl { "lsl" } else if kind == BinaryOp::LShr { "lsr" } else { "asr" };
                        writeln!(out, "  {op} x9, x9, x10").unwrap();
                    }
                    Target::Riscv64UnknownNone => {
                        self.immediate(out, 2, u64::from(bits));
                        writeln!(out, "  bgeu t1, t2, {poison}").unwrap();
                        let op = if kind == BinaryOp::Shl { "sll" } else if kind == BinaryOp::LShr { "srl" } else { "sra" };
                        writeln!(out, "  {op} t0, t0, t1").unwrap();
                    }
                }
                self.jump(out, &done);
                writeln!(out, "{poison}:").unwrap();
                self.immediate(out, 0, 0);
                writeln!(out, "{done}:").unwrap();
            }
            BinaryOp::UDiv | BinaryOp::SDiv | BinaryOp::URem | BinaryOp::SRem => {
                return Err(error_diagnostic("fixed vector division/remainder requires explicit poison-safe lane lowering"));
            }
        }
        self.mask(out, 0, bits);
        Ok(())
    }

    fn vector_index_equals(&self, out: &mut String, index: &Operand, lane: u64) {
        self.operand(out, 0, index);
        self.mask(out, 0, self.bits(index));
        self.immediate(out, 1, lane);
        self.vector_compare_registers(out, IntPredicate::Eq, 64);
    }

    pub(super) fn vector_instruction(
        &mut self,
        out: &mut String,
        instruction: &Instruction,
    ) -> Result<bool, Diagnostic> {
        match &instruction.operation {
            Operation::Binary { kind, lhs, rhs, .. } if self.is_vector(self.ty(lhs)) => {
                let result = instruction.result.unwrap();
                let layout = self.vector_layout(result.ty);
                self.vector_zero(out, result);
                for lane in 0..layout.len {
                    self.vector_lane(out, 0, lhs, lane);
                    self.vector_lane(out, 1, rhs, lane);
                    self.vector_binary_registers(out, *kind, layout.lane_bits)?;
                    self.vector_spill_lane(out, result, lane);
                }
            }
            Operation::ICmp { predicate, lhs, rhs } if self.is_vector(self.ty(lhs)) => {
                let result = instruction.result.unwrap();
                let input = self.vector_layout(self.ty(lhs));
                self.vector_zero(out, result);
                for lane in 0..input.len {
                    self.vector_lane(out, 0, lhs, lane);
                    self.vector_lane(out, 1, rhs, lane);
                    self.vector_compare_registers(out, *predicate, input.lane_bits);
                    self.vector_spill_lane(out, result, lane);
                }
            }
            Operation::Cast { kind, value } if self.is_vector(self.ty(value)) => {
                let result = instruction.result.unwrap();
                let source = self.vector_layout(self.ty(value));
                if !self.is_vector(result.ty) || !matches!(kind, CastOp::ZExt | CastOp::SExt | CastOp::Trunc) {
                    return Err(error_diagnostic("fixed vectors support only same-lane integer zext/sext/trunc casts"));
                }
                self.vector_zero(out, result);
                for lane in 0..source.len {
                    self.vector_lane(out, 0, value, lane);
                    if *kind == CastOp::SExt { self.signed(out, 0, source.lane_bits); }
                    self.vector_spill_lane(out, result, lane);
                }
            }
            Operation::Select { condition, on_true, on_false } if self.is_vector(self.ty(condition)) => {
                let result = instruction.result.unwrap();
                let layout = self.vector_layout(result.ty);
                self.vector_zero(out, result);
                for lane in 0..layout.len {
                    let no = self.label();
                    let done = self.label();
                    self.vector_lane(out, 0, condition, lane);
                    self.zero_jump(out, 0, &no, true);
                    self.vector_lane(out, 0, on_true, lane);
                    self.jump(out, &done);
                    writeln!(out, "{no}:").unwrap();
                    self.vector_lane(out, 0, on_false, lane);
                    writeln!(out, "{done}:").unwrap();
                    self.vector_spill_lane(out, result, lane);
                }
            }
            Operation::ExtractElement { vector, index } => {
                let result = instruction.result.unwrap();
                let layout = self.vector_layout(self.ty(vector));
                self.immediate(out, 0, 0);
                self.spill_leaf(out, result, 0);
                let done = self.label();
                for lane in 0..layout.len {
                    let next = self.label();
                    self.vector_index_equals(out, index, lane);
                    self.zero_jump(out, 0, &next, true);
                    self.vector_lane(out, 0, vector, lane);
                    self.spill_leaf(out, result, 0);
                    self.jump(out, &done);
                    writeln!(out, "{next}:").unwrap();
                }
                writeln!(out, "{done}:").unwrap();
            }
            Operation::InsertElement { vector, value, index } => {
                let result = instruction.result.unwrap();
                let layout = self.vector_layout(result.ty);
                self.vector_zero(out, result);
                let done = self.label();
                self.operand(out, 0, index);
                self.mask(out, 0, self.bits(index));
                self.immediate(out, 1, layout.len);
                self.vector_compare_registers(out, IntPredicate::Ult, 64);
                self.zero_jump(out, 0, &done, true);
                for lane in 0..layout.len {
                    let original = self.label();
                    let selected = self.label();
                    self.vector_index_equals(out, index, lane);
                    self.zero_jump(out, 0, &original, true);
                    self.operand(out, 0, value);
                    self.jump(out, &selected);
                    writeln!(out, "{original}:").unwrap();
                    self.vector_lane(out, 0, vector, lane);
                    writeln!(out, "{selected}:").unwrap();
                    self.vector_spill_lane(out, result, lane);
                }
                writeln!(out, "{done}:").unwrap();
            }
            Operation::VectorReduceAdd { value } => {
                let result = instruction.result.unwrap();
                let layout = self.vector_layout(self.ty(value));
                self.immediate(out, 0, 0);
                self.spill_leaf(out, result, 0);
                for lane in 0..layout.len {
                    self.vector_lane(out, 0, value, lane);
                    self.stack_load(out, 1, self.slots[&result.id]);
                    self.simple_binary(out, "add");
                    self.spill_leaf(out, result, 0);
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}
