// Two-word lowering for original i128 SSA values. Registers are temporary;
// source values and aggregate fields retain their original semantic identities.
// No foreign IR executor or target object generator participates in this path.
impl Emitter<'_> {
    fn wide_reg(&self, n: usize) -> &'static str {
        match self.target {
            Target::X86_64UnknownNone => ["rax", "rcx", "rdx", "r8", "r9", "r10", "rsi", "rdi"][n],
            Target::Aarch64UnknownNone => {
                ["x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16"][n]
            }
            Target::Riscv64UnknownNone => ["t0", "t1", "t2", "t3", "t4", "t5", "t6", "a0"][n],
        }
    }

    pub(super) fn is_i128(&self, value: &Operand) -> bool {
        matches!(self.module.types[self.ty(value)], Type::Int { bits: 128 })
    }

    pub(super) fn wide_inputs(&self, out: &mut String, lhs: &Operand, rhs: &Operand) {
        // Stack addressing uses r11/x17/ra; it cannot destroy these stashes.
        self.operand_chunk(out, 0, lhs, 0, 0);
        self.mov(out, self.wide_reg(4), self.reg(0));
        self.operand_chunk(out, 0, lhs, 0, 64);
        self.mov(out, self.wide_reg(5), self.reg(0));
        self.operand_chunk(out, 0, rhs, 0, 0);
        self.mov(out, self.reg(2), self.reg(0));
        self.operand_chunk(out, 0, rhs, 0, 64);
        self.mov(out, self.wide_reg(3), self.reg(0));
        self.mov(out, self.reg(0), self.wide_reg(4));
        self.mov(out, self.reg(1), self.wide_reg(5));
    }

    fn wide_spill(&self, out: &mut String, result: Value) {
        // Finish carry-dependent arithmetic before stack-address generation,
        // which is permitted to change integer condition flags.
        self.spill_chunk(out, result, 0, 0);
        self.mov(out, self.reg(0), self.reg(1));
        self.spill_chunk(out, result, 0, 64);
    }

    pub(super) fn wide_integer_instruction(
        &mut self,
        out: &mut String,
        instruction: &Instruction,
    ) -> Result<bool, Diagnostic> {
        match &instruction.operation {
            Operation::Binary { kind, lhs, rhs, .. } if self.is_i128(lhs) => {
                self.wide_inputs(out, lhs, rhs);
                self.wide_binary(out, *kind)?;
                self.wide_spill(out, instruction.result.unwrap());
                return Ok(true);
            }
            Operation::ICmp {
                predicate,
                lhs,
                rhs,
            } if self.is_i128(lhs) => {
                self.wide_inputs(out, lhs, rhs);
                self.wide_compare(out, *predicate);
                self.spill_chunk(out, instruction.result.unwrap(), 0, 0);
                return Ok(true);
            }
            Operation::IntegerMinMax { kind, lhs, rhs } if self.is_i128(lhs) => {
                self.wide_inputs(out, lhs, rhs);
                self.wide_compare(
                    out,
                    match kind {
                        IntegerMinMaxKind::Smin => IntPredicate::Sle,
                        IntegerMinMaxKind::Smax => IntPredicate::Sge,
                        IntegerMinMaxKind::Umin => IntPredicate::Ule,
                        IntegerMinMaxKind::Umax => IntPredicate::Uge,
                    },
                );
                let other = self.label();
                let done = self.label();
                self.zero_jump(out, 0, &other, true);
                let result = instruction.result.unwrap();
                for bit in [0, 64] {
                    self.operand_chunk(out, 0, lhs, 0, bit);
                    self.spill_chunk(out, result, 0, bit);
                }
                self.jump(out, &done);
                writeln!(out, "{other}:").unwrap();
                for bit in [0, 64] {
                    self.operand_chunk(out, 0, rhs, 0, bit);
                    self.spill_chunk(out, result, 0, bit);
                }
                writeln!(out, "{done}:").unwrap();
                return Ok(true);
            }
            Operation::Cast { kind, value } => {
                let result = instruction.result.unwrap();
                let source_wide = self.is_i128(value);
                let result_wide = matches!(self.module.types[result.ty], Type::Int { bits: 128 });
                if !source_wide && !result_wide {
                    return Ok(false);
                }
                match kind {
                    CastOp::Trunc | CastOp::IntToPtr if source_wide && !result_wide => {
                        self.operand_chunk(out, 0, value, 0, 0);
                        self.spill_chunk(out, result, 0, 0);
                    }
                    CastOp::ZExt | CastOp::SExt | CastOp::PtrToInt if !source_wide && result_wide => {
                        let bits = self.bits(value);
                        self.operand(out, 0, value);
                        self.mask(out, 0, bits);
                        if *kind == CastOp::SExt {
                            self.signed(out, 0, bits);
                        }
                        self.spill_chunk(out, result, 0, 0);
                        if *kind == CastOp::SExt {
                            out.push_str(match self.target {
                                Target::X86_64UnknownNone => "  sar rax, 63\n",
                                Target::Aarch64UnknownNone => "  asr x9, x9, #63\n",
                                Target::Riscv64UnknownNone => "  srai t0, t0, 63\n",
                            });
                        } else {
                            self.immediate(out, 0, 0);
                        }
                        self.spill_chunk(out, result, 0, 64);
                    }
                    CastOp::Bitcast if source_wide && result_wide => {
                        for bit in [0, 64] {
                            self.operand_chunk(out, 0, value, 0, bit);
                            self.spill_chunk(out, result, 0, bit);
                        }
                    }
                    _ => return Err(error_diagnostic("unsupported i128 cast; floating numeric bridges require explicit provider interfaces")),
                }
                return Ok(true);
            }
            // These operations already copy all physical words of every field.
            Operation::Phi { .. }
            | Operation::Freeze { .. }
            | Operation::Select { .. }
            | Operation::Load { .. }
            | Operation::Store { .. }
            | Operation::Call { .. }
            | Operation::ExtractValue { .. }
            | Operation::InsertValue { .. } => return Ok(false),
            _ => {}
        }
        // Never accidentally route a newly admitted width through a 64-bit
        // intrinsic or an address/length implementation that truncates it.
        for operand in instruction_operands(&instruction.operation) {
            if self.is_i128(operand) {
                return Err(error_diagnostic(
                    "this i128 operation requires additional explicit native lowering",
                ));
            }
        }
        if instruction
            .result
            .is_some_and(|v| matches!(self.module.types[v.ty], Type::Int { bits: 128 }))
        {
            return Err(error_diagnostic(
                "unhandled i128 result cannot use scalar64 lowering",
            ));
        }
        Ok(false)
    }

    fn wide_binary(&mut self, out: &mut String, kind: BinaryOp) -> Result<(), Diagnostic> {
        match kind {
            BinaryOp::Add => out.push_str(match self.target {
                Target::X86_64UnknownNone => "  add rax, rdx\n  adc rcx, r8\n",
                Target::Aarch64UnknownNone => "  adds x9, x9, x11\n  adc x10, x10, x12\n",
                Target::Riscv64UnknownNone => "  add t4, t0, t2\n  sltu t5, t4, t0\n  add t1, t1, t3\n  add t1, t1, t5\n  mv t0, t4\n",
            }),
            BinaryOp::Sub => out.push_str(match self.target {
                Target::X86_64UnknownNone => "  sub rax, rdx\n  sbb rcx, r8\n",
                Target::Aarch64UnknownNone => "  subs x9, x9, x11\n  sbc x10, x10, x12\n",
                Target::Riscv64UnknownNone => "  sltu t5, t0, t2\n  sub t0, t0, t2\n  sub t1, t1, t3\n  sub t1, t1, t5\n",
            }),
            BinaryOp::Mul => out.push_str(match self.target {
                Target::X86_64UnknownNone => "  mov r9, rdx\n  mov r10, rax\n  imul rcx, r9\n  imul r8, r10\n  mul r9\n  add rcx, r8\n  add rcx, rdx\n",
                Target::Aarch64UnknownNone => "  umulh x13, x9, x11\n  mul x14, x9, x12\n  madd x13, x10, x11, x13\n  add x10, x13, x14\n  mul x9, x9, x11\n",
                Target::Riscv64UnknownNone => "  mulhu t4, t0, t2\n  mul t5, t0, t3\n  mul t1, t1, t2\n  add t1, t1, t4\n  add t1, t1, t5\n  mul t0, t0, t2\n",
            }),
            BinaryOp::And | BinaryOp::Or | BinaryOp::Xor => {
                let op = match (kind, self.target) {
                    (BinaryOp::And, _) => "and",
                    (BinaryOp::Or, Target::Aarch64UnknownNone) => "orr",
                    (BinaryOp::Or, _) => "or",
                    (_, Target::Aarch64UnknownNone) => "eor",
                    _ => "xor",
                };
                for (a, b) in [(0, 2), (1, 3)] {
                    if self.target == Target::X86_64UnknownNone {
                        writeln!(out, "  {op} {}, {}", self.wide_reg(a), self.wide_reg(b)).unwrap();
                    } else {
                        writeln!(out, "  {op} {}, {}, {}", self.wide_reg(a), self.wide_reg(a), self.wide_reg(b)).unwrap();
                    }
                }
            }
            BinaryOp::Shl | BinaryOp::LShr | BinaryOp::AShr => self.wide_shift(out, kind),
            BinaryOp::UDiv | BinaryOp::SDiv | BinaryOp::URem | BinaryOp::SRem => self.wide_divide(out, kind),
        }
        Ok(())
    }

    fn wide_shift(&mut self, out: &mut String, kind: BinaryOp) {
        let small = self.label();
        let done = self.label();
        match self.target {
            Target::X86_64UnknownNone => {
                writeln!(out, "  mov r9, rcx\n  mov rcx, rdx\n  and rcx, 127\n  test rcx, rcx\n  jz {done}\n  cmp rcx, 64\n  jb {small}\n  sub rcx, 64").unwrap();
                out.push_str(match kind {
                    BinaryOp::Shl => "  mov r9, rax\n  shl r9, cl\n  xor eax, eax\n",
                    BinaryOp::LShr => "  mov rax, r9\n  shr rax, cl\n  xor r9d, r9d\n",
                    _ => "  mov rax, r9\n  sar rax, cl\n  sar r9, 63\n",
                });
                writeln!(out, "  jmp {done}\n{small}:").unwrap();
                out.push_str(match kind {
                    BinaryOp::Shl => "  shld r9, rax, cl\n  shl rax, cl\n",
                    BinaryOp::LShr => "  shrd rax, r9, cl\n  shr r9, cl\n",
                    _ => "  shrd rax, r9, cl\n  sar r9, cl\n",
                });
                writeln!(out, "{done}:\n  mov rcx, r9").unwrap();
            }
            Target::Aarch64UnknownNone => {
                writeln!(out, "  and x11, x11, #127\n  cbz x11, {done}\n  cmp x11, #64\n  b.lo {small}\n  sub x11, x11, #64").unwrap();
                out.push_str(match kind {
                    BinaryOp::Shl => "  lsl x10, x9, x11\n  mov x9, xzr\n",
                    BinaryOp::LShr => "  lsr x9, x10, x11\n  mov x10, xzr\n",
                    _ => "  asr x9, x10, x11\n  asr x10, x10, #63\n",
                });
                writeln!(
                    out,
                    "  b {done}\n{small}:\n  mov x13, #64\n  sub x13, x13, x11"
                )
                .unwrap();
                out.push_str(match kind {
                    BinaryOp::Shl => "  lsr x14, x9, x13\n  lsl x10, x10, x11\n  orr x10, x10, x14\n  lsl x9, x9, x11\n",
                    BinaryOp::LShr => "  lsl x14, x10, x13\n  lsr x9, x9, x11\n  orr x9, x9, x14\n  lsr x10, x10, x11\n",
                    _ => "  lsl x14, x10, x13\n  lsr x9, x9, x11\n  orr x9, x9, x14\n  asr x10, x10, x11\n",
                });
                writeln!(out, "{done}:").unwrap();
            }
            Target::Riscv64UnknownNone => {
                writeln!(out, "  andi t2, t2, 127\n  beqz t2, {done}\n  li t4, 64\n  bltu t2, t4, {small}\n  addi t2, t2, -64").unwrap();
                out.push_str(match kind {
                    BinaryOp::Shl => "  sll t1, t0, t2\n  li t0, 0\n",
                    BinaryOp::LShr => "  srl t0, t1, t2\n  li t1, 0\n",
                    _ => "  sra t0, t1, t2\n  srai t1, t1, 63\n",
                });
                writeln!(out, "  j {done}\n{small}:\n  sub t4, t4, t2").unwrap();
                out.push_str(match kind {
                    BinaryOp::Shl => {
                        "  srl t5, t0, t4\n  sll t1, t1, t2\n  or t1, t1, t5\n  sll t0, t0, t2\n"
                    }
                    BinaryOp::LShr => {
                        "  sll t5, t1, t4\n  srl t0, t0, t2\n  or t0, t0, t5\n  srl t1, t1, t2\n"
                    }
                    _ => "  sll t5, t1, t4\n  srl t0, t0, t2\n  or t0, t0, t5\n  sra t1, t1, t2\n",
                });
                writeln!(out, "{done}:").unwrap();
            }
        }
    }

    pub(super) fn wide_compare(&mut self, out: &mut String, predicate: IntPredicate) {
        let yes = self.label();
        let no = self.label();
        let done = self.label();
        let signed = matches!(
            predicate,
            IntPredicate::Sgt | IntPredicate::Sge | IntPredicate::Slt | IntPredicate::Sle
        );
        let less = matches!(
            predicate,
            IntPredicate::Ult | IntPredicate::Ule | IntPredicate::Slt | IntPredicate::Sle
        );
        let low = if less { &yes } else { &no };
        let high = if less { &no } else { &yes };
        match self.target {
            Target::X86_64UnknownNone => {
                if matches!(predicate, IntPredicate::Eq | IntPredicate::Ne) {
                    writeln!(
                        out,
                        "  xor rax, rdx\n  xor rcx, r8\n  or rax, rcx\n  j{} {yes}",
                        if predicate == IntPredicate::Eq {
                            "z"
                        } else {
                            "nz"
                        }
                    )
                    .unwrap();
                } else {
                    writeln!(
                        out,
                        "  cmp rcx, r8\n  j{} {low}\n  j{} {high}\n  cmp rax, rdx\n  j{} {yes}",
                        if signed { "l" } else { "b" },
                        if signed { "g" } else { "a" },
                        match predicate {
                            IntPredicate::Ult | IntPredicate::Slt => "b",
                            IntPredicate::Ule | IntPredicate::Sle => "be",
                            IntPredicate::Ugt | IntPredicate::Sgt => "a",
                            _ => "ae",
                        }
                    )
                    .unwrap();
                }
            }
            Target::Aarch64UnknownNone => {
                if matches!(predicate, IntPredicate::Eq | IntPredicate::Ne) {
                    writeln!(out, "  eor x9, x9, x11\n  eor x10, x10, x12\n  orr x9, x9, x10\n  cb{} x9, {yes}", if predicate == IntPredicate::Eq { "z" } else { "nz" }).unwrap();
                } else {
                    writeln!(
                        out,
                        "  cmp x10, x12\n  b.{} {low}\n  b.{} {high}\n  cmp x9, x11\n  b.{} {yes}",
                        if signed { "lt" } else { "lo" },
                        if signed { "gt" } else { "hi" },
                        match predicate {
                            IntPredicate::Ult | IntPredicate::Slt => "lo",
                            IntPredicate::Ule | IntPredicate::Sle => "ls",
                            IntPredicate::Ugt | IntPredicate::Sgt => "hi",
                            _ => "hs",
                        }
                    )
                    .unwrap();
                }
            }
            Target::Riscv64UnknownNone => {
                if matches!(predicate, IntPredicate::Eq | IntPredicate::Ne) {
                    writeln!(
                        out,
                        "  xor t0, t0, t2\n  xor t1, t1, t3\n  or t0, t0, t1\n  b{}z t0, {yes}",
                        if predicate == IntPredicate::Eq {
                            "eq"
                        } else {
                            "ne"
                        }
                    )
                    .unwrap();
                } else {
                    let op = if signed { "blt" } else { "bltu" };
                    writeln!(out, "  {op} t1, t3, {low}\n  {op} t3, t1, {high}").unwrap();
                    let (branch, a, b) = match predicate {
                        IntPredicate::Ult | IntPredicate::Slt => ("bltu", "t0", "t2"),
                        IntPredicate::Ule | IntPredicate::Sle => ("bgeu", "t2", "t0"),
                        IntPredicate::Ugt | IntPredicate::Sgt => ("bltu", "t2", "t0"),
                        _ => ("bgeu", "t0", "t2"),
                    };
                    writeln!(out, "  {branch} {a}, {b}, {yes}").unwrap();
                }
            }
        }
        self.jump(out, &no);
        writeln!(out, "{yes}:").unwrap();
        self.immediate(out, 0, 1);
        self.jump(out, &done);
        writeln!(out, "{no}:").unwrap();
        self.immediate(out, 0, 0);
        writeln!(out, "{done}:").unwrap();
    }

    fn wide_negate(&self, out: &mut String, divisor: bool) {
        out.push_str(match (self.target, divisor) {
            (Target::X86_64UnknownNone, false) => "  neg rax\n  adc rcx, 0\n  neg rcx\n",
            (Target::X86_64UnknownNone, true) => "  neg rdx\n  adc r8, 0\n  neg r8\n",
            (Target::Aarch64UnknownNone, false) => "  negs x9, x9\n  ngc x10, x10\n",
            (Target::Aarch64UnknownNone, true) => "  negs x11, x11\n  ngc x12, x12\n",
            (Target::Riscv64UnknownNone, false) => {
                "  snez t4, t0\n  neg t0, t0\n  neg t1, t1\n  sub t1, t1, t4\n"
            }
            (Target::Riscv64UnknownNone, true) => {
                "  snez t4, t2\n  neg t2, t2\n  neg t3, t3\n  sub t3, t3, t4\n"
            }
        });
    }

    fn wide_divide(&mut self, out: &mut String, kind: BinaryOp) {
        let signed = matches!(kind, BinaryOp::SDiv | BinaryOp::SRem);
        let remainder = matches!(kind, BinaryOp::URem | BinaryOp::SRem);
        if signed {
            self.mov(out, self.wide_reg(7), self.reg(1));
            if !remainder {
                out.push_str(match self.target {
                    Target::X86_64UnknownNone => "  xor rdi, r8\n",
                    Target::Aarch64UnknownNone => "  eor x16, x16, x12\n",
                    Target::Riscv64UnknownNone => "  xor a0, a0, t3\n",
                });
            }
            for divisor in [false, true] {
                let positive = self.label();
                let hi = self.wide_reg(if divisor { 3 } else { 1 });
                match self.target {
                    Target::X86_64UnknownNone => {
                        writeln!(out, "  test {hi}, {hi}\n  jns {positive}").unwrap()
                    }
                    Target::Aarch64UnknownNone => {
                        writeln!(out, "  tbz {hi}, #63, {positive}").unwrap()
                    }
                    Target::Riscv64UnknownNone => writeln!(out, "  bgez {hi}, {positive}").unwrap(),
                }
                self.wide_negate(out, divisor);
                writeln!(out, "{positive}:").unwrap();
            }
        } else {
            self.mov(
                out,
                self.wide_reg(7),
                match self.target {
                    Target::X86_64UnknownNone => "0",
                    Target::Aarch64UnknownNone => "xzr",
                    Target::Riscv64UnknownNone => "zero",
                },
            );
        }
        let nonzero = self.label();
        let again = self.label();
        let subtract = self.label();
        let next = self.label();
        match self.target {
            Target::X86_64UnknownNone => writeln!(out, "  mov r9, rdx\n  or r9, r8\n  jnz {nonzero}\n  ud2\n{nonzero}:\n  xor r9d, r9d\n  xor r10d, r10d\n  mov esi, 128\n{again}:\n  shl rax, 1\n  rcl rcx, 1\n  rcl r9, 1\n  rcl r10, 1\n  jc {subtract}\n  cmp r10, r8\n  ja {subtract}\n  jb {next}\n  cmp r9, rdx\n  jb {next}\n{subtract}:\n  sub r9, rdx\n  sbb r10, r8\n  or rax, 1\n{next}:\n  dec esi\n  jnz {again}").unwrap(),
            Target::Aarch64UnknownNone => writeln!(out, "  orr x13, x11, x12\n  cbnz x13, {nonzero}\n  brk #1\n{nonzero}:\n  mov x13, xzr\n  mov x14, xzr\n  mov x15, #128\n{again}:\n  adds x9, x9, x9\n  adcs x10, x10, x10\n  adcs x13, x13, x13\n  adcs x14, x14, x14\n  b.cs {subtract}\n  cmp x14, x12\n  b.hi {subtract}\n  b.lo {next}\n  cmp x13, x11\n  b.lo {next}\n{subtract}:\n  subs x13, x13, x11\n  sbc x14, x14, x12\n  orr x9, x9, #1\n{next}:\n  subs x15, x15, #1\n  b.ne {again}").unwrap(),
            Target::Riscv64UnknownNone => writeln!(out, "  or t4, t2, t3\n  bnez t4, {nonzero}\n  unimp\n{nonzero}:\n  li t4, 0\n  li t5, 0\n  li t6, 128\n{again}:\n  srli a1, t0, 63\n  srli a2, t1, 63\n  slli t0, t0, 1\n  slli t1, t1, 1\n  or t1, t1, a1\n  srli a1, t4, 63\n  slli t4, t4, 1\n  or t4, t4, a2\n  srli a2, t5, 63\n  slli t5, t5, 1\n  or t5, t5, a1\n  bnez a2, {subtract}\n  bltu t3, t5, {subtract}\n  bltu t5, t3, {next}\n  bltu t4, t2, {next}\n{subtract}:\n  sltu a1, t4, t2\n  sub t4, t4, t2\n  sub t5, t5, t3\n  sub t5, t5, a1\n  ori t0, t0, 1\n{next}:\n  addi t6, t6, -1\n  bnez t6, {again}").unwrap(),
        }
        if remainder {
            self.mov(out, self.reg(0), self.wide_reg(4));
            self.mov(out, self.reg(1), self.wide_reg(5));
        }
        if signed {
            let done = self.label();
            let sign = self.wide_reg(7);
            match self.target {
                Target::X86_64UnknownNone => {
                    writeln!(out, "  test {sign}, {sign}\n  jns {done}").unwrap()
                }
                Target::Aarch64UnknownNone => writeln!(out, "  tbz {sign}, #63, {done}").unwrap(),
                Target::Riscv64UnknownNone => writeln!(out, "  bgez {sign}, {done}").unwrap(),
            }
            self.wide_negate(out, false);
            writeln!(out, "{done}:").unwrap();
        }
    }
}
