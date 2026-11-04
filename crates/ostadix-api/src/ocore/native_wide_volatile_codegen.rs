// Wide volatile memory realizations under the explicit ordinary-RAM contract.
// The original IR operation, type, width and alignment are never rewritten.
// A single memory instruction does not establish atomicity.
impl Emitter<'_> {
    pub(super) fn wide_volatile_instruction(
        &self,
        out: &mut String,
        instruction: &Instruction,
    ) -> Result<bool, Diagnostic> {
        match &instruction.operation {
            Operation::Load {
                pointer,
                alignment,
                volatile: true,
            } => {
                let result = instruction.result.unwrap();
                match (self.target, &self.module.types[result.ty]) {
                    (Target::X86_64UnknownNone, Type::Float { bits: 128 }) => {
                        self.operand(out, 1, pointer);
                        out.push_str("  movdqu xmm14, xmmword ptr [rcx]\n  movq rax, xmm14\n");
                        self.spill_chunk(out, result, 0, 0);
                        out.push_str("  movhlps xmm15, xmm14\n  movq rax, xmm15\n");
                        self.spill_chunk(out, result, 0, 64);
                    }
                    (Target::Aarch64UnknownNone, Type::Float { bits: 128 }) => {
                        let alignment = if *alignment == 0 {
                            type_alignment(self.module, result.ty)?
                        } else {
                            *alignment
                        };
                        if alignment < 16 {
                            return Ok(false);
                        }
                        self.operand(out, 1, pointer);
                        out.push_str("  ldr q16, [x10]\n  umov x9, v16.d[0]\n");
                        self.spill_chunk(out, result, 0, 0);
                        out.push_str("  umov x9, v16.d[1]\n");
                        self.spill_chunk(out, result, 0, 64);
                    }
                    (Target::X86_64UnknownNone, Type::Float { bits: 80 }) => {
                        self.operand(out, 1, pointer);
                        out.push_str("  fld tbyte ptr [rcx]\n");
                        self.stack_address(out, self.floating_scratch);
                        out.push_str("  fstp tbyte ptr [r11]\n");
                        for bit in [0u16, 64] {
                            self.stack_load(out, 0, self.floating_scratch + i64::from(bit / 8));
                            self.spill_chunk(out, result, 0, bit);
                        }
                    }
                    // Non-native scalar128 accesses retain the audited ordered
                    // word realization below. They require the RAM profile too.
                    _ => return Ok(false),
                }
                Ok(true)
            }
            Operation::Store {
                pointer,
                value,
                alignment,
                volatile: true,
            } => {
                match (self.target, &self.module.types[self.ty(value)]) {
                    (Target::X86_64UnknownNone, Type::Float { bits: 128 }) => {
                        self.operand_chunk(out, 0, value, 0, 0);
                        out.push_str("  movq xmm14, rax\n");
                        self.operand_chunk(out, 0, value, 0, 64);
                        out.push_str("  movq xmm15, rax\n  punpcklqdq xmm14, xmm15\n");
                        self.operand(out, 1, pointer);
                        out.push_str("  movdqu xmmword ptr [rcx], xmm14\n");
                    }
                    (Target::Aarch64UnknownNone, Type::Float { bits: 128 }) => {
                        let alignment = if *alignment == 0 {
                            type_alignment(self.module, self.ty(value))?
                        } else {
                            *alignment
                        };
                        if alignment < 16 {
                            return Ok(false);
                        }
                        self.operand_chunk(out, 0, value, 0, 0);
                        out.push_str("  fmov d16, x9\n");
                        self.operand_chunk(out, 0, value, 0, 64);
                        out.push_str("  mov v16.d[1], x9\n");
                        self.operand(out, 1, pointer);
                        out.push_str("  str q16, [x10]\n");
                    }
                    (Target::X86_64UnknownNone, Type::Float { bits: 80 }) => {
                        for bit in [0u16, 64] {
                            self.operand_chunk(out, 0, value, 0, bit);
                            self.mask(out, 0, (80 - bit).min(64));
                            self.stack_store(out, 0, self.floating_scratch + i64::from(bit / 8));
                        }
                        self.stack_address(out, self.floating_scratch);
                        out.push_str("  fld tbyte ptr [r11]\n");
                        self.operand(out, 1, pointer);
                        out.push_str("  fstp tbyte ptr [rcx]\n");
                    }
                    _ => return Ok(false),
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
