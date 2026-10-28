// Target ABI realization of LLVM va_start/va_end/va_copy. The importer and
// independent verifier retain and validate the exact intrinsic declarations.
use super::super::native_verify::VariadicIntrinsic;
use super::*;

impl Emitter<'_> {
    pub(super) fn incoming_stack_base(&self) -> i64 {
        if self.function.signature.variadic && self.target == Target::Riscv64UnknownNone {
            // Saved a0..a7 end exactly at entry SP, so a pointer va_list can
            // advance from the final saved register into the incoming stack.
            80
        } else {
            16
        }
    }

    pub(super) fn save_variadic_registers(&self, out: &mut String) {
        let Some(plan) = &self.abi_plan.variadic else {
            return;
        };
        for (index, reg) in plan.gp_registers.iter().enumerate() {
            let offset = if self.target == Target::Riscv64UnknownNone {
                16 + index as i64 * 8
            } else {
                self.variadic_save.unwrap() + index as i64 * 8
            };
            self.stack_address(out, offset);
            match self.target {
                Target::X86_64UnknownNone => writeln!(out, "  mov qword ptr [r11], {reg}").unwrap(),
                Target::Aarch64UnknownNone => writeln!(out, "  str {reg}, [x17]").unwrap(),
                Target::Riscv64UnknownNone => writeln!(out, "  sd {reg}, 0(ra)").unwrap(),
            }
        }
        // Save the full incoming vector bank, including when the body only
        // forwards an opaque va_list to an external implementation. These raw
        // saves do not claim first-class floating-point SSA support.
        if let Some(base) = self.variadic_save {
            for index in 0..8 {
                let offset =
                    base + if self.target == Target::X86_64UnknownNone {
                        48
                    } else {
                        64
                    } + index * 16;
                self.stack_address(out, offset);
                match self.target {
                    Target::X86_64UnknownNone => {
                        writeln!(out, "  movdqu xmmword ptr [r11], xmm{index}").unwrap()
                    }
                    Target::Aarch64UnknownNone => writeln!(out, "  str q{index}, [x17]").unwrap(),
                    Target::Riscv64UnknownNone => unreachable!(),
                }
            }
        }
    }

    fn va_store(&self, out: &mut String, list: &Operand, offset: u64, bytes: u64) {
        self.operand(out, 1, list);
        self.address_offset(out, offset);
        self.store(out, bytes, bytes);
    }

    fn va_frame_pointer(&self, out: &mut String, offset: i64) {
        self.stack_address(out, offset);
        let address = match self.target {
            Target::X86_64UnknownNone => "r11",
            Target::Aarch64UnknownNone => "x17",
            Target::Riscv64UnknownNone => "ra",
        };
        self.mov(out, self.reg(0), address);
    }

    pub(super) fn variadic_intrinsic(
        &self,
        out: &mut String,
        intrinsic: VariadicIntrinsic,
        args: &[Operand],
    ) -> Result<(), Diagnostic> {
        match intrinsic {
            VariadicIntrinsic::End => {}
            VariadicIntrinsic::Copy => {
                let bytes = match self.target {
                    Target::X86_64UnknownNone => 24,
                    Target::Aarch64UnknownNone => 32,
                    Target::Riscv64UnknownNone => 8,
                };
                for offset in (0..bytes).step_by(8) {
                    self.operand(out, 1, &args[1]);
                    self.address_offset(out, offset);
                    self.load(out, 8, 8);
                    self.va_store(out, &args[0], offset, 8);
                }
            }
            VariadicIntrinsic::Start => {
                let plan = self.abi_plan.variadic.as_ref().ok_or_else(|| {
                    error_diagnostic("va_start requires an enclosing variadic definition")
                })?;
                let stack_offset =
                    self.incoming_stack_base()
                        .checked_add(i64::try_from(plan.named_stack_bytes).map_err(|_| {
                            error_diagnostic("va_start incoming stack extent overflow")
                        })?)
                        .ok_or_else(|| error_diagnostic("va_start stack address overflow"))?;
                match self.target {
                    Target::Riscv64UnknownNone => {
                        let offset = if plan.named_gp < 8 {
                            16 + plan.named_gp as i64 * 8
                        } else {
                            stack_offset
                        };
                        self.va_frame_pointer(out, offset);
                        self.va_store(out, &args[0], 0, 8);
                    }
                    Target::X86_64UnknownNone => {
                        self.immediate(out, 0, (plan.named_gp * 8) as u64);
                        self.va_store(out, &args[0], 0, 4);
                        self.immediate(out, 0, 48);
                        self.va_store(out, &args[0], 4, 4);
                        self.va_frame_pointer(out, stack_offset);
                        self.va_store(out, &args[0], 8, 8);
                        self.va_frame_pointer(out, self.variadic_save.unwrap());
                        self.va_store(out, &args[0], 16, 8);
                    }
                    Target::Aarch64UnknownNone => {
                        self.va_frame_pointer(out, stack_offset);
                        self.va_store(out, &args[0], 0, 8);
                        self.va_frame_pointer(out, self.variadic_save.unwrap() + 64);
                        self.va_store(out, &args[0], 8, 8);
                        self.va_frame_pointer(out, self.variadic_save.unwrap() + 192);
                        self.va_store(out, &args[0], 16, 8);
                        self.immediate(out, 0, (-((8 - plan.named_gp) as i64) * 8) as u64);
                        self.va_store(out, &args[0], 24, 4);
                        self.immediate(out, 0, (-128i64) as u64);
                        self.va_store(out, &args[0], 28, 4);
                    }
                }
            }
        }
        Ok(())
    }
}
