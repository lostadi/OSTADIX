// Exact scalar floating-point bit transport. A semantic float remains one
// leaf; 80/128-bit spills retain two words and never travel through host f64.
use super::super::native_floating_helpers::{HelperRequirement, HelperType};
use super::*;

impl Emitter<'_> {
    fn float_register_word(&self, out: &mut String, register: &str, bits: u16, bit: u16) {
        match self.target {
            Target::X86_64UnknownNone => match (bits, bit) {
                (32, 0) => writeln!(out, "  movd eax, {register}").unwrap(),
                (_, 0) => writeln!(out, "  movq rax, {register}").unwrap(),
                (128, 64) => {
                    writeln!(out, "  movhlps xmm15, {register}\n  movq rax, xmm15").unwrap()
                }
                _ => unreachable!("audited scalar FP register chunk"),
            },
            Target::Aarch64UnknownNone => match (bits, bit) {
                (32, 0) => writeln!(out, "  fmov w9, {register}").unwrap(),
                (64, 0) => writeln!(out, "  fmov x9, {register}").unwrap(),
                (128, 0 | 64) => {
                    writeln!(out, "  umov x9, v{}.d[{}]", &register[1..], bit / 64).unwrap()
                }
                _ => unreachable!("audited AAPCS64 FP register chunk"),
            },
            Target::Riscv64UnknownNone => match (bits, bit) {
                (32, 0) => writeln!(out, "  fmv.x.w t0, {register}").unwrap(),
                (64, 0) => writeln!(out, "  fmv.x.d t0, {register}").unwrap(),
                _ => unreachable!("audited RV64 FLEN64 register chunk"),
            },
        }
    }

    fn install_float_register(
        &self,
        out: &mut String,
        register: &str,
        part: &AbiPart,
        value: &Operand,
    ) {
        self.operand_chunk(out, 0, value, part.leaf, part.bit_offset);
        match self.target {
            Target::X86_64UnknownNone => match part.value_bits {
                32 => writeln!(out, "  movd {register}, eax").unwrap(),
                64 => writeln!(out, "  movq {register}, rax").unwrap(),
                128 => {
                    writeln!(out, "  movq {register}, rax").unwrap();
                    self.operand_chunk(out, 0, value, part.leaf, part.bit_offset + 64);
                    // SSE2 is sufficient; do not require SSE4.1 PINSRQ.
                    writeln!(out, "  movq xmm15, rax\n  punpcklqdq {register}, xmm15").unwrap();
                }
                _ => unreachable!("audited SysV FP register"),
            },
            Target::Aarch64UnknownNone => match part.value_bits {
                32 => writeln!(out, "  fmov {register}, w9").unwrap(),
                64 => writeln!(out, "  fmov {register}, x9").unwrap(),
                128 => {
                    let number = &register[1..];
                    writeln!(out, "  fmov d{number}, x9").unwrap();
                    self.operand_chunk(out, 0, value, part.leaf, part.bit_offset + 64);
                    writeln!(out, "  mov v{number}.d[1], x9").unwrap();
                }
                _ => unreachable!("audited AAPCS64 FP register"),
            },
            Target::Riscv64UnknownNone => match part.value_bits {
                // FMV.W.X produces architectural NaN boxing for FLEN64.
                32 => writeln!(out, "  fmv.w.x {register}, t0").unwrap(),
                64 => writeln!(out, "  fmv.d.x {register}, t0").unwrap(),
                _ => unreachable!("audited RV64 FP register"),
            },
        }
    }

    pub(super) fn capture_abi_part(
        &self,
        out: &mut String,
        part: &AbiPart,
        result: Value,
    ) -> Result<(), Diagnostic> {
        if let AbiLocation::Register(register) = part.location {
            if part.class == AbiClass::X87 {
                self.stack_address(out, self.floating_scratch);
                out.push_str("  fstp tbyte ptr [r11]\n");
                for bit in [0u16, 64] {
                    self.stack_load(out, 0, self.floating_scratch + i64::from(bit / 8));
                    self.spill_chunk(out, result, part.leaf, part.bit_offset + bit);
                }
                return Ok(());
            }
            for bit in (0..part.value_bits).step_by(64) {
                if part.class == AbiClass::Float {
                    self.float_register_word(out, register, part.value_bits, bit);
                } else {
                    debug_assert_eq!(bit, 0);
                    self.mov(out, self.reg(0), register);
                }
                self.spill_chunk(out, result, part.leaf, part.bit_offset + bit);
            }
        } else if let AbiLocation::Stack { offset } = part.location {
            for bit in (0..part.value_bits).step_by(64) {
                let offset = offset
                    .checked_add(u64::from(bit / 8))
                    .and_then(|v| i64::try_from(v).ok())
                    .and_then(|v| v.checked_add(self.incoming_stack_base()))
                    .ok_or_else(|| error_diagnostic("floating incoming stack extent overflow"))?;
                if part.class == AbiClass::Float && part.value_bits == 32 {
                    // Packed Fast f32 locations need an exact four-byte load.
                    // No FPR scratch: ft0/ft1 may hold pending Fast arguments.
                    self.stack_address(out, offset);
                    out.push_str(match self.target {
                        Target::X86_64UnknownNone => "  mov eax, dword ptr [r11]\n",
                        Target::Aarch64UnknownNone => "  ldr w9, [x17]\n",
                        Target::Riscv64UnknownNone => "  lwu t0, 0(ra)\n",
                    });
                } else {
                    self.stack_load(out, 0, offset);
                }
                self.spill_chunk(out, result, part.leaf, part.bit_offset + bit);
            }
        } else {
            return Err(error_diagnostic(
                "floating transport requires a direct ABI location",
            ));
        }
        Ok(())
    }

    pub(super) fn place_abi_part(
        &self,
        out: &mut String,
        part: &AbiPart,
        value: &Operand,
    ) -> Result<(), Diagnostic> {
        match part.location {
            AbiLocation::Register(register) => match part.class {
                AbiClass::Float => self.install_float_register(out, register, part, value),
                AbiClass::General => {
                    self.operand_chunk(out, 0, value, part.leaf, part.bit_offset);
                    self.extend_abi_part(out, part)?;
                    self.mov(out, register, self.reg(0));
                }
                AbiClass::X87 => {
                    debug_assert_eq!(self.target, Target::X86_64UnknownNone);
                    for bit in [0u16, 64] {
                        self.operand_chunk(out, 0, value, part.leaf, part.bit_offset + bit);
                        self.mask(out, 0, (80 - bit).min(64));
                        self.stack_store(out, 0, self.floating_scratch + i64::from(bit / 8));
                    }
                    self.stack_address(out, self.floating_scratch);
                    out.push_str("  fld tbyte ptr [r11]\n");
                }
            },
            AbiLocation::Stack { offset } => {
                for bit in (0..part.value_bits).step_by(64) {
                    self.operand_chunk(out, 0, value, part.leaf, part.bit_offset + bit);
                    let bits = (part.value_bits - bit).min(64);
                    if part.class == AbiClass::General {
                        self.extend_abi_part(out, part)?;
                    } else {
                        self.mask(out, 0, bits);
                    }
                    let address = offset.checked_add(u64::from(bit / 8)).ok_or_else(|| {
                        error_diagnostic("floating outgoing stack extent overflow")
                    })?;
                    self.immediate(out, 1, address);
                    out.push_str(match self.target {
                        Target::X86_64UnknownNone => "  add rcx, rsp\n",
                        Target::Aarch64UnknownNone => "  add x10, sp, x10\n",
                        Target::Riscv64UnknownNone => "  add t1, sp, t1\n",
                    });
                    let bytes = if part.class == AbiClass::General {
                        8
                    } else {
                        u64::from(bits.div_ceil(8))
                    };
                    self.store(out, bytes, bytes.min(8));
                }
            }
            AbiLocation::IndirectResult { .. } => {
                return Err(error_diagnostic(
                    "indirect result needs memory ABI transport",
                ))
            }
        }
        Ok(())
    }

    // These selected compiler-runtime C interfaces have at most two scalar
    // operands. Their exact derived contracts also feed dependency inventory;
    // no arbitrary undefined symbol is admitted by emitting one of these calls.
    pub(super) fn floating_helper_call(
        &mut self,
        out: &mut String,
        helper: &HelperRequirement,
        args: &[Operand],
        result: Value,
    ) -> Result<(), Diagnostic> {
        if helper.params.len() != args.len() {
            return Err(error_diagnostic(
                "floating helper argument inventory mismatch",
            ));
        }
        let actual_types: Vec<_> = args.iter().map(|value| self.ty(value)).collect();
        let plan = self.abi.plan_helper(helper, &actual_types, result.ty)?;
        for mut part in plan.args {
            let index = part.param.unwrap();
            if matches!(helper.params[index], HelperType::Int { .. }) {
                part.value_bits = self.bits(&args[index]);
                part.extension = if helper.name == "__floatditf" {
                    Extension::Sign
                } else {
                    Extension::Zero
                };
            }
            self.place_abi_part(out, &part, &args[index])?;
        }
        let start = self
            .function
            .exception_handling
            .is_some()
            .then(|| self.label());
        if let Some(label) = &start {
            writeln!(out, "{label}:").unwrap();
        }
        writeln!(
            out,
            "  {} {}",
            if self.target == Target::Aarch64UnknownNone {
                "bl"
            } else {
                "call"
            },
            helper.name
        )
        .unwrap();
        if let Some(start) = start {
            let end = self.label();
            writeln!(out, "{end}:").unwrap();
            self.call_sites.push(CallSite {
                start,
                end,
                landing: None,
                action: 0,
            });
        }
        for part in plan.results {
            self.capture_abi_part(out, &part, result)?;
        }
        Ok(())
    }
}
