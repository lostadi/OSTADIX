// Scalar floating math. Storage, ABI transport, helper dependencies and whole-
// module admission are audited independently before this emitter is reached.
impl Emitter<'_> {
    pub(super) fn floating_instruction(
        &mut self,
        out: &mut String,
        instruction: &Instruction,
    ) -> Result<bool, Diagnostic> {
        let relevant = match &instruction.operation {
            Operation::FloatBinary { .. }
            | Operation::FloatNeg { .. }
            | Operation::FloatAbs { .. }
            | Operation::FCmp { .. } => true,
            Operation::Cast { kind, value } => {
                matches!(
                    kind,
                    CastOp::FpTrunc
                        | CastOp::FpExt
                        | CastOp::FpToUi
                        | CastOp::FpToSi
                        | CastOp::UiToFp
                        | CastOp::SiToFp
                ) || (*kind == CastOp::Bitcast
                    && (matches!(self.module.types[self.ty(value)], Type::Float { .. })
                        || instruction.result.is_some_and(|v| {
                            matches!(self.module.types[v.ty], Type::Float { .. })
                        })))
            }
            _ => false,
        };
        if !relevant {
            return Ok(false);
        }
        let result = instruction
            .result
            .ok_or_else(|| error_diagnostic("floating instruction requires its verified result"))?;
        if let Some(requirement) = super::super::native_floating_helpers::operation_requirement(
            self.module,
            self.target,
            instruction,
            &self.types,
        )? {
            let args = match &instruction.operation {
                Operation::FloatBinary { lhs, rhs, .. } => vec![lhs.clone(), rhs.clone()],
                Operation::Cast { value, .. } => vec![value.clone()],
                _ => return Err(error_diagnostic("unexpected floating helper operation")),
            };
            self.floating_helper_call(out, &requirement, &args, result)?;
            return Ok(true);
        }
        match &instruction.operation {
            Operation::FloatNeg { value, .. } | Operation::FloatAbs { value, .. } => {
                let absolute = matches!(instruction.operation, Operation::FloatAbs { .. });
                let bits = self.bits(value);
                self.operand_chunk(out, 0, value, 0, 0);
                if bits <= 64 {
                    self.immediate(
                        out,
                        1,
                        if absolute {
                            !(1u64 << (bits - 1))
                        } else {
                            1u64 << (bits - 1)
                        },
                    );
                    if absolute {
                        self.floating_sign_clear(out);
                    } else {
                        self.floating_xor(out);
                    }
                    self.spill_chunk(out, result, 0, 0);
                } else {
                    self.spill_chunk(out, result, 0, 0);
                    self.operand_chunk(out, 0, value, 0, 64);
                    self.immediate(
                        out,
                        1,
                        if absolute {
                            !(1u64 << (bits - 65))
                        } else {
                            1u64 << (bits - 65)
                        },
                    );
                    if absolute {
                        self.floating_sign_clear(out);
                    } else {
                        self.floating_xor(out);
                    }
                    self.spill_chunk(out, result, 0, 64);
                }
            }
            Operation::FloatBinary { kind, lhs, rhs, .. } => {
                let bits = self.bits(lhs);
                self.floating_load(out, lhs, Some(rhs), bits)?;
                let op = match kind {
                    FloatBinaryOp::Add => "add",
                    FloatBinaryOp::Sub => "sub",
                    FloatBinaryOp::Mul => "mul",
                    FloatBinaryOp::Div => "div",
                    FloatBinaryOp::Rem => {
                        return Err(error_diagnostic(
                            "floating remainder requires an explicit implementation dependency",
                        ))
                    }
                };
                match self.target {
                    Target::X86_64UnknownNone => writeln!(
                        out,
                        "  {op}{} xmm14, xmm15",
                        if bits == 32 { "ss" } else { "sd" }
                    )
                    .unwrap(),
                    Target::Aarch64UnknownNone => {
                        let p = if bits == 32 { "s" } else { "d" };
                        writeln!(out, "  f{op} {p}16, {p}16, {p}17").unwrap();
                    }
                    Target::Riscv64UnknownNone => writeln!(
                        out,
                        "  f{op}.{} ft0, ft0, ft1, rne",
                        if bits == 32 { "s" } else { "d" }
                    )
                    .unwrap(),
                }
                self.floating_read_result(out, bits);
                self.spill_chunk(out, result, 0, 0);
            }
            Operation::FCmp {
                predicate,
                lhs,
                rhs,
                ..
            } => {
                let bits = self.bits(lhs);
                self.floating_load(out, lhs, Some(rhs), bits)?;
                self.floating_compare(out, *predicate, bits);
                self.spill_chunk(out, result, 0, 0);
            }
            Operation::Cast {
                kind: CastOp::Bitcast,
                value,
            } => {
                let bits = scalar_bits(self.module, result.ty)?;
                self.operand_chunk(out, 0, value, 0, 0);
                self.spill_chunk(out, result, 0, 0);
                if bits > 64 {
                    self.operand_chunk(out, 0, value, 0, 64);
                    self.spill_chunk(out, result, 0, 64);
                }
            }
            Operation::Cast { kind, value } => self.floating_cast(out, *kind, value, result)?,
            _ => unreachable!(),
        }
        Ok(true)
    }

    fn floating_sign_clear(&self, out: &mut String) {
        match self.target {
            Target::X86_64UnknownNone => out.push_str("  and rax, rcx\n"),
            Target::Aarch64UnknownNone => out.push_str("  and x9, x9, x10\n"),
            Target::Riscv64UnknownNone => out.push_str("  and t0, t0, t1\n"),
        }
    }

    fn floating_xor(&self, out: &mut String) {
        match self.target {
            Target::X86_64UnknownNone => out.push_str("  xor rax, rcx\n"),
            Target::Aarch64UnknownNone => out.push_str("  eor x9, x9, x10\n"),
            Target::Riscv64UnknownNone => out.push_str("  xor t0, t0, t1\n"),
        }
    }

    fn floating_load(
        &self,
        out: &mut String,
        lhs: &Operand,
        rhs: Option<&Operand>,
        bits: u16,
    ) -> Result<(), Diagnostic> {
        if !matches!(bits, 32 | 64) {
            return Err(error_diagnostic("hardware floating computation requires IEEE32/64; wider operations require an audited implementation"));
        }
        self.operand_chunk(out, 0, lhs, 0, 0);
        if let Some(rhs) = rhs {
            self.operand_chunk(out, 1, rhs, 0, 0);
        }
        match self.target {
            Target::X86_64UnknownNone => {
                writeln!(
                    out,
                    "  {} xmm14, {}",
                    if bits == 32 { "movd" } else { "movq" },
                    if bits == 32 { "eax" } else { "rax" }
                )
                .unwrap();
                if rhs.is_some() {
                    writeln!(
                        out,
                        "  {} xmm15, {}",
                        if bits == 32 { "movd" } else { "movq" },
                        if bits == 32 { "ecx" } else { "rcx" }
                    )
                    .unwrap();
                }
            }
            Target::Aarch64UnknownNone => {
                let (p, g) = if bits == 32 { ("s", "w") } else { ("d", "x") };
                writeln!(out, "  fmov {p}16, {g}9").unwrap();
                if rhs.is_some() {
                    writeln!(out, "  fmov {p}17, {g}10").unwrap();
                }
            }
            Target::Riscv64UnknownNone => {
                let p = if bits == 32 { "w" } else { "d" };
                writeln!(out, "  fmv.{p}.x ft0, t0").unwrap();
                if rhs.is_some() {
                    writeln!(out, "  fmv.{p}.x ft1, t1").unwrap();
                }
            }
        }
        Ok(())
    }

    fn floating_read_result(&self, out: &mut String, bits: u16) {
        match self.target {
            Target::X86_64UnknownNone => writeln!(
                out,
                "  {} {}, xmm14",
                if bits == 32 { "movd" } else { "movq" },
                if bits == 32 { "eax" } else { "rax" }
            )
            .unwrap(),
            Target::Aarch64UnknownNone => writeln!(
                out,
                "  fmov {}9, {}16",
                if bits == 32 { "w" } else { "x" },
                if bits == 32 { "s" } else { "d" }
            )
            .unwrap(),
            Target::Riscv64UnknownNone => writeln!(
                out,
                "  fmv.x.{} t0, ft0",
                if bits == 32 { "w" } else { "d" }
            )
            .unwrap(),
        }
        if bits == 32 {
            self.mask(out, 0, 32);
        }
    }

    fn floating_compare(&self, out: &mut String, predicate: FloatPredicate, bits: u16) {
        use FloatPredicate::*;
        match self.target {
            Target::X86_64UnknownNone => {
                writeln!(
                    out,
                    "  ucomi{} xmm14, xmm15",
                    if bits == 32 { "ss" } else { "sd" }
                )
                .unwrap();
                match predicate {
                    False => out.push_str("  xor eax, eax\n"),
                    True => out.push_str("  mov eax, 1\n"),
                    Oeq | Olt | Ole => {
                        let c = match predicate {
                            Oeq => "e",
                            Olt => "b",
                            _ => "be",
                        };
                        writeln!(out, "  set{c} al\n  setnp dl\n  and al, dl").unwrap();
                    }
                    Ogt => out.push_str("  seta al\n"),
                    Oge => out.push_str("  setae al\n"),
                    One => out.push_str("  setne al\n"),
                    Ord => out.push_str("  setnp al\n"),
                    Uno => out.push_str("  setp al\n"),
                    Ueq => out.push_str("  sete al\n"),
                    Ult => out.push_str("  setb al\n"),
                    Ule => out.push_str("  setbe al\n"),
                    Ugt | Uge | Une => {
                        let c = match predicate {
                            Ugt => "a",
                            Uge => "ae",
                            _ => "ne",
                        };
                        writeln!(out, "  set{c} al\n  setp dl\n  or al, dl").unwrap();
                    }
                }
                out.push_str("  movzx eax, al\n");
            }
            Target::Aarch64UnknownNone => {
                writeln!(
                    out,
                    "  fcmp {}16, {}17",
                    if bits == 32 { "s" } else { "d" },
                    if bits == 32 { "s" } else { "d" }
                )
                .unwrap();
                match predicate {
                    False => out.push_str("  mov x9, #0\n"),
                    True => out.push_str("  mov x9, #1\n"),
                    One => out.push_str("  cset w9, vc\n  cset w10, ne\n  and w9, w9, w10\n"),
                    Ueq => out.push_str("  cset w9, eq\n  cset w10, vs\n  orr w9, w9, w10\n"),
                    _ => {
                        let c = match predicate {
                            Oeq => "eq",
                            Ogt => "gt",
                            Oge => "ge",
                            Olt => "mi",
                            Ole => "ls",
                            Ord => "vc",
                            Uno => "vs",
                            Ugt => "hi",
                            Uge => "pl",
                            Ult => "lt",
                            Ule => "le",
                            Une => "ne",
                            _ => unreachable!(),
                        };
                        writeln!(out, "  cset w9, {c}").unwrap();
                    }
                }
            }
            Target::Riscv64UnknownNone => {
                let p = if bits == 32 { "s" } else { "d" };
                writeln!(
                    out,
                    "  feq.{p} t0, ft0, ft0\n  feq.{p} t1, ft1, ft1\n  and t2, t0, t1"
                )
                .unwrap();
                match predicate {
                    False => out.push_str("  li t0, 0\n"),
                    True => out.push_str("  li t0, 1\n"),
                    Ord => out.push_str("  mv t0, t2\n"),
                    Uno => out.push_str("  xori t0, t2, 1\n"),
                    Oeq | Ueq => {
                        writeln!(out, "  feq.{p} t0, ft0, ft1").unwrap();
                        if predicate == Ueq {
                            out.push_str("  xori t2, t2, 1\n  or t0, t0, t2\n");
                        }
                    }
                    One | Une => {
                        writeln!(out, "  feq.{p} t0, ft0, ft1\n  xori t0, t0, 1").unwrap();
                        if predicate == One {
                            out.push_str("  and t0, t0, t2\n");
                        }
                    }
                    _ => {
                        let (op, reverse) = match predicate {
                            Ogt | Ugt => ("flt", true),
                            Oge | Uge => ("fle", true),
                            Olt | Ult => ("flt", false),
                            Ole | Ule => ("fle", false),
                            _ => unreachable!(),
                        };
                        writeln!(
                            out,
                            "  {op}.{p} t0, {}, {}",
                            if reverse { "ft1" } else { "ft0" },
                            if reverse { "ft0" } else { "ft1" }
                        )
                        .unwrap();
                        if matches!(predicate, Ugt | Uge | Ult | Ule) {
                            out.push_str("  xori t2, t2, 1\n  or t0, t0, t2\n");
                        }
                    }
                }
            }
        }
    }

    fn floating_cast(
        &mut self,
        out: &mut String,
        kind: CastOp,
        value: &Operand,
        result: Value,
    ) -> Result<(), Diagnostic> {
        let source_bits = self.bits(value);
        let result_bits = scalar_bits(self.module, result.ty)?;
        match kind {
            CastOp::FpTrunc | CastOp::FpExt => {
                if !matches!((source_bits, result_bits), (32, 64) | (64, 32)) {
                    return Err(error_diagnostic(
                        "floating-width conversion requires an audited wide-format helper",
                    ));
                }
                self.floating_load(out, value, None, source_bits)?;
                match self.target {
                    Target::X86_64UnknownNone => writeln!(
                        out,
                        "  {} xmm14, xmm14",
                        if result_bits == 32 {
                            "cvtsd2ss"
                        } else {
                            "cvtss2sd"
                        }
                    )
                    .unwrap(),
                    Target::Aarch64UnknownNone => writeln!(
                        out,
                        "  fcvt {}16, {}16",
                        if result_bits == 32 { "s" } else { "d" },
                        if source_bits == 32 { "s" } else { "d" }
                    )
                    .unwrap(),
                    Target::Riscv64UnknownNone => out.push_str(if result_bits == 32 {
                        "  fcvt.s.d ft0, ft0, rne\n"
                    } else {
                        "  fcvt.d.s ft0, ft0\n"
                    }),
                }
                self.floating_read_result(out, result_bits);
            }
            CastOp::SiToFp | CastOp::UiToFp => {
                if !matches!(result_bits, 32 | 64) {
                    return Err(error_diagnostic(
                        "integer-to-wide-floating conversion requires an audited helper",
                    ));
                }
                self.operand_chunk(out, 0, value, 0, 0);
                let signed = kind == CastOp::SiToFp;
                if signed {
                    self.signed(out, 0, source_bits);
                } else {
                    self.mask(out, 0, source_bits);
                }
                match self.target {
                    Target::X86_64UnknownNone => {
                        let op = if result_bits == 32 {
                            "cvtsi2ss"
                        } else {
                            "cvtsi2sd"
                        };
                        if !signed && source_bits == 64 {
                            let low = self.label();
                            let done = self.label();
                            writeln!(out, "  test rax, rax\n  jns {low}\n  mov rdx, rax\n  and edx, 1\n  shr rax, 1\n  or rax, rdx\n  {op} xmm14, rax\n  add{} xmm14, xmm14\n  jmp {done}\n{low}:\n  {op} xmm14, rax\n{done}:", if result_bits == 32 { "ss" } else { "sd" }).unwrap();
                        } else {
                            writeln!(out, "  {op} xmm14, rax").unwrap();
                        }
                    }
                    Target::Aarch64UnknownNone => writeln!(
                        out,
                        "  {} {}16, x9",
                        if signed { "scvtf" } else { "ucvtf" },
                        if result_bits == 32 { "s" } else { "d" }
                    )
                    .unwrap(),
                    Target::Riscv64UnknownNone => writeln!(
                        out,
                        "  fcvt.{}.{} ft0, t0, rne",
                        if result_bits == 32 { "s" } else { "d" },
                        if signed { "l" } else { "lu" }
                    )
                    .unwrap(),
                }
                self.floating_read_result(out, result_bits);
            }
            CastOp::FpToSi | CastOp::FpToUi => {
                self.floating_load(out, value, None, source_bits)?;
                let signed = kind == CastOp::FpToSi;
                match self.target {
                    Target::X86_64UnknownNone => {
                        let p = if source_bits == 32 { "ss" } else { "sd" };
                        if !signed && result_bits == 64 {
                            let low = self.label();
                            let done = self.label();
                            self.immediate(
                                out,
                                1,
                                if source_bits == 32 {
                                    0x5f000000
                                } else {
                                    0x43e0000000000000
                                },
                            );
                            writeln!(out, "  {} xmm15, {}\n  ucomi{p} xmm14, xmm15\n  jb {low}\n  sub{p} xmm14, xmm15\n  cvtt{p}2si rax, xmm14\n  bts rax, 63\n  jmp {done}\n{low}:\n  cvtt{p}2si rax, xmm14\n{done}:", if source_bits == 32 { "movd" } else { "movq" }, if source_bits == 32 { "ecx" } else { "rcx" }).unwrap();
                        } else {
                            writeln!(out, "  cvtt{p}2si rax, xmm14").unwrap();
                        }
                    }
                    Target::Aarch64UnknownNone => writeln!(
                        out,
                        "  {} x9, {}16",
                        if signed { "fcvtzs" } else { "fcvtzu" },
                        if source_bits == 32 { "s" } else { "d" }
                    )
                    .unwrap(),
                    Target::Riscv64UnknownNone => writeln!(
                        out,
                        "  fcvt.{}.{} t0, ft0, rtz",
                        if signed { "l" } else { "lu" },
                        if source_bits == 32 { "s" } else { "d" }
                    )
                    .unwrap(),
                }
                self.mask(out, 0, result_bits);
            }
            _ => return Err(error_diagnostic("unexpected floating conversion kind")),
        }
        self.spill_chunk(out, result, 0, 0);
        Ok(())
    }
}
