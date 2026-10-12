// Assembly realization of imported LLVM atomic operations.
//
// The explicit coherent-RAM profile excludes device memory and, for RV64GC
// subword RMW/CAS, promises accessibility of the containing aligned word and
// the execution environment's LR/SC eventuality property for that region.
// Source ordering/scope/weakness/volatility remain in NativeIR. Weak CAS is
// refined to a strong retry loop. No helper library or wider-atomic support
// is implied by this inline implementation.
use std::collections::BTreeMap;
use std::fmt::Write;

use crate::ocore::driver::Target;
use crate::ocore::native_codegen::{constant_type, scalar_bits, Emitter};
use crate::ocore::native_ir::{
    error_diagnostic, AtomicOrdering, AtomicProfile, AtomicRmwOp, Instruction, NativeModule, Operand,
    Operation, Type, TypeId, ValueId,
};
use crate::ocore::Diagnostic;

pub(super) fn audit_instruction(
    module: &NativeModule,
    instruction: &Instruction,
    value_types: &BTreeMap<ValueId, TypeId>,
) -> Result<(), Diagnostic> {
    let operand_type = |operand: &Operand| match operand {
        Operand::Value { id } => value_types[id],
        _ => constant_type(operand).unwrap(),
    };
    let (ty, alignment, scope) = match &instruction.operation {
        Operation::AtomicLoad {
            alignment,
            sync_scope,
            ..
        } => (
            Some(instruction.result.unwrap().ty),
            *alignment,
            *sync_scope,
        ),
        Operation::AtomicStore {
            value,
            alignment,
            sync_scope,
            ..
        } => (Some(operand_type(value)), *alignment, *sync_scope),
        Operation::AtomicRmw {
            kind,
            value,
            alignment,
            sync_scope,
            ..
        } => {
            if matches!(
                kind,
                AtomicRmwOp::Fadd
                    | AtomicRmwOp::Fsub
                    | AtomicRmwOp::Fmax
                    | AtomicRmwOp::Fmin
                    | AtomicRmwOp::Fmaximum
                    | AtomicRmwOp::Fminimum
            ) {
                return Err(error_diagnostic(
                    "floating-point atomic RMW needs a supported floating-point realization",
                ));
            }
            (Some(operand_type(value)), *alignment, *sync_scope)
        }
        Operation::AtomicCompareExchange {
            expected,
            alignment,
            sync_scope,
            ..
        } => (Some(operand_type(expected)), *alignment, *sync_scope),
        Operation::AtomicFence { sync_scope, .. } => (None, 0, *sync_scope),
        _ => return Ok(()),
    };
    if module.target.atomic_profile != Some(AtomicProfile::CoherentRamV1) {
        return Err(error_diagnostic(
            "atomic lowering requires the explicit coherent_ram_v1 execution profile; it does not cover device memory",
        ));
    }
    // These are the two LLVM built-ins, not names inferred from printed IR.
    // A custom scope called `system` is a different source contract.
    let source_scope = module
        .atomic_sync_scopes
        .iter()
        .find(|entry| entry.id == scope)
        .ok_or_else(|| error_diagnostic("atomic synchronization scope is absent"))?;
    if !matches!(
        (source_scope.id, source_scope.name.as_slice()),
        (1, []) | (0, b"singlethread")
    ) {
        return Err(error_diagnostic(
            "custom atomic synchronization scope needs a target-specific realization",
        ));
    }
    let Some(ty) = ty else { return Ok(()) };
    let bits = match module.types[ty] {
        Type::Int { bits: bits @ (8 | 16 | 32 | 64) } => bits,
        Type::Pointer { address_space: 0 } => 64,
        _ => {
            return Err(error_diagnostic(
                "inline atomic lowering supports i8/i16/i32/i64 and integral AS0 ptr64 only; wider/FP/vector atomics need a complete source-owned helper realization",
            ))
        }
    };
    let bytes = u64::from(bits / 8);
    if alignment < bytes {
        return Err(error_diagnostic(format!(
            "under-aligned atomic access (align {alignment}, size {bytes}) needs a complete source-owned helper realization; atomic byte splitting is forbidden"
        )));
    }
    // Natural halfword alignment guarantees that an RV masked access does not
    // straddle its containing word. The profile supplies the RAM footprint.
    Ok(())
}

fn has_acquire(order: AtomicOrdering) -> bool {
    matches!(
        order,
        AtomicOrdering::Acquire
            | AtomicOrdering::AcquireRelease
            | AtomicOrdering::SequentiallyConsistent
    )
}

fn has_release(order: AtomicOrdering) -> bool {
    matches!(
        order,
        AtomicOrdering::Release
            | AtomicOrdering::AcquireRelease
            | AtomicOrdering::SequentiallyConsistent
    )
}

/// LLVM22 permits failure ordering stronger than success. This merged order
/// supplies the hardware load component even on a comparison failure.
fn merged_cas_order(success: AtomicOrdering, failure: AtomicOrdering) -> AtomicOrdering {
    if success == AtomicOrdering::SequentiallyConsistent
        || failure == AtomicOrdering::SequentiallyConsistent
    {
        AtomicOrdering::SequentiallyConsistent
    } else if has_acquire(failure) {
        if has_release(success) {
            AtomicOrdering::AcquireRelease
        } else {
            AtomicOrdering::Acquire
        }
    } else {
        success
    }
}

fn x86_width(bytes: u64) -> (&'static str, &'static str, &'static str) {
    match bytes {
        1 => ("byte", "al", "r8b"),
        2 => ("word", "ax", "r8w"),
        4 => ("dword", "eax", "r8d"),
        8 => ("qword", "rax", "r8"),
        _ => unreachable!("audited atomic width"),
    }
}

impl Emitter<'_> {
    pub(super) fn atomic_instruction(
        &mut self,
        out: &mut String,
        instruction: &Instruction,
    ) -> Result<(), Diagnostic> {
        match &instruction.operation {
            Operation::AtomicLoad {
                pointer, ordering, ..
            } => {
                let result = instruction.result.unwrap();
                let bytes = u64::from(scalar_bits(self.module, result.ty)? / 8);
                self.operand(out, 1, pointer);
                self.atomic_load(out, bytes, *ordering);
                self.spill_leaf(out, result, 0);
            }
            Operation::AtomicStore {
                pointer,
                value,
                ordering,
                ..
            } => {
                self.operand(out, 1, pointer);
                self.operand(out, 0, value);
                self.atomic_store(out, u64::from(self.bits(value) / 8), *ordering);
            }
            Operation::AtomicFence {
                ordering,
                sync_scope,
            } => {
                self.atomic_fence(out, *ordering, *sync_scope);
            }
            Operation::AtomicRmw {
                kind,
                pointer,
                value,
                ordering,
                ..
            } => {
                self.atomic_rmw(out, *kind, pointer, value, *ordering);
                self.spill_leaf(out, instruction.result.unwrap(), 0);
            }
            Operation::AtomicCompareExchange {
                pointer,
                expected,
                replacement,
                weak,
                success_ordering,
                failure_ordering,
                ..
            } => {
                if *weak {
                    out.push_str("  # source weak CAS is refined to a strong retry loop\n");
                }
                self.atomic_cas(
                    out,
                    pointer,
                    expected,
                    replacement,
                    merged_cas_order(*success_ordering, *failure_ordering),
                );
                let result = instruction.result.unwrap();
                // Capture success before spilling old: x86 masking changes
                // flags, and all frame stores use a separate address scratch.
                self.spill_leaf(out, result, 0);
                let success = match self.target {
                    Target::X86_64UnknownNone => "r9",
                    Target::Aarch64UnknownNone => "x15",
                    Target::Riscv64UnknownNone => "a0",
                };
                self.mov(out, self.reg(0), success);
                self.spill_leaf(out, result, 1);
            }
            _ => unreachable!("atomic dispatch"),
        }
        Ok(())
    }

    fn atomic_load(&self, out: &mut String, bytes: u64, ordering: AtomicOrdering) {
        match self.target {
            Target::X86_64UnknownNone => self.load(out, bytes, bytes),
            Target::Aarch64UnknownNone if has_acquire(ordering) => out.push_str(match bytes {
                1 => "  ldarb w9, [x10]\n",
                2 => "  ldarh w9, [x10]\n",
                4 => "  ldar w9, [x10]\n",
                8 => "  ldar x9, [x10]\n",
                _ => unreachable!(),
            }),
            Target::Aarch64UnknownNone => self.load(out, bytes, bytes),
            Target::Riscv64UnknownNone => {
                if ordering == AtomicOrdering::SequentiallyConsistent {
                    out.push_str("  fence rw, rw\n");
                }
                self.load(out, bytes, bytes);
                if has_acquire(ordering) {
                    out.push_str("  fence r, rw\n");
                }
            }
        }
    }

    fn atomic_store(&self, out: &mut String, bytes: u64, ordering: AtomicOrdering) {
        match self.target {
            Target::X86_64UnknownNone if ordering == AtomicOrdering::SequentiallyConsistent => {
                let (width, value, _) = x86_width(bytes);
                writeln!(out, "  xchg {width} ptr [rcx], {value}").unwrap();
            }
            Target::X86_64UnknownNone => self.store(out, bytes, bytes),
            Target::Aarch64UnknownNone if has_release(ordering) => out.push_str(match bytes {
                1 => "  stlrb w9, [x10]\n",
                2 => "  stlrh w9, [x10]\n",
                4 => "  stlr w9, [x10]\n",
                8 => "  stlr x9, [x10]\n",
                _ => unreachable!(),
            }),
            Target::Aarch64UnknownNone => self.store(out, bytes, bytes),
            Target::Riscv64UnknownNone => {
                if has_release(ordering) {
                    out.push_str("  fence rw, w\n");
                }
                self.store(out, bytes, bytes);
            }
        }
    }

    fn atomic_fence(&self, out: &mut String, ordering: AtomicOrdering, scope: u32) {
        if scope == 0 {
            // This emitter never moves source instructions or memory accesses.
            // Keep same-thread (including signal-handler) ordering without
            // claiming synchronization with other threads.
            out.push_str("  # singlethread atomic compiler fence\n");
            return;
        }
        match self.target {
            Target::X86_64UnknownNone => {
                if ordering == AtomicOrdering::SequentiallyConsistent {
                    out.push_str("  mfence\n");
                } else {
                    out.push_str("  # x86 atomic compiler fence\n");
                }
            }
            Target::Aarch64UnknownNone => out.push_str(if ordering == AtomicOrdering::Acquire {
                "  dmb ishld\n"
            } else {
                "  dmb ish\n"
            }),
            Target::Riscv64UnknownNone => out.push_str(match ordering {
                AtomicOrdering::Acquire => "  fence r, rw\n",
                AtomicOrdering::Release => "  fence rw, w\n",
                // Stronger than fence.tso, valid on baseline RV64GC.
                AtomicOrdering::AcquireRelease | AtomicOrdering::SequentiallyConsistent => {
                    "  fence rw, rw\n"
                }
                _ => unreachable!("verified fence ordering"),
            }),
        }
    }

    fn atomic_rmw(
        &mut self,
        out: &mut String,
        kind: AtomicRmwOp,
        pointer: &Operand,
        value: &Operand,
        order: AtomicOrdering,
    ) {
        let bits = self.bits(value);
        self.operand(out, 1, pointer);
        self.operand(out, 0, value);
        match self.target {
            Target::X86_64UnknownNone => {
                out.push_str("  mov rdx, rax\n");
                self.x86_atomic_rmw(out, kind, bits);
            }
            Target::Aarch64UnknownNone => {
                out.push_str("  mov x11, x9\n");
                self.arm_atomic_rmw(out, kind, bits, order);
            }
            Target::Riscv64UnknownNone => {
                out.push_str("  addi t3, t0, 0\n");
                self.rv_atomic_rmw(out, kind, bits, order);
            }
        }
    }

    fn atomic_cas(
        &mut self,
        out: &mut String,
        pointer: &Operand,
        expected: &Operand,
        replacement: &Operand,
        order: AtomicOrdering,
    ) {
        let bits = self.bits(expected);
        self.operand(out, 1, pointer);
        self.operand(out, 0, expected);
        match self.target {
            Target::X86_64UnknownNone => {
                out.push_str("  mov rdx, rax\n");
                self.operand(out, 0, replacement);
                out.push_str("  mov r8, rax\n  mov rax, rdx\n");
                let (width, _, new) = x86_width(u64::from(bits / 8));
                writeln!(
                    out,
                    "  lock cmpxchg {width} ptr [rcx], {new}\n  sete r9b\n  movzx r9, r9b"
                )
                .unwrap();
            }
            Target::Aarch64UnknownNone => {
                out.push_str("  mov x11, x9\n");
                self.operand(out, 0, replacement);
                out.push_str("  mov x12, x9\n");
                self.arm_atomic_cas(out, bits, order);
            }
            Target::Riscv64UnknownNone => {
                out.push_str("  addi t3, t0, 0\n");
                self.operand(out, 0, replacement);
                out.push_str("  addi a1, t0, 0\n");
                self.rv_atomic_cas(out, bits, order);
            }
        }
    }

    fn x86_atomic_rmw(&mut self, out: &mut String, kind: AtomicRmwOp, bits: u16) {
        let bytes = u64::from(bits / 8);
        let (width, old, new) = x86_width(bytes);
        let value = match bytes {
            1 => "dl",
            2 => "dx",
            4 => "edx",
            8 => "rdx",
            _ => unreachable!(),
        };
        self.load(out, bytes, bytes);
        let retry = self.label();
        let merge = self.label();
        writeln!(out, "{retry}:\n  mov r8, rax").unwrap();
        match kind {
            AtomicRmwOp::Xchg => writeln!(out, "  mov {new}, {value}").unwrap(),
            AtomicRmwOp::Add
            | AtomicRmwOp::Sub
            | AtomicRmwOp::And
            | AtomicRmwOp::Or
            | AtomicRmwOp::Xor => {
                let op = match kind {
                    AtomicRmwOp::Add => "add",
                    AtomicRmwOp::Sub => "sub",
                    AtomicRmwOp::And => "and",
                    AtomicRmwOp::Or => "or",
                    _ => "xor",
                };
                writeln!(out, "  {op} {new}, {value}").unwrap();
            }
            AtomicRmwOp::Nand => writeln!(out, "  and {new}, {value}\n  not {new}").unwrap(),
            AtomicRmwOp::Max | AtomicRmwOp::Min | AtomicRmwOp::Umax | AtomicRmwOp::Umin => {
                let keep = match kind {
                    AtomicRmwOp::Max => "jge",
                    AtomicRmwOp::Min => "jle",
                    AtomicRmwOp::Umax => "jae",
                    _ => "jbe",
                };
                writeln!(
                    out,
                    "  cmp {old}, {value}\n  {keep} {merge}\n  mov {new}, {value}"
                )
                .unwrap();
            }
            AtomicRmwOp::UincWrap => {
                writeln!(
                    out,
                    "  inc {new}\n  cmp {old}, {value}\n  jb {merge}\n  xor r8d, r8d"
                )
                .unwrap();
            }
            AtomicRmwOp::UdecWrap => {
                let replace = self.label();
                writeln!(out, "  dec {new}\n  test {old}, {old}\n  jz {replace}\n  cmp {old}, {value}\n  jbe {merge}\n{replace}:\n  mov {new}, {value}").unwrap();
            }
            AtomicRmwOp::UsubCond => {
                writeln!(
                    out,
                    "  cmp {old}, {value}\n  jb {merge}\n  sub {new}, {value}"
                )
                .unwrap();
            }
            AtomicRmwOp::UsubSat => {
                let subtract = self.label();
                writeln!(out, "  cmp {old}, {value}\n  jae {subtract}\n  xor r8d, r8d\n  jmp {merge}\n{subtract}:\n  sub {new}, {value}").unwrap();
            }
            _ => unreachable!("audited integer RMW"),
        }
        // Every operation, including an unchanged candidate, linearizes at a
        // successful locked compare-exchange. Failure refreshes old in rax.
        writeln!(
            out,
            "{merge}:\n  lock cmpxchg {width} ptr [rcx], {new}\n  jne {retry}"
        )
        .unwrap();
    }

    fn arm_exclusive_load(&self, out: &mut String, bits: u16, order: AtomicOrdering) {
        let acquire = has_acquire(order);
        out.push_str(match (bits, acquire) {
            (8, false) => "  ldxrb w9, [x10]\n",
            (8, true) => "  ldaxrb w9, [x10]\n",
            (16, false) => "  ldxrh w9, [x10]\n",
            (16, true) => "  ldaxrh w9, [x10]\n",
            (32, false) => "  ldxr w9, [x10]\n",
            (32, true) => "  ldaxr w9, [x10]\n",
            (64, false) => "  ldxr x9, [x10]\n",
            (64, true) => "  ldaxr x9, [x10]\n",
            _ => unreachable!(),
        });
    }

    fn arm_exclusive_store(&self, out: &mut String, bits: u16, order: AtomicOrdering, cas: bool) {
        let op = match (bits, has_release(order)) {
            (8, false) => "stxrb",
            (8, true) => "stlxrb",
            (16, false) => "stxrh",
            (16, true) => "stlxrh",
            (32 | 64, false) => "stxr",
            (32 | 64, true) => "stlxr",
            _ => unreachable!(),
        };
        let value = match (bits, cas) {
            (64, false) => "x13",
            (64, true) => "x12",
            (_, false) => "w13",
            (_, true) => "w12",
        };
        writeln!(out, "  {op} w14, {value}, [x10]").unwrap();
    }

    fn arm_atomic_rmw(
        &mut self,
        out: &mut String,
        kind: AtomicRmwOp,
        bits: u16,
        order: AtomicOrdering,
    ) {
        let retry = self.label();
        writeln!(out, "{retry}:").unwrap();
        self.arm_exclusive_load(out, bits, order);
        match kind {
            AtomicRmwOp::Xchg => out.push_str("  mov x13, x11\n"),
            AtomicRmwOp::Add | AtomicRmwOp::Sub | AtomicRmwOp::And | AtomicRmwOp::Or | AtomicRmwOp::Xor => {
                let op = match kind { AtomicRmwOp::Add => "add", AtomicRmwOp::Sub => "sub", AtomicRmwOp::And => "and", AtomicRmwOp::Or => "orr", _ => "eor" };
                writeln!(out, "  {op} x13, x9, x11").unwrap();
            }
            AtomicRmwOp::Nand => out.push_str("  and x13, x9, x11\n  mvn x13, x13\n"),
            AtomicRmwOp::Max | AtomicRmwOp::Min | AtomicRmwOp::Umax | AtomicRmwOp::Umin => {
                if matches!(kind, AtomicRmwOp::Max | AtomicRmwOp::Min) && bits < 32 {
                    let extend = if bits == 8 { "sxtb" } else { "sxth" };
                    writeln!(out, "  {extend} w15, w9\n  {extend} w16, w11\n  cmp w15, w16").unwrap();
                } else {
                    out.push_str(if bits == 32 { "  cmp w9, w11\n" } else { "  cmp x9, x11\n" });
                }
                let keep = match kind { AtomicRmwOp::Max => "ge", AtomicRmwOp::Min => "le", AtomicRmwOp::Umax => "hs", _ => "ls" };
                writeln!(out, "  csel x13, x9, x11, {keep}").unwrap();
            }
            AtomicRmwOp::UincWrap => out.push_str("  add x13, x9, #1\n  cmp x9, x11\n  csel x13, x13, xzr, lo\n"),
            AtomicRmwOp::UdecWrap => out.push_str("  sub x13, x9, #1\n  cmp x9, x11\n  csel x13, x11, x13, hi\n  cmp x9, #0\n  csel x13, x11, x13, eq\n"),
            AtomicRmwOp::UsubCond | AtomicRmwOp::UsubSat => {
                out.push_str("  sub x13, x9, x11\n  cmp x9, x11\n");
                let otherwise = if kind == AtomicRmwOp::UsubCond { "x9" } else { "xzr" };
                writeln!(out, "  csel x13, x13, {otherwise}, hs").unwrap();
            }
            _ => unreachable!("audited integer RMW"),
        }
        self.arm_exclusive_store(out, bits, order, false);
        writeln!(out, "  cbnz w14, {retry}").unwrap();
    }

    fn arm_atomic_cas(&mut self, out: &mut String, bits: u16, order: AtomicOrdering) {
        let retry = self.label();
        let failed = self.label();
        let done = self.label();
        writeln!(out, "{retry}:").unwrap();
        self.arm_exclusive_load(out, bits, order);
        out.push_str(if bits == 64 {
            "  cmp x9, x11\n"
        } else {
            "  cmp w9, w11\n"
        });
        writeln!(out, "  b.ne {failed}").unwrap();
        self.arm_exclusive_store(out, bits, order, true);
        writeln!(out, "  cbnz w14, {retry}\n  mov x15, #1\n  b {done}\n{failed}:\n  clrex\n  mov x15, #0\n{done}:").unwrap();
    }

    /// t1=address; t3=operand/expected; a1=CAS replacement. All operands are
    /// already loaded from their frame slots. Reserve t2=lane mask, t4=shift,
    /// t5=whole word, t6=candidate, a0=temporary/status. None are callee-saved.
    fn rv_atomic_prepare(&self, out: &mut String, bits: u16, signed_value: bool) {
        out.push_str("  .option push\n  .option norvc\n");
        if bits < 32 {
            writeln!(
                out,
                "  andi t4, t1, 3\n  slli t4, t4, 3\n  andi t1, t1, -4\n  li t2, {}",
                (1u64 << bits) - 1
            )
            .unwrap();
        }
        if signed_value && bits < 64 {
            writeln!(
                out,
                "  slli t3, t3, {}\n  srai t3, t3, {}",
                64 - bits,
                64 - bits
            )
            .unwrap();
        }
    }

    fn rv_lr(&self, out: &mut String, bits: u16, order: AtomicOrdering) {
        let suffix = if order == AtomicOrdering::SequentiallyConsistent {
            ".aqrl"
        } else if has_acquire(order) {
            ".aq"
        } else {
            ""
        };
        if bits < 32 {
            writeln!(
                out,
                "  lr.w{suffix} t5, (t1)\n  srl t0, t5, t4\n  and t0, t0, t2"
            )
            .unwrap();
        } else if bits == 32 {
            // LR.W sign-extends on RV64. Return and unsigned comparisons use
            // the original i32 bits, not the sign-extended machine register.
            writeln!(
                out,
                "  lr.w{suffix} t0, (t1)\n  slli t0, t0, 32\n  srli t0, t0, 32"
            )
            .unwrap();
        } else {
            writeln!(out, "  lr.d{suffix} t0, (t1)").unwrap();
        }
    }

    fn rv_sc(&self, out: &mut String, bits: u16, order: AtomicOrdering) {
        let suffix = if has_release(order) { ".rl" } else { "" };
        let width = if bits <= 32 { "w" } else { "d" };
        writeln!(out, "  sc.{width}{suffix} a0, t6, (t1)").unwrap();
    }

    fn rv_atomic_merge(&self, out: &mut String) {
        // O ^ (((N ^ L) & K) << S): every retry refreshes O and preserves all
        // neighboring lanes, including arithmetic carry/borrow and NAND bits.
        out.push_str("  xor t6, t6, t0\n  and t6, t6, t2\n  sll t6, t6, t4\n  xor t6, t6, t5\n");
    }

    fn rv_atomic_rmw(
        &mut self,
        out: &mut String,
        kind: AtomicRmwOp,
        bits: u16,
        order: AtomicOrdering,
    ) {
        let signed = matches!(kind, AtomicRmwOp::Max | AtomicRmwOp::Min);
        self.rv_atomic_prepare(out, bits, signed);
        let retry = self.label();
        let merge = self.label();
        writeln!(out, "{retry}:").unwrap();
        self.rv_lr(out, bits, order);
        // Only fixed-width base-I arithmetic and direct forward branches occur
        // between LR and SC. The longest complete retry loop is 14 words.
        match kind {
            AtomicRmwOp::Xchg => out.push_str("  addi t6, t3, 0\n"),
            AtomicRmwOp::Add
            | AtomicRmwOp::Sub
            | AtomicRmwOp::And
            | AtomicRmwOp::Or
            | AtomicRmwOp::Xor => {
                let op = match kind {
                    AtomicRmwOp::Add => "add",
                    AtomicRmwOp::Sub => "sub",
                    AtomicRmwOp::And => "and",
                    AtomicRmwOp::Or => "or",
                    _ => "xor",
                };
                writeln!(out, "  {op} t6, t0, t3").unwrap();
            }
            AtomicRmwOp::Nand => out.push_str("  and t6, t0, t3\n  xori t6, t6, -1\n"),
            AtomicRmwOp::Max | AtomicRmwOp::Min | AtomicRmwOp::Umax | AtomicRmwOp::Umin => {
                out.push_str("  addi t6, t0, 0\n");
                let old = if signed && bits < 64 {
                    writeln!(
                        out,
                        "  slli a0, t0, {}\n  srai a0, a0, {}",
                        64 - bits,
                        64 - bits
                    )
                    .unwrap();
                    "a0"
                } else {
                    "t0"
                };
                let branch = if signed { "bge" } else { "bgeu" };
                if matches!(kind, AtomicRmwOp::Min | AtomicRmwOp::Umin) {
                    writeln!(out, "  {branch} t3, {old}, {merge}").unwrap();
                } else {
                    writeln!(out, "  {branch} {old}, t3, {merge}").unwrap();
                }
                out.push_str("  addi t6, t3, 0\n");
            }
            AtomicRmwOp::UincWrap => {
                writeln!(
                    out,
                    "  addi t6, zero, 0\n  bgeu t0, t3, {merge}\n  addi t6, t0, 1"
                )
                .unwrap();
            }
            AtomicRmwOp::UdecWrap => {
                writeln!(out, "  addi t6, t3, 0\n  beq t0, zero, {merge}\n  bltu t3, t0, {merge}\n  addi t6, t0, -1").unwrap();
            }
            AtomicRmwOp::UsubCond | AtomicRmwOp::UsubSat => {
                let otherwise = if kind == AtomicRmwOp::UsubCond {
                    "t0"
                } else {
                    "zero"
                };
                writeln!(
                    out,
                    "  addi t6, {otherwise}, 0\n  bltu t0, t3, {merge}\n  sub t6, t0, t3"
                )
                .unwrap();
            }
            _ => unreachable!("audited integer RMW"),
        }
        writeln!(out, "{merge}:").unwrap();
        if bits < 32 {
            self.rv_atomic_merge(out);
        }
        self.rv_sc(out, bits, order);
        writeln!(out, "  bne a0, zero, {retry}\n  .option pop").unwrap();
    }

    fn rv_atomic_cas(&mut self, out: &mut String, bits: u16, order: AtomicOrdering) {
        self.rv_atomic_prepare(out, bits, false);
        let retry = self.label();
        let failed = self.label();
        let done = self.label();
        writeln!(out, "{retry}:").unwrap();
        self.rv_lr(out, bits, order);
        writeln!(out, "  bne t0, t3, {failed}\n  addi t6, a1, 0").unwrap();
        if bits < 32 {
            self.rv_atomic_merge(out);
        }
        self.rv_sc(out, bits, order);
        writeln!(out, "  bne a0, zero, {retry}\n  addi a0, zero, 1\n  jal zero, {done}\n{failed}:\n  addi a0, zero, 0\n{done}:\n  .option pop").unwrap();
        // All exits retain t0 as the old source-width value and a0 as the
        // canonical success flag. The post-SC JAL is outside the retry window.
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fmt::Write;

    use super::merged_cas_order;
    use crate::ocore::driver::Target;
    use crate::ocore::native_codegen::emit;
    use crate::ocore::native_ir::{
        AtomicOrdering, AtomicProfile, AtomicSyncScope, NativeModule, Operation, FORMAT,
    };
    use serde_json::{json, Value as Json};

    const INTEGER_RMW_NAMES: [&str; 15] = [
        "xchg",
        "add",
        "sub",
        "and",
        "nand",
        "or",
        "xor",
        "max",
        "min",
        "umax",
        "umin",
        "uinc_wrap",
        "udec_wrap",
        "usub_cond",
        "usub_sat",
    ];

    fn source_value(id: usize, ty: usize) -> Json {
        json!({"id":id,"ty":ty})
    }
    fn value(id: usize) -> Json {
        json!({"kind":"value","id":id})
    }
    fn instruction(result: Option<(usize, usize)>, operation: Json) -> Json {
        json!({"result":result.map(|(id,ty)|source_value(id,ty)),"operation":operation})
    }
    fn function(name: String, param_types: &[usize], instructions: Vec<Json>) -> Json {
        json!({"name":name,"linkage":"external",
            "signature":{"result":0,"params":param_types,"variadic":false,"abi":"c"},
            "params":param_types.iter().enumerate().map(|(id,ty)|source_value(id,*ty)).collect::<Vec<_>>(),
            "entry":0,"blocks":[{"id":0,"instructions":instructions,"terminator":{"op":"return","value":null}}]})
    }
    fn narrowed(instructions: &mut Vec<Json>, id: usize, original: usize, ty: usize) -> Json {
        if ty == 5 {
            return value(original);
        }
        instructions.push(instruction(
            Some((id, ty)),
            json!({"op":"cast","kind":"trunc","value":value(original)}),
        ));
        value(id)
    }
    fn widened(instructions: &mut Vec<Json>, id: usize, original: usize, ty: usize) -> Json {
        if ty == 5 {
            return value(original);
        }
        instructions.push(instruction(
            Some((id, 5)),
            json!({"op":"cast","kind":"z_ext","value":value(original)}),
        ));
        value(id)
    }
    fn record_old(instructions: &mut Vec<Json>, old: usize, ty: usize, destination: usize) {
        let old = widened(instructions, 12, old, ty);
        instructions.push(instruction(None, json!({"op":"store","pointer":value(destination),"value":old,"alignment":8,"volatile":false})));
    }

    /// Full authored NativeIR backend corpus; not an imported compiler witness.
    /// Keep all operations, even cold/unusual integer RMW families.
    fn corpus(triple: &str) -> NativeModule {
        let mut types = vec![
            json!({"kind":"void"}),
            json!({"kind":"pointer","address_space":0}),
            json!({"kind":"int","bits":8}),
            json!({"kind":"int","bits":16}),
            json!({"kind":"int","bits":32}),
            json!({"kind":"int","bits":64}),
            json!({"kind":"int","bits":1}),
        ];
        for ty in 2..=5 {
            types.push(json!({"kind":"struct","fields":[ty,6],"packed":false}));
        }
        let mut functions = Vec::new();
        for (width_index, bits) in [8usize, 16, 32, 64].into_iter().enumerate() {
            let ty = width_index + 2;
            for (kind_index, kind) in INTEGER_RMW_NAMES.into_iter().enumerate() {
                let mut body = Vec::new();
                let operand = narrowed(&mut body, 3, 1, ty);
                body.push(instruction(Some((4,ty)),json!({"op":"atomic_rmw","kind":kind,"pointer":value(0),"value":operand,
                    "alignment":bits/8,"volatile":kind_index%2==0,
                    "ordering":(["monotonic","acquire","release","acq_rel","seq_cst"][kind_index%5]),"sync_scope":1})));
                record_old(&mut body, 4, ty, 2);
                functions.push(function(
                    format!("rmw_{bits}_{kind_index}"),
                    &[1, 5, 1],
                    body,
                ));
            }
            for weak in [false, true] {
                let mut body = Vec::new();
                let expected = narrowed(&mut body, 4, 1, ty);
                let replacement = narrowed(&mut body, 5, 2, ty);
                body.push(instruction(Some((6,7+width_index)),json!({"op":"atomic_compare_exchange","pointer":value(0),
                    "expected":expected,"replacement":replacement,"alignment":bits/8,"volatile":true,"weak":weak,
                    // Deliberately legal LLVM22 failure>success ordering.
                    "success_ordering":if weak{"monotonic"}else{"release"},
                    "failure_ordering":if weak{"seq_cst"}else{"acquire"},"sync_scope":1})));
                body.push(instruction(
                    Some((7, ty)),
                    json!({"op":"extract_value","aggregate":value(6),"indices":[0]}),
                ));
                body.push(instruction(
                    Some((8, 6)),
                    json!({"op":"extract_value","aggregate":value(6),"indices":[1]}),
                ));
                body.push(instruction(
                    Some((9, 5)),
                    json!({"op":"cast","kind":"z_ext","value":value(8)}),
                ));
                body.push(instruction(
                    Some((10, 1)),
                    json!({"op":"gep","base":value(3),"offset":{"kind":"int","ty":5,"bits":"8"},"inbounds":false}),
                ));
                record_old(&mut body, 7, ty, 3);
                body.push(instruction(None,json!({"op":"store","pointer":value(10),"value":value(9),"alignment":8,"volatile":false})));
                functions.push(function(
                    format!("cas_{bits}_{}", usize::from(weak)),
                    &[1, 5, 5, 1],
                    body,
                ));
            }
            for (category, orders) in [
                ("load", ["unordered", "monotonic", "acquire", "seq_cst"]),
                ("store", ["unordered", "monotonic", "release", "seq_cst"]),
            ] {
                for (order_index, order) in orders.into_iter().enumerate() {
                    let mut body = Vec::new();
                    let operand = narrowed(&mut body, 3, 1, ty);
                    body.push(instruction(None,json!({"op":"atomic_store","pointer":value(0),"value":operand,"alignment":bits/8,
                        "volatile":true,"ordering":if category=="store"{order}else{"seq_cst"},"sync_scope":1})));
                    body.push(instruction(Some((4,ty)),json!({"op":"atomic_load","pointer":value(0),"alignment":bits/8,"volatile":true,
                        "ordering":if category=="load"{order}else{"seq_cst"},"sync_scope":1})));
                    record_old(&mut body, 4, ty, 2);
                    functions.push(function(
                        format!("access_{bits}_{category}_{order_index}"),
                        &[1, 5, 1],
                        body,
                    ));
                }
            }
        }
        for scope in [0, 1] {
            for (order_index, order) in ["acquire", "release", "acq_rel", "seq_cst"]
                .into_iter()
                .enumerate()
            {
                functions.push(function(
                    format!("fence_{scope}_{order_index}"),
                    &[],
                    vec![instruction(
                        None,
                        json!({"op":"atomic_fence","ordering":order,"sync_scope":scope}),
                    )],
                ));
            }
        }
        types.push(json!({"kind":"struct","fields":[1,6],"packed":false}));
        functions.push(function("ptr_xchg".into(),&[1,1,1],vec![
            instruction(Some((3,1)),json!({"op":"atomic_rmw","kind":"xchg","pointer":value(0),"value":value(1),"alignment":8,
                "volatile":true,"ordering":"seq_cst","sync_scope":1})),
            instruction(None,json!({"op":"store","pointer":value(2),"value":value(3),"alignment":8,"volatile":false}))]));
        functions.push(function("ptr_access".into(),&[1,1,1],vec![
            instruction(None,json!({"op":"atomic_store","pointer":value(0),"value":value(1),"alignment":8,"volatile":true,"ordering":"release","sync_scope":1})),
            instruction(Some((3,1)),json!({"op":"atomic_load","pointer":value(0),"alignment":8,"volatile":true,"ordering":"acquire","sync_scope":1})),
            instruction(None,json!({"op":"store","pointer":value(2),"value":value(3),"alignment":8,"volatile":false}))]));
        functions.push(function("ptr_cas".into(),&[1,1,1,1],vec![
            instruction(Some((4,11)),json!({"op":"atomic_compare_exchange","pointer":value(0),"expected":value(1),"replacement":value(2),
                "alignment":8,"volatile":true,"weak":false,"success_ordering":"seq_cst","failure_ordering":"seq_cst","sync_scope":1})),
            instruction(Some((5,1)),json!({"op":"extract_value","aggregate":value(4),"indices":[0]})),
            instruction(Some((6,6)),json!({"op":"extract_value","aggregate":value(4),"indices":[1]})),
            instruction(Some((7,5)),json!({"op":"cast","kind":"z_ext","value":value(6)})),
            instruction(Some((8,1)),json!({"op":"gep","base":value(3),"offset":{"kind":"int","ty":5,"bits":"8"},"inbounds":false})),
            instruction(None,json!({"op":"store","pointer":value(3),"value":value(5),"alignment":8,"volatile":false})),
            instruction(None,json!({"op":"store","pointer":value(8),"value":value(7),"alignment":8,"volatile":false}))]));
        serde_json::from_value(json!({"format":FORMAT,"name":"atomic-backend-corpus",
            "target":{"triple":triple,"data_layout":"e-p:64:64-i64:64-n8:16:32:64-S128","pointer_bits":64,"little_endian":true,
                "atomic_profile":"coherent_ram_v1"},"semantics":"llvm_defined_behavior_v1","types":types,"globals":[],
            "functions":functions,"atomic_sync_scopes":[{"id":0,"name":b"singlethread"},{"id":1,"name":[]}],
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"authored backend QA","frontend_version":"1","importer":"unit test",
                "importer_version":"1","source_function_count":111,"source_global_count":0,"refinements":[]}})).unwrap()
    }

    #[test]
    fn all_atomic_families_emit_on_each_isa() {
        for (target, triple) in [
            (Target::X86_64UnknownNone, "x86_64-unknown-linux-gnu"),
            (Target::Aarch64UnknownNone, "aarch64-unknown-linux-gnu"),
            (Target::Riscv64UnknownNone, "riscv64-unknown-linux-gnu"),
        ] {
            let assembly = emit(&corpus(triple), target).unwrap();
            assert_eq!(assembly.matches(".cfi_startproc\n").count(), 111);
            assert!(!assembly.contains("__atomic_"));
            match target {
                Target::X86_64UnknownNone => {
                    assert_eq!(assembly.matches("lock cmpxchg").count(), 70);
                    assert!(assembly.contains("mfence"));
                }
                Target::Aarch64UnknownNone => {
                    assert!(assembly.contains("ldaxrb"));
                    assert!(assembly.contains("stlxrh"));
                    assert!(assembly.contains("clrex"));
                    assert!(assembly.contains("dmb ishld"));
                }
                Target::Riscv64UnknownNone => {
                    assert!(assembly.contains("lr.w.aqrl"));
                    assert!(assembly.contains("lr.d.aq"));
                    assert!(assembly.contains("sc.w.rl"));
                    assert!(assembly.contains("fence r, rw"));
                }
            }
            let mut singlethread = corpus(triple);
            for instruction in singlethread
                .functions
                .iter_mut()
                .flat_map(|function| &mut function.blocks)
                .flat_map(|block| &mut block.instructions)
            {
                let scope = match &mut instruction.operation {
                    Operation::AtomicLoad { sync_scope, .. }
                    | Operation::AtomicStore { sync_scope, .. }
                    | Operation::AtomicFence { sync_scope, .. }
                    | Operation::AtomicRmw { sync_scope, .. }
                    | Operation::AtomicCompareExchange { sync_scope, .. } => sync_scope,
                    _ => continue,
                };
                *scope = 0;
            }
            let assembly = emit(&singlethread, target).unwrap();
            assert_eq!(assembly.matches(".cfi_startproc\n").count(), 111);
        }
    }

    #[test]
    fn rv_exclusive_windows_are_fixed_width_and_constrained() {
        let assembly = emit(
            &corpus("riscv64-unknown-linux-gnu"),
            Target::Riscv64UnknownNone,
        )
        .unwrap();
        let lines = assembly.lines().collect::<Vec<_>>();
        let labels: BTreeMap<_, _> = lines
            .iter()
            .enumerate()
            .filter_map(|(position, line)| {
                line.trim().strip_suffix(':').map(|label| (label, position))
            })
            .collect();
        let mut loops = 0;
        for (start, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("lr.") {
                continue;
            }
            let retry = lines[start - 1].trim().trim_end_matches(':');
            let lr_opcode = line.split_whitespace().next().unwrap();
            let width = lr_opcode.split('.').nth(1).unwrap();
            assert!(matches!(width, "w" | "d"));
            assert!(matches!(
                line.trim().split_once(' ').unwrap().1,
                "t0, (t1)" | "t5, (t1)"
            ));
            let mut opcodes = Vec::new();
            let mut saw_sc = false;
            for (position, current) in lines.iter().enumerate().skip(start) {
                let current = current.trim();
                if current.ends_with(':') {
                    continue;
                }
                let opcode = current.split_whitespace().next().unwrap();
                assert!(
                    matches!(
                        opcode,
                        "srl"
                            | "sll"
                            | "slli"
                            | "srli"
                            | "srai"
                            | "and"
                            | "or"
                            | "xor"
                            | "xori"
                            | "add"
                            | "addi"
                            | "sub"
                            | "beq"
                            | "bne"
                            | "bge"
                            | "bgeu"
                            | "bltu"
                    ) || opcode.starts_with("lr.")
                        || opcode.starts_with("sc."),
                    "invalid constrained-loop instruction: {current}"
                );
                opcodes.push(opcode);
                if opcode.starts_with("sc.") {
                    assert!(!saw_sc);
                    assert_eq!(
                        opcode.split('.').nth(1).unwrap(),
                        width,
                        "LR/SC widths differ"
                    );
                    assert_eq!(
                        current,
                        format!("{opcode} a0, t6, (t1)"),
                        "LR/SC addresses or SC operands differ"
                    );
                    saw_sc = true;
                }
                if saw_sc && opcode == "bne" {
                    assert_eq!(current, format!("bne a0, zero, {retry}"));
                    break;
                }
                if matches!(opcode, "beq" | "bne" | "bge" | "bgeu" | "bltu") {
                    let target = current.rsplit(',').next().unwrap().trim();
                    assert!(
                        labels[target] > position,
                        "backward branch before SC: {current}"
                    );
                } else {
                    let destination = current
                        .split_whitespace()
                        .nth(1)
                        .unwrap()
                        .trim_end_matches(',');
                    assert_ne!(
                        destination, "t1",
                        "exclusive address overwritten inside retry window"
                    );
                }
            }
            assert!(saw_sc);
            assert!(
                opcodes.len() <= 16,
                "{}-instruction exclusive loop",
                opcodes.len()
            );
            assert!(lines[..start]
                .iter()
                .rev()
                .take_while(|line| !line.contains(".option pop"))
                .any(|line| line.contains(".option norvc")));
            loops += 1;
        }
        assert_eq!(loops, 70);
    }

    #[test]
    fn atomic_profile_and_helper_gaps_fail_closed() {
        let mut module = corpus("x86_64-unknown-linux-gnu");
        module.target.atomic_profile = None;
        assert!(emit(&module, Target::X86_64UnknownNone)
            .unwrap_err()
            .message
            .contains("coherent_ram_v1"));
        module.target.atomic_profile = Some(AtomicProfile::CoherentRamV1);
        let instruction = &mut module.functions[50].blocks[0].instructions[1];
        let Operation::AtomicRmw { alignment, .. } = &mut instruction.operation else {
            panic!()
        };
        *alignment = 1; // Valid source i32 atomic, unsupported underaligned realization.
        assert!(emit(&module, Target::X86_64UnknownNone)
            .unwrap_err()
            .message
            .contains("under-aligned atomic"));
        *match &mut module.functions[50].blocks[0].instructions[1].operation {
            Operation::AtomicRmw { alignment, .. } => alignment,
            _ => unreachable!(),
        } = 4;
        module.atomic_sync_scopes.push(AtomicSyncScope {
            id: 8,
            name: b"system".to_vec(),
        });
        let Operation::AtomicRmw { sync_scope, .. } =
            &mut module.functions[50].blocks[0].instructions[1].operation
        else {
            panic!()
        };
        *sync_scope = 8;
        assert!(emit(&module, Target::X86_64UnknownNone)
            .unwrap_err()
            .message
            .contains("custom atomic synchronization scope"));
    }

    #[test]
    fn cas_merges_failure_order_without_obsolete_strength_restriction() {
        assert_eq!(
            merged_cas_order(AtomicOrdering::Release, AtomicOrdering::Acquire),
            AtomicOrdering::AcquireRelease
        );
        assert_eq!(
            merged_cas_order(AtomicOrdering::Monotonic, AtomicOrdering::Acquire),
            AtomicOrdering::Acquire
        );
        assert_eq!(
            merged_cas_order(
                AtomicOrdering::Release,
                AtomicOrdering::SequentiallyConsistent
            ),
            AtomicOrdering::SequentiallyConsistent
        );
        assert_eq!(
            merged_cas_order(AtomicOrdering::AcquireRelease, AtomicOrdering::Monotonic),
            AtomicOrdering::AcquireRelease
        );
    }

    /// Compare the actual x86 object with an independent C model, including
    /// all integer kinds, lane overflow/boundaries, unchanged RMWs and both
    /// CAS outcomes. Neighbor canaries catch accidental wider writes.
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn native_atomic_integer_operations_match_independent_c_oracle() {
        use std::{
            fs,
            process::Command,
            time::{SystemTime, UNIX_EPOCH},
        };
        let directory = std::env::temp_dir().join(format!(
            "ostadix-native-atomics-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::write(
            directory.join("own.s"),
            emit(
                &corpus("x86_64-unknown-linux-gnu"),
                Target::X86_64UnknownNone,
            )
            .unwrap(),
        )
        .unwrap();
        let mut source=String::from("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\ntypedef void(*Rmw)(void*,uint64_t,uint64_t*);\ntypedef void(*Cas)(void*,uint64_t,uint64_t,uint64_t*);\n");
        for bits in [8, 16, 32, 64] {
            for kind in 0..15 {
                writeln!(
                    source,
                    "extern void rmw_{bits}_{kind}(void*,uint64_t,uint64_t*);"
                )
                .unwrap();
            }
            for weak in 0..2 {
                writeln!(
                    source,
                    "extern void cas_{bits}_{weak}(void*,uint64_t,uint64_t,uint64_t*);"
                )
                .unwrap();
            }
            for category in ["load", "store"] {
                for order in 0..4 {
                    writeln!(
                        source,
                        "extern void access_{bits}_{category}_{order}(void*,uint64_t,uint64_t*);"
                    )
                    .unwrap();
                }
            }
        }
        source.push_str("extern void ptr_xchg(void*,void*,void**);\nextern void ptr_access(void*,void*,void**);\nextern void ptr_cas(void*,void*,void*,void*);\n");
        source.push_str("static Rmw rmws[4][15]={\n");
        for bits in [8, 16, 32, 64] {
            source.push('{');
            for kind in 0..15 {
                write!(source, "rmw_{bits}_{kind},").unwrap();
            }
            source.push_str("},\n");
        }
        source.push_str("};\nstatic Cas cases[4][2]={\n");
        for bits in [8, 16, 32, 64] {
            writeln!(source, "{{cas_{bits}_0,cas_{bits}_1}},").unwrap();
        }
        source.push_str("};\nstatic Rmw accessors[4][8]={\n");
        for bits in [8, 16, 32, 64] {
            source.push('{');
            for category in ["load", "store"] {
                for order in 0..4 {
                    write!(source, "access_{bits}_{category}_{order},").unwrap();
                }
            }
            source.push_str("},\n");
        }
        source.push_str(r#"};
typedef unsigned __int128 U128;
typedef __int128 I128;
static uint64_t random_bits(uint64_t *s){*s^=*s<<13;*s^=*s>>7;*s^=*s<<17;return *s;}
static uint64_t next(unsigned kind,uint64_t old,uint64_t v,unsigned bits){
  uint64_t mask=bits==64?UINT64_MAX:(UINT64_C(1)<<bits)-1,high=UINT64_C(1)<<(bits-1);
  I128 so=(I128)old-((old&high)?(I128)((U128)1<<bits):0),sv=(I128)v-((v&high)?(I128)((U128)1<<bits):0);
  switch(kind){case 0:return v;case 1:return(old+v)&mask;case 2:return(old-v)&mask;case 3:return old&v;
    case 4:return~(old&v)&mask;case 5:return old|v;case 6:return old^v;case 7:return so>sv?old:v;
    case 8:return so<sv?old:v;case 9:return old>v?old:v;case 10:return old<v?old:v;
    case 11:return old>=v?0:(old+1)&mask;case 12:return(old==0||old>v)?v:(old-1)&mask;
    case 13:return old>=v?old-v:old;case 14:return old>=v?old-v:0;}return UINT64_MAX;
}
static int neighbors(const unsigned char *before,const unsigned char *after,unsigned offset,unsigned bytes){
  for(unsigned k=0;k<32;k++)if((k<offset||k>=offset+bytes)&&before[k]!=after[k])return 0;return 1;
}
int main(int argc,char **argv){
  int corrupt=argc>1;(void)argv;
  uint64_t state=UINT64_C(0x173face912fea565),checks=0;
  for(unsigned w=0;w<4;w++){
    unsigned bits=8u<<w,bytes=bits/8;uint64_t mask=bits==64?UINT64_MAX:(UINT64_C(1)<<bits)-1,high=UINT64_C(1)<<(bits-1);
    uint64_t corners[]={0,1,mask,mask>>1,high,mask-1,high-1,(high+1)&mask};
    for(unsigned sample=0;sample<320;sample++){
      uint64_t old=(sample<64?corners[sample/8]:random_bits(&state))&mask,v=(sample<64?corners[sample%8]:random_bits(&state))&mask;
      unsigned offset=bytes*(1+sample%(16/bytes));
      for(unsigned kind=0;kind<15;kind++){
        _Alignas(16) unsigned char cell[32],before[32];memset(cell,0xa5,32);memcpy(cell+offset,&old,bytes);memcpy(before,cell,32);
        uint64_t actual=~UINT64_C(0),loaded=0;rmws[w][kind](cell+offset,v,&actual);memcpy(&loaded,cell+offset,bytes);
        uint64_t wanted=next(kind,old,v,bits);if(corrupt&&w==0&&sample==0&&kind==0)wanted^=1;
        if(actual!=old||loaded!=wanted||!neighbors(before,cell,offset,bytes)){
          fprintf(stderr,"RMW width=%u kind=%u sample=%u old=%llu v=%llu actual=%llu memory=%llu expected=%llu\n",bits,kind,sample,
            (unsigned long long)old,(unsigned long long)v,(unsigned long long)actual,(unsigned long long)loaded,(unsigned long long)wanted);return 1;
        }checks++;
      }
      for(unsigned weak=0;weak<2;weak++)for(unsigned success=0;success<2;success++){
        _Alignas(16) unsigned char cell[32],before[32];memset(cell,0x5a,32);memcpy(cell+offset,&old,bytes);memcpy(before,cell,32);
        uint64_t actual[2]={~UINT64_C(0),~UINT64_C(0)},loaded=0,expected=success?old:(old^1);
        cases[w][weak](cell+offset,expected,v,actual);memcpy(&loaded,cell+offset,bytes);
        if(actual[0]!=old||actual[1]!=success||loaded!=(success?v:old)||!neighbors(before,cell,offset,bytes))return 2;checks++;
      }
      for(unsigned order=0;order<8;order++){
        _Alignas(16) unsigned char cell[32],before[32];memset(cell,0x35,32);memcpy(before,cell,32);
        uint64_t actual=~UINT64_C(0),loaded=0;accessors[w][order](cell+offset,v,&actual);memcpy(&loaded,cell+offset,bytes);
        if(actual!=v||loaded!=v||!neighbors(before,cell,offset,bytes))return 3;checks++;
      }
    }
  }
  {
    uint64_t objects[3]={11,23,47};void *cell=&objects[0],*old=0;
    ptr_xchg(&cell,&objects[1],&old);if(old!=&objects[0]||cell!=&objects[1])return 5;checks++;
    ptr_access(&cell,&objects[2],&old);if(old!=&objects[2]||cell!=&objects[2])return 6;checks++;
    struct {void *old;uint64_t success;} result;
    ptr_cas(&cell,&objects[2],&objects[0],&result);if(result.old!=&objects[2]||result.success!=1||cell!=&objects[0])return 7;checks++;
    ptr_cas(&cell,&objects[2],&objects[1],&result);if(result.old!=&objects[0]||result.success!=0||cell!=&objects[0])return 8;checks++;
  }
  printf("%llu exact atomic cases\n",(unsigned long long)checks);return checks==34564?0:4;
}
"#);
        fs::write(directory.join("oracle.c"), source).unwrap();
        let compiler = std::env::var_os("OCORE_TEST_CLANG").unwrap_or_else(|| "clang".into());
        let output = Command::new(compiler)
            .current_dir(&directory)
            .args(["-O2", "oracle.c", "own.s", "-o", "oracle"])
            .output()
            .expect("native atomic QA requires clang");
        fs::write(directory.join("compile.stdout"), &output.stdout).unwrap();
        fs::write(directory.join("compile.stderr"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{}: {}",
            directory.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(directory.join("oracle")).output().unwrap();
        fs::write(directory.join("execution.stdout"), &output.stdout).unwrap();
        fs::write(directory.join("execution.stderr"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{}: {}",
            directory.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "34564 exact atomic cases\n"
        );
        let output = Command::new(directory.join("oracle"))
            .arg("--corrupt-oracle")
            .output()
            .unwrap();
        fs::write(directory.join("corrupt.stdout"), &output.stdout).unwrap();
        fs::write(directory.join("corrupt.stderr"), &output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("RMW width=8 kind=0 sample=0"));
        println!(
            "atomic backend QA: 34564 exact cases; artifacts {}",
            directory.display()
        );
    }
}
