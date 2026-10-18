//! Independent, side-effect-free reference evaluation of imported integer IR.
//!
//! This evaluator shares the verified schema, not machine-code lowering. Values
//! are exact-width bit vectors, including integers wider than a host register.
//! Undef and explicit poison refine to zero; poison flags do not become traps
//! or assumptions. Division by zero and signed division overflow refine to
//! zero. Legal shifts retain their count; an overshift refines to a count ANDed
//! with width - 1. All phi inputs are read before any phi destination changes.
//!
//! Memory, external/indirect calls, globals, and noninteger executable values
//! are rejected across the entire module before execution. This is an oracle
//! for the declared pure subset, not a substitute for native runtime tests.

use std::collections::HashMap;

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, ToPrimitive, Zero};

use super::native_ir::*;
use super::Diagnostic;

type Result<T> = std::result::Result<T, Diagnostic>;

fn fail(message: impl std::fmt::Display) -> Diagnostic {
    error_diagnostic(format!("native reference interpreter: {message}"))
}

/// Evaluate a pure integer definition with no practical implicit step budget.
/// Argument and result values are unsigned encodings of exact bit patterns.
/// A void result is `None`. Use `evaluate_with_step_limit` for a chosen budget.
pub fn evaluate(
    module: &NativeModule,
    function: &str,
    args: &[BigUint],
) -> Result<Option<BigUint>> {
    evaluate_with_step_limit(module, function, args, u64::MAX)
}

/// Evaluate with an explicit budget shared by all calls and loop iterations.
/// Each block entry, instruction (including a phi), and terminator costs one
/// step. Unsupported operations are audited before the budget is consumed.
pub fn evaluate_with_step_limit(
    module: &NativeModule,
    function: &str,
    args: &[BigUint],
    max_steps: u64,
) -> Result<Option<BigUint>> {
    let prepared = Prepared::new(module)?;
    let function_id = *prepared
        .functions
        .get(function)
        .ok_or_else(|| fail(format!("unknown entry function {function:?}")))?;
    let mut frames = vec![prepared.frame(function_id, args.to_vec(), None)?];
    let mut remaining = max_steps;

    // Calls use explicit frames so valid deep recursion does not consume the
    // Rust interpreter's native stack. Every loop edge consumes budget too.
    loop {
        if frames.last().unwrap().entering {
            step(&mut remaining)?;
            let frame = frames.last().unwrap();
            let block = &module.functions[frame.function].blocks[frame.block];
            let mut updates = Vec::new();
            for instruction in &block.instructions {
                let Operation::Phi { incoming } = &instruction.operation else {
                    break;
                };
                step(&mut remaining)?;
                let predecessor = frame
                    .predecessor
                    .ok_or_else(|| fail("entry block unexpectedly requires a phi predecessor"))?;
                let edge = incoming
                    .iter()
                    .find(|edge| edge.block == predecessor)
                    .ok_or_else(|| fail("phi has no value for the executed incoming edge"))?;
                updates.push((
                    instruction.result.unwrap().id,
                    prepared.operand(frame, &edge.value)?,
                ));
            }
            let frame = frames.last_mut().unwrap();
            frame.position = updates.len();
            for (id, value) in updates {
                frame.values.insert(id, value);
            }
            frame.entering = false;
        }

        let action = {
            let frame = frames.last().unwrap();
            let block = &module.functions[frame.function].blocks[frame.block];
            step(&mut remaining)?;
            if let Some(instruction) = block.instructions.get(frame.position) {
                if let Operation::Call { callee, args, .. } = &instruction.operation {
                    let Operand::Symbol { name, .. } = callee else {
                        return Err(fail("indirect call escaped the support audit"));
                    };
                    let args = args
                        .iter()
                        .map(|arg| prepared.operand(frame, arg))
                        .collect::<Result<Vec<_>>>()?;
                    Action::Call {
                        function: prepared.functions[name.as_str()],
                        args,
                        result: instruction.result.map(|result| result.id),
                    }
                } else if matches!(instruction.operation, Operation::Trap {}) {
                    return Err(fail(format!(
                        "executed explicit trap in function {:?}, block {}",
                        module.functions[frame.function].name, block.id
                    )));
                } else if matches!(
                    instruction.operation,
                    Operation::Assume { .. } | Operation::NoAliasScopeDecl { .. }
                ) {
                    Action::NoResult
                } else {
                    Action::Value {
                        id: instruction.result.unwrap().id,
                        value: prepared.instruction(frame, instruction)?,
                    }
                }
            } else {
                match &block.terminator {
                    Terminator::Return { value } => Action::Return(
                        value
                            .as_ref()
                            .map(|value| prepared.operand(frame, value))
                            .transpose()?,
                    ),
                    Terminator::Jump { target } => Action::Jump(*target),
                    Terminator::Branch {
                        condition,
                        on_true,
                        on_false,
                    } => Action::Jump(if prepared.operand(frame, condition)?.is_zero() {
                        *on_false
                    } else {
                        *on_true
                    }),
                    Terminator::Switch {
                        condition, default, ..
                    } => {
                        let condition = prepared.operand(frame, condition)?;
                        Action::Jump(
                            *prepared.switches[frame.function][&block.id]
                                .get(&condition)
                                .unwrap_or(default),
                        )
                    }
                    Terminator::Unreachable => {
                        return Err(fail(format!(
                            "executed unreachable in function {:?}, block {}",
                            module.functions[frame.function].name, block.id
                        )));
                    }
                    Terminator::Invoke { .. } | Terminator::Resume { .. } => {
                        return Err(fail("exception execution is not implemented by the scalar reference interpreter"));
                    }
                }
            }
        };

        match action {
            Action::NoResult => frames.last_mut().unwrap().position += 1,
            Action::Value { id, value } => {
                let frame = frames.last_mut().unwrap();
                frame.values.insert(id, value);
                frame.position += 1;
            }
            Action::Call {
                function,
                args,
                result,
            } => {
                frames.last_mut().unwrap().position += 1;
                frames.push(prepared.frame(function, args, result)?);
            }
            Action::Jump(target) => {
                let frame = frames.last_mut().unwrap();
                frame.predecessor = Some(module.functions[frame.function].blocks[frame.block].id);
                frame.block = prepared.blocks[frame.function][&target];
                frame.position = 0;
                frame.entering = true;
            }
            Action::Return(value) => {
                let finished = frames.pop().unwrap();
                let Some(caller) = frames.last_mut() else {
                    return Ok(value);
                };
                if let Some(id) = finished.caller_result {
                    caller.values.insert(
                        id,
                        value.ok_or_else(|| fail("nonvoid call returned no bits"))?,
                    );
                }
            }
        }
    }
}

fn step(remaining: &mut u64) -> Result<()> {
    if *remaining == 0 {
        Err(fail("explicit execution step limit exhausted"))
    } else {
        *remaining -= 1;
        Ok(())
    }
}

fn integer_constant(bits: &str) -> BigUint {
    let digits = bits.trim_start_matches('0');
    if digits.is_empty() {
        BigUint::zero()
    } else {
        BigUint::parse_bytes(digits.as_bytes(), 10).expect("verified integer constant")
    }
}

enum Action {
    NoResult,
    Value {
        id: ValueId,
        value: BigUint,
    },
    Call {
        function: usize,
        args: Vec<BigUint>,
        result: Option<ValueId>,
    },
    Jump(BlockId),
    Return(Option<BigUint>),
}

struct Frame {
    function: usize,
    block: usize,
    position: usize,
    predecessor: Option<BlockId>,
    entering: bool,
    values: HashMap<ValueId, BigUint>,
    caller_result: Option<ValueId>,
}

struct Prepared<'a> {
    module: &'a NativeModule,
    functions: HashMap<&'a str, usize>,
    blocks: Vec<HashMap<BlockId, usize>>,
    widths: Vec<HashMap<ValueId, u16>>,
    switches: Vec<SwitchDispatch>,
}

type SwitchDispatch = HashMap<BlockId, HashMap<BigUint, BlockId>>;

impl<'a> Prepared<'a> {
    fn new(module: &'a NativeModule) -> Result<Self> {
        super::native_verify::verify(module)?;
        if module
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .any(|instruction| {
                matches!(
                    instruction.operation,
                    Operation::AtomicLoad { .. }
                        | Operation::AtomicStore { .. }
                        | Operation::AtomicFence { .. }
                        | Operation::AtomicRmw { .. }
                        | Operation::AtomicCompareExchange { .. }
                )
            })
        {
            return Err(fail("atomic memory and synchronization execution is not implemented by the scalar reference interpreter"));
        }
        if module.globals.iter().any(|global| global.thread_local)
            || module
                .functions
                .iter()
                .flat_map(|function| &function.blocks)
                .flat_map(|block| &block.instructions)
                .any(|instruction| {
                    matches!(instruction.operation, Operation::ThreadLocalAddress { .. })
                })
        {
            return Err(fail("thread-local storage execution is not implemented by the scalar reference interpreter"));
        }
        if !module.globals.is_empty() {
            return Err(fail("global storage/relocations are not implemented"));
        }
        // Audit even unused declarations and unreachable memory instructions
        // before constructing integer frames. Pointer bits are not a memory
        // model, and lifetime markers are not evidence of memory execution.
        if module.functions.iter().any(|function| {
            function.intrinsic.as_deref().is_some_and(|name| {
                !matches!(name, "llvm.assume" | "llvm.trap" | NOALIAS_SCOPE_DECL)
                    && super::native_verify::integer_minmax_intrinsic(name).is_none()
            }) || function.blocks.iter().any(|block| {
                block.instructions.iter().any(|instruction| {
                    matches!(
                        instruction.operation,
                        Operation::Lifetime { .. }
                            | Operation::MemorySet { .. }
                            | Operation::MemoryCopy { .. }
                            | Operation::Alloca { .. }
                            | Operation::Gep { .. }
                            | Operation::Load { .. }
                            | Operation::Store { .. }
                    )
                })
            })
        }) {
            return Err(fail(
                "memory operations and lifetime markers are not implemented",
            ));
        }
        let mut prepared = Self {
            module,
            functions: HashMap::new(),
            blocks: Vec::new(),
            widths: Vec::new(),
            switches: Vec::new(),
        };
        for (id, function) in module.functions.iter().enumerate() {
            prepared.functions.insert(&function.name, id);
            if function.entry.is_none() && function.intrinsic.is_none() {
                return Err(fail(format!(
                    "external/host function declaration {:?} is not implemented",
                    function.name
                )));
            }
            let metadata_declaration = function.intrinsic.as_deref() == Some(NOALIAS_SCOPE_DECL);
            if !metadata_declaration {
                prepared.signature(&function.signature)?;
            }
            let mut widths = HashMap::new();
            if !metadata_declaration {
                for param in &function.params {
                    widths.insert(param.id, prepared.width(param.ty)?);
                }
            }
            let mut blocks = HashMap::new();
            for (index, block) in function.blocks.iter().enumerate() {
                blocks.insert(block.id, index);
                for instruction in &block.instructions {
                    if let Some(result) = instruction.result {
                        widths.insert(result.id, prepared.width(result.ty)?);
                    }
                }
            }
            prepared.blocks.push(blocks);
            prepared.widths.push(widths);
            prepared.switches.push(HashMap::new());
        }
        for alias in &module.aliases {
            let function = prepared.functions.get(alias.aliasee.as_str()).copied()
                .ok_or_else(|| fail("non-function aliases are not implemented by the scalar reference interpreter"))?;
            prepared.functions.insert(&alias.name, function);
        }
        // The complete inventory is inspected, including unreachable code and
        // unused functions. No execution happens before this audit finishes.
        for (function_id, function) in module.functions.iter().enumerate() {
            for block in &function.blocks {
                for instruction in &block.instructions {
                    match &instruction.operation {
                        Operation::Trap {} | Operation::NoAliasScopeDecl { .. } => {}
                        Operation::Assume { condition } => {
                            prepared.scalar_operand(function_id, condition)?;
                        }
                        Operation::Binary { lhs, rhs, .. }
                        | Operation::IntegerMinMax { lhs, rhs, .. }
                        | Operation::ICmp { lhs, rhs, .. } => {
                            prepared.scalar_operand(function_id, lhs)?;
                            prepared.scalar_operand(function_id, rhs)?;
                        }
                        Operation::Cast { kind, value } => {
                            if !matches!(
                                kind,
                                CastOp::Trunc | CastOp::ZExt | CastOp::SExt | CastOp::Bitcast
                            ) {
                                return Err(fail("pointer casts are not implemented"));
                            }
                            prepared.scalar_operand(function_id, value)?;
                        }
                        Operation::Select {
                            condition,
                            on_true,
                            on_false,
                        } => {
                            for operand in [condition, on_true, on_false] {
                                prepared.scalar_operand(function_id, operand)?;
                            }
                        }
                        Operation::Freeze { value } => {
                            prepared.scalar_operand(function_id, value)?;
                        }
                        Operation::Phi { incoming } => {
                            for edge in incoming {
                                prepared.scalar_operand(function_id, &edge.value)?;
                            }
                        }
                        Operation::Call {
                            callee,
                            signature,
                            args,
                        } => {
                            prepared.signature(signature)?;
                            let Operand::Symbol { name, .. } = callee else {
                                return Err(fail("indirect calls are not implemented"));
                            };
                            if !prepared.functions.contains_key(name.as_str()) {
                                return Err(fail("call target has no reference implementation"));
                            }
                            for arg in args {
                                prepared.scalar_operand(function_id, arg)?;
                            }
                        }
                        Operation::IntegerOverflow { .. }
                        | Operation::ExtractValue { .. }
                        | Operation::InsertValue { .. } => {
                            return Err(fail("aggregate SSA is not implemented by the scalar reference interpreter"));
                        }
                        Operation::LandingPad { .. } | Operation::EhTypeId { .. } => {
                            return Err(fail("exception execution is not implemented by the scalar reference interpreter"));
                        }
                        Operation::Alloca { .. }
                        | Operation::ThreadLocalAddress { .. }
                        | Operation::Gep { .. }
                        | Operation::Load { .. }
                        | Operation::Store { .. }
                        | Operation::Lifetime { .. }
                        | Operation::MemorySet { .. }
                        | Operation::MemoryCopy { .. } => {
                            return Err(fail("memory operations are not implemented"));
                        }
                        Operation::AtomicLoad { .. }
                        | Operation::AtomicStore { .. }
                        | Operation::AtomicFence { .. }
                        | Operation::AtomicRmw { .. }
                        | Operation::AtomicCompareExchange { .. } => {
                            return Err(fail("atomic memory and synchronization execution is not implemented by the scalar reference interpreter"));
                        }
                    }
                }
                match &block.terminator {
                    Terminator::Invoke { .. } | Terminator::Resume { .. } => {
                        return Err(fail("exception execution is not implemented by the scalar reference interpreter"));
                    }
                    Terminator::Return { value: Some(value) } => {
                        prepared.scalar_operand(function_id, value)?;
                    }
                    Terminator::Branch { condition, .. } => {
                        prepared.scalar_operand(function_id, condition)?;
                    }
                    Terminator::Switch {
                        condition, cases, ..
                    } => {
                        prepared.scalar_operand(function_id, condition)?;
                        let mut dispatch = HashMap::new();
                        for case in cases {
                            prepared.scalar_operand(function_id, &case.value)?;
                            let Operand::Int { bits, .. } = &case.value else {
                                return Err(fail("nonconstant switch case escaped verification"));
                            };
                            dispatch.insert(integer_constant(bits), case.target);
                        }
                        prepared.switches[function_id].insert(block.id, dispatch);
                    }
                    _ => {}
                }
            }
        }
        Ok(prepared)
    }

    fn width(&self, ty: TypeId) -> Result<u16> {
        match self.module.types[ty] {
            Type::Int { bits } => Ok(bits),
            _ => Err(fail(format!(
                "executable type {ty} is not an implemented integer bit vector"
            ))),
        }
    }

    fn signature(&self, signature: &Signature) -> Result<()> {
        if signature.return_storage.is_some() {
            return Err(fail("return-storage memory effects are not implemented by the scalar reference interpreter"));
        }
        if signature.abi != "c" || signature.variadic {
            return Err(fail("only fixed scalar C call signatures are implemented"));
        }
        for ty in &signature.params {
            self.width(*ty)?;
        }
        if !matches!(self.module.types[signature.result], Type::Void) {
            self.width(signature.result)?;
        }
        Ok(())
    }

    fn scalar_operand(&self, function: usize, operand: &Operand) -> Result<u16> {
        match operand {
            Operand::Value { id } => Ok(self.widths[function][id]),
            Operand::Int { ty, .. } | Operand::Undef { ty } | Operand::Poison { ty } => {
                self.width(*ty)
            }
            Operand::Aggregate { .. } | Operand::AggregateZero { .. } => Err(fail(
                "aggregate constants are not implemented by the scalar reference interpreter",
            )),
            Operand::Null { .. }
            | Operand::Symbol { .. }
            | Operand::SymbolOffset { .. }
            | Operand::PointerBits { .. } => {
                Err(fail("pointer/symbol scalar values are not implemented"))
            }
        }
    }

    fn frame(
        &self,
        function: usize,
        args: Vec<BigUint>,
        caller_result: Option<ValueId>,
    ) -> Result<Frame> {
        let definition = &self.module.functions[function];
        if definition.entry.is_none() {
            return Err(fail(
                "an intrinsic declaration is not an executable entry point",
            ));
        }
        if args.len() != definition.params.len() {
            return Err(fail(format!(
                "entry/call argument count does not match {:?}",
                definition.name
            )));
        }
        let mut values = HashMap::new();
        for (param, bits) in definition.params.iter().zip(args) {
            let width = self.width(param.ty)?;
            if bits.bits() > u64::from(width) {
                return Err(fail(format!(
                    "argument for value {} exceeds its {width}-bit width",
                    param.id
                )));
            }
            values.insert(param.id, bits);
        }
        Ok(Frame {
            function,
            block: self.blocks[function][&definition.entry.unwrap()],
            position: 0,
            predecessor: None,
            entering: true,
            values,
            caller_result,
        })
    }

    fn operand(&self, frame: &Frame, operand: &Operand) -> Result<BigUint> {
        match operand {
            Operand::Value { id } => frame.values.get(id).cloned().ok_or_else(|| {
                fail(format!(
                    "value {id} is not defined on the executed path in {:?}",
                    self.module.functions[frame.function].name
                ))
            }),
            Operand::Int { bits, .. } => Ok(integer_constant(bits)),
            Operand::Undef { .. } | Operand::Poison { .. } => Ok(BigUint::zero()),
            _ => Err(fail("noninteger operand escaped the support audit")),
        }
    }

    fn instruction(&self, frame: &Frame, instruction: &Instruction) -> Result<BigUint> {
        let width = self.width(instruction.result.unwrap().ty)?;
        let value = match &instruction.operation {
            Operation::Binary { kind, lhs, rhs, .. } => binary(
                *kind,
                width,
                &self.operand(frame, lhs)?,
                &self.operand(frame, rhs)?,
            )
            .ok_or_else(|| fail(format!("integer {kind:?} by zero trapped")))?,
            Operation::IntegerMinMax { kind, lhs, rhs } => {
                // Materialize each source operand once. Reusing an unfrozen
                // undef independently for comparison and selection could
                // violate the min/max bound on the other defined operand.
                let lhs = self.operand(frame, lhs)?;
                let rhs = self.operand(frame, rhs)?;
                let predicate = match kind {
                    IntegerMinMaxKind::Smin => IntPredicate::Slt,
                    IntegerMinMaxKind::Smax => IntPredicate::Sgt,
                    IntegerMinMaxKind::Umin => IntPredicate::Ult,
                    IntegerMinMaxKind::Umax => IntPredicate::Ugt,
                };
                if compare(predicate, width, &lhs, &rhs) {
                    lhs
                } else {
                    rhs
                }
            }
            Operation::ICmp {
                predicate,
                lhs,
                rhs,
            } => {
                let operand_width = self.scalar_operand(frame.function, lhs)?;
                BigUint::from(u8::from(compare(
                    *predicate,
                    operand_width,
                    &self.operand(frame, lhs)?,
                    &self.operand(frame, rhs)?,
                )))
            }
            Operation::Cast { kind, value } => {
                let bits = self.operand(frame, value)?;
                if *kind == CastOp::SExt {
                    encode_signed(
                        &signed(&bits, self.scalar_operand(frame.function, value)?),
                        width,
                    )
                } else {
                    bits
                }
            }
            Operation::Select {
                condition,
                on_true,
                on_false,
            } => self.operand(
                frame,
                if self.operand(frame, condition)?.is_zero() {
                    on_false
                } else {
                    on_true
                },
            )?,
            Operation::Freeze { value } => self.operand(frame, value)?,
            _ => return Err(fail("instruction escaped its audited evaluation path")),
        };
        Ok(value & mask(width))
    }
}

fn mask(width: u16) -> BigUint {
    (BigUint::one() << usize::from(width)) - BigUint::one()
}

fn signed(bits: &BigUint, width: u16) -> BigInt {
    let unsigned = BigInt::from_biguint(Sign::Plus, bits.clone());
    if bits.bit(u64::from(width - 1)) {
        unsigned - (BigInt::one() << usize::from(width))
    } else {
        unsigned
    }
}

fn encode_signed(value: &BigInt, width: u16) -> BigUint {
    let modulus = BigUint::one() << usize::from(width);
    let (sign, bytes) = value.to_bytes_le();
    let magnitude = BigUint::from_bytes_le(&bytes) % &modulus;
    if sign == Sign::Minus && !magnitude.is_zero() {
        modulus - magnitude
    } else {
        magnitude
    }
}

/// One integer binary operation at `width`, or `None` when it traps.
///
/// only division by zero traps, for sdiv, srem, udiv and urem at every
/// width. signed MIN / -1 does not trap: sdiv yields MIN, the wrapped
/// quotient, and srem yields 0. add, sub, mul and shl wrap (nsw and nuw are
/// ignored), and an over-wide shift count is masked.
fn binary(kind: BinaryOp, width: u16, lhs: &BigUint, rhs: &BigUint) -> Option<BigUint> {
    let modulus = BigUint::one() << usize::from(width);
    let bits = match kind {
        BinaryOp::Add => lhs + rhs,
        BinaryOp::Sub => lhs + &modulus - rhs,
        BinaryOp::Mul => lhs * rhs,
        BinaryOp::And => lhs & rhs,
        BinaryOp::Or => lhs | rhs,
        BinaryOp::Xor => lhs ^ rhs,
        BinaryOp::UDiv | BinaryOp::URem => {
            if rhs.is_zero() {
                return None;
            } else if kind == BinaryOp::UDiv {
                lhs / rhs
            } else {
                lhs % rhs
            }
        }
        BinaryOp::SDiv | BinaryOp::SRem => {
            let lhs = signed(lhs, width);
            let rhs = signed(rhs, width);
            let minimum = -(BigInt::one() << usize::from(width - 1));
            if rhs.is_zero() {
                return None;
            } else if lhs == minimum && rhs == -BigInt::one() {
                // the quotient wraps to MIN; the remainder is exactly 0.
                if kind == BinaryOp::SDiv {
                    encode_signed(&minimum, width)
                } else {
                    BigUint::zero()
                }
            } else if kind == BinaryOp::SDiv {
                encode_signed(&(lhs / rhs), width)
            } else {
                encode_signed(&(lhs % rhs), width)
            }
        }
        BinaryOp::Shl | BinaryOp::LShr | BinaryOp::AShr => {
            let count = if rhs < &BigUint::from(width) {
                rhs.to_usize().unwrap()
            } else {
                (rhs & BigUint::from(width - 1)).to_usize().unwrap()
            };
            match kind {
                BinaryOp::Shl => lhs << count,
                BinaryOp::LShr => lhs >> count,
                _ => encode_signed(&(signed(lhs, width) >> count), width),
            }
        }
    };
    Some(bits & (&modulus - BigUint::one()))
}

fn compare(predicate: IntPredicate, width: u16, lhs: &BigUint, rhs: &BigUint) -> bool {
    use std::cmp::Ordering;
    let unsigned = lhs.cmp(rhs);
    let signed = match (lhs.bit(u64::from(width - 1)), rhs.bit(u64::from(width - 1))) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => unsigned,
    };
    match predicate {
        IntPredicate::Eq => unsigned.is_eq(),
        IntPredicate::Ne => !unsigned.is_eq(),
        IntPredicate::Ugt => unsigned.is_gt(),
        IntPredicate::Uge => !unsigned.is_lt(),
        IntPredicate::Ult => unsigned.is_lt(),
        IntPredicate::Ule => !unsigned.is_gt(),
        IntPredicate::Sgt => signed.is_gt(),
        IntPredicate::Sge => !signed.is_lt(),
        IntPredicate::Slt => signed.is_lt(),
        IntPredicate::Sle => !signed.is_gt(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn signature(params: Vec<TypeId>, result: TypeId) -> Signature {
        Signature {
            params,
            result,
            abi: "c".into(),
            variadic: false,
            param_attributes: vec![],
            result_attributes: vec![],
            return_storage: None,
        }
    }

    fn base(width: u16) -> NativeModule {
        NativeModule {
            format: FORMAT.into(),
            name: "integer-reference-tests".into(),
            target: TargetLayout {
                triple: "x86_64-unknown-none-elf".into(),
                abi: None,
                tls_profile: None,
                atomic_profile: None,
                data_layout: "e-p:64:64-i64:64-i128:128".into(),
                pointer_bits: 64,
                little_endian: true,
            },
            semantics: Semantics::LlvmDefinedBehaviorV1,
            types: vec![
                Type::Void,
                Type::Int { bits: 1 },
                Type::Int { bits: width },
                Type::Pointer { address_space: 0 },
            ],
            globals: vec![],
            functions: vec![],
            aliases: vec![],
            comdats: vec![],
            noalias_metadata: NoAliasMetadata::default(),
            atomic_sync_scopes: vec![],
            provenance: Provenance {
                input_sha256: "0".repeat(64),
                frontend: "independent-test".into(),
                frontend_version: "1".into(),
                importer: "independent-test".into(),
                importer_version: "1".into(),
                source_function_count: 0,
                source_global_count: 0,
                source_alias_count: 0,
                referenced_comdat_count: 0,
                noalias_metadata_source: vec![],
                refinements: vec![],
            },
        }
    }

    fn value(id: ValueId) -> Operand {
        Operand::Value { id }
    }

    fn constant(ty: TypeId, bits: impl std::fmt::Display) -> Operand {
        Operand::Int {
            ty,
            bits: bits.to_string(),
        }
    }

    fn result(id: ValueId, ty: TypeId, operation: Operation) -> Instruction {
        Instruction {
            result: Some(Value { id, ty }),
            operation,
        }
    }

    fn function(module: &mut NativeModule, definition: Function) {
        module.functions.push(definition);
        module.provenance.source_function_count += 1;
    }

    fn binary_module(width: u16, kind: BinaryOp) -> NativeModule {
        let mut module = base(width);
        function(
            &mut module,
            Function {
                name: "calculate".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: signature(vec![2, 2], 2),
                params: vec![Value { id: 11, ty: 2 }, Value { id: 22, ty: 2 }],
                entry: Some(9),
                blocks: vec![Block {
                    id: 9,
                    instructions: vec![result(
                        90,
                        2,
                        Operation::Binary {
                            kind,
                            lhs: value(11),
                            rhs: value(22),
                            flags: vec![],
                        },
                    )],
                    terminator: Terminator::Return {
                        value: Some(value(90)),
                    },
                }],
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
            },
        );
        module
    }

    #[test]
    fn unused_aggregate_extraction_is_not_silently_interpreted_as_scalar_support() {
        let mut module = binary_module(64, BinaryOp::Add);
        let aggregate = module.types.len();
        module.types.push(Type::Struct {
            fields: vec![2, 2],
            packed: false,
        });
        module.functions[0].blocks[0].instructions.push(result(
            101,
            2,
            Operation::ExtractValue {
                aggregate: Operand::Aggregate {
                    ty: aggregate,
                    elements: vec![constant(2, 1), constant(2, 2)],
                },
                indices: vec![1],
            },
        ));
        super::super::native_verify::verify(&module).unwrap();
        let error = evaluate(&module, "calculate", &[1u32.into(), 2u32.into()]).unwrap_err();
        assert!(
            error.message.contains("aggregate SSA is not implemented"),
            "{}",
            error.message
        );
    }

    #[test]
    fn explicit_trap_fails_only_when_its_path_executes_and_never_returns_a_value() {
        let mut module = binary_module(8, BinaryOp::Add);
        // The untouched cold path remains in the audited module. Adding a trap
        // does not make a defined safe path fail or erase the following code.
        let calculate = &mut module.functions[0];
        calculate.blocks.insert(
            0,
            Block {
                id: 1,
                instructions: vec![result(
                    33,
                    1,
                    Operation::ICmp {
                        predicate: IntPredicate::Eq,
                        lhs: value(11),
                        rhs: constant(2, 0),
                    },
                )],
                terminator: Terminator::Branch {
                    condition: value(33),
                    on_true: 2,
                    on_false: 9,
                },
            },
        );
        calculate.entry = Some(1);
        calculate.blocks.push(Block {
            id: 2,
            instructions: vec![Instruction {
                result: None,
                operation: Operation::Trap {},
            }],
            // Returning after a call to LLVM's noreturn intrinsic is permitted
            // by LLVM's structural verifier but must not execute here.
            terminator: Terminator::Return {
                value: Some(constant(2, 99)),
            },
        });
        function(
            &mut module,
            Function {
                name: "llvm.trap".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: signature(vec![], 0),
                params: vec![],
                entry: None,
                blocks: vec![],
                managed_method: None,
                intrinsic: Some("llvm.trap".into()),
                exception_handling: None,
            },
        );
        assert_eq!(
            evaluate(
                &module,
                "calculate",
                &[BigUint::from(3_u8), BigUint::from(4_u8)]
            )
            .unwrap(),
            Some(BigUint::from(7_u8))
        );
        let error = evaluate(
            &module,
            "calculate",
            &[BigUint::zero(), BigUint::from(4_u8)],
        )
        .unwrap_err();
        assert!(
            error.message.contains("executed explicit trap"),
            "{}",
            error.message
        );
        assert!(evaluate(&module, "llvm.trap", &[])
            .unwrap_err()
            .message
            .contains("intrinsic"));
    }

    #[test]
    fn integer_alias_entries_and_calls_use_the_original_definition() {
        let mut module = binary_module(8, BinaryOp::Add);
        let signature = module.functions[0].signature.clone();
        let ty = module.types.len();
        module.types.push(Type::Function {
            signature: signature.clone(),
        });
        module.aliases.push(Alias {
            name: "facade".into(),
            ty,
            aliasee: "calculate".into(),
            linkage: "weak".into(),
            visibility: Visibility::Hidden,
        });
        module.provenance.source_alias_count = 1;
        function(
            &mut module,
            Function {
                name: "caller".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: signature.clone(),
                params: vec![Value { id: 0, ty: 2 }, Value { id: 1, ty: 2 }],
                entry: Some(0),
                blocks: vec![Block {
                    id: 0,
                    instructions: vec![result(
                        2,
                        2,
                        Operation::Call {
                            callee: Operand::Symbol {
                                ty: 3,
                                name: "facade".into(),
                            },
                            signature,
                            args: vec![value(0), value(1)],
                        },
                    )],
                    terminator: Terminator::Return {
                        value: Some(value(2)),
                    },
                }],
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
            },
        );
        for entry in ["calculate", "facade", "caller"] {
            for (left, right) in [(0u32, 0u32), (255, 1), (128, 128), (17, 99)] {
                let result = evaluate(&module, entry, &[BigUint::from(left), BigUint::from(right)])
                    .unwrap()
                    .unwrap();
                assert_eq!(result, BigUint::from((left + right) & 255));
            }
        }
    }

    fn calculate(module: &NativeModule, args: &[u64]) -> BigUint {
        evaluate(
            module,
            "calculate",
            &args.iter().copied().map(BigUint::from).collect::<Vec<_>>(),
        )
        .unwrap()
        .unwrap()
    }

    fn switch_module(width: u16) -> NativeModule {
        let mut module = base(width);
        module.types.push(Type::Int { bits: 64 });
        let high = BigUint::one() << (width - 1);
        let mut cases = vec![
            SwitchCase {
                value: constant(2, "0000"),
                target: 20,
            },
            SwitchCase {
                value: constant(2, &high),
                target: 30,
            },
        ];
        if width > 1 {
            cases.push(SwitchCase {
                value: constant(2, (BigUint::one() << width) - BigUint::one()),
                target: 20,
            });
        }
        function(
            &mut module,
            Function {
                name: "calculate".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: signature(vec![2], 4),
                params: vec![Value { id: 11, ty: 2 }],
                entry: Some(9),
                blocks: vec![
                    Block {
                        id: 9,
                        instructions: vec![],
                        terminator: Terminator::Switch {
                            condition: value(11),
                            default: 40,
                            cases,
                        },
                    },
                    Block {
                        id: 20,
                        instructions: vec![],
                        terminator: Terminator::Return {
                            value: Some(constant(4, 10)),
                        },
                    },
                    Block {
                        id: 30,
                        instructions: vec![],
                        terminator: Terminator::Return {
                            value: Some(constant(4, 20)),
                        },
                    },
                    Block {
                        id: 40,
                        instructions: vec![],
                        terminator: Terminator::Return {
                            value: Some(constant(4, 30)),
                        },
                    },
                ],
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
            },
        );
        module
    }

    #[test]
    fn switch_matches_exact_signed_and_unsigned_bit_patterns_at_every_width() {
        for width in [1, 8, 16, 24, 32, 64, 257] {
            let module = switch_module(width);
            let high = BigUint::one() << (width - 1);
            let max = (BigUint::one() << width) - BigUint::one();
            assert_eq!(
                evaluate(&module, "calculate", &[BigUint::zero()]).unwrap(),
                Some(BigUint::from(10_u8))
            );
            assert_eq!(
                evaluate(&module, "calculate", &[high]).unwrap(),
                Some(BigUint::from(20_u8))
            );
            if width > 1 {
                assert_eq!(
                    evaluate(&module, "calculate", &[max]).unwrap(),
                    Some(BigUint::from(10_u8))
                );
                assert_eq!(
                    evaluate(&module, "calculate", &[BigUint::one()]).unwrap(),
                    Some(BigUint::from(30_u8))
                );
            }
        }
        let module = switch_module(8);
        for bits in 0_u64..=255 {
            let expected = match bits {
                0 | 255 => 10_u8,
                128 => 20,
                _ => 30,
            };
            assert_eq!(calculate(&module, &[bits]), BigUint::from(expected));
        }
    }

    #[test]
    fn empty_switch_dispatches_to_default_and_poison_refines_without_trapping() {
        let mut module = switch_module(8);
        let Terminator::Switch { cases, .. } = &mut module.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        cases.clear();
        for bits in [0, 1, 128, 255] {
            assert_eq!(calculate(&module, &[bits]), BigUint::from(30_u8));
        }
        for condition in [Operand::Undef { ty: 2 }, Operand::Poison { ty: 2 }] {
            let mut module = switch_module(8);
            let Terminator::Switch {
                condition: current, ..
            } = &mut module.functions[0].blocks[0].terminator
            else {
                unreachable!()
            };
            *current = condition;
            assert_eq!(calculate(&module, &[73]), BigUint::from(10_u8));
        }
    }

    #[test]
    fn large_switch_retains_last_case_and_all_default_bit_patterns() {
        let mut module = switch_module(32);
        let Terminator::Switch { cases, .. } = &mut module.functions[0].blocks[0].terminator else {
            unreachable!()
        };
        *cases = (0..1922)
            .map(|bits| SwitchCase {
                value: constant(2, bits),
                target: 20,
            })
            .collect();
        for bits in [0, 17, 1920, 1921] {
            assert_eq!(calculate(&module, &[bits]), BigUint::from(10_u8));
        }
        for bits in [1922, 1923, u32::MAX as u64] {
            assert_eq!(calculate(&module, &[bits]), BigUint::from(30_u8));
        }
    }

    #[test]
    fn switch_loop_and_shared_destinations_preserve_parallel_phi_values() {
        let mut module = swapping_phis();
        module.functions[0].blocks[1].terminator = Terminator::Switch {
            condition: value(4),
            default: 40,
            cases: vec![
                SwitchCase {
                    value: constant(1, 0),
                    target: 40,
                },
                SwitchCase {
                    value: constant(1, 1),
                    target: 30,
                },
            ],
        };
        module.functions[0].blocks[2].terminator = Terminator::Switch {
            condition: value(5),
            default: 20,
            cases: vec![
                SwitchCase {
                    value: constant(2, 1),
                    target: 20,
                },
                SwitchCase {
                    value: constant(2, 2),
                    target: 20,
                },
            ],
        };
        for trips in 0..70 {
            let expected = if trips % 2 == 0 { 102_u16 } else { 201_u16 };
            assert_eq!(calculate(&module, &[trips]), BigUint::from(expected));
        }
    }

    #[test]
    fn evaluates_exact_wide_integer_arithmetic() {
        let module = binary_module(257, BinaryOp::Mul);
        let lhs = (BigUint::one() << 200) + BigUint::from(3_u8);
        let rhs = (BigUint::one() << 100) + BigUint::from(5_u8);
        // The 2^300 product is discarded; the cross terms and 15 remain.
        let expected =
            (BigUint::from(5_u8) << 200) + (BigUint::from(3_u8) << 100) + BigUint::from(15_u8);
        assert_eq!(
            evaluate(&module, "calculate", &[lhs, rhs]).unwrap(),
            Some(expected)
        );
        let module = binary_module(129, BinaryOp::Add);
        let maximum = BigUint::parse_bytes(b"680564733841876926926749214863536422911", 10).unwrap();
        assert_eq!(
            evaluate(&module, "calculate", &[maximum, BigUint::one()]).unwrap(),
            Some(BigUint::zero())
        );
    }

    #[test]
    fn signed_division_and_remainder_match_independent_i8_arithmetic() {
        for lhs in 0_u16..256 {
            for rhs in 0_u16..256 {
                let a = i32::from(lhs as u8 as i8);
                let b = i32::from(rhs as u8 as i8);
                let lhs = BigUint::from(lhs);
                let rhs = BigUint::from(rhs);
                if b == 0 {
                    assert_eq!(binary(BinaryOp::SDiv, 8, &lhs, &rhs), None);
                    assert_eq!(binary(BinaryOp::SRem, 8, &lhs, &rhs), None);
                    continue;
                }
                // MIN / -1 wraps to MIN; its remainder is 0.
                let quotient = (a.wrapping_div(b) as i8) as u8;
                let remainder = (a % b) as u8;
                assert_eq!(
                    binary(BinaryOp::SDiv, 8, &lhs, &rhs),
                    Some(BigUint::from(quotient))
                );
                assert_eq!(
                    binary(BinaryOp::SRem, 8, &lhs, &rhs),
                    Some(BigUint::from(remainder))
                );
            }
        }
    }

    #[test]
    fn division_refinements_apply_at_all_widths_including_i1() {
        for width in [1, 8, 16, 24, 32, 64, 129] {
            let minimum = BigUint::one() << usize::from(width - 1);
            let negative_one = mask(width);
            // MIN / -1 does not trap: sdiv gives MIN and srem gives 0. at i1
            // MIN and -1 are the same pattern, so -1 / -1 gives -1.
            for (kind, expected) in [
                (BinaryOp::SDiv, minimum.clone()),
                (BinaryOp::SRem, BigUint::zero()),
            ] {
                let module = binary_module(width, kind);
                assert_eq!(
                    evaluate(
                        &module,
                        "calculate",
                        &[minimum.clone(), negative_one.clone()]
                    )
                    .unwrap(),
                    Some(expected),
                    "width {width} {kind:?}"
                );
            }
            // division by zero traps for every division at every width.
            for kind in [
                BinaryOp::SDiv,
                BinaryOp::SRem,
                BinaryOp::UDiv,
                BinaryOp::URem,
            ] {
                let module = binary_module(width, kind);
                let error = evaluate(&module, "calculate", &[minimum.clone(), BigUint::zero()])
                    .unwrap_err();
                assert!(
                    error.message.contains("by zero trapped"),
                    "width {width} {kind:?}: {}",
                    error.message
                );
            }
        }
    }

    #[test]
    fn legal_nonpower_of_two_shifts_keep_their_count() {
        let module = binary_module(24, BinaryOp::Shl);
        assert_eq!(calculate(&module, &[1, 8]), BigUint::from(256_u16));
        // Overshift 24 refines to 24 & 23 = 16, while legal 8 stays 8.
        assert_eq!(calculate(&module, &[1, 24]), BigUint::from(65536_u32));
        let module = binary_module(24, BinaryOp::AShr);
        assert_eq!(
            calculate(&module, &[0x80_0000, 8]),
            BigUint::from(0xff_8000_u32)
        );
        assert_eq!(
            calculate(&module, &[0x80_0000, 24]),
            BigUint::from(0xff_ff80_u32)
        );
    }

    #[test]
    fn sign_extending_i1_uses_the_sign_bit_instead_of_boolean_value() {
        let mut module = base(64);
        function(
            &mut module,
            Function {
                name: "calculate".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: signature(vec![1], 2),
                params: vec![Value { id: 3, ty: 1 }],
                entry: Some(17),
                blocks: vec![Block {
                    id: 17,
                    instructions: vec![result(
                        8,
                        2,
                        Operation::Cast {
                            kind: CastOp::SExt,
                            value: value(3),
                        },
                    )],
                    terminator: Terminator::Return {
                        value: Some(value(8)),
                    },
                }],
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
            },
        );
        assert_eq!(calculate(&module, &[0]), BigUint::zero());
        assert_eq!(calculate(&module, &[1]), BigUint::from(u64::MAX));
    }

    #[test]
    fn freeze_and_select_refine_poison_without_eager_traps() {
        let mut module = base(8);
        function(
            &mut module,
            Function {
                name: "calculate".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: signature(vec![], 2),
                params: vec![],
                entry: Some(10),
                blocks: vec![Block {
                    id: 10,
                    instructions: vec![
                        result(
                            1,
                            2,
                            Operation::Binary {
                                kind: BinaryOp::SDiv,
                                lhs: constant(2, 128),
                                rhs: constant(2, 255),
                                flags: vec![],
                            },
                        ),
                        result(
                            2,
                            2,
                            Operation::Freeze {
                                value: Operand::Poison { ty: 2 },
                            },
                        ),
                        result(
                            3,
                            2,
                            Operation::Select {
                                condition: constant(1, 1),
                                on_true: constant(2, 73),
                                on_false: value(1),
                            },
                        ),
                        result(
                            4,
                            2,
                            Operation::Binary {
                                kind: BinaryOp::Add,
                                lhs: value(3),
                                rhs: value(2),
                                flags: vec!["nsw".into()],
                            },
                        ),
                    ],
                    terminator: Terminator::Return {
                        value: Some(value(4)),
                    },
                }],
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
            },
        );
        assert_eq!(calculate(&module, &[]), BigUint::from(73_u8));
        let Operation::Freeze { value } =
            &mut module.functions[0].blocks[0].instructions[1].operation
        else {
            unreachable!()
        };
        *value = Operand::Undef { ty: 2 };
        assert_eq!(calculate(&module, &[]), BigUint::from(73_u8));
    }

    fn swapping_phis() -> NativeModule {
        let mut module = base(32);
        function(
            &mut module,
            Function {
                name: "calculate".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: signature(vec![2], 2),
                params: vec![Value { id: 99, ty: 2 }],
                entry: Some(10),
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
                blocks: vec![
                    Block {
                        id: 10,
                        instructions: vec![],
                        terminator: Terminator::Jump { target: 20 },
                    },
                    Block {
                        id: 20,
                        instructions: vec![
                            result(
                                1,
                                2,
                                Operation::Phi {
                                    incoming: vec![
                                        PhiIncoming {
                                            block: 10,
                                            value: constant(2, 1),
                                        },
                                        PhiIncoming {
                                            block: 30,
                                            value: value(2),
                                        },
                                    ],
                                },
                            ),
                            result(
                                2,
                                2,
                                Operation::Phi {
                                    incoming: vec![
                                        PhiIncoming {
                                            block: 10,
                                            value: constant(2, 2),
                                        },
                                        PhiIncoming {
                                            block: 30,
                                            value: value(1),
                                        },
                                    ],
                                },
                            ),
                            result(
                                3,
                                2,
                                Operation::Phi {
                                    incoming: vec![
                                        PhiIncoming {
                                            block: 10,
                                            value: constant(2, 0),
                                        },
                                        PhiIncoming {
                                            block: 30,
                                            value: value(5),
                                        },
                                    ],
                                },
                            ),
                            result(
                                4,
                                1,
                                Operation::ICmp {
                                    predicate: IntPredicate::Ult,
                                    lhs: value(3),
                                    rhs: value(99),
                                },
                            ),
                        ],
                        terminator: Terminator::Branch {
                            condition: value(4),
                            on_true: 30,
                            on_false: 40,
                        },
                    },
                    Block {
                        id: 30,
                        instructions: vec![result(
                            5,
                            2,
                            Operation::Binary {
                                kind: BinaryOp::Add,
                                lhs: value(3),
                                rhs: constant(2, 1),
                                flags: vec![],
                            },
                        )],
                        terminator: Terminator::Jump { target: 20 },
                    },
                    Block {
                        id: 40,
                        instructions: vec![
                            result(
                                6,
                                2,
                                Operation::Binary {
                                    kind: BinaryOp::Mul,
                                    lhs: value(1),
                                    rhs: constant(2, 100),
                                    flags: vec![],
                                },
                            ),
                            result(
                                7,
                                2,
                                Operation::Binary {
                                    kind: BinaryOp::Add,
                                    lhs: value(6),
                                    rhs: value(2),
                                    flags: vec![],
                                },
                            ),
                        ],
                        terminator: Terminator::Return {
                            value: Some(value(7)),
                        },
                    },
                ],
            },
        );
        module
    }

    #[test]
    fn cyclic_phi_assignments_are_simultaneous_on_each_loop_edge() {
        let module = swapping_phis();
        for iterations in 0..20 {
            assert_eq!(
                calculate(&module, &[iterations]),
                BigUint::from(if iterations % 2 == 0 {
                    102_u32
                } else {
                    201_u32
                })
            );
        }
    }

    fn recursion() -> NativeModule {
        let mut module = base(32);
        let sig = signature(vec![2], 2);
        function(
            &mut module,
            Function {
                name: "calculate".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: sig.clone(),
                params: vec![Value { id: 10, ty: 2 }],
                entry: Some(1),
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
                blocks: vec![
                    Block {
                        id: 1,
                        instructions: vec![result(
                            11,
                            1,
                            Operation::ICmp {
                                predicate: IntPredicate::Eq,
                                lhs: value(10),
                                rhs: constant(2, 0),
                            },
                        )],
                        terminator: Terminator::Branch {
                            condition: value(11),
                            on_true: 2,
                            on_false: 3,
                        },
                    },
                    Block {
                        id: 2,
                        instructions: vec![],
                        terminator: Terminator::Return {
                            value: Some(constant(2, 0)),
                        },
                    },
                    Block {
                        id: 3,
                        instructions: vec![
                            result(
                                12,
                                2,
                                Operation::Binary {
                                    kind: BinaryOp::Sub,
                                    lhs: value(10),
                                    rhs: constant(2, 1),
                                    flags: vec![],
                                },
                            ),
                            result(
                                13,
                                2,
                                Operation::Call {
                                    callee: Operand::Symbol {
                                        ty: 3,
                                        name: "calculate".into(),
                                    },
                                    signature: sig,
                                    args: vec![value(12)],
                                },
                            ),
                            result(
                                14,
                                2,
                                Operation::Binary {
                                    kind: BinaryOp::Add,
                                    lhs: value(13),
                                    rhs: constant(2, 1),
                                    flags: vec![],
                                },
                            ),
                        ],
                        terminator: Terminator::Return {
                            value: Some(value(14)),
                        },
                    },
                ],
            },
        );
        module
    }

    #[test]
    fn direct_recursive_calls_use_explicit_interpreter_frames() {
        let module = recursion();
        assert_eq!(calculate(&module, &[4096]), BigUint::from(4096_u32));
        let error = evaluate_with_step_limit(&module, "calculate", &[BigUint::from(4096_u32)], 20)
            .unwrap_err();
        assert!(error.message.contains("step limit"));
    }

    #[test]
    fn void_direct_calls_resume_the_caller_without_inventing_a_result() {
        let mut module = base(8);
        let sig = signature(vec![], 0);
        function(
            &mut module,
            Function {
                name: "noop".into(),
                linkage: "internal".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: sig.clone(),
                params: vec![],
                entry: Some(1),
                blocks: vec![Block {
                    id: 1,
                    instructions: vec![],
                    terminator: Terminator::Return { value: None },
                }],
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
            },
        );
        function(
            &mut module,
            Function {
                name: "calculate".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: signature(vec![], 2),
                params: vec![],
                entry: Some(1),
                blocks: vec![Block {
                    id: 1,
                    instructions: vec![Instruction {
                        result: None,
                        operation: Operation::Call {
                            callee: Operand::Symbol {
                                ty: 3,
                                name: "noop".into(),
                            },
                            signature: sig,
                            args: vec![],
                        },
                    }],
                    terminator: Terminator::Return {
                        value: Some(constant(2, 42)),
                    },
                }],
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
            },
        );
        assert_eq!(calculate(&module, &[]), BigUint::from(42_u8));
        assert_eq!(evaluate(&module, "noop", &[]).unwrap(), None);
    }

    #[test]
    fn explicit_budget_catches_empty_loops_and_executed_unreachable() {
        let mut module = base(8);
        function(
            &mut module,
            Function {
                name: "calculate".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: signature(vec![], 0),
                params: vec![],
                entry: Some(1),
                blocks: vec![
                    Block {
                        id: 1,
                        instructions: vec![],
                        terminator: Terminator::Jump { target: 2 },
                    },
                    Block {
                        id: 2,
                        instructions: vec![],
                        terminator: Terminator::Jump { target: 2 },
                    },
                ],
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
            },
        );
        assert!(evaluate_with_step_limit(&module, "calculate", &[], 10)
            .unwrap_err()
            .message
            .contains("step limit"));
        module.functions[0].blocks[0].terminator = Terminator::Unreachable;
        assert!(evaluate(&module, "calculate", &[])
            .unwrap_err()
            .message
            .contains("executed unreachable"));
    }

    #[test]
    fn assumptions_are_explicit_no_result_refinements_and_declarations_are_not_entries() {
        let mut module = binary_module(8, BinaryOp::Add);
        module.types.push(Type::Int { bits: 1 });
        let boolean = module.types.len() - 1;
        module.functions[0].blocks[0].instructions.insert(
            0,
            Instruction {
                result: None,
                operation: Operation::Assume {
                    condition: constant(boolean, 0),
                },
            },
        );
        function(
            &mut module,
            Function {
                name: "llvm.assume".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: signature(vec![boolean], 0),
                params: vec![Value { id: 0, ty: boolean }],
                entry: None,
                blocks: vec![],
                managed_method: None,
                intrinsic: Some("llvm.assume".into()),
                exception_handling: None,
            },
        );
        assert_eq!(calculate(&module, &[2, 3]), BigUint::from(5_u8));
        assert!(evaluate(&module, "llvm.assume", &[BigUint::zero()])
            .unwrap_err()
            .message
            .contains("not an executable"));
    }

    #[test]
    fn rejects_unsupported_dead_memory_and_host_functions_before_execution() {
        let mut module = binary_module(8, BinaryOp::Add);
        module.functions[0].blocks.push(Block {
            id: 100,
            instructions: vec![result(
                300,
                3,
                Operation::Alloca {
                    size: 8,
                    alignment: 8,
                },
            )],
            terminator: Terminator::Unreachable,
        });
        let error =
            evaluate_with_step_limit(&module, "calculate", &[BigUint::one(), BigUint::one()], 0)
                .unwrap_err();
        assert!(
            error.message.contains("not an implemented integer")
                || error.message.contains("memory operations")
        );
        let mut module = binary_module(8, BinaryOp::Add);
        function(
            &mut module,
            Function {
                name: "unused_host".into(),
                linkage: "external".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: signature(vec![], 0),
                params: vec![],
                entry: None,
                blocks: vec![],
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
            },
        );
        assert!(
            evaluate(&module, "calculate", &[BigUint::one(), BigUint::one()])
                .unwrap_err()
                .message
                .contains("external/host")
        );
        let mut module = binary_module(8, BinaryOp::Add);
        module.globals.push(Global {
            name: "unused_data".into(),
            ty: 2,
            linkage: "internal".into(),
            visibility: Visibility::Default,
            comdat: None,
            alignment: 1,
            constant: false,
            thread_local: false,
            tls_model: None,
            initializer: Some(Initializer {
                bytes: vec![0],
                relocations: vec![],
            }),
        });
        module.provenance.source_global_count = 1;
        assert!(
            evaluate(&module, "calculate", &[BigUint::one(), BigUint::one()])
                .unwrap_err()
                .message
                .contains("global storage")
        );
    }

    #[test]
    fn literal_pointer_bits_reject_before_execution_in_dead_blocks_and_unused_functions() {
        for bits in ["0", "255", "18446744073709551615"] {
            for unused_function in [false, true] {
                let mut module = binary_module(64, BinaryOp::Add);
                let block = Block {
                    id: 100,
                    instructions: vec![result(
                        120,
                        1,
                        Operation::ICmp {
                            predicate: IntPredicate::Eq,
                            lhs: Operand::PointerBits {
                                ty: 3,
                                bits: bits.into(),
                            },
                            rhs: Operand::PointerBits {
                                ty: 3,
                                bits: bits.into(),
                            },
                        },
                    )],
                    terminator: if unused_function {
                        Terminator::Return {
                            value: Some(value(120)),
                        }
                    } else {
                        Terminator::Unreachable
                    },
                };
                if unused_function {
                    function(
                        &mut module,
                        Function {
                            name: "unused_pointer_comparison".into(),
                            linkage: "internal".into(),
                            visibility: Visibility::Default,
                            comdat: None,
                            alignment: 0,
                            signature: signature(vec![], 1),
                            params: vec![],
                            entry: Some(100),
                            blocks: vec![block],
                            managed_method: None,
                            intrinsic: None,
                            exception_handling: None,
                        },
                    );
                } else {
                    module.functions[0].blocks.push(block);
                }
                super::super::native_verify::verify(&module).unwrap();
                let error = evaluate_with_step_limit(
                    &module,
                    "calculate",
                    &[BigUint::one(), BigUint::one()],
                    0,
                )
                .unwrap_err();
                assert!(
                    error.message.contains("pointer/symbol scalar values"),
                    "{}",
                    error.message
                );
                assert!(!error.message.contains("step limit"));
            }
        }
    }

    #[test]
    fn literal_pointer_results_and_casts_cannot_create_an_integer_reference_memory_model() {
        for pointer_result in [false, true] {
            let mut module = binary_module(64, BinaryOp::Add);
            let literal = Operand::PointerBits {
                ty: 3,
                bits: "4096".into(),
            };
            function(
                &mut module,
                Function {
                    name: "unused_literal_address".into(),
                    linkage: "internal".into(),
                    visibility: Visibility::Default,
                    comdat: None,
                    alignment: 0,
                    signature: signature(vec![], if pointer_result { 3 } else { 2 }),
                    params: vec![],
                    entry: Some(100),
                    blocks: vec![Block {
                        id: 100,
                        instructions: if pointer_result {
                            vec![]
                        } else {
                            vec![result(
                                120,
                                2,
                                Operation::Cast {
                                    kind: CastOp::PtrToInt,
                                    value: literal.clone(),
                                },
                            )]
                        },
                        terminator: Terminator::Return {
                            value: Some(if pointer_result { literal } else { value(120) }),
                        },
                    }],
                    managed_method: None,
                    intrinsic: None,
                    exception_handling: None,
                },
            );
            super::super::native_verify::verify(&module).unwrap();
            let error = evaluate_with_step_limit(
                &module,
                "calculate",
                &[BigUint::one(), BigUint::one()],
                0,
            )
            .unwrap_err();
            assert!(
                error.message.contains(if pointer_result {
                    "not an implemented integer"
                } else {
                    "pointer casts"
                }),
                "{}",
                error.message
            );
            assert!(!error.message.contains("step limit"));
        }
        // Verification still comes first: malformed literals cannot be hidden
        // by a support rejection or an execution budget.
        let mut module = binary_module(64, BinaryOp::Add);
        module.functions[0].blocks.push(Block {
            id: 100,
            instructions: vec![result(
                120,
                1,
                Operation::ICmp {
                    predicate: IntPredicate::Eq,
                    lhs: Operand::PointerBits {
                        ty: 3,
                        bits: "18446744073709551616".into(),
                    },
                    rhs: Operand::PointerBits {
                        ty: 3,
                        bits: "0".into(),
                    },
                },
            )],
            terminator: Terminator::Unreachable,
        });
        let error =
            evaluate_with_step_limit(&module, "calculate", &[BigUint::one(), BigUint::one()], 0)
                .unwrap_err();
        assert!(error.message.contains("64-bit address width"));
    }

    #[test]
    fn lifetime_and_memory_intrinsics_reject_before_execution_even_in_dead_code() {
        let operations = [
            Operation::Lifetime {
                pointer: Operand::Poison { ty: 3 },
                end: false,
            },
            Operation::Lifetime {
                pointer: Operand::Poison { ty: 3 },
                end: true,
            },
            Operation::MemorySet {
                destination: Operand::Null { ty: 3 },
                value: constant(4, 165),
                length: constant(2, 0),
                alignment: 1,
                volatile: true,
            },
            Operation::MemoryCopy {
                destination: Operand::Null { ty: 3 },
                source: Operand::Null { ty: 3 },
                length: constant(2, 0),
                destination_alignment: 1,
                source_alignment: 1,
                volatile: true,
                allow_overlap: false,
            },
            Operation::MemoryCopy {
                destination: Operand::Null { ty: 3 },
                source: Operand::Null { ty: 3 },
                length: constant(2, 0),
                destination_alignment: 1,
                source_alignment: 1,
                volatile: false,
                allow_overlap: true,
            },
        ];
        for operation in operations {
            for unused_function in [false, true] {
                let mut module = binary_module(64, BinaryOp::Add);
                module.types.push(Type::Int { bits: 8 });
                let block = Block {
                    id: 100,
                    instructions: vec![Instruction {
                        result: None,
                        operation: operation.clone(),
                    }],
                    terminator: if unused_function {
                        Terminator::Return { value: None }
                    } else {
                        Terminator::Unreachable
                    },
                };
                if unused_function {
                    function(
                        &mut module,
                        Function {
                            name: "unused_memory".into(),
                            linkage: "internal".into(),
                            visibility: Visibility::Default,
                            comdat: None,
                            alignment: 0,
                            signature: signature(vec![], 0),
                            params: vec![],
                            entry: Some(100),
                            blocks: vec![block],
                            managed_method: None,
                            intrinsic: None,
                            exception_handling: None,
                        },
                    );
                } else {
                    module.functions[0].blocks.push(block);
                }
                super::super::native_verify::verify(&module).unwrap();
                let error = evaluate_with_step_limit(
                    &module,
                    "calculate",
                    &[BigUint::from(2_u8), BigUint::from(3_u8)],
                    0,
                )
                .unwrap_err();
                assert!(error
                    .message
                    .contains("memory operations and lifetime markers"));
                assert!(!error.message.contains("step limit"));
            }
        }
    }

    #[test]
    fn unused_memory_builtin_declarations_do_not_create_a_reference_memory_runtime() {
        let profiles: [(&str, &[TypeId]); 8] = [
            ("llvm.lifetime.start.p0", &[3]),
            ("llvm.lifetime.end.p0", &[3]),
            ("llvm.memset.p0.i32", &[3, 4, 5, 1]),
            ("llvm.memset.p0.i64", &[3, 4, 2, 1]),
            ("llvm.memcpy.p0.p0.i32", &[3, 3, 5, 1]),
            ("llvm.memcpy.p0.p0.i64", &[3, 3, 2, 1]),
            ("llvm.memmove.p0.p0.i32", &[3, 3, 5, 1]),
            ("llvm.memmove.p0.p0.i64", &[3, 3, 2, 1]),
        ];
        for (name, params) in profiles {
            let mut module = binary_module(64, BinaryOp::Add);
            module.types.push(Type::Int { bits: 8 });
            module.types.push(Type::Int { bits: 32 });
            function(
                &mut module,
                Function {
                    name: name.into(),
                    linkage: "external".into(),
                    visibility: Visibility::Default,
                    comdat: None,
                    alignment: 0,
                    signature: signature(params.to_vec(), 0),
                    params: params
                        .iter()
                        .enumerate()
                        .map(|(id, ty)| Value { id, ty: *ty })
                        .collect(),
                    entry: None,
                    blocks: vec![],
                    managed_method: None,
                    intrinsic: Some(name.into()),
                    exception_handling: None,
                },
            );
            super::super::native_verify::verify(&module).unwrap();
            let error = evaluate_with_step_limit(
                &module,
                "calculate",
                &[BigUint::from(2_u8), BigUint::from(3_u8)],
                0,
            )
            .unwrap_err();
            assert!(error
                .message
                .contains("memory operations and lifetime markers"));
            assert!(!error.message.contains("step limit"));
        }
    }

    #[test]
    fn rejects_unsupported_indirect_calls_and_noninteger_signatures() {
        let mut module = recursion();
        let Operation::Call { callee, .. } =
            &mut module.functions[0].blocks[2].instructions[1].operation
        else {
            unreachable!()
        };
        *callee = Operand::Null { ty: 3 };
        assert!(evaluate(&module, "calculate", &[BigUint::one()])
            .unwrap_err()
            .message
            .contains("indirect calls"));
        let mut module = binary_module(8, BinaryOp::Add);
        module.types.push(Type::Float { bits: 32 });
        let mut sig = signature(vec![4], 0);
        sig.abi = "c".into();
        function(
            &mut module,
            Function {
                name: "float_noop".into(),
                linkage: "internal".into(),
                visibility: Visibility::Default,
                comdat: None,
                alignment: 0,
                signature: sig,
                params: vec![Value { id: 1, ty: 4 }],
                entry: Some(1),
                blocks: vec![Block {
                    id: 1,
                    instructions: vec![],
                    terminator: Terminator::Return { value: None },
                }],
                managed_method: None,
                intrinsic: None,
                exception_handling: None,
            },
        );
        assert!(
            evaluate(&module, "calculate", &[BigUint::one(), BigUint::one()])
                .unwrap_err()
                .message
                .contains("not an implemented integer")
        );
    }

    #[test]
    fn validates_exact_input_widths_arity_and_module_before_evaluation() {
        let mut module = binary_module(8, BinaryOp::Add);
        assert!(evaluate(&module, "calculate", &[BigUint::one()])
            .unwrap_err()
            .message
            .contains("argument count"));
        assert!(evaluate(
            &module,
            "calculate",
            &[BigUint::from(256_u32), BigUint::zero()]
        )
        .unwrap_err()
        .message
        .contains("exceeds"));
        assert!(evaluate(&module, "missing", &[])
            .unwrap_err()
            .message
            .contains("unknown entry"));
        module.functions[0].blocks[0].instructions[0]
            .result
            .as_mut()
            .unwrap()
            .id = 11;
        assert!(
            evaluate(&module, "calculate", &[BigUint::one(), BigUint::one()])
                .unwrap_err()
                .message
                .contains("duplicate SSA")
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(160))]
        #[test]
        fn bitvector_arithmetic_matches_independent_host_integer_oracle(width in 1_u16..=128,a in any::<u128>(),b in any::<u128>()) {
            let mask=if width==128 {u128::MAX} else {(1_u128 << width)-1};
            let a=a&mask;let b=b&mask;
            for (op,expected) in [
                (BinaryOp::Add,a.wrapping_add(b)&mask),
                (BinaryOp::Sub,a.wrapping_sub(b)&mask),
                (BinaryOp::Mul,a.wrapping_mul(b)&mask),
                (BinaryOp::And,a&b),(BinaryOp::Or,a|b),(BinaryOp::Xor,a^b),
            ] {
                prop_assert_eq!(binary(op,width,&BigUint::from(a),&BigUint::from(b)),Some(BigUint::from(expected)));
            }
            prop_assert_eq!(binary(BinaryOp::UDiv,width,&BigUint::from(a),&BigUint::from(b)),a.checked_div(b).map(BigUint::from));
            prop_assert_eq!(binary(BinaryOp::URem,width,&BigUint::from(a),&BigUint::from(b)),a.checked_rem(b).map(BigUint::from));
            let signed_a=((a << (128-width)) as i128) >> (128-width);
            let signed_b=((b << (128-width)) as i128) >> (128-width);
            let minimum=if width==128 {i128::MIN} else {-(1_i128 << (width-1))};
            // division by zero traps; MIN / -1 wraps to MIN with remainder 0.
            let quotient=(signed_b!=0).then(|| if signed_a==minimum && signed_b == -1 {minimum} else {signed_a.wrapping_div(signed_b)});
            let remainder=(signed_b!=0).then(|| if signed_a==minimum && signed_b == -1 {0} else {signed_a.wrapping_rem(signed_b)});
            prop_assert_eq!(binary(BinaryOp::SDiv,width,&BigUint::from(a),&BigUint::from(b)),quotient.map(|q| BigUint::from((q as u128)&mask)));
            prop_assert_eq!(binary(BinaryOp::SRem,width,&BigUint::from(a),&BigUint::from(b)),remainder.map(|r| BigUint::from((r as u128)&mask)));
            for (predicate,expected) in [
                (IntPredicate::Eq,a==b),(IntPredicate::Ne,a!=b),(IntPredicate::Ugt,a>b),(IntPredicate::Uge,a>=b),
                (IntPredicate::Ult,a<b),(IntPredicate::Ule,a<=b),(IntPredicate::Sgt,signed_a>signed_b),(IntPredicate::Sge,signed_a>=signed_b),
                (IntPredicate::Slt,signed_a<signed_b),(IntPredicate::Sle,signed_a<=signed_b),
            ] {prop_assert_eq!(compare(predicate,width,&BigUint::from(a),&BigUint::from(b)),expected);}
        }
    }
}
