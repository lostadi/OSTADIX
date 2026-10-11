//! Typed SSA MIR for native O-core computation.
//!
//! Every `ValueId` has one defining instruction. Mutable source locals and
//! statics are explicit memory `Place`s; loading from them produces new SSA
//! values. This keeps machine computation separate from orchestration OIR.

use super::ast::{BinaryOp, UnaryOp};
use super::hir::*;
use super::{Diagnostic, Span};

pub type ValueId = usize;
pub type BlockId = usize;

#[derive(Debug, Clone)]
pub struct MirProgram {
    pub functions: Vec<MirFunction>,
    pub statics: Vec<MirStatic>,
}

#[derive(Debug, Clone)]
pub struct MirStatic {
    pub source: StaticId,
}

#[derive(Debug, Clone)]
pub struct MirFunction {
    pub source: FunctionId,
    pub local_types: Vec<TypeId>,
    pub values: Vec<TypeId>,
    pub blocks: Vec<BasicBlock>,
    pub entry: BlockId,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub instructions: Vec<Instruction>,
    pub terminator: Terminator,
}

#[derive(Debug, Clone)]
pub enum Instruction {
    Const {
        dst: ValueId,
        value: u64,
    },
    FunctionAddress {
        dst: ValueId,
        function: FunctionId,
    },
    AddressOf {
        dst: ValueId,
        place: Place,
    },
    Load {
        dst: ValueId,
        place: Place,
        volatile: bool,
    },
    Store {
        place: Place,
        value: ValueId,
        volatile: bool,
    },
    Copy {
        destination: Place,
        source: Place,
        size: u64,
    },
    Unary {
        dst: ValueId,
        op: UnaryOp,
        operand: ValueId,
    },
    Binary {
        dst: ValueId,
        op: BinaryOp,
        lhs: ValueId,
        rhs: ValueId,
    },
    Cast {
        dst: ValueId,
        value: ValueId,
        from: TypeId,
        to: TypeId,
    },
    Call {
        dst: Option<ValueId>,
        function: FunctionId,
        args: Vec<ValueId>,
    },
    CallIndirect {
        dst: Option<ValueId>,
        callee: ValueId,
        args: Vec<ValueId>,
    },
    Intrinsic {
        dst: Option<ValueId>,
        intrinsic: Intrinsic,
        args: Vec<ValueId>,
    },
    Phi {
        dst: ValueId,
        incoming: Vec<(BlockId, ValueId)>,
    },
    Asm {
        template: String,
        operands: Vec<MirAsmOperand>,
        options: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub enum MirAsmOperand {
    In {
        register: String,
        value: ValueId,
    },
    Out {
        register: String,
        target: Place,
    },
    InOut {
        register: String,
        input: ValueId,
        output: Place,
    },
}

#[derive(Debug, Clone)]
pub struct Place {
    pub base: PlaceBase,
    pub projections: Vec<Projection>,
    pub ty: TypeId,
}

#[derive(Debug, Clone)]
pub enum PlaceBase {
    Local(LocalId),
    Static(StaticId),
    Pointer(ValueId),
}

#[derive(Debug, Clone)]
pub enum Projection {
    Field { offset: u64 },
    Index { index: ValueId, element_size: u64 },
}

#[derive(Debug, Clone)]
pub enum Terminator {
    Pending,
    Unreachable,
    Return(Option<ValueId>),
    Jump(BlockId),
    Branch {
        condition: ValueId,
        then_block: BlockId,
        else_block: BlockId,
    },
}

pub fn lower(program: &HirProgram) -> Result<MirProgram, Diagnostic> {
    let mut functions = Vec::new();
    for (source, function) in program.functions.iter().enumerate() {
        if function.body.is_some() {
            functions.push(FunctionBuilder::new(program, source).lower()?);
        }
    }
    Ok(MirProgram {
        functions,
        statics: program
            .statics
            .iter()
            .enumerate()
            .map(|(source, _)| MirStatic { source })
            .collect(),
    })
}

struct FunctionBuilder<'a> {
    program: &'a HirProgram,
    source: FunctionId,
    function: &'a HirFunction,
    local_types: Vec<TypeId>,
    values: Vec<TypeId>,
    blocks: Vec<BasicBlock>,
    current: BlockId,
    loops: Vec<(BlockId, BlockId)>, // break, continue
}

impl<'a> FunctionBuilder<'a> {
    fn new(program: &'a HirProgram, source: FunctionId) -> Self {
        Self {
            program,
            source,
            function: &program.functions[source],
            local_types: program.functions[source]
                .locals
                .iter()
                .map(|local| local.ty)
                .collect(),
            values: Vec::new(),
            blocks: vec![BasicBlock {
                instructions: Vec::new(),
                terminator: Terminator::Pending,
            }],
            current: 0,
            loops: Vec::new(),
        }
    }

    fn lower(mut self) -> Result<MirFunction, Diagnostic> {
        let body = self.function.body.as_ref().unwrap();
        self.lower_block(body)?;
        if !self.terminated(self.current) {
            let void = self.program.types.primitive("void").unwrap();
            if self.function.result == void {
                self.terminate(Terminator::Return(None));
            } else {
                self.terminate(Terminator::Unreachable);
            }
        }
        Ok(MirFunction {
            source: self.source,
            local_types: self.local_types,
            values: self.values,
            blocks: self.blocks,
            entry: 0,
        })
    }

    fn lower_block(&mut self, block: &HirBlock) -> Result<(), Diagnostic> {
        for stmt in &block.stmts {
            if self.terminated(self.current) {
                break;
            }
            self.lower_stmt(stmt)?;
        }
        Ok(())
    }

    fn lower_stmt(&mut self, stmt: &HirStmt) -> Result<(), Diagnostic> {
        match &stmt.kind {
            HirStmtKind::Let { local, init } => {
                let place = Place {
                    base: PlaceBase::Local(*local),
                    projections: Vec::new(),
                    ty: self.function.locals[*local].ty,
                };
                self.lower_initializer(place, init)?;
            }
            HirStmtKind::Expr(expr) => {
                let _ = self.lower_expr(expr)?;
            }
            HirStmtKind::Unsafe(block) => self.lower_block(block)?,
            HirStmtKind::Return(value) => {
                let value = value
                    .as_ref()
                    .map(|value| self.lower_expr(value))
                    .transpose()?;
                if !self.terminated(self.current) {
                    self.terminate(Terminator::Return(value));
                }
            }
            HirStmtKind::If {
                condition,
                then_block,
                else_block,
            } => {
                let condition = self.lower_expr(condition)?;
                if self.terminated(self.current) {
                    return Ok(());
                }
                let then_id = self.new_block();
                let else_id = self.new_block();
                let join_id = self.new_block();
                self.terminate(Terminator::Branch {
                    condition,
                    then_block: then_id,
                    else_block: else_id,
                });

                self.current = then_id;
                self.lower_block(then_block)?;
                if !self.terminated(self.current) {
                    self.terminate(Terminator::Jump(join_id));
                }

                self.current = else_id;
                if let Some(else_block) = else_block {
                    self.lower_block(else_block)?;
                }
                if !self.terminated(self.current) {
                    self.terminate(Terminator::Jump(join_id));
                }
                self.current = join_id;
            }
            HirStmtKind::While { condition, body } => {
                let condition_block = self.new_block();
                self.terminate(Terminator::Jump(condition_block));
                self.current = condition_block;
                let condition = self.lower_expr(condition)?;
                if self.terminated(self.current) {
                    return Ok(());
                }
                let body_block = self.new_block();
                let exit_block = self.new_block();
                self.terminate(Terminator::Branch {
                    condition,
                    then_block: body_block,
                    else_block: exit_block,
                });
                self.loops.push((exit_block, condition_block));
                self.current = body_block;
                self.lower_block(body)?;
                self.loops.pop();
                if !self.terminated(self.current) {
                    self.terminate(Terminator::Jump(condition_block));
                }
                self.current = exit_block;
            }
            HirStmtKind::Loop(body) => {
                let body_block = self.new_block();
                let exit_block = self.new_block();
                self.terminate(Terminator::Jump(body_block));
                self.loops.push((exit_block, body_block));
                self.current = body_block;
                self.lower_block(body)?;
                self.loops.pop();
                if !self.terminated(self.current) {
                    self.terminate(Terminator::Jump(body_block));
                }
                self.current = exit_block;
            }
            HirStmtKind::Break => {
                let (target, _) = self.loops.last().copied().unwrap();
                self.terminate(Terminator::Jump(target));
            }
            HirStmtKind::Continue => {
                let (_, target) = self.loops.last().copied().unwrap();
                self.terminate(Terminator::Jump(target));
            }
        }
        Ok(())
    }

    fn lower_initializer(&mut self, place: Place, expr: &HirExpr) -> Result<(), Diagnostic> {
        if matches!(self.program.types.types[expr.ty], Type::Never) {
            self.lower_expr(expr)?;
            return Ok(());
        }
        match &expr.kind {
            HirExprKind::Struct { struct_id, fields } => {
                let def = &self.program.types.structs[*struct_id];
                for (index, value) in fields {
                    let field = &def.fields[*index];
                    let mut field_place = place.clone();
                    field_place.projections.push(Projection::Field {
                        offset: field.offset,
                    });
                    field_place.ty = field.ty;
                    self.lower_initializer(field_place, value)?;
                    if self.terminated(self.current) {
                        return Ok(());
                    }
                }
            }
            HirExprKind::EnumVariant {
                enum_id,
                variant,
                args,
            } => {
                let def = &self.program.types.enums[*enum_id];
                let tag_ty = match def.tag_size {
                    1 => self.program.types.primitive("u8").unwrap(),
                    2 => self.program.types.primitive("u16").unwrap(),
                    4 => self.program.types.primitive("u32").unwrap(),
                    _ => unreachable!(),
                };
                let mut tag_place = place.clone();
                tag_place.ty = tag_ty;
                let tag = self.const_value(*variant as u64, tag_ty);
                self.emit(Instruction::Store {
                    place: tag_place,
                    value: tag,
                    volatile: false,
                });

                let payload_offset = def.payload_offset;
                let payload_types = def.variants[*variant].payload.clone();
                let mut offset = 0u64;
                for (ty, value) in payload_types.into_iter().zip(args) {
                    let layout = self.program.types.layout(ty);
                    offset = align_up(offset, layout.align);
                    let mut payload_place = place.clone();
                    payload_place.projections.push(Projection::Field {
                        offset: payload_offset + offset,
                    });
                    payload_place.ty = ty;
                    self.lower_initializer(payload_place, value)?;
                    if self.terminated(self.current) {
                        return Ok(());
                    }
                    offset += layout.size;
                }
            }
            HirExprKind::Array(values) => {
                let Type::Array { element, .. } = self.program.types.types[place.ty] else {
                    return Err(self.error(expr.span, "array initializer reached non-array place"));
                };
                let element_size = self.program.types.layout(element).size;
                for (index, value) in values.iter().enumerate() {
                    let index_value = self
                        .const_value(index as u64, self.program.types.primitive("usize").unwrap());
                    let mut element_place = place.clone();
                    element_place.projections.push(Projection::Index {
                        index: index_value,
                        element_size,
                    });
                    element_place.ty = element;
                    self.lower_initializer(element_place, value)?;
                    if self.terminated(self.current) {
                        return Ok(());
                    }
                }
            }
            HirExprKind::ArrayRepeat { value, len } => {
                let Type::Array { element, .. } = self.program.types.types[place.ty] else {
                    return Err(self.error(expr.span, "array repeat reached non-array place"));
                };
                let element_size = self.program.types.layout(element).size;
                // Repeat is a value operation: evaluate its operand once,
                // including for an empty array. Aggregate operands need a
                // private snapshot so later writes cannot change that value.
                let scalar_value;
                let aggregate_value;
                if self.program.types.is_scalar(element) {
                    scalar_value = Some(self.lower_expr(value)?);
                    aggregate_value = None;
                } else {
                    let local = self.local_types.len();
                    self.local_types.push(element);
                    let temporary = Place {
                        base: PlaceBase::Local(local),
                        projections: Vec::new(),
                        ty: element,
                    };
                    self.lower_initializer(temporary.clone(), value)?;
                    scalar_value = None;
                    aggregate_value = Some(temporary);
                }
                if self.terminated(self.current) {
                    return Ok(());
                }
                for index in 0..*len {
                    let mut element_place = place.clone();
                    let offset = index.checked_mul(element_size).ok_or_else(|| {
                        self.error(expr.span, "array repeat element offset overflow")
                    })?;
                    element_place.projections.push(Projection::Field { offset });
                    element_place.ty = element;
                    if let Some(value) = scalar_value {
                        self.emit(Instruction::Store {
                            place: element_place,
                            value,
                            volatile: false,
                        });
                    } else {
                        self.emit(Instruction::Copy {
                            destination: element_place,
                            source: aggregate_value.as_ref().unwrap().clone(),
                            size: element_size,
                        });
                    }
                }
            }
            HirExprKind::Constant(HirConstValue::Bytes(bytes)) => {
                let Type::Array { element, .. } = self.program.types.types[place.ty] else {
                    return Err(self.error(expr.span, "byte string reached non-array place"));
                };
                for (index, byte) in bytes.iter().enumerate() {
                    let index_value = self
                        .const_value(index as u64, self.program.types.primitive("usize").unwrap());
                    let byte_value = self.const_value(*byte as u64, element);
                    let mut element_place = place.clone();
                    element_place.projections.push(Projection::Index {
                        index: index_value,
                        element_size: 1,
                    });
                    element_place.ty = element;
                    self.emit(Instruction::Store {
                        place: element_place,
                        value: byte_value,
                        volatile: false,
                    });
                }
            }
            _ => {
                if !self.program.types.is_scalar(expr.ty) {
                    let source = self.lower_place(expr)?;
                    if self.terminated(self.current) {
                        return Ok(());
                    }
                    self.emit(Instruction::Copy {
                        destination: place,
                        source,
                        size: self.program.types.layout(expr.ty).size,
                    });
                    return Ok(());
                }
                let value = self.lower_expr(expr)?;
                if self.terminated(self.current) {
                    return Ok(());
                }
                self.emit(Instruction::Store {
                    place,
                    value,
                    volatile: false,
                });
            }
        }
        Ok(())
    }

    fn lower_expr(&mut self, expr: &HirExpr) -> Result<ValueId, Diagnostic> {
        match &expr.kind {
            HirExprKind::Constant(HirConstValue::Integer(value)) => {
                Ok(self.const_value(*value, expr.ty))
            }
            HirExprKind::Constant(HirConstValue::Bool(value)) => {
                Ok(self.const_value(u64::from(*value), expr.ty))
            }
            HirExprKind::Constant(HirConstValue::Function(function)) => {
                let dst = self.new_value(expr.ty);
                self.emit(Instruction::FunctionAddress {
                    dst,
                    function: *function,
                });
                Ok(dst)
            }
            HirExprKind::Constant(_) => Err(self.error(
                expr.span,
                "aggregate constant is valid only as an initializer",
            )),
            HirExprKind::Local(_)
            | HirExprKind::Static(_)
            | HirExprKind::Field { .. }
            | HirExprKind::Index { .. } => {
                let place = self.lower_place(expr)?;
                if self.terminated(self.current) {
                    return Ok(self.diverged_value());
                }
                let dst = self.new_value(expr.ty);
                self.emit(Instruction::Load {
                    dst,
                    place,
                    volatile: false,
                });
                Ok(dst)
            }
            HirExprKind::Function(function) => {
                let dst = self.new_value(expr.ty);
                self.emit(Instruction::FunctionAddress {
                    dst,
                    function: *function,
                });
                Ok(dst)
            }
            HirExprKind::EnumVariant { .. }
            | HirExprKind::Array(_)
            | HirExprKind::ArrayRepeat { .. }
            | HirExprKind::Struct { .. } => Err(self.error(
                expr.span,
                "aggregate value must initialize a local or static directly",
            )),
            HirExprKind::Unary { op, operand } => match op {
                UnaryOp::AddressOf { .. } => {
                    let place = self.lower_place(operand)?;
                    if self.terminated(self.current) {
                        return Ok(self.diverged_value());
                    }
                    let dst = self.new_value(expr.ty);
                    self.emit(Instruction::AddressOf { dst, place });
                    Ok(dst)
                }
                UnaryOp::Deref => {
                    let place = self.lower_place(expr)?;
                    if self.terminated(self.current) {
                        return Ok(self.diverged_value());
                    }
                    let dst = self.new_value(expr.ty);
                    self.emit(Instruction::Load {
                        dst,
                        place,
                        volatile: false,
                    });
                    Ok(dst)
                }
                _ => {
                    let operand = self.lower_expr(operand)?;
                    if self.terminated(self.current) {
                        return Ok(operand);
                    }
                    let dst = self.new_value(expr.ty);
                    self.emit(Instruction::Unary {
                        dst,
                        op: *op,
                        operand,
                    });
                    Ok(dst)
                }
            },
            HirExprKind::Binary { op, lhs, rhs }
                if matches!(op, BinaryOp::LogicalAnd | BinaryOp::LogicalOr) =>
            {
                self.lower_short_circuit(*op, lhs, rhs, expr.ty)
            }
            HirExprKind::Binary { op, lhs, rhs } => {
                let lhs = self.lower_expr(lhs)?;
                if self.terminated(self.current) {
                    return Ok(lhs);
                }
                let rhs = self.lower_expr(rhs)?;
                if self.terminated(self.current) {
                    return Ok(rhs);
                }
                let dst = self.new_value(expr.ty);
                self.emit(Instruction::Binary {
                    dst,
                    op: *op,
                    lhs,
                    rhs,
                });
                Ok(dst)
            }
            HirExprKind::Assign { op, target, value } => {
                let place = self.lower_place(target)?;
                if self.terminated(self.current) {
                    return Ok(self.diverged_value());
                }
                if op.is_none() && !self.program.types.is_scalar(target.ty) {
                    let source = self.lower_place(value)?;
                    if self.terminated(self.current) {
                        return Ok(self.diverged_value());
                    }
                    self.emit(Instruction::Copy {
                        destination: place,
                        source,
                        size: self.program.types.layout(target.ty).size,
                    });
                    return Ok(self.const_value(0, expr.ty));
                }
                let value = if let Some(op) = op {
                    let old = self.new_value(target.ty);
                    self.emit(Instruction::Load {
                        dst: old,
                        place: place.clone(),
                        volatile: false,
                    });
                    let rhs = self.lower_expr(value)?;
                    if self.terminated(self.current) {
                        return Ok(rhs);
                    }
                    let combined = self.new_value(target.ty);
                    self.emit(Instruction::Binary {
                        dst: combined,
                        op: *op,
                        lhs: old,
                        rhs,
                    });
                    combined
                } else {
                    self.lower_expr(value)?
                };
                if self.terminated(self.current) {
                    return Ok(value);
                }
                self.emit(Instruction::Store {
                    place,
                    value,
                    volatile: false,
                });
                Ok(self.const_value(0, expr.ty))
            }
            HirExprKind::Call { function, args } => {
                let args = self.lower_arguments(args)?;
                if self.terminated(self.current) {
                    return Ok(self.diverged_value());
                }
                let void = self.program.types.primitive("void").unwrap();
                let never = self.program.types.primitive("never").unwrap();
                let dst = if expr.ty == void || expr.ty == never {
                    None
                } else {
                    Some(self.new_value(expr.ty))
                };
                // `lower_expr` returns a ValueId even for an expression that
                // cannot return. Define its unreachable placeholder before
                // emitting the diverging call so the MIR invariant that every
                // ValueId has exactly one definition remains true.
                let never_value = if expr.ty == never {
                    Some(self.const_value(0, expr.ty))
                } else {
                    None
                };
                self.emit(Instruction::Call {
                    dst,
                    function: *function,
                    args,
                });
                let value = if let Some(dst) = dst {
                    dst
                } else if let Some(never_value) = never_value {
                    never_value
                } else {
                    self.const_value(0, expr.ty)
                };
                if expr.ty == never {
                    self.terminate(Terminator::Unreachable);
                }
                Ok(value)
            }
            HirExprKind::CallIndirect { callee, args } => {
                // Evaluate the target before arguments, matching source order.
                // Its SSA slot remains stable across nested argument calls.
                let callee = self.lower_expr(callee)?;
                if self.terminated(self.current) {
                    return Ok(callee);
                }
                let args = self.lower_arguments(args)?;
                if self.terminated(self.current) {
                    return Ok(self.diverged_value());
                }
                let void = self.program.types.primitive("void").unwrap();
                let never = self.program.types.primitive("never").unwrap();
                let dst = if expr.ty == void || expr.ty == never {
                    None
                } else {
                    Some(self.new_value(expr.ty))
                };
                let never_value = if expr.ty == never {
                    Some(self.const_value(0, expr.ty))
                } else {
                    None
                };
                self.emit(Instruction::CallIndirect { dst, callee, args });
                let value = if let Some(dst) = dst {
                    dst
                } else if let Some(value) = never_value {
                    value
                } else {
                    self.const_value(0, expr.ty)
                };
                if expr.ty == never {
                    self.terminate(Terminator::Unreachable);
                }
                Ok(value)
            }
            HirExprKind::Intrinsic { intrinsic, args } => {
                if *intrinsic == Intrinsic::VolatileLoad {
                    let pointer = self.lower_expr(&args[0])?;
                    if self.terminated(self.current) {
                        return Ok(pointer);
                    }
                    let place = Place {
                        base: PlaceBase::Pointer(pointer),
                        projections: Vec::new(),
                        ty: expr.ty,
                    };
                    let dst = self.new_value(expr.ty);
                    self.emit(Instruction::Load {
                        dst,
                        place,
                        volatile: true,
                    });
                    return Ok(dst);
                }
                if *intrinsic == Intrinsic::VolatileStore {
                    let pointer = self.lower_expr(&args[0])?;
                    if self.terminated(self.current) {
                        return Ok(pointer);
                    }
                    let value = self.lower_expr(&args[1])?;
                    if self.terminated(self.current) {
                        return Ok(value);
                    }
                    self.emit(Instruction::Store {
                        place: Place {
                            base: PlaceBase::Pointer(pointer),
                            projections: Vec::new(),
                            ty: args[1].ty,
                        },
                        value,
                        volatile: true,
                    });
                    return Ok(self.const_value(0, expr.ty));
                }
                let args = self.lower_arguments(args)?;
                if self.terminated(self.current) {
                    return Ok(self.diverged_value());
                }
                let void = self.program.types.primitive("void").unwrap();
                let dst = if expr.ty == void {
                    None
                } else {
                    Some(self.new_value(expr.ty))
                };
                self.emit(Instruction::Intrinsic {
                    dst,
                    intrinsic: *intrinsic,
                    args,
                });
                Ok(dst.unwrap_or_else(|| self.const_value(0, expr.ty)))
            }
            HirExprKind::Cast { value, to } => {
                let from = value.ty;
                let value = self.lower_expr(value)?;
                if self.terminated(self.current) {
                    return Ok(value);
                }
                let dst = self.new_value(*to);
                self.emit(Instruction::Cast {
                    dst,
                    value,
                    from,
                    to: *to,
                });
                Ok(dst)
            }
            HirExprKind::Asm(asm) => {
                let mut operands = Vec::new();
                for operand in &asm.operands {
                    operands.push(match operand {
                        HirAsmOperand::In { register, value } => {
                            let value = self.lower_expr(value)?;
                            if self.terminated(self.current) {
                                return Ok(value);
                            }
                            MirAsmOperand::In {
                                register: register.clone(),
                                value,
                            }
                        }
                        HirAsmOperand::Out { register, target } => {
                            let target = self.lower_place(target)?;
                            if self.terminated(self.current) {
                                return Ok(self.diverged_value());
                            }
                            MirAsmOperand::Out {
                                register: register.clone(),
                                target,
                            }
                        }
                        HirAsmOperand::InOut {
                            register,
                            input,
                            output,
                        } => {
                            let input = self.lower_expr(input)?;
                            if self.terminated(self.current) {
                                return Ok(input);
                            }
                            let output = self.lower_place(output)?;
                            if self.terminated(self.current) {
                                return Ok(self.diverged_value());
                            }
                            MirAsmOperand::InOut {
                                register: register.clone(),
                                input,
                                output,
                            }
                        }
                    });
                }
                self.emit(Instruction::Asm {
                    template: asm.template.clone(),
                    operands,
                    options: asm.options.clone(),
                });
                Ok(self.const_value(0, expr.ty))
            }
        }
    }

    fn lower_short_circuit(
        &mut self,
        op: BinaryOp,
        lhs: &HirExpr,
        rhs: &HirExpr,
        ty: TypeId,
    ) -> Result<ValueId, Diagnostic> {
        let lhs = self.lower_expr(lhs)?;
        if self.terminated(self.current) {
            return Ok(lhs);
        }
        let rhs_block = self.new_block();
        let constant_block = self.new_block();
        let join_block = self.new_block();
        let (then_block, else_block, constant) = if op == BinaryOp::LogicalAnd {
            (rhs_block, constant_block, 0)
        } else {
            (constant_block, rhs_block, 1)
        };
        self.terminate(Terminator::Branch {
            condition: lhs,
            then_block,
            else_block,
        });

        self.current = rhs_block;
        let rhs = self.lower_expr(rhs)?;
        let rhs_predecessor = self.current;
        let rhs_returns = !self.terminated(self.current);
        if rhs_returns {
            self.terminate(Terminator::Jump(join_block));
        }

        self.current = constant_block;
        let constant = self.const_value(constant, ty);
        let constant_predecessor = self.current;
        self.terminate(Terminator::Jump(join_block));

        self.current = join_block;
        let dst = self.new_value(ty);
        let mut incoming = vec![(constant_predecessor, constant)];
        if rhs_returns {
            incoming.insert(0, (rhs_predecessor, rhs));
        }
        self.emit(Instruction::Phi { dst, incoming });
        Ok(dst)
    }

    fn lower_place(&mut self, expr: &HirExpr) -> Result<Place, Diagnostic> {
        match &expr.kind {
            HirExprKind::Local(local) => Ok(Place {
                base: PlaceBase::Local(*local),
                projections: Vec::new(),
                ty: expr.ty,
            }),
            HirExprKind::Static(id) => Ok(Place {
                base: PlaceBase::Static(*id),
                projections: Vec::new(),
                ty: expr.ty,
            }),
            HirExprKind::Unary {
                op: UnaryOp::Deref,
                operand,
            } => Ok(Place {
                base: PlaceBase::Pointer(self.lower_expr(operand)?),
                projections: Vec::new(),
                ty: expr.ty,
            }),
            HirExprKind::Field { base, offset, .. } => {
                let mut place = self.lower_place(base)?;
                if self.terminated(self.current) {
                    return Ok(place);
                }
                place
                    .projections
                    .push(Projection::Field { offset: *offset });
                place.ty = expr.ty;
                Ok(place)
            }
            HirExprKind::Index { base, index } => {
                let element_size = self.program.types.layout(expr.ty).size;
                let mut place = match self.program.types.types[base.ty] {
                    Type::Pointer { .. } => Place {
                        base: PlaceBase::Pointer(self.lower_expr(base)?),
                        projections: Vec::new(),
                        ty: expr.ty,
                    },
                    Type::Array { .. } => self.lower_place(base)?,
                    _ => return Err(self.error(expr.span, "invalid indexed place")),
                };
                if self.terminated(self.current) {
                    return Ok(place);
                }
                let index = self.lower_expr(index)?;
                if self.terminated(self.current) {
                    return Ok(place);
                }
                place.projections.push(Projection::Index {
                    index,
                    element_size,
                });
                place.ty = expr.ty;
                Ok(place)
            }
            _ => Err(self.error(expr.span, "expression is not a MIR place")),
        }
    }

    fn const_value(&mut self, value: u64, ty: TypeId) -> ValueId {
        let dst = self.new_value(ty);
        self.emit(Instruction::Const { dst, value });
        dst
    }

    fn lower_arguments(&mut self, args: &[HirExpr]) -> Result<Vec<ValueId>, Diagnostic> {
        let mut values = Vec::with_capacity(args.len());
        for arg in args {
            values.push(self.lower_expr(arg)?);
            if self.terminated(self.current) {
                break;
            }
        }
        Ok(values)
    }

    fn diverged_value(&self) -> ValueId {
        // A diverging call defines its unreachable placeholder before the
        // call. Propagation must reuse that existing value, never allocate an
        // undefined destination or emit into the terminated block.
        debug_assert!(self.terminated(self.current));
        self.values
            .len()
            .checked_sub(1)
            .expect("diverging expression has a defined placeholder")
    }

    fn new_value(&mut self, ty: TypeId) -> ValueId {
        let id = self.values.len();
        self.values.push(ty);
        id
    }

    fn new_block(&mut self) -> BlockId {
        let id = self.blocks.len();
        self.blocks.push(BasicBlock {
            instructions: Vec::new(),
            terminator: Terminator::Pending,
        });
        id
    }

    fn emit(&mut self, instruction: Instruction) {
        debug_assert!(!self.terminated(self.current));
        self.blocks[self.current].instructions.push(instruction);
    }

    fn terminate(&mut self, terminator: Terminator) {
        self.blocks[self.current].terminator = terminator;
    }

    fn terminated(&self, block: BlockId) -> bool {
        !matches!(self.blocks[block].terminator, Terminator::Pending)
    }

    fn error(&self, span: Span, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            file: self.function.qualified_name.clone(),
            span,
            message: message.into(),
        }
    }
}

impl MirProgram {
    pub fn to_text(&self, hir: &HirProgram) -> String {
        let mut out = String::new();
        out.push_str("; O-core typed SSA MIR\n");
        for function in &self.functions {
            let source = &hir.functions[function.source];
            out.push_str(&format!(
                "fn {} [{}]\n",
                source.qualified_name, source.symbol
            ));
            for (block_id, block) in function.blocks.iter().enumerate() {
                out.push_str(&format!("  bb{block_id}:\n"));
                for instruction in &block.instructions {
                    out.push_str(&format!("    {}\n", format_instruction(instruction)));
                }
                out.push_str(&format!("    {}\n", format_terminator(&block.terminator)));
            }
        }
        out
    }
}

fn format_instruction(instruction: &Instruction) -> String {
    match instruction {
        Instruction::Const { dst, value } => format!("%{dst} = const {value}"),
        Instruction::FunctionAddress { dst, function } => {
            format!("%{dst} = function_address fn{function}")
        }
        Instruction::AddressOf { dst, place } => format!("%{dst} = addr {place:?}"),
        Instruction::Load {
            dst,
            place,
            volatile,
        } => format!(
            "%{dst} = {}load {place:?}",
            if *volatile { "volatile " } else { "" }
        ),
        Instruction::Store {
            place,
            value,
            volatile,
        } => format!(
            "{}store %{value}, {place:?}",
            if *volatile { "volatile " } else { "" }
        ),
        Instruction::Copy {
            destination,
            source,
            size,
        } => format!("copy {size} bytes {source:?} -> {destination:?}"),
        Instruction::Unary { dst, op, operand } => format!("%{dst} = {op:?} %{operand}"),
        Instruction::Binary { dst, op, lhs, rhs } => format!("%{dst} = {op:?} %{lhs}, %{rhs}"),
        Instruction::Cast { dst, value, to, .. } => format!("%{dst} = cast %{value} to t{to}"),
        Instruction::Call {
            dst,
            function,
            args,
        } => format!(
            "{}call fn{function}({})",
            dst.map(|d| format!("%{d} = ")).unwrap_or_default(),
            args.iter()
                .map(|a| format!("%{a}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Instruction::CallIndirect { dst, callee, args } => format!(
            "{}call_indirect %{callee}({})",
            dst.map(|d| format!("%{d} = ")).unwrap_or_default(),
            args.iter()
                .map(|a| format!("%{a}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Instruction::Intrinsic {
            dst,
            intrinsic,
            args,
        } => format!(
            "{}intrinsic {intrinsic:?}({})",
            dst.map(|d| format!("%{d} = ")).unwrap_or_default(),
            args.iter()
                .map(|a| format!("%{a}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Instruction::Phi { dst, incoming } => format!("%{dst} = phi {incoming:?}"),
        Instruction::Asm { template, .. } => format!("asm {template:?}"),
    }
}

fn format_terminator(terminator: &Terminator) -> String {
    match terminator {
        Terminator::Pending => "<missing terminator>".into(),
        Terminator::Unreachable => "unreachable".into(),
        Terminator::Return(None) => "return".into(),
        Terminator::Return(Some(value)) => format!("return %{value}"),
        Terminator::Jump(block) => format!("jump bb{block}"),
        Terminator::Branch {
            condition,
            then_block,
            else_block,
        } => format!("branch %{condition}, bb{then_block}, bb{else_block}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ocore::{codegen, parser, typeck};

    #[test]
    fn lowering_produces_ssa_and_control_flow() {
        let ast = parser::parse(
            "test.oc",
            r#"
module mir;
fn max(a: u64, b: u64) -> u64 {
    if a > b { return a; } else { return b; }
}
"#,
        )
        .unwrap();
        let hir = typeck::check(&[("test.oc".into(), ast)]).unwrap();
        let mir = lower(&hir).unwrap();
        assert_eq!(mir.functions.len(), 1);
        assert!(mir.functions[0].blocks.len() >= 4);
        let text = mir.to_text(&hir);
        assert!(text.contains("branch"));
        assert!(text.contains("return"));
    }

    #[test]
    fn lowers_extern_never_call_as_diverging_statement() {
        let ast = parser::parse(
            "test.oc",
            r#"
module mir;
extern "sysv64" fn enter_user() -> never;
fn boot() -> never {
    enter_user();
}
"#,
        )
        .unwrap();
        let hir = typeck::check(&[("test.oc".into(), ast)]).unwrap();
        let mir = lower(&hir).unwrap();

        assert_eq!(mir.functions.len(), 1);
        assert!(matches!(
            mir.functions[0].blocks[0].instructions.as_slice(),
            [
                Instruction::Const { .. },
                Instruction::Call { dst: None, .. }
            ]
        ));
        assert!(matches!(
            mir.functions[0].blocks[0].terminator,
            Terminator::Unreachable
        ));
        let assembly = codegen::emit_assembly(&hir, &mir).unwrap();
        assert!(assembly.contains("call enter_user\n  ud2"));
    }

    #[test]
    fn propagates_diverging_children_without_emitting_later_effects() {
        for body in [
            "return exit_now();",
            "let x: u64 = exit_now(); return side();",
            "return consume(exit_now(), side());",
            "return !exit_now();",
            "return side() + exit_now();",
            "let mut x: u64 = 1; x += exit_now(); return side();",
            "let pair: Pair = Pair { first: exit_now(), second: side() }; return side();",
            "let values: [u64; 2] = [exit_now(), side()]; return side();",
            "if exit_now() { side(); } return side();",
            "while exit_now() { side(); } return side();",
        ] {
            let bool_result = body.contains("!exit_now()");
            let source = format!(
                "module mir; struct Pair {{ first:u64, second:u64 }} \
                 extern \"C\" fn exit_now()->never; \
                 extern \"C\" fn side()->u64; \
                 extern \"C\" fn consume(a:u64,b:u64)->u64; \
                 fn test()->{} {{ {body} }}",
                if bool_result { "bool" } else { "u64" }
            );
            let ast = parser::parse("diverging.oc", &source).unwrap();
            let hir = typeck::check(&[("diverging.oc".into(), ast)]).unwrap();
            let mir = lower(&hir).unwrap();
            let function = &mir.functions[0];
            let exit = hir
                .functions
                .iter()
                .position(|f| f.qualified_name == "mir::exit_now")
                .unwrap();
            let mut exit_blocks = 0;
            for block in &function.blocks {
                if let Some(index) = block.instructions.iter().position(|instruction| {
                    matches!(instruction, Instruction::Call { function, .. } if *function == exit)
                }) {
                    exit_blocks += 1;
                    assert_eq!(index + 1, block.instructions.len(), "{body}");
                    assert!(matches!(block.terminator, Terminator::Unreachable), "{body}");
                }
            }
            assert_eq!(exit_blocks, 1, "{body}");
            assert_each_value_defined_once(function);
            // Emission validates operand/result types as well as catching
            // accidentally consumed Never placeholders in the surviving MIR.
            codegen::emit_assembly(&hir, &mir).unwrap();
        }
    }

    #[test]
    fn short_circuit_divergence_keeps_only_returning_phi_predecessors() {
        let ast = parser::parse(
            "diverging.oc",
            "module mir; extern \"C\" fn exit_now()->never; \
             fn test(value:bool)->bool { return value && exit_now(); }",
        )
        .unwrap();
        let hir = typeck::check(&[("diverging.oc".into(), ast)]).unwrap();
        let mir = lower(&hir).unwrap();
        let function = &mir.functions[0];
        let incoming = function
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find_map(|instruction| match instruction {
                Instruction::Phi { incoming, .. } => Some(incoming),
                _ => None,
            })
            .unwrap();
        assert_eq!(incoming.len(), 1);
        assert!(matches!(
            function.blocks[incoming[0].0].terminator,
            Terminator::Jump(_)
        ));
        assert!(function
            .blocks
            .iter()
            .any(|block| matches!(block.terminator, Terminator::Unreachable)));
        codegen::emit_assembly(&hir, &mir).unwrap();
    }

    #[test]
    fn indirect_call_evaluates_target_before_arguments_and_stops_on_divergence() {
        let ast = parser::parse(
            "diverging.oc",
            "module mir; extern \"C\" fn exit_now()->never; \
             extern \"C\" fn side()->u64; \
             fn select(value:u64)->fn(u64)->u64 { return side_one; } \
             fn side_one(value:u64)->u64 { return value; } \
             unsafe fn test()->u64 { return select(exit_now())(side()); }",
        )
        .unwrap();
        let hir = typeck::check(&[("diverging.oc".into(), ast)]).unwrap();
        let mir = lower(&hir).unwrap();
        let test = mir
            .functions
            .iter()
            .find(|function| hir.functions[function.source].qualified_name == "mir::test")
            .unwrap();
        assert!(matches!(
            test.blocks[0].instructions.as_slice(),
            [
                Instruction::Const { .. },
                Instruction::Call { dst: None, .. }
            ]
        ));
        assert!(matches!(test.blocks[0].terminator, Terminator::Unreachable));
        codegen::emit_assembly(&hir, &mir).unwrap();
    }

    #[test]
    fn index_evaluates_pointer_base_before_index() {
        let ast = parser::parse(
            "order.oc",
            "module mir; extern \"C\" fn base()->*const u64; \
             extern \"C\" fn index()->usize; \
             unsafe fn test()->u64 { return base()[index()]; }",
        )
        .unwrap();
        let hir = typeck::check(&[("order.oc".into(), ast)]).unwrap();
        let mir = lower(&hir).unwrap();
        let calls: Vec<_> = mir.functions[0].blocks[0]
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::Call { function, .. } => {
                    Some(hir.functions[*function].qualified_name.as_str())
                }
                _ => None,
            })
            .collect();
        assert_eq!(calls, ["mir::base", "mir::index"]);
    }

    #[test]
    fn scalar_repeat_evaluates_once_even_when_empty() {
        for len in [0, 3, 8193] {
            let source = format!("module mir; extern \"C\" fn step()->u64; fn test()->u64 {{ let values:[u64;{len}]=[step();{len}]; return 0; }}");
            let ast = parser::parse("repeat.oc", &source).unwrap();
            let hir = typeck::check(&[("repeat.oc".into(), ast)]).unwrap();
            let mir = lower(&hir).unwrap();
            let instructions = &mir.functions[0].blocks[0].instructions;
            let results: Vec<_> = instructions
                .iter()
                .filter_map(|instruction| match instruction {
                    Instruction::Call {
                        dst: Some(value), ..
                    } => Some(*value),
                    _ => None,
                })
                .collect();
            assert_eq!(results.len(), 1);
            let stores: Vec<_> = instructions
                .iter()
                .filter_map(|instruction| match instruction {
                    Instruction::Store { value, .. } => Some(*value),
                    _ => None,
                })
                .collect();
            assert_eq!(stores, vec![results[0]; len]);
            // A large constant repeat must not allocate one SSA spill per
            // repeated element; only the call and return values are needed.
            assert_eq!(mir.functions[0].values.len(), 2);
            assert_each_value_defined_once(&mir.functions[0]);
        }
    }

    #[test]
    fn aggregate_repeat_evaluates_once_into_private_snapshot_even_when_empty() {
        for len in [0, 3] {
            let source = format!("module mir; struct Pair{{first:u64,second:u64}} extern \"C\" fn step()->u64; fn test()->u64 {{ let values:[Pair;{len}]=[Pair{{first:step(),second:9}};{len}]; return 0; }}");
            let ast = parser::parse("repeat.oc", &source).unwrap();
            let hir = typeck::check(&[("repeat.oc".into(), ast)]).unwrap();
            let mir = lower(&hir).unwrap();
            let function = &mir.functions[0];
            let source_function = &hir.functions[function.source];
            assert_eq!(function.local_types.len(), source_function.locals.len() + 1);
            assert_eq!(
                function.blocks[0]
                    .instructions
                    .iter()
                    .filter(|instruction| matches!(instruction, Instruction::Call { .. }))
                    .count(),
                1
            );
            let copies: Vec<_> = function.blocks[0]
                .instructions
                .iter()
                .filter_map(|instruction| match instruction {
                    Instruction::Copy { source, .. } => Some(source),
                    _ => None,
                })
                .collect();
            assert_eq!(copies.len(), len);
            for source in copies {
                assert!(
                    matches!(source.base, PlaceBase::Local(local) if local == source_function.locals.len())
                );
            }
            assert_each_value_defined_once(function);
            codegen::emit_assembly(&hir, &mir).unwrap();
        }
    }

    fn assert_each_value_defined_once(function: &MirFunction) {
        let mut definitions = vec![0; function.values.len()];
        for instruction in function.blocks.iter().flat_map(|block| &block.instructions) {
            let dst = match instruction {
                Instruction::Const { dst, .. }
                | Instruction::FunctionAddress { dst, .. }
                | Instruction::Load { dst, .. }
                | Instruction::AddressOf { dst, .. }
                | Instruction::Unary { dst, .. }
                | Instruction::Binary { dst, .. }
                | Instruction::Cast { dst, .. }
                | Instruction::Phi { dst, .. } => Some(*dst),
                Instruction::Call { dst, .. }
                | Instruction::CallIndirect { dst, .. }
                | Instruction::Intrinsic { dst, .. } => *dst,
                Instruction::Store { .. } | Instruction::Copy { .. } | Instruction::Asm { .. } => {
                    None
                }
            };
            if let Some(dst) = dst {
                definitions[dst] += 1;
            }
        }
        assert!(
            definitions.iter().all(|count| *count == 1),
            "SSA definitions: {definitions:?}"
        );
    }

    #[test]
    fn enum_payload_lowering_uses_aligned_variant_offsets() {
        let ast = parser::parse(
            "test.oc",
            r#"
module mir;
enum Mixed { empty, payload(u8, u64, u16) }
fn construct() -> u64 {
    let state: Mixed = Mixed::payload(1, 2, 3);
    return 0;
}
"#,
        )
        .unwrap();
        let hir = typeck::check(&[("test.oc".into(), ast)]).unwrap();
        let mir = lower(&hir).unwrap();
        let enum_def = &hir.types.enums[0];
        assert_eq!(enum_def.payload_offset, 8);
        assert_eq!(enum_def.layout, Layout { size: 32, align: 8 });

        let offsets = mir.functions[0].blocks[0]
            .instructions
            .iter()
            .filter_map(|instruction| {
                let Instruction::Store { place, .. } = instruction else {
                    return None;
                };
                Some(
                    place
                        .projections
                        .iter()
                        .filter_map(|projection| match projection {
                            Projection::Field { offset } => Some(*offset),
                            Projection::Index { .. } => None,
                        })
                        .sum::<u64>(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(offsets, vec![0, 8, 16, 24]);
    }
}
