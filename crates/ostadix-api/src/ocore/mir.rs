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

#[derive(Clone, Copy)]
pub struct MirConstant {
    pub value: u64,
    pub block: BlockId,
    pub instruction: usize,
}

/// Only a unique definition in the same block before the use can discharge a
/// machine check. This does not assume dominance for malformed MIR.
pub fn local_constants(function: &MirFunction) -> Vec<Option<MirConstant>> {
    let mut seen = vec![false; function.values.len()];
    let mut constants = vec![None; function.values.len()];
    for (block, body) in function.blocks.iter().enumerate() {
        for (instruction, operation) in body.instructions.iter().enumerate() {
            let dst = match operation {
                Instruction::Const { dst, .. }
                | Instruction::FunctionAddress { dst, .. }
                | Instruction::AddressOf { dst, .. }
                | Instruction::CheckedArrayElementAddress { dst, .. }
                | Instruction::Load { dst, .. }
                | Instruction::Unary { dst, .. }
                | Instruction::Binary { dst, .. }
                | Instruction::Cast { dst, .. }
                | Instruction::Wrap { dst, .. }
                | Instruction::Unwrap { dst, .. }
                | Instruction::Phi { dst, .. } => Some(*dst),
                Instruction::Call { dst, .. }
                | Instruction::CallIndirect { dst, .. }
                | Instruction::Intrinsic { dst, .. } => *dst,
                _ => None,
            };
            if let Some(dst) = dst.filter(|dst| *dst < constants.len()) {
                if seen[dst] {
                    constants[dst] = None;
                } else if let Instruction::Const { value, .. } = operation {
                    constants[dst] = Some(MirConstant {
                        value: *value,
                        block,
                        instruction,
                    });
                }
                seen[dst] = true;
            }
        }
    }
    constants
}

pub fn local_constant_before(
    constants: &[Option<MirConstant>],
    value: ValueId,
    block: BlockId,
    instruction: usize,
) -> Option<u64> {
    constants
        .get(value)
        .copied()
        .flatten()
        .filter(|constant| constant.block == block && constant.instruction < instruction)
        .map(|constant| constant.value)
}

#[derive(Clone, Copy)]
pub enum ArrayIndexPlan {
    Dynamic,
    Offset(u64),
    Trap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArrayHelperShape {
    pub signed: bool,
    pub len: u64,
    pub size: u64,
}

impl ArrayHelperShape {
    pub fn label(self) -> String {
        format!(
            ".L_ocore_array_bounds_{}_{}_{}",
            if self.signed { "s" } else { "u" },
            self.len,
            self.size
        )
    }
}

pub fn array_index_plan(
    index_type: &Type,
    constant: Option<u64>,
    len: u64,
    size: u64,
) -> ArrayIndexPlan {
    if len == 0 {
        return ArrayIndexPlan::Trap;
    }
    let Some(raw) = constant else {
        return ArrayIndexPlan::Dynamic;
    };
    let (bits, signed) = match index_type {
        Type::Int {
            bits: bits @ (8 | 16 | 32 | 64),
            signed,
        } => (*bits, *signed),
        Type::Isize => (64, true),
        Type::Usize => (64, false),
        _ => return ArrayIndexPlan::Dynamic,
    };
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let value = raw & mask;
    if (signed && value & (1u64 << (bits - 1)) != 0) || value >= len {
        return ArrayIndexPlan::Trap;
    }
    value
        .checked_mul(size)
        .map_or(ArrayIndexPlan::Trap, ArrayIndexPlan::Offset)
}

fn value_definition(operation: &Instruction) -> Option<ValueId> {
    match operation {
        Instruction::Const { dst, .. }
        | Instruction::FunctionAddress { dst, .. }
        | Instruction::AddressOf { dst, .. }
        | Instruction::CheckedArrayElementAddress { dst, .. }
        | Instruction::Load { dst, .. }
        | Instruction::Unary { dst, .. }
        | Instruction::Binary { dst, .. }
        | Instruction::Cast { dst, .. }
        | Instruction::Wrap { dst, .. }
        | Instruction::Unwrap { dst, .. }
        | Instruction::Phi { dst, .. } => Some(*dst),
        Instruction::Call { dst, .. }
        | Instruction::CallIndirect { dst, .. }
        | Instruction::Intrinsic { dst, .. } => *dst,
        _ => None,
    }
}

fn place_values(place: &Place, visit: &mut impl FnMut(ValueId)) {
    if let PlaceBase::Pointer(value) = place.base {
        visit(value);
    }
    for projection in &place.projections {
        if let Projection::Index { index, .. } = projection {
            visit(*index);
        }
    }
}

fn instruction_values(operation: &Instruction, visit: &mut impl FnMut(ValueId)) {
    match operation {
        Instruction::Const { .. } | Instruction::FunctionAddress { .. } => {}
        Instruction::AddressOf { place, .. } | Instruction::Load { place, .. } => {
            place_values(place, visit)
        }
        Instruction::Store { place, value, .. } => {
            place_values(place, visit);
            visit(*value);
        }
        Instruction::Copy {
            destination,
            source,
            ..
        } => {
            place_values(destination, visit);
            place_values(source, visit);
        }
        Instruction::CheckedArrayElementAddress { base, index, .. } => {
            visit(*base);
            visit(*index);
        }
        Instruction::Unary { operand, .. } => visit(*operand),
        Instruction::Binary { lhs, rhs, .. } => {
            visit(*lhs);
            visit(*rhs);
        }
        Instruction::Cast { value, .. }
        | Instruction::Wrap { value, .. }
        | Instruction::Unwrap { value, .. } => visit(*value),
        Instruction::Call { args, .. } | Instruction::Intrinsic { args, .. } => {
            args.iter().for_each(|value| visit(*value))
        }
        Instruction::CallIndirect { callee, args, .. } => {
            visit(*callee);
            args.iter().for_each(|value| visit(*value));
        }
        Instruction::Phi { incoming, .. } => incoming.iter().for_each(|(_, value)| visit(*value)),
        Instruction::Asm { operands, .. } => {
            for operand in operands {
                match operand {
                    MirAsmOperand::In { value, .. } => visit(*value),
                    MirAsmOperand::Out { target, .. } => place_values(target, visit),
                    MirAsmOperand::InOut { input, output, .. } => {
                        visit(*input);
                        place_values(output, visit);
                    }
                }
            }
        }
    }
}

/// Bounds-only machine reductions. Captured pointer/index SSA operands never
/// reload a source local after an index effect. There is no alias inference.
pub struct ArrayLowering {
    pub constants: Vec<Option<MirConstant>>,
    pub omit_constants: Vec<bool>,
    pub base_places: Vec<Option<Place>>,
    pub adjacent_loads: Vec<Option<(ValueId, Place)>>,
    pub skip_loads: Vec<Vec<bool>>,
    pub needs_helper: bool,
    pub helper_shapes: std::collections::BTreeSet<ArrayHelperShape>,
}

impl ArrayLowering {
    pub fn new(types: &TypeContext, function: &MirFunction) -> Self {
        let count = function.values.len();
        let mut uses = vec![0usize; count];
        let mut definitions = vec![None; count];
        let mut seen = vec![false; count];
        for (block, body) in function.blocks.iter().enumerate() {
            for (instruction, operation) in body.instructions.iter().enumerate() {
                instruction_values(operation, &mut |value| {
                    if let Some(count) = uses.get_mut(value) {
                        *count += 1;
                    }
                });
                if let Some(dst) = value_definition(operation).filter(|dst| *dst < count) {
                    definitions[dst] = if seen[dst] {
                        None
                    } else {
                        Some((block, instruction))
                    };
                    seen[dst] = true;
                }
            }
            match body.terminator {
                Terminator::Return(Some(value))
                | Terminator::Branch {
                    condition: value, ..
                } => {
                    if let Some(count) = uses.get_mut(value) {
                        *count += 1;
                    }
                }
                _ => {}
            }
        }
        let mut result = Self {
            constants: local_constants(function),
            omit_constants: vec![false; count],
            base_places: vec![None; count],
            adjacent_loads: vec![None; count],
            skip_loads: function
                .blocks
                .iter()
                .map(|body| vec![false; body.instructions.len()])
                .collect(),
            needs_helper: false,
            helper_shapes: std::collections::BTreeSet::new(),
        };
        let mut folded_index_uses = vec![0usize; count];
        for (block, body) in function.blocks.iter().enumerate() {
            for (instruction, operation) in body.instructions.iter().enumerate() {
                let Instruction::CheckedArrayElementAddress {
                    dst,
                    base,
                    index,
                    array,
                } = operation
                else {
                    continue;
                };
                let Ok((len, size)) =
                    validate_checked_array_address(types, function, *dst, *base, *index, *array)
                else {
                    continue;
                };
                let constant = local_constant_before(&result.constants, *index, block, instruction);
                let plan =
                    array_index_plan(&types.types[function.values[*index]], constant, len, size);
                result.needs_helper |= matches!(plan, ArrayIndexPlan::Dynamic);
                if matches!(plan, ArrayIndexPlan::Dynamic) {
                    result.helper_shapes.insert(ArrayHelperShape {
                        signed: matches!(
                            types.types[function.values[*index]],
                            Type::Int { signed: true, .. } | Type::Isize
                        ),
                        len,
                        size,
                    });
                }
                if constant.is_some() && !matches!(plan, ArrayIndexPlan::Dynamic) {
                    folded_index_uses[*index] += 1;
                }
                if uses[*base] == 1 {
                    if let Some((source_block, source_instruction)) = definitions[*base] {
                        if source_block == block && source_instruction < instruction {
                            if let Instruction::AddressOf { place, .. } =
                                &body.instructions[source_instruction]
                            {
                                let mut stable = true;
                                place_values(place, &mut |value| {
                                    stable &= definitions.get(value).is_some_and(Option::is_some)
                                });
                                if stable {
                                    result.base_places[*base] = Some(place.clone());
                                }
                            }
                        }
                    }
                }
                if uses[*dst] == 1 {
                    if let Some(Instruction::Load {
                        dst: loaded,
                        place,
                        volatile: false,
                    }) = body.instructions.get(instruction + 1)
                    {
                        let Type::Array { element, .. } = types.types[*array] else {
                            unreachable!()
                        };
                        if matches!(place.base, PlaceBase::Pointer(value) if value == *dst)
                            && place.projections.is_empty()
                            && place.ty == element
                            && function.values.get(*loaded) == Some(&element)
                            && definitions.get(*loaded) == Some(&Some((block, instruction + 1)))
                            && types.is_value_scalar(element)
                        {
                            result.adjacent_loads[*dst] = Some((*loaded, place.clone()));
                            result.skip_loads[block][instruction + 1] = true;
                        }
                    }
                }
            }
        }
        for value in 0..count {
            result.omit_constants[value] = result.constants[value].is_some()
                && uses[value] > 0
                && uses[value] == folded_index_uses[value];
        }
        result
    }
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
    CheckedArrayElementAddress {
        dst: ValueId,
        base: ValueId,
        index: ValueId,
        array: TypeId,
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
    Wrap {
        dst: ValueId,
        value: ValueId,
        wrapper: TypeId,
        repr: TypeId,
    },
    Unwrap {
        dst: ValueId,
        value: ValueId,
        wrapper: TypeId,
        repr: TypeId,
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

/// Validate nominal identities before a backend performs a representation move.
pub fn validate_representation_copy(
    types: &TypeContext,
    function: &MirFunction,
    dst: ValueId,
    value: ValueId,
    wrapper: TypeId,
    repr: TypeId,
    unwrap: bool,
) -> Result<(), &'static str> {
    let Some(Type::Struct(id)) = types.types.get(wrapper) else {
        return Err("representation copy requires a transparent wrapper identity");
    };
    let Some(definition) = types.structs.get(*id) else {
        return Err("representation copy has an invalid wrapper identity");
    };
    if !matches!(
        types.types.get(repr),
        Some(
            Type::Int {
                bits: 8 | 16 | 32 | 64,
                ..
            } | Type::Usize
                | Type::Isize
        )
    ) || definition.transparent_integer != Some(repr)
        || definition.fields.len() != 1
        || definition.fields[0].ty != repr
        || definition.fields[0].offset != 0
        || definition.layout != types.layout(repr)
    {
        return Err("invalid transparent integer representation metadata");
    }
    let (source, destination) = if unwrap {
        (wrapper, repr)
    } else {
        (repr, wrapper)
    };
    if function.values.get(value).copied() != Some(source)
        || function.values.get(dst).copied() != Some(destination)
    {
        return Err("representation copy nominal source/result type mismatch");
    }
    Ok(())
}

pub fn validate_callback_cast(
    types: &TypeContext,
    from: TypeId,
    to: TypeId,
) -> Result<(), &'static str> {
    if !types.callback_cast_preserves_identity(from, to) {
        Err("cannot cast between distinct transparent-wrapper callback signatures")
    } else {
        Ok(())
    }
}

/// The array type is authoritative: no independent length or stride can weaken
/// the check. The captured input and result retain their exact pointee types.
pub fn validate_checked_array_address(
    types: &TypeContext,
    function: &MirFunction,
    dst: ValueId,
    base: ValueId,
    index: ValueId,
    array: TypeId,
) -> Result<(u64, u64), &'static str> {
    let Some(Type::Array { element, len }) = types.types.get(array) else {
        return Err("checked array address requires an array type");
    };
    types.checked_layout(array)?;
    let size = types.checked_layout(*element)?.size;
    for (value, expected) in [(base, array), (dst, *element)] {
        let ty = *function
            .values
            .get(value)
            .ok_or("invalid checked array address value")?;
        if !matches!(types.types.get(ty), Some(Type::Pointer { pointee, .. }) if *pointee == expected)
        {
            return Err("checked array address pointer type mismatch");
        }
    }
    let index_type = *function
        .values
        .get(index)
        .ok_or("invalid checked array index value")?;
    if !matches!(
        types.types.get(index_type),
        Some(
            Type::Int {
                bits: 8 | 16 | 32 | 64,
                ..
            } | Type::Usize
                | Type::Isize
        )
    ) {
        return Err("checked array index must have a primitive integer type");
    }
    Ok((*len, size))
}

/// Places must not erase the wrapper identity already present in their storage.
/// Existing aggregate projection encodings remain unchanged.
pub fn validate_value_place(
    hir: &HirProgram,
    function: &MirFunction,
    place: &Place,
) -> Result<(), &'static str> {
    let types = &hir.types;
    for projection in &place.projections {
        if let Projection::Index { index, .. } = projection {
            let ty = *function
                .values
                .get(*index)
                .ok_or("invalid place index value")?;
            if !matches!(
                types.types.get(ty),
                Some(
                    Type::Int {
                        bits: 8 | 16 | 32 | 64,
                        ..
                    } | Type::Usize
                        | Type::Isize
                )
            ) {
                return Err("place index must have a primitive integer type");
            }
        }
    }
    let (base, mut raw_index) = match place.base {
        PlaceBase::Local(id) => (
            *function.local_types.get(id).ok_or("invalid place local")?,
            false,
        ),
        PlaceBase::Static(id) => (hir.statics.get(id).ok_or("invalid place static")?.ty, false),
        PlaceBase::Pointer(id) => {
            let ty = *function
                .values
                .get(id)
                .ok_or("invalid place pointer value")?;
            let Some(Type::Pointer { pointee, .. }) = types.types.get(ty) else {
                return Err("place base is not a typed pointer");
            };
            (*pointee, true)
        }
    };
    if base >= types.types.len() || place.ty >= types.types.len() {
        return Err("invalid place type");
    }
    if place.projections.is_empty() {
        if base == place.ty {
            return Ok(());
        }
        // Existing enum initialization stores its primitive tag at offset zero.
        if let Type::Enum(id) = types.types[base] {
            let tag = types
                .primitive(match types.enums[id].tag_size {
                    1 => "u8",
                    2 => "u16",
                    _ => "u32",
                })
                .unwrap();
            if place.ty == tag {
                return Ok(());
            }
        }
        return Err("place base/result nominal type mismatch");
    }
    let mut candidates = vec![base];
    for projection in &place.projections {
        let mut next = Vec::new();
        for current in candidates {
            match projection {
                Projection::Index { element_size, .. } if raw_index => {
                    if types.checked_layout(current)?.size == *element_size {
                        next.push(current);
                    }
                }
                Projection::Index { .. } => {
                    return Err("ordinary array index requires a checked array address")
                }
                Projection::Field { offset } => match &types.types[current] {
                    Type::Struct(id) => next.extend(
                        types.structs[*id]
                            .fields
                            .iter()
                            .filter(|field| field.offset == *offset)
                            .map(|field| field.ty),
                    ),
                    Type::Array { element, len } => {
                        let size = types.layout(*element).size;
                        if *len > 0
                            && ((size == 0 && *offset == 0)
                                || (size != 0 && *offset % size == 0 && *offset / size < *len))
                        {
                            next.push(*element);
                        }
                    }
                    Type::Enum(id) => {
                        let definition = &types.enums[*id];
                        if *offset == 0 {
                            next.push(
                                types
                                    .primitive(match definition.tag_size {
                                        1 => "u8",
                                        2 => "u16",
                                        _ => "u32",
                                    })
                                    .unwrap(),
                            );
                        }
                        for variant in &definition.variants {
                            let mut at = 0;
                            for ty in &variant.payload {
                                let layout = types.layout(*ty);
                                at = align_up(at, layout.align);
                                if definition.payload_offset.checked_add(at) == Some(*offset) {
                                    next.push(*ty);
                                }
                                at = at
                                    .checked_add(layout.size)
                                    .ok_or("enum place projection overflow")?;
                            }
                        }
                    }
                    _ => {}
                },
            }
        }
        raw_index = false;
        if next.is_empty() {
            return Err("place projection does not preserve nominal storage type");
        }
        next.sort_unstable();
        next.dedup();
        candidates = next;
    }
    if candidates.iter().any(|candidate| {
        if *candidate == place.ty {
            return true;
        }
        let Type::Enum(id) = types.types[*candidate] else {
            return false;
        };
        types.primitive(match types.enums[id].tag_size {
            1 => "u8",
            2 => "u16",
            _ => "u32",
        }) == Some(place.ty)
    }) {
        Ok(())
    } else {
        Err("place projection/result nominal type mismatch")
    }
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
            HirExprKind::Constant(HirConstValue::Struct(id, values)) => {
                if self.program.types.types[expr.ty] != Type::Struct(*id)
                    || values.len() != self.program.types.structs[*id].fields.len()
                {
                    return Err(self.error(expr.span, "constant structure identity/shape mismatch"));
                }
                let fields = self.program.types.structs[*id].fields.clone();
                for (field, value) in fields.iter().zip(values) {
                    let mut target = place.clone();
                    target.projections.push(Projection::Field {
                        offset: field.offset,
                    });
                    target.ty = field.ty;
                    self.lower_initializer(
                        target,
                        &HirExpr {
                            kind: HirExprKind::Constant(value.clone()),
                            ty: field.ty,
                            span: expr.span,
                        },
                    )?;
                }
            }
            HirExprKind::Constant(HirConstValue::Array(values)) => {
                let Type::Array { element, len } = self.program.types.types[expr.ty] else {
                    return Err(self.error(expr.span, "array constant requires array storage"));
                };
                if values.len() as u64 != len {
                    return Err(self.error(expr.span, "array constant length mismatch"));
                }
                let expanded = HirExpr {
                    kind: HirExprKind::Array(
                        values
                            .iter()
                            .map(|value| HirExpr {
                                kind: HirExprKind::Constant(value.clone()),
                                ty: element,
                                span: expr.span,
                            })
                            .collect(),
                    ),
                    ty: expr.ty,
                    span: expr.span,
                };
                self.lower_initializer(place, &expanded)?;
            }
            HirExprKind::Constant(HirConstValue::Repeat(value, len)) => {
                let Type::Array {
                    element,
                    len: expected,
                } = self.program.types.types[expr.ty]
                else {
                    return Err(self.error(expr.span, "repeat constant requires array storage"));
                };
                if *len != expected {
                    return Err(self.error(expr.span, "repeat constant length mismatch"));
                }
                let expanded = HirExpr {
                    kind: HirExprKind::ArrayRepeat {
                        value: Box::new(HirExpr {
                            kind: HirExprKind::Constant((**value).clone()),
                            ty: element,
                            span: expr.span,
                        }),
                        len: *len,
                    },
                    ty: expr.ty,
                    span: expr.span,
                };
                self.lower_initializer(place, &expanded)?;
            }
            HirExprKind::Constant(HirConstValue::Enum(id, variant, values)) => {
                if self.program.types.types[expr.ty] != Type::Enum(*id) {
                    return Err(self.error(expr.span, "enum constant identity mismatch"));
                }
                let payload = &self.program.types.enums[*id].variants[*variant].payload;
                if values.len() != payload.len() {
                    return Err(self.error(expr.span, "enum constant payload mismatch"));
                }
                let expanded = HirExpr {
                    kind: HirExprKind::EnumVariant {
                        enum_id: *id,
                        variant: *variant,
                        args: values
                            .iter()
                            .zip(payload)
                            .map(|(value, ty)| HirExpr {
                                kind: HirExprKind::Constant(value.clone()),
                                ty: *ty,
                                span: expr.span,
                            })
                            .collect(),
                    },
                    ty: expr.ty,
                    span: expr.span,
                };
                self.lower_initializer(place, &expanded)?;
            }
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
                    let mut element_place = place.clone();
                    element_place.projections.push(Projection::Field {
                        offset: (index as u64).checked_mul(element_size).ok_or_else(|| {
                            self.error(expr.span, "array initializer offset overflow")
                        })?,
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
                if self.program.types.is_value_scalar(element) {
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
                    let byte_value = self.const_value(*byte as u64, element);
                    let mut element_place = place.clone();
                    element_place.projections.push(Projection::Field {
                        offset: index as u64,
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
                if !self.program.types.is_value_scalar(expr.ty) {
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
            HirExprKind::Constant(HirConstValue::Struct(id, values))
                if self
                    .program
                    .types
                    .transparent_integer_repr(expr.ty)
                    .is_some() =>
            {
                let repr = self
                    .program
                    .types
                    .transparent_integer_repr(expr.ty)
                    .unwrap();
                if self.program.types.types[expr.ty] != Type::Struct(*id) || values.len() != 1 {
                    return Err(
                        self.error(expr.span, "transparent constant identity/shape mismatch")
                    );
                }
                let HirConstValue::Integer(raw) = values[0] else {
                    return Err(self.error(
                        expr.span,
                        "transparent constant requires its primitive integer representation",
                    ));
                };
                let value = self.const_value(raw, repr);
                let dst = self.new_value(expr.ty);
                self.emit(Instruction::Wrap {
                    dst,
                    value,
                    wrapper: expr.ty,
                    repr,
                });
                Ok(dst)
            }
            HirExprKind::Struct { fields, .. }
                if self
                    .program
                    .types
                    .transparent_integer_repr(expr.ty)
                    .is_some() =>
            {
                let repr = self
                    .program
                    .types
                    .transparent_integer_repr(expr.ty)
                    .unwrap();
                if fields.len() != 1 || fields[0].0 != 0 {
                    return Err(
                        self.error(expr.span, "transparent literal requires its single field")
                    );
                }
                let value = self.lower_expr(&fields[0].1)?;
                if self.terminated(self.current) {
                    return Ok(value);
                }
                let dst = self.new_value(expr.ty);
                self.emit(Instruction::Wrap {
                    dst,
                    value,
                    wrapper: expr.ty,
                    repr,
                });
                Ok(dst)
            }
            HirExprKind::Field { base, field, .. }
                if self
                    .program
                    .types
                    .transparent_integer_repr(base.ty)
                    .is_some() =>
            {
                let repr = self
                    .program
                    .types
                    .transparent_integer_repr(base.ty)
                    .unwrap();
                if *field != 0 || expr.ty != repr {
                    return Err(self.error(expr.span, "transparent field type mismatch"));
                }
                let value = self.lower_expr(base)?;
                if self.terminated(self.current) {
                    return Ok(value);
                }
                let dst = self.new_value(repr);
                self.emit(Instruction::Unwrap {
                    dst,
                    value,
                    wrapper: base.ty,
                    repr,
                });
                Ok(dst)
            }
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
                if op.is_none() && !self.program.types.is_value_scalar(target.ty) {
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
                if matches!(self.program.types.types[base.ty], Type::Array { .. }) {
                    let pointer_to = |pointee| {
                        self.program
                            .types
                            .types
                            .iter()
                            .position(|kind| {
                                *kind
                                    == Type::Pointer {
                                        mutable: false,
                                        pointee,
                                    }
                            })
                            .ok_or_else(|| {
                                self.error(expr.span, "missing checked array pointer type")
                            })
                    };
                    let base_pointer_ty = pointer_to(base.ty)?;
                    let element_pointer_ty = pointer_to(expr.ty)?;
                    let captured_base = self.new_value(base_pointer_ty);
                    self.emit(Instruction::AddressOf {
                        dst: captured_base,
                        place,
                    });
                    let index = self.lower_expr(index)?;
                    if self.terminated(self.current) {
                        return Ok(Place {
                            base: PlaceBase::Pointer(captured_base),
                            projections: Vec::new(),
                            ty: expr.ty,
                        });
                    }
                    let dst = self.new_value(element_pointer_ty);
                    self.emit(Instruction::CheckedArrayElementAddress {
                        dst,
                        base: captured_base,
                        index,
                        array: base.ty,
                    });
                    return Ok(Place {
                        base: PlaceBase::Pointer(dst),
                        projections: Vec::new(),
                        ty: expr.ty,
                    });
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
            HirExprKind::Array(_)
            | HirExprKind::ArrayRepeat { .. }
            | HirExprKind::Struct { .. }
            | HirExprKind::EnumVariant { .. }
            | HirExprKind::Constant(
                HirConstValue::Array(_)
                | HirConstValue::Repeat(..)
                | HirConstValue::Struct(..)
                | HirConstValue::Enum(..),
            ) => {
                let local = self.local_types.len();
                self.local_types.push(expr.ty);
                let place = Place {
                    base: PlaceBase::Local(local),
                    projections: Vec::new(),
                    ty: expr.ty,
                };
                self.lower_initializer(place.clone(), expr)?;
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
        Instruction::CheckedArrayElementAddress {
            dst,
            base,
            index,
            array,
        } => format!("%{dst} = checked_array_address %{base}[%{index}] array=t{array}"),
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
        Instruction::Wrap {
            dst,
            value,
            wrapper,
            repr,
        } => format!("%{dst} = wrap %{value} from t{repr} to t{wrapper}"),
        Instruction::Unwrap {
            dst,
            value,
            wrapper,
            repr,
        } => format!("%{dst} = unwrap %{value} from t{wrapper} to t{repr}"),
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

    type TestEmitter = fn(&HirProgram, &MirProgram) -> Result<String, Diagnostic>;

    #[test]
    fn constant_array_index_proofs_preserve_width_sign_range_and_overflow() {
        let signed = Type::Int {
            bits: 8,
            signed: true,
        };
        let unsigned = Type::Int {
            bits: 8,
            signed: false,
        };
        assert!(matches!(
            array_index_plan(&signed, Some(255), u64::MAX, 0),
            ArrayIndexPlan::Trap
        ));
        assert!(matches!(
            array_index_plan(&signed, Some(128), u64::MAX, 0),
            ArrayIndexPlan::Trap
        ));
        assert!(matches!(
            array_index_plan(&unsigned, Some(258), 3, 8),
            ArrayIndexPlan::Offset(16)
        ));
        assert!(matches!(
            array_index_plan(&signed, Some(256), 3, 8),
            ArrayIndexPlan::Offset(0)
        ));
        assert!(matches!(
            array_index_plan(&unsigned, Some(3), 3, 0),
            ArrayIndexPlan::Trap
        ));
        assert!(matches!(
            array_index_plan(&unsigned, None, 0, 0),
            ArrayIndexPlan::Trap
        ));
        assert!(matches!(
            array_index_plan(&unsigned, None, 3, 8),
            ArrayIndexPlan::Dynamic
        ));
        assert!(matches!(
            array_index_plan(&Type::Usize, Some(2), 3, u64::MAX),
            ArrayIndexPlan::Trap
        ));
    }

    #[test]
    fn constant_array_index_proof_requires_a_unique_prior_definition_in_its_block() {
        let ast = parser::parse(
            "bounds.oc",
            "module bounds; fn f()->u64 {let a:[u64;2]=[1,2];return a[1];}",
        )
        .unwrap();
        let hir = typeck::check(&[("bounds.oc".into(), ast)]).unwrap();
        let mut mir = lower(&hir).unwrap();
        let function = &mut mir.functions[0];
        let (block, instruction, index) = function
            .blocks
            .iter()
            .enumerate()
            .flat_map(|(block, body)| {
                body.instructions
                    .iter()
                    .enumerate()
                    .filter_map(move |(instruction, operation)| {
                        if let Instruction::CheckedArrayElementAddress { index, .. } = operation {
                            Some((block, instruction, *index))
                        } else {
                            None
                        }
                    })
            })
            .next()
            .unwrap();
        let constants = local_constants(function);
        let definition = constants[index].unwrap();
        assert_eq!(
            local_constant_before(&constants, index, block, instruction),
            Some(1)
        );
        assert_eq!(
            local_constant_before(&constants, index, block, definition.instruction),
            None
        );
        assert_eq!(
            local_constant_before(&constants, index, block + 1, instruction),
            None
        );
        function.blocks[block]
            .instructions
            .push(Instruction::Const {
                dst: index,
                value: 0,
            });
        assert!(local_constants(function)[index].is_none());
    }

    #[test]
    fn skipped_array_base_still_rejects_noninteger_raw_place_indices_before_constant_trap() {
        let emitters: [TestEmitter; 3] = [
            codegen::emit_assembly,
            crate::ocore::codegen_aarch64::emit_assembly,
            crate::ocore::codegen_riscv64::emit_assembly,
        ];
        for wrapper in [false, true] {
            let ast = parser::parse("bounds.oc", "module bounds; @transparent struct W{raw:u64} unsafe fn f(p:*const [u64;2],i:usize)->u64{return p[i][2];}").unwrap();
            let hir = typeck::check(&[("bounds.oc".into(), ast)]).unwrap();
            let mut mir = lower(&hir).unwrap();
            let function = &mut mir.functions[0];
            let raw = function.values.len();
            let raw_ty = hir
                .types
                .primitive(if wrapper { "u64" } else { "bool" })
                .unwrap();
            function.values.push(raw_ty);
            let bad_index = if wrapper {
                let Symbol::Type(w) = hir.symbols["bounds::W"] else {
                    unreachable!()
                };
                let value = function.values.len();
                function.values.push(w);
                function.blocks[0].instructions.insert(
                    0,
                    Instruction::Wrap {
                        dst: value,
                        value: raw,
                        wrapper: w,
                        repr: raw_ty,
                    },
                );
                value
            } else {
                raw
            };
            function.blocks[0]
                .instructions
                .insert(0, Instruction::Const { dst: raw, value: 0 });
            let mut changed = false;
            for operation in &mut function.blocks[0].instructions {
                if let Instruction::AddressOf { place, .. } = operation {
                    if let Some(Projection::Index { index, .. }) = place.projections.first_mut() {
                        *index = bad_index;
                        changed = true;
                    }
                }
            }
            assert!(changed);
            assert!(ArrayLowering::new(&hir.types, function)
                .base_places
                .iter()
                .any(Option::is_some));
            for emit in emitters {
                let error = emit(&hir, &mir).unwrap_err();
                assert!(
                    error
                        .message
                        .contains("place index must have a primitive integer type"),
                    "{error}"
                );
            }
        }
    }

    #[test]
    fn array_fusion_requires_unique_captured_values_and_nonvolatile_matching_loads() {
        let ast = parser::parse(
            "bounds.oc",
            "module bounds; unsafe fn f(p:*const [u64;2],i:usize)->u64{return (*p)[i];}",
        )
        .unwrap();
        let hir = typeck::check(&[("bounds.oc".into(), ast)]).unwrap();
        let mir = lower(&hir).unwrap();
        let initial = ArrayLowering::new(&hir.types, &mir.functions[0]);
        assert!(initial.needs_helper);
        assert_eq!(
            initial.base_places.iter().filter(|p| p.is_some()).count(),
            1
        );
        assert_eq!(
            initial
                .adjacent_loads
                .iter()
                .filter(|p| p.is_some())
                .count(),
            1
        );
        let mut volatile = mir.clone();
        let function = &mut volatile.functions[0];
        for operation in &mut function.blocks[0].instructions {
            if let Instruction::Load {
                place:
                    Place {
                        base: PlaceBase::Pointer(_),
                        ..
                    },
                volatile,
                ..
            } = operation
            {
                *volatile = true;
            }
        }
        assert!(ArrayLowering::new(&hir.types, function)
            .adjacent_loads
            .iter()
            .all(Option::is_none));
        let mut duplicate = mir.clone();
        let function = &mut duplicate.functions[0];
        let operation = function.blocks[0]
            .instructions
            .iter()
            .find(|operation| matches!(operation, Instruction::AddressOf { .. }))
            .unwrap()
            .clone();
        function.blocks[0].instructions.push(operation);
        assert!(ArrayLowering::new(&hir.types, function)
            .base_places
            .iter()
            .all(Option::is_none));
    }

    #[test]
    fn private_array_helper_entries_deduplicate_by_signedness_length_and_stride() {
        let ast = parser::parse("bounds.oc", "module bounds; unsafe fn f(p:*const [u64;3],u:usize,s:i8)->u64{return (*p)[u]+(*p)[u]+(*p)[s];}").unwrap();
        let hir = typeck::check(&[("bounds.oc".into(), ast)]).unwrap();
        let mir = lower(&hir).unwrap();
        let lowering = ArrayLowering::new(&hir.types, &mir.functions[0]);
        let expected = [
            ArrayHelperShape {
                signed: false,
                len: 3,
                size: 8,
            },
            ArrayHelperShape {
                signed: true,
                len: 3,
                size: 8,
            },
        ];
        assert_eq!(
            lowering.helper_shapes.iter().copied().collect::<Vec<_>>(),
            expected
        );
        let emitters: [TestEmitter; 3] = [
            codegen::emit_assembly,
            crate::ocore::codegen_aarch64::emit_assembly,
            crate::ocore::codegen_riscv64::emit_assembly,
        ];
        for emit in emitters {
            let assembly = emit(&hir, &mir).unwrap();
            for shape in expected {
                assert_eq!(assembly.matches(&format!("{}:", shape.label())).count(), 1);
            }
            assert_eq!(
                assembly.matches(".L_ocore_array_bounds_unsigned:").count(),
                1
            );
        }
    }

    #[test]
    fn explicit_function_sections_keep_inserted_array_checks_in_their_execution_domain() {
        let source = r#"module bounds;
@link_section(".text.user")
unsafe fn placed(p:*const [u64;3],u:usize,s:i8)->u64 { return (*p)[u] + (*p)[s]; }
unsafe fn ordinary(p:*const [u64;3],u:usize)->u64 { return (*p)[u]; }
"#;
        let ast = parser::parse("bounds.oc", source).unwrap();
        let hir = typeck::check(&[("bounds.oc".into(), ast)]).unwrap();
        let mir = lower(&hir).unwrap();
        let emitters: [TestEmitter; 3] = [
            codegen::emit_assembly,
            crate::ocore::codegen_aarch64::emit_assembly,
            crate::ocore::codegen_riscv64::emit_assembly,
        ];
        for emit in emitters {
            let assembly = emit(&hir, &mir).unwrap();
            let placed = assembly
                .split(".section .text.user,")
                .nth(1)
                .unwrap()
                .split(".section ")
                .next()
                .unwrap();
            assert!(
                !placed.lines().any(|line| {
                    line.contains(".L_ocore_array_bounds_")
                        && (line.contains("call ") || line.contains("bl "))
                }),
                "inserted helper crosses an explicit section: {placed}"
            );
            assert!(placed.contains("_trap:"));
            assert!(placed.contains("mul ") || placed.contains("umulh "));
            let ordinary = assembly
                .split(".section .text,\"")
                .nth(1)
                .unwrap()
                .split(".section ")
                .next()
                .unwrap();
            assert!(ordinary.contains(".L_ocore_array_bounds_u_3_8"));
            assert!(assembly.contains(".section .text.ocore_fn.__array_bounds,"));
        }
    }

    #[test]
    fn array_target_is_captured_and_checked_before_rhs_effects() {
        let source = r#"module bounds;
extern "C" fn base()->*mut [u64;2];
extern "C" fn index()->usize;
extern "C" fn rhs()->u64;
unsafe fn test()->void { (*base())[index()] = rhs(); }
"#;
        let ast = parser::parse("bounds.oc", source).unwrap();
        let hir = typeck::check(&[("bounds.oc".into(), ast)]).unwrap();
        let mir = lower(&hir).unwrap();
        let order: Vec<_> = mir.functions[0]
            .blocks
            .iter()
            .flat_map(|b| &b.instructions)
            .filter_map(|instruction| match instruction {
                Instruction::Call { function, .. } => {
                    Some(hir.functions[*function].qualified_name.as_str())
                }
                Instruction::AddressOf { .. } => Some("capture"),
                Instruction::CheckedArrayElementAddress { .. } => Some("check"),
                Instruction::Store { .. } => Some("store"),
                _ => None,
            })
            .collect();
        assert_eq!(
            order,
            [
                "bounds::base",
                "capture",
                "bounds::index",
                "check",
                "bounds::rhs",
                "store"
            ]
        );
        assert_each_value_defined_once(&mir.functions[0]);
    }

    #[test]
    fn diverging_array_index_does_not_emit_a_check_or_rhs() {
        let source = r#"module bounds;
extern "C" fn stop()->never;
extern "C" fn rhs()->u64;
fn test()->void { let mut a:[u64;2]=[1,2]; a[stop()] = rhs(); }
"#;
        let ast = parser::parse("bounds.oc", source).unwrap();
        let hir = typeck::check(&[("bounds.oc".into(), ast)]).unwrap();
        let mir = lower(&hir).unwrap();
        let instructions: Vec<_> = mir.functions[0]
            .blocks
            .iter()
            .flat_map(|b| &b.instructions)
            .collect();
        assert!(!instructions
            .iter()
            .any(|i| matches!(i, Instruction::CheckedArrayElementAddress { .. })));
        let calls: Vec<_> = instructions
            .iter()
            .filter_map(|i| match i {
                Instruction::Call { function, .. } => {
                    Some(hir.functions[*function].qualified_name.as_str())
                }
                _ => None,
            })
            .collect();
        assert_eq!(calls, ["bounds::stop"]);
        assert_each_value_defined_once(&mir.functions[0]);
    }

    #[test]
    fn every_emitter_rejects_malformed_checked_array_addresses_and_unchecked_array_places() {
        let emitters: [TestEmitter; 3] = [
            codegen::emit_assembly,
            crate::ocore::codegen_aarch64::emit_assembly,
            crate::ocore::codegen_riscv64::emit_assembly,
        ];
        for mutation in 0..9 {
            let ast = parser::parse(
                "bounds.oc",
                "module bounds; unsafe fn f(p:*const [u64;2],i:i64)->u64{return (*p)[i];}",
            )
            .unwrap();
            let mut hir = typeck::check(&[("bounds.oc".into(), ast)]).unwrap();
            let mut mir = lower(&hir).unwrap();
            let u64_ty = hir.types.primitive("u64").unwrap();
            let u8_ty = hir.types.primitive("u8").unwrap();
            let bool_ty = hir.types.primitive("bool").unwrap();
            let pointer = hir.types.intern(Type::Pointer {
                mutable: false,
                pointee: u8_ty,
            });
            let other_array = hir.types.intern(Type::Array {
                element: u64_ty,
                len: 3,
            });
            let function = &mut mir.functions[0];
            let instruction = function.blocks[0]
                .instructions
                .iter_mut()
                .find(|i| matches!(i, Instruction::CheckedArrayElementAddress { .. }))
                .unwrap();
            let Instruction::CheckedArrayElementAddress {
                dst,
                base,
                index,
                array,
            } = instruction
            else {
                unreachable!()
            };
            match mutation {
                0 => *array = u64_ty,
                1 => *array = other_array,
                2 => function.values[*dst] = pointer,
                3 => function.values[*base] = pointer,
                4 => function.values[*index] = bool_ty,
                5 => {
                    hir.types.types[*array] = Type::Array {
                        element: u64_ty,
                        len: u64::MAX,
                    }
                }
                6 => *index = usize::MAX,
                7 | 8 => {
                    let raw_base = *base;
                    let raw_index = *index;
                    let local = function.local_types.len();
                    function.local_types.push(*array);
                    let value = function.values.len();
                    function.values.push(u64_ty);
                    *instruction = Instruction::Load {
                        dst: value,
                        place: Place {
                            base: if mutation == 7 {
                                PlaceBase::Local(local)
                            } else {
                                PlaceBase::Pointer(raw_base)
                            },
                            projections: vec![Projection::Index {
                                index: raw_index,
                                element_size: 8,
                            }],
                            ty: u64_ty,
                        },
                        volatile: false,
                    };
                }
                _ => unreachable!(),
            }
            for emit in emitters {
                assert!(
                    emit(&hir, &mir).is_err(),
                    "emitter accepted checked-array mutation {mutation}"
                );
            }
        }
    }

    #[test]
    fn every_emitter_diagnoses_array_storage_and_frame_overflow_without_panicking() {
        let emitters: [TestEmitter; 3] = [
            codegen::emit_assembly,
            crate::ocore::codegen_aarch64::emit_assembly,
            crate::ocore::codegen_riscv64::emit_assembly,
        ];
        for (primitive, length) in [("u8", u64::MAX), ("u64", u64::MAX)] {
            let ast = parser::parse("bounds.oc", "module bounds; fn f()->u64{return 0;}").unwrap();
            let mut hir = typeck::check(&[("bounds.oc".into(), ast)]).unwrap();
            let mut mir = lower(&hir).unwrap();
            let element = hir.types.primitive(primitive).unwrap();
            let array = hir.types.intern(Type::Array {
                element,
                len: length,
            });
            mir.functions[0].local_types.push(array);
            for emit in emitters {
                assert!(emit(&hir, &mir).is_err());
            }
        }
    }

    #[test]
    fn every_emitter_diagnoses_invalid_static_array_layout_even_with_explicit_alignment() {
        let emitters: [TestEmitter; 3] = [
            codegen::emit_assembly,
            crate::ocore::codegen_aarch64::emit_assembly,
            crate::ocore::codegen_riscv64::emit_assembly,
        ];
        for container in 0..4 {
            for alignment in [None, Some(16)] {
                let ast = parser::parse("bounds.oc", "module bounds; struct Holder{a:[[u64;1];1]} enum E{value([[u64;1];1])} static A:[u64;1]=[0];").unwrap();
                let mut hir = typeck::check(&[("bounds.oc".into(), ast)]).unwrap();
                let mir = lower(&hir).unwrap();
                let u64_ty = hir.types.primitive("u64").unwrap();
                let inner = hir.statics[0].ty;
                let nested = hir.types.intern(Type::Array {
                    element: inner,
                    len: 1,
                });
                let Symbol::Type(holder) = hir.symbols["bounds::Holder"] else {
                    unreachable!()
                };
                let Symbol::Type(enumeration) = hir.symbols["bounds::E"] else {
                    unreachable!()
                };
                hir.statics[0].ty = [inner, nested, holder, enumeration][container];
                hir.statics[0].attrs.align = alignment;
                // Zero is an existing internal initializer, chosen so malformed
                // storage cannot be hidden by an earlier initializer mismatch.
                hir.statics[0].init = HirConstValue::Zero;
                hir.types.types[inner] = Type::Array {
                    element: u64_ty,
                    len: u64::MAX,
                };
                for emit in emitters {
                    let error = emit(&hir, &mir).unwrap_err();
                    assert!(error.message.contains("layout overflows"), "{error}");
                }
            }
        }
    }

    fn transparent_program() -> (HirProgram, MirProgram) {
        let source = r#"module wrappers;
@opaque @transparent struct A{raw:u64}
@transparent struct B{raw:u64}
const FIRST:A=A{raw:7};
fn keep(x:A)->A{return x;}
unsafe fn exercise(raw:u64)->u64{
 let mut x:A=FIRST;x=A{raw:raw};let a:[A;2]=[x;2];
 let f:fn(A)->A=keep;return f(keep(a[1])).raw;
}"#;
        let parsed = parser::parse("wrappers.oc", source).unwrap();
        let hir = typeck::check(&[("wrappers.oc".into(), parsed)]).unwrap();
        let mir = lower(&hir).unwrap();
        (hir, mir)
    }

    #[test]
    fn transparent_values_keep_explicit_nominal_wraps_and_unwraps() {
        let (hir, mir) = transparent_program();
        assert!(mir
            .functions
            .iter()
            .flat_map(|f| &f.blocks)
            .flat_map(|b| &b.instructions)
            .any(|i| matches!(i, Instruction::Wrap { .. })));
        assert!(mir
            .functions
            .iter()
            .flat_map(|f| &f.blocks)
            .flat_map(|b| &b.instructions)
            .any(|i| matches!(i, Instruction::Unwrap { .. })));
        for function in &mir.functions {
            assert_each_value_defined_once(function);
        }
        codegen::emit_assembly(&hir, &mir).unwrap();
        crate::ocore::codegen_aarch64::emit_assembly(&hir, &mir).unwrap();
        crate::ocore::codegen_riscv64::emit_assembly(&hir, &mir).unwrap();
    }

    #[test]
    fn every_emitter_rejects_malformed_representation_moves_and_foreign_calls() {
        let emitters: [TestEmitter; 3] = [
            codegen::emit_assembly,
            crate::ocore::codegen_aarch64::emit_assembly,
            crate::ocore::codegen_riscv64::emit_assembly,
        ];
        for mutation in 0..7 {
            let (mut hir, mut mir) = transparent_program();
            let Symbol::Type(a) = hir.symbols["wrappers::A"] else {
                panic!()
            };
            let Symbol::Type(b) = hir.symbols["wrappers::B"] else {
                panic!()
            };
            let u32_ty = hir.types.primitive("u32").unwrap();
            if mutation == 6 {
                let Symbol::Function(keep) = hir.symbols["wrappers::keep"] else {
                    panic!()
                };
                hir.functions[keep].abi = crate::ocore::ast::Abi::C;
            } else {
                let mut changed = false;
                'outer: for function in &mut mir.functions {
                    for block in &mut function.blocks {
                        for instruction in &mut block.instructions {
                            match instruction {
                                Instruction::Wrap {
                                    dst, wrapper, repr, ..
                                } if mutation < 4 => {
                                    match mutation {
                                        0 => *wrapper = b,
                                        1 => *repr = u32_ty,
                                        2 => function.values[*dst] = b,
                                        3 => {
                                            let target = *dst;
                                            *instruction = Instruction::Const {
                                                dst: target,
                                                value: 0,
                                            };
                                        }
                                        _ => unreachable!(),
                                    }
                                    changed = true;
                                    break 'outer;
                                }
                                Instruction::Unwrap { wrapper, .. } if mutation == 4 => {
                                    *wrapper = b;
                                    changed = true;
                                    break 'outer;
                                }
                                Instruction::Unwrap { dst, .. } if mutation == 5 => {
                                    function.values[*dst] = a;
                                    changed = true;
                                    break 'outer;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                assert!(changed, "mutation {mutation} did not find its instruction");
            }
            for emit in emitters {
                assert!(
                    emit(&hir, &mir).is_err(),
                    "emitter accepted mutation {mutation}"
                );
            }
        }
    }

    #[test]
    fn every_emitter_rejects_nominal_place_and_callback_retagging() {
        let emitters: [TestEmitter; 3] = [
            codegen::emit_assembly,
            crate::ocore::codegen_aarch64::emit_assembly,
            crate::ocore::codegen_riscv64::emit_assembly,
        ];
        for mutation in 0..4 {
            let (mut hir, mut mir) = transparent_program();
            let Symbol::Type(a) = hir.symbols["wrappers::A"] else {
                panic!()
            };
            let Symbol::Type(b) = hir.symbols["wrappers::B"] else {
                panic!()
            };
            let u64_ty = hir.types.primitive("u64").unwrap();
            let callback = hir.types.intern(Type::Function {
                params: vec![b],
                result: b,
                abi: crate::ocore::ast::Abi::OCore,
            });
            let mut changed = false;
            'outer: for function in &mut mir.functions {
                for block in &mut function.blocks {
                    for instruction in &mut block.instructions {
                        let Instruction::Load { dst, place, .. } = instruction else {
                            continue;
                        };
                        let change = match mutation {
                            0 => place.projections.is_empty() && place.ty == a,
                            1 => place.projections.is_empty() && place.ty == u64_ty,
                            2 => {
                                place.projections.is_empty()
                                    && matches!(hir.types.types[place.ty], Type::Function { .. })
                            }
                            // Array elements now arrive as captured checked
                            // pointers rather than deferred Index projections.
                            _ => matches!(place.base, PlaceBase::Pointer(_)) && place.ty == a,
                        };
                        if change {
                            place.ty = if mutation == 2 {
                                callback
                            } else if mutation == 1 {
                                a
                            } else {
                                b
                            };
                            function.values[*dst] = place.ty;
                            changed = true;
                            break 'outer;
                        }
                    }
                }
            }
            assert!(changed);
            for emit in emitters {
                let error = emit(&hir, &mir).unwrap_err();
                assert!(
                    error.message.contains("place"),
                    "mutation {mutation}: {error}"
                );
            }
        }
        let (mut hir, mut mir) = transparent_program();
        let Symbol::Type(b) = hir.symbols["wrappers::B"] else {
            panic!()
        };
        let to = hir.types.intern(Type::Function {
            params: vec![b],
            result: b,
            abi: crate::ocore::ast::Abi::OCore,
        });
        let mut changed = false;
        'outer: for function in &mut mir.functions {
            for block in &mut function.blocks {
                let source = block
                    .instructions
                    .iter()
                    .find_map(|instruction| match instruction {
                        Instruction::FunctionAddress { dst, .. } => Some(*dst),
                        _ => None,
                    });
                if let Some(value) = source {
                    let from = function.values[value];
                    let dst = function.values.len();
                    function.values.push(to);
                    block.instructions.push(Instruction::Cast {
                        dst,
                        value,
                        from,
                        to,
                    });
                    changed = true;
                    break 'outer;
                }
            }
        }
        assert!(changed);
        for emit in emitters {
            assert!(emit(&hir, &mir)
                .unwrap_err()
                .message
                .contains("callback signatures"));
        }
    }

    #[test]
    fn transparent_pointer_array_places_keep_both_valid_index_forms() {
        let source = r#"module pointer_arrays;
@transparent struct W{raw:u64}
unsafe fn read(p:*const [W;2])->W{return (*p)[1];}
unsafe fn raw(p:*const [W;2])->W{return p[1][0];}
unsafe fn nested(p:*const [[W;2];2])->W{return (*p)[1][0];}
unsafe fn one(p:*const [W;1])->W{return (*p)[0];}
unsafe fn wrapped()->u64{let array:[W;2]=[W{raw:3};2];return read(&array).raw;}
"#;
        let parsed = parser::parse("arrays.oc", source).unwrap();
        let hir = typeck::check(&[("arrays.oc".into(), parsed)]).unwrap();
        let mir = lower(&hir).unwrap();
        codegen::emit_assembly(&hir, &mir).unwrap();
        crate::ocore::codegen_aarch64::emit_assembly(&hir, &mir).unwrap();
        crate::ocore::codegen_riscv64::emit_assembly(&hir, &mir).unwrap();
    }

    #[test]
    fn every_emitter_requires_typed_pointer_storage_instead_of_implicit_retagging() {
        let source = r#"module pointer_storage;
@opaque @transparent struct A{raw:u64}
@opaque @transparent struct B{raw:u64}
struct Holder{pointer:*const A}
fn unused(pointer:*const A)->u64{let local:*const A=pointer;let holder:Holder=Holder{pointer:pointer};let copied:*const A=holder.pointer;return 0;}
"#;
        let ast = parser::parse("pointer-storage.oc", source).unwrap();
        let hir = typeck::check(&[("pointer-storage.oc".into(), ast)]).unwrap();
        let original = lower(&hir).unwrap();
        let Symbol::Type(b) = hir.symbols["pointer_storage::B"] else {
            panic!()
        };
        for projected in [false, true] {
            let mut hir = hir.clone();
            let mut program = original.clone();
            let wrong = hir.types.intern(Type::Pointer {
                mutable: false,
                pointee: b,
            });
            let mut changed = false;
            'outer: for function in &mut program.functions {
                for block in &mut function.blocks {
                    for instruction in &mut block.instructions {
                        if let Instruction::Load { dst, place, .. } = instruction {
                            if matches!(hir.types.types[place.ty], Type::Pointer { .. })
                                && (!place.projections.is_empty()) == projected
                            {
                                place.ty = wrong;
                                function.values[*dst] = wrong;
                                changed = true;
                                break 'outer;
                            }
                        }
                    }
                }
            }
            assert!(changed);
            for emit in [
                codegen::emit_assembly,
                crate::ocore::codegen_aarch64::emit_assembly,
                crate::ocore::codegen_riscv64::emit_assembly,
            ] {
                assert!(emit(&hir, &program).unwrap_err().message.contains("place"));
            }
        }
    }

    #[test]
    fn transparent_phi_executes_all_targets_when_requested() {
        use crate::ocore::{ast, codegen_aarch64, codegen_riscv64, common::Target};
        use sha2::{Digest, Sha256};
        use std::{
            fs,
            path::{Path, PathBuf},
            process::Command,
        };
        let source = r#"module wrapper_phi;
@opaque @transparent struct W{raw:i8}
fn exchange(a:W,b:W,count:u64)->W{return a;}
@export @no_mangle extern "C" fn ocore_wrapper_phi_entry()->u64{
 let first:W=exchange(W{raw:-128},W{raw:127},1);
 let second:W=exchange(W{raw:-128},W{raw:127},2);
 if first.raw!=127{return 1;}if second.raw!=-128{return 2;}return 0;
}"#;
        let ast = parser::parse("wrapper-phi.oc", source).unwrap();
        let hir = typeck::check(&[("wrapper-phi.oc".into(), ast)]).unwrap();
        let mut program = lower(&hir).unwrap();
        let Symbol::Function(exchange) = hir.symbols["wrapper_phi::exchange"] else {
            panic!()
        };
        let Symbol::Type(wrapper) = hir.symbols["wrapper_phi::W"] else {
            panic!()
        };
        let u64_ty = hir.types.primitive("u64").unwrap();
        let bool_ty = hir.types.primitive("bool").unwrap();
        let function = program
            .functions
            .iter_mut()
            .find(|function| function.source == exchange)
            .unwrap();
        function.values = vec![
            wrapper, wrapper, wrapper, wrapper, u64_ty, u64_ty, bool_ty, u64_ty, u64_ty,
        ];
        let place = |local, ty| Place {
            base: PlaceBase::Local(local),
            projections: vec![],
            ty,
        };
        function.blocks = vec![
            BasicBlock {
                instructions: vec![
                    Instruction::Load {
                        dst: 0,
                        place: place(0, wrapper),
                        volatile: false,
                    },
                    Instruction::Load {
                        dst: 1,
                        place: place(1, wrapper),
                        volatile: false,
                    },
                ],
                terminator: Terminator::Jump(1),
            },
            BasicBlock {
                instructions: vec![
                    Instruction::Phi {
                        dst: 2,
                        incoming: vec![(0, 0), (2, 3)],
                    },
                    Instruction::Phi {
                        dst: 3,
                        incoming: vec![(0, 1), (2, 2)],
                    },
                    Instruction::Load {
                        dst: 4,
                        place: place(2, u64_ty),
                        volatile: false,
                    },
                    Instruction::Const { dst: 5, value: 0 },
                    Instruction::Binary {
                        dst: 6,
                        op: ast::BinaryOp::Eq,
                        lhs: 4,
                        rhs: 5,
                    },
                ],
                terminator: Terminator::Branch {
                    condition: 6,
                    then_block: 3,
                    else_block: 2,
                },
            },
            BasicBlock {
                instructions: vec![
                    Instruction::Const { dst: 7, value: 1 },
                    Instruction::Binary {
                        dst: 8,
                        op: ast::BinaryOp::Sub,
                        lhs: 4,
                        rhs: 7,
                    },
                    Instruction::Store {
                        place: place(2, u64_ty),
                        value: 8,
                        volatile: false,
                    },
                ],
                terminator: Terminator::Jump(1),
            },
            BasicBlock {
                instructions: vec![],
                terminator: Terminator::Return(Some(2)),
            },
        ];
        assert_each_value_defined_once(function);
        let assemblies = [
            codegen::emit_assembly(&hir, &program).unwrap(),
            codegen_aarch64::emit_assembly(&hir, &program).unwrap(),
            codegen_riscv64::emit_assembly(&hir, &program).unwrap(),
        ];
        let Some(output) = std::env::var_os("OCORE_WRAPPER_PHI_OUTPUT_DIR") else {
            eprintln!("SKIP-OPTIONAL: typed Phi machine execution requires OCORE_WRAPPER_PHI_OUTPUT_DIR and matching Linux runners; all three assemblies validated");
            return;
        };
        let output = PathBuf::from(output);
        assert!(!output.exists(), "Phi evidence directory must be fresh");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("source.oc"), source).unwrap();
        fs::write(output.join("mir.txt"), program.to_text(&hir)).unwrap();
        fn resolve_tool(value: &str) -> PathBuf {
            let path = Path::new(value);
            if path.components().count() > 1 {
                assert!(path.is_file(), "missing tool {value}");
                return path.to_path_buf();
            }
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .map(|directory| directory.join(value))
                .find(|path| path.is_file())
                .unwrap_or_else(|| panic!("missing tool {value}"))
        }
        fn identity(path: &Path) -> serde_json::Value {
            let data = fs::read(path).unwrap();
            serde_json::json!({"path":path,"bytes":data.len(),"sha256":hex::encode(Sha256::digest(data))})
        }
        let clang = resolve_tool(&std::env::var("OCORE_CLANG").unwrap_or_else(|_| "clang".into()));
        let linker = resolve_tool("ld.lld");
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let sources = [
            "hir.rs",
            "typeck.rs",
            "mir.rs",
            "codegen.rs",
            "codegen_aarch64.rs",
            "codegen_riscv64.rs",
        ]
        .map(|name| identity(&repo.join("crates/ostadix-api/src/ocore").join(name)));
        let test_executable = std::env::current_exe().unwrap();
        let running = if cfg!(target_os = "linux") {
            PathBuf::from("/proc/self/exe")
        } else {
            test_executable.clone()
        };
        let mut report = serde_json::json!({"schema":"ostadix.ocore-transparent-phi-execution/v1","complete":false,"source_files":sources,"test_executable_path":test_executable,"running_test_binary":identity(&running),"clang":identity(&clang),"linker":identity(&linker),"commands":[],"targets":[],"scope":"Actual typed O-core MIR Phi/parallel-edge moves and internal narrow-signed wrapper ABI; no imported NativeModule or guest qualification"});
        for (target, assembly) in Target::ALL.iter().zip(assemblies) {
            let (id,hosted,flags,start,runner):( &str,&str,Vec<&str>,&str,Option<&str>)=match target{
                Target::X86_64UnknownNone=>("x86_64","x86_64-linux-gnu",vec![],".text\n.globl _start\n_start:\n and rsp,-16\n call ocore_wrapper_phi_entry\n mov rdi,rax\n mov rax,60\n syscall\n ud2\n",if cfg!(all(target_os="linux",target_arch="x86_64")){None}else{Some("OCORE_TEST_QEMU_X86_64")}),
                Target::Aarch64UnknownNone=>("aarch64","aarch64-linux-gnu",vec![],".text\n.globl _start\n_start:\n bl ocore_wrapper_phi_entry\n mov x8,#93\n svc #0\n brk #0\n",Some("OCORE_TEST_QEMU_AARCH64")),
                Target::Riscv64UnknownNone=>("riscv64","riscv64-linux-gnu",vec!["-march=rv64gc","-mabi=lp64"],".text\n.globl _start\n_start:\n call ocore_wrapper_phi_entry\n li a7,93\n ecall\n ebreak\n",Some("OCORE_TEST_QEMU_RISCV64")),
            };
            let source = output.join(format!("{id}.s"));
            let object = output.join(format!("{id}.o"));
            let executable = output.join(format!("{id}.elf"));
            fs::write(&source, format!("{assembly}{start}")).unwrap();
            let mut assemble = Command::new(&clang);
            assemble
                .arg(format!("--target={}", target.triple()))
                .args(&flags)
                .arg("-c")
                .arg(&source)
                .arg("-o")
                .arg(&object);
            let mut link = Command::new(&clang);
            link.arg(format!("--target={hosted}"))
                .args(&flags)
                .args([
                    "-nostdlib",
                    "-static",
                    "-fno-pic",
                    "-Wl,--build-id=none",
                    "-Wl,-e,_start",
                ])
                .arg(format!("--ld-path={}", linker.display()))
                .arg(&object)
                .arg("-o")
                .arg(&executable);
            let mut execute = if let Some(variable) = runner {
                let path = resolve_tool(
                    &std::env::var(variable)
                        .unwrap_or_else(|_| panic!("required runner {variable} is missing")),
                );
                let mut command = Command::new(path);
                command.arg(&executable);
                command
            } else {
                Command::new(&executable)
            };
            for (phase, command) in [
                ("assemble", &mut assemble),
                ("link", &mut link),
                ("execute", &mut execute),
            ] {
                command.current_dir(&output);
                let argv = std::iter::once(command.get_program().to_string_lossy().into_owned())
                    .chain(
                        command
                            .get_args()
                            .map(|value| value.to_string_lossy().into_owned()),
                    )
                    .collect::<Vec<_>>();
                let tool_before = identity(Path::new(command.get_program()));
                let version = if phase != "execute" || runner.is_some() {
                    Some(
                        Command::new(command.get_program())
                            .arg("--version")
                            .output()
                            .unwrap(),
                    )
                } else {
                    None
                };
                let result = command.output().unwrap();
                let tool_after = identity(Path::new(command.get_program()));
                assert_eq!(tool_before, tool_after, "tool changed during Phi execution");
                fs::write(output.join(format!("{id}-{phase}.stdout")), &result.stdout).unwrap();
                fs::write(output.join(format!("{id}-{phase}.stderr")), &result.stderr).unwrap();
                report["commands"].as_array_mut().unwrap().push(serde_json::json!({"target":target.name(),"phase":phase,"argv":argv,"cwd":output,"exit_code":result.status.code(),"status":format!("{:?}",result.status),"stdout":String::from_utf8_lossy(&result.stdout),"stderr":String::from_utf8_lossy(&result.stderr),"tool_before":tool_before,"tool_after":tool_after,"tool_version":version.map(|value|String::from_utf8_lossy(&value.stdout).into_owned())}));
                fs::write(
                    output.join("execution.json"),
                    serde_json::to_vec_pretty(&report).unwrap(),
                )
                .unwrap();
                assert!(
                    result.status.success(),
                    "{id} {phase} failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
            let machine = match target {
                Target::X86_64UnknownNone => 62u16,
                Target::Aarch64UnknownNone => 183,
                Target::Riscv64UnknownNone => 243,
            };
            for (path, kind) in [(&object, 1u16), (&executable, 2u16)] {
                let data = fs::read(path).unwrap();
                assert!(data.len() >= 64);
                assert_eq!(&data[..6], b"\x7fELF\x02\x01");
                assert_eq!(u16::from_le_bytes([data[16], data[17]]), kind);
                assert_eq!(u16::from_le_bytes([data[18], data[19]]), machine);
            }
            report["targets"].as_array_mut().unwrap().push(serde_json::json!({"target":target.name(),"assembly":identity(&source),"object":identity(&object),"executable":identity(&executable),"passed":true}));
        }
        assert_eq!(
            report["targets"].as_array().unwrap().len(),
            Target::ALL.len()
        );
        report["complete"] =
            serde_json::json!(report["targets"].as_array().unwrap().len() == Target::ALL.len());
        fs::write(
            output.join("execution.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }

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
                | Instruction::CheckedArrayElementAddress { dst, .. }
                | Instruction::Unary { dst, .. }
                | Instruction::Binary { dst, .. }
                | Instruction::Cast { dst, .. }
                | Instruction::Wrap { dst, .. }
                | Instruction::Unwrap { dst, .. }
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
