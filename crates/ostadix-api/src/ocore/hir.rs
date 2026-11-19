use std::collections::HashMap;

use super::ast::{Abi, BinaryOp, UnaryOp};
use super::Span;

pub type TypeId = usize;
pub type StructId = usize;
pub type EnumId = usize;
pub type FunctionId = usize;
pub type StaticId = usize;
pub type ConstId = usize;
pub type LocalId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub size: u64,
    pub align: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    Bool,
    Int {
        signed: bool,
        bits: u16,
    },
    Usize,
    Isize,
    Float {
        bits: u16,
    },
    Void,
    Never,
    Pointer {
        mutable: bool,
        pointee: TypeId,
    },
    Array {
        element: TypeId,
        len: u64,
    },
    Struct(StructId),
    Enum(EnumId),
    Function {
        params: Vec<TypeId>,
        result: TypeId,
        abi: Abi,
    },
}

#[derive(Debug, Clone)]
pub struct StructType {
    pub name: String,
    /// Canonical module identity; imports never change representation ownership.
    pub defining_module: String,
    pub opaque: bool,
    /// A direct primitive integer only. Source assignability remains nominal.
    pub transparent_integer: Option<TypeId>,
    pub fields: Vec<StructField>,
    pub packed: bool,
    pub requested_align: Option<u64>,
    pub layout: Layout,
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub ty: TypeId,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct EnumType {
    pub name: String,
    pub variants: Vec<EnumVariant>,
    pub tag_size: u64,
    pub payload_offset: u64,
    pub layout: Layout,
}

#[derive(Debug, Clone)]
pub struct EnumVariant {
    pub name: String,
    pub payload: Vec<TypeId>,
    pub payload_layout: Layout,
}

#[derive(Debug, Clone)]
pub struct TypeContext {
    pub types: Vec<Type>,
    pub structs: Vec<StructType>,
    pub enums: Vec<EnumType>,
    interned: HashMap<Type, TypeId>,
    primitive_names: HashMap<String, TypeId>,
}

impl TypeContext {
    pub fn new() -> Self {
        let mut cx = Self {
            types: Vec::new(),
            structs: Vec::new(),
            enums: Vec::new(),
            interned: HashMap::new(),
            primitive_names: HashMap::new(),
        };
        cx.add_primitive("bool", Type::Bool);
        for bits in [8, 16, 32, 64] {
            cx.add_primitive(
                &format!("u{bits}"),
                Type::Int {
                    signed: false,
                    bits,
                },
            );
            cx.add_primitive(&format!("i{bits}"), Type::Int { signed: true, bits });
        }
        cx.add_primitive("usize", Type::Usize);
        cx.add_primitive("isize", Type::Isize);
        cx.add_primitive("f32", Type::Float { bits: 32 });
        cx.add_primitive("f64", Type::Float { bits: 64 });
        cx.add_primitive("void", Type::Void);
        cx.add_primitive("never", Type::Never);
        cx
    }

    fn add_primitive(&mut self, name: &str, ty: Type) {
        let id = self.intern(ty);
        self.primitive_names.insert(name.to_string(), id);
    }

    pub fn primitive(&self, name: &str) -> Option<TypeId> {
        self.primitive_names.get(name).copied()
    }

    pub fn intern(&mut self, ty: Type) -> TypeId {
        if let Some(id) = self.interned.get(&ty) {
            return *id;
        }
        let id = self.types.len();
        self.types.push(ty.clone());
        self.interned.insert(ty, id);
        id
    }

    pub fn add_struct_placeholder(&mut self, name: String) -> (StructId, TypeId) {
        let struct_id = self.structs.len();
        self.structs.push(StructType {
            defining_module: name
                .rsplit_once("::")
                .map_or("", |(module, _)| module)
                .into(),
            name,
            opaque: false,
            transparent_integer: None,
            fields: Vec::new(),
            packed: false,
            requested_align: None,
            layout: Layout { size: 0, align: 1 },
        });
        let ty = self.intern(Type::Struct(struct_id));
        (struct_id, ty)
    }

    pub fn add_enum_placeholder(&mut self, name: String) -> (EnumId, TypeId) {
        let enum_id = self.enums.len();
        self.enums.push(EnumType {
            name,
            variants: Vec::new(),
            tag_size: 1,
            payload_offset: 1,
            layout: Layout { size: 1, align: 1 },
        });
        let ty = self.intern(Type::Enum(enum_id));
        (enum_id, ty)
    }

    pub fn layout(&self, ty: TypeId) -> Layout {
        self.checked_layout(ty).expect("validated type layout")
    }

    /// Source checking validates every array, including arrays behind pointers,
    /// before storage or a native address operation consumes its layout.
    pub fn checked_layout(&self, ty: TypeId) -> Result<Layout, &'static str> {
        self.checked_layout_at(ty, 0)
    }

    fn checked_layout_at(&self, ty: TypeId, depth: usize) -> Result<Layout, &'static str> {
        if depth > self.types.len() {
            return Err("recursive array layout");
        }
        let layout = match self.types.get(ty).ok_or("invalid layout type")? {
            Type::Bool | Type::Int { bits: 8, .. } => Layout { size: 1, align: 1 },
            Type::Int { bits: 16, .. } => Layout { size: 2, align: 2 },
            Type::Int { bits: 32, .. } | Type::Float { bits: 32 } => Layout { size: 4, align: 4 },
            Type::Int { bits: 64, .. }
            | Type::Float { bits: 64 }
            | Type::Usize
            | Type::Isize
            | Type::Pointer { .. }
            | Type::Function { .. } => Layout { size: 8, align: 8 },
            Type::Int { .. } | Type::Float { .. } => return Err("invalid primitive layout width"),
            Type::Void | Type::Never => Layout { size: 0, align: 1 },
            Type::Array { element, len } => {
                let element = self.checked_layout_at(*element, depth + 1)?;
                Layout {
                    size: element
                        .size
                        .checked_mul(*len)
                        .ok_or("array layout overflows u64")?,
                    align: element.align,
                }
            }
            Type::Struct(id) => {
                let definition = self.structs.get(*id).ok_or("invalid struct layout")?;
                for field in &definition.fields {
                    self.checked_layout_at(field.ty, depth + 1)?;
                }
                definition.layout
            }
            Type::Enum(id) => {
                let definition = self.enums.get(*id).ok_or("invalid enum layout")?;
                for ty in definition
                    .variants
                    .iter()
                    .flat_map(|variant| &variant.payload)
                {
                    self.checked_layout_at(*ty, depth + 1)?;
                }
                definition.layout
            }
        };
        if layout.align == 0 || !layout.align.is_power_of_two() {
            return Err("invalid layout alignment");
        }
        Ok(layout)
    }

    pub fn name(&self, ty: TypeId) -> String {
        match &self.types[ty] {
            Type::Bool => "bool".into(),
            Type::Int { signed, bits } => format!("{}{}", if *signed { 'i' } else { 'u' }, bits),
            Type::Usize => "usize".into(),
            Type::Isize => "isize".into(),
            Type::Float { bits } => format!("f{bits}"),
            Type::Void => "void".into(),
            Type::Never => "never".into(),
            Type::Pointer { mutable, pointee } => format!(
                "*{} {}",
                if *mutable { "mut" } else { "const" },
                self.name(*pointee)
            ),
            Type::Array { element, len } => format!("[{}; {len}]", self.name(*element)),
            Type::Struct(id) => self.structs[*id].name.clone(),
            Type::Enum(id) => self.enums[*id].name.clone(),
            Type::Function {
                params,
                result,
                abi,
            } => format!(
                "extern {:?} fn({}) -> {}",
                abi,
                params
                    .iter()
                    .map(|p| self.name(*p))
                    .collect::<Vec<_>>()
                    .join(", "),
                self.name(*result)
            ),
        }
    }

    pub fn is_integer(&self, ty: TypeId) -> bool {
        matches!(self.types[ty], Type::Int { .. } | Type::Usize | Type::Isize)
    }

    pub fn is_float(&self, ty: TypeId) -> bool {
        matches!(self.types[ty], Type::Float { .. })
    }

    pub fn is_scalar(&self, ty: TypeId) -> bool {
        matches!(
            self.types[ty],
            Type::Bool
                | Type::Int { .. }
                | Type::Usize
                | Type::Isize
                | Type::Float { .. }
                | Type::Pointer { .. }
                | Type::Function { .. }
        )
    }

    pub fn transparent_integer_repr(&self, ty: TypeId) -> Option<TypeId> {
        let Type::Struct(id) = self.types[ty] else {
            return None;
        };
        self.structs[id].transparent_integer
    }

    /// Values admitted to scalar storage/SSA, without granting scalar operators.
    pub fn is_value_scalar(&self, ty: TypeId) -> bool {
        self.is_scalar(ty) || self.transparent_integer_repr(ty).is_some()
    }

    pub fn is_call_scalar(&self, ty: TypeId, abi: Abi) -> bool {
        self.is_scalar(ty) || (abi == Abi::OCore && self.transparent_integer_repr(ty).is_some())
    }

    /// Machine-width queries use this only after nominal type validation.
    pub fn value_representation(&self, ty: TypeId) -> TypeId {
        self.transparent_integer_repr(ty).unwrap_or(ty)
    }

    pub fn contains_transparent_integer(&self, ty: TypeId) -> bool {
        fn visit(
            types: &TypeContext,
            ty: TypeId,
            seen: &mut std::collections::HashSet<TypeId>,
        ) -> bool {
            if !seen.insert(ty) {
                return false;
            }
            if types.transparent_integer_repr(ty).is_some() {
                return true;
            }
            match &types.types[ty] {
                Type::Array { element, .. } => visit(types, *element, seen),
                Type::Struct(id) => types.structs[*id]
                    .fields
                    .iter()
                    .any(|field| visit(types, field.ty, seen)),
                Type::Enum(id) => types.enums[*id]
                    .variants
                    .iter()
                    .flat_map(|variant| &variant.payload)
                    .any(|ty| visit(types, *ty, seen)),
                Type::Function { params, result, .. } => params
                    .iter()
                    .chain(std::iter::once(result))
                    .any(|ty| visit(types, *ty, seen)),
                // Reinterpreting raw pointers remains an explicit unsafe boundary.
                _ => false,
            }
        }
        visit(self, ty, &mut std::collections::HashSet::new())
    }

    pub fn callback_cast_preserves_identity(&self, from: TypeId, to: TypeId) -> bool {
        from == to
            || !(matches!(self.types[from], Type::Function { .. })
                && matches!(self.types[to], Type::Function { .. })
                && (self.contains_transparent_integer(from)
                    || self.contains_transparent_integer(to)))
    }
}

impl Default for TypeContext {
    fn default() -> Self {
        Self::new()
    }
}

pub fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

#[derive(Debug, Clone, Default)]
pub struct ItemAttrs {
    pub export: bool,
    pub no_mangle: bool,
    pub link_section: Option<String>,
    pub align: Option<u64>,
    pub used: bool,
    pub packed: bool,
    pub interrupt: bool,
    pub naked: bool,
    pub unsafe_linkage: bool,
    pub opaque: bool,
    pub transparent: bool,
}

#[derive(Debug, Clone)]
pub struct HirProgram {
    pub types: TypeContext,
    pub functions: Vec<HirFunction>,
    pub statics: Vec<HirStatic>,
    pub consts: Vec<HirConst>,
    pub symbols: HashMap<String, Symbol>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbol {
    Function(FunctionId),
    Static(StaticId),
    Const(ConstId),
    Type(TypeId),
}

#[derive(Debug, Clone)]
pub struct HirFunction {
    pub qualified_name: String,
    pub symbol: String,
    pub attrs: ItemAttrs,
    pub public: bool,
    pub unsafe_: bool,
    pub abi: Abi,
    pub params: Vec<LocalId>,
    pub result: TypeId,
    pub locals: Vec<HirLocal>,
    pub body: Option<HirBlock>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct HirLocal {
    pub name: String,
    pub ty: TypeId,
    pub mutable: bool,
    pub parameter: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct HirStatic {
    pub qualified_name: String,
    pub symbol: String,
    pub attrs: ItemAttrs,
    pub public: bool,
    pub mutable: bool,
    pub ty: TypeId,
    pub init: HirConstValue,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct HirConst {
    pub qualified_name: String,
    pub ty: TypeId,
    pub value: HirConstValue,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HirConstValue {
    /// Checker-only state; never an implicit source or runtime zero value.
    Unevaluated,
    Integer(u64),
    /// A relocatable code address, not a host-sized numeric address.
    Function(FunctionId),
    Bool(bool),
    Bytes(Vec<u8>),
    Array(Vec<HirConstValue>),
    Repeat(Box<HirConstValue>, u64),
    Struct(StructId, Vec<HirConstValue>),
    Enum(EnumId, usize, Vec<HirConstValue>),
    Zero,
}

#[derive(Debug, Clone)]
pub struct HirBlock {
    pub stmts: Vec<HirStmt>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct HirStmt {
    pub kind: HirStmtKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum HirStmtKind {
    Let {
        local: LocalId,
        init: HirExpr,
    },
    Expr(HirExpr),
    If {
        condition: HirExpr,
        then_block: HirBlock,
        else_block: Option<HirBlock>,
    },
    While {
        condition: HirExpr,
        body: HirBlock,
    },
    Loop(HirBlock),
    Unsafe(HirBlock),
    Return(Option<HirExpr>),
    Break,
    Continue,
}

#[derive(Debug, Clone)]
pub struct HirExpr {
    pub kind: HirExprKind,
    pub ty: TypeId,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum HirExprKind {
    Constant(HirConstValue),
    Local(LocalId),
    Static(StaticId),
    Function(FunctionId),
    EnumVariant {
        enum_id: EnumId,
        variant: usize,
        args: Vec<HirExpr>,
    },
    Array(Vec<HirExpr>),
    ArrayRepeat {
        value: Box<HirExpr>,
        len: u64,
    },
    Struct {
        struct_id: StructId,
        /// Declaration index plus initializer, retained in source order.
        fields: Vec<(usize, HirExpr)>,
    },
    Unary {
        op: UnaryOp,
        operand: Box<HirExpr>,
    },
    Binary {
        op: BinaryOp,
        lhs: Box<HirExpr>,
        rhs: Box<HirExpr>,
    },
    Assign {
        op: Option<BinaryOp>,
        target: Box<HirExpr>,
        value: Box<HirExpr>,
    },
    Call {
        function: FunctionId,
        args: Vec<HirExpr>,
    },
    CallIndirect {
        callee: Box<HirExpr>,
        args: Vec<HirExpr>,
    },
    Intrinsic {
        intrinsic: Intrinsic,
        args: Vec<HirExpr>,
    },
    Field {
        base: Box<HirExpr>,
        field: usize,
        offset: u64,
    },
    Index {
        base: Box<HirExpr>,
        index: Box<HirExpr>,
    },
    Cast {
        value: Box<HirExpr>,
        to: TypeId,
    },
    Asm(HirAsm),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intrinsic {
    VolatileLoad,
    VolatileStore,
    AtomicLoad,
    AtomicStore,
    AtomicExchange,
    AtomicCompareExchange,
    AtomicFetchAdd,
    In8,
    In16,
    In32,
    Out8,
    Out16,
    Out32,
    EnableInterrupts,
    DisableInterrupts,
    Halt,
    InvalidatePage,
    Syscall(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryOrder {
    Relaxed = 0,
    Acquire = 1,
    Release = 2,
    AcqRel = 3,
    SeqCst = 4,
}

#[derive(Debug, Clone)]
pub struct HirAsm {
    pub template: String,
    pub operands: Vec<HirAsmOperand>,
    pub options: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum HirAsmOperand {
    In {
        register: String,
        value: HirExpr,
    },
    Out {
        register: String,
        target: HirExpr,
    },
    InOut {
        register: String,
        input: HirExpr,
        output: HirExpr,
    },
}
