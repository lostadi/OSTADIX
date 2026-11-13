//! Syntax-only boundary for complete configured assembly inputs.
//!
//! This module has NO MachineBody conversion, native admission, interpreter or
//! emitter. Recognizing an opcode/operand does not establish instruction meaning.
//! Typed syntax does not validate every ISA encoding/operand legality rule; a
//! future checked semantic lifter must do that before creating MachineBody.
//! The separately selected inventory is a coverage floor, not authenticated
//! original-source completeness. Unknown constructs remain explicit problems;
//! their records must still occur in that floor. Original bytes are retained.
use super::common::Target;
use super::native_machine_ir::{
    Architecture, ArtifactIdentity, ByteOrder, MachineAbi, MachineProfile, OriginalSpan,
    PhysicalRegister, RegisterView, SourceSpan, SourceWitness, StateFeature, X86Gpr, SOURCE_FORMAT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SYNTAX_INVENTORY_FORMAT: &str = "ocore-selected-assembly-syntax-inventory-v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxKind {
    Instruction,
    Label,
    Cfi,
    Alignment,
    Symbol,
    Data,
    Relocation,
    Section,
    Debug,
    Preprocessor,
    Macro,
    UnknownDirective,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequiredRecord {
    pub id: u64,
    pub kind: SyntaxKind,
    pub span: SourceSpan,
    pub origins: Vec<OriginalSpan>,
}
/// Supplied independently as exact JSON bytes; never synthesized from successes.
/// Its externally selected identity is intentionally outside this JSON value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyntaxInventory {
    pub format: String,
    pub source: SourceWitness,
    pub profile: MachineProfile,
    pub records: Vec<RequiredRecord>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadSelection {
    pub source: SourceWitness,
    pub profile: MachineProfile,
    pub inventory: ArtifactIdentity,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    Identity(String),
    Profile(String),
    Inventory(String),
    Lexical { span: SourceSpan, reason: String },
}
impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ReadError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Backward,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relocation {
    GotPcRel,
    GotPcRelX,
    RexGotPcRelX,
    Got,
    Plt,
    TpOff,
    GpOff,
    PcRelHi,
    PcRelLo,
    Hi,
    Lo,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExprAtom {
    Integer(i128),
    Symbol(String),
    CurrentLocation,
    NumericLabel { number: u64, direction: Direction },
    Relocation { kind: Relocation, symbol: String },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddSub {
    Add,
    Subtract,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expression {
    pub first: ExprAtom,
    pub rest: Vec<(AddSub, ExprAtom)>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    Fs,
    Gs,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    X86 {
        segment: Option<Segment>,
        displacement: Expression,
        base: Option<RegisterView>,
        index: Option<RegisterView>,
        scale: u8,
    },
    Aarch64 {
        base: RegisterView,
        offset: Option<Expression>,
        writeback: bool,
    },
    Riscv {
        base: RegisterView,
        displacement: Expression,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftKind {
    LogicalLeft,
    LogicalRight,
    ArithmeticRight,
    RotateRight,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Register(RegisterView),
    ZeroRegister { bits: u16 },
    Immediate(Expression),
    Address(Address),
    Expression(Expression),
    String(Vec<u8>),
    Indirect(Box<Operand>),
    Shift { kind: ShiftKind, amount: u8 },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    Equal,
    NotEqual,
    Above,
    AboveEqual,
    Below,
    BelowEqual,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    Overflow,
    NoOverflow,
    Sign,
    NoSign,
    Parity,
    NoParity,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Opcode {
    Move,
    Lea,
    Add,
    Subtract,
    Xor,
    And,
    Or,
    Compare,
    Test,
    Push,
    Pop,
    Call,
    Jump,
    Return,
    RotateLeft,
    RotateRight,
    ShiftLeft,
    ShiftRight,
    ShiftArithmeticRight,
    Nop,
    ConditionalJump(Condition),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aarch64Opcode {
    Move,
    StorePair,
    LoadPair,
    Store,
    Load,
    Add,
    Subtract,
    And,
    Or,
    Xor,
    Compare,
    Test,
    Branch,
    BranchRegister,
    BranchLinkRegister,
    Return,
    CompareBranchZero,
    CompareBranchNonzero,
    TestBranchZero,
    TestBranchNonzero,
    Nop,
    ConditionalBranch(Condition),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiscvOpcode {
    LoadDouble,
    StoreDouble,
    LoadWord,
    StoreWord,
    LoadByteSigned,
    LoadByteUnsigned,
    LoadHalfSigned,
    LoadHalfUnsigned,
    StoreByte,
    StoreHalf,
    LoadFloatDouble,
    StoreFloatDouble,
    Move,
    LoadImmediate,
    AddImmediate,
    Add,
    Subtract,
    And,
    Or,
    Xor,
    ShiftLeftImmediate,
    ShiftRightImmediate,
    Jump,
    JumpRegister,
    JumpAndLink,
    BranchEqual,
    BranchNotEqual,
    BranchZero,
    BranchNonzero,
    Return,
    Nop,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    X86 {
        operation: X86Opcode,
        width: Option<u16>,
    },
    Aarch64(Aarch64Opcode),
    Riscv(RiscvOpcode),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Text,
    Data,
    Bss,
    Named,
    Push,
    Pop,
    Previous,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    Progbits,
    Nobits,
    Note,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentKind {
    Align,
    ByteAlign,
    PowerOfTwo,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    Global,
    Hidden,
    Weak,
    Local,
    Protected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    Function,
    Object,
    Notype,
    TlsObject,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cfi {
    Start {
        simple: bool,
    },
    End,
    DefCfa {
        register: RegisterView,
        offset: i64,
    },
    DefCfaRegister(RegisterView),
    DefCfaOffset(i64),
    Offset {
        register: RegisterView,
        offset: i64,
        relative: bool,
    },
    Restore(RegisterView),
    AdjustCfaOffset(i64),
    RememberState,
    RestoreState,
    ReturnColumn(RegisterView),
    SignalFrame,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    Section {
        kind: SectionKind,
        name: Option<String>,
        flags: Option<Vec<u8>>,
        section_type: Option<SectionType>,
        subsection: Option<u64>,
    },
    Alignment {
        kind: AlignmentKind,
        boundary: Expression,
        fill: Option<Expression>,
        maximum_skip: Option<Expression>,
    },
    Binding {
        kind: Binding,
        names: Vec<String>,
    },
    SymbolType {
        name: String,
        kind: SymbolType,
    },
    Size {
        name: String,
        size: Expression,
    },
    Assignment {
        name: String,
        value: Expression,
        equ: bool,
    },
    Integers {
        element_bytes: u8,
        values: Vec<Expression>,
    },
    Space {
        count: Expression,
        fill: Option<Expression>,
    },
    Strings {
        values: Vec<Vec<u8>>,
        nul_terminated: bool,
    },
    Cfi(Cfi),
    File {
        number: Option<u64>,
        path: Vec<u8>,
    },
    Location {
        file: u64,
        line: u64,
        column: u64,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Label {
    Named(String),
    Numeric(u64),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Syntax {
    Instruction {
        opcode: Opcode,
        operands: Vec<Operand>,
    },
    Label(Label),
    Directive(Directive),
    PreprocessorMarker {
        line: u64,
        path: Vec<u8>,
        flags: Vec<u8>,
    },
    Unsupported,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemKind {
    UnsupportedInstruction,
    UnsupportedDirective,
    UnexpandedMacroOrConditional,
    UnsupportedPreprocessor,
    Operand,
    DuplicateLabel,
    UnresolvedNumericLabel,
    UndeclaredStateFeature,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub record: usize,
    pub kind: ProblemKind,
    pub reason: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRecord {
    pub required: RequiredRecord,
    pub syntax: Syntax,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coverage {
    Trivia(SourceSpan),
    Record { index: usize, span: SourceSpan },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelUse {
    pub record: usize,
    pub number: u64,
    pub direction: Direction,
    pub definition: Option<usize>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAssembly {
    pub original: Vec<u8>,
    pub selected_inventory: ArtifactIdentity,
    pub source: SourceWitness,
    pub profile: MachineProfile,
    pub records: Vec<ParsedRecord>,
    pub coverage: Vec<Coverage>,
    pub label_uses: Vec<LabelUse>,
    pub problems: Vec<Problem>,
    pub required_syntax_features: Vec<StateFeature>,
    pub coverage_relative_to_selected_inventory: bool,
    pub syntax_supported: bool,
    pub original_source_authenticated: bool,
    pub selected_floor_authority_authenticated: bool,
    pub original_unit_completeness_qualified: bool,
    pub instruction_semantics_lifted: bool,
    pub machine_body_admitted: bool,
    pub provider_qualified: bool,
    pub native_qualified: bool,
    pub runtime_qualified: bool,
    pub isa_equivalence_qualified: bool,
}

fn identity(bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}
fn identity_shape(value: &ArtifactIdentity) -> bool {
    value.sha256.len() == 64
        && value
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn span(start: usize, end: usize) -> SourceSpan {
    SourceSpan {
        start: start as u64,
        end: end as u64,
    }
}
fn profile(selection: &ReadSelection, target: Target) -> Result<(), ReadError> {
    let p = &selection.profile;
    let ok = match target {
        Target::X86_64UnknownNone => {
            p.architecture == Architecture::X86_64 && p.abi == MachineAbi::SysvAmd64
        }
        Target::Aarch64UnknownNone => {
            p.architecture == Architecture::Aarch64 && p.abi == MachineAbi::Aapcs64
        }
        Target::Riscv64UnknownNone => {
            p.architecture == Architecture::Rv64
                && matches!(p.abi, MachineAbi::RiscvLp64 | MachineAbi::RiscvLp64d)
        }
    };
    if !ok || p.address_bits != 64 || p.byte_order != ByteOrder::Little {
        return Err(ReadError::Profile("selected architecture/ABI/byte order does not match the canonical target; 32-bit foundations unsupported".into()));
    }
    if p.entry_stack_alignment == 0
        || !p.entry_stack_alignment.is_power_of_two()
        || p.entry_stack_remainder >= p.entry_stack_alignment
    {
        return Err(ReadError::Profile(
            "invalid selected entry stack shape".into(),
        ));
    }
    let unique: BTreeSet<_> = p.features.iter().collect();
    if unique.len() != p.features.len() {
        return Err(ReadError::Profile(
            "duplicate selected state feature".into(),
        ));
    }
    Ok(())
}
fn check_floor(
    bytes: &[u8],
    selection: &ReadSelection,
    raw: &[u8],
) -> Result<SyntaxInventory, ReadError> {
    if !identity_shape(&selection.inventory) || identity(raw) != selection.inventory {
        return Err(ReadError::Identity(
            "consumed inventory bytes differ from selected identity".into(),
        ));
    }
    if selection.source.format != SOURCE_FORMAT
        || selection.source.unit_id.is_empty()
        || !identity_shape(&selection.source.decoded_assembly)
        || identity(bytes) != selection.source.decoded_assembly
    {
        return Err(ReadError::Identity(
            "consumed assembly differs from selected configured input".into(),
        ));
    }
    if !identity_shape(&selection.source.build_configuration)
        || !identity_shape(&selection.source.frontend_event)
    {
        return Err(ReadError::Identity(
            "missing selected build/frontend identity".into(),
        ));
    }
    let inventory: SyntaxInventory = serde_json::from_slice(raw)
        .map_err(|e| ReadError::Inventory(format!("invalid typed inventory JSON: {e}")))?;
    if inventory.format != SYNTAX_INVENTORY_FORMAT
        || inventory.source != selection.source
        || inventory.profile != selection.profile
    {
        return Err(ReadError::Inventory(
            "inventory source/profile does not equal independent selection".into(),
        ));
    }
    let mut files = BTreeMap::new();
    let mut paths = BTreeSet::new();
    for f in &selection.source.files {
        if f.logical_path.is_empty()
            || f.logical_path.starts_with('/')
            || f.logical_path.contains(['\\', '\0'])
            || f.logical_path
                .split('/')
                .any(|x| x.is_empty() || x == "." || x == "..")
            || !identity_shape(&f.identity)
            || files.insert(f.id, f.identity.bytes).is_some()
            || !paths.insert(&f.logical_path)
        {
            return Err(ReadError::Inventory(
                "invalid or duplicate selected original file claim".into(),
            ));
        }
    }
    if files.is_empty() || inventory.records.is_empty() {
        return Err(ReadError::Inventory(
            "empty required original-file or syntax inventory".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    let mut end = 0;
    for item in &inventory.records {
        if !ids.insert(item.id)
            || item.span.start < end
            || item.span.end <= item.span.start
            || item.span.end > bytes.len() as u64
            || item.origins.is_empty()
        {
            return Err(ReadError::Inventory(
                "duplicate, overlapping, out-of-range or origin-less required record".into(),
            ));
        }
        for o in &item.origins {
            if o.span.end <= o.span.start
                || !files.get(&o.file).is_some_and(|size| o.span.end <= *size)
            {
                return Err(ReadError::Inventory(
                    "required record origin outside selected original file".into(),
                ));
            }
        }
        end = item.span.end;
    }
    Ok(inventory)
}

fn cpp_line(bytes: &[u8], i: usize) -> bool {
    let line_start = bytes[..i]
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |p| p + 1);
    if bytes[line_start..i]
        .iter()
        .any(|b| !b.is_ascii_whitespace())
    {
        return false;
    }
    let rest = &bytes[i + 1..];
    let n = rest
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    let r = &rest[n..];
    r.first().is_some_and(u8::is_ascii_digit)
        || [
            b"line".as_slice(),
            b"include",
            b"define",
            b"undef",
            b"if",
            b"else",
            b"endif",
            b"error",
            b"pragma",
        ]
        .iter()
        .any(|k| r.starts_with(k))
}
/// Comment masking preserves byte positions. Unterminated quotes/comments are
/// lexical failures rather than dropped tails. Delimiters inside quotes survive.
fn statements(
    bytes: &[u8],
    architecture: Architecture,
) -> Result<Vec<(SourceSpan, String)>, ReadError> {
    std::str::from_utf8(bytes).map_err(|e| ReadError::Lexical {
        span: span(e.valid_up_to(), bytes.len()),
        reason: "configured text is not UTF-8".into(),
    })?;
    let mut clean = bytes.to_vec();
    let mut i = 0;
    let mut quote = false;
    while i < bytes.len() {
        if bytes[i] == 0 {
            return Err(ReadError::Lexical {
                span: span(i, i + 1),
                reason: "NUL in configured assembly".into(),
            });
        }
        if quote {
            if bytes[i] == b'\\' {
                i += 1;
                if i >= bytes.len() {
                    break;
                }
            } else if bytes[i] == b'"' {
                quote = false;
            }
            i += 1;
            continue;
        }
        if bytes[i] == b'"' {
            quote = true;
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            let start = i;
            clean[i] = b' ';
            clean[i + 1] = b' ';
            i += 2;
            while i + 1 < bytes.len() && !bytes[i..].starts_with(b"*/") {
                if bytes[i] != b'\n' {
                    clean[i] = b' ';
                }
                i += 1;
            }
            if i + 1 >= bytes.len() {
                return Err(ReadError::Lexical {
                    span: span(start, bytes.len()),
                    reason: "unterminated block comment".into(),
                });
            }
            clean[i] = b' ';
            clean[i + 1] = b' ';
            i += 2;
            continue;
        }
        let comment =
            (bytes[i] == b'#' && architecture != Architecture::Aarch64 && !cpp_line(bytes, i))
                || (architecture == Architecture::Aarch64 && bytes[i..].starts_with(b"//"));
        if comment {
            while i < bytes.len() && bytes[i] != b'\n' {
                clean[i] = b' ';
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    if quote {
        return Err(ReadError::Lexical {
            span: span(0, bytes.len()),
            reason: "unterminated string".into(),
        });
    }
    let mut result = Vec::new();
    let mut start = 0;
    let mut quote = false;
    let mut escaped = false;
    let mut depths = (0i64, 0i64);
    let emit = |start: usize, end: usize, out: &mut Vec<(SourceSpan, String)>| {
        let mut a = start;
        let mut b = end;
        while a < b && clean[a].is_ascii_whitespace() {
            a += 1;
        }
        while b > a && clean[b - 1].is_ascii_whitespace() {
            b -= 1;
        }
        if a < b {
            out.push((
                span(a, b),
                String::from_utf8(clean[a..b].to_vec()).expect("masked UTF-8"),
            ));
        }
    };
    for (i, b) in clean.iter().copied().enumerate() {
        if quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quote = false;
            }
            continue;
        }
        if b == b'"' {
            quote = true;
            continue;
        }
        match b {
            b'(' => depths.0 += 1,
            b')' => depths.0 -= 1,
            b'[' => depths.1 += 1,
            b']' => depths.1 -= 1,
            _ => {}
        }
        if depths.0 < 0 || depths.1 < 0 {
            return Err(ReadError::Lexical {
                span: span(i, i + 1),
                reason: "unmatched closing operand delimiter".into(),
            });
        }
        if b == b':'
            && depths == (0, 0)
            && label_name(std::str::from_utf8(&clean[start..i]).unwrap().trim())
        {
            emit(start, i + 1, &mut result);
            start = i + 1;
        } else if b == b'\n' || (b == b';' && depths == (0, 0)) {
            if depths != (0, 0) {
                return Err(ReadError::Lexical {
                    span: span(start, i + 1),
                    reason: "operand delimiter crosses physical line".into(),
                });
            }
            emit(start, i, &mut result);
            start = i + 1;
        }
    }
    if depths != (0, 0) {
        return Err(ReadError::Lexical {
            span: span(start, bytes.len()),
            reason: "unterminated operand delimiter".into(),
        });
    }
    emit(start, clean.len(), &mut result);
    Ok(result)
}
fn symbol(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.$".contains(&b))
        && !s.as_bytes()[0].is_ascii_digit()
}
fn label_name(s: &str) -> bool {
    symbol(s) || (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}
fn integer(s: &str) -> Result<i128, String> {
    let s = s.trim();
    let (negative, s) = s.strip_prefix('-').map_or((false, s), |s| (true, s));
    let s = s.strip_prefix('+').unwrap_or(s);
    // GNU as integer grammar: leading zero denotes octal, 0b/0B binary,
    // 0x/0X hexadecimal, otherwise nonzero-leading decimal. Oversized and
    // invalid digits remain explicit unsupported syntax, never a new value.
    let (digits, radix, empty_binary_zero) =
        if let Some(v) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            (v, 16, false)
        } else if let Some(v) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
            (v, 2, true)
        } else if let Some(v) = s.strip_prefix('0') {
            (v, 8, true)
        } else {
            (s, 10, false)
        };
    let value = if digits.is_empty() && empty_binary_zero {
        0
    } else {
        i128::from_str_radix(digits, radix)
            .map_err(|_| "unsupported or overflowing GNU integer".to_string())?
    };
    if negative {
        value.checked_neg().ok_or_else(|| "integer overflow".into())
    } else {
        Ok(value)
    }
}
/// Numeric local labels use one decimal-digit identifier grammar in both
/// definition and reference contexts, independent of expression literal radix.
fn local_label_number(s: &str) -> Result<u64, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("not a decimal-digit numeric local label".into());
    }
    s.parse::<u64>()
        .map_err(|_| "numeric local label identifier exceeds supported u64 range".into())
}
fn atom(s: &str) -> Result<ExprAtom, String> {
    let s = s.trim();
    if s == "." {
        return Ok(ExprAtom::CurrentLocation);
    }
    // A complete digit-sequence plus lowercase f/b is a numeric label first.
    // In particular 0b is NOT the empty binary integer in expression context.
    // Nonempty 0b101 / uppercase 0B101 still follow integer literal grammar.
    if let Some(number) = s.strip_suffix('f').or_else(|| s.strip_suffix('b')) {
        if !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(ExprAtom::NumericLabel {
                number: local_label_number(number)?,
                direction: if s.ends_with('f') {
                    Direction::Forward
                } else {
                    Direction::Backward
                },
            });
        }
    }
    if let Ok(v) = integer(s) {
        return Ok(ExprAtom::Integer(v));
    }
    if let Some((name, modifier)) = s.rsplit_once('@') {
        let kind = match modifier.to_ascii_uppercase().as_str() {
            "GOTPCREL" => Relocation::GotPcRel,
            "GOTPCRELX" => Relocation::GotPcRelX,
            "REX_GOTPCRELX" => Relocation::RexGotPcRelX,
            "GOT" => Relocation::Got,
            "PLT" => Relocation::Plt,
            "TPOFF" => Relocation::TpOff,
            "GPOFF" => Relocation::GpOff,
            _ => return Err("unsupported relocation modifier".into()),
        };
        if symbol(name) {
            return Ok(ExprAtom::Relocation {
                kind,
                symbol: name.into(),
            });
        }
    }
    for (prefix, kind) in [
        ("%pcrel_hi(", Relocation::PcRelHi),
        ("%pcrel_lo(", Relocation::PcRelLo),
        ("%hi(", Relocation::Hi),
        ("%lo(", Relocation::Lo),
    ] {
        if let Some(inner) = s.strip_prefix(prefix).and_then(|v| v.strip_suffix(')')) {
            if symbol(inner) {
                return Ok(ExprAtom::Relocation {
                    kind,
                    symbol: inner.into(),
                });
            }
            return Err("unsupported relocation expression".into());
        }
    }
    if symbol(s) {
        return Ok(ExprAtom::Symbol(s.into()));
    }
    Err("unsupported expression atom".into())
}
fn expression(s: &str) -> Result<Expression, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty expression".into());
    }
    let mut terms = Vec::new();
    let mut start = 0;
    let mut depth = 0i64;
    for (i, b) in s.bytes().enumerate() {
        if b == b'(' {
            depth += 1;
        }
        if b == b')' {
            depth -= 1;
        }
        if depth == 0 && i > start && (b == b'+' || b == b'-') {
            terms.push((&s[start..i], b));
            start = i + 1;
        }
    }
    if terms.is_empty() {
        return Ok(Expression {
            first: atom(s)?,
            rest: vec![],
        });
    }
    let first = atom(terms[0].0)?;
    let mut rest = Vec::new();
    for i in 0..terms.len() {
        let text = if i + 1 < terms.len() {
            terms[i + 1].0
        } else {
            &s[start..]
        };
        rest.push((
            if terms[i].1 == b'+' {
                AddSub::Add
            } else {
                AddSub::Subtract
            },
            atom(text)?,
        ));
    }
    Ok(Expression { first, rest })
}
fn split_operands(s: &str) -> Result<Vec<&str>, String> {
    if s.trim().is_empty() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    let mut start = 0;
    let mut quote = false;
    let mut escaped = false;
    let mut depth = 0i64;
    for (i, b) in s.bytes().enumerate() {
        if quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quote = false;
            }
            continue;
        }
        match b {
            b'"' => quote = true,
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                out.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(s[start..].trim());
    if quote || depth != 0 || out.iter().any(|x| x.is_empty()) {
        return Err("empty or unbalanced operand".into());
    }
    Ok(out)
}
fn string_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    let inner = s
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .ok_or("expected quoted string")?;
    let b = inner.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            if b[i] == b'"' {
                return Err("unescaped quote".into());
            }
            out.push(b[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i == b.len() {
            return Err("unfinished string escape".into());
        }
        let value = match b[i] {
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'b' => 8,
            b'f' => 12,
            b'v' => 11,
            b'\\' => b'\\',
            b'"' => b'"',
            b'0'..=b'7' => {
                let mut n = 0u16;
                let mut count = 0;
                while i < b.len() && count < 3 && (b'0'..=b'7').contains(&b[i]) {
                    n = n * 8 + (b[i] - b'0') as u16;
                    i += 1;
                    count += 1;
                }
                if n > 255 {
                    return Err("octal escape exceeds byte".into());
                }
                out.push(n as u8);
                continue;
            }
            _ => return Err("unsupported string escape".into()),
        };
        out.push(value);
        i += 1;
    }
    Ok(out)
}
fn view(register: PhysicalRegister, bits: u16) -> RegisterView {
    RegisterView {
        register,
        low_bit: 0,
        bits,
    }
}
fn register(s: &str, architecture: Architecture) -> Option<RegisterView> {
    let s = s.trim();
    // Fixed GNU default AT&T dialect: bare names such as rax/xmm0 are symbols.
    // .intel_syntax / .att_syntax noprefix are unsupported unit records, not
    // permission to change operand interpretation implicitly.
    if architecture == Architecture::X86_64 && !s.starts_with('%') {
        return None;
    }
    let s = s.strip_prefix('%').unwrap_or(s).to_ascii_lowercase();
    match architecture {
        Architecture::X86_64 => {
            for (i, names) in [
                ["rax", "eax", "ax", "al", "ah"],
                ["rbx", "ebx", "bx", "bl", "bh"],
                ["rcx", "ecx", "cx", "cl", "ch"],
                ["rdx", "edx", "dx", "dl", "dh"],
                ["rsi", "esi", "si", "sil", ""],
                ["rdi", "edi", "di", "dil", ""],
                ["rbp", "ebp", "bp", "bpl", ""],
                ["rsp", "esp", "sp", "spl", ""],
            ]
            .iter()
            .enumerate()
            {
                if let Some(j) = names.iter().position(|n| !n.is_empty() && *n == s) {
                    let name = [
                        X86Gpr::Rax,
                        X86Gpr::Rbx,
                        X86Gpr::Rcx,
                        X86Gpr::Rdx,
                        X86Gpr::Rsi,
                        X86Gpr::Rdi,
                        X86Gpr::Rbp,
                        X86Gpr::Rsp,
                    ][i];
                    return Some(RegisterView {
                        register: PhysicalRegister::X86Gpr { name },
                        low_bit: if j == 4 { 8 } else { 0 },
                        bits: [64, 32, 16, 8, 8][j],
                    });
                }
            }
            if s == "rip" {
                return Some(view(PhysicalRegister::X86Pc, 64));
            }
            if let Some(v) = s
                .strip_prefix("xmm")
                .and_then(|s| s.parse::<u8>().ok())
                .filter(|i| *i < 16)
            {
                return Some(view(PhysicalRegister::X86Xmm { index: v }, 128));
            }
            for i in 8..=15 {
                for (suffix, bits) in [("", 64), ("d", 32), ("w", 16), ("b", 8)] {
                    if s == format!("r{i}{suffix}") {
                        let name = [
                            X86Gpr::R8,
                            X86Gpr::R9,
                            X86Gpr::R10,
                            X86Gpr::R11,
                            X86Gpr::R12,
                            X86Gpr::R13,
                            X86Gpr::R14,
                            X86Gpr::R15,
                        ][i - 8];
                        return Some(view(PhysicalRegister::X86Gpr { name }, bits));
                    }
                }
            }
            None
        }
        Architecture::Aarch64 => {
            if s == "sp" || s == "wsp" {
                return Some(view(
                    PhysicalRegister::Aarch64Sp,
                    if s == "sp" { 64 } else { 32 },
                ));
            }
            if s == "lr" {
                return Some(view(PhysicalRegister::Aarch64Gpr { index: 30 }, 64));
            }
            if s == "fp" {
                return Some(view(PhysicalRegister::Aarch64Gpr { index: 29 }, 64));
            }
            for (prefix, bits, vector) in [
                ('x', 64, false),
                ('w', 32, false),
                ('q', 128, true),
                ('d', 64, true),
                ('s', 32, true),
                ('h', 16, true),
                ('b', 8, true),
            ] {
                if let Some(i) = s
                    .strip_prefix(prefix)
                    .and_then(|x| x.parse::<u8>().ok())
                    .filter(|i| *i < if vector { 32 } else { 31 })
                {
                    return Some(view(
                        if vector {
                            PhysicalRegister::Aarch64Vector { index: i }
                        } else {
                            PhysicalRegister::Aarch64Gpr { index: i }
                        },
                        bits,
                    ));
                }
            }
            None
        }
        Architecture::Rv64 => {
            if let Some(i) = s
                .strip_prefix('x')
                .and_then(|x| x.parse::<u8>().ok())
                .filter(|i| *i < 32)
            {
                return Some(view(PhysicalRegister::RiscvGpr { index: i }, 64));
            }
            if let Some(i) = s
                .strip_prefix('f')
                .and_then(|x| x.parse::<u8>().ok())
                .filter(|i| *i < 32)
            {
                return Some(view(PhysicalRegister::RiscvFpr { index: i }, 64));
            }
            let g = [
                "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2",
                "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9",
                "s10", "s11", "t3", "t4", "t5", "t6",
            ];
            if let Some(i) = g.iter().position(|x| *x == s) {
                return Some(view(PhysicalRegister::RiscvGpr { index: i as u8 }, 64));
            }
            if s == "fp" {
                return Some(view(PhysicalRegister::RiscvGpr { index: 8 }, 64));
            }
            let f = [
                "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1",
                "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7",
                "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
            ];
            f.iter()
                .position(|x| *x == s)
                .map(|i| view(PhysicalRegister::RiscvFpr { index: i as u8 }, 64))
        }
        _ => None,
    }
}
fn gp64(v: RegisterView, architecture: Architecture) -> bool {
    v.bits == 64
        && v.low_bit == 0
        && match architecture {
            Architecture::X86_64 => matches!(
                v.register,
                PhysicalRegister::X86Gpr { .. } | PhysicalRegister::X86Pc
            ),
            Architecture::Aarch64 => matches!(
                v.register,
                PhysicalRegister::Aarch64Gpr { .. } | PhysicalRegister::Aarch64Sp
            ),
            Architecture::Rv64 => matches!(v.register, PhysicalRegister::RiscvGpr { .. }),
            _ => false,
        }
}
fn operand(s: &str, a: Architecture) -> Result<Operand, String> {
    let s = s.trim();
    if let Some(v) = s.strip_prefix('*') {
        if a != Architecture::X86_64 {
            return Err("indirect marker is x86 AT&T syntax only".into());
        }
        return Ok(Operand::Indirect(Box::new(operand(v, a)?)));
    }
    if let Some(v) = s.strip_prefix('$') {
        if a == Architecture::X86_64 {
            return Ok(Operand::Immediate(expression(v)?));
        }
    }
    if let Some(v) = s.strip_prefix('#') {
        if a == Architecture::Aarch64 {
            return Ok(Operand::Immediate(expression(v)?));
        }
    }
    if s.starts_with('"') {
        return Ok(Operand::String(string_bytes(s)?));
    }
    if a == Architecture::Aarch64 && matches!(s, "xzr" | "wzr") {
        return Ok(Operand::ZeroRegister {
            bits: if s == "xzr" { 64 } else { 32 },
        });
    }
    if let Some(v) = register(s, a) {
        return Ok(Operand::Register(v));
    }
    if a == Architecture::Aarch64 {
        for (name, kind) in [
            ("lsl", ShiftKind::LogicalLeft),
            ("lsr", ShiftKind::LogicalRight),
            ("asr", ShiftKind::ArithmeticRight),
            ("ror", ShiftKind::RotateRight),
        ] {
            if let Some(v) = s.strip_prefix(name).and_then(|v| v.strip_prefix(' ')) {
                let n = integer(
                    v.trim()
                        .strip_prefix('#')
                        .ok_or("shift requires # amount")?,
                )?;
                return Ok(Operand::Shift {
                    kind,
                    amount: u8::try_from(n).map_err(|_| "shift amount outside byte range")?,
                });
            }
        }
        if s.starts_with('[') {
            let writeback = s.ends_with('!');
            let s = if writeback { &s[..s.len() - 1] } else { s };
            let inside = s
                .strip_prefix('[')
                .and_then(|v| v.strip_suffix(']'))
                .ok_or("malformed AArch64 address")?;
            let p = split_operands(inside)?;
            if !(1..=2).contains(&p.len()) {
                return Err("unsupported AArch64 register-offset address".into());
            }
            let base = register(p[0], a)
                .filter(|v| gp64(*v, a))
                .ok_or("AArch64 address requires a 64-bit GPR/SP")?;
            let offset = if p.len() == 2 {
                Some(expression(
                    p[1].strip_prefix('#').ok_or("address offset requires #")?,
                )?)
            } else {
                None
            };
            return Ok(Operand::Address(Address::Aarch64 {
                base,
                offset,
                writeback,
            }));
        }
    }
    let (segment, tail) = if a == Architecture::X86_64 {
        if let Some(v) = s.strip_prefix("%fs:") {
            (Some(Segment::Fs), v)
        } else if let Some(v) = s.strip_prefix("%gs:") {
            (Some(Segment::Gs), v)
        } else {
            (None, s)
        }
    } else {
        (None, s)
    };
    if tail.ends_with(')')
        && !tail.starts_with("%pcrel_")
        && !tail.starts_with("%hi(")
        && !tail.starts_with("%lo(")
    {
        if let Some((disp, args)) = tail.split_once('(') {
            let args = &args[..args.len() - 1];
            if a == Architecture::X86_64 {
                let p: Vec<_> = args.split(',').map(str::trim).collect();
                if p.is_empty() || p.len() > 3 {
                    return Err("malformed x86 address".into());
                }
                let base = if p[0].is_empty() {
                    None
                } else {
                    Some(
                        register(p[0], a)
                            .filter(|v| gp64(*v, a))
                            .ok_or("x86 base is not a 64-bit GPR/PC")?,
                    )
                };
                let index = if p.len() < 2 || p[1].is_empty() {
                    None
                } else {
                    Some(
                        register(p[1], a)
                            .filter(|v| {
                                gp64(*v, a)
                                    && !matches!(
                                        v.register,
                                        PhysicalRegister::X86Pc
                                            | PhysicalRegister::X86Gpr { name: X86Gpr::Rsp }
                                    )
                            })
                            .ok_or("x86 index is not a usable 64-bit GPR")?,
                    )
                };
                let scale = if p.len() == 3 {
                    u8::try_from(integer(p[2])?).map_err(|_| "invalid x86 scale")?
                } else {
                    1
                };
                if ![1, 2, 4, 8].contains(&scale)
                    || (index.is_none() && scale != 1)
                    || (base.is_none() && index.is_none())
                    || (base.is_some_and(|v| matches!(v.register, PhysicalRegister::X86Pc))
                        && index.is_some())
                {
                    return Err("invalid x86 scale/base/index combination".into());
                }
                return Ok(Operand::Address(Address::X86 {
                    segment,
                    displacement: expression(if disp.trim().is_empty() { "0" } else { disp })?,
                    base,
                    index,
                    scale,
                }));
            }
            if a == Architecture::Rv64 {
                let base = register(args, a)
                    .filter(|v| gp64(*v, a))
                    .ok_or("RISC-V address requires one GPR base")?;
                return Ok(Operand::Address(Address::Riscv {
                    base,
                    displacement: expression(if disp.trim().is_empty() { "0" } else { disp })?,
                }));
            }
        }
    }
    if let Some(segment) = segment {
        return Ok(Operand::Address(Address::X86 {
            segment: Some(segment),
            displacement: expression(tail)?,
            base: None,
            index: None,
            scale: 1,
        }));
    }
    if s.starts_with('%') && a == Architecture::X86_64 {
        return Err("unknown x86 register/address".into());
    }
    Ok(Operand::Expression(expression(s)?))
}
fn x86_condition(s: &str) -> Option<Condition> {
    Some(match s {
        "e" | "z" => Condition::Equal,
        "ne" | "nz" => Condition::NotEqual,
        "a" | "nbe" => Condition::Above,
        "ae" | "nb" | "nc" => Condition::AboveEqual,
        "b" | "c" | "nae" => Condition::Below,
        "be" | "na" => Condition::BelowEqual,
        "g" | "nle" => Condition::Greater,
        "ge" | "nl" => Condition::GreaterEqual,
        "l" | "nge" => Condition::Less,
        "le" | "ng" => Condition::LessEqual,
        "o" => Condition::Overflow,
        "no" => Condition::NoOverflow,
        "s" => Condition::Sign,
        "ns" => Condition::NoSign,
        "p" | "pe" => Condition::Parity,
        "np" | "po" => Condition::NoParity,
        _ => return None,
    })
}
fn aarch64_condition(s: &str) -> Option<Condition> {
    Some(match s {
        "eq" => Condition::Equal,
        "ne" => Condition::NotEqual,
        "hi" => Condition::Above,
        "hs" | "cs" => Condition::AboveEqual,
        "lo" | "cc" => Condition::Below,
        "ls" => Condition::BelowEqual,
        "gt" => Condition::Greater,
        "ge" => Condition::GreaterEqual,
        "lt" => Condition::Less,
        "le" => Condition::LessEqual,
        "vs" => Condition::Overflow,
        "vc" => Condition::NoOverflow,
        "mi" => Condition::Sign,
        "pl" => Condition::NoSign,
        _ => return None,
    })
}
fn opcode(m: &str, a: Architecture) -> Option<(Opcode, usize, usize)> {
    match a {
        Architecture::X86_64 => {
            if let Some(c) = m.strip_prefix('j').and_then(x86_condition) {
                return Some((
                    Opcode::X86 {
                        operation: X86Opcode::ConditionalJump(c),
                        width: None,
                    },
                    1,
                    1,
                ));
            }
            let (stem, width) = m
                .strip_suffix('b')
                .map(|s| (s, Some(8)))
                .or_else(|| m.strip_suffix('w').map(|s| (s, Some(16))))
                .or_else(|| m.strip_suffix('l').map(|s| (s, Some(32))))
                .or_else(|| m.strip_suffix('q').map(|s| (s, Some(64))))
                .unwrap_or((m, None));
            // Full names ending in a suffix letter must be recognized first.
            let (stem, width) = if ["call", "ret", "nop", "sub", "rol", "shl", "sal"].contains(&m) {
                (m, None)
            } else {
                (stem, width)
            };
            let (op, min, max) = match stem {
                "mov" => (X86Opcode::Move, 2, 2),
                "lea" => (X86Opcode::Lea, 2, 2),
                "add" => (X86Opcode::Add, 2, 2),
                "sub" => (X86Opcode::Subtract, 2, 2),
                "xor" => (X86Opcode::Xor, 2, 2),
                "and" => (X86Opcode::And, 2, 2),
                "or" => (X86Opcode::Or, 2, 2),
                "cmp" => (X86Opcode::Compare, 2, 2),
                "test" => (X86Opcode::Test, 2, 2),
                "push" => (X86Opcode::Push, 1, 1),
                "pop" => (X86Opcode::Pop, 1, 1),
                "call" => (X86Opcode::Call, 1, 1),
                "jmp" => (X86Opcode::Jump, 1, 1),
                "ret" => (X86Opcode::Return, 0, 1),
                "rol" => (X86Opcode::RotateLeft, 1, 2),
                "ror" => (X86Opcode::RotateRight, 1, 2),
                "shl" | "sal" => (X86Opcode::ShiftLeft, 1, 2),
                "shr" => (X86Opcode::ShiftRight, 1, 2),
                "sar" => (X86Opcode::ShiftArithmeticRight, 1, 2),
                "nop" => (X86Opcode::Nop, 0, 0),
                _ => return None,
            };
            Some((
                Opcode::X86 {
                    operation: op,
                    width,
                },
                min,
                max,
            ))
        }
        Architecture::Aarch64 => {
            if let Some(c) = m.strip_prefix("b.").and_then(aarch64_condition) {
                return Some((Opcode::Aarch64(Aarch64Opcode::ConditionalBranch(c)), 1, 1));
            }
            let (op, min, max) = match m {
                "mov" => (Aarch64Opcode::Move, 2, 2),
                "stp" => (Aarch64Opcode::StorePair, 3, 4),
                "ldp" | "ldpsw" => (Aarch64Opcode::LoadPair, 3, 4),
                "str" | "stur" | "strb" | "sturb" | "strh" | "sturh" => {
                    (Aarch64Opcode::Store, 2, 3)
                }
                "ldr" | "ldur" | "ldrb" | "ldurb" | "ldrh" | "ldurh" | "ldrsb" | "ldursb"
                | "ldrsh" | "ldursh" | "ldrsw" | "ldursw" => (Aarch64Opcode::Load, 2, 3),
                "add" | "adds" => (Aarch64Opcode::Add, 3, 4),
                "adc" | "adcs" => (Aarch64Opcode::Add, 3, 3),
                "sub" | "subs" => (Aarch64Opcode::Subtract, 3, 4),
                "sbc" | "sbcs" => (Aarch64Opcode::Subtract, 3, 3),
                "and" | "ands" => (Aarch64Opcode::And, 3, 4),
                "orr" => (Aarch64Opcode::Or, 3, 4),
                "eor" => (Aarch64Opcode::Xor, 3, 4),
                "cmp" | "cmn" => (Aarch64Opcode::Compare, 2, 3),
                "tst" => (Aarch64Opcode::Test, 2, 3),
                "b" => (Aarch64Opcode::Branch, 1, 1),
                "br" => (Aarch64Opcode::BranchRegister, 1, 1),
                "blr" => (Aarch64Opcode::BranchLinkRegister, 1, 1),
                "ret" => (Aarch64Opcode::Return, 0, 1),
                "cbz" => (Aarch64Opcode::CompareBranchZero, 2, 2),
                "cbnz" => (Aarch64Opcode::CompareBranchNonzero, 2, 2),
                "tbz" => (Aarch64Opcode::TestBranchZero, 3, 3),
                "tbnz" => (Aarch64Opcode::TestBranchNonzero, 3, 3),
                "nop" => (Aarch64Opcode::Nop, 0, 0),
                _ => return None,
            };
            Some((Opcode::Aarch64(op), min, max))
        }
        Architecture::Rv64 => {
            let (op, n) = match m {
                "ld" => (RiscvOpcode::LoadDouble, 2),
                "sd" => (RiscvOpcode::StoreDouble, 2),
                "lw" | "lwu" => (RiscvOpcode::LoadWord, 2),
                "sw" => (RiscvOpcode::StoreWord, 2),
                "lb" => (RiscvOpcode::LoadByteSigned, 2),
                "lbu" => (RiscvOpcode::LoadByteUnsigned, 2),
                "lh" => (RiscvOpcode::LoadHalfSigned, 2),
                "lhu" => (RiscvOpcode::LoadHalfUnsigned, 2),
                "sb" => (RiscvOpcode::StoreByte, 2),
                "sh" => (RiscvOpcode::StoreHalf, 2),
                "fld" => (RiscvOpcode::LoadFloatDouble, 2),
                "fsd" => (RiscvOpcode::StoreFloatDouble, 2),
                "mv" => (RiscvOpcode::Move, 2),
                "li" => (RiscvOpcode::LoadImmediate, 2),
                "addi" | "addiw" => (RiscvOpcode::AddImmediate, 3),
                "add" | "addw" => (RiscvOpcode::Add, 3),
                "sub" | "subw" => (RiscvOpcode::Subtract, 3),
                "and" | "andi" => (RiscvOpcode::And, 3),
                "or" | "ori" => (RiscvOpcode::Or, 3),
                "xor" | "xori" => (RiscvOpcode::Xor, 3),
                "slli" | "slliw" => (RiscvOpcode::ShiftLeftImmediate, 3),
                "srli" | "srai" | "srliw" | "sraiw" => (RiscvOpcode::ShiftRightImmediate, 3),
                "j" => (RiscvOpcode::Jump, 1),
                "jr" => (RiscvOpcode::JumpRegister, 1),
                "jalr" => (RiscvOpcode::JumpRegister, 3),
                "jal" => (RiscvOpcode::JumpAndLink, 2),
                "beq" => (RiscvOpcode::BranchEqual, 3),
                "bne" => (RiscvOpcode::BranchNotEqual, 3),
                "beqz" => (RiscvOpcode::BranchZero, 2),
                "bnez" => (RiscvOpcode::BranchNonzero, 2),
                "ret" => (RiscvOpcode::Return, 0),
                "nop" => (RiscvOpcode::Nop, 0),
                _ => return None,
            };
            Some((Opcode::Riscv(op), n, n))
        }
        _ => None,
    }
}
fn kind(text: &str) -> SyntaxKind {
    if text.ends_with(':') {
        return SyntaxKind::Label;
    }
    if text.starts_with('#') {
        return SyntaxKind::Preprocessor;
    }
    let m = text.split_whitespace().next().unwrap_or("");
    if m.starts_with(".cfi_") {
        SyntaxKind::Cfi
    } else if [".align", ".balign", ".p2align"].contains(&m) {
        SyntaxKind::Alignment
    } else if [
        ".globl",
        ".global",
        ".hidden",
        ".weak",
        ".local",
        ".protected",
        ".type",
        ".size",
        ".set",
        ".equ",
    ]
    .contains(&m)
    {
        SyntaxKind::Symbol
    } else if [
        ".quad", ".8byte", ".long", ".4byte", ".short", ".2byte", ".byte", ".zero", ".space",
        ".ascii", ".asciz", ".string",
    ]
    .contains(&m)
    {
        SyntaxKind::Data
    } else if m == ".reloc" {
        SyntaxKind::Relocation
    } else if [
        ".text",
        ".data",
        ".bss",
        ".section",
        ".pushsection",
        ".popsection",
        ".previous",
    ]
    .contains(&m)
    {
        SyntaxKind::Section
    } else if [".file", ".loc"].contains(&m) {
        SyntaxKind::Debug
    } else if [
        ".macro",
        ".endm",
        ".irp",
        ".irpc",
        ".rept",
        ".endr",
        ".if",
        ".ifdef",
        ".ifndef",
        ".elseif",
        ".else",
        ".endif",
        ".include",
        ".incbin",
        ".altmacro",
        ".purgem",
    ]
    .contains(&m)
    {
        SyntaxKind::Macro
    } else if m.starts_with('.') {
        SyntaxKind::UnknownDirective
    } else {
        SyntaxKind::Instruction
    }
}
fn words(s: &str) -> Result<Vec<&str>, String> {
    let mut out = Vec::new();
    let mut start = None;
    let mut quote = false;
    let mut escape = false;
    for (i, b) in s.bytes().enumerate() {
        if start.is_none() && !b.is_ascii_whitespace() {
            start = Some(i);
        }
        if quote {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                quote = false;
            }
        } else if b == b'"' {
            quote = true;
        } else if b.is_ascii_whitespace() {
            if let Some(a) = start.take() {
                out.push(&s[a..i]);
            }
        }
    }
    if quote {
        return Err("unclosed word string".into());
    }
    if let Some(a) = start {
        out.push(&s[a..]);
    }
    Ok(out)
}
fn unsigned(s: &str) -> Result<u64, String> {
    u64::try_from(integer(s)?).map_err(|_| "expected unsigned 64-bit value".into())
}
fn signed(s: &str) -> Result<i64, String> {
    i64::try_from(integer(s)?).map_err(|_| "expected signed 64-bit value".into())
}
fn name(s: &str) -> Result<String, String> {
    if symbol(s.trim()) {
        Ok(s.trim().into())
    } else {
        Err("expected assembler symbol".into())
    }
}
fn section_name(s: &str) -> Result<String, String> {
    let s = s.trim();
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.$-".contains(&b))
        && !s.as_bytes()[0].is_ascii_digit()
    {
        Ok(s.into())
    } else {
        Err("unsupported section name".into())
    }
}
fn cfi_register(s: &str, a: Architecture) -> Result<RegisterView, String> {
    if let Some(r) = register(s, a) {
        return Ok(r);
    }
    let n = unsigned(s)?;
    let r = match a {
        Architecture::X86_64 => {
            let names = [
                X86Gpr::Rax,
                X86Gpr::Rdx,
                X86Gpr::Rcx,
                X86Gpr::Rbx,
                X86Gpr::Rsi,
                X86Gpr::Rdi,
                X86Gpr::Rbp,
                X86Gpr::Rsp,
                X86Gpr::R8,
                X86Gpr::R9,
                X86Gpr::R10,
                X86Gpr::R11,
                X86Gpr::R12,
                X86Gpr::R13,
                X86Gpr::R14,
                X86Gpr::R15,
            ];
            if n < 16 {
                view(
                    PhysicalRegister::X86Gpr {
                        name: names[n as usize],
                    },
                    64,
                )
            } else if n == 16 {
                view(PhysicalRegister::X86Pc, 64)
            } else if (17..=32).contains(&n) {
                view(
                    PhysicalRegister::X86Xmm {
                        index: (n - 17) as u8,
                    },
                    128,
                )
            } else {
                return Err("unsupported x86 DWARF register".into());
            }
        }
        Architecture::Aarch64 => {
            if n < 31 {
                view(PhysicalRegister::Aarch64Gpr { index: n as u8 }, 64)
            } else if n == 31 {
                view(PhysicalRegister::Aarch64Sp, 64)
            } else if (64..96).contains(&n) {
                view(
                    PhysicalRegister::Aarch64Vector {
                        index: (n - 64) as u8,
                    },
                    128,
                )
            } else {
                return Err("unsupported AArch64 DWARF register".into());
            }
        }
        Architecture::Rv64 => {
            if n < 32 {
                view(PhysicalRegister::RiscvGpr { index: n as u8 }, 64)
            } else if n < 64 {
                view(
                    PhysicalRegister::RiscvFpr {
                        index: (n - 32) as u8,
                    },
                    64,
                )
            } else {
                return Err("unsupported RISC-V DWARF register".into());
            }
        }
        _ => return Err("unsupported architecture".into()),
    };
    Ok(r)
}
fn directive(m: &str, args: &str, a: Architecture) -> Result<Directive, String> {
    let p = split_operands(args)?;
    let exact = |n: usize| {
        if p.len() == n {
            Ok(())
        } else {
            Err("wrong directive operand count".to_string())
        }
    };
    let c = match m {
        ".cfi_startproc" => {
            if !p.is_empty() && !(p.len() == 1 && p[0] == "simple") {
                return Err("unsupported cfi_startproc argument".into());
            }
            Some(Cfi::Start {
                simple: !p.is_empty(),
            })
        }
        ".cfi_endproc" => {
            exact(0)?;
            Some(Cfi::End)
        }
        ".cfi_def_cfa" => {
            exact(2)?;
            Some(Cfi::DefCfa {
                register: cfi_register(p[0], a)?,
                offset: signed(p[1])?,
            })
        }
        ".cfi_def_cfa_register" => {
            exact(1)?;
            Some(Cfi::DefCfaRegister(cfi_register(p[0], a)?))
        }
        ".cfi_def_cfa_offset" => {
            exact(1)?;
            Some(Cfi::DefCfaOffset(signed(p[0])?))
        }
        ".cfi_offset" | ".cfi_rel_offset" => {
            exact(2)?;
            Some(Cfi::Offset {
                register: cfi_register(p[0], a)?,
                offset: signed(p[1])?,
                relative: m == ".cfi_rel_offset",
            })
        }
        ".cfi_restore" => {
            exact(1)?;
            Some(Cfi::Restore(cfi_register(p[0], a)?))
        }
        ".cfi_adjust_cfa_offset" => {
            exact(1)?;
            Some(Cfi::AdjustCfaOffset(signed(p[0])?))
        }
        ".cfi_remember_state" => {
            exact(0)?;
            Some(Cfi::RememberState)
        }
        ".cfi_restore_state" => {
            exact(0)?;
            Some(Cfi::RestoreState)
        }
        ".cfi_return_column" => {
            exact(1)?;
            Some(Cfi::ReturnColumn(cfi_register(p[0], a)?))
        }
        ".cfi_signal_frame" => {
            exact(0)?;
            Some(Cfi::SignalFrame)
        }
        _ => None,
    };
    if let Some(c) = c {
        return Ok(Directive::Cfi(c));
    }
    match m {
        ".text" | ".data" | ".bss" | ".popsection" | ".previous" => {
            if p.len() > 1 || ([".popsection", ".previous"].contains(&m) && !p.is_empty()) {
                return Err("unsupported section arguments".into());
            }
            Ok(Directive::Section {
                kind: match m {
                    ".text" => SectionKind::Text,
                    ".data" => SectionKind::Data,
                    ".bss" => SectionKind::Bss,
                    ".popsection" => SectionKind::Pop,
                    _ => SectionKind::Previous,
                },
                name: None,
                flags: None,
                section_type: None,
                subsection: p.first().map(|s| unsigned(s)).transpose()?,
            })
        }
        ".section" | ".pushsection" => {
            if p.is_empty() || p.len() > 3 {
                return Err("unsupported section/group arguments".into());
            }
            let section_type = if p.len() == 3 {
                Some(match p[2].trim_start_matches(['@', '%']) {
                    "progbits" => SectionType::Progbits,
                    "nobits" => SectionType::Nobits,
                    "note" => SectionType::Note,
                    _ => return Err("unsupported section type".into()),
                })
            } else {
                None
            };
            Ok(Directive::Section {
                kind: if m == ".section" {
                    SectionKind::Named
                } else {
                    SectionKind::Push
                },
                name: Some(section_name(p[0])?),
                flags: if p.len() > 1 {
                    Some(string_bytes(p[1])?)
                } else {
                    None
                },
                section_type,
                subsection: None,
            })
        }
        ".align" | ".balign" | ".p2align" => {
            if p.is_empty() || p.len() > 3 {
                return Err("unsupported alignment arguments".into());
            }
            Ok(Directive::Alignment {
                kind: match m {
                    ".align" => AlignmentKind::Align,
                    ".balign" => AlignmentKind::ByteAlign,
                    _ => AlignmentKind::PowerOfTwo,
                },
                boundary: expression(p[0])?,
                fill: p.get(1).map(|s| expression(s)).transpose()?,
                maximum_skip: p.get(2).map(|s| expression(s)).transpose()?,
            })
        }
        ".globl" | ".global" | ".hidden" | ".weak" | ".local" | ".protected" => {
            if p.is_empty() {
                return Err("empty symbol binding".into());
            }
            Ok(Directive::Binding {
                kind: match m {
                    ".globl" | ".global" => Binding::Global,
                    ".hidden" => Binding::Hidden,
                    ".weak" => Binding::Weak,
                    ".local" => Binding::Local,
                    _ => Binding::Protected,
                },
                names: p.iter().map(|s| name(s)).collect::<Result<_, _>>()?,
            })
        }
        ".type" => {
            exact(2)?;
            Ok(Directive::SymbolType {
                name: name(p[0])?,
                kind: match p[1].trim_start_matches(['@', '%']) {
                    "function" => SymbolType::Function,
                    "object" => SymbolType::Object,
                    "notype" => SymbolType::Notype,
                    "tls_object" => SymbolType::TlsObject,
                    _ => return Err("unsupported symbol type".into()),
                },
            })
        }
        ".size" => {
            exact(2)?;
            Ok(Directive::Size {
                name: name(p[0])?,
                size: expression(p[1])?,
            })
        }
        ".set" | ".equ" => {
            exact(2)?;
            Ok(Directive::Assignment {
                name: name(p[0])?,
                value: expression(p[1])?,
                equ: m == ".equ",
            })
        }
        ".quad" | ".8byte" | ".long" | ".4byte" | ".short" | ".2byte" | ".byte" => {
            if p.is_empty() {
                return Err("empty data directive".into());
            }
            Ok(Directive::Integers {
                element_bytes: match m {
                    ".quad" | ".8byte" => 8,
                    ".long" | ".4byte" => 4,
                    ".short" | ".2byte" => 2,
                    _ => 1,
                },
                values: p.iter().map(|s| expression(s)).collect::<Result<_, _>>()?,
            })
        }
        ".zero" | ".space" => {
            if p.is_empty() || p.len() > 2 {
                return Err("unsupported space arguments".into());
            }
            Ok(Directive::Space {
                count: expression(p[0])?,
                fill: p.get(1).map(|s| expression(s)).transpose()?,
            })
        }
        ".ascii" | ".asciz" | ".string" => {
            if p.is_empty() {
                return Err("empty string directive".into());
            }
            Ok(Directive::Strings {
                values: p
                    .iter()
                    .map(|s| string_bytes(s))
                    .collect::<Result<_, _>>()?,
                nul_terminated: m != ".ascii",
            })
        }
        ".file" => {
            let w = words(args)?;
            let (number, path) = match w.as_slice() {
                [path] => (None, *path),
                [number, path] => (Some(unsigned(number)?), *path),
                _ => return Err("unsupported .file directory/checksum form".into()),
            };
            Ok(Directive::File {
                number,
                path: string_bytes(path)?,
            })
        }
        ".loc" => {
            let w = words(args)?;
            if w.len() != 3 {
                return Err("unsupported .loc options".into());
            }
            Ok(Directive::Location {
                file: unsigned(w[0])?,
                line: unsigned(w[1])?,
                column: unsigned(w[2])?,
            })
        }
        _ => Err("directive has no supported typed syntax variant".into()),
    }
}
fn parse(text: &str, k: SyntaxKind, a: Architecture) -> Result<Syntax, (ProblemKind, String)> {
    if k == SyntaxKind::Label {
        let s = text.strip_suffix(':').unwrap().trim();
        let label = if s.bytes().all(|b| b.is_ascii_digit()) {
            Label::Numeric(local_label_number(s).map_err(|e| (ProblemKind::Operand, e))?)
        } else {
            Label::Named(name(s).map_err(|e| (ProblemKind::Operand, e))?)
        };
        return Ok(Syntax::Label(label));
    }
    let (m, args) = text
        .split_once(char::is_whitespace)
        .map_or((text, ""), |(m, a)| (m, a.trim()));
    if k == SyntaxKind::Preprocessor {
        let w = words(text.trim_start_matches('#').trim())
            .map_err(|e| (ProblemKind::UnsupportedPreprocessor, e))?;
        let w = if w.first() == Some(&"line") {
            &w[1..]
        } else {
            &w[..]
        };
        if w.len() < 2 {
            return Err((
                ProblemKind::UnsupportedPreprocessor,
                "unexpanded or unsupported preprocessor directive".into(),
            ));
        }
        let line = unsigned(w[0]).map_err(|_| {
            (
                ProblemKind::UnsupportedPreprocessor,
                "unexpanded preprocessor directive".into(),
            )
        })?;
        let path = string_bytes(w[1]).map_err(|e| (ProblemKind::UnsupportedPreprocessor, e))?;
        let mut flags = Vec::new();
        for f in &w[2..] {
            let n = unsigned(f).map_err(|e| (ProblemKind::UnsupportedPreprocessor, e))?;
            if !(1..=4).contains(&n) {
                return Err((
                    ProblemKind::UnsupportedPreprocessor,
                    "unknown line marker flag".into(),
                ));
            }
            flags.push(n as u8);
        }
        return Ok(Syntax::PreprocessorMarker { line, path, flags });
    }
    if k == SyntaxKind::Macro {
        return Err((
            ProblemKind::UnexpandedMacroOrConditional,
            "unexpanded assembler macro/conditional/include is retained, not lowered".into(),
        ));
    }
    if k != SyntaxKind::Instruction {
        return directive(m, args, a)
            .map(Syntax::Directive)
            .map_err(|e| (ProblemKind::UnsupportedDirective, e));
    }
    let (opcode, min, max) = opcode(m, a).ok_or_else(|| {
        (
            ProblemKind::UnsupportedInstruction,
            "instruction has no supported typed syntax variant".into(),
        )
    })?;
    let operands = split_operands(args).map_err(|e| (ProblemKind::Operand, e))?;
    if operands.len() < min || operands.len() > max {
        return Err((
            ProblemKind::Operand,
            "wrong instruction operand count".into(),
        ));
    }
    let operands = operands
        .into_iter()
        .map(|s| operand(s, a))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (ProblemKind::Operand, e))?;
    Ok(Syntax::Instruction { opcode, operands })
}
fn expression_uses(e: &Expression, out: &mut Vec<(u64, Direction)>) {
    for a in std::iter::once(&e.first).chain(e.rest.iter().map(|(_, a)| a)) {
        if let ExprAtom::NumericLabel { number, direction } = a {
            out.push((*number, *direction));
        }
    }
}
fn operand_uses(o: &Operand, out: &mut Vec<(u64, Direction)>) {
    match o {
        Operand::Immediate(e) | Operand::Expression(e) => expression_uses(e, out),
        Operand::Indirect(o) => operand_uses(o, out),
        Operand::Address(
            Address::X86 { displacement, .. } | Address::Riscv { displacement, .. },
        ) => expression_uses(displacement, out),
        Operand::Address(Address::Aarch64 {
            offset: Some(e), ..
        }) => expression_uses(e, out),
        _ => {}
    }
}
fn operand_features(o: &Operand, out: &mut BTreeSet<StateFeature>) {
    match o {
        Operand::Address(Address::X86 {
            segment: Some(_), ..
        }) => {
            out.insert(StateFeature::ThreadPointer);
        }
        Operand::Indirect(o) => operand_features(o, out),
        _ => {}
    }
}
fn syntax_uses(s: &Syntax) -> Vec<(u64, Direction)> {
    let mut out = Vec::new();
    match s {
        Syntax::Instruction { operands, .. } => {
            for o in operands {
                operand_uses(o, &mut out);
            }
        }
        Syntax::Directive(d) => match d {
            Directive::Alignment {
                boundary,
                fill,
                maximum_skip,
                ..
            } => {
                expression_uses(boundary, &mut out);
                for e in [fill, maximum_skip].into_iter().flatten() {
                    expression_uses(e, &mut out);
                }
            }
            Directive::Size { size, .. } => expression_uses(size, &mut out),
            Directive::Assignment { value, .. } => expression_uses(value, &mut out),
            Directive::Integers { values, .. } => {
                for e in values {
                    expression_uses(e, &mut out);
                }
            }
            Directive::Space { count, fill } => {
                expression_uses(count, &mut out);
                if let Some(e) = fill {
                    expression_uses(e, &mut out);
                }
            }
            _ => {}
        },
        _ => {}
    }
    out
}

/// Hashes, parses and consumes the SAME two input buffers. No filesystem import,
/// helper execution or bytecode cache participates. On floor mismatch this returns
/// an explicit error, never a filtered successful subset.
pub fn read_configured_assembly(
    bytes: &[u8],
    selection: &ReadSelection,
    required_inventory_json: &[u8],
    target: Target,
) -> Result<ParsedAssembly, ReadError> {
    profile(selection, target)?;
    let floor = check_floor(bytes, selection, required_inventory_json)?;
    let parts = statements(bytes, selection.profile.architecture)?;
    if parts.len() != floor.records.len() {
        return Err(ReadError::Inventory("parsed record count differs from complete selected floor (including unsupported records)".into()));
    }
    let mut records = Vec::new();
    let mut problems = Vec::new();
    let mut coverage = Vec::new();
    let mut end = 0u64;
    for (index, ((span, text), required)) in parts.into_iter().zip(floor.records).enumerate() {
        let k = kind(&text);
        if span != required.span || k != required.kind {
            return Err(ReadError::Inventory(format!(
                "record {index} span/kind differs from selected floor"
            )));
        }
        if end < span.start {
            coverage.push(Coverage::Trivia(SourceSpan {
                start: end,
                end: span.start,
            }));
        }
        coverage.push(Coverage::Record { index, span });
        end = span.end;
        let syntax = match parse(&text, k, selection.profile.architecture) {
            Ok(s) => s,
            Err((kind, reason)) => {
                problems.push(Problem {
                    record: index,
                    kind,
                    reason,
                });
                Syntax::Unsupported
            }
        };
        records.push(ParsedRecord { required, syntax });
    }
    if end < bytes.len() as u64 {
        coverage.push(Coverage::Trivia(SourceSpan {
            start: end,
            end: bytes.len() as u64,
        }));
    }
    let mut named = BTreeSet::new();
    let mut numeric: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, r) in records.iter().enumerate() {
        match &r.syntax {
            Syntax::Label(Label::Named(n)) => {
                if !named.insert(n) {
                    problems.push(Problem {
                        record: i,
                        kind: ProblemKind::DuplicateLabel,
                        reason: "duplicate named label".into(),
                    });
                }
            }
            Syntax::Label(Label::Numeric(n)) => numeric.entry(*n).or_default().push(i),
            _ => {}
        }
    }
    let mut label_uses = Vec::new();
    let mut required_syntax_features = BTreeSet::new();
    for (i, r) in records.iter().enumerate() {
        if let Syntax::Instruction { operands, .. } = &r.syntax {
            for o in operands {
                let mut detected = BTreeSet::new();
                operand_features(o, &mut detected);
                for feature in detected {
                    required_syntax_features.insert(feature);
                    if !selection.profile.features.contains(&feature) {
                        problems.push(Problem {
                            record: i,
                            kind: ProblemKind::UndeclaredStateFeature,
                            reason: format!(
                                "syntax requires explicitly declared state feature {feature:?}"
                            ),
                        });
                    }
                }
            }
        }
        for (number, direction) in syntax_uses(&r.syntax) {
            let definition = numeric.get(&number).and_then(|defs| match direction {
                Direction::Forward => defs.iter().copied().find(|j| *j > i),
                Direction::Backward => defs.iter().copied().rev().find(|j| *j < i),
            });
            if definition.is_none() {
                problems.push(Problem {
                    record: i,
                    kind: ProblemKind::UnresolvedNumericLabel,
                    reason: format!(
                        "numeric label {number}{direction:?} has no matching definition"
                    ),
                });
            }
            label_uses.push(LabelUse {
                record: i,
                number,
                direction,
                definition,
            });
        }
    }
    Ok(ParsedAssembly {
        original: bytes.to_vec(),
        selected_inventory: selection.inventory.clone(),
        source: selection.source.clone(),
        profile: selection.profile.clone(),
        records,
        coverage,
        label_uses,
        required_syntax_features: required_syntax_features.into_iter().collect(),
        coverage_relative_to_selected_inventory: true,
        syntax_supported: problems.is_empty(),
        problems,
        original_source_authenticated: false,
        selected_floor_authority_authenticated: false,
        original_unit_completeness_qualified: false,
        instruction_semantics_lifted: false,
        machine_body_admitted: false,
        provider_qualified: false,
        native_qualified: false,
        runtime_qualified: false,
        isa_equivalence_qualified: false,
    })
}

#[cfg(test)]
#[path = "native_machine_asm_reader_tests.rs"]
mod tests;
