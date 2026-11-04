//! Prospective compile-time machine-body contract, deliberately NOT NativeModule.
//!
//! There is no parser, emitter, interpreter, native exposure or provider admission
//! for this type. Source identities and the separately supplied inventory are
//! claims to be authenticated by a future original-source producer. Structural
//! coverage relative to that inventory is not original instruction completeness.
use serde::{Deserialize, Serialize};
use super::native_ir::{BlockId, ValueId};

/// Version 2 introduces typed flag definedness and scalar extensions.
pub const FORMAT: &str = "ocore-machine-body-contract-v2";
/// Version 3 requires an explicit computed target for ordinary returns.
/// Version 2 is retained only for legacy, unqualified structural fixtures.
pub const COMPUTED_CONTROL_FORMAT: &str = "ocore-machine-body-contract-v3";
pub const SOURCE_FORMAT: &str = "ocore-machine-original-source-claim-v1";
pub const INVENTORY_FORMAT: &str = "ocore-selected-machine-inventory-contract-v1";
pub type StateId = usize;
pub type SourceItemId = u64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity { pub bytes: u64, pub sha256: String }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceFile { pub id: u64, pub logical_path: String, pub identity: ArtifactIdentity }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MachineInputForm { ConfiguredAssemblyText }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[doc = "No source authenticity follows from this serialized claim."]
pub struct SourceWitness {
    pub format: String,
    pub input_form: MachineInputForm,
    pub unit_id: String,
    pub files: Vec<SourceFile>,
    pub decoded_assembly: ArtifactIdentity,
    pub build_configuration: ArtifactIdentity,
    pub frontend_event: ArtifactIdentity,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Architecture { X86_64, Aarch64, Rv64, I686, Armv7 }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MachineAbi { SysvAmd64, Aapcs64, RiscvLp64, RiscvLp64d }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder { Little, Big }
/// Known states are named so unsupported requirements cannot disappear as hints.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StateFeature {
    UserRegisterBits, ThreadPointer, TlsPointerMangling, CetShadowStack,
    PointerAuthentication, GuardedControlStack, ScalableMatrixZa, FloatingEnvironment,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CfiPolicy { Required, NoCfiDeclared }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineProfile {
    pub architecture: Architecture,
    pub abi: MachineAbi,
    pub address_bits: u16,
    pub byte_order: ByteOrder,
    pub entry_stack_alignment: u64,
    pub entry_stack_remainder: u64,
    pub features: Vec<StateFeature>,
    pub cfi: CfiPolicy,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum X86Gpr { Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rbp, Rsp, R8, R9, R10, R11, R12, R13, R14, R15 }
/// Canonical storage identities, never arbitrary register-name strings. Aliases
/// use views of ONE storage (x30 is also LR; x1 is also ra; x2 is also sp).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "bank", rename_all = "snake_case", deny_unknown_fields)]
pub enum PhysicalRegister {
    X86Gpr { name: X86Gpr }, X86Xmm { index: u8 }, X86Flags, X86Pc,
    Aarch64Gpr { index: u8 }, Aarch64Vector { index: u8 }, Aarch64Sp, Aarch64Pc, Aarch64Nzcv,
    RiscvGpr { index: u8 }, RiscvFpr { index: u8 }, RiscvPc,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RegisterView { pub register: PhysicalRegister, pub low_bit: u16, pub bits: u16 }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WriteMode { WholeStorage, PreserveOtherBits, ZeroExtendStorage }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryPolicy {
    NoImplicitFrameOrScratch,
    OrdinaryCompilerPrologue,
    UnverifiedEntrySnapshot,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryInterface { None, OrderedProcessData }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntryInterface {
    pub policy: EntryPolicy,
    /// Available entry bits, not noundef or a claim that ABI-unspecified bits
    /// have a portable numeric value. Overlapping declarations are rejected.
    pub initialized: Vec<RegisterView>,
    pub memory: MemoryInterface,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitKind { OrdinaryReturn, RestoredContinuation }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExitInterface {
    pub id: u32,
    pub kind: ExitKind,
    pub outputs: Vec<RegisterView>,
    /// Foundation-only readonly preservation: writing any of these bits is
    /// refused, even if a future semantic proof might show save/restore.
    pub preserved: Vec<RegisterView>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineInterface { pub entry: EntryInterface, pub exits: Vec<ExitInterface> }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceSpan { pub start: u64, pub end: u64 }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OriginalSpan { pub file: u64, pub span: SourceSpan }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceItemKind { Instruction, Label, CfiDirective, AlignmentDirective, SymbolDirective, DataDirective, RelocationDirective }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceItem {
    pub id: SourceItemId,
    pub kind: SourceItemKind,
    pub decoded_span: SourceSpan,
    pub origins: Vec<OriginalSpan>,
}
/// Separate API input, selected by a future independent complete producer/parser.
/// Its identity is NOT authenticated by the structural verifier. Never derive a
/// passing source-completeness gate from this self-describable Rust value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelectedInstructionInventory {
    pub format: String,
    pub identity: ArtifactIdentity,
    pub source: SourceWitness,
    pub symbol: String,
    pub profile: MachineProfile,
    pub interface: MachineInterface,
    pub items: Vec<SourceItem>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scalar { pub id: ValueId, pub bits: u16 }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BinaryKind { WrappingAdd, WrappingSub, And, Or, Xor, RotateRightModuloWidth }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompareKind { Equal, UnsignedLess }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionKind { Truncate, ZeroExtend, SignExtend }
/// No raw-assembly, binary-blob, arbitrary opcode or host callback variant.
/// These are explicit bit/state primitives, NOT proven meanings of an original
/// ISA instruction. A future decoder must supply a separately checked lift.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum MachineOperation {
    Constant { little_endian: Vec<u8> },
    ReadRegister { view: RegisterView },
    WriteRegister { view: RegisterView, value: ValueId, mode: WriteMode },
    /// Arithmetic flag views only; privileged/control/reserved flags excluded.
    ReadFlags { view: RegisterView },
    WriteFlags { view: RegisterView, value: ValueId },
    /// Removes definedness without selecting a convenient concrete value.
    InvalidateRegister { view: RegisterView },
    /// Target width comes from the exact result scalar.
    Cast { kind: ExtensionKind, value: ValueId },
    Binary { kind: BinaryKind, lhs: ValueId, rhs: ValueId },
    Compare { kind: CompareKind, lhs: ValueId, rhs: ValueId },
    Load { address: ValueId, alignment: u64 },
    Store { address: ValueId, value: ValueId, alignment: u64 },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineInstruction {
    pub source_item: SourceItemId,
    pub state_in: StateId,
    pub state_out: StateId,
    pub result: Option<Scalar>,
    pub operation: MachineOperation,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Edge { pub target: BlockId, pub arguments: Vec<ValueId> }
/// Exact architectural return branch class, not a native realization or source proof.
/// x86 RET is absent until its stack/CET protocol has a typed realization.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReturnMechanism { Rv64Jalr, Aarch64Ret }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "control", rename_all = "snake_case", deny_unknown_fields)]
pub enum MachineControl {
    Jump { edge: Edge },
    Branch { condition: ValueId, on_true: Edge, on_false: Edge },
    /// Legacy v2 structural marker: contains no computed continuation.
    Return { exit: u32 },
    /// v3 only. The target is an actual defined address-width SSA value.
    /// This represents the target without authenticating its original-source meaning.
    ReturnTo { exit: u32, target: ValueId, mechanism: ReturnMechanism },
    /// Typed future seam, always rejected by this foundation. No ordinary
    /// epilogue or generic indirectbr is authorized to realize this operation.
    RestoreContext { stack_pointer: ValueId, program_counter: ValueId },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineTerminator { pub source_item: SourceItemId, pub state: StateId, pub control: MachineControl }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineBlock {
    pub id: BlockId,
    pub source_label: Option<SourceItemId>,
    pub state_parameter: StateId,
    pub parameters: Vec<Scalar>,
    pub instructions: Vec<MachineInstruction>,
    pub terminator: MachineTerminator,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "directive", rename_all = "snake_case", deny_unknown_fields)]
pub enum MachineDirective {
    CfiStart, CfiEnd,
    CfiDefCfa { register: RegisterView, offset: i64 },
    CfiSaved { register: RegisterView, offset: i64 },
    CfiRestore { register: RegisterView },
    Alignment { bytes: u64 },
    Symbol { name: String },
    UnsupportedData, UnsupportedRelocation,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectiveRecord { pub source_item: SourceItemId, pub directive: MachineDirective }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineBodyContract {
    pub format: String,
    pub selected_inventory: ArtifactIdentity,
    pub source: SourceWitness,
    pub symbol: String,
    pub profile: MachineProfile,
    pub interface: MachineInterface,
    pub entry: BlockId,
    pub blocks: Vec<MachineBlock>,
    pub directives: Vec<DirectiveRecord>,
}
