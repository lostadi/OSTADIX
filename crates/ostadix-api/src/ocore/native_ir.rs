//! Self-contained import boundary for foreign implementations.
//!
//! This is not orchestration OIR and does not inherit `.oc` arithmetic. Imported
//! instructions retain their frontend's widths and signed operation predicates.
//! Every input module is verified before it reaches an ISA emitter.

use serde::{Deserialize, Serialize};

pub type TypeId = usize;
pub type ValueId = usize;
pub type BlockId = usize;

pub const FORMAT: &str = "ocore-native-module-v1";
pub const NOALIAS_SCOPE_DECL: &str = "llvm.experimental.noalias.scope.decl";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeModule {
    pub format: String,
    pub name: String,
    pub target: TargetLayout,
    pub semantics: Semantics,
    pub types: Vec<Type>,
    pub globals: Vec<Global>,
    pub functions: Vec<Function>,
    /// Additional source symbols for existing storage/code, never copied bodies.
    #[serde(default)]
    pub aliases: Vec<Alias>,
    /// Linker selection applies to every member of a group together.
    #[serde(default)]
    pub comdats: Vec<Comdat>,
    /// Original scoped-alias metadata, separate from executable SSA values.
    /// The current nonoptimizing realization uses none of its alias promises.
    #[serde(default)]
    pub noalias_metadata: NoAliasMetadata,
    /// Exact context-local LLVM synchronization scope IDs and raw names. IDs
    /// are not global capability keys and must never be compared across images.
    #[serde(default)]
    pub atomic_sync_scopes: Vec<AtomicSyncScope>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AtomicSyncScope {
    pub id: u32,
    pub name: Vec<u8>,
}

/// Source orderings, independent of either the LLVM C enum's numeric values
/// or a platform helper library's order argument ABI.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AtomicOrdering {
    Unordered,
    Monotonic,
    Acquire,
    Release,
    #[serde(rename = "acq_rel")]
    AcquireRelease,
    #[serde(rename = "seq_cst")]
    SequentiallyConsistent,
}

/// LLVM22's original operation names. The C and C++ enumerations have different
/// orders; frontends must map named operations, never cast numeric ordinals.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AtomicRmwOp {
    Xchg,
    Add,
    Sub,
    And,
    Nand,
    Or,
    Xor,
    Max,
    Min,
    Umax,
    Umin,
    Fadd,
    Fsub,
    Fmax,
    Fmin,
    Fmaximum,
    Fminimum,
    UincWrap,
    UdecWrap,
    UsubCond,
    UsubSat,
}

/// Module-local identities of original parsed LLVM MDTuples. IDs share one
/// namespace across the three tables; they are neither code addresses nor
/// printed LLVM slot numbers. Strings preserve arbitrary source bytes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoAliasMetadata {
    pub domains: Vec<NoAliasDomain>,
    pub scopes: Vec<NoAliasScope>,
    pub lists: Vec<NoAliasScopeList>,
    pub attachments: Vec<NoAliasAttachment>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NoAliasNodeStorage {
    Uniqued,
    Distinct,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NoAliasIdentity {
    /// Operand zero refers to this exact node, never a similarly named node.
    SelfReference {},
    Bytes {
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoAliasDomain {
    pub id: usize,
    pub storage: NoAliasNodeStorage,
    pub identity: NoAliasIdentity,
    /// None and Some(empty) are different original operand lists.
    pub description: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoAliasScope {
    pub id: usize,
    pub storage: NoAliasNodeStorage,
    pub identity: NoAliasIdentity,
    pub domain: usize,
    pub description: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoAliasScopeList {
    pub id: usize,
    pub storage: NoAliasNodeStorage,
    /// Preserve order and repeated members. A declaration requires one member;
    /// access attachments may contain any verified list of original scopes.
    pub scopes: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct NoAliasSite {
    pub function: String,
    pub block: BlockId,
    /// Index in the native instruction list (a terminator follows its length).
    pub instruction: usize,
    /// Exact contiguous range produced by the source instruction. Zero denotes
    /// a terminator or an erased compiler-only source site at this anchor.
    pub instruction_count: usize,
    /// Index in the original LLVM block, before any one-to-many lowering.
    pub source_instruction: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoAliasAttachment {
    pub site: NoAliasSite,
    pub alias_scope: Option<usize>,
    pub noalias: Option<usize>,
    /// Actual LLVM enumeration order of the noalias-relevant access attachments
    /// at this instruction, not the order of unrelated/debug metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_order: Option<Vec<NoAliasAttachmentKind>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NoAliasAttachmentKind {
    #[serde(rename = "alias_scope")]
    AliasScope,
    #[serde(rename = "noalias")]
    NoAlias,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LlvmMetadataGraphSchema {
    #[serde(rename = "ocore.llvm-metadata-graph/v1")]
    V1,
}

/// Deterministic, typed serialization of the actual parsed LLVM metadata graph.
/// IDs are local traversal identities, never LLVM display slots or pointers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LlvmMetadataGraphSource {
    pub schema: LlvmMetadataGraphSchema,
    pub nodes: Vec<LlvmMetadataSourceNode>,
    pub alias_bindings: Vec<LlvmMetadataAliasBinding>,
    pub roots: Vec<LlvmMetadataSourceRoot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LlvmMetadataSourceNode {
    Tuple {
        id: usize,
        metadata_kind: u32,
        storage: NoAliasNodeStorage,
        operands: Vec<usize>,
    },
    String {
        id: usize,
        metadata_kind: u32,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LlvmMetadataAliasBinding {
    pub alias_id: usize,
    pub node: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LlvmMetadataSourceSite {
    pub function: String,
    pub block: BlockId,
    pub source_instruction: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LlvmMetadataSourceRootKind {
    #[serde(rename = "scope_declaration")]
    ScopeDeclaration,
    #[serde(rename = "alias_scope")]
    AliasScope,
    #[serde(rename = "noalias")]
    NoAlias,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LlvmMetadataSourceRoot {
    pub kind: LlvmMetadataSourceRootKind,
    pub site: LlvmMetadataSourceSite,
    pub node: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetLayout {
    pub triple: String,
    pub data_layout: String,
    pub pointer_bits: u16,
    pub little_endian: bool,
    /// Explicit frontend ABI where a bare architecture triple omits it.
    #[serde(default)]
    pub abi: Option<String>,
    /// An explicit realization contract, separate from the original frontend
    /// triple and requested TLS access models. Objects using it must be linked
    /// into one nonpreemptive static Linux ELF image with genuine TLS providers.
    #[serde(default)]
    pub tls_profile: Option<TlsProfile>,
    /// Explicit memory realization contract, independent of source orderings.
    /// It covers ordinary coherent RAM, never device memory. Masked subword
    /// realizations require the complete containing word to belong to that RAM.
    /// RV64 exclusive loops additionally require the platform's LR/SC eventuality
    /// property for these regions; this does not promise starvation freedom.
    #[serde(default)]
    pub atomic_profile: Option<AtomicProfile>,
    /// Explicit ordinary-RAM realization for wide volatile accesses. Native
    /// accesses may use ordered target-sized parts: this excludes MMIO and
    /// provides no indivisibility or atomicity. Original operations are retained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wide_volatile_profile: Option<WideVolatileProfile>,
    /// Required native realization for strictfp source scopes. Consumers must
    /// reject an unknown required profile rather than erase the source contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict_fp_profile: Option<StrictFpProfile>,
    /// Explicit Linux userspace raw-syscall ABI; never a native-kernel provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux_syscall_profile: Option<LinuxSyscallProfile>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StrictFpProfile {
    /// Audited scalar integer/pointer operations preserve ambient FP state;
    /// ordered original provider calls retain their own observable effects.
    IntegerOnlyV1,
    /// IntegerOnlyV1 plus the separately audited opaque Linux platform operation.
    /// The original Linux provider remains an external execution obligation.
    IntegerLinuxSyscallV1,
    /// Ordered scalar IEEE32/64 multiplication under the unchanged dynamic
    /// environment; exception-ignore is not a strict/trapping contract.
    ScalarDynamicMulV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConstrainedFpRounding {
    Dynamic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConstrainedFpExceptions {
    Ignore,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinuxSyscallProfile {
    LinuxUserRawV1,
}

/// Complete supported InlineAsm source contract. Machine emission never copies
/// these bytes. Fresh-source comparison authenticates the witness; structural
/// verification alone is not proof that a claimed source produced this packet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxSyscallSource {
    pub schema: String,
    pub site: LlvmMetadataSourceSite,
    pub assembly: Vec<u8>,
    pub constraints: Vec<u8>,
    pub side_effects: bool,
    pub align_stack: bool,
    pub dialect: u32,
    pub can_unwind: bool,
    pub calling_convention: u32,
    pub tail_kind: u32,
    pub signature: Signature,
    pub attributes: Vec<LinuxSyscallAttribute>,
    /// Separate non-enum source payloads. Empty preserves the exact V1 wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constant_ranges: Vec<LinuxSyscallConstantRangeAttribute>,
    pub srcloc: Option<LinuxSyscallSourceLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxSyscallAttribute {
    pub index: u32,
    pub name: String,
    pub value: u64,
}

/// Exact original callslot ConstantRange. Outside-range values become poison;
/// this witness introduces no ABI change, optimizer assumption or provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxSyscallConstantRangeAttribute {
    pub index: u32,
    pub name: String,
    pub schema: String,
    pub storage: String,
    pub width: u16,
    pub lower: String,
    pub upper: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxSyscallSourceLocation {
    /// Module-local source-order node identity, not a context kind or printer slot.
    pub node: usize,
    pub storage: NoAliasNodeStorage,
    pub operands: Vec<LinuxSyscallLocationInteger>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxSyscallLocationInteger {
    pub width: u16,
    pub bits: String,
}

/// Original function subtarget strings, not replacement executable IR. Their
/// ordered spelling is retained so ABI-sensitive legalization can be checked
/// independently against the original producer and at caller/provider edges.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceAbiWitness {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_cpu: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_features: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AtomicProfile {
    CoherentRamV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WideVolatileProfile {
    OrdinaryRamSplitV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsProfile {
    LinuxElfStaticNonpreemptiveV1,
}

/// Original LLVM access model. Local-exec machine addressing is a realization
/// under the explicit static-image profile; it does not rewrite this metadata.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsModel {
    GeneralDynamic,
    LocalDynamic,
    InitialExec,
    LocalExec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Semantics {
    /// Preserve all defined LLVM behavior. Poison/undef may be refined to
    /// deterministic bits; no optimization may assume dropped poison flags.
    LlvmDefinedBehaviorV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Type {
    Void,
    /// Compiler-only LLVM metadata. It has no size, alignment, SSA storage,
    /// register, stack slot, global address, or ordinary native calling ABI.
    Metadata {},
    /// An identified LLVM structure whose body is unknown. Its TypeId preserves
    /// identity even when `name` is None. This has no allocation/SSA/ABI layout;
    /// only a direct external global declaration may use it.
    OpaqueStruct {
        name: Option<String>,
    },
    Int {
        bits: u16,
    },
    Float {
        bits: u16,
    },
    Pointer {
        address_space: u32,
    },
    /// Fixed integer vector. Lanes occupy consecutive significant bits in
    /// memory, not the allocation stride of the scalar element type.
    Vector {
        element: TypeId,
        len: u64,
    },
    Array {
        element: TypeId,
        len: u64,
    },
    Struct {
        fields: Vec<TypeId>,
        packed: bool,
    },
    Function {
        signature: Signature,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub params: Vec<TypeId>,
    pub result: TypeId,
    pub abi: String,
    pub variadic: bool,
    /// Declarations, definitions and function value types describe the fixed
    /// prefix. A variadic Call/Invoke records one vector per actual argument,
    /// including every unnamed trailing operand's independent ABI attributes.
    #[serde(default)]
    pub param_attributes: Vec<Vec<String>>,
    #[serde(default)]
    pub result_attributes: Vec<String>,
    /// LLVM's typed `sret` contract. The original pointer parameter and void
    /// result remain in the signature; target lowering assigns its ABI location.
    #[serde(default)]
    pub return_storage: Option<ReturnStorage>,
}

/// Caller-provided storage for a source result, not an LLVM SSA return value.
/// Pointer alignment promises remain separate from this ABI contract. The
/// storage type may be any supported sized memory type, not only a structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReturnStorage {
    pub param: usize,
    pub ty: TypeId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub input_sha256: String,
    pub frontend: String,
    pub frontend_version: String,
    pub importer: String,
    pub importer_version: String,
    /// Includes declarations: nothing executable may be silently dropped.
    pub source_function_count: usize,
    pub source_global_count: usize,
    #[serde(default)]
    pub source_alias_count: usize,
    #[serde(default)]
    /// Groups referenced by GlobalObjects in the verified canonical bitcode.
    /// LLVM serialization omits unused, non-executable group declarations.
    pub referenced_comdat_count: usize,
    /// Exact trusted LLVM node-printer evidence used for post-parse storage
    /// classification. Printed slots/pointer fallback text are evidence only,
    /// never portable graph IDs or executable addresses.
    #[serde(default)]
    pub noalias_metadata_source: Vec<NoAliasNodeSource>,
    /// Versioned deterministic graph source. Raw LLVM printer diagnostics are
    /// retained separately; they are not part of this canonical representation.
    /// Legacy packets omit this field and retain their exact old evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noalias_metadata_graph_source: Option<LlvmMetadataGraphSource>,
    pub refinements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoAliasNodeSource {
    pub id: usize,
    pub metadata_kind: u32,
    pub printer_bytes: Vec<u8>,
    pub printer_sha256: String,
}

/// Source symbol visibility, retained independently of its linkage. Native
/// modules currently use a static, nonpreemptive linkage contract; retaining
/// these ELF attributes does not introduce dynamic loading or interposition.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    #[default]
    Default,
    Hidden,
    Protected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Global {
    pub name: String,
    pub ty: TypeId,
    pub linkage: String,
    #[serde(default)]
    pub visibility: Visibility,
    #[serde(default)]
    pub comdat: Option<String>,
    pub alignment: u64,
    pub constant: bool,
    pub thread_local: bool,
    #[serde(default)]
    pub tls_model: Option<TlsModel>,
    /// None denotes an external declaration, not an empty definition.
    pub initializer: Option<Initializer>,
}

/// A direct, zero-offset alias to a definition in the same native module.
/// Symbol names remain distinct for calls, addresses and linker resolution.
/// Constant-expression/chained/TLS aliases require separate representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alias {
    pub name: String,
    /// The aliased value type (function type or global storage type).
    pub ty: TypeId,
    pub aliasee: String,
    pub linkage: String,
    #[serde(default)]
    pub visibility: Visibility,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comdat {
    pub name: String,
    pub selection: ComdatSelection,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComdatSelection {
    Any,
    NoDeduplicate,
    ExactMatch,
    Largest,
    SameSize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Initializer {
    pub bytes: Vec<u8>,
    pub relocations: Vec<Relocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relocation {
    pub offset: u64,
    pub width: u16,
    pub symbol: String,
    pub addend: i64,
    /// A source symbol-difference initializer, truncated to `width` bits.
    /// `None` retains the original absolute-address relocation contract.
    /// The first native profile requires the base to be the containing local
    /// global; its identity remains explicit rather than becoming a PC offset.
    #[serde(default)]
    pub relative_to: Option<String>,
    /// An owned code-block target; `symbol` is empty for this variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<BlockAddressRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockAddressRef {
    pub function: String,
    pub block: BlockId,
}

/// Raw source control effects, separate from the ordinary calling signature.
/// `returns_twice` permits later resumption of this call's continuation; it
/// does not assert a qualified native frame or external jump provider.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlEffects {
    #[serde(default)]
    pub returns_twice: bool,
}

impl ControlEffects {
    pub fn is_empty(&self) -> bool {
        !self.returns_twice
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Function {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_abi: Option<SourceAbiWitness>,
    #[serde(default, skip_serializing_if = "ControlEffects::is_empty")]
    pub control_effects: ControlEffects,
    pub name: String,
    pub linkage: String,
    #[serde(default)]
    pub visibility: Visibility,
    #[serde(default)]
    pub comdat: Option<String>,
    /// Minimum source code-address alignment; zero leaves target defaults.
    #[serde(default)]
    pub alignment: u64,
    pub signature: Signature,
    pub params: Vec<Value>,
    /// None denotes an external declaration. A definition has an entry block.
    pub entry: Option<BlockId>,
    pub blocks: Vec<Block>,
    #[serde(default)]
    pub managed_method: Option<ManagedMethod>,
    /// Recognized compiler intrinsic, retained in the source inventory.
    #[serde(default)]
    pub intrinsic: Option<String>,
    /// An explicit source exception ABI, independent of the ordinary call ABI.
    /// The personality operand keeps the original symbol/declaration identity.
    #[serde(default)]
    pub exception_handling: Option<ExceptionHandling>,
    /// Original LLVM call-target promises for SSA or named direct calls. These restrict defined
    /// executions; they do not promote calls, insert runtime checks, or invent
    /// executable/link references to otherwise unused declarations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_target_constraints: Vec<CallTargetConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallTargetConstraint {
    /// The exact source instruction and its contiguous native expansion. The
    /// final operation is the unchanged SSA/named direct call (or invoke).
    /// Its original operand is retained on that operation, never inferred from this list.
    pub site: NoAliasSite,
    /// Preserve ordering, repeated names and the empty set. An empty set is
    /// distinct from an absent promise: executing such a call is source UB.
    pub callees: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionHandling {
    pub model: ExceptionModel,
    pub personality: Operand,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionModel {
    ItaniumDwarfV1,
}

/// Ordered source landing-pad clauses. A catch of null is a catch-all, while
/// an empty filter excludes every exception; neither is a cleanup clause.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExceptionClause {
    Catch { typeinfo: Operand },
    Filter { typeinfos: Vec<Operand> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ManagedMethod {
    pub module: String,
    pub loader_namespace: String,
    pub class_name: String,
    pub method_name: String,
    pub descriptor: String,
    pub class_sha256: String,
    pub code_sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Value {
    pub id: ValueId,
    pub ty: TypeId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub id: BlockId,
    pub instructions: Vec<Instruction>,
    pub terminator: Terminator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instruction {
    pub result: Option<Value>,
    pub operation: Operation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operand {
    Value {
        id: ValueId,
    },
    /// Unsigned decimal representation of the exact bit pattern.
    Int {
        ty: TypeId,
        bits: String,
    },
    /// Unsigned decimal encoding of the exact IEEE32/64/128 or x87 extended80
    /// significant bits. No host floating-point conversion or ABI padding.
    Float {
        ty: TypeId,
        bits: String,
    },
    /// Literal unsigned address bits for an integral, little-endian 64-bit
    /// address-space-zero pointer. This is neither a symbol nor a relocation,
    /// and does not establish that the address is dereferenceable.
    PointerBits {
        ty: TypeId,
        bits: String,
    },
    /// An executable LLVM scalar constant-expression pointer conversion.
    /// Keep the original pointer/provenance and linker dependency; this is
    /// neither an absolute integer initializer nor a host address resolver.
    PointerToInteger {
        ty: TypeId,
        pointer: Box<Operand>,
    },
    Null {
        ty: TypeId,
    },
    Symbol {
        ty: TypeId,
        name: String,
    },
    /// A named integral AS0 pointer plus an exact wrapping 64-bit byte offset.
    /// The name stays a link dependency; this is not an absolute address or
    /// permission to dereference the resulting pointer.
    SymbolOffset {
        ty: TypeId,
        name: String,
        addend: i64,
    },
    /// A code-block address, retaining reversible opaque address arithmetic.
    BlockAddress {
        ty: TypeId,
        function: String,
        block: BlockId,
        #[serde(default)]
        addend: i64,
    },
    /// A source struct/array/vector constant with its original type. Every
    /// child is itself constant; SSA construction uses InsertValue instead.
    Aggregate {
        ty: TypeId,
        elements: Vec<Operand>,
    },
    /// Compact LLVM zeroinitializer for a sized struct, array or vector, including
    /// empty aggregates. This does not materialize padding or repeated leaves.
    AggregateZero {
        ty: TypeId,
    },
    Undef {
        ty: TypeId,
    },
    Poison {
        ty: TypeId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    /// Ordered opaque Linux provider effect, with raw signed-error return bits.
    /// May block, signal, create tasks or never return; never pure/speculatable.
    LinuxSyscall {
        number: Operand,
        arguments: Vec<Operand>,
        // Metadata stays off the hot enum storage used by every ordinary op.
        source: Box<LinuxSyscallSource>,
    },
    /// Unconditionally end the executing path with the target's explicit LLVM
    /// trap instruction. This has no result and must never be erased as an
    /// assumption or replaced by an ordinary unresolved runtime call.
    Trap {},
    /// LLVM assumptions constrain defined executions. This unoptimized profile
    /// retains the assertion as IR but does not use it to transform computation.
    Assume {
        condition: Operand,
    },
    /// Declares the original scope at this source instruction. Retained as a
    /// verified compiler marker; the current native realization emits no code
    /// and uses no associated alias.scope/noalias promises for optimization.
    NoAliasScopeDecl {
        scope_list: usize,
        source_instruction: usize,
    },
    /// LLVM 22 object-lifetime marker. The operand is a literal alloca SSA
    /// value or poison; the native profile does not reuse its storage or use
    /// this marker for optimization. Poison has no effect.
    Lifetime {
        pointer: Operand,
        end: bool,
    },
    /// Fill an unsigned byte count, preserving individual volatile accesses.
    /// Alignment is a retained source guarantee, not a reason to widen access.
    MemorySet {
        destination: Operand,
        value: Operand,
        length: Operand,
        alignment: u64,
        volatile: bool,
    },
    /// Copy an unsigned byte count. With allow_overlap, the result is the
    /// original source bytes even when source and destination ranges overlap.
    MemoryCopy {
        destination: Operand,
        source: Operand,
        length: Operand,
        destination_alignment: u64,
        source_alignment: u64,
        volatile: bool,
        allow_overlap: bool,
    },
    Binary {
        kind: BinaryOp,
        lhs: Operand,
        rhs: Operand,
        flags: Vec<String>,
    },
    FloatBinary {
        kind: FloatBinaryOp,
        lhs: Operand,
        rhs: Operand,
        #[serde(default)]
        flags: FastMathFlags,
    },
    /// Distinct environment-sensitive operation; never ordinary FloatBinary.
    ConstrainedFloatBinary {
        kind: FloatBinaryOp,
        lhs: Operand,
        rhs: Operand,
        rounding: ConstrainedFpRounding,
        exceptions: ConstrainedFpExceptions,
    },
    FloatNeg {
        value: Operand,
        #[serde(default)]
        flags: FastMathFlags,
    },
    /// Exact significant-bit sign clearing, including signed zeros and NaN
    /// payloads. This is LLVM fabs, not comparison or host floating arithmetic.
    FloatAbs {
        value: Operand,
        #[serde(default)]
        flags: FastMathFlags,
    },
    FCmp {
        predicate: FloatPredicate,
        lhs: Operand,
        rhs: Operand,
        #[serde(default)]
        flags: FastMathFlags,
    },
    /// Exact modular arithmetic and representability flag, as returned by
    /// LLVM's scalar `[su]{add,sub,mul}.with.overflow` intrinsics. Overflow is
    /// defined for every input and does not produce LLVM poison.
    IntegerOverflow {
        kind: BinaryOp,
        signed: bool,
        lhs: Operand,
        rhs: Operand,
    },
    /// Select one original-width input according to LLVM's integer signed or
    /// unsigned ordering. This introduces no arithmetic overflow or new poison.
    /// Source poison/undef remain governed by LlvmDefinedBehaviorV1 refinement.
    IntegerMinMax {
        kind: IntegerMinMaxKind,
        lhs: Operand,
        rhs: Operand,
    },
    /// Same-width population count; one original scalar operand and no poison flag.
    IntegerPopulationCount {
        value: Operand,
    },
    /// Same-width leading-zero count. The original LLVM immediate poison flag
    /// is retained; LlvmDefinedBehaviorV1 realizes zero as the source width even
    /// when the source flag permits poison. No undefined target BSR is exposed.
    IntegerCountLeadingZeros {
        value: Operand,
        zero_is_poison: bool,
    },
    /// Same-width wrapping magnitude. INT_MIN remains INT_MIN; a true source
    /// poison flag permits this deterministic refinement, not overflow trapping.
    IntegerAbs {
        value: Operand,
        int_min_is_poison: bool,
    },
    ICmp {
        predicate: IntPredicate,
        lhs: Operand,
        rhs: Operand,
    },
    Cast {
        kind: CastOp,
        value: Operand,
    },
    Select {
        condition: Operand,
        on_true: Operand,
        on_false: Operand,
    },
    Freeze {
        value: Operand,
    },
    /// Unsigned lane index; an out-of-range source index produces poison,
    /// which LlvmDefinedBehaviorV1 may refine without introducing a trap.
    ExtractElement {
        vector: Operand,
        index: Operand,
    },
    /// Replace one lane and retain every other defined original lane.
    InsertElement {
        vector: Operand,
        value: Operand,
        index: Operand,
    },
    /// Source integer-lane-width modular addition across all fixed lanes.
    VectorReduceAdd {
        value: Operand,
    },
    /// A nonempty constant path through original struct fields/array elements.
    ExtractValue {
        aggregate: Operand,
        indices: Vec<u64>,
    },
    /// Replace exactly the selected source value, retaining every other leaf.
    InsertValue {
        aggregate: Operand,
        value: Operand,
        indices: Vec<u64>,
    },
    Alloca {
        size: u64,
        alignment: u64,
    },
    /// Address of the named TLS storage instance in the calling thread. It is
    /// neither a process-wide symbol address nor a constant initializer value.
    ThreadLocalAddress {
        global: String,
    },
    /// Byte offset has already been computed using the frontend DataLayout.
    Gep {
        base: Operand,
        offset: Operand,
        inbounds: bool,
    },
    /// Mask address bits while preserving the original pointer's underlying
    /// object/provenance. The current native profile is integral AS0 with
    /// 64-bit pointer and index widths; this is not an integer round trip.
    PtrMask {
        pointer: Operand,
        mask: Operand,
        /// Original LLVM call-result pointer alignment. A present constraint
        /// must be independently proved from the literal mask (or be 1).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        return_alignment: Option<u64>,
    },
    Load {
        pointer: Operand,
        alignment: u64,
        volatile: bool,
    },
    Store {
        pointer: Operand,
        value: Operand,
        alignment: u64,
        volatile: bool,
    },
    /// Atomic accesses are never ordinary loads/stores or byte-split memory.
    /// The scope resolves through this module's exact atomic_sync_scopes table.
    AtomicLoad {
        pointer: Operand,
        alignment: u64,
        volatile: bool,
        ordering: AtomicOrdering,
        sync_scope: u32,
    },
    AtomicStore {
        pointer: Operand,
        value: Operand,
        alignment: u64,
        volatile: bool,
        ordering: AtomicOrdering,
        sync_scope: u32,
    },
    AtomicFence {
        ordering: AtomicOrdering,
        sync_scope: u32,
    },
    /// Returns the original value, including for operations that leave its bits
    /// unchanged. Every successful operation remains a read-modify-write event.
    AtomicRmw {
        kind: AtomicRmwOp,
        pointer: Operand,
        value: Operand,
        alignment: u64,
        volatile: bool,
        ordering: AtomicOrdering,
        sync_scope: u32,
    },
    /// Original unpacked {T,i1}: old value and success flag. Weakness permits
    /// spurious failure; it does not permit changing the returned value. LLVM22
    /// permits failure ordering stronger than success ordering.
    AtomicCompareExchange {
        pointer: Operand,
        expected: Operand,
        replacement: Operand,
        alignment: u64,
        volatile: bool,
        weak: bool,
        success_ordering: AtomicOrdering,
        failure_ordering: AtomicOrdering,
        sync_scope: u32,
    },
    Call {
        #[serde(default, skip_serializing_if = "ControlEffects::is_empty")]
        control_effects: ControlEffects,
        callee: Operand,
        signature: Signature,
        args: Vec<Operand>,
    },
    /// Receives the original exception pointer and selector on an unwind edge.
    /// Its result is the source unpacked {ptr, i32}, without memory padding.
    LandingPad {
        cleanup: bool,
        clauses: Vec<ExceptionClause>,
    },
    /// A selector in this function's LSDA type table, shared with catch/filter
    /// entries. This is not an ordinary call to an unresolved LLVM intrinsic.
    EhTypeId {
        typeinfo: Operand,
    },
    Phi {
        incoming: Vec<PhiIncoming>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    URem,
    SRem,
    Shl,
    LShr,
    AShr,
    And,
    Or,
    Xor,
}

/// Retained LLVM fast-math promises. The strict realization does not exploit
/// these permissions; it must not invent reassociation, contraction or NaNs.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct FastMathFlags {
    pub reassoc: bool,
    pub nnan: bool,
    pub ninf: bool,
    pub nsz: bool,
    pub arcp: bool,
    pub contract: bool,
    pub afn: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FloatBinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FloatPredicate {
    False,
    Oeq,
    Ogt,
    Oge,
    Olt,
    Ole,
    One,
    Ord,
    Uno,
    Ueq,
    Ugt,
    Uge,
    Ult,
    Ule,
    Une,
    True,
}

/// Distinct from floating-point min/max and the atomic read-modify-write kinds.
/// In particular, signed i1 orders true (-1) before false (0).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntegerMinMaxKind {
    Smin,
    Smax,
    Umin,
    Umax,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntPredicate {
    Eq,
    Ne,
    Ugt,
    Uge,
    Ult,
    Ule,
    Sgt,
    Sge,
    Slt,
    Sle,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CastOp {
    Trunc,
    ZExt,
    SExt,
    PtrToInt,
    IntToPtr,
    Bitcast,
    FpTrunc,
    FpExt,
    FpToUi,
    FpToSi,
    UiToFp,
    SiToFp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhiIncoming {
    pub block: BlockId,
    pub value: Operand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchCase {
    /// An exact-width integer constant; verified cases have unique bit patterns.
    pub value: Operand,
    pub target: BlockId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Terminator {
    Return {
        value: Option<Operand>,
    },
    Jump {
        target: BlockId,
    },
    Branch {
        condition: Operand,
        on_true: BlockId,
        on_false: BlockId,
    },
    /// All original destinations are explicit CFG edges, including repeats.
    IndirectBranch {
        address: Operand,
        destinations: Vec<BlockId>,
    },
    Switch {
        condition: Operand,
        default: BlockId,
        cases: Vec<SwitchCase>,
    },
    /// The call result exists only on the normal edge, not in the invoking
    /// block or on its unwind edge. Both successor identities are retained.
    Invoke {
        callee: Operand,
        signature: Signature,
        args: Vec<Operand>,
        result: Option<Value>,
        normal: BlockId,
        unwind: BlockId,
    },
    /// Re-raises the original exception through the Itanium resume interface;
    /// this terminator cannot return to the function's ordinary caller.
    Resume {
        value: Operand,
    },
    Unreachable,
}

impl NativeModule {
    /// Conservative whole-module gate, including cold/unused declarations.
    pub fn has_nonlocal_control_effects(&self) -> bool {
        self.functions.iter().any(|function| {
            function.control_effects.returns_twice
                || function
                    .blocks
                    .iter()
                    .flat_map(|block| &block.instructions)
                    .any(|instruction| {
                        matches!(&instruction.operation, Operation::Call { control_effects, .. }
                        if control_effects.returns_twice)
                    })
        })
    }

    /// Raw site effects remain distinct from the direct declaration's effects.
    /// Unknown indirect/alias combinations are not inferred from symbol names.
    pub fn effective_returns_twice(&self, callee: &Operand, site: ControlEffects) -> bool {
        site.returns_twice
            || matches!(callee, Operand::Symbol { name, .. }
            if self.functions.iter().any(|function|
                function.name == *name && function.control_effects.returns_twice))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, super::Diagnostic> {
        let module: Self = serde_json::from_slice(bytes)
            .map_err(|error| error_diagnostic(format!("invalid native module: {error}")))?;
        super::native_verify::verify(&module)?;
        Ok(module)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, super::Diagnostic> {
        super::native_verify::verify(self)?;
        serde_json::to_vec_pretty(self).map_err(|error| error_diagnostic(error.to_string()))
    }
}

pub(crate) fn error_diagnostic(message: impl Into<String>) -> super::Diagnostic {
    super::Diagnostic {
        file: "<native-module>".into(),
        span: super::Span::default(),
        message: message.into(),
    }
}

#[cfg(test)]
mod metadata_wire_tests {
    use super::Type;
    use serde_json::json;

    #[test]
    fn unsized_metadata_type_rejects_every_invented_storage_or_abi_field() {
        assert_eq!(
            serde_json::from_value::<Type>(json!({"kind":"metadata"})).unwrap(),
            Type::Metadata {}
        );
        for (name, value) in [
            ("size", json!(8)),
            ("alignment", json!(8)),
            ("address_space", json!(0)),
            ("bits", json!(64)),
        ] {
            let mut input = json!({"kind":"metadata"});
            input[name] = value;
            assert!(
                serde_json::from_value::<Type>(input).is_err(),
                "accepted invented metadata {name}"
            );
        }
    }
}
