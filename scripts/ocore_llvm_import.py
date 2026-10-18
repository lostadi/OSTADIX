#!/usr/bin/env python3
"""Parse and verify LLVM IR with a pinned LLVM, then import supported whole units.

This is a deliberately fail-closed scalar importer, not a runtime coverage claim.
The consumer must run the independent NativeModule verifier before emission.
No LLVM object emitter or printed-IR parser is used. Running the CLI isolates
LLVM's native parser and its handle lifetimes from the compiler process.
"""

from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

if "audit_bitcode" not in globals():
    try:
        from ocore_llvm_bitcode import BitcodeFailure, audit_bitcode
    except ModuleNotFoundError:
        from scripts.ocore_llvm_bitcode import BitcodeFailure, audit_bitcode


PINNED_VERSION = (22, 1, 6)
PINNED_SHA256 = "ed4f320c4e1ed6de7d2db6fd89faccf764d63186c2f877057ddf31065b1fac09"
PINNED_RUST = "1.97.1"
FORMAT = "ocore-native-module-v1"
P, U, Q, B, S = C.c_void_p, C.c_uint, C.c_uint64, C.c_int, C.c_size_t


class ImportFailure(Exception):
    """A complete input unit could not be imported; no partial output is valid."""

    def __init__(self, message: str, stage: str = "import", symbol: str = ""):
        self.stage, self.symbol = stage, symbol
        super().__init__(message)


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def discover_library() -> Path:
    rustup = Path(os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")))
    matches = list((rustup / "toolchains").glob(
        f"{PINNED_RUST}-*/lib/libLLVM.so.22.1-rust-{PINNED_RUST}-stable"))
    if len(matches) != 1:
        raise ImportFailure("exactly one pinned Rust LLVM ELF is required; pass --llvm-library and --llvm-sha256", "toolchain")
    return matches[0]


class LLVM:
    def __init__(self, path: Path, expected_sha256: str):
        self.digest = _digest(path)
        if self.digest != expected_sha256:
            raise ImportFailure(f"LLVM library digest mismatch: expected {expected_sha256}, got {self.digest}", "toolchain")
        with path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise ImportFailure("LLVM library is not an ELF shared library", "toolchain")
        try:
            self.lib = C.CDLL(str(path.resolve()))
        except OSError as error:
            raise ImportFailure(str(error), "toolchain") from error
        bindings = {
            "LLVMGetVersion": (None, [C.POINTER(U)] * 3),
            "LLVMContextCreate": (P, []), "LLVMContextDispose": (None, [P]),
            "LLVMCreateMemoryBufferWithMemoryRangeCopy": (P, [C.c_char_p, S, C.c_char_p]),
            "LLVMDisposeMemoryBuffer": (None, [P]),
            "LLVMWriteBitcodeToMemoryBuffer": (P, [P]),
            "LLVMGetBufferStart": (P, [P]), "LLVMGetBufferSize": (S, [P]),
            "LLVMParseIRInContext2": (B, [P, P, C.POINTER(P), C.POINTER(P)]),
            "LLVMDisposeModule": (None, [P]), "LLVMDisposeMessage": (None, [P]),
            "LLVMVerifyModule": (B, [P, B, C.POINTER(P)]),
            "LLVMGetTarget": (C.c_char_p, [P]), "LLVMGetDataLayoutStr": (C.c_char_p, [P]),
            "LLVMCreateTargetData": (P, [C.c_char_p]), "LLVMDisposeTargetData": (None, [P]),
            "LLVMPointerSize": (U, [P]), "LLVMByteOrder": (B, [P]),
            "LLVMABISizeOfType": (Q, [P, P]), "LLVMStoreSizeOfType": (Q, [P, P]),
            "LLVMABIAlignmentOfType": (U, [P, P]), "LLVMOffsetOfElement": (Q, [P, P, U]),
            "LLVMGetModuleIdentifier": (P, [P, C.POINTER(S)]),
            "LLVMGetModuleInlineAsm": (P, [P, C.POINTER(S)]),
            "LLVMGetFirstFunction": (P, [P]), "LLVMGetNextFunction": (P, [P]),
            "LLVMGetNamedFunction": (P, [P, C.c_char_p]),
            "LLVMDeleteFunction": (None, [P]),
            "LLVMGetFirstGlobal": (P, [P]), "LLVMGetNextGlobal": (P, [P]),
            "LLVMGetFirstGlobalAlias": (P, [P]), "LLVMGetNextGlobalAlias": (P, [P]),
            "LLVMAliasGetAliasee": (P, [P]), "LLVMIsAGlobalAlias": (P, [P]),
            "LLVMGetFirstGlobalIFunc": (P, [P]),
            "LLVMGetValueName2": (P, [P, C.POINTER(S)]), "LLVMTypeOf": (P, [P]),
            "LLVMGetFirstUse": (P, [P]), "LLVMGetNextUse": (P, [P]),
            "LLVMGetUser": (P, [P]),
            "LLVMGlobalGetValueType": (P, [P]), "LLVMGetTypeKind": (B, [P]),
            "LLVMTypeIsSized": (B, [P]),
            "LLVMGetIntTypeWidth": (U, [P]), "LLVMGetPointerAddressSpace": (U, [P]),
            "LLVMGetArrayLength2": (Q, [P]), "LLVMGetElementType": (P, [P]),
            "LLVMCountStructElementTypes": (U, [P]), "LLVMGetStructElementTypes": (None, [P, C.POINTER(P)]),
            "LLVMIsPackedStruct": (B, [P]), "LLVMIsOpaqueStruct": (B, [P]),
            "LLVMCountParamTypes": (U, [P]), "LLVMGetParamTypes": (None, [P, C.POINTER(P)]),
            "LLVMGetReturnType": (P, [P]), "LLVMIsFunctionVarArg": (B, [P]),
            "LLVMGetLinkage": (B, [P]), "LLVMGetVisibility": (B, [P]),
            "LLVMGetDLLStorageClass": (B, [P]), "LLVMGetSection": (C.c_char_p, [P]),
            "LLVMGetUnnamedAddress": (B, [P]),
            "LLVMGetComdat": (P, [P]), "LLVMGetAlignment": (U, [P]),
            "LLVMGetOrInsertComdat": (P, [P, C.c_char_p]),
            "LLVMGetComdatSelectionKind": (B, [P]),
            "LLVMIsThreadLocal": (B, [P]), "LLVMIsExternallyInitialized": (B, [P]),
            "LLVMGetThreadLocalMode": (B, [P]),
            "LLVMIsGlobalConstant": (B, [P]), "LLVMGetInitializer": (P, [P]),
            "LLVMGetGC": (C.c_char_p, [P]), "LLVMHasPersonalityFn": (B, [P]),
            "LLVMGetPersonalityFn": (P, [P]),
            "LLVMHasPrefixData": (B, [P]), "LLVMHasPrologueData": (B, [P]),
            "LLVMGetFunctionCallConv": (U, [P]), "LLVMGetIntrinsicID": (U, [P]),
            "LLVMGetAttributeCountAtIndex": (U, [P, U]),
            "LLVMGetAttributesAtIndex": (None, [P, U, C.POINTER(P)]),
            "LLVMGetCallSiteAttributeCount": (U, [P, U]),
            "LLVMGetCallSiteAttributes": (None, [P, U, C.POINTER(P)]),
            "LLVMGetEnumAttributeKindForName": (U, [C.c_char_p, S]),
            "LLVMGetEnumAttributeKind": (U, [P]), "LLVMGetEnumAttributeValue": (Q, [P]),
            "LLVMIsEnumAttribute": (B, [P]), "LLVMIsStringAttribute": (B, [P]),
            "LLVMIsTypeAttribute": (B, [P]), "LLVMGetTypeAttributeValue": (P, [P]),
            "LLVMGetStringAttributeKind": (P, [P, C.POINTER(U)]),
            "LLVMGetStringAttributeValue": (P, [P, C.POINTER(U)]),
            "LLVMCountParams": (U, [P]), "LLVMGetParams": (None, [P, C.POINTER(P)]),
            "LLVMGetFirstBasicBlock": (P, [P]), "LLVMGetNextBasicBlock": (P, [P]),
            "LLVMGetFirstInstruction": (P, [P]), "LLVMGetNextInstruction": (P, [P]),
            "LLVMGetBasicBlockTerminator": (P, [P]), "LLVMGetInstructionOpcode": (B, [P]),
            "LLVMGetInstructionParent": (P, [P]),
            "LLVMGetNumOperands": (B, [P]), "LLVMGetOperand": (P, [P, U]),
            "LLVMConstIntGetZExtValue": (Q, [P]), "LLVMGetConstOpcode": (B, [P]),
            "LLVMIsNull": (B, [P]),
            "LLVMGetAggregateElement": (P, [P, U]),
            "LLVMGetICmpPredicate": (B, [P]), "LLVMGetICmpSameSign": (B, [P]),
            "LLVMGetNUW": (B, [P]), "LLVMGetNSW": (B, [P]), "LLVMGetExact": (B, [P]),
            "LLVMGetIsDisjoint": (B, [P]), "LLVMGetNNeg": (B, [P]),
            "LLVMIsInBounds": (B, [P]), "LLVMGEPGetNoWrapFlags": (U, [P]),
            "LLVMGetGEPSourceElementType": (P, [P]), "LLVMGetAllocatedType": (P, [P]),
            "LLVMGetVolatile": (B, [P]), "LLVMGetOrdering": (B, [P]),
            "LLVMIsAtomic": (B, [P]), "LLVMGetAtomicSyncScopeID": (U, [P]),
            "LLVMGetAtomicRMWBinOp": (B, [P]), "LLVMGetWeak": (B, [P]),
            "LLVMGetCmpXchgSuccessOrdering": (B, [P]),
            "LLVMGetCmpXchgFailureOrdering": (B, [P]),
            "LLVMGetCalledValue": (P, [P]), "LLVMGetCalledFunctionType": (P, [P]),
            "LLVMGetNumArgOperands": (U, [P]),
            "LLVMGetInstructionCallConv": (U, [P]), "LLVMGetNumOperandBundles": (U, [P]),
            "LLVMGetTailCallKind": (B, [P]),
            "LLVMGetNormalDest": (P, [P]), "LLVMGetUnwindDest": (P, [P]),
            "LLVMGetNumClauses": (U, [P]), "LLVMGetClause": (P, [P, U]),
            "LLVMIsCleanup": (B, [P]),
            "LLVMCountIncoming": (U, [P]), "LLVMGetIncomingValue": (P, [P, U]),
            "LLVMGetIncomingBlock": (P, [P, U]),
            "LLVMGetNumIndices": (U, [P]), "LLVMGetIndices": (C.POINTER(U), [P]),
            "LLVMGetNumSuccessors": (U, [P]), "LLVMGetSuccessor": (P, [P, U]),
            "LLVMGetCondition": (P, [P]),
            "LLVMGetSwitchCaseValue": (P, [P, U]),
            "LLVMGetMDKindIDInContext": (U, [P, C.c_char_p, U]),
            "LLVMInstructionGetAllMetadataOtherThanDebugLoc": (P, [P, C.POINTER(S)]),
            "LLVMGetMetadata": (P, [P, U]),
            "LLVMGlobalCopyAllMetadata": (P, [P, C.POINTER(S)]),
            "LLVMValueMetadataEntriesGetKind": (U, [P, U]),
            "LLVMValueMetadataEntriesGetMetadata": (P, [P, U]),
            "LLVMMetadataAsValue": (P, [P, P]),
            "LLVMValueAsMetadata": (P, [P]),
            "LLVMGetMetadataKind": (U, [P]),
            "LLVMPrintValueToString": (P, [P]),
            "LLVMDisposeValueMetadataEntries": (None, [P]),
            "LLVMGetFirstNamedMetadata": (P, [P]), "LLVMGetNextNamedMetadata": (P, [P]),
            "LLVMGetNamedMetadataName": (P, [P, C.POINTER(S)]),
            "LLVMGetNamedMetadataNumOperands": (U, [P, C.c_char_p]),
            "LLVMGetNamedMetadataOperands": (None, [P, C.c_char_p, C.POINTER(P)]),
            "LLVMGetMDNodeNumOperands": (U, [P]), "LLVMGetMDNodeOperands": (None, [P, C.POINTER(P)]),
            "LLVMGetMDString": (P, [P, C.POINTER(U)]),
        }
        for name in ("Constant", "ConstantInt", "ConstantPointerNull", "ConstantAggregateZero", "ConstantExpr", "AllocaInst",
                     "Function", "GlobalVariable", "UndefValue", "PoisonValue", "MDString", "MDNode",
                     "LoadInst", "StoreInst", "FenceInst", "AtomicRMWInst", "AtomicCmpXchgInst"):
            bindings["LLVMIsA" + name] = (P, [P])
        try:
            for name, (result, args) in bindings.items():
                fn = getattr(self.lib, name)
                fn.restype, fn.argtypes = result, args
                setattr(self, name.removeprefix("LLVM"), fn)
        except AttributeError as error:
            raise ImportFailure(f"pinned LLVM C API missing: {error}", "toolchain") from error
        version = [U(), U(), U()]
        self.GetVersion(*(C.byref(part) for part in version))
        self.version = tuple(part.value for part in version)
        if self.version != PINNED_VERSION:
            raise ImportFailure(f"LLVM {self.version} is not supported; expected {PINNED_VERSION}", "toolchain")

    @staticmethod
    def string(fn, value, length_type=S) -> str:
        length = length_type()
        pointer = fn(value, C.byref(length))
        try:
            return C.string_at(pointer, length.value).decode("utf-8") if pointer else ""
        except UnicodeDecodeError as error:
            raise ImportFailure("non-UTF8 names are not representable in native module v1") from error

    @staticmethod
    def sequence(first, next_value, owner):
        value = first(owner)
        while value:
            yield value
            value = next_value(value)

    def name(self, value):
        return self.string(self.GetValueName2, value)


class Importer:
    VISIBILITY = {0: "default", 1: "hidden", 2: "protected"}
    TLS_PROFILE = "linux-elf-static-nonpreemptive-v1"
    ATOMIC_PROFILE = "coherent-ram-v1"
    ATOMIC_ORDERINGS = {1: "unordered", 2: "monotonic", 4: "acquire", 5: "release",
                        6: "acq_rel", 7: "seq_cst"}
    # Public LLVMAtomicRMWBinOp differs from the internal C++ enum after14.
    ATOMIC_RMW_OPS = dict(enumerate(("xchg", "add", "sub", "and", "nand", "or", "xor",
                                   "max", "min", "umax", "umin", "fadd", "fsub", "fmax", "fmin",
                                   "uinc_wrap", "udec_wrap", "usub_cond", "usub_sat",
                                   "fmaximum", "fminimum")))
    TLS_MODELS = {1: "general_dynamic", 2: "local_dynamic", 3: "initial_exec", 4: "local_exec"}
    LIFETIME_INTRINSICS = {"llvm.lifetime.start.p0", "llvm.lifetime.end.p0"}
    MEMORY_INTRINSICS = {f"llvm.memset.p0.i{bits}" for bits in (32, 64)} | {
        f"llvm.{operation}.p0.p0.i{bits}" for operation in ("memcpy", "memmove") for bits in (32, 64)}
    OVERFLOW_INTRINSICS = {f"llvm.{operation}.with.overflow.i{bits}"
                           for operation in ("sadd", "uadd", "ssub", "usub", "smul", "umul")
                           for bits in range(1, 65)}
    # Exact selected LLVM22 provider IDs, not recognition by a name prefix.
    MINMAX_IDS = {"smin": 343, "smax": 342, "umin": 380, "umax": 379}
    MINMAX_INTRINSICS = {f"llvm.{kind}.i{bits}": intrinsic_id
                         for kind, intrinsic_id in MINMAX_IDS.items() for bits in range(1, 65)}
    RELATIVE_INTRINSICS = {"llvm.load.relative.i32", "llvm.load.relative.i64"}
    NOALIAS_INTRINSIC = "llvm.experimental.noalias.scope.decl"
    INTRINSICS = {"llvm.assume", "llvm.trap", "llvm.eh.typeid.for.p0", "llvm.threadlocal.address.p0", NOALIAS_INTRINSIC} | LIFETIME_INTRINSICS | MEMORY_INTRINSICS | OVERFLOW_INTRINSICS | RELATIVE_INTRINSICS | set(MINMAX_INTRINSICS)
    BIN = {8: "add", 10: "sub", 12: "mul", 14: "u_div", 15: "s_div", 17: "u_rem", 18: "s_rem",
           20: "shl", 21: "l_shr", 22: "a_shr", 23: "and", 24: "or", 25: "xor"}
    CAST = {30: "trunc", 31: "z_ext", 32: "s_ext", 39: "ptr_to_int", 40: "int_to_ptr", 41: "bitcast"}
    CMP = dict(zip(range(32, 42), ("eq", "ne", "ugt", "uge", "ult", "ule", "sgt", "sge", "slt", "sle")))
    LINKAGES = {0: "external", 2: "linkonce", 3: "linkonce_odr", 5: "weak",
                6: "weak_odr", 8: "internal", 9: "private"}
    BITCODE_LINKAGES = {0: 0, 2: 18, 3: 19, 5: 16, 6: 17, 8: 3, 9: 9}
    MERGEABLE_DEFINITIONS = {"linkonce", "linkonce_odr", "weak", "weak_odr"}
    # These assumptions may be erased because emission never uses them to optimize.
    # ABI attributes and code generation requirements are handled separately.
    ERASED = {"noundef", "nonnull", "noalias", "readnone", "readonly", "writeonly", "nounwind", "noreturn",
              "norecurse", "nosync", "nofree", "willreturn", "mustprogress", "speculatable",
              "alwaysinline", "noinline", "inlinehint", "optnone", "optsize", "minsize", "cold", "hot", "memory",
              "vscale_range", "nonlazybind", "nobuiltin", "captures", "nocallback"}
    # Restriction payloads are not reused by the unoptimized native emitters.
    # The original bytes are identified by input_sha256 for audit/reproduction.
    ERASED_RESTRICTIONS = {"range", "initializes"}
    METADATA = {"dbg", "tbaa", "tbaa.struct", "alias.scope", "noalias", "range", "nonnull",
                "nontemporal", "invariant.load", "invariant.group", "llvm.loop", "prof",
                "align", "dereferenceable", "dereferenceable_or_null", "unpredictable"}

    def __init__(self, api: LLVM, context, module, tls_profile=None, atomic_profile=None):
        self.a, self.context, self.module = api, context, module
        if tls_profile not in {None, self.TLS_PROFILE}:
            raise ImportFailure(f"unsupported TLS profile {tls_profile}")
        self.tls_profile = tls_profile
        if atomic_profile not in {None, self.ATOMIC_PROFILE}:
            raise ImportFailure(f"unsupported atomic profile {atomic_profile}")
        self.atomic_profile = atomic_profile
        self.atomic_sync_scope_names = None
        self.atomic_sync_scope_ids = set()
        self.types, self.type_ids, self.refinements = [], {}, set()
        self.values, self.block_ids, self.next_id = {}, {}, 0
        self.instruction_positions = {}
        self.source_sites = {}
        self.noalias_metadata = {"domains": [], "scopes": [], "lists": [], "attachments": []}
        self.noalias_nodes = {}
        self.noalias_node_sources = []
        self.producer_ident = []
        self.target_abi = None
        self.metadata_checked = False
        self.symbol_alignments = {}
        self.alias_contracts = {}
        self.comdats = []
        self.symbol_comdats = {}
        self.comdat_handles = {}
        self.symbol_values = {}
        self.metadata_personalities = set()
        self.exception_handling = None
        self.symbol = ""
        self.attribute_names = {}
        for name in self.ERASED | self.ERASED_RESTRICTIONS | {
                "signext", "zeroext", "uwtable", "align", "dereferenceable", "dereferenceable_or_null",
                "immarg", "dead_on_unwind", "allockind", "allocsize", "allocalign", "allocptr",
                "writable", "returned", "builtin", "sret",
                "nocreateundeforpoison"}:
            kind = api.GetEnumAttributeKindForName(name.encode(), len(name))
            if kind:
                self.attribute_names[kind] = name
        self.metadata_names = {api.GetMDKindIDInContext(context, name.encode(), len(name)): name for name in self.METADATA}
        self.noundef_metadata_kind = api.GetMDKindIDInContext(context, b"noundef", 7)

    def reject(self, message):
        raise ImportFailure(message, symbol=self.symbol)

    def ty(self, llvm_type):
        if llvm_type in self.type_ids:
            return self.type_ids[llvm_type]
        a, kind = self.a, self.a.GetTypeKind(llvm_type)
        ident = len(self.types)
        self.type_ids[llvm_type] = ident
        self.types.append(None)
        if kind == 0:
            result = {"kind": "void"}
        elif kind == 5:
            # LLVM FP128 is IEEE binary128, distinct from PPC_FP128 and i128.
            # Only its storage layout is admitted; value_type and native ABI/
            # executable-value audits reject every first-class use.
            if (a.ABISizeOfType(self.layout, llvm_type) != 16
                    or a.ABIAlignmentOfType(self.layout, llvm_type) != 16):
                self.reject("binary128 storage layout requires exactly 16-byte ABI size and alignment")
            result = {"kind": "float", "bits": 128}
            self.refinements.add("retained IEEE binary128 solely as original 16-byte size/alignment storage layout; alloca/GEP, positive-zero static storage and raw memory copies do not imply floating arithmetic, first-class SSA or ABI support")
        elif kind == 8:
            bits = a.GetIntTypeWidth(llvm_type)
            if not 1 <= bits <= 64:
                self.reject(f"unsupported integer width i{bits}")
            result = {"kind": "int", "bits": bits}
        elif kind == 12:
            space = a.GetPointerAddressSpace(llvm_type)
            if space != 0:
                self.reject(f"unsupported pointer address space {space}")
            result = {"kind": "pointer", "address_space": space}
        elif kind == 11:
            result = {"kind": "array", "element": self.ty(a.GetElementType(llvm_type)), "len": a.GetArrayLength2(llvm_type)}
        elif kind == 10:
            if a.IsOpaqueStruct(llvm_type):
                self.reject("opaque structure has no importable layout")
            fields = (P * a.CountStructElementTypes(llvm_type))()
            a.GetStructElementTypes(llvm_type, fields)
            result = {"kind": "struct", "fields": [self.ty(field) for field in fields], "packed": bool(a.IsPackedStruct(llvm_type))}
        elif kind == 9:
            result = {"kind": "function", "signature": self.signature(llvm_type)}
        else:
            self.reject(f"unsupported LLVM type kind {kind} (float, vector, token and target types require another lowering)")
        self.types[ident] = result
        return ident

    def contains_binary128(self, ty):
        pending, seen = [ty], set()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            record = self.types[current]
            if record["kind"] == "float" and record["bits"] == 128:
                return True
            if record["kind"] == "struct":
                pending.extend(record["fields"])
            elif record["kind"] == "array":
                # Even zero-length first-class array types retain this contract.
                pending.append(record["element"])
        return False

    def scalar(self, llvm_type):
        ty = self.ty(llvm_type)
        if self.types[ty]["kind"] not in {"int", "pointer"}:
            self.reject("aggregate SSA/call values are unsupported")
        return ty

    def value_type(self, llvm_type):
        """Preserve sized scalar or aggregate value types without ABI coercion."""
        kind = self.a.GetTypeKind(llvm_type)
        if kind in {10, 11} and not self.a.TypeIsSized(llvm_type):
            self.reject("aggregate SSA requires a supported sized struct or array")
        ty = self.ty(llvm_type)
        if self.contains_binary128(ty):
            self.reject("binary128 is supported only for storage layout, not first-class SSA or ABI values")
        if self.types[ty]["kind"] not in {"int", "pointer", "struct", "array"}:
            self.reject("unsupported SSA value type")
        if kind in {10, 11}:
            self.refinements.add("aggregate SSA retains original nested struct fields and array elements, typed poison/undef, PHI/select and element-wise freeze; padding is not an SSA field; memory lowering requires original DataLayout leaf offsets and allocation strides; native aggregate C/fastcc ABI classification remains mandatory")
        return ty

    def attribute_records(self, value, index, call=False):
        a = self.a
        count = (a.GetCallSiteAttributeCount if call else a.GetAttributeCountAtIndex)(value, index)
        attributes = (P * count)()
        (a.GetCallSiteAttributes if call else a.GetAttributesAtIndex)(value, index, attributes)
        return attributes

    def riscv_abi_features(self, text):
        if self.target_abi != "lp64d":
            return
        # This is a bounded compatibility check against the declared own
        # RV64GC execution profile, not reconstruction of the producer's CPU.
        # Pinned LLVM processes feature tokens in order: enabling sets implied
        # features; disabling clears their reverse dependents. D -> F -> Zicsr.
        d, e, uncertain = True, False, False
        for feature in text.split(","):
            if feature in {"+d", "+q", "+zcd", "+zve64d", "+v"}:
                d, uncertain = True, False
            elif feature in {"-d", "-f", "-zicsr"}:
                d, uncertain = False, False
            elif feature == "+e":
                e = True
            elif feature == "-e":
                e = False
            elif feature.startswith("+") and feature not in {"+f", "+zicsr"} and not d:
                # An unmodeled positive dependency may restore D. Do not
                # misdiagnose a verified but unsupported sequence as invalid.
                uncertain = True
        if e:
            self.reject("lp64d conflicts with the enabled E feature under the own RV64GC profile")
        if not d:
            if uncertain:
                self.reject("unsupported lp64d target-feature implication sequence under the own RV64GC profile")
            self.reject("lp64d requires enabled D/F/Zicsr features under the own RV64GC profile")
        self.refinements.add("lp64d target-feature ordering checked against the declared own RV64GC D/F/Zicsr-enabled, E-disabled execution profile; known implications retained, unknown restoring sequences remain unsupported; no original CPU normalization or ABI inference")

    def allocator_profile(self, value, call, intrinsic):
        a = self.a
        function_type = (a.GetCalledFunctionType if call else a.GlobalGetValueType)(value)
        convention = (a.GetInstructionCallConv if call else a.GetFunctionCallConv)(value)
        if intrinsic is not None or convention != 0 or a.IsFunctionVarArg(function_type):
            self.reject("allocator descriptions require an ordinary supported fixed C function or callsite")
        return function_type

    def allocator_description(self, value, index, name, payload, call):
        site = "callsite" if call else "function"
        if call:
            block, instruction = self.instruction_positions[value]
            position = f"parsed block {block} instruction {instruction}"
        else:
            position = f"parsed function {self.a.name(value)}"
        self.refinements.add(f"{self.symbol}: {site} attribute index {index}: validated allocator description {name}={payload}; {position}; original body, calls, arguments, memory effects and dependency symbols retained; no allocator substitution, elision, zeroing, purity, runtime value guard or provider closure inferred")
        self.refinements.add("allocator descriptions validated after pinned LLVM parsing and attribute normalization; input_sha256 binds the original bytes; exact parsed names, values and attribute positions retained without callee inheritance; allocptr pointer types and actual free/realloc effects are preserved")

    def attrs(self, value, index, call=False, intrinsic=None, attribute_type=None):
        a = self.a
        attributes = self.attribute_records(value, index, call)
        preserved = []
        for attribute in attributes:
            if a.IsStringAttribute(attribute):
                key = a.string(a.GetStringAttributeKind, attribute, U)
                text = a.string(a.GetStringAttributeValue, attribute, U)
                if key in {"alloc-family", "alloc-variant-zeroed"}:
                    self.allocator_profile(value, call, intrinsic)
                    if index != 0xffffffff or not text or "\0" in text:
                        self.reject(f"{key} requires a nonempty ordinary function-slot string description without NUL")
                    self.allocator_description(value, index, key, repr(text), call)
                    if key == "alloc-variant-zeroed":
                        # LLVM verifies a present Function's compatible family,
                        # zeroed kind and exact type. An absent alternative is
                        # valid: no optimization here chooses or calls it.
                        self.refinements.add(f"{self.symbol}: alloc-variant-zeroed={text!r} remains an optional optimizer alternative; no function, dependency, call or zero-fill is synthesized from this hint")
                    continue
                # Tuning preferences cannot introduce an ABI/security contract.
                if key in {"target-cpu", "tune-cpu", "target-features"} and index == 0xffffffff:
                    if key == "target-features":
                        self.riscv_abi_features(text)
                    self.refinements.add(f"erased target tuning attribute {key}={text}; no target intrinsic lowering")
                    continue
                if index == 0xffffffff and (
                    (key == "min-legal-vector-width" and text == "0")
                    or (key == "no-trapping-math" and text in {"true", "false"})
                    or (key == "stack-protector-buffer-size" and text.isdecimal())
                    or (key == "frame-pointer" and text in {"none", "non-leaf", "all", "non-leaf-no-reserve"})
                    or (key == "no-builtins" and text == "")
                    or (key == "probe-stack" and text == "inline-asm")
                ):
                    if key == "probe-stack":
                        self.refinements.add("required own-emitter guard-page stack probing; frontend probe-stack=inline-asm is not imported machine code")
                    elif key == "frame-pointer":
                        self.refinements.add(f"re-lowered frame-pointer={text}; own emitters preserve a frame pointer in every function")
                    else:
                        self.refinements.add(f"erased scalar codegen preference {key}={text}; no FP/vector/stack-protector operation")
                    continue
                self.reject(f"unsupported string attribute {key}={text}")
            kind = a.GetEnumAttributeKind(attribute)
            name = self.attribute_names.get(kind)
            pointer_indices = {1} if intrinsic and intrinsic.startswith("llvm.memset.") else {1, 2}
            if intrinsic == "llvm.threadlocal.address.p0" and name == "align":
                if (not a.IsEnumAttribute(attribute) or index not in {0, 1}
                        or attribute_type is None or a.GetTypeKind(attribute_type) != 12
                        or a.GetPointerAddressSpace(attribute_type) != 0):
                    self.reject("TLS intrinsic align requires an AS0 pointer return or its sole fixed parameter")
                payload = a.GetEnumAttributeValue(attribute)
                if not payload or payload > 1 << 32 or payload & (payload - 1):
                    self.reject("TLS intrinsic pointer alignment must be a positive power of two, at most 2^32")
                site = "callsite" if call else "function"
                self.refinements.add(f"{self.symbol}: {site} attribute index {index}: erased TLS intrinsic pointer promise align={payload}; original current-thread address operation, global identity, source storage alignment and all memory operations retained; no memory alignment/effect, provider binding or optimization inferred")
                self.refinements.add("TLS intrinsic pointer alignment promises validated after pinned LLVM parsing and attribute normalization; input_sha256 binds the original bytes; no declaration-to-callsite inheritance")
            elif (intrinsic in self.MEMORY_INTRINSICS and index in pointer_indices
                    and name in {"align", "dereferenceable", "dereferenceable_or_null"}
                    and a.IsEnumAttribute(attribute)):
                payload = a.GetEnumAttributeValue(attribute)
                if name == "align" and (not payload or payload > 1 << 32 or payload & (payload - 1)):
                    self.reject("memory intrinsic pointer alignment must be a positive power of two, at most 2^32")
                self.refinements.add(f"{self.symbol}: {intrinsic} pointer index {index}: {name}={payload} validated; own memory operations retain callsite alignment and do not optimize using pointer assumptions")
            elif intrinsic is None and name in {"align", "dereferenceable", "dereferenceable_or_null"}:
                if (not a.IsEnumAttribute(attribute) or index == 0xffffffff
                        or attribute_type is None or a.GetTypeKind(attribute_type) != 12
                        or a.GetPointerAddressSpace(attribute_type) != 0):
                    self.reject(f"{name} requires an integral AS0 pointer result or fixed parameter")
                payload = a.GetEnumAttributeValue(attribute)
                if name == "align":
                    if not payload or payload > 1 << 32 or payload & (payload - 1):
                        self.reject("pointer alignment must be a positive power of two, at most 2^32")
                elif not payload:
                    self.reject(f"{name} requires a positive uint64 byte count")
                site = "callsite" if call else "function"
                self.refinements.add(f"{self.symbol}: {site} attribute index {index}: erased pointer promise {name}={payload}; no native optimization, runtime guard, allocation or speculative memory access assumes this promise")
                self.refinements.add("pointer promises validated after pinned LLVM parsing and attribute normalization; input_sha256 binds the original bytes")
            elif (name == "sret" and intrinsic is None and index in {1, 2}
                    and a.IsTypeAttribute(attribute)):
                # signature() validates the complete return-storage contract
                # and records the actual type payload independently of scalar
                # extension attributes. Never erase or infer this ABI feature.
                continue
            elif name == "writable":
                if (not a.IsEnumAttribute(attribute) or index in {0, 0xffffffff}
                        or attribute_type is None or a.GetTypeKind(attribute_type) != 12
                        or a.GetPointerAddressSpace(attribute_type) != 0
                        or a.GetEnumAttributeValue(attribute) != 0):
                    self.reject("writable requires an integral AS0 pointer fixed parameter/call argument with enum payload zero")
                extents = []
                for paired in attributes:
                    if a.IsEnumAttribute(paired):
                        paired_name = self.attribute_names.get(a.GetEnumAttributeKind(paired))
                        if paired_name in {"dereferenceable", "dereferenceable_or_null"}:
                            condition = " if nonnull" if paired_name == "dereferenceable_or_null" else ""
                            extents.append(f"{paired_name}={a.GetEnumAttributeValue(paired)}{condition}")
                prefix = ", ".join(sorted(extents)) or "no explicit dereferenceable prefix"
                site = "callsite" if call else "function"
                self.refinements.add(f"{self.symbol}: {site} attribute index {index}: validated writable=0 entry-only memory permission ({prefix}); original calls, loads and stores retained; no entry access, speculative store, runtime guard, allocation or lifetime-wide writability inferred")
                self.refinements.add("writable entry permissions are an explicit defined-behavior refinement under nonoptimizing lowering, not an ABI extension; validated after pinned LLVM parsing and normalization; input_sha256 binds the original bytes")
            elif name == "returned":
                if (not a.IsEnumAttribute(attribute) or index in {0, 0xffffffff}
                        or attribute_type is None or a.GetTypeKind(attribute_type) not in {8, 12}
                        or a.GetEnumAttributeValue(attribute) != 0):
                    self.reject("returned requires a supported scalar fixed parameter/call argument with enum payload zero")
                function_type = (a.GetCalledFunctionType if call else a.GlobalGetValueType)(value)
                count = a.CountParamTypes(function_type)
                if index > count or attribute_type != a.GetReturnType(function_type):
                    self.reject("returned requires the exact same supported scalar argument and result type")
                returned_count = sum(
                    a.IsEnumAttribute(candidate)
                    and self.attribute_names.get(a.GetEnumAttributeKind(candidate)) == "returned"
                    for parameter in range(1, count + 1)
                    for candidate in self.attribute_records(value, parameter, call))
                if returned_count != 1:
                    self.reject("returned requires exactly one annotated fixed parameter")
                site = "callsite" if call else "function"
                self.refinements.add(f"{self.symbol}: {site} attribute index {index}: validated returned=0 with exact result type {self.types[self.ty(attribute_type)]}; actual body, calls and result operands retained; no argument substitution, call removal or return-register optimization")
                self.refinements.add("returned is an optional independently validated function/callsite semantic hint under the nonoptimizing C profile; signext/zeroext ABI attributes remain exact; pinned LLVM normalization and input_sha256 bind the original contract")
            elif name == "builtin":
                if (not call or index != 0xffffffff or intrinsic is not None
                        or not a.IsEnumAttribute(attribute) or a.GetEnumAttributeValue(attribute) != 0):
                    self.reject("builtin requires an ordinary direct-call function attribute with enum payload zero")
                callee = a.GetCalledValue(value)
                if not a.IsAFunction(callee) or a.GetIntrinsicID(callee):
                    self.reject("builtin requires an actual direct function callee, not an alias, indirect call or intrinsic")
                nobuiltin = [candidate for candidate in self.attribute_records(callee, 0xffffffff)
                             if a.IsEnumAttribute(candidate)
                             and self.attribute_names.get(a.GetEnumAttributeKind(candidate)) == "nobuiltin"]
                if len(nobuiltin) != 1 or a.GetEnumAttributeValue(nobuiltin[0]) != 0:
                    self.reject("builtin requires the actual direct callee's nobuiltin enum attribute with payload zero")
                self.refinements.add(f"{self.symbol}: callsite function attribute index 4294967295: validated builtin=0 direct callee {a.name(callee)} with underlying nobuiltin=0; original ordinary call, body, side effects and dependency symbol retained; no builtin replacement or intrinsic admission")
                self.refinements.add("builtin recognition permission is ignored by nonoptimizing lowering only after explicit direct-callee validation; input_sha256 binds the original function/callsite contract")
            elif name in {"readnone", "dead_on_unwind"}:
                if (not a.IsEnumAttribute(attribute) or index in {0, 0xffffffff}
                        or attribute_type is None or a.GetTypeKind(attribute_type) != 12
                        or a.GetPointerAddressSpace(attribute_type) != 0
                        or a.GetEnumAttributeValue(attribute) != 0):
                    self.reject(f"{name} requires a pointer parameter/call argument with enum payload zero")
                site = "callsite" if call else "function"
                consequence = ("no native optimization or function purity is inferred" if name == "readnone"
                               else "no unwind-path optimization or exception-handling support is inferred")
                self.refinements.add(f"{self.symbol}: {site} attribute index {index}: erased optimization assumption {name}=0; all calls, loads and stores retained; {consequence}")
                self.refinements.add("optimizer promises validated after pinned LLVM parsing and attribute normalization; input_sha256 binds the original bytes")
            elif name == "allocsize":
                if (not a.IsEnumAttribute(attribute) or index != 0xffffffff
                        or intrinsic is not None):
                    self.reject("allocsize requires an ordinary function or callsite function integer attribute")
                function_type = (a.GetCalledFunctionType if call else a.GlobalGetValueType)(value)
                result_type = a.GetReturnType(function_type)
                convention = (a.GetInstructionCallConv if call else a.GetFunctionCallConv)(value)
                if (a.IsFunctionVarArg(function_type) or convention != 0
                        or a.GetTypeKind(result_type) != 12
                        or a.GetPointerAddressSpace(result_type) != 0):
                    self.reject("allocsize requires the supported fixed C profile with an AS0 pointer result")
                # Integer attributes retain the full uint64 payload, including
                # zero. LLVM packs ordered uint32 indices, with low FFFFFFFF
                # denoting absence; text/bitcode normalization is authoritative.
                payload = a.GetEnumAttributeValue(attribute)
                element = payload >> 32
                count_index = payload & 0xffffffff
                count_index = None if count_index == 0xffffffff else count_index
                if count_index == element:
                    self.reject("allocsize duplicate indices are unsupported by the own fixed C profile")
                count = a.CountParamTypes(function_type)
                params = (P * count)()
                a.GetParamTypes(function_type, params)
                indices = [element] + ([] if count_index is None else [count_index])
                for parameter in indices:
                    if (parameter >= count or a.GetTypeKind(params[parameter]) != 8
                            or not 1 <= a.GetIntTypeWidth(params[parameter]) <= 64):
                        self.reject("allocsize indices require fixed scalar integer parameters of width 1..64")
                site = "callsite" if call else "function"
                number = "absent" if count_index is None else str(count_index)
                self.refinements.add(f"{self.symbol}: {site} attribute index {index}: validated allocsize raw={payload}, element_index={element}, count_index={number}; original body, calls, memory effects, null results and dependency symbols retained; no allocation, zeroing, product computation, runtime guard, trap, purity or nonnull assumption is introduced")
                self.refinements.add("allocsize is an optional allocator-size hint validated after pinned LLVM parsing and integer-attribute normalization; input_sha256 binds the original bytes; raw uint64 and ordered decoded indices retained without callee inheritance or allocator rewriting")
            elif name in {"allocalign", "allocptr"}:
                function_type = self.allocator_profile(value, call, intrinsic)
                if (not a.IsEnumAttribute(attribute) or a.GetEnumAttributeValue(attribute) != 0
                        or not 1 <= index <= a.CountParamTypes(function_type)
                        or attribute_type is None):
                    self.reject(f"{name} requires an enum-zero attribute on an ordinary fixed parameter or call argument")
                kind = a.GetTypeKind(attribute_type)
                if name == "allocalign":
                    if kind != 8 or not 1 <= a.GetIntTypeWidth(attribute_type) <= 64:
                        self.reject("allocalign requires a scalar integer parameter of width 1..64")
                elif kind != 12 or a.GetPointerAddressSpace(attribute_type) != 0:
                    self.reject("allocptr requires an AS0 scalar pointer parameter")
                self.allocator_description(value, index, name, 0, call)
            elif name == "allockind":
                if not a.IsEnumAttribute(attribute) or index != 0xffffffff:
                    self.reject("allockind requires a function or callsite function attribute")
                function_type = self.allocator_profile(value, call, intrinsic)
                payload = a.GetEnumAttributeValue(attribute)
                # Pinned LLVM22 Attributes.h AllocFnKind: these are the six
                # documented bits, not a permissive guessed integer mask.
                alloc, realloc, free, uninitialized, zeroed, aligned = 1, 2, 4, 8, 16, 32
                primary, modifiers = alloc | realloc | free, uninitialized | zeroed | aligned
                base = payload & primary
                if (payload & ~(primary | modifiers) or base not in {alloc, realloc, free}
                        or (payload & (uninitialized | zeroed)) == (uninitialized | zeroed)
                        or (base == free and payload & modifiers)):
                    self.reject(f"unsupported allockind payload {payload}; requires one allocation kind and compatible modifiers")
                if base == free and a.GetTypeKind(a.GetReturnType(function_type)) != 0:
                    self.reject("allockind free requires a void result")
                site = "callsite" if call else "function"
                self.refinements.add(f"{self.symbol}: {site} attribute index {index}: erased allocator description allockind={payload}; original body, calls and dependency symbols retained; no allocator substitution, purity or native optimization assumes this description")
                self.refinements.add("optimizer promises validated after pinned LLVM parsing and attribute normalization; input_sha256 binds the original bytes")
                self.allocator_description(value, index, name, payload, call)
            elif (intrinsic in self.OVERFLOW_INTRINSICS and name == "nocreateundeforpoison"
                    and index == 0xffffffff and a.IsEnumAttribute(attribute)
                    and a.GetEnumAttributeValue(attribute) == 0):
                site = "callsite" if call else "function"
                self.refinements.add(f"{self.symbol}: {site} nocreateundeforpoison=0 realized by the exact owned integer-overflow operation; defined integer operands yield a defined wrapped result and overflow bit; input poison/undef remain represented; no ordinary function purity or optimization inferred")
            elif (intrinsic in self.MINMAX_INTRINSICS and name == "nocreateundeforpoison"
                    and index == 0xffffffff and a.IsEnumAttribute(attribute)
                    and a.GetEnumAttributeValue(attribute) == 0):
                site = "callsite" if call else "function"
                self.refinements.add(f"{self.symbol}: {site} nocreateundeforpoison=0 realized by the exact owned integer-min/max operation; defined integer operands select a defined original-width input; input poison/undef remain represented; no input noundef, ordinary function purity or optimization inferred")
            elif (intrinsic in self.MEMORY_INTRINSICS and name == "immarg" and index == 4
                    and not call and a.IsEnumAttribute(attribute) and a.GetEnumAttributeValue(attribute) == 0):
                self.refinements.add(f"{intrinsic}: volatile immarg contract retained by validating every direct call's constant i1 operand")
            elif name == "uwtable" and a.IsEnumAttribute(attribute):
                level = a.GetEnumAttributeValue(attribute)
                if (index != 0xffffffff or call or level not in {1, 2}
                        or intrinsic is not None):
                    self.reject(f"unsupported uwtable attribute level {level} at index {index}; requires an ordinary function declaration or definition, Sync/Async level and no callsite contract")
                level_name = "Sync" if level == 1 else "Async"
                if a.GetFirstBasicBlock(value):
                    self.refinements.add(f"{self.symbol}: realized function uwtable={level} ({level_name}) with required own-emitter instruction-precise DWARF unwind tables; external provider unwind realization and EH services are not inferred")
                else:
                    self.refinements.add(f"{self.symbol}: retained ordinary declaration uwtable={level} ({level_name}) at function attribute index 4294967295; no function body or consumer unwind-table entry emitted; source declaration, calls and dependencies retained; own native definitions emit instruction-precise CFI, external provider unwind realization and EH services are not inferred")
                self.refinements.add("UWTable attributes validated after pinned LLVM parsing and attribute normalization; input_sha256 binds the original bytes")
            elif name in {"signext", "zeroext"} and index != 0xffffffff:
                preserved.append(name)
            elif name in self.ERASED and a.IsEnumAttribute(attribute):
                self.refinements.add(f"{self.symbol}: attribute index {index}: erased optimization assumption {name}={a.GetEnumAttributeValue(attribute)}")
            elif name in self.ERASED_RESTRICTIONS:
                self.refinements.add(f"{self.symbol}: attribute index {index}: erased {name} restriction payload; no native optimization assumes it")
            else:
                self.reject(f"unsupported attribute kind {kind} at index {index}")
        return sorted(preserved)

    def return_storage(self, owner, call, params, result_type, intrinsic):
        a = self.a
        storage = None
        for parameter, parameter_type in enumerate(params):
            attributes = self.attribute_records(owner, parameter + 1, call)
            for attribute in attributes:
                if (a.IsStringAttribute(attribute)
                        or self.attribute_names.get(a.GetEnumAttributeKind(attribute)) != "sret"):
                    continue
                if (intrinsic is not None or not a.IsTypeAttribute(attribute)
                        or storage is not None or parameter not in {0, 1}
                        or a.GetTypeKind(result_type) != 0
                        or a.GetTypeKind(parameter_type) != 12
                        or a.GetPointerAddressSpace(parameter_type) != 0):
                    self.reject("sret requires exactly one typed AS0 pointer first or second fixed parameter and a void result")
                payload = a.GetTypeAttributeValue(attribute)
                # LLVMVerifyModule does not enforce sret sizedness. This guard
                # precedes any DataLayout access, including nested type layout.
                if not payload or not a.TypeIsSized(payload):
                    self.reject("sret requires a supported sized in-memory type payload")
                storage = {"param": parameter, "ty": self.ty(payload)}
                alignments = [a.GetEnumAttributeValue(candidate) for candidate in attributes
                              if a.IsEnumAttribute(candidate)
                              and self.attribute_names.get(a.GetEnumAttributeKind(candidate)) == "align"]
                alignment = str(alignments[0]) if alignments else "not explicitly specified"
                site = "callsite" if call else "function"
                self.refinements.add(f"{self.symbol}: {site} typed sret parameter {parameter} retains exact in-memory type and explicit alignment {alignment}; original pointer, parameter order, void result, calls and stores retained; caller must provide valid properly aligned return storage; no scalar return or callee attribute inference")
                self.refinements.add("sret ABI metadata validated after pinned LLVM parsing and type-attribute normalization; input_sha256 binds the original bytes; explicit function and callsite return-storage contracts require native ABI validation")
        return storage

    def signature(self, llvm_type, owner=None, call=False, intrinsic=None):
        a = self.a
        convention = (a.GetInstructionCallConv if call else a.GetFunctionCallConv)(owner) if owner else 0
        abi = {0: "c", 8: "fastcc"}.get(convention)
        if abi is None:
            self.reject(f"unsupported calling convention {convention}")
        if intrinsic is not None and convention != 0:
            self.reject("owned intrinsic requires the exact C calling convention")
        count = a.CountParamTypes(llvm_type)
        params = (P * count)()
        a.GetParamTypes(llvm_type, params)
        result_type = a.GetReturnType(llvm_type)
        variadic = bool(a.IsFunctionVarArg(llvm_type))
        metadata_personality = bool(owner and not call and owner in self.metadata_personalities)
        if variadic and not metadata_personality:
            self.reject("variadic calling convention is unsupported")
        result = self.ty(result_type) if a.GetTypeKind(result_type) == 0 else self.value_type(result_type)
        if intrinsic == self.NOALIAS_INTRINSIC:
            if count != 1 or a.GetTypeKind(params[0]) != 14 or a.GetTypeKind(result_type) != 0:
                self.reject("llvm.experimental.noalias.scope.decl requires exact void(metadata) signature")
            metadata_type = params[0]
            if metadata_type not in self.type_ids:
                self.type_ids[metadata_type] = len(self.types)
                self.types.append({"kind": "metadata"})
            param_types = [self.type_ids[metadata_type]]
        else:
            param_types = [self.value_type(param) for param in params]
        signature = {"params": param_types, "result": result, "abi": abi, "variadic": variadic,
                     "param_attributes": [[] for _ in params], "result_attributes": []}
        if owner:
            if convention == 8 or any(a.GetTypeKind(ty) in {10, 11} for ty in [result_type, *params]):
                site = "callsite" if call else "function"
                self.refinements.add(f"{self.symbol}: {site} exact calling convention {convention} retained as {abi}; original aggregate parameter/result types, parameter order and explicit ABI attributes retained; native target/profile ABI classification required; no signature flattening, callee inheritance or convention substitution")
            storage = self.return_storage(owner, call, params, result_type, intrinsic)
            if storage is not None:
                signature["return_storage"] = storage
            self.attrs(owner, 0xffffffff, call, intrinsic)
            signature["result_attributes"] = self.attrs(owner, 0, call, intrinsic, result_type)
            signature["param_attributes"] = [self.attrs(owner, i + 1, call, intrinsic, param)
                                             for i, param in enumerate(params)]
            if metadata_personality:
                if (signature["param_attributes"] or signature["result_attributes"]
                        or signature.get("return_storage") is not None):
                    self.reject("metadata-only personality declaration requires no ABI extension attributes")
                self.refinements.add(f"{self.symbol}: retained metadata-only personality declaration i32(...) with exact C convention and no ABI extension attributes; original declaration, personality references and dependency identity retained; explicit included five-argument C unwinder callback adaptation required; no ordinary variadic call admission")
        return signature

    def minmax_identity(self, value, name):
        a = self.a
        if (not a.IsAFunction(value) or name not in self.MINMAX_INTRINSICS
                or a.GetIntrinsicID(value) != self.MINMAX_INTRINSICS[name]):
            self.reject(f"intrinsic {name} requires its exact actual pinned integer-min/max intrinsic ID")
        if (a.GetLinkage(value) != 0 or a.GetPointerAddressSpace(a.TypeOf(value)) != 0
                or a.GetFirstBasicBlock(value)):
            self.reject(f"intrinsic {name} requires an external AS0 owned intrinsic declaration")

    def intrinsic_signature(self, name, signature):
        pointer = {"kind": "pointer", "address_space": 0}
        integer = lambda bits: {"kind": "int", "bits": bits}
        if name == self.NOALIAS_INTRINSIC:
            if (self.types[signature["result"]] != {"kind": "void"}
                    or [self.types[ty] for ty in signature["params"]] != [{"kind": "metadata"}]
                    or signature["result_attributes"] or any(signature["param_attributes"])
                    or signature.get("return_storage") is not None):
                self.reject("llvm.experimental.noalias.scope.decl requires exact void(metadata) signature without ABI extension attributes")
            return
        if name == "llvm.threadlocal.address.p0":
            if self.tls_profile is None:
                self.reject("thread-local intrinsic requires explicit TLS profile")
            if (self.types[signature["result"]] != pointer
                    or [self.types[ty] for ty in signature["params"]] != [pointer]
                    or signature["result_attributes"] or any(signature["param_attributes"])
                    or signature.get("return_storage") is not None):
                self.reject("llvm.threadlocal.address.p0 requires exact ptrAS0(ptrAS0) signature without ABI extension attributes")
            return
        if name in self.RELATIVE_INTRINSICS:
            width = int(name.rsplit(".i", 1)[1])
            if (self.types[signature["result"]] != pointer
                    or [self.types[ty] for ty in signature["params"]] != [pointer, integer(width)]
                    or signature["result_attributes"] or any(signature["param_attributes"])
                    or signature.get("return_storage") is not None):
                self.reject(f"intrinsic {name} requires exact ptrAS0(ptrAS0,i{width}) signature without ABI extension attributes")
            return
        if name == "llvm.eh.typeid.for.p0":
            if (self.types[signature["result"]] != integer(32)
                    or [self.types[ty] for ty in signature["params"]] != [pointer]
                    or signature["result_attributes"] or any(signature["param_attributes"])
                    or signature.get("return_storage") is not None):
                self.reject("llvm.eh.typeid.for.p0 requires exact i32(ptrAS0) signature without ABI extension attributes")
            return
        if name in self.OVERFLOW_INTRINSICS:
            width = int(name.rsplit(".i", 1)[1])
            result = self.types[signature["result"]]
            if (result.get("kind") != "struct" or result["packed"]
                    or [self.types[ty] for ty in result["fields"]] != [integer(width), integer(1)]
                    or [self.types[ty] for ty in signature["params"]] != [integer(width), integer(width)]
                    or signature["result_attributes"] or any(signature["param_attributes"])):
                self.reject(f"intrinsic {name} requires its exact unpacked {{i{width}, i1}} result and two i{width} parameters without ABI extension attributes")
            return
        if name in self.MINMAX_INTRINSICS:
            width = int(name.rsplit(".i", 1)[1])
            if (self.types[signature["result"]] != integer(width)
                    or [self.types[ty] for ty in signature["params"]] != [integer(width), integer(width)]
                    or signature["abi"] != "c" or signature["variadic"]
                    or signature["result_attributes"] or any(signature["param_attributes"])
                    or signature.get("return_storage") is not None):
                self.reject(f"intrinsic {name} requires exact i{width}(i{width},i{width}) C signature without ABI extension attributes")
            self.refinements.add("integer-min/max intrinsic identity, canonical overload name, signatures and attributes validated after pinned LLVM parsing and intrinsic normalization; input_sha256 binds original spelling and bytes; raw callsite attributes are checked independently without declaration inheritance")
            return
        if name == "llvm.assume":
            expected = [integer(1)]
        elif name == "llvm.trap":
            expected = []
        elif name in self.LIFETIME_INTRINSICS:
            expected = [pointer]
        elif name in self.MEMORY_INTRINSICS:
            width = int(name.rsplit(".i", 1)[1])
            expected = [pointer, integer(8) if name.startswith("llvm.memset.") else pointer,
                        integer(width), integer(1)]
        else:
            self.reject(f"intrinsic {name} requires explicit lowering")
        if (self.types[signature["result"]] != {"kind": "void"}
                or [self.types[ty] for ty in signature["params"]] != expected
                or signature["result_attributes"] or any(signature["param_attributes"])):
            self.reject(f"intrinsic {name} requires its exact void signature without ABI extension attributes")

    def memory_alignment(self, value, index):
        a = self.a
        count = a.GetCallSiteAttributeCount(value, index)
        attributes = (P * count)()
        a.GetCallSiteAttributes(value, index, attributes)
        for attribute in attributes:
            if (a.IsEnumAttribute(attribute)
                    and self.attribute_names.get(a.GetEnumAttributeKind(attribute)) == "align"):
                return a.GetEnumAttributeValue(attribute)
        return 1

    def noalias_tuple(self, metadata):
        """Validate the real metadata subclass before assertion-based getters."""
        a = self.a
        if not metadata or a.GetMetadataKind(metadata) != 4:  # LLVMMDTupleMetadataKind
            self.reject("scoped alias metadata requires an actual MDTuple")
        value = a.MetadataAsValue(self.context, metadata)
        if not value or a.ValueAsMetadata(value) != metadata:
            self.reject("scoped alias MDTuple must preserve parsed metadata identity")
        count = a.GetMDNodeNumOperands(value)
        operands = (P * count)()
        a.GetMDNodeOperands(value, operands)
        return value, [a.ValueAsMetadata(item) if item else None for item in operands]

    def noalias_bytes(self, metadata):
        a = self.a
        if not metadata or a.GetMetadataKind(metadata) != 0:  # LLVMMDStringMetadataKind
            self.reject("scoped alias identity and description require raw MDString bytes")
        value = a.MetadataAsValue(self.context, metadata)
        if not value or a.ValueAsMetadata(value) != metadata:
            self.reject("scoped alias MDString must preserve parsed metadata identity")
        length = U()
        data = a.GetMDString(value, C.byref(length))
        if not data and length.value:
            self.reject("scoped alias MDString has no byte storage")
        return list(C.string_at(data, length.value)) if length.value else []

    def noalias_register(self, metadata, role):
        if metadata in self.noalias_nodes:
            node = self.noalias_nodes[metadata]
            if node["role"] != role:
                self.reject("scoped alias metadata node has incompatible graph roles")
            return node, None
        value, operands = self.noalias_tuple(metadata)
        message = self.a.PrintValueToString(value)
        if not message:
            self.reject("scoped alias MDTuple storage requires trusted LLVM printer evidence")
        try:
            raw = C.string_at(message)
        finally:
            self.a.DisposeMessage(message)
        prefix, separator, body = raw.partition(b" = ")
        numbered = prefix.startswith(b"!") and prefix[1:].isdigit()
        pointer = (prefix.startswith(b"<0x") and prefix.endswith(b">")
                   and bool(prefix[3:-1])
                   and all(byte in b"0123456789abcdefABCDEF" for byte in prefix[3:-1]))
        if not separator or not (numbered or pointer):
            self.reject("scoped alias MDTuple printer requires an anchored node body")
        if body.startswith(b"<temporary!> "):
            self.reject("temporary scoped alias metadata is unsupported")
        if body.startswith(b"distinct !{"):
            storage = "distinct"
        elif body.startswith(b"!{"):
            storage = "uniqued"
        else:
            self.reject("scoped alias MDTuple printer has unsupported storage syntax")
        node = {"id": len(self.noalias_nodes), "storage": storage, "role": role}
        # Register before following operands: permitted self cycles are identity.
        self.noalias_nodes[metadata] = node
        self.noalias_node_sources.append({"id": node["id"], "metadata_kind": 4,
                                         "printer_bytes": list(raw),
                                         "printer_sha256": hashlib.sha256(raw).hexdigest()})
        return node, operands

    def noalias_identity(self, metadata, identity):
        return ({"kind": "self_reference"} if identity == metadata else
                {"kind": "bytes", "bytes": self.noalias_bytes(identity)})

    def noalias_domain(self, metadata):
        node, operands = self.noalias_register(metadata, "domain")
        if operands is not None:
            if len(operands) not in {1, 2}:
                self.reject("scoped alias domain requires one or two operands")
            record = {"id": node["id"], "storage": node["storage"],
                      "identity": self.noalias_identity(metadata, operands[0]),
                      "description": self.noalias_bytes(operands[1]) if len(operands) == 2 else None}
            self.noalias_metadata["domains"].append(record)
        return node["id"]

    def noalias_scope(self, metadata):
        node, operands = self.noalias_register(metadata, "scope")
        if operands is not None:
            if len(operands) not in {2, 3}:
                self.reject("scoped alias scope requires two or three operands")
            record = {"id": node["id"], "storage": node["storage"],
                      "identity": self.noalias_identity(metadata, operands[0]),
                      "domain": self.noalias_domain(operands[1]),
                      "description": self.noalias_bytes(operands[2]) if len(operands) == 3 else None}
            self.noalias_metadata["scopes"].append(record)
        return node["id"]

    def noalias_list(self, metadata, declaration=False):
        node, operands = self.noalias_register(metadata, "list")
        if operands is not None:
            node["record"] = {"id": node["id"], "storage": node["storage"],
                              "scopes": [self.noalias_scope(item) for item in operands]}
            self.noalias_metadata["lists"].append(node["record"])
        record = node["record"]
        if declaration and len(record["scopes"]) != 1:
            self.reject("noalias scope declaration requires a list containing exactly one scope")
        return node["id"]

    def metadata(self, value, global_value=False):
        a, count = self.a, S()
        entries = (a.GlobalCopyAllMetadata if global_value else a.InstructionGetAllMetadataOtherThanDebugLoc)(value, C.byref(count))
        alias_roots = {}
        try:
            for i in range(count.value):
                kind = a.ValueMetadataEntriesGetKind(entries, i)
                if kind == self.noundef_metadata_kind:
                    if global_value or a.GetInstructionOpcode(value) != 27:
                        self.reject("noundef metadata requires a LoadInst owner")
                    metadata = a.ValueMetadataEntriesGetMetadata(entries, i)
                    node = a.MetadataAsValue(self.context, metadata) if metadata else None
                    if (not node or a.ValueAsMetadata(node) != metadata
                            or not a.IsAMDNode(node) or a.GetMDNodeNumOperands(node) != 0):
                        self.reject("noundef load metadata requires an empty MDNode")
                    block = self.block_ids[a.GetInstructionParent(value)]
                    self.refinements.add(f"{self.symbol}: block {block} load value {self.values[value]}: erased empty !noundef load promise; original load, volatile flag, alignment and type retained; atomic and other memory contracts remain independently validated; no native optimization, purity, runtime guard, trap, ABI, provider or MemorySanitizer support inferred")
                    self.refinements.add("noundef metadata validated by exact parsed context name and empty MDNode on LoadInst only; input_sha256 binds the original bytes")
                    continue
                name = self.metadata_names.get(kind)
                if name is None:
                    self.reject(f"unsupported metadata kind {kind}")
                if name in {"alias.scope", "noalias"}:
                    if global_value or value not in self.source_sites:
                        self.reject("scoped alias access metadata requires an original instruction site")
                    metadata = a.ValueMetadataEntriesGetMetadata(entries, i)
                    alias_roots["alias_scope" if name == "alias.scope" else "noalias"] = metadata
                    self.refinements.add(f"{self.symbol}: retained original scoped alias access graph and source/native instruction range; all original memory operations retained; no alias-based optimization, purity or runtime effect inferred")
                else:
                    self.refinements.add(f"erased non-codegen metadata {name}")
            if alias_roots:
                attachment = {"site": self.source_sites[value], "alias_scope": None, "noalias": None}
                # A fixed name order avoids depending on context metadata IDs.
                for key in ("alias_scope", "noalias"):
                    if key in alias_roots:
                        attachment[key] = self.noalias_list(alias_roots[key])
                self.noalias_metadata["attachments"].append(attachment)
        finally:
            if entries:
                a.DisposeValueMetadataEntries(entries)

    def bind_comdats(self, audit):
        """Bind every referenced serialized group to live GlobalObject handles."""
        a = self.a
        inventories = [
            (list(a.sequence(a.GetFirstGlobal, a.GetNextGlobal, self.module)),
             audit["global_comdat_ids"]),
            (list(a.sequence(a.GetFirstFunction, a.GetNextFunction, self.module)),
             audit["function_comdat_ids"]),
        ]
        contracts = audit["comdat_contracts"]
        if len(contracts) != audit["comdat_count"] or any(
                len(symbols) != len(ids) for symbols, ids in inventories):
            raise ImportFailure("LLVM bitcode COMDAT audit and C API inventories disagree", "bitcode-audit")
        # GetComdat is valid on these GlobalObjects, never on an alias. Collect
        # existing referenced handles before the name lookup, so a mismatched
        # decoder name cannot fabricate an accepted group through insertion.
        actual = {value: a.GetComdat(value) for symbols, _ in inventories for value in symbols}
        referenced = {handle for handle in actual.values() if handle}
        if len(referenced) != len(contracts):
            raise ImportFailure("LLVM bitcode COMDAT audit and C API referenced groups disagree", "bitcode-audit")
        handles = [None]
        selections = {1: (0, "any"), 4: (3, "no_deduplicate")}
        for record in contracts:
            if record["selection_encoding"] not in selections:
                raise ImportFailure("unsupported ELF COMDAT selection in verified bitcode audit", "bitcode-audit")
            expected_kind, selection = selections[record["selection_encoding"]]
            # The fresh verified writer supplies an already-existing exact
            # name. LLVM-C has no read-only group-name getter; on success this
            # lookup does not insert. A mismatch discards the whole module.
            handle = a.GetOrInsertComdat(self.module, record["name"].encode("utf-8"))
            if (handle not in referenced or handle in self.comdat_handles
                    or a.GetComdatSelectionKind(handle) != expected_kind):
                raise ImportFailure("LLVM bitcode names/selections and C API COMDAT handles disagree", "bitcode-audit")
            self.comdat_handles[handle] = record["name"]
            handles.append(handle)
            self.comdats.append({"name": record["name"], "selection": selection})
        used = set()
        for symbols, ids in inventories:
            for value, ident in zip(symbols, ids):
                if not 0 <= ident < len(handles) or actual[value] != handles[ident]:
                    raise ImportFailure("LLVM bitcode IDs and C API COMDAT memberships disagree", "bitcode-audit")
                self.symbol_comdats[value] = self.comdat_handles.get(handles[ident]) if ident else None
                if ident:
                    used.add(ident)
        if used != set(range(1, len(handles))):
            raise ImportFailure("verified bitcode COMDAT inventory contains an unreferenced group", "bitcode-audit")
        self.refinements.add("COMDAT inventory includes every group referenced by verified normalized LLVM globals/functions; unused nonexecutable declarations omitted by LLVM serialization are bound only by original input_sha256, not counted as executable groups")

    def global_contract(self, value):
        a = self.a
        if value not in self.symbol_alignments:
            self.reject("symbol alignment requires the verified LLVM bitcode alignment audit")
        alignment = self.symbol_alignments[value]
        if a.GetAlignment(value) != alignment & 0xffffffff:
            self.reject("LLVM C API and verified bitcode symbol alignments disagree")
        if alignment == 1 << 32:
            self.refinements.add(f"{self.symbol}: full byte alignment 4294967296 retained from verified LLVM bitcode; the uint32 C API accessor truncates this alignment to zero")
        visibility = self.VISIBILITY.get(a.GetVisibility(value))
        if visibility is None:
            self.reject("unsupported symbol visibility")
        if a.GetDLLStorageClass(value) or a.GetSection(value):
            self.reject("unsupported DLL storage or explicit section")
        if value not in self.symbol_comdats:
            self.reject("symbol COMDAT membership requires the verified LLVM bitcode contract audit")
        comdat = self.symbol_comdats[value]
        actual_comdat = a.GetComdat(value)
        if (self.comdat_handles.get(actual_comdat) if actual_comdat else None) != comdat:
            self.reject("LLVM C API and verified bitcode COMDAT memberships disagree")
        source_linkage = a.GetLinkage(value)
        linkage = self.LINKAGES.get(source_linkage)
        if linkage is None:
            self.reject(f"unsupported linkage {source_linkage}")
        if linkage in self.MERGEABLE_DEFINITIONS:
            definition = (a.GetFirstBasicBlock(value) if a.IsAFunction(value)
                          else a.GetInitializer(value))
            if not definition:
                self.reject(f"{linkage} linkage requires a definition; mergeable declarations require separate resolution")
        if linkage == "weak":
            self.refinements.add(f"{self.symbol}: preserved ordinary weak definition (LLVMWeakAnyLinkage=5); native STB_WEAK binding and qualified closure/link selection required; no ODR or COMDAT contract inferred")
        elif linkage in self.MERGEABLE_DEFINITIONS:
            self.refinements.add(f"{self.symbol}: preserved exact LLVM {linkage} definition linkage; no collapse to ordinary weak or inferred COMDAT membership; native binding, qualified closure and whole-group selection remain explicit")
        if comdat is not None:
            self.refinements.add(f"{self.symbol}: preserved exact referenced COMDAT membership {comdat}; complete function/global/alias dependencies require atomic native group realization and selection, not independent weak-symbol substitution")
        self.scalar(a.TypeOf(value))  # Checks the global/function address space.
        if a.GetUnnamedAddress(value):
            self.refinements.add(f"{self.symbol}: unnamed-address identity optimization assumption erased")
        if visibility != "default":
            elf_code = 2 if visibility == "hidden" else 3
            self.refinements.add(f"{self.symbol}: preserved {visibility} symbol visibility as ELF st_other={elf_code}; required own-emitter visibility directives on definitions and declarations within the static, non-preemptive native linkage profile; nondefault external symbols must resolve within the included native image")
        self.metadata(value, global_value=True)
        return linkage, visibility, alignment, comdat

    def instruction_alignment(self, value):
        # Alloca/Load/Store carry a nonzero llvm::Align, unlike the optional
        # alignment on globals/functions. Their only legal zero uint32 result
        # is the maximum 2^32-byte alignment, which must not become a default.
        alignment = self.a.GetAlignment(value)
        if not alignment:
            self.refinements.add(f"{self.symbol}: mandatory instruction alignment 4294967296 retained despite uint32 LLVMGetAlignment truncation; no default alignment substitution")
            return 1 << 32
        return alignment

    def bind_atomic_sync_scopes(self, audit):
        names = audit.get("sync_scope_names")
        if names is None:
            return
        if (not isinstance(names, list) or not 2 <= len(names) <= 256
                or any(not isinstance(name, bytes) for name in names)
                or names[:2] != [b"singlethread", b""] or len(set(names)) != len(names)):
            raise ImportFailure("verified LLVM bitcode synchronization scope table is invalid", "bitcode-audit")
        self.atomic_sync_scope_names = tuple(names)

    def atomic_operation(self, value, opcode):
        a = self.a
        classes = {27: (a.IsALoadInst, 1), 28: (a.IsAStoreInst, 2),
                   55: (a.IsAFenceInst, 0), 56: (a.IsAAtomicCmpXchgInst, 3),
                   57: (a.IsAAtomicRMWInst, 2)}
        guard, count = classes[opcode]
        if not guard(value) or a.GetNumOperands(value) != count or not a.IsAtomic(value):
            self.reject("atomic instruction subclass or operand inventory is invalid")
        scope = a.GetAtomicSyncScopeID(value)
        names = self.atomic_sync_scope_names
        if names is None or scope >= len(names) or scope > 255:
            raise ImportFailure("atomic synchronization scope ID requires its exact verified LLVM bitcode name", "bitcode-audit", self.symbol)
        self.atomic_sync_scope_ids.update((0, 1, scope))

        def ordering(raw, allowed):
            if raw not in allowed or raw not in self.ATOMIC_ORDERINGS:
                self.reject(f"unsupported atomic ordering enum {raw} for opcode {opcode}")
            return self.ATOMIC_ORDERINGS[raw]

        operation = {"op": {27: "atomic_load", 28: "atomic_store", 55: "atomic_fence",
                            56: "atomic_compare_exchange", 57: "atomic_rmw"}[opcode],
                     "sync_scope": scope}
        detail = []
        if opcode == 56:
            # The generic LLVMGetOrdering casts its final receiver to RMW,
            # so compare-exchange requires these two dedicated typed getters.
            success, failure = a.GetCmpXchgSuccessOrdering(value), a.GetCmpXchgFailureOrdering(value)
            operation["success_ordering"] = ordering(success, {2, 4, 5, 6, 7})
            operation["failure_ordering"] = ordering(failure, {2, 4, 7})
            operation["weak"] = bool(a.GetWeak(value))
            detail += [f"success_ordering={success}:{operation['success_ordering']}",
                       f"failure_ordering={failure}:{operation['failure_ordering']}",
                       f"weak={str(operation['weak']).lower()}"]
            # LLVM22 permits every pair from these sets, including failure
            # ordering stronger than success. Do not import a legacy .oc ban.
        else:
            raw = a.GetOrdering(value)
            allowed = {27: {1, 2, 4, 7}, 28: {1, 2, 5, 7},
                       55: {4, 5, 6, 7}, 57: {2, 4, 5, 6, 7}}[opcode]
            operation["ordering"] = ordering(raw, allowed)
            detail.append(f"ordering={raw}:{operation['ordering']}")
        if opcode != 55:
            pointer = a.GetOperand(value, 1 if opcode == 28 else 0)
            if a.GetTypeKind(a.TypeOf(pointer)) != 12:
                self.reject("atomic address operand must be a scalar pointer")
            operation["pointer"] = self.operand(pointer)
            value_type = a.TypeOf(value) if opcode == 27 else a.TypeOf(a.GetOperand(value, 0 if opcode == 28 else 1))
            ty = self.scalar(value_type)
            if self.types[ty]["kind"] == "int" and self.types[ty]["bits"] not in {8, 16, 32, 64}:
                self.reject(f"unsupported atomic integer width i{self.types[ty]['bits']}")
            operation["alignment"] = self.instruction_alignment(value)
            operation["volatile"] = bool(a.GetVolatile(value))
            detail += [f"alignment={operation['alignment']}", f"volatile={str(operation['volatile']).lower()}"]
            if opcode == 28:
                operation["value"] = self.operand(a.GetOperand(value, 0))
            elif opcode == 57:
                raw = a.GetAtomicRMWBinOp(value)
                if raw not in self.ATOMIC_RMW_OPS:
                    self.reject(f"unsupported public LLVMAtomicRMWBinOp enum {raw}")
                operation["kind"] = self.ATOMIC_RMW_OPS[raw]
                if self.types[ty]["kind"] == "pointer" and raw != 0:
                    self.reject("atomic RMW pointer values require xchg")
                operation["value"] = self.operand(a.GetOperand(value, 1))
                detail.append(f"RMW_operation={raw}:{operation['kind']}")
            elif opcode == 56:
                if a.TypeOf(a.GetOperand(value, 2)) != value_type:
                    self.reject("compare-exchange expected and replacement types must match")
                result_type = a.TypeOf(value)
                if (a.GetTypeKind(result_type) != 10 or a.IsPackedStruct(result_type)
                        or a.CountStructElementTypes(result_type) != 2):
                    self.reject("compare-exchange requires original unpacked {T,i1} result")
                fields = (P * 2)()
                a.GetStructElementTypes(result_type, fields)
                if fields[0] != value_type or a.GetTypeKind(fields[1]) != 8 or a.GetIntTypeWidth(fields[1]) != 1:
                    self.reject("compare-exchange requires original unpacked {T,i1} result")
                operation["expected"] = self.operand(a.GetOperand(value, 1))
                operation["replacement"] = self.operand(a.GetOperand(value, 2))
        site = self.source_sites[value]
        detail += [f"sync_scope={scope}", f"name_bytes={names[scope].hex()}"]
        self.refinements.add(f"{self.symbol}: retained {operation['op']} at block {site['block']} source instruction {site['source_instruction']}: "
                             + ", ".join(detail) + "; original atomic event and operands retained; no ordinary-memory substitution, alias optimization or provider/realization admission inferred")
        return operation

    def alias(self, value, definitions):
        """Retain an independent symbol for a direct same-module definition."""
        a = self.a
        self.symbol = a.name(value)
        if not self.symbol or self.symbol.startswith("llvm."):
            self.reject("unnamed/special alias is unsupported")
        audit = self.alias_contracts.get(value)
        if audit is None:
            self.reject("alias requires the verified LLVM bitcode contract audit")
        # These are GlobalValue getters. GlobalObject metadata/COMDAT and
        # alignment getters, and GlobalVariable TLS getters, cannot read aliases.
        source_linkage = a.GetLinkage(value)
        encoded_linkage = self.BITCODE_LINKAGES.get(source_linkage)
        linkage = self.LINKAGES.get(source_linkage)
        if linkage is None:
            self.reject(f"unsupported alias linkage {source_linkage}")
        source_visibility = a.GetVisibility(value)
        visibility = self.VISIBILITY.get(source_visibility)
        if visibility is None or (linkage in {"internal", "private"} and visibility != "default"):
            self.reject("unsupported alias visibility")
        unnamed = {0: 0, 1: 2, 2: 1}.get(a.GetUnnamedAddress(value))
        if (audit["linkage_encoding"] != encoded_linkage
                or audit["visibility"] != source_visibility
                or audit["dll_storage_class"] != a.GetDLLStorageClass(value)
                or audit["unnamed_address"] != unnamed):
            self.reject("LLVM C API and verified bitcode alias contracts disagree")
        if (audit["address_space"] != 0 or audit["dll_storage_class"]
                or audit["thread_local_mode"] or audit["partition_length"]):
            self.reject("alias address spaces, DLL storage, TLS and partitions require explicit lowering")
        self.scalar(a.TypeOf(value))
        target = a.AliasGetAliasee(value)
        if not target or not (a.IsAFunction(target) or a.IsAGlobalVariable(target)):
            self.reject("alias requires a direct zero-offset function/global definition; chains and expressions require explicit lowering")
        if target not in definitions:
            self.reject("alias target requires a definition in the same module")
        if a.IsAFunction(target) and a.GetIntrinsicID(target):
            self.reject("owned intrinsic cannot be an alias target")
        if a.IsAGlobalVariable(target) and a.IsThreadLocal(target):
            self.reject("TLS aliases require explicit thread-local alias lowering")
        if a.GlobalGetValueType(value) != a.GlobalGetValueType(target):
            self.reject("alias and target require the exact same value type, not merely the same opaque pointer type")
        self.scalar(a.TypeOf(target))
        if unnamed:
            self.refinements.add(f"{self.symbol}: alias unnamed-address identity optimization assumption erased")
        self.refinements.add(f"{self.symbol}: retained direct zero-offset alias to same-module definition {a.name(target)}; calls, addresses and relocations keep the alias name and independent binding/visibility; no body or storage copied and no selected global-name provider substituted")
        self.refinements.add("alias contracts validated after pinned LLVM parsing and attribute normalization; input_sha256 binds the original bytes")
        return {"name": self.symbol, "ty": self.ty(a.GlobalGetValueType(value)),
                "aliasee": a.name(target), "linkage": linkage, "visibility": visibility}

    def operand(self, value):
        a = self.a
        llvm_type = a.TypeOf(value)
        ty = self.value_type(llvm_type)
        if value in self.values:
            return {"kind": "value", "id": self.values[value]}
        if a.IsAPoisonValue(value):
            return {"kind": "poison", "ty": ty}
        if a.IsAUndefValue(value):
            return {"kind": "undef", "ty": ty}
        if self.types[ty]["kind"] in {"struct", "array"}:
            if a.IsAConstantAggregateZero(value):
                return {"kind": "aggregate_zero", "ty": ty}
            if not a.IsAConstant(value):
                self.reject("aggregate literal requires a constant; SSA construction uses insertvalue")
            if a.GetTypeKind(llvm_type) == 10:
                fields = (P * a.CountStructElementTypes(llvm_type))()
                a.GetStructElementTypes(llvm_type, fields)
                children = enumerate(fields)
            else:
                element_type = a.GetElementType(llvm_type)
                children = ((index, element_type) for index in range(a.GetArrayLength2(llvm_type)))
            elements = []
            for index, child_type in children:
                # This is the actual public C API index domain, not a graph
                # size policy. Compact zero/poison/undef never enumerate it.
                if index > 0xffffffff:
                    self.reject("constant aggregate element index exceeds the LLVM C API unsigned range")
                child = a.GetAggregateElement(value, index)
                if (not child or not a.IsAConstant(child)
                        or a.TypeOf(child) != child_type):
                    self.reject("aggregate constant requires exact typed constant fields/elements")
                elements.append(self.operand(child))
            return {"kind": "aggregate", "ty": ty, "elements": elements}
        if a.IsAConstantInt(value):
            return {"kind": "int", "ty": ty, "bits": str(a.ConstIntGetZExtValue(value))}
        if a.IsAConstantPointerNull(value):
            return {"kind": "null", "ty": ty}
        if a.IsAConstantExpr(value) and a.GetConstOpcode(value) == 40:
            return {"kind": "pointer_bits", "ty": ty, "bits": str(self.pointer_literal_bits(value))}
        if a.IsAConstantExpr(value) and a.GetConstOpcode(value) in {29, 41}:
            name, offset = self.symbol_constant(value)
            # AS0's admitted pointer and GEP index widths are both 64 bits.
            # Keep a tracked symbol even when constant address arithmetic wraps.
            addend = (offset + (1 << 63)) % (1 << 64) - (1 << 63)
            self.refinements.add(f"{self.symbol}: constant symbolic AS0 address retains original root {name} and signed i64 byte addend {addend} modulo 2^64; no provider substitution, dereference or new runtime memory access")
            if addend == 0:
                return {"kind": "symbol", "ty": ty, "name": name}
            return {"kind": "symbol_offset", "ty": ty, "name": name, "addend": addend}
        if a.IsAFunction(value) or a.IsAGlobalVariable(value) or a.IsAGlobalAlias(value):
            if a.IsAFunction(value) and a.GetIntrinsicID(value):
                self.reject("intrinsic address cannot cross as an ordinary native symbol")
            if a.IsAGlobalVariable(value) and a.IsThreadLocal(value):
                self.reject("TLS address cannot cross as an ordinary native symbol")
            return {"kind": "symbol", "ty": ty, "name": a.name(value)}
        self.reject("unsupported constant expression or non-scalar operand")

    def integer_type(self, bits=64):
        for index, ty in enumerate(self.types):
            if ty == {"kind": "int", "bits": bits}:
                return index
        self.types.append({"kind": "int", "bits": bits})
        return len(self.types) - 1

    def literal(self, value, bits=64):
        return {"kind": "int", "ty": self.integer_type(bits), "bits": str(value % (1 << bits))}

    def synthetic(self, operation, ty, instructions):
        ident = self.next_id
        self.next_id += 1
        instructions.append({"result": {"id": ident, "ty": ty}, "operation": operation})
        return {"kind": "value", "id": ident}

    def gep_offset(self, value, instructions=None):
        a, total, current = self.a, 0, self.a.GetGEPSourceElementType(value)
        self.ty(current)
        dynamic = []
        for i in range(1, a.GetNumOperands(value)):
            index = a.GetOperand(value, i)
            self.scalar(a.TypeOf(index))
            width = a.GetIntTypeWidth(a.TypeOf(index))
            if i > 1 and a.GetTypeKind(current) == 10:
                if not a.IsAConstantInt(index):
                    self.reject("nonconstant struct GEP index")
                field = a.ConstIntGetZExtValue(index)
                fields = (P * a.CountStructElementTypes(current))()
                a.GetStructElementTypes(current, fields)
                total += a.OffsetOfElement(self.layout, current, field)
                current = fields[field]
                continue
            if i > 1:
                if a.GetTypeKind(current) != 11:
                    self.reject("unsupported GEP indexing type")
                current = a.GetElementType(current)
            stride = a.ABISizeOfType(self.layout, current)
            if a.IsAConstantInt(index):
                bits = a.ConstIntGetZExtValue(index)
                signed = bits - (1 << width) if bits & (1 << (width - 1)) else bits
                total += signed * stride
            elif instructions is None:
                self.reject("nonconstant initializer GEP offset")
            else:
                operand = self.operand(index)
                if width < 64:
                    operand = self.synthetic({"op": "cast", "kind": "s_ext", "value": operand}, self.integer_type(), instructions)
                if stride != 1:
                    operand = self.synthetic({"op": "binary", "kind": "mul", "lhs": operand, "rhs": self.literal(stride), "flags": []}, self.integer_type(), instructions)
                dynamic.append(operand)
        if instructions is None:
            return total
        offset = self.literal(total)
        for term in dynamic:
            offset = self.synthetic({"op": "binary", "kind": "add", "lhs": offset, "rhs": term, "flags": []}, self.integer_type(), instructions)
        if a.GEPGetNoWrapFlags(value):
            self.refinements.add("GEP no-wrap/inbounds poison is refined without using it as an optimization assumption")
        return offset

    def symbol_constant(self, value):
        a = self.a
        if a.GetTypeKind(a.TypeOf(value)) != 12:
            self.reject("symbolic address requires a scalar pointer")
        self.scalar(a.TypeOf(value))
        if a.IsAGlobalVariable(value) or a.IsAFunction(value) or a.IsAGlobalAlias(value):
            if a.IsAFunction(value) and a.GetIntrinsicID(value):
                self.reject("intrinsic address cannot be a native relocation")
            if a.IsAGlobalVariable(value) and a.IsThreadLocal(value):
                self.reject("TLS address cannot be a static initializer relocation or ordinary symbolic address")
            return a.name(value), 0
        if a.IsAConstantExpr(value):
            opcode = a.GetConstOpcode(value)
            if opcode == 29:
                self.refinements.add(f"{self.symbol}: constant GEP inrange/no-wrap restrictions erased; exact DataLayout address retained")
                name, offset = self.symbol_constant(a.GetOperand(value, 0))
                return name, offset + self.gep_offset(value)
            if opcode == 41:
                if a.GetTypeKind(a.TypeOf(a.GetOperand(value, 0))) != 12:
                    self.reject("symbolic bitcast requires a pointer-to-pointer cast")
                return self.symbol_constant(a.GetOperand(value, 0))
        self.reject("unsupported symbolic initializer (only symbol, pointer bitcast and constant GEP are supported)")

    def pointer_literal_bits(self, value):
        """Fold only an immediate integral AS0 inttoptr constant, exactly."""
        a = self.a
        integer = a.GetOperand(value, 0)
        integer_type = a.TypeOf(integer)
        if not a.IsAConstantInt(integer) or a.GetTypeKind(integer_type) != 8:
            self.reject("constant inttoptr requires an integer literal; symbolic integer expressions need explicit relocation lowering")
        width = a.GetIntTypeWidth(integer_type)
        if not 1 <= width <= 64:
            self.reject(f"unsupported constant inttoptr source integer width i{width}")
        # This compile-time source width is folded into exact pointer bits; it
        # is not an executable integer type or a new native arithmetic promise.
        self.refinements.add(f"{self.symbol}: constant integer-to-pointer source i{width} retains exact zero-extended integral AS0 address bits; no symbol relocation or dereference is introduced")
        return a.ConstIntGetZExtValue(integer)

    def relative_initializer(self, value, offset):
        """Recognize the exact parsed i32 trunc(i64(target - base)) form."""
        a = self.a
        diagnostic = "relative initializer requires exact i32 trunc(i64 sub(ptrtoint AS0 target,ptrtoint AS0 containing base))"
        if (a.GetTypeKind(a.TypeOf(value)) != 8 or a.GetIntTypeWidth(a.TypeOf(value)) != 32
                or not a.IsAConstantExpr(value) or a.GetConstOpcode(value) != 30
                or a.GetNumOperands(value) != 1):
            self.reject(diagnostic)
        difference = a.GetOperand(value, 0)
        if (a.GetTypeKind(a.TypeOf(difference)) != 8 or a.GetIntTypeWidth(a.TypeOf(difference)) != 64
                or not a.IsAConstantExpr(difference) or a.GetConstOpcode(difference) != 10
                or a.GetNumOperands(difference) != 2):
            self.reject(diagnostic)
        roots = []
        for index in range(2):
            integer = a.GetOperand(difference, index)
            if (a.GetTypeKind(a.TypeOf(integer)) != 8 or a.GetIntTypeWidth(a.TypeOf(integer)) != 64
                    or not a.IsAConstantExpr(integer) or a.GetConstOpcode(integer) != 39
                    or a.GetNumOperands(integer) != 1):
                self.reject(diagnostic)
            roots.append(self.symbol_constant(a.GetOperand(integer, 0)))
        (target, target_offset), (base, base_offset) = roots
        containing = self.symbol_values.get(self.symbol)
        if (base != self.symbol or not containing or not a.IsAGlobalVariable(containing)
                or a.GetLinkage(containing) not in {8, 9}
                or not a.GetInitializer(containing) or a.IsThreadLocal(containing)):
            self.reject("relative initializer base must be its containing initialized private/internal nonTLS global")
        root = self.symbol_values.get(target)
        if not root or not (a.IsAFunction(root) or a.IsAGlobalVariable(root) or a.IsAGlobalAlias(root)):
            self.reject("relative initializer target requires an ordinary named function/global/alias")
        if a.IsAGlobalVariable(root) and a.IsThreadLocal(root):
            self.reject("relative initializer target cannot be thread-local")
        # ptrtoint/sub are i64 modular operations; the stored difference is
        # truncated to i32. A signed i64 addend preserves those exact bits.
        addend = ((target_offset - base_offset + (1 << 63)) % (1 << 64)) - (1 << 63)
        self.refinements.add(f"{self.symbol}: relative i32 initializer at byte offset {offset} retains target {target}, containing base {base} and signed addend {addend}; constant GEP byte offsets use original DataLayout, i64 subtraction wraps and stored displacement truncates modulo 2^32; included native linking must realize the relocation; no link-span or medium-code-model guarantee inferred")
        return {"offset": offset, "width": 32, "symbol": target, "addend": addend, "relative_to": base}

    def initializer(self, value, llvm_type, data, relocations, offset=0):
        a, kind = self.a, self.a.GetTypeKind(llvm_type)
        ty = self.ty(llvm_type)
        if (a.IsAPoisonValue(value) or a.IsAUndefValue(value)) and self.contains_binary128(ty):
            self.reject("binary128 storage initializer cannot contain poison or undef")
        if a.IsAConstantAggregateZero(value) or a.IsAConstantPointerNull(value):
            return
        if a.IsAPoisonValue(value) or a.IsAUndefValue(value):
            self.refinements.add("global undef/poison initializer refined to zero bytes")
            return
        if kind == 5:
            # Constant::isNullValue tests exact positive zero, not a conversion
            # through host double (which could erase -0, NaNs or tiny values).
            if not a.IsNull(value):
                self.reject("binary128 storage initializer requires exact positive zero")
            return
        if kind == 8 and a.IsAConstantInt(value):
            size = a.StoreSizeOfType(self.layout, llvm_type)
            data[offset:offset + size] = a.ConstIntGetZExtValue(value).to_bytes(size, "little")
        elif kind == 8 and a.IsAConstantExpr(value):
            relocations.append(self.relative_initializer(value, offset))
        elif kind == 12:
            if a.IsAConstantExpr(value) and a.GetConstOpcode(value) == 40:
                # run() and ty() already require integral, little-endian,
                # 64-bit AS0 pointers. LLVM inttoptr zero-extends a narrower
                # integer; a signed spelling such as i8 -1 therefore denotes
                # address 255, not 64-bit -1. No native symbol is referenced.
                size = a.StoreSizeOfType(self.layout, llvm_type)
                data[offset:offset + size] = self.pointer_literal_bits(value).to_bytes(size, "little")
                return
            name, addend = self.symbol_constant(value)
            if not -(1 << 63) <= addend < (1 << 63):
                self.reject("relocation addend exceeds signed 64-bit range")
            relocations.append({"offset": offset, "width": 64, "symbol": name, "addend": addend})
        elif kind in {10, 11}:
            if kind == 10:
                fields = (P * a.CountStructElementTypes(llvm_type))()
                a.GetStructElementTypes(llvm_type, fields)
                for i, field in enumerate(fields):
                    element = a.GetAggregateElement(value, i)
                    if not element:
                        self.reject("unsupported aggregate initializer")
                    self.initializer(element, field, data, relocations, offset + a.OffsetOfElement(self.layout, llvm_type, i))
            else:
                element_type = a.GetElementType(llvm_type)
                stride = a.ABISizeOfType(self.layout, element_type)
                for i in range(a.GetArrayLength2(llvm_type)):
                    element = a.GetAggregateElement(value, i)
                    if not element:
                        self.reject("unsupported array initializer")
                    self.initializer(element, element_type, data, relocations, offset + i * stride)
        else:
            self.reject("unsupported initializer value")

    def exception_aggregate(self, llvm_type):
        ty = self.value_type(llvm_type)
        aggregate = self.types[ty]
        if (aggregate.get("kind") != "struct" or aggregate["packed"]
                or [self.types[field] for field in aggregate["fields"]]
                != [{"kind": "pointer", "address_space": 0}, {"kind": "int", "bits": 32}]):
            self.reject("landingpad requires original unpacked {ptrAS0,i32}")
        return ty

    def exception_pointer(self, value, *, personality=False, filter_entry=False):
        a = self.a
        diagnostic = ("exception personality requires a named zero-offset AS0 source function"
                      if personality else "exception typeinfo requires null or a named zero-offset AS0 pointer")
        if a.GetTypeKind(a.TypeOf(value)) != 12 or a.GetPointerAddressSpace(a.TypeOf(value)) != 0:
            self.reject(diagnostic)
        if a.IsAConstantPointerNull(value) and not personality and not filter_entry:
            return self.operand(value)
        if not (a.IsAFunction(value) or a.IsAGlobalVariable(value) or a.IsAGlobalAlias(value)
                or a.IsAConstantExpr(value) and a.GetConstOpcode(value) in {29, 41}):
            self.reject("nonempty filter entries require named zero-offset GlobalValues" if filter_entry else diagnostic)
        name, offset = self.symbol_constant(value)
        if offset % (1 << 64):
            self.reject(diagnostic)
        root = self.symbol_values.get(name)
        if root and a.IsAGlobalAlias(root):
            root = a.AliasGetAliasee(root)
        if not root or not (a.IsAFunction(root) or a.IsAGlobalVariable(root)):
            self.reject(diagnostic)
        if a.name(root) == "llvm.eh.catch.all.value":
            self.reject("llvm.eh.catch.all.value requires explicit initializer normalization")
        if a.IsAFunction(root) and (a.GetIntrinsicID(root) or a.name(root).startswith("llvm.")):
            self.reject("intrinsic cannot be exception personality or typeinfo")
        if personality and not a.IsAFunction(root):
            self.reject(diagnostic)
        if personality:
            signature = a.GlobalGetValueType(root)
            result = a.GetReturnType(signature)
            count = a.CountParamTypes(signature)
            params = (P * count)()
            a.GetParamTypes(signature, params)
            valid_result = a.GetTypeKind(result) == 8 and a.GetIntTypeWidth(result) == 32
            if a.IsFunctionVarArg(signature):
                valid = not a.GetFirstBasicBlock(root) and a.GetLinkage(root) == 0 and count == 0
            else:
                valid = (count == 5 and [a.GetTypeKind(param) for param in params] == [8, 8, 8, 12, 12]
                         and [a.GetIntTypeWidth(param) for param in params[:3]] == [32, 32, 64]
                         and all(a.GetPointerAddressSpace(param) == 0 for param in params[3:]))
            if not valid_result or a.GetFunctionCallConv(root) != 0 or not valid:
                self.reject("personality requires the exact five-argument C unwinder callback ABI or a metadata-only i32(...) declaration")
        return self.operand(value)

    def classify_metadata_personalities(self, functions):
        """Permit only actual personality-only i32(...) source declarations."""
        a = self.a
        referenced = set()
        for function in functions:
            if a.HasPersonalityFn(function):
                self.symbol = a.name(function)
                operand = self.exception_pointer(a.GetPersonalityFn(function), personality=True)
                referenced.add(self.symbol_values[operand["name"]])
        for function in referenced:
            if not a.IsAFunction(function):
                continue
            llvm_type = a.GlobalGetValueType(function)
            if not a.IsFunctionVarArg(llvm_type):
                continue
            self.symbol = a.name(function)
            result = a.GetReturnType(llvm_type)
            if (a.GetFirstBasicBlock(function) or a.GetLinkage(function) != 0
                    or a.GetFunctionCallConv(function) != 0 or a.CountParamTypes(llvm_type)
                    or a.GetTypeKind(result) != 8 or a.GetIntTypeWidth(result) != 32):
                self.reject("metadata-only personality requires an external C i32(...) declaration with zero fixed parameters")
            pending, visited = [function], set()
            while pending:
                value = pending.pop()
                if value in visited:
                    continue
                visited.add(value)
                for use in a.sequence(a.GetFirstUse, a.GetNextUse, value):
                    user = a.GetUser(use)
                    if (a.IsAFunction(user) and a.HasPersonalityFn(user)
                            and a.GetPersonalityFn(user) == value
                            and not a.HasPrefixData(user) and not a.HasPrologueData(user)):
                        continue
                    if a.IsAConstantExpr(user) and a.GetConstOpcode(user) in {29, 41}:
                        name, offset = self.symbol_constant(user)
                        if name == self.symbol and offset % (1 << 64) == 0:
                            pending.append(user)
                            continue
                    self.reject("metadata-only variadic personality declaration cannot escape into ordinary uses")
            self.metadata_personalities.add(function)

    def instruction(self, value, instructions):
        a, opcode = self.a, self.a.GetInstructionOpcode(value)
        self.metadata(value)
        operand = lambda i: self.operand(a.GetOperand(value, i))
        if opcode == 59:
            self.exception_aggregate(a.TypeOf(value))
            if self.exception_handling is None:
                self.reject("landingpad requires a retained exception personality")
            clauses = []
            for index in range(a.GetNumClauses(value)):
                clause = a.GetClause(value, index)
                clause_type = a.TypeOf(clause)
                if a.GetTypeKind(clause_type) == 12:
                    clauses.append({"kind": "catch", "typeinfo": self.exception_pointer(clause)})
                elif a.GetTypeKind(clause_type) == 11:
                    element = a.GetElementType(clause_type)
                    if a.GetTypeKind(element) != 12 or a.GetPointerAddressSpace(element) != 0:
                        self.reject("landingpad filter requires an original constant [N x ptrAS0] array")
                    typeinfos = []
                    for member in range(a.GetArrayLength2(clause_type)):
                        if member > 0xffffffff:
                            self.reject("landingpad filter element index exceeds LLVM C API unsigned range")
                        item = a.GetAggregateElement(clause, member)
                        if not item or a.TypeOf(item) != element:
                            self.reject("landingpad filter requires exact typed constant elements")
                        typeinfos.append(self.exception_pointer(item, filter_entry=True))
                    clauses.append({"kind": "filter", "typeinfos": typeinfos})
                else:
                    self.reject("landingpad requires supported ordered catch/filter clauses")
            cleanup = bool(a.IsCleanup(value))
            if not cleanup and not clauses:
                self.reject("landingpad requires cleanup or at least one clause")
            operation = {"op": "landing_pad", "cleanup": cleanup, "clauses": clauses}
            self.refinements.add(f"{self.symbol}: landingpad retains original unpacked {{ptrAS0,i32}}, cleanup flag and ordered catch/filter typeinfos including empty filters; required native LSDA/CFI and genuine provider closure are separate; no catch-all or cleanup substitution")
        elif opcode in self.BIN:
            flags = []
            if opcode in {8, 10, 12, 20}:
                flags += [name for name, fn in (("nsw", a.GetNSW), ("nuw", a.GetNUW)) if fn(value)]
            if opcode in {14, 15, 21, 22} and a.GetExact(value):
                flags.append("exact")
            if opcode == 24 and a.GetIsDisjoint(value):
                flags.append("disjoint")
            operation = {"op": "binary", "kind": self.BIN[opcode], "lhs": operand(0), "rhs": operand(1), "flags": flags}
        elif opcode in self.CAST:
            if opcode == 31 and a.GetNNeg(value):
                self.refinements.add("zext nneg poison assumption erased")
            if opcode == 30 and (a.GetNSW(value) or a.GetNUW(value)):
                self.refinements.add("trunc nowrap poison assumptions erased")
            operation = {"op": "cast", "kind": self.CAST[opcode], "value": operand(0)}
        elif opcode == 42:
            if a.GetICmpSameSign(value):
                self.refinements.add("icmp samesign poison assumption erased")
            operation = {"op": "i_cmp", "predicate": self.CMP[a.GetICmpPredicate(value)], "lhs": operand(0), "rhs": operand(1)}
        elif opcode == 46:
            operation = {"op": "select", "condition": operand(0), "on_true": operand(1), "on_false": operand(2)}
        elif opcode == 68:
            operation = {"op": "freeze", "value": operand(0)}
        elif opcode in {53, 54}:
            # Extract/insert paths are unsigned integer metadata on the
            # instruction, not ordinary LLVM value operands or GEP indices.
            count = a.GetNumIndices(value)
            path = a.GetIndices(value)
            if not count or not path:
                self.reject("extractvalue/insertvalue requires a nonempty constant index path")
            indices = [int(path[index]) for index in range(count)]
            operation = {"op": "extract_value" if opcode == 53 else "insert_value",
                         "aggregate": operand(0), "indices": indices}
            if opcode == 54:
                operation["value"] = operand(1)
        elif opcode == 26:
            if self.block_ids[a.GetInstructionParent(value)] != 0:
                self.reject("non-entry alloca needs dynamic stack lifetime lowering")
            count = a.GetOperand(value, 0)
            if not a.IsAConstantInt(count):
                self.reject("dynamic alloca is unsupported")
            self.scalar(a.TypeOf(count))
            self.refinements.add(f"{self.symbol}: alloca inalloca/swifterror restrictions, if present, refined to ordinary storage; every ABI-dependent use is rejected")
            allocated = a.GetAllocatedType(value)
            self.ty(allocated)
            size = a.ABISizeOfType(self.layout, allocated) * a.ConstIntGetZExtValue(count)
            if size >= 1 << 64:
                self.reject("alloca byte extent exceeds u64")
            operation = {"op": "alloca", "size": size,
                         "alignment": self.instruction_alignment(value)}
        elif opcode == 29:
            operation = {"op": "gep", "base": operand(0), "offset": self.gep_offset(value, instructions), "inbounds": bool(a.IsInBounds(value))}
        elif opcode in {27, 28}:
            if not (a.IsALoadInst if opcode == 27 else a.IsAStoreInst)(value):
                self.reject("load/store instruction subclass is invalid")
            if a.GetOrdering(value):
                operation = self.atomic_operation(value, opcode)
            elif opcode == 27:
                operation = {"op": "load", "pointer": operand(0), "alignment": self.instruction_alignment(value), "volatile": bool(a.GetVolatile(value))}
            else:
                operation = {"op": "store", "pointer": operand(1), "value": operand(0), "alignment": self.instruction_alignment(value), "volatile": bool(a.GetVolatile(value))}
        elif opcode in {55, 56, 57}:
            operation = self.atomic_operation(value, opcode)
        elif opcode == 45:
            if a.GetNumOperandBundles(value) or a.GetTailCallKind(value) == 2:
                self.reject("operand bundles and musttail calls are unsupported")
            callee = a.GetCalledValue(value)
            intrinsic = None
            if a.IsAFunction(callee) and a.GetIntrinsicID(callee):
                intrinsic = a.name(callee)
                if intrinsic not in self.INTRINSICS:
                    self.reject(f"intrinsic {intrinsic} requires explicit call lowering")
                if intrinsic in self.MINMAX_INTRINSICS:
                    self.minmax_identity(callee, intrinsic)
            signature = self.signature(a.GetCalledFunctionType(value), value, call=True, intrinsic=intrinsic)
            # A TLS GlobalVariable is the descriptor of current-thread storage,
            # not an ordinary constant Symbol address. Only this owned call
            # reads its literal global argument without materializing a Symbol.
            args = ([] if intrinsic in {"llvm.threadlocal.address.p0", self.NOALIAS_INTRINSIC} else
                    [self.operand(a.GetOperand(value, i)) for i in range(a.GetNumArgOperands(value))])
            if intrinsic:
                self.intrinsic_signature(intrinsic, signature)
            if intrinsic == self.NOALIAS_INTRINSIC:
                argument = a.GetOperand(value, 0)
                if a.GetTypeKind(a.TypeOf(argument)) != 14:
                    self.reject("noalias scope declaration requires a compiler-only metadata argument")
                scope_list = self.noalias_list(a.ValueAsMetadata(argument), declaration=True)
                operation = {"op": "no_alias_scope_decl", "scope_list": scope_list,
                             "source_instruction": self.instruction_positions[value][1]}
                self.refinements.add(f"{self.symbol}: retained llvm.experimental.noalias.scope.decl as an exact compiler-only scope marker; original list/scope/domain identity and declaration placement retained; no runtime instruction, metadata ABI, alias-based optimization, purity or memory-effect inference")
                self.refinements.add("scoped alias metadata graph uses actual parsed metadata identity and deterministic module-local traversal IDs; trusted LLVM printer records attest post-parse storage only; raw pointer fallback labels remain provenance bytes, never graph IDs; input_sha256 binds original spelling and bytes; no associated alias assumptions are used for optimization")
            elif intrinsic == "llvm.assume":
                operation = {"op": "assume", "condition": args[0]}
                self.refinements.add("llvm.assume with empty operand bundles retained as an explicit assumption; defined true has no effect, false/poison are UB; own no-opt emitter may erase it")
            elif intrinsic == "llvm.trap":
                operation = {"op": "trap"}
                self.refinements.add("llvm.trap with exact void() signature retained as an explicit terminating effect after preceding operations; own native lowering uses the target-specific trap instruction, with signal and debugger delivery qualified by the execution profile; no native helper symbol or unreachable substitution")
            elif intrinsic == "llvm.eh.typeid.for.p0":
                operation = {"op": "eh_type_id", "typeinfo": self.exception_pointer(a.GetOperand(value, 0))}
                self.refinements.add(f"{self.symbol}: llvm.eh.typeid.for.p0 retains exact declaration identity and static typeinfo in the function-local LSDA type table shared with catch/filter clauses; no ordinary intrinsic call or global type-id substitution")
            elif intrinsic == "llvm.threadlocal.address.p0":
                global_ = a.GetOperand(value, 0)
                if (a.GetNumArgOperands(value) != 1 or not a.IsAGlobalVariable(global_)
                        or not a.IsThreadLocal(global_)):
                    self.reject("thread-local address requires a direct TLS GlobalVariable argument")
                operation = {"op": "thread_local_address", "global": a.name(global_)}
                self.refinements.add(f"{self.symbol}: llvm.threadlocal.address.p0 retains current-thread address identity for TLS global {operation['global']} and original result; no ordinary Symbol address, static TLS relocation, resolver substitution or provider closure inferred")
            elif intrinsic in self.RELATIVE_INTRINSICS:
                width = int(intrinsic.rsplit(".i", 1)[1])
                index = args[1]
                if width == 32:
                    index = self.synthetic({"op": "cast", "kind": "s_ext", "value": index}, self.integer_type(), instructions)
                slot = self.synthetic({"op": "gep", "base": args[0], "offset": index, "inbounds": False}, signature["result"], instructions)
                displacement = self.synthetic({"op": "load", "pointer": slot, "alignment": 4, "volatile": False}, self.integer_type(32), instructions)
                displacement = self.synthetic({"op": "cast", "kind": "s_ext", "value": displacement}, self.integer_type(), instructions)
                operation = {"op": "gep", "base": args[0], "offset": displacement, "inbounds": False}
                self.refinements.add(f"{self.symbol}: {intrinsic} retains exact declaration and original result identity; signed byte index addresses a nonvolatile aligned-4 i32 load, whose signed displacement is added to the ORIGINAL base; lowered with existing native GEP/load/cast operations, no helper or invoke admission; no link-span guarantee inferred")
            elif intrinsic in self.OVERFLOW_INTRINSICS:
                family = intrinsic.split(".")[1]
                operation = {"op": "integer_overflow", "kind": family[1:], "signed": family[0] == "s",
                             "lhs": args[0], "rhs": args[1]}
                width = int(intrinsic.rsplit(".i", 1)[1])
                self.refinements.add(f"{intrinsic}: exact owned {'signed' if operation['signed'] else 'unsigned'} {operation['kind']} retains wrapped i{width} result and i1 mathematical overflow; input poison/undef retained; no nsw/nuw substitution, ordinary runtime call or trapping overflow")
            elif intrinsic in self.MINMAX_INTRINSICS:
                kind = intrinsic.split(".")[1]
                operation = {"op": "integer_min_max", "kind": kind, "lhs": args[0], "rhs": args[1]}
                width = int(intrinsic.rsplit(".i", 1)[1])
                self.refinements.add(f"{intrinsic}: exact owned integer {kind} retains original i{width} operands and result with {'signed' if kind.startswith('s') else 'unsigned'} ordering; each original operand represented once, poison/undef retained under llvm_defined_behavior_v1; signed i1 true orders as -1 before false; no arithmetic/no-wrap flags, duplicated cmp/select uses, runtime helper or purity inference")
            elif intrinsic in self.LIFETIME_INTRINSICS:
                pointer = a.GetOperand(value, 0)
                if not a.IsAAllocaInst(pointer) and not a.IsAPoisonValue(pointer):
                    self.reject("lifetime requires a direct alloca SSA pointer or poison")
                operation = {"op": "lifetime", "pointer": args[0], "end": intrinsic == "llvm.lifetime.end.p0"}
                self.refinements.add("owned lifetime start/end retained; fixed distinct alloca storage and address identity are preserved without marker-driven slot reuse or optimization; poison markers have no effect")
                self.refinements.add("lifetime contracts validated after pinned LLVM parsing and legacy upgrades; input_sha256 binds the original bytes")
            elif intrinsic in self.MEMORY_INTRINSICS:
                volatility = a.GetOperand(value, 3)
                if not a.IsAConstantInt(volatility):
                    self.reject("memory intrinsic volatility must be a constant i1")
                volatile = a.ConstIntGetZExtValue(volatility)
                if volatile not in {0, 1}:
                    self.reject("memory intrinsic volatility must be exactly false or true")
                if intrinsic.startswith("llvm.memset."):
                    operation = {"op": "memory_set", "destination": args[0], "value": args[1],
                                 "length": args[2], "alignment": self.memory_alignment(value, 1), "volatile": bool(volatile)}
                else:
                    operation = {"op": "memory_copy", "destination": args[0], "source": args[1], "length": args[2],
                                 "destination_alignment": self.memory_alignment(value, 1),
                                 "source_alignment": self.memory_alignment(value, 2),
                                 "volatile": bool(volatile), "allow_overlap": intrinsic.startswith("llvm.memmove.")}
                self.refinements.add(f"{intrinsic}: owned exact-byte memory operation retains unsigned length, callsite alignment and volatility; zero length accesses no memory; overlap policy is explicit; no native helper symbol or erased memory effect")
            else:
                operation = {"op": "call", "callee": self.operand(callee), "signature": signature, "args": args}
        elif opcode == 44:
            incoming = {}
            for i in range(a.CountIncoming(value)):
                block = self.block_ids[a.GetIncomingBlock(value, i)]
                operand_ = self.operand(a.GetIncomingValue(value, i))
                if block in incoming:
                    if incoming[block] != operand_:
                        self.reject("duplicate PHI edges have different values")
                    self.refinements.add(f"{self.symbol}: duplicate CFG edges with identical PHI values coalesced")
                else:
                    incoming[block] = operand_
            operation = {"op": "phi", "incoming": [{"block": block, "value": operand_} for block, operand_ in incoming.items()]}
        else:
            self.reject(f"unsupported instruction opcode {opcode}")
        result = None if a.GetTypeKind(a.TypeOf(value)) == 0 else {"id": self.values[value], "ty": self.value_type(a.TypeOf(value))}
        instructions.append({"result": result, "operation": operation})

    def terminator(self, value):
        a, opcode = self.a, self.a.GetInstructionOpcode(value)
        self.metadata(value)
        if opcode == 5:
            if self.exception_handling is None:
                self.reject("invoke requires a retained Itanium exception personality")
            if a.GetNumOperandBundles(value):
                self.reject("operand bundles on invoke are unsupported")
            callee = a.GetCalledValue(value)
            if a.IsAFunction(callee) and (a.GetIntrinsicID(callee) or a.name(callee).startswith("llvm.")):
                self.reject("intrinsic cannot be invoked through an ordinary unwind call")
            # Invoke is a CallBase but not a CallInst: no TailCallKind getter.
            signature = self.signature(a.GetCalledFunctionType(value), value, call=True)
            args = [self.operand(a.GetOperand(value, i)) for i in range(a.GetNumArgOperands(value))]
            result = None if a.GetTypeKind(a.TypeOf(value)) == 0 else {"id": self.values[value], "ty": self.value_type(a.TypeOf(value))}
            block = self.block_ids[a.GetInstructionParent(value)]
            self.refinements.add(f"{self.symbol}: invoke block {block} retains original callee, raw callsite signature/CC/arguments, result and normal/unwind destinations; result is available only on the normal edge; pinned LLVM and mandatory NativeModule edge-aware SSA verification required")
            return {"op": "invoke", "callee": self.operand(callee), "signature": signature,
                    "args": args, "result": result, "normal": self.block_ids[a.GetNormalDest(value)],
                    "unwind": self.block_ids[a.GetUnwindDest(value)]}
        if opcode == 58:
            if self.exception_handling is None:
                self.reject("resume requires a retained exception personality")
            exception = a.GetOperand(value, 0)
            self.exception_aggregate(a.TypeOf(exception))
            self.refinements.add(f"{self.symbol}: resume retains the original exception aggregate and explicit _Unwind_Resume provider interface; no ordinary return, fabricated exception or manual unwinder")
            return {"op": "resume", "value": self.operand(exception)}
        if opcode == 1:
            return {"op": "return", "value": self.operand(a.GetOperand(value, 0)) if a.GetNumOperands(value) else None}
        if opcode == 2:
            successors = [self.block_ids[a.GetSuccessor(value, i)] for i in range(a.GetNumSuccessors(value))]
            if len(successors) == 1:
                return {"op": "jump", "target": successors[0]}
            return {"op": "branch", "condition": self.operand(a.GetCondition(value)), "on_true": successors[0], "on_false": successors[1]}
        if opcode == 3:
            successors = a.GetNumSuccessors(value)
            if not successors or a.GetNumOperands(value) != successors + 1:
                self.reject("unsupported LLVM switch operand layout")
            condition = a.GetOperand(value, 0)
            condition_type = a.TypeOf(condition)
            if a.GetTypeKind(condition_type) != 8:
                self.reject("switch condition must have scalar integer type")
            imported_condition = self.operand(condition)
            cases = []
            # LLVM 22 stores case integers outside the ordinary operands.
            # Its dedicated getter and successor API share one-based indices.
            for index in range(1, successors):
                case = a.GetSwitchCaseValue(value, index)
                if not case or not a.IsAConstantInt(case) or a.TypeOf(case) != condition_type:
                    self.reject("switch case must be a constant integer of the condition type")
                cases.append({"value": self.operand(case),
                              "target": self.block_ids[a.GetSuccessor(value, index)]})
            return {"op": "switch", "condition": imported_condition,
                    "default": self.block_ids[a.GetSuccessor(value, 0)], "cases": cases}
        if opcode == 7:
            return {"op": "unreachable"}
        self.reject(f"unsupported terminator opcode {opcode}")

    def assume_signature(self, signature):
        if (self.types[signature["result"]] != {"kind": "void"}
                or len(signature["params"]) != 1
                or self.types[signature["params"][0]] != {"kind": "int", "bits": 1}
                or signature["result_attributes"]
                or any(signature["param_attributes"])):
            self.reject("llvm.assume requires exact void(i1) signature without ABI extension attributes")

    def function(self, value):
        a = self.a
        self.symbol = a.name(value)
        if not self.symbol:
            self.reject("unnamed function")
        linkage, visibility, alignment, comdat = self.global_contract(value)
        intrinsic = None
        if a.GetIntrinsicID(value) or self.symbol.startswith("llvm."):
            if self.symbol not in self.INTRINSICS or not a.GetIntrinsicID(value):
                self.reject(f"intrinsic {self.symbol} requires explicit lowering")
            intrinsic = self.symbol
            if intrinsic in self.MINMAX_INTRINSICS:
                self.minmax_identity(value, intrinsic)
        if a.GetGC(value) or a.HasPrefixData(value) or a.HasPrologueData(value):
            self.reject("unsupported function GC or prefix/prologue data")
        self.exception_handling = None
        if a.HasPersonalityFn(value):
            if intrinsic or not a.GetFirstBasicBlock(value):
                self.reject("exception personality requires an ordinary function definition")
            self.exception_handling = {"model": "itanium_dwarf_v1",
                                       "personality": self.exception_pointer(a.GetPersonalityFn(value), personality=True)}
            self.refinements.add(f"{self.symbol}: retained original Itanium/DWARF personality identity without callback substitution; native instruction-precise CFI/LSDA, unwind services and complete included provider closure require independent realization")
        signature = self.signature(a.GlobalGetValueType(value), value, intrinsic=intrinsic)
        if intrinsic:
            if visibility != "default":
                self.reject("owned intrinsic requires default symbol visibility")
            self.intrinsic_signature(intrinsic, signature)
            if a.GetFirstBasicBlock(value):
                self.reject(f"{intrinsic} must remain an owned intrinsic declaration")
        params = (P * a.CountParams(value))()
        a.GetParams(value, params)
        blocks = list(a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, value))
        self.values, self.block_ids = {}, {block: i for i, block in enumerate(blocks)}
        self.instruction_positions = {}
        self.source_sites = {}
        for param in params:
            self.values[param] = len(self.values)
        for block in blocks:
            for ordinal, inst in enumerate(a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block)):
                self.instruction_positions[inst] = (self.block_ids[block], ordinal)
                if a.GetTypeKind(a.TypeOf(inst)) != 0:
                    self.value_type(a.TypeOf(inst))
                    self.values[inst] = len(self.values)
        self.next_id = len(self.values)
        imported = []
        for block in blocks:
            terminator = a.GetBasicBlockTerminator(block)
            instructions = []
            for inst in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                self.source_sites[inst] = {"function": self.symbol, "block": self.block_ids[block],
                                           "instruction": len(instructions), "instruction_count": 0,
                                           "source_instruction": self.instruction_positions[inst][1]}
                if inst != terminator:
                    start = len(instructions)
                    self.instruction(inst, instructions)
                    self.source_sites[inst]["instruction_count"] = len(instructions) - start
            imported.append({"id": self.block_ids[block], "instructions": instructions, "terminator": self.terminator(terminator)})
        return {"name": self.symbol, "linkage": linkage, "visibility": visibility, "alignment": alignment, "comdat": comdat, "signature": signature,
                "params": [{"id": self.values[param], "ty": signature["params"][index]}
                           for index, param in enumerate(params)],
                "entry": 0 if blocks else None, "blocks": imported, "managed_method": None, "intrinsic": intrinsic,
                "exception_handling": self.exception_handling}

    def module_metadata(self):
        if self.metadata_checked:
            return
        a = self.a
        riscv64 = (a.GetTarget(self.module) or b"").split(b"-")[0] == b"riscv64"
        relocation_flags = set()
        unwind_table_seen = False
        for node in a.sequence(a.GetFirstNamedMetadata, a.GetNextNamedMetadata, self.module):
            name = a.string(a.GetNamedMetadataName, node)
            if name == "llvm.errno.tbaa":
                # LLVMVerifyModule validates the TBAA nodes. They only constrain
                # alias analysis (LangRef: llvm.errno.tbaa); emission performs no
                # such optimization and retains actual calls and memory effects.
                self.refinements.add("erased llvm.errno.tbaa alias-analysis assumptions; calls and memory effects retained")
                continue
            if name in {"llvm.ident", "llvm.dbg.cu"}:
                if name == "llvm.ident":
                    entries = (P * a.GetNamedMetadataNumOperands(self.module, name.encode()))()
                    a.GetNamedMetadataOperands(self.module, name.encode(), entries)
                    for entry in entries:
                        parts = (P * a.GetMDNodeNumOperands(entry))()
                        a.GetMDNodeOperands(entry, parts)
                        self.producer_ident.extend(a.string(a.GetMDString, part, U) for part in parts if part and a.IsAMDString(part))
                self.refinements.add(f"erased descriptive named metadata {name}")
                continue
            if name != "llvm.module.flags":
                self.reject(f"unsupported named metadata {name}")
            entries = (P * a.GetNamedMetadataNumOperands(self.module, name.encode()))()
            a.GetNamedMetadataOperands(self.module, name.encode(), entries)
            for entry in entries:
                if a.GetMDNodeNumOperands(entry) != 3:
                    self.reject("unsupported module flag structure")
                parts = (P * 3)()
                a.GetMDNodeOperands(entry, parts)
                if not a.IsAMDString(parts[1]):
                    self.reject("module flag has no string key")
                key = a.string(a.GetMDString, parts[1], U)
                # Other flags may change code generation, linking, EH or security.
                if key in {"wchar_size", "Debug Info Version", "Dwarf Version"}:
                    self.refinements.add(f"erased descriptive module flag {key}")
                elif key in {"PIC Level", "PIE Level"}:
                    expected_behavior = 8 if key == "PIC Level" else 7
                    if (not a.IsAConstantInt(parts[0]) or not a.IsAConstantInt(parts[2])
                            or a.GetIntTypeWidth(a.TypeOf(parts[0])) != 32
                            or a.GetIntTypeWidth(a.TypeOf(parts[2])) != 32):
                        self.reject(f"unsupported module flag {key} types; expected i32 behavior and level")
                    behavior = a.ConstIntGetZExtValue(parts[0])
                    level = a.ConstIntGetZExtValue(parts[2])
                    if behavior != expected_behavior or level not in {0, 1, 2} or key in relocation_flags:
                        self.reject(f"unsupported module flag {key}={level}, behavior={behavior}")
                    relocation_flags.add(key)
                    # LLVM IR linking merges PIC (Min) and PIE (Max) separately;
                    # equal levels are a Clang producer choice, not an IR rule.
                    level_name = ({0: "NotPIC", 1: "SmallPIC", 2: "BigPIC"} if key == "PIC Level"
                                  else {0: "Default", 1: "Small", 2: "Large"})[level]
                    merge_name = "Min" if key == "PIC Level" else "Max"
                    self.refinements.add(f"re-lowered parsed LLVM {key}={level} ({level_name}), behavior={behavior} ({merge_name}) under the required static, non-preemptive native linkage profile; symbol operands, calls and initializer relocations retained; dynamic ELF linking/PIE publication and mixed precompiled PIC interoperability are unsupported")
                    self.refinements.add("PIC/PIE metadata validated after pinned LLVM parsing and legacy upgrades; input_sha256 binds the original bytes")
                elif key == "uwtable":
                    if (not a.IsAConstantInt(parts[0]) or not a.IsAConstantInt(parts[2])
                            or a.GetIntTypeWidth(a.TypeOf(parts[0])) != 32
                            or a.GetIntTypeWidth(a.TypeOf(parts[2])) != 32):
                        self.reject("unsupported module flag uwtable types; expected i32 behavior and level")
                    behavior = a.ConstIntGetZExtValue(parts[0])
                    level = a.ConstIntGetZExtValue(parts[2])
                    if behavior != 7 or level not in {0, 1, 2} or unwind_table_seen:
                        self.reject(f"unsupported module flag uwtable={level}, behavior={behavior}")
                    unwind_table_seen = True
                    # The module flag requests the default for synthesized
                    # functions. None is not a ban on additional unwind tables.
                    # Own emitters realize the strongest supported requirement
                    # with instruction-precise CFI in every native definition.
                    level_name = {0: "None", 1: "Sync", 2: "Async"}[level]
                    self.refinements.add(f"realized parsed LLVM module uwtable={level} ({level_name}), behavior=7 (Max) with required own-emitter instruction-precise DWARF unwind tables in every native definition; exception personalities, EH landing pads and runtime unwind services require separate supported paths")
                elif key == "target-abi" and a.IsAMDString(parts[2]):
                    abi = a.string(a.GetMDString, parts[2], U)
                    if not riscv64 or abi not in {"lp64", "lp64d"} or self.target_abi not in {None, abi}:
                        self.reject(f"unsupported target ABI {abi}")
                    self.target_abi = abi
                    self.refinements.add(f"verified RISC-V {abi} target ABI")
                    self.refinements.add("exact RISC-V scalar ABI identity retained independently of target tuning; floating-point first-class values and operations remain unsupported; binary128 storage layout is separately audited")
                    if abi == "lp64d":
                        self.refinements.add("lp64d requires the own RV64GC D/F/Zicsr-enabled, E-disabled execution profile and matching native ELF ABI identity; absent target tuning is qualified by that profile, not inferred from the producer CPU")
                elif key == "riscv-isa" and riscv64:
                    self.refinements.add("frontend RISC-V ISA tuning erased; own RV64GC emitter consumes scalar operations only")
                elif key == "Code Model" and a.IsAConstantInt(parts[2]):
                    if a.GetIntTypeWidth(a.TypeOf(parts[2])) != 32:
                        self.reject(f"unsupported module flag {key} integer width; expected i32")
                    number = a.ConstIntGetZExtValue(parts[2])
                    if not riscv64 or number != 3:
                        self.reject(f"unsupported module flag {key}={number}")
                    self.refinements.add("re-lowered RISC-V Code Model=3 (Medium) under the required static, non-preemptive scalar native linkage profile; own emission and linking must resolve address materialization and relocation spans; mixed precompiled code models are unsupported")
                elif key in {"frame-pointer", "RtLibUseGOT", "SmallDataLimit"} and a.IsAConstantInt(parts[2]):
                    if a.GetIntTypeWidth(a.TypeOf(parts[2])) != 32:
                        self.reject(f"unsupported module flag {key} integer width; expected i32")
                    number = a.ConstIntGetZExtValue(parts[2])
                    if (key == "frame-pointer" and number not in {0, 1, 2, 4}) or (key == "RtLibUseGOT" and number not in {0, 1}):
                        self.reject(f"unsupported module flag {key}={number}")
                    self.refinements.add(f"erased scalar codegen module flag {key}={number}; own emitters use frame pointers and introduce no LLVM runtime libcalls")
                else:
                    self.reject(f"unsupported module flag {key}")
        self.metadata_checked = True

    def check_target_profile(self):
        a = self.a
        triple = (a.GetTarget(self.module) or b"").decode()
        layout = (a.GetDataLayoutStr(self.module) or b"").decode()
        parts = triple.split("-")
        elf_profile = len(parts) in {3, 4} and bool(parts[1]) and (
            (parts[2] == "linux" and len(parts) == 4 and parts[3] in {"gnu", "musl"})
            or (parts[2] == "none" and (len(parts) == 3 or parts[3] in {"elf", "eabi"}))
        )
        bare_riscv = triple == "riscv64" and self.target_abi in {"lp64", "lp64d"}
        if parts[0] not in {"x86_64", "aarch64", "riscv64"} or not (elf_profile or bare_riscv) or not layout:
            self.reject("explicit supported target triple and DataLayout are required")
        if self.tls_profile is not None and not (
                len(parts) == 4 and bool(parts[1]) and parts[2] == "linux"
                and parts[3] in {"gnu", "musl"}):
            self.reject("native TLS profile requires a qualified Linux GNU/musl target triple")
        return triple, layout

    def run(self, input_digest, frontend, frontend_version):
        a = self.a
        self.module_metadata()
        triple, layout = self.check_target_profile()
        self.layout = a.CreateTargetData(layout.encode())
        try:
            if a.PointerSize(self.layout) != 8 or a.ByteOrder(self.layout) != 1:
                self.reject("only 64-bit little-endian target layouts are supported")
            # Non-integral pointers, alternate program/alloca/global spaces and
            # non-64-bit GEP indices cannot be represented by this schema.
            for field in layout.split("-"):
                if field.startswith(("ni:", "A", "P", "G")):
                    self.reject(f"unsupported DataLayout component {field}")
                if field.startswith(("p:", "p0:")) and len(field.split(":")) > 4 and field.split(":")[-1] != "64":
                    self.reject("non-64-bit pointer index width is unsupported")
            length = S()
            a.GetModuleInlineAsm(self.module, C.byref(length))
            if length.value or a.GetFirstGlobalIFunc(self.module):
                self.reject("module inline assembly and IFUNCs require explicit lowering")
            source_functions = list(a.sequence(a.GetFirstFunction, a.GetNextFunction, self.module))
            source_globals = list(a.sequence(a.GetFirstGlobal, a.GetNextGlobal, self.module))
            source_aliases = list(a.sequence(a.GetFirstGlobalAlias, a.GetNextGlobalAlias, self.module))
            self.symbol_values = {a.name(value): value for value in [*source_functions, *source_globals, *source_aliases]}
            self.classify_metadata_personalities(source_functions)
            globals_ = []
            for value in source_globals:
                self.symbol = a.name(value)
                if not self.symbol or self.symbol.startswith("llvm."):
                    self.reject("unnamed/special global (constructors, retention, annotations) is unsupported")
                linkage, visibility, alignment, comdat = self.global_contract(value)
                if a.IsExternallyInitialized(value):
                    self.reject("externally initialized globals are unsupported")
                mode = a.GetThreadLocalMode(value)
                thread_local = bool(a.IsThreadLocal(value))
                if (mode not in {0, *self.TLS_MODELS} or thread_local != bool(mode)):
                    self.reject(f"unsupported or inconsistent TLS mode {mode}")
                tls_model = self.TLS_MODELS.get(mode)
                if thread_local and self.tls_profile is None:
                    self.reject("TLS globals require explicit --tls-profile linux-elf-static-nonpreemptive-v1")
                llvm_type = a.GlobalGetValueType(value)
                ty = self.ty(llvm_type)
                initializer = a.GetInitializer(value)
                init = None
                if initializer:
                    data = bytearray(a.ABISizeOfType(self.layout, llvm_type))
                    relocations = []
                    self.initializer(initializer, llvm_type, data, relocations)
                    init = {"bytes": list(data), "relocations": relocations}
                global_ = {"name": self.symbol, "ty": ty, "linkage": linkage, "visibility": visibility,
                                 "comdat": comdat,
                                 "alignment": alignment or a.ABIAlignmentOfType(self.layout, llvm_type),
                                  "constant": bool(a.IsGlobalConstant(value)), "thread_local": thread_local, "initializer": init}
                if tls_model is not None:
                    global_["tls_model"] = tls_model
                    self.refinements.add(f"{self.symbol}: retained TLS storage and original access model {tls_model} (LLVM mode {mode}); original type, template initializer, alignment, linkage, visibility and COMDAT retained; own local-exec realization requires complete executable-local nonpreemptive bindings and genuine TLS image/thread-pointer lifecycle providers; no relaxation, interposition or provider closure inferred")
                globals_.append(global_)
            functions = [self.function(value) for value in source_functions]
            definitions = {value for value in source_functions if a.GetFirstBasicBlock(value)}
            definitions.update(value for value in source_globals if a.GetInitializer(value))
            aliases = [self.alias(value, definitions) for value in source_aliases]
            if frontend_version == "producer version not declared" and self.producer_ident:
                frontend_version = "self-reported !llvm.ident: " + "; ".join(self.producer_ident)
            self.refinements.add("LLVM poison/undef may be refined deterministically; dropped assumptions are never used for optimization")
            target = {"triple": triple, "data_layout": layout, "pointer_bits": 64, "little_endian": True}
            if self.target_abi is not None:
                target["abi"] = self.target_abi
            if self.tls_profile is not None:
                target["tls_profile"] = "linux_elf_static_nonpreemptive_v1"
                self.refinements.add("explicit linux-elf-static-nonpreemptive-v1 TLS realization profile retained independently of original source access models; native linking and execution must establish complete static nonpreemptive TLS bindings, genuine TLS templates and each thread's initialized thread pointer; no automatic provider or lifecycle admission")
            if self.atomic_profile is not None:
                target["atomic_profile"] = "coherent_ram_v1"
                self.refinements.add("explicit coherent-ram-v1 atomic realization profile retained independently of source orderings, synchronization scopes and volatility; ordinary coherent RAM only, no MMIO; masked subword realization requires the complete containing word mapped as coherent RAM; RV LR/SC realization requires the platform's eventuality-region property, and a constrained loop alone does not establish liveness or starvation freedom; native realization, threading providers and dependency closure are not inferred")
            if self.atomic_sync_scope_ids:
                self.refinements.add("atomic synchronization scopes retain exact parsed LLVM context-local IDs and arbitrary name bytes from verified LLVM bitcode serialization; original input_sha256 binds reader scope-ID normalization; IDs are not global linkage or capability identities")
                if self.atomic_profile is None:
                    self.refinements.add("original atomic operations preserved as source IR without an inferred atomic profile; own native backend requires an explicit coherent-ram-v1 realization contract")
            return {"format": FORMAT, "name": a.string(a.GetModuleIdentifier, self.module),
                    "target": target,
                    "semantics": "llvm_defined_behavior_v1", "types": self.types, "globals": globals_, "functions": functions, "aliases": aliases,
                    "comdats": self.comdats,
                    "noalias_metadata": self.noalias_metadata,
                    "atomic_sync_scopes": [{"id": ident, "name": list(self.atomic_sync_scope_names[ident])}
                                           for ident in sorted(self.atomic_sync_scope_ids)],
                    "provenance": {"input_sha256": input_digest, "frontend": frontend, "frontend_version": frontend_version,
                                   "importer": "ocore_llvm_import.py", "importer_version": f"1; LLVM 22.1.6; library-sha256={a.digest}",
                                   "source_function_count": len(source_functions), "source_global_count": len(source_globals),
                                   "source_alias_count": len(source_aliases),
                                   "referenced_comdat_count": len(self.comdats),
                                   "noalias_metadata_source": self.noalias_node_sources,
                                   "refinements": sorted(self.refinements)}}
        finally:
            a.DisposeTargetData(self.layout)


def preflight_scoped_alias_metadata(a, context, module):
    """Reject unsafe scoped graph nulls before the pinned verifier visits them.

    LLVM 22's scoped-alias verifier uses null-unsafe casts in list, scope and
    domain operands. This is only a native-call safety boundary: nonnull shape
    and subclass errors still receive mandatory LLVM verification, followed by
    the importer's stricter graph contract. No metadata is rewritten or erased.
    """
    kinds = {a.GetMDKindIDInContext(context, name, len(name))
             for name in (b"alias.scope", b"noalias")}
    visited = set()
    symbol = ""

    def reject(detail):
        raise ImportFailure("pre-verifier scoped alias metadata safety: " + detail,
                            symbol=symbol)

    def operands(metadata):
        if not metadata:
            reject("null metadata graph node")
        # MDString, ValueAsMetadata and DistinctMDOperandPlaceholder are not
        # MDNodes. LLVMIsAMDNode also accepts ValueAsMetadata, so exclude them
        # before any assertion-based operand getter. Specialized MDNodes stay
        # eligible for verification; supported import still requires MDTuple.
        if a.GetMetadataKind(metadata) in {0, 1, 2, 3}:
            return None
        value = a.MetadataAsValue(context, metadata)
        if not value or a.ValueAsMetadata(value) != metadata:
            reject("metadata wrapper canonicalization loses parsed node identity")
        if not a.IsAMDNode(value):
            return None
        count = a.GetMDNodeNumOperands(value)
        items = (P * count)()
        a.GetMDNodeOperands(value, items)
        return [a.ValueAsMetadata(item) if item else None for item in items]

    def visit(metadata, role):
        key = (metadata, role)
        if key in visited:
            return
        visited.add(key)
        items = operands(metadata)
        if items is None:
            return
        if role == "list":
            for item in items:
                if not item:
                    reject("null scope list member")
                visit(item, "scope")
        elif role == "scope" and len(items) in {2, 3}:
            if not items[0]:
                reject("null scope identity")
            if not items[1]:
                reject("null scope domain")
            if len(items) == 3 and not items[2]:
                reject("null scope description")
            visit(items[1], "domain")
        elif role == "domain":
            # The child getter wraps each node through MetadataAsValue::get:
            # an original one-null domain is exposed as an empty MDTuple, so
            # its raw identity cannot be recovered through this C API. Both
            # that unsafe case and a real empty domain violate the 1/2 grammar.
            if not items:
                reject("empty domain or canonicalized null domain violates the required one-or-two-operand grammar")
            if len(items) in {1, 2}:
                if not items[0]:
                    reject("null domain identity")
                if len(items) == 2 and not items[1]:
                    reject("null domain description")

    def attachments(value, global_value=False):
        count = S()
        entries = (a.GlobalCopyAllMetadata if global_value else
                   a.InstructionGetAllMetadataOtherThanDebugLoc)(value, C.byref(count))
        try:
            for index in range(count.value):
                if a.ValueMetadataEntriesGetKind(entries, index) in kinds:
                    visit(a.ValueMetadataEntriesGetMetadata(entries, index), "list")
        finally:
            if entries:
                a.DisposeValueMetadataEntries(entries)

    def raw_name(value):
        length = S()
        name = a.GetValueName2(value, C.byref(length))
        return C.string_at(name, length.value) if name else b""

    for global_ in a.sequence(a.GetFirstGlobal, a.GetNextGlobal, module):
        symbol = raw_name(global_).decode(errors="replace")
        attachments(global_, global_value=True)
    for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
        symbol = raw_name(function).decode(errors="replace")
        attachments(function, global_value=True)
        for block in a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function):
            for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                attachments(instruction)
                # All three are CallBase; never use CallInst-only tail getters.
                if a.GetInstructionOpcode(instruction) not in {5, 45, 67}:
                    continue
                callee = a.GetCalledValue(instruction)
                if (not a.IsAFunction(callee) or not a.GetIntrinsicID(callee)
                        or raw_name(callee) != Importer.NOALIAS_INTRINSIC.encode()
                        or not a.GetNumArgOperands(instruction)):
                    continue
                argument = a.GetOperand(instruction, 0)
                if a.GetTypeKind(a.TypeOf(argument)) == 14:  # LLVMMetadataTypeKind
                    visit(a.ValueAsMetadata(argument), "list")


def audit_verified_module(a, module):
    serialized = a.WriteBitcodeToMemoryBuffer(module)
    if not serialized:
        raise ImportFailure("LLVM could not serialize verified module for blind-field audit", "bitcode-audit")
    try:
        try:
            return audit_bitcode(C.string_at(a.GetBufferStart(serialized), a.GetBufferSize(serialized)))
        except BitcodeFailure as error:
            raise ImportFailure(str(error), "bitcode-audit") from error
    finally:
        a.DisposeMemoryBuffer(serialized)


def metadata_references_any(a, context, module, candidates):
    """Include metadata uses, which LLVMGetFirstUse does not enumerate."""
    pending, visited = [], set()

    def attachments(value, global_value=False):
        count = S()
        entries = (a.GlobalCopyAllMetadata if global_value else
                   a.InstructionGetAllMetadataOtherThanDebugLoc)(value, C.byref(count))
        try:
            for index in range(count.value):
                metadata = a.ValueMetadataEntriesGetMetadata(entries, index)
                if metadata:
                    pending.append(a.MetadataAsValue(context, metadata))
        finally:
            if entries:
                a.DisposeValueMetadataEntries(entries)

    for node in a.sequence(a.GetFirstNamedMetadata, a.GetNextNamedMetadata, module):
        name = a.string(a.GetNamedMetadataName, node).encode()
        values = (P * a.GetNamedMetadataNumOperands(module, name))()
        a.GetNamedMetadataOperands(module, name, values)
        pending.extend(values)
    for global_ in a.sequence(a.GetFirstGlobal, a.GetNextGlobal, module):
        attachments(global_, True)
    debug_kind = a.GetMDKindIDInContext(context, b"dbg", 3)
    for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
        attachments(function, True)
        for block in a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function):
            for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                attachments(instruction)
                pending.append(a.GetMetadata(instruction, debug_kind))
                for index in range(a.GetNumOperands(instruction)):
                    operand = a.GetOperand(instruction, index)
                    if operand and a.GetTypeKind(a.TypeOf(operand)) == 14:
                        pending.append(operand)
    while pending:
        value = pending.pop()
        if not value:
            continue
        if value in candidates:
            return True
        if value in visited:
            continue
        visited.add(value)
        # LLVM22's getters also expose the underlying ValueAsMetadata operand.
        if a.IsAMDNode(value):
            values = (P * a.GetMDNodeNumOperands(value))()
            a.GetMDNodeOperands(value, values)
            pending.extend(values)
    return False


def normalize_legacy_lifetime_artifacts(a, context, module, audit):
    """Remove only the unused declarations left by LLVM22's legacy upgrade bug.

    LLVM PR204601 (https://github.com/llvm/llvm-project/pull/204601) fixes
    the old (i64 size, ptr) upgrade choosing the size's
    type for an unused declaration, while actual calls become canonical p0.
    This is not admission of lifetime.i64 calls or arbitrary malformed IR.
    Audit the original parsed module first so deletion cannot hide blind fields.
    """
    kinds = (("start", 219), ("end", 218))
    candidates = {kind: a.GetNamedFunction(module, f"llvm.lifetime.{kind}.i64".encode())
                  for kind, _ in kinds}
    if not any(candidates.values()):
        return []
    functions = list(a.sequence(a.GetFirstFunction, a.GetNextFunction, module))
    if len(functions) != len(audit["function_alignments"]):
        raise ImportFailure("LLVM bitcode alignment audit and C API symbol inventories disagree", "bitcode-audit")
    alignments = dict(zip(functions, audit["function_alignments"]))
    by_name = {a.name(value): value for value in functions}
    removed = []
    for kind, intrinsic_id in kinds:
        name = f"llvm.lifetime.{kind}.i64"
        value = candidates[kind]
        if not value:
            continue
        canonical = by_name.get(f"llvm.lifetime.{kind}.p0")

        def parameter(function, expected_kind):
            ty = a.GlobalGetValueType(function)
            if (a.CountParamTypes(ty) != 1 or a.IsFunctionVarArg(ty)
                    or a.GetTypeKind(a.GetReturnType(ty)) != 0):
                return False
            params = (P * 1)()
            a.GetParamTypes(ty, params)
            return (a.GetTypeKind(params[0]) == expected_kind
                    and (a.GetIntTypeWidth(params[0]) == 64 if expected_kind == 8
                         else a.GetPointerAddressSpace(params[0]) == 0))

        count = S()
        metadata = a.GlobalCopyAllMetadata(value, C.byref(count))
        a.DisposeValueMetadataEntries(metadata)
        if (not canonical or not parameter(value, 8) or not parameter(canonical, 12)
                or a.GetIntrinsicID(value) != intrinsic_id
                or a.GetIntrinsicID(canonical) != intrinsic_id
                or a.GetFirstUse(value) or a.GetFirstBasicBlock(value)
                or a.GetFirstBasicBlock(canonical) or a.GetFunctionCallConv(canonical)
                or a.GetLinkage(canonical) or a.GetVisibility(canonical)
                or a.GetPointerAddressSpace(a.TypeOf(canonical))
                or a.GetFunctionCallConv(value) or a.GetLinkage(value) or a.GetVisibility(value)
                or a.GetPointerAddressSpace(a.TypeOf(value)) or alignments[value]
                or a.GetDLLStorageClass(value) or a.GetSection(value) or a.GetComdat(value)
                or a.GetUnnamedAddress(value) or a.GetGC(value) or a.HasPersonalityFn(value)
                or a.HasPrefixData(value) or a.HasPrologueData(value) or count.value
                or any(a.GetAttributeCountAtIndex(value, index) for index in (0xffffffff, 0, 1))):
            raise ImportFailure("legacy lifetime upgrade artifact requires an unused unannotated external void(i64) declaration and its canonical void(ptr AS0) counterpart", symbol=name)
        removed.append((name, value))
    if removed and metadata_references_any(a, context, module, {value for _, value in removed}):
        raise ImportFailure("legacy lifetime upgrade artifact has metadata references")
    for _, value in removed:
        a.DeleteFunction(value)
    return [(functions.index(value), f"{name}: removed exact unused void(i64) declaration left by pinned LLVM22 legacy lifetime auto-upgrade (LLVM PR204601); canonical pointer lifetime calls and original input_sha256 retained; complete module audited before and after normalization")
            for name, value in removed]


def import_module(path, library_path=None, *, expected_sha256=PINNED_SHA256,
                  frontend="LLVM IR", frontend_version="producer version not declared", tls_profile=None,
                  atomic_profile=None):
    """Return a fully traversed supported module; reject unsupported whole units."""
    path = Path(path)
    data = path.read_bytes()
    a = LLVM(Path(library_path) if library_path else discover_library(), expected_sha256)
    context, module, buffer = a.ContextCreate(), P(), None
    try:
        buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), os.fsencode(path))
        message = P()
        if a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(message)):
            detail = C.string_at(message).decode(errors="replace") if message else "LLVM parse failed"
            if message:
                a.DisposeMessage(message)
            raise ImportFailure(detail, "parse")
        preflight_scoped_alias_metadata(a, context, module)
        message = P()
        invalid = a.VerifyModule(module, 2, C.byref(message))  # LLVMReturnStatusAction
        detail = C.string_at(message).decode(errors="replace") if message else ""
        if message:
            a.DisposeMessage(message)
        if invalid:
            raise ImportFailure(detail or "LLVM verification failed", "llvm-verify")
        importer = Importer(a, context, module, tls_profile=tls_profile, atomic_profile=atomic_profile)
        importer.module_metadata()
        importer.check_target_profile()
        audit = audit_verified_module(a, module)
        normalized = normalize_legacy_lifetime_artifacts(a, context, module, audit)
        if normalized:
            removed_indices = {index for index, _ in normalized}
            importer.refinements.update(note for _, note in normalized)
            original_audit, audit = audit, audit_verified_module(a, module)
            if (original_audit["function_count"] != audit["function_count"] + len(normalized)
                    or any(original_audit[key] != audit[key] for key in
                           ("dso_local_count", "global_count", "global_alignments", "global_comdat_ids",
                            "alias_count", "comdat_count", "comdat_contracts"))
                    or any([value for index, value in enumerate(original_audit[key])
                            if index not in removed_indices] != audit[key]
                           for key in ("function_alignments", "function_comdat_ids"))):
                raise ImportFailure("legacy lifetime normalization changed additional audited symbol contracts")
        if ((audit["triple"] or "") != (a.GetTarget(module) or b"").decode()
                or (audit["data_layout"] or "") != (a.GetDataLayoutStr(module) or b"").decode()):
            raise ImportFailure("LLVM bitcode audit and C API target strings disagree", "bitcode-audit")
        for first, next_value, alignments in (
                (a.GetFirstGlobal, a.GetNextGlobal, audit["global_alignments"]),
                (a.GetFirstFunction, a.GetNextFunction, audit["function_alignments"])):
            symbols = list(a.sequence(first, next_value, module))
            if len(symbols) != len(alignments):
                raise ImportFailure("LLVM bitcode alignment audit and C API symbol inventories disagree", "bitcode-audit")
            importer.symbol_alignments.update(zip(symbols, alignments))
        aliases = list(a.sequence(a.GetFirstGlobalAlias, a.GetNextGlobalAlias, module))
        if len(aliases) != audit["alias_count"] or len(aliases) != len(audit["alias_contracts"]):
            raise ImportFailure("LLVM bitcode alias audit and C API inventories disagree", "bitcode-audit")
        importer.alias_contracts.update(zip(aliases, audit["alias_contracts"]))
        importer.bind_comdats(audit)
        importer.bind_atomic_sync_scopes(audit)
        if audit["dso_local_count"]:
            importer.refinements.add("dso_local symbol constraints retained by the required static, non-preemptive native linkage profile; dynamic ELF preemption is unsupported")
        result = importer.run(hashlib.sha256(data).hexdigest(), frontend, frontend_version)
        if (audit["function_count"] != len(result["functions"]) or audit["global_count"] != len(result["globals"])
                or audit["alias_count"] != len(result["aliases"])
                or audit["comdat_count"] != len(result["comdats"])):
            raise ImportFailure("LLVM bitcode audit and C API inventories disagree", "bitcode-audit")
        return result
    finally:
        if module:
            a.DisposeModule(module)
        if buffer:
            a.DisposeMemoryBuffer(buffer)  # ParseIRInContext2 borrows this buffer.
        a.ContextDispose(context)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", "-o", type=Path)
    parser.add_argument("--llvm-library", type=Path)
    parser.add_argument("--llvm-sha256", default=PINNED_SHA256)
    parser.add_argument("--frontend", default="LLVM IR")
    parser.add_argument("--frontend-version", default="producer version not declared")
    parser.add_argument("--tls-profile")
    parser.add_argument("--atomic-profile")
    args = parser.parse_args()
    try:
        module = import_module(args.input, args.llvm_library, expected_sha256=args.llvm_sha256,
                               frontend=args.frontend, frontend_version=args.frontend_version,
                               tls_profile=args.tls_profile, atomic_profile=args.atomic_profile)
        encoded = json.dumps(module, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            # Publish only after the entire input has been successfully traversed.
            with tempfile.NamedTemporaryFile("w", dir=args.output.parent, delete=False, encoding="utf-8") as stream:
                temporary = Path(stream.name)
                stream.write(encoded)
            try:
                temporary.replace(args.output)
            finally:
                temporary.unlink(missing_ok=True)
        else:
            sys.stdout.write(encoded)
        return 0
    except (ImportFailure, OSError, ValueError) as error:
        failure = {"stage": getattr(error, "stage", "io"), "symbol": getattr(error, "symbol", ""), "message": str(error)}
        print(json.dumps({"error": failure}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
