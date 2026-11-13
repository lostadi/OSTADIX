"""Independent LLVM22 unit inventory for native compiler test evidence.

This uses LLVM's C API directly, not the production importer's inventory or
initializer encoder. It checks source interfaces and static data. It does not
prove executable instruction equivalence or resolve external providers.
"""

from collections import Counter
import ctypes as c
import hashlib
import json
import re
from pathlib import Path


class InventoryMismatch(AssertionError):
    pass


def artifact(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class Reader:
    def __init__(self, library, expected_sha256):
        self.library = artifact(library)
        if self.library["sha256"] != expected_sha256:
            raise InventoryMismatch("independent inventory LLVM library pin mismatch")
        self.dll = c.CDLL(str(library))
        P, U, Z, Q = c.c_void_p, c.c_uint, c.c_size_t, c.c_ulonglong
        declarations = {
            "ContextCreate": (P, []), "ContextDispose": (None, [P]),
            "GetVersion": (None, [c.POINTER(U), c.POINTER(U), c.POINTER(U)]),
            "CreateMemoryBufferWithMemoryRangeCopy": (P, [c.c_char_p, Z, c.c_char_p]),
            "ParseIRInContext": (c.c_int, [P, P, c.POINTER(P), c.POINTER(P)]),
            "VerifyModule": (c.c_int, [P, c.c_int, c.POINTER(P)]),
            "DisposeModule": (None, [P]), "DisposeMessage": (None, [P]),
            "GetDataLayoutStr": (c.c_char_p, [P]), "GetTarget": (c.c_char_p, [P]),
            "CreateTargetData": (P, [c.c_char_p]),
            "DisposeTargetData": (None, [P]), "ABISizeOfType": (Q, [P, P]),
            "StoreSizeOfType": (Q, [P, P]), "OffsetOfElement": (Q, [P, P, U]),
            "GetValueName2": (P, [P, c.POINTER(Z)]), "PrintValueToString": (P, [P]),
            "GetTypeKind": (c.c_int, [P]), "TypeOf": (P, [P]),
            "GlobalGetValueType": (P, [P]), "GetIntTypeWidth": (U, [P]),
            "GetPointerAddressSpace": (U, [P]), "GetElementType": (P, [P]),
            "GetArrayLength2": (Q, [P]), "GetVectorSize": (U, [P]), "CountStructElementTypes": (U, [P]),
            "GetStructElementTypes": (None, [P, c.POINTER(P)]), "IsPackedStruct": (c.c_int, [P]),
            "IsOpaqueStruct": (c.c_int, [P]), "GetStructName": (c.c_char_p, [P]),
            "CountParamTypes": (U, [P]), "GetParamTypes": (None, [P, c.POINTER(P)]),
            "GetReturnType": (P, [P]), "IsFunctionVarArg": (c.c_int, [P]),
            "GetFirstFunction": (P, [P]), "GetNextFunction": (P, [P]),
            "GetFirstGlobal": (P, [P]), "GetNextGlobal": (P, [P]),
            "GetFirstGlobalAlias": (P, [P]), "GetNextGlobalAlias": (P, [P]),
            "AliasGetAliasee": (P, [P]), "GetInitializer": (P, [P]),
            "GetFirstBasicBlock": (P, [P]), "GetNextBasicBlock": (P, [P]),
            "GetBasicBlockParent": (P, [P]), "ValueAsBasicBlock": (P, [P]),
            "ValueIsBasicBlock": (c.c_int, [P]),
            "GetNumSuccessors": (U, [P]), "GetSuccessor": (P, [P, U]),
            "CountIncoming": (U, [P]), "GetIncomingBlock": (P, [P, U]),
            "GetIncomingValue": (P, [P, U]),
            "GetFirstInstruction": (P, [P]), "GetNextInstruction": (P, [P]),
            "GetInstructionOpcode": (U, [P]), "GetCalledValue": (P, [P]),
            "IsAInlineAsm": (P, [P]),
            "GetInlineAsmAsmString": (P, [P, c.POINTER(Z)]),
            "GetInlineAsmConstraintString": (P, [P, c.POINTER(Z)]),
            "GetInlineAsmDialect": (U, [P]),
            "GetInlineAsmFunctionType": (P, [P]),
            "GetInlineAsmHasSideEffects": (c.c_int, [P]),
            "GetInlineAsmNeedsAlignedStack": (c.c_int, [P]),
            "GetInlineAsmCanUnwind": (c.c_int, [P]),
            "GetTailCallKind": (U, [P]),
            "ConstIntGetZExtValue": (Q, [P]),
            "GetCalledFunctionType": (P, [P]), "GetInstructionCallConv": (U, [P]),
            "GetMDKindIDInContext": (U, [P, c.c_char_p, U]),
            "GetMetadata": (P, [P, U]), "IsAMDNode": (P, [P]),
            "GetMDNodeNumOperands": (U, [P]),
            "InstructionGetAllMetadataOtherThanDebugLoc": (P, [P, c.POINTER(Z)]),
            "ValueMetadataEntriesGetKind": (U, [P, U]),
            "ValueMetadataEntriesGetMetadata": (P, [P, U]),
            "DisposeValueMetadataEntries": (None, [P]),
            "MetadataAsValue": (P, [P, P]), "ValueAsMetadata": (P, [P]),
            "GetMetadataKind": (U, [P]), "GetMDString": (P, [P, c.POINTER(U)]),
            "LookupIntrinsicID": (U, [c.c_char_p, Z]),
            "MDNodeInContext2": (P, [P, c.POINTER(P), Z]),
            "GetMDNodeOperands": (None, [P, c.POINTER(P)]),
            "GetIntrinsicID": (U, [P]), "GetFunctionCallConv": (U, [P]),
            "GetAttributeCountAtIndex": (U, [P, U]),
            "GetAttributesAtIndex": (None, [P, U, c.POINTER(P)]),
            "IsStringAttribute": (c.c_int, [P]),
            "IsTypeAttribute": (c.c_int, [P]),
            "GetStringAttributeKind": (P, [P, c.POINTER(U)]),
            "GetStringAttributeValue": (P, [P, c.POINTER(U)]),
            "HasPersonalityFn": (c.c_int, [P]), "GetPersonalityFn": (P, [P]),
            "CountParams": (U, [P]), "GetParams": (None, [P, c.POINTER(P)]),
            "GetNumArgOperands": (U, [P]), "GetNumOperandBundles": (U, [P]), "GetFastMathFlags": (U, [P]),
            "GetICmpPredicate": (U, [P]), "GetNUW": (c.c_int, [P]),
            "GetNSW": (c.c_int, [P]), "GetExact": (c.c_int, [P]),
            "GetIsDisjoint": (c.c_int, [P]), "GetVolatile": (c.c_int, [P]),
            "GetNumIndices": (U, [P]), "GetIndices": (c.POINTER(U), [P]),
            "GetCallSiteAttributeCount": (U, [P, U]),
            "GetCallSiteAttributes": (None, [P, U, c.POINTER(P)]),
            "CreateConstantRangeAttribute": (P, [P, U, U, c.POINTER(Q), c.POINTER(Q)]),
            "IsEnumAttribute": (c.c_int, [P]), "GetEnumAttributeKind": (U, [P]),
            "GetEnumAttributeValue": (Q, [P]),
            "GetEnumAttributeKindForName": (U, [c.c_char_p, Z]),
            "GetLinkage": (c.c_int, [P]), "GetVisibility": (c.c_int, [P]),
            "GetThreadLocalMode": (c.c_int, [P]),
            "GetAlignment": (U, [P]), "IsGlobalConstant": (c.c_int, [P]),
            "IsThreadLocal": (c.c_int, [P]), "GetOperand": (P, [P, U]),
            "GetNumOperands": (c.c_int, [P]), "GetConstOpcode": (U, [P]),
            "GetGEPSourceElementType": (P, [P]), "GetAggregateElement": (P, [P, U]),
            "IntTypeInContext": (P, [P, U]), "ConstBitCast": (P, [P, P]),
        }
        for name in ("ConstantAggregateZero", "ConstantPointerNull", "UndefValue", "PoisonValue",
                     "ConstantInt", "ConstantExpr", "GlobalVariable", "Function", "GlobalAlias", "BlockAddress", "Instruction"):
            declarations["IsA" + name] = (P, [P])
        for name, (result, arguments) in declarations.items():
            function = getattr(self.dll, "LLVM" + name)
            function.restype, function.argtypes = result, arguments
            setattr(self, name, function)
        version = [U() for _ in range(3)]
        self.GetVersion(*(c.byref(item) for item in version))
        if tuple(item.value for item in version) != (22, 1, 6):
            raise InventoryMismatch("independent inventory requires LLVM22.1.6")

    @staticmethod
    def sequence(first, following, owner):
        value = first(owner)
        while value:
            yield value
            value = following(value)

    def name(self, value):
        length = c.c_size_t()
        pointer = self.GetValueName2(value, c.byref(length))
        return c.string_at(pointer, length.value).decode()

    def printed(self, value):
        pointer = self.PrintValueToString(value)
        try:
            return c.string_at(pointer).decode()
        finally:
            self.DisposeMessage(pointer)

    def integer(self, value):
        text = self.printed(value).split(None, 1)[1]
        return {"true": 1, "false": 0}[text] if text in ("true", "false") else int(text)

    def extension_vectors(self, value, call=False):
        # Independently read both source sites. This is not a proof of other
        # ABI storage attributes, metadata, or arbitrary instruction semantics.
        names = {kind: name for name in ("signext", "zeroext", "noext")
                 if (kind := self.GetEnumAttributeKindForName(name.encode(), len(name)))}
        def at(index):
            count = (self.GetCallSiteAttributeCount if call else self.GetAttributeCountAtIndex)(value, index)
            attrs = (c.c_void_p * count)()
            (self.GetCallSiteAttributes if call else self.GetAttributesAtIndex)(value, index, attrs)
            result = []
            for attr in attrs:
                if self.IsEnumAttribute(attr) and self.GetEnumAttributeKind(attr) in names:
                    if self.GetEnumAttributeValue(attr) != 0:
                        raise InventoryMismatch("malformed source integer extension attribute")
                    result.append(names[self.GetEnumAttributeKind(attr)])
            return sorted(result)
        count = self.GetNumArgOperands(value) if call else self.CountParams(value)
        return {"params": [at(index + 1) for index in range(count)], "result": at(0)}

    def control_effects(self, value, call=False):
        index = 0xffffffff
        count = (self.GetCallSiteAttributeCount if call else self.GetAttributeCountAtIndex)(value, index)
        attrs = (c.c_void_p * count)()
        (self.GetCallSiteAttributes if call else self.GetAttributesAtIndex)(value, index, attrs)
        kind = self.GetEnumAttributeKindForName(b"returns_twice", 13)
        found = False
        for attribute in attrs:
            if self.IsEnumAttribute(attribute) and self.GetEnumAttributeKind(attribute) == kind:
                if self.GetEnumAttributeValue(attribute) != 0:
                    raise InventoryMismatch("malformed source returns_twice effect")
                found = True
        return {"returns_twice": found}

    def strict_fp(self, value, call=False):
        index = 0xffffffff
        count = (self.GetCallSiteAttributeCount if call else self.GetAttributeCountAtIndex)(value, index)
        attributes = (c.c_void_p * count)()
        (self.GetCallSiteAttributes if call else self.GetAttributesAtIndex)(value, index, attributes)
        kind = self.GetEnumAttributeKindForName(b"strictfp", 8)
        found = False
        for attribute in attributes:
            if self.IsEnumAttribute(attribute) and self.GetEnumAttributeKind(attribute) == kind:
                if self.GetEnumAttributeValue(attribute) != 0:
                    raise InventoryMismatch("original strictfp has a nonzero enum value")
                found = True
        return found

    def source_abi_witness(self, function):
        count = self.GetAttributeCountAtIndex(function, 0xffffffff)
        attributes = (c.c_void_p * count)()
        self.GetAttributesAtIndex(function, 0xffffffff, attributes)
        witness = {}
        for attribute in attributes:
            if self.IsStringAttribute(attribute):
                length = c.c_uint()
                pointer = self.GetStringAttributeKind(attribute, c.byref(length))
                key = c.string_at(pointer, length.value).decode()
                if key in {"target-cpu", "target-features"}:
                    field = key.replace("-", "_")
                    if field in witness:
                        raise InventoryMismatch("ambiguous original source ABI witness")
                    pointer = self.GetStringAttributeValue(attribute, c.byref(length))
                    witness[field] = c.string_at(pointer, length.value).decode()
        return witness or None

    def call_return_alignment(self, instruction):
        count = self.GetCallSiteAttributeCount(instruction, 0)
        attributes = (c.c_void_p * count)()
        self.GetCallSiteAttributes(instruction, 0, attributes)
        kind = self.GetEnumAttributeKindForName(b"align", 5)
        alignments = [self.GetEnumAttributeValue(attribute) for attribute in attributes
                      if self.IsEnumAttribute(attribute) and self.GetEnumAttributeKind(attribute) == kind]
        if len(alignments) > 1:
            raise InventoryMismatch("ambiguous original intrinsic return alignment")
        return alignments[0] if alignments else None

    def operand(self, value, values):
        ty = self.shape(self.TypeOf(value))
        if value in values:
            return {"kind": "value", "id": values[value]}
        if self.IsAConstantInt(value):
            return {"kind": "int", "type": ty, "bits": str(self.integer(value) % (1 << ty["bits"]))}
        if self.IsAConstantPointerNull(value):
            return {"kind": "null", "type": ty}
        if self.IsAUndefValue(value) or self.IsAPoisonValue(value):
            # LLVM PoisonValue is also an UndefValue subclass: test the more
            # specific predicate first, preserving the original distinction.
            return {"kind": "poison" if self.IsAPoisonValue(value) else "undef", "type": ty}
        if ty["kind"] in {"struct", "array", "vector"}:
            if self.IsAConstantAggregateZero(value):
                return {"kind": "aggregate_zero", "type": ty}
            llvm_type = self.TypeOf(value)
            if ty["kind"] == "struct":
                children = (c.c_void_p * self.CountStructElementTypes(llvm_type))()
                self.GetStructElementTypes(llvm_type, children)
                children = enumerate(children)
            else:
                element = self.GetElementType(llvm_type)
                children = ((index, element) for index in range(ty["len"]))
            elements = []
            for index, element_type in children:
                if index > 0xffffffff:
                    raise InventoryMismatch("independent aggregate lane index exceeds C API unsigned range")
                lane = self.GetAggregateElement(value, index)
                if not lane or self.TypeOf(lane) != element_type:
                    raise InventoryMismatch("independent aggregate/vector literal requires exact typed lanes")
                elements.append(self.operand(lane, values))
            return {"kind": "aggregate", "type": ty, "elements": elements}
        if self.IsAConstantExpr(value) and self.GetConstOpcode(value) == 39:
            return self.constant_pointer_integer(value, values)
        block = self.code_address(value)
        if block is not None:
            return {"kind": "block_address", "type": ty, **block}
        if self.IsAGlobalVariable(value) or self.IsAFunction(value) or self.IsAGlobalAlias(value):
            return {"kind": "symbol", "name": self.name(value), "type": ty}
        if self.IsAConstantExpr(value) and self.GetConstOpcode(value) in (29, 41):
            name, offset = self.address(value)
            offset = (offset + (1 << 63)) % (1 << 64) - (1 << 63)
            return ({"kind": "symbol", "name": name, "type": ty} if offset == 0 else
                    {"kind": "symbol_offset", "name": name, "type": ty, "addend": offset})
        if self.IsAConstantExpr(value) and self.GetConstOpcode(value) == 40:
            integer = self.GetOperand(value, 0)
            return {"kind": "pointer_bits", "type": ty,
                    "bits": str(self.integer(integer) % (1 << self.GetIntTypeWidth(self.TypeOf(integer))))}
        if ty["kind"] == "float":
            integer = self.ConstBitCast(value, self.IntTypeInContext(self.context, ty["bits"]))
            return {"kind": "float", "type": ty, "bits": str(self.integer(integer) % (1 << ty["bits"]))}
        if ty["kind"] == "metadata":
            result = {"kind": "compiler_metadata", "printed_sha256": hashlib.sha256(self.printed(value).encode()).hexdigest()}
            metadata = self.ValueAsMetadata(value)
            if metadata and self.GetMetadataKind(metadata) == 0:
                length = c.c_uint()
                raw = self.GetMDString(value, c.byref(length))
                if not raw and length.value:
                    raise InventoryMismatch("actual MDString has no byte storage")
                result["mdstring_bytes"] = list(c.string_at(raw, length.value)) if length.value else []
            return result
        raise InventoryMismatch("independent inventory has no intrinsic operand mapping")

    def constant_pointer_integer(self, value, values):
        """Independent actual C API scalar constant conversion reconstruction."""
        if (not self.IsAConstantExpr(value) or self.GetConstOpcode(value) != 39
                or self.GetNumOperands(value) != 1
                or self.GetTypeKind(self.TypeOf(value)) != 8):
            raise InventoryMismatch("constant ptrtoint inventory requires one pointer and integer result")
        width = self.GetIntTypeWidth(self.TypeOf(value))
        if not (1 <= width <= 64 or width == 128):
            raise InventoryMismatch("constant ptrtoint inventory requires a supported integer width")
        child = self.GetOperand(value, 0)
        ty = self.TypeOf(child)
        layout = self.source_data_layout
        if (self.GetTypeKind(ty) != 12 or self.GetPointerAddressSpace(ty) != 0
                or self.ABISizeOfType(self.layout, ty) != 8 or not layout.startswith("e")):
            raise InventoryMismatch("constant ptrtoint inventory requires integral little-endian AS0 64-bit pointers")
        for piece in layout.split("-"):
            if piece.startswith(("p:", "p0:")):
                numbers = piece.split(":")
                if numbers[1] != "64" or (len(numbers) >= 5 and numbers[4] != "64"):
                    raise InventoryMismatch("constant ptrtoint inventory pointer/index width mismatch")
            if piece.startswith("ni:") and "0" in piece.split(":")[1:]:
                raise InventoryMismatch("constant ptrtoint inventory requires integral pointers")
            if piece[:1] in {"A", "P", "G"} and piece[1:] != "0":
                raise InventoryMismatch("constant ptrtoint inventory requires default address spaces")
        return {"kind": "pointer_to_integer", "type": self.shape(self.TypeOf(value)),
                "pointer": self.operand(child, values)}

    def instruction_constant_pointer_integers(self, instruction, values, blocks):
        """Exact typed tree, SSA owner/edge/field path and ordered use sites.

        This primitive proof supplements dependency and full fresh body equality;
        it does not replace the latter with an instruction-count approximation.
        Unknown expression-bearing contexts fail closed rather than omit a site.
        """
        def leaves(value, path):
            if value in values:
                return []
            if self.IsAConstantExpr(value):
                if self.GetConstOpcode(value) == 39:
                    return [{"path": path, "value": self.constant_pointer_integer(value, values)}]
                if any(leaves(self.GetOperand(value, i), []) for i in range(self.GetNumOperands(value))):
                    raise InventoryMismatch("unmapped enclosing constant ptrtoint expression")
                return []
            kind = self.GetTypeKind(self.TypeOf(value))
            if kind in (10, 11, 13) and not (self.IsAConstantAggregateZero(value)
                    or self.IsAUndefValue(value) or self.IsAPoisonValue(value)):
                ty = self.TypeOf(value)
                count = self.CountStructElementTypes(ty) if kind == 10 else (self.GetVectorSize(ty) if kind == 13 else self.GetArrayLength2(ty))
                output = []
                for index in range(count):
                    if index > 0xffffffff:
                        raise InventoryMismatch("constant ptrtoint aggregate C API index overflow")
                    item = self.GetAggregateElement(value, index)
                    if not item:
                        raise InventoryMismatch("constant ptrtoint aggregate element absent")
                    found = leaves(item, path + ["elements", index])
                    if kind == 13 and found:
                        raise InventoryMismatch("symbolic constant ptrtoint packed-vector lanes are unsupported")
                    output.extend(found)
                return output
            return []
        direct = [leaves(self.GetOperand(instruction, i), []) for i in range(self.GetNumOperands(instruction))]
        if not any(direct):
            return None
        opcode = self.GetInstructionOpcode(instruction)
        fields = {1: ("return", ["value"]), 3: ("switch", ["value"]),
                  27: ("load", ["pointer"]), 28: ("store", ["value", "pointer"]),
                  29: ("gep", ["base"]), 42: ("i_cmp", ["lhs", "rhs"]),
                  46: ("select", ["condition", "on_true", "on_false"]),
                  53: ("extract_value", ["aggregate"]), 54: ("insert_value", ["aggregate", "value"]),
                  68: ("freeze", ["value"])}
        if opcode == 2 and self.GetNumSuccessors(instruction) == 2:
            fields[2] = ("branch", ["condition"])
        if opcode in (8, 10, 12, 14, 15, 17, 18, 20, 21, 22, 23, 24, 25):
            fields[opcode] = ("binary", ["lhs", "rhs"])
        if opcode in (30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 60):
            fields[opcode] = ("cast", ["value"])
        if opcode == 44:
            found, predecessors = [], {}
            for index in range(self.CountIncoming(instruction)):
                block = blocks.index(self.GetIncomingBlock(instruction, index))
                if block not in predecessors:
                    predecessors[block] = len(predecessors)
                    found.extend(leaves(self.GetIncomingValue(instruction, index), ["incoming", predecessors[block], "value"]))
            return "phi", found
        if opcode in (5, 45):
            callee = self.GetCalledValue(instruction)
            if self.IsAFunction(callee) and self.GetIntrinsicID(callee):
                raise InventoryMismatch("constant ptrtoint intrinsic-graph arguments require a separate exact mapping")
            if self.IsAInlineAsm(callee):
                if opcode != 45:
                    raise InventoryMismatch("constant ptrtoint InlineAsm only supports owned raw call")
                found = leaves(self.GetOperand(instruction, 0), ["number"])
                for index in range(1, self.GetNumArgOperands(instruction)):
                    found.extend(leaves(self.GetOperand(instruction, index), ["arguments", index-1]))
                return "linux_syscall", found
            found = leaves(callee, ["callee"])
            for index in range(self.GetNumArgOperands(instruction)):
                found.extend(leaves(self.GetOperand(instruction, index), ["args", index]))
            return ("invoke" if opcode == 5 else "call"), found
        if opcode not in fields:
            raise InventoryMismatch(f"unmapped constant ptrtoint instruction context {opcode}")
        operation, names = fields[opcode]
        found = []
        for index, group in enumerate(direct):
            if group:
                if index >= len(names):
                    raise InventoryMismatch("unmapped constant ptrtoint operand role")
                found.extend({"path": [names[index], *item["path"]], "value": item["value"]} for item in group)
        return operation, found

    def contract(self, value):
        # The producer/core already admit this exact public LLVM linkage only
        # on optional declarations. Keep original linkage, type, storage and
        # visibility; do not confuse it with a weak definition or a provider.
        actual_linkage = self.GetLinkage(value)
        if actual_linkage == 12:
            declaration = ((self.IsAFunction(value) and not self.GetFirstBasicBlock(value)
                            and not self.GetIntrinsicID(value) and not self.name(value).startswith("llvm."))
                           or (self.IsAGlobalVariable(value) and not self.GetInitializer(value)
                               and not self.IsThreadLocal(value)))
            if not declaration:
                raise InventoryMismatch("extern_weak source inventory requires an ordinary nonTLS declaration")
        linkage = {0: "external", 2: "linkonce", 3: "linkonce_odr", 5: "weak", 6: "weak_odr", 8: "internal", 9: "private", 12: "extern_weak"}
        visibility = {0: "default", 1: "hidden", 2: "protected"}
        return {"linkage": linkage.get(actual_linkage, "unsupported"),
                "visibility": visibility.get(self.GetVisibility(value), "unsupported"),
                "alignment": 0 if self.IsAGlobalAlias(value) else self.GetAlignment(value)}

    def shape(self, ty):
        kind = self.GetTypeKind(ty)
        if kind in (0, 14):
            return {"kind": "void" if kind == 0 else "metadata"}
        if kind == 8:
            return {"kind": "int", "bits": self.GetIntTypeWidth(ty)}
        if kind in (2, 3, 4, 5):
            return {"kind": "float", "bits": {2: 32, 3: 64, 4: 80, 5: 128}[kind]}
        if kind == 12:
            return {"kind": "pointer", "address_space": self.GetPointerAddressSpace(ty)}
        if kind == 13:
            return {"kind": "vector", "len": self.GetVectorSize(ty), "element": self.shape(self.GetElementType(ty))}
        if kind == 11:
            return {"kind": "array", "len": self.GetArrayLength2(ty), "element": self.shape(self.GetElementType(ty))}
        if kind == 10:
            if self.IsOpaqueStruct(ty):
                name = self.GetStructName(ty)
                return {"kind": "opaque_struct", "name": name.decode() if name else None}
            fields = (c.c_void_p * self.CountStructElementTypes(ty))()
            self.GetStructElementTypes(ty, fields)
            return {"kind": "struct", "packed": bool(self.IsPackedStruct(ty)), "fields": [self.shape(x) for x in fields]}
        if kind == 9:
            params = (c.c_void_p * self.CountParamTypes(ty))()
            self.GetParamTypes(ty, params)
            return {"kind": "function", "params": [self.shape(x) for x in params],
                    "result": self.shape(self.GetReturnType(ty)), "variadic": bool(self.IsFunctionVarArg(ty))}
        raise InventoryMismatch(f"independent inventory has no type mapping for LLVM kind {kind}")

    def address_root(self, value):
        offset = 0
        while self.IsAConstantExpr(value):
            opcode = self.GetConstOpcode(value)
            if opcode == 41:
                value = self.GetOperand(value, 0)
                continue
            if opcode != 29:
                raise InventoryMismatch("unmapped source symbolic initializer expression")
            ty = self.GetGEPSourceElementType(value)
            for index in range(1, self.GetNumOperands(value)):
                number = self.integer(self.GetOperand(value, index))
                if index == 1:
                    offset += number * self.ABISizeOfType(self.layout, ty)
                elif self.GetTypeKind(ty) == 10:
                    fields = (c.c_void_p * self.CountStructElementTypes(ty))()
                    self.GetStructElementTypes(ty, fields)
                    offset += self.OffsetOfElement(self.layout, ty, number)
                    ty = fields[number]
                else:
                    ty = self.GetElementType(ty)
                    offset += number * self.ABISizeOfType(self.layout, ty)
            value = self.GetOperand(value, 0)
        return value, offset

    def code_address(self, value):
        # Resolve original LLVM objects independently of production block IDs.
        # No printed label parsing and no source numeric-address assumptions.
        root, offset = self.address_root(value) if self.IsAConstantExpr(value) and self.GetConstOpcode(value) in (29, 41) else (value, 0)
        if not self.IsABlockAddress(root):
            return None
        if self.GetNumOperands(root) != 1:
            raise InventoryMismatch("invalid original blockaddress arity")
        label = self.GetOperand(root, 0)
        if not self.ValueIsBasicBlock(label):
            raise InventoryMismatch("invalid original blockaddress identity")
        block = self.ValueAsBasicBlock(label)
        owner = self.GetBasicBlockParent(block)
        if not owner or not self.IsAFunction(owner):
            raise InventoryMismatch("invalid original blockaddress parent")
        blocks = list(self.sequence(self.GetFirstBasicBlock, self.GetNextBasicBlock, owner))
        if self.GetBasicBlockParent(block) != owner or block not in blocks or block == blocks[0]:
            raise InventoryMismatch("invalid original blockaddress owner/entry")
        return {"function": self.name(owner), "block": blocks.index(block),
                "addend": (offset + (1 << 63)) % (1 << 64) - (1 << 63)}

    def address(self, value):
        value, offset = self.address_root(value)
        if not (self.IsAGlobalVariable(value) or self.IsAFunction(value) or self.IsAGlobalAlias(value)):
            raise InventoryMismatch("unmapped source relocation base")
        return self.name(value), offset

    def initializer(self, value, ty):
        data = bytearray(self.ABISizeOfType(self.layout, ty))
        relocations, refinements = [], []
        pending = [(value, ty, 0)]
        while pending:
            value, ty, offset = pending.pop()
            if self.IsAConstantAggregateZero(value) or self.IsAConstantPointerNull(value):
                continue
            if self.IsAUndefValue(value) or self.IsAPoisonValue(value):
                refinements.append({"offset": offset, "size": self.ABISizeOfType(self.layout, ty),
                                    "mapping": "explicit LLVM-defined-behavior zero refinement"})
                continue
            kind, size = self.GetTypeKind(ty), self.StoreSizeOfType(self.layout, ty)
            if kind in (2, 3, 4, 5):
                bits = {2: 32, 3: 64, 4: 80, 5: 128}[kind]
                integer = self.ConstBitCast(value, self.IntTypeInContext(self.context, bits))
                data[offset:offset+size] = (self.integer(integer) % (1 << bits)).to_bytes(size, "little")
            elif kind == 8 and self.IsAConstantInt(value):
                data[offset:offset+size] = (self.integer(value) % (1 << self.GetIntTypeWidth(ty))).to_bytes(size, "little")
            elif kind == 12:
                if self.IsAConstantExpr(value) and self.GetConstOpcode(value) == 40:
                    integer = self.GetOperand(value, 0)
                    bits = self.GetIntTypeWidth(self.TypeOf(integer))
                    data[offset:offset+size] = (self.integer(integer) % (1 << bits)).to_bytes(size, "little")
                else:
                    block = self.code_address(value)
                    if block is not None:
                        relocations.append({"offset": offset, "width": size*8, "symbol": "",
                                            "addend": block["addend"], "relative_to": None,
                                            "block": {key: block[key] for key in ("function", "block")}})
                    else:
                        symbol, addend = self.address(value)
                        relocations.append({"offset": offset, "width": size*8, "symbol": symbol,
                                            "addend": addend, "relative_to": None})
            elif kind == 8 and self.IsAConstantExpr(value):
                expression = value
                if self.GetConstOpcode(expression) != 30:
                    raise InventoryMismatch("unmapped integer relocation expression")
                expression = self.GetOperand(expression, 0)
                if self.GetConstOpcode(expression) != 10:
                    raise InventoryMismatch("unmapped relative relocation expression")
                operands = [self.GetOperand(expression, i) for i in (0, 1)]
                if any(not self.IsAConstantExpr(x) or self.GetConstOpcode(x) != 39 for x in operands):
                    raise InventoryMismatch("unmapped relative relocation operands")
                (symbol, addend), (base, base_addend) = [self.address(self.GetOperand(x, 0)) for x in operands]
                relocations.append({"offset": offset, "width": self.GetIntTypeWidth(ty), "symbol": symbol,
                                    "addend": addend-base_addend, "relative_to": base})
            elif kind == 13:
                element = self.GetElementType(ty)
                if self.GetTypeKind(element) != 8:
                    raise InventoryMismatch("independent fixed vector initializer requires integer elements")
                width, packed = self.GetIntTypeWidth(element), 0
                for index in range(self.GetVectorSize(ty)):
                    lane = self.GetAggregateElement(value, index)
                    if not lane or self.TypeOf(lane) != element:
                        raise InventoryMismatch("independent vector initializer lane type differs")
                    if self.IsAPoisonValue(lane) or self.IsAUndefValue(lane):
                        refinements.append({"bit_offset": offset*8+index*width, "bits": width,
                                            "mapping": "explicit per-lane LLVM-defined-behavior zero refinement"})
                    elif self.IsAConstantInt(lane):
                        packed |= (self.integer(lane) % (1 << width)) << (index*width)
                    else:
                        raise InventoryMismatch("independent vector initializer has unmapped lane")
                data[offset:offset+size] = packed.to_bytes(size, "little")
            elif kind in (10, 11):
                if kind == 10:
                    fields = (c.c_void_p * self.CountStructElementTypes(ty))()
                    self.GetStructElementTypes(ty, fields)
                    children = [(field, self.OffsetOfElement(self.layout, ty, index)) for index, field in enumerate(fields)]
                else:
                    element = self.GetElementType(ty)
                    children = ((element, index*self.ABISizeOfType(self.layout, element)) for index in range(self.GetArrayLength2(ty)))
                for index, (field, position) in enumerate(children):
                    item = self.GetAggregateElement(value, index)
                    if not item:
                        raise InventoryMismatch("unmapped source aggregate initializer element")
                    pending.append((item, field, offset+position))
            else:
                raise InventoryMismatch("unmapped source initializer kind")
        return {"bytes": list(data), "relocations": sorted(relocations, key=lambda r: r["offset"])}, refinements

    def instruction_code_addresses(self, instruction, values, blocks):
        """Retain the semantic operand position, not just its owner dependency.

        Unknown address-bearing instruction forms fail closed. This supplements
        static inventory and does not claim equivalence for other instructions.
        """
        opcode = self.GetInstructionOpcode(instruction)

        def leaves(value, path):
            if value in values:
                return []
            address = self.code_address(value)
            if address is not None:
                return [{"path": path, "value": {"kind": "block_address",
                         "type": self.shape(self.TypeOf(value)), **address}}]
            if self.IsAConstantExpr(value) and self.GetConstOpcode(value) == 39:
                return leaves(self.GetOperand(value, 0), path + ["pointer"])
            if self.IsAConstantExpr(value):
                nested = [leaf for index in range(self.GetNumOperands(value))
                          for leaf in leaves(self.GetOperand(value, index), [])]
                if nested:
                    raise InventoryMismatch("unmapped block-address constant expression")
            kind = self.GetTypeKind(self.TypeOf(value))
            if kind in (10, 11) and not (self.IsAConstantAggregateZero(value)
                    or self.IsAUndefValue(value) or self.IsAPoisonValue(value)):
                ty = self.TypeOf(value)
                count = self.CountStructElementTypes(ty) if kind == 10 else self.GetArrayLength2(ty)
                output = []
                for index in range(count):
                    element = self.GetAggregateElement(value, index)
                    if not element:
                        raise InventoryMismatch("unmapped aggregate code-address operand")
                    output.extend(leaves(element, path + ["elements", index]))
                return output
            return []

        direct = [leaves(self.GetOperand(instruction, index), [])
                  for index in range(self.GetNumOperands(instruction))]
        if not any(direct):
            return []
        fields = {1: ("return", ["value"]), 4: ("indirect_branch", ["address"]),
                  27: ("load", ["pointer"]), 28: ("store", ["value", "pointer"]),
                  29: ("gep", ["base"]), 42: ("i_cmp", ["lhs", "rhs"]),
                  46: ("select", ["condition", "on_true", "on_false"]),
                  68: ("freeze", ["value"])}
        if opcode == 2 and self.GetNumSuccessors(instruction) == 2:
            fields[2] = ("branch", ["condition"])
        if opcode in (8, 10, 12, 14, 15, 17, 18, 20, 21, 22, 23, 24, 25):
            fields[opcode] = ("binary", ["lhs", "rhs"])
        if opcode in (30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 60):
            fields[opcode] = ("cast", ["value"])
        if opcode == 44:
            addresses, seen = [], {}
            for index in range(self.CountIncoming(instruction)):
                block = blocks.index(self.GetIncomingBlock(instruction, index))
                value = self.GetIncomingValue(instruction, index)
                if block not in seen:
                    seen[block] = len(seen)
                    addresses.extend(leaves(value, ["incoming", seen[block], "value"]))
            return "phi", addresses
        if opcode in (5, 45):
            callee = self.GetCalledValue(instruction)
            if self.IsAInlineAsm(callee):
                if opcode != 45:
                    raise InventoryMismatch("unmapped block-address InlineAsm context")
                addresses = leaves(self.GetOperand(instruction, 0), ["number"])
                for index in range(1, self.GetNumArgOperands(instruction)):
                    addresses.extend(leaves(self.GetOperand(instruction, index), ["arguments", index-1]))
                return "linux_syscall", addresses
            addresses = leaves(callee, ["callee"])
            for index in range(self.GetNumArgOperands(instruction)):
                addresses.extend(leaves(self.GetOperand(instruction, index), ["args", index]))
            return ("invoke" if opcode == 5 else "call"), addresses
        if opcode not in fields:
            raise InventoryMismatch(f"unmapped code-address instruction opcode {opcode}")
        operation, names = fields[opcode]
        addresses = []
        for index, group in enumerate(direct):
            if group:
                if index >= len(names):
                    raise InventoryMismatch("unmapped code-address operand position")
                addresses.extend({"path": [names[index], *item["path"]], "value": item["value"]}
                                 for item in group)
        return operation, addresses

    def has_vector(self, ty):
        kind = self.GetTypeKind(ty)
        if kind == 13:
            return True
        if kind == 11:
            return self.has_vector(self.GetElementType(ty))
        if kind == 10 and not self.IsOpaqueStruct(ty):
            fields = (c.c_void_p * self.CountStructElementTypes(ty))()
            self.GetStructElementTypes(ty, fields)
            return any(self.has_vector(field) for field in fields)
        return False

    def vector_site(self, instruction, values, blocks, block_id):
        opcode = self.GetInstructionOpcode(instruction)
        operands = [self.GetOperand(instruction, index) for index in range(self.GetNumOperands(instruction))]
        if not (self.has_vector(self.TypeOf(instruction))
                or any(self.has_vector(self.TypeOf(value)) for value in operands)):
            return None
        arg = lambda index: self.operand(operands[index], values)
        binary = {8:"add", 10:"sub", 12:"mul", 14:"u_div", 15:"s_div", 17:"u_rem", 18:"s_rem",
                  20:"shl", 21:"l_shr", 22:"a_shr", 23:"and", 24:"or", 25:"xor"}
        if opcode in binary:
            flags = []
            if opcode in (8,10,12,20):
                flags += [name for name, query in (("nsw", self.GetNSW), ("nuw", self.GetNUW)) if query(instruction)]
            if opcode in (14,15,21,22) and self.GetExact(instruction):
                flags.append("exact")
            if opcode == 24 and self.GetIsDisjoint(instruction):
                flags.append("disjoint")
            operation = {"op":"binary", "kind":binary[opcode], "lhs":arg(0), "rhs":arg(1), "flags":flags}
        elif opcode == 42:
            predicates = dict(zip(range(32,42), ("eq","ne","ugt","uge","ult","ule","sgt","sge","slt","sle")))
            operation = {"op":"i_cmp", "predicate":predicates[self.GetICmpPredicate(instruction)], "lhs":arg(0), "rhs":arg(1)}
        elif opcode in (30,31,32):
            operation = {"op":"cast", "kind":{30:"trunc",31:"z_ext",32:"s_ext"}[opcode], "value":arg(0)}
        elif opcode == 46:
            operation = {"op":"select", "condition":arg(0), "on_true":arg(1), "on_false":arg(2)}
        elif opcode == 68:
            operation = {"op":"freeze", "value":arg(0)}
        elif opcode in (50,51):
            operation = {"op":"extract_element" if opcode == 50 else "insert_element", "vector":arg(0), "index":arg(1 if opcode == 50 else 2)}
            if opcode == 51:
                operation["value"] = arg(1)
        elif opcode in (53,54):
            indices = self.GetIndices(instruction)
            operation = {"op":"extract_value" if opcode == 53 else "insert_value", "aggregate":arg(0),
                         "indices":[int(indices[index]) for index in range(self.GetNumIndices(instruction))]}
            if opcode == 54:
                operation["value"] = arg(1)
        elif opcode == 27:
            operation = {"op":"load", "pointer":arg(0), "alignment":self.GetAlignment(instruction), "volatile":bool(self.GetVolatile(instruction))}
        elif opcode == 28:
            operation = {"op":"store", "pointer":arg(1), "value":arg(0), "alignment":self.GetAlignment(instruction), "volatile":bool(self.GetVolatile(instruction))}
        elif opcode == 44:
            incoming = {}
            for index in range(self.CountIncoming(instruction)):
                block = blocks.index(self.GetIncomingBlock(instruction,index))
                value = self.operand(self.GetIncomingValue(instruction,index),values)
                if block in incoming and incoming[block] != value:
                    raise InventoryMismatch("vector PHI duplicate edge values disagree")
                incoming[block] = value
            operation = {"op":"phi", "incoming":[{"block":block,"value":value} for block,value in incoming.items()]}
        elif opcode == 45:
            callee = self.GetCalledValue(instruction)
            if not (self.IsAFunction(callee) and self.GetIntrinsicID(callee)
                    and re.fullmatch(r"llvm\.vector\.reduce\.add\.v[1-9][0-9]*i(?:1|8|16|32|64)", self.name(callee))):
                raise InventoryMismatch("vector call requires a separately supported source operation inventory")
            operation = {"op":"vector_reduce_add", "value":arg(0)}
        else:
            raise InventoryMismatch(f"unmapped fixed vector source instruction {opcode}")
        return {"block":block_id, "result_id":values.get(instruction),
                "result_type":self.shape(self.TypeOf(instruction)), "operation":operation}

    def linux_syscall_site(self, instruction, callee, function, block, ordinal, values):
        # Independent CAPI inventory. No production recognizer, operation schema
        # classifier, source extractor or code generator is imported here.
        def bytes_(getter):
            count = c.c_size_t()
            value = getter(callee, c.byref(count))
            return list(c.string_at(value, count.value)) if count.value else []
        attributes, constant_ranges = [], []
        names = {self.GetEnumAttributeKindForName(name.encode(), len(name)): name
                 for name in ("nounwind", "strictfp", "noundef")}
        count = self.GetNumArgOperands(instruction)
        for slot in [0, *range(1, count+1), 0xffffffff]:
            number = self.GetCallSiteAttributeCount(instruction, slot)
            entries = (c.c_void_p * number)()
            self.GetCallSiteAttributes(instruction, slot, entries)
            for entry in entries:
                if (not self.IsEnumAttribute(entry) and not self.IsStringAttribute(entry)
                        and not self.IsTypeAttribute(entry)
                        and self.GetEnumAttributeKind(entry) == self.GetEnumAttributeKindForName(b"range", 5)):
                    constant_ranges.append(self.linux_constant_range(instruction, slot, entry))
                    continue
                if not self.IsEnumAttribute(entry) or self.GetEnumAttributeKind(entry) not in names:
                    raise InventoryMismatch("unsupported raw syscall attribute source witness")
                attributes.append({"index":slot, "name":names[self.GetEnumAttributeKind(entry)],
                                   "value":self.GetEnumAttributeValue(entry)})
        attributes.sort(key=lambda item:(item["index"],item["name"]))
        constant_ranges.sort(key=lambda item:item["index"])
        kind = self.GetMDKindIDInContext(self.context, b"srcloc", 6)
        attachment_count = c.c_size_t()
        attachments = self.InstructionGetAllMetadataOtherThanDebugLoc(instruction,c.byref(attachment_count))
        metadata = None
        try:
            for index in range(attachment_count.value):
                if self.ValueMetadataEntriesGetKind(attachments,index) == kind:
                    if metadata is not None:
                        raise InventoryMismatch("duplicate contextual srcloc attachment")
                    metadata = self.ValueMetadataEntriesGetMetadata(attachments,index)
        finally:
            if attachments: self.DisposeValueMetadataEntries(attachments)
        node = self.MetadataAsValue(self.context,metadata) if metadata else None
        location = None
        if node:
            if not self.IsAMDNode(node):
                raise InventoryMismatch("raw syscall srcloc must be an actual tuple")
            entries = (c.c_void_p * self.GetMDNodeNumOperands(node))()
            self.GetMDNodeOperands(node, entries)
            integers = []
            for entry in entries:
                if not entry or not self.IsAConstantInt(entry):
                    raise InventoryMismatch("raw syscall srcloc must contain constant integers")
                width = self.GetIntTypeWidth(self.TypeOf(entry))
                if not 1 <= width <= 64:
                    raise InventoryMismatch("unsupported raw syscall srcloc integer width")
                integers.append({"width":width, "bits":str(self.ConstIntGetZExtValue(entry))})
            if not integers:
                raise InventoryMismatch("empty raw syscall srcloc tuple")
            members = (c.c_void_p * len(entries))(*(self.ValueAsMetadata(entry) for entry in entries))
            storage = "uniqued" if self.MDNodeInContext2(self.context,members,len(entries)) == metadata else "distinct"
            if metadata not in self.platform_locations:
                self.platform_locations[metadata] = len(self.platform_locations)
            location = {"node":self.platform_locations[metadata], "storage":storage, "operands":integers}
        return {"site":{"function":function,"block":block,"source_instruction":ordinal},
                "assembly":bytes_(self.GetInlineAsmAsmString),
                "constraints":bytes_(self.GetInlineAsmConstraintString),
                "side_effects":bool(self.GetInlineAsmHasSideEffects(callee)),
                "align_stack":bool(self.GetInlineAsmNeedsAlignedStack(callee)),
                "dialect":self.GetInlineAsmDialect(callee), "can_unwind":bool(self.GetInlineAsmCanUnwind(callee)),
                "calling_convention":self.GetInstructionCallConv(instruction),
                "tail_kind":self.GetTailCallKind(instruction), "attributes":attributes,"srcloc":location,
                **({"constant_ranges":constant_ranges} if constant_ranges else {}),
                "signature":self.shape(self.GetInlineAsmFunctionType(callee)),
                "extension_attributes":self.extension_vectors(instruction,call=True),
                "args":[self.operand(self.GetOperand(instruction,index),values) for index in range(count)],
                "result_id":values[instruction],"result_type":self.shape(self.TypeOf(instruction))}

    def fp_register_barrier_site(self, instruction, callee, function, block, ordinal, values):
        # Read genuine LLVM objects independently; no production shape predicate.
        number = c.c_size_t()
        attachments = self.InstructionGetAllMetadataOtherThanDebugLoc(instruction, c.byref(number))
        kind = self.GetMDKindIDInContext(self.context, b"srcloc", 6)
        try:
            for index in range(number.value):
                if self.ValueMetadataEntriesGetKind(attachments, index) == kind:
                    if self.GetMetadataKind(self.ValueMetadataEntriesGetMetadata(attachments, index)) != 4:
                        raise InventoryMismatch("FP register barrier srcloc is not an actual MDTuple")
        finally:
            if attachments: self.DisposeValueMetadataEntries(attachments)
        site = self.linux_syscall_site(instruction, callee, function, block, ordinal, values)
        site.update(original_target=self.source_target,
                    fast_math=self.GetFastMathFlags(instruction),
                    operand_bundles=self.GetNumOperandBundles(instruction),
                    call_opcode=self.GetInstructionOpcode(instruction))
        return site

    def linux_constant_range(self, instruction, slot, original):
        """Independent actual-slot identity proof, not a production decoder."""
        count = self.GetNumArgOperands(instruction)
        if slot == 0xffffffff or type(slot) is not int or slot < 0 or slot > count:
            raise InventoryMismatch("source ConstantRange has no result/argument slot")
        ty = self.TypeOf(instruction) if slot == 0 else self.TypeOf(self.GetOperand(instruction, slot - 1))
        if self.GetTypeKind(ty) != 8 or self.GetIntTypeWidth(ty) != 64:
            raise InventoryMismatch("source raw-syscall ConstantRange is not its original i64 slot")
        kind = self.GetEnumAttributeKindForName(b"range", 5)
        if (not kind or self.IsStringAttribute(original) or self.IsTypeAttribute(original)
                or self.IsEnumAttribute(original) or self.GetEnumAttributeKind(original) != kind):
            raise InventoryMismatch("source ConstantRange kind/storage mismatch")
        # Quoted source identifiers and strings cannot contribute candidates.
        text, pieces, start = self.printed(instruction), [], 0
        while start < len(text):
            quote = text.find('"', start)
            if quote < 0:
                pieces.append(text[start:]);break
            pieces.append(text[start:quote]);index = quote + 1
            while index < len(text) and text[index] != '"':
                if text[index] == "\\":
                    if not re.fullmatch(r"[A-Fa-f0-9]{2}", text[index + 1:index + 3]):
                        raise InventoryMismatch("unknown independent range transport escape")
                    index += 3
                else:index += 1
            if index >= len(text):
                raise InventoryMismatch("unterminated independent range transport quote")
            pieces.append(" ");start = index + 1
        candidates = set()
        for segment in pieces:
            for hit in re.finditer(r"(?<![A-Za-z0-9_.$@%])range\(", segment):
                parsed = re.match(r"range\(i([1-9][0-9]*) (-?(?:0|[1-9][0-9]*)), (-?(?:0|[1-9][0-9]*))\)", segment[hit.start():])
                if parsed is None or len(parsed[1]) > 3:
                    raise InventoryMismatch("unknown independent range candidate syntax")
                width = int(parsed[1])
                if not (1 <= width <= 64 or width == 128):
                    raise InventoryMismatch("independent range width outside native integer profile")
                spellings = parsed[2], parsed[3]
                if any(len(part.lstrip('-')) > len(str(1 << (width - 1))) for part in spellings):
                    raise InventoryMismatch("independent range candidate exceeds source integer width")
                endpoints = tuple(int(part) for part in spellings)
                if any(str(number) != spelling or not -(1 << (width - 1)) <= number < (1 << (width - 1))
                       for number, spelling in zip(endpoints,spellings)):
                    raise InventoryMismatch("noncanonical independent range printer bits")
                lower, upper = (number % (1 << width) for number in endpoints)
                if lower == upper and lower != 0:
                    raise InventoryMismatch("independent range rejects full/invalid equal bounds")
                candidates.add((width,lower,upper))
        matches = []
        for width, lower, upper in sorted(candidates):
            if width != 64:continue
            limbs = (width + 63) // 64
            word = c.c_ulonglong
            lows = (word * limbs)(*((lower >> (64 * i)) & ((1 << 64) - 1) for i in range(limbs)))
            highs = (word * limbs)(*((upper >> (64 * i)) & ((1 << 64) - 1) for i in range(limbs)))
            if self.CreateConstantRangeAttribute(self.context, kind, width, lows, highs) == original:
                matches.append((lower,upper))
        if len(matches) != 1:
            raise InventoryMismatch("independent range lacks unique original callslot AttributeRef identity")
        lower, upper = matches[0]
        return {"index":slot,"name":"range","schema":"ocore.llvm-constant-range-attribute/v1",
                "storage":"context_uniqued_constant_range_attribute","width":64,
                "lower":str(lower),"upper":str(upper)}

    def read(self, path):
        source = artifact(path)
        raw = Path(path).read_bytes()
        self.context = self.ContextCreate()
        self.platform_locations = {}
        module, error = c.c_void_p(), c.c_void_p()
        buffer = self.CreateMemoryBufferWithMemoryRangeCopy(raw, len(raw), b"independent-inventory")
        self.layout = None
        try:
            if self.ParseIRInContext(self.context, buffer, c.byref(module), c.byref(error)):
                raise InventoryMismatch("independent LLVM parse failed")
            if self.VerifyModule(module, 2, c.byref(error)):
                raise InventoryMismatch("independent LLVM verifier rejected source")
            self.source_target = (self.GetTarget(module) or b"").decode()
            self.source_data_layout = self.GetDataLayoutStr(module).decode()
            self.layout = self.CreateTargetData(self.GetDataLayoutStr(module))
            output = {"source": source, "llvm_library": self.library, "data_layout": self.GetDataLayoutStr(module).decode(),
                      "target_triple": (self.GetTarget(module) or b"").decode(),
                      "functions": {}, "globals": {}, "aliases": {}, "strict_fp_required": False}
            for function in self.sequence(self.GetFirstFunction, self.GetNextFunction, module):
                name = self.name(function)
                output["strict_fp_required"] |= self.strict_fp(function)
                uses = Counter()
                params = (c.c_void_p * self.CountParams(function))()
                self.GetParams(function, params)
                values = {value: index for index, value in enumerate(params)}
                blocks = list(self.sequence(self.GetFirstBasicBlock, self.GetNextBasicBlock, function))
                positions = {}
                for block_id, block in enumerate(blocks):
                    for ordinal, instruction in enumerate(self.sequence(self.GetFirstInstruction, self.GetNextInstruction, block)):
                        positions[instruction] = {"block": block_id, "source_instruction": ordinal}
                        if self.GetTypeKind(self.TypeOf(instruction)) != 0:
                            values[instruction] = len(values)
                sites, direct_calls, references, indirect, phis, code_sites, control_calls = [], [], set(), [], [], [], []
                primitive_counts, gep_counts = Counter(), Counter()
                ssa_calls, vector_sites, linux_syscalls, pointer_integer_sites, fp_register_barriers = [], [], [], [], []
                if self.HasPersonalityFn(function):
                    references.add(self.address(self.GetPersonalityFn(function))[0])
                for block_id, block in enumerate(blocks):
                    for ordinal, instruction in enumerate(self.sequence(self.GetFirstInstruction, self.GetNextInstruction, block)):
                        opcode = self.GetInstructionOpcode(instruction)
                        vector_site = self.vector_site(instruction, values, blocks, block_id)
                        if vector_site is not None:
                            vector_sites.append(vector_site)
                        primitive = {8: "binary:add", 10: "binary:sub", 12: "binary:mul",
                                     14: "binary:u_div", 15: "binary:s_div", 17: "binary:u_rem", 18: "binary:s_rem",
                                     20: "binary:shl", 21: "binary:l_shr", 22: "binary:a_shr",
                                     23: "binary:and", 24: "binary:or", 25: "binary:xor",
                                     42: "i_cmp", 46: "select", 68: "freeze", 29: "gep",
                                     30: "cast:trunc", 31: "cast:z_ext", 32: "cast:s_ext",
                                     33: "cast:fp_to_ui", 34: "cast:fp_to_si", 35: "cast:ui_to_fp",
                                     36: "cast:si_to_fp", 37: "cast:fp_trunc", 38: "cast:fp_ext",
                                     39: "cast:ptr_to_int", 40: "cast:int_to_ptr", 41: "cast:bitcast"}.get(opcode)
                        if primitive:
                            primitive_counts[primitive] += 1
                        # Byte-offset GEP lowering contributes integer arithmetic
                        # without corresponding source binary instructions. Derive
                        # only those exact counts independently from source types.
                        if opcode == 29:
                            current = self.GetGEPSourceElementType(instruction)
                            for index in range(1, self.GetNumOperands(instruction)):
                                value = self.GetOperand(instruction, index)
                                if index > 1 and self.GetTypeKind(current) == 10:
                                    if not self.IsAConstantInt(value):
                                        raise InventoryMismatch("nonconstant source struct GEP field")
                                    fields = (c.c_void_p * self.CountStructElementTypes(current))()
                                    self.GetStructElementTypes(current, fields)
                                    current = fields[self.integer(value)]
                                    continue
                                if index > 1:
                                    if self.GetTypeKind(current) != 11:
                                        raise InventoryMismatch("unmapped source GEP index type")
                                    current = self.GetElementType(current)
                                if not self.IsAConstantInt(value):
                                    index_type = self.TypeOf(value)
                                    if self.GetTypeKind(index_type) != 8:
                                        raise InventoryMismatch("unmapped nonscalar source GEP index")
                                    index_width = self.GetIntTypeWidth(index_type)
                                    if index_width < 64:
                                        gep_counts["cast:s_ext"] += 1
                                    if self.ABISizeOfType(self.layout, current) != 1:
                                        gep_counts["binary:mul"] += 1
                                    gep_counts["binary:add"] += 1
                        pending = [self.GetOperand(instruction, index) for index in range(self.GetNumOperands(instruction))]
                        while pending:
                            value = pending.pop()
                            if self.IsAGlobalVariable(value) or self.IsAFunction(value) or self.IsAGlobalAlias(value):
                                references.add(self.name(value))
                            elif self.IsABlockAddress(value):
                                references.add(self.code_address(value)["function"])
                            elif self.IsAConstantExpr(value) or (value not in values and self.GetTypeKind(self.TypeOf(value)) in (10, 11)):
                                pending.extend(self.GetOperand(value, index) for index in range(self.GetNumOperands(value)))
                        opcode = self.GetInstructionOpcode(instruction)
                        pointer_site = self.instruction_constant_pointer_integers(instruction, values, blocks)
                        if pointer_site:
                            pointer_op, conversions = pointer_site
                            pointer_integer_sites.append({"block": block_id, "result_id": values.get(instruction),
                                "op": pointer_op, "conversions": sorted(conversions, key=lambda item: repr(item["path"]))})
                        code_site = self.instruction_code_addresses(instruction, values, blocks)
                        if code_site:
                            operation, addresses = code_site
                            code_sites.append({"block": block_id, "result_id": values.get(instruction),
                                "op": operation, "addresses": sorted(addresses, key=lambda item: repr(item["path"]))})
                        if opcode == 4:
                            indirect.append({"block": block_id,
                                "address": self.operand(self.GetOperand(instruction, 0), values),
                                "destinations": [blocks.index(self.GetSuccessor(instruction, index))
                                                 for index in range(self.GetNumSuccessors(instruction))]})
                        if opcode == 44:
                            phis.append({"block": block_id, "result_id": values[instruction],
                                "result_type": self.shape(self.TypeOf(instruction)),
                                "incoming": [{"block": blocks.index(self.GetIncomingBlock(instruction, index)),
                                              "value": self.operand(self.GetIncomingValue(instruction, index), values)}
                                             for index in range(self.CountIncoming(instruction))]})
                        if self.GetInstructionOpcode(instruction) in (5, 45, 67):
                            output["strict_fp_required"] |= self.strict_fp(instruction, call=True)
                            callee = self.GetCalledValue(instruction)
                            if self.IsAInlineAsm(callee):
                                shape = self.shape(self.TypeOf(instruction))
                                if shape.get("kind") == "float":
                                    fp_register_barriers.append(self.fp_register_barrier_site(instruction, callee, name, block_id, ordinal, values))
                                else:
                                    linux_syscalls.append(self.linux_syscall_site(instruction, callee, name, block_id, ordinal, values))
                            if self.IsAFunction(callee) and not self.GetIntrinsicID(callee):
                                args = [self.GetOperand(instruction, index) for index in range(self.GetNumArgOperands(instruction))]
                                witnesses = {}
                                for index, value in enumerate(args):
                                    if self.IsAInstruction(value) and self.GetInstructionOpcode(value) == 31:
                                        operand = self.GetOperand(value, 0)
                                        witnesses[str(index)] = {"result_id": values[value],
                                            "source_type": self.shape(self.TypeOf(operand)),
                                            "result_type": self.shape(self.TypeOf(value)),
                                            "operand": self.operand(operand, values), **positions[value]}
                                direct_targets = None
                                node = self.GetMetadata(instruction, self.GetMDKindIDInContext(self.context, b"callees", 7))
                                if node:
                                    if opcode not in (5, 45) or not self.IsAMDNode(node):
                                        raise InventoryMismatch("direct callees requires an original call/invoke MDTuple")
                                    members = (c.c_void_p * self.GetMDNodeNumOperands(node))()
                                    self.GetMDNodeOperands(node, members)
                                    if any(not item or not self.IsAFunction(item) or self.GetIntrinsicID(item) for item in members):
                                        raise InventoryMismatch("direct callees requires ordinary original functions")
                                    direct_targets = [self.name(item) for item in members]
                                    if self.name(callee) not in direct_targets:
                                        raise InventoryMismatch("direct callees excludes its original named target")
                                direct_calls.append({"callee": self.name(callee),
                                    "kind": {45: "call", 5: "invoke", 67: "call_br"}[opcode],
                                    "block": block_id, "source_instruction": ordinal,
                                    "result_id": values.get(instruction),
                                    "type": self.shape(self.GetCalledFunctionType(instruction)),
                                    "calling_convention": self.GetInstructionCallConv(instruction),
                                    "extension_attributes": self.extension_vectors(instruction, call=True),
                                    "arg_types": [self.shape(self.TypeOf(value)) for value in args],
                                    "args": [self.operand(value, values) for value in args],
                                    "z_ext_producers": witnesses, "callees": direct_targets})

                            if not self.IsAInlineAsm(callee) and not (self.IsAFunction(callee) and self.GetIntrinsicID(callee)):
                                control_calls.append({"op": {45: "call", 5: "invoke", 67: "call_br"}[self.GetInstructionOpcode(instruction)],
                                    "block": block_id, "callee": self.operand(callee, values),
                                    "result_id": values.get(instruction),
                                    "result_type": self.shape(self.TypeOf(instruction)),
                                    "args": [self.operand(self.GetOperand(instruction, i), values)
                                             for i in range(self.GetNumArgOperands(instruction))],
                                    "control_effects": self.control_effects(instruction, call=True)})

                            if callee in values:
                                kind = self.GetMDKindIDInContext(self.context, b"callees", 7)
                                node = self.GetMetadata(instruction, kind)
                                targets = None
                                if node:
                                    if not self.IsAMDNode(node):
                                        raise InventoryMismatch("callees requires an independently parsed MDTuple")
                                    members = (c.c_void_p * self.GetMDNodeNumOperands(node))()
                                    self.GetMDNodeOperands(node, members)
                                    if any(not item or not self.IsAFunction(item) or self.GetIntrinsicID(item)
                                           for item in members):
                                        raise InventoryMismatch("callees requires ordinary original function members")
                                    targets = [self.name(item) for item in members]
                                ssa_calls.append({"block": block_id, "source_instruction": ordinal,
                                    "op": {5: "invoke", 45: "call", 67: "callbr"}[opcode],
                                    "callee": self.operand(callee, values),
                                    "result_id": values.get(instruction),
                                    "type": self.shape(self.GetCalledFunctionType(instruction)),
                                    "calling_convention": self.GetInstructionCallConv(instruction),
                                    "args": [self.operand(self.GetOperand(instruction, index), values)
                                             for index in range(self.GetNumArgOperands(instruction))],
                                    "callees": targets})
                            if self.IsAFunction(callee) and self.GetIntrinsicID(callee):
                                uses[self.name(callee)] += 1
                                intrinsic_name = self.name(callee)
                                sites.append({"name": intrinsic_name, "block": block_id, "source_instruction": ordinal,
                                    "result_id": values.get(instruction),
                                    "result_type": self.shape(self.TypeOf(instruction)),
                                    "arg_types": [self.shape(self.TypeOf(self.GetOperand(instruction, index)))
                                                  for index in range(self.GetNumArgOperands(instruction))],
                                    "args": [self.operand(self.GetOperand(instruction, index), values)
                                             for index in range(self.GetNumArgOperands(instruction))],
                                    "fast_math": self.GetFastMathFlags(instruction) if intrinsic_name.startswith(("llvm.fabs.", "llvm.floor.", "llvm.ceil.", "llvm.trunc.", "llvm.experimental.constrained.fmul.")) else 0})
                                if intrinsic_name in {"llvm.experimental.constrained.fmul.f32", "llvm.experimental.constrained.fmul.f64"}:
                                    base = b"llvm.experimental.constrained.fmul"
                                    sites[-1]["constrained_fp_source"] = {
                                        "actual_intrinsic_id": self.GetIntrinsicID(callee),
                                        "expected_intrinsic_id": self.LookupIntrinsicID(base, len(base)),
                                        "enclosing_strictfp": self.strict_fp(function),
                                        "call_or_declaration_strictfp": self.strict_fp(instruction, call=True) or self.strict_fp(callee)}
                                if intrinsic_name == "llvm.ptrmask.p0.i64":
                                    sites[-1]["return_alignment"] = self.call_return_alignment(instruction)
                output["functions"][name] = {"type": self.shape(self.GlobalGetValueType(function)),
                    "source_abi": self.source_abi_witness(function),
                    "defined": bool(self.GetFirstBasicBlock(function)), "calling_convention": self.GetFunctionCallConv(function),
                    "intrinsic_id": self.GetIntrinsicID(function), "intrinsic_uses": dict(uses),
                    "intrinsic_sites": sites, "direct_call_sites": direct_calls,
                    "extension_attributes": self.extension_vectors(function), "primitive_graph_counts": dict(primitive_counts),
                    "gep_offset_graph_counts": dict(gep_counts), "symbol_references": sorted(references),
                    "control_effects": self.control_effects(function), "control_call_sites": control_calls,
                    "block_ids": list(range(len(blocks))), "indirect_branches": indirect, "phis": phis,
                    "block_address_sites": code_sites, "constant_pointer_integer_sites": pointer_integer_sites, "ssa_indirect_calls": ssa_calls, "vector_sites": vector_sites, "linux_syscalls": linux_syscalls, "fp_register_barriers": fp_register_barriers,
                    **self.contract(function)}
            opaque_groups = {}
            for global_ in self.sequence(self.GetFirstGlobal, self.GetNextGlobal, module):
                ty, initial = self.GlobalGetValueType(global_), self.GetInitializer(global_)
                if self.GetTypeKind(ty) == 10 and self.IsOpaqueStruct(ty):
                    group = opaque_groups.setdefault(ty, {"name": self.shape(ty)["name"], "globals": []})
                    group["globals"].append(self.name(global_))
                encoded, refinements = self.initializer(initial, ty) if initial else (None, [])
                output["globals"][self.name(global_)] = {"type": self.shape(ty), "initializer": encoded,
                    "address_space": self.GetPointerAddressSpace(self.TypeOf(global_)),
                    "constant": bool(self.IsGlobalConstant(global_)), "thread_local": bool(self.IsThreadLocal(global_)),
                    "tls_model": {0: None, 1: "general_dynamic", 2: "local_dynamic", 3: "initial_exec", 4: "local_exec"}.get(self.GetThreadLocalMode(global_), "unsupported"),
                    "initializer_refinements": refinements, **self.contract(global_)}
            output["opaque_global_types"] = sorted(
                ({"name": group["name"], "globals": sorted(group["globals"])} for group in opaque_groups.values()),
                key=lambda group: (group["name"] or "", group["globals"]))
            for alias in self.sequence(self.GetFirstGlobalAlias, self.GetNextGlobalAlias, module):
                symbol, offset = self.address(self.AliasGetAliasee(alias))
                output["aliases"][self.name(alias)] = {"type": self.shape(self.GlobalGetValueType(alias)), "aliasee": symbol, "offset": offset, **self.contract(alias)}
            if artifact(path) != source:
                raise InventoryMismatch("source changed during independent inventory")
            return output
        finally:
            if error.value:
                self.DisposeMessage(error)
            if self.layout:
                self.DisposeTargetData(self.layout)
            if module.value:
                self.DisposeModule(module)
            self.ContextDispose(self.context)


def native_shape(types, index):
    ty = dict(types[index])
    if ty["kind"] in {"array", "vector"}:
        ty["element"] = native_shape(types, ty["element"])
    elif ty["kind"] == "struct":
        ty["fields"] = [native_shape(types, item) for item in ty["fields"]]
    elif ty["kind"] == "function":
        signature = ty["signature"]
        return {"kind": "function", "params": [native_shape(types, item) for item in signature["params"]],
                "result": native_shape(types, signature["result"]), "variadic": signature["variadic"]}
    return ty


def native_operand(operand, types):
    output = dict(operand)
    if "ty" in output:
        output["type"] = native_shape(types, output.pop("ty"))
    if output.get("kind") == "pointer_to_integer":
        output["pointer"] = native_operand(output["pointer"], types)
    if "elements" in output:
        output["elements"] = [native_operand(element, types) for element in output["elements"]]
    return output


def contains_vector(shape):
    if not isinstance(shape, dict):
        return False
    return (shape.get("kind") == "vector"
            or any(contains_vector(value) for value in shape.values() if isinstance(value, dict))
            or any(contains_vector(value) for values in shape.values() if isinstance(values, list) for value in values))


def check_vector_sites(original, function, types):
    """Exact independent vector instruction/operand census, including unused ops.

    Match original result identities and block order; synthetic scalar GEP
    instructions do not change those identities or become vector operations.
    """
    value_types = {param["id"]: native_shape(types, param["ty"]) for param in function["params"]}
    value_types.update({instruction["result"]["id"]: native_shape(types, instruction["result"]["ty"])
                       for block in function["blocks"] for instruction in block["instructions"] if instruction.get("result")})
    def vector_operand(item):
        if isinstance(item, list):
            return any(vector_operand(value) for value in item)
        if not isinstance(item, dict):
            return False
        if item.get("kind") == "value" and contains_vector(value_types.get(item["id"])):
            return True
        if "ty" in item and contains_vector(native_shape(types, item["ty"])):
            return True
        return any(vector_operand(value) for value in item.values())
    def normalize(item):
        if isinstance(item, list):
            return [normalize(value) for value in item]
        if isinstance(item, dict):
            return {("type" if key == "ty" else key): (native_shape(types, value) if key == "ty" else normalize(value))
                    for key, value in item.items()}
        return item
    actual = []
    for block in function["blocks"]:
        for instruction in block["instructions"]:
            result, operation = instruction.get("result"), instruction["operation"]
            result_type = native_shape(types, result["ty"]) if result else {"kind": "void"}
            if (contains_vector(result_type) or vector_operand(operation)
                    or operation["op"] in {"extract_element", "insert_element", "vector_reduce_add"}):
                actual.append({"block": block["id"], "result_id": result["id"] if result else None,
                               "result_type": result_type, "operation": normalize(operation)})
    if actual != original.get("vector_sites", []):
        raise InventoryMismatch("fixed vector operation/type/operand inventory changed: " + function["name"])
    return len(actual)


def integral_rounding_graph(site, function, block, operation, result, types, graph_claims=None):
    """Independent IEEE sign/exponent/fraction contract, not importer dispatch.

    Match every edge, type, flag and shared SSA identity. Constants and the
    source's sole original argument are leaves; all other edges must resolve
    to distinct, exact typed definitions in this original block.
    """
    parsed = re.fullmatch(r"llvm\.(floor|ceil|trunc)\.f(32|64|128)", site["name"])
    if not parsed:
        return False
    rounding, width = parsed[1], int(parsed[2])
    precision, exponent_bits = {32: (24, 8), 64: (53, 11), 128: (113, 15)}[width]
    fraction = precision - 1
    bias = (1 << (exponent_bits - 1)) - 1
    integer, floating, boolean = ({"kind": "int", "bits": width},
                                 {"kind": "float", "bits": width}, {"kind": "int", "bits": 1})
    if (len(site["args"]) != 1 or site.get("arg_types") != [floating]
            or site.get("result_type") != floating or site.get("fast_math") != 0
            or result is None or native_shape(types, result["ty"]) != floating):
        return False

    def node(ty, **fields):
        return {"type": ty, "operation": fields}

    def constant(n):
        return {"constant": n % (1 << width), "type": integer}

    def binary(kind, lhs, rhs, ty=integer):
        return node(ty, op="binary", kind=kind, lhs=lhs, rhs=rhs, flags=[])

    def comparison(predicate, lhs, rhs):
        return node(boolean, op="i_cmp", predicate=predicate, lhs=lhs, rhs=rhs)

    def select(condition, on_true, on_false):
        return node(integer, op="select", condition=condition, on_true=on_true, on_false=on_false)

    frozen = node(floating, op="freeze", value={"source": site["args"][0]})
    raw = node(integer, op="cast", kind="bitcast", value=frozen)
    sign = binary("and", raw, constant(1 << (width - 1)))
    exponent = binary("and", binary("l_shr", raw, constant(fraction)), constant((1 << exponent_bits) - 1))
    below_one = comparison("ult", exponent, constant(bias))
    middle = binary("and", comparison("ult", exponent, constant(bias + fraction)),
                    comparison("uge", exponent, constant(bias)), boolean)
    shift = select(middle, binary("sub", constant(bias + fraction), exponent), constant(1))
    unit = binary("shl", constant(1), shift)
    mask = binary("sub", unit, constant(1))
    truncated = binary("and", raw, binary("xor", mask, constant((1 << width) - 1)))
    if rounding == "trunc":
        rounded, tiny = truncated, sign
    else:
        negative = comparison("ne", sign, constant(0))
        zero = comparison("eq", binary("and", raw, constant((1 << (width - 1)) - 1)), constant(0))
        direction = negative if rounding == "floor" else comparison("eq", sign, constant(0))
        discarded = comparison("ne", binary("and", raw, mask), constant(0))
        add_one = binary("and", direction, discarded, boolean)
        rounded = select(add_one, binary("add", truncated, unit), truncated)
        tiny_nonzero = (select(negative, constant((1 << (width - 1)) | (bias << fraction)), constant(0))
                        if rounding == "floor" else select(negative, sign, constant(bias << fraction)))
        tiny = select(zero, raw, tiny_nonzero)
    non_nan = select(below_one, tiny, select(middle, rounded, raw))
    nan = binary("and", comparison("eq", exponent, constant((1 << exponent_bits) - 1)),
                 comparison("ne", binary("and", raw, constant((1 << fraction) - 1)), constant(0)), boolean)
    selected = select(nan, binary("or", raw, constant(1 << (fraction - 1))), non_nan)
    expected = node(floating, op="cast", kind="bitcast", value=selected)
    definitions = {item["result"]["id"]: item for item in block["instructions"] if item.get("result")}
    bindings, owners = {}, {}

    def edge(actual, wanted):
        if "source" in wanted:
            return native_operand(actual, types) == wanted["source"]
        if "constant" in wanted:
            return native_operand(actual, types) == {"kind": "int", "type": wanted["type"],
                                                       "bits": str(wanted["constant"])}
        if actual.get("kind") != "value":
            return False
        key, value_id = id(wanted), actual["id"]
        if key in bindings:
            return bindings[key] == value_id
        if value_id in owners:
            return False
        instruction = definitions.get(value_id)
        if not instruction or native_shape(types, instruction["result"]["ty"]) != wanted["type"]:
            return False
        bindings[key], owners[value_id] = value_id, key
        return match(instruction["operation"], wanted["operation"])

    def match(actual, wanted):
        if set(actual) != set(wanted):
            return False
        for field, value in wanted.items():
            if isinstance(value, dict):
                if not edge(actual[field], value):
                    return False
            elif actual[field] != value:
                return False
        return True

    if not match(operation, expected["operation"]) or result["id"] in owners:
        return False
    if graph_claims is not None:
        graph_claims[result["id"]] = set(owners) | {result["id"]}
    return True


def byte_swap_graph(site, block, operation, result, types, graph_claims=None):
    """Independent exact byte-position DAG, with one stable original operand."""
    width = int(site["name"].removeprefix("llvm.bswap.i"))
    integer = {"kind": "int", "bits": width}
    if (width not in (16, 32, 48, 64, 128) or len(site["args"]) != 1
            or site.get("arg_types") != [integer] or site.get("result_type") != integer
            or result is None or native_shape(types, result["ty"]) != integer):
        return False
    definitions = {item["result"]["id"]: item for item in block["instructions"] if item.get("result")}
    frozen = {"op": "freeze", "value": {"source": site["args"][0]}}
    literal = lambda bits: {"literal": bits}
    binary = lambda kind, lhs, rhs: {"op": "binary", "kind": kind,
                                    "lhs": lhs, "rhs": rhs, "flags": []}
    terms = [binary("shl", binary("and", binary("l_shr", frozen, literal(8 * index)),
                                    literal(255)), literal(width - 8 * (index + 1)))
             for index in range(width // 8)]
    expected = terms[0]
    for term in terms[1:]:
        expected = binary("or", expected, term)
    bindings = {}

    def edge(value, wanted):
        if "source" in wanted:
            return native_operand(value, types) == wanted["source"]
        if "literal" in wanted:
            return native_operand(value, types) == {"kind": "int", "type": integer,
                                                     "bits": str(wanted["literal"])}
        if value.get("kind") != "value":
            return False
        identity = id(wanted)
        if identity in bindings:
            return bindings[identity] == value["id"]
        item = definitions.get(value["id"])
        if not item or native_shape(types, item["result"]["ty"]) != integer:
            return False
        bindings[identity] = value["id"]
        return node(item["operation"], wanted)

    def node(actual, wanted):
        return (set(actual) == set(wanted) and all(
            edge(actual[key], value) if isinstance(value, dict) else actual[key] == value
            for key, value in wanted.items()))

    if not node(operation, expected):
        return False
    claimed = set(bindings.values()) | {result["id"]}
    if len(bindings) != len(set(bindings.values())) or len(claimed) != width // 2:
        return False
    if graph_claims is not None:
        graph_claims[result["id"]] = claimed
    return True


def funnel_width(name):
    match = re.fullmatch(r"llvm\.fs(?:hl|hr)\.i([1-9][0-9]*)", name)
    if match:
        width = int(match[1])
        if 1 <= width <= 64 or width == 128:
            return width
    return None


def intrinsic_mapping(site, function, types, graph_claims=None):
    """Account for each actual source call by retained identity/operands.

    This is an independently specified test contract, not a production-importer
    dispatch table. Compiler-only metadata identity remains a separate gate.
    """
    name, args = site["name"], site["args"]
    value_types = {value["id"]: native_shape(types, value["ty"]) for value in function["params"]}
    value_types.update({instruction["result"]["id"]: native_shape(types, instruction["result"]["ty"])
                        for original_block in function["blocks"] for instruction in original_block["instructions"]
                        if instruction.get("result")})

    def operand_type(operand):
        if operand.get("kind") == "value":
            return value_types.get(operand["id"])
        return native_shape(types, operand["ty"]) if "ty" in operand else None

    block = next((block for block in function["blocks"] if block["id"] == site["block"]), None)
    if block is None:
        raise InventoryMismatch(f"missing original block for intrinsic {name}")
    candidates = list(enumerate(block["instructions"]))
    # Void instructions have result:null, whereas nonvoid results carry a value.
    if site["result_id"] is not None:
        candidates = [(index, instruction) for index, instruction in enumerate(block["instructions"])
                      if instruction.get("result") and instruction["result"]["id"] == site["result_id"]]

    def matches(operation, result):
        op = operation["op"]
        same = lambda field, index: native_operand(operation[field], types) == args[index]
        reduction = re.fullmatch(r"llvm\.vector\.reduce\.add\.v([1-9][0-9]*)i(1|8|16|32|64)", name)
        if reduction:
            count, width = int(reduction[1]), int(reduction[2])
            element = {"kind": "int", "bits": width}
            return (op == "vector_reduce_add" and set(operation) == {"op", "value"}
                    and site["arg_types"] == [{"kind": "vector", "len": count, "element": element}]
                    and site["result_type"] == element and result is not None
                    and native_shape(types, result["ty"]) == element and same("value", 0)
                    and operand_type(operation["value"]) == site["arg_types"][0])
        if re.fullmatch(r"llvm\.bswap\.i(?:16|32|48|64|128)", name):
            return byte_swap_graph(site, block, operation, result, types, graph_claims)
        if re.fullmatch(r"llvm\.(floor|ceil|trunc)\.f(32|64|128)", name):
            return integral_rounding_graph(site, function, block, operation, result, types, graph_claims)
        if name == "llvm.ptrmask.p0.i64":
            pointer, integer = {"kind": "pointer", "address_space": 0}, {"kind": "int", "bits": 64}
            if "return_alignment" not in site:
                raise InventoryMismatch("original ptrmask return-alignment accounting is missing")
            alignment = site["return_alignment"]
            actual_alignment = operation.get("return_alignment")
            if (actual_alignment is not None and type(actual_alignment) is not int) or actual_alignment != alignment:
                return False
            if alignment is not None:
                if type(alignment) is not int or alignment < 1 or alignment > 1 << 32 or alignment & (alignment - 1):
                    return False
                if alignment > 1 and (len(args) != 2 or args[1].get("kind") != "int"
                                      or args[1].get("type") != integer
                                      or int(args[1]["bits"]) & (alignment - 1)):
                    return False
            return (len(args) == 2 and site.get("arg_types") == [pointer, integer]
                    and site.get("result_type") == pointer
                    and result is not None and native_shape(types, result["ty"]) == pointer
                    and op == "ptr_mask" and same("pointer", 0) and same("mask", 1)
                    and operand_type(operation["pointer"]) == pointer
                    and operand_type(operation["mask"]) == integer)
        if name in ("llvm.ctpop.i32", "llvm.ctpop.i64"):
            integer = {"kind": "int", "bits": int(name.rsplit("i", 1)[1])}
            return (len(args) == 1 and site.get("arg_types") == [integer]
                    and site.get("result_type") == integer
                    and result is not None and native_shape(types, result["ty"]) == integer
                    and op == "integer_population_count" and set(operation) == {"op", "value"}
                    and same("value", 0) and operand_type(operation["value"]) == integer)
        if name in ("llvm.ctlz.i32", "llvm.ctlz.i64", "llvm.abs.i32", "llvm.abs.i64"):
            integer = {"kind": "int", "bits": int(name.rsplit("i", 1)[1])}
            boolean = {"kind": "int", "bits": 1}
            leading = name.startswith("llvm.ctlz.")
            flag = "zero_is_poison" if leading else "int_min_is_poison"
            return (len(args) == 2 and site.get("arg_types") == [integer, boolean]
                    and site.get("result_type") == integer
                    and result is not None and native_shape(types, result["ty"]) == integer
                    and args[1].get("kind") == "int" and args[1].get("type") == boolean
                    and args[1].get("bits") in ("0", "1")
                    and op == ("integer_count_leading_zeros" if leading else "integer_abs")
                    and same("value", 0) and operand_type(operation["value"]) == integer
                    and type(operation.get(flag)) is bool
                    and operation[flag] is (args[1]["bits"] == "1"))
        if name in ("llvm.va_start.p0", "llvm.va_end.p0", "llvm.va_copy.p0"):
            return (op == "call" and operation["callee"].get("name") == name
                    and [native_operand(value, types) for value in operation["args"]] == args)
        if name.startswith("llvm.memset."):
            return (op == "memory_set" and same("destination", 0) and same("value", 1)
                    and same("length", 2) and operation["volatile"] == bool(int(args[3]["bits"])))
        if name.startswith(("llvm.memcpy.", "llvm.memmove.")):
            return (op == "memory_copy" and same("destination", 0) and same("source", 1) and same("length", 2)
                    and operation["volatile"] == bool(int(args[3]["bits"]))
                    and operation["allow_overlap"] == name.startswith("llvm.memmove."))
        if name in ("llvm.lifetime.start.p0", "llvm.lifetime.end.p0"):
            return op == "lifetime" and same("pointer", 0) and operation["end"] == name.startswith("llvm.lifetime.end.")
        if name == "llvm.assume":
            return op == "assume" and same("condition", 0)
        if name == "llvm.trap":
            return op == "trap"
        if name in {"llvm.experimental.constrained.fmul.f32", "llvm.experimental.constrained.fmul.f64"}:
            width = 32 if name.endswith("f32") else 64
            scalar = {"kind": "float", "bits": width}
            fact = site.get("constrained_fp_source", {})
            if (not fact.get("expected_intrinsic_id") or fact.get("actual_intrinsic_id") != fact["expected_intrinsic_id"]
                    or not fact.get("enclosing_strictfp") or not fact.get("call_or_declaration_strictfp")
                    or site.get("fast_math") != 0
                    or site.get("arg_types") != [scalar, scalar, {"kind": "metadata"}, {"kind": "metadata"}]
                    or site.get("result_type") != scalar or len(args) != 4
                    or args[2].get("mdstring_bytes") != list(b"round.dynamic")
                    or args[3].get("mdstring_bytes") != list(b"fpexcept.ignore")):
                raise InventoryMismatch("original constrained multiply identity/signature/metadata/strictfp mismatch")
            return (op == "constrained_float_binary" and operation.get("kind") == "mul"
                    and same("lhs", 0) and same("rhs", 1)
                    and operation.get("rounding") == "dynamic" and operation.get("exceptions") == "ignore"
                    and result is not None and native_shape(types, result["ty"]) == scalar)
        if name.startswith("llvm.fabs."):
            flags = {flag: bool(site["fast_math"] & (1 << bit))
                     for bit, flag in enumerate(("reassoc", "nnan", "ninf", "nsz", "arcp", "contract", "afn"))}
            return op == "float_abs" and same("value", 0) and operation["flags"] == flags
        if name.startswith("llvm.usub.sat.i"):
            spelling = name.removeprefix("llvm.usub.sat.i")
            if not spelling.isdecimal():
                return False
            width = int(spelling)
            integer = {"kind": "int", "bits": width}
            if (str(width) != spelling or not (1 <= width <= 64 or width == 128)
                    or site.get("arg_types") != [integer, integer] or site.get("result_type") != integer
                    or result is None or native_shape(types, result["ty"]) != integer):
                return False
            definitions = {item["result"]["id"]: item for item in block["instructions"] if item.get("result")}
            lhs, rhs = [{"op": "freeze", "value": {"source": arg}} for arg in args]
            difference = {"op": "binary", "kind": "sub", "lhs": lhs, "rhs": rhs, "flags": []}
            underflow = {"op": "i_cmp", "predicate": "ult", "lhs": lhs, "rhs": rhs}
            expected = {"op": "select", "condition": underflow,
                        "on_true": {"literal": 0}, "on_false": difference}
            bindings = {}

            def edge(value, wanted, bits):
                if "source" in wanted:
                    return native_operand(value, types) == wanted["source"]
                if "literal" in wanted:
                    return native_operand(value, types) == {"kind": "int", "type": {"kind": "int", "bits": bits}, "bits": str(wanted["literal"])}
                if value.get("kind") != "value":
                    return False
                identity = id(wanted)
                if identity in bindings:
                    return bindings[identity] == value["id"]
                item = definitions.get(value["id"])
                if not item or native_shape(types, item["result"]["ty"]) != {"kind": "int", "bits": bits}:
                    return False
                bindings[identity] = value["id"]
                return node(item["operation"], wanted)

            def node(actual, wanted):
                if set(actual) != set(wanted):
                    return False
                for field, expected_value in wanted.items():
                    if isinstance(expected_value, dict):
                        if not edge(actual[field], expected_value, 1 if field == "condition" else width):
                            return False
                    elif actual[field] != expected_value:
                        return False
                return True

            if not node(operation, expected) or len(set(bindings.values())) != 4:
                return False
            claimed = set(bindings.values()) | {result["id"]}
            if len(claimed) != 5:
                return False
            if graph_claims is not None:
                graph_claims[result["id"]] = claimed
            return True
        if funnel_width(name) is not None:
            width = int(name.rsplit(".i", 1)[1])
            integer = {"kind": "int", "bits": width}
            if (site.get("arg_types") != [integer] * 3 or site.get("result_type") != integer
                    or result is None or native_shape(types, result["ty"]) != integer):
                return False
            definitions = {item["result"]["id"]: item for item in block["instructions"]
                           if item.get("result")}
            source = lambda index: {"source": args[index]}
            literal = lambda value: {"literal": value}
            binary = lambda kind, lhs, rhs: {"op": "binary", "kind": kind,
                                             "lhs": lhs, "rhs": rhs, "flags": []}
            high, low, count = [{"op": "freeze", "value": source(index)} for index in range(3)]
            leftward = name.startswith("llvm.fshl.")
            def expansion(remainder):
                if remainder:
                    shift = binary("u_rem", count, literal(width))
                    reverse = binary("u_rem", binary("sub", literal(width), shift), literal(width))
                else:
                    shift = binary("and", count, literal(width - 1))
                    reverse = binary("and", binary("sub", literal(0), shift), literal(width - 1))
                return {"op": "select",
                        "condition": {"op": "i_cmp", "predicate": "eq", "lhs": shift, "rhs": literal(0)},
                        "on_true": high if leftward else low,
                        "on_false": binary("or", binary("shl", high, shift if leftward else reverse),
                                           binary("l_shr", low, reverse if leftward else shift))}
            # Both qualified canonical expansions are independently checked.
            # Bit-mask normalization is valid only at a power-of-two width.
            expected = [expansion(True)]
            if width & (width - 1) == 0:
                expected.append(expansion(False))
            # Repeated graph nodes must reference the SAME frozen SSA value.
            # In-range shifts and the correct zero-count source operand are
            # checked even when the source input happens to be a constant.
            bindings = {}

            def node(actual, wanted):
                if set(actual) != set(wanted):
                    return False
                for field, expected_value in wanted.items():
                    value = actual[field]
                    if isinstance(expected_value, dict):
                        bits = 1 if field == "condition" else width
                        if not edge(value, expected_value, bits):
                            return False
                    elif value != expected_value:
                        return False
                return True

            def edge(value, wanted, bits):
                if "source" in wanted:
                    return native_operand(value, types) == wanted["source"]
                if "literal" in wanted:
                    return native_operand(value, types) == {
                        "kind": "int", "type": {"kind": "int", "bits": bits},
                        "bits": str(wanted["literal"])}
                if value.get("kind") != "value":
                    return False
                identity = id(wanted)
                if identity in bindings:
                    return bindings[identity] == value["id"]
                instruction = definitions.get(value["id"])
                if (not instruction or native_shape(types, instruction["result"]["ty"])
                        != {"kind": "int", "bits": bits}):
                    return False
                bindings[identity] = value["id"]
                return node(instruction["operation"], wanted)

            for candidate in expected:
                bindings.clear()
                if node(operation, candidate):
                    if graph_claims is not None:
                        graph_claims[result["id"]] = set(bindings.values()) | {result["id"]}
                    return True
            return False
        if ".with.overflow." in name:
            family = name.split(".")[1]
            return (op == "integer_overflow" and operation["kind"] == family[1:]
                    and operation["signed"] == family.startswith("s") and same("lhs", 0) and same("rhs", 1))
        if re.fullmatch(r"llvm\.[su](?:min|max)\.i\d+", name):
            return op == "integer_min_max" and operation["kind"] == name.split(".")[1] and same("lhs", 0) and same("rhs", 1)
        if name == "llvm.threadlocal.address.p0":
            return op == "thread_local_address" and operation["global"] == args[0]["name"]
        if name == "llvm.eh.typeid.for.p0":
            return op == "eh_type_id" and same("typeinfo", 0)
        if name == "llvm.experimental.noalias.scope.decl":
            return op == "no_alias_scope_decl" and operation["source_instruction"] == site["source_instruction"]
        if name in ("llvm.load.relative.i32", "llvm.load.relative.i64"):
            if op != "gep" or not same("base", 0) or operation["inbounds"]:
                return False
            definitions = {item["result"]["id"]: item for b in function["blocks"] for item in b["instructions"] if item.get("result")}
            def definition(value):
                return definitions.get(value.get("id"), {}) if value.get("kind") == "value" else {}
            def producer(value):
                return definition(value).get("operation", {})
            def result_type(value):
                result = definition(value).get("result")
                return native_shape(types, result["ty"]) if result else None
            signed = producer(operation["offset"])
            load = producer(signed.get("value", {}))
            address = producer(load.get("pointer", {}))
            if not (signed.get("op") == "cast" and signed.get("kind") == "s_ext"
                    and load.get("op") == "load" and load.get("alignment") == 4 and not load.get("volatile")
                    and result_type(operation["offset"]) == {"kind": "int", "bits": 64}
                    and result_type(signed.get("value", {})) == {"kind": "int", "bits": 32}
                    and address.get("op") == "gep" and not address.get("inbounds")
                    and result_type(load.get("pointer", {})) == {"kind": "pointer", "address_space": 0}
                    and native_operand(address["base"], types) == args[0]):
                return False
            index = address["offset"]
            if name.endswith("i32"):
                extension = producer(index)
                return (extension.get("op") == "cast" and extension.get("kind") == "s_ext"
                        and result_type(index) == {"kind": "int", "bits": 64}
                        and native_operand(extension["value"], types) == args[1])
            return native_operand(index, types) == args[1]
        raise InventoryMismatch(f"independent intrinsic mapping is unavailable: {name}")

    found = [(index, instruction) for index, instruction in candidates
             if matches(instruction["operation"], instruction.get("result"))]
    if not found:
        raise InventoryMismatch(f"missing/changed intrinsic operation {name} in {function['name']}")
    return found


def native_extension_vectors(signature, actual_count=None):
    count = len(signature["params"]) if actual_count is None else actual_count
    attrs = signature.get("param_attributes", [])
    if attrs and len(attrs) != count:
        raise InventoryMismatch("native extension attribute inventory has wrong length")
    names = {"signext", "zeroext", "noext"}
    return {"params": [sorted(name for name in (attrs[index] if attrs else []) if name in names)
                       for index in range(count)],
            "result": sorted(name for name in signature.get("result_attributes", []) if name in names)}


def check_direct_call_extensions(original, function, types):
    """Exact ordinary direct-site extensions, typed args and z_ext witnesses.

    Other ABI storage/metadata, indirect callees and arbitrary body semantics
    require separate proofs. This function never adapts source signatures.
    """
    definitions = {instruction["result"]["id"]: (block["id"], instruction)
                   for block in function["blocks"] for instruction in block["instructions"]
                   if instruction.get("result")}
    value_types = {value["id"]: native_shape(types, value["ty"]) for value in function["params"]}
    value_types.update({key: native_shape(types, instruction["result"]["ty"])
                        for key, (_, instruction) in definitions.items()})
    for block in function["blocks"]:
        if block["terminator"].get("result"):
            result = block["terminator"]["result"]
            value_types[result["id"]] = native_shape(types, result["ty"])
    def operand_type(value):
        return value_types.get(value["id"]) if value.get("kind") == "value" else native_shape(types, value["ty"])
    candidates = []
    for block in function["blocks"]:
        for index, instruction in enumerate(block["instructions"]):
            if instruction["operation"]["op"] == "call":
                candidates.append((block["id"], index, instruction.get("result"), instruction["operation"]))
        term = block["terminator"]
        if term["op"] == "invoke":
            candidates.append((block["id"], len(block["instructions"]), term.get("result"), term))
    consumed, previous, proofs = set(), {}, []
    for site in original["direct_call_sites"]:
        found = None
        for block, index, result, operation in candidates:
            callee = operation["callee"]
            if (block != site["block"] or (block, index) in consumed
                    or index <= previous.get(block, -1) or callee.get("kind") != "symbol"
                    or callee.get("name") != site["callee"] or operation["op"] != site["kind"]):
                continue
            signature = operation["signature"]
            shape = {"kind": "function", "params": [native_shape(types, ty) for ty in signature["params"]],
                     "result": native_shape(types, signature["result"]), "variadic": signature["variadic"]}
            if ((result["id"] if result else None) != site["result_id"] or shape != site["type"]
                    or signature["abi"] != {0: "c", 8: "fastcc"}.get(site["calling_convention"])
                    or [native_operand(value, types) for value in operation["args"]] != site["args"]
                    or [operand_type(value) for value in operation["args"]] != site["arg_types"]
                    or native_extension_vectors(signature, len(operation["args"])) != site["extension_attributes"]):
                continue
            found = (block, index)
            break
        if found is None:
            raise InventoryMismatch(f"ordinary direct call extension/operand site changed: {function['name']}/{site['callee']}")
        for witness in site["z_ext_producers"].values():
            definition = definitions.get(witness["result_id"])
            if not definition:
                raise InventoryMismatch(f"ordinary call z_ext witness missing: {function['name']}/{site['callee']}")
            block, instruction = definition
            operation = instruction["operation"]
            if (block != witness["block"] or native_shape(types, instruction["result"]["ty"]) != witness["result_type"]
                    or operation != {"op": "cast", "kind": "z_ext", "value": operation.get("value")}
                    or native_operand(operation["value"], types) != witness["operand"]
                    or operand_type(operation["value"]) != witness["source_type"]):
                raise InventoryMismatch(f"ordinary call z_ext witness changed: {function['name']}/{site['callee']}")
        consumed.add(found); previous[found[0]] = found[1]
        proofs.append({"source_site": site, "native_block": found[0], "native_instruction": found[1]})
    return proofs, consumed, candidates

def normalized_control_effects(value):
    if not isinstance(value, dict) or set(value) - {"returns_twice"}:
        raise InventoryMismatch("unknown native control effect")
    effect = value.get("returns_twice", False)
    if type(effect) is not bool:
        raise InventoryMismatch("native returns_twice effect must be boolean")
    return {"returns_twice": effect}


def check_control_call_sites(original, function, types, intrinsic_names):
    sites = []
    value_types = {v["id"]: v["ty"] for v in function["params"]}
    for block in function["blocks"]:
        for instruction in block["instructions"]:
            if instruction.get("result"):
                value_types[instruction["result"]["id"]] = instruction["result"]["ty"]
    for block in function["blocks"]:
        calls = [(i["operation"], i.get("result")) for i in block["instructions"]
                 if i["operation"]["op"] == "call"]
        term = block["terminator"]
        if term["op"] == "invoke":
            calls.append((term, term.get("result")))
        for operation, result in calls:
            callee = operation["callee"]
            if callee.get("kind") == "symbol" and callee["name"] in intrinsic_names:
                continue
            sites.append({"op": operation["op"], "block": block["id"],
                "callee": native_operand(callee, types),
                "result_id": result["id"] if result else None,
                "result_type": native_shape(types, result["ty"]) if result else {"kind": "void"},
                "args": [native_operand(value, types) for value in operation["args"]],
                "control_effects": normalized_control_effects(operation.get("control_effects", {}))})
    if sites != original["control_call_sites"]:
        raise InventoryMismatch(f"ordinary call control-effect site/operand inventory changed: {function['name']}")
    return sites

def check_call_target_constraints(original, function, types):
    """Bind every SSA call and original named-direct target promise in order.

    Metadata function names do not become executable symbol dependencies.
    This is source/IR accounting, not a dynamic membership proof or provider
    resolution. Empty and absent target lists remain different contracts.
    """
    candidates = []
    for block in function["blocks"]:
        for index, item in enumerate(block["instructions"]):
            op = item["operation"]
            if op["op"] == "call" and op["callee"].get("kind") == "value":
                candidates.append((block["id"], index, item.get("result"), op))
        op = block["terminator"]
        if op["op"] == "invoke" and op["callee"].get("kind") == "value":
            candidates.append((block["id"], len(block["instructions"]), op.get("result"), op))
    source_calls = original["ssa_indirect_calls"]
    if len(candidates) != len(source_calls):
        raise InventoryMismatch(f"SSA indirect call membership changed: {function['name']}")
    expected, proofs = [], []
    for site, (block, index, result, op) in zip(source_calls, candidates):
        sig = op["signature"]
        shape = {"kind": "function", "params": [native_shape(types, ty) for ty in sig["params"]],
                 "result": native_shape(types, sig["result"]), "variadic": sig["variadic"]}
        if (block != site["block"] or op["op"] != site["op"]
                or native_operand(op["callee"], types) != site["callee"]
                or (result["id"] if result else None) != site["result_id"]
                or shape != site["type"]
                or sig["abi"] != {0: "c", 8: "fastcc"}.get(site["calling_convention"])
                or [native_operand(value, types) for value in op["args"]] != site["args"]):
            raise InventoryMismatch(f"SSA indirect call/source operand identity changed: {function['name']}")
        if site["callees"] is not None:
            expected.append({"site": {"function": function["name"], "block": block,
                            "instruction": index, "instruction_count": int(op["op"] == "call"),
                            "source_instruction": site["source_instruction"]},
                             "callees": site["callees"]})
        proofs.append({"source": site, "native_block": block, "native_instruction": index})
    if any(site.get("callees") is not None for site in original["direct_call_sites"]):
        direct_proofs, _, _ = check_direct_call_extensions(original, function, types)
        for proof in direct_proofs:
            site = proof["source_site"]
            if site.get("callees") is None:
                continue
            if site["kind"] not in ("call", "invoke") or site["type"]["variadic"] or site["callee"] not in site["callees"]:
                raise InventoryMismatch(f"unsupported direct callee promise: {function['name']}")
            block, index = proof["native_block"], proof["native_instruction"]
            expected.append({"site": {"function": function["name"], "block": block,
                            "instruction": index, "instruction_count": int(site["kind"] == "call"),
                            "source_instruction": site["source_instruction"]}, "callees": site["callees"]})
            proofs.append({"source": site, "native_block": block, "native_instruction": index, "direct": True})
    expected.sort(key=lambda promise: (promise["site"]["block"], promise["site"]["source_instruction"]))
    if function.get("call_target_constraints", []) != expected:
        raise InventoryMismatch(f"callees target promise/site changed: {function['name']}")
    return proofs


def check_linux_syscall_sites(original, translated, types):
    sites = original.get("linux_syscalls", [])
    operations = [(block["id"], item) for block in translated["blocks"] for item in block["instructions"]
                  if item["operation"]["op"] == "linux_syscall"]
    if len(operations) != len(sites):
        raise InventoryMismatch("missing/extra Linux syscall operation sites")
    proofs = []
    for site, (block, item) in zip(sites, operations):
        operation = item["operation"]
        witness = dict(operation["source"])
        expected_schema = ("ocore.llvm-linux-syscall-source/v2" if site.get("constant_ranges")
                           else "ocore.llvm-linux-syscall-source/v1")
        if witness.pop("schema",None) != expected_schema:
            raise InventoryMismatch("Linux syscall source schema changed")
        signature = witness.pop("signature")
        shape = {"kind":"function", "params":[native_shape(types,ty) for ty in signature["params"]],
                 "result":native_shape(types,signature["result"]),"variadic":signature["variadic"]}
        expected = {key:value for key,value in site.items() if key not in {"signature","extension_attributes","args","result_id","result_type"}}
        if (witness != expected or shape != site["signature"]
                or signature["abi"] != {0:"c",8:"fastcc"}.get(site["calling_convention"])
                or native_extension_vectors(signature) != site["extension_attributes"]
                or block != site["site"]["block"] or item.get("result") is None
                or item["result"]["id"] != site["result_id"]
                or native_shape(types,item["result"]["ty"]) != site["result_type"]
                or [native_operand(value,types) for value in [operation["number"],*operation["arguments"]]] != site["args"]):
            raise InventoryMismatch("Linux syscall original operands/signature/constraints/effects/attributes/srcloc/site changed")
        proofs.append({"site":site["site"],"arity":len(operation["arguments"]),
                       "required_provider":"linux-user-raw-v1","source_witness_complete":True})
    return proofs


def check_fp_register_barrier_sites(original, translated, types):
    sites = original.get("fp_register_barriers", [])
    operations = [(block["id"], item) for block in translated["blocks"]
                  for item in block["instructions"] if item["operation"]["op"] == "fp_register_barrier"]
    if len(sites) != len(operations):
        raise InventoryMismatch("FP register barrier source site inventory changed")
    proofs = []
    for site, (block, item) in zip(sites, operations):
        operation = item["operation"]; witness = dict(operation["source"])
        if witness.pop("schema", None) != "ocore.llvm-fp-register-barrier-source/v1":
            raise InventoryMismatch("FP register barrier source schema changed")
        signature = witness.pop("signature")
        shape = {"kind":"function", "params":[native_shape(types,x) for x in signature["params"]],
                 "result":native_shape(types,signature["result"]),"variadic":signature["variadic"]}
        expected = {key:value for key,value in site.items()
                    if key not in {"signature","extension_attributes","args","result_id","result_type"}}
        if (witness != expected or shape != site["signature"] or signature["abi"] != "c"
                or site["call_opcode"] != 45 or site["fast_math"] != 0 or site["operand_bundles"] != 0
                or native_extension_vectors(signature) != site["extension_attributes"]
                or block != site["site"]["block"] or item.get("result") is None
                or item["result"]["id"] != site["result_id"]
                or native_shape(types,item["result"]["ty"]) != site["result_type"]
                or [native_operand(operation["value"],types)] != site["args"]):
            raise InventoryMismatch("FP register barrier original source contract/operand/site changed")
        proofs.append({"site":site["site"],"source_witness_complete":True,"ordered":True})
    return proofs


def check_inventory(source, module):
    """Fail closed on a missing or changed source interface/static datum.

    Intrinsic declarations remain bindings to owned operations, not unresolved
    provider obligations. Executable body semantics need separate execution
    and lowering tests; this inventory does not replace those gates.
    """
    def require(condition, message):
        if not condition:
            raise InventoryMismatch(message)
    barriers = any(function.get("fp_register_barriers") for function in source["functions"].values())
    if source.get("strict_fp_required") or barriers:
        constrained_mul = any(site["name"] in {"llvm.experimental.constrained.fmul.f32", "llvm.experimental.constrained.fmul.f64"}
                              for function in source["functions"].values() for site in function["intrinsic_sites"])
        expected_strict = ("scalar_dynamic_mul_register_barrier_v1" if barriers else "scalar_dynamic_mul_v1" if constrained_mul else "integer_linux_syscall_v1" if module["target"].get("linux_syscall_profile") == "linux_user_raw_v1" else "integer_only_v1")
        require(module["target"].get("strict_fp_profile") == expected_strict,
                "original strictfp requires its independently verified realization profile")
    types = module["types"]
    # TypeIds, not a fabricated common name or empty field list, distinguish
    # anonymous identified opaque structures. Compare their complete global
    # membership partition independently of either implementation's TypeIds.
    opaque_groups = {}
    for global_ in module.get("globals", []):
        ty = types[global_["ty"]]
        if ty["kind"] == "opaque_struct":
            group = opaque_groups.setdefault(global_["ty"], {"name": ty.get("name"), "globals": []})
            group["globals"].append(global_["name"])
    native_opaque = sorted(
        ({"name": group["name"], "globals": sorted(group["globals"])} for group in opaque_groups.values()),
        key=lambda group: (group["name"] or "", group["globals"]))
    require(native_opaque == source.get("opaque_global_types", []),
            "opaque global type identity partition changed (including anonymous structures)")
    require(module["target"]["data_layout"] == source["data_layout"], "source data layout changed")
    require(module["target"]["triple"] == source["target_triple"], "original source target triple changed")
    require(module["provenance"]["input_sha256"] == source["source"]["sha256"], "original LLVM input identity changed")
    mappings = {"functions": [], "globals": [], "aliases": [], "external_declarations": [],
                "intrinsic_bindings": [], "intrinsic_sites": [], "initializer_references": [], "function_references": [],
                "indirect_control_flow": [], "declaration_extension_vectors": [], "ordinary_direct_call_extensions": [], "call_target_constraints": [],
                "function_source_abi_witnesses": [], "fast_float_source_edges": [], "opaque_external_declarations": []}
    for category in ("functions", "globals", "aliases"):
        native = {item["name"]: item for item in module.get(category, [])}
        require(len(native) == len(module.get(category, [])), f"duplicate native {category}")
        require(set(native) == set(source[category]), f"{category} source/native inventory mismatch: missing={sorted(set(source[category])-set(native))}, extra={sorted(set(native)-set(source[category]))}")
        for name, original in source[category].items():
            translated = native[name]
            require(translated["linkage"] == original["linkage"] and translated.get("visibility", "default") == original["visibility"], f"{category} linkage/visibility changed: {name}")
            if category == "functions":
                signature = translated["signature"]
                shape = {"kind": "function", "params": [native_shape(types, item) for item in signature["params"]],
                         "result": native_shape(types, signature["result"]), "variadic": signature["variadic"]}
                require(shape == original["type"], f"function signature changed: {name}")
                require((translated["entry"] is not None) == original["defined"], f"function definition/declaration changed: {name}")
                require(signature["abi"] == {0: "c", 8: "fastcc"}.get(original["calling_convention"]), f"calling convention changed: {name}")
                require(translated.get("source_abi") == original["source_abi"], f"function source ABI witness changed: {name}")
                mappings["function_source_abi_witnesses"].append({"function": name, "source_abi": original["source_abi"]})
                require(native_extension_vectors(signature) == original["extension_attributes"],
                        f"function integer extension attributes changed: {name}")
                mappings["declaration_extension_vectors"].append({"function": name, "extensions": original["extension_attributes"]})
                check_linux_syscall_sites(original, translated, types)
                check_fp_register_barrier_sites(original, translated, types)
                check_vector_sites(original, translated, types)
                calls, consumed_calls, candidates = check_direct_call_extensions(original, translated, types)
                ordinary_names = {symbol for symbol, item in source["functions"].items() if not item["intrinsic_id"]}
                for block_id, index, result, operation in candidates:
                    callee = operation["callee"]
                    if callee.get("kind") == "symbol" and callee.get("name") in ordinary_names:
                        require((block_id, index) in consumed_calls, f"unaccounted ordinary direct call: {name}")
                mappings["ordinary_direct_call_extensions"].extend(calls)
                for proof in calls:
                    site = proof["source_site"]
                    if (site["calling_convention"] == 8
                            and any(ty.get("kind") == "float" for ty in site["type"]["params"] + [site["type"]["result"]])):
                        mappings["fast_float_source_edges"].append({"caller": name, "callee": site["callee"],
                            "caller_source_abi": original["source_abi"],
                            "callee_source_abi": source["functions"][site["callee"]]["source_abi"],
                            "source_site": site, "native_block": proof["native_block"],
                            "native_instruction": proof["native_instruction"]})

                require(normalized_control_effects(translated.get("control_effects", {})) == original["control_effects"],
                        f"function control effects changed: {name}")
                check_control_call_sites(original, translated, types,
                    {symbol for symbol, item in source["functions"].items() if item["intrinsic_id"]})

                call_proofs = check_call_target_constraints(original, translated, types)
                mappings["call_target_constraints"].append({"function": name, "ssa_call_sites": call_proofs})
                if original["intrinsic_id"]:
                    require(translated.get("intrinsic") == name, f"missing intrinsic semantic binding: {name}")
                    mappings["intrinsic_bindings"].append({"name": name, "llvm_id": original["intrinsic_id"], "mapping": "retained typed intrinsic binding; not an ordinary external provider"})
                else:
                    require(translated.get("intrinsic") is None, f"ordinary function relabeled intrinsic: {name}")
                    if not original["defined"]:
                        mappings["external_declarations"].append(name)
                require(translated.get("alignment", 0) == original["alignment"], f"function alignment changed: {name}")
                def code_leaves(item, path=()):
                    if isinstance(item, dict):
                        if item.get("kind") == "block_address":
                            return [{"path": list(path), "value": native_operand(item, types)}]
                        return [leaf for key, value in item.items()
                                for leaf in code_leaves(value, (*path, key))]
                    if isinstance(item, list):
                        return [leaf for index, value in enumerate(item)
                                for leaf in code_leaves(value, (*path, index))]
                    return []
                native_code_sites = []
                for block in translated["blocks"]:
                    for result_id, operation in [
                            *((instruction["result"]["id"] if instruction.get("result") else None,
                               instruction["operation"]) for instruction in block["instructions"]),
                            ((block["terminator"].get("result") or {}).get("id"), block["terminator"])]:
                        addresses = code_leaves(operation)
                        if addresses:
                            native_code_sites.append({"block": block["id"], "result_id": result_id,
                                "op": operation["op"], "addresses": sorted(addresses, key=lambda item: repr(item["path"]))})
                def pointer_integer_leaves(item, path=()):
                    if isinstance(item, dict):
                        if item.get("kind") == "pointer_to_integer":
                            return [{"path": list(path), "value": native_operand(item, types)}]
                        return [leaf for key, value in item.items() for leaf in pointer_integer_leaves(value, (*path, key))]
                    if isinstance(item, list):
                        return [leaf for index, value in enumerate(item) for leaf in pointer_integer_leaves(value, (*path, index))]
                    return []
                native_pointer_sites = []
                for block in translated["blocks"]:
                    for result_id, operation in [
                            *((instruction["result"]["id"] if instruction.get("result") else None,
                               instruction["operation"]) for instruction in block["instructions"]),
                            ((block["terminator"].get("result") or {}).get("id"), block["terminator"])]:
                        conversions = pointer_integer_leaves(operation)
                        if conversions:
                            native_pointer_sites.append({"block": block["id"], "result_id": result_id,
                                "op": operation["op"], "conversions": sorted(conversions, key=lambda item: repr(item["path"]))})
                require(native_pointer_sites == original.get("constant_pointer_integer_sites", []),
                        f"constant ptrtoint tree/type/source SSA/edge/operand position changed: {name}")
                require(native_code_sites == original.get("block_address_sites", []),
                        f"code-block address operand identity/position changed: {name}")
                native_indirect = [{"block": block["id"],
                    "address": native_operand(block["terminator"]["address"], types),
                    "destinations": block["terminator"]["destinations"]}
                    for block in translated["blocks"] if block["terminator"]["op"] == "indirect_branch"]
                require(native_indirect == original.get("indirect_branches", []),
                        f"indirect branch address/destination list changed: {name}")
                if native_indirect:
                    require([block["id"] for block in translated["blocks"]] == original["block_ids"],
                            f"indirect function original block inventory changed: {name}")
                    expected_phis = []
                    for phi in original["phis"]:
                        unique = {}
                        for edge in phi["incoming"]:
                            require(edge["block"] not in unique or unique[edge["block"]] == edge["value"],
                                    f"conflicting original repeated PHI edge: {name}")
                            unique[edge["block"]] = edge["value"]
                        expected_phis.append({"block": phi["block"], "result_id": phi["result_id"],
                            "result_type": phi["result_type"],
                            "incoming": [{"block": block, "value": value} for block, value in unique.items()]})
                    native_phis = [{"block": block["id"], "result_id": instruction["result"]["id"],
                        "result_type": native_shape(types, instruction["result"]["ty"]),
                        "incoming": [{"block": edge["block"], "value": native_operand(edge["value"], types)}
                                     for edge in instruction["operation"]["incoming"]]}
                        for block in translated["blocks"] for instruction in block["instructions"]
                        if instruction["operation"]["op"] == "phi"]
                    require(native_phis == expected_phis, f"indirect function PHI edge/value inventory changed: {name}")
                    mappings["indirect_control_flow"].append({"function": name,
                        "indirect_branches": native_indirect, "original_phis": original["phis"],
                        "native_phis": native_phis, "native_execution_qualified_here": False})
                consumed, previous, graph_claims, consumed_graph = set(), {}, {}, set()
                for site in original["intrinsic_sites"]:
                    found = intrinsic_mapping(site, translated, types, graph_claims)
                    match = next(((index, instruction) for index, instruction in found
                                  if (site["block"], index) not in consumed and index > previous.get(site["block"], -1)), None)
                    require(match is not None, f"intrinsic site count/order changed: {name}/{site['name']}")
                    consumed.add((site["block"], match[0])); previous[site["block"]] = match[0]
                    if (site["name"].startswith("llvm.usub.sat.i")
                            or re.fullmatch(r"llvm\.bswap\.i(?:16|32|48|64|128)", site["name"])
                            or re.fullmatch(r"llvm\.(floor|ceil|trunc)\.f(32|64|128)", site["name"])
                            or funnel_width(site["name"]) is not None):
                        claimed = graph_claims.get(match[1]["result"]["id"], set())
                        graph_kind = ("saturation" if site["name"].startswith("llvm.usub.sat.i") else
                                      "byte-swap" if site["name"].startswith("llvm.bswap.i") else
                                      "funnel" if funnel_width(site["name"]) is not None else "rounding")
                        require(claimed and not (claimed & consumed_graph)
                                and (not site["name"].startswith("llvm.usub.sat.i") or len(claimed) == 5),
                                f"shared/missing {graph_kind} graph nodes: {name}")
                        consumed_graph.update(claimed)
                    mappings["intrinsic_sites"].append({"function": name, "source": site,
                        "native_block": site["block"], "native_instruction": match[0],
                        "native_operation": match[1]["operation"], "ordinary_external_provider_required": False,
                        "metadata_graph_identity_qualified_here": False})
                # These operations are one-to-one translations of source calls.
                # An extra well-typed unused operation must not evade accounting
                # merely because every required source site was also retained.
                for block in translated["blocks"]:
                    for index, instruction in enumerate(block["instructions"]):
                        if instruction["operation"]["op"] in {
                                "ptr_mask", "integer_count_leading_zeros", "integer_abs", "integer_population_count", "vector_reduce_add", "constrained_float_binary"}:
                            require((block["id"], index) in consumed,
                                    f"unaccounted scalar intrinsic operation: {name}")
                if any(site["name"].startswith("llvm.usub.sat.i")
                       or re.fullmatch(r"llvm\.bswap\.i(?:16|32|48|64|128)", site["name"])
                       or re.fullmatch(r"llvm\.(floor|ceil|trunc)\.f(32|64|128)", site["name"])
                       or funnel_width(site["name"]) is not None
                       for site in original["intrinsic_sites"]):
                    expected_counts = Counter(original["primitive_graph_counts"])
                    expected_counts.update(original["gep_offset_graph_counts"])
                    definitions = {i["result"]["id"]: i for b in translated["blocks"]
                                   for i in b["instructions"] if i.get("result")}
                    for site in original["intrinsic_sites"]:
                        if re.fullmatch(r"llvm\.bswap\.i(?:16|32|48|64|128)", site["name"]):
                            count = int(site["name"].rsplit("i", 1)[1]) // 8
                            expected_counts.update({"freeze": 1, "binary:l_shr": count,
                                "binary:and": count, "binary:shl": count, "binary:or": count - 1})
                        elif site["name"].startswith("llvm.usub.sat.i"):
                            expected_counts.update({"freeze": 2, "binary:sub": 1, "i_cmp": 1, "select": 1})
                        elif re.fullmatch(r"llvm\.(floor|ceil|trunc)\.f(32|64|128)", site["name"]):
                            # All claimed nodes have already matched the exact
                            # independently specified typed DAG. Count only that
                            # proven graph; unused additional graphs stay extra.
                            for value_id in graph_claims[site["result_id"]]:
                                operation = definitions[value_id]["operation"]
                                if operation["op"] == "binary":
                                    expected_counts["binary:" + operation["kind"]] += 1
                                elif operation["op"] == "cast":
                                    expected_counts["cast:" + operation["kind"]] += 1
                                elif operation["op"] in ("freeze", "i_cmp", "select"):
                                    expected_counts[operation["op"]] += 1
                        elif funnel_width(site["name"]) is not None:
                            for value_id in graph_claims[site["result_id"]]:
                                operation = definitions[value_id]["operation"]
                                key = "binary:" + operation["kind"] if operation["op"] == "binary" else operation["op"]
                                expected_counts[key] += 1
                        elif site["name"] in ("llvm.load.relative.i32", "llvm.load.relative.i64"):
                            expected_counts.update({"gep": 2, "cast:s_ext": 2 if site["name"].endswith("i32") else 1})
                    actual_counts = Counter()
                    for block in translated["blocks"]:
                        for instruction in block["instructions"]:
                            operation = instruction["operation"]
                            if operation["op"] == "binary":
                                actual_counts["binary:" + operation["kind"]] += 1
                            elif operation["op"] == "cast":
                                actual_counts["cast:" + operation["kind"]] += 1
                            elif operation["op"] in ("freeze", "i_cmp", "select", "gep"):
                                actual_counts[operation["op"]] += 1
                    require(actual_counts == expected_counts,
                            f"integer intrinsic graph primitive inventory changed: {name}")
                intrinsic_names = {symbol for symbol, item in source["functions"].items() if item["intrinsic_id"]}
                original_refs = set(original["symbol_references"]) - intrinsic_names
                native_refs, pending = set(), [translated["blocks"], translated.get("exception_handling")]
                while pending:
                    item = pending.pop()
                    if isinstance(item, list):
                        pending.extend(item)
                    elif isinstance(item, dict):
                        if item.get("kind") in ("symbol", "symbol_offset"):
                            native_refs.add(item["name"])
                        if item.get("kind") == "block_address":
                            native_refs.add(item["function"])
                        if item.get("op") == "thread_local_address":
                            native_refs.add(item["global"])
                        pending.extend(item.values())
                require(native_refs - intrinsic_names == original_refs, f"function source symbol dependencies changed: {name}")
                mappings["function_references"].append({"function": name, "symbols": sorted(original_refs)})
            else:
                require(native_shape(types, translated["ty"]) == original["type"], f"{category} type changed: {name}")
                if category == "globals":
                    if original["type"]["kind"] == "opaque_struct":
                        require(original["address_space"] == 0 and translated["linkage"] == "external"
                                and translated.get("comdat") is None and translated["initializer"] is None
                                and not translated["thread_local"] and translated.get("tls_model") is None,
                                f"opaque declaration requires direct unsized AS0 external storage: {name}")
                        mappings["opaque_external_declarations"].append({"name": name,
                            "source_type": original["type"], "native_type_id": translated["ty"],
                            "source_identity_partition": source["opaque_global_types"],
                            "address_space": original["address_space"], "alignment": original["alignment"],
                            "storage_layout": None, "sized_provider_required": True})
                    require(translated["alignment"] == original["alignment"], f"global alignment changed: {name}")
                    require(translated["constant"] == original["constant"] and translated["thread_local"] == original["thread_local"] and translated.get("tls_model") == original["tls_model"], f"global storage contract changed: {name}")
                    initializer = translated["initializer"]
                    if initializer is not None:
                        initializer = {"bytes": initializer["bytes"], "relocations": sorted([
                            {**{key: item.get(key) for key in ("offset", "width", "symbol", "addend", "relative_to")},
                             **({"block": item["block"]} if item.get("block") is not None else {})}
                            for item in initializer["relocations"]], key=lambda item: item["offset"])}
                    require(initializer == original["initializer"], f"global initializer bytes/relocations changed: {name}")
                    if initializer:
                        mappings["initializer_references"].append({"global": name, "relocations": initializer["relocations"], "explicit_refinements": original["initializer_refinements"]})
                else:
                    require(original["offset"] == 0 and translated["aliasee"] == original["aliasee"], f"alias target changed: {name}")
            mappings[category].append(name)
    return {"schema": "ocore-independent-source-inventory-v1", "source": source["source"],
            "llvm_library": source["llvm_library"], "mappings": mappings,
            "counts": {kind: len(source[kind]) for kind in ("functions", "globals", "aliases")},
            "provider_resolution_complete": False, "executable_semantics_qualified": False,
            "ordinary_direct_call_extension_accounting": True,
            "other_abi_storage_metadata_semantics_qualified": False}


def audit_native_module(llvm_path, module, library, expected_sha256):
    return check_inventory(Reader(library, expected_sha256).read(llvm_path), module)
