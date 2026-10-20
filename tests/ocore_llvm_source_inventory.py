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
            "GetDataLayoutStr": (c.c_char_p, [P]), "CreateTargetData": (P, [c.c_char_p]),
            "DisposeTargetData": (None, [P]), "ABISizeOfType": (Q, [P, P]),
            "StoreSizeOfType": (Q, [P, P]), "OffsetOfElement": (Q, [P, P, U]),
            "GetValueName2": (P, [P, c.POINTER(Z)]), "PrintValueToString": (P, [P]),
            "GetTypeKind": (c.c_int, [P]), "TypeOf": (P, [P]),
            "GlobalGetValueType": (P, [P]), "GetIntTypeWidth": (U, [P]),
            "GetPointerAddressSpace": (U, [P]), "GetElementType": (P, [P]),
            "GetArrayLength2": (Q, [P]), "CountStructElementTypes": (U, [P]),
            "GetStructElementTypes": (None, [P, c.POINTER(P)]), "IsPackedStruct": (c.c_int, [P]),
            "CountParamTypes": (U, [P]), "GetParamTypes": (None, [P, c.POINTER(P)]),
            "GetReturnType": (P, [P]), "IsFunctionVarArg": (c.c_int, [P]),
            "GetFirstFunction": (P, [P]), "GetNextFunction": (P, [P]),
            "GetFirstGlobal": (P, [P]), "GetNextGlobal": (P, [P]),
            "GetFirstGlobalAlias": (P, [P]), "GetNextGlobalAlias": (P, [P]),
            "AliasGetAliasee": (P, [P]), "GetInitializer": (P, [P]),
            "GetFirstBasicBlock": (P, [P]), "GetNextBasicBlock": (P, [P]),
            "GetFirstInstruction": (P, [P]), "GetNextInstruction": (P, [P]),
            "GetInstructionOpcode": (U, [P]), "GetCalledValue": (P, [P]),
            "GetIntrinsicID": (U, [P]), "GetFunctionCallConv": (U, [P]),
            "HasPersonalityFn": (c.c_int, [P]), "GetPersonalityFn": (P, [P]),
            "CountParams": (U, [P]), "GetParams": (None, [P, c.POINTER(P)]),
            "GetNumArgOperands": (U, [P]), "GetFastMathFlags": (U, [P]),
            "GetLinkage": (c.c_int, [P]), "GetVisibility": (c.c_int, [P]),
            "GetThreadLocalMode": (c.c_int, [P]),
            "GetAlignment": (U, [P]), "IsGlobalConstant": (c.c_int, [P]),
            "IsThreadLocal": (c.c_int, [P]), "GetOperand": (P, [P, U]),
            "GetNumOperands": (c.c_int, [P]), "GetConstOpcode": (U, [P]),
            "GetGEPSourceElementType": (P, [P]), "GetAggregateElement": (P, [P, U]),
            "IntTypeInContext": (P, [P, U]), "ConstBitCast": (P, [P, P]),
        }
        for name in ("ConstantAggregateZero", "ConstantPointerNull", "UndefValue", "PoisonValue",
                     "ConstantInt", "ConstantExpr", "GlobalVariable", "Function", "GlobalAlias"):
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

    def operand(self, value, values):
        ty = self.shape(self.TypeOf(value))
        if value in values:
            return {"kind": "value", "id": values[value]}
        if self.IsAConstantInt(value):
            return {"kind": "int", "type": ty, "bits": str(self.integer(value) % (1 << ty["bits"]))}
        if self.IsAConstantPointerNull(value):
            return {"kind": "null", "type": ty}
        if self.IsAUndefValue(value) or self.IsAPoisonValue(value):
            return {"kind": "undef" if self.IsAUndefValue(value) else "poison", "type": ty}
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
            return {"kind": "compiler_metadata", "printed_sha256": hashlib.sha256(self.printed(value).encode()).hexdigest()}
        raise InventoryMismatch("independent inventory has no intrinsic operand mapping")

    def contract(self, value):
        linkage = {0: "external", 2: "linkonce", 3: "linkonce_odr", 5: "weak", 6: "weak_odr", 8: "internal", 9: "private"}
        visibility = {0: "default", 1: "hidden", 2: "protected"}
        return {"linkage": linkage.get(self.GetLinkage(value), "unsupported"),
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
        if kind == 11:
            return {"kind": "array", "len": self.GetArrayLength2(ty), "element": self.shape(self.GetElementType(ty))}
        if kind == 10:
            fields = (c.c_void_p * self.CountStructElementTypes(ty))()
            self.GetStructElementTypes(ty, fields)
            return {"kind": "struct", "packed": bool(self.IsPackedStruct(ty)), "fields": [self.shape(x) for x in fields]}
        if kind == 9:
            params = (c.c_void_p * self.CountParamTypes(ty))()
            self.GetParamTypes(ty, params)
            return {"kind": "function", "params": [self.shape(x) for x in params],
                    "result": self.shape(self.GetReturnType(ty)), "variadic": bool(self.IsFunctionVarArg(ty))}
        raise InventoryMismatch(f"independent inventory has no type mapping for LLVM kind {kind}")

    def address(self, value):
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

    def read(self, path):
        source = artifact(path)
        raw = Path(path).read_bytes()
        self.context = self.ContextCreate()
        module, error = c.c_void_p(), c.c_void_p()
        buffer = self.CreateMemoryBufferWithMemoryRangeCopy(raw, len(raw), b"independent-inventory")
        self.layout = None
        try:
            if self.ParseIRInContext(self.context, buffer, c.byref(module), c.byref(error)):
                raise InventoryMismatch("independent LLVM parse failed")
            if self.VerifyModule(module, 2, c.byref(error)):
                raise InventoryMismatch("independent LLVM verifier rejected source")
            self.layout = self.CreateTargetData(self.GetDataLayoutStr(module))
            output = {"source": source, "llvm_library": self.library, "data_layout": self.GetDataLayoutStr(module).decode(),
                      "functions": {}, "globals": {}, "aliases": {}}
            for function in self.sequence(self.GetFirstFunction, self.GetNextFunction, module):
                name = self.name(function)
                uses = Counter()
                params = (c.c_void_p * self.CountParams(function))()
                self.GetParams(function, params)
                values = {value: index for index, value in enumerate(params)}
                blocks = list(self.sequence(self.GetFirstBasicBlock, self.GetNextBasicBlock, function))
                for block in blocks:
                    for instruction in self.sequence(self.GetFirstInstruction, self.GetNextInstruction, block):
                        if self.GetTypeKind(self.TypeOf(instruction)) != 0:
                            values[instruction] = len(values)
                sites, references = [], set()
                if self.HasPersonalityFn(function):
                    references.add(self.address(self.GetPersonalityFn(function))[0])
                for block_id, block in enumerate(blocks):
                    for ordinal, instruction in enumerate(self.sequence(self.GetFirstInstruction, self.GetNextInstruction, block)):
                        pending = [self.GetOperand(instruction, index) for index in range(self.GetNumOperands(instruction))]
                        while pending:
                            value = pending.pop()
                            if self.IsAGlobalVariable(value) or self.IsAFunction(value) or self.IsAGlobalAlias(value):
                                references.add(self.name(value))
                            elif self.IsAConstantExpr(value) or (value not in values and self.GetTypeKind(self.TypeOf(value)) in (10, 11)):
                                pending.extend(self.GetOperand(value, index) for index in range(self.GetNumOperands(value)))
                        if self.GetInstructionOpcode(instruction) in (5, 45, 67):
                            callee = self.GetCalledValue(instruction)
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
                                    "fast_math": self.GetFastMathFlags(instruction) if intrinsic_name.startswith("llvm.fabs.") else 0})
                output["functions"][name] = {"type": self.shape(self.GlobalGetValueType(function)),
                    "defined": bool(self.GetFirstBasicBlock(function)), "calling_convention": self.GetFunctionCallConv(function),
                    "intrinsic_id": self.GetIntrinsicID(function), "intrinsic_uses": dict(uses),
                    "intrinsic_sites": sites, "symbol_references": sorted(references), **self.contract(function)}
            for global_ in self.sequence(self.GetFirstGlobal, self.GetNextGlobal, module):
                ty, initial = self.GlobalGetValueType(global_), self.GetInitializer(global_)
                encoded, refinements = self.initializer(initial, ty) if initial else (None, [])
                output["globals"][self.name(global_)] = {"type": self.shape(ty), "initializer": encoded,
                    "constant": bool(self.IsGlobalConstant(global_)), "thread_local": bool(self.IsThreadLocal(global_)),
                    "tls_model": {0: None, 1: "general_dynamic", 2: "local_dynamic", 3: "initial_exec", 4: "local_exec"}.get(self.GetThreadLocalMode(global_), "unsupported"),
                    "initializer_refinements": refinements, **self.contract(global_)}
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
    if ty["kind"] == "array":
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
    return output


def intrinsic_mapping(site, function, types):
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
        if name == "llvm.ptrmask.p0.i64":
            pointer, integer = {"kind": "pointer", "address_space": 0}, {"kind": "int", "bits": 64}
            return (len(args) == 2 and site.get("arg_types") == [pointer, integer]
                    and site.get("result_type") == pointer
                    and result is not None and native_shape(types, result["ty"]) == pointer
                    and op == "ptr_mask" and same("pointer", 0) and same("mask", 1)
                    and operand_type(operation["pointer"]) == pointer
                    and operand_type(operation["mask"]) == integer)
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
        if name.startswith("llvm.fabs."):
            flags = {flag: bool(site["fast_math"] & (1 << bit))
                     for bit, flag in enumerate(("reassoc", "nnan", "ninf", "nsz", "arcp", "contract", "afn"))}
            return op == "float_abs" and same("value", 0) and operation["flags"] == flags
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


def check_inventory(source, module):
    """Fail closed on a missing or changed source interface/static datum.

    Intrinsic declarations remain bindings to owned operations, not unresolved
    provider obligations. Executable body semantics need separate execution
    and lowering tests; this inventory does not replace those gates.
    """
    def require(condition, message):
        if not condition:
            raise InventoryMismatch(message)
    types = module["types"]
    require(module["target"]["data_layout"] == source["data_layout"], "source data layout changed")
    require(module["provenance"]["input_sha256"] == source["source"]["sha256"], "original LLVM input identity changed")
    mappings = {"functions": [], "globals": [], "aliases": [], "external_declarations": [],
                "intrinsic_bindings": [], "intrinsic_sites": [], "initializer_references": [], "function_references": []}
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
                if original["intrinsic_id"]:
                    require(translated.get("intrinsic") == name, f"missing intrinsic semantic binding: {name}")
                    mappings["intrinsic_bindings"].append({"name": name, "llvm_id": original["intrinsic_id"], "mapping": "retained typed intrinsic binding; not an ordinary external provider"})
                else:
                    require(translated.get("intrinsic") is None, f"ordinary function relabeled intrinsic: {name}")
                    if not original["defined"]:
                        mappings["external_declarations"].append(name)
                require(translated.get("alignment", 0) == original["alignment"], f"function alignment changed: {name}")
                consumed, previous = set(), {}
                for site in original["intrinsic_sites"]:
                    found = intrinsic_mapping(site, translated, types)
                    match = next(((index, instruction) for index, instruction in found
                                  if (site["block"], index) not in consumed and index > previous.get(site["block"], -1)), None)
                    require(match is not None, f"intrinsic site count/order changed: {name}/{site['name']}")
                    consumed.add((site["block"], match[0])); previous[site["block"]] = match[0]
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
                                "ptr_mask", "integer_count_leading_zeros", "integer_abs"}:
                            require((block["id"], index) in consumed,
                                    f"unaccounted scalar intrinsic operation: {name}")
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
                        if item.get("op") == "thread_local_address":
                            native_refs.add(item["global"])
                        pending.extend(item.values())
                require(native_refs - intrinsic_names == original_refs, f"function source symbol dependencies changed: {name}")
                mappings["function_references"].append({"function": name, "symbols": sorted(original_refs)})
            else:
                require(native_shape(types, translated["ty"]) == original["type"], f"{category} type changed: {name}")
                if category == "globals":
                    require(translated["alignment"] == original["alignment"], f"global alignment changed: {name}")
                    require(translated["constant"] == original["constant"] and translated["thread_local"] == original["thread_local"] and translated.get("tls_model") == original["tls_model"], f"global storage contract changed: {name}")
                    initializer = translated["initializer"]
                    if initializer is not None:
                        initializer = {"bytes": initializer["bytes"], "relocations": sorted([
                            {key: item.get(key) for key in ("offset", "width", "symbol", "addend", "relative_to")}
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
            "provider_resolution_complete": False, "executable_semantics_qualified": False}


def audit_native_module(llvm_path, module, library, expected_sha256):
    return check_inventory(Reader(library, expected_sha256).read(llvm_path), module)
