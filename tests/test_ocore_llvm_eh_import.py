"""Whole LLVM Itanium EH structure and honest source/API failure boundaries.

The original C++/Rust producers emit complete units; no input IR is retargeted
or filtered. These tests do not link providers, execute handlers, or establish
native unwinding, compiler/runtime completeness or dependency closure.
"""

import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory
from tests import test_ocore_llvm_aggregates as aggregates
from tests import test_ocore_llvm_noundef_metadata as noundef


TRIPLES = baseline.TRIPLES
PERSONALITY = "declare i32 @personality(i32, i32, i64, ptr, ptr)\n"
TYPEID = "llvm.eh.typeid.for.p0"


def cleanup(personality="@personality", result="{ptr, i32}", clause="cleanup", callee="@may_throw"):
    return f"""{PERSONALITY}
declare i64 @may_throw(i64)
@cold_global = constant i64 43, align 8
define i64 @entry(i64 %arg) personality ptr {personality} {{
entry:
  %result = invoke i64 {callee}(i64 %arg) to label %normal unwind label %unwind
normal:
  ret i64 %result
unwind:
  %exception = landingpad {result} {clause}
  resume {result} %exception
}}
"""


class LlvmEHImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()
        cls.library_artifact = noundef.artifact(cls.library)
        cls.worker_source = Path(importer.__file__).read_bytes()
        cls.test_source = Path(__file__).read_bytes()

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_EH_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-eh-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.api = importer.LLVM(self.library, importer.PINNED_SHA256)
        self.sequence, self.records = 0, []
        for name, result, args in (
            ("LLVMGetPersonalityFn", importer.P, [importer.P]),
            ("LLVMGetNormalDest", importer.P, [importer.P]),
            ("LLVMGetUnwindDest", importer.P, [importer.P]),
            ("LLVMGetNumClauses", importer.U, [importer.P]),
            ("LLVMGetClause", importer.P, [importer.P, importer.U]),
            ("LLVMIsCleanup", importer.B, [importer.P]),
        ):
            fn = getattr(self.api.lib, name)
            fn.restype, fn.argtypes = result, args
            setattr(self.api, name.removeprefix("LLVM"), fn)

    original = noundef.LlvmNoundefMetadataTests.original
    llvm_shape = noundef.LlvmNoundefMetadataTests.llvm_shape
    write = noundef.LlvmNoundefMetadataTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)
    realization = staticmethod(aggregates.LlvmAggregateImportTests.realization)
    shape = classmethod(aggregates.LlvmAggregateImportTests.shape.__func__)
    rust_compiler = aggregates.LlvmAggregateImportTests.rust_compiler

    def tearDown(self):
        worker, test = self.directory / "worker-source.py", self.directory / "test-source.py"
        worker.write_bytes(self.worker_source)
        test.write_bytes(self.test_source)
        report = {"scope": "whole original LLVM Itanium EH source/API conformance", "test_id": self.id(),
                  "worker_source": noundef.artifact(worker), "test_source": noundef.artifact(test),
                  "llvm_library": self.library_artifact, "records": self.records,
                  "native_unwinding_verified": False, "external_provider_verified": False,
                  "runtime_complete": False, "compiler_implementation_lowered": False,
                  "dependency_closure_complete": False}
        (self.directory / "eh-source-conformance.json").write_text(json.dumps(report, indent=2) + "\n")
        self.assertEqual(Path(importer.__file__).read_bytes(), self.worker_source)
        self.assertEqual(Path(__file__).read_bytes(), self.test_source)

    def raw_attributes(self, owner, index, call=False):
        a = self.api
        count = (a.GetCallSiteAttributeCount if call else a.GetAttributeCountAtIndex)(owner, index)
        values = (importer.P * count)()
        (a.GetCallSiteAttributes if call else a.GetAttributesAtIndex)(owner, index, values)
        return values

    def signature(self, ty, owner, call=False):
        a = self.api
        result_type = a.GetReturnType(ty)
        params = (importer.P * a.CountParamTypes(ty))()
        a.GetParamTypes(ty, params)
        extensions = {a.GetEnumAttributeKindForName(name.encode(), len(name)): name for name in ("signext", "zeroext")}
        def attributes(index):
            return sorted(extensions[a.GetEnumAttributeKind(attr)] for attr in self.raw_attributes(owner, index, call)
                          if a.IsEnumAttribute(attr) and a.GetEnumAttributeKind(attr) in extensions)
        result = {"result": {"kind": "void"} if a.GetTypeKind(result_type) == 0 else self.llvm_shape(result_type),
                  "params": [self.llvm_shape(param) for param in params], "variadic": bool(a.IsFunctionVarArg(ty)),
                  "convention": (a.GetInstructionCallConv if call else a.GetFunctionCallConv)(owner),
                  "result_attributes": attributes(0), "param_attributes": [attributes(i + 1) for i in range(len(params))],
                  "return_storage": None}
        sret = a.GetEnumAttributeKindForName(b"sret", 4)
        for index in range(len(params)):
            for attr in self.raw_attributes(owner, index + 1, call):
                if a.IsTypeAttribute(attr) and a.GetEnumAttributeKind(attr) == sret:
                    result["return_storage"] = {"param": index, "type": self.llvm_shape(a.GetTypeAttributeValue(attr))}
        return result

    def native_signature(self, module, signature):
        storage = signature.get("return_storage")
        return {"result": self.shape(module, signature["result"]),
                "params": [self.shape(module, ty) for ty in signature["params"]],
                "variadic": signature["variadic"], "convention": {"c": 0, "fastcc": 8}[signature["abi"]],
                "result_attributes": signature["result_attributes"], "param_attributes": signature["param_attributes"],
                "return_storage": None if storage is None else {"param": storage["param"], "type": self.shape(module, storage["ty"])}}

    @staticmethod
    def strip_types(operand):
        return {key: [LlvmEHImportTests.strip_types(child) for child in value] if key == "elements" else value
                for key, value in operand.items() if key != "ty"}

    def operand(self, value, ids):
        a = self.api
        if value in ids:
            return {"kind": "value", "id": ids[value]}
        if a.IsAConstantPointerNull(value):
            return {"kind": "null"}
        if a.IsAConstantInt(value) and a.GetIntTypeWidth(a.TypeOf(value)) <= 64:
            return {"kind": "int", "bits": str(a.ConstIntGetZExtValue(value))}
        if a.IsAFunction(value) or a.IsAGlobalVariable(value) or a.IsAGlobalAlias(value):
            return {"kind": "symbol", "name": a.name(value)}
        if a.IsAConstantExpr(value):
            return {"original_constant_opcode": a.GetConstOpcode(value)}
        return {"original_type": self.llvm_shape(a.TypeOf(value))}

    def oracle(self, path):
        a = self.api
        result = {"functions": [], "definitions": [], "globals": [], "aliases": [], "bodies": {}, "signatures": {}}
        with self.original(path) as (_, module):
            result["globals"] = [a.name(value) for value in a.sequence(a.GetFirstGlobal, a.GetNextGlobal, module)]
            result["aliases"] = [a.name(value) for value in a.sequence(a.GetFirstGlobalAlias, a.GetNextGlobalAlias, module)]
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                name = a.name(function)
                result["functions"].append(name)
                result["signatures"][name] = self.signature(a.GlobalGetValueType(function), function)
                params = (importer.P * a.CountParams(function))()
                a.GetParams(function, params)
                ids = {value: index for index, value in enumerate(params)}
                blocks = list(a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function))
                block_ids = {value: index for index, value in enumerate(blocks)}
                if blocks:
                    result["definitions"].append(name)
                for block in blocks:
                    for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                        if a.GetTypeKind(a.TypeOf(instruction)) != 0:
                            ids[instruction] = len(ids)
                body = {"personality": self.operand(a.GetPersonalityFn(function), ids) if a.HasPersonalityFn(function) else None,
                        "calls": [], "invokes": [], "landing_pads": [], "resumes": [], "accesses": []}
                result["bodies"][name] = body
                for block_id, block in enumerate(blocks):
                    for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                        opcode = a.GetInstructionOpcode(instruction)
                        if opcode in (45, 5):
                            callee = a.GetCalledValue(instruction)
                            item = {"block": block_id, "callee": self.operand(callee, ids),
                                "signature": self.signature(a.GetCalledFunctionType(instruction), instruction, True),
                                "args": [self.operand(a.GetOperand(instruction, i), ids) for i in range(a.GetNumArgOperands(instruction))],
                                "result": None if a.GetTypeKind(a.TypeOf(instruction)) == 0 else {"id": ids[instruction], "type": self.llvm_shape(a.TypeOf(instruction))}}
                            if opcode == 5:
                                item.update(normal=block_ids[a.GetNormalDest(instruction)], unwind=block_ids[a.GetUnwindDest(instruction)])
                                body["invokes"].append(item)
                            else:
                                body["calls"].append(item)
                        elif opcode == 59:
                            clauses = []
                            for i in range(a.GetNumClauses(instruction)):
                                clause = a.GetClause(instruction, i)
                                if a.GetTypeKind(a.TypeOf(clause)) == 12:
                                    clauses.append({"kind": "catch", "typeinfo": self.operand(clause, ids)})
                                else:
                                    clauses.append({"kind": "filter", "typeinfos": [self.operand(a.GetAggregateElement(clause, j), ids)
                                        for j in range(a.GetArrayLength2(a.TypeOf(clause)))]})
                            body["landing_pads"].append({"block": block_id, "result": {"id": ids[instruction], "type": self.llvm_shape(a.TypeOf(instruction))},
                                                        "cleanup": bool(a.IsCleanup(instruction)), "clauses": clauses})
                        elif opcode == 58:
                            body["resumes"].append({"block": block_id, "value": self.operand(a.GetOperand(instruction, 0), ids)})
                        elif opcode in (27, 28):
                            body["accesses"].append({"op": "load" if opcode == 27 else "store", "volatile": bool(a.GetVolatile(instruction)),
                                                    "alignment": a.GetAlignment(instruction)})
        return result

    def assert_original(self, path, module):
        original = self.oracle(path)
        self.assertEqual(module["provenance"]["input_sha256"], noundef.artifact(path)["sha256"])
        for category, plural in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
            self.assertEqual([item["name"] for item in module[plural]], original[plural])
            self.assertEqual(module["provenance"]["source_" + category + "_count"], len(original[plural]))
        self.assertEqual([fn["name"] for fn in module["functions"] if fn["entry"] is not None], original["definitions"])
        for function in module["functions"]:
            name, source = function["name"], original["bodies"][function["name"]]
            self.assertEqual(self.native_signature(module, function["signature"]), original["signatures"][name])
            eh = function.get("exception_handling")
            self.assertEqual(None if eh is None else self.strip_types(eh["personality"]), source["personality"])
            if eh:
                self.assertEqual(eh["model"], "itanium_dwarf_v1")
            calls, invokes, pads, resumes, accesses, typeids = [], [], [], [], [], []
            for block in function["blocks"]:
                for instruction in block["instructions"]:
                    op, value = instruction["operation"], instruction["result"]
                    if op["op"] == "call":
                        calls.append({"block": block["id"], "callee": self.strip_types(op["callee"]),
                                      "signature": self.native_signature(module, op["signature"]), "args": [self.strip_types(arg) for arg in op["args"]],
                                      "result": None if value is None else {"id": value["id"], "type": self.shape(module, value["ty"])}})
                    elif op["op"] == "landing_pad":
                        clauses = [{"kind": clause["kind"], **({"typeinfo": self.strip_types(clause["typeinfo"])} if clause["kind"] == "catch"
                                  else {"typeinfos": [self.strip_types(child) for child in clause["typeinfos"]]})} for clause in op["clauses"]]
                        pads.append({"block": block["id"], "result": {"id": value["id"], "type": self.shape(module, value["ty"])},
                                     "cleanup": op["cleanup"], "clauses": clauses})
                    elif op["op"] in ("load", "store"):
                        accesses.append({"op": op["op"], "volatile": op["volatile"], "alignment": op["alignment"]})
                    elif op["op"] == "eh_type_id":
                        typeids.append({"block": block["id"], "typeinfo": self.strip_types(op["typeinfo"]),
                                        "result": {"id": value["id"], "type": self.shape(module, value["ty"])}})
                term = block["terminator"]
                if term["op"] == "invoke":
                    value = term["result"]
                    invokes.append({"block": block["id"], "callee": self.strip_types(term["callee"]),
                        "signature": self.native_signature(module, term["signature"]), "args": [self.strip_types(arg) for arg in term["args"]],
                        "result": None if value is None else {"id": value["id"], "type": self.shape(module, value["ty"])},
                        "normal": term["normal"], "unwind": term["unwind"]})
                elif term["op"] == "resume":
                    resumes.append({"block": block["id"], "value": self.strip_types(term["value"])})
            self.assertEqual(invokes, source["invokes"])
            self.assertEqual(pads, source["landing_pads"])
            self.assertEqual(resumes, source["resumes"])
            self.assertEqual(accesses, source["accesses"])
            ordinary = [call for call in source["calls"] if call["callee"].get("name", "").startswith("llvm.") is False]
            self.assertEqual(calls, ordinary)
            intrinsic_source = [call for call in source["calls"] if call not in ordinary]
            self.assertEqual(typeids, [{"block": call["block"], "typeinfo": call["args"][0], "result": call["result"]}
                                      for call in intrinsic_source if call["callee"]["name"] == TYPEID])
            expected_ops = []
            for call in intrinsic_source:
                callee = call["callee"]["name"]
                if callee == TYPEID:
                    expected_ops.append("eh_type_id")
                elif callee.startswith(("llvm.memcpy.", "llvm.memmove.")):
                    expected_ops.append("memory_copy")
                elif callee.startswith("llvm.memset."):
                    expected_ops.append("memory_set")
                elif callee.startswith("llvm.lifetime."):
                    expected_ops.append("lifetime")
                elif callee == "llvm.assume":
                    expected_ops.append("assume")
                elif callee == "llvm.trap":
                    expected_ops.append("trap")
                else:
                    self.fail(f"original intrinsic {callee} needs an explicit effect oracle")
            mapped = {"eh_type_id", "memory_copy", "memory_set", "lifetime", "assume", "trap"}
            self.assertEqual([op["op"] for op in self.operations(function) if op["op"] in mapped], expected_ops)
            notes = module["provenance"]["refinements"]
            for invoke in invokes:
                prefix = f"{name}: invoke block {invoke['block']} retains original callee, raw callsite signature/CC/arguments"
                self.assertTrue(any(note.startswith(prefix) and "only on the normal edge" in note for note in notes))
        return original

    def accept(self, path, **kwargs):
        before = noundef.artifact(path)
        module = importer.import_module(path, library_path=self.library, **kwargs)
        original = self.assert_original(path, module)
        output = path.with_name(path.name + ".native.json")
        output.write_text(json.dumps(module, indent=2) + "\n")
        self.assertEqual(noundef.artifact(path), before)
        self.records.append({"input": before, "outcome": "accepted", "original_inventory": original, "module": noundef.artifact(output)})
        return module

    def reject(self, path, stage="import", diagnostic=None, symbol=None):
        before = noundef.artifact(path)
        if stage == "import":
            with self.original(path):
                pass
        with self.assertRaises(importer.ImportFailure) as raised:
            importer.import_module(path, library_path=self.library)
        error = raised.exception
        self.assertEqual(error.stage, stage, "a parser/verifier/tool failure is not an importer guard")
        if diagnostic:
            self.assertIn(diagnostic, str(error))
        if symbol:
            self.assertEqual(error.symbol, symbol)
        self.assertEqual(noundef.artifact(path), before)
        self.records.append({"input": before, "outcome": "rejected", "error": {"stage": error.stage, "symbol": error.symbol, "message": str(error)}})

    def pair(self, body, triple, accepted=True, diagnostic=None, symbol=None):
        source = self.write(body, triple)
        paths = source, self.bitcode(source)
        if not accepted:
            for path in paths:
                with self.subTest(triple=triple, format=path.suffix):
                    self.reject(path, diagnostic=diagnostic, symbol=symbol)
            return []
        modules = [self.accept(path) for path in paths]
        self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        return modules

    def invalid_pair(self, body, triple, diagnostic):
        source = self.write(body, triple)
        a = self.api
        context, buffer, module, message, error, serialized = a.ContextCreate(), None, importer.P(), importer.P(), importer.P(), None
        try:
            data = source.read_bytes()
            buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"verifier-negative-original")
            self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0)
            self.assertNotEqual(a.VerifyModule(module, 2, C.byref(message)), 0)
            self.assertIn(diagnostic, C.string_at(message).decode())
            serialized = a.WriteBitcodeToMemoryBuffer(module)
            binary = source.with_suffix(".bc")
            binary.write_bytes(C.string_at(a.GetBufferStart(serialized), a.GetBufferSize(serialized)))
        finally:
            if serialized: a.DisposeMemoryBuffer(serialized)
            if message: a.DisposeMessage(message)
            if error: a.DisposeMessage(error)
            if module: a.DisposeModule(module)
            if buffer: a.DisposeMemoryBuffer(buffer)
            if context: a.ContextDispose(context)
        for path in (source, binary):
            self.reject(path, "llvm-verify", diagnostic)

    def test_cleanup_invoke_result_normal_edge_personality_and_resume_keep_full_cold_inventory_all_three_isas_ll_bc(self):
        body = cleanup().replace("normal:\n", "normal:\n  store volatile i64 %result, ptr @effect, align 8\n")
        body += "@effect = global i64 0, align 8\ndeclare void @cold_provider(ptr)\ndefine i64 @cold() { ret i64 7 }\n"
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                function = self.function(module, "entry")
                invoke = function["blocks"][0]["terminator"]
                self.assertEqual((invoke["op"], invoke["normal"], invoke["unwind"]), ("invoke", 1, 2))
                self.assertEqual(function["blocks"][1]["terminator"]["value"], {"kind": "value", "id": invoke["result"]["id"]})
                self.assertEqual(self.operations(function)[1]["clauses"], [])
                self.assertEqual(len(module["functions"]), 5)

    def test_direct_alias_indirect_c_and_fastcc_invokes_retain_raw_call_abi_extensions_all_three_isas_ll_bc(self):
        body = PERSONALITY + """
+define signext i8 @narrow(i8 zeroext %x) { ret i8 %x }
+@narrow_alias = alias i8(i8), ptr @narrow
+define fastcc i64 @fast(i64 %x) { ret i64 %x }
+define i8 @c_calls(i8 %x, ptr %callback) personality ptr @personality {
+entry:
+  %a = invoke signext i8 @narrow_alias(i8 zeroext %x) to label %second unwind label %unwind
+second:
+  %b = invoke signext i8 %callback(i8 zeroext %a) to label %normal unwind label %unwind
+normal: ret i8 %b
+unwind: %ex = landingpad {ptr, i32} cleanup
+  resume {ptr, i32} %ex
+}
+define i64 @fast_calls(i64 %x, ptr %callback) personality ptr @personality {
+entry:
+  %a = invoke fastcc i64 @fast(i64 %x) to label %second unwind label %unwind
+second:
+  %b = invoke fastcc i64 %callback(i64 %a) to label %normal unwind label %unwind
+normal: ret i64 %b
+unwind: %ex = landingpad {ptr, i32} cleanup
+  resume {ptr, i32} %ex
+}
+""".replace("\n+", "\n")
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                c = self.function(module, "c_calls")
                self.assertEqual(c["blocks"][0]["terminator"]["signature"]["result_attributes"], ["signext"])
                self.assertEqual(c["blocks"][0]["terminator"]["signature"]["param_attributes"], [["zeroext"]])
                fast = self.function(module, "fast_calls")
                self.assertEqual([block["terminator"]["signature"]["abi"] for block in fast["blocks"] if block["terminator"]["op"] == "invoke"], ["fastcc", "fastcc"])

    def test_aggregate_result_and_explicit_sret_both_supported_parameter_positions_preserve_original_signatures_all_three_isas_ll_bc(self):
        body = PERSONALITY + """
%R = type {i7, [2 x i33]}
declare %R @aggregate(i64)
declare void @sret0(ptr sret(%R), i64)
declare void @sret1(i64, ptr sret(%R))
define %R @aggregate_entry(i64 %x) personality ptr @personality {
entry: %r = invoke %R @aggregate(i64 %x) to label %normal unwind label %unwind
normal: ret %R %r
unwind: %ex = landingpad {ptr, i32} cleanup
  resume {ptr, i32} %ex
}
define void @storage(ptr %out, i64 %x) personality ptr @personality {
entry: invoke void @sret0(ptr sret(%R) align 8 %out, i64 %x) to label %second unwind label %unwind
second: invoke void @sret1(i64 %x, ptr sret(%R) align 8 %out) to label %normal unwind label %unwind
normal: ret void
unwind: %ex = landingpad {ptr, i32} cleanup
  resume {ptr, i32} %ex
}
"""
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                invokes = [block["terminator"] for block in self.function(module, "storage")["blocks"] if block["terminator"]["op"] == "invoke"]
                self.assertEqual([invoke["signature"]["return_storage"]["param"] for invoke in invokes], [0, 1])
                self.assertTrue(all(invoke["result"] is None for invoke in invokes))
                result = self.function(module, "aggregate_entry")["blocks"][0]["terminator"]["result"]
                self.assertEqual(self.shape(module, result["ty"])["kind"], "struct")

    def test_ordered_duplicate_catches_filters_null_catchall_and_empty_filter_remain_distinct_all_three_isas_ll_bc(self):
        body = cleanup(clause="cleanup catch ptr @type_b filter [3 x ptr] [ptr @type_b, ptr @type_a, ptr @type_b] catch ptr null filter [0 x ptr] zeroinitializer catch ptr @type_a")
        body += "@type_a = constant i8 1\n@type_b = constant i8 2\n"
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                pad = self.operations(self.function(module, "entry"))[0]
                self.assertEqual([clause["kind"] for clause in pad["clauses"]], ["catch", "filter", "catch", "filter", "catch"])
                self.assertEqual([child["name"] for child in pad["clauses"][1]["typeinfos"]], ["type_b", "type_a", "type_b"])
                self.assertEqual(pad["clauses"][2]["typeinfo"]["kind"], "null")
                self.assertEqual(pad["clauses"][3]["typeinfos"], [])
                self.assertTrue(pad["cleanup"])
                for clause in ("catch ptr null", "filter [0 x ptr] zeroinitializer"):
                    for only in self.pair(cleanup(clause=clause), triple):
                        self.assertFalse(self.operations(self.function(only, "entry"))[0]["cleanup"])

    def test_named_landingpad_pair_extract_insert_and_resume_keep_exact_original_aggregate_identity_all_three_isas_ll_bc(self):
        body = cleanup(result="%Pair").replace("resume %Pair %exception", "%pointer = extractvalue %Pair %exception, 0\n  %selector = extractvalue %Pair %exception, 1\n  %a = insertvalue %Pair poison, ptr %pointer, 0\n  %b = insertvalue %Pair %a, i32 %selector, 1\n  resume %Pair %b")
        body = "%Pair = type {ptr, i32}\n" + body
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                function = self.function(module, "entry")
                instructions = self.instructions(function)
                self.assertEqual([row["operation"]["op"] for row in instructions], ["landing_pad", "extract_value", "extract_value", "insert_value", "insert_value"])
                self.assertEqual(instructions[0]["result"]["ty"], instructions[-1]["result"]["ty"])
                self.assertEqual(function["blocks"][2]["terminator"]["value"], {"kind": "value", "id": instructions[-1]["result"]["id"]})

    def test_metadata_only_variadic_personality_and_actual_callback_self_personality_preserve_names_and_raw_shapes_all_three_isas_ll_bc(self):
        metadata = cleanup().replace(PERSONALITY, 'declare i32 @personality(...) unnamed_addr nonlazybind\n')
        actual = cleanup(personality="@personality_alias").replace(PERSONALITY, """
define i32 @personality(i32 %version, i32 %actions, i64 %class, ptr %exception, ptr %context) personality ptr @personality {
  ret i32 8
}
@personality_alias = alias i32(i32,i32,i64,ptr,ptr), ptr @personality
""")
        for triple in TRIPLES:
            for module in self.pair(metadata, triple):
                declaration = self.function(module, "personality")
                self.assertTrue(declaration["signature"]["variadic"])
                self.assertEqual(declaration["signature"]["params"], [])
                self.assertIsNone(declaration["entry"])
                self.assertTrue(any(note.startswith("personality: retained metadata-only personality declaration i32(...)") for note in module["provenance"]["refinements"]))
            for module in self.pair(actual, triple):
                self.assertEqual(self.function(module, "entry")["exception_handling"]["personality"]["name"], "personality_alias")
                provider = self.function(module, "personality")
                self.assertEqual(provider["exception_handling"]["personality"]["name"], "personality")
                self.assertFalse(provider["signature"]["variadic"])
                self.assertEqual(len(provider["signature"]["params"]), 5)

    def test_metadata_only_declaration_use_graph_rejects_ordinary_calls_addresses_nested_globals_and_typeinfo_all_three_isas_ll_bc(self):
        base = cleanup().replace(PERSONALITY, "declare i32 @personality(...)\n")
        suffixes = (
            "define i32 @cold() { %x = call i32 (...) @personality()\nret i32 %x }\n",
            "define ptr @cold() { ret ptr @personality }\n",
            "@cold_pointer = constant ptr @personality\n",
            "@cold_nested = constant {i8,[2 x ptr]} {i8 7,[2 x ptr] [ptr null,ptr @personality]}\n",
            "define ptr @cold(i1 %flag) {\nentry: br i1 %flag, label %a, label %b\na: br label %join\nb: br label %join\njoin: %p = phi ptr [@personality, %a], [null, %b]\nret ptr %p }\n",
        )
        for triple in TRIPLES:
            for suffix in suffixes:
                self.pair(base + suffix, triple, False)
            self.pair(base.replace("landingpad {ptr, i32} cleanup", "landingpad {ptr, i32} catch ptr @personality"), triple, False)

    def test_wrong_personality_shapes_conventions_extension_attributes_dynamic_offsets_and_nonfunction_roots_fail_closed_all_three_isas_ll_bc(self):
        declarations = ("declare i64 @personality(...)\n", "declare i32 @personality(i64,...)\n",
                        "define i32 @personality(...) { ret i32 0 }\n", "declare fastcc i32 @personality(i32,i32,i64,ptr,ptr)\n",
                        "declare signext i32 @personality(...)\n", "declare i32 @personality(i32,i32,i64,ptr addrspace(1),ptr)\n")
        for triple in TRIPLES:
            for declaration in declarations:
                self.pair(cleanup().replace(PERSONALITY, declaration), triple, False)
            for operand, suffix in (("inttoptr (i64 7 to ptr)", ""),
                                    ("getelementptr (i8, ptr @personality, i64 1)", ""),
                                    ("@not_callable", "@not_callable = global i8 7\n")):
                self.pair(cleanup(personality=operand) + suffix, triple, False)

    def test_verified_noncanonical_landingpad_and_matching_resume_types_reject_profile_not_llvm_validation_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for result, diagnostic in (("i64", "landingpad requires original unpacked {ptrAS0,i32}"),
                                       ("[2 x ptr]", "landingpad requires original unpacked {ptrAS0,i32}"),
                                       ("<{ptr, i32}>", "landingpad requires original unpacked {ptrAS0,i32}"),
                                       ("{ptr, i64}", "landingpad requires original unpacked {ptrAS0,i32}"),
                                       ("{ptr, i33}", "landingpad requires original unpacked {ptrAS0,i32}"),
                                       ("{ptr addrspace(1), i32}", "unsupported pointer address space 1")):
                self.pair(cleanup(result=result), triple, False, diagnostic)

    def test_typeinfo_nonzero_offsets_literal_addresses_poison_and_nonempty_null_filters_remain_unsupported_all_three_isas_ll_bc(self):
        clauses = ("catch ptr inttoptr (i64 7 to ptr)", "catch ptr getelementptr (i8, ptr @typeinfo, i64 1)",
                   "catch ptr undef", "catch ptr poison", "catch ptr addrspace(1) null",
                   "filter [1 x ptr] zeroinitializer", "filter [2 x ptr] [ptr @typeinfo, ptr null]",
                   "filter [1 x i64] zeroinitializer", "filter [1 x ptr addrspace(1)] zeroinitializer")
        for triple in TRIPLES:
            for clause in clauses:
                self.pair(cleanup(clause=clause) + "@typeinfo = constant i8 7\n", triple, False)
            self.pair(cleanup(clause="catch ptr @llvm.eh.catch.all.value") + "@llvm.eh.catch.all.value = constant ptr null\n", triple, False)

    def test_typeid_exact_parsed_overload_name_and_function_local_operations_require_no_personality_or_provider_all_three_isas_ll_bc(self):
        body = """
@type_a = constant i8 1
@type_b = constant i8 2
declare i32 @llvm.eh.typeid.for(ptr)
define i32 @first() {
  %a = call i32 @llvm.eh.typeid.for(ptr @type_a)
  %b = call i32 @llvm.eh.typeid.for(ptr @type_a)
  %sum = add i32 %a, %b
  ret i32 %sum
}
define i32 @second() {
  %b = call i32 @llvm.eh.typeid.for(ptr @type_b)
  %n = call i32 @llvm.eh.typeid.for(ptr null)
  %sum = add i32 %b, %n
  ret i32 %sum
}
"""
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                declaration = self.function(module, TYPEID)
                self.assertEqual(declaration["intrinsic"], TYPEID)
                self.assertNotIn("llvm.eh.typeid.for", {fn["name"] for fn in module["functions"]})
                for name in ("first", "second"):
                    function = self.function(module, name)
                    self.assertIsNone(function.get("exception_handling"))
                    self.assertEqual([op["op"] for op in self.operations(function)], ["eh_type_id", "eh_type_id", "binary"])
                self.assertEqual(self.operations(self.function(module, "first"))[0], self.operations(self.function(module, "first"))[1])

    def test_typeid_dynamic_and_unsafe_constant_roots_and_callsite_abi_extensions_reject_after_llvm_verification_all_three_isas_ll_bc(self):
        base = "declare i32 @llvm.eh.typeid.for(ptr)\n@typeinfo = constant i8 7\ndefine i32 @bad(ptr %p) { %s = call i32 @llvm.eh.typeid.for(ptr VALUE)\nret i32 %s }\n"
        for triple in TRIPLES:
            for value in ("%p", "inttoptr (i64 7 to ptr)", "getelementptr (i8, ptr @typeinfo, i64 1)", "undef", "poison"):
                self.pair(base.replace("VALUE", value), triple, False)
            self.pair(base.replace("VALUE", "@typeinfo").replace("call i32", "call zeroext i32"), triple, False)

    def test_normal_edge_phi_shared_unwind_previous_result_and_self_normal_loop_preserve_original_ssa_all_three_isas_ll_bc(self):
        shared = cleanup().replace("%result = invoke", "%first = invoke").replace("to label %normal", "to label %second", 1)
        shared = shared.replace("normal:\n  ret i64 %result", "second:\n  %result = invoke i64 @may_throw(i64 %first) to label %normal unwind label %unwind\nnormal:\n  ret i64 %result")
        shared = shared.replace("unwind:\n", "unwind:\n  %safe = phi i64 [%arg, %entry], [%first, %second]\n")
        bypass = cleanup().replace("define i64 @entry(i64 %arg)", "define i64 @entry(i64 %arg, i1 %flag)")
        bypass = bypass.replace("entry:\n  %result", "entry:\n  br i1 %flag, label %call, label %bypass\ncall:\n  %result")
        bypass = bypass.replace("normal:\n  ret i64 %result", "bypass:\n  br label %normal\nnormal:\n  %safe = phi i64 [%result, %call], [7, %bypass]\n  ret i64 %safe")
        loop = cleanup().replace("entry:\n  %result = invoke i64 @may_throw(i64 %arg) to label %normal unwind label %unwind\nnormal:\n  ret i64 %result", "entry:\n  br label %again\nagain:\n  %previous = phi i64 [%arg, %entry], [%result, %again]\n  %result = invoke i64 @may_throw(i64 %previous) to label %again unwind label %unwind")
        for triple in TRIPLES:
            for body in (shared, bypass, loop):
                for module in self.pair(body, triple):
                    self.assertTrue(any(op["op"] == "phi" for op in self.operations(self.function(module, "entry"))))

    def test_bad_invoke_result_edges_and_landingpad_cfg_fail_at_llvm_verifier_stage_in_text_and_binary_all_three_isas(self):
        invalids = (
            (cleanup().replace("resume {ptr, i32} %exception", "ret i64 %result"), "does not dominate"),
            (cleanup().replace("@may_throw(i64 %arg)", "@may_throw(i64 %result)"), "Only PHI nodes may reference their own value"),
            (cleanup().replace("%result = invoke", "%early = add i64 %result, 1\n  %result = invoke"), "does not dominate"),
            (cleanup().replace("  %exception = landingpad", "  %early = add i64 %arg, 1\n  %exception = landingpad"), "first non-PHI"),
            (cleanup().replace("landingpad {ptr, i32} cleanup", "landingpad {ptr, i32}"), "at least one clause"),
            (cleanup().replace(" personality ptr @personality", ""), "with a personality"),
            (cleanup().replace("normal:\n  ret i64 %result", "normal:\n  br label %unwind"), "unwind edge"),
            (cleanup().replace("resume {ptr, i32} %exception", "resume {ptr, i64} zeroinitializer"), "consistent result type"),
        )
        for triple in TRIPLES:
            for body, diagnostic in invalids:
                with self.subTest(triple=triple, diagnostic=diagnostic):
                    self.invalid_pair(body, triple, diagnostic)

    def test_intrinsic_invoke_stage_boundaries_and_operand_bundle_guard_do_not_erase_original_calls_all_three_isas_ll_bc(self):
        trap = cleanup().replace("declare i64 @may_throw(i64)", "declare void @llvm.trap()")
        trap = trap.replace("%result = invoke i64 @may_throw(i64 %arg)", "invoke void @llvm.trap()").replace("ret i64 %result", "ret i64 %arg")
        donothing = trap.replace("llvm.trap", "llvm.donothing")
        bundles = cleanup().replace("(i64 %arg) to label", '(i64 %arg) ["unsupported.bundle"(i64 %arg)] to label')
        for triple in TRIPLES:
            self.invalid_pair(trap, triple, "Cannot invoke an intrinsic")
            self.pair(donothing, triple, False, "requires explicit lowering")
            self.pair(bundles, triple, False, "operand bundles")

    def test_dynamic_landingpad_clauses_fail_parse_and_poison_filter_fails_verifier_before_import_all_three_isas(self):
        for triple in TRIPLES:
            for clause in ("catch ptr %tag", "filter [1 x ptr] %filter"):
                body = cleanup(clause=clause).replace("define i64 @entry(i64 %arg)",
                                                    "define i64 @entry(i64 %arg, ptr %tag, [1 x ptr] %filter)")
                self.reject(self.write(body, triple), "parse")
            self.invalid_pair(cleanup(clause="filter [1 x ptr] poison"), triple,
                              "Filter operand is not an array of constants")

    def test_whole_cold_allocalign_preserves_eh_while_float_tls_unsupported_abi_and_other_eh_models_reject_all_three_isas_ll_bc(self):
        suffixes = (
            ("declare double @unused_float(double)\n", "unsupported LLVM type kind"),
            ("@unused_tls = thread_local global i32 7\n", "TLS globals require explicit --tls-profile linux-elf-static-nonpreemptive-v1"),
            ("declare void @unused_byval(ptr byval(i32))\n", "unsupported attribute"),
            ("declare ptr @unused_allocator(i64 allocalign)\n", "unsupported attribute"),
            ("define void @unused_funclet() personality ptr @personality {\nentry: invoke i64 @may_throw(i64 7) to label %normal unwind label %pad\nnormal: ret void\npad: %p = cleanuppad within none []\ncleanupret from %p unwind to caller\n}\n", "unsupported"),
        )
        for triple in TRIPLES:
            for suffix, diagnostic in suffixes:
                if "allocalign" in suffix:
                    for module in self.pair(cleanup() + suffix, triple):
                        self.assertTrue(any(f["name"] == "unused_allocator" and f["entry"] is None
                                            for f in module["functions"]))
                        self.assertTrue(any("function attribute index 1: validated allocator description allocalign=0;" in item
                                            for item in module["provenance"]["refinements"]))
                    continue
                self.pair(cleanup() + suffix, triple, False, diagnostic)

    @staticmethod
    def cpp_source():
        return '''typedef unsigned long long word;
extern "C" word may_throw(word);
extern "C" void observe(word) noexcept;
struct Guard { word value; ~Guard() { observe(value); } };
extern "C" word cpp_eh(word value) {
  Guard guard{value};
  try { return may_throw(value) ^ 17; }
  catch (int number) { return (word)(unsigned int)number; }
}
extern "C" word cold(word value) { return value + 3; }
extern "C" { extern const word cold_marker = 43; }
'''

    @staticmethod
    def rust_source():
        return '''#![no_std]
extern "C-unwind" { fn may_throw(value: u64) -> u64; }
#[no_mangle] pub static mut effect: u64 = 0;
struct Guard(u64);
impl Drop for Guard { fn drop(&mut self) { unsafe { core::ptr::write_volatile(&raw mut effect, self.0); } } }
#[no_mangle] pub unsafe extern "C-unwind" fn rust_eh(value: u64) -> u64 {
  let guard = Guard(value);
  let result = may_throw(value);
  core::ptr::write_volatile(&raw mut effect, result);
  core::mem::drop(guard);
  result
}
#[no_mangle] pub extern "C" fn cold(value: u64) -> u64 { value.wrapping_add(3) }
'''

    def producer(self, command, source, output):
        completed = subprocess.run([str(arg) for arg in command], cwd=baseline.ROOT, capture_output=True, text=True, timeout=45)
        copy = output.with_name(output.name + ".original-source")
        copy.write_bytes(source.read_bytes())
        self.records.append({"outcome": "original-producer", "command": [str(arg) for arg in command], "cwd": str(baseline.ROOT),
            "exit_code": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr,
            "source": noundef.artifact(source), "source_copy": noundef.artifact(copy), "input": noundef.artifact(output) if output.exists() else None})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output

    def test_actual_untouched_clang22_cpp_raii_typed_catch_whole_units_and_unused_float_tls_guards_all_three_isas_ll_bc(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        for extra in ("", 'extern "C" double unused_float(word value) { return (double)value; }\n', 'extern "C" thread_local word unused_tls = 7;\n'):
            source = self.directory / ("whole-eh" + str(len(extra)) + ".cpp")
            source.write_text(self.cpp_source() + extra)
            before = noundef.artifact(source)
            for triple in TRIPLES:
                modules = []
                for suffix in ("ll", "bc"):
                    output = self.directory / f"{source.stem}-{triple}.{suffix}"
                    flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
                    command = [clang, "--target=" + triple, *flags, "-x", "c++", "-std=c++17", "-fexceptions", *memory.LlvmMemoryImportTests.clang_flags(),
                               "-S" if suffix == "ll" else "-c", source, "-o", output]
                    path = self.producer(command, source, output)
                    if extra:
                        self.reject(path, diagnostic="unsupported LLVM type kind" if "unused_float" in extra else "TLS globals require explicit --tls-profile linux-elf-static-nonpreemptive-v1")
                    else:
                        module = self.accept(path, frontend="Clang C++", frontend_version=version)
                        modules.append(module)
                        self.assertEqual(module["target"]["triple"], triple)
                        self.assertIsNotNone(self.function(module, "cpp_eh")["exception_handling"])
                        self.assertTrue(any(block["terminator"]["op"] == "invoke" for block in self.function(module, "cpp_eh")["blocks"]))
                        self.assertIn("cold", {fn["name"] for fn in module["functions"]})
                        self.assertIn("cold_marker", {g["name"] for g in module["globals"]})
                        self.assertIn(TYPEID, {fn["name"] for fn in module["functions"]})
                if modules:
                    self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(noundef.artifact(source), before)

    def test_actual_untouched_rust1971_drop_c_unwind_whole_units_and_unused_float_keep_genuine_targets_all_three_isas_ll_bc(self):
        rustc, version = self.rust_compiler()
        for extra in ("", '#[no_mangle] pub extern "C" fn unused_float(value: u64) -> f64 { value as f64 }\n'):
            source = self.directory / ("whole-rust-eh" + str(len(extra)) + ".rs")
            source.write_text(self.rust_source() + extra)
            before = noundef.artifact(source)
            for target, triple, abi in ((TRIPLES[0], TRIPLES[0], None), (TRIPLES[1], TRIPLES[1], None), ("riscv64gc-unknown-linux-gnu", TRIPLES[2], "lp64d")):
                modules = []
                for suffix in ("ll", "bc"):
                    output = self.directory / f"{source.stem}-{target}.{suffix}"
                    command = [rustc, source, "--crate-type=lib", "--edition=2021", "--crate-name=eh_fixture", "--target=" + target,
                               "--emit=" + ("llvm-ir" if suffix == "ll" else "llvm-bc"), "-Copt-level=1", "-Cpanic=unwind", "-Coverflow-checks=no",
                               "-Ccodegen-units=1", "-Crelocation-model=static", "-o", output]
                    path = self.producer(command, source, output)
                    if extra:
                        self.reject(path, diagnostic="unsupported LLVM type kind", symbol="unused_float")
                    else:
                        module = self.accept(path, frontend="Rust", frontend_version=version)
                        modules.append(module)
                        self.assertEqual(module["target"]["triple"], triple)
                        self.assertEqual(module["target"].get("abi"), abi)
                        function = self.function(module, "rust_eh")
                        self.assertIsNotNone(function["exception_handling"])
                        self.assertTrue(any(block["terminator"]["op"] == "invoke" for block in function["blocks"]))
                        self.assertTrue(any(op["op"] == "store" and op["volatile"] for op in self.operations(function)))
                        self.assertIn("cold", {fn["name"] for fn in module["functions"]})
                        self.assertIn("effect", {g["name"] for g in module["globals"]})
                if modules:
                    self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(noundef.artifact(source), before)


if __name__ == "__main__":
    unittest.main()
