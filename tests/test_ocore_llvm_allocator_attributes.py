"""Whole LLVM allocator descriptions retain original calls, types and effects.

Source/API evidence only: no allocator substitution, native execution, provider
or dependency closure claim. Frontend units are original complete outputs.
"""

import ctypes as C
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_eh_import as eh
from tests import test_ocore_llvm_noundef_metadata as noundef


TRIPLES = baseline.TRIPLES
FUNCTION_INDEX = 0xffffffff
STRINGS = {"alloc-family", "alloc-variant-zeroed"}
ENUMS = {"allocalign", "allocptr", "allockind"}
KINDS = {1: "alloc", 9: "alloc,uninitialized", 17: "alloc,zeroed",
         33: "alloc,aligned", 41: "alloc,uninitialized,aligned", 49: "alloc,zeroed,aligned",
         2: "realloc", 10: "realloc,uninitialized", 18: "realloc,zeroed",
         34: "realloc,aligned", 42: "realloc,uninitialized,aligned", 50: "realloc,zeroed,aligned",
         4: "free"}


class LlvmAllocatorAttributeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()
        cls.library_artifact = noundef.artifact(cls.library)
        cls.worker_source = Path(importer.__file__).read_bytes()
        cls.test_source = Path(__file__).read_bytes()

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_ALLOCATOR_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-allocator-attributes-")
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

    original = eh.LlvmEHImportTests.original
    llvm_shape = eh.LlvmEHImportTests.llvm_shape
    write = eh.LlvmEHImportTests.write
    bitcode = eh.LlvmEHImportTests.bitcode
    function = staticmethod(eh.LlvmEHImportTests.function)
    instructions = staticmethod(eh.LlvmEHImportTests.instructions)
    operations = classmethod(eh.LlvmEHImportTests.operations.__func__)
    realization = staticmethod(eh.LlvmEHImportTests.realization)
    shape = classmethod(eh.LlvmEHImportTests.shape.__func__)
    rust_compiler = eh.LlvmEHImportTests.rust_compiler
    raw_attributes = eh.LlvmEHImportTests.raw_attributes
    signature = eh.LlvmEHImportTests.signature
    native_signature = eh.LlvmEHImportTests.native_signature
    strip_types = staticmethod(eh.LlvmEHImportTests.strip_types)
    operand = eh.LlvmEHImportTests.operand
    oracle = eh.LlvmEHImportTests.oracle
    accept = eh.LlvmEHImportTests.accept
    reject = eh.LlvmEHImportTests.reject
    pair = eh.LlvmEHImportTests.pair
    invalid_pair = eh.LlvmEHImportTests.invalid_pair
    producer = eh.LlvmEHImportTests.producer

    def tearDown(self):
        worker, test = self.directory / "worker-source.py", self.directory / "test-source.py"
        worker.write_bytes(self.worker_source)
        test.write_bytes(self.test_source)
        report = {"scope": "whole original allocator attributes source/API conformance", "test_id": self.id(),
                  "worker_source": noundef.artifact(worker), "test_source": noundef.artifact(test),
                  "llvm_library": self.library_artifact, "records": self.records,
                  "native_execution_verified": False, "allocator_provider_verified": False,
                  "runtime_complete": False, "dependency_closure_complete": False}
        (self.directory / "allocator-source-conformance.json").write_text(json.dumps(report, indent=2) + "\n")
        self.assertEqual(Path(importer.__file__).read_bytes(), self.worker_source)
        self.assertEqual(Path(__file__).read_bytes(), self.test_source)

    def descriptors(self, path):
        a = self.api
        kinds = {a.GetEnumAttributeKindForName(name.encode(), len(name)): name for name in ENUMS}
        records = []
        with self.original(path) as (_, module):
            def collect(owner, function_name, call=False, block=None, ordinal=None):
                count = a.GetNumArgOperands(owner) if call else a.CountParams(owner)
                for index in [FUNCTION_INDEX, *range(count + 1)]:
                    for attribute in self.raw_attributes(owner, index, call):
                        if a.IsStringAttribute(attribute):
                            name = a.string(a.GetStringAttributeKind, attribute, importer.U)
                            if name not in STRINGS:
                                continue
                            value = a.string(a.GetStringAttributeValue, attribute, importer.U)
                            attribute_class = "string"
                        elif a.IsEnumAttribute(attribute) and a.GetEnumAttributeKind(attribute) in kinds:
                            name = kinds[a.GetEnumAttributeKind(attribute)]
                            value = a.GetEnumAttributeValue(attribute)
                            attribute_class = "enum"
                        else:
                            continue
                        records.append({"symbol": function_name, "site": "callsite" if call else "function",
                                        "index": index, "name": name, "value": value, "class": attribute_class,
                                        "block": block, "ordinal": ordinal})
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                name = a.name(function)
                collect(function, name)
                for block_id, block in enumerate(a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function)):
                    for ordinal, instruction in enumerate(a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block)):
                        if a.GetInstructionOpcode(instruction) in (5, 45):
                            collect(instruction, name, True, block_id, ordinal)
        return records

    def assert_original(self, path, module):
        inventory = eh.LlvmEHImportTests.assert_original(self, path, module)
        descriptors = self.descriptors(path)
        notes = module["provenance"]["refinements"]
        for record in descriptors:
            payload = repr(record["value"]) if record["class"] == "string" else record["value"]
            prefix = f"{record['symbol']}: {record['site']} attribute index {record['index']}: validated allocator description {record['name']}={payload}; "
            position = (f"parsed function {record['symbol']}" if record["site"] == "function" else
                        f"parsed block {record['block']} instruction {record['ordinal']}")
            self.assertTrue(any(note.startswith(prefix + position + "; ") for note in notes), (prefix, notes))
            if record["name"] in {"allocalign", "allocptr"}:
                self.assertEqual(record["value"], 0)
        validated = [note for note in notes if ": validated allocator description " in note]
        self.assertEqual(len(validated), len(descriptors), "no invented callee inheritance or descriptor sites")
        for function in module["functions"]:
            signatures = [function["signature"]] + [op["signature"] for op in self.operations(function) if op["op"] == "call"]
            signatures += [block["terminator"]["signature"] for block in function["blocks"] if block["terminator"]["op"] == "invoke"]
            for signature in signatures:
                for attributes in signature["param_attributes"] + [signature["result_attributes"]]:
                    self.assertLessEqual(set(attributes), {"signext", "zeroext"})
                for name in STRINGS | ENUMS:
                    self.assertNotIn(name, signature)
        inventory["allocator_descriptions"] = descriptors
        return inventory

    @staticmethod
    def whole_body():
        return '''@effect = global i64 0, align 8
declare void @host_free(ptr)
declare i32 @personality(i32, i32, i64, ptr, ptr)
declare ptr @unused(i64 allocalign, ptr allocptr) allockind("realloc,aligned") "alloc-family"="generic"
define ptr @allocator(i64 allocalign %alignment, ptr allocptr %old) allockind("realloc,aligned") "alloc-family"="generic" "alloc-variant-zeroed"="missing_zeroed" {
  store volatile i64 %alignment, ptr @effect, align 8
  ret ptr null
}
define void @free_body(ptr allocptr %pointer) allockind("free") "alloc-family"="generic" {
  call void @host_free(ptr %pointer)
  store volatile i64 7, ptr @effect, align 8
  ret void
}
@allocator_alias = alias ptr(i64, ptr), ptr @allocator
define ptr @direct(i64 %alignment, ptr %old) {
  %p = call ptr @allocator(i64 allocalign %alignment, ptr allocptr %old) allockind("realloc,aligned") "alloc-family"="generic"
  ret ptr %p
}
define ptr @indirect(ptr %callee, i64 %alignment, ptr %old) {
  %p = call ptr %callee(i64 allocalign %alignment, ptr allocptr %old) allockind("realloc,aligned") "alloc-family"="generic"
  ret ptr %p
}
define ptr @alias_user(i64 %alignment, ptr %old) {
  %p = call ptr @allocator_alias(i64 allocalign %alignment, ptr allocptr %old) "alloc-family"="generic"
  ret ptr %p
}
define ptr @invoke_user(i64 %alignment, ptr %old) personality ptr @personality {
entry:
  %p = invoke ptr @allocator(i64 allocalign %alignment, ptr allocptr %old) allockind("realloc,aligned") "alloc-family"="generic" to label %normal unwind label %bad
normal: ret ptr %p
bad:
  %ex = landingpad {ptr, i32} cleanup
  resume {ptr, i32} %ex
}
'''

    def test_complete_function_declaration_alias_direct_indirect_and_invoke_descriptions_keep_original_effects_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for module in self.pair(self.whole_body(), triple):
                self.assertEqual({f["name"] for f in module["functions"]}, {"host_free", "personality", "unused", "allocator", "free_body", "direct", "indirect", "alias_user", "invoke_user"})
                self.assertEqual([a["name"] for a in module["aliases"]], ["allocator_alias"])
                stores = [op for f in module["functions"] for op in self.operations(f) if op["op"] == "store"]
                self.assertEqual(len(stores), 2)
                self.assertTrue(all(op["volatile"] for op in stores))
                calls = [op for f in module["functions"] for op in self.operations(f) if op["op"] == "call"]
                self.assertEqual(len(calls), 4)
                self.assertEqual(self.function(module, "allocator")["blocks"][0]["terminator"]["value"]["kind"], "null")
                self.assertNotIn("missing_zeroed", {f["name"] for f in module["functions"]})

    def test_all_thirteen_documented_allockind_combinations_keep_full_payloads_in_declarations_definitions_calls_all_three_isas_ll_bc(self):
        body = 'declare void @host_free(ptr allocptr) allockind("free")\n'
        for value, spelling in KINDS.items():
            result, ret = ("void", "ret void") if value == 4 else ("ptr", "ret ptr null")
            body += f'declare {result} @decl_{value}(i64 allocalign, ptr allocptr) allockind("{spelling}")\n'
            actual_free = "call void @host_free(ptr %old)\n" if value == 4 else ""
            body += f'define {result} @body_{value}(i64 allocalign %alignment, ptr allocptr %old) allockind("{spelling}") {{ {actual_free}{ret} }}\n'
            call = 'call void' if value == 4 else '%p = call ptr'
            body += f'define {result} @use_{value}(ptr %callee) {{ {call} %callee(i64 allocalign 3, ptr allocptr null) allockind("{spelling}")\n{ret} }}\n'
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                self.assertEqual(len(module["functions"]), 40)
                self.assertEqual(sum(f["entry"] is not None for f in module["functions"]), 26)
                notes = "\n".join(module["provenance"]["refinements"])
                for value in KINDS:
                    self.assertIn(f"validated allocator description allockind={value};", notes)

    def test_allocalign_every_width_1_to_64_preserves_exact_types_and_nullable_invalid_alignment_arguments_all_three_isas_ll_bc(self):
        body = ""
        for width in range(1, 65):
            body += f'define ptr @align_{width}(i{width} allocalign %alignment) {{ ret ptr null }}\n'
        body += '''define ptr @invalid_values() {
  %a = call ptr @align_64(i64 allocalign 0)
  %b = call ptr @align_64(i64 allocalign 3)
  %c = call ptr @align_64(i64 allocalign -1)
  ret ptr %c
}
'''
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                calls = self.operations(self.function(module, "invalid_values"))
                self.assertEqual([int(op["args"][0]["bits"]) for op in calls], [0, 3, (1 << 64) - 1])
                self.assertEqual([op["op"] for op in calls], ["call"] * 3)
                for width in range(1, 65):
                    fn = self.function(module, f"align_{width}")
                    self.assertEqual(module["types"][fn["signature"]["params"][0]]["bits"], width)
                    self.assertEqual(fn["blocks"][0]["terminator"]["value"]["kind"], "null")

    def test_pointer_parameter_order_extensions_and_uninherited_callsite_descriptions_remain_separate_all_three_isas_ll_bc(self):
        body = '''declare ptr @declared(i8 zeroext, ptr allocptr, i64 allocalign) "alloc-family"="callee_only"
define ptr @omit(i8 zeroext %tag, ptr %old, i64 %align) {
  %p = call ptr @declared(i8 zeroext %tag, ptr %old, i64 %align)
  ret ptr %p
}
define ptr @only_callsite(ptr %callee, ptr %old, i64 %align) {
  %p = call ptr %callee(i8 zeroext 0, ptr allocptr %old, i64 allocalign %align) "alloc-family"="site_only"
  ret ptr %p
}
'''
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                notes = module["provenance"]["refinements"]
                self.assertFalse(any(n.startswith("omit: callsite") and "validated allocator description" in n for n in notes))
                self.assertTrue(any(n.startswith("only_callsite: callsite attribute index 2: validated allocator description allocptr=0") for n in notes))
                self.assertEqual(self.function(module, "declared")["signature"]["param_attributes"], [["zeroext"], [], []])

    def test_existing_scalar_aggregate_extensions_and_typed_sret_contracts_are_not_reclassified_by_descriptions_all_three_isas_ll_bc(self):
        body = '''define signext i8 @small(i8 zeroext %value, i64 allocalign %alignment) "alloc-family"="generic" { ret i8 %value }
define {i8, i64} @pair(i64 allocalign %alignment) "alloc-family"="generic" { ret {i8, i64} {i8 7, i64 43} }
define void @storage(i8 zeroext %tag, ptr sret({i64, i64}) %out, i64 allocalign %alignment, ptr allocptr %old) "alloc-family"="generic" {
  store i64 37, ptr %out, align 8
  ret void
}
define signext i8 @use(i8 zeroext %value) {
  %out = alloca {i64, i64}, align 8
  call void @storage(i8 zeroext %value, ptr sret({i64, i64}) %out, i64 allocalign 3, ptr allocptr null) "alloc-family"="generic"
  %p = call {i8, i64} @pair(i64 allocalign 3) "alloc-family"="generic"
  %v = call signext i8 @small(i8 zeroext %value, i64 allocalign 3) "alloc-family"="generic"
  ret i8 %v
}
'''
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                small = self.function(module, "small")["signature"]
                self.assertEqual(small["result_attributes"], ["signext"])
                self.assertEqual(small["param_attributes"], [["zeroext"], []])
                storage = self.function(module, "storage")["signature"]
                self.assertEqual(storage["return_storage"]["param"], 1)
                self.assertEqual(self.shape(module, storage["return_storage"]["ty"]),
                                 {"kind": "struct", "packed": False, "fields": [{"kind": "int", "bits": 64}] * 2})
                self.assertEqual([op["op"] for op in self.operations(self.function(module, "use"))], ["alloca", "call", "call", "call"])

    def test_optional_zeroed_variant_missing_and_alias_only_names_do_not_create_dependencies_or_zero_fills_all_three_isas_ll_bc(self):
        body = '''define ptr @base(i64 %size) allockind("alloc") "alloc-family"="generic" "alloc-variant-zeroed"="not_present" { ret ptr null }
define ptr @target(i64 %size) { ret ptr null }
@alias_only = alias ptr(i64), ptr @target
declare ptr @other(i64) "alloc-variant-zeroed"="alias_only"
define ptr @use(i64 %size) { %p = call ptr @base(i64 %size)\nret ptr %p }
'''
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                self.assertNotIn("not_present", {f["name"] for f in module["functions"]})
                self.assertEqual(self.operations(self.function(module, "use"))[0]["callee"]["name"], "base")
                self.assertFalse(any(op["op"] in {"memory_set", "memory_copy", "trap"} for f in module["functions"] for op in self.operations(f)))
                self.assertTrue(any("optional optimizer alternative" in n for n in module["provenance"]["refinements"]))

    def test_present_compatible_zeroed_variant_preserves_distinct_bodies_and_actual_called_symbol_all_three_isas_ll_bc(self):
        body = '''@effect = global i64 0
define ptr @base(i64 %size) allockind("alloc,uninitialized") "alloc-family"="generic" "alloc-variant-zeroed"="zeroed" {
  store volatile i64 7, ptr @effect
  ret ptr null
}
define ptr @zeroed(i64 %size) allockind("alloc,zeroed") "alloc-family"="generic" {
  %unused = add i64 %size, 0
  store volatile i64 7, ptr @effect
  ret ptr null
}
define ptr @use(i64 %size) { %p = call ptr @base(i64 %size) "alloc-variant-zeroed"="zeroed"\nret ptr %p }
'''
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                self.assertEqual(self.operations(self.function(module, "use"))[0]["callee"]["name"], "base")
                self.assertEqual([int(next(op for op in self.operations(self.function(module, f)) if op["op"] == "store")["value"]["bits"]) for f in ("base", "zeroed")], [7, 7])
                self.assertEqual([op["op"] for op in self.operations(self.function(module, "zeroed"))], ["binary", "store"])

    def test_incompatible_present_variants_reject_at_llvm_verifier_without_importer_fiction_all_three_isas_ll_bc(self):
        template = 'declare ptr @base(i64) "alloc-family"="generic" "alloc-variant-zeroed"="variant"\nDECLARATION\n'
        variants = (
            ('declare ptr @variant(i64) allockind("alloc,zeroed") "alloc-family"="other"', "same 'alloc-family'"),
            ('declare ptr @variant(i64) allockind("alloc") "alloc-family"="generic"', "allockind"),
            ('declare ptr @variant(i32) allockind("alloc,zeroed") "alloc-family"="generic"', "same signature"),
        )
        for triple in TRIPLES:
            for declaration, diagnostic in variants:
                self.invalid_pair(template.replace("DECLARATION", declaration), triple, diagnostic)

    def test_verified_string_wrong_sites_empty_nul_nonutf8_and_enum_lookalikes_fail_closed_all_three_isas_ll_bc(self):
        cases = (
            'declare "alloc-family"="generic" ptr @bad(i64)',
            'declare ptr @bad(i64 "alloc-family"="generic")',
            'declare "alloc-variant-zeroed"="missing" ptr @bad(i64)',
            'declare ptr @bad(i64 "alloc-variant-zeroed"="missing")',
            'declare ptr @bad(i64) "alloc-family"=""',
            r'declare ptr @bad(i64) "alloc-family"="prefix\00suffix"',
            r'declare ptr @bad(i64) "alloc-family"="\FF"',
            r'declare ptr @bad(i64) "alloc-variant-zeroed"="prefix\00suffix"',
            'declare ptr @bad(i64) "allocalign"="0"',
            'declare void @bad(ptr) "allocptr"="0"',
            'declare ptr @bad(i64) "allockind"="1"',
        )
        for triple in TRIPLES:
            for body in cases:
                source = self.write(body + "\n", triple)
                binary = self.bitcode(source)
                self.reject(source)
                if r"\00" in body:
                    self.reject(binary, stage="parse", diagnostic="Invalid attribute group entry")
                else:
                    self.reject(binary)

    def test_unicode_string_payloads_keep_full_utf8_without_symbol_substitution_all_three_isas_ll_bc(self):
        body = 'declare ptr @allocator(i64) "alloc-family"="famille-é" "alloc-variant-zeroed"="absent-λ"\n'
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                notes = "\n".join(module["provenance"]["refinements"])
                self.assertIn("alloc-family='famille-é'", notes)
                self.assertIn("alloc-variant-zeroed='absent-λ'", notes)
                self.assertEqual(len(module["functions"]), 1)

    def mutated(self, body, triple, name, payload, index=FUNCTION_INDEX, call=False):
        source = self.write(body, triple)
        a = self.api
        create, add, add_call = a.lib.LLVMCreateEnumAttribute, a.lib.LLVMAddAttributeAtIndex, a.lib.LLVMAddCallSiteAttribute
        create.restype, create.argtypes = importer.P, [importer.P, importer.U, importer.Q]
        add.restype, add.argtypes = None, [importer.P, importer.U, importer.P]
        add_call.restype, add_call.argtypes = None, [importer.P, importer.U, importer.P]
        with self.original(source) as (context, module):
            fn = next(f for f in a.sequence(a.GetFirstFunction, a.GetNextFunction, module) if a.name(f) == "bad")
            owner = fn
            if call:
                owner = next(i for b in a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, fn)
                             for i in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, b) if a.GetInstructionOpcode(i) in (5, 45))
            kind = a.GetEnumAttributeKindForName(name.encode(), len(name))
            (add_call if call else add)(owner, index, create(context, kind, payload))
            parsed = [a.GetEnumAttributeValue(attr) for attr in self.raw_attributes(owner, index, call)
                      if a.IsEnumAttribute(attr) and a.GetEnumAttributeKind(attr) == kind]
            message, serialized = importer.P(), None
            try:
                status = a.VerifyModule(module, 2, C.byref(message))
                diagnostic = C.string_at(message).decode() if message else None
                serialized = a.WriteBitcodeToMemoryBuffer(module)
                binary = source.with_suffix(".bc")
                binary.write_bytes(C.string_at(a.GetBufferStart(serialized), a.GetBufferSize(serialized)))
            finally:
                if serialized: a.DisposeMemoryBuffer(serialized)
                if message: a.DisposeMessage(message)
        self.records.append({"outcome": "raw-attribute-construction", "source": noundef.artifact(source), "input": noundef.artifact(binary),
                             "name": name, "index": index, "requested_payload": payload, "actual_enum_payloads": parsed,
                             "verifier_status": status, "verifier_diagnostic": diagnostic})
        return binary, status, parsed

    def raw_reader_boundary(self, path, name, index):
        a = self.api
        context, buffer, module, error, message = a.ContextCreate(), None, importer.P(), importer.P(), importer.P()
        try:
            data = path.read_bytes()
            buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"allocator-raw-roundtrip")
            status = a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error))
            stage, payloads = ("parse" if status else None), []
            if not status:
                kind = a.GetEnumAttributeKindForName(name.encode(), len(name))
                fn = next(f for f in a.sequence(a.GetFirstFunction, a.GetNextFunction, module) if a.name(f) == "bad")
                payloads = [a.GetEnumAttributeValue(attr) for attr in self.raw_attributes(fn, index)
                            if a.IsEnumAttribute(attr) and a.GetEnumAttributeKind(attr) == kind]
                if a.VerifyModule(module, 2, C.byref(message)): stage = "llvm-verify"
            self.records.append({"outcome": "raw-reader-boundary", "input": noundef.artifact(path),
                                 "name": name, "index": index, "stage": stage, "actual_enum_payloads": payloads,
                                 "diagnostic": C.string_at(error or message).decode() if error or message else None})
            return stage, payloads
        finally:
            if message: a.DisposeMessage(message)
            if error: a.DisposeMessage(error)
            if module: a.DisposeModule(module)
            if buffer: a.DisposeMemoryBuffer(buffer)
            if context: a.ContextDispose(context)

    def assert_bad_raw_site(self, path, name, index):
        stage, payloads = self.raw_reader_boundary(path, name, index)
        if stage:
            self.reject(path, stage=stage)
        elif payloads:
            self.reject(path)
        else:
            module = self.accept(path)
            self.assertFalse(any(r["name"] == name and r["index"] == index for r in self.descriptors(path)))
            self.assertFalse(any("validated allocator description" in n for n in module["provenance"]["refinements"]))

    def test_raw_api_wrong_enum_positions_require_verifier_or_explicit_profile_rejection_all_three_isas(self):
        for triple in TRIPLES:
            for name, body in (("allocalign", "declare ptr @bad(i64)\n"), ("allocptr", "declare void @bad(ptr)\n")):
                for index in (0, FUNCTION_INDEX):
                    path, status, parsed = self.mutated(body, triple, name, 0, index)
                    self.assertEqual(parsed, [0])
                    self.assert_bad_raw_site(path, name, index)
            for body, name in (("declare ptr @bad(ptr)\n", "allocalign"), ("declare void @bad(i64)\n", "allocptr")):
                path, status, parsed = self.mutated(body, triple, name, 0, 1)
                self.assertEqual(parsed, [0])
                self.assert_bad_raw_site(path, name, 1)

    def test_raw_full_integer_allockind_unknown_bits_and_illegal_modifiers_never_disappear_all_three_isas(self):
        for triple in TRIPLES:
            for payload in (0, 3, 5, 6, 7, 12, 20, 36, 25, 64, 65, (1 << 63) | 1, (1 << 64) - 1):
                path, status, parsed = self.mutated("declare ptr @bad(i64)\n", triple, "allockind", payload)
                self.assertEqual(parsed, [payload], "full uint64 payload must be measured before fresh writing")
                self.reject(path, stage="llvm-verify" if status else "import")

    def test_free_nonvoid_and_unsupported_fast_vararg_pointer_width_and_security_profiles_reject_whole_units_all_three_isas_ll_bc(self):
        cases = (
            'declare ptr @bad(ptr allocptr) allockind("free")',
            'declare fastcc ptr @bad(i64) "alloc-family"="generic"',
            'declare ptr @bad(i64, ...) "alloc-family"="generic"',
            'declare void @bad(ptr addrspace(1) allocptr)',
            'declare ptr @bad(i128 allocalign)',
            'declare void @bad(ptr byval(i32) allocptr)',
            'define void @bad(ptr allocptr %p) shadowcallstack { ret void }',
        )
        for triple in TRIPLES:
            for body in cases:
                self.pair(body + "\n", triple, False)

    def test_owned_intrinsic_declaration_normalization_is_honest_and_surviving_callsite_descriptions_reject_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for module in self.pair('declare void @llvm.trap() "alloc-family"="generic"\n', triple):
                self.assertFalse(any(": validated allocator description " in n for n in module["provenance"]["refinements"]))
                self.assertEqual([f["name"] for f in module["functions"]], ["llvm.trap"])
            self.pair('declare void @llvm.trap()\ndefine void @bad() { call void @llvm.trap() "alloc-family"="generic"\nunreachable }\n', triple, False,
                      "ordinary supported fixed C function or callsite")
            self.pair('declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)\ndefine void @bad(ptr %p) { call void @llvm.memset.p0.i64(ptr allocptr %p, i8 0, i64 0, i1 false)\nret void }\n', triple, False)

    def test_valid_descriptors_do_not_prune_unused_float_tls_eh_provider_or_abi_blockers_all_three_isas_ll_bc(self):
        base = 'declare ptr @allocator(i64 allocalign) allockind("alloc,aligned") "alloc-family"="generic"\n'
        for triple in TRIPLES:
            for suffix in ("declare double @unused_float(double)\n", "@unused_tls = thread_local global i32 7\n",
                           "declare void @unused_byval(ptr byval(i32))\n", 'define void @unused_gc() gc "shadow-stack" { ret void }\n'):
                self.pair(base + suffix, triple, False)

    @staticmethod
    def clang_source():
        return '''typedef unsigned long size_t;
extern void *malloc(size_t);
extern void *calloc(size_t, size_t);
extern void *realloc(void *, size_t);
extern void free(void *);
volatile size_t allocator_effect;
void *allocate(size_t n) { allocator_effect = n; return malloc(n); }
void *zero_allocate(size_t n) { return calloc(n, 1); }
void *resize(void *p, size_t n) { return realloc(p, n); }
void release(void *p) { free(p); allocator_effect = 7; }
size_t cold(size_t n) { return n + 3; }
'''

    @staticmethod
    def clang_aligned_source():
        """The initial complete alignment-bundle producer, kept byte for byte."""
        return '''typedef unsigned long size_t;
extern void *malloc(size_t);
extern void *calloc(size_t, size_t);
extern void *realloc(void *, size_t);
extern void free(void *);
extern void *aligned_alloc(size_t, size_t);
volatile size_t allocator_effect;
void *allocate(size_t n) { allocator_effect = n; return malloc(n); }
void *zero_allocate(size_t n) { return calloc(n, 1); }
void *resize(void *p, size_t n) { return realloc(p, n); }
void release(void *p) { free(p); allocator_effect = 7; }
void *aligned(size_t alignment, size_t n) { return aligned_alloc(alignment, n); }
size_t cold(size_t n) { return n + 3; }
'''

    def test_actual_untouched_clang22_allocator_whole_units_and_unused_float_tls_negatives_all_three_isas_ll_bc(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        for extra in ("", "double unused_float(size_t n) { return (double)n; }\n", "_Thread_local size_t unused_tls = 7;\n",
                      "extern void *aligned_alloc(size_t, size_t);\nvoid *aligned(size_t alignment, size_t n) { return aligned_alloc(alignment, n); }\n"):
            source = self.directory / ("whole-allocator-" + str(len(extra)) + ".c")
            source.write_text(self.clang_aligned_source() if "aligned_alloc" in extra else self.clang_source() + extra)
            before = noundef.artifact(source)
            for triple in TRIPLES:
                modules = []
                for suffix in ("ll", "bc"):
                    output = self.directory / f"{source.stem}-{triple}.{suffix}"
                    target_flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
                    command = [clang, "--target=" + triple, *target_flags, "-x", "c", "-std=c11", "-O1", "-fno-stack-protector",
                               "-fno-pic", "-fno-pie", "-fno-vectorize", "-fno-slp-vectorize", "-emit-llvm", "-S" if suffix == "ll" else "-c", source, "-o", output]
                    path = self.producer(command, source, output)
                    if extra:
                        diagnostic = ("unsupported LLVM type kind" if "unused_float" in extra else
                                      "TLS globals require explicit --tls-profile linux-elf-static-nonpreemptive-v1" if "unused_tls" in extra else "operand bundles")
                        self.reject(path, diagnostic=diagnostic)
                    else:
                        module = self.accept(path, frontend="Clang C", frontend_version=version)
                        modules.append(module)
                        self.assertEqual(module["target"]["triple"], triple)
                        self.assertTrue(any(r["name"] == "alloc-family" for r in self.descriptors(path)))
                        self.assertTrue({"allocate", "zero_allocate", "resize", "release", "cold"}.issubset({f["name"] for f in module["functions"]}))
                if modules:
                    self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(noundef.artifact(source), before)

    @staticmethod
    def rust_source():
        return '''#![no_std]
extern crate alloc;
use alloc::alloc::{alloc, alloc_zeroed, realloc, dealloc, Layout};
#[no_mangle] pub static mut allocator_effect: usize = 0;
#[no_mangle] pub unsafe extern "C" fn rust_allocate() -> *mut u8 { alloc(Layout::from_size_align_unchecked(64, 8)) }
#[no_mangle] pub unsafe extern "C" fn rust_zeroed() -> *mut u8 { alloc_zeroed(Layout::from_size_align_unchecked(64, 8)) }
#[no_mangle] pub unsafe extern "C" fn rust_resize(p: *mut u8) -> *mut u8 { realloc(p, Layout::from_size_align_unchecked(64, 8), 128) }
#[no_mangle] pub unsafe extern "C" fn rust_free(p: *mut u8) { dealloc(p, Layout::from_size_align_unchecked(64, 8)); core::ptr::write_volatile(&raw mut allocator_effect, 7); }
#[no_mangle] pub extern "C" fn cold(n: usize) -> usize { n.wrapping_add(3) }
'''

    def test_actual_untouched_rust1971_alloc_family_whole_units_and_unused_float_keep_genuine_targets_all_three_isas_ll_bc(self):
        rustc, version = self.rust_compiler()
        for extra in ("", '#[no_mangle] pub extern "C" fn unused_float(n: usize) -> f64 { n as f64 }\n'):
            source = self.directory / ("whole-rust-allocator-" + str(len(extra)) + ".rs")
            source.write_text(self.rust_source() + extra)
            before = noundef.artifact(source)
            for target, triple, abi in ((TRIPLES[0], TRIPLES[0], None), (TRIPLES[1], TRIPLES[1], None), ("riscv64gc-unknown-linux-gnu", TRIPLES[2], "lp64d")):
                modules = []
                for suffix in ("ll", "bc"):
                    output = self.directory / f"{source.stem}-{target}.{suffix}"
                    command = [rustc, source, "--crate-type=lib", "--edition=2021", "--crate-name=allocator_fixture", "--target=" + target,
                               "--emit=" + ("llvm-ir" if suffix == "ll" else "llvm-bc"), "-Copt-level=1", "-Cpanic=unwind", "-Coverflow-checks=no",
                               "-Ccodegen-units=1", "-Crelocation-model=static", "-o", output]
                    path = self.producer(command, source, output)
                    if extra:
                        self.reject(path, diagnostic="unsupported LLVM type kind", symbol="unused_float")
                    else:
                        module = self.accept(path, frontend="Rust", frontend_version=version)
                        modules.append(module)
                        self.assertEqual(module["target"]["triple"], triple)
                        if abi: self.assertEqual(module["target"]["abi"], abi)
                        self.assertTrue(any(r["name"] == "alloc-family" for r in self.descriptors(path)))
                        self.assertTrue({"rust_allocate", "rust_zeroed", "rust_resize", "rust_free", "cold"}.issubset({f["name"] for f in module["functions"]}))
                if modules:
                    self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(noundef.artifact(source), before)


if __name__ == "__main__":
    unittest.main()
