"""Ordinary LLVM declaration unwind requests without invented unwind support.

Whole original text/bitcode modules retain declarations, calls and globals.
An external declaration has no body and emits no consumer FDE. Own-emitter
CFI and provider linking have separate qualification; this source suite makes
no exception-runtime, external-provider or whole-compiler completion claim.
"""

import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory
from tests import test_ocore_native_allocsize as inventory_qa
from tests import test_ocore_native_weak as artifacts


TRIPLES = baseline.TRIPLES
SPELLINGS = (("uwtable(sync)", 1), ("uwtable(async)", 2), ("uwtable", 2))
DECLARATIONS = {"provider_a", "provider_b", "cold_provider", "narrow_provider", "unannotated"}
ANNOTATED = DECLARATIONS - {"unannotated"}
DEFINITIONS = {"entry", "nested", "unused_defined"}


def body(attribute="", definition_attribute=""):
    return f"""
declare i64 @provider_a(i64) {attribute}
declare i64 @provider_b(i64) {attribute}
declare void @cold_provider(ptr) {attribute}
declare signext i32 @narrow_provider(i32 zeroext) {attribute}
declare i64 @unannotated(i64)
@marker = global i64 7, align 8
@provider_callback = constant ptr @provider_b, align 8
@provider_address = constant ptr @provider_a, align 8
@cold_storage = constant [2 x i64] [i64 17, i64 19], align 8
@marker_alias = alias i64, ptr @marker
@entry_alias = alias i64(i64, ptr), ptr @entry
define i64 @entry(i64 %value, ptr %callee) {definition_attribute} {{
  %direct = call i64 @provider_a(i64 %value)
  %result = call i64 @nested(i64 %direct, ptr %callee)
  ret i64 %result
}}
define internal i64 @nested(i64 %value, ptr %callee) {{
  %global_callee = load ptr, ptr @provider_callback, align 8
  %global_call = call i64 %global_callee(i64 %value)
  %argument_call = call i64 %callee(i64 %global_call)
  %result = xor i64 %argument_call, %value
  ret i64 %result
}}
define i64 @unused_defined(i64 %value) {{
  store volatile i64 %value, ptr @marker_alias, align 8
  %observed = load volatile i64, ptr @marker, align 8
  ret i64 %observed
}}
"""


class LlvmUWTableDeclarationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library_path = baseline.llvm_library()
        cls.worker_source = Path(importer.__file__).read_bytes()
        cls.test_source = Path(__file__).read_bytes()

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_UWTABLE_DECLARATIONS_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-uwtable-declarations-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)
        self.sequence, self.records = 0, []
        self.library = importer.LLVM(self.library_path, importer.PINNED_SHA256)

    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)
    original_inventory = inventory_qa.AllocsizeNativeTests.original_inventory

    def tearDown(self):
        worker = self.directory / "worker-source.py"; worker.write_bytes(self.worker_source)
        test = self.directory / "test-source.py"; test.write_bytes(self.test_source)
        report = {"scope": "whole original LLVM ordinary-declaration uwtable source conformance",
                  "test_source": artifacts.artifact(test), "importer_source": artifacts.artifact(worker),
                  "llvm_library": artifacts.artifact(self.library_path), "records": self.records,
                  "runtime_complete": False, "compiler_implementation_lowered": False,
                  "exception_handling_verified": False, "external_provider_unwind_verified": False,
                  "native_cfi_verified": False, "dependency_closure_complete": False}
        (self.directory / "uwtable-declarations-source-conformance.json").write_text(json.dumps(report, indent=2) + "\n")
        self.assertEqual(Path(importer.__file__).read_bytes(), self.worker_source, "worker must remain frozen during source qualification")
        self.assertEqual(Path(__file__).read_bytes(), self.test_source, "test source must remain frozen during qualification")

    def write(self, text, triple=TRIPLES[0]):
        self.sequence += 1
        path = self.directory / f"original-{self.sequence:03}.ll"
        layout = memory.LAYOUT + ("-Fn32" if triple.startswith("aarch64-") else "")
        path.write_text(f'target triple = "{triple}"\ntarget datalayout = "{layout}"\n' + text)
        return path

    def bitcode(self, source):
        a = self.library; data = source.read_bytes(); context = a.ContextCreate()
        buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"uwtable-original-bitcode")
        module, error = importer.P(), importer.P(); serialized = None
        try:
            self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0)
            self.assertEqual(a.VerifyModule(module, 2, C.byref(error)), 0,
                             C.string_at(error).decode() if error else "LLVM verification failed")
            serialized = a.WriteBitcodeToMemoryBuffer(module)
            binary = source.with_suffix(".bc")
            binary.write_bytes(C.string_at(a.GetBufferStart(serialized), a.GetBufferSize(serialized)))
            return binary
        finally:
            if serialized: a.DisposeMemoryBuffer(serialized)
            if error: a.DisposeMessage(error)
            if module: a.DisposeModule(module)
            a.DisposeMemoryBuffer(buffer); a.ContextDispose(context)

    def import_path(self, path):
        original = path.read_bytes()
        try:
            module = importer.import_module(path, library_path=self.library_path)
        except importer.ImportFailure as error:
            self.records.append({"input": artifacts.artifact(path), "error": {"stage": error.stage, "symbol": error.symbol, "message": str(error)}})
            raise
        output = path.with_name(path.name + ".native.json")
        output.write_text(json.dumps(module, indent=2) + "\n")
        self.records.append({"input": artifacts.artifact(path), "native_module": artifacts.artifact(output)})
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(original).hexdigest())
        return module

    @staticmethod
    def realization(module):
        return {key: value for key, value in module.items() if key not in {"name", "provenance"}}

    def original_uwtable(self, path):
        a = self.library; data = path.read_bytes(); context = a.ContextCreate()
        buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"original-uwtable-inventory")
        module, error = importer.P(), importer.P()
        try:
            self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0)
            kind = a.GetEnumAttributeKindForName(b"uwtable", 7); rows = []
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                count = a.GetAttributeCountAtIndex(function, 0xffffffff); attributes = (importer.P * count)()
                a.GetAttributesAtIndex(function, 0xffffffff, attributes)
                for attribute in attributes:
                    if a.IsEnumAttribute(attribute) and a.GetEnumAttributeKind(attribute) == kind:
                        rows.append({"symbol": a.name(function), "index": 0xffffffff,
                                     "level": int(a.GetEnumAttributeValue(attribute)),
                                     "definition": bool(a.GetFirstBasicBlock(function))})
        finally:
            if error: a.DisposeMessage(error)
            if module: a.DisposeModule(module)
            if buffer: a.DisposeMemoryBuffer(buffer)
            if context: a.ContextDispose(context)
        return rows

    def assert_declaration_provenance(self, module, symbol, level):
        # The stable worker prefix/site is coordinated with its source owner.
        prefix = f"{symbol}: retained ordinary declaration uwtable={level}"
        matches = [text for text in module["provenance"]["refinements"] if prefix in text]
        self.assertEqual(len(matches), 1, (symbol, level, matches))
        text = matches[0]
        self.assertIn("Sync" if level == 1 else "Async", text)
        self.assertIn("4294967295", text)
        for requirement in ("declaration", "no function body", "consumer", "dependencies", "CFI", "external", "not inferred"):
            self.assertIn(requirement, text)
        self.assertNotIn("realized function uwtable", text)
        self.assertNotIn("erased optimization", text)
        self.assertTrue(any("UWTable attributes validated after pinned LLVM parsing" in item
                            and "normalization" in item and "input_sha256" in item
                            for item in module["provenance"]["refinements"]))

    def assert_inventory(self, module, original, triple):
        self.assertEqual(module["target"]["triple"], triple)
        functions = {function["name"]: function for function in module["functions"]}
        self.assertEqual(set(functions), set(original["functions"]))
        self.assertEqual({name for name, function in functions.items() if function["entry"] is not None}, set(original["definitions"]))
        for category, key in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
            self.assertEqual(module["provenance"]["source_" + category + "_count"], len(original[key]))
            self.assertEqual({item["name"] for item in module[key]}, set(original[key]))
        for name in DECLARATIONS:
            self.assertIsNone(functions[name]["entry"])
            self.assertEqual(functions[name]["blocks"], [])
            self.assertIsNone(functions[name]["intrinsic"])
            self.assertEqual(functions[name]["linkage"], "external")
            self.assertEqual(functions[name]["signature"]["abi"], "c")
        narrow = functions["narrow_provider"]["signature"]
        self.assertEqual(narrow["param_attributes"], [["zeroext"]])
        self.assertEqual(narrow["result_attributes"], ["signext"])
        for name, function in functions.items():
            operations = self.operations(function)
            calls = [operation["callee"].get("name") if operation["callee"]["kind"] == "symbol" else None
                     for operation in operations if operation["op"] == "call"]
            accesses = [(operation["op"], operation.get("volatile", False)) for operation in operations
                        if operation["op"] in {"load", "store"}]
            self.assertEqual(calls, original["body_calls"][name])
            self.assertEqual(accesses, original["body_accesses"][name])
        globals_ = {global_["name"]: global_ for global_ in module["globals"]}
        for name, symbol in (("provider_callback", "provider_b"), ("provider_address", "provider_a")):
            self.assertEqual(globals_[name]["initializer"]["relocations"], [{"offset": 0, "width": 64, "symbol": symbol, "addend": 0}])

    def roundtrip(self, text, triple, expected_declarations=None):
        source = self.write(text, triple); before = source.read_bytes(); modules = []
        for path in (source, self.bitcode(source)):
            original = self.original_inventory(path); requests = self.original_uwtable(path)
            module = self.import_path(path); self.assert_inventory(module, original, triple)
            if expected_declarations is not None:
                self.assertEqual({row["symbol"]: row["level"] for row in requests if not row["definition"]}, expected_declarations)
            for request in requests:
                if not request["definition"]:
                    self.assert_declaration_provenance(module, request["symbol"], request["level"])
            modules.append(module)
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        return modules

    def reject(self, text, triple, stage="import", binary=True, diagnostic=None, symbol=None):
        source = self.write(text, triple)
        for path in ((source, self.bitcode(source)) if binary else (source,)):
            with self.assertRaises(importer.ImportFailure) as raised:
                self.import_path(path)
            self.assertEqual(raised.exception.stage, stage, "tool failure is not an input rejection")
            if diagnostic: self.assertIn(diagnostic, str(raised.exception))
            if symbol is not None: self.assertEqual(raised.exception.symbol, symbol)

    def test_sync_async_and_bare_ordinary_declarations_keep_whole_bodies_calls_globals_and_aliases_ll_bc_all_three(self):
        for triple in TRIPLES:
            reference = self.import_path(self.write(body(), triple))
            for spelling, level in SPELLINGS:
                for module in self.roundtrip(body(spelling), triple, {name: level for name in ANNOTATED}):
                    self.assertEqual(self.realization(module), self.realization(reference))
                    self.assertEqual({function["name"] for function in module["functions"]}, DECLARATIONS | DEFINITIONS)
                    self.assertEqual(len(module["globals"]), 4)
                    self.assertEqual(len(module["aliases"]), 2)

    def test_unreferenced_and_nounwind_declarations_are_retained_without_emitting_body_or_assuming_exception_services(self):
        for triple in TRIPLES:
            for spelling, level in SPELLINGS:
                for module in self.roundtrip(body("nounwind " + spelling), triple, {name: level for name in ANNOTATED}):
                    self.assertEqual(self.function(module, "cold_provider")["blocks"], [])
                    self.assertFalse(any(operation["op"] in {"trap", "unreachable"} for function in module["functions"] for operation in self.operations(function)))

    def test_declaration_and_definition_levels_do_not_change_signature_or_propagate_across_calls_or_module_default(self):
        for triple in TRIPLES:
            for declaration, declaration_level in SPELLINGS[:2]:
                for definition, definition_level in SPELLINGS[:2]:
                    for module_level in (0, 2):
                        metadata = f'!llvm.module.flags = !{{!0}}\n!0 = !{{i32 7, !"uwtable", i32 {module_level}}}\n'
                        for module in self.roundtrip(body(declaration, definition) + metadata, triple, {name: declaration_level for name in ANNOTATED}):
                            baseline.LlvmImportTests.assert_function_uwtable_provenance(self, module, "entry", definition_level)
                            self.assertFalse(any("nested: realized function uwtable=" in text for text in module["provenance"]["refinements"]))
                            self.assertTrue(all("uwtable" not in json.dumps(operation.get("signature", {}))
                                                for function in module["functions"] for operation in self.operations(function)))

    def test_callsite_direct_and_indirect_unwind_requests_remain_unsupported_on_all_three(self):
        for triple in TRIPLES:
            for spelling, _ in SPELLINGS:
                for callee in ("@foreign", "%callee"):
                    text = "declare i64 @foreign(i64)\ndefine i64 @entry(ptr %callee, i64 %value) {\n"
                    text += f"%result = call i64 {callee}(i64 %value) {spelling}\nret i64 %result\n}}\n"
                    self.reject(text, triple, diagnostic="unsupported uwtable", symbol="entry")

    def test_intrinsic_reader_normalization_does_not_widen_surviving_declaration_unwind_guards(self):
        a = self.library
        create = a.lib.LLVMCreateEnumAttribute; create.restype, create.argtypes = importer.P, [importer.P, importer.U, importer.Q]
        add = a.lib.LLVMAddAttributeAtIndex; add.restype, add.argtypes = None, [importer.P, importer.U, importer.P]
        kind = a.GetEnumAttributeKindForName(b"uwtable", 7)
        for triple in TRIPLES:
            for spelling, level in SPELLINGS:
                source = self.write(f"declare void @llvm.trap() {spelling}\n", triple)
                for path in (source, self.bitcode(source)):
                    # LLVM supplies canonical intrinsic attributes and removes
                    # this extra source request before the importer sees it.
                    # An accepted canonical declaration is not guard widening.
                    self.assertEqual(self.original_uwtable(path), [])
                    imported = self.import_path(path)
                    intrinsic = self.function(imported, "llvm.trap")
                    self.assertEqual(intrinsic["intrinsic"], "llvm.trap")
                    self.assertIsNone(intrinsic["entry"])
                    self.assertFalse(any("uwtable=" in text for text in imported["provenance"]["refinements"]))
                    data = path.read_bytes(); context = a.ContextCreate()
                    buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"surviving-uwtable-guard")
                    module, error = importer.P(), importer.P()
                    try:
                        self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0)
                        function = a.GetFirstFunction(module)
                        attribute = create(context, kind, level); add(function, 0xffffffff, attribute)
                        count = a.GetAttributeCountAtIndex(function, 0xffffffff); attributes = (importer.P * count)()
                        a.GetAttributesAtIndex(function, 0xffffffff, attributes)
                        self.assertEqual([int(a.GetEnumAttributeValue(item)) for item in attributes
                                          if a.IsEnumAttribute(item) and a.GetEnumAttributeKind(item) == kind], [level])
                        worker = importer.Importer(a, context, module); worker.symbol = "llvm.trap"
                        with self.assertRaises(importer.ImportFailure) as raised:
                            worker.attrs(function, 0xffffffff, intrinsic="llvm.trap")
                        self.assertEqual(raised.exception.stage, "import")
                        self.assertEqual(raised.exception.symbol, "llvm.trap")
                        self.assertIn("unsupported uwtable", str(raised.exception))
                        self.records.append({"input": artifacts.artifact(path), "boundary_guard": "CAPI intrinsic UW injected after canonical reader normalization",
                                             "level": level, "stage": raised.exception.stage, "symbol": raised.exception.symbol})
                    finally:
                        if error: a.DisposeMessage(error)
                        if module: a.DisposeModule(module)
                        a.DisposeMemoryBuffer(buffer); a.ContextDispose(context)

    def test_invalid_spellings_and_return_parameter_placements_reject_as_parse_errors(self):
        cases = ("declare i32 @foreign() uwtable(none)\n", "declare i32 @foreign() uwtable(default)\n",
                 "declare uwtable(sync) i32 @foreign()\n", "declare i32 @foreign(i32 uwtable(async))\n",
                 "define i32 @entry() { %r=call uwtable(sync) i32 @foreign()\nret i32 %r }\ndeclare i32 @foreign()\n")
        for triple in TRIPLES:
            for text in cases: self.reject(text, triple, stage="parse", binary=False)

    def test_declaration_bitcode_payloads_validate_normalized_levels_and_reject_surviving_invalid_values(self):
        a = self.library
        create = a.lib.LLVMCreateEnumAttribute; create.restype, create.argtypes = importer.P, [importer.P, importer.U, importer.Q]
        add = a.lib.LLVMAddAttributeAtIndex; add.restype, add.argtypes = None, [importer.P, importer.U, importer.P]
        kind = a.GetEnumAttributeKindForName(b"uwtable", 7)
        for triple in TRIPLES:
            source = self.write(body(), triple)
            reference = self.import_path(source)
            for raw, normalized in ((0, None), (1, 1), (2, 2), ((1 << 32) + 2, 2), (3, "reject"), ((1 << 64) - 1, "reject")):
                context = a.ContextCreate(); module, error = importer.P(), importer.P(); serialized = None
                data = source.read_bytes(); buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"uwtable-raw-declaration")
                try:
                    self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0)
                    attribute = create(context, kind, raw); self.assertEqual(int(a.GetEnumAttributeValue(attribute)), raw)
                    add(a.GetFirstFunction(module), 0xffffffff, attribute)
                    self.assertEqual(a.VerifyModule(module, 2, C.byref(error)), 0)
                    serialized = a.WriteBitcodeToMemoryBuffer(module)
                    binary = source.with_name(source.stem + f"-raw-{raw}.bc")
                    binary.write_bytes(C.string_at(a.GetBufferStart(serialized), a.GetBufferSize(serialized)))
                finally:
                    if serialized: a.DisposeMemoryBuffer(serialized)
                    if error: a.DisposeMessage(error)
                    if module: a.DisposeModule(module)
                    a.DisposeMemoryBuffer(buffer); a.ContextDispose(context)
                self.records.append({"input": artifacts.artifact(binary), "raw_capi_uwtable": raw, "expected_normalization": normalized})
                requests = self.original_uwtable(binary)
                if normalized == "reject":
                    self.assertTrue(requests)
                    with self.assertRaises(importer.ImportFailure) as raised: self.import_path(binary)
                    self.assertEqual(raised.exception.stage, "import")
                    self.assertEqual(raised.exception.symbol, "provider_a")
                    self.assertIn("unsupported uwtable", str(raised.exception))
                else:
                    self.assertEqual([request["level"] for request in requests], [] if normalized is None else [normalized])
                    imported = self.import_path(binary)
                    self.assertEqual(self.realization(imported), self.realization(reference))
                    if normalized is not None: self.assert_declaration_provenance(imported, "provider_a", normalized)

    def test_ordinary_declaration_admission_rejects_malformed_eh_callbacks_and_security_requirements(self):
        cases = (
            ("declare i32 @personality()\ndefine i32 @entry() personality ptr @personality { ret i32 0 }\n", "personality requires the exact five-argument C unwinder callback ABI"),
            ("declare i32 @personality()\ndeclare void @foreign()\ndefine void @entry() personality ptr @personality { invoke void @foreign() to label %ok unwind label %bad\nok: ret void\nbad: %exception = landingpad {ptr, i32} cleanup\nresume {ptr, i32} %exception }\n", "personality requires the exact five-argument C unwinder callback ABI"),
            ("define i32 @entry() shadowcallstack { ret i32 0 }\n", "unsupported attribute kind"),
        )
        for triple in TRIPLES:
            for text, diagnostic in cases:
                self.reject("declare void @cold_provider() uwtable(async)\n" + text, triple, diagnostic=diagnostic, symbol="entry")


if __name__ == "__main__": unittest.main()
