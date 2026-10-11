"""Exact load !noundef promises, independently verified original LLVM units.

These are source/API tests. They preserve every original load, call and symbol;
they do not execute native code or qualify sanitizers, providers or runtimes.
The Rust producer fixture is the unchanged earlier typed-read source.
"""

import ctypes as C
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory
from tests import test_ocore_llvm_aggregates as aggregates
from tests import test_ocore_native_allocsize as inventory_qa


TRIPLES = baseline.TRIPLES
SITE = "erased empty !noundef load promise; original load, volatile flag, alignment and type retained"
SUMMARY = "noundef metadata validated by exact parsed context name and empty MDNode on LoadInst only; input_sha256 binds the original bytes"


def artifact(path):
    path = Path(path).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(8 * 1024 * 1024):
            digest.update(block)
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def initialized_load():
    return """
@cold_global = constant i64 43, align 8
declare void @cold_provider(ptr)
define i32 @entry() {
  %slot = alloca i32, align 4
  store volatile i32 37, ptr %slot, align 4
  %value = load volatile i32, ptr %slot, align 4, !noundef !0
  ret i32 %value
}
!0 = !{}
"""


class LlvmNoundefMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()
        cls.library_artifact = artifact(cls.library)
        cls.worker_source = Path(importer.__file__).read_bytes()
        cls.test_source = Path(__file__).read_bytes()

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NOUNDEF_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-noundef-metadata-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.api = importer.LLVM(self.library, importer.PINNED_SHA256)
        self.sequence, self.records = 0, []

    def tearDown(self):
        worker = self.directory / "worker-source.py"
        test = self.directory / "test-source.py"
        worker.write_bytes(self.worker_source)
        test.write_bytes(self.test_source)
        report = {"scope": "exact empty load noundef metadata source/API conformance",
                  "test_id": self.id(), "test_source": artifact(test), "worker_source": artifact(worker),
                  "llvm_library": self.library_artifact, "records": self.records,
                  "native_execution_qualified": False, "runtime_complete": False,
                  "compiler_implementation_lowered": False, "dependency_closure_complete": False,
                  "memory_sanitizer_verified": False}
        (self.directory / "noundef-source-conformance.json").write_text(json.dumps(report, indent=2) + "\n")
        self.assertEqual(Path(importer.__file__).read_bytes(), self.worker_source)
        self.assertEqual(Path(__file__).read_bytes(), self.test_source)

    bitcode = memory.LlvmMemoryImportTests.bitcode
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)
    realization = staticmethod(aggregates.LlvmAggregateImportTests.realization)
    shape = classmethod(aggregates.LlvmAggregateImportTests.shape.__func__)
    rust_compiler = aggregates.LlvmAggregateImportTests.rust_compiler

    def write(self, body, triple):
        self.sequence += 1
        path = self.directory / f"original-{self.sequence:03}.ll"
        layout = memory.LAYOUT + ("-Fn32" if triple.startswith("aarch64-") else "")
        path.write_text(f'target triple = "{triple}"\ntarget datalayout = "{layout}"\n' + body)
        return path

    @contextmanager
    def original(self, path, custom_names=()):
        """InContext2 borrows its buffer; release each handle on every exit."""
        a = self.api
        context = a.ContextCreate()
        buffer = None
        module, error, message = importer.P(), importer.P(), importer.P()
        try:
            for name in custom_names:
                a.GetMDKindIDInContext(context, name.encode(), len(name))
            data = path.read_bytes()
            buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"original-noundef-oracle")
            status = a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error))
            self.assertEqual(status, 0, C.string_at(error).decode() if error else "LLVM parse failed")
            status = a.VerifyModule(module, 2, C.byref(message))
            self.assertEqual(status, 0, C.string_at(message).decode() if message else "LLVM verification failed")
            yield context, module
        finally:
            if message:
                a.DisposeMessage(message)
            if error:
                a.DisposeMessage(error)
            if module:
                a.DisposeModule(module)
            if buffer:
                a.DisposeMemoryBuffer(buffer)
            if context:
                a.ContextDispose(context)

    def llvm_shape(self, ty):
        a = self.api
        kind = a.GetTypeKind(ty)
        if kind == 8:
            return {"kind": "int", "bits": a.GetIntTypeWidth(ty)}
        if kind == 12:
            return {"kind": "pointer", "address_space": a.GetPointerAddressSpace(ty)}
        if kind == 11:
            return {"kind": "array", "len": a.GetArrayLength2(ty), "element": self.llvm_shape(a.GetElementType(ty))}
        if kind == 10:
            fields = (importer.P * a.CountStructElementTypes(ty))()
            a.GetStructElementTypes(ty, fields)
            return {"kind": "struct", "packed": bool(a.IsPackedStruct(ty)),
                    "fields": [self.llvm_shape(field) for field in fields]}
        return {"llvm_kind": kind}

    def metadata_oracle(self, path, custom_names=()):
        a = self.api
        result = {"loads": {}, "attachments": [], "context_ids": {}}
        with self.original(path, custom_names) as (context, module):
            def attachments(value, owner, global_value=False, block=None, ident=None):
                count = importer.S()
                entries = (a.GlobalCopyAllMetadata if global_value else a.InstructionGetAllMetadataOtherThanDebugLoc)(value, C.byref(count))
                try:
                    for index in range(count.value):
                        md = a.ValueMetadataEntriesGetMetadata(entries, index)
                        node = a.MetadataAsValue(context, md) if md else None
                        roundtrip = a.lib.LLVMValueAsMetadata
                        roundtrip.restype, roundtrip.argtypes = importer.P, [importer.P]
                        result["attachments"].append({"owner": owner, "global_value": global_value,
                            "opcode": None if global_value else a.GetInstructionOpcode(value),
                            "block": block, "value": ident, "kind": a.ValueMetadataEntriesGetKind(entries, index),
                            "is_node": bool(node and a.IsAMDNode(node)),
                            "roundtrip_identity": bool(node and roundtrip(node) == md),
                            "operand_count": a.GetMDNodeNumOperands(node) if node and a.IsAMDNode(node) else None})
                finally:
                    if entries:
                        a.DisposeValueMetadataEntries(entries)

            for value in a.sequence(a.GetFirstGlobal, a.GetNextGlobal, module):
                attachments(value, a.name(value), True)
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                name = a.name(function)
                attachments(function, name, True)
                result["loads"][name] = []
                ident = a.CountParams(function)
                for block_id, block in enumerate(a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function)):
                    for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                        has_result = a.GetTypeKind(a.TypeOf(instruction)) != 0
                        value_id = ident if has_result else None
                        attachments(instruction, name, block=block_id, ident=value_id)
                        if a.GetInstructionOpcode(instruction) == 27:
                            result["loads"][name].append({"block": block_id, "value": value_id,
                                "type": self.llvm_shape(a.TypeOf(instruction)), "alignment": a.GetAlignment(instruction),
                                "volatile": bool(a.GetVolatile(instruction)), "ordering": a.GetOrdering(instruction)})
                        if has_result:
                            ident += 1
            for name in ("noundef", "srcloc", "unknown.first", *custom_names):
                result["context_ids"][name] = a.GetMDKindIDInContext(context, name.encode(), len(name))
        return result

    def original_inventory(self, path):
        owner = unittest.TestCase()
        owner.library = self.api
        return inventory_qa.AllocsizeNativeTests.original_inventory(owner, path)

    def assert_inventory(self, path, module):
        original = self.original_inventory(path)
        oracle = self.metadata_oracle(path)
        self.assertEqual(module["provenance"]["input_sha256"], artifact(path)["sha256"])
        self.assertEqual(module["semantics"], "llvm_defined_behavior_v1")
        for kind, plural in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
            self.assertEqual([item["name"] for item in module[plural]], original[plural])
            self.assertEqual(module["provenance"]["source_" + kind + "_count"], len(original[plural]))
        self.assertEqual([fn["name"] for fn in module["functions"] if fn["entry"] is not None], original["definitions"])
        for function in module["functions"]:
            name = function["name"]
            operations = self.operations(function)
            accesses = [(op["op"], op.get("volatile", False)) for op in operations if op["op"] in {"load", "store"}]
            self.assertEqual(accesses, original["body_accesses"][name])
            source_calls = original["body_calls"][name]
            ordinary = [op["callee"].get("name") for op in operations if op["op"] == "call"]
            self.assertEqual(ordinary, [callee for callee in source_calls if callee is None or not callee.startswith("llvm.")])
            intrinsic_calls = [callee for callee in source_calls if callee and callee.startswith("llvm.")]
            expected = []
            for callee in intrinsic_calls:
                if callee.startswith(("llvm.memcpy.", "llvm.memmove.")):
                    expected.append("memory_copy")
                elif callee.startswith("llvm.memset."):
                    expected.append("memory_set")
                elif callee.startswith("llvm.lifetime."):
                    expected.append("lifetime")
                else:
                    self.fail(f"oracle needs an explicit effect mapping for {callee}")
            self.assertEqual([op["op"] for op in operations if op["op"] in {"memory_copy", "memory_set", "lifetime"}], expected)
            actual_loads = []
            for block in function["blocks"]:
                for instruction in block["instructions"]:
                    if instruction["operation"]["op"] == "load":
                        op, result = instruction["operation"], instruction["result"]
                        actual_loads.append({"block": block["id"], "value": result["id"],
                            "type": self.shape(module, result["ty"]), "alignment": op["alignment"],
                            "volatile": op["volatile"], "ordering": 0})
            self.assertEqual(actual_loads, oracle["loads"][name])
        notes = module["provenance"]["refinements"]
        attached = [row for row in oracle["attachments"] if row["kind"] == oracle["context_ids"]["noundef"]]
        matching = [note for note in notes if SITE in note]
        self.assertEqual(len(matching), len(attached))
        if attached:
            self.assertIn(SUMMARY, notes)
        else:
            self.assertNotIn(SUMMARY, notes)
        for row in attached:
            self.assertFalse(row["global_value"])
            self.assertEqual((row["opcode"], row["is_node"], row["operand_count"], row["roundtrip_identity"]), (27, True, 0, True))
            prefix = f"{row['owner']}: block {row['block']} load value {row['value']}: {SITE}"
            self.assertTrue(any(note.startswith(prefix) for note in matching), prefix)
        return original, oracle

    def accept(self, path, **kwargs):
        before = artifact(path)
        module = importer.import_module(path, library_path=self.library, **kwargs)
        original, oracle = self.assert_inventory(path, module)
        self.assertEqual(artifact(path), before)
        output = path.with_name(path.name + ".native.json")
        output.write_text(json.dumps(module, indent=2) + "\n")
        self.records.append({"input": before, "outcome": "accepted", "module": artifact(output),
                             "original_inventory": original, "original_metadata": oracle})
        return module

    def reject(self, path, diagnostic=None, symbol=None):
        before = artifact(path)
        # Both text and binary inputs must be genuinely LLVM-verified first.
        oracle = self.metadata_oracle(path)
        with self.assertRaises(importer.ImportFailure) as raised:
            importer.import_module(path, library_path=self.library)
        error = raised.exception
        self.assertEqual(error.stage, "import", "parser/verifier/tool failures are not import guard evidence")
        if diagnostic is not None:
            self.assertIn(diagnostic, str(error))
        if symbol is not None:
            self.assertEqual(error.symbol, symbol)
        self.assertEqual(artifact(path), before)
        self.records.append({"input": before, "outcome": "rejected", "original_metadata": oracle,
            "error": {"stage": error.stage, "symbol": error.symbol, "message": str(error)}})

    def pair(self, body, triple, accepted=True, diagnostic=None, symbol=None):
        source = self.write(body, triple)
        binary = self.bitcode(source)  # Parses and verifies the original before serializing.
        if not accepted:
            for path in (source, binary):
                with self.subTest(triple=triple, format=path.suffix):
                    self.reject(path, diagnostic, symbol)
            return []
        modules = [self.accept(path) for path in (source, binary)]
        self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        return modules

    def compare(self, annotated, plain, triple):
        original = self.pair(annotated, triple)
        ordinary = self.pair(plain, triple)
        self.assertEqual(self.realization(original[0]), self.realization(ordinary[0]),
                         "erasing an optimizer promise must preserve actual operations and ABI")
        return original

    def test_all_integer_widths_initialized_same_type_stores_preserve_bits_flags_alignment_and_loads_all_three_isas_ll_bc(self):
        functions = []
        for width in range(1, 65):
            alignment = 1 if width <= 8 else 2 if width <= 16 else 4 if width <= 32 else 8
            volatile = "volatile " if width % 2 else ""
            bits = (1 << width) - 1
            functions.append(f"""define i{width} @width{width}() {{
  %slot = alloca i{width}, align {alignment}
  store {volatile}i{width} {bits}, ptr %slot, align {alignment}
  %value = load {volatile}i{width}, ptr %slot, align {alignment}, !noundef !0
  ret i{width} %value
}}
""")
        body = "".join(functions) + "!0 = !{}\n"
        for triple in TRIPLES:
            for module in self.compare(body, body.replace(", !noundef !0", ""), triple):
                self.assertEqual(len(module["functions"]), 64)
                for width in range(1, 65):
                    ops = self.operations(self.function(module, "width" + str(width)))
                    self.assertEqual([op["op"] for op in ops], ["alloca", "store", "load"])
                    self.assertEqual(ops[1]["value"]["bits"], str((1 << width) - 1))
                    self.assertEqual(ops[1]["volatile"], bool(width % 2))

    def test_nullable_noundef_only_and_truthful_nonnull_alignment_companions_preserve_pointer_values_all_three_isas_ll_bc(self):
        body = """
@byte = global i8 5, align 16
define ptr @nullable() {
  %slot = alloca ptr, align 8
  store ptr null, ptr %slot, align 8
  %value = load ptr, ptr %slot, align 8, !noundef !0
  ret ptr %value
}
define ptr @nonnull_aligned() {
  %slot = alloca ptr, align 8
  store ptr @byte, ptr %slot, align 8
  %value = load volatile ptr, ptr %slot, align 8, !noundef !0, !nonnull !0, !align !1
  ret ptr %value
}
!0 = !{}
!1 = !{i64 16}
"""
        plain = body.replace(", !noundef !0", "").replace(", !nonnull !0, !align !1", "")
        for triple in TRIPLES:
            for module in self.compare(body, plain, triple):
                nullable = self.operations(self.function(module, "nullable"))
                self.assertEqual(nullable[1]["value"]["kind"], "null")
                nonnull = self.operations(self.function(module, "nonnull_aligned"))
                self.assertEqual(nonnull[1]["value"]["name"], "byte")
                self.assertTrue(nonnull[2]["volatile"])
                self.assertEqual(nonnull[2]["alignment"], 8, "loaded-pointer promise is not load-address alignment")

    def test_initialized_nested_named_packed_array_and_empty_aggregate_loads_preserve_type_tree_all_three_isas_ll_bc(self):
        body = """
%R = type <{i7, [2 x {i33, ptr}], i1}>
@record = constant %R <{i7 17, [2 x {i33, ptr}] [{i33, ptr} {i33 19, ptr null}, {i33, ptr} {i33 23, ptr null}], i1 true}>, align 1
@array = constant [2 x i21] [i21 31, i21 37], align 8
@empty = constant {} zeroinitializer
@record_alias = alias %R, ptr @record
@cold_address = constant ptr @record_alias
define void @read(ptr %out) {
  %record = load %R, ptr @record_alias, align 1, !noundef !0
  store %R %record, ptr %out, align 1
  %array = load [2 x i21], ptr @array, align 8, !noundef !0
  store [2 x i21] %array, ptr %out, align 1
  %empty = load {}, ptr @empty, align 1, !noundef !0
  store {} %empty, ptr %out, align 1
  ret void
}
!0 = !{}
"""
        for triple in TRIPLES:
            for module in self.compare(body, body.replace(", !noundef !0", ""), triple):
                instructions = self.instructions(self.function(module, "read"))
                self.assertEqual([row["operation"]["op"] for row in instructions], ["load", "store"] * 3)
                self.assertTrue(self.shape(module, instructions[0]["result"]["ty"])["packed"])
                self.assertEqual(self.shape(module, instructions[4]["result"]["ty"]), {"kind": "struct", "packed": False, "fields": []})
                self.assertEqual(len(module["globals"]), 4)
                self.assertEqual(module["aliases"][0]["name"], "record_alias")

    def test_multiblock_site_provenance_cold_calls_globals_and_parameter_attributes_do_not_add_guards_all_three_isas_ll_bc(self):
        body = """
@state = global i64 41, align 8
@state_alias = alias i64, ptr @state
@cold_address = constant ptr @state_alias
declare i64 @cold_provider(i64)
define i64 @entry(i1 noundef %flag) {
entry:
  %first = load volatile i64, ptr @state, align 8, !noundef !0
  br i1 %flag, label %then, label %else
then:
  %second = load i64, ptr @state_alias, align 8, !noundef !0
  ret i64 %second
else:
  store volatile i64 %first, ptr @state, align 8
  %third = load volatile i64, ptr @state, align 8, !noundef !0
  ret i64 %third
}
define i64 @cold(i64 %value) {
  %result = call i64 @cold_provider(i64 %value)
  ret i64 %result
}
!0 = !{}
"""
        for triple in TRIPLES:
            for module in self.compare(body, body.replace(", !noundef !0", ""), triple):
                entry = self.function(module, "entry")
                self.assertEqual(len(entry["blocks"]), 3)
                self.assertEqual(entry["signature"]["param_attributes"], [[]])
                self.assertEqual([op["op"] for op in self.operations(entry)], ["load", "load", "store", "load"])
                self.assertEqual(self.operations(self.function(module, "cold"))[0]["callee"]["name"], "cold_provider")

    def test_distinct_and_uniqued_empty_nodes_have_the_same_load_contract_all_three_isas_ll_bc(self):
        body = initialized_load().replace("!0 = !{}", "!0 = distinct !{}")
        plain = initialized_load().replace(", !noundef !0", "")
        for triple in TRIPLES:
            self.compare(body, plain, triple)

    def test_verifier_valid_nonempty_integer_string_null_nested_and_mixed_nodes_reject_explicit_payload_guard_all_three_isas_ll_bc(self):
        payloads = ("!{i32 1}", "!{i64 1}", '!{!"bad"}', "!{null}", "!{!1}\n!1 = !{}", '!{i1 true, !"bad", null}')
        for triple in TRIPLES:
            for payload in payloads:
                with self.subTest(triple=triple, payload=payload):
                    self.pair(initialized_load().replace("!0 = !{}", "!0 = " + payload), triple, False,
                              "noundef load metadata requires an empty MDNode", "entry")

    def test_verifier_valid_call_store_add_return_global_and_function_owners_reject_explicit_owner_guard_all_three_isas_ll_bc(self):
        bodies = {
            "call": "declare i32 @g()\ndefine i32 @bad() { %v = call i32 @g(), !noundef !0\nret i32 %v }",
            "store": "define void @bad(ptr %p) { store i32 7, ptr %p, !noundef !0\nret void }",
            "add": "define i32 @bad(i32 %x) { %v = add i32 %x, 1, !noundef !0\nret i32 %v }",
            "return": "define i32 @bad() { ret i32 7, !noundef !0 }",
            "global": "@bad = global i32 7, !noundef !0\ndefine void @f() { ret void }",
            "function": "define void @bad() !noundef !0 { ret void }",
        }
        for triple in TRIPLES:
            for owner, body in bodies.items():
                with self.subTest(triple=triple, owner=owner):
                    self.pair(body + "\n!0 = !{}\n", triple, False,
                              "noundef metadata requires a LoadInst owner", "bad")

    def test_arbitrary_context_name_allocated_numeric47_is_not_admitted_as_noundef_all_three_isas_ll_bc(self):
        body = initialized_load().replace("!noundef !0", "!unknown.first !0")
        for triple in TRIPLES:
            source = self.write(body, triple)
            for path in (source, self.bitcode(source)):
                oracle = self.metadata_oracle(path)
                self.assertEqual(oracle["context_ids"]["unknown.first"], 47)
                self.assertEqual(oracle["attachments"][0]["kind"], 47)
                self.reject(path, "unsupported metadata kind 47", "entry")

    def test_srcloc_context_ids_shift_but_unsupported_inline_asm_and_diagnostic_metadata_remain_rejected_all_three_isas_ll_bc(self):
        asm = 'define void @bad() { call void asm sideeffect "", "~{memory}"()\nret void }\n'
        annotated = asm.replace('"~{memory}"()', '"~{memory}"(), !srcloc !0') + "!0 = !{i64 8516284494791009}\n"
        for triple in TRIPLES:
            # Current phase admits only noundef: srcloc is rejected before the
            # independent ordinary-operand guard rejects unannotated asm.
            self.pair(asm, triple, False, "unsupported constant expression or non-scalar operand", "bad")
            source = self.write(annotated, triple)
            for path in (source, self.bitcode(source)):
                for names, expected in (((), 47), (("custom.first",), 48), (("custom.first", "custom.second"), 49)):
                    oracle = self.metadata_oracle(path, names)
                    self.assertEqual(oracle["context_ids"]["srcloc"], expected)
                    self.assertEqual(oracle["attachments"][0]["kind"], expected)
                    self.records.append({"input": artifact(path), "outcome": "original-context-oracle",
                                         "preallocated_custom_names": names, "original_metadata": oracle})
                self.reject(path, "unsupported metadata kind 47", "bad")

    def test_atomic_load_preserves_empty_metadata_while_nondefault_address_space_float_vector_and_wide_integer_guards_survive_all_three_isas_ll_bc(self):
        atomic = "define i32 @bad(ptr %p) { %v = load atomic i32, ptr %p monotonic, align 4, !noundef !0\nret i32 %v }"
        cases = (
            ("define i32 @bad(ptr addrspace(1) %p) { %v = load i32, ptr addrspace(1) %p, !noundef !0\nret i32 %v }", "unsupported pointer address space 1"),
            ("define double @bad(ptr %p) { %v = load double, ptr %p, !noundef !0\nret double %v }", "unsupported LLVM type kind"),
            ("define <2 x i32> @bad(ptr %p) { %v = load <2 x i32>, ptr %p, !noundef !0\nret <2 x i32> %v }", "unsupported LLVM type kind"),
            ("define i65 @bad(ptr %p) { %v = load i65, ptr %p, !noundef !0\nret i65 %v }", "unsupported integer width i65"),
        )
        for triple in TRIPLES:
            source = self.write(atomic + "\n!0 = !{}\n", triple)
            modules = []
            for path in (source, self.bitcode(source)):
                with self.subTest(triple=triple, format=path.suffix, supported_atomic=True):
                    before = artifact(path)
                    original = self.original_inventory(path)
                    metadata = self.metadata_oracle(path)
                    module = importer.import_module(path, library_path=self.library)
                    modules.append(module)
                    self.assertEqual(artifact(path), before)
                    self.assertEqual(module["provenance"]["input_sha256"], before["sha256"])
                    for singular, plural in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
                        self.assertEqual([row["name"] for row in module[plural]], original[plural])
                        self.assertEqual(module["provenance"]["source_" + singular + "_count"], len(original[plural]))
                    self.assertEqual(original["definitions"], ["bad"])
                    source_load = metadata["loads"]["bad"]
                    self.assertEqual(source_load, [{"block": 0, "value": 1, "type": {"kind": "int", "bits": 32},
                                                    "alignment": 4, "volatile": False, "ordering": 2}])
                    rows = self.instructions(self.function(module, "bad"))
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["operation"], {"op": "atomic_load", "pointer": {"kind": "value", "id": 0},
                                                           "alignment": 4, "volatile": False, "ordering": "monotonic", "sync_scope": 1})
                    self.assertEqual(rows[0]["result"]["id"], source_load[0]["value"])
                    self.assertEqual(self.shape(module, rows[0]["result"]["ty"]), source_load[0]["type"])
                    self.assertEqual(len(metadata["attachments"]), 1)
                    attachment = metadata["attachments"][0]
                    self.assertEqual((attachment["owner"], attachment["opcode"], attachment["kind"], attachment["operand_count"], attachment["roundtrip_identity"]),
                                     ("bad", 27, metadata["context_ids"]["noundef"], 0, True))
                    notes = module["provenance"]["refinements"]
                    self.assertIn(SUMMARY, notes)
                    self.assertEqual(sum(note.startswith(f"bad: block 0 load value 1: {SITE}") for note in notes), 1)
                    self.assertNotIn("atomic_profile", module["target"])
                    output = path.with_name(path.name + ".native.json")
                    output.write_text(json.dumps(module, indent=2) + "\n")
                    self.records.append({"input": before, "outcome": "accepted", "module": artifact(output),
                                         "original_inventory": original, "original_metadata": metadata})
            self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            for body, diagnostic in cases:
                self.pair(body + "\n!0 = !{}\n", triple, False, diagnostic, "bad")

    def test_whole_unused_float_tls_and_personality_units_still_fail_without_filtering_all_three_isas_ll_bc(self):
        cases = (
            ("declare double @unused_float(double)\n", "unsupported LLVM type kind", "unused_float"),
            ("@unused_tls = thread_local global i32 7\n", "TLS globals require explicit --tls-profile linux-elf-static-nonpreemptive-v1", "unused_tls"),
            ("declare i32 @personality()\ndefine void @unused_eh() personality ptr @personality { ret void }\n", "personality requires the exact five-argument C unwinder callback ABI", "unused_eh"),
        )
        for triple in TRIPLES:
            for suffix, diagnostic, symbol in cases:
                self.pair(initialized_load() + suffix, triple, False, diagnostic, symbol)

    def rust_compile(self, rustc, source, target, suffix):
        # Reuse the original frontend recipe verbatim; record every original
        # source/output and command locally rather than rewrite generated IR.
        return aggregates.LlvmAggregateImportTests.rust_compile(self, rustc, source, target, suffix)

    def record_producer(self, command, result, source, output):
        source_copy = output.with_name(output.name + ".source.rs")
        source_copy.write_bytes(source.read_bytes())
        self.records.append({"outcome": "original-producer", "command": [str(arg) for arg in command],
            "cwd": str(baseline.ROOT), "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            "source": artifact(source), "source_copy": artifact(source_copy),
            "input": artifact(output) if output.exists() else None})

    def test_unchanged_rust1971_typed_read_whole_units_and_original_pair_variant_preserve_all_loads_and_genuine_targets_all_three_isas_ll_bc(self):
        rustc, version = self.rust_compiler()
        original = aggregates.LlvmAggregateImportTests.rust_typed_read_source()
        pair = '''#[repr(C)] pub struct Small { pub first: u64, pub second: u64 }
#[no_mangle] pub extern "C" fn unsupported_pair(value: u64) -> Small { Small { first: value, second: value ^ 37 } }
'''
        for with_pair in (False, True):
            source = self.directory / ("whole-typed-read-pair.rs" if with_pair else "whole-typed-read.rs")
            source.write_text(original + (pair if with_pair else ""))
            before = artifact(source)
            self.assertTrue(source.read_text().startswith(original), "earlier typed-read source must remain byte-identical")
            for target, triple, abi in ((TRIPLES[0], TRIPLES[0], None), (TRIPLES[1], TRIPLES[1], None),
                                       ("riscv64gc-unknown-linux-gnu", TRIPLES[2], "lp64d")):
                modules = []
                for suffix in ("ll", "bc"):
                    path = self.rust_compile(rustc, source, target, suffix)
                    module = self.accept(path, frontend="Rust", frontend_version=version)
                    modules.append(module)
                    self.assertEqual(module["target"]["triple"], triple)
                    self.assertEqual(module["target"].get("abi"), abi)
                    expected = {"rust_make", "rust_read", "rust_scalar"} | ({"unsupported_pair"} if with_pair else set())
                    self.assertEqual({fn["name"] for fn in module["functions"] if fn["entry"] is not None}, expected)
                    self.assertEqual({g["name"] for g in module["globals"]}, {"rust_state"})
                    self.assertTrue(any(note.startswith("rust_read:") and SITE in note for note in module["provenance"]["refinements"]))
                    self.assertEqual([op["op"] for op in self.operations(self.function(module, "rust_read"))].count("load"), 2)
                    if suffix == "ll":
                        self.assertIn("!noundef", path.read_text())
                self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(artifact(source), before)

    def test_original_rust_typed_read_with_unused_float_keeps_whole_unit_rejection_after_metadata_admission_all_three_isas_ll_bc(self):
        rustc, version = self.rust_compiler()
        source = self.directory / "whole-typed-read-unused-float.rs"
        source.write_text(aggregates.LlvmAggregateImportTests.rust_typed_read_source() +
                          '#[no_mangle] pub extern "C" fn unused_float(value: u64) -> f64 { value as f64 }\n')
        before = artifact(source)
        for target in (TRIPLES[0], TRIPLES[1], "riscv64gc-unknown-linux-gnu"):
            for suffix in ("ll", "bc"):
                path = self.rust_compile(rustc, source, target, suffix)
                if suffix == "ll":
                    self.assertIn("!noundef", path.read_text())
                    self.assertIn("@unused_float(", path.read_text())
                self.reject(path, "unsupported LLVM type kind", "unused_float")
        self.assertEqual(artifact(source), before)


if __name__ == "__main__":
    unittest.main()
