"""Whole original LLVM integer min/max at the source/API boundary.

The independent typed C API census checks original identities, scalar widths,
SSA operands, signatures and effects. These tests do not execute min/max,
establish native poison/undef refinement or prove runtime/provider closure.
Original producer units and parsed intrinsic normalization are retained.
"""

import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory
from tests import test_ocore_llvm_aggregates as aggregates
from tests import test_ocore_llvm_noundef_metadata as noundef
from tests import test_ocore_llvm_eh_import as eh


TRIPLES = baseline.TRIPLES
FAMILIES = ("smin", "smax", "umin", "umax")
# Pinned generated provider IDs, independently recorded by the primary packet.
# Neither the production resolver nor its operation map is the test oracle.
INTRINSIC_IDS = {"smin": 343, "smax": 342, "umin": 380, "umax": 379}


def name(family, width):
    return f"llvm.{family}.i{width}"


def declaration(family, width):
    return f"declare i{width} @{name(family, width)}(i{width}, i{width})\n"


class LlvmIntegerMinMaxImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()
        cls.library_artifact = noundef.artifact(cls.library)
        cls.worker_source = Path(importer.__file__).read_bytes()
        cls.test_source = Path(__file__).read_bytes()

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_MINMAX_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-minmax-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.api = importer.LLVM(self.library, importer.PINNED_SHA256)
        self.sequence, self.records = 0, []

    original = eh.LlvmEHImportTests.original
    llvm_shape = eh.LlvmEHImportTests.llvm_shape
    write = eh.LlvmEHImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)
    shape = classmethod(aggregates.LlvmAggregateImportTests.shape.__func__)
    realization = staticmethod(aggregates.LlvmAggregateImportTests.realization)
    raw_attributes = eh.LlvmEHImportTests.raw_attributes
    signature = eh.LlvmEHImportTests.signature
    native_signature = eh.LlvmEHImportTests.native_signature
    strip_types = staticmethod(eh.LlvmEHImportTests.strip_types)
    rust_compiler = aggregates.LlvmAggregateImportTests.rust_compiler

    def tearDown(self):
        worker, test = self.directory / "worker-source.py", self.directory / "test-source.py"
        worker.write_bytes(self.worker_source)
        test.write_bytes(self.test_source)
        report = {"schema": "ocore-llvm-minmax-source-conformance-v1", "test_id": self.id(),
            "scope": "whole original scalar integer min/max source/API conformance",
            "worker_source": noundef.artifact(worker), "test_source": noundef.artifact(test),
            "llvm_library": self.library_artifact, "records": self.records,
            "native_execution_qualified": False, "native_poison_undef_refinement_verified": False,
            "compiler_implementation_lowered": False, "runtime_complete": False,
            "dependency_closure_complete": False}
        (self.directory / "minmax-source-conformance.json").write_text(json.dumps(report, indent=2) + "\n")
        self.assertEqual(Path(importer.__file__).read_bytes(), self.worker_source)
        self.assertEqual(Path(__file__).read_bytes(), self.test_source)

    def operand(self, value, ids):
        if self.api.IsAPoisonValue(value):
            return {"kind": "poison"}
        if self.api.IsAUndefValue(value):
            return {"kind": "undef"}
        return eh.LlvmEHImportTests.operand(self, value, ids)

    def oracle(self, path):
        """Census the verified parsed original, without importing/lowering it."""
        a = self.api
        original = {"functions": [], "definitions": [], "globals": [], "aliases": [],
                    "signatures": {}, "bodies": {}, "intrinsic_ids": {}, "generated_promises": {}}
        no_create = a.GetEnumAttributeKindForName(b"nocreateundeforpoison", 21)
        with self.original(path) as (_, module):
            original["globals"] = [a.name(g) for g in a.sequence(a.GetFirstGlobal, a.GetNextGlobal, module)]
            original["aliases"] = [a.name(g) for g in a.sequence(a.GetFirstGlobalAlias, a.GetNextGlobalAlias, module)]
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                fn = a.name(function)
                original["functions"].append(fn)
                original["signatures"][fn] = self.signature(a.GlobalGetValueType(function), function)
                original["intrinsic_ids"][fn] = a.GetIntrinsicID(function)
                promises = [int(a.GetEnumAttributeValue(attr)) for attr in self.raw_attributes(function, 0xffffffff)
                    if a.IsEnumAttribute(attr) and a.GetEnumAttributeKind(attr) == no_create]
                original["generated_promises"][fn] = promises
                params = (importer.P * a.CountParams(function))()
                a.GetParams(function, params)
                ids = {value: index for index, value in enumerate(params)}
                blocks = list(a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function))
                if blocks:
                    original["definitions"].append(fn)
                for block in blocks:
                    for value in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                        if a.GetTypeKind(a.TypeOf(value)) != 0:
                            ids[value] = len(ids)
                body = {"minmax": [], "ordinary_calls": [], "accesses": [], "other_intrinsics": []}
                original["bodies"][fn] = body
                for block_id, block in enumerate(blocks):
                    for ordinal, value in enumerate(a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block)):
                        opcode = a.GetInstructionOpcode(value)
                        result = None if a.GetTypeKind(a.TypeOf(value)) == 0 else {
                            "id": ids[value], "type": self.llvm_shape(a.TypeOf(value))}
                        if opcode == 45:
                            callee = a.GetCalledValue(value)
                            ident = a.GetIntrinsicID(callee) if a.IsAFunction(callee) else 0
                            callee_name = a.name(callee) if a.IsAFunction(callee) else ""
                            args = [self.operand(a.GetOperand(value, i), ids) for i in range(a.GetNumArgOperands(value))]
                            if ident in INTRINSIC_IDS.values():
                                family = next(k for k, v in INTRINSIC_IDS.items() if v == ident)
                                body["minmax"].append({"block": block_id, "source_instruction": ordinal,
                                    "intrinsic": callee_name, "raw_intrinsic_id": ident,
                                    "signature": self.signature(a.GetCalledFunctionType(value), value, True),
                                    "operation": {"op": "integer_min_max", "kind": family, "lhs": args[0], "rhs": args[1]},
                                    "result": result})
                            elif callee_name.startswith("llvm."):
                                body["other_intrinsics"].append(callee_name)
                            else:
                                body["ordinary_calls"].append({"block": block_id,
                                    "callee": self.operand(callee, ids),
                                    "signature": self.signature(a.GetCalledFunctionType(value), value, True),
                                    "args": args, "result": result})
                        elif opcode in (27, 28):
                            op = {"op": "load" if opcode == 27 else "store",
                                "pointer": self.operand(a.GetOperand(value, 0 if opcode == 27 else 1), ids),
                                "alignment": a.GetAlignment(value) or (1 << 32), "volatile": bool(a.GetVolatile(value))}
                            if opcode == 28:
                                op["value"] = self.operand(a.GetOperand(value, 0), ids)
                            body["accesses"].append({"block": block_id, "operation": op, "result": result})
        return original

    def assert_original(self, path, module, triple=None):
        original = self.oracle(path)
        self.assertEqual(module["provenance"]["input_sha256"], noundef.artifact(path)["sha256"])
        if triple is not None:
            self.assertEqual(module["target"]["triple"], triple)
        for category, plural in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
            self.assertEqual([value["name"] for value in module[plural]], original[plural])
            self.assertEqual(module["provenance"]["source_" + category + "_count"], len(original[plural]))
        self.assertEqual([f["name"] for f in module["functions"] if f["entry"] is not None], original["definitions"])
        for function in module["functions"]:
            fn = function["name"]
            self.assertEqual(self.native_signature(module, function["signature"]), original["signatures"][fn])
            minmax, calls, accesses, other_intrinsics = [], [], [], []
            for block in function["blocks"]:
                for instruction in block["instructions"]:
                    op, value = instruction["operation"], instruction["result"]
                    result = None if value is None else {"id": value["id"], "type": self.shape(module, value["ty"])}
                    if op["op"] == "integer_min_max":
                        self.assertEqual(set(op), {"op", "kind", "lhs", "rhs"})
                        minmax.append({"block": block["id"], "operation": {**op,
                            "lhs": self.strip_types(op["lhs"]), "rhs": self.strip_types(op["rhs"])}, "result": result})
                    elif op["op"] == "call":
                        calls.append({"block": block["id"], "callee": self.strip_types(op["callee"]),
                            "signature": self.native_signature(module, op["signature"]),
                            "args": [self.strip_types(arg) for arg in op["args"]], "result": result})
                    elif op["op"] in ("load", "store"):
                        accesses.append({"block": block["id"], "operation": {k: self.strip_types(v)
                            if k in {"pointer", "value"} else v for k, v in op.items()}, "result": result})
                    elif op["op"] in {"lifetime", "memory_set", "memory_copy", "assume", "trap", "no_alias_scope_decl"}:
                        other_intrinsics.append(op["op"])
            body = original["bodies"][fn]
            self.assertEqual(minmax, [{k: v for k, v in row.items() if k in {"block", "operation", "result"}}
                                     for row in body["minmax"]])
            self.assertEqual(calls, body["ordinary_calls"])
            self.assertEqual(accesses, body["accesses"])
            expected_intrinsics = []
            for intrinsic in body["other_intrinsics"]:
                if intrinsic.startswith("llvm.lifetime."):
                    expected_intrinsics.append("lifetime")
                elif intrinsic.startswith(("llvm.memcpy.", "llvm.memmove.")):
                    expected_intrinsics.append("memory_copy")
                elif intrinsic.startswith("llvm.memset."):
                    expected_intrinsics.append("memory_set")
                else:
                    expected_intrinsics.append({"llvm.assume": "assume", "llvm.trap": "trap",
                        "llvm.experimental.noalias.scope.decl": "no_alias_scope_decl"}[intrinsic])
            self.assertEqual(other_intrinsics, expected_intrinsics)
            for row in body["minmax"]:
                width = row["result"]["type"]["bits"]
                self.assertEqual(row["intrinsic"], name(row["operation"]["kind"], width))
                self.assertEqual(row["signature"]["result"], {"kind": "int", "bits": width})
                self.assertEqual(row["signature"]["params"], [{"kind": "int", "bits": width}] * 2)
                self.assertEqual(row["signature"]["convention"], 0)
        return original

    def accept_path(self, path, triple=None, frontend="LLVM IR", version="authored original LLVM22 unit"):
        try:
            module = importer.import_module(path, library_path=self.library, frontend=frontend, frontend_version=version)
        except importer.ImportFailure as error:
            self.records.append({"input": noundef.artifact(path), "unexpected_error": {
                "stage": error.stage, "symbol": error.symbol, "message": str(error)}})
            raise
        original = self.assert_original(path, module, triple)
        output = path.with_suffix(path.suffix + ".module.json")
        output.write_text(json.dumps(module, indent=2) + "\n")
        oracle = path.with_suffix(path.suffix + ".original-capi.json")
        oracle.write_text(json.dumps(original, indent=2) + "\n")
        self.records.append({"input": noundef.artifact(path), "module": noundef.artifact(output),
                             "original_capi": noundef.artifact(oracle)})
        return module

    def roundtrip(self, body, triple):
        text = self.write(body, triple)
        modules = [self.accept_path(path, triple) for path in (text, self.bitcode(text))]
        self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        return modules

    def reject(self, body, triple, stage="import", binary=True, symbol=None, diagnostic=None):
        text = self.write(body, triple)
        for path in (text, self.bitcode(text)) if binary else (text,):
            self.records.append({"attempted_rejection_input": noundef.artifact(path), "expected_stage": stage})
            try:
                module = importer.import_module(path, library_path=self.library)
            except importer.ImportFailure as failure:
                error = failure
            else:
                output = path.with_suffix(path.suffix + ".unexpected-module.json")
                output.write_text(json.dumps(module, indent=2) + "\n")
                self.records.append({"input": noundef.artifact(path), "unexpected_module": noundef.artifact(output)})
                self.fail(f"whole source expected {stage} rejection but imported successfully: {path}")
            self.records.append({"input": noundef.artifact(path), "error": {
                "stage": error.stage, "symbol": error.symbol, "message": str(error)}})
            self.assertEqual(error.stage, stage, "toolchain failure is not an input rejection")
            if symbol is not None:
                self.assertEqual(error.symbol, symbol)
            if diagnostic is not None:
                self.assertIn(diagnostic, str(error))

    def assert_declaration(self, module, family, width):
        function = self.function(module, name(family, width))
        self.assertEqual(function["intrinsic"], name(family, width))
        self.assertEqual((function["linkage"], function["visibility"], function["blocks"], function["entry"]),
                         ("external", "default", [], None))
        signature = function["signature"]
        self.assertEqual(self.native_signature(module, signature), {"result": {"kind": "int", "bits": width},
            "params": [{"kind": "int", "bits": width}] * 2, "variadic": False, "convention": 0,
            "result_attributes": [], "param_attributes": [[], []], "return_storage": None})

    def test_all_four_families_and_every_width_1_to_64_preserve_complete_units_all_three_isas_ll_bc(self):
        parts, expected = [], set()
        for family in FAMILIES:
            for width in range(1, 65):
                function = f"probe_{family}_{width}"
                expected.update((function, name(family, width)))
                parts.append(declaration(family, width) + f"define i{width} @{function}(i{width} %a, i{width} %b) {{\n%value = call i{width} @{name(family, width)}(i{width} %a, i{width} %b)\nret i{width} %value\n}}\n")
        parts.append("""@retained = global i64 37
@address = global ptr @probe_smin_64
@ordinary_alias = alias i64(i64,i64), ptr @probe_smin_64
declare void @unused_declaration(ptr)
define void @unused_cold(i64 %a, i64 %b) cold {
  %v = call i64 @llvm.smin.i64(i64 %a, i64 %b)
  store volatile i64 %v, ptr @retained, align 8
  ret void
}
""")
        expected.update(("unused_declaration", "unused_cold"))
        for triple in TRIPLES:
            for module in self.roundtrip("".join(parts), triple):
                self.assertEqual({f["name"] for f in module["functions"]}, expected)
                self.assertEqual(len(module["functions"]), 514)
                self.assertEqual([g["name"] for g in module["globals"]], ["retained", "address"])
                self.assertEqual(module["globals"][1]["initializer"]["relocations"],
                                 [{"offset": 0, "width": 64, "symbol": "probe_smin_64", "addend": 0}])
                self.assertEqual(module["aliases"][0]["aliasee"], "probe_smin_64")
                for family in FAMILIES:
                    for width in range(1, 65):
                        self.assert_declaration(module, family, width)
                        fn = self.function(module, f"probe_{family}_{width}")
                        inst, = self.instructions(fn)
                        self.assertEqual(inst["operation"], {"op": "integer_min_max", "kind": family,
                            "lhs": {"kind": "value", "id": fn["params"][0]["id"]},
                            "rhs": {"kind": "value", "id": fn["params"][1]["id"]}})
                        self.assertEqual(inst["result"]["ty"], fn["signature"]["result"])
                        self.assertEqual(fn["blocks"][0]["terminator"]["value"], {"kind": "value", "id": inst["result"]["id"]})
                self.assertEqual([o["op"] for o in self.operations(self.function(module, "unused_cold"))],
                                 ["integer_min_max", "store"])

    def test_all_256_unused_declarations_have_exact_typed_ids_signatures_and_generated_enum_zero_promises(self):
        body = "".join(declaration(family, width) for family in FAMILIES for width in range(1, 65))
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                self.assertEqual(len(module["functions"]), 256)
                self.assertEqual((module["globals"], module["aliases"]), ([], []))
                for family in FAMILIES:
                    for width in range(1, 65):
                        self.assert_declaration(module, family, width)
            original = self.oracle(self.directory / f"original-{self.sequence:03}.ll")
            for family in FAMILIES:
                for width in range(1, 65):
                    self.assertEqual(original["intrinsic_ids"][name(family, width)], INTRINSIC_IDS[family])
                    self.assertEqual(original["generated_promises"][name(family, width)], [0])

    def test_i1_signed_true_and_false_operands_keep_all_four_truth_tables_without_boolean_or_arithmetic_rewrite(self):
        # Pinned original mathematical identity: signed true=-1, false=0.
        # Source tests assert the operation and original inputs, not execution.
        parts = [declaration(f, 1) for f in FAMILIES]
        for family in FAMILIES:
            for lhs in (0, 1):
                for rhs in (0, 1):
                    parts.append(f"define i1 @{family}_{lhs}_{rhs}() {{\n%v = call i1 @{name(family, 1)}(i1 {lhs}, i1 {rhs})\nret i1 %v\n}}\n")
        for triple in TRIPLES:
            for module in self.roundtrip("".join(parts), triple):
                for family in FAMILIES:
                    for lhs in (0, 1):
                        for rhs in (0, 1):
                            op, = self.operations(self.function(module, f"{family}_{lhs}_{rhs}"))
                            self.assertEqual(op["kind"], family)
                            self.assertEqual((op["lhs"]["bits"], op["rhs"]["bits"]), (str(lhs), str(rhs)))
                            self.assertEqual(self.shape(module, op["lhs"]["ty"]), {"kind": "int", "bits": 1})

    def test_signed_unsigned_extreme_and_equality_inputs_keep_original_bits_operand_order_and_width_all_64_widths(self):
        parts, inputs = [], {}
        for width in range(1, 65):
            for family in FAMILIES:
                parts.append(declaration(family, width))
                minimum, maximum = 1 << (width - 1), (1 << (width - 1)) - 1
                for case, pair in enumerate(((minimum, maximum), ((1 << width) - 1, 0), (maximum, maximum))):
                    fn = f"extreme_{family}_{width}_{case}"
                    inputs[fn] = (family, width, pair)
                    parts.append(f"define i{width} @{fn}() {{\n%v = call i{width} @{name(family, width)}(i{width} {pair[0]}, i{width} {pair[1]})\nret i{width} %v\n}}\n")
        for triple in TRIPLES:
            for module in self.roundtrip("".join(parts), triple):
                for fn, (family, width, pair) in inputs.items():
                    op, = self.operations(self.function(module, fn))
                    self.assertEqual((op["kind"], op["lhs"]["bits"], op["rhs"]["bits"]), (family, str(pair[0]), str(pair[1])))
                    self.assertEqual(self.shape(module, op["rhs"]["ty"]), {"kind": "int", "bits": width})

    def test_same_ssa_undef_and_poison_are_represented_once_per_operand_with_only_original_result_freezes(self):
        parts = []
        for family in FAMILIES:
            parts.append(declaration(family, 7))
            for category, operands in (("same", "i7 %a, i7 %a"), ("undef", "i7 undef, i7 37"),
                                       ("poison", "i7 poison, i7 37"), ("both", "i7 undef, i7 undef")):
                parts.append(f"define i7 @{family}_{category}(i7 %a) {{\n%v = call i7 @{name(family, 7)}({operands})\n%stable = freeze i7 %v\nret i7 %stable\n}}\n")
        for triple in TRIPLES:
            for module in self.roundtrip("".join(parts), triple):
                for family in FAMILIES:
                    for category in ("same", "undef", "poison", "both"):
                        fn = self.function(module, family + "_" + category)
                        insts = self.instructions(fn)
                        self.assertEqual([i["operation"]["op"] for i in insts], ["integer_min_max", "freeze"])
                        op = insts[0]["operation"]
                        if category == "same":
                            self.assertEqual(op["lhs"], op["rhs"])
                            self.assertEqual(op["lhs"], {"kind": "value", "id": fn["params"][0]["id"]})
                        else:
                            self.assertEqual(op["lhs"]["kind"], "undef" if category == "both" else category)
                            self.assertEqual(self.shape(module, op["lhs"]["ty"]), {"kind": "int", "bits": 7})
                            self.assertEqual(op["rhs"]["kind"], "undef" if category == "both" else "int")
                        self.assertEqual(insts[1]["operation"]["value"], {"kind": "value", "id": insts[0]["result"]["id"]})

    def test_full_control_flow_effects_noundef_load_metadata_and_cold_dependencies_remain_around_minmax(self):
        body = declaration("smin", 9) + declaration("umax", 9) + """@slot = global i9 1, align 2
declare i9 @provider(i9)
define i9 @entry(i9 %a, i9 %b, i1 %pick) {
entry:
  %before = load volatile i9, ptr @slot, align 2, !noundef !0
  %bounded = add nsw nuw i9 %a, %b
  %left = call i9 @llvm.smin.i9(i9 %bounded, i9 %b)
  br i1 %pick, label %taken, label %other, !prof !1
taken:
  %right = call i9 @llvm.umax.i9(i9 %before, i9 %left)
  br label %join
other:
  br label %join
join:
  %value = phi i9 [%right, %taken], [%left, %other]
  %stable = freeze i9 %value
  store volatile i9 %stable, ptr @slot, align 2
  %observed = call i9 @provider(i9 %stable)
  ret i9 %observed
}
define void @unused_cold(i9 %a, i9 %b) cold {
  %v = call i9 @llvm.smin.i9(i9 %a, i9 %b)
  store volatile i9 %v, ptr @slot, align 1
  ret void
}
!0 = !{}
!1 = !{!"branch_weights", i32 7, i32 3}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                fn = self.function(module, "entry")
                self.assertEqual([op["op"] for op in self.operations(fn)],
                                 ["load", "binary", "integer_min_max", "integer_min_max", "phi", "freeze", "store", "call"])
                self.assertEqual(fn["blocks"][0]["terminator"]["op"], "branch")
                self.assertTrue(self.operations(fn)[0]["volatile"])
                self.assertEqual(self.operations(fn)[1]["flags"], ["nsw", "nuw"])
                self.assertNotIn("flags", self.operations(fn)[2])
                self.assertTrue(self.operations(fn)[6]["volatile"])
                self.assertEqual(self.operations(fn)[7]["callee"]["name"], "provider")
                self.assertTrue(any("erased empty !noundef load promise" in note for note in module["provenance"]["refinements"]))

    def test_original_c_and_fastcc_callers_keep_extension_abi_while_intrinsic_calls_remain_exact_c(self):
        parts = []
        for width in (1, 7, 33, 64):
            parts.append(declaration("smax", width))
            for cc in ("", "fastcc"):
                suffix = "c" if not cc else "fast"
                parts.append(f"define {cc} signext i{width} @caller_{width}_{suffix}(i{width} zeroext %a, i{width} signext %b) {{\n%v = call i{width} @{name('smax', width)}(i{width} %a, i{width} %b)\nret i{width} %v\n}}\n")
        for triple in TRIPLES:
            for module in self.roundtrip("".join(parts), triple):
                for width in (1, 7, 33, 64):
                    for cc in ("c", "fast"):
                        sig = self.function(module, f"caller_{width}_{cc}")["signature"]
                        self.assertEqual(sig["abi"], "c" if cc == "c" else "fastcc")
                        self.assertEqual((sig["result_attributes"], sig["param_attributes"]), (["signext"], [["zeroext"], ["signext"]]))
                        self.assert_declaration(module, "smax", width)

    def test_ordinary_minmax_named_alias_indirect_calls_and_provider_effects_are_not_recognized_as_intrinsics(self):
        body = declaration("umin", 64) + """@ordinary_alias = alias i64(i64,i64), ptr @ordinary_min
declare void @observe(i64)
define i64 @ordinary_min(i64 %a, i64 %b) {
  call void @observe(i64 %a)
  ret i64 %b
}
define i64 @entry(ptr %function, i64 %a, i64 %b) {
  %v = call i64 %function(i64 %a, i64 %b)
  %w = call i64 @ordinary_alias(i64 %b, i64 %v)
  %x = call i64 @llvm.umin.i64(i64 %w, i64 %a)
  ret i64 %x
}
"""
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                ops = self.operations(self.function(module, "entry"))
                self.assertEqual([op["op"] for op in ops], ["call", "call", "integer_min_max"])
                self.assertEqual(ops[0]["callee"]["kind"], "value")
                self.assertEqual(ops[1]["callee"]["name"], "ordinary_alias")
                self.assertEqual(self.operations(self.function(module, "ordinary_min"))[0]["callee"]["name"], "observe")

    def test_unused_malformed_intrinsic_signatures_are_rejected_by_whole_import_not_ignored(self):
        for triple in TRIPLES:
            for family in FAMILIES:
                intrinsic = name(family, 8)
                for body in (f"declare i8 @{intrinsic}(i8)\n", f"declare i8 @{intrinsic}(i8, i8, i8)\n",
                             f"declare i8 @{intrinsic}(i7, i7)\n", f"declare void @{intrinsic}(i8, i8)\n",
                             f"declare i8 @{intrinsic}(i8, i8, ...)\n"):
                    with self.subTest(triple=triple, body=body):
                        self.reject(body, triple)

    def test_called_malformed_intrinsics_and_intrinsic_bodies_fail_upstream_verification_before_import(self):
        for triple in TRIPLES:
            for family in FAMILIES:
                intrinsic = name(family, 8)
                self.reject(f"declare i8 @{intrinsic}(i8)\ndefine i8 @entry(i8 %a) {{ %v = call i8 @{intrinsic}(i8 %a)\nret i8 %v }}\n",
                            triple, stage="llvm-verify", binary=False)
                self.reject(f"define i8 @{intrinsic}(i8 %a, i8 %b) {{ ret i8 %a }}\n",
                            triple, stage="llvm-verify", binary=False)

    def test_llvm_valid_wide_fixed_scalable_vector_and_neighbor_intrinsics_still_reject_whole_units(self):
        bodies = [declaration("smin", 65), declaration("umax", 128),
                  "declare <2 x i8> @llvm.umin.v2i8(<2 x i8>, <2 x i8>)\n",
                  "declare <vscale x 2 x i8> @llvm.smax.nxv2i8(<vscale x 2 x i8>, <vscale x 2 x i8>)\n",
                  "declare i8 @llvm.abs.i8(i8, i1 immarg)\n", "declare i8 @llvm.sadd.sat.i8(i8, i8)\n",
                  "declare i8 @llvm.min_like.i8(i8, i8)\n"]
        for triple in TRIPLES:
            for body in bodies:
                self.reject(body, triple)

    def test_owned_declarations_keep_external_default_as0_c_profile_and_no_hidden_unused_abi(self):
        for triple in TRIPLES:
            for qualifier in ("hidden", "protected", "extern_weak", "fastcc"):
                self.reject(f"declare {qualifier} i8 @llvm.smin.i8(i8, i8)\n", triple)
            self.reject("declare i8 @llvm.smin.i8(i8, i8) addrspace(1)\n", triple)

    def test_surviving_callsite_extension_attributes_wrong_convention_and_no_wrap_string_contracts_reject(self):
        for triple in TRIPLES:
            for call in ("call signext i8 @llvm.smin.i8(i8 %a, i8 %b)",
                         "call i8 @llvm.smin.i8(i8 signext %a, i8 %b)",
                         "call i8 @llvm.smin.i8(i8 %a, i8 zeroext %b)",
                         "call fastcc i8 @llvm.smin.i8(i8 %a, i8 %b)",
                         'call i8 @llvm.smin.i8(i8 %a, i8 %b) "no-wrap"="nsw,nuw"'):
                self.reject(declaration("smin", 8) + f"define i8 @entry(i8 %a, i8 %b) {{ %v = {call}\nret i8 %v }}\n",
                            triple, symbol="entry")
            self.reject(declaration("smin", 8) + "define i8 @entry(i8 %a, i8 %b) { %v = call nsw i8 @llvm.smin.i8(i8 %a, i8 %b)\nret i8 %v }\n",
                        triple, stage="parse", binary=False)

    def test_callsite_bundles_musttail_security_unwind_and_unknown_metadata_are_not_erased(self):
        for triple in TRIPLES:
            for prefix, suffix in (("call", ' ["deopt"()]'), ("musttail call", ""),
                                   ("call", " sanitize_memory"), ("call", " uwtable"),
                                   ("call", ' "minmax-unknown"="1"'), ("call", ", !minmax.extra !0")):
                self.reject(declaration("smax", 8) + f"define i8 @entry(i8 %a, i8 %b) {{ %v = {prefix} i8 @llvm.smax.i8(i8 %a, i8 %b){suffix}\nret i8 %v }}\n!0 = !{{i32 1}}\n",
                            triple, symbol="entry")

    def test_intrinsic_address_relocations_aliases_and_indirect_escape_fail_upstream_verification(self):
        bodies = ["@escape = global ptr @llvm.umin.i8\n",
                  "@escape = alias i8(i8,i8), ptr @llvm.umin.i8\n",
                  "define ptr @escape() { ret ptr @llvm.umin.i8 }\n",
                  "define ptr @escape() { ret ptr getelementptr (i8, ptr @llvm.umin.i8, i64 4) }\n",
                  "define i8 @entry(i1 %pick) { %f = select i1 %pick, ptr @llvm.umin.i8, ptr null\n%v = call i8 %f(i8 1, i8 2)\nret i8 %v }\n"]
        for triple in TRIPLES:
            for body in bodies:
                self.reject(declaration("umin", 8) + body, triple, stage="llvm-verify", binary=False)

    def test_intrinsic_invoke_and_callbr_reject_at_actual_upstream_terminator_boundary(self):
        invoke = declaration("smax", 8) + """declare i32 @personality(i32,i32,i64,ptr,ptr)
define i8 @entry(i8 %a, i8 %b) personality ptr @personality {
entry:
  %v = invoke i8 @llvm.smax.i8(i8 %a, i8 %b) to label %normal unwind label %unwind
normal:
  ret i8 %v
unwind:
  %e = landingpad {ptr,i32} cleanup
  resume {ptr,i32} %e
}
"""
        callbr = declaration("smax", 8) + """define i8 @entry(i8 %a, i8 %b) {
entry:
  %v = callbr i8 @llvm.smax.i8(i8 %a, i8 %b) to label %normal [label %other]
normal:
  ret i8 %v
other:
  ret i8 0
}
"""
        for triple in TRIPLES:
            for body in (invoke, callbr):
                self.reject(body, triple, stage="llvm-verify", binary=False)

    def test_upstream_remangling_and_declaration_attribute_reset_preserve_original_sha_not_raw_token_contracts(self):
        # Actual postparse C API is the boundary. Never infer raw-token attribute
        # preservation or rejection after intrinsic AutoUpgrade resets them.
        bodies = ["declare i8 @llvm.smin.i08(i8, i8)\n",
                  "declare i8 @llvm.smin.unknown(i8, i8)\n",
                  "declare i8 @llvm.smin.i8(i8 signext, i8 zeroext)\n",
                  "declare signext i8 @llvm.smin.i8(i8, i8)\n",
                  "declare i8 @llvm.smin.i8(i8, i8) \"minmax-decl-reset\"=\"1\"\n"]
        for triple in TRIPLES:
            for body in bodies:
                for module in self.roundtrip(body, triple):
                    self.assert_declaration(module, "smin", 8)
                    self.assertEqual([f["name"] for f in module["functions"]], ["llvm.smin.i8"])
                    self.assertTrue(any("validated after pinned LLVM parsing and intrinsic normalization" in note
                                        for note in module["provenance"]["refinements"]))

    def test_scoped_generated_nocreateundeforpoison_does_not_admit_ordinary_or_string_or_wrong_site_attributes(self):
        body = declaration("umax", 8) + "define i8 @entry(i8 %a, i8 %b) { %v = call i8 @llvm.umax.i8(i8 %a, i8 %b) nocreateundeforpoison\nret i8 %v }\n"
        for triple in TRIPLES:
            for module in self.roundtrip(body, triple):
                notes = module["provenance"]["refinements"]
                self.assertTrue(any("llvm.umax.i8: function nocreateundeforpoison=0 realized" in note for note in notes))
                self.assertTrue(any("entry: callsite nocreateundeforpoison=0 realized" in note for note in notes))
            self.reject("declare i8 @ordinary(i8) nocreateundeforpoison\n", triple, symbol="ordinary")
            self.reject(declaration("umax", 8) + 'define i8 @entry(i8 %a, i8 %b) { %v = call i8 @llvm.umax.i8(i8 %a, i8 %b) "nocreateundeforpoison"\nret i8 %v }\n', triple)
            self.reject(declaration("umax", 8) + "define i8 @entry(i8 %a, i8 %b) { %v = call i8 @llvm.umax.i8(i8 nocreateundeforpoison %a, i8 %b)\nret i8 %v }\n",
                        triple, stage="parse", binary=False)

    def test_unused_float_tls_unknown_named_metadata_and_unsupported_cold_abi_still_reject_full_minmax_units(self):
        bodies = [("declare double @unused_float(double)\n", "unused_float"),
                  ("@unused_tls = thread_local global i64 37\n", "unused_tls"),
                  ("declare i8 @unused_cold(i8 inreg)\n", "unused_cold"),
                  ("!minmax.publication = !{!0}\n!0 = !{i32 1}\n", None)]
        for triple in TRIPLES:
            for body, symbol in bodies:
                self.reject(declaration("smin", 8) + body, triple, symbol=symbol)

    @staticmethod
    def clang_source():
        return """long retained_global = 37;
long probe_smin(long a,long b) { return a < b ? a : b; }
long probe_smax(long a,long b) { return a > b ? a : b; }
unsigned long probe_umin(unsigned long a,unsigned long b) { return a < b ? a : b; }
unsigned long probe_umax(unsigned long a,unsigned long b) { return a > b ? a : b; }
long unused_cold(long value) { return value ^ 37; }
"""

    @staticmethod
    def rust_source():
        return """#![no_std]
#[no_mangle] pub static RETAINED_GLOBAL:u64 = 37;
#[no_mangle] pub extern "C" fn probe_smin(a:i64,b:i64)->i64 { a.min(b) }
#[no_mangle] pub extern "C" fn probe_smax(a:i64,b:i64)->i64 { a.max(b) }
#[no_mangle] pub extern "C" fn probe_umin(a:u64,b:u64)->u64 { a.min(b) }
#[no_mangle] pub extern "C" fn probe_umax(a:u64,b:u64)->u64 { a.max(b) }
#[no_mangle] pub extern "C" fn unused_cold(value:u64)->u64 { value ^ 37 }
"""

    def producer(self, command, source, output):
        self.assertFalse(any(path.exists() for path in (
            output, output.with_suffix(output.suffix + ".producer.stdout"),
            output.with_suffix(output.suffix + ".producer.stderr"))),
            "producer output and stream paths must be unused: " + str(output))
        original = source.read_bytes()
        result = subprocess.run(command, cwd=baseline.ROOT, capture_output=True, timeout=30)
        stdout, stderr = output.with_suffix(output.suffix + ".producer.stdout"), output.with_suffix(output.suffix + ".producer.stderr")
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        self.records.append({"producer": {"command": [str(v) for v in command], "cwd": str(baseline.ROOT),
            "exit_code": result.returncode, "source": noundef.artifact(source),
            "stdout": noundef.artifact(stdout), "stderr": noundef.artifact(stderr),
            "output": noundef.artifact(output) if output.exists() else None}})
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return output

    def clang_compile(self, clang, source, triple, suffix, cpp):
        output = self.directory / f"{source.name}-{triple}.{suffix}"
        flags = ["-x", "c++", "-std=c++17", "-fno-exceptions", "-fno-rtti"] if cpp else ["-x", "c"]
        target = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
        return self.producer([clang, "--target=" + triple, *target, *flags, *memory.LlvmMemoryImportTests.clang_flags(),
                              "-S" if suffix == "ll" else "-c", str(source), "-o", str(output)], source, output)

    def rust_compile(self, rustc, source, target, suffix):
        output = self.directory / f"{source.name}-{target}.{suffix}"
        return self.producer([str(rustc), str(source), "--crate-type=lib", "--edition=2021", "--crate-name=minmax_fixture",
            "--target=" + target, "--emit=" + ("llvm-ir" if suffix == "ll" else "llvm-bc"), "-Copt-level=1",
            "-Cpanic=abort", "-Coverflow-checks=no", "-Ccodegen-units=1", "-Crelocation-model=static", "-o", str(output)], source, output)

    def assert_producer(self, module, global_name):
        self.assertEqual({f["name"] for f in module["functions"] if f["entry"] is not None},
                         {"probe_" + f for f in FAMILIES} | {"unused_cold"})
        self.assertEqual({f["intrinsic"] for f in module["functions"] if f["intrinsic"]}, {name(f, 64) for f in FAMILIES})
        self.assertEqual([g["name"] for g in module["globals"]], [global_name])
        for family in FAMILIES:
            self.assert_declaration(module, family, 64)
            op, = self.operations(self.function(module, "probe_" + family))
            self.assertEqual((op["op"], op["kind"]), ("integer_min_max", family))
        self.assertEqual(self.operations(self.function(module, "unused_cold"))[0]["op"], "binary")

    def test_actual_untouched_clang22_c_cpp_units_keep_all_four_minmax_families_and_complete_unused_inventory_all_three_isas_ll_bc(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        for cpp in (False, True):
            source = self.directory / ("whole-minmax.cpp" if cpp else "whole-minmax.c")
            code = self.clang_source()
            source.write_text('extern "C" {\n' + code + '}\n' if cpp else code)
            original = source.read_bytes()
            for triple in TRIPLES:
                modules = []
                for suffix in ("ll", "bc"):
                    path = self.clang_compile(clang, source, triple, suffix, cpp)
                    module = self.accept_path(path, triple, "Clang C++" if cpp else "Clang C", version)
                    self.assert_producer(module, "retained_global")
                    modules.append(module)
                self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(source.read_bytes(), original)

    def test_actual_untouched_rust1971_units_keep_all_four_families_real_triples_and_lp64d_all_three_isas_ll_bc(self):
        rustc, version = self.rust_compiler()
        source = self.directory / "whole-minmax.rs"
        source.write_text(self.rust_source())
        original = source.read_bytes()
        for target, triple in ((TRIPLES[0], TRIPLES[0]), (TRIPLES[1], TRIPLES[1]),
                               ("riscv64gc-unknown-linux-gnu", TRIPLES[2])):
            modules = []
            for suffix in ("ll", "bc"):
                path = self.rust_compile(rustc, source, target, suffix)
                module = self.accept_path(path, triple, "Rust", version)
                self.assert_producer(module, "RETAINED_GLOBAL")
                self.assertEqual(module["target"].get("abi"), "lp64d" if triple.startswith("riscv64") else None)
                modules.append(module)
            self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        self.assertEqual(source.read_bytes(), original)

    def test_actual_whole_c_cpp_rust_producers_reject_retained_unused_float_without_partial_minmax_import(self):
        clang, clang_version = baseline.LlvmImportTests.clang22_frontend(self)
        rustc, rust_version = self.rust_compiler()
        for language in ("c", "cpp", "rust"):
            source = self.directory / ("whole-minmax-negative." + {"c": "c", "cpp": "cpp", "rust": "rs"}[language])
            if language == "rust":
                code = self.rust_source() + '#[no_mangle] pub extern "C" fn unsupported_float(value:u64)->f64 { value as f64 }\n'
            else:
                code = self.clang_source() + "double unsupported_float(unsigned long value) { return (double)value; }\n"
            source.write_text('extern "C" {\n' + code + '}\n' if language == "cpp" else code)
            original = source.read_bytes()
            for triple in TRIPLES:
                for suffix in ("ll", "bc"):
                    target = "riscv64gc-unknown-linux-gnu" if language == "rust" and triple.startswith("riscv64") else triple
                    path = self.rust_compile(rustc, source, target, suffix) if language == "rust" else self.clang_compile(clang, source, triple, suffix, language == "cpp")
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(path, library_path=self.library, frontend=language,
                            frontend_version=rust_version if language == "rust" else clang_version)
                    error = raised.exception
                    self.records.append({"input": noundef.artifact(path), "error": {"stage": error.stage,
                        "symbol": error.symbol, "message": str(error)}})
                    self.assertEqual((error.stage, error.symbol), ("import", "unsupported_float"))
                    self.assertIn("unsupported LLVM type kind", str(error))
            self.assertEqual(source.read_bytes(), original)

    def test_failed_whole_unit_cli_import_retains_existing_output_and_emits_no_partial_success_artifact(self):
        body = declaration("umax", 8) + "declare double @unused_float(double)\n"
        output = self.directory / "existing-output.json"
        sentinel = b"existing reviewed artifact\x00must remain byte-exact\n"
        for triple in TRIPLES:
            text = self.write(body, triple)
            for path in (text, self.bitcode(text)):
                output.write_bytes(sentinel)
                command = [sys.executable, "-B", str(Path(importer.__file__)), str(path), "--llvm-library", str(self.library), "-o", str(output)]
                result = subprocess.run(command, capture_output=True, timeout=30)
                stdout, stderr = path.with_suffix(path.suffix + ".cli.stdout"), path.with_suffix(path.suffix + ".cli.stderr")
                stdout.write_bytes(result.stdout); stderr.write_bytes(result.stderr)
                self.records.append({"input": noundef.artifact(path), "cli": {"command": command,
                    "exit_code": result.returncode, "stdout": noundef.artifact(stdout), "stderr": noundef.artifact(stderr),
                    "preserved_output": noundef.artifact(output)}})
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(output.read_bytes(), sentinel)
                self.assertEqual(json.loads(result.stderr)["error"]["stage"], "import")
                self.assertEqual(json.loads(result.stderr)["error"]["symbol"], "unused_float")


if __name__ == "__main__":
    unittest.main()
