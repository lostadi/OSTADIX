"""Whole-unit fixed-vector source preservation controls.

Requires explicitly selected LLVM22 bytes; no skips, frontend regeneration or
unit filtering. Source controls exercise the candidate Python worker and an
independent C API reader. They do not execute a rebuilt compiler/native code,
prove providers, or qualify original Lua runtime behavior.
"""
from __future__ import annotations

import copy
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ORIGINALS = (
    ("00-lgc.c.ll", "62dfee8f9b763308b57c9aaa6aff02bcb9c87f2baf8143f0427680fee7f12aa0"),
    ("01-ltable.c.ll", "75f4f1d65f113c202bc8f0afaa8af6a969b85d02b781d7ea573c67ebed3ed4e1"),
    ("02-lstate.c.ll", "a9fef74802f44c85f2386f94302d6ba27636d448b4642d758868b0ac3abb5a32"),
    ("03-ldebug.c.ll", "06a2515c74224d7bfce7b5f4dc4ea8d29855b8bc666370dff58486591b760b69"),
)


def identity(path):
    path = Path(path)
    raw = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(raw),
            "mode": path.stat().st_mode & 0o7777, "sha256": hashlib.sha256(raw).hexdigest()}


def checked_source(path, expected, namespace=None):
    path = Path(path)
    before = identity(path)
    if before != expected:
        raise AssertionError("checked source selected Pin differs")
    with path.open("rb") as stream:
        raw = stream.read()
        consumed = {"path": str(path.resolve()), "bytes": len(raw),
                    "mode": os.fstat(stream.fileno()).st_mode & 0o7777,
                    "sha256": hashlib.sha256(raw).hexdigest()}
    if consumed != expected:
        raise AssertionError("checked source consumed buffer differs from selected Pin")
    namespace = {} if namespace is None else namespace
    namespace.update(__name__="fixed_vector_checked_source", __file__=str(path))
    exec(compile(raw, str(path), "exec"), namespace)
    if identity(path) != expected:
        raise AssertionError("checked source changed during execution")
    return namespace


def checked_inventory_read(reader, path, raw, expected, record):
    """Observe the exact public CAPI buffer boundary, including a reached swap.

    Check in finally so Reader keeps its ordinary module/context cleanup even
    when changed bytes fail parsing or inventory. No changed input can qualify.
    """
    create = reader.CreateMemoryBufferWithMemoryRangeCopy
    consumed = record["reader_buffers"] = []

    def observed_buffer(data, extent, name):
        consumed.append({"bytes": len(data), "extent": extent,
                         "sha256": hashlib.sha256(data).hexdigest(), "exact_selected_bytes": data == raw})
        return create(data, extent, name)

    reader.CreateMemoryBufferWithMemoryRangeCopy = observed_buffer
    try:
        return reader.read(path)
    finally:
        reader.CreateMemoryBufferWithMemoryRangeCopy = create
        selected = {"bytes": expected["bytes"], "extent": len(raw),
                    "sha256": expected["sha256"], "exact_selected_bytes": True}
        if consumed != [selected]:
            raise AssertionError("Reader consumed buffer differs from selected LLVM input")


def fixture():
    return b'''target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-p:64:64-i64:64-i128:128-v24:32-n8:16:32:64-S128"
@packed_mask = global <4 x i1> <i1 true, i1 false, i1 true, i1 false>, align 1
@odd_width = global <3 x i8> <i8 1, i8 2, i8 3>, align 4
@partial_global = global <4 x i32> <i32 poison, i32 7, i32 0, i32 9>, align 16
declare i64 @original_unused_provider(i64)
declare i32 @llvm.vector.reduce.add.v4i32(<4 x i32>)
define i64 @original_cold() { ret i64 1122334455 }
define i32 @exercise(ptr %p, i32 %x, i64 %index, i1 %condition) {
entry:
  %a = load <4 x i8>, ptr %p, align 1
  %m = icmp ugt <4 x i8> %a, splat (i8 1)
  %z = zext <4 x i1> %m to <4 x i32>
  %s = sext <4 x i8> %a to <4 x i32>
  %b = add nuw <4 x i32> %z, %s
  %n = trunc <4 x i32> %b to <4 x i8>
  %f = freeze <4 x i8> %n
  store <4 x i8> %f, ptr %p, align 1
  %partial = insertelement <4 x i32> <i32 poison, i32 0, i32 7, i32 9>, i32 %x, i64 0
  %sel = select <4 x i1> %m, <4 x i32> %b, <4 x i32> %partial
  %all = select i1 %condition, <4 x i32> %sel, <4 x i32> zeroinitializer
  %e = extractelement <4 x i32> %all, i64 %index
  %r = call i32 @llvm.vector.reduce.add.v4i32(<4 x i32> %all)
  store <4 x i32> %all, ptr %p, align 1
  %out = add i32 %r, %e
  ret i32 %out
}
'''


class FixedVectorSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = Path(os.environ["OCORE_TEST_LLVM_LIBRARY"])
        cls.library_sha = os.environ["OCORE_TEST_LLVM_SHA256"]
        if identity(cls.library)["sha256"] != cls.library_sha:
            raise AssertionError("explicit LLVM library pin differs")
        cls.original_root = Path(os.environ.get("OCORE_VECTOR_ORIGINAL_INPUTS", "/tmp/ostadix-Lua-x86-vector-original-inputs-20261025-r1"))
        cls.source_paths = [ROOT / path for path in (
            "scripts/ocore_llvm_bitcode.py", "scripts/ocore_llvm_import.py",
            "tests/ocore_llvm_source_inventory.py", "tests/test_ocore_llvm_fixed_vector.py",
            "crates/ostadix-api/src/ocore/native_ir.rs", "crates/ostadix-api/src/ocore/native_verify.rs")]
        cls.source_paths += [cls.library] + [cls.original_root / name for name, _ in ORIGINALS]
        cls.before = [identity(path) for path in cls.source_paths]
        for name, digest in ORIGINALS:
            if identity(cls.original_root / name)["sha256"] != digest:
                raise AssertionError("unchanged original Lua LLVM pin differs: " + name)
        cls.directory = Path(tempfile.mkdtemp(prefix="fixed-vector-source-", dir=os.environ.get("OCORE_VECTOR_RETAIN")))
        cls.records = []
        # The exact checked bitcode buffer supplies the importer's dependency;
        # no importlib/PYC or unpinned dynamic helper execution is used here.
        importer_ns = checked_source(cls.source_paths[0], cls.before[0])
        cls.importer = checked_source(cls.source_paths[1], cls.before[1], namespace=importer_ns)
        cls.inventory = checked_source(cls.source_paths[2], cls.before[2])
        cls.reader = cls.inventory["Reader"](cls.library, cls.library_sha)

    @classmethod
    def tearDownClass(cls):
        after = [identity(path) for path in cls.source_paths]
        report = {"schema": "ocore-fixed-vector-source-controls-v1", "before": cls.before, "after": after,
                  "stable": cls.before == after, "records": cls.records, "compiler_execution": False,
                  "native_execution": False, "runtime_qualified": False, "provider_qualified": False,
                  "all_isa_qualified": False,
                  "authored_controls": unittest.defaultTestLoader.getTestCaseNames(cls)}
        report["authored_control_count"] = len(report["authored_controls"])
        (cls.directory / "receipt.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        if cls.before != after:
            raise AssertionError("source/input/library pins changed during source controls")

    def imported(self, label, raw):
        source = self.directory / (label + ".ll")
        source.write_bytes(raw)
        selected = identity(source)
        if selected["bytes"] != len(raw) or selected["sha256"] != hashlib.sha256(raw).hexdigest():
            raise AssertionError("written LLVM input differs from selected argument bytes")
        record = {"source": selected, "import": "attempted", "inventory": "pending", "custody": "pending"}
        self.records.append(record)
        try:
            module = self.importer["import_module"](source, self.library, expected_sha256=self.library_sha)
            record["import"] = "complete"
            record["mir_input_sha256"] = module["provenance"]["input_sha256"]
            self.assertEqual(record["mir_input_sha256"], selected["sha256"], "MIR provenance differs from selected LLVM input")
            self.assertEqual(identity(source), selected, "LLVM input changed after importer")
            original = checked_inventory_read(self.reader, source, raw, selected, record)
            expected_source = {key: selected[key] for key in ("path", "bytes", "sha256")}
            self.assertEqual(original["source"], expected_source, "Reader source differs from selected LLVM input")
            proof = self.inventory["check_inventory"](original, module)
            self.assertEqual(proof["source"], expected_source, "proof source differs from selected LLVM input")
            record["inventory"] = "complete"
            for suffix, value in (("native", module), ("source-inventory", original), ("preservation", proof)):
                path = self.directory / (label + "." + suffix + ".json")
                path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
                record[suffix] = identity(path)
            return module, original
        except BaseException as error:
            record["error"] = type(error).__name__ + ": " + str(error)
            record["custody"] = "failed"
            raise
        finally:
            record["source_after"] = identity(source)
            if record["source_after"] != selected:
                record["custody"] = "failed"
                record["custody_error"] = "LLVM input Pin changed during source controls"
            self.assertEqual(record["source_after"], selected, "LLVM input Pin changed during source controls")
            if "error" not in record and record["inventory"] == "complete":
                record["custody"] = "complete"

    def test_selected_helper_pin_and_actual_execution_buffer_swaps_are_rejected(self):
        path = self.directory / "helper-custody.py"
        raw, changed = b"SELECTED = True\n", b'raise RuntimeError("unselected helper executed")\n'
        path.write_bytes(raw)
        selected = identity(path)
        path.write_bytes(changed)
        try:
            with self.assertRaisesRegex(AssertionError, "checked source selected Pin differs"):
                checked_source(path, selected)
        finally:
            path.write_bytes(raw)
        actual_open, reached = Path.open, {"opens": 0, "buffer_hook": False}

        class ChangedRead:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): self.stream.__enter__(); return self
            def __exit__(self, *args): return self.stream.__exit__(*args)
            def fileno(self): return self.stream.fileno()
            def read(self):
                reached["buffer_hook"] = True
                return changed

        def swapped_open(current, *args, **kwargs):
            stream = actual_open(current, *args, **kwargs)
            if current == path:
                reached["opens"] += 1
                if reached["opens"] == 2:
                    return ChangedRead(stream)
            return stream

        with mock.patch.object(Path, "open", swapped_open):
            with self.assertRaisesRegex(AssertionError, "checked source consumed buffer differs from selected Pin"):
                checked_source(path, selected)
        self.assertTrue(reached["buffer_hook"], "actual execution-buffer mutation hook did not fire")
        self.assertEqual(identity(path), selected)
        self.records.append({"control": "helper-selected-pin-and-consumed-buffer", "reached": reached,
                             "selected": selected, "changed_sha256": hashlib.sha256(changed).hexdigest()})

    def test_reader_changed_consumed_buffer_restored_on_disk_is_rejected(self):
        raw = fixture()
        changed = raw.replace(b"1122334455", b"1122334456")
        self.assertNotEqual(raw, changed)
        read, artifact = self.reader.read, self.inventory["artifact"]
        reached = {"artifact_swap": False}

        def swapped_read(path):
            def swapped_artifact(current):
                selected = artifact(current)
                if Path(current) == path:
                    Path(current).write_bytes(changed)
                    reached["artifact_swap"] = True
                return selected
            try:
                with mock.patch.dict(self.inventory, {"artifact": swapped_artifact}):
                    return read(path)
            finally:
                path.write_bytes(raw)

        with mock.patch.object(self.reader, "read", swapped_read):
            with self.assertRaisesRegex(AssertionError, "Reader consumed buffer differs from selected LLVM input"):
                self.imported("reader-consumed-buffer-swap", raw)
        self.assertTrue(reached["artifact_swap"], "actual Reader source mutation hook did not fire")
        record = self.records[-1]
        self.assertEqual(len(record["reader_buffers"]), 1)
        self.assertEqual(record["reader_buffers"][0]["sha256"], hashlib.sha256(changed).hexdigest())
        self.assertFalse(record["reader_buffers"][0]["exact_selected_bytes"])
        self.assertEqual(record["source_after"], record["source"])
        self.assertEqual(record["custody"], "failed")
        record["mutation_reached"] = reached

    def test_input_provenance_reader_and_proof_source_mismatches_are_rejected(self):
        for fault, message in (("mir", "MIR provenance"), ("reader", "Reader source"), ("proof", "proof source")):
            reached = []
            if fault == "mir":
                owner, key = self.importer, "import_module"
            elif fault == "reader":
                owner, key = self.reader, "read"
            else:
                owner, key = self.inventory, "check_inventory"
            original_call = getattr(owner, key) if fault == "reader" else owner[key]

            def changed_result(*args, **kwargs):
                result = copy.deepcopy(original_call(*args, **kwargs))
                reached.append(fault)
                if fault == "mir": result["provenance"]["input_sha256"] = "0" * 64
                else: result["source"]["sha256"] = "0" * 64
                return result

            patch = mock.patch.object(owner, key, changed_result) if fault == "reader" else mock.patch.dict(owner, {key: changed_result})
            with self.subTest(fault=fault), patch:
                with self.assertRaisesRegex(AssertionError, message + " differs from selected LLVM input"):
                    self.imported("custody-" + fault, fixture())
            self.assertEqual(reached, [fault], "actual returned-field mutation hook did not fire")
            self.records[-1]["mutation_reached"] = reached

    @staticmethod
    def operations(module):
        function = next(function for function in module["functions"] if function["name"] == "exercise")
        return function, [instruction for block in function["blocks"] for instruction in block["instructions"]]

    def rejected(self, original, mutant):
        with self.assertRaisesRegex(self.inventory["InventoryMismatch"], "vector|intrinsic|initializer|signature"):
            self.inventory["check_inventory"](original, mutant)

    def test_four_complete_unchanged_original_lua_units(self):
        for name, digest in ORIGINALS:
            with self.subTest(unit=name):
                raw = (self.original_root / name).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
                module, original = self.imported(name, raw)
                self.assertEqual({function["name"] for function in module["functions"]}, set(original["functions"]))
                self.assertEqual({global_["name"] for global_ in module["globals"]}, set(original["globals"]))
                self.assertEqual({alias["name"] for alias in module["aliases"]}, set(original["aliases"]))
                self.assertGreater(sum(len(function["vector_sites"]) for function in original["functions"].values()), 0)
                self.assertEqual(module["target"]["triple"], original["target_triple"])

    def test_typed_constants_packed_masks_data_vectors_splat_and_declared_reduction(self):
        module, original = self.imported("mechanism", fixture())
        globals_ = {value["name"]: value for value in module["globals"]}
        self.assertEqual(globals_["packed_mask"]["initializer"]["bytes"], [5])
        self.assertEqual(globals_["odd_width"]["initializer"]["bytes"], [1, 2, 3, 0])
        self.assertEqual(globals_["partial_global"]["initializer"]["bytes"], list(bytes(4) + (7).to_bytes(4,"little") + bytes(4) + (9).to_bytes(4,"little")))
        _, instructions = self.operations(module)
        insert = next(item["operation"] for item in instructions if item["operation"]["op"] == "insert_element")
        self.assertEqual([lane["kind"] for lane in insert["vector"]["elements"]], ["poison", "int", "int", "int"])
        self.assertEqual([lane.get("bits") for lane in insert["vector"]["elements"]][1:], ["0", "7", "9"])
        reduction = next(function for function in module["functions"] if function["name"] == "llvm.vector.reduce.add.v4i32")
        self.assertEqual(reduction["intrinsic"], reduction["name"])
        self.assertIsNone(reduction["entry"])
        self.assertEqual(len(original["functions"]["exercise"]["vector_sites"]), 14)

    def test_exact_vector_operands_predicates_casts_indices_select_and_alignment(self):
        module, original = self.imported("mutations", fixture())
        for fault in ("predicate", "cast", "index", "defined-lane", "poison-kind", "select", "alignment", "nowrap", "reduce"):
            with self.subTest(fault=fault):
                mutant = copy.deepcopy(module)
                _, instructions = self.operations(mutant)
                ops = [item["operation"] for item in instructions]
                if fault == "predicate": next(op for op in ops if op["op"] == "i_cmp")["predicate"] = "ult"
                elif fault == "cast": next(op for op in ops if op.get("kind") == "s_ext")["kind"] = "z_ext"
                elif fault == "index": next(op for op in ops if op["op"] == "insert_element")["index"]["bits"] = "1"
                elif fault == "defined-lane": next(op for op in ops if op["op"] == "insert_element")["vector"]["elements"][2]["bits"] = "8"
                elif fault == "poison-kind": next(op for op in ops if op["op"] == "insert_element")["vector"]["elements"][0]["kind"] = "undef"
                elif fault == "select":
                    op = next(op for op in ops if op["op"] == "select")
                    op["on_true"], op["on_false"] = op["on_false"], op["on_true"]
                elif fault == "alignment": next(op for op in ops if op["op"] == "load")["alignment"] = 2
                elif fault == "nowrap": next(op for op in ops if op["op"] == "binary")["flags"] = []
                else: next(op for op in ops if op["op"] == "vector_reduce_add")["value"] = next(op for op in ops if op["op"] == "select")["on_false"]
                self.rejected(original, mutant)

    def test_unused_extra_vector_and_reduction_cannot_evade_inventory(self):
        module, original = self.imported("extra", fixture())
        for operation_name in ("i_cmp", "vector_reduce_add"):
            mutant = copy.deepcopy(module)
            function, instructions = self.operations(mutant)
            extra = copy.deepcopy(next(item for item in instructions if item["operation"]["op"] == operation_name))
            extra["result"]["id"] = max(item["result"]["id"] for item in instructions if item["result"]) + 1
            function["blocks"][0]["instructions"].append(extra)
            self.rejected(original, mutant)

    def test_packed_initializer_and_full_original_declaration_membership(self):
        module, original = self.imported("static", fixture())
        for fault in ("packed-bit", "defined-initializer-lane", "cold-function", "intrinsic-declaration", "global"):
            mutant = copy.deepcopy(module)
            if fault == "packed-bit": next(g for g in mutant["globals"] if g["name"] == "packed_mask")["initializer"]["bytes"][0] ^= 2
            elif fault == "defined-initializer-lane": next(g for g in mutant["globals"] if g["name"] == "partial_global")["initializer"]["bytes"][4] = 0
            elif fault in ("cold-function", "intrinsic-declaration"):
                target = "original_cold" if fault == "cold-function" else "llvm.vector.reduce.add.v4i32"
                mutant["functions"] = [f for f in mutant["functions"] if f["name"] != target]
            else: mutant["globals"].pop()
            with self.subTest(fault=fault), self.assertRaises(self.inventory["InventoryMismatch"]):
                self.inventory["check_inventory"](original, mutant)

    def test_original_vector_bit_layout_not_scalar_allocation_stride(self):
        raw = b'''target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-p:64:64-i64:128-v24:32-v128:256-n8:16:32:64-S128"
@cross_byte_mask = global <10 x i1> <i1 true, i1 false, i1 true, i1 true, i1 false, i1 false, i1 true, i1 false, i1 true, i1 true>, align 2
@odd = global <3 x i8> <i8 11, i8 22, i8 33>, align 4
@pair = global <2 x i64> <i64 1, i64 2>, align 32
@adjacent = global { <3 x i8>, i8 } { <3 x i8> <i8 1, i8 2, i8 3>, i8 99 }, align 4
define void @roundtrip(ptr %source, ptr %destination) {
  %value = load <2 x i64>, ptr %source, align 1
  store <2 x i64> %value, ptr %destination, align 1
  ret void
}
'''
        module, original = self.imported("distinct-store-allocation", raw)
        globals_ = {value["name"]: value for value in module["globals"]}
        self.assertEqual(globals_["cross_byte_mask"]["initializer"]["bytes"], [77, 3])
        self.assertEqual(globals_["odd"]["initializer"]["bytes"], [11, 22, 33, 0])
        self.assertEqual(globals_["pair"]["initializer"]["bytes"], list((1).to_bytes(8,"little") + (2).to_bytes(8,"little") + bytes(16)))
        self.assertEqual(globals_["adjacent"]["initializer"]["bytes"], [1, 2, 3, 0, 99, 0, 0, 0])
        self.assertEqual(len(original["functions"]["roundtrip"]["vector_sites"]), 2)

    def test_unsupported_vector_neighbors_fail_without_partial_module(self):
        neighbors = {
            "scalable": b'define void @bad(ptr %p) { %x = load <vscale x 4 x i32>, ptr %p\n ret void }',
            "float": b'define void @bad(ptr %p) { %x = load <4 x float>, ptr %p\n ret void }',
            "pointer": b'define void @bad(ptr %p) { %x = load <4 x ptr>, ptr %p\n ret void }',
            "width3": b'define void @bad(ptr %p) { %x = load <4 x i3>, ptr %p\n ret void }',
            "div": b'define void @bad(ptr %p) { %x = load <4 x i32>, ptr %p\n %y = udiv <4 x i32> %x, splat(i32 2)\n ret void }',
            "volatile": b'define void @bad(ptr %p) { %x = load volatile <4 x i32>, ptr %p\n ret void }',
        }
        for label, body in neighbors.items():
            path = self.directory / ("unsupported-" + label + ".ll")
            path.write_bytes(b'target triple = "x86_64-unknown-linux-gnu"\ntarget datalayout = "e-p:64:64-i64:64-i128:128-n8:16:32:64-S128"\n' + body + b'\n')
            selected, raw = identity(path), path.read_bytes()
            self.assertEqual(len(raw), selected["bytes"], "unsupported-neighbor buffer extent differs from selected Pin")
            self.assertEqual(hashlib.sha256(raw).hexdigest(), selected["sha256"],
                             "unsupported-neighbor consumed buffer differs from selected Pin")
            # Independent LLVM parse+verification accepts each complete neighbor
            # before its intended importer limitation may satisfy the refusal.
            context, module, error = self.reader.ContextCreate(), c.c_void_p(), c.c_void_p()
            try:
                buffer = self.reader.CreateMemoryBufferWithMemoryRangeCopy(raw, len(raw), b"unsupported-neighbor")
                self.assertEqual(self.reader.ParseIRInContext(context, buffer, c.byref(module), c.byref(error)), 0,
                                 "unsupported-neighbor control is malformed LLVM: " + label)
                self.assertEqual(self.reader.VerifyModule(module, 2, c.byref(error)), 0,
                                 "unsupported-neighbor control fails LLVM verification: " + label)
            finally:
                if error: self.reader.DisposeMessage(error)
                if module: self.reader.DisposeModule(module)
                self.reader.ContextDispose(context)
            reason = ({"scalable": "unsupported LLVM type kind 17 (half, bfloat, PPC128, scalable vector, token and target types require another lowering)",
                       "div": "vector div/rem requires nontrapping poison-lane realization",
                       "volatile": "volatile/atomic vector memory requires an explicit supported effect realization"}
                      .get(label, "fixed vectors require positive length and supported integer lanes i1/i8/i16/i32/i64"))
            with self.subTest(shape=label), self.assertRaises(self.importer["ImportFailure"]) as rejected:
                self.importer["import_module"](path, self.library, expected_sha256=self.library_sha)
            self.assertEqual(rejected.exception.stage, "import", "parse/LLVM-verifier refusal cannot count as unsupported lowering")
            self.assertEqual(str(rejected.exception), reason)
            self.assertEqual(identity(path), selected)
            self.records.append({"control": "unsupported-neighbor", "shape": label, "source": selected,
                                 "independent_llvm_parse_verify": "accepted", "rejection_stage": rejected.exception.stage,
                                 "rejection_reason": str(rejected.exception)})


if __name__ == "__main__":
    unittest.main()
