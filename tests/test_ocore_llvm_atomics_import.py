"""Retain whole original LLVM atomic units at the source/API boundary.

These checks do not execute atomics or establish native ordering, lock freedom,
coherent-memory mappings, thread providers, or complete runtime closure. An
absent realization profile preserves source IR and leaves native admission to
the mandatory later gate. Custom synchronization names remain source identities.
"""

import ctypes as C
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_eh_import as eh
from tests import test_ocore_llvm_noundef_metadata as noundef


TRIPLES = baseline.TRIPLES
PROFILE = "coherent-ram-v1"
ORDERINGS = {1: "unordered", 2: "monotonic", 4: "acquire", 5: "release",
             6: "acq_rel", 7: "seq_cst"}
# Pinned public llvm-c/Core.h:362-404, NOT the internal AtomicRMWInst enum.
RMW_NAMES = ("xchg", "add", "sub", "and", "nand", "or", "xor", "max", "min",
             "umax", "umin", "fadd", "fsub", "fmax", "fmin", "uinc_wrap",
             "udec_wrap", "usub_cond", "usub_sat", "fmaximum", "fminimum")
INTEGER_RMW = RMW_NAMES[:11] + RMW_NAMES[15:19]
ATOMIC_OPS = {"atomic_load", "atomic_store", "atomic_fence", "atomic_rmw", "atomic_compare_exchange"}
CAS_PAIRS = [(success, failure) for success in ("monotonic", "acquire", "release", "acq_rel", "seq_cst")
             for failure in ("monotonic", "acquire", "seq_cst")]


def scope_string(data):
    """Every raw byte uses an LLVM string escape, including quote, NUL and FF."""
    return 'syncscope("' + "".join(f"\\{byte:02X}" for byte in data) + '") '


def scalar_family(bits=64, scope="", alignment=None):
    alignment = alignment if alignment is not None else bits // 8
    return f'''@effect = global i64 0, align 8
declare i64 @provider(i64)
define i{bits} @entry(ptr %address, i{bits} %expected, i{bits} %replacement) {{
entry:
  %before = load atomic volatile i{bits}, ptr %address {scope}acquire, align {alignment}
  store atomic volatile i{bits} %replacement, ptr %address {scope}release, align {alignment}
  fence {scope}acq_rel
  %old = atomicrmw volatile add ptr %address, i{bits} %replacement {scope}seq_cst, align {alignment}
  %pair = cmpxchg weak volatile ptr %address, i{bits} %expected, i{bits} %replacement {scope}monotonic seq_cst, align {alignment}
  %observed = extractvalue {{i{bits}, i1}} %pair, 0
  %success = extractvalue {{i{bits}, i1}} %pair, 1
  %chosen = select i1 %success, i{bits} %observed, i{bits} %old
  %effect = load volatile i64, ptr @effect, align 8
  store volatile i64 %effect, ptr @effect, align 8
  %dependency = call i64 @provider(i64 %effect)
  ret i{bits} %chosen
}}
define i64 @unused_cold(i64 %value) {{ ret i64 %value }}
'''


class LlvmAtomicImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()
        cls.library_artifact = noundef.artifact(cls.library)
        cls.worker_source = Path(importer.__file__).read_bytes()
        cls.test_source = Path(__file__).read_bytes()

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_ATOMIC_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-atomics-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.api = importer.LLVM(self.library, importer.PINNED_SHA256)
        self.sequence, self.records = 0, []
        for name, result, args in (
            ("LLVMIsAtomic", importer.B, [importer.P]),
            ("LLVMGetAtomicSyncScopeID", importer.U, [importer.P]),
            ("LLVMGetSyncScopeID", importer.U, [importer.P, C.c_char_p, importer.S]),
            ("LLVMGetOrdering", importer.B, [importer.P]),
            ("LLVMGetAtomicRMWBinOp", importer.B, [importer.P]),
            ("LLVMGetWeak", importer.B, [importer.P]),
            ("LLVMGetCmpXchgSuccessOrdering", importer.B, [importer.P]),
            ("LLVMGetCmpXchgFailureOrdering", importer.B, [importer.P]),
        ):
            function = getattr(self.api.lib, name)
            function.restype, function.argtypes = result, args
            setattr(self.api, name.removeprefix("LLVM"), function)

    original = eh.LlvmEHImportTests.original
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

    def llvm_shape(self, ty):
        if self.api.GetTypeKind(ty) == 14:
            return {"kind": "metadata"}
        return eh.LlvmEHImportTests.llvm_shape(self, ty)

    def tearDown(self):
        worker, test = self.directory / "worker-source.py", self.directory / "test-source.py"
        worker.write_bytes(self.worker_source)
        test.write_bytes(self.test_source)
        report = {"scope": "whole original LLVM atomic source/API conformance", "test_id": self.id(),
            "worker_source": noundef.artifact(worker), "test_source": noundef.artifact(test),
            "llvm_library": self.library_artifact, "records": self.records,
            "native_execution_verified": False, "native_ordering_verified": False,
            "native_profile_admitted": False, "lock_freedom_verified": False,
            "coherent_memory_mapping_verified": False, "thread_provider_verified": False,
            "runtime_complete": False, "dependency_closure_complete": False}
        (self.directory / "atomic-source-conformance.json").write_text(json.dumps(report, indent=2) + "\n")
        self.assertEqual(Path(importer.__file__).read_bytes(), self.worker_source)
        self.assertEqual(Path(__file__).read_bytes(), self.test_source)

    def operand(self, value, ids):
        if self.api.IsAPoisonValue(value):
            return {"kind": "poison"}
        if self.api.IsAUndefValue(value):
            return {"kind": "undef"}
        return eh.LlvmEHImportTests.operand(self, value, ids)

    def atomic_oracle(self, path, expected_scope_names=()):
        """Typed pinned CAPI observes operands, identities and public enums.

        Scope bytes are supplied by the controlled original fixture, then
        looked up with the length-bearing CAPI. Actual frontend units use only
        the two builtin names. No production decoder or operation mapper is
        used as the assertion oracle.
        """
        a = self.api
        result = {"functions": [], "definitions": [], "globals": [], "aliases": [],
                  "signatures": {}, "bodies": {}, "scopes": []}
        with self.original(path) as (context, module):
            scope_names = {a.GetSyncScopeID(context, name, len(name)): name
                           for name in (b"singlethread", b"", *expected_scope_names)}
            self.assertEqual(scope_names[0], b"singlethread")
            self.assertEqual(scope_names[1], b"")
            used_scopes = set()
            result["globals"] = [a.name(g) for g in a.sequence(a.GetFirstGlobal, a.GetNextGlobal, module)]
            result["aliases"] = [a.name(g) for g in a.sequence(a.GetFirstGlobalAlias, a.GetNextGlobalAlias, module)]
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                name = a.name(function)
                result["functions"].append(name)
                result["signatures"][name] = self.signature(a.GlobalGetValueType(function), function)
                params = (importer.P * a.CountParams(function))()
                a.GetParams(function, params)
                ids = {value: index for index, value in enumerate(params)}
                blocks = list(a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function))
                if blocks:
                    result["definitions"].append(name)
                for block in blocks:
                    for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                        if a.GetTypeKind(a.TypeOf(instruction)) != 0:
                            ids[instruction] = len(ids)
                body = {"atomics": [], "ordinary_memory": [], "calls": [], "instruction_opcodes": []}
                result["bodies"][name] = body
                for block_id, block in enumerate(blocks):
                    for ordinal, instruction in enumerate(a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block)):
                        opcode = a.GetInstructionOpcode(instruction)
                        body["instruction_opcodes"].append(opcode)
                        value = None if a.GetTypeKind(a.TypeOf(instruction)) == 0 else {
                            "id": ids[instruction], "type": self.llvm_shape(a.TypeOf(instruction))}
                        if a.IsAtomic(instruction):
                            scope = a.GetAtomicSyncScopeID(instruction)
                            self.assertIn(scope, scope_names, "a producer custom scope needs an explicit raw-byte oracle")
                            used_scopes.update((0, 1, scope))
                            op = {"op": {27: "atomic_load", 28: "atomic_store", 55: "atomic_fence",
                                         56: "atomic_compare_exchange", 57: "atomic_rmw"}[opcode], "sync_scope": scope}
                            raw = {}
                            if opcode == 56:
                                success, failure = a.GetCmpXchgSuccessOrdering(instruction), a.GetCmpXchgFailureOrdering(instruction)
                                op.update(success_ordering=ORDERINGS[success], failure_ordering=ORDERINGS[failure],
                                          weak=bool(a.GetWeak(instruction)))
                                raw.update(success=success, failure=failure)
                            else:
                                ordering = a.GetOrdering(instruction)
                                op["ordering"] = ORDERINGS[ordering]
                                raw["ordering"] = ordering
                            if opcode != 55:
                                # Unsigned alignment getters return the low32
                                # bits. For instructions, zero means the legal
                                # mandatory maximum alignment, not absence.
                                op.update(alignment=a.GetAlignment(instruction) or (1 << 32),
                                          volatile=bool(a.GetVolatile(instruction)))
                                op["pointer"] = self.operand(a.GetOperand(instruction, 1 if opcode == 28 else 0), ids)
                                if opcode in (28, 57):
                                    op["value"] = self.operand(a.GetOperand(instruction, 0 if opcode == 28 else 1), ids)
                                if opcode == 57:
                                    rmw = a.GetAtomicRMWBinOp(instruction)
                                    op["kind"] = RMW_NAMES[rmw]
                                    raw["rmw"] = rmw
                                if opcode == 56:
                                    op["expected"] = self.operand(a.GetOperand(instruction, 1), ids)
                                    op["replacement"] = self.operand(a.GetOperand(instruction, 2), ids)
                            body["atomics"].append({"block": block_id, "source_instruction": ordinal,
                                "operation": op, "result": value, "raw_enums": raw})
                        elif opcode in (27, 28):
                            op = {"op": "load" if opcode == 27 else "store",
                                  "pointer": self.operand(a.GetOperand(instruction, 0 if opcode == 27 else 1), ids),
                                  "alignment": a.GetAlignment(instruction) or (1 << 32), "volatile": bool(a.GetVolatile(instruction))}
                            if opcode == 28:
                                op["value"] = self.operand(a.GetOperand(instruction, 0), ids)
                            body["ordinary_memory"].append({"block": block_id, "operation": op, "result": value})
                        elif opcode == 45:
                            body["calls"].append({"block": block_id, "callee": self.operand(a.GetCalledValue(instruction), ids),
                                "signature": self.signature(a.GetCalledFunctionType(instruction), instruction, True),
                                "args": [self.operand(a.GetOperand(instruction, i), ids) for i in range(a.GetNumArgOperands(instruction))],
                                "result": value})
            result["scopes"] = [{"id": ident, "name": list(scope_names[ident])} for ident in sorted(used_scopes)]
        return result

    def assert_original(self, path, module, profile=PROFILE, scopes=()):
        original = self.atomic_oracle(path, scopes)
        self.assertEqual(module["provenance"]["input_sha256"], noundef.artifact(path)["sha256"])
        self.assertEqual(module["target"].get("atomic_profile"), None if profile is None else "coherent_ram_v1")
        for singular, plural in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
            self.assertEqual([item["name"] for item in module[plural]], original[plural])
            self.assertEqual(module["provenance"]["source_" + singular + "_count"], len(original[plural]))
        self.assertEqual([f["name"] for f in module["functions"] if f["entry"] is not None], original["definitions"])
        self.assertEqual(module["atomic_sync_scopes"], original["scopes"])
        notes = module["provenance"]["refinements"]
        for function in module["functions"]:
            name, body = function["name"], original["bodies"][function["name"]]
            self.assertEqual(self.native_signature(module, function["signature"]), original["signatures"][name])
            atomics, ordinary_memory, calls, intrinsic_ops = [], [], [], []
            for block in function["blocks"]:
                for instruction in block["instructions"]:
                    op, value = instruction["operation"], instruction["result"]
                    value = None if value is None else {"id": value["id"], "type": self.shape(module, value["ty"])}
                    if op["op"] in ATOMIC_OPS:
                        item = {"block": block["id"], "operation": {k: self.strip_types(v) if k in {
                            "pointer", "value", "expected", "replacement"} else v for k, v in op.items()}, "result": value}
                        atomics.append(item)
                    elif op["op"] in {"load", "store"}:
                        ordinary_memory.append({"block": block["id"], "operation": {k: self.strip_types(v) if k in {
                            "pointer", "value"} else v for k, v in op.items()}, "result": value})
                    elif op["op"] == "call":
                        calls.append({"block": block["id"], "callee": self.strip_types(op["callee"]),
                            "signature": self.native_signature(module, op["signature"]),
                            "args": [self.strip_types(arg) for arg in op["args"]], "result": value})
                    elif op["op"] in {"lifetime", "memory_set", "memory_copy", "assume", "trap", "no_alias_scope_decl"}:
                        intrinsic_ops.append(op["op"])
            self.assertEqual(atomics, [{k: v for k, v in row.items() if k not in {"source_instruction", "raw_enums"}}
                                       for row in body["atomics"]])
            self.assertEqual(ordinary_memory, body["ordinary_memory"])
            ordinary_calls, expected_intrinsics = [], []
            for call in body["calls"]:
                callee = call["callee"].get("name", "")
                if not callee.startswith("llvm."):
                    ordinary_calls.append(call)
                else:
                    if callee.startswith("llvm.lifetime."): expected_intrinsics.append("lifetime")
                    elif callee.startswith(("llvm.memcpy.", "llvm.memmove.")): expected_intrinsics.append("memory_copy")
                    elif callee.startswith("llvm.memset."): expected_intrinsics.append("memory_set")
                    elif callee == "llvm.experimental.noalias.scope.decl": expected_intrinsics.append("no_alias_scope_decl")
                    elif callee == "llvm.assume": expected_intrinsics.append("assume")
                    elif callee == "llvm.trap": expected_intrinsics.append("trap")
                    else: self.fail(f"original intrinsic {callee} requires an explicit effect oracle")
            self.assertEqual(calls, ordinary_calls)
            self.assertEqual(intrinsic_ops, expected_intrinsics)
            for row in body["atomics"]:
                op = row["operation"]
                prefix = f"{name}: retained {op['op']} at block {row['block']} source instruction {row['source_instruction']}: "
                note = next((note for note in notes if note.startswith(prefix)), None)
                self.assertIsNotNone(note)
                self.assertIn(f"sync_scope={op['sync_scope']}", note)
                name_bytes = bytes(next(scope["name"] for scope in original["scopes"] if scope["id"] == op["sync_scope"]))
                self.assertIn(f"name_bytes={name_bytes.hex()}", note)
                self.assertIn("original atomic event and operands retained", note)
        return original

    def accept(self, path, profile=PROFILE, scopes=(), **kwargs):
        before = noundef.artifact(path)
        module = importer.import_module(path, library_path=self.library, atomic_profile=profile, **kwargs)
        original = self.assert_original(path, module, profile, scopes)
        output = path.with_name(path.name + f".{'none' if profile is None else 'profile'}.native.json")
        output.write_text(json.dumps(module, indent=2) + "\n")
        self.assertEqual(noundef.artifact(path), before)
        self.records.append({"input": before, "profile": profile, "outcome": "accepted",
                             "original_inventory": original, "module": noundef.artifact(output)})
        return module

    def reject(self, path, stage="import", diagnostic=None, profile=PROFILE, verified=True):
        before = noundef.artifact(path)
        if verified:
            with self.original(path): pass
        # Malformed-source handling is isolated: an unexpected LLVM signal is
        # retained and fails this assertion without killing the whole suite.
        self.sequence += 1
        output = self.directory / f"negative-{self.sequence:03}.json"
        command = [sys.executable, "-B", str(Path(importer.__file__)), str(path),
                   "--llvm-library", str(self.library), "--output", str(output)]
        if profile is not None:
            command += ["--atomic-profile", profile]
        completed = subprocess.run(command, cwd=baseline.ROOT, capture_output=True, text=True, timeout=45)
        self.records.append({"input": before, "profile": profile, "outcome": "worker-rejection",
            "command": command, "cwd": str(baseline.ROOT), "exit_code": completed.returncode,
            "stdout": completed.stdout, "stderr": completed.stderr, "output_exists": output.exists()})
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertFalse(output.exists(), "whole-unit rejection must not publish a partial module")
        error = json.loads(completed.stderr)["error"]
        self.assertEqual(error["stage"], stage, "parser/verifier failure is not an importer guard")
        if diagnostic:
            self.assertIn(diagnostic, error["message"])
        self.assertEqual(noundef.artifact(path), before)
        return error

    def pair(self, body, triple, accepted=True, stage="import", diagnostic=None, profile=PROFILE, scopes=()):
        source = self.write(body, triple)
        paths = source, self.bitcode(source)
        if not accepted:
            for path in paths:
                with self.subTest(triple=triple, format=path.suffix):
                    self.reject(path, stage, diagnostic, profile)
            return []
        modules = [self.accept(path, profile, scopes) for path in paths]
        self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        return modules

    def reference_negative(self, body, triple, expected_stage, diagnostic):
        source = self.write(body, triple)
        binary = source.with_suffix(".bc")
        program = '''import ctypes as C, json, sys
from pathlib import Path
from scripts import ocore_llvm_import as w
a=w.LLVM(Path(sys.argv[2]),w.PINNED_SHA256)
c=a.ContextCreate(); b=None; m=w.P(); e=w.P(); v=w.P(); out=None
r={}
try:
 d=Path(sys.argv[1]).read_bytes(); b=a.CreateMemoryBufferWithMemoryRangeCopy(d,len(d),b"atomic-reference")
 r["parse_status"]=a.ParseIRInContext2(c,b,C.byref(m),C.byref(e))
 r["parse_message"]=C.string_at(e).decode(errors="backslashreplace") if e else ""
 if not r["parse_status"]:
  r["verify_status"]=a.VerifyModule(m,2,C.byref(v))
  r["verify_message"]=C.string_at(v).decode(errors="backslashreplace") if v else ""
  out=a.WriteBitcodeToMemoryBuffer(m)
  Path(sys.argv[3]).write_bytes(C.string_at(a.GetBufferStart(out),a.GetBufferSize(out)))
finally:
 if out:a.DisposeMemoryBuffer(out)
 if v:a.DisposeMessage(v)
 if e:a.DisposeMessage(e)
 if m:a.DisposeModule(m)
 if b:a.DisposeMemoryBuffer(b)
 a.ContextDispose(c)
print(json.dumps(r))
'''
        script = source.with_name(source.stem + "-reference.py")
        script.write_text(program)
        command = [sys.executable, "-B", str(script), str(source), str(self.library), str(binary)]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(baseline.ROOT)
        completed = subprocess.run(command, cwd=baseline.ROOT, env=environment,
                                   capture_output=True, text=True, timeout=45)
        self.records.append({"outcome": "isolated-LLVM-reference", "input": noundef.artifact(source),
            "script": noundef.artifact(script), "command": command, "cwd": str(baseline.ROOT),
            "environment_overrides": {"PYTHONPATH": str(baseline.ROOT)}, "exit_code": completed.returncode,
            "stdout": completed.stdout, "stderr": completed.stderr,
            "binary": noundef.artifact(binary) if binary.exists() else None})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        reference = json.loads(completed.stdout)
        if expected_stage == "parse":
            self.assertNotEqual(reference["parse_status"], 0)
            self.assertIn(diagnostic, reference["parse_message"])
            self.assertFalse(binary.exists())
        else:
            self.assertEqual(reference["parse_status"], 0)
            self.assertNotEqual(reference["verify_status"], 0)
            self.assertIn(diagnostic, reference["verify_message"])
        for path in (source, binary) if binary.exists() else (source,):
            self.reject(path, expected_stage, diagnostic, verified=False)

    def test_all_five_families_typed_widths_original_results_ordinary_effects_and_cold_inventory_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for bits in (8, 16, 32, 64):
                for module in self.pair(scalar_family(bits), triple):
                    ops = self.operations(self.function(module, "entry"))
                    self.assertEqual([op["op"] for op in ops if op["op"] in ATOMIC_OPS],
                                     ["atomic_load", "atomic_store", "atomic_fence", "atomic_rmw", "atomic_compare_exchange"])
                    self.assertEqual(sum(op["op"] == "load" for op in ops), 1)
                    self.assertEqual(sum(op["op"] == "store" for op in ops), 1)
                    self.assertEqual(sum(op["op"] == "call" for op in ops), 1)
                    self.assertIn("unused_cold", [f["name"] for f in module["functions"]])

    def test_public_integer_rmw_enum_mapping_wrap_conditional_saturating_and_old_value_identity_all_three_isas_ll_bc(self):
        definitions = []
        for bits in (8, 16, 32, 64):
            for index, name in enumerate(INTEGER_RMW):
                definitions.append(f'''define i{bits} @rmw_{bits}_{name}(ptr %p, i{bits} %value) {{
 %old = atomicrmw {'volatile ' if index % 2 else ''}{name} ptr %p, i{bits} %value acq_rel, align {bits // 8}
 ret i{bits} %old
}}''')
        for triple in TRIPLES:
            for module in self.pair("\n".join(definitions), triple):
                rows = [op for fn in module["functions"] for op in self.operations(fn) if op["op"] == "atomic_rmw"]
                self.assertEqual([op["kind"] for op in rows], list(INTEGER_RMW) * 4)
                self.assertEqual(len(rows), 60)
                for fn in module["functions"]:
                    instruction = self.instructions(fn)[0]
                    self.assertEqual(fn["blocks"][0]["terminator"]["value"]["id"], instruction["result"]["id"])

    def test_all_fifteen_compare_exchange_order_pairs_stronger_failure_weakness_and_original_struct_all_three_isas_ll_bc(self):
        definitions = []
        for index, (success, failure) in enumerate(CAS_PAIRS):
            for weak in (False, True):
                definitions.append(f'''define {{i64,i1}} @cas_{index}_{int(weak)}(ptr %p, i64 %expected, i64 %replacement) {{
 %pair = cmpxchg {'weak ' if weak else ''}{'volatile ' if index % 2 else ''}ptr %p, i64 %expected, i64 %replacement {success} {failure}, align 8
 ret {{i64,i1}} %pair
}}''')
        for triple in TRIPLES:
            for module in self.pair("\n".join(definitions), triple):
                rows = [op for fn in module["functions"] for op in self.operations(fn) if op["op"] == "atomic_compare_exchange"]
                self.assertEqual([(op["success_ordering"], op["failure_ordering"], op["weak"]) for op in rows],
                                 [(s, f, weak) for s, f in CAS_PAIRS for weak in (False, True)])
                self.assertEqual(len(rows), 30)
                for fn in module["functions"]:
                    instruction = self.instructions(fn)[0]
                    self.assertEqual(self.shape(module, instruction["result"]["ty"]),
                        {"kind": "struct", "packed": False, "fields": [{"kind": "int", "bits": 64}, {"kind": "int", "bits": 1}]})
                    self.assertEqual(fn["blocks"][0]["terminator"]["value"]["id"], instruction["result"]["id"])

    def test_all_legal_load_store_fence_and_rmw_orderings_remain_distinct_all_three_isas_ll_bc(self):
        instructions = []
        for index, ordering in enumerate(("unordered", "monotonic", "acquire", "seq_cst")):
            instructions.append(f"%load{index} = load atomic i32, ptr %p {ordering}, align 4")
        for ordering in ("unordered", "monotonic", "release", "seq_cst"):
            instructions.append(f"store atomic i32 %value, ptr %p {ordering}, align 4")
        for ordering in ("acquire", "release", "acq_rel", "seq_cst"):
            instructions.append(f"fence {ordering}")
        for index, ordering in enumerate(("monotonic", "acquire", "release", "acq_rel", "seq_cst")):
            instructions.append(f"%rmw{index} = atomicrmw xor ptr %p, i32 %value {ordering}, align 4")
        body = "define void @entry(ptr %p, i32 %value) {\n" + "\n".join(instructions) + "\nret void\n}\n"
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                ops = self.operations(self.function(module, "entry"))
                self.assertEqual([op["ordering"] for op in ops],
                    ["unordered", "monotonic", "acquire", "seq_cst", "unordered", "monotonic", "release", "seq_cst",
                     "acquire", "release", "acq_rel", "seq_cst", "monotonic", "acquire", "release", "acq_rel", "seq_cst"])

    def test_pointer_load_store_exchange_cas_null_symbol_and_aggregate_success_results_all_three_isas_ll_bc(self):
        body = '''@object = global i64 37, align 8
@slot = global ptr @object, align 8
define {ptr,i1} @entry(ptr %address, ptr %expected, ptr %replacement) {
 %before = load atomic volatile ptr, ptr %address acquire, align 8
 store atomic volatile ptr null, ptr %address release, align 8
 %old = atomicrmw volatile xchg ptr @slot, ptr @object acq_rel, align 8
 %pair = cmpxchg weak volatile ptr %address, ptr %expected, ptr %replacement release acquire, align 8
 ret {ptr,i1} %pair
}
'''
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                ops = self.operations(self.function(module, "entry"))
                self.assertEqual(self.strip_types(ops[1]["value"]), {"kind": "null"})
                self.assertEqual(self.shape(module, ops[1]["value"]["ty"]), {"kind": "pointer", "address_space": 0})
                self.assertEqual(ops[2]["kind"], "xchg")
                self.assertEqual(self.strip_types(ops[2]["value"]), {"kind": "symbol", "name": "object"})
                self.assertEqual(self.shape(module, ops[2]["value"]["ty"]), {"kind": "pointer", "address_space": 0})
                self.assertEqual(self.shape(module, self.instructions(self.function(module, "entry"))[-1]["result"]["ty"]),
                    {"kind": "struct", "packed": False, "fields": [{"kind": "pointer", "address_space": 0}, {"kind": "int", "bits": 1}]})

    def test_source_profile_is_explicit_and_absent_profile_keeps_ir_even_with_atomics_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for body in ("define i64 @cold(i64 %x) { ret i64 %x }\n", scalar_family()):
                source = self.write(body, triple)
                for path in (source, self.bitcode(source)):
                    absent, explicit = self.accept(path, None), self.accept(path, PROFILE)
                    self.assertNotIn("atomic_profile", absent["target"])
                    a, b = self.realization(absent), self.realization(explicit)
                    b = dict(b, target={k: v for k, v in b["target"].items() if k != "atomic_profile"})
                    self.assertEqual(a, b)
                    if absent["atomic_sync_scopes"]:
                        self.assertTrue(any("source IR without an inferred atomic profile" in note for note in absent["provenance"]["refinements"]))
                    else:
                        self.assertEqual(absent["atomic_sync_scopes"], [])
                    for invalid in ("coherent_ram_v1", "device-ram-v1", ""):
                        self.reject(path, diagnostic="unsupported atomic profile", profile=invalid)

    def test_alignment_maximum_undernatural_and_parser_default_values_are_preserved_without_machine_admission_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for alignment in (1, 16, 1 << 32):
                for module in self.pair(scalar_family(64, alignment=alignment), triple):
                    self.assertEqual([op["alignment"] for op in self.operations(self.function(module, "entry"))
                                      if op["op"] in ATOMIC_OPS and "alignment" in op], [alignment] * 4)
            body = '''define {i32,i1} @entry(ptr %p, i32 %value) {
 %old = atomicrmw add ptr %p, i32 %value monotonic
 %pair = cmpxchg ptr %p, i32 %old, i32 %value seq_cst monotonic
 ret {i32,i1} %pair
}
'''
            for module in self.pair(body, triple):
                self.assertEqual([op["alignment"] for op in self.operations(self.function(module, "entry"))], [4, 4])

    def test_builtin_and_arbitrary_all256_byte_scope_names_preserve_context_ids_and_raw_bytes_all_three_isas_ll_bc(self):
        names = (b"", b"singlethread", b"custom", b"custom\x00suffix", bytes(range(256)), b"\xff\xfe")
        body = "\n".join(f"define void @scope_{index}() {{ fence {scope_string(name)}seq_cst\nret void }}"
                         for index, name in enumerate(names))
        for triple in TRIPLES:
            for module in self.pair(body, triple, scopes=names):
                scopes = {scope["id"]: bytes(scope["name"]) for scope in module["atomic_sync_scopes"]}
                self.assertEqual(set(scopes.values()), set(names))
                self.assertEqual([scopes[self.operations(fn)[0]["sync_scope"]] for fn in module["functions"]], list(names))

    def test_more_than32_custom_scope_ids_and_same_scope_across_all_five_families_all_three_isas_ll_bc(self):
        names = tuple(f"scope-{index:03}".encode() for index in range(65))
        body = "\n".join(f"define void @scope_{index}() {{ fence {scope_string(name)}acquire\nret void }}"
                         for index, name in enumerate(names)) + "\n" + scalar_family(scope=scope_string(names[-1]))
        for triple in TRIPLES:
            for module in self.pair(body, triple, scopes=names):
                scope_ids = {bytes(scope["name"]): scope["id"] for scope in module["atomic_sync_scopes"]}
                self.assertEqual(len(scope_ids), 67)
                self.assertEqual({op["sync_scope"] for op in self.operations(self.function(module, "entry")) if op["op"] in ATOMIC_OPS},
                                 {scope_ids[names[-1]]})

    def test_preseeded_original_bitcode_context_names_and_unused_scope_entries_do_not_become_global_capabilities(self):
        # The producer context intentionally allocates unused scope IDs first.
        # A fresh reader may normalize IDs; exact original bytes remain hashed.
        a = self.api
        for triple in TRIPLES:
            source = self.write(scalar_family(scope=scope_string(b"actual\x00scope")), triple)
            context, module, error, message, buffer, serialized = a.ContextCreate(), importer.P(), importer.P(), importer.P(), None, None
            try:
                for name in (b"unused\xff", b"unused\x00name", b"unused-third"):
                    a.GetSyncScopeID(context, name, len(name))
                data = source.read_bytes()
                buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"seeded-atomic-original")
                self.assertEqual(a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error)), 0)
                self.assertEqual(a.VerifyModule(module, 2, C.byref(message)), 0)
                serialized = a.WriteBitcodeToMemoryBuffer(module)
                binary = source.with_suffix(".seeded.bc")
                binary.write_bytes(C.string_at(a.GetBufferStart(serialized), a.GetBufferSize(serialized)))
            finally:
                if serialized: a.DisposeMemoryBuffer(serialized)
                if message: a.DisposeMessage(message)
                if error: a.DisposeMessage(error)
                if module: a.DisposeModule(module)
                if buffer: a.DisposeMemoryBuffer(buffer)
                a.ContextDispose(context)
            text = self.accept(source, scopes=(b"actual\x00scope",))
            parsed = self.accept(binary, scopes=(b"actual\x00scope",))
            self.assertEqual([bytes(scope["name"]) for scope in parsed["atomic_sync_scopes"]],
                             [b"singlethread", b"", b"actual\x00scope"])
            text_id = self.operations(self.function(text, "entry"))[0]["sync_scope"]
            binary_id = self.operations(self.function(parsed, "entry"))[0]["sync_scope"]
            self.records.append({"outcome": "context-local-scope-normalization", "text_scope_id": text_id,
                                 "bitcode_scope_id": binary_id, "source_ids_are_not_cross_image_capabilities": True})

    def test_scoped_alias_metadata_and_empty_noundef_on_atomic_load_preserve_original_sites_and_memory_events_all_three_isas_ll_bc(self):
        body = '''declare void @llvm.experimental.noalias.scope.decl(metadata)
define i32 @entry(ptr %p, i32 %value) {
 call void @llvm.experimental.noalias.scope.decl(metadata !2)
 %load = load atomic volatile i32, ptr %p acquire, align 4, !noundef !3, !alias.scope !2
 store atomic volatile i32 %value, ptr %p release, align 4, !noalias !2
 %old = atomicrmw add ptr %p, i32 %value acq_rel, align 4, !alias.scope !2
 %pair = cmpxchg ptr %p, i32 %load, i32 %old monotonic seq_cst, align 4, !noalias !2
 fence seq_cst
 ret i32 %old
}
!0 = distinct !{!0, !"atomic domain"}
!1 = distinct !{!1, !0, !"atomic scope"}
!2 = !{!1}
!3 = !{}
'''
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                attachments = module["noalias_metadata"]["attachments"]
                self.assertEqual(len(attachments), 4)
                self.assertEqual([a["site"]["source_instruction"] for a in attachments], [1, 2, 3, 4])
                self.assertEqual([a["site"]["instruction_count"] for a in attachments], [1] * 4)
                self.assertTrue(any("erased empty !noundef load promise" in note for note in module["provenance"]["refinements"]))
                self.assertEqual([op["op"] for op in self.operations(self.function(module, "entry")) if op["op"] in ATOMIC_OPS],
                                 ["atomic_load", "atomic_store", "atomic_rmw", "atomic_compare_exchange", "atomic_fence"])

    def test_typed_poison_and_undef_atomic_operands_remain_explicit_without_purity_or_runtime_guards_all_three_isas_ll_bc(self):
        body = '''define {i32,i1} @entry(ptr %p) {
 store atomic i32 undef, ptr %p unordered, align 4
 %old = atomicrmw xchg ptr %p, i32 poison monotonic, align 4
 %pair = cmpxchg ptr %p, i32 undef, i32 poison acquire monotonic, align 4
 ret {i32,i1} %pair
}
'''
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                ops = self.operations(self.function(module, "entry"))
                self.assertEqual([ops[0]["value"]["kind"], ops[1]["value"]["kind"], ops[2]["expected"]["kind"], ops[2]["replacement"]["kind"]],
                                 ["undef", "poison", "undef", "poison"])

    def test_all_public_floating_rmw_enum_names_are_verified_but_unsupported_as_whole_units_all_three_isas_ll_bc(self):
        for name in ("xchg", "fadd", "fsub", "fmax", "fmin", "fmaximum", "fminimum"):
            body = f'''define i64 @entry(i64 %x) {{ ret i64 %x }}
define float @unused_fp(ptr %p, float %value) {{
 %old = atomicrmw {name} ptr %p, float %value seq_cst, align 4
 ret float %old
}}
'''
            for triple in TRIPLES:
                source = self.write(body, triple)
                for path in (source, self.bitcode(source)):
                    with self.original(path) as (_, module):
                        function = next(fn for fn in self.api.sequence(self.api.GetFirstFunction, self.api.GetNextFunction, module)
                                        if self.api.name(fn) == "unused_fp")
                        instruction = self.api.GetFirstInstruction(self.api.GetFirstBasicBlock(function))
                        raw = self.api.GetAtomicRMWBinOp(instruction)
                        self.assertEqual(RMW_NAMES[raw], name)
                        self.records.append({"outcome": "public-floating-RMW-reference", "input": noundef.artifact(path),
                                             "public_enum": raw, "name": name})
                    self.reject(path, diagnostic="unsupported LLVM type kind")

    def test_verified_wide_fp_vector_as1_and_unused_cold_contracts_reject_complete_unit_all_three_isas_ll_bc(self):
        unsupported = (
            ("define i128 @unused_wide(ptr %p) { %v = load atomic i128, ptr %p seq_cst, align 16\nret i128 %v }", "unsupported integer width i128"),
            ("define double @unused_fp(ptr %p) { %v = load atomic double, ptr %p acquire, align 8\nret double %v }", "unsupported LLVM type kind"),
            ("define <2 x i32> @unused_vector(ptr %p) { %v = load atomic <2 x i32>, ptr %p acquire, align 8\nret <2 x i32> %v }", "unsupported LLVM type kind"),
            ("define i32 @unused_as1(ptr addrspace(1) %p) { %v = load atomic i32, ptr addrspace(1) %p acquire, align 4\nret i32 %v }", "unsupported pointer address space 1"),
            ("@unused_tls = thread_local global i64 37", "TLS globals require explicit"),
            ("declare void @unused_abi(ptr byval(i64))", "unsupported attribute"),
        )
        for triple in TRIPLES:
            for extra, diagnostic in unsupported:
                self.pair(scalar_family() + extra + "\n", triple, False, diagnostic=diagnostic)

    def test_invalid_orderings_explicit_alignment_and_compare_types_are_parser_failures_not_importer_guards(self):
        rows = (
            ("%v = load atomic i32, ptr %p release, align 4", "atomic load cannot use Release ordering"),
            ("store atomic i32 1, ptr %p acquire, align 4", "atomic store cannot use Acquire ordering"),
            ("%v = load atomic i32, ptr %p monotonic", "atomic load must have explicit non-zero alignment"),
            ("store atomic i32 1, ptr %p monotonic", "atomic store must have explicit non-zero alignment"),
            ("fence monotonic", "fence cannot be monotonic"),
            ("%v = atomicrmw add ptr %p, i32 1 unordered, align 4", "atomicrmw cannot be unordered"),
            ("%v = atomicrmw add ptr %p, ptr null monotonic, align 8", "operand must be an integer"),
            ("%v = cmpxchg ptr %p, i32 1, i64 2 seq_cst monotonic, align 8", "compare value and new value type do not match"),
            ("%v = cmpxchg ptr %p, i32 1, i32 2 unordered monotonic, align 4", "invalid cmpxchg success ordering"),
            ("%v = cmpxchg ptr %p, i32 1, i32 2 monotonic release, align 4", "invalid cmpxchg failure ordering"),
        )
        for triple in TRIPLES:
            for instruction, diagnostic in rows:
                with self.subTest(triple=triple, instruction=instruction):
                    self.reference_negative("define void @entry(ptr %p) {\n" + instruction + "\nret void\n}\n", triple, "parse", diagnostic)

    def test_non_byte_and_non_power_of_two_atomic_loads_fail_llvm_verifier_in_text_and_bitcode(self):
        for triple in TRIPLES:
            for bits, diagnostic in ((1, "atomic memory access' size must be byte-sized"),
                                     (24, "atomic memory access' operand must have a power-of-two size")):
                body = f"define i{bits} @entry(ptr %p) {{ %v = load atomic i{bits}, ptr %p monotonic, align 4\nret i{bits} %v }}\n"
                self.reference_negative(body, triple, "llvm-verify", diagnostic)

    def test_source_worker_cli_keeps_explicit_or_absent_profile_and_never_publishes_partial_cold_units_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            source = self.write(scalar_family(), triple)
            for path in (source, self.bitcode(source)):
                for profile in (None, PROFILE):
                    expected = self.accept(path, profile)
                    output = path.with_name(path.name + (".cli-none.json" if profile is None else ".cli-profile.json"))
                    command = [sys.executable, "-B", str(Path(importer.__file__)), str(path),
                               "--llvm-library", str(self.library), "--output", str(output)]
                    if profile is not None: command += ["--atomic-profile", profile]
                    completed = subprocess.run(command, cwd=baseline.ROOT, capture_output=True, text=True, timeout=45)
                    self.records.append({"outcome": "source-worker-cli", "input": noundef.artifact(path), "command": command,
                        "exit_code": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr,
                        "output": noundef.artifact(output) if output.exists() else None})
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(json.loads(output.read_text()), expected)
            self.pair(scalar_family() + "@unused_float = global double 1.0\n", triple, False,
                      diagnostic="unsupported LLVM type kind")

    def producer(self, command, source, output, environment=None):
        env = os.environ.copy()
        env.update(environment or {})
        before = noundef.artifact(source)
        completed = subprocess.run([str(arg) for arg in command], cwd=baseline.ROOT, env=env,
                                   capture_output=True, text=True, timeout=60)
        copy = output.with_name(output.name + ".original-source")
        copy.write_bytes(source.read_bytes())
        self.records.append({"outcome": "original-producer", "command": [str(arg) for arg in command],
            "cwd": str(baseline.ROOT), "environment_overrides": environment or {}, "exit_code": completed.returncode,
            "stdout": completed.stdout, "stderr": completed.stderr, "source": before,
            "source_copy": noundef.artifact(copy), "input": noundef.artifact(output) if output.exists() else None})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(noundef.artifact(source), before)
        return output

    def clang_unit(self, original, language, variants, expected_names, required_ops):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        for label, extra, diagnostic in variants:
            source = self.directory / f"whole-atomic-{language}-{label}.{'cpp' if language == 'c++' else 'c'}"
            source.write_text(original + extra)
            before = noundef.artifact(source)
            for triple in TRIPLES:
                modules = []
                for suffix in ("ll", "bc"):
                    output = self.directory / f"{source.stem}-{triple}.{suffix}"
                    flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
                    path = self.producer([clang, "--target=" + triple, *flags, "-x", language,
                        "-std=c++17" if language == "c++" else "-std=c11", "-O1", "-fno-stack-protector",
                        "-fno-pic", "-fno-pie", "-fno-vectorize", "-fno-slp-vectorize", "-emit-llvm",
                        "-S" if suffix == "ll" else "-c", source, "-o", output], source, output)
                    if extra:
                        self.reject(path, diagnostic=diagnostic)
                    else:
                        module = self.accept(path, frontend="Clang " + language, frontend_version=version)
                        modules.append(module)
                        self.assertEqual(module["target"]["triple"], triple)
                        self.assertTrue(expected_names.issubset({f["name"] for f in module["functions"]}))
                        self.assertTrue(required_ops.issubset({op["op"] for f in module["functions"] for op in self.operations(f)}))
                if modules: self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(noundef.artifact(source), before)

    def test_actual_untouched_clang22_c_five_atomic_families_and_whole_unused_float_tls_boundaries_all_three_isas_ll_bc(self):
        original = '''typedef unsigned long word;
word state = 37;
word read_atomic(word *p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
void write_atomic(word *p, word x) { __atomic_store_n(p, x, __ATOMIC_RELEASE); }
word add_atomic(word *p, word x) { return __atomic_fetch_add(p, x, __ATOMIC_ACQ_REL); }
word nand_atomic(word *p, word x) { return __atomic_fetch_nand(p, x, __ATOMIC_SEQ_CST); }
word exchange_atomic(word *p, word x) { return __atomic_exchange_n(p, x, __ATOMIC_SEQ_CST); }
word cas_atomic(word *p, word old, word replacement) { int ok = __atomic_compare_exchange_n(p, &old, replacement, 1, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE); return old ^ (word)ok; }
void fence_atomic(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); __atomic_signal_fence(__ATOMIC_ACQUIRE); }
word cold(word x) { return x + 3; }
'''
        self.clang_unit(original, "c", (("positive", "", None), ("float", "double unused_float = 1.0;\n", "unsupported LLVM type kind"),
            ("tls", "_Thread_local word unused_tls = 41;\n", "TLS globals require explicit")),
            {"read_atomic", "write_atomic", "add_atomic", "nand_atomic", "exchange_atomic", "cas_atomic", "fence_atomic", "cold"}, ATOMIC_OPS)

    def test_actual_untouched_clang22_cpp_template_comdat_atomic_calls_and_whole_float_variadic_boundaries_all_three_isas_ll_bc(self):
        original = '''using word = unsigned long;
template<class T> __attribute__((noinline)) T bump(T *p, T x) { return __atomic_fetch_add(p, x, __ATOMIC_ACQ_REL); }
extern "C" word add_atomic(word *p, word x) { return bump<word>(p, x); }
extern "C" word cas_atomic(word *p, word old, word replacement) { bool ok = __atomic_compare_exchange_n(p, &old, replacement, false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE); return old ^ word(ok); }
extern "C" word cold(word x) { return x + 3; }
'''
        self.clang_unit(original, "c++", (("positive", "", None),
            ("float", "extern \"C\" double unused_float(double x) { return x; }\n", "unsupported LLVM type kind"),
            ("abi", "extern \"C\" word unused_abi(word x, ...) { return x; }\n", "variadic")),
            {"add_atomic", "cas_atomic", "cold"}, {"atomic_rmw", "atomic_compare_exchange"})

    def test_actual_untouched_rust1971_atomic_whole_units_preserve_real_targets_and_unused_float_boundary_all_three_isas_ll_bc(self):
        rustc, version = self.rust_compiler()
        original = '''#![no_std]
use core::sync::atomic::{AtomicU64, Ordering, fence, compiler_fence};
#[no_mangle] pub static STATE: AtomicU64 = AtomicU64::new(37);
#[no_mangle] pub unsafe extern "C" fn read_atomic(p: *const AtomicU64) -> u64 { (*p).load(Ordering::Acquire) }
#[no_mangle] pub unsafe extern "C" fn write_atomic(p: *const AtomicU64, value: u64) { (*p).store(value, Ordering::Release); }
#[no_mangle] pub unsafe extern "C" fn add_atomic(p: *const AtomicU64, value: u64) -> u64 { (*p).fetch_add(value, Ordering::AcqRel) }
#[no_mangle] pub unsafe extern "C" fn exchange_atomic(p: *const AtomicU64, value: u64) -> u64 { (*p).swap(value, Ordering::SeqCst) }
#[no_mangle] pub unsafe extern "C" fn cas_atomic(p: *const AtomicU64, old: u64, value: u64) -> u64 { match (*p).compare_exchange_weak(old, value, Ordering::AcqRel, Ordering::Acquire) { Ok(v) => v, Err(v) => v } }
#[no_mangle] pub extern "C" fn fence_atomic() { fence(Ordering::SeqCst); compiler_fence(Ordering::Acquire); }
#[no_mangle] pub extern "C" fn cold(x: u64) -> u64 { x.wrapping_add(3) }
'''
        for label, extra in (("positive", ""), ("float", "#[no_mangle] pub extern \"C\" fn unused_float(x: f64) -> f64 { x }\n")):
            source = self.directory / f"whole-rust-atomic-{label}.rs"
            source.write_text(original + extra)
            before = noundef.artifact(source)
            for target, triple, abi in ((TRIPLES[0], TRIPLES[0], None), (TRIPLES[1], TRIPLES[1], None),
                                       ("riscv64gc-unknown-linux-gnu", TRIPLES[2], "lp64d")):
                modules = []
                for suffix in ("ll", "bc"):
                    output = self.directory / f"{source.stem}-{target}.{suffix}"
                    path = self.producer([rustc, source, "--crate-type=lib", "--edition=2021", "--crate-name=atomic_fixture",
                        "--target=" + target, "-Copt-level=1", "-Cpanic=abort", "-Ccodegen-units=1",
                        "--emit=" + ("llvm-ir" if suffix == "ll" else "llvm-bc"), "-o", output], source, output)
                    if extra:
                        self.reject(path, diagnostic="unsupported LLVM type kind")
                    else:
                        module = self.accept(path, frontend="Rust", frontend_version=version)
                        modules.append(module)
                        self.assertEqual(module["target"]["triple"], triple)
                        self.assertEqual(module["target"].get("abi"), abi)
                        self.assertTrue({"read_atomic", "write_atomic", "add_atomic", "exchange_atomic", "cas_atomic", "fence_atomic", "cold"}.issubset(
                            {fn["name"] for fn in module["functions"]}))
                        self.assertTrue(ATOMIC_OPS.issubset({op["op"] for fn in module["functions"] for op in self.operations(fn)}))
                if modules: self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(noundef.artifact(source), before)


if __name__ == "__main__":
    unittest.main()
