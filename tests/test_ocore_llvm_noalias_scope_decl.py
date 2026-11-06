"""Complete original scoped-alias metadata at the LLVM source/API boundary.

These checks retain metadata identities and all ordinary memory effects.
Selected supported whole producer units also pass standalone NativeVerifier;
intentionally dominated source cases still require its separate rejection.
There is no native execution, optimizer, provider-closure or runtime claim.
"""

import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_eh_import as eh
from tests import test_ocore_llvm_noundef_metadata as noundef


TRIPLES = baseline.TRIPLES
INTRINSIC = "llvm.experimental.noalias.scope.decl"
DECLARATION = f"declare void @{INTRINSIC}(metadata)\n"
GRAPH = '''!0 = distinct !{!0, !"domain"}
!1 = distinct !{!1, !0, !"scope"}
!2 = !{!1}
'''


def marker_body(graph=GRAPH, argument="!2", tail=""):
    return DECLARATION + f'''@effect = global i64 0, align 8
declare i64 @provider(i64)
define i64 @entry(ptr %pointer, i64 %value) {{
entry:
  {tail}call void @{INTRINSIC}(metadata {argument})
  %before = load volatile i64, ptr %pointer, align 8, !alias.scope !2
  %sum = add i64 %before, %value
  store volatile i64 %sum, ptr %pointer, align 8, !noalias !2
  %answer = call i64 @provider(i64 %sum)
  ret i64 %answer
}}
define i64 @unused_cold(i64 %value) {{ ret i64 %value }}
''' + graph


class LlvmNoAliasScopeDeclTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()
        cls.library_artifact = noundef.artifact(cls.library)
        cls.worker_source = Path(importer.__file__).read_bytes()
        cls.test_source = Path(__file__).read_bytes()

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NOALIAS_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-noalias-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.api = importer.LLVM(self.library, importer.PINNED_SHA256)
        self.sequence, self.records = 0, []
        for name, result, args in (
            ("LLVMGetMetadataKind", importer.U, [importer.P]),
            ("LLVMPrintValueToString", importer.P, [importer.P]),
            ("LLVMGetPersonalityFn", importer.P, [importer.P]),
            ("LLVMGetNormalDest", importer.P, [importer.P]),
            ("LLVMGetUnwindDest", importer.P, [importer.P]),
            ("LLVMGetNumClauses", importer.U, [importer.P]),
            ("LLVMGetClause", importer.P, [importer.P, importer.U]),
            ("LLVMIsCleanup", importer.B, [importer.P]),
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
    operand = eh.LlvmEHImportTests.operand
    oracle = eh.LlvmEHImportTests.oracle

    def llvm_shape(self, ty):
        if self.api.GetTypeKind(ty) == 14:
            return {"kind": "metadata"}
        return eh.LlvmEHImportTests.llvm_shape(self, ty)

    def tearDown(self):
        worker, test = self.directory / "worker-source.py", self.directory / "test-source.py"
        worker.write_bytes(self.worker_source)
        test.write_bytes(self.test_source)
        report = {"scope": "whole original LLVM noalias scope source/API conformance", "test_id": self.id(),
                  "worker_source": noundef.artifact(worker), "test_source": noundef.artifact(test),
                  "llvm_library": self.library_artifact, "records": self.records,
                  "native_execution_verified": False, "native_dominance_gate_verified": False,
                  "alias_optimizer_verified": False, "external_provider_verified": False,
                  "runtime_complete": False, "dependency_closure_complete": False}
        (self.directory / "noalias-source-conformance.json").write_text(json.dumps(report, indent=2) + "\n")
        self.assertEqual(Path(importer.__file__).read_bytes(), self.worker_source)
        self.assertEqual(Path(__file__).read_bytes(), self.test_source)

    def metadata_oracle(self, path):
        """Observe the parsed graph independently of the importer's graph IDs.

        Typed CAPI operands establish byte strings, edges and pointer identity.
        The pinned printer is used only for the top-level storage spelling;
        neither descriptions nor addresses/printed slot numbers become IDs.
        """
        a = self.api
        result = {"nodes": {}, "markers": [], "attachments": [], "sites": {}, "roots": []}
        with self.original(path) as (context, module):
            kinds = {name: a.GetMDKindIDInContext(context, name.encode(), len(name))
                     for name in ("alias.scope", "noalias")}
            identities = {}

            def printed(node):
                message = a.PrintValueToString(node)
                self.assertTrue(message)
                try:
                    data = C.string_at(message)
                finally:
                    a.DisposeMessage(message)
                # All valid controlled nodes here are MDTuples. This observes
                # storage only; arbitrary escaped descriptions stay in CAPI.
                match = re.match(rb"^[^\n]*? = (distinct )?!\{", data)
                self.assertIsNotNone(match, data)
                return ("distinct" if match.group(1) else "uniqued"), data

            def node_id(value, role):
                self.assertTrue(value)
                raw = a.ValueAsMetadata(value)
                self.assertEqual(a.GetMetadataKind(raw), 4, "reference oracle only accepts actual MDTuples")
                if raw in identities:
                    ident = identities[raw]
                    self.assertEqual(result["nodes"][str(ident)]["role"], role)
                    return ident
                ident = len(identities)
                identities[raw] = ident
                storage, printer = printed(value)
                record = {"role": role, "storage": storage, "printer_bytes": list(printer)}
                result["nodes"][str(ident)] = record
                count = a.GetMDNodeNumOperands(value)
                children = (importer.P * count)()
                a.GetMDNodeOperands(value, children)

                def string(child):
                    self.assertTrue(child and a.IsAMDString(child))
                    length = importer.U()
                    pointer = a.GetMDString(child, C.byref(length))
                    self.assertTrue(pointer or length.value == 0)
                    return list(C.string_at(pointer, length.value)) if length.value else []

                if role == "list":
                    record["scopes"] = [node_id(child, "scope") for child in children]
                else:
                    self.assertIn(count, (1, 2) if role == "domain" else (2, 3))
                    first = children[0]
                    self.assertTrue(first)
                    record["identity"] = ({"kind": "self_reference"} if a.ValueAsMetadata(first) == raw
                                          else {"kind": "bytes", "bytes": string(first)})
                    record["description"] = (string(children[-1]) if count == (2 if role == "domain" else 3) else None)
                    if role == "scope":
                        record["domain"] = node_id(children[1], "domain")
                return ident

            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                name = a.name(function)
                params = (importer.P * a.CountParams(function))()
                a.GetParams(function, params)
                values = {value: index for index, value in enumerate(params)}
                blocks = list(a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function))
                for block in blocks:
                    for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                        if a.GetTypeKind(a.TypeOf(instruction)) != 0:
                            values[instruction] = len(values)
                result["sites"][name] = []
                for block_id, block in enumerate(blocks):
                    for ordinal, instruction in enumerate(a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block)):
                        opcode = a.GetInstructionOpcode(instruction)
                        row = {"block": block_id, "source_instruction": ordinal, "opcode": opcode,
                               "result": None if a.GetTypeKind(a.TypeOf(instruction)) == 0 else values[instruction]}
                        if opcode in (27, 28):
                            row.update(volatile=bool(a.GetVolatile(instruction)), alignment=a.GetAlignment(instruction))
                        result["sites"][name].append(row)
                        if opcode == 45:
                            callee = a.GetCalledValue(instruction)
                            if a.IsAFunction(callee) and a.name(callee) == INTRINSIC:
                                self.assertEqual(a.GetNumArgOperands(instruction), 1)
                                scope_list = node_id(a.GetOperand(instruction, 0), "list")
                                result["markers"].append({"function": name, "block": block_id,
                                    "source_instruction": ordinal, "scope_list": scope_list})
                                result["roots"].append({"kind": "scope_declaration", "node": scope_list,
                                    "site": {"function": name, "block": block_id, "source_instruction": ordinal}})
                        count = importer.S()
                        entries = a.InstructionGetAllMetadataOtherThanDebugLoc(instruction, C.byref(count))
                        try:
                            attached = {}
                            for index in range(count.value):
                                kind = a.ValueMetadataEntriesGetKind(entries, index)
                                for key, wanted in kinds.items():
                                    if kind == wanted:
                                        raw = a.ValueMetadataEntriesGetMetadata(entries, index)
                                        node = a.MetadataAsValue(context, raw)
                                        self.assertEqual(a.ValueAsMetadata(node), raw)
                                        attached[key] = node_id(node, "list")
                                        result["roots"].append({"kind": key.replace(".", "_"), "node": attached[key],
                                            "site": {"function": name, "block": block_id, "source_instruction": ordinal}})
                            if attached:
                                result["attachments"].append({"function": name, "block": block_id,
                                    "source_instruction": ordinal, "alias_scope": attached.get("alias.scope"),
                                    "noalias": attached.get("noalias"),
                                    "source_order": [key.replace(".", "_") for key in attached]})
                        finally:
                            if entries:
                                a.DisposeValueMetadataEntries(entries)
        return result

    def assert_graph(self, original, module, diagnostics):
        graph = module.get("noalias_metadata", {"domains": [], "scopes": [], "lists": [], "attachments": []})
        self.assertEqual(set(graph), {"domains", "scopes", "lists", "attachments"})
        rows = {}
        roles = {}
        for plural, role in (("domains", "domain"), ("scopes", "scope"), ("lists", "list")):
            for row in graph[plural]:
                self.assertNotIn(row["id"], rows, "metadata IDs share one namespace")
                rows[row["id"]], roles[row["id"]] = row, role
        mapping, reverse = {}, {}

        def compare(source_id, native_id, role):
            if source_id in mapping:
                self.assertEqual(mapping[source_id], native_id, "the same parsed node must keep its identity")
                return
            self.assertNotIn(native_id, reverse, "different actual nodes must not merge by description")
            mapping[source_id], reverse[native_id] = native_id, source_id
            source, native = original["nodes"][str(source_id)], rows[native_id]
            self.assertEqual((source["role"], roles[native_id]), (role, role))
            self.assertEqual(native["storage"], source["storage"])
            if role == "list":
                self.assertEqual(len(native["scopes"]), len(source["scopes"]))
                for left, right in zip(source["scopes"], native["scopes"]):
                    compare(left, right, "scope")
            else:
                self.assertEqual(native["identity"], source["identity"])
                self.assertEqual(native["description"], source["description"])
                if role == "scope":
                    compare(source["domain"], native["domain"], "domain")

        markers = []
        for function in module["functions"]:
            for block in function["blocks"]:
                for index, instruction in enumerate(block["instructions"]):
                    op = instruction["operation"]
                    if op["op"] == "no_alias_scope_decl":
                        self.assertIsNone(instruction["result"])
                        self.assertEqual(set(op), {"op", "scope_list", "source_instruction"})
                        self.assertEqual(len(rows[op["scope_list"]]["scopes"]), 1)
                        markers.append({"function": function["name"], "block": block["id"],
                            "instruction": index, "source_instruction": op["source_instruction"], "scope_list": op["scope_list"]})
        self.assertEqual(len(markers), len(original["markers"]))
        for source, native in zip(original["markers"], markers):
            for field in ("function", "block", "source_instruction"):
                self.assertEqual(native[field], source[field])
            compare(source["scope_list"], native["scope_list"], "list")
        self.assertEqual(len(graph["attachments"]), len(original["attachments"]))
        for source, native in zip(original["attachments"], graph["attachments"]):
            site = native["site"]
            self.assertEqual(set(site), {"function", "block", "instruction", "instruction_count", "source_instruction"})
            for field in ("function", "block", "source_instruction"):
                self.assertEqual(site[field], source[field])
            function = self.function(module, site["function"])
            block = next(row for row in function["blocks"] if row["id"] == site["block"])
            self.assertLessEqual(site["instruction"] + site["instruction_count"], len(block["instructions"]))
            self.assertEqual(native["source_order"], source["source_order"])
            for field in ("alias_scope", "noalias"):
                self.assertEqual(native[field] is None, source[field] is None)
                if source[field] is not None:
                    compare(source[field], native[field], "list")
        self.assertEqual(len(mapping), len(original["nodes"]))
        self.assertEqual(len(rows), len(original["nodes"]), "the complete referenced graph must survive")
        # New packets retain actual graph identities and bytes canonically;
        # process-specific printer labels stay only in the explicit sidecar.
        self.assertEqual(module["provenance"]["noalias_metadata_source"], [])
        canonical = module["provenance"]["noalias_metadata_graph_source"]
        self.assertEqual(set(canonical), {"schema", "nodes", "alias_bindings", "roots"})
        self.assertEqual(canonical["schema"], "ocore.llvm-metadata-graph/v1")
        nodes = {row["id"]: row for row in canonical["nodes"]}
        self.assertEqual(len(nodes), len(canonical["nodes"]))
        self.assertEqual([row["id"] for row in canonical["nodes"]], list(range(len(nodes))))
        bindings = {row["alias_id"]: row["node"] for row in canonical["alias_bindings"]}
        self.assertEqual(len(bindings), len(canonical["alias_bindings"]))
        self.assertEqual(set(bindings), set(rows))
        self.assertEqual(len(set(bindings.values())), len(bindings), "actual distinct tuple identities must not merge")
        strings, string_ids, visited = {}, {}, set()

        def string_node(ident, expected):
            node = nodes[ident]
            self.assertEqual(set(node), {"kind", "id", "metadata_kind", "bytes"})
            self.assertEqual((node["kind"], node["metadata_kind"], node["bytes"]), ("string", 0, expected))
            value = bytes(expected)
            if value in strings:
                self.assertEqual(ident, strings[value], "equal actual MDStrings share one identity")
            if ident in string_ids:
                self.assertEqual(value, string_ids[ident], "different MDString bytes cannot alias")
            strings[value], string_ids[ident] = ident, value
            visited.add(ident)

        for source_id, native_id in mapping.items():
            source = original["nodes"][str(source_id)]
            ident = bindings[native_id]
            node = nodes[ident]
            self.assertEqual(set(node), {"kind", "id", "metadata_kind", "storage", "operands"})
            self.assertEqual((node["kind"], node["metadata_kind"], node["storage"]),
                             ("tuple", 4, source["storage"]))
            visited.add(ident)
            if source["role"] == "list":
                self.assertEqual(node["operands"], [bindings[mapping[child]] for child in source["scopes"]])
                continue
            count = 1 if source["role"] == "domain" else 2
            self.assertEqual(len(node["operands"]), count + int(source["description"] is not None))
            if source["identity"]["kind"] == "self_reference":
                self.assertEqual(node["operands"][0], ident)
            else:
                string_node(node["operands"][0], source["identity"]["bytes"])
            if source["role"] == "scope":
                self.assertEqual(node["operands"][1], bindings[mapping[source["domain"]]])
            if source["description"] is not None:
                string_node(node["operands"][-1], source["description"])
        self.assertEqual(visited, set(nodes), "canonical source graph must contain exactly the referenced tuples and strings")
        self.assertEqual(canonical["roots"], [{"kind": root["kind"], "site": root["site"],
            "node": bindings[mapping[root["node"]]]} for root in original["roots"]])
        self.assertEqual(diagnostics["graph_source"], canonical)
        raw = diagnostics["alias_nodes"]
        self.assertEqual({row["id"] for row in raw}, set(rows))
        self.assertEqual(len(raw), len(rows))
        for row in raw:
            self.assertEqual(row["metadata_kind"], 4)
            printed = bytes(row["printer_bytes"])
            self.assertEqual(hashlib.sha256(printed).hexdigest(), row["printer_sha256"])
            match = re.match(rb"^[^\n]*? = (distinct )?!\{", printed)
            self.assertIsNotNone(match, printed)
            self.assertEqual("distinct" if match.group(1) else "uniqued", rows[row["id"]]["storage"])
        return graph, markers

    def assert_original(self, path, module, diagnostics):
        original, metadata = self.oracle(path), self.metadata_oracle(path)
        self.assertEqual(module["provenance"]["input_sha256"], noundef.artifact(path)["sha256"])
        for singular, plural in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
            self.assertEqual([row["name"] for row in module[plural]], original[plural])
            self.assertEqual(module["provenance"]["source_" + singular + "_count"], len(original[plural]))
        self.assertEqual([row["name"] for row in module["functions"] if row["entry"] is not None], original["definitions"])
        for function in module["functions"]:
            name, source = function["name"], original["bodies"][function["name"]]
            self.assertEqual(self.native_signature(module, function["signature"]), original["signatures"][name])
            calls = []
            for block in function["blocks"]:
                for instruction in block["instructions"]:
                    op, value = instruction["operation"], instruction["result"]
                    if op["op"] == "call":
                        calls.append({"block": block["id"], "callee": self.strip_types(op["callee"]),
                            "signature": self.native_signature(module, op["signature"]),
                            "args": [self.strip_types(arg) for arg in op["args"]],
                            "result": None if value is None else {"id": value["id"], "type": self.shape(module, value["ty"])}})
            self.assertEqual(calls, [call for call in source["calls"] if not call["callee"].get("name", "").startswith("llvm.")])
            native_values = {row["result"]["id"]: row for block in function["blocks"] for row in block["instructions"] if row["result"]}
            source_loads = [row for row in metadata["sites"][name] if row["opcode"] == 27]
            for row in source_loads:
                instruction = native_values[row["result"]]
                self.assertEqual(instruction["operation"]["op"], "load")
                self.assertEqual((instruction["operation"]["volatile"], instruction["operation"]["alignment"]),
                                 (row["volatile"], row["alignment"]))
            stores = [row for row in self.operations(function) if row["op"] == "store"]
            source_stores = [row for row in metadata["sites"][name] if row["opcode"] == 28]
            self.assertEqual([(row["volatile"], row["alignment"]) for row in stores],
                             [(row["volatile"], row["alignment"]) for row in source_stores])
            expected = []
            for call in source["calls"]:
                callee = call["callee"].get("name", "")
                if not callee.startswith("llvm."):
                    continue
                op = {INTRINSIC: "no_alias_scope_decl", "llvm.assume": "assume", "llvm.trap": "trap"}.get(callee)
                if callee.startswith("llvm.lifetime."): op = "lifetime"
                if callee.startswith("llvm.memset."): op = "memory_set"
                if callee.startswith(("llvm.memcpy.", "llvm.memmove.")): op = "memory_copy"
                if callee.startswith("llvm.load.relative."): continue  # Dedicated span/SSA assertions below.
                self.assertIsNotNone(op, f"original intrinsic {callee} requires an explicit effect oracle")
                expected.append(op)
            owned = {"no_alias_scope_decl", "assume", "trap", "lifetime", "memory_set", "memory_copy"}
            self.assertEqual([op["op"] for op in self.operations(function) if op["op"] in owned], expected)
        self.assertEqual(set(diagnostics), {"schema", "input_sha256", "input_bytes", "import_complete",
                                           "parser", "alias_nodes", "graph_source"})
        self.assertEqual(diagnostics["schema"], "ocore.raw-llvm-metadata-diagnostics/v1")
        self.assertEqual((diagnostics["input_sha256"], diagnostics["input_bytes"]),
                         (noundef.artifact(path)["sha256"], path.stat().st_size))
        # Traversal completion is not the separate mandatory NativeVerifier
        # dominance gate, including the intentionally dominated source cases.
        self.assertIs(diagnostics["import_complete"], True)
        self.assertEqual(diagnostics["parser"], {"version": [22, 1, 6], "sha256": self.library_artifact["sha256"]})
        graph, markers = self.assert_graph(metadata, module, diagnostics)
        return {"inventory": original, "metadata": metadata, "marker_count": len(markers),
                "attachment_count": len(graph["attachments"])}

    def accept(self, path):
        before = noundef.artifact(path)
        diagnostics = {}
        module = importer.import_module(path, library_path=self.library, metadata_diagnostics=diagnostics)
        sidecar = path.with_name(path.name + ".metadata-diagnostics.json")
        sidecar.write_text(json.dumps(diagnostics, indent=2) + "\n")
        original = self.assert_original(path, module, json.loads(sidecar.read_text()))
        output = path.with_name(path.name + ".native.json")
        output.write_text(json.dumps(module, indent=2) + "\n")
        self.assertEqual(noundef.artifact(path), before)
        self.records.append({"input": before, "outcome": "accepted", "module": noundef.artifact(output),
                             "metadata_diagnostics": noundef.artifact(sidecar), "original": original})
        return module

    def reject(self, path, stage="import", diagnostic=None):
        before = noundef.artifact(path)
        if stage == "import":
            with self.original(path):
                pass
        with self.assertRaises(importer.ImportFailure) as raised:
            importer.import_module(path, library_path=self.library)
        self.assertEqual(raised.exception.stage, stage, "LLVM failure is not evidence of an importer guard")
        if diagnostic:
            self.assertIn(diagnostic, str(raised.exception))
        self.assertEqual(noundef.artifact(path), before)
        self.records.append({"input": before, "outcome": "rejected", "error": {"stage": stage, "message": str(raised.exception)}})

    def pair(self, body, triple, accepted=True, diagnostic=None):
        source = self.write(body, triple)
        paths = source, self.bitcode(source)
        if not accepted:
            for path in paths:
                self.reject(path, diagnostic=diagnostic)
            return []
        modules = [self.accept(path) for path in paths]
        # Raw trusted-printer labels remain in separate bound sidecars. The
        # complete canonical tuple/string graph is stable across LL/BC readers.
        self.assertEqual(modules[0]["provenance"]["noalias_metadata_graph_source"],
                         modules[1]["provenance"]["noalias_metadata_graph_source"])
        self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        return modules

    def invalid_original(self, body, triple, scoped_shape=False, safety_guard=False, parser_signal=None):
        """Bind the real pinned parser/verifier stage, retaining original .bc.

        Bad intrinsic spellings/signatures can be upgraded by the reader. A
        control must actually fail before its rejection is claimed; successful
        normalized graphs belong in explicit positive tests instead.
        """
        source = self.write(body, triple)
        binary = source.with_suffix(".bc")
        probe = source.with_name(source.stem + ".reference.py")
        probe.write_text('''import ctypes as C,json,sys
from pathlib import Path
P=C.c_void_p; U=C.c_uint
api=C.CDLL(sys.argv[1])
for name,result,args in [
 ('LLVMContextCreate',P,[]),
 ('LLVMCreateMemoryBufferWithMemoryRangeCopy',P,[P,C.c_size_t,P]),
 ('LLVMParseIRInContext2',U,[P,P,C.POINTER(P),C.POINTER(P)]),
 ('LLVMVerifyModule',U,[P,U,C.POINTER(P)]),
 ('LLVMWriteBitcodeToMemoryBuffer',P,[P]),
 ('LLVMGetBufferStart',P,[P]),('LLVMGetBufferSize',C.c_size_t,[P]),
 ('LLVMDisposeModule',None,[P]),('LLVMDisposeMemoryBuffer',None,[P]),
 ('LLVMContextDispose',None,[P]),('LLVMDisposeMessage',None,[P])]:
 f=getattr(api,name);f.restype=result;f.argtypes=args
context=api.LLVMContextCreate();buffer=None;module=P();error=P();message=P();serialized=None
def log(**item):print(json.dumps(item),flush=True)
try:
 data=Path(sys.argv[2]).read_bytes()
 buffer=api.LLVMCreateMemoryBufferWithMemoryRangeCopy(data,len(data),b'original-noalias-negative')
 log(phase='parse')
 status=api.LLVMParseIRInContext2(context,buffer,C.byref(module),C.byref(error))
 log(phase='parsed',status=status,diagnostic=C.string_at(error).decode(errors='replace') if error else '')
 if status:sys.exit(0)
 # Serialize parsed negative controls before verification. This is explicitly
 # NOT a verified module: it also preserves null-description controls when
 # this exact pinned verifier subsequently crashes.
 log(phase='serialize-unverified-negative')
 serialized=api.LLVMWriteBitcodeToMemoryBuffer(module)
 Path(sys.argv[3]).write_bytes(C.string_at(api.LLVMGetBufferStart(serialized),api.LLVMGetBufferSize(serialized)))
 log(phase='verify')
 status=api.LLVMVerifyModule(module,2,C.byref(message))
 log(phase='verified',status=status,diagnostic=C.string_at(message).decode(errors='replace') if message else '')
finally:
 if serialized:api.LLVMDisposeMemoryBuffer(serialized)
 if message:api.LLVMDisposeMessage(message)
 if error:api.LLVMDisposeMessage(error)
 if module:api.LLVMDisposeModule(module)
 if buffer:api.LLVMDisposeMemoryBuffer(buffer)
 if context:api.LLVMContextDispose(context)
''')
        command = [sys.executable, "-B", str(probe), str(self.library), str(source), str(binary)]
        completed = subprocess.run(command, capture_output=True, timeout=15)
        stdout, stderr = source.with_suffix(".reference.stdout"), source.with_suffix(".reference.stderr")
        stdout.write_bytes(completed.stdout)
        stderr.write_bytes(completed.stderr)
        phases = [json.loads(line) for line in completed.stdout.splitlines() if line.startswith(b"{")]
        self.records.append({"outcome": "isolated-original-LLVM-negative", "input": noundef.artifact(source),
                             "command": command, "exit_code": completed.returncode, "phases": phases,
                             "probe": noundef.artifact(probe), "stdout": noundef.artifact(stdout),
                             "stderr": noundef.artifact(stderr), "binary": noundef.artifact(binary) if binary.exists() else None,
                             "binary_verified": False})
        self.assertTrue(phases)
        parsed = next((row for row in phases if row["phase"] == "parsed"), None)
        if parser_signal is not None:
            # The pinned parser constructs the zeroinitializer before its
            # metadata-global type check and traps in getNullValue. No parsed
            # module is returned, so neither verification nor an importer guard
            # rejected this original non-storable metadata input. Preserve the
            # measured production CLI limitation instead of masking the signal
            # as a structured failure or rewriting the negative fixture.
            self.assertIsNone(parsed)
            self.assertEqual(phases, [{"phase": "parse"}])
            self.assertEqual(completed.returncode, parser_signal)
            self.assertFalse(binary.exists())
            input_before = noundef.artifact(source)
            output = source.with_name(source.name + ".unexpected.native.json")
            worker_command = [sys.executable, "-B", str(Path(importer.__file__)), str(source),
                              "--llvm-library", str(self.library), "--output", str(output)]
            worker = subprocess.run(worker_command, cwd=baseline.ROOT, capture_output=True, timeout=15)
            worker_out, worker_err = source.with_suffix(".parser-worker.stdout"), source.with_suffix(".parser-worker.stderr")
            worker_out.write_bytes(worker.stdout)
            worker_err.write_bytes(worker.stderr)
            self.records.append({"outcome": "upstream-parser-signal-boundary", "input": input_before,
                "command": worker_command, "exit_code": worker.returncode, "expected_signal": "SIGILL",
                "stdout": noundef.artifact(worker_out), "stderr": noundef.artifact(worker_err),
                "parsed_module_available": False, "binary_created": False, "structured_importer_rejection_verified": False,
                "parser_safety_verified": False, "production_failure_removed": False})
            self.assertEqual(worker.returncode, parser_signal)
            self.assertFalse(output.exists(), "the invalid metadata global must never publish a native module")
            self.assertEqual(noundef.artifact(source), input_before)
            return
        self.assertIsNotNone(parsed, "the reference parser did not complete")
        if parsed["status"]:
            self.assertEqual(completed.returncode, 0)
            stage = "parse"
        elif completed.returncode < 0:
            self.assertEqual(phases[-1]["phase"], "verify", "crash occurred outside the isolated verifier")
            self.assertTrue(scoped_shape, "an unrelated upstream crash requires a separately scoped contract")
            stage = "import"  # The corrected worker must guard this before LLVM.
        else:
            self.assertEqual(completed.returncode, 0, completed.stderr)
            verified = next((row for row in phases if row["phase"] == "verified"), None)
            self.assertIsNotNone(verified)
            self.assertNotEqual(verified["status"], 0, "negative control normalized into a valid graph")
            stage = "import" if safety_guard else "llvm-verify"
        # Safe pre-verification shape rejection is an importer guard. A raw
        # reference verifier crash is never described as a verifier rejection.
        for path in (source, binary) if binary.exists() else (source,):
            if stage == "import":
                before = noundef.artifact(path)
                worker_probe = path.with_name(path.name + ".guard.py")
                worker_probe.write_text('''import json,sys
from pathlib import Path
from scripts import ocore_llvm_import as importer
try:
 module=importer.import_module(Path(sys.argv[1]),library_path=sys.argv[2])
 Path(sys.argv[1]+'.unexpected-accepted.native.json').write_text(json.dumps(module,indent=2)+'\\n')
 print(json.dumps({'accepted':True}),flush=True)
except importer.ImportFailure as error:
 print(json.dumps({'accepted':False,'stage':error.stage,'message':str(error)}),flush=True)
''')
                guarded = subprocess.run([sys.executable, "-B", str(worker_probe), str(path), str(self.library)],
                    cwd=baseline.ROOT, env={**os.environ, "PYTHONPATH": str(baseline.ROOT)}, capture_output=True, timeout=15)
                guard_out, guard_err = path.with_name(path.name + ".guard.stdout"), path.with_name(path.name + ".guard.stderr")
                guard_out.write_bytes(guarded.stdout)
                guard_err.write_bytes(guarded.stderr)
                self.records.append({"outcome": "isolated-scoped-metadata-worker", "input": before, "exit_code": guarded.returncode,
                                     "probe": noundef.artifact(worker_probe), "stdout": noundef.artifact(guard_out),
                                     "stderr": noundef.artifact(guard_err)})
                self.assertEqual(guarded.returncode, 0, "malformed scoped metadata must produce a safe structured diagnostic")
                error = json.loads(guarded.stdout)
                self.assertFalse(error["accepted"])
                self.assertEqual(error["stage"], stage)
                self.assertEqual(noundef.artifact(path), before)
                self.records.append({"outcome": "pre-verifier-scoped-metadata-rejection", "input": before,
                                     "error": {"stage": stage, "message": error["message"]}})
            else:
                self.reject(path, stage)

    def test_genuine_marker_keeps_void_metadata_declaration_cold_inventory_and_effects_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for module in self.pair(marker_body(), triple):
                declaration = self.function(module, INTRINSIC)
                self.assertEqual(declaration["intrinsic"], INTRINSIC)
                self.assertEqual(self.native_signature(module, declaration["signature"])["params"], [{"kind": "metadata"}])
                self.assertEqual(declaration["entry"], None)
                self.assertEqual(len(module["functions"]), 4)
                entry = self.function(module, "entry")
                self.assertEqual([op["op"] for op in self.operations(entry)], ["no_alias_scope_decl", "load", "binary", "store", "call"])
                self.assertEqual(self.operations(entry)[2]["kind"], "add")
                self.assertFalse(any(self.shape(module, row["ty"])["kind"] == "metadata" for row in entry["params"]))

    def test_arbitrary_byte_identity_description_embedded_nul_and_all_byte_values_all_three_isas_ll_bc(self):
        identity = "".join(f"\\{value:02X}" for value in range(256))
        graph = f'''!0 = !{{!"{identity}", !"\\00\\FF\\22\\5C"}}
!1 = !{{!"scope\\00\\80", !0, !""}}
!2 = !{{!1}}
'''
        for triple in TRIPLES:
            for module in self.pair(marker_body(graph), triple):
                metadata = module["noalias_metadata"]
                self.assertEqual(metadata["domains"][0]["identity"], {"kind": "bytes", "bytes": list(range(256))})
                self.assertEqual(metadata["domains"][0]["description"], [0, 255, 34, 92])
                self.assertEqual(metadata["scopes"][0]["identity"]["bytes"], list(b"scope\x00\x80"))
                self.assertEqual(metadata["scopes"][0]["description"], [])

    def test_absent_and_empty_descriptions_remain_different_domains_scopes_all_three_isas_ll_bc(self):
        body = DECLARATION + '''define void @entry() {
  call void @llvm.experimental.noalias.scope.decl(metadata !4)
  call void @llvm.experimental.noalias.scope.decl(metadata !5)
  ret void
}
!0 = !{!"domain"}
!1 = !{!"domain", !""}
!2 = !{!"scope", !0}
!3 = !{!"scope", !1, !""}
!4 = !{!2}
!5 = !{!3}
'''
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                for key in ("domains", "scopes"):
                    self.assertEqual([row["description"] for row in module["noalias_metadata"][key]], [None, []])

    def test_distinct_nodes_with_equal_labels_never_merge_and_uniqued_nodes_do_all_three_isas_ll_bc(self):
        for storage, expected in (("distinct ", 2), ("", 1)):
            body = DECLARATION + f'''define void @left() {{ call void @{INTRINSIC}(metadata !4)
  ret void }}
define void @right() {{ call void @{INTRINSIC}(metadata !5)
  ret void }}
!0 = {storage}!{{!"domain", !"same"}}
!1 = {storage}!{{!"domain", !"same"}}
!2 = {storage}!{{!"scope", !0, !"same"}}
!3 = {storage}!{{!"scope", !1, !"same"}}
!4 = !{{!2}}
!5 = !{{!3}}
'''
            for triple in TRIPLES:
                for module in self.pair(body, triple):
                    self.assertEqual(len(module["noalias_metadata"]["domains"]), expected)
                    self.assertEqual(len(module["noalias_metadata"]["scopes"]), expected)

    def test_self_reference_without_lexical_distinct_preserves_parsed_distinct_storage_all_three_isas_ll_bc(self):
        graph = '!0 = !{!0}\n!1 = !{!1, !0}\n!2 = !{!1}\n'
        for triple in TRIPLES:
            for module in self.pair(marker_body(graph), triple):
                for key in ("domains", "scopes"):
                    self.assertEqual(module["noalias_metadata"][key][0]["storage"], "distinct")
                    self.assertEqual(module["noalias_metadata"][key][0]["identity"], {"kind": "self_reference"})

    def test_different_list_wrappers_share_actual_scope_across_reachable_branch_antichain_all_three_isas_ll_bc(self):
        body = DECLARATION + '''define void @entry(i1 %choice) {
entry: br i1 %choice, label %left, label %right
left:
  call void @llvm.experimental.noalias.scope.decl(metadata !2)
  ret void
right:
  call void @llvm.experimental.noalias.scope.decl(metadata !3)
  ret void
}
''' + GRAPH.replace('!2 = !{!1}', '!2 = distinct !{!1}\n!3 = distinct !{!1}')
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                graph = module["noalias_metadata"]
                self.assertEqual((len(graph["lists"]), len(graph["scopes"])), (2, 1))
                self.assertEqual(graph["lists"][0]["scopes"], graph["lists"][1]["scopes"])
                self.assertNotEqual(graph["lists"][0]["id"], graph["lists"][1]["id"])

    def test_attachment_lists_preserve_order_duplicates_empty_and_distinct_wrappers_all_three_isas_ll_bc(self):
        body = DECLARATION + '''declare void @provider(ptr)
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)
define void @entry(ptr %pointer) {
  call void @llvm.experimental.noalias.scope.decl(metadata !2)
  %value = load volatile i64, ptr %pointer, align 8, !alias.scope !4, !noalias !5
  store volatile i64 %value, ptr %pointer, align 8, !alias.scope !6, !noalias !4
  call void @provider(ptr %pointer), !alias.scope !4, !noalias !6
  call void @llvm.memset.p0.i64(ptr %pointer, i8 0, i64 8, i1 false), !alias.scope !5
  ret void
}
''' + GRAPH + '''!3 = distinct !{!3, !0, !"other"}
!4 = !{!1, !3, !1}
!5 = !{}
!6 = distinct !{!1, !3, !1}
'''
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                graph = module["noalias_metadata"]
                lists = {row["id"]: row for row in graph["lists"]}
                rows = graph["attachments"]
                members = lists[rows[0]["alias_scope"]]["scopes"]
                self.assertEqual(len(members), 3)
                self.assertEqual(members[0], members[2])
                self.assertNotEqual(members[0], members[1])
                self.assertEqual(lists[rows[0]["noalias"]]["scopes"], [])
                self.assertEqual(lists[rows[1]["alias_scope"]]["storage"], "distinct")
                self.assertEqual([row["site"]["source_instruction"] for row in rows], [1, 2, 3, 4])
                self.assertEqual([row["site"]["instruction_count"] for row in rows], [1, 1, 1, 1])

    def test_original_relative_expansion_and_terminator_attachment_exact_contiguous_site_ranges_all_three_isas_ll_bc(self):
        body = DECLARATION + '''declare ptr @llvm.load.relative.i32(ptr, i32)
define ptr @entry(ptr %base, i32 %offset) {
  call void @llvm.experimental.noalias.scope.decl(metadata !2)
  %result = call ptr @llvm.load.relative.i32(ptr %base, i32 %offset), !alias.scope !2, !noalias !2
  ret ptr %result, !alias.scope !2
}
''' + GRAPH
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                block = self.function(module, "entry")["blocks"][0]
                rows = module["noalias_metadata"]["attachments"]
                span, terminator = rows[0]["site"], rows[1]["site"]
                self.assertEqual((span["source_instruction"], span["instruction"]), (1, 1))
                self.assertEqual(span["instruction_count"], len(block["instructions"]) - 1)
                self.assertGreater(span["instruction_count"], 1)
                self.assertEqual((terminator["source_instruction"], terminator["instruction"], terminator["instruction_count"]),
                                 (2, len(block["instructions"]), 0))
                self.assertEqual(block["terminator"]["value"], {"kind": "value", "id": 2})
                self.assertEqual(block["instructions"][-1]["result"]["id"], 2)

    def test_memory_attachments_without_marker_still_retain_complete_graph_all_three_isas_ll_bc(self):
        body = '''define i8 @entry(ptr %pointer) {
  %value = load i8, ptr %pointer, align 1, !alias.scope !2, !noalias !2
  ret i8 %value
}
''' + GRAPH
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                self.assertFalse(any(op["op"] == "no_alias_scope_decl" for op in self.operations(self.function(module, "entry"))))
                self.assertEqual(len(module["noalias_metadata"]["scopes"]), 1)

    def test_full_large_reachable_antichain_has_no_32_declaration_source_ceiling_all_three_isas_ll_bc(self):
        count = 65
        branches = "\n".join(f"    i64 {i}, label %leaf{i}" for i in range(1, count))
        leaves = "\n".join(f"leaf{i}:\n  call void @{INTRINSIC}(metadata !2)\n  ret i64 {i}" for i in range(count))
        body = DECLARATION + f"define i64 @entry(i64 %choice) {{\nentry:\n  switch i64 %choice, label %leaf0 [\n{branches}\n  ]\n{leaves}\n}}\n" + GRAPH
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                function = self.function(module, "entry")
                self.assertEqual(len(function["blocks"]), count + 1)
                self.assertEqual(sum(op["op"] == "no_alias_scope_decl" for op in self.operations(function)), count)
                self.assertEqual(len(module["noalias_metadata"]["scopes"]), 1)

    def test_dominating_scope_markers_over_32_and_wrapper_identity_retained_for_mandatory_native_gate_all_three_isas_ll_bc(self):
        for count, separate in ((2, False), (2, True), (33, False), (65, True)):
            graph = GRAPH
            if separate:
                graph = GRAPH.replace('!2 = !{!1}', '') + "\n".join(f"!{i + 2} = distinct !{{!1}}" for i in range(count)) + "\n"
            calls = "\n".join(f"  call void @{INTRINSIC}(metadata !{i + 2 if separate else 2})" for i in range(count))
            body = DECLARATION + "define void @entry() {\n" + calls + "\n  ret void\n}\n" + graph
            for triple in TRIPLES:
                for module in self.pair(body, triple):
                    function = self.function(module, "entry")
                    markers = [op for op in self.operations(function) if op["op"] == "no_alias_scope_decl"]
                    self.assertEqual(len(markers), count)
                    self.assertEqual([op["source_instruction"] for op in markers], list(range(count)))
                    self.assertEqual(len(module["noalias_metadata"]["scopes"]), 1)
                    self.records.append({"outcome": "mandatory-native-dominance-rejection-required", "marker_count": count,
                                         "different_wrappers": separate, "source_import_is_not_native_admission": True})

    def test_loop_local_marker_and_unreachable_scope_boundary_are_preserved_not_hoisted_all_three_isas_ll_bc(self):
        valid = DECLARATION + '''define i64 @entry(i64 %limit) {
entry: br label %loop
loop:
  %index = phi i64 [0, %entry], [%next, %loop]
  call void @llvm.experimental.noalias.scope.decl(metadata !2)
  %next = add i64 %index, 1
  %again = icmp ult i64 %next, %limit
  br i1 %again, label %loop, label %exit
exit: ret i64 %next
}
''' + GRAPH
        unreachable = DECLARATION + '''define void @entry() {
entry: ret void
dead_left: call void @llvm.experimental.noalias.scope.decl(metadata !2)
  ret void
dead_right: call void @llvm.experimental.noalias.scope.decl(metadata !2)
  ret void
}
''' + GRAPH
        for triple in TRIPLES:
            for module in self.pair(valid, triple):
                blocks = self.function(module, "entry")["blocks"]
                self.assertEqual([block["id"] for block in blocks if any(row["operation"]["op"] == "no_alias_scope_decl" for row in block["instructions"])], [1])
            for module in self.pair(unreachable, triple):
                self.assertEqual(len(self.function(module, "entry")["blocks"]), 3)
                self.assertEqual(sum(op["op"] == "no_alias_scope_decl" for op in self.operations(self.function(module, "entry"))), 2)
                # Pinned Dominators.cpp treats every unreachable use as
                # dominated. Default LLVM verification does not enforce this
                # intrinsic rule; this is not a valid unreachable antichain.
                self.records.append({"outcome": "mandatory-native-dominance-rejection-required",
                                     "reason": "two unreachable uses share the same actual scope"})

    def test_malformed_list_scope_domain_shapes_scalar_null_and_descriptions_keep_real_llvm_stages_all_three_isas(self):
        cases = [
            ("!2", "!2 = !{}\n"),
            ("!2", GRAPH.replace("!2 = !{!1}", "!2 = !{!1, !1}")),
            ("!2", "!2 = !{null}\n"),
            ("i64 1", ""),
            ('!"scope"', ""),
            ("!2", "!0 = !{!\"domain\"}\n!1 = !{!\"scope\"}\n!2 = !{!1}\n"),
            ("!2", GRAPH.replace('!1 = distinct !{!1, !0, !"scope"}', '!1 = distinct !{!0, !0, !"scope"}')),
            ("!2", '!0 = !{}\n!1 = !{!"scope", !0}\n!2 = !{!1}\n'),
            ("!2", '!0 = !{!"domain", i32 1}\n!1 = !{!"scope", !0}\n!2 = !{!1}\n'),
            ("!2", '!0 = !{!"domain"}\n!1 = !{!"scope", !0, null}\n!2 = !{!1}\n'),
            ("!2", '!0 = !{!"domain"}\n!1 = !{!"scope", !0, !{!"nested"}}\n!2 = !{!1}\n'),
            ("!2", '!0 = !{null}\n!1 = !{!"scope", !0}\n!2 = !{!1}\n'),
            ("!2", '!0 = !{null, !"description"}\n!1 = !{!"scope", !0}\n!2 = !{!1}\n'),
            ("!2", '!0 = !{!"domain", null}\n!1 = !{!"scope", !0}\n!2 = !{!1}\n'),
            ("!2", '!0 = !{!"domain"}\n!1 = !{null, !0}\n!2 = !{!1}\n'),
        ]
        for triple in TRIPLES:
            for argument, graph in cases:
                with self.subTest(triple=triple, argument=argument, graph=graph):
                    body = DECLARATION + f"define void @entry() {{ call void @{INTRINSIC}(metadata {argument})\n  ret void }}\n" + graph
                    # A genuine empty domain and a hidden single-null domain
                    # have the same CAPI child view. The corrected worker must
                    # reject both safely before the dangerous verifier.
                    empty_domain = graph.startswith('!0 = !{}\n')
                    self.invalid_original(body, triple, scoped_shape=True, safety_guard=empty_domain)
            for kind in ("alias.scope", "noalias"):
                for members in ("null", "!1, null, !1"):
                    body = '''define i8 @entry(ptr %pointer) {
  %value = load i8, ptr %pointer, align 1, !ATTACHMENT !3
  ret i8 %value
}
'''.replace("ATTACHMENT", kind) + GRAPH + f"!3 = !{{{members}}}\n"
                    with self.subTest(triple=triple, attachment=kind, members=members):
                        self.invalid_original(body, triple, scoped_shape=True, safety_guard=True)

    def test_verifier_valid_specialized_domain_is_not_flattened_to_ordinary_tuple_all_three_isas_ll_bc(self):
        graph = '''!0 = !DIMacro(type: DW_MACINFO_define, name: "domain", value: "description")
!1 = !{!"scope", !0}
!2 = !{!1}
'''
        for triple in TRIPLES:
            self.pair(marker_body(graph), triple, accepted=False)

    def test_ordinary_metadata_signature_storage_escape_alias_and_intrinsic_invoke_remain_guarded_all_three_isas(self):
        cases = [
            "declare void @ordinary(metadata)\n",
            "@ordinary = global metadata zeroinitializer\n",
            "define metadata @ordinary() { ret metadata !0 }\n!0 = !{}\n",
            DECLARATION + f"@escape = global ptr @{INTRINSIC}\n",
            DECLARATION + f"@alternate = alias void(metadata), ptr @{INTRINSIC}\n",
            DECLARATION + '''declare i32 @personality(...)
define void @entry() personality ptr @personality {
  invoke void @llvm.experimental.noalias.scope.decl(metadata !2) to label %normal unwind label %unwind
normal: ret void
unwind: %ex = landingpad {ptr, i32} cleanup
  resume {ptr, i32} %ex
}
''' + GRAPH,
        ]
        for triple in TRIPLES:
            for body in cases:
                with self.subTest(triple=triple, body=body):
                    parser_signal = -4 if body == "@ordinary = global metadata zeroinitializer\n" else None
                    self.invalid_original(body, triple, parser_signal=parser_signal)

    def test_existing_call_convention_bundle_attributes_and_unknown_metadata_guards_are_not_erased_all_three_isas_ll_bc(self):
        cases = [
            marker_body().replace('call void @' + INTRINSIC, 'call fastcc void @' + INTRINSIC),
            marker_body().replace('metadata !2)\n', 'metadata !2) [ "deopt"(i32 1) ]\n', 1),
            marker_body().replace('metadata !2)\n', 'metadata !2) "unknown-call-contract"="keep"\n', 1),
            marker_body().replace('align 8, !alias.scope !2', 'align 8, !unknown_noalias_neighbor !2'),
        ]
        for triple in TRIPLES:
            for body in cases:
                with self.subTest(triple=triple, body=body):
                    self.pair(body, triple, accepted=False)

    def producer(self, command, source, output):
        completed = subprocess.run([str(arg) for arg in command], cwd=baseline.ROOT,
                                   capture_output=True, text=True, timeout=60)
        copy = output.with_name(output.name + ".original-source")
        copy.write_bytes(source.read_bytes())
        self.records.append({"outcome": "original-producer", "command": [str(arg) for arg in command],
            "cwd": str(baseline.ROOT), "environment_overrides": {}, "exit_code": completed.returncode,
            "stdout": completed.stdout, "stderr": completed.stderr, "source": noundef.artifact(source),
            "source_copy": noundef.artifact(copy), "input": noundef.artifact(output) if output.exists() else None})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output

    def verify_native_unit(self, path, module):
        compiler = Path(os.environ.get("OCOREC_BIN", str(baseline.ROOT / "target/debug/ocorec"))).resolve()
        self.assertTrue(compiler.is_file(), "the supported variadic producer profile requires actual NativeVerifier")
        before = noundef.artifact(compiler)
        native = path.with_name(path.name + ".native.json")
        self.assertEqual(json.loads(native.read_text()), module)
        receipt = path.with_name(path.name + ".verification.json")
        command = [str(compiler), str(native), "--input-kind", "native-ir", "--verify-native", "--receipt", str(receipt)]
        result = subprocess.run(command, cwd=baseline.ROOT, capture_output=True, timeout=60)
        stdout, stderr = path.with_name(path.name + ".verify.stdout"), path.with_name(path.name + ".verify.stderr")
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        self.records.append({"outcome": "standalone-whole-unit-native-verification", "input": noundef.artifact(path),
            "module": noundef.artifact(native), "compiler": before, "command": command,
            "exit_code": result.returncode, "stdout": noundef.artifact(stdout), "stderr": noundef.artifact(stderr),
            "receipt": noundef.artifact(receipt) if receipt.exists() else None,
            "native_execution_verified": False, "runtime_complete": False})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(noundef.artifact(compiler), before)

    def assert_identity_body(self, path, module, name):
        # The extra supported definition is not selected away: independently
        # observe its entire original one-block return, then require the exact
        # same fixed-parameter result and no native instructions or effects.
        a = self.api
        with self.original(path) as (_, original):
            source = next(row for row in a.sequence(a.GetFirstFunction, a.GetNextFunction, original) if a.name(row) == name)
            parameters = (importer.P * a.CountParams(source))()
            a.GetParams(source, parameters)
            self.assertEqual(len(parameters), 1)
            blocks = list(a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, source))
            self.assertEqual(len(blocks), 1)
            instructions = list(a.sequence(a.GetFirstInstruction, a.GetNextInstruction, blocks[0]))
            self.assertEqual(len(instructions), 1)
            self.assertEqual(a.GetInstructionOpcode(instructions[0]), 1)  # LLVMRet
            self.assertEqual(a.GetNumOperands(instructions[0]), 1)
            self.assertEqual(a.GetOperand(instructions[0], 0), parameters[0])
        function = self.function(module, name)
        self.assertEqual(len(function["params"]), 1)
        self.assertEqual(len(function["blocks"]), 1)
        self.assertEqual(function["blocks"][0]["instructions"], [])
        self.assertEqual(function["blocks"][0]["terminator"],
                         {"op": "return", "value": {"kind": "value", "id": function["params"][0]["id"]}})

    def test_actual_untouched_clang22_whole_variadic_units_and_returned_float_default_tls_guards_all_three_isas_ll_bc(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        original = '''typedef unsigned long word;
static inline __attribute__((always_inline)) word step(word *restrict a, word *restrict b) {
  *a += *b;
  return *a;
}
word original_loop(word *a, word *b, word count) {
  word result = 0;
  for (word i = 0; i < count; ++i) result += step(a + i, b + i);
  return result;
}
word unused_cold(word value) { return value + 3; }
'''
        variants = (("positive", ""), ("float", "double unused_float(double value) { return value; }\n"),
                    ("tls", "_Thread_local word unused_tls = 37;\n"),
                    ("abi", "word unused_variadic(word value, ...) { return value; }\n"))
        for label, extra in variants:
            source = self.directory / f"whole-noalias-{label}.c"
            source.write_text(original + extra)
            before = noundef.artifact(source)
            for triple in TRIPLES:
                modules = []
                for suffix in ("ll", "bc"):
                    output = self.directory / f"{source.stem}-{triple}.{suffix}"
                    flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
                    path = self.producer([clang, "--target=" + triple, *flags, "-std=c11", "-O1", "-fno-stack-protector",
                        "-fno-vectorize", "-fno-slp-vectorize", "-emit-llvm", "-S" if suffix == "ll" else "-c", source, "-o", output], source, output)
                    parsed = self.metadata_oracle(path)
                    self.assertGreater(len(parsed["markers"]), 0, "unchanged frontend must actually generate scoped declarations")
                    self.assertGreater(len(parsed["attachments"]), 0)
                    if label == "float":
                        self.reject(path, diagnostic="returned requires a supported scalar fixed parameter/call argument with enum payload zero")
                    elif label == "tls":
                        self.reject(path, diagnostic="TLS globals require explicit --tls-profile linux-elf-static-nonpreemptive-v1")
                    else:
                        module = self.accept(path)
                        self.assertEqual(len([row for row in module["functions"] if row["entry"] is not None]), 3 if label == "abi" else 2)
                        if label == "abi":
                            added = self.function(module, "unused_variadic")
                            self.assertIs(added["signature"]["variadic"], True)
                            self.assertEqual(self.shape(module, added["signature"]["result"]), {"kind": "int", "bits": 64})
                            self.assertEqual([self.shape(module, ty) for ty in added["signature"]["params"]], [{"kind": "int", "bits": 64}])
                            self.assert_identity_body(path, module, "unused_variadic")
                            self.verify_native_unit(path, module)
                        modules.append(module)
                if modules:
                    self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
                    self.assertEqual(modules[0]["provenance"]["noalias_metadata_graph_source"],
                                     modules[1]["provenance"]["noalias_metadata_graph_source"])
            self.assertEqual(noundef.artifact(source), before)
        self.records.append({"outcome": "producer-identity", "frontend": "clang", "version": version})

    def test_actual_untouched_rust1971_reference_inline_loops_whole_units_and_unused_float_keep_genuine_targets_all_three_isas_ll_bc(self):
        rustc, version = self.rust_compiler()
        original = '''#![no_std]
#[inline(always)]
fn step(a: &mut u64, b: &mut u64) -> u64 {
    *a = a.wrapping_add(*b);
    *a
}
#[no_mangle]
pub unsafe extern "C" fn original_loop(a: *mut u64, b: *mut u64, count: u64) -> u64 {
    let mut i = 0;
    let mut result = 0u64;
    while i < count {
        result = result.wrapping_add(step(&mut *a.add(i as usize), &mut *b.add(i as usize)));
        i += 1;
    }
    result
}
#[no_mangle]
pub extern "C" fn unused_cold(value: u64) -> u64 { value.wrapping_add(3) }
'''
        for label, extra in (("positive", ""), ("float", '#[no_mangle]\npub extern "C" fn unused_float(value:f64)->f64 { value }\n')):
            source = self.directory / f"whole-rust-noalias-{label}.rs"
            source.write_text(original + extra)
            before = noundef.artifact(source)
            for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "riscv64gc-unknown-linux-gnu"):
                modules = []
                for suffix, emission in (("ll", "llvm-ir"), ("bc", "llvm-bc")):
                    output = self.directory / f"{source.stem}-{target}.{suffix}"
                    path = self.producer([rustc, "--crate-name", "noalias_source_contract", "--crate-type=lib", "--edition=2021",
                        "--target", target, "-Copt-level=1", "-Cpanic=abort", "-Cno-vectorize-loops", "-Cno-vectorize-slp",
                        "--emit=" + emission, source, "-o", output], source, output)
                    parsed = self.metadata_oracle(path)
                    self.assertGreater(len(parsed["markers"]), 0, "genuine reference inlining must generate scoped declarations")
                    if extra:
                        self.reject(path)
                    else:
                        module = self.accept(path)
                        expected = "riscv64-unknown-linux-gnu" if target.startswith("riscv64gc-") else target
                        self.assertEqual(module["target"]["triple"], expected)
                        if target.startswith("riscv64gc-"):
                            self.assertEqual(module["target"]["abi"], "lp64d")
                        modules.append(module)
                if modules:
                    self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(noundef.artifact(source), before)
        self.records.append({"outcome": "producer-identity", "frontend": "rustc", "version": version})


if __name__ == "__main__":
    unittest.main()
