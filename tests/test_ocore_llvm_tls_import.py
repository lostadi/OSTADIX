"""Whole original TLS units require an explicit Linux execution profile.

Source/API checks preserve source models, current-thread address operations and
template storage. They do not establish PT_TLS, thread-pointer initialization,
native local-exec relocations, lifecycle providers or complete runtime closure.
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
PROFILE = "linux-elf-static-nonpreemptive-v1"
INTRINSIC = "llvm.threadlocal.address.p0"
MODELS = {1: "general_dynamic", 2: "local_dynamic", 3: "initial_exec", 4: "local_exec"}
DECLARATION = "declare ptr @llvm.threadlocal.address.p0(ptr)\n"


def address_body(declaration=DECLARATION, argument="@tls"):
    return declaration + f"""@tls = thread_local global i32 37, align 4
define i32 @entry() {{
  %address = call ptr @llvm.threadlocal.address.p0(ptr {argument})
  %value = load volatile i32, ptr %address, align 4
  store volatile i32 %value, ptr %address, align 4
  ret i32 %value
}}
"""


class LlvmTLSImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()
        cls.library_artifact = noundef.artifact(cls.library)
        cls.worker_source = Path(importer.__file__).read_bytes()
        cls.test_source = Path(__file__).read_bytes()

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_TLS_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-tls-")
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
    invalid_pair = eh.LlvmEHImportTests.invalid_pair

    def tearDown(self):
        worker, test = self.directory / "worker-source.py", self.directory / "test-source.py"
        worker.write_bytes(self.worker_source)
        test.write_bytes(self.test_source)
        report = {"scope": "whole original LLVM TLS source/API conformance", "test_id": self.id(),
                  "worker_source": noundef.artifact(worker), "test_source": noundef.artifact(test),
                  "llvm_library": self.library_artifact, "records": self.records,
                  "native_execution_verified": False, "native_tls_relocations_verified": False,
                  "tls_image_verified": False, "thread_pointer_lifecycle_verified": False,
                  "external_provider_verified": False, "runtime_complete": False,
                  "dependency_closure_complete": False}
        (self.directory / "tls-source-conformance.json").write_text(json.dumps(report, indent=2) + "\n")
        self.assertEqual(Path(importer.__file__).read_bytes(), self.worker_source)
        self.assertEqual(Path(__file__).read_bytes(), self.test_source)

    def global_inventory(self, path):
        a, result = self.api, []
        with self.original(path) as (_, module):
            data_layout = a.GetDataLayoutStr(module)
            layout = a.CreateTargetData(data_layout)
            try:
                for value in a.sequence(a.GetFirstGlobal, a.GetNextGlobal, module):
                    ty, initializer = a.GlobalGetValueType(value), a.GetInitializer(value)
                    result.append({"name": a.name(value), "type": self.llvm_shape(ty),
                        "thread_local": bool(a.IsThreadLocal(value)), "mode": a.GetThreadLocalMode(value),
                        "constant": bool(a.IsGlobalConstant(value)), "linkage": a.GetLinkage(value),
                        "visibility": a.GetVisibility(value), "alignment_getter": a.GetAlignment(value),
                        "abi_alignment": a.ABIAlignmentOfType(layout, ty),
                        "declaration": not bool(initializer), "allocation_bytes": a.ABISizeOfType(layout, ty),
                        "comdat": bool(a.GetComdat(value))})
            finally:
                a.DisposeTargetData(layout)
        return result

    def tls_align_inventory(self, path):
        a, records = self.api, []
        kind = a.GetEnumAttributeKindForName(b"align", 5)
        def collect(owner, symbol, call=False):
            for index in (0, 1):
                for attr in self.raw_attributes(owner, index, call):
                    if a.IsEnumAttribute(attr) and a.GetEnumAttributeKind(attr) == kind:
                        records.append({"symbol": symbol, "site": "callsite" if call else "function", "index": index,
                                        "name": "align", "payload": a.GetEnumAttributeValue(attr)})
        with self.original(path) as (_, module):
            for function in a.sequence(a.GetFirstFunction, a.GetNextFunction, module):
                if a.name(function) == INTRINSIC:
                    collect(function, a.name(function))
                for block in a.sequence(a.GetFirstBasicBlock, a.GetNextBasicBlock, function):
                    for instruction in a.sequence(a.GetFirstInstruction, a.GetNextInstruction, block):
                        if a.GetInstructionOpcode(instruction) == 45:
                            callee = a.GetCalledValue(instruction)
                            if a.IsAFunction(callee) and a.name(callee) == INTRINSIC:
                                collect(instruction, a.name(function), True)
        return records

    def assert_original(self, path, module, profile=PROFILE):
        original = self.oracle(path)
        self.assertEqual(module["provenance"]["input_sha256"], noundef.artifact(path)["sha256"])
        self.assertEqual(module["target"].get("tls_profile"), None if profile is None else "linux_elf_static_nonpreemptive_v1")
        for singular, plural in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
            self.assertEqual([item["name"] for item in module[plural]], original[plural])
            self.assertEqual(module["provenance"]["source_" + singular + "_count"], len(original[plural]))
        self.assertEqual([fn["name"] for fn in module["functions"] if fn["entry"] is not None], original["definitions"])
        notes = module["provenance"]["refinements"]
        globals_ = self.global_inventory(path)
        for source, native in zip(globals_, module["globals"]):
            self.assertEqual(self.shape(module, native["ty"]), source["type"])
            for key in ("thread_local", "constant"):
                self.assertEqual(native[key], source[key])
            getter = source["alignment_getter"]
            if getter:
                self.assertEqual(native["alignment"], getter)
            else:
                # The public unsigned getter aliases unspecified alignment and
                # legal 2^32 alignment. The maximum fixture separately binds
                # the actual full value; never call zero proof of absence.
                self.assertIn(native["alignment"], (source["abi_alignment"], 1 << 32))
            self.assertEqual(native["visibility"], {0: "default", 1: "hidden", 2: "protected"}[source["visibility"]])
            self.assertEqual(native["linkage"], {0: "external", 2: "linkonce", 3: "linkonce_odr", 5: "weak", 6: "weak_odr", 8: "internal", 9: "private"}[source["linkage"]])
            self.assertEqual(native.get("tls_model"), MODELS.get(source["mode"]))
            self.assertEqual(native["initializer"] is None, source["declaration"])
            self.assertEqual(bool(native.get("comdat")), source["comdat"])
            if native["initializer"] is not None:
                self.assertEqual(len(native["initializer"]["bytes"]), source["allocation_bytes"])
            if source["thread_local"]:
                prefix = f"{source['name']}: retained TLS storage and original access model {MODELS[source['mode']]} (LLVM mode {source['mode']}); "
                self.assertTrue(any(note.startswith(prefix) and "thread-pointer lifecycle providers" in note for note in notes))
        intrinsic_ops = {INTRINSIC: "thread_local_address", "llvm.assume": "assume", "llvm.trap": "trap"}
        for function in module["functions"]:
            name, source = function["name"], original["bodies"][function["name"]]
            self.assertEqual(self.native_signature(module, function["signature"]), original["signatures"][name])
            ordinary, tls, expected_ops = [], [], []
            for call in source["calls"]:
                callee = call["callee"].get("name", "")
                if not callee.startswith("llvm."):
                    ordinary.append(call)
                else:
                    op = intrinsic_ops.get(callee)
                    if callee.startswith("llvm.lifetime."): op = "lifetime"
                    if callee.startswith("llvm.memset."): op = "memory_set"
                    if callee.startswith(("llvm.memcpy.", "llvm.memmove.")): op = "memory_copy"
                    self.assertIsNotNone(op, f"original intrinsic {callee} requires an explicit source oracle")
                    expected_ops.append(op)
                    if callee == INTRINSIC:
                        tls.append({"block": call["block"], "global": call["args"][0]["name"], "result": call["result"]})
            native_calls, native_tls, accesses = [], [], []
            for block in function["blocks"]:
                for instruction in block["instructions"]:
                    op, result = instruction["operation"], instruction["result"]
                    result = None if result is None else {"id": result["id"], "type": self.shape(module, result["ty"])}
                    if op["op"] == "call":
                        native_calls.append({"block": block["id"], "callee": self.strip_types(op["callee"]),
                            "signature": self.native_signature(module, op["signature"]), "args": [self.strip_types(arg) for arg in op["args"]], "result": result})
                    elif op["op"] == "thread_local_address":
                        self.assertEqual(set(op), {"op", "global"})
                        native_tls.append({"block": block["id"], "global": op["global"], "result": result})
                        prefix = f"{name}: llvm.threadlocal.address.p0 retains current-thread address identity for TLS global {op['global']} and original result; "
                        self.assertTrue(any(note.startswith(prefix) for note in notes))
                    elif op["op"] in {"load", "store"}:
                        accesses.append({"op": op["op"], "volatile": op["volatile"], "alignment": op["alignment"]})
            self.assertEqual(native_calls, ordinary)
            self.assertEqual(native_tls, tls)
            self.assertEqual(accesses, source["accesses"])
            mapped = {"thread_local_address", "assume", "trap", "lifetime", "memory_set", "memory_copy"}
            self.assertEqual([op["op"] for op in self.operations(function) if op["op"] in mapped], expected_ops)
        original["global_contracts"] = globals_
        original["tls_pointer_promises"] = self.tls_align_inventory(path)
        for promise in original["tls_pointer_promises"]:
            prefix = f"{promise['symbol']}: {promise['site']} attribute index {promise['index']}: erased TLS intrinsic pointer promise align={promise['payload']}; "
            self.assertTrue(any(note.startswith(prefix) and "current-thread address operation" in note for note in notes))
        return original

    def accept(self, path, profile=PROFILE, **kwargs):
        before = noundef.artifact(path)
        module = importer.import_module(path, library_path=self.library, tls_profile=profile, **kwargs)
        inventory = self.assert_original(path, module, profile)
        output = path.with_name(path.name + ".native.json")
        output.write_text(json.dumps(module, indent=2) + "\n")
        self.assertEqual(noundef.artifact(path), before)
        self.records.append({"input": before, "profile": profile, "outcome": "accepted",
                             "original_inventory": inventory, "module": noundef.artifact(output)})
        return module

    def reject(self, path, stage="import", diagnostic=None, symbol=None, profile=PROFILE):
        before = noundef.artifact(path)
        if stage == "import":
            with self.original(path): pass
        with self.assertRaises(importer.ImportFailure) as raised:
            importer.import_module(path, library_path=self.library, tls_profile=profile)
        error = raised.exception
        self.assertEqual(error.stage, stage, "an LLVM parser/verifier failure is not an importer guard")
        if diagnostic: self.assertIn(diagnostic, str(error))
        if symbol: self.assertEqual(error.symbol, symbol)
        self.assertEqual(noundef.artifact(path), before)
        self.records.append({"input": before, "profile": profile, "outcome": "rejected",
                             "error": {"stage": error.stage, "symbol": error.symbol, "message": str(error)}})

    def pair(self, body, triple, accepted=True, diagnostic=None, symbol=None, profile=PROFILE, stage="import"):
        source = self.write(body, triple)
        paths = source, self.bitcode(source)
        if not accepted:
            for path in paths:
                with self.subTest(triple=triple, format=path.suffix):
                    self.reject(path, stage, diagnostic, symbol, profile)
            return []
        modules = [self.accept(path, profile) for path in paths]
        self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        return modules

    def test_all_four_models_declarations_constants_and_current_thread_ssa_identity_all_three_isas_ll_bc(self):
        body = DECLARATION + """@gd = thread_local global i32 37, align 4
@ld = internal thread_local(localdynamic) global i16 19, align 16
@ie = external thread_local(initialexec) global i64, align 8
@le = hidden thread_local(localexec) constant i8 7, align 32
@ordinary = global i32 41, align 4
declare void @cold_provider(ptr)
define i32 @entry(i1 %condition) {
entry:
  %gd = call ptr @llvm.threadlocal.address.p0(ptr @gd)
  %gd_again = call ptr @llvm.threadlocal.address.p0(ptr @gd)
  %ld = call ptr @llvm.threadlocal.address.p0(ptr @ld)
  %ie = call ptr @llvm.threadlocal.address.p0(ptr @ie)
  %le = call ptr @llvm.threadlocal.address.p0(ptr @le)
  %value = load volatile i32, ptr %gd, align 4
  store volatile i32 %value, ptr %gd_again, align 4
  br i1 %condition, label %left, label %right
left: br label %merge
right: br label %merge
merge:
  %selected = phi ptr [%gd, %left], [%gd_again, %right]
  %result = load i32, ptr %selected, align 4
  ret i32 %result
}
define i64 @cold() { ret i64 43 }
"""
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                self.assertEqual([g.get("tls_model") for g in module["globals"]], list(MODELS.values()) + [None])
                globals_ = {g["name"]: g for g in module["globals"]}
                self.assertIsNone(globals_["ie"]["initializer"])
                self.assertEqual(globals_["le"]["initializer"]["bytes"], [7])
                ops = self.operations(self.function(module, "entry"))
                self.assertEqual([op["global"] for op in ops if op["op"] == "thread_local_address"], ["gd", "gd", "ld", "ie", "le"])
                self.assertEqual(self.function(module, "entry")["params"], [{"id": 0, "ty": self.function(module, "entry")["signature"]["params"][0]}])

    def test_tls_template_nested_odd_width_zero_fill_and_non_tls_absolute_relocations_retain_layout_all_three_isas_ll_bc(self):
        body = """@ordinary = global i64 43, align 8
define i64 @provider(i64 %x) { ret i64 %x }
@ordinary_alias = alias i64, ptr @ordinary
@template = thread_local(initialexec) global {i7, [2 x i16], ptr, ptr} {i7 127, [2 x i16] [i16 258, i16 772], ptr @ordinary_alias, ptr @provider}, align 32
@zeros = private thread_local(localexec) global [17 x i8] zeroinitializer, align 64
"""
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                globals_ = {g["name"]: g for g in module["globals"]}
                template = globals_["template"]["initializer"]
                self.assertEqual(template["bytes"][:6], [127, 0, 2, 1, 4, 3])
                self.assertEqual(len(template["bytes"]), 24)
                self.assertEqual([(r["offset"], r["width"], r["symbol"], r["addend"]) for r in template["relocations"]],
                                 [(8, 64, "ordinary_alias", 0), (16, 64, "provider", 0)])
                self.assertEqual(globals_["zeros"]["initializer"], {"bytes": [0] * 17, "relocations": []})

    def test_tls_comdat_membership_weak_odr_and_linkonce_models_keep_exact_group_inventory_all_three_isas_ll_bc(self):
        body = DECLARATION + """$shared = comdat any
$retained = comdat nodeduplicate
@shared = linkonce_odr hidden thread_local(localdynamic) global i64 37, comdat, align 8
@retained = weak_odr thread_local(initialexec) global i32 41, comdat, align 4
define i64 @read_shared() {
  %address = call ptr @llvm.threadlocal.address.p0(ptr @shared)
  %value = load i64, ptr %address, align 8
  ret i64 %value
}
"""
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                self.assertEqual(module["comdats"], [{"name": "shared", "selection": "any"}, {"name": "retained", "selection": "no_deduplicate"}])
                self.assertEqual(module["provenance"]["referenced_comdat_count"], 2)
                self.assertEqual([(g["name"], g["comdat"], g["linkage"]) for g in module["globals"]], [("shared", "shared", "linkonce_odr"), ("retained", "retained", "weak_odr")])

    def test_explicit_profile_linux_gnu_and_musl_only_preserves_original_triple_even_without_tls_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for qualified in (triple, triple.removesuffix("gnu") + "musl"):
                for module in self.pair("@ordinary = global i32 7\ndefine i32 @entry() { ret i32 7 }\n", qualified):
                    self.assertEqual(module["target"]["triple"], qualified)
                    self.assertNotIn("tls_model", module["globals"][0])
                self.pair(address_body(), qualified)

    def test_no_implicit_admission_for_used_unused_or_declaration_only_tls_and_unused_owned_intrinsic_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for body in (address_body(), "@unused = thread_local global i32 7\ndefine void @entry() { ret void }\n",
                         "@unused = external thread_local(localexec) global i32\ndefine void @entry() { ret void }\n"):
                self.pair(body, triple, False, "TLS globals require explicit --tls-profile", profile=None)
            self.pair(DECLARATION + "define void @entry() { ret void }\n", triple, False,
                      "thread-local intrinsic requires explicit TLS profile", profile=None)
            self.pair("@ordinary = global i32 7\ndefine i32 @entry() { ret i32 7 }\n", triple, profile=None)

    def test_unknown_profile_and_bare_or_non_linux_targets_reject_without_inference_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            self.pair(address_body(), triple, False, "unsupported TLS profile", profile="linux_elf_static_nonpreemptive_v1")
            self.pair(address_body(), triple.replace("linux-gnu", "none-elf"), False,
                      "requires a qualified Linux GNU/musl target triple")
        self.pair(address_body() + '!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"lp64"}\n',
                  "riscv64", False, "requires a qualified Linux GNU/musl target triple")

    def test_raw_tls_symbols_gep_load_store_return_and_ordinary_call_cannot_bypass_current_thread_op_all_three_isas_ll_bc(self):
        bodies = ("define i32 @bad() { %v = load i32, ptr @tls, align 4\nret i32 %v }",
                  "define void @bad() { store i32 7, ptr @tls, align 4\nret void }",
                  "define ptr @bad() { ret ptr @tls }",
                  "define ptr @bad() { %p = getelementptr i32, ptr @tls, i64 1\nret ptr %p }",
                  "declare void @provider(ptr)\ndefine void @bad() { call void @provider(ptr @tls)\nret void }")
        for triple in TRIPLES:
            for body in bodies:
                self.pair("@tls = thread_local global i32 7\n" + body + "\n", triple, False,
                          "TLS address cannot cross as an ordinary native symbol", "bad")

    def test_static_tls_relocations_from_tls_or_process_templates_and_constant_gep_are_rejected_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for prefix, value in (("", "@tls"), ("thread_local ", "@tls"),
                                  ("", "getelementptr (i32, ptr @tls, i64 1)"),
                                  ("thread_local ", "getelementptr (i32, ptr @tls, i64 0)")):
                self.pair("@tls = thread_local global i32 7\n@pointer = " + prefix + "global ptr " + value + "\n",
                          triple, False, "TLS address cannot be a static initializer relocation", "pointer")

    def test_tls_alias_contracts_reject_without_silent_storage_identity_or_address_strengthening_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            self.pair("@tls = thread_local global i32 7\n@alias = thread_local alias i32, ptr @tls\n", triple, False,
                      "thread_local_mode", stage="bitcode-audit")
            self.pair("@tls = thread_local global i32 7\n@alias = alias i32, ptr @tls\n", triple, False,
                      "TLS aliases require explicit thread-local alias lowering", "alias")

    def test_invalid_intrinsic_arguments_fail_at_llvm_verifier_not_as_importer_support_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for body, diagnostic in ((address_body(argument="null"), "first argument must be a GlobalValue"),
                                     (address_body(argument="poison"), "first argument must be a GlobalValue"),
                                     (address_body(argument="getelementptr (i32, ptr @tls, i64 1)"), "first argument must be a GlobalValue"),
                                     (address_body().replace("@tls = thread_local", "@tls ="), "operand isThreadLocal() must be true")):
                self.invalid_pair(body, triple, diagnostic)

    def test_intrinsic_parsed_name_normalization_keeps_original_sha_and_inventory_all_three_isas_ll_bc(self):
        body = address_body().replace("llvm.threadlocal.address.p0", "llvm.threadlocal.address")
        for triple in TRIPLES:
            for module in self.pair(body, triple):
                names = {f["name"] for f in module["functions"]}
                self.assertIn(INTRINSIC, names)
                self.assertNotIn("llvm.threadlocal.address", names)
                self.assertEqual(self.function(module, INTRINSIC)["intrinsic"], INTRINSIC)
                self.assertEqual(self.operations(self.function(module, "entry"))[0]["op"], "thread_local_address")

    def test_owned_intrinsic_callsite_cc_bundles_and_address_escape_guards_remain_independent_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            for alignment in (1, 8, 1 << 32):
                body = address_body().replace("global i32 37, align 4", f"global i32 37, align {alignment}")
                body = body.replace("call ptr", f"call align {alignment} ptr").replace("(ptr @tls)", f"(ptr align {alignment} @tls)")
                if alignment == 1:
                    body = body.replace("ptr %address, align 4", "ptr %address, align 1")
                for module in self.pair(body, triple):
                    self.assertEqual(module["globals"][0]["alignment"], alignment)
                    self.assertEqual([op["op"] for op in self.operations(self.function(module, "entry"))],
                                     ["thread_local_address", "load", "store"])
                    self.assertEqual(self.function(module, INTRINSIC)["signature"]["result_attributes"], [])
            for payload in (3, 1 << 33):
                self.reject(self.write(address_body().replace("call ptr", f"call align {payload} ptr"), triple), stage="parse")
            self.pair(address_body().replace("(ptr @tls)", "(ptr dereferenceable(4) @tls)"), triple, False,
                      "unsupported attribute kind", "entry")
            self.pair(address_body().replace("(ptr @tls)\n", '(ptr @tls) "align"="8"\n'), triple, False,
                      "unsupported string attribute align", "entry")
            self.pair(address_body().replace("(ptr @tls)\n", '(ptr @tls) alignstack(8)\n'), triple, False,
                      "unsupported attribute kind", "entry")
            self.pair(address_body().replace("call ptr", "call fastcc ptr"), triple, False,
                      "exact C calling convention", "entry")
            self.pair(address_body().replace("(ptr @tls)\n", '(ptr @tls) [ "tag"(i32 7) ]\n'), triple, False,
                      "operand bundles", "entry")
            self.invalid_pair(DECLARATION + "@escaped = global ptr @llvm.threadlocal.address.p0\n", triple,
                              "Invalid user of intrinsic instruction!")

    def test_explicit_tls_profile_preserves_unused_atomic_and_rejects_float_address_space_external_initializer_and_abi_all_three_isas_ll_bc(self):
        atomic = "define i32 @atomic(ptr %p) { %v = load atomic i32, ptr %p seq_cst, align 4\nret i32 %v }\n"
        for triple in TRIPLES:
            source = self.write(address_body() + atomic, triple)
            modules = []
            for path in (source, self.bitcode(source)):
                with self.subTest(triple=triple, format=path.suffix, supported_atomic=True):
                    before = noundef.artifact(path)
                    original = self.oracle(path)
                    globals_ = self.global_inventory(path)
                    with self.original(path) as (_, llvm_module):
                        llvm_function = next(function for function in self.api.sequence(self.api.GetFirstFunction, self.api.GetNextFunction, llvm_module)
                                             if self.api.name(function) == "atomic")
                        llvm_block = self.api.GetFirstBasicBlock(llvm_function)
                        llvm_load = self.api.GetFirstInstruction(llvm_block)
                        self.assertTrue(self.api.IsALoadInst(llvm_load))
                        self.assertEqual(self.api.GetOrdering(llvm_load), 7)
                        self.assertEqual(self.api.GetAlignment(llvm_load), 4)
                        self.assertFalse(self.api.GetVolatile(llvm_load))
                    module = importer.import_module(path, library_path=self.library, tls_profile=PROFILE)
                    modules.append(module)
                    self.assertEqual(noundef.artifact(path), before)
                    self.assertEqual(module["provenance"]["input_sha256"], before["sha256"])
                    for singular, plural in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
                        self.assertEqual([row["name"] for row in module[plural]], original[plural])
                        self.assertEqual(module["provenance"]["source_" + singular + "_count"], len(original[plural]))
                    self.assertEqual(original["definitions"], ["entry", "atomic"])
                    self.assertEqual([row["name"] for row in module["functions"]], [INTRINSIC, "entry", "atomic"])
                    self.assertEqual([row["name"] for row in module["globals"]], ["tls"])
                    self.assertEqual(globals_[0]["mode"], 1)
                    self.assertTrue(module["globals"][0]["thread_local"])
                    self.assertEqual(module["globals"][0]["tls_model"], "general_dynamic")
                    self.assertEqual(module["globals"][0]["initializer"], {"bytes": [37, 0, 0, 0], "relocations": []})
                    self.assertEqual(module["target"]["tls_profile"], "linux_elf_static_nonpreemptive_v1")
                    self.assertNotIn("atomic_profile", module["target"])
                    for function in module["functions"]:
                        self.assertEqual(self.native_signature(module, function["signature"]), original["signatures"][function["name"]])
                    entry = self.operations(self.function(module, "entry"))
                    self.assertEqual([op["op"] for op in entry], ["thread_local_address", "load", "store"])
                    self.assertEqual(entry[0]["global"], "tls")
                    self.assertTrue(entry[1]["volatile"] and entry[2]["volatile"])
                    rows = self.instructions(self.function(module, "atomic"))
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["operation"], {"op": "atomic_load", "pointer": {"kind": "value", "id": 0},
                                                           "alignment": 4, "volatile": False, "ordering": "seq_cst", "sync_scope": 1})
                    self.assertEqual(self.shape(module, rows[0]["result"]["ty"]), {"kind": "int", "bits": 32})
                    output = path.with_name(path.name + ".native.json")
                    output.write_text(json.dumps(module, indent=2) + "\n")
                    self.records.append({"input": before, "profile": PROFILE, "outcome": "accepted",
                                         "original_inventory": original, "original_global_contracts": globals_, "module": noundef.artifact(output)})
            self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            for extra, diagnostic, stage in (("@unused = thread_local global double 1.0\n", "unsupported LLVM type kind", "import"),
                                             ("@unused = thread_local addrspace(1) global i32 7\n", "address space", "import"),
                                             ("@unused = thread_local externally_initialized global i32 7\n", "externally initialized", "import"),
                                             ("declare void @unsupported(ptr byval(i64))\n", "unsupported attribute kind 84", "import")):
                self.pair(address_body() + extra, triple, False, diagnostic, stage=stage)

    def producer(self, command, source, output, environment=None):
        env = os.environ.copy()
        env.update(environment or {})
        completed = subprocess.run([str(arg) for arg in command], cwd=baseline.ROOT, env=env,
                                   capture_output=True, text=True, timeout=45)
        copy = output.with_name(output.name + ".original-source")
        copy.write_bytes(source.read_bytes())
        self.records.append({"outcome": "original-producer", "command": [str(arg) for arg in command],
            "cwd": str(baseline.ROOT), "environment_overrides": environment or {}, "exit_code": completed.returncode,
            "stdout": completed.stdout, "stderr": completed.stderr, "source": noundef.artifact(source),
            "source_copy": noundef.artifact(copy), "input": noundef.artifact(output) if output.exists() else None})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output

    def test_actual_untouched_clang22_c_all_models_whole_units_and_unused_float_abi_negatives_all_three_isas_ll_bc(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        original = '''typedef unsigned long word;
_Thread_local volatile word gd __attribute__((tls_model("global-dynamic"))) = 37;
_Thread_local word ld __attribute__((tls_model("local-dynamic"))) = 41;
_Thread_local word ie __attribute__((tls_model("initial-exec"))) = 43;
_Thread_local word le __attribute__((tls_model("local-exec"))) = 47;
word read_tls(void) { word v = gd; gd = v + 1; return v + ld + ie + le; }
void *address_tls(void) { return (void *)&gd; }
word cold(word x) { return x + 3; }
'''
        for label, extra in (("positive", ""), ("float", "_Thread_local double unused_float = 1.0;\n"),
                             ("abi", "word unused_abi(word first, ...) { return first; }\n")):
            source = self.directory / f"whole-tls-{label}.c"
            source.write_text(original + extra)
            before = noundef.artifact(source)
            for triple in TRIPLES:
                modules = []
                for suffix in ("ll", "bc"):
                    output = self.directory / f"{source.stem}-{triple}.{suffix}"
                    flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
                    path = self.producer([clang, "--target=" + triple, *flags, "-x", "c", "-std=c11", "-O1",
                        "-fno-stack-protector", "-fno-pic", "-fno-pie", "-fno-vectorize", "-fno-slp-vectorize", "-emit-llvm",
                        "-S" if suffix == "ll" else "-c", source, "-o", output], source, output)
                    if extra:
                        self.reject(path, diagnostic="unsupported LLVM type kind" if label == "float" else "variadic")
                    else:
                        module = self.accept(path, frontend="Clang C", frontend_version=version)
                        modules.append(module)
                        self.assertEqual(module["target"]["triple"], triple)
                        self.assertEqual({g["tls_model"] for g in module["globals"] if g["thread_local"]}, set(MODELS.values()))
                        self.assertTrue({"read_tls", "address_tls", "cold"}.issubset({f["name"] for f in module["functions"]}))
                        self.reject(path, diagnostic="TLS globals require explicit --tls-profile", profile=None)
                if modules: self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(noundef.artifact(source), before)

    def test_source_worker_cli_requires_explicit_profile_and_publishes_only_complete_tls_module_all_three_isas_ll_bc(self):
        for triple in TRIPLES:
            source = self.write(address_body(), triple)
            for path in (source, self.bitcode(source)):
                expected = self.accept(path)
                for label, flags, accepted in (("profile", ["--tls-profile", PROFILE], True), ("absent", [], False),
                                                ("unknown", ["--tls-profile", "linux_elf_static_nonpreemptive_v1"], False)):
                    output = path.with_name(path.name + ".cli-" + label + ".json")
                    command = [sys.executable, "-B", str(Path(importer.__file__)), str(path), "--llvm-library", str(self.library),
                               "--output", str(output), *flags]
                    completed = subprocess.run(command, cwd=baseline.ROOT, capture_output=True, text=True, timeout=45)
                    self.records.append({"outcome": "source-worker-cli", "input": noundef.artifact(path), "command": command,
                        "cwd": str(baseline.ROOT), "exit_code": completed.returncode, "stdout": completed.stdout,
                        "stderr": completed.stderr, "output": noundef.artifact(output) if output.exists() else None})
                    if accepted:
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                        self.assertEqual(json.loads(output.read_text()), expected)
                    else:
                        self.assertNotEqual(completed.returncode, 0)
                        self.assertFalse(output.exists(), "failed complete-module admission must not publish a partial artifact")
                        self.assertIn("TLS globals require explicit" if label == "absent" else "unsupported TLS profile", completed.stderr)

    def test_actual_untouched_clang22_cpp_template_tls_comdat_whole_units_all_three_isas_ll_bc(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "whole-template-tls.cpp"
        source.write_text('''template<class T> thread_local T state = 37;
extern "C" unsigned long read_tls() { unsigned long v = state<unsigned long>; state<unsigned long> = v + 1; return v; }
extern "C" unsigned long *address_tls() { return &state<unsigned long>; }
extern "C" unsigned long cold(unsigned long x) { return x + 3; }
''')
        before = noundef.artifact(source)
        for triple in TRIPLES:
            modules = []
            for suffix in ("ll", "bc"):
                output = self.directory / f"{source.stem}-{triple}.{suffix}"
                flags = ["-march=rv64gc", "-mabi=lp64"] if triple.startswith("riscv64-") else []
                path = self.producer([clang, "--target=" + triple, *flags, "-x", "c++", "-std=c++17", "-O1",
                    "-fno-stack-protector", "-fno-pic", "-fno-pie", "-fno-vectorize", "-fno-slp-vectorize", "-emit-llvm",
                    "-S" if suffix == "ll" else "-c", source, "-o", output], source, output)
                module = self.accept(path, frontend="Clang C++", frontend_version=version)
                modules.append(module)
                tls = [g for g in module["globals"] if g["thread_local"]]
                self.assertTrue(tls)
                self.assertTrue(any(g["comdat"] for g in tls))
                self.assertTrue(module["comdats"])
            self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
        self.assertEqual(noundef.artifact(source), before)

    def test_actual_untouched_rust1971_tls_with_recorded_language_feature_and_unused_float_keep_genuine_targets_all_three_isas_ll_bc(self):
        rustc, version = self.rust_compiler()
        original = '''#![no_std]
#![feature(thread_local)]
#[thread_local] #[no_mangle] pub static mut state: u64 = 37;
#[no_mangle] pub unsafe extern "C" fn read_tls() -> u64 { let p = &raw mut state; let v = core::ptr::read_volatile(p); core::ptr::write_volatile(p, v.wrapping_add(1)); v }
#[no_mangle] pub unsafe extern "C" fn address_tls() -> *mut u64 { &raw mut state }
#[no_mangle] pub extern "C" fn cold(x: u64) -> u64 { x.wrapping_add(3) }
'''
        for label, extra in (("positive", ""), ("float", "#[no_mangle] pub extern \"C\" fn unused_float(x: u64) -> f64 { x as f64 }\n")):
            source = self.directory / f"whole-rust-tls-{label}.rs"
            source.write_text(original + extra)
            before = noundef.artifact(source)
            for target, triple, abi in ((TRIPLES[0], TRIPLES[0], None), (TRIPLES[1], TRIPLES[1], None),
                                       ("riscv64gc-unknown-linux-gnu", TRIPLES[2], "lp64d")):
                modules = []
                for suffix in ("ll", "bc"):
                    output = self.directory / f"{source.stem}-{target}.{suffix}"
                    path = self.producer([rustc, source, "--crate-type=lib", "--edition=2021", "--crate-name=tls_fixture", "--target=" + target,
                        "-Copt-level=1", "-Cpanic=abort", "-Ccodegen-units=1", "--emit=" + ("llvm-ir" if suffix == "ll" else "llvm-bc"),
                        "-o", output], source, output, {"RUSTC_BOOTSTRAP": "1"})
                    if extra:
                        self.reject(path, diagnostic="unsupported LLVM type kind")
                    else:
                        module = self.accept(path, frontend="Rust", frontend_version=version)
                        modules.append(module)
                        self.assertEqual(module["target"]["triple"], triple)
                        self.assertEqual(module["target"].get("abi"), abi)
                        self.assertTrue(any(g["name"] == "state" and g["thread_local"] for g in module["globals"]))
                        self.assertTrue(any(op["op"] == "thread_local_address" for op in self.operations(self.function(module, "read_tls"))))
                if modules: self.assertEqual(self.realization(modules[0]), self.realization(modules[1]))
            self.assertEqual(noundef.artifact(source), before)


if __name__ == "__main__":
    unittest.main()
