"""Source/API conformance for writable, builtin and returned contracts.

Every input is a complete unit. The pinned parser/verifier and fresh bitcode
writer define the normalization boundary; original bytes remain hash-bound.
These checks establish import behavior, not native or runtime completeness.
"""

import ctypes as C
import hashlib
from pathlib import Path
import re
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


TRIPLES = baseline.TRIPLES


class LlvmAdditionalAttributeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-additional-attrs-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    write = memory.LlvmMemoryImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    import_ir = memory.LlvmMemoryImportTests.import_ir
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)
    clang_flags = staticmethod(memory.LlvmMemoryImportTests.clang_flags)
    compile_clang = memory.LlvmMemoryImportTests.compile_clang

    def roundtrip(self, body, triple=TRIPLES[0]):
        source = self.write(body, triple)
        original = source.read_bytes()
        binary = self.bitcode(source)
        paths = (source, binary)
        modules = [importer.import_module(path, library_path=self.library) for path in paths]
        self.assertEqual(source.read_bytes(), original, "the original unit must not be rewritten")
        self.assertEqual({key: value for key, value in modules[0].items()
                          if key not in {"name", "provenance"}},
                         {key: value for key, value in modules[1].items()
                          if key not in {"name", "provenance"}})
        for path, module in zip(paths, modules):
            self.assertEqual(module["provenance"]["input_sha256"],
                             hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(module["target"]["triple"], triple)
            for function in module["functions"]:
                signatures = [function["signature"]] + [operation["signature"]
                    for operation in self.operations(function) if operation["op"] == "call"]
                for signature in signatures:
                    self.assertEqual(set(signature), {"params", "result", "abi", "variadic",
                                                     "param_attributes", "result_attributes"})
                    self.assertEqual(signature["abi"], "c")
                    for attributes in signature["param_attributes"] + [signature["result_attributes"]]:
                        self.assertLessEqual(set(attributes), {"signext", "zeroext"},
                                             "semantic promises must not widen the ABI")
        return modules

    def reject_verified(self, body, diagnostic=None, triple=TRIPLES[0]):
        source = self.write(body, triple)
        original = source.read_bytes()
        # Parsing and verification are checked independently before invoking the
        # importer, so a malformed fixture cannot establish an import guard.
        for path in (source, self.bitcode(source)):
            with self.assertRaises(importer.ImportFailure) as raised:
                importer.import_module(path, library_path=self.library)
            self.assertEqual(raised.exception.stage, "import")
            self.assertTrue(str(raised.exception).strip())
            if diagnostic is not None:
                self.assertIn(diagnostic, str(raised.exception))
        self.assertEqual(source.read_bytes(), original)

    def reject_before_import(self, body, stages=("parse", "llvm-verify")):
        with self.assertRaises(importer.ImportFailure) as raised:
            self.import_ir(body)
        self.assertIn(raised.exception.stage, stages)
        self.assertTrue(str(raised.exception).strip())

    def assert_contract(self, module, symbol, site, index, name, suffix=None):
        text = "\n".join(module["provenance"]["refinements"])
        prefix = f"{symbol}: {site} attribute index {index}: validated {name}=0"
        self.assertIn(prefix, text)
        if suffix is not None:
            self.assertIn(prefix + suffix, text)
        self.assertIn("input_sha256", text)

    def raw_contracts(self, body):
        """Read explicit enum attributes without printing or inheriting them."""
        source = self.write(body)
        api = importer.LLVM(self.library, importer.PINNED_SHA256)
        data = source.read_bytes()
        context, module, message = api.ContextCreate(), importer.P(), importer.P()
        buffer = api.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"explicit-attributes")
        records = []
        names = {api.GetEnumAttributeKindForName(name.encode(), len(name)): name
                 for name in ("writable", "builtin", "nobuiltin", "returned", "signext", "zeroext")}

        def read(owner, symbol, site, index):
            call = site == "callsite"
            count = (api.GetCallSiteAttributeCount if call else api.GetAttributeCountAtIndex)(owner, index)
            attributes = (importer.P * count)()
            (api.GetCallSiteAttributes if call else api.GetAttributesAtIndex)(owner, index, attributes)
            for attribute in attributes:
                if api.IsEnumAttribute(attribute):
                    name = names.get(api.GetEnumAttributeKind(attribute))
                    if name is not None:
                        records.append((symbol, site, index, name, api.GetEnumAttributeValue(attribute)))

        try:
            status = api.ParseIRInContext2(context, buffer, C.byref(module), C.byref(message))
            self.assertEqual(status, 0, C.string_at(message).decode() if message else "parse failed")
            if message:
                api.DisposeMessage(message)
                message = importer.P()
            status = api.VerifyModule(module, 2, C.byref(message))
            self.assertEqual(status, 0, C.string_at(message).decode() if message else "verify failed")
            for function in api.sequence(api.GetFirstFunction, api.GetNextFunction, module):
                symbol = api.name(function)
                for index in [0xffffffff, 0, *range(1, api.CountParams(function) + 1)]:
                    read(function, symbol, "function", index)
                for block in api.sequence(api.GetFirstBasicBlock, api.GetNextBasicBlock, function):
                    for instruction in api.sequence(api.GetFirstInstruction, api.GetNextInstruction, block):
                        if api.GetInstructionOpcode(instruction) == 45:
                            for index in [0xffffffff, 0, *range(1, api.GetNumArgOperands(instruction) + 1)]:
                                read(instruction, symbol, "callsite", index)
        finally:
            if message:
                api.DisposeMessage(message)
            if module:
                api.DisposeModule(module)
            api.DisposeMemoryBuffer(buffer)
            api.ContextDispose(context)
        return records

    def test_writable_definitions_declarations_direct_and_indirect_calls_keep_all_effects_all_three_isas(self):
        body = """
@counter = global i64 0, align 8
declare void @observe(ptr writable dereferenceable(8))
declare void @unused(ptr writable dereferenceable_or_null(16))
define i64 @mutate(ptr writable dereferenceable(8) %out, i64 %value) {
  %old = load volatile i64, ptr %out, align 8
  %sum = add i64 %old, %value
  store volatile i64 %sum, ptr %out, align 8
  store i64 %sum, ptr @counter, align 8
  call void @observe(ptr writable dereferenceable(8) %out)
  ret i64 %sum
}
define i64 @direct(ptr %out, i64 %value) {
  %result = call i64 @mutate(ptr writable dereferenceable(8) %out, i64 %value)
  ret i64 %result
}
define i64 @indirect(ptr %callee, ptr %out, i64 %value) {
  %result = call i64 %callee(ptr writable dereferenceable_or_null(16) %out, i64 %value)
  ret i64 %result
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 5)
                    self.assertEqual(module["provenance"]["source_global_count"], 1)
                    self.assertEqual({fn["name"] for fn in module["functions"]},
                                     {"observe", "unused", "mutate", "direct", "indirect"})
                    for name in ("observe", "unused"):
                        self.assertIsNone(self.function(module, name)["entry"])
                        self.assertEqual(self.operations(self.function(module, name)), [])
                    mutate = self.function(module, "mutate")
                    ops = self.operations(mutate)
                    self.assertEqual([op["op"] for op in ops], ["load", "binary", "store", "store", "call"])
                    self.assertTrue(ops[0]["volatile"])
                    self.assertTrue(ops[2]["volatile"])
                    self.assertEqual(ops[3]["pointer"]["kind"], "symbol")
                    self.assertEqual(ops[3]["pointer"]["name"], "counter")
                    self.assertEqual(ops[4]["callee"]["kind"], "symbol")
                    self.assertEqual(ops[4]["callee"]["name"], "observe")
                    self.assertEqual(ops[2]["value"], mutate["blocks"][0]["terminator"]["value"])
                    for name in ("direct", "indirect"):
                        function = self.function(module, name)
                        instructions = self.instructions(function)
                        self.assertEqual(len(instructions), 1)
                        self.assertEqual(instructions[0]["operation"]["op"], "call")
                        self.assertEqual(function["blocks"][0]["terminator"]["value"],
                                         {"kind": "value", "id": instructions[0]["result"]["id"]})
                    for symbol, site, extent in (("observe", "function", "dereferenceable=8"),
                            ("unused", "function", "dereferenceable_or_null=16 if nonnull"),
                            ("mutate", "function", "dereferenceable=8"),
                            ("mutate", "callsite", "dereferenceable=8"),
                            ("direct", "callsite", "dereferenceable=8"),
                            ("indirect", "callsite", "dereferenceable_or_null=16 if nonnull")):
                        self.assert_contract(module, symbol, site, 1, "writable",
                                             f" entry-only memory permission ({extent})")
                    self.assertEqual(ops[4]["signature"]["param_attributes"], [[]])

    def test_writable_without_extent_nullable_entry_and_initializes_add_no_implicit_access(self):
        body = """
define void @bare(ptr writable %p) { ret void }
define void @nullable(ptr writable dereferenceable_or_null(8) %p) { ret void }
define void @initialized(ptr writable writeonly initializes((0, 8)) dereferenceable(8) %p) memory(argmem: write) {
  store i64 17, ptr %p, align 1
  ret void
}
define void @normal_store(ptr writable dead_on_unwind dereferenceable(8) %p) {
  store i64 29, ptr %p, align 1
  ret void
}
define void @null_caller() {
  call void @nullable(ptr writable dereferenceable_or_null(8) null)
  ret void
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 5)
                    for name in ("bare", "nullable"):
                        self.assertEqual(self.operations(self.function(module, name)), [])
                    self.assert_contract(module, "bare", "function", 1, "writable",
                                         " entry-only memory permission (no explicit dereferenceable prefix)")
                    self.assert_contract(module, "nullable", "function", 1, "writable",
                                         " entry-only memory permission (dereferenceable_or_null=8 if nonnull)")
                    for name, value in (("initialized", "17"), ("normal_store", "29")):
                        operations = self.operations(self.function(module, name))
                        self.assertEqual([op["op"] for op in operations], ["store"])
                        self.assertEqual(operations[0]["value"]["bits"], value)
                    caller = self.operations(self.function(module, "null_caller"))
                    self.assertEqual([op["op"] for op in caller], ["call"])
                    self.assertEqual(caller[0]["args"], [{"kind": "null", "ty":
                        self.function(module, "nullable")["signature"]["params"][0]}])
                    text = "\n".join(module["provenance"]["refinements"])
                    self.assertIn("no entry access, speculative store, runtime guard", text)
                    self.assertIn("not an ABI extension", text)

    def test_writable_invalid_placement_read_contracts_and_address_spaces_remain_rejected(self):
        cases = {
            "integer": "declare void @bad(i64 writable)\n",
            "result": "declare writable ptr @bad()\n",
            "function": "declare void @bad(ptr) writable\n",
            "readonly": "declare void @bad(ptr writable readonly)\n",
            "readnone": "declare void @bad(ptr writable readnone)\n",
            "no writes": "declare void @bad(ptr writable) memory(none)\n",
            "read-only argmem": "declare void @bad(ptr writable) memory(argmem: read)\n",
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                self.reject_before_import(body)
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                self.reject_verified("declare void @unused(ptr addrspace(1) writable)\n", triple=triple)
                self.reject_verified('declare void @unused(ptr "writable")\n',
                                     diagnostic="unsupported string attribute writable", triple=triple)

    def test_builtin_direct_declared_defined_and_combined_nobuiltin_calls_stay_ordinary_all_three_isas(self):
        body = """
@counter = global i64 0, align 8
declare i64 @dependency(i64) nobuiltin
define i64 @malloc(i64 %value) nobuiltin {
  %sum = add i64 %value, 17
  store volatile i64 %sum, ptr @counter, align 8
  ret i64 %sum
}
define i64 @entry(i64 %value) {
  %defined = call i64 @malloc(i64 %value) builtin
  %declared = call i64 @dependency(i64 %defined) builtin nobuiltin
  %again = call i64 @malloc(i64 %declared) nobuiltin
  ret i64 %again
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 3)
                    self.assertEqual(module["provenance"]["source_global_count"], 1)
                    self.assertIsNone(self.function(module, "dependency")["entry"])
                    self.assertIsNone(self.function(module, "malloc")["intrinsic"])
                    malloc_ops = self.operations(self.function(module, "malloc"))
                    self.assertEqual([op["op"] for op in malloc_ops], ["binary", "store"])
                    self.assertEqual(malloc_ops[0]["rhs"]["bits"], "17")
                    self.assertTrue(malloc_ops[1]["volatile"])
                    entry = self.function(module, "entry")
                    instructions = self.instructions(entry)
                    self.assertEqual([instruction["operation"]["op"] for instruction in instructions], ["call"] * 3)
                    self.assertEqual([instruction["operation"]["callee"]["name"] for instruction in instructions],
                                     ["malloc", "dependency", "malloc"])
                    self.assertEqual(entry["blocks"][0]["terminator"]["value"],
                                     {"kind": "value", "id": instructions[-1]["result"]["id"]})
                    for callee in ("malloc", "dependency"):
                        self.assert_contract(module, "entry", "callsite function", 0xffffffff, "builtin",
                                             f" direct callee {callee} with underlying nobuiltin=0")
                    self.assertIn("no builtin replacement or intrinsic admission",
                                  "\n".join(module["provenance"]["refinements"]))

    def test_builtin_verified_calls_without_exact_direct_nobuiltin_callee_reject(self):
        cases = {
            "unmarked declaration": "declare i64 @target(i64)\ndefine i64 @entry(i64 %v) { %r = call i64 @target(i64 %v) builtin ret i64 %r }\n",
            "unmarked definition": "define i64 @target(i64 %v) { ret i64 %v }\ndefine i64 @entry(i64 %v) { %r = call i64 @target(i64 %v) builtin ret i64 %r }\n",
            "alias": "@alias = alias i64 (i64), ptr @target\ndefine i64 @target(i64 %v) nobuiltin { ret i64 %v }\ndefine i64 @entry(i64 %v) { %r = call i64 @alias(i64 %v) builtin ret i64 %r }\n",
            "indirect": "define i64 @entry(ptr %callee, i64 %v) { %r = call i64 %callee(i64 %v) builtin ret i64 %r }\n",
            "string callee marker": 'declare i64 @target(i64) "nobuiltin"\ndefine i64 @entry(i64 %v) { %r = call i64 @target(i64 %v) builtin ret i64 %r }\n',
            "string call marker": 'declare i64 @target(i64) nobuiltin\ndefine i64 @entry(i64 %v) { %r = call i64 @target(i64 %v) "builtin" ret i64 %r }\n',
        }
        for triple in TRIPLES:
            for label, body in cases.items():
                with self.subTest(triple=triple, case=label):
                    self.reject_verified(body, triple=triple)
        for body in ("declare i64 @bad(i64) builtin\n",
                     "define i64 @bad(i64 %v) builtin { ret i64 %v }\n",
                     "declare builtin i64 @bad()\n",
                     "declare void @bad(ptr builtin)\n"):
            with self.subTest(placement=body):
                self.reject_before_import(body)

    def test_builtin_intrinsic_permission_does_not_expand_owned_intrinsic_scope(self):
        body = """
declare void @llvm.assume(i1)
define void @entry(i1 %condition) {
  call void @llvm.assume(i1 %condition) builtin
  ret void
}
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                self.reject_verified(body, "ordinary direct-call function attribute", triple)

    def test_returned_all_scalar_widths_pointer_and_nonfirst_parameter_preserve_actual_results_all_three_isas(self):
        definitions = ["@side_effect = global i64 0, align 8\n"]
        for width in (1, 8, 16, 32, 64):
            definitions.append(f"""
define i{width} @identity{width}(i64 %effect, i{width} returned %value) {{
  store volatile i64 %effect, ptr @side_effect, align 8
  %copy = add i{width} %value, 0
  ret i{width} %copy
}}
define i{width} @caller{width}(i64 %effect, i{width} %value) {{
  %actual = call i{width} @identity{width}(i64 %effect, i{width} returned %value)
  ret i{width} %actual
}}
""")
        definitions.append("""
define ptr @pointer_identity(ptr returned %value) {
  %copy = getelementptr i8, ptr %value, i64 0
  ret ptr %copy
}
define ptr @pointer_caller(ptr %value) {
  %actual = call ptr @pointer_identity(ptr returned %value)
  ret ptr %actual
}
""")
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip("".join(definitions), triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 12)
                    self.assertEqual(module["provenance"]["source_global_count"], 1)
                    for width in (1, 8, 16, 32, 64):
                        identity = self.function(module, f"identity{width}")
                        instructions = self.instructions(identity)
                        self.assertEqual([i["operation"]["op"] for i in instructions], ["store", "binary"])
                        self.assertTrue(instructions[0]["operation"]["volatile"])
                        self.assertEqual(identity["blocks"][0]["terminator"]["value"],
                                         {"kind": "value", "id": instructions[1]["result"]["id"]})
                        self.assert_contract(module, f"identity{width}", "function", 2, "returned")
                        self.assert_contract(module, f"caller{width}", "callsite", 2, "returned")
                        caller = self.function(module, f"caller{width}")
                        calls = self.instructions(caller)
                        self.assertEqual(len(calls), 1)
                        self.assertEqual(calls[0]["operation"]["op"], "call")
                        self.assertEqual(caller["blocks"][0]["terminator"]["value"],
                                         {"kind": "value", "id": calls[0]["result"]["id"]})
                        self.assertEqual(calls[0]["operation"]["signature"], identity["signature"])
                        self.assertEqual(module["types"][identity["signature"]["result"]],
                                         {"kind": "int", "bits": width})
                    pointer = self.function(module, "pointer_identity")
                    instructions = self.instructions(pointer)
                    self.assertEqual([i["operation"]["op"] for i in instructions], ["gep"])
                    self.assertEqual(pointer["blocks"][0]["terminator"]["value"],
                                     {"kind": "value", "id": instructions[0]["result"]["id"]})
                    self.assert_contract(module, "pointer_identity", "function", 1, "returned")
                    self.assert_contract(module, "pointer_caller", "callsite", 1, "returned")

    def test_returned_optional_explicit_sites_aliases_and_indirect_calls_do_not_inherit_or_replace_results(self):
        body = """
@alias = alias i64 (i64), ptr @identity
declare i64 @external_identity(i64 returned)
declare i64 @callsite_only_target(i64)
define i64 @identity(i64 returned %value) { %copy = add i64 %value, 0 ret i64 %copy }
define i64 @direct_omitted(i64 %value) { %actual = call i64 @external_identity(i64 %value) ret i64 %actual }
define i64 @callsite_only(i64 %value) { %actual = call i64 @callsite_only_target(i64 returned %value) ret i64 %actual }
define i64 @alias_omitted(i64 %value) { %actual = call i64 @alias(i64 %value) ret i64 %actual }
define i64 @alias_explicit(i64 %value) { %actual = call i64 @alias(i64 returned %value) ret i64 %actual }
define i64 @indirect_omitted(ptr %callee, i64 %value) { %actual = call i64 %callee(i64 %value) ret i64 %actual }
define i64 @indirect_explicit(ptr %callee, i64 %value) { %actual = call i64 %callee(i64 returned %value) ret i64 %actual }
define i64 @two_params(i64 returned %a, i64 %b) { ret i64 %a }
define i64 @different_explicit_index(i64 %same) { %actual = call i64 @two_params(i64 %same, i64 returned %same) ret i64 %actual }
"""
        raw = self.raw_contracts(body)
        for symbol in ("direct_omitted", "alias_omitted", "indirect_omitted"):
            self.assertFalse(any(record[0] == symbol and record[1] == "callsite" and record[3] == "returned"
                                 for record in raw), "the C API must not invent inherited callsite attributes")
        self.assertIn(("different_explicit_index", "callsite", 2, "returned", 0), raw)
        self.assertIn(("two_params", "function", 1, "returned", 0), raw)
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 11)
                    self.assertEqual(module["provenance"]["source_alias_count"], 1)
                    refinements = "\n".join(module["provenance"]["refinements"])
                    for symbol in ("direct_omitted", "alias_omitted", "indirect_omitted"):
                        self.assertNotIn(f"{symbol}: callsite attribute index 1: validated returned", refinements)
                    for symbol in ("callsite_only", "alias_explicit", "indirect_explicit"):
                        self.assert_contract(module, symbol, "callsite", 1, "returned")
                    self.assert_contract(module, "different_explicit_index", "callsite", 2, "returned")
                    for symbol in ("direct_omitted", "callsite_only", "alias_omitted", "alias_explicit",
                                   "indirect_omitted", "indirect_explicit", "different_explicit_index"):
                        function = self.function(module, symbol)
                        calls = self.instructions(function)
                        self.assertEqual(len(calls), 1)
                        self.assertEqual(calls[0]["operation"]["op"], "call")
                        self.assertEqual(function["blocks"][0]["terminator"]["value"],
                                         {"kind": "value", "id": calls[0]["result"]["id"]})
                    callee = self.operations(self.function(module, "alias_explicit"))[0]["callee"]
                    self.assertEqual(callee["kind"], "symbol")
                    self.assertEqual(callee["name"], "alias")

    def test_returned_preserves_independent_signext_zeroext_and_exposes_abi_mismatches_to_native_verification(self):
        body = """
define signext i8 @identity(i8 zeroext returned %value) { %copy = add i8 %value, 0 ret i8 %copy }
define signext i8 @caller(i8 zeroext %value) { %actual = call signext i8 @identity(i8 zeroext returned %value) ret i8 %actual }
"""
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(body, triple):
                    identity = self.function(module, "identity")
                    self.assertEqual(identity["signature"]["result_attributes"], ["signext"])
                    self.assertEqual(identity["signature"]["param_attributes"], [["zeroext"]])
                    call = self.operations(self.function(module, "caller"))[0]
                    self.assertEqual(call["signature"], identity["signature"])
                    self.assert_contract(module, "identity", "function", 1, "returned")
                    self.assert_contract(module, "caller", "callsite", 1, "returned")
                for incorrect, expected_params, expected_result in (
                        (body.replace("call signext i8", "call i8"), [["zeroext"]], []),
                        (body.replace("i8 zeroext returned %value) ret", "i8 returned %value) ret"), [[]], ["signext"])):
                    # Import keeps both explicit signatures. Mandatory native
                    # verification owns direct-callee signature rejection; it
                    # must receive the mismatch rather than a stripped ABI.
                    for module in self.roundtrip(incorrect, triple):
                        identity = self.function(module, "identity")
                        call = self.operations(self.function(module, "caller"))[0]
                        self.assertEqual(call["signature"]["param_attributes"], expected_params)
                        self.assertEqual(call["signature"]["result_attributes"], expected_result)
                        self.assertNotEqual(call["signature"], identity["signature"])
                        self.assert_contract(module, "caller", "callsite", 1, "returned")

    def test_returned_invalid_counts_types_placements_and_unsupported_pointer_abi_reject(self):
        for label, body in {
            "duplicate": "declare i64 @bad(i64 returned, i64 returned)\n",
            "different integer width": "declare i64 @bad(i32 returned)\n",
            "void result": "declare void @bad(ptr returned)\n",
            "result attribute": "declare returned i64 @bad(i64)\n",
            "function attribute": "declare i64 @bad(i64) returned\n",
            "different callsite width": "declare i64 @target(i32)\ndefine i64 @bad(i32 %p) { %r = call i64 @target(i32 returned %p) ret i64 %r }\n",
            "duplicate callsite": "declare i64 @target(i64, i64)\ndefine i64 @bad(i64 %p) { %r = call i64 @target(i64 returned %p, i64 returned %p) ret i64 %r }\n",
        }.items():
            with self.subTest(case=label):
                self.reject_before_import(body)
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                self.reject_verified("declare ptr addrspace(1) @unused(ptr addrspace(1) returned)\n", triple=triple)
                self.reject_verified("declare ptr @unused(ptr returned byval(i64))\n", triple=triple)
                self.reject_verified('declare ptr @unused(ptr "returned")\n', triple=triple)

    def test_explicit_enum_zero_payloads_and_optional_callsite_contracts_match_real_c_api(self):
        body = """
declare ptr @identity(ptr returned writable dereferenceable(8)) nobuiltin
define ptr @omitted(ptr %p) { %r = call ptr @identity(ptr %p) ret ptr %r }
define ptr @explicit(ptr %p) { %r = call ptr @identity(ptr returned writable dereferenceable(8) %p) builtin ret ptr %r }
"""
        records = self.raw_contracts(body)
        self.assertEqual(set(records), {
            ("identity", "function", 0xffffffff, "nobuiltin", 0),
            ("identity", "function", 1, "returned", 0),
            ("identity", "function", 1, "writable", 0),
            ("explicit", "callsite", 0xffffffff, "builtin", 0),
            ("explicit", "callsite", 1, "returned", 0),
            ("explicit", "callsite", 1, "writable", 0),
        })
        for module in self.roundtrip(body):
            self.assert_contract(module, "identity", "function", 1, "writable")
            self.assert_contract(module, "identity", "function", 1, "returned")
            self.assert_contract(module, "explicit", "callsite", 1, "writable")
            self.assert_contract(module, "explicit", "callsite", 1, "returned")
            self.assert_contract(module, "explicit", "callsite function", 0xffffffff, "builtin")
            refinements = "\n".join(module["provenance"]["refinements"])
            self.assertNotIn("omitted: callsite attribute index 1: validated returned", refinements)
            self.assertNotIn("omitted: callsite attribute index 1: validated writable", refinements)
            callee = self.operations(self.function(module, "omitted"))[0]["callee"]
            self.assertEqual(callee["kind"], "symbol")
            self.assertEqual(callee["name"], "identity")

    def test_unused_unsupported_entities_still_reject_the_complete_unit_all_three_isas(self):
        supported = """
declare ptr @identity(ptr returned writable dereferenceable(8)) nobuiltin
define ptr @entry(ptr %p) { %r = call ptr @identity(ptr writable returned dereferenceable(8) %p) builtin ret ptr %r }
"""
        additions = {
            "unused floating body": "define double @unused(double %x) { ret double %x }\n",
            "unused wide sret storage": "declare void @unused(ptr writable sret(i128))\n",
            "unused byval": "declare ptr @unused(ptr returned byval(i64))\n",
            "unused inalloca": "declare void @unused(ptr writable inalloca(i64))\n",
            "unused DLL": "declare dllimport ptr @unused(ptr returned)\n",
            "unused GC": 'define ptr @unused(ptr returned %p) gc "statepoint-example" { ret ptr %p }\n',
        }
        for triple in TRIPLES:
            for label, addition in additions.items():
                with self.subTest(triple=triple, case=label):
                    self.reject_verified(supported + addition, triple=triple)

    def test_clang22_original_complete_returned_c_units_import_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "ordinary.c"
        source.write_text("""
volatile unsigned long effects;
extern void observe(unsigned long *);
__attribute__((noinline)) unsigned long *identity(unsigned long *p, unsigned long value) {
  *p = value;
  effects = value;
  observe(p);
  return p;
}
__attribute__((noinline)) unsigned long *direct(unsigned long *p, unsigned long value) {
  return identity(p, value);
}
__attribute__((noinline)) unsigned long *indirect(unsigned long *(*fn)(unsigned long *, unsigned long),
                                                unsigned long *p, unsigned long value) {
  return fn(p, value);
}
""")
        original = source.read_bytes()
        expected = {"identity", "direct", "indirect", "observe"}
        for triple in TRIPLES:
            with self.subTest(triple=triple, frontend=version):
                text = self.compile_clang(clang, source, triple, "ll")
                produced = text.read_text()
                self.assertRegex(produced, r"define\b[^\n]*@identity\(ptr\b[^,\n]*\breturned\b")
                inventory = dict((name, kind) for kind, name in re.findall(
                    r"^(define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", produced, re.MULTILINE))
                self.assertEqual(set(inventory), expected)
                globals_ = set(re.findall(r"^@([A-Za-z_][A-Za-z0-9_.$]*)\s*=", produced, re.MULTILINE))
                self.assertEqual(globals_, {"effects"})
                modules = []
                for path in (text, self.compile_clang(clang, source, triple, "bc")):
                    captured = path.read_bytes()
                    module = importer.import_module(path, library_path=self.library)
                    modules.append(module)
                    self.assertEqual(path.read_bytes(), captured)
                    self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(captured).hexdigest())
                    self.assertEqual({fn["name"] for fn in module["functions"]}, expected)
                    self.assertEqual(module["provenance"]["source_function_count"], 4)
                    self.assertEqual(module["provenance"]["source_global_count"], 1)
                    self.assert_contract(module, "identity", "function", 1, "returned")
                    identity_ops = self.operations(self.function(module, "identity"))
                    self.assertEqual([op["op"] for op in identity_ops], ["store", "store", "call"])
                    self.assertTrue(identity_ops[1]["volatile"])
                    self.assertEqual(identity_ops[2]["callee"]["kind"], "symbol")
                    self.assertEqual(identity_ops[2]["callee"]["name"], "observe")
                    for name in ("direct", "indirect"):
                        self.assertEqual([op["op"] for op in self.operations(self.function(module, name))], ["call"])
                self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                                 {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})
        self.assertEqual(source.read_bytes(), original)

    def test_clang22_original_writable_sret_and_unused_float_units_preserve_complete_units_all_three_isas(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        sources = {
            "writable_sret": "struct Big { unsigned long words[8]; };\nvoid observe(struct Big *);\nstruct Big original(void) { struct Big result = {{1, 2, 3, 4, 5, 6, 7, 8}}; observe(&result); return result; }\n",
            "unused_float": "unsigned long *identity(unsigned long *p) { return p; }\ndouble untouched_unused(double x) { return x; }\n",
        }
        for label, body in sources.items():
            source = self.directory / f"{label}.c"
            source.write_text(body)
            original = source.read_bytes()
            for triple in TRIPLES:
                with self.subTest(case=label, triple=triple, frontend=version):
                    text = self.compile_clang(clang, source, triple, "ll")
                    produced = text.read_text()
                    if label == "writable_sret":
                        self.assertIn("sret(", produced)
                        self.assertIn("writable", produced)
                    else:
                        self.assertRegex(produced, r"define\b[^\n]*double @untouched_unused\(")
                    modules = []
                    for path in (text, self.compile_clang(clang, source, triple, "bc")):
                        captured = path.read_bytes()
                        if label == "writable_sret":
                            module = importer.import_module(path, library_path=self.library)
                            modules.append(module)
                            self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(captured).hexdigest())
                            inventory = set(re.findall(r"^(?:define|declare)\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", produced, re.MULTILINE))
                            self.assertEqual({fn["name"] for fn in module["functions"]}, inventory)
                            self.assertEqual(module["provenance"]["source_function_count"], len(inventory))
                            signature = self.function(module, "original")["signature"]
                            storage = signature["return_storage"]
                            self.assertEqual(storage["param"], 0)
                            self.assertEqual(module["types"][signature["result"]], {"kind": "void"})
                            self.assertEqual(module["types"][signature["params"][0]], {"kind": "pointer", "address_space": 0})
                            payload = module["types"][storage["ty"]]
                            self.assertEqual(payload["kind"], "struct")
                            self.assertEqual(len(payload["fields"]), 1)
                            array = module["types"][payload["fields"][0]]
                            self.assertEqual(array["kind"], "array")
                            self.assertEqual(array["len"], 8)
                            self.assertEqual(module["types"][array["element"]], {"kind": "int", "bits": 64})
                            self.assertTrue(any(op["op"] == "call" and op["callee"].get("name") == "observe"
                                                for op in self.operations(self.function(module, "original"))))
                        else:
                            with self.assertRaises(importer.ImportFailure) as raised:
                                importer.import_module(path, library_path=self.library)
                            self.assertEqual(raised.exception.stage, "import")
                            self.assertEqual(raised.exception.symbol, "untouched_unused")
                        self.assertEqual(path.read_bytes(), captured)
                    if modules:
                        self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                                         {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})
            self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
