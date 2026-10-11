"""Keep all scalar integer widths, layouts and producer ABI coercions intact."""

import hashlib
from itertools import product
from pathlib import Path
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


TRIPLES = baseline.TRIPLES
WIDTHS = range(1, 65)


class LlvmIntegerWidthImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-llvm-integer-width-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "input.ll"

    write = memory.LlvmMemoryImportTests.write
    bitcode = memory.LlvmMemoryImportTests.bitcode
    function = staticmethod(memory.LlvmMemoryImportTests.function)
    instructions = staticmethod(memory.LlvmMemoryImportTests.instructions)
    operations = classmethod(memory.LlvmMemoryImportTests.operations.__func__)
    compile_clang = memory.LlvmMemoryImportTests.compile_clang

    @staticmethod
    def clang_flags():
        return ["-std=c23", *memory.LlvmMemoryImportTests.clang_flags()]

    def roundtrip(self, body, triple):
        text = self.write(body, triple)
        binary = self.bitcode(text)
        modules = [importer.import_module(path, library_path=self.library) for path in (text, binary)]
        self.assertEqual({key: value for key, value in modules[0].items() if key not in {"name", "provenance"}},
                         {key: value for key, value in modules[1].items() if key not in {"name", "provenance"}})
        for path, module in zip((text, binary), modules):
            self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(module["target"]["triple"], triple)
            self.assertTrue(all(1 <= ty["bits"] <= 64 for ty in module["types"] if ty["kind"] == "int"))
        return modules

    def assert_integer(self, module, ident, width):
        self.assertEqual(module["types"][ident], {"kind": "int", "bits": width})

    def assert_inventory(self, module, functions, globals_, aliases):
        self.assertEqual({fn["name"] for fn in module["functions"]}, functions)
        self.assertEqual({glob["name"] for glob in module["globals"]}, globals_)
        self.assertEqual({alias["name"] for alias in module["aliases"]}, aliases)
        for name, expected in (("function", len(functions)), ("global", len(globals_)), ("alias", len(aliases))):
            self.assertEqual(module["provenance"]["source_" + name + "_count"], expected)

    @staticmethod
    def allocation(width):
        # Explicit fixture layout uses the normal integer ABI alignments:
        # i1..8 -> 1, i9..16 -> 2, i17..32 -> 4, i33..64 -> 8 bytes.
        return 1 if width <= 8 else 2 if width <= 16 else 4 if width <= 32 else 8

    def test_every_width_keeps_ssa_control_flow_constants_aliases_and_relocation_inventory_all_three_isas_text_and_bitcode(self):
        parts = []
        for width in WIDTHS:
            parts.append(f"""
declare i{width} @unused_{width}(i{width})
@function_alias_{width} = alias i{width}(i{width}, i{width}, i1), ptr @ssa_{width}
define i{width} @ssa_{width}(i{width} %value, i{width} %other, i1 %take) {{
entry:
  %sum = add i{width} %value, %other
  %masked = xor i{width} %sum, -1
  %compare = icmp ult i{width} %value, %other
  %chosen = select i1 %take, i{width} %masked, i{width} %value
  br i1 %compare, label %left, label %right
left:
  %wrapped = sub i{width} %chosen, 1
  br label %join
right:
  %product = mul i{width} %value, %other
  br label %join
join:
  %incoming = phi i{width} [ %wrapped, %left ], [ %product, %right ]
  %stable = freeze i{width} %incoming
  ret i{width} %stable
}}
""")
        parts.append("@addresses = global [64 x ptr] [" + ", ".join(f"ptr @function_alias_{width}" for width in WIDTHS) + "]\n")
        for triple in TRIPLES:
            for module in self.roundtrip("".join(parts), triple):
                self.assert_inventory(module, {f"{prefix}_{width}" for prefix in ("ssa", "unused") for width in WIDTHS},
                                      {"addresses"}, {f"function_alias_{width}" for width in WIDTHS})
                self.assertEqual({ty["bits"] for ty in module["types"] if ty["kind"] == "int"}, set(WIDTHS))
                aliases = {alias["name"]: alias for alias in module["aliases"]}
                for width in WIDTHS:
                    with self.subTest(triple=triple, width=width):
                        function = self.function(module, f"ssa_{width}")
                        self.assert_integer(module, function["signature"]["result"], width)
                        self.assertEqual([module["types"][param["ty"]]["bits"] for param in function["params"]], [width, width, 1])
                        self.assertIsNone(self.function(module, f"unused_{width}")["entry"])
                        self.assertEqual(aliases[f"function_alias_{width}"]["aliasee"], f"ssa_{width}")
                        instructions = self.instructions(function)
                        self.assertEqual([inst["operation"]["op"] for inst in instructions],
                                         ["binary", "binary", "i_cmp", "select", "binary", "binary", "phi", "freeze"])
                        self.assertEqual([inst["operation"]["kind"] for inst in instructions if inst["operation"]["op"] == "binary"],
                                         ["add", "xor", "sub", "mul"])
                        self.assertEqual(instructions[1]["operation"]["rhs"]["bits"], str((1 << width) - 1))
                        self.assert_integer(module, instructions[2]["result"]["ty"], 1)
                        for inst in instructions[:2] + instructions[3:]:
                            self.assert_integer(module, inst["result"]["ty"], width)
                        self.assertEqual(len(instructions[6]["operation"]["incoming"]), 2)
                        self.assertEqual(function["blocks"][-1]["terminator"]["value"],
                                         {"kind": "value", "id": instructions[-1]["result"]["id"]})
                self.assertEqual(module["globals"][0]["initializer"]["relocations"],
                                 [{"offset": 8 * (width - 1), "width": 64, "symbol": f"function_alias_{width}", "addend": 0}
                                  for width in WIDTHS])

    def test_integer_store_footprints_and_allocation_strides_stay_distinct_in_globals_arrays_structs_allocas_and_geps_all_three_isas(self):
        parts = []
        for width in WIDTHS:
            allocation = self.allocation(width)
            parts.append(f"""
@scalar_{width} = global i{width} -1
@array_{width} = global [2 x i{width}] [i{width} -1, i{width} 1]
@record_{width} = global {{i8, i{width}, i8}} {{i8 85, i{width} -1, i8 102}}
@packed_{width} = global <{{i8, i{width}, i8}}> <{{i8 85, i{width} -1, i8 102}}>
@data_alias_{width} = alias i{width}, ptr @scalar_{width}
define ptr @address_{width}() {{ ret ptr getelementptr (i{width}, ptr @data_alias_{width}, i64 1) }}
define i{width} @memory_{width}(i{width} %value, ptr %destination) {{
  %slot = alloca i{width}, i64 2, align {allocation}
  store volatile i{width} %value, ptr %slot, align {allocation}
  %loaded = load volatile i{width}, ptr %slot, align {allocation}
  store volatile i{width} %loaded, ptr %destination, align 1
  ret i{width} %loaded
}}
""")
        for triple in TRIPLES:
            for module in self.roundtrip("".join(parts), triple):
                self.assert_inventory(module, {f"{prefix}_{width}" for prefix in ("address", "memory") for width in WIDTHS},
                                      {f"{prefix}_{width}" for prefix in ("scalar", "array", "record", "packed") for width in WIDTHS},
                                      {f"data_alias_{width}" for width in WIDTHS})
                globals_ = {glob["name"]: glob for glob in module["globals"]}
                for width in WIDTHS:
                    with self.subTest(triple=triple, width=width):
                        store_size, allocation = (width + 7) // 8, self.allocation(width)
                        integer = list(((1 << width) - 1).to_bytes(store_size, "little"))
                        allocated = integer + [0] * (allocation - store_size)
                        expected = {
                            "scalar": allocated,
                            "array": allocated + [1] + [0] * (allocation - 1),
                            "record": [85] + [0] * (allocation - 1) + allocated + [102] + [0] * (allocation - 1),
                            "packed": [85] + allocated + [102],
                        }
                        for prefix, data in expected.items():
                            global_ = globals_[f"{prefix}_{width}"]
                            self.assertEqual(global_["initializer"], {"bytes": data, "relocations": []})
                            self.assertEqual(global_["alignment"], 1 if prefix == "packed" else allocation)
                        self.assert_integer(module, globals_[f"scalar_{width}"]["ty"], width)
                        address = self.function(module, f"address_{width}")["blocks"][0]["terminator"]["value"]
                        self.assertEqual(address["kind"], "symbol_offset")
                        self.assertEqual((address["name"], address["addend"]), (f"data_alias_{width}", allocation))
                        instructions = self.instructions(self.function(module, f"memory_{width}"))
                        self.assertEqual(instructions[0]["operation"], {"op": "alloca", "size": 2 * allocation, "alignment": allocation})
                        self.assertEqual([inst["operation"]["op"] for inst in instructions], ["alloca", "store", "load", "store"])
                        self.assertTrue(all(inst["operation"]["volatile"] for inst in instructions[1:]))
                        self.assert_integer(module, instructions[2]["result"]["ty"], width)

    def test_every_width_preserves_all_four_scalar_extension_abi_pairs_on_definitions_declarations_alias_and_direct_indirect_calls_all_three_isas(self):
        parts, functions, aliases = [], set(), set()
        for width in WIDTHS:
            for result, parameter in product(("signext", "zeroext"), repeat=2):
                suffix = f"{width}_{result}_{parameter}"
                functions.update(f"{prefix}_{suffix}" for prefix in ("target", "external", "caller"))
                aliases.add(f"alias_{suffix}")
                parts.append(f"""
declare {result} i{width} @external_{suffix}(i{width} {parameter})
define {result} i{width} @target_{suffix}(i{width} {parameter} %value) {{ ret i{width} %value }}
@alias_{suffix} = alias i{width}(i{width}), ptr @target_{suffix}
define {result} i{width} @caller_{suffix}(ptr %function, i{width} {parameter} %value) {{
  %first = call {result} i{width} @alias_{suffix}(i{width} {parameter} %value)
  %second = call {result} i{width} @external_{suffix}(i{width} {parameter} %first)
  %third = call {result} i{width} %function(i{width} {parameter} %second)
  ret i{width} %third
}}
""")
        for triple in TRIPLES:
            for module in self.roundtrip("".join(parts), triple):
                self.assert_inventory(module, functions, set(), aliases)
                for width in WIDTHS:
                    for result, parameter in product(("signext", "zeroext"), repeat=2):
                        suffix = f"{width}_{result}_{parameter}"
                        with self.subTest(triple=triple, width=width, result=result, parameter=parameter):
                            target = self.function(module, f"target_{suffix}")
                            signature = target["signature"]
                            self.assert_integer(module, signature["result"], width)
                            self.assert_integer(module, signature["params"][0], width)
                            self.assertEqual(signature["result_attributes"], [result])
                            self.assertEqual(signature["param_attributes"], [[parameter]])
                            self.assertEqual(signature, self.function(module, f"external_{suffix}")["signature"])
                            calls = self.operations(self.function(module, f"caller_{suffix}"))
                            self.assertEqual([call["op"] for call in calls], ["call", "call", "call"])
                            self.assertTrue(all(call["signature"] == signature for call in calls))
                            self.assertEqual(calls[0]["callee"]["name"], f"alias_{suffix}")
                            self.assertEqual(calls[1]["callee"]["name"], f"external_{suffix}")
                            self.assertEqual(calls[2]["callee"]["kind"], "value")

    def test_every_integer_width_retains_cast_widths_and_signed_constant_bit_patterns_all_three_isas(self):
        parts, names = [], set()
        for width in WIDTHS:
            for name, literal in (("maximum", -1), ("minimum", -(1 << (width - 1)))):
                names.add(f"{name}_{width}")
                parts.append(f"define i{width} @{name}_{width}() {{ ret i{width} {literal} }}\n")
            if width < 64:
                for name, operation in (("signed", "sext"), ("unsigned", "zext")):
                    names.add(f"{name}_{width}")
                    parts.append(f"define i64 @{name}_{width}(i{width} %value) {{ %wide = {operation} i{width} %value to i64\nret i64 %wide }}\n")
                names.add(f"truncate_{width}")
                parts.append(f"define i{width} @truncate_{width}(i64 %value) {{ %narrow = trunc i64 %value to i{width}\nret i{width} %narrow }}\n")
        for triple in TRIPLES:
            for module in self.roundtrip("".join(parts), triple):
                self.assert_inventory(module, names, set(), set())
                for width in WIDTHS:
                    for name, bits in (("maximum", (1 << width) - 1), ("minimum", 1 << (width - 1))):
                        function = self.function(module, f"{name}_{width}")
                        operand = function["blocks"][0]["terminator"]["value"]
                        self.assertEqual(operand["kind"], "int")
                        self.assertEqual(operand["bits"], str(bits))
                        self.assert_integer(module, operand["ty"], width)
                    if width < 64:
                        for name, kind, source, result in (("signed", "s_ext", width, 64), ("unsigned", "z_ext", width, 64), ("truncate", "trunc", 64, width)):
                            function = self.function(module, f"{name}_{width}")
                            instructions = self.instructions(function)
                            self.assertEqual(len(instructions), 1)
                            self.assertEqual(instructions[0]["operation"]["kind"], kind)
                            self.assert_integer(module, function["params"][0]["ty"], source)
                            self.assert_integer(module, instructions[0]["result"]["ty"], result)

    def test_verified_width_65_rejects_whole_source_modules_at_import_even_when_unused_all_three_isas_text_and_bitcode(self):
        cases = [
            ("declare i65 @unsupported(i65)\n", "unsupported"),
            ("define i65 @unsupported(i65 %value) { ret i65 %value }\n", "unsupported"),
            ("@unsupported = global i65 1\n", "unsupported"),
            ("@unsupported = global [2 x i65] zeroinitializer\n", "unsupported"),
            ("@unsupported = global {i8, i65} zeroinitializer\n", "unsupported"),
        ]
        for triple in TRIPLES:
            for body, symbol in cases:
                source = self.write("define i64 @supported() { ret i64 7 }\n" + body, triple)
                for path in (source, self.bitcode(source)):
                    with self.subTest(triple=triple, format=path.suffix, body=body):
                        with self.assertRaises(importer.ImportFailure) as raised:
                            importer.import_module(path, library_path=self.library)
                        self.assertEqual(raised.exception.stage, "import")
                        self.assertEqual(raised.exception.symbol, symbol)
                        self.assertIn("unsupported integer width i65", str(raised.exception))

    @staticmethod
    def bitint_source():
        parts = []
        for width in WIDTHS:
            parts.append(f'''typedef unsigned _BitInt({width}) U{width};
U{width} unsigned_global_{width} = (U{width})-1;
U{width} unsigned_array_{width}[2] = {{ (U{width})-1, 1 }};
extern U{width} external_{width}(U{width});
U{width} unsigned_{width}(U{width} value) {{ return value + (U{width})1; }}
U{width} caller_{width}(U{width} value) {{ return external_{width}(value); }}
extern U{width} alias_{width}(U{width}) __attribute__((alias("unsigned_{width}")));
''')
            if width >= 2:
                parts.append(f'''typedef signed _BitInt({width}) S{width};
S{width} signed_{width}(S{width} value) {{ return value ^ (S{width})-1; }}
''')
        return "".join(parts)

    @staticmethod
    def producer_abi(triple, width, signed=False):
        if triple.startswith("aarch64-"):
            return width, []
        if triple.startswith("x86_64-"):
            return (width, ["signext" if signed else "zeroext"]) if width < 32 else (32 if width == 32 else 64, [])
        return width, ["signext" if signed or width == 32 else "zeroext"]

    def test_actual_clang22_c23_all_bitint_widths_keep_complete_units_original_abi_coercions_and_storage_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "all-bitint-widths.c"
        source.write_text(self.bitint_source())
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        expected_functions = {f"{prefix}_{width}" for prefix in ("unsigned", "caller", "external") for width in WIDTHS}
        expected_functions.update(f"signed_{width}" for width in range(2, 65))
        for triple in TRIPLES:
            imported = []
            for suffix in ("ll", "bc"):
                with self.subTest(triple=triple, format=suffix):
                    path = self.compile_clang(clang, source, triple, suffix)
                    module = importer.import_module(path, library_path=self.library, frontend="Clang C23", frontend_version=version)
                    imported.append(module)
                    self.assertEqual(module["target"]["triple"], triple)
                    self.assertEqual(module["provenance"]["frontend_version"], version)
                    self.assertEqual(module["provenance"]["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)
                    self.assert_inventory(module, expected_functions,
                                          {f"{prefix}_{width}" for prefix in ("unsigned_global", "unsigned_array") for width in WIDTHS},
                                          {f"alias_{width}" for width in WIDTHS})
                    self.assertEqual(sum(fn["entry"] is not None for fn in module["functions"]), 191)
                    globals_ = {glob["name"]: glob for glob in module["globals"]}
                    aliases = {alias["name"]: alias for alias in module["aliases"]}
                    for width in WIDTHS:
                        with self.subTest(width=width):
                            abi_width, extension = self.producer_abi(triple, width)
                            for prefix in ("unsigned", "caller", "external"):
                                function = self.function(module, f"{prefix}_{width}")
                                signature = function["signature"]
                                self.assert_integer(module, signature["result"], abi_width)
                                self.assert_integer(module, signature["params"][0], abi_width)
                                self.assertEqual(signature["result_attributes"], extension)
                                self.assertEqual(signature["param_attributes"], [extension])
                            external = self.function(module, f"external_{width}")
                            self.assertIsNone(external["entry"])
                            calls = [op for op in self.operations(self.function(module, f"caller_{width}")) if op["op"] == "call"]
                            self.assertEqual(len(calls), 1)
                            self.assertEqual(calls[0]["callee"]["name"], f"external_{width}")
                            self.assertEqual(calls[0]["signature"], external["signature"])
                            self.assertTrue(self.operations(self.function(module, f"unsigned_{width}")))
                            if width >= 2:
                                signed = self.function(module, f"signed_{width}")
                                signed_width, signed_extension = self.producer_abi(triple, width, signed=True)
                                self.assert_integer(module, signed["signature"]["result"], signed_width)
                                self.assertEqual(signed["signature"]["result_attributes"], signed_extension)
                                self.assertEqual(signed["signature"]["param_attributes"], [signed_extension])
                                self.assertTrue(any(op["op"] == "binary" and op["kind"] == "xor" for op in self.operations(signed)))
                            alias = aliases[f"alias_{width}"]
                            self.assertEqual(alias["aliasee"], f"unsigned_{width}")
                            alias_signature = module["types"][alias["ty"]]["signature"]
                            self.assert_integer(module, alias_signature["result"], abi_width)
                            self.assert_integer(module, alias_signature["params"][0], abi_width)
                            allocation = self.allocation(width)
                            data = list(((1 << width) - 1).to_bytes(allocation, "little"))
                            global_ = globals_[f"unsigned_global_{width}"]
                            self.assert_integer(module, global_["ty"], allocation * 8)
                            self.assertEqual(global_["alignment"], allocation)
                            self.assertEqual(global_["initializer"], {"bytes": data, "relocations": []})
                            self.assertEqual(globals_[f"unsigned_array_{width}"]["initializer"],
                                             {"bytes": data + [1] + [0] * (allocation - 1), "relocations": []})
            self.assertEqual({key: value for key, value in imported[0].items() if key not in {"name", "provenance"}},
                             {key: value for key, value in imported[1].items() if key not in {"name", "provenance"}})

    def test_actual_clang22_c23_complete_bitint_unit_rejects_unused_wide_storage_without_dropping_it_all_three_isas_text_and_bitcode(self):
        clang, version = baseline.LlvmImportTests.clang22_frontend(self)
        source = self.directory / "all-bitint-widths-with-wide.c"
        source.write_text(self.bitint_source() + "unsigned _BitInt(65) unsupported_global = 1;\n")
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        for triple in TRIPLES:
            for suffix in ("ll", "bc"):
                with self.subTest(triple=triple, format=suffix):
                    path = self.compile_clang(clang, source, triple, suffix)
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(path, library_path=self.library, frontend="Clang C23", frontend_version=version)
                    self.assertEqual(raised.exception.stage, "import")
                    self.assertEqual(raised.exception.symbol, "unsupported_global")
                    self.assertRegex(str(raised.exception), r"unsupported integer width i(?:65|128)")
                    self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)


if __name__ == "__main__":
    unittest.main()
