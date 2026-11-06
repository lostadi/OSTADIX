"""Pure source-graph checks only: no LLVM API, NativeVerifier or target execution.

The tests compile the exact candidate method ASTs. Integer evaluation is a test
oracle for the lowering DAG, never an implementation-IR runtime or support claim.
Actual original-unit import, verification and ISA execution remain separate gates.
"""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WIDTHS = (16, 32, 48, 64, 128)


def deny(event, args):
    if event in ("subprocess.Popen", "os.system", "os.posix_spawn", "os.fork",
                 "os.posix_spawnp", "ctypes.dlopen", "os.exec"):
        raise RuntimeError("pure byte-swap controls forbid external dispatch")


sys.addaudithook(deny)
SOURCES = [ROOT / "scripts/ocore_llvm_import.py", ROOT / "tests/ocore_llvm_source_inventory.py",
           ROOT / "src/bin/olangc/native_runtime/source_inventory.py",
           ROOT / "crates/ostadix-api/src/ocore/native_verify.rs", Path(__file__)]


def pin(path):
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read_checked(path, expected):
    raw = path.read_bytes()
    if len(raw) != expected['bytes'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
        raise RuntimeError('actual consumed source buffer drift')
    return raw


BEFORE = [pin(path) for path in SOURCES]
COMPILED_SOURCE_BUFFERS = {str(path): read_checked(path, BEFORE[index])
                          for index, path in enumerate(SOURCES[:2])}
raw = COMPILED_SOURCE_BUFFERS[str(SOURCES[0])]
tree = ast.parse(raw)
owner = next(n for n in tree.body if isinstance(n, ast.ClassDef)
             and any(isinstance(m, ast.FunctionDef) and m.name == "integer_byte_swap" for m in n.body))
selected = {"integer_type", "literal", "synthetic", "integer_byte_swap", "intrinsic_signature"}
methods = [copy.deepcopy(n) for n in owner.body if isinstance(n, ast.FunctionDef) and n.name in selected]
assert {n.name for n in methods} == selected
constant = next(copy.deepcopy(n) for n in owner.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "INTEGER_BYTE_SWAP_INTRINSICS" for t in n.targets))
reject = ast.parse("def reject(self, message):\n    raise RuntimeError(message)\n").body[0]
body = ast.ClassDef(name="Lowering", bases=[], keywords=[], body=[constant, *methods, reject], decorator_list=[])
namespace = {}
exec(compile(ast.fix_missing_locations(ast.Module(body=[body], type_ignores=[])), str(SOURCES[0]), "exec"), namespace)
Lowering = namespace["Lowering"]

inventory_tree = ast.parse(COMPILED_SOURCE_BUFFERS[str(SOURCES[1])])
functions = [copy.deepcopy(n) for n in inventory_tree.body if isinstance(n, ast.FunctionDef)
             and n.name in ("native_shape", "native_operand", "byte_swap_graph")]
assert len(functions) == 3
inventory = {}
exec(compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])), str(SOURCES[1]), "exec"), inventory)


def graph(width, argument=None):
    obj = Lowering()
    obj.types, obj.next_id, obj.refinements = [{"kind": "int", "bits": width}], 1, set()
    instructions = []
    operand = {"kind": "value", "id": 0} if argument is None else argument
    operation = obj.integer_byte_swap(f"llvm.bswap.i{width}", operand, 0, instructions)
    result = {"id": 9000, "ty": 0}
    instructions.append({"result": result, "operation": operation})
    block = {"id": 0, "instructions": instructions}
    site = {"name": f"llvm.bswap.i{width}", "args": [inventory["native_operand"](operand, obj.types)],
            "arg_types": [{"kind": "int", "bits": width}], "result_type": {"kind": "int", "bits": width}}
    return obj, block, site, operation, result


def evaluate(block, width, value):
    values, mask = {0: value}, (1 << width) - 1
    def operand(v):
        return values[v["id"]] if v["kind"] == "value" else int(v["bits"])
    for instruction in block["instructions"]:
        op = instruction["operation"]
        if op["op"] == "freeze":
            output = operand(op["value"])
        else:
            assert op["op"] == "binary" and op["flags"] == []
            lhs, rhs = operand(op["lhs"]), operand(op["rhs"])
            kind = op["kind"]
            if kind in ("l_shr", "shl"):
                assert 0 <= rhs < width
            output = {"and": lambda: lhs & rhs, "or": lambda: lhs | rhs,
                      "l_shr": lambda: lhs >> rhs, "shl": lambda: lhs << rhs}[kind]()
        values[instruction["result"]["id"]] = output & mask
    return values[9000]


class ByteSwapPureControls(unittest.TestCase):
    def test_i16_complete_defined_domain_matches_independent_byte_oracle(self):
        _, block, _, _, _ = graph(16)
        for value in range(1 << 16):
            self.assertEqual(evaluate(block, 16, value), int.from_bytes(value.to_bytes(2, "little"), "big"))

    def test_other_width_basis_and_seeded_values_match_byte_oracle(self):
        rng = random.Random(712347)
        for width in WIDTHS[1:]:
            _, block, _, _, _ = graph(width)
            values = [0, (1 << width) - 1, *[1 << bit for bit in range(width)],
                      *[rng.getrandbits(width) for _ in range(256)]]
            for value in values:
                expected = int.from_bytes(value.to_bytes(width // 8, "little"), "big")
                self.assertEqual(evaluate(block, width, value), expected)
                self.assertEqual(evaluate(block, width, expected), value)

    def test_independent_inventory_matches_all_exact_typed_graphs(self):
        for width in WIDTHS:
            obj, block, site, operation, result = graph(width)
            claims = {}
            self.assertTrue(inventory["byte_swap_graph"](site, block, operation, result, obj.types, claims))
            self.assertEqual(len(claims[9000]), width // 2)
            self.assertEqual(sum(i["operation"]["op"] == "freeze" for i in block["instructions"]), 1)

    def test_same_typed_mask_shift_direction_and_source_mutations_are_refused(self):
        for width in WIDTHS:
            for mutation in ("mask", "shift", "direction", "source"):
                obj, block, site, operation, result = graph(width)
                if mutation == "source":
                    block["instructions"][0]["operation"]["value"] = {"kind": "value", "id": 99}
                elif mutation == "mask":
                    next(i["operation"] for i in block["instructions"] if i["operation"].get("kind") == "and")["rhs"]["bits"] = "254"
                else:
                    op = next(i["operation"] for i in block["instructions"] if i["operation"].get("kind") == "l_shr")
                    if mutation == "shift": op["rhs"]["bits"] = "8"
                    else: op["kind"] = "a_shr"
                self.assertFalse(inventory["byte_swap_graph"](site, block, operation, result, obj.types))

    def test_one_shared_freeze_is_required_for_original_undef_and_poison(self):
        for kind in ("undef", "poison"):
            obj, block, site, operation, result = graph(32, {"kind": kind, "ty": 0})
            self.assertTrue(inventory["byte_swap_graph"](site, block, operation, result, obj.types))
            duplicate = copy.deepcopy(block["instructions"][0]); duplicate["result"]["id"] = 99
            block["instructions"].insert(1, duplicate)
            shifts = [i["operation"] for i in block["instructions"] if i["operation"].get("kind") == "l_shr"]
            shifts[-1]["lhs"] = {"kind": "value", "id": 99}
            self.assertFalse(inventory["byte_swap_graph"](site, block, operation, result, obj.types))

    def test_call_signature_requires_exact_types_C_ABI_and_no_abi_attributes(self):
        for width in WIDTHS:
            obj, *_ = graph(width)
            obj.types += [{"kind": "void"}, {"kind": "int", "bits": 1}]
            original = dict(params=[0], result=0, abi="c", variadic=False,
                            param_attributes=[[]], result_attributes=[])
            obj.intrinsic_signature(f"llvm.bswap.i{width}", original)
            for changes in (dict(params=[]), dict(result=1), dict(params=[2]), dict(abi="fastcc"),
                            dict(variadic=True), dict(result_attributes=["zeroext"]),
                            dict(param_attributes=[["signext"]]), dict(return_storage=0)):
                changed = copy.deepcopy(original); changed.update(changes)
                with self.assertRaises(RuntimeError): obj.intrinsic_signature(f"llvm.bswap.i{width}", changed)

    def test_wrong_inventory_type_result_or_missing_original_operand_refused(self):
        for field, changed in (("arg_types", [{"kind": "int", "bits": 64}]),
                               ("result_type", {"kind": "int", "bits": 64}), ("args", [])):
            obj, block, site, operation, result = graph(32)
            site[field] = changed
            self.assertFalse(inventory["byte_swap_graph"](site, block, operation, result, obj.types))

    def test_consumed_buffers_are_checked_before_compile_and_changed_bytes_refused(self):
        for index, path in enumerate(SOURCES[:2]):
            value = COMPILED_SOURCE_BUFFERS[str(path)]
            self.assertEqual(len(value), BEFORE[index]['bytes'])
            self.assertEqual(hashlib.sha256(value).hexdigest(), BEFORE[index]['sha256'])
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'source-buffer'
            path.write_bytes(b'graph-A')
            expected = pin(path)
            self.assertEqual(read_checked(path, expected), b'graph-A')
            path.write_bytes(b'graph-B')
            with self.assertRaisesRegex(RuntimeError, 'actual consumed source buffer drift'):
                read_checked(path, expected)

    def test_embedded_inventory_source_and_static_python_syntax_match(self):
        self.assertEqual(SOURCES[1].read_bytes(), SOURCES[2].read_bytes())
        for path in (SOURCES[0], SOURCES[1], Path(__file__)):
            ast.parse(path.read_bytes(), filename=str(path))


if __name__ == "__main__":
    output = ROOT / "pure-controls-r1"
    output.mkdir()
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ByteSwapPureControls)
    ids = [test.id() for test in suite]
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    (output / "unittest.log").write_text(stream.getvalue())
    after = [pin(path) for path in SOURCES]
    passed = result.wasSuccessful() and result.testsRun == 9 and not result.skipped and BEFORE == after
    report = dict(schema="ocore-byte-swap-pure-source-controls-v1", passed=passed, tests_run=result.testsRun,
                  required_ids=ids, failures=len(result.failures), errors=len(result.errors), skips=len(result.skipped),
                  before=BEFORE, after=after, source_AST_buffers_compiled=True, defined_i16_inputs=65536,
                  actual_consumed_source_buffers=[dict(path=path, bytes=len(value),
                       sha256=hashlib.sha256(value).hexdigest()) for path, value in COMPILED_SOURCE_BUFFERS.items()],
                  native_verifier_run=False, LLVM_parser_run=False, original_units_imported=0,
                  compiler_rebuilt=False, target_execution=False, runtime_accepted=False, all_isa_qualified=False)
    (output / "receipt.json").write_text(json.dumps(report, indent=2) + "\n")
    print(stream.getvalue()); print(json.dumps(report))
    raise SystemExit(0 if passed else 1)
