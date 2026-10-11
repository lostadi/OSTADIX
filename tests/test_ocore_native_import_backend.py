"""Adversarial tests of the verified NativeModule -> own ISA emitter boundary.

These tests do not build Cargo. Set OCOREC to the binary being reviewed; the
default is target/debug/ocorec. Structural verification must succeed before a
backend rejection counts, so malformed SSA cannot conceal an emitter defect.
The scalar fixtures are compiler-bridge evidence, not complete runtime support.
"""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "x86_64": "x86_64-unknown-none",
    "aarch64": "aarch64-unknown-none",
    "riscv64": "riscv64-unknown-none",
}
VOID, I64, PTR, I1, I8, I32 = range(6)
LAYOUT = "e-p:64:64-i64:64-n8:16:32:64-S128"


def value(identifier):
    return {"kind": "value", "id": identifier}


def integer(ty, bits):
    return {"kind": "int", "ty": ty, "bits": str(bits)}


def instruction(identifier, ty, operation):
    return {"result": {"id": identifier, "ty": ty}, "operation": operation}


def signature(params=(), result=I64, **extra):
    return {"params": list(params), "result": result, "abi": "c",
            "variadic": False, **extra}


def function(name, instructions=(), result=None, params=(), **extra):
    return {
        "name": name, "linkage": "external", "signature": signature(params),
        "params": [{"id": i, "ty": ty} for i, ty in enumerate(params)],
        "entry": 0,
        "blocks": [{"id": 0, "instructions": list(instructions),
                    "terminator": {"op": "return", "value":
                                   integer(I64, 0) if result is None else result}}],
        **extra,
    }


def module(isa="x86_64", functions=None, globals_=None):
    functions = [function("entry")] if functions is None else functions
    globals_ = [] if globals_ is None else globals_
    return {
        "format": "ocore-native-module-v1", "name": "native-backend-contract",
        "target": {"triple": f"{isa}-unknown-linux-gnu",
                   "data_layout": LAYOUT, "pointer_bits": 64,
                   "little_endian": True},
        "semantics": "llvm_defined_behavior_v1",
        "types": [{"kind": "void"}, {"kind": "int", "bits": 64},
                  {"kind": "pointer", "address_space": 0},
                  {"kind": "int", "bits": 1},
                  {"kind": "int", "bits": 8},
                  {"kind": "int", "bits": 32}],
        "globals": globals_, "functions": functions,
        "provenance": {
            "input_sha256": "0" * 64, "frontend": "adversarial-native-ir",
            "frontend_version": "1", "importer": "regression-fixture",
            "importer_version": "1", "source_function_count": len(functions),
            "source_global_count": len(globals_), "refinements": [],
        },
    }


def global_(name="slot", linkage="external", initializer=True, ty=I64):
    return {
        "name": name, "ty": ty, "linkage": linkage, "alignment": 8,
        "constant": False, "thread_local": False,
        "initializer": {"bytes": [0] * 8, "relocations": []}
        if initializer else None,
    }


def volatile_module(isa, alignment, bits=64, access="both"):
    ty = I64 if bits == 64 else I32
    operations = []
    if access in {"store", "both"}:
        operations.append({"result": None, "operation": {
            "op": "store", "pointer": value(0), "value": value(1),
            "alignment": alignment, "volatile": True}})
    result = integer(I64, 0)
    if access in {"load", "both"}:
        operations.append(instruction(2, ty, {
            "op": "load", "pointer": value(0), "alignment": alignment,
            "volatile": True}))
        result = value(2)
        if ty == I32:
            operations.append(instruction(3, I64, {
                "op": "cast", "kind": "z_ext", "value": value(2)}))
            result = value(3)
    return module(isa, [function("volatile_access", operations, result, (PTR, ty))])


def repeated_alloca_module(isa):
    fn = function("alloca_repeat")
    fn["blocks"] = [
        {"id": 0, "instructions": [], "terminator": {"op": "jump", "target": 1}},
        {"id": 1, "instructions": [
            instruction(0, I64, {"op": "phi", "incoming": [
                {"block": 0, "value": integer(I64, 0)},
                {"block": 1, "value": integer(I64, 1)}]}),
            instruction(1, PTR, {"op": "phi", "incoming": [
                {"block": 0, "value": {"kind": "null", "ty": PTR}},
                {"block": 1, "value": value(2)}]}),
            instruction(2, PTR, {"op": "alloca", "size": 8, "alignment": 8}),
            {"result": None, "operation": {"op": "store", "pointer": value(2),
             "value": value(0), "alignment": 8, "volatile": False}},
            instruction(3, I1, {"op": "i_cmp", "predicate": "eq",
                        "lhs": value(0), "rhs": integer(I64, 1)}),
        ], "terminator": {"op": "branch", "condition": value(3),
                           "on_true": 2, "on_false": 1}},
        {"id": 2, "instructions": [instruction(4, I64, {
            "op": "load", "pointer": value(1), "alignment": 8, "volatile": False})],
         "terminator": {"op": "return", "value": value(4)}},
    ]
    return module(isa, [fn])


def large_phi_switch_module(isa, count):
    fn = function("large_phi_switch", params=(I64,))
    fn["blocks"] = [
        {"id": 0, "instructions": [], "terminator": {
            "op": "switch", "condition": value(0), "default": 1,
            "cases": [{"value": integer(I64, 0), "target": 2}]}},
        {"id": 1, "instructions": [],
         "terminator": {"op": "return", "value": integer(I64, 99)}},
        {"id": 2, "instructions": [instruction(i + 1, I64, {
            "op": "phi", "incoming": [{"block": 0, "value": integer(I64, i)}]})
            for i in range(count)],
         "terminator": {"op": "return", "value": value(1)}},
    ]
    return module(isa, [fn])


def scalar_edge_fixtures():
    def binary(kind, lhs, rhs, flags=()):
        return {"op": "binary", "kind": kind, "lhs": lhs, "rhs": rhs,
                "flags": list(flags)}

    def cast(kind, operand):
        return {"op": "cast", "kind": kind, "value": operand}

    def hidden(operand):
        return {"op": "select", "condition": integer(I1, 0),
                "on_true": operand, "on_false": integer(I8, 17)}

    # Each expected result is defined by LLVM, including hidden deferred poison.
    # Divisor zero and signed-division overflow are deliberately not treated as
    # defined-behavior differential cases.
    cases = [
        ("trunc256", [instruction(0, I1, cast("trunc", integer(I64, 256))),
                      instruction(1, I64, cast("z_ext", value(0)))],
         "%a = trunc i64 256 to i1\n%b = zext i1 %a to i64", 0),
        ("sext_true", [instruction(0, I64, cast("s_ext", integer(I1, 1)))],
         "%b = sext i1 true to i64", (1 << 64) - 1),
        ("ashr8", [instruction(0, I8, binary("a_shr", integer(I8, 128), integer(I8, 7))),
                   instruction(1, I64, cast("z_ext", value(0)))],
         "%a = ashr i8 -128, 7\n%b = zext i8 %a to i64", 255),
        ("lshr8", [instruction(0, I8, binary("l_shr", integer(I8, 128), integer(I8, 7))),
                   instruction(1, I64, cast("z_ext", value(0)))],
         "%a = lshr i8 -128, 7\n%b = zext i8 %a to i64", 1),
        ("hidden_overflow", [
            instruction(0, I8, binary("add", integer(I8, 255), integer(I8, 1), ("nuw",))),
            instruction(1, I8, hidden(value(0))),
            instruction(2, I64, cast("z_ext", value(1)))],
         "%a = add nuw i8 -1, 1\n%s = select i1 false, i8 %a, i8 17\n"
         "%b = zext i8 %s to i64", 17),
        ("hidden_shift", [
            instruction(0, I8, binary("shl", integer(I8, 1), integer(I8, 8))),
            instruction(1, I8, hidden(value(0))),
            instruction(2, I64, cast("z_ext", value(1)))],
         "%a = shl i8 1, 8\n%s = select i1 false, i8 %a, i8 17\n"
         "%b = zext i8 %s to i64", 17),
        ("stable_freeze", [
            instruction(0, I8, binary("add", integer(I8, 127), integer(I8, 1), ("nsw",))),
            instruction(1, I8, {"op": "freeze", "value": value(0)}),
            instruction(2, I8, binary("xor", value(1), value(1))),
            instruction(3, I64, cast("z_ext", value(2)))],
         "%a = add nsw i8 127, 1\n%f = freeze i8 %a\n%x = xor i8 %f, %f\n"
         "%b = zext i8 %x to i64", 0),
        ("hidden_exact", [
            instruction(0, I8, binary("u_div", integer(I8, 5), integer(I8, 2), ("exact",))),
            instruction(1, I8, hidden(value(0))),
            instruction(2, I64, cast("z_ext", value(1)))],
         "%a = udiv exact i8 5, 2\n%s = select i1 false, i8 %a, i8 17\n"
         "%b = zext i8 %s to i64", 17),
    ]
    functions = [function(name, ops, value(ops[-1]["result"]["id"]))
                 for name, ops, _, _ in cases]
    llvm = f'target triple = "x86_64-unknown-linux-gnu"\ntarget datalayout = "{LAYOUT}"\n'
    llvm += "\n".join(f"define i64 @{name}() {{\n{body}\nret i64 %b\n}}"
                      for name, _, body, _ in cases)
    return functions, llvm, [(name, expected) for name, _, _, expected in cases]


def scalar_abi_functions():
    def binary(kind, lhs, rhs):
        return {"op": "binary", "kind": kind, "lhs": lhs, "rhs": rhs, "flags": []}

    operations, accumulator, next_id = [], value(0), 12
    for index in range(1, 12):
        operations.append(instruction(next_id, I64,
                                     binary("mul", value(index), integer(I64, index + 1))))
        operations.append(instruction(next_id + 1, I64,
                                     binary("add", accumulator, value(next_id))))
        accumulator, next_id = value(next_id + 1), next_id + 2
    functions = [function("many", operations, accumulator, [I64] * 12)]
    external = function("foreign_sum", params=[I64] * 12)
    external.update(entry=None, blocks=[])
    functions.append(external)
    for name, indirect in (("forward_direct", False), ("forward_indirect", True)):
        functions.append(function(name, [instruction(2, I64, {
            "op": "call", "callee": value(0) if indirect else
            {"kind": "symbol", "ty": PTR, "name": "foreign_sum"},
            "signature": signature([I64] * 12),
            "args": [value(1 if indirect else 0)] +
                    [integer(I64, i) for i in range(2, 13)]})],
            value(2), (PTR, I64) if indirect else (I64,)))
    byte_signature = signature([I8], I8, param_attributes=[["signext"]],
                               result_attributes=["signext"])
    byte = function("signed_byte", result=value(0), params=(I8,))
    byte["signature"] = byte_signature
    functions.append(byte)
    functions.append(function("nested_byte", [
        instruction(1, I8, {"op": "cast", "kind": "trunc", "value": value(0)}),
        instruction(2, I8, {"op": "call", "callee": {
            "kind": "symbol", "ty": PTR, "name": "signed_byte"},
            "signature": byte_signature, "args": [value(1)]}),
        instruction(3, I64, {"op": "cast", "kind": "s_ext", "value": value(2)}),
    ], value(3), (I64,)))
    word = function("unsigned_word", result=integer(I32, (1 << 32) - 1))
    word["signature"] = signature(result=I32, result_attributes=["zeroext"])
    functions.append(word)
    functions.append(function("stack_test", [
        instruction(1, PTR, {"op": "alloca", "size": 16384, "alignment": 16}),
        instruction(2, PTR, {"op": "gep", "base": value(1),
                            "offset": integer(I64, 8192), "inbounds": True}),
        instruction(3, I64, binary("add", value(0), integer(I64, 1))),
        {"result": None, "operation": {"op": "store", "pointer": value(1),
         "value": value(0), "alignment": 16, "volatile": True}},
        {"result": None, "operation": {"op": "store", "pointer": value(2),
         "value": value(3), "alignment": 16, "volatile": True}},
        instruction(4, I64, {"op": "load", "pointer": value(1),
                            "alignment": 16, "volatile": True}),
        instruction(5, I64, {"op": "load", "pointer": value(2),
                            "alignment": 16, "volatile": True}),
        instruction(6, I64, binary("xor", value(4), value(5))),
    ], value(6), (I64,)))
    # Outgoing stack arguments exceed a page on every supported C ABI. The
    # independently compiled callee validates the values after stack probing.
    external = function("foreign_600", params=[I64] * 600)
    external.update(entry=None, blocks=[])
    functions.append(external)
    functions.append(function("forward_600", [instruction(1, I64, {
        "op": "call", "callee": {"kind": "symbol", "ty": PTR, "name": "foreign_600"},
        "signature": signature([I64] * 600),
        "args": [value(0)] + [integer(I64, i) for i in range(2, 601)],
    })], value(1), (I64,)))
    return functions


class NativeImportBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        chosen = os.environ.get("OCOREC")
        path = Path(chosen) if chosen else ROOT / "target/debug/ocorec"
        if not path.is_absolute():
            found = shutil.which(str(path))
            path = Path(found) if found else ROOT / path
        if not path.is_file() or not os.access(path, os.X_OK):
            raise unittest.SkipTest("ocorec unavailable; build it separately or set OCOREC")
        cls.compiler = str(path.resolve())

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-native-backend-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.counter = 0

    def run_command(self, command, timeout=60):
        return subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                              timeout=timeout)

    def succeeded(self, command, timeout=60):
        result = self.run_command(command, timeout)
        self.assertEqual(result.returncode, 0,
                         f"{command!r}\n{result.stdout}\n{result.stderr}")
        return result

    def verified_input(self, native_module):
        self.counter += 1
        source = self.directory / f"input-{self.counter}.json"
        source.write_text(json.dumps(native_module), encoding="utf-8")
        receipt = source.with_suffix(".receipt.json")
        self.succeeded([self.compiler, str(source), "--input-kind", "native-ir",
                        "--verify-native", "--receipt", str(receipt)])
        record = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertIs(record["verified"], True)
        self.assertEqual(record["scope"], "structural_ir_verification")
        self.assertEqual(record["module_sha256"],
                         hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(len(record["functions"]), len(native_module["functions"]))
        self.assertEqual(record["global_count"], len(native_module["globals"]))
        return source

    def reject_backend(self, native_module, isa, reason):
        source = self.verified_input(native_module)
        output = source.with_suffix(".s")
        result = self.run_command([self.compiler, str(source), "--input-kind", "native-ir",
                                   "--emit", "asm", "--target", TARGETS[isa],
                                   "--output", str(output)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("phase: native compilation", result.stderr)
        self.assertIn("cause:", result.stderr)
        self.assertIn(reason, result.stderr)
        self.assertFalse(output.exists(), "a rejected module must not produce assembly")

    def assembly(self, native_module, isa):
        source = self.verified_input(native_module)
        output = source.with_suffix(".s")
        self.succeeded([self.compiler, str(source), "--input-kind", "native-ir",
                        "--emit", "asm", "--target", TARGETS[isa], "-o", str(output)])
        return output.read_text(encoding="utf-8")

    def test_repeated_fixed_alloca_cannot_alias_across_loop_executions(self):
        # Originally this valid loop returned 1; a Clang object returned 0.
        # Until per-execution allocation exists, the entire module must reject.
        for isa in TARGETS:
            with self.subTest(isa=isa):
                self.reject_backend(repeated_alloca_module(isa), isa, "non-entry allocation")

    def test_function_linkage_requires_real_backend_support(self):
        for isa in TARGETS:
            for linkage in ("extern_weak", "available_externally", "linkonce",
                            "weak", "linkonce_odr", "weak_odr"):
                with self.subTest(isa=isa, linkage=linkage):
                    fn = function("hook", linkage=linkage)
                    if linkage == "extern_weak":
                        fn.update(entry=None, blocks=[])
                    self.reject_backend(module(isa, [fn]), isa, f"linkage `{linkage}`")

    def test_global_linkage_requires_real_backend_support(self):
        for isa in TARGETS:
            for linkage in ("extern_weak", "common", "available_externally", "linkonce",
                            "weak", "linkonce_odr", "weak_odr"):
                with self.subTest(isa=isa, linkage=linkage):
                    glob = global_(linkage=linkage, initializer=linkage != "extern_weak")
                    self.reject_backend(module(isa, globals_=[glob]), isa,
                                        f"linkage `{linkage}`")

    def test_unrealizable_global_storage_alignment_rejects_before_any_artifact(self):
        for isa in TARGETS:
            for alignment in (1 << 32,):
                with self.subTest(isa=isa, alignment=alignment):
                    glob = global_(ty=I8)
                    glob["alignment"] = alignment
                    glob["initializer"]["bytes"] = [7]
                    native = module(isa, globals_=[glob])
                    reason = f"global storage alignment {alignment}"
                    self.reject_backend(native, isa, reason)
                    source = self.verified_input(native)
                    output = source.with_suffix(".o")
                    result = self.run_command([self.compiler, str(source),
                        "--input-kind", "native-ir", "--emit", "obj",
                        "--target", TARGETS[isa], "-o", str(output)])
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(reason, result.stderr)
                    self.assertFalse(output.exists(), "unrealizable alignment cannot produce an object")

    def test_windows_and_darwin_c_abi_cannot_use_linux_register_assignment(self):
        for isa in TARGETS:
            for suffix in ("pc-windows-msvc", "apple-darwin"):
                with self.subTest(isa=isa, suffix=suffix):
                    native = module(isa)
                    native["target"]["triple"] = f"{isa}-{suffix}"
                    self.reject_backend(native, isa, "Linux/ELF frontend profiles")

    def test_foreign_c_abi_cannot_hide_inside_a_supported_target_suffix(self):
        # The Windows case originally verified and emitted a SysV object:
        # a five-argument ms_abi caller received argument 3 instead of argument 5.
        for isa in TARGETS:
            for suffix in ("pc-windows-msvc-linux-gnu", "apple-darwin-unknown-none",
                           "pc-windows-msvc-unknown-none-elf", "-linux-gnu"):
                with self.subTest(isa=isa, suffix=suffix):
                    native = module(isa)
                    native["target"]["triple"] = f"{isa}-{suffix}"
                    self.reject_backend(native, isa, "Linux/ELF frontend profiles")

    def test_bare_rv64_target_requires_explicit_lp64_and_rejects_other_abis(self):
        for abi in (None, "missing", "lp64d", "lp64f", "lp64e", "", "lp64 "):
            with self.subTest(abi=abi):
                native = module("riscv64")
                native["target"]["triple"] = "riscv64"
                if abi != "missing":
                    native["target"]["abi"] = abi
                reason = "Linux/ELF frontend profiles" if abi in (None, "missing") \
                    else "unsupported explicit frontend ABI"
                self.reject_backend(native, "riscv64", reason)
        native = module("riscv64")
        native["target"].update(triple="riscv64", abi="lp64")
        self.assertIn("entry:", self.assembly(native, "riscv64"))
        for isa in TARGETS:
            with self.subTest(qualified_isa=isa):
                native = module(isa)
                native["target"]["abi"] = "lp64d" if isa == "riscv64" else "lp64"
                self.reject_backend(native, isa, "unsupported explicit frontend ABI")

    def test_frontend_isa_must_match_selected_emitter(self):
        for source_isa, emitter_isa in (("x86_64", "aarch64"),
                                        ("aarch64", "riscv64"),
                                        ("riscv64", "x86_64")):
            with self.subTest(source=source_isa, emitter=emitter_isa):
                self.reject_backend(module(source_isa), emitter_isa, "does not match")
        native = module()
        native["target"]["triple"] = "x86_64_not_an_isa-unknown-linux-gnu"
        self.reject_backend(native, "x86_64", "does not match")

    def test_non_lp64_or_big_endian_layout_cannot_enter_scalar_emitters(self):
        for isa in TARGETS:
            for profile in ("pointer32", "big_endian"):
                with self.subTest(isa=isa, profile=profile):
                    native = module(isa)
                    if profile == "pointer32":
                        native["target"].update(pointer_bits=32,
                                                data_layout="e-p:32:32-i64:64")
                    else:
                        native["target"].update(little_endian=False,
                                                data_layout="E-p:64:64-i64:64")
                    self.reject_backend(native, isa, "little-endian LP64")

    def test_non_c_and_variadic_signatures_do_not_use_fixed_scalar_abi(self):
        for isa in TARGETS:
            for mode in ("fast", "variadic"):
                with self.subTest(isa=isa, mode=mode):
                    fn = function("foreign")
                    fn.update(entry=None, blocks=[])
                    fn["signature"].update({"abi": "fast"} if mode == "fast"
                                           else {"variadic": True})
                    self.reject_backend(module(isa, [fn]), isa, "fixed scalar C ABI")

    def test_wide_weakly_aligned_volatile_accesses_never_split_to_bytes(self):
        for isa in ("aarch64", "riscv64"):
            for bits, alignment in ((64, 1), (64, 4), (32, 1), (32, 2)):
                for access in ("load", "store"):
                    with self.subTest(isa=isa, bits=bits, alignment=alignment, access=access):
                        self.reject_backend(volatile_module(isa, alignment, bits, access),
                                            isa, "unaligned volatile access")

    def test_default_and_explicit_volatile_alignment_preserve_access_width(self):
        patterns = {
            "x86_64": ("mov qword ptr [rcx], rax", "mov rax, qword ptr [rcx]",
                       "byte ptr [rcx]"),
            "aarch64": ("str x9, [x10]", "ldr x9, [x10]", "b w11, [x10"),
            "riscv64": ("sd t0, 0(t1)", "ld t0, 0(t1)", "bu t2,"),
        }
        for isa in TARGETS:
            for alignment in (0, 8):
                with self.subTest(isa=isa, alignment=alignment):
                    assembly = self.assembly(volatile_module(isa, alignment), isa)
                    store, load, byte_access = patterns[isa]
                    self.assertEqual(assembly.count(store), 1)
                    self.assertEqual(assembly.count(load), 1)
                    self.assertNotIn(byte_access, assembly)
                    if isa == "riscv64":
                        self.assertNotRegex(assembly, r"\bsb\s+t2,\s*\d+\(t1\)")

    def test_memory_store_width_differs_from_abi_allocation_stride(self):
        slot = {"kind": "symbol", "ty": PTR, "name": "padded_i32"}
        operations = [
            {"result": None, "operation": {"op": "store", "pointer": slot,
             "value": value(0), "alignment": 8, "volatile": False}},
            instruction(1, I32, {"op": "load", "pointer": slot,
                        "alignment": 8, "volatile": False}),
            instruction(2, I64, {"op": "cast", "kind": "z_ext", "value": value(1)}),
        ]
        patterns = {
            "x86_64": ("mov dword ptr [rcx], eax", "mov eax, dword ptr [rcx]",
                       "qword ptr [rcx]"),
            "aarch64": ("str w9, [x10]", "ldr w9, [x10]", "x9, [x10]"),
            "riscv64": ("sw t0, 0(t1)", "lwu t0, 0(t1)", "d t0, 0(t1)"),
        }
        for isa in TARGETS:
            with self.subTest(isa=isa):
                native = module(isa, [function("store_padded", operations, value(2), (I32,))],
                                [global_("padded_i32", ty=I32)])
                native["target"]["data_layout"] += "-i32:64"
                assembly = self.assembly(native, isa)
                store, load, wide_access = patterns[isa]
                self.assertIn(store, assembly)
                self.assertIn(load, assembly)
                self.assertNotIn(wide_access, assembly)

    def test_imported_symbols_cannot_collide_with_generated_block_labels(self):
        for isa in TARGETS:
            with self.subTest(isa=isa):
                name = ".Locore_native_0_0_b0"
                assembly = self.assembly(module(isa, [function(name)]), isa)
                labels = re.findall(r"^([A-Za-z_.$][A-Za-z0-9_.$]*):$", assembly, re.MULTILINE)
                self.assertEqual(labels.count(name), 1)
                self.assertEqual(len(labels), len(set(labels)))
                self.assertIn(".Locore_native_1_0_b0:", assembly)

    def test_all_three_scalar_abis_emit_calls_extensions_and_page_probes(self):
        direct = {"x86_64": "call foreign_sum", "aarch64": "bl foreign_sum",
                  "riscv64": "call foreign_sum"}
        indirect = {"x86_64": "call rax", "aarch64": "blr x9", "riscv64": "jalr t0"}
        probes = {"x86_64": "mov byte ptr [rsp], 0", "aarch64": "strb wzr, [sp]",
                  "riscv64": "sb zero, 0(sp)"}
        for isa in TARGETS:
            with self.subTest(isa=isa):
                assembly = self.assembly(module(isa, scalar_abi_functions()), isa)
                self.assertIn(direct[isa], assembly)
                self.assertIn(indirect[isa], assembly)
                self.assertIn(probes[isa], assembly)
                if isa == "riscv64":
                    word_body = assembly.split("unsigned_word:\n", 1)[1]
                    word_body = word_body.split(".size unsigned_word,", 1)[0]
                    self.assertIn("srai t0, t0, 32", word_body,
                                  "RV64 C ABI sign-extends even unsigned 32-bit returns")

    def test_x86_c_abi_stack_arguments_extensions_and_probes_execute(self):
        clang = shutil.which("clang")
        if platform.machine() not in {"x86_64", "AMD64"} or clang is None:
            self.skipTest("x86-64 CPU and Clang required for C ABI execution")
        source = self.verified_input(module(functions=scalar_abi_functions()))
        obj, executable = self.directory / "abi.o", self.directory / "abi"
        self.succeeded([self.compiler, str(source), "--input-kind", "native-ir",
                        "--target", TARGETS["x86_64"], "-o", str(obj)])
        parameters12 = ",".join(f"u64 p{i}" for i in range(12))
        parameters600 = ",".join(f"u64 p{i}" for i in range(600))
        sum12 = "+".join(f"{i + 1}ULL*p{i}" for i in range(12))
        sum600 = "+".join(f"{i + 1}ULL*p{i}" for i in range(600))
        harness = self.directory / "abi-main.c"
        harness.write_text(f"""#include <stdio.h>
typedef unsigned long long u64;
typedef long long i64;
u64 foreign_sum({parameters12}) {{ return {sum12}; }}
u64 foreign_600({parameters600}) {{ return {sum600}; }}
extern u64 many({parameters12});
extern u64 forward_direct(u64);
extern u64 forward_indirect(u64 (*)( {','.join(['u64'] * 12)} ), u64);
extern signed char signed_byte(signed char);
extern u64 nested_byte(u64);
extern unsigned int unsigned_word(void);
extern u64 stack_test(u64);
extern u64 forward_600(u64);
int main(void) {{
    u64 state=0x9e3779b97f4a7c15ULL;
    for (unsigned i=0;i<256;i++) {{
        state^=state<<13;state^=state>>7;state^=state<<17;
        if(many(state,2,3,4,5,6,7,8,9,10,11,12)!=state+649) return 1;
        if(forward_direct(state)!=state+649) return 2;
        if(forward_indirect(foreign_sum,state)!=state+649) return 3;
        if(signed_byte((signed char)state)!=(signed char)state) return 4;
        if(nested_byte(state)!=(u64)(i64)(signed char)state) return 5;
        if(unsigned_word()!=0xffffffffU) return 6;
        if(stack_test(state)!=(state^(state+1))) return 7;
        if(forward_600(state)!=state+72180099ULL) return 8;
    }}
    puts("2048 scalar C ABI and stack probe checks PASS");
    return 0;
}}
""", encoding="utf-8")
        self.succeeded([clang, "-O1", str(harness), str(obj), "-o", str(executable)])
        self.assertEqual(self.succeeded([str(executable)]).stdout,
                         "2048 scalar C ABI and stack probe checks PASS\n")

    def test_x86_defined_scalar_edges_match_independent_llvm_codegen(self):
        clang = shutil.which("clang")
        if platform.machine() not in {"x86_64", "AMD64"} or clang is None:
            self.skipTest("x86-64 CPU and Clang required for execution comparison")
        functions, llvm, cases = scalar_edge_fixtures()
        source = self.verified_input(module(functions=functions))
        ours_object = self.directory / "own.o"
        self.succeeded([self.compiler, str(source), "--input-kind", "native-ir",
                        "--target", TARGETS["x86_64"], "-o", str(ours_object)])
        reference_source = self.directory / "reference.ll"
        reference_source.write_text(llvm, encoding="utf-8")
        reference_object = self.directory / "reference.o"
        self.succeeded([clang, "-O0", "-c", str(reference_source), "-o", str(reference_object)])
        harness = self.directory / "main.c"
        declarations = "\n".join(f"extern unsigned long long {name}(void);" for name, _ in cases)
        checks = "\n".join(f"if ({name}() != {expected}ULL) return {i + 1};"
                           for i, (name, expected) in enumerate(cases))
        harness.write_text(f"#include <stdio.h>\n{declarations}\nint main(void){{\n{checks}\n"
                           'puts("8 defined scalar edge cases PASS"); return 0;}\n', encoding="utf-8")
        results = []
        for name, obj in (("own", ours_object), ("reference", reference_object)):
            executable = self.directory / name
            self.succeeded([clang, str(harness), str(obj), "-o", str(executable)])
            results.append(self.succeeded([str(executable)]).stdout)
        self.assertEqual(results, ["8 defined scalar edge cases PASS\n"] * 2)

    def test_aarch64_large_outgoing_call_assembles_beyond_literal_pool_reach(self):
        clang = shutil.which("clang")
        if clang is None:
            self.skipTest("Clang required for AArch64 object assembly")
        targets = self.succeeded([clang, "--print-targets"]).stdout
        if not re.search(r"\baarch64\b", targets):
            self.skipTest("installed Clang lacks AArch64 target")
        # The old emitter put stack-argument offset 65544 in the final literal
        # pool; this complete function exceeded LDR's one-megabyte reach.
        argument_count, body_count = 8210, 70000
        callee = function("many_args", params=[I64] * argument_count)
        callee.update(entry=None, blocks=[])
        operations = [instruction(0, I64, {
            "op": "call", "callee": {"kind": "symbol", "ty": PTR,
                                       "name": "many_args"},
            "signature": signature([I64] * argument_count),
            "args": [integer(I64, 0)] * argument_count})]
        operations.extend(instruction(i + 1, I64, {
            "op": "freeze", "value": integer(I64, 0)}) for i in range(body_count))
        caller = function("large_call", operations, value(body_count))
        source = self.verified_input(module("aarch64", [callee, caller]))
        obj = self.directory / "large-call.o"
        self.succeeded([self.compiler, str(source), "--input-kind", "native-ir",
                        "--target", TARGETS["aarch64"], "-o", str(obj)], timeout=120)
        self.assertGreater(obj.stat().st_size, 1 << 20,
                           "the regression must actually cross literal-pool reach")

    def clang22_assembler(self, isa):
        override = os.environ.get("OCORE_TEST_CLANG22")
        sdk = Path.home() / ".cache/ostadix-toolchains/llvm-22.1.6/sdk"
        candidates = [override] if override else [*(str(path) for path in sorted(
            sdk.glob("LLVM-22.1.6-*/bin/clang"))), "clang-22", "clang22", "clang"]
        for candidate in candidates:
            executable = shutil.which(candidate)
            if executable is None:
                if override:
                    self.fail(f"requested Clang 22.1.6 unavailable: {candidate}")
                continue
            version = self.run_command([executable, "--version"])
            if version.returncode == 0 and re.search(r"\bclang version 22\.1\.6\b", version.stdout):
                targets = self.succeeded([executable, "--print-targets"]).stdout
                if re.search(rf"\b{isa}\b", targets):
                    return executable
                self.skipTest(f"Clang 22.1.6 lacks the {isa} target")
            if override:
                self.fail(f"requested assembler is not Clang 22.1.6: {version.stdout}{version.stderr}")
        self.skipTest("Clang 22.1.6 unavailable; set OCORE_TEST_CLANG22 to require it")

    def check_switch_phi_transfer(self, isa, count):
        clang, linker = self.clang22_assembler(isa), shutil.which("ld.lld")
        if linker is None:
            self.skipTest("LLD required for complete switch object linking")
        source = self.verified_input(large_phi_switch_module(isa, count))
        assembly = source.with_suffix(".s")
        obj, executable = self.directory / "switch.o", self.directory / "switch.elf"
        self.succeeded([self.compiler, str(source), "--input-kind", "native-ir",
                        "--emit", "asm", "--target", TARGETS[isa], "-o", str(assembly)],
                       timeout=120)
        options = ["-march=rv64gc", "-mabi=lp64"] if isa == "riscv64" else []
        self.succeeded([clang, "-target", TARGETS[isa], *options, "-c", "-x", "assembler",
                        str(assembly), "-o", str(obj)], timeout=120)
        self.assertGreater(obj.stat().st_size, 1 << 20,
                           "the PHI edge copies must actually cross conditional-transfer reach")
        mode = "aarch64elf" if isa == "aarch64" else "elf64lriscv"
        self.succeeded([linker, "-static", "-m", mode, "-e", "large_phi_switch",
                        str(obj), "-o", str(executable)])
        self.assertTrue(executable.is_file())

    def test_aarch64_switch_skip_crosses_large_phi_edge_copies(self):
        # This verified fixture formerly failed B.cond's one-megabyte fixup.
        self.check_switch_phi_transfer("aarch64", 16384)

    def test_rv64_switch_skip_crosses_large_phi_edge_copies(self):
        # The assembler relaxed BNE to BEQ+JAL; LLD rejected that JAL's
        # 1,530,258-byte displacement. Own emission must use a long transfer.
        self.check_switch_phi_transfer("riscv64", 32768)

    def test_rv64_block_jump_over_one_megabyte_assembles_and_links(self):
        clang, linker = shutil.which("clang"), shutil.which("ld.lld")
        if clang is None or linker is None:
            self.skipTest("Clang and LLD required for long-transfer object/link test")
        targets = self.succeeded([clang, "--print-targets"]).stdout
        if not re.search(r"\briscv64\b", targets):
            self.skipTest("installed Clang lacks RISC-V target")
        # This is a measured regression fixture: the previous near JAL failed
        # its fixup on this complete module. It is not an input-size limit.
        fn = function("long_branch")
        fn["blocks"] = [
            {"id": 0, "instructions": [], "terminator": {"op": "jump", "target": 2}},
            {"id": 1, "instructions": [instruction(i, I64, {
                "op": "binary", "kind": "add", "lhs": integer(I64, 1),
                "rhs": integer(I64, 1), "flags": []}) for i in range(70000)],
             "terminator": {"op": "unreachable"}},
            {"id": 2, "instructions": [],
             "terminator": {"op": "return", "value": integer(I64, 0)}},
        ]
        source = self.verified_input(module("riscv64", [fn]))
        obj, executable = self.directory / "long.o", self.directory / "long.elf"
        self.succeeded([self.compiler, str(source), "--input-kind", "native-ir",
                        "--target", TARGETS["riscv64"], "-o", str(obj)], timeout=120)
        self.assertGreater(obj.stat().st_size, 1 << 20,
                           "the regression must actually cross near-JAL reach")
        self.succeeded([linker, "-m", "elf64lriscv", "-e", "long_branch", str(obj),
                        "-o", str(executable)])
        self.assertTrue(executable.is_file())


if __name__ == "__main__":
    unittest.main()
