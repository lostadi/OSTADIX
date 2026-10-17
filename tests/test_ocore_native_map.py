"""Artifact-bound imported-IR assembly maps. Set OCOREC; never builds Cargo.

These maps identify assembly byte ranges, not machine PCs or executions.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_ocore_native_import_backend import (
    ROOT, TARGETS, I1, I64, function, instruction, integer, module, value,
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def map_module(isa="x86_64"):
    fn = function("mapped_choose", params=(I1, I64, I64))
    fn["entry"] = 7
    fn["blocks"] = [
        {"id": 7, "instructions": [{"result": None, "operation": {
            "op": "assume", "condition": integer(I1, 1)}}],
         "terminator": {"op": "branch", "condition": value(0),
                        "on_true": 11, "on_false": 23}},
        {"id": 11, "instructions": [instruction(3, I64, {
            "op": "binary", "kind": "add", "lhs": value(1),
            "rhs": value(2), "flags": []})],
         "terminator": {"op": "jump", "target": 23}},
        {"id": 23, "instructions": [instruction(4, I64, {
            "op": "phi", "incoming": [{"block": 7, "value": value(1)},
                                          {"block": 11, "value": value(3)}]})],
         "terminator": {"op": "return", "value": value(4)}},
    ]
    declaration = function("declared_only")
    declaration.update(entry=None, blocks=[])
    return module(isa, [declaration, fn])


class NativeMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        chosen = os.environ.get("OCOREC", str(ROOT / "target/debug/ocorec"))
        path = Path(shutil.which(chosen) or chosen)
        if not path.is_absolute():
            path = ROOT / path
        if not path.is_file() or not os.access(path, os.X_OK):
            raise unittest.SkipTest("ocorec unavailable; build separately or set OCOREC")
        cls.compiler = str(path.resolve())

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-native-map-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def run_command(self, command):
        return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=60)

    def succeeded(self, command):
        result = self.run_command(command)
        self.assertEqual(result.returncode, 0,
                         f"{command!r}\n{result.stdout}\n{result.stderr}")
        return result

    def source(self, native_module=None, name="input.json"):
        path = self.directory / name
        path.write_text(json.dumps(native_module or map_module()), encoding="utf-8")
        return path

    def compile_args(self, source, output, sidecar=None, isa="x86_64", emit="asm", **extra):
        command = [self.compiler, str(source), "--input-kind", "native-ir",
                   "--target", TARGETS[isa], "--emit", emit, "-o", str(output)]
        if sidecar is not None:
            command.extend(["--native-map", str(sidecar)])
        if extra.get("keep_assembly"):
            command.append("--keep-asm")
        return command

    def verify_args(self, source, sidecar, assembly, artifact, isa="x86_64"):
        return [self.compiler, str(source), "--input-kind", "native-ir",
                "--target", TARGETS[isa], "--verify-native-map", str(sidecar),
                "--map-assembly", str(assembly), "--map-artifact", str(artifact)]

    def assert_bindings(self, source, assembly, artifact, sidecar, kind):
        record = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(record["format"], "ocore-native-artifact-map-v1")
        self.assertEqual(record["module_file_sha256"], sha256(source))
        self.assertEqual(record["artifact_kind"], kind)
        self.assertEqual(record["artifact_sha256"], sha256(artifact))
        self.assertEqual(record["artifact_bytes"], artifact.stat().st_size)
        inner = record["assembly"]
        self.assertEqual(inner["format"], "ocore-native-assembly-map-v1")
        self.assertEqual(inner["assembly_sha256"], sha256(assembly))
        self.assertEqual(inner["assembly_bytes"], assembly.stat().st_size)
        self.assertEqual(inner["input_sha256"], "0" * 64)
        self.succeeded(self.verify_args(source, sidecar, assembly, artifact,
                                       inner["target"].split("-")[0]))
        return record

    def test_three_isa_maps_preserve_assembly_and_cover_all_ir_sites(self):
        for isa in TARGETS:
            with self.subTest(isa=isa):
                source = self.source(map_module(isa), f"{isa}.json")
                assembly = self.directory / f"{isa}.s"
                plain = self.directory / f"{isa}-plain.s"
                sidecar = self.directory / f"{isa}.map.json"
                self.succeeded(self.compile_args(source, plain, isa=isa))
                self.succeeded(self.compile_args(source, assembly, sidecar, isa))
                self.assertEqual(plain.read_bytes(), assembly.read_bytes())
                first_map = sidecar.read_bytes()
                self.succeeded(self.compile_args(source, assembly, sidecar, isa))
                self.assertEqual(first_map, sidecar.read_bytes())
                record = self.assert_bindings(source, assembly, assembly, sidecar, "assembly")
                sites = record["assembly"]["sites"]
                self.assertTrue(all(site["function_index"] == 1 and
                                    site["function"] == "mapped_choose" for site in sites))
                instructions = [site for site in sites if site["kind"] == "instruction"]
                self.assertEqual([(site["block"], site["instruction"]) for site in instructions],
                                 [(7, 0), (11, 0), (23, 0)])
                for index in (0, 2):
                    self.assertEqual(instructions[index]["assembly_start"], instructions[index]["assembly_end"])
                self.assertLess(instructions[1]["assembly_start"], instructions[1]["assembly_end"])
                self.assertEqual(len([site for site in sites if site["kind"] == "terminator"]), 3)
                previous_end = 0
                for site in sites:
                    self.assertLessEqual(previous_end, site["assembly_start"])
                    self.assertLessEqual(site["assembly_start"], site["assembly_end"])
                    self.assertLessEqual(site["assembly_end"], assembly.stat().st_size)
                    previous_end = site["assembly_end"]

    def test_three_isa_object_maps_bind_real_assembler_outputs(self):
        clang = shutil.which("clang")
        if clang is None:
            self.skipTest("Clang required for object artifact bindings")
        supported = self.succeeded([clang, "--print-targets"]).stdout
        for isa in TARGETS:
            with self.subTest(isa=isa):
                target_name = "x86-64" if isa == "x86_64" else isa
                if target_name not in supported:
                    self.skipTest(f"Clang lacks {isa}")
                source = self.source(map_module(isa), f"{isa}.json")
                obj = self.directory / f"{isa}.o"
                sidecar = self.directory / f"{isa}.map.json"
                self.succeeded(self.compile_args(source, obj, sidecar, isa, "obj",
                                                keep_assembly=True, clang=clang))
                self.assertEqual(obj.read_bytes()[:4], b"\x7fELF")
                assembly = obj.with_suffix(".s")
                self.assert_bindings(source, assembly, obj, sidecar, "object")
                plain = self.directory / f"{isa}-plain.o"
                self.succeeded(self.compile_args(source, plain, isa=isa, emit="obj", clang=clang))
                self.assertEqual(obj.read_bytes(), plain.read_bytes())
                obj.write_bytes(obj.read_bytes() + b"tampered")
                result = self.run_command(self.verify_args(source, sidecar, assembly, obj, isa))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("binding mismatch", result.stderr)

    def test_verifier_rejects_tampering_missing_reordered_sites_and_stale_module(self):
        source = self.source()
        assembly, sidecar = self.directory / "out.s", self.directory / "out.map.json"
        self.succeeded(self.compile_args(source, assembly, sidecar))
        original = json.loads(sidecar.read_text(encoding="utf-8"))
        mutants = []
        missing = copy.deepcopy(original)
        missing["assembly"]["sites"].pop(3)
        mutants.append(missing)
        reordered = copy.deepcopy(original)
        reordered["assembly"]["sites"].reverse()
        mutants.append(reordered)
        ranged = copy.deepcopy(original)
        ranged["assembly"]["sites"][0]["assembly_end"] -= 1
        mutants.append(ranged)
        unknown = copy.deepcopy(original)
        unknown["execution_authority"] = True
        mutants.append(unknown)
        for mutant in mutants:
            sidecar.write_text(json.dumps(mutant), encoding="utf-8")
            self.assertNotEqual(self.run_command(self.verify_args(source, sidecar, assembly, assembly)).returncode, 0)
        sidecar.write_text(json.dumps(original), encoding="utf-8")
        native = json.loads(source.read_text(encoding="utf-8"))
        native["name"] += "-changed"
        source.write_text(json.dumps(native), encoding="utf-8")
        self.assertNotEqual(self.run_command(self.verify_args(source, sidecar, assembly, assembly)).returncode, 0)

    def test_verifier_rejects_modified_assembly_even_with_recomputed_claimed_hashes(self):
        source = self.source()
        assembly, sidecar = self.directory / "out.s", self.directory / "out.map.json"
        self.succeeded(self.compile_args(source, assembly, sidecar))
        with assembly.open("a", encoding="utf-8") as output:
            output.write("# forged assembly\n")
        record = json.loads(sidecar.read_text(encoding="utf-8"))
        record["assembly"]["assembly_sha256"] = record["artifact_sha256"] = sha256(assembly)
        record["assembly"]["assembly_bytes"] = record["artifact_bytes"] = assembly.stat().st_size
        sidecar.write_text(json.dumps(record), encoding="utf-8")
        self.assertNotEqual(self.run_command(self.verify_args(source, sidecar, assembly, assembly)).returncode, 0)

    def test_failed_verification_or_backend_removes_stale_map(self):
        source = self.source()
        output, sidecar = self.directory / "out.s", self.directory / "out.map.json"
        self.succeeded(self.compile_args(source, output, sidecar))
        source.write_text("{}", encoding="utf-8")
        self.assertNotEqual(self.run_command(self.compile_args(source, output, sidecar)).returncode, 0)
        self.assertFalse(sidecar.exists())
        native = map_module()
        native["target"]["triple"] = "aarch64-unknown-linux-gnu"
        source.write_text(json.dumps(native), encoding="utf-8")
        sidecar.write_text("old successful map", encoding="utf-8")
        self.assertNotEqual(self.run_command(self.compile_args(source, output, sidecar)).returncode, 0)
        self.assertFalse(sidecar.exists())

    def test_original_llvm_input_is_protected_and_failed_import_removes_stale_map(self):
        source = self.directory / "input.ll"
        source.write_text("not LLVM IR\n", encoding="utf-8")
        output, sidecar = self.directory / "out.s", self.directory / "out.map.json"
        original = source.read_bytes()
        command = [self.compiler, str(source), "--input-kind", "llvm-ir",
                   "--emit", "asm", "-o", str(output), "--native-map"]
        self.assertNotEqual(self.run_command([*command, str(source)]).returncode, 0)
        self.assertEqual(source.read_bytes(), original)
        sidecar.write_text("old successful map", encoding="utf-8")
        self.assertNotEqual(self.run_command([*command, str(sidecar)]).returncode, 0)
        self.assertFalse(sidecar.exists())

    def test_failed_assembler_removes_stale_map(self):
        source = self.source()
        output, sidecar = self.directory / "out.o", self.directory / "out.map.json"
        sidecar.write_text("old successful map", encoding="utf-8")
        shim_directory = self.directory / "failing-assembler"
        shim_directory.mkdir()
        clang = shim_directory / "clang"
        clang.write_text("#!/bin/sh\nexit 19\n", encoding="utf-8")
        clang.chmod(0o700)
        environment = os.environ.copy()
        environment["PATH"] = str(shim_directory)
        result = subprocess.run(self.compile_args(source, output, sidecar, emit="obj"),
                                cwd=ROOT, env=environment, text=True,
                                capture_output=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(sidecar.exists())

    def test_mapped_llvm_import_matches_retained_native_snapshot_bytes(self):
        library = os.environ.get("OCORE_TEST_LLVM22_LIBRARY")
        library_sha256 = os.environ.get("OCORE_TEST_LLVM22_SHA256")
        if not library or not library_sha256:
            self.skipTest("set OCORE_TEST_LLVM22_LIBRARY and OCORE_TEST_LLVM22_SHA256 to a validated LLVM22.1.6 parser")
        self.assertEqual(sha256(Path(library)), library_sha256)
        source = self.directory / "mapped-import.ll"
        source.write_text('target triple = "riscv64-unknown-linux-gnu"\n'
                          'target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"\n'
                          'define i64 @mapped_import(i64 %input) {\n'
                          '  %sum = add i64 %input, 1\n'
                          '  ret i64 %sum\n}\n', encoding="utf-8")
        assembly = self.directory / "mapped-import.s"
        snapshot = self.directory / "mapped-import.native-ir.json"
        sidecar = self.directory / "mapped-import.map.json"
        command = [self.compiler, str(source), "--input-kind", "llvm-ir",
                   "--llvm-library", library, "--llvm-sha256", library_sha256,
                   "--target", TARGETS["riscv64"]]
        self.succeeded([*command, "--emit", "mir", "-o", str(snapshot)])
        self.succeeded([*command, "--emit", "asm", "-o", str(assembly),
                        "--native-map", str(sidecar)])
        record = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(record["module_file_sha256"], sha256(snapshot))
        self.assertEqual(record["assembly"]["input_sha256"], sha256(source))
        self.succeeded(self.verify_args(snapshot, sidecar, assembly, assembly, "riscv64"))

    def test_path_collisions_preserve_inputs_outputs_symlinks_and_hardlinks(self):
        source = self.source()
        output = self.directory / "out.s"
        output.write_text("previous output", encoding="utf-8")
        for protected in (source, output):
            for style in ("same", "symlink", "hardlink"):
                with self.subTest(protected=protected.name, style=style):
                    before = protected.read_bytes()
                    if style == "same":
                        sidecar = protected
                    else:
                        sidecar = self.directory / f"{protected.name}-{style}"
                        if style == "symlink":
                            sidecar.symlink_to(protected)
                        else:
                            os.link(protected, sidecar)
                    self.assertNotEqual(self.run_command(self.compile_args(source, output, sidecar)).returncode, 0)
                    self.assertEqual(before, protected.read_bytes())
                    self.assertTrue(sidecar.exists())

    def test_object_and_retained_assembly_collision_is_rejected_before_overwrite(self):
        source = self.source()
        output = self.directory / "out.s"
        output.write_text("previous artifact", encoding="utf-8")
        sidecar = self.directory / "map.json"
        self.assertNotEqual(self.run_command(self.compile_args(source, output, sidecar,
                                                              emit="obj", keep_assembly=True)).returncode, 0)
        self.assertEqual(output.read_text(encoding="utf-8"), "previous artifact")
        self.assertFalse(sidecar.exists())


if __name__ == "__main__":
    unittest.main()
