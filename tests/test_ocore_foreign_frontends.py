"""Independent frontend evidence and fail-closed conformance gate checks."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import check_ocore_foreign_frontends as probe


def arguments(**kwargs):
    values = dict(rustc="rustc",ocorec=probe.ROOT/"target/debug/ocorec",llvm_library=None,
                  clang="clang",java="java",qemu_aarch64="qemu-aarch64",
                  qemu_riscv64="qemu-riscv64",targets=list(probe.TARGETS))
    values.update(kwargs)
    return argparse.Namespace(**values)


class FrontendEvidenceTests(unittest.TestCase):
    def test_java_golden_preserves_java_specific_integer_edges(self):
        output = probe.golden_java()
        lines = dict(line.split("=",1) for line in output.decode().splitlines())
        self.assertEqual(len(lines),70)
        self.assertEqual(lines["int_add_wrap"],"80000000")
        self.assertEqual(lines["long_add_wrap"],"8000000000000000")
        self.assertEqual(lines["int_shl_32"],lines["int_shl_0"])
        self.assertEqual(lines["int_shl_-1"],lines["int_shl_31"])
        self.assertEqual(lines["long_shl_64"],lines["long_shl_0"])
        self.assertEqual(lines["long_shr_-1"],"ffffffffffffffff")
        self.assertEqual(lines["long_ushr_-1"],"0000000000000001")
        self.assertEqual(lines["int_min_div_minus1"],"80000000")
        self.assertEqual(lines["long_min_div_minus1"],"8000000000000000")
        self.assertEqual(lines["long_min_rem_minus1"],"0000000000000000")
        self.assertEqual(lines["int_negative_div"],"fffffffe")
        self.assertEqual(lines["int_negative_rem"],"ffffffff")
        self.assertEqual(lines["char_zero_extend"],"0000ffff")
        self.assertEqual(lines["byte_sign_extend"],"ffffff80")
        self.assertEqual(lines["int_div_zero"],"java/lang/ArithmeticException")

    def test_tool_keeps_rustup_proxy_invocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rustup = directory/"rustup"
            rustup.write_text("#!/bin/sh\nexit 0\n")
            rustup.chmod(0o755)
            proxy = directory/"rustc"
            proxy.symlink_to(rustup)
            self.assertEqual(probe.tool(proxy,"rustc"),str(proxy))

    def test_missing_core_is_a_failure_with_install_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError,"rustup target add.*aarch64-unknown-linux-gnu"):
                probe.check_rust("aarch64",arguments(),{"sysroot":Path(temporary)},Path(temporary))

    def test_subset_never_claims_complete_conformance(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"version":"fixture","rustc":"fixture","sysroot":Path("fixture"),"library":Path("fixture"),
                   "library_sha256":"0"*64,"ocorec":"fixture","clang":"fixture","assembler":"fixture"}
            completed = subprocess.CompletedProcess([],0,b"fixture\n",b"")
            with mock.patch.object(probe,"tool",return_value="fixture"), \
                 mock.patch.object(probe,"check_java",return_value={"status":"reference_only"}), \
                 mock.patch.object(probe,"rust_environment",return_value=env), \
                 mock.patch.object(probe,"digest",return_value="0"*64), \
                 mock.patch.object(probe,"run",return_value=completed), \
                 mock.patch.object(probe,"check_rust",return_value={"status":"pass","output":"same"}):
                report = probe.check(arguments(targets=["x86_64"]),Path(temporary))
            self.assertFalse(report["all_three_rust_isas_passed"])
            self.assertFalse(report["conformance_gate_passed"])
            self.assertFalse(report["java_lowering_complete"])
            self.assertFalse(report["full_runtime_complete"])
            self.assertTrue(any("all three" in error for error in report["errors"]))

    def test_isa_mismatch_cannot_pass_even_when_all_runs_individually_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"version":"fixture","rustc":"fixture","sysroot":Path("fixture"),"library":Path("fixture"),
                   "library_sha256":"0"*64,"ocorec":"fixture","clang":"fixture","assembler":"fixture"}
            completed = subprocess.CompletedProcess([],0,b"fixture\n",b"")
            with mock.patch.object(probe,"tool",return_value="fixture"), \
                 mock.patch.object(probe,"check_java",return_value={"status":"reference_only"}), \
                 mock.patch.object(probe,"rust_environment",return_value=env), \
                 mock.patch.object(probe,"digest",return_value="0"*64), \
                 mock.patch.object(probe,"run",return_value=completed), \
                 mock.patch.object(probe,"check_rust",side_effect=[
                     {"status":"pass","output":"a"},{"status":"pass","output":"b"},{"status":"pass","output":"a"}]):
                report = probe.check(arguments(),Path(temporary))
            self.assertFalse(report["conformance_gate_passed"])
            self.assertTrue(any("differ across" in error for error in report["errors"]))

    def test_invalid_elf_isa_and_softfloat_abi_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/"fixture.o"
            data = bytearray(64)
            data[:6] = b"\x7fELF\x02\x01"
            data[16:18] = (1).to_bytes(2,"little")
            data[18:20] = (243).to_bytes(2,"little")
            data[48:52] = (4).to_bytes(4,"little")
            path.write_bytes(data)
            with self.assertRaisesRegex(RuntimeError,"LP64"):
                probe.elf(path,243,1)
            with self.assertRaisesRegex(RuntimeError,"incorrect ELF"):
                probe.elf(path,183,1)

    def test_actual_java_reference_and_complete_fixture_method_inventory(self):
        java = shutil.which("java")
        if java is None:
            self.skipTest("Java 25 reference runtime unavailable; full CLI gate fails without it")
        version = subprocess.run([java,"-version"],capture_output=True,timeout=15)
        if b'version "25.' not in version.stderr:
            self.skipTest("Java 25 reference runtime unavailable; full CLI gate fails without it")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = probe.check_java(java,directory)
            self.assertEqual(report["status"],"reference_only")
            self.assertEqual(report["golden_cases"],70)
            self.assertEqual(report["verified_ocore_method_count"],0)
            self.assertFalse(report["lowering_complete"])
            inventory = json.loads((directory/"java-method-inventory.json").read_text())
            names = {entry["identity"]["method_name"] for entry in inventory["methods"]}
            self.assertIn("<init>",names)
            self.assertIn("<clinit>",names)
            self.assertIn("divideInt",names)
            self.assertIn("shiftUnsignedLong",names)
            self.assertTrue({"castByte","castShort","castChar","castInt","castLong"} <= names)
            self.assertEqual(report["concrete_method_count"],len(inventory["methods"]))

    def test_failed_cli_rerun_replaces_stale_success_and_retains_real_inventory_paths(self):
        java = shutil.which("java")
        if java is None or shutil.which("rustc") is None:
            self.skipTest("host frontend tools unavailable; strict CLI still fails without them")
        version = subprocess.run([java,"-version"],capture_output=True,timeout=15)
        if b'version "25.' not in version.stderr:
            self.skipTest("Java 25 reference runtime unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            receipt = directory/"conformance.json"
            receipt.write_text(json.dumps({"format":"ocore-foreign-frontend-conformance-v1",
                                           "conformance_gate_passed":True}))
            result = subprocess.run([sys.executable,str(Path(probe.__file__)),"--ocorec",
                                     str(directory/"missing-ocorec"),"--java",java,
                                     "--targets","x86_64","--output-dir",str(directory)],
                                    capture_output=True,timeout=30)
            self.assertEqual(result.returncode,1)
            report = json.loads(receipt.read_text())
            self.assertFalse(report["conformance_gate_passed"])
            self.assertTrue(report["errors"])
            self.assertEqual(report["java"]["status"],"reference_only")
            artifacts = Path(report["artifact_directory"])
            self.assertTrue(artifacts.is_dir())
            inventory = json.loads((artifacts/"java-method-inventory.json").read_text())
            for source in inventory["sources"]:
                self.assertTrue(Path(source["path"]).exists(),"inventory source moved or deleted after capture")

    @unittest.skipUnless(os.environ.get("OCORE_TEST_FOREIGN_FRONTENDS") == "1",
                         "set OCORE_TEST_FOREIGN_FRONTENDS=1 for actual strict all-ISA Rust/Java gate")
    def test_actual_all_three_rust_frontends_and_java_reference(self):
        args = arguments(qemu_aarch64=os.environ.get("OCORE_TEST_QEMU_AARCH64","qemu-aarch64"),
                         qemu_riscv64=os.environ.get("OCORE_TEST_QEMU_RISCV64","qemu-riscv64"))
        with tempfile.TemporaryDirectory() as temporary:
            report = probe.check(args,Path(temporary))
            self.assertTrue(report["conformance_gate_passed"],json.dumps(report["errors"],indent=2))
            self.assertEqual(set(report["rust"]),set(probe.TARGETS))
            for value in report["rust"].values():
                self.assertEqual(value["cases"],28672)
                self.assertTrue(value["negative_reference_rejected"])


if __name__ == "__main__":
    unittest.main()
