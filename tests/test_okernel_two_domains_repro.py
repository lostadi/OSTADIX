"""Reproducer input/recipe/retention contracts; these fixtures do not build a VM."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_okernel_two_domains_repro.py"
SPEC = importlib.util.spec_from_file_location("two_domains_repro_test", SCRIPT)
repro = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repro)


def required_profile():
    tree = ast.parse(SCRIPT.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "validate_profile")
    required = next(node for node in function.body if isinstance(node, ast.Assign))
    return ast.literal_eval(required.value)


class TwoDomainsReproTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="two domains repro fixture ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.build = self.root / "admitted"
        self.build.mkdir()
        self.manifest = required_profile()
        self.order = ("ocore/runtime/aarch64/unified_world.oc", "ocore/runtime/aarch64/coordinator_uart.oc")
        self.profile_text = "module runtime::aarch64::kernel_world_profile;\npub const PERSISTENT: u64 = 1;\n"
        builder = ("SOURCES = " + repr(self.order) + "\n"
                   "def linux_dts(template, initrd_bytes):\n"
                   "    return template.replace('INITRD_END', hex(0x48000000 + initrd_bytes))\n"
                   "def build():\n"
                   "    profile.write_text(" + repr(self.profile_text) + ")\n")
        self.sources = {repro.BUILDER: builder.encode(), repro.ASSEMBLY: b".text\n", repro.LINKER: b"SECTIONS {}\n",
                        repro.LINUX_DTS: b"/dts-v1/; / { end=INITRD_END; };\n", repro.PLAN9_DTS: b"/dts-v1/; / {};\n",
                        **{name: b"module fixture;\n" for name in self.order}}
        source_artifacts = {}
        for name, data in self.sources.items():
            path = self.build / "sources" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            source_artifacts[name] = {**repro.identity(path), "path": "sources/" + name}
        self.manifest["source_artifacts"] = source_artifacts
        self.manifest["source_sha256"] = {name: item["sha256"] for name, item in source_artifacts.items()}
        data = {name: ("fixture admitted " + name).encode() for name in repro.COMPARE}
        data.update({"inputs/linux.Image": b"original Linux fixture", "inputs/linux.initramfs": b"initrd fixture",
                     "inputs/plan9.kernel": b"original Plan9 fixture", "inputs/plan9-recovery.kernel": b"original Plan9 fixture",
                     "inputs/plan9-recovery.dtb": data["plan9.dtb"], "profile.oc": self.profile_text.encode(),
                     "linux.dts": self.sources[repro.LINUX_DTS].replace(b"INITRD_END", hex(0x48000000 + len(b"initrd fixture")).encode()),
                     "plan9.dts": self.sources[repro.PLAN9_DTS]})
        artifacts = {}
        for name, contents in data.items():
            path = self.build / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
            artifacts[name] = {**repro.identity(path), "path": name}
        self.manifest["artifacts"] = artifacts
        self.save()

    def save(self):
        repro.write_json(self.build / "monitor-profile.json", self.manifest)

    def test_captured_closure_and_source_order_are_bound(self):
        manifest, files = repro.inspect_build(self.build)
        order, generator, profile = repro.recipe(self.build, manifest)
        self.assertEqual(order, self.order)
        self.assertEqual(profile.encode(), (self.build / "profile.oc").read_bytes())
        self.assertEqual(generator(self.sources[repro.LINUX_DTS].decode(), len(b"initrd fixture")).encode(),
                         (self.build / "linux.dts").read_bytes())
        self.assertTrue({"sources/" + name for name in self.sources} <= files.keys())
        self.assertTrue(set(repro.COMPARE) <= files.keys())

    def test_old_single_domain_and_tampered_native_contract_fail(self):
        for changes in ({"schema": "ostadix.kernel-world-linux-monitor/v1"}, {"profile": "package-domain"},
                        {"outer_ram_bytes": 0x80000000}, {"coordinator_uart": {}}, {"plan9_recovery": {}},
                        {"domains": self.manifest["domains"][:1]}):
            value = copy.deepcopy(self.manifest)
            value.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                repro.validate_profile(value)
        value = copy.deepcopy(self.manifest)
        value["domains"][1]["id"] = True
        with self.assertRaises(ValueError):
            repro.validate_profile(value)

    def test_artifact_source_map_size_and_missing_source_tampering_fail(self):
        original = copy.deepcopy(self.manifest)
        for key in ("bytes", "sha256", "path"):
            self.manifest = copy.deepcopy(original)
            self.manifest["artifacts"]["monitor.elf"][key] = 1 if key == "bytes" else "wrong"
            self.save()
            with self.subTest(key=key), self.assertRaises(ValueError):
                repro.inspect_build(self.build)
        self.manifest = copy.deepcopy(original)
        self.manifest["source_sha256"][repro.ASSEMBLY] = "f" * 64
        self.save()
        with self.assertRaisesRegex(ValueError, "digest maps"):
            repro.inspect_build(self.build)
        self.manifest = copy.deepcopy(original)
        del self.manifest["source_sha256"][repro.LINKER]
        del self.manifest["source_artifacts"][repro.LINKER]
        self.save()
        with self.assertRaisesRegex(ValueError, "source closure"):
            repro.inspect_build(self.build)

    def test_recovery_backups_must_equal_originals_even_with_updated_hashes(self):
        path = self.build / "inputs/plan9-recovery.kernel"
        path.write_bytes(b"different self-consistent backup")
        self.manifest["artifacts"]["inputs/plan9-recovery.kernel"] = {**repro.identity(path), "path": "inputs/plan9-recovery.kernel"}
        self.save()
        with self.assertRaisesRegex(ValueError, "recovery input"):
            repro.inspect_build(self.build)

    def test_absolute_traversal_noncanonical_and_symlink_paths_fail(self):
        for value in ("/etc/passwd", "../outside", "sources/../outside", "a//b", "./a", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                repro.relative(value)
        path = self.build / "sources" / repro.ASSEMBLY
        external = self.root / "external.S"
        external.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(external)
        with self.assertRaisesRegex(ValueError, "symlink"):
            repro.inspect_build(self.build)

    def test_compiler_order_missing_module_and_nonliteral_recipe_fail(self):
        path = self.build / "sources" / repro.BUILDER
        source = path.read_text()
        path.write_text(source.replace(repr(self.order), repr(tuple(reversed(self.order)))))
        self.assertEqual(repro.recipe(self.build, self.manifest)[0], tuple(reversed(self.order)))
        path.write_text(source.replace(repr(self.order), repr(self.order[:1])))
        with self.assertRaisesRegex(ValueError, "order/closure"):
            repro.recipe(self.build, self.manifest)
        path.write_text(source.replace(repr(self.profile_text), "computed_profile()"))
        with self.assertRaisesRegex(ValueError, "not a literal"):
            repro.recipe(self.build, self.manifest)

    def test_five_commands_keep_exact_flags_and_paths_as_argv(self):
        calls = repro.commands(self.root / "source ; literal", self.root / "output spaces", self.root / "tools", self.order)
        self.assertEqual(len(calls), 5)
        self.assertEqual(calls[0][2:4], [str(self.root / "source ; literal" / name) for name in self.order])
        self.assertEqual(calls[0][4:10], ["--target", "aarch64-unknown-none", "--emit", "obj", "--keep-asm", "-o"])
        self.assertIn("--build-id=none", calls[2])
        self.assertIn("max-page-size=0x1000", calls[2])
        self.assertEqual([Path(call[0]).name for call in calls], ["ocorec", "clang", "ld.lld", "dtc", "dtc"])

    def test_capture_inventory_can_move_and_detects_tool_or_source_change(self):
        captured = self.root / "capture"
        captured.mkdir()
        shutil.copytree(self.build, captured / "captured-build")
        tools = captured / "tools/native"
        tools.mkdir(parents=True)
        (tools / "compiler").write_bytes(b"frozen compiler fixture")
        inventory = repro.inventory(captured, ("captured-build", "tools"))
        moved = self.root / "relocated"
        captured.rename(moved)
        repro.check_inventory(moved, inventory)
        (moved / "tools/native/compiler").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "identity differs"):
            repro.check_inventory(moved, inventory)

    def test_streaming_identity_and_freezer_override_do_not_need_file_digest(self):
        with patch.object(repro.hashlib, "file_digest", create=True, side_effect=AssertionError("Python3.11 API")):
            self.assertEqual(repro.identity(SCRIPT)["bytes"], SCRIPT.stat().st_size)
            freezer = repro.load_freezer(ROOT / "scripts/verify_okernel_unified_repro.py")
            self.assertIs(freezer.identity, repro.identity)
            self.assertEqual(freezer.identity(SCRIPT), repro.identity(SCRIPT))

    def test_host_elf_interpreter_is_recorded_from_original_program_headers(self):
        value = repro.elf_interpreter(Path(sys.executable).resolve())
        self.assertTrue(value is None or Path(value).is_absolute())
        fake = self.root / "not-elf"
        fake.write_bytes(b"not ELF")
        with self.assertRaisesRegex(ValueError, "ELF64"):
            repro.elf_interpreter(fake)

    def test_cli_refuses_existing_output_and_does_not_start_native_tools(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--build", str(self.build), "--output", str(self.build)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("new directory", result.stderr)
        self.assertFalse((self.build / "tools").exists())


if __name__ == "__main__":
    unittest.main()
