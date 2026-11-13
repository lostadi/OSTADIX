"""Reproducer input/recipe/retention contracts; these fixtures do not build a VM."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import struct
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

    def enable_linux_recovery(self):
        self.manifest["linux_recovery"] = {
            "kernel_image": 3, "aux_image": 4, "namespace_version": "9P2000.u",
            "kernel_backup_address": 0xd2000000, "kernel_max_bytes": 0x7e00000,
            "dtb_backup_address": 0xe2000000, "dtb_max_bytes": 0x10000,
            "initrd_backup_address": 0xda000000, "initrd_max_bytes": 0x8000000,
            "kernel_bytes_address": 0x6d000100, "dtb_bytes_address": 0x6d000108,
            "initrd_bytes_address": 0x6d000110,
        }
        self.manifest["loader_addresses"].update({
            "inputs/linux-recovery.Image": 0xd2000000,
            "inputs/linux-recovery.dtb": 0xe2000000,
            "inputs/linux-recovery.initramfs": 0xda000000,
        })
        for target, original in (
                ("inputs/linux-recovery.Image", "inputs/linux.Image"),
                ("inputs/linux-recovery.dtb", "linux.dtb"),
                ("inputs/linux-recovery.initramfs", "inputs/linux.initramfs")):
            path = self.build / target
            path.write_bytes((self.build / original).read_bytes())
            self.manifest["artifacts"][target] = {**repro.identity(path), "path": target}
        original = self.build / "inputs/linux-original.initramfs"
        original.write_bytes(b"original initrd before namespace overlay")
        self.manifest["artifacts"]["inputs/linux-original.initramfs"] = {
            **repro.identity(original), "path": "inputs/linux-original.initramfs"}
        self.manifest["linux_initramfs_derivation"] = {
            "schema": "ostadix.o10-linux-initramfs/v1",
            "original_sha256": repro.identity(original)["sha256"],
            "derived_sha256": self.manifest["artifacts"]["inputs/linux.initramfs"]["sha256"],
            "changed_entries": ["init"], "disk_script_modified": False,
            "namespace_version": "9P2000.u",
        }
        self.save()


    def enable_native_fixture(self):
        self.enable_linux_recovery()
        _, fixture, fixture_builder, builder = repro.native_support()
        self.manifest.update(native_fixture=copy.deepcopy(fixture.CONTRACT),
                             domain_capacity=8, o10_qualification=True,
                             plan9_derivation_kind="qualified-original-userland")
        self.manifest["loader_addresses"].update({
            "inputs/native-fixture.kernel": fixture.CONTRACT["kernel_backup_pa"],
            "inputs/native-fixture.aux": fixture.CONTRACT["aux_backup_pa"]})
        self.manifest["source_artifacts"] = {}
        for name in builder.captured_source_paths("qualified-original-userland", native_fixture=True):
            path = self.build / "sources" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
            self.manifest["source_artifacts"][name] = {**repro.identity(path), "path": "sources/" + name}
        self.manifest["source_sha256"] = {
            name: item["sha256"] for name, item in self.manifest["source_artifacts"].items()}
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", header, 18, 183)
        struct.pack_into("<Q", header, 24, fixture.CONTRACT["entry"])
        contents = {"fixture.bin": b"synthetic native image: host admission fixture only",
                    "fixture.aux": fixture.auxiliary_image(), "fixture.elf": bytes(header),
                    "fixture.su": b"synthetic stack-usage fixture"}
        artifacts = {}
        aliases = {"fixture.bin": "inputs/native-fixture.kernel",
                   "fixture.aux": "inputs/native-fixture.aux",
                   "fixture.elf": "native-fixture/fixture.elf",
                   "fixture.su": "native-fixture/fixture.su"}
        for name, data in contents.items():
            path = self.build / "native-fixture" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            artifacts[name] = repro.identity(path)
            alias = self.build / aliases[name]
            alias.parent.mkdir(parents=True, exist_ok=True)
            alias.write_bytes(data)
            self.manifest["artifacts"][aliases[name]] = {**repro.identity(alias), "path": aliases[name]}
        sources = set(fixture_builder.SOURCES) | {
            "scripts/build_o10_native_fixture.py", "scripts/o10_native_fixture.py"}
        records = {name: repro.identity(self.build / "sources" / name) for name in sources}
        commands = []
        for index in range(4):
            step = {"argv": ["synthetic-host-fixture-only"], "returncode": 0}
            for stream in ("stdout", "stderr"):
                path = self.build / ("native-fixture/command-%d.%s" % (index, stream))
                path.write_bytes(b"")
                step[stream] = repro.identity(path)
            commands.append(step)
        self.native_receipt = {
            "schema": "ostadix.o10-m3-native-fixture-build/v1",
            "built": True, "source_unchanged": True, "contract": copy.deepcopy(fixture.CONTRACT),
            "source_before": records, "source_after": copy.deepcopy(records),
            "artifacts": artifacts, "commands": commands}
        self.save_native_receipt()

    def save_native_receipt(self):
        path = self.build / "native-fixture/build.json"
        repro.write_json(path, self.native_receipt)
        self.manifest["artifacts"]["native-fixture/build.json"] = {
            **repro.identity(path), "path": "native-fixture/build.json"}
        self.save()

    def test_native_geometry_accepts_only_exact_closed_reserved_image_contract(self):
        self.enable_native_fixture()
        repro.inspect_build(self.build)
        original = copy.deepcopy(self.manifest)
        for group, field, replacement in (
                ("native_fixture", "private_ram_pa", 0x48000000),
                ("native_fixture", "kernel_backup_pa", 0xe2200000),
                ("native_fixture", "aux_bytes", 129),
                ("native_fixture", "baseline_grant", 1),
                ("native_fixture", "kind", True),
                ("loader_addresses", "inputs/native-fixture.kernel", 0xe2200000),
                ("loader_addresses", "inputs/native-fixture.aux", 0xe2400000)):
            changed = copy.deepcopy(original)
            changed[group][field] = replacement
            with self.subTest(group=group, field=field), self.assertRaisesRegex(ValueError, "exact admitted"):
                repro.validate_profile(changed)
        for field, replacement in (("domain_capacity", 2), ("o10_qualification", False),
                                   ("o10_qualification", 1)):
            changed = copy.deepcopy(original)
            changed[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "exact admitted"):
                repro.validate_profile(changed)
        changed = copy.deepcopy(original)
        del changed["linux_recovery"]
        with self.assertRaisesRegex(ValueError, "Linux recovery"):
            repro.validate_profile(changed)

    def test_native_source_closure_cannot_omit_a_module_or_drift_its_recipe(self):
        self.enable_native_fixture()
        original = copy.deepcopy(self.manifest)
        missing = "ocore/runtime/aarch64/native_namespace_uart.oc"
        del self.manifest["source_artifacts"][missing]
        del self.manifest["source_sha256"][missing]
        self.save()
        with self.assertRaisesRegex(ValueError, "canonical.*source closure"):
            repro.inspect_build(self.build)
        self.manifest = original
        name = "scripts/build_okernel_unified_world.py"
        path = self.build / "sources" / name
        path.write_bytes(path.read_bytes() + b"\n# changed captured recipe\n")
        self.manifest["source_artifacts"][name] = {**repro.identity(path), "path": "sources/" + name}
        self.manifest["source_sha256"][name] = repro.identity(path)["sha256"]
        self.save()
        with self.assertRaisesRegex(ValueError, "identity differs"):
            repro.inspect_build(self.build)

    def test_native_auxiliary_bytes_and_image_window_fail_even_with_updated_identities(self):
        self.enable_native_fixture()
        for name, data, message in (
                ("fixture.aux", b"x" * 128, "auxiliary bytes"),
                ("fixture.bin", b"x" * (0x100000 + 1), "image window"),
                ("fixture.elf", b"x" * 64, "AArch64")):
            alias = {"fixture.aux": "inputs/native-fixture.aux",
                     "fixture.bin": "inputs/native-fixture.kernel",
                     "fixture.elf": "native-fixture/fixture.elf"}[name]
            path = self.build / alias
            old = path.read_bytes()
            (self.build / "native-fixture" / name).write_bytes(data)
            path.write_bytes(data)
            self.native_receipt["artifacts"][name] = repro.identity(path)
            self.manifest["artifacts"][alias] = {**repro.identity(path), "path": alias}
            self.save_native_receipt()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                repro.inspect_build(self.build)
            (self.build / "native-fixture" / name).write_bytes(old)
            path.write_bytes(old)
            self.native_receipt["artifacts"][name] = repro.identity(path)
            self.manifest["artifacts"][alias] = {**repro.identity(path), "path": alias}
            self.save_native_receipt()

    def test_native_build_receipt_and_raw_compiler_logs_are_bound(self):
        self.enable_native_fixture()
        original = copy.deepcopy(self.native_receipt)
        for group, field, value, message in (
                (None, "built", False, "successful"),
                (None, "source_unchanged", 1, "successful"),
                ("contract", "irq", 51, "successful"),
                ("source_after", "scripts/o10_native_fixture.py", {}, "identity"),
                ("artifacts", "fixture.bin", {}, "identity")):
            self.native_receipt = copy.deepcopy(original)
            target = self.native_receipt if group is None else self.native_receipt[group]
            target[field] = value
            self.save_native_receipt()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                repro.inspect_build(self.build)
        for value in (1, False, None):
            self.native_receipt = copy.deepcopy(original)
            self.native_receipt["commands"][2]["returncode"] = value
            self.save_native_receipt()
            with self.subTest(returncode=value), self.assertRaisesRegex(ValueError, "did not succeed"):
                repro.inspect_build(self.build)
        self.native_receipt = original
        self.save_native_receipt()
        (self.build / "native-fixture/command-0.stderr").write_bytes(b"changed raw compiler output")
        with self.assertRaisesRegex(ValueError, "identity differs"):
            repro.inspect_build(self.build)

    def test_native_artifact_omission_and_alias_substitution_are_rejected(self):
        self.enable_native_fixture()
        original = copy.deepcopy(self.manifest)
        for name in ("inputs/native-fixture.kernel", "inputs/native-fixture.aux",
                     "native-fixture/build.json", "native-fixture/fixture.elf",
                     "native-fixture/fixture.su"):
            self.manifest = copy.deepcopy(original)
            del self.manifest["artifacts"][name]
            self.save()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "artifact closure"):
                repro.inspect_build(self.build)
        self.manifest = original
        self.save()
        (self.build / "native-fixture/fixture.bin").write_bytes(b"changed alias")
        with self.assertRaisesRegex(ValueError, "identity differs"):
            repro.inspect_build(self.build)

    def test_native_admission_helpers_work_in_a_relocated_reproduction_bundle(self):
        self.enable_native_fixture()
        bundle = self.root / "relocated-bundle"
        shutil.copytree(self.build, bundle / "captured-build")
        shutil.copyfile(SCRIPT, bundle / "reproduce.py")
        support = bundle / "support/native-admission"
        support.mkdir(parents=True)
        for name in repro.NATIVE_SUPPORT:
            shutil.copyfile(ROOT / "scripts" / name, support / name)
        result = subprocess.run(
            [sys.executable, "-B", "-c",
             "import importlib.util,pathlib; p=pathlib.Path('reproduce.py'); "
             "s=importlib.util.spec_from_file_location('relocated',p); "
             "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
             "v,paths=m.inspect_build(pathlib.Path('captured-build')); "
             "assert v['native_fixture']['kernel_image']==5; "
             "assert 'native-fixture/fixture.bin' in paths"],
            cwd=bundle, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_linux_recovery_profile_accepts_only_exact_reserved_loader_contract(self):
        self.enable_linux_recovery()
        repro.inspect_build(self.build)
        original = copy.deepcopy(self.manifest)
        for address in ("inputs/linux-recovery.Image", "inputs/linux-recovery.dtb",
                        "inputs/linux-recovery.initramfs"):
            value = copy.deepcopy(original)
            value["loader_addresses"][address] = 0x48000000
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, "exact admitted"):
                repro.validate_profile(value)
        for field, replacement in (("namespace_version", "9P2000"), ("kernel_image", True),
                                   ("initrd_max_bytes", 0x8000001)):
            value = copy.deepcopy(original)
            value["linux_recovery"][field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "exact admitted"):
                repro.validate_profile(value)
        value = copy.deepcopy(original)
        del value["linux_recovery"]
        with self.assertRaisesRegex(ValueError, "exact admitted"):
            repro.validate_profile(value)

    def test_all_linux_backup_bytes_must_equal_originals_with_updated_hashes(self):
        self.enable_linux_recovery()
        original = copy.deepcopy(self.manifest)
        for name in ("inputs/linux-recovery.Image", "inputs/linux-recovery.dtb",
                     "inputs/linux-recovery.initramfs"):
            path = self.build / name
            previous = path.read_bytes()
            path.write_bytes(previous + b" changed")
            self.manifest["artifacts"][name] = {**repro.identity(path), "path": name}
            self.save()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Linux recovery input"):
                repro.inspect_build(self.build)
            path.write_bytes(previous)
            self.manifest = copy.deepcopy(original)
            self.save()

    def test_linux_backup_missing_from_manifest_is_rejected(self):
        self.enable_linux_recovery()
        del self.manifest["artifacts"]["inputs/linux-recovery.initramfs"]
        self.save()
        with self.assertRaisesRegex(ValueError, "Linux recovery input"):
            repro.inspect_build(self.build)

    def test_linux_initrd_derivation_binds_both_payloads_and_only_init_overlay(self):
        self.enable_linux_recovery()
        original = copy.deepcopy(self.manifest)
        for field, value in (
                ("original_sha256", "a" * 64), ("derived_sha256", "b" * 64),
                ("changed_entries", ["init", "bin/sh"]), ("disk_script_modified", True),
                ("disk_script_modified", 0), ("namespace_version", "9P2000")):
            self.manifest = copy.deepcopy(original)
            self.manifest["linux_initramfs_derivation"][field] = value
            self.save()
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "derivation"):
                repro.inspect_build(self.build)

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

    def test_qualification_profile_fstring_is_extracted_without_general_evaluation(self):
        path = self.build / "sources" / repro.BUILDER
        original = path.read_text()
        template = "module fixture;\\npub const O10_QUALIFICATION: u64 = {1 if o10_qualification else 0};\\n"
        path.write_text(original.replace(repr(self.profile_text), 'f"""' + template + '"""'))
        for qualification in (False, True):
            self.manifest["o10_qualification"] = qualification
            self.assertEqual(repro.recipe(self.build, self.manifest)[2],
                             "module fixture;\npub const O10_QUALIFICATION: u64 = %d;\n" % qualification)
        for expression in ("1 if different_flag else 0", "__import__('os').system('false')",
                           "(lambda: 1)()", "1 if o10_qualification else 2",
                           "(1 if o10_qualification else 0)!r",
                           "(1 if o10_qualification else 0):04"):
            path.write_text(original.replace(repr(self.profile_text),
                            'f"""' + template.replace("1 if o10_qualification else 0", expression) + '"""'))
            with self.subTest(expression=expression), self.assertRaisesRegex(ValueError, "not a literal"):
                repro.recipe(self.build, self.manifest)
        path.write_text(original.replace(repr(self.profile_text), 'f"""' + template + '"""'))
        self.manifest["o10_qualification"] = 1
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
