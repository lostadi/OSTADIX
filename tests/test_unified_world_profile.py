"""Check the actual unified builder's memory contract without compiling or booting.

Only original-kernel admission and external compiler processes are replaced in
the builder fixture. These tests qualify profile construction and validation,
not upstream authentication or simultaneous guest execution.
"""
import copy
import importlib.abc
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILDER = load("unified_profile_builder_test", "scripts/build_okernel_unified_world.py")
RUNNER = load("unified_profile_runner_test", "scripts/okernel_unified_world.py")
EXPECTED_RECOVERY = {
    "control_address": 0x6d000070, "control_bytes": 48,
    "kernel_backup_address": 0xd0000000, "kernel_max_bytes": 0x1000000,
    "dtb_backup_address": 0xd1000000, "dtb_max_bytes": 0x10000,
    "pause": 1, "restart": 2,
}


class AdmissionFixture(importlib.abc.Loader):
    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.admit_derivation = lambda receipt, artifact: {"source_commit": "fixture-original-source"}
        module.inspect_uimage = lambda path: ({"fixture": True}, b"captured Plan9 kernel fixture")


class UnifiedWorldProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="unified profile contract ")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        payload = directory / "payload"
        payload.mkdir()
        image = payload / "Image"
        image.write_bytes(b"captured Linux image fixture")
        (payload / "linux.config").write_text("CONFIG_ARM_GIC_V3=y\nCONFIG_PROC_CHILDREN=y\n")
        from tests.test_o10_linux_profile import fixture_initramfs
        (payload / "initramfs.cpio").write_bytes(fixture_initramfs())
        (payload / "linux-payload.json").write_text(json.dumps({
            "schema": "ostadix.real-linux-payload/v1", "profile": "package-domain",
            "linux_version": "6.12.43", "source_modifications": False,
            "source_archive_sha256": "0fcbbbbcd456e87bbbfc8bf37af541fda62ccfcce76903503424fd101ef7bdee",
            "artifacts": {"Image": BUILDER.identity(image),
                          "initramfs.cpio": BUILDER.identity(payload / "initramfs.cpio"),
                          "linux.config": BUILDER.identity(payload / "linux.config")},
        }))
        plan9, derivation = directory / "plan9.uimage", directory / "derivation.json"
        plan9.write_bytes(b"captured Plan9 container fixture")
        derivation.write_text("{}\n")
        tool = directory / "already-built-tool"
        tool.write_bytes(b"external compiler fixture")
        tool.chmod(0o755)
        cls.output = directory / "profile"
        cls.calls = []

        def compile_fixture(command, *, check):
            cls.calls.append(command)
            output = Path(command[command.index("-o") + 1])
            output.write_bytes(b"fixture external tool output: " + output.name.encode())
            return subprocess.CompletedProcess(command, 0)

        admission = importlib.machinery.ModuleSpec("unified_plan9_admission", AdmissionFixture())
        with mock.patch.object(BUILDER.importlib.util, "spec_from_file_location", return_value=admission), \
                mock.patch.object(BUILDER.subprocess, "run", side_effect=compile_fixture):
            cls.profile = BUILDER.build(payload, plan9, derivation, cls.output, tool,
                                        str(tool), str(tool), str(tool))
            normal_calls = cls.calls
            cls.calls = []
            cls.recovery_output = directory / "recovery profile"
            cls.recovery_profile = BUILDER.build(
                payload, plan9, derivation, cls.recovery_output, tool,
                str(tool), str(tool), str(tool), plan9_recovery=True)
            cls.recovery_calls, cls.calls = cls.calls, normal_calls
            cls.calls = []
            cls.qualification_output = directory / "qualification profile"
            cls.qualification_profile = BUILDER.build(
                payload, plan9, derivation, cls.qualification_output, tool,
                str(tool), str(tool), str(tool), plan9_recovery=True, o10_qualification=True)
            cls.calls = normal_calls
        cls.template = (ROOT / "ocore/kernel/aarch64/kernel_world/guest.dts").read_text()

    def test_fault_injection_requires_explicit_qualification_build(self):
        self.assertIs(self.profile["o10_qualification"], False)
        self.assertIn("pub const O10_QUALIFICATION: u64 = 0;", (self.output / "profile.oc").read_text())
        self.assertIs(self.recovery_profile["o10_qualification"], False)
        self.assertIs(self.qualification_profile["o10_qualification"], True)
        self.assertIn("pub const O10_QUALIFICATION: u64 = 1;",
                      (self.qualification_output / "profile.oc").read_text())
        RUNNER.validate_profile(self.qualification_profile)

    def test_builder_manifest_is_accepted_and_artifacts_are_bound(self):
        RUNNER.validate_profile(self.profile)
        self.assertEqual(json.loads((self.output / "monitor-profile.json").read_text()), self.profile)
        for name, record in self.profile["artifacts"].items():
            with self.subTest(artifact=name):
                self.assertEqual(record["path"], name)
                self.assertFalse(Path(name).is_absolute())
                RUNNER.checked(self.output / name, record)
        self.assertEqual(len(self.calls), 5)  # Native compiler, assembler, linker, two DTBs.

    def test_guest_physical_windows_and_vmids_are_independent(self):
        linux, plan9 = self.profile["domains"]
        self.assertEqual((linux["id"], plan9["id"]), (0, 1))
        self.assertEqual((linux["vmid"], plan9["vmid"]), (1, 2))
        self.assertEqual(linux["guest_ram_ipa"], plan9["guest_ram_ipa"])
        self.assertEqual(linux["guest_ram_pa"] + linux["guest_ram_bytes"], 0x68000000)
        self.assertGreaterEqual(plan9["guest_ram_pa"], linux["guest_ram_pa"] + linux["guest_ram_bytes"])
        for domain in (linux, plan9):
            self.assertEqual(domain["guest_ram_bytes"], 0x20000000)
            self.assertGreaterEqual(domain["guest_ram_pa"], 0x40000000)
            self.assertLessEqual(domain["guest_ram_pa"] + domain["guest_ram_bytes"],
                                 0x40000000 + self.profile["outer_ram_bytes"])

    def test_entry_arguments_are_guest_addresses_and_loaders_are_host_addresses(self):
        linux, plan9 = self.profile["domains"]
        addresses = self.profile["loader_addresses"]

        def translate(domain, host):
            self.assertGreaterEqual(host, domain["guest_ram_pa"])
            self.assertLess(host, domain["guest_ram_pa"] + domain["guest_ram_bytes"])
            return host - domain["guest_ram_pa"] + domain["guest_ram_ipa"]

        self.assertEqual(linux["x0"], 0x47e00000)
        self.assertEqual(addresses["linux.dtb"], 0x4fe00000)
        self.assertEqual(translate(linux, addresses["linux.dtb"]), linux["x0"])
        self.assertEqual(translate(linux, addresses["inputs/linux.Image"]), linux["entry"])
        self.assertEqual(translate(linux, addresses["inputs/linux.initramfs"]), 0x48000000)
        self.assertEqual(translate(plan9, addresses["plan9.dtb"]), plan9["x0"])
        self.assertEqual(translate(plan9, addresses["inputs/plan9.kernel"]), plan9["entry"])

    def test_native_volumes_and_controls_are_not_guest_ram(self):
        namespace = self.profile["namespace"]
        console = self.profile["plan9_console"]
        mux = self.profile["console_mux"]
        ranges = [(self.profile["block_backing"]["address"], self.profile["block_backing"]["bytes"]),
                  (namespace["address"], namespace["bytes"]),
                  (namespace["epoch_address"], 112),
                  (console["input_address"], 8 + console["input_bytes"]),
                  (console["output_address"], 8 + console["output_bytes"]),
                  (mux["linux_output_address"], 8 + mux["output_bytes"])]
        for base, size in ranges:
            with self.subTest(base=hex(base)):
                for domain in self.profile["domains"]:
                    self.assertTrue(base + size <= domain["guest_ram_pa"]
                                    or domain["guest_ram_pa"] + domain["guest_ram_bytes"] <= base)
        for first, (base, size) in enumerate(ranges):
            for other, length in ranges[first + 1:]:
                self.assertTrue(base + size <= other or other + length <= base)
        self.assertEqual(namespace["quiescence_address"], namespace["epoch_address"] + 8)
        self.assertEqual(namespace["clock_address"], namespace["epoch_address"] + 16)
        self.assertEqual((namespace["linux_grant"], namespace["plan9_grant"],
                          namespace["native_peer_grant"]), (1, 4, 2))

    def test_console_mux_selectors_and_complete_output_rings_are_bound(self):
        mux = self.profile["console_mux"]
        self.assertEqual(mux["escape"], 0x1e)
        self.assertEqual(mux["linux_select"], ord("0"))
        self.assertEqual(mux["plan9_select"], ord("1"))
        self.assertEqual(mux["linux_output_address"], 0x6d040000)
        self.assertEqual(mux["output_bytes"], 65536)
        plan9 = self.profile["plan9_console"]
        self.assertEqual(plan9["output_address"], 0x6d020000)
        # Count headers are additional to the declared data capacities. Putting
        # the Linux header at +65536 would corrupt the final eight Plan9 bytes.
        self.assertLessEqual(plan9["output_address"] + 8 + plan9["output_bytes"],
                             mux["linux_output_address"])

    def test_gic_ownership_excludes_physical_controller_and_lpis(self):
        gic = self.profile["gic"]
        self.assertEqual(gic["version"], 3)
        self.assertEqual(gic["physical_controller"], "native monitor only")
        self.assertIs(gic["lpi_authority"], False)
        self.assertEqual(gic["native_quantum_irq"], 26)
        self.assertEqual(gic["quantum_counter_divisor"], 100)

    def test_optional_recovery_preserves_legacy_profile_and_binds_exact_copy_bytes(self):
        self.assertNotIn("plan9_recovery", self.profile)
        RUNNER.validate_profile(self.profile)
        RUNNER.validate_profile(self.recovery_profile)
        self.assertEqual(self.recovery_profile["plan9_recovery"], EXPECTED_RECOVERY)
        self.assertEqual(self.recovery_profile["loader_addresses"]["inputs/plan9-recovery.kernel"],
                         EXPECTED_RECOVERY["kernel_backup_address"])
        self.assertEqual(self.recovery_profile["loader_addresses"]["inputs/plan9-recovery.dtb"],
                         EXPECTED_RECOVERY["dtb_backup_address"])
        for backup, original in (("inputs/plan9-recovery.kernel", "inputs/plan9.kernel"),
                                 ("inputs/plan9-recovery.dtb", "plan9.dtb")):
            with self.subTest(backup=backup):
                target, source = self.recovery_output / backup, self.recovery_output / original
                RUNNER.checked(target, self.recovery_profile["artifacts"][backup])
                self.assertEqual(target.read_bytes(), source.read_bytes())
                self.assertNotEqual(target.stat().st_ino, source.stat().st_ino)
                self.assertEqual(target.stat().st_mode & 0o777, 0o400)

    def test_recovery_controls_and_backups_are_outside_guests_and_other_native_regions(self):
        recovery = self.recovery_profile["plan9_recovery"]
        namespace, console, mux = (self.profile[key] for key in
                                   ("namespace", "plan9_console", "console_mux"))
        existing = [(self.profile["block_backing"]["address"], self.profile["block_backing"]["bytes"]),
                    (namespace["address"], namespace["bytes"]),
                    (namespace["epoch_address"], 112),
                    (console["input_address"], 8 + console["input_bytes"]),
                    (console["output_address"], 8 + console["output_bytes"]),
                    (mux["linux_output_address"], 8 + mux["output_bytes"])]
        ranges = [(recovery["control_address"], recovery["control_bytes"]),
                  (recovery["kernel_backup_address"], recovery["kernel_max_bytes"]),
                  (recovery["dtb_backup_address"], recovery["dtb_max_bytes"])]
        for index, (base, length) in enumerate(ranges):
            with self.subTest(base=hex(base)):
                for other, size in existing + ranges[index + 1:]:
                    self.assertTrue(base + length <= other or other + size <= base)
                for domain in self.profile["domains"]:
                    self.assertTrue(base + length <= domain["guest_ram_pa"]
                                    or domain["guest_ram_pa"] + domain["guest_ram_bytes"] <= base)
                self.assertLessEqual(base + length, 0x40000000 + self.profile["outer_ram_bytes"])

    def test_recovery_contract_and_loader_tampering_is_rejected(self):
        changes = {"control_address": 0x48000000, "control_bytes": 56,
                   "kernel_backup_address": 0xb0000000, "kernel_max_bytes": 0x1000001,
                   "dtb_backup_address": 0xd0000000, "dtb_max_bytes": 0x10001,
                   "pause": 2, "restart": 1}
        for key, value in changes.items():
            with self.subTest(key=key):
                profile = copy.deepcopy(self.recovery_profile)
                profile["plan9_recovery"][key] = value
                with self.assertRaises(ValueError):
                    RUNNER.validate_profile(profile)
        for name in ("inputs/plan9-recovery.kernel", "inputs/plan9-recovery.dtb"):
            for address in (None, 0x48000000):
                with self.subTest(loader=name, address=address):
                    profile = copy.deepcopy(self.recovery_profile)
                    if address is None:
                        del profile["loader_addresses"][name]
                    else:
                        profile["loader_addresses"][name] = address
                    with self.assertRaises(ValueError):
                        RUNNER.validate_profile(profile)
        profile = copy.deepcopy(self.recovery_profile)
        del profile["plan9_recovery"]
        with self.assertRaises(ValueError):
            RUNNER.validate_profile(profile)
        for invalid in (None, {}, False):
            profile = copy.deepcopy(self.recovery_profile)
            profile["plan9_recovery"] = invalid
            with self.assertRaises(ValueError):
                RUNNER.validate_profile(profile)

    def test_recovery_image_capacity_bounds_are_checked_before_build(self):
        self.assertEqual(BUILDER.plan9_recovery_contract(0x1000000, 0x10000), EXPECTED_RECOVERY)
        self.assertEqual(BUILDER.plan9_recovery_contract(1, 1), EXPECTED_RECOVERY)
        for kernel, dtb in ((0, 1), (1, 0), (-1, 1), (1, -1), (0x1000001, 1), (1, 0x10001)):
            with self.subTest(kernel_bytes=kernel, dtb_bytes=dtb):
                with self.assertRaises(ValueError):
                    BUILDER.plan9_recovery_contract(kernel, dtb)

    def test_tampered_memory_roles_and_interrupt_contracts_are_rejected(self):
        mutations = [
            (("outer_ram_bytes",), 0x80000000),
            (("domains", 0, "id"), 1), (("domains", 1, "id"), 0),
            (("domains", 1, "vmid"), 1),
            (("domains", 1, "guest_ram_pa"), 0x48000000),
            (("domains", 0, "guest_ram_bytes"), 0x40000000),
            (("domains", 0, "x0"), 0x4fe00000),
            (("loader_addresses", "linux.dtb"), 0x47e00000),
            (("block_backing", "bytes"), 0x20000000),
            (("block_backing", "address"), 0x48000000),
            (("namespace", "address"), 0xb0000000),
            (("namespace", "bytes"), 0x2000000),
            (("namespace", "quiescence_address"), 0x48000000),
            (("namespace", "linux_grant"), 4),
            (("namespace", "plan9_grant"), 1),
            (("namespace", "native_peer_grant"), 4),
            (("plan9_console", "input_address"), 0x48000000),
            (("console_mux", "escape"), 27),
            (("console_mux", "linux_select"), ord("1")),
            (("console_mux", "plan9_select"), ord("0")),
            (("console_mux", "linux_output_address"), 0x6d020000),
            (("console_mux", "linux_output_address"), 0x6d030000),
            (("console_mux", "linux_output_address"), 0x48000000),
            (("console_mux", "output_bytes"), 65544),
            (("gic", "version"), 2), (("gic", "lpi_authority"), True),
            (("gic", "physical_controller"), "guest directly mapped"),
            (("gic", "native_quantum_irq"), 27),
        ]
        for path, value in mutations:
            with self.subTest(path=path, value=value):
                changed = copy.deepcopy(self.profile)
                target = changed
                for component in path[:-1]:
                    target = target[component]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    RUNNER.validate_profile(changed)

    def test_linux_dtb_uses_virtual_gicv3_and_private_network_namespace_irqs(self):
        dts = BUILDER.linux_dts(self.template, 8192)
        self.assertIn('compatible = "arm,gic-v3";', dts)
        self.assertNotIn("cortex-a15-gic", dts)
        self.assertNotIn("08010000", dts)
        self.assertNotIn("gic-its", dts)
        self.assertIn("<0 0x080a0000 0 0x20000>", dts)
        self.assertIn("#redistributor-regions = <1>;", dts)
        self.assertIn("linux,initrd-end = <0 0x48002000>;", dts)
        for address, spi in (("a000200", 17), ("a000400", 18)):
            self.assertIn("virtio_mmio@" + address, dts)
            self.assertIn("<0 0x0" + address + " 0 0x200>", dts)
            self.assertIn("interrupts = <0 " + str(spi) + " 4>;", dts)
        for placeholder in ("INITRD_END", "NETWORK_DEVICE", "NAMESPACE_DEVICE"):
            self.assertNotIn(placeholder, dts)

    def test_linux_dtb_template_drift_fails_before_adapting_wrong_controller(self):
        for template in (self.template.replace("arm,cortex-a15-gic", "different-gic"),
                         self.template + self.template):
            with self.subTest(duplicate=template.count("interrupt-controller@8000000")):
                with self.assertRaisesRegex(ValueError, "explicit GICv3 adaptation"):
                    BUILDER.linux_dts(template, 8192)


class UnifiedRecoveryInputTests(unittest.TestCase):
    def inputs(self):
        temporary = tempfile.TemporaryDirectory(prefix="unified recovery identities ")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        values = {}
        for backup, original, content in (
                ("inputs/plan9-recovery.kernel", "inputs/plan9.kernel", b"admitted raw Plan9 kernel"),
                ("inputs/plan9-recovery.dtb", "plan9.dtb", b"admitted Plan9 DTB")):
            for name in (backup, original):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                values[name] = path
        return values

    def test_identical_regular_captured_kernel_and_dtb_are_accepted(self):
        RUNNER.validate_recovery_inputs(self.inputs())

    def test_self_consistent_backup_identity_cannot_replace_original_runtime_bytes(self):
        for name in ("inputs/plan9-recovery.kernel", "inputs/plan9-recovery.dtb"):
            with self.subTest(backup=name):
                artifacts = self.inputs()
                artifacts[name].write_bytes(b"different but individually hashed captured file")
                # The individual manifest check alone is insufficient. The
                # recovery boundary must also compare the admitted live input.
                RUNNER.checked(artifacts[name], RUNNER.identity(artifacts[name]))
                with self.assertRaisesRegex(ValueError, "differs from admitted original"):
                    RUNNER.validate_recovery_inputs(artifacts)

    def test_missing_nonregular_or_symlink_inputs_are_rejected(self):
        for name in ("inputs/plan9-recovery.kernel", "inputs/plan9.kernel",
                     "inputs/plan9-recovery.dtb", "plan9.dtb"):
            for kind in ("missing record", "missing file", "directory", "symlink"):
                with self.subTest(input=name, kind=kind):
                    artifacts = self.inputs()
                    target = artifacts[name]
                    if kind == "missing record":
                        del artifacts[name]
                    else:
                        content = target.read_bytes()
                        target.unlink()
                        if kind == "directory":
                            target.mkdir()
                        if kind == "symlink":
                            source = target.with_name(target.name + ".regular")
                            source.write_bytes(content)
                            target.symlink_to(source)
                    with self.assertRaises((ValueError, KeyError)):
                        RUNNER.validate_recovery_inputs(artifacts)

    def test_matching_empty_or_oversized_copies_are_rejected(self):
        for backup, original, maximum in (
                ("inputs/plan9-recovery.kernel", "inputs/plan9.kernel", 0x1000000),
                ("inputs/plan9-recovery.dtb", "plan9.dtb", 0x10000)):
            for size in (0, maximum + 1):
                with self.subTest(backup=backup, size=size):
                    artifacts = self.inputs()
                    for name in (backup, original):
                        with artifacts[name].open("wb") as stream:
                            stream.truncate(size)
                    with self.assertRaises(ValueError):
                        RUNNER.validate_recovery_inputs(artifacts)

    def test_exact_maximum_backup_capacities_are_accepted(self):
        artifacts = self.inputs()
        for names, size in ((("inputs/plan9-recovery.kernel", "inputs/plan9.kernel"), 0x1000000),
                            (("inputs/plan9-recovery.dtb", "plan9.dtb"), 0x10000)):
            for name in names:
                with artifacts[name].open("wb") as stream:
                    stream.truncate(size)
        RUNNER.validate_recovery_inputs(artifacts)


class UnifiedConsoleCompletionTests(unittest.TestCase):
    def domain_with_full_capture(self, completion):
        temporary = tempfile.TemporaryDirectory(prefix="unified console completion ")
        self.addCleanup(temporary.cleanup)
        domain = RUNNER.UnifiedDomain.__new__(RUNNER.UnifiedDomain)
        domain.session = Path(temporary.name)
        domain.capture = bytearray(b"previous output\n".ljust(1048576, b"x"))
        domain.linux_position = len(domain.capture)
        domain.live, domain.timeout, domain.record = True, 1, {}
        domain.log = io.BytesIO()
        domain.process = mock.Mock()
        domain.process.poll.return_value = None
        pending = []

        def export_ring(command, arguments):
            self.assertEqual(command, "pmemsave")
            self.assertEqual(arguments["val"], 0x6d040000)
            data = pending.pop()
            ring = bytearray(65536)
            for index, value in enumerate(data):
                ring[(domain.linux_position + index) % 65536] = value
            Path(arguments["filename"]).write_bytes(
                struct.pack("<Q", domain.linux_position + len(data)) + ring)

        domain.qmp = mock.Mock()
        domain.qmp.execute.side_effect = export_ring

        def send(wire):
            token = re.search(rb"UNIFIED_COMMAND_[0-9a-f]{32}", wire).group()
            # Echoing the exact submitted printf command must not count as its
            # completion. Any completion is supplied separately by the fixture.
            pending.append(wire + completion(token))
            domain.linux_position = domain.drain_console(
                0x6d040000, domain.linux_position, domain.log, domain.capture, "linux")
            self.assertEqual(len(domain.capture), 1048576)

        domain.send = send
        domain.pump = mock.Mock(side_effect=TimeoutError("no completed command line"))
        return domain

    def test_fresh_command_completes_after_actual_live_capture_truncation(self):
        domain = self.domain_with_full_capture(lambda token: b"\n" + token + b":0\n")
        domain.command("true")
        domain.pump.assert_not_called()

    def test_echo_cannot_complete_command_after_capture_truncation(self):
        domain = self.domain_with_full_capture(lambda token: b"")
        with self.assertRaisesRegex(TimeoutError, "no completed command"):
            domain.command("true")

    def test_partial_nonce_line_is_not_command_completion(self):
        domain = self.domain_with_full_capture(lambda token: b"\n" + token + b":0")
        with self.assertRaisesRegex(TimeoutError, "no completed command"):
            domain.command("true")

    def test_nonzero_completed_command_still_fails_after_truncation(self):
        domain = self.domain_with_full_capture(lambda token: b"\n" + token + b":7\n")
        with self.assertRaisesRegex(RuntimeError, "guest command failed"):
            domain.command("false")


class IdleObservationTests(unittest.TestCase):
    def test_builder_and_runner_bind_identical_private_idle_geometry(self):
        self.assertEqual(BUILDER.IDLE_SCHEDULER, RUNNER.IDLE_SCHEDULER)
        idle = BUILDER.IDLE_SCHEDULER
        self.assertEqual(idle["blocked_mask_address"], 0x6d0000a0)
        self.assertEqual(idle["idle_waits_address"], idle["blocked_mask_address"] + 8)
        self.assertGreaterEqual(idle["blocked_mask_address"],
                                EXPECTED_RECOVERY["control_address"] + EXPECTED_RECOVERY["control_bytes"])

    def observe(self, idle, blocked=3):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        domain = RUNNER.UnifiedDomain.__new__(RUNNER.UnifiedDomain)
        domain.session = Path(temporary.name)
        domain.idle_scheduler = idle
        domain.qmp = mock.Mock()

        def export(command, arguments):
            self.assertEqual(command, "pmemsave")
            if arguments["val"] == 0x6d000020:
                self.assertEqual(arguments["size"], 80)
                data = struct.pack("<10Q", 3, 40, 5, 7, 0x1234, 0x5678, 1, 2, 0, 0)
            else:
                self.assertEqual((arguments["val"], arguments["size"]), (0x6d0000a0, 40))
                data = struct.pack("<5Q", blocked, 31, 44, 3014, 2000)
            Path(arguments["filename"]).write_bytes(data)
        domain.qmp.execute.side_effect = export
        return domain, domain.counters

    def test_new_monitor_reports_blocking_and_native_waits(self):
        domain, observe = self.observe(RUNNER.IDLE_SCHEDULER)
        result = observe()
        self.assertEqual((result["blocked_domains"], result["native_idle_waits"]), (3, 31))
        self.assertEqual((result["linux_exits"], result["plan9_exits"]), (5, 7))
        self.assertEqual((result["plan9_9p_requests"], result["plan9_9p_request_bytes"],
                          result["plan9_9p_reply_bytes"]), (44, 3014, 2000))
        self.assertEqual(domain.qmp.execute.call_count, 2)

    def test_original_monitor_does_not_read_unbound_extension(self):
        domain, observe = self.observe(None)
        result = observe()
        self.assertNotIn("blocked_domains", result)
        self.assertNotIn("native_idle_waits", result)
        self.assertEqual(domain.qmp.execute.call_count, 1)

    def test_invalid_domain_bits_are_rejected(self):
        _, observe = self.observe(RUNNER.IDLE_SCHEDULER, blocked=4)
        with self.assertRaisesRegex(RuntimeError, "idle scheduler state"):
            observe()


if __name__ == "__main__":
    unittest.main()
