"""Boot selection and validation against isolated helper/process fixtures.

No QEMU is started. Real monitor/codec admission and guest behavior are covered
by the corresponding backend tests and live acceptance tests.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = '''
import hashlib,json,os,sys,shutil
from pathlib import Path
NETWORK_GRANT={"enabled":True,"name":"network"}
NAMESPACE_GRANT={"enabled":True,"name":"namespace"}
def checked_file(path, record):
    if path.is_symlink() or not path.is_file(): raise ValueError("artifact is not regular")
    b=path.read_bytes()
    if len(b)!=record["bytes"] or hashlib.sha256(b).hexdigest()!=record["sha256"]: raise ValueError("artifact digest changed")
    return path
def validate_profile(profile):
    if profile["profile"]!="package-domain": raise ValueError("wrong profile")
def selected_disk_bytes(state):
    return (state/"disk.bin").stat().st_size
def validate_head(state, head):
    if head.get("schema")!="fixture-head": raise ValueError("wrong head")
def copy_state(source, target):
    shutil.copytree(source,target)
    p=target/"monitor/monitor-profile.json"
    p.write_text(p.read_text().replace(str(source),str(target)))
if __name__=="__main__":
    with open(os.environ["BOOT_CALLS"],"a") as f:
        f.write(json.dumps({"argv":sys.argv[1:],"codec":os.environ.get("OCORE_LINUX_NATIVE_9P_MANIFEST")})+"\\n")
    if sys.argv[1]=="build":
        copy_state(Path(os.environ["BOOT_TEMPLATE"]),Path(sys.argv[sys.argv.index("--state")+1]))
    sys.exit(int(os.environ.get("BOOT_RUN_STATUS","0")))
'''
CODEC = '''
import json
from pathlib import Path
def validate_capture(native, build):
    if native.get("fixture_valid") is not True: raise ValueError("native codec receipt failed")
    p=Path(native["captured_manifest"]["path"])
    if not p.is_relative_to(build): raise ValueError("codec outside build")
    if not json.loads(p.read_text()).get("fixture_valid"): raise ValueError("corrupt captured codec")
'''
FORK = '''
import os,sys,json
from pathlib import Path
from okernel_package_domain import copy_state
with open(os.environ["BOOT_CALLS"],"a") as f:
    f.write(json.dumps({"fork":sys.argv[1:]})+"\\n")
copy_state(Path(sys.argv[sys.argv.index("--source")+1]),Path(sys.argv[sys.argv.index("--output")+1]))
'''


class BootEntrypointTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="okernel-boot-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / "checkout with spaces"
        for directory in ("boot", "scripts", "ocore/kernel", "okernel-multikernel", "bin"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        for relative in ("boot/boot.sh", "scripts/boot_okernel.py", "boot-and-test.sh", "okernel-multikernel/boot-and-test.sh"):
            shutil.copy2(ROOT / relative, self.root / relative)
        (self.root / "Cargo.toml").touch()
        (self.root / "ocore/kernel/build.sh").write_text("#!/bin/sh\nexit 90\n")
        self.write("scripts/okernel_package_domain.py", RUNNER)
        self.write("scripts/okernel_native_codec.py", CODEC)
        self.write("scripts/fork_okernel_state.py", FORK)
        self.write("ocore/kernel/run-qemu.sh", '#!/bin/sh\nprintf "mode=%s\\nqemu=%s\\n" "$OCORE_PROBE_MODE" "${OCORE_QEMU_BIN:-}"\nexit "${BOOT_NATIVE_STATUS:-0}"\n')
        self.qemu = self.write("bin/qemu with spaces", "#!/bin/sh\nexit 99\n")
        self.calls = self.base / "calls.jsonl"
        self.state = self.base / "saved state"
        self.prepare_fixture(self.state)
        self.environment = dict(os.environ, BOOT_CALLS=str(self.calls), BOOT_TEMPLATE=str(self.state),
                                OSTADIX_OKERNEL_PACKAGE_QEMU=str(self.qemu))
        for name in ("OCORE_PROBE_MODE", "OSTADIX_OKERNEL_STATE", "XDG_STATE_HOME", "BOOT_RUN_STATUS", "BOOT_NATIVE_STATUS"):
            self.environment.pop(name, None)

    def write(self, relative, text):
        path = self.root / relative
        path.write_text(text)
        path.chmod(0o755)
        return path

    def prepare_fixture(self, state):
        (state / "monitor").mkdir(parents=True)
        profile = {"profile": "package-domain", "backing_bytes": 4096,
                   "network_grant": {"enabled": True, "name": "network"},
                   "namespace_grant": {"enabled": True, "name": "namespace"}, "artifacts": {}}
        for name in ("monitor", "guest_dtb", "profile", "Image", "initramfs"):
            path = state / (name + ".bin")
            data = (name + " fixture").encode()
            path.write_bytes(data)
            profile["artifacts"][name] = {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        (state / "disk.bin").write_bytes(b"\0" * 4096)
        manifest = state / "monitor/native-codec.json"
        manifest.write_text('{"fixture_valid":true}')
        profile["native_9p_codec"] = {"schema": "ostadix.monitor-native-u9fs/v1", "isa": "aarch64",
                                      "fixture_valid": True, "captured_manifest": {"path": str(manifest)}}
        (state / "monitor/monitor-profile.json").write_text(json.dumps(profile))

    def profile(self, mutate):
        path = self.state / "monitor/monitor-profile.json"
        record = json.loads(path.read_text())
        mutate(record)
        path.write_text(json.dumps(record))

    def run_boot(self, *args, state=True, entry="boot/boot.sh"):
        command = [str(self.root / entry), *map(str, args)]
        if state:
            command += ["--state", str(self.state)]
        return subprocess.run(command, cwd=self.base, env=self.environment,
                              capture_output=True, text=True, timeout=15)

    def recorded(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_default_boot_runs_prepared_source_system_without_build(self):
        self.environment["OSTADIX_OKERNEL_STATE"] = str(self.state.parent / "parent")
        (self.state.parent / "parent").mkdir()
        destination = self.state.parent / "parent/package-domain"
        shutil.copytree(self.state, destination)
        p = destination / "monitor/monitor-profile.json"
        p.write_text(p.read_text().replace(str(self.state), str(destination)))
        result = self.run_boot(state=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        call, = self.recorded()
        self.assertEqual(call["argv"], ["run", "--state", str(destination), "--qemu", str(self.qemu)])

    def test_xdg_state_default_selects_dedicated_native_source_state(self):
        self.environment["XDG_STATE_HOME"] = str(self.base / "xdg state")
        destination = Path(self.environment["XDG_STATE_HOME"]) / "ostadix/okernel/native-source/package-domain"
        shutil.copytree(self.state, destination)
        p = destination / "monitor/monitor-profile.json"
        p.write_text(p.read_text().replace(str(self.state), str(destination)))
        result = self.run_boot("doctor", state=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(destination), result.stdout)
        self.assertEqual(self.recorded(), [])

    def test_explicit_qemu_and_state_preserve_arguments_and_exit_status(self):
        self.environment["BOOT_RUN_STATUS"] = "37"
        result = self.run_boot("run", "--qemu", self.qemu)
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertEqual(self.recorded()[0]["argv"][-1], str(self.qemu))

    def test_doctor_validates_without_running_or_building(self):
        result = self.run_boot("doctor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("valid", result.stdout)
        self.assertEqual(self.recorded(), [])

    def test_missing_qemu_fails_without_running_a_different_profile(self):
        result = self.run_boot("--qemu", self.base / "missing-qemu")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("QEMU executable is not installed", result.stderr)
        self.assertEqual(self.recorded(), [])

    def test_state_symlink_rejects_before_runner(self):
        alias = self.base / "state alias"
        alias.symlink_to(self.state, target_is_directory=True)
        result = self.run_boot("--state", alias, state=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not be a symlink", result.stderr)
        self.assertEqual(self.recorded(), [])

    def test_saved_head_requires_a_paired_namespace(self):
        (self.state / "head.json").write_text('{"schema":"fixture-head"}')
        result = self.run_boot("doctor")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("paired native namespace", result.stderr)
        self.assertEqual(self.recorded(), [])

    def test_unprepared_state_fails_with_explicit_prepare_help(self):
        (self.state / "monitor/monitor-profile.json").unlink()
        result = self.run_boot()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Prepare explicitly", result.stderr)
        self.assertEqual(self.recorded(), [])

    def test_missing_network_or_namespace_never_falls_back(self):
        for name in ("network_grant", "namespace_grant"):
            path = self.state / "monitor/monitor-profile.json"
            saved = path.read_bytes()
            self.profile(lambda p: p.pop(name))
            result = self.run_boot()
            self.assertNotEqual(result.returncode, 0, name)
            self.assertEqual(self.recorded(), [])
            path.write_bytes(saved)

    def test_plain_package_profile_cannot_be_called_native_codec(self):
        self.profile(lambda p: p.pop("native_9p_codec"))
        result = self.run_boot()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("lacks the original-source native codec", result.stderr)
        self.assertEqual(self.recorded(), [])

    def test_tampered_core_artifact_rejects_before_runner(self):
        (self.state / "monitor.bin").write_bytes(b"tampered")
        result = self.run_boot()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest changed", result.stderr)
        self.assertEqual(self.recorded(), [])

    def test_codec_validator_failure_rejects_before_runner(self):
        (self.state / "monitor/native-codec.json").write_text('{"fixture_valid":false}')
        result = self.run_boot()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("corrupt captured codec", result.stderr)
        self.assertEqual(self.recorded(), [])

    def test_artifact_outside_selected_state_rejects(self):
        outside = self.base / "outside.bin"
        shutil.copyfile(self.state / "monitor.bin", outside)
        self.profile(lambda p: p["artifacts"]["monitor"].update(path=str(outside)))
        result = self.run_boot()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the selected state", result.stderr)

    def test_native_baseline_and_explicit_probe_mode_remain_available(self):
        for action, mode in (("native", "16"), ("baseline", "0")):
            result = self.run_boot(action, "--qemu", self.qemu)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("mode=" + mode, result.stdout)
            self.assertIn("qemu=" + str(self.qemu), result.stdout)
        self.environment["OCORE_PROBE_MODE"] = "16"
        self.environment["BOOT_NATIVE_STATUS"] = "41"
        result = self.run_boot()
        self.assertEqual(result.returncode, 41)
        self.assertIn("mode=16", result.stdout)

    def test_root_and_multikernel_kernel_dispatch_to_prepared_system(self):
        self.environment["OSTADIX_OKERNEL_STATE"] = str(self.state.parent / "selected")
        target = Path(self.environment["OSTADIX_OKERNEL_STATE"]) / "package-domain"
        shutil.copytree(self.state, target)
        p = target / "monitor/monitor-profile.json"
        p.write_text(p.read_text().replace(str(self.state), str(target)))
        for entry in ("boot-and-test.sh", "okernel-multikernel/boot-and-test.sh"):
            result = self.run_boot("kernel", state=False, entry=entry)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.recorded()), 2)
        self.assertTrue(all(c["argv"][0] == "run" for c in self.recorded()))

    def test_root_console_baseline_and_probe_override_keep_native_runner(self):
        for action, mode in (("console", "16"), ("baseline", "0")):
            result = self.run_boot(action, state=False, entry="boot-and-test.sh")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("mode=" + mode, result.stdout)
        self.environment["OCORE_PROBE_MODE"] = "0"
        result = self.run_boot("kernel", state=False, entry="boot-and-test.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mode=0", result.stdout)
        self.assertEqual(self.recorded(), [])

    def test_prepare_requires_an_explicit_source_and_new_destination(self):
        for args in (("prepare",), ("prepare", "--codec-manifest", self.state / "monitor/native-codec.json")):
            result = self.run_boot(*args)
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.recorded(), [])

    def test_preparation_options_cannot_mutate_on_run(self):
        result = self.run_boot("run", "--codec-manifest", self.state / "monitor/native-codec.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("apply only to prepare", result.stderr)
        self.assertEqual(self.recorded(), [])

    def test_prepare_build_forwards_native_manifest_and_required_grants(self):
        destination = self.base / "new prepared state"
        manifest = self.state / "monitor/native-codec.json"
        result = self.run_boot("prepare", "--codec-manifest", manifest, "--state", destination, state=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        call, = self.recorded()
        self.assertEqual(call["argv"], ["build", "--state", str(destination), "--network", "--namespace"])
        self.assertEqual(call["codec"], str(manifest))

    def test_prepare_forks_verified_source_without_mutating_it(self):
        destination = self.base / "fork state"
        original = (self.state / "monitor/monitor-profile.json").read_bytes()
        result = self.run_boot("prepare", "--from-state", self.state, "--state", destination, state=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.state / "monitor/monitor-profile.json").read_bytes(), original)
        self.assertIn("fork", self.recorded()[0])
        self.assertTrue(destination.is_dir())


if __name__ == "__main__":
    unittest.main()
