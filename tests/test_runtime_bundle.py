"""Archive boundary tests use explicit synthetic binaries, not execution proof.

The real native/MCP qualification runs through runtime_bundle build/install on
each native release runner. These tests do not label fixture bytes as Ostadix.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("runtime_bundle", ROOT / "scripts/runtime_bundle.py")
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


def header(system, architecture):
    if system == "linux":
        data = bytearray(64); data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<H", data, 18, {"x86_64": 62, "aarch64": 183}[architecture])
    else:
        data = bytearray(32); data[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", data, 4, {"x86_64": 0x01000007, "aarch64": 0x0100000C}[architecture])
    return bytes(data)


class RuntimeBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="runtime bundle fixture ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.build = self.root / "build"; (self.build / "bin").mkdir(parents=True)
        self.host = bundle.host_platform(); self.commit = "a" * 40
        self.source_members = {"source/Cargo.toml": b"fixture", "source/backends/python_shim.py": b"fixture",
                               "source/examples/hello.O": b"fixture", "source/scripts/executable.sh": b"fixture"}
        with zipfile.ZipFile(self.build / "SOURCE.zip", "w") as z:
            for name, data in self.source_members.items():
                info = zipfile.ZipInfo(name); info.create_system = 3
                info.external_attr = (0o100755 if name.endswith(".sh") else 0o100644) << 16
                z.writestr(info, data)
        artifacts = {}
        for name in bundle.TOOLS:
            path = self.build / "bin" / name; path.write_bytes(header(self.host["system"], self.host["architecture"]) + name.encode()); path.chmod(0o755)
            artifacts[name] = {"path": "bin/" + name, **bundle.record(path), "platform": bundle.native_platform(path)}
        smoke = {"passed": True, "host": self.host,
                 "checks": [{"name": n, "exitCode": 0, "stdout": "2\n", "stderr": ""}
                            for n in ["native-evaluation", "native-plan", "ocore-command"]]
                           + [{"name": "mcp-stdio-execution", "protocolVersion": "2025-03-26", "toolCount": 3,
                               "result": {"content": [{"type": "text", "text": "SMOKE_OK fixture only"}]}}]}
        (self.build / "SMOKE.json").write_bytes(bundle.json_bytes(smoke))
        commands = []
        for i in range(2):
            log = self.build / f"build-{i}.log"; log.write_text("synthetic fixture, no build ran\n")
            commands.append({"argv": ["cargo", "build"], "exitCode": 0, "log": {"path": log.name, **bundle.record(log)}})
        target = self.host["architecture"] + ("-apple-darwin" if self.host["system"] == "macos" else "-unknown-linux-gnu")
        self.manifest = {"schema": bundle.BUILD_SCHEMA, "profile": "runtime-only", "source": {"commit": self.commit, "dirty": False},
                         "targetTriple": target, "host": self.host, "commands": commands, "artifacts": artifacts,
                         "sourceArchive": bundle.record(self.build / "SOURCE.zip"), "smoke": bundle.record(self.build / "SMOKE.json")}
        (self.build / "BUILD-MANIFEST.json").write_bytes(bundle.json_bytes(self.manifest))
        self.source_mock = patch.object(bundle.source_release, "verify_archive", return_value={"commit": self.commit})
        self.source_mock.start(); self.addCleanup(self.source_mock.stop)
        self.archive = self.root / "runtime.zip"

    def pack(self):
        return bundle.package(self.build, self.archive)

    def rewrite(self, changes=None, add=None, mode_changes=None):
        values = bundle.read_members(self.archive); modes = bundle.member_modes(self.archive)
        for name, value in (changes or {}).items(): values[name] = value
        values.update(add or {})
        manifest = json.loads(values["BUNDLE-MANIFEST.json"])
        manifest["files"] = {n: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                             for n, data in values.items() if n != "BUNDLE-MANIFEST.json"}
        values["BUNDLE-MANIFEST.json"] = bundle.json_bytes(manifest)
        with zipfile.ZipFile(self.archive, "w") as z:
            for name, data in values.items():
                info = zipfile.ZipInfo(name); info.create_system = 3
                info.external_attr = (mode_changes or {}).get(name, 0o100000 | modes.get(name, 0o644)) << 16
                z.writestr(info, data)

    def test_package_verifies_inventory_source_modes_and_external_checksum(self):
        manifest = self.pack()
        self.assertEqual(bundle.verify(self.archive, bundle.digest(self.archive)), manifest)
        self.assertTrue(self.archive.with_suffix(".zip.sha256").read_text().startswith(bundle.digest(self.archive)))
        self.assertEqual(bundle.member_modes(self.archive)["source/scripts/executable.sh"], 0o755)
        self.assertEqual(set(n[4:] for n in manifest["files"] if n.startswith("bin/")), set(bundle.TOOLS))

    def test_archive_generation_is_deterministic_for_identical_inputs(self):
        self.pack(); second = self.root / "again.zip"; bundle.package(self.build, second)
        self.assertEqual(self.archive.read_bytes(), second.read_bytes())

    def test_tampered_binary_is_rejected_without_executing_it(self):
        self.pack()
        with zipfile.ZipFile(self.archive, "a") as z:
            # A duplicate name is rejected even if the original entry was valid.
            with self.assertWarns(UserWarning): z.writestr("bin/O", b"tampered")
        with self.assertRaisesRegex(bundle.BundleError, "Duplicate"):
            bundle.verify(self.archive)

    def test_internal_inventory_hash_mismatch_is_rejected(self):
        self.pack(); data = bytearray(self.archive.read_bytes()); data[12] ^= 1
        # External pin catches any mutation before archive parsing or execution.
        old = bundle.digest(self.archive); self.archive.write_bytes(data)
        with self.assertRaisesRegex(bundle.BundleError, "checksum mismatch"):
            bundle.verify(self.archive, old)

    def test_unpacked_source_must_match_the_source_archive(self):
        self.pack(); self.rewrite({"source/examples/hello.O": b"different source"})
        with self.assertRaisesRegex(bundle.BundleError, "Unpacked source"):
            bundle.verify(self.archive)

    def test_native_header_target_cannot_be_relabelled_in_manifests(self):
        self.pack(); alternate = "aarch64" if self.host["architecture"] == "x86_64" else "x86_64"
        self.rewrite({"bin/O": header(self.host["system"], alternate)})
        with self.assertRaisesRegex(bundle.BundleError, "target/hash"):
            bundle.verify(self.archive)

    def test_target_triple_must_match_the_actual_header_platform(self):
        self.manifest["targetTriple"] = ("aarch64-unknown-linux-gnu" if self.host["architecture"] == "x86_64"
                                          else "x86_64-unknown-linux-gnu")
        (self.build / "BUILD-MANIFEST.json").write_bytes(bundle.json_bytes(self.manifest))
        with self.assertRaisesRegex(bundle.BundleError, "target triple"):
            self.pack()

    def test_top_level_pass_does_not_override_a_failed_native_measurement(self):
        proof = json.loads((self.build / "SMOKE.json").read_text())
        proof["checks"][0]["exitCode"] = 9
        (self.build / "SMOKE.json").write_bytes(bundle.json_bytes(proof))
        self.manifest["smoke"] = bundle.record(self.build / "SMOKE.json")
        (self.build / "BUILD-MANIFEST.json").write_bytes(bundle.json_bytes(self.manifest))
        with self.assertRaisesRegex(bundle.BundleError, "measurement did not complete"):
            self.pack()

    def test_dirty_build_or_incomplete_smoke_cannot_be_packaged(self):
        self.manifest["source"]["dirty"] = True
        (self.build / "BUILD-MANIFEST.json").write_bytes(bundle.json_bytes(self.manifest))
        with self.assertRaisesRegex(bundle.BundleError, "clean build"):
            self.pack()
        self.assertFalse(self.archive.exists())
        self.manifest["source"]["dirty"] = False
        proof = {"passed": True, "host": self.host, "checks": [{"name": "native-evaluation"}]}
        (self.build / "SMOKE.json").write_bytes(bundle.json_bytes(proof)); self.manifest["smoke"] = bundle.record(self.build / "SMOKE.json")
        (self.build / "BUILD-MANIFEST.json").write_bytes(bundle.json_bytes(self.manifest))
        with self.assertRaisesRegex(bundle.BundleError, "smoke evidence"):
            self.pack()

    def test_source_commit_and_build_log_hashes_are_bound(self):
        self.pack(); altered = dict(self.manifest); altered["source"] = {"commit": "b" * 40, "dirty": False}
        self.rewrite({"BUILD-MANIFEST.json": bundle.json_bytes(altered)})
        with self.assertRaisesRegex(bundle.BundleError, "source or target"):
            bundle.verify(self.archive)
        self.archive.unlink(); self.pack(); self.rewrite({"build-0.log": b"different retained output"})
        with self.assertRaisesRegex(bundle.BundleError, "build log checksum"):
            bundle.verify(self.archive)

    def test_path_traversal_and_symlinks_are_rejected_before_extraction(self):
        self.pack(); self.rewrite(add={"../outside": b"no"})
        with self.assertRaisesRegex(bundle.BundleError, "Unsafe"):
            bundle.verify(self.archive)
        self.archive.unlink(); self.pack(); self.rewrite(mode_changes={"source/Cargo.toml": 0o120777})
        with self.assertRaisesRegex(bundle.BundleError, "non-regular"):
            bundle.verify(self.archive)
        self.assertFalse((self.root.parent / "outside").exists())

    def test_wrong_host_or_checksum_creates_nothing_and_executes_nothing(self):
        self.pack(); dest, bins = self.root / "permanent", self.root / "installed"
        with patch.object(bundle, "smoke") as native_smoke:
            with self.assertRaises(bundle.BundleError): bundle.install(self.archive, dest, bins, "0" * 64)
            different = dict(self.host, architecture="unsupported")
            with patch.object(bundle, "host_platform", return_value=different):
                with self.assertRaisesRegex(bundle.BundleError, "does not match"):
                    bundle.install(self.archive, dest, bins, bundle.digest(self.archive))
            native_smoke.assert_not_called()
        self.assertFalse(dest.exists()); self.assertFalse(bins.exists())

    def test_relocated_install_retains_source_and_portable_metadata(self):
        self.pack(); dest, bins = self.root / "permanent", self.root / "installed"
        # Synthetic binary fixtures are never executed. Real release-runner
        # installation independently invokes the native smoke without this mock.
        with patch.object(bundle, "smoke", return_value={"fixtureOnly": True}) as native_smoke:
            result = bundle.install(self.archive, dest, bins, bundle.digest(self.archive))
            native_smoke.assert_called_once()
        self.assertTrue(result["installed"])
        metadata = json.loads((bins / "ostadix-install.json").read_text())
        self.assertEqual(metadata["profile"], "runtime-only")
        self.assertEqual(metadata["repo_root"], str(dest / "source"))
        self.assertEqual(metadata["source_commit"], self.commit)
        self.assertEqual((bins / "ostadix-mcp").read_bytes(), (self.build / "bin/ostadix-mcp").read_bytes())
        self.assertTrue((dest / "source/scripts/executable.sh").stat().st_mode & 0o111)
        self.assertFalse((bins / "o-node").exists())

    def test_install_uses_private_verified_copy_if_original_archive_is_replaced(self):
        self.pack(); dest, bins = self.root / "permanent", self.root / "installed"
        original = (self.build / "bin/O").read_bytes()
        verify = bundle.verify
        def swap_after_verification(path, *args, **kwargs):
            result = verify(path, *args, **kwargs)
            self.assertNotEqual(Path(path), self.archive)
            self.archive.write_bytes(b"changed after verification")
            return result
        with patch.object(bundle, "verify", side_effect=swap_after_verification), patch.object(bundle, "smoke", return_value={"fixtureOnly": True}):
            bundle.install(self.archive, dest, bins, bundle.digest(self.archive))
        self.assertEqual((bins / "ostadix-evaluator").read_bytes(), original)
        self.assertEqual(self.archive.read_bytes(), b"changed after verification")

    def test_elf_and_macho_headers_identify_real_machine_fields(self):
        for system in ["linux", "macos"]:
            for architecture in ["x86_64", "aarch64"]:
                p = self.root / "header"; p.write_bytes(header(system, architecture))
                self.assertEqual(bundle.native_platform(p), {"system": system, "architecture": architecture})
        p.write_text("#!/bin/sh\n")
        with self.assertRaises(bundle.BundleError): bundle.native_platform(p)

    def test_native_smoke_output_is_bounded_while_the_process_is_running(self):
        with self.assertRaisesRegex(bundle.BundleError, "output budget"):
            bundle.checked_run([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*(2*1024*1024))"],
                               self.root, os.environ.copy(), timeout=3)

    def test_native_smoke_deadline_cleans_up_pipe_holding_descendants(self):
        pid_path = self.root / "descendant.pid"
        script = ("import subprocess,sys,pathlib;"
                  "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                  "pathlib.Path(sys.argv[1]).write_text(str(p.pid))")
        with self.assertRaisesRegex(bundle.BundleError, "execution deadline"):
            bundle.checked_run([sys.executable, "-c", script, str(pid_path)], self.root, os.environ.copy(), timeout=.3)
        self.assertTrue(pid_path.is_file())
        pid = int(pid_path.read_text())
        for _ in range(20):
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
            if not state or state.startswith("Z"):
                break
            time.sleep(.02)
        self.assertTrue(not state or state.startswith("Z"), "The owned descendant is still running: " + state)

    def synthetic_mcp(self, extra):
        path = self.root / "synthetic-mcp"
        path.write_text("#!" + sys.executable + "\n" + '''import sys,json
for line in sys.stdin:
 request=json.loads(line);request_id=request.get('id');method=request.get('method')
 if request_id is None: continue
 if method=='initialize':result={'protocolVersion':'2025-03-26'}
 elif method=='tools/list':result={'tools':[{'name':n} for n in ['o_smoke','o_env','o_execute']]}
 else:
  EXTRA
  result={'content':[{'type':'text','text':'SMOKE_OK synthetic fixture only'}]}
 print(json.dumps({'jsonrpc':'2.0','id':request_id,'result':result}),flush=True)
'''.replace("EXTRA", extra))
        path.chmod(0o700)
        return path

    def test_mcp_stderr_final_partial_chunk_cannot_escape_the_budget(self):
        path = self.synthetic_mcp("sys.stderr.buffer.write(b'x'*(1024*1024+1));sys.stderr.buffer.flush()")
        host = {k: self.host[k] for k in ['system', 'architecture']}
        with patch.object(bundle, 'native_platform', return_value=host), patch.object(bundle, 'checked_run', return_value={'stdout':'2\n','stderr':'','exitCode':0}):
            with self.assertRaisesRegex(bundle.BundleError, "stderr budget"):
                bundle.smoke(self.root, self.root, path)

    def test_synthetic_mcp_normal_stdio_can_still_complete_with_bounded_readers(self):
        path = self.synthetic_mcp("sys.stderr.write('short synthetic diagnostic\\n');sys.stderr.flush()")
        host = {k: self.host[k] for k in ['system', 'architecture']}
        with patch.object(bundle, 'native_platform', return_value=host), patch.object(bundle, 'checked_run', return_value={'stdout':'2\n','stderr':'','exitCode':0}):
            result = bundle.smoke(self.root, self.root, path)
        self.assertTrue(result['passed'])
        self.assertEqual(result['checks'][-1]['name'], 'mcp-stdio-execution')


if __name__ == "__main__":
    unittest.main()
