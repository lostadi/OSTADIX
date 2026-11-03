"""Original-server component checks; guest/native qualification is a separate gate.

To execute authenticated upstream engines on a private host fixture, set
OSTADIX_9P_COMPONENT_PLAN9_PREFIX to a built Plan9port source/runtime closure and
OSTADIX_9P_COMPONENT_U9FS_ARCHIVE to the pinned original u9fs archive. No guest
state, native volume or active VM is opened by these tests.
"""
import hashlib
import os
from pathlib import Path
import pwd
import select
import shlex
import shutil
import socket
import struct
import subprocess
import tarfile
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "ocore/guest/linux/package-domain"
U9FS_SHA256 = "56887d41253810986cfeb7a8a559b193b5d4c302ace18bff0a03c48f1dea9bcd"


def wait_for(predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("private component did not reach the expected state")


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p9bridge-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.export = self.root / "native-fixture"
        self.export.mkdir()
        self.runtime = self.root / "run"
        self.runtime.mkdir(mode=0o700)
        self.tools = self.root / "tools"
        (self.tools / "bin").mkdir(parents=True)
        self.program = self.root / "supervisor"
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        '-DOKERNEL_BRIDGE_TEST_ROOT="' + str(self.export) + '"',
                        str(HERE / "okernel-9p-bridge.c"), "-o", str(self.program)], check=True)
        for name in ("u9fs", "9pserve"):
            tool = self.tools / "bin" / name
            tool.write_text("#!/bin/sh\nexec sleep 60\n")
            tool.chmod(0o755)
        self.processes = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=12)

    def launch(self):
        process = subprocess.Popen([str(self.program), str(self.tools), str(self.runtime)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(process)
        return process

    def children(self, process):
        path = Path(f"/proc/{process.pid}/task/{process.pid}/children")
        return [int(pid) for pid in path.read_text().split()] if path.exists() else []

    def test_stop_reaps_only_owned_original_processes_and_removes_record(self):
        unrelated = subprocess.Popen(["sleep", "60"])
        self.addCleanup(lambda: unrelated.poll() is None and unrelated.terminate())
        self.addCleanup(lambda: unrelated.wait(timeout=3))
        process = self.launch()
        wait_for(lambda: len(self.children(process)) == 2)
        children = self.children(process)
        process.terminate()
        self.assertEqual(process.wait(timeout=12), 0)
        self.assertTrue(all(not Path(f"/proc/{child}").exists() for child in children))
        self.assertFalse((self.runtime / "supervisor.pid").exists())
        self.assertIsNone(unrelated.poll())
        unrelated.terminate()

    def test_original_child_failure_cleans_up_its_peer(self):
        (self.tools / "bin/u9fs").write_text("#!/bin/sh\nsleep 0.1\nexit 23\n")
        process = self.launch()
        wait_for(lambda: len(self.children(process)) == 2)
        children = self.children(process)
        self.assertEqual(process.wait(timeout=12), 1)
        self.assertTrue(all(not Path(f"/proc/{child}").exists() for child in children))
        self.assertFalse((self.runtime / "supervisor.pid").exists())

    def test_duplicate_supervisor_cannot_replace_identity_or_kill_first(self):
        process = self.launch()
        wait_for(lambda: len(self.children(process)) == 2)
        identity = (self.runtime / "supervisor.pid").read_bytes()
        duplicate = self.launch()
        self.assertEqual(duplicate.wait(timeout=3), 1)
        self.assertEqual((self.runtime / "supervisor.pid").read_bytes(), identity)
        self.assertIsNone(process.poll())

    def test_regular_service_path_is_preserved(self):
        path = self.runtime / "okernel"
        path.write_text("unrelated")
        self.assertEqual(self.launch().wait(timeout=3), 1)
        self.assertEqual(path.read_text(), "unrelated")

    def test_insecure_or_symlink_runtime_is_rejected(self):
        self.runtime.chmod(0o755)
        self.assertEqual(self.launch().wait(timeout=3), 1)
        self.runtime.rmdir()
        self.runtime.symlink_to(self.export, target_is_directory=True)
        self.assertEqual(self.launch().wait(timeout=3), 1)

    def test_production_binary_has_no_host_directory_fallback(self):
        program = self.root / "production"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(HERE / "okernel-9p-bridge.c"), "-o", str(program)], check=True)
        # The host component fixture is deliberately not the native guest mount.
        mounts = Path("/proc/mounts").read_text()
        if "okernel /n/okernel 9p " in mounts:
            self.skipTest("this test requires a host without the actual native guest mount")
        result = subprocess.run([str(program), str(self.tools), str(self.runtime)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("refusing to export a fallback", result.stderr)
        self.assertFalse((self.runtime / "supervisor.pid").exists())

    def test_missing_kernel_child_ownership_interface_fails_before_launch(self):
        program = self.root / "missing-children"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        '-DOKERNEL_BRIDGE_TEST_ROOT="' + str(self.export) + '"',
                        '-DOKERNEL_BRIDGE_TEST_CHILDREN_PATH="' + str(self.root / "absent-children") + '"',
                        str(HERE / "okernel-9p-bridge.c"), "-o", str(program)], check=True)
        marker = self.root / "unexpected-child-launch"
        for name in ("u9fs", "9pserve"):
            (self.tools / "bin" / name).write_text('#!/bin/sh\nprintf launched > "' + str(marker) + '"\n')
        result = subprocess.run([str(program), str(self.tools), str(self.runtime)],
                                capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertIn("CONFIG_PROC_CHILDREN", result.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse((self.runtime / "supervisor.pid").exists())


@unittest.skipUnless(os.environ.get("OSTADIX_9P_COMPONENT_PLAN9_PREFIX")
                     and os.environ.get("OSTADIX_9P_COMPONENT_U9FS_ARCHIVE"),
                     "explicit original-source component fixture paths are required")
class OriginalServerTests(SupervisorTests):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="p9original-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.build_root = Path(cls.build.name)
        cls.plan9 = Path(os.environ["OSTADIX_9P_COMPONENT_PLAN9_PREFIX"]).resolve()
        archive = Path(os.environ["OSTADIX_9P_COMPONENT_U9FS_ARCHIVE"])
        if hashlib.sha256(archive.read_bytes()).hexdigest() != U9FS_SHA256:
            raise AssertionError("original u9fs archive identity changed")
        cls.tree = cls.build_root / "u9fs"
        cls.tree.mkdir()
        with tarfile.open(archive) as stream:
            for member in stream.getmembers():
                if member.isfile():
                    relative = Path(*Path(member.name).parts[1:])
                    if relative.is_absolute() or ".." in relative.parts:
                        raise AssertionError("archive path escaped private source tree")
                    target = cls.tree / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(stream.extractfile(member).read())
        subprocess.run(["patch", "--fuzz=0", "-p1", "-i", str(HERE / "u9fs-path-hardening.patch")],
                       cwd=cls.tree, check=True, capture_output=True)
        subprocess.run(["make", "-j2", "CC=gcc", "LD=gcc", "CFLAGS=-O2 -g0 -I.", "LDFLAGS="],
                       cwd=cls.tree, check=True, capture_output=True)
        environment = dict(os.environ, PLAN9=str(cls.plan9))
        cls.mux = cls.build_root / "9pserve"
        obj = cls.build_root / "9pserve.o"
        subprocess.run([str(cls.plan9 / "bin/9c"), "-o", str(obj), str(cls.plan9 / "src/cmd/9pserve.c")],
                       env=environment, check=True, capture_output=True)
        subprocess.run([str(cls.plan9 / "bin/9l"), "-o", str(cls.mux), str(obj), "-lthread"],
                       env=environment, check=True, capture_output=True)

    def start_original(self):
        (self.export / "work").mkdir(exist_ok=True)
        for name, target in (("u9fs", self.tree / "u9fs"), ("9pserve", self.mux), ("9p", self.plan9 / "bin/9p")):
            destination = self.tools / "bin" / name
            destination.unlink(missing_ok=True)
            destination.symlink_to(target)
        process = self.launch()
        wait_for(lambda: (self.runtime / "okernel").is_socket())
        return process

    def client(self, *args, input=None):
        return subprocess.run([str(self.plan9 / "bin/9p"), "-n", *args], input=input,
                              env=dict(os.environ, PLAN9=str(self.plan9), NAMESPACE=str(self.runtime)),
                              capture_output=True, timeout=4)

    def test_original_client_read_write_stat_and_named_root_confinement(self):
        process = self.start_original()
        wait_for(lambda: len(self.children(process)) >= 2)
        children = self.children(process)
        path = self.export / "work/shared"
        path.write_bytes(b"linux-to-original-client\n")
        self.assertEqual(self.client("read", "okernel/work/shared").stdout, path.read_bytes())
        result = self.client("write", "okernel/work/shared", input=b"original-client-to-linux\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(path.read_bytes(), b"original-client-to-linux\n")
        self.assertEqual(self.client("stat", "okernel/work/shared").returncode, 0)
        canary = self.root / "outside-canary"
        canary.write_bytes(b"PRIVATE_HOST_CANARY")
        for request in ("okernel/../../outside-canary", r"okernel/\2e\2e/outside-canary",
                        r"okernel/\2e\2e\2foutside-canary", r"okernel/work/\2e\2e\2f\2e\2e\2foutside-canary",
                        r"okernel/\00outside-canary", r"okernel/work/shared\00suffix", r"okernel/\xxoutside-canary"):
            with self.subTest(request=request):
                rejected = self.client("read", request)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertNotIn(canary.read_bytes(), rejected.stdout)
        self.assertEqual(canary.read_bytes(), b"PRIVATE_HOST_CANARY")
        # Normal leading dots and escaped parent walks inside the named root work.
        (self.export / ".hidden").write_bytes(b"inside")
        self.assertEqual(self.client("read", "okernel/.hidden").stdout, b"inside")
        self.assertEqual(self.client("read", r"okernel/work/\2e\2e/.hidden").stdout, b"inside")
        process.terminate()
        self.assertEqual(process.wait(timeout=12), 0)
        self.assertFalse((self.runtime / "okernel").exists())
        self.assertTrue(all(not Path(f"/proc/{child}").exists() for child in children))

    def test_original_service_keeps_pinned_root_when_mount_path_is_replaced(self):
        self.start_original()
        (self.export / "work/shared").write_bytes(b"original-pinned-root")
        preserved = self.root / "preserved-root"
        self.export.rename(preserved)
        (self.export / "work").mkdir(parents=True)
        (self.export / "work/shared").write_bytes(b"unrelated-fallback-root")
        self.assertEqual(self.client("read", "okernel/work/shared").stdout, b"original-pinned-root")

    def test_shell_helper_publication_status_data_test_and_stop(self):
        (self.export / "work").mkdir()
        for name, target in (("u9fs", self.tree / "u9fs"), ("9pserve", self.mux),
                             ("9p", self.plan9 / "bin/9p"), ("okernel-9p-bridge", self.program)):
            destination = self.tools / "bin" / name
            destination.unlink(missing_ok=True)
            destination.symlink_to(target)
        # Only the private host probe substitutes fixture paths. The installed
        # helper and production C binary retain their fixed native export root.
        helper = self.root / "pkg-9p"
        text = (HERE / "pkg-9p").read_text()
        self.assertEqual(text.count("runtime=/run/okernel-9p"), 1)
        self.assertEqual(text.count("root=/n/okernel"), 1)
        helper.write_text(text.replace("runtime=/run/okernel-9p", "runtime=" + shlex.quote(str(self.runtime)))
                         .replace("root=/n/okernel", "root=" + shlex.quote(str(self.export))))
        environment = dict(os.environ, OSTADIX_PLAN9_PREFIX=str(self.tools), PLAN9=str(self.plan9))
        def invoke(*args):
            return subprocess.run(["sh", str(helper), *args], env=environment,
                                  capture_output=True, text=True, timeout=20)
        self.addCleanup(lambda: invoke("stop"))
        result = invoke("start")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ORIGINAL 9P BRIDGE READY", result.stdout)
        self.assertEqual(invoke("status").returncode, 0)
        self.assertIn("already running", invoke("start").stdout)
        result = invoke("test")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ORIGINAL 9P SHARED OBJECT ROUNDTRIP PASS", result.stdout)
        self.assertEqual(list((self.export / "work").iterdir()), [])
        self.assertEqual(invoke("stop").returncode, 0)
        self.assertEqual(invoke("status").returncode, 1)
        self.assertFalse((self.runtime / "okernel").exists())
        self.assertEqual(invoke("start", "arbitrary-root").returncode, 2)

    def direct_server(self):
        process = subprocess.Popen([str(self.tree / "u9fs"), "-n", "-a", "none", "-u", pwd.getpwuid(os.geteuid()).pw_name,
                                    "-m", "8192", "-l", str(self.root / "direct.log"), str(self.export)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        def cleanup():
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=3)
            process.stdin.close()
            process.stdout.close()
        self.addCleanup(cleanup)
        return process

    def rpc(self, process, kind, payload=b"", tag=1):
        process.stdin.write(struct.pack("<IBH", len(payload) + 7, kind, tag) + payload)
        process.stdin.flush()
        header = self.read_exact(process, 7)
        size, reply, returned_tag = struct.unpack("<IBH", header)
        self.assertEqual(returned_tag, tag)
        return reply, self.read_exact(process, size - 7)

    def read_exact(self, process, size):
        result = bytearray()
        while len(result) < size:
            self.assertTrue(select.select([process.stdout], [], [], 3)[0], "original exporter stalled")
            data = os.read(process.stdout.fileno(), size - len(result))
            self.assertTrue(data, "original exporter closed before its bounded reply")
            result.extend(data)
        return bytes(result)

    def string(self, value):
        return struct.pack("<H", len(value)) + value

    def attach(self, process):
        self.assertEqual(self.rpc(process, 100, struct.pack("<I", 8192) + self.string(b"9P2000"), 0xffff)[0], 101)
        self.assertEqual(self.rpc(process, 104, struct.pack("<II", 1, 0xffffffff) + self.string(b"root") + self.string(b""))[0], 105)

    def walk(self, process, fresh, *names):
        return self.rpc(process, 110, struct.pack("<IIH", 1, fresh, len(names)) + b"".join(self.string(name) for name in names))

    def test_original_create_rename_and_wire_nul_preflight_preserves_objects(self):
        (self.export / "work").mkdir()
        safe = self.export / "work/safe"
        safe.write_bytes(b"must remain unchanged")
        safe.chmod(0o644)
        process = self.direct_server()
        self.attach(process)
        self.assertEqual(self.walk(process, 2, b"work")[0], 111)
        for index, name in enumerate((b"..", b"\\2e\\2e", b"\\2e\\2e\\2fescape", b"bad/name", b"bad\\00suffix", b"bad\0suffix", b"bad\\xx")):
            with self.subTest(name=name):
                before = sorted(str(p.relative_to(self.export)) for p in self.export.rglob("*"))
                create = struct.pack("<I", 2) + self.string(name) + struct.pack("<IB", 0o644, 1)
                self.assertEqual(self.rpc(process, 114, create)[0], 107)
                self.assertEqual(sorted(str(p.relative_to(self.export)) for p in self.export.rglob("*")), before)
                # Embedded wire NULs must not allocate or retarget this fid.
                expected = 111 if index < 2 else 107
                self.assertEqual(self.walk(process, index + 10, b"work", name)[0], expected)
        self.assertEqual(self.walk(process, 4, b"work", b"safe")[0], 111)
        for name in (b"\\2e\\2e\\2fescape", b"../escape", b"bad\0suffix", b"\\00"):
            # Invalid rename plus destructive attributes must reject BEFORE chmod/truncate.
            stat_body = (struct.pack("<HI", 0xffff, 0xffffffff) + bytes(13)
                         + struct.pack("<IIIQ", 0o600, 0xffffffff, 0xffffffff, 0)
                         + self.string(name) + self.string(b"") * 3)
            stat = struct.pack("<H", len(stat_body)) + stat_body
            self.assertEqual(self.rpc(process, 126, struct.pack("<IH", 4, len(stat)) + stat)[0], 107)
            self.assertEqual(safe.read_bytes(), b"must remain unchanged")
            self.assertEqual(safe.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.rpc(process, 126, struct.pack("<IH", 4, 0))[0], 107)
        self.assertEqual(self.rpc(process, 124, struct.pack("<I", 4))[0], 125)

    def test_oversized_frame_returns_error_then_closes_without_mutation(self):
        (self.export / "work").mkdir()
        process = self.direct_server()
        self.attach(process)
        process.stdin.write(struct.pack("<IBH", 8193, 118, 0x1234))
        process.stdin.flush()
        size, kind, tag = struct.unpack("<IBH", self.read_exact(process, 7))
        self.assertEqual((kind, tag), (107, 0x1234))
        self.read_exact(process, size - 7)
        self.assertEqual(process.wait(timeout=3), 0)
        self.assertEqual(list((self.export / "work").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
