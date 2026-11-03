"""Read-only provider inspection, complete inventories and malformed inputs."""
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("plan9_readonly_verifier_test", ROOT / "scripts/plan9_userland_admission.py")
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)
ACTUAL = Path.home() / ".cache/okernel-plan9-userland/build-7"


def identity(path):
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def listing(values):
    return "".join(digest + " " + name + "\n" for name, digest in sorted(values.items()))


class ProviderFixture:
    """Synthetic metadata is only for verifier tests, never outer admission."""

    def __init__(self, root):
        self.root = root
        self.exports = root / "artifacts"
        self.captured = root / "inputs"
        self.exports.mkdir()
        self.captured.mkdir()
        names = {"/arm64/bin/" + name for name in verifier.TOOLS}
        names.update("/arm64/lib/" + name for name in verifier.LIBRARIES)
        names.update(("/arm64/include/u.h", "/sys/include/libc.h", "/rc/lib/rcmain",
                      "/arm64/mkfile", "/sys/src/mkfile.proto", "/sys/src/cmd/mkone",
                      "/sys/src/cmd/mkmany", "/sys/src/cmd/mklib", "/rc/bin/nusbrc"))
        self.files = {name: ("original:" + name).encode() for name in sorted(names)}
        originals = {name: hashlib.sha256(value).hexdigest() for name, value in self.files.items()}
        # The original boot prototype intentionally remaps this boot helper.
        originals["/rc/bin/nusbrc"] = "e" * 64
        self.files["/arm64/bin/p9cmdsrv"] = b"original-ABI test service bytes"
        self.files["/rc/bin/okernel-start"] = b"#!/bin/rc\noriginal-startup\n"
        self.startup = self.captured / "START.RC"
        self.startup.write_bytes(self.files["/rc/bin/okernel-start"])
        self.paq = b"PAQ test payload\0\xff\n"
        (self.exports / "USER.PAQ").write_bytes(self.paq)
        (self.exports / "SERVICE").write_bytes(self.files["/arm64/bin/p9cmdsrv"])
        (self.exports / "COMMIT.TXT").write_text(verifier.COMMIT + "\n")
        (self.exports / "ORIG.TXT").write_text(listing(originals))
        (self.exports / "SOURCE.TXT").write_text("declared original source inventory\n")
        (self.exports / "BUILD.LOG").write_text("synthetic unit fixture, no build executed\n")
        self.tools = {name: hashlib.sha256(self.files.get(name, ("native:" + name).encode())).hexdigest()
                      for name in verifier.BUILD_TOOLS}
        (self.exports / "TOOLS.TXT").write_text(listing(self.tools))
        self.document = {"schema": "ostadix.original9front-userland-builder/v1", "source_commit": verifier.COMMIT,
                         "exports_captured_after_halt": True, "original_tools": self.tools,
                         "inputs": {"START.RC": identity(self.startup)}}
        self.write_tar()
        self.write_image()
        self.refresh()

    def refresh(self):
        self.document["artifacts"] = {name: identity(self.exports / name) for name in verifier.EXPORTS}
        self.document["provider_files"] = [
            {"guest_path": name, "path": str(self.root / "provider" / name.lstrip("/")),
             "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
            for name, value in sorted(self.files.items())]
        self.document["provider_bytes"] = sum(map(len, self.files.values()))

    def write_tar(self, extra=(), *, directories=True, modes=None):
        with tarfile.open(self.exports / "USER.TAR", "w", format=tarfile.USTAR_FORMAT) as archive:
            if directories:
                names = {"qemu.bootfs"}
                for guest in self.files:
                    names.update(parent.as_posix() for parent in PurePosixPath("qemu.bootfs" + guest).parents
                                 if parent.as_posix() != ".")
                for name in sorted(names, key=lambda name: (name.count("/"), name)):
                    item = tarfile.TarInfo(name)
                    item.type = tarfile.DIRTYPE
                    item.mode = 0o775
                    archive.addfile(item)
            for guest, data in sorted(self.files.items()):
                item = tarfile.TarInfo("qemu.bootfs" + guest)
                item.mode = (modes or {}).get(guest, 0o775)
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
            for item, data in extra:
                archive.addfile(item, io.BytesIO(data) if data is not None else None)
        hashes = {"qemu.bootfs" + name: hashlib.sha256(data).hexdigest() for name, data in self.files.items()}
        (self.exports / "FILES.TXT").write_text(listing(hashes))

    def write_image(self, *, payload=None, **updates):
        payload = b"KERNEL\0" + self.paq + b"\0END" if payload is None else payload
        fields = dict(timestamp=verifier.EPOCH, length=len(payload), load=0x40100000,
                      entry=0x40100000, data_crc=zlib.crc32(payload), os=23, architecture=22,
                      kind=2, compression=0, name=b"9qemu")
        fields.update(updates)
        header = struct.pack(">7I4B32s", 0x27051956, 0, fields["timestamp"], fields["length"],
                             fields["load"], fields["entry"], fields["data_crc"], fields["os"],
                             fields["architecture"], fields["kind"], fields["compression"], fields["name"])
        checksum = zlib.crc32(header)
        header = header[:4] + struct.pack(">I", checksum) + header[8:]
        (self.exports / "KERNEL.U").write_bytes(header + payload)
        self.document["uimage"] = {"os": fields["os"], "architecture": fields["architecture"],
            "kind": fields["kind"], "compression": fields["compression"], "load": fields["load"],
            "entry": fields["entry"], "timestamp": fields["timestamp"],
            "name": fields["name"].rstrip(b"\0").decode("ascii"), "header_crc32": checksum,
            "payload_crc32": fields["data_crc"], "payload_bytes": fields["length"]}

    def verify(self):
        return verifier.verify_exports(self.root, self.captured, self.document)


def deny_writes():
    """Test guard covers writes, extraction, tempdirs and external execution."""
    stack = ExitStack()
    original_open = os.open
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def open_readonly(path, flags, *args, **kwargs):
        if flags & write_flags:
            raise AssertionError("verifier attempted an os.open write")
        return original_open(path, flags, *args, **kwargs)

    stack.enter_context(mock.patch.object(os, "open", side_effect=open_readonly))
    for owner, names in [(Path, ("mkdir", "write_bytes", "write_text", "chmod", "rename", "replace", "unlink")),
                         (os, ("mkdir", "makedirs", "chmod", "rename", "replace", "unlink", "remove", "symlink")),
                         (tarfile.TarFile, ("extract", "extractall")),
                         (tempfile, ("mkdtemp", "mkstemp", "TemporaryDirectory", "TemporaryFile")),
                         (subprocess, ("run", "Popen"))]:
        for name in names:
            stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("forbidden verifier effect: " + name)))
    return stack


class ReadonlyProviderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="plan9-readonly-test-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = ProviderFixture(Path(self.temporary.name))

    def test_complete_fixture_without_writes_or_extraction_and_remapped_boot_helper(self):
        with deny_writes():
            result = self.fixture.verify()
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["provider_files"]), len(self.fixture.files))
        self.assertEqual(result["provider_bytes"], sum(map(len, self.fixture.files.values())))
        self.assertEqual((result["writes"], result["extractions"], result["subprocesses"]), ([], [], []))

    def test_complete_exact_export_set_required(self):
        for action in ("extra", "missing", "manifest"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                fixture = ProviderFixture(Path(directory))
                if action == "extra":
                    (fixture.exports / "EXTRA").write_bytes(b"not declared")
                elif action == "missing":
                    (fixture.exports / "BUILD.LOG").unlink()
                else:
                    del fixture.document["artifacts"]["BUILD.LOG"]
                with self.assertRaisesRegex(ValueError, "export set"):
                    fixture.verify()

    def test_export_content_identity_mismatch_rejected(self):
        (self.fixture.exports / "BUILD.LOG").write_text("changed")
        with self.assertRaisesRegex(ValueError, "captured identity"):
            self.fixture.verify()

    def test_symlink_export_rejected(self):
        target = self.fixture.exports / "SERVICE"
        original = target.with_name("SERVICE.saved")
        target.rename(original)
        target.symlink_to(original)
        # Keep the exact export set to reach the nonsymlink descriptor check.
        original.rename(self.fixture.root / "SERVICE.saved")
        target.unlink()
        target.symlink_to(self.fixture.root / "SERVICE.saved")
        with self.assertRaisesRegex(ValueError, "nonsymlink"):
            self.fixture.verify()

    def test_symlink_export_directory_rejected(self):
        directory = self.fixture.exports.with_name("exports.saved")
        self.fixture.exports.rename(directory)
        self.fixture.exports.symlink_to(directory, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "nonsymlink directory"):
            self.fixture.verify()

    def test_source_commit_and_halted_export_requirement(self):
        for field, value in [("source_commit", "0" * 40), ("exports_captured_after_halt", False)]:
            document = copy.deepcopy(self.fixture.document)
            document[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "incomplete"):
                verifier.verify_exports(self.fixture.root, self.fixture.captured, document)
        (self.fixture.exports / "COMMIT.TXT").write_text("0" * 40 + "\n")
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "source commit"):
            self.fixture.verify()

    def test_declared_file_duplicate_alias_and_total_rejected(self):
        for change in ("duplicate", "alias", "total"):
            document = copy.deepcopy(self.fixture.document)
            if change == "duplicate":
                document["provider_files"].append(dict(document["provider_files"][0]))
            elif change == "alias":
                document["provider_files"][0]["guest_path"] = "/arm64//bin/7a"
            else:
                document["provider_bytes"] += 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                verifier.verify_exports(self.fixture.root, self.fixture.captured, document)

    def test_complete_member_set_and_native_hash_inventory_required(self):
        document = copy.deepcopy(self.fixture.document)
        document["provider_files"] = document["provider_files"][1:]
        with self.assertRaisesRegex(ValueError, "native or declared inventory"):
            verifier.verify_exports(self.fixture.root, self.fixture.captured, document)
        path = self.fixture.exports / "FILES.TXT"
        path.write_text(path.read_text() + path.read_text().splitlines()[0] + "\n")
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.fixture.verify()

    def test_archive_path_traversal_alias_duplicate_and_nonregular_rejected(self):
        for name, kind in [("qemu.bootfs/../escape", tarfile.REGTYPE),
                           ("qemu.bootfs/./escape", tarfile.REGTYPE),
                           ("qemu.bootfs//escape", tarfile.REGTYPE),
                           ("/qemu.bootfs/escape", tarfile.REGTYPE),
                           ("qemu.bootfs/arm64/bin/7a", tarfile.REGTYPE),
                           ("qemu.bootfs/link", tarfile.SYMTYPE),
                           ("qemu.bootfs/link", tarfile.LNKTYPE),
                           ("qemu.bootfs/sparse", tarfile.GNUTYPE_SPARSE),
                           ("qemu.bootfs/fifo", tarfile.FIFOTYPE)]:
            with self.subTest(name=name, kind=kind):
                item = tarfile.TarInfo(name)
                item.type = kind
                item.linkname = "elsewhere" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                item.size = 1 if kind == tarfile.REGTYPE else 0
                self.fixture.write_tar([(item, b"x" if item.size else None)])
                self.fixture.refresh()
                with self.assertRaises(ValueError):
                    self.fixture.verify()

    def test_file_ancestor_collision_rejected_without_filesystem_extraction(self):
        self.fixture.files["/shadow"] = b"file cannot be a directory"
        self.fixture.files["/shadow/child"] = b"child"
        self.fixture.write_tar(directories=False)
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "ancestor"):
            self.fixture.verify()

    def test_directory_replaced_by_file_and_special_modes_rejected(self):
        item = tarfile.TarInfo("qemu.bootfs/arm64")
        item.size = 1
        self.fixture.write_tar([(item, b"x")])
        self.fixture.refresh()
        with self.assertRaises(ValueError):
            self.fixture.verify()
        self.fixture.write_tar(modes={"/arm64/bin/7a": 0o4775})
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "special permission"):
            self.fixture.verify()

    def test_archive_content_and_length_must_match_manifest(self):
        old_document = copy.deepcopy(self.fixture.document)
        self.fixture.files["/arm64/bin/7a"] = b"modified"
        self.fixture.write_tar()
        self.fixture.refresh()
        old_document["artifacts"] = self.fixture.document["artifacts"]
        with self.assertRaisesRegex(ValueError, "length differs"):
            verifier.verify_exports(self.fixture.root, self.fixture.captured, old_document)
        self.fixture.document["provider_files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "native inventory"):
            self.fixture.verify()

    def test_archive_trailing_hidden_data_rejected(self):
        with (self.fixture.exports / "USER.TAR").open("ab") as stream:
            stream.write(b"hidden data")
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "after its terminator"):
            self.fixture.verify()

    def test_truncated_archive_rejected_without_publishing_partial_files(self):
        path = self.fixture.exports / "USER.TAR"
        path.write_bytes(path.read_bytes()[:513])
        self.fixture.refresh()
        before = {str(item.relative_to(self.fixture.root)) for item in self.fixture.root.rglob("*")}
        with self.assertRaises((ValueError, tarfile.TarError)):
            self.fixture.verify()
        after = {str(item.relative_to(self.fixture.root)) for item in self.fixture.root.rglob("*")}
        self.assertEqual(after, before)

    def test_original_selected_header_and_required_closure_checked(self):
        path = self.fixture.exports / "ORIG.TXT"
        originals = verifier._listing(path.read_text())
        originals["/arm64/include/u.h"] = "0" * 64
        path.write_text(listing(originals))
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "changed an original file"):
            self.fixture.verify()
        del self.fixture.files["/arm64/lib/libc.a"]
        self.fixture.write_tar()
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "missing a required"):
            self.fixture.verify()

    def test_tool_inventory_set_and_executed_tool_identity_checked(self):
        path = self.fixture.exports / "TOOLS.TXT"
        tools = dict(self.fixture.tools)
        del tools["/arm64/bin/mkpaqfs"]
        path.write_text(listing(tools))
        self.fixture.document["original_tools"] = tools
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "compiler/tool inventory"):
            self.fixture.verify()
        tools = dict(self.fixture.tools, **{"/arm64/bin/7c": "0" * 64})
        path.write_text(listing(tools))
        self.fixture.document["original_tools"] = tools
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "executed native tool"):
            self.fixture.verify()

    def test_service_and_startup_match_exact_captured_bytes(self):
        self.fixture.files["/arm64/bin/p9cmdsrv"] = b"replacement service"
        self.fixture.write_tar()
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "startup/service"):
            self.fixture.verify()
        self.fixture.files["/arm64/bin/p9cmdsrv"] = (self.fixture.exports / "SERVICE").read_bytes()
        self.fixture.files["/rc/bin/okernel-start"] = b"replacement startup"
        self.fixture.write_tar()
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "startup/service"):
            self.fixture.verify()

    def test_uimage_header_payload_crc_and_length_checked(self):
        path = self.fixture.exports / "KERNEL.U"
        original = path.read_bytes()
        for offset in (0, 4, len(original) - 1):
            with self.subTest(offset=offset):
                value = bytearray(original)
                value[offset] ^= 1
                path.write_bytes(value)
                self.fixture.refresh()
                with self.assertRaisesRegex(ValueError, "CRC"):
                    self.fixture.verify()
        self.fixture.write_image(length=999)
        self.fixture.refresh()
        with self.assertRaisesRegex(ValueError, "payload length"):
            self.fixture.verify()

    def test_uimage_isa_entry_epoch_and_metadata_checked(self):
        for changes in [dict(architecture=2), dict(entry=0x40200000), dict(timestamp=0)]:
            with self.subTest(changes=changes):
                self.fixture.write_image(**changes)
                self.fixture.refresh()
                with self.assertRaises(ValueError):
                    self.fixture.verify()
        self.fixture.write_image()
        self.fixture.refresh()
        self.fixture.document["uimage"]["name"] = "different"
        with self.assertRaisesRegex(ValueError, "metadata differs"):
            self.fixture.verify()

    def test_kernel_must_embed_exact_paq_once(self):
        for payload in [b"without provider", self.fixture.paq + b"separator" + self.fixture.paq]:
            with self.subTest(payload=payload):
                self.fixture.write_image(payload=payload)
                self.fixture.refresh()
                with self.assertRaisesRegex(ValueError, "PAQ"):
                    self.fixture.verify()

    def test_in_place_mutation_during_digest_rejected(self):
        original = verifier._StableFile._digest
        changed = []

        def mutate(file):
            result = original(file)
            if file.path.name == "USER.TAR" and not changed:
                changed.append(True)
                with file.path.open("r+b") as stream:
                    stream.write(b"mutated")
            return result

        with mock.patch.object(verifier._StableFile, "_digest", mutate), self.assertRaisesRegex(ValueError, "changed during"):
            self.fixture.verify()

    def test_regular_file_replaced_by_fifo_before_open_cannot_block(self):
        original = os.open
        target = self.fixture.exports / "SERVICE"
        changed = []

        def swap(path, flags, *args, **kwargs):
            if Path(path) == target and not changed:
                # Fail safely on the old flags rather than hang the test.
                self.assertTrue(flags & os.O_NONBLOCK, "read-only open must not block on a raced FIFO")
                target.unlink()
                os.mkfifo(target)
                changed.append(True)
            return original(path, flags, *args, **kwargs)

        with mock.patch.object(os, "open", side_effect=swap), self.assertRaises(ValueError):
            self.fixture.verify()
        self.assertTrue(changed)


@unittest.skipUnless((ACTUAL / "result.json").is_file(), "qualified original provider capture unavailable")
class ActualOriginalProviderTests(unittest.TestCase):
    def test_actual_build7_complete_closure_verified_without_writes_or_extraction(self):
        document = json.loads((ACTUAL / "result.json").read_text())
        with deny_writes():
            result = verifier.verify_exports(ACTUAL, ACTUAL / "inputs", document)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["provider_files"]), 239)
        self.assertEqual(result["provider_bytes"], 13163590)
        self.assertEqual(result["paq_payload_offset"], 1268464)
        self.assertEqual(result["original_tools"], document["original_tools"])
        self.assertEqual(result["uimage"], document["uimage"])


if __name__ == "__main__":
    unittest.main()
