"""Artifact-boundary tests; actual native build qualification uses a private VM."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("plan9_userland_builder", ROOT / "scripts/build_okernel_plan9_userland.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class Plan9UserlandBuilderTests(unittest.TestCase):
    def archive(self, directory, entries):
        path = directory / "provider.tar"
        with tarfile.open(path, "w") as tar:
            for name, data, kind in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.mode = 0o555
                member.size = len(data) if kind == tarfile.REGTYPE else 0
                if kind == tarfile.SYMTYPE:
                    member.linkname = "/tmp/unrelated"
                tar.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        return path

    def test_pinned_image_admission_uses_full_bytes_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image"; path.write_bytes(b"original image")
            with patch.object(BUILDER.original, "IMAGE_BYTES", path.stat().st_size), patch.object(
                    BUILDER.original, "IMAGE_SHA256", hashlib.sha256(path.read_bytes()).hexdigest()):
                self.assertEqual(BUILDER.admit_image(path)["bytes"], 14)
                link = Path(tmp) / "link"; link.symlink_to(path)
                with self.assertRaisesRegex(ValueError, "nonsymlink"):
                    BUILDER.admit_image(link)
                path.write_bytes(b"changed! image")
                with self.assertRaisesRegex(ValueError, "pinned"):
                    BUILDER.admit_image(path)

    def test_archive_extracts_exact_native_hashes_and_preserves_executable_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); data = b"original executable\x00\xff"
            archive = self.archive(root, [("qemu.bootfs", b"", tarfile.DIRTYPE),
                                         ("qemu.bootfs/arm64/bin/rc", data, tarfile.REGTYPE)])
            records = BUILDER.extract_provider(archive, root / "out", {
                "qemu.bootfs/arm64/bin/rc": hashlib.sha256(data).hexdigest()})
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["guest_path"], "/arm64/bin/rc")
            self.assertEqual((root / "out/arm64/bin/rc").read_bytes(), data)
            self.assertEqual((root / "out/arm64/bin/rc").stat().st_mode & 0o777, 0o555)

    def test_archive_rejects_paths_links_duplicates_and_unbound_files(self):
        cases = [
            [("/qemu.bootfs/file", b"x", tarfile.REGTYPE)],
            [("qemu.bootfs/../../escape", b"x", tarfile.REGTYPE)],
            [("other/file", b"x", tarfile.REGTYPE)],
            [("qemu.bootfs/link", b"", tarfile.SYMTYPE)],
            [("qemu.bootfs/f", b"x", tarfile.REGTYPE)] * 2,
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); archive = self.archive(root, entries)
                hashes = {name: hashlib.sha256(data).hexdigest() for name, data, _ in entries}
                with self.assertRaises(ValueError):
                    BUILDER.extract_provider(archive, root / "out", hashes)
                self.assertFalse((root / "escape").exists())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = self.archive(root, [("qemu.bootfs/f", b"x", tarfile.REGTYPE)])
            with self.assertRaisesRegex(ValueError, "lacks"):
                BUILDER.extract_provider(archive, root / "out", {})

    def test_archive_rejects_changed_or_omitted_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = self.archive(root, [("qemu.bootfs/f", b"x", tarfile.REGTYPE)])
            with self.assertRaisesRegex(ValueError, "differs"):
                BUILDER.extract_provider(archive, root / "bad", {"qemu.bootfs/f": "0" * 64})
            with self.assertRaisesRegex(ValueError, "omits"):
                BUILDER.extract_provider(archive, root / "missing", {
                    "qemu.bootfs/f": hashlib.sha256(b"x").hexdigest(), "qemu.bootfs/missing": "0" * 64})

    def test_native_hash_inventory_rejects_ambiguity(self):
        digest = hashlib.sha256(b"hello").hexdigest()
        self.assertEqual(BUILDER.hash_listing(digest + "\t/arm64/bin/rc\n"), {"/arm64/bin/rc": digest})
        for value in [digest + " x\n" + digest + " x\n", "garbage", digest + " file name"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                BUILDER.hash_listing(value)

    def test_native_build_contract_keeps_archive_closure_inside_paq(self):
        proto = BUILDER.provider_proto()
        for name in ("7c", "7a", "7l", "mk", "libc.a", "libbio.a", "libsec.a", "libmp.a"):
            self.assertIn("\t\t" + name + "\n", proto)
        self.assertIn("\tinclude\n\t\t+", proto)
        self.assertIn("okernel-start 555 sys sys /tmp/START.RC", proto)
        script = BUILDER.guest_script("fixture")
        self.assertIn("7l -o /tmp/p9cmdsrv /tmp/p9cmdsrv.7 -lsec -lmp", script)
        self.assertIn("bind /tmp/paqmount/arm64 /arm64", script)
        self.assertNotIn("bind -b", script)
        self.assertIn("/arm64/bin/7c -o HELLO.7 HELLO.C", script)
        self.assertIn("@{\n    rfork n\n", script)
        self.assertIn("if(! ~ $paqbefore(1) $paqafter(1)) fail changedpaq", script)
        self.assertLess(script.index("paqfs -qav"), script.index("mk 'CONF=qemu'"))
        self.assertNotIn("/n/okernel", script)
        self.assertNotIn("head.json", script)

    def test_original_inventory_cannot_omit_required_tool(self):
        required = {"/arm64/bin/" + name for name in BUILDER.TOOLS}
        required.update("/arm64/lib/" + name for name in BUILDER.LIBRARIES)
        required.update(("/rc/lib/rcmain", "/arm64/mkfile", "/sys/src/mkfile.proto",
                         "/sys/src/cmd/mkone", "/sys/src/cmd/mkmany", "/sys/src/cmd/mklib",
                         "/sys/include/libc.h", "/arm64/include/u.h"))
        records = [{"guest_path": name, "sha256": "a" * 64} for name in required]
        hashes = {name: "a" * 64 for name in required}
        BUILDER.validate_original_files(records, hashes)
        del hashes["/arm64/lib/libc.a"]
        with self.assertRaisesRegex(ValueError, "omits"):
            BUILDER.validate_original_files(records, hashes)

    def test_private_script_hook_rejects_reused_outputs_and_unsafe_inputs_before_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / "source"; source.write_bytes(b"input")
            with patch.object(BUILDER, "admit_image") as admit:
                cases = [(root, {}, (b"PASS",)),
                         (root / "new", {}, ()),
                         (root / "new", {"../oops": source}, (b"PASS",)),
                         (root / "new", {"a.rc": source, "A.RC": source}, (b"PASS",)),
                         (root / "new", {"VERIFY.RC": source}, (b"PASS",)),
                         (root / "new", {}, (b"bad\nmarker",)),
                         (root / "new", {}, (b"\xff",))]
                for output, inputs, markers in cases:
                    with self.subTest(output=output, inputs=inputs, markers=markers), self.assertRaises(ValueError):
                        BUILDER.run_script_vm(output, source, source, root, b"rc", inputs, "qemu", 1, markers)
                admit.assert_not_called()
                self.assertFalse((root / "new").exists())

    def test_revalidation_rejects_legacy_unsealed_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "result.json").write_text(json.dumps({
                "schema": "ostadix.original9front-userland-builder/v1",
                "source_commit": BUILDER.COMMIT, "ok": False}))
            with self.assertRaisesRegex(ValueError, "export identities sealed"):
                BUILDER.revalidate(root)
            self.assertFalse((root / "result-revalidated.json").exists())

    def test_console_exchange_rejects_ambiguous_or_nonbyte_inputs_before_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / "source"; source.write_bytes(b"input")
            invalid = [((b"READY\n", b"input"),), ((b"READY", "input"),),
                       ((b"READY", b""),), ((b"READY", b"one"), (b"READY", b"two")),
                       ((b"READY",),)]
            with patch.object(BUILDER, "admit_image") as admit:
                for exchanges in invalid:
                    with self.subTest(exchanges=exchanges), self.assertRaisesRegex(ValueError, "console exchange"):
                        BUILDER.run_script_vm(root / "new", source, source, root,
                            b"rc", {}, "qemu", 1, (b"PASS",), console_exchanges=exchanges)
                admit.assert_not_called()
                self.assertFalse((root / "new").exists())


if __name__ == "__main__":
    unittest.main()
