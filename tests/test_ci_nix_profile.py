"""Pure profile/transport safety checks; these do not qualify a Nix runtime."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts import prepare_ci_nix_profile as profile


ROOT = Path(__file__).resolve().parents[1]


class NixProfileTests(unittest.TestCase):
    def test_missing_safe_extraction_support_fails_before_preparation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work_dir = Path(temporary) / "work"
            with mock.patch.object(profile, "tarfile", object()):
                with self.assertRaisesRegex(RuntimeError, "tarfile.data_filter"):
                    profile.prepare(work_dir, {}, {"commands": []})
            self.assertFalse(work_dir.exists())

    def test_checked_in_pin_is_an_immutable_official_archive(self) -> None:
        pin = profile.load_pin(profile.PIN)
        self.assertEqual(pin["revision"], "ac588ef1c914865dad517b337ea0eb9694a4021c")
        self.assertEqual(pin["archive_sha256"], "a5ccd31da7019267139fc2be2a39f1d646c893a4f6117a0f7bef50679e00f3c3")
        self.assertEqual(pin["archive_bytes"], 51276763)

    def test_mutable_unofficial_malformed_or_remote_profile_is_rejected(self) -> None:
        pin = profile.load_pin(profile.PIN)
        for changes in (
            {"revision": "nixos-26.05"},
            {"archive_url": "https://codeload.github.com/NixOS/nixpkgs/tar.gz/nixos-26.05"},
            {"repository": "https://github.com/example/nixpkgs"},
            {"archive_sha256": "0" * 63},
            {"archive_bytes": True},
            {"archive_bytes": profile.MAX_ARCHIVE_BYTES + 1},
            {"store": "ssh://example"},
        ):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "pin.json"
                path.write_text(json.dumps(dict(pin, **changes)))
                with self.assertRaises(ValueError):
                    profile.load_pin(path)

    def test_transport_requires_exact_bytes_and_hash_before_retaining_archive(self) -> None:
        data = b"bounded transport test bytes"
        pin = {"archive_bytes": len(data), "archive_sha256": hashlib.sha256(data).hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "archive"
            profile.copy_verified_archive(io.BytesIO(data), destination, pin)
            self.assertEqual(destination.read_bytes(), data)
            # A failed exclusive create must not delete an existing file.
            with self.assertRaises(FileExistsError):
                profile.copy_verified_archive(io.BytesIO(data), destination, pin)
            self.assertEqual(destination.read_bytes(), data)
            destination.unlink()
            for payload in (data[:-1], data + b"extra", b"X" * len(data)):
                with self.subTest(payload=payload), self.assertRaises(ValueError):
                    profile.copy_verified_archive(io.BytesIO(payload), destination, pin)
                self.assertFalse(destination.exists())

    @staticmethod
    def write_test_tar(path: Path, members: list[tuple[str, bytes | str]]) -> None:
        with tarfile.open(path, "w:gz") as archive:
            for name, payload in members:
                member = tarfile.TarInfo(name)
                if isinstance(payload, str):
                    member.type = tarfile.SYMTYPE
                    member.linkname = payload
                    archive.addfile(member)
                else:
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))

    def test_archive_retains_safe_original_relative_symlinks(self) -> None:
        revision = "a" * 40
        prefix = f"nixpkgs-{revision}"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.tar.gz"
            self.write_test_tar(archive, [
                (prefix + "/default.nix", b"transport test only"),
                (prefix + "/lib/.version", b"26.05"),
                (prefix + "/.version", "lib/.version"),
            ])
            source = profile.extract_archive(archive, root / "source", revision)
            self.assertTrue((source / ".version").is_symlink())
            self.assertEqual((source / ".version").read_bytes(), b"26.05")

    def test_archive_cannot_escape_root_or_materialize_external_links(self) -> None:
        revision = "a" * 40
        prefix = f"nixpkgs-{revision}"
        for entry in (
            ("/absolute", b"bad"),
            (prefix + "/../escape", b"bad"),
            ("different-root/default.nix", b"bad"),
            (prefix + "/escape", "../../outside"),
        ):
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "source.tar.gz"
                self.write_test_tar(archive, [(prefix + "/default.nix", b"test"), entry])
                with self.assertRaises((ValueError, tarfile.FilterError)):
                    profile.extract_archive(archive, root / "source", revision)
                self.assertFalse((root / "outside").exists())

    def test_logical_path_without_readable_exact_bytes_does_not_qualify(self) -> None:
        store_path = "/nix/store/" + "a" * 32 + "-ostadix-ci-profile.txt"
        with mock.patch.object(Path, "read_bytes", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                profile.verify_store_bytes(store_path, profile.PROBE_BYTES)
        with mock.patch.object(Path, "read_bytes", return_value=b"different"):
            with self.assertRaises(ValueError):
                profile.verify_store_bytes(store_path, profile.PROBE_BYTES)
        with self.assertRaises(ValueError):
            profile.verify_store_bytes("ssh://host" + store_path, profile.PROBE_BYTES)

    def test_workflow_requires_preflight_before_original_examples_and_retains_report(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        suite = workflow.split("  rust-tests:\n", 1)[1].split("  rust-hosted:\n", 1)[0]
        self.assertIn("nix-bin nix-setup-systemd", suite)
        self.assertIn("sudo systemctl start nix-daemon.service || ci_nix_profile_fail", suite)
        self.assertNotIn("sudo systemctl start nix-daemon.socket", suite)
        self.assertIn("--no-install-recommends acl clang", suite)
        self.assertIn("ci_nix_socket=/nix/var/nix/daemon-socket/socket", suite)
        self.assertIn('sudo test -S "$ci_nix_socket" && sudo test ! -L "$ci_nix_socket"', suite)
        self.assertIn('$(sudo stat -c %u "$ci_nix_socket")', suite)
        self.assertIn('ci_nix_uid="$(id -u)"', suite)
        self.assertIn('sudo setfacl -m "u:$ci_nix_uid:--x" /nix/var/nix/daemon-socket', suite)
        self.assertIn('sudo setfacl -m "u:$ci_nix_uid:rw-" "$ci_nix_socket"', suite)
        self.assertIn('[[ "$ci_nix_socket_ready" == 1 ]] || ci_nix_profile_fail', suite)
        self.assertNotIn("chmod", suite)
        self.assertNotIn("chown", suite)
        self.assertLess(suite.index("Cache Cargo"), suite.index("scripts/prepare_ci_nix_profile.py"))
        self.assertLess(suite.index("scripts/prepare_ci_nix_profile.py"), suite.index("./test_o_lang_examples.sh"))
        self.assertIn("target/ci-tool-pins/nix-example-profile.json", suite)
        self.assertIn("if: always()", suite)


if __name__ == "__main__":
    unittest.main()
