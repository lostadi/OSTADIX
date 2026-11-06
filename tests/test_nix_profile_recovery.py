"""Nix recovery must preserve original bytes and refuse ambiguous host state."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


HELPER = Path(__file__).resolve().parents[1] / "scripts/nix_profile_recovery.py"
SPEC = importlib.util.spec_from_file_location("nix_profile_recovery", HELPER)
assert SPEC and SPEC.loader
recovery = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = recovery
SPEC.loader.exec_module(recovery)
BLOCK = (b"\n# Nix\nif [ -e '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh' ]; then\n"
         b"  . '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh'\nfi\n# End Nix\n\n")


class NixProfileRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="nix recovery test ")
        self.addCleanup(self.temporary.cleanup)
        self.etc = Path(self.temporary.name).resolve() / "etc"
        self.etc.mkdir(mode=0o755)

    def write(self, name: str, data: bytes) -> Path:
        path = self.etc / name
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o644)
        return path

    def snapshot(self) -> dict[str, bytes]:
        return {str(path.relative_to(self.etc)): path.read_bytes()
                for path in self.etc.rglob("*") if path.is_file() and not path.is_symlink()}

    def reported_failure(self) -> dict[str, bytes]:
        self.write("zsh/zshrc", BLOCK)
        self.write("zsh/zshrc.backup-before-nix", BLOCK.replace(b"  .", b"    .") + b"        \n")
        self.write("bash.bashrc", BLOCK + BLOCK)
        self.write("profile.d/nix.sh", BLOCK)
        self.write("zshrc", b"# macOS custom settings\nsetopt COMBINING_CHARS\n")
        self.write("bashrc", b"# macOS bash settings\nPS1='hello'\n")
        return self.snapshot()

    def test_reported_nix_only_backup_is_archived_with_all_original_bytes(self) -> None:
        original = self.reported_failure()
        plan = recovery.plan_recovery(self.etc)
        self.assertEqual(len(plan), 4)
        archive = recovery.archive_profiles(plan, self.etc)
        self.assertIsNotNone(archive)
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o700)
        manifest = json.loads((archive / "manifest.json").read_text())
        self.assertEqual(len(manifest), 4)
        for item in manifest:
            source = Path(item["original"])
            self.assertFalse(source.exists())
            self.assertEqual((archive / item["archived"]).read_bytes(), original[str(source.relative_to(self.etc))])
        for retained in ("zshrc", "bashrc"):
            self.assertEqual((self.etc / retained).read_bytes(), original[retained])
        self.assertEqual(recovery.plan_recovery(self.etc), [])

    def test_empty_backup_and_absent_profile_are_recoverable(self) -> None:
        self.write("zshrc.backup-before-nix", b" \n")
        plan = recovery.plan_recovery(self.etc)
        self.assertEqual(len(plan), 1)
        recovery.archive_profiles(plan, self.etc)
        self.assertFalse((self.etc / "zshrc").exists())

    def test_fresh_host_and_installed_nix_do_not_touch_backups(self) -> None:
        self.assertEqual(recovery.plan_recovery(self.etc), [])
        self.reported_failure()
        before = self.snapshot()
        self.assertEqual(recovery.plan_recovery(self.etc, installed=True, evidence=("/nix",)), [])
        self.assertEqual(self.snapshot(), before)

    def test_custom_backup_or_paired_profile_refuses_entire_plan(self) -> None:
        for target in ("zsh/zshrc.backup-before-nix", "zsh/zshrc"):
            with self.subTest(target=target):
                self.reported_failure()
                self.write(target, BLOCK + b"export CUSTOM=keep\n")
                before = self.snapshot()
                with self.assertRaisesRegex(recovery.RecoveryError, "custom or unrecognized"):
                    recovery.plan_recovery(self.etc)
                self.assertEqual(self.snapshot(), before)
                self.assertFalse(list(self.etc.glob("nix-profile-recovery-*")))

    def test_unpaired_mixed_nix_profile_is_preserved_and_refused(self) -> None:
        self.reported_failure()
        self.write("bashrc", b"export CUSTOM=keep\n" + BLOCK)
        before = self.snapshot()
        with self.assertRaises(recovery.RecoveryError):
            recovery.plan_recovery(self.etc)
        self.assertEqual(self.snapshot(), before)

    def test_existing_installation_evidence_prevents_repair(self) -> None:
        self.reported_failure()
        before = self.snapshot()
        for evidence in ("/nix", "daemon", "Nix Store", "mount", "user profile"):
            with self.subTest(evidence=evidence), self.assertRaisesRegex(recovery.RecoveryError, "existing or incomplete"):
                recovery.plan_recovery(self.etc, evidence=(evidence,))
        self.assertEqual(self.snapshot(), before)

    def test_file_symlink_directory_and_hardlink_are_refused(self) -> None:
        backup = self.write("zshrc.backup-before-nix", BLOCK)
        other = self.write("outside", BLOCK)
        for kind in ("symlink", "directory", "hardlink"):
            with self.subTest(kind=kind):
                backup.unlink()
                if kind == "symlink":
                    backup.symlink_to(other)
                elif kind == "directory":
                    backup.mkdir()
                else:
                    os.link(other, backup)
                with self.assertRaisesRegex(recovery.RecoveryError, "regular profile"):
                    recovery.plan_recovery(self.etc)
                self.assertEqual(other.read_bytes(), BLOCK)
                if kind == "directory":
                    backup.rmdir()
                    backup.write_bytes(BLOCK)

    def test_symlinked_or_writable_parent_directory_is_refused(self) -> None:
        outside = self.etc.parent / "outside"
        outside.mkdir()
        (outside / "zshrc.backup-before-nix").write_bytes(BLOCK)
        (self.etc / "zsh").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(recovery.RecoveryError, "unsafe profile directory"):
            recovery.plan_recovery(self.etc)
        (self.etc / "zsh").unlink()
        self.write("zsh/zshrc.backup-before-nix", BLOCK)
        (self.etc / "zsh").chmod(0o777)
        with self.assertRaisesRegex(recovery.RecoveryError, "unsafe profile directory"):
            recovery.plan_recovery(self.etc)

    def test_changed_profile_or_install_state_aborts_before_any_move(self) -> None:
        self.reported_failure()
        plan = recovery.plan_recovery(self.etc)
        self.write("zsh/zshrc", BLOCK + b"# changed\n")
        before = self.snapshot()
        with self.assertRaisesRegex(recovery.RecoveryError, "changed since inspection"):
            recovery.archive_profiles(plan, self.etc)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(list(self.etc.glob("nix-profile-recovery-*")))
        with self.assertRaisesRegex(recovery.RecoveryError, "state changed"):
            recovery.archive_profiles(plan, self.etc, state_check=lambda: ("/nix",))

    def test_failed_second_move_restores_first_without_overwriting(self) -> None:
        original = self.reported_failure()
        plan = recovery.plan_recovery(self.etc)
        real_rename = Path.rename
        calls = 0

        def fail_second(path: Path, target: Path) -> Path:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected move failure")
            return real_rename(path, target)

        with mock.patch.object(Path, "rename", fail_second):
            with self.assertRaisesRegex(recovery.RecoveryError, "moved profiles restored"):
                recovery.archive_profiles(plan, self.etc)
        for name, data in original.items():
            self.assertEqual((self.etc / name).read_bytes(), data)

    def test_existing_archive_is_not_reused_or_overwritten(self) -> None:
        self.reported_failure()
        old = self.etc / "nix-profile-recovery-existing"
        old.mkdir()
        marker = old / "keep"
        marker.write_bytes(b"previous backup")
        new = recovery.archive_profiles(recovery.plan_recovery(self.etc), self.etc)
        self.assertNotEqual(new, old)
        self.assertEqual(marker.read_bytes(), b"previous backup")

    def test_read_only_cli_modes_never_archive_or_escalate(self) -> None:
        self.reported_failure()
        plan = recovery.plan_recovery(self.etc)
        before = self.snapshot()
        for args, expected in (([], 1), (["--plan-repair"], 3), (["--repair", "--dry-run"], 0)):
            with self.subTest(args=args), mock.patch.object(recovery, "plan_recovery", return_value=plan), \
                    mock.patch.object(recovery, "installation_evidence", return_value=()), \
                    mock.patch.object(recovery, "archive_profiles") as archive, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(recovery.main(args), expected)
                archive.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_invoking_user_home_survives_sudo_home_change(self) -> None:
        with mock.patch.object(recovery.os, "geteuid", return_value=0), \
                mock.patch.dict(os.environ, {"SUDO_UID": "1234"}), \
                mock.patch.object(recovery.pwd, "getpwuid", side_effect=lambda uid: type("User", (), {"pw_dir": "/invoker" if uid == 1234 else "/root"})), \
                mock.patch.object(Path, "home", return_value=Path("/root")):
            self.assertEqual(recovery.user_homes(), {Path("/root"), Path("/invoker")})


if __name__ == "__main__":
    unittest.main()
