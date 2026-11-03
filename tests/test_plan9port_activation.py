"""Exercise real prefix publication with an injected bridge health failure."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ACTIVATE = ROOT / "ocore/guest/linux/package-domain/plan9port-activate"


class Plan9ActivationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="plan9-activation-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.prefix = self.root / "plan9"
        self.old = self.root / "plan9.generations/runtime.old"
        self.new = self.root / "plan9.generations/runtime.new"
        self.bin = self.root / "commands"
        self.bin.mkdir()
        self.receipt = self.root / "receipt"
        self.receipt.mkdir()
        (self.receipt / "status").write_text("incomplete\n")
        for runtime in (self.old, self.new):
            (runtime / "bin").mkdir(parents=True)
            for name in ("rc", "mk", "9p", "9"):
                path = runtime / "bin" / name
                path.write_text(f"#!/bin/sh\necho '{runtime.name}-{name}'\n")
                path.chmod(0o755)
        self.prefix.symlink_to(self.old)
        for name in ("rc", "mk", "9p", "9"):
            (self.bin / name).symlink_to(self.prefix / "bin" / name)
        self.unrelated = self.bin / "unrelated-user-tool"
        self.unrelated.write_text("preserve this user command\n")
        self.state = self.root / "service"
        self.state.write_text(str(self.old) + "\n")
        self.namespace = self.root / "namespace"
        self.namespace.write_text("#!/bin/sh\nexit 0\n")
        self.namespace.chmod(0o755)
        self.bridge = self.root / "bridge"
        self.bridge.write_text('''#!/bin/sh
set -eu
selected="$(readlink "$PLAN9" 2>/dev/null || true)"
running="$(cat "$SERVICE_STATE")"
printf '%s|%s|%s\n' "$1" "$selected" "$running" >> "$SERVICE_LOG"
case "$1" in
 status) [ -n "$running" ] || exit 1; printf 'owned-supervisor=4242 start=112233 executable=%s/bin/bridge\n' "$running" ;;
 stop) : > "$SERVICE_STATE" ;;
 start) printf '%s\n' "$selected" > "$SERVICE_STATE" ;;
 test)
  printf '%s\n' "$selected" > "$SERVICE_STATE"
  if [ "${CONCURRENT_PREFIX:-0}" = 1 ]; then rm "$PLAN9"; printf 'unrelated new owner\n' > "$PLAN9"; fi
  exit "${BRIDGE_HEALTH_STATUS:-17}"
  ;;
esac
''')
        self.bridge.chmod(0o755)
        self.env = {**os.environ, "SERVICE_STATE": str(self.state), "SERVICE_LOG": str(self.root / "service.log")}

    def invoke(self):
        return subprocess.run(["sh", str(ACTIVATE), str(self.prefix), str(self.new), str(self.bin),
                               str(self.receipt), str(self.namespace), str(self.bridge)],
                              env=self.env, capture_output=True, text=True)

    def test_failed_health_restores_old_active_prefix_tools_and_running_service(self):
        identities = {name: (self.bin / name).lstat().st_ino for name in ("rc", "mk", "9p", "9")}
        result = self.invoke()
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
        self.assertEqual(self.prefix.readlink(), self.old)
        self.assertEqual(self.state.read_text(), str(self.old) + "\n")
        self.assertEqual(subprocess.check_output([str(self.bin / "rc")], text=True), "runtime.old-rc\n")
        self.assertEqual({name: (self.bin / name).lstat().st_ino for name in identities}, identities)
        self.assertEqual(self.unrelated.read_text(), "preserve this user command\n")
        self.assertTrue((self.new / "bin/rc").is_file())
        self.assertEqual((self.receipt / "status").read_text(), "incomplete\n")
        self.assertIn("start=112233", (self.receipt / "bridge-before.txt").read_text())
        self.assertIn("prior prefix restored", (self.receipt / "activation-result").read_text())
        actions = (self.root / "service.log").read_text().splitlines()
        self.assertEqual([line.split("|", 1)[0] for line in actions], ["status", "stop", "test", "stop", "start"])
        self.assertEqual(actions[-1].split("|")[1], str(self.old))

    def test_failed_first_install_removes_only_its_new_links(self):
        self.prefix.unlink()
        for name in ("rc", "mk", "9p", "9"):
            (self.bin / name).unlink()
        self.state.write_text("")
        result = self.invoke()
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertFalse(self.prefix.is_symlink())
        self.assertEqual(list(self.bin.iterdir()), [self.unrelated])
        self.assertTrue(self.old.is_dir())
        self.assertTrue(self.new.is_dir())
        self.assertEqual(self.state.read_text(), "")

    def test_rollback_does_not_start_a_previously_stopped_service(self):
        self.state.write_text("")
        self.assertEqual(self.invoke().returncode, 17)
        self.assertEqual(self.prefix.readlink(), self.old)
        self.assertEqual(self.state.read_text(), "")
        self.assertNotIn("start|", (self.root / "service.log").read_text())

    def test_success_publishes_new_runtime_and_preserves_old_generation(self):
        self.env["BRIDGE_HEALTH_STATUS"] = "0"
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.prefix.readlink(), self.new)
        self.assertEqual(self.state.read_text(), str(self.new) + "\n")
        self.assertEqual(subprocess.check_output([str(self.bin / "rc")], text=True), "runtime.new-rc\n")
        self.assertTrue((self.old / "bin/rc").is_file())

    def test_unrelated_prefix_or_command_is_preserved_before_service_changes(self):
        (self.bin / "rc").unlink()
        (self.bin / "rc").write_text("unrelated command\n")
        self.assertEqual(self.invoke().returncode, 1)
        self.assertEqual((self.bin / "rc").read_text(), "unrelated command\n")
        self.assertEqual(self.prefix.readlink(), self.old)
        self.assertFalse((self.root / "service.log").exists())

    def test_concurrent_prefix_owner_is_not_overwritten_by_rollback(self):
        self.env["CONCURRENT_PREFIX"] = "1"
        result = self.invoke()
        self.assertEqual(result.returncode, 17)
        self.assertFalse(self.prefix.is_symlink())
        self.assertEqual(self.prefix.read_text(), "unrelated new owner\n")
        self.assertIn("concurrent prefix owner preserved", (self.receipt / "activation-result").read_text())

    def test_required_missing_namespace_preserves_old_prefix_and_service(self):
        self.namespace.write_text("#!/bin/sh\nexit 3\n")
        self.env["OSTADIX_PKG_NAMESPACE_REQUIRED"] = "1"
        self.assertEqual(self.invoke().returncode, 3)
        self.assertEqual(self.prefix.readlink(), self.old)
        self.assertEqual(self.state.read_text(), str(self.old) + "\n")
        self.assertFalse((self.root / "service.log").exists())


if __name__ == "__main__":
    unittest.main()
