"""Exercise DHCP/repository state transitions without touching host networking."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / "ocore/guest/linux/package-domain"
SPEC = importlib.util.spec_from_file_location("guest_tools_update", ROOT / "scripts/update_okernel_guest_tools.py")
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)


class GuestNetworkingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("pkg-net", "pkg-net-udhcpc"):
            shutil.copyfile(HELPERS / name, self.bin / name)
            (self.bin / name).chmod(0o755)
        self.tool("ip", 'printf "%s\\n" "$*" >> "$NETWORK_LOG"\n[ "${IP_FAIL:-0}" != 1 ]\n')
        self.tool("ipcalc", "printf 'PREFIX=24\\n'\n")
        self.tool("udhcpc", '''[ "${DHCP_FAIL:-0}" != 1 ] || exit 8
while [ "$#" -gt 0 ]; do
 case "$1" in
  -i) interface="$2"; shift 2 ;;
  -s) hook="$2"; shift 2 ;;
  *) shift ;;
 esac
done
[ "${DHCP_NO_HOOK:-0}" != 1 ] || exit 0
export interface ip=10.0.2.15 subnet=255.255.255.0 router=10.0.2.2 dns=10.0.2.3
"$hook" bound
''')
        self.repositories = self.root / "repositories"
        self.repositories.write_text("/repositories/main\n/repositories/community\n")
        self.resolver = self.root / "resolv.conf"
        self.resolver.write_text("# original resolver\n")
        self.env = {
            **os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "NETWORK_LOG": str(self.root / "network.log"),
            "OSTADIX_PKG_NET_RUN": str(self.root / "run"),
            "OSTADIX_PKG_REPOSITORIES": str(self.repositories),
            "OSTADIX_PKG_RESOLV_CONF": str(self.resolver),
            "OSTADIX_PKG_DHCP_SCRIPT": str(self.bin / "pkg-net-udhcpc"),
        }

    def tool(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\nset -eu\n" + body)
        path.chmod(0o755)

    def invoke(self, *args):
        return subprocess.run([str(self.bin / "pkg-net"), *args], env=self.env, capture_output=True, text=True)

    def test_online_configures_linux_dhcp_before_https_repositories(self):
        result = self.invoke("online")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OKERNEL PACKAGE NETWORK ONLINE", result.stdout)
        commands = (self.root / "network.log").read_text()
        self.assertIn("link set dev eth0 up", commands)
        self.assertIn("address add 10.0.2.15/24 dev eth0", commands)
        self.assertIn("route replace default via 10.0.2.2 dev eth0", commands)
        self.assertEqual(self.resolver.read_text(), "nameserver 10.0.2.3\n")
        self.assertIn("https://dl-cdn.alpinelinux.org/alpine/v3.24/main", self.repositories.read_text())
        self.assertTrue((self.root / "run/eth0.lease").is_file())

    def test_dhcp_failure_keeps_prior_repository_configuration(self):
        before = self.repositories.read_bytes()
        self.env["DHCP_FAIL"] = "1"
        result = self.invoke("online")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.repositories.read_bytes(), before)
        self.assertFalse((self.root / "run/eth0.lease").exists())
        self.assertNotIn("NETWORK ONLINE", result.stdout)

    def test_successful_client_without_configuration_hook_is_not_online(self):
        before = self.repositories.read_bytes()
        self.env["DHCP_NO_HOOK"] = "1"
        result = self.invoke("online")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configuration did not complete", result.stderr)
        self.assertEqual(self.repositories.read_bytes(), before)

    def test_offline_restores_local_repositories(self):
        self.assertEqual(self.invoke("online").returncode, 0)
        result = self.invoke("offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.repositories.read_text(), "/repositories/main\n/repositories/community\n")


@unittest.skipUnless(all(shutil.which(name) for name in ("mke2fs", "debugfs", "e2fsck")), "e2fsprogs required")
class GuestToolsUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        (self.state / "rootfs").mkdir(parents=True)
        content = self.root / "filesystem"
        for directory in ("work", "etc/apk", "lib/apk/db", "usr/local/bin", "sbin"):
            (content / directory).mkdir(parents=True, exist_ok=True)
        (content / "work/hello").write_text("keep user executable\n")
        (content / "etc/apk/repositories").write_text("keep configured repositories\n")
        (content / "lib/apk/db/installed").write_text("keep installed package database\n")
        (content / "usr/local/bin/pkg").write_text("#!/bin/sh\necho previous helper\n")
        image = self.state / "rootfs/package-domain.ext4"
        with image.open("wb") as stream:
            stream.truncate(536870912)
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", "-b", "4096", "-d", str(content), str(image)], check=True)
        self.previous = updater.domain.identity(image)
        (self.state / "rootfs/package-domain.json").write_text(json.dumps({
            "schema": "ostadix.linux-package-domain/v1", "architecture": "aarch64",
            "artifacts": {"package-domain.ext4": self.previous},
        }))

    def test_update_replaces_only_declared_helpers_with_exact_ownership_and_bytes(self):
        result = updater.update(self.state)
        self.assertTrue(result["ok"])
        self.assertTrue(result["workspace_and_apk_state_preserved"])
        self.assertEqual({tool["guest_path"] for tool in result["tools"]}, set(updater.TOOLS))
        head = json.loads((self.state / "head.json").read_text())
        self.assertIn("guest_tools_update", head)
        self.assertNotIn("repository_staging", head)
        image = Path(head["disk"]["path"])
        for index, (guest, source) in enumerate(updater.TOOLS.items()):
            copied = updater.stager.dump_file(image, guest, self.root / "readback" / str(index))
            self.assertEqual(copied.read_bytes(), source.read_bytes())
        copied = updater.stager.dump_file(image, "/work/hello", self.root / "hello")
        self.assertEqual(copied.read_text(), "keep user executable\n")
        self.assertEqual(updater.domain.digest(Path(self.previous["path"])), self.previous["sha256"])

    def test_bad_local_tool_leaves_selected_disk_unchanged(self):
        tools = dict(updater.TOOLS)
        tools["/usr/local/bin/pkg"] = self.root / "missing-source-helper"
        with patch.object(updater, "TOOLS", tools):
            with self.assertRaisesRegex(ValueError, "regular source"):
                updater.update(self.state)
        self.assertFalse((self.state / "head.json").exists())
        self.assertEqual(updater.domain.digest(Path(self.previous["path"])), self.previous["sha256"])

    def test_unverified_gnu_dependency_bundle_cannot_modify_the_guest(self):
        abi = self.root / "unverified-abi"
        abi.mkdir()
        (abi / "glibc-abi.json").write_text('{"schema":"untrusted"}\n')
        with self.assertRaisesRegex(ValueError, "unsupported original glibc ABI"):
            updater.update(self.state, abi)
        self.assertFalse((self.state / "head.json").exists())
        self.assertEqual(updater.domain.digest(Path(self.previous["path"])), self.previous["sha256"])


if __name__ == "__main__":
    unittest.main()
