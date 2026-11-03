"""Exercise the real capture worker's immutable identity at inventory loading."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


DIRECTORY = Path(__file__).resolve().parent
ROOT = DIRECTORY.parents[2]
SPEC = importlib.util.spec_from_file_location("musl_inventory_worker_test", DIRECTORY / "build_inventory.py")
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class InventoryWorkerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.capture = Path(self.directory.name)
        self.worker = self.capture / "capture-worker.py"
        self.worker.write_bytes((ROOT / "scripts/ocore_runtime_capture.py").read_bytes())
        self.session = {"capture_worker": {"artifact": inventory.info(self.worker)}}
        self.write_session()

    def write_session(self):
        (self.capture / "session.json").write_text(json.dumps(self.session))

    def test_current_real_worker_loads_with_its_bound_identity(self):
        session, scope = inventory.load_worker(self.capture)
        self.assertEqual(session, self.session)
        self.assertTrue(callable(scope["native_archive_members"]))

    def test_mutated_worker_is_rejected_before_execution(self):
        marker = self.capture / "executed"
        with self.worker.open("a") as stream:
            stream.write(f"\nopen({str(marker)!r}, 'w').write('unexpected execution')\n")
        with self.assertRaisesRegex(inventory.InventoryError, "provenance differs"):
            inventory.load_worker(self.capture)
        self.assertFalse(marker.exists())

    def test_session_cannot_relabel_another_worker_identity(self):
        self.session["capture_worker"]["artifact"]["sha256"] = "0" * 64
        self.write_session()
        with self.assertRaisesRegex(inventory.InventoryError, "provenance differs"):
            inventory.load_worker(self.capture)


if __name__ == "__main__":
    unittest.main()
