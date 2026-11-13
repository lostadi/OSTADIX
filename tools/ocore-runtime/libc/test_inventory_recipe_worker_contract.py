"""Keep reviewed worker compatibility bound to every original musl recipe."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


DIRECTORY = Path(__file__).resolve().parent
ROOT = DIRECTORY.parents[2]
SPEC = importlib.util.spec_from_file_location("musl_recipe_worker_contract", DIRECTORY / "build_inventory.py")
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)

CURRENT_WORKER = "303aac632cac6caff5179372811d98081e57eb98bfae34b43db9e1ecf90033b0"
HISTORICAL_WORKERS = {
    "a18a349afb994a8a3035209bc43f480cfeb399be4198022b29ef4d776cfc7779",
    "0f3cee8f19faa091281bc11033d20b18a6aad10915b07713cedc8a93a89de059",
    "758bec4a31a3384113d31f4517d2a9ef16ddbf6a1824dc071aace756433c7c36",
}
PREVIOUS_HELPER = "cab10c3cd3032ee79ccd5a3b35dd6e413887760d7bbc72693e084b6d56cc962d"


class RecipeWorkerContractTests(unittest.TestCase):
    def test_current_and_historical_worker_set_stays_explicit(self):
        self.assertEqual(inventory.WORKER_SHAS, HISTORICAL_WORKERS | {CURRENT_WORKER})
        self.assertEqual(hashlib.sha256((ROOT / "scripts/ocore_runtime_capture.py").read_bytes()).hexdigest(), CURRENT_WORKER)

    def test_every_recipe_inventory_invocation_binds_the_same_helper(self):
        digest = hashlib.sha256((DIRECTORY / "build_inventory.py").read_bytes()).hexdigest()
        for isa in inventory.PROFILES:
            with self.subTest(isa=isa):
                recipe = json.loads((DIRECTORY / f"{isa}.static.recipe.json").read_text())
                self.assertEqual(recipe["source_inventory_helper"], {"path": "build_inventory.py", "sha256": digest})
                actions = []
                for step in recipe["commands"]:
                    argv = step["argv"]
                    if "{recipe_dir}/build_inventory.py" not in argv:
                        continue
                    self.assertEqual(argv[:2], ["python3", "{recipe_dir}/build_inventory.py"])
                    self.assertEqual(argv.count("--expected-helper-sha256"), 1)
                    self.assertEqual(argv[argv.index("--expected-helper-sha256") + 1], digest)
                    self.assertEqual(argv[argv.index("--isa") + 1], isa)
                    actions.append(argv[2])
                self.assertEqual(actions, ["configure", "plan", "inventory", "inventory", "inventory"])

    def test_stale_helper_binding_stops_before_source_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, build, capture = (root / name for name in ("source", "build", "capture"))
            for directory in (source, build, capture):
                directory.mkdir()
            for stale in (PREVIOUS_HELPER, "0" * 64):
                with self.subTest(expected=stale):
                    result = subprocess.run(
                        [sys.executable, str(DIRECTORY / "build_inventory.py"), "configure",
                         "--source", str(source), "--build", str(build), "--capture", str(capture),
                         "--isa", "x86_64", "--expected-helper-sha256", stale],
                        capture_output=True, text=True, timeout=10,
                        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("source inventory helper differs from digest-bound recipe", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(list(build.iterdir()), [])
                    self.assertEqual(list(capture.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
