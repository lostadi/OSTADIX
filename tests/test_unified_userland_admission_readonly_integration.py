"""Complete original-provider admission must not mutate even temporary paths."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
QUALIFIED = Path.home() / ".cache/okernel-plan9-userland/build-7"


@unittest.skipUnless((QUALIFIED / "FROZEN.json").is_file(), "qualified original9front cache unavailable")
class ReadOnlyAdmissionIntegrationTests(unittest.TestCase):
    def test_real_complete_admission_with_all_writes_and_process_launches_denied(self):
        program = r'''
import importlib.util
import json
import os
from pathlib import Path
import sys

root, qualified = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("readonly_complete_admission", root / "scripts/build_okernel_unified_world.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
denied = []
write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
mutations = {"os.mkdir", "os.remove", "os.rename", "os.rmdir", "os.link", "os.symlink",
             "os.chmod", "os.chown", "os.utime", "os.truncate", "subprocess.Popen",
             "os.exec", "os.posix_spawn", "tempfile.mkstemp", "tempfile.mkdtemp"}
def audit(event, args):
    writing = event == "open" and ((isinstance(args[1], str) and any(c in args[1] for c in "wax+"))
                                  or isinstance(args[2], int) and args[2] & write_flags)
    if event in mutations or writing:
        denied.append(event)
        raise AssertionError("admission attempted mutation or process launch: " + event)
sys.addaudithook(audit)
admitted = builder.admit_userland_derivation(qualified / "result.json", builder.identity(qualified / "artifacts/KERNEL.U"))
assert not denied, denied
assert "build_okernel_plan9_userland" not in sys.modules
assert "unified_userland_validator" not in sys.modules
provider = admitted["provider_admission"]
assert provider["files"] == 239 and provider["bytes"] == 13163590
assert admitted["admission_copies"]["admission-verifier.py"] == provider["export_verifier"]
assert provider["export_verifier"] == builder.identity(root / "scripts/plan9_userland_admission.py")
print(json.dumps({"files": provider["files"], "bytes": provider["bytes"],
                  "mutation_attempts": denied, "helper_captured": True}))
'''
        completed = subprocess.run([sys.executable, "-B", "-c", program, str(ROOT), str(QUALIFIED)],
                                   capture_output=True, text=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(json.loads(completed.stdout), {
            "files": 239, "bytes": 13163590, "mutation_attempts": [], "helper_captured": True})


if __name__ == "__main__":
    unittest.main()
