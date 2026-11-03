"""Version-aware setup checks without installing packages or changing PATH globally."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SetupPythonRuntimeTests(unittest.TestCase):
    def check_version(self, version):
        source = (ROOT / 'setup.sh').read_text()
        body = source.split('\ncheck_python_runtime() {\n', 1)[1].split('\n}\n', 1)[0]
        with tempfile.TemporaryDirectory(prefix='python setup check ') as directory:
            root = Path(directory)
            if version is not None:
                executable = root / 'python3'
                executable.write_text(
                    '#!' + sys.executable + '\n'
                    'import sys\n'
                    'sys.version_info = ' + repr(version) + '\n'
                    'exec(sys.argv[2])\n'
                )
                executable.chmod(0o755)
            env = os.environ.copy()
            env['PATH'] = str(root)
            result = subprocess.run(
                ['/bin/bash', '-c', 'set -euo pipefail\nCHECK_FAILURES=0\n'
                 + 'check_python_runtime() {\n' + body + '\n}\n'
                 + 'check_python_runtime\nexit "$CHECK_FAILURES"\n'],
                env=env, text=True, capture_output=True, timeout=10,
            )
            return result

    def test_supported_versions_and_paths_with_spaces(self):
        for version in ((3, 10, 0), (3, 11, 9), (3, 12, 3)):
            with self.subTest(version=version):
                result = self.check_version(version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('[ok]', result.stdout)
                self.assertIn('.'.join(map(str, version)), result.stdout)

    def test_older_python_is_not_reported_as_ready(self):
        for version in ((3, 8, 10), (3, 9, 21)):
            with self.subTest(version=version):
                result = self.check_version(version)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertNotIn('[ok]', result.stdout)
                self.assertIn('Install Python 3.10 or newer', result.stderr)

    def test_missing_python_is_reported_without_crashing_shell(self):
        result = self.check_version(None)
        self.assertEqual(result.returncode, 1)
        self.assertIn('unavailable or unusable', result.stderr)
        self.assertIn('python3 on PATH', result.stderr)


if __name__ == '__main__':
    unittest.main()
