"""In-process history failures remain client errors, never program status.

Execute checked copies of the actual history helper. A fixture subclass changes
only its fixed archive/mapping constructor defaults to private temporary paths;
all archive validation and cleanup methods execute unchanged. No guest or
native domain is launched. Existing in-process integration tests own the
checked-byte/PID/stdin contract; these cover the exception boundary.
"""
from __future__ import annotations

import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from tests import test_p9_history as history_fixture
from tests.test_plan9_installed_resolution import CLIENT


class HistoryErrorBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = history_fixture.P9HistoryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.helper = self.fixture.base / "checked-p9-history"
        source = history_fixture.SCRIPT.read_bytes()
        # Only path configuration differs from the deployed helper. Its
        # History.collect/delete_archived implementations are inherited.
        configuration = (
            "\nclass History(History):\n"
            " def __init__(self, control, protocol):\n"
            "  super().__init__(control, protocol, archive=Path(" + repr(str(self.fixture.archive))
            + "), mapping=" + repr(self.fixture.mapping) + ")\n")
        self.helper.write_bytes(source + configuration.encode())
        self.helper.chmod(0o600)

    def assert_client_failure_without_dispatch(self, manifest):
        archive = self.fixture.archive
        archive.mkdir(mode=0o700)
        wire = history_fixture.history.encoded(manifest)
        published = archive / history_fixture.history.digest(wire)
        published.mkdir(mode=0o700)
        self.fixture.put(published / "manifest.json", wire)
        native_before = self.fixture.files(self.fixture.root)
        stderr = io.StringIO()
        stdin = io.StringIO("job input must remain untouched")
        preserve = CLIENT.preserve_history

        def checked_helper(control, protocol):
            return preserve(control, protocol, self.helper)

        arguments = ["p9", "--control-dir", str(self.fixture.control),
                     "--protocol", str(self.fixture.base / "protocol.py"),
                     "--cwd", str(self.fixture.base / "native"), "echo", "must-not-submit"]
        with patch.object(CLIENT, "preserve_history", side_effect=checked_helper), \
                patch.object(CLIENT, "Client") as dispatch, \
                patch.object(sys, "argv", arguments), \
                patch.object(sys, "stdin", stdin), patch.object(sys, "stderr", stderr):
            self.assertEqual(CLIENT.main(), 125)
        dispatch.assert_not_called()
        self.assertIn("history", stderr.getvalue().lower())
        self.assertEqual(stdin.tell(), 0)
        self.assertEqual(self.fixture.files(self.fixture.root), native_before)
        self.assertEqual((published / "manifest.json").read_bytes(), wire)
        self.assertFalse((self.fixture.control / "pending.json").exists())
        self.assertFalse(list(self.fixture.root.glob("g*/s*/r*/submit")))

    def test_missing_archive_field_keyerror_is_client125_without_dispatch(self):
        self.assert_client_failure_without_dispatch({"schema": history_fixture.history.SCHEMA})

    def test_wrong_archive_field_type_is_client125_without_dispatch(self):
        self.assert_client_failure_without_dispatch({"schema": history_fixture.history.SCHEMA,
                                                   "source_relative": None, "kind": "completed-job"})

    def test_valid_checked_history_still_archives_exact_old_job_and_retains_newest(self):
        first, first_files = self.fixture.job(1)
        second, second_files = self.fixture.job(2)
        with patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected second interpreter")):
            CLIENT.preserve_history(self.fixture.control, self.fixture.protocol, self.helper)
        self.assertFalse(first.exists())
        self.assertEqual(self.fixture.files(second), second_files)
        published = self.fixture.published()
        self.assertEqual(len(published), 1)
        self.assertEqual(self.fixture.files(published[0] / "native"), first_files)
        self.assertFalse((self.fixture.control / "pending.json").exists())


if __name__ == "__main__":
    unittest.main()
