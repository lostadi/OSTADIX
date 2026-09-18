"""Complete output, inventory and publication regressions for HTML exports."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import render_docs

class DocumentationExportTests(unittest.TestCase):
    def test_repository_pairs_are_all_registered(self):
        self.assertTrue(render_docs.load_exports(render_docs.ROOT)["sources"])

    def test_large_render_uses_complete_output_file_and_detects_tail_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "example.md").write_text("example\n")
            expected = b"<p>" + b"x" * 150000 + b"</p>\n"
            (root / "example.html").write_bytes(expected[:65536])

            def renderer(command, **kwargs):
                self.assertEqual(command[-2], "--output")
                Path(command[-1]).write_bytes(expected + b"\n")
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(render_docs.subprocess, "run", side_effect=renderer):
                _, matched, size = render_docs.render(root, "example.md", "marked", False)
                self.assertFalse(matched)
                self.assertEqual(size, len(expected))
                render_docs.render(root, "example.md", "marked", True)
                self.assertEqual((root / "example.html").read_bytes(), expected)
                self.assertTrue(render_docs.render(root, "example.md", "marked", False)[1])

    def test_renderer_failure_does_not_replace_document(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "example.md").write_text("example")
            (root / "example.html").write_text("old complete export")
            with mock.patch.object(render_docs.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "marked")):
                with self.assertRaises(subprocess.CalledProcessError):
                    render_docs.render(root, "example.md", "marked", True)
            self.assertEqual((root / "example.html").read_text(), "old complete export")


    def export_fixture(self, root):
        (root / "docs").mkdir()
        (root / "example.md").write_text("example")
        (root / "example.html").write_text("old complete export")
        (root / "docs/html-exports.json").write_text(json.dumps({"schema": "ostadix.html-exports/v1", "renderer": "marked", "version": "18.0.13", "sources": ["example.md"]}))

    def test_new_tracked_pair_requires_inventory_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.export_fixture(root)
            with mock.patch.object(render_docs, "tracked_files", return_value={"example.md", "example.html", "new.md", "new.html"}):
                with self.assertRaisesRegex(render_docs.SourceError, "coverage mismatch.*new.md"):
                    render_docs.load_exports(root)

    def test_missing_tracked_export_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.export_fixture(root)
            with mock.patch.object(render_docs, "tracked_files", return_value={"example.md"}):
                with self.assertRaisesRegex(render_docs.SourceError, "coverage mismatch.*stale"):
                    render_docs.load_exports(root)

    def test_renderer_version_mismatch_never_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.export_fixture(root)
            with mock.patch.object(render_docs, "tracked_files", return_value={"example.md", "example.html"}), mock.patch.object(render_docs.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "0.0.0", "")), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(render_docs.main(["write", "--root", str(root)]), 1)
            self.assertEqual((root / "example.html").read_text(), "old complete export")

    def test_failed_atomic_publish_preserves_previous_document(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.export_fixture(root)
            def renderer(command, **kwargs):
                Path(command[-1]).write_bytes(b"new complete export\n")
                return subprocess.CompletedProcess(command, 0)
            with mock.patch.object(render_docs.subprocess, "run", side_effect=renderer), mock.patch.object(render_docs.os, "replace", side_effect=OSError("publication failed")):
                with self.assertRaisesRegex(OSError, "publication failed"):
                    render_docs.render(root, "example.md", "marked", True)
            self.assertEqual((root / "example.html").read_text(), "old complete export")
            self.assertEqual(list(root.glob(".example.html.*")), [])


if __name__ == "__main__":
    unittest.main()
