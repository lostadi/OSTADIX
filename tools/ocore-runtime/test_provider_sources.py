import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("provider_sources", Path(__file__).with_name("provider_sources.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProviderSourceTests(unittest.TestCase):
    def fixture(self, root):
        provider = root / "libcandidate.a"
        provider.write_bytes(b"original archive provider")
        a = {k: v for k, v in module.artifact(provider).items() if k != "stable_during_read"}
        occurrences = [{"original": a, "snapshot": a, "invocation_id": "first",
                        "archive_member": {"index": 0, "member": "same.o", "sha256": "a" * 64, "bytes": 12}},
                       {"original": a, "snapshot": a, "invocation_id": "second",
                        "archive_member": {"index": 1, "member": "same.o", "sha256": "b" * 64, "bytes": 13}},
                       {"original": a, "snapshot": a, "invocation_id": "third",
                        "archive_member": {"index": 0, "member": "same.o", "sha256": "a" * 64, "bytes": 12}}]
        report = root / "capture.json"
        report.write_text(json.dumps({"schema": "ocore-runtime-capture-v1", "native_linkage": {"unowned_native_providers": occurrences}}))
        catalog = root / "packages.json"
        catalog.write_text(json.dumps({"schema": "ocore-native-provider-package-candidates-v1", "packages": [
            {"binary_package": "candidate-dev", "binary_version": "9", "source_package": "candidate",
             "source_version": "8", "providers": [{**a, "ownership": "installed-package-database-claim"}]}]}))
        archive = root / "candidate_8.orig.tar.xz"
        archive.write_bytes(b"original source archive")
        metadata = root / "Sources"
        metadata.write_text("Package: candidate\nVersion: 8\nDirectory: pool/main/c/candidate\nChecksums-Sha256:\n " + hashlib.sha256(archive.read_bytes()).hexdigest() + " " + str(archive.stat().st_size) + " " + archive.name + "\n")
        return provider, report, catalog, metadata, archive

    def test_preserves_every_occurrence_duplicate_member_name_and_cold_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, report, catalog, metadata, _ = self.fixture(root)
            result = module.inventory([report], catalog, [metadata], root)
            self.assertEqual(result["provider_occurrences"], 3)
            self.assertEqual(len(result["providers"]), 1)
            self.assertEqual([x["index"] for x in result["providers"][0]["archive_members"]], [0, 1])
            self.assertEqual([x["invocation_id"] for x in result["providers"][0]["occurrences"]], ["first", "second", "third"])
            self.assertTrue(result["source_packages"][0]["metadata_candidates"][0]["archives"][0]["available_and_sha256_verified"])
            for key in ["complete", "source_provider_ownership_complete", "dependency_closure_complete",
                        "ocore_lowering_complete", "native_execution_qualified", "runtime_complete"]:
                self.assertFalse(result[key])
            self.assertFalse(result["providers"][0]["package_candidates"][0]["source_ownership_admitted"])

    def test_exact_source_version_does_not_substitute_latest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, report, catalog, metadata, _ = self.fixture(root)
            metadata.write_text(metadata.read_text().replace("Version: 8", "Version: 9"))
            result = module.inventory([report], catalog, [metadata], root)
            self.assertIn("exact_source_version_metadata_missing", [x["kind"] for x in result["gaps"]])
            self.assertEqual(result["source_packages"][0]["version"], "8")

    def test_source_archive_tamper_is_visible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, report, catalog, metadata, archive = self.fixture(root)
            archive.write_bytes(b"changed source")
            result = module.inventory([report], catalog, [metadata], root)
            self.assertIn("source_archive_unavailable_or_mismatched", [x["kind"] for x in result["gaps"]])

    def test_package_claim_cannot_rebind_provider_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, report, catalog, metadata, _ = self.fixture(root)
            c = json.loads(catalog.read_text());c["packages"][0]["providers"][0]["sha256"] = "f" * 64
            catalog.write_text(json.dumps(c))
            result = module.inventory([report], catalog, [metadata], root)
            self.assertFalse(result["providers"][0]["package_candidates"])
            self.assertIn("package_provider_hash_mismatch", [x["kind"] for x in result["gaps"]])

    def test_original_report_and_catalog_are_not_mutated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, report, catalog, metadata, _ = self.fixture(root)
            original = [p.read_bytes() for p in [report, catalog, metadata]]
            module.inventory([report], catalog, [metadata], root)
            self.assertEqual(original, [p.read_bytes() for p in [report, catalog, metadata]])

    def test_archive_path_escape_is_rejected_without_reading_it(self):
        with self.assertRaisesRegex(ValueError, "single filename"):
            module.source_archives({"Checksums-Sha256": "f" * 64 + " 4 ../outside"})

    def test_hosted_loader_observation_stays_distinct_from_linker_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provider, report, catalog, metadata, _ = self.fixture(root)
            observation = root / "hosted-loader.json"
            original = {k: v for k, v in module.artifact(provider).items() if k != "stable_during_read"}
            observation.write_text(json.dumps({"schema": "ocore-hosted-native-provider-observation-v1",
                                               "providers": [{"original": original}]}))
            result = module.inventory([report], catalog, [metadata], root,
                                      observation_paths=[observation])
            self.assertEqual(result["provider_occurrences"], 4)
            self.assertEqual(result["providers"][0]["occurrences"][-1]["input_kind"], "hosted-loader-observation")
            self.assertFalse(result["dependency_closure_complete"])


if __name__ == "__main__":
    unittest.main()
