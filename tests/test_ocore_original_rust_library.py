"""Fail-closed eligibility for the bounded original-library recipe."""
import importlib.util
import copy
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("configured_rust_library", ROOT / "tools/ocore-runtime/rust-crates/configured_library.py")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class ConfiguredOriginalRustLibraryTests(unittest.TestCase):
    def fixture(self, manifest):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        source = Path(directory.name)
        (source / "Cargo.toml").write_text('[package]\nname="original-library"\nversion="1.0.0"\nedition="2021"\n' + manifest)
        (source / "src").mkdir()
        (source / "src/lib.rs").write_text('pub fn original(x:u64)->u64{x.wrapping_add(1)}\n')
        return source

    def test_default_feature_graph_is_complete_and_order_independent(self):
        source = self.fixture('[features]\ndefault=["std","extra"]\nextra=["std"]\nstd=[]\n')
        result = helper.configuration(source)
        self.assertEqual(result["features"], ["default", "extra", "std"])
        self.assertEqual(result["root"], "src/lib.rs")
        self.assertEqual(result["crate_name"], "original_library")
        self.assertEqual(result["crate_root"], helper.artifact(source / "src/lib.rs"))

    def test_required_or_activated_providers_cannot_disappear(self):
        for manifest in ('[dependencies]\nprovider="1"\n',
                         '[dependencies]\nprovider={version="1",optional=true}\n[features]\ndefault=["dep:provider"]\n',
                         '[dependencies]\nprovider={version="1",optional=true}\n[features]\ndefault=["provider"]\n',
                         '[features]\ndefault=["absent-feature"]\n'):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                helper.configuration(self.fixture(manifest))
        source = self.fixture('[dependencies]\nprovider={version="1",optional=true}\n[features]\ndefault=["std"]\nstd=[]\n')
        self.assertEqual(helper.configuration(source)["features"], ["default", "std"])

    def test_build_workspace_proc_macro_target_and_source_escape_are_rejected(self):
        for manifest in ('[workspace]\nmembers=[]\n', '[lib]\nproc-macro=true\n',
                         '[target."cfg(unix)".dependencies]\nprovider="1"\n',
                         '[lib]\npath="../outside.rs"\n'):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                helper.configuration(self.fixture(manifest))
        source = self.fixture('')
        (source / "build.rs").write_text('fn main(){}\n')
        with self.assertRaisesRegex(ValueError, "build scripts"):
            helper.configuration(source)


class OriginalRustMemberCopyTests(unittest.TestCase):
    def fixture(self, members):
        from tests import test_ocore_runtime_capture_rust_cgu as original
        fixture = original.RustCguCaptureTests("test_original_object_edge_uses_exact_bytes_and_no_replay")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        output = fixture.write("original.rlib", original.archive(members))
        event = fixture.collect([output])
        args = [fixture.source["path"], "--crate-type", "rlib", "-o", output["path"]]
        executed, changes = fixture.worker.rust_instrumentation(args, True)
        event.update(kind="rustc", state="finished", exit_code=0, cwd=str(fixture.root),
                     argv=args, expanded_argv=args, response_files=[], rust_response_files=[], executed_argv=executed,
                     rust_capture={"policy":fixture.worker.RUST_EMBEDDED_POLICY,"applied":True,
                         "transformations":changes,"original_command_executed":executed==args,
                         "frontend_replay_used":False,"post_lto_equivalence_verified":False,"argfile_gap":None})
        fixture.worker.verify_rust_capture_event(event, fixture.session, fixture.directory)
        return fixture, event, original

    def test_exact_member_copy_retains_original_byte_edges_without_claiming_equivalence(self):
        from tests import test_ocore_runtime_capture_rust_cgu as original
        fixture, event, _ = self.fixture([("body.o", original.elf())])
        origins = fixture.worker.verified_rust_native_member_copies(event, fixture.session, fixture.directory)
        artifact = fixture.write("body.o", original.elf())
        result = fixture.worker.exact_rust_native_member_copy(artifact, fixture.worker.rust_native_member_copy_index(origins))
        self.assertIsNotNone(result)
        origin = result["captured_rust_member"]
        self.assertEqual(origin["archive"], event["saved_cgus"][0]["container"]["artifact"])
        self.assertEqual(origin["member_index"], 0)
        self.assertEqual(origin["member_name_bytes"], list(b"body.o"))
        self.assertEqual(origin["object"]["sha256"], artifact["sha256"])
        self.assertEqual(origin["bitcode"], event["saved_cgus"][0]["bitcode"])
        self.assertFalse(result["source_production_ownership_verified"])
        self.assertFalse(result["native_machine_equivalence_verified"])
        self.assertFalse(result["post_lto_equivalence_verified"])

    def test_wrong_name_modified_copy_and_ambiguous_original_members_remain_unowned(self):
        from tests import test_ocore_runtime_capture_rust_cgu as original
        fixture, event, _ = self.fixture([("body.o", original.elf()), ("body.o", original.elf())])
        origins = fixture.worker.verified_rust_native_member_copies(event, fixture.session, fixture.directory)
        artifact = fixture.write("body.o", original.elf())
        unique = fixture.worker.rust_native_member_copy_index(origins[:1])
        self.assertIsNone(fixture.worker.exact_rust_native_member_copy(fixture.write("wrong.o", original.elf()), unique))
        self.assertIsNone(fixture.worker.exact_rust_native_member_copy(fixture.write("body.o", original.elf()+b"modified"), unique))
        self.assertIsNone(fixture.worker.exact_rust_native_member_copy(artifact, fixture.worker.rust_native_member_copy_index(origins)))
        self.assertIsNone(fixture.worker.exact_rust_native_member_copy(artifact, fixture.worker.rust_native_member_copy_index(origins+origins)))

    def test_corrupt_original_archive_or_saved_bitcode_never_supplies_copy_authority(self):
        from tests import test_ocore_runtime_capture_rust_cgu as original
        fixture, event, _ = self.fixture([("body.o", original.elf())])
        bad = copy.deepcopy(event)
        bad["saved_cgus"][0]["container"]["member"]["index"] = 1
        with self.assertRaises(fixture.worker.CaptureError):
            fixture.worker.verified_rust_native_member_copies(bad, fixture.session, fixture.directory)
        Path(event["saved_cgus"][0]["bitcode"]["path"]).write_bytes(b"changed-bitcode")
        with self.assertRaises(fixture.worker.CaptureError):
            fixture.worker.verified_rust_native_member_copies(event, fixture.session, fixture.directory)


if __name__ == "__main__":
    unittest.main()
