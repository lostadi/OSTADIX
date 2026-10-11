"""Source-only ownership regressions over synthetic hashed capture journals.

No compiler, linker, archiver, runtime, or O-core lowering runs. Native payloads
are inert byte fixtures; these tests qualify reconstruction and rejection only.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get("OCORE_TEST_CAPTURE_WORKER", ROOT / "scripts/ocore_runtime_capture.py"))
SPEC = importlib.util.spec_from_file_location("capture_ownership_under_test", SCRIPT)
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


def elf_bytes(tag, kind=1):
    return b"\x7fELF\x02\x01\x01" + bytes(9) + kind.to_bytes(2, "little") + tag


def archive_bytes(members):
    result = bytearray(b"!<arch>\n")
    for name, data in members:
        # BSD extended names retain arbitrary names and duplicate occurrences.
        encoded = name.encode()
        payload = encoded + data
        header = f"{'#1/' + str(len(encoded)):<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(payload):<10}`\n".encode()
        result.extend(header + payload + (b"\n" if len(payload) % 2 else b""))
    return bytes(result)


class CaptureOwnershipTests(unittest.TestCase):
    def setUp(self):
        retained = os.environ.get("OCORE_TEST_CAPTURE_OWNERSHIP_OUTPUT_DIR")
        if retained:
            base = Path(retained).expanduser().resolve()
            base.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=base))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="capture-ownership-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.records = []
        self.worker = capture.file_info(SCRIPT)
        self.tool = self.write("identity-only.tool", b"synthetic tool identity, never executed\n")
        self.tool_info = {**self.tool, "invoked_path": self.tool["path"], "version": "synthetic LLVM frontend identity"}
        patch = mock.patch.object(capture.subprocess, "run", side_effect=AssertionError("source-only ownership tests must not execute tools"))
        patch.start()
        self.addCleanup(patch.stop)

    def tearDown(self):
        worker_copy = self.directory / "worker-source.py"
        worker_copy.write_bytes(SCRIPT.read_bytes())
        test_copy = self.directory / "test-source.py"
        test_copy.write_bytes(Path(__file__).read_bytes())
        report = {"scope": "source-only synthetic native-member ownership reconstruction", "test_id": self.id(),
                  "worker": capture.file_info(worker_copy), "test": capture.file_info(test_copy),
                  "records": self.records, "native_execution_qualified": False, "ocore_lowering_complete": False,
                  "runtime_complete": False, "dependency_closure_complete": False}
        (self.directory / "ownership-conformance.json").write_text(json.dumps(report, indent=2) + "\n")
        self.assertEqual(capture.file_info(SCRIPT), self.worker)

    def write(self, name, data):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return capture.file_info(path)

    def compiler(self, ident, payload=None, name=None, start=1, end=2, assembly=False):
        source = self.write(ident + (".S" if assembly else ".c"), b"synthetic original source\n")
        output = self.write(name or ident + ".o", payload if payload is not None else elf_bytes(ident.encode()))
        args = ["-c", source["path"], "-o", output["path"]]
        event = {"id": ident, "kind": "clang", "state": "finished", "exit_code": 0,
                 "started_ns": start, "finished_ns": end, "capture_worker": self.worker,
                 "frontend": self.tool_info, "compiler": self.tool["path"], "cwd": str(self.directory),
                 "argv": args, "expanded_argv": args, "response_files": [], "sources": [source],
                 "outputs": [output], "units": [], "link_inputs": {"files": [], "ordered": []}}
        if not assembly:
            ir = self.write(ident + ".ll", b'target triple = "x86_64-unknown-linux-gnu"\ntarget datalayout = "e-p:64:64"\ndefine void @f() { ret void }\n')
            ir = {**ir, "format": "llvm-text", "target_triple": "x86_64-unknown-linux-gnu", "data_layout": "e-p:64:64"}
            replay = [self.tool["path"], "-S", "-emit-llvm", "-MD", "-MF", str(Path(ir["path"]).with_suffix(".d")), "-o", ir["path"], source["path"]]
            event["units"] = [{"id": ident + ":0", "kind": "clang", "source": source, "ir": ir,
                               "replay_exit_code": 0, "replay_argv": replay,
                               "frontend_version": self.tool_info["version"], "dependencies": [source]}]
        return event

    def provider(self, artifact):
        return {"spelling": artifact["path"], "original": artifact, "snapshot": artifact}

    def native_event(self, ident, output, providers, kind="archive", start=100, end=110):
        return {"id": ident, "kind": kind, "state": "finished", "exit_code": 0,
                "started_ns": start, "finished_ns": end, "tool": self.tool_info,
                "capture_worker": self.worker, "sources": [], "units": [], "outputs": [output],
                "link_inputs": {"files": providers, "ordered": []},
                "native_linkage": {"complete": True, "ordered_argv": ["synthetic-observed-command"],
                                   "providers": [self.provider(x) for x in providers], "archive_members": []}}

    def evaluate(self, events, root):
        membership = {"roots": [root], "contributing_invocation_ids": [event["id"] for event in events]}
        result = capture.linkage_evidence(events, membership)
        self.records.append({"events": copy.deepcopy(events), "membership": membership, "result": result})
        self.assertFalse(result["dependency_closure_complete"])
        return result

    def ordinary_archive(self, compiler, members=None):
        output = compiler["outputs"][0]
        data = Path(output["path"]).read_bytes()
        archive = self.write("libfixture.a", archive_bytes(members or [(Path(output["path"]).name, data)]))
        event = self.native_event("archive", archive, [output])
        return archive, event

    def test_compiler_owned_rlib_does_not_bless_prebuilt_members_for_root_or_link_provider(self):
        archive = self.write("libcrate.rlib", archive_bytes([("prebuilt.o", elf_bytes(b"prebuilt without captured source"))]))
        crate = self.compiler("crate")
        crate.update(kind="rustc", outputs=[archive])
        crate["units"][0]["kind"] = "rustc"
        # A real compiler CGU record exists, but has no member hash relation.
        for as_provider in (False, True):
            if as_provider:
                executable = self.write("executable", elf_bytes(b"linked", 2))
                native = self.native_event("linker", executable, [archive], "linker", 200, 210)
                root = executable
            else:
                native = self.native_event("ranlib", archive, [archive], "archive-index")
                root = archive
            result = self.evaluate([crate, native], root)
            self.assertFalse(result["source_provider_ownership_complete"])
            self.assertTrue(any(item.get("archive_member", {}).get("member") == "prebuilt.o" for item in result["unowned_native_providers"]))

    def test_source_less_partial_link_output_is_not_a_source_producer(self):
        object_ = self.write("partial.o", elf_bytes(b"prebuilt partial link"))
        no_source = {"id": "source-less-driver", "kind": "clang", "outputs": [object_], "units": [], "sources": [],
                     "state": "finished", "exit_code": 0, "argv": ["-r", "prebuilt.o", "-o", object_["path"]]}
        executable = self.write("executable", elf_bytes(b"linked", 2))
        linker = self.native_event("linker", executable, [object_], "linker")
        self.assertFalse(self.evaluate([no_source, linker], executable)["source_provider_ownership_complete"])

    def test_exact_source_object_and_corresponding_replay_own_every_root_member(self):
        compiler = self.compiler("source")
        archive, archiver = self.ordinary_archive(compiler)
        result = self.evaluate([compiler, archiver], archive)
        self.assertTrue(result["source_provider_ownership_complete"], result)
        self.assertTrue(result["native_source_ownership_complete"])
        self.assertEqual(result["archive_member_ownership"][0]["observed_input_edges"][0]["candidate_outputs"][0]["llvm_replay_unit_ids"], ["source:0"])

    def test_renamed_member_keeps_content_producer_through_actual_input_edge(self):
        compiler = self.compiler("source", name="original-name.o")
        archive, archiver = self.ordinary_archive(compiler, [("renamed-inside-archive.o", Path(compiler["outputs"][0]["path"]).read_bytes())])
        result = self.evaluate([compiler, archiver], archive)
        self.assertTrue(result["source_provider_ownership_complete"])
        self.assertEqual(result["archive_member_ownership"][0]["archive_member"]["member"], "renamed-inside-archive.o")
        membership = capture.runtime_output_membership({"coverage": {"required_outputs": ["libfixture.a"]}}, None,
                                                     [compiler, archiver], self.directory)
        self.assertEqual(membership["contributing_invocation_ids"], ["archive", "source"])
        self.assertTrue(capture.linkage_evidence([compiler, archiver], membership)["source_provider_ownership_complete"])
        self.records.append({"membership": membership})

    def test_duplicate_names_payloads_and_all_source_candidates_keep_order(self):
        first = self.compiler("first", payload=elf_bytes(b"same"))
        duplicate = self.compiler("other-stage", payload=elf_bytes(b"same"))
        second = self.compiler("second", payload=elf_bytes(b"different"))
        members = [("same.o", Path(first["outputs"][0]["path"]).read_bytes()), ("same.o", Path(second["outputs"][0]["path"]).read_bytes()), ("same.o", Path(first["outputs"][0]["path"]).read_bytes())]
        archive = self.write("duplicates.a", archive_bytes(members))
        archiver = self.native_event("archive", archive, [first["outputs"][0], second["outputs"][0]])
        result = self.evaluate([first, duplicate, second, archiver], archive)
        self.assertTrue(result["source_provider_ownership_complete"])
        proofs = result["archive_member_ownership"]
        self.assertEqual([p["archive_member"]["index"] for p in proofs], [0, 1, 2])
        self.assertEqual([p["archive_member"]["member"] for p in proofs], ["same.o"] * 3)
        self.assertEqual({p["invocation_id"] for p in proofs[0]["candidate_outputs"]}, {"first", "other-stage"})
        matches = proofs[0]["observed_input_edges"][0]["candidate_outputs"]
        self.assertEqual({p["invocation_id"] for p in matches if p["observed_input_match"]}, {"first"})

    def test_missing_hash_size_or_source_contract_never_matches_member(self):
        for mutation in ("size", "source", "command", "worker", "frontend", "failure", "unfinished", "response"):
            with self.subTest(mutation=mutation):
                compiler = self.compiler(mutation)
                archive, archiver = self.ordinary_archive(compiler)
                if mutation == "size": compiler["outputs"][0] = {**compiler["outputs"][0], "bytes": compiler["outputs"][0]["bytes"] + 1}
                elif mutation == "source": compiler["sources"] = []
                elif mutation == "command": compiler["argv"] = ["-r", "old.o", "-o", compiler["outputs"][0]["path"]]
                elif mutation == "worker": compiler["capture_worker"] = {**compiler["capture_worker"], "sha256": "0" * 64}
                elif mutation == "frontend": compiler["frontend"] = {**compiler["frontend"], "sha256": "0" * 64}
                elif mutation == "failure": compiler["exit_code"] = 1
                elif mutation == "unfinished": compiler["state"] = "running"
                else:
                    response = self.write("changed.rsp", b"-c unrelated.c -o unrelated.o\n")
                    compiler["argv"] = ["@" + response["path"]]
                    compiler["response_files"] = [response]
                result = self.evaluate([compiler, archiver], archive)
                self.assertFalse(result["source_provider_ownership_complete"])

    def test_source_matched_replay_identity_and_success_are_mandatory(self):
        for mutation in ("source", "IR", "failure", "duplicate", "replay-command", "dependency"):
            with self.subTest(mutation=mutation):
                compiler = self.compiler(mutation)
                archive, archiver = self.ordinary_archive(compiler)
                unit = compiler["units"][0]
                if mutation == "source": unit["source"] = self.write("unrelated.c", b"unrelated source")
                elif mutation == "IR": unit["ir"] = {**unit["ir"], "sha256": "0" * 64}
                elif mutation == "failure": unit["replay_exit_code"] = 1
                elif mutation == "duplicate": compiler["units"].append({**unit, "id": "different-unit"})
                elif mutation == "replay-command": unit["replay_argv"] = [self.tool["path"], "unrelated.c"]
                else: unit["dependencies"] = []
                result = self.evaluate([compiler, archiver], archive)
                self.assertTrue(result["native_source_ownership_complete"])
                self.assertTrue(result["source_provider_ownership_complete"])
                self.assertFalse(result["llvm_replay_ownership_complete"])
                self.assertFalse(result["unowned_native_providers"])
                self.assertTrue(result["unmatched_llvm_replays"])

    def test_future_same_hash_producer_cannot_own_earlier_archive_input(self):
        compiler = self.compiler("future", start=300, end=310)
        archive, archiver = self.ordinary_archive(compiler)
        result = self.evaluate([compiler, archiver], archive)
        self.assertFalse(result["source_provider_ownership_complete"])
        self.assertTrue(result["archive_member_ownership"][0]["candidate_outputs"])

    def test_cold_retained_member_requires_its_own_observed_archive_edge(self):
        old, new = self.compiler("cold"), self.compiler("new")
        archive = self.write("updated.a", archive_bytes([("cold.o", Path(old["outputs"][0]["path"]).read_bytes()), ("new.o", Path(new["outputs"][0]["path"]).read_bytes())]))
        # An update observing only the new input cannot invent the old edge.
        archiver = self.native_event("archive-update", archive, [new["outputs"][0]])
        result = self.evaluate([old, new, archiver], archive)
        self.assertFalse(result["source_provider_ownership_complete"])
        self.assertEqual([p["archive_member"]["member"] for p in result["archive_member_ownership"] if not p["complete"]], ["cold.o"])

    def test_ranlib_propagates_prior_archive_edges_without_creating_source_owners(self):
        compiler = self.compiler("source")
        prior, archiver = self.ordinary_archive(compiler)
        indexed = self.write("indexed.a", Path(prior["path"]).read_bytes())
        ranlib = self.native_event("ranlib", indexed, [prior], "archive-index", 150, 160)
        result = self.evaluate([compiler, archiver, ranlib], indexed)
        self.assertTrue(result["source_provider_ownership_complete"])
        self.assertTrue(any("prior_archive_member" in edge for proof in result["archive_member_ownership"]
                            for edge in proof["observed_input_edges"]))
        self.assertFalse(self.evaluate([ranlib], indexed)["source_provider_ownership_complete"])

    def test_archive_update_records_retained_input_before_mutation(self):
        old, new = self.compiler("old"), self.compiler("new")
        prior, previous = self.ordinary_archive(old)
        new_output = new["outputs"][0]
        members = [("old.o", Path(old["outputs"][0]["path"]).read_bytes()),
                   ("new.o", Path(new_output["path"]).read_bytes())]
        (self.directory / "units").mkdir()
        frozen = capture.snapshot_worker(self.directory)
        capture.write_json(self.directory / "session.json", {
            "capture_worker": frozen, "native_tools": {"ar": self.tool_info},
            "tools": {"nm": self.tool_info}})

        def simulate_archive_command(argv):
            self.assertEqual(argv, [self.tool["path"], "rcs", prior["path"], new_output["path"]])
            Path(prior["path"]).write_bytes(archive_bytes(members))
            return type("SyntheticResult", (), {"returncode": 0})()

        # Only this Python byte-fixture transition substitutes for the tool; no
        # subprocess/compiler/archiver is executed by the recorder regression.
        with mock.patch.object(capture.Path, "cwd", return_value=self.directory), \
             mock.patch.object(capture.subprocess, "run", side_effect=simulate_archive_command), \
             mock.patch.object(capture, "inspect_symbols", return_value={}):
            self.assertEqual(capture.native_tool(self.directory, "ar", ["rcs", prior["path"], new_output["path"]]), 0)
        events = [json.loads(path.read_text()) for path in (self.directory / "events").glob("*.json")]
        self.assertEqual(len(events), 1)
        update = events[0]
        providers = update["native_linkage"]["providers"]
        self.assertEqual(providers[0]["role"], "archive-before-update")
        self.assertEqual(providers[0]["original"], prior)
        self.assertEqual(capture.file_info(Path(providers[0]["snapshot"]["path"]))["sha256"], prior["sha256"])
        self.assertEqual(providers[1]["original"], new_output)
        current = capture.file_info(Path(prior["path"]))
        result = self.evaluate([old, new, previous, update], current)
        self.assertTrue(result["source_provider_ownership_complete"], result)
        final_members = [p["archive_member"]["member"] for p in result["archive_member_ownership"]
                         if p["archive"]["sha256"] == current["sha256"]]
        self.assertEqual(final_members, ["old.o", "new.o"])
        self.assertTrue(any(p["archive"]["sha256"] == prior["sha256"] for p in result["archive_member_ownership"]))

    def test_identity_cache_rechecks_changed_frontend_and_final_traversal(self):
        compiler = self.compiler("source")
        cache = {}
        self.assertTrue(capture.native_source_output(compiler, compiler["outputs"][0], cache)["native_source_owned"])
        Path(self.tool["path"]).write_bytes(b"changed frontend identity\n")
        self.assertFalse(capture.native_source_output(compiler, compiler["outputs"][0], cache)["native_source_owned"])
        Path(self.tool["path"]).write_bytes(b"synthetic tool identity, never executed\n")
        archive, archiver = self.ordinary_archive(compiler)
        original = capture.native_source_output

        def mutate_after_observation(owner, output, identities=None):
            proof = original(owner, output, identities)
            if proof["native_source_owned"]:
                Path(self.tool["path"]).write_bytes(b"changed after identity observation\n")
            return proof

        with mock.patch.object(capture, "native_source_output", side_effect=mutate_after_observation):
            result = self.evaluate([compiler, archiver], archive)
        self.assertFalse(result["source_provider_ownership_complete"])
        self.assertTrue(any("changed during reconstruction" in issue for issue in result["issues"]))

    def test_assembly_source_origin_does_not_claim_a_corresponding_llvm_replay(self):
        compiler = self.compiler("assembly", assembly=True)
        archive, archiver = self.ordinary_archive(compiler)
        result = self.evaluate([compiler, archiver], archive)
        self.assertTrue(result["native_source_ownership_complete"])
        self.assertTrue(result["source_provider_ownership_complete"])
        self.assertFalse(result["llvm_replay_ownership_complete"])
        self.assertFalse(result["unowned_native_providers"])

    def test_elf_metadata_and_bundled_archive_wrappers_have_no_blanket_exemption(self):
        nested = archive_bytes([("prebuilt.o", elf_bytes(b"prebuilt"))])
        payloads = [("lib.rmeta", elf_bytes(b"metadata")), ("lib.rmeta-link", elf_bytes(b"metadata linkage")), ("foreign.bundled_lib", elf_bytes(b".bundled_lib" + nested)), ("code.bc", b"BC\xc0\xdecode-bearing"), ("unknown.bin", b"unknown")]
        archive = self.write("libcrate.rlib", archive_bytes(payloads))
        crate = self.compiler("crate")
        crate.update(kind="rustc", outputs=[archive])
        archiver = self.native_event("archive", archive, [])
        result = self.evaluate([crate, archiver], archive)
        self.assertFalse(result["source_provider_ownership_complete"])
        self.assertEqual([p["archive_member"]["member"] for p in result["archive_member_ownership"]], [p[0] for p in payloads])
        self.assertTrue(all(not p["complete"] for p in result["archive_member_ownership"]))

    def test_membership_retains_archive_hash_size_and_every_member_ordinal(self):
        compiler = self.compiler("source")
        archive, archiver = self.ordinary_archive(compiler, [("same.o", b"one"), ("same.o", b"two"), ("same.o", b"one")])
        membership = capture.runtime_output_membership({"coverage": {"required_outputs": ["libfixture.a"]}}, None, [compiler, archiver], self.directory)
        self.assertTrue(membership["complete"])
        self.assertEqual([m["index"] for m in membership["archive_members"]], [0, 1, 2])
        self.assertTrue(all(m["archive_sha256"] == archive["sha256"] and m["archive_bytes"] == archive["bytes"] for m in membership["archive_members"]))
        self.records.append({"membership": membership})

    def test_archive_symbol_table_like_prefix_does_not_hide_native_members(self):
        archive = self.write("symbols.a", archive_bytes([("__.SYMDEF", bytes(8)),
                             ("__.SYMDEF.prebuilt.o", elf_bytes(b"native")),
                             ("__.SYMDEF", elf_bytes(b"native payload under reserved-looking name")),
                             ("__.SYMDEF_64", bytes(16)), ("__.SYMDEF", b"unknown payload")]))
        self.assertEqual([m["member"] for m in capture.native_archive_members(Path(archive["path"]))],
                         ["__.SYMDEF.prebuilt.o", "__.SYMDEF", "__.SYMDEF"])


if __name__ == "__main__":
    unittest.main()
