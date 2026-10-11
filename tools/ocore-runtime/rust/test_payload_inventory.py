from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("ocore_rust_payload_inventory", Path(__file__).with_name("payload_inventory.py"))
payload = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(payload)


def original_elf(bitcode=b"BC\xc0\xdeoriginal-embedded-module", *, machine=62, duplicate=False):
    """Small independent ELF contract fixture, not a compiler/module emulator."""
    names = b"\0.text\0.llvmbc\0.shstrtab\0"
    text = b"\xc3"
    text_at, bitcode_at = 64, 80
    names_at = bitcode_at + len(bitcode)
    sections_at = (names_at + len(names) + 7) & ~7
    count = 5 if duplicate else 4
    data = bytearray(sections_at + count * 64)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0, ident, 1, machine, 1, 0, 0,
                     sections_at, 0, 64, 0, 0, 64, count, 3)
    data[text_at:text_at + len(text)] = text
    data[bitcode_at:bitcode_at + len(bitcode)] = bitcode
    data[names_at:names_at + len(names)] = names
    for index, values in enumerate([
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, 0, text_at, len(text), 0, 0, 1, 0),
        (7, 1, 0x80000000, 0, bitcode_at, len(bitcode), 0, 0, 1, 0),
        (15, 3, 0, 0, names_at, len(names), 0, 0, 1, 0),
    ]):
        struct.pack_into("<IIQQQQIIQQ", data, sections_at + index * 64, *values)
    if duplicate:
        struct.pack_into("<IIQQQQIIQQ", data, sections_at + 4 * 64,
                         7, 1, 0, 0, bitcode_at, len(bitcode), 0, 0, 1, 0)
    return bytes(data)


def original_archive(rows):
    data = bytearray(b"!<arch>\n")
    for name, body in rows:
        if isinstance(name, str):
            name = name.encode()
        if len(name) > 16:
            raise ValueError("fixture archive name must use an explicit GNU/BSD extension")
        header = name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
        header += b"100644".ljust(8) + str(len(body)).encode().ljust(10) + b"`\n"
        data.extend(header)
        data.extend(body)
        if len(body) % 2:
            data.extend(b"\n")
    return bytes(data)


class PayloadArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def artifact(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return payload.file_info(path)

    def rejected(self, kind, callback):
        with self.assertRaises(payload.PayloadError) as error:
            callback()
        self.assertEqual(kind, error.exception.kind, error.exception.record())
        return error.exception

    def cgu(self, *, archived=False):
        bitcode = b"BC\xc0\xdeindependent-module-byte-edge"
        obj = self.artifact("saved.o", original_elf(bitcode))
        event = {"id": "compiler", "cargo_parent_invocation_id": "cargo-parent", "outputs": [obj]}
        if archived:
            archive = self.artifact("saved.rlib", original_archive([(b"/", b"symbol-index"), (b"saved.o/", Path(obj["path"]).read_bytes())]))
            extracted = payload.extract_embedded_bitcode(archive, 0)
            container = {"artifact": archive, "member": extracted["member"]}
            event["outputs"] = [archive]
        else:
            extracted, container = payload.extract_embedded_bitcode(obj), None
        record = {"schema": payload.EDGE_SCHEMA, "compiler_invocation_id": "compiler",
                  "cargo_parent_invocation_id": "cargo-parent", "object": obj,
                  "bitcode": self.artifact("saved.bc", bitcode), "edge": extracted["edge"]}
        if container:
            record["container"] = container
        event["saved_cgus"] = [record]
        return record, event

    def graph(self, *, external=False, archived=False):
        capture = self.root / "capture"
        (capture / "events").mkdir(parents=True)
        observer = self.root / "observer"
        observer.mkdir()
        # These deliberately synthetic trusted workers isolate the edge graph
        # verifier's wire contracts. They do not qualify a real source capture.
        capture_worker = self.artifact("capture/worker.py", b'''import json
def verify_worker(session, directory, expected):
    assert session["capture_worker"]["artifact"]["sha256"] == expected
def validate_recipe(recipe):
    assert recipe == {"schema": "synthetic-edge-fixture"}
def verify_source(recipe, source):
    assert source.is_dir()
def make_report(directory, persist=True, expected_worker_sha256=None):
    assert persist is False
    return json.loads((directory / "report.json").read_bytes())
''')
        observer_worker = self.artifact("observer/worker.py", b'''import json
def verify(directory, expected_worker_sha256=None):
    result = json.loads((directory / "verification.json").read_bytes())
    assert result["trusted_worker_sha256"] == expected_worker_sha256
    return result
''')
        binding = {"schema": "ocore-runtime-capture-worker-v1", "artifact": capture_worker}
        observer_session = self.artifact("observer/session.json", json.dumps({
            "schema": "ocore-cargo-parent-observer-session-v1", "observer_worker": observer_worker,
            "source_capture_worker": binding}).encode())
        record, event = self.cgu(archived=archived)
        event.update(capture_worker=capture_worker, kind="rustc", state="finished", exit_code=0,
                     translation_required=True, capture_errors=[], cwd=str(self.root),
                     frontend={"executing_binary": self.artifact("producer/rustc", b"synthetic producer binary"),
                               "default_sysroot": str(self.root / "producer/sysroot")},
                     argv=["--crate-name", "whole_original_fixture", "--crate-type=rlib"],
                     build_environment={"RUSTC_STAGE": "1"},
                     cargo_parent={"id": "cargo-parent", "observer_session": observer_session,
                                   "observer_worker": observer_worker, "source_capture_worker": capture_worker})
        compiler_journal = self.artifact("capture/events/compiler.json", json.dumps(event).encode())
        child_receipt = self.artifact("observer/children/compiler.json", json.dumps({
            "schema": "ocore-cargo-compiler-child-v1", "cargo_parent_invocation_id": "cargo-parent",
            "capture_invocation_id": "compiler", "capture_event": compiler_journal,
            "observer_session": observer_session, "source_capture_worker": capture_worker}).encode())
        parent = {"schema": "ocore-cargo-parent-invocation-v1", "id": "cargo-parent",
                  "observer_worker": observer_worker, "source_capture_worker": binding,
                  "argv": [str(self.root / "original-cargo"), "build", "--release"],
                  "upstream_exit_code": 0, "capture_errors": [],
                  "compiler_children": [{"receipt": child_receipt, "capture_event": compiler_journal,
                                         "capture_invocation_id": "compiler"}]}
        parent_journal = self.artifact("observer/parent.json", json.dumps(parent).encode())
        invocations = [event]
        output = event["outputs"][0]
        if external:
            source = output
            foreign = self.artifact("unowned-original-provider.o", original_elf())
            executable = self.artifact("app", b"synthetic final native output identity")
            dependency = self.artifact("capture/link.d", f"app: {source['path']} {foreign['path']}\n".encode())
            linker = {"id": "linker", "kind": "linker", "capture_worker": capture_worker,
                      "state": "finished", "exit_code": 0, "capture_errors": [], "cwd": str(self.root),
                      "outputs": [executable], "native_linkage": {"complete": True, "issues": [],
                      "dependency_trace": dependency, "archive_trace": self.artifact("capture/why-extract.tsv", b"reference\textracted\tsymbol\n"),
                      "providers": [{"original": item, "snapshot": item} for item in [source, foreign]]}}
            self.artifact("capture/events/linker.json", json.dumps(linker).encode())
            invocations.append(linker)
            output = executable
        report = self.artifact("capture/report.json", json.dumps({"schema": "ocore-runtime-capture-v1",
            "capture_worker": binding, "invocations": invocations}).encode())
        source_directory = self.root / "source"
        source_directory.mkdir()
        recipe = {"schema": "synthetic-edge-fixture"}
        manifest = self.artifact("recipe.json", json.dumps(recipe).encode())
        session = self.artifact("capture/session.json", json.dumps({"capture_worker": binding,
            "manifest": manifest, "recipe": recipe, "source": {"path": str(source_directory)}}).encode())
        verification = self.artifact("observer/verification.json", json.dumps({
            "schema": "ocore-cargo-observer-verification-v1", "session": observer_session,
            "trusted_worker_sha256": observer_worker["sha256"], "observer_errors": [],
            "events": [{"event": parent_journal, "parent_argv": parent["argv"], "upstream_exit_code": 0}]}).encode())
        evidence = {"schema": payload.EVIDENCE_SCHEMA, "capture_report": report, "capture_session": session,
                    "observer_verification": verification, "roots": [output]}
        path = self.root / "payload-evidence.json"
        path.write_text(json.dumps(evidence))
        return path, evidence, event, parent, capture_worker, observer_worker

    def verify_graph(self, data):
        path, _, _, _, capture_worker, observer_worker = data
        return payload.verify_payload(path, expected_capture_worker_sha256=capture_worker["sha256"],
                                      expected_observer_worker_sha256=observer_worker["sha256"])

    def rewrite_graph_journal(self, data, *, event=None, parent=None):
        path, spec, original, original_parent, _, _ = data
        if event is not None:
            journal = self.artifact("capture/events/compiler.json", json.dumps(event).encode())
            parent = copy.deepcopy(parent or original_parent)
            parent["compiler_children"][0]["capture_event"] = journal
            child = parent["compiler_children"][0]
            receipt = json.loads(Path(child["receipt"]["path"]).read_bytes())
            receipt["capture_event"] = journal
            child["receipt"] = self.artifact("observer/children/compiler.json", json.dumps(receipt).encode())
            report = json.loads(Path(spec["capture_report"]["path"]).read_bytes())
            report["invocations"][0] = event
            spec["capture_report"] = self.artifact("capture/report.json", json.dumps(report).encode())
        if parent is not None:
            parent_journal = self.artifact("observer/parent.json", json.dumps(parent).encode())
            receipt = json.loads(Path(spec["observer_verification"]["path"]).read_bytes())
            receipt["events"][0]["event"] = parent_journal
            spec["observer_verification"] = self.artifact("observer/verification.json", json.dumps(receipt).encode())
        path.write_text(json.dumps(spec))

    def test_bound_parent_producer_sysroot_and_cgu_edges_remain_bounded(self):
        data = self.graph()
        result = self.verify_graph(data)
        self.assertTrue(result["verified"], result["gaps"])
        self.assertEqual(1, result["counts"]["embedded_edges"])
        self.assertEqual("actual_producer_query", result["compiler_contexts"][0]["sysroot"]["source"])
        for key in ["complete", "source_capture_qualified", "source_production_inventory_complete",
                    "runtime_output_membership_complete", "dependency_closure_complete", "ocore_lowering_complete",
                    "native_execution_qualified", "runtime_complete", "post_lto_native_equivalence_verified"]:
            self.assertFalse(result[key], key)

    def test_final_parent_child_hash_anchor_rejects_journal_rewriting(self):
        data = self.graph()
        spec, event = data[1], copy.deepcopy(data[2])
        event["frontend"]["executing_binary"] = self.artifact("other-producer", b"another producer generation")
        self.artifact("capture/events/compiler.json", json.dumps(event).encode())
        # Rewrite the convenient report too, while the independently finalized
        # parent still names the original compiler journal hash.
        report = json.loads(Path(spec["capture_report"]["path"]).read_bytes())
        report["invocations"][0] = event
        spec["capture_report"] = self.artifact("capture/report.json", json.dumps(report).encode())
        data[0].write_text(json.dumps(spec))
        result = self.verify_graph(data)
        self.assertFalse(result["verified"])
        self.assertIn("artifact_mismatch", {gap["kind"] for gap in result["gaps"]})

    def test_worker_and_parent_binding_cannot_be_replaced_by_stage_labels(self):
        data = self.graph()
        result = payload.verify_payload(data[0], expected_capture_worker_sha256="0" * 64,
                                        expected_observer_worker_sha256=data[5]["sha256"])
        self.assertIn("capture_worker_mismatch", {gap["kind"] for gap in result["gaps"]})
        event = copy.deepcopy(data[2]); event["cargo_parent_invocation_id"] = "a-different-parent"
        self.rewrite_graph_journal(data, event=event)
        result = self.verify_graph(data)
        self.assertIn("cargo_parent_missing", {gap["kind"] for gap in result["gaps"]})

    def test_missing_sysroot_or_final_children_remains_a_typed_gap(self):
        data = self.graph()
        event = copy.deepcopy(data[2]); event["frontend"].pop("default_sysroot")
        event["build_environment"]["RUSTC_SYSROOT"] = "/a/stage-label-is-not-a-producer-query"
        self.rewrite_graph_journal(data, event=event)
        result = self.verify_graph(data)
        self.assertIn("sysroot_missing", {gap["kind"] for gap in result["gaps"]})
        parent = copy.deepcopy(data[3]); parent.pop("compiler_children")
        self.rewrite_graph_journal(data, parent=parent)
        result = self.verify_graph(data)
        self.assertIn("final_child_inventory_missing", {gap["kind"] for gap in result["gaps"]})

    def test_exact_six_key_child_receipt_and_environment_binding_are_required(self):
        data = self.graph()
        parent = copy.deepcopy(data[3])
        child = parent["compiler_children"][0]
        receipt = json.loads(Path(child["receipt"]["path"]).read_bytes())
        receipt["self_reported_verified"] = True
        child["receipt"] = self.artifact("observer/children/compiler.json", json.dumps(receipt).encode())
        self.rewrite_graph_journal(data, parent=parent)
        self.assertIn("child_receipt_mismatch", {gap["kind"] for gap in self.verify_graph(data)["gaps"]})
        # Restore the original receipt, then change only the source-worker wire
        # from the agreed artifact triple to a supplied wrapper object.
        receipt.pop("self_reported_verified")
        parent["compiler_children"][0]["receipt"] = self.artifact("observer/children/compiler.json", json.dumps(receipt).encode())
        event = copy.deepcopy(data[2])
        event["cargo_parent"]["source_capture_worker"] = {"artifact": data[4]}
        self.rewrite_graph_journal(data, event=event, parent=parent)
        self.assertIn("cargo_parent_binding_mismatch", {gap["kind"] for gap in self.verify_graph(data)["gaps"]})

    def test_trusted_worker_reconstruction_rejection_is_a_typed_gap(self):
        data = self.graph()
        spec = data[1]
        session = json.loads(Path(spec["capture_session"]["path"]).read_bytes())
        session["recipe"] = {"schema": "a-rewritten-recipe"}
        spec["capture_session"] = self.artifact("capture/session.json", json.dumps(session).encode())
        data[0].write_text(json.dumps(spec))
        self.assertIn("capture_recipe_mismatch", {gap["kind"] for gap in self.verify_graph(data)["gaps"]})
        session["recipe"] = {"schema": "synthetic-edge-fixture"}
        session["source"]["path"] = str(self.root / "absent-original-source")
        spec["capture_session"] = self.artifact("capture/session.json", json.dumps(session).encode())
        data[0].write_text(json.dumps(spec))
        rejected = self.verify_graph(data)
        self.assertIn("worker_readmission_rejected", {gap["kind"] for gap in rejected["gaps"]})
        self.assertFalse(rejected["complete"])

    def test_explicit_original_sysroot_precedes_default_query_without_role_inference(self):
        event = {"argv": ["--sysroot", "actual"], "cwd": str(self.root),
                 "frontend": {"default_sysroot": "/a/default-that-was-not-selected"},
                 "build_environment": {"RUSTC_STAGE": "99"}}
        selected = payload.effective_sysroot(event)
        self.assertEqual(str(self.root / "actual"), selected["path"])
        self.assertFalse(selected["artifact_membership_complete"])
        self.rejected("ambiguous_sysroot", lambda: payload.effective_sysroot({**event, "argv": ["--sysroot=first", "--sysroot=second"]}))

    def test_exact_linker_order_and_all_unowned_provider_occurrences_are_retained(self):
        data = self.graph(external=True)
        result = self.verify_graph(data)
        self.assertFalse(result["verified"])
        self.assertEqual(1, len(result["ordered_inputs"]))
        self.assertEqual([0, 1], [item["index"] for item in result["ordered_inputs"][0]["providers"]])
        self.assertEqual(1, len(result["unresolved_providers"]))
        self.assertEqual("unowned-original-provider.o", Path(result["unresolved_providers"][0]["original"]["path"]).name)
        self.assertIn("unresolved_native_providers", {gap["kind"] for gap in result["gaps"]})
        self.assertFalse(result["ordered_inputs"][0]["archive_extraction_selection_verified"])
        # Change both the report and native journal, preserving a valid local
        # artifact, but reverse the claimed order against the original trace.
        spec = data[1]
        report = json.loads(Path(spec["capture_report"]["path"]).read_bytes())
        linker = report["invocations"][1]
        linker["native_linkage"]["providers"].reverse()
        self.artifact("capture/events/linker.json", json.dumps(linker).encode())
        spec["capture_report"] = self.artifact("capture/report.json", json.dumps(report).encode())
        data[0].write_text(json.dumps(spec))
        wrong = self.verify_graph(data)
        self.assertIn("ordered_provider_mismatch", {gap["kind"] for gap in wrong["gaps"]})

    def test_report_dropping_original_cold_journals_and_claim_flags_is_rejected(self):
        data = self.graph()
        spec = data[1]
        cold = copy.deepcopy(data[2]); cold["id"] = "original-cold-compiler"
        self.artifact("capture/events/original-cold-compiler.json", json.dumps(cold).encode())
        result = self.verify_graph(data)
        self.assertIn("capture_inventory_mismatch", {gap["kind"] for gap in result["gaps"]})
        spec["complete"] = True
        data[0].write_text(json.dumps(spec))
        result = self.verify_graph(data)
        self.assertIn("invalid_evidence", {gap["kind"] for gap in result["gaps"]})

    def test_make_trace_preserves_escaped_names_dollars_and_repeated_order(self):
        trace = self.artifact("link.d", b"app: first\\ input.o second$$name.a \\\n first\\ input.o\n")
        self.assertEqual([str(self.root / "first input.o"), str(self.root / "second$name.a"),
                          str(self.root / "first input.o")], payload.ordered_link_paths(trace, str(self.root)))

    def test_elf_all_three_machines_exact_section_ranges_and_bytes(self):
        bitcode = b"BC\xc0\xdeunchanged-cgu-bytes"
        for machine in [62, 183, 243]:
            result = payload.extract_embedded_bitcode(self.artifact(f"arch-{machine}.o", original_elf(bitcode, machine=machine)))
            self.assertEqual(machine, result["object"]["machine"])
            self.assertEqual(80, result["edge"]["object_offset"])
            self.assertEqual(2, result["edge"]["section_index"])
            self.assertEqual(list(b".llvmbc"), result["edge"]["section_name_bytes"])
            self.assertEqual(len(bitcode), result["edge"]["bytes"])
            self.assertEqual(hashlib.sha256(bitcode).hexdigest(), result["edge"]["sha256"])
            self.assertEqual("original-ELF-embedded-byte-provenance-only", result["scope"])

    def test_extended_elf_section_count_and_name_table_index(self):
        raw = bytearray(original_elf())
        section_table = struct.unpack_from("<Q", raw, 40)[0]
        struct.pack_into("<HH", raw, 60, 0, 0xffff)
        struct.pack_into("<Q", raw, section_table + 32, 4)
        struct.pack_into("<I", raw, section_table + 40, 3)
        result = payload.extract_embedded_bitcode(self.artifact("extended.o", raw))
        self.assertEqual(2, result["edge"]["section_index"])

    def test_common_names_never_disambiguate_archive_objects(self):
        first, second = original_elf(b"BC\xc0\xdefirst"), original_elf(b"BC\xc0\xdesecond")
        archive = self.artifact("two.rlib", original_archive([(b"/", b"index"), (b"same.rcgu.o/", first), (b"same.rcgu.o/", second)]))
        one, two = payload.extract_embedded_bitcode(archive, 0), payload.extract_embedded_bitcode(archive, 1)
        self.assertEqual(one["member"]["name_bytes"], two["member"]["name_bytes"])
        self.assertNotEqual(one["object"]["sha256"], two["object"]["sha256"])
        self.assertNotEqual(one["member"]["data_offset"], two["member"]["data_offset"])
        self.assertEqual((1, 2), (one["member"]["physical_index"], two["member"]["physical_index"]))
        self.assertEqual(one["member"]["data_offset"] + 80, one["edge"]["container_offset"])
        self.rejected("archive_member_required", lambda: payload.extract_embedded_bitcode(archive))
        self.rejected("archive_member_missing", lambda: payload.extract_embedded_bitcode(archive, 2))

    def test_gnu_and_bsd_long_names_retain_raw_member_offsets(self):
        name = b"original.very-long-rust-cgu-name.rcgu.o"
        obj = original_elf()
        gnu = self.artifact("gnu.a", original_archive([(b"//", name + b"/\n"), (b"/0", obj)]))
        bsd = self.artifact("bsd.a", original_archive([(b"#1/" + str(len(name)).encode(), name + obj)]))
        for artifact in [gnu, bsd]:
            result = payload.extract_embedded_bitcode(artifact, 0)
            self.assertEqual(list(name), result["member"]["name_bytes"])
            self.assertEqual(hashlib.sha256(obj).hexdigest(), result["member"]["sha256"])
            self.assertEqual(len(obj), result["member"]["bytes"])
        self.assertEqual(8 + 60 + len(name), payload.extract_embedded_bitcode(bsd, 0)["member"]["data_offset"])

    def test_duplicate_missing_compressed_and_nonprogbits_sections_fail_closed(self):
        self.rejected("ambiguous_embedded_bitcode", lambda: payload.extract_embedded_bitcode(self.artifact("duplicate.o", original_elf(duplicate=True))))
        for name, field, value, kind in [
            ("missing", 0, 1, "embedded_bitcode_missing"),
            ("compressed", 8, 0x800, "unsupported_embedded_bitcode"),
            ("nobits", 4, 8, "unsupported_embedded_bitcode"),
        ]:
            raw = bytearray(original_elf())
            section_table = struct.unpack_from("<Q", raw, 40)[0]
            struct.pack_into("<Q" if field == 8 else "<I", raw, section_table + 2 * 64 + field, value)
            self.rejected(kind, lambda raw=raw: payload.extract_embedded_bitcode(self.artifact(name + ".o", raw)))

    def test_elf_malformed_headers_ranges_and_section_names_are_rejected(self):
        for name, change in [
            ("table", lambda b: struct.pack_into("<Q", b, 40, len(b) - 8)),
            ("count", lambda b: struct.pack_into("<H", b, 60, 65534)),
            ("strindex", lambda b: struct.pack_into("<H", b, 62, 9)),
            ("sectionrange", lambda b: struct.pack_into("<Q", b, struct.unpack_from("<Q", b, 40)[0] + 2 * 64 + 24, len(b) + 1)),
            ("badname", lambda b: struct.pack_into("<I", b, struct.unpack_from("<Q", b, 40)[0] + 2 * 64, 999)),
        ]:
            raw = bytearray(original_elf())
            change(raw)
            self.rejected("malformed_object", lambda raw=raw: payload.extract_embedded_bitcode(self.artifact(name + ".o", raw)))
        self.rejected("malformed_object", lambda: payload.extract_embedded_bitcode(self.artifact("truncated.o", b"\x7fELF")))

    def test_other_object_and_archive_contracts_remain_explicit(self):
        for name, offset, byte in [("elf32", 4, 1), ("bigendian", 5, 2), ("elfversion", 6, 0)]:
            raw = bytearray(original_elf()); raw[offset] = byte
            self.rejected("unsupported_object", lambda raw=raw: payload.extract_embedded_bitcode(self.artifact(name + ".o", raw)))
        raw = bytearray(original_elf()); struct.pack_into("<H", raw, 16, 3)
        self.rejected("unsupported_object", lambda: payload.extract_embedded_bitcode(self.artifact("shared.so", raw)))
        self.rejected("unsupported_archive", lambda: payload.extract_embedded_bitcode(self.artifact("thin.a", b"!<thin>\n")))
        self.rejected("unsupported_object", lambda: payload.extract_embedded_bitcode(self.artifact("nonobject.a", original_archive([(b"metadata/", b"serialized Rust metadata")])) , 0))

    def test_bitcode_magic_and_wrapper_ranges_are_not_guessed(self):
        for raw in [b"", b"BC", b"not bitcode", struct.pack("<IIIII", 0x0b17c0de, 0, 999, 4, 0)]:
            self.rejected("malformed_bitcode", lambda raw=raw: payload.extract_embedded_bitcode(self.artifact("bad-bc.o", original_elf(raw))))
        body = b"BC\xc0\xdewrapped-original"
        wrapped = struct.pack("<IIIII", 0x0b17c0de, 0, 20, len(body), 0) + body
        result = payload.extract_embedded_bitcode(self.artifact("wrapper.o", original_elf(wrapped)))
        self.assertEqual("wrapper", result["edge"]["bitcode_header"])
        self.assertEqual(hashlib.sha256(wrapped).hexdigest(), result["edge"]["sha256"])

    def test_artifact_mutation_and_typed_identity_guards(self):
        artifact = self.artifact("object.o", original_elf())
        Path(artifact["path"]).write_bytes(original_elf(b"BC\xc0\xdemutant"))
        self.rejected("artifact_mismatch", lambda: payload.extract_embedded_bitcode(artifact))
        for field, value in [("bytes", True), ("sha256", "not-a-hash"), ("path", "relative.o")]:
            wrong = copy.deepcopy(artifact); wrong[field] = value
            self.rejected("invalid_evidence", lambda wrong=wrong: payload.extract_embedded_bitcode(wrong))

    def test_original_journaled_direct_and_archive_byte_edges(self):
        for archived in [False, True]:
            record, event = self.cgu(archived=archived)
            result = payload.verify_saved_cgu(record, event)
            self.assertEqual("compiler", result["compiler_invocation_id"])
            self.assertEqual("cargo-parent", result["cargo_parent_invocation_id"])
            self.assertEqual(record["bitcode"]["sha256"], result["edge"]["sha256"])

    def test_cross_parent_and_replay_only_guesses_cannot_qualify(self):
        for field in ["compiler_invocation_id", "cargo_parent_invocation_id"]:
            record, event = self.cgu(); record[field] = "other-parent"
            self.rejected("cgu_parent_mismatch", lambda: payload.verify_saved_cgu(record, event))
        record, event = self.cgu(); event["saved_cgus"] = []
        self.rejected("cgu_not_journaled", lambda: payload.verify_saved_cgu(record, event))
        record, event = self.cgu(); event["outputs"] = []
        self.rejected("cgu_not_produced", lambda: payload.verify_saved_cgu(record, event))
        record, event = self.cgu(); record["bitcode"] = self.artifact("same-name-other-replay.bc", b"BC\xc0\xdeseparately-replayed-body")
        self.rejected("bitcode_byte_mismatch", lambda: payload.verify_saved_cgu(record, event))

    def test_archive_member_and_embedded_section_controls_isolate_each_edge(self):
        for field in ["physical_index", "name", "name_bytes", "header_offset", "data_offset",
                      "raw_data_offset", "raw_bytes", "bytes", "sha256"]:
            record, event = self.cgu(archived=True)
            original = record["container"]["member"][field]
            record["container"]["member"][field] = original + 1 if type(original) is int else [] if isinstance(original, list) else "0" * 64
            self.rejected("archive_member_mismatch", lambda: payload.verify_saved_cgu(record, event))
        for field in ["section_index", "section_name_bytes", "object_offset", "container_offset",
                      "bytes", "sha256", "bitcode_header"]:
            record, event = self.cgu()
            original = record["edge"][field]
            record["edge"][field] = original + 1 if type(original) is int else [] if isinstance(original, list) else "0" * 64
            self.rejected("embedded_edge_mismatch", lambda: payload.verify_saved_cgu(record, event))

    def test_actual_pinned_rust_embedded_rlib_artifacts_when_explicitly_available(self):
        command = os.environ.get("OCORE_TEST_RUST_PAYLOAD_RUSTC")
        if not command:
            self.skipTest("set OCORE_TEST_RUST_PAYLOAD_RUSTC to the explicit pinned Rust 1.97.1/LLVM22.1.6 binary; no ambient fallback")
        rustc = Path(command)
        self.assertTrue(rustc.is_absolute())
        version = subprocess.run([str(rustc), "-vV"], capture_output=True, check=True).stdout.decode()
        self.assertIn("release: 1.97.1\n", version)
        self.assertIn("LLVM version: 22.1.6\n", version)
        self.assertIn("commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452\n", version)
        source = self.root / "original_probe.rs"
        source.write_text('''#![no_std]
#[unsafe(no_mangle)]
pub extern "C" fn payload_probe(value: u64) -> u64 {
    value.wrapping_mul(0x9e3779b185ebca87) ^ value.rotate_left(13)
}
''')
        output = self.root / "original.rlib"
        argv = [str(rustc), str(source), "--crate-name", "original_probe", "--crate-type=rlib",
                "-Cpanic=abort", "-Copt-level=1", "-Ccodegen-units=2", "-Cembed-bitcode=yes",
                "-Csave-temps", "-o", str(output)]
        result = subprocess.run(argv, capture_output=True)
        self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))
        artifact = payload.file_info(output)
        edges, gaps = [], []
        with payload.mapped_artifact(artifact) as data:
            members = payload.archive_members(data)
        for member in members:
            try:
                edges.append(payload.extract_embedded_bitcode(artifact, member["index"]))
            except payload.PayloadError as error:
                gaps.append({"member": member, **error.record()})
        self.assertGreater(len(edges), 0, gaps)
        for edge in edges:
            with output.open("rb") as stream:
                stream.seek(edge["edge"]["container_offset"])
                original = stream.read(edge["edge"]["bytes"])
            self.assertEqual(edge["edge"]["sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(b"BC\xc0\xde", original[:4])
        # This genuine original-compiler byte extraction is not a trusted full
        # source capture, import/native execution, or a Rust engine witness.
        receipt = {"schema": "ocore-rust-original-embedded-byte-probe-v1", "argv": argv,
                   "compiler": payload.file_info(rustc), "version": version,
                   "source": payload.file_info(source), "archive": artifact,
                   "embedded_edges": edges, "unresolved_members": gaps,
                   "source_capture_qualified": False, "ocore_lowering_complete": False,
                   "native_execution_qualified": False, "runtime_complete": False}
        destination = os.environ.get("OCORE_TEST_RUST_PAYLOAD_OUTPUT_DIR")
        if destination:
            directory = Path(destination)
            directory.mkdir(parents=True, exist_ok=True)
            saved = Path(tempfile.mkdtemp(prefix="original-rust-byte-edge-", dir=directory))
            # Preserve the original artifacts and source; receipt references
            # the saved paths rather than soon-deleted temporary inputs.
            for artifact in [receipt["source"], receipt["archive"], *[payload.file_info(p) for p in self.root.glob("*.bc")]]:
                original = Path(artifact["path"])
                target = saved / original.name
                target.write_bytes(original.read_bytes())
            receipt["source"] = payload.file_info(saved / source.name)
            receipt["archive"] = payload.file_info(saved / output.name)
            for edge in receipt["embedded_edges"]:
                edge["container"] = receipt["archive"]
            (saved / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
