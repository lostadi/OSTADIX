"""Authored acceptance/receipt controls; no original-runtime qualification."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "tools/ocore-runtime/acceptance/check_runtime.py"
SPEC = importlib.util.spec_from_file_location("metadata_receipt_acceptance", PATH)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class MetadataDiagnosticReceipts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="raw-metadata-receipt-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "original.ll"
        self.source.write_bytes(b"authored exact input\0\xff")
        self.parser = self.root / "selected-parser"
        self.parser.write_bytes(b"explicit parser pin; not executed")
        self.module = {"provenance": {"input_sha256": acceptance.digest(self.source),
            "importer_version": "1; LLVM 22.1.6; library-sha256=" + acceptance.digest(self.parser),
            "noalias_metadata_source": [],
            "noalias_metadata_graph_source": {"schema": "ocore.llvm-metadata-graph/v1",
                "nodes": [{"id": 0, "kind": "tuple", "metadata_kind": 4,
                           "storage": "distinct", "operands": [0, 1]},
                          {"id": 1, "kind": "string", "metadata_kind": 0, "bytes": [0, 255]}],
                "alias_bindings": [{"alias_id": 0, "node": 0}], "roots": []}}}
        self.packet = {"schema": acceptance.RAW_METADATA_SCHEMA,
            "input_sha256": acceptance.digest(self.source), "input_bytes": self.source.stat().st_size,
            "import_complete": True, "parser": {"version": [22, 1, 6], "sha256": acceptance.digest(self.parser)},
            "alias_nodes": [self.node(b"<0xCAFE> = distinct !{<0xCAFE>, !\"\\00\\FF\"}")],
            "graph_source": copy.deepcopy(self.module["provenance"]["noalias_metadata_graph_source"])}
        self.path = self.root / "raw.json"

    @staticmethod
    def node(printer):
        return {"id": 0, "metadata_kind": 4, "printer_bytes": list(printer),
                "printer_sha256": hashlib.sha256(printer).hexdigest()}

    def validate(self, packet=None, module=None):
        self.path.write_text(json.dumps(self.packet if packet is None else packet))
        return acceptance.validate_metadata_diagnostics(self.path, self.module if module is None else module,
            acceptance.artifact(self.source), acceptance.artifact(self.parser))

    def test_valid_raw_pointer_variation_changes_only_separate_receipt(self):
        before = copy.deepcopy(self.module)
        a = self.validate()
        changed = copy.deepcopy(self.packet)
        changed["alias_nodes"] = [self.node(b"!79 = distinct !{!79, !\"\\00\\FF\"}")]
        b = self.validate(changed)
        self.assertTrue(a["validated"])
        self.assertEqual(a["tuple_count"], 1)
        self.assertNotEqual(a["sha256"], b["sha256"])
        self.assertEqual(self.module, before)

    def test_headers_parser_inputs_completion_and_required_fields_fail_closed(self):
        for key, bad in [("schema", "other"), ("input_bytes", 1), ("input_bytes", True),
                         ("input_sha256", "0" * 64), ("import_complete", False),
                         ("import_complete", 1), ("parser", None)]:
            packet = copy.deepcopy(self.packet); packet[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(acceptance.Unmet):
                self.validate(packet)
        for key in self.packet:
            packet = copy.deepcopy(self.packet); del packet[key]
            with self.subTest(missing=key), self.assertRaises(acceptance.Unmet):
                self.validate(packet)
        for field, bad in [("version", [22, True, 6]), ("version", [22, 1, 5]), ("sha256", "0" * 64)]:
            packet = copy.deepcopy(self.packet); packet["parser"][field] = bad
            with self.subTest(parser=field, bad=bad), self.assertRaises(acceptance.Unmet):
                self.validate(packet)
        packet = copy.deepcopy(self.packet); packet["error"] = {"stage": "failed"}
        with self.assertRaises(acceptance.Unmet): self.validate(packet)
        module = copy.deepcopy(self.module); module["provenance"]["importer_version"] = "1"
        with self.assertRaises(acceptance.Unmet): self.validate(module=module)

    def test_tuple_inventory_kind_bytes_sha_and_storage_fail_closed(self):
        for aliases in [[], self.packet["alias_nodes"] * 2]:
            packet = copy.deepcopy(self.packet); packet["alias_nodes"] = aliases
            with self.assertRaises(acceptance.Unmet): self.validate(packet)
        for key, bad in [("id", 1), ("id", False), ("metadata_kind", 5),
                         ("printer_bytes", [True]), ("printer_bytes", [256]), ("printer_sha256", "0" * 64)]:
            packet = copy.deepcopy(self.packet); packet["alias_nodes"][0][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(acceptance.Unmet):
                self.validate(packet)
        for printer in [b"!1 = !{}", b"<0xZZ> = distinct !{}", b"! = distinct !{}", b"!1=distinct !{}"]:
            packet = copy.deepcopy(self.packet); packet["alias_nodes"] = [self.node(printer)]
            with self.subTest(printer=printer), self.assertRaises(acceptance.Unmet): self.validate(packet)

    def test_graph_comparison_preserves_byte_integer_boolean_and_float_distinctions(self):
        for bad in [1, True, 0.0, False]:
            packet = copy.deepcopy(self.packet); packet["graph_source"]["nodes"][1]["bytes"][0] = bad
            with self.subTest(byte=bad), self.assertRaises(acceptance.Unmet): self.validate(packet)
        packet = copy.deepcopy(self.packet); packet["graph_source"]["alias_bindings"][0]["node"] = 1
        with self.assertRaises(acceptance.Unmet): self.validate(packet)
        packet = copy.deepcopy(self.packet); packet["graph_source"]["extra"] = True
        with self.assertRaises(acceptance.Unmet): self.validate(packet)

    def test_legacy_empty_and_new_graph_missing_sidecar_are_distinct(self):
        source = acceptance.artifact(self.source); parser = acceptance.artifact(self.parser)
        with self.assertRaises(acceptance.Unmet):
            acceptance.validate_metadata_diagnostics(None, self.module, source, parser)
        module = copy.deepcopy(self.module); module["provenance"].pop("noalias_metadata_graph_source")
        self.assertFalse(acceptance.validate_metadata_diagnostics(None, module, source, parser)["deterministic_graph_source_gate"])
        packet = copy.deepcopy(self.packet); packet.update(alias_nodes=[], graph_source=None)
        self.assertTrue(self.validate(packet, module)["validated"])
        module["noalias_metadata"] = {"domains": [{"id": 0, "storage": "distinct"}]}
        module["provenance"]["noalias_metadata_source"] = self.packet["alias_nodes"]
        packet.update(alias_nodes=self.packet["alias_nodes"])
        self.assertTrue(self.validate(packet, module)["validated"])
        packet["alias_nodes"] = [self.node(b"!1 = distinct !{}")]
        with self.assertRaises(acceptance.Unmet): self.validate(packet, module)

    def test_duplicate_json_fields_and_partial_failure_are_retained_but_rejected(self):
        self.path.write_text('{"schema":"x","schema":"y"}')
        retained = acceptance.retained_metadata_diagnostics(self.path)
        self.assertFalse(retained["validated"])
        with self.assertRaisesRegex(acceptance.Unmet, "duplicate"):
            acceptance.validate_metadata_diagnostics(self.path, self.module,
                acceptance.artifact(self.source), acceptance.artifact(self.parser))
        packet = copy.deepcopy(self.packet); packet["import_complete"] = False
        with self.assertRaises(acceptance.Unmet): self.validate(packet)
        self.assertEqual(acceptance.retained_metadata_diagnostics(self.path)["sha256"], acceptance.digest(self.path))
        self.path.unlink()
        self.assertIn("unavailable", acceptance.retained_metadata_diagnostics(self.path))

    def test_explicit_parser_file_pin_and_source_pin_are_rehashed(self):
        self.path.write_text(json.dumps(self.packet))
        parser = acceptance.artifact(self.parser); source = acceptance.artifact(self.source)
        self.parser.write_bytes(b"changed parser")
        with self.assertRaises(acceptance.Unmet):
            acceptance.validate_metadata_diagnostics(self.path, self.module, source, parser)
        self.parser.write_bytes(b"explicit parser pin; not executed")
        self.source.write_bytes(b"changed original")
        with self.assertRaises(acceptance.Unmet):
            acceptance.validate_metadata_diagnostics(self.path, self.module, source, parser)

    def test_real_help_discovery_is_lazy_cached_exact_and_bound_to_tool_pin(self):
        compiler = self.root / "compiler"
        for index, text, status, expected in [(0, acceptance.RAW_METADATA_OPTION, 0, True),
                (1, acceptance.RAW_METADATA_OPTION + "-other", 0, False),
                (2, acceptance.RAW_METADATA_OPTION, 1, False)]:
            compiler.write_text("#!" + sys.executable + "\nimport sys\nprint(" + repr(text) + ")\nsys.exit(" + str(status) + ")\n")
            compiler.chmod(0o700)
            runner = acceptance.Runner.__new__(acceptance.Runner)
            runner.tools = {"ocorec": acceptance.artifact(compiler)}
            runner.output = self.root / ("case-" + str(index)); runner.output.mkdir()
            runner.record = {"commands": []}; runner.environment = {}
            first = runner.metadata_diagnostics_capability(runner.output)
            self.assertEqual(first["supported"], expected)
            self.assertEqual(runner.metadata_diagnostics_capability(runner.output), first)
            self.assertEqual(len(runner.record["commands"]), 1)
            compiler.write_text(compiler.read_text() + "\n# changed\n")
            with self.assertRaises(acceptance.Unmet): runner.metadata_diagnostics_capability(runner.output)


if __name__ == "__main__":
    unittest.main()
