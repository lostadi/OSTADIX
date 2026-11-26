"""Focused source candidate controls. All are authored UNRUN in this packet."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("identity_capture_candidate", ROOT / "scripts/ocore_runtime_capture.py")
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class IdentityAssemblyCaptureContractTests(unittest.TestCase):
    def profile(self):
        return {"target_triple": "riscv64-unknown-linux-gnu", "march": "rv64gc", "mabi": "lp64d", "elf_flags": 5}

    def args(self, *tail):
        return ["--no-default-config", "--target=riscv64-unknown-linux-gnu", "-march=rv64gc", "-mabi=lp64d", "-c", *tail]

    def command(self, args):
        return capture._identity_command(args, pathlib.Path("/original"), [pathlib.Path("/original/body.s")], self.profile())

    def elf(self):
        raw = bytearray(193)
        raw[:9] = b"\x7fELF\x02\x01\x01\x00\x00"
        for offset, size, value in [(16,2,1),(18,2,243),(20,4,1),(40,8,64),(48,4,5),(52,2,64),
                                    (58,2,64),(60,2,2),(62,2,1),(132,4,3),(152,8,192),(160,8,1)]:
            raw[offset:offset+size] = value.to_bytes(size,"little")
        return raw

    def test_plain_and_explicit_assembler_language_are_positive(self):
        for prefix in [(),("-x","assembler"),("-xassembler",)]:
            self.assertEqual(self.command(self.args(*prefix,"body.s"))["effective_language"],"assembler")

    def test_effective_cpp_override_before_lowercase_source_is_rejected(self):
        for prefix in [("-x","assembler-with-cpp"),("-xassembler-with-cpp",)]:
            with self.assertRaises(capture.CaptureError):
                self.command(self.args(*prefix,"body.s"))

    def test_later_language_does_not_retroactively_change_original_input(self):
        self.assertEqual(self.command(self.args("body.s","-xassembler-with-cpp"))["effective_language"],"assembler")

    def test_last_global_target_controls_profile_matching(self):
        with self.assertRaises(capture.CaptureError):
            self.command(self.args("body.s","--target=x86_64-unknown-linux-gnu"))

    def test_paired_output_operand_is_not_a_language_selection(self):
        self.assertEqual(self.command(self.args("-o","-xassembler-with-cpp","body.s"))["output_path"],
                         "/original/-xassembler-with-cpp")

    def test_missing_paired_operands_are_capture_errors(self):
        for option in ["-target","--target","-I","-o","-x"]:
            with self.assertRaises(capture.CaptureError):
                self.command(self.args("body.s",option))

    def test_transformed_or_multiple_inputs_are_refused(self):
        for paths in [[pathlib.Path("/original/body.S")],
                      [pathlib.Path("/original/body.s"),pathlib.Path("/original/other.s")]]:
            with self.assertRaises(capture.CaptureError):
                capture._identity_command(self.args("body.s"),pathlib.Path("/original"),paths,self.profile())

    def test_default_config_and_abi_overrides_are_refused(self):
        with self.assertRaises(capture.CaptureError):
            self.command(self.args("body.s")[1:])
        with self.assertRaises(capture.CaptureError):
            self.command(self.args("body.s","-msoft-float"))

    def test_include_incbin_macro_and_conditional_generators_are_refused(self):
        for raw in [b'.include "x"\n',b'label: .incbin "x"\n',b'.macro body\n.endm\n',b'.if 1\n.endif\n']:
            with self.assertRaises(capture.CaptureError):
                capture._identity_source(raw)

    def test_directive_names_in_strings_and_comments_are_not_dependencies(self):
        capture._identity_source(b'.ascii ".include x" # .incbin "y"\n/* .macro */\n')

    def test_real_elf_envelope_is_positive_magic_only_is_not(self):
        self.assertEqual(capture._identity_elf(bytes(self.elf()),self.profile())["machine"],243)
        with self.assertRaises(capture.CaptureError):
            capture._identity_elf(b"\x7fELF",self.profile())

    def test_wrong_isa_float_flags_and_section_bounds_are_refused(self):
        for offset,size,value in [(18,2,62),(48,4,1),(40,8,1<<32),(160,8,1<<32)]:
            raw=self.elf();raw[offset:offset+size]=value.to_bytes(size,"little")
            with self.assertRaises(capture.CaptureError):
                capture._identity_elf(bytes(raw),self.profile())

    def test_boolean_file_length_cannot_authorize_consumed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/"body.s";path.write_bytes(b"ret\n")
            with self.assertRaises(capture.CaptureError):
                capture._identity_consumed({"path":str(path),"bytes":True,"sha256":"0"*64})

    def test_unknown_and_refused_representation_rows_are_retained(self):
        self.assertTrue(capture.captured_producer_unit({"representation":"future-unknown"}))
        self.assertTrue(capture.captured_producer_unit({"representation":"configured-assembly",
                                                       "configured_assembly":{"capture_complete":False}}))

    def test_v1_cannot_accept_machine_representation(self):
        with self.assertRaises(capture.CaptureError):
            capture.verify_report({"schema":capture.REPORT_SCHEMA,"units":[{"representation":"configured-assembly"}]})

    def test_default_and_selected_report_versions_remain_distinct(self):
        self.assertEqual(capture.capture_report_schema({"toolchain":{}}),capture.REPORT_SCHEMA)
        self.assertEqual(capture.capture_report_schema({"toolchain":{"clang_assembly_capture":{}}}),capture.MIXED_REPORT_SCHEMA)

    def test_constructor_entry_failure_remains_unknown(self):
        context={"record":{"execution":{},"issues":[]},"policy":{},"compiler_native":None}
        with mock.patch.object(capture.subprocess,"Popen",side_effect=OSError("injected constructor failure")):
            with self.assertRaises(OSError):
                capture._identity_run(context,["compiler"],{},None)
        result=context["record"]["execution"]
        self.assertTrue(result["attempt_entered"])
        self.assertFalse(result["completion_known"])
        self.assertFalse(result["reaped"])
        self.assertEqual(result["dispatch_state"],"constructor_entered_no_handle_unknown")

    def test_communicate_failure_never_claims_known_reap(self):
        child=mock.Mock(pid=123456789)
        child.communicate.side_effect=OSError("injected wait failure")
        context={"record":{"execution":{},"issues":[]},"policy":{},"compiler_native":None}
        with mock.patch.object(capture.subprocess,"Popen",return_value=child), mock.patch.object(capture.os,"open",side_effect=OSError("unobservable image")):
            with self.assertRaises(OSError):
                capture._identity_run(context,["compiler"],{},None)
        self.assertFalse(context["record"]["execution"]["completion_known"])
        self.assertFalse(context["record"]["execution"]["reaped"])




class IdentityAssemblyQuotedLabelAndOptionControls(unittest.TestCase):
    def test_quoted_labels_cannot_hide_dependency_directives(self):
        for source in ('"entry": .include "unheld.inc"\n', '"entry": .incbin "unheld.bin"\n',
                       '"en\\"try": .include "unheld.inc"\n', 'first: "second": .incbin "unheld.bin"\n'):
            with self.subTest(source=source), self.assertRaises(capture.CaptureError):
                capture._identity_source(source.encode())

    def test_quoted_labels_without_dependencies_remain_supported(self):
        for source in ('"entry": ret\n', '"en\\"try": ret\n'):
            with self.subTest(source=source):
                capture._identity_source(source.encode())

    def test_secondary_output_and_tool_override_forms_are_refused(self):
        profile={"target_triple":"riscv64-unknown-linux-gnu","march":"rv64gc","mabi":"lp64d"}
        path=pathlib.Path("/tmp/original.s")
        prefix=["--no-default-config","--target="+profile["target_triple"],"-march=rv64gc","-mabi=lp64d","-c"]
        for option in ("-B/unheld","--config=unheld.cfg","-fno-integrated-as","-no-integrated-as","-cc1","-cc1as","-save-temps=obj"):
            with self.subTest(option=option), self.assertRaises(capture.CaptureError):
                capture._identity_command(prefix+[option,str(path)],pathlib.Path("/tmp"),[path],profile)

    def test_output_operand_cannot_satisfy_default_config_guard(self):
        profile={"target_triple":"riscv64-unknown-linux-gnu","march":"rv64gc","mabi":"lp64d"}
        path=pathlib.Path("/tmp/original.s")
        args=["--target="+profile["target_triple"],"-march=rv64gc","-mabi=lp64d","-c",str(path),"-o","--no-default-config"]
        with self.assertRaises(capture.CaptureError):
            capture._identity_command(args,pathlib.Path("/tmp"),[path],profile)

    def test_output_operand_is_not_a_tool_override_option(self):
        profile={"target_triple":"riscv64-unknown-linux-gnu","march":"rv64gc","mabi":"lp64d"}
        path=pathlib.Path("/tmp/original.s")
        args=["--no-default-config","--target="+profile["target_triple"],"-march=rv64gc","-mabi=lp64d","-c",str(path),"-o","-B/not-a-tool"]
        self.assertEqual(capture._identity_command(args,pathlib.Path("/tmp"),[path],profile)["output_path"],"/tmp/-B/not-a-tool")



class IdentityAssemblyStrictRecordTypes(unittest.TestCase):
    def test_saved_native_and_selector_records_preserve_json_types(self):
        for observed, expected in (({"nlink": True}, {"nlink": 1}),
                                   ({"argv_index": 1.0}, {"argv_index": 1}),
                                   ({"complete": 0}, {"complete": False}),
                                   ({"native": {"uid": 0.0}}, {"native": {"uid": 0}})):
            with self.subTest(observed=observed, expected=expected):
                self.assertFalse(capture._identity_record_equal(observed, expected))
        self.assertTrue(capture._identity_record_equal({"uid": 0, "nlink": 1}, {"nlink": 1, "uid": 0}))



# No compiler/assembler invocation: direct metadata/refusal and lexical controls.
import importlib.util as _identity_repair_importlib
import json as _identity_repair_json
import pathlib as _identity_repair_pathlib
import sys as _identity_repair_sys
import unittest as _identity_repair_unittest
import unittest.mock as _identity_repair_mock


class IdentityAssemblyRequiredRefusalRepairTests(_identity_repair_unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = _identity_repair_pathlib.Path(__file__).resolve().parents[1] / "scripts" / "ocore_runtime_capture.py"
        spec = _identity_repair_importlib.spec_from_file_location("ocore_identity_required_refusal_repair", path)
        cls.worker = _identity_repair_importlib.module_from_spec(spec)
        _identity_repair_sys.modules[spec.name] = cls.worker
        spec.loader.exec_module(cls.worker)

    def event(self, code=0, known=True, required=True):
        source = {"path": "/source/original.s", "bytes": 1, "sha256": "0" * 64}
        raw = {"schema": "ocore-original-assembly-action-capture-only-v1", "original_event_id": "event",
               "original_object_selection": {"required": required},
               "sources": [{"source_path": source["path"], "suffix": ".s"}],
               "original_action_terminal_known": known, "native_exit_code": code if known else None}
        execution = {"attempt_entered": True, "completion_known": known, "reaped": known,
                     "dispatch_state": "known_reaped" if known else "constructor_entered_no_handle_unknown",
                     "pid": 42 if known else None, "exit_code": code if known else None}
        observation = {"schema": "ocore-identity-assembly-action-observation-v1", "execution": execution,
                       "native_status_known": known, "native_exit_code": code if known else None}
        return {"id": "event", "kind": "clang", "producer": "clang-llvm-v1", "sources": [source], "units": [],
                "capture_errors": [], "assembly_capture_only": [raw], "clang_identity_assembly_capture": observation,
                "exit_code": code if known else 127, "translation_required": True, "state": "finished"}

    def retain(self, event):
        session = {"recipe": {"toolchain": {"clang_assembly_capture": {}}}}
        with _identity_repair_mock.patch.object(self.worker, "_identity_consumed", side_effect=AssertionError("refusal consumed a file")):
            self.worker.retain_identity_assembly_refusal_units(event, session, _identity_repair_pathlib.Path("/session"))

    def test_numeric_dollar_label_dependency_directives_are_inspected(self):
        self.worker._identity_source(b"1$: addi a0, a0, 1\n")
        for directive in (b'.include "unheld.inc"', b'.incbin "unheld.bin"'):
            with self.subTest(directive=directive), self.assertRaises(self.worker.CaptureError):
                self.worker._identity_source(b"1$: " + directive + b"\n")

    def test_required_known_failed_action_retains_refusal_without_consumption(self):
        event = self.event(code=7)
        self.retain(event)
        self.assertEqual([row["id"] for row in event["units"]], ["event:0"])
        payload = event["units"][0]["configured_assembly"]
        self.assertIs(payload["capture_complete"], False)
        self.assertTrue(any("known exit 7" in issue for issue in payload["issues"]))

    def test_required_unknown_action_does_not_use_default_exit_as_terminal(self):
        event = self.event(known=False)
        self.retain(event)
        self.assertEqual([row["id"] for row in event["units"]], ["event:0"])
        payload = event["units"][0]["configured_assembly"]
        self.assertIs(payload["capture_complete"], False)
        self.assertTrue(any("UNKNOWN" in issue for issue in payload["issues"]))
        self.assertFalse(any("known exit 127" in issue for issue in payload["issues"]))

    def test_required_missing_delivery_stays_refused_even_with_known_zero(self):
        event = self.event()
        self.retain(event)
        self.assertEqual([row["id"] for row in event["units"]], ["event:0"])
        payload = event["units"][0]["configured_assembly"]
        self.assertIs(payload["capture_complete"], False)
        self.assertIn("identity assembly ordinary required unit delivery was incomplete", payload["issues"])

    def test_query_raw_selection_creates_no_required_unit(self):
        event = self.event(known=False, required=False)
        self.retain(event)
        self.assertEqual(event["units"], [])
        self.assertNotIn("identity_assembly_delivery_refusals", event)

    def test_existing_required_unit_is_preserved(self):
        event = self.event()
        row = {"id": "event:0", "representation": "configured-assembly",
               "capture_policy": "clang-identity-assembly-v1", "sentinel": ["preserve"]}
        event["units"].append(row)
        before = _identity_repair_json.loads(_identity_repair_json.dumps(event["units"]))
        self.retain(event)
        self.assertEqual(event["units"], before)
        self.assertNotIn("identity_assembly_delivery_refusals", event)

    def test_duplicate_existing_required_ids_are_retained_and_diagnosed(self):
        event = self.event()
        row = {"id": "event:0", "representation": "configured-assembly", "capture_policy": "clang-identity-assembly-v1"}
        event["units"] = [dict(row), dict(row)]
        before = _identity_repair_json.loads(_identity_repair_json.dumps(event["units"]))
        self.retain(event)
        self.assertEqual(event["units"], before)
        self.assertTrue(any("duplicate" in issue for issue in event["capture_errors"]))

if __name__ == "__main__":
    unittest.main()
