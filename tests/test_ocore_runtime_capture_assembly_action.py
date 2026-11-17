import ast, hashlib, os, stat, sys, tempfile, types, unittest, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Historical provenance only; never a current-loader fallback.
PAX_PREDECESSOR_WORKER_SHA = "26788e75cfd6906193a759ecf1e207df7369b04adeeb1afe8931e754d514f540"
EXPECTED = "3d43ce7507a49cf093bcc1e1a88d84e764a31ff6521660a8533e8f01aad9095a"
EXPECTED_BYTES = 261585
WORKER = None

def _native_identity(status):
    return tuple(getattr(status, field) for field in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))

def _selected_production_worker():
    path = ROOT / "scripts/ocore_runtime_capture.py"
    if os.path.realpath(path) != str(path):
        raise AssertionError("selected production worker path is not physical")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        status = os.fstat(descriptor)
        before = _native_identity(status)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise AssertionError("selected production worker is not a regular singleton")
        if _native_identity(os.lstat(path)) != before:
            raise AssertionError("selected production worker held/named identity differs")
        chunks, offset = [], 0
        while True:
            part = os.pread(descriptor, 1048576, offset)
            if not part:
                break
            chunks.append(part)
            offset += len(part)
        raw = b"".join(chunks)
        if len(raw) != EXPECTED_BYTES or hashlib.sha256(raw).hexdigest() != EXPECTED:
            raise AssertionError("selected production worker whole bytes/SHA differ")
        if _native_identity(os.fstat(descriptor)) != before or _native_identity(os.lstat(path)) != before:
            raise AssertionError("selected production worker postread native identity differs")
        return raw
    finally:
        os.close(descriptor)

def selected(raw, expected):
    if hashlib.sha256(raw).hexdigest() != expected:
        raise AssertionError("selected whole worker SHA differs")
    tree = ast.parse(raw.decode())
    helpers = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("_assembly_capture_")]
    if len(helpers) != 9:
        raise AssertionError("nine actual production helpers required")
    constants = [n for n in tree.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id in {"ASM_SUFFIXES", "PAIR_OPTIONS"} for t in n.targets)]
    if len(constants) != 2:
        raise AssertionError("actual ASM_SUFFIXES and PAIR_OPTIONS definitions required")
    namespace = {"os": os, "hashlib": hashlib, "Path": Path,
                 "CaptureError": type("CaptureError", (Exception,), {})}
    exec(compile(ast.Module(body=constants + helpers, type_ignores=[]), "<selected-worker-helpers>", "exec"), namespace)
    compiler = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "compiler")
    def find(nodes):
        for index, node in enumerate(nodes):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_assembly_action_capture" for t in node.targets):
                return nodes[index:index + 3]
            for _, value in ast.iter_fields(node):
                if isinstance(value, list) and value and all(isinstance(x, ast.stmt) for x in value):
                    found = find(value)
                    if found is not None:
                        return found
        return None
    fragment = find(compiler.body)
    if fragment is None or len(fragment) != 3 or not isinstance(fragment[2], ast.Try):
        raise AssertionError("actual original-action before/status/try-finally fragment missing")
    if "assembly translation unit requires an explicit target-specific importer:" not in raw.decode():
        raise AssertionError("original importer refusal missing")
    return namespace, compile(ast.Module(body=fragment, type_ignores=[]), "<selected-original-action-fragment>", "exec")

class CaptureOnlyControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global WORKER
        WORKER = _selected_production_worker()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.session = self.root / "session"; self.session.mkdir()
        self.source = self.root / "source.S"; self.source.write_bytes(b"# original fixture\nret\n")
        self.output, self.stage = self.root / "out.o", self.root / "out.s"
        self.namespace, self.fragment = selected(WORKER, EXPECTED)
        self.calls = []
        self.synthetic_object_writes = []
        self.object_bytes = b"retained opaque fixture bytes; ELF validation remains unqualified"
    def execute(self, args=None, sources=None, action=None, status=0, header=False, expected_capture=True, write_objects=True):
        args = args if args is not None else ["-c", "-save-temps=obj", str(self.source), "-o", str(self.output)]
        event = {"id": "fixture-" + uuid.uuid4().hex, "argv": list(args), "response_files": [],
                 "compiler": {"fixture": True}, "frontend": {"fixture": True},
                 "build_environment": {"CPPFLAGS": "-DFIXTURE=1"}, "units": [], "capture_errors": []}
        scope, native_env = dict(self.namespace), {"SYNTHETIC_DECLARED_VALUE": "unchanged"}
        def run(argv, **kwargs):
            self.calls.append((argv, kwargs))
            self.assertEqual(argv, ["selected-original-compiler", *args])
            self.assertIs(kwargs["env"], native_env)
            if write_objects and status == 0 and "-c" in args and "-S" not in args and "-emit-llvm" not in args:
                self.output.write_bytes(self.object_bytes)
                self.synthetic_object_writes.append(str(self.output))
            if action is not None:
                action(scope)
            return types.SimpleNamespace(returncode=status)
        scope.update(session_path=self.session, event=event, args=args,
                     inputs=sources if sources is not None else [self.source], cwd=self.root,
                     kind="clang", header_compile=header, program="selected-original-compiler",
                     executed_args=args, native_environment=native_env,
                     subprocess=types.SimpleNamespace(run=run), stdin_source=None, stdin_bytes=None)
        exec(self.fragment, scope)
        self.assertEqual(len(self.calls), 1); self.assertEqual(scope["native_code"], status)
        if not expected_capture:
            self.assertNotIn("assembly_capture_only", event)
            self.assertFalse((self.session / "assembly-capture-only").exists())
            return event, None, scope
        record = event["assembly_capture_only"][0]
        self.assertFalse(record["capture_complete"]); self.assertFalse(record["admission"])
        self.assertFalse(record["compiler_source_consumption_proven"])
        self.assertTrue(all(x["known"] for x in record["closes"]))
        return event, record, scope
    def codes(self, record):
        return [x["code"] for x in record["problems"]]
    def test_plain_s_retains_bytes_without_claiming_include_or_consumption_closure(self):
        self.source = self.root / "plain.s"; data = b'.include "missing.inc"\n.incbin "missing.bin"\nret\n'
        self.source.write_bytes(data)
        _, record, _ = self.execute(args=["-c", str(self.source), "-o", str(self.output)])
        kept = record["sources"][0]["source_retention"]["retained"]
        self.assertEqual(Path(kept["path"]).read_bytes(), data)
        self.assertEqual(kept["sha256"], hashlib.sha256(data).hexdigest())
        self.assertFalse(record["include_incbin_generated_header_toolchild_closure_complete"])
    def test_fresh_explicit_save_temps_stage_retains_exact_candidate(self):
        data = b".text\nret\n"
        _, record, _ = self.execute(action=lambda _: self.stage.write_bytes(data))
        stage = record["sources"][0]["stage_candidate"]
        self.assertTrue(stage["fresh_named_file_after_original_action"])
        self.assertEqual(Path(stage["retained"]["retained"]["path"]).read_bytes(), data)
        self.assertEqual(stage["retained"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertFalse(stage["producer_attribution_proven"])
        self.assertTrue(record["retention_passed"])
    def test_missing_explicit_save_temps_never_promotes_existing_s(self):
        self.stage.write_bytes(b"unrelated")
        _, record, _ = self.execute(args=["-c", str(self.source), "-o", str(self.output)])
        self.assertIn("CONFIGURED_ASSEMBLY_OUTPUT_MISSING", self.codes(record))
        self.assertIsNone(record["sources"][0]["stage_candidate"]["retained"])
    def test_preexisting_stage_even_rewritten_is_not_attributed(self):
        self.stage.write_bytes(b"before")
        _, record, _ = self.execute(action=lambda _: self.stage.write_bytes(b"after"))
        self.assertIn("PREEXISTING_STAGE_NOT_ATTRIBUTED", self.codes(record))
        self.assertFalse(record["sources"][0]["stage_candidate"]["eligible"])
        self.assertIsNone(record["sources"][0]["stage_candidate"]["retained"])
    def test_source_mutation_preserves_original_zero_but_fails_custody(self):
        def action(_):
            self.stage.write_bytes(b"stage"); self.source.write_bytes(b"changed source")
        _, record, scope = self.execute(action=action)
        self.assertEqual(scope["native_code"], 0)
        self.assertIn("FILE_CUSTODY_FAILED", self.codes(record)); self.assertFalse(record["retention_passed"])
        self.assertTrue(any(x["role"] == "original-source" and not x["passed"] for x in record["custody"]))
    def test_stage_symlink_refused_without_target_copy(self):
        outside = self.root / "outside"; outside.write_bytes(b"not compiler output")
        _, record, _ = self.execute(action=lambda _: self.stage.symlink_to(outside))
        self.assertIn("STAGE_RETENTION_FAILED", self.codes(record))
        self.assertFalse(record["sources"][0]["stage_candidate"]["fresh_named_file_after_original_action"])
        self.assertIsNone(record["sources"][0]["stage_candidate"]["retained"])
    def test_nonzero_original_retains_status_and_diagnostic_stage(self):
        _, record, scope = self.execute(action=lambda _: self.stage.write_bytes(b"failed stage"), status=7)
        self.assertEqual(scope["native_code"], 7); self.assertEqual(record["native_exit_code"], 7)
        self.assertIn("ORIGINAL_ACTION_FAILED_OR_UNKNOWN", self.codes(record))
        self.assertIsNotNone(record["sources"][0]["stage_candidate"]["retained"])
    def test_constructor_exception_propagates_with_all_capture_closes(self):
        class Sentinel(Exception): pass
        sentinel = Sentinel("original constructor reached after writing stage")
        reached = {"stage_copy_calls": 0, "stage_hash_calls": 0, "object_copy_calls": 0, "object_hash_calls": 0}
        original_copy = self.namespace["_assembly_capture_copy"]
        original_hash = self.namespace["_assembly_capture_hash_fd"]
        def copy_spy(context, source, name, role):
            if role == "stage-output-candidate":
                reached["stage_copy_calls"] += 1
            if role == "original-object-output-candidate":
                reached["object_copy_calls"] += 1
            return original_copy(context, source, name, role)
        def hash_spy(descriptor):
            status = os.fstat(descriptor)
            if reached.get("stage_inode") == (status.st_dev, status.st_ino):
                reached["stage_hash_calls"] += 1
            if reached.get("object_inode") == (status.st_dev, status.st_ino):
                reached["object_hash_calls"] += 1
            return original_hash(descriptor)
        self.namespace["_assembly_capture_copy"] = copy_spy
        self.namespace["_assembly_capture_hash_fd"] = hash_spy
        data = b"written by reached fake constructor before exception"
        def action(scope):
            reached["context"] = scope["_assembly_action_capture"]
            object_status = os.lstat(self.output)
            reached["object_inode"] = (object_status.st_dev, object_status.st_ino)
            reached["object_identity"] = self.namespace["_assembly_capture_identity"](object_status)
            self.stage.write_bytes(data)
            status = os.lstat(self.stage)
            reached["stage_inode"] = (status.st_dev, status.st_ino)
            reached["stage_identity"] = self.namespace["_assembly_capture_identity"](status)
            raise sentinel
        with self.assertRaises(Sentinel) as caught:
            self.execute(action=action)
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.stage.read_bytes(), data)
        self.assertEqual(self.namespace["_assembly_capture_identity"](os.lstat(self.stage)), reached["stage_identity"])
        self.assertEqual(reached["stage_copy_calls"], 0)
        self.assertEqual(reached["stage_hash_calls"], 0)
        self.assertEqual(reached["object_copy_calls"], 0)
        self.assertEqual(reached["object_hash_calls"], 0)
        self.assertEqual(self.output.read_bytes(), self.object_bytes)
        self.assertEqual(self.namespace["_assembly_capture_identity"](os.lstat(self.output)), reached["object_identity"])
        record = reached["context"]["record"]
        self.assertEqual(record["original_object_outputs"][0]["consumption_skipped_reason"], "ORIGINAL_ACTION_TERMINAL_UNKNOWN")
        self.assertIsNone(record["original_object_outputs"][0]["retained"])
        self.assertFalse(record["original_object_bytes_retained"])
        self.assertFalse(record["original_action_terminal_known"])
        self.assertIsNone(record["native_exit_code"])
        stage = record["sources"][0]["stage_candidate"]
        self.assertTrue(stage["eligible"])
        self.assertIsNone(stage["retained"])
        self.assertEqual(stage["consumption_skipped_reason"], "ORIGINAL_ACTION_TERMINAL_UNKNOWN")
        self.assertFalse(stage["fresh_named_file_after_original_action"])
        self.assertIn("STAGE_OUTPUT_CONSUMPTION_SKIPPED_UNKNOWN", self.codes(record))
        self.assertIn("ORIGINAL_ACTION_FAILED_OR_UNKNOWN", self.codes(record))
        self.assertFalse(record["retention_passed"])
        self.assertTrue(record["custody"])
        self.assertTrue(all(x["passed"] for x in record["custody"]))
        self.assertTrue(record["closes"])
        self.assertTrue(all(x["known"] for x in record["closes"]))
        self.assertTrue(all(x["fd"] is None for x in reached["context"]["files"]))
        self.assertTrue(all(x["fd"] is None for x in reached["context"]["directories"]))
    def test_conflicting_save_temp_modes_remain_missing_not_guessed(self):
        _, record, _ = self.execute(args=["-c", "-save-temps=obj", "-save-temps=cwd", str(self.source), "-o", str(self.output)])
        self.assertIsNotNone(record["sources"][0]["source_retention"])
        self.assertIn("CONFIGURED_ASSEMBLY_OUTPUT_MISSING", self.codes(record))
    def test_stdout_object_destination_is_not_a_stage_filename(self):
        _, record, scope = self.execute(args=["-c", "-save-temps=obj", str(self.source), "-o", "-"])
        self.assertEqual(scope["native_code"], 0)
        self.assertIn("CONFIGURED_ASSEMBLY_OUTPUT_MISSING", self.codes(record))
        stage = record["sources"][0]["stage_candidate"]
        self.assertEqual(stage["selection"], "unsupported-or-ambiguous-save-temps-layout")
        self.assertNotIn("path", stage)
        self.assertIsNone(stage["retained"])
        self.assertFalse(record["retention_passed"])
    def test_retained_source_mutation_reaches_actual_late_guard(self):
        def action(scope):
            self.stage.write_bytes(b"stage")
            kept = Path(scope["_assembly_action_capture"]["record"]["sources"][0]["source_retention"]["retained"]["path"])
            kept.chmod(0o600); kept.write_bytes(b"changed retained source")
        _, record, _ = self.execute(action=action)
        self.assertIn("FILE_CUSTODY_FAILED", self.codes(record))
        self.assertTrue(any(x["role"] == "retained-original-source" and not x["passed"] for x in record["custody"]))
    def test_query_keeps_original_call_without_assembly_record(self):
        self.execute(args=["-E", str(self.source)], expected_capture=False)
    def test_header_keeps_original_call_without_assembly_record(self):
        self.execute(header=True, expected_capture=False)
    def test_inputless_link_keeps_original_call_without_assembly_record(self):
        self.execute(args=["prior.o", "-o", "binary"], sources=[], expected_capture=False)


    def plain_source(self):
        self.source = self.root / "plain.s"
        self.source.write_bytes(b".text\nret\n")
        return ["-c", str(self.source), "-o", str(self.output)]

    def test_original_object_retains_full_bytes_and_original_action_selector(self):
        args = self.plain_source()
        _, record, scope = self.execute(args=args)
        self.assertEqual(scope["native_code"], 0)
        self.assertEqual(self.synthetic_object_writes, [str(self.output)])
        self.assertTrue(record["original_object_selection"]["selection_complete"])
        self.assertTrue(record["original_object_bytes_retained"])
        self.assertEqual(len(record["original_object_outputs"]), 1)
        row = record["original_object_outputs"][0]
        self.assertEqual(row["selector"]["original_event_id"], record["original_event_id"])
        self.assertEqual(row["selector"]["source_path"], str(self.source))
        self.assertEqual(row["selector"]["output_path"], str(self.output))
        self.assertEqual(row["selector"]["explicit_output_argv_index"], 2)
        self.assertEqual(row["selector"]["naming_profile"], "separate-explicit-output-v1")
        kept = row["retained"]["retained"]
        self.assertEqual(Path(kept["path"]).read_bytes(), self.object_bytes)
        self.assertEqual(kept["bytes"], len(self.object_bytes))
        self.assertEqual(kept["sha256"], hashlib.sha256(self.object_bytes).hexdigest())
        self.assertEqual(stat.S_IMODE(os.lstat(kept["path"]).st_mode), 0o400)
        self.assertFalse(row["format_validated"])
        self.assertFalse(row["target_abi_profile_admitted"])
        self.assertFalse(row["producer_source_consumption_proven"])
        self.assertFalse(record["admission"])

    def test_multiple_assembly_sources_retain_every_default_object_without_reordering(self):
        self.plain_source()
        second = self.root / "second.s"; second.write_bytes(b".text\nsecond:\nret\n")
        first_output, second_output = self.root / "plain.o", self.root / "second.o"
        first_data, second_data = b"first original output", b"second original output"
        reached = []
        def action(_):
            first_output.write_bytes(first_data); second_output.write_bytes(second_data)
            reached.extend([str(first_output), str(second_output)])
        _, record, _ = self.execute(args=["-c", str(second), str(self.source)],
            sources=[second, self.source], action=action, write_objects=False)
        self.assertEqual(reached, [str(first_output), str(second_output)])
        rows = record["original_object_outputs"]
        self.assertEqual([row["selector"]["source_path"] for row in rows], [str(second), str(self.source)])
        self.assertEqual([row["path"] for row in rows], [str(second_output), str(first_output)])
        self.assertEqual([Path(row["retained"]["retained"]["path"]).read_bytes() for row in rows],
                         [second_data, first_data])
        self.assertTrue(record["original_object_bytes_retained"])

    def test_missing_original_object_is_not_an_empty_success(self):
        args = self.plain_source()
        _, record, scope = self.execute(args=args, write_objects=False)
        self.assertEqual(scope["native_code"], 0)
        self.assertFalse(self.output.exists())
        self.assertIn("OBJECT_RETENTION_FAILED", self.codes(record))
        self.assertIsNone(record["original_object_outputs"][0]["retained"])
        self.assertFalse(record["original_object_bytes_retained"])

    def test_preexisting_object_overwrite_does_not_manufacture_original_authority(self):
        args = self.plain_source(); self.output.write_bytes(b"stale")
        before = self.namespace["_assembly_capture_identity"](os.lstat(self.output))
        _, record, scope = self.execute(args=args)
        self.assertEqual(scope["native_code"], 0)
        self.assertEqual(self.output.read_bytes(), self.object_bytes)
        row = record["original_object_outputs"][0]
        self.assertEqual(row["before_identity"], before)
        self.assertFalse(row["eligible"]); self.assertIsNone(row["retained"])
        self.assertIn("PREEXISTING_OBJECT_NOT_ATTRIBUTED", self.codes(record))
        self.assertFalse(record["original_object_bytes_retained"])

    def test_original_object_symlink_is_refused_after_reached_action(self):
        args = self.plain_source(); outside = self.root / "outside.o"
        outside.write_bytes(b"outside bytes")
        reached = []
        def action(_):
            self.output.symlink_to(outside); reached.append(os.readlink(self.output))
        _, record, scope = self.execute(args=args, action=action, write_objects=False)
        self.assertEqual(scope["native_code"], 0)
        self.assertEqual(reached, [str(outside)])
        self.assertTrue(self.output.is_symlink()); self.assertEqual(outside.read_bytes(), b"outside bytes")
        self.assertIn("OBJECT_RETENTION_FAILED", self.codes(record))
        self.assertIsNone(record["original_object_outputs"][0]["retained"])
        self.assertFalse(record["original_object_bytes_retained"])

    def test_original_object_hardlink_is_refused_without_alias_byte_acceptance(self):
        args = self.plain_source(); outside = self.root / "outside.o"
        outside.write_bytes(b"same linked bytes"); reached = []
        def action(_):
            os.link(outside, self.output); reached.append(os.lstat(self.output).st_ino)
        _, record, _ = self.execute(args=args, action=action, write_objects=False)
        self.assertEqual(reached, [os.lstat(outside).st_ino])
        self.assertEqual(os.lstat(self.output).st_nlink, 2)
        self.assertIn("OBJECT_RETENTION_FAILED", self.codes(record))
        self.assertFalse(record["original_object_bytes_retained"])

    def changed_object_during_read(self, rename):
        args = self.plain_source(); original_pread = os.pread
        reached = {"hook": False}; changed = b"changed object identity"
        replacement = self.root / "replacement.o"
        def pread(descriptor, size, offset):
            data = original_pread(descriptor, size, offset)
            current = os.fstat(descriptor)
            if (not reached["hook"] and self.output.exists()
                    and (current.st_dev, current.st_ino) ==
                    (os.lstat(self.output).st_dev, os.lstat(self.output).st_ino)):
                reached.update(hook=True, before_ino=current.st_ino, returned=data)
                if rename:
                    replacement.write_bytes(changed); os.replace(replacement, self.output)
                else:
                    self.output.write_bytes(changed)
                reached["after_ino"] = os.lstat(self.output).st_ino
            return data
        os.pread = pread
        try:
            _, record, scope = self.execute(args=args)
        finally:
            os.pread = original_pread
        self.assertTrue(reached["hook"])
        self.assertEqual(reached["returned"], self.object_bytes)
        self.assertEqual(self.output.read_bytes(), changed)
        self.assertEqual(hashlib.sha256(self.output.read_bytes()).hexdigest(), hashlib.sha256(changed).hexdigest())
        if rename:
            self.assertNotEqual(reached["before_ino"], reached["after_ino"])
        else:
            self.assertEqual(reached["before_ino"], reached["after_ino"])
        self.assertEqual(scope["native_code"], 0)
        self.assertIn("OBJECT_RETENTION_FAILED", self.codes(record))
        problem = next(item for item in record["problems"] if item["code"] == "OBJECT_RETENTION_FAILED")
        self.assertIn("source changed while retained", problem["detail"])
        self.assertFalse(record["original_object_bytes_retained"])

    def test_same_inode_original_object_mutation_is_observed_and_rejected(self):
        self.changed_object_during_read(rename=False)

    def test_atomic_original_object_replacement_is_observed_and_rejected(self):
        self.changed_object_during_read(rename=True)

    def test_retained_object_late_mutation_reaches_final_custody_guard(self):
        args = self.plain_source(); original_copy = self.namespace["_assembly_capture_copy"]
        reached = []; changed = b"changed retained object"
        def copy(context, source, name, role):
            result = original_copy(context, source, name, role)
            if role == "original-object-output-candidate":
                path = Path(result["retained"]["path"])
                path.chmod(0o600); path.write_bytes(changed); reached.append(str(path))
            return result
        self.namespace["_assembly_capture_copy"] = copy
        _, record, scope = self.execute(args=args)
        self.assertEqual(scope["native_code"], 0); self.assertEqual(len(reached), 1)
        self.assertEqual(Path(reached[0]).read_bytes(), changed)
        self.assertIn("FILE_CUSTODY_FAILED", self.codes(record))
        self.assertTrue(any(item["role"] == "retained-original-object-output-candidate"
                            and not item["passed"] for item in record["custody"]))
        self.assertFalse(record["original_object_bytes_retained"])

    def test_failed_original_action_does_not_consume_written_object(self):
        args = self.plain_source(); reached = []; original_copy = self.namespace["_assembly_capture_copy"]
        def copy(context, source, name, role):
            if role == "original-object-output-candidate": reached.append(str(source))
            return original_copy(context, source, name, role)
        self.namespace["_assembly_capture_copy"] = copy
        data = b"failed compiler diagnostic output"
        _, record, scope = self.execute(args=args, status=7, write_objects=False,
            action=lambda _: self.output.write_bytes(data))
        self.assertEqual(scope["native_code"], 7); self.assertEqual(self.output.read_bytes(), data)
        self.assertEqual(reached, [])
        self.assertEqual(record["original_object_outputs"][0]["consumption_skipped_reason"], "ORIGINAL_ACTION_FAILED")
        self.assertIsNone(record["original_object_outputs"][0]["retained"])
        self.assertFalse(record["original_object_bytes_retained"])

    def test_nonstandard_explicit_object_suffix_is_bound_by_compile_intent(self):
        self.plain_source()
        for basename in ("shared.os", "extensionless"):
            with self.subTest(basename=basename):
                self.calls.clear(); self.synthetic_object_writes.clear()
                self.output = self.root / basename
                _, record, _ = self.execute(args=["-c", str(self.source), "-o", str(self.output)])
                row = record["original_object_outputs"][0]
                self.assertEqual(row["path"], str(self.output))
                self.assertEqual(Path(row["retained"]["retained"]["path"]).read_bytes(), self.object_bytes)
                self.assertTrue(record["original_object_bytes_retained"])

    def test_wrong_compile_mode_never_reads_a_misleading_object_name(self):
        self.plain_source(); copied = []; original_copy = self.namespace["_assembly_capture_copy"]
        def copy(context, source, name, role):
            if role == "original-object-output-candidate": copied.append(str(source))
            return original_copy(context, source, name, role)
        self.namespace["_assembly_capture_copy"] = copy
        for prefix in (["-S"], ["-c", "-emit-llvm"], []):
            with self.subTest(prefix=prefix):
                self.calls.clear(); self.output.unlink(missing_ok=True)
                _, record, scope = self.execute(args=[*prefix, str(self.source), "-o", str(self.output)],
                    write_objects=False, action=lambda _: self.output.write_bytes(self.object_bytes))
                self.assertEqual(scope["native_code"], 0)
                self.assertEqual(self.output.read_bytes(), self.object_bytes)
                self.assertFalse(record["original_object_selection"]["required"])
                self.assertEqual(record["original_object_outputs"], [])
                self.assertFalse(record["original_object_bytes_retained"])
        self.assertEqual(copied, [])

    def test_unknown_and_boolean_statuses_do_not_consume_written_objects(self):
        self.plain_source(); copied = []; original_copy = self.namespace["_assembly_capture_copy"]
        def copy(context, source, name, role):
            if role == "original-object-output-candidate": copied.append(str(source))
            return original_copy(context, source, name, role)
        self.namespace["_assembly_capture_copy"] = copy
        for status in (None, False):
            with self.subTest(status=status):
                self.calls.clear(); self.output.unlink(missing_ok=True)
                _, record, scope = self.execute(args=["-c", str(self.source), "-o", str(self.output)],
                    status=status, write_objects=False, action=lambda _: self.output.write_bytes(self.object_bytes))
                self.assertIs(scope["native_code"], status)
                self.assertEqual(self.output.read_bytes(), self.object_bytes)
                self.assertFalse(record["original_action_terminal_known"])
                self.assertEqual(record["original_object_outputs"][0]["consumption_skipped_reason"], "ORIGINAL_ACTION_TERMINAL_UNKNOWN")
                self.assertIsNone(record["original_object_outputs"][0]["retained"])
                self.assertFalse(record["original_object_bytes_retained"])
        self.assertEqual(copied, [])

    def test_ambiguous_output_flags_never_fall_back_to_an_invented_default(self):
        self.plain_source()
        variants = (["-o"], ["-o", "-"], ["-o", str(self.output), "-o", str(self.output)],
                    ["-o" + str(self.output)], ["-o=" + str(self.output)])
        for flags in variants:
            with self.subTest(flags=flags):
                self.calls.clear()
                _, record, scope = self.execute(args=["-c", str(self.source), *flags], write_objects=False)
                self.assertEqual(scope["native_code"], 0)
                self.assertIn("OBJECT_OUTPUT_SELECTION_UNSUPPORTED", self.codes(record))
                self.assertEqual(record["original_object_outputs"], [])
                self.assertFalse(record["original_object_bytes_retained"])

    def test_duplicate_default_object_names_reject_complete_selection(self):
        first = self.root / "a"; second = self.root / "b"; first.mkdir(); second.mkdir()
        sources = [first / "same.s", second / "same.s"]
        for source in sources: source.write_bytes(b"ret\n")
        _, record, scope = self.execute(args=["-c", *map(str, sources)], sources=sources, write_objects=False)
        self.assertEqual(scope["native_code"], 0)
        self.assertIn("OBJECT_OUTPUT_SELECTION_COLLISION", self.codes(record))
        self.assertEqual(record["original_object_outputs"], [])
        self.assertFalse(record["original_object_selection"]["selection_complete"])
        self.assertFalse(record["original_object_bytes_retained"])

    def test_compile_flag_used_as_include_operand_never_selects_an_object(self):
        self.plain_source(); copied = []; original_copy = self.namespace["_assembly_capture_copy"]
        def copy(context, source, name, role):
            if role == "original-object-output-candidate": copied.append(str(source))
            return original_copy(context, source, name, role)
        self.namespace["_assembly_capture_copy"] = copy
        args = ["-I", "-c", str(self.source), "-o", str(self.output)]
        _, record, scope = self.execute(args=args, write_objects=False,
            action=lambda _: self.output.write_bytes(self.object_bytes))
        self.assertEqual(scope["native_code"], 0)
        self.assertEqual(self.output.read_bytes(), self.object_bytes)
        self.assertEqual(record["original_object_selection"]["profile"], "not-an-original-object-compile")
        self.assertFalse(record["original_object_selection"]["required"])
        self.assertEqual(record["original_object_outputs"], []); self.assertEqual(copied, [])
        self.assertFalse(record["original_object_bytes_retained"])

    def test_mode_like_option_operands_do_not_hide_a_real_compile(self):
        self.plain_source()
        for option, operand in (("-I", "-S"), ("-D", "-emit-llvm"), ("-Xclang", "-o")):
            with self.subTest(option=option, operand=operand):
                self.calls.clear(); self.output.unlink(missing_ok=True)
                args = ["-c", option, operand, str(self.source), "-o", str(self.output)]
                _, record, _ = self.execute(args=args, write_objects=False,
                    action=lambda _: self.output.write_bytes(self.object_bytes))
                self.assertEqual(self.output.read_bytes(), self.object_bytes)
                self.assertTrue(record["original_object_selection"]["required"])
                self.assertTrue(record["original_object_bytes_retained"])
                row = record["original_object_outputs"][0]
                self.assertEqual(row["selector"]["explicit_output_argv_index"], 4)
                self.assertEqual(Path(row["retained"]["retained"]["path"]).read_bytes(), self.object_bytes)
                self.assertFalse(row["producer_attribution_proven"])

    def test_mode_like_explicit_output_operand_is_a_filename(self):
        self.plain_source(); self.output = self.root / "-S"
        _, record, _ = self.execute(args=["-c", str(self.source), "-o", "-S"], write_objects=False,
            action=lambda _: self.output.write_bytes(self.object_bytes))
        self.assertEqual(self.output.read_bytes(), self.object_bytes)
        row = record["original_object_outputs"][0]
        self.assertEqual(row["path"], str(self.output))
        self.assertEqual(row["selector"]["explicit_output_argv_index"], 2)
        self.assertEqual(Path(row["retained"]["retained"]["path"]).read_bytes(), self.object_bytes)
        self.assertTrue(record["original_object_bytes_retained"])

    def test_unknown_option_and_end_of_options_do_not_invent_compile_intent(self):
        self.plain_source()
        cases = [(["--unknown-option", "-c", str(self.source), "-o", str(self.output)], "OBJECT_OUTPUT_SELECTION_UNSUPPORTED"),
                 (["--", "-c", str(self.source), "-o", str(self.output)], None)]
        for args, refusal in cases:
            with self.subTest(args=args):
                self.calls.clear(); self.output.unlink(missing_ok=True)
                _, record, scope = self.execute(args=args, write_objects=False,
                    action=lambda _: self.output.write_bytes(self.object_bytes))
                self.assertEqual(scope["native_code"], 0)
                self.assertEqual(self.output.read_bytes(), self.object_bytes)
                self.assertEqual(record["original_object_outputs"], [])
                self.assertFalse(record["original_object_bytes_retained"])
                if refusal is not None: self.assertIn(refusal, self.codes(record))

if __name__ == "__main__":
    unittest.main()
