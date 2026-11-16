import ast, hashlib, os, stat, sys, tempfile, types, unittest, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = "26788e75cfd6906193a759ecf1e207df7369b04adeeb1afe8931e754d514f540"
EXPECTED_BYTES = 252440
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
    if len(helpers) != 7:
        raise AssertionError("seven actual production helpers required")
    constants = [n for n in tree.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "ASM_SUFFIXES" for t in n.targets)]
    if len(constants) != 1:
        raise AssertionError("actual ASM_SUFFIXES definition required")
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
    def execute(self, args=None, sources=None, action=None, status=0, header=False, expected_capture=True):
        args = args if args is not None else ["-c", "-save-temps=obj", str(self.source), "-o", str(self.output)]
        event = {"id": "fixture-" + uuid.uuid4().hex, "argv": list(args), "response_files": [],
                 "compiler": {"fixture": True}, "frontend": {"fixture": True},
                 "build_environment": {"CPPFLAGS": "-DFIXTURE=1"}, "units": [], "capture_errors": []}
        scope, native_env = dict(self.namespace), {"SYNTHETIC_DECLARED_VALUE": "unchanged"}
        def run(argv, **kwargs):
            self.calls.append((argv, kwargs))
            self.assertEqual(argv, ["selected-original-compiler", *args])
            self.assertIs(kwargs["env"], native_env)
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
        reached = {"stage_copy_calls": 0, "stage_hash_calls": 0}
        original_copy = self.namespace["_assembly_capture_copy"]
        original_hash = self.namespace["_assembly_capture_hash_fd"]
        def copy_spy(context, source, name, role):
            if role == "stage-output-candidate":
                reached["stage_copy_calls"] += 1
            return original_copy(context, source, name, role)
        def hash_spy(descriptor):
            status = os.fstat(descriptor)
            if reached.get("stage_inode") == (status.st_dev, status.st_ino):
                reached["stage_hash_calls"] += 1
            return original_hash(descriptor)
        self.namespace["_assembly_capture_copy"] = copy_spy
        self.namespace["_assembly_capture_hash_fd"] = hash_spy
        data = b"written by reached fake constructor before exception"
        def action(scope):
            reached["context"] = scope["_assembly_action_capture"]
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
        record = reached["context"]["record"]
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

if __name__ == "__main__":
    unittest.main()
