"""Regression tests for the release MCP stdio smoke client."""

from __future__ import annotations

import importlib.util
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "smoke_ostadix_mcp.py"
ROOT = SCRIPT.parents[1]
CI_WORKFLOW = SCRIPT.parents[1] / ".github/workflows/ci.yml"
SPEC = importlib.util.spec_from_file_location("ostadix_mcp_smoke", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import failure is fatal
    raise RuntimeError(f"cannot import {SCRIPT}")
smoke = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = smoke
SPEC.loader.exec_module(smoke)


def frame(request_id: int, value: str) -> bytes:
    return (
        json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "result": {"value": value}},
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


class ResponseReaderTests(unittest.TestCase):
    def test_batched_frames_remain_available_after_first_response(self) -> None:
        reader = smoke.ResponseReader(io.BytesIO(frame(1, "first") + frame(2, "second")))
        self.assertEqual(reader.response(1, 0.5), {"value": "first"})
        self.assertEqual(reader.response(2, 0.5), {"value": "second"})
        reader.join(0.5)

    def test_ci_builds_every_binary_required_by_the_mcp_smoke(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        for required_binary in ("O", "o-cli", "olangc", "o-info", "o-link"):
            self.assertIn(
                f"--bin {required_binary}",
                workflow,
                f"MCP smoke requires the fixed local {required_binary} binary",
            )

    def test_catalog_schema_is_read_from_the_independent_engine(self) -> None:
        self.assertEqual(
            smoke._current_catalog_schema(ROOT),
            "ostadix.backend-catalog/v6",
        )
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"crates" / "ostadix-api" / "src"', source)
        self.assertNotIn('root / "src" / "backend_catalog.inc.rs"', source)

    def test_installed_layout_uses_explicit_runtime_and_information_paths(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--o-info", type=Path)', source)
        self.assertIn('parser.add_argument("--runtime-bin-dir", type=Path)', source)
        self.assertIn('parser.add_argument("--server-cwd", type=Path)', source)
        self.assertIn("wasm_mode = parser.add_mutually_exclusive_group()", source)
        self.assertIn(
            'wasm_mode.add_argument("--require-wasm", action="store_true")', source
        )
        self.assertIn(
            'wasm_mode.add_argument("--require-wasm-materialization", '
            'action="store_true")',
            source,
        )
        for release_binding in (
            "--wasm-release-manifest",
            "--wasm-release-artifact",
            "--wasm-source-tree",
            "--wasm-base-commit",
            "--wasm-source-archive-sha256",
        ):
            self.assertIn(release_binding, source)
        self.assertIn('environment["OSTADIX_O_INFO_BIN"]', source)
        self.assertIn('environment["PYTHONDONTWRITEBYTECODE"] = "1"', source)
        self.assertIn('environment.pop("A18_WORK", None)', source)
        self.assertIn("restricted_path.insert(0", source)
        self.assertIn("for index, path in enumerate(restricted_path)", source)
        self.assertIn('"name": "o_doctor"', source)
        self.assertIn('"name": "o_search_run"', source)
        self.assertIn('"source": "python^(', source)
        self.assertIn('result.get("structuredContent")', source)
        self.assertIn('"local_unified_front_door"', source)
        self.assertIn('"o-link"', source)
        self.assertIn("loaded a lifted bundle without executing", source)
        self.assertIn('"target": "wasm"', source)
        self.assertIn('wasm_output.read_bytes()[:4] != b"\\x00asm"', source)
        self.assertIn('"materialize_only"', source)
        self.assertIn("o_olangc schema omitted materialize_only", source)
        self.assertIn(
            "olangc: materialize-only target=wasm rust-target=wasm32-wasip1 ",
            source,
        )
        self.assertIn("cargo-invoked=false dir={materialize_project}", source)
        self.assertIn('(materialize_project / "target").exists()', source)
        self.assertIn("or materialize_output.exists()", source)
        self.assertIn(
            '(materialize_project / "src/program.O").read_bytes()', source
        )
        self.assertIn('"path": "examples/wasm_hello.O"', source)
        self.assertIn('root / "examples/wasm_hello.O"', source)
        self.assertIn(
            "MCP-materialized WASM project failed its release binding", source
        )
        self.assertIn("return wasm_materialization_evidence", source)
        self.assertIn(
            "ostadix-mcp o_olangc wasm materialization: PASS ", source
        )
        self.assertIn("ostadix-mcp o_olangc wasm artifact: PASS ", source)
        self.assertNotIn('prefix=".mcp-intent-smoke-", dir=root', source)
        self.assertNotIn(
            '"runtime-search-entry index=0 source=inherited:0 path=/usr/bin"',
            source,
        )

    def test_out_of_order_response_is_retained_by_id(self) -> None:
        reader = smoke.ResponseReader(io.BytesIO(frame(2, "second") + frame(1, "first")))
        self.assertEqual(reader.response(1, 0.5), {"value": "first"})
        self.assertEqual(reader.response(2, 0.5), {"value": "second"})
        reader.join(0.5)

    def test_protocol_error_is_reported(self) -> None:
        payload = b'{"jsonrpc":"2.0","id":7,"error":{"code":-1}}\n'
        reader = smoke.ResponseReader(io.BytesIO(payload))
        with self.assertRaisesRegex(smoke.SmokeError, "MCP request 7 failed"):
            reader.response(7, 0.5)
        reader.join(0.5)


class StructuredToolResultTests(unittest.TestCase):
    @staticmethod
    def result(value: object, **extra: object) -> dict[str, object]:
        return {
            "content": [{"type": "text", "text": json.dumps(value)}],
            **extra,
        }

    def test_text_only_clients_receive_the_same_job_object(self) -> None:
        value = {"job_id": "job-1", "state": "completed", "exit_code": 0}
        self.assertEqual(smoke._content_object(self.result(value)), value)
        self.assertEqual(
            smoke._content_object(self.result(value, structuredContent=value)), value
        )

    def test_disagreeing_structured_and_text_results_are_rejected(self) -> None:
        with self.assertRaisesRegex(smoke.SmokeError, "disagree"):
            smoke._content_object(
                self.result({"exit_code": 1}, structuredContent={"exit_code": 0})
            )

    def test_non_object_and_invalid_json_are_rejected(self) -> None:
        with self.assertRaisesRegex(smoke.SmokeError, "non-object"):
            smoke._content_object(self.result(["job-1"]))
        with self.assertRaisesRegex(smoke.SmokeError, "invalid JSON"):
            smoke._content_object({"content": [{"type": "text", "text": "not-json"}]})


class NativeExecuteResultTests(unittest.TestCase):
    @staticmethod
    def result(native: dict[str, object], **extra: object) -> dict[str, object]:
        success = native.get("ok") is True
        return {
            "job_id": "job-1",
            "state": "completed" if success else "failed",
            "exit_code": 0 if success else 1,
            "result": native,
            "stdout": {"text": json.dumps(native)},
            **extra,
        }

    def test_native_value_and_failure_preserve_exact_process_evidence(self) -> None:
        for native in (
            {"ok": True, "type": "text", "value": {"t": "text", "v": "answer"}},
            {"ok": False, "stage": "parse", "error": "unterminated block"},
        ):
            with self.subTest(native=native):
                self.assertEqual(smoke._native_execute_result(self.result(native)), native)

    def test_native_value_cannot_disagree_with_retained_stdout(self) -> None:
        with self.assertRaisesRegex(smoke.SmokeError, "disagrees with raw stdout"):
            smoke._native_execute_result(
                self.result({"ok": True}, stdout={"text": '{"ok": false}'})
            )

    def test_native_success_cannot_mask_failed_or_running_process(self) -> None:
        for extra in (
            {"exit_code": 1},
            {"exit_code": None},
            {"state": "running"},
        ):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(smoke.SmokeError, "process outcome"):
                    smoke._native_execute_result(self.result({"ok": True}, **extra))

    def test_failure_cannot_claim_successful_process(self) -> None:
        with self.assertRaisesRegex(smoke.SmokeError, "process outcome"):
            smoke._native_execute_result(self.result({"ok": False}, exit_code=0))

    def test_missing_identity_and_non_json_output_are_rejected(self) -> None:
        with self.assertRaisesRegex(smoke.SmokeError, "job identity"):
            smoke._native_execute_result(self.result({"ok": True}, job_id=None))
        with self.assertRaisesRegex(smoke.SmokeError, "not native JSON"):
            smoke._native_execute_result(
                self.result({"ok": True}, stdout={"text": "not-json"})
            )


class OneWorkerOverlapControlTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.source = "autonomous(batch(left_fixture, right_fixture))"
        for name, timestamp in (("left.ready", 1), ("right.ready", 2), ("right.finished", 3)):
            (self.workspace / name).write_text(str(timestamp))
        error = "Traceback (most recent call last):\nRuntimeError: unified-workers-did-not-overlap\n"
        native = {
            "ok": False, "type": "list",
            "value": {"t": "list", "v": [
                {"t": "error", "msg": error},
                {"t": "text", "v": {"encoding": "utf-8", "utf8": "right"}},
            ]},
            "failed_batch_members": [{"member": 0, "node": 2, "error": error}],
            "execution_evidence": {
                "schema": "ostadix.native-execution-evidence/v1", "execution_mode": "graph",
                "source_sha256": hashlib.sha256(self.source.encode()).hexdigest(),
                "source_intent_gate": {"verified": True},
            },
        }
        self.result = NativeExecuteResultTests.result(
            native, mode="admitted", signal=None, input={"cwd": str(self.workspace)}
        )
        plan = {"schema": "oexec.schedule-explanation/v2",
                "realizability": {"dispatch": "not-run", "selected_workers": 1}}
        self.plan = {"state": "completed", "exit_code": 0, "result": plan,
                     "stdout": {"text": json.dumps(plan)}, "input": {"cwd": str(self.workspace)}}

    def test_exact_typed_failure_and_bound_one_worker_context_are_accepted(self) -> None:
        smoke._verify_one_worker_overlap_control(self.result, self.plan, self.source, self.workspace)

    def test_arbitrary_errors_timeouts_and_wrong_context_are_rejected(self) -> None:
        mutations = (
            ("success", lambda r: r["result"].update(ok=True)),
            ("missing members", lambda r: r["result"].update(failed_batch_members=[])),
            ("wrong member", lambda r: r["result"]["failed_batch_members"][0].update(member=1)),
            ("wrong tagged value", lambda r: r["result"]["value"].update(v=[])),
            ("wrong cwd", lambda r: r["input"].update(cwd="/different/workspace")),
            ("wrong source", lambda r: r["result"]["execution_evidence"].update(source_sha256="0" * 64)),
            ("unadmitted", lambda r: r["result"]["execution_evidence"].update(source_intent_gate=None)),
            ("wrong execution mode", lambda r: r["result"]["execution_evidence"].update(execution_mode="serial")),
            ("signal", lambda r: r.update(signal=9)),
            ("timeout exit", lambda r: r.update(exit_code=124)),
            ("timeout state", lambda r: r.update(state="timed_out")),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                result = copy.deepcopy(self.result)
                mutate(result)
                result["stdout"]["text"] = json.dumps(result["result"])
                with self.assertRaises(smoke.SmokeError):
                    smoke._verify_one_worker_overlap_control(result, self.plan, self.source, self.workspace)
        for error in ("unrelated failure containing unified-workers-did-not-overlap",
                      "RuntimeError: unified-workers-did-not-overlap-extra\n"):
            with self.subTest(error=error):
                result = copy.deepcopy(self.result)
                result["result"]["failed_batch_members"][0]["error"] = error
                result["result"]["value"]["v"][0]["msg"] = error
                result["stdout"]["text"] = json.dumps(result["result"])
                with self.assertRaises(smoke.SmokeError):
                    smoke._verify_one_worker_overlap_control(result, self.plan, self.source, self.workspace)

    def test_missing_worker_plan_and_changed_planning_context_are_rejected(self) -> None:
        for name, mutate in (
            ("worker count", lambda p: p["result"]["realizability"].update(selected_workers=2)),
            ("dispatch", lambda p: p["result"]["realizability"].update(dispatch="ran")),
            ("cwd", lambda p: p["input"].update(cwd="/different/workspace")),
        ):
            with self.subTest(name=name):
                plan = copy.deepcopy(self.plan)
                mutate(plan)
                plan["stdout"]["text"] = json.dumps(plan["result"])
                with self.assertRaises(smoke.SmokeError):
                    smoke._verify_one_worker_overlap_control(self.result, plan, self.source, self.workspace)

    def test_missing_or_overlapping_backend_effects_are_rejected(self) -> None:
        (self.workspace / "left.finished").write_text("2")
        with self.assertRaises(smoke.SmokeError):
            smoke._verify_one_worker_overlap_control(self.result, self.plan, self.source, self.workspace)
        (self.workspace / "left.finished").unlink()
        (self.workspace / "left.ready").write_text("4")
        with self.assertRaises(smoke.SmokeError):
            smoke._verify_one_worker_overlap_control(self.result, self.plan, self.source, self.workspace)
        (self.workspace / "right.ready").unlink()
        with self.assertRaises(smoke.SmokeError):
            smoke._verify_one_worker_overlap_control(self.result, self.plan, self.source, self.workspace)


if __name__ == "__main__":
    unittest.main()
