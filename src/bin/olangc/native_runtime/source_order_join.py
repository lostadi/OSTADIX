"""Two-stage original-action/fresh-unit consistency join (not admission).

Pre-capture commitments contain ORIGINAL unit IDs and action projections, never
predictions of UUIDs that the next capture will allocate. Post-capture resolution
matches the complete independently required action set, then translates an
independently supplied original occurrence sequence without sorting/deduplication.

This module does not authenticate a capture, generate the original link-order
oracle, qualify a frontend, import code, or establish provider closure. Its caller
must reconstruct/verify both captures and supply the independently required floor
and original order. It is an unintegrated shared-pipeline component. Multiple IR
units in one action need an original producer's stable unit selector; they remain
explicitly unsupported here, rather than being selected by CGU order or UUID.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re


class JoinError(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise JoinError(reason)


def _pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def decode(raw):
    require(type(raw) is bytes, "input must be exact bytes")
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              JoinError("nonfinite JSON number")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise JoinError("invalid JSON") from error


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(value, name):
    require(type(value) is str and value and value.strip() == value
            and not any(ord(c) < 32 for c in value), name)
    return value


def _pin(value):
    require(type(value) is dict, "artifact identity must be an object")
    identity(value.get("path"), "artifact path absent")
    require(type(value.get("bytes")) is int and value["bytes"] >= 0,
            "artifact length must be an integer")
    require(type(value.get("sha256")) is str and
            re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None,
            "artifact SHA-256 absent")
    return {k: value[k] for k in ("path", "bytes", "sha256")}


class Paths:
    """Explicit lexical namespace correspondence; no filesystem or retargeting.

    Only whole paths and the listed attached path-option spellings are mapped.
    Embedded root strings in macros, environment command strings, response-file
    contents, or unknown flag syntaxes reject instead of being normalized away.
    Paths outside supplied roots remain literal and therefore must match exactly.
    """
    def __init__(self, roots):
        require(type(roots) is dict, "root bindings must be an object")
        self.roots = []
        for alias, root in roots.items():
            require(type(alias) is str and re.fullmatch("[A-Za-z][A-Za-z0-9_]*", alias),
                    "invalid namespace alias")
            require(type(root) is str and root.startswith("/") and root != "/"
                    and posixpath.normpath(root) == root, "invalid namespace root")
            self.roots.append((alias, root))
        for index, (_, root) in enumerate(self.roots):
            for _, other in self.roots[index + 1:]:
                require(root != other and not root.startswith(other + "/")
                        and not other.startswith(root + "/"), "overlapping namespace roots")

    def path(self, value):
        require(type(value) is str and "\0" not in value, "path is not a string")
        for alias, root in self.roots:
            if value == root or value.startswith(root + "/"):
                require(posixpath.normpath(value) == value, "noncanonical mapped path")
                return {"root": alias, "relative": value[len(root):]}
        return value

    def token(self, value):
        # Empty arguments and whitespace have actual compiler semantics. Keep
        # them verbatim, rather than applying the identifier grammar to argv.
        require(type(value) is str and "\0" not in value, "command/environment token type")
        mapped = self.path(value)
        if type(mapped) is dict:
            return mapped
        for prefix in ("--sysroot=", "-isystem", "-iquote", "-I", "-L", "-B", "@"):
            if value.startswith(prefix) and len(value) > len(prefix):
                mapped = self.path(value[len(prefix):])
                if type(mapped) is dict:
                    return {"option": prefix, "path": mapped}
        require(not any(root in value for _, root in self.roots),
                "unmapped embedded namespace path")
        return value

    def artifact(self, value):
        result = _pin(value)
        result["path"] = self.path(result["path"])
        return result


def _tokens(values, paths):
    require(type(values) is list and values, "argv must be a nonempty array")
    return [paths.token(value) for value in values]


def _action(raw, roots):
    event = decode(raw)
    require(type(event) is dict, "compiler event must be an object")
    event_id = identity(event.get("id"), "compiler invocation identity absent")
    require(event.get("state") == "finished" and type(event.get("exit_code")) is int
            and event["exit_code"] == 0, "compiler action did not succeed")
    require(event.get("capture_errors") == [], "compiler capture has errors")
    paths = Paths(roots)
    units = event.get("units")
    require(type(units) is list and len(units) == 1,
            "action needs a stable producer selector for multiple/absent units")
    unit = units[0]
    require(type(unit) is dict, "unit must be an object")
    unit_id = identity(unit.get("id"), "unit identity absent")
    require(type(unit.get("replay_exit_code")) is int and unit["replay_exit_code"] == 0,
            "implementation IR production did not succeed")
    require(unit.get("kind") == event.get("kind"), "unit/producer kind differs")
    source = _pin(unit.get("source"))
    sources = event.get("sources")
    require(type(sources) is list and sources and source in [_pin(s) for s in sources],
            "unit source lacks an owning invocation source")
    ir = unit.get("ir")
    _pin(ir)
    for field in ("format", "target_triple", "data_layout"):
        identity(ir.get(field), "IR profile field absent: " + field)
    # All additional IR profile metadata remains in the key. Only the actual
    # artifact location/length/hash are evidence, not action identity.
    ir_profile = {k: v for k, v in ir.items() if k not in ("path", "bytes", "sha256")}
    replay = unit.get("replay_argv")
    require(type(replay) is list and replay, "IR producer argv absent")
    replay_key = []
    for index, token in enumerate(replay):
        if index and replay[index - 1] == "-o":
            require(token == ir["path"], "IR output argv differs from captured unit")
            replay_key.append({"unit_artifact": "ir"})
        elif index and replay[index - 1] == "-MF":
            require(type(token) is str and token.endswith(".d")
                    and posixpath.dirname(token) == posixpath.dirname(ir["path"]),
                    "IR dependency output is not in the owning unit directory")
            replay_key.append({"unit_artifact": "dependency"})
        else:
            replay_key.append(paths.token(token))
    require(replay.count("-o") == 1, "IR output option must appear once")
    frontend = event.get("frontend")
    _pin(frontend)
    dependencies = unit.get("dependencies")
    require(type(dependencies) is list,
            "original included-source inventory absent")
    environment = event.get("build_environment")
    require(type(environment) is dict and all(type(k) is str for k in environment),
            "build environment absent")
    step = event.get("build_step")
    require(type(step) is dict and set(step) == {"name", "index"}
            and type(step["index"]) is int and step["index"] >= 0, "build-step binding absent")
    identity(step["name"], "build-step name absent")
    responses = event.get("response_files")
    outputs = event.get("outputs")
    require(type(responses) is list and type(outputs) is list and outputs,
            "response/native-output inventory absent")
    projection = {
        "kind": identity(event.get("kind"), "producer kind absent"),
        "producer": event.get("producer"),
        "driver_kind": identity(event.get("driver_kind"), "driver kind absent"),
        "compiler": paths.token(identity(event.get("compiler"), "compiler path absent")),
        "capture_worker": paths.artifact(event.get("capture_worker")),
        "cwd": paths.path(event.get("cwd")),
        "argv": _tokens(event.get("argv"), paths),
        "expanded_argv": _tokens(event.get("expanded_argv"), paths),
        "environment": {k: paths.token(v) for k, v in environment.items()},
        "build_step": step,
        "frontend": {**paths.artifact(frontend), "version": frontend.get("version"),
                     "llvm_version": frontend.get("llvm_version")},
        "sources": [paths.artifact(s) for s in sources],
        "response_files": [paths.artifact(s) for s in responses],
        "native_outputs": [{"path": paths.path(_pin(s)["path"]),
                            "artifact_kind": s.get("artifact_kind")} for s in outputs],
        "unit": {"kind": unit["kind"], "producer": unit.get("producer"),
                 "source": paths.artifact(source), "ir_profile": ir_profile,
                 "replay_argv": replay_key,
                 "dependencies": [paths.artifact(s) for s in dependencies],
                 "other_metadata": {k: v for k, v in unit.items() if k not in
                     {"id", "kind", "producer", "source", "ir", "replay_argv",
                      "replay_exit_code", "dependencies"}}},
    }
    return {"action_key": digest(encode(projection)), "projection": projection,
            "original_invocation_id": event_id, "original_unit_id": unit_id,
            "event_sha256": digest(raw), "event_bytes": len(raw)}


def commit(original_events, required_unit_ids, roots):
    """Commit original evidence before a new capture allocates any IDs."""
    require(type(original_events) is list and original_events, "original actions absent")
    require(type(required_unit_ids) is list and required_unit_ids, "independent unit floor absent")
    for unit_id in required_unit_ids:
        identity(unit_id, "required original unit identity absent")
    require(len(set(required_unit_ids)) == len(required_unit_ids), "duplicate required unit")
    actions = [_action(raw, roots) for raw in original_events]
    require(len({a["action_key"] for a in actions}) == len(actions), "ambiguous original action")
    require(len({a["original_invocation_id"] for a in actions}) == len(actions),
            "duplicate original invocation")
    require(len({a["original_unit_id"] for a in actions}) == len(actions)
            and {a["original_unit_id"] for a in actions} == set(required_unit_ids),
            "complete original required unit floor differs")
    return encode({"schema": "ocore-original-action-commitment-v1",
                   "required_unit_ids": required_unit_ids, "actions": actions})


def resolve(committed_raw, original_events, required_unit_ids, original_occurrences,
            fresh_events, original_roots, fresh_roots):
    """Recompute original commitment, then join exact fresh action keys.

    Occurrences are an independently selected ORIGINAL sequence, not capture
    chronology. Repetitions are meaningful and preserved. This function cannot
    establish the authenticity of that input sequence or a complete link graph.
    """
    require(committed_raw == commit(original_events, required_unit_ids, original_roots),
            "pre-capture original commitment changed")
    require(set(original_roots) == set(fresh_roots), "namespace alias set differs")
    require(type(original_occurrences) is list and original_occurrences
            and all(type(u) is str for u in original_occurrences)
            and set(original_occurrences) == set(required_unit_ids),
            "original occurrence sequence omits or adds a required unit")
    require(type(fresh_events) is list and fresh_events, "fresh action set absent")
    original = decode(committed_raw)["actions"]
    fresh = [_action(raw, fresh_roots) for raw in fresh_events]
    require(len({a["action_key"] for a in fresh}) == len(fresh), "ambiguous fresh action")
    require(len({a["original_invocation_id"] for a in fresh}) == len(fresh)
            and len({a["original_unit_id"] for a in fresh}) == len(fresh),
            "duplicate fresh invocation or unit")
    by_key = {a["action_key"]: a for a in fresh}
    require(set(by_key) == {a["action_key"] for a in original},
            "fresh source/command/profile/dependency action set differs")
    mapping = {a["original_unit_id"]: by_key[a["action_key"]]["original_unit_id"]
               for a in original}
    return {
        "schema": "ocore-original-action-fresh-unit-join-v1",
        "commitment_sha256": digest(committed_raw),
        "unit_mapping": mapping,
        "original_occurrences": original_occurrences,
        "fresh_occurrences": [mapping[u] for u in original_occurrences],
        "fresh_capture_order": [a["original_unit_id"] for a in fresh],
        "fresh_event_evidence": [{k: a[k] for k in
                                  ("event_sha256", "event_bytes", "original_invocation_id",
                                   "original_unit_id", "action_key")} for a in fresh],
        "consistency_join_complete": True,
        "capture_admitted": False,
        "original_order_producer_qualified": False,
        "provider_closure_qualified": False,
        "runtime_qualified": False,
    }


# The prior API remains caller-owned consistency only. This additive API seals
# the selected raw original order before fresh results. The production Rust
# consumer must hold this commitment before staging and independently authenticate
# both captures and the externally selected policy; bytes alone are not authority.
def _original_occurrences(required_unit_ids, occurrences):
    require(type(occurrences) is list and occurrences
            and all(type(u) is str for u in occurrences)
            and set(occurrences) == set(required_unit_ids),
            "original occurrence sequence omits or adds a required unit")
    return list(occurrences)


def commit_order(original_events, required_unit_ids, roots, original_occurrences,
                 original_order_raw):
    require(type(original_order_raw) is bytes and original_order_raw,
            "original order must be a nonempty held byte buffer")
    policy = decode(original_order_raw)
    require(type(policy) is dict and policy.get("schema") == "ocore-original-provider-order-v3",
            "original order policy schema differs")
    action_commitment = commit(original_events, required_unit_ids, roots)
    occurrences = _original_occurrences(required_unit_ids, original_occurrences)
    return encode({"schema": "ocore-original-ordered-action-commitment-v1",
                   "action_commitment": decode(action_commitment),
                   "original_occurrences": occurrences,
                   "original_order": {"bytes": len(original_order_raw),
                                      "sha256": digest(original_order_raw)}})


def resolve_order(committed_raw, original_events, required_unit_ids, original_occurrences,
                  fresh_events, original_roots, fresh_roots, original_order_raw):
    require(type(committed_raw) is bytes and committed_raw == commit_order(
        original_events, required_unit_ids, original_roots, original_occurrences, original_order_raw),
        "pre-stage original action/order commitment changed")
    sealed = decode(committed_raw)
    result = resolve(encode(sealed["action_commitment"]), original_events, required_unit_ids,
                     sealed["original_occurrences"], fresh_events, original_roots, fresh_roots)
    result["schema"] = "ocore-original-ordered-action-fresh-unit-join-v1"
    result["order_commitment_sha256"] = digest(committed_raw)
    result["original_order"] = sealed["original_order"]
    return result


def bridge(request):
    """Checked-buffer compiler bridge; no files/processes/admission in Python."""
    require(type(request) is dict, "bridge request must be an object")
    common = {"schema", "operation", "original_events", "required_unit_ids",
              "original_roots", "original_occurrences", "original_order_raw"}
    require(request.get("schema") == "Main-source-order-helper-request/v1", "bridge request schema")
    operation = request.get("operation")
    require(operation in {"commit", "resolve"}, "unsupported bridge operation")
    fields = common if operation == "commit" else common | {"commitment", "fresh_events", "fresh_roots"}
    require(set(request) == fields, "bridge request fields differ")
    def buffers(key):
        values = request[key]
        require(type(values) is list and all(type(v) is str for v in values), "event buffers must be JSON strings")
        return [v.encode("utf-8", "strict") for v in values]
    require(type(request["original_order_raw"]) is str, "order buffer must be a JSON string")
    original = buffers("original_events")
    order_raw = request["original_order_raw"].encode("utf-8", "strict")
    if operation == "commit":
        return {"commitment": commit_order(original, request["required_unit_ids"], request["original_roots"],
                                          request["original_occurrences"], order_raw).decode("utf-8")}
    require(type(request["commitment"]) is str, "commitment buffer must be a JSON string")
    return resolve_order(request["commitment"].encode("utf-8", "strict"), original,
                         request["required_unit_ids"], request["original_occurrences"],
                         buffers("fresh_events"), request["original_roots"], request["fresh_roots"], order_raw)
