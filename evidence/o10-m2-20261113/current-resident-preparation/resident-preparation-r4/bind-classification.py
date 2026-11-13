#!/usr/bin/env python3
"""Bind current M2 classified paths to completed component/context receipts; runs no tests."""
import argparse, ast, hashlib, json, re, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode = True

PREP = Path(__file__).resolve().parent
PINS = json.loads((PREP / "pins.json").read_text())
ROOT = Path(PINS["root"])
sys.path.insert(0, str(ROOT / "scripts"))
import verify_o10_m1 as shared

def need(value, message):
    if not value:
        raise ValueError(message)

def model_inventory(source):
    tree = ast.parse(source)
    method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                  and n.name == shared.CLASSIFIED_METHOD.split(".")[-1])
    loops = [n for n in ast.walk(method) if isinstance(n, ast.For)]
    configs = ast.literal_eval(next(n.iter for n in loops
                               if isinstance(n.target, ast.Name) and n.target.id == "configuration"))
    expression = next(n.iter for n in loops
                      if isinstance(n.target, ast.Name) and n.target.id == "scenario")
    inventory = []
    for qualification, services in configs:
        scenarios = eval(compile(ast.Expression(expression), "<hashed scenario inventory>", "eval"),
                         {"__builtins__": {}, "range": range, "list": list}, {"services": services})
        need(isinstance(scenarios, list) and len(scenarios) == len(set(scenarios))
             and all(type(n) is int for n in scenarios), "scenario inventory malformed")
        inventory.append({"qualification": qualification, "services": services, "scenario_ids": scenarios})
    return inventory

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component-result", type=Path, required=True)
    parser.add_argument("--unit-result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    need(not args.output.exists() and not args.output.is_symlink(), "output must be new")
    args.output.mkdir(parents=True)
    result = {"schema": "ostadix.o10-m2-classification-binding/v1", "ok": False,
              "full_milestone_qualified": False, "started_unix": time.time(),
              "scope": "Source-classified native host-register-model paths plus separately logged actual QEMU EL2 context tests; no resident 60-second VM claim"}
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                  text=True, check=True).stdout.strip()
        need(revision == PINS["revision"], "HEAD changed")
        component = shared.document(args.component_result)
        unit = shared.document(args.unit_result)
        for name, record in (("component", component), ("unit", unit)):
            need(record.get("source_revision") == record.get("mcp_release") == revision,
                 name + " revision mismatch")
            need(record.get("source_unchanged") is True and not record.get("skips")
                 and not record.get("error"), name + " failed, skipped or changed")
        need(component.get("component_ok") is True and component.get("failures") == 0
             and component.get("errors") == 0, "component did not pass")
        need(unit.get("ok") is True, "ordinary unit receipt did not pass")
        model_sources = {n: wanted for n, wanted in PINS["sources"].items() if n.endswith(".oc")}
        for name, wanted in model_sources.items():
            need(component.get("source_sha256", {}).get(name) == wanted == shared.digest(ROOT / name),
                 "current compiled model dependency not bound: " + name)
        component_log_path = args.component_result.parent / "tests.log"
        component_log = component_log_path.read_text()
        need(shared.unittest_summary(component_log, "current component") == component["tests_run"],
             "component count/log mismatch")
        mapping = shared.document(PREP / "classification-template.json")
        need(mapping["implementation_revision"] == revision, "template revision mismatch")
        mapping.pop("prepared_only", None)
        template_path = args.output / "classification.json"
        template_path.write_text(json.dumps(mapping, indent=2) + "\n")
        shared.validate_classification(ROOT, template_path, revision, component, component_log)
        # A completed hashed method proves the whole source-defined loop. The
        # component log retains one unittest method, not per-case traces.
        inventory = model_inventory((ROOT / shared.CLASSIFIED_TEST).read_text())
        targeted = unit.get("targeted", {})
        need(targeted.get("returncode") == 0 and targeted.get("timed_out") is False
             and targeted.get("skipped") is False, "targeted context command incomplete")
        context_log_path = Path(targeted["log"]["path"])
        need(shared.digest(context_log_path) == targeted["log"]["sha256"], "context log hash changed")
        context_log = context_log_path.read_text()
        shared.unittest_summary(context_log, "current targeted")
        context_name = "tests/test_unified_world_context.py"
        context_tree = ast.parse((ROOT / context_name).read_text())
        expected = set()
        for cls in context_tree.body:
            if isinstance(cls, ast.ClassDef):
                expected.update("test_unified_world_context." + cls.name + "." + n.name
                                for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_"))
        observed = set()
        for line in context_log.splitlines():
            match = re.fullmatch(r"test_\w+ \((?:tests\.)?(test_unified_world_context\.[\w.]+)\) \.\.\. ok", line)
            if match:
                observed.add(match.group(1))
        need(expected and observed == expected, "actual EL2 context methods omitted or unsuccessful")
        for name in (context_name, "ocore/kernel/aarch64/unified_world/monitor.S"):
            need(unit.get("source_sha256", {}).get(name) == shared.digest(ROOT / name),
                 "current context source not bound: " + name)
        result.update(ok=True, source_revision=revision, mcp_release=revision,
                      classification=shared.identity(template_path),
                      component=shared.identity(args.component_result),
                      component_log=shared.identity(component_log_path),
                      unit=shared.identity(args.unit_result), context_log=shared.identity(context_log_path),
                      native_model_sources=model_sources,
                      native_model_method=shared.CLASSIFIED_METHOD, native_model_method_tests=1,
                      source_defined_model_invocations=sum(len(r["scenario_ids"]) for r in inventory),
                      source_defined_model_configurations=inventory,
                      model_count_scope="Derived from current hashed loop after its complete actual unittest method passed; per-scenario subprocess traces are not separately retained",
                      actual_qemu_el2_context_tests=len(observed), actual_qemu_el2_context_methods=sorted(observed))
    except BaseException as error:
        result["error"] = type(error).__name__ + ": " + str(error)
    result["finished_unix"] = time.time()
    (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"ok": result["ok"], "result": str(args.output / "result.json"),
                      "error": result.get("error")}))
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
