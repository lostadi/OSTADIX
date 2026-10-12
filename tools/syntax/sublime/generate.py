#!/usr/bin/env python3
"""Export the shipped Code grammar closure as native TextMate XML for Sublime."""

import argparse
import importlib.util
import json
from pathlib import Path
import plistlib
import uuid

HERE = Path(__file__).resolve().parent
CODE = HERE.parent / "vscode"
spec = importlib.util.spec_from_file_location("ostadix_textmate_export", HERE.parent / "textmate_export.py")
textmate_export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(textmate_export)


def outputs():
    package = json.loads((CODE / "package.json").read_text())
    result = {}
    for entry in package["contributes"]["grammars"]:
        path = (CODE / entry["path"]).resolve()
        grammar = json.loads(path.read_text())
        scope = grammar["scopeName"]
        grammar["uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, "ostadix-syntax:" + scope)).upper()
        # Foreign grammars are included only by O's scope references. Installing
        # O support must not replace the editor's normal .py/.js/etc associations.
        grammar.pop("fileTypes", None)
        grammar.pop("firstLineMatch", None)
        if scope == "source.ostadix":
            grammar["fileTypes"] = ["O", "olang"]
            name = "Ostadix"
        else:
            name = scope.replace("/", "_")
        result[HERE / f"{name}.tmLanguage"] = plistlib.dumps(textmate_export.xml_safe(grammar))
    # Preserve the upstream redistributor's attribution alongside the exports.
    for path in (CODE / "vendor").rglob("*"):
        if path.is_file() and ("LICENSE" in path.name.upper() or "NOTICE" in path.name.upper()
                              or path.name in {"manifest.json", "provenance.json"}):
            relative = path.relative_to(CODE / "vendor")
            result[HERE / "licenses" / relative] = path.read_bytes()
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = outputs()
    stale = []
    for path, content in result.items():
        if args.check:
            if not path.exists() or path.read_bytes() != content:
                stale.append(str(path))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    expected = {path for path in result if path.suffix == ".tmLanguage"}
    extra = set(HERE.glob("*.tmLanguage")) - expected
    if args.check:
        if stale or extra:
            raise SystemExit("Stale Sublime grammar exports; run tools/syntax/sublime/generate.py")
        print(f"PASS: {len(expected)} Sublime/TextMate grammar exports match the shipped grammar closure")
    else:
        for path in extra:
            path.unlink()
        print(f"Exported {len(expected)} Sublime/TextMate grammars")
