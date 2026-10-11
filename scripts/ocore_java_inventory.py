#!/usr/bin/env python3
"""Inventory original Java method bodies and check verified O-core coverage.

This is a class-file structure reader, not a JVM bytecode verifier or compiler.
Inventory completion never implies that any method has been lowered.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import zipfile

FORMAT = "ocore-java-inventory-v1"
EXPORT_FORMAT = "ocore-java-method-exports-v1"
IDENTITY_FIELDS = (
    "module", "loader_namespace", "class_name", "method_name", "descriptor",
    "class_sha256", "code_sha256",
)
ROOT = Path(__file__).resolve().parents[1]


class InventoryError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Reader:
    def __init__(self, data: bytes, label: str):
        self.data = data
        self.offset = 0
        self.label = label

    def read(self, size: int) -> bytes:
        end = self.offset + size
        if size < 0 or end > len(self.data):
            raise InventoryError(f"{self.label}: truncated at byte {self.offset}")
        result = self.data[self.offset:end]
        self.offset = end
        return result

    def number(self, size: int) -> int:
        return int.from_bytes(self.read(size), "big")

    def u1(self) -> int:
        return self.number(1)

    def u2(self) -> int:
        return self.number(2)

    def u4(self) -> int:
        return self.number(4)

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise InventoryError(f"{self.label}: trailing bytes at {self.offset}")


def modified_utf8(data: bytes) -> str:
    """Decode JVM modified UTF-8, including CESU-8 surrogate pairs."""
    units: list[int] = []
    index = 0
    while index < len(data):
        first = data[index]
        index += 1
        if 1 <= first <= 0x7F:
            units.append(first)
        elif 0xC0 <= first <= 0xDF:
            if index >= len(data) or data[index] & 0xC0 != 0x80:
                raise InventoryError("invalid modified UTF-8 continuation")
            value = ((first & 0x1F) << 6) | (data[index] & 0x3F)
            index += 1
            if value < 0x80 and not (first == 0xC0 and value == 0):
                raise InventoryError("overlong modified UTF-8")
            units.append(value)
        elif 0xE0 <= first <= 0xEF:
            if index + 1 >= len(data) or any(byte & 0xC0 != 0x80 for byte in data[index:index + 2]):
                raise InventoryError("invalid modified UTF-8 continuation")
            value = ((first & 0x0F) << 12) | ((data[index] & 0x3F) << 6) | (data[index + 1] & 0x3F)
            index += 2
            if value < 0x800:
                raise InventoryError("overlong modified UTF-8")
            units.append(value)
        else:
            raise InventoryError("invalid modified UTF-8 leading byte")
    encoded = b"".join(unit.to_bytes(2, "big") for unit in units)
    return encoded.decode("utf-16-be", errors="surrogatepass")


def method_descriptor(value: str) -> None:
    def field(index: int, allow_void: bool = False) -> int:
        start = index
        while index < len(value) and value[index] == "[":
            index += 1
        dimensions = index - start
        if dimensions > 255 or index >= len(value):
            raise InventoryError(f"invalid method descriptor {value!r}")
        kind = value[index]
        if kind in "BCDFIJSZ" or (kind == "V" and allow_void and dimensions == 0):
            return index + 1
        if kind == "L":
            end = value.find(";", index + 1)
            name = value[index + 1:end] if end >= 0 else ""
            if name and not any(char in name for char in ".;[") and all(name.split("/")):
                return end + 1
        raise InventoryError(f"invalid method descriptor {value!r}")

    if not value.startswith("("):
        raise InventoryError(f"invalid method descriptor {value!r}")
    index = 1
    slots = 0
    while index < len(value) and value[index] != ")":
        start = index
        index = field(index)
        slots += 2 if value[start] in "JD" else 1
    if index >= len(value) or slots > 255 or field(index + 1, True) != len(value):
        raise InventoryError(f"invalid method descriptor {value!r}")


def parse_class(data: bytes, label: str = "class", max_major: int = 69) -> dict:
    reader = Reader(data, label)
    if reader.u4() != 0xCAFEBABE:
        raise InventoryError(f"{label}: invalid class magic")
    minor, major = reader.u2(), reader.u2()
    if not 45 <= major <= max_major or (major >= 56 and minor not in {0, 65535}):
        raise InventoryError(f"{label}: unsupported class version {major}.{minor}")
    count = reader.u2()
    if count == 0:
        raise InventoryError(f"{label}: empty constant pool")
    pool: list[tuple | None] = [None] * count
    index = 1
    while index < count:
        tag = reader.u1()
        if tag == 1:
            pool[index] = (tag, modified_utf8(reader.read(reader.u2())))
        elif tag in {3, 4}:
            pool[index] = (tag, reader.read(4))
        elif tag in {5, 6}:
            pool[index] = (tag, reader.read(8))
            index += 1
            if index >= count:
                raise InventoryError(f"{label}: missing long/double constant-pool slot")
        elif tag in {7, 8, 16, 19, 20}:
            pool[index] = (tag, reader.u2())
        elif tag in {9, 10, 11, 12, 17, 18}:
            pool[index] = (tag, reader.u2(), reader.u2())
        elif tag == 15:
            pool[index] = (tag, reader.u1(), reader.u2())
        else:
            raise InventoryError(f"{label}: unsupported constant-pool tag {tag}")
        if (tag in {15, 16, 18} and major < 51) or (tag in {19, 20} and major < 53) or (tag == 17 and major < 55):
            raise InventoryError(f"{label}: constant-pool tag {tag} invalid for class version")
        index += 1

    def cp(at: int, tags: set[int]) -> tuple:
        if not 0 < at < len(pool) or pool[at] is None or pool[at][0] not in tags:
            raise InventoryError(f"{label}: invalid constant-pool reference {at}; expected {sorted(tags)}")
        return pool[at]  # type: ignore[return-value]

    def utf(at: int) -> str:
        return cp(at, {1})[1]

    def named(at: int, tag: int) -> str:
        return utf(cp(at, {tag})[1])

    for item in pool[1:]:
        if item is None:
            continue
        tag = item[0]
        if tag in {7, 8, 16, 19, 20}:
            cp(item[1], {1})
        elif tag in {9, 10, 11}:
            cp(item[1], {7})
            cp(item[2], {12})
        elif tag == 12:
            cp(item[1], {1})
            cp(item[2], {1})
        elif tag in {17, 18}:
            cp(item[2], {12})
        elif tag == 15:
            kind = item[1]
            if not 1 <= kind <= 9:
                raise InventoryError(f"{label}: invalid method-handle kind")
            tags = {9} if kind <= 4 else {11} if kind == 9 else {10, 11} if kind in {6, 7} and major >= 52 else {10}
            cp(item[2], tags)

    def attributes(stream: Reader) -> list[tuple[str, bytes]]:
        result = []
        for _ in range(stream.u2()):
            name = utf(stream.u2())
            result.append((name, stream.read(stream.u4())))
        return result

    access, class_index, super_index = reader.u2(), reader.u2(), reader.u2()
    class_name = named(class_index, 7)
    if not class_name or any(char in class_name for char in ".;[") or not all(class_name.split("/")):
        raise InventoryError(f"{label}: invalid class name")
    if super_index:
        cp(super_index, {7})
    for _ in range(reader.u2()):
        cp(reader.u2(), {7})
    for _ in range(reader.u2()):
        reader.u2()
        utf(reader.u2())
        utf(reader.u2())
        attributes(reader)

    methods = []
    seen: set[tuple[str, str]] = set()
    for _ in range(reader.u2()):
        flags, name, descriptor = reader.u2(), utf(reader.u2()), utf(reader.u2())
        if not name or any(char in name for char in ".;[/") or (name not in {"<init>", "<clinit>"} and any(char in name for char in "<>")):
            raise InventoryError(f"{label}: invalid method name {name!r}")
        method_descriptor(descriptor)
        if name == "<init>" and not descriptor.endswith(")V"):
            raise InventoryError(f"{label}: constructor must return void")
        if name == "<clinit>" and (descriptor != "()V" or (major >= 51 and not flags & 0x0008)):
            raise InventoryError(f"{label}: invalid class initializer")
        if (name, descriptor) in seen:
            raise InventoryError(f"{label}: duplicate method {name}{descriptor}")
        seen.add((name, descriptor))
        attrs = attributes(reader)
        bodies = [payload for attr, payload in attrs if attr == "Code"]
        abstract, native = bool(flags & 0x0400), bool(flags & 0x0100)
        if abstract and flags & (0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0100 | 0x0800):
            raise InventoryError(f"{label}: invalid abstract method flags")
        kind = "abstract" if abstract else "native" if native else "code"
        if len(bodies) != (1 if kind == "code" else 0):
            raise InventoryError(f"{label}: {name}{descriptor}: {kind} method has invalid Code count {len(bodies)}")
        method = {"method_name": name, "descriptor": descriptor, "access_flags": flags,
                  "kind": kind, "code_sha256": "", "code_length": 0}
        if bodies:
            body = Reader(bodies[0], f"{label}:{name}{descriptor}:Code")
            method["max_stack"], method["max_locals"] = body.u2(), body.u2()
            length = body.u4()
            if not 0 < length < 65536:
                raise InventoryError(f"{label}: invalid code length {length}")
            code = body.read(length)
            method.update(code_sha256=sha256(code), code_length=length,
                          code_attribute_sha256=sha256(bodies[0]))
            handlers = []
            for _ in range(body.u2()):
                start, end, handler, catch = body.u2(), body.u2(), body.u2(), body.u2()
                if not 0 <= start < end <= length or not handler < length:
                    raise InventoryError(f"{label}: invalid exception-handler range")
                if catch:
                    cp(catch, {7})
                handlers.append({"start": start, "end": end, "handler": handler, "catch_type": named(catch, 7) if catch else None})
            method["exception_handlers"] = handlers
            nested = attributes(body)
            if sum(attr == "StackMapTable" for attr, _ in nested) > 1:
                raise InventoryError(f"{label}: duplicate StackMapTable")
            body.finish()
        methods.append(method)

    class_attrs = attributes(reader)
    reader.finish()
    module = None
    module_attrs = [payload for name, payload in class_attrs if name == "Module"]
    if len(module_attrs) > 1 or bool(access & 0x8000) != bool(module_attrs) or (module_attrs and class_name != "module-info"):
        raise InventoryError(f"{label}: invalid module-info/Module attribute")
    if module_attrs:
        stream = Reader(module_attrs[0], f"{label}:Module")
        module_name = named(stream.u2(), 19)
        module_flags, version = stream.u2(), stream.u2()
        if version:
            utf(version)
        requires = []
        for _ in range(stream.u2()):
            dependency, dep_flags, dep_version = named(stream.u2(), 19), stream.u2(), stream.u2()
            if dep_version:
                utf(dep_version)
            requires.append({"module": dependency, "flags": dep_flags})
        for _ in range(2):  # exports, opens
            for _ in range(stream.u2()):
                cp(stream.u2(), {20})
                stream.u2()
                for _ in range(stream.u2()):
                    cp(stream.u2(), {19})
        for _ in range(stream.u2()):
            cp(stream.u2(), {7})
        for _ in range(stream.u2()):
            cp(stream.u2(), {7})
            implementations = stream.u2()
            if implementations == 0:
                raise InventoryError(f"{label}: empty module service providers")
            for _ in range(implementations):
                cp(stream.u2(), {7})
        stream.finish()
        module = {"name": module_name, "flags": module_flags, "requires": requires}
    bootstrap_attrs = [payload for name, payload in class_attrs if name == "BootstrapMethods"]
    if len(bootstrap_attrs) > 1:
        raise InventoryError(f"{label}: duplicate BootstrapMethods")
    bootstrap_count = 0
    if bootstrap_attrs:
        stream = Reader(bootstrap_attrs[0], f"{label}:BootstrapMethods")
        bootstrap_count = stream.u2()
        for _ in range(bootstrap_count):
            cp(stream.u2(), {15})
            for _ in range(stream.u2()):
                cp(stream.u2(), {3, 4, 5, 6, 7, 8, 15, 16, 17})
        stream.finish()
    if any(item and item[0] in {17, 18} and item[1] >= bootstrap_count for item in pool):
        raise InventoryError(f"{label}: invalid bootstrap-method reference")
    return {"class_name": class_name, "class_sha256": sha256(data), "major": major,
            "minor": minor, "access_flags": access, "methods": methods, "module": module}


def safe_entry(name: str) -> None:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name or str(path) != name:
        raise InventoryError(f"invalid archive entry {name!r}")


def manifest_attributes(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    current: str | None = None
    try:
        lines = data.decode("utf-8").replace("\r\n", "\n").split("\n")
    except UnicodeError as exc:
        raise InventoryError("invalid UTF-8 JAR manifest") from exc
    for line in lines:
        if not line:
            break
        if line.startswith(" ") and current is not None:
            result[current] += line[1:]
            continue
        if ": " not in line:
            raise InventoryError("invalid JAR manifest")
        key, value = line.split(": ", 1)
        current = key.lower()
        if current in result:
            raise InventoryError("duplicate JAR manifest attribute")
        result[current] = value
    return result


def input_entries(path: Path, java_feature: int) -> tuple[list[tuple[str, bytes]], dict]:
    if path.is_dir():
        entries = []
        for item in sorted(path.rglob("*")):
            if item.is_symlink():
                raise InventoryError(f"directory input contains symlink: {item}")
            if item.is_file():
                entries.append((item.relative_to(path).as_posix(), item.read_bytes()))
        digest = sha256(b"".join(name.encode() + b"\0" + bytes.fromhex(sha256(data)) for name, data in entries))
        return entries, {"path": str(path.resolve()), "kind": "directory", "sha256": digest}
    data = path.read_bytes()
    source = {"path": str(path.resolve()), "sha256": sha256(data)}
    if path.suffix == ".class":
        source["kind"] = "class"
        return [(path.name, data)], source
    is_jmod = path.suffix == ".jmod"
    if is_jmod and data[:4] != b"JM\x01\x00":
        raise InventoryError(f"{path}: invalid JMOD header")
    source["kind"] = "jmod" if is_jmod else "jar"
    try:
        archive = zipfile.ZipFile(path)
        with archive:
            files: dict[str, bytes] = {}
            for info in archive.infolist():
                if info.is_dir():
                    continue
                safe_entry(info.filename)
                if info.filename in files:
                    raise InventoryError(f"{path}: duplicate archive entry {info.filename}")
                files[info.filename] = archive.read(info)
    except (zipfile.BadZipFile, RuntimeError) as exc:
        raise InventoryError(f"{path}: invalid archive: {exc}") from exc
    if is_jmod:
        return [(name.removeprefix("classes/"), payload) for name, payload in sorted(files.items()) if name.startswith("classes/")], source
    attrs = manifest_attributes(files.get("META-INF/MANIFEST.MF", b""))
    multi_release = attrs.get("multi-release", "false").lower() == "true"
    selected: dict[str, tuple[int, bytes]] = {}
    for name, payload in files.items():
        match = re.fullmatch(r"META-INF/versions/([0-9]+)/(.+)", name)
        if match:
            version = int(match[1])
            if not multi_release or version < 9 or version > java_feature:
                continue
            name = match[2]
        elif name.startswith("META-INF/versions/"):
            continue
        else:
            version = 0
        if name not in selected or version > selected[name][0]:
            selected[name] = (version, payload)
    return [(name, item[1]) for name, item in sorted(selected.items())], source


def inventory(inputs: list[tuple[str, Path]], loader_namespace: str = "boot", java_feature: int = 25) -> dict:
    if not inputs or not loader_namespace or not 1 <= java_feature <= 25:
        raise InventoryError("inputs, loader namespace and supported Java feature are required")
    sources, classes, methods, resources, modules = [], [], [], [], []
    seen_classes: set[tuple[str, str]] = set()
    seen_modules: set[str] = set()
    for module_name, path in sorted(inputs, key=lambda item: item[0]):
        if not module_name or module_name in seen_modules:
            raise InventoryError(f"empty or duplicate module input: {module_name!r}")
        seen_modules.add(module_name)
        entries, source = input_entries(path, java_feature)
        source["module"] = module_name
        sources.append(source)
        descriptor = None
        class_count = 0
        for entry, data in entries:
            if not entry.endswith(".class"):
                resources.append({"module": module_name, "path": entry, "sha256": sha256(data), "size": len(data)})
                continue
            parsed = parse_class(data, f"{path}!{entry}", max_major=java_feature + 44)
            class_name = parsed["class_name"]
            if path.suffix != ".class" and entry != class_name + ".class":
                raise InventoryError(f"class name/path mismatch: {entry} vs {class_name}")
            key = (module_name, class_name)
            if key in seen_classes:
                raise InventoryError(f"duplicate class {module_name}:{class_name}")
            seen_classes.add(key)
            class_count += 1
            if parsed["module"]:
                descriptor = parsed["module"]
                if descriptor["name"] != module_name:
                    raise InventoryError(f"module name mismatch: {module_name} vs {descriptor['name']}")
            summary = {key: value for key, value in parsed.items() if key not in {"methods", "module"}}
            summary.update(module=module_name, loader_namespace=loader_namespace, path=entry)
            classes.append(summary)
            for method in parsed["methods"]:
                identity = {"module": module_name, "loader_namespace": loader_namespace,
                            "class_name": class_name, "method_name": method["method_name"],
                            "descriptor": method["descriptor"], "class_sha256": parsed["class_sha256"],
                            "code_sha256": method["code_sha256"]}
                methods.append({"identity": identity, **{key: value for key, value in method.items() if key not in {"method_name", "descriptor", "code_sha256"}}})
        if class_count == 0:
            raise InventoryError(f"module {module_name}: no class files")
        modules.append(descriptor or {"name": module_name, "flags": None, "requires": []})
    methods.sort(key=lambda item: identity_key(item["identity"]))
    counts = {kind: sum(method["kind"] == kind for method in methods) for kind in ("code", "native", "abstract")}
    missing_modules = sorted({requirement["module"] for module in modules for requirement in module["requires"]} - seen_modules)
    return {"format": FORMAT, "java_feature": java_feature, "loader_namespace": loader_namespace,
            "sources": sources, "modules": modules, "classes": classes, "methods": methods,
            "resources": resources,
            "summary": {"modules": len(modules), "classes": len(classes), "methods": len(methods), **counts,
                        "bytecode_bytes": sum(method["code_length"] for method in methods)},
            "declared_dependency_closure": {"complete": not missing_modules, "missing_modules": missing_modules},
            "lowering_complete": False}


def identity_key(identity: object, require_code: bool = False) -> tuple[str, ...]:
    if not isinstance(identity, dict) or set(identity) != set(IDENTITY_FIELDS):
        raise InventoryError("invalid managed method identity fields")
    if not all(isinstance(identity[field], str) and (bool(identity[field]) or field == "code_sha256") for field in IDENTITY_FIELDS):
        raise InventoryError("invalid managed method identity values")
    for field in ("class_sha256", "code_sha256"):
        value = identity[field]
        if (field == "class_sha256" or require_code or value) and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise InventoryError(f"invalid managed method {field}")
    method_descriptor(identity["descriptor"])
    return tuple(identity[field] for field in IDENTITY_FIELDS)


def load_json(path: Path, data: bytes | None = None) -> dict:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise InventoryError(f"{path}: duplicate JSON field {key}")
            result[key] = value
        return result
    try:
        text = (path.read_bytes() if data is None else data).decode("utf-8")
        value = json.loads(text, object_pairs_hook=unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise InventoryError(f"{path}: expected JSON object")
    return value


def write_json(path: Path | None, value: dict) -> None:
    text = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    if path is None:
        print(text, end="")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def module_argument(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or not name or not path:
        raise argparse.ArgumentTypeError("input must be MODULE=CLASS_DIRECTORY/JMOD/JAR/CLASS")
    return name, Path(path)


def extract_runtime(java: Path, output: Path, roots: list[str], all_modules: bool = False) -> dict:
    helper = ROOT / "tools/ocore-runtime/java/ExtractRuntimeImage.java"
    java = java.resolve(strict=True)
    command = [str(java), str(helper), str(output), *( ["--all"] if all_modules else roots)]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode:
        raise InventoryError(f"runtime image extraction failed ({completed.returncode}): {completed.stderr.strip()}")
    module_names = (output / "modules.txt").read_text(encoding="utf-8").splitlines()
    properties = dict(line.split("=", 1) for line in (output / "runtime.properties").read_text(encoding="utf-8").splitlines())
    version = properties["java.runtime.version"]
    if not re.match(r"25\.0\.4\.1(?:\+|$)", version):
        raise InventoryError(f"runtime image version mismatch: expected 25.0.4.1, got {version}")
    result = inventory([(name, output / name) for name in module_names])
    image = Path(properties["java.home"]) / "lib/modules"
    result["runtime_image"] = {**properties, "module_image_sha256": sha256(image.read_bytes()),
                               "java_executable_sha256": sha256(java.read_bytes()),
                               "extractor_sha256": sha256(helper.read_bytes()),
                               "roots": roots if not all_modules else ["--all"],
                               "command": command, "host_tool_only": True}
    if not result["declared_dependency_closure"]["complete"]:
        raise InventoryError("extracted runtime image has an unresolved module dependency")
    return result


def validate_inventory(value: dict) -> dict[tuple[str, ...], dict]:
    if value.get("format") != FORMAT or not isinstance(value.get("methods"), list) or not value["methods"]:
        raise InventoryError("invalid or empty Java inventory")
    closure = value.get("declared_dependency_closure")
    if not isinstance(closure, dict) or closure.get("complete") is not True or closure.get("missing_modules") != []:
        raise InventoryError("Java inventory has unresolved declared module dependencies")
    methods = {}
    for method in value["methods"]:
        if not isinstance(method, dict) or method.get("kind") not in {"code", "native", "abstract"}:
            raise InventoryError("invalid method inventory record")
        key = identity_key(method.get("identity"), require_code=method["kind"] == "code")
        if key in methods:
            raise InventoryError(f"duplicate inventory method identity {key}")
        if method["kind"] != "code" and key[-1]:
            raise InventoryError("native/abstract declaration cannot have a bytecode body hash")
        methods[key] = method
    return methods


def verified_module(path: Path, verifier: Path) -> tuple[dict, dict]:
    """Generate a fresh receipt using the real verifier on immutable input bytes."""
    original = path.read_bytes()
    digest = sha256(original)
    verifier_digest = sha256(verifier.read_bytes())
    with tempfile.TemporaryDirectory(prefix="ocore-java-verify-") as temp:
        staged = Path(temp) / "module.json"
        receipt_path = Path(temp) / "receipt.json"
        staged.write_bytes(original)
        command = [str(verifier), str(staged), "--verify-native", "--receipt", str(receipt_path)]
        process = subprocess.run(command, capture_output=True, text=True)
        if process.returncode:
            raise InventoryError(f"native module verification failed for {path}: {process.stderr.strip()}")
        if not receipt_path.is_file():
            raise InventoryError(f"verifier produced no verification receipt for {path}")
        receipt = load_json(receipt_path)
        if (receipt.get("format") != "ocore-native-verification-v1" or
                receipt.get("module_sha256") != digest or receipt.get("verifier") != "ocore-native-v1" or
                receipt.get("verified") is not True):
            raise InventoryError(f"invalid/mismatched verification receipt for {path}")
        if staged.read_bytes() != original:
            raise InventoryError("native module bytes changed during verification")
        module = load_json(staged)
    if sha256(verifier.read_bytes()) != verifier_digest:
        raise InventoryError("verifier executable changed during verification")
    if module.get("format") != "ocore-native-module-v1" or not isinstance(module.get("functions"), list):
        raise InventoryError(f"invalid native module schema: {path}")
    return module, {"path": str(path.resolve()), "module_sha256": digest, "receipt": receipt,
                    "verifier_executable_sha256": verifier_digest}


def compare_inventory(value: dict, module_paths: list[Path], verifier: Path,
                      bindings: dict | None = None) -> dict:
    expected = validate_inventory(value)
    if not module_paths:
        raise InventoryError("at least one verified native module is required")
    verifier = verifier.resolve(strict=True)
    if not verifier.is_file() or not os.access(verifier, os.X_OK):
        raise InventoryError("verifier must be an executable file")
    definitions: dict[tuple[str, ...], tuple[str, str]] = {}
    managed_declarations: set[tuple[str, ...]] = set()
    provider_definitions: set[tuple[str, str]] = set()
    modules, receipts = [], []
    layout = None
    seen_digests: set[str] = set()
    for path in module_paths:
        module, evidence = verified_module(path, verifier)
        digest = evidence["module_sha256"]
        if digest in seen_digests:
            raise InventoryError("duplicate native module input")
        seen_digests.add(digest)
        target = module.get("target")
        if not isinstance(target, dict):
            raise InventoryError("native module is missing target layout")
        if layout is not None and target != layout:
            raise InventoryError("compare each target realization separately; module target layouts differ")
        layout = target
        modules.append(module)
        receipts.append(evidence)
        for function in module["functions"]:
            if not isinstance(function, dict) or not isinstance(function.get("name"), str):
                raise InventoryError("invalid native function record")
            entry = function.get("entry")
            body = entry is not None
            if body and (type(entry) is not int or entry < 0 or not function.get("blocks")):
                raise InventoryError("native function has no concrete body")
            if body:
                provider_definitions.add((digest, function["name"]))
            identity = function.get("managed_method")
            if identity is None:
                continue
            key = identity_key(identity, require_code=True)
            if body:
                if key in definitions:
                    raise InventoryError(f"duplicate exported method definition {key}")
                definitions[key] = (digest, function["name"])
            else:
                managed_declarations.add(key)

    code_expected = {key for key, method in expected.items() if method["kind"] == "code"}
    missing = sorted(code_expected - definitions.keys())
    unexpected = sorted(definitions.keys() - code_expected)
    if missing or unexpected:
        raise InventoryError(f"method body coverage mismatch: missing={len(missing)} unexpected={len(unexpected)}; "
                             f"missing identities={missing[:8]}; unexpected identities={unexpected[:8]}")
    unresolved_managed = managed_declarations - definitions.keys()
    if unresolved_managed:
        raise InventoryError(f"unresolved managed method declarations: {sorted(unresolved_managed)[:8]}")
    native_expected = {key for key, method in expected.items() if method["kind"] == "native"}
    native_bound: set[tuple[str, ...]] = set()
    if bindings is not None:
        if bindings.get("format") != EXPORT_FORMAT or not isinstance(bindings.get("native_bindings"), list):
            raise InventoryError("invalid native method binding manifest")
        for binding in bindings["native_bindings"]:
            if not isinstance(binding, dict) or set(binding) != {"method", "provider_module_sha256", "provider_symbol"}:
                raise InventoryError("invalid native method binding fields")
            key = identity_key(binding["method"])
            if (not isinstance(binding["provider_module_sha256"], str) or
                    not re.fullmatch(r"[0-9a-f]{64}", binding["provider_module_sha256"]) or
                    not isinstance(binding["provider_symbol"], str) or not binding["provider_symbol"]):
                raise InventoryError("invalid native binding provider identity")
            provider = (binding["provider_module_sha256"], binding["provider_symbol"])
            if key not in native_expected or key in native_bound:
                raise InventoryError("unexpected or duplicate native method binding")
            if provider not in provider_definitions:
                raise InventoryError(f"native binding provider has no verified definition: {provider}")
            native_bound.add(key)
    if native_bound != native_expected:
        raise InventoryError(f"unresolved native methods: {sorted(native_expected - native_bound)[:8]}")
    return {"format": "ocore-java-method-coverage-v1", "target": layout,
            "code_methods": len(code_expected), "native_bindings": len(native_bound),
            "abstract_declarations": sum(method["kind"] == "abstract" for method in expected.values()),
            "exact_body_inventory_complete": True, "verification": receipts,
            "semantic_equivalence_verified": False, "runtime_complete": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    scan = commands.add_parser("inventory", help="read complete class/method inventories without running methods")
    scan.add_argument("--input", action="append", type=module_argument, required=True)
    scan.add_argument("--loader-namespace", default="boot")
    scan.add_argument("--java-feature", type=int, default=25)
    scan.add_argument("--output", type=Path)
    image = commands.add_parser("runtime-image", help="extract and inventory pinned installed Java25.0.4.1 module closure")
    image.add_argument("--java", type=Path, required=True)
    image.add_argument("--module", action="append", default=[])
    image.add_argument("--all-modules", action="store_true")
    image.add_argument("--output-dir", type=Path, required=True)
    image.add_argument("--output", type=Path)
    compare = commands.add_parser("compare", help="require exact method coverage and fresh native verifier receipts")
    compare.add_argument("--inventory", type=Path, required=True)
    compare.add_argument("--native-module", action="append", type=Path, required=True)
    compare.add_argument("--native-bindings", type=Path)
    compare.add_argument("--verifier", type=Path, required=True)
    compare.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "inventory":
            result = inventory(args.input, args.loader_namespace, args.java_feature)
        elif args.action == "runtime-image":
            if args.all_modules and args.module:
                raise InventoryError("choose explicit module roots or all modules")
            result = extract_runtime(args.java, args.output_dir, args.module or ["jdk.compiler"], args.all_modules)
        else:
            if args.output is not None:
                protected = [args.inventory, args.verifier, *args.native_module]
                if args.native_bindings:
                    protected.append(args.native_bindings)
                if args.output.resolve() in {path.resolve() for path in protected}:
                    raise InventoryError("coverage output must not overwrite an input or verifier")
                if args.output.exists():
                    old = load_json(args.output)
                    if old.get("format") != "ocore-java-method-coverage-v1":
                        raise InventoryError("existing coverage output is not a method-coverage receipt")
                    # A failing recheck must not retain a previous successful receipt.
                    args.output.unlink()
            inventory_bytes = args.inventory.read_bytes()
            value = load_json(args.inventory, inventory_bytes)
            # Recompute the complete inventory from its original inputs. A shrunk or
            # stale JSON method list must not turn an incomplete export into success.
            refreshed = inventory([(source["module"], Path(source["path"])) for source in value.get("sources", [])],
                                  value.get("loader_namespace", ""), value.get("java_feature", 0))
            for key in ("sources", "modules", "classes", "methods", "resources", "summary", "declared_dependency_closure"):
                if value.get(key) != refreshed[key]:
                    raise InventoryError(f"stale or altered Java inventory field: {key}")
            result = compare_inventory(value, args.native_module, args.verifier,
                                       load_json(args.native_bindings) if args.native_bindings else None)
            result["inventory_sha256"] = sha256(inventory_bytes)
        write_json(args.output, result)
        return 0
    except (InventoryError, OSError) as exc:
        print(f"Java inventory failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
