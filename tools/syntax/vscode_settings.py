"""Preserve JSONC user settings while installing Ostadix's editor run actions."""

import json
import os
from pathlib import Path
import re
import shlex
import sys

RUN_NAME = "Ostadix: Run Current File"
EDITOR_DIRECTORIES = {
    "Visual Studio Code": "Code",
    "Visual Studio Code Insiders": "Code - Insiders",
    "Cursor": "Cursor",
    "VSCodium": "VSCodium",
}
TOKEN = re.compile(r'\s+|//[^\r\n]*|/\*[\s\S]*?\*/|"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"|[{}\[\]:,]|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null')


class Node:
    def __init__(self, start, end, value, children=None, trailing=False):
        self.start, self.end, self.value = start, end, value
        self.children = children
        self.trailing = trailing


def parse_jsonc(text):
    """Parse JSON with comments/trailing commas and retain value spans for edits."""
    tokens, offset = [], 1 if text.startswith("\ufeff") else 0
    while offset < len(text):
        match = TOKEN.match(text, offset)
        if not match:
            raise ValueError(f"Invalid JSONC at character {offset}; settings were not modified")
        token = match.group()
        if not token.isspace() and not token.startswith(("//", "/*")):
            tokens.append((token, offset, match.end()))
        offset = match.end()
    position = 0

    def take(expected=None):
        nonlocal position
        if position >= len(tokens) or (expected is not None and tokens[position][0] != expected):
            raise ValueError("Invalid JSONC structure; settings were not modified")
        item = tokens[position]
        position += 1
        return item

    def peek():
        return tokens[position][0] if position < len(tokens) else None

    def value():
        token, start, end = take()
        if token in ("{", "["):
            is_object = token == "{"
            close = "}" if is_object else "]"
            children = {} if is_object else []
            trailing = False
            while peek() != close:
                if is_object:
                    key_token, _, _ = take()
                    if not key_token.startswith('"'):
                        raise ValueError("JSONC object keys must be quoted")
                    key = json.loads(key_token)
                    if key in children:
                        raise ValueError(f"Duplicate JSONC key {key!r}; settings were not modified")
                    take(":")
                    children[key] = value()
                else:
                    children.append(value())
                if peek() != ",":
                    break
                take(",")
                trailing = peek() == close
            _, _, end = take(close)
            data = {key: node.value for key, node in children.items()} if is_object else [node.value for node in children]
            return Node(start, end, data, children, trailing)
        if token in ("}", "]", ":", ","):
            raise ValueError("Unexpected JSONC punctuation")
        return Node(start, end, json.loads(token))

    root = value()
    if position != len(tokens) or not isinstance(root.value, dict):
        raise ValueError("VS Code settings must contain one JSONC object")
    return root


class Settings:
    """Surgical value edits: unrelated comments, order and formatting stay intact."""
    def __init__(self, text):
        self.text = text if text.strip() else "{\n}\n"
        self.root = parse_jsonc(self.text)

    def node(self, path):
        node = self.root
        for key in path:
            if not isinstance(node.children, (dict, list)):
                raise ValueError(f"Expected a settings object/array at {path!r}")
            node = node.children[key]
        return node

    def replace(self, start, end, text):
        self.text = self.text[:start] + text + self.text[end:]
        self.root = parse_jsonc(self.text)

    def insert(self, path, value, key=None):
        node = self.node(path)
        if not isinstance(node.children, (dict, list)):
            raise ValueError(f"Expected a settings collection at {path!r}")
        # Add a separator before an existing line comment, never after it.
        children = list(node.children.values()) if isinstance(node.children, dict) else node.children
        if children and not node.trailing:
            self.replace(children[-1].end, children[-1].end, ",")
            node = self.node(path)
        close = node.end - 1
        line = self.text.rfind("\n", 0, close) + 1
        whitespace = self.text[line:close]
        insertion = line if not whitespace.strip() else close
        indent = whitespace if not whitespace.strip() else "  " * len(path)
        encoded = json.dumps(value, ensure_ascii=False, indent=2)
        if key is not None:
            encoded = json.dumps(key) + ": " + encoded
        encoded = ("\n" + indent + "  ").join(encoded.splitlines())
        prefix = "" if insertion > 0 and self.text[insertion - 1] == "\n" else "\n"
        suffix = "," if node.trailing else ""
        self.replace(insertion, insertion, prefix + indent + "  " + encoded + suffix + "\n" + (indent if insertion == close else ""))

    def set(self, path, value):
        parent = self.node(path[:-1])
        key = path[-1]
        if not isinstance(parent.children, dict):
            raise ValueError(f"Expected a settings object at {path[:-1]!r}")
        if key not in parent.children:
            self.insert(path[:-1], value, key)
        elif type(parent.children[key].value) is not type(value) or parent.children[key].value != value:
            node = parent.children[key]
            line = self.text.rfind("\n", 0, node.start) + 1
            indent = re.match(r'[ \t]*', self.text[line:node.start]).group()
            encoded = json.dumps(value, ensure_ascii=False, indent=2).replace("\n", "\n" + indent)
            self.replace(node.start, node.end, encoded)

    def object(self, path):
        parent = self.node(path[:-1])
        if not isinstance(parent.children, dict):
            raise ValueError(f"Expected a settings object at {path[:-1]!r}")
        if path[-1] not in parent.children:
            self.set(path, {})
        if not isinstance(self.node(path).value, dict):
            raise ValueError(f"Expected a settings object at {path!r}; settings were not modified")


def settings_path(label, binary, home, config, *, platform=None, environ=None):
    """Locate the default profile; respect explicit or adjacent portable data."""
    platform = sys.platform if platform is None else platform
    environ = os.environ if environ is None else environ
    if environ.get("VSCODE_PORTABLE"):
        return Path(environ["VSCODE_PORTABLE"]) / "user-data/User/settings.json"
    executable = Path(binary).resolve()
    if platform == "darwin":
        application = next((p for p in executable.parents if p.suffix == ".app"), None)
        portable_name = {"Visual Studio Code": "code-portable-data", "Visual Studio Code Insiders": "code-insiders-portable-data"}.get(label)
        portable = application.parent / portable_name if application and portable_name else None
        base = Path(home) / "Library/Application Support"
    else:
        portable = executable.parent.parent / "data"
        base = Path(environ.get("APPDATA", Path(home) / "AppData/Roaming")) if platform == "win32" else Path(config)
    if portable and portable.is_dir():
        return portable / "user-data/User/settings.json"
    return base / EDITOR_DIRECTORIES[label] / "User/settings.json"


def runtime_command(root, file_argument):
    root = Path(root).resolve()
    return " ".join([
        "/usr/bin/env", "-u NODE_OPTIONS", "-u VSCODE_INSPECTOR_OPTIONS",
        shlex.quote(f"O_LANG_ROOT={root}"),
        shlex.quote(f"O_BACKENDS_DIR={root / 'backends'}"),
        shlex.quote(str(root / "target/release/O")), file_argument,
        shlex.quote(str(root / "backends")),
    ])


def configure_settings(original, root):
    """Return updated POSIX settings; callers write only after every edit validates."""
    settings = Settings(original)
    settings.object(("launch",))
    launch = settings.node(("launch",)).value
    if "version" not in launch:
        settings.set(("launch", "version"), "0.2.0")
    if "configurations" not in launch:
        settings.set(("launch", "configurations"), [])
    configurations = settings.node(("launch", "configurations")).value
    if not isinstance(configurations, list):
        raise ValueError("launch.configurations must be an array; settings were not modified")
    matches = [i for i, item in enumerate(configurations) if isinstance(item, dict) and item.get("name") == RUN_NAME]
    if len(matches) > 1:
        raise ValueError(f"Multiple {RUN_NAME!r} configurations; settings were not modified")
    run = {
        "name": RUN_NAME, "type": "node-terminal", "request": "launch",
        "command": runtime_command(root, '"$OSTADIX_VSCODE_FILE"'),
        "cwd": "${fileDirname}", "noDebug": True,
        "autoAttachChildProcesses": False, "internalConsoleOptions": "neverOpen",
        "env": {"OSTADIX_VSCODE_FILE": "${file}"},
    }
    if matches:
        path = ("launch", "configurations", matches[0])
        for key, value in run.items():
            if key == "env":
                settings.object(path + (key,))
                settings.set(path + (key, "OSTADIX_VSCODE_FILE"), "${file}")
            else:
                settings.set(path + (key,), value)
    else:
        settings.insert(("launch", "configurations"), run)
    command = runtime_command(root, "$fullFileName")
    for name, keys in (("code-runner.executorMap", ("ostadix",)), ("code-runner.executorMapByFileExtension", (".O", ".olang"))):
        settings.object((name,))
        for key in keys:
            settings.set((name, key), command)
    for key in ("fileDirectoryAsCwd", "saveFileBeforeRun", "runInTerminal", "showRunIconInEditorTitleMenu"):
        # These options affect every Code Runner language, so retain explicit
        # user choices and supply defaults only when they have no preference.
        if "code-runner." + key not in settings.root.value:
            settings.set(("code-runner." + key,), True)
    return settings.text


def install_settings(installer, label, binary, root):
    if sys.platform == "win32":
        print(f"{label}: syntax installed; automatic Ostadix run settings currently require macOS/Linux (POSIX shell).")
        return
    target = settings_path(label, binary, installer.home, installer.config)
    # Disable universal-newline conversion so untouched CRLF spans stay intact.
    original = ""
    if target.exists():
        with target.open(encoding="utf-8", newline="") as stream:
            original = stream.read()
    installer.write(target, configure_settings(original, root))
    if not (Path(root) / "target/release/O").is_file():
        print(f"{label}: run settings target {root}/target/release/O; finish setup/build before running .O files.")
    print(f"{label}: select {RUN_NAME!r} in Run and Debug, or use Code Runner: Run Code if Code Runner is installed.")
