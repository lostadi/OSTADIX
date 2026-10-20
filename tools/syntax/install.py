#!/usr/bin/env python3
"""Install highlighting for available editors, preserving user configuration."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import importlib.util
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
import uuid

SOURCE = Path(__file__).resolve().parent
BEGIN = "# >>> Ostadix syntax highlighting >>>"
END = "# <<< Ostadix syntax highlighting <<<"
COMPONENTS = ("vscode", "nano", "bat", "vim", "nvim", "emacs", "sublime", "textmate", "cat")
DEFAULT_COMPONENTS = tuple(component for component in COMPONENTS if component not in {"cat", "textmate"})
CODE_EDITORS = (
    ("code", "Visual Studio Code", "Visual Studio Code.app"),
    ("code-insiders", "Visual Studio Code Insiders", "Visual Studio Code - Insiders.app"),
    ("cursor", "Cursor", "Cursor.app"),
    ("codium", "VSCodium", "VSCodium.app"),
)


class Unavailable(RuntimeError):
    """A supported editor is absent; this is a normal installation skip."""


def use_login_user():
    """Drop sudo/doas privileges before touching the login user's editor files."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return True
    import pwd
    account = None
    for key in ("SUDO_USER", "DOAS_USER"):
        name = os.environ.get(key)
        if name and name != "root":
            try:
                account = pwd.getpwnam(name)
                break
            except KeyError:
                pass
    if account is None:
        for key in ("SUDO_UID", "PKEXEC_UID"):
            try:
                account = pwd.getpwuid(int(os.environ[key]))
                break
            except (KeyError, ValueError):
                pass
    if account is None or account.pw_uid == 0:
        print("SKIP editor support: running as root without an identified login user; run the syntax installer as your editor user.")
        return False
    home = Path(account.pw_dir)
    for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "ZDOTDIR"):
        value = os.environ.get(key)
        if value:
            path = Path(value)
            try:
                owned = path.is_relative_to(home) or path.stat().st_uid == account.pw_uid
            except OSError:
                owned = path.is_relative_to(home)
            if not owned:
                os.environ.pop(key, None)
    os.environ.update(HOME=str(home), USER=account.pw_name, LOGNAME=account.pw_name)
    os.environ["PATH"] = str(home / ".local/bin") + os.pathsep + os.environ.get("PATH", "")
    os.initgroups(account.pw_name, account.pw_gid)
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    print(f"Editor support user: {account.pw_name} ({home})")
    return True


def managed_span(original, comment="#"):
    begin, end = BEGIN.replace("#", comment, 1), END.replace("#", comment, 1)
    if begin not in original and end not in original:
        return None
    if original.count(begin) != 1 or original.count(end) != 1:
        raise ValueError("Ambiguous Ostadix config markers; refusing to overwrite")
    start = original.index(begin)
    finish = original.index(end, start) + len(end)
    if original[finish:finish + 1] == "\n":
        finish += 1
    return start, finish


def managed_block(original, content, comment="#"):
    """Replace our block only; retain all unrelated settings verbatim."""
    begin, end = BEGIN.replace("#", comment, 1), END.replace("#", comment, 1)
    block = f"{begin}\n{content.rstrip()}\n{end}\n"
    span = managed_span(original, comment)
    if span is None:
        return original + ("\n" if original and not original.endswith("\n") else "") + block
    start, finish = span
    return original[:start] + block + original[finish:]


class Installer:
    def __init__(self, *, dry_run=False, check=False):
        self.home = Path.home()
        self.config = Path(os.environ.get("XDG_CONFIG_HOME", self.home / ".config"))
        self.data = Path(os.environ.get("XDG_DATA_HOME", self.home / ".local/share")) / "ostadix/syntax"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        self.backups = self.data / "backups" / stamp
        self.dry_run = dry_run
        self.check = check

    def command(self, arguments):
        if self.dry_run or self.check:
            print(f"[{'CHECK' if self.check else 'DRY'}] {shlex.join(map(str, arguments))}")
            return
        subprocess.run(arguments, check=True)

    def code_editors(self):
        editors = []
        seen = set()
        for name, label, application in CODE_EDITORS:
            binary = shutil.which(name)
            if not binary and sys.platform == "darwin":
                for directory in (Path("/Applications"), self.home / "Applications"):
                    candidate = directory / application / "Contents/Resources/app/bin" / name
                    if candidate.is_file() and os.access(candidate, os.X_OK):
                        binary = str(candidate)
                        break
            # Snap launchers are a multicall executable: resolving both `code`
            # and `code-insiders` reaches /usr/bin/snap, but they are two apps.
            invocation = os.path.abspath(binary) if binary else None
            if binary and invocation not in seen:
                editors.append((label, binary))
                seen.add(invocation)
        return editors

    def available(self, component):
        if component == "vscode":
            return bool(self.code_editors())
        if component == "bat":
            return bool(shutil.which("bat") or shutil.which("batcat"))
        if component == "sublime":
            return bool(self.sublime_directories())
        if component in {"cat", "textmate"}:
            return True  # Explicit shell adapter / manual grammar export only.
        binary = shutil.which(component)
        return bool(binary and (component != "nano" or "pico" not in Path(binary).resolve().name.lower()))

    def write(self, target, data, executable=False):
        target = Path(target).expanduser()
        if isinstance(data, str):
            data = data.encode()
        if self.dry_run or self.check:
            print(f"[{'CHECK' if self.check else 'DRY'}] write {target}" + (" (executable)" if executable else ""))
            return
        # Respect a user's symlinked dotfile by updating its destination.
        target = target.resolve()
        if target.exists() and target.read_bytes() == data:
            if executable:
                target.chmod((target.stat().st_mode & 0o777) | 0o111)
            print(f"Unchanged: {target}")
            return
        mode = 0o755 if executable else 0o644
        if target.exists():
            backup = self.backups / str(target).lstrip("/")
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup)
            mode = target.stat().st_mode & 0o777
            if executable:
                mode |= 0o111
            print(f"Backup: {backup}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as stream:
            stream.write(data)
            temporary = Path(stream.name)
        temporary.chmod(mode)
        temporary.replace(target)
        print(f"Installed: {target}")

    def configure(self, target, content, comment="#"):
        original = target.read_text() if target.exists() else ""
        self.write(target, managed_block(original, content, comment))

    def bat(self):
        binary = shutil.which("bat") or shutil.which("batcat")
        if not binary:
            raise Unavailable("bat/batcat is not installed")
        if self.dry_run:
            print(f"[DRY] query {binary} --config-dir; install bat syntax in its reported syntaxes directory")
            for source in sorted((SOURCE / "bat").glob("*.sublime-syntax")):
                print(f"[DRY] copy {source} to <bat --config-dir>/syntaxes/{source.name}")
            self.command([binary, "cache", "--build"])
            return
        else:
            directory = Path(subprocess.check_output([binary, "--config-dir"], text=True).strip())
        for source in sorted((SOURCE / "bat").glob("*.sublime-syntax")):
            self.write(directory / "syntaxes" / source.name, source.read_bytes())
        self.command([binary, "cache", "--build"])

    def nano(self):
        binary = shutil.which("nano")
        # macOS /usr/bin/nano is Pico; --version starts its editor.
        if not binary or "pico" in Path(binary).resolve().name:
            raise Unavailable("GNU nano is not installed; Pico cannot load nanorc syntax")
        if self.dry_run:
            print(f"[DRY] verify GNU nano: {binary} --version")
        else:
            version = subprocess.check_output([binary, "--version"], text=True, timeout=10)
            if "GNU nano" not in version:
                raise Unavailable(f"not GNU nano: {binary}")
        directory = self.config / "nano/syntax"
        includes = []
        for source in sorted((SOURCE / "nano").glob("*.nanorc")):
            target = directory / source.name
            self.write(target, source.read_bytes())
            includes.append(f'include "{target}"')
        # Nano reads the first existing user config in this order.
        candidates = [self.home / ".nanorc", self.config / "nano/nanorc", self.home / ".config/nano/nanorc"]
        config = next((p for p in candidates if p.exists()), self.home / ".nanorc")
        self.configure(config, "\n".join(includes))

    def vim(self):
        runtime = self.home / ("vimfiles" if os.name == "nt" else ".vim")
        self.vim_runtime(runtime, "Vim")
        candidates = [self.home / ".vimrc", runtime / "vimrc", self.home / "_vimrc"]
        config = next((path for path in candidates if path.is_file()), None)
        if config:
            self.activate_vim(config)

    def nvim(self):
        runtime = self.config / "nvim"
        self.vim_runtime(runtime, "Neovim")
        candidates = [runtime / "init.lua", runtime / "init.vim"]
        config = next((path for path in candidates if path.is_file()), None)
        if config:
            self.activate_vim(config, lua=config.suffix == ".lua")

    def vim_runtime(self, directory, label):
        for kind in ("ftdetect", "syntax"):
            if not (SOURCE / "vim" / kind / "ostadix.vim").is_file():
                raise RuntimeError(f"missing required Vim asset: {kind}/ostadix.vim")
        for kind in ("ftdetect", "syntax"):
            for source in sorted((SOURCE / "vim" / kind).rglob("*.vim")):
                if ".template." not in source.name:
                    target = directory / kind / source.relative_to(SOURCE / "vim" / kind)
                    if source.name != "ostadix.vim" and target.exists():
                        print(f"Preserving existing {label} language syntax: {target}")
                        continue
                    self.write(target, source.read_bytes())
        for source in sorted((SOURCE / "vim").rglob("*")):
            if source.is_file() and self.support_notice(source):
                self.write(directory / "ostadix-notices" / source.relative_to(SOURCE / "vim"), source.read_bytes())
        print(f"{label}: Ostadix runtime installed.")

    def activate_vim(self, config, lua=False):
        if os.environ.get("VIMINIT"):
            print("VIMINIT controls editor initialization; enable filetype and syntax there if needed.")
            return
        original = config.read_text()
        comment = "--" if lua else '"'
        lines = [line for line in original.splitlines() if not line.lstrip().startswith(comment)]
        source = "\n".join(lines)
        pattern = r"\b(?:syn(?:tax)?\s+(?:off|disable)|filet(?:ype)?(?:\s+(?:plugin|indent))*\s+off)\b"
        if re.search(pattern, source, flags=re.MULTILINE | re.IGNORECASE):
            span = managed_span(original, comment)
            if span:
                self.write(config, original[:span[0]] + original[span[1]:])
            print(f"Preserved explicit filetype/syntax disable in {config}.")
            return
        content = "vim.cmd('filetype on')\nvim.cmd('syntax enable')" if lua else "filetype on\nsyntax enable"
        self.configure(config, content, comment)

    def emacs(self):
        source = SOURCE / "emacs/ostadix-mode.el"
        target = self.config / "ostadix/syntax/ostadix-mode.el"
        self.write(target, source.read_bytes())
        for source in sorted((SOURCE / "emacs/vendor").rglob("*")):
            if source.is_file() and (source.suffix == ".el" or self.support_notice(source)):
                self.write(target.parent / "vendor" / source.relative_to(SOURCE / "emacs/vendor"), source.read_bytes())
        candidates = [self.home / ".emacs", self.home / ".emacs.el", self.home / ".emacs.d/init.el", self.config / "emacs/init.el"]
        config = next((path for path in candidates if path.exists()), self.config / "emacs/init.el" if (self.config / "emacs").is_dir() else self.home / ".emacs.d/init.el")
        content = f"(load {json.dumps(str(target), ensure_ascii=False)} nil t)"
        self.configure(config, content, ";;")

    def sublime_directories(self):
        if sys.platform == "darwin":
            base = self.home / "Library/Application Support"
            candidates = [base / name / "Packages" for name in ("Sublime Text", "Sublime Text 3")]
        elif os.name == "nt":
            base = Path(os.environ.get("APPDATA", self.home / "AppData/Roaming"))
            candidates = [base / name / "Packages" for name in ("Sublime Text", "Sublime Text 3")]
        else:
            candidates = [self.config / name / "Packages" for name in ("sublime-text", "sublime-text-3")]
        existing = [path for path in candidates if path.parent.is_dir()]
        if existing:
            return existing
        if shutil.which("subl") or shutil.which("sublime_text"):
            return candidates[:1]
        return []

    def sublime(self):
        directories = self.sublime_directories()
        if not directories:
            raise Unavailable("no Sublime Text executable or existing profile was found")
        source = SOURCE / "sublime"
        files = sorted(path for path in source.rglob("*") if path.is_file() and (path.suffix == ".tmLanguage" or self.support_notice(path)))
        if not files:
            raise RuntimeError(f"Sublime Text syntax assets are missing: {source}")
        for directory in directories:
            for path in files:
                self.write(directory / "Ostadix" / path.relative_to(source), path.read_bytes())

    def textmate(self):
        spec = importlib.util.spec_from_file_location("ostadix_textmate_export", SOURCE / "textmate_export.py")
        export = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(export)
        bundle = self.data / "textmate/Ostadix.tmbundle"
        identity = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/lostadi/ostadix-BM/tools/syntax")).upper()
        info = {"name": "Ostadix", "uuid": identity, "description": "Ostadix orchestration with nested foreign-language highlighting"}
        self.write(bundle / "info.plist", plistlib.dumps(info))
        vscode = SOURCE / "vscode"
        package = json.loads((vscode / "package.json").read_text())
        sources = sorted({vscode / grammar["path"] for grammar in package["contributes"]["grammars"]})
        for source in sources:
            if not source.resolve().is_relative_to(vscode.resolve()):
                raise RuntimeError(f"grammar path is outside the packaged extension: {source}")
            grammar = json.loads(source.read_text())
            if not isinstance(grammar, dict) or "scopeName" not in grammar:
                continue
            grammar.setdefault("uuid", str(uuid.uuid5(uuid.NAMESPACE_URL, "ostadix-syntax:" + grammar["scopeName"])).upper())
            if grammar["scopeName"] == "source.ostadix":
                grammar["fileTypes"] = ["O", "olang"]
            else:
                grammar.pop("fileTypes", None)
                grammar.pop("firstLineMatch", None)
            name = "Ostadix" if grammar["scopeName"] == "source.ostadix" else grammar["scopeName"].replace("/", "_")
            self.write(bundle / "Syntaxes" / f"{name}.tmLanguage", plistlib.dumps(export.xml_safe(grammar)))
        for source in sorted((vscode / "vendor").rglob("*")):
            if source.is_file() and source not in sources and self.support_notice(source):
                self.write(bundle / "Vendor" / source.relative_to(vscode / "vendor"), source.read_bytes())
        license = SOURCE.parents[1] / "LICENSE"
        if license.is_file():
            self.write(bundle / "Vendor/Ostadix-LICENSE", license.read_bytes())
        print(f"TextMate bundle: {bundle}; import it explicitly in editors with TextMate bundle support.")

    @staticmethod
    def support_notice(path):
        name = path.name.upper()
        return any(word in name for word in ("LICENSE", "NOTICE", "COPYING", "PROVENANCE")) or path.suffix.lower() in {".md", ".txt", ".json"}

    def cat(self):
        target = self.config / "ostadix/syntax/ostadix-cat.zsh"
        self.write(target, (SOURCE / "terminal/ostadix-cat.zsh").read_bytes())
        self.write(self.home / ".local/bin/ocat", (SOURCE / "terminal/ocat").read_bytes(), executable=True)
        zshrc = Path(os.environ.get("ZDOTDIR", self.home)) / ".zshrc"
        quoted = shlex.quote(str(target))
        self.configure(zshrc, f"[[ -r {quoted} ]] && source {quoted}")
        print(f"Activate in existing zsh sessions: source {quoted}")

    def vscode(self):
        # Load by path so embedding this installer with importlib also works.
        spec = importlib.util.spec_from_file_location("ostadix_vscode_settings", SOURCE / "vscode_settings.py")
        run_settings = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(run_settings)
        package = json.loads((SOURCE / "vscode/package.json").read_text())
        identity = f"{package['publisher']}.{package['name']}"
        manifest = ET.Element("PackageManifest", Version="2.0.0", xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011")
        metadata = ET.SubElement(manifest, "Metadata")
        ET.SubElement(metadata, "Identity", Language="en-US", Id=package["name"], Version=package["version"], Publisher=package["publisher"])
        ET.SubElement(metadata, "DisplayName").text = package["displayName"]
        ET.SubElement(metadata, "Description").text = package["description"]
        ET.SubElement(metadata, "Categories").text = "Programming Languages"
        properties = ET.SubElement(metadata, "Properties")
        for key, value in {
            "Microsoft.VisualStudio.Code.Engine": package["engines"]["vscode"],
            "Microsoft.VisualStudio.Code.ExtensionDependencies": "",
            "Microsoft.VisualStudio.Code.ExtensionPack": "",
            "Microsoft.VisualStudio.Code.LocalizedLanguages": "",
            "Microsoft.VisualStudio.Code.EnabledApiProposals": "",
            "Microsoft.VisualStudio.Code.ExecutesCode": "false",
        }.items():
            ET.SubElement(properties, "Property", Id=key, Value=value)
        installation = ET.SubElement(manifest, "Installation")
        ET.SubElement(installation, "InstallationTarget", Id="Microsoft.VisualStudio.Code")
        ET.SubElement(manifest, "Dependencies")
        assets = ET.SubElement(manifest, "Assets")
        ET.SubElement(assets, "Asset", Type="Microsoft.VisualStudio.Code.Manifest", Path="extension/package.json", Addressable="true")
        types = ET.Element("Types", xmlns="http://schemas.openxmlformats.org/package/2006/content-types")
        for extension, mime in [("json", "application/json"), ("vsixmanifest", "text/xml"), ("md", "text/markdown"), ("txt", "text/plain")]:
            ET.SubElement(types, "Default", Extension=extension, ContentType=mime)
        vsix = self.data / f"{identity}-{package['version']}.vsix"
        editors = self.code_editors()
        if not editors:
            raise Unavailable("no Code, Code Insiders, Cursor, or VSCodium CLI/application was found")
        if self.dry_run:
            print(f"[DRY] package local syntax extension: {vsix}")
            for label, binary in editors:
                print(f"{label}: install local Ostadix grammar")
                self.command([binary, "--install-extension", str(vsix), "--force"])
                run_settings.install_settings(self, label, binary, SOURCE.parents[1])
            return
        self.data.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(vsix, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("extension.vsixmanifest", ET.tostring(manifest, encoding="utf-8", xml_declaration=True))
            archive.writestr("[Content_Types].xml", ET.tostring(types, encoding="utf-8", xml_declaration=True))
            for path in sorted((SOURCE / "vscode").rglob("*")):
                relative = path.relative_to(SOURCE / "vscode")
                if path.is_file() and not any(part in {"node_modules", "test", "tests"} for part in relative.parts) and path.suffix not in {".vsix", ".mjs"}:
                    archive.write(path, f"extension/{relative}")
        print(f"Packaged: {vsix}")
        failures = []
        for label, binary in editors:
            try:
                print(f"{label}: install local Ostadix grammar")
                self.command([binary, "--install-extension", str(vsix), "--force"])
                run_settings.install_settings(self, label, binary, SOURCE.parents[1])
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                failures.append(f"{label}: {error}")
        if failures:
            raise RuntimeError("; ".join(failures))
        print("Reload already-open editor windows if .O files still show plain text.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="+", choices=COMPONENTS, help="Select supported components; cat integration is explicit only")
    parser.add_argument("--auto", action="store_true", help="Install all available supported editors (the default)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Report available editor support without running editor commands or writing files")
    mode.add_argument("--dry-run", action="store_true", help="Print installation actions without changing files")
    args = parser.parse_args(argv)
    if not use_login_user():
        return 0
    installer = Installer(dry_run=args.dry_run, check=args.check)
    failed = []
    for component in args.only or DEFAULT_COMPONENTS:
        if not installer.available(component):
            print(f"SKIP {component}: no supported editor executable found")
            continue
        if args.check:
            detail = ", ".join(label for label, _ in installer.code_editors()) if component == "vscode" else component
            print(f"AVAILABLE {component}: {detail}")
            continue
        try:
            getattr(installer, component)()
        except Unavailable as exc:
            print(f"SKIP {component}: {exc}")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            print(f"{component}: {exc}", file=sys.stderr)
            failed.append(component)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
