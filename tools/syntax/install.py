#!/usr/bin/env python3
"""Install Ostadix highlighting locally, preserving existing configuration."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

SOURCE = Path(__file__).resolve().parent
BEGIN = "# >>> Ostadix syntax highlighting >>>"
END = "# <<< Ostadix syntax highlighting <<<"


def managed_block(original, content):
    """Replace our block only; retain all unrelated settings verbatim."""
    block = f"{BEGIN}\n{content.rstrip()}\n{END}\n"
    if BEGIN not in original and END not in original:
        return original + ("\n" if original and not original.endswith("\n") else "") + block
    if original.count(BEGIN) != 1 or original.count(END) != 1:
        raise ValueError("Ambiguous Ostadix config markers; refusing to overwrite")
    start = original.index(BEGIN)
    finish = original.index(END, start) + len(END)
    if original[finish:finish + 1] == "\n":
        finish += 1
    return original[:start] + block + original[finish:]


class Installer:
    def __init__(self):
        self.home = Path.home()
        self.config = Path(os.environ.get("XDG_CONFIG_HOME", self.home / ".config"))
        self.data = Path(os.environ.get("XDG_DATA_HOME", self.home / ".local/share")) / "ostadix/syntax"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        self.backups = self.data / "backups" / stamp

    def write(self, target, data, executable=False):
        target = Path(target).expanduser()
        if isinstance(data, str):
            data = data.encode()
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

    def configure(self, target, content):
        original = target.read_text() if target.exists() else ""
        self.write(target, managed_block(original, content))

    def bat(self):
        binary = shutil.which("bat") or shutil.which("batcat")
        if not binary:
            raise RuntimeError("bat is required; install bat and rerun --only bat cat")
        directory = Path(subprocess.check_output([binary, "--config-dir"], text=True).strip())
        for source in sorted((SOURCE / "bat").glob("*.sublime-syntax")):
            self.write(directory / "syntaxes" / source.name, source.read_bytes())
        subprocess.run([binary, "cache", "--build"], check=True)

    def nano(self):
        binary = shutil.which("nano")
        # macOS /usr/bin/nano is Pico; --version starts its editor.
        if not binary or "pico" in Path(binary).resolve().name:
            raise RuntimeError("GNU nano is required (macOS: brew install nano); Pico cannot load nanorc syntax")
        version = subprocess.check_output([binary, "--version"], text=True, timeout=10)
        if "GNU nano" not in version:
            raise RuntimeError(f"Not GNU nano: {binary}")
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

    def cat(self):
        target = self.config / "ostadix/syntax/ostadix-cat.zsh"
        self.write(target, (SOURCE / "terminal/ostadix-cat.zsh").read_bytes())
        self.write(self.home / ".local/bin/ocat", (SOURCE / "terminal/ocat").read_bytes(), executable=True)
        zshrc = Path(os.environ.get("ZDOTDIR", self.home)) / ".zshrc"
        quoted = shlex.quote(str(target))
        self.configure(zshrc, f"[[ -r {quoted} ]] && source {quoted}")
        print(f"Activate in existing zsh sessions: source {quoted}")

    def vscode(self):
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
        self.data.mkdir(parents=True, exist_ok=True)
        vsix = self.data / f"{identity}-{package['version']}.vsix"
        with zipfile.ZipFile(vsix, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("extension.vsixmanifest", ET.tostring(manifest, encoding="utf-8", xml_declaration=True))
            archive.writestr("[Content_Types].xml", ET.tostring(types, encoding="utf-8", xml_declaration=True))
            for path in sorted((SOURCE / "vscode").rglob("*")):
                relative = path.relative_to(SOURCE / "vscode")
                if path.is_file() and not any(part in {"node_modules", "test", "tests"} for part in relative.parts) and path.suffix not in {".vsix", ".mjs"}:
                    archive.write(path, f"extension/{relative}")
        print(f"Packaged: {vsix}")
        binary = shutil.which("code")
        if not binary:
            raise RuntimeError(f"VS Code CLI unavailable. Install the generated VSIX manually: {vsix}")
        subprocess.run([binary, "--install-extension", str(vsix), "--force"], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="+", choices=["bat", "nano", "cat", "vscode"], default=["bat", "nano", "cat", "vscode"])
    args = parser.parse_args()
    installer = Installer()
    failed = []
    for component in args.only:
        try:
            getattr(installer, component)()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            print(f"{component}: {exc}", file=sys.stderr)
            failed.append(component)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
