#!/usr/bin/env python3
"""Build the technical whitepaper with Tectonic and normalize its PDF metadata.

Requires installed ``tectonic`` and qpdf with JSON v2 support. Build products
stay in target/whitepaper by default; --install explicitly refreshes both
published PDF copies. Reproducible bytes require the same source/assets,
Tectonic resource bundle, and tool versions.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/Ostadix-lang_Technical_Whitepaper.tex"
AUTHOR = "u:Lee Daghlar Ostadi"
INFO_KEYS = ("/Author", "/Title", "/Subject", "/Keywords")


def run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments, check=True, text=True, capture_output=True, **kwargs
    )


def pdf_objects(qpdf: str, path: Path) -> dict:
    data = json.loads(run([
        qpdf, "--json-output=2", "--json-stream-data=none", str(path)
    ], timeout=120).stdout)
    return data["qpdf"][1]


def remove_private_metadata(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: remove_private_metadata(item)
            for key, item in value.items()
            if key != "/Metadata" and not key.upper().startswith("/PTEX")
        }
    if isinstance(value, list):
        return [remove_private_metadata(item) for item in value]
    return value


def normalize_pdf(source: Path, destination: Path, qpdf: str) -> dict:
    """Retain authored Info fields; remove XMP, dates, tools and PTEX paths."""
    original = pdf_objects(qpdf, source)
    objects = copy.deepcopy(original)
    trailer = objects["trailer"]["value"]
    # The original first ID otherwise survives --deterministic-id and can
    # encode a prior time/path-dependent build identity.
    trailer.pop("/ID", None)
    info_reference = trailer.get("/Info")
    if not isinstance(info_reference, str):
        raise ValueError("whitepaper PDF has no indirect document Info dictionary")
    info_object = objects["obj:" + info_reference]
    old_info = info_object["value"]
    info = {key: old_info[key] for key in INFO_KEYS if key in old_info}
    info["/Author"] = AUTHOR
    if any(not isinstance(info.get(key), str) for key in INFO_KEYS):
        raise ValueError("whitepaper must declare a title, subject and keywords")
    info_object["value"] = info
    objects = remove_private_metadata(objects)
    # Supplying only changed objects leaves original stream bytes untouched.
    updates = {
        key: value for key, value in objects.items() if value != original[key]
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pdf-normalize-", dir=destination.parent) as temporary:
        directory = Path(temporary)
        patch = directory / "metadata.json"
        patch.write_text(json.dumps({"qpdf": [{"jsonversion": 2}, updates]}), encoding="utf-8")
        normalized = directory / "normalized.pdf"
        run([
            qpdf, str(source), "--update-from-json=" + str(patch),
            "--deterministic-id", "--min-version=1.7", "--object-streams=generate",
            "--stream-data=compress", str(normalized),
        ], timeout=120)
        run([qpdf, "--check", str(normalized)], timeout=120)
        checked = pdf_objects(qpdf, normalized)
        checked_info = checked["obj:" + checked["trailer"]["value"]["/Info"]]["value"]
        if checked_info != info or remove_private_metadata(checked) != checked:
            raise ValueError("normalized PDF did not retain the requested metadata policy")
        for item in checked.values():
            if item.get("stream", {}).get("dict", {}).get("/Type") == "/Metadata":
                raise ValueError("normalized PDF still contains an XMP metadata stream")
        os.replace(normalized, destination)
    return info


def source_epoch(explicit: int | None) -> int:
    if explicit is not None:
        epoch = explicit
    elif "SOURCE_DATE_EPOCH" in os.environ:
        epoch = int(os.environ["SOURCE_DATE_EPOCH"])
    else:
        epoch = int(run([
            "git", "-C", str(ROOT), "log", "-1", "--format=%ct"
        ], timeout=15).stdout.strip())
    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be a nonnegative Unix timestamp")
    return epoch


def build_pdf(source: Path, output: Path, tectonic: str, qpdf: str,
              epoch: int, only_cached: bool = False) -> Path:
    """Compile in a fresh directory so stale auxiliary files cannot affect it."""
    output.mkdir(parents=True, exist_ok=True)
    destination = output / source.with_suffix(".pdf").name
    environment = os.environ.copy()
    environment.update(SOURCE_DATE_EPOCH=str(epoch), TZ="UTC")
    with tempfile.TemporaryDirectory(prefix="tectonic-", dir=output) as temporary:
        directory = Path(temporary)
        arguments = [tectonic, "--keep-logs", "--outdir", str(directory)]
        if only_cached:
            arguments.append("--only-cached")
        arguments.append(str(source))
        try:
            result = run(arguments, cwd=source.parent, env=environment, timeout=900)
        except subprocess.CalledProcessError as error:
            (output / "tectonic-build.log").write_text(
                (error.stdout or "") + (error.stderr or ""), encoding="utf-8"
            )
            raise
        finally:
            for log in directory.glob("*.log"):
                shutil.copyfile(log, output / log.name)
        (output / "tectonic-build.log").write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        info = normalize_pdf(directory / destination.name, destination, qpdf)
    record = {
        "schema": "ostadix.whitepaper-build/v1",
        "source": str(source),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "source_date_epoch": epoch,
        "tectonic": run([tectonic, "--version"], timeout=15).stdout.strip(),
        "qpdf": run([qpdf, "--version"], timeout=15).stdout.splitlines()[0],
        "pdf": destination.name,
        "pdf_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "metadata": info,
    }
    (output / "build.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return destination


def install_pdf(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="." + destination.name + ".",
                                         dir=destination.parent, delete=False) as temporary:
            temporary_path = Path(temporary.name)
            with source.open("rb") as stream:
                shutil.copyfileobj(stream, temporary)
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.chmod(0o644)
        os.replace(temporary_path, destination)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "target/whitepaper",
                        help="build directory (default: repository target/whitepaper)")
    parser.add_argument("--source-date-epoch", type=int,
                        help="fixed Unix timestamp (default: environment, then HEAD commit time)")
    parser.add_argument("--only-cached", action="store_true",
                        help="require Tectonic resources already available locally")
    parser.add_argument("--install", action="store_true",
                        help="also replace the root and output/pdf published PDF copies")
    args = parser.parse_args(argv)
    try:
        tectonic, qpdf = shutil.which("tectonic"), shutil.which("qpdf")
        if not tectonic or not qpdf:
            raise ValueError("installed tectonic and qpdf are required; no dependencies were installed")
        epoch = source_epoch(args.source_date_epoch)
        output = args.output_dir.resolve()
        print(f"whitepaper: compiling with SOURCE_DATE_EPOCH={epoch}", flush=True)
        pdf = build_pdf(SOURCE, output, tectonic, qpdf, epoch, args.only_cached)
        print(f"whitepaper: built {pdf}")
        print(f"whitepaper: sha256 {hashlib.sha256(pdf.read_bytes()).hexdigest()}")
        if args.install:
            for destination in (ROOT / pdf.name, ROOT / "output/pdf" / pdf.name):
                if destination.resolve() != pdf.resolve():
                    install_pdf(pdf, destination)
                print(f"whitepaper: installed {destination}")
        return 0
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f"whitepaper: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print((error.stderr or error.stdout or "")[-5000:], file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
