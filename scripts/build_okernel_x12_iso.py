#!/usr/bin/env python3
"""Build an offline X12 Linux-hosted O-core compatibility development ISO.

The original running Linux kernel/modules/firmware supply physical hardware
support. The captured O-core monitor still runs its original Linux/Plan9
domains through QEMU/TCG. This is not native driver lowering, a completed
single-native OS, physical-device qualification, or an efficiency proof.

No package installation, download, sudo, VM interaction, internal-disk mount
or write is performed. Every output is new. Carrier preparation and final ISO
assembly are separate so a newly qualified frozen controller can be supplied.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "ocore/guest/x12-live"
RELEASE = "7.0.14-ustad-native-20261031"
PAYLOAD_PYTHON = Path("/usr/bin/python3.12")
EPOCH = 315532800
CARRIER_SCHEMA = "ostadix.okernel-x12-linux-carrier/v1"
ISO_SCHEMA = "ostadix.okernel-x12-hosted-iso/v1"


def sha(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            value.update(chunk)
    return value.hexdigest()


def identity(path: Path) -> dict:
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}


def save(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def new_output(path: Path) -> Path:
    path = path.expanduser().absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        if part in (".", ".."):
            raise ValueError("noncanonical output path")
        current /= part
        if current.is_symlink():
            raise ValueError("output path contains a symlink")
    if path.exists() or path.is_symlink():
        raise ValueError("output must be new: " + str(path))
    path.mkdir(mode=0o700, parents=True)
    return path


def run(record: dict, label: str, argv: list, cwd: Path, timeout: int = 600,
        environment: dict | None = None) -> subprocess.CompletedProcess:
    argv = [str(value) for value in argv]
    started = time.monotonic()
    selected_environment = None
    if environment:
        selected_environment = os.environ.copy()
        for key, value in environment.items():
            if value is None: selected_environment.pop(key, None)
            else: selected_environment[key] = value
    outcome = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=timeout,
                             env=selected_environment)
    log = cwd / (label + ".log")
    log.write_bytes(outcome.stdout + outcome.stderr)
    record.setdefault("commands", []).append({"label": label, "argv": argv,
        "returncode": outcome.returncode, "seconds": time.monotonic() - started,
        "log": identity(log)})
    if environment: record["commands"][-1]["environment_overrides"] = environment
    if outcome.returncode:
        raise ValueError(label + " failed: " + outcome.stderr.decode(errors="replace")[-3000:])
    return outcome


def tool(name: str) -> Path:
    found = shutil.which(name)
    if found is None:
        raise ValueError("required installed tool missing: " + name)
    Path(found).resolve(strict=True)
    # Multi-call tools such as depmod/modprobe dispatch on argv[0].
    return Path(found).absolute()


def inventory(root: Path) -> dict:
    result = {}
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort(); files.sort()
        for name in directories[:] + files:
            path = Path(current) / name
            relative = str(path.relative_to(root))
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                result[relative] = {"type": "symlink", "target": os.readlink(path)}
                if name in directories:
                    directories.remove(name)
            elif stat.S_ISREG(metadata.st_mode):
                result[relative] = {"type": "file", "bytes": metadata.st_size,
                                    "sha256": sha(path), "mode": stat.S_IMODE(metadata.st_mode)}
            elif not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("unexpected special carrier input: " + relative)
    return result


def verify_inventory(root: Path, expected: dict) -> None:
    if inventory(root) != expected:
        raise ValueError("carrier inventory changed")


def canonical_fat_free(image: bytes, parser) -> tuple[bytes, dict]:
    """Zero only free data clusters in an agreed, bounded FAT12/16 image."""
    geometry = parser._fat_geometry(image)
    if geometry["fat_bits"] not in (12, 16) or geometry["fat_count"] != 2 or geometry["image_bytes"] != len(image):
        raise ValueError("expected complete two-copy FAT12/16 EFI image")
    sector = geometry["bytes_per_sector"]
    start = geometry["reserved_sectors"] * sector
    table_bytes = geometry["fat_sectors"] * sector
    if image[start:start+table_bytes] != image[start+table_bytes:start+2*table_bytes]:
        raise ValueError("EFI FAT copies disagree")
    original_boot = parser._find_fat_bootloader(image, geometry)
    cluster_bytes = sector * geometry["sectors_per_cluster"]
    first = geometry["first_data_sector"] * sector
    count = (geometry["total_sectors"] - geometry["first_data_sector"]) // geometry["sectors_per_cluster"]
    result = bytearray(image)
    changed = []; free = 0
    for cluster in range(2, count + 2):
        entry_end = cluster + cluster // 2 + 2 if geometry["fat_bits"] == 12 else cluster * 2 + 2
        if entry_end > table_bytes: raise ValueError("EFI cluster allocation leaves FAT")
        if parser._fat_next(image, geometry, cluster) != 0: continue
        free += 1
        offset = first + (cluster - 2) * cluster_bytes
        if offset + cluster_bytes > len(image): raise ValueError("free cluster outside EFI image")
        if any(result[offset:offset+cluster_bytes]): changed.append(cluster)
        result[offset:offset+cluster_bytes] = bytes(cluster_bytes)
    result = bytes(result)
    if parser._find_fat_bootloader(result, geometry) != original_boot:
        raise ValueError("free-cluster normalization changed EFI bootloader")
    return result, {"fat_bits": geometry["fat_bits"], "free_clusters": free,
                    "zeroed_nonempty_clusters": changed, "bootloader_sha256": hashlib.sha256(original_boot).hexdigest()}


def normalize_iso_free(iso: Path) -> dict:
    parser = load_module(ROOT / "scripts/ostadix_boot_iso.py", "x12_iso_structure")
    with iso.open("r+b") as stream, mmap.mmap(stream.fileno(), 0) as image:
        primary = image[16*2048:17*2048]
        if primary[:7] != b"\x01CD001\x01": raise ValueError("missing primary ISO9660 descriptor")
        volume_bytes = parser._u32_both(primary, 80, "volume size") * 2048
        if volume_bytes != len(image): raise ValueError("ISO extent mismatch")
        length = primary[156]
        root = parser._directory_record(primary[156:156+length], volume_bytes, "root")
        efi, entry = parser._find_iso_path(image, root, ("EFI.IMG",), volume_bytes)
        canonical, record = canonical_fat_free(efi, parser)
        offset = int(entry["extent_lba"]) * 2048
        image[offset:offset+len(efi)] = canonical
        image.flush()
        return {**record, "efi_offset": offset, "efi_bytes": len(efi),
                "efi_sha256": hashlib.sha256(canonical).hexdigest(),
                "scope": "only data clusters marked free by both identical FAT copies"}


def assemble(stage: Path, output: Path, record: dict) -> None:
    for path in sorted(stage.rglob("*"), reverse=True):
        os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)
    os.utime(stage, (EPOCH, EPOCH))
    iso = output / "okernel-x12-development.iso"
    wrapper = ROOT / "scripts/ostadix_xorriso_reproducible.py"
    run(record, "grub-iso", [tool("grub-mkrescue"), "--directory=/usr/lib/grub/x86_64-efi",
        "--xorriso=" + str(wrapper), "--output=" + str(iso), "--compress=no", "--fonts=",
        "--locales=", "--themes=", stage, "--modification-date=1980010100000000",
        "-uid", "0", "-gid", "0", "-V", "OKERNEL_X12"], output, 600,
        environment={"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": str(EPOCH),
                     "OSTADIX_REAL_XORRISO": str(tool("xorriso"))})
    record["efi_free_space_normalization"] = normalize_iso_free(iso)
    record["iso"] = identity(iso)


def attribution_append(stage: Path, original: dict) -> dict:
    """Retain installed upstream/distro notices without changing boot payloads."""
    carrier = json.loads(Path(original["carrier"]["path"]).read_bytes())
    runtime = json.loads(Path(original["runtime"]["manifest"]["path"]).read_bytes())
    inputs = set()
    def paths(value):
        if isinstance(value, dict):
            if isinstance(value.get("path"), str) and value["path"].startswith(("/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/")):
                inputs.add(value["path"])
            for item in value.values(): paths(item)
        elif isinstance(value, list):
            for item in value: paths(item)
    paths(carrier["captured_inputs"]); paths(original.get("captured_inputs", {})); paths(runtime)
    def usrpath(path):
        return "/usr" + path if path.startswith(("/bin/", "/sbin/", "/lib/", "/lib64/")) else path
    wanted = {usrpath(path) for path in inputs}
    packages = set(); matched = set()
    for listing in sorted(Path("/var/lib/dpkg/info").glob("*.list")):
        members = {usrpath(line) for line in listing.read_text(errors="strict").splitlines()}
        hits = wanted & members
        if hits: packages.add(listing.name[:-5].split(":")[0]); matched.update(hits)
    packages.update(path.parent.name for path in Path("/usr/share/doc").glob("linux-firmware*/copyright"))
    packages.update(("firmware-sof-signed", "linux-image-" + RELEASE, "dash"))
    licenses = stage / "licenses"; licenses.mkdir()
    captures = []; missing = []
    def copy(source, relative):
        pin = identity(source)
        target = licenses / relative; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target); target.chmod(0o444)
        if sha(target) != pin["sha256"] or identity(source) != pin: raise ValueError("notice source changed")
        captures.append({"source": pin, "media_path": "/licenses/" + relative})
    for package in sorted(packages):
        source = Path("/usr/share/doc") / package / "copyright"
        if source.is_file(): copy(source, "packages/" + package + "/copyright")
        else: missing.append(str(source))
    for source in sorted(Path("/usr/share/common-licenses").iterdir()):
        if source.is_file(): copy(source, "common/" + source.name)
    # Historical host replay used dash; include its exact bytes as an optional
    # tool. Active init /bin/sh remains the declared original BusyBox shell.
    dash = Path("/usr/bin/dash")
    directory = stage / "carrier-tools"; directory.mkdir()
    dash_before = identity(dash)
    shutil.copyfile(dash, directory / "dash"); (directory / "dash").chmod(0o555)
    if sha(directory / "dash") != dash_before["sha256"] or identity(dash) != dash_before:
        raise ValueError("optional dash source changed")
    notice = {"schema": "ostadix.x12-media-attributions/v1", "captured_notices": captures,
        "missing_package_notice_paths": missing, "unmatched_recorded_host_paths": sorted(wanted - matched),
        "optional_dash": {"bytes": dash.stat().st_size, "sha256": sha(dash)},
        "active_carrier_shell": "original BusyBox /bin/sh; dash is an optional /carrier-tools/dash executable",
        "scope": "installed package notices for captured host tools/libraries plus all installed firmware packages; binary capture is not complete corresponding source provenance"}
    save(licenses / "manifest.json", notice)
    (licenses / "README.txt").write_text("Installed package copyright notices and referenced common licenses are retained here.\nOn the running ISO this directory is /media/okernel/licenses.\nThe optional original dash executable is /media/okernel/carrier-tools/dash; active /bin/sh is BusyBox.\nThis development image is volatile and Linux-hosted; it does not qualify native driver lowering or physical hardware.\n")
    return {"manifest": identity(licenses / "manifest.json"), "inventory": inventory(licenses),
            "optional_dash": identity(directory / "dash"), "missing_package_notice_paths": missing}


def repack(args, output: Path, record: dict) -> None:
    prior = args.from_build.resolve(strict=True)
    receipt = prior / "result.json"
    original = json.loads(receipt.read_bytes())
    if original.get("schema") != ISO_SCHEMA or original.get("ok") is not True:
        raise ValueError("successful captured ISO build required")
    source_stage = prior / "iso-tree"
    expected = {"boot/rootfs.squashfs": original["squashfs"], "boot/initramfs.gz": original["bootstrap"],
                "boot/vmlinuz": original["kernel"]}
    for relative, pin in expected.items():
        path = source_stage / relative
        if path.stat().st_size != pin["bytes"] or sha(path) != pin["sha256"]: raise ValueError("captured boot payload changed: " + relative)
    before = inventory(source_stage)
    stage = output / "iso-tree"
    run(record, "copy-captured-iso-tree", [tool("cp"), "-a", "--reflink=auto", source_stage, stage], output)
    record.update(source_build_receipt=identity(receipt), preserved_boot_payloads={key: {k: pin[k] for k in ("bytes", "sha256")} for key,pin in expected.items()},
        scope=__doc__, runtime=original["runtime"], seed=original["seed"], carrier=original["carrier"],
        kernel=original["kernel"], squashfs=identity(stage / "boot/rootfs.squashfs"), bootstrap=identity(stage / "boot/initramfs.gz"))
    if (stage / "licenses").exists():
        retained = original.get("attributions")
        if not isinstance(retained, dict): raise ValueError("unbound preexisting media notices")
        verify_inventory(stage / "licenses", retained["inventory"])
        dash = stage / "carrier-tools/dash"
        if dash.stat().st_size != retained["optional_dash"]["bytes"] or sha(dash) != retained["optional_dash"]["sha256"]:
            raise ValueError("retained optional dash changed")
        record["attributions"] = {**retained, "manifest": identity(stage / "licenses/manifest.json"), "optional_dash": identity(dash)}
    else:
        record["attributions"] = attribution_append(stage, original)
    record["stage_inventory"] = inventory(stage)
    assemble(stage, output, record)
    verify_inventory(source_stage, before)
    verify_inventory(stage, record["stage_inventory"])
    record["ok"] = True


def retained_attributions(source: Path, stage: Path) -> dict:
    source = source.resolve(strict=True)
    receipt = source / "result.json"
    value = json.loads(receipt.read_bytes())
    if value.get("schema") != ISO_SCHEMA or value.get("ok") is not True:
        raise ValueError("completed attribution source required")
    retained = value["attributions"]
    origin = source / "iso-tree"
    verify_inventory(origin / "licenses", retained["inventory"])
    dash = origin / "carrier-tools/dash"
    if dash.is_symlink() or dash.stat().st_size != retained["optional_dash"]["bytes"] or sha(dash) != retained["optional_dash"]["sha256"]:
        raise ValueError("attribution source dash changed")
    shutil.copytree(origin / "licenses", stage / "licenses")
    (stage / "carrier-tools").mkdir()
    shutil.copyfile(dash, stage / "carrier-tools/dash")
    (stage / "carrier-tools/dash").chmod(0o555)
    verify_inventory(stage / "licenses", retained["inventory"])
    if sha(stage / "carrier-tools/dash") != retained["optional_dash"]["sha256"]:
        raise ValueError("retained dash copy changed")
    return {**retained, "retained_source_receipt": identity(receipt),
            "manifest": identity(stage / "licenses/manifest.json"),
            "optional_dash": identity(stage / "carrier-tools/dash")}


class Capture:
    def __init__(self, root: Path, record: dict):
        self.root, self.record = root, record
        self.inputs = record.setdefault("captured_inputs", {})
        self.elfs = set()

    def target(self, absolute: str) -> Path:
        path = PurePosixPath(absolute)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("noncanonical carrier destination")
        return self.root / str(path).lstrip("/")

    def file(self, source: Path, absolute: str | None = None) -> Path:
        source = source.resolve(strict=True)
        absolute = absolute or str(source)
        expected = identity(source)
        destination = self.target(absolute)
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if destination.exists():
            if destination.is_symlink() or sha(destination) != expected["sha256"]:
                raise ValueError("carrier destination collision: " + absolute)
        else:
            shutil.copyfile(source, destination)
            destination.chmod(0o555 if os.access(source, os.X_OK) else 0o444)
        if identity(source) != expected or sha(destination) != expected["sha256"]:
            raise ValueError("source changed while captured: " + str(source))
        self.inputs[absolute] = {"source": expected, "captured": identity(destination)}
        return destination

    def elf(self, source: Path, absolute: str | None = None) -> None:
        destination = self.file(source, absolute)
        with destination.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                return
        key = str(source.resolve())
        if key in self.elfs:
            return
        self.elfs.add(key)
        result = subprocess.run(["/usr/bin/ldd", str(source)], capture_output=True, text=True,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=30)
        if "not found" in result.stdout:
            raise ValueError("unresolved host ELF dependency: " + str(source))
        if result.returncode and not any(text in result.stderr + result.stdout
                                       for text in ("not a dynamic executable", "statically linked")):
            raise ValueError("ldd failed: " + str(source) + ": " + result.stderr)
        for line in result.stdout.splitlines():
            match = re.search(r"(?:=>\s+)?(/\S+)\s+\(0x", line)
            if match:
                dependency = Path(match.group(1))
                self.elf(dependency, str(dependency))

    def tree(self, source: Path, absolute: str, *, modules: bool = False) -> None:
        source = source.resolve(strict=True)
        target = self.target(absolute)
        target.mkdir(mode=0o755, parents=True, exist_ok=True)
        for current, directories, files in os.walk(source, followlinks=False):
            directories.sort(); files.sort()
            relative = Path(current).relative_to(source)
            for name in directories[:] + files:
                path = Path(current) / name
                suffix = relative / name
                destination = target / suffix
                if modules and suffix.parts[0] in ("build", "source"):
                    if name in directories: directories.remove(name)
                    self.record.setdefault("excluded_module_build_links", []).append(str(path))
                    continue
                if path.is_symlink():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    link = os.readlink(path)
                    if destination.exists() or destination.is_symlink():
                        raise ValueError("carrier symlink collision")
                    destination.symlink_to(link)
                    self.inputs[str(destination.relative_to(self.root))] = {
                        "source_path": str(path), "symlink_target": link}
                    if name in directories: directories.remove(name)
                elif path.is_dir():
                    destination.mkdir(mode=0o755, parents=True, exist_ok=True)
                elif path.is_file():
                    if not os.access(path, os.R_OK):
                        self.record.setdefault("unreadable_inputs", []).append(str(path))
                        if modules and path.name.startswith("modules."):
                            continue
                        raise ValueError("required input unreadable: " + str(path))
                    self.file(path, "/" + str(destination.relative_to(self.root)))


def prepare(args, output: Path, record: dict) -> None:
    root = output / "root"
    root.mkdir()
    for directory in ("usr/bin", "usr/sbin", "usr/lib", "usr/local/sbin", "etc", "dev/pts",
                      "proc", "sys", "run", "tmp", "root", "media/okernel", "lib64"):
        (root / directory).mkdir(mode=0o755, parents=True, exist_ok=True)
    for name, link in (("bin", "usr/bin"), ("sbin", "usr/sbin"), ("lib", "usr/lib")):
        (root / name).symlink_to(link)
    capture = Capture(root, record)
    release = args.release
    if release != os.uname().release:
        raise ValueError("carrier profile requires the running kernel's exact release")
    kernel = args.kernel or Path("/boot/vmlinuz-" + release)
    record.update(release=release, kernel=identity(kernel), modules_source=str(args.modules or Path("/lib/modules") / release),
                  firmware_source=str(args.firmware), physical_hardware_qualified=False,
                  native_driver_lowering=False, persistent_storage=False)
    record["network_tools"] = {name: str(shutil.which(name)) if shutil.which(name) else None
                               for name in ("ip", "wpa_supplicant", "wpa_cli", "wpa_passphrase", "rfkill", "iw")}
    record["network_scope"] = "Original WPA supplicant/CLI and BusyBox DHCP; no copied host network configuration or credentials; iw is optional and absent on this source host."
    version = subprocess.check_output([str(PAYLOAD_PYTHON), "-I", "-c", "import sys;print('.'.join(map(str,sys.version_info[:3])))"], text=True).strip()
    if not version.startswith("3.12."):
        raise ValueError("this carrier requires the declared original Python3.12 payload")
    record["python_payload"] = {**identity(PAYLOAD_PYTHON), "version": version,
                                "stdlib": "/usr/lib/python3.12"}
    shutil.copyfile(kernel, output / "vmlinuz")
    record["copied_kernel"] = identity(output / "vmlinuz")
    config = Path("/boot/config-" + release)
    capture.file(config, "/usr/share/okernel/linux.config")
    capture.file(Path("/usr/bin/busybox"), "/usr/bin/busybox")
    applets = subprocess.check_output(["/usr/bin/busybox", "--list"], text=True).splitlines()
    for name in applets:
        path = root / "usr/bin" / name
        if not path.exists(): path.symlink_to("busybox")
    for source in (Path("/usr/bin/bash"), Path("/usr/bin/tmux"), PAYLOAD_PYTHON,
                   tool("kmod"), tool("ip"), tool("wpa_supplicant"), tool("wpa_cli"),
                   tool("wpa_passphrase"), tool("rfkill")):
        destination = "/usr/bin/python3.12" if source == PAYLOAD_PYTHON else str(source)
        existing = capture.target(destination)
        if existing.is_symlink(): existing.unlink()
        capture.elf(source, destination)
    for alias, target in (("usr/bin/python3", "python3.12"), ("usr/sbin/modprobe", "/usr/bin/kmod"),
                           ("usr/sbin/depmod", "/usr/bin/kmod"), ("usr/sbin/insmod", "/usr/bin/kmod"),
                           ("usr/sbin/modinfo", "/usr/bin/kmod"), ("usr/sbin/rmmod", "/usr/bin/kmod")):
        path = root / alias
        if path.is_symlink(): path.unlink()
        path.symlink_to(target)
    capture.file(Path("/usr/bin/ldd"), "/usr/bin/ldd")
    capture.tree(Path("/usr/lib/python3.12"), "/usr/lib/python3.12")
    capture.file(Path("/etc/python3.12/sitecustomize.py"), "/etc/python3.12/sitecustomize.py")
    for extension in sorted((root / "usr/lib/python3.12").rglob("*.so")):
        source = Path("/") / extension.relative_to(root)
        capture.elf(source, "/" + str(extension.relative_to(root)))
    for source in (Path("/usr/share/terminfo"), Path("/lib/terminfo"), Path("/usr/lib/locale/C.utf8")):
        if source.is_dir(): capture.tree(source, str(source))
    capture.tree(args.modules or Path("/lib/modules") / release, "/usr/lib/modules/" + release, modules=True)
    capture.tree(args.firmware, "/usr/lib/firmware")
    for source in (Path("/usr/share/doc/linux-firmware"), Path("/usr/share/doc/busybox-static"),
                   Path("/usr/share/doc/python3.12"), Path("/usr/share/doc/bash"), Path("/usr/share/doc/tmux"),
                   Path("/usr/share/doc/python3"), Path("/usr/share/doc/python3.12-minimal"),
                   Path("/usr/share/doc/bash-completion"), Path("/usr/share/doc/kmod"),
                   Path("/usr/share/doc/wpasupplicant"), Path("/usr/share/doc/iproute2"),
                   Path("/usr/share/common-licenses")):
        if source.is_dir(): capture.tree(source, str(source))
    run(record, "private-depmod", [tool("depmod"), "-b", root, release], output)
    (root / "etc/passwd").write_text("root:x:0:0:OKernel live:/root:/bin/bash\n")
    (root / "etc/group").write_text("root:x:0:\n")
    (root / "etc/nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files dns\n")
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n::1 localhost\n")
    (root / "etc/mdev.conf").write_text('$MODALIAS=.* 0:0 660 @/sbin/modprobe "$MODALIAS"\n')
    (root / "etc/ld.so.conf").write_text("/usr/lib/x86_64-linux-gnu\n/usr/lib\n")
    # Exact ldd-selected SONAMEs retain their standard absolute loader paths.
    # A host ld.so.cache would describe unrelated installed packages; creating
    # a chroot cache would require privilege, so this profile uses default paths.
    record["root_inventory"] = inventory(root)
    record["module_count"] = sum(name.endswith(".ko") for name in record["root_inventory"])
    record["firmware_file_count"] = sum(name.startswith("usr/lib/firmware/") for name in record["root_inventory"])
    record["ok"] = True


def newc(root: Path, output: Path) -> None:
    """Root-owned deterministic newc, including console/null without mknod."""
    entries = [(".", root)]
    entries.extend((str(p.relative_to(root)), p) for p in sorted(root.rglob("*")))
    inode = 1
    with output.open("xb") as stream:
        def emit(name, mode, data, major=0, minor=0):
            nonlocal inode
            encoded = name.encode() + b"\0"
            values = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0)
            header = b"070701" + b"".join(f"{value:08x}".encode() for value in values)
            stream.write(header); stream.write(encoded)
            stream.write(b"\0" * ((-(len(header) + len(encoded))) % 4))
            stream.write(data); stream.write(b"\0" * ((-len(data)) % 4)); inode += 1
        for name, path in entries:
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode): emit(name, stat.S_IFDIR | 0o755, b"")
            elif stat.S_ISLNK(metadata.st_mode): emit(name, stat.S_IFLNK | 0o777, os.readlink(path).encode())
            elif stat.S_ISREG(metadata.st_mode): emit(name, stat.S_IFREG | stat.S_IMODE(metadata.st_mode), path.read_bytes())
            else: raise ValueError("unsupported newc input")
        emit("dev/console", stat.S_IFCHR | 0o600, b"", 5, 1)
        emit("dev/null", stat.S_IFCHR | 0o666, b"", 1, 3)
        emit("TRAILER!!!", 0, b"")


def copy_runtime(source: Path, target: Path) -> dict:
    source = source.resolve(strict=True)
    manifest = json.loads((source / "runtime.json").read_bytes())
    if manifest.get("schema") != "ostadix.okernel-unified-runtime/v1" or manifest.get("passed") is not True:
        raise ValueError("runtime must be a completed frozen capture")
    expected = manifest["inventory"]
    target.mkdir(parents=True)
    for name, pin in expected.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or str(relative) != name:
            raise ValueError("runtime inventory path escaped capture")
        selected = source
        for part in relative.parts:
            selected /= part
            if selected.is_symlink(): raise ValueError("runtime inventory symlink")
        if selected.stat().st_size != pin["bytes"] or sha(selected) != pin["sha256"]:
            raise ValueError("runtime inventory mismatch")
        destination = target / name; destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(selected, destination); destination.chmod(stat.S_IMODE(selected.stat().st_mode))
        if sha(destination) != pin["sha256"]: raise ValueError("runtime copy mismatch")
    shutil.copyfile(source / "runtime.json", target / "runtime.json")
    return {"manifest": identity(source / "runtime.json"), "inventory_files": len(expected)}


def saved_seed(source: Path, target: Path) -> dict:
    source = source.resolve(strict=True)
    fork = json.loads((source / "fork.json").read_bytes())
    if fork.get("schema") != "ostadix.okernel-state-fork/v1" or fork.get("ok") is not True or fork.get("output") != str(source):
        raise ValueError("--state-seed must be an existing verified private fork")
    common = load_module(ROOT / "scripts/okernel_package_domain.py", "x12_seed_common")
    selected = (source / "head.json").read_bytes(); head = json.loads(selected)
    common.validate_head(source, head)
    if head.get("schema") != "ostadix.package-domain-disk-head/v2" or not head.get("namespace"):
        raise ValueError("saved disk/native namespace pair required")
    target.mkdir(parents=True)
    generations = {}
    for key, folder, suffix, size in (("disk", "disk-generations", ".ext4", 1073741824),
                                      ("namespace", "namespace-generations", ".raw", 16777216)):
        pin = head[key]
        if pin["bytes"] != size: raise ValueError("wrong saved generation size")
        original = common.checked_file(Path(pin["path"]), pin)
        relative = folder + "/" + pin["sha256"] + suffix
        destination = target / relative; destination.parent.mkdir(parents=True)
        shutil.copyfile(original, destination); destination.chmod(0o444)
        if destination.stat().st_size != size or sha(destination) != pin["sha256"]:
            raise ValueError("seed copy changed")
        generations[key] = {"relative_path": relative, "bytes": size, "sha256": pin["sha256"]}
    (target / "source-head.json").write_bytes(selected)
    qualification_head = head
    session = Path(head.get("session", ""))
    if session.parent != source:
        original_head_path = source / "source-head.json"
        original_bytes = original_head_path.read_bytes()
        original_head = json.loads(original_bytes)
        if (head.get("fork_origin", {}).get("head_sha256") != hashlib.sha256(original_bytes).hexdigest()
                or any(any(head[key][field] != original_head[key][field] for field in ("bytes", "sha256"))
                       for key in ("disk", "namespace"))):
            raise ValueError("fork saved pair lacks matching original selected head")
        qualification_head = original_head
        session = Path(original_head.get("session", ""))
        if session.parent != Path(fork["source"]):
            raise ValueError("original paired save is outside its declared fork source")
    paired_file = session / "result.json"
    paired_bytes = paired_file.read_bytes()
    paired = json.loads(paired_bytes)
    if (paired.get("schema") != "ostadix.unified-world-session/v1" or paired.get("ok") is not True
            or paired.get("after") != qualification_head
            or any(paired.get(key) is not True for key in
                   ("paired_snapshot", "virtual_cpu_stopped", "native_operations_quiescent"))):
        raise ValueError("selected seed has no completed quiescent paired save")
    (target / "paired-save.json").write_bytes(paired_bytes)
    def pin(path): return {key: value for key, value in identity(path).items() if key != "path"}
    seed = {"schema": "ostadix.x12-live-state-seed/v1", "saved_pair": True,
            "source_head": pin(target / "source-head.json"), "generations": generations,
            "paired_save": pin(target / "paired-save.json")}
    save(target / "seed.json", seed)
    if (source / "head.json").read_bytes() != selected:
        raise ValueError("private selected seed head changed during copy")
    return {"source_fork": identity(source / "fork.json"), "source_head": identity(source / "head.json"),
            "manifest": identity(target / "seed.json"), "generations": generations}


def build(args, output: Path, record: dict) -> None:
    carrier = args.carrier.resolve(strict=True)
    data = json.loads((carrier / "carrier.json").read_bytes())
    if data.get("schema") != CARRIER_SCHEMA or data.get("ok") is not True:
        raise ValueError("completed carrier required")
    verify_inventory(carrier / "root", data["root_inventory"])
    if sha(carrier / "vmlinuz") != data["copied_kernel"]["sha256"]:
        raise ValueError("carrier kernel changed")
    root = output / "root"
    run(record, "copy-carrier", [tool("cp"), "-a", "--reflink=auto", carrier / "root", root], output)
    record["carrier"] = identity(carrier / "carrier.json")
    extra = Capture(root, record)
    extra.elf(tool("setfont"), "/usr/bin/setfont")
    extra.file(Path("/usr/share/consolefonts/Uni3-TerminusBold32x16.psf.gz"),
               "/usr/share/consolefonts/Uni3-TerminusBold32x16.psf.gz")
    if Path("/usr/share/doc/kbd").is_dir():
        extra.tree(Path("/usr/share/doc/kbd"), "/usr/share/doc/kbd")
    record["runtime"] = copy_runtime(args.runtime, root / "opt/okernel/runtime")
    run(record, "runtime-self-check", [PAYLOAD_PYTHON, "-B", root / "opt/okernel/runtime/okernel-unified", "check"], output)
    record["seed"] = saved_seed(args.state_seed, root / "opt/okernel/seed")
    for source, destination in (("init", "usr/sbin/init"), ("session", "usr/local/sbin/okernel-live-session"),
                                 ("network", "usr/local/sbin/okernel-network"), ("dhcp", "usr/lib/okernel/dhcp"),
                                 ("interface.py", "usr/lib/okernel/interface.py"),
                                 ("seed.py", "usr/lib/okernel/seed.py")):
        target = root / destination; target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink(): target.unlink()
        shutil.copyfile(LIVE / source, target); target.chmod(0o555)
    record.update(release=data["release"], kernel=data["copied_kernel"], source_payloads={name: identity(LIVE / name) for name in ("init", "session", "seed.py", "bootstrap-init", "network", "dhcp", "interface.py")},
                  scope=__doc__, physical_hardware_qualified=False, native_driver_lowering=False,
                  root_mounts="read-only ISO and SquashFS, tmpfs overlay; internal NVMe/SATA never mounted",
                  persistence="volatile RAM state and packages; no durable installation or automatic disk selection")
    (root / "usr/share/okernel").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(LIVE / "README.md", root / "usr/share/okernel/README.md")
    # Only stable content identities enter the image. Absolute build-output
    # paths, wall-clock times and command logs belong to the external receipt.
    def pin(item): return {key: item[key] for key in ("bytes", "sha256")}
    image_metadata = {"schema": ISO_SCHEMA, "scope": __doc__, "release": data["release"],
        "kernel": pin(data["copied_kernel"]), "carrier_manifest": pin(record["carrier"]),
        "runtime_manifest": pin(record["runtime"]["manifest"]),
        "saved_seed_manifest": pin(record["seed"]["manifest"]),
        "helpers": {name: pin(item) for name, item in record["source_payloads"].items()},
        "source_date_epoch": EPOCH, "physical_hardware_qualified": False,
        "native_driver_lowering": False, "persistent_storage": False,
        "module_count": data["module_count"], "firmware_entry_count": data["firmware_file_count"],
        "root_mounts": record["root_mounts"], "persistence": record["persistence"]}
    save(root / "usr/share/okernel/image.json", image_metadata)
    record["root_inventory"] = inventory(root)
    stage = output / "iso-tree"; (stage / "boot/grub").mkdir(parents=True)
    shutil.copyfile(carrier / "vmlinuz", stage / "boot/vmlinuz")
    run(record, "squashfs", [tool("mksquashfs"), root, stage / "boot/rootfs.squashfs", "-noappend", "-all-root",
        "-comp", "zstd", "-Xcompression-level", "9", "-processors", "1", "-no-progress",
        "-mkfs-time", str(EPOCH), "-all-time", str(EPOCH)], output, 1800,
        environment={"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": None})
    squash = identity(stage / "boot/rootfs.squashfs")
    bootstrap = output / "bootstrap"
    bootstrap.mkdir()
    for directory in ("bin", "sbin", "etc", "dev", "proc", "sys", "usr/lib/modules"):
        (bootstrap / directory).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / "usr/bin/busybox", bootstrap / "bin/busybox"); (bootstrap / "bin/busybox").chmod(0o555)
    for name in subprocess.check_output(["/usr/bin/busybox", "--list"], text=True).splitlines():
        path = bootstrap / "bin" / name
        if not path.exists(): path.symlink_to("busybox")
    (bootstrap / "lib").symlink_to("usr/lib")
    # Preserve exactly the closure selected by depmod/modprobe in the copied tree.
    module_root = root / "usr/lib/modules" / data["release"]
    required = set()
    for module in ("isofs", "overlay", "loop", "usb_storage", "uas", "sd_mod", "sr_mod", "ahci", "ata_piix", "virtio_pci", "virtio_blk"):
        query = subprocess.run([str(tool("modprobe")), "-d", str(root), "-S", data["release"], "--show-depends", module], capture_output=True, text=True, timeout=30)
        if query.returncode: raise ValueError("bootstrap module closure missing: " + module + ": " + query.stderr)
        for line in query.stdout.splitlines():
            if line.startswith("insmod "):
                path = Path(line.split()[1]).resolve(strict=True); required.add(path)
    for source in required:
        relative = source.relative_to(module_root)
        target = bootstrap / "usr/lib/modules" / data["release"] / relative
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, target)
    for source in module_root.glob("modules.*"):
        if source.is_file():
            target = bootstrap / "usr/lib/modules" / data["release"] / source.name
            target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, target)
    shutil.copyfile(LIVE / "bootstrap-init", bootstrap / "init"); (bootstrap / "init").chmod(0o555)
    (bootstrap / "etc/okernel-rootfs.identity").write_text("ROOTFS_SHA256=" + squash["sha256"] + "\n")
    archive = output / "bootstrap.cpio"; newc(bootstrap, archive)
    with (stage / "boot/initramfs.gz").open("xb") as destination:
        outcome = subprocess.run([str(tool("gzip")), "-n", "-9", "-c", str(archive)], stdout=destination, stderr=subprocess.PIPE, timeout=300)
    if outcome.returncode: raise ValueError("bootstrap compression failed")
    (stage / "OKERNEL_X12_LIVE").write_text(ISO_SCHEMA + "\n")
    config = '''set timeout=8
set default=0
set gfxpayload=keep
insmod all_video
insmod serial
serial --unit=0 --speed=115200
terminal_input console serial
terminal_output console serial
menuentry "OKernel X12 development (Linux-hosted O-core console)" {
    linux /boot/vmlinuz console=tty0 rdinit=/init quiet
    initrd /boot/initramfs.gz
}
menuentry "OKernel serial test console (ttyS0)" --hotkey=s {
    linux /boot/vmlinuz console=ttyS0,115200n8 okernel.console=serial rdinit=/init
    initrd /boot/initramfs.gz
}
'''
    (stage / "boot/grub/grub.cfg").write_text(config)
    record["attributions"] = (retained_attributions(args.notices_from, stage)
        if args.notices_from else attribution_append(stage, record))
    record["stage_inventory"] = inventory(stage)
    assemble(stage, output, record)
    record.update(squashfs=squash, bootstrap=identity(stage / "boot/initramfs.gz"),
                  bootstrap_module_paths=[str(p.relative_to(root)) for p in sorted(required)], ok=True)
    verify_inventory(carrier / "root", data["root_inventory"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    carrier = sub.add_parser("carrier", help="capture local original Linux driver/Python shell closure")
    carrier.add_argument("--output", type=Path, required=True)
    carrier.add_argument("--release", default=RELEASE)
    carrier.add_argument("--kernel", type=Path)
    carrier.add_argument("--modules", type=Path)
    carrier.add_argument("--firmware", type=Path, default=Path("/usr/lib/firmware"))
    iso = sub.add_parser("build", help="assemble a new carrier plus exact frozen runtime and saved pair")
    iso.add_argument("--output", type=Path, required=True)
    iso.add_argument("--carrier", type=Path, required=True)
    iso.add_argument("--runtime", type=Path, required=True)
    iso.add_argument("--state-seed", type=Path, required=True)
    iso.add_argument("--notices-from", type=Path,
                     help="retain exact audited notices/dash from a completed captured ISO assembly")
    repacked = sub.add_parser("repack", help="reuse verified boot payloads and append installed attribution notices")
    repacked.add_argument("--output", type=Path, required=True)
    repacked.add_argument("--from-build", type=Path, required=True)
    args = parser.parse_args()
    output = new_output(args.output)
    record = {"schema": CARRIER_SCHEMA if args.action == "carrier" else ISO_SCHEMA, "ok": False,
              "started_unix_seconds": time.time(), "output": str(output), "builder": identity(Path(__file__).resolve()),
              "host": {"uname": list(os.uname()), "python": sys.version}, "commands": [], "live_vm_actions": []}
    name = "carrier.json" if args.action == "carrier" else "result.json"
    try:
        source_capture = output / "source-inputs"
        source_capture.mkdir()
        sources = [Path(__file__).resolve(), *(LIVE / name for name in
                    ("bootstrap-init", "init", "session", "seed.py", "network", "dhcp", "interface.py", "README.md"))]
        if args.action in ("build", "repack"):
            sources.extend([ROOT / "scripts/okernel_package_domain.py", ROOT / "scripts/ostadix_xorriso_reproducible.py"])
        sources.append(ROOT / "scripts/ostadix_boot_iso.py")
        record["source_before"] = []
        for source in sources:
            selected = identity(source)
            destination = source_capture / source.name
            shutil.copyfile(source, destination)
            if sha(destination) != selected["sha256"]: raise ValueError("source snapshot raced")
            record["source_before"].append({"selected": selected, "captured": identity(destination)})
        if args.action == "carrier": prepare(args, output, record)
        elif args.action == "build": build(args, output, record)
        else: repack(args, output, record)
        for source in record["source_before"]:
            if identity(Path(source["selected"]["path"])) != source["selected"]:
                raise ValueError("builder/bootstrap source changed during construction")
        record["source_inputs_unchanged"] = True
    except BaseException as error:
        record.update(ok=False, error=type(error).__name__ + ": " + str(error))
        save(output / name, record)
        print("OKernel X12 ISO: FAIL: " + str(error) + "\nEvidence: " + str(output / name), file=sys.stderr)
        return 1
    record["finished_unix_seconds"] = time.time()
    save(output / name, record)
    print("OKernel X12 " + args.action + ": PASS\nEvidence: " + str(output / name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
