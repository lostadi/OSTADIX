#!/usr/bin/env python3
"""Small local control panel for the volatile Linux-hosted OKernel image.

Runs on the boot machine's existing terminal, using only Python's standard
library and the admitted helpers. It never selects or mounts a physical disk.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


PYTHON = "/usr/bin/python3"
RUNTIME = "/opt/okernel/runtime/okernel-unified"
STATE = "/run/okernel/state"
NETWORK = "/usr/local/sbin/okernel-network"


def visible(value: object) -> str:
    """Do not let a device name or child error control the local terminal."""
    return "".join(char if char == "\n" or char == "\t" or 32 <= ord(char) < 127
                   else "?" for char in str(value))


class Services:
    def runtime(self, action: str, *, interactive: bool = False):
        return self.run([PYTHON, "-B", RUNTIME, "--state", STATE, action], interactive=interactive)

    def run(self, command: list[str], *, interactive: bool = False):
        # All commands/paths are fixed by this image. User input is never a
        # shell program or interpolated into a command argument.
        return subprocess.run(command, check=False, text=True,
                              stdin=None if interactive else subprocess.DEVNULL,
                              stdout=None if interactive else subprocess.PIPE,
                              stderr=None if interactive else subprocess.STDOUT)

    def diagnostics(self) -> str:
        return diagnostics()


def diagnostics(root: Path = Path("/")) -> str:
    def read(relative: str, limit: int = 32768) -> str:
        try:
            with (root / relative).open("r", encoding="utf-8", errors="replace") as stream:
                return stream.read(limit)
        except OSError:
            return ""

    lines = ["LOCAL HARDWARE AND DRIVERS", "Kernel: " + os.uname().release]
    try:
        terminal = os.ttyname(0)
    except OSError:
        terminal = "no keyboard terminal attached"
    lines.append("Terminal: " + terminal)
    try:
        image = json.loads(read("usr/share/okernel/image.json"))
        lines.append("Image modules: " + str(image["module_count"]) +
                     "    Firmware entries: " + str(image["firmware_entry_count"]))
    except (ValueError, KeyError, TypeError):
        lines.append("Image driver inventory is unavailable; see /usr/share/okernel/image.json.")
    modules = read("proc/modules", 2 * 1024 * 1024)
    lines.append("Loaded modules: " + str(len(modules.splitlines())) if modules
                 else "Loaded-module information is unavailable.")
    lines.extend(["", "Display:"])
    displays = []
    for entry in sorted((root / "sys/class/graphics").glob("fb*")):
        name = read(str(entry.relative_to(root) / "name")).strip()
        if name:
            displays.append("  " + entry.name + ": " + name)
    for entry in sorted((root / "sys/class/drm").glob("card*-*")):
        status = read(str(entry.relative_to(root) / "status")).strip()
        if status:
            displays.append("  " + entry.name + ": " + status)
    lines.extend(displays or ["  No display is reported. Serial terminals can still be used."])
    lines.extend(["", "Keyboard and pointer devices:"])
    inputs = read("proc/bus/input/devices")
    selected = ["  " + line[3:] for line in inputs.splitlines()
                if line.startswith(("N: ", "H: "))]
    lines.extend(selected or ["  No input devices are reported. Check USB/I2C drivers and the keyboard connection."])
    lines.extend(["", "Network interfaces:"])
    networks = []
    for entry in sorted((root / "sys/class/net").glob("*")):
        if entry.name != "lo":
            networks.append("  " + entry.name + ": " +
                            (read(str(entry.relative_to(root) / "operstate")).strip() or "state unavailable"))
    lines.extend(networks or ["  No network interface is reported. Check its driver and firmware."])
    lines.extend(["", "A listed device or included driver does not prove every function works.",
                  "Fingerprint, camera, audio and cellular services are not configured by this image."])
    return visible("\n".join(lines))


HELP = """USING OKERNEL

Open terminal gives you the common Linux / Plan 9 working environment.
Inside it, use help for commands, pkg for package operations, and p9 for
original Plan 9 programs. The common workspace is /n/okernel/work.

Type exit or quit at the main OKernel prompt to save and return here.
Ctrl+] also saves and stops. Ctrl+B then d detaches while it keeps running;
Open terminal reconnects to that same session.

Save and stop waits for the existing paired-save checks. A failed save keeps
this panel open and prevents its poweroff action. Do not power off to recover
from a failed save without first reviewing the error.

This live image uses RAM. Saves support resume during this boot only.
Packages, shared files, network settings and logs disappear on poweroff.
The image does not install itself or mount your internal filesystems.

Display, keyboard and device access use this image's original Linux drivers.
The interface itself is a small userspace program, not a kernel GUI.
Device functionality on your physical machine needs its own verification.
"""


class Panel:
    def __init__(self, services: Services | None = None, source=None, output=None):
        self.services = services or Services()
        self.source = source if source is not None else sys.stdin
        self.output = output if output is not None else sys.stdout

    def write(self, message: str = ""):
        print(message, file=self.output, flush=True)

    def read(self, prompt: str) -> str | None:
        print(prompt, end="", file=self.output, flush=True)
        text = self.source.readline()
        return text.rstrip("\r\n") if text else None

    def result(self, result, label: str) -> bool:
        if result.stdout:
            self.write(visible(result.stdout).rstrip())
        if result.returncode != 0:
            self.write(label + " failed (status " + str(result.returncode) + ").")
            return False
        return True

    def stop(self) -> bool:
        self.write("Saving and stopping the managed terminal...")
        return self.result(self.services.runtime("stop"), "Save and stop")

    def poweroff(self) -> bool:
        answer = self.read("Poweroff discards this boot's RAM changes. Type POWER OFF to continue: ")
        if answer != "POWER OFF":
            self.write("Poweroff cancelled.")
            return False
        return self.shutdown()

    def shutdown(self) -> bool:
        """Both local menus use the same save barrier before volatile poweroff."""
        if not self.stop():
            self.write("Poweroff blocked because the managed terminal did not stop successfully.")
            return False
        if not self.result(self.services.run(["/usr/bin/sync"]), "Sync"):
            return False
        self.write("OKERNEL X12 POWEROFF")
        return self.result(self.services.run(["/usr/bin/busybox", "poweroff", "-f"]), "Poweroff")

    def run(self) -> int:
        if not self.source.isatty():
            self.write("Local interface needs a keyboard terminal. Use the serial console or reconnect a local terminal.")
            return 2
        while True:
            self.write("\nOKERNEL | LOCAL INTERFACE\n")
            self.write("RAM session: changes disappear on poweroff. Internal filesystems stay unmounted.")
            self.write("[c] Open terminal      [s] Session status       [n] Networking")
            self.write("[d] Devices/drivers    [x] Save and stop         [h] Help")
            self.write("[p] Power off          [r] Return")
            try:
                choice = self.read("Choose an action, then Enter: ")
                if choice is None:
                    self.write("Terminal disconnected. Managed state has not been stopped or discarded.")
                    return 0
                choice = choice.strip().lower()
                if choice in ("c", "console", "terminal", ""):
                    self.write("Opening OKernel. Type exit to save and return to this interface.")
                    self.result(self.services.runtime("start", interactive=True), "Terminal")
                elif choice in ("s", "status"):
                    self.result(self.services.runtime("status"), "Session status")
                elif choice in ("n", "network"):
                    self.result(self.services.run([NETWORK], interactive=True), "Networking")
                elif choice in ("d", "devices", "drivers"):
                    self.write(self.services.diagnostics())
                elif choice in ("x", "stop", "save"):
                    self.stop()
                elif choice in ("h", "help", "?"):
                    self.write(HELP)
                elif choice in ("p", "poweroff", "shutdown"):
                    if self.poweroff():
                        return 0
                elif choice in ("r", "return", "exit", "quit"):
                    return 0
                else:
                    self.write("Unknown action. Choose one of the displayed letters; h opens help.")
            except KeyboardInterrupt:
                self.write("\nInterrupted. The managed terminal may still be running; check Session status.")
            except (OSError, ValueError, TypeError) as error:
                self.write("Action unavailable: " + visible(error))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--diagnostics", action="store_true", help="print local device/driver diagnostics")
    action.add_argument("--poweroff", action="store_true",
                        help="save/stop the managed terminal, then power off this volatile live image")
    args = parser.parse_args(argv)
    if args.diagnostics:
        print(diagnostics())
        return 0
    if args.poweroff:
        try:
            return 0 if Panel().shutdown() else 1
        except (OSError, ValueError, TypeError) as error:
            print("Poweroff blocked: " + visible(error), file=sys.stderr)
            return 1
    return Panel().run()


if __name__ == "__main__":
    sys.exit(main())
