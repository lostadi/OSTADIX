# Ostadix radio diagnostics

This directory provides a deliberately narrow, read-only diagnostics workflow
for this Google `blazer` / `G4QUR` device. Hardware-facing commands require
the exact system and vendor fingerprint
`google/blazer/blazer:17/CP2A.260805.005/15828068:user/release-keys`, the
`2026-08-05` security patch, and baseband
`g5400i-260317-260429-B-15308590,g5400i-260317-260429-B-15308590`.
Any mismatch refuses execution, with no bypass flag.

The tool mirrors mounted firmware and copies existing diagnostic artifacts; it
does not expose the baseband's live diagnostic interface. Cellular diagnostic
data can contain subscriber identifiers, nearby cell information, location
clues, call/SMS metadata, and packet contents. Treat every generated artifact
as highly sensitive.

## Safety boundary

The CLI:

- verifies the exact system fingerprint, vendor fingerprint, device, SKU,
  security patch, and baseband listed above before hardware/file operations;
- keeps outputs outside the repository and ordinary backup paths under
  `/data/data/com.termux/no_backup/ostadix-radio-diagnostics/`, using a `077`
  umask (files are created as mode `0600`);
- reads only regular files in narrow firmware or vendor-log allowlists;
- hard-bounds every copy and parser output and reserves 64 MiB of free space;
- never reads from or writes to `/dev`, modem partitions, sysfs, procfs, shared
  storage, USB DM interfaces, or serial DM interfaces;
- never remounts a filesystem or changes permissions/ownership of device nodes,
  firmware, or vendor files;
- never changes persistent properties and never starts/stops vendor logging
  services; and
- forces SCAT to use `-F` (its local PCAP writer), never its default UDP writer.

There is intentionally no "expose everything" mode. Live DM and write access
would weaken the radio/security boundary and can disrupt emergency calling or
brick radio firmware.

## Commands

From the repository root:

```bash
tools/radio-diagnostics/radio-diagnostics status
tools/radio-diagnostics/radio-diagnostics capabilities
tools/radio-diagnostics/radio-diagnostics self-test
```

`status` and `capabilities` are non-mutating and can run off-target. The other
commands require the exact build; reading protected files/log buffers also
requires root.

### Mirror mounted modem firmware

```bash
tools/radio-diagnostics/radio-diagnostics mirror-firmware
```

The tool locates a regular file named exactly `modem.bin` in an allowlisted
mounted firmware tree, enforces a 1 GiB maximum, copies exactly the initial
regular-file length, and compares source/copy/source SHA-256 plus the final
source length. A growing or changing source cannot overrun the bound. If more
than one source exists it stops and asks for an explicit selection:

```bash
tools/radio-diagnostics/radio-diagnostics mirror-firmware \
  --source /mnt/vendor/modem_img/images/g5400i-260317-260429-B-15308590/modem.bin
```

It never reads a raw block device and the mirrored file is mode `0600`. The
result contains `modem.bin` plus system/vendor fingerprint, baseband, source,
size, time, ownership, and SHA-256 metadata.

### Bounded radio log

```bash
tools/radio-diagnostics/radio-diagnostics radio-log 60
```

The duration must be 1–300 seconds. With KernelSU, Toybox `timeout` and `logcat`
are launched together inside one UID-0 shell; a Termux-owned timeout is never
asked to signal a root child. The root shell applies the 64 MiB file limit,
`timeout` interrupts its direct `logcat` child and escalates to `KILL` after
three seconds. The capture also stops at 50,000 lines. Unexpected statuses fail
the command. This captures Android's `radio` log buffer, not a live modem DM
endpoint.

### Existing SDM/QMDL/LPD dumps

```bash
tools/radio-diagnostics/radio-diagnostics list-sdm
tools/radio-diagnostics/radio-diagnostics export-sdm
```

`list-sdm` prints metadata only. `export-sdm` copies regular dump files from
the narrow vendor-radio/log roots. It streams exactly the prechecked length,
compares hashes before and after, limits each file to 512 MiB and each bundle to
1 GiB, and records a manifest. A concurrently growing log cannot exceed those
limits. It never deletes or changes the source.

### Offline SCAT parsing

SCAT is an optional, separately maintained parser. This project pins both its
Python dependencies and its source revision in `requirements-scat.txt`.

SCAT 2.0.0 supports ordinary QMDL/SDM/LPD dump parsing but does not expose
`--modem-file`. Firmware-assisted Samsung trace parsing therefore uses audited
upstream commit `361ff551a4fbb30789c46750c00586682a7a9b26`, which adds that
feature. The CLI checks both the installed feature and the PEP 610
`direct_url.json` commit before parsing anything.

To recreate `.venv`, preferably use an audited offline wheel/cache. If fetching
is explicitly acceptable, the requirement still resolves SCAT to that immutable
commit:

```bash
cd tools/radio-diagnostics
python -m venv .venv
.venv/bin/pip install -r requirements-scat.txt
```

Return to the repository root and parse only a previously exported private
file:

```bash
tools/radio-diagnostics/radio-diagnostics parse-scat sec \
  /data/data/com.termux/no_backup/ostadix-radio-diagnostics/sdm-export-.../files/0001-capture.sdm
```

For a raw Samsung SDM without a start response, add a conservative model
override. Firmware-assisted trace decoding accepts only a private firmware
mirror:

```bash
DUMP=/data/data/com.termux/no_backup/ostadix-radio-diagnostics/sdm-export-.../files/0001-capture.sdm
MODEM=/data/data/com.termux/no_backup/ostadix-radio-diagnostics/firmware-.../modem.bin
tools/radio-diagnostics/radio-diagnostics parse-scat sec "$DUMP" \
  --model MODEL --gsmtapv3 --trace --modem-file "$MODEM"
```

The default layers are control-plane-only `nas,rrc`. User-plane-bearing layers
such as `ip`, `pdcp`, `rlc`, and `mac` require an explicit `--layers`
choice and substantially increase privacy risk.

The wrapper accepts only dump-file input and always supplies a local PCAP
output through SCAT's `-F` writer. It exposes no SCAT USB, serial, hostname, or
port arguments. Input is limited to 512 MiB; runtime is limited to 300 seconds;
the PCAP and parser log are each capped at 512 MiB. See the
[pinned upstream source](https://github.com/fgsect/scat/tree/361ff551a4fbb30789c46750c00586682a7a9b26).

## Enabling vendor diagnostics

This tool does not automate the build-specific `vendor.modem_logging_start` /
`vendor.modem_logging_stop` services. A shell interruption, SELinux denial, or
reboot could otherwise leave persistent, privacy-sensitive logging enabled.

If an existing dump is required, manually enable **verbose vendor logging** in
Android's Developer Options (the exact label can vary), reproduce the issue for
the shortest practical time, then turn it off in the UI. Afterward use
`list-sdm` / `export-sdm`. If the build exposes no dump, use `radio-log`; do not
enable a USB diagnostic composition or change any `/dev` permissions.

## Tests

```bash
tools/radio-diagnostics/tests/self-test.sh
```

The tests exercise the fingerprint matcher, duration limit, fixed root capture
command, Toybox timeout escalation/reaping, device-path rejection, SCAT layer
allowlist, and private file mode. They do not request root, start logging,
inspect `/dev`, or touch vendor files.
