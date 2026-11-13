# OSTADIX × iPhone 16 Pro

Mission: use the OSTADIX polyglot execution stack (O / OIR / shims / o-link /
olangc) as the operating layer for probing, mapping, and exploiting an
iPhone 16 Pro (A18 Pro, iOS 18.x, USB-C).

## Principles

1. **OSTADIX-first**: every capability ships as a `.O` program first —
   typed parens over `bash`, `python`, `nix`, `sql`, host tools. A C/Python
   helper only exists when a shim cannot express it.
2. **Read-only until a phase says otherwise.** Each phase declares its
   threat model and write surface in this file before it is exercised.
3. **Structured facts, not vibes.** Probes return O values (dicts) with a
   versioned schema; reports are rendered from facts.

## Attack-surface map (iPhone 16 Pro)

| Layer | Surface | OSTADIX angle |
|---|---|---|
| USB-C | usbmuxd/lockdown (Pair Record), AFC, house_arrest, installation_proxy, syslog, diagnostics, DTX when Developer Mode is on | `bash`/`python` shims over libimobiledevice; `sql` shim for structured evidence capture |
| Wi-Fi | Remote Service Discovery (RSD, UDP 49152+) off the Pair Record; CoreDevice/lockdown over RSD tunnel | `python` shim (pure-Python RSD client) |
| MDM/Provisioning | unsigned MDM channel (iOS 18 legacy), OTA manifests | `python` + `bash` |
| Developer Mode | DTX/instruments, debugserver, LLDB over `iproxy` | `bash` shim; PTY for interactive debuggers via o-cli/PTY |
| Boot/secure world | A18 secure boot chain, kernelcache, jailbreak posture for iOS 18.x | `nix` for toolchains; `c_cpp`/`rust` shims for payloads |
| Bluetooth | CoreBluetooth / personal hotspots | later |

## Phases

- **P0 — Recon (this directory's `recon.O`)**: host toolchain inventory,
  USB device enumeration, pair-record inventory, device property capture.
  *Read-only.*
- **P1 — Trust & services**: pairing state, TLS session properties,
  lockdownd service map (which StartService names are offered), RSD
  reachability from the Mac. *Read-only.*
- **P2 — Forensics**: live syslog capture, crash-report export, AFC browse
  of `MobileDocument`, app-container listing via house_arrest. *Read-only
  on device state.*
- **P3 — Developer-mode surface**: DTX service inventory, `debugserver`
  attach, LLDB over port-forward. *Mutates process state, not storage.*
- **P4 — Wi-Fi RSD**: pair-record → RSD probe → CoreDevice over Wi-Fi.
- **P5 — Exploit surface**: current iOS 18.x-on-A18 exploit-chain posture,
  provisioning/MDM abuse, OTA surface.

## Layout

- `recon.O` — P0 polyglot recon (bash + python, structured + report).
- `evidence/` — append-only outputs (gitignored).
- `REPORT.md` — running log of findings per phase (created in P0).

## Run

```bash
export O_LANG_ROOT=$HOME/OSTADIX
cd $O_LANG_ROOT
O apps/iphone16-pro/recon.O backends
```
