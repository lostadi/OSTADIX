# Interactive Linux and original Plan 9 under O-core

This guide describes the preserved two-kernel compatibility experiment. The
current target is [one native O-core service system with POSIX/Linux compatibility, original drivers and package managers](OKERNEL_UNIFIED_IMPLEMENTATION.md).
The experiment is usable within the scope below; it does not establish the
completed merge or an efficiency improvement over Linux.
The [consolidated user requirements](/home/ustad/okernel-unified-requirements.md)
define the final architecture and persistent interactive `.O` acceptance.

The unified profile runs both original kernels beneath one native O-core EL2
supervisor. They have separate RAM, CPU state, timers, interrupts and namespace
sessions. Both use the same native 9P object store. The original Plan 9 provider
contains original rc, ARM64 tools, headers and libraries; `p9` does not dispatch
to Plan9port or a host shell.

On X12, start or reconnect from a host terminal:

```sh
okernel-unified
```

`okernel-unified start --detach` starts it in the background. Use
`okernel-unified status` to check the console and `okernel-unified stop` for a
confirmed save and stop. Closing an attached terminal leaves the tmux session
running; Ctrl+B then D detaches explicitly. The older `okernel` command keeps
its separate saved state.

This installed entry selects the frozen R9 runtime and the prepared
`unified-system-20261102` state. It verifies 233 captured files before launch,
including the native monitor, original kernels, host controller and QEMU
closure. Normal startup uses those captured bytes. `okernel-unified check`
checks that inventory without starting a VM. The saved Linux disk and native
store remain writable through new coordinated generations.

From the Linux console, use ordinary Linux commands and `p9 NAME` for original
Plan 9 programs. Both resolve files in the shared workspace:

```sh
pwd                         # /n/okernel/work in Linux
p9 pwd                      # /n/work in original Plan 9
p9 echo hello
printf 'bytes\000\377\n' | p9 cat
```

Build and install an original Plan 9 program from the Linux prompt:

```sh
cd /n/okernel/work
cat > hello.c <<'EOF'
#include <u.h>
#include <libc.h>
void main(void)
{
    print("hello from original Plan 9\n");
    exits(nil);
}
EOF
p9 7c -o hello.7 hello.c
p9 7l -o hello hello.7
p9 ./hello
p9-install ./hello hello
p9 hello
```

For Linux, use `cc linux-program.c -o /work/linux-program` and run
`/work/linux-program`. Both toolchains read source files in the common workspace;
the resulting executables retain their original operating-system ABI.

Plan 9 C source uses its original headers and APIs, including `<u.h>`,
`<libc.h>` and `exits`. Linux source uses its own original compiler and ABI.
`p9 rc -I -c 'COMMAND'` explicitly selects original rc syntax. Arguments passed
to an ordinary `p9 NAME` invocation retain their argument boundaries.
Installed names resolve under `/n/packages/plan9/bin` before the read-only
original tool directory. The installer checks the original ARM64 executable
format and copies/verifies the selected bytes before publishing an absent
name. It refuses existing names and records the input identity automatically.

Linux is the main interface and driver environment. O-core schedules the
execution providers and governs their memory, interrupts, device access and
native namespace sessions. Original Plan 9 programs use that common backend
through the Linux `p9` interface; its raw console is available for diagnostics.

`pkg install NAME` installs from the configured signed APK repositories or a
registered source recipe. `pkg source zlib` and `pkg source plan9port` use the
existing original source providers. Plan9port remains a Linux program provider;
`p9` selects the original Plan 9 kernel instead. Package hashes and command
request hashes are checked internally; users do not need to type them.

`p9 --help` and `pkg help` describe the command interfaces. The invocation
budget defaults to two minutes under emulation and can be changed with
`--timeout-ms` up to five minutes. Each framed request and each captured output
stream is limited to 1 MiB. Standard input comes from a pipe or `--stdin-file`;
interactive original programs and longer jobs can use the original Plan 9
console.

The interactive native console also accepts Ctrl-^ followed by 1 to select the
original Plan 9 shell, or Ctrl-^ followed by 0 to return to Linux. Ctrl-^ is
usually Ctrl+Shift+6. Ctrl+] requests a coordinated save and stop. In tmux,
Ctrl+B followed by D detaches while leaving the system running.
The original Plan 9 console uses DEL (byte 127) to interrupt a foreground
program; the Linux `p9` client handles Ctrl+C through its recovery protocol.

## Persistence and recovery

The launcher uses an explicit private saved-state fork, a separate tmux server
and an admitted build. Reconnecting does not reseed a disk or replace user
files. Completed saves publish one disk/native-store generation pair only after
Linux sync, a stopped CPU and a native transaction boundary. This saves files
and installed packages, not running application memory.
Use Ctrl+] or `okernel-unified stop` before rebooting the host: these paired
checkpoints make guest file changes durable.

Each system boot provisions a fresh coordinator generation and original Plan 9
service instance. Request IDs, publication claims and exact completion hashes
prevent accidental replay; they are not authentication credentials. The current
policy grants a single trusted operator root read/write access through distinct
native sessions.

Cancellation requires discarding the owning Plan 9 domain: original rc can
create background processes in other note groups. O-core withdraws its grant,
clears its private RAM and complete architectural/interrupt state, then boots
the admitted original kernel with a fresh service instance. Linux survives
this replacement. Other running Plan 9 processes are terminated and must be
restarted explicitly. Save their work before cancelling a service command.
The client accepts final interrupted completion only after a native-authoritative
recovery acknowledgement.

That acknowledgement travels through a Linux-only virtual UART into protected
Linux-local control files. Plan 9 can edit shared objects, so shared ready or
recovery text alone is never evidence that native domain replacement occurred.
Unknown outcomes remain unknown and are not automatically submitted again.

Protocol history is preserved under the Linux-private
`/var/lib/okernel/p9-history` before completed records are reclaimed from the
small common volume. Recent current-instance history stays within both a
count and byte budget. Pending work is preserved, archived unknown work is
never replayed, and user workspace/program files are outside this cleanup.

## Reproducing and qualifying

The X12 [qualification record](/home/ustad/.local/state/ostadix/okernel/unified-system-20261102/qualification.json)
binds the frozen runtime, saved pair, completed terminal tests, source builds,
package installation and native reproduction proofs. Its current running VM
has a separate live observation; an in-progress session receipt is finalized
when that session saves and stops.

For an explicitly prepared stopped fork:

```sh
python3 scripts/prepare_okernel_unified.py --state PRIVATE_FORK --build ADMITTED_BUILD
scripts/okernel-unified-console.sh --state PRIVATE_FORK --build ADMITTED_BUILD start
```

The launcher also supports `start --detach`, `attach`, `status` and `stop`.
`stop` requires the controller's new paired-save receipt before reporting
success. The default older `okernel` session is a separate preserved system.

The automated acceptance scripts distinguish foreground PTY keystrokes,
original-provider component execution, native architectural stress, and byte
reproduction. Their receipts state their scope; automated typing is not a
claim of a human acceptance session.

`verify_okernel_two_domains_repro.py` reproduces the native monitor and DTBs
from captured sources with frozen compiler/tool dependencies. It also retains
a checkout-independent replay entry. Original kernel and initramfs bytes are
fixed admitted inputs to that proof; foreign compiler bootstrapping is not
claimed.

Native-build reproduction requires host Python 3.10 or newer with its standard
library, `/bin/sh`, Bash, `ldd`, and the recorded native ELF `PT_INTERP` loader.
The captured compiler/tool binaries and shared libraries support replay outside
the checkout with these declared host dependencies.

The retained R9 proof can be repeated outside the checkout:

```sh
proof="$HOME/.local/state/ostadix/okernel/two-domains-repro-20261102-r9"
replay="$(mktemp -d "$HOME/.cache/okernel-native-replay.XXXXXXXX")"
python3 "$proof/reproduce.py" --capture "$proof" --output "$replay/result"
```

The frozen launcher still requires a compatible Linux x86-64 host, Python
3.10 or newer with its standard library, `/bin/sh`, Bash, tmux, and the recorded
host ELF interpreter. It carries its QEMU libraries, modules and data. This is
a captured runtime and native-build proof, rather than a bootstrap of every
host tool or a claim that mutable package repositories will reproduce the
same disk later.

## Present scope

This is an ARM64 QEMU/TCG execution profile running on X12. Physical X12 boot,
graphics, unrestricted hardware devices, and arbitrary package repository
formats are not qualified. Current package installation uses the configured
Alpine APK repositories and declared source recipes. Original Plan 9 programs
use the admitted command/compiler closure or compatible programs built from
source. This execution profile preserves foreign engines; it does not claim
that Linux, 9front or their compilers were lowered through O-core.

This profile is slow: three real terminal `p9 echo` measurements took
9.72–15.51 seconds to first output and 14.91–19.33 seconds to validated CLI
completion. These include the cross-kernel command protocol and history
maintenance. The terminal acceptance also checks streaming before completion,
keyboard cancellation and recovery, rather than treating quiet compilation as
a successful interaction.

The common native volume is currently 16 MiB with 1,024 objects; the Linux
package disk is 1 GiB. The provider tool closure is in a separate read-only
boot PAQ rather than consuming the common store. Capacity failures must remain
visible. Plan 9 replacement is qualified separately from severe Linux/native
backend failures that can still stop the whole supervisor.
