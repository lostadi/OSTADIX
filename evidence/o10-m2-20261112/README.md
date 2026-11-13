# M2 reset helper candidate

This is an uncommitted component candidate, **not an M2 milestone pass**.
The exact copied M1 R5 sources are recorded in base-source.json; M1 itself
was not changed. Final lineage inheritance is pending parent integration.

final-components/result.json records19 passing tests without skips, including
four native reset scenarios, plus the language check:262 sources parsed as
expected,0 failed. The new image module compiles AArch64 MIR and executes as
native x86_64 code in the mapped-memory fixture.

The native corpus verifies every byte of512MiB private Linux RAM after reload,
a real held block read discarded without guest completion writes, stale queue
disablement, generation exhaustion, stale ownership refusing to revoke a new
session, unbound provisioning that mints no authority, and preservation of
Plan9's real namespace session/fid and RAM/disk canaries. Unknown architecture
calls abort in the host model; these are not guest architectural-reset proofs.

The helpers never call cold kw_monitor_init, shared namespace init, peer init
or physical network init during replacement. Image registration is boot-only
and separate from unresolved O10 image-handle binding. Its source windows are
d2000000/da000000/e2000000; Linux kernel size is capped at126MiB to avoid its
DTB destination, initrd at128MiB and DTB at64KiB.

O10 integration, bootloader metadata, VMID/vCPU/vGIC reset, Linux policy,
explicit ESTALE error mapping and real APK/ext4 recovery gates remain. No
QEMU, disk fork, physical media write, commit, merge or publication occurred.
