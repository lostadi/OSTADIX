# Upstream source and notices

The patch applies to the original QEMU 11.1.3 source archive from https://download.qemu.org/qemu-11.1.3.tar.xz (141,819,712 bytes; SHA-256 `5a8289c7940dc77d3873c81a6c29ba3afe1446fc9d36e77fa1658cdbecb84b22`). This identifies the retained archive; it is not a fresh publisher-signature verification.

`LICENSES/COPYING` and `LICENSES/COPYING.LIB` are byte-identical original root license texts selected from that archive. Preserve those texts, original copyright/license headers, and the applicable upstream rules when reconstructing or redistributing source. The patch does not relicense QEMU.

The seven patched files are `target/i386/cpu.h`, `target/i386/helper.h`, `target/i386/tcg/emit.c.inc`, `target/i386/tcg/fpu_helper.c`, `target/i386/tcg/translate.c`, `target/i386/machine.c`, and `linux-user/i386/signal.c`. The header-bearing target files declare LGPL-2.1-or-later; `linux-user/i386/signal.c` declares GPL-2.0-or-later. Files without individual headers retain the applicable upstream source/project terms; no new individual license is invented here. Full original source and notices remain recoverable from the exact archive plus the retained patch.

The recipe scripts and authored controls remain separate from original emulator source. This package records source/license identities; it is not a legal-compliance certification, complete external-source bundle, firmware license grant, or binary distribution.
