# Native executable startup input capture

`runtime::exec_startup_capture::configure_current` copies a current native
process's pathname, argument vector and environment through the production
checked user-memory interface into a validated ELF plan's initial stack.
This is process-start preparation, **not a Linux `execve` syscall**. It is not
registered as syscall 59, and it does not replace a running address space.

The trusted process-start owner supplies the plan and a seven-word immutable
policy descriptor: entropy pointer, entropy length (16), UID, effective UID,
GID, effective GID and secure-execution flag. The owner must obtain entropy
and credentials from its platform policy and authorize the executable/plan.
The function does not bind an arbitrary plan to the current process or make
user-selected plan handles or policy pointers safe to expose as syscall
arguments.

Pathname and vector/string bytes are copied from the actual current process's
address space. The module preserves raw argument bytes, including empty
arguments; null vectors explicitly mean empty vectors in this native profile.
Linux empty-argv normalization is not supplied. Pathnames include their NUL
within the 4096-byte bound. Argument and environment storage derives from the
loader's existing 16 KiB stack; the loader also checks the combined strings,
pointer tables, auxiliary vector and alignment. Exhaustion reports an error
without replacing a previously configured stack. No caller pointers or copied
scratch contents survive a completed call.

The process-start owner must serialize calls with scheduling, source writes,
mapping changes and loader operations. The reentry guard is not an SMP lock.
Path resolution, executable authority, address-space replacement, thread
termination, close-on-exec descriptors, TLS reset, signal state and final
execution admission still require the surrounding exec transaction.

Run the native carrier tests with an explicitly selected built compiler:

```sh
OCOREC_BIN=/path/to/ocorec python3 -B -m unittest \
  tests.test_exec_startup_capture tests.test_linux_initial_stack -v
```

The tests execute the production process, capability, address-space,
user-memory and ELF-loader modules. They replace immutable image delivery
and five privileged architecture hooks. Every copy position is separately
faulted, including pointer words and strings; previous stack bytes remain
unchanged. Capacity, raw-byte, authority, unmapped-range, stale-plan and
reentry cases are checked. A child actually enters the fixture ELF with the
user-captured argument/environment/auxv stack and checks it at entry.
The host kernel supplies that child's execution context; this is not an
original application, protected-kernel exec, or hardware copy-fault proof.
