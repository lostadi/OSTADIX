// Test-only same-module controls; exact production prefix is captured before
// composition. No ordinary build includes or exports these privileged hooks.
pub unsafe fn exit_probe_negative(kind: u64) -> u64 {
    let frame: usize = SYSCALL_FRAME;
    if kind == 7 { PENDING_LINUX_EXIT = 1; return kernel_scheduler_syscall_route(SYSCALL_CONTROL_SCHEDULE); }
    if request_linux_process_exit(SYSCALL_NUMBER, 0) != SYSCALL_CONTROL_SCHEDULE { return 99; }
    if kind == 6 { PENDING_SERIAL = SYSCALL_SERIAL + 1; return kernel_scheduler_syscall_route(SYSCALL_CONTROL_SCHEDULE); }
    if kind == 9 { SYSCALL_NUMBER = 231; return kernel_scheduler_syscall_route(SYSCALL_CONTROL_SCHEDULE); }
    if kind == 8 { PENDING_ACTION = 2; }
    if kind == 11 { PENDING_LINUX_EXIT = 2; }
    if kind == 12 { PENDING_EXIT_STATUS = 1; }
    if kind == 13 { PENDING_LINUX_EXIT = 0; }
    if kernel_scheduler_syscall_route(SYSCALL_CONTROL_SCHEDULE) != 2 { return 98; }
    volatile_store((frame as *mut u64) + 14, 0);
    if kind == 14 { volatile_store((frame as *mut u64) + 19, 0x200); }
    if kind == 10 { return kernel_scheduler_syscall((frame + 8) as *mut u64) as u64; }
    return kernel_scheduler_syscall(frame as *mut u64) as u64;
}
