// Test-only same-module instrumentation appended to an exact archived copy of
// production scheduler.oc by verify.py. Never linked by ordinary kernel builds.
// It constructs invalid trusted-native internal state, not a guest API.
static mut TEST_ENTRY_SIDE_EFFECTS: u64 = 0;
pub unsafe fn idle_probe_negative(kind: u64) -> u64 {
    if kind == 1 { return kernel_scheduler_syscall_enter(SYSCALL_FRAME); }
    if kind == 2 {
        if request_sleep(2) != SYSCALL_CONTROL_SCHEDULE { return 99; }
        PENDING_SERIAL = SYSCALL_SERIAL + 1;
        return kernel_scheduler_syscall_route(SYSCALL_CONTROL_SCHEDULE);
    }
    if kind == 3 {
        volatile_store((SYSCALL_FRAME as *mut u64) + 14, SYSCALL_NUMBER + 1);
        return kernel_scheduler_syscall_route(0);
    }
    if kind == 4 {
        volatile_store((SYSCALL_FRAME as *mut u64) + 15, 32);
        return kernel_scheduler_syscall_route(0);
    }
    if kind == 5 {
        SYSCALL_IDLE_DISPOSITION = 1;
        return kernel_scheduler_take_idle(0);
    }
    if kind == 6 {
        SYSCALL_IDLE_DISPOSITION = 1;
        return kernel_scheduler_take_idle(SYSCALL_FRAME);
    }
    if kind == 7 {
        let frame: usize = SYSCALL_FRAME;
        if request_yield() != SYSCALL_CONTROL_SCHEDULE
            || kernel_scheduler_syscall_route(SYSCALL_CONTROL_SCHEDULE) != 2 { return 99; }
        volatile_store((frame as *mut u64) + 14, 0);
        return kernel_scheduler_syscall(frame as *mut u64) as u64;
    }
    if kind == 8 {
        let frame: usize = SYSCALL_FRAME;
        if request_sleep(2) != SYSCALL_CONTROL_SCHEDULE
            || kernel_scheduler_syscall_route(SYSCALL_CONTROL_SCHEDULE) != 2 { return 99; }
        volatile_store((frame as *mut u64) + 14, 0);
        return kernel_scheduler_syscall((frame + 8) as *mut u64) as u64;
    }
    if kind == 9 {
        SYSCALL_IDLE_DISPOSITION = 2;
        return kernel_scheduler_take_idle(0);
    }
    if kind == 10 {
        let frame: usize = SYSCALL_FRAME;
        clear_syscall_entry(); SYSCALL_SERIAL = 0xffff_ffff_ffff_ffff;
        return kernel_scheduler_syscall_enter(frame);
    }
    if kind == 18 { CONTEXT_SWITCHES = 1; return enable_personality_idle(); }
    if kind == 19 || kind == 20 {
        let frame: usize = SYSCALL_FRAME;
        let thread: u64 = SYSCALL_THREAD;
        clear_syscall_entry();
        if kind == 19 { ocore_context_install(ocore_management_cr3(), kernel_stack_for(thread)); }
        else { ocore_context_install(root_cr3(address_space_for_thread(thread)), ocore_management_stack_top()); }
        let admitted: u64 = kernel_scheduler_syscall_enter(frame);
        if admitted == 1 { TEST_ENTRY_SIDE_EFFECTS += 1; }
        return admitted;
    }
    return 99;
}
