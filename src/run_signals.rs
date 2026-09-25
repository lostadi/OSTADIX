//! Invocation-scoped signal handling shared by the native execution entry points.

use o_lang::cancellation::CancellationToken;
use std::io;

pub(super) struct RunSignals {
    cancellation: CancellationToken,
    #[cfg(unix)]
    unix: UnixSignals,
}

#[cfg(unix)]
struct UnixSignals {
    first: std::sync::Arc<std::sync::atomic::AtomicI32>,
    registrations: Vec<signal_hook::SigId>,
}

impl RunSignals {
    pub(super) fn new() -> io::Result<Self> {
        let cancellation = CancellationToken::new();
        #[cfg(unix)]
        {
            use signal_hook::consts::signal::{SIGINT, SIGTERM};
            use std::sync::atomic::{AtomicI32, Ordering};
            use std::sync::Arc;

            let first = Arc::new(AtomicI32::new(0));
            let mut unix = UnixSignals {
                first,
                registrations: Vec::new(),
            };
            for signal in [SIGINT, SIGTERM] {
                let observed = Arc::clone(&unix.first);
                let request = cancellation.clone();
                // SAFETY: the callback only performs lock-free atomic operations
                // and signal-hook's async-signal-safe termination operations.
                // CancellationToken::cancel only stores its own atomic flag.
                // Latching here avoids losing queued iterator events at shutdown.
                let registration = unsafe {
                    signal_hook::low_level::register(signal, move || {
                        if observed
                            .compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                        {
                            request.cancel();
                        } else {
                            // A second signal explicitly forces termination. As with
                            // SIGKILL, execution may end without a terminal record.
                            let _ = signal_hook::low_level::emulate_default_handler(signal);
                            signal_hook::low_level::exit(128 + signal);
                        }
                    })?
                };
                unix.registrations.push(registration);
            }
            Ok(Self { cancellation, unix })
        }
        #[cfg(not(unix))]
        Ok(Self { cancellation })
    }

    pub(super) fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Remove handlers only after execution, cleanup, and record finalization.
    pub(super) fn finish(mut self) -> Option<i32> {
        #[cfg(unix)]
        {
            self.unix.stop();
            let signal = self.unix.first.load(std::sync::atomic::Ordering::SeqCst);
            (signal != 0).then_some(signal)
        }
        #[cfg(not(unix))]
        {
            let _ = &mut self;
            None
        }
    }
}

#[cfg(unix)]
impl UnixSignals {
    fn stop(&mut self) {
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

#[cfg(unix)]
impl Drop for UnixSignals {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(super) fn terminate(signal: i32) -> ! {
    #[cfg(unix)]
    let _ = signal_hook::low_level::emulate_default_handler(signal);
    std::process::exit(128 + signal);
}
