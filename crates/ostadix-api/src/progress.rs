//! One stderr writer for runtime status: the step spinner, hang warnings and
//! forwarded backend stderr.
//!
//! why one writer: a spinner is a line without a newline that is redrawn in
//! place. any other stderr text written while it is on screen would land in
//! the middle of it. every status line therefore goes through here, which
//! clears the spinner first and redraws it only at a line boundary. stdout is
//! never touched.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

static QUIET: AtomicBool = AtomicBool::new(false);
static SCREEN: Mutex<Screen> = Mutex::new(Screen::new());

/// Silence the spinner (`O --quiet`, MCP and other embedders). Warnings are
/// still written; they are ordinary stderr lines.
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

#[cfg(test)]
thread_local! {
    static FORCE_SPINNER: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    static CAPTURE: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn force_spinner_for_test(enabled: Option<bool>) {
    FORCE_SPINNER.with(|cell| cell.set(enabled));
}

/// Capture status lines written on this thread instead of printing them.
#[cfg(test)]
pub(crate) fn capture_lines_for_test(enabled: bool) -> Vec<String> {
    CAPTURE.with(|cell| {
        let previous = cell.borrow_mut().take().unwrap_or_default();
        if enabled {
            *cell.borrow_mut() = Some(Vec::new());
        }
        previous
    })
}

/// The spinner draws only for an interactive stderr. It is off with
/// `--quiet`, under the MCP server (which sets `O_QUIET`), in CI (`CI`) and
/// when `NO_COLOR` is set.
pub fn spinner_enabled() -> bool {
    #[cfg(test)]
    if let Some(forced) = FORCE_SPINNER.with(std::cell::Cell::get) {
        return forced;
    }
    static ENVIRONMENT_ALLOWS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let environment_allows = *ENVIRONMENT_ALLOWS.get_or_init(|| {
        let set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
        !set("O_QUIET") && !set("CI") && !set("NO_COLOR")
    });
    !QUIET.load(Ordering::Relaxed) && environment_allows && std::io::stderr().is_terminal()
}

/// Write one complete status line (a newline is added).
pub fn line(text: &str) {
    #[cfg(test)]
    {
        let captured = CAPTURE.with(|cell| {
            if let Some(lines) = cell.borrow_mut().as_mut() {
                lines.push(text.to_string());
                true
            } else {
                false
            }
        });
        if captured {
            return;
        }
    }
    let mut screen = SCREEN.lock().unwrap_or_else(|poison| poison.into_inner());
    let mut stderr = std::io::stderr().lock();
    screen.line(&mut stderr, text);
}

/// Draw or redraw the spinner for a running step.
pub fn spinner(label: &str, elapsed: Duration) {
    if !spinner_enabled() {
        return;
    }
    let mut screen = SCREEN.lock().unwrap_or_else(|poison| poison.into_inner());
    let mut stderr = std::io::stderr().lock();
    screen.spinner(&mut stderr, label, elapsed);
}

/// Remove the spinner when the step completes.
pub fn clear_spinner() {
    let mut screen = SCREEN.lock().unwrap_or_else(|poison| poison.into_inner());
    if screen.drawn {
        let mut stderr = std::io::stderr().lock();
        screen.clear(&mut stderr);
    }
}

/// Forward a chunk of backend stderr (used only while the spinner is on,
/// when backend stderr is piped through here instead of inherited).
pub fn backend_stderr(chunk: &[u8]) {
    let mut screen = SCREEN.lock().unwrap_or_else(|poison| poison.into_inner());
    let mut stderr = std::io::stderr().lock();
    screen.raw(&mut stderr, chunk);
}

/// Screen state behind the one writer. Generic over the sink so tests can
/// check the exact byte stream.
pub(crate) struct Screen {
    drawn: bool,
    mid_line: bool,
    frame: usize,
}

const CLEAR: &[u8] = b"\r\x1b[2K";
const GLYPHS: [char; 4] = ['|', '/', '-', '\\'];

impl Screen {
    pub(crate) const fn new() -> Self {
        Self {
            drawn: false,
            mid_line: false,
            frame: 0,
        }
    }

    pub(crate) fn clear(&mut self, out: &mut impl Write) {
        if self.drawn {
            let _ = out.write_all(CLEAR);
            let _ = out.flush();
            self.drawn = false;
        }
    }

    pub(crate) fn line(&mut self, out: &mut impl Write, text: &str) {
        self.clear(out);
        if self.mid_line {
            // never append to someone else's partial line.
            let _ = out.write_all(b"\n");
            self.mid_line = false;
        }
        let _ = out.write_all(text.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }

    pub(crate) fn raw(&mut self, out: &mut impl Write, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.clear(out);
        let _ = out.write_all(chunk);
        let _ = out.flush();
        self.mid_line = !chunk.ends_with(b"\n");
    }

    pub(crate) fn spinner(&mut self, out: &mut impl Write, label: &str, elapsed: Duration) {
        if self.mid_line {
            // a backend is part-way through a line; drawing now would split it.
            return;
        }
        self.frame = (self.frame + 1) % GLYPHS.len();
        let text = format!(
            "{} {label} running {}s",
            GLYPHS[self.frame],
            elapsed.as_secs()
        );
        let _ = out.write_all(CLEAR);
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
        self.drawn = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_lines_clear_the_spinner_and_never_split_a_line() {
        let mut screen = Screen::new();
        let mut out = Vec::new();
        screen.spinner(&mut out, "python[1]", Duration::from_secs(3));
        screen.raw(&mut out, b"partial");
        // spinner must not draw while a backend line is open.
        screen.spinner(&mut out, "python[1]", Duration::from_secs(4));
        screen.line(&mut out, "warning");
        screen.raw(&mut out, b"whole line\n");
        screen.spinner(&mut out, "python[1]", Duration::from_secs(5));
        screen.clear(&mut out);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "\r\x1b[2K/ python[1] running 3s\r\x1b[2Kpartial\nwarning\nwhole line\n\r\x1b[2K- python[1] running 5s\r\x1b[2K"
        );
    }
}
