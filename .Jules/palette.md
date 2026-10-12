# Palette journal

Entries retain the dates and wording recorded on their source branches.

## 2024-11-09 - CLI Error Handling
**Learning:** Bare stack traces on missing files (e.g. `FileNotFoundError`) provide poor UX in CLI tools, exposing internal implementation details instead of actionable feedback. This makes the tool feel unpolished and can confuse non-technical users.
**Action:** Always wrap file loading operations in try-except blocks to catch standard `OSError` exceptions and provide clean, human-readable error messages to stderr before exiting.

Source: `upstream/palette/cli-error-handling-4423928523852424637` (`eeb0222a`).

## 2026-08-22 - Graceful CLI Error Handling
**Learning:** Raw stack traces from unhandled exceptions (like `FileNotFoundError` or `PermissionError`) in CLI tools degrade user experience by presenting overly technical details and obscuring the actual problem and solution. Users benefit significantly from friendly, actionable error messages.
**Action:** When creating or modifying CLI tools, ensure that common expected failures (like file I/O operations) are wrapped in `try-except` blocks. Output clear, context-specific error messages to `sys.stderr` and exit with a non-zero code instead of propagating raw stack traces to the user.

Source: `upstream/palette-cli-error-ux-9104623671049710645` (`a18400d0`).

## 2026-08-23 - Missing file handling in CLI
**Learning:** The CLI throws raw unhandled exceptions (`FileNotFoundError`) instead of a user-friendly error message when attempting to execute a non-existent file, degrading user experience.
**Action:** Always wrap file I/O operations with try-except blocks to provide clean, actionable error messages.

Source: `upstream/jules-ux-cli-file-errors-9567731891484906250` (`20560612`).

## 2026-08-24 - REPL Ctrl+C Abort Feedback
**Learning:** When users abort a multiline input in a REPL using Ctrl+C, failing to provide visual feedback (like a `^C` printout) leaves them uncertain whether their input was actually canceled or if the REPL merely swallowed the newline. Standard shells provide this feedback, setting a baseline expectation for terminal UX.
**Action:** Always echo `^C` before clearing the buffer and issuing a new prompt when trapping SIGINT/Ctrl+C in custom REPLs.

Source: `upstream/jules-repl-ctrl-c-ux-4582478923382288125` (`ac424d94`).

## 2024-05-18 - Added `clear` command to REPL
**Learning:** For long-running CLI sessions like an interactive REPL, screen clutter significantly degrades UX and accessibility, especially when using complex multiline inputs or large output data. Having explicit screen-clearing commands (`:c`, `:clear`, `clear`) helps users maintain focus and manage cognitive load by providing a fresh visual slate.
**Action:** Always consider implementing terminal management commands (like clear screen, history navigation, and prompt resetting) in interactive REPL environments as baseline UX features, rather than treating them as optional enhancements.

Source: `upstream/feat/repl-clear-screen-2213356304128161974` (`11e2694b`).

## 2024-05-18 - Clear Screen Command in REPL
**Learning:** Terminal-based REPL users often need to quickly clear the screen to focus on a fresh prompt after complex or verbose operations (like syntax errors, large outputs, or evaluating many files). The existing flow required quitting the REPL or depending on terminal emulator shortcuts. Implementing a native `:clear` command makes the interactive experience smoother and more inclusive, addressing cognitive overload and improving accessibility for users who depend on clear visual distinction.
**Action:** Adding `:c` | `:clear` shortcuts to all future REPL environments as a foundational UX requirement.

Source: `upstream/palette-repl-clear-cmd-8745059712295164011` (`5a2d88cd`).

## 2024-05-24 - Graceful CLI Error Handling
**Learning:** Raw stack traces on expected file errors (like missing files or permission denied) create a poor CLI user experience, appearing as unhandled crashes rather than actionable user errors.
**Action:** Always intercept expected OS errors at the CLI entry point (like `FileNotFoundError`, `PermissionError`) and present them as clean, actionable error messages instead of raw stack traces.

Source: `upstream/cli-error-ux-10775695524624767334` (`6f2fe324`).

## 2024-08-29 - Clear Command in CLI REPL
**Learning:** Keyboard-centric users working in REPLs frequently need to clear their screens to reduce cognitive load and focus on current context. While `Ctrl+L` works for some, having explicit `:clear` and `:c` commands in line with other REPL commands (like `:reset` or `:quit`) makes this feature discoverable and consistent with the interface's mental model.
**Action:** When working on CLI REPLs, ensure screen clearing is available both as a standard keyboard shortcut (e.g. `Ctrl+L` via terminal bindings) and as an explicit, documented command that aligns with the application's command structure (e.g., `:clear` or `:c`).

Source: `upstream/ux-add-repl-clear-command-14385163191800482413` (`0efe6638`).

## 2024-05-24 - Clearing the terminal in REPL
**Learning:** A standard user expectation in interactive REPLs (like Python or Node.js) is a mechanism to clear the screen, such as a `:clear` command or a keyboard shortcut like Ctrl+L. Currently, the Rust REPL lacks this feature, leading to a cluttered terminal.
**Action:** Implement `:c` and `:clear` commands in the `main.rs` REPL loop utilizing rustyline's built-in `clear_screen` method (which handles ANSI clearing properly).

Source: `upstream/palette-repl-clear-10920733176746515596` (`90841ac0`).

## 2024-05-24 - REPL clear screen shortcut
**Learning:** Terminal REPL users often need to quickly clear the screen to focus on new output, and relying entirely on shell shortcuts (like Ctrl-L) which might not be obvious to all users or behave consistently across terminal emulators, can hinder usability.
**Action:** Implemented a direct text command (`:c` / `:clear`) within the REPL itself to trigger clearing the screen, providing a built-in, discoverable alternative.

Source: `upstream/palette-ux-improvement-repl-clear-12002940389259549745` (`ab35a13a`).

## 2024-05-18 - Missing ARIA Labels in O-Notebook
**Learning:** The interactive O-Notebook application (`src/bin/o-notebook.rs`) contains icon-only buttons for cell manipulation (move up, move down, clear output, delete) that rely entirely on the `title` attribute for context. `title` attributes are not a reliable way to provide accessible names. The buttons lack `aria-label`s, rendering them functionally opaque to screen readers.
**Action:** Always add explicit `aria-label` attributes to icon-only buttons, even when a `title` attribute is present, to ensure consistent and reliable accessibility for assistive technologies.

Source: `upstream/palette-ux-aria-labels-17543968112545744121` (`d213da3c`).

## 2024-05-18 - Missing ARIA Labels in Interactive Notebook UI
**Learning:** Found several icon-only buttons (Run, Move up, Move down, Clear output, Delete) in the embedded HTML interface of `src/bin/o-notebook.rs` that were missing `aria-label` attributes. Without these labels, screen readers would simply read out the unicode character (e.g. "black right-pointing triangle"), which provides a poor user experience. I also discovered a textarea missing an `aria-label` where the `placeholder` attribute was being relied upon (which is not consistently read by screen readers).
**Action:** When working on UI templates (even those embedded directly in server-side Rust files), I should always ensure that interactive elements relying on visual icons or placeholders have explicit `aria-label` attributes to maintain accessibility.

Source: `upstream/palette-add-aria-labels-16419148431743606071` (`f47448ca`).

## 2024-03-24 - Screen Reader Literalism with Unicode Symbols
**Learning:** The notebook UI uses raw Unicode symbols (▶, ↑, ↓, ⬜, ✕) as pseudo-icons for cell control buttons. Without explicit `aria-label`s, screen readers read these literally (e.g., "black right-pointing triangle" or "multiplication x"), confusing visually impaired users relying on audio cues for functional understanding.
**Action:** Always add semantic `aria-label`s to any icon-only button, especially those using Unicode glyphs, so screen readers announce the button's action (e.g., "Run cell") rather than its visual representation.

Source: `upstream/palette/a11y-notebook-buttons-2197054148375180996` (`9b1da302`).

## 2026-10-09 - Accessible Interactive Cells in Minimalist Web UIs
**Learning:** When building minimal, interactive HTML templates with embedded JS (like this project's o-notebook), standard `title` attributes on icon-only buttons are often insufficient for screen reader accessibility, particularly when building custom cell management interfaces. Screen readers may ignore titles on non-standard styled buttons.
**Action:** Always enforce explicit `aria-label` attributes on icon-only interactive elements and primary text areas within raw HTML string templates, bypassing the assumption that the `title` attribute alone ensures compliance.

Source: `upstream/jules-palette-ux-notebook-16726529523203072523` (`2e78a34f`).

## 2024-10-24 - Accessibility gaps in Vanilla JS Template Strings
**Learning:** Vanilla JS template strings (used for dynamically generating HTML, like `createCell` in the notebook) often bypass automated accessibility linters that check JSX or static HTML. This can lead to omitted ARIA labels on dynamic elements like icon-only buttons.
**Action:** Always manually audit dynamically generated UI elements within template literals for accessibility attributes, especially `aria-label` for icon-only buttons, as automated tools may miss them.

Source: `upstream/palette-add-aria-labels-14417253590846761119` (`7ce82200`).

## 2025-02-25 - Accessibility in Dynamic HTML Templates
**Learning:** Vanilla JS template strings for dynamic HTML generation bypass standard automated linters, making manual audits crucial for ensuring accessibility attributes like `aria-label` are present on icon-only buttons.
**Action:** Always manually audit dynamic HTML template strings for accessibility attributes when working on UI components that are generated client-side, especially when standard linters are not available.

Source: `upstream/ux-aria-labels-17754742340276186369` (`6318810f`).
