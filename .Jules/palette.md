## 2024-05-24 - Clearing the terminal in REPL
**Learning:** A standard user expectation in interactive REPLs (like Python or Node.js) is a mechanism to clear the screen, such as a `:clear` command or a keyboard shortcut like Ctrl+L. Currently, the Rust REPL lacks this feature, leading to a cluttered terminal.
**Action:** Implement `:c` and `:clear` commands in the `main.rs` REPL loop utilizing rustyline's built-in `clear_screen` method (which handles ANSI clearing properly).
