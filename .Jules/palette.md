## 2026-08-24 - REPL Ctrl+C Abort Feedback
**Learning:** When users abort a multiline input in a REPL using Ctrl+C, failing to provide visual feedback (like a `^C` printout) leaves them uncertain whether their input was actually canceled or if the REPL merely swallowed the newline. Standard shells provide this feedback, setting a baseline expectation for terminal UX.
**Action:** Always echo `^C` before clearing the buffer and issuing a new prompt when trapping SIGINT/Ctrl+C in custom REPLs.
