## 2026-08-23 - Missing file handling in CLI
**Learning:** The CLI throws raw unhandled exceptions (`FileNotFoundError`) instead of a user-friendly error message when attempting to execute a non-existent file, degrading user experience.
**Action:** Always wrap file I/O operations with try-except blocks to provide clean, actionable error messages.
