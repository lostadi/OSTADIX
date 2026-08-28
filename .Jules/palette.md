## 2024-05-24 - Graceful CLI Error Handling
**Learning:** Raw stack traces on expected file errors (like missing files or permission denied) create a poor CLI user experience, appearing as unhandled crashes rather than actionable user errors.
**Action:** Always intercept expected OS errors at the CLI entry point (like `FileNotFoundError`, `PermissionError`) and present them as clean, actionable error messages instead of raw stack traces.
