## 2024-11-09 - CLI Error Handling
**Learning:** Bare stack traces on missing files (e.g. `FileNotFoundError`) provide poor UX in CLI tools, exposing internal implementation details instead of actionable feedback. This makes the tool feel unpolished and can confuse non-technical users.
**Action:** Always wrap file loading operations in try-except blocks to catch standard `OSError` exceptions and provide clean, human-readable error messages to stderr before exiting.
