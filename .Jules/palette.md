## 2024-05-24 - REPL clear screen shortcut
**Learning:** Terminal REPL users often need to quickly clear the screen to focus on new output, and relying entirely on shell shortcuts (like Ctrl-L) which might not be obvious to all users or behave consistently across terminal emulators, can hinder usability.
**Action:** Implemented a direct text command (`:c` / `:clear`) within the REPL itself to trigger clearing the screen, providing a built-in, discoverable alternative.
