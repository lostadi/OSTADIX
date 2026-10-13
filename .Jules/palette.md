## 2024-05-24 - Accessibility in Vanilla JS Templates
**Learning:** UI components generated dynamically via Vanilla JS template strings (like the `o-notebook` UI in `src/bin/o-notebook.rs`) bypass standard automated linters (ESLint, axe-core). As a result, critical accessibility attributes like `aria-label` for icon-only buttons are easily missed.
**Action:** Always perform manual code audits on inline HTML strings and dynamically constructed elements to ensure `aria-labels` and other essential a11y attributes are included.
