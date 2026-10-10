## 2024-10-24 - Accessibility gaps in Vanilla JS Template Strings
**Learning:** Vanilla JS template strings (used for dynamically generating HTML, like `createCell` in the notebook) often bypass automated accessibility linters that check JSX or static HTML. This can lead to omitted ARIA labels on dynamic elements like icon-only buttons.
**Action:** Always manually audit dynamically generated UI elements within template literals for accessibility attributes, especially `aria-label` for icon-only buttons, as automated tools may miss them.
