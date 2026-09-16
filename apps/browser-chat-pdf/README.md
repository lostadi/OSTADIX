# Chatprint — browser AI chats to PDF

Chatprint is a dependency-free Manifest V3 extension for Chromium-based
browsers. It reads the current tab's **live DOM**, rebuilds the conversation as
safe semantic HTML, and opens a print-focused preview. The browser's native
print engine then creates a PDF whose text can be selected, searched, copied,
and linked.

It does not take a screenshot, call an AI service, or upload the conversation.

## Install

For a validated, managed desktop install on macOS or Linux, run:

```bash
./scripts/setup.sh
```

On Windows PowerShell, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
```

The script copies only the reviewed runtime allowlist, copies the destination
path to the clipboard when possible, and tries to open the browser's extension
manager. Chromium still requires the final **Load unpacked** confirmation.

To install directly from the source tree instead:

1. Open `chrome://extensions` in Chrome, Edge, Brave, or another Chromium-based
   browser.
2. Turn on **Developer mode**.
3. Choose **Load unpacked** and select this `apps/browser-chat-pdf` directory.
4. Pin **Chatprint** to the toolbar if desired.

No build or package installation is required to use the extension.

Chrome and Brave on Android cannot load this desktop extension. Use the
self-contained [Chatprint Mobile bookmarklet](mobile/README.md) instead; its
Termux setup script builds the installer and puts it in Android Downloads.

## Export a chat

1. Open the AI conversation and wait for the current response to finish.
2. Click **Chatprint**. Keep **Conversation** selected for a normalized
   transcript, or choose **Whole page** for all readable rendered page text.
3. Choose whether to keep images and the document header. Enable automatic
   printing if you want the print dialog to open as soon as the preview is
   ready.
4. Select **Create PDF preview**.
5. Edit the title or switch the theme/paper size, then choose
   **Print / Save PDF**.
6. In the native print dialog, select **Save as PDF** and choose the destination.

`Alt+Shift+P` runs the same capture with the last-used settings. Browser shortcut
assignments can be changed at `chrome://extensions/shortcuts`.

For a clean PDF, disable the browser's own **Headers and footers** setting. Keep
**Background graphics** enabled if you want the subtle code and table shading.

## What it preserves

- user, assistant, system, and tool message order and labels;
- paragraphs, headings, emphasis, quotes, and links;
- ordered and unordered lists;
- whitespace-preserving code blocks and inline code;
- wrapping tables;
- ordinary images when requested;
- native MathML when the source page exposes it.

Chatprint includes targeted adapters for common ChatGPT, Claude, Gemini,
Copilot, and Perplexity DOM patterns plus a generic semantic-HTML adapter. It
also walks open shadow roots and readable same-origin frames. For virtualized
conversations, it temporarily scans the nearest scroll container from top to
bottom, deduplicates messages, and restores the original scroll position.

## Why live DOM instead of “View Source”

Most browser AI clients are single-page applications. The network-delivered
page source usually contains only an application shell; messages are added
later by JavaScript. The live DOM is the browser's current structured view of
that rendered conversation, so it is the useful source for a text-native PDF.

The output is intentionally normalized instead of cloning a site's entire CSS
bundle. That makes pagination stable, avoids printing navigation and copy
buttons, and keeps the PDF readable after the source site changes its visual
theme.

## Privacy and permissions

The manifest requests only:

- `activeTab`, granting temporary access after a toolbar click or shortcut;
- `scripting`, used to run the extractor in that one tab;
- `storage`, used for settings and a short-lived handoff to the preview tab.

There are no host permissions, cookie permissions, telemetry endpoints, remote
scripts, or uploads. The temporary capture is removed from extension storage as
soon as the preview reads it. If **Include images** is enabled, the preview may
load the original image URLs from their original hosts; turn the option off for
a text-only, network-quiet preview.

Captured markup is hostile input. Both the page extractor and preview renderer
apply tag, attribute, and URL allowlists. Scripts, inline event handlers,
interactive controls, frame elements, embedded objects, styles, and
`javascript:` URLs are discarded. Safe readable text inside ordinary form
wrappers and accessible same-origin frames is retained.

## Deliberate automation boundary

A normal low-permission Chromium extension cannot silently confirm **Save as
PDF** or choose a filesystem destination. Doing that would require a broad
debugger/DevTools connection, enterprise printing policy, or an external native
automation companion. Chatprint deliberately avoids those permissions: it
automates capture, cleanup, pagination, and preview, then leaves the final file
write in the browser's trusted print dialog.

## Known limits

- Content that is collapsed, on an unselected branch, or not loaded by the site
  cannot be exported until it is made visible/loaded.
- Closed shadow roots and cross-origin iframes cannot be inspected with
  `activeTab`; canvas text has no DOM text to preserve.
- Site redesigns can outpace targeted selectors. The generic adapter or Whole
  page mode remains available, and the preview shows a fallback warning.
- A 100-viewport safety bound applies while scanning unusually long virtualized
  chats. The preview warns when that bound is reached.
- Very large captures adapt to Chromium's temporary-storage quota (up to
  approximately 8 MB on current versions). A truncation warning is shown
  rather than failing silently.
- Authenticated or short-lived image URLs may not load in the extension preview.
  The surrounding text and image alternative text are still retained.

## Development and tests

Runtime files are plain HTML, CSS, and JavaScript. The Node dependency is used
only by DOM fixture tests:

```bash
cd apps/browser-chat-pdf
npm ci
npm test
```

Useful dependency-free checks:

```bash
node --check background.js
node --check extractor.js
node --check popup.js
node --check preview.js
node --check renderer.js
python3 -m json.tool manifest.json >/dev/null
```

For end-to-end desktop evidence, load the unpacked extension, serve the fixture
over localhost, and open
`http://127.0.0.1:8765/tests/fixtures/generic-chat.html`:

```bash
cd apps/browser-chat-pdf
python3 -m http.server 8765 --bind 127.0.0.1
```

Export that page, save the PDF, then inspect it with:

```bash
pdfinfo chatprint-fixture.pdf
pdftotext chatprint-fixture.pdf -
pdffonts chatprint-fixture.pdf
```

`pdftotext` should report the fixture's headings, messages, list items, code,
and table cells in reading order. This proves text-native output more directly
than a screenshot does.

## File map

- `background.js` coordinates explicit capture and the short-lived preview
  handoff.
- `extractor.js` detects messages, materializes long chats, and creates safe
  semantic fragments from the live DOM.
- `popup.html` / `popup.js` expose capture settings.
- `preview.html` / `preview.js` render and print the normalized document.
- `renderer.js` performs the second, extension-side sanitization pass.
- `popup.css` and `preview.css` provide screen, responsive, and print styles.
