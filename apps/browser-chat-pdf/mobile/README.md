# Chatprint Mobile

Chatprint Mobile is a self-contained bookmarklet for Android Chrome. It captures
the page's live DOM into an allowlisted structured tree, renders that tree with
safe DOM operations in a touch-friendly preview, and calls the browser's native
print flow. The PDF contains real, searchable, highlightable text.

## Install on Android Chrome

1. Open `dist/install.html` from a trusted HTTPS host (for example, this
   repository's GitHub Pages site) and tap **Copy Chatprint bookmark code**.
2. In Chrome, bookmark that page or any ordinary page.
3. Open Chrome's bookmark editor, rename the bookmark **Chatprint**, replace its
   URL with the copied code, and save it.
4. Open the AI chat. Type `Chatprint` in the address bar and tap the bookmarked
   result. Selecting it from the address bar ensures it runs on the chat tab.
5. In the preview, tap **Print / Save PDF**, select **Save as PDF**, and save.

The browser intentionally requires the bookmark-edit step; webpages cannot add
or modify a user's bookmarks automatically.

If the preview is blocked, allow pop-ups for the AI chat site and run Chatprint
again. Bookmarklets cannot run on browser-owned pages such as `chrome://` URLs.
Brave Android bookmarklets remain experimental and may not run on every release.

### One-command Termux setup

From the repository root:

```bash
apps/browser-chat-pdf/mobile/setup-termux.sh
```

This reproducibly builds the bookmarklet, writes the installer and checksummed
artifacts to `/sdcard/Download/Chatprint-Mobile`, copies the one-line URL when
Termux:API clipboard support is installed, and opens the installer. Pass
`--no-open` to skip the last action. It refuses to overwrite an existing folder
unless that folder has Chatprint's management marker.

## Privacy and behavior

- The bundle contains all extraction, sanitization, rendering, and styling code.
  It fetches no scripts, fonts, analytics, or services.
- Images are off by default. Turning them on recaptures safe HTTP(S) or approved
  inline image URLs and sends no referrer header from the preview.
- Chatprint reads only the current tab after you explicitly invoke the bookmark.
  It does not save or upload the captured conversation.
- Conversation mode includes compact ChatGPT, Claude, Gemini, Copilot,
  Perplexity, and generic live-DOM adapters. Whole page
  mode includes rendered text from the document, open shadow roots, and
  accessible same-origin frames.
- The compact mobile build captures messages currently represented in the live
  DOM. For an unusually long virtualized chat, scroll through it first or use
  the desktop extension's deeper materialization pass.
- Site CSP, Trusted Types, or cross-origin isolation changes can prevent a
  bookmarklet from running. The desktop extension is the more reliable option
  on a computer.

## Deterministic build

From `apps/browser-chat-pdf`:

```bash
npm ci
npm run build:mobile
```

The build takes the URL, role, and title helpers from the desktop `shared.js`
source using an audited deterministic export transform, then combines them with
the mobile structured-tree extractor/renderer in `mobile/src/bookmarklet.js`.
It writes:

- `dist/chatprint-mobile.txt`: paste-ready `javascript:` bookmark URL
- `dist/chatprint-mobile.min.js`: auditable minified bundle
- `dist/install.html`: offline installer/copy page
- `dist/build.json`: input and output SHA-256 hashes and byte sizes

No timestamps or machine-specific paths enter the outputs, so identical inputs
produce byte-identical artifacts.
