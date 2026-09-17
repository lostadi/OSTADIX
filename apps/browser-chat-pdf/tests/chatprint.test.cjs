"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { describe, test } = require("node:test");
const { JSDOM } = require("jsdom");

const APP_ROOT = path.resolve(__dirname, "..");
const FIXTURE_PATH = path.join(__dirname, "fixtures", "generic-chat.html");
const FIXTURE_URL = "https://chat.example.test/conversations/quarterly";

const shared = require(path.join(APP_ROOT, "shared.js"));
const extractor = require(path.join(APP_ROOT, "extractor.js"));
const renderer = require(path.join(APP_ROOT, "renderer.js"));

function fixtureDom() {
  return new JSDOM(fs.readFileSync(FIXTURE_PATH, "utf8"), { url: FIXTURE_URL });
}

function htmlRoot(html, url = FIXTURE_URL) {
  const dom = new JSDOM("<!doctype html><div id=\"root\"></div>", { url });
  const root = dom.window.document.querySelector("#root");
  root.innerHTML = html;
  return { dom, root };
}

function assertNoExecutableMarkup(root) {
  assert.equal(
    root.querySelector("script, style, iframe, object, embed, form, input, button"),
    null,
    "executable or interactive elements must not reach the preview",
  );

  for (const element of root.querySelectorAll("*")) {
    for (const attribute of element.attributes) {
      assert.doesNotMatch(attribute.name, /^on/i, `event attribute ${attribute.name} survived`);
    }
  }

  for (const anchor of root.querySelectorAll("a[href]")) {
    assert.doesNotMatch(anchor.getAttribute("href"), /^\s*javascript:/i);
  }
  for (const image of root.querySelectorAll("img[src]")) {
    assert.doesNotMatch(image.getAttribute("src"), /^\s*javascript:/i);
  }
}

describe("shared helpers", () => {
  test("normalizes capture options, roles, titles, and URLs", () => {
    assert.deepEqual(shared.normalizeOptions({
      mode: "page",
      includeImages: false,
      includeHeader: false,
      autoPrint: true,
      paper: "letter",
      theme: "compact",
      materializeLongChats: false,
    }), {
      mode: "page",
      includeImages: false,
      includeHeader: false,
      autoPrint: true,
      paper: "letter",
      theme: "compact",
      materializeLongChats: false,
    });
    assert.deepEqual(shared.normalizeOptions({ mode: "invalid", paper: "legal", theme: "neon" }), {
      ...shared.DEFAULT_OPTIONS,
    });

    assert.equal(shared.normalizeRole("data-message-author-role:assistant"), "assistant");
    assert.equal(shared.normalizeRole("human"), "user");
    assert.equal(shared.roleLabel("bot"), "Assistant");
    assert.equal(shared.deriveTitle("Quarterly plan — ChatGPT", "chatgpt.com"), "Quarterly plan");
    assert.equal(shared.deriveTitle("New chat", "chat.example.test"), "Chat from chat.example.test");

    assert.equal(
      shared.safeUrl("../guide?print=1#pdf", FIXTURE_URL, "link"),
      "https://chat.example.test/guide?print=1#pdf",
    );
    assert.equal(shared.safeUrl("mailto:owner@example.test", FIXTURE_URL, "link"), "mailto:owner@example.test");
    assert.equal(shared.safeUrl("javascript:alert(1)", FIXTURE_URL, "link"), "");
    assert.equal(shared.safeUrl("data:text/html,boom", FIXTURE_URL, "image"), "");
    assert.equal(shared.safeUrl("data:image/svg+xml,<svg/>", FIXTURE_URL, "image"), "");
    assert.equal(shared.safeUrl("data:image/png;base64,AA==", FIXTURE_URL, "image"), "data:image/png;base64,AA==");
    assert.equal(shared.isSupportedPageUrl(FIXTURE_URL), true);
    assert.equal(shared.isSupportedPageUrl("chrome://settings"), false);
  });

  test("uses stable hashes and marks documents truncated when they exceed the budget", () => {
    assert.equal(shared.hashText("same text"), shared.hashText("same text"));
    assert.notEqual(shared.hashText("same text"), shared.hashText("different text"));

    const bounded = shared.fitDocumentToBudget({
      title: "Large capture",
      messages: [
        { role: "user", text: "a".repeat(2_000), html: "a".repeat(2_000) },
        { role: "assistant", text: "b".repeat(2_000), html: "b".repeat(2_000) },
      ],
      diagnostics: {},
    }, 800);

    assert.equal(bounded.diagnostics.truncated, true);
    assert.equal(bounded.diagnostics.originalMessageCount, 2);
    assert.ok(bounded.messages.length < 2);
  });
});

describe("live DOM extraction", () => {
  test("extracts an ordered generic conversation and preserves semantic formatting", async () => {
    const dom = fixtureDom();
    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);

    assert.equal(capture.schemaVersion, 1);
    assert.equal(capture.title, "Quarterly planning chat");
    assert.equal(capture.source.url, FIXTURE_URL);
    assert.equal(capture.adapter, "generic");
    assert.equal(capture.diagnostics.adapterGroup, "generic-role-value");
    assert.deepEqual(capture.messages.map((message) => message.role), ["user", "assistant"]);
    assert.deepEqual(capture.messages.map((message) => message.id), [
      "data-message-id:turn-user-1",
      "data-message-id:turn-assistant-1",
    ]);

    const user = htmlRoot(capture.messages[0].html).root;
    assert.equal(user.querySelector("strong").textContent, "selectable PDF");
    assert.equal(user.querySelector("button"), null);

    const assistant = htmlRoot(capture.messages[1].html).root;
    assert.equal(assistant.querySelector("h2").textContent, "Export plan");
    assert.equal(assistant.querySelector("em").textContent, "semantic formatting");
    assert.equal(assistant.querySelector("blockquote").textContent, "Text should remain highlightable.");
    assert.equal(assistant.querySelector("ol").getAttribute("start"), "2");
    assert.equal(assistant.querySelector("li[value]").getAttribute("value"), "4");
    assert.equal(assistant.querySelector("code").className, "language-js");
    assert.equal(assistant.querySelector("code").textContent, "const answer = 42;\nconsole.log(answer);");
    assert.equal(assistant.querySelector("table tbody td").textContent, "HTML to PDF");
    assert.equal(assistant.querySelector("a").href, "https://chat.example.test/docs/export");
    assert.equal(assistant.querySelector("button"), null);
    assert.doesNotMatch(assistant.textContent, /Hidden implementation detail/);
  });

  test("falls back to sanitized main-page content when no message structure exists", async () => {
    const dom = new JSDOM(`<!doctype html>
      <title>Research notes</title>
      <nav>Global navigation</nav>
      <main>
        <h1>Research notes</h1>
        <p>The useful whole-page fallback.</p>
        <button>Delete everything</button>
        <aside aria-hidden="true">Invisible UI detail</aside>
      </main>`, { url: "https://notes.example.test/topic" });

    const capture = await extractor.capture({ mode: "conversation", materializeLongChats: false }, dom.window.document);

    assert.equal(capture.adapter, "generic-page-fallback");
    assert.equal(capture.diagnostics.fellBackToPage, true);
    assert.equal(capture.messages.length, 1);
    assert.equal(capture.messages[0].role, "page");
    const page = htmlRoot(capture.messages[0].html).root;
    assert.equal(page.querySelector("h1").textContent, "Research notes");
    assert.match(page.textContent, /useful whole-page fallback/);
    assert.doesNotMatch(page.textContent, /Global navigation|Delete everything|Invisible UI detail/);
  });

  test("strips executable markup and unsafe URLs while extracting", async () => {
    const dom = new JSDOM(`<!doctype html><title>Hostile chat</title><main>
      <article data-role="assistant">
        <p onclick="globalThis.pwned = true">Keep this answer.</p>
        <a id="bad-link" href="javascript:alert(document.domain)" onmouseover="steal()">Unsafe link text</a>
        <a id="good-link" href="/safe" onclick="steal()">Safe link</a>
        <img id="bad-image" src="javascript:alert(1)" alt="Unsafe image description" onerror="steal()">
        <script>globalThis.pwned = true</script>
        <style>.tracker-only { background-image: url(https://tracker.invalid/pixel) }</style>
        <iframe srcdoc="<script>parent.pwned=true</script>"></iframe>
      </article>
    </main>`, { url: "https://hostile.example.test/chat" });

    const capture = await extractor.capture({ includeImages: true, materializeLongChats: false }, dom.window.document);
    const extracted = htmlRoot(capture.messages[0].html, "https://hostile.example.test/chat").root;

    assert.match(extracted.textContent, /Keep this answer/);
    assert.equal(extracted.querySelector("#bad-link"), null, "IDs should not be copied from source markup");
    const links = Array.from(extracted.querySelectorAll("a"));
    assert.equal(links[0].hasAttribute("href"), false);
    assert.equal(links[1].href, "https://hostile.example.test/safe");
    assert.equal(extracted.querySelector("img").hasAttribute("src"), false);
    assertNoExecutableMarkup(extracted);
    assert.equal(globalThis.pwned, undefined);
  });

  test("honors the image toggle while retaining useful alternative text", async () => {
    const shown = await extractor.capture(
      { includeImages: true, materializeLongChats: false },
      fixtureDom().window.document,
    );
    const hidden = await extractor.capture(
      { includeImages: false, materializeLongChats: false },
      fixtureDom().window.document,
    );

    const shownBody = htmlRoot(shown.messages[1].html).root;
    assert.equal(shownBody.querySelector("img").src, "https://chat.example.test/assets/diagram.png");
    assert.equal(shownBody.querySelector("img").alt, "Export pipeline diagram");

    const hiddenBody = htmlRoot(hidden.messages[1].html).root;
    assert.equal(hiddenBody.querySelector("img"), null);
    assert.match(hiddenBody.textContent, /Export pipeline diagram/);
  });
});

describe("preview renderer defense in depth", () => {
  test("re-sanitizes forged capture HTML without discarding safe formatting", () => {
    const dom = new JSDOM("<!doctype html><div id=\"preview\"></div>", {
      url: "chrome-extension://chatprint/preview.html",
    });
    const preview = dom.window.document.querySelector("#preview");

    renderer.sanitizeInto(preview, `
      <custom-wrapper data-danger="yes"><p onclick="steal()">A <strong>formatted</strong> answer.</p></custom-wrapper>
      <a id="unsafe" href="javascript:steal()" target="_blank">Unsafe destination</a>
      <a id="relative" href="/source" onfocus="steal()">Relative destination</a>
      <img id="unsafe-image" src="javascript:steal()" alt="Image fallback" onerror="steal()">
      <script>globalThis.pwned = true</script>
      <style>@import url(https://tracker.invalid)</style>
      <iframe src="https://tracker.invalid"></iframe>
      <form><input autofocus onfocus="steal()"><button>Submit</button></form>
    `, { baseUrl: "https://source.example.test/chat", includeImages: true });

    assert.equal(preview.querySelector("strong").textContent, "formatted");
    assert.equal(preview.querySelector("custom-wrapper"), null);
    assert.equal(preview.querySelector("#unsafe"), null, "IDs should not survive sanitization");
    const links = Array.from(preview.querySelectorAll("a"));
    assert.equal(links[0].hasAttribute("href"), false);
    assert.equal(links[1].href, "https://source.example.test/source");
    assert.equal(links[1].getAttribute("rel"), "noreferrer noopener");
    assert.equal(preview.querySelector("img").hasAttribute("src"), false);
    assert.equal(preview.querySelector("img").alt, "Image fallback");
    assertNoExecutableMarkup(preview);
    assert.equal(globalThis.pwned, undefined);
  });

  test("renderer image suppression removes the resource but keeps its alt text", () => {
    const dom = new JSDOM("<!doctype html><div id=\"preview\"></div>");
    const preview = dom.window.document.querySelector("#preview");

    renderer.sanitizeInto(preview, "Before <img src=\"https://images.example.test/chart.png\" alt=\"Revenue chart\"> after", {
      baseUrl: "https://source.example.test/chat",
      includeImages: false,
    });

    assert.equal(preview.querySelector("img"), null);
    assert.match(preview.textContent, /Before Revenue chart after/);
  });
});
