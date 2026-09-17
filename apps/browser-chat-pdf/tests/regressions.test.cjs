"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { describe, test } = require("node:test");
const vm = require("node:vm");
const { JSDOM } = require("jsdom");

const APP_ROOT = path.resolve(__dirname, "..");
const shared = require(path.join(APP_ROOT, "shared.js"));
const extractor = require(path.join(APP_ROOT, "extractor.js"));
const renderer = require(path.join(APP_ROOT, "renderer.js"));

function domFrom(body, url = "https://chat.example.test/thread") {
  return new JSDOM(`<!doctype html><html><head><title>Regression chat</title></head><body>${body}</body></html>`, {
    url,
  });
}

function fragmentFrom(html, url = "https://chat.example.test/thread") {
  const dom = new JSDOM("<!doctype html><div id=\"root\"></div>", { url });
  const root = dom.window.document.querySelector("#root");
  root.innerHTML = html;
  return root;
}

async function waitUntil(predicate, message, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(message);
}

describe("conversation extraction regressions", () => {
  test("prefers the outer ChatGPT markdown root over a nested whitespace wrapper", async () => {
    const dom = domFrom(`
      <main>
        <div data-message-author-role="user"><div class="whitespace-pre-wrap">Keep the prompt.</div></div>
        <div data-message-author-role="assistant">
          <div class="markdown">
            <p>Intro before the nested block.</p>
            <div class="whitespace-pre-wrap"><pre><code>const middle = true;</code></pre></div>
            <p><strong>Outro after the nested block.</strong></p>
          </div>
        </div>
      </main>
    `, "https://chatgpt.com/c/regression");

    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);

    assert.equal(capture.adapter, "chatgpt");
    assert.equal(capture.messages.length, 2);
    const answer = fragmentFrom(capture.messages[1].html);
    assert.match(answer.textContent, /Intro before the nested block/);
    assert.equal(answer.querySelector("code").textContent, "const middle = true;");
    assert.equal(answer.querySelector("strong").textContent, "Outro after the nested block.");
  });

  test("keeps meaningful ChatGPT citation siblings outside a single markdown root", async () => {
    const dom = domFrom(`
      <main>
        <div data-message-author-role="user"><div class="whitespace-pre-wrap">Cite the answer.</div></div>
        <div data-message-author-role="assistant">
          <div class="markdown"><p>Primary answer text.</p></div>
          <aside><a href="https://example.test/source">Citation sibling</a></aside>
          <button type="button">Copy</button>
        </div>
      </main>
    `, "https://chatgpt.com/c/citation-regression");

    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);

    assert.equal(capture.messages.length, 2);
    assert.match(capture.messages[1].text, /Primary answer text/);
    assert.match(capture.messages[1].text, /Citation sibling/);
    assert.doesNotMatch(capture.messages[1].text, /Copy/);
  });

  test("excludes messages beneath hidden, inert, and aria-hidden ancestors", async () => {
    const dom = domFrom(`
      <main>
        <article data-role="user">Visible question</article>
        <article data-role="assistant">Visible answer</article>
        <section style="display: none"><article data-role="assistant">Display-hidden answer</article></section>
        <section hidden><article data-role="assistant">Hidden-attribute answer</article></section>
        <section inert><article data-role="assistant">Inert answer</article></section>
        <section aria-hidden="true"><article data-role="assistant">ARIA-hidden answer</article></section>
      </main>
    `);

    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);

    assert.deepEqual(capture.messages.map((message) => message.text), ["Visible question", "Visible answer"]);
    assert.doesNotMatch(capture.messages.map((message) => message.text).join(" "), /hidden answer/i);
  });

  test("excludes conversation candidates inside a hidden same-origin frame", async () => {
    const dom = domFrom(`
      <main>
        <article data-role="user">Visible framed-page question</article>
        <article data-role="assistant">Visible framed-page answer</article>
        <section style="display: none"><iframe title="Hidden transcript"></iframe></section>
      </main>
    `);
    dom.window.document.querySelector("iframe").contentDocument.body.innerHTML =
      "<article data-role=\"assistant\">Hidden frame secret</article>";

    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);

    assert.deepEqual(capture.messages.map((message) => message.text), [
      "Visible framed-page question",
      "Visible framed-page answer",
    ]);
    assert.doesNotMatch(capture.messages.map((message) => message.text).join(" "), /Hidden frame secret/);
  });

  test("prunes nested wrappers representing the same message", async () => {
    const dom = domFrom(`
      <main>
        <article data-role="user">Question appears once.</article>
        <article data-role="assistant">
          Answer prefix.
          <div data-role="assistant"><p>Nested answer body.</p></div>
          Answer suffix.
        </article>
      </main>
    `);

    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);

    assert.equal(capture.messages.length, 2);
    assert.deepEqual(capture.messages.map((message) => message.role), ["user", "assistant"]);
    assert.equal(capture.messages.filter((message) => /Nested answer body/.test(message.text)).length, 1);
    assert.match(capture.messages[1].text, /Answer prefix/);
    assert.match(capture.messages[1].text, /Answer suffix/);
  });

  test("keeps nested different-role messages without contaminating the outer turn", async () => {
    const dom = domFrom(`
      <main>
        <article data-role="user">
          Outer question only.
          <article data-role="assistant"><p>Nested answer only.</p></article>
        </article>
      </main>
    `);

    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);

    assert.equal(capture.messages.length, 2);
    assert.deepEqual(capture.messages.map((message) => message.role), ["user", "assistant"]);
    assert.match(capture.messages[0].text, /Outer question only/);
    assert.doesNotMatch(capture.messages[0].text, /Nested answer only/);
    assert.equal(capture.messages[1].text, "Nested answer only.");
  });

  test("keeps alternating roles nested three levels deep", async () => {
    const dom = domFrom(`
      <main>
        <article data-role="user">
          First question.
          <article data-role="assistant">
            First answer.
            <article data-role="user">Follow-up question.</article>
          </article>
        </article>
      </main>
    `);

    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);

    assert.deepEqual(capture.messages.map((message) => message.role), ["user", "assistant", "user"]);
    assert.deepEqual(capture.messages.map((message) => message.text), [
      "First question.",
      "First answer.",
      "Follow-up question.",
    ]);
  });

  test("prefers a structured conversation over many unrelated articles", async () => {
    const unrelated = Array.from(
      { length: 52 },
      (_, index) => `<article>Unrelated article ${index + 1}</article>`,
    ).join("");
    const dom = domFrom(`
      <main>
        <div data-role="user">Structured question.</div>
        <div data-role="assistant">Structured answer.</div>
        ${unrelated}
      </main>
    `);

    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);

    assert.equal(capture.adapter, "generic");
    assert.equal(capture.diagnostics.adapterGroup, "generic-role-value");
    assert.deepEqual(capture.messages.map((message) => message.text), [
      "Structured question.",
      "Structured answer.",
    ]);
  });

  test("prefers a complete article fallback over an incomplete site adapter", async () => {
    const dom = domFrom(`
      <main>
        <div data-message-author-role="user">Stray incomplete selector.</div>
        <article>User: Article fallback question.</article>
        <article>Assistant: Article fallback answer.</article>
      </main>
    `, "https://chatgpt.com/c/selector-churn");

    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);

    assert.equal(capture.adapter, "generic");
    assert.equal(capture.diagnostics.adapterGroup, "generic-articles");
    assert.deepEqual(capture.messages.map((message) => message.role), ["user", "assistant"]);
    assert.match(capture.messages[0].text, /Article fallback question/);
    assert.match(capture.messages[1].text, /Article fallback answer/);
    assert.doesNotMatch(capture.messages.map((message) => message.text).join(" "), /Stray incomplete selector/);
  });

  test("uses whole-page fallback instead of accepting an unrelated low-confidence article", async () => {
    const dom = domFrom(`
      <main>
        <article>Unrelated editorial introduction.</article>
        <section><h2>Unsupported chat transcript</h2><p>Important page content outside the article.</p></section>
      </main>
    `);

    const capture = await extractor.capture({ mode: "conversation", materializeLongChats: false }, dom.window.document);

    assert.equal(capture.adapter, "generic-page-fallback");
    assert.equal(capture.diagnostics.fellBackToPage, true);
    assert.equal(capture.messages.length, 1);
    assert.match(capture.messages[0].text, /Unrelated editorial introduction/);
    assert.match(capture.messages[0].text, /Important page content outside the article/);
  });

  test("turns pre-wrap newlines into explicit printable line breaks", async () => {
    const dom = domFrom(`<main>
      <article data-role="user"><div style="white-space: pre-wrap">line one\n  line two\n\nline four</div></article>
      <article data-role="assistant">Acknowledged.</article>
    </main>`);

    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);
    const prompt = fragmentFrom(capture.messages[0].html);

    assert.equal(prompt.querySelectorAll("br").length, 3);
    assert.equal(prompt.querySelector("br").nextSibling.nodeValue, "  line two");
    assert.match(capture.messages[0].html, /line one<br>  line two<br><br>line four/);
  });
});

describe("whole-page traversal regressions", () => {
  test("captures the whole document, open-shadow content, and same-origin frame text", async () => {
    const dom = domFrom(`
      <header>Document header outside main.</header>
      <main><p>Light DOM text.</p><div id="shadow-host"></div><iframe title="Inline notes"></iframe></main>
      <footer>Document footer outside main.</footer>
    `, "https://page.example.test/report");
    const document = dom.window.document;
    document.querySelector("#shadow-host")
      .attachShadow({ mode: "open" })
      .innerHTML = "<section><h2>Open shadow heading</h2><p>Open shadow body.</p></section>";
    const frameDocument = document.querySelector("iframe").contentDocument;
    frameDocument.body.innerHTML = "<main><h2>Same-origin frame heading</h2><p>Same-origin frame body.</p></main>";

    const capture = await extractor.capture({ mode: "page", materializeLongChats: false }, document);

    assert.equal(capture.adapter, "whole-page");
    assert.equal(capture.diagnostics.adapterGroup, "whole-document");
    assert.equal(capture.messages.length, 1);
    const text = capture.messages[0].text;
    assert.match(text, /Document header outside main/);
    assert.match(text, /Light DOM text/);
    assert.match(text, /Open shadow heading/);
    assert.match(text, /Open shadow body/);
    assert.match(text, /Same-origin frame heading/);
    assert.match(text, /Same-origin frame body/);
    assert.match(text, /Document footer outside main/);
  });

  test("includes same-origin frame text in conversation-mode page fallback", async () => {
    const dom = domFrom(`
      <main>
        <h1>Unsupported conversation shell</h1>
        <iframe title="Fallback transcript"></iframe>
      </main>
    `, "https://page.example.test/unsupported-chat");
    dom.window.document.querySelector("iframe").contentDocument.body.innerHTML =
      "<section><h2>Frame-only transcript</h2><p>Fallback frame answer.</p></section>";

    const capture = await extractor.capture({
      mode: "conversation",
      materializeLongChats: false,
    }, dom.window.document);

    assert.equal(capture.adapter, "generic-page-fallback");
    assert.equal(capture.diagnostics.fellBackToPage, true);
    assert.match(capture.messages[0].text, /Unsupported conversation shell/);
    assert.match(capture.messages[0].text, /Frame-only transcript/);
    assert.match(capture.messages[0].text, /Fallback frame answer/);
  });

  test("unwraps forms while discarding their interactive controls", async () => {
    const dom = domFrom(`
      <main>
        <form action="https://attacker.invalid/submit" onsubmit="steal()">
          <h2>Visible form explanation</h2>
          <p>This guidance belongs in the printable page.</p>
          <label>Secret <input name="secret" value="do not export"></label>
          <button type="submit">Send private data</button>
        </form>
      </main>
    `);

    const capture = await extractor.capture({ mode: "page", materializeLongChats: false }, dom.window.document);
    const page = fragmentFrom(capture.messages[0].html);

    assert.match(page.textContent, /Visible form explanation/);
    assert.match(page.textContent, /guidance belongs in the printable page/);
    assert.doesNotMatch(page.textContent, /do not export|Send private data/);
    assert.equal(page.querySelector("form, input, button"), null);
  });
});

describe("format and size regressions", () => {
  test("keeps expanded details open through extraction and renderer sanitization", async () => {
    const dom = domFrom(`<main>
      <article data-role="user">Show the details.</article>
      <article data-role="assistant"><details open><summary>Explanation</summary><p>Expanded detail body.</p></details></article>
    </main>`);
    const capture = await extractor.capture({ materializeLongChats: false }, dom.window.document);
    const extracted = fragmentFrom(capture.messages[1].html);
    assert.equal(extracted.querySelector("details").open, true);

    const previewDom = new JSDOM("<!doctype html><div id=\"preview\"></div>");
    const preview = previewDom.window.document.querySelector("#preview");
    renderer.sanitizeInto(preview, capture.messages[1].html);
    assert.equal(preview.querySelector("details").open, true);
    assert.match(preview.textContent, /Expanded detail body/);
  });

  test("keeps a single oversized message nonblank and within the byte budget", () => {
    const byteBudget = 800;
    const bounded = shared.fitDocumentToBudget({
      title: "Oversized capture",
      messages: [{
        id: "large-message",
        role: "assistant",
        label: "Assistant",
        text: "<&".repeat(4_000),
        html: `<p>${"<&".repeat(4_000)}</p>`,
      }],
      diagnostics: {},
    }, byteBudget);

    assert.equal(bounded.messages.length, 1);
    assert.ok(bounded.messages[0].text.length > 0);
    assert.ok(shared.byteLength(bounded) <= byteBudget, `${shared.byteLength(bounded)} bytes exceeded ${byteBudget}`);
    assert.doesNotMatch(bounded.messages[0].html, /<p><&/);
  });

  test("uses a nonblank placeholder when an oversized first message contains only an image", () => {
    const byteBudget = 800;
    const bounded = shared.fitDocumentToBudget({
      title: "Oversized image capture",
      messages: [
        {
          id: "large-image",
          role: "assistant",
          label: "Assistant",
          text: "",
          html: `<img alt="Large chart" src="data:image/png;base64,${"A".repeat(4_000)}">`,
        },
        {
          id: "later-text",
          role: "assistant",
          label: "Assistant",
          text: "Later readable answer",
          html: "<p>Later readable answer</p>",
        },
      ],
      diagnostics: {},
    }, byteBudget);

    assert.equal(bounded.messages.length, 1);
    assert.match(bounded.messages[0].text, /\S/);
    assert.match(fragmentFrom(bounded.messages[0].html).textContent, /\S/);
    assert.ok(shared.byteLength(bounded) <= byteBudget, `${shared.byteLength(bounded)} bytes exceeded ${byteBudget}`);
  });

  test("keeps the preview schema when oversized metadata requires an emergency envelope", () => {
    const byteBudget = 128_000;
    const bounded = shared.fitDocumentToBudget({
      schemaVersion: 1,
      title: "Long source URL",
      source: {
        hostname: "example.test",
        url: `https://example.test/?q=${"x".repeat(150_000)}`,
      },
      capturedAt: "2026-09-04T00:00:00.000Z",
      mode: "conversation",
      adapter: "generic",
      options: shared.DEFAULT_OPTIONS,
      messages: [{
        role: "assistant",
        label: "Assistant",
        text: "hello",
        html: "<p>hello</p>",
      }],
      diagnostics: {},
    }, byteBudget);

    assert.equal(bounded.messages.length, 1);
    assert.deepEqual(bounded.source, {
      hostname: "example.test",
      url: "https://example.test/",
    });
    assert.equal(bounded.capturedAt, "2026-09-04T00:00:00.000Z");
    assert.deepEqual(bounded.options, shared.DEFAULT_OPTIONS);
    assert.ok(shared.byteLength(bounded) <= byteBudget, `${shared.byteLength(bounded)} bytes exceeded ${byteBudget}`);
  });
});

describe("preview option regressions", () => {
  test("disables the one-way image selector when capture excluded image URLs", async () => {
    const key = "chatprint:capture:preview-regression";
    const capture = {
      schemaVersion: 1,
      title: "Images excluded",
      source: {
        hostname: "chat.example.test",
        url: "https://chat.example.test/thread",
      },
      sourceTabId: 7,
      capturedAt: "2026-09-04T00:00:00.000Z",
      options: {
        ...shared.DEFAULT_OPTIONS,
        includeImages: false,
      },
      messages: [{
        id: "answer",
        role: "assistant",
        label: "Assistant",
        html: "<p>Image description retained as text.</p>",
        text: "Image description retained as text.",
      }],
      diagnostics: {},
    };
    const previewHtml = fs.readFileSync(path.join(APP_ROOT, "preview.html"), "utf8");
    const dom = new JSDOM(previewHtml, {
      runScripts: "outside-only",
      url: `https://extension.example.test/preview.html?capture=${encodeURIComponent(key)}`,
    });
    const removedKeys = [];
    dom.window.chrome = {
      runtime: { lastError: null },
      storage: {
        session: {
          get: async (requestedKey) => ({ [requestedKey]: capture }),
          remove: async (requestedKey) => removedKeys.push(requestedKey),
        },
      },
    };

    for (const file of ["shared.js", "renderer.js", "preview.js"]) {
      dom.window.eval(fs.readFileSync(path.join(APP_ROOT, file), "utf8"));
    }

    const imagesSelect = dom.window.document.querySelector("#imagesSelect");
    await waitUntil(() => imagesSelect.disabled, "preview did not disable the unavailable image option");

    assert.equal(imagesSelect.value, "hide");
    assert.equal(imagesSelect.disabled, true);
    assert.equal(imagesSelect.querySelector("option[value='show']").disabled, true);
    assert.match(imagesSelect.title, /excluded during capture/i);
    assert.deepEqual(removedKeys, [key]);
    assert.match(dom.window.document.querySelector("#messages").textContent, /Image description retained as text/);
  });
});

describe("popup interaction regressions", () => {
  test("restores settings and sends normalized capture options", async () => {
    const popupHtml = fs.readFileSync(path.join(APP_ROOT, "popup.html"), "utf8");
    const dom = new JSDOM(popupHtml, {
      runScripts: "outside-only",
      url: "https://extension.example.test/popup.html",
    });
    const settings = {
      ...shared.DEFAULT_OPTIONS,
      mode: "page",
      includeImages: false,
      paper: "letter",
      theme: "clean",
    };
    const storedValues = [];
    const messages = [];
    dom.window.chrome = {
      runtime: {
        lastError: null,
        sendMessage(message, callback) {
          messages.push(message);
          callback({ ok: true, messageCount: 2, truncated: false });
        },
      },
      storage: {
        local: {
          get: async () => ({ "chatprint:settings": settings }),
          set: async (value) => storedValues.push(value),
        },
      },
    };

    for (const file of ["shared.js", "popup.js"]) {
      dom.window.eval(fs.readFileSync(path.join(APP_ROOT, file), "utf8"));
    }

    await waitUntil(
      () => dom.window.document.querySelector("input[value='page']").checked,
      "popup did not restore saved settings",
    );
    assert.equal(dom.window.document.querySelector("#includeImages").checked, false);
    assert.equal(dom.window.document.querySelector("#paper").value, "letter");
    assert.equal(dom.window.document.querySelector("#theme").value, "clean");

    dom.window.document.querySelector("#settingsButton").click();
    assert.equal(dom.window.document.querySelector("#advancedSettings").hidden, false);
    assert.equal(dom.window.document.querySelector("#settingsButton").textContent, "Done");

    dom.window.document.querySelector("#captureForm").dispatchEvent(new dom.window.Event("submit", {
      bubbles: true,
      cancelable: true,
    }));
    await waitUntil(() => messages.length === 1, "popup did not request a capture");
    await waitUntil(
      () => /Preview opened with 2 messages/.test(dom.window.document.querySelector("#status").textContent),
      "popup did not report capture success",
    );

    assert.equal(messages[0].type, "chatprint:capture");
    assert.deepEqual(JSON.parse(JSON.stringify(messages[0].options)), settings);
    assert.ok(storedValues.length >= 1);
  });
});

describe("background handoff regressions", () => {
  test("uses remaining session quota and clears only stale capture handoffs", async () => {
    const oldKey = `chatprint:capture:${Date.now() - (11 * 60 * 1000)}:old`;
    const recentKey = `chatprint:capture:${Date.now()}:recent`;
    const removed = [];
    const stored = [];
    const scriptCalls = [];
    let onMessage;
    const capture = {
      schemaVersion: 1,
      title: "Quota-aware capture",
      source: { hostname: "chat.example.test", url: "https://chat.example.test/thread" },
      capturedAt: "2026-09-04T00:00:00.000Z",
      options: shared.DEFAULT_OPTIONS,
      messages: [{ role: "assistant", text: "Answer", html: "<p>Answer</p>" }],
      diagnostics: {},
    };
    const session = {
      QUOTA_BYTES: 1_000_000,
      get: async () => ({ [oldKey]: capture, [recentKey]: capture }),
      getBytesInUse: async () => 200_000,
      remove: async (keys) => removed.push(...(Array.isArray(keys) ? keys : [keys])),
      set: async (value) => stored.push(value),
    };
    const context = vm.createContext({
      ChatprintShared: shared,
      URL,
      clearTimeout,
      console,
      importScripts() {},
      setTimeout,
      chrome: {
        action: {
          setBadgeBackgroundColor: async () => {},
          setBadgeText: async () => {},
        },
        commands: { onCommand: { addListener() {} } },
        runtime: {
          getURL: (value) => `chrome-extension://chatprint/${value}`,
          onMessage: { addListener(listener) { onMessage = listener; } },
        },
        scripting: {
          async executeScript(details) {
            scriptCalls.push(details);
            return details.files ? [] : [{ result: capture }];
          },
        },
        storage: { local: session, session },
        tabs: {
          create: async () => ({ id: 11 }),
          get: async () => ({ id: 7, url: "https://chat.example.test/thread" }),
          query: async () => [{ id: 7, url: "https://chat.example.test/thread" }],
        },
      },
    });
    vm.runInContext(fs.readFileSync(path.join(APP_ROOT, "background.js"), "utf8"), context);

    const response = await new Promise((resolve) => {
      const keepAlive = onMessage({ type: "chatprint:capture" }, {}, resolve);
      assert.equal(keepAlive, true);
    });

    assert.equal(response.ok, true);
    assert.deepEqual(removed, [oldKey]);
    assert.equal(scriptCalls.length, 2);
    assert.equal(scriptCalls[1].args[1], 588_800);
    assert.equal(stored.length, 1);
    assert.match(Object.keys(stored[0])[0], /^chatprint:capture:/);
  });
});
