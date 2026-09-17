"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { describe, test } = require("node:test");
const { JSDOM } = require("jsdom");

const APP_ROOT = path.resolve(__dirname, "..");
const MOBILE_ROOT = path.join(APP_ROOT, "mobile");
const DIST_ROOT = path.join(MOBILE_ROOT, "dist");
const BUILD = path.join(MOBILE_ROOT, "build.cjs");
const BOOKMARKLET = path.join(DIST_ROOT, "chatprint-mobile.txt");
const MINIFIED = path.join(DIST_ROOT, "chatprint-mobile.min.js");

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function decodedBundle() {
  const value = fs.readFileSync(BOOKMARKLET, "utf8").trim();
  return decodeURIComponent(value.slice("javascript:".length));
}

function makeRuntime(openPreview = true) {
  const source = new JSDOM(`<!doctype html><html><head><title>Garden plan — Claude</title></head><body>
    <header>Outside whole-page heading</header>
    <main id="chat">
      <article data-testid="user-message"><p>First question.</p></article>
      <article data-testid="assistant-message"><p>First answer with <a href="/safe">a source</a>.</p></article>
      <article data-testid="user-message"><p>Second question.</p></article>
      <article data-testid="assistant-message">
        <h2>Second answer</h2>
        <pre><code class="language-js">const answer = 42;</code></pre>
        <table><thead><tr><th>Task</th><th>Why</th></tr></thead><tbody><tr><td>Capture</td><td>Selectable text</td></tr></tbody></table>
        <a href="javascript:alert(1)" onclick="steal()">Unsafe destination</a>
        <img src="https://images.example.test/chart.png" alt="Garden chart" onerror="steal()">
        <script>globalThis.pwned = true</script>
      </article>
      <section style="display:none"><article data-testid="assistant-message">Hidden answer</article></section>
    </main>
  </body></html>`, {
    pretendToBeVisual: true,
    runScripts: "outside-only",
    url: "https://claude.ai/chat/thread-id",
  });
  const preview = new JSDOM("<!doctype html><html><head></head><body></body></html>", {
    pretendToBeVisual: true,
    runScripts: "outside-only",
    url: "https://claude.ai/chatprint-preview",
  });
  const calls = { alerts: [], focus: 0, open: 0, print: 0, synchronousOpen: false };
  let evaluating = false;
  source.window.alert = (message) => calls.alerts.push(String(message));
  source.window.focus = () => { calls.focus += 1; };
  source.window.fetch = () => { throw new Error("network access is forbidden"); };
  source.window.XMLHttpRequest = class ForbiddenRequest {
    constructor() { throw new Error("network access is forbidden"); }
  };
  source.window.URL.createObjectURL = undefined;
  preview.window.closed = false;
  preview.window.focus = () => { calls.focus += 1; };
  preview.window.print = () => { calls.print += 1; };
  preview.window.stop = () => {};
  source.window.open = () => {
    calls.open += 1;
    calls.synchronousOpen = evaluating;
    return openPreview ? preview.window : null;
  };
  const before = source.window.document.documentElement.outerHTML;
  evaluating = true;
  let returnValue;
  try {
    returnValue = source.window.eval(decodedBundle());
  } finally {
    evaluating = false;
  }
  return { before, calls, preview, returnValue, source };
}

describe("mobile bookmarklet build", () => {
  test("is deterministic, checksum-complete, one-line, and below the 32 KiB ceiling", () => {
    const before = new Map(
      fs.readdirSync(DIST_ROOT).sort().map((name) => [name, fs.readFileSync(path.join(DIST_ROOT, name))]),
    );
    execFileSync(process.execPath, [BUILD], { cwd: APP_ROOT, stdio: "pipe" });
    for (const [name, contents] of before) {
      assert.deepEqual(fs.readFileSync(path.join(DIST_ROOT, name)), contents, `${name} changed across identical builds`);
    }

    const bookmarklet = fs.readFileSync(BOOKMARKLET, "utf8");
    const minified = fs.readFileSync(MINIFIED, "utf8");
    assert.ok(bookmarklet.startsWith("javascript:"));
    assert.ok(Buffer.byteLength(bookmarklet) <= 32 * 1024, `bookmarklet is ${Buffer.byteLength(bookmarklet)} bytes`);
    assert.doesNotMatch(bookmarklet.trim(), /[\r\n]/u);
    assert.equal(decodedBundle(), minified.trim());
    assert.match(decodedBundle(), /;void 0$/u);
    assert.doesNotMatch(decodedBundle(), /\b(?:fetch|XMLHttpRequest|WebSocket|importScripts|sendBeacon|eval|Function)\s*\(/u);
    assert.doesNotMatch(decodedBundle(), /\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|DOMParser)\b/u);

    const manifest = JSON.parse(fs.readFileSync(path.join(DIST_ROOT, "build.json"), "utf8"));
    assert.equal(manifest.schemaVersion, 1);
    assert.equal(manifest.transform, "shared-mobile-export-v1");
    for (const input of manifest.inputs) {
      assert.equal(hash(fs.readFileSync(path.join(APP_ROOT, input.path))), input.sha256);
    }
    for (const output of manifest.outputs) {
      const contents = fs.readFileSync(path.join(APP_ROOT, output.path));
      assert.equal(contents.byteLength, output.bytes);
      assert.equal(hash(contents), output.sha256);
    }

    const installerText = fs.readFileSync(path.join(DIST_ROOT, "install.html"), "utf8");
    assert.doesNotMatch(installerText, /__BOOKMARKLET_/u);
    assert.ok(installerText.includes(JSON.stringify(bookmarklet.trim())), "installer does not embed the built bookmarklet exactly");
    const installer = new JSDOM(installerText);
    assert.equal(installer.window.document.querySelector("script[src],link[rel='stylesheet']"), null);
    assert.equal(installer.window.document.querySelector("h1").textContent.replace(/\s+/gu, " ").trim(), "Print AI chats from your phone");
    assert.equal(installer.window.document.querySelectorAll(".steps li").length, 3);
  });
});

describe("mobile bookmarklet runtime", () => {
  test("invokes the built bundle synchronously and renders alternating safe semantic content", async () => {
    const runtime = makeRuntime(true);
    const document = runtime.preview.window.document;

    assert.equal(runtime.returnValue, undefined);
    assert.equal(runtime.calls.open, 1);
    assert.equal(runtime.calls.synchronousOpen, true);
    assert.deepEqual(runtime.calls.alerts, []);
    assert.equal(runtime.source.window.document.documentElement.outerHTML, runtime.before, "capture mutated the source DOM");
    assert.deepEqual(Array.from(document.querySelectorAll(".role"), (node) => node.textContent), [
      "You", "Assistant", "You", "Assistant",
    ]);
    assert.equal(document.querySelector(".document-header h1").textContent, "Garden plan");
    assert.equal(document.querySelector("pre code").textContent, "const answer = 42;");
    assert.equal(document.querySelector("table tbody td").textContent, "Capture");
    assert.equal(document.querySelector("script,iframe,object,embed"), null);
    assert.equal(document.querySelector(".body img"), null, "mobile images must default off");
    assert.match(document.querySelector(".body").parentElement.parentElement.textContent, /Garden chart/);
    assert.doesNotMatch(document.body.textContent, /Hidden answer/);
    const anchors = Array.from(document.querySelectorAll(".body a"));
    assert.equal(anchors[0].href, "https://claude.ai/safe");
    assert.equal(anchors[0].target, "_blank");
    assert.equal(anchors[0].rel, "noreferrer noopener");
    assert.equal(anchors[1].hasAttribute("href"), false);
    assert.equal(document.querySelector(".meta a").href, "https://claude.ai/");

    const screenHeader = document.querySelector(".screen-header");
    runtime.preview.window.dispatchEvent(new runtime.preview.window.Event("beforeprint"));
    assert.equal(screenHeader.hidden, true);
    runtime.preview.window.dispatchEvent(new runtime.preview.window.Event("afterprint"));
    assert.equal(screenHeader.hidden, false);
    document.querySelector(".print").click();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(runtime.calls.print, 1);
  });

  test("supports whole-page and images-on recapture without leaking a referrer", () => {
    const runtime = makeRuntime(true);
    const document = runtime.preview.window.document;
    const mode = document.querySelector("select[aria-label='Capture mode']");
    mode.value = "page";
    mode.dispatchEvent(new runtime.preview.window.Event("change"));
    assert.match(document.querySelector(".paper").textContent, /Outside whole-page heading/);

    const images = document.querySelector("select[aria-label='Images']");
    images.value = "on";
    images.dispatchEvent(new runtime.preview.window.Event("change"));
    const image = document.querySelector(".body img");
    assert.equal(image.src, "https://images.example.test/chart.png");
    assert.equal(image.referrerPolicy, "no-referrer");
    assert.equal(image.getAttribute("onerror"), null);
  });

  test("reports a denied preview cleanly without throwing or touching the page", () => {
    const runtime = makeRuntime(false);
    assert.equal(runtime.returnValue, undefined);
    assert.equal(runtime.calls.open, 1);
    assert.equal(runtime.calls.synchronousOpen, true);
    assert.equal(runtime.source.window.document.documentElement.outerHTML, runtime.before);
    assert.equal(runtime.calls.alerts.length, 1);
    assert.match(runtime.calls.alerts[0], /Allow pop-ups/iu);
  });
});
