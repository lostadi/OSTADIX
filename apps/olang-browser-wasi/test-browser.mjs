import { constants as fsConstants } from "node:fs";
import { createHash } from "node:crypto";
import {
  access,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, extname, join, resolve, sep } from "node:path";
import { pipeline } from "node:stream/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { launchBrowser } from "./browser-process.mjs";

const PASS_MARKER = "OSTADIX_BROWSER_WASI_DOM_PASS_V1";
const TEST_PAGE = "/__olang_browser_qualification__.html";
const DONE_RESOURCE = "/__olang_browser_qualification_done__";
// A cold browser has a separate deadline from the unchanged UI execution budget.
const STARTUP_TIMEOUT_MS = 60_000;
const LINUX_SCHEMA = "ostadix.olang-linux-browser-bundle/v1";

export function manifestSha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export async function verifyManifestUnchanged(path, expectedSha256) {
  if (manifestSha256(await readFile(path)) !== expectedSha256) {
    throw new Error("Bundle manifest changed during browser qualification");
  }
}

export function executionTimeout(manifest) {
  return manifest?.schema === LINUX_SCHEMA ? 600_000 : 30_000;
}

export function failureFixture(environment = process.env) {
  const name = environment.OLANG_BROWSER_FAILURE_ENV ?? "OSTADIX_WASM_EXPECT_FAILURE";
  const marker = environment.OLANG_BROWSER_FAILURE_MARKER ?? "OSTADIX WASM INTENTIONAL FAILURE";
  if (typeof name !== "string" || !/^[A-Z_][A-Z0-9_]*$/.test(name)) {
    throw new Error("OLANG_BROWSER_FAILURE_ENV must be an uppercase environment-variable name");
  }
  if (typeof marker !== "string" || marker.length === 0 || marker.length > 1024 || marker.includes("\0")) {
    throw new Error("OLANG_BROWSER_FAILURE_MARKER must be a nonempty, NUL-free string of at most 1024 characters");
  }
  return Object.freeze({ name, value: "1", marker });
}

export function qualificationPage(index, linux = false) {
  if (!index.includes("</body>")) {
    throw new Error("shipped index.html lacks a closing body element");
  }
  const qualification = `
    <script>
    window.__olangBrowserEvidence = { messages: [], heartbeat: null };
    for (const level of ["error", "warn"]) {
      const original = console[level].bind(console);
      console[level] = (...args) => {
        if (window.__olangBrowserEvidence.messages.length < 50) {
          window.__olangBrowserEvidence.messages.push({ level, message: args.map(String).join(" ") });
        }
        original(...args);
      };
    }
    addEventListener("error", (event) => {
      window.__olangBrowserEvidence.messages.push({ level: "error", message:
        event.message || "resource failed: " + (event.target?.src || event.target?.href || "unknown") });
    }, true);
    addEventListener("unhandledrejection", (event) => {
      window.__olangBrowserEvidence.messages.push({ level: "error", message: String(event.reason) });
    });
    window.__olangStartHeartbeat = () => {
      let previous = performance.now();
      let ticks = 0;
      let maximumGapMs = 0;
      const sample = () => {
        const now = performance.now();
        maximumGapMs = Math.max(maximumGapMs, now - previous);
        previous = now;
      };
      const timer = setInterval(() => { sample(); ticks += 1; }, 25);
      return () => {
        sample();
        clearInterval(timer);
        return { ticks, maximumGapMs };
      };
    };
    // Register during parsing; DOMContentLoaded waits for the shipped module and
    // its dependencies, even when this inline script arrives before they do.
    document.addEventListener("DOMContentLoaded", async () => {
      const runButton = document.querySelector("#run");
      const output = document.querySelector("#output");
      const expected = new URL(location.href).searchParams.get("expected");
      const passMarker = ["OSTADIX", "BROWSER", "WASI", "DOM", "PASS", "V1"].join("_");
      const failMarker = ["OSTADIX", "BROWSER", "WASI", "DOM", "FAIL", "V1"].join("_");
      let status = "fail";
      let stopHeartbeat;
      try {
        if (!globalThis.isSecureContext) throw new Error("loopback page is not a secure context");
        if (${linux} && !globalThis.crossOriginIsolated) throw new Error("Linux browser page is not cross-origin isolated");
        if (!(runButton instanceof HTMLButtonElement) || !(output instanceof HTMLElement)) {
          throw new Error("shipped browser UI selectors are missing");
        }
        const completed = new Promise((resolve) => {
          document.addEventListener("olang-browser-run-complete", resolve, { once: true });
        });
        if (${linux}) stopHeartbeat = window.__olangStartHeartbeat();
        runButton.click();
        const event = await completed;
        if (stopHeartbeat) {
          const heartbeat = stopHeartbeat();
          stopHeartbeat = null;
          window.__olangBrowserEvidence.heartbeat = heartbeat;
          if (heartbeat.ticks < 3 || heartbeat.maximumGapMs > 5000) {
            throw new Error("UI did not remain responsive: " + JSON.stringify(heartbeat));
          }
        }
        if (event.detail?.status !== "success" || event.detail?.exitCode !== 0) {
          throw new Error(\`program failed through UI: \${JSON.stringify(event.detail)}\`);
        }
        if (document.documentElement.dataset.olangExecution !== "success") {
          throw new Error("browser-main did not expose successful UI state");
        }
        if (expected === null || !output.textContent.includes(expected)) {
          throw new Error(\`UI output did not contain the expected marker: \${output.textContent}\`);
        }
        document.documentElement.setAttribute("data-olang-browser-qualification", "pass");
        document.documentElement.dataset.olangQualificationMarker = passMarker;
        status = "pass";
      } catch (error) {
        document.documentElement.setAttribute("data-olang-browser-qualification", "fail");
        const diagnostic = document.createElement("pre");
        diagnostic.textContent = failMarker + ": " + (error?.stack ?? error);
        document.body.append(diagnostic);
      } finally {
        if (stopHeartbeat) window.__olangBrowserEvidence.heartbeat = stopHeartbeat();
        const completion = new URLSearchParams({
          status,
          domStatus: document.documentElement.getAttribute("data-olang-browser-qualification") ?? "",
          domMarker: document.documentElement.dataset.olangQualificationMarker ?? "",
          domOutput: (output?.textContent ?? "").slice(0, 4096),
        });
        await fetch(\`${DONE_RESOURCE}?\${completion}\`, { cache: "no-store" });
      }
    }, { once: true });
    </script>
  `;
  return index.replace("</body>", `${qualification}</body>`);
}

const MIME_TYPES = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".O": "text/plain; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".wasm": "application/wasm",
});

function responseHeaders(contentType, contentLength) {
  return {
    "Cache-Control": "no-store",
    "Content-Length": contentLength,
    "Content-Type": contentType,
    "X-Content-Type-Options": "nosniff",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
  };
}

export function send(response, status, contentType, body, headOnly = false) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body);
  response.writeHead(status, responseHeaders(contentType, bytes.byteLength));
  response.end(headOnly ? undefined : bytes);
}

export async function createBundleServer(bundleRoot, linux, { openAsset = open } = {}) {
  const page = qualificationPage(await readFile(join(bundleRoot, "index.html"), "utf8"), linux);
  const requestLog = [];
  let completionStatus;
  let resolveCompletion;
  const completion = new Promise((resolvePromise) => {
    resolveCompletion = resolvePromise;
  });
  const server = createServer((request, response) => {
    void (async () => {
      const method = request.method ?? "GET";
      if (method !== "GET" && method !== "HEAD") {
        send(response, 405, "text/plain; charset=utf-8", "method not allowed\n", method === "HEAD");
        return;
      }

      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      requestLog.push(`${method} ${url.pathname}${url.search}`);
      if (url.pathname === TEST_PAGE) {
        send(response, 200, MIME_TYPES[".html"], page, method === "HEAD");
        return;
      }
      if (url.pathname === DONE_RESOURCE) {
        const status = url.searchParams.get("status");
        const domStatus = url.searchParams.get("domStatus");
        const domMarker = url.searchParams.get("domMarker");
        const domOutput = url.searchParams.get("domOutput");
        if (status !== "pass" && status !== "fail") {
          send(response, 400, "text/plain; charset=utf-8", "invalid completion status\n");
          return;
        }
        if (completionStatus !== undefined && completionStatus !== status) {
          send(response, 409, "text/plain; charset=utf-8", "completion status changed\n");
          return;
        }
        const firstCompletion = completionStatus === undefined;
        completionStatus = status;
        send(response, 200, "text/plain; charset=utf-8", `${status}\n`, method === "HEAD");
        if (firstCompletion) resolveCompletion({ status, domStatus, domMarker, domOutput });
        return;
      }

      let pathname;
      try {
        pathname = decodeURIComponent(url.pathname);
      } catch {
        send(response, 400, "text/plain; charset=utf-8", "invalid URL encoding\n");
        return;
      }
      const relative = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
      const candidate = resolve(bundleRoot, relative);
      if (candidate !== bundleRoot && !candidate.startsWith(`${bundleRoot}${sep}`)) {
        send(response, 403, "text/plain; charset=utf-8", "path escapes bundle root\n");
        return;
      }

      let canonical;
      try {
        canonical = await realpath(candidate);
      } catch {
        send(response, 404, "text/plain; charset=utf-8", "not found\n");
        return;
      }
      if (!canonical.startsWith(`${bundleRoot}${sep}`)) {
        send(response, 403, "text/plain; charset=utf-8", "symlink escapes bundle root\n");
        return;
      }

      let asset;
      try {
        // Refuse a leaf replaced by a symlink after the confinement check.
        asset = await openAsset(canonical, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
      } catch {
        send(response, 404, "text/plain; charset=utf-8", "not found\n", method === "HEAD");
        return;
      }
      try {
        const metadata = await asset.stat();
        if (!metadata.isFile()) {
          send(response, 404, "text/plain; charset=utf-8", "not found\n", method === "HEAD");
          return;
        }
        if (response.destroyed) return;
        const contentType = MIME_TYPES[extname(canonical)] ?? "application/octet-stream";
        response.writeHead(200, responseHeaders(contentType, metadata.size));
        if (method === "HEAD" || metadata.size === 0) {
          response.end();
          return;
        }
        // Stream the opened file under HTTP backpressure, including large Wasm
        // artifacts. HEAD creates no reader. Limit the reader to the fstat size
        // so concurrent growth cannot exceed the declared Content-Length.
        await pipeline(asset.createReadStream({
          autoClose: false, highWaterMark: 64 * 1024, start: 0, end: metadata.size - 1,
        }), response);
      } finally {
        // pipeline destroys the reader on client abort or read failure; this
        // owner closes the descriptor on every path, including HEAD and errors.
        await asset.close();
      }
    })().catch((error) => {
      if (response.destroyed) return;
      if (!response.headersSent) {
        send(response, 500, "text/plain; charset=utf-8", `server error: ${error.message}\n`);
      } else {
        response.destroy(error);
      }
    });
  });

  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  server.requestLog = requestLog;
  server.completion = completion;
  return server;
}

async function findBrowser() {
  const candidates = [
    process.env.CHROME_BIN,
    process.env.GOOGLE_CHROME_BIN,
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
  ].filter(Boolean);

  for (const candidate of [...new Set(candidates)]) {
    const paths = candidate.includes(sep)
      ? [candidate]
      : (process.env.PATH ?? "").split(delimiter).map((directory) => join(directory, candidate));
    for (const command of paths) {
      try {
        await access(command, fsConstants.X_OK);
        if ((await stat(command)).isFile()) return command;
      } catch (error) {
        if (!["ENOENT", "ENOTDIR", "EACCES"].includes(error?.code)) throw error;
      }
    }
  }
  throw new Error(
    "browser qualification requires Google Chrome or Chromium; install one or set CHROME_BIN to its executable",
  );
}

export async function evidenceDirectory(requested) {
  if (!requested) return mkdtemp(join(tmpdir(), "olang-browser-evidence-"));
  const candidate = resolve(requested);
  const canonical = join(await realpath(dirname(candidate)), basename(candidate));
  const repository = await realpath(fileURLToPath(new URL("../../", import.meta.url)));
  if (canonical === repository || canonical.startsWith(`${repository}${sep}`)) {
    throw new Error("browser evidence must be saved outside the repository");
  }
  await mkdir(canonical, { mode: 0o700 });
  return canonical;
}

async function captureEvidence(browserProcess, sessionId, directory, phase) {
  const dom = await browserProcess.send("Runtime.evaluate", {
    expression: `({ url: location.href, title: document.title,
      heading: document.querySelector("h1")?.textContent,
      runLabel: document.querySelector("#run")?.textContent,
      runDisabled: document.querySelector("#run")?.disabled,
      status: document.documentElement.getAttribute("data-olang-browser-qualification"),
      execution: document.documentElement.dataset.olangExecution,
      marker: document.documentElement.dataset.olangQualificationMarker,
      output: document.querySelector("#output")?.textContent,
      body: document.body.innerText.slice(0, 16384),
      overlay: Boolean(document.querySelector("nextjs-portal, vite-error-overlay, #webpack-dev-server-client-overlay")),
      evidence: window.__olangBrowserEvidence })`,
    returnByValue: true,
  }, sessionId);
  if (dom.exceptionDetails || !dom.result?.value) {
    throw new Error(`could not inspect browser DOM: ${JSON.stringify(dom)}`);
  }
  const state = dom.result.value;
  const screenshot = await browserProcess.send("Page.captureScreenshot", {
    format: "png", captureBeyondViewport: false,
  }, sessionId);
  await writeFile(join(directory, `${phase}.png`), Buffer.from(screenshot.data, "base64"), { flag: "wx" });
  await writeFile(join(directory, `${phase}.json`), `${JSON.stringify(state, null, 2)}\n`, { flag: "wx" });
  return state;
}

export function validatePageEvidence(state, expectedUrl, expectedTitle, expectedStdout, linux = false) {
  if (state.url !== expectedUrl || state.title !== expectedTitle) {
    throw new Error(`browser page identity mismatch: ${JSON.stringify({ url: state.url, title: state.title })}`);
  }
  if (!state.heading?.trim() || !state.runLabel?.trim() || !state.body?.includes(expectedStdout)) {
    throw new Error("browser page lacks meaningful application content");
  }
  if (state.overlay) throw new Error("browser shows a framework error overlay");
  if (!Array.isArray(state.evidence?.messages)) {
    throw new Error("browser console/resource observations are missing");
  }
  if (state.evidence.messages.length) {
    throw new Error(`browser console/resource errors: ${JSON.stringify(state.evidence.messages)}`);
  }
  if (state.status !== "pass" || state.execution !== "success" || state.marker !== PASS_MARKER
      || !state.output?.includes(expectedStdout) || state.runDisabled !== false) {
    throw new Error(`browser DOM did not confirm successful UI execution: ${JSON.stringify(state)}`);
  }
  if (linux && (!Number.isSafeInteger(state.evidence?.heartbeat?.ticks)
      || state.evidence.heartbeat.ticks < 3
      || !(state.evidence?.heartbeat?.maximumGapMs <= 5000))) {
    throw new Error("Linux worker execution did not prove a responsive UI heartbeat");
  }
}

async function main() {
  const [bundleArgument, expectedStdout] = process.argv.slice(2);
  if (!bundleArgument || expectedStdout === undefined) {
    throw new Error("usage: node test-browser.mjs BUNDLE_DIR EXPECTED_STDOUT_SUBSTRING");
  }
  const bundleRoot = await realpath(resolve(bundleArgument));
  const manifestPath = join(bundleRoot, "manifest.json");
  const manifestBytes = await readFile(manifestPath);
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const linux = manifest.schema === LINUX_SCHEMA;
  const failure = linux ? failureFixture() : null;
  const expectedTitle = /<title>([^<]+)<\/title>/i.exec(await readFile(join(bundleRoot, "index.html"), "utf8"))?.[1];
  if (!expectedTitle) throw new Error("shipped browser page must declare a meaningful title");
  for (const path of [
    "manifest.json",
    "program.O",
    "program.plan.txt",
    "program.wasm",
    "runner.mjs",
    "wasi-preview1-host.mjs",
  ]) {
    await access(join(bundleRoot, path), fsConstants.R_OK);
  }

  const browser = await findBrowser();
  const evidencePath = await evidenceDirectory(process.env.OLANG_BROWSER_EVIDENCE_DIR);
  const evidence = {
    schema: "ostadix.browser-qualification/v1", status: "running", profile: manifest.schema,
    artifact_sha256: manifest.artifact.sha256, source_sha256: manifest.source.sha256,
    manifest_sha256: manifestSha256(manifestBytes),
    viewport: { width: 1280, height: 900 }, browserPath: browser,
    browserPlugin: "not available; existing repository browser E2E harness",
    executionTimeoutMs: executionTimeout(manifest), checks: {},
    expectedFailure: failure,
  };
  console.log(`browser evidence -> ${evidencePath}`);
  const profileDirectory = await mkdtemp(join(tmpdir(), "olang-browser-qualification-"));
  let server;
  let browserProcess;
  let interruption;
  const interrupted = (signal) => {
    interruption = new Error(`browser qualification interrupted by ${signal}`);
    browserProcess?.abort(interruption);
  };
  process.on("SIGINT", interrupted);
  process.on("SIGTERM", interrupted);

  try {
    server = await createBundleServer(bundleRoot, linux);
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("loopback browser-test server did not expose a TCP address");
    }
    const testUrl = new URL(TEST_PAGE, `http://127.0.0.1:${address.port}`);
    testUrl.searchParams.set("expected", expectedStdout);

    browserProcess = launchBrowser(browser, [
      "--headless",
      "--remote-debugging-pipe",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-default-apps",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--disable-sync",
      "--metrics-recording-only",
      "--no-default-browser-check",
      "--no-first-run",
      "--hide-scrollbars",
      "--mute-audio",
      "--password-store=basic",
      "--use-mock-keychain",
      `--user-data-dir=${profileDirectory}`,
      "about:blank",
    ]);
    if (interruption) browserProcess.abort(interruption);
    const started = Date.now();
    const { version, sessionId } = await browserProcess.phase("browser startup/readiness", STARTUP_TIMEOUT_MS, async () => {
      const version = await browserProcess.send("Browser.getVersion");
      const { targetId } = await browserProcess.send("Target.createTarget", { url: "about:blank" });
      const { sessionId } = await browserProcess.send("Target.attachToTarget", { targetId, flatten: true });
      await browserProcess.send("Page.enable", {}, sessionId);
      await browserProcess.send("Emulation.setDeviceMetricsOverride", {
        width: 1280, height: 900, deviceScaleFactor: 1, mobile: false,
      }, sessionId);
      return { version, sessionId };
    });
    const startupMs = Date.now() - started;
    evidence.browser = version.product;
    evidence.url = testUrl.href;
    evidence.startupMs = startupMs;
    const executionStarted = Date.now();
    await browserProcess.phase("browser navigation/UI execution", executionTimeout(manifest), async () => {
      const navigation = await browserProcess.send("Page.navigate", { url: testUrl.href }, sessionId);
      if (navigation.errorText) throw new Error(`browser navigation failed: ${navigation.errorText}`);
      const completion = await server.completion;
      // Preserve the real rendered output in the screenshot and DOM evidence,
      // including on a failing completion. Never replace it with a PASS marker.
      const state = await captureEvidence(browserProcess, sessionId, evidencePath, "ui-success");
      evidence.checks.ui = state;
      if (
        completion.status !== "pass"
        || completion.domStatus !== "pass"
        || completion.domMarker !== PASS_MARKER
      ) {
        throw new Error(`browser UI qualification failed: ${JSON.stringify(completion)}`);
      }
      validatePageEvidence(state, testUrl.href, expectedTitle, expectedStdout, linux);
    });
    if (linux) {
      await browserProcess.phase("Linux intentional failure", 600_000, async () => {
        const checked = await browserProcess.send("Runtime.evaluate", {
          expression: `(async () => {
            const { runOlangBrowserBundle } = await import("./linux-runner.mjs");
            const stopHeartbeat = window.__olangStartHeartbeat();
            let result;
            try {
              result = await runOlangBrowserBundle({ env: ${JSON.stringify({ [failure.name]: failure.value })} });
            } finally {
              window.__olangBrowserEvidence.failureHeartbeat = stopHeartbeat();
            }
            const panel = document.createElement("section");
            panel.id = "linux-failure-qualification";
            const heading = document.createElement("h2");
            heading.textContent = "Intentional failure — verified runner";
            const output = document.createElement("pre");
            output.textContent = "exit: " + result.exitCode + "\\nstdout:\\n" + result.stdout + "\\nstderr:\\n" + result.stderr;
            panel.append(heading, output);
            document.body.append(panel);
            return { ok: result.ok, exitCode: result.exitCode, stdout: result.stdout,
              stderr: result.stderr, executionMode: result.executionMode,
              heartbeat: window.__olangBrowserEvidence.failureHeartbeat };
          })()`,
          awaitPromise: true, returnByValue: true,
        }, sessionId);
        const result = checked.result?.value;
        evidence.checks.intentionalFailure = result ?? checked;
        const state = await captureEvidence(browserProcess, sessionId, evidencePath, "intentional-failure");
        validatePageEvidence(state, testUrl.href, expectedTitle, expectedStdout, true);
        if (checked.exceptionDetails || !result || result.ok !== false || result.exitCode !== 1
            || result.executionMode !== "browser-embedded-linux-wasi"
            || !(result.stdout + result.stderr).includes(failure.marker)
            || result.stdout.includes(expectedStdout)
            || !Number.isSafeInteger(result.heartbeat?.ticks)
            || result.heartbeat.ticks < 3 || !(result.heartbeat?.maximumGapMs <= 5000)) {
          throw new Error(`Linux guest failure did not propagate correctly: ${JSON.stringify(checked)}`);
        }
      });
    }
    await verifyManifestUnchanged(manifestPath, evidence.manifest_sha256);
    evidence.status = "passed";
    evidence.executionMs = Date.now() - executionStarted;
    console.log(`${PASS_MARKER} (${version.product}; startup=${startupMs}ms execution=${Date.now() - executionStarted}ms)`);
  } catch (error) {
    evidence.status = "failed";
    evidence.error = error.message;
    throw new Error(`${error.message}; requests:\n${server?.requestLog.join("\n") ?? ""}\n${browserProcess?.stderr ?? ""}`, { cause: error });
  } finally {
    try {
      await writeFile(join(evidencePath, "receipt.json"), `${JSON.stringify(evidence, null, 2)}\n`);
    } finally {
    try {
      try {
        await browserProcess?.close();
      } finally {
        if (server) {
          server.closeAllConnections?.();
          await new Promise((resolveClose) => server.close(resolveClose));
        }
        await rm(profileDirectory, { recursive: true, force: true, maxRetries: 3 });
      }
    } finally {
      process.off("SIGINT", interrupted);
      process.off("SIGTERM", interrupted);
    }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
