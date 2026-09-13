import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { mkdir, mkdtemp, open, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Script } from "node:vm";
import { launchBrowser } from "./browser-process.mjs";
import {
  createBundleServer, evidenceDirectory, executionTimeout, failureFixture, qualificationPage, send, validatePageEvidence,
  manifestSha256, verifyManifestUnchanged,
} from "./test-browser.mjs";

assert.equal(executionTimeout({ schema: "ostadix.olang-browser-bundle/v1" }), 30_000);
assert.equal(executionTimeout({ schema: "ostadix.olang-linux-browser-bundle/v1" }), 600_000);
assert.equal(executionTimeout({ schema: "unknown" }), 30_000);
assert.deepEqual(failureFixture({}), {
  name: "OSTADIX_WASM_EXPECT_FAILURE", value: "1", marker: "OSTADIX WASM INTENTIONAL FAILURE",
});
assert.deepEqual(failureFixture({
  OLANG_BROWSER_FAILURE_ENV: "OSTADIX_GUIX_FORCE_FAILURE",
  OLANG_BROWSER_FAILURE_MARKER: "OSTADIX_GUIX_INTENTIONAL_FAILURE",
}), { name: "OSTADIX_GUIX_FORCE_FAILURE", value: "1", marker: "OSTADIX_GUIX_INTENTIONAL_FAILURE" });
for (const name of ["", "lowercase", "1_INVALID", "INJECT=1", "HAS SPACE", "X\nY", "X\0Y"]) {
  assert.throws(() => failureFixture({ OLANG_BROWSER_FAILURE_ENV: name }), /environment-variable/);
}
for (const marker of ["", "X\0Y", "x".repeat(1025)]) {
  assert.throws(() => failureFixture({ OLANG_BROWSER_FAILURE_MARKER: marker }), /MARKER/);
}
const pageSource = "<html><head><title>Fixture</title></head><body><h1>Fixture</h1></body></html>";
for (const linux of [false, true]) {
  const page = qualificationPage(pageSource, linux);
  assert.match(page, /<title>Fixture<\/title>/);
  assert.ok(page.includes(`if (${linux}) stopHeartbeat`));
  assert.ok(page.includes("maximumGapMs > 5000"));
  assert.ok(page.includes("dataset.olangQualificationMarker = passMarker"));
  assert.ok(!page.includes("output.textContent = passMarker"));
  assert.ok(page.includes("diagnostic.textContent = failMarker"));
  assert.ok(page.includes("console[level] ="));
  const script = /<script>([\s\S]*?)<\/script>/.exec(page)?.[1];
  assert.ok(script);
  new Script(script, { filename: "browser-qualification-fixture.js" });
}
assert.throws(() => qualificationPage("<html></html>"), /closing body/);
let served;
send({
  writeHead(status, headers) { served = { status, headers }; },
  end(body) { served.body = body; },
}, 200, "text/plain", "fixture");
assert.equal(served.status, 200);
assert.equal(served.headers["Cross-Origin-Opener-Policy"], "same-origin");
assert.equal(served.headers["Cross-Origin-Embedder-Policy"], "require-corp");
assert.equal(served.body.toString(), "fixture");

const pageEvidence = {
  url: "http://127.0.0.1/fixture", title: "Fixture", heading: "Olang",
  runLabel: "Run program", runDisabled: false, body: "OSTADIX WASM Linux 42",
  output: "status: success\nexit: 0\nOSTADIX WASM Linux 42", overlay: false,
  status: "pass", execution: "success", marker: "OSTADIX_BROWSER_WASI_DOM_PASS_V1",
  evidence: { messages: [], heartbeat: { ticks: 100, maximumGapMs: 30 } },
};
const checkEvidence = (value, linux = true) => validatePageEvidence(
  value, pageEvidence.url, pageEvidence.title, "OSTADIX WASM Linux 42", linux,
);
checkEvidence(pageEvidence);
const directEvidence = structuredClone(pageEvidence);
delete directEvidence.evidence.heartbeat;
checkEvidence(directEvidence, false);
assert.throws(() => checkEvidence(directEvidence), /heartbeat/);
for (const [key, value, message] of [
  ["url", "http://unexpected/", /identity/],
  ["title", "Wrong", /identity/],
  ["heading", "", /meaningful/],
  ["body", "", /meaningful/],
  ["overlay", true, /overlay/],
  ["runDisabled", true, /successful UI/],
  ["execution", "failure", /successful UI/],
  ["output", "OSTADIX_BROWSER_WASI_DOM_PASS_V1", /successful UI/],
]) assert.throws(() => checkEvidence({ ...pageEvidence, [key]: value }), message);
for (const heartbeat of [{ ticks: 1, maximumGapMs: 25 }, { ticks: 100, maximumGapMs: 5001 }, { maximumGapMs: 10 }]) {
  assert.throws(() => checkEvidence({ ...pageEvidence, evidence: { messages: [], heartbeat } }), /heartbeat/);
}
assert.throws(() => checkEvidence({ ...pageEvidence, evidence: { messages: [{ level: "error", message: "fixture" }] } }), /console/);
assert.throws(() => checkEvidence({ ...pageEvidence, evidence: {} }), /observations/);

const evidenceParent = await mkdtemp(join(tmpdir(), "olang-browser-evidence-test-"));
try {
  assert.equal(manifestSha256(Buffer.from("abc")),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const manifestPath = join(evidenceParent, "manifest.json");
  const manifestBytes = Buffer.from('{"assets":[{"path":"linux-worker.mjs","sha256":"fixture"}]}\n');
  await writeFile(manifestPath, manifestBytes);
  const expectedManifestHash = manifestSha256(manifestBytes);
  await verifyManifestUnchanged(manifestPath, expectedManifestHash);
  // Even equivalent JSON is not the exact qualified manifest bytes.
  await writeFile(manifestPath, Buffer.concat([manifestBytes, Buffer.from("\n")]));
  await assert.rejects(verifyManifestUnchanged(manifestPath, expectedManifestHash), /manifest changed/);
  await writeFile(manifestPath, manifestBytes.toString().replace("fixture", "changed-worker"));
  await assert.rejects(verifyManifestUnchanged(manifestPath, expectedManifestHash), /manifest changed/);
  await assert.rejects(verifyManifestUnchanged(join(evidenceParent, "missing.json"), expectedManifestHash),
    { code: "ENOENT" });

  const destination = join(evidenceParent, "fresh");
  const created = await evidenceDirectory(destination);
  await writeFile(join(created, "keep.txt"), "keep");
  if (process.platform !== "win32") assert.equal((await stat(created)).mode & 0o777, 0o700);
  await assert.rejects(evidenceDirectory(destination), { code: "EEXIST" });
  assert.equal(await readFile(join(created, "keep.txt"), "utf8"), "keep");
  await assert.rejects(evidenceDirectory(fileURLToPath(new URL("../../forbidden-browser-evidence", import.meta.url))), /outside the repository/);
} finally {
  await rm(evidenceParent, { recursive: true, force: true });
}

// Real HTTP requests exercise the same server used by browser qualification.
// Instrument only file opening to prove HEAD performs no reads and aborted
// downloads close their actual descriptor; the response bytes are not mocked.
const servingParent = await mkdtemp(join(tmpdir(), "olang-browser-serving-test-"));
let bundleServer;
try {
  const bundle = join(servingParent, "bundle");
  await mkdir(bundle);
  await writeFile(join(bundle, "index.html"), pageSource);
  const wasmBytes = Buffer.alloc(256 * 1024 + 137);
  for (let index = 0; index < wasmBytes.length; index += 1) wasmBytes[index] = index % 251;
  await writeFile(join(bundle, "program.wasm"), wasmBytes);
  await writeFile(join(bundle, "read-error.wasm"), wasmBytes);
  await writeFile(join(bundle, "empty.txt"), "");
  const sparse = await open(join(bundle, "abort.wasm"), "wx");
  try { await sparse.truncate(32 * 1024 * 1024); } finally { await sparse.close(); }
  await writeFile(join(servingParent, "outside.txt"), "must not be served");
  await symlink(join(servingParent, "outside.txt"), join(bundle, "escape.txt"));
  const opened = [];
  bundleServer = await createBundleServer(await realpath(bundle), true, {
    async openAsset(path, flags) {
      const file = await open(path, flags);
      const observation = { path, streams: [], closed: false };
      opened.push(observation);
      return {
        stat: () => file.stat(),
        createReadStream(options) {
          assert.equal(options.highWaterMark, 64 * 1024);
          assert.equal(options.autoClose, false);
          const stream = file.createReadStream(options);
          if (path.endsWith("/read-error.wasm")) {
            stream.once("data", () => stream.destroy(new Error("injected asset read failure")));
          }
          observation.streams.push(stream);
          return stream;
        },
        async close() { await file.close(); observation.closed = true; },
      };
    },
  });
  const port = bundleServer.address().port;
  const requestOptions = (path, method = "GET") => ({
    host: "127.0.0.1", port, path, method, agent: false,
  });
  const fetchAsset = (path, method = "GET") => new Promise((resolveRequest, rejectRequest) => {
    const request = httpRequest(requestOptions(path, method), (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.once("error", rejectRequest);
      response.once("end", () => resolveRequest({
        status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks),
      }));
    });
    request.setTimeout(5_000, () => request.destroy(new Error("HTTP regression request timed out")));
    request.once("error", rejectRequest);
    request.end();
  });
  const waitForClosedAssets = async () => {
    for (let attempt = 0; attempt < 100 && opened.some((asset) => !asset.closed); attempt += 1) {
      await delay(10);
    }
    assert.ok(opened.every((asset) => asset.closed), "HTTP asset descriptor survived request cleanup");
  };

  const received = await fetchAsset("/program.wasm");
  assert.equal(received.status, 200);
  assert.deepEqual(received.body, wasmBytes);
  assert.equal(received.headers["content-length"], String(wasmBytes.length));
  assert.equal(received.headers["content-type"], "application/wasm");
  assert.equal(received.headers["cross-origin-opener-policy"], "same-origin");
  assert.equal(received.headers["cross-origin-embedder-policy"], "require-corp");
  await waitForClosedAssets();
  assert.equal(opened.at(-1).streams.length, 1);

  const head = await fetchAsset("/program.wasm", "HEAD");
  assert.equal(head.status, 200);
  assert.equal(head.body.length, 0);
  assert.deepEqual(head.headers["content-length"], received.headers["content-length"]);
  assert.equal(head.headers["content-type"], "application/wasm");
  await waitForClosedAssets();
  assert.equal(opened.at(-1).streams.length, 0, "HEAD opened a file reader");

  const empty = await fetchAsset("/empty.txt");
  assert.equal(empty.status, 200);
  assert.equal(empty.headers["content-length"], "0");
  assert.equal(empty.body.length, 0);
  await waitForClosedAssets();
  assert.equal(opened.at(-1).streams.length, 0);

  await new Promise((resolveAbort, rejectAbort) => {
    let aborted = false;
    const request = httpRequest(requestOptions("/abort.wasm"), (response) => {
      response.once("error", (error) => { if (!aborted) rejectAbort(error); });
      response.once("data", () => {
        aborted = true;
        response.destroy();
        request.destroy();
        resolveAbort();
      });
      response.once("end", () => { if (!aborted) rejectAbort(new Error("download ended before abort")); });
    });
    request.setTimeout(5_000, () => request.destroy(new Error("HTTP abort regression timed out")));
    request.once("error", (error) => { if (!aborted) rejectAbort(error); });
    request.end();
  });
  await waitForClosedAssets();
  assert.equal(opened.at(-1).streams.length, 1);
  assert.equal(opened.at(-1).streams[0].destroyed, true);
  assert.ok(opened.at(-1).streams[0].bytesRead < 32 * 1024 * 1024, "aborted transfer read the entire artifact");
  assert.deepEqual((await fetchAsset("/program.wasm")).body, wasmBytes, "server failed after client abort");
  await assert.rejects(fetchAsset("/read-error.wasm"), /aborted|socket hang up|ECONNRESET/);
  await waitForClosedAssets();
  assert.equal(opened.at(-1).streams[0].destroyed, true, "failed asset reader survived cleanup");

  assert.equal((await fetchAsset("/escape.txt")).status, 403);
  assert.equal((await fetchAsset("/..%2foutside.txt")).status, 403);
  assert.equal((await fetchAsset("/missing.wasm")).status, 404);
  await mkdir(join(bundle, "directory"));
  assert.equal((await fetchAsset("/directory")).status, 404);
  assert.equal((await fetchAsset("/%FF")).status, 400);
  assert.equal((await fetchAsset("/program.wasm", "POST")).status, 405);
  const instrumented = await fetchAsset("/__olang_browser_qualification__.html");
  assert.equal(instrumented.status, 200);
  assert.ok(instrumented.body.toString().includes("dataset.olangQualificationMarker = passMarker"));
  const done = "/__olang_browser_qualification_done__?status=pass&domStatus=pass&domMarker=marker&domOutput=output";
  assert.equal((await fetchAsset(done)).status, 200);
  assert.deepEqual(await bundleServer.completion, {
    status: "pass", domStatus: "pass", domMarker: "marker", domOutput: "output",
  });
  assert.equal((await fetchAsset("/__olang_browser_qualification_done__?status=fail")).status, 409);
  await waitForClosedAssets();
} finally {
  if (bundleServer) {
    bundleServer.closeAllConnections();
    await new Promise((resolveClose, rejectClose) => {
      bundleServer.close((error) => error ? rejectClose(error) : resolveClose());
    });
  }
  await rm(servingParent, { recursive: true, force: true });
}

// A subprocess speaks the same private pipe protocol as Chrome. Delays, crashes,
// and inherited pipes exercise failure cases without depending on a local GUI.
const fixture = `
  import { createReadStream, writeSync } from "node:fs";
  import { spawn } from "node:child_process";
  const mode = process.argv[1];
  let input = "";
  let descendant;
  const reply = (message) => {
    const bytes = Buffer.from(JSON.stringify(message) + "\\0");
    // Deliberately split a response across chunks in the transport.
    writeSync(4, bytes.subarray(0, 5));
    setTimeout(() => writeSync(4, bytes.subarray(5)), 5);
  };
  createReadStream(null, { fd: 3 }).on("data", (chunk) => {
    input += chunk;
    let end;
    while ((end = input.indexOf("\\0")) !== -1) {
      const request = JSON.parse(input.slice(0, end));
      input = input.slice(end + 1);
      if (request.method === "Browser.close") {
        if (mode !== "ignore-close") process.exit(0);
        continue;
      }
      if (mode === "hang") continue;
      if (mode === "crash") process.exit(7);
      if (mode === "malformed") { writeSync(4, "bad-json\\0"); continue; }
      if (mode === "flood") { process.stderr.write("x".repeat(9 * 1024 * 1024)); continue; }
      if (mode === "descendant") {
        descendant ??= spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "inherit" });
      }
      const wait = mode === "delayed" ? 250 : request.method === "slow" ? 40 : 0;
      setTimeout(() => reply({
        id: request.id,
        result: { method: request.method, sessionId: request.sessionId, descendant: descendant?.pid },
      }), wait);
    }
  });
`;

function start(mode) {
  return launchBrowser(process.execPath, ["--input-type=module", "-e", fixture, mode]);
}

async function rejectsMode(mode, pattern, timeoutMs = 1_000) {
  const browser = start(mode);
  try {
    await assert.rejects(browser.phase("browser startup/readiness", timeoutMs,
      () => browser.send("Browser.getVersion")), pattern);
  } finally {
    await browser.close(30);
  }
}

const reordered = start("normal");
try {
  const result = await reordered.phase("protocol", 2_000, () => Promise.all([
    reordered.send("slow", {}, "session-a"),
    reordered.send("fast", {}, "session-b"),
  ]));
  assert.deepEqual(result.map(({ method, sessionId }) => [method, sessionId]), [
    ["slow", "session-a"], ["fast", "session-b"],
  ]);
} finally {
  await reordered.close(100);
}

const delayed = start("delayed");
try {
  // Combined latency exceeds either phase budget; each phase gets its own clock.
  await delayed.phase("browser startup/readiness", 450, () => delayed.send("Browser.getVersion"));
  await delayed.phase("browser navigation/UI execution", 450, () => delayed.send("Page.navigate"));
  await assert.rejects(delayed.phase("browser navigation/UI execution", 20,
    () => new Promise(() => {})), /browser navigation\/UI execution exceeded 20 ms/);
} finally {
  await delayed.close(100);
}

await rejectsMode("hang", /browser startup\/readiness exceeded 100 ms/, 100);
await rejectsMode("crash", /browser (exited|closed its DevTools pipe)/);
await rejectsMode("malformed", /invalid browser DevTools message/);
await rejectsMode("flood", /diagnostic output bytes/);

const nonexistent = launchBrowser("/does-not-exist/olang-browser", []);
try {
  await assert.rejects(nonexistent.phase("startup", 1_000,
    () => nonexistent.send("Browser.getVersion")), /ENOENT/);
} finally {
  await nonexistent.close(30);
}

if (process.platform !== "win32") {
  const inherited = start("descendant");
  const { descendant } = await inherited.phase("startup", 1_000,
    () => inherited.send("Browser.getVersion"));
  process.kill(descendant, 0);
  await inherited.close(100);
  let stillAlive = true;
  for (let attempt = 0; attempt < 100 && stillAlive; attempt++) {
    try { process.kill(descendant, 0); } catch (error) {
      if (error.code !== "ESRCH") throw error;
      stillAlive = false;
    }
    if (stillAlive) await delay(10);
  }
  assert.equal(stillAlive, false, "browser descendant survived cleanup");
}

const stubborn = start("ignore-close");
await stubborn.phase("startup", 1_000, () => stubborn.send("Browser.getVersion"));
await stubborn.close(30);
assert.throws(() => process.kill(stubborn.pid, 0), { code: "ESRCH" });

const interrupted = start("normal");
await interrupted.phase("startup", 1_000, () => interrupted.send("Browser.getVersion"));
interrupted.abort(new Error("qualification interrupted by SIGTERM"));
await assert.rejects(interrupted.phase("execution", 1_000, () => new Promise(() => {})), /interrupted by SIGTERM/);
await interrupted.close(30);
assert.throws(() => process.kill(interrupted.pid, 0), { code: "ESRCH" });

console.log("olang-browser-wasi browser harness tests: PASS");
