import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { Script } from "node:vm";
import {
  createLinuxWorkerUrl, executeLinuxWorker, LINUX_BROWSER_PROFILE,
  runOlangBrowserBundle, validateLinuxManifest, verifyLinuxBuild,
} from "./linux-runner.mjs";
import { compileAndVerifyModule, loadAndVerifyBundle, validateManifest } from "./runner.mjs";
import { LINUX_WASI_PREVIEW1_SIGNATURES, LinuxWasiPreview1Host } from "./linux-wasi-host.mjs";

// Contract tests use a no-op typed module and mock Worker lifecycle. They do
// not qualify Linux boot; test-linux-host and test-browser run the real guest.
const encode = (text) => new TextEncoder().encode(text);
const record = (path, bytes) => ({
  path, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
});
const u32 = (input) => {
  const result = [];
  let value = input;
  do { const part = value & 127; value >>>= 7; result.push(part | (value ? 128 : 0)); } while (value);
  return result;
};
const name = (text) => [...u32(encode(text).length), ...encode(text)];
const vector = (entries) => [...u32(entries.length), ...entries.flat()];
const section = (id, payload) => [id, ...u32(payload.length), ...payload];
function moduleBytes({ badSignature = false, coreStart = false } = {}) {
  const imports = LINUX_BROWSER_PROFILE.imports;
  const signatures = imports.map((key, index) => index === 0 && badSignature
    ? { parameters: [], results: ["i32"] } : LINUX_WASI_PREVIEW1_SIGNATURES[key]);
  signatures.push({ parameters: [], results: [] });
  const types = signatures.map(({ parameters, results }) => [
    0x60, ...vector(parameters.map((type) => [type === "i64" ? 0x7e : 0x7f])),
    ...vector(results.map(() => [0x7f])),
  ]);
  return Uint8Array.from([
    0, 97, 115, 109, 1, 0, 0, 0,
    ...section(1, vector(types)),
    ...section(2, vector(imports.map((key, index) => [...name("wasi_snapshot_preview1"), ...name(key), 0, ...u32(index)]))),
    ...section(3, vector([u32(imports.length)])),
    ...section(5, vector([[0, 1]])),
    ...section(7, vector([[...name("memory"), 2, 0], [...name("_start"), 0, ...u32(imports.length)]])),
    ...(coreStart ? section(8, u32(imports.length)) : []),
    ...section(10, vector([[2, 0, 11]])),
  ]);
}
const wasmBytes = moduleBytes();
const sourceBytes = encode("python^(__oval_result__ = 42)_python\n");
const planBytes = encode("node 0 exec python [env ephemeral] backend=python spec=fixture pure=false renderer=Default execution=shim required=[]\n");
const adapterBytes = { "adapters/0000.shim": encode("# contract fixture adapter\n") };
const assetBytes = Object.fromEntries(await Promise.all(LINUX_BROWSER_PROFILE.assets.map(async (path) => [
  path, await readFile(new URL(path === "browser-main.mjs" ? "linux-browser-main.mjs" : path, import.meta.url)),
])));
const manifest = {
  schema: LINUX_BROWSER_PROFILE.schema,
  source: record("program.O", sourceBytes), artifact: record("program.wasm", wasmBytes),
  assets: Object.entries(assetBytes).map(([path, bytes]) => record(path, bytes)),
  adapters: [{ name: "python_shim.py", file: record("adapters/0000.shim", adapterBytes["adapters/0000.shim"]) }],
  plan: { ...record("program.plan.txt", planBytes), nodes: 1 },
  compatibility: {
    local_execution: false, class: "requires-whole-program-provider",
    blockers: [{ plan_node: 0, code: "shim-backend", operation: "exec", backend: "python", required_authorities: [], diagnostic: "P0 shim-backend backend=python operation=exec" }],
  },
  provider: { schema: "ostadix.olang-browser-provider/v1", mode: "whole-program", required: true },
  backend_grants: [],
  abi: {
    module: "wasi_snapshot_preview1", imports: [...LINUX_BROWSER_PROFILE.imports], required_exports: ["memory", "_start"],
    local_capabilities: [...LINUX_BROWSER_PROFILE.localCapabilities], denied_capabilities: [...LINUX_BROWSER_PROFILE.deniedCapabilities],
  },
};
const build = {
  schema: "ostadix.olang-wasm-container-build/v1", profile: "embedded-linux-amd64-wasi-experimental",
  source_sha256: manifest.source.sha256, plan_sha256: manifest.plan.sha256,
  runtime_image: `fixture/runtime@sha256:${"a".repeat(64)}`, builder_image: `fixture/builder@sha256:${"b".repeat(64)}`,
  backend_grants: [], adapters: [{ name: "python_shim.py", sha256: manifest.adapters[0].file.sha256 }],
  runtime_closure_verified: false, execution_verified: false, browser_bundle_host_qualified: false,
};
const buildBytes = encode(JSON.stringify(build));
manifest.build = record("wasm-build.json", buildBytes);
const options = { manifest, wasmBytes, sourceBytes, planBytes, adapterBytes, assetBytes, buildBytes };
assert.equal(validateLinuxManifest(manifest), manifest);
assert.throws(() => validateManifest(manifest), { code: "manifest-invalid" });
for (const mutate of [
  (value) => { value.schema = "unknown"; },
  (value) => { value.assets.pop(); },
  (value) => { value.build.path = "../escape"; },
  (value) => { value.abi.imports.push("random_get"); },
  (value) => { value.abi.denied_capabilities.pop(); },
  (value) => { value.compatibility.local_execution = true; },
]) {
  const changed = structuredClone(manifest); mutate(changed);
  assert.throws(() => validateLinuxManifest(changed), { code: "manifest-invalid" });
}
await verifyLinuxBuild(manifest, buildBytes);
for (const mutate of [
  (value) => { value.source_sha256 = "c".repeat(64); },
  (value) => { value.plan_sha256 = "c".repeat(64); },
  (value) => { value.backend_grants = ["network"]; },
  (value) => { value.adapters[0].sha256 = "c".repeat(64); },
  (value) => { value.runtime_image = "fixture/runtime:latest"; },
  (value) => { value.execution_verified = true; },
]) {
  const changed = structuredClone(build); mutate(changed);
  const bytes = encode(JSON.stringify(changed));
  await assert.rejects(verifyLinuxBuild({ ...manifest, build: record("wasm-build.json", bytes) }, bytes), { code: "integrity-failed" });
}
const loaded = await loadAndVerifyBundle(options, validateLinuxManifest);
assert.equal(loaded.manifest.compatibility.blockers.length, 1);
for (const field of ["sourceBytes", "planBytes", "wasmBytes", "buildBytes"]) {
  await assert.rejects(runOlangBrowserBundle({ ...options, [field]: encode("tampered") }), { code: "integrity-failed" });
}
await assert.rejects(runOlangBrowserBundle({ ...options, provider: {} }), { code: "invalid-options" });
const module = await compileAndVerifyModule(wasmBytes, manifest.abi, LINUX_WASI_PREVIEW1_SIGNATURES);
for (const config of [{ badSignature: true }, { coreStart: true }]) {
  await assert.rejects(compileAndVerifyModule(moduleBytes(config), manifest.abi, LINUX_WASI_PREVIEW1_SIGNATURES), { code: "abi-mismatch" });
}
const blob = createLinuxWorkerUrl(loaded.assetPayloads);
assert.match(await (await fetch(blob.url)).text(), /from "blob:/);
blob.dispose();
await assert.rejects(fetch(blob.url));
assert.throws(() => executeLinuxWorker(module, loaded.assetPayloads), { code: "linux-worker-unavailable" });

const originalWorker = Object.getOwnPropertyDescriptor(globalThis, "Worker");
const originalIsolation = Object.getOwnPropertyDescriptor(globalThis, "crossOriginIsolated");
let mode = "result";
let terminated = 0;
let sent;
class MockWorker {
  terminate() { terminated += 1; }
  postMessage(message) {
    sent = message;
    if (mode === "hang") return;
    queueMicrotask(() => this.onmessage({ data: mode === "invalid" ? { kind: "unknown" } : {
      kind: "result", result: { ok: true, exitCode: 0, stdout: "contract mock", stderr: "" },
    } }));
  }
}
try {
  Object.defineProperty(globalThis, "Worker", { configurable: true, value: MockWorker });
  Object.defineProperty(globalThis, "crossOriginIsolated", { configurable: true, value: true });
  const result = await runOlangBrowserBundle(options);
  assert.equal(result.executionMode, "browser-embedded-linux-wasi");
  assert.deepEqual(sent.args, ["program.wasm", "--no-stdin"]);
  assert.deepEqual(sent.env, {});
  assert.equal(terminated, 1);
  mode = "invalid";
  await assert.rejects(executeLinuxWorker(module, loaded.assetPayloads), { code: "worker-failed" });
  mode = "hang";
  await assert.rejects(executeLinuxWorker(module, loaded.assetPayloads, { timeoutMs: 5 }), { code: "execution-timeout" });
  const controller = new AbortController();
  const pending = executeLinuxWorker(module, loaded.assetPayloads, { signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, { code: "execution-aborted" });
  assert.equal(terminated, 4);
  for (const invalid of [{ timeoutMs: 0 }, { timeoutMs: 600001 }, { args: [42] }, { env: { X: 1 } }, { signal: {} }]) {
    assert.throws(() => executeLinuxWorker(module, loaded.assetPayloads, invalid), { code: "invalid-options" });
  }
} finally {
  if (originalWorker) Object.defineProperty(globalThis, "Worker", originalWorker);
  else delete globalThis.Worker;
  if (originalIsolation) Object.defineProperty(globalThis, "crossOriginIsolated", originalIsolation);
  else delete globalThis.crossOriginIsolated;
}

// Exercise the actual worker wrapper and host with a synthetic entrypoint.
// No browser, Linux boot, or compiled workload is involved in these checks.
const workerSource = await readFile(new URL("linux-worker.mjs", import.meta.url), "utf8");
const workerImport = 'import { LinuxWasiPreview1Host } from "./linux-wasi-host.mjs";';
assert.equal(workerSource.split(workerImport).length, 2);
async function workerOutputFixture(start, pages = 1) {
  const memory = new WebAssembly.Memory({ initial: pages });
  const messages = [];
  let host;
  class ObservedHost extends LinuxWasiPreview1Host {
    constructor(options) { super(options); host = this; }
  }
  const self = { postMessage: (message) => messages.push(message) };
  new Script(workerSource.replace(workerImport, ""), { filename: "linux-worker.mjs" }).runInNewContext({
    self,
    LinuxWasiPreview1Host: ObservedHost,
    DataView,
    WebAssembly: {
      instantiate: async (_module, imports) => ({
        exports: { memory, _start: () => start(imports.wasi_snapshot_preview1, memory) },
      }),
    },
  });
  await self.onmessage({ data: { module: null, args: [], env: {} } });
  assert.equal(messages.length, 1);
  return { message: messages[0], host };
}

const writeResults = [];
const malformed = await workerOutputFixture((wasi, memory) => {
  const view = new DataView(memory.buffer);
  new Uint8Array(memory.buffer).set(encode("ABC"), 32);
  view.setUint32(0, 32, true);
  view.setUint32(4, 3, true);
  // Previously each failed write appended ABC without charging the cap.
  writeResults.push(wasi.fd_write(1, 0, 1, 65535));
  writeResults.push(wasi.fd_write(2, 0, 1, -1));
  writeResults.push(wasi.fd_write(1, 65535, 1, 64));
  writeResults.push(wasi.fd_write(1, 0, 0, 65535));
  view.setUint32(0, 65535, true);
  writeResults.push(wasi.fd_write(1, 0, 1, 64));
  view.setUint32(0, 32, true);
  writeResults.push(wasi.fd_write(1, 0, 1, 64));
  assert.equal(view.getUint32(64, true), 3);
});
assert.deepEqual(writeResults, [21, 21, 21, 21, 21, 0]);
assert.equal(malformed.message.kind, "result");
assert.equal(malformed.message.result.stdout, "ABC");
assert.equal(malformed.message.result.stderr, "");

const limited = await workerOutputFixture((wasi, memory) => {
  const view = new DataView(memory.buffer);
  new Uint8Array(memory.buffer, 4096, 65536).fill(65);
  view.setUint32(0, 4096, true);
  view.setUint32(4, 65536, true);
  for (let index = 0; index < 129; index += 1) wasi.fd_write(1 + index % 2, 0, 1, 64);
}, 2);
assert.equal(limited.message.kind, "error");
assert.match(limited.message.message, /output exceeded 8 MiB/);
assert.equal(limited.host.stdout.length + limited.host.stderr.length, 8 * 1024 * 1024);
console.log("olang Linux browser runner contract tests: PASS (mock lifecycle; no Linux boot claim)");
