import { loadAndVerifyBundle, validateManifest, verifyFile, compileAndVerifyModule, OlangBrowserBundleError } from "./runner.mjs";
import { LINUX_WASI_PREVIEW1_IMPORTS, LINUX_WASI_PREVIEW1_SIGNATURES } from "./linux-wasi-host.mjs";
import { createInteractiveLinuxTransport } from "./interactive-linux-wasi-host.mjs";
import { createGuixNetworkTransport, GuixNetworkEndpoint } from "./guix-network-transport.mjs";
import { GuixMirrorFetchBroker } from "./guix-mirror-fetch-broker.mjs";
import { GUIX_PROXY_ARTIFACT, GUIX_NETWORK_PROXY_IMPORT_PROFILE, GUIX_PROXY_IMPORT_MULTIPLICITIES } from "./guix-network-proxy-host.mjs";

export const GUIX_BROWSER_SCHEMA = "ostadix.olang-guix-browser-bundle/v1";
const ASSETS = Object.freeze([
  "browser-main.mjs", "browser-disk-wasi.mjs", "c2w-net-proxy.wasm", "guix-browser-state.mjs",
  "guix-mirror-fetch-broker.mjs", "guix-network-transport.mjs", "guix-network-guest-host.mjs",
  "guix-network-proxy-host.mjs", "guix-network-proxy-worker.mjs", "guix-session-runner.mjs",
  "guix-session-worker.mjs", "index.html", "initial-disk.json", "interactive-linux-wasi-host.mjs",
  "linux-wasi-host.mjs", "runner.mjs", "state-profile.json", "wasi-preview1-host.mjs",
].sort());
const PROFILE = Object.freeze({schema: GUIX_BROWSER_SCHEMA, build: true, assets: ASSETS,
  imports: LINUX_WASI_PREVIEW1_IMPORTS,
  localCapabilities: ["args", "environment", "clock-realtime", "clock-monotonic", "queued-stdin",
    "streamed-stdout", "streamed-stderr", "embedded-linux-filesystem", "embedded-linux-processes",
    "origin-private-guix-disk", "guix-mirror-fetch"],
  deniedCapabilities: ["host-filesystem-paths", "host-process-spawn", "arbitrary-network", "local-helper"]});
const decode = new TextDecoder("utf-8", {fatal: true});
function error(message) { return new OlangBrowserBundleError("guix-session-failed", message); }

async function fetchBounded(url, {bytes, maximum, signal}) {
  if (!Number.isSafeInteger(maximum) || maximum < 0
      || (bytes !== undefined && (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > maximum))) {
    throw error("Bundle file exceeds its declared loading budget");
  }
  const response = await fetch(url, {credentials: "omit", redirect: "error", cache: "no-store", signal});
  if (response.status !== 200 || !response.body) throw error(`Bundle file unavailable: ${url}`);
  const output = new Uint8Array(bytes ?? maximum);
  const reader = response.body.getReader();
  let offset = 0;
  try {
    for (;;) {
      const item = await reader.read();
      if (item.done) break;
      if (!(item.value instanceof Uint8Array) || offset + item.value.length > output.length) {
        throw error(`Bundle file exceeds its declared byte count: ${url}`);
      }
      output.set(item.value, offset); offset += item.value.length;
    }
    if (bytes !== undefined && offset !== bytes) throw error(`Bundle file has a truncated body: ${url}`);
    return bytes === undefined ? output.slice(0, offset) : output;
  } finally {
    try { await reader.cancel(); } catch { /* Preserve the actual fetch/integrity error. */ }
    reader.releaseLock();
  }
}

// Pinned bytes are necessary but do not replace the two-namespace ABI check.
// The common command checker admits only one namespace, so inspect this small
// proxy's type/import/export sections separately without instantiating it.
function verifyProxyModule(bytes, module) {
  function reader(bytes) {
    let at = 0;
    const take = (size) => {
      if (!Number.isSafeInteger(size) || size < 0 || at + size > bytes.length) throw error("Invalid proxy WASM section");
      const result = bytes.subarray(at, at + size); at += size; return result;
    };
    const byte = () => take(1)[0];
    const u32 = () => {
      let result = 0;
      for (let index = 0; index < 5; index++) {
        const value = byte();
        if (index === 4 && (value & 0xf0)) throw error("Invalid proxy WASM integer");
        result += (value & 127) * 2 ** (index * 7);
        if (!(value & 128)) return result;
      }
      throw error("Invalid proxy WASM integer");
    };
    return {take, byte, u32, name: () => decode.decode(take(u32())), remaining: () => bytes.length - at};
  }
  const expected = new Map(GUIX_NETWORK_PROXY_IMPORT_PROFILE.map((entry) => [`${entry.module}:${entry.name}`, entry]));
  const expectedCount = Object.values(GUIX_PROXY_IMPORT_MULTIPLICITIES).reduce((sum, count) => sum + count, 0);
  const actual = WebAssembly.Module.imports(module);
  if (actual.length !== expectedCount || actual.some((entry) => entry.kind !== "function" || !expected.has(`${entry.module}:${entry.name}`))) {
    throw error("Network proxy imports differ from the pinned two-namespace host contract");
  }
  const input = reader(bytes);
  if (input.take(8).some((value, index) => value !== [0, 97, 115, 109, 1, 0, 0, 0][index])) throw error("Invalid proxy WASM header");
  const names = new Map([[0x7f, "i32"], [0x7e, "i64"], [0x7d, "f32"], [0x7c, "f64"],
    [0x7b, "v128"], [0x70, "funcref"], [0x6f, "externref"]]);
  const types = [], functions = [], seen = new Map();
  let start;
  while (input.remaining()) {
    const id = input.byte(), part = reader(input.take(input.u32()));
    if (id === 1) {
      const vector = () => {
        const count = part.u32(), result = [];
        for (let i = 0; i < count; i++) {
          const name = names.get(part.byte());
          if (!name) throw error("Unsupported proxy WASM value type");
          result.push(name);
        }
        return result;
      };
      for (let count = part.u32(); count > 0; count--) {
        if (part.byte() !== 0x60) throw error("Unsupported proxy WASM function type");
        types.push({parameters: vector(), results: vector()});
      }
    } else if (id === 2) {
      for (let count = part.u32(); count > 0; count--) {
        const key = `${part.name()}:${part.name()}`;
        if (part.byte() !== 0) throw error("Non-function proxy import");
        const type = part.u32(), expectedType = expected.get(key), actualType = types[type];
        const occurrence = (seen.get(key) ?? 0) + 1;
        if (!expectedType || occurrence > GUIX_PROXY_IMPORT_MULTIPLICITIES[key] || !actualType
            || JSON.stringify(actualType.parameters) !== JSON.stringify(expectedType.parameters)
            || JSON.stringify(actualType.results) !== JSON.stringify(expectedType.results)) {
          throw error(`Network proxy import signature mismatch: ${key}`);
        }
        seen.set(key, occurrence); functions.push(type);
      }
    } else if (id === 3) {
      for (let count = part.u32(); count > 0; count--) functions.push(part.u32());
    } else if (id === 7) {
      for (let count = part.u32(); count > 0; count--) {
        const name = part.name(), kind = part.byte(), index = part.u32();
        if (name === "_start" && kind === 0) start = index;
      }
    } else if (id === 8) throw error("Proxy core Start sections are not admitted");
    else continue;
    if (part.remaining()) throw error("Trailing proxy WASM section bytes");
  }
  const exports = new Map(WebAssembly.Module.exports(module).map((entry) => [entry.name, entry.kind]));
  const startType = types[functions[start]];
  if (seen.size !== expected.size || [...expected.keys()].some((key) => seen.get(key) !== GUIX_PROXY_IMPORT_MULTIPLICITIES[key])
      || exports.get("memory") !== "memory" || exports.get("_start") !== "function"
      || !startType || startType.parameters.length || startType.results.length) {
    throw error("Network proxy requires memory and the command entrypoint () -> ()");
  }
  return module;
}

async function prepareSession(baseUrl, signal, onStatus) {
  const controller = new AbortController();
  const cancel = () => controller.abort(error("Bundle loading cancelled"));
  signal?.addEventListener("abort", cancel, {once: true});
  if (signal?.aborted) cancel();
  const timer = setTimeout(() => controller.abort(error("Bundle loading/compilation exceeded 15 minutes")), 900000);
  // WebAssembly.compile and Web Crypto themselves have no cancellation API.
  // Stop waiting on abort; no Worker or storage is opened on that path. Fetch
  // requests do receive the signal and their readers are cancelled immediately.
  const wait = (operation) => new Promise((resolve, reject) => {
    const abort = () => reject(controller.signal.reason);
    controller.signal.addEventListener("abort", abort, {once: true});
    if (controller.signal.aborted) abort();
    Promise.resolve(operation).then(resolve, reject).finally(() => controller.signal.removeEventListener("abort", abort));
  });
  try {
    onStatus("Loading and verifying the Guix bundle…");
    const manifestBytes = await fetchBounded(new URL("manifest.json", baseUrl), {maximum: 4 * 1048576, signal: controller.signal});
    const selected = validateManifest(JSON.parse(decode.decode(manifestBytes)), PROFILE);
    const records = [selected.source, selected.artifact, selected.plan, selected.build,
      ...selected.assets, ...selected.adapters.map((adapter) => adapter.file)];
    const files = new Map(records.map((record) => [new URL(record.path, baseUrl).href, record]));
    if (selected.artifact.bytes > 1073741824 || records.filter((record) => record !== selected.artifact)
      .reduce((total, record) => total + record.bytes, 0) > 128 * 1048576) throw error("Guix bundle exceeds its browser loading budget");
    const fetchFile = (url) => {
      const record = files.get(new URL(url, baseUrl).href);
      if (!record) throw error("Unadmitted bundle fetch");
      const maximum = record === selected.artifact ? 1073741824
        : record.path === "c2w-net-proxy.wasm" ? GUIX_PROXY_ARTIFACT.bytes : 16 * 1048576;
      return fetchBounded(url, {bytes: record.bytes, maximum, signal: controller.signal});
    };
    const loaded = await wait(loadAndVerifyBundle({baseUrl, manifest: selected, fetchFile},
      (manifest) => validateManifest(manifest, PROFILE)));
    const buildBytes = await fetchFile(new URL(loaded.manifest.build.path, baseUrl));
    await wait(verifyFile(loaded.manifest.build, buildBytes, loaded.manifest.build.path));
    return {loaded, buildBytes, wait, dispose() { clearTimeout(timer); signal?.removeEventListener("abort", cancel); }};
  } catch (caught) {
    clearTimeout(timer); signal?.removeEventListener("abort", cancel);
    controller.abort(caught);
    throw caught;
  }
}

// Link only manifest-verified module bytes. No executable is refetched after
// verification; relative imports must name another admitted asset exactly.
function workerGraph(payloads) {
  const sources = new Map(payloads.filter(([record]) => record.path.endsWith(".mjs"))
    .map(([record, bytes]) => [record.path, decode.decode(bytes)]));
  const urls = new Map(), visiting = new Set();
  function link(name) {
    if (urls.has(name)) return urls.get(name);
    if (!sources.has(name) || visiting.has(name)) throw error(`unadmitted/cyclic Worker dependency ${name}`);
    visiting.add(name);
    const original = sources.get(name);
    // This bundle uses static relative imports only, not arbitrary JavaScript
    // module syntax. Reject a dynamic import rather than refetch executable
    // bytes after verification. Rewrite external/bare specifiers only to reject
    // them explicitly, never leave an accidental network import in a blob.
    if (/\bimport\s*\(/.test(original)) throw error(`Dynamic Worker import is not admitted: ${name}`);
    const source = original.replace(/(\bfrom\s*|\bimport\s*)(["'])([^"']+)\2/g,
      (_match, prefix, _quote, path) => {
        if (!/^\.\/[a-z0-9-]+\.mjs$/.test(path)) throw error(`Unadmitted Worker import ${path}`);
        return `${prefix}${JSON.stringify(link(path.slice(2)))}`;
      });
    const url = URL.createObjectURL(new Blob([source], {type: "text/javascript"}));
    visiting.delete(name); urls.set(name, url); return url;
  }
  return {link, dispose() { for (const url of urls.values()) URL.revokeObjectURL(url); }};
}

export async function startGuixBrowserSession({baseUrl = new URL("./", import.meta.url),
  onOutput = () => {}, onStatus = () => {}, signal} = {}) {
  if (!globalThis.isSecureContext || !globalThis.crossOriginIsolated
      || typeof SharedArrayBuffer !== "function" || typeof Worker !== "function"
      || !navigator.storage?.getDirectory) throw error("A secure, cross-origin-isolated browser with OPFS is required");
  if (typeof onOutput !== "function" || typeof onStatus !== "function"
      || (signal !== undefined && !(signal instanceof AbortSignal))) throw error("Invalid browser session callbacks or signal");
  baseUrl = new URL(baseUrl, globalThis.location.href);
  if (!["https:", "http:"].includes(baseUrl.protocol) || baseUrl.username || baseUrl.password
      || baseUrl.search || baseUrl.hash || !baseUrl.pathname.endsWith("/")) throw error("Invalid browser bundle base URL");
  if (signal?.aborted) throw error("Session cancelled");
  let prepared, assetPayloads, profile, initialDisk, module, proxyModule;
  try {
    prepared = await prepareSession(baseUrl, signal, onStatus);
    const {manifest, wasmBytes} = prepared.loaded;
    assetPayloads = prepared.loaded.assetPayloads;
    const payload = new Map(assetPayloads.map(([record, bytes]) => [record.path, bytes]));
    profile = JSON.parse(decode.decode(payload.get("state-profile.json")));
    initialDisk = JSON.parse(decode.decode(payload.get("initial-disk.json")));
    const build = JSON.parse(decode.decode(prepared.buildBytes));
    if (build.schema !== "ostadix.olang-wasm-container-build/v1"
        || build.profile !== "embedded-linux-amd64-wasi-experimental"
        || build.source_sha256 !== manifest.source.sha256 || build.plan_sha256 !== manifest.plan.sha256
        || build.runtime_image !== profile.runtime_image || build.converter?.browser_guix !== true
        || ![build.runtime_image, build.builder_image].every((image) => typeof image === "string"
          && /^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}$/.test(image))
        || JSON.stringify(build.backend_grants) !== JSON.stringify(manifest.backend_grants)
        || build.runtime_closure_verified !== false || build.execution_verified !== false
        || build.browser_bundle_host_qualified !== false
        || !Array.isArray(build.adapters) || build.adapters.length !== manifest.adapters.length
        || build.adapters.some((item, index) => item.name !== manifest.adapters[index].name
          || item.sha256 !== manifest.adapters[index].file.sha256)
        || JSON.stringify(Object.entries(build.browser_guix_state ?? {}).sort()) !== JSON.stringify(Object.entries(profile).sort())) {
      throw error("Guix build is not bound to the source, plan, adapters and state profile");
    }
    const proxyRecord = manifest.assets.find(item => item.path === "c2w-net-proxy.wasm");
    if (proxyRecord.bytes !== GUIX_PROXY_ARTIFACT.bytes || proxyRecord.sha256 !== GUIX_PROXY_ARTIFACT.sha256) {
      throw error("Only the pinned in-browser network module is admitted");
    }
    onStatus("Compiling the Linux guest and browser network stack…");
    module = await prepared.wait(compileAndVerifyModule(wasmBytes, manifest.abi, LINUX_WASI_PREVIEW1_SIGNATURES));
    const proxyBytes = payload.get("c2w-net-proxy.wasm");
    proxyModule = verifyProxyModule(proxyBytes, await prepared.wait(WebAssembly.compile(proxyBytes)));
  } finally {
    prepared?.dispose();
    prepared = undefined;
  }
  if (signal?.aborted) throw error("Session cancelled");
  const transport = createInteractiveLinuxTransport();
  const networkBuffer = createGuixNetworkTransport();
  const network = new GuixNetworkEndpoint(networkBuffer, "guest", {wake: () => transport.wake()});
  const http = new SharedArrayBuffer(4108);
  const httpControl = new Int32Array(http, 0, 3);
  const httpData = new Uint8Array(http, 12);
  const graph = workerGraph(assetPayloads);
  // The pinned Go proxy ignores io.Copy's error. A broker/body failure must
  // terminate the session rather than become an apparently successful EOF.
  const broker = new GuixMirrorFetchBroker({onError: (message) => finish(error(`Mirror transport failed: ${message}`))});
  let guest, proxy, timer, poll, settled = false, certificateSeen = false, readySeen = false, httpPending = false;
  let resolveDone, rejectDone;
  const done = new Promise((resolve, reject) => { resolveDone = resolve; rejectDone = reject; });
  // Attach immediately: callers may still be rendering their session controls.
  done.catch(() => {});
  function drain() {
    let budget = 262144;
    for (let item; budget > 0 && (item = transport.readOutput());) {
      budget -= item.bytes.length; onOutput(item);
    }
  }
  function finish(failure, result) {
    if (settled) return;
    settled = true;
    clearTimeout(timer); clearInterval(poll); signal?.removeEventListener("abort", abort);
    try { drain(); } catch (caught) { failure ??= caught; }
    for (const cleanup of [() => transport.cancel(), () => network.cancel(), () => broker.dispose(),
      () => guest?.terminate(), () => proxy?.terminate(), () => graph.dispose()]) {
      try { cleanup(); } catch (caught) { failure ??= caught; }
    }
    if (failure) rejectDone(failure); else resolveDone(Object.freeze(result));
  }
  const abort = () => finish(error("Session stopped; unfinished disk state requires recovery"));
  signal?.addEventListener("abort", abort, {once: true});
  try {
    if (signal?.aborted) throw error("Session cancelled before Worker startup");
    // The O backend has a one-hour budget. The enclosing owner adds five
    // minutes for boot/shutdown; it never extends the evaluator from inside O.
    timer = setTimeout(() => finish(error("Guix session exceeded 65 minutes")), 3900000);
    poll = setInterval(() => { try { drain(); } catch (caught) { finish(caught); } }, 16);
    guest = new Worker(graph.link("guix-session-worker.mjs"), {type: "module", name: "O Guix guest"});
    proxy = new Worker(graph.link("guix-network-proxy-worker.mjs"), {type: "module", name: "O browser network"});
    for (const worker of [guest, proxy]) {
      worker.onerror = event => { event.preventDefault(); finish(error(event.message || "Worker failure")); };
      worker.onmessageerror = () => finish(error("Invalid Worker message"));
    }
    guest.onmessage = ({data}) => {
      if (settled) return;
      try {
        if (data?.kind === "ready" && certificateSeen && !readySeen) {
          readySeen = true;
          onStatus("Linux guest started. Wait for the guix> prompt before typing commands.");
        }
        else if (data?.kind === "error") finish(error(String(data.message).slice(0, 4096)));
        else if (data?.kind === "result" && readySeen && data.result?.stateSaved === true
            && Number.isInteger(data.result.exitCode) && data.result.exitCode >= 0 && data.result.exitCode <= 255
            && data.result.ok === (data.result.exitCode === 0)) finish(null, data.result);
        else finish(error("Unexpected guest lifecycle message"));
      } catch (caught) { finish(caught); }
    };
    proxy.onmessage = async ({data}) => {
      if (settled) return;
      try {
        if (data?.kind === "certificate") {
          if (certificateSeen || !(data.certificate instanceof Uint8Array) || !data.certificate.length
              || data.certificate.length > 16384 || !decode.decode(data.certificate).startsWith("-----BEGIN CERTIFICATE-----")) {
            throw error("Invalid browser proxy certificate");
          }
          certificateSeen = true;
          onStatus("Opening the browser-owned disk and booting Guix…");
          guest.postMessage({kind: "start", module, network: networkBuffer, transport: transport.buffer,
            certificate: data.certificate, profile, initialDisk, baseUrl: baseUrl.href});
        } else if (data?.kind === "error") finish(error(String(data.message).slice(0, 4096)));
        else if (typeof data?.type === "string" && data.type.startsWith("http_")) {
          if (httpPending) throw error("Concurrent proxy HTTP import");
          httpPending = true;
          try {
            const response = await broker.handle(data);
            if (settled) return;
            if (!(response.data instanceof Uint8Array) || response.data.length > httpData.length
                || !Number.isInteger(response.status)) throw error("Invalid bounded HTTP reply");
            httpData.set(response.data);
            Atomics.store(httpControl, 1, response.status); Atomics.store(httpControl, 2, response.data.length);
            Atomics.store(httpControl, 0, 1); Atomics.notify(httpControl, 0);
          } finally { httpPending = false; }
        } else throw error("Unexpected network Worker message");
      } catch (caught) { finish(caught); }
    };
    proxy.postMessage({kind: "start", module: proxyModule, network: networkBuffer, http, transport: transport.buffer});
    onStatus("Starting the in-browser network stack…");
  } catch (caught) { finish(caught); }
  return Object.freeze({done, sendInput(bytes) {
    if (settled) throw error("Session is closed");
    return transport.writeInput(bytes);
  }, closeInput() { transport.closeInput(); }, stop: abort});
}
