import {
  bytesFrom, compileAndVerifyModule, fetchBytes, loadAndVerifyBundle,
  OlangBrowserBundleError, validateManifest, verifyFile,
} from "./runner.mjs";
import {
  LINUX_WASI_PREVIEW1_IMPORTS, LINUX_WASI_PREVIEW1_SIGNATURES,
} from "./linux-wasi-host.mjs";

export const LINUX_BROWSER_SCHEMA = "ostadix.olang-linux-browser-bundle/v1";
export const LINUX_BROWSER_PROFILE = Object.freeze({
  schema: LINUX_BROWSER_SCHEMA,
  build: true,
  assets: Object.freeze([
    "browser-main.mjs", "index.html", "linux-runner.mjs", "linux-wasi-host.mjs",
    "linux-worker.mjs", "runner.mjs", "wasi-preview1-host.mjs",
  ]),
  imports: LINUX_WASI_PREVIEW1_IMPORTS,
  localCapabilities: Object.freeze([
    "args", "environment", "clock-realtime", "clock-monotonic", "stdin-eof",
    "stdout-capture", "stderr-capture", "embedded-linux-filesystem", "embedded-linux-processes",
  ]),
  deniedCapabilities: Object.freeze([
    "host-filesystem-paths", "preopened-directories", "host-process-spawn", "network-sockets",
  ]),
});

export function validateLinuxManifest(manifest) {
  // compatibility/provider deliberately retain the direct-WASI assessment.
  // This distinct schema selects embedded Linux execution, not a hidden remote
  // provider or a claim that direct WASI can spawn Python/Guix.
  return validateManifest(manifest, LINUX_BROWSER_PROFILE);
}

export async function verifyLinuxBuild(manifest, bytes) {
  await verifyFile(manifest.build, bytes, manifest.build.path);
  let build;
  try {
    build = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (error) {
    throw new OlangBrowserBundleError("integrity-failed", "invalid Linux build record", error);
  }
  if (
    build?.schema !== "ostadix.olang-wasm-container-build/v1"
    || build.profile !== "embedded-linux-amd64-wasi-experimental"
    || build.source_sha256 !== manifest.source.sha256
    || build.plan_sha256 !== manifest.plan.sha256
    || JSON.stringify(build.backend_grants) !== JSON.stringify(manifest.backend_grants)
    || !Array.isArray(build.adapters)
    || build.adapters.length !== manifest.adapters.length
    || build.adapters.some((adapter, index) => (
      adapter?.name !== manifest.adapters[index].name
      || adapter.sha256 !== manifest.adapters[index].file.sha256
    ))
    || build.runtime_closure_verified !== false
    || build.execution_verified !== false
    || build.browser_bundle_host_qualified !== false
    || ![build.runtime_image, build.builder_image].every((image) => (
      typeof image === "string" && /^[a-zA-Z0-9][a-zA-Z0-9._/:\-]*@sha256:[0-9a-f]{64}$/.test(image)
    ))
  ) {
    throw new OlangBrowserBundleError(
      "integrity-failed", "Linux build inputs do not match the source, plan, adapters and grants",
    );
  }
  return build;
}

// Construct the worker from the exact bytes already checked against the
// manifest. Do not refetch executable host files after verifying them.
export function createLinuxWorkerUrl(assetPayloads) {
  const assets = new Map(assetPayloads.map(([record, bytes]) => [record.path, bytes]));
  const urls = [];
  const make = (source) => {
    const url = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
    urls.push(url);
    return url;
  };
  const read = (path) => {
    if (!assets.has(path)) throw new OlangBrowserBundleError("integrity-failed", `missing ${path}`);
    return new TextDecoder("utf-8", { fatal: true }).decode(assets.get(path));
  };
  const bind = (source, path, url) => {
    const needle = JSON.stringify(`./${path}`);
    if (source.split(needle).length !== 2) {
      throw new OlangBrowserBundleError("integrity-failed", `noncanonical worker import ${path}`);
    }
    return source.replace(needle, JSON.stringify(url));
  };
  try {
    const base = make(read("wasi-preview1-host.mjs"));
    const host = make(bind(read("linux-wasi-host.mjs"), "wasi-preview1-host.mjs", base));
    const worker = make(bind(read("linux-worker.mjs"), "linux-wasi-host.mjs", host));
    return { url: worker, dispose: () => urls.forEach((url) => URL.revokeObjectURL(url)) };
  } catch (error) {
    urls.forEach((url) => URL.revokeObjectURL(url));
    throw error;
  }
}

export function executeLinuxWorker(module, assetPayloads, options = {}) {
  const timeoutMs = options.timeoutMs ?? 600_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600_000) {
    throw new OlangBrowserBundleError("invalid-options", "timeoutMs must be 1..600000");
  }
  if (options.args !== undefined && (!Array.isArray(options.args) || options.args.some(
    (arg) => typeof arg !== "string" || arg.includes("\0"),
  ))) {
    throw new OlangBrowserBundleError("invalid-options", "args must be NUL-free strings");
  }
  if (options.env !== undefined && (
    !options.env || typeof options.env !== "object" || Array.isArray(options.env)
    || Object.entries(options.env).some(([key, value]) => (
      !key || key.includes("=") || key.includes("\0")
      || typeof value !== "string" || value.includes("\0")
    ))
  )) {
    throw new OlangBrowserBundleError("invalid-options", "env must contain NUL-free string entries");
  }
  if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) {
    throw new OlangBrowserBundleError("invalid-options", "signal must be an AbortSignal");
  }
  if (typeof Worker !== "function" || typeof SharedArrayBuffer !== "function"
      || globalThis.crossOriginIsolated !== true) {
    throw new OlangBrowserBundleError(
      "linux-worker-unavailable",
      "Linux WASI requires a dedicated Worker in a secure, cross-origin-isolated page; serve COOP: same-origin and COEP: require-corp",
    );
  }
  if (options.signal?.aborted) {
    throw new OlangBrowserBundleError("execution-aborted", "Linux WASI execution aborted");
  }
  const assets = createLinuxWorkerUrl(assetPayloads);
  let worker;
  try {
    worker = new Worker(assets.url, { type: "module", name: "Olang Linux WASI" });
  } catch (error) {
    assets.dispose();
    throw error;
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
      worker.terminate();
      assets.dispose();
      if (error) reject(error);
      else resolve(Object.freeze(result));
    };
    const abort = () => finish(new OlangBrowserBundleError("execution-aborted", "Linux WASI execution aborted"));
    options.signal?.addEventListener("abort", abort, { once: true });
    timer = setTimeout(() => finish(new OlangBrowserBundleError(
      "execution-timeout", `Linux WASI worker exceeded ${timeoutMs} ms and was terminated`,
    )), timeoutMs);
    worker.onerror = (event) => {
      event.preventDefault();
      finish(new OlangBrowserBundleError("worker-failed", event.message || "Linux WASI worker failed"));
    };
    worker.onmessageerror = () => finish(new OlangBrowserBundleError("worker-failed", "invalid Linux worker message"));
    worker.onmessage = ({ data }) => {
      if (data?.kind === "error") {
        finish(new OlangBrowserBundleError(data.code || "worker-failed", data.message));
      } else if (data?.kind === "result") {
        const result = data.result;
        if (!result || !Number.isInteger(result.exitCode) || result.exitCode < 0
            || result.exitCode > 0xffff_ffff || result.ok !== (result.exitCode === 0)
            || typeof result.stdout !== "string" || typeof result.stderr !== "string") {
          finish(new OlangBrowserBundleError("worker-failed", "inconsistent Linux worker result"));
          return;
        }
        try {
          options.onStdout?.(result.stdout);
          options.onStderr?.(result.stderr);
          finish(null, result);
        } catch (error) { finish(error); }
      } else {
        finish(new OlangBrowserBundleError("worker-failed", "unknown Linux worker message"));
      }
    };
    try {
      worker.postMessage({ module, args: ["program.wasm", "--no-stdin", ...(options.args ?? [])], env: options.env ?? {} });
    } catch (error) { finish(error); }
  });
}

export async function runOlangBrowserBundle(options = {}) {
  if (options.provider !== undefined) {
    throw new OlangBrowserBundleError("invalid-options", "embedded Linux execution does not use a whole-program provider");
  }
  const { manifest, wasmBytes, assetPayloads, baseUrl } = await loadAndVerifyBundle(options, validateLinuxManifest);
  const buildBytes = options.buildBytes === undefined
    ? await fetchBytes(new URL(manifest.build.path, baseUrl))
    : bytesFrom(options.buildBytes, "buildBytes");
  await verifyLinuxBuild(manifest, buildBytes);
  const module = await compileAndVerifyModule(wasmBytes, manifest.abi, LINUX_WASI_PREVIEW1_SIGNATURES);
  const result = await executeLinuxWorker(module, assetPayloads, options);
  return Object.freeze({ ...result, executionMode: "browser-embedded-linux-wasi", manifest });
}
