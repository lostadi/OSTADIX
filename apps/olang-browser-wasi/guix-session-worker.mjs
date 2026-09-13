// One complete disposable Linux guest. All human I/O uses shared bounded rings.
import { InteractiveLinuxTransport, InteractiveLinuxWasiHost } from "./interactive-linux-wasi-host.mjs";
import { acquireBrowserDisk } from "./browser-disk-wasi.mjs";
import { openGuixBrowserState } from "./guix-browser-state.mjs";
import { GuixNetworkEndpoint } from "./guix-network-transport.mjs";
import { installGuixGuestNetwork } from "./guix-network-guest-host.mjs";

async function chunkBytes(record, baseUrl) {
  if (!/^disk-chunks\/[0-9]{4}\.bin$/.test(record.path) || record.bytes > 1048576) throw new Error("invalid sparse chunk");
  const response = await fetch(new URL(record.path, baseUrl), {
    credentials: "omit", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(60000),
  });
  if (!response.ok || !response.body) throw new Error("initial disk chunk unavailable");
  const result = new Uint8Array(record.bytes);
  const reader = response.body.getReader();
  let offset = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      if (offset + part.value.length > result.length) throw new Error("initial disk chunk exceeds declared size");
      result.set(part.value, offset); offset += part.value.length;
    }
  } finally {
    try { await reader.cancel(); } catch { /* Preserve the fetch/integrity error. */ }
    reader.releaseLock();
  }
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", result)), byte => byte.toString(16).padStart(2, "0")).join("");
  if (offset !== result.length || digest !== record.sha256) throw new Error("initial disk chunk integrity mismatch");
  return result;
}

self.onmessage = async ({ data }) => {
  self.onmessage = null;
  let transport, network, state, disk, terminal;
  try {
    if (data?.kind !== "start" || !(data.module instanceof WebAssembly.Module)
        || typeof data.baseUrl !== "string") throw new Error("invalid Guix guest startup");
    const base = new URL(data.baseUrl);
    if (!["https:", "http:"].includes(base.protocol) || base.username || base.password
        || base.search || base.hash || !base.pathname.endsWith("/")) throw new Error("invalid Guix bundle URL");
    if (!(data.certificate instanceof Uint8Array) || !data.certificate.length || data.certificate.length > 16384
        || !new TextDecoder("utf-8", {fatal: true}).decode(data.certificate).startsWith("-----BEGIN CERTIFICATE-----")) {
      throw new Error("invalid Guix proxy certificate");
    }
    transport = new InteractiveLinuxTransport(data.transport);
    network = new GuixNetworkEndpoint(data.network, "guest", { wake: () => transport.wake() });
    transport.checkCancelled();
    state = await openGuixBrowserState({profile: data.profile, initialDisk: data.initialDisk,
      fetchChunk: record => chunkBytes(record, base)});
    disk = await acquireBrowserDisk({fileHandle: state.fileHandle,
      expectedBytes: data.profile.bytes, maxBytes: data.profile.bytes});
    transport.checkCancelled();
    const host = new InteractiveLinuxWasiHost({transport,
      args: ["program.wasm", "--net=socket=listenfd=5"],
      env: {O_BACKEND_OPERATION_TIMEOUT_MS: "3600000"}});
    host.imports = disk.wrap(host);
    installGuixGuestNetwork(host, {network, certificate: data.certificate, transport});
    const instance = await WebAssembly.instantiate(data.module, host.imports);
    self.postMessage({kind: "ready"});
    const result = host.run(instance);
    // Only the paired privileged init/emulator channel adds this tag, after
    // workload teardown, checked syncfs and non-lazy filesystem unmounts.
    const finalized = (result.exitCode >>> 8) === 0x4f5300;
    disk.dispose(); disk = undefined;
    if (!finalized) throw new Error(`Guest did not acknowledge a clean state shutdown (WASI ${result.exitCode}); saved state requires recovery`);
    transport.checkCancelled();
    await state.markClean();
    terminal = {kind: "result", result: {exitCode: result.exitCode & 255,
      ok: (result.exitCode & 255) === 0, stateSaved: true}};
  } catch (error) {
    terminal = {kind: "error", code: String(error?.code ?? "guix-guest-failed").slice(0, 128),
      message: String(error?.message ?? error).slice(0, 4096)};
  } finally {
    try { disk?.dispose(); } catch (error) {
      terminal = {kind: "error", code: "disk-close-failed", message: String(error).slice(0, 4096)};
    }
    try { await state?.close(); } catch (error) {
      terminal = {kind: "error", code: "state-close-failed", message: String(error).slice(0, 4096)};
    }
    transport?.closeInput(); transport?.closeOutput();
    // The parent closes networking after receiving the terminal result. It
    // must not interpret proxy shutdown as a guest failure before this message.
  }
  self.postMessage(terminal);
};
