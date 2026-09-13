// Explicit, one-shot interactive stdio Worker. It does not verify module bytes
// or admit a module on the parent's behalf: the integrating runner must verify
// source/artifact bindings and the interactive profile before sending a module.
// Parent -> Worker: { kind: "start", module: WebAssembly.Module,
//   transport: SharedArrayBuffer, args?: string[], env?: Record<string,string> }.
// Worker -> parent: at most one "ready", then one "result" or "error" message.
// All stdin/stdout/stderr bytes travel through the bounded shared rings, not
// postMessage. Drain output while the guest runs and after the terminal message.
//
// The parent owns both an absolute deadline and Worker.terminate(). Calling
// transport.cancel() wakes synchronous blocked imports; termination is necessary
// for guest code that does not call imports. Messages cannot interrupt _start.
// The parent must impose a bounded UI scrollback and retry only the unaccepted
// suffix of writeInput; this Worker does not create another buffering layer.
import {
  InteractiveLinuxTransport,
  InteractiveLinuxWasiHost,
  INTERACTIVE_LINUX_STDIO_PROFILE,
} from "./interactive-linux-wasi-host.mjs";
import { WasiHostError } from "./wasi-preview1-host.mjs";

function argumentsAndEnvironment(message) {
  const args = message.args ?? ["program.wasm"];
  const env = message.env ?? {};
  if (!Array.isArray(args) || args.length > 128
      || env === null || typeof env !== "object" || Array.isArray(env)
      || (Object.getPrototypeOf(env) !== Object.prototype && Object.getPrototypeOf(env) !== null)) {
    throw new WasiHostError("interactive-options-invalid", "interactive arguments/environment have invalid shape");
  }
  const entries = Object.entries(env);
  const text = [...args, ...entries.flat()];
  if (entries.length > 128 || text.some((value) => typeof value !== "string" || value.includes("\0") || value.length > 4096)
      || entries.some(([key]) => !key || key.includes("="))
      || text.reduce((total, value) => total + value.length, 0) > 65536) {
    throw new WasiHostError("interactive-options-invalid", "interactive arguments/environment exceed their bounded string contract");
  }
  // Do not append --no-stdin: this profile deliberately exposes queued stdin.
  return { args, env };
}

self.onmessage = async ({ data }) => {
  // A second start must never create another concurrent guest or queue owner.
  self.onmessage = null;
  let transport;
  let terminal;
  try {
    if (data?.kind !== "start" || !(data.module instanceof WebAssembly.Module)) {
      throw new WasiHostError("interactive-start-invalid", "interactive Worker requires a compiled WebAssembly module");
    }
    transport = new InteractiveLinuxTransport(data.transport);
    const host = new InteractiveLinuxWasiHost({ transport, ...argumentsAndEnvironment(data) });
    transport.checkCancelled();
    const instance = await WebAssembly.instantiate(data.module, host.imports);
    self.postMessage({ kind: "ready", profile: INTERACTIVE_LINUX_STDIO_PROFILE.id });
    const result = host.run(instance);
    terminal = { kind: "result", result };
  } catch (error) {
    terminal = { kind: "error", code: String(error?.code ?? "interactive-worker-failed").slice(0, 128),
      message: String(error?.message ?? error).slice(0, 4096) };
  } finally {
    transport?.closeInput();
    transport?.closeOutput();
  }
  // Terminal delivery means no further output can be published. Remaining
  // committed frames must still be drained before the UI declares completion.
  self.postMessage(terminal);
};
