import { GuixNetworkEndpoint } from "./guix-network-transport.mjs";
import { GuixNetworkProxyHost } from "./guix-network-proxy-host.mjs";
import { InteractiveLinuxTransport } from "./interactive-linux-wasi-host.mjs";

// The parent verifies the exact release bytes/import signatures before sending
// this compiled module, owns the common deadline, and terminates both Workers.
// No fetch, network socket, dynamic import, or unverified executable URL here.
self.onmessage = async ({ data }) => {
  self.onmessage = null;
  let network;
  try {
    if (data?.kind !== "start" || !(data.module instanceof WebAssembly.Module)) throw new Error("invalid proxy Worker start");
    const transport = new InteractiveLinuxTransport(data.transport);
    network = new GuixNetworkEndpoint(data.network, "proxy", { wake: () => transport.wake() });
    const host = new GuixNetworkProxyHost({ network, http: data.http, postMessage: (message) => self.postMessage(message) });
    network.checkCancelled();
    const instance = await WebAssembly.instantiate(data.module, host.imports);
    const result = host.run(instance);
    throw new Error(`network proxy exited unexpectedly (${result.exitCode}): ${host.diagnostic}`);
  } catch (error) {
    network?.cancel();
    self.postMessage({ kind: "error", code: "guix-network-proxy-failed",
      message: String(error?.message ?? error).slice(0, 4096) });
  }
};
