import { LinuxWasiPreview1Host } from "./linux-wasi-host.mjs";

// Synchronous guest imports run off the UI thread. The parent owns the hard
// deadline and terminates this worker even if the guest never returns.
self.onmessage = async ({ data }) => {
  self.onmessage = null;
  try {
    let outputBytes = 0;
    const host = new LinuxWasiPreview1Host({ args: data.args, env: data.env });
    const wasi = host.imports.wasi_snapshot_preview1;
    const imports = { wasi_snapshot_preview1: {
      ...wasi,
      fd_write: (fd, iovs, count, written) => {
        if ((fd !== 1 && fd !== 2) || !host.descriptorOpen(fd)) {
          return wasi.fd_write(fd, iovs, count, written);
        }
        let requested = 0;
        const pointer = iovs >>> 0;
        const length = count >>> 0;
        const memory = host.memory?.buffer;
        if (memory) {
          // The shared host appends output before storing nwritten. Validate
          // every accessed range first so FAULT cannot append uncounted bytes.
          if (pointer + length * 8 > memory.byteLength
              || (written >>> 0) + 4 > memory.byteLength) return 21; // FAULT.
          const view = new DataView(memory);
          for (let index = 0; index < length; index += 1) {
            const offset = view.getUint32(pointer + index * 8, true);
            const size = view.getUint32(pointer + index * 8 + 4, true);
            if (offset + size > memory.byteLength) return 21; // FAULT.
            requested += size;
            if (outputBytes + requested > 8 * 1024 * 1024) {
              // Throw outside the base host's errno guard, before it appends
              // output. A callback exception would merely become WASI FAULT.
              throw new Error("Linux WASI output exceeded 8 MiB");
            }
          }
        }
        const result = wasi.fd_write(fd, iovs, count, written);
        if (result === 0) outputBytes += requested;
        return result;
      },
    } };
    const instance = await WebAssembly.instantiate(data.module, imports);
    self.postMessage({ kind: "result", result: host.run(instance) });
  } catch (error) {
    self.postMessage({ kind: "error", code: error.code, message: error.message || String(error) });
  }
};
