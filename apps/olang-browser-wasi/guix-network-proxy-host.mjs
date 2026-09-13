import { LinuxWasiPreview1Host, LINUX_WASI_PREVIEW1_SIGNATURES } from "./linux-wasi-host.mjs";
import { WASI_PREVIEW1_SIGNATURES, WasiHostError } from "./wasi-preview1-host.mjs";

export const GUIX_PROXY_ARTIFACT = Object.freeze({
  url: "https://github.com/container2wasm/container2wasm/releases/download/v0.8.4/c2w-net-proxy.wasm",
  sha256: "2156167ecd413d1b7a0f5cf404e4a99967a9ae37c96161621ebb9f0b15d97638",
  bytes: 21574298,
  revision: "6ed3d98882a2b22eafc1334f574c364a5b2b8c47",
});
export const GUIX_PROXY_WASI_IMPORTS = Object.freeze([
  "args_get", "args_sizes_get", "clock_time_get", "environ_get", "environ_sizes_get",
  "fd_close", "fd_fdstat_get", "fd_fdstat_set_flags", "fd_filestat_get", "fd_prestat_dir_name",
  "fd_prestat_get", "fd_read", "fd_readdir", "fd_write", "path_filestat_get", "path_open",
  "path_readlink", "path_remove_directory", "path_unlink_file", "poll_oneoff", "proc_exit",
  "random_get", "sched_yield", "sock_accept", "sock_shutdown",
]);
const signature = (count) => Object.freeze({ parameters: Object.freeze(Array(count).fill("i32")), results: Object.freeze(["i32"]) });
export const GUIX_PROXY_HTTP_SIGNATURES = Object.freeze({
  http_send: signature(5), http_writebody: signature(5), http_isreadable: signature(2),
  http_recv: signature(5), http_readbody: signature(5),
});
export const GUIX_PROXY_WASI_SIGNATURES = Object.freeze(Object.fromEntries(GUIX_PROXY_WASI_IMPORTS.map((name) => [name,
  name === "sock_shutdown" ? signature(2) : LINUX_WASI_PREVIEW1_SIGNATURES[name] ?? WASI_PREVIEW1_SIGNATURES[name],
])));
export const GUIX_NETWORK_PROXY_IMPORT_PROFILE = Object.freeze([
  ...Object.entries(GUIX_PROXY_WASI_SIGNATURES).map(([name, type]) => Object.freeze({ module: "wasi_snapshot_preview1", name, ...type })),
  ...Object.entries(GUIX_PROXY_HTTP_SIGNATURES).map(([name, type]) => Object.freeze({ module: "env", name, ...type })),
]);
// The pinned Go release has 33 import entries, not 30: these three WASI
// functions occur twice with the same signature. No other duplicates belong
// to its exact import contract.
export const GUIX_PROXY_IMPORT_MULTIPLICITIES = Object.freeze(Object.fromEntries(
  GUIX_NETWORK_PROXY_IMPORT_PROFILE.map(({ module, name }) => [
    `${module}:${name}`,
    module === "wasi_snapshot_preview1" && ["fd_write", "random_get", "path_filestat_get"].includes(name) ? 2 : 1,
  ]),
));

const E = Object.freeze({ AGAIN: 6, BADF: 8, INVAL: 28, NOTCAPABLE: 76 });

// Narrow host for the pinned Go WASI network proxy, not a general Go host.
// fd3 writes one CA; fd4/fd5 are an in-browser virtual stream, not host sockets.
export class GuixNetworkProxyHost extends LinuxWasiPreview1Host {
  constructor({ network, http, postMessage }) {
    super({ args: ["c2w-net-proxy.wasm", "--certfd=3", "--net-listenfd=4"], env: {} });
    if (!(http instanceof SharedArrayBuffer) || http.byteLength !== 4108 || typeof postMessage !== "function") {
      throw new Error("invalid proxy HTTP transport");
    }
    this.network = network;
    this.post = postMessage;
    this.httpControl = new Int32Array(http, 0, 3);
    this.httpData = new Uint8Array(http, 12);
    this.certificate = new Uint8Array(16384);
    this.certificateLength = 0;
    this.certificateClosed = false;
    this.connected = false;
    this.diagnostic = "";
    const original = this.imports.wasi_snapshot_preview1;
    const guard = (operation) => (...args) => this.guard(() => operation(...args));
    const wasi = {
      ...original,
      sched_yield: () => 0,
      random_get: guard((pointer, length) => {
        const range = this.view(pointer, length >>> 0);
        const bytes = new Uint8Array(range.buffer, range.byteOffset, range.byteLength);
        if (!globalThis.crypto?.getRandomValues) throw new WasiHostError("proxy-random-unavailable", "cryptographic randomness is required for the proxy CA");
        for (let offset = 0; offset < bytes.length; offset += 65536) {
          globalThis.crypto.getRandomValues(bytes.subarray(offset, Math.min(offset + 65536, bytes.length)));
        }
        return 0;
      }),
      fd_prestat_get: () => E.BADF,
      fd_prestat_dir_name: () => E.BADF,
      fd_fdstat_get: guard((fd, pointer) => {
        if (fd < 0 || fd > 5 || (fd === 3 && this.certificateClosed) || (fd === 5 && !this.connected)) return E.BADF;
        const value = this.view(pointer, 24);
        new Uint8Array(value.buffer, value.byteOffset, 24).fill(0);
        value.setUint8(0, fd >= 4 ? 6 : fd === 3 ? 4 : 2);
        value.setUint16(2, fd >= 4 ? 4 : 0, true);
        value.setBigUint64(8, 2n | 8n | 64n | (1n << 21n) | (1n << 27n) | (1n << 29n), true);
        return 0;
      }),
      fd_fdstat_set_flags: (fd, flags) => fd < 0 || fd > 5 ? E.BADF : (flags & ~4) ? E.INVAL : 0,
      fd_filestat_get: guard((fd, pointer) => {
        if (fd < 0 || fd > 5) return E.BADF;
        const value = this.view(pointer, 64);
        new Uint8Array(value.buffer, value.byteOffset, 64).fill(0);
        value.setUint8(16, fd >= 4 ? 6 : fd === 3 ? 4 : 2);
        value.setBigUint64(24, 1n, true);
        return 0;
      }),
      fd_close: (fd) => {
        if (fd === 3) {
          if (this.certificateClosed || !this.certificateLength) return E.BADF;
          this.certificateClosed = true;
          const certificate = this.certificate.slice(0, this.certificateLength);
          this.certificate.fill(0);
          this.post({ kind: "certificate", certificate });
          return 0;
        }
        // Go's FileListener retains the admitted listener while closing its
        // temporary os.File wrapper. Its virtual endpoint belongs to the whole
        // proxy session; no new connection or external authority is created.
        if (fd === 4) return 0;
        if (fd === 5) { this.connected = false; this.network.cancel(); return 0; }
        return fd >= 0 && fd <= 2 ? 0 : E.BADF;
      },
      fd_read: guard((fd, pointer, count, result) => {
        const iovs = this.iovecs(pointer, count, result);
        if (fd === 0) { this.view(result, 4).setUint32(0, 0, true); return 0; }
        if (fd !== 5 || !this.connected) return E.BADF;
        let total = 0;
        for (const item of iovs) {
          const bytes = this.network.receive(Math.min(item.length, this.network.capacity));
          new Uint8Array(this.memory.buffer, item.pointer, bytes.length).set(bytes);
          total += bytes.length;
          if (bytes.length < item.length) break;
        }
        this.view(result, 4).setUint32(0, total, true);
        return !total && iovs.some((item) => item.length) ? E.AGAIN : 0;
      }),
      fd_write: guard((fd, pointer, count, result) => {
        const iovs = this.iovecs(pointer, count, result);
        const total = iovs.reduce((sum, item) => sum + item.length, 0);
        if (total > this.network.capacity) throw new Error("proxy write budget exceeded");
        if (fd === 3 && (this.certificateClosed || this.certificateLength + total > this.certificate.length)) {
          throw new Error("proxy certificate write budget exceeded");
        }
        if (fd !== 1 && fd !== 2 && fd !== 3 && !(fd === 5 && this.connected)) return E.BADF;
        const bytes = new Uint8Array(total);
        let offset = 0;
        for (const item of iovs) { bytes.set(new Uint8Array(this.memory.buffer, item.pointer, item.length), offset); offset += item.length; }
        if (fd === 5) this.network.send(bytes);
        else if (fd === 3) { this.certificate.set(bytes, this.certificateLength); this.certificateLength += total; }
        else if (this.diagnostic.length < 4096) this.diagnostic += new TextDecoder().decode(bytes.subarray(0, 4096 - this.diagnostic.length));
        this.view(result, 4).setUint32(0, total, true);
        return 0;
      }),
      sock_accept: guard((fd, flags, result) => {
        if (fd !== 4) return E.BADF;
        if (flags & ~4) return E.INVAL;
        if (this.connected) return E.AGAIN;
        this.network.checkCancelled();
        this.view(result, 4).setUint32(0, 5, true);
        this.connected = true;
        return 0;
      }),
      sock_shutdown: (fd) => {
        if (fd !== 5 || !this.connected) return E.BADF;
        this.connected = false; this.network.cancel(); return 0;
      },
      poll_oneoff: guard((...args) => this.pollProxy(...args)),
    };
    for (const name of ["fd_readdir", "path_filestat_get", "path_open", "path_readlink", "path_remove_directory", "path_unlink_file"]) {
      wasi[name] = () => E.NOTCAPABLE;
    }
    const receive = (type, id, pointer, size, lengthPointer, eofPointer) => {
      if (size > 4096 || size === 0) return E.INVAL;
      this.view(pointer, size); this.view(lengthPointer, 4); this.view(eofPointer, 4);
      const answer = this.exchange({ type, id, len: size });
      if (answer.status < 0) return E.INVAL;
      if (answer.bytes.length > size || (answer.status !== 0 && answer.status !== 1)) throw new Error("invalid HTTP response shape");
      new Uint8Array(this.memory.buffer, pointer >>> 0, answer.bytes.length).set(answer.bytes);
      this.view(lengthPointer, 4).setUint32(0, answer.bytes.length, true);
      this.view(eofPointer, 4).setUint32(0, answer.status, true);
      return 0;
    };
    const env = {
      http_send: guard((address, addressLength, request, requestLength, idPointer) => {
        if (addressLength > 2048 || requestLength > 16384) return E.INVAL;
        this.view(idPointer, 4);
        const addressView = this.view(address, addressLength);
        const requestView = this.view(request, requestLength);
        const answer = this.exchange({ type: "http_send",
          address: new Uint8Array(addressView.buffer, addressView.byteOffset, addressLength).slice(),
          req: new Uint8Array(requestView.buffer, requestView.byteOffset, requestLength).slice() });
        if (answer.status < 0) return E.INVAL;
        this.view(idPointer, 4).setUint32(0, answer.status, true);
        return 0;
      }),
      http_writebody: guard((id, pointer, length, written, eof) => {
        if (length !== 0 || (eof !== 0 && eof !== 1)) return E.INVAL;
        this.view(written, 4); this.view(pointer, 0);
        const answer = this.exchange({ type: "http_writebody", id, body: new Uint8Array(), isEOF: eof });
        if (answer.status < 0) return E.INVAL;
        this.view(written, 4).setUint32(0, 0, true);
        return 0;
      }),
      http_isreadable: guard((id, result) => {
        this.view(result, 4);
        const answer = this.exchange({ type: "http_isreadable", id });
        if (answer.status < 0) return E.INVAL;
        if (answer.bytes.length !== 1 || answer.bytes[0] > 1) throw new Error("invalid HTTP readiness response");
        this.view(result, 4).setUint32(0, answer.bytes[0], true);
        return 0;
      }),
      http_recv: guard((...args) => receive("http_recv", ...args)),
      http_readbody: guard((...args) => receive("http_readbody", ...args)),
    };
    this.imports = Object.freeze({ wasi_snapshot_preview1: Object.freeze(Object.fromEntries(
      GUIX_PROXY_WASI_IMPORTS.map((name) => [name, wasi[name]]))), env: Object.freeze(env) });
  }

  iovecs(pointer, count, result) {
    if ((count >>> 0) > 1024) throw new RangeError("too many proxy iovecs");
    const vector = this.view(pointer, count * 8);
    this.view(result, 4);
    const entries = [];
    for (let index = 0; index < count; index++) {
      const address = vector.getUint32(index * 8, true);
      const length = vector.getUint32(index * 8 + 4, true);
      this.view(address, length);
      entries.push({ pointer: address, length });
    }
    return entries;
  }

  exchange(message) {
    this.network.checkCancelled();
    Atomics.store(this.httpControl, 1, -1);
    Atomics.store(this.httpControl, 2, 0);
    Atomics.store(this.httpControl, 0, 0);
    this.post(message);
    while (Atomics.load(this.httpControl, 0) === 0) {
      Atomics.wait(this.httpControl, 0, 0, 1000);
      this.network.checkCancelled();
    }
    const length = Atomics.load(this.httpControl, 2);
    if (length < 0 || length > this.httpData.length) throw new Error("invalid HTTP shared reply length");
    return { status: Atomics.load(this.httpControl, 1), bytes: this.httpData.slice(0, length) };
  }

  pollProxy(inputPointer, outputPointer, count, resultPointer) {
    if (!Number.isInteger(count) || count < 1 || count > 1024) return E.INVAL;
    const input = this.view(inputPointer, count * 48);
    this.view(outputPointer, count * 32); this.view(resultPointer, 4);
    const subscriptions = [];
    for (let i = 0; i < count; i++) {
      const at = i * 48;
      const item = { userdata: input.getBigUint64(at, true), type: input.getUint8(at + 8), error: 0 };
      if (item.type === 0) {
        item.clock = input.getUint32(at + 16, true);
        const timeout = input.getBigUint64(at + 24, true);
        const flags = input.getUint16(at + 40, true);
        const now = this.clockNow(item.clock);
        if (now === null || (flags & ~1)) item.error = E.INVAL;
        else item.deadline = flags ? timeout : now + timeout;
      } else if (item.type === 1 || item.type === 2) {
        item.fd = input.getUint32(at + 16, true);
        if (![0, 1, 2, 3, 4, 5].includes(item.fd)) item.error = E.BADF;
      } else return E.INVAL;
      subscriptions.push(item);
    }
    for (;;) {
      const version = this.network.wakeVersion();
      this.network.checkCancelled();
      const ready = [];
      let wait = Infinity;
      for (const item of subscriptions) {
        if (item.error) ready.push(item);
        else if (item.type === 0) {
          const delay = item.deadline - this.clockNow(item.clock);
          if (delay <= 0n) ready.push(item);
          else wait = Math.min(wait, Number(delay) / 1000000);
        } else if (item.fd === 5) {
          if (!this.connected) ready.push({ ...item, error: E.BADF });
          else if (item.type === 2 || this.network.readable()) ready.push(item);
        } else if (item.fd === 4) {
          if (!this.connected) ready.push(item);
        } else ready.push(item);
      }
      if (ready.length) {
        const output = this.view(outputPointer, ready.length * 32);
        new Uint8Array(output.buffer, output.byteOffset, output.byteLength).fill(0);
        ready.forEach((item, index) => {
          output.setBigUint64(index * 32, item.userdata, true);
          output.setUint16(index * 32 + 8, item.error, true);
          output.setUint8(index * 32 + 10, item.type);
          if (item.type === 1 && item.fd === 0) output.setUint16(index * 32 + 24, 1, true);
        });
        this.view(resultPointer, 4).setUint32(0, ready.length, true);
        return 0;
      }
      this.network.waitForChange(version, wait);
    }
  }
}
