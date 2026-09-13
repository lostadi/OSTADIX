// Noninteractive host profile for the embedded Linux/amd64 WASI artifact.
// Guest files and processes remain inside the emulator's embedded filesystem;
// this host grants neither browser filesystem nor socket authority.
import {
  WASI_PREVIEW1_SIGNATURES,
  WasiHostError,
  WasiPreview1Host,
} from "./wasi-preview1-host.mjs";

export const LINUX_WASI_PREVIEW1_IMPORTS = Object.freeze([
  "args_get", "args_sizes_get", "clock_time_get", "environ_get",
  "environ_sizes_get", "fd_close", "fd_fdstat_get", "fd_fdstat_set_flags",
  "fd_filestat_get", "fd_filestat_set_size", "fd_pread", "fd_prestat_dir_name",
  "fd_prestat_get", "fd_pwrite", "fd_read", "fd_readdir", "fd_seek", "fd_write",
  "path_create_directory", "path_filestat_get", "path_filestat_set_times",
  "path_link", "path_open", "path_readlink", "path_remove_directory",
  "path_rename", "path_symlink", "path_unlink_file", "poll_oneoff", "proc_exit",
  "sock_accept", "sock_recv", "sock_send",
]);

const signature = (parameters) => Object.freeze({
  parameters: Object.freeze(parameters),
  results: Object.freeze(["i32"]),
});
const additionalSignatures = {
  fd_fdstat_set_flags: signature(["i32", "i32"]),
  fd_filestat_set_size: signature(["i32", "i64"]),
  fd_pread: signature(["i32", "i32", "i32", "i64", "i32"]),
  fd_pwrite: signature(["i32", "i32", "i32", "i64", "i32"]),
  path_create_directory: signature(["i32", "i32", "i32"]),
  path_filestat_set_times: signature(["i32", "i32", "i32", "i32", "i64", "i64", "i32"]),
  path_link: signature(["i32", "i32", "i32", "i32", "i32", "i32", "i32"]),
  path_symlink: signature(["i32", "i32", "i32", "i32", "i32"]),
  sock_accept: signature(["i32", "i32", "i32"]),
  sock_recv: signature(["i32", "i32", "i32", "i32", "i32", "i32"]),
  sock_send: signature(["i32", "i32", "i32", "i32", "i32"]),
};
export const LINUX_WASI_PREVIEW1_SIGNATURES = Object.freeze(Object.fromEntries(
  LINUX_WASI_PREVIEW1_IMPORTS.map((name) => [
    name, additionalSignatures[name] ?? WASI_PREVIEW1_SIGNATURES[name],
  ]),
));

const ERRNO = Object.freeze({ BADF: 8, FAULT: 21, INVAL: 28, NOTSUP: 58, SPIPE: 70, NOTCAPABLE: 76 });
const NONBLOCK = 4;
const READ = 1;
const WRITE = 2;

function clockNow(id) {
  if (id === 0) return BigInt(Date.now()) * 1_000_000n;
  if (id === 1) return BigInt(Math.floor(performance.now() * 1_000_000));
  return null;
}

export class LinuxWasiPreview1Host extends WasiPreview1Host {
  constructor(options = {}) {
    super(options);
    this.descriptorFlags = new Map([[0, 0], [1, 0], [2, 0]]);
    this.clockNow = options.clockNow ?? clockNow;
    let waitCell;
    this.waitMilliseconds = options.waitMilliseconds ?? ((milliseconds) => {
      if (typeof SharedArrayBuffer !== "function" || typeof Atomics?.wait !== "function") {
        throw new WasiHostError(
          "linux-wasi-poll-unavailable",
          "Linux WASI polling requires a dedicated Worker and cross-origin isolation",
        );
      }
      waitCell ??= new Int32Array(new SharedArrayBuffer(4));
      Atomics.wait(waitCell, 0, 0, milliseconds);
    });
    const original = this.imports.wasi_snapshot_preview1;
    const deniedPath = () => ERRNO.NOTCAPABLE;
    const overrides = {
      fd_fdstat_get: (fd, pointer) => {
        const result = original.fd_fdstat_get(fd, pointer);
        if (result !== 0) return result;
        return this.guard(() => {
          const view = this.view(pointer, 24);
          view.setUint16(2, this.descriptorFlags.get(fd), true);
          // Stdio supports its direction, fd flags/stat, and polling only.
          const direction = fd === 0 ? 1n << 1n : 1n << 6n;
          view.setBigUint64(8, direction | (1n << 3n) | (1n << 21n) | (1n << 27n), true);
          return 0;
        });
      },
      fd_fdstat_set_flags: (fd, flags) => {
        if (!this.descriptorOpen(fd)) return ERRNO.BADF;
        if ((flags & ~31) !== 0) return ERRNO.INVAL;
        if ((flags & ~NONBLOCK) !== 0) return ERRNO.NOTSUP;
        this.descriptorFlags.set(fd, flags);
        return 0;
      },
      fd_filestat_set_size: (fd) => this.descriptorOpen(fd) ? ERRNO.NOTCAPABLE : ERRNO.BADF,
      fd_pread: (fd) => this.descriptorOpen(fd) ? ERRNO.SPIPE : ERRNO.BADF,
      fd_pwrite: (fd) => this.descriptorOpen(fd) ? ERRNO.SPIPE : ERRNO.BADF,
      path_create_directory: deniedPath,
      path_filestat_set_times: deniedPath,
      path_link: deniedPath,
      path_symlink: deniedPath,
      poll_oneoff: (...args) => this.guard(() => this.pollOneoff(...args)),
      sock_accept: () => ERRNO.BADF,
      sock_recv: () => ERRNO.BADF,
      sock_send: () => ERRNO.BADF,
    };
    this.imports = Object.freeze({ wasi_snapshot_preview1: Object.freeze(Object.fromEntries(
      LINUX_WASI_PREVIEW1_IMPORTS.map((name) => [name, overrides[name] ?? original[name]]),
    )) });
  }

  descriptorOpen(fd) {
    return Number.isInteger(fd) && fd >= 0 && fd <= 2 && !this.closedDescriptors.has(fd);
  }

  view(pointer, length) {
    const start = Number(pointer) >>> 0;
    if (!Number.isSafeInteger(length) || length < 0 || start + length > this.memory?.buffer.byteLength) {
      throw new RangeError("Linux WASI guest memory range is out of bounds");
    }
    return new DataView(this.memory.buffer, start, length);
  }

  guard(operation) {
    try {
      return operation();
    } catch (error) {
      if (error instanceof WasiHostError) throw error;
      if (error instanceof RangeError || error instanceof TypeError) return ERRNO.FAULT;
      throw error;
    }
  }

  pollOneoff(inputPointer, outputPointer, count, resultPointer) {
    count >>>= 0;
    if (count === 0) return ERRNO.INVAL;
    const input = this.view(inputPointer, count * 48);
    this.view(outputPointer, count * 32);
    this.view(resultPointer, 4);
    const subscriptions = [];
    for (let index = 0; index < count; index += 1) {
      const offset = index * 48;
      const subscription = {
        userdata: input.getBigUint64(offset, true),
        type: input.getUint8(offset + 8),
        error: 0,
        flags: 0,
      };
      if (subscription.type === 0) {
        subscription.clock = input.getUint32(offset + 16, true);
        const timeout = input.getBigUint64(offset + 24, true);
        const flags = input.getUint16(offset + 40, true);
        if ((flags & ~1) !== 0) return ERRNO.INVAL;
        const now = this.clockNow(subscription.clock);
        if (now === null) subscription.error = ERRNO.INVAL;
        else subscription.deadline = flags === 1 ? timeout : now + timeout;
      } else if (subscription.type === READ || subscription.type === WRITE) {
        const fd = input.getUint32(offset + 16, true);
        if (!this.descriptorOpen(fd) || (subscription.type === READ ? fd !== 0 : fd === 0)) {
          subscription.error = ERRNO.BADF;
        } else if (subscription.type === READ) {
          subscription.flags = 1; // EOF: EVENTRWFLAGS_FD_READWRITE_HANGUP.
        }
      } else {
        return ERRNO.INVAL;
      }
      subscriptions.push(subscription);
    }

    let ready;
    for (;;) {
      let remaining;
      ready = subscriptions.filter((subscription) => {
        if (subscription.error !== 0 || subscription.type !== 0) return true;
        const delay = subscription.deadline - this.clockNow(subscription.clock);
        if (delay <= 0n) return true;
        if (remaining === undefined || delay < remaining) remaining = delay;
        return false;
      });
      if (ready.length > 0) break;
      // Imports are synchronous in this artifact. Wait in its Worker, never
      // resolve an import with a Promise or report a clock before it expires.
      this.waitMilliseconds(Number(remaining) / 1_000_000);
    }

    const output = this.view(outputPointer, ready.length * 32);
    new Uint8Array(output.buffer, output.byteOffset, output.byteLength).fill(0);
    ready.forEach((subscription, index) => {
      const offset = index * 32;
      output.setBigUint64(offset, subscription.userdata, true);
      output.setUint16(offset + 8, subscription.error, true);
      output.setUint8(offset + 10, subscription.type);
      output.setUint16(offset + 24, subscription.flags, true);
    });
    this.view(resultPointer, 4).setUint32(0, ready.length, true);
    return 0;
  }
}
