// Explicit interactive-stdio building block, not the sealed stdin-EOF profile.
// No host files, directories, processes or sockets are admitted. The parent
// verifies the module, owns the session deadline, drains output, and terminates
// the Worker on cancellation/deadline. A shared flag wakes blocked imports;
// terminating the Worker is still required for guest code that never imports.
import { LinuxWasiPreview1Host, LINUX_WASI_PREVIEW1_IMPORTS, LINUX_WASI_PREVIEW1_SIGNATURES } from "./linux-wasi-host.mjs";
import { WasiExit, WasiHostError } from "./wasi-preview1-host.mjs";

export const INTERACTIVE_LINUX_STDIO_PROFILE = Object.freeze({
  id: "ostadix.linux-wasi-interactive-stdio/v1",
  imports: LINUX_WASI_PREVIEW1_IMPORTS,
  signatures: LINUX_WASI_PREVIEW1_SIGNATURES,
  capabilities: Object.freeze(["queued-stdin", "streamed-stdout", "streamed-stderr", "clocks"]),
  deniedCapabilities: Object.freeze(["host-filesystem", "preopened-directories", "host-process-spawn", "network-sockets"]),
});

const ERRNO = Object.freeze({ AGAIN: 6, BADF: 8, FAULT: 21, INVAL: 28, PIPE: 64 });
const NONBLOCK = 4;
const MAX_IOVECS = 1024;
const MAX_SUBSCRIPTIONS = 1024;
const HEADER_BYTES = 64;
const FRAME_BYTES = 8;
const MAGIC = 0x4f495354;
const INDEX = Object.freeze({ MAGIC: 0, VERSION: 1, INPUT_CAPACITY: 2, OUTPUT_CAPACITY: 3,
  INPUT_READ: 4, INPUT_WRITE: 5, INPUT_CLOSED: 6, OUTPUT_READ: 7, OUTPUT_WRITE: 8,
  OUTPUT_CLOSED: 9, CANCELLED: 10, WAKE: 11 });

function transportError(message) {
  return new WasiHostError("interactive-transport-invalid", message);
}

function capacity(value, minimum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > 1024 * 1024 || (value & (value - 1)) !== 0) {
    throw transportError(`queue capacity must be a power of two between ${minimum} and 1048576 bytes`);
  }
  return value;
}

export function createInteractiveLinuxTransport({ stdinCapacity = 65536, outputCapacity = 65536 } = {}) {
  capacity(stdinCapacity, 1);
  capacity(outputCapacity, FRAME_BYTES + 1);
  const buffer = new SharedArrayBuffer(HEADER_BYTES + stdinCapacity + outputCapacity);
  const control = new Int32Array(buffer, 0, HEADER_BYTES / 4);
  control[INDEX.MAGIC] = MAGIC;
  control[INDEX.VERSION] = 1;
  control[INDEX.INPUT_CAPACITY] = stdinCapacity;
  control[INDEX.OUTPUT_CAPACITY] = outputCapacity;
  return new InteractiveLinuxTransport(buffer);
}

// Two single-producer/single-consumer rings: parent -> stdin, guest -> framed
// stdout/stderr. Do not call producer/consumer methods from multiple threads.
// Indices wrap modulo 2^32; power-of-two capacities preserve ring offsets at
// that wrap and are much smaller than 2^31. Copy before
// publishing an index, and never retain a view of consumed ring storage.
export class InteractiveLinuxTransport {
  constructor(buffer) {
    if (!(buffer instanceof SharedArrayBuffer) || buffer.byteLength < HEADER_BYTES) {
      throw transportError("interactive transport requires a SharedArrayBuffer");
    }
    this.buffer = buffer;
    this.control = new Int32Array(buffer, 0, HEADER_BYTES / 4);
    if (this.control[INDEX.MAGIC] !== MAGIC || this.control[INDEX.VERSION] !== 1) {
      throw transportError("unsupported interactive transport header");
    }
    this.inputCapacity = capacity(this.control[INDEX.INPUT_CAPACITY], 1);
    this.outputCapacity = capacity(this.control[INDEX.OUTPUT_CAPACITY], FRAME_BYTES + 1);
    if (buffer.byteLength !== HEADER_BYTES + this.inputCapacity + this.outputCapacity) {
      throw transportError("interactive transport size does not match its header");
    }
    this.input = new Uint8Array(buffer, HEADER_BYTES, this.inputCapacity);
    this.output = new Uint8Array(buffer, HEADER_BYTES + this.inputCapacity, this.outputCapacity);
  }

  wakeVersion() { return Atomics.load(this.control, INDEX.WAKE); }
  wake() {
    Atomics.add(this.control, INDEX.WAKE, 1);
    Atomics.notify(this.control, INDEX.WAKE);
  }
  cancelled() { return Atomics.load(this.control, INDEX.CANCELLED) !== 0; }
  checkCancelled() {
    if (this.cancelled()) throw new WasiHostError("interactive-session-cancelled", "interactive session was cancelled");
  }
  cancel() { Atomics.store(this.control, INDEX.CANCELLED, 1); this.wake(); }
  closeInput() { Atomics.store(this.control, INDEX.INPUT_CLOSED, 1); this.wake(); }
  closeOutput() { Atomics.store(this.control, INDEX.OUTPUT_CLOSED, 1); this.wake(); }
  inputClosed() { return Atomics.load(this.control, INDEX.INPUT_CLOSED) !== 0; }
  outputClosed() { return Atomics.load(this.control, INDEX.OUTPUT_CLOSED) !== 0; }

  ringState(readIndex, writeIndex, size) {
    const read = Atomics.load(this.control, readIndex) >>> 0;
    const write = Atomics.load(this.control, writeIndex) >>> 0;
    const used = (write - read) >>> 0;
    if (used > size) throw transportError("interactive queue indices are inconsistent");
    return { read, write, used, free: size - used };
  }
  inputState() { return this.ringState(INDEX.INPUT_READ, INDEX.INPUT_WRITE, this.inputCapacity); }
  outputState() { return this.ringState(INDEX.OUTPUT_READ, INDEX.OUTPUT_WRITE, this.outputCapacity); }
  status() {
    return { inputBytes: this.inputState().used, outputBytes: this.outputState().used,
      inputClosed: this.inputClosed(), outputClosed: this.outputClosed(), cancelled: this.cancelled() };
  }
  copyInto(ring, position, bytes) {
    const offset = position % ring.length;
    const first = Math.min(bytes.length, ring.length - offset);
    ring.set(bytes.subarray(0, first), offset);
    ring.set(bytes.subarray(first), 0);
  }
  copyOut(ring, position, destination) {
    const offset = position % ring.length;
    const first = Math.min(destination.length, ring.length - offset);
    destination.set(ring.subarray(offset, offset + first));
    destination.set(ring.subarray(0, destination.length - first), first);
  }

  // Parent-facing: never blocks the UI and never silently discards input.
  // The caller retains and retries any unaccepted suffix under its own bound.
  writeInput(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new TypeError("stdin must be Uint8Array bytes");
    this.checkCancelled();
    if (this.inputClosed()) throw transportError("stdin is closed");
    const state = this.inputState();
    const count = Math.min(state.free, bytes.length);
    if (count) {
      this.copyInto(this.input, state.write, bytes.subarray(0, count));
      Atomics.store(this.control, INDEX.INPUT_WRITE, (state.write + count) | 0);
      this.wake();
    }
    return count;
  }

  // Parent-facing: one bounded record, preserving stdout/stderr write order.
  // Returns null when empty, including after close; status distinguishes close.
  readOutput() {
    const state = this.outputState();
    if (!state.used) return null;
    if (state.used < FRAME_BYTES) throw transportError("incomplete output frame");
    const header = new Uint8Array(FRAME_BYTES);
    this.copyOut(this.output, state.read, header);
    const view = new DataView(header.buffer);
    const fd = view.getUint32(0, true);
    const count = view.getUint32(4, true);
    if ((fd !== 1 && fd !== 2) || count === 0 || count + FRAME_BYTES > state.used) {
      throw transportError("invalid output frame");
    }
    const bytes = new Uint8Array(count);
    this.copyOut(this.output, (state.read + FRAME_BYTES) >>> 0, bytes);
    Atomics.store(this.control, INDEX.OUTPUT_READ, (state.read + FRAME_BYTES + count) | 0);
    this.wake();
    return { fd, bytes };
  }

  // Synchronous waiting is valid only in a dedicated browser Worker. Tests
  // may inject a waitForChange function instead; no Promise-valued WASI import.
  waitForChange(version, milliseconds) {
    if (typeof DedicatedWorkerGlobalScope === "undefined"
        || !(globalThis instanceof DedicatedWorkerGlobalScope)) {
      throw new WasiHostError("interactive-worker-required", "blocking interactive I/O requires a dedicated Worker");
    }
    Atomics.wait(this.control, INDEX.WAKE, version, milliseconds);
  }
}

export class InteractiveLinuxWasiHost extends LinuxWasiPreview1Host {
  constructor(options = {}) {
    super({ args: options.args, env: options.env, clockNow: options.clockNow });
    this.transport = options.transport instanceof InteractiveLinuxTransport
      ? options.transport : new InteractiveLinuxTransport(options.transport);
    this.waitForChange = options.waitForChange ?? ((version, milliseconds) => this.transport.waitForChange(version, milliseconds));
    const original = this.imports.wasi_snapshot_preview1;
    this.imports = Object.freeze({ wasi_snapshot_preview1: Object.freeze({
      ...original,
      fd_read: (...args) => this.guard(() => this.readStdin(...args)),
      fd_write: (...args) => this.guard(() => this.writeStdio(...args)),
      poll_oneoff: (...args) => this.guard(() => this.pollInteractive(...args)),
      fd_close: (fd) => {
        const result = original.fd_close(fd);
        if (result === 0 && fd === 0) this.transport.closeInput();
        return result;
      },
    }) });
  }

  iovecs(pointer, count, resultPointer) {
    count >>>= 0;
    if (count > MAX_IOVECS) return null;
    const vector = this.view(pointer, count * 8);
    this.view(resultPointer, 4);
    const entries = [];
    let total = 0;
    for (let index = 0; index < count; index += 1) {
      const offset = vector.getUint32(index * 8, true);
      const length = vector.getUint32(index * 8 + 4, true);
      this.view(offset, length);
      entries.push({ offset, length });
      total += length;
    }
    return { entries, total };
  }

  wait(version, milliseconds) {
    const result = this.waitForChange(version, milliseconds);
    if (result && typeof result.then === "function") {
      throw new WasiHostError("interactive-wait-invalid", "interactive WASI waiting must be synchronous");
    }
  }

  readStdin(fd, pointer, count, resultPointer) {
    if (fd !== 0 || !this.descriptorOpen(fd)) return ERRNO.BADF;
    const vectors = this.iovecs(pointer, count, resultPointer);
    if (!vectors) return ERRNO.INVAL;
    for (;;) {
      const version = this.transport.wakeVersion();
      this.transport.checkCancelled();
      const state = this.transport.inputState();
      if (state.used || this.transport.inputClosed() || vectors.total === 0) {
        const available = Math.min(state.used, vectors.total);
        let copied = 0;
        for (const { offset, length } of vectors.entries) {
          const size = Math.min(length, available - copied);
          if (size === 0) continue;
          this.transport.copyOut(this.transport.input, (state.read + copied) >>> 0,
            new Uint8Array(this.memory.buffer, offset, size));
          copied += size;
        }
        this.view(resultPointer, 4).setUint32(0, copied, true);
        Atomics.store(this.transport.control, INDEX.INPUT_READ, (state.read + copied) | 0);
        if (copied) this.transport.wake();
        return 0;
      }
      if (this.descriptorFlags.get(fd) & NONBLOCK) return ERRNO.AGAIN;
      this.wait(version, Infinity);
    }
  }

  writeStdio(fd, pointer, count, resultPointer) {
    if ((fd !== 1 && fd !== 2) || !this.descriptorOpen(fd)) return ERRNO.BADF;
    const vectors = this.iovecs(pointer, count, resultPointer);
    if (!vectors) return ERRNO.INVAL;
    for (;;) {
      const version = this.transport.wakeVersion();
      this.transport.checkCancelled();
      if (this.transport.outputClosed()) return ERRNO.PIPE;
      const state = this.transport.outputState();
      if (vectors.total === 0) {
        this.view(resultPointer, 4).setUint32(0, 0, true);
        return 0;
      }
      if (state.free > FRAME_BYTES) {
        const available = Math.min(vectors.total, state.free - FRAME_BYTES);
        const header = new Uint8Array(FRAME_BYTES);
        const view = new DataView(header.buffer);
        view.setUint32(0, fd, true);
        view.setUint32(4, available, true);
        this.transport.copyInto(this.transport.output, state.write, header);
        let copied = 0;
        for (const { offset, length } of vectors.entries) {
          const size = Math.min(length, available - copied);
          if (size === 0) continue;
          this.transport.copyInto(this.transport.output, (state.write + FRAME_BYTES + copied) >>> 0,
            new Uint8Array(this.memory.buffer, offset, size));
          copied += size;
        }
        this.view(resultPointer, 4).setUint32(0, copied, true);
        Atomics.store(this.transport.control, INDEX.OUTPUT_WRITE, (state.write + FRAME_BYTES + copied) | 0);
        this.transport.wake();
        return 0;
      }
      if (this.descriptorFlags.get(fd) & NONBLOCK) return ERRNO.AGAIN;
      this.wait(version, Infinity);
    }
  }

  pollInteractive(inputPointer, outputPointer, count, resultPointer) {
    count >>>= 0;
    if (count === 0 || count > MAX_SUBSCRIPTIONS) return ERRNO.INVAL;
    const input = this.view(inputPointer, count * 48);
    this.view(outputPointer, count * 32);
    this.view(resultPointer, 4);
    const subscriptions = [];
    for (let index = 0; index < count; index += 1) {
      const offset = index * 48;
      const subscription = { userdata: input.getBigUint64(offset, true), type: input.getUint8(offset + 8), error: 0 };
      if (subscription.type === 0) {
        subscription.clock = input.getUint32(offset + 16, true);
        const timeout = input.getBigUint64(offset + 24, true);
        const flags = input.getUint16(offset + 40, true);
        if (flags & ~1) return ERRNO.INVAL;
        const now = this.clockNow(subscription.clock);
        if (now === null) subscription.error = ERRNO.INVAL;
        else subscription.deadline = flags === 1 ? timeout : now + timeout;
      } else if (subscription.type === 1 || subscription.type === 2) {
        subscription.fd = input.getUint32(offset + 16, true);
        const additional = this.additionalPollReadiness?.(subscription.fd, subscription.type);
        subscription.additional = additional !== undefined && additional !== null;
        if (!subscription.additional && (!this.descriptorOpen(subscription.fd)
            || (subscription.type === 1 ? subscription.fd !== 0 : subscription.fd === 0))) {
          subscription.error = ERRNO.BADF;
        }
      } else return ERRNO.INVAL;
      subscriptions.push(subscription);
    }
    for (;;) {
      const version = this.transport.wakeVersion();
      this.transport.checkCancelled();
      let remaining = Infinity;
      const ready = [];
      for (const subscription of subscriptions) {
        let event;
        if (subscription.error) event = { ...subscription, bytes: 0, flags: 0 };
        else if (subscription.type === 0) {
          const delay = subscription.deadline - this.clockNow(subscription.clock);
          if (delay <= 0n) event = { ...subscription, bytes: 0, flags: 0 };
          else remaining = Math.min(remaining, Number(delay) / 1_000_000);
        } else if (subscription.additional) {
          const additional = this.additionalPollReadiness?.(subscription.fd, subscription.type);
          if (!additional) event = { ...subscription, error: ERRNO.BADF, bytes: 0, flags: 0 };
          else if (additional.ready || additional.error) {
            event = { ...subscription, error: additional.error ?? 0,
              bytes: additional.nbytes ?? 0, flags: additional.hangup ? 1 : 0 };
          }
        } else if (subscription.type === 1) {
          const bytes = this.transport.inputState().used;
          const closed = this.transport.inputClosed();
          if (bytes || closed) event = { ...subscription, bytes, flags: closed ? 1 : 0 };
        } else {
          const bytes = Math.max(0, this.transport.outputState().free - FRAME_BYTES);
          if (bytes || this.transport.outputClosed()) {
            event = { ...subscription, bytes, flags: this.transport.outputClosed() ? 1 : 0,
              error: this.transport.outputClosed() ? ERRNO.PIPE : 0 };
          }
        }
        if (event) ready.push(event);
      }
      if (ready.length) {
        const output = this.view(outputPointer, ready.length * 32);
        new Uint8Array(output.buffer, output.byteOffset, output.byteLength).fill(0);
        ready.forEach((event, index) => {
          const offset = index * 32;
          output.setBigUint64(offset, event.userdata, true);
          output.setUint16(offset + 8, event.error, true);
          output.setUint8(offset + 10, event.type);
          output.setBigUint64(offset + 16, BigInt(event.bytes), true);
          output.setUint16(offset + 24, event.flags, true);
        });
        this.view(resultPointer, 4).setUint32(0, ready.length, true);
        return 0;
      }
      this.wait(version, remaining);
    }
  }

  run(instance) {
    try {
      this.attach(instance);
      if (typeof instance.exports._start !== "function") {
        throw new WasiHostError("missing-start-export", "interactive WASI module must export _start");
      }
      this.transport.checkCancelled();
      let exitCode = 0;
      try { instance.exports._start(); } catch (error) {
        if (error instanceof WasiExit) exitCode = error.code;
        else if (error instanceof WasiHostError) throw error;
        else throw new WasiHostError("wasm-trap", `interactive WASI guest trapped: ${error?.message ?? error}`, error);
      }
      return Object.freeze({ ok: exitCode === 0, exitCode, output: "shared-queue", profile: INTERACTIVE_LINUX_STDIO_PROFILE.id });
    } finally {
      this.transport.closeInput();
      this.transport.closeOutput();
    }
  }
}
