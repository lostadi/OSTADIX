// Lightweight host/Worker contracts only. No Guix/Linux boot is claimed here.
import assert from "node:assert/strict";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";
import {
  createInteractiveLinuxTransport,
  InteractiveLinuxTransport,
  InteractiveLinuxWasiHost,
  INTERACTIVE_LINUX_STDIO_PROFILE,
} from "./interactive-linux-wasi-host.mjs";
import { LinuxWasiPreview1Host, LINUX_WASI_PREVIEW1_IMPORTS } from "./linux-wasi-host.mjs";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const INPUT_READ = 4, INPUT_WRITE = 5, OUTPUT_READ = 7, OUTPUT_WRITE = 8;
const encode = (value) => encoder.encode(value);
const text = (value) => decoder.decode(value);

function fixture(options = {}) {
  const transport = options.transport ?? createInteractiveLinuxTransport({ stdinCapacity: 16, outputCapacity: 32 });
  const host = new InteractiveLinuxWasiHost({ ...options, transport });
  host.attach(new WebAssembly.Memory({ initial: 1 }));
  const memory = new DataView(host.memory.buffer);
  const bytes = new Uint8Array(host.memory.buffer);
  const wasi = host.imports.wasi_snapshot_preview1;
  const vectors = (entries) => entries.forEach(([offset, length], index) => {
    memory.setUint32(index * 8, offset, true);
    memory.setUint32(index * 8 + 4, length, true);
  });
  const read = (size = 16) => { vectors([[1024, size]]); return wasi.fd_read(0, 0, 1, 256); };
  const write = (value, fd = 1) => {
    const data = typeof value === "string" ? encode(value) : value;
    bytes.set(data, 1024);
    vectors([[1024, data.length]]);
    return wasi.fd_write(fd, 0, 1, 256);
  };
  const subscription = (index, type, value, userdata = 42n, flags = 0) => {
    const offset = index * 48;
    bytes.fill(0, offset, offset + 48);
    memory.setBigUint64(offset, userdata, true);
    memory.setUint8(offset + 8, type);
    memory.setUint32(offset + 16, type === 0 ? 1 : value, true);
    if (type === 0) {
      memory.setBigUint64(offset + 24, value, true);
      memory.setUint16(offset + 40, flags, true);
    }
  };
  return { transport, host, memory, bytes, wasi, vectors, read, write, subscription,
    count: () => memory.getUint32(256, true), poll: (count = 1) => wasi.poll_oneoff(0, 512, count, 768) };
}

let checks = 0;
function check(name, operation) {
  operation();
  checks += 1;
  console.log(`interactive stdio ${name}: PASS`);
}

function unitTests() {
  check("bounded transport and separate profile", () => {
    const { wasi, transport } = fixture();
    assert.deepEqual(Object.keys(wasi), [...LINUX_WASI_PREVIEW1_IMPORTS]);
    assert.equal(Object.keys(wasi).length, 33);
    assert.equal(INTERACTIVE_LINUX_STDIO_PROFILE.id, "ostadix.linux-wasi-interactive-stdio/v1");
    assert.ok(INTERACTIVE_LINUX_STDIO_PROFILE.deniedCapabilities.includes("network-sockets"));
    for (const name of ["path_open", "path_create_directory", "path_symlink"]) assert.equal(wasi[name](), 76);
    for (const name of ["sock_accept", "sock_recv", "sock_send", "fd_prestat_get"]) assert.equal(wasi[name](3, 0), 8);
    assert.equal(transport.buffer.byteLength, 64 + 16 + 32);
    assert.throws(() => createInteractiveLinuxTransport({ stdinCapacity: 3 }), /power of two/);
    assert.throws(() => createInteractiveLinuxTransport({ outputCapacity: 8 }), /power of two/);
    assert.throws(() => createInteractiveLinuxTransport({ outputCapacity: 2 ** 21 }), /power of two/);
    assert.throws(() => new InteractiveLinuxTransport(new ArrayBuffer(64)), /SharedArrayBuffer/);
    assert.throws(() => new InteractiveLinuxTransport(new SharedArrayBuffer(64)), /header/);
    const malformed = createInteractiveLinuxTransport();
    malformed.control[2] = 16;
    assert.throws(() => new InteractiveLinuxTransport(malformed.buffer), /size/);
    assert.throws(() => transport.writeInput("text"), /Uint8Array/);
    const sealed = new LinuxWasiPreview1Host();
    sealed.attach(new WebAssembly.Memory({ initial: 1 }));
    assert.equal(sealed.imports.wasi_snapshot_preview1.fd_read(0, 0, 0, 0), 0);
    assert.equal(new DataView(sealed.memory.buffer).getUint32(0, true), 0);
  });

  check("queued partial reads, EOF and flags", () => {
    const f = fixture();
    assert.equal(f.wasi.fd_fdstat_set_flags(0, 4), 0);
    assert.equal(f.wasi.fd_fdstat_get(0, 400), 0);
    assert.equal(f.memory.getUint16(402, true), 4);
    assert.equal(f.wasi.fd_fdstat_set_flags(0, 1), 58);
    assert.equal(f.wasi.fd_fdstat_set_flags(0, 32), 28);
    f.memory.setUint32(256, 999, true);
    assert.equal(f.read(), 6);
    assert.equal(f.count(), 999);
    assert.equal(f.transport.writeInput(encode("abcdefghijklmnopq")), 16);
    assert.equal(f.transport.writeInput(encode("q")), 0);
    f.vectors([[1024, 2], [2048, 3]]);
    assert.equal(f.wasi.fd_read(0, 0, 2, 256), 0);
    assert.equal(f.count(), 5);
    assert.equal(text(f.bytes.subarray(1024, 1026)) + text(f.bytes.subarray(2048, 2051)), "abcde");
    assert.equal(f.transport.writeInput(encode("qrs")), 3);
    f.transport.closeInput();
    assert.equal(f.read(), 0);
    assert.equal(f.count(), 14);
    assert.equal(text(f.bytes.subarray(1024, 1038)), "fghijklmnopqrs");
    assert.equal(f.read(), 0);
    assert.equal(f.count(), 0);
    assert.throws(() => f.transport.writeInput(encode("x")), /closed/);
    assert.equal(f.wasi.fd_close(0), 0);
    assert.equal(f.read(), 8);
    assert.equal(f.wasi.fd_fdstat_set_flags(0, 0), 8);
  });

  check("FAULT never consumes input or publishes output", () => {
    for (const operation of ["fd_read", "fd_write"]) {
      const f = fixture();
      f.transport.writeInput(encode("queued"));
      f.bytes.fill(0x7e, 1024, 1032);
      f.memory.setUint32(256, 999, true);
      const fd = operation === "fd_read" ? 0 : 1;
      for (const entries of [[[65535, 2]], [[1024, 2], [65535, 2]], [[0xffffffff, 4]]]) {
        f.vectors(entries);
        assert.equal(f.wasi[operation](fd, 0, entries.length, 256), 21);
        assert.equal(f.count(), 999);
        assert.equal(f.transport.status().inputBytes, 6);
        assert.equal(f.transport.status().outputBytes, 0);
        assert.deepEqual([...f.bytes.subarray(1024, 1032)], Array(8).fill(0x7e));
      }
      f.vectors([[1024, 2]]);
      assert.equal(f.wasi[operation](fd, 0, 1, 65534), 21);
      assert.equal(f.wasi[operation](fd, 65535, 1, 256), 21);
      assert.equal(f.wasi[operation](fd, 0, 1025, 256), 28);
      assert.equal(f.wasi[operation](fd, 0, -1, 256), 28);
      assert.equal(f.transport.status().inputBytes, 6);
      assert.equal(f.transport.status().outputBytes, 0);
      assert.equal(f.wasi[operation](fd, 65536, 0, 256), 0);
      assert.equal(f.count(), 0);
    }
  });

  check("partial output, bounded backpressure and stream order", () => {
    const f = fixture();
    assert.equal(f.write("abcdefghijklmnopqrstuvwxyz"), 0);
    assert.equal(f.count(), 24);
    assert.equal(f.transport.status().outputBytes, 32);
    f.wasi.fd_fdstat_set_flags(2, 4);
    f.memory.setUint32(256, 999, true);
    assert.equal(f.write("error", 2), 6);
    assert.equal(f.count(), 999);
    let record = f.transport.readOutput();
    assert.equal(record.fd, 1);
    assert.equal(text(record.bytes), "abcdefghijklmnopqrstuvwx");
    assert.equal(f.write("error", 2), 0);
    assert.equal(f.write("rest", 1), 0);
    record = f.transport.readOutput();
    assert.equal(record.fd, 2);
    assert.equal(text(record.bytes), "error");
    record = f.transport.readOutput();
    assert.equal(record.fd, 1);
    assert.equal(text(record.bytes), "rest");
    assert.equal(f.transport.readOutput(), null);
    let waits = 0;
    f.host.waitForChange = () => { waits += 1; assert.equal(f.transport.readOutput().bytes.length, 24); };
    assert.equal(f.write("x".repeat(24)), 0);
    assert.equal(f.write("after drain"), 0);
    assert.equal(waits, 1);
    assert.equal(text(f.transport.readOutput().bytes), "after drain");
    for (let index = 0; index < 2000; index += 1) {
      assert.equal(f.write("abcdefgh", index % 2 + 1), 0);
      assert.equal(f.transport.readOutput().bytes.length, 8);
    }
    assert.equal(f.host.stdout, "");
    assert.equal(f.host.stderr, "");
    assert.equal(f.transport.status().outputBytes, 0);
    f.transport.closeOutput();
    assert.equal(f.write("closed"), 64);
    assert.equal(f.wasi.fd_close(1), 0);
    assert.equal(f.write("closed descriptor"), 8);
  });

  check("32-bit counter wrap and malformed indices", () => {
    const f = fixture();
    for (const index of [INPUT_READ, INPUT_WRITE, OUTPUT_READ, OUTPUT_WRITE]) Atomics.store(f.transport.control, index, -4);
    assert.equal(f.transport.writeInput(encode("across wrap")), 11);
    assert.equal(f.read(), 0);
    assert.equal(f.count(), 11);
    assert.equal(text(f.bytes.subarray(1024, 1035)), "across wrap");
    assert.equal(f.write("output wrap"), 0);
    assert.equal(text(f.transport.readOutput().bytes), "output wrap");
    assert.equal(f.transport.status().inputBytes, 0);
    assert.equal(f.transport.status().outputBytes, 0);
    Atomics.store(f.transport.control, INPUT_WRITE, 999);
    assert.throws(() => f.read(), /indices/);
  });

  check("poll input wakeup, EOF and descriptor errors", () => {
    const f = fixture();
    let waits = 0;
    f.host.waitForChange = (version, delay) => {
      assert.equal(version, f.transport.wakeVersion());
      assert.equal(delay, Infinity);
      waits += 1;
      f.transport.writeInput(encode("ready"));
    };
    f.subscription(0, 1, 0, 77n);
    assert.equal(f.poll(), 0);
    assert.equal(waits, 1);
    assert.equal(f.memory.getUint32(768, true), 1);
    assert.equal(f.memory.getBigUint64(512, true), 77n);
    assert.equal(f.memory.getUint16(520, true), 0);
    assert.equal(f.memory.getUint8(522), 1);
    assert.equal(f.memory.getBigUint64(528, true), 5n);
    assert.equal(f.memory.getUint16(536, true), 0);
    assert.equal(f.transport.status().inputBytes, 5);
    f.transport.closeInput();
    assert.equal(f.poll(), 0);
    assert.equal(f.memory.getUint16(536, true), 1);
    assert.equal(f.read(), 0);
    f.subscription(0, 1, 0);
    assert.equal(f.poll(), 0);
    assert.equal(f.memory.getBigUint64(528, true), 0n);
    for (const [type, fd] of [[1, 1], [2, 0], [2, 3]]) {
      f.subscription(0, type, fd);
      assert.equal(f.poll(), 0);
      assert.equal(f.memory.getUint16(520, true), 8);
    }
    f.wasi.fd_close(0);
    f.subscription(0, 1, 0);
    assert.equal(f.poll(), 0);
    assert.equal(f.memory.getUint16(520, true), 8);
  });

  check("poll output readiness, deadlines and pointer validation", () => {
    let now = 10_000_000n;
    const f = fixture({ clockNow: (id) => id <= 1 ? now : null });
    const waits = [];
    f.host.waitForChange = (_version, milliseconds) => {
      waits.push(milliseconds);
      now += BigInt(Math.ceil(milliseconds * 1_000_000));
    };
    f.subscription(0, 0, 5_000_000n);
    f.subscription(1, 0, 2_000_000n, 99n);
    assert.equal(f.poll(2), 0);
    assert.deepEqual(waits, [2]);
    assert.equal(f.memory.getBigUint64(512, true), 99n);
    assert.equal(f.memory.getUint32(768, true), 1);
    f.subscription(0, 0, now - 1n, 42n, 1);
    assert.equal(f.poll(), 0);
    assert.deepEqual(waits, [2]);
    f.subscription(0, 0, 1n, 42n, 2);
    assert.equal(f.poll(), 28);
    f.subscription(0, 0, 1n);
    f.memory.setUint32(16, 99, true);
    assert.equal(f.poll(), 0);
    assert.equal(f.memory.getUint16(520, true), 28);
    f.subscription(0, 9, 0);
    assert.equal(f.poll(), 28);
    assert.equal(f.poll(0), 28);
    assert.equal(f.poll(1025), 28);
    f.subscription(0, 1, 0);
    assert.equal(f.wasi.poll_oneoff(65535, 512, 1, 768), 21);
    assert.equal(f.wasi.poll_oneoff(0, 65535, 1, 768), 21);
    assert.equal(f.wasi.poll_oneoff(0, 512, 1, 65535), 21);
    assert.deepEqual(waits, [2]);
    f.write("x".repeat(24));
    f.subscription(0, 2, 1);
    f.host.waitForChange = (_version, delay) => {
      assert.equal(delay, Infinity);
      assert.equal(f.transport.readOutput().bytes.length, 24);
    };
    assert.equal(f.poll(), 0);
    assert.equal(f.memory.getBigUint64(528, true), 24n);
    f.transport.closeOutput();
    assert.equal(f.poll(), 0);
    assert.equal(f.memory.getUint16(520, true), 64);
    assert.equal(f.memory.getUint16(536, true), 1);
  });

  check("cancellation, run finalization and no UI-thread blocking", () => {
    const f = fixture();
    assert.throws(() => f.read(), { code: "interactive-worker-required" });
    const asynchronous = fixture({ waitForChange: async () => {} });
    assert.throws(() => asynchronous.read(), { code: "interactive-wait-invalid" });
    f.transport.cancel();
    assert.throws(() => f.read(), { code: "interactive-session-cancelled" });
    assert.throws(() => f.transport.writeInput(encode("x")), { code: "interactive-session-cancelled" });
    for (const code of [0, 1, 125]) {
      const g = fixture();
      const result = g.host.run({ exports: { memory: g.host.memory, _start: () => {
        g.write("bounded output", 2);
        g.wasi.proc_exit(code);
      } } });
      assert.equal(result.exitCode, code);
      assert.equal(result.ok, code === 0);
      assert.equal(result.output, "shared-queue");
      assert.equal(result.stdout, undefined);
      assert.equal(g.transport.status().inputClosed, true);
      assert.equal(g.transport.status().outputClosed, true);
      assert.equal(text(g.transport.readOutput().bytes), "bounded output");
    }
    for (const exports of [{}, { memory: f.host.memory }, { memory: f.host.memory, _start() { throw new Error("trap"); } }]) {
      const g = fixture();
      assert.throws(() => g.host.run({ exports }));
      assert.equal(g.transport.status().inputClosed, true);
      assert.equal(g.transport.status().outputClosed, true);
    }
  });
}

async function threadGuest() {
  if (workerData.mode === "entry") {
    // Exercise the actual browser entry module in a real Node Worker with only
    // its message surface adapted; the tiny module does not require blocking.
    globalThis.self = { postMessage: (message) => parentPort.postMessage(message), onmessage: null };
    await import("./interactive-linux-worker.mjs");
    parentPort.once("message", (data) => self.onmessage({ data }));
    parentPort.postMessage({ kind: "listening" });
    return;
  }
  const transport = new InteractiveLinuxTransport(workerData.transport);
  const f = fixture({ transport, waitForChange: (version, milliseconds) => {
    // This test adapter is only installed inside a real Node Worker thread.
    Atomics.wait(transport.control, 11, version, milliseconds);
  } });
  parentPort.postMessage({ kind: "ready" });
  try {
    if (workerData.mode === "echo") {
      assert.equal(f.read(), 0);
      const received = f.bytes.slice(1024, 1024 + f.count());
      // The second write must wait until the parent drains the first frame.
      assert.equal(f.write("x".repeat(24)), 0);
      assert.equal(f.write(received, 2), 0);
      parentPort.postMessage({ kind: "done", received: text(received) });
    } else {
      f.read();
      throw new Error("cancelled read unexpectedly returned");
    }
  } catch (error) {
    parentPort.postMessage({ kind: "error", code: error.code, message: error.message });
  } finally {
    transport.closeInput();
    transport.closeOutput();
  }
}

async function crossThreadTests() {
  for (const mode of ["echo", "cancel"]) {
    const transport = createInteractiveLinuxTransport({ stdinCapacity: 16, outputCapacity: 32 });
    const worker = new Worker(new URL(import.meta.url), { workerData: { mode, transport: transport.buffer } });
    const records = [];
    let timer, drain, enqueue;
    try {
      const result = await new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error("interactive host Worker exceeded 3000 ms")), 3000);
        worker.once("error", reject);
        worker.on("message", (message) => {
          if (message.kind === "ready") {
            // Delayed enqueue/cancel exercises an actual blocked Atomics.wait.
            enqueue = setTimeout(() => {
              if (mode === "echo") transport.writeInput(encode("thread input"));
              else transport.cancel();
            }, 20);
          } else resolve(message);
        });
        drain = setInterval(() => {
          const record = transport.readOutput();
          if (record) records.push({ fd: record.fd, text: text(record.bytes) });
        }, 10);
      });
      for (let record; (record = transport.readOutput()) !== null;) records.push({ fd: record.fd, text: text(record.bytes) });
      if (mode === "echo") {
        assert.deepEqual(result, { kind: "done", received: "thread input" });
        assert.deepEqual(records, [{ fd: 1, text: "x".repeat(24) }, { fd: 2, text: "thread input" }]);
      } else assert.equal(result.code, "interactive-session-cancelled");
    } finally {
      clearTimeout(timer);
      clearTimeout(enqueue);
      clearInterval(drain);
      transport.cancel();
      await worker.terminate();
    }
    checks += 1;
    console.log(`interactive stdio real Worker ${mode}: PASS`);
  }
}

async function entrypointTests() {
  // A real tiny Wasm module exporting one page of memory and an empty _start.
  // This verifies entrypoint lifecycle, not a Linux emulator or O evaluation.
  const name = (value) => [value.length, ...encode(value)];
  const exports = [2, ...name("memory"), 2, 0, ...name("_start"), 0, 0];
  const module = await WebAssembly.compile(new Uint8Array([
    0, 97, 115, 109, 1, 0, 0, 0,
    1, 4, 1, 96, 0, 0,
    3, 2, 1, 0,
    5, 3, 1, 0, 1,
    7, exports.length, ...exports,
    10, 4, 1, 2, 0, 11,
  ]));
  for (const options of [{}, { args: ["program.wasm", "interactive"] },
    { args: "invalid" }, { args: ["nul\0byte"] }, { args: Array(129).fill("x") },
    { env: { "bad=key": "value" } }, { env: { "": "value" } }, { env: { LONG: "x".repeat(4097) } }]) {
    const transport = createInteractiveLinuxTransport({ stdinCapacity: 16, outputCapacity: 32 });
    const worker = new Worker(new URL(import.meta.url), { workerData: { mode: "entry" } });
    let timer;
    const messages = [];
    try {
      const terminal = await new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error("interactive entrypoint exceeded 3000 ms")), 3000);
        worker.once("error", reject);
        worker.on("message", (message) => {
          if (message.kind === "listening") {
            worker.postMessage({ kind: "start", module, transport: transport.buffer, ...options });
            return;
          }
          messages.push(message);
          if (message.kind === "error" || message.kind === "result") resolve(message);
        });
      });
      const valid = messages[0]?.kind === "ready";
      assert.equal(valid, Object.keys(options).length === 0 || (Array.isArray(options.args) && options.args[1] === "interactive"));
      if (valid) {
        assert.equal(terminal.kind, "result");
        assert.equal(terminal.result.exitCode, 0);
        assert.equal(terminal.result.output, "shared-queue");
        assert.equal(messages.length, 2);
      } else {
        assert.equal(terminal.code, "interactive-options-invalid");
        assert.equal(messages.length, 1);
      }
      assert.equal(transport.status().inputClosed, true);
      assert.equal(transport.status().outputClosed, true);
    } finally {
      clearTimeout(timer);
      transport.cancel();
      await worker.terminate();
    }
    assert.equal(transport.status().inputClosed, true);
    assert.equal(transport.status().outputClosed, true);
  }
  checks += 1;
  console.log("interactive stdio actual entrypoint lifecycle/options: PASS");
}

if (!isMainThread) {
  await threadGuest();
} else {
  unitTests();
  await crossThreadTests();
  await entrypointTests();
  console.log(`Interactive Linux stdio contracts: ${checks} groups PASS (no Linux/Guix boot performed)`);
}
