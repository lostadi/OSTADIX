// Deterministic one-file host contracts, not a browser/Guix qualification.
import assert from "node:assert/strict";
import { LinuxWasiPreview1Host, LINUX_WASI_PREVIEW1_IMPORTS } from "./linux-wasi-host.mjs";
import { acquireBrowserDisk, BrowserDiskWasi, BROWSER_DISK_PREOPEN, BROWSER_DISK_FILE_RIGHTS } from "./browser-disk-wasi.mjs";

const encoder = new TextEncoder(), decoder = new TextDecoder();
const READ = 1n << 1n, SEEK = 1n << 2n, FLAGS = 1n << 3n, WRITE = 1n << 6n, STAT = 1n << 21n;
function mockHandle(size = 512) {
  return {
    data: Uint8Array.from({ length: size }, (_, index) => index % 251), calls: [], closed: false,
    faults: {}, shortWrite: undefined, shortRead: undefined,
    getSize() { this.calls.push(["size"]); return this.data.length; },
    read(buffer, { at }) {
      this.calls.push(["read", at, buffer.length]);
      if (this.faults.read) throw this.faults.read;
      const length = Math.min(buffer.length, Math.max(0, this.data.length - at), this.shortRead ?? Infinity);
      buffer.set(this.data.subarray(at, at + length));
      return length;
    },
    write(buffer, { at }) {
      this.calls.push(["write", at, buffer.length]);
      if (this.faults.write) throw this.faults.write;
      const length = Math.min(buffer.length, this.shortWrite ?? Infinity);
      this.data.set(buffer.subarray(0, length), at);
      return length;
    },
    flush() { this.calls.push(["flush"]); this.onFlush?.(); if (this.faults.flush) throw this.faults.flush; },
    close() { this.calls.push(["close"]); this.closed = true; if (this.faults.close) throw this.faults.close; },
  };
}
function fixture(options = {}) {
  const access = options.access ?? mockHandle();
  const disk = new BrowserDiskWasi({ accessHandle: access, expectedBytes: 512, maxBytes: 1024, ...options });
  const host = new LinuxWasiPreview1Host();
  host.attach(new WebAssembly.Memory({ initial: 2 }));
  const memory = new DataView(host.memory.buffer), bytes = new Uint8Array(host.memory.buffer);
  const wasi = disk.wrap(host).wasi_snapshot_preview1;
  const path = (value) => { const data = encoder.encode(value); bytes.set(data, 128); return data.length; };
  const open = (name = "guix.img", rights = BROWSER_DISK_FILE_RIGHTS, oflags = 0, flags = 0) => {
    const result = wasi.path_open(disk.preopenFd, 1, 128, path(name), oflags, rights, BROWSER_DISK_FILE_RIGHTS, flags, 256);
    return { result, fd: memory.getUint32(256, true) };
  };
  const vectors = (entries) => entries.forEach(([offset, length], index) => {
    memory.setUint32(index * 8, offset, true);
    memory.setUint32(index * 8 + 4, length, true);
  });
  const count = () => memory.getUint32(256, true);
  return { access, disk, host, memory, bytes, wasi, path, open, vectors, count };
}
let groups = 0;
function check(name, operation) { operation(); groups += 1; console.log(`browser disk ${name}: PASS`); }

function unitTests() {
  check("one-file capability ABI and contiguous fd", () => {
    const f = fixture();
    assert.equal(f.disk.preopenFd, 3);
    assert.deepEqual(Object.keys(f.wasi), [...LINUX_WASI_PREVIEW1_IMPORTS]);
    assert.equal(f.wasi.fd_prestat_get(3, 512), 0);
    assert.equal(f.memory.getUint32(512, true), 0);
    assert.equal(f.memory.getUint32(516, true), BROWSER_DISK_PREOPEN.length);
    assert.equal(f.wasi.fd_prestat_dir_name(3, 512, 64), 0);
    assert.equal(decoder.decode(f.bytes.subarray(512, 512 + BROWSER_DISK_PREOPEN.length)), BROWSER_DISK_PREOPEN);
    assert.equal(f.wasi.fd_prestat_dir_name(3, 512, 1), 28);
    assert.equal(f.wasi.fd_prestat_get(4, 512), 8);
    assert.equal(f.wasi.fd_fdstat_get(3, 512), 0);
    assert.equal(f.memory.getUint8(512), 3);
    assert.equal(f.memory.getBigUint64(528, true), BROWSER_DISK_FILE_RIGHTS);
    assert.equal(f.wasi.path_create_directory(3, 0, 0), 76);
    assert.equal(f.wasi.sock_accept(4, 0, 0), 8);
    assert.equal(f.wasi.path_rename(0, 0, 0, 3, 0, 0), 76);
    assert.equal(f.wasi.path_link(0, 0, 0, 0, 3, 0, 0), 76);
    assert.equal(f.wasi.path_symlink(0, 0, 3, 0, 0), 76);
    // Unowned stdio still belongs to the original host.
    f.bytes.set(encoder.encode("ok"), 1024); f.vectors([[1024, 2]]);
    assert.equal(f.wasi.fd_write(1, 0, 1, 256), 0);
    assert.equal(f.host.stdout, "ok");
    f.disk.dispose();
    const alternative = fixture({ preopenFd: 4 });
    assert.equal(alternative.wasi.fd_prestat_get(4, 512), 0);
    assert.equal(alternative.wasi.fd_prestat_get(3, 512), 8); // Caller must fill this gap; no invented authority.
    alternative.disk.dispose();
  });

  check("namespace confinement and no disk overwrite", () => {
    const f = fixture();
    const original = f.access.data.slice();
    for (const name of ["", "/guix.img", "../guix.img", "./guix.img", "guix.img/", "guix.img\0", "guix.img.lock/x", "other", "guix\\img"]) {
      assert.equal(f.open(name).result, 76, name);
    }
    for (const flags of [1, 8, 9]) assert.equal(f.open("guix.img", BROWSER_DISK_FILE_RIGHTS, flags).result, 76);
    assert.equal(f.open("guix.img", BROWSER_DISK_FILE_RIGHTS, 2).result, 54);
    assert.equal(f.open("guix.img", BROWSER_DISK_FILE_RIGHTS, 4).result, 28);
    assert.equal(f.open("guix.img", BROWSER_DISK_FILE_RIGHTS, 16).result, 28);
    assert.equal(f.open(".").result, 76);
    assert.equal(f.wasi.path_unlink_file(3, 128, f.path("guix.img")), 76);
    assert.equal(f.wasi.path_filestat_get(3, 1, 128, f.path("."), 512), 0);
    assert.equal(f.memory.getUint8(528), 3);
    assert.equal(f.wasi.path_filestat_get(3, 1, 128, f.path("guix.img"), 512), 0);
    assert.equal(f.memory.getBigUint64(544, true), 512n);
    assert.equal(f.wasi.path_filestat_get(3, 2, 128, f.path("guix.img"), 512), 28);
    assert.deepEqual(f.access.data, original);
    assert.deepEqual(f.access.calls, [["size"]]);
    f.disk.dispose();
  });

  check("rights, flags and bounded descriptors", () => {
    const f = fixture();
    const reader = f.open("guix.img", READ | SEEK | STAT | FLAGS);
    assert.equal(reader.result, 0);
    assert.equal(reader.fd, 16);
    f.vectors([[1024, 4]]);
    assert.equal(f.wasi.fd_write(reader.fd, 0, 1, 256), 76);
    assert.equal(f.wasi.fd_fdstat_set_flags(reader.fd, 4), 0);
    assert.equal(f.wasi.fd_fdstat_get(reader.fd, 512), 0);
    assert.equal(f.memory.getUint16(514, true), 4);
    assert.equal(f.wasi.fd_fdstat_set_flags(reader.fd, 1), 58);
    assert.equal(f.wasi.fd_fdstat_set_flags(reader.fd, 32), 28);
    assert.equal(f.wasi.fd_filestat_set_size(reader.fd, 0n), 76);
    const writer = f.open("guix.img", WRITE | SEEK);
    assert.equal(f.wasi.fd_read(writer.fd, 0, 1, 256), 76);
    assert.equal(f.wasi.fd_filestat_get(writer.fd, 512), 76);
    assert.equal(f.wasi.fd_fdstat_set_flags(writer.fd, 0), 76);
    assert.equal(f.open("guix.img", 1n << 63n).result, 76);
    assert.equal(f.open("guix.img", -1n).result, 76);
    while (f.disk.files.size < 32) assert.equal(f.open().result, 0);
    assert.equal(f.open().result, 33);
    assert.equal(f.open("guix.img.lock", READ, 1).result, 33);
    assert.equal(f.disk.lock, null);
    assert.equal(f.wasi.fd_close(reader.fd), 0);
    assert.equal(f.wasi.fd_close(reader.fd), 8);
    assert.equal(f.open().fd, reader.fd);
    assert.equal(f.wasi.fd_close(3), 0);
    assert.equal(f.wasi.fd_prestat_get(3, 512), 8);
    assert.equal(f.open().result, 8);
    assert.equal(f.access.closed, false);
    f.disk.dispose();
  });

  check("seek, positional I/O, EOF and flush-before-ack", () => {
    const f = fixture(), fd = f.open().fd;
    f.vectors([[1024, 3], [2048, 5]]);
    assert.equal(f.wasi.fd_read(fd, 0, 2, 256), 0);
    assert.equal(f.count(), 8);
    assert.deepEqual([...f.bytes.subarray(1024, 1027)], [0, 1, 2]);
    assert.deepEqual([...f.bytes.subarray(2048, 2053)], [3, 4, 5, 6, 7]);
    assert.equal(f.wasi.fd_seek(fd, -2n, 1, 512), 0);
    assert.equal(f.memory.getBigUint64(512, true), 6n);
    f.vectors([[1024, 4]]);
    assert.equal(f.wasi.fd_pread(fd, 0, 1, 100n, 256), 0);
    assert.equal(f.disk.files.get(fd).position, 6);
    assert.deepEqual([...f.bytes.subarray(1024, 1028)], [100, 101, 102, 103]);
    f.bytes.set([9, 8, 7, 6], 1024);
    f.memory.setUint32(256, 999, true);
    f.access.onFlush = () => assert.equal(f.count(), 999);
    assert.equal(f.wasi.fd_pwrite(fd, 0, 1, 508n, 256), 0);
    assert.equal(f.count(), 4);
    assert.deepEqual([...f.access.data.subarray(508)], [9, 8, 7, 6]);
    assert.deepEqual(f.access.calls.slice(-2), [["write", 508, 4], ["flush"]]);
    assert.equal(f.disk.files.get(fd).position, 6);
    f.access.onFlush = null;
    assert.equal(f.wasi.fd_seek(fd, -2n, 2, 512), 0);
    assert.equal(f.wasi.fd_read(fd, 0, 1, 256), 0);
    assert.equal(f.count(), 2);
    assert.equal(f.wasi.fd_read(fd, 0, 1, 256), 0);
    assert.equal(f.count(), 0);
    assert.equal(f.wasi.fd_seek(fd, 1024n, 0, 512), 0);
    assert.equal(f.wasi.fd_read(fd, 0, 1, 256), 0);
    assert.equal(f.count(), 0);
    assert.equal(f.wasi.fd_write(fd, 0, 1, 256), 22);
    assert.equal(f.wasi.fd_seek(fd, -1n, 0, 512), 28);
    assert.equal(f.wasi.fd_seek(fd, 0n, 3, 512), 28);
    assert.equal(f.wasi.fd_seek(fd, 1n << 60n, 0, 512), 61);
    assert.equal(f.wasi.fd_pread(fd, 0, 1, -1n, 256), 61);
    assert.equal(f.wasi.fd_pwrite(fd, 0, 1, 1n << 60n, 256), 61);
    assert.equal(f.disk.files.get(fd).position, 1024);
    assert.equal(f.access.data.length, 512);
    f.disk.dispose();
  });

  check("all pointers validated before storage effects", () => {
    for (const writing of [false, true]) {
      const f = fixture(), fd = f.open().fd;
      const original = f.access.data.slice(), before = f.access.calls.length;
      f.memory.setUint32(256, 999, true);
      f.bytes.fill(0x77, 1024, 1032);
      for (const entries of [[[131071, 2]], [[1024, 2], [131071, 2]], [[0xffffffff, 4]]]) {
        f.vectors(entries);
        assert.equal(f.wasi[writing ? "fd_write" : "fd_read"](fd, 0, entries.length, 256), 21);
        assert.equal(f.count(), 999);
        assert.equal(f.disk.files.get(fd).position, 0);
        assert.deepEqual([...f.bytes.subarray(1024, 1032)], Array(8).fill(0x77));
      }
      f.vectors([[1024, 4]]);
      for (const [table, result] of [[131071, 256], [0, 131071]]) {
        assert.equal(f.wasi[writing ? "fd_write" : "fd_read"](fd, table, 1, result), 21);
      }
      assert.equal(f.wasi[writing ? "fd_write" : "fd_read"](fd, 0, 1025, 256), 28);
      assert.equal(f.wasi[writing ? "fd_write" : "fd_read"](fd, 0, -1, 256), 28);
      f.vectors(Array.from({ length: 1024 }, () => [16384, 2048]));
      assert.equal(f.wasi[writing ? "fd_write" : "fd_read"](fd, 0, 1024, 12000), 28);
      assert.equal(f.access.calls.length, before);
      assert.deepEqual(f.access.data, original);
      assert.equal(f.disk.poisoned, false);
      assert.equal(f.wasi.fd_seek(fd, 4n, 0, 131071), 21);
      assert.equal(f.disk.files.get(fd).position, 0);
      f.disk.dispose();
    }
    const f = fixture();
    const length = f.path("guix.img.lock");
    assert.equal(f.wasi.path_open(3, 0, 128, length, 1, READ, 0n, 0, 131071), 21);
    assert.equal(f.disk.files.size, 0);
    assert.equal(f.disk.lock, null);
    assert.equal(f.wasi.path_open(3, 0, 131071, 2, 1, READ, 0n, 0, 256), 21);
    assert.equal(f.wasi.path_filestat_get(3, 0, 128, length, 131071), 21);
    f.open("guix.img.lock", READ, 1);
    assert.equal(f.wasi.path_unlink_file(3, 131071, 2), 21);
    assert.ok(f.disk.lock);
    f.disk.dispose();
  });

  check("bounded ephemeral lock lifecycle", () => {
    const f = fixture();
    assert.equal(f.open("guix.img.lock").result, 44);
    const lock = f.open("guix.img.lock", BROWSER_DISK_FILE_RIGHTS, 5);
    assert.equal(lock.result, 0);
    assert.equal(f.open("guix.img.lock", READ, 5).result, 20);
    f.bytes.set([1, 2, 3], 1024); f.vectors([[1024, 3]]);
    assert.equal(f.wasi.fd_write(lock.fd, 0, 1, 256), 0);
    assert.equal(f.wasi.fd_filestat_get(lock.fd, 512), 0);
    assert.equal(f.memory.getBigUint64(544, true), 3n);
    assert.equal(f.wasi.fd_pread(lock.fd, 0, 1, 0n, 256), 0);
    assert.deepEqual([...f.bytes.subarray(1024, 1027)], [1, 2, 3]);
    assert.equal(f.wasi.fd_pwrite(lock.fd, 0, 1, 63n, 256), 22);
    assert.equal(f.wasi.fd_seek(lock.fd, 999n, 0, 512), 0);
    assert.equal(f.wasi.fd_write(lock.fd, 0, 0, 256), 0);
    assert.equal(f.disk.lock.length, 3); // zero-byte writes never grow the lock.
    assert.equal(f.wasi.path_unlink_file(3, 128, f.path("guix.img.lock")), 0);
    assert.equal(f.open("guix.img.lock").result, 44);
    const replacement = f.open("guix.img.lock", READ, 5);
    assert.equal(replacement.result, 0);
    assert.equal(f.disk.files.get(replacement.fd).inode.length, 0);
    assert.equal(f.disk.files.get(lock.fd).inode.length, 3); // existing fd retains its unlinked inode.
    assert.deepEqual(f.access.calls, [["size"]]);
    assert.equal(f.wasi.fd_close(lock.fd), 0);
    assert.equal(f.access.closed, false);
    f.disk.dispose();
    assert.equal(f.disk.lock, null);
  });

  check("disk errors poison writes without a success acknowledgement", () => {
    for (const [stage, name, expected] of [["write", "QuotaExceededError", 51], ["flush", "QuotaExceededError", 51],
      ["flush", "UnknownError", 29], ["write", "NotAllowedError", 2], ["write", "InvalidStateError", 8]]) {
      const f = fixture(), fd = f.open().fd;
      f.access.faults[stage] = new DOMException("injected failure", name);
      f.bytes.fill(0x44, 1024, 1028); f.vectors([[1024, 4]]);
      f.memory.setUint32(256, 999, true);
      assert.equal(f.wasi.fd_write(fd, 0, 1, 256), expected);
      assert.equal(f.count(), 999);
      assert.equal(f.disk.files.get(fd).position, 0);
      assert.equal(f.disk.poisoned, true);
      assert.equal(f.wasi.fd_read(fd, 0, 1, 256), 29);
      assert.equal(f.wasi.fd_close(fd), 0); // Guest close never drops ownership.
      assert.equal(f.access.closed, false);
      f.access.faults = {};
      assert.throws(() => f.disk.dispose(), { code: "browser-disk-poisoned" });
      assert.equal(f.access.closed, true);
    }
    const f = fixture(), fd = f.open().fd;
    f.access.shortWrite = 2;
    f.bytes.fill(0x22, 1024, 1028); f.vectors([[1024, 4]]);
    f.memory.setUint32(256, 999, true);
    assert.equal(f.wasi.fd_write(fd, 0, 1, 256), 29);
    assert.equal(f.count(), 999);
    assert.deepEqual([...f.access.data.subarray(0, 4)], [0x22, 0x22, 2, 3]); // no false rollback claim.
    assert.throws(() => f.disk.dispose(), { code: "browser-disk-poisoned" });
  });

  check("read errors, short reads and idempotent exclusive cleanup", () => {
    const f = fixture(), fd = f.open().fd;
    f.vectors([[1024, 4]]); f.memory.setUint32(256, 999, true);
    f.access.faults.read = new DOMException("read failed", "NotAllowedError");
    assert.equal(f.wasi.fd_read(fd, 0, 1, 256), 2);
    assert.equal(f.count(), 999);
    assert.equal(f.disk.files.get(fd).position, 0);
    f.access.faults = {}; f.access.shortRead = 2;
    assert.equal(f.wasi.fd_read(fd, 0, 1, 256), 0);
    assert.equal(f.count(), 2);
    assert.equal(f.wasi.fd_close(fd), 0);
    assert.equal(f.access.closed, false);
    f.disk.dispose(); f.disk.dispose();
    assert.equal(f.access.calls.filter(([name]) => name === "close").length, 1);
    assert.equal(f.wasi.fd_prestat_get(3, 0), 8);
    assert.equal(f.open().result, 8);
    const g = fixture();
    g.access.faults.flush = new Error("flush failed");
    g.access.faults.close = new Error("close failed");
    assert.throws(() => g.disk.dispose(), { code: "browser-disk-cleanup-failed" });
    assert.equal(g.access.closed, true);
    g.disk.dispose();
    assert.equal(g.access.calls.filter(([name]) => name === "close").length, 1);
  });
}

async function acquisitionTests() {
  const file = (handle) => ({ kind: "file", name: "guix.img", async createSyncAccessHandle() { return handle; } });
  await assert.rejects(acquireBrowserDisk({ fileHandle: file(mockHandle()), expectedBytes: 512, maxBytes: 1024 }),
    { code: "browser-disk-worker-required" });
  // Only the browser-global type check is substituted; no actual OPFS/browser
  // access occurs in this deterministic unit test.
  const previous = globalThis.DedicatedWorkerGlobalScope;
  globalThis.DedicatedWorkerGlobalScope = class { static [Symbol.hasInstance]() { return true; } };
  try {
    let opens = 0;
    const handle = mockHandle();
    const input = file(handle);
    input.createSyncAccessHandle = async () => { opens += 1; return handle; };
    for (const [expectedBytes, maxBytes] of [[0, 1024], [513, 1024], [512, 511], [512, Infinity]]) {
      await assert.rejects(acquireBrowserDisk({ fileHandle: input, expectedBytes, maxBytes }), { code: "browser-disk-size-invalid" });
    }
    assert.equal(opens, 0);
    const disk = await acquireBrowserDisk({ fileHandle: input, expectedBytes: 512, maxBytes: 1024 });
    assert.equal(opens, 1);
    assert.equal(handle.closed, false);
    disk.dispose();
    for (const expectedBytes of [1024, 1536]) {
      const wrong = mockHandle();
      await assert.rejects(acquireBrowserDisk({ fileHandle: file(wrong), expectedBytes, maxBytes: 2048 }),
        { code: "browser-disk-size-mismatch" });
      assert.equal(wrong.closed, true);
      assert.deepEqual(wrong.calls, [["size"], ["close"]]);
    }
    const invalidFd = mockHandle();
    await assert.rejects(acquireBrowserDisk({ fileHandle: file(invalidFd), expectedBytes: 512, maxBytes: 1024, preopenFd: 16 }),
      { code: "browser-disk-fd-invalid" });
    assert.equal(invalidFd.closed, true);
    await assert.rejects(acquireBrowserDisk({ fileHandle: { ...file(mockHandle()), name: "other" }, expectedBytes: 512, maxBytes: 1024 }),
      { code: "browser-disk-handle-invalid" });
    const busy = { ...file(mockHandle()), async createSyncAccessHandle() { throw new DOMException("already locked", "NoModificationAllowedError"); } };
    await assert.rejects(acquireBrowserDisk({ fileHandle: busy, expectedBytes: 512, maxBytes: 1024 }),
      (error) => error.code === "browser-disk-acquire-failed" && /errno 10/.test(error.message));
  } finally {
    if (previous === undefined) delete globalThis.DedicatedWorkerGlobalScope;
    else globalThis.DedicatedWorkerGlobalScope = previous;
  }
  groups += 1;
  console.log("browser disk exclusive acquisition validation/cleanup: PASS");
}

unitTests();
await acquisitionTests();
console.log(`Browser disk WASI contracts: ${groups} groups PASS (mock OPFS; no Guix/browser integration claimed)`);
