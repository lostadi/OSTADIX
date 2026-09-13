// Explicit one-file disk capability; not a filesystem or an admitted profile.
// The caller verifies the disk's identity/initial asset, then acquires an EXISTING
// guix.img in a dedicated Worker before _start. This module never creates,
// formats, resizes, or replaces that disk. Only /browser-state/guix.img and a
// bounded, ephemeral guix.img.lock exist in the guest-facing namespace.
//
// Compose with WebAssembly.instantiate(module, disk.wrap(host)); host.attach/run
// still owns guest memory. Call disk.dispose() in the Worker's outer finally,
// AFTER the whole guest has stopped. Guest fd_close does not release the OPFS
// exclusive handle. The parent still owns cancellation and Worker termination.
// A write is acknowledged only after OPFS flush: pinned Bochs USB cache-flush
// commands are no-ops. A failed/partial disk write poisons further disk I/O;
// its data may already have changed and must not be presented as rolled back.
//
// OPFS contract: https://fs.spec.whatwg.org/#api-filesystemsyncaccesshandle
import { WasiHostError } from "./wasi-preview1-host.mjs";

export const BROWSER_DISK_PREOPEN = "/browser-state";
export const BROWSER_DISK_NAME = "guix.img";
export const BROWSER_DISK_LOCK_NAME = "guix.img.lock";
export const BROWSER_DISK_LIMITS = Object.freeze({ descriptors: 32, iovecs: 1024, ioBytes: 1048576, lockBytes: 64 });
const FIRST_FILE_FD = 16;
const E = Object.freeze({ ACCES: 2, BADF: 8, BUSY: 10, EXIST: 20, FAULT: 21, FBIG: 22,
  INVAL: 28, IO: 29, ISDIR: 31, MFILE: 33, NOENT: 44, NOSPC: 51, NOTDIR: 54,
  NOTSUP: 58, OVERFLOW: 61, NOTCAPABLE: 76 });
const R = Object.freeze({ READ: 1n << 1n, SEEK: 1n << 2n, FLAGS: 1n << 3n,
  TELL: 1n << 5n, WRITE: 1n << 6n, CREATE: 1n << 10n, OPEN: 1n << 13n,
  PATH_STAT: 1n << 18n, STAT: 1n << 21n, UNLINK: 1n << 26n });
export const BROWSER_DISK_FILE_RIGHTS = R.READ | R.SEEK | R.FLAGS | R.TELL | R.WRITE | R.STAT;
const DIRECTORY_RIGHTS = R.CREATE | R.OPEN | R.PATH_STAT | R.UNLINK | R.STAT;
const encode = new TextEncoder();
const decode = new TextDecoder("utf-8", { fatal: true });

class Errno extends Error { constructor(value) { super(String(value)); this.value = value; } }
function fail(value) { throw new Errno(value); }
function errorNumber(error) {
  if (error instanceof Errno) return error.value;
  return ({ NotAllowedError: E.ACCES, NoModificationAllowedError: E.BUSY,
    QuotaExceededError: E.NOSPC, NotFoundError: E.NOENT, InvalidStateError: E.BADF,
    TypeMismatchError: E.NOTDIR, NotSupportedError: E.NOTSUP, SecurityError: E.NOTCAPABLE })[error?.name] ?? E.IO;
}
function sizeContract(expectedBytes, maxBytes) {
  if (!Number.isSafeInteger(expectedBytes) || expectedBytes < 512 || expectedBytes % 512 !== 0
      || !Number.isSafeInteger(maxBytes) || maxBytes < expectedBytes) {
    throw new WasiHostError("browser-disk-size-invalid", "disk size must be an exact positive multiple of 512 bytes within its explicit safe-integer cap");
  }
}

// This async acquisition is never called from a synchronous WASI import.
// createSyncAccessHandle() uses the standard exclusive lock, not unsafe sharing.
export async function acquireBrowserDisk({ fileHandle, expectedBytes, maxBytes, preopenFd = 3 } = {}) {
  sizeContract(expectedBytes, maxBytes);
  if (typeof DedicatedWorkerGlobalScope === "undefined" || !(globalThis instanceof DedicatedWorkerGlobalScope)) {
    throw new WasiHostError("browser-disk-worker-required", "OPFS disk acquisition requires a dedicated Worker");
  }
  if (fileHandle?.kind !== "file" || fileHandle.name !== BROWSER_DISK_NAME
      || typeof fileHandle.createSyncAccessHandle !== "function") {
    throw new WasiHostError("browser-disk-handle-invalid", "provide the already selected guix.img file handle");
  }
  let accessHandle;
  try { accessHandle = await fileHandle.createSyncAccessHandle(); }
  catch (error) {
    throw new WasiHostError("browser-disk-acquire-failed", `cannot acquire exclusive disk handle (errno ${errorNumber(error)})`, error);
  }
  // Constructor adopts ownership, including closing on validation failure.
  return new BrowserDiskWasi({ accessHandle, expectedBytes, maxBytes, preopenFd });
}

export class BrowserDiskWasi {
  // The constructor is the deterministic-testing/embedding seam: accessHandle
  // must already be exclusively held. Production uses acquireBrowserDisk().
  constructor({ accessHandle, expectedBytes, maxBytes, preopenFd = 3 } = {}) {
    try {
      sizeContract(expectedBytes, maxBytes);
      // fd 3 is contiguous with stdio for wasi-libc/Bochs preopen enumeration.
      // Override only when the integrating host owns all earlier descriptors.
      if (!Number.isInteger(preopenFd) || preopenFd < 3 || preopenFd >= FIRST_FILE_FD) {
        throw new WasiHostError("browser-disk-fd-invalid", "disk preopen must be fd 3 through 15");
      }
      if (!["getSize", "read", "write", "flush", "close"].every((name) => typeof accessHandle?.[name] === "function")) {
        throw new WasiHostError("browser-disk-handle-invalid", "disk requires a held synchronous OPFS access handle");
      }
      if (accessHandle.getSize() !== expectedBytes) {
        throw new WasiHostError("browser-disk-size-mismatch", "existing disk size differs from the selected fixed-size contract; it was not resized");
      }
    } catch (error) {
      try { accessHandle?.close(); } catch { /* Preserve the validation error. */ }
      throw error;
    }
    this.access = accessHandle;
    this.size = expectedBytes;
    this.preopenFd = preopenFd;
    this.disposed = false;
    this.poisoned = false;
    this.directoryOpen = true;
    this.files = new Map();
    this.lock = null;
    this.nextInode = 3n;
  }

  owns(fd) { return fd === this.preopenFd || (fd >= FIRST_FILE_FD && fd < FIRST_FILE_FD + BROWSER_DISK_LIMITS.descriptors); }
  live() { if (this.disposed) fail(E.BADF); }
  directory(fd) {
    this.live();
    if (fd !== this.preopenFd || !this.directoryOpen) fail(E.BADF);
  }
  file(fd, rights = 0n) {
    this.live();
    if (fd === this.preopenFd && this.directoryOpen) fail(E.ISDIR);
    const entry = this.files.get(fd);
    if (!entry) fail(E.BADF);
    if ((entry.rights & rights) !== rights) fail(E.NOTCAPABLE);
    if (entry.kind === "disk" && this.poisoned) fail(E.IO);
    return entry;
  }
  view(pointer, length) {
    const start = Number(pointer) >>> 0;
    if (!(this.host?.memory instanceof WebAssembly.Memory) || !Number.isSafeInteger(length)
        || length < 0 || start + length > this.host.memory.buffer.byteLength) fail(E.FAULT);
    return new DataView(this.host.memory.buffer, start, length);
  }
  bytes(pointer, length) {
    const view = this.view(pointer, length);
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  path(pointer, length) {
    length >>>= 0;
    // Validate the complete guest range before rejecting the bounded path.
    const bytes = this.bytes(pointer, length);
    if (length > BROWSER_DISK_LOCK_NAME.length) fail(E.NOTCAPABLE);
    let path;
    try { path = decode.decode(bytes); } catch { fail(E.INVAL); }
    if (path !== BROWSER_DISK_NAME && path !== BROWSER_DISK_LOCK_NAME && path !== ".") fail(E.NOTCAPABLE);
    return path;
  }
  vectors(pointer, count, result) {
    count >>>= 0;
    if (count > BROWSER_DISK_LIMITS.iovecs) fail(E.INVAL);
    const table = this.view(pointer, count * 8);
    this.view(result, 4);
    const entries = [];
    let total = 0;
    for (let index = 0; index < count; index += 1) {
      const offset = table.getUint32(index * 8, true), length = table.getUint32(index * 8 + 4, true);
      this.view(offset, length);
      entries.push({ offset, length });
      total += length;
    }
    if (total > BROWSER_DISK_LIMITS.ioBytes) fail(E.INVAL);
    return { entries, total };
  }
  offset(value) {
    if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) fail(E.OVERFLOW);
    return Number(value);
  }
  length(entry) { return entry.kind === "disk" ? this.size : entry.inode.length; }
  flush() {
    const result = this.access.flush();
    if (result && typeof result.then === "function") fail(E.IO);
  }
  flags(value) {
    if ((value & ~31) !== 0) fail(E.INVAL);
    if ((value & ~4) !== 0) fail(E.NOTSUP); // Only NONBLOCK; regular-file I/O is synchronous.
  }
  allocate() {
    for (let fd = FIRST_FILE_FD; fd < FIRST_FILE_FD + BROWSER_DISK_LIMITS.descriptors; fd += 1) {
      if (!this.files.has(fd)) return fd;
    }
    fail(E.MFILE);
  }
  filestat(pointer, kind, size, inode = 1n) {
    const view = this.view(pointer, 64);
    new Uint8Array(view.buffer, view.byteOffset, 64).fill(0);
    view.setBigUint64(0, 1n, true);
    view.setBigUint64(8, inode, true);
    view.setUint8(16, kind === "directory" ? 3 : 4);
    view.setBigUint64(24, 1n, true);
    view.setBigUint64(32, BigInt(size), true);
  }

  open(fd, lookup, pointer, length, oflags, rights, inheriting, flags, result) {
    this.directory(fd);
    this.view(result, 4);
    const path = this.path(pointer, length);
    if ((lookup & ~1) !== 0 || (oflags & ~15) !== 0 || ((oflags & 4) && !(oflags & 1))) fail(E.INVAL);
    this.flags(flags);
    if (typeof rights !== "bigint" || typeof inheriting !== "bigint" || rights < 0n || inheriting < 0n
        || (rights & ~BROWSER_DISK_FILE_RIGHTS) || (inheriting & ~BROWSER_DISK_FILE_RIGHTS)) fail(E.NOTCAPABLE);
    if (path === ".") fail(E.NOTCAPABLE);
    if (oflags & 2) fail(E.NOTDIR);
    if (oflags & 8) fail(E.NOTCAPABLE); // Never truncate, including through open.
    if (path === BROWSER_DISK_NAME && (oflags & 1)) fail(E.NOTCAPABLE);
    if (path === BROWSER_DISK_NAME && this.poisoned) fail(E.IO);
    if (path === BROWSER_DISK_LOCK_NAME) {
      if (!this.lock && !(oflags & 1)) fail(E.NOENT);
      if (this.lock && (oflags & 4)) fail(E.EXIST);
    }
    const opened = this.allocate(); // Before even ephemeral namespace mutation.
    if (path === BROWSER_DISK_LOCK_NAME && !this.lock) {
      this.lock = { bytes: new Uint8Array(BROWSER_DISK_LIMITS.lockBytes), length: 0, number: this.nextInode++ };
    }
    const entry = { kind: path === BROWSER_DISK_NAME ? "disk" : "lock", inode: this.lock,
      position: 0, rights, inheriting, flags };
    this.files.set(opened, entry);
    this.view(result, 4).setUint32(0, opened, true);
    return 0;
  }

  io(fd, pointer, count, result, writing, explicitOffset) {
    const entry = this.file(fd, writing ? R.WRITE : R.READ);
    if (explicitOffset !== undefined && !(entry.rights & R.SEEK)) fail(E.NOTCAPABLE);
    const vectors = this.vectors(pointer, count, result);
    const position = explicitOffset === undefined ? entry.position : this.offset(explicitOffset);
    const limit = entry.kind === "disk" ? this.size : BROWSER_DISK_LIMITS.lockBytes;
    if (writing && vectors.total && BigInt(position) + BigInt(vectors.total) > BigInt(limit)) fail(E.FBIG);
    let transferred = 0;
    const maximum = writing ? vectors.total : Math.min(vectors.total, Math.max(0, this.length(entry) - position));
    try {
      for (const { offset, length } of vectors.entries) {
        const wanted = Math.min(length, maximum - transferred);
        if (!wanted) continue;
        const buffer = this.bytes(offset, wanted);
        let done;
        if (entry.kind === "disk") {
          done = this.access[writing ? "write" : "read"](buffer, { at: position + transferred });
          if (!Number.isSafeInteger(done) || done < 0 || done > wanted) fail(E.IO);
        } else {
          if (writing) entry.inode.bytes.set(buffer, position + transferred);
          else buffer.set(entry.inode.bytes.subarray(position + transferred, position + transferred + wanted));
          done = wanted;
        }
        transferred += done;
        if (done !== wanted) {
          if (writing) fail(E.IO);
          break;
        }
      }
      if (writing && transferred && entry.kind === "disk") this.flush();
    } catch (error) {
      if (writing && entry.kind === "disk") this.poisoned = true;
      throw error;
    }
    if (writing && transferred && entry.kind === "lock") entry.inode.length = Math.max(entry.inode.length, position + transferred);
    if (explicitOffset === undefined) entry.position = position + transferred;
    this.view(result, 4).setUint32(0, transferred, true);
    return 0;
  }

  wrap(host) {
    if (this.host && this.host !== host) throw new WasiHostError("browser-disk-host-invalid", "a disk adapter belongs to one guest host");
    const original = host?.imports?.wasi_snapshot_preview1;
    if (!original) throw new WasiHostError("browser-disk-host-invalid", "a WASI host namespace is required");
    this.host = host;
    const own = (operation) => (...args) => {
      try { return operation(...args); } catch (error) { return errorNumber(error); }
    };
    const fdCall = (name, operation) => (...args) => this.owns(args[0]) ? own(operation)(...args) : original[name](...args);
    const overrides = {
      path_open: fdCall("path_open", (...args) => this.open(...args)),
      fd_read: fdCall("fd_read", (fd, p, n, r) => this.io(fd, p, n, r, false)),
      fd_write: fdCall("fd_write", (fd, p, n, r) => this.io(fd, p, n, r, true)),
      fd_pread: fdCall("fd_pread", (fd, p, n, offset, r) => this.io(fd, p, n, r, false, offset)),
      fd_pwrite: fdCall("fd_pwrite", (fd, p, n, offset, r) => this.io(fd, p, n, r, true, offset)),
      fd_close: fdCall("fd_close", (fd) => {
        this.live();
        if (fd === this.preopenFd) { this.directory(fd); this.directoryOpen = false; }
        else { if (!this.files.has(fd)) fail(E.BADF); this.files.delete(fd); }
        return 0;
      }),
      fd_seek: fdCall("fd_seek", (fd, offset, whence, result) => {
        const entry = this.file(fd, R.SEEK);
        this.view(result, 8);
        if (typeof offset !== "bigint" || ![0, 1, 2].includes(whence)) fail(E.INVAL);
        const base = whence === 0 ? 0 : whence === 1 ? entry.position : this.length(entry);
        const position = BigInt(base) + offset;
        if (position < 0n) fail(E.INVAL);
        const next = this.offset(position);
        this.view(result, 8).setBigUint64(0, position, true);
        entry.position = next;
        return 0;
      }),
      fd_fdstat_get: fdCall("fd_fdstat_get", (fd, pointer) => {
        const entry = fd === this.preopenFd ? (this.directory(fd), null) : this.file(fd);
        const view = this.view(pointer, 24);
        new Uint8Array(view.buffer, view.byteOffset, 24).fill(0);
        view.setUint8(0, entry ? 4 : 3);
        view.setUint16(2, entry?.flags ?? 0, true);
        view.setBigUint64(8, entry?.rights ?? DIRECTORY_RIGHTS, true);
        view.setBigUint64(16, entry?.inheriting ?? BROWSER_DISK_FILE_RIGHTS, true);
        return 0;
      }),
      fd_fdstat_set_flags: fdCall("fd_fdstat_set_flags", (fd, flags) => {
        const entry = this.file(fd, R.FLAGS);
        this.flags(flags);
        entry.flags = flags;
        return 0;
      }),
      fd_filestat_get: fdCall("fd_filestat_get", (fd, pointer) => {
        if (fd === this.preopenFd) { this.directory(fd); this.filestat(pointer, "directory", 0); }
        else { const entry = this.file(fd, R.STAT); this.filestat(pointer, entry.kind, this.length(entry), entry.kind === "disk" ? 2n : entry.inode.number); }
        return 0;
      }),
      fd_filestat_set_size: fdCall("fd_filestat_set_size", (fd) => { this.file(fd); return E.NOTCAPABLE; }),
      fd_prestat_get: fdCall("fd_prestat_get", (fd, pointer) => {
        this.directory(fd);
        const view = this.view(pointer, 8);
        new Uint8Array(view.buffer, view.byteOffset, 8).fill(0);
        view.setUint32(4, encode.encode(BROWSER_DISK_PREOPEN).length, true);
        return 0;
      }),
      fd_prestat_dir_name: fdCall("fd_prestat_dir_name", (fd, pointer, length) => {
        this.directory(fd);
        const target = this.bytes(pointer, length >>> 0), name = encode.encode(BROWSER_DISK_PREOPEN);
        if (target.length < name.length) fail(E.INVAL);
        target.set(name);
        return 0;
      }),
      path_filestat_get: fdCall("path_filestat_get", (fd, lookup, pointer, length, result) => {
        this.directory(fd);
        this.view(result, 64);
        const path = this.path(pointer, length);
        if (lookup & ~1) fail(E.INVAL);
        if (path === BROWSER_DISK_LOCK_NAME && !this.lock) fail(E.NOENT);
        this.filestat(result, path === "." ? "directory" : "disk", path === "." ? 0 : path === BROWSER_DISK_NAME ? this.size : this.lock.length,
          path === "." ? 1n : path === BROWSER_DISK_NAME ? 2n : this.lock.number);
        return 0;
      }),
      path_unlink_file: fdCall("path_unlink_file", (fd, pointer, length) => {
        this.directory(fd);
        if (this.path(pointer, length) !== BROWSER_DISK_LOCK_NAME) fail(E.NOTCAPABLE);
        if (!this.lock) fail(E.NOENT);
        this.lock = null;
        return 0;
      }),
    };
    // All general filesystem operations remain denied. In particular a guest
    // cannot rename/delete the disk, make symlinks, or turn it into a directory.
    for (const name of ["fd_readdir", "path_create_directory", "path_filestat_set_times", "path_link", "path_readlink",
      "path_remove_directory", "path_rename", "path_symlink"]) {
      overrides[name] = (...args) => {
        const touchesDisk = name === "path_symlink" ? this.owns(args[2])
          : this.owns(args[0]) || (name === "path_link" && this.owns(args[4])) || (name === "path_rename" && this.owns(args[3]));
        return touchesDisk ? (this.disposed ? E.BADF : E.NOTCAPABLE) : original[name](...args);
      };
    }
    return Object.freeze({ wasi_snapshot_preview1: Object.freeze({ ...original, ...overrides }) });
  }

  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.directoryOpen = false;
    this.files.clear();
    this.lock = null;
    let failure;
    try { this.flush(); } catch (error) { failure = error; }
    try { this.access.close(); } catch (error) { failure ??= error; }
    if (failure) throw new WasiHostError("browser-disk-cleanup-failed", `disk flush/close failed (errno ${errorNumber(failure)})`, failure);
    if (this.poisoned) throw new WasiHostError("browser-disk-poisoned", "disk I/O previously failed; storage may be partially modified");
  }
}
