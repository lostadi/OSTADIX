import { GuixNetworkEndpoint } from "./guix-network-transport.mjs";

const E = Object.freeze({ AGAIN: 6, BADF: 8, INVAL: 28, ISDIR: 31, MFILE: 33, NOTCAPABLE: 76 });
const decoder = new TextDecoder("utf-8", { fatal: true });
const encoder = new TextEncoder();
const CERT_DIR = 4;
const LISTEN = 5;
const CONNECTION = 6;
const READ_RIGHTS = 2n | 4n | 32n | (1n << 21n) | (1n << 27n);
const DIR_RIGHTS = (1n << 13n) | (1n << 14n) | (1n << 18n) | (1n << 21n);

// Compose after the disk adapter. Only fd4..15 belong to this adapter; disk
// allocations start at16. The certificate is fresh, memory-only and read-only.
export function installGuixGuestNetwork(host, { network, certificate, transport }) {
  if (!(certificate instanceof Uint8Array) || !certificate.length || certificate.length > 16384
      || !decoder.decode(certificate).startsWith("-----BEGIN CERTIFICATE-----")) {
    throw new Error("invalid browser proxy certificate");
  }
  const cert = certificate.slice();
  const endpoint = network instanceof GuixNetworkEndpoint ? network
    : new GuixNetworkEndpoint(network, "guest", { wake: () => transport.wake() });
  const descriptors = new Map([[CERT_DIR, { directory: true, position: 0 }]]);
  let listening = true;
  let connected = false;
  const original = host.imports.wasi_snapshot_preview1;
  const owned = (fd) => fd >= CERT_DIR && fd < 16;
  const guard = (fn) => (...args) => host.guard(() => fn(...args));
  const get = (fd) => descriptors.get(fd);
  function view(pointer, length) { return host.view(pointer, length); }
  function path(pointer, length) {
    if (length > 4096) return null;
    const text = decoder.decode(new Uint8Array(view(pointer, length).buffer, pointer >>> 0, length));
    return text === "." || text === "./" || text === "" ? "." : text === "proxy.crt" || text === "./proxy.crt" ? "proxy.crt" : null;
  }
  function vectors(pointer, count, result) {
    if ((count >>> 0) > 1024) throw new RangeError("too many network iovecs");
    view(result, 4);
    const data = view(pointer, count * 8);
    const output = [];
    for (let i = 0; i < count; i++) {
      const address = data.getUint32(i * 8, true);
      const length = data.getUint32(i * 8 + 4, true);
      view(address, length);
      output.push({ address, length });
    }
    return output;
  }
  function stat(pointer, directory) {
    const data = view(pointer, 64);
    new Uint8Array(data.buffer, data.byteOffset, 64).fill(0);
    data.setUint8(16, directory ? 3 : 4);
    data.setBigUint64(24, 1n, true);
    data.setBigUint64(32, BigInt(directory ? 0 : cert.length), true);
    return 0;
  }
  function read(fd, pointer, count, result, position) {
    if (!get(fd)) return E.BADF;
    if (get(fd).directory) return E.ISDIR;
    const iovs = vectors(pointer, count, result);
    if (position < 0n || position > BigInt(Number.MAX_SAFE_INTEGER)) return E.INVAL;
    let offset = Number(position);
    let total = 0;
    for (const iov of iovs) {
      const length = Math.min(iov.length, Math.max(0, cert.length - offset));
      new Uint8Array(host.memory.buffer, iov.address, length).set(cert.subarray(offset, offset + length));
      offset += length;
      total += length;
    }
    view(result, 4).setUint32(0, total, true);
    return { offset, total };
  }
  const override = {
    fd_prestat_get: guard((fd, pointer) => {
      if (fd === CERT_DIR && get(fd)) {
        const value = view(pointer, 8);
        value.setUint32(0, 0, true);
        value.setUint32(4, 14, true); // /browser-proxy
        return 0;
      }
      if (fd === LISTEN || fd === CONNECTION) {
        // The pinned wasi-vfs/Bochs discovery skips non-directory sentinels.
        // Keep its fd enumeration contiguous through the reserved sockets.
        const value = view(pointer, 8);
        value.setUint32(0, 1, true);
        value.setUint32(4, 0, true);
        return 0;
      }
      return owned(fd) ? E.BADF : original.fd_prestat_get(fd, pointer);
    }),
    fd_prestat_dir_name: guard((fd, pointer, length) => {
      if (fd !== CERT_DIR) return owned(fd) ? E.BADF : original.fd_prestat_dir_name(fd, pointer, length);
      if (!get(fd) || length < 14) return E.INVAL;
      new Uint8Array(view(pointer, 14).buffer, pointer >>> 0, 14).set(encoder.encode("/browser-proxy"));
      return 0;
    }),
    fd_fdstat_get: guard((fd, pointer) => {
      if (!owned(fd)) return original.fd_fdstat_get(fd, pointer);
      const item = get(fd);
      if (!item && !(fd === LISTEN && listening) && !(fd === CONNECTION && connected)) return E.BADF;
      const value = view(pointer, 24);
      new Uint8Array(value.buffer, value.byteOffset, 24).fill(0);
      value.setUint8(0, item ? item.directory ? 3 : 4 : 6);
      value.setUint16(2, item ? 0 : 4, true);
      value.setBigUint64(8, item ? item.directory ? DIR_RIGHTS : READ_RIGHTS : READ_RIGHTS | 64n | 8n | (1n << 29n), true);
      value.setBigUint64(16, item?.directory ? DIR_RIGHTS | READ_RIGHTS : 0n, true);
      return 0;
    }),
    fd_fdstat_set_flags: (fd, flags) => {
      if (!owned(fd)) return original.fd_fdstat_set_flags(fd, flags);
      return get(fd) ? flags === 0 ? 0 : E.NOTCAPABLE
        : (fd === LISTEN && listening) || (fd === CONNECTION && connected) ? flags === 0 || flags === 4 ? 0 : E.INVAL : E.BADF;
    },
    fd_filestat_get: guard((fd, pointer) => !owned(fd) ? original.fd_filestat_get(fd, pointer)
      : get(fd) ? stat(pointer, get(fd).directory) : E.BADF),
    fd_close: (fd) => {
      if (!owned(fd)) return original.fd_close(fd);
      if (descriptors.delete(fd)) return 0;
      if (fd === LISTEN && listening) { listening = false; return 0; }
      if (fd === CONNECTION && connected) { connected = false; endpoint.cancel(); return 0; }
      return E.BADF;
    },
    path_open: guard((fd, flags, pointer, length, oflags, base, inherited, fdflags, result) => {
      if (!owned(fd)) return original.path_open(fd, flags, pointer, length, oflags, base, inherited, fdflags, result);
      if (!get(fd)?.directory) return E.BADF;
      const name = path(pointer, length);
      if (!name || (flags & ~1) || (oflags & ~2) || fdflags || (base & ~(DIR_RIGHTS | READ_RIGHTS))
          || (inherited & ~(DIR_RIGHTS | READ_RIGHTS))) return E.NOTCAPABLE;
      if ((oflags & 2) && name !== ".") return E.INVAL;
      view(result, 4);
      const free = Array.from({ length: 9 }, (_, i) => i + 7).find((candidate) => !descriptors.has(candidate));
      if (free === undefined) return E.MFILE;
      descriptors.set(free, { directory: name === ".", position: 0 });
      view(result, 4).setUint32(0, free, true);
      return 0;
    }),
    path_filestat_get: guard((fd, flags, pointer, length, result) => {
      if (!owned(fd)) return original.path_filestat_get(fd, flags, pointer, length, result);
      if (!get(fd)?.directory) return E.BADF;
      const name = path(pointer, length);
      return !name || (flags & ~1) ? E.NOTCAPABLE : stat(result, name === ".");
    }),
    fd_read: guard((fd, pointer, count, result) => {
      if (fd === CONNECTION) return override.sock_recv(fd, pointer, count, 0, result, 0);
      if (!owned(fd)) return original.fd_read(fd, pointer, count, result);
      const answer = read(fd, pointer, count, result, BigInt(get(fd)?.position ?? 0));
      if (typeof answer === "number") return answer;
      get(fd).position = answer.offset;
      return 0;
    }),
    fd_pread: guard((fd, pointer, count, offset, result) => {
      if (!owned(fd)) return original.fd_pread(fd, pointer, count, offset, result);
      const answer = read(fd, pointer, count, result, offset);
      return typeof answer === "number" ? answer : 0;
    }),
    fd_seek: guard((fd, offset, whence, result) => {
      if (!owned(fd)) return original.fd_seek(fd, offset, whence, result);
      const item = get(fd);
      if (!item || item.directory) return E.BADF;
      const position = offset + (whence === 0 ? 0n : whence === 1 ? BigInt(item.position) : whence === 2 ? BigInt(cert.length) : -1n);
      if (whence > 2 || position < 0 || position > BigInt(Number.MAX_SAFE_INTEGER)) return E.INVAL;
      view(result, 8).setBigUint64(0, position, true);
      item.position = Number(position);
      return 0;
    }),
    fd_readdir: guard((fd, pointer, length, cookie, result) => {
      if (!owned(fd)) return original.fd_readdir(fd, pointer, length, cookie, result);
      if (!get(fd)?.directory) return E.BADF;
      view(pointer, length); view(result, 4);
      if (cookie < 0n) return E.INVAL;
      const output = new Uint8Array(cookie === 0n ? 33 : 0);
      if (output.length) {
        const data = new DataView(output.buffer);
        data.setBigUint64(0, 1n, true); data.setBigUint64(8, 1n, true);
        data.setUint32(16, 9, true); data.setUint8(20, 4);
        output.set(encoder.encode("proxy.crt"), 24);
      }
      const size = Math.min(length, output.length);
      new Uint8Array(host.memory.buffer, pointer >>> 0, size).set(output.subarray(0, size));
      view(result, 4).setUint32(0, size, true);
      return 0;
    }),
    sock_accept: guard((fd, flags, result) => {
      if (fd !== LISTEN || !listening) return E.BADF;
      if (flags & ~4) return E.INVAL;
      if (connected) return E.AGAIN;
      endpoint.checkCancelled(); view(result, 4).setUint32(0, CONNECTION, true);
      connected = true;
      return 0;
    }),
    sock_send: guard((fd, pointer, count, flags, result) => {
      if (fd !== CONNECTION || !connected) return E.BADF;
      if (flags) return E.INVAL;
      const iovs = vectors(pointer, count, result);
      const total = iovs.reduce((sum, item) => sum + item.length, 0);
      if (total > 16388) return E.INVAL;
      const bytes = new Uint8Array(total);
      let offset = 0;
      for (const item of iovs) { bytes.set(new Uint8Array(host.memory.buffer, item.address, item.length), offset); offset += item.length; }
      endpoint.send(bytes);
      view(result, 4).setUint32(0, total, true);
      return 0;
    }),
    sock_recv: guard((fd, pointer, count, flags, result, outputFlags) => {
      if (fd !== CONNECTION || !connected) return E.BADF;
      if (flags) return E.INVAL;
      const iovs = vectors(pointer, count, result);
      if (outputFlags) view(outputFlags, 2);
      let total = 0;
      for (const item of iovs) {
        const bytes = endpoint.receive(Math.min(item.length, endpoint.capacity));
        new Uint8Array(host.memory.buffer, item.address, bytes.length).set(bytes);
        total += bytes.length;
        if (bytes.length < item.length) break;
      }
      view(result, 4).setUint32(0, total, true);
      if (outputFlags) view(outputFlags, 2).setUint16(0, 0, true);
      return !total && iovs.some((item) => item.length) ? E.AGAIN : 0;
    }),
  };
  for (const name of ["fd_write", "fd_pwrite", "fd_filestat_set_size", "path_create_directory",
    "path_filestat_set_times", "path_readlink", "path_remove_directory", "path_unlink_file"]) {
    override[name] = (fd, ...args) => owned(fd) ? E.NOTCAPABLE : original[name](fd, ...args);
  }
  for (const [name, destination] of [["path_link", 4], ["path_rename", 3]]) {
    override[name] = (...args) => owned(args[0]) || owned(args[destination]) ? E.NOTCAPABLE : original[name](...args);
  }
  override.path_symlink = (...args) => owned(args[2]) ? E.NOTCAPABLE : original.path_symlink(...args);
  host.imports = Object.freeze({ wasi_snapshot_preview1: Object.freeze({ ...original, ...override }) });
  const previousPoll = host.additionalPollReadiness;
  host.additionalPollReadiness = (fd, type) => {
    if (!owned(fd)) return previousPoll?.(fd, type) ?? null;
    if (fd === CONNECTION && connected) return { ready: type === 2 || endpoint.readable(), error: 0, nbytes: 0, hangup: false };
    if (fd === LISTEN && listening) return { ready: type === 1 && !connected, error: 0, nbytes: 0, hangup: false };
    return { ready: true, error: get(fd) ? type === 1 ? 0 : E.NOTCAPABLE : E.BADF, nbytes: 0, hangup: false };
  };
  return { endpoint, dispose: () => { cert.fill(0); descriptors.clear(); endpoint.cancel(); } };
}
