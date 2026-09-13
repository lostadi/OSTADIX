// Browser-only substitute access. This policy is a capability, not a generic
// HTTP proxy. The integrating runner must admit and bind this exact policy.
export const GUIX_MIRROR_FETCH_POLICY = Object.freeze({
  id: "ostadix.guix-mirror-fetch/v1",
  origin: "https://mirror.yandex.ru",
  prefix: "/mirrors/guix/",
  methods: Object.freeze(["GET", "HEAD"]),
  maxActive: 8,
  maxMetadataBytes: 65536,
  maxArchiveBytes: 536870912,
  maxSessionBytes: 2147483648,
  maxRequests: 8192,
  requestTimeoutMs: 600000,
  maxChunkBytes: 1048576,
  replyBytes: 4096,
});

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const HASH = "[0123456789abcdfghijklmnpqrsvwxyz]{32}";
const META = new RegExp(`^(?:nix-cache-info|${HASH}\\.narinfo)$`);
const ARCHIVE = new RegExp(`^nar/(?:lzip|gzip|zstd|none)/${HASH}-[A-Za-z0-9+._-]{1,240}$`);
const EMPTY = new Uint8Array();

function fail(message) { throw new Error(`Guix mirror access denied: ${message}`); }
function bytes(value, limit) {
  if (!(value instanceof Uint8Array) || value.byteLength > limit) fail("invalid request bytes");
  return value;
}

function admit(address, request) {
  const spelling = decoder.decode(bytes(address, 2048));
  // Reject encodings and normalization ambiguities before URL parsing.
  if (/[\\%\s]/.test(spelling)) fail("noncanonical URL");
  const url = new URL(spelling);
  if (url.origin !== GUIX_MIRROR_FETCH_POLICY.origin || url.username || url.password
      || url.search || url.hash || !url.pathname.startsWith(GUIX_MIRROR_FETCH_POLICY.prefix)
      || url.href !== spelling) fail("URL is outside the admitted mirror");
  const path = url.pathname.slice(GUIX_MIRROR_FETCH_POLICY.prefix.length);
  const metadata = META.test(path);
  if (!metadata && !ARCHIVE.test(path)) fail("path is not a substitute object");
  const spec = JSON.parse(decoder.decode(bytes(request, 16384)));
  if (!spec || typeof spec !== "object" || Array.isArray(spec)
      || Object.keys(spec).some((key) => key !== "method" && key !== "headers")
      || !GUIX_MIRROR_FETCH_POLICY.methods.includes(spec.method)) fail("only GET/HEAD are admitted");
  if (spec.headers !== undefined && (!spec.headers || typeof spec.headers !== "object" || Array.isArray(spec.headers))) {
    fail("invalid headers");
  }
  for (const [name, value] of Object.entries(spec.headers ?? {})) {
    if (typeof value !== "string" || name.length > 128 || value.length > 4096
        || /[\r\n\0]/.test(name + value)) fail("invalid header");
    // Full-object downloads only. Content-Range is not CORS-exposed by this
    // mirror, so this version does not pretend to validate range responses.
    if (["range", "if-range", "authorization", "proxy-authorization", "cookie"].includes(name.toLowerCase())) {
      fail("credentials and partial downloads are not admitted");
    }
  }
  // Guest headers are deliberately not forwarded: no custom-header preflight,
  // authority changes, credentials, compression negotiation or cache validators.
  return { url: url.href, method: spec.method, metadata };
}

export class GuixMirrorFetchBroker {
  constructor({ signal, fetchImpl = globalThis.fetch, onError = () => {} } = {}) {
    if (typeof fetchImpl !== "function") fail("Fetch is unavailable");
    this.fetchImpl = fetchImpl;
    this.onError = onError;
    this.connections = new Map();
    this.nextId = 0;
    this.totalBytes = 0;
    this.closed = false;
    this.signal = signal;
    this.abort = () => this.dispose("session cancelled");
    signal?.addEventListener("abort", this.abort, { once: true });
    if (signal?.aborted) this.dispose("session already cancelled");
  }

  connection(id) {
    if (this.closed || !Number.isSafeInteger(id) || !this.connections.has(id)) fail("unknown or closed request");
    return this.connections.get(id);
  }

  release(conn, reason) {
    clearTimeout(conn.timer);
    conn.controller.abort(reason);
    const reader = conn.reader;
    conn.reader = null;
    if (reader) Promise.resolve(reader.cancel(reason)).catch(() => {});
    conn.pending = EMPTY;
    conn.header = EMPTY;
    conn.buffered = EMPTY;
    this.connections.delete(conn.id);
  }

  broken(conn, error) {
    if (!this.connections.has(conn.id)) return;
    this.release(conn, error);
    try { this.onError(String(error?.message ?? error).slice(0, 1024)); } catch {}
  }

  count(conn, value) {
    bytes(value, GUIX_MIRROR_FETCH_POLICY.maxChunkBytes);
    const maximum = conn.metadata ? GUIX_MIRROR_FETCH_POLICY.maxMetadataBytes : GUIX_MIRROR_FETCH_POLICY.maxArchiveBytes;
    if (conn.received + value.length > maximum
        || this.totalBytes + value.length > GUIX_MIRROR_FETCH_POLICY.maxSessionBytes) fail("download byte budget exceeded");
    conn.received += value.length;
    this.totalBytes += value.length;
  }

  async start(conn) {
    try {
      const response = await this.fetchImpl(conn.url, {
        method: conn.method, mode: "cors", credentials: "omit", redirect: "error",
        referrerPolicy: "no-referrer", cache: "no-store", signal: conn.controller.signal,
      });
      if (!this.connections.has(conn.id)) { await response.body?.cancel(); return; }
      if (response.type !== "cors" || response.redirected || response.url !== conn.url
          || !Number.isInteger(response.status) || response.status < 200 || response.status > 599
          || (response.status >= 300 && response.status < 400) || response.status === 206) {
        await response.body?.cancel();
        fail("unexpected response origin, redirect or partial response");
      }
      // Fetch transparently decodes HTTP Content-Encoding (not NAR compression).
      // Never forward encoded Content-Length/Encoding or hop-by-hop framing.
      // Metadata is small: buffer under its strict cap and synthesize the true
      // length, supporting Guix's pipelined narinfo parser. NARs stay streaming;
      // the Go HTTP server selects correct chunked/connection framing itself.
      const headers = {};
      for (const name of ["content-type", "cache-control", "last-modified", "expires"]) {
        const value = response.headers.get(name);
        if (value !== null && value.length <= 4096) headers[name] = value;
      }
      if (conn.method === "HEAD") {
        await response.body?.cancel();
        conn.done = true;
      } else if (response.body) {
        conn.reader = response.body.getReader();
        if (conn.metadata) {
          const chunks = [];
          for (;;) {
            const item = await conn.reader.read();
            if (!this.connections.has(conn.id)) return;
            if (item.done) break;
            this.count(conn, item.value);
            chunks.push(item.value.slice());
          }
          conn.reader.releaseLock();
          conn.reader = null;
          conn.buffered = new Uint8Array(conn.received);
          let offset = 0;
          for (const chunk of chunks) { conn.buffered.set(chunk, offset); offset += chunk.length; }
          conn.done = true;
          headers["content-length"] = String(conn.received);
        }
      } else {
        conn.done = true;
        if (conn.method !== "HEAD") headers["content-length"] = "0";
      }
      conn.header = encoder.encode(JSON.stringify({ status: response.status,
        statusText: String(response.statusText).slice(0, 256), headers }));
      if (conn.header.length > 16384) fail("response headers exceeded budget");
      conn.ready = true;
    } catch (error) { this.broken(conn, error); }
  }

  async handle(message) {
    let conn;
    try {
      if (this.closed || !message || typeof message !== "object") fail("session is closed");
      if (message.type === "http_send") {
        const spec = admit(message.address, message.req);
        if (this.connections.size >= GUIX_MIRROR_FETCH_POLICY.maxActive
            || this.nextId >= GUIX_MIRROR_FETCH_POLICY.maxRequests) fail("request budget exceeded");
        const id = this.nextId++;
        conn = { ...spec, id, controller: new AbortController(), ready: false, started: false,
          received: 0, header: EMPTY, pending: EMPTY, buffered: EMPTY, done: false, reader: null, reading: false };
        this.connections.set(id, conn);
        conn.timer = setTimeout(() => this.broken(conn, new Error("mirror request deadline exceeded")),
          GUIX_MIRROR_FETCH_POLICY.requestTimeoutMs);
        return { status: id, data: EMPTY };
      }
      conn = this.connection(message.id);
      if (message.type === "http_writebody") {
        if (bytes(message.body, 0).length || (message.isEOF !== 0 && message.isEOF !== 1) || conn.started) {
          fail("request bodies or repeated sends are not admitted");
        }
        if (message.isEOF === 1) { conn.started = true; void this.start(conn); }
        return { status: 0, data: EMPTY };
      }
      if (message.type === "http_isreadable") {
        return { status: 0, data: Uint8Array.of(conn.ready ? 1 : 0) };
      }
      if (!conn.ready || !Number.isSafeInteger(message.len) || message.len < 1
          || message.len > GUIX_MIRROR_FETCH_POLICY.replyBytes) fail("invalid response read");
      if (message.type === "http_recv") {
        const data = conn.header.slice(0, message.len);
        conn.header = conn.header.slice(data.length);
        return { status: conn.header.length ? 0 : 1, data };
      }
      if (message.type !== "http_readbody" || conn.header.length || conn.reading) fail("invalid body read order");
      conn.reading = true;
      try {
        if (conn.metadata) {
          const data = conn.buffered.slice(0, message.len);
          conn.buffered = conn.buffered.slice(data.length);
          const eof = conn.buffered.length === 0;
          if (eof) this.release(conn, "complete");
          return { status: eof ? 1 : 0, data };
        }
        while (!conn.pending.length && !conn.done) {
          const item = await conn.reader.read();
          if (!this.connections.has(conn.id)) fail("request cancelled while reading");
          if (item.done) {
            conn.done = true;
            conn.reader.releaseLock();
            conn.reader = null;
          } else {
            this.count(conn, item.value);
            conn.pending = item.value;
          }
        }
        const data = conn.pending.slice(0, message.len);
        conn.pending = conn.pending.subarray(data.length);
        const eof = conn.done && !conn.pending.length;
        if (eof) this.release(conn, "complete");
        return { status: eof ? 1 : 0, data };
      } finally { conn.reading = false; }
    } catch (error) {
      if (conn) this.broken(conn, error);
      return { status: -1, data: EMPTY };
    }
  }

  dispose(reason = "session closed") {
    if (this.closed) return;
    this.closed = true;
    this.signal?.removeEventListener("abort", this.abort);
    for (const conn of this.connections.values()) this.release(conn, reason);
  }
}
