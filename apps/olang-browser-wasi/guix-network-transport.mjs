// Bounded in-browser byte streams for c2w's QEMU Ethernet protocol. No host
// sockets are opened. A frame is uint32 big-endian length + Ethernet bytes.
const HEADER = 64;
const MAGIC = 0x4f474e54;
const MAX_FRAME = 16384;
const I = Object.freeze({ MAGIC: 0, VERSION: 1, CAPACITY: 2, CANCEL: 3, WAKE: 4,
  GREAD: 5, GWRITE: 6, PREAD: 7, PWRITE: 8 });

export function createGuixNetworkTransport({ capacity = 262144 } = {}) {
  if (!Number.isInteger(capacity) || capacity < 32768 || capacity > 1048576 || (capacity & (capacity - 1))) {
    throw new Error("network queue must be a power of two between 32768 and 1048576");
  }
  const buffer = new SharedArrayBuffer(HEADER + 2 * capacity);
  const control = new Int32Array(buffer, 0, HEADER / 4);
  control[I.MAGIC] = MAGIC;
  control[I.VERSION] = 1;
  control[I.CAPACITY] = capacity;
  return buffer;
}

export class GuixNetworkEndpoint {
  constructor(buffer, side, { wake = () => {} } = {}) {
    if (!(buffer instanceof SharedArrayBuffer) || buffer.byteLength < HEADER || !["guest", "proxy"].includes(side)) {
      throw new Error("invalid network shared transport");
    }
    this.buffer = buffer;
    this.control = new Int32Array(buffer, 0, HEADER / 4);
    this.capacity = this.control[I.CAPACITY];
    if (this.control[I.MAGIC] !== MAGIC || this.control[I.VERSION] !== 1
        || this.capacity < 32768 || this.capacity > 1048576 || (this.capacity & (this.capacity - 1))
        || buffer.byteLength !== HEADER + 2 * this.capacity) throw new Error("invalid network shared header");
    this.side = side;
    this.notifyCommon = wake;
    this.guest = new Uint8Array(buffer, HEADER, this.capacity);
    this.proxy = new Uint8Array(buffer, HEADER + this.capacity, this.capacity);
    this.frameRemaining = 0;
  }
  checkCancelled() { if (Atomics.load(this.control, I.CANCEL)) throw new Error("network session cancelled"); }
  wakeVersion() { return Atomics.load(this.control, I.WAKE); }
  wake() { Atomics.add(this.control, I.WAKE, 1); Atomics.notify(this.control, I.WAKE); this.notifyCommon(); }
  cancel() { Atomics.store(this.control, I.CANCEL, 1); this.wake(); }
  waitForChange(version, milliseconds) { this.checkCancelled(); Atomics.wait(this.control, I.WAKE, version, milliseconds); this.checkCancelled(); }
  state(outgoing) {
    this.checkCancelled();
    const guest = (this.side === "guest") === outgoing;
    const ri = guest ? I.GREAD : I.PREAD;
    const wi = guest ? I.GWRITE : I.PWRITE;
    const read = Atomics.load(this.control, ri) >>> 0;
    const write = Atomics.load(this.control, wi) >>> 0;
    const used = (write - read) >>> 0;
    if (used > this.capacity) { this.cancel(); throw new Error("corrupt network queue indices"); }
    return { ri, wi, read, write, used, ring: guest ? this.guest : this.proxy };
  }
  copyOut(state, length) {
    const output = new Uint8Array(length);
    const offset = state.read % this.capacity;
    const first = Math.min(length, this.capacity - offset);
    output.set(state.ring.subarray(offset, offset + first));
    output.set(state.ring.subarray(0, length - first), first);
    return output;
  }
  readable() {
    const state = this.state(false);
    return this.side !== "guest" || this.frameRemaining ? state.used > 0 : state.used >= 4;
  }
  send(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length > this.capacity) throw new Error("invalid network write");
    if (this.side === "guest" && bytes.length) {
      if (bytes.length < 18 || bytes.length > MAX_FRAME + 4
          || new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false) !== bytes.length - 4) {
        this.cancel(); throw new Error("invalid complete guest Ethernet frame");
      }
    }
    const state = this.state(true);
    // Pinned Bochs ignores short send() results. Never report a short write or
    // silently drop a suffix. A full queue terminates the bounded session.
    if (bytes.length > this.capacity - state.used) { this.cancel(); throw new Error("network queue budget exceeded"); }
    const offset = state.write % this.capacity;
    const first = Math.min(bytes.length, this.capacity - offset);
    state.ring.set(bytes.subarray(0, first), offset);
    state.ring.set(bytes.subarray(first), 0);
    Atomics.store(this.control, state.wi, (state.write + bytes.length) | 0);
    this.wake();
    return bytes.length;
  }
  receive(maxLength) {
    if (!Number.isInteger(maxLength) || maxLength < 0 || maxLength > this.capacity) throw new Error("invalid network read bound");
    const state = this.state(false);
    let length = Math.min(maxLength, state.used);
    if (this.side === "guest") {
      if (this.frameRemaining === 0) {
        // Pinned Bochs has incorrect pointer arithmetic on a fragmented header.
        // Withhold an incomplete 4-byte header; never expose a partial one.
        if (length < 4) return new Uint8Array();
        length = 4;
        const size = new DataView(this.copyOut(state, 4).buffer).getUint32(0, false);
        if (size < 14 || size > MAX_FRAME) { this.cancel(); throw new Error("invalid proxy Ethernet frame length"); }
        this.frameRemaining = size;
      } else {
        length = Math.min(length, this.frameRemaining);
        this.frameRemaining -= length;
      }
    }
    const output = this.copyOut(state, length);
    Atomics.store(this.control, state.ri, (state.read + length) | 0);
    if (length) this.wake();
    return output;
  }
}
