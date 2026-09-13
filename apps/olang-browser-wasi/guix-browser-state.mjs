// Origin-private, profile-bound Guix disk lifecycle. This is deliberately not a
// general filesystem, a formatter for existing disks, or a recovery utility.
// The caller authenticates the immutable profile and sparse-disk manifest before
// calling this module in a dedicated Worker. Each chunk digest is checked again
// here before that chunk is written. Only a fresh directory may be provisioned.
//
// A separate, flushed dirty marker protects even a failed metadata flush. It is
// removed ONLY by awaited markClean()/complete(), after the caller has observed
// the trusted guest-exit tag AND disk.dispose() has successfully flushed/closed.
// A trap, cancellation, Worker termination, or interrupted initialization leaves
// the marker in place. close() never makes a session clean. No automatic reset,
// repair, reformat, migration, storage helper, or directory export is performed.
//
// The exclusive session.lock access handle is held for the entire lifecycle,
// including the gap between provisioning and the guest's own disk acquisition.
// Browser storage may still be evicted or cleared; persistence permission and
// quota reporting belong to the calling UI, not to a claim of durable hardware.
// OPFS contract: https://fs.spec.whatwg.org/#api-filesystemsyncaccesshandle
import { WasiHostError } from "./wasi-preview1-host.mjs";
import { BROWSER_DISK_NAME } from "./browser-disk-wasi.mjs";

export const GUIX_STATE_SCHEMA = "ostadix.guix-state/v1";
export const GUIX_STATE_BYTES = 2147483648;
export const GUIX_SPARSE_DISK_SCHEMA = "ostadix.sparse-disk/v1";
const NAMESPACE = "ostadix-guix-state-v1";
const METADATA = "metadata.json";
const METADATA_SCHEMA = "ostadix.guix-state-metadata/v1";
const SESSION_LOCK = "session.lock";
const DIRTY = "dirty";
const MAX_METADATA_BYTES = 16384;
const MAX_CHUNK_BYTES = 1048576;
const MAX_CHUNKS = 4096;
const MAX_INITIAL_BYTES = 64 * 1048576;
const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const IMAGE = /^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}$/;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function invalid(message) {
  throw new WasiHostError("guix-state-contract-invalid", message);
}

function recovery(message, cause) {
  return new WasiHostError("guix-state-recovery-required",
    `${message}; existing state was not erased or reformatted. Recovery/export or an explicitly confirmed reset is required`, cause);
}

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function checkedProfile(value) {
  if (!exactKeys(value, ["schema", "uuid", "bytes", "runtime_image", "layout"])
      || value.schema !== GUIX_STATE_SCHEMA || typeof value.uuid !== "string" || !UUID.test(value.uuid)
      || value.bytes !== GUIX_STATE_BYTES || value.layout !== 1
      || typeof value.runtime_image !== "string" || value.runtime_image.length > 512
      || !IMAGE.test(value.runtime_image)) {
    invalid("expected the exact v1 Guix state profile with a UUID, 2 GiB disk, layout 1, and digest-pinned runtime image");
  }
  // Fixed field order is the namespace identity; never hash caller key order.
  return Object.freeze({ schema: GUIX_STATE_SCHEMA, uuid: value.uuid,
    bytes: value.bytes, runtime_image: value.runtime_image, layout: value.layout });
}

function checkedSparseDisk(value, profile) {
  if (!exactKeys(value, ["schema", "bytes", "block_bytes", "chunks"])
      || value.schema !== GUIX_SPARSE_DISK_SCHEMA || value.bytes !== profile.bytes
      || value.block_bytes !== 4096 || !Array.isArray(value.chunks)
      || value.chunks.length > MAX_CHUNKS) {
    invalid("initialDisk must be the verified sparse-disk/v1 manifest for this exact disk size");
  }
  let end = 0, total = 0;
  const paths = new Set();
  const chunks = value.chunks.map((record) => {
    if (!exactKeys(record, ["offset", "bytes", "sha256", "path"])
        || !Number.isSafeInteger(record.offset) || record.offset < end || record.offset % 4096 !== 0
        || !Number.isSafeInteger(record.bytes) || record.bytes <= 0 || record.bytes % 4096 !== 0
        || record.bytes > MAX_CHUNK_BYTES || record.offset + record.bytes > profile.bytes
        || typeof record.sha256 !== "string" || !HASH.test(record.sha256)
        || typeof record.path !== "string" || record.path.length > 256
        || !/^[A-Za-z0-9_-][A-Za-z0-9._/-]*$/.test(record.path)
        || record.path.split("/").some((part) => !part || part === "." || part === "..")
        || paths.has(record.path)) {
      invalid("sparse chunks must be sorted, nonoverlapping, 4 KiB aligned, bounded, hash-addressed relative files");
    }
    end = record.offset + record.bytes;
    total += record.bytes;
    if (total > MAX_INITIAL_BYTES) invalid("sparse initial disk exceeds the 64 MiB materialization limit");
    paths.add(record.path);
    return Object.freeze({ offset: record.offset, bytes: record.bytes,
      sha256: record.sha256, path: record.path });
  });
  return Object.freeze({ schema: GUIX_SPARSE_DISK_SCHEMA, bytes: profile.bytes,
    block_bytes: 4096, chunks: Object.freeze(chunks) });
}

async function sha256(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function optionalFile(directory, name) {
  try { return await directory.getFileHandle(name, { create: false }); }
  catch (error) {
    if (error?.name === "NotFoundError") return null;
    throw error;
  }
}

function synchronous(result, operation) {
  if (result && typeof result.then === "function") {
    throw new WasiHostError("guix-state-storage-invalid", `${operation} must be synchronous`);
  }
  return result;
}

function writeAll(handle, bytes, at) {
  const written = synchronous(handle.write(bytes, { at }), "OPFS write");
  if (written !== bytes.byteLength) {
    throw new WasiHostError("guix-state-write-failed", "OPFS returned a short write; the state remains dirty");
  }
}

function flush(handle) { synchronous(handle.flush(), "OPFS flush"); }
function closeHandle(handle) { synchronous(handle.close(), "OPFS close"); }

function metadataRecord(profile, profileDigest, initialDigest, phase, clean) {
  return { schema: METADATA_SCHEMA, profile, profile_sha256: profileDigest,
    initial_disk_sha256: initialDigest, phase, clean };
}

function writeMetadata(handle, record) {
  const bytes = encoder.encode(JSON.stringify(record));
  if (bytes.byteLength > MAX_METADATA_BYTES) invalid("state metadata exceeds its bound");
  // The separately flushed dirty marker already exists before this mutation.
  synchronous(handle.truncate(0), "OPFS truncate");
  writeAll(handle, bytes, 0);
  flush(handle);
}

function readMetadata(handle, profile, profileDigest) {
  const size = synchronous(handle.getSize(), "OPFS getSize");
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_METADATA_BYTES) {
    throw recovery("state metadata is missing, truncated, or outside its size bound");
  }
  const bytes = new Uint8Array(size);
  if (synchronous(handle.read(bytes, { at: 0 }), "OPFS read") !== size) {
    throw recovery("state metadata could not be read completely");
  }
  let record;
  try { record = JSON.parse(decoder.decode(bytes)); }
  catch (error) { throw recovery("state metadata is malformed", error); }
  if (!exactKeys(record, ["schema", "profile", "profile_sha256", "initial_disk_sha256", "phase", "clean"])
      || record.schema !== METADATA_SCHEMA || record.profile_sha256 !== profileDigest
      || record.phase !== "ready" || record.clean !== true
      || typeof record.initial_disk_sha256 !== "string" || !HASH.test(record.initial_disk_sha256)) {
    throw recovery("state metadata does not describe a completed clean session");
  }
  let savedProfile;
  try { savedProfile = checkedProfile(record.profile); }
  catch (error) { throw recovery("state metadata has an invalid profile", error); }
  if (JSON.stringify(savedProfile) !== JSON.stringify(profile)) {
    throw recovery("the stored profile differs from the verified runtime profile");
  }
  return record;
}

async function createDirtyMarker(directory) {
  const file = await directory.getFileHandle(DIRTY, { create: true });
  const access = await file.createSyncAccessHandle();
  try { writeAll(access, new Uint8Array([1]), 0); flush(access); }
  finally { closeHandle(access); }
}

/**
 * Open a single profile-bound session. initialDisk is a previously verified
 * sparse manifest. fetchChunk(record) must fetch only the verified bundle asset;
 * sparseChunks optionally supplies already fetched bytes keyed by record.path.
 * Provisioning retains only one copied chunk (at most 1 MiB) at a time.
 *
 * The returned fileHandle is selected but NOT held open: acquireBrowserDisk()
 * takes its exclusive disk access handle before guest execution. session.lock
 * remains held here throughout. Await markClean() ONLY after a tagged orderly
 * guest exit and successful disk.dispose(); await close() in the outer finally.
 */
export async function openGuixBrowserState({ profile: suppliedProfile, initialDisk,
  sparseChunks, fetchChunk } = {}) {
  const profile = checkedProfile(suppliedProfile);
  const sparse = checkedSparseDisk(initialDisk, profile);
  if (sparseChunks !== undefined && !(sparseChunks instanceof Map)) invalid("sparseChunks must be a Map keyed by manifest path");
  if (fetchChunk !== undefined && typeof fetchChunk !== "function") invalid("fetchChunk must be a function");
  if (typeof DedicatedWorkerGlobalScope === "undefined" || !(globalThis instanceof DedicatedWorkerGlobalScope)
      || typeof globalThis.navigator?.storage?.getDirectory !== "function") {
    throw new WasiHostError("guix-state-worker-required", "Guix state provisioning requires OPFS in a dedicated Worker");
  }
  const profileDigest = await sha256(encoder.encode(JSON.stringify(profile)));
  const initialDigest = await sha256(encoder.encode(JSON.stringify(sparse)));
  const root = await navigator.storage.getDirectory();
  const namespace = await root.getDirectoryHandle(NAMESPACE, { create: true });
  const directory = await namespace.getDirectoryHandle(profileDigest, { create: true });
  const lockFile = await directory.getFileHandle(SESSION_LOCK, { create: true });
  let sessionLock;
  try { sessionLock = await lockFile.createSyncAccessHandle(); }
  catch (error) {
    if (error?.name === "NoModificationAllowedError") {
      throw new WasiHostError("guix-state-busy", "this Guix state is already held by another browser session", error);
    }
    throw new WasiHostError("guix-state-lock-failed", "could not acquire the exclusive Guix session lock", error);
  }

  let metadataAccess, diskAccess;
  try {
    // Bound enumeration as well as permitted names. A profile directory is not
    // repurposed when unrelated or half-created entries are discovered.
    const expected = new Set([SESSION_LOCK, METADATA, DIRTY, BROWSER_DISK_NAME]);
    let count = 0;
    for await (const [name, handle] of directory.entries()) {
      if (++count > expected.size || !expected.has(name) || handle.kind !== "file") {
        throw recovery("the profile directory contains an unexpected entry");
      }
    }
    const dirtyFile = await optionalFile(directory, DIRTY);
    if (dirtyFile) throw recovery("a previous session or initialization did not finish cleanly");
    let fileHandle = await optionalFile(directory, BROWSER_DISK_NAME);
    let metadataFile = await optionalFile(directory, METADATA);
    if (Boolean(fileHandle) !== Boolean(metadataFile)) {
      throw recovery("the disk and its metadata are not a complete pair");
    }

    let originalInitialDigest = initialDigest;
    if (!fileHandle) {
      // Check asset availability before creating an initialization marker. Do
      // not fetch or buffer all chunks; only check the configured source here.
      if (typeof fetchChunk !== "function" && sparse.chunks.some((record) => !sparseChunks?.has(record.path))) {
        invalid("fresh provisioning requires a byte source for every sparse chunk");
      }
      await createDirtyMarker(directory);
      metadataFile = await directory.getFileHandle(METADATA, { create: true });
      metadataAccess = await metadataFile.createSyncAccessHandle();
      writeMetadata(metadataAccess, metadataRecord(profile, profileDigest, initialDigest, "initializing", false));
      fileHandle = await directory.getFileHandle(BROWSER_DISK_NAME, { create: true });
      diskAccess = await fileHandle.createSyncAccessHandle();
      // Fresh-only allocation is zero-filled by the OPFS truncate contract. No
      // buffer proportional to disk size, fetch-all, or existing-disk resize.
      synchronous(diskAccess.truncate(profile.bytes), "OPFS truncate");
      if (synchronous(diskAccess.getSize(), "OPFS getSize") !== profile.bytes) {
        throw recovery("fresh disk allocation did not produce the exact declared size");
      }
      for (const record of sparse.chunks) {
        const supplied = sparseChunks?.has(record.path) ? sparseChunks.get(record.path) : await fetchChunk(record);
        if (!(supplied instanceof Uint8Array) || supplied.byteLength !== record.bytes) {
          throw recovery(`initial disk chunk ${record.path} has the wrong byte count`);
        }
        // Own the bytes across digest's await; caller mutation cannot race the
        // subsequent disk write after a successful hash check.
        const bytes = new Uint8Array(supplied);
        if (await sha256(bytes) !== record.sha256) throw recovery(`initial disk chunk ${record.path} failed its SHA-256 check`);
        writeAll(diskAccess, bytes, record.offset);
      }
      flush(diskAccess);
      closeHandle(diskAccess);
      diskAccess = undefined;
    } else {
      metadataAccess = await metadataFile.createSyncAccessHandle();
      const saved = readMetadata(metadataAccess, profile, profileDigest);
      originalInitialDigest = saved.initial_disk_sha256;
      // Existing disks are never seeded again. Their original seed digest is
      // provenance; the exact runtime profile, not a rebuilt seed's timestamps,
      // is the compatibility boundary for reusing persistent state.
      diskAccess = await fileHandle.createSyncAccessHandle();
      if (synchronous(diskAccess.getSize(), "OPFS getSize") !== profile.bytes) {
        throw recovery("the existing disk size differs from the declared fixed-size profile");
      }
      closeHandle(diskAccess);
      diskAccess = undefined;
      await createDirtyMarker(directory);
    }
    writeMetadata(metadataAccess, metadataRecord(profile, profileDigest, originalInitialDigest, "running", false));

    let closing = false, closed = false, finishPromise, closePromise;
    const markClean = () => {
      if (closing || closed) return Promise.reject(new WasiHostError("guix-state-closed", "cannot complete a closed Guix state session"));
      if (!finishPromise) finishPromise = (async () => {
        // The caller's successful disk cleanup is a precondition, not inferred
        // from stdout, an untagged exit, or metadata alone. Any failure below
        // preserves the dirty marker (even if the JSON happens to say clean).
        writeMetadata(metadataAccess, metadataRecord(profile, profileDigest, originalInitialDigest, "ready", true));
        await directory.removeEntry(DIRTY);
      })();
      return finishPromise;
    };
    const close = () => {
      if (!closePromise) {
        closing = true;
        closePromise = (async () => {
          let failure;
          try { if (finishPromise) await finishPromise; } catch (error) { failure = error; }
          try { closeHandle(metadataAccess); } catch (error) { failure ??= error; }
          try { closeHandle(sessionLock); } catch (error) { failure ??= error; }
          closed = true;
          if (failure) throw failure;
        })();
      }
      return closePromise;
    };
    return Object.freeze({ fileHandle, profileDigest, markClean, complete: markClean, close });
  } catch (error) {
    // Do not remove a marker, metadata, disk, or lock file on failure. Releasing
    // the session handle permits explicit recovery, not automatic overwriting.
    try { if (diskAccess) closeHandle(diskAccess); } catch { /* Preserve the original failure. */ }
    try { if (metadataAccess) closeHandle(metadataAccess); } catch { /* Preserve the original failure. */ }
    try { closeHandle(sessionLock); } catch { /* Preserve the original failure. */ }
    if (error instanceof WasiHostError) throw error;
    throw recovery("Guix browser state could not be opened or provisioned", error);
  }
}
