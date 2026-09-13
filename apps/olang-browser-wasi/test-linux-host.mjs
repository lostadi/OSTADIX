import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  LINUX_WASI_PREVIEW1_IMPORTS,
  LINUX_WASI_PREVIEW1_SIGNATURES,
  LinuxWasiPreview1Host,
} from "./linux-wasi-host.mjs";

function unitTests() {
  let now = 10_000_000n;
  const waits = [];
  const host = new LinuxWasiPreview1Host({
    clockNow: (id) => id <= 1 ? now : null,
    waitMilliseconds: (milliseconds) => {
      waits.push(milliseconds);
      now += BigInt(Math.ceil(milliseconds * 1_000_000));
    },
  });
  host.attach(new WebAssembly.Memory({ initial: 1 }));
  const wasi = host.imports.wasi_snapshot_preview1;
  const memory = new DataView(host.memory.buffer);
  assert.equal(LINUX_WASI_PREVIEW1_IMPORTS.length, 33);
  assert.deepEqual(Object.keys(wasi), [...LINUX_WASI_PREVIEW1_IMPORTS]);
  for (const name of LINUX_WASI_PREVIEW1_IMPORTS) {
    assert.equal(typeof wasi[name], "function", name);
    assert.ok(LINUX_WASI_PREVIEW1_SIGNATURES[name], name);
  }
  assert.equal(wasi.fd_fdstat_set_flags(0, 4), 0);
  assert.equal(wasi.fd_fdstat_get(0, 256), 0);
  assert.equal(memory.getUint16(258, true), 4);
  assert.equal(wasi.fd_fdstat_set_flags(0, 32), 28);
  assert.equal(wasi.fd_fdstat_set_flags(0, 1), 58);
  assert.equal(wasi.fd_fdstat_set_flags(3, 0), 8);
  assert.equal(wasi.fd_pread(0, 0, 0, 0n, 0), 70);
  assert.equal(wasi.fd_pwrite(1, 0, 0, 0n, 0), 70);
  assert.equal(wasi.fd_filestat_set_size(1, 1n), 76);
  assert.equal(wasi.fd_prestat_get(3, 0), 8);
  for (const name of ["path_create_directory", "path_filestat_set_times", "path_link", "path_symlink", "path_open"]) {
    assert.equal(wasi[name](), 76, name);
  }
  for (const name of ["sock_accept", "sock_recv", "sock_send"]) assert.equal(wasi[name](), 8, name);
  assert.equal(wasi.fd_read(0, 0, 0, 256), 0);
  assert.equal(memory.getUint32(256, true), 0);
  assert.equal(wasi.poll_oneoff(0, 512, 0, 768), 28);
  assert.equal(wasi.poll_oneoff(0, 512, -1, 768), 21);

  function subscription(index, type, value, userdata = 42n, flags = 0) {
    const offset = index * 48;
    new Uint8Array(host.memory.buffer, offset, 48).fill(0);
    memory.setBigUint64(offset, userdata, true);
    memory.setUint8(offset + 8, type);
    if (type === 0) {
      memory.setUint32(offset + 16, 1, true);
      memory.setBigUint64(offset + 24, value, true);
      memory.setUint16(offset + 40, flags, true);
    } else memory.setUint32(offset + 16, value, true);
  }
  subscription(0, 0, 2_000_000n);
  assert.equal(wasi.poll_oneoff(0, 512, 1, 768), 0);
  assert.deepEqual(waits, [2]);
  assert.equal(memory.getBigUint64(512, true), 42n);
  assert.equal(memory.getUint32(768, true), 1);
  assert.equal(memory.getUint16(520, true), 0);
  subscription(0, 0, now - 1n, 43n, 1);
  assert.equal(wasi.poll_oneoff(0, 512, 1, 768), 0);
  assert.equal(waits.length, 1);
  subscription(0, 0, 20_000_000n);
  subscription(1, 1, 0, 44n);
  assert.equal(wasi.poll_oneoff(0, 512, 2, 768), 0);
  assert.equal(waits.length, 1);
  assert.equal(memory.getBigUint64(512, true), 44n);
  assert.equal(memory.getUint8(522), 1);
  assert.equal(memory.getUint16(536, true), 1);
  assert.equal(memory.getBigUint64(528, true), 0n);
  subscription(0, 2, 3);
  assert.equal(wasi.poll_oneoff(0, 512, 1, 768), 0);
  assert.equal(memory.getUint16(520, true), 8);
  subscription(0, 0, 1n, 42n, 2);
  assert.equal(wasi.poll_oneoff(0, 512, 1, 768), 28);
  subscription(0, 3, 0);
  assert.equal(wasi.poll_oneoff(0, 512, 1, 768), 28);
  subscription(0, 0, 1n);
  memory.setUint32(16, 99, true);
  assert.equal(wasi.poll_oneoff(0, 512, 1, 768), 0);
  assert.equal(memory.getUint16(520, true), 28);
  assert.equal(wasi.fd_close(0), 0);
  assert.equal(wasi.fd_fdstat_set_flags(0, 4), 8);
  subscription(0, 1, 0);
  assert.equal(wasi.poll_oneoff(0, 512, 1, 768), 0);
  assert.equal(memory.getUint16(520, true), 8);
  assert.equal(wasi.poll_oneoff(0, 65_530, 1, 768), 21);
  console.log("Linux WASI host contract: PASS");
}

async function guest(artifact, fail) {
  const bytes = await readFile(artifact);
  const module = await WebAssembly.compile(bytes);
  assert.deepEqual(WebAssembly.Module.imports(module).map((item) => {
    assert.equal(item.module, "wasi_snapshot_preview1");
    assert.equal(item.kind, "function");
    return item.name;
  }).sort(), [...LINUX_WASI_PREVIEW1_IMPORTS].sort());
  const host = new LinuxWasiPreview1Host({
    args: ["program.wasm", "--no-stdin"],
    env: fail ? { OSTADIX_WASM_EXPECT_FAILURE: "1" } : {},
  });
  const instance = await WebAssembly.instantiate(module, host.imports);
  const result = host.run(instance);
  console.log(JSON.stringify(result));
  process.exitCode = result.exitCode;
}

async function boundedGuest(artifact, fail) {
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--guest", artifact, fail ? "failure" : "success"], {
    env: {},
    detached: process.platform !== "win32",
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let failure;
  function stop(error) {
    failure ??= error;
    if (!child.pid) return;
    try {
      if (process.platform === "win32") child.kill("SIGKILL");
      else process.kill(-child.pid, "SIGKILL");
    } catch (killError) {
      if (killError.code !== "ESRCH") throw killError;
    }
  }
  const timer = setTimeout(() => stop(new Error("Linux WASI guest exceeded 600000 ms")), 600_000);
  const interrupted = () => stop(new Error("Linux WASI host qualification interrupted"));
  process.on("SIGINT", interrupted);
  process.on("SIGTERM", interrupted);
  const collect = (name, chunk) => {
    if (name === "stdout") stdout += chunk.toString("utf8");
    else stderr += chunk.toString("utf8");
    if (stdout.length + stderr.length > 1_048_576) stop(new Error("Linux WASI guest exceeded output limit"));
  };
  child.stdout.on("data", (chunk) => collect("stdout", chunk));
  child.stderr.on("data", (chunk) => collect("stderr", chunk));
  const started = Date.now();
  try {
    const code = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code) => resolve(code));
    });
    if (failure) throw failure;
    assert.equal(code, fail ? 1 : 0, stderr || stdout);
    const result = JSON.parse(stdout);
    assert.equal(result.exitCode, code);
    assert.equal(result.ok, !fail);
    if (fail) {
      assert.match(result.stdout + result.stderr, /OSTADIX WASM INTENTIONAL FAILURE/);
      assert.doesNotMatch(result.stdout, /OSTADIX WASM Linux 42/);
    } else assert.match(result.stdout, /OSTADIX WASM Linux 42/);
    console.log(`Linux WASI actual artifact ${fail ? "failure" : "success"}: PASS (exit=${code}, ${Date.now() - started}ms)`);
  } finally {
    clearTimeout(timer);
    process.off("SIGINT", interrupted);
    process.off("SIGTERM", interrupted);
  }
}

if (process.argv[2] === "--guest") {
  await guest(process.argv[3], process.argv[4] === "failure");
} else {
  unitTests();
  if (process.argv[2]) {
    await boundedGuest(process.argv[2], false);
    await boundedGuest(process.argv[2], true);
  }
}
