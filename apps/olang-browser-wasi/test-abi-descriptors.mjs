import assert from "node:assert/strict";
import test from "node:test";
import { compileAndVerifyModule } from "./runner.mjs";
import {
  WASI_PREVIEW1_IMPORTS, WASI_PREVIEW1_SIGNATURES,
} from "./wasi-preview1-host.mjs";
import {
  LINUX_WASI_PREVIEW1_IMPORTS, LINUX_WASI_PREVIEW1_SIGNATURES,
} from "./linux-wasi-host.mjs";

const encode = (value) => new TextEncoder().encode(value);
const u32 = (input) => {
  const result = [];
  let value = input;
  do {
    const byte = value & 127;
    value >>>= 7;
    result.push(byte | (value ? 128 : 0));
  } while (value);
  return result;
};
const name = (value) => [...u32(encode(value).length), ...encode(value)];
const vector = (entries) => [...u32(entries.length), ...entries.flat()];
const section = (id, bytes) => [id, ...u32(bytes.length), ...bytes];
const valtype = (value) => ({ i32: 0x7f, i64: 0x7e })[value];

// Every case is a valid, no-op command module. Negative cases change a real
// import descriptor, so refusal must come from the selected host contract,
// rather than malformed Wasm or an incompatible imported function signature.
function fixture(imports, signatures, change = {}) {
  const types = imports.map((key) => signatures[key]);
  types.push({ parameters: [], results: [] });
  const importEntries = imports.map((key, index) => {
    const module = index === 0 && change.namespace
      ? change.namespace : "wasi_snapshot_preview1";
    const descriptor = index !== 0 || !change.kind
      ? [0x00, ...u32(index)]
      : change.kind === "global"
        ? [0x03, 0x7f, 0x00]
        : [0x01, 0x70, 0x00, 0x01];
    return [...name(module), ...name(key), ...descriptor];
  });
  const functionImports = imports.length - (change.kind ? 1 : 0);
  return Uint8Array.from([
    0, 97, 115, 109, 1, 0, 0, 0,
    ...section(1, vector(types.map(({ parameters, results }) => [
      0x60,
      ...vector(parameters.map((value) => [valtype(value)])),
      ...vector(results.map((value) => [valtype(value)])),
    ]))),
    ...section(2, vector(importEntries)),
    ...section(3, vector([u32(imports.length)])),
    ...section(5, vector([[0, 1]])),
    ...section(7, vector([
      [...name("memory"), 2, 0],
      [...name("_start"), 0, ...u32(functionImports)],
    ])),
    ...section(10, vector([[2, 0, 11]])),
  ]);
}

for (const profile of [
  { name: "direct WASI", imports: WASI_PREVIEW1_IMPORTS, signatures: WASI_PREVIEW1_SIGNATURES },
  { name: "Linux WASI", imports: LINUX_WASI_PREVIEW1_IMPORTS, signatures: LINUX_WASI_PREVIEW1_SIGNATURES },
]) {
  const abi = {
    module: "wasi_snapshot_preview1",
    imports: [...profile.imports],
    required_exports: ["memory", "_start"],
  };
  await test(`${profile.name} accepts its complete typed import contract`, async () => {
    const module = await compileAndVerifyModule(
      fixture(profile.imports, profile.signatures), abi, profile.signatures,
    );
    assert.ok(module instanceof WebAssembly.Module);
  });
  for (const [description, change] of [
    ["wrong namespace", { namespace: "unapproved_host" }],
    ["global instead of function", { kind: "global" }],
    ["table instead of function", { kind: "table" }],
  ]) {
    await test(`${profile.name} rejects a valid module with ${description}`, async () => {
      const bytes = fixture(profile.imports, profile.signatures, change);
      assert.ok(await WebAssembly.compile(bytes) instanceof WebAssembly.Module);
      await assert.rejects(
        compileAndVerifyModule(bytes, abi, profile.signatures),
        (error) => error.code === "abi-mismatch" && /imports do not match/.test(error.message),
      );
    });
  }
}
