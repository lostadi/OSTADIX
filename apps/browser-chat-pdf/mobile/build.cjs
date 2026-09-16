#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { minify } = require("terser");

const MOBILE_ROOT = __dirname;
const APP_ROOT = path.resolve(MOBILE_ROOT, "..");
const DIST_ROOT = path.join(MOBILE_ROOT, "dist");
const INPUTS = [
  path.join(APP_ROOT, "shared.js"),
  path.join(MOBILE_ROOT, "src", "bookmarklet.js"),
];

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function relative(filePath) {
  return path.relative(APP_ROOT, filePath).split(path.sep).join("/");
}

function writeStable(filePath, value) {
  const current = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : null;
  if (current !== value) fs.writeFileSync(filePath, value, "utf8");
}

async function build() {
  const sourceParts = INPUTS.map((filePath) => fs.readFileSync(filePath, "utf8"));
  const fullSharedExport = /return Object\.freeze\(\{[\s\S]*?\n  \}\);\n\}\);\s*$/u;
  sourceParts[0] = sourceParts[0].replace(
    fullSharedExport,
    "return { deriveTitle, isSupportedPageUrl, normalizeRole, roleLabel, safeUrl };\n});",
  );
  if (!sourceParts[0].includes("return { deriveTitle, isSupportedPageUrl")) {
    throw new Error("shared.js export shape changed; update the audited mobile export transform.");
  }
  const source = `${sourceParts.join("\n;\n")}\n;void globalThis.ChatprintMobile.run();\n`;
  const result = await minify(source, {
    compress: { passes: 2 },
    ecma: 2020,
    format: { ascii_only: true, comments: false, semicolons: true },
    mangle: { toplevel: true },
    toplevel: true,
  });
  if (!result.code) throw new Error("Terser did not produce a bookmarklet bundle.");

  fs.mkdirSync(DIST_ROOT, { recursive: true });
  const executable = `${result.code};void 0`;
  const minified = `${executable}\n`;
  const bookmarklet = `javascript:${encodeURIComponent(executable)}\n`;
  const minifiedPath = path.join(DIST_ROOT, "chatprint-mobile.min.js");
  const bookmarkletPath = path.join(DIST_ROOT, "chatprint-mobile.txt");
  writeStable(minifiedPath, minified);
  writeStable(bookmarkletPath, bookmarklet);

  const templatePath = path.join(MOBILE_ROOT, "install.template.html");
  const template = fs.readFileSync(templatePath, "utf8");
  const installPage = template
    .replace("__BOOKMARKLET_JSON__", JSON.stringify(bookmarklet.trim()))
    .replace("__BOOKMARKLET_KIB__", (Buffer.byteLength(bookmarklet) / 1024).toFixed(1))
    .replace("__BOOKMARKLET_SHA__", sha256(bookmarklet).slice(0, 12));
  const installPath = path.join(DIST_ROOT, "install.html");
  writeStable(installPath, installPage);

  const manifest = {
    schemaVersion: 1,
    transform: "shared-mobile-export-v1",
    inputs: INPUTS.concat(templatePath).map((filePath) => {
      const contents = fs.readFileSync(filePath);
      return { path: relative(filePath), sha256: sha256(contents) };
    }),
    outputs: [minifiedPath, bookmarkletPath, installPath].map((filePath) => {
      const contents = fs.readFileSync(filePath);
      return { bytes: contents.byteLength, path: relative(filePath), sha256: sha256(contents) };
    }),
  };
  writeStable(path.join(DIST_ROOT, "build.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write(`Built ${relative(bookmarkletPath)} (${manifest.outputs[1].bytes} bytes)\n`);
}

build().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
