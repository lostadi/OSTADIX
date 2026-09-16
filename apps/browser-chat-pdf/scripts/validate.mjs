#!/usr/bin/env node

"use strict";

import process from "node:process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { lstat, readFile, realpath } from "node:fs/promises";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SOURCE_ROOT = path.resolve(SCRIPT_DIR, "..");
const ALLOWLIST_PATH = path.join(SCRIPT_DIR, "runtime-files.txt");

const EXPECTED_RUNTIME_FILES = Object.freeze([
  "manifest.json",
  "LICENSE",
  "background.js",
  "shared.js",
  "extractor.js",
  "renderer.js",
  "popup.html",
  "popup.css",
  "popup.js",
  "preview.html",
  "preview.css",
  "preview.js",
  "icons/chatprint.svg",
  "icons/icon-16.png",
  "icons/icon-32.png",
  "icons/icon-48.png",
  "icons/icon-128.png",
]);

function usage() {
  return "Usage: node scripts/validate.mjs [--root PATH] [--quiet]";
}

function parseArguments(argv) {
  let root = SOURCE_ROOT;
  let quiet = false;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--quiet") {
      quiet = true;
    } else if (argument === "--root") {
      const value = argv[index + 1];
      if (!value) throw new Error(`--root requires a path.\n${usage()}`);
      root = path.resolve(value);
      index += 1;
    } else if (argument.startsWith("--root=")) {
      root = path.resolve(argument.slice("--root=".length));
    } else if (argument === "--help" || argument === "-h") {
      process.stdout.write(`${usage()}\n`);
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${argument}\n${usage()}`);
    }
  }

  return { root, quiet };
}

function parseRuntimeFiles(source) {
  return source
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}

function assertSafeRelativePath(relativePath) {
  if (relativePath.includes("\\")) {
    throw new Error(`Runtime path must use forward slashes: ${relativePath}`);
  }
  if (path.posix.isAbsolute(relativePath)) {
    throw new Error(`Runtime path must be relative: ${relativePath}`);
  }
  const normalized = path.posix.normalize(relativePath);
  if (normalized !== relativePath || normalized === ".." || normalized.startsWith("../")) {
    throw new Error(`Unsafe runtime path: ${relativePath}`);
  }
}

function assertExactAllowlist(runtimeFiles) {
  const duplicates = runtimeFiles.filter((file, index) => runtimeFiles.indexOf(file) !== index);
  if (duplicates.length) {
    throw new Error(`Duplicate runtime allowlist entries: ${[...new Set(duplicates)].join(", ")}`);
  }
  if (JSON.stringify(runtimeFiles) !== JSON.stringify(EXPECTED_RUNTIME_FILES)) {
    throw new Error(
      "scripts/runtime-files.txt differs from the reviewed runtime allowlist. " +
      "Update validate.mjs deliberately when adding extension runtime files.",
    );
  }
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function assertExactPermissions(manifest) {
  const expected = ["activeTab", "scripting", "storage"];
  if (!Array.isArray(manifest.permissions) ||
      JSON.stringify(sorted(manifest.permissions)) !== JSON.stringify(sorted(expected))) {
    throw new Error(`Manifest permissions must be exactly: ${expected.join(", ")}`);
  }

  for (const forbidden of [
    "host_permissions",
    "optional_permissions",
    "optional_host_permissions",
    "externally_connectable",
    "key",
    "update_url",
  ]) {
    if (Object.hasOwn(manifest, forbidden)) {
      throw new Error(`Manifest must not define ${forbidden}`);
    }
  }
}

function assertLocalRuntimeReference(reference, label, allowedFiles) {
  if (typeof reference !== "string" || !reference) {
    throw new Error(`${label} must be a non-empty local path`);
  }
  const withoutQuery = reference.split(/[?#]/u, 1)[0];
  assertSafeRelativePath(withoutQuery);
  if (/^(?:[a-z][a-z\d+.-]*:|\/\/)/iu.test(reference)) {
    throw new Error(`${label} must not use a remote URL: ${reference}`);
  }
  if (!allowedFiles.has(withoutQuery)) {
    throw new Error(`${label} is not in scripts/runtime-files.txt: ${withoutQuery}`);
  }
}

function manifestReferences(manifest) {
  const references = [];
  const add = (value, label) => {
    if (value !== undefined) references.push({ value, label });
  };

  add(manifest.background?.service_worker, "background.service_worker");
  add(manifest.action?.default_popup, "action.default_popup");
  for (const [size, value] of Object.entries(manifest.action?.default_icon || {})) {
    add(value, `action.default_icon.${size}`);
  }
  for (const [size, value] of Object.entries(manifest.icons || {})) {
    add(value, `icons.${size}`);
  }
  add(manifest.options_page, "options_page");
  add(manifest.options_ui?.page, "options_ui.page");
  add(manifest.side_panel?.default_path, "side_panel.default_path");

  return references;
}

async function assertRuntimeFiles(root, runtimeFiles) {
  const rootRealPath = await realpath(root);
  const rootPrefix = `${rootRealPath}${path.sep}`;

  for (const relativePath of runtimeFiles) {
    assertSafeRelativePath(relativePath);
    const candidate = path.join(root, ...relativePath.split("/"));
    const status = await lstat(candidate).catch(() => null);
    if (!status || !status.isFile() || status.isSymbolicLink()) {
      throw new Error(`Missing regular runtime file: ${relativePath}`);
    }
    const candidateRealPath = await realpath(candidate);
    if (!candidateRealPath.startsWith(rootPrefix)) {
      throw new Error(`Runtime file escapes the extension root: ${relativePath}`);
    }
  }
}

async function assertHtmlReferences(root, runtimeFiles, allowedFiles) {
  const referencePattern = /<(?:script|link|img)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']/giu;
  for (const relativePath of runtimeFiles.filter((file) => file.endsWith(".html"))) {
    const html = await readFile(path.join(root, relativePath), "utf8");
    for (const match of html.matchAll(referencePattern)) {
      assertLocalRuntimeReference(match[1], `${relativePath} resource`, allowedFiles);
    }
  }
}

async function assertPackageVersion(root, manifestVersion) {
  const packagePath = path.join(root, "package.json");
  const status = await lstat(packagePath).catch(() => null);
  if (!status) return;
  if (!status.isFile() || status.isSymbolicLink()) {
    throw new Error("package.json must be a regular file when present");
  }
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  if (packageJson.version !== manifestVersion) {
    throw new Error(
      `package.json version ${packageJson.version || "(missing)"} does not match manifest ${manifestVersion}`,
    );
  }
}

async function validate(root) {
  const runtimeFiles = parseRuntimeFiles(await readFile(ALLOWLIST_PATH, "utf8"));
  assertExactAllowlist(runtimeFiles);
  await assertRuntimeFiles(root, runtimeFiles);

  const manifest = JSON.parse(await readFile(path.join(root, "manifest.json"), "utf8"));
  if (manifest.manifest_version !== 3) {
    throw new Error("manifest.json must use Manifest V3");
  }
  if (typeof manifest.name !== "string" || !manifest.name.trim()) {
    throw new Error("manifest.json must have a non-empty name");
  }
  if (typeof manifest.version !== "string" || !/^\d+(?:\.\d+){0,3}$/u.test(manifest.version)) {
    throw new Error("manifest.json has an invalid Chromium extension version");
  }
  assertExactPermissions(manifest);

  const csp = manifest.content_security_policy?.extension_pages;
  if (csp !== "script-src 'self'; object-src 'self'") {
    throw new Error("Extension page CSP must allow only self-hosted scripts and objects");
  }

  const allowedFiles = new Set(runtimeFiles);
  for (const { value, label } of manifestReferences(manifest)) {
    assertLocalRuntimeReference(value, label, allowedFiles);
  }
  await assertHtmlReferences(root, runtimeFiles, allowedFiles);
  await assertPackageVersion(root, manifest.version);

  return { manifest, runtimeFiles };
}

try {
  const { root, quiet } = parseArguments(process.argv.slice(2));
  const { manifest, runtimeFiles } = await validate(root);
  if (!quiet) {
    process.stdout.write(
      `Chatprint validation passed\n` +
      `  root: ${root}\n` +
      `  version: ${manifest.version}\n` +
      `  runtime files: ${runtimeFiles.length}\n`,
    );
  }
} catch (error) {
  process.stderr.write(`Chatprint validation failed: ${error.message || String(error)}\n`);
  process.exitCode = 1;
}
