#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
ALLOWLIST="$SCRIPT_DIR/runtime-files.txt"

output=""
force=0
temporary_dir=""

usage() {
  cat <<'EOF'
Usage: scripts/package-extension.sh [--output FILE] [--force]

Creates a deterministic-content extension ZIP and adjacent .sha256 file.
Only files in scripts/runtime-files.txt are included, with manifest.json at
the archive root. The default output is dist/chatprint-extension-VERSION.zip.
EOF
}

fail() {
  printf 'Chatprint packaging failed: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$temporary_dir" && -d "$temporary_dir" ]]; then
    rm -rf -- "$temporary_dir"
  fi
}
trap cleanup EXIT HUP INT TERM

while (($#)); do
  case "$1" in
    --output)
      (($# >= 2)) || fail "--output requires a file"
      output="$2"
      shift 2
      ;;
    --output=*)
      output="${1#*=}"
      shift
      ;;
    --force)
      force=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

for command_name in node zipinfo; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done
if command -v zip >/dev/null 2>&1; then
  archive_tool="zip"
elif command -v 7z >/dev/null 2>&1; then
  archive_tool="7z"
else
  fail "zip or 7z is required"
fi
node "$SCRIPT_DIR/validate.mjs" --root "$SOURCE_ROOT"

version="$(node -e 'const fs = require("node:fs"); process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).version);' "$SOURCE_ROOT/manifest.json")"
[[ -n "$version" ]] || fail "manifest version is empty"
if [[ -z "$output" ]]; then
  output="$SOURCE_ROOT/dist/chatprint-extension-$version.zip"
elif [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi

output_parent="$(dirname -- "$output")"
output_name="$(basename -- "$output")"
[[ -n "$output_name" && "$output_name" != "." && "$output_name" != ".." ]] || fail "invalid output path"
mkdir -p -- "$output_parent"
output_parent="$(cd -- "$output_parent" && pwd -P)"
output="$output_parent/$output_name"
checksum="$output.sha256"

if ((force == 0)) && { [[ -e "$output" ]] || [[ -e "$checksum" ]]; }; then
  fail "output already exists; pass --force to replace it: $output"
fi

runtime_files=()
while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
  line="${raw_line%$'\r'}"
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -z "$line" || "$line" == \#* ]] && continue
  case "$line" in
    /*|..|../*|*/../*|*/..|*\\*|*//* ) fail "unsafe runtime allowlist entry: $line" ;;
  esac
  runtime_files+=("$line")
done < "$ALLOWLIST"
((${#runtime_files[@]} > 0)) || fail "runtime allowlist is empty"

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/chatprint-package.XXXXXX")"
payload="$temporary_dir/payload"
archive="$temporary_dir/archive.zip"
expected_list="$temporary_dir/expected.txt"
actual_list="$temporary_dir/actual.txt"
mkdir -p -- "$payload"

for relative in "${runtime_files[@]}"; do
  [[ -f "$SOURCE_ROOT/$relative" && ! -L "$SOURCE_ROOT/$relative" ]] || fail "missing regular runtime file: $relative"
  mkdir -p -- "$payload/$(dirname -- "$relative")"
  cp -p -- "$SOURCE_ROOT/$relative" "$payload/$relative"
done

node "$SCRIPT_DIR/validate.mjs" --root "$payload" --quiet
if [[ "$archive_tool" == "zip" ]]; then
  (
    cd -- "$payload"
    zip -q -X "$archive" "${runtime_files[@]}"
  )
else
  (
    cd -- "$payload"
    7z a -bd -y -tzip -mx=9 "$archive" "${runtime_files[@]}" >/dev/null
  )
fi

printf '%s\n' "${runtime_files[@]}" | LC_ALL=C sort > "$expected_list"
zipinfo -1 "$archive" | sed '/\/$/d' | LC_ALL=C sort > "$actual_list"
cmp -s -- "$expected_list" "$actual_list" || fail "archive contents differ from the runtime allowlist"

if command -v sha256sum >/dev/null 2>&1; then
  archive_hash="$(sha256sum "$archive" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  archive_hash="$(shasum -a 256 "$archive" | awk '{print $1}')"
else
  fail "sha256sum or shasum is required"
fi

if ((force)); then
  mv -f -- "$archive" "$output"
else
  mv -- "$archive" "$output"
fi
printf '%s  %s\n' "$archive_hash" "$output_name" > "$temporary_dir/archive.sha256"
if ((force)); then
  mv -f -- "$temporary_dir/archive.sha256" "$checksum"
else
  mv -- "$temporary_dir/archive.sha256" "$checksum"
fi

printf 'Created %s\n' "$output"
printf 'Created %s\n' "$checksum"
printf 'SHA-256 %s\n' "$archive_hash"
