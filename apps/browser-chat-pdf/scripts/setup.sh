#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
ALLOWLIST="$SCRIPT_DIR/runtime-files.txt"
MARKER_TEXT="chatprint-managed-install-v1"

install_dir=""
open_manager=1
run_tests=0
staging_dir=""

usage() {
  cat <<'EOF'
Usage: scripts/setup.sh [options]

Options:
  --install-dir PATH  Install the unpacked extension at PATH.
  --no-open           Do not open the browser extensions page.
  --run-tests         Run npm ci and the test suite before installing.
  -h, --help          Show this help.

The script installs and validates Chatprint, then opens the extensions page.
Chromium still requires you to enable Developer mode and click Load unpacked.
EOF
}

fail() {
  printf 'Chatprint setup failed: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$staging_dir" && -d "$staging_dir" ]]; then
    rm -rf -- "$staging_dir"
  fi
}
trap cleanup EXIT HUP INT TERM

while (($#)); do
  case "$1" in
    --install-dir)
      (($# >= 2)) || fail "--install-dir requires a path"
      install_dir="$2"
      shift 2
      ;;
    --install-dir=*)
      install_dir="${1#*=}"
      shift
      ;;
    --no-open)
      open_manager=0
      shift
      ;;
    --run-tests)
      run_tests=1
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

if [[ -z "$install_dir" ]]; then
  case "$(uname -s)" in
    Darwin)
      : "${HOME:?HOME is required}"
      install_dir="$HOME/Library/Application Support/Chatprint/extension"
      ;;
    Linux)
      : "${HOME:?HOME is required}"
      install_dir="${XDG_DATA_HOME:-$HOME/.local/share}/chatprint/extension"
      ;;
    *)
      fail "unsupported operating system; pass --install-dir explicitly"
      ;;
  esac
fi

[[ -n "$install_dir" && "$install_dir" != "/" ]] || fail "refusing unsafe install path"
install_parent="$(dirname -- "$install_dir")"
install_name="$(basename -- "$install_dir")"
[[ -n "$install_name" && "$install_name" != "." && "$install_name" != ".." ]] || fail "invalid install path"
mkdir -p -- "$install_parent"
install_parent="$(cd -- "$install_parent" && pwd -P)"
install_dir="$install_parent/$install_name"
marker_file="$install_dir.chatprint-managed"

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

basic_validate() {
  local root="$1"
  local relative source
  for relative in "${runtime_files[@]}"; do
    source="$root/$relative"
    [[ -f "$source" && ! -L "$source" ]] || fail "missing regular runtime file: $relative"
  done
  grep -Eq '"manifest_version"[[:space:]]*:[[:space:]]*3' "$root/manifest.json" ||
    fail "manifest.json is not Manifest V3"
  if grep -Eq '"(host_permissions|optional_host_permissions|update_url|key)"[[:space:]]*:' "$root/manifest.json"; then
    fail "manifest.json contains a forbidden privileged field"
  fi
}

basic_validate "$SOURCE_ROOT"
if command -v node >/dev/null 2>&1; then
  node "$SCRIPT_DIR/validate.mjs" --root "$SOURCE_ROOT"
fi

if ((run_tests)); then
  command -v npm >/dev/null 2>&1 || fail "npm is required by --run-tests"
  (
    cd -- "$SOURCE_ROOT"
    npm ci --ignore-scripts
    npm test
  )
fi

if [[ -e "$marker_file" || -L "$marker_file" ]]; then
  [[ -f "$marker_file" && ! -L "$marker_file" ]] || fail "foreign management marker exists: $marker_file"
  grep -qxF "$MARKER_TEXT" "$marker_file" || fail "foreign management marker exists: $marker_file"
fi
if [[ -L "$install_dir" ]]; then
  fail "refusing a symbolic-link install directory: $install_dir"
fi
if [[ -e "$install_dir" && ! -f "$marker_file" ]]; then
  fail "refusing to replace foreign directory without Chatprint marker: $install_dir"
fi

install_is_current() {
  [[ -d "$install_dir" && -f "$marker_file" ]] || return 1
  grep -qxF "$MARKER_TEXT" "$marker_file" || return 1
  [[ -z "$(find "$install_dir" -type l -print -quit)" ]] || return 1
  local installed_count relative
  installed_count="$(find "$install_dir" -type f -print | wc -l | tr -d '[:space:]')"
  [[ "$installed_count" == "${#runtime_files[@]}" ]] || return 1
  for relative in "${runtime_files[@]}"; do
    [[ -f "$install_dir/$relative" ]] || return 1
    cmp -s -- "$SOURCE_ROOT/$relative" "$install_dir/$relative" || return 1
  done
}

backup_dir=""
if install_is_current; then
  printf 'Chatprint is already current at %s\n' "$install_dir"
else
  staging_dir="$(mktemp -d "$install_parent/.chatprint-stage.XXXXXX")"
  for relative in "${runtime_files[@]}"; do
    mkdir -p -- "$staging_dir/$(dirname -- "$relative")"
    cp -p -- "$SOURCE_ROOT/$relative" "$staging_dir/$relative"
    cmp -s -- "$SOURCE_ROOT/$relative" "$staging_dir/$relative" || fail "copy verification failed: $relative"
  done

  basic_validate "$staging_dir"
  if command -v node >/dev/null 2>&1; then
    node "$SCRIPT_DIR/validate.mjs" --root "$staging_dir" --quiet
  fi

  if [[ -e "$install_dir" ]]; then
    backup_dir="$install_dir.backup-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    mv -- "$install_dir" "$backup_dir"
  fi

  if ! mv -- "$staging_dir" "$install_dir"; then
    if [[ -n "$backup_dir" && ! -e "$install_dir" && -e "$backup_dir" ]]; then
      mv -- "$backup_dir" "$install_dir"
    fi
    fail "could not activate the staged install"
  fi
  staging_dir=""

  marker_temp="$marker_file.tmp.$$"
  printf '%s\n' "$MARKER_TEXT" > "$marker_temp"
  mv -f -- "$marker_temp" "$marker_file"

  printf 'Installed Chatprint at %s\n' "$install_dir"
  [[ -z "$backup_dir" ]] || printf 'Previous managed install backed up at %s\n' "$backup_dir"
fi

clipboard_status=""
if command -v pbcopy >/dev/null 2>&1; then
  printf '%s' "$install_dir" | pbcopy && clipboard_status=" (path copied to clipboard)" || true
elif command -v wl-copy >/dev/null 2>&1; then
  printf '%s' "$install_dir" | wl-copy && clipboard_status=" (path copied to clipboard)" || true
elif command -v xclip >/dev/null 2>&1; then
  printf '%s' "$install_dir" | xclip -selection clipboard && clipboard_status=" (path copied to clipboard)" || true
elif command -v xsel >/dev/null 2>&1; then
  printf '%s' "$install_dir" | xsel --clipboard --input && clipboard_status=" (path copied to clipboard)" || true
fi

opened=0
if ((open_manager)); then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    for app_and_url in \
      "Google Chrome|chrome://extensions" \
      "Brave Browser|brave://extensions" \
      "Microsoft Edge|edge://extensions" \
      "Chromium|chrome://extensions"; do
      app="${app_and_url%%|*}"
      manager_url="${app_and_url#*|}"
      if open -Ra "$app" >/dev/null 2>&1; then
        open -a "$app" "$manager_url" >/dev/null 2>&1 || true
        opened=1
        break
      fi
    done
  else
    for browser in google-chrome google-chrome-stable brave-browser microsoft-edge microsoft-edge-stable chromium chromium-browser; do
      if command -v "$browser" >/dev/null 2>&1; then
        case "$browser" in
          brave-browser) manager_url="brave://extensions" ;;
          microsoft-edge*) manager_url="edge://extensions" ;;
          *) manager_url="chrome://extensions" ;;
        esac
        nohup "$browser" "$manager_url" >/dev/null 2>&1 &
        opened=1
        break
      fi
    done
  fi
fi

printf '\nFinish in your desktop browser:\n'
if ((open_manager == 0 || opened == 0)); then
  printf '  1. Open chrome://extensions (or edge://extensions / brave://extensions).\n'
else
  printf '  1. Use the extensions page that was opened.\n'
fi
printf '  2. Turn on Developer mode.\n'
printf '  3. Click Load unpacked and select:\n     %s%s\n' "$install_dir" "$clipboard_status"
printf '\nChromium requires that final Load unpacked confirmation; normal extensions cannot bypass it.\n'
