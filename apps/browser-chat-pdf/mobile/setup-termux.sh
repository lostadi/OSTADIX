#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

open_installer=1
if [[ "${1:-}" == "--no-open" ]]; then
  open_installer=0
  shift
fi
if [[ "$#" -ne 0 ]]; then
  echo "Usage: $0 [--no-open]" >&2
  exit 2
fi

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
app_dir="$(dirname -- "$script_dir")"
download_root="/sdcard/Download"
install_dir="$download_root/Chatprint-Mobile"
marker="$install_dir/.chatprint-mobile-managed"

if [[ ! -d "$download_root" || ! -w "$download_root" ]]; then
  echo "Android shared storage is not available." >&2
  echo "Run termux-setup-storage, approve access, then run this script again." >&2
  exit 1
fi
if [[ -e "$install_dir" && ! -f "$marker" ]]; then
  echo "Refusing to overwrite the existing unmanaged directory:" >&2
  echo "  $install_dir" >&2
  echo "Rename it or add the marker only after confirming Chatprint owns it:" >&2
  echo "  $marker" >&2
  exit 1
fi

cd "$app_dir"
npm ci --ignore-scripts --no-audit --no-fund
npm run build:mobile

mkdir -p "$install_dir"
install -m 0644 "$script_dir/dist/install.html" "$install_dir/install.html"
install -m 0644 "$script_dir/dist/chatprint-mobile.txt" "$install_dir/chatprint-mobile.txt"
install -m 0644 "$script_dir/dist/build.json" "$install_dir/build.json"
printf '%s\n' "Chatprint Mobile managed directory v1" > "$marker"

if command -v termux-clipboard-set >/dev/null 2>&1; then
  tr -d '\r\n' < "$script_dir/dist/chatprint-mobile.txt" | termux-clipboard-set
  echo "Bookmarklet copied to the Android clipboard."
else
  echo "Install Termux:API to enable automatic clipboard copying."
fi

echo "Chatprint Mobile is ready in:"
echo "  $install_dir"
echo "Chrome still requires one protected manual step: create/edit a bookmark and"
echo "paste chatprint-mobile.txt into its URL field. A script cannot do that for you."
echo "Then open an AI chat, type Chatprint in Chrome's address bar, and select the bookmark."

if [[ "$open_installer" -eq 1 ]]; then
  if command -v termux-open >/dev/null 2>&1; then
    termux-open "$install_dir/install.html"
  else
    echo "Open $install_dir/install.html in your browser for illustrated instructions."
  fi
fi
