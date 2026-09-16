#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")" && pwd)"
prefix_dir="${PREFIX:-/data/data/com.termux/files/usr}"
cargo build --release --manifest-path "$project_dir/Cargo.toml" --locked
install -m 0755 "$project_dir/target/release/mobile-console" "$prefix_dir/bin/mobile-console"
echo "Installed $prefix_dir/bin/mobile-console"
