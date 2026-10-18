#!/usr/bin/env bash
# Reproducible HTTP connector build in this checkout. No service is installed.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd -P)"
build_runtime=false
with_runtime=false
skip_smoke=false
verify_only=false

usage() {
  cat <<'USAGE'
Usage: scripts/setup_ostadix_mcp_http.sh [OPTIONS]

Build the native HTTP/stdio MCP server from Cargo.lock, then test its HTTP
endpoint against the O runtime in the same checkout. Does not start a public
listener, write credentials, or install a service.

  --root PATH       Build this checkout (defaults to the script's parent repo)
  --build-runtime   Also compile the hosted Rust core into this checkout using
                    already installed dependencies; no host package installs
  --with-runtime    First run setup.sh -y --minimal --no-mcp (may install system
                    dependencies and user command aliases); initial setup only
  --verify-only     Run the HTTP smoke against existing binaries, without builds
  --skip-smoke      Build only, explicitly skipping HTTP/runtime verification
  -h, --help        Show this help

Requirements: Bash, Python 3.10+, the repository's Rust toolchain, and a native
C linker. --build-runtime also needs the dependencies of the hosted Rust core.
On Windows use WSL2. See deployment/mcp/README.md for HTTPS and client setup.
USAGE
}

fail() { printf 'Error: %s\n' "$*" >&2; exit 2; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      [[ $# -ge 2 && -n "$2" ]] || fail '--root requires a checkout path'
      repo_root="$(CDPATH= cd -- "$2" && pwd -P)"; shift 2 ;;
    --build-runtime) build_runtime=true; shift ;;
    --with-runtime) with_runtime=true; shift ;;
    --verify-only) verify_only=true; shift ;;
    --skip-smoke) skip_smoke=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

$build_runtime && $with_runtime && fail 'choose --build-runtime or --with-runtime'
if $verify_only && { $build_runtime || $with_runtime || $skip_smoke; }; then
  fail '--verify-only cannot be combined with build or skip options'
fi
case "$(uname -s)" in
  Linux|Darwin) ;;
  *) fail 'this hosted connector workflow supports Linux/macOS; use WSL2 on Windows' ;;
esac

for required_path in rust-toolchain.toml Cargo.lock backends/python_shim.py \
  mcp/ostadix_lang_mcp_server/Cargo.toml mcp/ostadix_lang_mcp_server/Cargo.lock \
  scripts/smoke_ostadix_mcp_http.py; do
  [[ -f "$repo_root/$required_path" ]] || fail "missing $required_path in $repo_root"
done
command -v python3 >/dev/null || fail 'Python 3.10+ is required'
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ is required")'

cd "$repo_root"
export O_LANG_ROOT="$repo_root"
export O_BACKENDS_DIR="$repo_root/backends"
export PATH="$repo_root/target/release:$PATH"
# Always build native binaries into the documented checkout-local locations.
unset CARGO_BUILD_TARGET
mcp_manifest="$repo_root/mcp/ostadix_lang_mcp_server/Cargo.toml"
mcp_target="$repo_root/mcp/ostadix_lang_mcp_server/target"
server="$mcp_target/release/ostadix-mcp"

printf 'Checkout: %s\n' "$repo_root"
if ! $verify_only; then
  if $with_runtime; then
    bash "$repo_root/setup.sh" -y --minimal --no-mcp --no-env \
      --no-local-bins --no-editor-support
    # setup.sh may install Rust; make its conventional location available here.
    export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
  fi
  command -v cargo >/dev/null || fail 'install Rust using rustup and the checked-in rust-toolchain.toml'
  # An explicit rustup selector also defeats a caller's RUSTUP_TOOLCHAIN or
  # directory override. The repository uses a quoted channel in this file.
  rust_channel="$(python3 - "$repo_root/rust-toolchain.toml" <<'PY'
import pathlib, re, sys
match = re.search(r'(?m)^\s*channel\s*=\s*"([^"\n]+)"', pathlib.Path(sys.argv[1]).read_text())
if match is None:
    sys.exit('rust-toolchain.toml must declare a quoted channel')
print(match.group(1))
PY
)"
  cargo_command=(cargo "+$rust_channel")
  if $build_runtime; then
    # Match setup.sh's minimal hosted Rust command set. Keep the C17/Python
    # editions and extra backend dependency provisioning in canonical setup.sh.
    runtime_bins=(O o-cli olangc ocorec o-link o-unlink ogit o-live-host o-node octl
      o-registry o-info ostadix-device ocore-kernel-world-record)
    cargo_args=(build --release --locked --manifest-path "$repo_root/Cargo.toml"
      --package o-lang --target-dir "$repo_root/target")
    for runtime_bin in "${runtime_bins[@]}"; do cargo_args+=(--bin "$runtime_bin"); done
    "${cargo_command[@]}" "${cargo_args[@]}"
    # Replace aliases atomically, including an alias left as a symlink by a
    # previous installation. Never copy through a link into its source file.
    cp "$repo_root/target/release/o-cli" "$repo_root/target/release/.o.$$"
    mv -f "$repo_root/target/release/.o.$$" "$repo_root/target/release/o"
    cp "$repo_root/target/release/O" "$repo_root/target/release/.ostadix-evaluator.$$"
    mv -f "$repo_root/target/release/.ostadix-evaluator.$$" "$repo_root/target/release/ostadix-evaluator"
  fi
  "${cargo_command[@]}" build --release --locked --manifest-path "$mcp_manifest" --target-dir "$mcp_target"
fi

[[ -x "$server" ]] || fail "MCP executable missing: $server"
if $skip_smoke; then
  printf 'Build complete; HTTP/runtime smoke was explicitly skipped.\n'
else
  [[ -x "$repo_root/target/release/O" ]] || fail 'same-checkout O binary missing; use --build-runtime or --with-runtime'
  python3 "$repo_root/scripts/smoke_ostadix_mcp_http.py" --root "$repo_root" --server "$server"
fi
printf '\nServer: %s\nDeployment instructions: %s/deployment/mcp/README.md\n' "$server" "$repo_root"
