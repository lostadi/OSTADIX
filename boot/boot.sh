#!/usr/bin/env bash
# Persistent Linux/native-codec system; native kernel probes remain explicit.
set -euo pipefail
boot_repository="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec python3 "$boot_repository/scripts/boot_okernel.py" "$@"
