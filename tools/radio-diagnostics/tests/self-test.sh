#!/data/data/com.termux/files/usr/bin/bash

set -Eeuo pipefail

readonly TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec "${TEST_DIR}/../radio-diagnostics" self-test
