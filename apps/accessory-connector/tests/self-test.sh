#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

APP_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_TMP=$(mktemp -d "${TMPDIR:-/data/data/com.termux/files/usr/tmp}/accessory-connector-test.XXXXXX")
trap 'find "$TEST_TMP" -depth -delete' EXIT HUP INT TERM

command -v python3 >/dev/null 2>&1 || {
    echo "Missing required test tool: python3" >&2
    exit 1
}
command -v javac >/dev/null 2>&1 || {
    echo "Missing required test tool: javac" >&2
    exit 1
}
command -v java >/dev/null 2>&1 || {
    echo "Missing required test tool: java" >&2
    exit 1
}

python3 "$APP_ROOT/tests/safety_contract_test.py"

PACKAGE_ROOT="$APP_ROOT/app/src/main/java/org/ostadix/accessory"
TEST_ROOT="$APP_ROOT/app/src/test/java/org/ostadix/accessory"
javac -Xlint:-options -encoding UTF-8 -source 8 -target 8 -d "$TEST_TMP/classes" \
    "$PACKAGE_ROOT/AccessoryConnectionController.java" \
    "$PACKAGE_ROOT/PublicIntNoArgMethod.java" \
    "$TEST_ROOT/AccessoryConnectionControllerTest.java"
java -cp "$TEST_TMP/classes" org.ostadix.accessory.AccessoryConnectionControllerTest

echo "accessory-connector self-test: PASS"
