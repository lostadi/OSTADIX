#!/usr/bin/env bash
# One persistent package-domain console; native mode-16 tools stay explicit.
set -euo pipefail

okernel_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
okernel_state="${OSTADIX_OKERNEL_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/ostadix/okernel}"
okernel_package_state="$okernel_state/package-domain"
okernel_mode=package
okernel_action="${1:-start}"
if [[ "$okernel_action" == exit || "$okernel_action" == quit ]]; then okernel_action=stop; fi
if (( $# )); then shift; fi
if [[ "$okernel_action" == native ]]; then
    okernel_mode=native
    okernel_action="${1:-start}"
    if (( $# )); then shift; fi
fi
if [[ "$okernel_mode" == native ]]; then
    # Keep the original development session reachable after changing the default.
    okernel_socket="${OSTADIX_OKERNEL_SOCKET:-ostadix-okernel}"
    okernel_reconnect='okernel native'
else
    okernel_socket="${OSTADIX_OKERNEL_PACKAGE_SOCKET:-ostadix-okernel-package}"
    okernel_reconnect=okernel
fi
okernel_target='okernel:console.0'

usage() {
    cat <<'HELP'
Usage: okernel [COMMAND]
  start [--detach]   Start the prepared persistent OS, or reconnect
  run               Run the prepared OS directly in this terminal
  attach            Reconnect to its tmux session
  status            Show session state and log location
  logs              Print the latest session log
  stop|exit|quit    Ask the OS to sync/save and exit; wait for completion
  restart           Save, stop, and start the prepared OS
  doctor            Check package-console tools and prepared artifacts
  test [OPTIONS]    Verify online packages, shared files, source builds/restart
  verify [OUTPUT]   Compare two native unified-monitor builds
  fork OUTPUT       Copy the saved checkpoint into a new isolated state
  packages COMMAND  Build/test/install packages through the domain runner
  native [COMMAND]  Explicit mode-16 development console and verification
  help              Show these commands

Prepare once: okernel packages build --network --namespace
The default OS uses Linux userspace and a shared native O-core 9P namespace.
Start never rebuilds it. Guest: pkg help. Save/exit: Ctrl+] or Ctrl+B then Q.
Detach without stopping: Ctrl+B then D. Reconnect: okernel.
Native tools: okernel native help; native test; native verify [OUTPUT].
HELP
}
native_usage() {
    cat <<'HELP'
Usage: okernel native [start [--detach]|run|attach|status|logs|stop|restart|doctor|test|verify [OUTPUT]]
The mode-16 kernel development console supports help, status, and bounded
embedded-package install/activation. It has no general shell or writable files.
Native start/run builds current source. Detach: Ctrl+B then D.
Exit native QEMU: Ctrl+A then X. Reconnect: okernel native.
HELP
}
fail_usage() {
    if [[ "$okernel_mode" == native ]]; then native_usage >&2; else usage >&2; fi
    exit 2
}
no_arguments() { if (( $# )); then fail_usage; fi; }
start_arguments() {
    if (( $# > 1 )) || [[ "${1:-}" != '' && "${1:-}" != --detach ]]; then fail_usage; fi
}
session_exists() { tmux -L "$okernel_socket" has-session -t '=okernel' 2>/dev/null; }
pane_dead() { tmux -L "$okernel_socket" display-message -p -t "$okernel_target" '#{pane_dead}'; }
latest_log() {
    local pointer="$okernel_package_state/latest-session" run_directory
    if [[ "$okernel_mode" == native ]]; then pointer="$okernel_state/latest-run"; fi
    if [[ -f "$pointer" ]]; then
        IFS= read -r run_directory < "$pointer" || [[ -n "$run_directory" ]]
        printf '%s/console.log\n' "$run_directory"
    fi
}
require_tools() {
    local tool
    for tool in "$@"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            printf 'Missing prerequisite: %s\n' "$tool" >&2
            return 1
        fi
    done
}
native_environment() {
    if [[ -f "$okernel_root/scripts/bm-dev-env.sh" ]]; then
        source "$okernel_root/scripts/bm-dev-env.sh"
    fi
    export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$okernel_root/target}"
    if [[ -z "${OCORE_QEMU_BIN:-}" ]]; then
        if [[ -x "$HOME/.local/opt/qemu-11.1.3/bin/qemu-system-x86_64" ]]; then
            export OCORE_QEMU_BIN="$HOME/.local/opt/qemu-11.1.3/bin/qemu-system-x86_64"
        else
            export OCORE_QEMU_BIN="$(command -v qemu-system-x86_64 || true)"
        fi
    fi
    if [[ -z "$OCORE_QEMU_BIN" ]]; then
        printf 'Missing prerequisite: qemu-system-x86_64\n' >&2
        return 1
    fi
    export PATH="${OCORE_QEMU_BIN%/*}:$PATH"
}
native_prerequisites() {
    require_tools bash git cargo rustc clang tmux script python3 file "$OCORE_QEMU_BIN"
}
package_environment() {
    okernel_package_qemu="${OSTADIX_OKERNEL_PACKAGE_QEMU:-qemu-system-aarch64}"
    require_tools python3 tmux "$okernel_package_qemu"
    okernel_package_qemu="$(command -v "$okernel_package_qemu")"
}
prepared_package() {
    local manifest="$okernel_package_state/monitor/monitor-profile.json"
    if [[ ! -f "$manifest" ]]; then
        printf 'No prepared integrated OS profile at %s\nRun: okernel packages build --network --namespace\n' "$manifest" >&2
        return 1
    fi
    if ! python3 - "$okernel_root" "$manifest" <<'PY'
import importlib.util
import json
import pathlib
import sys
try:
    root, profile = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    spec = importlib.util.spec_from_file_location("okernel_package_domain", root / "scripts/okernel_package_domain.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    manifest = json.loads(profile.read_bytes())
    runner.validate_profile(manifest)
    if manifest.get("namespace_grant") != runner.NAMESPACE_GRANT:
        raise ValueError("the default OS requires its shared native namespace grant")
    if manifest.get("network_grant") != runner.NETWORK_GRANT:
        raise ValueError("the default OS requires its mediated network grant")
    for name in ("monitor", "guest_dtb", "Image", "initramfs"):
        record = manifest["artifacts"][name]
        runner.checked_file(pathlib.Path(record["path"]), record)
except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
    print(f"Prepared OS validation failed: {error}", file=sys.stderr)
    sys.exit(1)
PY
    then
        printf 'Prepare the required profile explicitly: okernel packages build --network --namespace\n' >&2
        return 1
    fi
}
stop_native() {
    if ! session_exists; then return; fi
    if [[ "$(pane_dead)" != 1 ]]; then
        tmux -L "$okernel_socket" send-keys -t "$okernel_target" C-a
        tmux -L "$okernel_socket" send-keys -t "$okernel_target" -l x
        local attempt
        for attempt in {1..30}; do
            if ! session_exists; then return; fi
            if [[ "$(pane_dead)" == 1 ]]; then break; fi
            sleep 0.1
        done
        if [[ "$(pane_dead)" != 1 ]]; then
            printf 'Native console has not exited; inspect with native status/logs. A build may still be running.\n' >&2
            return 1
        fi
    fi
    tmux -L "$okernel_socket" kill-session -t '=okernel'
}
stop_package() {
    if ! session_exists; then printf 'OKernel is stopped.\n'; return; fi
    local deadline status timeout="${OSTADIX_OKERNEL_STOP_TIMEOUT:-180}"
    if [[ ! "$timeout" =~ ^[0-9]+$ ]] || (( timeout > 3600 )); then
        printf 'OSTADIX_OKERNEL_STOP_TIMEOUT must be an integer from 0 to 3600 seconds.\n' >&2
        return 2
    fi
    if [[ "$(pane_dead)" != 1 ]]; then
        printf 'Requesting filesystem sync and a saved disk/namespace generation.\n'
        tmux -L "$okernel_socket" send-keys -t "$okernel_target" 'C-]'
        deadline=$((SECONDS + timeout))
        while session_exists && [[ "$(pane_dead)" != 1 ]]; do
            if (( SECONDS >= deadline )); then
                printf 'Save/exit is still pending. The VM was left running; inspect okernel logs or reconnect.\n' >&2
                return 1
            fi
            sleep 0.1
        done
    fi
    if session_exists; then
        status="$(tmux -L "$okernel_socket" display-message -p -t "$okernel_target" '#{pane_dead_status}')"
        if [[ "$status" != 0 ]]; then
            printf 'The console exited without a successful save (status %s). Inspect okernel logs.\n' "$status" >&2
            return 1
        fi
        # Only remove a pane whose runner has already exited successfully.
        tmux -L "$okernel_socket" kill-session -t '=okernel'
    fi
    printf 'OKernel saved and stopped.\n'
}
start_session() {
    start_arguments "$@"
    require_tools tmux
    local fresh=1 command
    if session_exists && [[ "$(pane_dead)" != 1 ]]; then fresh=0; fi
    if (( fresh )); then
        if [[ "$okernel_mode" == native ]]; then
            native_environment; native_prerequisites
        else
            package_environment; prepared_package
        fi
        if session_exists; then tmux -L "$okernel_socket" kill-session -t '=okernel'; fi
        # tmux may have been started with an older environment. Pass state and
        # tool selections explicitly, with shell quoting for paths with spaces.
        local -a child=(env "OSTADIX_OKERNEL_STATE=$okernel_state"
            "OSTADIX_OKERNEL_SOCKET=${OSTADIX_OKERNEL_SOCKET:-ostadix-okernel}"
            "OSTADIX_OKERNEL_PACKAGE_SOCKET=${OSTADIX_OKERNEL_PACKAGE_SOCKET:-ostadix-okernel-package}")
        if [[ "$okernel_mode" == native ]]; then
            child+=("OCORE_QEMU_BIN=$OCORE_QEMU_BIN" "$okernel_root/scripts/okernel-console.sh" native run)
        else
            child+=("OSTADIX_OKERNEL_PACKAGE_QEMU=$okernel_package_qemu" "$okernel_root/scripts/okernel-console.sh" run)
        fi
        printf -v command '%q ' "${child[@]}"
        tmux -L "$okernel_socket" -f /dev/null new-session -d -s okernel -n console \
            -x 120 -y 36 "$command" \; set-window-option -t okernel:console remain-on-exit on
    fi
    if [[ "$okernel_mode" == package ]]; then
        tmux -L "$okernel_socket" bind-key -T prefix q send-keys -t "$okernel_target" 'C-]'
    fi
    if [[ "${1:-}" == --detach || ! -t 0 || ! -t 1 ]]; then
        printf 'OKernel session ready. Reconnect with: %s attach\n' "$okernel_reconnect"
    else
        exec tmux -L "$okernel_socket" attach-session -t '=okernel'
    fi
}

case "$okernel_action" in
    help|--help|-h) if [[ "$okernel_mode" == native ]]; then native_usage; else usage; fi ;;
    fork)
        if [[ "$okernel_mode" != package || "$#" != 1 ]]; then fail_usage; fi
        require_tools python3
        exec python3 "$okernel_root/scripts/fork_okernel_state.py" --source "$okernel_package_state" --output "$1"
        ;;
    start) start_session "$@" ;;
    attach)
        no_arguments "$@"
        if [[ "$okernel_mode" == package ]]; then
            tmux -L "$okernel_socket" bind-key -T prefix q send-keys -t "$okernel_target" 'C-]'
        fi
        exec tmux -L "$okernel_socket" attach-session -t '=okernel'
        ;;
    status)
        no_arguments "$@"
        if session_exists; then
            tmux -L "$okernel_socket" list-panes -t '=okernel' \
                -F 'OKernel session: pane_pid=#{pane_pid} exited=#{pane_dead} command=#{pane_current_command}'
        else
            printf 'OKernel is stopped. Start with: %s\n' "$okernel_reconnect"
        fi
        printf 'Log: %s\n' "$(latest_log)"
        ;;
    logs)
        no_arguments "$@"; okernel_log="$(latest_log)"
        if [[ -z "$okernel_log" || ! -f "$okernel_log" ]]; then printf 'No console log is available.\n' >&2; exit 1; fi
        tail -n 100 -- "$okernel_log"
        ;;
    stop)
        no_arguments "$@"
        if [[ "$okernel_mode" == native ]]; then stop_native; else stop_package; fi
        ;;
    restart)
        start_arguments "$@"
        if [[ "$okernel_mode" == native ]]; then stop_native; exec "$okernel_root/scripts/okernel-console.sh" native start "$@"; fi
        stop_package
        exec "$okernel_root/scripts/okernel-console.sh" start "$@"
        ;;
    packages|test)
        if [[ "$okernel_mode" == native ]]; then
            if [[ "$okernel_action" != test ]]; then fail_usage; fi
            native_environment; native_prerequisites; cd "$okernel_root"
            mkdir -p "$okernel_state"
            okernel_test="$(mktemp -d "$okernel_state/test.XXXXXXXX")"
            export OCORE_BUILD_DIR="$okernel_test/kernel" OCORE_M5_BUILD_DIR="$okernel_test/m5"
            ./ocore/kernel/smoke-live-qemu.sh 2>&1 | tee "$okernel_test/lifecycle.log"
        else
            if [[ "$okernel_action" == test ]]; then
                package_environment; prepared_package
                exec python3 "$okernel_root/scripts/verify_okernel_unified.py" --state "$okernel_package_state" --qemu "$okernel_package_qemu" "$@"
            fi
            # Explicit builds can select the checkout's compiler/linker tools;
            # starting an already prepared OS never sources this helper.
            if [[ "${1:-}" == build && -f "$okernel_root/scripts/bm-dev-env.sh" ]]; then source "$okernel_root/scripts/bm-dev-env.sh"; fi
            exec python3 "$okernel_root/scripts/okernel_package_domain.py" --state "$okernel_package_state" "$@"
        fi
        ;;
    doctor|run|verify)
        if [[ "$okernel_mode" == native ]]; then
            native_environment; native_prerequisites; cd "$okernel_root"
            case "$okernel_action" in
                doctor)
                    printf 'Source: %s\n' "$okernel_root"
                    git log -1 --format='Base revision: %H'
                    printf 'Cargo jobs: %s\n' "$CARGO_BUILD_JOBS"
                    cargo --version; rustc --version; clang --version; "$OCORE_QEMU_BIN" --version
                    ;;
                verify)
                    mkdir -p "$okernel_state"
                    cargo build --locked --package o-lang --bin ocorec
                    okernel_output="${1:-$okernel_state/verification-$(date -u +%Y%m%dT%H%M%S%N)}"
                    exec python3 scripts/verify_okernel_repro.py --source "$okernel_root" \
                        --output "$okernel_output" --ocorec "$CARGO_TARGET_DIR/debug/ocorec" --qemu "$OCORE_QEMU_BIN"
                    ;;
                run)
                    no_arguments "$@"; mkdir -p "$okernel_state"
                    okernel_run="$(mktemp -d "$okernel_state/run.XXXXXXXX")"
                    printf '%s\n' "$okernel_run" > "$okernel_state/latest-run"
                    unset OCOREC_BIN
                    export OCORE_PROBE_MODE=16 OCORE_BUILD_DIR="$okernel_run/kernel" OCORE_M5_BUILD_DIR="$okernel_run/m5"
                    printf 'Building the native OKernel development console (Cargo jobs: %s).\n' "$CARGO_BUILD_JOBS"
                    printf 'Log: %s/console.log\nDetach: Ctrl+B then D. Reconnect: okernel native. Exit QEMU: Ctrl+A then X.\n\n' "$okernel_run"
                    exec script --quiet --flush --return --command 'exec bash ./ocore/kernel/run-qemu.sh' "$okernel_run/console.log"
                    ;;
            esac
        else
            if [[ "$okernel_action" == verify ]]; then
                if [[ -f "$okernel_root/scripts/bm-dev-env.sh" ]]; then source "$okernel_root/scripts/bm-dev-env.sh"; fi
                okernel_output="$okernel_state/verification-unified-$(date -u +%Y%m%dT%H%M%S%N)"
                if (( $# )) && [[ "$1" != -* ]]; then okernel_output="$1"; shift; fi
                okernel_backing_bytes="$(python3 - "$okernel_root" "$okernel_package_state" <<'PY'
import importlib.util
import pathlib
import sys
root, state = map(pathlib.Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("okernel_package_domain", root / "scripts/okernel_package_domain.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
print(runner.selected_disk_bytes(state))
PY
)"
                exec python3 "$okernel_root/scripts/verify_okernel_unified_repro.py" --source "$okernel_root" \
                    --payload "$okernel_package_state/payload" --output "$okernel_output" --backing-bytes "$okernel_backing_bytes" "$@"
            fi
            no_arguments "$@"; package_environment; prepared_package
            if [[ "$okernel_action" == doctor ]]; then
                printf 'Source: %s\nState: %s\nPython: ' "$okernel_root" "$okernel_package_state"
                python3 --version; "$okernel_package_qemu" --version; tmux -V
                printf 'Prepared network and shared native namespace grants: valid\n'
            else
                exec python3 "$okernel_root/scripts/okernel_package_domain.py" run --state "$okernel_package_state" --qemu "$okernel_package_qemu"
            fi
        fi
        ;;
    *) fail_usage ;;
esac
