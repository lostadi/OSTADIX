#!/usr/bin/env bash
# An explicit, persistent terminal for the separately prepared two-kernel state.
set -euo pipefail

script_directory=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository=$(CDPATH= cd -- "$script_directory/.." && pwd -P)
runner="$script_directory/okernel_unified_world.py"
action=""
state=""
build=""
detach=0
stop_timeout=120
qemu="${OSTADIX_OKERNEL_UNIFIED_QEMU:-qemu-system-aarch64}"
session=okernel-unified
target='=okernel-unified:console.0'

usage() {
    cat <<'EOF'
Usage: okernel-unified-console.sh --state STATE --build BUILD ACTION [OPTIONS]

Actions: help, status, start, attach, stop (also exit or quit)
  start --detach       Start without attaching, or reconnect to the same session
  attach               Attach a real terminal to the existing session
  stop                 Request Ctrl+] and wait for a confirmed paired save

Options: --qemu PATH, --stop-timeout SECONDS (default 120)

STATE must be an explicitly forked private state. BUILD must contain its
prepared unified monitor profile. This launcher never builds or selects the
default working OS. Status does not change the saved head.

Guest console: Ctrl-^ then 0 selects Linux; Ctrl-^ then 1 selects original Plan9.
Save and stop: Ctrl+] or Ctrl+B then q. Detach: Ctrl+B then d.
Rerun with the same --state and --build to reconnect or resume its saved pair.
Requires Python 3, tmux, and an AArch64 QEMU; O is not a runtime dependency.
EOF
}
fail() { printf 'Unified console: %s\n' "$*" >&2; exit 2; }

while (( $# )); do
    case "$1" in
        --state|--build|--qemu|--stop-timeout)
            (( $# >= 2 )) || fail "$1 needs a value"
            case "$1" in
                --state) state=$2 ;;
                --build) build=$2 ;;
                --qemu) qemu=$2 ;;
                --stop-timeout) stop_timeout=$2 ;;
            esac
            shift 2 ;;
        --detach) detach=1; shift ;;
        -h|--help|help) usage; exit 0 ;;
        status|start|attach|stop)
            [[ -z "$action" ]] || fail 'choose one action'
            action=$1; shift ;;
        exit|quit)
            [[ -z "$action" ]] || fail 'choose one action'
            action=stop; shift ;;
        *) fail "unknown argument: $1" ;;
    esac
done
[[ -n "$action" ]] || { usage >&2; exit 2; }
[[ -n "$state" && -n "$build" ]] || fail 'both --state and --build are required'
[[ "$stop_timeout" =~ ^[1-9][0-9]*$ ]] && (( stop_timeout <= 600 )) \
    || fail '--stop-timeout must be an integer from 1 to 600'
[[ "$action" == start || "$detach" == 0 ]] || fail '--detach applies only to start'
python=$(command -v python3) || fail 'python3 is required'
command -v tmux >/dev/null || fail 'tmux is required'

# Resolve once without modifying the selected state. Reuse the runner's exact
# profile/head checks so this entry cannot loosen the native memory grants.
if ! resolved=$("$python" -B - "$repository" "$state" "$build" <<'PY'
import hashlib, importlib.util, json, os, sys
from pathlib import Path
root, state, build = map(Path, sys.argv[1:])
try:
    if state.is_symlink():
        raise ValueError('state must not be a symlink')
    state, build = state.expanduser().resolve(strict=True), build.expanduser().resolve(strict=True)
    if not state.is_dir() or not build.is_dir():
        raise ValueError('state and build must be prepared directories')
    if any(c in str(path) for path in (state, build) for c in '\r\n'):
        raise ValueError('state/build paths must not contain line breaks')
    spec = importlib.util.spec_from_file_location('unified_launcher_validation', root / 'scripts/okernel_unified_world.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    configured = Path(os.environ.get('OSTADIX_OKERNEL_STATE') or str(runner.common.DEFAULT_STATE.parent)) / 'package-domain'
    if state in (runner.common.DEFAULT_STATE.resolve(), configured.expanduser().resolve()):
        raise ValueError('the working package-domain state is not a unified console target')
    fork = json.loads((state / 'fork.json').read_text())
    if fork.get('schema') != 'ostadix.okernel-state-fork/v1' or fork.get('ok') is not True or fork.get('output') != str(state):
        raise ValueError('use an explicitly copied, isolated state fork')
    runner.validate_profile(json.loads((build / 'monitor-profile.json').read_text()))
    head_file = state / 'head.json'
    if head_file.is_symlink():
        raise ValueError('saved head must not be a symlink')
    data = head_file.read_bytes()
    head = json.loads(data)
    runner.common.validate_head(state, head)
    if head['disk']['bytes'] != runner.DISK_BYTES or not head.get('namespace'):
        raise ValueError('a saved 1GiB disk/native-store pair is required')
    print(state)
    print(build)
    print('ostadix-unified-' + hashlib.sha256(os.fsencode(state)).hexdigest()[:24])
    print(hashlib.sha256(data).hexdigest())
except (OSError, ValueError, KeyError, TypeError) as error:
    print('Unified console: ' + str(error), file=sys.stderr)
    raise SystemExit(2)
PY
); then exit 2; fi
mapfile -t fields <<< "$resolved"
state=${fields[0]}
build=${fields[1]}
socket=${fields[2]}
before_head=${fields[3]}

tm() { tmux -L "$socket" "$@"; }
exists() { tm has-session -t "=$session" 2>/dev/null; }
option() { tm show-options -qv -t "=$session:" "$1"; }
dead() { tm display-message -p -t "$target" '#{pane_dead}'; }
owned() {
    [[ "$(option @okernel-unified-state)" == "$state" ]] \
        && [[ "$(option @okernel-unified-build)" == "$build" ]] \
        || fail 'the existing private session belongs to a different state/build; use its original arguments'
}
attach() {
    [[ -t 0 && -t 1 ]] || fail 'attach requires a real foreground terminal; use start --detach'
    exec tmux -L "$socket" attach-session -t "=$session"
}
confirm_save() {
    "$python" -B - "$state" "$1" <<'PY'
import hashlib, json, sys
from pathlib import Path
state, before = Path(sys.argv[1]), sys.argv[2]
try:
    data = (state / 'head.json').read_bytes()
    if hashlib.sha256(data).hexdigest() == before:
        raise ValueError('the controller did not publish a new saved pair')
    head = json.loads(data)
    session = Path(head['session'])
    if session.parent != state or not session.name.startswith('unified-session-'):
        raise ValueError('the selected save does not belong to this unified state')
    result = json.loads((session / 'result.json').read_text())
    if (head.get('schema') != 'ostadix.package-domain-disk-head/v2'
            or result.get('schema') != 'ostadix.unified-world-session/v1'
            or result.get('ok') is not True or result.get('after') != head
            or any(result.get(key) is not True for key in
                   ('paired_snapshot', 'virtual_cpu_stopped', 'native_operations_quiescent'))):
        raise ValueError('the controller has not confirmed a complete paired save')
    print('Saved disk: ' + head['disk']['sha256'])
    print('Saved namespace: ' + head['namespace']['sha256'])
    print('Evidence: ' + str(session / 'result.json'))
except (OSError, ValueError, KeyError, TypeError) as error:
    print('Unified save not confirmed: ' + str(error), file=sys.stderr)
    raise SystemExit(1)
PY
}

case "$action" in
    status)
        printf 'State: %s\nBuild: %s\n' "$state" "$build"
        if exists; then
            owned
            if [[ "$(dead)" == 1 ]]; then
                printf 'Console stopped (exit %s).\n' "$(tm display-message -p -t "$target" '#{pane_dead_status}')"
            else
                printf 'Console running. Detach: Ctrl+B then D. Save/stop: Ctrl+].\n'
            fi
        else printf 'Console not running.\n'; fi
        ;;
    start)
        if exists; then
            owned
            if [[ "$(dead)" == 1 ]]; then tm kill-session -t "=$session"; fi
        fi
        if ! exists; then
            qemu=$(command -v "$qemu") || fail 'the selected qemu-system-aarch64 is unavailable'
            # Multiple command arguments make tmux exec directly, avoiding an
            # intermediary shell and its quoting or backend-operation deadline.
            tm -f /dev/null new-session -d -s "$session" -n console -x 120 -y 36 \
                -e "PATH=$PATH" -e PYTHONUNBUFFERED=1 \
                "$python" -B "$runner" run --state "$state" --build "$build" --qemu "$qemu" \
                \; set-window-option -t "$session:console" remain-on-exit failed \
                \; set-option -t "=$session:" @okernel-unified-state "$state" \
                \; set-option -t "=$session:" @okernel-unified-build "$build" \
                \; set-option -t "=$session:" @okernel-unified-before-head "$before_head"
        fi
        tm bind-key -T prefix q send-keys -t "$target" 'C-]'
        if (( detach )) || [[ ! -t 0 || ! -t 1 ]]; then
            printf 'Unified console ready. Reconnect with the same --state and --build.\n'
        else attach; fi
        ;;
    attach)
        exists || fail 'the private console is not running; use start'
        owned
        [[ "$(dead)" != 1 ]] || fail 'the console has stopped; use start to resume its saved pair'
        tm bind-key -T prefix q send-keys -t "$target" 'C-]'
        attach
        ;;
    stop)
        if ! exists; then printf 'Unified console is already stopped.\n'; exit 0; fi
        owned
        started_before=$(option @okernel-unified-before-head)
        if [[ "$(dead)" != 1 ]]; then
            printf 'Requesting both original shells and a paired disk/namespace save.\n'
            tm send-keys -t "$target" 'C-]'
        fi
        for (( waited=0; waited <= stop_timeout; waited++ )); do
            if ! exists; then
                confirm_save "$started_before" || exit 1
                printf 'Unified console saved and stopped.\n'
                exit 0
            fi
            if [[ "$(dead)" == 1 ]]; then
                code=$(tm display-message -p -t "$target" '#{pane_dead_status}')
                [[ "$code" == 0 ]] || fail "controller exited $code; its pane and evidence are retained"
                confirm_save "$started_before" || exit 1
                tm kill-session -t "=$session"
                printf 'Unified console saved and stopped.\n'
                exit 0
            fi
            (( waited < stop_timeout )) && sleep 1
        done
        fail 'save is not confirmed; the running console is retained for inspection and retry'
        ;;
esac
