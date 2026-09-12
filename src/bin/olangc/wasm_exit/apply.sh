#!/bin/sh
# Apply only to the exact upstream files reviewed for this exit protocol.
set -eu

case "${1-}" in
    init)
        tree=/work
        source=cmd/init/main.go
        expected=d6a53a0acbfbe58ddb57dd262c3af7d768354d620ca72914a79aae0768658fac
        patch=/ostadix-exit/init.patch
        ;;
    bochs)
        tree=/Bochs
        source=bochs/iodev/unmapped.cc
        expected=bb07a42be89d27e2f857aae7c9af9a06435be22f5719baf55129ca7d8022ca21
        config_source=bochs/config.cc
        config_expected=2932eb64b3e1290c136c768ca5e6b334f8bd227d835e81450a743c39705ef63a
        msr_source=bochs/cpu/msr.cc
        msr_expected=4d7fde6fa6869e462eedf2a9d8b223e8cb2a2aed1e56c28619e1e8cd226fbc09
        patch=/ostadix-exit/bochs.patch
        ;;
    *)
        printf '%s\n' 'usage: apply.sh init|bochs' >&2
        exit 1
        ;;
esac

cd "$tree"
actual=$(sha256sum "$source")
actual=${actual%% *}
if [ "$actual" != "$expected" ]; then
    printf 'refusing exit-status patch: unexpected SHA-256 for %s\n' "$source" >&2
    exit 1
fi
if [ "$1" = bochs ]; then
    actual=$(sha256sum "$config_source")
    actual=${actual%% *}
    if [ "$actual" != "$config_expected" ]; then
        printf 'refusing exit-status patch: unexpected SHA-256 for %s\n' "$config_source" >&2
        exit 1
    fi
    actual=$(sha256sum "$msr_source")
    actual=${actual%% *}
    if [ "$actual" != "$msr_expected" ]; then
        printf 'refusing exit-status patch: unexpected SHA-256 for %s\n' "$msr_source" >&2
        exit 1
    fi
fi
git apply --check --whitespace=error "$patch"
git apply --whitespace=error "$patch"
if [ "$1" = init ]; then
    cp /ostadix-exit/exit_status_linux_amd64.go cmd/init/exit_status_linux_amd64.go
fi
