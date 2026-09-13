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
        network_source=bochs/wasm.cc
        network_expected=11f064262c1027618c729966a14f8407326dff061c745f60b44ffcebad3bb9a7
        patch=/ostadix-exit/bochs.patch
        ;;
    bochs-state-config)
        source=/bochsrc.template
        expected=6449e36f254efea5c6c7c8885da3a717914fd3b7ee0a191062a6ecd7a222138d
        actual=$(sha256sum "$source")
        actual=${actual%% *}
        if [ "$actual" != "$expected" ]; then
            printf '%s\n' 'refusing browser-state configuration: unexpected Bochs template SHA-256' >&2
            exit 1
        fi
        sed 's@^usb_ehci: port1=cdrom, options1="path:/pack/rootfs.bin, speed:high"$@usb_ehci: port1=cdrom, options1="path:/pack/rootfs.bin, speed:high", port2=disk, options2="path:/browser-state/guix.img, speed:high"@' "$source" > /bochsrc.state.template
        mv /bochsrc.state.template "$source"
        exit 0
        ;;
    *)
        printf '%s\n' 'usage: apply.sh init|bochs|bochs-state-config' >&2
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
    actual=$(sha256sum "$network_source")
    actual=${actual%% *}
    if [ "$actual" != "$network_expected" ]; then
        printf 'refusing network patch: unexpected SHA-256 for %s\n' "$network_source" >&2
        exit 1
    fi
    git apply --check --unidiff-zero --whitespace=error /ostadix-exit/bochs-network.patch
fi
git apply --check --whitespace=error "$patch"
git apply --whitespace=error "$patch"
if [ "$1" = bochs ]; then
    git apply --unidiff-zero --whitespace=error /ostadix-exit/bochs-network.patch
fi
if [ "$1" = init ]; then
    cp /ostadix-exit/exit_status_linux_amd64.go cmd/init/exit_status_linux_amd64.go
    cp /ostadix-exit/browser_guix_state_linux_amd64.go cmd/init/browser_guix_state_linux_amd64.go
fi
