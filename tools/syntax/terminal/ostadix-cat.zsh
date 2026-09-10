# Interactive Ostadix file viewing. Source from .zshrc.
# Options, stdin, mixed file types, pipes and redirects keep system cat semantics.
if [[ -o interactive ]]; then
    unalias cat 2>/dev/null
    function cat {
        local ostadix_file ostadix_viewer
        if [[ ! -t 1 || $# -eq 0 || -n ${NO_COLOR-} || ${TERM-} == dumb ]]; then
            command cat "$@"
            return $?
        fi
        for ostadix_file in "$@"; do
            if [[ "$ostadix_file" == -* || ! -f "$ostadix_file" ]]; then
                command cat "$@"
                return $?
            fi
            case "$ostadix_file" in
                *.O | *.olang) ;;
                *) command cat "$@"; return $? ;;
            esac
        done
        ostadix_viewer=${commands[bat]:-${commands[batcat]-}}
        if [[ -n "$ostadix_viewer" ]]; then
            "$ostadix_viewer" --no-config --paging=never --style=plain --color=auto -- "$@"
        else
            command cat "$@"
        fi
    }
fi
