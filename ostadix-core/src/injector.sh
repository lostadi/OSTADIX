#!/usr/bin/env bash
# src/injector.sh
# Detects the user's shell and injects Ostadix Lisp keybindings
# into a temporary shell session without permanently modifying dotfiles.

TARGET_SHELL=$1

if [[ "$TARGET_SHELL" == *"zsh"* ]]; then
    tmp_rc=$(mktemp)
    cat << 'ZSHEOF' > "$tmp_rc"
    # Source standard user config
    if [ -f "$HOME/.zshrc" ]; then source "$HOME/.zshrc"; fi

    # --- Ostadix ZLE Widget ---
    # Intercepts Enter. If the buffer is a Lisp form (...), route to SBCL.
    # Otherwise, execute normally as a standard Zsh command.
    ostadix-eval() {
        if [[ "$BUFFER" =~ ^\(.*\)$ ]]; then
            echo -e "\n\033[35m[Ostadix Orchestrating via SBCL...]\033[0m"
            sbcl --noinform \
                 --eval "(progn \
                            (load \"$HOME/.config/ostadix/ostadix.lisp\") \
                            (eval (read-from-string \"$BUFFER\")) \
                            (quit))"
            BUFFER=""
            zle accept-line
        else
            zle accept-line
        fi
    }
    zle -N ostadix-eval
    bindkey '^M' ostadix-eval

    # Visual prompt indicator
    export PROMPT="%F{cyan}ostadix%f-zsh %~ ❯ "
ZSHEOF
    ZDOTDIR=$(dirname "$tmp_rc") exec zsh

elif [[ "$TARGET_SHELL" == *"fish"* ]]; then
    exec fish --init-command "
        function bind_ostadix_eval
            set cmd (commandline)
            if string match -q -r '^\(.*\)$' \"\$cmd\"
                echo -e '\\n\\e[35m[Ostadix Orchestrating via SBCL...]\\e[0m'
                commandline -r \"sbcl --noinform --eval \\\"(progn (load (quote ~/.config/ostadix/ostadix.lisp)) (eval (read-from-string \\\\\\\"'\$cmd'\\\\\\\")) (quit))\\\"\"
                commandline -f execute
            else
                commandline -f execute
            end
        end
        bind \r bind_ostadix_eval
        set -gx fish_prompt '(ostadix-fish) '
    "

elif [[ "$TARGET_SHELL" == *"bash"* ]]; then
    tmp_rc=$(mktemp)
    cat << 'BASHEOF' > "$tmp_rc"
    if [ -f "$HOME/.bashrc" ]; then source "$HOME/.bashrc"; fi

    # Explicit CLI fallback for Bash (Readline injection is fragile)
    ostadix() {
        sbcl --noinform \
             --eval "(progn \
                        (load \"$HOME/.config/ostadix/ostadix.lisp\") \
                        (eval (read-from-string \"$1\")) \
                        (quit))"
    }
    export PS1="\[\e[36m\]ostadix\[\e[0m\]-bash \W ❯ "
    echo "[Ostadix] Bash active. Use: ostadix '(your-lisp-form)'"
BASHEOF
    exec bash --rcfile "$tmp_rc"

else
    # Generic POSIX fallback
    echo "[Ostadix] Unknown shell '$TARGET_SHELL'. Launching bare sbcl REPL."
    exec sbcl --noinform
fi
