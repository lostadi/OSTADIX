#ifndef O_LANG_BACKENDS_H
#define O_LANG_BACKENDS_H

#include "parser.h"

/* Keep parser registration and AOT shim publication on the same list. These
   are the generic wire-protocol adapters shipped in backends/, not a claim
   that their external runtimes are installed on the target machine. */
#define OLANG_SHIM_BACKENDS(X) \
    X(python) \
    X(nix) \
    X(nix_store) \
    X(nixos_test) \
    X(bash) \
    X(shell) \
    X(rust) \
    X(racket) \
    X(javascript) \
    X(common_lisp) \
    X(lisp) \
    X(cpp) \
    X(csharp) \
    X(haskell) \
    X(java) \
    X(mathematica) \
    X(matlab) \
    X(ocaml) \
    X(ruby) \
    X(sql) \
    X(ubuntu_vm) \
    X(webassembly)

static inline StringSet *olang_default_backends(void) {
#define OLANG_BACKEND_TAG(name) #name,
    const char *tags[] = {
        "O", "html", "latex", "markdown", "text", "quote", "nix_expr",
        OLANG_SHIM_BACKENDS(OLANG_BACKEND_TAG)
        NULL
    };
#undef OLANG_BACKEND_TAG
    StringSet *backends = string_set_new();
    if (!backends) return NULL;
    for (size_t i = 0; tags[i]; ++i) {
        string_set_add(backends, tags[i]);
        if (!string_set_contains(backends, tags[i])) {
            string_set_free(backends);
            return NULL;
        }
    }
    return backends;
}

#endif
