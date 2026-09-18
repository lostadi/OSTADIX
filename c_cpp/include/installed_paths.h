#ifndef OLANG_INSTALLED_PATHS_H
#define OLANG_INSTALLED_PATHS_H

/* Optional CLI installation metadata. This header is shared by the two C
 * command entry points; it is not part of backend or generated-program dispatch. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#include "value.h"

static inline char *olang_path_join(const char *left, const char *right) {
    size_t a = strlen(left), b = strlen(right);
    if (b > SIZE_MAX - 2U || a > SIZE_MAX - b - 2U) return NULL;
    char *out = malloc(a + b + 2U);
    if (out) {
        memcpy(out, left, a);
        out[a] = '/';
        memcpy(out + a + 1U, right, b + 1U);
    }
    return out;
}

static inline int olang_path_is_dir(const char *path) {
    struct stat status;
    return path && stat(path, &status) == 0 && S_ISDIR(status.st_mode);
}

static inline char *olang_executable_path(const char *argv0) {
#if defined(__APPLE__)
    char first;
    uint32_t size = 1;
    if (_NSGetExecutablePath(&first, &size) != 0 && size > 1) {
        char *buffer = malloc(size);
        if (buffer) {
            char *resolved = _NSGetExecutablePath(buffer, &size) == 0 ? realpath(buffer, NULL) : NULL;
            free(buffer);
            if (resolved) return resolved;
        }
    }
#elif defined(__linux__)
    for (size_t size = 256U; size <= SIZE_MAX / 2U; size *= 2U) {
        char *buffer = malloc(size);
        if (!buffer) break;
        ssize_t length = readlink("/proc/self/exe", buffer, size - 1U);
        if (length >= 0 && (size_t)length < size - 1U) {
            buffer[length] = '\0';
            return buffer;
        }
        free(buffer);
        if (length < 0) break;
    }
#endif
    if (!argv0 || !*argv0) return NULL;
    if (strchr(argv0, '/')) return realpath(argv0, NULL);
    const char *search = getenv("PATH");
    if (!search) return NULL;
    const char *start = search;
    do {
        const char *end = strchr(start, ':');
        size_t length = end ? (size_t)(end - start) : strlen(start);
        char *directory = malloc(length + 1U);
        if (!directory) return NULL;
        memcpy(directory, start, length);
        directory[length] = '\0';
        char *candidate = olang_path_join(length ? directory : ".", argv0);
        free(directory);
        char *resolved = candidate && access(candidate, X_OK) == 0 ? realpath(candidate, NULL) : NULL;
        free(candidate);
        if (resolved) return resolved;
        start = end ? end + 1 : NULL;
    } while (start);
    return NULL;
}

/* Return an absolute field, resolving relative metadata against its own
 * executable directory. Invalid/absent metadata keeps build-tree fallback. */
static inline char *olang_installed_path(const char *argv0, const char *field) {
    char *directory = olang_executable_path(argv0);
    if (!directory) return NULL;
    char *slash = strrchr(directory, '/');
    if (!slash) { free(directory); return NULL; }
    if (slash == directory) slash[1] = '\0'; else *slash = '\0';
    char *manifest = olang_path_join(directory, "ostadix-install.json");
    FILE *stream = manifest ? fopen(manifest, "rb") : NULL;
    free(manifest);
    char *json = NULL;
    if (stream && fseek(stream, 0, SEEK_END) == 0) {
        long length = ftell(stream);
        if (length >= 0 && (uintmax_t)length < SIZE_MAX && fseek(stream, 0, SEEK_SET) == 0) {
            json = malloc((size_t)length + 1U);
            if (json) {
                size_t read = fread(json, 1, (size_t)length, stream);
                json[read] = '\0';
                if (read != (size_t)length || ferror(stream)) { free(json); json = NULL; }
            }
        }
    }
    if (stream) fclose(stream);
    int64_t schema = 0;
    char *schema_name = oval_json_object_string(json, "schema");
    int valid = (oval_json_object_int(json, "schema", &schema) && schema == 1) ||
                (schema_name && strcmp(schema_name, "ostadix.install/v1") == 0);
    free(schema_name);
    char *value = valid ? oval_json_object_string(json, field) : NULL;
    free(json);
    if (value && !*value) { free(value); value = NULL; }
    if (value && value[0] != '/') {
        char *absolute = olang_path_join(directory, value);
        free(value);
        value = absolute;
    }
    free(directory);
    return value;
}

static inline char *olang_installed_backends(const char *argv0) {
    char *path = olang_installed_path(argv0, "backends_dir");
    if (!path) {
        char *repo = olang_installed_path(argv0, "repo_root");
        path = repo ? olang_path_join(repo, "backends") : NULL;
        free(repo);
    }
    if (path && !olang_path_is_dir(path)) { free(path); return NULL; }
    return path;
}

#endif
