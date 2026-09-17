#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef const char *(*get_string_fn)(void);
typedef int (*initialize_fn)(void);
typedef void *(*context_create_fn)(void);
typedef int (*context_delete_fn)(void *);

static void *required_symbol(void *handle, const char *name) {
    dlerror();
    void *symbol = dlsym(handle, name);
    const char *error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "dlsym(%s) failed: %s\n", name, error);
        exit(3);
    }
    return symbol;
}

int main(void) {
    const char *library_name = "libedgetpu_litert.so";
    void *handle = dlopen(library_name, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen(%s) failed: %s\n", library_name, dlerror());
        return 2;
    }

    get_string_fn get_version =
            (get_string_fn)required_symbol(handle, "thrGetVendorApiVersion");
    get_string_fn get_vendor =
            (get_string_fn)required_symbol(handle, "thrGetVendorId");
    initialize_fn initialize =
            (initialize_fn)required_symbol(handle, "thrInitialize");
    context_create_fn create_context =
            (context_create_fn)required_symbol(handle, "thrContextCreate");
    context_delete_fn delete_context =
            (context_delete_fn)required_symbol(handle, "thrContextDelete");

    printf("library=%s\n", library_name);
    printf("vendor_api_version=%s\n", get_version());
    printf("vendor_id=%s\n", get_vendor());

    int status = initialize();
    printf("initialize_status=%d\n", status);
    if (status != 0) {
        dlclose(handle);
        return 4;
    }

    void *context = create_context();
    printf("context_create=%s\n", context != NULL ? "non-null" : "null");
    if (context == NULL) {
        dlclose(handle);
        return 5;
    }

    status = delete_context(context);
    printf("context_delete_status=%d\n", status);
    dlclose(handle);
    return status == 0 ? 0 : 6;
}
