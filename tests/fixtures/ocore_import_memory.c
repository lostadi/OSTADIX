/* Original headerless frontend witness. No rewritten or stripped LLVM input. */
typedef unsigned char byte;
typedef __SIZE_TYPE__ size_type;
typedef unsigned long long u64;

__attribute__((noinline))
void frontend_copy(byte *destination, const byte *source, size_type length) {
    /* Native LLVM memcpy admits equality. Keep the original C witness within
     * its own builtin preconditions by handling equality before that call. */
    if (destination != source)
        __builtin_memcpy(destination, source, length);
}

__attribute__((noinline))
void frontend_move(byte *destination, const byte *source, size_type length) {
    __builtin_memmove(destination, source, length);
}

__attribute__((noinline))
void frontend_set(byte *destination, int fill, size_type length) {
    __builtin_memset(destination, fill, length);
}

/* The explicit test dependency forces the original local array to escape and
 * retains lifetime markers. Its independently compiled carrier implementation
 * mutates the first/last bytes; it is not an ambient language engine fallback. */
extern void opaque_escape(byte *array, size_type length);

__attribute__((noinline))
u64 frontend_lifetime(u64 fill) {
    byte local[64];
    __builtin_memset(local, (int)fill, sizeof(local));
    opaque_escape(local, sizeof(local));
    return (u64)local[0] | ((u64)local[63] << 8);
}
