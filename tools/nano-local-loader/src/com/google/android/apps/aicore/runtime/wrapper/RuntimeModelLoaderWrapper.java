package com.google.android.apps.aicore.runtime.wrapper;

/** Only the native runtime destructor is exposed by this initialization probe. */
public final class RuntimeModelLoaderWrapper {
    private native void nativeFree(long handle);
    private static native long nativeLoadModel(long handle, byte[] config);

    public static long loadModel(long handle, byte[] config) {
        if (handle == 0) throw new IllegalArgumentException("zero runtime handle");
        return nativeLoadModel(handle, config);
    }

    public void free(long handle) {
        if (handle == 0) throw new IllegalArgumentException("zero runtime handle");
        nativeFree(handle);
    }
}
