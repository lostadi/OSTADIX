package com.google.android.apps.aicore.runtime.wrapper;

/** ABI declarations for unloading and token inspection; no generation entrypoint. */
public final class LargeLanguageModelWrapper {
    private native void nativeUnload(long handle);
    private native byte[] nativeGetTokenInfo(long handle, byte[] request);
    private native long nativeCreateSession(long handle, byte[] config);

    public long createSession(long handle, byte[] config) {
        if (handle == 0) throw new IllegalArgumentException("zero model handle");
        return nativeCreateSession(handle, config);
    }

    public void unload(long handle) {
        if (handle == 0) throw new IllegalArgumentException("zero model handle");
        nativeUnload(handle);
    }

    public byte[] getTokenInfo(long handle, byte[] request) {
        if (handle == 0) throw new IllegalArgumentException("zero model handle");
        return nativeGetTokenInfo(handle, request);
    }
}
