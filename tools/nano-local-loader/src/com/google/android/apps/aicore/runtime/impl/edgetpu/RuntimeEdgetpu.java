package com.google.android.apps.aicore.runtime.impl.edgetpu;

/** ABI declaration for the installed library; this does not implement Nano. */
public final class RuntimeEdgetpu {
    private RuntimeEdgetpu() {}
    private static native long nativeCreate();

    public static long create() {
        return nativeCreate();
    }
}
