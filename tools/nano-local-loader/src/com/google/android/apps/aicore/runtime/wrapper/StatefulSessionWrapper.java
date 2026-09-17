package com.google.android.apps.aicore.runtime.wrapper;

/** ABI declarations matching stock StatefulSessionWrapper nested callback names. */
public final class StatefulSessionWrapper {
    public interface Controller { int process(float progress); }
    public interface ControllingStreamingConsumer { int accept(String text, float progress, byte[] metadata); }

    private native byte[] nativeGenerateResponse(long handle, byte[] request, Controller controller);
    private native byte[] nativeStreamResponse(long handle, byte[] request, ControllingStreamingConsumer consumer);
    private native void nativeUnload(long handle);

    public byte[] generate(long handle, byte[] request, Controller controller) {
        if (handle == 0) throw new IllegalArgumentException("zero session handle");
        return nativeGenerateResponse(handle, request, controller);
    }

    public byte[] stream(long handle, byte[] request, ControllingStreamingConsumer consumer) {
        if (handle == 0) throw new IllegalArgumentException("zero session handle");
        return nativeStreamResponse(handle, request, consumer);
    }

    public void unload(long handle) {
        if (handle == 0) throw new IllegalArgumentException("zero session handle");
        nativeUnload(handle);
    }
}
