package com.google.android.apps.aicore.base;

/** Constructor ABI used by the installed native runtime for initialization errors. */
public final class InferenceException extends Exception {
    public final int statusCode;

    public InferenceException(int statusCode, String message) {
        super(message);
        this.statusCode = statusCode;
    }
}
