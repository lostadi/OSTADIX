package org.ostadix.aicore.extension;

import android.content.Context;

import org.ostadix.terminal.OstadixRuntime;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;

final class OstadixResultBridge implements AutoCloseable {
    private static final int MAX_REPLIES = 3;
    private static final int POLICY_LIMIT_MILLI = 500;
    private static final long TIMEOUT_MS = 500L;

    private final OstadixRuntime runtime;

    OstadixResultBridge(Context asossContext) throws Exception {
        Context module = asossContext.createPackageContext(
                ExtensionGate.MODULE_PACKAGE, Context.CONTEXT_IGNORE_SECURITY);
        File nativeDirectory = new File(module.getApplicationInfo().nativeLibraryDir);
        File runtimeLibrary = new File(nativeDirectory, "libostadix_runtime.so");
        if (!runtimeLibrary.isFile()) {
            throw new IllegalStateException("packaged OSTADIX JNI runtime unavailable");
        }
        System.load(runtimeLibrary.getAbsolutePath());
        File o = requireExecutable(nativeDirectory, "libostadix_cli.so");
        File bash = requireExecutable(nativeDirectory, "libostadix_bash.so");
        // Bash is a native Rust backend and uses no legacy shim. The immutable
        // module native directory is therefore also a valid empty shim root;
        // initialization writes nothing into AS.OSS private storage.
        runtime = new OstadixRuntime(nativeDirectory.getAbsolutePath(),
                o.getAbsolutePath(), bash.getAbsolutePath());
    }

    Object select(Object originalResult, RequestIdentity identity) throws Exception {
        Method getResults = originalResult.getClass().getMethod("getResults");
        List<?> replies = (List<?>) getResults.invoke(originalResult);
        if (replies == null || replies.isEmpty() || replies.size() > MAX_REPLIES) {
            throw new IllegalArgumentException("unsupported LLM reply count");
        }
        int count = replies.size();
        int[] scores = new int[count];
        int[] stops = new int[count];
        int[] policies = new int[count];
        for (int index = 0; index < count; index++) {
            Object reply = replies.get(index);
            scores[index] = scaledMilli((Number) reply.getClass()
                    .getMethod("getScore").invoke(reply));
            stops[index] = ((Number) reply.getClass()
                    .getMethod("getStopReason").invoke(reply)).intValue();
            Object bundle = reply.getClass().getMethod("getPolicyScoresBundle").invoke(reply);
            policies[index] = maximumPolicyMilli(bundle);
        }

        OstadixRuntime.Evaluation result = runtime.postprocessAicoreReplies(
                scores, stops, policies, POLICY_LIMIT_MILLI,
                identity.callerId(), identity.requestId, TIMEOUT_MS);
        if (!result.ok || result.selectedSourceIndex < 0
                || result.selectedSourceIndex >= replies.size()) {
            throw new IllegalStateException("OSTADIX result selection failed closed");
        }

        return rebuildSelectedResult(originalResult, replies, result.selectedSourceIndex);
    }

    static Object rebuildSelectedResult(Object originalResult, List<?> replies, int selectedIndex)
            throws Exception {
        if (selectedIndex < 0 || selectedIndex >= replies.size()) {
            throw new IllegalArgumentException("selected reply index is out of range");
        }
        Object selected = replies.get(selectedIndex);
        Method trace = originalResult.getClass().getMethod("getInferenceEventTraceResult");
        Method legion = originalResult.getClass().getMethod("getLegionResultMetadata");
        Method thought = originalResult.getClass().getMethod("getThoughtProcess");
        ClassLoader loader = originalResult.getClass().getClassLoader();
        Class<?> traceClass = Class.forName(
                "com.google.android.apps.aicore.aidl.InferenceEventTraceResult", false, loader);
        Class<?> legionClass = Class.forName(
                "com.google.android.apps.aicore.aidl.LegionResultMetadata", false, loader);
        Constructor<?> constructor = originalResult.getClass().getConstructor(
                List.class, traceClass, legionClass, List.class);
        return constructor.newInstance(Collections.singletonList(selected),
                trace.invoke(originalResult), legion.invoke(originalResult),
                thought.invoke(originalResult));
    }

    boolean cancel(RequestIdentity identity) {
        return runtime.cancelRequest(identity.callerId(), identity.requestId);
    }

    @Override
    public void close() {
        runtime.close();
    }

    private static File requireExecutable(File directory, String name) {
        File executable = new File(directory, name);
        if (!executable.isFile() || !executable.canExecute()) {
            throw new IllegalStateException("packaged executable unavailable: " + name);
        }
        return executable;
    }

    private static int scaledMilli(Number value) {
        double scaled = value.doubleValue() * 1000.0d;
        if (!Double.isFinite(scaled) || scaled > Integer.MAX_VALUE
                || scaled < Integer.MIN_VALUE) {
            throw new IllegalArgumentException("non-finite or out-of-range reply score");
        }
        return (int) Math.round(scaled);
    }

    private static int maximumPolicyMilli(Object bundleObject) throws Exception {
        if (!(bundleObject instanceof android.os.Bundle)) {
            return 0;
        }
        android.os.Bundle bundle = (android.os.Bundle) bundleObject;
        int maximum = 0;
        for (String key : bundle.keySet()) {
            Object values = bundle.getSerializable(key);
            if (values instanceof Iterable<?>) {
                for (Object value : (Iterable<?>) values) {
                    if (value instanceof Number) {
                        maximum = Math.max(maximum, scaledMilli((Number) value));
                    }
                }
            }
        }
        return maximum;
    }
}
