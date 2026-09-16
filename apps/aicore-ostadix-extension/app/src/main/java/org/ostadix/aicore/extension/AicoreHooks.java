package org.ostadix.aicore.extension;

import android.content.Context;
import android.os.Binder;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicLong;

import io.github.libxposed.api.XposedInterface;

final class AicoreHooks {
    private static final AtomicLong NEXT_REQUEST = new AtomicLong();
    private static final Map<Object, RequestIdentity> CALLBACKS =
            Collections.synchronizedMap(new WeakHashMap<Object, RequestIdentity>());
    private static final Map<Object, RequestIdentity> CANCELLATIONS =
            Collections.synchronizedMap(new WeakHashMap<Object, RequestIdentity>());

    private final Context context;
    private final OstadixResultBridge bridge;
    private final Field callbackField;

    AicoreHooks(Context context, OstadixResultBridge bridge, Class<?> callbackClass)
            throws Exception {
        this.context = context;
        this.bridge = bridge;
        callbackField = callbackClass.getDeclaredField("a");
        callbackField.setAccessible(true);
    }

    Object interceptForward(XposedInterface.Chain chain) throws Throwable {
        if (!ExtensionGate.isExplicitlyEnabled(context)) {
            return chain.proceed();
        }
        Object callback = chain.getArg(1);
        RequestIdentity identity = new RequestIdentity(
                Binder.getCallingUid(), NEXT_REQUEST.incrementAndGet());
        if (callback != null) {
            CALLBACKS.put(callback, identity);
        }
        Object cancellation = chain.proceed();
        if (cancellation != null) {
            CANCELLATIONS.put(cancellation, identity);
        }
        return cancellation;
    }

    Object interceptSuccess(XposedInterface.Chain chain) throws Throwable {
        Object callback = callbackField.get(chain.getThisObject());
        RequestIdentity identity = callback == null ? null : CALLBACKS.get(callback);
        if (identity == null || !ExtensionGate.isExplicitlyEnabled(context)
                || !ExtensionGate.thermalPolicyAllows(context)) {
            return chain.proceed();
        }
        Object replacement;
        try {
            replacement = bridge.select(chain.getArg(0), identity);
        } catch (Throwable error) {
            ExtensionGate.rethrowIfVmFatal(error);
            return chain.proceed();
        } finally {
            CALLBACKS.remove(callback);
        }
        // Delivery sits outside the transformation catch: if the existing
        // downstream callback throws, propagate it and never invoke it twice.
        return chain.proceed(new Object[] {replacement});
    }

    Object interceptCancellation(XposedInterface.Chain chain) throws Throwable {
        RequestIdentity identity = CANCELLATIONS.remove(chain.getThisObject());
        if (identity != null) {
            try {
                bridge.cancel(identity);
            } catch (Throwable error) {
                ExtensionGate.rethrowIfVmFatal(error);
            }
        }
        return chain.proceed();
    }
}
