package org.ostadix.accessory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/** Resolves and invokes only a public, zero-argument method returning primitive int. */
final class PublicIntNoArgMethod {
    private PublicIntNoArgMethod() {
    }

    static Method resolve(Class<?> owner, String name) throws NoSuchMethodException {
        Method method = owner.getMethod(name);
        if (!Modifier.isPublic(method.getModifiers())
                || method.getParameterTypes().length != 0
                || method.getReturnType() != Integer.TYPE) {
            throw new NoSuchMethodException(name + " is not a public no-argument int method");
        }
        return method;
    }

    static int invoke(Object target, String name) throws Exception {
        Method method = resolve(target.getClass(), name);
        try {
            return ((Integer) method.invoke(target)).intValue();
        } catch (InvocationTargetException error) {
            Throwable cause = error.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new IllegalStateException("public method invocation failed", cause);
        }
    }
}
