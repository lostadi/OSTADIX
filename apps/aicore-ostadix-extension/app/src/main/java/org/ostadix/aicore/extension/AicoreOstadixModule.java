package org.ostadix.aicore.extension;

import android.content.Context;
import android.util.Log;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

public final class AicoreOstadixModule extends XposedModule {
    private static final String TAG = "OstadixAicoreExperiment";
    private boolean acceptedProcess;

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        acceptedProcess = !param.isSystemServer()
                && ExtensionGate.matchesEarlyProcess(
                        param.getProcessName(), getFrameworkName(), getApiVersion());
        if (!acceptedProcess) {
            detach();
        }
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!acceptedProcess || !param.isFirstPackage()
                || !ExtensionGate.ASOSS_PACKAGE.equals(param.getPackageName())) {
            return;
        }
        Context context = ExtensionGate.currentApplication();
        if (!ExtensionGate.acceptsInstalledPackages(context)
                || !ExtensionGate.isExplicitlyEnabled(context)) {
            log(Log.WARN, TAG, "Identity or explicit activation gate rejected; detaching");
            detach();
            return;
        }
        try {
            ClassLoader loader = param.getClassLoader();
            Class<?> request = Class.forName(
                    "com.google.android.apps.aicore.aidl.LLMRequest", false, loader);
            Class<?> result = Class.forName(
                    "com.google.android.apps.aicore.aidl.LLMResult", false, loader);
            Class<?> resultCallback = Class.forName("defpackage.flr", false, loader);
            Class<?> forwarder = Class.forName("defpackage.fls", false, loader);
            Class<?> callback = Class.forName("defpackage.fmz", false, loader);
            Class<?> cancellation = Class.forName("defpackage.flo", false, loader);
            Method forward = forwarder.getDeclaredMethod("a", request, resultCallback);
            Method success = callback.getDeclaredMethod("onLLMInferenceSuccess", result);
            Method cancel = cancellation.getDeclaredMethod("a");
            final AicoreHooks hooks = new AicoreHooks(
                    context, new OstadixResultBridge(context), callback);

            hook(forward).setId("ostadix-aicore/fls-forward-v1")
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            return hooks.interceptForward(chain);
                        }
                    });
            hook(success).setId("ostadix-aicore/fmz-success-v1")
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            return hooks.interceptSuccess(chain);
                        }
                    });
            hook(cancel).setId("ostadix-aicore/flo-cancel-v1")
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            return hooks.interceptCancellation(chain);
                        }
                    });
            log(Log.INFO, TAG, "Installed three version-pinned protected hooks");
            detach();
        } catch (Throwable error) {
            ExtensionGate.rethrowIfVmFatal(error);
            log(Log.ERROR, TAG, "Hook installation failed; original AS.OSS path retained", error);
            detach();
        }
    }
}
