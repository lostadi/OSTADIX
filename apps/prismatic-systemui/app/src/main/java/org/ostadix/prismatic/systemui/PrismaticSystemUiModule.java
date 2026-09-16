package org.ostadix.prismatic.systemui;

import android.util.Log;
import android.view.View;
import android.view.ViewGroup;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

public final class PrismaticSystemUiModule extends XposedModule {
    private static final String TAG = "PrismaticSystemUi";
    private static final String EXPECTED_FRAMEWORK = "Vector";

    private boolean acceptedProcess;

    @Override
    public void onModuleLoaded(ModuleLoadedParam param) {
        acceptedProcess = !param.isSystemServer()
                && BuildGate.SYSTEM_UI_PROCESS.equals(param.getProcessName())
                && EXPECTED_FRAMEWORK.equals(getFrameworkName())
                && getApiVersion() == XposedInterface.API_102
                && BuildGate.matchesFirmware();

        if (!acceptedProcess) {
            log(Log.WARN, TAG, "Gate rejected process, framework, API, or firmware; detaching");
            detach();
            return;
        }

        log(Log.INFO, TAG, "Firmware and Vector API gates accepted; waiting for SystemUI package");
    }

    @Override
    public void onPackageReady(PackageReadyParam param) {
        if (!acceptedProcess
                || !param.isFirstPackage()
                || !BuildGate.SYSTEM_UI_PACKAGE.equals(param.getPackageName())) {
            return;
        }

        try {
            Class<?> implementation = Class.forName(
                    "android.view.WindowManagerImpl", false, param.getClassLoader());
            Method addView = implementation.getDeclaredMethod(
                    "addView", View.class, ViewGroup.LayoutParams.class);
            hook(addView)
                    .setId("prismatic-systemui/window-manager-add-view")
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(new XposedInterface.Hooker() {
                        @Override
                        public Object intercept(XposedInterface.Chain chain) throws Throwable {
                            return SystemUiGlass.interceptAddView(chain);
                        }
                    });
            log(Log.INFO, TAG, "Installed one protected WindowManagerImpl.addView hook");
            detach();
        } catch (Throwable error) {
            log(Log.ERROR, TAG, "Hook installation failed; no visual changes were applied", error);
            detach();
        }
    }
}

