package org.ostadix.prismatic.systemui;

import android.content.Context;
import android.content.res.Resources;
import android.view.View;
import android.view.ViewParent;
import android.view.WindowManager;

import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

import io.github.libxposed.api.XposedInterface;

final class SystemUiGlass {
    private static final TargetSpec[] VOLUME_TARGETS = new TargetSpec[] {
            new TargetSpec("volume_dialog_background", 0x7f0a0a33),
            new TargetSpec("volume_dialog_container", 0x7f0a0a35)
    };
    private static final TargetSpec[] GLOBAL_ACTIONS_TARGETS = new TargetSpec[] {
            new TargetSpec(
                    "global_actions_view", 0x7f0a03c3,
                    "com.android.systemui.globalactions.GlobalActionsLayoutLite",
                    "global_actions_container", 0x7f0a03bf)
    };
    private static final WindowPlan VOLUME_DIALOG =
            new WindowPlan("VolumeDialog", VOLUME_TARGETS, false);
    private static final WindowPlan GLOBAL_ACTIONS_DIALOG =
            new WindowPlan("GlobalActionsDialogLite", GLOBAL_ACTIONS_TARGETS, true);
    private static final Map<View, OverlayBinding> DECORATED_VIEWS =
            Collections.synchronizedMap(new WeakHashMap<View, OverlayBinding>());

    private SystemUiGlass() {}

    static Object interceptAddView(XposedInterface.Chain chain) throws Throwable {
        View root = null;
        WindowPlan plan = null;

        try {
            Object viewArg = chain.getArg(0);
            Object paramsArg = chain.getArg(1);
            if (viewArg instanceof View && paramsArg instanceof WindowManager.LayoutParams) {
                root = (View) viewArg;
                WindowManager.LayoutParams params = (WindowManager.LayoutParams) paramsArg;
                CharSequence title = params.getTitle();
                plan = title == null ? null : planForTitle(title.toString());
                if (plan == null
                        || !BuildGate.matchesSystemUi(root.getContext())
                        || !BuildGate.isExplicitlyEnabled(root.getContext())
                        || (plan.requiresStageTwoConsent
                                && !BuildGate.isStageTwoExplicitlyEnabled(root.getContext()))) {
                    root = null;
                    plan = null;
                }
            }
        } catch (Throwable error) {
            BuildGate.rethrowIfVmFatal(error);
            root = null;
            plan = null;
        }

        Object result = chain.proceed();

        if (root != null && plan != null) {
            try {
                scheduleDecoration(root, plan);
            } catch (Throwable error) {
                BuildGate.rethrowIfVmFatal(error);
                // The original addView already succeeded. Visual decoration must never change that result.
            }
        }
        return result;
    }

    static boolean resourceTableMatches(Context context) {
        Resources resources = context.getResources();
        return targetsMatch(resources, VOLUME_TARGETS)
                && targetsMatch(resources, GLOBAL_ACTIONS_TARGETS);
    }

    private static boolean targetsMatch(Resources resources, TargetSpec[] targets) {
        for (TargetSpec target : targets) {
            int actual = resources.getIdentifier(
                    target.resourceName, "id", BuildGate.SYSTEM_UI_PACKAGE);
            if (actual != target.expectedId) {
                return false;
            }
            if (target.requiredAncestorResourceName != null) {
                int actualAncestor = resources.getIdentifier(
                        target.requiredAncestorResourceName, "id", BuildGate.SYSTEM_UI_PACKAGE);
                if (actualAncestor != target.requiredAncestorId) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean targetShapeMatches(View view, TargetSpec target) {
        if (target.expectedClassName != null
                && !target.expectedClassName.equals(view.getClass().getName())) {
            return false;
        }
        if (target.requiredAncestorId == 0) {
            return true;
        }

        ViewParent parent = view.getParent();
        while (parent instanceof View) {
            if (((View) parent).getId() == target.requiredAncestorId) {
                return true;
            }
            parent = parent.getParent();
        }
        return false;
    }

    private static WindowPlan planForTitle(String title) {
        if (VOLUME_DIALOG.windowTitle.equals(title)) {
            return VOLUME_DIALOG;
        }
        if (GLOBAL_ACTIONS_DIALOG.windowTitle.equals(title)) {
            return GLOBAL_ACTIONS_DIALOG;
        }
        return null;
    }


    private static void scheduleDecoration(final View root, final WindowPlan plan) {
        decorateTargetsSafely(root, plan.targets);
        postDecorationSafely(root, plan, 750L);
        postDecorationSafely(root, plan, 2500L);
    }

    private static void postDecorationSafely(
            final View root, final WindowPlan plan, long delayMillis) {
        try {
            root.postDelayed(new Runnable() {
                @Override
                public void run() {
                    try {
                        decorateTargetsSafely(root, plan.targets);
                    } catch (Throwable error) {
                        BuildGate.rethrowIfVmFatal(error);
                    }
                }
            }, delayMillis);
        } catch (Throwable error) {
            BuildGate.rethrowIfVmFatal(error);
        }
    }

    private static void decorateTargetsSafely(View root, TargetSpec[] targets) {
        try {
            if (!root.isAttachedToWindow()) {
                return;
            }
        } catch (Throwable error) {
            BuildGate.rethrowIfVmFatal(error);
            return;
        }

        for (TargetSpec target : targets) {
            try {
                View view = root.findViewById(target.expectedId);
                if (view != null && targetShapeMatches(view, target)) {
                    attachOverlay(view);
                }
            } catch (Throwable error) {
                BuildGate.rethrowIfVmFatal(error);
                // A failure for one exact target must not block the other target.
            }
        }
    }

    private static void attachOverlay(View view) {
        synchronized (DECORATED_VIEWS) {
            if (DECORATED_VIEWS.containsKey(view)) {
                return;
            }
            OverlayBinding binding = null;
            try {
                binding = new OverlayBinding(view);
                view.getOverlay().add(binding.drawable);
                view.addOnLayoutChangeListener(binding.layoutListener);
                view.addOnAttachStateChangeListener(binding.attachListener);
                binding.updateBounds(view);
                DECORATED_VIEWS.put(view, binding);
            } catch (Throwable error) {
                if (binding != null) {
                    binding.removeSafely(view);
                }
                BuildGate.rethrowIfVmFatal(error);
            }
        }
    }

    private static final class TargetSpec {
        final String resourceName;
        final int expectedId;
        final String expectedClassName;
        final String requiredAncestorResourceName;
        final int requiredAncestorId;

        TargetSpec(String resourceName, int expectedId) {
            this(resourceName, expectedId, null, null, 0);
        }

        TargetSpec(
                String resourceName, int expectedId, String expectedClassName,
                String requiredAncestorResourceName, int requiredAncestorId) {
            this.resourceName = resourceName;
            this.expectedId = expectedId;
            this.expectedClassName = expectedClassName;
            this.requiredAncestorResourceName = requiredAncestorResourceName;
            this.requiredAncestorId = requiredAncestorId;
        }
    }

    private static final class WindowPlan {
        final String windowTitle;
        final TargetSpec[] targets;
        final boolean requiresStageTwoConsent;

        WindowPlan(String windowTitle, TargetSpec[] targets, boolean requiresStageTwoConsent) {
            this.windowTitle = windowTitle;
            this.targets = targets;
            this.requiresStageTwoConsent = requiresStageTwoConsent;
        }
    }

    private static final class OverlayBinding {
        final GlassEdgeDrawable drawable;
        final View.OnLayoutChangeListener layoutListener;
        final View.OnAttachStateChangeListener attachListener;

        OverlayBinding(View view) {
            drawable = new GlassEdgeDrawable(
                    view.getResources().getDisplayMetrics().density);
            layoutListener = new View.OnLayoutChangeListener() {
                @Override
                public void onLayoutChange(View changed, int left, int top, int right, int bottom,
                        int oldLeft, int oldTop, int oldRight, int oldBottom) {
                    try {
                        updateBounds(changed);
                    } catch (Throwable error) {
                        BuildGate.rethrowIfVmFatal(error);
                    }
                }
            };
            attachListener = new View.OnAttachStateChangeListener() {
                @Override
                public void onViewAttachedToWindow(View attached) {}

                @Override
                public void onViewDetachedFromWindow(View detached) {
                    try {
                        removeSafely(detached);
                    } catch (Throwable error) {
                        BuildGate.rethrowIfVmFatal(error);
                    }
                }
            };
        }

        void removeSafely(View view) {
            try {
                view.getOverlay().remove(drawable);
            } catch (Throwable error) {
                BuildGate.rethrowIfVmFatal(error);
            }
            try {
                view.removeOnLayoutChangeListener(layoutListener);
            } catch (Throwable error) {
                BuildGate.rethrowIfVmFatal(error);
            }
            try {
                view.removeOnAttachStateChangeListener(attachListener);
            } catch (Throwable error) {
                BuildGate.rethrowIfVmFatal(error);
            }
            try {
                DECORATED_VIEWS.remove(view);
            } catch (Throwable error) {
                BuildGate.rethrowIfVmFatal(error);
            }
        }

        void updateBounds(View view) {
            drawable.setBounds(0, 0, Math.max(0, view.getWidth()), Math.max(0, view.getHeight()));
        }
    }
}

