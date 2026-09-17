package org.ostadix.prismatic;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.WallpaperColors;
import android.app.WallpaperManager;
import android.app.role.RoleManager;
import android.content.ActivityNotFoundException;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.LauncherApps;
import android.graphics.Color;
import android.graphics.Rect;
import android.graphics.drawable.ColorDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.Gravity;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * A user-selectable, reversible Home app. It never claims the HOME role or
 * edits SystemUI without an explicit system consent screen.
 */
public final class HomeActivity extends Activity implements HomeScreen.Host {
    private static final int REQUEST_HOME_ROLE = 4101;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean reloadRequested = new AtomicBoolean();
    private final AtomicBoolean loaderRunning = new AtomicBoolean();
    private final ExecutorService appLoader = Executors.newSingleThreadExecutor(
            new ThreadFactory() {
                @Override
                public Thread newThread(Runnable runnable) {
                    Thread thread = new Thread(runnable, "Prismatic-app-loader");
                    thread.setDaemon(true);
                    return thread;
                }
            });

    private GlassPreferences preferences;
    private LauncherRepository repository;
    private HomeScreen homeScreen;
    private WallpaperManager wallpaperManager;
    private WindowManager windowManager;
    private boolean launcherCallbackRegistered;
    private boolean wallpaperListenerRegistered;
    private boolean blurListenerRegistered;
    private boolean crossWindowBlurEnabled;
    private boolean searchMode;
    private boolean roleObserved;
    private boolean lastHomeRoleHeld;
    private int appliedBlurRadius = -1;
    private Object searchBackCallback;

    private final LauncherApps.Callback launcherCallback = new LauncherApps.Callback() {
        @Override
        public void onPackageRemoved(String packageName, android.os.UserHandle user) {
            refreshApps();
        }

        @Override
        public void onPackageAdded(String packageName, android.os.UserHandle user) {
            refreshApps();
        }

        @Override
        public void onPackageChanged(String packageName, android.os.UserHandle user) {
            refreshApps();
        }

        @Override
        public void onPackagesAvailable(String[] packageNames, android.os.UserHandle user,
                boolean replacing) {
            refreshApps();
        }

        @Override
        public void onPackagesUnavailable(String[] packageNames, android.os.UserHandle user,
                boolean replacing) {
            refreshApps();
        }
    };

    private final WallpaperManager.OnColorsChangedListener wallpaperListener =
            new WallpaperManager.OnColorsChangedListener() {
                @Override
                public void onColorsChanged(WallpaperColors colors, int which) {
                    if ((which & WallpaperManager.FLAG_SYSTEM) == 0 || homeScreen == null) {
                        return;
                    }
                    GlassPalette palette = GlassPalette.read(HomeActivity.this);
                    homeScreen.setPalette(palette);
                    updateSystemBarAppearance(palette);
                }
            };

    private final Consumer<Boolean> blurListener = new Consumer<Boolean>() {
        @Override
        public void accept(Boolean enabled) {
            crossWindowBlurEnabled = Boolean.TRUE.equals(enabled);
            applyWindowBlur(searchMode);
        }
    };

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        configureWindow();
        preferences = new GlassPreferences(this);
        repository = new LauncherRepository(this);
        wallpaperManager = getSystemService(WallpaperManager.class);
        windowManager = getSystemService(WindowManager.class);
        crossWindowBlurEnabled = windowManager != null
                && windowManager.isCrossWindowBlurEnabled();

        GlassPalette palette = GlassPalette.read(this);
        homeScreen = new HomeScreen(this, this, preferences, palette, false);
        setContentView(homeScreen);
        updateSystemBarAppearance(palette);
        applyWindowBlur(false);
        registerObservers();
        refreshApps();
    }

    private void configureWindow() {
        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_SHOW_WALLPAPER
                | WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.setStatusBarColor(Color.TRANSPARENT);
        window.setNavigationBarColor(Color.TRANSPARENT);
        window.setNavigationBarDividerColor(Color.TRANSPARENT);
        window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        window.setDecorFitsSystemWindows(false);
    }

    private void registerObservers() {
        LauncherApps launcherApps = repository.launcherApps();
        if (launcherApps != null) {
            try {
                launcherApps.registerCallback(launcherCallback, mainHandler);
                launcherCallbackRegistered = true;
            } catch (RuntimeException ignored) {
                launcherCallbackRegistered = false;
            }
        }
        if (wallpaperManager != null) {
            try {
                wallpaperManager.addOnColorsChangedListener(wallpaperListener, mainHandler);
                wallpaperListenerRegistered = true;
            } catch (RuntimeException ignored) {
                wallpaperListenerRegistered = false;
            }
        }
        if (windowManager != null) {
            try {
                windowManager.addCrossWindowBlurEnabledListener(blurListener);
                blurListenerRegistered = true;
            } catch (RuntimeException ignored) {
                blurListenerRegistered = false;
            }
        }
    }

    private void refreshApps() {
        if (isFinishing() || appLoader.isShutdown()) {
            return;
        }
        reloadRequested.set(true);
        if (!loaderRunning.compareAndSet(false, true)) {
            return;
        }
        try {
            appLoader.execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        List<LauncherItem> latest;
                        try {
                            do {
                                reloadRequested.set(false);
                                latest = repository.loadApps();
                            } while (reloadRequested.get()
                                    && !Thread.currentThread().isInterrupted());
                        } catch (RuntimeException error) {
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    if (!isFinishing() && !isDestroyed()) {
                                        Toast.makeText(HomeActivity.this,
                                                "Could not refresh apps", Toast.LENGTH_SHORT).show();
                                    }
                                }
                            });
                            return;
                        }
                        final List<LauncherItem> loaded = latest;
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                if (!isFinishing() && !isDestroyed()) {
                                    homeScreen.setApps(loaded);
                                }
                            }
                        });
                    } finally {
                        loaderRunning.set(false);
                        if (reloadRequested.get() && !appLoader.isShutdown()) {
                            mainHandler.post(new Runnable() {
                                @Override
                                public void run() {
                                    refreshApps();
                                }
                            });
                        }
                    }
                }
            });
        } catch (RuntimeException error) {
            loaderRunning.set(false);
            if (!appLoader.isShutdown()) {
                throw error;
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        boolean held = isHomeRoleHeld();
        if (homeScreen != null) {
            homeScreen.updateHomeRole();
        }
        if (roleObserved && held != lastHomeRoleHeld) {
            refreshApps();
        }
        lastHomeRoleHeld = held;
        roleObserved = true;
        setBackRegistration(searchMode || held);
        applyWindowBlur(searchMode);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (homeScreen != null) {
            homeScreen.returnHome();
            homeScreen.updateHomeRole();
        }
    }

    @Override
    public void onBackPressed() {
        if (Build.VERSION.SDK_INT < 33
                && homeScreen != null
                && homeScreen.handleBack()) {
            return;
        }
        if (!isHomeRoleHeld()) {
            super.onBackPressed();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_HOME_ROLE && homeScreen != null) {
            homeScreen.updateHomeRole();
            refreshApps();
            setBackRegistration(searchMode || isHomeRoleHeld());
            if (isHomeRoleHeld()) {
                Toast.makeText(this, "Prismatic Glass is now your Home app",
                        Toast.LENGTH_SHORT).show();
            }
        }
    }

    @Override
    protected void onDestroy() {
        setBackRegistration(false);
        clearWindowBlur();
        LauncherApps launcherApps = repository == null ? null : repository.launcherApps();
        if (launcherCallbackRegistered && launcherApps != null) {
            try {
                launcherApps.unregisterCallback(launcherCallback);
            } catch (RuntimeException ignored) {
            }
        }
        if (wallpaperListenerRegistered && wallpaperManager != null) {
            try {
                wallpaperManager.removeOnColorsChangedListener(wallpaperListener);
            } catch (RuntimeException ignored) {
            }
        }
        if (blurListenerRegistered && windowManager != null) {
            try {
                windowManager.removeCrossWindowBlurEnabledListener(blurListener);
            } catch (RuntimeException ignored) {
            }
        }
        appLoader.shutdownNow();
        super.onDestroy();
    }

    @Override
    public boolean isHomeRoleHeld() {
        RoleManager roles = getSystemService(RoleManager.class);
        try {
            return roles != null
                    && roles.isRoleAvailable(RoleManager.ROLE_HOME)
                    && roles.isRoleHeld(RoleManager.ROLE_HOME);
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    @Override
    public void requestHomeRole() {
        RoleManager roles = getSystemService(RoleManager.class);
        try {
            if (roles != null && roles.isRoleAvailable(RoleManager.ROLE_HOME)) {
                if (roles.isRoleHeld(RoleManager.ROLE_HOME)) {
                    openHomeSettings();
                    return;
                }
                startActivityForResult(
                        roles.createRequestRoleIntent(RoleManager.ROLE_HOME),
                        REQUEST_HOME_ROLE);
                return;
            }
        } catch (ActivityNotFoundException | SecurityException ignored) {
            // Some vendor role controllers expose only the Home settings screen.
        }
        openHomeSettings();
    }

    @Override
    public void openHomeSettings() {
        try {
            startActivity(new Intent(Settings.ACTION_HOME_SETTINGS));
        } catch (ActivityNotFoundException error) {
            startActivity(new Intent(Settings.ACTION_SETTINGS));
        }
    }

    @Override
    public void openApp(LauncherItem item, Rect sourceBounds) {
        try {
            repository.launch(item, sourceBounds);
        } catch (RuntimeException error) {
            Toast.makeText(this, "Could not open " + item.label,
                    Toast.LENGTH_SHORT).show();
            refreshApps();
        }
    }

    @Override
    public void showAppActions(final LauncherItem item, final Rect sourceBounds) {
        final boolean pinned = homeScreen.isPinned(item);
        String[] actions = {
                "Open",
                pinned ? "Remove from Dock" : "Pin to Dock",
                "App info"
        };
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(item.label)
                .setItems(actions, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface ignored, int which) {
                        if (which == 0) {
                            openApp(item, sourceBounds);
                        } else if (which == 1) {
                            homeScreen.togglePinned(item);
                        } else if (which == 2) {
                            try {
                                repository.showDetails(item, sourceBounds);
                            } catch (RuntimeException error) {
                                Toast.makeText(HomeActivity.this,
                                        "App info is unavailable", Toast.LENGTH_SHORT).show();
                            }
                        }
                    }
                })
                .setNegativeButton("Cancel", null)
                .create();
        prepareDialogBlur(dialog);
        dialog.show();
    }

    @Override
    public void showGlassSettings() {
        final Switch transparency = settingSwitch(
                "Reduce transparency", preferences.reduceTransparency());
        final Switch motion = settingSwitch(
                "Reduce motion", preferences.reduceMotion());
        final Switch labels = settingSwitch(
                "Show app labels", preferences.showLabels());
        final Switch blur = settingSwitch(
                "Use system blur when available", preferences.useBlur());

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int horizontal = dp(22);
        content.setPadding(horizontal, dp(6), horizontal, dp(2));
        TextView explanation = new TextView(this);
        explanation.setText("Glass adapts to your wallpaper. Android may disable blur in Battery Saver; the higher-opacity fallback remains readable.");
        explanation.setTextSize(13);
        explanation.setPadding(0, 0, 0, dp(8));
        content.addView(explanation, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        content.addView(transparency);
        content.addView(motion);
        content.addView(labels);
        content.addView(blur);

        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Prismatic Glass")
                .setView(content)
                .setPositiveButton("Apply", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface ignored, int which) {
                        preferences.setReduceTransparency(transparency.isChecked());
                        preferences.setReduceMotion(motion.isChecked());
                        preferences.setShowLabels(labels.isChecked());
                        preferences.setUseBlur(blur.isChecked());
                        homeScreen.applyPreferences();
                        applyWindowBlur(homeScreen.isSearchActive());
                    }
                })
                .setNeutralButton("Home apps", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface ignored, int which) {
                        openHomeSettings();
                    }
                })
                .setNegativeButton("Cancel", null)
                .create();
        prepareDialogBlur(dialog);
        dialog.show();
    }

    @Override
    public void onSearchModeChanged(boolean active) {
        searchMode = active;
        setBackRegistration(active || isHomeRoleHeld());
        applyWindowBlur(active);
    }

    private void applyWindowBlur(boolean searchRequested) {
        Window window = getWindow();
        WindowManager.LayoutParams attributes = window.getAttributes();
        boolean enabled = preferences != null
                && preferences.useBlur()
                && !preferences.reduceTransparency()
                && crossWindowBlurEnabled;
        int radius = enabled ? dp(searchRequested ? 18 : 8) : 0;
        if (radius == appliedBlurRadius) {
            if (homeScreen != null) {
                homeScreen.setBlurAvailable(enabled);
            }
            return;
        }
        if (enabled) {
            attributes.flags |= WindowManager.LayoutParams.FLAG_BLUR_BEHIND;
            attributes.setBlurBehindRadius(radius);
        } else {
            attributes.flags &= ~WindowManager.LayoutParams.FLAG_BLUR_BEHIND;
            attributes.setBlurBehindRadius(0);
        }
        window.setAttributes(attributes);
        appliedBlurRadius = radius;
        if (homeScreen != null) {
            homeScreen.setBlurAvailable(enabled);
        }
    }

    private void clearWindowBlur() {
        if (appliedBlurRadius == 0) {
            return;
        }
        WindowManager.LayoutParams attributes = getWindow().getAttributes();
        attributes.flags &= ~WindowManager.LayoutParams.FLAG_BLUR_BEHIND;
        attributes.setBlurBehindRadius(0);
        getWindow().setAttributes(attributes);
        appliedBlurRadius = 0;
    }

    private void setBackRegistration(boolean enabled) {
        if (Build.VERSION.SDK_INT < 33) {
            return;
        }
        try {
            if (enabled && searchBackCallback == null) {
                searchBackCallback = BackApi33.register(this, new Runnable() {
                    @Override
                    public void run() {
                        if (homeScreen != null && homeScreen.handleBack()) {
                            return;
                        }
                        if (!isHomeRoleHeld()) {
                            finishAfterTransition();
                        }
                    }
                });
            } else if (!enabled && searchBackCallback != null) {
                BackApi33.unregister(this, searchBackCallback);
                searchBackCallback = null;
            }
        } catch (RuntimeException ignored) {
            searchBackCallback = null;
        }
    }

    private void prepareDialogBlur(final AlertDialog dialog) {
        dialog.setOnShowListener(new DialogInterface.OnShowListener() {
            @Override
            public void onShow(DialogInterface ignored) {
                Window window = dialog.getWindow();
                if (window == null || preferences.reduceTransparency()
                        || !preferences.useBlur() || !crossWindowBlurEnabled) {
                    return;
                }
                WindowManager.LayoutParams attributes = window.getAttributes();
                attributes.flags |= WindowManager.LayoutParams.FLAG_BLUR_BEHIND;
                attributes.setBlurBehindRadius(dp(22));
                window.setAttributes(attributes);
            }
        });
    }

    private Switch settingSwitch(String text, boolean checked) {
        Switch control = new Switch(this);
        control.setText(text);
        control.setTextSize(15);
        control.setChecked(checked);
        control.setGravity(Gravity.CENTER_VERTICAL);
        control.setMinHeight(dp(52));
        control.setPadding(0, 0, 0, 0);
        return control;
    }

    private void updateSystemBarAppearance(GlassPalette palette) {
        WindowInsetsController controller = getWindow().getInsetsController();
        if (controller == null) {
            return;
        }
        int mask = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
        controller.setSystemBarsAppearance(palette.darkText ? mask : 0, mask);
    }

    /** Isolates API 33 Back classes so Android 12 never verifies them. */
    private static final class BackApi33 {
        static Object register(final Activity activity, final Runnable action) {
            android.window.OnBackInvokedCallback callback =
                    new android.window.OnBackInvokedCallback() {
                        @Override
                        public void onBackInvoked() {
                            action.run();
                        }
                    };
            activity.getOnBackInvokedDispatcher().registerOnBackInvokedCallback(
                    android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT,
                    callback);
            return callback;
        }

        static void unregister(Activity activity, Object callback) {
            activity.getOnBackInvokedDispatcher().unregisterOnBackInvokedCallback(
                    (android.window.OnBackInvokedCallback) callback);
        }

        private BackApi33() {
        }
    }

    private int dp(float value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
