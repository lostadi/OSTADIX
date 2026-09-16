package org.ostadix.prismatic;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.LauncherActivityInfo;
import android.content.pm.LauncherApps;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Process;
import android.os.UserHandle;
import android.os.UserManager;

import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Reads and opens launchable activities without requesting broad package access. */
final class LauncherRepository {
    private final Context context;
    private final LauncherApps launcherApps;
    private final UserManager userManager;
    private final PackageManager packageManager;

    LauncherRepository(Context context) {
        this.context = context.getApplicationContext();
        this.launcherApps = context.getSystemService(LauncherApps.class);
        this.userManager = context.getSystemService(UserManager.class);
        this.packageManager = context.getPackageManager();
    }

    LauncherApps launcherApps() {
        return launcherApps;
    }

    List<LauncherItem> loadApps() {
        ArrayList<LauncherItem> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        if (launcherApps != null) {
            List<UserHandle> profiles;
            try {
                profiles = launcherApps.getProfiles();
            } catch (RuntimeException ignored) {
                profiles = Collections.emptyList();
            }
            for (UserHandle profile : profiles) {
                List<LauncherActivityInfo> activities;
                try {
                    activities = launcherApps.getActivityList(null, profile);
                } catch (RuntimeException ignored) {
                    continue;
                }
                long serial = profileSerial(profile);
                for (LauncherActivityInfo info : activities) {
                    try {
                        ComponentName component = info.getComponentName();
                        if (context.getPackageName().equals(component.getPackageName())
                                || !launcherApps.isActivityEnabled(component, profile)) {
                            continue;
                        }
                        String id = component.flattenToShortString() + "#" + serial;
                        if (!seen.add(id)) {
                            continue;
                        }
                        Drawable icon = info.getBadgedIcon(context.getResources()
                                .getDisplayMetrics().densityDpi);
                        result.add(new LauncherItem(id, safeLabel(info.getLabel(), component),
                                component, profile, icon));
                    } catch (RuntimeException ignored) {
                        // A broken package or locked profile must not hide healthy apps.
                    }
                }
            }
        }

        if (result.isEmpty()) {
            Intent query = new Intent(Intent.ACTION_MAIN);
            query.addCategory(Intent.CATEGORY_LAUNCHER);
            List<ResolveInfo> activities;
            try {
                activities = packageManager.queryIntentActivities(query, 0);
            } catch (RuntimeException ignored) {
                activities = Collections.emptyList();
            }
            UserHandle current = Process.myUserHandle();
            for (ResolveInfo info : activities) {
                try {
                    if (info.activityInfo == null
                            || !info.activityInfo.enabled
                            || info.activityInfo.applicationInfo == null
                            || !info.activityInfo.applicationInfo.enabled) {
                        continue;
                    }
                    ComponentName component = new ComponentName(
                            info.activityInfo.packageName, info.activityInfo.name);
                    if (context.getPackageName().equals(component.getPackageName())) {
                        continue;
                    }
                    String id = component.flattenToShortString()
                            + "#" + profileSerial(current);
                    if (!seen.add(id)) {
                        continue;
                    }
                    CharSequence label = info.loadLabel(packageManager);
                    Drawable icon = info.loadIcon(packageManager);
                    result.add(new LauncherItem(id, safeLabel(label, component),
                            component, current, icon));
                } catch (RuntimeException ignored) {
                    // Ignore a package being replaced while the list is loading.
                }
            }
        }

        final Collator collator = Collator.getInstance(Locale.getDefault());
        collator.setStrength(Collator.PRIMARY);
        Collections.sort(result, new Comparator<LauncherItem>() {
            @Override
            public int compare(LauncherItem left, LauncherItem right) {
                int labelOrder = collator.compare(
                        left.label.toString(), right.label.toString());
                if (labelOrder != 0) {
                    return labelOrder;
                }
                return left.id.compareTo(right.id);
            }
        });
        return result;
    }

    void launch(LauncherItem item, Rect sourceBounds) {
        if (launcherApps != null) {
            try {
                launcherApps.startMainActivity(
                        item.component, item.user, sourceBounds, null);
                return;
            } catch (RuntimeException ignored) {
                // Fall through for current-profile apps when HOME permission has
                // not been granted yet.
            }
        }
        if (!Process.myUserHandle().equals(item.user)) {
            throw new IllegalStateException("The selected profile is locked or unavailable");
        }
        Intent intent = new Intent(Intent.ACTION_MAIN)
                .addCategory(Intent.CATEGORY_LAUNCHER)
                .setComponent(item.component)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                        | Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED);
        context.startActivity(intent);
    }

    void showDetails(LauncherItem item, Rect sourceBounds) {
        if (launcherApps != null) {
            try {
                launcherApps.startAppDetailsActivity(
                        item.component, item.user, sourceBounds, null);
                return;
            } catch (RuntimeException ignored) {
                // Use the package settings intent as a current-profile fallback.
            }
        }
        if (!Process.myUserHandle().equals(item.user)) {
            throw new IllegalStateException("The selected profile is locked or unavailable");
        }
        Intent intent = new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(android.net.Uri.parse("package:" + item.component.getPackageName()))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);
    }

    private long profileSerial(UserHandle profile) {
        if (userManager == null) {
            return profile.hashCode();
        }
        try {
            return userManager.getSerialNumberForUser(profile);
        } catch (RuntimeException ignored) {
            return profile.hashCode();
        }
    }

    private static CharSequence safeLabel(CharSequence label, ComponentName component) {
        if (label == null || label.toString().trim().isEmpty()) {
            return component.getPackageName();
        }
        return label.toString().trim();
    }
}
