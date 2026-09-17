package org.ostadix.prismatic;

import android.content.ComponentName;
import android.graphics.drawable.Drawable;
import android.os.UserHandle;

import java.util.Locale;

/** Immutable launcher entry, including the Android profile that owns it. */
final class LauncherItem {
    final String id;
    final CharSequence label;
    final String searchText;
    final ComponentName component;
    final UserHandle user;
    final Drawable icon;

    LauncherItem(
            String id,
            CharSequence label,
            ComponentName component,
            UserHandle user,
            Drawable icon) {
        this.id = id;
        this.label = label;
        this.component = component;
        this.user = user;
        this.icon = icon;
        this.searchText = (label + " " + component.getPackageName())
                .toLowerCase(Locale.ROOT);
    }
}
