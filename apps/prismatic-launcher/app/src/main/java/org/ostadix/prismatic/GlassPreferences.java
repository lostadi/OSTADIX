package org.ostadix.prismatic;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Small, private and export-free preference store for visual/accessibility choices. */
final class GlassPreferences {
    private static final String FILE = "prismatic_glass";
    private static final String REDUCE_TRANSPARENCY = "reduce_transparency";
    private static final String REDUCE_MOTION = "reduce_motion";
    private static final String SHOW_LABELS = "show_labels";
    private static final String USE_BLUR = "use_blur";
    private static final String DOCK = "dock";
    private static final String DOCK_INITIALIZED = "dock_initialized";

    private final SharedPreferences preferences;

    GlassPreferences(Context context) {
        preferences = context.getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    boolean reduceTransparency() {
        return preferences.getBoolean(REDUCE_TRANSPARENCY, false);
    }

    void setReduceTransparency(boolean value) {
        preferences.edit().putBoolean(REDUCE_TRANSPARENCY, value).apply();
    }

    boolean reduceMotion() {
        return preferences.getBoolean(REDUCE_MOTION, false);
    }

    void setReduceMotion(boolean value) {
        preferences.edit().putBoolean(REDUCE_MOTION, value).apply();
    }

    boolean showLabels() {
        return preferences.getBoolean(SHOW_LABELS, true);
    }

    void setShowLabels(boolean value) {
        preferences.edit().putBoolean(SHOW_LABELS, value).apply();
    }

    boolean useBlur() {
        return preferences.getBoolean(USE_BLUR, true);
    }

    void setUseBlur(boolean value) {
        preferences.edit().putBoolean(USE_BLUR, value).apply();
    }

    boolean dockInitialized() {
        return preferences.getBoolean(DOCK_INITIALIZED, false);
    }

    List<String> dockIds() {
        String encoded = preferences.getString(DOCK, "");
        if (encoded == null || encoded.isEmpty()) {
            return Collections.emptyList();
        }
        ArrayList<String> ids = new ArrayList<>();
        for (String line : encoded.split("\\n")) {
            if (!line.isEmpty()) {
                ids.add(line);
            }
        }
        return ids;
    }

    void setDockIds(List<String> ids) {
        StringBuilder encoded = new StringBuilder();
        for (String id : ids) {
            if (id == null || id.indexOf('\n') >= 0) {
                continue;
            }
            if (encoded.length() > 0) {
                encoded.append('\n');
            }
            encoded.append(id);
        }
        preferences.edit()
                .putString(DOCK, encoded.toString())
                .putBoolean(DOCK_INITIALIZED, true)
                .apply();
    }
}
