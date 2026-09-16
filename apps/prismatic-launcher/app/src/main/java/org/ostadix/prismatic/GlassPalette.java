package org.ostadix.prismatic;

import android.app.WallpaperColors;
import android.app.WallpaperManager;
import android.content.Context;
import android.graphics.Color;

/** Wallpaper-derived colors with conservative legibility defaults. */
final class GlassPalette {
    final int accent;
    final int primaryText;
    final int secondaryText;
    final boolean darkText;

    private GlassPalette(int accent, boolean darkText) {
        this.accent = accent;
        this.darkText = darkText;
        this.primaryText = darkText ? 0xff1a1d24 : 0xffffffff;
        this.secondaryText = darkText ? 0xff30343c : 0xffe1e6ef;
    }

    static GlassPalette read(Context context) {
        int accent = 0xff8ba7ff;
        boolean darkText = false;
        try {
            WallpaperManager manager = context.getSystemService(WallpaperManager.class);
            WallpaperColors colors = manager == null
                    ? null
                    : manager.getWallpaperColors(WallpaperManager.FLAG_SYSTEM);
            if (colors != null && colors.getPrimaryColor() != null) {
                accent = makeExpressive(colors.getPrimaryColor().toArgb());
                darkText = (colors.getColorHints()
                        & WallpaperColors.HINT_SUPPORTS_DARK_TEXT) != 0;
            }
        } catch (RuntimeException ignored) {
            // Wallpaper providers may be unavailable while a profile is locked.
        }
        return new GlassPalette(accent, darkText);
    }

    private static int makeExpressive(int color) {
        float[] hsv = new float[3];
        Color.colorToHSV(color, hsv);
        hsv[1] = Math.max(0.32f, Math.min(0.72f, hsv[1]));
        hsv[2] = Math.max(0.68f, Math.min(0.94f, hsv[2]));
        return Color.HSVToColor(hsv);
    }
}
