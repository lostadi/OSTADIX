package org.ostadix.prismatic;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PixelFormat;
import android.graphics.RadialGradient;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;

/**
 * Original wallpaper-aware glass material made from layered gradients.
 *
 * This intentionally does not pretend that RenderEffect is backdrop blur:
 * the host window owns optional cross-window blur, while this drawable keeps
 * controls readable when the platform disables blur.
 */
final class GlassDrawable extends Drawable {
    private final float radius;
    private final float stroke;
    private final Paint fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint lightPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint lowlightPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint borderPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint innerBorderPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF rect = new RectF();
    private final RectF insetRect = new RectF();
    private final Path clip = new Path();

    private GlassPalette palette;
    private boolean reduceTransparency;
    private boolean blurAvailable;
    private boolean pressed;
    private float hotX = 0.22f;
    private float hotY = 0.08f;
    private int drawableAlpha = 255;
    private boolean shaderDirty = true;

    GlassDrawable(float density, float radiusDp, GlassPalette palette,
            boolean reduceTransparency, boolean blurAvailable) {
        this.radius = radiusDp * density;
        this.stroke = Math.max(1f, density);
        this.palette = palette;
        this.reduceTransparency = reduceTransparency;
        this.blurAvailable = blurAvailable;
        borderPaint.setStyle(Paint.Style.STROKE);
        borderPaint.setStrokeWidth(stroke);
        innerBorderPaint.setStyle(Paint.Style.STROKE);
        innerBorderPaint.setStrokeWidth(Math.max(0.6f, density * 0.55f));
    }

    void setMaterial(GlassPalette palette, boolean reduceTransparency,
            boolean blurAvailable) {
        this.palette = palette;
        this.reduceTransparency = reduceTransparency;
        this.blurAvailable = blurAvailable;
        shaderDirty = true;
        invalidateSelf();
    }

    void setLightPosition(float x, float y) {
        hotX = clamp(x, 0f, 1f);
        hotY = clamp(y, 0f, 1f);
        shaderDirty = true;
        invalidateSelf();
    }

    @Override
    protected void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        rect.set(bounds.left, bounds.top, bounds.right, bounds.bottom);
        insetRect.set(rect);
        insetRect.inset(stroke * 1.65f, stroke * 1.65f);
        clip.reset();
        clip.addRoundRect(rect, radius, radius, Path.Direction.CW);
        shaderDirty = true;
    }

    @Override
    public void draw(Canvas canvas) {
        if (rect.isEmpty()) {
            return;
        }
        if (shaderDirty) {
            rebuildShaders();
        }
        int save = canvas.save();
        canvas.clipPath(clip);
        canvas.drawRoundRect(rect, radius, radius, fillPaint);
        canvas.drawRoundRect(rect, radius, radius, lowlightPaint);
        canvas.drawRoundRect(rect, radius, radius, lightPaint);
        canvas.restoreToCount(save);
        canvas.drawRoundRect(insetRect, Math.max(0f, radius - stroke),
                Math.max(0f, radius - stroke), innerBorderPaint);
        canvas.drawRoundRect(rect, radius, radius, borderPaint);
    }

    private void rebuildShaders() {
        shaderDirty = false;
        int baseAlpha;
        if (reduceTransparency) {
            baseAlpha = 255;
        } else if (blurAvailable) {
            baseAlpha = 198;
        } else {
            baseAlpha = 224;
        }
        if (pressed) {
            baseAlpha = Math.min(255, baseAlpha + 18);
        }

        int startRgb;
        int endRgb;
        int accentBase;
        if (palette.darkText) {
            startRgb = Color.rgb(250, 252, 255);
            endRgb = Color.rgb(225, 232, 244);
            accentBase = Color.rgb(239, 244, 250);
        } else {
            startRgb = Color.rgb(28, 34, 46);
            endRgb = Color.rgb(12, 17, 28);
            accentBase = Color.rgb(21, 27, 38);
        }
        int endAlpha = reduceTransparency ? 255 : Math.max(190, baseAlpha - 8);
        int accentAlpha = reduceTransparency ? 255 : Math.max(194, baseAlpha - 4);
        int baseStart = withAlpha(startRgb, baseAlpha);
        int baseEnd = withAlpha(endRgb, endAlpha);
        int accent = withAlpha(blendOpaque(accentBase, palette.accent,
                reduceTransparency ? 0.10f : 0.16f), accentAlpha);
        fillPaint.setShader(new LinearGradient(
                rect.left, rect.top, rect.right, rect.bottom,
                new int[] {baseStart, accent, baseEnd},
                new float[] {0f, 0.56f, 1f}, Shader.TileMode.CLAMP));
        fillPaint.setAlpha(drawableAlpha);

        float radiusPx = Math.max(rect.width(), rect.height()) * 0.82f;
        lightPaint.setShader(new RadialGradient(
                rect.left + rect.width() * hotX,
                rect.top + rect.height() * hotY,
                radiusPx,
                new int[] {
                        argb(pressed ? 92 : 76, 255, 255, 255),
                        argb(20, 255, 255, 255),
                        Color.TRANSPARENT
                },
                new float[] {0f, 0.36f, 1f}, Shader.TileMode.CLAMP));
        lightPaint.setAlpha(drawableAlpha);

        lowlightPaint.setShader(new LinearGradient(
                rect.left, rect.top, rect.right, rect.bottom,
                new int[] {Color.TRANSPARENT, withAlpha(palette.accent,
                        reduceTransparency ? 28 : 48)},
                new float[] {0.42f, 1f}, Shader.TileMode.CLAMP));
        lowlightPaint.setAlpha(drawableAlpha);

        borderPaint.setShader(new LinearGradient(
                rect.left, rect.top, rect.right, rect.bottom,
                new int[] {
                        argb(170, 255, 255, 255),
                        argb(46, 255, 255, 255),
                        withAlpha(palette.accent, 120)
                },
                new float[] {0f, 0.5f, 1f}, Shader.TileMode.CLAMP));
        borderPaint.setAlpha(drawableAlpha);
        innerBorderPaint.setColor(palette.darkText
                ? argb(58, 255, 255, 255)
                : argb(36, 255, 255, 255));
        innerBorderPaint.setAlpha(drawableAlpha);
    }

    @Override
    public boolean isStateful() {
        return true;
    }

    @Override
    protected boolean onStateChange(int[] state) {
        boolean nextPressed = false;
        for (int value : state) {
            if (value == android.R.attr.state_pressed) {
                nextPressed = true;
                break;
            }
        }
        if (pressed == nextPressed) {
            return false;
        }
        pressed = nextPressed;
        shaderDirty = true;
        invalidateSelf();
        return true;
    }

    @Override
    public void getOutline(Outline outline) {
        Rect bounds = getBounds();
        outline.setRoundRect(bounds, radius);
        outline.setAlpha(reduceTransparency ? 0.96f : 0.72f);
    }

    @Override
    public void setAlpha(int alpha) {
        drawableAlpha = alpha;
        shaderDirty = true;
        invalidateSelf();
    }

    @Override
    public int getAlpha() {
        return drawableAlpha;
    }

    @Override
    public void setColorFilter(ColorFilter colorFilter) {
        fillPaint.setColorFilter(colorFilter);
        lightPaint.setColorFilter(colorFilter);
        lowlightPaint.setColorFilter(colorFilter);
        borderPaint.setColorFilter(colorFilter);
        innerBorderPaint.setColorFilter(colorFilter);
        invalidateSelf();
    }

    @Override
    public int getOpacity() {
        return PixelFormat.TRANSLUCENT;
    }

    private static int withAlpha(int color, int alpha) {
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
    }

    private static int blendOpaque(int base, int overlay, float amount) {
        float clamped = clamp(amount, 0f, 1f);
        float inverse = 1f - clamped;
        return Color.rgb(
                Math.round(Color.red(base) * inverse + Color.red(overlay) * clamped),
                Math.round(Color.green(base) * inverse + Color.green(overlay) * clamped),
                Math.round(Color.blue(base) * inverse + Color.blue(overlay) * clamped));
    }

    private static int argb(int alpha, int red, int green, int blue) {
        return Color.argb(alpha, red, green, blue);
    }

    private static float clamp(float value, float minimum, float maximum) {
        return Math.max(minimum, Math.min(maximum, value));
    }
}
