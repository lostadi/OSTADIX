package org.ostadix.prismatic.systemui;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.PixelFormat;
import android.graphics.RadialGradient;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;

final class GlassEdgeDrawable extends Drawable {
    private final Paint sheenPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint edgePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF frame = new RectF();
    private final float cornerRadius;
    private final float inset;
    private int alpha = 255;

    GlassEdgeDrawable(float density) {
        cornerRadius = 22f * density;
        inset = Math.max(1f, 0.75f * density);
        edgePaint.setStyle(Paint.Style.STROKE);
        edgePaint.setStrokeWidth(Math.max(1f, density));
    }

    @Override
    protected void onBoundsChange(Rect bounds) {
        try {
            float width = Math.max(1f, bounds.width());
            float height = Math.max(1f, bounds.height());
            frame.set(bounds.left + inset, bounds.top + inset,
                    bounds.right - inset, bounds.bottom - inset);

            sheenPaint.setShader(new RadialGradient(
                    bounds.left, bounds.top,
                    Math.max(width, height) * 0.82f,
                    new int[] {0x2effffff, 0x10ffffff, 0x00ffffff},
                    new float[] {0f, 0.36f, 1f}, Shader.TileMode.CLAMP));
            edgePaint.setShader(new LinearGradient(
                    bounds.left, bounds.top, bounds.right, bounds.bottom,
                    new int[] {0x55ffffff, 0x18ffffff, 0x0800d5ff, 0x38ffffff},
                    new float[] {0f, 0.42f, 0.72f, 1f}, Shader.TileMode.CLAMP));
        } catch (Throwable error) {
            BuildGate.rethrowIfVmFatal(error);
            try {
                frame.setEmpty();
            } catch (Throwable cleanupError) {
                BuildGate.rethrowIfVmFatal(cleanupError);
            }
        }
    }

    @Override
    public void draw(Canvas canvas) {
        try {
            if (frame.isEmpty()) {
                return;
            }
            canvas.drawRoundRect(frame, cornerRadius, cornerRadius, sheenPaint);
            canvas.drawRoundRect(frame, cornerRadius, cornerRadius, edgePaint);
        } catch (Throwable error) {
            BuildGate.rethrowIfVmFatal(error);
        }
    }

    @Override
    public void setAlpha(int value) {
        try {
            alpha = Math.max(0, Math.min(255, value));
            sheenPaint.setAlpha(alpha);
            edgePaint.setAlpha(alpha);
            invalidateSelf();
        } catch (Throwable error) {
            BuildGate.rethrowIfVmFatal(error);
        }
    }

    @Override
    public int getAlpha() {
        return alpha;
    }

    @Override
    public void setColorFilter(ColorFilter filter) {
        try {
            sheenPaint.setColorFilter(filter);
            edgePaint.setColorFilter(filter);
            invalidateSelf();
        } catch (Throwable error) {
            BuildGate.rethrowIfVmFatal(error);
        }
    }

    @Override
    public int getOpacity() {
        return PixelFormat.TRANSLUCENT;
    }
}

