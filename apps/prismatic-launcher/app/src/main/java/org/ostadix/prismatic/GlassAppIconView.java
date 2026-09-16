package org.ostadix.prismatic;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.AdaptiveIconDrawable;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.ViewOutlineProvider;

/** Displays app artwork in an original rounded-square, layered glass frame. */
final class GlassAppIconView extends View {
    private final Paint backingPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint sheenPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint borderPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF iconRect = new RectF();
    private final Path clip = new Path();
    private final float density;
    private final float cornerRadius;
    private Drawable icon;
    private GlassPalette palette;

    GlassAppIconView(Context context, GlassPalette palette) {
        super(context);
        this.density = getResources().getDisplayMetrics().density;
        this.cornerRadius = density * 13.5f;
        this.palette = palette;
        borderPaint.setStyle(Paint.Style.STROKE);
        borderPaint.setStrokeWidth(Math.max(1f, density * 0.8f));
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
        setFocusable(false);
        setClipToOutline(true);
        setOutlineProvider(new ViewOutlineProvider() {
            @Override
            public void getOutline(View view, Outline outline) {
                outline.setRoundRect(0, 0, view.getWidth(), view.getHeight(), cornerRadius);
            }
        });
    }

    void setIcon(Drawable value) {
        if (icon != null) {
            icon.setCallback(null);
        }
        Drawable fresh = value;
        if (value != null && value.getConstantState() != null) {
            fresh = value.getConstantState().newDrawable(getResources());
        }
        icon = fresh == null ? null : fresh.mutate();
        if (icon != null) {
            icon.setCallback(this);
            icon.setState(getDrawableState());
        }
        invalidate();
    }

    void setPalette(GlassPalette value) {
        palette = value;
        rebuildPaints();
        invalidate();
    }

    @Override
    protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
        super.onSizeChanged(width, height, oldWidth, oldHeight);
        iconRect.set(0f, 0f, width, height);
        clip.reset();
        clip.addRoundRect(iconRect, cornerRadius, cornerRadius, Path.Direction.CW);
        rebuildPaints();
    }

    private void rebuildPaints() {
        if (getWidth() == 0 || getHeight() == 0 || palette == null) {
            return;
        }
        backingPaint.setShader(new LinearGradient(0f, 0f, getWidth(), getHeight(),
                new int[] {0x7affffff, withAlpha(palette.accent, 112), 0x54101520},
                null, Shader.TileMode.CLAMP));
        sheenPaint.setShader(new LinearGradient(0f, 0f, 0f, getHeight(),
                new int[] {0x72ffffff, 0x0affffff, Color.TRANSPARENT},
                new float[] {0f, 0.4f, 1f}, Shader.TileMode.CLAMP));
        borderPaint.setColor(0x8fffffff);
    }

    @Override
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        if (icon != null && icon.isStateful()) {
            icon.setState(getDrawableState());
        }
    }

    @Override
    protected boolean verifyDrawable(Drawable who) {
        return who == icon || super.verifyDrawable(who);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (iconRect.isEmpty()) {
            return;
        }
        int save = canvas.save();
        canvas.clipPath(clip);
        canvas.drawRoundRect(iconRect, cornerRadius, cornerRadius, backingPaint);
        if (icon != null) {
            if (icon instanceof AdaptiveIconDrawable) {
                icon.setBounds(0, 0, getWidth(), getHeight());
            } else {
                int inset = Math.round(density * 5f);
                icon.setBounds(inset, inset, getWidth() - inset, getHeight() - inset);
            }
            icon.draw(canvas);
        }
        canvas.drawRoundRect(iconRect, cornerRadius, cornerRadius, sheenPaint);
        canvas.restoreToCount(save);
        RectF border = new RectF(iconRect);
        float halfStroke = borderPaint.getStrokeWidth() * 0.5f;
        border.inset(halfStroke, halfStroke);
        canvas.drawRoundRect(border, cornerRadius, cornerRadius, borderPaint);
    }

    private static int withAlpha(int color, int alpha) {
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
    }
}
