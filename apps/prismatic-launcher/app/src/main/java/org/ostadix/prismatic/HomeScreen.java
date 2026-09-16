package org.ostadix.prismatic;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.RadialGradient;
import android.graphics.Rect;
import android.graphics.Shader;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.HapticFeedbackConstants;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.GridLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextClock;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Framework-only, accessible Home surface for the Prismatic Glass launcher. */
final class HomeScreen extends FrameLayout {
    interface Host {
        boolean isHomeRoleHeld();
        void requestHomeRole();
        void openHomeSettings();
        void openApp(LauncherItem item, Rect sourceBounds);
        void showAppActions(LauncherItem item, Rect sourceBounds);
        void showGlassSettings();
        void onSearchModeChanged(boolean active);
    }

    private static final int ACTION_APP_ACTIONS = 0x01020001;

    private static final String[] PREFERRED_DOCK_PACKAGES = {
            "com.google.android.dialer",
            "com.google.android.apps.messaging",
            "com.google.android.GoogleCamera",
            "com.android.chrome"
    };

    private final Host host;
    private final GlassPreferences preferences;
    private final float density;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ArrayList<LauncherItem> apps = new ArrayList<>();
    private final Map<String, View> gridTiles = new HashMap<>();
    private final Runnable filterRunnable = new Runnable() {
        @Override
        public void run() {
            filterGrid();
        }
    };

    private GlassPalette palette;
    private boolean blurAvailable;
    private boolean searchUiActive;
    private int columns = 4;
    private int lastResultCount = -1;
    private int insetTop;
    private int insetBottom;
    private int insetLeft;
    private int insetRight;

    private AmbientView ambient;
    private LinearLayout shell;
    private TextClock clock;
    private TextClock date;
    private TextView roleButton;
    private TextView settingsButton;
    private EditText search;
    private TextView clearSearch;
    private ScrollView scroller;
    private AccessibleGrid grid;
    private TextView emptyState;
    private AccessibleDock dock;
    private FrameLayout dockFrame;

    private GlassDrawable timeGlass;
    private GlassDrawable roleGlass;
    private GlassDrawable settingsGlass;
    private GlassDrawable searchGlass;
    private GlassDrawable dockGlass;
    private GlassDrawable emptyGlass;

    HomeScreen(Context context, Host host, GlassPreferences preferences,
            GlassPalette palette, boolean blurAvailable) {
        super(context);
        this.host = host;
        this.preferences = preferences;
        this.palette = palette;
        this.blurAvailable = blurAvailable;
        this.density = getResources().getDisplayMetrics().density;
        setFocusable(true);
        setFocusableInTouchMode(true);
        setOnApplyWindowInsetsListener(new OnApplyWindowInsetsListener() {
            @Override
            public WindowInsets onApplyWindowInsets(View view, WindowInsets insets) {
                android.graphics.Insets system = insets.getInsets(
                        WindowInsets.Type.systemBars()
                                | WindowInsets.Type.displayCutout()
                                | WindowInsets.Type.mandatorySystemGestures());
                insetTop = system.top;
                insetBottom = system.bottom;
                insetLeft = system.left;
                insetRight = system.right;
                applyInsets();
                return insets;
            }
        });
        buildInterface();
    }

    void setApps(List<LauncherItem> loaded) {
        apps.clear();
        apps.addAll(loaded);
        createGridTiles();
        rebuildDock();
    }

    void setPalette(GlassPalette next) {
        palette = next;
        ambient.setPalette(next, preferences.reduceTransparency());
        clock.setTextColor(next.primaryText);
        date.setTextColor(next.secondaryText);
        search.setTextColor(next.primaryText);
        search.setHintTextColor(next.secondaryText);
        clearSearch.setTextColor(next.primaryText);
        applyMaterial();
        createGridTiles();
        rebuildDock();
    }

    void setBlurAvailable(boolean available) {
        if (blurAvailable == available) {
            return;
        }
        blurAvailable = available;
        applyMaterial();
    }

    void applyPreferences() {
        ambient.setPalette(palette, preferences.reduceTransparency());
        applyMaterial();
        createGridTiles();
        rebuildDock();
    }

    void updateHomeRole() {
        boolean held = host.isHomeRoleHeld();
        roleButton.setText(isLargeText()
                ? (held ? "Active" : "Set Home") : (held ? "Home active" : "Make Home"));
        roleButton.setContentDescription(held
                ? "Prismatic Glass is the current Home app. Double tap for Home app settings."
                : "Make Prismatic Glass the Home app");
    }

    void returnHome() {
        handler.removeCallbacks(filterRunnable);
        search.setText("");
        search.clearFocus();
        hideKeyboard();
        scroller.scrollTo(0, 0);
        host.onSearchModeChanged(false);
        requestFocus();
    }

    boolean handleBack() {
        if (search.hasFocus() || search.length() > 0) {
            returnHome();
            return true;
        }
        return false;
    }

    boolean isSearchActive() {
        return search.hasFocus() || search.length() > 0;
    }

    boolean isPinned(LauncherItem item) {
        return currentDockIds().contains(item.id);
    }

    void togglePinned(LauncherItem item) {
        ArrayList<String> ids = new ArrayList<>(currentDockIds());
        if (ids.remove(item.id)) {
            preferences.setDockIds(ids);
            rebuildDock();
            announceForAccessibility(item.label + " removed from Dock");
            return;
        }
        while (ids.size() >= 4) {
            ids.remove(ids.size() - 1);
        }
        ids.add(item.id);
        preferences.setDockIds(ids);
        rebuildDock();
        announceForAccessibility(item.label + " pinned to Dock");
    }

    private void buildInterface() {
        ambient = new AmbientView(getContext());
        ambient.setPalette(palette, preferences.reduceTransparency());
        addView(ambient, new LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        shell = new LinearLayout(getContext());
        shell.setOrientation(LinearLayout.VERTICAL);
        shell.setClipToPadding(false);
        addView(shell, new LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        applyInsets();

        shell.addView(buildHeader(), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        shell.addView(buildSearch(), withMargins(
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(56)),
                0, 4, 0, 8));

        scroller = new ScrollView(getContext());
        scroller.setFillViewport(true);
        scroller.setClipToPadding(false);
        scroller.setOverScrollMode(OVER_SCROLL_NEVER);
        scroller.setContentDescription("Apps");
        LinearLayout appContent = new LinearLayout(getContext());
        appContent.setOrientation(LinearLayout.VERTICAL);
        appContent.setPadding(0, dp(4), 0, dp(10));
        grid = new AccessibleGrid(getContext());
        grid.setColumnCount(columns);
        grid.setAlignmentMode(GridLayout.ALIGN_BOUNDS);
        grid.setUseDefaultMargins(false);
        grid.setAccessibilityLiveRegion(ACCESSIBILITY_LIVE_REGION_POLITE);
        appContent.addView(grid, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        emptyState = new TextView(getContext());
        emptyState.setGravity(Gravity.CENTER);
        emptyState.setTextSize(16);
        emptyState.setText("No matching apps");
        emptyState.setPadding(dp(24), dp(24), dp(24), dp(24));
        emptyGlass = glass(20f);
        emptyState.setBackground(emptyGlass);
        emptyState.setElevation(dp(7));
        emptyState.setVisibility(GONE);
        appContent.addView(emptyState, withMargins(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
                8, 12, 8, 0));
        scroller.addView(appContent, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        shell.addView(scroller, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        dockFrame = new FrameLayout(getContext());
        dockFrame.setPadding(dp(2), dp(5), dp(2), dp(3));
        dock = new AccessibleDock(getContext());
        dock.setOrientation(LinearLayout.HORIZONTAL);
        dock.setGravity(Gravity.CENTER);
        dock.setPadding(dp(10), dp(8), dp(10), dp(8));
        dockGlass = glass(34f);
        dock.setBackground(dockGlass);
        dock.setElevation(dp(14));
        dock.setContentDescription("Dock");
        dockFrame.addView(dock, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(80), Gravity.CENTER));
        shell.addView(dockFrame, withMargins(
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(90)),
                6, 0, 6, 2));

        updateHomeRole();
    }

    private View buildHeader() {
        boolean largeText = isLargeText();
        LinearLayout header = new LinearLayout(getContext());
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setMinimumHeight(dp(68));
        LinearLayout topRow;
        if (largeText) {
            header.setOrientation(LinearLayout.VERTICAL);
            topRow = new LinearLayout(getContext());
            topRow.setGravity(Gravity.CENTER_VERTICAL);
            topRow.setMinimumHeight(dp(68));
        } else {
            topRow = header;
        }

        LinearLayout timeBlock = new LinearLayout(getContext());
        timeBlock.setOrientation(LinearLayout.VERTICAL);
        timeBlock.setGravity(Gravity.CENTER_VERTICAL);
        timeBlock.setPadding(dp(12), dp(4), dp(12), dp(4));
        timeGlass = glass(18f);
        timeBlock.setBackground(timeGlass);
        timeBlock.setElevation(dp(7));
        clock = new TextClock(getContext());
        clock.setFormat12Hour("h:mm");
        clock.setFormat24Hour("HH:mm");
        clock.setTextSize(25);
        clock.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        clock.setTextColor(palette.primaryText);
        timeBlock.addView(clock, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        date = new TextClock(getContext());
        date.setFormat12Hour("EEEE, MMMM d");
        date.setFormat24Hour("EEEE, MMMM d");
        date.setTextSize(12.5f);
        date.setTextColor(palette.secondaryText);
        date.setSingleLine(true);
        date.setEllipsize(android.text.TextUtils.TruncateAt.END);
        timeBlock.addView(date, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        topRow.addView(timeBlock, new LinearLayout.LayoutParams(0,
                largeText ? ViewGroup.LayoutParams.WRAP_CONTENT
                        : ViewGroup.LayoutParams.MATCH_PARENT, 1f));

        roleButton = glassTextButton("Make Home", 13.5f, 18f);
        roleButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                if (host.isHomeRoleHeld()) {
                    host.openHomeSettings();
                } else {
                    host.requestHomeRole();
                }
            }
        });
        roleGlass = (GlassDrawable) roleButton.getBackground();

        settingsButton = glassTextButton("•••", 17f, 22f);
        settingsButton.setContentDescription("Prismatic Glass settings");
        settingsButton.setMinWidth(dp(48));
        settingsButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                host.showGlassSettings();
            }
        });
        settingsGlass = (GlassDrawable) settingsButton.getBackground();
        if (largeText) {
            topRow.addView(settingsButton, new LinearLayout.LayoutParams(dp(48), dp(48)));
            header.addView(topRow, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            header.addView(roleButton, withMargins(
                    new LinearLayout.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT),
                    0, 4, 0, 0));
        } else {
            header.addView(roleButton, withMargins(
                    new LinearLayout.LayoutParams(
                            ViewGroup.LayoutParams.WRAP_CONTENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT),
                    6, 0, 6, 0));
            header.addView(settingsButton, new LinearLayout.LayoutParams(dp(48), dp(48)));
        }
        return header;
    }

    private View buildSearch() {
        FrameLayout frame = new FrameLayout(getContext());
        search = new EditText(getContext());
        search.setSingleLine(true);
        search.setHint("Search apps");
        search.setTextSize(16);
        search.setTextColor(palette.primaryText);
        search.setHintTextColor(palette.secondaryText);
        search.setPadding(dp(20), 0, dp(52), 0);
        search.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
        search.setImeOptions(EditorInfo.IME_ACTION_GO);
        search.setSelectAllOnFocus(false);
        searchGlass = glass(28f);
        search.setBackground(searchGlass);
        search.setElevation(dp(10));
        attachGlassHotspot(search, searchGlass);
        frame.addView(search, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        clearSearch = new TextView(getContext());
        clearSearch.setText("×");
        clearSearch.setTextSize(26);
        clearSearch.setGravity(Gravity.CENTER);
        clearSearch.setTextColor(palette.primaryText);
        clearSearch.setContentDescription("Clear search");
        clearSearch.setClickable(true);
        clearSearch.setFocusable(true);
        clearSearch.setVisibility(INVISIBLE);
        clearSearch.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                search.setText("");
                search.requestFocus();
            }
        });
        FrameLayout.LayoutParams clearParams = new FrameLayout.LayoutParams(
                dp(48), ViewGroup.LayoutParams.MATCH_PARENT, Gravity.END | Gravity.CENTER_VERTICAL);
        frame.addView(clearSearch, clearParams);

        search.setOnFocusChangeListener(new OnFocusChangeListener() {
            @Override
            public void onFocusChange(View view, boolean focused) {
                setSearchMode(focused || search.length() > 0);
            }
        });
        search.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence value, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence value, int start, int before, int count) {
                clearSearch.setVisibility(value.length() == 0 ? INVISIBLE : VISIBLE);
                setSearchMode(search.hasFocus() || value.length() > 0);
                handler.removeCallbacks(filterRunnable);
                handler.postDelayed(filterRunnable, 350L);
            }

            @Override
            public void afterTextChanged(Editable value) {
            }
        });
        search.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView view, int actionId, KeyEvent event) {
                if (actionId == EditorInfo.IME_ACTION_GO) {
                    LauncherItem first = firstMatch();
                    if (first != null) {
                        open(first, search);
                    }
                    return true;
                }
                return false;
            }
        });
        return frame;
    }

    private TextView glassTextButton(String text, float sizeSp, float radiusDp) {
        TextView button = new TextView(getContext());
        button.setText(text);
        button.setTextSize(sizeSp);
        button.setTextColor(palette.primaryText);
        button.setGravity(Gravity.CENTER);
        button.setPadding(dp(15), 0, dp(15), 0);
        button.setMinWidth(dp(48));
        button.setMinHeight(dp(48));
        button.setClickable(true);
        button.setFocusable(true);
        button.setElevation(dp(7));
        button.setAccessibilityDelegate(new AccessibilityDelegate() {
            @Override
            public void onInitializeAccessibilityNodeInfo(
                    View hostView, AccessibilityNodeInfo info) {
                super.onInitializeAccessibilityNodeInfo(hostView, info);
                info.setClassName("android.widget.Button");
            }
        });
        GlassDrawable material = glass(radiusDp);
        button.setBackground(material);
        attachGlassMotion(button, material);
        return button;
    }

    private void createGridTiles() {
        if (grid == null) {
            return;
        }
        grid.removeAllViews();
        gridTiles.clear();
        int index = 0;
        for (LauncherItem item : apps) {
            int row = index / columns;
            int column = index % columns;
            View tile = appTile(item, preferences.showLabels(), false, row, column);
            gridTiles.put(item.id, tile);
            grid.addView(tile, gridParams(row, column));
            index++;
        }
        filterGrid();
    }

    private void filterGrid() {
        if (grid == null) {
            return;
        }
        String query = normalizedQuery();
        int matchIndex = 0;
        for (LauncherItem item : apps) {
            View tile = gridTiles.get(item.id);
            if (tile == null) {
                continue;
            }
            boolean matches = query.isEmpty() || item.searchText.contains(query);
            tile.setVisibility(matches ? VISIBLE : GONE);
            if (!matches) {
                continue;
            }
            int row = matchIndex / columns;
            int column = matchIndex % columns;
            GridCell cell = (GridCell) tile.getTag();
            cell.row = row;
            cell.column = column;
            tile.setLayoutParams(gridParams(row, column));
            matchIndex++;
        }
        int rows = matchIndex == 0 ? 0 : ((matchIndex - 1) / columns) + 1;
        grid.setCollectionShape(rows, columns);
        if (matchIndex != lastResultCount) {
            String count = matchIndex + (matchIndex == 1 ? " app" : " apps");
            grid.setContentDescription(query.isEmpty() ? count : count + " found");
            lastResultCount = matchIndex;
        }
        emptyState.setTextColor(palette.primaryText);
        emptyState.setVisibility(matchIndex == 0 ? VISIBLE : GONE);
    }

    private GridLayout.LayoutParams gridParams(int row, int column) {
        GridLayout.LayoutParams params = new GridLayout.LayoutParams(
                GridLayout.spec(row), GridLayout.spec(column, 1f));
        params.width = 0;
        params.height = appTileHeight();
        params.setMargins(dp(2), dp(2), dp(2), dp(2));
        return params;
    }

    private void rebuildDock() {
        if (dock == null) {
            return;
        }
        dock.removeAllViews();
        List<LauncherItem> items = resolveDockItems();
        dock.setColumnCount(items.size());
        for (int index = 0; index < items.size(); index++) {
            View tile = appTile(items.get(index), false, true, 0, index);
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.MATCH_PARENT, 1f);
            dock.addView(tile, params);
        }
    }

    private View appTile(final LauncherItem item, boolean showLabel, boolean inDock,
            final int row, final int column) {
        LinearLayout tile = new LinearLayout(getContext());
        final GridCell cell = new GridCell(row, column);
        tile.setTag(cell);
        tile.setOrientation(LinearLayout.VERTICAL);
        tile.setGravity(Gravity.CENTER_HORIZONTAL | Gravity.CENTER_VERTICAL);
        tile.setClickable(true);
        tile.setFocusable(true);
        tile.setLongClickable(true);
        String profileDescription = android.os.Process.myUserHandle().equals(item.user)
                ? "" : ", work profile";
        tile.setContentDescription(item.label + profileDescription + (inDock ? ", Dock" : ""));
        tile.setTooltipText(item.label);
        tile.setPadding(dp(3), dp(2), dp(3), dp(2));
        tile.setAccessibilityDelegate(new AccessibilityDelegate() {
            @Override
            public void onInitializeAccessibilityNodeInfo(
                    View hostView, AccessibilityNodeInfo info) {
                super.onInitializeAccessibilityNodeInfo(hostView, info);
                info.setCollectionItemInfo(AccessibilityNodeInfo.CollectionItemInfo.obtain(
                        cell.row, 1, cell.column, 1, false, false));
                info.addAction(new AccessibilityNodeInfo.AccessibilityAction(
                        ACTION_APP_ACTIONS, "App actions"));
            }

            @Override
            public boolean performAccessibilityAction(
                    View hostView, int action, android.os.Bundle arguments) {
                if (action == ACTION_APP_ACTIONS) {
                    host.showAppActions(item, boundsOnScreen(hostView));
                    return true;
                }
                return super.performAccessibilityAction(hostView, action, arguments);
            }
        });

        int iconSize = dp(inDock ? 57 : 55);
        GlassAppIconView icon = new GlassAppIconView(getContext(), palette);
        icon.setIcon(item.icon);
        icon.setElevation(dp(inDock ? 8 : 5));
        tile.addView(icon, new LinearLayout.LayoutParams(iconSize, iconSize));

        if (showLabel) {
            TextView label = new TextView(getContext());
            label.setText(item.label);
            label.setTextSize(12f);
            label.setTextColor(palette.primaryText);
            label.setGravity(Gravity.CENTER);
            label.setMaxLines(isLargeText() ? 2 : 1);
            label.setEllipsize(android.text.TextUtils.TruncateAt.END);
            label.setPadding(dp(5), 0, dp(5), 0);
            GradientDrawable plate = new GradientDrawable();
            plate.setShape(GradientDrawable.RECTANGLE);
            plate.setCornerRadius(dp(7));
            plate.setColor(palette.darkText ? 0xeeffffff : 0xdd000000);
            label.setBackground(plate);
            label.setMinHeight(dp(23));
            label.setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
            LinearLayout.LayoutParams labelParams = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            labelParams.topMargin = dp(2);
            tile.addView(label, labelParams);
        }

        tile.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                open(item, view);
            }
        });
        tile.setOnLongClickListener(new OnLongClickListener() {
            @Override
            public boolean onLongClick(View view) {
                view.performHapticFeedback(HapticFeedbackConstants.LONG_PRESS);
                host.showAppActions(item, boundsOnScreen(view));
                return true;
            }
        });
        attachScaleMotion(tile);
        return tile;
    }

    private void open(LauncherItem item, View source) {
        host.openApp(item, boundsOnScreen(source));
    }

    private LauncherItem firstMatch() {
        String query = normalizedQuery();
        for (LauncherItem item : apps) {
            if (query.isEmpty() || item.searchText.contains(query)) {
                return item;
            }
        }
        return null;
    }

    private List<LauncherItem> resolveDockItems() {
        Map<String, LauncherItem> byId = new HashMap<>();
        for (LauncherItem app : apps) {
            byId.put(app.id, app);
        }
        ArrayList<LauncherItem> result = new ArrayList<>();
        for (String id : currentDockIds()) {
            LauncherItem item = byId.get(id);
            if (item != null) {
                result.add(item);
            }
        }
        return result;
    }

    private List<String> currentDockIds() {
        if (preferences.dockInitialized()) {
            return preferences.dockIds();
        }
        if (apps.isEmpty()) {
            return new ArrayList<>();
        }
        ArrayList<String> defaults = new ArrayList<>();
        Set<String> used = new HashSet<>();
        for (String packageName : PREFERRED_DOCK_PACKAGES) {
            for (LauncherItem item : apps) {
                if (packageName.equals(item.component.getPackageName()) && used.add(item.id)) {
                    defaults.add(item.id);
                    break;
                }
            }
            if (defaults.size() == 4) {
                break;
            }
        }
        if (defaults.size() < 4) {
            for (LauncherItem item : apps) {
                if (used.add(item.id)) {
                    defaults.add(item.id);
                }
                if (defaults.size() == 4) {
                    break;
                }
            }
        }
        preferences.setDockIds(defaults);
        return defaults;
    }

    private void setSearchMode(boolean active) {
        if (searchUiActive == active) {
            return;
        }
        searchUiActive = active;
        host.onSearchModeChanged(active);
        dockFrame.animate().cancel();
        if (preferences.reduceMotion() || !ValueAnimator.areAnimatorsEnabled()) {
            dockFrame.setAlpha(active ? 0f : 1f);
            dockFrame.setTranslationY(0f);
            dockFrame.setVisibility(active ? INVISIBLE : VISIBLE);
        } else if (active) {
            dockFrame.animate().alpha(0f).translationY(dp(10)).setDuration(120L)
                    .withEndAction(new Runnable() {
                        @Override
                        public void run() {
                            if (searchUiActive) {
                                dockFrame.setVisibility(INVISIBLE);
                            }
                        }
                    }).start();
        } else {
            dockFrame.setVisibility(VISIBLE);
            dockFrame.setAlpha(0f);
            dockFrame.setTranslationY(dp(10));
            dockFrame.animate().alpha(1f).translationY(0f).setDuration(180L).start();
        }
    }

    private void applyMaterial() {
        boolean reduced = preferences.reduceTransparency();
        timeGlass.setMaterial(palette, reduced, blurAvailable);
        roleGlass.setMaterial(palette, reduced, blurAvailable);
        settingsGlass.setMaterial(palette, reduced, blurAvailable);
        searchGlass.setMaterial(palette, reduced, blurAvailable);
        dockGlass.setMaterial(palette, reduced, blurAvailable);
        emptyGlass.setMaterial(palette, reduced, blurAvailable);
        roleButton.setTextColor(palette.primaryText);
        settingsButton.setTextColor(palette.primaryText);
        search.setTextColor(palette.primaryText);
        search.setHintTextColor(palette.secondaryText);
        clearSearch.setTextColor(palette.primaryText);
    }

    private GlassDrawable glass(float radiusDp) {
        return new GlassDrawable(density, radiusDp, palette,
                preferences.reduceTransparency(), blurAvailable);
    }

    private void attachGlassHotspot(final View view, final GlassDrawable material) {
        view.setOnTouchListener(new OnTouchListener() {
            @Override
            public boolean onTouch(View touched, MotionEvent event) {
                if (touched.getWidth() > 0 && touched.getHeight() > 0) {
                    material.setLightPosition(event.getX() / touched.getWidth(),
                            event.getY() / touched.getHeight());
                }
                return false;
            }
        });
    }

    private void attachGlassMotion(final View view, final GlassDrawable material) {
        view.setOnTouchListener(new OnTouchListener() {
            @Override
            public boolean onTouch(View touched, MotionEvent event) {
                if (touched.getWidth() > 0 && touched.getHeight() > 0) {
                    material.setLightPosition(event.getX() / touched.getWidth(),
                            event.getY() / touched.getHeight());
                }
                animateTouch(touched, event);
                return false;
            }
        });
    }

    private void attachScaleMotion(final View view) {
        view.setOnTouchListener(new OnTouchListener() {
            @Override
            public boolean onTouch(View touched, MotionEvent event) {
                animateTouch(touched, event);
                return false;
            }
        });
    }

    private void animateTouch(View view, MotionEvent event) {
        if (preferences.reduceMotion() || !ValueAnimator.areAnimatorsEnabled()) {
            view.setScaleX(1f);
            view.setScaleY(1f);
            view.setTranslationY(0f);
            return;
        }
        if (event.getActionMasked() == MotionEvent.ACTION_DOWN) {
            view.animate().cancel();
            view.animate().scaleX(0.95f).scaleY(0.95f)
                    .translationY(dp(1)).setDuration(85L).start();
        } else if (event.getActionMasked() == MotionEvent.ACTION_UP
                || event.getActionMasked() == MotionEvent.ACTION_CANCEL) {
            view.animate().cancel();
            view.animate().scaleX(1f).scaleY(1f).translationY(0f)
                    .setDuration(210L)
                    .setInterpolator(new android.view.animation.DecelerateInterpolator(1.8f))
                    .start();
        }
    }

    private void applyInsets() {
        if (shell == null) {
            return;
        }
        shell.setPadding(
                Math.max(dp(14), insetLeft + dp(10)),
                insetTop + dp(6),
                Math.max(dp(14), insetRight + dp(10)),
                insetBottom + dp(5));
    }

    @Override
    protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
        super.onSizeChanged(width, height, oldWidth, oldHeight);
        float widthDp = width / density;
        int nextColumns = widthDp >= 840f ? 8 : (widthDp >= 600f ? 6 : 4);
        if (isLargeText()) {
            nextColumns = Math.min(nextColumns, widthDp >= 600f ? 4 : 3);
        }
        if (nextColumns != columns) {
            columns = nextColumns;
            if (grid != null) {
                grid.setColumnCount(columns);
                filterGrid();
            }
        }
    }

    private String normalizedQuery() {
        return search == null
                ? ""
                : search.getText().toString().trim().toLowerCase(Locale.ROOT);
    }

    private void hideKeyboard() {
        InputMethodManager keyboard = getContext().getSystemService(InputMethodManager.class);
        if (keyboard != null) {
            keyboard.hideSoftInputFromWindow(getWindowToken(), 0);
        }
    }

    private Rect boundsOnScreen(View view) {
        Rect bounds = new Rect();
        if (!view.getGlobalVisibleRect(bounds)) {
            int[] location = new int[2];
            view.getLocationOnScreen(location);
            bounds.set(location[0], location[1],
                    location[0] + view.getWidth(), location[1] + view.getHeight());
        }
        return bounds;
    }

    private LinearLayout.LayoutParams withMargins(LinearLayout.LayoutParams params,
            int left, int top, int right, int bottom) {
        params.setMargins(dp(left), dp(top), dp(right), dp(bottom));
        return params;
    }

    private int appTileHeight() {
        float fontScale = getResources().getConfiguration().fontScale;
        float lines = isLargeText() ? 2f : 1f;
        float labelHeight = Math.max(24f, 22f * fontScale * lines);
        return dp(preferences.showLabels() ? 70f + labelHeight : 76f);
    }

    private boolean isLargeText() {
        return getResources().getConfiguration().fontScale >= 1.35f;
    }

    private int dp(float value) {
        return Math.round(value * density);
    }

    private static final class GridCell {
        int row;
        int column;

        GridCell(int row, int column) {
            this.row = row;
            this.column = column;
        }
    }

    private static final class AccessibleGrid extends GridLayout {
        private int rows;
        private int columns;

        AccessibleGrid(Context context) {
            super(context);
        }

        void setCollectionShape(int rows, int columns) {
            this.rows = rows;
            this.columns = columns;
        }

        @Override
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setCollectionInfo(AccessibilityNodeInfo.CollectionInfo.obtain(
                    rows, columns, false, AccessibilityNodeInfo.CollectionInfo.SELECTION_MODE_NONE));
        }
    }

    private static final class AccessibleDock extends LinearLayout {
        private int columns;

        AccessibleDock(Context context) {
            super(context);
        }

        void setColumnCount(int value) {
            columns = value;
        }

        @Override
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setCollectionInfo(AccessibilityNodeInfo.CollectionInfo.obtain(
                    columns == 0 ? 0 : 1,
                    columns,
                    false,
                    AccessibilityNodeInfo.CollectionInfo.SELECTION_MODE_NONE));
        }
    }

    private static final class AmbientView extends View {
        private final android.graphics.Paint topPaint = new android.graphics.Paint(
                android.graphics.Paint.ANTI_ALIAS_FLAG);
        private final android.graphics.Paint bottomPaint = new android.graphics.Paint(
                android.graphics.Paint.ANTI_ALIAS_FLAG);
        private final android.graphics.Paint scrimPaint = new android.graphics.Paint();
        private GlassPalette palette;
        private boolean reduceTransparency;

        AmbientView(Context context) {
            super(context);
            setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
        }

        void setPalette(GlassPalette palette, boolean reduceTransparency) {
            this.palette = palette;
            this.reduceTransparency = reduceTransparency;
            rebuildShaders();
            invalidate();
        }

        @Override
        protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
            super.onSizeChanged(width, height, oldWidth, oldHeight);
            rebuildShaders();
        }

        private void rebuildShaders() {
            if (palette == null || getWidth() == 0 || getHeight() == 0) {
                return;
            }
            topPaint.setShader(new RadialGradient(
                    getWidth() * 0.16f, getHeight() * 0.07f,
                    Math.max(getWidth(), getHeight()) * 0.62f,
                    new int[] {withAlpha(palette.accent, 66), Color.TRANSPARENT},
                    null, Shader.TileMode.CLAMP));
            bottomPaint.setShader(new RadialGradient(
                    getWidth() * 0.94f, getHeight() * 0.88f,
                    Math.max(getWidth(), getHeight()) * 0.55f,
                    new int[] {withAlpha(rotateHue(palette.accent), 52), Color.TRANSPARENT},
                    null, Shader.TileMode.CLAMP));
            int scrimAlpha = reduceTransparency ? 76 : 24;
            scrimPaint.setColor(palette.darkText
                    ? Color.argb(scrimAlpha, 255, 255, 255)
                    : Color.argb(scrimAlpha, 0, 0, 0));
        }

        @Override
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            canvas.drawRect(0f, 0f, getWidth(), getHeight(), scrimPaint);
            canvas.drawRect(0f, 0f, getWidth(), getHeight(), topPaint);
            canvas.drawRect(0f, 0f, getWidth(), getHeight(), bottomPaint);
        }

        private static int rotateHue(int color) {
            float[] hsv = new float[3];
            Color.colorToHSV(color, hsv);
            hsv[0] = (hsv[0] + 52f) % 360f;
            return Color.HSVToColor(hsv);
        }

        private static int withAlpha(int color, int alpha) {
            return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
        }
    }
}
