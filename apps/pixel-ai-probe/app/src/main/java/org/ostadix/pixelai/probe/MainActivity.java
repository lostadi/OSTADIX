package org.ostadix.pixelai.probe;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.mlkit.genai.common.FeatureStatus;
import com.google.mlkit.genai.common.GenAiException;
import com.google.mlkit.genai.imagedescription.ImageDescriber;
import com.google.mlkit.genai.imagedescription.ImageDescriberOptions;
import com.google.mlkit.genai.imagedescription.ImageDescription;
import com.google.mlkit.genai.imagedescription.ImageDescriptionRequest;
import com.google.mlkit.genai.imagedescription.ImageDescriptionResult;
import com.google.mlkit.genai.prompt.Candidate;
import com.google.mlkit.genai.prompt.CountTokensResponse;
import com.google.mlkit.genai.prompt.GenerateContentRequest;
import com.google.mlkit.genai.prompt.GenerateContentResponse;
import com.google.mlkit.genai.prompt.Generation;
import com.google.mlkit.genai.prompt.GenerationConfig;
import com.google.mlkit.genai.prompt.GenerativeModel;
import com.google.mlkit.genai.prompt.ModelConfig;
import com.google.mlkit.genai.prompt.ModelPreference;
import com.google.mlkit.genai.prompt.ModelReleaseStage;
import com.google.mlkit.genai.prompt.TextPart;
import com.google.mlkit.genai.prompt.java.GenerativeModelFutures;
import com.google.mlkit.genai.speechrecognition.SpeechRecognition;
import com.google.mlkit.genai.speechrecognition.SpeechRecognizer;
import com.google.mlkit.genai.speechrecognition.SpeechRecognizerOptions;
import com.google.mlkit.genai.summarization.Summarization;
import com.google.mlkit.genai.summarization.SummarizationRequest;
import com.google.mlkit.genai.summarization.SummarizationResult;
import com.google.mlkit.genai.summarization.Summarizer;
import com.google.mlkit.genai.summarization.SummarizerOptions;

import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import kotlin.ResultKt;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt;

/**
 * A user-triggered, foreground-only probe for the public ML Kit GenAI APIs.
 *
 * No user content is accepted. Every inference input is a constant or an in-memory bitmap created
 * below. The activity cancels outstanding futures and closes all clients as soon as it is paused
 * or loses window focus, and it refuses calls while the secure keyguard reports the device locked.
 */
public final class MainActivity extends Activity {
    private static final String TAG = "PixelAiProbe";
    private static final String PROBE_VERSION = "0.1.3";

    public static final String ACTION_RUN_PROMPT =
            "org.ostadix.pixelai.probe.RUN_PROMPT";
    public static final String ACTION_RUN_SUMMARY =
            "org.ostadix.pixelai.probe.RUN_SUMMARY";
    public static final String ACTION_RUN_IMAGE =
            "org.ostadix.pixelai.probe.RUN_IMAGE";
    public static final String ACTION_RUN_SPEECH_STATUS =
            "org.ostadix.pixelai.probe.RUN_SPEECH_STATUS";
    public static final String ACTION_RUN_ALL =
            "org.ostadix.pixelai.probe.RUN_ALL";

    private static final String PROMPT_VERSION = "genai-prompt:1.0.0-beta4";
    private static final String SUMMARY_VERSION = "genai-summarization:1.0.0-beta1";
    private static final String IMAGE_VERSION = "genai-image-description:1.0.0-beta1";
    private static final String SPEECH_VERSION = "genai-speech-recognition:1.0.0-alpha1";

    private static final String SYNTHETIC_BUILD_LOG =
            "[00:00:01] compile app/Main.java\n"
                    + "[00:00:02] error: package demo.widgets does not exist\n"
                    + "[00:00:02] import demo.widgets.Panel;\n"
                    + "[00:00:03] error: cannot find symbol class Panel\n"
                    + "[00:00:03] error: cannot find symbol class Panel\n"
                    + "[00:00:04] build failed with 3 errors";

    private static final String SYNTHETIC_PROMPT =
            "Analyze this entirely synthetic build log. Return one line in exactly this format: "
                    + "ROOT_CAUSE=<short cause>;DISTINCT_ERRORS=<integer>;NEXT_STEP=<short action>. "
                    + "Count repeated messages once.\n\n" + SYNTHETIC_BUILD_LOG;

    // ARTICLE input must exceed 400 characters. This synthetic passage is intentionally non-private.
    private static final String SYNTHETIC_ARTICLE =
            "A fictional engineering team tested a tiny offline classification tool in a controlled "
                    + "laboratory. The first run loaded a model, converted a short generated input, "
                    + "and produced a label. The team then repeated the same generated request ten "
                    + "times while recording startup time, inference time, and memory use. Nothing in "
                    + "the experiment came from a real user, message, recording, photograph, account, "
                    + "or device database. During the warm trials, latency became steadier because the "
                    + "runtime no longer had to initialize every component. One deliberately invalid "
                    + "request was also submitted so the report would contain a reproducible error. "
                    + "The team concluded that backend identity still required an independent trace: "
                    + "a fast result alone did not prove that specialized hardware executed the model. "
                    + "They preserved the generated inputs, version numbers, timings, and full error "
                    + "messages so another engineer could repeat the same narrow test.";

    private final List<Future<?>> pending = Collections.synchronizedList(new ArrayList<>());
    private final Executor mainExecutor = command -> runOnUiThread(command);
    private final ExecutorService speechExecutor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "pixel-ai-speech-status");
        thread.setDaemon(true);
        return thread;
    });

    private TextView output;
    private Button promptButton;
    private Button summaryButton;
    private Button imageButton;
    private Button speechButton;
    private boolean resumed;

    private GenerativeModel promptClient;
    private Summarizer summarizer;
    private ImageDescriber imageDescriber;
    private SpeechRecognizer speechRecognizer;
    private String queuedAutomationAction;

    private interface Formatter<T> {
        String format(T value);
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(buildUi());
        queuedAutomationAction = getIntent() == null ? null : getIntent().getAction();
        append("probe", "created", "version=" + PROBE_VERSION
                + "; no private input; no automatic model download; no background run", 0);
        append("versions", "resolved", PROMPT_VERSION + "; " + SUMMARY_VERSION + "; "
                + IMAGE_VERSION + "; " + SPEECH_VERSION, 0);
    }

    @Override
    protected void onResume() {
        super.onResume();
        resumed = true;
        refreshProbeAvailability("resumed");
    }

    @Override
    protected void onPostResume() {
        super.onPostResume();
        // onPostResume does not prove that this window is focused or unobscured. Automation is
        // dispatched from onWindowFocusChanged only after the full foreground gate passes.
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (!hasFocus) {
            setProbeButtonsEnabled(false);
            if (resumed) {
                cancelPending();
                closeAllClients();
                append("lifecycle", "focusLost",
                        "Cancelled pending futures and closed ML clients", 0);
            }
            return;
        }
        refreshProbeAvailability("windowFocused");
        dispatchQueuedAutomation();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        queuedAutomationAction = intent == null ? null : intent.getAction();
        if (isProbeForeground()) {
            dispatchQueuedAutomation();
        }
    }

    @Override
    protected void onPause() {
        resumed = false;
        setProbeButtonsEnabled(false);
        cancelPending();
        closeAllClients();
        append("lifecycle", "paused", "Cancelled pending futures and closed ML clients", 0);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        closeAllClients();
        speechExecutor.shutdownNow();
        super.onDestroy();
    }

    private View buildUi() {
        int pad = dp(18);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);
        root.setBackgroundColor(Color.rgb(246, 248, 250));

        TextView title = new TextView(this);
        title.setText("Pixel on-device AI probe");
        title.setTextSize(24);
        title.setTextColor(Color.rgb(24, 31, 42));
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        root.addView(title, matchWrap());

        TextView note = new TextView(this);
        note.setText("Tap one probe while this screen is visible. Inference runs only when status is "
                + "AVAILABLE. Inputs are synthetic; DOWNLOADABLE models are not downloaded automatically.");
        note.setTextSize(15);
        note.setTextColor(Color.rgb(65, 75, 88));
        note.setPadding(0, dp(8), 0, dp(12));
        root.addView(note, matchWrap());

        promptButton = addButton(root, R.id.probe_prompt,
                "Prompt: status + metadata + synthetic log analysis", v -> runPrompt());
        summaryButton = addButton(root, R.id.probe_summary,
                "Summarization: readiness + synthetic article", v -> runSummary());
        imageButton = addButton(root, R.id.probe_image,
                "Image description: readiness + generated bitmap", v -> runImage());
        speechButton = addButton(root, R.id.probe_speech,
                "Speech: advanced-mode readiness only", v -> runSpeechStatus());

        Button clear = addButton(root, R.id.probe_clear, "Clear report", v -> output.setText(""));
        clear.setContentDescription("Clear the probe report shown below");

        TextView reportTitle = new TextView(this);
        reportTitle.setText("Evidence log");
        reportTitle.setTextSize(17);
        reportTitle.setTextColor(Color.rgb(24, 31, 42));
        reportTitle.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        reportTitle.setPadding(0, dp(12), 0, dp(6));
        root.addView(reportTitle, matchWrap());

        output = new TextView(this);
        output.setId(R.id.probe_output);
        output.setTextSize(12);
        output.setTextColor(Color.rgb(18, 24, 32));
        output.setTypeface(android.graphics.Typeface.MONOSPACE);
        output.setTextIsSelectable(true);
        output.setMovementMethod(new ScrollingMovementMethod());
        output.setPadding(dp(12), dp(12), dp(12), dp(12));
        output.setBackgroundColor(Color.WHITE);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(output, matchWrap());
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        root.addView(scroll, scrollParams);
        return root;
    }

    private Button addButton(LinearLayout root, int id, String label,
            View.OnClickListener listener) {
        Button button = new Button(this);
        button.setId(id);
        button.setText(label);
        button.setAllCaps(false);
        button.setGravity(Gravity.CENTER_VERTICAL);
        button.setOnClickListener(listener);
        LinearLayout.LayoutParams params = matchWrap();
        params.bottomMargin = dp(5);
        root.addView(button, params);
        return button;
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private boolean begin(Button button, String scope, String version) {
        if (!isProbeForeground()) {
            append(scope, "blocked",
                    "Requires resumed, focused, unlocked Activity; resumed=" + resumed
                            + "; windowFocus=" + hasWindowFocus()
                            + "; deviceLocked=" + isDeviceLocked(),
                    0);
            return false;
        }
        if (!button.isEnabled()) {
            append(scope, "blocked", "Probe is already running", 0);
            return false;
        }
        button.setEnabled(false);
        append(scope, "start", version, 0);
        return true;
    }

    private void dispatchQueuedAutomation() {
        String action = queuedAutomationAction;
        if (action == null || Intent.ACTION_MAIN.equals(action)) {
            queuedAutomationAction = null;
            return;
        }
        if (!isProbeForeground()) {
            append("automation", "deferred",
                    "Waiting for resumed, focused, unlocked Activity; action=" + action, 0);
            return;
        }
        queuedAutomationAction = null;
        append("automation", "intent", "action=" + action, 0);
        switch (action) {
            case ACTION_RUN_PROMPT:
                runPrompt();
                break;
            case ACTION_RUN_SUMMARY:
                runSummary();
                break;
            case ACTION_RUN_IMAGE:
                runImage();
                break;
            case ACTION_RUN_SPEECH_STATUS:
                runSpeechStatus();
                break;
            case ACTION_RUN_ALL:
                runPrompt();
                runSummary();
                runImage();
                runSpeechStatus();
                break;
            default:
                append("automation", "ignored", "Unknown action=" + action, 0);
        }
    }

    private void refreshProbeAvailability(String event) {
        boolean ready = isProbeForeground();
        setProbeButtonsEnabled(ready);
        append("lifecycle", event,
                ready
                        ? "Probe calls are enabled; Activity is resumed, focused, and unlocked"
                        : "Probe calls disabled; resumed=" + resumed
                                + "; windowFocus=" + hasWindowFocus()
                                + "; deviceLocked=" + isDeviceLocked(),
                0);
    }

    private boolean isProbeForeground() {
        return resumed && !isFinishing() && hasWindowFocus() && !isDeviceLocked();
    }

    private boolean isDeviceLocked() {
        KeyguardManager keyguard = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        return keyguard == null || keyguard.isDeviceLocked();
    }

    private void runPrompt() {
        if (!begin(promptButton, "prompt", PROMPT_VERSION)) {
            return;
        }
        closePrompt();
        final long suiteStart = SystemClock.elapsedRealtime();
        try {
            String requestedModel = getIntent() == null ? null
                    : getIntent().getStringExtra("nano_model");
            if (requestedModel == null) {
                requestedModel = "stable_full";
            }
            final int releaseStage;
            final int preference;
            switch (requestedModel) {
                case "stable_full":
                    releaseStage = ModelReleaseStage.STABLE;
                    preference = ModelPreference.FULL;
                    break;
                case "stable_fast":
                    releaseStage = ModelReleaseStage.STABLE;
                    preference = ModelPreference.FAST;
                    break;
                case "preview_full":
                    releaseStage = ModelReleaseStage.PREVIEW;
                    preference = ModelPreference.FULL;
                    break;
                case "preview_fast":
                    releaseStage = ModelReleaseStage.PREVIEW;
                    preference = ModelPreference.FAST;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown Nano model configuration");
            }
            ModelConfig.Builder modelConfig = new ModelConfig.Builder();
            modelConfig.setReleaseStage(releaseStage);
            modelConfig.setPreference(preference);
            GenerationConfig.Builder generationConfig = new GenerationConfig.Builder();
            generationConfig.setModelConfig(modelConfig.build());
            append("prompt", "target",
                    "provider=AICore; modelFamily=Gemini Nano; configuration="
                            + requestedModel + "; cloudFallback=false; "
                            + "requested configuration, not proof of inference",
                    elapsed(suiteStart));
            promptClient = Generation.INSTANCE.getClient(generationConfig.build());
            final GenerativeModel client = promptClient;
            final GenerativeModelFutures futures = GenerativeModelFutures.from(client);

            GenerateContentRequest.Builder requestBuilder =
                    new GenerateContentRequest.Builder(new TextPart(SYNTHETIC_PROMPT));
            requestBuilder.setTemperature(0.0f);
            requestBuilder.setSeed(7);
            requestBuilder.setTopK(1);
            requestBuilder.setCandidateCount(1);
            requestBuilder.setMaxOutputTokens(64);
            final GenerateContentRequest request = requestBuilder.build();

            final AtomicInteger remaining = new AtomicInteger(4);
            final Runnable oneDone = () -> {
                if (remaining.decrementAndGet() == 0) {
                    finishPrompt(client, suiteStart);
                }
            };

            observe(futures.getBaseModelName(), "prompt", "baseModel", suiteStart,
                    value -> "name=" + quote(value), oneDone);
            observe(futures.getTokenLimit(), "prompt", "tokenLimit", suiteStart,
                    value -> "tokens=" + value, oneDone);
            observe(futures.countTokens(request), "prompt", "syntheticTokenCount", suiteStart,
                    value -> "tokens=" + value.getTotalTokens() + "; promptChars="
                            + SYNTHETIC_PROMPT.length(), oneDone);
            observe(futures.checkStatus(), "prompt", "status", suiteStart, value -> {
                if (value != null && value == FeatureStatus.AVAILABLE
                        && isProbeForeground()) {
                    remaining.incrementAndGet();
                    observe(futures.generateContent(request), "prompt", "syntheticInference",
                            suiteStart, MainActivity::formatPromptResult, oneDone);
                } else {
                    append("prompt", "syntheticInference", "skipped; status="
                            + statusName(value), elapsed(suiteStart));
                }
                return "value=" + value + " (" + statusName(value) + ")";
            }, oneDone);
        } catch (Throwable failure) {
            recordFailure("prompt", "setup", suiteStart, failure);
            closePrompt();
            if (isProbeForeground()) {
                promptButton.setEnabled(true);
            }
        }
    }

    private static String formatPromptResult(GenerateContentResponse response) {
        if (response == null || response.getCandidates() == null) {
            return "response=null";
        }
        StringBuilder detail = new StringBuilder("candidateCount=")
                .append(response.getCandidates().size());
        int index = 0;
        for (Candidate candidate : response.getCandidates()) {
            detail.append("\n  candidate[").append(index++).append("] finishReason=")
                    .append(candidate.getFinishReason()).append(" text=")
                    .append(quote(candidate.getText()));
        }
        return detail.toString();
    }

    private void finishPrompt(GenerativeModel client, long started) {
        if (promptClient == client) {
            closePrompt();
        } else {
            closeQuietly(client);
        }
        append("prompt", "complete", "client closed", elapsed(started));
        if (isProbeForeground()) {
            promptButton.setEnabled(true);
        }
    }

    private void runSummary() {
        if (!begin(summaryButton, "summary", SUMMARY_VERSION)) {
            return;
        }
        closeSummary();
        final long suiteStart = SystemClock.elapsedRealtime();
        try {
            SummarizerOptions options = SummarizerOptions.builder(this)
                    .setInputType(SummarizerOptions.InputType.ARTICLE)
                    .setOutputType(SummarizerOptions.OutputType.ONE_BULLET)
                    .setLanguage(SummarizerOptions.Language.ENGLISH)
                    .setLongInputAutoTruncationEnabled(false)
                    .build();
            summarizer = Summarization.getClient(options);
            final Summarizer client = summarizer;
            final SummarizationRequest request =
                    SummarizationRequest.builder(SYNTHETIC_ARTICLE).build();
            final AtomicInteger remaining = new AtomicInteger(2);
            final Runnable oneDone = () -> {
                if (remaining.decrementAndGet() == 0) {
                    finishSummary(client, suiteStart);
                }
            };

            append("summary", "syntheticInput", "chars=" + SYNTHETIC_ARTICLE.length()
                    + "; type=ARTICLE; output=ONE_BULLET; language=ENGLISH", elapsed(suiteStart));
            observe(client.getBaseModelName(), "summary", "baseModel", suiteStart,
                    value -> "name=" + quote(value), oneDone);
            observe(client.checkFeatureStatus(), "summary", "status", suiteStart, value -> {
                if (value != null && value == FeatureStatus.AVAILABLE
                        && isProbeForeground()) {
                    remaining.incrementAndGet();
                    observe(client.runInference(request), "summary", "syntheticInference",
                            suiteStart, result -> "summary=" + quote(result.getSummary()), oneDone);
                } else {
                    append("summary", "syntheticInference", "skipped; status="
                            + statusName(value), elapsed(suiteStart));
                }
                return "value=" + value + " (" + statusName(value) + ")";
            }, oneDone);
        } catch (Throwable failure) {
            recordFailure("summary", "setup", suiteStart, failure);
            closeSummary();
            if (isProbeForeground()) {
                summaryButton.setEnabled(true);
            }
        }
    }

    private void finishSummary(Summarizer client, long started) {
        if (summarizer == client) {
            closeSummary();
        } else {
            closeQuietly(client);
        }
        append("summary", "complete", "client closed", elapsed(started));
        if (isProbeForeground()) {
            summaryButton.setEnabled(true);
        }
    }

    private void runImage() {
        if (!begin(imageButton, "image", IMAGE_VERSION)) {
            return;
        }
        closeImage();
        final long suiteStart = SystemClock.elapsedRealtime();
        try {
            ImageDescriberOptions options = ImageDescriberOptions.builder(this).build();
            imageDescriber = ImageDescription.getClient(options);
            final ImageDescriber client = imageDescriber;
            final AtomicInteger remaining = new AtomicInteger(2);
            final Runnable oneDone = () -> {
                if (remaining.decrementAndGet() == 0) {
                    finishImage(client, suiteStart);
                }
            };

            observe(client.getBaseModelName(), "image", "baseModel", suiteStart,
                    value -> "name=" + quote(value), oneDone);
            observe(client.checkFeatureStatus(), "image", "status", suiteStart, value -> {
                if (value != null && value == FeatureStatus.AVAILABLE
                        && isProbeForeground()) {
                    final Bitmap bitmap = createSyntheticBitmap();
                    final ImageDescriptionRequest request =
                            ImageDescriptionRequest.builder(bitmap).build();
                    append("image", "syntheticInput",
                            "inMemory=true; width=" + bitmap.getWidth() + "; height="
                                    + bitmap.getHeight() + "; format=ARGB_8888",
                            elapsed(suiteStart));
                    remaining.incrementAndGet();
                    observe(client.runInference(request), "image", "syntheticInference", suiteStart,
                            result -> "description=" + quote(result.getDescription()), () -> {
                                bitmap.recycle();
                                oneDone.run();
                            });
                } else {
                    append("image", "syntheticInference", "skipped; status="
                            + statusName(value), elapsed(suiteStart));
                }
                return "value=" + value + " (" + statusName(value) + ")";
            }, oneDone);
        } catch (Throwable failure) {
            recordFailure("image", "setup", suiteStart, failure);
            closeImage();
            if (isProbeForeground()) {
                imageButton.setEnabled(true);
            }
        }
    }

    private static Bitmap createSyntheticBitmap() {
        Bitmap bitmap = Bitmap.createBitmap(256, 256, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);
        canvas.drawColor(Color.rgb(225, 238, 252));
        Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        paint.setColor(Color.rgb(30, 125, 72));
        canvas.drawRect(0, 168, 256, 256, paint);
        paint.setColor(Color.rgb(252, 190, 42));
        canvas.drawCircle(204, 52, 28, paint);
        paint.setColor(Color.rgb(39, 92, 160));
        canvas.drawRect(50, 103, 142, 185, paint);
        paint.setColor(Color.WHITE);
        canvas.drawCircle(78, 135, 9, paint);
        canvas.drawCircle(116, 135, 9, paint);
        paint.setColor(Color.rgb(15, 24, 35));
        paint.setStrokeWidth(7);
        canvas.drawLine(77, 165, 115, 165, paint);
        return bitmap;
    }

    private void finishImage(ImageDescriber client, long started) {
        if (imageDescriber == client) {
            closeImage();
        } else {
            closeQuietly(client);
        }
        append("image", "complete", "client closed", elapsed(started));
        if (isProbeForeground()) {
            imageButton.setEnabled(true);
        }
    }

    private void runSpeechStatus() {
        if (!begin(speechButton, "speech", SPEECH_VERSION)) {
            return;
        }
        closeSpeech();
        final long started = SystemClock.elapsedRealtime();
        final AtomicBoolean completed = new AtomicBoolean(false);
        try {
            SpeechRecognizerOptions.Builder builder = new SpeechRecognizerOptions.Builder();
            builder.setLocale(Locale.US);
            builder.setPreferredMode(SpeechRecognizerOptions.Mode.MODE_ADVANCED);
            builder.setExecutor(speechExecutor);
            speechRecognizer = SpeechRecognition.INSTANCE.getClient(builder.build());
            final SpeechRecognizer client = speechRecognizer;
            append("speech", "configuration",
                    "locale=en-US; preferredMode=MODE_ADVANCED(1); microphoneNotOpened=true",
                    elapsed(started));

            Continuation<Integer> continuation = new Continuation<Integer>() {
                @Override
                public CoroutineContext getContext() {
                    return EmptyCoroutineContext.INSTANCE;
                }

                @Override
                public void resumeWith(Object result) {
                    mainExecutor.execute(() -> {
                        try {
                            ResultKt.throwOnFailure(result);
                            completeSpeechStatus(client, (Integer) result, started, completed);
                        } catch (Throwable failure) {
                            failSpeechStatus(client, started, completed, failure);
                        }
                    });
                }
            };

            Object result = client.checkStatus(continuation);
            if (result != IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                completeSpeechStatus(client, (Integer) result, started, completed);
            }
        } catch (Throwable failure) {
            SpeechRecognizer client = speechRecognizer;
            failSpeechStatus(client, started, completed, failure);
        }
    }

    private void completeSpeechStatus(SpeechRecognizer client, Integer status, long started,
            AtomicBoolean completed) {
        if (!completed.compareAndSet(false, true)) {
            return;
        }
        append("speech", "advancedStatus", "value=" + status + " (" + statusName(status) + ")",
                elapsed(started));
        finishSpeech(client, started);
    }

    private void failSpeechStatus(SpeechRecognizer client, long started, AtomicBoolean completed,
            Throwable failure) {
        if (!completed.compareAndSet(false, true)) {
            return;
        }
        recordFailure("speech", "advancedStatus", started, failure);
        finishSpeech(client, started);
    }

    private void finishSpeech(SpeechRecognizer client, long started) {
        if (speechRecognizer == client) {
            closeSpeech();
        } else {
            closeQuietly(client);
        }
        append("speech", "complete", "readiness only; client closed", elapsed(started));
        if (isProbeForeground()) {
            speechButton.setEnabled(true);
        }
    }

    private <T> void observe(ListenableFuture<T> future, String scope, String operation,
            long started, Formatter<T> formatter, Runnable done) {
        pending.add(future);
        Futures.addCallback(future, new FutureCallback<T>() {
            @Override
            public void onSuccess(T value) {
                pending.remove(future);
                try {
                    append(scope, operation, formatter.format(value), elapsed(started));
                } catch (Throwable formatterFailure) {
                    recordFailure(scope, operation + ".format", started, formatterFailure);
                } finally {
                    done.run();
                }
            }

            @Override
            public void onFailure(Throwable failure) {
                pending.remove(future);
                if (!(failure instanceof CancellationException)) {
                    recordFailure(scope, operation, started, failure);
                } else {
                    append(scope, operation, "cancelled", elapsed(started));
                }
                done.run();
            }
        }, mainExecutor);
    }

    private void recordFailure(String scope, String operation, long started, Throwable failure) {
        String detail = formatFailure(failure);
        append(scope, operation + ".failure", detail, elapsed(started));
        Log.e(TAG, "[" + scope + "] " + operation + " failed; " + detail, failure);
    }

    private static String formatFailure(Throwable failure) {
        StringBuilder text = new StringBuilder();
        Throwable cursor = failure;
        GenAiException genAi = null;
        int depth = 0;
        while (cursor != null && depth < 12) {
            if (depth > 0) {
                text.append("\n  causedBy=");
            }
            text.append(cursor.getClass().getName())
                    .append("; message=").append(quote(cursor.getMessage()));
            if (genAi == null && cursor instanceof GenAiException) {
                genAi = (GenAiException) cursor;
            }
            cursor = cursor.getCause();
            depth++;
        }
        if (genAi != null) {
            Duration delay = genAi.getRetryDelay();
            text.append("\n  genAiErrorCode=").append(genAi.getErrorCode())
                    .append("; retryDelay=").append(delay == null ? "null" : delay.toString())
                    .append("; retryDelayMs=")
                    .append(delay == null ? "null" : Long.toString(delay.toMillis()));
        } else {
            text.append("\n  genAiErrorCode=not-present; retryDelay=not-present");
        }
        return text.toString();
    }

    private void append(String scope, String event, String detail, long elapsedMs) {
        String timestamp = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(new Date());
        String line = timestamp + " [" + scope + "] " + event + " elapsedMs=" + elapsedMs
                + "\n" + detail + "\n\n";
        Log.i(TAG, line.trim());
        if (output != null) {
            output.append(line);
        }
    }

    private static long elapsed(long started) {
        return SystemClock.elapsedRealtime() - started;
    }

    private static String quote(String value) {
        if (value == null) {
            return "null";
        }
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String statusName(Integer status) {
        if (status == null) {
            return "null";
        }
        switch (status) {
            case FeatureStatus.UNAVAILABLE:
                return "UNAVAILABLE";
            case FeatureStatus.DOWNLOADABLE:
                return "DOWNLOADABLE";
            case FeatureStatus.DOWNLOADING:
                return "DOWNLOADING";
            case FeatureStatus.AVAILABLE:
                return "AVAILABLE";
            default:
                return "UNKNOWN_" + status;
        }
    }

    private void cancelPending() {
        synchronized (pending) {
            for (Future<?> future : new ArrayList<>(pending)) {
                future.cancel(true);
            }
            pending.clear();
        }
    }

    private void setProbeButtonsEnabled(boolean enabled) {
        if (promptButton != null) {
            promptButton.setEnabled(enabled);
            summaryButton.setEnabled(enabled);
            imageButton.setEnabled(enabled);
            speechButton.setEnabled(enabled);
        }
    }

    private void closeAllClients() {
        closePrompt();
        closeSummary();
        closeImage();
        closeSpeech();
    }

    private void closePrompt() {
        GenerativeModel client = promptClient;
        promptClient = null;
        closeQuietly(client);
    }

    private void closeSummary() {
        Summarizer client = summarizer;
        summarizer = null;
        closeQuietly(client);
    }

    private void closeImage() {
        ImageDescriber client = imageDescriber;
        imageDescriber = null;
        closeQuietly(client);
    }

    private void closeSpeech() {
        SpeechRecognizer client = speechRecognizer;
        speechRecognizer = null;
        closeQuietly(client);
    }

    private static void closeQuietly(AutoCloseable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (Throwable ignored) {
            Log.w(TAG, "Client close failed", ignored);
        }
    }

    private static void closeQuietly(GenerativeModel client) {
        if (client == null) {
            return;
        }
        try {
            client.close();
        } catch (Throwable ignored) {
            Log.w(TAG, "Prompt client close failed", ignored);
        }
    }

    private static void closeQuietly(Summarizer client) {
        if (client == null) {
            return;
        }
        try {
            client.close();
        } catch (Throwable ignored) {
            Log.w(TAG, "Summarizer close failed", ignored);
        }
    }

    private static void closeQuietly(ImageDescriber client) {
        if (client == null) {
            return;
        }
        try {
            client.close();
        } catch (Throwable ignored) {
            Log.w(TAG, "Image describer close failed", ignored);
        }
    }
}
