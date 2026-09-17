package org.ostadix.nanoloader;

import android.os.Process;
import android.os.SystemClock;
import android.util.Base64;
import com.google.android.apps.aicore.runtime.wrapper.LargeLanguageModelWrapper;
import com.google.android.apps.aicore.runtime.wrapper.StatefulSessionWrapper;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import org.json.JSONArray;
import org.json.JSONObject;

/** Explicit, bounded generation entrypoint. Loading a model alone cannot enable it. */
public final class SyntheticGenerationProbe {
    private static volatile boolean dispatched;
    private static volatile boolean returned;

    static boolean wasDispatched() { return dispatched; }
    static boolean wasReturned() { return returned; }

    public static void main(String[] args) throws Exception {
        LocalModelProbe.execute(args, true);
    }

    private static void event(String phase, Object detail) throws Exception {
        JSONObject output = new JSONObject();
        output.put("schema", "ostadix.nano-synthetic-generation/v1");
        output.put("phase", phase);
        output.put("detail", detail);
        output.put("uid", Process.myUid());
        output.put("pid", Process.myPid());
        output.put("inference_dispatched", dispatched);
        output.put("inference_returned", returned);
        System.out.println(output.toString());
    }

    static void run(long model, JSONObject input) throws Exception {
        String prompt = input.getString("prompt");
        int maxTokens = input.optInt("maxOutputTokens", 32);
        long timeout = input.optLong("timeoutMs", 10000);
        long seed = input.optLong("seed", 123);
        double temperature = input.optDouble("temperature", 0.0);
        final boolean stream = input.optBoolean("stream", true);
        if (prompt.getBytes(StandardCharsets.UTF_8).length > 16384 || maxTokens < 1 || maxTokens > 512
            || timeout < 1 || timeout > 30000 || seed < 0 || !Double.isFinite(temperature)
            || temperature < 0 || temperature > 1) {
            throw new IllegalArgumentException("host limits: prompt <=16KiB, maxOutputTokens 1..512, timeoutMs 1..30000, seed >=0, temperature 0..1");
        }
        // Stock ccr -> cjj -> cfq: RNG seed is extension100.field1, not cfe.field2.
        byte[] runtimeConfig = new Wire().integer(1, seed).integer(2, 1440).integer(3, 0).integer(4, 1).finish();
        byte[] sessionConfig = new Wire().bytes(100, runtimeConfig).integer(18, 0).integer(20, 0).finish();
        byte[] request = new Wire().floating(2, (float) temperature).integer(3, maxTokens)
            .integer(5, 1).integer(6, 1).floating(14, 1.0f).raw(Wire.textInput(prompt)).finish();
        JSONObject prepared = new JSONObject();
        prepared.put("prompt", prompt);
        prepared.put("max_output_tokens", maxTokens);
        prepared.put("timeout_ms", timeout);
        prepared.put("rng_seed", seed);
        prepared.put("temperature", temperature);
        prepared.put("top_k", 1);
        prepared.put("top_p", 1.0);
        prepared.put("stream", stream);
        prepared.put("session_protobuf_base64", Base64.encodeToString(sessionConfig, Base64.NO_WRAP));
        prepared.put("request_protobuf_base64", Base64.encodeToString(request, Base64.NO_WRAP));
        event("generation_prepared", prepared);
        long session = new LargeLanguageModelWrapper().createSession(model, sessionConfig);
        if (session == 0) throw new IllegalStateException("nativeCreateSession returned zero");
        event("session_created", "nonzero native session handle");
        final long deadline = SystemClock.elapsedRealtime() + timeout;
        final int[] callbacks = {0};
        final long[] bytes = {0};
        final boolean[] cancelled = {false};
        final ArrayList<JSONObject> chunks = new ArrayList<JSONObject>();
        StatefulSessionWrapper wrapper = new StatefulSessionWrapper();
        try {
            dispatched = true;
            event("generation_dispatched", "one native call; no retry");
            byte[] response;
            if (stream) {
                response = wrapper.stream(session, request, new StatefulSessionWrapper.ControllingStreamingConsumer() {
                    @Override public int accept(String text, float progress, byte[] metadata) {
                        synchronized (chunks) {
                            callbacks[0]++;
                            bytes[0] += text == null ? 0 : text.getBytes(StandardCharsets.UTF_8).length;
                            bytes[0] += metadata == null ? 0 : metadata.length;
                            if (SystemClock.elapsedRealtime() >= deadline || callbacks[0] > 4096 || bytes[0] > 1024 * 1024) {
                                cancelled[0] = true;
                                return 2; // Stock StatefulSessionWrapper.m2839a cancellation code.
                            }
                            try {
                                JSONObject chunk = new JSONObject();
                                chunk.put("text", text);
                                chunk.put("progress", Float.isFinite(progress) ? progress : JSONObject.NULL);
                                chunk.put("metadata_base64", metadata == null ? JSONObject.NULL : Base64.encodeToString(metadata, Base64.NO_WRAP));
                                chunks.add(chunk);
                            } catch (Exception invalid) {
                                cancelled[0] = true;
                                return 2;
                            }
                            return 0;
                        }
                    }
                });
            } else {
                response = wrapper.generate(session, request, new StatefulSessionWrapper.Controller() {
                    @Override public int process(float progress) {
                        callbacks[0]++;
                        if (SystemClock.elapsedRealtime() >= deadline) { cancelled[0] = true; return 2; }
                        return 0;
                    }
                });
            }
            returned = true;
            if (response.length > 4 * 1024 * 1024) throw new IllegalStateException("native response exceeds 4MiB host bound");
            JSONObject result = new JSONObject();
            result.put("callback_count", callbacks[0]);
            result.put("cancel_requested", cancelled[0]);
            result.put("chunks", new JSONArray(chunks));
            result.put("response_protobuf_base64", Base64.encodeToString(response, Base64.NO_WRAP));
            result.put("candidates", ResponseDecoder.candidates(response));
            event("generation_returned", result);
            if (cancelled[0]) throw new IllegalStateException("host cancelled generation; returned data is partial");
        } finally {
            wrapper.unload(session);
            event("session_unloaded", "nativeUnload returned");
        }
    }
}
