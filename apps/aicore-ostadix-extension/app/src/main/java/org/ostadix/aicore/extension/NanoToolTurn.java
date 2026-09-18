package org.ostadix.aicore.extension;

import android.content.Context;
import android.os.CancellationSignal;
import android.os.SystemClock;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;
import org.ostadix.terminal.HostMcpClient;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/** One host-owned tool interaction, using the existing source-first MCP adapter. */
final class NanoToolTurn {
    private final Context context;
    private final String id;
    private final CancellationSignal cancellation;
    private final JSONObject evidence = new JSONObject();
    private String phase = "not_dispatched";

    NanoToolTurn(Context context, String id, CancellationSignal cancellation) {
        this.context = context; this.id = id; this.cancellation = cancellation;
    }

    String run(String userText) throws Exception {
        long start = SystemClock.elapsedRealtime();
        evidence.put("schema", "ostadix.gemini-local-tool-turn/v1").put("request_id", id)
                .put("ordinary_assistant_request", true).put("caller_uid", android.os.Process.myUid())
                .put("caller_pid", android.os.Process.myPid()).put("user_text", userText)
                .put("stock_callback_delegations", 0).put("mcp_dispatch_attempts", 0);
        try {
            check();
            phase = "source_generation"; save();
            JSONObject generated = NanoActionClient.generate(context, frame(
                    "Write a complete Ostadix .O program for this request. Return only source. "
                    + "The host executes it with o_execute. Do not claim you ran it. "
                    + "Do not create compiler scripts or temporary files. Keep it within 512 tokens.\n"
                    + "Language guide: python^(code)_python returns __oval_result__. "
                    + "rust^(fn main(){...})_rust returns stdout decoded as JSON when valid. "
                    + "bash^(commands)_bash returns stdout, decoded as JSON when valid, else text. "
                    + "let parts = autonomous(batch(python^(...)_python,rust^(...)_rust,bash^(...)_bash)) "
                    + "runs independent branches. A final python block can use a,b,c = $parts. "
                    + "Use real work in every requested language. Embed all supplied input data. "
                    + "Use Bash printf '%s\\n' with separate arguments, not escaped newline strings. "
                    + "Bash JSON numeric output becomes a number, not a string. "
                    + "Do not use f-strings containing O splices; assign $parts first. "
                    + "No explanations, computed answer, or tool-call JSON.\n"
                    + "COMPLETE SYNTAX EXAMPLE (different computation, replace its data and operations):\n"
                    + "let parts = autonomous(batch(\n"
                    + "python^(\n    __oval_result__ = sum([2,4])\n)_python,\n"
                    + "rust^(\nfn main(){let mut n=1; for i in 1..=3 {n*=i;} println!(\"{}\",n);}\n)_rust,\n"
                    + "bash^(\n    printf '%s\\n' apple pear apple | sort -u | wc -l\n)_bash\n))\n"
                    + "python^(\n    a,b,c = $parts\n    __oval_result__ = a+b+c\n)_python\n"
                    + "END EXAMPLE. The example's operations are unrelated to the actual request. "
                    + "Re-derive each branch from the actual request, including its operators and bounds. "
                    + "Your output must include ALL requested executable language blocks "
                    + "and the final combining block. No bare Python outside python^(...)_python.\n"
                    + "ACTUAL REQUEST:\n" + userText), cancellation);
            evidence.put("source_generation", generated);
            String source = extractSource(candidate(generated));
            evidence.put("mcp_request", new JSONObject().put("method", "tools/call").put("params",
                    new JSONObject().put("name", "o_execute").put("arguments",
                            new JSONObject().put("source", source).put("timeout_secs", 120))))
                    .put("source_sha256", digest(source));
            check(); phase = "mcp_dispatch";
            evidence.put("mcp_dispatch_attempts", 1); save();
            JSONObject result;
            try (HostMcpClient host = new HostMcpClient()) {
                result = new JSONObject(host.execute(context, source, "{}", 120000, id, cancellation));
            }
            evidence.put("mcp_result", result); phase = "mcp_returned"; save();
            if (!"completed".equals(result.optString("state")) || result.optInt("exit_code", -1) != 0
                    || !result.has("result") || !result.getJSONObject("result").optBoolean("ok")) {
                JSONObject nativeFailure = result.optJSONObject("result");
                throw new IllegalStateException("o_execute "
                        + (nativeFailure == null ? result.optString("state") : nativeFailure.optString("stage"))
                        + " failed: " + (nativeFailure == null ? result.optString("error")
                        : nativeFailure.optString("error", result.optString("error"))) + "; no retry");
            }
            check(); phase = "result_consumption"; save();
            JSONObject nativeResult = result.getJSONObject("result");
            JSONObject interpretationInput = new JSONObject().put("ok", nativeResult.getBoolean("ok"))
                    .put("type", nativeResult.getString("type")).put("value", nativeResult.get("value"));
            JSONObject consumed = NanoActionClient.generate(context, frame(
                    "Report the actual Ostadix result below in at most two short sentences. "
                    + "The value uses tagged OValue JSON (t=type,v=value). "
                    + "Do not reproduce JSON, source code, hashes, or execution evidence. "
                    + "The host adds execution evidence separately. Report what the tool actually returned. "
                    + "Do not recalculate or substitute an expected answer.\nUSER REQUEST:\n" + userText
                    + "\nACTUAL TOOL RESULT:\n" + interpretationInput.toString()), cancellation);
            evidence.put("result_consumption", consumed);
            String answer = candidate(consumed);
            check();
            String identity = nativeResult.getJSONObject("execution_evidence")
                    .getString("result_content_identity");
            answer += "\n\nExecuted locally with Ostadix. Result identity: " + identity;
            evidence.put("answer", answer).put("elapsed_ms", SystemClock.elapsedRealtime() - start);
            phase = "answer_ready"; save();
            return answer;
        } catch (Exception failure) {
            String failedAt = phase;
            evidence.put("failure_phase", phase).put("error", failure.toString());
            phase = "failed"; save();
            if ("result_consumption".equals(failedAt)) {
                JSONObject executed = evidence.getJSONObject("mcp_result").getJSONObject("result");
                String value = executed.get("value").toString();
                if (value.length() > 1024) { value = value.substring(0, 1024) + " [truncated for display]"; }
                throw new IllegalStateException("Ostadix executed successfully; actual typed result: " + value
                        + ". Local interpretation failed: " + failure.getMessage()
                        + ". Result identity: " + executed.getJSONObject("execution_evidence")
                                .getString("result_content_identity"), failure);
            }
            throw failure;
        }
    }

    private void check() {
        cancellation.throwIfCanceled();
        if (!GeminiNanoActionHooks.enabled(context)) {
            throw new IllegalStateException("local assistant activation revoked; no retry");
        }
    }

    private void save() throws Exception {
        evidence.put("phase", phase);
        try (FileOutputStream out = context.openFileOutput(id + ".json", Context.MODE_PRIVATE)) {
            out.write((evidence.toString() + "\n").getBytes(StandardCharsets.UTF_8)); out.getFD().sync();
        }
        Log.i("OstadixGeminiNano", "event=turn_phase request_id=" + id + " phase=" + phase);
    }

    private static String frame(String text) { return "\n<ctrl99>user\n" + text + "<ctrl100>\n<ctrl99>model\n"; }
    private static String candidate(JSONObject result) throws Exception {
        if (!result.optBoolean("ok")) { throw new IllegalStateException("local Nano: " + result.opt("error")); }
        JSONArray candidates = result.getJSONObject("result").getJSONArray("candidates");
        if (candidates.length() != 1) { throw new IllegalStateException("local Nano requires one finished candidate"); }
        JSONObject first = candidates.getJSONObject(0);
        if (first.optBoolean("text_truncated_in_event") || first.optInt("finish_reason_enum") != 1) {
            throw new IllegalStateException("local Nano candidate unfinished or truncated; no retry");
        }
        String text = first.getString("text");
        if (text.trim().isEmpty()) { throw new IllegalStateException("local Nano candidate empty"); }
        return text;
    }
    private static String extractSource(String text) {
        String s = text.trim();
        if (s.startsWith("```")) {
            int newline = s.indexOf('\n');
            if (newline < 0 || !s.endsWith("```")) { throw new IllegalArgumentException("incomplete source fence"); }
            s = s.substring(newline + 1, s.length() - 3);
        }
        if (s.contains("```")) { throw new IllegalArgumentException("multiple source fences; not dispatched"); }
        return s;
    }
    static String digest(String text) throws Exception {
        StringBuilder out = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))) {
            out.append(String.format(Locale.ROOT, "%02x", b & 255));
        }
        return out.toString();
    }
}
