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
        evidence.put("schema", "ostadix.gemini-local-tool-turn/v2").put("request_id", id)
                .put("ordinary_assistant_request", true).put("caller_uid", android.os.Process.myUid())
                .put("caller_pid", android.os.Process.myPid()).put("user_text", userText)
                .put("stock_callback_delegations", 0).put("mcp_dispatch_attempts", 0)
                .put("execution_dispatch_attempts", 0).put("source_correction_attempts", 0)
                .put("source_checks", new JSONArray());
        try {
            check();
            phase = "source_generation"; save();
            JSONObject generated = NanoActionClient.generate(context, frame(
                    "Write a complete Ostadix .O program for this request. Return only source. "
                    + "The host executes it with o_execute. Do not claim you ran it. "
                    + "You have a real local execution tool through this host. Do not tell the user to run "
                    + "commands in Codex or claim there is no device connection. For a question or writing task, "
                    + "produce a Python block that returns your answer as __oval_result__. "
                    + "For a computation, execute the actual calculation in the program. "
                    + "Use only runtimes needed for the request; the example is syntax guidance. "
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
                    + "SMALL COMPLETE EXAMPLE for a single Python calculation:\n"
                    + "python^(\n    __oval_result__ = 6 * 9\n)_python\n"
                    + "END EXAMPLE. Replace that calculation with the actual request. "
                    + "For one Python calculation return ONE python^(...)_python block. "
                    + "Additional runtimes are optional: include them only when the request requires them. "
                    + "Never duplicate a calculation across languages and add the duplicate results. "
                    + "Use a combining block only when the request requires combining distinct results. "
                    + "Implement each requested operator and bound exactly. "
                    + "A sum of squares squares each input before adding; a sum of cubes cubes each input. "
                    + "Every python^( MUST close with )_python, every rust^( with )_rust, "
                    + "and every bash^( with )_bash. A bare ) does not close a language block. "
                    + "Check the final delimiter before ending. No bare Python outside python^(...)_python.\n"
                    + "ACTUAL REQUEST:\n" + userText), cancellation);
            evidence.put("source_generation", generated);
            String initialSource = extractSource(candidate(generated));
            evidence.put("initial_source", initialSource); save();
            NanoSourcePreparation.Prepared prepared = NanoSourcePreparation.prepare(initialSource,
                    new NanoSourcePreparation.Operations() {
                        public void checkActive() { check(); }
                        public String validate(String source) throws Exception { return validateSource(source); }
                        public String correct(String source, String error) throws Exception {
                            check(); phase = "source_correction";
                            evidence.put("source_correction_attempts", 1); save();
                            JSONObject correction = NanoActionClient.generate(context, frame(
                                    "Correct this complete Ostadix .O program before execution. "
                                    + "Nothing has executed. This is the only correction attempt. "
                                    + "Return the entire corrected program as source, within 512 tokens, "
                                    + "without Markdown fences or explanation. Implement the original request exactly. "
                                    + "A sum of squares squares each input; a sum of cubes cubes each input. "
                                    + "python^(code)_python, rust^(code)_rust and bash^(code)_bash "
                                    + "are executable blocks. Every opening must have its matching language suffix; "
                                    + "a bare ) is not enough. Python returns __oval_result__. "
                                    + "Independent blocks can use let parts = autonomous(batch(...)); "
                                    + "final Python reads a,b,c = $parts. Preserve the requested runtimes and inputs. "
                                    + "Do not create compiler scripts or run commands yourself.\n"
                                    + "ORIGINAL REQUEST:\n" + userText + "\nVALIDATION ERROR:\n" + error
                                    + "\nREJECTED PROGRAM:\n" + source), cancellation);
                            evidence.put("source_correction", correction); save();
                            return extractSource(candidate(correction));
                        }
                    });
            String source = prepared.source;
            evidence.put("mcp_request", new JSONObject().put("method", "tools/call").put("params",
                    new JSONObject().put("name", "o_execute").put("arguments",
                            new JSONObject().put("source", source).put("timeout_secs", 120))))
                    .put("source_sha256", digest(source));
            check(); phase = "mcp_dispatch";
            evidence.put("mcp_dispatch_attempts", evidence.getInt("mcp_dispatch_attempts") + 1)
                    .put("execution_dispatch_attempts", 1); save();
            JSONObject result;
            try (HostMcpClient host = new HostMcpClient()) {
                result = new JSONObject(host.execute(context, source, "{}", 120000, id, cancellation));
            }
            evidence.put("mcp_result", result); phase = "mcp_returned"; save();
            if (!"completed".equals(result.optString("state")) || result.optInt("exit_code", -1) != 0
                    || !result.has("result") || !result.getJSONObject("result").optBoolean("ok")) {
                throw new IllegalStateException(NanoToolOutput.failed(result));
            }
            NanoTurnStore.publish(context, id, userText, NanoToolOutput.completed(result.getJSONObject("result"))
                    + "\n\nNano is preparing an explanation. The execution result above is already saved.", null, false);
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
            String interpretation = candidate(consumed);
            check();
            String answer = NanoToolOutput.completed(nativeResult)
                    + "\n\nNano's explanation (not independently verified):\n" + interpretation;
            if (prepared.corrected) { answer += "\n\nNano corrected the generated program before execution."; }
            evidence.put("answer", answer).put("elapsed_ms", SystemClock.elapsedRealtime() - start);
            phase = "answer_ready"; save();
            return answer;
        } catch (Exception failure) {
            String failedAt = phase;
            evidence.put("failure_phase", phase).put("error", failure.toString());
            phase = "failed"; save();
            if ("result_consumption".equals(failedAt)) {
                JSONObject executed = evidence.getJSONObject("mcp_result").getJSONObject("result");
                check();
                String answer = NanoToolOutput.completed(executed)
                        + "\n\nNano could not explain this result: " + failure.getMessage();
                evidence.put("answer", answer).put("elapsed_ms", SystemClock.elapsedRealtime() - start);
                phase = "answer_ready_without_interpretation"; save();
                return answer;
            }
            throw failure;
        }
    }

    private String validateSource(String source) throws Exception {
        check(); phase = "source_validation";
        JSONArray checks = evidence.getJSONArray("source_checks");
        JSONObject entry = new JSONObject().put("source_sha256", digest(source))
                .put("request", new JSONObject().put("method", "tools/call").put("params",
                        new JSONObject().put("name", "o_execute").put("arguments", new JSONObject()
                                .put("source", source).put("action", "check").put("timeout_secs", 15))));
        checks.put(entry);
        evidence.put("mcp_dispatch_attempts", evidence.getInt("mcp_dispatch_attempts") + 1); save();
        JSONObject result;
        try (HostMcpClient host = new HostMcpClient()) {
            result = new JSONObject(host.check(context, source, 15000, id + "-check-" + checks.length(), cancellation));
        }
        entry.put("result", result); save(); check();
        JSONObject nativeResult = result.optJSONObject("result");
        if ("check".equals(result.optString("action")) && nativeResult != null
                && "parse".equals(nativeResult.optString("stage"))) {
            if ("completed".equals(result.optString("state")) && result.optInt("exit_code", -1) == 0
                    && nativeResult.optBoolean("ok")) {
                String contractError = NanoSourcePreparation.executableContractError(source);
                if (contractError != null) { entry.put("source_contract_rejection", contractError); save(); }
                return contractError;
            }
            if ("failed".equals(result.optString("state")) && result.optInt("exit_code", 0) != 0
                    && nativeResult.has("ok") && !nativeResult.getBoolean("ok")
                    && nativeResult.has("error")) { return nativeResult.getString("error"); }
        }
        throw new IllegalStateException("Could not validate Nano's program. Nothing was executed. "
                + (nativeResult == null ? result.optString("error", "Unexpected validation response")
                        : nativeResult.optString("error", "Unexpected validation response")));
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
