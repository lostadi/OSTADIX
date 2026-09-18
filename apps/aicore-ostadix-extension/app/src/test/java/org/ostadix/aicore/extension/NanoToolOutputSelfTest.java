package org.ostadix.aicore.extension;

import org.json.JSONObject;

/** Runs on the JVM with a real org.json implementation, not the Android SDK stubs. */
public final class NanoToolOutputSelfTest {
    public static void main(String[] args) throws Exception {
        JSONObject number = new JSONObject("{\"value\":{\"t\":\"number\",\"v\":{\"kind\":\"int\",\"v\":\"276\"}},"
                + "\"execution_evidence\":{\"result_content_identity\":\"synthetic-result-id\"}}");
        String actual = NanoToolOutput.completed(number);
        require(actual.startsWith("Ostadix output:\n276\n") && actual.contains("synthetic-result-id"),
                "actual number or identity missing");
        StringBuilder longText = new StringBuilder();
        for (int i = 0; i < 4096; i++) { longText.append('x'); }
        number.put("value", new JSONObject().put("t", "string").put("v", longText.toString()));
        require(NanoToolOutput.completed(number).contains(longText), "actual output truncated");
        number.put("value", new JSONObject().put("t", "text").put("v",
                new JSONObject().put("encoding", "utf-8").put("utf8", "actual UTF-8 text")));
        require(NanoToolOutput.completed(number).startsWith("Ostadix output:\nactual UTF-8 text\n"), "text value not decoded");
        JSONObject failed = new JSONObject().put("result", new JSONObject().put("error", "backend failed"))
                .put("stdout", new JSONObject().put("text", "partial output").put("complete", true))
                .put("stderr", new JSONObject().put("text", "compiler error").put("complete", true));
        String failure = NanoToolOutput.failed(failed);
        require(failure.contains("partial output") && failure.contains("compiler error")
                && failure.contains("not retried") && !failure.contains("Nothing was executed"),
                "execution failure hid output or implied rollback");
        String report = "Actual tool output: number, identity, long text and failure streams passed\n";
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(args[0])) {
            out.write(report.getBytes(java.nio.charset.StandardCharsets.UTF_8)); out.getFD().sync();
        }
    }
    private static void require(boolean condition, String message) {
        if (!condition) { throw new AssertionError(message); }
    }
}
