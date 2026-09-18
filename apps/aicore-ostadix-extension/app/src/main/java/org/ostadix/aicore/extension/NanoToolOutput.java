package org.ostadix.aicore.extension;

import org.json.JSONObject;

/** Formats actual tool output independently of any model interpretation. */
final class NanoToolOutput {
    static String completed(JSONObject result) throws Exception {
        return "Ostadix output:\n" + value(result.get("value")) + "\n\nExecuted locally with Ostadix. "
                + "Result identity: " + result.getJSONObject("execution_evidence").getString("result_content_identity");
    }

    private static String value(Object item) throws Exception {
        if (!(item instanceof JSONObject)) { return String.valueOf(item); }
        JSONObject tagged = (JSONObject) item;
        String type = tagged.optString("t"); Object v = tagged.opt("v");
        if ("number".equals(type) && v instanceof JSONObject) {
            JSONObject n = (JSONObject) v;
            if ("int".equals(n.optString("kind")) || "float".equals(n.optString("kind"))) {
                return n.get("v").toString();
            }
        }
        if ("text".equals(type) && v instanceof JSONObject && ((JSONObject) v).has("utf8")) {
            return ((JSONObject) v).getString("utf8");
        }
        if ("string".equals(type) || "text".equals(type) || "bool".equals(type)) {
            return String.valueOf(v);
        }
        // Keep all values and their types for collections or less common O types.
        return tagged.toString(2);
    }

    static String failed(JSONObject result) {
        JSONObject nativeResult = result.optJSONObject("result");
        String error = nativeResult == null ? result.optString("error", "No result was returned")
                : nativeResult.optString("error", result.optString("error", "Execution failed"));
        StringBuilder text = new StringBuilder("Ostadix execution failed: ").append(error);
        for (String name : new String[]{"stdout", "stderr"}) {
            JSONObject stream = result.optJSONObject(name);
            if (stream != null && !stream.optString("text").isEmpty()) {
                text.append("\n\n").append(name).append(":\n").append(stream.optString("text"));
                if (!stream.optBoolean("complete")) { text.append("\n[Output excerpt; full output retained by Ostadix.]"); }
            }
        }
        text.append("\nExecution was not retried; completed effects were not rolled back.");
        return text.toString();
    }

    private NanoToolOutput() {}
}
