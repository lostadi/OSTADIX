package org.ostadix.aicore.extension;

import com.google.android.apps.aicore.aidl.InferenceEventTraceResult;
import com.google.android.apps.aicore.aidl.LLMResult;
import com.google.android.apps.aicore.aidl.LegionResultMetadata;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class ResultReplacementSelfTest {
    private ResultReplacementSelfTest() {}

    public static void main(String[] arguments) throws Exception {
        Object first = new Object();
        Object selected = new Object();
        InferenceEventTraceResult trace = new InferenceEventTraceResult();
        LegionResultMetadata legion = new LegionResultMetadata();
        List<String> thought = Collections.singletonList("private-thought-placeholder");
        LLMResult original = new LLMResult(
                Arrays.asList(first, selected), trace, legion, thought);
        LLMResult replacement = (LLMResult) OstadixResultBridge.rebuildSelectedResult(
                original, original.getResults(), 1);

        if (replacement == original || replacement.getResults().size() != 1
                || replacement.getResults().get(0) != selected
                || replacement.getInferenceEventTraceResult() != trace
                || replacement.getLegionResultMetadata() != legion
                || replacement.getThoughtProcess() != thought) {
            throw new AssertionError("LLMResult replacement did not preserve its owned metadata");
        }
        try {
            OstadixResultBridge.rebuildSelectedResult(original, original.getResults(), 2);
            throw new AssertionError("out-of-range selection did not fail closed");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
        System.out.println("LLMResult replacement self-test passed");
    }
}
