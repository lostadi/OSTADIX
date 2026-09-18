package org.ostadix.aicore.extension;

import com.google.android.apps.aicore.aidl.InferenceEventTraceResult;
import com.google.android.apps.aicore.aidl.SmartReplyReplyEntry;
import com.google.android.apps.aicore.aidl.SmartReplyResult;

import java.util.Arrays;

public final class ResultReplacementSelfTest {
    private ResultReplacementSelfTest() {}

    public static void main(String[] arguments) throws Exception {
        Object first = new Object();
        Object selected = new Object();
        InferenceEventTraceResult trace = new InferenceEventTraceResult();
        SmartReplyResult original = new SmartReplyResult(
                Arrays.asList(first, selected), trace);
        SmartReplyResult replacement = (SmartReplyResult)
                OstadixResultBridge.rebuildSelectedSmartReplyResult(
                original, original.getResults(), 1);

        if (replacement == original || replacement.getResults().size() != 1
                || replacement.getResults().get(0) != selected
                || replacement.getInferenceEventTraceResult() != trace) {
            throw new AssertionError(
                    "SmartReplyResult replacement did not preserve its trace metadata");
        }
        try {
            OstadixResultBridge.rebuildSelectedSmartReplyResult(
                    original, original.getResults(), 2);
            throw new AssertionError("out-of-range selection did not fail closed");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }

        OstadixResultBridge.ReplyProjection projection =
                OstadixResultBridge.projectSmartReplies(Arrays.asList(
                        new SmartReplyReplyEntry("safe", 0, 0.6f),
                        new SmartReplyReplyEntry("", 0, 0.95f),
                        new SmartReplyReplyEntry("unsafe", 2, 0.99f)));
        if (projection.scores[0] != 600 || projection.scores[1] != 950
                || projection.scores[2] != 990
                || projection.hasText[0] != 1 || projection.hasText[1] != 0
                || projection.safetyClassifications[0] != 0
                || projection.safetyClassifications[2] != 2) {
            throw new AssertionError("Smart Reply scalar projection is incorrect");
        }

        RequestCorrelations correlations = new RequestCorrelations();
        Object callback = new Object();
        Object cancellation = new Object();
        RequestCorrelations.State state = correlations.begin(
                callback, new RequestIdentity(1000, 1));
        correlations.registerCancellation(cancellation, state);
        if (correlations.claimCallback(callback) != state
                || correlations.cancel(cancellation) != state
                || !correlations.isCancelled(state)
                || correlations.commitReplacement(state)
                || correlations.callbackCountForTest() != 0
                || correlations.cancellationCountForTest() != 0) {
            throw new AssertionError("cancellation was not latched before replacement delivery");
        }

        Object completedCallback = new Object();
        Object terminalCancellation = new Object();
        Object lateCancellation = new Object();
        RequestCorrelations.State completed = correlations.begin(
                completedCallback, new RequestIdentity(1000, 2));
        correlations.registerCancellation(terminalCancellation, completed);
        if (correlations.claimCallback(completedCallback) != completed
                || !correlations.commitReplacement(completed)
                || correlations.cancellationCountForTest() != 0) {
            throw new AssertionError("valid replacement delivery could not be committed");
        }
        correlations.registerCancellation(lateCancellation, completed);
        if (correlations.cancel(lateCancellation) != null
                || correlations.callbackCountForTest() != 0
                || correlations.cancellationCountForTest() != 0) {
            throw new AssertionError("terminal correlation accepted a late cancellation handle");
        }
        System.out.println("SmartReplyResult replacement self-test passed");
    }
}
