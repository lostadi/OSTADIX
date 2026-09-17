#!/data/data/com.termux/files/usr/bin/bash
# Read-only seam verification for the exact installed AS.OSS/AICore snapshot.
set -euo pipefail

APP_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$APP_ROOT/../.." && pwd)
AUDIT_ROOT="$REPO_ROOT/audits/pixel-ai-20260915"
JADX_ROOT=${ASOSS_JADX_ROOT:-/data/local/tmp/ostadix-ai-audit-20260915/asoss-jadx/sources}

"$AUDIT_ROOT/check-extension-compatibility.sh"

require_line() {
    local file=$1 text=$2
    [[ -f "$file" ]] || { echo "contract=false missing=$file"; exit 4; }
    grep -Fq "$text" "$file" || {
        echo "contract=false file=$file missing_shape=$text"
        exit 4
    }
}

FMZ="$JADX_ROOT/defpackage/fmz.java"
FLS="$JADX_ROOT/defpackage/fls.java"
FLO="$JADX_ROOT/defpackage/flo.java"
RESULT="$JADX_ROOT/com/google/android/apps/aicore/aidl/LLMResult.java"
REPLY="$JADX_ROOT/com/google/android/apps/aicore/aidl/LLMReply.java"

require_line "$FMZ" 'public final class fmz extends ILLMResultCallback.Stub'
require_line "$FMZ" 'public final void onLLMInferenceSuccess(LLMResult lLMResult)'
require_line "$FMZ" 'this.a.b(lLMResult);'
require_line "$FLS" 'public final flp a(LLMRequest lLMRequest, flr flrVar)'
require_line "$FLS" 'new flo((ICancellationCallback)'
require_line "$FLO" 'public final void a()'
require_line "$FLO" 'iCancellationCallback.cancel();'
require_line "$RESULT" 'public LLMResult(List list, InferenceEventTraceResult inferenceEventTraceResult, LegionResultMetadata legionResultMetadata, List list2)'
require_line "$RESULT" 'public jya getResults()'
require_line "$RESULT" 'public jya getThoughtProcess()'
require_line "$REPLY" 'public float getScore()'
require_line "$REPLY" 'public int getStopReason()'
require_line "$REPLY" 'public Bundle getPolicyScoresBundle()'

echo 'contract=true seam=fmz.onLLMInferenceSuccess replacement=LLMResult caller_capture=fls.a cancellation=flo.a'
