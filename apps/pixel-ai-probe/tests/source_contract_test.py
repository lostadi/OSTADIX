#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "app/src/main/java/org/ostadix/pixelai/probe/MainActivity.java").read_text()
MANIFEST = (ROOT / "app/src/main/AndroidManifest.xml").read_text()
DEPENDENCIES = (ROOT / "build.gradle").read_text()
BUILD_SCRIPT = (ROOT / "build.sh").read_text()


def require(text: str, needle: str) -> None:
    assert needle in text, f"missing required contract: {needle}"


for coordinate in (
    "com.google.mlkit:genai-prompt:1.0.0-beta4",
    "com.google.mlkit:genai-summarization:1.0.0-beta1",
    "com.google.mlkit:genai-image-description:1.0.0-beta1",
    "com.google.mlkit:genai-speech-recognition:1.0.0-alpha1",
):
    require(DEPENDENCIES, coordinate)

require(BUILD_SCRIPT, "VERSION_CODE=2")
require(BUILD_SCRIPT, "VERSION_NAME=0.1.1")
require(SOURCE, 'PROBE_VERSION = "0.1.1"')

for required_source in (
    "SYNTHETIC_BUILD_LOG",
    "SYNTHETIC_ARTICLE",
    "Bitmap.createBitmap",
    "FeatureStatus.AVAILABLE",
    "getBaseModelName()",
    "getTokenLimit()",
    "countTokens(request)",
    "MODE_ADVANCED",
    "getRetryDelay()",
    "getErrorCode()",
    "cancelPending();",
    "closeAllClients();",
    "onWindowFocusChanged(boolean hasFocus)",
    "hasWindowFocus()",
    "keyguard.isDeviceLocked()",
    "if (!isProbeForeground())",
    "&& isProbeForeground()",
):
    require(SOURCE, required_source)

for action in (
    "RUN_PROMPT",
    "RUN_SUMMARY",
    "RUN_IMAGE",
    "RUN_SPEECH_STATUS",
):
    require(SOURCE, action)
    require(MANIFEST, action)

assert "android.permission.RECORD_AUDIO" not in MANIFEST
assert "READ_MEDIA" not in MANIFEST
assert "READ_EXTERNAL_STORAGE" not in MANIFEST
assert "startService(" not in SOURCE
assert "startForegroundService(" not in SOURCE
assert ".download(" not in SOURCE
assert "clearApplicationUserData" not in SOURCE
assert "ContentResolver" not in SOURCE

# onResume/onPostResume alone do not prove top-window visibility. Automation must stay queued until
# the same resumed + focused + unlocked gate used by the buttons is satisfied.
post_resume = re.search(
    r"protected void onPostResume\(\)\s*\{(.*?)\n\s*\}", SOURCE, flags=re.DOTALL
)
assert post_resume, "could not locate onPostResume"
assert "dispatchQueuedAutomation" not in post_resume.group(1)
dispatch_start = SOURCE.index("private void dispatchQueuedAutomation()")
dispatch_end = SOURCE.index("private void refreshProbeAvailability", dispatch_start)
dispatch = SOURCE[dispatch_start:dispatch_end]
gate_at = dispatch.find("if (!isProbeForeground())")
clear_at = dispatch.find("queuedAutomationAction = null;", gate_at)
assert gate_at >= 0 and clear_at > gate_at, "automation action is cleared before foreground gate"

# The hand-written manifest carries the declarations needed by the four direct API routes.
for required_manifest in (
    "com.google.mlkit.common.internal.MlKitInitProvider",
    "com.google.mlkit.common.internal.MlKitComponentDiscoveryService",
    "com.google.mlkit.common.internal.CommonComponentRegistrar",
    "com.google.android.apps.aicore.service.BIND_SERVICE",
    '<package android:name="com.google.android.aicore"',
    '<package android:name="com.google.android.tts"',
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.INTERNET",
    "com.google.android.gms.version",
    "androidx.core.app.CoreComponentFactory",
):
    require(MANIFEST, required_manifest)

# The only declared service is ML Kit's non-exported component-discovery hook. DataTransport's
# optional telemetry backend/scheduler components are intentionally not installed by this probe.
assert MANIFEST.count("<service") == 1
for omitted_telemetry_component in (
    "com.google.android.datatransport.runtime.backends.TransportBackendDiscovery",
    "com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService",
    "com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver",
):
    assert omitted_telemetry_component not in MANIFEST

article_block = re.search(
    r"SYNTHETIC_ARTICLE\s*=\s*(.*?);\n\n", SOURCE, flags=re.DOTALL
)
assert article_block, "could not locate the synthetic article"
article_parts = re.findall(r'"((?:[^"\\]|\\.)*)"', article_block.group(1))
article = "".join(bytes(part, "utf-8").decode("unicode_escape") for part in article_parts)
assert len(article) > 400, f"synthetic summary input is only {len(article)} characters"

print(f"source contract OK; synthetic summary chars={len(article)}")
