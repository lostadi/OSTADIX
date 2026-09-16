#!/usr/bin/env python3
"""Static negative tests for the connector's intentionally narrow Android surface."""

from pathlib import Path
import sys
import xml.etree.ElementTree as ET


APP_ROOT = Path(__file__).resolve().parents[1]
MAIN_ROOT = APP_ROOT / "app" / "src" / "main"
MANIFEST = MAIN_ROOT / "AndroidManifest.xml"
ANDROID = "{http://schemas.android.com/apk/res/android}"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    root = ET.parse(MANIFEST).getroot()

    permissions = [node.get(ANDROID + "name") for node in root.findall("uses-permission")]
    require(
        permissions == ["android.permission.BLUETOOTH_CONNECT"],
        f"manifest permissions must be exactly BLUETOOTH_CONNECT, got {permissions}",
    )

    expected_features = {
        "android.hardware.bluetooth",
        "android.hardware.bluetooth_le",
        "android.software.companion_device_setup",
        "android.hardware.touchscreen",
    }
    features = root.findall("uses-feature")
    require({node.get(ANDROID + "name") for node in features} == expected_features,
            "optional feature declarations changed")
    require(all(node.get(ANDROID + "required") == "false" for node in features),
            "every hardware/software feature must remain optional")

    application = root.find("application")
    require(application is not None, "application element missing")
    require(application.get(ANDROID + "allowBackup") == "false", "backup must be disabled")
    require(application.get(ANDROID + "usesCleartextTraffic") == "false",
            "cleartext traffic must be disabled")
    require(not root.findall(".//service"), "background services are forbidden")
    require(not root.findall(".//receiver"), "manifest receivers are forbidden")
    require(not root.findall(".//provider"), "content providers are forbidden")

    activities = root.findall(".//activity")
    require(len(activities) == 1, "exactly one Activity is expected")
    require(activities[0].get(ANDROID + "exported") == "true",
            "the launcher Activity must be exported")

    inspected = [MANIFEST]
    inspected.extend(sorted((MAIN_ROOT / "java").rglob("*.java")))
    inspected.extend(sorted((MAIN_ROOT / "res").rglob("*.xml")))
    source = "\n".join(path.read_text(encoding="utf-8") for path in inspected)

    forbidden = [
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BLUETOOTH_ADMIN",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "getDeclaredMethod(",
        "setAccessible(",
        "createBond(",
        "setPin(",
        "setPairingConfirmation(",
        "startDiscovery(",
        "connectGatt(",
        "SystemProperties",
        "Runtime.getRuntime",
        "startForegroundService(",
        "setprop",
        "su -c",
        "RenderEffect",
        "FLAG_BLUR_BEHIND",
        "setBackgroundBlurRadius",
        "ValueAnimator",
        "ObjectAnimator",
        "<animated-",
    ]
    present = [token for token in forbidden if token in source]
    require(not present, f"forbidden API/permission/behavior tokens found: {present}")

    activity = (MAIN_ROOT / "java" / "org" / "ostadix" / "accessory" /
                "MainActivity.java").read_text(encoding="utf-8")
    adapter = (MAIN_ROOT / "java" / "org" / "ostadix" / "accessory" /
               "Api37ProfileConnector.java").read_text(encoding="utf-8")
    resolver = (MAIN_ROOT / "java" / "org" / "ostadix" / "accessory" /
                "PublicIntNoArgMethod.java").read_text(encoding="utf-8")

    require("companionManager.associate(" in activity, "CDM association is missing")
    require("startIntentSenderForResult(" in activity, "CDM system chooser is missing")
    require("getMyAssociations()" in activity,
            "connect tap must revalidate the current CDM association")
    require("Manifest.permission.BLUETOOTH_PRIVILEGED" in activity,
            "exported Bluetooth receiver must authenticate its sender")
    require("connectSelectedAccessory();" in activity,
            "explicit Connect button handler is missing")
    require(activity.count("connectSelectedAccessory();") == 1,
            "connection must only start from the explicit button handler")
    require("Settings.ACTION_BLUETOOTH_SETTINGS" in activity,
            "pre-API-37/pairing settings fallback is missing")
    require("setMinHeight(dp(52))" in activity, "buttons must remain at least 48dp high")
    require("ACCESSIBILITY_LIVE_REGION_POLITE" in activity,
            "connection status must remain screen-reader accessible")
    require("setStateListAnimator(null)" in activity,
            "buttons must avoid motion-dependent state animation")
    require("getMethod(name)" in resolver, "public reflection resolver is missing")
    require("\"connect\"" in adapter, "API 37 public connect method name is missing")

    print(f"safety_contract_test: checked {len(inspected)} source/resource files")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"safety_contract_test: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
