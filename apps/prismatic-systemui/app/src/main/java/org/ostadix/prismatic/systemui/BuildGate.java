package org.ostadix.prismatic.systemui;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.provider.Settings;

import java.security.MessageDigest;

final class BuildGate {
    static final String SYSTEM_UI_PACKAGE = "com.android.systemui";
    static final String SYSTEM_UI_PROCESS = "com.android.systemui";
    static final String CONSENT_SETTING = "ostadix_prismatic_glass_build_token";
    static final String STAGE_TWO_CONSENT_SETTING =
            "ostadix_prismatic_glass_global_actions_token";

    private static final String EXPECTED_BUILD_FINGERPRINT =
            "google/blazer/blazer:17/CP2A.260805.005/15828068:user/release-keys";
    static final String EXPECTED_BUILD_TOKEN = EXPECTED_BUILD_FINGERPRINT;
    static final String EXPECTED_STAGE_TWO_TOKEN =
            EXPECTED_BUILD_FINGERPRINT + ":global-actions-v1";
    private static final long EXPECTED_SYSTEM_UI_VERSION = 37L;
    private static final String EXPECTED_SYSTEM_UI_CERT_SHA256 =
            "86170a4850632ee9e435372bb6139441a1bd207f54e973a00f0ac2cb961c0ca1";

    private static volatile boolean verifiedSystemUiIdentity;

    private BuildGate() {}

    static boolean matchesFirmware() {
        return Build.VERSION.SDK_INT == 37
                && EXPECTED_BUILD_FINGERPRINT.equals(Build.FINGERPRINT);
    }

    static boolean isExplicitlyEnabled(Context context) {
        return settingMatches(context, CONSENT_SETTING, EXPECTED_BUILD_TOKEN);
    }

    static boolean isStageTwoExplicitlyEnabled(Context context) {
        return settingMatches(
                context, STAGE_TWO_CONSENT_SETTING, EXPECTED_STAGE_TWO_TOKEN);
    }

    private static boolean settingMatches(
            Context context, String settingName, String expectedValue) {
        if (context == null) {
            return false;
        }
        try {
            String token = Settings.Global.getString(
                    context.getContentResolver(), settingName);
            return expectedValue.equals(token);
        } catch (Throwable error) {
            rethrowIfVmFatal(error);
            return false;
        }
    }

    static boolean matchesSystemUi(Context context) {
        if (context == null
                || !SYSTEM_UI_PACKAGE.equals(context.getPackageName())
                || !matchesFirmware()) {
            return false;
        }
        if (verifiedSystemUiIdentity) {
            return true;
        }

        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    SYSTEM_UI_PACKAGE, PackageManager.GET_SIGNING_CERTIFICATES);
            if (info.getLongVersionCode() != EXPECTED_SYSTEM_UI_VERSION
                    || info.signingInfo == null) {
                return false;
            }

            Signature[] signers = info.signingInfo.getApkContentsSigners();
            if (signers == null || signers.length != 1
                    || !EXPECTED_SYSTEM_UI_CERT_SHA256.equals(sha256(signers[0].toByteArray()))) {
                return false;
            }

            if (!SystemUiGlass.resourceTableMatches(context)) {
                return false;
            }

            verifiedSystemUiIdentity = true;
            return true;
        } catch (Throwable error) {
            rethrowIfVmFatal(error);
            return false;
        }
    }

    static void rethrowIfVmFatal(Throwable error) {
        if (error instanceof VirtualMachineError) {
            throw (VirtualMachineError) error;
        }
    }

    private static String sha256(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte item : digest) {
                result.append(String.format(java.util.Locale.ROOT, "%02x", item & 0xff));
            }
            return result.toString();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            return "";
        }
    }
}

