package org.ostadix.aicore.extension;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.PowerManager;
import android.provider.Settings;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;

final class ExtensionGate {
    static final String ASOSS_PACKAGE = "com.google.android.as.oss";
    static final String ASOSS_PROCESS = "com.google.android.as.oss";
    static final String MODULE_PACKAGE = "org.ostadix.aicore.extension";

    private static final String AICORE_PACKAGE = "com.google.android.aicore";
    private static final String EXPECTED_FRAMEWORK = "Vector";
    private static final String EXPECTED_FINGERPRINT =
            "google/blazer/blazer:17/CP2A.260805.005/15828068:user/release-keys";
    private static final long EXPECTED_AICORE_CODE = 494417L;
    private static final String EXPECTED_AICORE_NAME =
            "0.release.prod_aicore_20260723.00_RC11.964081323";
    private static final String EXPECTED_AICORE_APK =
            "67aa6c6cc457163d18b8cff35706eeffd60ac234fa10bf4f3b4b7bd8e1d45f57";
    private static final String EXPECTED_AICORE_SIGNER =
            "b7971ccc10a03932e14a3557a1b4c2a84be0ecb506777f0c72dd46cf5d7093c6";
    private static final long EXPECTED_ASOSS_CODE = 143685L;
    private static final String EXPECTED_ASOSS_NAME = "1.0.release.962568596";
    private static final String EXPECTED_ASOSS_APK =
            "c08952bafbd19a4bcb4399aaebc17ae7b1685c8b20cad033a41b435fbfe3620c";
    private static final String EXPECTED_ASOSS_SIGNER =
            "071f09456bf1a8e8ad2e808ffe6a0ebc13582a7e6f9aba13e47280ad9a85d833";
    private static final String ACTIVATION_SETTING = "ostadix_aicore_extension_token";
    private static final String ACTIVATION_TOKEN = EXPECTED_FINGERPRINT
            + ":asoss-llm-result-v1:" + EXPECTED_ASOSS_APK;

    private ExtensionGate() {}

    static boolean matchesEarlyProcess(String processName, String framework, int apiVersion) {
        return Build.VERSION.SDK_INT == 37
                && EXPECTED_FINGERPRINT.equals(Build.FINGERPRINT)
                && ASOSS_PROCESS.equals(processName)
                && EXPECTED_FRAMEWORK.equals(framework)
                && apiVersion == 102;
    }

    static boolean acceptsInstalledPackages(Context context) {
        return context != null
                && ASOSS_PACKAGE.equals(context.getPackageName())
                && packageMatches(context, ASOSS_PACKAGE, EXPECTED_ASOSS_CODE,
                        EXPECTED_ASOSS_NAME, EXPECTED_ASOSS_APK, EXPECTED_ASOSS_SIGNER)
                && packageMatches(context, AICORE_PACKAGE, EXPECTED_AICORE_CODE,
                        EXPECTED_AICORE_NAME, EXPECTED_AICORE_APK, EXPECTED_AICORE_SIGNER);
    }

    static boolean isExplicitlyEnabled(Context context) {
        try {
            return ACTIVATION_TOKEN.equals(Settings.Global.getString(
                    context.getContentResolver(), ACTIVATION_SETTING));
        } catch (Throwable error) {
            rethrowIfVmFatal(error);
            return false;
        }
    }

    static boolean thermalPolicyAllows(Context context) {
        try {
            PowerManager power = context.getSystemService(PowerManager.class);
            return power != null
                    && power.getCurrentThermalStatus() < PowerManager.THERMAL_STATUS_SEVERE;
        } catch (Throwable error) {
            rethrowIfVmFatal(error);
            return false;
        }
    }

    static Context currentApplication() {
        try {
            Class<?> activityThread = Class.forName("android.app.ActivityThread");
            return (Context) activityThread.getDeclaredMethod("currentApplication").invoke(null);
        } catch (Throwable error) {
            rethrowIfVmFatal(error);
            return null;
        }
    }

    static void rethrowIfVmFatal(Throwable error) {
        if (error instanceof VirtualMachineError) {
            throw (VirtualMachineError) error;
        }
    }

    private static boolean packageMatches(Context context, String packageName, long code,
            String name, String apkSha256, String signerSha256) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    packageName, PackageManager.GET_SIGNING_CERTIFICATES);
            if (info.getLongVersionCode() != code || !name.equals(info.versionName)
                    || info.signingInfo == null) {
                return false;
            }
            Signature[] signers = info.signingInfo.getApkContentsSigners();
            if (signers == null || signers.length != 1
                    || !signerSha256.equals(sha256(signers[0].toByteArray()))) {
                return false;
            }
            ApplicationInfo application = info.applicationInfo;
            return application != null && application.sourceDir != null
                    && apkSha256.equals(sha256(new File(application.sourceDir)));
        } catch (Throwable error) {
            rethrowIfVmFatal(error);
            return false;
        }
    }

    private static String sha256(File file) {
        try (InputStream input = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                digest.update(buffer, 0, count);
            }
            return hex(digest.digest());
        } catch (Throwable error) {
            rethrowIfVmFatal(error);
            return "";
        }
    }

    private static String sha256(byte[] value) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (Throwable error) {
            rethrowIfVmFatal(error);
            return "";
        }
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        }
        return result.toString();
    }
}
