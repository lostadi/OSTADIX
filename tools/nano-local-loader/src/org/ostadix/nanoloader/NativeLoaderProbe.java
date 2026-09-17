package org.ostadix.nanoloader;

import android.os.Process;
import com.google.android.apps.aicore.base.InferenceException;
import com.google.android.apps.aicore.runtime.impl.edgetpu.RuntimeEdgetpu;
import com.google.android.apps.aicore.runtime.wrapper.RuntimeModelLoaderWrapper;
import java.io.File;
import org.json.JSONObject;

/** Create and free a runtime object. No model loading, generation, or networking. */
public final class NativeLoaderProbe {
    private static void event(String phase, String detail, boolean success) throws Exception {
        JSONObject result = new JSONObject();
        result.put("schema", "ostadix.nano-loader-probe/v1");
        result.put("phase", phase);
        result.put("detail", detail);
        result.put("success", success);
        result.put("uid", Process.myUid());
        result.put("pid", Process.myPid());
        result.put("model_loaded", false);
        result.put("inference_executed", false);
        System.out.println(result.toString());
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1 || !new File(args[0]).isAbsolute()) {
            throw new IllegalArgumentException("one absolute directory of extracted native libraries required");
        }
        String phase = "native_library_load";
        long handle = 0;
        try {
            // libgoogle3 is the DT_NEEDED implementation library, not a Java
            // entrypoint. Loading its generic JNI_OnLoad directly returns JNI_ERR.
            String[] libraries = {"libruntime_edgetpu_jni.so", "libruntime_model_loader_wrapper_jni.so"};
            for (String library : libraries) {
                System.load(new File(args[0], library).getCanonicalPath());
                event(phase, library, true);
            }
            phase = "runtime_create";
            handle = RuntimeEdgetpu.create();
            if (handle == 0) throw new IllegalStateException("nativeCreate returned zero");
            event(phase, "nonzero native runtime handle", true);
            phase = "runtime_free";
            new RuntimeModelLoaderWrapper().free(handle);
            handle = 0;
            event(phase, "nativeFree returned", true);
        } catch (Throwable failure) {
            String detail = failure.getClass().getName() + ": " + failure.getMessage();
            if (failure instanceof InferenceException) {
                detail += " (statusCode=" + ((InferenceException) failure).statusCode + ")";
            }
            event(phase, detail, false);
            failure.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
