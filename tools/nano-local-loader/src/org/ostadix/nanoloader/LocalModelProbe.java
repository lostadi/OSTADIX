package org.ostadix.nanoloader;

import android.os.ParcelFileDescriptor;
import android.os.Process;
import com.google.android.apps.aicore.base.InferenceException;
import com.google.android.apps.aicore.runtime.impl.edgetpu.RuntimeEdgetpu;
import com.google.android.apps.aicore.runtime.wrapper.LargeLanguageModelWrapper;
import com.google.android.apps.aicore.runtime.wrapper.RuntimeModelLoaderWrapper;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import org.json.JSONArray;
import org.json.JSONObject;

/** Offline local-file loader. It provides no generation or provisioning method. */
public final class LocalModelProbe {
    private static boolean modelLoaded;

    private static void event(String phase, Object detail, boolean success) throws Exception {
        JSONObject result = new JSONObject();
        result.put("schema", "ostadix.nano-local-model-probe/v1");
        result.put("phase", phase);
        result.put("detail", detail);
        result.put("success", success);
        result.put("uid", Process.myUid());
        result.put("pid", Process.myPid());
        result.put("model_loaded", modelLoaded);
        result.put("inference_dispatched", SyntheticGenerationProbe.wasDispatched());
        result.put("inference_returned", SyntheticGenerationProbe.wasReturned());
        System.out.println(result.toString());
    }

    private static String sha256(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder output = new StringBuilder();
        for (byte value : digest) output.append(String.format("%02x", value & 255));
        return output.toString();
    }

    public static void main(String[] args) throws Exception {
        execute(args, false);
    }

    static void execute(String[] args, boolean generationMode) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("native-library directory and host model manifest required");
        File nativeDirectory = new File(args[0]);
        File manifest = new File(args[1]);
        if (!nativeDirectory.isAbsolute() || !manifest.isAbsolute()) throw new IllegalArgumentException("absolute paths required");
        if (manifest.length() > 1024 * 1024) throw new IllegalArgumentException("manifest exceeds 1MiB");
        byte[] manifestBytes = Files.readAllBytes(manifest.toPath());
        JSONObject input = new JSONObject(new String(manifestBytes, StandardCharsets.UTF_8));
        if (generationMode != input.has("generation")) {
            throw new IllegalArgumentException("generation manifest requires explicit SyntheticGenerationProbe entrypoint");
        }
        String modelName = input.getString("modelName");
        JSONObject files = input.optJSONObject("files");
        String baseDirectory = input.optString("baseDirectory", "");
        if (modelName.length() == 0 || ((files == null) == baseDirectory.isEmpty())
            || (files != null && (files.length() == 0 || files.length() > 256))) {
            throw new IllegalArgumentException("nonempty modelName and exactly one of baseDirectory or 1..256 files required");
        }
        ArrayList<String> names = new ArrayList<String>();
        if (files != null) {
            Iterator<String> iterator = files.keys();
            while (iterator.hasNext()) names.add(iterator.next());
        }
        Collections.sort(names);
        ArrayList<ParcelFileDescriptor> openFiles = new ArrayList<ParcelFileDescriptor>();
        long runtime = 0;
        long model = 0;
        String phase = "open_local_files";
        int status = 0;
        try {
            Wire config = new Wire();
            JSONArray fileEvidence = new JSONArray();
            if (!baseDirectory.isEmpty()) {
                File base = new File(baseDirectory);
                if (!base.isAbsolute() || !base.isDirectory()) throw new IllegalArgumentException("absolute base directory required");
                config.string(1, base.getCanonicalPath()).integer(5, 0); // Stock enable_ssv2 default false.
            }
            for (String name : names) {
                File file = new File(files.getString(name));
                if (!file.isAbsolute() || !file.isFile()) throw new IllegalArgumentException("not an absolute regular file: " + file);
                ParcelFileDescriptor descriptor = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
                openFiles.add(descriptor);
                config.bytes(2, new Wire().string(1, name).integer(2, descriptor.getFd()).finish());
                JSONObject evidence = new JSONObject();
                evidence.put("logical_name", name);
                evidence.put("path", file.getCanonicalPath());
                evidence.put("bytes", file.length());
                fileEvidence.put(evidence);
            }
            config.string(3, modelName).integer(4, 1); // cfa model enum wire value 1 = LLM.
            JSONObject prepared = new JSONObject();
            prepared.put("manifest_sha256", sha256(manifestBytes));
            prepared.put("model_name", modelName);
            prepared.put("base_directory", baseDirectory);
            prepared.put("files", fileEvidence);
            prepared.put("native_config_sha256", sha256(config.finish()));
            event(phase, prepared, true);
            phase = "native_library_load";
            String[] libraries = {"libruntime_edgetpu_jni.so", "libruntime_model_loader_wrapper_jni.so", "libllm_wrapper_jni.so"};
            for (String library : libraries) System.load(new File(nativeDirectory, library).getCanonicalPath());
            event(phase, "runtime, loader and LLM JNI entrypoints", true);
            phase = "runtime_create";
            runtime = RuntimeEdgetpu.create();
            if (runtime == 0) throw new IllegalStateException("nativeCreate returned zero");
            event(phase, "nonzero native runtime handle", true);
            phase = "model_load";
            model = RuntimeModelLoaderWrapper.loadModel(runtime, config.finish());
            if (model == 0) throw new IllegalStateException("nativeLoadModel returned zero");
            modelLoaded = true;
            event(phase, "nonzero native model handle; no generation performed", true);
            if (input.has("tokenText")) {
                phase = "token_info";
                byte[] response = new LargeLanguageModelWrapper().getTokenInfo(model,
                    Wire.textInput(input.getString("tokenText")));
                JSONObject evidence = new JSONObject();
                evidence.put("protobuf_base64", android.util.Base64.encodeToString(response, android.util.Base64.NO_WRAP));
                evidence.put("protobuf_sha256", sha256(response));
                event(phase, evidence, true);
            }
            if (generationMode) {
                phase = "generation";
                SyntheticGenerationProbe.run(model, input.getJSONObject("generation"));
            }
        } catch (Throwable failure) {
            String detail = failure.getClass().getName() + ": " + failure.getMessage();
            if (failure instanceof InferenceException) detail += " (statusCode=" + ((InferenceException) failure).statusCode + ")";
            event(phase, detail, false);
            failure.printStackTrace(System.err);
            status = 1;
        } finally {
            if (model != 0) {
                try {
                    new LargeLanguageModelWrapper().unload(model);
                    modelLoaded = false;
                    event("model_unload", "nativeUnload returned", true);
                } catch (Throwable failure) {
                    event("model_unload", failure.toString(), false);
                    status = 1;
                }
            }
            if (runtime != 0) {
                try {
                    new RuntimeModelLoaderWrapper().free(runtime);
                    event("runtime_free", "nativeFree returned", true);
                } catch (Throwable failure) {
                    event("runtime_free", failure.toString(), false);
                    status = 1;
                }
            }
            for (ParcelFileDescriptor descriptor : openFiles) descriptor.close();
        }
        System.exit(status);
    }
}
