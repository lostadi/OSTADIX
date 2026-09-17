package org.ostadix.nanoloader;

import dalvik.system.PathClassLoader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import org.json.JSONObject;

/** Parse our encoded request using the installed APK's original protobuf parser. */
public final class StockWireVerifier {
    private static Object field(Object object, String name) throws Exception {
        for (Class<?> type = object.getClass(); type != null; type = type.getSuperclass()) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(object);
            } catch (NoSuchFieldException missing) { }
        }
        throw new NoSuchFieldException(name);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("installed AICore base APK required");
        ClassLoader loader = new PathClassLoader(args[0], StockWireVerifier.class.getClassLoader());
        Class<?> requestClass = Class.forName("cer", true, loader);
        Object prototype = requestClass.getDeclaredField("a").get(null);
        Class<?> registryClass = Class.forName("gzx", true, loader);
        Object registry = registryClass.getDeclaredMethod("a").invoke(null);
        Class<?> messageClass = Class.forName("hak", true, loader);
        Method parse = messageClass.getDeclaredMethod("w", messageClass, byte[].class, registryClass);
        byte[] request = new Wire().floating(2, 0.25f).integer(3, 17).integer(5, 1).integer(6, 1)
            .floating(14, 1.0f).raw(Wire.textInput("Ostadix wire verification")).finish();
        Object parsed = parse.invoke(null, prototype, request, registry);
        List<?> inputs = (List<?>) field(parsed, "i");
        Object input = inputs.get(0);
        Object part = ((List<?>) field(input, "c")).get(0);
        JSONObject output = new JSONObject();
        output.put("parser", "installed_AICore_protobuf");
        output.put("temperature", field(parsed, "c"));
        output.put("max_output_tokens", field(parsed, "d"));
        output.put("top_k", field(parsed, "f"));
        output.put("num_samples", field(parsed, "g"));
        output.put("top_p", field(parsed, "k"));
        output.put("input_count", inputs.size());
        output.put("input_mode", field(input, "g"));
        output.put("text_oneof_case", field(part, "b"));
        output.put("text", field(part, "c"));
        output.put("inference_executed", false);
        if (!field(part, "c").equals("Ostadix wire verification")
            || ((Number) field(parsed, "d")).intValue() != 17
            || ((Number) field(parsed, "c")).floatValue() != 0.25f
            || ((Number) field(part, "b")).intValue() != 1) {
            throw new IllegalStateException("original parser disagrees with recovered wire contract");
        }
        Class<?> extensionClass = Class.forName("cfq", true, loader);
        byte[] runtimeConfig = new Wire().integer(1, 123).integer(2, 1440).integer(3, 0).integer(4, 1).finish();
        Class<?> sessionClass = Class.forName("cfe", true, loader);
        byte[] sessionConfig = new Wire().bytes(100, runtimeConfig).integer(18, 0).integer(20, 0).finish();
        Object parsedSession = parse.invoke(null, sessionClass.getDeclaredField("a").get(null), sessionConfig, registry);
        Object extensionDescriptor = extensionClass.getDeclaredField("k").get(null);
        Object extensionKey = field(extensionDescriptor, "d");
        Object extensionSet = field(parsedSession, "u");
        Method extensionGetter = extensionSet.getClass().getDeclaredMethod("j", Class.forName("haj", true, loader));
        Object parsedExtension = extensionGetter.invoke(extensionSet, extensionKey);
        if (parsedExtension == null || ((Number) field(parsedExtension, "e")).longValue() != 123) {
            throw new IllegalStateException("original parser did not recover session RNG extension");
        }
        output.put("session_rng_seed", field(parsedExtension, "e"));
        output.put("session_extension_100_recognized", true);
        byte[] response = new Wire().bytes(1, new Wire().string(1, "synthetic decoder fixture").integer(5, 2).finish()).finish();
        Class<?> responseClass = Class.forName("ceu", true, loader);
        Object parsedResponse = parse.invoke(null, responseClass.getDeclaredField("a").get(null), response, registry);
        Object candidate = ((List<?>) field(parsedResponse, "b")).get(0);
        JSONObject ownCandidate = ResponseDecoder.candidates(response).getJSONObject(0);
        if (!field(candidate, "c").equals(ownCandidate.getString("text"))
            || ((Number) field(candidate, "f")).intValue() != ownCandidate.getInt("finish_reason_enum")) {
            throw new IllegalStateException("response decoder disagrees with original parser");
        }
        output.put("response_decoder_matches_original_parser", true);
        System.out.println(output.toString());
    }
}
