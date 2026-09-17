package org.ostadix.nanoloader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;

/** Bounded reader for ceu.field1 repeated cdw; preserves full native bytes separately. */
final class ResponseDecoder {
    private final byte[] bytes;
    private int position;

    private ResponseDecoder(byte[] bytes) { this.bytes = bytes; }

    private long varint() {
        long value = 0;
        for (int shift = 0; shift < 64; shift += 7) {
            if (position >= bytes.length) throw new IllegalArgumentException("truncated protobuf varint");
            int next = bytes[position++] & 255;
            value |= (long) (next & 127) << shift;
            if ((next & 128) == 0) return value;
        }
        throw new IllegalArgumentException("protobuf varint exceeds 64 bits");
    }

    private byte[] data(int length) {
        if (length < 0 || length > bytes.length - position) throw new IllegalArgumentException("truncated protobuf data");
        byte[] result = Arrays.copyOfRange(bytes, position, position + length);
        position += length;
        return result;
    }

    private byte[] lengthData() {
        long length = varint();
        if (length > Integer.MAX_VALUE || length < 0) throw new IllegalArgumentException("protobuf length overflow");
        return data((int) length);
    }

    private void skip(int wireType) {
        switch (wireType) {
            case 0: varint(); break;
            case 1: data(8); break;
            case 2: lengthData(); break;
            case 5: data(4); break;
            default: throw new IllegalArgumentException("unsupported protobuf wire type: " + wireType);
        }
    }

    static JSONArray candidates(byte[] response) throws Exception {
        ResponseDecoder outer = new ResponseDecoder(response);
        JSONArray result = new JSONArray();
        while (outer.position < response.length) {
            long tag = outer.varint();
            if (tag == 10) {
                if (result.length() >= 16) throw new IllegalArgumentException("native response has >16 candidates");
                ResponseDecoder candidate = new ResponseDecoder(outer.lengthData());
                JSONObject item = new JSONObject();
                while (candidate.position < candidate.bytes.length) {
                    long candidateTag = candidate.varint();
                    if (candidateTag == 10) item.put("text", new String(candidate.lengthData(), StandardCharsets.UTF_8));
                    else if (candidateTag == 17) {
                        double score = ByteBuffer.wrap(candidate.data(8)).order(ByteOrder.LITTLE_ENDIAN).getDouble();
                        item.put("score", Double.isFinite(score) ? score : JSONObject.NULL);
                    } else if (candidateTag == 40) item.put("finish_reason_enum", candidate.varint());
                    else candidate.skip((int) candidateTag & 7);
                }
                result.put(item);
            } else outer.skip((int) tag & 7);
        }
        return result;
    }
}
