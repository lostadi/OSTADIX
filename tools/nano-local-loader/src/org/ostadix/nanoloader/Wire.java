package org.ostadix.nanoloader;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** Minimal protobuf wire encoder for the recovered loader boundary. */
final class Wire {
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

    private void varint(long value) {
        while ((value & ~0x7fL) != 0) {
            bytes.write(((int) value & 0x7f) | 0x80);
            value >>>= 7;
        }
        bytes.write((int) value);
    }

    Wire integer(int field, long value) {
        varint((long) field << 3);
        varint(value);
        return this;
    }

    Wire bytes(int field, byte[] value) {
        varint(((long) field << 3) | 2);
        varint(value.length);
        bytes.write(value, 0, value.length);
        return this;
    }

    Wire string(int field, String value) {
        return bytes(field, value.getBytes(StandardCharsets.UTF_8));
    }

    Wire floating(int field, float value) {
        varint(((long) field << 3) | 5);
        int bits = Float.floatToIntBits(value);
        for (int index = 0; index < 4; index++) bytes.write(bits >>> (index * 8));
        return this;
    }

    Wire raw(byte[] value) {
        bytes.write(value, 0, value.length);
        return this;
    }

    static byte[] textInput(String text) {
        // cer.input(11) -> ceq.parts(1) -> cdv.text(1).
        // ceq.field10=1 matches cdl.m2470l's single text generation mode.
        byte[] part = new Wire().string(1, text).finish();
        byte[] input = new Wire().bytes(1, part).integer(10, 1).finish();
        return new Wire().bytes(11, input).finish();
    }

    byte[] finish() { return bytes.toByteArray(); }
}
