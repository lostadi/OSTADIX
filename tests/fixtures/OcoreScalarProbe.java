/* Original Java frontend/reference evidence. This class is not lowered to
 * O-core yet: the runner inventories every concrete method and records the
 * absence of verified managed implementations explicitly. */
public final class OcoreScalarProbe {
    private static int initializedValue = 41;
    private OcoreScalarProbe() {}

    private static int addInt(int a, int b) { return a + b; }
    private static long addLong(long a, long b) { return a + b; }
    private static int multiplyInt(int a, int b) { return a * b; }
    private static long multiplyLong(long a, long b) { return a * b; }
    private static int shiftLeftInt(int a, int n) { return a << n; }
    private static int shiftRightInt(int a, int n) { return a >> n; }
    private static int shiftUnsignedInt(int a, int n) { return a >>> n; }
    private static long shiftLeftLong(long a, int n) { return a << n; }
    private static long shiftRightLong(long a, int n) { return a >> n; }
    private static long shiftUnsignedLong(long a, int n) { return a >>> n; }
    private static int divideInt(int a, int b) { return a / b; }
    private static long divideLong(long a, long b) { return a / b; }
    private static int remainderInt(int a, int b) { return a % b; }
    private static long remainderLong(long a, long b) { return a % b; }
    private static int castByte(int value) { return (byte)value; }
    private static int castShort(int value) { return (short)value; }
    private static int castChar(int value) { return (char)value; }
    private static int castInt(long value) { return (int)value; }
    private static long castLong(int value) { return (long)value; }

    private static void emit32(String name, int value) {
        System.out.printf("%s=%08x%n", name, value);
    }
    private static void emit64(String name, long value) {
        System.out.printf("%s=%016x%n", name, value);
    }

    public static void main(String[] args) {
        emit32("int_add_wrap", addInt(Integer.MAX_VALUE, 1));
        emit64("long_add_wrap", addLong(Long.MAX_VALUE, 1));
        emit32("int_mul_wrap", multiplyInt(0x40000001, 4));
        emit64("long_mul_wrap", multiplyLong(0x4000000000000001L, 4));
        emit32("class_initializer", initializedValue);
        int[] shifts = {0, 31, 32, 33, 63, 64, 65, -1};
        for (int shift : shifts) {
            emit32("int_shl_" + shift, shiftLeftInt(0x81234567, shift));
            emit32("int_shr_" + shift, shiftRightInt(0x81234567, shift));
            emit32("int_ushr_" + shift, shiftUnsignedInt(0x81234567, shift));
            emit64("long_shl_" + shift, shiftLeftLong(0x8123456789abcdefL, shift));
            emit64("long_shr_" + shift, shiftRightLong(0x8123456789abcdefL, shift));
            emit64("long_ushr_" + shift, shiftUnsignedLong(0x8123456789abcdefL, shift));
        }
        emit32("int_min_div_minus1", divideInt(Integer.MIN_VALUE, -1));
        emit64("long_min_div_minus1", divideLong(Long.MIN_VALUE, -1));
        emit32("int_min_rem_minus1", remainderInt(Integer.MIN_VALUE, -1));
        emit64("long_min_rem_minus1", remainderLong(Long.MIN_VALUE, -1));
        emit32("int_negative_div", divideInt(-7, 3));
        emit64("long_negative_div", divideLong(-7, 3));
        emit32("int_negative_rem", remainderInt(-7, 3));
        emit64("long_negative_rem", remainderLong(-7, 3));
        emit32("byte_sign_extend", castByte(0x80));
        emit32("short_sign_extend", castShort(0x8000));
        emit32("char_zero_extend", castChar(-1));
        emit32("long_to_int", castInt(0x1234567889abcdefL));
        emit64("int_to_long", castLong(0x81234567));
        try {
            emit32("int_div_zero", divideInt(7, 0));
        } catch (ArithmeticException expected) {
            System.out.println("int_div_zero=java/lang/ArithmeticException");
        }
        try {
            emit64("long_div_zero", divideLong(7, 0));
        } catch (ArithmeticException expected) {
            System.out.println("long_div_zero=java/lang/ArithmeticException");
        }
        try {
            emit32("int_rem_zero", remainderInt(7, 0));
        } catch (ArithmeticException expected) {
            System.out.println("int_rem_zero=java/lang/ArithmeticException");
        }
        try {
            emit64("long_rem_zero", remainderLong(7, 0));
        } catch (ArithmeticException expected) {
            System.out.println("long_rem_zero=java/lang/ArithmeticException");
        }
    }
}
