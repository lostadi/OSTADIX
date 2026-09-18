package org.ostadix.aicore.extension;

public final class AsiDelegationSelfTest {
    public static void main(String[] args) throws Throwable {
        for (boolean transformThrows : new boolean[]{false, true}) {
            for (boolean originalThrows : new boolean[]{false, true}) {
                int[] invocations = {0};
                int[] failures = {0};
                Object[] changed = {"selected"};
                Object expected = new Object();
                Throwable originalError = new IllegalStateException("original failed");
                Object actual = null;
                try {
                    actual = AsiDelegation.invoke(new AsiDelegation.Preparation() {
                        public Object[] prepare() throws Throwable {
                            if (transformThrows) throw new IllegalArgumentException("selection failed");
                            return changed;
                        }
                    }, new AsiDelegation.Original() {
                        public Object invoke(Object[] arguments) throws Throwable {
                            invocations[0]++;
                            if (arguments != (transformThrows ? null : changed))
                                throw new AssertionError("wrong delegated arguments");
                            if (originalThrows) throw originalError;
                            return expected;
                        }
                    }, new AsiDelegation.Failure() {
                        public void record(Throwable error) { failures[0]++; }
                    });
                    if (originalThrows) throw new AssertionError("original error swallowed");
                } catch (Throwable error) {
                    if (!originalThrows || error != originalError) throw error;
                }
                if (invocations[0] != 1 || failures[0] != (transformThrows ? 1 : 0)
                        || (!originalThrows && actual != expected))
                    throw new AssertionError("delegation repeated or result changed");
            }
        }
        int[] invocations = {0};
        final OutOfMemoryError fatal = new OutOfMemoryError("test");
        try {
            AsiDelegation.invoke(new AsiDelegation.Preparation() {
                public Object[] prepare() { throw fatal; }
            }, new AsiDelegation.Original() {
                public Object invoke(Object[] arguments) {
                    invocations[0]++;
                    return null;
                }
            }, new AsiDelegation.Failure() {
                public void record(Throwable error) {
                    throw new AssertionError("fatal error treated as fallback");
                }
            });
            throw new AssertionError("fatal error swallowed");
        } catch (OutOfMemoryError error) {
            if (error != fatal || invocations[0] != 0) throw new AssertionError("fatal delegated");
        }
        System.out.println("ASI delegation: four success/failure combinations called original once; fatal called zero times");
    }
}
