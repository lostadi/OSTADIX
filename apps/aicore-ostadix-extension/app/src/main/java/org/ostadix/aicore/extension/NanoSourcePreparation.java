package org.ostadix.aicore.extension;

/** At most one model correction, exclusively before any execution dispatch. */
final class NanoSourcePreparation {
    interface Operations {
        void checkActive() throws Exception;
        /** Null means valid. A string means a confirmed parse or source-contract rejection.
         * Transport, cancellation and other failures must throw. */
        String validate(String source) throws Exception;
        String correct(String source, String parseError) throws Exception;
    }

    static final class Prepared {
        final String source;
        final boolean corrected;
        Prepared(String source, boolean corrected) { this.source = source; this.corrected = corrected; }
    }

    static Prepared prepare(String source, Operations operations) throws Exception {
        operations.checkActive();
        String error = operations.validate(source);
        if (error == null) { return new Prepared(source, false); }
        operations.checkActive();
        String corrected = operations.correct(source, error);
        operations.checkActive();
        String remainingError = operations.validate(corrected);
        if (remainingError != null) {
            throw new IllegalArgumentException("Nano generated an invalid program, and its one correction "
                    + "attempt did not fix it. Nothing was executed. Validation: " + remainingError);
        }
        return new Prepared(corrected, true);
    }

    /** A negative contract check, not a parser: native O also accepts plain text.
     * This tool requires an executable language block. Native validation still
     * checks its syntax; this check does not prove intent or successful execution. */
    static String executableContractError(String source) {
        if (java.util.regex.Pattern.compile("[A-Za-z_][A-Za-z0-9_]*\\^\\s*\\(").matcher(source).find()) {
            return null;
        }
        return "The document has no O executable language block. Bare Python is treated as text. "
                + "Return the complete O program, including python^( before the Python body and )_python after it. "
                + "For example: python^( __oval_result__ = 6 * 9 )_python. Use the actual request's calculation.";
    }

    private NanoSourcePreparation() {}
}
