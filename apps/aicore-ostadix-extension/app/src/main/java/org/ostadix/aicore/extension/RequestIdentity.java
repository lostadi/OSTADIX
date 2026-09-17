package org.ostadix.aicore.extension;

final class RequestIdentity {
    final int uid;
    final long sequence;
    final String requestId;

    RequestIdentity(int uid, long sequence) {
        this.uid = uid;
        this.sequence = sequence;
        this.requestId = "asoss-llm-" + uid + "-" + sequence;
    }

    String callerId() {
        return "asoss-caller/uid-" + uid;
    }
}
