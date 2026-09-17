package org.ostadix.accessory;

/**
 * Pure-Java gate for one explicit Android profile-connection request.
 *
 * <p>The controller never schedules work or retries. Its only call into the platform is the
 * supplied {@link ProfileConnector}, and that call is possible only after every safety gate is
 * satisfied.</p>
 */
public final class AccessoryConnectionController {
    public static final int MINIMUM_PROFILE_CONNECT_API = 37;
    public static final int STATUS_SUCCESS = 0;

    public enum Gate {
        READY,
        BLUETOOTH_UNAVAILABLE,
        API_UNSUPPORTED,
        PERMISSION_REQUIRED,
        BLUETOOTH_DISABLED,
        ASSOCIATION_REQUIRED,
        BOND_REQUIRED,
        REQUEST_IN_FLIGHT
    }

    public interface ProfileConnector {
        int connectOnce() throws Exception;
    }

    public static final class Attempt {
        private final Gate gate;
        private final boolean invoked;
        private final Integer statusCode;
        private final boolean failed;

        private Attempt(Gate gate, boolean invoked, Integer statusCode, boolean failed) {
            this.gate = gate;
            this.invoked = invoked;
            this.statusCode = statusCode;
            this.failed = failed;
        }

        static Attempt blocked(Gate gate) {
            return new Attempt(gate, false, null, false);
        }

        static Attempt completed(int statusCode) {
            return new Attempt(Gate.READY, true, statusCode, false);
        }

        static Attempt exceptionFailure() {
            return new Attempt(Gate.READY, true, null, true);
        }

        public Gate gate() {
            return gate;
        }

        public boolean wasInvoked() {
            return invoked;
        }

        public Integer statusCode() {
            return statusCode;
        }

        public boolean failed() {
            return failed;
        }

        public boolean wasAccepted() {
            return invoked && !failed && statusCode != null && statusCode == STATUS_SUCCESS;
        }
    }

    private int apiLevel;
    private boolean bluetoothAvailable;
    private boolean permissionGranted;
    private boolean bluetoothEnabled;
    private boolean associationConfirmed;
    private boolean bonded;
    private boolean requestInFlight;

    public synchronized void update(
            int apiLevel,
            boolean bluetoothAvailable,
            boolean permissionGranted,
            boolean bluetoothEnabled,
            boolean associationConfirmed,
            boolean bonded) {
        this.apiLevel = apiLevel;
        this.bluetoothAvailable = bluetoothAvailable;
        this.permissionGranted = permissionGranted;
        this.bluetoothEnabled = bluetoothEnabled;
        this.associationConfirmed = associationConfirmed;
        this.bonded = bonded;
        if (gateWithoutInFlight() != Gate.READY) {
            requestInFlight = false;
        }
    }

    public synchronized Gate gate() {
        Gate blocked = gateWithoutInFlight();
        if (blocked == Gate.READY && requestInFlight) {
            return Gate.REQUEST_IN_FLIGHT;
        }
        return blocked;
    }

    public synchronized Attempt requestConnect(ProfileConnector connector) {
        if (connector == null) {
            throw new NullPointerException("connector");
        }
        Gate blocked = gate();
        if (blocked != Gate.READY) {
            return Attempt.blocked(blocked);
        }

        requestInFlight = true;
        try {
            int status = connector.connectOnce();
            if (status != STATUS_SUCCESS) {
                requestInFlight = false;
            }
            return Attempt.completed(status);
        } catch (Exception error) {
            requestInFlight = false;
            return Attempt.exceptionFailure();
        }
    }

    /** Completes the one-shot request after Android reports an asynchronous connection update. */
    public synchronized void onConnectionBroadcast() {
        requestInFlight = false;
    }

    public synchronized boolean isRequestInFlight() {
        return requestInFlight;
    }

    private Gate gateWithoutInFlight() {
        if (!bluetoothAvailable) {
            return Gate.BLUETOOTH_UNAVAILABLE;
        }
        if (apiLevel < MINIMUM_PROFILE_CONNECT_API) {
            return Gate.API_UNSUPPORTED;
        }
        if (!permissionGranted) {
            return Gate.PERMISSION_REQUIRED;
        }
        if (!bluetoothEnabled) {
            return Gate.BLUETOOTH_DISABLED;
        }
        if (!associationConfirmed) {
            return Gate.ASSOCIATION_REQUIRED;
        }
        if (!bonded) {
            return Gate.BOND_REQUIRED;
        }
        return Gate.READY;
    }
}
