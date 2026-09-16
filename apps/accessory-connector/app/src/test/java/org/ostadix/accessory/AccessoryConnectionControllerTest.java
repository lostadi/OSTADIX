package org.ostadix.accessory;

import java.lang.reflect.Method;

/** Dependency-free unit tests for the safety gate and public-method resolver. */
public final class AccessoryConnectionControllerTest {
    private int assertions;

    public static void main(String[] args) throws Exception {
        AccessoryConnectionControllerTest test = new AccessoryConnectionControllerTest();
        test.gatesEveryPreconditionInOrder();
        test.blockedAttemptsNeverInvokePlatformCode();
        test.acceptedRequestIsExactlyOnceUntilBroadcast();
        test.rejectionRequiresAnotherExplicitRequest();
        test.exceptionDoesNotRetry();
        test.publicResolverAcceptsOnlyPublicNoArgIntMethods();
        System.out.println("AccessoryConnectionControllerTest: " + test.assertions + " assertions passed");
    }

    private void gatesEveryPreconditionInOrder() {
        AccessoryConnectionController controller = new AccessoryConnectionController();
        assertGate(controller, AccessoryConnectionController.Gate.BLUETOOTH_UNAVAILABLE);

        controller.update(36, true, true, true, true, true);
        assertGate(controller, AccessoryConnectionController.Gate.API_UNSUPPORTED);
        controller.update(37, true, false, true, true, true);
        assertGate(controller, AccessoryConnectionController.Gate.PERMISSION_REQUIRED);
        controller.update(37, true, true, false, true, true);
        assertGate(controller, AccessoryConnectionController.Gate.BLUETOOTH_DISABLED);
        controller.update(37, true, true, true, false, true);
        assertGate(controller, AccessoryConnectionController.Gate.ASSOCIATION_REQUIRED);
        controller.update(37, true, true, true, true, false);
        assertGate(controller, AccessoryConnectionController.Gate.BOND_REQUIRED);
        controller.update(37, true, true, true, true, true);
        assertGate(controller, AccessoryConnectionController.Gate.READY);
    }

    private void blockedAttemptsNeverInvokePlatformCode() {
        boolean[][] states = {
                {false, false, false, false, false},
                {true, false, false, false, false},
                {true, true, false, false, false},
                {true, true, true, false, false},
                {true, true, true, true, false}
        };
        for (boolean[] state : states) {
            AccessoryConnectionController controller = new AccessoryConnectionController();
            controller.update(37, state[0], state[1], state[2], state[3], state[4]);
            CountingConnector connector = new CountingConnector(0, false);
            AccessoryConnectionController.Attempt attempt = controller.requestConnect(connector);
            assertFalse(attempt.wasInvoked(), "blocked attempt was invoked");
            assertEquals(0, connector.calls, "blocked attempt called platform connector");
        }

        AccessoryConnectionController oldPlatform = new AccessoryConnectionController();
        oldPlatform.update(36, true, true, true, true, true);
        CountingConnector connector = new CountingConnector(0, false);
        assertFalse(oldPlatform.requestConnect(connector).wasInvoked(), "API 36 attempt was invoked");
        assertEquals(0, connector.calls, "API 36 called platform connector");
    }

    private void acceptedRequestIsExactlyOnceUntilBroadcast() {
        AccessoryConnectionController controller = readyController();
        CountingConnector connector = new CountingConnector(0, false);

        AccessoryConnectionController.Attempt first = controller.requestConnect(connector);
        assertTrue(first.wasAccepted(), "success status was not accepted");
        assertEquals(1, connector.calls, "first tap did not make exactly one call");
        assertGate(controller, AccessoryConnectionController.Gate.REQUEST_IN_FLIGHT);

        AccessoryConnectionController.Attempt duplicate = controller.requestConnect(connector);
        assertFalse(duplicate.wasInvoked(), "in-flight request was invoked twice");
        assertEquals(1, connector.calls, "duplicate request called platform connector");

        controller.onConnectionBroadcast();
        assertGate(controller, AccessoryConnectionController.Gate.READY);
        controller.requestConnect(connector);
        assertEquals(2, connector.calls, "new explicit tap did not make one new call");
    }

    private void rejectionRequiresAnotherExplicitRequest() {
        AccessoryConnectionController controller = readyController();
        CountingConnector connector = new CountingConnector(7, false);
        AccessoryConnectionController.Attempt rejected = controller.requestConnect(connector);

        assertTrue(rejected.wasInvoked(), "rejected request was not invoked");
        assertFalse(rejected.wasAccepted(), "nonzero status was accepted");
        assertEquals(Integer.valueOf(7), rejected.statusCode(), "status code was lost");
        assertEquals(1, connector.calls, "controller retried a rejected request");
        assertFalse(controller.isRequestInFlight(), "rejected request remained in flight");

        controller.requestConnect(connector);
        assertEquals(2, connector.calls, "second explicit request was not honored");
    }

    private void exceptionDoesNotRetry() {
        AccessoryConnectionController controller = readyController();
        CountingConnector connector = new CountingConnector(0, true);
        AccessoryConnectionController.Attempt failed = controller.requestConnect(connector);

        assertTrue(failed.failed(), "connector exception was not reported");
        assertEquals(1, connector.calls, "controller retried after an exception");
        assertFalse(controller.isRequestInFlight(), "failed request remained in flight");
    }

    private void publicResolverAcceptsOnlyPublicNoArgIntMethods() throws Exception {
        Method valid = PublicIntNoArgMethod.resolve(PublicMethods.class, "success");
        assertEquals(Integer.TYPE, valid.getReturnType(), "valid method return type changed");
        assertEquals(41, PublicIntNoArgMethod.invoke(new PublicMethods(), "success"),
                "valid public method was not invoked");
        expectNoSuchMethod(PublicMethods.class, "privateMethod");
        expectNoSuchMethod(PublicMethods.class, "withArgument");
        expectNoSuchMethod(PublicMethods.class, "wrongReturn");

        try {
            PublicIntNoArgMethod.invoke(new PublicMethods(), "checkedFailure");
            fail("checked exception was swallowed");
        } catch (Exception expected) {
            assertEquals("expected", expected.getMessage(), "checked exception was not unwrapped");
        }
    }

    private void expectNoSuchMethod(Class<?> owner, String name) throws Exception {
        try {
            PublicIntNoArgMethod.resolve(owner, name);
            fail("unsafe signature resolved: " + name);
        } catch (NoSuchMethodException expected) {
            assertions++;
        }
    }

    private AccessoryConnectionController readyController() {
        AccessoryConnectionController controller = new AccessoryConnectionController();
        controller.update(37, true, true, true, true, true);
        return controller;
    }

    private void assertGate(
            AccessoryConnectionController controller,
            AccessoryConnectionController.Gate expected) {
        assertEquals(expected, controller.gate(), "wrong safety gate");
    }

    private void assertTrue(boolean value, String message) {
        assertions++;
        if (!value) {
            throw new AssertionError(message);
        }
    }

    private void assertFalse(boolean value, String message) {
        assertTrue(!value, message);
    }

    private void assertEquals(Object expected, Object actual, String message) {
        assertions++;
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(message + ": expected " + expected + ", got " + actual);
        }
    }

    private void fail(String message) {
        throw new AssertionError(message);
    }

    private static final class CountingConnector
            implements AccessoryConnectionController.ProfileConnector {
        private final int status;
        private final boolean throwException;
        private int calls;

        CountingConnector(int status, boolean throwException) {
            this.status = status;
            this.throwException = throwException;
        }

        @Override
        public int connectOnce() throws Exception {
            calls++;
            if (throwException) {
                throw new Exception("expected");
            }
            return status;
        }
    }

    public static final class PublicMethods {
        public int success() {
            return 41;
        }

        private int privateMethod() {
            return 0;
        }

        public int withArgument(int ignored) {
            return ignored;
        }

        public Integer wrongReturn() {
            return Integer.valueOf(0);
        }

        public int checkedFailure() throws Exception {
            throw new Exception("expected");
        }
    }
}
