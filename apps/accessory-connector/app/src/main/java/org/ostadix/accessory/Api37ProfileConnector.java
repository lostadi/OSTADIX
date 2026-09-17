package org.ostadix.accessory;

import android.bluetooth.BluetoothDevice;
import android.os.Build;

/** API-34-compilable adapter for the public BluetoothDevice.connect() method added in API 37. */
final class Api37ProfileConnector implements AccessoryConnectionController.ProfileConnector {
    private final BluetoothDevice device;

    Api37ProfileConnector(BluetoothDevice device) {
        if (device == null) {
            throw new NullPointerException("device");
        }
        this.device = device;
    }

    @Override
    public int connectOnce() throws Exception {
        if (Build.VERSION.SDK_INT < AccessoryConnectionController.MINIMUM_PROFILE_CONNECT_API) {
            throw new UnsupportedOperationException("Android API 37 is required");
        }
        // getMethod resolves public members only. Deliberately do not bypass access checks.
        return PublicIntNoArgMethod.invoke(device, "connect");
    }
}
