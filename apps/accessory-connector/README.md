# Ostadix Accessory Connector

This is a deliberately narrow, foreground-only Android accessory helper. On Android 17
(API 37) or newer, one explicit **Connect supported profiles** tap asks Android to connect
every Bluetooth profile that both the paired accessory and the user-enabled Android profile
settings support.

It does not modify Android, Bluetooth firmware, the baseband, system properties, pairing
policy, or profile settings. It has no service, automatic retry, automatic pairing, root path,
hidden-API access, or background connection path.

## Consent and connection flow

1. Tap **Choose or change accessory**.
2. Grant Android's Nearby devices permission if prompted.
3. Select an accessory in Android's Companion Device Manager system chooser.
4. If Android reports that it is not bonded, use **Open Bluetooth settings** to pair it.
5. Return and tap **Connect supported profiles**. That tap causes exactly one request.

Companion Device Manager performs the system-owned scan and association UI. Association is
an authorization gate; it does not connect the device. Android continues to own discovery,
pairing, authentication, profile negotiation, connection policy, and connection broadcasts.
Immediately before each connect request, the app re-reads its own current CDM associations;
revoking the association therefore closes the gate.

The Activity-lifetime receiver is exported only because framework Bluetooth broadcasts can
come from a highly privileged app outside the system UID. Its registration requires the
sender to hold Android's signature/privileged Bluetooth permission. The app does not request
or receive that permission.
The app never renders, logs, or persists the accessory name or hardware address.

On API 36 or older, the app clearly directs the user to Android Bluetooth settings and does
not attempt the all-profile API.

## Capability limits

`BluetoothDevice.connect()` can only request profiles Android and the accessory mutually
support, and only profiles the user has enabled. It cannot add vendor protocols, codecs,
certifications, or radio capabilities. In particular, this does **not** provide MFi, AirPlay,
CarPlay, Apple Continuity features, or general iPhone accessory parity.

The manifest requests only `android.permission.BLUETOOTH_CONNECT`. Bluetooth, Bluetooth LE,
Companion Device Setup, and touchscreen are declared optional so unsupported devices can
show a useful fallback instead of being falsely advertised as capable.

The local compiler is Android API 34. The runtime method was added in API 37, so the tiny
adapter resolves the public method with Java `Class.getMethod`; it never uses declared-member
lookup or disables access checks. The pure-Java controller independently enforces API level,
permission, enabled Bluetooth, confirmed CDM association, bond state, and one-request-at-a-time
gates before that adapter can run.

## Build and tests

The module follows the repository's no-Gradle Android build convention:

```bash
cd apps/accessory-connector
./tests/self-test.sh
./build.sh
```

`self-test.sh` compiles into a private temporary directory and checks controller behavior,
public-reflection constraints, manifest permissions/components, forbidden APIs, explicit-tap
semantics, and accessibility/static-visual requirements. `build.sh` writes only to the ignored
`build/` directory and creates its debug keystore inside build intermediates.

## Primary Android documentation

- [`BluetoothDevice.connect()`](https://developer.android.com/reference/android/bluetooth/BluetoothDevice#connect())
- [Companion device pairing](https://developer.android.com/develop/connectivity/bluetooth/companion-device-pairing)
- [Bluetooth permissions](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions)
- [`CompanionDeviceManager`](https://developer.android.com/reference/android/companion/CompanionDeviceManager)
- [Broadcast receiver export behavior](https://developer.android.com/develop/background-work/background-tasks/broadcasts)
