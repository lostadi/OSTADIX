package org.ostadix.accessory;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHearingAid;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothLeAudio;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.companion.AssociatedDevice;
import android.companion.AssociationInfo;
import android.companion.AssociationRequest;
import android.companion.BluetoothDeviceFilter;
import android.companion.BluetoothLeDeviceFilter;
import android.companion.CompanionDeviceManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentSender;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcelable;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Foreground-only, consent-driven connector for one CDM-associated Bluetooth accessory. */
public final class MainActivity extends Activity {
    private static final int REQUEST_CONNECT_PERMISSION = 100;
    private static final int REQUEST_ASSOCIATION = 101;

    private final AccessoryConnectionController controller =
            new AccessoryConnectionController();

    private BluetoothAdapter bluetoothAdapter;
    private CompanionDeviceManager companionManager;
    private BluetoothDevice selectedDevice;
    private boolean associationConfirmed;
    private boolean associationInProgress;
    private boolean chooserVisible;
    private boolean receiverRegistered;
    private boolean chooseAfterPermission;

    private TextView statusView;
    private Button chooseButton;
    private Button connectButton;
    private Button settingsButton;

    private final CompanionDeviceManager.Callback associationCallback =
            new CompanionDeviceManager.Callback() {
                @Override
                public void onAssociationPending(IntentSender chooserLauncher) {
                    launchAssociationChooser(chooserLauncher);
                }

                @Override
                @SuppressWarnings("deprecation")
                public void onDeviceFound(IntentSender chooserLauncher) {
                    launchAssociationChooser(chooserLauncher);
                }

                @Override
                public void onAssociationCreated(AssociationInfo associationInfo) {
                    associationInProgress = false;
                    BluetoothDevice device = deviceFromAssociation(associationInfo);
                    if (device == null) {
                        refreshUi("Android created the association but returned no Bluetooth device.");
                        return;
                    }
                    acceptAssociatedDevice(device);
                }

                @Override
                public void onFailure(CharSequence error) {
                    associationInProgress = false;
                    chooserVisible = false;
                    refreshUi("Android did not create an accessory association.");
                }
            };

    private final BroadcastReceiver connectionReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (BluetoothAdapter.ACTION_STATE_CHANGED.equals(action)) {
                refreshUi(null);
                return;
            }

            BluetoothDevice eventDevice = intent.getParcelableExtra(
                    BluetoothDevice.EXTRA_DEVICE, BluetoothDevice.class);
            if (selectedDevice == null || !selectedDevice.equals(eventDevice)) {
                return;
            }

            controller.onConnectionBroadcast();
            int state;
            if (BluetoothDevice.ACTION_ACL_CONNECTED.equals(action)) {
                state = BluetoothProfile.STATE_CONNECTED;
            } else if (BluetoothDevice.ACTION_ACL_DISCONNECTED.equals(action)) {
                state = BluetoothProfile.STATE_DISCONNECTED;
            } else {
                state = intent.getIntExtra(
                        BluetoothProfile.EXTRA_STATE, BluetoothProfile.STATE_DISCONNECTED);
            }
            refreshUi(profileLabel(action) + " is " + stateLabel(state) + ".");
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        BluetoothManager bluetoothManager = getSystemService(BluetoothManager.class);
        bluetoothAdapter = bluetoothManager == null ? null : bluetoothManager.getAdapter();
        companionManager = getSystemService(CompanionDeviceManager.class);
        createContentView();
        refreshUi(null);
    }

    @Override
    protected void onStart() {
        super.onStart();
        registerConnectionReceiverIfPermitted();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshUi(null);
    }

    @Override
    protected void onStop() {
        if (receiverRegistered) {
            unregisterReceiver(connectionReceiver);
            receiverRegistered = false;
        }
        controller.onConnectionBroadcast();
        super.onStop();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_ASSOCIATION) {
            return;
        }
        chooserVisible = false;
        associationInProgress = false;
        if (resultCode != RESULT_OK || data == null) {
            refreshUi("Accessory selection was canceled.");
            return;
        }

        AssociationInfo associationInfo = data.getParcelableExtra(
                CompanionDeviceManager.EXTRA_ASSOCIATION, AssociationInfo.class);
        BluetoothDevice device = deviceFromAssociation(associationInfo);
        if (device == null) {
            Parcelable selected = data.getParcelableExtra(CompanionDeviceManager.EXTRA_DEVICE);
            device = deviceFromSelection(selected);
        }
        if (device == null) {
            refreshUi("Waiting for Android to confirm the accessory association.");
            return;
        }
        // RESULT_OK is returned by the CDM chooser only after the user confirms association.
        acceptAssociatedDevice(device);
    }

    @Override
    public void onRequestPermissionsResult(
            int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != REQUEST_CONNECT_PERMISSION) {
            return;
        }
        boolean granted = grantResults.length > 0
                && grantResults[0] == PackageManager.PERMISSION_GRANTED;
        if (!granted) {
            chooseAfterPermission = false;
            refreshUi("Nearby devices permission was not granted. Nothing was connected.");
            return;
        }
        registerConnectionReceiverIfPermitted();
        if (chooseAfterPermission) {
            chooseAfterPermission = false;
            beginAssociation();
        } else {
            refreshUi(null);
        }
    }

    private void createContentView() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundResource(R.drawable.prismatic_background);

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setGravity(Gravity.CENTER_HORIZONTAL);
        int spacing = dp(20);
        content.setPadding(spacing, dp(28), spacing, dp(28));
        content.setBackgroundResource(R.drawable.glass_panel);
        ScrollView.LayoutParams contentParams = new ScrollView.LayoutParams(
                ScrollView.LayoutParams.MATCH_PARENT,
                ScrollView.LayoutParams.WRAP_CONTENT);
        contentParams.setMargins(dp(16), dp(18), dp(16), dp(18));
        scroll.addView(content, contentParams);

        TextView title = textView(getString(R.string.title), 28f, true);
        title.setAccessibilityHeading(true);
        content.addView(title, matchWidth());

        TextView intro = textView(getString(R.string.intro), 17f, false);
        intro.setTextColor(getColor(R.color.accessory_text_muted));
        content.addView(intro, spacedWidth(dp(12)));

        statusView = textView(getString(R.string.status_initial), 18f, true);
        statusView.setBackgroundResource(R.drawable.glass_status);
        statusView.setPadding(dp(16), dp(16), dp(16), dp(16));
        statusView.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        statusView.setFocusable(true);
        content.addView(statusView, spacedWidth(dp(24)));

        chooseButton = actionButton(getString(R.string.choose_accessory));
        chooseButton.setContentDescription(
                "Choose an accessory using Android's companion device chooser");
        chooseButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                chooseAccessory();
            }
        });
        content.addView(chooseButton, spacedWidth(dp(20)));

        connectButton = actionButton(getString(R.string.connect_accessory));
        connectButton.setContentDescription(
                "Explicitly request connection of Android-supported profiles");
        connectButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                connectSelectedAccessory();
            }
        });
        content.addView(connectButton, spacedWidth(dp(12)));

        settingsButton = actionButton(getString(R.string.open_bluetooth_settings));
        settingsButton.setContentDescription(
                "Open Android Bluetooth settings for pairing or troubleshooting");
        settingsButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                openBluetoothSettings();
            }
        });
        content.addView(settingsButton, spacedWidth(dp(12)));

        TextView limits = textView(getString(R.string.limits), 15f, false);
        limits.setTextColor(getColor(R.color.accessory_text_muted));
        content.addView(limits, spacedWidth(dp(24)));

        setContentView(scroll);
    }

    private void chooseAccessory() {
        if (Build.VERSION.SDK_INT < AccessoryConnectionController.MINIMUM_PROFILE_CONNECT_API) {
            refreshUi("Android 17 is required. Use Android Bluetooth settings on this version.");
            openBluetoothSettings();
            return;
        }
        if (!hasConnectPermission()) {
            chooseAfterPermission = true;
            requestPermissions(
                    new String[] {Manifest.permission.BLUETOOTH_CONNECT},
                    REQUEST_CONNECT_PERMISSION);
            return;
        }
        beginAssociation();
    }

    private void beginAssociation() {
        if (associationInProgress || chooserVisible) {
            return;
        }
        if (companionManager == null || bluetoothAdapter == null) {
            refreshUi("Companion device setup or Bluetooth is unavailable on this device.");
            return;
        }
        if (!safeBluetoothEnabled()) {
            refreshUi("Bluetooth is off. Turn it on in Android settings first.");
            return;
        }

        BluetoothDeviceFilter classicFilter = new BluetoothDeviceFilter.Builder().build();
        BluetoothLeDeviceFilter lowEnergyFilter = new BluetoothLeDeviceFilter.Builder()
                .setScanFilter(new ScanFilter.Builder().build())
                .build();
        AssociationRequest request = new AssociationRequest.Builder()
                .addDeviceFilter(classicFilter)
                .addDeviceFilter(lowEnergyFilter)
                .setSingleDevice(false)
                .build();
        associationInProgress = true;
        refreshUi("Android is searching. Choose one accessory in the system dialog.");
        try {
            companionManager.associate(request, getMainExecutor(), associationCallback);
        } catch (RuntimeException error) {
            associationInProgress = false;
            refreshUi("Android could not start companion device selection.");
        }
    }

    private void launchAssociationChooser(IntentSender chooserLauncher) {
        if (chooserLauncher == null || chooserVisible) {
            return;
        }
        chooserVisible = true;
        try {
            startIntentSenderForResult(
                    chooserLauncher, REQUEST_ASSOCIATION, null, 0, 0, 0);
        } catch (IntentSender.SendIntentException error) {
            chooserVisible = false;
            associationInProgress = false;
            refreshUi("Android could not open the companion device chooser.");
        }
    }

    private void acceptAssociatedDevice(BluetoothDevice device) {
        selectedDevice = device;
        associationConfirmed = true;
        controller.onConnectionBroadcast();
        if (safeBonded()) {
            refreshUi("Accessory associated and paired. Tap Connect supported profiles.");
        } else {
            refreshUi("Accessory associated but not paired. Pair it in Android settings first.");
        }
    }

    private void connectSelectedAccessory() {
        associationConfirmed = isCurrentlyAssociated(selectedDevice);
        updateController();
        if (selectedDevice == null) {
            refreshUi(gateMessage(controller.gate()));
            return;
        }
        AccessoryConnectionController.Attempt attempt = controller.requestConnect(
                new Api37ProfileConnector(selectedDevice));
        if (!attempt.wasInvoked()) {
            refreshUi(gateMessage(attempt.gate()));
        } else if (attempt.failed()) {
            refreshUi("Android rejected the profile connection request before it started.");
        } else if (attempt.wasAccepted()) {
            refreshUi("Request accepted. Waiting for Android profile connection broadcasts.");
        } else {
            refreshUi(statusMessage(attempt.statusCode()));
        }
    }

    private void openBluetoothSettings() {
        Intent intent = new Intent(Settings.ACTION_BLUETOOTH_SETTINGS);
        try {
            startActivity(intent);
        } catch (RuntimeException error) {
            startActivity(new Intent(Settings.ACTION_SETTINGS));
        }
    }

    private void refreshUi(String announcement) {
        updateController();
        if (statusView == null) {
            return;
        }
        String message = announcement == null ? gateMessage(controller.gate()) : announcement;
        statusView.setText(message);
        if (announcement != null) {
            statusView.sendAccessibilityEvent(AccessibilityEvent.TYPE_ANNOUNCEMENT);
        }

        boolean platformReady = bluetoothAdapter != null
                && Build.VERSION.SDK_INT >= AccessoryConnectionController.MINIMUM_PROFILE_CONNECT_API;
        chooseButton.setEnabled(platformReady && !associationInProgress && !chooserVisible);
        connectButton.setEnabled(controller.gate() == AccessoryConnectionController.Gate.READY);
        settingsButton.setEnabled(true);
    }

    private void updateController() {
        boolean permission = hasConnectPermission();
        controller.update(
                Build.VERSION.SDK_INT,
                bluetoothAdapter != null,
                permission,
                permission && safeBluetoothEnabled(),
                associationConfirmed && selectedDevice != null,
                permission && associationConfirmed && selectedDevice != null && safeBonded());
    }

    private boolean hasConnectPermission() {
        return checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                == PackageManager.PERMISSION_GRANTED;
    }

    private boolean safeBluetoothEnabled() {
        if (bluetoothAdapter == null || !hasConnectPermission()) {
            return false;
        }
        try {
            return bluetoothAdapter.isEnabled();
        } catch (SecurityException error) {
            return false;
        }
    }

    private boolean safeBonded() {
        if (selectedDevice == null || !hasConnectPermission()) {
            return false;
        }
        try {
            return selectedDevice.getBondState() == BluetoothDevice.BOND_BONDED;
        } catch (SecurityException error) {
            return false;
        }
    }

    private boolean isCurrentlyAssociated(BluetoothDevice device) {
        if (device == null || companionManager == null || !hasConnectPermission()) {
            return false;
        }
        try {
            java.util.List<AssociationInfo> associations = companionManager.getMyAssociations();
            if (associations == null) {
                return false;
            }
            for (AssociationInfo association : associations) {
                BluetoothDevice associated = deviceFromAssociation(association);
                if (device.equals(associated)) {
                    return true;
                }
            }
        } catch (RuntimeException error) {
            return false;
        }
        return false;
    }

    private BluetoothDevice deviceFromAssociation(AssociationInfo associationInfo) {
        if (associationInfo == null || bluetoothAdapter == null) {
            return null;
        }
        try {
            AssociatedDevice associatedDevice = associationInfo.getAssociatedDevice();
            if (associatedDevice != null) {
                BluetoothDevice classic = associatedDevice.getBluetoothDevice();
                if (classic != null) {
                    return classic;
                }
                ScanResult lowEnergy = associatedDevice.getBleDevice();
                if (lowEnergy != null) {
                    return lowEnergy.getDevice();
                }
            }
            if (associationInfo.getDeviceMacAddress() != null) {
                return bluetoothAdapter.getRemoteDevice(
                        associationInfo.getDeviceMacAddress().toString());
            }
        } catch (RuntimeException error) {
            return null;
        }
        return null;
    }

    private BluetoothDevice deviceFromSelection(Parcelable selected) {
        if (selected instanceof BluetoothDevice) {
            return (BluetoothDevice) selected;
        }
        if (selected instanceof ScanResult) {
            return ((ScanResult) selected).getDevice();
        }
        if (selected instanceof AssociationInfo) {
            return deviceFromAssociation((AssociationInfo) selected);
        }
        return null;
    }

    private void registerConnectionReceiverIfPermitted() {
        if (receiverRegistered || !hasConnectPermission()) {
            return;
        }
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED);
        filter.addAction(BluetoothDevice.ACTION_ACL_CONNECTED);
        filter.addAction(BluetoothDevice.ACTION_ACL_DISCONNECTED);
        filter.addAction(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothHearingAid.ACTION_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothLeAudio.ACTION_LE_AUDIO_CONNECTION_STATE_CHANGED);
        try {
            // Bluetooth broadcasts originate from a highly privileged framework app, so Android's
            // documented dynamic-receiver guidance requires RECEIVER_EXPORTED. The receiver exists
            // only while this Activity is started, accepts signature/privileged senders, and
            // ignores events for every other device. This app never requests that permission.
            registerReceiver(
                    connectionReceiver,
                    filter,
                    Manifest.permission.BLUETOOTH_PRIVILEGED,
                    null,
                    Context.RECEIVER_EXPORTED);
            receiverRegistered = true;
        } catch (RuntimeException error) {
            receiverRegistered = false;
        }
    }

    private String gateMessage(AccessoryConnectionController.Gate gate) {
        switch (gate) {
            case BLUETOOTH_UNAVAILABLE:
                return "This device does not expose a Bluetooth adapter.";
            case API_UNSUPPORTED:
                return "Android 17 is required. Use Android Bluetooth settings on this version.";
            case PERMISSION_REQUIRED:
                return "Tap Choose accessory to grant Nearby devices access through Android.";
            case BLUETOOTH_DISABLED:
                return "Bluetooth is off. Turn it on in Android settings; this app will not enable it.";
            case ASSOCIATION_REQUIRED:
                return "Choose one accessory through Android's companion device dialog.";
            case BOND_REQUIRED:
                return "The selected accessory is not paired. Pair it in Android settings first.";
            case REQUEST_IN_FLIGHT:
                return "Waiting for Android profile connection broadcasts.";
            case READY:
            default:
                return "Ready. Tap Connect supported profiles to make one explicit request.";
        }
    }

    private static String statusMessage(Integer statusCode) {
        if (statusCode == null) {
            return "Android did not return a connection status.";
        }
        return "Android returned status " + statusCode
                + " and did not accept the profile connection request.";
    }

    private static String profileLabel(String action) {
        if (BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED.equals(action)) {
            return "Media audio";
        }
        if (BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED.equals(action)) {
            return "Call audio";
        }
        if (BluetoothHearingAid.ACTION_CONNECTION_STATE_CHANGED.equals(action)) {
            return "Hearing aid audio";
        }
        if (BluetoothLeAudio.ACTION_LE_AUDIO_CONNECTION_STATE_CHANGED.equals(action)) {
            return "LE Audio";
        }
        return "Bluetooth link";
    }

    private static String stateLabel(int state) {
        switch (state) {
            case BluetoothProfile.STATE_CONNECTED:
                return "connected";
            case BluetoothProfile.STATE_CONNECTING:
                return "connecting";
            case BluetoothProfile.STATE_DISCONNECTING:
                return "disconnecting";
            case BluetoothProfile.STATE_DISCONNECTED:
            default:
                return "disconnected";
        }
    }

    private Button actionButton(String label) {
        Button button = new Button(this);
        button.setText(label);
        button.setTextSize(16f);
        button.setAllCaps(false);
        button.setMinHeight(dp(52));
        button.setTextColor(getColorStateList(R.color.glass_button_text));
        button.setBackgroundResource(R.drawable.glass_button);
        // A static state-list keeps the control usable when reduced motion is enabled.
        button.setStateListAnimator(null);
        button.setPadding(dp(16), dp(10), dp(16), dp(10));
        return button;
    }

    private TextView textView(String text, float sizeSp, boolean bold) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(sizeSp);
        view.setTextColor(getColor(R.color.accessory_text));
        view.setLineSpacing(0f, 1.15f);
        if (bold) {
            view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        }
        return view;
    }

    private LinearLayout.LayoutParams matchWidth() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    private LinearLayout.LayoutParams spacedWidth(int topMargin) {
        LinearLayout.LayoutParams params = matchWidth();
        params.topMargin = topMargin;
        return params;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
