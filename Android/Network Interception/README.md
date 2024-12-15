# Network Interception
- [Patching Network Security Config with apktool](#patching-network-security-config-with-apktool)
- [Installing Certificate in System Store](#installing-certificate-in-system-store)
- [Dynamic Instrumentation (Hooking)](#dynamic-instrumentation-hooking)
- [Intercept traffic of Flutter & Xamarin Apps](#intercept-traffic-of-flutter--xamarin-apps-non-proxy-aware-applications)

## SSL Pinning
- SSL pinning is a security technique used in Android applications to prevent man-in-the-middle attacks by ensuring that the app only trusts a specific certificate or set of certificates. However, improper configurations and certain techniques can expose the application to vulnerabilities.

### Patching Network Security Config with apktool

- The `network_security_config.xml` file defines the trusted certificates for the application when running HTTPS. To intercept the app’s HTTPS traffic, you need to modify the NSC file to trust user certificates in addition to system certificates.

- User certificates are only trusted by apps when:

   - The app targets Android 6 (API level 23) or lower
   - Or network security config specifically includes "user" certs
   - Example `xml/network_security_config.xml` which trusts "user" certificates:

```xml
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
    </trust-anchors>
</base-config>
```

> [!NOTE]
> We can confirm app uses NCS file from: `android:networkSecurityConfig` in xml file (Manifest.xml)

- **Steps:**

   1. Locate the `network_security_config.xml` file in the `res/xml` directory of the application's code.
   2. Modify the trusted certificates in this file to include the user’s certificates.
   3. Ensure that the `AndroidManifest.xml` references the correct `network_security_config` file using the `android:networkSecurityConfig` attribute.
   4. Rebuild the application using `apktool`:
      ```bash
      apktool b <app_directory>/ -o <app_name>_patched.apk

   5. Sign the APK using the [Uber APK Signer](https://github.com/patrickfav/uber-apk-signer/releases):
   `java -jar <jar_name>.jar --apks <app_name>_patched.apk --out <app_name>_signed.apk`

   6. Install the patched APK:`adb install <app_name>_signed.apk`

### Installing Certificate in System Store

> [!NOTE]
> In order to install our certificate into the system store, root access is required.

1. Install the proxy certificate as a regular user certificate
2. Ensure you are root (adb root), and execute the following commands in adb shell:
- **< Android 13 Technique**
```bash
# Backup the existing system certificates to the user certs folder
cp /system/etc/security/cacerts/* /data/misc/user/0/cacerts-added/

# Create the in-memory mount on top of the system certs folder
mount -t tmpfs tmpfs /system/etc/security/cacerts

# copy all system certs and our user cert into the tmpfs system certs folder
cp /data/misc/user/0/cacerts-added/* /system/etc/security/cacerts/

# Fix any permissions & selinux context labels
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*
```

- **Android 14**

```bash
# Create a separate temp directory, to hold the current certificates
# Otherwise, when we add the mount we can't read the current certs anymore.
mkdir -p -m 700 /data/local/tmp/tmp-ca-copy

# Copy out the existing certificates
cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/tmp-ca-copy/

# Create the in-memory mount on top of the system certs folder
mount -t tmpfs tmpfs /system/etc/security/cacerts

# Copy the existing certs back into the tmpfs, so we keep trusting them
mv /data/local/tmp/tmp-ca-copy/* /system/etc/security/cacerts/

# Copy our new cert in, so we trust that too
cp /data/misc/user/0/cacerts-added/* /system/etc/security/cacerts/

# Update the perms & selinux context labels
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*

# Deal with the APEX overrides, which need injecting into each namespace:

# First we get the Zygote process(es), which launch each app
ZYGOTE_PID=$(pidof zygote || true)
ZYGOTE64_PID=$(pidof zygote64 || true)
# N.b. some devices appear to have both!

# Apps inherit the Zygote's mounts at startup, so we inject here to ensure
# all newly started apps will see these certs straight away:
for Z_PID in "$ZYGOTE_PID" "$ZYGOTE64_PID"; do
    if [ -n "$Z_PID" ]; then
        nsenter --mount=/proc/$Z_PID/ns/mnt -- \
            /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
    fi
done

# Then we inject the mount into all already running apps, so they
# too see these CA certs immediately:

# Get the PID of every process whose parent is one of the Zygotes:
APP_PIDS=$(
    echo "$ZYGOTE_PID $ZYGOTE64_PID" | \
    xargs -n1 ps -o 'PID' -P | \
    grep -v PID
)

# Inject into the mount namespace of each of those apps:
for PID in $APP_PIDS; do
    nsenter --mount=/proc/$PID/ns/mnt -- \
        /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts &
done
wait # Launched in parallel - wait for completion here

echo "System certificate injected"
```

> [!TIP]
> We can intercept traffic automatically using [HTTP Toolkit](http://httptoolkit.com/)

### Dynamic Instrumentation (Hooking)
- Hooking allows for monitoring and editing the application during runtime. This approach can be used to bypass SSL pinning by dynamically modifying the app's behavior while it’s running.

- To verify that the application uses `TrustManager`, follow these steps:

1. Open the application in **jadx-gui**.
2. Search for the keyword **'trust'** in the decompiled Java code.
3. Inspect the results to confirm the presence and implementation of the `TrustManager` class.

- We can abuse the Trust Manager to trust our certificate `burp` using frida scripts e.g. multiple-unpinner frida script.

### Intercept traffic of Flutter & Xamarin Apps (Non-proxy aware applications)

>[!NOTE]
> You can identify that the app using Flutter by the 'io.flutter' file and Xamarin by the 'xamarin.android.net' file.
- Using [Reflutter](https://github.com/Impact-I/reFlutter) tool that make the proxy hardcoded into the application

- [Xamarin Traffic Interception](https://notes.akenofu.me/pentest/Mobile%20Application%20Testing/Xamarin%20-%20Android/)

### Common Issues 
- `NetworkOnMainThreadException`: 
   - This happens due to Android trying to avoid blocking code, such as waiting for a response, on the main thread of the app. In that case surround the HTTP request code with for example:
   ```java
   ExecutorService executor = Executors.newSingleThreadExecutor();
   executor.execute() -> {
      // ... place code here
   }
   ```

