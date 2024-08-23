## SSL Pinning

### Overview
SSL pinning is a security technique used in Android applications to prevent man-in-the-middle attacks by ensuring that the app only trusts a specific certificate or set of certificates. However, improper configurations and certain techniques can expose the application to vulnerabilities.

### Security Consideration
- Ensure `android:debuggable="false"` in your `AndroidManifest.xml` to prevent attackers from debugging the application and exposing its internal architecture during runtime.

### Approaches to Bypass SSL Pinning

#### 1. Network Security Configuration (NSC) File Modification
The `network_security_config.xml` file defines the trusted certificates for the application when running HTTPS. To intercept the app’s HTTPS traffic, you need to modify the NSC file to trust user certificates in addition to system certificates.

**Steps:**

1. Locate the `network_security_config.xml` file in the `res/xml` directory of the application's code.
2. Modify the trusted certificates in this file to include the user’s certificates.
3. Ensure that the `AndroidManifest.xml` references the correct `network_security_config` file using the `android:networkSecurityConfig` attribute.
4. Rebuild the application using `apktool`:
   ```bash
   apktool b <app_directory>/ -o <app_name>_patched.apk

5. Sign the APK using the [Uber APK Signer](https://github.com/patrickfav/uber-apk-signer/releases):
`java -jar <jar_name>.jar --apks <app_name>_patched.apk --out <app_name>_signed.apk`

6. Install the patched APK:`adb install <app_name>_signed.apk`

#### 2. Dynamic Instrumentation (Hooking)
Hooking allows for monitoring and editing the application during runtime. This approach can be used to bypass SSL pinning by dynamically modifying the app's behavior while it’s running.

- To verify that the application uses `TrustManager`, follow these steps:

1. Open the application in **jadx-gui**.
2. Search for the keyword **'trust'** in the decompiled Java code.
3. Inspect the results to confirm the presence and implementation of the `TrustManager` class.