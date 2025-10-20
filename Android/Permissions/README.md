# Android Permissions

- There exist several [protectionLevel](https://developer.android.com/guide/topics/manifest/permission-element) for permissions
- This is the Android core [AndroidManifest.xml](https://android.googlesource.com/platform/frameworks/base.git/+/refs/heads/main/core/res/AndroidManifest.xml) for a huge list of default permissions.

> [!NOTE]
> The system permissions such as `system` or `internal` are permissions that we as an attacker cannot get. BUT by looking for apps that use them, we can identify very valuable targets.

- Besides using system permissions, applications can also create their own permissions in their AndroidManifest.xml.
- Termux for example declares a dangerous permission that can be used to execute arbitrary code.
```xml
<permission android:label="@string/permission_run_command_label"
    android:icon="@mipmap/ic_launcher"
    android:name="com.termux.permission.RUN_COMMAND"
    android:protectionLevel="dangerous"
    android:description="@string/permission_run_command_description"/>
```
- If another app wants to use Termux to run code, it has to request the RUN_COMMAND permission, which triggers an explicit consent dialog.

> [!TIP]
> You can also use the Android Code Search to look for any log message or exception reason, to learn more about the implementation details of certain Android features.

- Besides the permissions, the Android core AndroidManifest.xml also contains lots of protected broadcasts. No regular app is allowed to send these broadcasts to other apps.
```xml
// [...]
<protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />
<protected-broadcast android:name="android.intent.action.PACKAGE_INSTALL" />
<protected-broadcast android:name="android.intent.action.PACKAGE_ADDED" />
<protected-broadcast android:name="android.intent.action.PACKAGE_REPLACED" />
// [...]
```