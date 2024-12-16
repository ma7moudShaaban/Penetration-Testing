# ADB (Android Debuggin Bridge)

- Lists all installed packages - including system packages: `adb shell pm list packages`
- List only third party packages: `adb shell pm list packages -3`
- Clear the application data without removing the actual application: `adb shell pm clear <package_name>`
- List information such as activities and permissions of a package: `adb shell dumpsys package <package_name>`



- Start a specific action which fires intent with, so components that listen on this action will respond.
    - `adb shell am start -a ACTION_NAME`
    - `adb shell am start -n <package_name>/<activity_name>`

- Pass Arguments to intent:
    - `--ez` boolean value
    - `--es` string value





## Resources
- https://developer.android.com/tools/adb