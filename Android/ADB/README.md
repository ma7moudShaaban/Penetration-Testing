# ADB (Android Debuggin Bridge)


- Start a specific action which fires intent with, so components that listen on this action will respond.
    - `adb shell am start -a ACTION_NAME`
    - `adb shell am start -n PACKAGE_NAME/COMPONENT_NAME`

- Pass Arguments to intent:
    - `--ez` boolean value
    - `--es` string value





## Resources
- https://developer.android.com/tools/adb