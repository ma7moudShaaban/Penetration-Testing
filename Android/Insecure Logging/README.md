# Insecure Logging 

Logging is a method that developers use for tracing the code and watching warnings or errors. Unfortunately, Sometimes developers write sensitive data in logs. In such a situations other applications may gain access and read logs for stealing sensitive data.

- To scrutinize logs using adb. Obtain the process ID (PID) of the target application:
            `adb logcat --pid=PROCESS-ID`
    You can use package name to get process ID:
            `adb logcat pidof -s package-name`
    Alternatively, directly specify the package name to obtain the PID:
            `adb logcat --pid=$(adb shell pidof -s package-name)`

- To know which code execute this activity 
            `adb shell dumpsys window | grep mCurrentFocus`
            `adb shell dumpsys window | grep mFocusedApp`
            `adb shell dumpsys activity activities | grep mResumed`