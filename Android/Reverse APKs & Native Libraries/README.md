# Reverse APKs & Native Libraries

## Overview

This guide provides steps to reverse native libraries in an Android APK. The primary tool used is `apktool`, which helps in decompiling the APK file. Additionally, you can search for specific functions within the decompiled code.

## Reverse APKs 
- **Java Applications:**
   - Just open the apk using `jadx-gui` 

- **Xamarin Applications:**
   1. Decompile the apk using `apktool` 
   2. Investigate dll files in `/unknown/assemblies`, then we found the dll with APPLICATION_NAME.dll
   3. Decompress the dll files using [XALZ](https://github.com/x41sec/tools/blob/master/Mobile/Xamarin/Xamarin_XALZ_decompress.py)
   4. Decompile the dll file using dnspy

- **React Native Applications:**
   - Disassemble Herms bytecode or Hermes JavaScript bytecode file found in assets directory using this [tool](https://github.com/P1sec/hermes-dec) 
> [!NOTE]
> File `index.android.bundle` is a file used in React Native development. It contains the compiled and bundled JavaScript code for your app. This file is used when you want to install the application via Android Studio without running the metro bundler.


- **Games created by Godot Engine**
   - You can identify using metadata in AndroidManifest.xml
   - Use this [tool](https://github.com/bruvzg/gdsdecomp) to decombile the apk

## Reverse Native Libraries
### Steps

1. **Decompile the APK:**

   Use `apktool` to decompile the APK file. Replace `APKFILE` with the path to your APK file.
   ```sh
   apktool d APKFILE
    ```

2. **Search for Functions:**
### Dynamic Linking

- You can search for specific functions using the following pattern:

`JAVA_PACKAGENAME_CLASSNAME_FUNCTIONNAME`

   - JAVA_PACKAGENAME: The package name of the Java class.
   - CLASSNAME: The name of the class.
   - FUNCTIONNAME: The name of the function.
- This will help in identifying and analyzing the desired function in the decompiled code.

### Static Linking
- We must use the RegisterNatives API in order to do the pairing between the Java-declared native method and the function in the native library.

> ![NOTE]
> The `RegisterNatives` function is called from the native code, not the Java code and is most often called in the `JNI_OnLoad` function since RegisterNatives must be executed prior to calling the Java-declared native method.

```C
jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);

typedef struct { 
    char *name; 
    char *signature; 
    void *fnPtr; 
} JNINativeMethod;
```

- If the application is using the static linking method, we as analysts can find the `JNINativeMethod` struct that is being passed to `RegisterNatives` in order to determine which subroutine in the native library is executed when the Java-declared native method is called.

- The `JNINativeMethod` struct requires a string of the Java-declared native method name and a string of the method’s signature, so we should be able to find these in our native library.

- Method Signature:
   - Z: boolean
   - B: byte
   - C: char
   - S: short
   - I: int
   - J: long
   - F: float
   - D: double
   - L fully-qualified-class ; :fully-qualified-class
   - [ type: type[]
   - ( arg-types ) ret-type: method type
   - V: void

- Example: For the native method
```java
public native String doThingsInNativeLibrary(int var0);
```
The type signature is 
```
(I)Ljava/lang/String;
```

- Here is another example:
```java
public native long f (int n, String s, int[] arr); 
```
the type signature is 
```
(ILjava/lang/String;[I)J
```

## Additional Resources
- For more detailed information on using apktool, please refer to the official [apktool documentation](https://apktool.org/).
- [JNI Functions](https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/functions.html): I always have this one open and refer to it while reversing Android native libraries
- [Android JNI Tips](https://developer.android.com/training/articles/perf-jni): Highly suggest reading the “Native Libraries” section to start
- [Getting Started with the NDK](https://developer.android.com/ndk/guides/): This is guidance for how developers develop native libraries and understanding how things are built, makes it easier to reverse.


