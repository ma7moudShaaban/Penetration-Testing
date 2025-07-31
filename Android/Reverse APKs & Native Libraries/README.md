# Reverse APKs & Native Libraries
- [Overview](#overview)
- [Reverse APKs](#reverse-apks)
- [Reverse Native Libraries](#reverse-native-libraries)
   - [Static Linking](#static-linking)
   - [Dynamic Linking](#dynamic-linking)
   - [JNIEnv](#jnienv)


## Overview
- This guide provides steps to reverse native libraries in an Android APK. The primary tool used is `apktool`, which helps in decompiling the APK file. Additionally, you can search for specific functions within the decompiled code.

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

   - Usages: 
   ```bash
      # Install hermes-dec
      pip install --upgrade git+https://github.com/P1sec/hermes-dec
      
      # View strings and functions name
      hbc-file-parser assets/index.android.bundle

      # Disassemble bytecode
      hbc-disassembler assets/index.android.bundle

      # Decompile into pseudo-code
      hbc-decompiler assets/index.android.bundle
   ```


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

> [!NOTE]
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

- The `JNINativeMethod` struct requires a string of the Java-declared native method name and a string of the method's signature, so we should be able to find these in our native library.

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

- Example: For the native method `public native String doThingsInNativeLibrary(int var0);` The type signature is `(I)Ljava/lang/String;`

- Here is another example:
```java
public native long f (int n, String s, int[] arr); 
```
the type signature is 
```
(ILjava/lang/String;[I)J
```
### JNIEnv
- JNIEnv is a struct of function pointers to JNI Functions. You can think `JNIEnv*` = A toolbox that C/C++ code uses to interact with Java objects/methods.
- Every JNI function in Android native libraries, takes JNIEnv* as the first argument.

#### Common Functions in JNIEnv (with Offsets)

| Offset    | Function Purpose                                            |
| --------- | ----------------------------------------------------------- |
| 0x18      | `FindClass` – Find a Java class by name                     |
| 0x34      | `Throw` – Throw a Java exception                            |
| 0x70/0x84 | `NewObject` – Create a new Java object                      |
| 0x28C     | `NewString` – Create a new Java string                      |
| 0x35C     | `RegisterNatives` – Link native C functions to Java methods |

- Here is a [PDF](./Sheet1.pdf) of the C-implementation of the JNIEnv struct to know what function pointers are at the different offsets.

> [!TIP]
> - There's a way to get the JNI function without doing all of this manually! In both the Ghidra and IDA Pro decompilers you can re-type the first argument in JNI functions to `JNIEnv *` type and it will automatically identify the JNI Functions being called. 
> - In IDA Pro, this work out of the box. In Ghidra, you have to load the JNI types (either the jni.h file or a Ghidra Data Types archive of the jni.h file) first. 
> - For ease, we will load the JNI types from the Ghidra Data Types archive (gdt) produced by Ayrx and available [here](https://github.com/Ayrx/JNIAnalyzer/blob/master/JNIAnalyzer/data/jni_all.gdt). 
> - To load it for use in Ghidra, in the Data Type Manager Window, click on the down arrow in the right-hand corner and select "Open File Archive".
> - Then select `jni_all.gdt` file to load. Once it's loaded, you should see jni_all in the Data Type Manager List as shown below.
> - Once this is loaded in Ghidra, you can then select any argument types in the decompiler and select "Retype Variable". Set the new type to `JNIEnv *`. This will cause the decompiler to now show the names of the JNIFunctions called rather than the offsets from the pointer.


> [!NOTE]
> - For JNI native functions, the arguments will be shifted by 2. The first argument is always JNIEnv*. The second argument will be the object that the function should be run on. For static native methods (they have the static keyword in the Java declaration) this will be NULL.
> - Let's say you have a native Java method like this:
> ```java
> public native int add(int a, int b);
> ```
> - From the Java side, it looks like this method takes 2 arguments: a and b.
> - But in the C/C++ native function, it will actually look like this:
> ```C
> jint Java_com_example_add(JNIEnv* env, jobject thiz, jint a, jint b);
> ```
> - So now it has 4 arguments:
> `JNIEnv* env — lets native code talk to Java`
> `jobject thiz — the Java object (like this)`
> `jint a`
> `jint b`
> 
> - So the real arguments are "shifted by 2" because of the first two JNI-specific ones.
> - If it's a static method, thiz becomes jclass and might be NULL.



## Additional Resources
- For more detailed information on using apktool, please refer to the official [apktool documentation](https://apktool.org/).
- [JNI Functions](https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/functions.html): I always have this one open and refer to it while reversing Android native libraries
- [Android JNI Tips](https://developer.android.com/training/articles/perf-jni): Highly suggest reading the “Native Libraries” section to start
- [Getting Started with the NDK](https://developer.android.com/ndk/guides/): This is guidance for how developers develop native libraries and understanding how things are built, makes it easier to reverse.


