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




## Reverse Native Libraries
### Steps

1. **Decompile the APK:**

   Use `apktool` to decompile the APK file. Replace `APKFILE` with the path to your APK file.
   ```sh
   apktool d APKFILE
    ```

2. **Search for Functions:**

- You can search for specific functions using the following pattern:

`JAVA_PACKAGENAME_CLASSNAME_FUNCTIONNAME`

   - JAVA_PACKAGENAME: The package name of the Java class.
   - CLASSNAME: The name of the class.
   - FUNCTIONNAME: The name of the function.
- This will help in identifying and analyzing the desired function in the decompiled code.

## Additional Information
- For more detailed information on using apktool and other reverse engineering tools, please refer to the official [apktool documentation](https://apktool.org/).