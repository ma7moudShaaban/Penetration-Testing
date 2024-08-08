# Frida

## Overview
Frida allows you to inject JavaScript code into applications during runtime, making it a powerful tool for dynamic analysis and debugging.

## Installation

1. Install Frida tools on Kali Linux:
   ```bash
   pip3 install frida-tools
   pip3 install frida

> [!Note] 
>  Determine your CPU architecture using ADB: `adb shell getprop ro.product.cpu.abi`

2. Download the appropriate [Frida server](https://github.com/frida/frida/releases) version that matches both the Frida version on Kali and your emulator's architecture.

3. Push the Frida server to your emulator using ADB:
`adb push /path/to/frida-server /data/local/tmp`

4. Start the Frida server on the emulator:

```
adb shell
cd /data/local/tmp
./frida-server
```