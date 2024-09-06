# Frida
- [Overview](#overview)
- [Installation](#installation)
- [Interaction with Frida](#interaction-with-frida)
- [Frida Gadget](#frida-gadget)

## Overview
Frida allows you to inject JavaScript code into applications during runtime, making it a powerful tool for dynamic analysis and debugging.

## Installation

1. Install Frida tools on Kali Linux:
```bash
   pip3 install frida-tools
   pip3 install frida
```

> [!NOTE] 
>  Determine your CPU architecture using ADB: `adb shell getprop ro.product.cpu.abi`

2. Download the appropriate [Frida server](https://github.com/frida/frida/releases) version that matches both the Frida version on Kali and your emulator's architecture.

>[!NOTE]
> We can run Frida on non-rooted device using frida gadget instead of frida server

3. Push the Frida server to your emulator using ADB:
`adb push /path/to/frida-server /data/local/tmp`

4. Start the Frida server on the emulator:

```
adb shell
cd /data/local/tmp
./frida-server
```
## Interaction with Frida
- List running applications and installed packages on USB-connected devices:
- `frida-ps -Uai`
   - `-U`: USB connected devices 
   - `-a`: Running applications 
   - `-i`: All installed applications

- Spawn an application with Frida and attach a script:

 ```
 frida -U -f PACKAGE_NAME -l ATTACHED_SCRIPT
 ``` 
   - This opens the REPL shell, a Frida CLI interface that emulates IPython/Cycript for rapid prototyping and debugging.

### Example 1: Hooking a Function
In a simple application with a sum function `x + y`, hook the function to sum custom values and check logs using ADB:
```
Java.perform(function() {
    var my_cls = Java.use("com.example.allx256.frida_test.my_activity");
    my_cls.fun.implementation = function(x, y) {
        var ret = this.fun(2, 5);
        return ret;
    };
});

```
### Example 2: Hooking Overloaded Functions
For an application with overloaded functions, hook the overloaded function and manipulate the non-primitive data type like string, then check logs using ADB:
```
Java.perform(function() {
    var my_cls = Java.use("com.example.allx256.frida_test.my_activity");
    my_cls.fun.overload("java.lang.String").implementation = function(x) {
      var stringCls = Java.use("java.lang.String");
      var myStr = stringCls.$new("HOoKed_SUcCess4ullY...!!!")
      var ret = this.fun(myStr);
      return ret;
    };
});

```

### Example 3: Using `Java.choose` for Dead Code Analysis
In an application with dead code, use Java.choose to find an instance of a class and execute its methods:

```
Java.perform(function() {
    Java.choose("com.example.allx256.frida_test.my_activity", {
        onMatch: function(instance) {
            console.log("[+] Found instance: " + instance);
            console.log("[+] Result of secret func: " + instance.secret());
        },
        onComplete: function() { }
    });
});

```
>[!NOTE]
> The previous code may not output results in the REPL shell because it executes before the application is fully loaded into memory. To solve this, use Frida's ability to attach a script to an already running process:
```
frida -U -p PROCESS_ID -l ATTACHED_SCRIPT

```

### Example 4: Using Python Bindings for Extended Control
For greater control over function calls, use Python bindings to interface between Python and JavaScript.
- hook.js:

```
function CallSecretFunction() {
    Java.perform(function() {
        Java.choose("com.example.allx256.frida_test.my_activity", {
            onMatch: function(instance) {
                console.log("[+] Found instance: " + instance);
                console.log("[+] Result of secret func: " + instance.secret());
            },
            onComplete: function() { }
        });
    });
}
rpc.exports = { callsecretfrompython: CallSecretFunction };

```

- hook.py:
```
import frida, time

device = frida.get_usb_device()
pid = device.spawn(["com.example.allx256.frida_test"])
device.resume(pid)
time.sleep(5)
session = device.attach(pid)
script = session.create_script(open("hook.js").read())
script.load()

while True:
    cmd = str(input("1: CallSecretFunction\n2. Exit\n--> "))
    if cmd == "1":
        script.exports.callsecretfrompython()
    elif cmd == "2":
        break

```
## Frida Gadget

- If root detection is extreme, we can use **Frida Gadget**, which can be considered as a Frida server injected into the application.
- We can inject Frida Gadget into the application and sign it using the [Frida Injector](https://github.com/Shapa7276/Frida-Injector) tool:

    ```bash
    python3 Frida-Injector.py -i TARGET_APK -m 1
    ```

- Once injected, we can connect to the application using either Frida:

    ```bash
    frida -U -f Gadget -l ATTACHED_SCRIPT
    ```

  or the [Objection](https://github.com/sensepost/objection) Framework.

> [!NOTE]  
> Ensure the application is open before starting Objection.

### Objection Commands:
- `objection -g Gadget explore`: Connect to the Gadget.
- `android sslpinning disable`: Bypass SSL pinning.
- `android hooking watch class_method FUNCTION_NAME --dump-args --dump-return`: Hook and inspect the results from the function.


## Additional Resources
- [Frida](https://www.infosec-blog.com/categories/#frida)
- [Frida CodeShare](https://codeshare.frida.re/)
- [Fridump](https://github.com/Nightbringer21/fridump)