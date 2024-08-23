# Frida

## Overview
Frida allows you to inject JavaScript code into applications during runtime, making it a powerful tool for dynamic analysis and debugging.

## Installation

1. Install Frida tools on Kali Linux:
   ```bash
   pip3 install frida-tools
   pip3 install frida

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
- `frida-ps -Uai` U for USB connected devices , a for running applications and i for all installed applications.

- Spawn application with frida `frida -U -f PACKAGE_NAME -l ATTACHED_SCRIPT`. Now, we can see Repl shell.
   - REPL interface is Frida CLI that aims to emulate a lot of the nice features of IPython (or Cycript), which tries to get you closer to your code for rapid prototyping and easy debugging.

- Example: We have simple application contains a sum function x+y, we will hook the function to sum the values we want and check the logs with adb.
```
Java.perform( function(){
   var my_cls = Java.use("com.example.allx256.frida_test.my_activity");
   my_cls.fun.implementation = function(x, y){
      var ret = this.fun(2,5);
      return ret;
      }
});

```
- Example: We have the same application but conatins overloaded functions, we will hook the overloaded function and the argument string value passes with and check logs with adb.
```
Java.perform(
   var my_cls = Java.use("com.example.allx256.frida_test.my_activity");
   my_cls.fun.overload("java.lang.String").implementation = function (x){
      var ret = this.fun("HOoKed_SUcCess4ullY...!!!");
      return ret;
   }
);
```

- Example: We have application contains dead code, we will utilize `Java.choose` to accomplish that.
- `Java.choose`: Search in Memory about instance of the class. Once found, implement Instance of it and execute call-back functions `OnMatch` `OnComplete` as we will see:
```
Java.perform(function(){

   Java.choose("com.example.allx256.frida_test.my_activity",{
      onMatch: function (instance) {
      console.log("[+] Found instance: " + instance);
      console.log("[+] Result of secret func: " + instance.secret());
      },
      onComplete: funcction () { }
   });
});

```
>[!NOTE]
> The previous code doesn't output any result in the Ripl shell, because our code loaded more fast than loading process of the application in the memory and the function `Java.choose` run one time.
> The solution that frida offers a feature give us the ability to attack the script on an already running process using the following command: `frida -U -p PROCESS_ID -l ATTACHED_SCRIPT`.

- For excessive control on calling functions in the application, we will use python bindings offers Interfacing between python and javascript. 
- hook.js:

```
function CallSecretFunction(){
      Java.perform(function(){

         Java.choose("com.example.allx256.frida_test.my_activity",{
            onMatch: function (instance) {
               console.log("[+] found instance: " + instance);
               console.log("[+] Result of secret func: " + instance.secret());
               },
            onComplete: function () { }
            });
      });
}
rpc.exports = { callsecretfrompython : CallSecretFunction};
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
cmd = str(input("1: CallSecretFunction\n2. Exit\n -->"))
if cmd == "1":
 script.exports.callsecretfrompython()
elif cmd == "2":
break
```




## Additional Resources
- [Frida](https://www.infosec-blog.com/categories/#frida)