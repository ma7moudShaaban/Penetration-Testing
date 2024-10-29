# Frida
- [Hooking](#hooking)
- [Installation](#installation)
- [Interaction with Frida](#interaction-with-frida)
    - [Hooking a Function](#hooking-a-function)
        - [Changing the value of variable](#changing-the-value-of-variable)
    - [Hooking Overloaded Functions](#hooking-overloaded-functions)
    - [Calling a Static Function](#calling-a-static-function)
    - [Create a Class Instance](#create-a-class-instance)
    - [Invoking methods on an existing instance or Calling Dead Code](#invoking-methods-on-an-existing-instance-or-calling-dead-code)
- [Frida Gadget](#frida-gadget)

## Hooking
Hooking refers to the process of intercepting and modifying the behavior of functions or methods in an application or the Android system itself. For example, we can hook a method in our application and change its functionality by inserting our own implementation.

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

4. Start the Frida server:

```bash
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

 ```bash
 frida -U -f PACKAGE_NAME -l ATTACHED_SCRIPT
 ``` 
   - This opens the REPL shell, a Frida CLI interface that emulates IPython/Cycript for rapid prototyping and debugging.

### Hooking a Function

```java
Java.perform(function() {

  var <class_reference> = Java.use("<package_name>.<class>");
  <class_reference>.<method_to_hook>.implementation = function(<args>) {

    /*
      OUR OWN IMPLEMENTATION OF THE METHOD
    */

  }

})
```

- `var <class_reference> = Java.use("<package_name>.<class>");`

Here, you declare a variable `<class_reference>` to represent a Java class within the target Android application. You specify the class to be used with the Java.use function, which takes the class name as an argument. `<package_name>` represents the package name of the Android application, and `<class>` represents the class you want to interact with.

- `<class_reference>.<method_to_hook>.implementation = function(<args>) {}`

Within the selected class, you specify the method that you want to hook by accessing it using the `<class_reference>`.`<method_to_hook>` notation. This is where you can define your own logic to be executed when the hooked method is called.`<args>`represents the arguments passed to the function.

#### Changing the value of variable
```java
Java.perform(function (){

    var <class_reference> = Java.use("<package_name>.<class>");
    <class_reference>.<variable>.value = <value>;

})
```

### Hooking Overloaded Functions

- When dealing with hooking methods that have arguments, it's important to specify the expected argument types using the `overload(arg_type)` keyword. Additionally, ensure that you include these specified arguments in your implementation when hooking the method. Here our check() function takes two integer arguments so we can specify it like this:

```java
a.check.overload(int, int).implementation = function(a, b) {

  ...

}

```

```java
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
### Calling a Static Function

```java

Java.perform(function() {

    var <class_reference> = Java.use("<package_name>.<class>");
    <class_reference>.<static_method>();

})
```
- This is the template that we can use to call a static method. We can just use the `<class_reference>.<method>` to invoke the method.


### Create a Class Instance 

```java
Java.perform(function() {

  var <class_reference> = Java.use("<package_name>.<class>");
  var <class_instance> = <class_reference>.$new(); // Class Object
  <class_instance>.<method>(); // Calling the method

})

```
- In Frida, to create an instance of a Java class, you can use the $new() method. This is a Frida-specific method allows you to instantiate objects of a particular class.

### Invoking methods on an existing instance or Calling Dead Code 
- For invoking methods on an existing instance can be easily done by frida. For this we will be using an two APIs.

    - `Java.performNow` : function that is used to execute code within the context of the Java runtime.

    - `Java.choose`: enumerates through instances of the specified Java class (provided as the first argument) at runtime.

- Let me show you a template:

```java
Java.performNow(function() {
  Java.choose('<Package>.<class_Name>', {
    onMatch: function(instance) {
      // TODO
    },
    onComplete: function() {}
  });
});
```
- There are two callbacks in this:

    - onMatch
        - The onMatch callback function is executed for each instance of the specified class found during the Java.choose operation.
        - This callback function receives the current instance as its parameter.
        - You can define custom actions within the `onMatch` callback to be performed on each instance.
        - `function(instance) {}`, the instance parameter represents each matched instance of the target class. You can use any other name you want.
    - onComplete
        The `onComplete` callback performs actions or cleanup tasks after the `Java.choose` operation is completed. This block is optional, and you can choose to leave it empty if you don't need to perform any specific actions after the search is finished.




- Example: In an application with dead code, use Java.choose to find an instance of a class and execute its methods:

```java
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
>[!TIP]
> The previous code may not output results in the REPL shell because it executes before the application is fully loaded into memory. To solve this, use Frida's ability to attach a script to an already running process:
```
frida -U -p PROCESS_ID -l ATTACHED_SCRIPT

```

### Example 4: Using Python Bindings for Extended Control
For greater control over function calls, use Python bindings to interface between Python and JavaScript.
- hook.js:

```java
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
```python
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