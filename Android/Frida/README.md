# Frida

## overview
- we can inject javascript code in application during runtime
## Installation 

- In kali linux `pip3 install frida-tools ` `pip3 install frida`
> [!Note] 
> Know CPU architecture using adb `adb shell getprop ro.product.cpu.abi`

- Install [frida server](https://github.com/frida/frida/releases) that match frida version in kali and your emulator architecture, Then push it to emulator using adb.

- I prefer push to /data/local/tmp and run it using `./frida-server`