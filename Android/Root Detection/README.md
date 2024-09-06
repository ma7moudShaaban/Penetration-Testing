# Root Detection

- We can hook into methods and functions that detect a rooted device and bypass them during runtime.

- **Magisk Options**:
    - **Magisk Hide**: The traditional method to hide root permissions for selected apps.
    - **Zygisk**: The newer method to hide root permissions for selected apps.

> [!TIP]  
> It’s possible to change the Magisk app name to avoid detection as a root management tool.

- If the previous bypasses fail, we can use **Frida Gadget** to continue the penetration testing process.

- **[SecureFlag](https://gist.github.com/su-vikas/36410f67c9e0127961ae344010c4c0ef)**: Prevents taking screenshots or sharing the screen within the app. We can use Frida scripts to bypass this restriction.

## Resources
- [SafetyNet - MSTG](https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md)
