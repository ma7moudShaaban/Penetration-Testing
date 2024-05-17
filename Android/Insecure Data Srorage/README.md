# Insecure Data Storage
- There are 3 general states from which data may be accessible: 
    - At rest - the data is sitting in a file or data store
    - In use- an app has loaded the data into its address space
    - In transit - data has been exchanged between mobile app and enpoint or consuming processes on the 
        device, e.g., during IPC


- Access to the data depends on the encryption: unencrypted databases are easily accessible, while encrypted ones require investigation into how the key is managed - whether it's hardcoded or stored unencrypted in an insecure location such as shared preferences, or securely in the platform's KeyStore (which is best practice).

- However, if an attacker has sufficient access to the device (e.g. root access) or can repackage the app, he can still retrieve encryption keys at runtime using tools like Frida.