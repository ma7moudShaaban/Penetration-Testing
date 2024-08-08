# SSL Pinning
- `android:debuggable="true"` as this allows an attacker to debug the application
and expose internal architecture during runtime.

1. First Approach
- network_security_config (NSC file) => contains the trusted certificates developer provided to intercept the application running https , you need to modify the trusted cert in network_security_config.xml file in xml in res in the application code. you need to patch the nsc file to trust the user certs not system only. you need to check in the AndroidManifest.xml for android:networkSecurityConfig that mention xml/network_security_config file. Once you modified the code, you need to build the app again, use apktool for that.
- `apktool b indeed/ -o indeed_patched.apk`
use [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer/releases) to sign apk release certificate to build the app to sign the app, download the jar release with curl /link.
``` 
java -jar /jar_name --apks indeed_patched.apk --out indeed_signed.apk
cd indeed_signed.apk
adb install indeed_patched_aligned-debugSigned.apk
``` 
2. Second Approach: Hooking (Dynamic instrumentation) => Monitor and edit application during runtime 
