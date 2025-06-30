# Insecure Data Storage
## Common persistent storage that should be tested:
- [ ] Shared preferences
- [ ] SQLite Databases
- [ ] Firebase Databases
- [ ] Realm Databases
- [ ] Internal Storage
- [ ] External Storage
- [ ] Key store

 ## 1. Shared Preferences
 - `MODE_WORLD-READABLE` allow all applications to access and read the contents fo xml files 
 - Note that the `MODE_WORLD_READABLE` and `MODE_WORLD_WRITABLE` were deprecated starting on API level 17.

 ## 2. SQLite Databases
 ### Unencrypted
 - Once the activity that stores data has been called, the database file will be created with the data and stored in a clear text file at directory /databases/ 
 ### Encrypted
 - [ ] Check if PIN or Password stord improperly on the device.

## 3. Firebase Real-Time Databases
- The data is stored as JSON and is synchronized in real-time to every connected client and also remains available even when the application goes offline
- [ ] A misconfigured firebase instance can be identified by making the following network call:
        `https://_firebaseprojectName_.firebaseio.com/.json`

## 4. Realm Databases
- The database and its contents can be encrypted with a key stored in the configuration file
- [ ] Check if the key is hardcoded or stored unencrypted in an insecure location
- If an attacker has sufficient access to the device (e.g. root access) or can repackage the app, he can still retrieve encryption keys at runtime using tools like Frida. The following Frida script demonstrates how to intercept the Realm encryption key and access the contents of the encrypted database:
```
'use strict';

function modulus(x, n){
    return ((x % n) + n) % n;
}

function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) { hex.push(((bytes[i] >>> 4) & 0xF).toString(16).toUpperCase());
        hex.push((bytes[i] & 0xF).toString(16).toUpperCase());
    }
    return hex.join("");
}

function b2s(array) {
    var result = "";
    for (var i = 0; i < array.length; i++) {
        result += String.fromCharCode(modulus(array[i], 256));
    }
    return result;
}

// Main Modulus and function.

if(Java.available){
    console.log("Java is available");
    console.log("[+] Android Device.. Hooking Realm Configuration.");

    Java.perform(function(){
        var RealmConfiguration = Java.use('io.realm.RealmConfiguration');
        if(RealmConfiguration){
            console.log("[++] Realm Configuration is available");
            Java.choose("io.realm.Realm", {
                onMatch: function(instance)
                {
                    console.log("[==] Opened Realm Database...Obtaining the key...")
                    console.log(instance);
                    console.log(instance.getPath());
                    console.log(instance.getVersion());
                    var encryption_key = instance.getConfiguration().getEncryptionKey();
                    console.log(encryption_key);
                    console.log("Length of the key: " + encryption_key.length); 
                    console.log("Decryption Key:", bytesToHex(encryption_key));

                }, 
                onComplete: function(instance){
                    RealmConfiguration.$init.overload('java.io.File', 'java.lang.String', '[B', 'long', 'io.realm.RealmMigration', 'boolean', 'io.realm.internal.OsRealmConfig$Durability', 'io.realm.internal.RealmProxyMediator', 'io.realm.rx.RxObservableFactory', 'io.realm.coroutines.FlowFactory', 'io.realm.Realm$Transaction', 'boolean', 'io.realm.CompactOnLaunchCallback', 'boolean', 'long', 'boolean', 'boolean').implementation = function(arg1)
                    {
                        console.log("[==] Realm onComplete Finished..")
                        
                    }
                }
                   
            });
        }
    });
}
```
## 5. Internal Storage 
- [ ] Check the file mode to make sure that only the app can access the file.
- [ ] Search for the class FileInputStream to find out which files are opened and read within the app
- Best Practive: set access `MODE_PRIVATE`

## 6. External Storage
- Files saved to external storage are world-readable 
- It's also worth knowing that files stored outside the app folder will not be deleted when the user uninstalls the application