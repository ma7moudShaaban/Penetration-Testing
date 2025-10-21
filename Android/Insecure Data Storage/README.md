# Insecure Data Storage
- [Firebase Databases](#firebase-real-time-databases)
- [Internal Storage](#internal-storage)
    - [Shared preferences](#shared-preferences)
    - [SQLite Databases](#sqlite-databases) 
    - [Realm Databases](#realm-databases)
- [External Storage](#external-storage)
    - [Scoped Storage](#scoped-storage)
- [Key store](#)




## Firebase Real-Time Databases
- The data is stored as JSON and is synchronized in real-time to every connected client and also remains available even when the application goes offline
- [ ] A misconfigured firebase instance can be identified by making the following network call:
        `https://_firebaseprojectName_.firebaseio.com/.json`


## Internal Storage 
- When creating a file with `openFileOutput()`, a file is created in the internal storage `/data/data/<apk_name>/files/` directory. 
- The application Context also provides a convenient function to get the files directory path using `getFilesDir()`.
### Shared Preferences
- `MODE_WORLD-READABLE` allow all applications to access and read the contents fo xml files 
- Note that the `MODE_WORLD_READABLE` and `MODE_WORLD_WRITABLE` were deprecated starting on API level 17.

- [ ] Check the file mode to make sure that only the app can access the file.
- [ ] Search for the class FileInputStream to find out which files are opened and read within the app
- Best Practive: set access `MODE_PRIVATE`

### SQLite Databases
- Unencrypted
    - Once the activity that stores data has been called, the database file will be created with the data and stored in a clear text file at directory `/databases/` 
-  Encrypted
    - [ ] Check if PIN or Password stord improperly on the device.

### Realm Databases
- The database and its contents can be encrypted with a key stored in the configuration file
- [ ] Check if the key is hardcoded or stored unencrypted in an insecure location
- If an attacker has sufficient access to the device (e.g. root access) or can repackage the app, he can still retrieve encryption keys at runtime using tools like Frida. The following Frida script demonstrates how to intercept the Realm encryption key and access the contents of the encrypted database:
```javascript
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

## External Storage
- Historically the external storage was stored on a physically accessible SD card. That's why the external storage folder is called `/sdcard/`, even though on modern phones without an SD card slot it's technically also "internal phone" storage.

> [!NOTE]
> It's also worth knowing that files stored outside the app folder will not be deleted when the user uninstalls the application

### Scoped Storage 
- Since Android 10, and especially Android 11, the scoped storage feature basically turned the "external storage" into a well protected storage similar to the traditional "internal storage".

- _"To give users more control over their files and to limit file clutter, apps that target Android 10 (API level 29) and higher are given scoped access into external storage, or scoped storage, by default. Such apps have access only to the app-specific directory on external storage, as well as specific types of media that the app has created."_

> [!IMPORTANT]
> - Always recommended to not just blindly report apps that use external storage, but rather carefully investigate and test whether you can actually access or leak these files or not. 
> - Impact always depends on the Android version usage and what API levels an app supports.
> - While apps can still use the permission `MANAGE_EXTERNAL_STORAGE` on Android 13+ to request access to all files on external storage, additionally the user must be directed to a special settings page where they have to enable "Allow access to manage all files" for the app.

> [!NOTE]
> - While the scoped storage heavily protects the external storage, there is still one exception. There exists the `MANAGE_EXTERNAL_STORAGE` dangerous permission that can be requested by apps to still read the external storage files. 
> - This permission is only available to apps in the Play Store with an exception, or via side-loading. Thus limiting the impact and risk a lot. 
> - Though the risk is not completely mitigated, so depending on the unique threat-model of an app, you might still want to consider a malicious app to have this permission.