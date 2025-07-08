# Content Provider
- [Overview](#overview)


## Overview
- Content Providers are identified and accessed with a `content://` URI. 
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



- [ ] Check whether no protection on Content Provider `adb shell content query --uri CONTENT_URI`


## Resources
- [Oversecured Content Provider](https://blog.oversecured.com/Gaining-access-to-arbitrary-Content-Providers)