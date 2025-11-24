# WebViews
- [@JavaScriptInterface](#javascriptinterface)
- [SOP & WebView Settings](#sop--webview-settings)
- [Custom Tabs](#custom-tabs)

## @JavaScriptInterface

- WebViews in Android can allow JavaScript running in the WebView to call native Java methods. 
- This is especially useful if the app logic is primarily implemented in HTML/Javascript and wants to access native Android features.

- If an attacker can control the document loaded into a WebView, these exposed Java methods could lead to security issues.

- To expose native functionality to the WebView, the developer has to create a class with methods annotated with @JavascriptInterface.
```java
class MyNativeBridge {
    @JavascriptInterface
    public void init(String msg) {
        // [...]
    }
    @JavascriptInterface
    public String getData() {
        // [...]
        return db.getData();
    }
}
```
- This object can then be exposed to the WebView by calling addJavascriptInterface()
```java
WebView webView = findViewById(R.id.main_webview);
webView.addJavascriptInterface(new MyNativeBridge(), "app");
webView.loadUrl(url);
```
- On the side of the website, this object will become available on the global Window object with the name given in the call to addJavascriptInterface(object, name).
```javascript
<script>
window.app.init("Hello");
</script>
```

- It can be a hassle to create malicious websites when attacking WebViews. So let's go over different techniques:
1. Setup Own Server
  - You can setup your server and public on internet to be accessible. `ssh -R 80:localhost:8000 nokey@localhost.run`

2. Data URI:
  - Sometimes it can be enough to just create a data URI
  ```javascript
  data:text/html,<script>alert(1)</script>
  ```
3. Hextree WebView Pwn
  - Hextree created a page that runs various tests to analyse the current render context. It also offers a JS shell so you can easily explore the page and execute the attack from within the WebView:

  https://oak.hackstree.io/android/webview/pwn.html

## SOP & WebView Settings
- SOP ensures that JavaScript can only access resources from the same origin (defined by the protocol, hostname, and port). For example JavaScript executed on https://example.com: 

  - can access other resources like https://example.com/secret.xml.
  - cannot access https://another.com/secret.xml

- Depending on the WebView settings and the origin of the loaded .html document, the test case results vary. Using the app you can change the settings on the fly to observe their impact:

  - [setJavaScriptEnabled(boolean)](https://developer.android.com/reference/android/webkit/WebSettings#setJavaScriptEnabled(boolean))
  - [setAllowContentAccess(boolean)](https://developer.android.com/reference/android/webkit/WebSettings#setAllowContentAccess(boolean))
  - [setAllowFileAccess(boolean)](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess(boolean))
  - [setAllowFileAccessFromFileURLs(boolean)](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccessFromFileURLs(boolean))
  - [setAllowUniversalAccessFromFileURLs(boolean)](https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean))


> [!IMPORTANT]
> **Mitigation**: The WebViewAssetLoader class is the modern approach for loading local files. It uses http(s) URLs for accessing local assets and resources, aligning with the Same-Origin policy, thus facilitating CORS management.


- When WebViews have settings like `AllowFileAccessFromFileURLs` or `AllowUniversalAccessFromFileURLs enabled`, the impact of a compromised WebView increases a lot. In that case an attacker could steal app-internal files like the shared preferences.

1. Leak via XMLHttpRequest
- Example code snippet that tries to read the content of a URL using XHR.
```javascript
function leakFileXHR(url) {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.responseText) {
            console.log(xhr.responseText);
        }
    };
    xhr.onerror = function(error) {
        // console.log(error);
    }
    xhr.send();
}
```
2. Leak via `<iframe>`
- The following functions creates an `<iframe>` of a given URL and attempts to read the document's content.
```javascript
function leakFileIframe(url) {
  const iframe = document.createElement('iframe');
  iframe.onload = () => {
    const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
    if (!iframeDoc) return;
    const contentType = iframeDoc.contentType;
    const data = iframeDoc.documentElement.innerHTML;
    const blob = new Blob([data], { type: contentType });
    const reader = new FileReader();
    const contentPromise = new Promise((resolve, reject) => {
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsText(blob);
    });
    contentPromise.then(content => {
      if (content && !content.includes("net::ERR_")) {
        console.log(content);
      }
    });
  };
  document.body.appendChild(iframe);
  iframe.src = url;
}
```
- WebView does not natively support intent:// URIs (used in Chrome to send intents from websites). However, developers may implement custom logic to handle these intents, making the app vulnerable if not properly secured.

- Example custom code to handle intent:// URIs:
```java
// https://stackoverflow.com/questions/33151246/how-to-handle-intent-on-a-webview-url
@Override
public boolean shouldOverrideUrlLoading(WebView view, String url) {
    if (url.startsWith("intent://")) {
        try {
            Context context = view.getContext();
            Intent intent = Intent.parseUri(url, Intent.URI_INTENT_SCHEME);
            if (intent != null) {
                view.stopLoading();
                PackageManager packageManager = context.getPackageManager();
                ResolveInfo info = packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY);
                if (info != null) {
                    context.startActivity(intent);
                } else {
                    String fallbackUrl = intent.getStringExtra("browser_fallback_url");
                    view.loadUrl(fallbackUrl);
                    // or call external broswer
                    // Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(fallbackUrl));
                    //context.startActivity(browserIntent);
                }
                return true;
            }
        } catch (URISyntaxException e) {
            if (GeneralData.DEBUG) {
                Log.e(TAG, "Can't resolve intent://", e);
            }
        }
    }
    return false;
}
```
## Custom Tabs
- Custom Tabs are a different way to display web content within an app. Unlike WebViews, Custom Tabs are actually not a UI element. Instead, they rely on the browser installed on the device to provide the interface and functionality.
```java
// Launcha a basic CustomTab
CustomTabsIntent customTabsIntent = new CustomTabsIntent.Builder()
    .setToolbarColor(ContextCompat.getColor(this, R.color.colorPrimary))
    .addDefaultShareMenuItem()
    .build();

customTabsIntent.launchUrl(this, Uri.parse("https://hextree.io"));
```
- The code above actually sends an intent to the default Browser and the browser then displays the website.

## Resources
- [Web view Check list](https://blog.oversecured.com/Android-security-checklist-webview/)
- [HackTricks - WebView](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting/webview-attacks)