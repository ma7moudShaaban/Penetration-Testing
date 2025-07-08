# Web Cache Poisoning
- [Overview](#overview)
- [Identifying Unkeyed Parameters](#identifying-unkeyed-parameters)
    - [Unkeyed GET Parameters](#unkeyed-get-parameters)
    - [Unkeyed Headers](#unkeyed-headers)
- [Web Cache Poisoning Attacks](#web-cache-poisoning-attacks)
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
- There are demonstrated test cases to determin keyed and unkeyed parameters:
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






## Resources
- [Chaining-cache-poisoning-to-stored-xss  ](https://nahoragg.medium.com/chaining-cache-poisoning-to-stored-xss-b910076bda4f)
- [Web-cache-poisoning-worth-it ](https://yaseenzubair.medium.com/web-cache-poisoning-worth-it-e7c6d88797b1) 
- [sensitive-information-disclosure-web-cache...](https://medium.com/@dr.spitfire/sensitive-information-disclosure-web-cache-deception-attack-bcac6cb9cd86)  
- https://infosecwriteups.com/how-i-made-16-500-hacking-cdn-caching-servers-part-2-4995ece4c6e6
- https://book.hacktricks.xyz/pentesting-web/cache-deception
- https://youst.in/posts/cache-poisoning-at-scale/
- https://portswigger.net/research/practical-web-cache-poisoning
- Black Hat: [• Web Cache Deception Attack  ](https://www.youtube.com/watch?v=mroq9eHFOIU&t=0s)
- Black Hat: [• Practical Web Cache Poisoning ](https://www.youtube.com/watch?v=j2RrmNxJZ5c&t=0s) 
