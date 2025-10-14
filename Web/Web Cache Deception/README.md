# Web Cache Deception
- [Overview](#overview)
- [Constructing a web cache deception attack](#constructing-a-web-cache-deception-attack)
- [Using a cache buster](#using-a-cache-buster)
- [Detecting cached responses](#detecting-cached-responses)
- [Exploiting static extension cache rules](#exploiting-static-extension-cache-rules)
    - [Path mapping discrepancies](#path-mapping-discrepancies)




## Overview
- Web cache deception is a vulnerability that enables an attacker to trick a web cache into storing sensitive, dynamic content. It's caused by discrepancies between how the cache server and origin server handle requests.

## Constructing a web cache deception attack
1. Identify a target endpoint that returns a dynamic response containing sensitive information. 

> [!TIP]
> Focus on endpoints that support the `GET`, `HEAD`, or `OPTIONS` methods as requests that alter the origin server's state are generally not cached.

2. Identify a discrepancy in how the cache and origin server parse the URL path. This could be a discrepancy in how they:

    - Map URLs to resources.
    - Process delimiter characters.
    - Normalize paths.

3. Craft a malicious URL that uses the discrepancy to trick the cache into storing a dynamic response. When the victim accesses the URL, their response is stored in the cache.

> [!IMPORTANT]
> Using Burp, you can then send a request to the same URL to fetch the cached response containing the victim's data. Avoid doing this directly in the browser as some applications redirect users without a session or invalidate local data, which could hide a vulnerability.

## Using a cache buster
- While testing for discrepancies and crafting a web cache deception exploit, make sure that each request you send has a different cache key. Otherwise, you may be served cached responses, which will impact your test results.
- As both URL path and any query parameters are typically included in the cache key, you can change the key by adding a query string to the path and changing it each time you send a request.
- Automate this process using the Param Miner extension. To do this, once you've installed the extension, click on the top-level Param miner > Settings menu, then select Add dynamic cachebuster.
- Burp now adds a unique query string to every request that you make.

## Detecting cached responses
- The `X-Cache` header provides information about whether a response was served from the cache. Typical values include:
    - `X-Cache: hit` - The response was served from the cache.
    - `X-Cache: miss` - The cache did not contain a response for the request's key, so it was fetched from the origin server. In most cases, the response is then cached. To confirm this, send the request again to see whether the value updates to hit.
    - `X-Cache: dynamic` - The origin server dynamically generated the content. Generally this means the response is not suitable for caching.
    - `X-Cache: refresh` - The cached content was outdated and needed to be refreshed or revalidated.
- The `Cache-Control` header may include a directive that indicates caching, like `public` with a `max-age` higher than `0`. Note that this only suggests that the resource is cacheable. It isn't always indicative of caching, as the cache may sometimes override this header.

- If you notice a big difference in response time for the same request, this may also indicate that the faster response is served from the cache.

## Exploiting static extension cache rules
- Cache rules often target static resources by matching common file extensions like `.css` or `.js`. This is the default behavior in most CDNs.

### Path mapping discrepancies
- URL path mapping is the process of associating URL paths with resources on a server, such as files, scripts, or command executions

- REST-style URLs don't directly match the physical file structure like traditional URI. They abstract file paths into logical parts of the API `http://example.com/path/resource/param1/param2`:
    - `http://example.com` points to the server.
    - `/path/resource/` is an endpoint representing a resource.
    - `param1` and `param2` are path parameters used by the server to process the request.

- Discrepancies in how the cache and origin server map the URL path to resources can result in web cache deception vulnerabilities. Consider the following example `http://example.com/user/123/profile/wcd.css`
    - An origin server using REST-style URL mapping may interpret this as a request for the `/user/123/profile` endpoint and returns the profile information for user 123, ignoring `wcd.css` as a non-significant parameter.
    - A cache that uses traditional URL mapping may view this as a request for a file named `wcd.css` located in the `/profile` directory under `/user/123`. It interprets the URL path as `/user/123/profile/wcd.css`. If the cache is configured to store responses for requests where the path ends in `.css`, it would cache and serve the profile information as if it were a CSS file.

#### Exploitation
- Add an arbitrary path segment to the URL of your target endpoint. 
- If the response still contains the same sensitive data as the base response, it indicates that the origin server abstracts the URL path and ignores the added segment.
- For example, this is the case if modifying `/api/orders/123` to `/api/orders/123/foo` still returns order information.
- To test how the cache maps the URL path to resources, you'll need to modify the path to attempt to match a cache rule by adding a static extension. 
- For example, update `/api/orders/123/foo` to `/api/orders/123/foo.js`. If the response is cached, this indicates:

    - That the cache interprets the full URL path with the static extension.
    - That there is a cache rule to store responses for requests ending in `.js`.

> [!TIP]
> Caches may have rules based on specific static extensions. Try a range of extensions, including `.css`, `.ico`, and `.exe`.