# Broken Access Control
- [HTTP Verb Tampering](#http-verb-tampering)
- [Session Fixation](#session-fixation)


## HTTP verb Tampering

|Verb|	Description|
|:---|:------------|
|HEAD|	Identical to a GET request, but its response only contains the headers, without the response body|
|PUT|	Writes the request payload to the specified location|
|DELETE|	Deletes the resource at the specified location|
|OPTIONS|	Shows different options accepted by a web server, like accepted HTTP verbs|
|PATCH|	Apply partial modifications to the resource at the specified location|




## Session Fixation 

1. Acquire a legitimate session token.

2. Lock or "fix" that session token to a user’s session. This can occur under the following conditions:

    - The session token given to the user before logging in does not change after they log in.
    - The application accepts session tokens (like cookies or tokens in URLs or form data) from client-supplied sources such as query parameters or POST data, and continues to use them throughout the session.


### Testing:
- [ ]  Parameter Pollution
- [ ]  Try different verbs on every function
- [ ]  Always check source code and robots.txt file
- [ ]  Fuzz hidden parameters in login page
- [ ]  Check whether admin cookie exist e.g. admin= roleid=
- [ ]  Check whether roleid in Response
- [ ]  Check whether GUID is disclosed in some place
- [ ]  Check whether victim data is disclosed while login page redirection
- [ ]  Bypass 403 by X-Original-URL: OR X-Rewrite-URL: (Override URL)
- [ ]  Bypass 403
    
    **IP-based Access Control:**
    
    - X-Originating-IP: 127.0.0.1
    - X-Forwarded-For: 127.0.0.1
    - X-Forwarded: 127.0.0.1
    - Forwarded-For: 127.0.0.1
    - X-Forwarded-Host: 127.0.0.1
    - X-Remote-IP: 127.0.0.1
    - X-Remote-Addr: 127.0.0.1
    - X-ProxyUser-Ip: 127.0.0.1
    - X-Original-URL: 127.0.0.1
    - Client-IP: 127.0.0.1
    - X-Client-IP: 127.0.0.1
    - X-Host: 127.0.0.1
    - True-Client-IP: 127.0.0.1
    - Cluster-Client-IP: 127.0.0.1
    - X-ProxyUser-Ip: 127.0.0.1
    - Via: 1.0 fred, 1.1 127.0.0.1
- [ ]  Bypass 403 by change method to POSTX,  GET, CONNECT, Head and so
- [ ]  Bypass 403
    
    **URL-matching Discrepancies**
    
    - site.com/secret –> HTTP 403 Forbidden
    - site.com/SECRET –> HTTP 200 OK
    - site.com/secret/ –> HTTP 200 OK
    - site.com/secret/. –> HTTP 200 OK
    - site.com//secret// –> HTTP 200 OK
    - site.com/./secret/.. –> HTTP 200 OK
    - site.com/;/secret –> HTTP 200 OK
    - site.com/.;/secret –> HTTP 200 OK
    - site.com//;//secret –> HTTP 200 OK
    - site.com/secret.json –> HTTP 200 OK (ruby)
    - site.com/secret.anything -> HTTP 200 OK
- [ ]  Bypass 403 by tampering with Referer header
- [ ]  Bypass Blocked paths 
    - Try Access allowed file after disallowed file e.g. If /data is forbidden Try /data/home
    - Try using // instead of / in the path
    - Try using /uploads/ instead of /uploads
    - Try using `.` or `%2e`: /%2e/path
    - Try also /%252e/path (double URL encode)
    - /api/23423423/users -> 403 forbidden, you can bypass using:
        - /api//users
        - /api\\users
  