# Access control and privilege Escalation

## Vertical Privilege Escalation
- If a user can gain access to functionality that they are not permitted to access then this is vertical privilege escalation. For example, if a non-administrative user can gain access to an admin page where they can delete user accounts, then this is vertical privilege escalation.

## Horizontal Privilege Escalation
- Horizontal privilege escalation occurs if a user is able to gain access to resources belonging to another user, instead of their own resources of that type.


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
    - Try using // instead of / in the path
    - Try using /uploads/ instead of /uploads
    - Try using `.` or `%2e`: /%2e/path
    - Try also /%252e/path (double URL encode)