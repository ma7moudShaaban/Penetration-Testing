# WebSockets
- [Overview](#overview)
- [Exploiting XSS via WebSockets](#exploiting-xss-via-websockets)

## Overview
1. HTTP/1.1 — Traditional Web Communication
    - Browser and server communicate using request–response model.
    - The client (browser) always starts the conversation.
    - The server only replies when it receives a request.
    - Once the server responds, the connection usually ends (unless keep-alive is used).
    - The server cannot send data on its own — it must wait for the client’s request.

- Example:
    - Browser: "Give me index.html."
    - Server: "Here it is." (Then stays silent.)

2. HTTP/2 — Server Push Feature
    - Introduced to make web pages load faster.
    - Still uses the request–response model, but with an improvement.
    - The server can "push" additional resources that the client will likely need (like CSS or JS files).
    - This saves time by reducing extra requests.
    - However, it's still not fully two-way communication — the client must start the connection first.

- Example:
    - Browser: "Give me index.html."
    - Server: "Here’s index.html, and by the way, here are style.css and script.js too!"

3. WebSocket — Full-Duplex Communication
    - A separate protocol that starts as HTTP but then upgrades to WebSocket.
    - Creates a persistent (long-lived) connection between client and server.
    - Allows bi-directional (two-way) communication.
    - Both client and server can send messages anytime, without waiting for each other.
    - Commonly used for real-time apps (chat, gaming, live dashboards, stock tickers, etc.).
- Example:
    - Server: "New message received!"
    - Browser: "Got it — user is typing a reply."

- WebSocket connections can be identified by the `ws://` and `wss://` protocol schemes. `ws://` is used for WebSocket communication over an unencrypted/insecure HTTP connection, whereas `wss://` is used for WebSocket communication over a secure/encrypted HTTPS connection. 
- Connections to both HTTP and HTTPS servers can establish WebSocket connections. However, when connecting to an HTTP server, the WebSocket connection is typically considered insecure (`ws://`) because it does not use encryption. 
- On the other hand, when connecting to an HTTPS server, the WebSocket connection should be established securely (`wss://`) to ensure data encryption and security.

### WebSocket Connection Establishment
- WebSocket connections begin with an initial handshake process, which involves an exchange of specific messages between the client and server to upgrade the connection from HTTP to WebSocket.
- Web browser can attempt to establish WebSocket connections via multiple means; for example, they can use the JavaScript client-side WebSocket object:
```javascript
const socket = new WebSocket('ws://websockets.htb/echo');
```
- The WebSocket handshake is initiated with an HTTP request similar to this:
```http
GET /echo HTTP/1.1
Host: websockets.htb
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: 7QpTshdCiQfiv3tH7myJ1g==
Origin: http://websockets.htb

```
- It contains the following important headers:

    - The `Connection` header with the value `Upgrade` and the `Upgrade` header with the value websocket indicate the client's intent to establish a WebSocket connection
    - The `Sec-WebSocket-Version` header contains the WebSocket protocol version chosen by the client, with the latest version being `13`
    - The `Sec-WebSocket-Key` header contains a unique value confirming that the client wants to establish a WebSocket connection; this header does not provide any security protections
    - The `Origin` header contains the origin just like in regular HTTP requests and is used for security purposes, as we will discuss in a later section

- The server responds with a response similar to the following:
```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: QU/gD/2y41z9ygrOaGWgaC+Pm2M=
```
- The response contains the following information:

    - The HTTP status code of `101` indicates that the WebSocket connection establishment has been completed
    - The `Connection` and `Upgrade` headers contain the same values as in the client's request, which is Upgrade and websocket, respectively
    - The `Sec-WebSocket-Accept` header contains a value derived from the value sent by the client in the `Sec-WebSocket-Key` header and confirms that the server is willing to establish a WebSocket connection
- After the server's response, the WebSocket connection has been established, and messages can be exchanged.

## Exploiting XSS via WebSockets
- Like any other unsanitized input, embedding messages from a WebSocket connection into a website can lead to Cross-Site Scripting (XSS). 
- Suppose an attacker can send a malicious XSS payload to other users so that it is embedded into their browser's Document Object Model (DOM). In that case, there is a valid XSS attack vector.
