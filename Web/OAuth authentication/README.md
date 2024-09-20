# OAuth authentication
- [OAuth Scopes](#oauth-scopes)
- [OAuth grant types](#oauth-grant-types)
    - [Authorization code grant type](#authorization-code-grant-type)
    - [Implicit grant type](#implicit-grant-type)
- [Testing](#testing)

![OAuth flow diagram](../../images/OAuth%20Flow.jpg)

## OAuth Scopes
- The client application has to specify which data it wants to access and what kind of operations it wants to perform. It does this using the `scope` parameter of the authorization request it sends to the OAuth service.

## OAuth grant types
- We'll focus on the "authorization code" and "implicit" grant types as these are by far the most common

### Authorization code grant type

![Authorization Code grant flow](../../images/Authorization%20code%20grant.jpg)
- **Authorization request**
- The client application sends a request to the OAuth service's /authorization endpoint asking for permission to access specific user data.
e.g. 
```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```
- `client_id` Mandatory parameter containing the unique identifier of the client application. This value is generated when the client application registers with the OAuth service.

- `state` Stores a unique, unguessable value that is tied to the current session on the client application. The OAuth service should return this exact value in the response, along with the authorization code. This parameter serves as a form of CSRF token for the client application by making sure that the request to its /callback endpoint is from the same person who initiated the OAuth flow.

> [!NOTE]
> All communication from Access token request on takes place in a secure back-channel and, therefore, cannot usually be observed or controlled by an attacker.

### Implicit grant type
![Implicit grant](../../images/Implicit%20grant.jpg)
- The implicit grant type is much simpler. Rather than first obtaining an authorization code and then exchanging it for an access token, the client application receives the access token immediately after the user gives their consent.

> [!WARNING]
> When using the implicit grant type, all communication happens via browser redirects - there is no secure back-channel like in the authorization code flow.

- The implicit grant type is more suited to single-page applications and native desktop applications, which cannot easily store the client_secret on the back-end

- **Authorization request**
The implicit flow starts in much the same way as the authorization code flow. The only major difference is that the response_type parameter must be set to token.
```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```

- **Access Token grant**
- The same as authorization code , instead of sending a query parameter containing an authorization code, it will send the access token and other token-specific data as a URL fragment, e.g. 
```
GET /callback#access_token=z0y9x8w7v6u5&token_type=Bearer&expires_in=5000&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com
```

## Testing

- Once you know the hostname of the authorization server, you should always try sending a GET request to the following standard endpoints:
```
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
```
- [ ] Vulnerabilities in the client application
    - [ ] Check Flow of Authentication whether token is tied to this user or not


- [ ] Vulnerabilities in the OAuth service


## Resources
- [Hidden OAuth attack vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)